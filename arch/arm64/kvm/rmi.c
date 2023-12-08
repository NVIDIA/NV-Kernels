// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2025 ARM Ltd.
 */

#include <linux/kvm_host.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/rmi_cmds.h>
#include <asm/virt.h>

#include <asm/kvm_pgtable.h>

static unsigned long rmm_feat_reg0;

#define RMM_PAGE_SHIFT		12
#define RMM_PAGE_SIZE		BIT(RMM_PAGE_SHIFT)

#define RMM_RTT_BLOCK_LEVEL	2
#define RMM_RTT_MAX_LEVEL	3

/* See ARM64_HW_PGTABLE_LEVEL_SHIFT() */
#define RMM_RTT_LEVEL_SHIFT(l)	\
	((RMM_PAGE_SHIFT - 3) * (4 - (l)) + 3)
#define RMM_L2_BLOCK_SIZE	BIT(RMM_RTT_LEVEL_SHIFT(2))

static inline unsigned long rmi_rtt_level_mapsize(int level)
{
	if (WARN_ON(level > RMM_RTT_MAX_LEVEL))
		return RMM_PAGE_SIZE;

	return (1UL << RMM_RTT_LEVEL_SHIFT(level));
}

static bool rmi_has_feature(unsigned long feature)
{
	return !!u64_get_bits(rmm_feat_reg0, feature);
}

bool kvm_rmi_supports_sve(void)
{
	return rmi_has_feature(RMI_FEATURE_REGISTER_0_SVE_EN);
}

static int rmi_check_version(void)
{
	struct arm_smccc_res res;
	unsigned short version_major, version_minor;
	unsigned long host_version = RMI_ABI_VERSION(RMI_ABI_MAJOR_VERSION,
						     RMI_ABI_MINOR_VERSION);
	unsigned long aa64pfr0 = read_sanitised_ftr_reg(SYS_ID_AA64PFR0_EL1);

	/* If RME isn't supported, then RMI can't be */
	if (cpuid_feature_extract_unsigned_field(aa64pfr0, ID_AA64PFR0_EL1_RME_SHIFT) == 0)
		return -ENXIO;

	arm_smccc_1_1_invoke(SMC_RMI_VERSION, host_version, &res);

	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		return -ENXIO;

	version_major = RMI_ABI_VERSION_GET_MAJOR(res.a1);
	version_minor = RMI_ABI_VERSION_GET_MINOR(res.a1);

	if (res.a0 != RMI_SUCCESS) {
		unsigned short high_version_major, high_version_minor;

		high_version_major = RMI_ABI_VERSION_GET_MAJOR(res.a2);
		high_version_minor = RMI_ABI_VERSION_GET_MINOR(res.a2);

		kvm_err("Unsupported RMI ABI (v%d.%d - v%d.%d) we want v%d.%d\n",
			version_major, version_minor,
			high_version_major, high_version_minor,
			RMI_ABI_MAJOR_VERSION,
			RMI_ABI_MINOR_VERSION);
		return -ENXIO;
	}

	kvm_info("RMI ABI version %d.%d\n", version_major, version_minor);

	return 0;
}

u32 kvm_realm_ipa_limit(void)
{
	return u64_get_bits(rmm_feat_reg0, RMI_FEATURE_REGISTER_0_S2SZ);
}

u32 kvm_realm_vgic_nr_lr(void)
{
	return u64_get_bits(rmm_feat_reg0, RMI_FEATURE_REGISTER_0_GICV3_NUM_LRS);
}

u64 kvm_realm_reset_id_aa64dfr0_el1(const struct kvm_vcpu *vcpu, u64 val)
{
	u32 bps = u64_get_bits(rmm_feat_reg0, RMI_FEATURE_REGISTER_0_NUM_BPS);
	u32 wps = u64_get_bits(rmm_feat_reg0, RMI_FEATURE_REGISTER_0_NUM_WPS);
	u32 ctx_cmps;

	if (!kvm_is_realm(vcpu->kvm))
		return val;

	/* Ensure CTX_CMPs is still valid */
	ctx_cmps = FIELD_GET(ID_AA64DFR0_EL1_CTX_CMPs, val);
	ctx_cmps = min(bps, ctx_cmps);

	val &= ~(ID_AA64DFR0_EL1_BRPs_MASK | ID_AA64DFR0_EL1_WRPs_MASK |
		 ID_AA64DFR0_EL1_CTX_CMPs);
	val |= FIELD_PREP(ID_AA64DFR0_EL1_BRPs_MASK, bps) |
	       FIELD_PREP(ID_AA64DFR0_EL1_WRPs_MASK, wps) |
	       FIELD_PREP(ID_AA64DFR0_EL1_CTX_CMPs, ctx_cmps);

	return val;
}

static int get_start_level(struct realm *realm)
{
	/*
	 * Open coded version of 4 - stage2_pgtable_levels(ia_bits) but using
	 * the RMM's page size rather than the host's.
	 */
	return 4 - ((realm->ia_bits - 8) / (RMM_PAGE_SHIFT - 3));
}

static int find_map_level(struct realm *realm,
			  unsigned long start,
			  unsigned long end)
{
	int level = RMM_RTT_MAX_LEVEL;

	while (level > get_start_level(realm)) {
		unsigned long map_size = rmi_rtt_level_mapsize(level - 1);

		if (!IS_ALIGNED(start, map_size) ||
		    (start + map_size) > end)
			break;

		level--;
	}

	return level;
}

static phys_addr_t alloc_delegated_granule(struct kvm_mmu_memory_cache *mc)
{
	phys_addr_t phys;
	void *virt;

	if (mc) {
		virt = kvm_mmu_memory_cache_alloc(mc);
	} else {
		virt = (void *)__get_free_page(GFP_ATOMIC | __GFP_ZERO |
					       __GFP_ACCOUNT);
	}

	if (!virt)
		return PHYS_ADDR_MAX;

	phys = virt_to_phys(virt);
	if (rmi_granule_delegate(phys)) {
		free_page((unsigned long)virt);
		return PHYS_ADDR_MAX;
	}

	return phys;
}

static phys_addr_t alloc_rtt(struct kvm_mmu_memory_cache *mc)
{
	phys_addr_t phys = alloc_delegated_granule(mc);

	if (phys != PHYS_ADDR_MAX)
		kvm_account_pgtable_pages(phys_to_virt(phys), 1);

	return phys;
}

static int free_delegated_granule(phys_addr_t phys)
{
	if (WARN_ON(rmi_granule_undelegate(phys))) {
		/* Undelegate failed: leak the page */
		return -EBUSY;
	}

	free_page((unsigned long)phys_to_virt(phys));

	return 0;
}

static void free_rtt(phys_addr_t phys)
{
	if (free_delegated_granule(phys))
		return;

	kvm_account_pgtable_pages(phys_to_virt(phys), -1);
}

int realm_psci_complete(struct kvm_vcpu *source, struct kvm_vcpu *target,
			unsigned long status)
{
	int ret;

	ret = rmi_psci_complete(virt_to_phys(source->arch.rec.rec_page),
				virt_to_phys(target->arch.rec.rec_page),
				status);
	if (ret)
		return -EINVAL;

	return 0;
}

static int realm_rtt_create(struct realm *realm,
			    unsigned long addr,
			    int level,
			    phys_addr_t phys)
{
	addr = ALIGN_DOWN(addr, rmi_rtt_level_mapsize(level - 1));
	return rmi_rtt_create(virt_to_phys(realm->rd), phys, addr, level);
}

static int realm_rtt_fold(struct realm *realm,
			  unsigned long addr,
			  int level,
			  phys_addr_t *rtt_granule)
{
	unsigned long out_rtt;
	int ret;

	addr = ALIGN_DOWN(addr, rmi_rtt_level_mapsize(level - 1));
	ret = rmi_rtt_fold(virt_to_phys(realm->rd), addr, level, &out_rtt);

	if (rtt_granule)
		*rtt_granule = out_rtt;

	return ret;
}

static int realm_rtt_destroy(struct realm *realm, unsigned long addr,
			     int level, phys_addr_t *rtt_granule,
			     unsigned long *next_addr)
{
	unsigned long out_rtt;
	int ret;

	ret = rmi_rtt_destroy(virt_to_phys(realm->rd), addr, level,
			      &out_rtt, next_addr);

	*rtt_granule = out_rtt;

	return ret;
}

static int realm_create_rtt_levels(struct realm *realm,
				   unsigned long ipa,
				   int level,
				   int max_level,
				   struct kvm_mmu_memory_cache *mc)
{
	while (level++ < max_level) {
		phys_addr_t rtt = alloc_rtt(mc);
		int ret;

		if (rtt == PHYS_ADDR_MAX)
			return -ENOMEM;

		ret = realm_rtt_create(realm, ipa, level, rtt);
		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT &&
		    RMI_RETURN_INDEX(ret) == level - 1) {
			/* The RTT already exists, continue */
			free_rtt(rtt);
			continue;
		}

		if (ret) {
			WARN(1, "Failed to create RTT at level %d: %d\n",
			     level, ret);
			free_rtt(rtt);
			return -ENXIO;
		}
	}

	return 0;
}

static int realm_tear_down_rtt_level(struct realm *realm, int level,
				     unsigned long start, unsigned long end)
{
	ssize_t map_size;
	unsigned long addr, next_addr;

	if (WARN_ON(level > RMM_RTT_MAX_LEVEL))
		return -EINVAL;

	map_size = rmi_rtt_level_mapsize(level - 1);

	for (addr = start; addr < end; addr = next_addr) {
		phys_addr_t rtt_granule;
		int ret;
		unsigned long align_addr = ALIGN(addr, map_size);

		next_addr = ALIGN(addr + 1, map_size);

		if (next_addr > end || align_addr != addr) {
			/*
			 * The target range is smaller than what this level
			 * covers, recurse deeper.
			 */
			ret = realm_tear_down_rtt_level(realm,
							level + 1,
							addr,
							min(next_addr, end));
			if (ret)
				return ret;
			continue;
		}

		ret = realm_rtt_destroy(realm, addr, level,
					&rtt_granule, &next_addr);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			free_rtt(rtt_granule);
			break;
		case RMI_ERROR_RTT:
			if (next_addr > addr) {
				/* Missing RTT, skip */
				break;
			}
			/*
			 * We tear down the RTT range for the full IPA
			 * space, after everything is unmapped. Also we
			 * descend down only if we cannot tear down a
			 * top level RTT. Thus RMM must be able to walk
			 * to the requested level. e.g., a block mapping
			 * exists at L1 or L2.
			 */
			if (WARN_ON(RMI_RETURN_INDEX(ret) != level))
				return -EBUSY;
			if (WARN_ON(level == RMM_RTT_MAX_LEVEL))
				return -EBUSY;

			/*
			 * The table has active entries in it, recurse deeper
			 * and tear down the RTTs.
			 */
			next_addr = ALIGN(addr + 1, map_size);
			ret = realm_tear_down_rtt_level(realm,
							level + 1,
							addr,
							next_addr);
			if (ret)
				return ret;
			/*
			 * Now that the child RTTs are destroyed,
			 * retry at this level.
			 */
			next_addr = addr;
			break;
		default:
			WARN_ON(1);
			return -ENXIO;
		}
	}

	return 0;
}

static int realm_tear_down_rtt_range(struct realm *realm,
				     unsigned long start, unsigned long end)
{
	/*
	 * Root level RTTs can only be destroyed after the RD is destroyed. So
	 * tear down everything below the root level
	 */
	return realm_tear_down_rtt_level(realm, get_start_level(realm) + 1,
					 start, end);
}

/*
 * Returns 0 on successful fold, a negative value on error, a positive value if
 * we were not able to fold all tables at this level.
 */
static int realm_fold_rtt_level(struct realm *realm, int level,
				unsigned long start, unsigned long end)
{
	int not_folded = 0;
	ssize_t map_size;
	unsigned long addr, next_addr;

	if (WARN_ON(level > RMM_RTT_MAX_LEVEL))
		return -EINVAL;

	map_size = rmi_rtt_level_mapsize(level - 1);

	for (addr = start; addr < end; addr = next_addr) {
		phys_addr_t rtt_granule;
		int ret;
		unsigned long align_addr = ALIGN(addr, map_size);

		next_addr = ALIGN(addr + 1, map_size);

		ret = realm_rtt_fold(realm, align_addr, level, &rtt_granule);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			free_rtt(rtt_granule);
			break;
		case RMI_ERROR_RTT:
			if (level == RMM_RTT_MAX_LEVEL ||
			    RMI_RETURN_INDEX(ret) < level) {
				not_folded++;
				break;
			}
			/* Recurse a level deeper */
			ret = realm_fold_rtt_level(realm,
						   level + 1,
						   addr,
						   next_addr);
			if (ret < 0) {
				return ret;
			} else if (ret == 0) {
				/* Try again at this level */
				next_addr = addr;
			}
			break;
		default:
			WARN_ON(1);
			return -ENXIO;
		}
	}

	return not_folded;
}

void kvm_realm_destroy_rtts(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned int ia_bits = realm->ia_bits;

	WARN_ON(realm_tear_down_rtt_range(realm, 0, (1UL << ia_bits)));
}

static int realm_destroy_private_granule(struct realm *realm,
					 unsigned long ipa,
					 unsigned long *next_addr)
{
	unsigned long rd = virt_to_phys(realm->rd);
	unsigned long phy_addr;
	phys_addr_t rtt;
	int ret;

retry:
	ret = rmi_data_destroy(rd, ipa, &phy_addr, next_addr);
	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		if (*next_addr > ipa)
			return 0; /* UNASSIGNED */
		rtt = alloc_rtt(NULL);
		if (WARN_ON(rtt == PHYS_ADDR_MAX))
			return -ENOMEM;
		/*
		 * ASSIGNED - ipa is mapped as a block, so split. The index
		 * from the return code should be 2 otherwise it appears
		 * there's a huge page bigger than KVM currently supports
		 */
		WARN_ON(RMI_RETURN_INDEX(ret) != 2);
		ret = realm_rtt_create(realm, ipa, 3, rtt);
		if (WARN_ON(ret)) {
			free_rtt(rtt);
			return -ENXIO;
		}
		goto retry;
	} else if (WARN_ON(ret)) {
		return -ENXIO;
	}

	ret = rmi_granule_undelegate(phy_addr);
	if (WARN_ON(ret))
		return -ENXIO;

	return 0;
}

static void realm_unmap_shared_range(struct kvm *kvm,
				     int level,
				     unsigned long start,
				     unsigned long end,
				     bool may_block)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long rd = virt_to_phys(realm->rd);
	ssize_t map_size = rmi_rtt_level_mapsize(level);
	unsigned long next_addr, addr;
	unsigned long shared_bit = BIT(realm->ia_bits - 1);

	if (WARN_ON(level > RMM_RTT_MAX_LEVEL))
		return;

	start |= shared_bit;
	end |= shared_bit;

	for (addr = start; addr < end; addr = next_addr) {
		unsigned long align_addr = ALIGN(addr, map_size);
		int ret;

		next_addr = ALIGN(addr + 1, map_size);

		if (align_addr != addr || next_addr > end) {
			/* Need to recurse deeper */
			if (addr < align_addr)
				next_addr = align_addr;
			realm_unmap_shared_range(kvm, level + 1, addr,
						 min(next_addr, end),
						 may_block);
			continue;
		}

		ret = rmi_rtt_unmap_unprotected(rd, addr, level, &next_addr);
		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			break;
		case RMI_ERROR_RTT:
			if (next_addr == addr) {
				/*
				 * There's a mapping here, but it's not a block
				 * mapping, so reset next_addr to the next block
				 * boundary and recurse to clear out the pages
				 * one level deeper.
				 */
				next_addr = ALIGN(addr + 1, map_size);
				realm_unmap_shared_range(kvm, level + 1, addr,
							 next_addr,
							 may_block);
			}
			break;
		default:
			WARN_ON(1);
			return;
		}

		if (may_block)
			cond_resched_rwlock_write(&kvm->mmu_lock);
	}

	realm_fold_rtt_level(realm, get_start_level(realm) + 1,
			     start, end);
}

/* Calculate the number of s2 root rtts needed */
static int realm_num_root_rtts(struct realm *realm)
{
	unsigned int ipa_bits = realm->ia_bits;
	unsigned int levels = 4 - get_start_level(realm);
	unsigned int sl_ipa_bits = levels * (RMM_PAGE_SHIFT - 3) +
				   RMM_PAGE_SHIFT;

	if (sl_ipa_bits >= ipa_bits)
		return 1;

	return 1 << (ipa_bits - sl_ipa_bits);
}

static int realm_create_rd(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct realm_params *params = realm->params;
	void *rd = NULL;
	phys_addr_t rd_phys, params_phys;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
	u64 dfr0 = kvm_read_vm_id_reg(kvm, SYS_ID_AA64DFR0_EL1);
	int i, r;
	int rtt_num_start;

	realm->ia_bits = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);
	rtt_num_start = realm_num_root_rtts(realm);

	if (WARN_ON(realm->rd || !realm->params))
		return -EEXIST;

	if (pgd_size / RMM_PAGE_SIZE < rtt_num_start)
		return -EINVAL;

	rd = (void *)__get_free_page(GFP_KERNEL);
	if (!rd)
		return -ENOMEM;

	rd_phys = virt_to_phys(rd);
	if (rmi_granule_delegate(rd_phys)) {
		r = -ENXIO;
		goto free_rd;
	}

	for (i = 0; i < pgd_size; i += RMM_PAGE_SIZE) {
		phys_addr_t pgd_phys = kvm->arch.mmu.pgd_phys + i;

		if (rmi_granule_delegate(pgd_phys)) {
			r = -ENXIO;
			goto out_undelegate_tables;
		}
	}

	params->s2sz = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);
	params->rtt_level_start = get_start_level(realm);
	params->rtt_num_start = rtt_num_start;
	params->rtt_base = kvm->arch.mmu.pgd_phys;
	params->vmid = realm->vmid;
	params->num_bps = SYS_FIELD_GET(ID_AA64DFR0_EL1, BRPs, dfr0);
	params->num_wps = SYS_FIELD_GET(ID_AA64DFR0_EL1, WRPs, dfr0);

	if (kvm->arch.arm_pmu) {
		params->pmu_num_ctrs = kvm->arch.nr_pmu_counters;
		params->flags |= RMI_REALM_PARAM_FLAG_PMU;
	}

	params_phys = virt_to_phys(params);

	if (rmi_realm_create(rd_phys, params_phys)) {
		r = -ENXIO;
		goto out_undelegate_tables;
	}

	if (WARN_ON(rmi_rec_aux_count(rd_phys, &realm->num_aux))) {
		WARN_ON(rmi_realm_destroy(rd_phys));
		r = -ENXIO;
		goto out_undelegate_tables;
	}

	realm->rd = rd;
	WRITE_ONCE(realm->state, REALM_STATE_NEW);
	/* The realm is up, free the parameters.  */
	free_page((unsigned long)realm->params);
	realm->params = NULL;

	return 0;

out_undelegate_tables:
	while (i > 0) {
		i -= RMM_PAGE_SIZE;

		phys_addr_t pgd_phys = kvm->arch.mmu.pgd_phys + i;

		if (WARN_ON(rmi_granule_undelegate(pgd_phys))) {
			/* Leak the pages if they cannot be returned */
			kvm->arch.mmu.pgt = NULL;
			break;
		}
	}
	if (WARN_ON(rmi_granule_undelegate(rd_phys))) {
		/* Leak the page if it isn't returned */
		return r;
	}
free_rd:
	free_page((unsigned long)rd);
	return r;
}

/* Protects access to rmi_vmid_bitmap */
static DEFINE_SPINLOCK(rmi_vmid_lock);
static unsigned long *rmi_vmid_bitmap;

static int rmi_vmid_init(void)
{
	unsigned int vmid_count = 1 << kvm_get_vmid_bits();

	rmi_vmid_bitmap = bitmap_zalloc(vmid_count, GFP_KERNEL);
	if (!rmi_vmid_bitmap) {
		kvm_err("%s: Couldn't allocate rmi vmid bitmap\n", __func__);
		return -ENOMEM;
	}

	return 0;
}

static int rmi_vmid_reserve(void)
{
	int ret;
	unsigned int vmid_count = 1 << kvm_get_vmid_bits();

	spin_lock(&rmi_vmid_lock);
	ret = bitmap_find_free_region(rmi_vmid_bitmap, vmid_count, 0);
	spin_unlock(&rmi_vmid_lock);

	return ret;
}

static void rmi_vmid_release(unsigned int vmid)
{
	spin_lock(&rmi_vmid_lock);
	bitmap_release_region(rmi_vmid_bitmap, vmid, 0);
	spin_unlock(&rmi_vmid_lock);
}

static int realm_unmap_private_page(struct realm *realm,
				    unsigned long ipa,
				    unsigned long *next_addr)
{
	unsigned long end = ALIGN(ipa + 1, PAGE_SIZE);
	unsigned long addr;
	int ret;

	for (addr = ipa; addr < end; addr = *next_addr) {
		ret = realm_destroy_private_granule(realm, addr, next_addr);
		if (ret)
			return ret;
	}

	return 0;
}

static void realm_unmap_private_range(struct kvm *kvm,
				      unsigned long start,
				      unsigned long end,
				      bool may_block)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long next_addr, addr;
	int ret;

	for (addr = start; addr < end; addr = next_addr) {
		ret = realm_unmap_private_page(realm, addr, &next_addr);

		if (ret)
			break;

		if (may_block)
			cond_resched_rwlock_write(&kvm->mmu_lock);
	}

	realm_fold_rtt_level(realm, get_start_level(realm) + 1,
			     start, end);
}

void kvm_realm_unmap_range(struct kvm *kvm, unsigned long start,
			   unsigned long size, bool unmap_private,
			   bool may_block)
{
	unsigned long end = start + size;
	struct realm *realm = &kvm->arch.realm;

	end = min(BIT(realm->ia_bits - 1), end);

	if (!kvm_realm_is_created(kvm))
		return;

	realm_unmap_shared_range(kvm, find_map_level(realm, start, end),
				 start, end, may_block);
	if (unmap_private)
		realm_unmap_private_range(kvm, start, end, may_block);
}

static int realm_create_protected_data_granule(struct realm *realm,
					       unsigned long ipa,
					       phys_addr_t dst_phys,
					       phys_addr_t src_phys,
					       unsigned long flags)
{
	phys_addr_t rd = virt_to_phys(realm->rd);
	int ret;

	if (rmi_granule_delegate(dst_phys))
		return -ENXIO;

	ret = rmi_data_create(rd, dst_phys, ipa, src_phys, flags);
	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		/* Create missing RTTs and retry */
		int level = RMI_RETURN_INDEX(ret);

		WARN_ON(level == RMM_RTT_MAX_LEVEL);

		ret = realm_create_rtt_levels(realm, ipa, level,
					      RMM_RTT_MAX_LEVEL, NULL);
		if (ret)
			return -EIO;

		ret = rmi_data_create(rd, dst_phys, ipa, src_phys, flags);
	}
	if (ret)
		return -EIO;

	return 0;
}

static int realm_create_protected_data_page(struct realm *realm,
					    unsigned long ipa,
					    kvm_pfn_t dst_pfn,
					    kvm_pfn_t src_pfn,
					    unsigned long flags)
{
	unsigned long rd = virt_to_phys(realm->rd);
	phys_addr_t dst_phys, src_phys;
	bool undelegate_failed = false;
	int ret, offset;

	dst_phys = __pfn_to_phys(dst_pfn);
	src_phys = __pfn_to_phys(src_pfn);

	for (offset = 0; offset < PAGE_SIZE; offset += RMM_PAGE_SIZE) {
		ret = realm_create_protected_data_granule(realm,
							  ipa,
							  dst_phys,
							  src_phys,
							  flags);
		if (ret)
			goto err;

		ipa += RMM_PAGE_SIZE;
		dst_phys += RMM_PAGE_SIZE;
		src_phys += RMM_PAGE_SIZE;
	}

	return 0;

err:
	if (ret == -EIO) {
		/* current offset needs undelegating */
		if (WARN_ON(rmi_granule_undelegate(dst_phys)))
			undelegate_failed = true;
	}
	while (offset > 0) {
		ipa -= RMM_PAGE_SIZE;
		offset -= RMM_PAGE_SIZE;
		dst_phys -= RMM_PAGE_SIZE;

		rmi_data_destroy(rd, ipa, NULL, NULL);

		if (WARN_ON(rmi_granule_undelegate(dst_phys)))
			undelegate_failed = true;
	}

	if (undelegate_failed) {
		/*
		 * A granule could not be undelegated,
		 * so the page has to be leaked
		 */
		get_page(pfn_to_page(dst_pfn));
	}

	return -ENXIO;
}

static int fold_rtt(struct realm *realm, unsigned long addr, int level)
{
	phys_addr_t rtt_addr;
	int ret;

	ret = realm_rtt_fold(realm, addr, level, &rtt_addr);
	if (ret)
		return ret;

	free_rtt(rtt_addr);

	return 0;
}

int realm_map_protected(struct realm *realm,
			unsigned long ipa,
			kvm_pfn_t pfn,
			unsigned long map_size,
			struct kvm_mmu_memory_cache *memcache)
{
	phys_addr_t phys = __pfn_to_phys(pfn);
	phys_addr_t rd = virt_to_phys(realm->rd);
	unsigned long base_ipa = ipa;
	unsigned long size;
	int map_level = IS_ALIGNED(map_size, RMM_L2_BLOCK_SIZE) ?
			RMM_RTT_BLOCK_LEVEL : RMM_RTT_MAX_LEVEL;
	int ret = 0;

	if (WARN_ON(!IS_ALIGNED(map_size, RMM_PAGE_SIZE) ||
		    !IS_ALIGNED(ipa, map_size)))
		return -EINVAL;

	if (map_level < RMM_RTT_MAX_LEVEL) {
		/*
		 * A temporary RTT is needed during the map, precreate it,
		 * however if there is an error (e.g. missing parent tables)
		 * this will be handled below.
		 */
		realm_create_rtt_levels(realm, ipa, map_level,
					RMM_RTT_MAX_LEVEL, memcache);
	}

	for (size = 0; size < map_size; size += RMM_PAGE_SIZE) {
		if (rmi_granule_delegate(phys)) {
			/*
			 * It's likely we raced with another VCPU on the same
			 * fault. Assume the other VCPU has handled the fault
			 * and return to the guest.
			 */
			return 0;
		}

		ret = rmi_data_create_unknown(rd, phys, ipa);

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			/* Create missing RTTs and retry */
			int level = RMI_RETURN_INDEX(ret);

			WARN_ON(level == RMM_RTT_MAX_LEVEL);
			ret = realm_create_rtt_levels(realm, ipa, level,
						      RMM_RTT_MAX_LEVEL,
						      memcache);
			if (ret)
				goto err_undelegate;

			ret = rmi_data_create_unknown(rd, phys, ipa);
		}

		if (WARN_ON(ret))
			goto err_undelegate;

		phys += RMM_PAGE_SIZE;
		ipa += RMM_PAGE_SIZE;
	}

	if (map_size == RMM_L2_BLOCK_SIZE) {
		ret = fold_rtt(realm, base_ipa, map_level + 1);
		if (WARN_ON(ret))
			goto err;
	}

	return 0;

err_undelegate:
	if (WARN_ON(rmi_granule_undelegate(phys))) {
		/* Page can't be returned to NS world so is lost */
		get_page(phys_to_page(phys));
	}
err:
	while (size > 0) {
		unsigned long data, top;

		phys -= RMM_PAGE_SIZE;
		size -= RMM_PAGE_SIZE;
		ipa -= RMM_PAGE_SIZE;

		WARN_ON(rmi_data_destroy(rd, ipa, &data, &top));

		if (WARN_ON(rmi_granule_undelegate(phys))) {
			/* Page can't be returned to NS world so is lost */
			get_page(phys_to_page(phys));
		}
	}
	return -ENXIO;
}

int realm_map_non_secure(struct realm *realm,
			 unsigned long ipa,
			 kvm_pfn_t pfn,
			 unsigned long size,
			 struct kvm_mmu_memory_cache *memcache)
{
	phys_addr_t rd = virt_to_phys(realm->rd);
	phys_addr_t phys = __pfn_to_phys(pfn);
	unsigned long offset;
	/* TODO: Support block mappings */
	int map_level = RMM_RTT_MAX_LEVEL;
	int map_size = rmi_rtt_level_mapsize(map_level);
	int ret = 0;

	if (WARN_ON(!IS_ALIGNED(size, RMM_PAGE_SIZE) ||
		    !IS_ALIGNED(ipa, size)))
		return -EINVAL;

	for (offset = 0; offset < size; offset += map_size) {
		/*
		 * realm_map_ipa() enforces that the memory is writable,
		 * so for now we permit both read and write.
		 */
		unsigned long desc = phys |
				     PTE_S2_MEMATTR(MT_S2_FWB_NORMAL) |
				     KVM_PTE_LEAF_ATTR_LO_S2_S2AP_R |
				     KVM_PTE_LEAF_ATTR_LO_S2_S2AP_W;
		ret = rmi_rtt_map_unprotected(rd, ipa, map_level, desc);

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			/* Create missing RTTs and retry */
			int level = RMI_RETURN_INDEX(ret);

			ret = realm_create_rtt_levels(realm, ipa, level,
						      map_level, memcache);
			if (ret)
				return -ENXIO;

			ret = rmi_rtt_map_unprotected(rd, ipa, map_level, desc);
		}
		/*
		 * RMI_ERROR_RTT can be reported for two reasons: either the
		 * RTT tables are not there, or there is an RTTE already
		 * present for the address.  The above call to create RTTs
		 * handles the first case, and in the second case this
		 * indicates that another thread has already populated the RTTE
		 * for us, so we can ignore the error and continue.
		 */
		if (ret && RMI_RETURN_STATUS(ret) != RMI_ERROR_RTT)
			return -ENXIO;

		ipa += map_size;
		phys += map_size;
	}

	return 0;
}

static int populate_region_cb(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn,
			      void __user *src, int order, void *opaque)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long data_flags = *(unsigned long *)opaque;
	phys_addr_t ipa = gfn_to_gpa(gfn);
	int npages = (1 << order);
	int i;

	for (i = 0; i < npages; i++) {
		struct page *src_page;
		int ret;

		ret = get_user_pages((unsigned long)src, 1, 0, &src_page);
		if (ret < 0)
			return ret;
		if (ret != 1)
			return -ENOMEM;

		ret = realm_create_protected_data_page(realm, ipa, pfn,
						       page_to_pfn(src_page),
						       data_flags);

		put_page(src_page);

		if (ret)
			return ret;

		ipa += PAGE_SIZE;
		pfn++;
		src += PAGE_SIZE;
	}

	return 0;
}

static long populate_region(struct kvm *kvm,
			    gfn_t base_gfn,
			    unsigned long pages,
			    u64 uaddr,
			    unsigned long data_flags)
{
	long ret = 0;

	mutex_lock(&kvm->slots_lock);
	mmap_read_lock(current->mm);
	ret = kvm_gmem_populate(kvm, base_gfn, u64_to_user_ptr(uaddr), pages,
				populate_region_cb, &data_flags);
	mmap_read_unlock(current->mm);
	mutex_unlock(&kvm->slots_lock);

	return ret;
}

enum ripas_action {
	RIPAS_INIT,
	RIPAS_SET,
};

static int ripas_change(struct kvm *kvm,
			struct kvm_vcpu *vcpu,
			unsigned long ipa,
			unsigned long end,
			enum ripas_action action,
			unsigned long *top_ipa)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	phys_addr_t rec_phys;
	struct kvm_mmu_memory_cache *memcache = NULL;
	int ret = 0;

	if (vcpu) {
		rec_phys = virt_to_phys(vcpu->arch.rec.rec_page);
		memcache = &vcpu->arch.mmu_page_cache;

		WARN_ON(action != RIPAS_SET);
	} else {
		WARN_ON(action != RIPAS_INIT);
	}

	while (ipa < end) {
		unsigned long next = ~0;

		switch (action) {
		case RIPAS_INIT:
			ret = rmi_rtt_init_ripas(rd_phys, ipa, end, &next);
			break;
		case RIPAS_SET:
			ret = rmi_rtt_set_ripas(rd_phys, rec_phys, ipa, end,
						&next);
			break;
		}

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			ipa = next;
			break;
		case RMI_ERROR_RTT: {
			int err_level = RMI_RETURN_INDEX(ret);
			int level = find_map_level(realm, ipa, end);

			if (err_level >= level) {
				/* FIXME: Ugly hack to skip regions which are
				 * already RIPAS_RAM
				 */
				ipa += PAGE_SIZE;
				break;
				return -EINVAL;
			}

			ret = realm_create_rtt_levels(realm, ipa, err_level,
						      level, memcache);
			if (ret)
				return ret;
			/* Retry with the RTT levels in place */
			break;
		}
		default:
			WARN_ON(1);
			return -ENXIO;
		}
	}

	if (top_ipa)
		*top_ipa = ipa;

	return 0;
}

static int realm_set_ipa_state(struct kvm_vcpu *vcpu,
			       unsigned long start,
			       unsigned long end,
			       unsigned long ripas,
			       unsigned long *top_ipa)
{
	struct kvm *kvm = vcpu->kvm;
	int ret = ripas_change(kvm, vcpu, start, end, RIPAS_SET, top_ipa);

	if (ripas == RMI_EMPTY && *top_ipa != start)
		realm_unmap_private_range(kvm, start, *top_ipa, false);

	return ret;
}

static int realm_init_ipa_state(struct kvm *kvm,
				unsigned long gfn,
				unsigned long pages)
{
	return ripas_change(kvm, NULL, gfn_to_gpa(gfn), gfn_to_gpa(gfn + pages),
			    RIPAS_INIT, NULL);
}

static int realm_ensure_created(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	int ret;

	switch (kvm_realm_state(kvm)) {
	case REALM_STATE_NONE:
		break;
	case REALM_STATE_NEW:
		return 0;
	case REALM_STATE_DEAD:
		return -ENXIO;
	default:
		return -EBUSY;
	}

	ret = rmi_vmid_reserve();
	if (ret < 0)
		return ret;
	realm->vmid = ret;
	ret = realm_create_rd(kvm);
	if (ret)
		rmi_vmid_release(realm->vmid);
	return ret;
}

static int set_ripas_of_protected_regions(struct kvm *kvm)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int idx, bkt;
	int ret = 0;

	idx = srcu_read_lock(&kvm->srcu);

	slots = kvm_memslots(kvm);
	kvm_for_each_memslot(memslot, bkt, slots) {
		if (!kvm_slot_has_gmem(memslot))
			continue;

		ret = realm_init_ipa_state(kvm, memslot->base_gfn,
					   memslot->npages);
		if (ret)
			break;
	}
	srcu_read_unlock(&kvm->srcu, idx);

	return ret;
}

int kvm_arm_rmi_populate(struct kvm *kvm,
			 struct kvm_arm_rmi_populate *args)
{
	unsigned long data_flags = 0;
	unsigned long ipa_start = args->base;
	unsigned long ipa_end = ipa_start + args->size;
	int ret;

	if (args->reserved ||
	    (args->flags & ~KVM_ARM_RMI_POPULATE_FLAGS_MEASURE) ||
	    !IS_ALIGNED(ipa_start, PAGE_SIZE) ||
	    !IS_ALIGNED(ipa_end, PAGE_SIZE))
		return -EINVAL;

	ret = realm_ensure_created(kvm);
	if (ret)
		return ret;

	if (args->flags & KVM_ARM_RMI_POPULATE_FLAGS_MEASURE)
		data_flags |= RMI_MEASURE_CONTENT;

	ret = populate_region(kvm, gpa_to_gfn(ipa_start),
			      args->size >> PAGE_SHIFT,
			      args->source_uaddr, args->flags);

	if (ret < 0)
		return ret;

	return ret * PAGE_SIZE;
}

static void kvm_complete_ripas_change(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct realm_rec *rec = &vcpu->arch.rec;
	unsigned long base = rec->run->exit.ripas_base;
	unsigned long top = rec->run->exit.ripas_top;
	unsigned long ripas = rec->run->exit.ripas_value;
	unsigned long top_ipa;
	int ret;

	do {
		kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_page_cache,
					   kvm_mmu_cache_min_pages(vcpu->arch.hw_mmu));
		write_lock(&kvm->mmu_lock);
		ret = realm_set_ipa_state(vcpu, base, top, ripas, &top_ipa);
		write_unlock(&kvm->mmu_lock);

		if (WARN_RATELIMIT(ret && ret != -ENOMEM,
				   "Unable to satisfy RIPAS_CHANGE for %#lx - %#lx, ripas: %#lx\n",
				   base, top, ripas))
			break;

		base = top_ipa;
	} while (base < top);

	/*
	 * If this function is called again before the REC_ENTER call then
	 * avoid calling realm_set_ipa_state() again by changing to the value
	 * of ripas_base for the part that has already been covered. The RMM
	 * ignores the contains of the rec_exit structure so this doesn't
	 * affect the RMM.
	 */
	rec->run->exit.ripas_base = base;
}

/*
 * kvm_rec_pre_enter - Complete operations before entering a REC
 *
 * Some operations require work to be completed before entering a realm. That
 * work may require memory allocation so cannot be done in the kvm_rec_enter()
 * call.
 *
 * Return: 1 if we should enter the guest
 *	   0 if we should exit to userspace
 *	   < 0 if we should exit to userspace, where the return value indicates
 *	   an error
 */
int kvm_rec_pre_enter(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;

	if (kvm_realm_state(vcpu->kvm) != REALM_STATE_ACTIVE)
		return -EINVAL;

	switch (rec->run->exit.exit_reason) {
	case RMI_EXIT_HOST_CALL:
	case RMI_EXIT_PSCI:
		for (int i = 0; i < REC_RUN_GPRS; i++)
			rec->run->enter.gprs[i] = vcpu_get_reg(vcpu, i);
		break;
	case RMI_EXIT_RIPAS_CHANGE:
		kvm_complete_ripas_change(vcpu);
		break;
	}

	return 1;
}

int kvm_rec_enter(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;

	return rmi_rec_enter(virt_to_phys(rec->rec_page),
			     virt_to_phys(rec->run));
}

static void free_rec_aux(struct page **aux_pages,
			 unsigned int num_aux)
{
	unsigned int i, j;
	unsigned int page_count = 0;

	for (i = 0; i < num_aux;) {
		struct page *aux_page = aux_pages[page_count++];
		phys_addr_t aux_page_phys = page_to_phys(aux_page);
		bool should_free = true;

		for (j = 0; j < PAGE_SIZE && i < num_aux; j += RMM_PAGE_SIZE) {
			if (WARN_ON(rmi_granule_undelegate(aux_page_phys)))
				should_free = false;
			aux_page_phys += RMM_PAGE_SIZE;
			i++;
		}
		/* Only free if all the undelegate calls were successful */
		if (should_free)
			__free_page(aux_page);
	}
}

static int alloc_rec_aux(struct page **aux_pages,
			 u64 *aux_phys_pages,
			 unsigned int num_aux)
{
	struct page *aux_page;
	int page_count = 0;
	unsigned int i, j;
	int ret;

	for (i = 0; i < num_aux;) {
		phys_addr_t aux_page_phys;

		aux_page = alloc_page(GFP_KERNEL);
		if (!aux_page) {
			ret = -ENOMEM;
			goto out_err;
		}

		aux_page_phys = page_to_phys(aux_page);
		for (j = 0; j < PAGE_SIZE && i < num_aux; j += RMM_PAGE_SIZE) {
			if (rmi_granule_delegate(aux_page_phys)) {
				ret = -ENXIO;
				goto err_undelegate;
			}
			aux_phys_pages[i++] = aux_page_phys;
			aux_page_phys += RMM_PAGE_SIZE;
		}
		aux_pages[page_count++] = aux_page;
	}

	return 0;
err_undelegate:
	while (j > 0) {
		j -= RMM_PAGE_SIZE;
		i--;
		if (WARN_ON(rmi_granule_undelegate(aux_phys_pages[i]))) {
			/* Leak the page if the undelegate fails */
			goto out_err;
		}
	}
	__free_page(aux_page);
out_err:
	free_rec_aux(aux_pages, i);
	return ret;
}

static int kvm_create_rec(struct kvm_vcpu *vcpu)
{
	struct user_pt_regs *vcpu_regs = vcpu_gp_regs(vcpu);
	unsigned long mpidr = kvm_vcpu_get_mpidr_aff(vcpu);
	struct realm *realm = &vcpu->kvm->arch.realm;
	struct realm_rec *rec = &vcpu->arch.rec;
	unsigned long rec_page_phys;
	struct rec_params *params;
	int r, i;

	if (rec->run)
		return -EBUSY;

	/*
	 * The RMM will report PSCI v1.0 to Realms and the KVM_ARM_VCPU_PSCI_0_2
	 * flag covers v0.2 and onwards.
	 */
	if (!vcpu_has_feature(vcpu, KVM_ARM_VCPU_PSCI_0_2))
		return -EINVAL;

	if (vcpu->kvm->arch.arm_pmu && !kvm_vcpu_has_pmu(vcpu))
		return -EINVAL;

	BUILD_BUG_ON(sizeof(*params) > PAGE_SIZE);
	BUILD_BUG_ON(sizeof(*rec->run) > PAGE_SIZE);

	params = (struct rec_params *)get_zeroed_page(GFP_KERNEL);
	rec->rec_page = (void *)__get_free_page(GFP_KERNEL);
	rec->run = (void *)get_zeroed_page(GFP_KERNEL);
	if (!params || !rec->rec_page || !rec->run) {
		r = -ENOMEM;
		goto out_free_pages;
	}

	for (i = 0; i < ARRAY_SIZE(params->gprs); i++)
		params->gprs[i] = vcpu_regs->regs[i];

	params->pc = vcpu_regs->pc;

	if (vcpu->vcpu_id == 0)
		params->flags |= REC_PARAMS_FLAG_RUNNABLE;

	rec_page_phys = virt_to_phys(rec->rec_page);

	if (rmi_granule_delegate(rec_page_phys)) {
		r = -ENXIO;
		goto out_free_pages;
	}

	r = alloc_rec_aux(rec->aux_pages, params->aux, realm->num_aux);
	if (r)
		goto out_undelegate_rmm_rec;

	params->num_rec_aux = realm->num_aux;
	params->mpidr = mpidr;

	if (rmi_rec_create(virt_to_phys(realm->rd),
			   rec_page_phys,
			   virt_to_phys(params))) {
		r = -ENXIO;
		goto out_free_rec_aux;
	}

	rec->mpidr = mpidr;

	free_page((unsigned long)params);
	return 0;

out_free_rec_aux:
	free_rec_aux(rec->aux_pages, realm->num_aux);
out_undelegate_rmm_rec:
	if (WARN_ON(rmi_granule_undelegate(rec_page_phys)))
		rec->rec_page = NULL;
out_free_pages:
	free_page((unsigned long)rec->run);
	free_page((unsigned long)rec->rec_page);
	free_page((unsigned long)params);
	return r;
}

void kvm_destroy_rec(struct kvm_vcpu *vcpu)
{
	struct realm *realm = &vcpu->kvm->arch.realm;
	struct realm_rec *rec = &vcpu->arch.rec;
	unsigned long rec_page_phys;

	if (!vcpu_is_rec(vcpu))
		return;

	if (!rec->run) {
		/* Nothing to do if the VCPU hasn't been finalized */
		return;
	}

	free_page((unsigned long)rec->run);

	rec_page_phys = virt_to_phys(rec->rec_page);

	/*
	 * The REC and any AUX pages cannot be reclaimed until the REC is
	 * destroyed. So if the REC destroy fails then the REC page and any AUX
	 * pages will be leaked.
	 */
	if (WARN_ON(rmi_rec_destroy(rec_page_phys)))
		return;

	free_rec_aux(rec->aux_pages, realm->num_aux);

	free_delegated_granule(rec_page_phys);
}

int kvm_activate_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct kvm_vcpu *vcpu;
	unsigned long i;
	int ret;

	if (!kvm_is_realm(kvm))
		return -ENXIO;

	if (kvm_realm_state(kvm) == REALM_STATE_ACTIVE)
		return 0;

	guard(mutex)(&kvm->arch.config_lock);
	/* Check again with the lock held */
	if (kvm_realm_state(kvm) == REALM_STATE_ACTIVE)
		return 0;

	ret = realm_ensure_created(kvm);
	if (ret)
		return ret;

	/* Mark state as dead in case we fail */
	WRITE_ONCE(realm->state, REALM_STATE_DEAD);

	if (!irqchip_in_kernel(kvm)) {
		/* Userspace irqchip not yet supported with realms */
		return -EOPNOTSUPP;
	}

	kvm_for_each_vcpu(i, vcpu, kvm) {
		ret = kvm_create_rec(vcpu);
		if (ret)
			return ret;
	}

	ret = set_ripas_of_protected_regions(kvm);
	if (ret)
		return ret;

	ret = rmi_realm_activate(virt_to_phys(realm->rd));
	if (ret)
		return -ENXIO;

	WRITE_ONCE(realm->state, REALM_STATE_ACTIVE);
	return 0;
}

void kvm_destroy_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
	int i;

	write_lock(&kvm->mmu_lock);
	kvm_stage2_unmap_range(&kvm->arch.mmu, 0,
			       BIT(realm->ia_bits - 1), true);
	write_unlock(&kvm->mmu_lock);
	kvm_realm_destroy_rtts(kvm);

	if (realm->params) {
		free_page((unsigned long)realm->params);
		realm->params = NULL;
	}

	if (!kvm_realm_is_created(kvm))
		return;

	WRITE_ONCE(realm->state, REALM_STATE_DYING);

	if (realm->rd) {
		phys_addr_t rd_phys = virt_to_phys(realm->rd);

		if (WARN_ON(rmi_realm_destroy(rd_phys)))
			return;
		free_delegated_granule(rd_phys);
		realm->rd = NULL;
	}

	rmi_vmid_release(realm->vmid);

	for (i = 0; i < pgd_size; i += RMM_PAGE_SIZE) {
		phys_addr_t pgd_phys = kvm->arch.mmu.pgd_phys + i;

		if (WARN_ON(rmi_granule_undelegate(pgd_phys)))
			return;
	}

	WRITE_ONCE(realm->state, REALM_STATE_DEAD);

	/* Now that the Realm is destroyed, free the entry level RTTs */
	kvm_free_stage2_pgd(&kvm->arch.mmu);
}

int kvm_init_realm_vm(struct kvm *kvm)
{
	kvm->arch.realm.params = (void *)get_zeroed_page(GFP_KERNEL);

	if (!kvm->arch.realm.params)
		return -ENOMEM;
	return 0;
}

void kvm_init_rmi(void)
{
	/* Only 4k page size on the host is supported */
	if (PAGE_SIZE != SZ_4K)
		return;

	/* Continue without realm support if we can't agree on a version */
	if (rmi_check_version())
		return;

	if (WARN_ON(rmi_features(0, &rmm_feat_reg0)))
		return;

	if (rmi_vmid_init())
		return;

	/* Future patch will enable static branch kvm_rmi_is_available */
}
