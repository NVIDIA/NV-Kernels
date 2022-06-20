// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#include <linux/kvm_host.h>
#include <linux/hugetlb.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/rmi_cmds.h>
#include <asm/virt.h>

#include <asm/kvm_pgtable.h>

static unsigned long rmm_feat_reg0;

static bool rme_supports(unsigned long feature)
{
	return !!u64_get_bits(rmm_feat_reg0, feature);
}

bool kvm_rme_supports_sve(void)
{
	return rme_supports(RMI_FEATURE_REGISTER_0_SVE_EN);
}

static int rmi_check_version(void)
{
	struct arm_smccc_res res;
	int version_major, version_minor;
	unsigned long host_version = RMI_ABI_VERSION(RMI_ABI_MAJOR_VERSION,
						     RMI_ABI_MINOR_VERSION);

	arm_smccc_1_1_invoke(SMC_RMI_VERSION, host_version, &res);

	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		return -ENXIO;

	version_major = RMI_ABI_VERSION_GET_MAJOR(res.a1);
	version_minor = RMI_ABI_VERSION_GET_MINOR(res.a1);

	if (res.a0 != RMI_SUCCESS) {
		kvm_err("Unsupported RMI ABI (v%d.%d) host supports v%d.%d\n",
			version_major, version_minor,
			RMI_ABI_MAJOR_VERSION,
			RMI_ABI_MINOR_VERSION);
		return -ENXIO;
	}

	kvm_info("RMI ABI version %d.%d\n", version_major, version_minor);

	return 0;
}

static phys_addr_t alloc_delegated_page(struct realm *realm,
					struct kvm_mmu_memory_cache *mc,
					gfp_t flags)
{
	phys_addr_t phys = PHYS_ADDR_MAX;
	void *virt;

	if (realm->spare_page != PHYS_ADDR_MAX) {
		swap(realm->spare_page, phys);
		goto out;
	}

	if (mc)
		virt = kvm_mmu_memory_cache_alloc(mc);
	else
		virt = (void *)__get_free_page(flags);

	if (!virt)
		goto out;

	phys = virt_to_phys(virt);

	if (rmi_granule_delegate(phys)) {
		free_page((unsigned long)virt);

		phys = PHYS_ADDR_MAX;
	}

out:
	return phys;
}

static void free_delegated_page(struct realm *realm, phys_addr_t phys)
{
	if (realm->spare_page == PHYS_ADDR_MAX) {
		realm->spare_page = phys;
		return;
	}

	if (WARN_ON(rmi_granule_undelegate(phys))) {
		/* Undelegate failed: leak the page */
		return;
	}

	free_page((unsigned long)phys_to_virt(phys));
}

int realm_psci_complete(struct kvm_vcpu *calling, struct kvm_vcpu *target,
			unsigned long status)
{
	int ret;

	ret = rmi_psci_complete(virt_to_phys(calling->arch.rec.rec_page),
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
	addr = ALIGN_DOWN(addr, rme_rtt_level_mapsize(level - 1));
	return rmi_rtt_create(virt_to_phys(realm->rd), phys, addr, level);
}

static int realm_rtt_fold(struct realm *realm,
			  unsigned long addr,
			  int level,
			  phys_addr_t *rtt_granule)
{
	unsigned long out_rtt;
	int ret;

	ret = rmi_rtt_fold(virt_to_phys(realm->rd), addr, level, &out_rtt);

	if (RMI_RETURN_STATUS(ret) == RMI_SUCCESS && rtt_granule)
		*rtt_granule = out_rtt;

	return ret;
}

static int realm_destroy_protected(struct realm *realm,
				   unsigned long ipa,
				   unsigned long *next_addr)
{
	unsigned long rd = virt_to_phys(realm->rd);
	unsigned long addr;
	phys_addr_t rtt;
	int ret;

loop:
	ret = rmi_data_destroy(rd, ipa, &addr, next_addr);
	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		if (*next_addr > ipa)
			return 0; /* UNASSIGNED */
		rtt = alloc_delegated_page(realm, NULL, GFP_KERNEL);
		if (WARN_ON(rtt == PHYS_ADDR_MAX))
			return -1;
		/*
		 * ASSIGNED - ipa is mapped as a block, so split. The index
		 * from the return code should be 2 otherwise it appears
		 * there's a huge page bigger than allowed
		 */
		WARN_ON(RMI_RETURN_INDEX(ret) != 2);
		ret = realm_rtt_create(realm, ipa, 3, rtt);
		if (WARN_ON(ret)) {
			free_delegated_page(realm, rtt);
			return -1;
		}
		/* retry */
		goto loop;
	} else if (WARN_ON(ret)) {
		return -1;
	}
	ret = rmi_granule_undelegate(addr);

	/*
	 * If the undelegate fails then something has gone seriously
	 * wrong: take an extra reference to just leak the page
	 */
	if (!WARN_ON(ret))
		put_page(phys_to_page(addr));

	return 0;
}

static void realm_unmap_range_shared(struct kvm *kvm,
				     int level,
				     unsigned long start,
				     unsigned long end)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long rd = virt_to_phys(realm->rd);
	ssize_t map_size = rme_rtt_level_mapsize(level);
	unsigned long next_addr, addr;
	unsigned long shared_bit = BIT(realm->ia_bits - 1);

	if (WARN_ON(level > RME_RTT_MAX_LEVEL))
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
			realm_unmap_range_shared(kvm, level + 1, addr,
						 min(next_addr, end));
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
				realm_unmap_range_shared(kvm, level + 1, addr,
							 next_addr);
			}
			break;
		default:
			WARN_ON(1);
			return;
		}
	}
}

static void realm_unmap_range_private(struct kvm *kvm,
				      unsigned long start,
				      unsigned long end)
{
	struct realm *realm = &kvm->arch.realm;
	ssize_t map_size = RME_PAGE_SIZE;
	unsigned long next_addr, addr;

	for (addr = start; addr < end; addr = next_addr) {
		int ret;

		next_addr = ALIGN(addr + 1, map_size);

		ret = realm_destroy_protected(realm, addr, &next_addr);

		if (WARN_ON(ret))
			break;
	}
}

static int get_start_level(struct realm *realm)
{
	return 4 - stage2_pgtable_levels(realm->ia_bits);
}

static void realm_unmap_range(struct kvm *kvm,
			      unsigned long start,
			      unsigned long end,
			      bool unmap_private)
{
	struct realm *realm = &kvm->arch.realm;

	if (realm->state == REALM_STATE_NONE)
		return;

	realm_unmap_range_shared(kvm, get_start_level(realm), start, end);
	if (unmap_private)
		realm_unmap_range_private(kvm, start, end);
}

u32 kvm_realm_ipa_limit(void)
{
	return u64_get_bits(rmm_feat_reg0, RMI_FEATURE_REGISTER_0_S2SZ);
}

u8 kvm_realm_max_pmu_counters(void)
{
	return u64_get_bits(rmm_feat_reg0, RMI_FEATURE_REGISTER_0_PMU_NUM_CTRS);
}

unsigned int kvm_realm_sve_max_vl(void)
{
	return sve_vl_from_vq(u64_get_bits(rmm_feat_reg0,
					   RMI_FEATURE_REGISTER_0_SVE_VL) + 1);
}

u64 kvm_realm_reset_id_aa64dfr0_el1(struct kvm_vcpu *vcpu, u64 val)
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

static int realm_init_sve_param(struct kvm *kvm, struct realm_params *params)
{
	int ret = 0;
	unsigned long i;
	struct kvm_vcpu *vcpu;
	int max_vl, realm_max_vl = -1;

	/*
	 * Get the preferred SVE configuration, set by userspace with the
	 * KVM_ARM_VCPU_SVE feature and KVM_REG_ARM64_SVE_VLS pseudo-register.
	 */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		mutex_lock(&vcpu->mutex);
		if (vcpu_has_sve(vcpu)) {
			if (!kvm_arm_vcpu_sve_finalized(vcpu))
				ret = -EINVAL;
			max_vl = vcpu->arch.sve_max_vl;
		} else {
			max_vl = 0;
		}
		mutex_unlock(&vcpu->mutex);
		if (ret)
			return ret;

		/* We need all vCPUs to have the same SVE config */
		if (realm_max_vl >= 0 && realm_max_vl != max_vl)
			return -EINVAL;

		realm_max_vl = max_vl;
	}

	if (realm_max_vl > 0) {
		params->sve_vl = sve_vq_from_vl(realm_max_vl) - 1;
		params->flags |= RMI_REALM_PARAM_FLAG_SVE;
	}
	return 0;
}

static int realm_create_rd(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct realm_params *params = realm->params;
	void *rd = NULL;
	phys_addr_t rd_phys, params_phys;
	struct kvm_pgtable *pgt = kvm->arch.mmu.pgt;
	u64 dfr0 = kvm_read_vm_id_reg(kvm, SYS_ID_AA64DFR0_EL1);
	int i, r;

	if (WARN_ON(realm->rd) || WARN_ON(!realm->params))
		return -EEXIST;

	rd = (void *)__get_free_page(GFP_KERNEL);
	if (!rd)
		return -ENOMEM;

	rd_phys = virt_to_phys(rd);
	if (rmi_granule_delegate(rd_phys)) {
		r = -ENXIO;
		goto free_rd;
	}

	for (i = 0; i < pgt->pgd_pages; i++) {
		phys_addr_t pgd_phys = kvm->arch.mmu.pgd_phys + i * PAGE_SIZE;

		if (rmi_granule_delegate(pgd_phys)) {
			r = -ENXIO;
			goto out_undelegate_tables;
		}
	}

	realm->ia_bits = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);

	params->s2sz = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);
	params->rtt_level_start = get_start_level(realm);
	params->rtt_num_start = pgt->pgd_pages;
	params->rtt_base = kvm->arch.mmu.pgd_phys;
	params->vmid = realm->vmid;
	params->num_bps = SYS_FIELD_GET(ID_AA64DFR0_EL1, BRPs, dfr0);
	params->num_wps = SYS_FIELD_GET(ID_AA64DFR0_EL1, WRPs, dfr0);

	if (kvm->arch.arm_pmu) {
		params->pmu_num_ctrs = kvm->arch.pmcr_n;
		params->flags |= RMI_REALM_PARAM_FLAG_PMU;
	}

	r = realm_init_sve_param(kvm, params);
	if (r)
		goto out_undelegate_tables;

	params_phys = virt_to_phys(params);

	if (rmi_realm_create(rd_phys, params_phys)) {
		r = -ENXIO;
		goto out_undelegate_tables;
	}

	realm->rd = rd;
	realm->spare_page = PHYS_ADDR_MAX;

	if (WARN_ON(rmi_rec_aux_count(rd_phys, &realm->num_aux))) {
		WARN_ON(rmi_realm_destroy(rd_phys));
		goto out_undelegate_tables;
	}

	return 0;

out_undelegate_tables:
	while (--i >= 0) {
		phys_addr_t pgd_phys = kvm->arch.mmu.pgd_phys + i * PAGE_SIZE;

		WARN_ON(rmi_granule_undelegate(pgd_phys));
	}
	WARN_ON(rmi_granule_undelegate(rd_phys));
free_rd:
	free_page((unsigned long)rd);
	return r;
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
	if (WARN_ON(level == max_level))
		return 0;

	while (level++ < max_level) {
		phys_addr_t rtt = alloc_delegated_page(realm, mc, GFP_KERNEL);

		if (rtt == PHYS_ADDR_MAX)
			return -ENOMEM;

		if (realm_rtt_create(realm, ipa, level, rtt)) {
			free_delegated_page(realm, rtt);
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

	if (WARN_ON(level > RME_RTT_MAX_LEVEL))
		return -EINVAL;

	map_size = rme_rtt_level_mapsize(level - 1);

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
			if (!WARN_ON(rmi_granule_undelegate(rtt_granule)))
				free_page((unsigned long)phys_to_virt(rtt_granule));
			break;
		case RMI_ERROR_RTT:
			if (next_addr > addr) {
				/* Missing RTT, skip */
				break;
			}
			if (WARN_ON(RMI_RETURN_INDEX(ret) != level))
				return -EBUSY;
			/*
			 * We tear down the RTT range for the full IPA
			 * space, after everything is unmapped. Also we
			 * descend down only if we cannot tear down a
			 * top level RTT. Thus RMM must be able to walk
			 * to the requested level. e.g., a block mapping
			 * exists at L1 or L2.
			 */
			if (WARN_ON(level == RME_RTT_MAX_LEVEL))
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

	if (WARN_ON(level > RME_RTT_MAX_LEVEL))
		return -EINVAL;

	map_size = rme_rtt_level_mapsize(level - 1);

	for (addr = start; addr < end; addr = next_addr) {
		phys_addr_t rtt_granule;
		int ret;
		unsigned long align_addr = ALIGN(addr, map_size);

		next_addr = ALIGN(addr + 1, map_size);

		ret = realm_rtt_fold(realm, align_addr, level, &rtt_granule);

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			if (!WARN_ON(rmi_granule_undelegate(rtt_granule)))
				free_page((unsigned long)phys_to_virt(rtt_granule));
			break;
		case RMI_ERROR_RTT:
			if (level == RME_RTT_MAX_LEVEL ||
			    RMI_RETURN_INDEX(ret) < level) {
				not_folded++;
				break;
			}
			/* Recurse a level deeper */
			ret = realm_fold_rtt_level(realm,
						   level + 1,
						   addr,
						   next_addr);
			if (ret < 0)
				return ret;
			else if (ret == 0)
				/* Try again at this level */
				next_addr = addr;
			break;
		default:
			WARN_ON(1);
			return -ENXIO;
		}
	}

	return not_folded;
}

static int realm_fold_rtt_range(struct realm *realm,
				unsigned long start, unsigned long end)
{
	return realm_fold_rtt_level(realm, get_start_level(realm) + 1,
				    start, end);
}

static void ensure_spare_page(struct realm *realm)
{
	phys_addr_t tmp_rtt;

	/*
	 * Make sure we have a spare delegated page for tearing down the
	 * block mappings. We do this by allocating then freeing a page.
	 * We must use Atomic allocations as we are called with kvm->mmu_lock
	 * held.
	 */
	tmp_rtt = alloc_delegated_page(realm, NULL, GFP_ATOMIC);

	/*
	 * If the allocation failed, continue as we may not have a block level
	 * mapping so it may not be fatal, otherwise free it to assign it
	 * to the spare page.
	 */
	if (tmp_rtt != PHYS_ADDR_MAX)
		free_delegated_page(realm, tmp_rtt);
}

void kvm_realm_destroy_rtts(struct kvm *kvm, u32 ia_bits)
{
	struct realm *realm = &kvm->arch.realm;

	WARN_ON(realm_tear_down_rtt_range(realm, 0, (1UL << ia_bits)));
}

void kvm_realm_unmap_range(struct kvm *kvm, unsigned long ipa, u64 size,
			   bool unmap_private)
{
	unsigned long end = ipa + size;
	struct realm *realm = &kvm->arch.realm;

	end = min(BIT(realm->ia_bits - 1), end);

	ensure_spare_page(realm);

	realm_unmap_range(kvm, ipa, end, unmap_private);

	if (unmap_private)
		realm_fold_rtt_range(realm, ipa, end);
}

static int realm_create_protected_data_page(struct realm *realm,
					    unsigned long ipa,
					    struct page *dst_page,
					    struct page *src_page,
					    unsigned long flags)
{
	phys_addr_t dst_phys, src_phys;
	int ret;

	dst_phys = page_to_phys(dst_page);
	src_phys = page_to_phys(src_page);

	if (rmi_granule_delegate(dst_phys))
		return -ENXIO;

	ret = rmi_data_create(virt_to_phys(realm->rd), dst_phys, ipa, src_phys,
			      flags);

	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		/* Create missing RTTs and retry */
		int level = RMI_RETURN_INDEX(ret);

		ret = realm_create_rtt_levels(realm, ipa, level,
					      RME_RTT_MAX_LEVEL, NULL);
		if (ret)
			goto err;

		ret = rmi_data_create(virt_to_phys(realm->rd), dst_phys, ipa,
				      src_phys, flags);
	}

	if (!ret)
		return 0;

err:
	if (WARN_ON(rmi_granule_undelegate(dst_phys))) {
		/* Page can't be returned to NS world so is lost */
		get_page(dst_page);
	}
	return -ENXIO;
}

static int fold_rtt(struct realm *realm, unsigned long addr, int level)
{
	phys_addr_t rtt_addr;
	int ret;

	ret = realm_rtt_fold(realm, addr, level + 1, &rtt_addr);
	if (ret)
		return ret;

	free_delegated_page(realm, rtt_addr);

	return 0;
}

static phys_addr_t rtt_get_phys(struct realm *realm, struct rtt_entry *rtt)
{
	/* FIXME: For now LPA2 isn't supported in a realm guest */
	bool lpa2 = false;

	if (lpa2)
		return rtt->desc & GENMASK(49, 12);
	return rtt->desc & GENMASK(47, 12);
}

int realm_map_protected(struct realm *realm,
			unsigned long base_ipa,
			struct page *dst_page,
			unsigned long map_size,
			struct kvm_mmu_memory_cache *memcache)
{
	phys_addr_t dst_phys = page_to_phys(dst_page);
	phys_addr_t rd = virt_to_phys(realm->rd);
	unsigned long phys = dst_phys;
	unsigned long ipa = base_ipa;
	unsigned long size;
	int map_level;
	int ret = 0;

	if (WARN_ON(!IS_ALIGNED(ipa, map_size)))
		return -EINVAL;

	switch (map_size) {
	case PAGE_SIZE:
		map_level = 3;
		break;
	case RME_L2_BLOCK_SIZE:
		map_level = 2;
		break;
	default:
		return -EINVAL;
	}

	if (map_level < RME_RTT_MAX_LEVEL) {
		/*
		 * A temporary RTT is needed during the map, precreate it,
		 * however if there is an error (e.g. missing parent tables)
		 * this will be handled below.
		 */
		realm_create_rtt_levels(realm, ipa, map_level,
					RME_RTT_MAX_LEVEL, memcache);
	}

	for (size = 0; size < map_size; size += PAGE_SIZE) {
		if (rmi_granule_delegate(phys)) {
			struct rtt_entry rtt;

			/*
			 * It's possible we raced with another VCPU on the same
			 * fault. If the entry exists and matches then exit
			 * early and assume the other VCPU will handle the
			 * mapping.
			 */
			if (rmi_rtt_read_entry(rd, ipa, RME_RTT_MAX_LEVEL, &rtt))
				goto err;

			/*
			 * FIXME: For a block mapping this could race at level
			 * 2 or 3... currently we don't support block mappings
			 */
			if (WARN_ON((rtt.walk_level != RME_RTT_MAX_LEVEL ||
				     rtt.state != RMI_ASSIGNED ||
				     rtt_get_phys(realm, &rtt) != phys))) {
				goto err;
			}

			return 0;
		}

		ret = rmi_data_create_unknown(rd, phys, ipa);

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			/* Create missing RTTs and retry */
			int level = RMI_RETURN_INDEX(ret);

			ret = realm_create_rtt_levels(realm, ipa, level,
						      RME_RTT_MAX_LEVEL,
						      memcache);
			WARN_ON(ret);
			if (ret)
				goto err_undelegate;

			ret = rmi_data_create_unknown(rd, phys, ipa);
		}
		WARN_ON(ret);

		if (ret)
			goto err_undelegate;

		phys += PAGE_SIZE;
		ipa += PAGE_SIZE;
	}

	if (map_size == RME_L2_BLOCK_SIZE)
		ret = fold_rtt(realm, base_ipa, map_level);
	if (WARN_ON(ret))
		goto err;

	return 0;

err_undelegate:
	if (WARN_ON(rmi_granule_undelegate(phys))) {
		/* Page can't be returned to NS world so is lost */
		get_page(phys_to_page(phys));
	}
err:
	while (size > 0) {
		unsigned long data, top;

		phys -= PAGE_SIZE;
		size -= PAGE_SIZE;
		ipa -= PAGE_SIZE;

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
			 struct page *page,
			 unsigned long map_size,
			 struct kvm_mmu_memory_cache *memcache)
{
	phys_addr_t rd = virt_to_phys(realm->rd);
	int map_level;
	int ret = 0;
	unsigned long desc = page_to_phys(page) |
			     PTE_S2_MEMATTR(MT_S2_FWB_NORMAL) |
			     /* FIXME: Read+Write permissions for now */
			     (3 << 6);

	if (WARN_ON(!IS_ALIGNED(ipa, map_size)))
		return -EINVAL;

	switch (map_size) {
	case PAGE_SIZE:
		map_level = 3;
		break;
	case RME_L2_BLOCK_SIZE:
		map_level = 2;
		break;
	default:
		return -EINVAL;
	}

	ret = rmi_rtt_map_unprotected(rd, ipa, map_level, desc);

	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		/* Create missing RTTs and retry */
		int level = RMI_RETURN_INDEX(ret);

		ret = realm_create_rtt_levels(realm, ipa, level, map_level,
					      memcache);
		if (WARN_ON(ret))
			return -ENXIO;

		ret = rmi_rtt_map_unprotected(rd, ipa, map_level, desc);
	}
	if (WARN_ON(ret))
		return -ENXIO;

	return 0;
}

static int populate_par_region(struct kvm *kvm,
			       phys_addr_t ipa_base,
			       phys_addr_t ipa_end,
			       u32 flags)
{
	struct realm *realm = &kvm->arch.realm;
	struct kvm_memory_slot *memslot;
	gfn_t base_gfn, end_gfn;
	int idx;
	phys_addr_t ipa;
	int ret = 0;
	unsigned long data_flags = 0;

	base_gfn = gpa_to_gfn(ipa_base);
	end_gfn = gpa_to_gfn(ipa_end);

	if (flags & KVM_ARM_RME_POPULATE_FLAGS_MEASURE)
		data_flags = RMI_MEASURE_CONTENT;

	idx = srcu_read_lock(&kvm->srcu);
	memslot = gfn_to_memslot(kvm, base_gfn);
	if (!memslot) {
		ret = -EFAULT;
		goto out;
	}

	/* We require the region to be contained within a single memslot */
	if (memslot->base_gfn + memslot->npages < end_gfn) {
		ret = -EINVAL;
		goto out;
	}

	if (!kvm_slot_can_be_private(memslot)) {
		ret = -EINVAL;
		goto out;
	}

	mmap_read_lock(current->mm);

	ipa = ipa_base;
	while (ipa < ipa_end) {
		struct vm_area_struct *vma;
		unsigned long map_size;
		unsigned int vma_shift;
		unsigned long offset;
		unsigned long hva;
		struct page *page;
		kvm_pfn_t pfn;
		int level;

		hva = gfn_to_hva_memslot(memslot, gpa_to_gfn(ipa));
		vma = vma_lookup(current->mm, hva);
		if (!vma) {
			ret = -EFAULT;
			break;
		}

		/* FIXME: Currently we only support 4k sized mappings */
		vma_shift = PAGE_SHIFT;

		map_size = 1 << vma_shift;

		ipa = ALIGN_DOWN(ipa, map_size);

		switch (map_size) {
		case RME_L2_BLOCK_SIZE:
			level = 2;
			break;
		case PAGE_SIZE:
			level = 3;
			break;
		default:
			WARN_ONCE(1, "Unsupported vma_shift %d", vma_shift);
			ret = -EFAULT;
			break;
		}

		pfn = gfn_to_pfn_memslot(memslot, gpa_to_gfn(ipa));

		if (is_error_pfn(pfn)) {
			ret = -EFAULT;
			break;
		}

		if (level < RME_RTT_MAX_LEVEL) {
			/*
			 * A temporary RTT is needed during the map, precreate
			 * it, however if there is an error (e.g. missing
			 * parent tables) this will be handled in the
			 * realm_create_protected_data_page() call.
			 */
			realm_create_rtt_levels(realm, ipa, level,
						RME_RTT_MAX_LEVEL, NULL);
		}

		page = pfn_to_page(pfn);

		for (offset = 0; offset < map_size && !ret;
		     offset += PAGE_SIZE, page++) {
			phys_addr_t page_ipa = ipa + offset;
			kvm_pfn_t priv_pfn;
			int order;

			ret = kvm_gmem_get_pfn(kvm, memslot,
					       page_ipa >> PAGE_SHIFT,
					       &priv_pfn, &order);
			if (ret)
				break;

			ret = realm_create_protected_data_page(realm, page_ipa,
							       pfn_to_page(priv_pfn),
							       page, data_flags);
		}

		kvm_release_pfn_clean(pfn);

		if (ret)
			break;

		if (level == 2)
			fold_rtt(realm, ipa, level);

		ipa += map_size;
	}

	mmap_read_unlock(current->mm);

out:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

static int kvm_populate_realm(struct kvm *kvm,
			      struct kvm_cap_arm_rme_populate_realm_args *args)
{
	phys_addr_t ipa_base, ipa_end;

	if (kvm_realm_state(kvm) != REALM_STATE_NEW)
		return -EINVAL;

	if (!IS_ALIGNED(args->populate_ipa_base, PAGE_SIZE) ||
	    !IS_ALIGNED(args->populate_ipa_size, PAGE_SIZE))
		return -EINVAL;

	if (args->flags & ~RMI_MEASURE_CONTENT)
		return -EINVAL;

	ipa_base = args->populate_ipa_base;
	ipa_end = ipa_base + args->populate_ipa_size;

	if (ipa_end < ipa_base)
		return -EINVAL;

	return populate_par_region(kvm, ipa_base, ipa_end, args->flags);
}

static int find_map_level(struct realm *realm,
			  unsigned long start,
			  unsigned long end)
{
	int level = RME_RTT_MAX_LEVEL;

	while (level > get_start_level(realm)) {
		unsigned long map_size = rme_rtt_level_mapsize(level - 1);

		if (!IS_ALIGNED(start, map_size) ||
		    (start + map_size) > end)
			break;

		level--;
	}

	return level;
}

int realm_set_ipa_state(struct kvm_vcpu *vcpu,
			unsigned long start,
			unsigned long end,
			unsigned long ripas,
			unsigned long *top_ipa)
{
	struct kvm *kvm = vcpu->kvm;
	struct realm *realm = &kvm->arch.realm;
	struct realm_rec *rec = &vcpu->arch.rec;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	phys_addr_t rec_phys = virt_to_phys(rec->rec_page);
	struct kvm_mmu_memory_cache *memcache = &vcpu->arch.mmu_page_cache;
	unsigned long ipa = start;
	int ret = 0;

	while (ipa < end) {
		unsigned long next;

		ret = rmi_rtt_set_ripas(rd_phys, rec_phys, ipa, end, &next);

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			int walk_level = RMI_RETURN_INDEX(ret);
			int level = find_map_level(realm, ipa, end);

			/*
			 * If the RMM walk ended early then more tables are
			 * needed to reach the required depth to set the RIPAS.
			 */
			if (walk_level < level) {
				ret = realm_create_rtt_levels(realm, ipa,
							      walk_level,
							      level,
							      memcache);
				/* Retry with RTTs created */
				if (!ret)
					continue;
			} else {
				ret = -EINVAL;
			}

			break;
		} else if (RMI_RETURN_STATUS(ret) != RMI_SUCCESS) {
			WARN(1, "Unexpected error in %s: %#x\n", __func__,
			     ret);
			ret = -EINVAL;
			break;
		}
		ipa = next;
	}

	*top_ipa = ipa;

	if (ripas == RMI_EMPTY && ipa != start) {
		realm_unmap_range_private(kvm, start, ipa);
		realm_fold_rtt_range(realm, start, ipa);
	}

	return ret;
}

static int realm_init_ipa_state(struct realm *realm,
				unsigned long ipa,
				unsigned long end)
{
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	int ret;

	while (ipa < end) {
		unsigned long next;

		ret = rmi_rtt_init_ripas(rd_phys, ipa, end, &next);

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			int err_level = RMI_RETURN_INDEX(ret);
			int level = find_map_level(realm, ipa, end);

			if (WARN_ON(err_level >= level))
				return -ENXIO;

			ret = realm_create_rtt_levels(realm, ipa,
						      err_level,
						      level, NULL);
			if (ret)
				return ret;
			/* Retry with the RTT levels in place */
			continue;
		} else if (WARN_ON(ret)) {
			return -ENXIO;
		}

		ipa = next;
	}

	return 0;
}

static int kvm_init_ipa_range_realm(struct kvm *kvm,
				    struct kvm_cap_arm_rme_init_ipa_args *args)
{
	gpa_t addr, end;
	struct realm *realm = &kvm->arch.realm;

	addr = args->init_ipa_base;
	end = addr + args->init_ipa_size;

	if (end < addr)
		return -EINVAL;

	if (kvm_realm_state(kvm) != REALM_STATE_NEW)
		return -EINVAL;

	return realm_init_ipa_state(realm, addr, end);
}

static int kvm_activate_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;

	if (kvm_realm_state(kvm) != REALM_STATE_NEW)
		return -EINVAL;

	if (rmi_realm_activate(virt_to_phys(realm->rd)))
		return -ENXIO;

	WRITE_ONCE(realm->state, REALM_STATE_ACTIVE);
	return 0;
}

/* Protects access to rme_vmid_bitmap */
static DEFINE_SPINLOCK(rme_vmid_lock);
static unsigned long *rme_vmid_bitmap;

static int rme_vmid_init(void)
{
	unsigned int vmid_count = 1 << kvm_get_vmid_bits();

	rme_vmid_bitmap = bitmap_zalloc(vmid_count, GFP_KERNEL);
	if (!rme_vmid_bitmap) {
		kvm_err("%s: Couldn't allocate rme vmid bitmap\n", __func__);
		return -ENOMEM;
	}

	return 0;
}

static int rme_vmid_reserve(void)
{
	int ret;
	unsigned int vmid_count = 1 << kvm_get_vmid_bits();

	spin_lock(&rme_vmid_lock);
	ret = bitmap_find_free_region(rme_vmid_bitmap, vmid_count, 0);
	spin_unlock(&rme_vmid_lock);

	return ret;
}

static void rme_vmid_release(unsigned int vmid)
{
	spin_lock(&rme_vmid_lock);
	bitmap_release_region(rme_vmid_bitmap, vmid, 0);
	spin_unlock(&rme_vmid_lock);
}

static int kvm_create_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	int ret;

	if (!kvm_is_realm(kvm))
		return -EINVAL;
	if (kvm_realm_is_created(kvm))
		return -EEXIST;

	ret = rme_vmid_reserve();
	if (ret < 0)
		return ret;
	realm->vmid = ret;

	ret = realm_create_rd(kvm);
	if (ret) {
		rme_vmid_release(realm->vmid);
		return ret;
	}

	WRITE_ONCE(realm->state, REALM_STATE_NEW);

	/* The realm is up, free the parameters.  */
	free_page((unsigned long)realm->params);
	realm->params = NULL;

	return 0;
}

static int config_realm_hash_algo(struct realm *realm,
				  struct kvm_cap_arm_rme_config_item *cfg)
{
	switch (cfg->hash_algo) {
	case KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA256:
		if (!rme_supports(RMI_FEATURE_REGISTER_0_HASH_SHA_256))
			return -EINVAL;
		break;
	case KVM_CAP_ARM_RME_MEASUREMENT_ALGO_SHA512:
		if (!rme_supports(RMI_FEATURE_REGISTER_0_HASH_SHA_512))
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}
	realm->params->hash_algo = cfg->hash_algo;
	return 0;
}

static int kvm_rme_config_realm(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	struct kvm_cap_arm_rme_config_item cfg;
	struct realm *realm = &kvm->arch.realm;
	int r = 0;

	if (kvm_realm_is_created(kvm))
		return -EBUSY;

	if (copy_from_user(&cfg, (void __user *)cap->args[1], sizeof(cfg)))
		return -EFAULT;

	switch (cfg.cfg) {
	case KVM_CAP_ARM_RME_CFG_RPV:
		memcpy(&realm->params->rpv, &cfg.rpv, sizeof(cfg.rpv));
		break;
	case KVM_CAP_ARM_RME_CFG_HASH_ALGO:
		r = config_realm_hash_algo(realm, &cfg);
		break;
	default:
		r = -EINVAL;
	}

	return r;
}

int kvm_realm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	int r = 0;

	if (!kvm_is_realm(kvm))
		return -EINVAL;

	switch (cap->args[0]) {
	case KVM_CAP_ARM_RME_CONFIG_REALM:
		r = kvm_rme_config_realm(kvm, cap);
		break;
	case KVM_CAP_ARM_RME_CREATE_RD:
		r = kvm_create_realm(kvm);
		break;
	case KVM_CAP_ARM_RME_INIT_IPA_REALM: {
		struct kvm_cap_arm_rme_init_ipa_args args;
		void __user *argp = u64_to_user_ptr(cap->args[1]);

		if (copy_from_user(&args, argp, sizeof(args))) {
			r = -EFAULT;
			break;
		}

		r = kvm_init_ipa_range_realm(kvm, &args);
		break;
	}
	case KVM_CAP_ARM_RME_POPULATE_REALM: {
		struct kvm_cap_arm_rme_populate_realm_args args;
		void __user *argp = u64_to_user_ptr(cap->args[1]);

		if (copy_from_user(&args, argp, sizeof(args))) {
			r = -EFAULT;
			break;
		}

		r = kvm_populate_realm(kvm, &args);
		break;
	}
	case KVM_CAP_ARM_RME_ACTIVATE_REALM:
		r = kvm_activate_realm(kvm);
		break;
	default:
		r = -EINVAL;
		break;
	}

	return r;
}

void kvm_destroy_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct kvm_pgtable *pgt = kvm->arch.mmu.pgt;
	int i;

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
		if (WARN_ON(rmi_granule_undelegate(rd_phys)))
			return;
		free_page((unsigned long)realm->rd);
		realm->rd = NULL;
	}

	rme_vmid_release(realm->vmid);

	if (realm->spare_page != PHYS_ADDR_MAX) {
		/* Leak the page if the undelegate fails */
		if (!WARN_ON(rmi_granule_undelegate(realm->spare_page)))
			free_page((unsigned long)phys_to_virt(realm->spare_page));
		realm->spare_page = PHYS_ADDR_MAX;
	}

	for (i = 0; i < pgt->pgd_pages; i++) {
		phys_addr_t pgd_phys = kvm->arch.mmu.pgd_phys + i * PAGE_SIZE;

		if (WARN_ON(rmi_granule_undelegate(pgd_phys)))
			return;

		clear_page(phys_to_virt(pgd_phys));
	}

	WRITE_ONCE(realm->state, REALM_STATE_DEAD);

	/* Now that the Realm is destroyed, free the entry level RTTs */
	kvm_free_stage2_pgd(&kvm->arch.mmu);
}

int kvm_rec_enter(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;

	switch (rec->run->exit.exit_reason) {
	case RMI_EXIT_HOST_CALL:
	case RMI_EXIT_PSCI:
		for (int i = 0; i < REC_RUN_GPRS; i++)
			rec->run->enter.gprs[i] = vcpu_get_reg(vcpu, i);
		break;
	}

	if (kvm_realm_state(vcpu->kvm) != REALM_STATE_ACTIVE)
		return -EINVAL;

	return rmi_rec_enter(virt_to_phys(rec->rec_page),
			     virt_to_phys(rec->run));
}

static void free_rec_aux(struct page **aux_pages,
			 unsigned int num_aux)
{
	unsigned int i;

	for (i = 0; i < num_aux; i++) {
		phys_addr_t aux_page_phys = page_to_phys(aux_pages[i]);

		/* If the undelegate fails then leak the page */
		if (WARN_ON(rmi_granule_undelegate(aux_page_phys)))
			continue;

		__free_page(aux_pages[i]);
	}
}

static int alloc_rec_aux(struct page **aux_pages,
			 u64 *aux_phys_pages,
			 unsigned int num_aux)
{
	int ret;
	unsigned int i;

	for (i = 0; i < num_aux; i++) {
		struct page *aux_page;
		phys_addr_t aux_page_phys;

		aux_page = alloc_page(GFP_KERNEL);
		if (!aux_page) {
			ret = -ENOMEM;
			goto out_err;
		}
		aux_page_phys = page_to_phys(aux_page);
		if (rmi_granule_delegate(aux_page_phys)) {
			__free_page(aux_page);
			ret = -ENXIO;
			goto out_err;
		}
		aux_pages[i] = aux_page;
		aux_phys_pages[i] = aux_page_phys;
	}

	return 0;
out_err:
	free_rec_aux(aux_pages, i);
	return ret;
}

int kvm_create_rec(struct kvm_vcpu *vcpu)
{
	struct user_pt_regs *vcpu_regs = vcpu_gp_regs(vcpu);
	unsigned long mpidr = kvm_vcpu_get_mpidr_aff(vcpu);
	struct realm *realm = &vcpu->kvm->arch.realm;
	struct realm_rec *rec = &vcpu->arch.rec;
	unsigned long rec_page_phys;
	struct rec_params *params;
	int r, i;

	if (kvm_realm_state(vcpu->kvm) != REALM_STATE_NEW)
		return -ENOENT;

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

	/* If the undelegate fails then leak the REC page */
	if (WARN_ON(rmi_granule_undelegate(rec_page_phys)))
		return;

	free_page((unsigned long)rec->rec_page);
}

int kvm_init_realm_vm(struct kvm *kvm)
{
	struct realm_params *params;

	params = (struct realm_params *)get_zeroed_page(GFP_KERNEL);
	if (!params)
		return -ENOMEM;

	kvm->arch.realm.params = params;
	return 0;
}

void kvm_init_rme(void)
{
	if (PAGE_SIZE != SZ_4K)
		/* Only 4k page size on the host is supported */
		return;

	if (rmi_check_version())
		/* Continue without realm support */
		return;

	if (WARN_ON(rmi_features(0, &rmm_feat_reg0)))
		return;

	if (rme_vmid_init())
		return;

	static_branch_enable(&kvm_rme_is_available);
}
