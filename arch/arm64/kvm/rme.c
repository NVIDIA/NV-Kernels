// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#include <linux/kvm_host.h>

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

static int realm_create_rd(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct realm_params *params = realm->params;
	void *rd = NULL;
	phys_addr_t rd_phys, params_phys;
	struct kvm_pgtable *pgt = kvm->arch.mmu.pgt;
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

	/* Future patch will enable static branch kvm_rme_is_available */
}
