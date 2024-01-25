// SPDX-License-Identifier: GPL-2.0
/*
 * Implementation of the IOMMU SVA API for the ARM SMMUv3
 */

#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/mmu_notifier.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <kunit/visibility.h>

#include "arm-smmu-v3.h"
#include "../../io-pgtable-arm.h"

static DEFINE_MUTEX(sva_lock);

static int arm_smmu_realloc_s1_domain_asid(struct arm_smmu_device *smmu,
					   struct arm_smmu_domain *smmu_domain)
{
	struct arm_smmu_master_domain *master_domain;
	struct arm_smmu_cd target_cd;
	unsigned long flags;
	int ret;

	lockdep_assert_held(&smmu->asid_lock);

	/*
	 * FIXME: The unmap and invalidation path doesn't take any locks but
	 * this is not fully safe. Since updating the CD tables is not atomic
	 * there is always a hole where invalidating only one ASID of two active
	 * ASIDs during unmap will cause the IOTLB to become stale.
	 *
	 * This approach is to hopefully shift the racing CPUs to the new ASID
	 * before we start programming the HW. This increases the chance that
	 * racing IOPTE changes will pick up an invalidation for the new ASID
	 * and we achieve eventual consistency. For the brief period where the
	 * old ASID is still in the CD entries it will become incoherent.
	 */
	ret = xa_alloc(&smmu->asid_map, &smmu_domain->asid, smmu_domain,
		       XA_LIMIT(1, (1 << smmu->asid_bits) - 1), GFP_KERNEL);
	if (ret)
		return ret;

	spin_lock_irqsave(&smmu_domain->devices_lock, flags);
	list_for_each_entry(master_domain, &smmu_domain->devices, devices_elm) {
		struct arm_smmu_master *master = master_domain->master;
		struct arm_smmu_cd *cdptr;

		cdptr = arm_smmu_get_cd_ptr(master, master_domain->ssid);
		if (WARN_ON(!cdptr))
			continue;

		arm_smmu_make_s1_cd(&target_cd, master, smmu_domain);
		arm_smmu_write_cd_entry(master, master_domain->ssid, cdptr,
					&target_cd);
	}
	spin_unlock_irqrestore(&smmu_domain->devices_lock, flags);
	return 0;
}

static u64 page_size_to_cd(void)
{
	static_assert(PAGE_SIZE == SZ_4K || PAGE_SIZE == SZ_16K ||
		      PAGE_SIZE == SZ_64K);
	if (PAGE_SIZE == SZ_64K)
		return ARM_LPAE_TCR_TG0_64K;
	if (PAGE_SIZE == SZ_16K)
		return ARM_LPAE_TCR_TG0_16K;
	return ARM_LPAE_TCR_TG0_4K;
}

VISIBLE_IF_KUNIT
void arm_smmu_make_sva_cd(struct arm_smmu_cd *target,
			  struct arm_smmu_master *master, struct mm_struct *mm,
			  u16 asid, bool btm_invalidation)
{
	u64 par;

	memset(target, 0, sizeof(*target));

	par = cpuid_feature_extract_unsigned_field(
		read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1),
		ID_AA64MMFR0_EL1_PARANGE_SHIFT);

	target->data[0] = cpu_to_le64(
		CTXDESC_CD_0_TCR_EPD1 |
#ifdef __BIG_ENDIAN
		CTXDESC_CD_0_ENDI |
#endif
		CTXDESC_CD_0_V |
		FIELD_PREP(CTXDESC_CD_0_TCR_IPS, par) |
		CTXDESC_CD_0_AA64 |
		(master->stall_enabled ? CTXDESC_CD_0_S : 0) |
		CTXDESC_CD_0_R |
		CTXDESC_CD_0_A |
		(btm_invalidation ? 0 : CTXDESC_CD_0_ASET) |
		FIELD_PREP(CTXDESC_CD_0_ASID, asid));

	/*
	 * If no MM is passed then this creates a SVA entry that faults
	 * everything. arm_smmu_write_cd_entry() can hitlessly go between these
	 * two entries types since TTB0 is ignored by HW when EPD0 is set.
	 */
	if (mm) {
		target->data[0] |= cpu_to_le64(
			FIELD_PREP(CTXDESC_CD_0_TCR_T0SZ,
				   64ULL - vabits_actual) |
			FIELD_PREP(CTXDESC_CD_0_TCR_TG0, page_size_to_cd()) |
			FIELD_PREP(CTXDESC_CD_0_TCR_IRGN0,
				   ARM_LPAE_TCR_RGN_WBWA) |
			FIELD_PREP(CTXDESC_CD_0_TCR_ORGN0,
				   ARM_LPAE_TCR_RGN_WBWA) |
			FIELD_PREP(CTXDESC_CD_0_TCR_SH0, ARM_LPAE_TCR_SH_IS));

		target->data[1] = cpu_to_le64(virt_to_phys(mm->pgd) &
					      CTXDESC_CD_1_TTB0_MASK);
	} else {
		target->data[0] |= cpu_to_le64(CTXDESC_CD_0_TCR_EPD0);

		/*
		 * Disable stall and immediately generate an abort if stall
		 * disable is permitted. This speeds up cleanup for an unclean
		 * exit if the device is still doing a lot of DMA.
		 */
		if (!(master->smmu->features & ARM_SMMU_FEAT_STALL_FORCE))
			target->data[0] &=
				cpu_to_le64(~(CTXDESC_CD_0_S | CTXDESC_CD_0_R));
	}

	/*
	 * MAIR value is pretty much constant and global, so we can just get it
	 * from the current CPU register
	 */
	target->data[3] = cpu_to_le64(read_sysreg(mair_el1));
}
EXPORT_SYMBOL_IF_KUNIT(arm_smmu_make_sva_cd);

/*
 * Cloned from the MAX_TLBI_OPS in arch/arm64/include/asm/tlbflush.h, this
 * is used as a threshold to replace per-page TLBI commands to issue in the
 * command queue with an address-space TLBI command, when SMMU w/o a range
 * invalidation feature handles too many per-page TLBI commands, which will
 * otherwise result in a soft lockup.
 */
#define CMDQ_MAX_TLBI_OPS		(1 << (PAGE_SHIFT - 3))

static void arm_smmu_mm_arch_invalidate_secondary_tlbs(struct mmu_notifier *mn,
						struct mm_struct *mm,
						unsigned long start,
						unsigned long end)
{
	struct arm_smmu_domain *smmu_domain =
		container_of(mn, struct arm_smmu_domain, mmu_notifier);
	size_t size;

	/*
	 * The mm_types defines vm_end as the first byte after the end address,
	 * different from IOMMU subsystem using the last address of an address
	 * range. So do a simple translation here by calculating size correctly.
	 */
	size = end - start;
	if (!(smmu_domain->smmu->features & ARM_SMMU_FEAT_RANGE_INV)) {
		if (size >= CMDQ_MAX_TLBI_OPS * PAGE_SIZE)
			size = 0;
	} else {
		if (size == ULONG_MAX)
			size = 0;
	}

	if (!smmu_domain->btm_invalidation) {
		ioasid_t asid = READ_ONCE(smmu_domain->asid);

		if (!size)
			arm_smmu_tlb_inv_all_s1(smmu_domain);
		else
			arm_smmu_tlb_inv_range_asid(start, size, asid,
						    PAGE_SIZE, false,
						    smmu_domain);
	}

	arm_smmu_atc_inv_domain(smmu_domain, start, size);
}

static void arm_smmu_mm_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct arm_smmu_domain *smmu_domain =
		container_of(mn, struct arm_smmu_domain, mmu_notifier);
	struct arm_smmu_master_domain *master_domain;
	unsigned long flags;

	/*
	 * DMA may still be running. Keep the cd valid to avoid C_BAD_CD events,
	 * but disable translation.
	 */
	spin_lock_irqsave(&smmu_domain->devices_lock, flags);
	list_for_each_entry(master_domain, &smmu_domain->devices,
			    devices_elm) {
		struct arm_smmu_master *master = master_domain->master;
		struct arm_smmu_cd target;
		struct arm_smmu_cd *cdptr;

		cdptr = arm_smmu_get_cd_ptr(master, master_domain->ssid);
		if (WARN_ON(!cdptr))
			continue;

		/* An SVA ASID never changes, no asid_lock required */
		arm_smmu_make_sva_cd(&target, master, NULL,
				     smmu_domain->asid,
				     smmu_domain->btm_invalidation);
		arm_smmu_write_cd_entry(master, master_domain->ssid, cdptr,
					&target);
	}
	spin_unlock_irqrestore(&smmu_domain->devices_lock, flags);

	arm_smmu_tlb_inv_all_s1(smmu_domain);
	arm_smmu_atc_inv_domain(smmu_domain, 0, 0);
}

static void arm_smmu_mmu_notifier_free(struct mmu_notifier *mn)
{
	kfree(container_of(mn, struct arm_smmu_domain, mmu_notifier));
}

static const struct mmu_notifier_ops arm_smmu_mmu_notifier_ops = {
	.arch_invalidate_secondary_tlbs	= arm_smmu_mm_arch_invalidate_secondary_tlbs,
	.release			= arm_smmu_mm_release,
	.free_notifier			= arm_smmu_mmu_notifier_free,
};

bool arm_smmu_sva_supported(struct arm_smmu_device *smmu)
{
	unsigned long reg, fld;
	unsigned long oas;
	unsigned long asid_bits;
	u32 feat_mask = ARM_SMMU_FEAT_COHERENCY;

	if (vabits_actual == 52)
		feat_mask |= ARM_SMMU_FEAT_VAX;

	if ((smmu->features & feat_mask) != feat_mask)
		return false;

	if (!(smmu->pgsize_bitmap & PAGE_SIZE))
		return false;

	/*
	 * Get the smallest PA size of all CPUs (sanitized by cpufeature). We're
	 * not even pretending to support AArch32 here. Abort if the MMU outputs
	 * addresses larger than what we support.
	 */
	reg = read_sanitised_ftr_reg(SYS_ID_AA64MMFR0_EL1);
	fld = cpuid_feature_extract_unsigned_field(reg, ID_AA64MMFR0_EL1_PARANGE_SHIFT);
	oas = id_aa64mmfr0_parange_to_phys_shift(fld);
	if (smmu->oas < oas)
		return false;

	/* We can support bigger ASIDs than the CPU, but not smaller */
	fld = cpuid_feature_extract_unsigned_field(reg, ID_AA64MMFR0_EL1_ASIDBITS_SHIFT);
	asid_bits = fld ? 16 : 8;
	if (smmu->asid_bits < asid_bits)
		return false;

	/*
	 * See max_pinned_asids in arch/arm64/mm/context.c. The following is
	 * generally the maximum number of bindable processes.
	 */
	if (arm64_kernel_unmapped_at_el0())
		asid_bits--;
	dev_dbg(smmu->dev, "%d shared contexts\n", (1 << asid_bits) -
		num_possible_cpus() - 2);

	return true;
}

bool arm_smmu_master_iopf_supported(struct arm_smmu_master *master)
{
	/* We're not keeping track of SIDs in fault events */
	if (master->num_streams != 1)
		return false;

	return master->stall_enabled;
}

bool arm_smmu_master_sva_supported(struct arm_smmu_master *master)
{
	if (!(master->smmu->features & ARM_SMMU_FEAT_SVA))
		return false;

	/* SSID support is mandatory for the moment */
	return master->ssid_bits;
}

bool arm_smmu_master_sva_enabled(struct arm_smmu_master *master)
{
	bool enabled;

	mutex_lock(&sva_lock);
	enabled = master->sva_enabled;
	mutex_unlock(&sva_lock);
	return enabled;
}

static int arm_smmu_master_sva_enable_iopf(struct arm_smmu_master *master)
{
	struct device *dev = master->dev;

	/*
	 * Drivers for devices supporting PRI or stall should enable IOPF first.
	 * Others have device-specific fault handlers and don't need IOPF.
	 */
	if (!arm_smmu_master_iopf_supported(master))
		return 0;

	if (!master->iopf_enabled)
		return -EINVAL;

	return iopf_queue_add_device(master->smmu->evtq.iopf, dev);
}

static void arm_smmu_master_sva_disable_iopf(struct arm_smmu_master *master)
{
	struct device *dev = master->dev;

	if (!master->iopf_enabled)
		return;

	iopf_queue_remove_device(master->smmu->evtq.iopf, dev);
}

int arm_smmu_master_enable_sva(struct arm_smmu_master *master)
{
	int ret;

	mutex_lock(&sva_lock);
	ret = arm_smmu_master_sva_enable_iopf(master);
	if (!ret)
		master->sva_enabled = true;
	mutex_unlock(&sva_lock);

	return ret;
}

int arm_smmu_master_disable_sva(struct arm_smmu_master *master)
{
	mutex_lock(&sva_lock);
	arm_smmu_master_sva_disable_iopf(master);
	master->sva_enabled = false;
	mutex_unlock(&sva_lock);

	return 0;
}

void arm_smmu_sva_notifier_synchronize(void)
{
	/*
	 * Some MMU notifiers may still be waiting to be freed, using
	 * arm_smmu_mmu_notifier_free(). Wait for them.
	 */
	mmu_notifier_synchronize();
}

static int arm_smmu_sva_set_dev_pasid(struct iommu_domain *domain,
				      struct device *dev, ioasid_t id)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);
	struct arm_smmu_cd target;
	int ret;

	/* Prevent arm_smmu_mm_release from being called while we are attaching */
	if (!mmget_not_zero(domain->mm))
		return -EINVAL;

	/*
	 * This does not need the arm_smmu_asid_lock because SVA domains never
	 * get reassigned
	 */
	arm_smmu_make_sva_cd(&target, master, domain->mm, smmu_domain->asid,
			     smmu_domain->btm_invalidation);
	ret = arm_smmu_set_pasid(master, smmu_domain, id, &target);

	mmput(domain->mm);
	return ret;
}

static void arm_smmu_sva_domain_free(struct iommu_domain *domain)
{
	struct arm_smmu_domain *smmu_domain = to_smmu_domain(domain);

	/*
	 * Notice that the arm_smmu_mm_arch_invalidate_secondary_tlbs op can
	 * still be called/running at this point. We allow the ASID to be
	 * reused, and if there is a race then it just suffers harmless
	 * unnecessary invalidation.
	 */
	arm_smmu_domain_free_id(smmu_domain);
	if (smmu_domain->btm_invalidation)
		arm64_mm_context_put(domain->mm);

	/*
	 * Actual free is defered to the SRCU callback
	 * arm_smmu_mmu_notifier_free()
	 */
	mmu_notifier_put(&smmu_domain->mmu_notifier);
}

static const struct iommu_domain_ops arm_smmu_sva_domain_ops = {
	.set_dev_pasid		= arm_smmu_sva_set_dev_pasid,
	.free			= arm_smmu_sva_domain_free
};

static int arm_smmu_share_asid(struct arm_smmu_device *smmu,
			       struct arm_smmu_domain *smmu_domain,
			       struct mm_struct *mm)
{
	struct arm_smmu_domain *old_s1_domain;
	int ret;

	/*
	 * Notice that BTM is never currently enabled, this is all dead code.
	 * The specification cautions:
	 *
	 * Note: Arm expects that SMMU stage 2 address spaces are generally
	 * shared with their respective PE virtual machine stage 2
	 * configuration. If broadcast invalidation is required to be avoided
	 * for a particular SMMU stage 2 address space, Arm recommends that a
	 * hypervisor configures the STE with a VMID that is not allocated for
	 * virtual machine use on the PEs
	 *
	 * However, in Linux, both KVM and SMMU think they own the VMID pool.
	 * Unfortunately the ARM design is problematic for Linux as we do not
	 * currently share the S2 table with KVM. This creates a situation where
	 * the S2 needs to have the same VMID as KVM in order to allow the guest
	 * to use BTM, however we must still invalidate the S2 directly since it
	 * is a different radix tree. What Linux would like is something like
	 * ASET for the STE to disable BTM only for the S2.
	 *
	 * Arguably in a system with BTM the driver should prefer to use a S1
	 * table in all cases execpt when explicitly asked to create a nesting
	 * parent. Then it should use the VMID of KVM to enable BTM in the
	 * guest. We cannot optimize away the resulting double invalidation of
	 * the S2 :( Or we simply ignore BTM entirely as we are doing now.
	 */
	if (!(smmu_domain->smmu->features & ARM_SMMU_FEAT_BTM))
		return arm_smmu_domain_alloc_id(smmu, smmu_domain);

	/* At this point the caller ensures we have a mmget() */
	smmu_domain->asid = arm64_mm_context_get(mm);

	mutex_lock(&smmu->asid_lock);
	old_s1_domain = xa_store(&smmu->asid_map, smmu_domain->asid,
				 smmu_domain, GFP_KERNEL);
	if (xa_err(old_s1_domain)) {
		ret = xa_err(old_s1_domain);
		goto out_put_asid;
	}

	/*
	 * In BTM mode the CPU ASID and the IOMMU ASID have to be the same.
	 * Unfortunately we run separate allocators for this and the IOMMU
	 * ASID can already have been assigned to a S1 domain. SVA domains
	 * always align to their CPU ASIDs. In this case we change
	 * the S1 domain's ASID, update the CD entry and flush the caches.
	 *
	 * This is a bit tricky, all the places writing to a S1 CD, reading the
	 * S1 ASID, or doing xa_erase must hold the asid_lock or xa_lock to
	 * avoid IOTLB incoherence.
	 */
	if (old_s1_domain) {
		if (WARN_ON(old_s1_domain->domain.type == IOMMU_DOMAIN_SVA)) {
			ret = -EINVAL;
			goto out_restore_s1;
		}
		ret = arm_smmu_realloc_s1_domain_asid(smmu, old_s1_domain);
		if (ret)
			goto out_restore_s1;

		/* Clean the ASID since it was just recovered before using it */
		arm_smmu_tlb_inv_all_s1(smmu_domain);
	}

	smmu_domain->btm_invalidation = true;

	ret = 0;
	goto out_unlock;

out_restore_s1:
	xa_store(&smmu->asid_map, smmu_domain->asid, old_s1_domain,
		 GFP_KERNEL);
out_put_asid:
	arm64_mm_context_put(mm);
out_unlock:
	mutex_unlock(&smmu->asid_lock);
	return ret;
}

struct iommu_domain *arm_smmu_sva_domain_alloc(struct device *dev,
					       struct mm_struct *mm)
{
	struct arm_smmu_master *master = dev_iommu_priv_get(dev);
	struct arm_smmu_device *smmu = master->smmu;
	struct arm_smmu_domain *smmu_domain;
	int ret;

	smmu_domain = arm_smmu_domain_alloc();
	if (IS_ERR(smmu_domain))
		return ERR_CAST(smmu_domain);
	smmu_domain->domain.type = IOMMU_DOMAIN_SVA;
	smmu_domain->domain.ops = &arm_smmu_sva_domain_ops;
	smmu_domain->smmu = smmu;

	ret = arm_smmu_share_asid(smmu, smmu_domain, mm);
	if (ret)
		goto err_free;

	smmu_domain->mmu_notifier.ops = &arm_smmu_mmu_notifier_ops;
	ret = mmu_notifier_register(&smmu_domain->mmu_notifier, mm);
	if (ret)
		goto err_asid;

	return &smmu_domain->domain;

err_asid:
	arm_smmu_domain_free_id(smmu_domain);
	if (smmu_domain->btm_invalidation)
		arm64_mm_context_put(mm);
err_free:
	kfree(smmu_domain);
	return ERR_PTR(ret);
}
