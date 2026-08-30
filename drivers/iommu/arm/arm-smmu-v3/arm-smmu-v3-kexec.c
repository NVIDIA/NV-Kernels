// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES
 */

#define dev_fmt(fmt) "kexec: " fmt

#include <linux/io.h>
#include <linux/slab.h>

#include "arm-smmu-v3.h"

/*
 * Common helpers for a kexec'd kernel to parse, validate, and walk through the
 * previous kernel's SMMU table structures, shared by the kdump adoption and a
 * future live-update restoration.
 *
 * The common helpers are read-only against the previous kernel's structures: a
 * table that is not yet mapped by this kernel gets a transient memremap during
 * a walk, followed by an immediate memunmap. They never allocate memory or take
 * ownership of the previous kernel's tables; the callers make those decisions.
 */

/**
 * arm_smmu_kexec_parse_strtab_2lvl() - Validate a 2-level stream table
 * @smmu: SMMU device of this kernel
 * @cfg_reg: STRTAB_BASE_CFG register value set by the previous kernel
 * @base: stream table base address extracted from the STRTAB_BASE register
 * @num_l1_ents: pointer to return the number of L1 entries
 *
 * Validate the 2-level stream table geometry in @cfg_reg and @base's alignment
 * against this kernel's hardware limits.
 *
 * Return: 0 on success with @num_l1_ents set, or -EINVAL on a bad geometry
 */
static int arm_smmu_kexec_parse_strtab_2lvl(struct arm_smmu_device *smmu,
					    u32 cfg_reg, phys_addr_t base,
					    u32 *num_l1_ents)
{
	u32 log2size = FIELD_GET(STRTAB_BASE_CFG_LOG2SIZE, cfg_reg);
	u32 split = FIELD_GET(STRTAB_BASE_CFG_SPLIT, cfg_reg);
	u32 num_ents;
	size_t size;

	if (log2size < split || log2size > smmu->sid_bits) {
		dev_err(smmu->dev, "log2size %u out of range [%u, %u]\n",
			log2size, split, smmu->sid_bits);
		return -EINVAL;
	}
	if (split != STRTAB_SPLIT) {
		dev_err(smmu->dev,
			"unsupported STRTAB_SPLIT %u (expected %u)\n", split,
			STRTAB_SPLIT);
		return -EINVAL;
	}

	/*
	 * Bound the entry count before the shift, as a log2size wider than what
	 * this kernel itself supports would overflow it.
	 */
	if (log2size - split > ilog2(STRTAB_MAX_L1_ENTRIES)) {
		dev_err(smmu->dev, "l1 entries 2^%u exceeds max %u\n",
			log2size - split, STRTAB_MAX_L1_ENTRIES);
		return -EINVAL;
	}

	num_ents = 1U << (log2size - split);

	size = num_ents * sizeof(struct arm_smmu_strtab_l1);
	/*
	 * According to spec (6.3.24), HW aligns the base down to the L1 table
	 * size, i.e. min 64 bytes, so an unaligned base would make this kernel
	 * read another table.
	 */
	if (!IS_ALIGNED(base, size)) {
		dev_err(smmu->dev, "unaligned l1 stream table base %pa\n",
			&base);
		return -EINVAL;
	}

	*num_l1_ents = num_ents;
	return 0;
}

/**
 * arm_smmu_kexec_parse_strtab_linear() - Validate a linear stream table
 * @smmu: SMMU device of this kernel
 * @cfg_reg: STRTAB_BASE_CFG register value set by the previous kernel
 * @base: stream table base address extracted from the STRTAB_BASE register
 * @num_ents: pointer to return the number of STEs
 *
 * Validate the linear stream table geometry in @cfg_reg and @base's alignment
 * against this kernel's own limits.
 *
 * Return: 0 on success with @num_ents set, or -EINVAL on a bad geometry
 */
static int arm_smmu_kexec_parse_strtab_linear(struct arm_smmu_device *smmu,
					      u32 cfg_reg, phys_addr_t base,
					      u32 *num_ents)
{
	u32 log2size = FIELD_GET(STRTAB_BASE_CFG_LOG2SIZE, cfg_reg);
	unsigned int max_log2size = smmu->sid_bits;
	size_t size;

	/* Cap the size at what this kernel itself would have allocated */
	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB)
		max_log2size = min_t(
			unsigned int, max_log2size,
			ilog2(STRTAB_MAX_L1_ENTRIES * STRTAB_NUM_L2_STES));

	/* num_ents is limited to a u32, so cap log2size at 31 */
	max_log2size = min(max_log2size, 31U);
	if (log2size > max_log2size) {
		dev_err(smmu->dev, "unsupported log2size %u (> %u)\n", log2size,
			max_log2size);
		return -EINVAL;
	}

	size = (1U << log2size) * sizeof(struct arm_smmu_ste);
	/*
	 * According to spec (6.3.24), HW aligns the base down to the table size
	 * and ignores the low bits, so an unaligned base would make this kernel
	 * read a different table.
	 */
	if (!IS_ALIGNED(base, size)) {
		dev_err(smmu->dev, "unaligned stream table base %pa\n", &base);
		return -EINVAL;
	}

	*num_ents = 1U << log2size;
	return 0;
}

/**
 * arm_smmu_kexec_check_strtab_l1_desc() - Check one stream table L1 descriptor
 * @smmu: SMMU device of this kernel
 * @base: L2 table address from the previous kernel's L1 descriptor
 * @span: span field from the same L1 descriptor
 * @idx: index of the L1 descriptor, for diagnostics
 *
 * Return: 1 if the descriptor is unused, 0 if it is valid, or -EINVAL if it is
 * malformed
 */
static int arm_smmu_kexec_check_strtab_l1_desc(struct arm_smmu_device *smmu,
					       phys_addr_t base, u32 span,
					       u32 idx)
{
	/* L1STD.L2Ptr is invalid */
	if (!span)
		return 1;

	if (span != STRTAB_SPLIT + 1) {
		dev_err(smmu->dev, "L1[%u] unsupported span %u (vs %u)\n", idx,
			span, STRTAB_SPLIT + 1);
		return -EINVAL;
	}

	/*
	 * A valid descriptor never carries a null pointer. Also, HW aligns the
	 * pointer down to the L2 table size, so an unaligned pointer would make
	 * this kernel read a different table.
	 */
	if (!base || !IS_ALIGNED(base, sizeof(struct arm_smmu_strtab_l2))) {
		dev_err(smmu->dev, "L1[%u] bad l2 table base %pa\n", idx,
			&base);
		return -EINVAL;
	}

	return 0;
}

/**
 * arm_smmu_kexec_check_ste_cdtab() - Decode the CD table geometry of an STE
 * @smmu: SMMU device of this kernel
 * @ste0: first 64 bits of the previous kernel's S1 STE
 * @cdtab: pointer to return the CD table's physical address
 * @s1fmt: pointer to return the CD table format
 * @max_contexts: pointer to return the number of CDs
 *
 * A linear CD table on the 2-level capable hardware is accepted, as a previous
 * kernel might have used one, like the linear stream table.
 *
 * Note that the spec requires a CD table to be aligned to its own size, so an
 * unaligned @cdtab gets rejected here: HW may then zero the low bits or fetch
 * any CD in the table, leaving the live ASIDs unknowable to this scan.
 *
 * Return: 0 on success with the three outputs set, or -EINVAL on a bad geometry
 */
static int arm_smmu_kexec_check_ste_cdtab(struct arm_smmu_device *smmu,
					  u64 ste0, phys_addr_t *cdtab,
					  u32 *s1fmt, u32 *max_contexts)
{
	phys_addr_t base = ste0 & STRTAB_STE_0_S1CTXPTR_MASK;
	u32 s1cdmax = FIELD_GET(STRTAB_STE_0_S1CDMAX, ste0);
	u32 fmt = FIELD_GET(STRTAB_STE_0_S1FMT, ste0);
	size_t size;

	if (!base || s1cdmax > smmu->ssid_bits)
		return -EINVAL;

	if (fmt != STRTAB_STE_0_S1FMT_LINEAR &&
	    fmt != STRTAB_STE_0_S1FMT_64K_L2)
		return -EINVAL;

	/* Both kernels run on the same HW, so a genuine STE never has this */
	if (fmt == STRTAB_STE_0_S1FMT_64K_L2 &&
	    !(smmu->features & ARM_SMMU_FEAT_2_LVL_CDTAB))
		return -EINVAL;

	if (fmt == STRTAB_STE_0_S1FMT_LINEAR)
		size = (1UL << s1cdmax) * sizeof(struct arm_smmu_cd);
	else
		size = DIV_ROUND_UP(1UL << s1cdmax, CTXDESC_L2_ENTRIES) *
		       sizeof(struct arm_smmu_cdtab_l1);

	/*
	 * An unaligned base is CONSTRAINED UNPREDICTABLE: HW may zero the low
	 * bits or fetch any CD in the table, so live ASIDs become unknowable.
	 */
	if (!IS_ALIGNED(base, size))
		return -EINVAL;

	*cdtab = base;
	*s1fmt = fmt;
	*max_contexts = 1U << s1cdmax;
	return 0;
}

static int arm_smmu_kexec_resv_asid(struct arm_smmu_device *smmu, u32 asid)
{
	/* A valid CD never has ASID 0; both kernels share the same HW limit */
	if (!asid || asid >= 1UL << smmu->asid_bits)
		return -EINVAL;

	guard(mutex)(&arm_smmu_asid_lock);

	/*
	 * The scan runs before this SMMU registers with the IOMMU core, so no
	 * domain of its own holds an ASID yet, while xa_reserve() does nothing
	 * if the entry is there, covering a domain's ASID that many CDs share.
	 */
	return xa_reserve(&smmu->asid_map, asid, GFP_KERNEL);
}

static int arm_smmu_kexec_resv_vmid(struct arm_smmu_device *smmu, u32 vmid)
{
	int ret;

	/* A translating STE never has VMID 0, which is reserved for bypass */
	if (!vmid || vmid >= 1UL << smmu->vmid_bits)
		return -EINVAL;

	ret = ida_alloc_range(&smmu->vmid_map, vmid, vmid, GFP_KERNEL);
	if (ret < 0 && ret != -ENOSPC) /* -ENOSPC means already reserved */
		return ret;
	return 0;
}

static int arm_smmu_kexec_resv_cd_asids(struct arm_smmu_device *smmu,
					struct arm_smmu_cd *cds, u32 num_cds)
{
	int ret = 0;
	u32 i;

	for (i = 0; i < num_cds; i++) {
		u64 val = le64_to_cpu(cds[i].data[0]);
		u32 asid = FIELD_GET(CTXDESC_CD_0_ASID, val);

		if (!(val & CTXDESC_CD_0_V))
			continue;
		ret = arm_smmu_kexec_resv_asid(smmu, asid);
		if (ret)
			break;
	}
	return ret;
}

/*
 * Reserve the ASIDs of all the valid CDs of an S1 STE in the previous kernel's
 * CD tables. The CD tables are transiently memremapped for the scan.
 */
static int arm_smmu_kexec_resv_s1_asids(struct arm_smmu_device *smmu, u64 ste0)
{
	struct arm_smmu_cdtab_l1 *l1tab;
	u32 num_l1_ents, num_cds, i;
	u32 max_contexts, s1fmt;
	phys_addr_t cdtab;
	int ret;

	ret = arm_smmu_kexec_check_ste_cdtab(smmu, ste0, &cdtab, &s1fmt,
					     &max_contexts);
	if (ret)
		return ret;

	if (s1fmt == STRTAB_STE_0_S1FMT_LINEAR) {
		struct arm_smmu_cd *cds;

		cds = memremap(cdtab, max_contexts * sizeof(*cds), MEMREMAP_WB);
		if (!cds)
			return -ENOMEM;
		ret = arm_smmu_kexec_resv_cd_asids(smmu, cds, max_contexts);
		memunmap(cds);
		return ret;
	}

	num_l1_ents = DIV_ROUND_UP(max_contexts, CTXDESC_L2_ENTRIES);
	l1tab = memremap(cdtab, num_l1_ents * sizeof(*l1tab), MEMREMAP_WB);
	if (!l1tab)
		return -ENOMEM;

	/* max_contexts being under a full leaf makes the only leaf partial */
	num_cds = min_t(u32, max_contexts, CTXDESC_L2_ENTRIES);

	/* Aliased L2 tables cannot extend the walk; they only repeat a scan */
	for (i = 0; i < num_l1_ents; i++) {
		u64 l1_desc = le64_to_cpu(l1tab[i].l2ptr);
		phys_addr_t l2_base = l1_desc & CTXDESC_L1_DESC_L2PTR_MASK;
		struct arm_smmu_cdtab_l2 *l2;

		if (!(l1_desc & CTXDESC_L1_DESC_V))
			continue;

		/*
		 * A valid descriptor never carries a null pointer. Also, an L2
		 * table is always 64KB-aligned, so an unaligned pointer would
		 * make this kernel read a different table.
		 */
		if (!l2_base || !IS_ALIGNED(l2_base, sizeof(*l2))) {
			ret = -EINVAL;
			break;
		}

		l2 = memremap(l2_base, num_cds * sizeof(*l2->cds), MEMREMAP_WB);
		if (!l2) {
			ret = -ENOMEM;
			break;
		}
		ret = arm_smmu_kexec_resv_cd_asids(smmu, l2->cds, num_cds);
		memunmap(l2);
		if (ret)
			break;
	}
	memunmap(l1tab);
	return ret;
}

static int arm_smmu_kexec_resv_ste_ids(struct arm_smmu_device *smmu,
				       struct arm_smmu_ste *ste)
{
	u32 vmid = FIELD_GET(STRTAB_STE_2_S2VMID, le64_to_cpu(ste->data[2]));
	u64 ste0 = le64_to_cpu(ste->data[0]);

	if (!(ste0 & STRTAB_STE_0_V))
		return 0;

	switch (FIELD_GET(STRTAB_STE_0_CFG, ste0)) {
	case STRTAB_STE_0_CFG_ABORT:
	case STRTAB_STE_0_CFG_BYPASS:
		return 0;
	case STRTAB_STE_0_CFG_S1_TRANS:
		return arm_smmu_kexec_resv_s1_asids(smmu, ste0);
	case STRTAB_STE_0_CFG_NESTED:
		/*
		 * A guest-owned CD table is in the IPA space, unreachable. Its
		 * ASIDs are only tagged with the S2VMID reserved below, so they
		 * cannot alias this kernel's VMID-0 or EL2 S1 domains.
		 */
		fallthrough;
	case STRTAB_STE_0_CFG_S2_TRANS:
		return arm_smmu_kexec_resv_vmid(smmu, vmid);
	default:
		return -EINVAL;
	}
}

/**
 * arm_smmu_kexec_scan_and_resv_ids() - Reserve a stream table's in-use IDs
 * @smmu: SMMU device of this kernel, with an adopted or restored strtab_cfg
 *
 * Scan the stream table set up in the strtab_cfg and every CD table behind an
 * S1 STE, reserving all of the in-use ASIDs and VMIDs. A failing scan rolls
 * back through arm_smmu_kexec_unresv_ids().
 *
 * Note that the scan selects the linear or 2-level walk per this kernel's own
 * ARM_SMMU_FEAT_2_LVL_STRTAB, so the caller must have matched the feature bit
 * to the format of the adopted stream table in the strtab_cfg.
 *
 * Return: 0 on success, -EINVAL on any malformed table entry, or -ENOMEM on a
 * memory shortage
 */
static int arm_smmu_kexec_scan_and_resv_ids(struct arm_smmu_device *smmu)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	int ret = 0;
	u32 i, j;

	if (!(smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB)) {
		for (i = 0; i < cfg->linear.num_ents; i++) {
			ret = arm_smmu_kexec_resv_ste_ids(
				smmu, &cfg->linear.table[i]);
			if (ret)
				return ret;
		}
		return 0;
	}

	/* Aliased L2 tables cannot extend the scan; they only repeat a scan */
	for (i = 0; i < cfg->l2.num_l1_ents; i++) {
		u64 l1_desc = le64_to_cpu(cfg->l2.l1tab[i].l2ptr);
		phys_addr_t base = l1_desc & STRTAB_L1_DESC_L2PTR_MASK;
		u32 span = FIELD_GET(STRTAB_L1_DESC_SPAN, l1_desc);
		struct arm_smmu_strtab_l2 *l2;

		ret = arm_smmu_kexec_check_strtab_l1_desc(smmu, base, span, i);
		if (ret == 1)
			continue;
		if (ret)
			return ret;

		/*
		 * This kernel will map the previous kernel's L2 tables lazily
		 * or not at all. Here, take a transient view for this scan.
		 */
		l2 = memremap(base, sizeof(*l2), MEMREMAP_WB);
		if (!l2)
			return -ENOMEM;
		for (j = 0; j < ARRAY_SIZE(l2->stes); j++) {
			ret = arm_smmu_kexec_resv_ste_ids(smmu, &l2->stes[j]);
			if (ret)
				break;
		}
		memunmap(l2);
		if (ret)
			return ret;
	}
	return 0;
}

/**
 * arm_smmu_kexec_unresv_ids() - Release the IDs that a failing scan reserved
 * @smmu: SMMU device of this kernel that failed its reservation scan
 *
 * Undo the reservations of a failing arm_smmu_kexec_scan_and_resv_ids() call,
 * for a caller that falls back to a full reset.
 *
 * That reset flushes the whole TLB, so the previous kernel's IDs no longer need
 * any protection. A scan that fails halfway would otherwise keep a good share
 * of an 8-bit ASID or VMID space reserved for nothing.
 */
static void arm_smmu_kexec_unresv_ids(struct arm_smmu_device *smmu)
{
	/*
	 * Emptying both maps releases exactly this scan's IDs, as no domain of
	 * this SMMU can hold one until it registers with the IOMMU core, later
	 * in the probe. Both stay initialized and usable for the full reset.
	 */
	mutex_lock(&arm_smmu_asid_lock);
	xa_destroy(&smmu->asid_map);
	mutex_unlock(&arm_smmu_asid_lock);

	ida_destroy(&smmu->vmid_map);
}

#ifdef CONFIG_CRASH_DUMP
/*
 * Helper functions of the kdump stream table adoption for ARM SMMUv3
 *
 * When the crashed kernel left the SMMU enabled with in-flight DMAs, the kdump
 * kernel adopts the crashed kernel's stream tables, instead of doing a regular
 * reset, to keep in-flight DMAs translating until the endpoint device drivers
 * re-probe and quiesce their devices.
 *
 * Note:
 *  - Adoption only starts on an SMMU that the crashed kernel left enabled, as a
 *    disabled SMMU (CR0_SMMUEN=0) could hold meaningless register values.
 *  - Values read from the crashed kernel's registers get structural validation
 *    only (format, size, span, alignment, and ID range); the physical addresses
 *    are not vetted, as the kdump kernel has no record of which pages held the
 *    tables.
 *  - A structural inconsistency at adoption time tosses the entire adoption and
 *    makes the SMMU fall back to a full reset blocking in-flight DMAs.
 *  - L2 stream tables are adopted lazily at master-inserting time, to bound the
 *    peak memory use against a corrupted L1 table; any lazy L2 adoption failure
 *    rejects that device alone, as its blast radius is bounded to the bus.
 *  - Only a coherent SMMU (ARM_SMMU_FEAT_COHERENCY) is supported, as the stream
 *    table adoption is done by memremap with MEMREMAP_WB, which is verified on
 *    the real hardware. Callers of these functions are responsible for gating
 *    ARM_SMMU_FEAT_COHERENCY once during the probe.
 */

int arm_smmu_kdump_adopt_deferred_l2_strtab(struct arm_smmu_device *smmu,
					    u32 sid, phys_addr_t base, u32 span,
					    struct arm_smmu_strtab_l2 **l2table)
{
	struct arm_smmu_strtab_l2 *table;
	int ret;

	/*
	 * Recheck the L1 descriptor in case it has been overwritten since the
	 * adopt. Reject this master's insert, as a panic or SMMU-disable would
	 * either lose the vmcore or cascade aborts. Do not try to fix it, as it
	 * would break all other SIDs in the same bus (PCI case). The corruption
	 * blast radius is already bounded to that bus range.
	 */
	ret = arm_smmu_kexec_check_strtab_l1_desc(smmu, base, span,
						  arm_smmu_strtab_l1_idx(sid));
	if (ret)
		return ret;

	/*
	 * This L2 table is mapped lazily per master; devres frees it at unbind,
	 * as with the dmam_alloc_coherent() used for a fresh L2.
	 */
	table = devm_memremap(smmu->dev, base, sizeof(*table), MEMREMAP_WB);
	if (IS_ERR(table)) {
		dev_err(smmu->dev,
			"failed to adopt l2 stream table for SID %u\n", sid);
		return PTR_ERR(table);
	}

	*l2table = table;
	return 0;
}

static int arm_smmu_kdump_adopt_strtab_2lvl(struct arm_smmu_device *smmu,
					    u32 cfg_reg, phys_addr_t base)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u32 num_l1_ents;
	size_t size;
	int ret, i;

	ret = arm_smmu_kexec_parse_strtab_2lvl(smmu, cfg_reg, base,
					       &num_l1_ents);
	if (ret)
		return ret;

	cfg->l2.num_l1_ents = num_l1_ents;

	size = num_l1_ents * sizeof(struct arm_smmu_strtab_l1);
	cfg->l2.l1tab = memremap(base, size, MEMREMAP_WB);
	if (!cfg->l2.l1tab)
		return -ENOMEM;

	cfg->l2.l2ptrs =
		kcalloc(num_l1_ents, sizeof(*cfg->l2.l2ptrs), GFP_KERNEL);
	if (!cfg->l2.l2ptrs)
		return -ENOMEM;

	for (i = 0; i < num_l1_ents; i++) {
		u64 l2ptr = le64_to_cpu(cfg->l2.l1tab[i].l2ptr);
		phys_addr_t l2_base = l2ptr & STRTAB_L1_DESC_L2PTR_MASK;
		u32 span = FIELD_GET(STRTAB_L1_DESC_SPAN, l2ptr);

		ret = arm_smmu_kexec_check_strtab_l1_desc(smmu, l2_base, span,
							  i);
		if (ret < 0)
			return ret;

		/*
		 * If the crashed kernel's l1 descriptors are deeply corrupted,
		 * blindly memremapping every l2 table here could lead to OOM.
		 *
		 * Defer the l2 memremap to arm_smmu_init_l2_strtab(), so peak
		 * memory is bounded by the kdump kernel's actual demand.
		 */
	}

	return 0;
}

static int arm_smmu_kdump_adopt_strtab_linear(struct arm_smmu_device *smmu,
					      u32 cfg_reg, phys_addr_t base)
{
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;
	u32 num_ents;
	size_t size;
	int ret;

	ret = arm_smmu_kexec_parse_strtab_linear(smmu, cfg_reg, base,
						 &num_ents);
	if (ret)
		return ret;

	/*
	 * We might end up with a num_ents != sid_bits, which is fine, since the
	 * ARM_SMMU_OPT_KDUMP_ADOPT case bypasses arm_smmu_write_strtab().
	 */
	cfg->linear.num_ents = num_ents;

	size = num_ents * sizeof(struct arm_smmu_ste);
	cfg->linear.table = memremap(base, size, MEMREMAP_WB);
	if (!cfg->linear.table)
		return -ENOMEM;
	return 0;
}

static void arm_smmu_kdump_adopt_cleanup(void *data)
{
	struct arm_smmu_device *smmu = data;
	struct arm_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;

	if (smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB) {
		kfree(cfg->l2.l2ptrs);
		if (cfg->l2.l1tab)
			memunmap(cfg->l2.l1tab);
	} else {
		if (cfg->linear.table)
			memunmap(cfg->linear.table);
	}
}

int arm_smmu_kdump_adopt_strtab(struct arm_smmu_device *smmu)
{
	u32 cfg_reg = readl_relaxed(smmu->base + ARM_SMMU_STRTAB_BASE_CFG);
	u64 base_reg = readq_relaxed(smmu->base + ARM_SMMU_STRTAB_BASE);
	bool was_2lvl = smmu->features & ARM_SMMU_FEAT_2_LVL_STRTAB;
	u32 idr0 = readl_relaxed(smmu->base + ARM_SMMU_IDR0);
	phys_addr_t base = base_reg & STRTAB_BASE_ADDR_MASK;
	u32 fmt = FIELD_GET(STRTAB_BASE_CFG_FMT, cfg_reg);
	int ret;

	dev_dbg(smmu->dev, "attempting to adopt crashed kernel's stream table\n");

	if (fmt == STRTAB_BASE_CFG_FMT_2LVL) {
		/*
		 * Both kernels run on the same hardware, so it's impossible for
		 * kdump kernel to see the support for linear stream table only.
		 */
		if (WARN_ON(FIELD_GET(IDR0_ST_LVL, idr0) != IDR0_ST_LVL_2LVL)) {
			ret = -EINVAL;
		} else {
			smmu->features |= ARM_SMMU_FEAT_2_LVL_STRTAB;
			ret = arm_smmu_kdump_adopt_strtab_2lvl(smmu, cfg_reg,
							       base);
		}
	} else if (fmt == STRTAB_BASE_CFG_FMT_LINEAR) {
		/*
		 * The kdump kernel need not match the crashed kernel. An older
		 * crashed kernel that predates two-level stream table support
		 * may have used a linear table on 2-level-capable hardware, so
		 * enforce the same format here to match the adopted table.
		 */
		ret = arm_smmu_kdump_adopt_strtab_linear(smmu, cfg_reg, base);
		if (!ret)
			smmu->features &= ~ARM_SMMU_FEAT_2_LVL_STRTAB;
	} else {
		dev_err(smmu->dev, "invalid STRTAB format %u\n", fmt);
		ret = -EINVAL;
	}

	if (ret) {
		arm_smmu_kdump_adopt_cleanup(smmu);
		goto err;
	}

	ret = arm_smmu_kexec_scan_and_resv_ids(smmu);
	if (ret) {
		dev_warn(smmu->dev, "failed to reserve in-use ASIDs/VMIDs\n");
		arm_smmu_kdump_adopt_cleanup(smmu);
		goto err_unresv;
	}

	ret = devm_add_action_or_reset(smmu->dev, arm_smmu_kdump_adopt_cleanup,
				       smmu);
	/* devm_add_action_or_reset ran the cleanup upon failure */
	if (ret)
		goto err_unresv;

	return 0;

err_unresv:
	/* The full reset will flush the entire TLB, so release everything */
	arm_smmu_kexec_unresv_ids(smmu);
err:
	dev_warn(smmu->dev, "falling back to full reset after adoption failed\n");
	/*
	 * Undo either adoption's change to FEAT_2_LVL_STRTAB, so that the full
	 * reset fallback uses the format that this kernel itself would choose.
	 */
	if (was_2lvl)
		smmu->features |= ARM_SMMU_FEAT_2_LVL_STRTAB;
	else
		smmu->features &= ~ARM_SMMU_FEAT_2_LVL_STRTAB;
	memset(&smmu->strtab_cfg, 0, sizeof(smmu->strtab_cfg));
	smmu->options &= ~ARM_SMMU_OPT_KDUMP_ADOPT;
	return ret;
}

bool arm_smmu_kdump_is_attach_deferred(struct arm_smmu_master *master)
{
	struct arm_smmu_device *smmu = master->smmu;
	int i;

	for (i = 0; i < master->num_streams; i++) {
		struct arm_smmu_ste *ste =
			arm_smmu_get_step_for_sid(smmu, master->streams[i].id);
		u64 ent0 = le64_to_cpu(ste->data[0]);

		/* Defer only when there might be in-flight DMAs */
		if ((ent0 & STRTAB_STE_0_V) &&
		    FIELD_GET(STRTAB_STE_0_CFG, ent0) != STRTAB_STE_0_CFG_ABORT)
			return true;
	}

	return false;
}
#endif /* CONFIG_CRASH_DUMP */
