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

	ret = devm_add_action_or_reset(smmu->dev, arm_smmu_kdump_adopt_cleanup,
				       smmu);
	/* devm_add_action_or_reset ran the cleanup upon failure */
	if (ret)
		goto err;

	return 0;

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
#endif /* CONFIG_CRASH_DUMP */
