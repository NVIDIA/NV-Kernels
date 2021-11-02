// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2022 Arm Ltd.

#define pr_fmt(fmt) "mpam: " fmt

#include <linux/acpi.h>
#include <linux/atomic.h>
#include <linux/arm_mpam.h>
#include <linux/bitfield.h>
#include <linux/bitmap.h>
#include <linux/cacheinfo.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <acpi/pcc.h>

#include <asm/mpam.h>

#include "mpam_internal.h"

DEFINE_STATIC_KEY_FALSE(mpam_enabled);

/*
 * mpam_list_lock protects the SRCU lists when writing. Once the
 * mpam_enabled key is enabled these lists are read-only,
 * unless the error interrupt disables the driver.
 */
static DEFINE_MUTEX(mpam_list_lock);
static LIST_HEAD(mpam_all_msc);

struct srcu_struct mpam_srcu;

/* MPAM isn't available until all the MSC have been probed. */
static u32 mpam_num_msc;

static int mpam_cpuhp_state;
static DEFINE_MUTEX(mpam_cpuhp_state_lock);

/*
 * The smallest common values for any CPU or MSC in the system.
 * Generating traffic outside this range will result in screaming interrupts.
 */
u16 mpam_partid_max;
u8 mpam_pmg_max;
static bool partid_max_init, partid_max_published;
static DEFINE_SPINLOCK(partid_max_lock);

/*
 * mpam is enabled once all devices have been probed from CPU online callbacks,
 * scheduled via this work_struct. If access to an MSC depends on a CPU that
 * was not brought online at boot, this can happen surprisingly late.
 */
static DECLARE_WORK(mpam_enable_work, &mpam_enable);

/*
 * All mpam error interrupts indicate a software bug. On receipt, disable the
 * driver.
 */
static DECLARE_WORK(mpam_broken_work, &mpam_disable);

/*
 * An MSC is a container for resources, each identified by their RIS index.
 * Components are a group of RIS that control the same thing.
 * Classes are the set components of the same type.
 *
 * e.g. The set of RIS that make up the L2 are a component. These are sometimes
 * termed slices. They should be configured as if they were one MSC.
 *
 * e.g. The SoC probably has more than one L2, each attached to a distinct set
 * of CPUs. All the L2 components are grouped as a class.
 *
 * When creating an MSC, struct mpam_msc is added to the all mpam_all_msc list,
 * then linked via struct mpam_ris to a component and a class.
 * The same MSC may exist under different class->component paths, but the RIS
 * index will be unique.
 */
LIST_HEAD(mpam_classes);

static u32 __mpam_read_reg(struct mpam_msc *msc, u16 reg)
{
	WARN_ON_ONCE((reg + sizeof(u32)) > msc->mapped_hwpage_sz);
	WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(), &msc->accessibility));

	return readl_relaxed(msc->mapped_hwpage + reg);
}

static void __mpam_write_reg(struct mpam_msc *msc, u16 reg, u32 val)
{
	WARN_ON_ONCE((reg + sizeof(u32)) > msc->mapped_hwpage_sz);
	WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(), &msc->accessibility));

	writel_relaxed(val, msc->mapped_hwpage + reg);
}

#define mpam_read_partsel_reg(msc, reg)			\
({							\
	u32 ____ret;					\
							\
	lockdep_assert_held_once(&msc->part_sel_lock);	\
	____ret = __mpam_read_reg(msc, MPAMF_##reg);	\
							\
	____ret;					\
})

#define mpam_write_partsel_reg(msc, reg, val)			\
({								\
	lockdep_assert_held_once(&msc->part_sel_lock);		\
	__mpam_write_reg(msc, MPAMCFG_##reg, val);		\
})

#define mpam_read_monsel_reg(msc, reg)			\
({							\
	u32 ____ret;					\
							\
	lockdep_assert_held_once(&msc->mon_sel_lock);	\
	____ret = __mpam_read_reg(msc, MSMON_##reg);	\
							\
	____ret;					\
})

#define mpam_write_monsel_reg(msc, reg, val)			\
({								\
	lockdep_assert_held_once(&msc->mon_sel_lock);		\
	__mpam_write_reg(msc, MSMON_##reg, val);		\
})

static u64 mpam_msc_read_idr(struct mpam_msc *msc)
{
	u64 idr_high = 0, idr_low;

	lockdep_assert_held(&msc->part_sel_lock);

	idr_low = mpam_read_partsel_reg(msc, IDR);
	if (FIELD_GET(MPAMF_IDR_HAS_EXT, idr_low))
		idr_high = mpam_read_partsel_reg(msc, IDR + 4);

	return (idr_high << 32) | idr_low;
}

static void mpam_msc_zero_esr(struct mpam_msc *msc)
{
	writel_relaxed(0, msc->mapped_hwpage + MPAMF_ESR);
	if (msc->has_extd_esr)
		writel_relaxed(0, msc->mapped_hwpage + MPAMF_ESR + 4);
}

static u64 mpam_msc_read_esr(struct mpam_msc *msc)
{
	u64 esr_high = 0, esr_low;

	esr_low = readl_relaxed(msc->mapped_hwpage + MPAMF_ESR);
	if (msc->has_extd_esr)
		esr_high = readl_relaxed(msc->mapped_hwpage + MPAMF_ESR + 4);

	return (esr_high << 32) | esr_low;
}

static void __mpam_part_sel(u8 ris_idx, u16 partid, struct mpam_msc *msc)
{
	u32 partsel;

	lockdep_assert_held(&msc->part_sel_lock);

	partsel = FIELD_PREP(MPAMCFG_PART_SEL_RIS, ris_idx) |
		  FIELD_PREP(MPAMCFG_PART_SEL_PARTID_SEL, partid);
	mpam_write_partsel_reg(msc, PART_SEL, partsel);
}

int mpam_register_requestor(u16 partid_max, u8 pmg_max)
{
	int err = 0;

	spin_lock(&partid_max_lock);
	if (!partid_max_init) {
		mpam_partid_max = partid_max;
		mpam_pmg_max = pmg_max;
		partid_max_init = true;
	} else if (!partid_max_published) {
		mpam_partid_max = min(mpam_partid_max, partid_max);
		mpam_pmg_max = min(mpam_pmg_max, pmg_max);
	} else {
		/* New requestors can't lower the values */
		if ((partid_max < mpam_partid_max) || (pmg_max < mpam_pmg_max))
			err = -EBUSY;
	}
	spin_unlock(&partid_max_lock);

	return err;
}
EXPORT_SYMBOL(mpam_register_requestor);

static struct mpam_component *
mpam_component_alloc(struct mpam_class *class, int id, gfp_t gfp)
{
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_list_lock);

	comp = kzalloc(sizeof(*comp), gfp);
	if (!comp)
		return ERR_PTR(-ENOMEM);

	comp->comp_id = id;
	INIT_LIST_HEAD_RCU(&comp->ris);
	/* affinity is updated when ris are added */
	INIT_LIST_HEAD_RCU(&comp->class_list);
	comp->class = class;

	list_add_rcu(&comp->class_list, &class->components);

	return comp;
}

static struct mpam_component *
mpam_component_get(struct mpam_class *class, int id, bool alloc, gfp_t gfp)
{
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_list_lock);

	list_for_each_entry(comp, &class->components, class_list) {
		if (comp->comp_id == id)
			return comp;
	}

	if (!alloc)
		return ERR_PTR(-ENOENT);

	return mpam_component_alloc(class, id, gfp);
}

static struct mpam_class *
mpam_class_alloc(u8 level_idx, enum mpam_class_types type, gfp_t gfp)
{
	struct mpam_class *class;

	lockdep_assert_held(&mpam_list_lock);

	class = kzalloc(sizeof(*class), gfp);
	if (!class)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD_RCU(&class->components);
	/* affinity is updated when ris are added */
	class->level = level_idx;
	class->type = type;
	INIT_LIST_HEAD_RCU(&class->classes_list);
	ida_init(&class->ida_csu_mon);
	ida_init(&class->ida_mbwu_mon);

	list_add_rcu(&class->classes_list, &mpam_classes);

	return class;
}

static struct mpam_class *
mpam_class_get(u8 level_idx, enum mpam_class_types type, bool alloc, gfp_t gfp)
{
	bool found = false;
	struct mpam_class *class;

	lockdep_assert_held(&mpam_list_lock);

	list_for_each_entry(class, &mpam_classes, classes_list) {
		if (class->type == type && class->level == level_idx) {
			found = true;
			break;
		}
	}

	if (found)
		return class;

	if (!alloc)
		return ERR_PTR(-ENOENT);

	return mpam_class_alloc(level_idx, type, gfp);
}

static void mpam_class_destroy(struct mpam_class *class)
{
	lockdep_assert_held(&mpam_list_lock);

	list_del_rcu(&class->classes_list);
	synchronize_srcu(&mpam_srcu);
	kfree(class);
}

static void mpam_comp_destroy(struct mpam_component *comp)
{
	struct mpam_class *class = comp->class;

	lockdep_assert_held(&mpam_list_lock);

	list_del_rcu(&comp->class_list);
	synchronize_srcu(&mpam_srcu);
	kfree(comp);

	if (list_empty(&class->components))
		mpam_class_destroy(class);
}

/* synchronise_srcu() before freeing ris */
static void mpam_ris_destroy(struct mpam_msc_ris *ris)
{
	struct mpam_component *comp = ris->comp;
	struct mpam_class *class = comp->class;
	struct mpam_msc *msc = ris->msc;

	lockdep_assert_held(&mpam_list_lock);
	lockdep_assert_preemption_enabled();

	clear_bit(ris->ris_idx, msc->ris_idxs);
	list_del_rcu(&ris->comp_list);
	list_del_rcu(&ris->msc_list);

	cpumask_andnot(&comp->affinity, &comp->affinity, &ris->affinity);
	cpumask_andnot(&class->affinity, &class->affinity, &ris->affinity);

	if (list_empty(&comp->ris))
		mpam_comp_destroy(comp);
}

/*
 * There are two ways of reaching a struct mpam_msc_ris. Via the
 * class->component->ris, or via the msc.
 * When destroying the msc, the other side needs unlinking and cleaning up too.
 * synchronise_srcu() before freeing msc.
 */
static void mpam_msc_destroy(struct mpam_msc *msc)
{
	struct mpam_msc_ris *ris, *tmp;

	lockdep_assert_held(&mpam_list_lock);
	lockdep_assert_preemption_enabled();

	list_for_each_entry_safe(ris, tmp, &msc->ris, msc_list)
		mpam_ris_destroy(ris);
}

/*
 * The cacheinfo structures are only populated when CPUs are online.
 * This helper walks the device tree to include offline CPUs too.
 */
static int get_cpumask_from_cache_id(u32 cache_id, u32 cache_level,
				     cpumask_t *affinity)
{
	int cpu, err;
	u32 iter_level;
	int iter_cache_id;
	struct device_node *iter;

	if (!acpi_disabled)
		return acpi_pptt_get_cpumask_from_cache_id(cache_id, affinity);

	for_each_possible_cpu(cpu) {
		iter = of_get_cpu_node(cpu, NULL);
		if (!iter) {
			pr_err("Failed to find cpu%d device node\n", cpu);
			return -ENOENT;
		}

		while ((iter = of_find_next_cache_node(iter))) {
			err = of_property_read_u32(iter, "cache-level",
						   &iter_level);
			if (err || (iter_level != cache_level)) {
				of_node_put(iter);
				continue;
			}

			/*
			 * get_cpu_cacheinfo_id() isn't ready until sometime
			 * during device_initcall(). Use cache_of_get_id().
			 */
			iter_cache_id = cache_of_get_id(iter);
			if (cache_id == ~0UL) {
				of_node_put(iter);
				continue;
			}

			if (iter_cache_id == cache_id)
				cpumask_set_cpu(cpu, affinity);

			of_node_put(iter);
		}
	}

	return 0;
}


/*
 * cpumask_of_node() only knows about online CPUs. This can't tell us whether
 * a class is represented on all possible CPUs.
 */
static void get_cpumask_from_node_id(u32 node_id, cpumask_t *affinity)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (node_id == cpu_to_node(cpu))
			cpumask_set_cpu(cpu, affinity);
	}
}

static int get_cpumask_from_cache(struct device_node *cache,
				  cpumask_t *affinity)
{
	int err;
	u32 cache_level;
	int cache_id;

	err = of_property_read_u32(cache, "cache-level", &cache_level);
	if (err) {
		pr_err("Failed to read cache-level from cache node\n");
		return -ENOENT;
	}

	cache_id = cache_of_get_id(cache);
	if (cache_id == ~0UL) {
		pr_err("Failed to calculate cache-id from cache node\n");
		return -ENOENT;
	}

	return get_cpumask_from_cache_id(cache_id, cache_level, affinity);
}

static int mpam_ris_get_affinity(struct mpam_msc *msc, cpumask_t *affinity,
				 enum mpam_class_types type,
				 struct mpam_class *class,
				 struct mpam_component *comp)
{
	int err;

	switch (type) {
	case MPAM_CLASS_CACHE:
		err = get_cpumask_from_cache_id(comp->comp_id, class->level,
						affinity);
		if (err)
			return err;

		if (cpumask_empty(affinity))
			pr_warn_once("%s no CPUs associated with cache node",
				     dev_name(&msc->pdev->dev));

		break;
	case MPAM_CLASS_MEMORY:
		get_cpumask_from_node_id(comp->comp_id, affinity);
		if (cpumask_empty(affinity))
			pr_warn_once("%s no CPUs associated with memory node",
				     dev_name(&msc->pdev->dev));
		break;
	case MPAM_CLASS_UNKNOWN:
		return 0;
	}

	cpumask_and(affinity, affinity, &msc->accessibility);

	return 0;
}

static int mpam_ris_create_locked(struct mpam_msc *msc, u8 ris_idx,
				  enum mpam_class_types type, u8 class_id,
				  int component_id, gfp_t gfp)
{
	int err;
	struct mpam_msc_ris *ris;
	struct mpam_class *class;
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_list_lock);

	if (test_and_set_bit(ris_idx, msc->ris_idxs))
		return -EBUSY;

	ris = devm_kzalloc(&msc->pdev->dev, sizeof(*ris), gfp);
	if (!ris)
		return -ENOMEM;

	class = mpam_class_get(class_id, type, true, gfp);
	if (IS_ERR(class))
		return PTR_ERR(class);

	comp = mpam_component_get(class, component_id, true, gfp);
	if (IS_ERR(comp)) {
		if (list_empty(&class->components))
			mpam_class_destroy(class);
		return PTR_ERR(comp);
	}

	err = mpam_ris_get_affinity(msc, &ris->affinity, type, class, comp);
	if (err) {
		if (list_empty(&class->components))
			mpam_class_destroy(class);
		return err;
	}

	ris->ris_idx = ris_idx;
	INIT_LIST_HEAD_RCU(&ris->comp_list);
	INIT_LIST_HEAD_RCU(&ris->msc_list);
	ris->msc = msc;
	ris->comp = comp;

	cpumask_or(&comp->affinity, &comp->affinity, &ris->affinity);
	cpumask_or(&class->affinity, &class->affinity, &ris->affinity);
	list_add_rcu(&ris->comp_list, &comp->ris);
	list_add_rcu(&ris->msc_list, &msc->ris);

	return 0;
}

int mpam_ris_create(struct mpam_msc *msc, u8 ris_idx,
		    enum mpam_class_types type, u8 class_id, int component_id)
{
	int err;

	mutex_lock(&mpam_list_lock);
	err = mpam_ris_create_locked(msc, ris_idx, type, class_id,
				     component_id, GFP_KERNEL);
	mutex_unlock(&mpam_list_lock);

	return err;
}

static struct mpam_msc_ris *mpam_get_or_create_ris(struct mpam_msc *msc,
						   u8 ris_idx)
{
	int err;
	struct mpam_msc_ris *ris, *found = ERR_PTR(-ENOENT);

	lockdep_assert_held(&mpam_list_lock);

	if (!test_bit(ris_idx, msc->ris_idxs)) {
		err = mpam_ris_create_locked(msc, ris_idx, MPAM_CLASS_UNKNOWN,
					     0, 0, GFP_ATOMIC);
		if (err)
			return ERR_PTR(err);
	}

	list_for_each_entry(ris, &msc->ris, msc_list) {
		if (ris->ris_idx == ris_idx) {
			found = ris;
			break;
		}
	}

	return found;
}

static void mpam_ris_hw_probe(struct mpam_msc_ris *ris)
{
	int err;
	struct mpam_msc *msc = ris->msc;
	struct mpam_props *props = &ris->props;
	struct mpam_class *class = ris->comp->class;

	lockdep_assert_held(&msc->lock);
	lockdep_assert_held(&msc->part_sel_lock);

	/* Cache Capacity Partitioning */
	if (FIELD_GET(MPAMF_IDR_HAS_CCAP_PART, ris->idr)) {
		u32 ccap_features = mpam_read_partsel_reg(msc, CCAP_IDR);

		props->cmax_wd = FIELD_GET(MPAMF_CCAP_IDR_CMAX_WD, ccap_features);
		if (props->cmax_wd)
			mpam_set_feature(mpam_feat_ccap_part, props);
	}

	/* Cache Portion partitioning */
	if (FIELD_GET(MPAMF_IDR_HAS_CPOR_PART, ris->idr)) {
		u32 cpor_features = mpam_read_partsel_reg(msc, CPOR_IDR);

		props->cpbm_wd = FIELD_GET(MPAMF_CPOR_IDR_CPBM_WD, cpor_features);
		if (props->cpbm_wd)
			mpam_set_feature(mpam_feat_cpor_part, props);
	}

	/* Memory bandwidth partitioning */
	if (FIELD_GET(MPAMF_IDR_HAS_MBW_PART, ris->idr)) {
		u32 mbw_features = mpam_read_partsel_reg(msc, MBW_IDR);

		/* portion bitmap resolution */
		props->mbw_pbm_bits = FIELD_GET(MPAMF_MBW_IDR_BWPBM_WD, mbw_features);
		if (props->mbw_pbm_bits &&
		    FIELD_GET(MPAMF_MBW_IDR_HAS_PBM, mbw_features))
			mpam_set_feature(mpam_feat_mbw_part, props);

		props->bwa_wd = FIELD_GET(MPAMF_MBW_IDR_BWA_WD, mbw_features);
		if (props->bwa_wd && FIELD_GET(MPAMF_MBW_IDR_HAS_MAX, mbw_features))
			mpam_set_feature(mpam_feat_mbw_max, props);

		if (props->bwa_wd && FIELD_GET(MPAMF_MBW_IDR_HAS_MIN, mbw_features))
			mpam_set_feature(mpam_feat_mbw_min, props);

		if (props->bwa_wd && FIELD_GET(MPAMF_MBW_IDR_HAS_PROP, mbw_features))
			mpam_set_feature(mpam_feat_mbw_prop, props);
	}

	/* Priority partitioning */
	if (FIELD_GET(MPAMF_IDR_HAS_PRI_PART, ris->idr)) {
		u32 pri_features = mpam_read_partsel_reg(msc, PRI_IDR);

		props->intpri_wd = FIELD_GET(MPAMF_PRI_IDR_INTPRI_WD, pri_features);
		if (props->intpri_wd && FIELD_GET(MPAMF_PRI_IDR_HAS_INTPRI, pri_features)) {
			mpam_set_feature(mpam_feat_intpri_part, props);
			if (FIELD_GET(MPAMF_PRI_IDR_INTPRI_0_IS_LOW, pri_features))
				mpam_set_feature(mpam_feat_intpri_part_0_low, props);
		}

		props->dspri_wd = FIELD_GET(MPAMF_PRI_IDR_DSPRI_WD, pri_features);
		if (props->dspri_wd && FIELD_GET(MPAMF_PRI_IDR_HAS_DSPRI, pri_features)) {
			mpam_set_feature(mpam_feat_dspri_part, props);
			if (FIELD_GET(MPAMF_PRI_IDR_DSPRI_0_IS_LOW, pri_features))
				mpam_set_feature(mpam_feat_dspri_part_0_low, props);
		}
	}

	/* Performance Monitoring */
	if (FIELD_GET(MPAMF_IDR_HAS_MSMON, ris->idr)) {
		u32 msmon_features = mpam_read_partsel_reg(msc, MSMON_IDR);

		if (FIELD_GET(MPAMF_MSMON_IDR_MSMON_CSU, msmon_features)) {
			u32 csumonidr, discard;

			/*
			 * If the firmware max-nrdy-us property is missing, the
			 * CSU counters can't be used. Should we wait forever?
			 */
			err = device_property_read_u32(&msc->pdev->dev,
						       "arm,not-ready-us",
						       &discard);

			csumonidr = mpam_read_partsel_reg(msc, CSUMON_IDR);
			props->num_csu_mon = FIELD_GET(MPAMF_CSUMON_IDR_NUM_MON, csumonidr);
			if (props->num_csu_mon && !err)
				mpam_set_feature(mpam_feat_msmon_csu, props);
			else if (props->num_csu_mon)
				pr_err_once("Counters are not usable because not-ready timeout was not provided by firmware.");
		}
		if (FIELD_GET(MPAMF_MSMON_IDR_MSMON_MBWU, msmon_features)) {
			bool has_long;
			u32 mbwumonidr = mpam_read_partsel_reg(msc, MBWUMON_IDR);

			props->num_mbwu_mon = FIELD_GET(MPAMF_MBWUMON_IDR_NUM_MON, mbwumonidr);
			if (props->num_mbwu_mon)
				mpam_set_feature(mpam_feat_msmon_mbwu, props);

			if (FIELD_GET(MPAMF_MBWUMON_IDR_HAS_RWBW, mbwumonidr))
				mpam_set_feature(mpam_feat_msmon_mbwu_rwbw, props);

			/*
			 * Treat long counter and its extension, lwd as mutually
			 * exclusive feature bits. Though these are dependent
			 * fields at the implementation level, there would never
			 * be a need for mpam_feat_msmon_mbwu_44counter (long
			 * counter) and mpam_feat_msmon_mbwu_63counter (lwd)
			 * bits to be set together.
			 *
			 * mpam_feat_msmon_mbwu isn't treated as an exclusive
			 * bit as this feature bit would be used as the "front
			 * facing feature bit" for any checks related to mbwu
			 * monitors.
			 */
			has_long = FIELD_GET(MPAMF_MBWUMON_IDR_HAS_LONG, mbwumonidr);
			if (props->num_mbwu_mon && has_long) {
				if (FIELD_GET(MPAMF_MBWUMON_IDR_LWD, mbwumonidr))
					mpam_set_feature(mpam_feat_msmon_mbwu_63counter, props);
				else
					mpam_set_feature(mpam_feat_msmon_mbwu_44counter, props);
			}
		}
	}

	/*
	 * RIS with PARTID narrowing don't have enough storage for one
	 * configuration per PARTID. If these are in a class we could use,
	 * reduce the supported partid_max to match the numer of intpartid.
	 * If the class is unknown, just ignore it.
	 */
	if (FIELD_GET(MPAMF_IDR_HAS_PARTID_NRW, ris->idr) &&
	    class->type != MPAM_CLASS_UNKNOWN) {
		u32 nrwidr = mpam_read_partsel_reg(msc, PARTID_NRW_IDR);
		u16 partid_max = FIELD_GET(MPAMF_PARTID_NRW_IDR_INTPARTID_MAX, nrwidr);

		mpam_set_feature(mpam_feat_partid_nrw, props);
		msc->partid_max = min(msc->partid_max, partid_max);
	}
}

static int mpam_msc_hw_probe(struct mpam_msc *msc)
{
	u64 idr;
	u16 partid_max;
	u8 ris_idx, pmg_max;
	struct mpam_msc_ris *ris;

	lockdep_assert_held(&msc->lock);

	spin_lock(&msc->part_sel_lock);
	idr = mpam_read_partsel_reg(msc, AIDR);
	if ((idr & MPAMF_AIDR_ARCH_MAJOR_REV) != MPAM_ARCHITECTURE_V1) {
		pr_err_once("%s does not match MPAM architecture v1.0\n",
			    dev_name(&msc->pdev->dev));
		spin_unlock(&msc->part_sel_lock);
		return -EIO;
	}

	idr = mpam_msc_read_idr(msc);
	spin_unlock(&msc->part_sel_lock);

	msc->ris_max = FIELD_GET(MPAMF_IDR_RIS_MAX, idr);

	/* Use these values so partid/pmg always starts with a valid value */
	msc->partid_max = FIELD_GET(MPAMF_IDR_PARTID_MAX, idr);
	msc->pmg_max = FIELD_GET(MPAMF_IDR_PMG_MAX, idr);

	for (ris_idx = 0; ris_idx <= msc->ris_max; ris_idx++) {
		spin_lock(&msc->part_sel_lock);
		__mpam_part_sel(ris_idx, 0, msc);
		idr = mpam_msc_read_idr(msc);
		spin_unlock(&msc->part_sel_lock);

		partid_max = FIELD_GET(MPAMF_IDR_PARTID_MAX, idr);
		pmg_max = FIELD_GET(MPAMF_IDR_PMG_MAX, idr);
		msc->partid_max = min(msc->partid_max, partid_max);
		msc->pmg_max = min(msc->pmg_max, pmg_max);
		msc->has_extd_esr = FIELD_GET(MPAMF_IDR_HAS_EXT_ESR, idr);

		ris = mpam_get_or_create_ris(msc, ris_idx);
		if (IS_ERR(ris)) {
			return PTR_ERR(ris);
		}
		ris->idr = idr;

		spin_lock(&msc->part_sel_lock);
		__mpam_part_sel(ris_idx, 0, msc);
		mpam_ris_hw_probe(ris);
		spin_unlock(&msc->part_sel_lock);
	}

	spin_lock(&partid_max_lock);
	mpam_partid_max = min(mpam_partid_max, msc->partid_max);
	mpam_pmg_max = min(mpam_pmg_max, msc->pmg_max);
	spin_unlock(&partid_max_lock);

	msc->probed = true;

	return 0;
}

struct mon_read
{
	struct mpam_msc_ris		*ris;
	struct mon_cfg			*ctx;
	enum mpam_device_features	type;
	u64				*val;
	int				err;
};

static bool mpam_ris_has_mbwu_long_counter(struct mpam_msc_ris *ris)
{
	return (mpam_has_feature(mpam_feat_msmon_mbwu_63counter, &ris->props) ||
		mpam_has_feature(mpam_feat_msmon_mbwu_44counter, &ris->props));
}

static u64 mpam_msc_read_mbwu_l(struct mpam_msc *msc)
{
	int retry = 3;
	u32 mbwu_l_low;
	u64 mbwu_l_high1, mbwu_l_high2;

	lockdep_assert_held_once(&msc->mon_sel_lock);

	WARN_ON_ONCE((MSMON_MBWU_L + sizeof(u64)) > msc->mapped_hwpage_sz);
	WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(), &msc->accessibility));

	mbwu_l_high2 = readl_relaxed(msc->mapped_hwpage + MSMON_MBWU_L + 4);
	do {
		mbwu_l_high1 = mbwu_l_high2;
		mbwu_l_low = readl_relaxed(msc->mapped_hwpage + MSMON_MBWU_L);
		mbwu_l_high2 = readl_relaxed(msc->mapped_hwpage + MSMON_MBWU_L + 4);

		retry--;
	} while (mbwu_l_high1 != mbwu_l_high2 && retry > 0);

	if (mbwu_l_high2 == mbwu_l_high1)
		return (mbwu_l_high1 << 32) | mbwu_l_low;
	return MSMON___NRDY_L;
}

static void mpam_msc_zero_mbwu_l(struct mpam_msc *msc)
{
	lockdep_assert_held_once(&msc->mon_sel_lock);

	WARN_ON_ONCE((MSMON_MBWU_L + sizeof(u64)) > msc->mapped_hwpage_sz);
	WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(), &msc->accessibility));

	writel_relaxed(0, msc->mapped_hwpage + MSMON_MBWU_L);
	writel_relaxed(0, msc->mapped_hwpage + MSMON_MBWU_L + 4);
}

static void gen_msmon_ctl_flt_vals(struct mon_read *m, u32 *ctl_val,
				   u32 *flt_val)
{
	struct mon_cfg *ctx = m->ctx;

	switch (m->type) {
	case mpam_feat_msmon_csu:
		*ctl_val = MSMON_CFG_MBWU_CTL_TYPE_CSU;
		break;
	case mpam_feat_msmon_mbwu:
		*ctl_val = MSMON_CFG_MBWU_CTL_TYPE_MBWU;
		break;
	default:
		return;
	}

	/*
	 * For CSU counters its implementation-defined what happens when not
	 * filtering by partid.
	 */
	*ctl_val |= MSMON_CFG_x_CTL_MATCH_PARTID;

	*flt_val = FIELD_PREP(MSMON_CFG_MBWU_FLT_PARTID, ctx->partid);
	*flt_val |= FIELD_PREP(MSMON_CFG_MBWU_FLT_RWBW, ctx->opts);
	if (m->ctx->match_pmg) {
		*ctl_val |= MSMON_CFG_x_CTL_MATCH_PMG;
		*flt_val |= FIELD_PREP(MSMON_CFG_MBWU_FLT_PMG, ctx->pmg);
	}

	if (mpam_has_feature(mpam_feat_msmon_mbwu_rwbw, &m->ris->props))
		*flt_val |= FIELD_PREP(MSMON_CFG_MBWU_FLT_RWBW, ctx->opts);
}

static void read_msmon_ctl_flt_vals(struct mon_read *m, u32 *ctl_val,
				    u32 *flt_val)
{
	struct mpam_msc *msc = m->ris->msc;

	switch (m->type) {
	case mpam_feat_msmon_csu:
		*ctl_val = mpam_read_monsel_reg(msc, CFG_CSU_CTL);
		*flt_val = mpam_read_monsel_reg(msc, CFG_CSU_FLT);
		break;
	case mpam_feat_msmon_mbwu:
		*ctl_val = mpam_read_monsel_reg(msc, CFG_MBWU_CTL);
		*flt_val = mpam_read_monsel_reg(msc, CFG_MBWU_FLT);
		break;
	default:
		return;
	}
}

static void write_msmon_ctl_flt_vals(struct mon_read *m, u32 ctl_val,
				     u32 flt_val)
{
	struct mpam_msc *msc = m->ris->msc;
	struct msmon_mbwu_state *mbwu_state;

	/*
	 * Write the ctl_val with the enable bit cleared, reset the counter,
	 * then enable counter.
	 */
	switch (m->type) {
	case mpam_feat_msmon_csu:
		mpam_write_monsel_reg(msc, CFG_CSU_FLT, flt_val);
		mpam_write_monsel_reg(msc, CFG_CSU_CTL, ctl_val);
		mpam_write_monsel_reg(msc, CSU, 0);
		mpam_write_monsel_reg(msc, CFG_CSU_CTL, ctl_val|MSMON_CFG_x_CTL_EN);
		break;
	case mpam_feat_msmon_mbwu:
		mpam_write_monsel_reg(msc, CFG_MBWU_FLT, flt_val);
		mpam_write_monsel_reg(msc, CFG_MBWU_CTL, ctl_val);

		if (mpam_ris_has_mbwu_long_counter(m->ris))
			mpam_msc_zero_mbwu_l(m->ris->msc);
		else
			mpam_write_monsel_reg(msc, MBWU, 0);

		mpam_write_monsel_reg(msc, CFG_MBWU_CTL, ctl_val|MSMON_CFG_x_CTL_EN);

		mbwu_state = &m->ris->mbwu_state[m->ctx->mon];
		if (mbwu_state)
			mbwu_state->prev_val = 0;

		break;
	default:
		return;
	}
}

static u64 mpam_msmon_overflow_val(struct mpam_msc_ris *ris)
{
	/* TODO: implement scaling counters */
	if (mpam_has_feature(mpam_feat_msmon_mbwu_63counter, &ris->props))
		return GENMASK_ULL(62, 0);
	else if (mpam_has_feature(mpam_feat_msmon_mbwu_44counter, &ris->props))
		return GENMASK_ULL(43, 0);
	else
		return GENMASK_ULL(30, 0);
}

static void __ris_msmon_read(void *arg)
{
	bool nrdy = false;
	unsigned long flags;
	bool config_mismatch;
	struct mon_read *m = arg;
	u64 now, overflow_val = 0;
	struct mon_cfg *ctx = m->ctx;
	bool reset_on_next_read = false;
	struct mpam_msc_ris *ris = m->ris;
	struct mpam_msc *msc = m->ris->msc;
	struct msmon_mbwu_state *mbwu_state;
	u32 mon_sel, ctl_val, flt_val, cur_ctl, cur_flt;

	lockdep_assert_held(&msc->lock);

	spin_lock_irqsave(&msc->mon_sel_lock, flags);
	mon_sel = FIELD_PREP(MSMON_CFG_MON_SEL_MON_SEL, ctx->mon) |
		  FIELD_PREP(MSMON_CFG_MON_SEL_RIS, ris->ris_idx);
	mpam_write_monsel_reg(msc, CFG_MON_SEL, mon_sel);

	if (m->type == mpam_feat_msmon_mbwu) {
		mbwu_state = &ris->mbwu_state[ctx->mon];
		if (mbwu_state) {
			reset_on_next_read = mbwu_state->reset_on_next_read;
			mbwu_state->reset_on_next_read = false;
		}
	}

	/*
	 * Read the existing configuration to avoid re-writing the same values.
	 * This saves waiting for 'nrdy' on subsequent reads.
	 */
	read_msmon_ctl_flt_vals(m, &cur_ctl, &cur_flt);
	gen_msmon_ctl_flt_vals(m, &ctl_val, &flt_val);
	config_mismatch = cur_flt != flt_val ||
			  cur_ctl != (ctl_val | MSMON_CFG_x_CTL_EN);

	if (config_mismatch || reset_on_next_read)
		write_msmon_ctl_flt_vals(m, ctl_val, flt_val);

	switch (m->type) {
	case mpam_feat_msmon_csu:
		now = mpam_read_monsel_reg(msc, CSU);
		nrdy = now & MSMON___NRDY;
		now = FIELD_GET(MSMON___VALUE, now);
		break;
	case mpam_feat_msmon_mbwu:
		/*
		 * If long or lwd counters are supported, use them, else revert
		 * to the 32 bit counter.
		 */
		if (mpam_ris_has_mbwu_long_counter(ris)) {
			now = mpam_msc_read_mbwu_l(msc);
			nrdy = now & MSMON___NRDY_L;
			if (mpam_has_feature(mpam_feat_msmon_mbwu_63counter, &ris->props))
				now = FIELD_GET(MSMON___LWD_VALUE, now);
			else
				now = FIELD_GET(MSMON___L_VALUE, now);
		} else {
			now = mpam_read_monsel_reg(msc, MBWU);
			nrdy = now & MSMON___NRDY;
			now = FIELD_GET(MSMON___VALUE, now);
		}

		if (nrdy)
			break;

		if (!mbwu_state)
			break;

		/* Add any pre-overflow value to the mbwu_state->val */
		if (mbwu_state->prev_val > now)
			overflow_val = mpam_msmon_overflow_val(ris) - mbwu_state->prev_val;

		mbwu_state->prev_val = now;
		mbwu_state->correction += overflow_val;

		/* Include bandwidth consumed before the last hardware reset */
		now += mbwu_state->correction;
		break;
	default:
		return;
	}
	spin_unlock_irqrestore(&msc->mon_sel_lock, flags);

	if (nrdy) {
		m->err = -EBUSY;
		return;
	}

	*(m->val) += now;
}

static int _msmon_read(struct mpam_component *comp, struct mon_read *arg)
{
	int err, idx;
	struct mpam_msc *msc;
	struct mpam_msc_ris *ris;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(ris, &comp->ris, comp_list) {
		arg->ris = ris;

		msc = ris->msc;
		mutex_lock(&msc->lock);
		err = smp_call_function_any(&msc->accessibility,
					    __ris_msmon_read, arg, true);
		mutex_unlock(&msc->lock);
		if (!err && arg->err)
			err = arg->err;
		if (err)
			break;
	}
	srcu_read_unlock(&mpam_srcu, idx);

	return err;
}

int mpam_msmon_read(struct mpam_component *comp, struct mon_cfg *ctx,
		    enum mpam_device_features type, u64 *val)
{
	int err;
	struct mon_read arg;
	u64 wait_jiffies = 0;
	struct mpam_props *cprops = &comp->class->props;

	might_sleep();

	if (!mpam_is_enabled())
		return -EIO;

	if (!mpam_has_feature(type, cprops))
		return -EOPNOTSUPP;

	memset(&arg, 0, sizeof(arg));
	arg.ctx = ctx;
	arg.type = type;
	arg.val = val;
	*val = 0;

	err = _msmon_read(comp, &arg);
	if (err == -EBUSY)
		wait_jiffies = usecs_to_jiffies(comp->class->nrdy_usec);

	while (wait_jiffies)
		wait_jiffies = schedule_timeout_uninterruptible(wait_jiffies);

	if (err == -EBUSY) {
		memset(&arg, 0, sizeof(arg));
		arg.ctx = ctx;
		arg.type = type;
		arg.val = val;
		*val = 0;

		err = _msmon_read(comp, &arg);
	}

	return err;
}

void mpam_msmon_reset_all_mbwu(struct mpam_component *comp)
{
	int idx, i;
	unsigned long flags;
	struct mpam_msc *msc;
	struct mpam_msc_ris *ris;

	if (!mpam_is_enabled())
		return;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(ris, &comp->ris, comp_list) {
		if (!mpam_has_feature(mpam_feat_msmon_mbwu, &ris->props))
			continue;

		msc = ris->msc;
		spin_lock_irqsave(&msc->mon_sel_lock, flags);
		for(i = 0; i < ris->props.num_mbwu_mon; i++) {
			ris->mbwu_state[i].correction = 0;
			ris->mbwu_state[i].reset_on_next_read = true;
		}
		spin_unlock_irqrestore(&msc->mon_sel_lock, flags);
	}
	srcu_read_unlock(&mpam_srcu, idx);
}

void mpam_msmon_reset_mbwu(struct mpam_component *comp, struct mon_cfg *ctx)
{
	int idx;
	unsigned long flags;
	struct mpam_msc *msc;
	struct mpam_msc_ris *ris;

	if (!mpam_is_enabled())
		return;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(ris, &comp->ris, comp_list) {
		if (!mpam_has_feature(mpam_feat_msmon_mbwu, &ris->props))
			continue;

		msc = ris->msc;
		spin_lock_irqsave(&msc->mon_sel_lock, flags);
		ris->mbwu_state[ctx->mon].correction = 0;
		ris->mbwu_state[ctx->mon].reset_on_next_read = true;
		spin_unlock_irqrestore(&msc->mon_sel_lock, flags);
	}
	srcu_read_unlock(&mpam_srcu, idx);
}

static void mpam_reset_msc_bitmap(struct mpam_msc *msc, u16 reg, u16 wd)
{
	u32 num_words, msb;
	u32 bm = ~0;
	int i;

	lockdep_assert_held(&msc->part_sel_lock);

	/*
	 * Write all ~0 to all but the last 32bit-word, which may
	 * have fewer bits...
	 */
	num_words = DIV_ROUND_UP(wd, 32);
	for (i = 0; i < num_words - 1; i++, reg += sizeof(bm))
		__mpam_write_reg(msc, reg, bm);

	/*
	 * ....and then the last (maybe) partial 32bit word. When wd is a
	 * multiple of 32, msb should be 31 to write a full 32bit word.
	 */
	msb = (wd - 1) % 32;
	bm = GENMASK(msb , 0);
	if (bm)
		__mpam_write_reg(msc, reg, bm);
}

static void mpam_reprogram_ris_partid(struct mpam_msc_ris *ris, u16 partid,
				      struct mpam_config *cfg)
{
	u32 pri_val = 0;
	u16 cmax = MPAMCFG_CMAX_CMAX;
	struct mpam_msc *msc = ris->msc;
	u16 bwa_fract = MPAMCFG_MBW_MAX_MAX;
	struct mpam_props *rprops = &ris->props;
	u16 dspri = GENMASK(rprops->dspri_wd, 0);
	u16 intpri = GENMASK(rprops->intpri_wd, 0);

	spin_lock(&msc->part_sel_lock);
	__mpam_part_sel(ris->ris_idx, partid, msc);

	if(mpam_has_feature(mpam_feat_partid_nrw, rprops))
		mpam_write_partsel_reg(msc, INTPARTID,
				      (MPAMCFG_PART_SEL_INTERNAL | partid));

	if (mpam_has_feature(mpam_feat_cpor_part, rprops)) {
		if (mpam_has_feature(mpam_feat_cpor_part, cfg))
			mpam_write_partsel_reg(msc, CPBM, cfg->cpbm);
		else
			mpam_reset_msc_bitmap(msc, MPAMCFG_CPBM,
					      rprops->cpbm_wd);
	}

	if (mpam_has_feature(mpam_feat_mbw_part, rprops)) {
		if (mpam_has_feature(mpam_feat_mbw_part, cfg))
			mpam_write_partsel_reg(msc, MBW_PBM, cfg->mbw_pbm);
		else
			mpam_reset_msc_bitmap(msc, MPAMCFG_MBW_PBM,
					      rprops->mbw_pbm_bits);
	}

	if (mpam_has_feature(mpam_feat_mbw_min, rprops))
		mpam_write_partsel_reg(msc, MBW_MIN, 0);

	if (mpam_has_feature(mpam_feat_mbw_max, rprops)) {
		if (mpam_has_feature(mpam_feat_mbw_max, cfg))
			mpam_write_partsel_reg(msc, MBW_MAX, cfg->mbw_max);
		else
			mpam_write_partsel_reg(msc, MBW_MAX, bwa_fract);
	}

	if (mpam_has_feature(mpam_feat_mbw_prop, rprops))
		mpam_write_partsel_reg(msc, MBW_PROP, bwa_fract);

	if (mpam_has_feature(mpam_feat_ccap_part, rprops))
		mpam_write_partsel_reg(msc, CMAX, cmax);

	if (mpam_has_feature(mpam_feat_intpri_part, rprops) ||
	    mpam_has_feature(mpam_feat_dspri_part, rprops)) {
		/* aces high? */
		if (!mpam_has_feature(mpam_feat_intpri_part_0_low, rprops))
			intpri = 0;
		if (!mpam_has_feature(mpam_feat_dspri_part_0_low, rprops))
			dspri = 0;

		if (mpam_has_feature(mpam_feat_intpri_part, rprops))
			pri_val |= FIELD_PREP(MPAMCFG_PRI_INTPRI, intpri);
		if (mpam_has_feature(mpam_feat_dspri_part, rprops))
			pri_val |= FIELD_PREP(MPAMCFG_PRI_DSPRI, dspri);

		mpam_write_partsel_reg(msc, PRI, pri_val);
	}

	spin_unlock(&msc->part_sel_lock);
}

struct reprogram_ris {
	struct mpam_msc_ris *ris;
	struct mpam_config *cfg;
};

/* Call with MSC lock held */
static int mpam_reprogram_ris(void *_arg)
{
	u16 partid, partid_max;
	struct reprogram_ris *arg = _arg;
	struct mpam_msc_ris *ris = arg->ris;
	struct mpam_config *cfg = arg->cfg;

	if (ris->in_reset_state)
		return 0;

	spin_lock(&partid_max_lock);
	partid_max = mpam_partid_max;
	spin_unlock(&partid_max_lock);
	for (partid = 0; partid < partid_max; partid++)
		mpam_reprogram_ris_partid(ris, partid, cfg);

	return 0;
}

static int mpam_restore_mbwu_state(void *_ris)
{
	int i;
	struct mon_read mwbu_arg;
	struct mpam_msc_ris *ris = _ris;

	for (i = 0; i < ris->props.num_mbwu_mon; i++) {
		if (ris->mbwu_state[i].enabled) {
			mwbu_arg.ris = ris;
			mwbu_arg.ctx = &ris->mbwu_state[i].cfg;
			mwbu_arg.type = mpam_feat_msmon_mbwu;

			__ris_msmon_read(&mwbu_arg);
		}
	}

	return 0;
}

static int mpam_save_mbwu_state(void *arg)
{
	int i;
	u64 val;
	struct mon_cfg *cfg;
	unsigned long flags;
	u32 cur_flt, cur_ctl, mon_sel;
	struct mpam_msc_ris *ris = arg;
	struct mpam_msc *msc = ris->msc;
	struct msmon_mbwu_state *mbwu_state;

	for (i = 0; i < ris->props.num_mbwu_mon; i++) {
		mbwu_state = &ris->mbwu_state[i];
		cfg = &mbwu_state->cfg;

		spin_lock_irqsave(&msc->mon_sel_lock, flags);
		mon_sel = FIELD_PREP(MSMON_CFG_MON_SEL_MON_SEL, i) |
			  FIELD_PREP(MSMON_CFG_MON_SEL_RIS, ris->ris_idx);
		mpam_write_monsel_reg(msc, CFG_MON_SEL, mon_sel);

		cur_flt = mpam_read_monsel_reg(msc, CFG_MBWU_FLT);
		cur_ctl = mpam_read_monsel_reg(msc, CFG_MBWU_CTL);
		mpam_write_monsel_reg(msc, CFG_MBWU_CTL, 0);

		if (mpam_ris_has_mbwu_long_counter(ris)) {
			val = mpam_msc_read_mbwu_l(msc);
			mpam_msc_zero_mbwu_l(msc);
		} else {
			val = mpam_read_monsel_reg(msc, MBWU);
			mpam_write_monsel_reg(msc, MBWU, 0);
		}

		cfg->mon = i;
		cfg->pmg = FIELD_GET(MSMON_CFG_MBWU_FLT_PMG, cur_flt);
		cfg->match_pmg = FIELD_GET(MSMON_CFG_x_CTL_MATCH_PMG, cur_ctl);
		cfg->partid = FIELD_GET(MSMON_CFG_MBWU_FLT_PARTID, cur_flt);
		mbwu_state->correction += val;
		mbwu_state->enabled = FIELD_GET(MSMON_CFG_x_CTL_EN, cur_ctl);
		spin_unlock_irqrestore(&msc->mon_sel_lock, flags);
	}

	return 0;
}

/*
 * Called via smp_call_on_cpu() to prevent migration, while still being
 * pre-emptible.
 */
static int mpam_reset_ris(void *arg)
{
	struct mpam_msc_ris *ris = arg;
	struct reprogram_ris reprogram_arg;
	struct mpam_config empty_cfg = { 0 };

	if (ris->in_reset_state)
		return 0;

	reprogram_arg.ris = ris;
	reprogram_arg.cfg = &empty_cfg;

	mpam_reprogram_ris(&reprogram_arg);

	return 0;
}

/*
 * Get the preferred CPU for this MSC. If it is accessible from this CPU,
 * this CPU is preferred. This can be preempted/migrated, it will only result
 * in more work.
 */
static int mpam_get_msc_preferred_cpu(struct mpam_msc *msc)
{
	int cpu = raw_smp_processor_id();

	if (cpumask_test_cpu(cpu, &msc->accessibility))
		return cpu;

	return cpumask_first_and(&msc->accessibility, cpu_online_mask);
}

static int mpam_touch_msc(struct mpam_msc *msc, int (*fn)(void *a), void *arg)
{
	lockdep_assert_irqs_enabled();
	lockdep_assert_cpus_held();
	lockdep_assert_held(&msc->lock);

	return smp_call_on_cpu(mpam_get_msc_preferred_cpu(msc), fn, arg, true);
}

static void mpam_reset_msc(struct mpam_msc *msc, bool online)
{
	int idx;
	struct mpam_msc_ris *ris;

	lockdep_assert_held(&msc->lock);

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(ris, &msc->ris, msc_list) {
		mpam_touch_msc(msc, &mpam_reset_ris, ris);

		/*
		 * Set in_reset_state when coming online. The reset state
		 * for non-zero partid may be lost while the CPUs are offline.
		 */
		ris->in_reset_state = online;

		if (mpam_is_enabled() && !online)
			mpam_touch_msc(msc, &mpam_save_mbwu_state, ris);
	}
	srcu_read_unlock(&mpam_srcu, idx);
}

static void mpam_reprogram_msc(struct mpam_msc *msc)
{
	int idx;
	u16 partid;
	bool reset;
	struct mpam_config *cfg;
	struct mpam_msc_ris *ris;

	lockdep_assert_held(&msc->lock);

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(ris, &msc->ris, msc_list) {
		if (!mpam_is_enabled() && !ris->in_reset_state) {
			mpam_touch_msc(msc, &mpam_reset_ris, ris);
			ris->in_reset_state = true;
			continue;
		}

		reset = true;
		for (partid = 0; partid < mpam_partid_max; partid++) {
			cfg = &ris->comp->cfg[partid];
			if (cfg->features)
				reset = false;

			mpam_reprogram_ris_partid(ris, partid, cfg);
		}
		ris->in_reset_state = reset;

		if (mpam_has_feature(mpam_feat_msmon_mbwu, &ris->props))
			mpam_touch_msc(msc, &mpam_restore_mbwu_state, ris);
	}
	srcu_read_unlock(&mpam_srcu, idx);
}

static void _enable_percpu_irq(void *_irq)
{
	int *irq = _irq;
	enable_percpu_irq(*irq, IRQ_TYPE_NONE);
}

static int mpam_cpu_online(unsigned int cpu)
{
	int idx;
	struct mpam_msc *msc;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(msc, &mpam_all_msc, glbl_list) {
		if (!cpumask_test_cpu(cpu, &msc->accessibility))
			continue;

		mutex_lock(&msc->lock);
		if (msc->reenable_error_ppi)
			_enable_percpu_irq(&msc->reenable_error_ppi);

		if (atomic_fetch_inc(&msc->online_refs) == 0)
			mpam_reprogram_msc(msc);
		mutex_unlock(&msc->lock);
	}
	srcu_read_unlock(&mpam_srcu, idx);

	if (mpam_is_enabled())
		mpam_resctrl_online_cpu(cpu);

	return 0;
}

/* Before mpam is enabled, try to probe new MSC */
static int mpam_discovery_cpu_online(unsigned int cpu)
{
	int err = 0;
	struct mpam_msc *msc;
	bool new_device_probed = false;

	if (mpam_is_enabled())
		return 0;

	mutex_lock(&mpam_list_lock);
	list_for_each_entry(msc, &mpam_all_msc, glbl_list) {
		if (!cpumask_test_cpu(cpu, &msc->accessibility))
			continue;

		mutex_lock(&msc->lock);
		if (!msc->probed)
			err = mpam_msc_hw_probe(msc);
		mutex_unlock(&msc->lock);

		if (!err)
			new_device_probed = true;
		else
			break; // mpam_broken
	}
	mutex_unlock(&mpam_list_lock);

	if (new_device_probed && !err)
		schedule_work(&mpam_enable_work);

	if (err < 0)
		return err;

	return mpam_cpu_online(cpu);
}

static int mpam_cpu_offline(unsigned int cpu)
{
	int idx;
	struct mpam_msc *msc;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(msc, &mpam_all_msc, glbl_list) {
		if (!cpumask_test_cpu(cpu, &msc->accessibility))
			continue;

		mutex_lock(&msc->lock);
		if (msc->reenable_error_ppi)
			disable_percpu_irq(msc->reenable_error_ppi);

		if (atomic_dec_and_test(&msc->online_refs))
			mpam_reset_msc(msc, false);
		mutex_unlock(&msc->lock);
	}
	srcu_read_unlock(&mpam_srcu, idx);

	if (mpam_is_enabled())
		mpam_resctrl_offline_cpu(cpu);

	return 0;
}

static void mpam_register_cpuhp_callbacks(int (*online)(unsigned int online))
{
	mutex_lock(&mpam_cpuhp_state_lock);
	mpam_cpuhp_state = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mpam:online",
					     online, mpam_cpu_offline);
	if (mpam_cpuhp_state <= 0) {
		pr_err("Failed to register cpuhp callbacks");
		mpam_cpuhp_state = 0;
	}
	mutex_unlock(&mpam_cpuhp_state_lock);
}

static int __setup_ppi(struct mpam_msc *msc)
{
	int cpu;

	msc->error_dev_id = alloc_percpu_gfp(struct mpam_msc *, GFP_KERNEL);
	if (!msc->error_dev_id)
		return -ENOMEM;

	for_each_cpu(cpu, &msc->accessibility) {
		struct mpam_msc *empty = *per_cpu_ptr(msc->error_dev_id, cpu);
		if (empty != NULL) {
			pr_err_once("%s shares PPI with %s!\n", 				    dev_name(&msc->pdev->dev),
				    dev_name(&empty->pdev->dev));
			return -EBUSY;
		}
		*per_cpu_ptr(msc->error_dev_id, cpu) = msc;
	}

	return 0;
}

static int mpam_msc_setup_error_irq(struct mpam_msc *msc)
{
	int irq;

	irq = platform_get_irq_byname_optional(msc->pdev, "error");
	if (irq <= 0)
		return 0;

	/* Allocate and initialise the percpu device pointer for PPI */
	if (irq_is_percpu(irq))

		return __setup_ppi(msc);

	/* sanity check: shared interrupts can be routed anywhere? */
	if (!cpumask_equal(&msc->accessibility, cpu_possible_mask)) {
		pr_err_once("msc:%u is a private resource with a shared error interrupt",
			    msc->id);
		return -EINVAL;
	}

	return 0;
}

static int mpam_dt_count_msc(void)
{
	int count = 0;
	struct device_node *np;

	for_each_compatible_node(np, NULL, "arm,mpam-msc")
		count++;

	return count;
}

static int mpam_dt_parse_resource(struct mpam_msc *msc, struct device_node *np,
				  u32 ris_idx)
{
	int err = 0;
	u32 level = 0;
	unsigned long cache_id;
	struct device_node *cache;

	do {
		if (of_device_is_compatible(np, "arm,mpam-cache")) {
			cache = of_parse_phandle(np, "arm,mpam-device", 0);
			if (!cache) {
				pr_err("Failed to read phandle\n");
				break;
			}
		} else if (of_device_is_compatible(np->parent, "cache")) {
			cache = np->parent;
		} else {
			/* For now, only caches are supported */
			cache = NULL;
			break;
		}

		err = of_property_read_u32(cache, "cache-level", &level);
		if (err) {
			pr_err("Failed to read cache-level\n");
			break;
		}

		cache_id = cache_of_get_id(cache);
		if (cache_id == ~0UL) {
			err = -ENOENT;
			break;
		}

		err = mpam_ris_create(msc, ris_idx, MPAM_CLASS_CACHE, level,
				      cache_id);
	} while (0);
	of_node_put(cache);

	return err;
}


static int mpam_dt_parse_resources(struct mpam_msc *msc, void *ignored)
{
	int err, num_ris = 0;
	const u32 *ris_idx_p;
	struct device_node *iter, *np;

	np = msc->pdev->dev.of_node;
	for_each_child_of_node(np, iter) {
		ris_idx_p = of_get_property(iter, "reg", NULL);
		if (ris_idx_p) {
			num_ris++;
			err = mpam_dt_parse_resource(msc, iter, *ris_idx_p);
			if (err) {
				of_node_put(iter);
				return err;
			}
		}
	}

	if (!num_ris)
		mpam_dt_parse_resource(msc, np, 0);

	return err;
}

static int get_msc_affinity(struct mpam_msc *msc)
{
	struct device_node *parent;
	u32 affinity_id;
	int err;

	if (!acpi_disabled) {
		err = device_property_read_u32(&msc->pdev->dev, "cpu_affinity",
					       &affinity_id);
		if (err) {
			cpumask_copy(&msc->accessibility, cpu_possible_mask);
			err = 0;
		} else {
			err = acpi_pptt_get_cpus_from_container(affinity_id,
								&msc->accessibility);
		}

		return err;
	}

	/* This depends on the path to of_node */
	parent = of_get_parent(msc->pdev->dev.of_node);
	if (parent == of_root) {
		cpumask_copy(&msc->accessibility, cpu_possible_mask);
		err = 0;
	} else {
		if (of_device_is_compatible(parent, "cache")) {
			err = get_cpumask_from_cache(parent,
						     &msc->accessibility);
		} else {
			err = -EINVAL;
			pr_err("Cannot determine accessibility of MSC: %s\n",
			       dev_name(&msc->pdev->dev));
		}
	}
	of_node_put(parent);

	return err;
}

static int fw_num_msc;

static void mpam_pcc_rx_callback(struct mbox_client *cl, void *msg)
{
	/* TODO: wake up tasks blocked on this MSC's PCC channel */
}

static int mpam_msc_drv_probe(struct platform_device *pdev)
{
	int err;
	pgprot_t prot;
	void * __iomem io;
	struct mpam_msc *msc;
	struct resource *msc_res;
	void *plat_data = pdev->dev.platform_data;

	mutex_lock(&mpam_list_lock);
	do {
		msc = devm_kzalloc(&pdev->dev, sizeof(*msc), GFP_KERNEL);
		if (!msc) {
			err = -ENOMEM;
			break;
		}

		msc->id = mpam_num_msc++;
		INIT_LIST_HEAD_RCU(&msc->glbl_list);
		msc->pdev = pdev;

		err = device_property_read_u32(&pdev->dev, "arm,not-ready-us",
					       &msc->nrdy_usec);
		if (err) {
			/* This will prevent CSU monitors being usable */
			msc->nrdy_usec = 0;
		}

		err = get_msc_affinity(msc);
		if (err)
			break;
		if (cpumask_empty(&msc->accessibility)) {
			pr_err_once("msc:%u is not accessible from any CPU!",
				    msc->id);
			err = -EINVAL;
			break;
		}

		mutex_init(&msc->lock);
		INIT_LIST_HEAD_RCU(&msc->ris);
		spin_lock_init(&msc->part_sel_lock);

		err = mpam_msc_setup_error_irq(msc);
		if (err) {
			devm_kfree(&pdev->dev, msc);
			msc = ERR_PTR(err);
			break;
		}

		if (device_property_read_u32(&pdev->dev, "pcc-channel",
					     &msc->pcc_subspace_id))
			msc->iface = MPAM_IFACE_MMIO;
		else
			msc->iface = MPAM_IFACE_PCC;

		if (msc->iface == MPAM_IFACE_MMIO) {
			io = devm_platform_get_and_ioremap_resource(pdev, 0,
								    &msc_res);
			if (IS_ERR(io)) {
				pr_err("Failed to map MSC base address\n");
				devm_kfree(&pdev->dev, msc);
				err = PTR_ERR(io);
				break;
			}
			msc->mapped_hwpage_sz = msc_res->end - msc_res->start;
			msc->mapped_hwpage = io;
		} else if (msc->iface == MPAM_IFACE_PCC) {
			msc->pcc_cl.dev = &pdev->dev;
			msc->pcc_cl.rx_callback = mpam_pcc_rx_callback;
			msc->pcc_cl.tx_block = false;
			msc->pcc_cl.tx_tout = 1000; /* 1s */
			msc->pcc_cl.knows_txdone = false;

			msc->pcc_chan = pcc_mbox_request_channel(&msc->pcc_cl,
								 msc->pcc_subspace_id);
			if (IS_ERR(msc->pcc_chan)) {
				pr_err("Failed to request MSC PCC channel\n");
				devm_kfree(&pdev->dev, msc);
				err = PTR_ERR(msc->pcc_chan);
				break;
			}

			prot = __acpi_get_mem_attribute(msc->pcc_chan->shmem_base_addr);
			io = ioremap_prot(msc->pcc_chan->shmem_base_addr,
					  msc->pcc_chan->shmem_size, pgprot_val(prot));
			if (IS_ERR(io)) {
				pr_err("Failed to map MSC base address\n");
				pcc_mbox_free_channel(msc->pcc_chan);
				devm_kfree(&pdev->dev, msc);
				err = PTR_ERR(io);
				break;
			}

			/* TODO: issue a read to update the registers */

			msc->mapped_hwpage_sz = msc->pcc_chan->shmem_size;
			msc->mapped_hwpage = io + sizeof(struct acpi_pcct_shared_memory);
		}

		list_add_rcu(&msc->glbl_list, &mpam_all_msc);
		platform_set_drvdata(pdev, msc);
	} while (0);
	mutex_unlock(&mpam_list_lock);

	if (!err) {
		/* Create RIS entries described by firmware */
		if (!acpi_disabled)
			err = acpi_mpam_parse_resources(msc, plat_data);
		else
			err = mpam_dt_parse_resources(msc, plat_data);
	}

	if (!err && fw_num_msc == mpam_num_msc)
		mpam_register_cpuhp_callbacks(&mpam_discovery_cpu_online);

	return err;
}

/*
 * If a resource doesn't match class feature/configuration, do the right thing.
 * For 'num' properties we can just take the minimum.
 * For properties where the mismatched unused bits would make a difference, we
 * nobble the class feature, as we can't configure all the resources.
 * e.g. The L3 cache is composed of two resources with 13 and 17 portion
 * bitmaps respectively.
 */
static void
__resource_props_mismatch(struct mpam_msc_ris *ris, struct mpam_class *class)
{
	struct mpam_props *cprops = &class->props;
	struct mpam_props *rprops = &ris->props;

	lockdep_assert_held(&mpam_list_lock); /* we modify class */

	/* Clear missing features */
	cprops->features &= rprops->features;

	/* Clear incompatible features */
	if (cprops->cpbm_wd != rprops->cpbm_wd)
		mpam_clear_feature(mpam_feat_cpor_part, &cprops->features);
	if (cprops->mbw_pbm_bits != rprops->mbw_pbm_bits)
		mpam_clear_feature(mpam_feat_mbw_part, &cprops->features);

	/* bwa_wd is a count of bits, fewer bits means less precision */
	if (cprops->bwa_wd != rprops->bwa_wd)
		cprops->bwa_wd = min(cprops->bwa_wd, rprops->bwa_wd);

	/* For num properties, take the minimum */
	if (cprops->num_csu_mon != rprops->num_csu_mon)
		cprops->num_csu_mon = min(cprops->num_csu_mon, rprops->num_csu_mon);
	if (cprops->num_mbwu_mon != rprops->num_mbwu_mon)
		cprops->num_mbwu_mon = min(cprops->num_mbwu_mon, rprops->num_mbwu_mon);

	if (cprops->intpri_wd != rprops->intpri_wd)
		cprops->intpri_wd = min(cprops->intpri_wd, rprops->intpri_wd);
	if (cprops->dspri_wd != rprops->dspri_wd)
		cprops->dspri_wd = min(cprops->dspri_wd, rprops->dspri_wd);

	/* {int,ds}pri may not have differing 0-low behaviour */
	if (mpam_has_feature(mpam_feat_intpri_part_0_low, cprops) !=
	    mpam_has_feature(mpam_feat_intpri_part_0_low, rprops))
		mpam_clear_feature(mpam_feat_intpri_part, &cprops->features);
	if (mpam_has_feature(mpam_feat_dspri_part_0_low, cprops) !=
	    mpam_has_feature(mpam_feat_dspri_part_0_low, rprops))
		mpam_clear_feature(mpam_feat_dspri_part, &cprops->features);
}

/*
 * Copy the first component's first resources's properties and features to the
 * class. __resource_props_mismatch() will remove conflicts.
 * It is not possible to have a class with no components, or a component with
 * no resources.
 */
static void mpam_enable_init_class_features(struct mpam_class *class)
{
	struct mpam_msc_ris *ris;
	struct mpam_component *comp;

	comp = list_first_entry_or_null(&class->components,
					struct mpam_component, class_list);
	if (WARN_ON(!comp))
		return;

	ris = list_first_entry_or_null(&comp->ris,
				       struct mpam_msc_ris, comp_list);
	if (WARN_ON(!ris))
		return;

	class->props = ris->props;
}

/* Merge all the common resource features into class. */
static void mpam_enable_merge_features(void)
{
	struct mpam_msc_ris *ris;
	struct mpam_class *class;
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_list_lock);

	list_for_each_entry(class, &mpam_classes, classes_list) {
		mpam_enable_init_class_features(class);

		list_for_each_entry(comp, &class->components, class_list) {
			list_for_each_entry(ris, &comp->ris, comp_list) {
				__resource_props_mismatch(ris, class);

				class->nrdy_usec = max(class->nrdy_usec,
						     ris->msc->nrdy_usec);
			}
		}
	}
}

static char *mpam_errcode_names[16] = {
	[0] = "No error",
	[1] = "PARTID_SEL_Range",
	[2] = "Req_PARTID_Range",
	[3] = "MSMONCFG_ID_RANGE",
	[4] = "Req_PMG_Range",
	[5] = "Monitor_Range",
	[6] = "intPARTID_Range",
	[7] = "Unexpected_INTERNAL",
	[8] = "Undefined_RIS_PART_SEL",
	[9] = "RIS_No_Control",
	[10] = "Undefined_RIS_MON_SEL",
	[11] = "RIS_No_Monitor",
	[12 ... 15] = "Reserved"
};

static int mpam_enable_msc_ecr(void *_msc)
{
	struct mpam_msc *msc = _msc;

	writel_relaxed(1, msc->mapped_hwpage + MPAMF_ECR);

	return 0;
}

static int mpam_disable_msc_ecr(void *_msc)
{
	struct mpam_msc *msc = _msc;

	writel_relaxed(0, msc->mapped_hwpage + MPAMF_ECR);

	return 0;
}

static irqreturn_t __mpam_irq_handler(int irq, struct mpam_msc *msc)
{
	u64 reg;
	u16 partid;
	u8 errcode, pmg, ris;

	if (WARN_ON_ONCE(!msc) ||
	    WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(),
					   &msc->accessibility)))
		return IRQ_NONE;

	reg = mpam_msc_read_esr(msc);

	errcode = FIELD_GET(MPAMF_ESR_ERRCODE, reg);
	if (!errcode)
		return IRQ_NONE;

	/* Clear level triggered irq */
	mpam_msc_zero_esr(msc);

	partid = FIELD_GET(MPAMF_ESR_PARTID_OR_MON, reg);
	pmg = FIELD_GET(MPAMF_ESR_PMG, reg);
	ris = FIELD_GET(MPAMF_ESR_PMG, reg);

	pr_err("error irq from msc:%u '%s', partid:%u, pmg: %u, ris: %u\n",
	       msc->id, mpam_errcode_names[errcode], partid, pmg, ris);

	if (irq_is_percpu(irq)) {
		mpam_disable_msc_ecr(msc);
		schedule_work(&mpam_broken_work);
		return IRQ_HANDLED;
	}

	return IRQ_WAKE_THREAD;
}

static irqreturn_t mpam_ppi_handler(int irq, void *dev_id)
{
	struct mpam_msc *msc = *(struct mpam_msc **)dev_id;

	return __mpam_irq_handler(irq, msc);
}

static irqreturn_t mpam_spi_handler(int irq, void *dev_id)
{
	struct mpam_msc *msc = dev_id;

	return __mpam_irq_handler(irq, msc);
}

static irqreturn_t mpam_disable_thread(int irq, void *dev_id);

static int mpam_register_irqs(void)
{
	int err, irq;
	struct mpam_msc *msc;

	lockdep_assert_cpus_held();
	lockdep_assert_held(&mpam_list_lock);

	list_for_each_entry(msc, &mpam_all_msc, glbl_list) {
		irq = platform_get_irq_byname_optional(msc->pdev, "error");
		if (irq <= 0)
			continue;

		/* The MPAM spec says the interrupt can be SPI, PPI or LPI */
		/* We anticipate sharing the interrupt with other MSCs */
		if (irq_is_percpu(irq)) {
			err = request_percpu_irq(irq, &mpam_ppi_handler,
						 "mpam:msc:error",
						 msc->error_dev_id);
			if (err)
				return err;

			mutex_lock(&msc->lock);
			msc->reenable_error_ppi = irq;
			smp_call_function_many(&msc->accessibility,
					       &_enable_percpu_irq, &irq,
					       true);
			mutex_unlock(&msc->lock);
		} else {
			err = devm_request_threaded_irq(&msc->pdev->dev, irq,
							&mpam_spi_handler,
							&mpam_disable_thread,
							IRQF_SHARED,
							"mpam:msc:error", msc);
			if (err)
				return err;
		}

		mutex_lock(&msc->lock);
		msc->error_irq_requested = true;
		mpam_touch_msc(msc, mpam_enable_msc_ecr, msc);
		msc->error_irq_hw_enabled = true;
		mutex_unlock(&msc->lock);
	}

	return 0;
}

static void mpam_unregister_irqs(void)
{
	int irq;
	struct mpam_msc *msc;

	cpus_read_lock();
	/* take the lock as free_irq() can sleep */
	mutex_lock(&mpam_list_lock);
	list_for_each_entry(msc, &mpam_all_msc, glbl_list) {
		irq = platform_get_irq_byname_optional(msc->pdev, "error");
		if (irq <= 0)
			continue;

		mutex_lock(&msc->lock);
		if (msc->error_irq_hw_enabled) {
			mpam_touch_msc(msc, mpam_disable_msc_ecr, msc);
			msc->error_irq_hw_enabled = false;
		}

		if (msc->error_irq_requested) {
			if (irq_is_percpu(irq)) {
				msc->reenable_error_ppi = 0;
				free_percpu_irq(irq, msc->error_dev_id);
			} else {
				devm_free_irq(&msc->pdev->dev, irq, msc);
			}
			msc->error_irq_requested = false;
		}
		mutex_unlock(&msc->lock);
	}
	mutex_unlock(&mpam_list_lock);
	cpus_read_unlock();
}

static void __destroy_component_cfg(struct mpam_component *comp)
{
	unsigned long flags;
	struct mpam_msc_ris *ris;
	struct msmon_mbwu_state *mbwu_state;

	kfree(comp->cfg);
	list_for_each_entry(ris, &comp->ris, comp_list) {
		mutex_lock(&ris->msc->lock);
		spin_lock_irqsave(&ris->msc->mon_sel_lock, flags);
		mbwu_state = ris->mbwu_state;
		ris->mbwu_state = NULL;
		spin_unlock_irqrestore(&ris->msc->mon_sel_lock, flags);
		mutex_unlock(&ris->msc->lock);

		kfree(mbwu_state);
	}
}

static int __allocate_component_cfg(struct mpam_component *comp)
{
	unsigned long flags;
	struct mpam_msc_ris *ris;
	struct msmon_mbwu_state *mbwu_state;

	if (comp->cfg)
		return 0;

	comp->cfg = kcalloc(mpam_partid_max, sizeof(*comp->cfg), GFP_KERNEL);
	if (!comp->cfg)
		return -ENOMEM;

	list_for_each_entry(ris, &comp->ris, comp_list) {
		if (!ris->props.num_mbwu_mon)
			continue;

		mbwu_state = kcalloc(ris->props.num_mbwu_mon,
				     sizeof(*ris->mbwu_state), GFP_KERNEL);
		if (!mbwu_state) {
			__destroy_component_cfg(comp);
			return -ENOMEM;
		}

		mutex_lock(&ris->msc->lock);
		spin_lock_irqsave(&ris->msc->mon_sel_lock, flags);
		ris->mbwu_state = mbwu_state;
		spin_unlock_irqrestore(&ris->msc->mon_sel_lock, flags);
		mutex_unlock(&ris->msc->lock);
	}

	return 0;
}

static int mpam_allocate_config(void)
{
	int err = 0;
	struct mpam_class *class;
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_list_lock);

	list_for_each_entry(class, &mpam_classes, classes_list) {
		list_for_each_entry(comp, &class->components, class_list) {
			err = __allocate_component_cfg(comp);
			if (err)
				return err;
		}
	}

	return 0;
}

static void mpam_enable_once(void)
{
	int err;

	/*
	 * If all the MSC have been probed, enabling the IRQs happens next.
	 * That involves cross-calling to a CPU that can reach the MSC, and
	 * the locks must be taken in this order:
	 */
	cpus_read_lock();
	mutex_lock(&mpam_list_lock);
	do {
		mpam_enable_merge_features();

		err = mpam_allocate_config();
		if (err) {
			pr_err("Failed to allocate configuration arrays.\n");
			break;
		}

		err = mpam_register_irqs();
		if (err) {
			pr_warn("Failed to register irqs: %d\n", err);
			break;
		}
	} while (0);
	mutex_unlock(&mpam_list_lock);
	cpus_read_unlock();

	if (!err) {
		err = mpam_resctrl_setup();
		if (err)
			pr_err("Failed to initialise resctrl: %d\n", err);
	}

	if (err) {
		schedule_work(&mpam_broken_work);
		return;
	}

	mutex_lock(&mpam_cpuhp_state_lock);
	cpuhp_remove_state(mpam_cpuhp_state);
	mpam_cpuhp_state = 0;
	mutex_unlock(&mpam_cpuhp_state_lock);

	/*
	 * Once the cpuhp callbacks have been changed, mpam_partid_max can no
	 * longer change.
	 */
	spin_lock(&partid_max_lock);
	partid_max_published = true;
	spin_unlock(&partid_max_lock);

	static_branch_enable(&mpam_enabled);
	mpam_register_cpuhp_callbacks(mpam_cpu_online);

	pr_info("MPAM enabled with %u partid and %u pmg\n",
		READ_ONCE(mpam_partid_max) + 1, mpam_pmg_max + 1);
}

void mpam_reset_class(struct mpam_class *class)
{
	int idx;
	struct mpam_msc_ris *ris;
	struct mpam_component *comp;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(comp, &class->components, class_list) {
		memset(comp->cfg, 0, (mpam_partid_max * sizeof(*comp->cfg)));

		list_for_each_entry_rcu(ris, &comp->ris, comp_list) {
			mutex_lock(&ris->msc->lock);
			mpam_touch_msc(ris->msc, mpam_reset_ris, ris);
			mutex_unlock(&ris->msc->lock);
			ris->in_reset_state = true;
		}
	}
	srcu_read_unlock(&mpam_srcu, idx);
}

/*
 * Called in response to an error IRQ.
 * All of MPAMs errors indicate a software bug, restore any modified
 * controls to their reset values.
 */
static irqreturn_t mpam_disable_thread(int irq, void *dev_id)
{
	int idx;
	struct mpam_class *class;

	mutex_lock(&mpam_cpuhp_state_lock);
	if (mpam_cpuhp_state) {
		cpuhp_remove_state(mpam_cpuhp_state);
		mpam_cpuhp_state = 0;
	}
	mutex_unlock(&mpam_cpuhp_state_lock);

	mpam_resctrl_exit();

	static_branch_disable(&mpam_enabled);

	mpam_unregister_irqs();

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(class, &mpam_classes, classes_list)
		mpam_reset_class(class);
	srcu_read_unlock(&mpam_srcu, idx);

	return IRQ_HANDLED;
}

void mpam_disable(struct work_struct *ignored)
{
	mpam_disable_thread(0, NULL);
}

/*
 * Enable mpam once all devices have been probed.
 * Scheduled by mpam_discovery_cpu_online() once all devices have been created.
 * Also scheduled when new devices are probed when new CPUs come online.
 */
void mpam_enable(struct work_struct *work)
{
	static atomic_t once;
	struct mpam_msc *msc;
	bool all_devices_probed = true;

	mutex_lock(&mpam_list_lock);
	list_for_each_entry(msc, &mpam_all_msc, glbl_list) {
		mutex_lock(&msc->lock);
		if (!msc->probed)
			all_devices_probed = false;
		mutex_unlock(&msc->lock);

		if (!all_devices_probed)
			break;
	}
	mutex_unlock(&mpam_list_lock);

	if (all_devices_probed && !atomic_fetch_inc(&once))
		mpam_enable_once();
}

static int mpam_msc_drv_remove(struct platform_device *pdev)
{
	struct mpam_msc *msc = platform_get_drvdata(pdev);

	if (!msc)
		return 0;

	mutex_lock(&mpam_list_lock);
	mpam_num_msc--;
	platform_set_drvdata(pdev, NULL);
	list_del_rcu(&msc->glbl_list);
	mpam_msc_destroy(msc);
	synchronize_srcu(&mpam_srcu);
	mutex_unlock(&mpam_list_lock);

	return 0;
}

struct mpam_write_config_arg {
	struct mpam_msc_ris *ris;
	struct mpam_component *comp;
	u16 partid;
};

static int __write_config(void *arg)
{
	struct mpam_write_config_arg *c = arg;

	mpam_reprogram_ris_partid(c->ris, c->partid, &c->comp->cfg[c->partid]);

	return 0;
}

/* TODO: split into write_config/sync_config */
/* TODO: add config_dirty bitmap to drive sync_config */
int mpam_apply_config(struct mpam_component *comp, u16 partid,
		      struct mpam_config *cfg)
{
	struct mpam_write_config_arg arg;
	struct mpam_msc_ris *ris;
	int idx;

	lockdep_assert_cpus_held();

	if (!memcmp(&comp->cfg[partid], cfg, sizeof(*cfg)))
		return 0;

	comp->cfg[partid] = *cfg;
	arg.comp = comp;
	arg.partid = partid;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(ris, &comp->ris, comp_list) {
		arg.ris = ris;
		mutex_lock(&ris->msc->lock);
		mpam_touch_msc(ris->msc, __write_config, &arg);
		mutex_unlock(&ris->msc->lock);
	}
	srcu_read_unlock(&mpam_srcu, idx);

	return 0;
}

static const struct of_device_id mpam_of_match[] = {
	{ .compatible = "arm,mpam-msc", },
	{},
};
MODULE_DEVICE_TABLE(of, mpam_of_match);

static struct platform_driver mpam_msc_driver = {
	.driver = {
		.name = "mpam_msc",
		.of_match_table = of_match_ptr(mpam_of_match),
	},
	.probe = mpam_msc_drv_probe,
	.remove = mpam_msc_drv_remove,
};

/*
 * MSC that are hidden under caches are not created as platform devices
 * as there is no cache driver. Caches are also special-cased in
 * get_msc_affinity().
 */
static void mpam_dt_create_foundling_msc(void)
{
	int err;
	struct device_node *cache;

	for_each_compatible_node(cache, NULL, "cache") {
		err = of_platform_populate(cache, mpam_of_match, NULL, NULL);
		if (err) {
			pr_err("Failed to create MSC devices under caches\n");
		}
	}
}

static int __init mpam_msc_driver_init(void)
{
	bool mpam_not_available = false;

	if (!mpam_cpus_have_feature())
		return -EOPNOTSUPP;

	init_srcu_struct(&mpam_srcu);

	/*
	 * If the MPAM CPU interface is not implemented, or reserved by
	 * firmware, there is no point touching the rest of the hardware.
	 */
	spin_lock(&partid_max_lock);
	if (!partid_max_init || (!mpam_partid_max && !mpam_pmg_max))
		mpam_not_available = true;
	spin_unlock(&partid_max_lock);

	if (mpam_not_available)
		return 0;

	if (!acpi_disabled)
		fw_num_msc = acpi_mpam_count_msc();
	else
		fw_num_msc = mpam_dt_count_msc();

	if (fw_num_msc <= 0) {
		pr_err("No MSC devices found in firmware\n");
		return -EINVAL;
	}

	if (acpi_disabled)
		mpam_dt_create_foundling_msc();

	return platform_driver_register(&mpam_msc_driver);
}
/* Must occur after arm64_mpam_register_cpus() from arch_initcall() */
subsys_initcall(mpam_msc_driver_init);
