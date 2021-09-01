// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2025 Arm Ltd.

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

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
#include <linux/list_sort.h>
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

#include "mpam_internal.h"

/* Values for the T241 errata workaround */
#define T241_CHIPS_MAX			4
#define T241_CHIP_NSLICES		12
#define T241_SPARE_REG0_OFF		0x1b0000
#define T241_SPARE_REG1_OFF		0x1c0000
#define T241_CHIP_ID(phys)		FIELD_GET(GENMASK_ULL(44, 43), phys)
#define T241_SHADOW_REG_OFF(sidx, pid)	(0x360048 + (sidx) * 0x10000 + (pid) * 8)
#define SMCCC_SOC_ID_T241		0x036b0241
static void __iomem *t241_scratch_regs[T241_CHIPS_MAX];

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

static struct dentry *mpam_debugfs;

/*
 * Whether has been setup. Used by cpuhp in preference to mpam_is_enabled()
 * the disable call after an error interrupt makes mpam_is_enabled() false before
 * the cpuhp callbacks are made.
 * Reads/writes should hold mpam_cpuhp_state_lock, (or be cpuhp callbacks).
 */
static bool mpam_resctrl_enabled;

/*
 * An MSC is a physical container for controls and monitors, each identified by
 * their RIS index. These share a base-address, interrupts and some MMIO
 * registers. A vMSC is a virtual container for RIS in an MSC that control or
 * monitor the same thing. Members of a vMSC are all RIS in the same MSC, but
 * not all RIS in an MSC share a vMSC.
 * Components are a group of vMSC that control or monitor the same thing but
 * are from different MSC, so have different base-address, interrupts etc.
 * Classes are the set components of the same type.
 *
 * The features of a vMSC is the union of the RIS it contains.
 * The features of a Class and Component are the common subset of the vMSC
 * they contain.
 *
 * e.g. The system cache may have bandwidth controls on multiple interfaces,
 * for regulating traffic from devices independently of traffic from CPUs.
 * If these are two RIS in one MSC, they will be treated as controlling
 * different things, and will not share a vMSC/component/class.
 *
 * e.g. The L2 may have one MSC and two RIS, one for cache-controls another
 * for bandwidth. These two RIS are members of the same vMSC.
 *
 * e.g. The set of RIS that make up the L2 are grouped as a component. These
 * are sometimes termed slices. They should be configured the same, as if there
 * were only one.
 *
 * e.g. The SoC probably has more than one L2, each attached to a distinct set
 * of CPUs. All the L2 components are grouped as a class.
 *
 * When creating an MSC, struct mpam_msc is added to the all mpam_all_msc list,
 * then linked via struct mpam_ris to a vmsc, component and class.
 * The same MSC may exist under different class->component->vmsc paths, but the
 * RIS index will be unique.
 */
LIST_HEAD(mpam_classes);

/* List of all objects that can be free()d after synchronise_srcu() */
static LLIST_HEAD(mpam_garbage);

static u32 __mpam_read_reg(struct mpam_msc *msc, u16 reg)
{
	WARN_ON_ONCE(reg + sizeof(u32) > msc->mapped_hwpage_sz);
	WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(), &msc->accessibility));

	return readl_relaxed(msc->mapped_hwpage + reg);
}

static inline u32 _mpam_read_partsel_reg(struct mpam_msc *msc, u16 reg)
{
	lockdep_assert_held_once(&msc->part_sel_lock);
	return __mpam_read_reg(msc, reg);
}

#define mpam_read_partsel_reg(msc, reg)        _mpam_read_partsel_reg(msc, MPAMF_##reg)

static void __mpam_write_reg(struct mpam_msc *msc, u16 reg, u32 val)
{
	WARN_ON_ONCE(reg + sizeof(u32) > msc->mapped_hwpage_sz);
	WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(), &msc->accessibility));

	writel_relaxed(val, msc->mapped_hwpage + reg);
}

static inline void _mpam_write_partsel_reg(struct mpam_msc *msc, u16 reg, u32 val)
{
	lockdep_assert_held_once(&msc->part_sel_lock);
	__mpam_write_reg(msc, reg, val);
}
#define mpam_write_partsel_reg(msc, reg, val)  _mpam_write_partsel_reg(msc, MPAMCFG_##reg, val)

static inline u32 _mpam_read_monsel_reg(struct mpam_msc *msc, u16 reg)
{
	mpam_mon_sel_lock_held(msc);
	return __mpam_read_reg(msc, reg);
}
#define mpam_read_monsel_reg(msc, reg) _mpam_read_monsel_reg(msc, MSMON_##reg)

static inline void _mpam_write_monsel_reg(struct mpam_msc *msc, u16 reg, u32 val)
{
	mpam_mon_sel_lock_held(msc);
	__mpam_write_reg(msc, reg, val);
}
#define mpam_write_monsel_reg(msc, reg, val)   _mpam_write_monsel_reg(msc, MSMON_##reg, val)

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
	__mpam_write_reg(msc, MPAMF_ESR, 0);
	if (msc->has_extd_esr)
		__mpam_write_reg(msc, MPAMF_ESR + 4, 0);
}

static u64 mpam_msc_read_esr(struct mpam_msc *msc)
{
	u64 esr_high = 0, esr_low;

	esr_low = __mpam_read_reg(msc, MPAMF_ESR);
	if (msc->has_extd_esr)
		esr_high = __mpam_read_reg(msc, MPAMF_ESR + 4);

	return (esr_high << 32) | esr_low;
}

static void __mpam_part_sel_raw(u32 partsel, struct mpam_msc *msc)
{
	lockdep_assert_held(&msc->part_sel_lock);

	mpam_write_partsel_reg(msc, PART_SEL, partsel);
}

static void __mpam_part_sel(u8 ris_idx, u16 partid, struct mpam_msc *msc)
{
	u32 partsel = FIELD_PREP(MPAMCFG_PART_SEL_RIS, ris_idx) |
		      FIELD_PREP(MPAMCFG_PART_SEL_PARTID_SEL, partid);

	__mpam_part_sel_raw(partsel, msc);
}

static void __mpam_intpart_sel(u8 ris_idx, u16 intpartid, struct mpam_msc *msc)
{
	u32 partsel = FIELD_PREP(MPAMCFG_PART_SEL_RIS, ris_idx) |
		      FIELD_PREP(MPAMCFG_PART_SEL_PARTID_SEL, intpartid) |
		      MPAMCFG_PART_SEL_INTERNAL;

	__mpam_part_sel_raw(partsel, msc);
}

int mpam_register_requestor(u16 partid_max, u8 pmg_max)
{
	int err = 0;

	lockdep_assert_irqs_enabled();

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
		if (partid_max < mpam_partid_max || pmg_max < mpam_pmg_max)
			err = -EBUSY;
	}
	spin_unlock(&partid_max_lock);

	return err;
}
EXPORT_SYMBOL(mpam_register_requestor);

#define init_garbage(x)	init_llist_node(&(x)->garbage.llist)

static struct mpam_vmsc *
mpam_vmsc_alloc(struct mpam_component *comp, struct mpam_msc *msc, gfp_t gfp)
{
	struct mpam_vmsc *vmsc;

	lockdep_assert_held(&mpam_list_lock);

	vmsc = kzalloc(sizeof(*vmsc), gfp);
	if (!comp)
		return ERR_PTR(-ENOMEM);
	init_garbage(vmsc);

	INIT_LIST_HEAD_RCU(&vmsc->ris);
	INIT_LIST_HEAD_RCU(&vmsc->comp_list);
	vmsc->comp = comp;
	vmsc->msc = msc;

	list_add_rcu(&vmsc->comp_list, &comp->vmsc);

	return vmsc;
}

static struct mpam_vmsc *mpam_vmsc_get(struct mpam_component *comp,
				       struct mpam_msc *msc, bool alloc,
				       gfp_t gfp)
{
	struct mpam_vmsc *vmsc;

	lockdep_assert_held(&mpam_list_lock);

	list_for_each_entry(vmsc, &comp->vmsc, comp_list) {
		if (vmsc->msc->id == msc->id)
			return vmsc;
	}

	if (!alloc)
		return ERR_PTR(-ENOENT);

	return mpam_vmsc_alloc(comp, msc, gfp);
}

static struct mpam_component *
mpam_component_alloc(struct mpam_class *class, int id, gfp_t gfp)
{
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_list_lock);

	comp = kzalloc(sizeof(*comp), gfp);
	if (!comp)
		return ERR_PTR(-ENOMEM);
	init_garbage(comp);

	comp->comp_id = id;
	INIT_LIST_HEAD_RCU(&comp->vmsc);
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
	init_garbage(class);

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

#define add_to_garbage(x)				\
do {							\
	__typeof__(x) _x = x;				\
	(_x)->garbage.to_free = (_x);			\
	llist_add(&(_x)->garbage.llist, &mpam_garbage);	\
} while (0)

static void mpam_class_destroy(struct mpam_class *class)
{
	lockdep_assert_held(&mpam_list_lock);

	debugfs_remove_recursive(class->debugfs);
	class->debugfs = NULL;
	list_del_rcu(&class->classes_list);
	add_to_garbage(class);
}

static void __destroy_component_cfg(struct mpam_component *comp);

static void mpam_comp_destroy(struct mpam_component *comp)
{
	struct mpam_class *class = comp->class;

	lockdep_assert_held(&mpam_list_lock);

	__destroy_component_cfg(comp);

	debugfs_remove_recursive(comp->debugfs);
	comp->debugfs = NULL;
	list_del_rcu(&comp->class_list);
	add_to_garbage(comp);

	if (list_empty(&class->components))
		mpam_class_destroy(class);
}

static void mpam_vmsc_destroy(struct mpam_vmsc *vmsc)
{
	struct mpam_component *comp = vmsc->comp;

	lockdep_assert_held(&mpam_list_lock);

	debugfs_remove_recursive(vmsc->debugfs);
	vmsc->debugfs = NULL;
	list_del_rcu(&vmsc->comp_list);
	add_to_garbage(vmsc);

	if (list_empty(&comp->vmsc))
		mpam_comp_destroy(comp);
}

static void mpam_ris_destroy(struct mpam_msc_ris *ris)
{
	struct mpam_vmsc *vmsc = ris->vmsc;
	struct mpam_msc *msc = vmsc->msc;
	struct platform_device *pdev = msc->pdev;
	struct mpam_component *comp = vmsc->comp;
	struct mpam_class *class = comp->class;

	lockdep_assert_held(&mpam_list_lock);

	/*
	 * Once a RIS has been removed from a class, it can no longer be used
	 * by resctrl, even though the class has yet to be removed.
	 */
	mpam_resctrl_teardown_class(class);

	cpumask_andnot(&comp->affinity, &comp->affinity, &ris->affinity);
	cpumask_andnot(&class->affinity, &class->affinity, &ris->affinity);
	clear_bit(ris->ris_idx, msc->ris_idxs);
	debugfs_remove_recursive(ris->debugfs);
	ris->debugfs = NULL;
	list_del_rcu(&ris->vmsc_list);
	list_del_rcu(&ris->msc_list);
	add_to_garbage(ris);
	ris->garbage.pdev = pdev;

	if (list_empty(&vmsc->ris))
		mpam_vmsc_destroy(vmsc);
}

/*
 * There are two ways of reaching a struct mpam_msc_ris. Via the
 * class->component->vmsc->ris, or via the msc.
 * When destroying the msc, the other side needs unlinking and cleaning up too.
 */
static void mpam_msc_destroy(struct mpam_msc *msc)
{
	struct platform_device *pdev = msc->pdev;
	struct mpam_msc_ris *ris, *tmp;

	lockdep_assert_held(&mpam_list_lock);

	list_for_each_entry_safe(ris, tmp, &msc->ris, msc_list)
		mpam_ris_destroy(ris);

	list_del_rcu(&msc->glbl_list);
	platform_set_drvdata(pdev, NULL);

	debugfs_remove_recursive(msc->debugfs);
	msc->debugfs = NULL;

	add_to_garbage(msc);
	msc->garbage.pdev = pdev;
}

static void mpam_free_garbage(void)
{
	struct mpam_garbage *iter, *tmp;
	struct llist_node *to_free = llist_del_all(&mpam_garbage);

	if (!to_free)
		return;

	synchronize_srcu(&mpam_srcu);

	llist_for_each_entry_safe(iter, tmp, to_free, llist) {
		if (iter->pdev)
			devm_kfree(&iter->pdev->dev, iter->to_free);
		else
			kfree(iter->to_free);
	}
}

/* Called recursively to walk the list of caches from a particular CPU */
static void __mpam_get_cpumask_from_cache_id(int cpu, struct device_node *cache_node,
					     unsigned long cache_id,
					     u32 cache_level,
					     cpumask_t *affinity)
{
	int err;
	u32 iter_level;
	unsigned long iter_cache_id;
	struct device_node *iter_node __free(device_node) = of_find_next_cache_node(cache_node);

	if (!iter_node) {
		pr_err("cpu %u next_cache_node returned NULL\n", cpu);
		return;
	}

	err = of_property_read_u32(iter_node, "cache-level", &iter_level);
	if (err)
		return;

	/*
	 * get_cpu_cacheinfo_id() isn't ready until sometime
	 * during device_initcall(). Use cache_of_calculate_id().
	 */
	iter_cache_id = cache_of_calculate_id(iter_node);
	if (cache_id == ~0UL)
		return;

	if (iter_level == cache_level && iter_cache_id == cache_id)
		cpumask_set_cpu(cpu, affinity);

	__mpam_get_cpumask_from_cache_id(cpu, iter_node, cache_id, cache_level,
					 affinity);
}

/*
 * The cacheinfo structures are only populated when CPUs are online.
 * This helper walks the device tree to include offline CPUs too.
 */
int mpam_get_cpumask_from_cache_id(unsigned long cache_id, u32 cache_level,
				   cpumask_t *affinity)
{
	int cpu;

	if (!acpi_disabled)
		return acpi_pptt_get_cpumask_from_cache_id(cache_id, affinity);

	for_each_possible_cpu(cpu) {
		struct device_node *cpu_node __free(device_node) = of_get_cpu_node(cpu, NULL);
		if (!cpu_node) {
			pr_err("Failed to find cpu%d device node\n", cpu);
			return -ENOENT;
		}

		__mpam_get_cpumask_from_cache_id(cpu, cpu_node, cache_id,
						 cache_level, affinity);
			continue;
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
	unsigned long cache_id;

	err = of_property_read_u32(cache, "cache-level", &cache_level);
	if (err) {
		pr_err("Failed to read cache-level from cache node\n");
		return -ENOENT;
	}

	cache_id = cache_of_calculate_id(cache);
	if (cache_id == ~0UL) {
		pr_err("Failed to calculate cache-id from cache node\n");
		return -ENOENT;
	}

	return mpam_get_cpumask_from_cache_id(cache_id, cache_level, affinity);
}

static int mpam_ris_get_affinity(struct mpam_msc *msc, cpumask_t *affinity,
				 enum mpam_class_types type,
				 struct mpam_class *class,
				 struct mpam_component *comp)
{
	int err;

	switch (type) {
	case MPAM_CLASS_CACHE:
		err = mpam_get_cpumask_from_cache_id(comp->comp_id, class->level,
						     affinity);
		if (err)
			return err;

		if (cpumask_empty(affinity))
			pr_warn_once("%s no CPUs associated with cache node",
				     dev_name(&msc->pdev->dev));

		break;
	case MPAM_CLASS_MEMORY:
		get_cpumask_from_node_id(comp->comp_id, affinity);
		/* affinity may be empty for CPU-less memory nodes */
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
	struct mpam_vmsc *vmsc;
	struct mpam_msc_ris *ris;
	struct mpam_class *class;
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_list_lock);

	if (test_and_set_bit(ris_idx, msc->ris_idxs))
		return -EBUSY;

	ris = devm_kzalloc(&msc->pdev->dev, sizeof(*ris), gfp);
	if (!ris)
		return -ENOMEM;
	init_garbage(ris);

	class = mpam_class_get(class_id, type, true, gfp);
	if (IS_ERR(class))
		return PTR_ERR(class);

	comp = mpam_component_get(class, component_id, true, gfp);
	if (IS_ERR(comp)) {
		if (list_empty(&class->components))
			mpam_class_destroy(class);
		return PTR_ERR(comp);
	}

	vmsc = mpam_vmsc_get(comp, msc, true, gfp);
	if (IS_ERR(vmsc)) {
		if (list_empty(&comp->vmsc))
			mpam_comp_destroy(comp);
		return PTR_ERR(vmsc);
	}

	err = mpam_ris_get_affinity(msc, &ris->affinity, type, class, comp);
	if (err) {
		if (list_empty(&vmsc->ris))
			mpam_vmsc_destroy(vmsc);
		return err;
	}

	ris->ris_idx = ris_idx;
	INIT_LIST_HEAD_RCU(&ris->vmsc_list);
	ris->vmsc = vmsc;

	cpumask_or(&comp->affinity, &comp->affinity, &ris->affinity);
	cpumask_or(&class->affinity, &class->affinity, &ris->affinity);
	list_add_rcu(&ris->vmsc_list, &vmsc->ris);
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
	if (err)
		mpam_free_garbage();

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

static void mpam_enable_quirk_nvidia_t241(struct mpam_msc *msc,
					  const struct mpam_quirk *quirk)
{
	s32 soc_id = arm_smccc_get_soc_id_version();
	struct resource *r;
	phys_addr_t phys;

	/*
	 * A mapping to a device other than the MSC is needed, check
	 * SOC_ID is  NVIDIA T241 chip (036b:0241)
	 */
	if (soc_id < 0 || soc_id != SMCCC_SOC_ID_T241)
		return;

	r = platform_get_resource(msc->pdev, IORESOURCE_MEM, 0);
	if (!r)
		return;

	/* Find the internal registers base addr from the CHIP ID */
	msc->t241_id = T241_CHIP_ID(r->start);
	phys = FIELD_PREP(GENMASK_ULL(45, 44), msc->t241_id) | 0x19000000ULL;

	t241_scratch_regs[msc->t241_id] = ioremap(phys, SZ_8M);
	if (WARN_ON_ONCE(!t241_scratch_regs[msc->t241_id]))
		return;

	mpam_set_quirk(quirk->workaround, msc);
	pr_info_once("Enabled workaround for NVIDIA T241 erratum T241-MPAM-1\n");
}

static const struct mpam_quirk mpam_quirks[] = {
	{
	/* NVIDIA t241 erratum T241-MPAM-1 */
	.init       = mpam_enable_quirk_nvidia_t241,
	.iidr       = IIDR_PROD(0x241) | IIDR_VAR(0) | IIDR_REV(0) | IIDR_IMP(0x36b),
	.iidr_mask  = IIDR_MATCH_ONE,
	.workaround = T241_SCRUB_SHADOW_REGS,
	},
	{
	/* NVIDIA t241 erratum T241-MPAM-4 */
	.iidr       = IIDR_PROD(0x241) | IIDR_VAR(0) | IIDR_REV(0) | IIDR_IMP(0x36b),
	.iidr_mask  = IIDR_MATCH_ONE,
	.workaround = T241_FORCE_MBW_MIN_TO_ONE,
	},
	{
	/* NVIDIA t241 erratum T241-MPAM-6 */
	.iidr       = IIDR_PROD(0x241) | IIDR_VAR(0) | IIDR_REV(0) | IIDR_IMP(0x36b),
	.iidr_mask  = IIDR_MATCH_ONE,
	.workaround = T241_MBW_COUNTER_SCALE_64,
	},
	{
	/* ARM CMN-650 CSU erratum 3642720 */
	.iidr       = IIDR_PROD(0) | IIDR_VAR(0) | IIDR_REV(0) | IIDR_IMP(0x43b),
	.iidr_mask  = IIDR_MATCH_ONE,
	.workaround = IGNORE_CSU_NRDY,
	},
	{ NULL }, /* Sentinel */
};

static void mpam_enable_quirks(struct mpam_msc *msc)
{
	const struct mpam_quirk *quirk;

	for (quirk = &mpam_quirks[0]; quirk->iidr_mask; quirk++) {
		if (quirk->iidr != (msc->iidr & quirk->iidr_mask))
			continue;

		if (quirk->init)
			quirk->init(msc, quirk);
		else
			mpam_set_quirk(quirk->workaround, msc);
	}
}

/*
 * IHI009A.a has this nugget: "If a monitor does not support automatic behaviour
 * of NRDY, software can use this bit for any purpose" - so hardware might not
 * implement this - but it isn't RES0.
 *
 * Try and see what values stick in this bit. If we can write either value,
 * its probably not implemented by hardware.
 */
#define mpam_ris_hw_probe_hw_nrdy(_ris, _mon_reg, _result)			\
do {										\
	u32 now;								\
	u64 mon_sel;								\
	bool can_set, can_clear;						\
	struct mpam_msc *_msc = _ris->vmsc->msc;				\
										\
	if (WARN_ON_ONCE(!mpam_mon_sel_inner_lock(_msc))) {			\
		_result = false;						\
		break;								\
	}									\
	mon_sel = FIELD_PREP(MSMON_CFG_MON_SEL_MON_SEL, 0) |			\
		  FIELD_PREP(MSMON_CFG_MON_SEL_RIS, _ris->ris_idx);		\
	mpam_write_monsel_reg(_msc, CFG_MON_SEL, mon_sel);			\
										\
	mpam_write_monsel_reg(_msc, _mon_reg, MSMON___NRDY);			\
	now = mpam_read_monsel_reg(_msc, _mon_reg);				\
	can_set = now & MSMON___NRDY;						\
										\
	mpam_write_monsel_reg(_msc, _mon_reg, 0);				\
	now = mpam_read_monsel_reg(_msc, _mon_reg);				\
	can_clear = !(now & MSMON___NRDY);					\
	mpam_mon_sel_inner_unlock(_msc);					\
										\
	_result = (!can_set || !can_clear);					\
} while (0)

static void mpam_ris_hw_probe(struct mpam_msc_ris *ris)
{
	int err;
	struct mpam_msc *msc = ris->vmsc->msc;
	struct mpam_props *props = &ris->props;
	struct mpam_class *class = ris->vmsc->comp->class;

	lockdep_assert_held(&msc->probe_lock);
	lockdep_assert_held(&msc->part_sel_lock);

	/* Cache Capacity Partitioning */
	if (FIELD_GET(MPAMF_IDR_HAS_CCAP_PART, ris->idr)) {
		ris->ccap_idr = mpam_read_partsel_reg(msc, CCAP_IDR);

		props->cmax_wd = FIELD_GET(MPAMF_CCAP_IDR_CMAX_WD, ris->ccap_idr);
		if (props->cmax_wd &&
		    FIELD_GET(MPAMF_CCAP_IDR_HAS_CMAX_SOFTLIM, ris->ccap_idr))
			mpam_set_feature(mpam_feat_cmax_softlim, props);

		if (props->cmax_wd &&
		    !FIELD_GET(MPAMF_CCAP_IDR_NO_CMAX, ris->ccap_idr))
			mpam_set_feature(mpam_feat_cmax_cmax, props);

		if (props->cmax_wd &&
		    FIELD_GET(MPAMF_CCAP_IDR_HAS_CMIN, ris->ccap_idr))
			mpam_set_feature(mpam_feat_cmax_cmin, props);

		props->cassoc_wd = FIELD_GET(MPAMF_CCAP_IDR_CASSOC_WD, ris->ccap_idr);

		if (props->cassoc_wd &&
		    FIELD_GET(MPAMF_CCAP_IDR_HAS_CASSOC, ris->ccap_idr))
			mpam_set_feature(mpam_feat_cmax_cassoc, props);
	}

	/* Cache Portion partitioning */
	if (FIELD_GET(MPAMF_IDR_HAS_CPOR_PART, ris->idr)) {
		ris->cpor_idr = mpam_read_partsel_reg(msc, CPOR_IDR);

		props->cpbm_wd = FIELD_GET(MPAMF_CPOR_IDR_CPBM_WD, ris->cpor_idr);
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

		/*
		 * The BWA_WD field can represent 0-63, but the control fields it
		 * describes have a maximum of 16 bits.
		 */
		props->bwa_wd = min(props->bwa_wd, 16);

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

		/*
		 * If the firmware max-nrdy-us property is missing, the
		 * CSU counters can't be used. Should we wait forever?
		 */
		err = device_property_read_u32(&msc->pdev->dev,
					       "arm,not-ready-us",
					       &msc->nrdy_usec);

		if (FIELD_GET(MPAMF_MSMON_IDR_MSMON_CSU, msmon_features)) {
			u32 csumonidr;

			csumonidr = mpam_read_partsel_reg(msc, CSUMON_IDR);
			props->num_csu_mon = FIELD_GET(MPAMF_CSUMON_IDR_NUM_MON, csumonidr);
			if (props->num_csu_mon) {
				bool hw_managed;

				mpam_set_feature(mpam_feat_msmon_csu, props);

				/* Is NRDY hardware managed? */
				mpam_mon_sel_outer_lock(msc);
				mpam_ris_hw_probe_hw_nrdy(ris, CSU, hw_managed);
				mpam_mon_sel_outer_unlock(msc);
				if (hw_managed)
					mpam_set_feature(mpam_feat_msmon_csu_hw_nrdy, props);
			}

			/*
			 * Accept the missing firmware property if NRDY appears
			 * un-implemented.
			 */
			if (err && mpam_has_feature(mpam_feat_msmon_csu_hw_nrdy, props))
				pr_err_once("Counters are not usable because not-ready timeout was not provided by firmware.");
		}
		if (FIELD_GET(MPAMF_MSMON_IDR_MSMON_MBWU, msmon_features)) {
			bool has_long, hw_managed;
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

			/* Is NRDY hardware managed? */
			mpam_mon_sel_outer_lock(msc);
			mpam_ris_hw_probe_hw_nrdy(ris, MBWU, hw_managed);
			mpam_mon_sel_outer_unlock(msc);
			if (hw_managed)
				mpam_set_feature(mpam_feat_msmon_mbwu_hw_nrdy, props);

			/*
			 * Don't warn about any missing firmware property for
			 * MBWU NRDY - it doesn't make any sense!
			 */
		}
	}

	/*
	 * RIS with PARTID narrowing don't have enough storage for one
	 * configuration per PARTID. If these are in a class we could use,
	 * reduce the supported partid_max to match the number of intpartid.
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

	lockdep_assert_held(&msc->probe_lock);

	mutex_lock(&msc->part_sel_lock);
	idr = mpam_read_partsel_reg(msc, AIDR);
	if ((idr & MPAMF_AIDR_ARCH_MAJOR_REV) != MPAM_ARCHITECTURE_V1) {
		pr_err_once("%s does not match MPAM architecture v1.0\n",
			    dev_name(&msc->pdev->dev));
		mutex_unlock(&msc->part_sel_lock);
		return -EIO;
	}

	idr = mpam_msc_read_idr(msc);
	msc->iidr = mpam_read_partsel_reg(msc, IIDR);
	mutex_unlock(&msc->part_sel_lock);

	mpam_enable_quirks(msc);

	msc->ris_max = FIELD_GET(MPAMF_IDR_RIS_MAX, idr);

	/* Use these values so partid/pmg always starts with a valid value */
	msc->partid_max = FIELD_GET(MPAMF_IDR_PARTID_MAX, idr);
	msc->pmg_max = FIELD_GET(MPAMF_IDR_PMG_MAX, idr);

	for (ris_idx = 0; ris_idx <= msc->ris_max; ris_idx++) {
		mutex_lock(&msc->part_sel_lock);
		__mpam_part_sel(ris_idx, 0, msc);
		idr = mpam_msc_read_idr(msc);
		mutex_unlock(&msc->part_sel_lock);

		partid_max = FIELD_GET(MPAMF_IDR_PARTID_MAX, idr);
		pmg_max = FIELD_GET(MPAMF_IDR_PMG_MAX, idr);
		msc->partid_max = min(msc->partid_max, partid_max);
		msc->pmg_max = min(msc->pmg_max, pmg_max);
		msc->has_extd_esr = FIELD_GET(MPAMF_IDR_HAS_EXT_ESR, idr);

		ris = mpam_get_or_create_ris(msc, ris_idx);
		if (IS_ERR(ris))
			return PTR_ERR(ris);
		ris->idr = idr;

		mutex_lock(&msc->part_sel_lock);
		__mpam_part_sel(ris_idx, 0, msc);
		mpam_ris_hw_probe(ris);
		mutex_unlock(&msc->part_sel_lock);
	}

	spin_lock(&partid_max_lock);
	mpam_partid_max = min(mpam_partid_max, msc->partid_max);
	mpam_pmg_max = min(mpam_pmg_max, msc->pmg_max);
	spin_unlock(&partid_max_lock);

	msc->probed = true;

	return 0;
}

struct mon_read {
	struct mpam_msc_ris		*ris;
	struct mon_cfg			*ctx;
	enum mpam_device_features	type;
	u64				*val;
	int				err;
	bool				waited_timeout;
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

	mpam_mon_sel_lock_held(msc);

	WARN_ON_ONCE((MSMON_MBWU_L + sizeof(u64)) > msc->mapped_hwpage_sz);
	WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(), &msc->accessibility));

	mbwu_l_high2 = __mpam_read_reg(msc, MSMON_MBWU_L + 4);
	do {
		mbwu_l_high1 = mbwu_l_high2;
		mbwu_l_low = __mpam_read_reg(msc, MSMON_MBWU_L);
		mbwu_l_high2 = __mpam_read_reg(msc, MSMON_MBWU_L + 4);

		retry--;
	} while (mbwu_l_high1 != mbwu_l_high2 && retry > 0);

	if (mbwu_l_high1 == mbwu_l_high2)
		return (mbwu_l_high1 << 32) | mbwu_l_low;
	return MSMON___NRDY_L;
}

static void mpam_msc_zero_mbwu_l(struct mpam_msc *msc)
{
	mpam_mon_sel_lock_held(msc);

	WARN_ON_ONCE((MSMON_MBWU_L + sizeof(u64)) > msc->mapped_hwpage_sz);
	WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(), &msc->accessibility));

	__mpam_write_reg(msc, MSMON_MBWU_L, 0);
	__mpam_write_reg(msc, MSMON_MBWU_L + 4, 0);
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
	struct mpam_msc *msc = m->ris->vmsc->msc;

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

/* Remove values set by the hardware to prevent aparant mismatches. */
static void clean_msmon_ctl_val(u32 *cur_ctl)
{
	*cur_ctl &= ~MSMON_CFG_x_CTL_OFLOW_STATUS;
	*cur_ctl &= ~MSMON_CFG_x_CTL_OFLOW_STATUS_L;
}

static void write_msmon_ctl_flt_vals(struct mon_read *m, u32 ctl_val,
				     u32 flt_val)
{
	struct msmon_mbwu_state *mbwu_state;
	struct mpam_msc *msc = m->ris->vmsc->msc;

	/*
	 * Write the ctl_val with the enable bit cleared, reset the counter,
	 * then enable counter.
	 */
	switch (m->type) {
	case mpam_feat_msmon_csu:
		mpam_write_monsel_reg(msc, CFG_CSU_FLT, flt_val);
		mpam_write_monsel_reg(msc, CFG_CSU_CTL, ctl_val);
		mpam_write_monsel_reg(msc, CSU, 0);
		mpam_write_monsel_reg(msc, CFG_CSU_CTL, ctl_val | MSMON_CFG_x_CTL_EN);
		break;
	case mpam_feat_msmon_mbwu:
		mpam_write_monsel_reg(msc, CFG_MBWU_FLT, flt_val);
		mpam_write_monsel_reg(msc, CFG_MBWU_CTL, ctl_val);
		if (mpam_ris_has_mbwu_long_counter(m->ris))
			mpam_msc_zero_mbwu_l(m->ris->vmsc->msc);
		else
			mpam_write_monsel_reg(msc, MBWU, 0);

		mpam_write_monsel_reg(msc, CFG_MBWU_CTL, ctl_val | MSMON_CFG_x_CTL_EN);

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

/* Call with MSC lock held */
static void __ris_msmon_read(void *arg)
{
	bool nrdy = false;
	bool config_mismatch;
	struct mon_read *m = arg;
	u64 now, overflow_val = 0;
	struct mon_cfg *ctx = m->ctx;
	bool reset_on_next_read = false;
	struct mpam_msc_ris *ris = m->ris;
	struct msmon_mbwu_state *mbwu_state;
	struct mpam_props *rprops = &ris->props;
	struct mpam_msc *msc = m->ris->vmsc->msc;
	u32 mon_sel, ctl_val, flt_val, cur_ctl, cur_flt;

	if (!mpam_mon_sel_inner_lock(msc)) {
		m->err = -EIO;
		return;
	}
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
	clean_msmon_ctl_val(&cur_ctl);
	gen_msmon_ctl_flt_vals(m, &ctl_val, &flt_val);
	config_mismatch = cur_flt != flt_val ||
			  cur_ctl != (ctl_val | MSMON_CFG_x_CTL_EN);

	if (config_mismatch || reset_on_next_read)
		write_msmon_ctl_flt_vals(m, ctl_val, flt_val);

	switch (m->type) {
	case mpam_feat_msmon_csu:
		now = mpam_read_monsel_reg(msc, CSU);
		if (mpam_has_feature(mpam_feat_msmon_csu_hw_nrdy, rprops))
			nrdy = now & MSMON___NRDY;
		now = FIELD_GET(MSMON___VALUE, now);

		if (mpam_has_quirk(IGNORE_CSU_NRDY, msc) && m->waited_timeout)
			nrdy = false;

		break;
	case mpam_feat_msmon_mbwu:
		/*
		 * If long or lwd counters are supported, use them, else revert
		 * to the 32 bit counter.
		 */
		if (mpam_ris_has_mbwu_long_counter(ris)) {
			now = mpam_msc_read_mbwu_l(msc);
			if (mpam_has_feature(mpam_feat_msmon_mbwu_hw_nrdy, rprops))
				nrdy = now & MSMON___NRDY_L;
			if (mpam_has_feature(mpam_feat_msmon_mbwu_63counter, rprops))
				now = FIELD_GET(MSMON___LWD_VALUE, now);
			else
				now = FIELD_GET(MSMON___L_VALUE, now);
		} else {
			now = mpam_read_monsel_reg(msc, MBWU);
			if (mpam_has_feature(mpam_feat_msmon_mbwu_hw_nrdy, rprops))
				nrdy = now & MSMON___NRDY;
			now = FIELD_GET(MSMON___VALUE, now);
		}

		if (mpam_has_quirk(T241_MBW_COUNTER_SCALE_64, msc))
			now *= 64;

		if (nrdy)
			break;

		if (!mbwu_state)
			break;

		/* Add any pre-overflow value to the mbwu_state->val */
		if (mbwu_state->prev_val > now) {
			overflow_val = mpam_msmon_overflow_val(ris);
			if (mpam_has_quirk(T241_MBW_COUNTER_SCALE_64, msc))
				overflow_val *= 64;
			overflow_val -= mbwu_state->prev_val;
		}

		mbwu_state->prev_val = now;
		mbwu_state->correction += overflow_val;

		/* Include bandwidth consumed before the last hardware reset */
		now += mbwu_state->correction;
		break;
	default:
		m->err = -EINVAL;
		break;
	}
	mpam_mon_sel_inner_unlock(msc);

	if (nrdy) {
		m->err = -EBUSY;
		return;
	}

	*m->val += now;
}

static int _msmon_read(struct mpam_component *comp, struct mon_read *arg)
{
	int err, idx;
	struct mpam_msc *msc;
	struct mpam_vmsc *vmsc;
	struct mpam_msc_ris *ris;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(vmsc, &comp->vmsc, comp_list) {
		msc = vmsc->msc;

		mpam_mon_sel_outer_lock(msc);
		list_for_each_entry_rcu(ris, &vmsc->ris, vmsc_list) {
			arg->ris = ris;

			err = smp_call_function_any(&msc->accessibility,
						    __ris_msmon_read, arg,
						    true);
			if (!err && arg->err)
				err = arg->err;
			if (err)
				break;
		}
		mpam_mon_sel_outer_unlock(msc);
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
	arg.waited_timeout = false;
	*val = 0;

	err = _msmon_read(comp, &arg);
	if (err == -EBUSY && comp->class->nrdy_usec)
		wait_jiffies = usecs_to_jiffies(comp->class->nrdy_usec);

	while (wait_jiffies)
		wait_jiffies = schedule_timeout_uninterruptible(wait_jiffies);

	if (err == -EBUSY) {
		memset(&arg, 0, sizeof(arg));
		arg.ctx = ctx;
		arg.type = type;
		arg.val = val;
		arg.waited_timeout = true;
		*val = 0;

		err = _msmon_read(comp, &arg);
	}

	return err;
}

void mpam_msmon_reset_all_mbwu(struct mpam_component *comp)
{
	int idx, i;
	struct mpam_msc *msc;
	struct mpam_vmsc *vmsc;
	struct mpam_msc_ris *ris;

	if (!mpam_is_enabled())
		return;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(vmsc, &comp->vmsc, comp_list) {
		if (!mpam_has_feature(mpam_feat_msmon_mbwu, &vmsc->props))
			continue;

		msc = vmsc->msc;
		mpam_mon_sel_outer_lock(msc);
		list_for_each_entry_rcu(ris, &msc->ris, vmsc_list) {
			if (!mpam_has_feature(mpam_feat_msmon_mbwu, &ris->props))
				continue;

			if (WARN_ON_ONCE(!mpam_mon_sel_inner_lock(msc)))
				continue;

			for (i = 0; i < ris->props.num_mbwu_mon; i++) {
				ris->mbwu_state[i].correction = 0;
				ris->mbwu_state[i].reset_on_next_read = true;
			}
			mpam_mon_sel_inner_unlock(msc);
		}
		mpam_mon_sel_outer_unlock(msc);
	}
	srcu_read_unlock(&mpam_srcu, idx);
}

void mpam_msmon_reset_mbwu(struct mpam_component *comp, struct mon_cfg *ctx)
{
	int idx;
	struct mpam_msc *msc;
	struct mpam_vmsc *vmsc;
	struct mpam_msc_ris *ris;

	if (!mpam_is_enabled())
		return;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(vmsc, &comp->vmsc, comp_list) {
		if (!mpam_has_feature(mpam_feat_msmon_mbwu, &vmsc->props))
			continue;

		msc = vmsc->msc;
		mpam_mon_sel_outer_lock(msc);
		list_for_each_entry_rcu(ris, &vmsc->ris, vmsc_list) {
			if (!mpam_has_feature(mpam_feat_msmon_mbwu, &ris->props))
				continue;

			if (WARN_ON_ONCE(!mpam_mon_sel_inner_lock(msc)))
				continue;

			ris->mbwu_state[ctx->mon].correction = 0;
			ris->mbwu_state[ctx->mon].reset_on_next_read = true;
			mpam_mon_sel_inner_unlock(msc);
		}
		mpam_mon_sel_outer_unlock(msc);
	}
	srcu_read_unlock(&mpam_srcu, idx);
}

static void mpam_reset_msc_bitmap(struct mpam_msc *msc, u16 reg, u16 wd)
{
	u32 num_words, msb;
	u32 bm = ~0;
	int i;

	lockdep_assert_held(&msc->part_sel_lock);

	if (wd == 0)
		return;

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
	bm = GENMASK(msb, 0);
	if (bm)
		__mpam_write_reg(msc, reg, bm);
}

static void mpam_apply_t241_erratum(struct mpam_msc_ris *ris, u16 partid)
{
	int sidx, i, lcount = 1000;
	void __iomem *regs;
	u64 val0, val;

	regs = t241_scratch_regs[ris->vmsc->msc->t241_id];

	for (i = 0; i < lcount; i++) {
		/* Read the shadow register at index 0 */
		val0 = readq_relaxed(regs + T241_SHADOW_REG_OFF(0, partid));

		/* Check if all the shadow registers have the same value */
		for (sidx = 1; sidx < T241_CHIP_NSLICES; sidx++) {
			val = readq_relaxed(regs +
					    T241_SHADOW_REG_OFF(sidx, partid));
			if (val != val0)
				break;
		}
		if (sidx == T241_CHIP_NSLICES)
			break;
	}

	if (i == lcount)
		pr_warn_once("t241: inconsistent values in shadow regs");

	/* Write a value zero to spare registers to take effect of MBW conf */
	writeq_relaxed(0, regs + T241_SPARE_REG0_OFF);
	writeq_relaxed(0, regs + T241_SPARE_REG1_OFF);
}

static void mpam_quirk_post_config_change(struct mpam_msc_ris *ris, u16 partid,
					  struct mpam_config *cfg)
{
	if (mpam_has_quirk(T241_SCRUB_SHADOW_REGS, ris->vmsc->msc))
		mpam_apply_t241_erratum(ris, partid);
}

/* Called via IPI. Call while holding an SRCU reference */
static void mpam_reprogram_ris_partid(struct mpam_msc_ris *ris, u16 partid,
				      struct mpam_config *cfg)
{
	u32 pri_val = 0;
	u16 cmax = MPAMCFG_CMAX_CMAX;
	u16 bwa_fract = MPAMCFG_MBW_MAX_MAX;
	struct mpam_msc *msc = ris->vmsc->msc;
	struct mpam_props *rprops = &ris->props;
	u16 dspri = GENMASK(rprops->dspri_wd, 0);
	u16 intpri = GENMASK(rprops->intpri_wd, 0);

	mutex_lock(&msc->part_sel_lock);
	__mpam_part_sel(ris->ris_idx, partid, msc);

	if (mpam_has_feature(mpam_feat_partid_nrw, rprops)) {
		/* Update the intpartid mapping */
		mpam_write_partsel_reg(msc, INTPARTID,
				       MPAMCFG_INTPARTID_INTERNAL | partid);

		/*
		 * Then switch to the 'internal' partid to update the
		 * configuration.
		 */
		__mpam_intpart_sel(ris->ris_idx, partid, msc);
	}

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

	if (mpam_has_feature(mpam_feat_mbw_min, rprops)) {
		if (mpam_has_feature(mpam_feat_mbw_min, cfg))
			mpam_write_partsel_reg(msc, MBW_MIN, cfg->mbw_min);
		else
			mpam_write_partsel_reg(msc, MBW_MIN, 0);
	}

	if (mpam_has_feature(mpam_feat_mbw_max, rprops)) {
		if (mpam_has_feature(mpam_feat_mbw_max, cfg))
			mpam_write_partsel_reg(msc, MBW_MAX, cfg->mbw_max);
		else
			mpam_write_partsel_reg(msc, MBW_MAX, bwa_fract);
	}

	if (mpam_has_feature(mpam_feat_mbw_prop, rprops))
		mpam_write_partsel_reg(msc, MBW_PROP, bwa_fract);

	if (mpam_has_feature(mpam_feat_cmax_cmax, rprops))
		mpam_write_partsel_reg(msc, CMAX, cmax);

	if (mpam_has_feature(mpam_feat_cmax_cmin, rprops))
		mpam_write_partsel_reg(msc, CMIN, 0);

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

	mpam_quirk_post_config_change(ris, partid, cfg);

	mutex_unlock(&msc->part_sel_lock);
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
	for (partid = 0; partid <= partid_max; partid++)
		mpam_reprogram_ris_partid(ris, partid, cfg);

	return 0;
}

/* Call with MSC lock and outer mon_sel lock held */
static int mpam_restore_mbwu_state(void *_ris)
{
	int i;
	struct mon_read mwbu_arg;
	struct mpam_msc_ris *ris = _ris;
	struct mpam_msc *msc = ris->vmsc->msc;

	mpam_mon_sel_outer_lock(msc);

	for (i = 0; i < ris->props.num_mbwu_mon; i++) {
		if (ris->mbwu_state[i].enabled) {
			mwbu_arg.ris = ris;
			mwbu_arg.ctx = &ris->mbwu_state[i].cfg;
			mwbu_arg.type = mpam_feat_msmon_mbwu;

			__ris_msmon_read(&mwbu_arg);
		}
	}

	mpam_mon_sel_outer_unlock(msc);

	return 0;
}

/* Call with MSC lock and outer mon_sel lock held */
static int mpam_save_mbwu_state(void *arg)
{
	int i;
	u64 val;
	struct mon_cfg *cfg;
	u32 cur_flt, cur_ctl, mon_sel;
	struct mpam_msc_ris *ris = arg;
	struct msmon_mbwu_state *mbwu_state;
	struct mpam_msc *msc = ris->vmsc->msc;

	for (i = 0; i < ris->props.num_mbwu_mon; i++) {
		mbwu_state = &ris->mbwu_state[i];
		cfg = &mbwu_state->cfg;

		if (WARN_ON_ONCE(!mpam_mon_sel_inner_lock(msc)))
			return -EIO;

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
		mpam_mon_sel_inner_unlock(msc);
	}

	return 0;
}

static void mpam_init_empty_cfg(struct mpam_msc_ris *ris, struct mpam_config *cfg)
{
	struct mpam_props *rprops = &ris->props;
	struct mpam_msc *msc = ris->vmsc->msc;
	u16 max_hw_value, min_hw_granule, res0_bits;

	memset(cfg, 0, sizeof(*cfg));

	if (mpam_has_quirk(T241_FORCE_MBW_MIN_TO_ONE, msc)) {
		res0_bits = 16 - rprops->bwa_wd;
		max_hw_value = ((1 << rprops->bwa_wd) - 1) << res0_bits;
		min_hw_granule = ~max_hw_value;

		cfg->mbw_min = min_hw_granule + 1;
		mpam_set_feature(mpam_feat_mbw_min, cfg);
	}
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

	mpam_init_empty_cfg(ris, &empty_cfg);

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
	mpam_assert_srcu_read_lock_held();

	return smp_call_on_cpu(mpam_get_msc_preferred_cpu(msc), fn, arg, true);
}

static void mpam_reset_msc(struct mpam_msc *msc, bool online)
{
	struct mpam_msc_ris *ris;

	mpam_assert_srcu_read_lock_held();

	mpam_mon_sel_outer_lock(msc);
	list_for_each_entry_srcu(ris, &msc->ris, msc_list, srcu_read_lock_held(&mpam_srcu)) {
		mpam_touch_msc(msc, &mpam_reset_ris, ris);

		/*
		 * Set in_reset_state when coming online. The reset state
		 * for non-zero partid may be lost while the CPUs are offline.
		 */
		ris->in_reset_state = online;

		if (mpam_is_enabled() && !online)
			mpam_touch_msc(msc, &mpam_save_mbwu_state, ris);
	}
	mpam_mon_sel_outer_unlock(msc);
}

static void mpam_reprogram_msc(struct mpam_msc *msc)
{
	int idx;
	u16 partid;
	bool reset;
	struct mpam_config *cfg;
	struct mpam_msc_ris *ris;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(ris, &msc->ris, msc_list) {
		if (!mpam_is_enabled() && !ris->in_reset_state) {
			mpam_touch_msc(msc, &mpam_reset_ris, ris);
			ris->in_reset_state = true;
			continue;
		}

		reset = true;
		for (partid = 0; partid <= mpam_partid_max; partid++) {
			cfg = &ris->vmsc->comp->cfg[partid];
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
	list_for_each_entry_srcu(msc, &mpam_all_msc, glbl_list, srcu_read_lock_held(&mpam_srcu)) {
		if (!cpumask_test_cpu(cpu, &msc->accessibility))
			continue;

		if (msc->reenable_error_ppi)
			_enable_percpu_irq(&msc->reenable_error_ppi);

		if (atomic_fetch_inc(&msc->online_refs) == 0)
			mpam_reprogram_msc(msc);
	}
	srcu_read_unlock(&mpam_srcu, idx);

	if (mpam_resctrl_enabled)
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

		mutex_lock(&msc->probe_lock);
		if (!msc->probed)
			err = mpam_msc_hw_probe(msc);
		mutex_unlock(&msc->probe_lock);

		if (!err)
			new_device_probed = true;
		else
			break; // mpam_broken
	}
	mutex_unlock(&mpam_list_lock);

	if (new_device_probed && !err)
		schedule_work(&mpam_enable_work);

	return err;
}

static int mpam_cpu_offline(unsigned int cpu)
{
	int idx;
	struct mpam_msc *msc;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_srcu(msc, &mpam_all_msc, glbl_list, srcu_read_lock_held(&mpam_srcu)) {
		if (!cpumask_test_cpu(cpu, &msc->accessibility))
			continue;

		if (msc->reenable_error_ppi)
			disable_percpu_irq(msc->reenable_error_ppi);

		if (atomic_dec_and_test(&msc->online_refs))
			mpam_reset_msc(msc, false);
	}
	srcu_read_unlock(&mpam_srcu, idx);

	if (mpam_resctrl_enabled)
		mpam_resctrl_offline_cpu(cpu);

	return 0;
}

static void mpam_register_cpuhp_callbacks(int (*online)(unsigned int online),
					  int (*offline)(unsigned int offline))
{
	mutex_lock(&mpam_cpuhp_state_lock);
	if (mpam_cpuhp_state) {
		cpuhp_remove_state(mpam_cpuhp_state);
		mpam_cpuhp_state = 0;
	}

	mpam_cpuhp_state = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mpam:online",
					     online, offline);
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

		if (empty) {
			pr_err_once("%s shares PPI with %s!\n",
				    dev_name(&msc->pdev->dev),
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
	u32 class_id = 0, component_id = 0;
	struct device_node *cache = NULL, *memory = NULL;
	enum mpam_class_types type = MPAM_CLASS_UNKNOWN;

	do {
		/* What kind of MSC is this? */
		if (of_device_is_compatible(np, "arm,mpam-cache")) {
			cache = of_parse_phandle(np, "arm,mpam-device", 0);
			if (!cache) {
				pr_err("Failed to read phandle\n");
				break;
			}
			type = MPAM_CLASS_CACHE;
		} else if (of_device_is_compatible(np->parent, "cache")) {
			cache = of_node_get(np->parent);
			type = MPAM_CLASS_CACHE;
		} else if (of_device_is_compatible(np, "arm,mpam-memory")) {
			memory = of_parse_phandle(np, "arm,mpam-device", 0);
			if (!memory) {
				pr_err("Failed to read phandle\n");
				break;
			}
			type = MPAM_CLASS_MEMORY;
		} else if (of_device_is_compatible(np, "arm,mpam-memory-controller-msc")) {
			memory = of_node_get(np->parent);
			type = MPAM_CLASS_MEMORY;
		} else {
			/*
			 * For now, only caches and memory controllers are
			 * supported.
			 */
			break;
		}

		/* Determine the class and component ids, based on type. */
		if (type == MPAM_CLASS_CACHE) {
			err = of_property_read_u32(cache, "cache-level", &class_id);
			if (err) {
				pr_err("Failed to read cache-level\n");
				break;
			}
			component_id = cache_of_calculate_id(cache);
			if (component_id == ~0UL) {
				err = -ENOENT;
				break;
			}
		} else if (type == MPAM_CLASS_MEMORY) {
			err = of_node_to_nid(np);
			component_id = (err == NUMA_NO_NODE) ? 0 : err;
			class_id = 255;
		}

		err = mpam_ris_create(msc, ris_idx, type, class_id,
				      component_id);
	} while (0);
	of_node_put(cache);
	of_node_put(memory);

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

/*
 * An MSC can control traffic from a set of CPUs, but may only be accessible
 * from a (hopefully wider) set of CPUs. The common reason for this is power
 * management. If all the CPUs in a cluster are in PSCI:CPU_SUSPEND, the
 * the corresponding cache may also be powered off. By making accesses from
 * one of those CPUs, we ensure this isn't the case.
 */
static int update_msc_accessibility(struct mpam_msc *msc)
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
		} else if (of_device_is_compatible(parent, "memory")) {
			cpumask_copy(&msc->accessibility, cpu_possible_mask);
			err = 0;
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

static void mpam_msc_drv_remove(struct platform_device *pdev)
{
	struct mpam_msc *msc = platform_get_drvdata(pdev);

	if (!msc)
		return;

	mutex_lock(&mpam_list_lock);
	mpam_num_msc--;
	mpam_msc_destroy(msc);
	mutex_unlock(&mpam_list_lock);

	mpam_free_garbage();
}

static int mpam_msc_drv_probe(struct platform_device *pdev)
{
	int err;
	char name[20];
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
		init_garbage(msc);

		mutex_init(&msc->probe_lock);
		mutex_init(&msc->part_sel_lock);
		mutex_init(&msc->outer_mon_sel_lock);
		raw_spin_lock_init(&msc->inner_mon_sel_lock);
		msc->id = mpam_num_msc++;
		msc->pdev = pdev;
		INIT_LIST_HEAD_RCU(&msc->glbl_list);
		INIT_LIST_HEAD_RCU(&msc->ris);

		err = update_msc_accessibility(msc);
		if (err)
			break;
		if (cpumask_empty(&msc->accessibility)) {
			pr_err_once("msc:%u is not accessible from any CPU!",
				    msc->id);
			err = -EINVAL;
			break;
		}

		err = mpam_msc_setup_error_irq(msc);
		if (err)
			break;

		if (device_property_read_u32(&pdev->dev, "pcc-channel",
					     &msc->pcc_subspace_id))
			msc->iface = MPAM_IFACE_MMIO;
		else
			msc->iface = MPAM_IFACE_PCC;

		if (msc->iface == MPAM_IFACE_MMIO) {
			void __iomem *io;

			io = devm_platform_get_and_ioremap_resource(pdev, 0,
								    &msc_res);
			if (IS_ERR(io)) {
				pr_err("Failed to map MSC base address\n");
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
				err = PTR_ERR(msc->pcc_chan);
				break;
			}
		}

		list_add_rcu(&msc->glbl_list, &mpam_all_msc);
		platform_set_drvdata(pdev, msc);

		snprintf(name, sizeof(name), "msc.%u", msc->id);
		msc->debugfs = debugfs_create_dir(name, mpam_debugfs);
		debugfs_create_x32("max_nrdy_usec", 0400, msc->debugfs, &msc->nrdy_usec);
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
		mpam_register_cpuhp_callbacks(&mpam_discovery_cpu_online, NULL);

	if (err && msc)
		mpam_msc_drv_remove(pdev);

	return err;
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

/* Any of these features mean the BWA_WD field is valid. */
static bool mpam_has_bwa_wd_feature(struct mpam_props *props)
{
	if (mpam_has_feature(mpam_feat_mbw_min, props))
		return true;
	if (mpam_has_feature(mpam_feat_mbw_max, props))
		return true;
	if (mpam_has_feature(mpam_feat_mbw_prop, props))
		return true;
	return false;
}

/* Any of these features mean the CMAX_WD field is valid. */
static bool mpam_has_cmax_wd_feature(struct mpam_props *props)
{
	if (mpam_has_feature(mpam_feat_cmax_cmax, props))
		return true;
	if (mpam_has_feature(mpam_feat_cmax_cmin, props))
		return true;
	return false;
}

#define MISMATCHED_HELPER(parent, child, helper, field, alias)		\
	helper(parent) &&						\
	((helper(child) && (parent)->field != (child)->field) ||	\
	 (!helper(child) && !(alias)))

#define MISMATCHED_FEAT(parent, child, feat, field, alias)		     \
	mpam_has_feature((feat), (parent)) &&				     \
	((mpam_has_feature((feat), (child)) && (parent)->field != (child)->field) || \
	 (!mpam_has_feature((feat), (child)) && !(alias)))

#define CAN_MERGE_FEAT(parent, child, feat, alias)			\
	(alias) && !mpam_has_feature((feat), (parent)) &&		\
	mpam_has_feature((feat), (child))

/*
 * Combime two props fields.
 * If this is for controls that alias the same resource, it is safe to just
 * copy the values over. If two aliasing controls implement the same scheme
 * a safe value must be picked.
 * For non-aliasing controls, these control different resources, and the
 * resulting safe value must be compatible with both. When merging values in
 * the tree, all the aliasing resources must be handled first.
 * On mismatch, parent is modified.
 */
static void __props_mismatch(struct mpam_props *parent,
			     struct mpam_props *child, bool alias)
{
	if (CAN_MERGE_FEAT(parent, child, mpam_feat_cpor_part, alias)) {
		parent->cpbm_wd = child->cpbm_wd;
	} else if (MISMATCHED_FEAT(parent, child, mpam_feat_cpor_part,
				   cpbm_wd, alias)) {
		pr_debug("%s cleared cpor_part\n", __func__);
		mpam_clear_feature(mpam_feat_cpor_part, &parent->features);
		parent->cpbm_wd = 0;
	}

	if (CAN_MERGE_FEAT(parent, child, mpam_feat_mbw_part, alias)) {
		parent->mbw_pbm_bits = child->mbw_pbm_bits;
	} else if (MISMATCHED_FEAT(parent, child, mpam_feat_mbw_part,
				   mbw_pbm_bits, alias)) {
		pr_debug("%s cleared mbw_part\n", __func__);
		mpam_clear_feature(mpam_feat_mbw_part, &parent->features);
		parent->mbw_pbm_bits = 0;
	}

	/* bwa_wd is a count of bits, fewer bits means less precision */
	if (alias && !mpam_has_bwa_wd_feature(parent) && mpam_has_bwa_wd_feature(child)) {
		parent->bwa_wd = child->bwa_wd;
	} else if (MISMATCHED_HELPER(parent, child, mpam_has_bwa_wd_feature,
				     bwa_wd, alias)) {
		pr_debug("%s took the min bwa_wd\n", __func__);
		parent->bwa_wd = min(parent->bwa_wd, child->bwa_wd);
	}

	if (alias && !mpam_has_cmax_wd_feature(parent) && mpam_has_cmax_wd_feature(child)) {
		parent->cmax_wd = child->cmax_wd;
	} else if (MISMATCHED_HELPER(parent, child, mpam_has_cmax_wd_feature,
				     cmax_wd, alias)) {
		pr_debug("%s took the min cmax_wd\n", __func__);
		parent->cmax_wd = min(parent->cmax_wd, child->cmax_wd);
	}

	if (CAN_MERGE_FEAT(parent, child, mpam_feat_cmax_cassoc, alias)) {
		parent->cassoc_wd = child->cassoc_wd;
	} else if (MISMATCHED_FEAT(parent, child, mpam_feat_cmax_cassoc,
				   cassoc_wd, alias)) {
		pr_debug("%s cleared cassoc_wd\n", __func__);
		mpam_clear_feature(mpam_feat_cmax_cassoc, &parent->features);
		parent->cassoc_wd = 0;
	}

	/* For num properties, take the minimum */
	if (CAN_MERGE_FEAT(parent, child, mpam_feat_msmon_csu, alias)) {
		parent->num_csu_mon = child->num_csu_mon;
	} else if (MISMATCHED_FEAT(parent, child, mpam_feat_msmon_csu,
				   num_csu_mon, alias)) {
		pr_debug("%s took the min num_csu_mon\n", __func__);
		parent->num_csu_mon = min(parent->num_csu_mon, child->num_csu_mon);
	}

	if (CAN_MERGE_FEAT(parent, child, mpam_feat_msmon_mbwu, alias)) {
		parent->num_mbwu_mon = child->num_mbwu_mon;
	} else if (MISMATCHED_FEAT(parent, child, mpam_feat_msmon_mbwu,
				   num_mbwu_mon, alias)) {
		pr_debug("%s took the min num_mbwu_mon\n", __func__);
		parent->num_mbwu_mon = min(parent->num_mbwu_mon, child->num_mbwu_mon);
	}

	if (CAN_MERGE_FEAT(parent, child, mpam_feat_intpri_part, alias)) {
		parent->intpri_wd = child->intpri_wd;
	} else if (MISMATCHED_FEAT(parent, child, mpam_feat_intpri_part,
				   intpri_wd, alias)) {
		pr_debug("%s took the min intpri_wd\n", __func__);
		parent->intpri_wd = min(parent->intpri_wd, child->intpri_wd);
	}

	if (CAN_MERGE_FEAT(parent, child, mpam_feat_dspri_part, alias)) {
		parent->dspri_wd = child->dspri_wd;
	} else if (MISMATCHED_FEAT(parent, child, mpam_feat_dspri_part,
				   dspri_wd, alias)) {
		pr_debug("%s took the min dspri_wd\n", __func__);
		parent->dspri_wd = min(parent->dspri_wd, child->dspri_wd);
	}

	/* TODO: alias support for these two */
	/* {int,ds}pri may not have differing 0-low behaviour */
	if (mpam_has_feature(mpam_feat_intpri_part, parent) &&
	    (!mpam_has_feature(mpam_feat_intpri_part, child) ||
	     mpam_has_feature(mpam_feat_intpri_part_0_low, parent) !=
	     mpam_has_feature(mpam_feat_intpri_part_0_low, child))) {
		pr_debug("%s cleared intpri_part\n", __func__);
		mpam_clear_feature(mpam_feat_intpri_part, &parent->features);
		mpam_clear_feature(mpam_feat_intpri_part_0_low, &parent->features);
	}
	if (mpam_has_feature(mpam_feat_dspri_part, parent) &&
	    (!mpam_has_feature(mpam_feat_dspri_part, child) ||
	     mpam_has_feature(mpam_feat_dspri_part_0_low, parent) !=
	     mpam_has_feature(mpam_feat_dspri_part_0_low, child))) {
		pr_debug("%s cleared dspri_part\n", __func__);
		mpam_clear_feature(mpam_feat_dspri_part, &parent->features);
		mpam_clear_feature(mpam_feat_dspri_part_0_low, &parent->features);
	}

	if (alias) {
		/* Merge features for aliased resources */
		parent->features |= child->features;
	} else {
		/* Clear missing features for non aliasing */
		parent->features &= child->features;
	}
}

/*
 * If a vmsc doesn't match class feature/configuration, do the right thing(tm).
 * For 'num' properties we can just take the minimum.
 * For properties where the mismatched unused bits would make a difference, we
 * nobble the class feature, as we can't configure all the resources.
 * e.g. The L3 cache is composed of two resources with 13 and 17 portion
 * bitmaps respectively.
 * Quirks on an MSC will apply to all MSC in that class.
 */
static void
__class_props_mismatch(struct mpam_class *class, struct mpam_vmsc *vmsc)
{
	struct mpam_props *cprops = &class->props;
	struct mpam_props *vprops = &vmsc->props;

	lockdep_assert_held(&mpam_list_lock); /* we modify class */

	pr_debug("%s: Merging features for class:0x%lx &= vmsc:0x%lx\n",
		 dev_name(&vmsc->msc->pdev->dev),
		 (long)cprops->features, (long)vprops->features);

	/* Merge quirks */
	class->quirks |= vmsc->msc->quirks;

	/* Take the safe value for any common features */
	__props_mismatch(cprops, vprops, false);
}

static void
__vmsc_props_mismatch(struct mpam_vmsc *vmsc, struct mpam_msc_ris *ris)
{
	struct mpam_props *rprops = &ris->props;
	struct mpam_props *vprops = &vmsc->props;

	lockdep_assert_held(&mpam_list_lock); /* we modify vmsc */

	pr_debug("%s: Merging features for vmsc:0x%lx |= ris:0x%lx\n",
		 dev_name(&vmsc->msc->pdev->dev),
		 (long)vprops->features, (long)rprops->features);

	/*
	 * Merge mismatched features - Copy any features that aren't common,
	 * but take the safe value for any common features.
	 */
	__props_mismatch(vprops, rprops, true);
}

/*
 * Copy the first component's first vMSC's properties and features to the
 * class. __class_props_mismatch() will remove conflicts.
 * It is not possible to have a class with no components, or a component with
 * no resources. The vMSC properties have already been built.
 */
static void mpam_enable_init_class_features(struct mpam_class *class)
{
	struct mpam_vmsc *vmsc;
	struct mpam_component *comp;

	comp = list_first_entry_or_null(&class->components,
					struct mpam_component, class_list);
	if (WARN_ON(!comp))
		return;

	vmsc = list_first_entry_or_null(&comp->vmsc,
					struct mpam_vmsc, comp_list);
	if (WARN_ON(!vmsc))
		return;

	class->props = vmsc->props;
}

static void mpam_enable_merge_vmsc_features(struct mpam_component *comp)
{
	struct mpam_vmsc *vmsc;
	struct mpam_msc_ris *ris;
	struct mpam_class *class = comp->class;

	list_for_each_entry(vmsc, &comp->vmsc, comp_list) {
		list_for_each_entry(ris, &vmsc->ris, vmsc_list) {
			__vmsc_props_mismatch(vmsc, ris);
			class->nrdy_usec = max(class->nrdy_usec,
					       vmsc->msc->nrdy_usec);
		}
	}
}

static void mpam_enable_merge_class_features(struct mpam_component *comp)
{
	struct mpam_vmsc *vmsc;
	struct mpam_class *class = comp->class;

	list_for_each_entry(vmsc, &comp->vmsc, comp_list)
		__class_props_mismatch(class, vmsc);
}


static int mpam_component_sort_cmp(void *priv, const struct list_head *a,
				   const struct list_head *b)
{
	const struct mpam_component *comp0;
	const struct mpam_component *comp1;

	lockdep_assert_held(&mpam_list_lock);

	comp0 = list_entry(a, struct mpam_component, class_list);
	comp1 = list_entry(b, struct mpam_component, class_list);

	return comp0->comp_id > comp1->comp_id;
}

/*
 * Merge all the common resource features into class.
 * vmsc features are bitwise-or'd together, this must be done first.
 * Next the class features are the bitwise-and of all the vmsc features.
 * Other features are the min/max as appropriate.
 *
 * To avoid walking the whole tree twice, the class->nrdy_usec property is
 * updated when working with the vmsc as it is a max(), and doesn't need
 * initialising first.
 */
static void mpam_enable_merge_features(struct list_head *all_classes_list)
{
	struct mpam_class *class;
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_list_lock);

	list_for_each_entry(class, all_classes_list, classes_list) {

		list_sort(NULL, &class->components, mpam_component_sort_cmp);

		list_for_each_entry(comp, &class->components, class_list)
			mpam_enable_merge_vmsc_features(comp);

		mpam_enable_init_class_features(class);

		list_for_each_entry(comp, &class->components, class_list)
			mpam_enable_merge_class_features(comp);
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

	__mpam_write_reg(msc, MPAMF_ECR, 1);

	return 0;
}

static int mpam_disable_msc_ecr(void *_msc)
{
	struct mpam_msc *msc = _msc;

	__mpam_write_reg(msc, MPAMF_ECR, 0);

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
	int err, irq, idx;
	struct mpam_msc *msc;

	lockdep_assert_cpus_held();

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_srcu(msc, &mpam_all_msc, glbl_list, srcu_read_lock_held(&mpam_srcu)) {
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

			msc->reenable_error_ppi = irq;
			smp_call_function_many(&msc->accessibility,
					       &_enable_percpu_irq, &irq,
					       true);
		} else {
			err = devm_request_threaded_irq(&msc->pdev->dev, irq,
							&mpam_spi_handler,
							&mpam_disable_thread,
							IRQF_SHARED,
							"mpam:msc:error", msc);
			if (err)
				return err;
		}

		msc->error_irq_requested = true;
		mpam_touch_msc(msc, mpam_enable_msc_ecr, msc);
		msc->error_irq_hw_enabled = true;
	}
	srcu_read_unlock(&mpam_srcu, idx);

	return 0;
}

static void mpam_unregister_irqs(void)
{
	int irq, idx;
	struct mpam_msc *msc;

	cpus_read_lock();
	/* take the lock as free_irq() can sleep */
	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_srcu(msc, &mpam_all_msc, glbl_list, srcu_read_lock_held(&mpam_srcu)) {
		irq = platform_get_irq_byname_optional(msc->pdev, "error");
		if (irq <= 0)
			continue;

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
	}
	srcu_read_unlock(&mpam_srcu, idx);
	cpus_read_unlock();
}

static void __destroy_component_cfg(struct mpam_component *comp)
{
	struct mpam_msc *msc;
	struct mpam_vmsc *vmsc;
	struct mpam_msc_ris *ris;

	lockdep_assert_held(&mpam_list_lock);

	add_to_garbage(comp->cfg);
	list_for_each_entry(vmsc, &comp->vmsc, comp_list) {
		msc = vmsc->msc;

		mpam_mon_sel_outer_lock(msc);
		if (mpam_mon_sel_inner_lock(msc)) {
			list_for_each_entry(ris, &vmsc->ris, vmsc_list)
				add_to_garbage(ris->mbwu_state);
			mpam_mon_sel_inner_unlock(msc);
		}
		mpam_mon_sel_outer_lock(msc);
	}
}

static int __allocate_component_cfg(struct mpam_component *comp)
{
	int err = 0;
	struct mpam_msc *msc;
	struct mpam_vmsc *vmsc;
	struct mpam_msc_ris *ris;
	struct msmon_mbwu_state *mbwu_state;

	lockdep_assert_held(&mpam_list_lock);

	if (comp->cfg)
		return 0;

	comp->cfg = kcalloc(mpam_partid_max + 1, sizeof(*comp->cfg), GFP_KERNEL);
	if (!comp->cfg)
		return -ENOMEM;
	init_garbage(comp->cfg);

	list_for_each_entry(vmsc, &comp->vmsc, comp_list) {
		if (!vmsc->props.num_mbwu_mon)
			continue;

		msc = vmsc->msc;
		mpam_mon_sel_outer_lock(msc);
		list_for_each_entry(ris, &vmsc->ris, vmsc_list) {
			if (!ris->props.num_mbwu_mon)
				continue;

			mbwu_state = kcalloc(ris->props.num_mbwu_mon,
					     sizeof(*ris->mbwu_state),
					     GFP_KERNEL);
			if (!mbwu_state) {
				__destroy_component_cfg(comp);
				err = -ENOMEM;
				break;
			}

			if (mpam_mon_sel_inner_lock(msc)) {
				init_garbage(mbwu_state);
				ris->mbwu_state = mbwu_state;
				mpam_mon_sel_inner_unlock(msc);
			}
		}
		mpam_mon_sel_outer_unlock(msc);

		if (err)
			break;
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

static void mpam_debugfs_setup_ris(struct mpam_msc_ris *ris)
{
	char name[40];
	struct dentry *d;
	struct mpam_props *rprops = &ris->props;

	snprintf(name, sizeof(name), "ris.%u", ris->ris_idx);
	d = debugfs_create_dir(name, ris->vmsc->msc->debugfs);
	debugfs_create_x64("mpamf_idr", 0400, d, &ris->idr);
	debugfs_create_x32("mpamf_cpor_idr", 0400, d, &ris->cpor_idr);
	debugfs_create_x32("mpamf_ccap_idr", 0400, d, &ris->ccap_idr);
	debugfs_create_x32("features", 0400, d, &rprops->features);
	debugfs_create_x16("cpbm_wd", 0400, d, &rprops->cpbm_wd);
	debugfs_create_x16("mbw_pbm_bits", 0400, d, &rprops->mbw_pbm_bits);
	debugfs_create_x16("num_csu_mon", 0400, d, &rprops->num_csu_mon);
	debugfs_create_x16("num_mbwu_mon", 0400, d, &rprops->num_mbwu_mon);
	debugfs_create_cpumask("affinity", 0400, d, &ris->affinity);
	ris->debugfs = d;
}

static void mpam_debugfs_setup_vmsc(struct mpam_component *comp,
				    struct mpam_vmsc *vmsc)
{
	u8 ris_idx;
	char name[40];
	char path[40];
	struct dentry *d;
	struct mpam_msc_ris *ris;
	int msc_id = vmsc->msc->id;

	snprintf(name, sizeof(name), "vmsc.%u", msc_id);
	d = debugfs_create_dir(name, comp->debugfs);
	debugfs_create_x32("features", 0400, d, &vmsc->props.features);
	vmsc->debugfs = d;

	list_for_each_entry_rcu(ris, &vmsc->ris, vmsc_list) {
		ris_idx = ris->ris_idx;

		snprintf(name, sizeof(name), "msc.%u_ris.%u", msc_id,
			 ris_idx);
		snprintf(path, sizeof(path), "../../../msc.%u/ris.%u",
			 msc_id, ris_idx);
		debugfs_create_symlink(name, d, path);
	}
}

static void mpam_debugfs_setup_comp(struct mpam_class *class,
				    struct mpam_component *comp)
{
	char name[40];
	struct dentry *d;
	struct mpam_vmsc *vmsc;

	snprintf(name, sizeof(name), "comp.%u", comp->comp_id);
	d = debugfs_create_dir(name, class->debugfs);
	comp->debugfs = d;

	list_for_each_entry_rcu(vmsc, &comp->vmsc, comp_list)
		mpam_debugfs_setup_vmsc(comp, vmsc);
}

static void mpam_debugfs_setup(void)
{
	char name[40];
	struct dentry *d;
	struct mpam_msc *msc;
	struct mpam_class *class;
	struct mpam_msc_ris *ris;
	struct mpam_component *comp;

	lockdep_assert_held(&mpam_list_lock);

	list_for_each_entry(msc, &mpam_all_msc, glbl_list) {
		d = msc->debugfs;
		debugfs_create_u32("fw_id", 0400, d, &msc->pdev->id);
		debugfs_create_x32("iface", 0400, d, &msc->iface);
		debugfs_create_x32("mpamf_iidr", 0400, d, &msc->iidr);
		list_for_each_entry(ris, &msc->ris, msc_list)
			mpam_debugfs_setup_ris(ris);
	}

	list_for_each_entry_rcu(class, &mpam_classes, classes_list) {
		snprintf(name, sizeof(name), "class.%u", class->level);
		d = debugfs_create_dir(name, mpam_debugfs);
		debugfs_create_x32("features", 0400, d, &class->props.features);
		debugfs_create_x32("nrdy_usec", 0400, d, &class->nrdy_usec);
		debugfs_create_x16("quirks", 0400, d, &class->quirks);
		debugfs_create_x8("level", 0400, d, &class->level);
		debugfs_create_cpumask("affinity", 0400, d, &class->affinity);
		class->debugfs = d;

		list_for_each_entry_rcu(comp, &class->components, class_list)
			mpam_debugfs_setup_comp(class, comp);
	}
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
		mpam_enable_merge_features(&mpam_classes);

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

		mpam_debugfs_setup();
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
	mpam_resctrl_enabled = true;
	mpam_register_cpuhp_callbacks(mpam_cpu_online, mpam_cpu_offline);

	printk(KERN_INFO "MPAM enabled with %u partid and %u pmg\n",
		READ_ONCE(mpam_partid_max) + 1, mpam_pmg_max + 1);
}

void mpam_reset_component_locked(struct mpam_component *comp)
{
	int idx;
	struct mpam_msc *msc;
	struct mpam_vmsc *vmsc;
	struct mpam_msc_ris *ris;

	might_sleep();
	lockdep_assert_cpus_held();

	memset(comp->cfg, 0, (mpam_partid_max * sizeof(*comp->cfg)));

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(vmsc, &comp->vmsc, comp_list) {
		msc = vmsc->msc;

		list_for_each_entry_rcu(ris, &vmsc->ris, vmsc_list) {
			if (!ris->in_reset_state)
				mpam_touch_msc(msc, mpam_reset_ris, ris);
			ris->in_reset_state = true;
		}
	}
	srcu_read_unlock(&mpam_srcu, idx);
}

void mpam_reset_class_locked(struct mpam_class *class)
{
	int idx;
	struct mpam_component *comp;

	lockdep_assert_cpus_held();

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(comp, &class->components, class_list)
		mpam_reset_component_locked(comp);
	srcu_read_unlock(&mpam_srcu, idx);
}

void mpam_reset_class(struct mpam_class *class)
{
	cpus_read_lock();
	mpam_reset_class_locked(class);
	cpus_read_unlock();
}

/*
 * Called in response to an error IRQ.
 * All of MPAMs errors indicate a software bug, restore any modified
 * controls to their reset values.
 */
static irqreturn_t mpam_disable_thread(int irq, void *dev_id)
{
	int idx;
	bool do_resctrl_exit;
	struct mpam_class *class;
	struct mpam_msc *msc, *tmp;

	if (mpam_is_enabled())
		static_branch_disable(&mpam_enabled);

	mutex_lock(&mpam_cpuhp_state_lock);
	if (mpam_cpuhp_state) {
		cpuhp_remove_state(mpam_cpuhp_state);
		mpam_cpuhp_state = 0;
	}

	/* mpam_cpu_offline() tells resctrl all the CPUs are offline. */
	do_resctrl_exit = mpam_resctrl_enabled;
	mpam_resctrl_enabled = false;
	mutex_unlock(&mpam_cpuhp_state_lock);

	if (do_resctrl_exit)
		mpam_resctrl_exit();

	mpam_unregister_irqs();

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_srcu(class, &mpam_classes, classes_list,
				 srcu_read_lock_held(&mpam_srcu))
		mpam_reset_class(class);
	srcu_read_unlock(&mpam_srcu, idx);

	mutex_lock(&mpam_list_lock);
	list_for_each_entry_safe(msc, tmp, &mpam_all_msc, glbl_list)
		mpam_msc_destroy(msc);
	mutex_unlock(&mpam_list_lock);
	mpam_free_garbage();

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
		mutex_lock(&msc->probe_lock);
		if (!msc->probed)
			all_devices_probed = false;
		mutex_unlock(&msc->probe_lock);

		if (!all_devices_probed)
			break;
	}
	mutex_unlock(&mpam_list_lock);

	if (all_devices_probed && !atomic_fetch_inc(&once))
		mpam_enable_once();
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

#define maybe_update_config(cfg, feature, newcfg, member, changes) do { \
	if (mpam_has_feature(feature, newcfg) &&			\
	    (newcfg)->member != (cfg)->member) {			\
		(cfg)->member = (newcfg)->member;			\
		cfg->features |= (1 << feature);			\
									\
		(changes) |= (1 << feature);				\
	}								\
} while (0)

static mpam_features_t mpam_update_config(struct mpam_config *cfg,
					  const struct mpam_config *newcfg)
{
	mpam_features_t changes = 0;

	maybe_update_config(cfg, mpam_feat_cpor_part, newcfg, cpbm, changes);
	maybe_update_config(cfg, mpam_feat_mbw_part, newcfg, mbw_pbm, changes);
	maybe_update_config(cfg, mpam_feat_mbw_max, newcfg, mbw_max, changes);
	maybe_update_config(cfg, mpam_feat_mbw_min, newcfg, mbw_min, changes);

	return changes;
}

static void mpam_extend_config(struct mpam_class *class, struct mpam_config *cfg)
{
	struct mpam_props *cprops = &class->props;
	u16 min, min_hw_granule, delta;
	u16 max_hw_value, res0_bits;

	/*
	 * Calculate the values the 'min' control can hold.
	 * e.g. on a platform with bwa_wd = 8, min_hw_granule is 0x00ff because
	 * those bits are RES0. Configurations of this value are effectively
	 * zero. But configurations need to saturate at min_hw_granule on
	 * systems with mismatched bwa_wd, where the 'less than 0' values are
	 * implemented on some MSC, but not others.
	 */
	res0_bits = 16 - cprops->bwa_wd;
	max_hw_value = ((1 << cprops->bwa_wd) - 1) << res0_bits;
	min_hw_granule = ~max_hw_value;

	/*
	 * MAX and MIN should be set together. If only one is provided,
	 * generate a configuration for the other. If only one control
	 * type is supported, the other value will be ignored.
	 *
	 * Resctrl can only configure the MAX.
	 */
	if (mpam_has_feature(mpam_feat_mbw_max, cfg) &&
	    !mpam_has_feature(mpam_feat_mbw_min, cfg)) {
		delta = ((5 * MPAMCFG_MBW_MAX_MAX) / 100) - 1;
		if (cfg->mbw_max > delta)
			min = cfg->mbw_max - delta;
		else
			min = 0;

		cfg->mbw_min = max(min, min_hw_granule);
		mpam_set_feature(mpam_feat_mbw_min, cfg);
	}

	if (mpam_has_quirk(T241_FORCE_MBW_MIN_TO_ONE, class) &&
	    cfg->mbw_min <= min_hw_granule) {
		cfg->mbw_min = min_hw_granule + 1;
		mpam_set_feature(mpam_feat_mbw_min, cfg);
	}
}

/* TODO: split into write_config/sync_config */
/* TODO: add config_dirty bitmap to drive sync_config */
int mpam_apply_config(struct mpam_component *comp, u16 partid,
		      struct mpam_config *user_cfg)
{
	struct mpam_write_config_arg arg;
	struct mpam_msc_ris *ris;
	struct mpam_config cfg;
	struct mpam_vmsc *vmsc;
	struct mpam_msc *msc;
	int idx;

	lockdep_assert_cpus_held();


	/* Don't pass in the current config! */
	WARN_ON_ONCE(&comp->cfg[partid] == user_cfg);

	/*
	 * Copy the config to avoid writing back the 'extended' version to
	 * the caller.
	 * This avoids mpam_devices.c setting a mbm_min that mpam_resctrl.c
	 * is unaware of ... when it then changes mbm_max to be lower than
	 * mbm_min.
	 */
	cfg = *user_cfg;

	mpam_extend_config(comp->class, &cfg);

	if (!mpam_update_config(&comp->cfg[partid], &cfg))
		return 0;

	arg.comp = comp;
	arg.partid = partid;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(vmsc, &comp->vmsc, comp_list) {
		msc = vmsc->msc;

		list_for_each_entry_rcu(ris, &vmsc->ris, vmsc_list) {
			arg.ris = ris;
			mpam_touch_msc(msc, __write_config, &arg);
		}
	}
	srcu_read_unlock(&mpam_srcu, idx);

	return 0;
}

/*
 * MSC that are hidden under caches are not created as platform devices
 * as there is no cache driver. Caches are also special-cased in
 * update_msc_accessibility().
 */
static void mpam_dt_create_foundling_msc(void)
{
	int err;
	struct device_node *cache;

	for_each_compatible_node(cache, NULL, "cache") {
		err = of_platform_populate(cache, mpam_of_match, NULL, NULL);
		if (err)
			pr_err("Failed to create MSC devices under caches\n");
	}
}

static int __init mpam_msc_driver_init(void)
{
	bool mpam_not_available = false;

	if (!system_supports_mpam())
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

	mpam_debugfs = debugfs_create_dir("mpam", NULL);

	return platform_driver_register(&mpam_msc_driver);
}
/* Must occur after arm64_mpam_register_cpus() from arch_initcall() */
subsys_initcall(mpam_msc_driver_init);

#ifdef CONFIG_MPAM_KUNIT_TEST
#include "test_mpam_devices.c"
#endif
