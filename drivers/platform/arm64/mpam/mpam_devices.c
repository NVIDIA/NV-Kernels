// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2025 Arm Ltd.

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <linux/acpi.h>
#include <linux/arm_mpam.h>
#include <linux/cacheinfo.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/gfp.h>
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

#include <acpi/pcc.h>

#include "mpam_internal.h"

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

	list_del_rcu(&class->classes_list);
	add_to_garbage(class);
}

static void mpam_comp_destroy(struct mpam_component *comp)
{
	struct mpam_class *class = comp->class;

	lockdep_assert_held(&mpam_list_lock);

	list_del_rcu(&comp->class_list);
	add_to_garbage(comp);

	if (list_empty(&class->components))
		mpam_class_destroy(class);
}

static void mpam_vmsc_destroy(struct mpam_vmsc *vmsc)
{
	struct mpam_component *comp = vmsc->comp;

	lockdep_assert_held(&mpam_list_lock);

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

	cpumask_andnot(&comp->affinity, &comp->affinity, &ris->affinity);
	cpumask_andnot(&class->affinity, &class->affinity, &ris->affinity);
	clear_bit(ris->ris_idx, msc->ris_idxs);
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

	list_del_rcu(&msc->glbl_list);
	platform_set_drvdata(pdev, NULL);

	list_for_each_entry_safe(ris, tmp, &msc->ris, msc_list)
		mpam_ris_destroy(ris);

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

static void mpam_discovery_complete(void)
{
	pr_err("Discovered all MSC\n");
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
		mpam_discovery_complete();

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
	if (!system_supports_mpam())
		return -EOPNOTSUPP;

	init_srcu_struct(&mpam_srcu);

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
subsys_initcall(mpam_msc_driver_init);
