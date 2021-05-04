// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2022 Arm Ltd.

#define pr_fmt(fmt) "mpam: " fmt

#include <linux/acpi.h>
#include <linux/atomic.h>
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
#include <linux/workqueue.h>

#include <acpi/pcc.h>

#include <asm/mpam.h>

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

static int mpam_cpuhp_state;
static DEFINE_MUTEX(mpam_cpuhp_state_lock);

/*
 * mpam is enabled once all devices have been probed from CPU online callbacks,
 * scheduled via this work_struct. If access to an MSC depends on a CPU that
 * was not brought online at boot, this can happen surprisingly late.
 */
static DECLARE_WORK(mpam_enable_work, &mpam_enable);

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
	WARN_ON_ONCE(reg > msc->mapped_hwpage_sz);
	WARN_ON_ONCE(!cpumask_test_cpu(smp_processor_id(), &msc->accessibility));

	return readl_relaxed(msc->mapped_hwpage + reg);
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

static int mpam_msc_hw_probe(struct mpam_msc *msc)
{
	u64 idr;
	int err;

	lockdep_assert_held(&msc->lock);

	spin_lock(&msc->part_sel_lock);
	idr = mpam_read_partsel_reg(msc, AIDR);
	if ((idr & MPAMF_AIDR_ARCH_MAJOR_REV) != MPAM_ARCHITECTURE_V1) {
		pr_err_once("%s does not match MPAM architecture v1.0\n",
			    dev_name(&msc->pdev->dev));
		err = -EIO;
	} else {
		msc->probed = true;
		err = 0;
	}
	spin_unlock(&msc->part_sel_lock);

	return err;
}

static int mpam_cpu_online(unsigned int cpu)
{
	return 0;
}

/* Before mpam is enabled, try to probe new MSC */
static int mpam_discovery_cpu_online(unsigned int cpu)
{
	int err = 0;
	struct mpam_msc *msc;
	bool new_device_probed = false;

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

static void mpam_enable_once(void)
{
	mutex_lock(&mpam_cpuhp_state_lock);
	cpuhp_remove_state(mpam_cpuhp_state);
	mpam_cpuhp_state = 0;
	mutex_unlock(&mpam_cpuhp_state_lock);

	mpam_register_cpuhp_callbacks(mpam_cpu_online);

	pr_info("MPAM enabled\n");
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

	/* Have we probed all the hw devices? */
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
	if (!mpam_cpus_have_feature())
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
