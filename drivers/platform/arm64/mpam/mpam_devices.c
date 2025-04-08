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
#include <linux/srcu.h>
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

static struct srcu_struct mpam_srcu;

/* MPAM isn't available until all the MSC have been probed. */
static u32 mpam_num_msc;

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
		if (of_device_is_compatible(parent, "memory")) {
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
	platform_set_drvdata(pdev, NULL);
	list_del_rcu(&msc->glbl_list);
	synchronize_srcu(&mpam_srcu);
	devm_kfree(&pdev->dev, msc);
	mutex_unlock(&mpam_list_lock);
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
