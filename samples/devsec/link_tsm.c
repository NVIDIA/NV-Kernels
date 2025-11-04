// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2024 - 2025 Intel Corporation. All rights reserved. */

#define dev_fmt(fmt) "devsec: " fmt
#include <linux/device/faux.h>
#include <linux/pci-tsm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/tsm.h>
#include "devsec.h"

struct devsec_tsm_pf0 {
	struct pci_tsm_pf0 pci;
#define NR_TSM_STREAMS 4
};

struct devsec_tsm_fn {
	struct pci_tsm pci;
};

static struct devsec_tsm_pf0 *to_devsec_tsm_pf0(struct pci_tsm *tsm)
{
	return container_of(tsm, struct devsec_tsm_pf0, pci.base_tsm);
}

static struct devsec_tsm_fn *to_devsec_tsm_fn(struct pci_tsm *tsm)
{
	return container_of(tsm, struct devsec_tsm_fn, pci);
}

static struct device *pci_tsm_host(struct pci_dev *pdev)
{
	struct pci_tsm *tsm = READ_ONCE(pdev->tsm);

	if (!tsm)
		return NULL;
	return tsm->tsm_dev->dev.parent;
}

static struct pci_tsm *devsec_tsm_pf0_probe(struct tsm_dev *tsm_dev,
					    struct pci_dev *pdev)
{
	int rc;

	dev_dbg(tsm_dev->dev.parent, "%s\n", pci_name(pdev));

	struct devsec_tsm_pf0 *devsec_tsm __free(kfree) =
		kzalloc(sizeof(*devsec_tsm), GFP_KERNEL);
	if (!devsec_tsm)
		return NULL;

	rc = pci_tsm_pf0_constructor(pdev, &devsec_tsm->pci, tsm_dev);
	if (rc)
		return NULL;

	pci_dbg(pdev, "TSM enabled\n");
	return &no_free_ptr(devsec_tsm)->pci.base_tsm;
}

static struct pci_tsm *devsec_link_tsm_fn_probe(struct tsm_dev *tsm_dev,
						struct pci_dev *pdev)
{
	int rc;

	dev_dbg(tsm_dev->dev.parent, "%s\n", pci_name(pdev));

	struct devsec_tsm_fn *devsec_tsm __free(kfree) =
		kzalloc(sizeof(*devsec_tsm), GFP_KERNEL);
	if (!devsec_tsm)
		return NULL;

	rc = pci_tsm_link_constructor(pdev, &devsec_tsm->pci, tsm_dev);
	if (rc)
		return NULL;

	pci_dbg(pdev, "TSM (sub-function) enabled\n");
	return &no_free_ptr(devsec_tsm)->pci;
}

static struct pci_tsm *devsec_link_tsm_pci_probe(struct tsm_dev *tsm_dev,
						 struct pci_dev *pdev)
{
	if (pdev->sysdata != devsec_sysdata)
		return NULL;

	if (is_pci_tsm_pf0(pdev))
		return devsec_tsm_pf0_probe(tsm_dev, pdev);
	return devsec_link_tsm_fn_probe(tsm_dev, pdev);
}

static void devsec_link_tsm_pci_remove(struct pci_tsm *tsm)
{
	struct pci_dev *pdev = tsm->pdev;

	dev_dbg(pci_tsm_host(pdev), "%s\n", pci_name(pdev));

	if (is_pci_tsm_pf0(pdev)) {
		struct devsec_tsm_pf0 *devsec_tsm = to_devsec_tsm_pf0(tsm);

		pci_tsm_pf0_destructor(&devsec_tsm->pci);
		kfree(devsec_tsm);
	} else {
		struct devsec_tsm_fn *devsec_tsm = to_devsec_tsm_fn(tsm);

		kfree(devsec_tsm);
	}
}

/*
 * Reference consumer for a TSM driver "connect" operation callback. The
 * low-level TSM driver understands details about the platform the PCI
 * core does not, like number of available streams that can be
 * established per host bridge. The expected flow is:
 *
 * 1/ Allocate platform specific Stream resource (TSM specific)
 * 2/ Allocate Stream Ids in the endpoint and Root Port (PCI TSM helper)
 * 3/ Register Stream Ids for the consumed resources from the last 2
 *    steps to be accountable (via sysfs) to the admin (PCI TSM helper)
 * 4/ Register the Stream with the TSM core so that either PCI sysfs or
 *    TSM core sysfs can list the in-use resources (TSM core helper)
 * 5/ Configure IDE settings in the endpoint and Root Port (PCI TSM helper)
 * 6/ RPC call to TSM to perform IDE_KM and optionally enable the stream
 * (TSM Specific)
 * 7/ Enable the stream in the endpoint, and root port if TSM call did
 *    not already handle that (PCI TSM helper)
 *
 * The expectation is the helpers referenceed are convenience "library"
 * APIs for common operations, not a "midlayer" that enforces a specific
 * or use model sequencing.
 */
static int devsec_link_tsm_connect(struct pci_dev *pdev)
{
	return -ENXIO;
}

static void devsec_link_tsm_disconnect(struct pci_dev *pdev)
{
}

static struct pci_tsm_ops devsec_link_pci_ops = {
	.probe = devsec_link_tsm_pci_probe,
	.remove = devsec_link_tsm_pci_remove,
	.connect = devsec_link_tsm_connect,
	.disconnect = devsec_link_tsm_disconnect,
};

static void devsec_link_tsm_remove(void *tsm_dev)
{
	tsm_unregister(tsm_dev);
}

static int devsec_link_tsm_probe(struct faux_device *fdev)
{
	struct tsm_dev *tsm_dev;

	tsm_dev = tsm_register(&fdev->dev, &devsec_link_pci_ops);
	if (IS_ERR(tsm_dev))
		return PTR_ERR(tsm_dev);

	return devm_add_action_or_reset(&fdev->dev, devsec_link_tsm_remove,
					tsm_dev);
}

static struct faux_device *devsec_link_tsm;

static const struct faux_device_ops devsec_link_device_ops = {
	.probe = devsec_link_tsm_probe,
};

static int __init devsec_link_tsm_init(void)
{
	devsec_link_tsm = faux_device_create("devsec_link_tsm", NULL,
					     &devsec_link_device_ops);
	if (!devsec_link_tsm)
		return -ENOMEM;
	return 0;
}
module_init(devsec_link_tsm_init);

static void __exit devsec_link_tsm_exit(void)
{
	faux_device_destroy(devsec_link_tsm);
}
module_exit(devsec_link_tsm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Device Security Sample Infrastructure: Platform Link-TSM Driver");
