// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2024 - 2025 Intel Corporation. All rights reserved. */

#define dev_fmt(fmt) "devsec: " fmt
#include <linux/device/faux.h>
#include <linux/pci-tsm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/tsm.h>
#include "devsec.h"

struct devsec_dev_data {
	struct pci_tsm_devsec pci;
};

static struct devsec_dev_data *to_devsec_data(struct pci_tsm *tsm)
{
	return container_of(tsm, struct devsec_dev_data, pci.base_tsm);
}

static struct pci_tsm *devsec_tsm_lock(struct tsm_dev *tsm_dev, struct pci_dev *pdev)
{
	int rc;

	struct devsec_dev_data *devsec_data __free(kfree) =
		kzalloc(sizeof(*devsec_data), GFP_KERNEL);
	if (!devsec_data)
		return ERR_PTR(-ENOMEM);

	rc = pci_tsm_devsec_constructor(pdev, &devsec_data->pci, tsm_dev);
	if (rc)
		return ERR_PTR(rc);

	return &no_free_ptr(devsec_data)->pci.base_tsm;
}

static void devsec_tsm_unlock(struct pci_tsm *tsm)
{
	struct devsec_dev_data *devsec_data = to_devsec_data(tsm);
	struct pci_tsm_devsec *devsec_tsm = to_pci_tsm_devsec(tsm);

	pci_tsm_mmio_teardown(devsec_tsm->mmio);
	kfree(devsec_tsm->mmio);
	kfree(devsec_data);
}

static int devsec_tsm_accept(struct pci_dev *pdev)
{
	struct pci_tsm_devsec *devsec_tsm = to_pci_tsm_devsec(pdev->tsm);
	int rc;

	struct pci_tsm_mmio *mmio __free(kfree) =
		kzalloc(struct_size(mmio, res, PCI_NUM_RESOURCES), GFP_KERNEL);
	if (!mmio)
		return -ENOMEM;

	/*
	 * Typically this range request would come from the TDISP Interface
	 * Report. For this sample, just request all BARs be marked encrypted
	 */
	for (int i = 0; i < PCI_NUM_RESOURCES; i++) {
		if (pci_resource_len(pdev, i) == 0 ||
		    !(pci_resource_flags(pdev, i) & IORESOURCE_MEM))
			continue;
		mmio->res[mmio->nr].start = pci_resource_start(pdev, i);
		mmio->res[mmio->nr].end = pci_resource_end(pdev, i);
		mmio->nr++;
	}

	rc = pci_tsm_mmio_setup(pdev, mmio);
	if (rc)
		return rc;
	devsec_tsm->mmio = no_free_ptr(mmio);
	return 0;
}

static struct pci_tsm_ops devsec_pci_ops = {
	.lock = devsec_tsm_lock,
	.unlock = devsec_tsm_unlock,
	.accept = devsec_tsm_accept,
};

static void devsec_tsm_remove(void *tsm_dev)
{
	tsm_unregister(tsm_dev);
}

static int devsec_tsm_probe(struct faux_device *fdev)
{
	struct tsm_dev *tsm_dev;

	tsm_dev = tsm_register(&fdev->dev, &devsec_pci_ops);
	if (IS_ERR(tsm_dev))
		return PTR_ERR(tsm_dev);

	return devm_add_action_or_reset(&fdev->dev, devsec_tsm_remove,
					tsm_dev);
}

static struct faux_device *devsec_tsm;

static const struct faux_device_ops devsec_device_ops = {
	.probe = devsec_tsm_probe,
};

static int __init devsec_tsm_init(void)
{
	devsec_tsm = faux_device_create("devsec_tsm", NULL, &devsec_device_ops);
	if (!devsec_tsm)
		return -ENOMEM;
	return 0;
}
module_init(devsec_tsm_init);

static void __exit devsec_tsm_exit(void)
{
	faux_device_destroy(devsec_tsm);
}
module_exit(devsec_tsm_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Device Security Sample Infrastructure: Device Security TSM Driver");
