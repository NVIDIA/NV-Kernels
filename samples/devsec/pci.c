// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2024 - 2025 Intel Corporation. All rights reserved. */
#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>

static int devsec_pci_probe(struct pci_dev *pdev,
			    const struct pci_device_id *id)
{
	void __iomem *base;
	int rc;

	rc = pcim_enable_device(pdev);
	if (rc)
		return dev_err_probe(&pdev->dev, rc, "enable failed\n");

	base = pcim_iomap_region(pdev, 0, KBUILD_MODNAME);
	if (IS_ERR(base))
		return dev_err_probe(&pdev->dev, PTR_ERR(base),
				     "iomap failed\n");

	rc = device_cc_probe(&pdev->dev);
	if (rc)
		return rc;

	dev_dbg(&pdev->dev, "attach\n");
	return 0;
}

static const struct pci_device_id devsec_pci_ids[] = {
	{ PCI_DEVICE(0x8086, 0xffff), .override_only = 1, },
	{ }
};

static struct pci_driver devsec_pci_driver = {
	.name = "devsec_pci",
	.probe = devsec_pci_probe,
	.id_table = devsec_pci_ids,
};

module_pci_driver(devsec_pci_driver);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Device Security Sample Infrastructure: Secure PCI Driver");
