/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#ifndef _VIRT_COCO_RSI_DA_H_
#define _VIRT_COCO_RSI_DA_H_

#include <linux/pci.h>
#include <linux/pci-tsm.h>
#include <asm/rsi_smc.h>

struct cca_guest_dsc {
	struct pci_tsm_devsec pci;
};

static inline struct cca_guest_dsc *to_cca_guest_dsc(struct pci_dev *pdev)
{
	struct pci_tsm *tsm = pdev->tsm;

	if (!tsm)
		return NULL;
	return container_of(tsm, struct cca_guest_dsc, pci.base_tsm);
}

/*
 * Linux use device requester id as the vdev id.
 */
static inline int rsi_vdev_id(struct pci_dev *pdev)
{
	return (pci_domain_nr(pdev->bus) << 16) |
	       PCI_DEVID(pdev->bus->number, pdev->devfn);
}

#endif
