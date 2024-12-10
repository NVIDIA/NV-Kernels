/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#ifndef _VIRT_COCO_RMM_DA_H_
#define _VIRT_COCO_RMM_DA_H_

#include <linux/pci.h>
#include <linux/pci-ide.h>
#include <linux/pci-tsm.h>
#include <asm/rmi_smc.h>

/**
 * struct cca_host_pf0_dsc - Device Security Context for physical function 0.
 * @pci: Physical Function 0 TDISP link context
 * @sel_stream: Selective IDE Stream descriptor
 * @rmm_pdev: Delegated granule address of rmm pdev object
 * @num_ax: Number of auxiliary granules allocated for pdev
 * @aux: Delegated auxiliary granules
 */
struct cca_host_pf0_dsc {
	struct pci_tsm_pf0 pci;
	struct pci_ide *sel_stream;

	void *rmm_pdev;
	int num_aux;
	void *aux[MAX_PDEV_AUX_GRANULES];
};

struct cca_host_fn_dsc {
	struct pci_tsm pci;
};

static inline struct cca_host_pf0_dsc *to_cca_pf0_dsc(struct pci_dev *pdev)
{
	struct pci_tsm *tsm = pdev->tsm;

	if (!tsm || !is_pci_tsm_pf0(pdev))
		return NULL;

	return container_of(tsm, struct cca_host_pf0_dsc, pci.base_tsm);
}

static inline struct cca_host_fn_dsc *to_cca_fn_dsc(struct pci_dev *pdev)
{
	struct pci_tsm *tsm = pdev->tsm;

	return container_of(tsm, struct cca_host_fn_dsc, pci);
}

int cca_pdev_create(struct pci_dev *pdev);
#endif
