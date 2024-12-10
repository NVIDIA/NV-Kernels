// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#include <linux/pci.h>
#include <linux/pci-ecam.h>
#include <asm/rmi_cmds.h>

#include "rmi-da.h"

static int pci_ide_aassoc_register_to_pdev_addr(struct rmi_pdev_addr_range *pdev_addr,
						unsigned int naddr, struct pci_ide_partner *partner)
{
	pdev_addr[0].base = partner->mem_assoc.start;
	pdev_addr[0].top  = partner->mem_assoc.end + 1;
	naddr--;

	if (!naddr)
		return 1;

	pdev_addr[1].base = partner->pref_assoc.start;
	pdev_addr[1].top  = partner->pref_assoc.end + 1;

	return 2;
}

static void free_aux_pages(int cnt, void *aux[])
{
	int ret;

	while (cnt--) {
		ret = rmi_granule_undelegate(virt_to_phys(aux[cnt]));
		if (!ret)
			free_page((unsigned long)aux[cnt]);
	}
}

static int init_pdev_params(struct pci_dev *pdev, struct rmi_pdev_params *params)
{
	int rid, ret, i;
	phys_addr_t aux_phys;
	struct pci_config_window *cfg = pdev->bus->sysdata;
	struct cca_host_pf0_dsc *pf0_dsc = to_cca_pf0_dsc(pdev);
	struct pci_ide *ide = pf0_dsc->sel_stream;

	/* assign the ep device with RMM */
	rid = pci_dev_id(pdev);
	params->pdev_id = rid;
	/* slot number for certificate chain */
	params->cert_id = 0;
	/* io coherent spdm/ide and non p2p */
	params->flags = RMI_PDEV_FLAGS_SPDM | RMI_PDEV_FLAGS_NCOH_IDE |
			RMI_PDEV_FLAGS_NCOH_ADDR;
	params->ncoh_ide_sid = ide->stream_id;
	params->hash_algo = RMI_HASH_SHA_256;
	/* use the rid and MMIO resources of the end point pdev */
	params->rid_base = rid;
	params->rid_top = params->rid_base + 1;
	params->ecam_addr = cfg->res.start;
	params->root_id = pci_dev_id(pcie_find_root_port(pdev));

	params->ncoh_num_addr_range =
		pci_ide_aassoc_register_to_pdev_addr(params->ncoh_addr_range,
						     ARRAY_SIZE(params->ncoh_addr_range),
						     &ide->partner[PCI_IDE_RP]);

	rmi_pdev_aux_count(params->flags, &params->num_aux);
	pf0_dsc->num_aux = params->num_aux;
	for (i = 0; i < params->num_aux; i++) {
		void *aux = (void *)__get_free_page(GFP_KERNEL);

		if (!aux) {
			ret = -ENOMEM;
			goto err_free_aux;
		}

		aux_phys = virt_to_phys(aux);
		if (rmi_granule_delegate(aux_phys)) {
			ret = -ENXIO;
			free_page((unsigned long)aux);
			goto err_free_aux;
		}
		params->aux_granule[i] = aux_phys;
		pf0_dsc->aux[i] = aux;
	}
	return 0;

err_free_aux:
	free_aux_pages(i, pf0_dsc->aux);
	return ret;
}

int cca_pdev_create(struct pci_dev *pci_dev)
{
	int ret;
	void *rmm_pdev;
	bool should_free = true;
	phys_addr_t rmm_pdev_phys;
	struct rmi_pdev_params *params;
	struct cca_host_pf0_dsc *pf0_dsc = to_cca_pf0_dsc(pci_dev);

	rmm_pdev = (void *)get_zeroed_page(GFP_KERNEL);
	if (!rmm_pdev)
		return -ENOMEM;

	rmm_pdev_phys = virt_to_phys(rmm_pdev);
	if (rmi_granule_delegate(rmm_pdev_phys)) {
		ret = -ENXIO;
		goto err_granule_delegate;
	}

	params = (struct rmi_pdev_params *)get_zeroed_page(GFP_KERNEL);
	if (!params) {
		ret = -ENOMEM;
		goto err_param_alloc;
	}

	ret = init_pdev_params(pci_dev, params);
	if (ret)
		goto err_init_pdev_params;

	if (rmi_pdev_create(rmm_pdev_phys, virt_to_phys(params))) {
		ret = -ENXIO;
		goto err_pdev_create;
	}

	pf0_dsc->rmm_pdev = rmm_pdev;
	free_page((unsigned long)params);
	return 0;

err_pdev_create:
	free_aux_pages(pf0_dsc->num_aux, pf0_dsc->aux);
err_init_pdev_params:
	free_page((unsigned long)params);
err_param_alloc:
	if (rmi_granule_undelegate(rmm_pdev_phys))
		should_free = false;
err_granule_delegate:
	if (should_free)
		free_page((unsigned long)rmm_pdev);
	return ret;
}
