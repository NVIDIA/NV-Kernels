// SPDX-License-Identifier: GPL-2.0-only
/****************************************************************************
 *
 * Driver for AMD network controllers and boards
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */

#include <linux/pci.h>

#include <cxl/cxl.h>
#include <cxl/pci.h>
#include "net_driver.h"
#include "efx.h"
#include "efx_cxl.h"

#define EFX_CTPIO_BUFFER_SIZE	SZ_256M

/* Called with cxl endpoint device locked for precluding potential related
 * cxl region removal triggered from user space, allowing safely mapping of
 * such cxl region by the sfc driver.
 */
static int efx_cxl_map_region(void *data) {
	struct efx_probe_data *probe_data = data;
	struct efx_nic *efx = &probe_data->efx;
	struct pci_dev *pci_dev = efx->pci_dev;
	struct efx_cxl *cxl = probe_data->cxl;
	struct range *cxl_pio_range = &cxl->attach_region.region;

	cxl->ctpio_cxl = ioremap(cxl_pio_range->start,
				 cxl_pio_range->end - cxl_pio_range->start + 1);
	if (!cxl->ctpio_cxl) {
		pci_err(pci_dev, "CXL ioremap region (%pra) failed\n",
				 cxl_pio_range);
		return -ENOMEM;
	}
	probe_data->cxl_pio_initialised = true;
	return 0;
}

/* Called at driver exit or when user space triggers cxl region removal. */
static void efx_cxl_unmap_region(void *data) {
	struct efx_probe_data *probe_data = data;

	efx_ef10_disable_piobufs(&probe_data->efx);
	probe_data->cxl_pio_initialised = false;
	iounmap(probe_data->cxl->ctpio_cxl);
}

int efx_cxl_init(struct efx_probe_data *probe_data)
{
	struct efx_nic *efx = &probe_data->efx;
	struct pci_dev *pci_dev = efx->pci_dev;
	struct efx_cxl *cxl;
	u16 dvsec;
	int rc;

	probe_data->cxl_pio_initialised = false;

	/* Is the device configured with and using CXL? */
	if (!pcie_is_cxl(pci_dev))
		return 0;

	dvsec = pci_find_dvsec_capability(pci_dev, PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_DEVICE);
	if (!dvsec) {
		pci_info(pci_dev, "CXL_DVSEC_PCIE_DEVICE capability not found\n");
		return 0;
	}

	pci_dbg(pci_dev, "CXL_DVSEC_PCIE_DEVICE capability found\n");

	/* Create a cxl_dev_state embedded in the cxl struct using cxl core api
	 * specifying no mbox available.
	 */
	cxl = devm_cxl_dev_state_create(&pci_dev->dev, CXL_DEVTYPE_DEVMEM,
					pci_get_dsn(pci_dev), dvsec,
					struct efx_cxl, cxlds, false);

	if (!cxl)
		return -ENOMEM;

	rc = cxl_pci_setup_regs(pci_dev, CXL_REGLOC_RBI_COMPONENT,
				&cxl->cxlds.reg_map);
	if (rc) {
		pci_err(pci_dev, "No component registers\n");
		return rc;
	}

	if (!cxl->cxlds.reg_map.component_map.hdm_decoder.valid) {
		pci_err(pci_dev, "Expected HDM component register not found\n");
		return -ENODEV;
	}

	if (!cxl->cxlds.reg_map.component_map.ras.valid) {
		pci_err(pci_dev, "Expected RAS component register not found\n");
		return -ENODEV;
	}

	/* Set media ready explicitly as there are neither mailbox for checking
	 * this state nor the CXL register involved, both not mandatory for
	 * type2.
	 */
	cxl->cxlds.media_ready = true;

	if (cxl_set_capacity(&cxl->cxlds, EFX_CTPIO_BUFFER_SIZE)) {
		pci_err(pci_dev, "dpa capacity setup failed\n");
		return -ENODEV;
	}

	cxl->cxlmd = devm_cxl_add_memdev(&cxl->cxlds, NULL);
	if (IS_ERR(cxl->cxlmd)) {
		pci_err(pci_dev, "CXL accel memdev creation failed\n");
		return PTR_ERR(cxl->cxlmd);
	}

	cxl->attach_region.attach = efx_cxl_map_region;
	cxl->attach_region.detach = efx_cxl_unmap_region;
	cxl->attach_region.data = probe_data;
	probe_data->cxl = cxl;

	rc = cxl_memdev_attach_region(cxl->cxlmd, &cxl->attach_region);
	if (rc)
		return rc;

	return 0;
}

MODULE_IMPORT_NS("CXL");
