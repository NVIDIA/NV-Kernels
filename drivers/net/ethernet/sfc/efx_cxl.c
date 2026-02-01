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
#include "efx_cxl.h"

#define EFX_CTPIO_BUFFER_SIZE	SZ_256M

int efx_cxl_init(struct efx_probe_data *probe_data)
{
	struct efx_nic *efx = &probe_data->efx;
	struct pci_dev *pci_dev = efx->pci_dev;
	resource_size_t max_size;
	struct efx_cxl *cxl;
	struct range range;
	u16 dvsec;
	int rc;

	probe_data->cxl_pio_initialised = false;

	/* Is the device configured with and using CXL? */
	if (!pcie_is_cxl(pci_dev))
		return 0;

	dvsec = pci_find_dvsec_capability(pci_dev, PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_DEVICE);
	if (!dvsec) {
		pci_err(pci_dev, "CXL_DVSEC_PCIE_DEVICE capability not found\n");
		return 0;
	}

	pci_dbg(pci_dev, "CXL_DVSEC_PCIE_DEVICE capability found\n");

	/* Create a cxl_dev_state embedded in the cxl struct using cxl core api
	 * specifying no mbox available.
	 */
	cxl = devm_cxl_dev_state_create(&pci_dev->dev, CXL_DEVTYPE_DEVMEM,
					pci_dev->dev.id, dvsec, struct efx_cxl,
					cxlds, false);

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

	rc = cxl_map_component_regs(&cxl->cxlds.reg_map,
				    &cxl->cxlds.regs.component,
				    BIT(CXL_CM_CAP_CAP_ID_RAS));
	if (rc) {
		pci_err(pci_dev, "Failed to map RAS capability.\n");
		return rc;
	}

	/*
	 * Set media ready explicitly as there are neither mailbox for checking
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
		pci_err(pci_dev, "CXL accel memdev creation failed");
		return PTR_ERR(cxl->cxlmd);
	}

	cxl->cxled = cxl_get_committed_decoder(cxl->cxlmd, &cxl->efx_region);
	if (cxl->cxled) {
		if (!cxl->efx_region) {
			pci_err(pci_dev, "CXL found committed decoder without a region");
			return -ENODEV;
		}
		rc = cxl_get_region_range(cxl->efx_region, &range);
		if (rc) {
			pci_err(pci_dev,
				"CXL getting regions params from a committed decoder failed");
			return rc;
		}

		cxl->ctpio_cxl = ioremap(range.start, range.end - range.start + 1);
		if (!cxl->ctpio_cxl) {
			pci_err(pci_dev, "CXL ioremap region (%pra) failed", &range);
			return -ENOMEM;
		}

		cxl->hdm_was_committed = true;
	} else {
		cxl->cxlrd = cxl_get_hpa_freespace(cxl->cxlmd, 1, CXL_DECODER_F_RAM |
						   CXL_DECODER_F_TYPE2, &max_size);
		if (IS_ERR(cxl->cxlrd)) {
			dev_err(&pci_dev->dev, "cxl_get_hpa_freespace failed\n");
			return PTR_ERR(cxl->cxlrd);
		}

		if (max_size < EFX_CTPIO_BUFFER_SIZE) {
			dev_err(&pci_dev->dev, "%s: not enough free HPA space %pap < %u\n",
				__func__, &max_size, EFX_CTPIO_BUFFER_SIZE);
			cxl_put_root_decoder(cxl->cxlrd);
			return -ENOSPC;
		}

		cxl->cxled = cxl_request_dpa(cxl->cxlmd, CXL_PARTMODE_RAM,
					     EFX_CTPIO_BUFFER_SIZE);
		if (IS_ERR(cxl->cxled)) {
			pci_err(pci_dev, "CXL accel request DPA failed");
			cxl_put_root_decoder(cxl->cxlrd);
			return PTR_ERR(cxl->cxled);
		}
	}

	probe_data->cxl = cxl;
	return 0;
}

void efx_cxl_exit(struct efx_probe_data *probe_data)
{
	if (!probe_data->cxl)
		return;

	if (probe_data->cxl->hdm_was_committed) {
		iounmap(probe_data->cxl->ctpio_cxl);
		cxl_unregister_region(probe_data->cxl->efx_region);
	} else {
		cxl_dpa_free(probe_data->cxl->cxled);
		cxl_put_root_decoder(probe_data->cxl->cxlrd);
	}
}

MODULE_IMPORT_NS("CXL");
