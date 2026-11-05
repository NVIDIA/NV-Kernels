// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 NVIDIA Corporation & Affiliates */
/*
 * CXL reset support in the PCI core. Cache the HDM decoder state of a CXL
 * memory device at enumeration, so it can be restored after a reset without
 * a CXL driver. HDM register formats and programming live in drivers/cxl.
 */
#include <linux/bitfield.h>
#include <linux/cleanup.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include <cxl/hdm.h>
#include <cxl/pci.h>

#include "pci.h"

/* Find the CXL Device DVSEC and read its capability register. */
static int cxl_pci_device_dvsec(struct pci_dev *pdev, u16 *dvsec, u16 *cap)
{
	int rc;

	*dvsec = pci_find_dvsec_capability(pdev, PCI_VENDOR_ID_CXL,
					   PCI_DVSEC_CXL_DEVICE);
	if (!*dvsec)
		return -ENOTTY;

	rc = pci_read_config_word(pdev, *dvsec + PCI_DVSEC_CXL_CAP, cap);
	if (rc)
		return pcibios_err_to_errno(rc);
	if (PCI_POSSIBLE_ERROR(*cap))
		return -ENODEV;

	return 0;
}

static bool cxl_pci_bar_assigned(struct pci_dev *pdev, int bar)
{
	struct resource *res = &pdev->resource[bar];

	return pci_resource_len(pdev, bar) &&
	       !(res->flags & (IORESOURCE_UNSET | IORESOURCE_DISABLED)) &&
	       resource_type(res) == IORESOURCE_MEM && res->start && res->end;
}

static void __iomem *cxl_pci_hdm_map_regs(struct pci_dev *pdev,
					  struct cxl_register_map *map,
					  resource_size_t *hdm_offset,
					  int *decoder_count)
{
	struct cxl_reg_map *hdm_map = &map->component_map.hdm_decoder;
	void __iomem *hdm;
	int rc;

	/* cxl_setup_regs() populates hdm_map, including its valid bit. */
	rc = cxl_setup_regs(map);
	if (rc)
		return ERR_PTR(rc);
	if (!hdm_map->valid)
		return ERR_PTR(-ENODEV);
	if (hdm_map->offset > map->max_size ||
	    hdm_map->size > map->max_size - hdm_map->offset)
		return ERR_PTR(-ENXIO);
	if (check_add_overflow(map->bar_offset,
			       (resource_size_t)hdm_map->offset, hdm_offset))
		return ERR_PTR(-EOVERFLOW);

	hdm = ioremap(map->resource + hdm_map->offset, hdm_map->size);
	if (!hdm)
		return ERR_PTR(-ENOMEM);

	*decoder_count = cxl_hdm_decoder_count_mapped(&pdev->dev, hdm,
						      hdm_map->size);
	if (*decoder_count < 0) {
		iounmap(hdm);
		return ERR_PTR(*decoder_count);
	}

	return hdm;
}

static struct cxl_hdm_info *__cxl_pci_hdm_read_info(struct pci_dev *pdev,
						    struct cxl_register_map *map,
						    int dvsec)
{
	struct cxl_reg_map *hdm_map = &map->component_map.hdm_decoder;
	struct cxl_hdm_info *info;
	resource_size_t hdm_offset;
	void __iomem *hdm;
	int decoder_count;
	u16 dvsec_ctrl;
	int rc;

	hdm = cxl_pci_hdm_map_regs(pdev, map, &hdm_offset, &decoder_count);
	if (IS_ERR(hdm))
		return ERR_CAST(hdm);

	rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CTRL,
				  &dvsec_ctrl);
	if (rc) {
		rc = pcibios_err_to_errno(rc);
		goto out_unmap;
	}

	info = kzalloc_flex(*info, settings, decoder_count, GFP_KERNEL);
	if (!info) {
		rc = -ENOMEM;
		goto out_unmap;
	}

	info->decoder_count = decoder_count;
	info->hdm_bar = map->bar;
	info->hdm_offset = hdm_offset;
	info->hdm_size = hdm_map->size;
	info->dvsec = dvsec;
	info->dvsec_ctrl = dvsec_ctrl;
	info->dvsec_ctrl_valid = true;

	rc = cxl_hdm_read_state(&pdev->dev, hdm, info);
	if (rc)
		goto out_free;

	iounmap(hdm);
	return info;

out_free:
	kfree(info);
out_unmap:
	iounmap(hdm);
	return ERR_PTR(rc);
}

static struct cxl_hdm_info *cxl_pci_hdm_read_info(struct pci_dev *pdev,
						  struct cxl_register_map *map,
						  int dvsec)
{
	struct cxl_hdm_info *info;
	u16 command;
	int rc;

	rc = pci_read_config_word(pdev, PCI_COMMAND, &command);
	if (rc)
		return ERR_PTR(pcibios_err_to_errno(rc));

	if (!(command & PCI_COMMAND_MEMORY)) {
		rc = pci_write_config_word(pdev, PCI_COMMAND,
					   command | PCI_COMMAND_MEMORY);
		if (rc)
			return ERR_PTR(pcibios_err_to_errno(rc));
	}

	info = __cxl_pci_hdm_read_info(pdev, map, dvsec);
	if (!(command & PCI_COMMAND_MEMORY)) {
		rc = pci_write_config_word(pdev, PCI_COMMAND, command);
		if (rc)
			pci_err(pdev,
				"failed to restore PCI_COMMAND after CXL HDM cache init: %d\n",
				pcibios_err_to_errno(rc));
	}
	return info;
}

static int __pci_cxl_hdm_cache_init(struct pci_dev *pdev)
{
	struct cxl_register_map map = { };
	struct cxl_hdm_info *read_info;
	u16 dvsec, cap;
	int rc;

	guard(pci_dev)(pdev);

	/* Avoid duplicate MMIO reads when the cache is already present. */
	if (pdev->hdm)
		return 0;

	rc = cxl_pci_device_dvsec(pdev, &dvsec, &cap);
	if (rc == -ENOTTY)
		return 0;
	if (rc)
		return rc;
	if (!(cap & PCI_DVSEC_CXL_CACHE_CAPABLE) ||
	    !(cap & PCI_DVSEC_CXL_MEM_CAPABLE) ||
	    !(cap & PCI_DVSEC_CXL_RST_CAPABLE) ||
	    !(cap & PCI_DVSEC_CXL_RST_MEM_CLR_CAPABLE) ||
	    !cxl_dvsec_hdm_count_valid(FIELD_GET(PCI_DVSEC_CXL_HDM_COUNT, cap)))
		return 0;

	rc = cxl_find_regblock(pdev, CXL_REGLOC_RBI_COMPONENT, &map);
	if (rc)
		return rc;
	if (map.bar < 0 || map.bar >= PCI_STD_NUM_BARS ||
	    !cxl_pci_bar_assigned(pdev, map.bar))
		return -ENODEV;

	read_info = cxl_pci_hdm_read_info(pdev, &map, dvsec);
	if (IS_ERR(read_info))
		return PTR_ERR(read_info);

	/*
	 * The PCI device lock held since the cache check excludes other
	 * initializers. CXL drivers bind only after enumeration, so no cache
	 * mutator can run yet and cxl_rwsem.dpa is not needed to publish.
	 */
	pdev->hdm = read_info;

	return 0;
}

void pci_cxl_hdm_cache_init(struct pci_dev *pdev)
{
	int rc;

	rc = __pci_cxl_hdm_cache_init(pdev);
	if (rc)
		pci_dbg(pdev, "CXL HDM cache init failed: %d\n", rc);
}

void pci_cxl_hdm_cache_release(struct pci_dev *pdev)
{
	cxl_hdm_cache_release(&pdev->hdm);
}
