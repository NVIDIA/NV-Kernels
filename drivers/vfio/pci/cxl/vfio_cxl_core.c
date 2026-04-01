// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO CXL Core - CXL.mem passthrough for vendor-specific CXL devices
 *
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 *
 * This module extends vfio-pci-core to pass through CXL.mem regions for
 * vendor-specific CXL devices (CXL_DEVTYPE_DEVMEM) that implement HDM-D or
 * HDM-DB decoders but do not report the standard CXL memory expander class
 * code (PCI_CLASS_MEMORY_CXL, 0x0502).  This covers both CXL Type-2
 * accelerators (with CXL.cache) and non-class-code Type-3 variants (e.g.
 * compressed memory devices) which cannot be paravirtualized by the host
 * CXL subsystem and require direct DPA region access from the guest.
 */

#include <linux/vfio_pci_core.h>
#include <linux/pci.h>
#include <cxl/cxl.h>
#include <cxl/pci.h>

#include "../vfio_pci_priv.h"
#include "vfio_cxl_priv.h"

/*
 * vfio_cxl_create_device_state - Allocate and validate CXL device state
 *
 * Returns a pointer to the allocated vfio_pci_cxl_state on success, or
 * ERR_PTR on failure.  The allocation uses devm; the caller must call
 * devm_kfree(&pdev->dev, cxl) on any subsequent setup failure to release
 * the resource before device unbind.  Using devm_kfree() to undo a devm
 * allocation early is explicitly supported by the devres API.
 *
 * The caller assigns vdev->cxl only after all setup steps succeed, preventing
 * partially-initialised state from being visible through vdev->cxl on any
 * failure path.
 */
static struct vfio_pci_cxl_state *
vfio_cxl_create_device_state(struct pci_dev *pdev, u16 dvsec)
{
	struct vfio_pci_cxl_state *cxl;
	u16 cap_word;
	u32 hdr1;

	/*
	 * Freed automatically when pdev->dev is released.  Use the PCI Device
	 * Serial Number capability for cxlds->serial; pdev->dev.id is the
	 * generic-device sibling counter (typically 0) and surfaces as a bogus
	 * serial in sysfs and CXL tracepoints.
	 */
	cxl = devm_cxl_dev_state_create(&pdev->dev,
					CXL_DEVTYPE_DEVMEM,
					pci_get_dsn(pdev), dvsec,
					struct vfio_pci_cxl_state,
					cxlds, false);
	if (!cxl)
		return ERR_PTR(-ENOMEM);

	pci_read_config_dword(pdev, dvsec + PCI_DVSEC_HEADER1, &hdr1);
	cxl->dvsec_len = PCI_DVSEC_HEADER1_LEN(hdr1);

	pci_read_config_word(pdev, dvsec + CXL_DVSEC_CAPABILITY_OFFSET,
			     &cap_word);

	/*
	 * Only handle vendor devices (class != 0x0502) with Mem_Capable set.
	 * CACHE_CAPABLE is forwarded to the VMM so it knows whether a WBI
	 * sequence is needed before FLR.
	 */
	if (!FIELD_GET(CXL_DVSEC_MEM_CAPABLE, cap_word) ||
	    (pdev->class >> 8) == PCI_CLASS_MEMORY_CXL) {
		devm_kfree(&pdev->dev, cxl);
		return ERR_PTR(-ENODEV);
	}

	cxl->cache_capable = FIELD_GET(CXL_DVSEC_CACHE_CAPABLE, cap_word);

	return cxl;
}

static int vfio_cxl_setup_regs(struct vfio_pci_core_device *vdev,
			       struct vfio_pci_cxl_state *cxl)
{
	struct cxl_register_map *map = &cxl->cxlds.reg_map;
	resource_size_t offset, bar_offset, size;
	struct pci_dev *pdev = vdev->pdev;
	void __iomem *base;
	int ret;
	u8 count;
	u8 bar;

	if (WARN_ON_ONCE(!pci_is_enabled(pdev)))
		return -EINVAL;

	/* Find component register block via Register Locator DVSEC */
	ret = cxl_find_regblock(pdev, CXL_REGLOC_RBI_COMPONENT, map);
	if (ret)
		return ret;

	/*
	 * Request the region and map.  This is a transient mapping
	 * used only to probe register capabilities; released immediately
	 * after cxl_probe_component_regs() returns.
	 */
	if (!request_mem_region(map->resource, map->max_size, "vfio-cxl-probe"))
		return -EBUSY;

	base = ioremap(map->resource, map->max_size);
	if (!base) {
		ret = -ENOMEM;
		goto failed_release;
	}

	/* Probe component register capabilities */
	cxl_probe_component_regs(&pdev->dev, base, &map->component_map);

	/* Check if HDM decoder was found */
	if (!map->component_map.hdm_decoder.valid) {
		ret = -ENODEV;
		goto failed_unmap;
	}

	pci_dbg(pdev, "vfio_cxl: HDM decoder at offset=0x%lx, size=0x%lx\n",
		map->component_map.hdm_decoder.offset,
		map->component_map.hdm_decoder.size);

	/* Get HDM register info */
	ret = cxl_get_hdm_info(&cxl->cxlds, &count, &offset, &size);
	if (ret)
		goto failed_unmap;

	if (!count || !size) {
		ret = -ENODEV;
		goto failed_unmap;
	}

	cxl->hdm_count = count;
	/*
	 * cxl_get_hdm_info() returns rmap->offset = CXL_CM_OFFSET + <hdm_within_cm>
	 * (see cxl_probe_component_regs() which does base += CXL_CM_OFFSET before
	 * reading caps and stores CXL_CM_OFFSET + cap_ptr as the offset).
	 * Subtract CXL_CM_OFFSET so hdm_reg_offset is relative to the CXL.mem
	 * register area start, which is where comp_reg_virt[0] is anchored.
	 * The physical BAR address for hdm_iobase is recovered by adding
	 * CXL_CM_OFFSET back in vfio_cxl_setup_virt_regs().
	 */
	cxl->hdm_reg_offset = offset - CXL_CM_OFFSET;
	cxl->hdm_reg_size = size;

	ret = cxl_regblock_get_bar_info(map, &bar, &bar_offset);
	if (ret)
		goto failed_unmap;

	cxl->comp_reg_bar = bar;
	cxl->comp_reg_offset = bar_offset;
	cxl->comp_reg_size = CXL_COMPONENT_REG_BLOCK_SIZE;

	ret = vfio_cxl_setup_virt_regs(vdev, cxl, base, map->max_size);
	iounmap(base);
	release_mem_region(map->resource, map->max_size);
	if (ret)
		return ret;

	return 0;

failed_unmap:
	iounmap(base);
failed_release:
	release_mem_region(map->resource, map->max_size);

	return ret;
}

static int vfio_cxl_create_memdev(struct vfio_pci_cxl_state *cxl,
				  resource_size_t capacity)
{
	int ret;

	ret = cxl_set_capacity(&cxl->cxlds, capacity);
	if (ret)
		return ret;

	cxl->cxlmd = devm_cxl_add_memdev(&cxl->cxlds, NULL);
	if (IS_ERR(cxl->cxlmd))
		return PTR_ERR(cxl->cxlmd);

	return 0;
}

/*
 * Free CXL state early on probe failure.  devm_kfree() on a live devres
 * allocation removes it from the list immediately, so the normal devres
 * teardown at unbind time won't double-free it.
 */
static void vfio_cxl_dev_state_free(struct pci_dev *pdev,
				    struct vfio_pci_cxl_state *cxl)
{
	devm_kfree(&pdev->dev, cxl);
}

/**
 * vfio_pci_cxl_detect_and_init - Detect and initialize a vendor-specific
 *                                CXL.mem device
 * @vdev: VFIO PCI device
 *
 * Called from vfio_pci_core_register_device(). Detects CXL DVSEC capability
 * and initializes CXL features. On failure vdev->cxl remains NULL and the
 * device operates as a standard PCI device.
 */
void vfio_pci_cxl_detect_and_init(struct vfio_pci_core_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	struct vfio_pci_cxl_state *cxl;
	resource_size_t capacity = 0;
	u16 dvsec;
	int ret;

	if (!pcie_is_cxl(pdev))
		return;

	dvsec = pci_find_dvsec_capability(pdev,
					  PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_DEVICE);
	if (!dvsec)
		return;

	/*
	 * CXL DVSEC found: any failure from here is a hard probe error on
	 * a confirmed CXL-capable device, not a silent non-CXL fallback.
	 * Warn the operator so misconfiguration is visible.
	 */
	cxl = vfio_cxl_create_device_state(pdev, dvsec);
	if (IS_ERR(cxl)) {
		if (PTR_ERR(cxl) != -ENODEV)
			pci_warn(pdev,
				 "vfio-cxl: CXL device state allocation failed: %ld\n",
				 PTR_ERR(cxl));
		return;
	}

	/*
	 * Required for ioremap of the component register block and
	 * calls to cxl_probe_component_regs().
	 */
	ret = pci_enable_device_mem(pdev);
	if (ret) {
		pci_warn(pdev,
			 "vfio-cxl: pci_enable_device_mem failed: %d\n", ret);
		goto free_cxl;
	}

	ret = vfio_cxl_setup_regs(vdev, cxl);
	if (ret) {
		pci_warn(pdev,
			 "vfio-cxl: HDM register probing failed: %d\n", ret);
		pci_disable_device(pdev);
		goto free_cxl;
	}

	cxl->cxlds.media_ready = !cxl_await_range_active(&cxl->cxlds);
	if (!cxl->cxlds.media_ready) {
		pci_warn(pdev, "CXL media not ready\n");
		pci_disable_device(pdev);
		goto regs_failed;
	}

	/*
	 * Take the single authoritative HDM decoder snapshot now that
	 * MEM_ACTIVE is confirmed and BAR memory is still enabled.  Using
	 * readl() per-dword ensures correct MMIO serialisation and captures
	 * the final firmware-written values for all fields including SIZE_HIGH,
	 * which firmware commits to the BAR at MEM_ACTIVE time.
	 */
	vfio_cxl_reinit_comp_regs(cxl);

	pci_disable_device(pdev);

	capacity = vfio_cxl_read_committed_decoder_size(vdev, cxl);
	if (capacity == 0) {
		/*
		 * TODO: Add handling for devices which do not have
		 * firmware pre-committed decoders
		 */
		pci_info(pdev, "Uncommitted region size must be configured via sysfs before bind\n");
		goto regs_failed;
	}

	cxl->dpa_size = capacity;

	pci_dbg(pdev, "Device capacity: %llu MB\n", capacity >> 20);

	ret = vfio_cxl_create_memdev(cxl, capacity);
	if (ret) {
		pci_warn(pdev, "Failed to create memdev\n");
		goto regs_failed;
	}

	/*
	 * Register probing succeeded.  Assign vdev->cxl now so that
	 * all subsequent helpers can access state via vdev->cxl.
	 * All failure paths below clear vdev->cxl before calling
	 * vfio_cxl_dev_state_free().
	 */
	vdev->cxl = cxl;

	return;

regs_failed:
	vfio_cxl_clean_virt_regs(cxl);

free_cxl:
	vfio_cxl_dev_state_free(pdev, cxl);
}

void vfio_pci_cxl_cleanup(struct vfio_pci_core_device *vdev)
{
	struct vfio_pci_cxl_state *cxl = vdev->cxl;

	if (!cxl)
		return;

	vfio_cxl_clean_virt_regs(cxl);
}

MODULE_IMPORT_NS("CXL");
