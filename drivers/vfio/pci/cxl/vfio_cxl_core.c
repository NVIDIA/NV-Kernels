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

u8 vfio_cxl_get_component_reg_bar(struct vfio_pci_core_device *vdev)
{
	return vdev->cxl->comp_reg_bar;
}

int vfio_cxl_get_region_info(struct vfio_pci_core_device *vdev,
			     struct vfio_region_info *info,
			     struct vfio_info_cap *caps)
{
	unsigned long minsz = offsetofend(struct vfio_region_info, offset);
	struct vfio_region_info_cap_sparse_mmap *sparse;
	struct vfio_pci_cxl_state *cxl = vdev->cxl;
	resource_size_t bar_len, comp_end;
	u32 nr_areas, cap_size;
	int ret;

	if (!cxl)
		return -ENOTTY;

	if (!info)
		return -ENOTTY;

	if (info->argsz < minsz)
		return -EINVAL;

	if (info->index != cxl->comp_reg_bar)
		return -ENOTTY;

	/*
	 * The device state is not fully initialised;
	 * fall through to the default BAR handler.
	 */
	if (!cxl->comp_reg_size)
		return -ENOTTY;

	bar_len  = pci_resource_len(vdev->pdev, info->index);
	comp_end = cxl->comp_reg_offset + cxl->comp_reg_size;

	/*
	 * A component block past the end of the BAR would walk subsequent
	 * readl()s off the ioremap window.  Reject that up front.
	 */
	if (comp_end > bar_len)
		return -EINVAL;

	/*
	 * If the component block covers the entire BAR there is nothing to
	 * mmap; return the BAR with read/write access only and let userspace
	 * use the COMP_REGS device region for register access.
	 */
	if (cxl->comp_reg_size == bar_len) {
		info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
		info->size   = bar_len;
		info->flags  = VFIO_REGION_INFO_FLAG_READ |
			       VFIO_REGION_INFO_FLAG_WRITE;
		return 0;
	}

	/*
	 * Preserve the existing vfio-pci bar_mmap_supported gate.  When the
	 * BAR is non-mappable for any reason (non-page-aligned resource, the
	 * non_mappable_bars policy, etc.), advertising a sparse-mmap cap and
	 * VFIO_REGION_INFO_FLAG_MMAP would let userspace try to mmap and get
	 * a stale -EINVAL from the mmap path.  Return the bare BAR descriptor
	 * instead and let userspace fall back to fd read/write.
	 */
	if (!vdev->bar_mmap_supported[info->index]) {
		info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
		info->size   = bar_len;
		info->flags  = VFIO_REGION_INFO_FLAG_READ |
			       VFIO_REGION_INFO_FLAG_WRITE;
		return 0;
	}

	/*
	 * Advertise the GPU/accelerator register windows as mmappable by
	 * carving the CXL component register block out of the BAR.  The
	 * number of sparse areas depends on where the block sits:
	 *
	 *  [A] comp block at BAR end  [gpu_regs | comp_regs]:
	 *    comp_reg_offset > 0  &&  comp_end == bar_len
	 *    = 1 area: [0, comp_reg_offset)
	 *
	 *  [B] comp block at BAR start [comp_regs | gpu_regs]:
	 *    comp_reg_offset == 0 &&  comp_end < bar_len
	 *    = 1 area: [comp_end, bar_len)
	 *
	 *  [C] comp block in middle    [gpu_regs | comp_regs | gpu_regs]:
	 *    comp_reg_offset > 0  &&  comp_end < bar_len
	 *    = 2 areas: [0, comp_reg_offset) and [comp_end, bar_len)
	 */
	if (cxl->comp_reg_offset > 0 && comp_end < bar_len)
		nr_areas = 2;
	else
		nr_areas = 1;

	cap_size = struct_size(sparse, areas, nr_areas);
	sparse = kzalloc(cap_size, GFP_KERNEL);
	if (!sparse)
		return -ENOMEM;

	sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
	sparse->header.version = 1;
	sparse->nr_areas = nr_areas;

	if (nr_areas == 2) {
		/* [C]: window before and after comp block */
		sparse->areas[0].offset = 0;
		sparse->areas[0].size   = cxl->comp_reg_offset;
		sparse->areas[1].offset = comp_end;
		sparse->areas[1].size   = bar_len - comp_end;
	} else if (cxl->comp_reg_offset == 0) {
		/* [B]: comp block at BAR start, window follows */
		sparse->areas[0].offset = comp_end;
		sparse->areas[0].size   = bar_len - comp_end;
	} else {
		/* [A]: comp block at BAR end, window precedes */
		sparse->areas[0].offset = 0;
		sparse->areas[0].size   = cxl->comp_reg_offset;
	}

	ret = vfio_info_add_capability(caps, &sparse->header, cap_size);
	kfree(sparse);
	if (ret)
		return ret;

	info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
	info->size   = bar_len;
	info->flags  = VFIO_REGION_INFO_FLAG_READ |
		       VFIO_REGION_INFO_FLAG_WRITE |
		       VFIO_REGION_INFO_FLAG_MMAP;

	return 0;
}

bool vfio_cxl_mmap_overlaps_comp_regs(struct vfio_pci_core_device *vdev,
				       u64 req_start, u64 req_len)
{
	struct vfio_pci_cxl_state *cxl = vdev->cxl;

	if (!cxl->comp_reg_size)
		return false;

	return req_start < cxl->comp_reg_offset + cxl->comp_reg_size &&
	       req_start + req_len > cxl->comp_reg_offset;
}

int vfio_cxl_get_info(struct vfio_pci_core_device *vdev,
		      struct vfio_info_cap *caps)
{
	struct vfio_pci_cxl_state *cxl = vdev->cxl;
	struct vfio_device_info_cap_cxl cxl_cap = {0};

	if (!cxl)
		return 0;

	/*
	 * Device is not fully initialised?
	 */
	if (WARN_ON(cxl->dpa_region_idx < 0 || cxl->comp_reg_region_idx < 0))
		return -ENODEV;

	/* Fill in from CXL device structure */
	cxl_cap.header.id = VFIO_DEVICE_INFO_CAP_CXL;
	cxl_cap.header.version = 1;
	/*
	 * COMP_REGS region starts at comp_reg_offset + CXL_CM_OFFSET within
	 * the BAR.  This is the byte offset of the CXL.mem register area (where
	 * the CXL Capability Array Header lives) within the component register
	 * block. Userspace derives hdm_decoder_offset and hdm_count from the
	 * COMP_REGS region itself (CXL Capability Array traversal + HDMC read).
	 */
	cxl_cap.hdm_regs_offset = cxl->comp_reg_offset + CXL_CM_OFFSET;
	cxl_cap.hdm_regs_bar_index = cxl->comp_reg_bar;

	if (cxl->precommitted)
		cxl_cap.flags |= VFIO_CXL_CAP_FIRMWARE_COMMITTED;
	if (cxl->cache_capable)
		cxl_cap.flags |= VFIO_CXL_CAP_CACHE_CAPABLE;

	/*
	 * Populate absolute VFIO region indices so userspace can query them
	 * directly with VFIO_DEVICE_GET_REGION_INFO.
	 */
	cxl_cap.dpa_region_index = VFIO_PCI_NUM_REGIONS + cxl->dpa_region_idx;
	cxl_cap.comp_regs_region_index =
		VFIO_PCI_NUM_REGIONS + cxl->comp_reg_region_idx;

	return vfio_info_add_capability(caps, &cxl_cap.header, sizeof(cxl_cap));
}

/*
 * Scope-based cleanup wrappers for the CXL resource APIs
 */
DEFINE_FREE(cxl_put_root_decoder, struct cxl_root_decoder *, if (!IS_ERR_OR_NULL(_T)) cxl_put_root_decoder(_T))
DEFINE_FREE(cxl_dpa_free, struct cxl_endpoint_decoder *, if (!IS_ERR_OR_NULL(_T)) cxl_dpa_free(_T))
DEFINE_FREE(cxl_unregister_region, struct cxl_region *, if (!IS_ERR_OR_NULL(_T)) cxl_unregister_region(_T))

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
	if (!FIELD_GET(CXL_DVSEC_CAP_MEM_CAPABLE, cap_word) ||
	    (pdev->class >> 8) == PCI_CLASS_MEMORY_CXL) {
		devm_kfree(&pdev->dev, cxl);
		return ERR_PTR(-ENODEV);
	}

	cxl->cache_capable = FIELD_GET(CXL_DVSEC_CAP_CACHE_CAPABLE, cap_word);
	cxl->dpa_region_idx = -1;
	cxl->comp_reg_region_idx = -1;

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

int vfio_cxl_create_cxl_region(struct vfio_pci_cxl_state *cxl,
			       resource_size_t size)
{
	resource_size_t max_size;

	struct cxl_root_decoder *cxlrd __free(cxl_put_root_decoder) =
		cxl_get_hpa_freespace(cxl->cxlmd, 1,
				      CXL_DECODER_F_RAM | CXL_DECODER_F_TYPE2,
				      &max_size);
	if (IS_ERR(cxlrd))
		return PTR_ERR(cxlrd);

	/* Insufficient HPA space; cxlrd freed automatically by __free() */
	if (max_size < size)
		return -ENOSPC;

	struct cxl_endpoint_decoder *cxled __free(cxl_dpa_free) =
		cxl_request_dpa(cxl->cxlmd, CXL_PARTMODE_RAM, size);
	if (IS_ERR(cxled))
		return PTR_ERR(cxled);

	struct cxl_region *region __free(cxl_unregister_region) =
		cxl_create_region(cxlrd, &cxled, 1);
	if (IS_ERR(region))
		return PTR_ERR(region);

	/* All operations succeeded; transfer ownership to cxl state */
	cxl->cxlrd  = no_free_ptr(cxlrd);
	cxl->cxled  = no_free_ptr(cxled);
	cxl->region = no_free_ptr(region);

	return 0;
}

void vfio_cxl_destroy_cxl_region(struct vfio_pci_cxl_state *cxl)
{
	if (!cxl->region)
		return;

	/*
	 * Precommitted regions are obtained via cxl_get_committed_decoder() as
	 * a borrowed reference owned by the cxl core; do not unregister or
	 * free the decoder objects from here.  Only vfio_cxl_create_cxl_region()
	 * owns the region and decoders.
	 */
	if (!cxl->precommitted) {
		cxl_unregister_region(cxl->region);
		cxl_dpa_free(cxl->cxled);
		cxl_put_root_decoder(cxl->cxlrd);
	}

	cxl->region = NULL;
	cxl->cxled = NULL;
	cxl->cxlrd = NULL;
}

static int vfio_cxl_create_region_helper(struct vfio_pci_core_device *vdev,
					 struct vfio_pci_cxl_state *cxl,
					 resource_size_t capacity)
{
	struct pci_dev *pdev = vdev->pdev;
	struct range range;
	int ret;

	if (cxl->precommitted) {
		struct cxl_endpoint_decoder *cxled;
		/*
		 * cxl_get_committed_decoder() does not write *region on every
		 * failure path (e.g. when cxlmd->endpoint is NULL or no decoder
		 * is committed).  Initialise to NULL so the !cxl->region check
		 * below catches it regardless of stack-init mode.
		 */
		struct cxl_region *region = NULL;

		cxled = cxl_get_committed_decoder(cxl->cxlmd, &region);
		if (IS_ERR(cxled))
			return PTR_ERR(cxled);
		cxl->cxled = cxled;
		cxl->region = region;
	} else {
		ret = vfio_cxl_create_cxl_region(cxl, capacity);
		if (ret)
			return ret;
	}

	if (!cxl->region) {
		pci_err(pdev, "Failed to create CXL region\n");
		ret = -ENODEV;
		goto failed;
	}

	ret = cxl_get_region_range(cxl->region, &range);
	if (ret)
		goto failed;

	cxl->region_hpa = range.start;
	cxl->region_size = range_len(&range);

	pci_dbg(pdev, "CXL region: HPA 0x%llx size %lu MB\n",
		cxl->region_hpa, cxl->region_size >> 20);

	return 0;

failed:
	vfio_cxl_destroy_cxl_region(cxl);

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

	cxl->precommitted = true;
	cxl->dpa_size = capacity;

	pci_dbg(pdev, "Device capacity: %llu MB\n", capacity >> 20);

	ret = vfio_cxl_create_memdev(cxl, capacity);
	if (ret) {
		pci_warn(pdev, "Failed to create memdev\n");
		goto regs_failed;
	}

	ret = vfio_cxl_create_region_helper(vdev, cxl, capacity);
	if (ret)
		goto regs_failed;

	/*
	 * Register probing succeeded.  Assign vdev->cxl now so that
	 * all subsequent helpers can access state via vdev->cxl.
	 * All failure paths below clear vdev->cxl before calling
	 * vfio_cxl_dev_state_free().  cxl->vdev is the back-pointer used
	 * by vm_fault and other helpers that only have the cxl state in hand.
	 */
	cxl->vdev = vdev;
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
	vfio_cxl_destroy_cxl_region(cxl);
}

static vm_fault_t vfio_cxl_region_vm_fault(struct vm_fault *vmf)
{
	struct vfio_pci_region *region = vmf->vma->vm_private_data;
	struct vfio_pci_cxl_state *cxl = region->data;
	struct vfio_pci_core_device *vdev = cxl->vdev;
	unsigned long pgoff;
	unsigned long pfn;
	vm_fault_t ret;

	/*
	 * Hold memory_lock read side across the region_active check and the
	 * vmf_insert_pfn so the reset path cannot run unmap_mapping_range
	 * between the two and leave a stale PTE pointing at the pre-reset HPA.
	 * vfio_cxl_prepare_reset holds the write side while it clears
	 * region_active and zaps existing PTEs.
	 */
	down_read(&vdev->memory_lock);

	if (!cxl->region_active) {
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	pgoff = vmf->pgoff &
		((1UL << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);

	if (pgoff >= (cxl->region_size >> PAGE_SHIFT)) {
		ret = VM_FAULT_SIGBUS;
		goto out;
	}

	pfn = PHYS_PFN(cxl->region_hpa) + pgoff;
	ret = vmf_insert_pfn(vmf->vma, vmf->address, pfn);

out:
	up_read(&vdev->memory_lock);
	return ret;
}

static const struct vm_operations_struct vfio_cxl_region_vm_ops = {
	.fault = vfio_cxl_region_vm_fault,
};

static int vfio_cxl_region_mmap(struct vfio_pci_core_device *vdev,
				struct vfio_pci_region *region,
				struct vm_area_struct *vma)
{
	struct vfio_pci_cxl_state *cxl = vdev->cxl;
	u64 req_len, pgoff, end;

	if (!(region->flags & VFIO_REGION_INFO_FLAG_MMAP))
		return -EINVAL;

	if (!(region->flags & VFIO_REGION_INFO_FLAG_READ) &&
	    (vma->vm_flags & VM_READ))
		return -EPERM;

	if (!(region->flags & VFIO_REGION_INFO_FLAG_WRITE) &&
	    (vma->vm_flags & VM_WRITE))
		return -EPERM;

	pgoff = vma->vm_pgoff &
		((1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);

	if (check_sub_overflow(vma->vm_end, vma->vm_start, &req_len) ||
	    check_add_overflow(PFN_PHYS(pgoff), req_len, &end))
		return -EOVERFLOW;

	if (end > cxl->region_size)
		return -EINVAL;

	vma->vm_page_prot = pgprot_decrypted(vma->vm_page_prot);

	vm_flags_set(vma, VM_ALLOW_ANY_UNCACHED | VM_IO | VM_PFNMAP |
		     VM_DONTEXPAND | VM_DONTDUMP);

	vma->vm_ops = &vfio_cxl_region_vm_ops;
	vma->vm_private_data = region;

	return 0;
}

/*
 * vfio_cxl_zap_region_locked - Invalidate all DPA region PTEs.
 *
 * Must be called with vdev->memory_lock held for writing.  Sets
 * region_active=false before zapping so any subsequent I/O to the region
 * sees the inactive state and returns an error rather than accessing
 * stale mappings.
 */
void vfio_cxl_zap_region_locked(struct vfio_pci_core_device *vdev)
{
	struct vfio_device *core_vdev = &vdev->vdev;
	struct vfio_pci_cxl_state *cxl = vdev->cxl;

	lockdep_assert_held_write(&vdev->memory_lock);

	if (!cxl || cxl->dpa_region_idx < 0)
		return;

	WRITE_ONCE(cxl->region_active, false);
	unmap_mapping_range(core_vdev->inode->i_mapping,
			    VFIO_PCI_INDEX_TO_OFFSET(VFIO_PCI_NUM_REGIONS +
						     cxl->dpa_region_idx),
			    cxl->region_size, true);
}

/*
 * vfio_cxl_reactivate_region - Re-enable DPA region after successful reset.
 *
 * Must be called with vdev->memory_lock held for writing.  Re-reads the
 * HDM decoder state from hardware (FLR cleared it) and sets region_active
 * so that subsequent I/O to the region is permitted again.
 */
void vfio_cxl_reactivate_region(struct vfio_pci_core_device *vdev)
{
	struct vfio_pci_cxl_state *cxl = vdev->cxl;

	lockdep_assert_held_write(&vdev->memory_lock);

	if (!cxl)
		return;
	/*
	 * Re-initialise the emulated HDM comp_reg_virt[] from hardware.
	 * After FLR the decoder registers read as zero; mirror that in
	 * the emulated state so QEMU sees a clean slate.
	 */
	vfio_cxl_reinit_comp_regs(cxl);

	/*
	 * Only re-enable the DPA mmap if the hardware has actually
	 * re-committed decoder 0 after FLR.  Read the COMMITTED bit from the
	 * freshly-re-snapshotted comp_reg_virt[] so we check the post-FLR
	 * hardware state, not stale pre-reset state.
	 *
	 * If COMMITTED is 0 (slow firmware re-commit path), leave
	 * region_active=false.	 Guest faults will return VM_FAULT_SIGBUS
	 * until the decoder is re-committed and the region is re-enabled.
	 */
	if (cxl->precommitted && cxl->comp_reg_virt) {
		/*
		 * Read CTRL via the full CXL.mem-relative index: hdm_reg_offset
		 * (now CXL.mem-relative) plus the within-HDM-block offset.
		 */
		u32 ctrl = le32_to_cpu(*hdm_reg_ptr(cxl,
					    CXL_HDM_DECODER0_CTRL_OFFSET(0)));

		if (ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED)
			WRITE_ONCE(cxl->region_active, true);
	}
}

static ssize_t vfio_cxl_region_rw(struct vfio_pci_core_device *core_dev,
				  char __user *buf, size_t count, loff_t *ppos,
				  bool iswrite)
{
	unsigned int i = VFIO_PCI_OFFSET_TO_INDEX(*ppos) - VFIO_PCI_NUM_REGIONS;
	struct vfio_pci_cxl_state *cxl = core_dev->region[i].data;
	loff_t pos = *ppos & VFIO_PCI_OFFSET_MASK;
	ssize_t ret;

	if (!count || pos >= cxl->region_size)
		return 0;

	/*
	 * Hold memory_lock read side across the region_active check and the
	 * user copy.  vfio_cxl_prepare_reset() holds the write side while it
	 * clears region_active and unmaps the inode range; without the read
	 * side here, the copy could still touch cxl->region_vaddr after the
	 * reset has begun.  Guard against access after a failed reset
	 * (region_active=false) or a release race (region_vaddr=NULL): either
	 * means the memremap'd window is no longer valid; touching it would
	 * produce a Synchronous External Abort.
	 */
	down_read(&core_dev->memory_lock);

	if (!cxl->region_active || !cxl->region_vaddr) {
		ret = -EIO;
		goto out;
	}

	count = min(count, (size_t)(cxl->region_size - pos));

	if (iswrite) {
		if (copy_from_user(cxl->region_vaddr + pos, buf, count)) {
			ret = -EFAULT;
			goto out;
		}
	} else {
		if (copy_to_user(buf, cxl->region_vaddr + pos, count)) {
			ret = -EFAULT;
			goto out;
		}
	}

	/*
	 * vfio_pci_rw() returns the region rw result verbatim and relies on
	 * the handler to advance *ppos.  Without this, successive read/write
	 * syscalls on the DPA region keep operating at the same offset
	 * instead of advancing.
	 */
	*ppos += count;
	ret = count;

out:
	up_read(&core_dev->memory_lock);
	return ret;
}

static void vfio_cxl_region_release(struct vfio_pci_core_device *vdev,
				    struct vfio_pci_region *region)
{
	struct vfio_device *core_vdev = &vdev->vdev;
	struct vfio_pci_cxl_state *cxl = region->data;

	/*
	 * Deactivate the region before removing user mappings so that any
	 * fault handler racing the release returns VM_FAULT_SIGBUS rather
	 * than inserting a PFN into an unmapped region.
	 */
	WRITE_ONCE(cxl->region_active, false);

	/*
	 * Remove all user mappings of the DPA region while the device is
	 * still alive.
	 */
	if (cxl->dpa_region_idx >= 0)
		unmap_mapping_range(core_vdev->inode->i_mapping,
			    VFIO_PCI_INDEX_TO_OFFSET(VFIO_PCI_NUM_REGIONS +
						     cxl->dpa_region_idx),
				    cxl->region_size, true);

	if (cxl->region_vaddr) {
		memunmap(cxl->region_vaddr);
		cxl->region_vaddr = NULL;
	}
}

static const struct vfio_pci_regops vfio_cxl_regops = {
	.rw		= vfio_cxl_region_rw,
	.mmap		= vfio_cxl_region_mmap,
	.release	= vfio_cxl_region_release,
};

int vfio_cxl_register_cxl_region(struct vfio_pci_core_device *vdev)
{
	struct vfio_pci_cxl_state *cxl = vdev->cxl;
	u32 flags;
	int ret;

	if (!cxl)
		return -ENODEV;

	if (!cxl->region || cxl->region_vaddr)
		return -ENODEV;

	/*
	 * CXL device memory is RAM, not MMIO.  Use memremap() rather than
	 * ioremap_cache() so the correct memory-mapping API is used.
	 * The WB attribute matches the cache-coherent nature of CXL.mem.
	 */
	cxl->region_vaddr = memremap(cxl->region_hpa, cxl->region_size,
				     MEMREMAP_WB);
	if (!cxl->region_vaddr)
		return -ENOMEM;

	/*
	 * BOS/backport policy: do not advertise DPA mmap until the CXL DPA
	 * backing is proven safe for userspace CPU mappings.  Keep fd
	 * read/write available via the memremap() kernel mapping.
	 */
	flags = VFIO_REGION_INFO_FLAG_READ |
		VFIO_REGION_INFO_FLAG_WRITE;

	ret = vfio_pci_core_register_dev_region(vdev,
						PCI_VENDOR_ID_CXL |
						VFIO_REGION_TYPE_PCI_VENDOR_TYPE,
						VFIO_REGION_SUBTYPE_CXL,
						&vfio_cxl_regops,
						cxl->region_size, flags,
						cxl);
	if (ret) {
		memunmap(cxl->region_vaddr);
		cxl->region_vaddr = NULL;
		return ret;
	}

	/*
	 * Cache the vdev->region[] index before activating the region.
	 * vfio_pci_core_register_dev_region() placed the new entry at
	 * vdev->region[num_regions - 1] and incremented num_regions.
	 * vfio_cxl_zap_region_locked() uses this to avoid scanning
	 * vdev->region[] on every FLR.
	 */
	cxl->dpa_region_idx = vdev->num_regions - 1;

	vfio_cxl_reinit_comp_regs(cxl);

	/*
	 * Only activate the DPA region when the HDM decoder is currently
	 * committed.  vfio_pci_core_enable() runs pci_try_reset_function()
	 * before regions are registered; that FLR clears the decoder
	 * COMMITTED bit and firmware may not have re-committed it yet.
	 * Mirror vfio_cxl_finish_reset(): if COMMITTED is not set here, the
	 * region stays inactive and guest DPA access returns
	 * VM_FAULT_SIGBUS / -EIO until a subsequent reset re-runs
	 * finish_reset with the decoder committed.
	 */
	if (cxl->precommitted && cxl->comp_reg_virt) {
		u32 ctrl = le32_to_cpu(*hdm_reg_ptr(cxl,
					    CXL_HDM_DECODER0_CTRL_OFFSET(0)));

		if (ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED)
			WRITE_ONCE(cxl->region_active, true);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(vfio_cxl_register_cxl_region);

/**
 * vfio_cxl_unregister_cxl_region - Undo vfio_cxl_register_cxl_region()
 * @vdev: VFIO PCI device
 *
 * Marks the DPA region inactive and resets dpa_region_idx.
 * Does NOT touch CXL subsystem state (cxl->region, cxl->cxled, cxl->cxlrd).
 * The caller must call vfio_cxl_destroy_cxl_region() separately to release
 * those objects.
 */
void vfio_cxl_unregister_cxl_region(struct vfio_pci_core_device *vdev)
{
	struct vfio_pci_cxl_state *cxl = vdev->cxl;

	if (!cxl || cxl->dpa_region_idx < 0)
		return;

	WRITE_ONCE(cxl->region_active, false);

	cxl->dpa_region_idx = -1;
}
EXPORT_SYMBOL_GPL(vfio_cxl_unregister_cxl_region);

MODULE_IMPORT_NS("CXL");
