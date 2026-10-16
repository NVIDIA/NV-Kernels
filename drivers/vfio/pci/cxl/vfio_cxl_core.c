// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO support for CXL Type-2 devices.
 *
 * Copyright (c) 2026 NVIDIA Corporation & Affiliates
 */

#include <linux/bitfield.h>
#include <linux/cleanup.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/memory-failure.h>
#include <linux/memregion.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci-p2pdma.h>
#include <linux/range.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vfio_pci_core.h>
#include <cxl/cxl.h>
#include <cxl/cxl_regs.h>
#include <cxl/hdm.h>
#include <cxl/pci.h>

/**
 * struct vfio_cxl_state - per-device state for a vfio-cxl device
 * @cxlds: CXL device state; kept first for devm_cxl_dev_state_create()
 * @cxlmd: memory device joined to the CXL topology at bind
 * @hpa_range: host physical range of the HDM region
 * @hpa_res: exclusive reservation of @hpa_range, held for the bind
 * @hdm: copy of the HDM state cached at PCI enumeration, taken at bind
 * @hdm_pfn_space: HDM-region pfn range registered with memory_failure()
 * @hdm_regs: mapped HDM decoder registers, read live by the decoder region
 * @hdm_len: length of the HDM decoder register block
 * @hdm_valid: true when host CPU access to the HDM range is safe; under memory_lock
 * @await_mem_active: the device reports Mem_HwInit_Mode, so wait for
 *	Memory_Active before host access reopens after a reset or low power
 * @mem_region_index: vfio region index of the HDM memory region while open, else 0
 * @hdm_open_at_prepare: @hdm_valid as reset_prepare found it; under memory_lock
 * @hdm_revoked_early: the raw-bus-reset path already revoked, so reset_prepare
 *	must not revoke again and lose @hdm_open_at_prepare. Cleared when that
 *	reset does not reach reset_done, and whenever HDM is rearmed
 * @hdm_flushed_early: reset_flush() wrote the range back while it stayed
 *	revoked, so reset_prepare does not write it back again. Cleared with
 *	@hdm_revoked_early
 * @hdm_needs_reset: a CXL Reset failed, so only a CXL Reset that succeeds
 *	reopens host access; under memory_lock
 */
struct vfio_cxl_state {
	struct cxl_dev_state cxlds;
	struct cxl_memdev *cxlmd;
	struct range hpa_range;
	struct resource *hpa_res;
	struct cxl_hdm_info *hdm;
	struct pfn_address_space hdm_pfn_space;
	void __iomem *hdm_regs;
	u32 hdm_len;
	bool hdm_valid;
	bool await_mem_active;
	unsigned int mem_region_index;
	bool hdm_open_at_prepare;
	bool hdm_revoked_early;
	bool hdm_flushed_early;
	bool hdm_needs_reset;
};

/* The next reset must revoke and write back the range for itself. */
static void vfio_cxl_forget_early_prepare(struct vfio_cxl_state *cxl)
{
	cxl->hdm_revoked_early = false;
	cxl->hdm_flushed_early = false;
}

static unsigned long vfio_cxl_mem_pgoff(struct vm_area_struct *vma,
					unsigned long addr)
{
	unsigned long mask = (1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1;

	return (vma->vm_pgoff & mask) + ((addr - vma->vm_start) >> PAGE_SHIFT);
}

static vm_fault_t vfio_cxl_mem_huge_fault(struct vm_fault *vmf,
					  unsigned int order)
{
	struct vm_area_struct *vma = vmf->vma;
	struct vfio_pci_core_device *vdev = vma->vm_private_data;
	struct vfio_cxl_state *cxl = vdev->cxl;
	unsigned long addr = ALIGN_DOWN(vmf->address, PAGE_SIZE << order);
	unsigned long pfn = PHYS_PFN(cxl->hpa_range.start) +
			    vfio_cxl_mem_pgoff(vma, addr);
	vm_fault_t ret = VM_FAULT_FALLBACK;

	if (is_aligned_for_order(vma, addr, pfn, order)) {
		scoped_guard(rwsem_read, &vdev->memory_lock) {
			/*
			 * Insert a PFN only for a known-good decoder whose
			 * media is ready. CXL.mem decode follows the committed
			 * decoder and Mem_Enable, not Memory Space Enable (CXL
			 * r4.0 sec 8.2.4.20.2, 8.1.3.2), so skip the BAR memory
			 * enable check; low power closes hdm_valid through
			 * power_down.
			 */
			if (cxl->hdm_valid && cxl->cxlds.media_ready)
				ret = __vfio_pci_vmf_insert_pfn(vdev, vmf, pfn,
								order);
			else
				ret = VM_FAULT_SIGBUS;
		}
	}

	return ret;
}

static vm_fault_t vfio_cxl_mem_fault(struct vm_fault *vmf)
{
	return vfio_cxl_mem_huge_fault(vmf, 0);
}

static const struct vm_operations_struct vfio_cxl_mem_vm_ops = {
	.fault = vfio_cxl_mem_fault,
#ifdef CONFIG_ARCH_SUPPORTS_HUGE_PFNMAP
	.huge_fault = vfio_cxl_mem_huge_fault,
#endif
};

static int vfio_cxl_mem_mmap(struct vfio_pci_core_device *vdev,
			     struct vfio_pci_region *region,
			     struct vm_area_struct *vma)
{
	unsigned long mask = (1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1;
	u64 req_start = (vma->vm_pgoff & mask) << PAGE_SHIFT;
	u64 req_len = vma->vm_end - vma->vm_start;

	if (req_start + req_len > region->size)
		return -EINVAL;

	/*
	 * CXL.mem is coherent memory, so leave the mapping write-back cacheable.
	 */
	vm_flags_set(vma, VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_ops = &vfio_cxl_mem_vm_ops;
	vma->vm_private_data = vdev;

	return 0;
}

/*
 * Copy one chunk between the bounce buffer and the HDM range under
 * memory_lock. The user copy stays outside the lock: a user buffer that is
 * itself an mmap of this device faults through a handler that takes
 * memory_lock for read, and a writer queued in between would deadlock the
 * two readers.
 */
static int vfio_cxl_mem_copy(struct vfio_pci_core_device *vdev, void *bounce,
			     u64 pos, size_t len, bool iswrite)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	void *mem;

	guard(rwsem_read)(&vdev->memory_lock);

	/*
	 * Only touch the HDM range with the decoder in a known-good state, or
	 * a host CPU access aborts as a fatal SError. CXL.mem decode follows
	 * the committed decoder and Mem_Enable, not Memory Space Enable (CXL
	 * r4.0 sec 8.2.4.20.2, 8.1.3.2).
	 */
	if (!cxl->hdm_valid || !cxl->cxlds.media_ready)
		return -EIO;

	mem = memremap(cxl->hpa_range.start + pos, len, MEMREMAP_WB);
	if (!mem)
		return -ENOMEM;
	if (iswrite)
		memcpy(mem, bounce, len);
	else
		memcpy(bounce, mem, len);
	memunmap(mem);

	return 0;
}

static ssize_t vfio_cxl_mem_rw(struct vfio_pci_core_device *vdev,
			       char __user *buf, size_t count, loff_t *ppos,
			       bool iswrite)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	ssize_t done = 0;
	void *bounce;
	int ret = 0;

	if (pos >= range_len(&cxl->hpa_range))
		return -EINVAL;
	count = min_t(u64, count, range_len(&cxl->hpa_range) - pos);

	bounce = kmalloc(min_t(size_t, count, PAGE_SIZE), GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;

	while (count) {
		size_t len = min_t(size_t, count, PAGE_SIZE);

		if (iswrite && copy_from_user(bounce, buf + done, len)) {
			ret = -EFAULT;
			break;
		}
		ret = vfio_cxl_mem_copy(vdev, bounce, pos + done, len, iswrite);
		if (ret)
			break;
		if (!iswrite && copy_to_user(buf + done, bounce, len)) {
			ret = -EFAULT;
			break;
		}
		done += len;
		count -= len;
	}
	kfree(bounce);

	if (!done)
		return ret;

	*ppos += done;
	return done;
}

/*
 * The HDM region follows hdm_valid, not Memory Space Enable, so a dma-buf
 * exported from it starts revoked while host access is unsafe and is
 * re-armed with the region in vfio_cxl_rearm_hdm().
 */
static bool vfio_cxl_mem_revoked(struct vfio_pci_core_device *vdev,
				 struct vfio_pci_region *region)
{
	struct vfio_cxl_state *cxl = vdev->cxl;

	lockdep_assert_held_write(&vdev->memory_lock);

	return !cxl->hdm_valid || !cxl->cxlds.media_ready;
}

/*
 * The CXL regions carry no per-region state (region->data is the shared,
 * devm-managed vfio_cxl_state), so releasing a region is a no-op.
 */
static void vfio_cxl_region_release(struct vfio_pci_core_device *vdev,
				    struct vfio_pci_region *region)
{
}

static const struct vfio_pci_regops vfio_cxl_mem_regops = {
	.rw = vfio_cxl_mem_rw,
	.mmap = vfio_cxl_mem_mmap,
	.release = vfio_cxl_region_release,
	.revoked = vfio_cxl_mem_revoked,
};

static ssize_t vfio_cxl_comp_rw(struct vfio_pci_core_device *vdev,
				char __user *buf, size_t count, loff_t *ppos,
				bool iswrite)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	loff_t pos = *ppos & VFIO_PCI_OFFSET_MASK;
	__le32 *tmp;

	if (pos >= cxl->hdm_len)
		return -EINVAL;

	/*
	 * Component registers allow only full-width accesses: a 32-bit
	 * register as one 4-byte read or write (CXL r4.0 sec 8.2.3).
	 */
	if (pos % sizeof(u32) || count % sizeof(u32))
		return -EINVAL;

	count = min_t(size_t, count, cxl->hdm_len - pos);

	/*
	 * The physical decoder was committed before the guest saw the device
	 * (firmware may also have locked it), so the guest never drives it:
	 * absorb writes without forwarding them to hardware. The guest programs
	 * a GPA that the VMM virtualizes; reads return the live registers, which
	 * already report the decoder committed. BASE_LOW and BASE_HIGH carry the
	 * host HPA, visible only to the trusted VMM that virtualizes it away from
	 * the guest.
	 */
	if (iswrite) {
		*ppos += count;
		return count;
	}

	tmp = kmalloc(count, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	/* The block is BAR MMIO, so it decodes only with memory enabled. */
	scoped_guard(rwsem_read, &vdev->memory_lock) {
		if (!__vfio_pci_memory_enabled(vdev)) {
			kfree(tmp);
			return -EIO;
		}
		/*
		 * One readl() per register: memcpy_fromio() may split the
		 * copy into byte or qword reads, and the decoder registers
		 * take only aligned dword accesses. Return them in the
		 * register byte order, as a raw copy would.
		 */
		for (size_t i = 0; i < count / sizeof(u32); i++)
			tmp[i] = cpu_to_le32(readl(cxl->hdm_regs + pos +
						   i * sizeof(u32)));
	}

	if (copy_to_user(buf, tmp, count)) {
		kfree(tmp);
		return -EFAULT;
	}
	kfree(tmp);

	*ppos += count;
	return count;
}

static int vfio_cxl_comp_add_capability(struct vfio_pci_core_device *vdev,
					struct vfio_pci_region *region,
					struct vfio_info_cap *caps)
{
	struct cxl_hdm_info *hdm = vdev->cxl->hdm;
	struct vfio_region_info_cap_cxl_comp_regs cap = {
		.header.id = VFIO_REGION_INFO_CAP_CXL_COMP_REGS,
		.header.version = 1,
		.bar = hdm->hdm_bar,
		.offset = hdm->hdm_offset,
	};

	return vfio_info_add_capability(caps, &cap.header, sizeof(cap));
}

static const struct vfio_pci_regops vfio_cxl_comp_regops = {
	.rw = vfio_cxl_comp_rw,
	.release = vfio_cxl_region_release,
	.add_capability = vfio_cxl_comp_add_capability,
};

/*
 * Map a poisoned HDM-region pfn back to the file offset of each user mapping so
 * memory_failure() can find the mapping and signal its owner. The region is a
 * single linear range at hpa_range.start; recover the per-vma file offset the
 * same way the fault handler derived the pfn.
 */
static int vfio_cxl_pfn_to_vma_pgoff(struct vm_area_struct *vma,
				     unsigned long pfn, pgoff_t *pgoff)
{
	struct vfio_pci_core_device *vdev;
	struct vfio_cxl_state *cxl;
	pgoff_t vma_off, pfn_off;
	unsigned long start_pfn;

	if (vma->vm_ops != &vfio_cxl_mem_vm_ops)
		return -ENOENT;

	vdev = vma->vm_private_data;
	cxl = vdev->cxl;

	start_pfn = PHYS_PFN(cxl->hpa_range.start);
	if (pfn < start_pfn ||
	    pfn >= start_pfn + (range_len(&cxl->hpa_range) >> PAGE_SHIFT))
		return -EFAULT;

	pfn_off = pfn - start_pfn;
	vma_off = vma->vm_pgoff &
		  ((1UL << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	/* Skip VMAs that do not map the pfn, e.g. a partial mmap of the region. */
	if (pfn_off < vma_off || pfn_off - vma_off >= vma_pages(vma))
		return -EFAULT;

	*pgoff = vma->vm_pgoff + (pfn_off - vma_off);
	return 0;
}

/*
 * The HDM region is struct-page-less device memory, so a memory error on it
 * cannot be routed through the normal page path. Register the range with
 * memory_failure() so such an error is contained to a SIGBUS to each process
 * that maps the poisoned page, instead of escalating to a host SError. The
 * mapping itself is not torn down.
 */
static int vfio_cxl_register_pfn_space(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	unsigned long start_pfn = PHYS_PFN(cxl->hpa_range.start);

	cxl->hdm_pfn_space.node.start = start_pfn;
	cxl->hdm_pfn_space.node.last =
		start_pfn + (range_len(&cxl->hpa_range) >> PAGE_SHIFT) - 1;
	cxl->hdm_pfn_space.mapping = vdev->vdev.inode->i_mapping;
	cxl->hdm_pfn_space.pfn_to_vma_pgoff = vfio_cxl_pfn_to_vma_pgoff;

	return register_pfn_address_space(&cxl->hdm_pfn_space);
}

/*
 * Create the CXL device state and join the device to the CXL topology. The
 * caller groups these devres allocations, so return on the first error.
 */
static struct vfio_cxl_state *
vfio_cxl_create_memdev(struct pci_dev *pdev, const struct cxl_hdm_info *hdm,
		       u64 hdm_size)
{
	struct vfio_cxl_state *cxl;
	struct cxl_memdev *cxlmd;
	u64 serial;
	u16 dvsec;
	int ret;

	dvsec = pci_find_dvsec_capability(pdev, PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_DEVICE);
	serial = pci_get_dsn(pdev);

	cxl = devm_cxl_dev_state_create(&pdev->dev, CXL_DEVTYPE_DEVMEM, serial,
					dvsec, struct vfio_cxl_state, cxlds,
					false);
	if (!cxl)
		return ERR_PTR(-ENOMEM);

	ret = cxl_pci_setup_regs(pdev, CXL_REGLOC_RBI_COMPONENT,
				 &cxl->cxlds.reg_map);
	if (ret) {
		pci_err(pdev, "vfio-cxl: no component registers\n");
		return ERR_PTR(ret);
	}

	/*
	 * vfio-pci-core requests the whole component-register BAR when the
	 * guest opens the device. Declare that BAR owned so the CXL core
	 * ioremaps the HDM and RAS sub-blocks without claiming them, and the
	 * full-BAR request does not collide.
	 */
	ret = cxl_reg_map_set_owned_resource(&cxl->cxlds.reg_map,
					     pci_resource_n(pdev, hdm->hdm_bar));
	if (ret)
		return ERR_PTR(ret);

	if (!cxl->cxlds.reg_map.component_map.hdm_decoder.valid) {
		pci_err(pdev, "vfio-cxl: HDM decoder registers not found\n");
		return ERR_PTR(-ENODEV);
	}

	/*
	 * Map the HDM decoder registers so the decoder region can read them
	 * live. The block location comes from the enumeration cache in
	 * pdev->hdm, read through the copy in hdm; vfio-pci owns the BAR, so map
	 * without claiming the block.
	 */
	cxl->hdm_regs = devm_ioremap(&pdev->dev,
				     pci_resource_start(pdev, hdm->hdm_bar) +
				     hdm->hdm_offset, hdm->hdm_size);
	if (!cxl->hdm_regs)
		return ERR_PTR(-ENOMEM);

	cxl->hdm_len = hdm->hdm_size;

	/*
	 * A Type-2 accelerator has no mailbox and no media-ready register, so
	 * set media ready directly.
	 */
	cxl->cxlds.media_ready = true;

	ret = cxl_set_capacity(&cxl->cxlds, hdm_size);
	if (ret)
		return ERR_PTR(ret);

	cxlmd = devm_cxl_probe_mem(&cxl->cxlds, &cxl->hpa_range);
	if (IS_ERR(cxlmd))
		return ERR_CAST(cxlmd);

	cxl->cxlmd = cxlmd;
	return cxl;
}

/*
 * Resolve the physical range that backs a dma-buf export. The core exporter
 * only knows BARs; teach it the HDM memory region so a guest IOAS can map the
 * coherent window by fd (IOMMU_IOAS_MAP_FILE) instead of the removed PFNMAP
 * work-around. Real BARs stay on the byte-identical core path.
 */
static int vfio_cxl_get_dmabuf_phys(struct vfio_pci_core_device *vdev,
				    struct p2pdma_provider **provider,
				    unsigned int region_index,
				    struct phys_vec *phys_vec,
				    struct vfio_region_dma_range *dma_ranges,
				    size_t nr_ranges)
{
	struct vfio_cxl_state *cxl = vdev->cxl;

	/* Real BARs go through the core P2P exporter unchanged. */
	if (region_index < VFIO_PCI_NUM_REGIONS)
		return vfio_pci_core_get_dmabuf_phys(vdev, provider,
						     region_index, phys_vec,
						     dma_ranges, nr_ranges);

	/* Of the device regions, only the HDM memory window is exportable. */
	if (region_index != cxl->mem_region_index)
		return -EINVAL;

	/*
	 * The HDM window is coherent host memory, not BAR MMIO, so it has no
	 * p2pdma provider of its own. Borrow BAR 0's: the P2P properties match
	 * and the iommufd importer does not consume the provider. The sgt map
	 * path (real peer DMA) is not supported for the HDM window.
	 */
	*provider = pcim_p2pdma_provider(vdev->pdev, 0);
	if (!*provider)
		return -EINVAL;

	return vfio_pci_core_fill_phys_vec(phys_vec, dma_ranges, nr_ranges,
					  cxl->hpa_range.start,
					  range_len(&cxl->hpa_range));
}

static const struct vfio_pci_device_ops vfio_cxl_pci_dev_ops = {
	.get_dmabuf_phys = vfio_cxl_get_dmabuf_phys,
};

/* CXL r4.0 sec 8.1.3.8.2: Range 1 Size Low Memory_Active_Timeout encodings */
static const unsigned int vfio_cxl_mem_active_timeout_s[] = { 1, 4, 16, 64, 256 };

/*
 * Poll Memory_Active in DVSEC CXL Range 1 Size Low (CXL r4.0 sec 8.1.3.8.2)
 * for up to the Memory_Active_Timeout the device reports, which is stored in
 * @timeout. Return 0 once it is set, -ETIMEDOUT, or -ENODEV if config space
 * does not respond.
 */
static int vfio_cxl_poll_mem_active(struct pci_dev *pdev, u16 dvsec,
				    unsigned int *timeout)
{
	int pos = dvsec + PCI_DVSEC_CXL_RANGE_SIZE_LOW(0);
	unsigned long deadline;
	u32 size_lo;

	if (pci_read_config_dword(pdev, pos, &size_lo) ||
	    PCI_POSSIBLE_ERROR(size_lo))
		return -ENODEV;

	*timeout = FIELD_GET(PCI_DVSEC_CXL_MEM_ACTIVE_TIMEOUT, size_lo);
	*timeout = vfio_cxl_mem_active_timeout_s[min_t(unsigned int, *timeout,
				ARRAY_SIZE(vfio_cxl_mem_active_timeout_s) - 1)];
	deadline = jiffies + secs_to_jiffies(*timeout);

	while (!(size_lo & PCI_DVSEC_CXL_MEM_ACTIVE)) {
		if (time_after(jiffies, deadline))
			return -ETIMEDOUT;
		msleep(20);
		if (pci_read_config_dword(pdev, pos, &size_lo) ||
		    PCI_POSSIBLE_ERROR(size_lo))
			return -ENODEV;
	}

	return 0;
}

/*
 * A reset or a return from low power leaves device memory unavailable until
 * the device sets Memory_Active. That can take seconds after the reset
 * completes and the decoder is restored, and a host access to the HDM range
 * before then can abort. Wait for it only on a device that reported
 * Mem_HwInit_Mode at bind; a device whose driver brings memory up never sets
 * Memory_Active on its own, so waiting would always time out.
 */
static int vfio_cxl_await_mem_active(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	unsigned int timeout = 0;
	int ret;

	if (!cxl->await_mem_active)
		return 0;

	ret = vfio_cxl_poll_mem_active(vdev->pdev, cxl->hdm->dvsec, &timeout);
	if (ret == -ETIMEDOUT)
		pci_err(vdev->pdev, "vfio-cxl: device memory not active after %us\n",
			timeout);
	return ret;
}

static int vfio_cxl_init_device(struct vfio_pci_core_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	struct cxl_hdm_info *hdm __free(kfree) = NULL;
	struct vfio_cxl_state *cxl;
	unsigned int timeout = 0;
	u64 hdm_size;
	u16 cap;
	int ret;

	/*
	 * pdev->hdm is cached at PCI enumeration, before any driver binds, so a
	 * device without it has no usable HDM decoder. Continue without CXL
	 * support rather than defer the bind forever. The cache belongs to the
	 * CXL core, so work from a copy. Probe may run in a worker on the
	 * device's NUMA node that does not own the device lock, so take the
	 * copy that needs none.
	 */
	hdm = pci_cxl_hdm_snapshot(pdev);
	if (IS_ERR(hdm))
		return PTR_ERR(hdm);
	if (!hdm)
		return -ENODEV;

	/* The guest drives one virtual decoder; multiple are unsupported. */
	if (hdm->decoder_count != 1)
		return -EOPNOTSUPP;

	/* An interleaved decoder cannot be mapped 1:1 to the guest. */
	if (hdm->settings[0].config.interleave_ways != 1)
		return -EOPNOTSUPP;

	/*
	 * The guest drives resets through the CXL Device DVSEC and polls the
	 * shadow for completion. If the host cannot service a function-scoped
	 * CXL reset, that request could never complete, so refuse the device
	 * rather than advertise a reset the guest would poll on forever. The
	 * check includes the CPU cache invalidation that the reset needs.
	 */
	if (!pci_cxl_reset_capable(pdev))
		return -EOPNOTSUPP;

	hdm_size = range_len(&hdm->settings[0].config.hpa_range);
	if (!hdm_size)
		return -ENXIO;

	/*
	 * Group the CXL-core allocations so a failure unwinds them here. A
	 * failed init leaves the device bound without CXL support, so devm
	 * would otherwise hold them until unbind.
	 */
	if (!devres_open_group(&pdev->dev, NULL, GFP_KERNEL))
		return -ENOMEM;

	cxl = vfio_cxl_create_memdev(pdev, hdm, hdm_size);
	if (IS_ERR(cxl)) {
		devres_release_group(&pdev->dev, NULL);
		return PTR_ERR(cxl);
	}

	/*
	 * Only a device that brings its memory up in hardware ever sets
	 * Memory_Active on its own, so only it is worth waiting for after a
	 * reset or low-power exit; see vfio_cxl_await_mem_active(). Read
	 * Mem_HwInit_Mode rather than inferring it from a poll: a poll cannot
	 * tell a slow hardware-init device or a dead config space apart from a
	 * driver-initialised one, and it stalls bind for the full
	 * Memory_Active_Timeout on every driver-initialised device.
	 */
	ret = pci_read_config_word(pdev, hdm->dvsec + PCI_DVSEC_CXL_CAP, &cap);
	if (ret || PCI_POSSIBLE_ERROR(cap)) {
		pci_err(pdev, "vfio-cxl: failed to read CXL DVSEC capability\n");
		devres_release_group(&pdev->dev, NULL);
		return ret ?: -ENODEV;
	}
	cxl->await_mem_active = cap & PCI_DVSEC_CXL_MEM_HWINIT_MODE;

	/*
	 * Memory_Active reads clear for seconds after a reset, including one
	 * the host ran just before this bind, so give a hardware-init device
	 * its Memory_Active_Timeout here. A device that never reports active
	 * keeps the HDM gate closed rather than handing the guest memory that
	 * is not there.
	 */
	if (cxl->await_mem_active) {
		ret = vfio_cxl_poll_mem_active(pdev, hdm->dvsec, &timeout);
		if (ret) {
			pci_err(pdev, "vfio-cxl: device memory not active after %us: %d\n",
				timeout, ret);
			devres_release_group(&pdev->dev, NULL);
			return ret;
		}
	}

	/*
	 * Claim the range IORESOURCE_EXCLUSIVE so no conflicting cacheable
	 * alias can fault the host once it is mapped write-back. Release it
	 * explicitly in vfio_cxl_release_device() rather than through a devm
	 * action on pdev->dev: the provider module ref is dropped as soon as
	 * that .release op returns, so a pdev-devres callback could run after
	 * vfio-cxl has unloaded and jump into freed module text.
	 */
	cxl->hpa_res = request_mem_region_exclusive(cxl->hpa_range.start,
						    range_len(&cxl->hpa_range),
						    "vfio-cxl-hdm");
	if (!cxl->hpa_res) {
		devres_release_group(&pdev->dev, NULL);
		return -EBUSY;
	}
	devres_close_group(&pdev->dev, NULL);

	cxl->hdm = no_free_ptr(hdm);
	/*
	 * The decoder decodes a non-empty range, so it is committed, and host
	 * access to the HDM range is safe. Reset, bus reset and low power
	 * close this gate until the decoder is restored.
	 */
	cxl->hdm_valid = true;
	vdev->cxl = cxl;

	return 0;
}

static void vfio_cxl_release_device(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;

	/*
	 * Drop the exclusive HDM range claim before vfio_pci_core_cxl_release()
	 * drops the provider module ref; see vfio_cxl_init_device().
	 */
	release_mem_region(cxl->hpa_range.start, range_len(&cxl->hpa_range));
	kfree(cxl->hdm);
	vdev->cxl = NULL;
}

static int vfio_cxl_add_region(struct vfio_pci_core_device *vdev, u32 subtype,
			       const struct vfio_pci_regops *ops, size_t size,
			       u32 flags)
{
	u32 type = VFIO_REGION_TYPE_PCI_VENDOR_TYPE | PCI_VENDOR_ID_CXL;

	return vfio_pci_core_register_dev_region(vdev, type, subtype, ops,
						 size, flags, vdev->cxl);
}

static int vfio_cxl_open_device(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	int ret;

	/*
	 * A bus reset the provider refused on the close path leaves this set,
	 * with no reset_done to clear it. Start the new user from a known
	 * state so the next reset records its own open state.
	 */
	vfio_cxl_forget_early_prepare(cxl);

	/*
	 * Keep the HDM decoder block out of the guest's direct BAR access: the
	 * guest reaches it only through the trapped decoder region, and a write
	 * through the BAR could uncommit or move an unlocked decoder that the
	 * host relies on. Exclude it from mmap, fill reads with -1 and drop
	 * writes. The list is cleared on close, so re-add it per open.
	 */
	ret = vfio_pci_core_add_excluded_range(vdev, cxl->hdm->hdm_bar,
					       cxl->hdm->hdm_offset,
					       cxl->hdm_len,
					       VFIO_PCI_EXCLUDE_MMAP |
					       VFIO_PCI_EXCLUDE_READ |
					       VFIO_PCI_EXCLUDE_WRITE);
	if (ret)
		return ret;

	/*
	 * vfio-pci-core frees all dynamic regions on close and on a failed
	 * open, so register them here per open rather than at bind.
	 */
	ret = vfio_cxl_add_region(vdev, VFIO_REGION_SUBTYPE_CXL_MEM,
				  &vfio_cxl_mem_regops,
				  range_len(&cxl->hpa_range),
				  VFIO_REGION_INFO_FLAG_READ |
				  VFIO_REGION_INFO_FLAG_WRITE |
				  VFIO_REGION_INFO_FLAG_MMAP);
	if (ret)
		return ret;

	/*
	 * Record where the HDM memory region landed, to revoke it and to
	 * resolve its dma-buf export.
	 */
	cxl->mem_region_index = VFIO_PCI_NUM_REGIONS + vdev->num_regions - 1;

	/*
	 * Override the device ops so a dma-buf export of the HDM memory region
	 * resolves to the coherent host range. This is done at open, not init:
	 * vfio_pci_probe() resets pci_ops after vfio_alloc_device() returns, so
	 * an override installed during init would be clobbered. Only a CXL device
	 * reaches this hook (cxl_ops is set on init success), so a device bound
	 * without CXL support keeps the core ops.
	 */
	vdev->pci_ops = &vfio_cxl_pci_dev_ops;

	ret = vfio_cxl_add_region(vdev, VFIO_REGION_SUBTYPE_CXL_COMP_REGS,
				  &vfio_cxl_comp_regops, cxl->hdm_len,
				  VFIO_REGION_INFO_FLAG_READ |
				  VFIO_REGION_INFO_FLAG_WRITE);
	if (ret)
		goto err_index;

	/*
	 * The HDM region is advertised mmap-able, so a fd holder can fault its
	 * struct-page-less device memory in from the host CPU. Register it with
	 * memory_failure() to contain a memory error. -EOPNOTSUPP means
	 * CONFIG_MEMORY_FAILURE is off, so run without containment.
	 */
	ret = vfio_cxl_register_pfn_space(vdev);
	if (ret && ret != -EOPNOTSUPP)
		goto err_index;

	return 0;

err_index:
	/*
	 * A failed open never reaches close_device, and vfio-pci-core frees
	 * the regions: forget the index, or a later revoke of the HDM gate
	 * (runtime suspend of the closed device) names a region that is gone.
	 */
	cxl->mem_region_index = 0;
	return ret;
}

static void vfio_cxl_close_device(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;

	unregister_pfn_address_space(&cxl->hdm_pfn_space);
	/* vfio-pci-core frees the regions after this returns. */
	cxl->mem_region_index = 0;
}

/*
 * Take the HDM memory region out of use: zap its mmaps and revoke its
 * dma-bufs. A fault then gets SIGBUS from vfio_cxl_mem_huge_fault() until
 * hdm_valid is set again.
 */
static void vfio_cxl_revoke_hdm(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;

	lockdep_assert_held_write(&vdev->memory_lock);

	cxl->hdm_valid = false;
	if (cxl->mem_region_index)
		vfio_pci_core_revoke_region(vdev, cxl->mem_region_index);
}

static void vfio_cxl_rearm_hdm(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;

	lockdep_assert_held_write(&vdev->memory_lock);

	/*
	 * HDM is open again, so the early-prepare record is stale: the range
	 * can be dirtied once more and the next reset has to take its own
	 * snapshot of the open state.
	 */
	vfio_cxl_forget_early_prepare(cxl);
	cxl->hdm_valid = true;
	if (cxl->mem_region_index)
		vfio_pci_core_rearm_region(vdev, cxl->mem_region_index);
}

/*
 * A CXL Reset or decoder restore that fails leaves Memory Space and Bus
 * Master disabled (cxl_reset_save_disabled_state()). The user reads Command
 * from the device, but vfio-pci-core gates BAR access, BAR mmap faults, BAR
 * dma-bufs and the decoder register region on its own record of Memory
 * Space. Match that record to the device, zapping the BAR mmaps and
 * revoking the BAR dma-bufs as a user clear would; the user's next Memory
 * Space write sets it again.
 */
static void vfio_cxl_sync_mem_enable(struct vfio_pci_core_device *vdev)
{
	u16 cmd;

	lockdep_assert_held_write(&vdev->memory_lock);

	if (!pci_read_config_word(vdev->pdev, PCI_COMMAND, &cmd) &&
	    !PCI_POSSIBLE_ERROR(cmd) && (cmd & PCI_COMMAND_MEMORY))
		return;

	vfio_pci_core_clear_memory_enable(vdev);
}

/*
 * cxl_reset refuses a device whose CXL DVSEC Control has Cache_Enable or
 * Mem_Enable clear (-ENOTTY). A CXL Reset that failed after the device reset
 * may leave Control at its reset value, so every later reset would refuse and
 * host access would never reopen. Put back the Control value taken at bind,
 * when pci_cxl_reset_capable() required both enables, before the reset.
 */
static void vfio_cxl_restore_dvsec_ctrl(struct vfio_pci_core_device *vdev)
{
	const u16 enables = PCI_DVSEC_CXL_CACHE_ENABLE | PCI_DVSEC_CXL_MEM_ENABLE;
	const struct cxl_hdm_info *hdm = vdev->cxl->hdm;
	struct pci_dev *pdev = vdev->pdev;
	u16 ctrl;

	if (!hdm->dvsec_ctrl_valid || (hdm->dvsec_ctrl & enables) != enables)
		return;

	if (pci_read_config_word(pdev, hdm->dvsec + PCI_DVSEC_CXL_CTRL, &ctrl) ||
	    PCI_POSSIBLE_ERROR(ctrl) || (ctrl & enables) == enables)
		return;

	pci_warn(pdev, "vfio-cxl: restoring CXL DVSEC control %#06x (was %#06x)\n",
		 hdm->dvsec_ctrl, ctrl);
	pci_write_config_word(pdev, hdm->dvsec + PCI_DVSEC_CXL_CTRL,
			      hdm->dvsec_ctrl);
}

/*
 * Run CXL Reset in place of a PCI function reset. An FLR leaves CXL.mem
 * state and HDM contents intact (CXL r4.0 sec 9.5), so the vfio reset points
 * route here. The reset clears or randomizes volatile device memory and
 * restores the HDM decoder. The caller holds memory_lock and the PCI device
 * lock. vfio-cxl holds the HDM range, so the PCI core's cxl_reset method
 * would fail to request it; run the same CXL Reset with that claim.
 */
static int vfio_cxl_reset(struct vfio_pci_core_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	int ret;

	/*
	 * This reset supersedes any raw-reset bookkeeping: it drives its own
	 * revoke, and on failure nothing rearms to clear the record.
	 */
	vfio_cxl_forget_early_prepare(vdev->cxl);

	/* Host CPU access to the HDM range is unsafe until the decoder is back. */
	vfio_cxl_revoke_hdm(vdev);

	/* Only after a failure: see vfio_cxl_restore_dvsec_ctrl(). */
	if (vdev->cxl->hdm_needs_reset)
		vfio_cxl_restore_dvsec_ctrl(vdev);

	/*
	 * The reset restores PCI state from the saved copy. The caller provides
	 * it: the try-reset helper saves the current state, and the close path
	 * keeps the open-time state that vfio_pci_core_disable() loaded.
	 */
	ret = pci_cxl_reset_owned(pdev, vdev->cxl->hpa_res);
	if (!ret)
		ret = vfio_cxl_await_mem_active(vdev);
	if (ret) {
		/*
		 * Device memory may hold data the reset was meant to clear. Only
		 * a later CXL Reset that succeeds reopens host access; a decoder
		 * restore alone does not.
		 */
		vdev->cxl->hdm_needs_reset = true;
		vfio_cxl_sync_mem_enable(vdev);
		return ret;
	}

	vdev->cxl->hdm_needs_reset = false;
	vfio_cxl_rearm_hdm(vdev);

	return 0;
}

/*
 * Report whether the device still decodes its HDM range: memory decode on,
 * CXL.mem enabled in the CXL Device DVSEC and the decoder committed. A
 * secondary bus reset or a link down clears all three. Config space is read
 * first; the decoder registers sit in a BAR and are read only while memory
 * decode is on.
 */
static bool vfio_cxl_hdm_intact(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	struct pci_dev *pdev = vdev->pdev;
	u16 cmd, ctrl;
	u32 dctrl;

	if (pci_read_config_word(pdev, PCI_COMMAND, &cmd) ||
	    PCI_POSSIBLE_ERROR(cmd) || !(cmd & PCI_COMMAND_MEMORY))
		return false;

	if (pci_read_config_word(pdev, cxl->hdm->dvsec + PCI_DVSEC_CXL_CTRL,
				 &ctrl) ||
	    PCI_POSSIBLE_ERROR(ctrl) || !(ctrl & PCI_DVSEC_CXL_MEM_ENABLE))
		return false;

	dctrl = readl(cxl->hdm_regs + CXL_HDM_DECODER0_CTRL_OFFSET(0));
	return dctrl != U32_MAX && (dctrl & CXL_HDM_DECODER0_CTRL_COMMITTED);
}

/* Low power loses the committed decoder: close host access until restored. */
static void vfio_cxl_power_down(struct vfio_pci_core_device *vdev)
{
	vfio_cxl_revoke_hdm(vdev);
}

static void vfio_cxl_power_up(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	struct pci_dev *pdev = vdev->pdev;
	int ret;

	lockdep_assert_held_write(&vdev->memory_lock);

	/* After a failed CXL Reset, only a CXL Reset reopens host access. */
	if (cxl->hdm_needs_reset)
		return;

	/*
	 * A D3 request that failed, or a quirk that kept the device in D0,
	 * lost nothing: reopen without decommitting and recommitting.
	 */
	if (vfio_cxl_hdm_intact(vdev)) {
		if (!vfio_cxl_await_mem_active(vdev))
			vfio_cxl_rearm_hdm(vdev);
		return;
	}

	/*
	 * Restore the decoder that low power lost. The restore needs the device
	 * lock; if it is contended, keep host access closed until a reset
	 * restores the decoder. The restore refreshes the decoders in cxl->hdm
	 * from the cache; global and DVSEC control stay as taken at bind, when
	 * pci_cxl_reset_capable() required HDM decode and Mem_Enable on.
	 */
	if (!pci_dev_trylock(pdev))
		return;

	ret = pci_save_state(pdev);
	if (!ret)
		ret = cxl_recover_state_after_pci_reset(pdev, cxl->hdm);
	pci_dev_unlock(pdev);

	if (ret) {
		pci_warn(pdev, "vfio-cxl: HDM decoder restore failed: %d\n", ret);
		vfio_cxl_sync_mem_enable(vdev);
	} else if (!vfio_cxl_await_mem_active(vdev)) {
		vfio_cxl_rearm_hdm(vdev);
	}
}

/*
 * A secondary bus reset only reaches a CXL endpoint when the upstream port
 * has SBR unmasked (CXL r4.0 sec 8.1.5.2); otherwise the Bridge Control SBR
 * bit is ignored and the decoder is left intact. Mirrors the cxl_sbr_masked()
 * check the PCI core uses for its own CXL bus reset.
 */
static bool vfio_cxl_sbr_unmasked(struct pci_dev *pdev)
{
	struct pci_dev *bridge = pci_upstream_bridge(pdev);
	u16 dvsec, ctl;

	if (!bridge)
		return false;

	dvsec = pci_find_dvsec_capability(bridge, PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_PORT);
	if (!dvsec)
		return false;

	if (pci_read_config_word(bridge, dvsec + PCI_DVSEC_CXL_PORT_CTL, &ctl))
		return false;

	return ctl & PCI_DVSEC_CXL_PORT_CTL_UNMASK_SBR;
}

/*
 * VFIO_DEVICE_PCI_HOT_RESET and the close-path bus reset drive a raw secondary
 * bus reset: it skips the CXL reset method and the invalidation that goes with
 * it, so on a port with SBR unmasked the decoder disappears with dirty HDM
 * lines still in the CPU caches. Revoke the region and write it back here,
 * while the reset can still be refused. vfio_pci_zap_bars() does not reach the
 * HDM region, which is device-specific, so revoking first is what stops a
 * mapping the guest still holds from dirtying the range again after the flush.
 *
 * cpu_cache_invalidate_memregion() reports -ENXIO when no cache-maintenance
 * provider is registered, under the same lock as the invalidation, so a
 * provider that unbinds concurrently cannot leave a silent no-op behind.
 */
static int vfio_cxl_reset_flush(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	struct pci_dev *pdev = vdev->pdev;
	int ret;

	lockdep_assert_held_write(&vdev->memory_lock);

	if (!vfio_cxl_sbr_unmasked(pdev))
		return 0;

	/*
	 * An attempt that another device in the set refused already revoked
	 * this one, so keep the open state recorded then.
	 */
	if (!cxl->hdm_revoked_early) {
		cxl->hdm_open_at_prepare = cxl->hdm_valid;
		vfio_cxl_revoke_hdm(vdev);
		cxl->hdm_revoked_early = true;
	}
	ret = cpu_cache_invalidate_memregion(cxl->hpa_range.start,
					     range_len(&cxl->hpa_range));
	if (ret) {
		pci_err(pdev, "vfio-cxl: cache maintenance failed, refusing bus reset: %d\n",
			ret);
		return ret;
	}

	/*
	 * Still revoked, so nothing can dirty the range until abort or
	 * rearm. reset_prepare() skips its own write-back while this holds.
	 */
	cxl->hdm_flushed_early = true;
	return 0;
}

/*
 * reset_done did not run, so the decoder never moved. Put the HDM gate back
 * where this attempt found it. Re-arm the HDM dma-bufs when the gate was
 * open: the core re-arms only BAR dma-bufs, and only while memory space is
 * enabled, and this region follows hdm_valid instead. A call after
 * reset_done finds the record already clear and does nothing.
 */
static void vfio_cxl_reset_flush_abort(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;

	lockdep_assert_held_write(&vdev->memory_lock);

	if (!cxl->hdm_revoked_early)
		return;

	if (cxl->hdm_open_at_prepare)
		vfio_cxl_rearm_hdm(vdev);
	else
		vfio_cxl_forget_early_prepare(cxl);
}

/* A PCI core reset may clear the decoder: take the HDM region out of use. */
static void vfio_cxl_reset_prepare(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	struct pci_dev *pdev = vdev->pdev;
	int ret;

	/* The raw-bus-reset path may have revoked already; keep its record. */
	if (!cxl->hdm_revoked_early) {
		cxl->hdm_open_at_prepare = cxl->hdm_valid;
		vfio_cxl_revoke_hdm(vdev);
	}

	/*
	 * reset_subordinate, the bus method, AER and DPC never called
	 * reset_flush(). A VFIO flush that succeeded left the region revoked,
	 * so nothing has been able to dirty it; skip the second write-back.
	 * Failing that second call would be reported for a range that is
	 * already clean.
	 */
	if (!vfio_cxl_sbr_unmasked(pdev) || cxl->hdm_flushed_early)
		return;

	ret = cpu_cache_invalidate_memregion(cxl->hpa_range.start,
					     range_len(&cxl->hpa_range));
	if (ret) {
		pci_err(pdev, "vfio-cxl: failed to invalidate CPU cache before reset: %d\n",
			ret);
		/*
		 * Dirty lines may outlive the decoder, so gate host access on
		 * a CXL Reset that succeeds, the same way a failed reset does.
		 */
		cxl->hdm_needs_reset = true;
	}
}

static int vfio_cxl_reset_done(struct vfio_pci_core_device *vdev)
{
	struct vfio_cxl_state *cxl = vdev->cxl;
	struct pci_dev *pdev = vdev->pdev;
	int ret;

	lockdep_assert_held_write(&vdev->memory_lock);

	/* This reset is over: a later one prepares itself again. */
	vfio_cxl_forget_early_prepare(cxl);

	/*
	 * VFIO_DEVICE_PCI_HOT_RESET drives a plain secondary bus reset, not the
	 * CXL-aware cxl_reset_bus_function(). When the upstream port has SBR
	 * unmasked the reset decommits the decoder. The PCI core has restored
	 * config space by now; recover the decoder with the helper for a reset
	 * the CXL core did not prepare. This path cannot use the prepared
	 * sequence: a bus reset runs reset_prepare() for every device on the
	 * bus before resetting any of them, so taking the region quiesce there
	 * would block a second CXL endpoint behind the same bridge. A masked
	 * port refuses the bus reset. Other resets (FLR, the cxl_reset and
	 * cxl_bus methods) leave the decoder committed or restore it
	 * themselves; restore only a decoder that is gone, so a committed one
	 * is not decommitted and committed again.
	 */
	if (vfio_cxl_sbr_unmasked(pdev) && !vfio_cxl_hdm_intact(vdev)) {
		ret = pci_save_state(pdev);
		if (!ret)
			ret = cxl_recover_state_after_pci_reset(pdev, cxl->hdm);
		if (ret) {
			pci_warn(pdev, "vfio-cxl: HDM decoder restore failed: %d\n",
				 ret);
			vfio_cxl_sync_mem_enable(vdev);
			return ret;
		}
	} else if (!cxl->hdm_open_at_prepare) {
		/*
		 * reset_done runs even when the reset method failed. Nothing
		 * restored the decoder, and it was not known good before this
		 * reset (a failed reset or a skipped restore closed the gate),
		 * so keep host access closed.
		 */
		return 0;
	}

	/* After a failed CXL Reset, only a CXL Reset reopens host access. */
	if (cxl->hdm_needs_reset)
		return 0;

	ret = vfio_cxl_await_mem_active(vdev);
	if (ret)
		return ret;

	vfio_cxl_rearm_hdm(vdev);
	return 0;
}

/*
 * AER or DPC recovery resumes the device without restoring its config space,
 * so do not restore the decoder here. Put the HDM region back only if the
 * device still decodes it; otherwise the user's reset restores it.
 */
static void vfio_cxl_error_resume(struct vfio_pci_core_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;

	lockdep_assert_held_write(&vdev->memory_lock);

	/* Low power closed the region; vfio_cxl_power_up() reopens it. */
	if (pdev->current_state != PCI_D0)
		return;

	/*
	 * The region was closed before the error, or a CXL Reset failed while
	 * recovery ran; keep it closed until a CXL Reset succeeds.
	 */
	if (!vdev->cxl->hdm_open_at_prepare || vdev->cxl->hdm_needs_reset)
		return;

	if (!vfio_cxl_hdm_intact(vdev)) {
		pci_warn(pdev, "vfio-cxl: HDM decoder lost in error recovery, reset the device to restore it\n");
		return;
	}

	if (!vfio_cxl_await_mem_active(vdev))
		vfio_cxl_rearm_hdm(vdev);
}

static const struct vfio_cxl_ops vfio_cxl_ops = {
	.init		= vfio_cxl_init_device,
	.release	= vfio_cxl_release_device,
	.open_device	= vfio_cxl_open_device,
	.close_device	= vfio_cxl_close_device,
	.reset_flush	= vfio_cxl_reset_flush,
	.reset_flush_abort = vfio_cxl_reset_flush_abort,
	.reset_prepare	= vfio_cxl_reset_prepare,
	.reset_done	= vfio_cxl_reset_done,
	.error_resume	= vfio_cxl_error_resume,
	.reset		= vfio_cxl_reset,
	.power_down	= vfio_cxl_power_down,
	.power_up	= vfio_cxl_power_up,
	.owner		= THIS_MODULE,
};

static int __init vfio_cxl_init(void)
{
	return vfio_pci_core_register_cxl_ops(&vfio_cxl_ops);
}

static void __exit vfio_cxl_exit(void)
{
	vfio_pci_core_unregister_cxl_ops(&vfio_cxl_ops);
}

module_init(vfio_cxl_init);
module_exit(vfio_cxl_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("VFIO support for CXL Type-2 devices");
MODULE_IMPORT_NS("CXL");
MODULE_IMPORT_NS("DEVMEM");
