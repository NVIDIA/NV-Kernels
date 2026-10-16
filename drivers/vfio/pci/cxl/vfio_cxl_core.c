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
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/range.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vfio_pci_core.h>
#include <cxl/cxl.h>
#include <cxl/hdm.h>
#include <cxl/pci.h>

/**
 * struct vfio_cxl_state - per-device state for a vfio-cxl device
 * @cxlds: CXL device state; kept first for devm_cxl_dev_state_create()
 * @cxlmd: memory device joined to the CXL topology at bind
 * @hpa_range: host physical range of the HDM region
 * @hpa_res: exclusive reservation of @hpa_range, held for the bind
 * @hdm: copy of the HDM state cached at PCI enumeration, taken at bind
 * @hdm_valid: true when host CPU access to the HDM range is safe; under memory_lock
 * @await_mem_active: the device reports Mem_HwInit_Mode, so wait for
 *	Memory_Active before host access reopens after a reset or low power
 * @mem_region_index: vfio region index of the HDM memory region while open, else 0
 */
struct vfio_cxl_state {
	struct cxl_dev_state cxlds;
	struct cxl_memdev *cxlmd;
	struct range hpa_range;
	struct resource *hpa_res;
	struct cxl_hdm_info *hdm;
	bool hdm_valid;
	bool await_mem_active;
	unsigned int mem_region_index;
};

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
};

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

	/* Record where the HDM memory region landed, to revoke it later. */
	cxl->mem_region_index = VFIO_PCI_NUM_REGIONS + vdev->num_regions - 1;

	return 0;
}

static void vfio_cxl_close_device(struct vfio_pci_core_device *vdev)
{
	/* vfio-pci-core frees the regions after this returns. */
	vdev->cxl->mem_region_index = 0;
}

static void vfio_cxl_reset_prepare(struct vfio_pci_core_device *vdev)
{
}

static int vfio_cxl_reset_done(struct vfio_pci_core_device *vdev)
{
	return 0;
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

	cxl->hdm_valid = true;
	if (cxl->mem_region_index)
		vfio_pci_core_rearm_region(vdev, cxl->mem_region_index);
}

/*
 * vfio-cxl holds the HDM range, so the PCI core's cxl_reset method would
 * fail to request it. Run the same CXL Reset with that claim.
 */
static int vfio_cxl_reset(struct vfio_pci_core_device *vdev)
{
	/*
	 * The reset restores PCI state from the saved copy. The caller provides
	 * it: the try-reset helper saves the current state, and the close path
	 * keeps the open-time state that vfio_pci_core_disable() loaded.
	 */
	return pci_cxl_reset_owned(vdev->pdev, vdev->cxl->hpa_res);
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

	if (ret)
		pci_warn(pdev, "vfio-cxl: HDM decoder restore failed: %d\n", ret);
	else if (!vfio_cxl_await_mem_active(vdev))
		vfio_cxl_rearm_hdm(vdev);
}

static const struct vfio_cxl_ops vfio_cxl_ops = {
	.init		= vfio_cxl_init_device,
	.release	= vfio_cxl_release_device,
	.open_device	= vfio_cxl_open_device,
	.close_device	= vfio_cxl_close_device,
	.reset_prepare	= vfio_cxl_reset_prepare,
	.reset_done	= vfio_cxl_reset_done,
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
