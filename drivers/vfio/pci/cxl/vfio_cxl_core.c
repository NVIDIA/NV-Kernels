// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO support for CXL Type-2 devices.
 *
 * Copyright (c) 2026 NVIDIA Corporation & Affiliates
 */

#include <linux/cleanup.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/range.h>
#include <linux/slab.h>
#include <linux/vfio_pci_core.h>
#include <cxl/cxl.h>
#include <cxl/hdm.h>
#include <cxl/pci.h>

/**
 * struct vfio_cxl_state - per-device state for a vfio-cxl device
 * @cxlds: CXL device state; kept first for devm_cxl_dev_state_create()
 * @cxlmd: memory device joined to the CXL topology at bind
 * @hpa_range: host physical range of the HDM region
 * @hdm: copy of the HDM state cached at PCI enumeration, taken at bind
 */
struct vfio_cxl_state {
	struct cxl_dev_state cxlds;
	struct cxl_memdev *cxlmd;
	struct range hpa_range;
	struct cxl_hdm_info *hdm;
};

/*
 * Create the CXL device state and join the device to the CXL topology. The
 * caller groups these devres allocations, so return on the first error.
 */
static struct vfio_cxl_state *vfio_cxl_create_memdev(struct pci_dev *pdev,
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

static int vfio_cxl_init_device(struct vfio_pci_core_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	struct cxl_hdm_info *hdm __free(kfree) = NULL;
	struct vfio_cxl_state *cxl;
	u64 hdm_size;

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

	cxl = vfio_cxl_create_memdev(pdev, hdm_size);
	if (IS_ERR(cxl)) {
		devres_release_group(&pdev->dev, NULL);
		return PTR_ERR(cxl);
	}
	devres_close_group(&pdev->dev, NULL);

	cxl->hdm = no_free_ptr(hdm);
	vdev->cxl = cxl;

	return 0;
}

static void vfio_cxl_release_device(struct vfio_pci_core_device *vdev)
{
	kfree(vdev->cxl->hdm);
	vdev->cxl = NULL;
}

static int vfio_cxl_open_device(struct vfio_pci_core_device *vdev)
{
	return 0;
}

static void vfio_cxl_close_device(struct vfio_pci_core_device *vdev)
{
}

static void vfio_cxl_reset_prepare(struct vfio_pci_core_device *vdev)
{
}

static int vfio_cxl_reset_done(struct vfio_pci_core_device *vdev)
{
	return 0;
}

/*
 * Until vfio-cxl serves the device memory, reset through the PCI core's
 * reset methods, which run CXL Reset ahead of FLR. Restore the PCI state
 * here rather than through pci_reset_function_locked(): its reset_prepare
 * and reset_done callbacks take memory_lock, which the caller already holds.
 * The caller has saved the state, or on close loaded the open-time copy.
 */
static int vfio_cxl_reset(struct vfio_pci_core_device *vdev)
{
	struct pci_dev *pdev = vdev->pdev;
	int ret;

	ret = __pci_reset_function_locked(pdev);
	pci_restore_state(pdev);

	return ret;
}

static const struct vfio_cxl_ops vfio_cxl_ops = {
	.init		= vfio_cxl_init_device,
	.release	= vfio_cxl_release_device,
	.open_device	= vfio_cxl_open_device,
	.close_device	= vfio_cxl_close_device,
	.reset_prepare	= vfio_cxl_reset_prepare,
	.reset_done	= vfio_cxl_reset_done,
	.reset		= vfio_cxl_reset,
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
