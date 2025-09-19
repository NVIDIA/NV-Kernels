// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#include <linux/pci.h>
#include <linux/mem_encrypt.h>
#include <asm/rsi_cmds.h>

#include "rsi-da.h"
#include "rhi-da.h"

int cca_device_lock(struct pci_dev *pdev)
{
	int ret;

	ret = rhi_vdev_set_tdi_state(pdev, RHI_DA_TDI_CONFIG_LOCKED);
	if (ret) {
		pci_err(pdev, "failed to lock the device (%d)\n", ret);
		return ret;
	}
	return 0;
}

int cca_device_unlock(struct pci_dev *pdev)
{
	int ret;

	ret = rhi_vdev_set_tdi_state(pdev, RHI_DA_TDI_CONFIG_UNLOCKED);
	if (ret) {
		pci_err(pdev, "failed to unlock the device (%d)\n", ret);
		return ret;
	}
	return 0;
}

struct page *alloc_shared_pages(int nid, gfp_t gfp_mask, unsigned long min_size)
{
	int ret;
	struct page *page;
	/* We should normalize the size based on hypervisor page size */
	int page_order = get_order(min_size);

	page = alloc_pages_node(nid, gfp_mask | __GFP_ZERO, page_order);
	if (!page)
		return NULL;

	ret = set_memory_decrypted((unsigned long)page_address(page),
				   1 << page_order);
	/*
	 * If set_memory_decrypted() fails then we don't know what state the
	 * page is in, so we can't free it. Instead we leak it.
	 * set_memory_decrypted() will already have WARNed.
	 */
	if (ret)
		return NULL;

	return page;
}

int free_shared_pages(struct page *page, unsigned long size)
{
	int ret;
	/* We should normalize the size based on hypervisor page size */
	int page_order = get_order(size);

	ret = set_memory_encrypted((unsigned long)page_address(page), 1 << page_order);
	/* If we fail to mark it encrypted don't free it back */
	if (ret)
		return ret;

	__free_pages(page, page_order);
	return 0;
}

static inline struct rhi_vdev_measurement_params *alloc_vdev_meas_params(void)
{
	struct page *pages;

	pages = alloc_shared_pages(NUMA_NO_NODE, GFP_KERNEL, sizeof(struct rhi_vdev_measurement_params));
	if (!pages)
		return NULL;
	return page_address(pages);
}

static inline void vdev_meas_params_free(struct rhi_vdev_measurement_params *params)
{
	struct page *pages = virt_to_page(params);

	free_shared_pages(pages, sizeof(struct rhi_vdev_measurement_params));
}
DEFINE_FREE(vdev_meas_params_free, struct rhi_vdev_measurement_params *, if (_T) vdev_meas_params_free(_T))
int cca_update_device_object_cache(struct pci_dev *pdev, struct cca_guest_dsc *dsc)
{
	int ret;

	ret = rhi_update_vdev_interface_report_cache(pdev);
	if (ret) {
		pci_err(pdev, "failed to get interface report (%d)\n", ret);
		return ret;
	}

	struct rhi_vdev_measurement_params *dev_meas __free(vdev_meas_params_free) =
		alloc_vdev_meas_params();
	if (!dev_meas)
		return -ENOMEM;

	/* request for signed full transcript */
	dev_meas->flags = RHI_VDEV_MEASURE_SIGNED | RHI_VDEV_MEASURE_EXCHANGE;
	/* request all measurement block. Set bit 254 */
	dev_meas->indices[31] = 0x40;
	ret = rhi_update_vdev_measurements_cache(pdev, dev_meas);

	if (ret) {
		pci_err(pdev, "failed to get device measurement (%d)\n", ret);
		return ret;
	}
	return 0;
}
