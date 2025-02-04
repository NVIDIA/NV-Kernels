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

static inline int
rsi_validate_dev_mapping(unsigned long vdev_id, phys_addr_t start_ipa,
			 phys_addr_t end_ipa, phys_addr_t io_pa,
			 unsigned long flags, unsigned long lock_nonce,
			 unsigned long meas_nonce, unsigned long report_nonce)
{
	unsigned long ret;
	phys_addr_t next_ipa;

	while (start_ipa < end_ipa) {
		ret = rsi_vdev_validate_mapping(vdev_id, start_ipa, end_ipa,
						io_pa, &next_ipa, flags,
						lock_nonce, meas_nonce, report_nonce);
		if (ret || next_ipa <= start_ipa || next_ipa > end_ipa)
			return -EINVAL;
		io_pa += next_ipa - start_ipa;
		start_ipa = next_ipa;
	}
	return 0;
}

static inline int rsi_invalidate_dev_mapping(phys_addr_t start_ipa, phys_addr_t end_ipa)
{
	return rsi_set_memory_range(start_ipa, end_ipa, RSI_RIPAS_EMPTY,
				    RSI_CHANGE_DESTROYED);
}

int cca_apply_interface_report_mappings(struct pci_dev *pdev, bool validate)
{
	int ret;
	struct pci_tdisp_mmio_range *mmio_range;
	struct cca_guest_dsc *dsc = to_cca_guest_dsc(pdev);
	struct pci_tdisp_device_interface_report *interface_report;

	interface_report = (struct pci_tdisp_device_interface_report *)dsc->interface_report;
	mmio_range = (struct pci_tdisp_mmio_range *)(interface_report + 1);


	for (int i = 0; i < interface_report->mmio_range_count; i++, mmio_range++) {
		struct resource *r;
		unsigned int range_id;
		phys_addr_t mmio_start_phys;
		phys_addr_t ipa_start, ipa_end, bar_offset;

		range_id = FIELD_GET(TSM_INTF_REPORT_MMIO_RANGE_ID, mmio_range->range_attributes);
		if (range_id >= PCI_NUM_RESOURCES) {
			pci_warn(pdev, "Skipping broken range [%d] #%d %d\n",
				 i, range_id, mmio_range->num_pages);
			continue;
		}

		r = pci_resource_n(pdev, range_id);
		if (r->end == r->start || resource_size(r) & ~PAGE_MASK ||
		    !mmio_range->num_pages) {
			pci_warn(pdev, "Skipping broken range [%d] #%d %d pages, %llx..%llx\n",
				i, range_id, mmio_range->num_pages, r->start, r->end);
			continue;
		}

		if (FIELD_GET(TSM_INTF_REPORT_MMIO_IS_NON_TEE, mmio_range->range_attributes)) {
			pci_info(pdev, "Skipping non-TEE range [%d] #%d %d pages, %llx..%llx\n",
				 i, range_id, mmio_range->num_pages, r->start, r->end);
			continue;
		}

		/* No secure interrupts, we should not find this set, ignore for now. */
		if (FIELD_GET(TSM_INTF_REPORT_MMIO_MSIX_TABLE, mmio_range->range_attributes) ||
		    FIELD_GET(TSM_INTF_REPORT_MMIO_PBA, mmio_range->range_attributes)) {
			pci_info(pdev, "Skipping MSIX (%ld/%ld) range [%d] #%d %d pages, %llx..%llx\n",
				 FIELD_GET(TSM_INTF_REPORT_MMIO_MSIX_TABLE, mmio_range->range_attributes),
				 FIELD_GET(TSM_INTF_REPORT_MMIO_PBA, mmio_range->range_attributes),
				 i, range_id, mmio_range->num_pages, r->start, r->end);
			continue;
		}

		/* units in 4K size*/
		mmio_start_phys = mmio_range->first_page << 12;
		bar_offset = mmio_start_phys & (pci_resource_len(pdev, range_id) - 1);
		ipa_start = r->start + bar_offset;
		ipa_end = ipa_start + (mmio_range->num_pages << 12);

		if (!validate)
			ret = rsi_invalidate_dev_mapping(ipa_start, ipa_end);
		if (ret)
			return ret;
	}
	return 0;
}
