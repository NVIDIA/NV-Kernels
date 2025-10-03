// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#include <linux/pci.h>
#include <linux/mem_encrypt.h>
#include <asm/rsi_cmds.h>
#include <crypto/hash.h>

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
	unsigned long mmio_flags = 0; /* non coherent, not limited order */
	int vdev_id = rsi_vdev_id(pdev);
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

		if (validate)
			ret = rsi_validate_dev_mapping(vdev_id, ipa_start,
						       ipa_end, mmio_start_phys,
						       mmio_flags,
						       dsc->dev_info.lock_nonce,
						       dsc->dev_info.meas_nonce,
						       dsc->dev_info.report_nonce);
		else
			ret = rsi_invalidate_dev_mapping(ipa_start, ipa_end);
		if (ret)
			return ret;
	}
	return 0;
}

static int verify_digests(struct cca_guest_dsc *dsc)
{
	u8 digest[SHA512_DIGEST_SIZE];
	size_t digest_size;
	void (*digest_func)(const u8 *data, size_t len, u8 *out);

	struct pci_dev *pdev = dsc->pci.base_tsm.pdev;
	struct {
		uint8_t *report;
		size_t size;
		uint8_t *digest;
	} reports[] = {
		{
			dsc->interface_report,
			dsc->interface_report_size,
			dsc->dev_info.report_digest
		},
		{
			dsc->certificate,
			dsc->certificate_size,
			dsc->dev_info.cert_digest
		},
		{
			dsc->measurements,
			dsc->measurements_size,
			dsc->dev_info.meas_digest
		}
	};

	switch (dsc->dev_info.hash_algo) {
	case RSI_HASH_SHA_256:
		digest_func = sha256;
		digest_size = SHA256_DIGEST_SIZE;
		break;

	case RSI_HASH_SHA_512:
		digest_func = sha512;
		digest_size = SHA512_DIGEST_SIZE;
		break;
	default:
		pci_err(pdev, "Unknown realm hash algorithm!\n");
		return -EINVAL;
	}

	for (int i = 0; i < ARRAY_SIZE(reports); i++) {
		digest_func(reports[i].report, reports[i].size, digest);
		if (memcmp(reports[i].digest, digest, digest_size)) {
			pci_err(pdev, "Invalid digest\n");
			return -EINVAL;
		}
	}

	pci_dbg(pdev, "Successfully verified the digests\n");
	return 0;
}

static inline int rsi_vdev_enable_dma(int vdev_id, struct dsm_device_info *dev_info)
{
	/* No ATS support */
	return __rsi_vdev_dma_enable(vdev_id, 0, 0, dev_info->lock_nonce,
				     dev_info->meas_nonce, dev_info->report_nonce);

}

int cca_device_verify_and_accept(struct pci_dev *pdev)
{
	int ret;
	int vdev_id = rsi_vdev_id(pdev);
	struct cca_guest_dsc *dsc = to_cca_guest_dsc(pdev);

	/* Now make a host call to copy the interface report to guest. */
	ret = rhi_read_cached_object(vdev_id, RHI_DA_OBJECT_INTERFACE_REPORT,
				     &dsc->interface_report, &dsc->interface_report_size);
	if (ret) {
		pci_err(pdev, "failed to get interface report from the host (%d)\n", ret);
		return ret;
	}

	ret = rhi_read_cached_object(vdev_id, RHI_DA_OBJECT_CERTIFICATE,
				     &dsc->certificate, &dsc->certificate_size);
	if (ret) {
		pci_err(pdev, "failed to get device certificate from the host (%d)\n", ret);
		return ret;
	}

	ret = rhi_read_cached_object(vdev_id, RHI_DA_OBJECT_MEASUREMENT,
				     &dsc->measurements, &dsc->measurements_size);
	if (ret) {
		pci_err(pdev, "failed to get device certificate from the host (%d)\n", ret);
		return ret;
	}

	struct rsi_vdevice_info *dev_info __free(kfree) =
		kmalloc(sizeof(*dev_info), GFP_KERNEL);
	if (!dev_info)
		return -ENOMEM;

	if (rsi_vdev_get_info(vdev_id, virt_to_phys(dev_info))) {
		pci_err(pdev, "failed to get device digests (%d)\n", ret);
		return -EIO;
	}

	dsc->dev_info.cert_id       = dev_info->cert_id;
	dsc->dev_info.hash_algo     = dev_info->hash_algo;
	dsc->dev_info.lock_nonce    = dev_info->lock_nonce;
	dsc->dev_info.meas_nonce    = dev_info->meas_nonce;
	dsc->dev_info.report_nonce  = dev_info->report_nonce;
	memcpy(dsc->dev_info.cert_digest, dev_info->cert_digest, SHA512_DIGEST_SIZE);
	memcpy(dsc->dev_info.meas_digest, dev_info->meas_digest, SHA512_DIGEST_SIZE);
	memcpy(dsc->dev_info.report_digest, dev_info->report_digest, SHA512_DIGEST_SIZE);

	/*
	 * Verify that the digests of the provided reports match with the
	 * digests from RMM
	 */
	ret = verify_digests(dsc);
	if (ret) {
		pci_err(pdev, "device digest validation failed (%d)\n", ret);
		return ret;
	}

	ret = cca_apply_interface_report_mappings(pdev, true);
	if (ret) {
		pci_err(pdev, "failed to validate the interface report\n");
		return -EIO;
	}

	ret = rhi_vdev_set_tdi_state(pdev, RHI_DA_TDI_CONFIG_RUN);
	if (ret) {
		pci_err(pdev, "failed to switch the device (%u) to RUN state\n", ret);
		return -EIO;
	}

	if (rsi_vdev_enable_dma(vdev_id, &dsc->dev_info)) {
		rhi_vdev_set_tdi_state(pdev, RHI_DA_TDI_CONFIG_LOCKED);
		pci_err(pdev, "failed to enable DMA from the device %d\n", ret);
		return -EIO;
	}

	return 0;
}
