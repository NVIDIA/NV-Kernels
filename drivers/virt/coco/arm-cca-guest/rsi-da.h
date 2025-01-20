/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#ifndef _VIRT_COCO_RSI_DA_H_
#define _VIRT_COCO_RSI_DA_H_

#include <linux/pci.h>
#include <linux/pci-tsm.h>
#include <asm/rsi_smc.h>
#include <crypto/sha2.h>

#define MAX_CACHE_OBJ_SIZE	SZ_16M

struct pci_tdisp_device_interface_report {
	u16 interface_info;
	u16 reserved;
	u16 msi_x_message_control;
	u16 lnr_control;
	u32 tph_control;
	u32 mmio_range_count;
} __packed;

struct pci_tdisp_mmio_range {
	u64 first_page;
	u32 num_pages;
	u32 range_attributes;
} __packed;

#define TSM_INTF_REPORT_MMIO_MSIX_TABLE		BIT(0)
#define TSM_INTF_REPORT_MMIO_PBA		BIT(1)
#define TSM_INTF_REPORT_MMIO_IS_NON_TEE		BIT(2)
#define TSM_INTF_REPORT_MMIO_IS_UPDATABLE	BIT(3)
#define TSM_INTF_REPORT_MMIO_RESERVED		GENMASK(15, 4)
#define TSM_INTF_REPORT_MMIO_RANGE_ID		GENMASK(31, 16)

struct dsm_device_info {
	u64 cert_id;
	u64 hash_algo;
	u64 lock_nonce;
	u64 meas_nonce;
	u64 report_nonce;
	u8 cert_digest[SHA512_DIGEST_SIZE];
	u8 meas_digest[SHA512_DIGEST_SIZE];
	u8 report_digest[SHA512_DIGEST_SIZE];
};

struct cca_guest_dsc {
	struct pci_tsm_devsec pci;
	void *interface_report;
	int interface_report_size;
	void *certificate;
	int certificate_size;
	void *measurements;
	int measurements_size;
	struct dsm_device_info dev_info;
};

static inline struct cca_guest_dsc *to_cca_guest_dsc(struct pci_dev *pdev)
{
	struct pci_tsm *tsm = pdev->tsm;

	if (!tsm)
		return NULL;
	return container_of(tsm, struct cca_guest_dsc, pci.base_tsm);
}

/*
 * Linux use device requester id as the vdev id.
 */
static inline int rsi_vdev_id(struct pci_dev *pdev)
{
	return (pci_domain_nr(pdev->bus) << 16) |
	       PCI_DEVID(pdev->bus->number, pdev->devfn);
}

int cca_device_lock(struct pci_dev *pdev);
int cca_device_unlock(struct pci_dev *pdev);
int cca_update_device_object_cache(struct pci_dev *pdev, struct cca_guest_dsc *dsc);
struct page *alloc_shared_pages(int nid, gfp_t gfp_mask, unsigned long min_size);
int free_shared_pages(struct page *page, unsigned long min_size);
int cca_apply_interface_report_mappings(struct pci_dev *pdev, bool validate);
int cca_device_verify_and_accept(struct pci_dev *pdev);
#endif
