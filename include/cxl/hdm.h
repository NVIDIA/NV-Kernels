/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 NVIDIA Corporation & Affiliates */
#ifndef __CXL_HDM_H__
#define __CXL_HDM_H__

#include <linux/types.h>
#include <cxl/cxl.h>

struct pci_dev;
struct cxl_endpoint_decoder;

/**
 * struct cxl_endpoint_decoder_settings - endpoint HDM decoder programming
 * @config: common decoder configuration
 * @skip: length of DPA space skipped before this decoder's DPA mapping
 */
struct cxl_endpoint_decoder_settings {
	struct cxl_decoder_config config;
	u64 skip;
};

/**
 * struct cxl_hdm_info - cached CXL HDM state for a PCI device
 * @decoder_count: number of entries in @settings
 * @hdm_bar: PCI BAR containing the HDM decoder capability
 * @hdm_offset: offset of the HDM decoder capability in @hdm_bar
 * @hdm_size: size of the HDM decoder register block
 * @global_ctrl: HDM decoder global control register
 * @dvsec: config space offset of the CXL Device DVSEC
 * @dvsec_ctrl: CXL DVSEC control register
 * @dvsec_ctrl_valid: whether @dvsec_ctrl contains valid state
 * @settings: per-endpoint-decoder programming state
 *
 * Publication through pci_dev.hdm and all mutable fields are protected by
 * cxl_rwsem.dpa.
 */
struct cxl_hdm_info {
	int decoder_count;
	int hdm_bar;
	resource_size_t hdm_offset;
	resource_size_t hdm_size;
	u32 global_ctrl;
	u16 dvsec;
	u16 dvsec_ctrl;
	bool dvsec_ctrl_valid;
	struct cxl_endpoint_decoder_settings settings[] __counted_by(decoder_count);
};
struct device;

int cxl_hdm_decoder_count_mapped(struct device *dev, void __iomem *hdm,
				 resource_size_t size);
int cxl_hdm_read_state(struct device *dev, void __iomem *hdm,
		       struct cxl_hdm_info *info);
void cxl_hdm_cache_set_dvsec_ctrl(struct pci_dev *pdev, u16 ctrl);
void cxl_hdm_cache_refresh_decoder(struct pci_dev *pdev, void __iomem *hdm,
				   struct cxl_endpoint_decoder *cxled);
int cxl_hdm_cache_check_decoder_count(struct pci_dev *pdev, int count);
void cxl_hdm_cache_release(struct cxl_hdm_info **slot);

#endif /* __CXL_HDM_H__ */
