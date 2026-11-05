// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 NVIDIA Corporation & Affiliates */
#include <linux/export.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/rwsem.h>

#include <cxl/hdm.h>

#include "cxl.h"
#include "core.h"

struct cxl_rwsem cxl_rwsem = {
	.region = __RWSEM_INITIALIZER(cxl_rwsem.region),
	.dpa = __RWSEM_INITIALIZER(cxl_rwsem.dpa),
};
EXPORT_SYMBOL_FOR_MODULES(cxl_rwsem, "cxl_core");

void cxl_hdm_cache_refresh_decoder(struct pci_dev *pdev, void __iomem *hdm,
				   struct cxl_endpoint_decoder *cxled)
{
	struct cxl_endpoint_decoder_settings *settings;
	struct cxl_decoder *cxld = &cxled->cxld;
	struct cxl_hdm_info *info;
	u32 global_ctrl;
	int id;

	guard(rwsem_write)(&cxl_rwsem.dpa);
	id = cxld->config.id;
	info = pdev->hdm;
	if (!info)
		return;
	if (id < 0 || id >= info->decoder_count) {
		pci_warn(pdev, "CXL HDM decoder %d exceeds cached count %d\n",
			 id, info->decoder_count);
		return;
	}

	/* Preserve the last good value when the device does not respond. */
	global_ctrl = readl(hdm + CXL_HDM_DECODER_CTRL_OFFSET);
	if (global_ctrl != U32_MAX)
		info->global_ctrl = global_ctrl;
	settings = &info->settings[id];

	/*
	 * A disabled decoder's software object may retain its old range and
	 * skip state. Leave only the decoder id in the cached settings so stale
	 * state is not restored as an enabled decode.
	 */
	*settings = (struct cxl_endpoint_decoder_settings) {
		.config.id = id,
	};
	if (cxld->config.flags & CXL_DECODER_F_ENABLE) {
		settings->config = cxld->config;
		settings->skip = cxled->skip;
	}
}
EXPORT_SYMBOL_FOR_MODULES(cxl_hdm_cache_refresh_decoder, "cxl_core");

int cxl_hdm_cache_check_decoder_count(struct pci_dev *pdev, int count)
{
	guard(rwsem_read)(&cxl_rwsem.dpa);
	if (pdev->hdm && pdev->hdm->decoder_count != count) {
		pci_warn(pdev,
			 "CXL HDM cache decoder count mismatch: cached=%d hdm=%d\n",
			 pdev->hdm->decoder_count, count);
		return -ENXIO;
	}

	return 0;
}
EXPORT_SYMBOL_FOR_MODULES(cxl_hdm_cache_check_decoder_count, "cxl_core");
