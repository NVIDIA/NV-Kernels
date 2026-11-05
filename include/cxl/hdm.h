/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 NVIDIA Corporation & Affiliates */
#ifndef __CXL_HDM_H__
#define __CXL_HDM_H__

#include <linux/types.h>
#include <cxl/cxl.h>

/**
 * struct cxl_endpoint_decoder_settings - endpoint HDM decoder programming
 * @config: common decoder configuration
 * @skip: length of DPA space skipped before this decoder's DPA mapping
 */
struct cxl_endpoint_decoder_settings {
	struct cxl_decoder_config config;
	u64 skip;
};

#endif /* __CXL_HDM_H__ */
