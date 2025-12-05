// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Intel Corporation. */

/*
 * Private interfaces betwen common drivers ("cxl_mem", "cxl_port") and
 * the cxl_core.
 */
#ifndef __CXL_PRIVATE_H__
#define __CXL_PRIVATE_H__
struct cxl_memdev *cxl_memdev_alloc(struct cxl_dev_state *cxlds,
				    const struct cxl_memdev_ops *ops);
struct cxl_memdev *devm_cxl_memdev_add_or_reset(struct device *host,
						struct cxl_memdev *cxlmd);
int devm_cxl_add_endpoint(struct device *host, struct cxl_memdev *cxlmd,
			  struct cxl_dport *parent_dport);
#endif /* __CXL_PRIVATE_H__ */
