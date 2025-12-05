// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2025 Intel Corporation. */

/* Private interfaces betwen common drivers ("cxl_mem") and the cxl_core */

#ifndef __CXL_PRIVATE_H__
#define __CXL_PRIVATE_H__
struct cxl_memdev *cxl_memdev_alloc(struct cxl_dev_state *cxlds);
struct cxl_memdev *devm_cxl_memdev_add_or_reset(struct device *host,
						struct cxl_memdev *cxlmd);
#endif /* __CXL_PRIVATE_H__ */
