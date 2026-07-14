/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Common infrastructure for CXL Type-2 device variant drivers
 *
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef __LINUX_VFIO_CXL_PRIV_H
#define __LINUX_VFIO_CXL_PRIV_H

#include <cxl/cxl.h>
#include <linux/types.h>
#include <cxl/pci.h>

/* CXL device state embedded in vfio_pci_core_device */
struct vfio_pci_cxl_state {
	struct cxl_dev_state         cxlds;
	struct cxl_memdev           *cxlmd;
	struct cxl_root_decoder     *cxlrd;
	struct cxl_endpoint_decoder *cxled;
	resource_size_t              hdm_reg_offset;
	size_t                       hdm_reg_size;
	resource_size_t              comp_reg_offset;
	size_t                       comp_reg_size;
	u16                          dvsec_len;
	u8                           hdm_count;
	u8                           comp_reg_bar;
	bool                         cache_capable;
};

/*
 * CXL DVSEC for CXL Devices - register offsets within the DVSEC
 * (CXL 4.0 8.1.3).
 * Offsets are relative to the DVSEC capability base (cxl->dvsec).
 */
#define CXL_DVSEC_CAPABILITY_OFFSET 0xa
#define CXL_DVSEC_MEM_CAPABLE	    BIT(2)
/* CXL DVSEC Capability register bit 0: device supports CXL.cache (HDM-DB) */
#define CXL_DVSEC_CACHE_CAPABLE	    BIT(0)

#endif /* __LINUX_VFIO_CXL_PRIV_H */
