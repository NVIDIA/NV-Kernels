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
	__le32                      *comp_reg_virt;
	size_t                       dpa_size;
	void __iomem                *hdm_iobase;
	u16                          dvsec_len;
	u8                           hdm_count;
	u8                           comp_reg_bar;
	bool                         cache_capable;
};

/* Register access sizes */
#define CXL_REG_SIZE_WORD  2
#define CXL_REG_SIZE_DWORD 4

/* HDM Decoder - register offsets (CXL 4.0 Table 8-115) */
#define CXL_HDM_DECODER_GLOBAL_CTRL_OFFSET        0x4
#define CXL_HDM_DECODER_FIRST_BLOCK_OFFSET        0x10
#define CXL_HDM_DECODER_BLOCK_STRIDE              0x20
#define CXL_HDM_DECODER_N_BASE_LOW_OFFSET         0x0
#define CXL_HDM_DECODER_N_BASE_HIGH_OFFSET        0x4
#define CXL_HDM_DECODER_N_SIZE_LOW_OFFSET         0x8
#define CXL_HDM_DECODER_N_SIZE_HIGH_OFFSET        0xc
#define CXL_HDM_DECODER_N_CTRL_OFFSET             0x10
#define CXL_HDM_DECODER_N_TARGET_LIST_LOW_OFFSET  0x14
#define CXL_HDM_DECODER_N_TARGET_LIST_HIGH_OFFSET 0x18
#define CXL_HDM_DECODER_N_REV_OFFSET              0x1c

/*
 * HDM Decoder N Control emulation masks.
 *
 * Single-bit hardware definitions are in <uapi/cxl/cxl_regs.h> as
 * CXL_HDM_DECODER0_CTRL_* (bits 0-14) and CXL_HDM_DECODER_*_CAP.
 * The masks below express emulation policy for a CXL.mem device.
 */
#define CXL_HDM_DECODER_CTRL_RO_BITS_MASK    (BIT(10) | BIT(11))
#define CXL_HDM_DECODER_CTRL_RESERVED_MASK   (BIT(15) | GENMASK(31, 28))
#define CXL_HDM_DECODER_CTRL_DEVICE_BITS_RO  BIT(12)
#define CXL_HDM_DECODER_CTRL_DEVICE_RESERVED (GENMASK(19, 16) | GENMASK(23, 20))
#define CXL_HDM_DECODER_CTRL_UIO_RESERVED    (BIT(14) | GENMASK(27, 24))
/*
 * bit 13 (BI) is RsvdP for devices without CXL.cache (Cache_Capable=0).
 * HDM-D (CXL.mem only) decoders must not have BI set by the guest.
 */
#define CXL_HDM_DECODER_CTRL_BI_RESERVED          BIT(13)
#define CXL_HDM_DECODER_BASE_LO_RESERVED_MASK     GENMASK(27, 0)

#define CXL_HDM_DECODER_GLOBAL_CTRL_RESERVED_MASK GENMASK(31, 2)
#define CXL_HDM_DECODER_GLOBAL_CTRL_POISON_EN_BIT BIT(0)

/*
 * CXL DVSEC for CXL Devices - register offsets within the DVSEC
 * (CXL 4.0 8.1.3).
 * Offsets are relative to the DVSEC capability base (cxl->dvsec).
 */
#define CXL_DVSEC_CAPABILITY_OFFSET 0xa
#define CXL_DVSEC_MEM_CAPABLE	    BIT(2)
/* CXL DVSEC Capability register bit 0: device supports CXL.cache (HDM-DB) */
#define CXL_DVSEC_CACHE_CAPABLE	    BIT(0)

int vfio_cxl_setup_virt_regs(struct vfio_pci_core_device *vdev,
			     struct vfio_pci_cxl_state *cxl,
			     void __iomem *cap_base,
			     resource_size_t max_size);
void vfio_cxl_clean_virt_regs(struct vfio_pci_cxl_state *cxl);
void vfio_cxl_reinit_comp_regs(struct vfio_pci_cxl_state *cxl);
resource_size_t
vfio_cxl_read_committed_decoder_size(struct vfio_pci_core_device *vdev,
				     struct vfio_pci_cxl_state *cxl);

#endif /* __LINUX_VFIO_CXL_PRIV_H */
