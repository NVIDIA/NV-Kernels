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

struct vfio_pci_core_device;

/*
 * CXL device state embedded in vfio_pci_core_device.
 *
 * cxlds must be the first field: devm_cxl_dev_state_create() asserts
 * offsetof(cxlds) == 0 so CXL core's container_of() lookups land back
 * on this struct.
 */
struct vfio_pci_cxl_state {
	struct cxl_dev_state         cxlds;
	struct vfio_pci_core_device *vdev;
	struct cxl_memdev           *cxlmd;
	struct cxl_root_decoder     *cxlrd;
	struct cxl_endpoint_decoder *cxled;
	struct cxl_region	    *region;
	resource_size_t		     region_hpa;
	size_t			     region_size;
	void			    *region_vaddr;
	resource_size_t              hdm_reg_offset;
	size_t                       hdm_reg_size;
	resource_size_t              comp_reg_offset;
	size_t                       comp_reg_size;
	__le32                      *comp_reg_virt;
	size_t                       dpa_size;
	void __iomem                *hdm_iobase;
	int                          dpa_region_idx;
	int                          comp_reg_region_idx;
	u16                          dvsec_len;
	u8                           hdm_count;
	u8                           comp_reg_bar;
	bool                         cache_capable;
	bool                         precommitted;
	bool                         region_active;
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
 * DVSEC register offsets and per-bit hardware definitions are in
 * <uapi/cxl/cxl_regs.h> as CXL_DVSEC_*.  The masks below encode
 * emulation policy: which bits to ignore, which to preserve separately
 * from their raw hardware state.
 */
/* DVSEC Control (0x0C): bits 13 (RsvdP) and 15 (RsvdP) are always discarded */
#define CXL_CTRL_RESERVED_MASK           (BIT(13) | BIT(15))
/* bit 12 (P2P_Mem_Enable) treated as reserved if Cap3.P2P_Mem_Capable=0 */
#define CXL_CTRL_P2P_REV_MASK            CXL_DVSEC_CTRL_P2P_MEM_ENABLE

/* DVSEC Status (0x0E): bits 13:0 and 15 are RsvdZ */
#define CXL_STATUS_RESERVED_MASK         (GENMASK(13, 0) | BIT(15))

/*
 * DVSEC Control2 (0x10) emulation masks.
 *
 * CXL_CTRL2_HW_BITS_MASK: bits 1 (Initiate_Cache_WBI) and 2
 * (Initiate_CXL_Reset) always read 0 from hardware _ they are write-only
 * action triggers per CXL 4.0 _8.1.3.8 Table 8-8.  Forward these to the
 * device to trigger the hardware action; clear them from vconfig shadow so
 * that subsequent guest reads return 0 as hardware requires.
 *
 * NOTE: bit 0 (Disable_Caching) and bit 3 (CXL_Reset_Mem_Clr_Enable) are
 * ordinary RW fields _ they must be preserved in vconfig, not forwarded.
 */
#define CXL_CTRL2_RESERVED_MASK          GENMASK(15, 6)
#define CXL_CTRL2_HW_BITS_MASK           (BIT(1) | BIT(2))
/* bit 4 is RsvdP if Cap3.Volatile_HDM_Configurability=0 */
#define CXL_CTRL2_VOLATILE_HDM_REV_MASK  CXL_DVSEC_CTRL2_DESIRED_VOLATILE_HDM
/* bit 5 is RsvdP if Cap2.Mod_Completion_Capable=0 */
#define CXL_CTRL2_MODIFIED_COMP_REV_MASK CXL_DVSEC_CTRL2_MOD_COMPLETION_ENABLE

/* DVSEC Lock (0x14): bits 15:1 are RsvdP */
#define CXL_LOCK_RESERVED_MASK           GENMASK(15, 1)

/* DVSEC Range Base Low: bits 27:0 are reserved per Tables 8-15/8-19 */
#define CXL_BASE_LO_RESERVED_MASK        CXL_DVSEC_RANGE_BASE_LOW_RSVD_MASK

int vfio_cxl_setup_virt_regs(struct vfio_pci_core_device *vdev,
			     struct vfio_pci_cxl_state *cxl,
			     void __iomem *cap_base,
			     resource_size_t max_size);
void vfio_cxl_clean_virt_regs(struct vfio_pci_cxl_state *cxl);
void vfio_cxl_reinit_comp_regs(struct vfio_pci_cxl_state *cxl);
resource_size_t
vfio_cxl_read_committed_decoder_size(struct vfio_pci_core_device *vdev,
				     struct vfio_pci_cxl_state *cxl);
int vfio_cxl_create_cxl_region(struct vfio_pci_cxl_state *cxl,
			       resource_size_t size);
void vfio_cxl_destroy_cxl_region(struct vfio_pci_cxl_state *cxl);

__le32 *hdm_reg_ptr(struct vfio_pci_cxl_state *cxl, u32 hdm_off);

#endif /* __LINUX_VFIO_CXL_PRIV_H */
