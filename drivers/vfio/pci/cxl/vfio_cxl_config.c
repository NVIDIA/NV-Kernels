// SPDX-License-Identifier: GPL-2.0-only
/*
 * CXL DVSEC configuration space emulation for vfio-pci.
 *
 * Integrates into the existing vfio-pci-core ecap_perms[] framework using
 * vdev->vconfig as the sole shadow buffer for DVSEC registers.
 *
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/pci.h>
#include <linux/unaligned.h>
#include <linux/vfio_pci_core.h>

#include "../vfio_pci_priv.h"
#include "vfio_cxl_priv.h"

static inline u16 _cxlds_get_dvsec(struct vfio_pci_cxl_state *cxl)
{
	return (u16)cxl->cxlds.cxl_dvsec;
}

/* Helpers to access vdev->vconfig at a DVSEC-relative offset */
static inline u16 dvsec_virt_read16(struct vfio_pci_core_device *vdev,
				    u16 off)
{
	u16 dvsec = _cxlds_get_dvsec(vdev->cxl);

	return get_unaligned_le16(vdev->vconfig + dvsec + off);
}

static inline void dvsec_virt_write16(struct vfio_pci_core_device *vdev,
				      u16 off, u16 val)
{
	u16 dvsec = _cxlds_get_dvsec(vdev->cxl);

	put_unaligned_le16(val, vdev->vconfig + dvsec + off);
}

static inline u32 dvsec_virt_read32(struct vfio_pci_core_device *vdev,
				    u16 off)
{
	u16 dvsec = _cxlds_get_dvsec(vdev->cxl);

	return get_unaligned_le32(vdev->vconfig + dvsec + off);
}

static inline void dvsec_virt_write32(struct vfio_pci_core_device *vdev,
				      u16 off, u32 val)
{
	u16 dvsec = _cxlds_get_dvsec(vdev->cxl);

	put_unaligned_le32(val, vdev->vconfig + dvsec + off);
}

static u32 dvsec_virt_merge_write32(struct vfio_pci_core_device *vdev,
				    u16 off, u16 byte_in_reg,
				    int count, __le32 val)
{
	u32 cur = dvsec_virt_read32(vdev, off);
	u32 data = le32_to_cpu(val);
	u32 mask;

	if (byte_in_reg + count > sizeof(u32))
		return cur;

	if (count == sizeof(u32))
		return data;

	mask = (1U << (count * 8)) - 1;
	mask <<= byte_in_reg * 8;

	return (cur & ~mask) | ((data << (byte_in_reg * 8)) & mask);
}

/* Individual DVSEC register write handlers */

static void cxl_dvsec_control_write(struct vfio_pci_core_device *vdev,
				    u16 new_val)
{
	u16 lock = dvsec_virt_read16(vdev, CXL_DVSEC_LOCK_OFFSET);
	u16 cap3 = dvsec_virt_read16(vdev, CXL_DVSEC_CAPABILITY3_OFFSET);
	u16 rev_mask = CXL_CTRL_RESERVED_MASK;

	if (lock & CXL_DVSEC_LOCK_CONFIG_LOCK)
		return; /* register is locked after first write */

	if (!(cap3 & CXL_DVSEC_CAP3_P2P_MEM_CAPABLE))
		rev_mask |= CXL_CTRL_P2P_REV_MASK;

	new_val &= ~rev_mask;
	new_val |= CXL_DVSEC_CTRL_IO_ENABLE; /* IO_Enable always returns 1 */

	dvsec_virt_write16(vdev, CXL_DVSEC_CONTROL_OFFSET, new_val);
}

static void cxl_dvsec_status_write(struct vfio_pci_core_device *vdev,
				   u16 new_val)
{
	u16 cur_val = dvsec_virt_read16(vdev, CXL_DVSEC_STATUS_OFFSET);

	/*
	 * VIRAL_STATUS (bit 14) is the only writable bit; all others are
	 * reserved and always zero.
	 */
	new_val = cur_val & ~(new_val & CXL_DVSEC_STATUS_VIRAL_STATUS);
	dvsec_virt_write16(vdev, CXL_DVSEC_STATUS_OFFSET, new_val);
}

static void cxl_dvsec_control2_write(struct vfio_pci_core_device *vdev,
				     u16 new_val)
{
	struct pci_dev *pdev = vdev->pdev;
	u16 dvsec = _cxlds_get_dvsec(vdev->cxl);
	u16 abs_off = dvsec + CXL_DVSEC_CONTROL2_OFFSET;
	u16 cap2 = dvsec_virt_read16(vdev, CXL_DVSEC_CAPABILITY2_OFFSET);
	u16 cap3 = dvsec_virt_read16(vdev, CXL_DVSEC_CAPABILITY3_OFFSET);
	u16 rev_mask = CXL_CTRL2_RESERVED_MASK;

	if (!(cap3 & CXL_DVSEC_CAP3_VOLATILE_HDM_CONFIGURABILITY))
		rev_mask |= CXL_CTRL2_VOLATILE_HDM_REV_MASK;
	if (!(cap2 & CXL_DVSEC_CAP2_MOD_COMPLETION_CAPABLE))
		rev_mask |= CXL_CTRL2_MODIFIED_COMP_REV_MASK;

	new_val &= ~rev_mask;

	/*
	 * Cache WBI: forward to hardware.  cxl_dev_reset() programs
	 * Disable_Caching first and then initiates Cache WBI with that bit
	 * still set; replicate that ordering for VMM-delegated WBI by carrying
	 * the just-written Disable_Caching value into the same hardware write.
	 * new_val is the post-merge 16-bit shadow value, so it already reflects
	 * a prior shadow-only Disable_Caching=1 followed by a WBI-only write.
	 */
	if (new_val & CXL_DVSEC_CTRL2_INITIATE_CACHE_WBI) {
		u16 hw_val = CXL_DVSEC_CTRL2_INITIATE_CACHE_WBI;

		if (new_val & CXL_DVSEC_CTRL2_DISABLE_CACHING)
			hw_val |= CXL_DVSEC_CTRL2_DISABLE_CACHING;
		pci_write_config_word(pdev, abs_off, hw_val);
	}

	/*
	 * CXL Reset: not yet supported - do not forward to HW.
	 * TODO: invoke CXL protocol reset via cxl subsystem
	 */
	if (new_val & CXL_DVSEC_CTRL2_INITIATE_CXL_RESET)
		pci_warn(pdev, "vfio-cxl: CXL reset requested but not yet supported\n");

	dvsec_virt_write16(vdev, CXL_DVSEC_CONTROL2_OFFSET,
			   new_val & ~CXL_CTRL2_HW_BITS_MASK);
}

static void cxl_dvsec_status2_write(struct vfio_pci_core_device *vdev,
				    u16 new_val)
{
	u16 cap3 = dvsec_virt_read16(vdev, CXL_DVSEC_CAPABILITY3_OFFSET);
	u16 dvsec = _cxlds_get_dvsec(vdev->cxl);
	u16 abs_off = dvsec + CXL_DVSEC_STATUS2_OFFSET;

	/* RW1CS: write 1 to clear, but only if the capability is supported */
	if ((cap3 & CXL_DVSEC_CAP3_VOLATILE_HDM_CONFIGURABILITY) &&
	    (new_val & CXL_DVSEC_STATUS2_VOLATILE_HDM_PRES_ERROR))
		pci_write_config_word(vdev->pdev, abs_off,
				      CXL_DVSEC_STATUS2_VOLATILE_HDM_PRES_ERROR);
	/* STATUS2 is not mirrored in vconfig - reads go to hardware */
}

static void cxl_dvsec_lock_write(struct vfio_pci_core_device *vdev,
				 u16 new_val)
{
	u16 cur_val = dvsec_virt_read16(vdev, CXL_DVSEC_LOCK_OFFSET);

	/* Once the LOCK bit is set it can only be cleared by conventional reset */
	if (cur_val & CXL_DVSEC_LOCK_CONFIG_LOCK)
		return;

	new_val &= ~CXL_LOCK_RESERVED_MASK;
	dvsec_virt_write16(vdev, CXL_DVSEC_LOCK_OFFSET, new_val);
}

static void cxl_range_base_lo_write(struct vfio_pci_core_device *vdev,
				    u16 dvsec_off, u32 new_val)
{
	new_val &= ~CXL_BASE_LO_RESERVED_MASK;
	dvsec_virt_write32(vdev, dvsec_off, new_val);
}

/**
 * vfio_cxl_dvsec_readfn - Per-device DVSEC read handler for CXL capable devices.
 * @vdev:   VFIO PCI core device
 * @pos:    Absolute byte position in PCI config space
 * @count:  Number of bytes to read
 * @perm:   Permission bits for this capability (passed through to fallback)
 * @offset: Byte offset within the capability structure (passed through)
 * @val:    Output buffer for the read value (little-endian)
 *
 * Called via vfio_pci_dvsec_dispatch_read() for CXL devices.  Returns shadow
 * vconfig values for virtualized DVSEC registers (CONTROL, STATUS, CONTROL2,
 * LOCK) so that userspace reads reflect emulated state rather than raw
 * hardware.  All other DVSEC bytes pass through to vfio_raw_config_read().
 *
 * Return: @count on success, or negative error code from the fallback read.
 */
static int vfio_cxl_dvsec_readfn(struct vfio_pci_core_device *vdev,
				 int pos, int count,
				 struct perm_bits *perm,
				 int offset, __le32 *val)
{
	struct vfio_pci_cxl_state *cxl = vdev->cxl;
	u16 dvsec = _cxlds_get_dvsec(vdev->cxl);
	u16 dvsec_off;

	if (!cxl || (u16)pos < dvsec ||
	    (u16)pos >= dvsec + cxl->dvsec_len)
		return vfio_raw_config_read(vdev, pos, count, perm, offset, val);

	dvsec_off = (u16)pos - dvsec;

	switch (dvsec_off) {
	case CXL_DVSEC_CONTROL_OFFSET:
	case CXL_DVSEC_STATUS_OFFSET:
	case CXL_DVSEC_CONTROL2_OFFSET:
	case CXL_DVSEC_LOCK_OFFSET:
		/* Return shadow vconfig value for virtualized registers */
		memcpy(val, vdev->vconfig + pos, count);
		return count;
	default:
		return vfio_raw_config_read(vdev, pos, count,
					    perm, offset, val);
	}
}

/**
 * vfio_cxl_dvsec_writefn - ecap_perms write handler for PCI_EXT_CAP_ID_DVSEC.
 *
 * Installed once into ecap_perms[PCI_EXT_CAP_ID_DVSEC].writefn by
 * vfio_pci_init_perm_bits() when CONFIG_VFIO_CXL_CORE=y.  Applies to every
 * device opened under vfio-pci; the vdev->cxl NULL check distinguishes CXL
 * devices from non-CXL devices that happen to expose a DVSEC capability.
 *
 * @vdev:   VFIO PCI core device
 * @pos:    Absolute byte position in PCI config space
 * @count:  Number of bytes to write
 * @perm:   Permission bits for this capability (passed through to fallback)
 * @offset: Byte offset within the capability structure (passed through)
 * @val:    Value to write (little-endian)
 *
 * Return: @count on success; non-CXL devices continue to
 *         vfio_raw_config_write() which also returns @count or negative error.
 */
static int vfio_cxl_dvsec_writefn(struct vfio_pci_core_device *vdev,
				  int pos, int count,
				  struct perm_bits *perm,
				  int offset, __le32 val)
{
	struct vfio_pci_cxl_state *cxl = vdev->cxl;
	u16 dvsec = _cxlds_get_dvsec(vdev->cxl);
	u16 abs_off = (u16)pos;
	u16 dvsec_off, dword_start, byte_in_dword;
	u16 wval16;
	u32 wval32;

	if (!cxl || (u16)pos < dvsec ||
	    (u16)pos >= dvsec + cxl->dvsec_len)
		return vfio_raw_config_write(vdev, pos, count, perm,
					     offset, val);

	pci_dbg(vdev->pdev,
		"vfio_cxl: DVSEC write: abs=0x%04x dvsec_off=0x%04x count=%d raw_val=0x%08x\n",
		abs_off, abs_off - dvsec, count, le32_to_cpu(val));

	dvsec_off = abs_off - dvsec;

	dword_start = dvsec_off & ~3u;
	byte_in_dword = dvsec_off - dword_start;

	switch (dword_start) {
	case CXL_DVSEC_RANGE1_BASE_HIGH_OFFSET:
	case CXL_DVSEC_RANGE2_BASE_HIGH_OFFSET:
		wval32 = dvsec_virt_merge_write32(vdev, dword_start, byte_in_dword, count, val);
		dvsec_virt_write32(vdev, dword_start, wval32);
		return count;
	case CXL_DVSEC_RANGE1_BASE_LOW_OFFSET:
	case CXL_DVSEC_RANGE2_BASE_LOW_OFFSET:
		wval32 = dvsec_virt_merge_write32(vdev, dword_start, byte_in_dword, count, val);
		cxl_range_base_lo_write(vdev, dword_start, wval32);
		return count;
	}

	/* Route to the appropriate per-register handler */
	switch (dvsec_off) {
	case CXL_DVSEC_CONTROL_OFFSET:
		wval16 = (u16)le32_to_cpu(val);
		cxl_dvsec_control_write(vdev, wval16);
		break;
	case CXL_DVSEC_STATUS_OFFSET:
		wval16 = (u16)le32_to_cpu(val);
		cxl_dvsec_status_write(vdev, wval16);
		break;
	case CXL_DVSEC_CONTROL2_OFFSET:
		wval16 = (u16)le32_to_cpu(val);
		cxl_dvsec_control2_write(vdev, wval16);
		break;
	case CXL_DVSEC_STATUS2_OFFSET:
		wval16 = (u16)le32_to_cpu(val);
		cxl_dvsec_status2_write(vdev, wval16);
		break;
	case CXL_DVSEC_LOCK_OFFSET:
		wval16 = (u16)le32_to_cpu(val);
		cxl_dvsec_lock_write(vdev, wval16);
		break;
	default:
		/* RO registers: header, capability, range sizes - discard */
		break;
	}

	return count;
}

/**
 * vfio_cxl_setup_dvsec_perms - Install per-device CXL DVSEC read/write hooks.
 * @vdev: VFIO PCI core device
 *
 * Called once per device open after vfio_config_init() has seeded vdev->vconfig
 * from hardware.  Installs vfio_cxl_dvsec_readfn and vfio_cxl_dvsec_writefn
 * as per-device DVSEC handlers so that the global ecap_perms[DVSEC] dispatcher
 * routes reads and writes through CXL-aware emulation.
 *
 * Forces CXL.io IO_ENABLE in the CONTROL vconfig shadow at init time so the
 * initial guest read returns the correct value before the first write.
 */
void vfio_cxl_setup_dvsec_perms(struct vfio_pci_core_device *vdev)
{
	u16 ctrl = dvsec_virt_read16(vdev, CXL_DVSEC_CONTROL_OFFSET);

	vdev->dvsec_readfn  = vfio_cxl_dvsec_readfn;
	vdev->dvsec_writefn = vfio_cxl_dvsec_writefn;

	/* Force IO_ENABLE; cxl_dvsec_control_write() maintains this invariant. */
	ctrl |= CXL_DVSEC_CTRL_IO_ENABLE;
	dvsec_virt_write16(vdev, CXL_DVSEC_CONTROL_OFFSET, ctrl);
}
EXPORT_SYMBOL_GPL(vfio_cxl_setup_dvsec_perms);
