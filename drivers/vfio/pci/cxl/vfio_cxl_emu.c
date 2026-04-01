// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/bitops.h>
#include <linux/vfio_pci_core.h>

#include "../vfio_pci_priv.h"
#include "vfio_cxl_priv.h"

/*
 * comp_reg_virt[] shadow layout:
 *   Covers the full CXL.mem register area (starting at CXL_CM_OFFSET
 *   within the component register block).  Index 0 is the CXL Capability
 *   Array Header; the HDM decoder block starts at index
 *   hdm_reg_offset / sizeof(__le32).
 *
 * Register layout within the HDM block (CXL spec 4.0 8.2.4.20 CXL HDM Decoder
 * Capability Structure):
 *   0x00: HDM Decoder Capability
 *   0x04: HDM Decoder Global Control
 *   0x08: (reserved)
 *   0x0c: (reserved)
 *   For each decoder N (N=0..hdm_count-1), at base 0x10 + N*0x20:
 *     +0x00: BASE_LO
 *     +0x04: BASE_HI
 *     +0x08: SIZE_LO
 *     +0x0c: SIZE_HI
 *     +0x10: CTRL
 *     +0x14: TARGET_LIST_LO
 *     +0x18: TARGET_LIST_HI
 *     +0x1c: (reserved)
 */

static inline __le32 *hdm_reg_ptr(struct vfio_pci_cxl_state *cxl, u32 hdm_off)
{
	/*
	 * hdm_off is a byte offset within the HDM decoder block.
	 * comp_reg_virt covers the CXL.mem register area starting at
	 * CXL_CM_OFFSET within the component register block.
	 * hdm_reg_offset is CXL.mem-relative, so adding hdm_reg_offset
	 * gives the correct index into comp_reg_virt[].
	 */
	return &cxl->comp_reg_virt[(cxl->hdm_reg_offset + hdm_off) /
				   sizeof(__le32)];
}

static ssize_t virt_hdm_rev_reg_write(struct vfio_pci_core_device *vdev,
				      const __le32 *val32, u64 offset, u64 size)
{
	/* Discard writes on reserved registers. */
	return size;
}

static ssize_t hdm_decoder_n_lo_write(struct vfio_pci_core_device *vdev,
				      const __le32 *val32, u64 offset, u64 size)
{
	u32 new_val = le32_to_cpu(*val32);
	u32 dec_idx, ctrl_off, ctrl;

	if (WARN_ON_ONCE(size != CXL_REG_SIZE_DWORD))
		return -EINVAL;

	/*
	 * Honor the CTRL LOCK bit the same way BASE_HI/SIZE_HI do: once the
	 * guest sets LOCK, BASE_LO/SIZE_LO must remain frozen in shadow.
	 */
	dec_idx = ((u32)offset - CXL_HDM_DECODER_FIRST_BLOCK_OFFSET) /
		  CXL_HDM_DECODER_BLOCK_STRIDE;
	ctrl_off = CXL_HDM_DECODER_FIRST_BLOCK_OFFSET +
		   dec_idx * CXL_HDM_DECODER_BLOCK_STRIDE +
		   CXL_HDM_DECODER_N_CTRL_OFFSET;
	ctrl = le32_to_cpu(*hdm_reg_ptr(vdev->cxl, ctrl_off));
	if (ctrl & CXL_HDM_DECODER0_CTRL_LOCK)
		return size;

	/* Bits [27:0] are reserved. */
	new_val &= ~CXL_HDM_DECODER_BASE_LO_RESERVED_MASK;

	*hdm_reg_ptr(vdev->cxl, offset) = cpu_to_le32(new_val);

	return size;
}

static ssize_t hdm_decoder_global_ctrl_write(struct vfio_pci_core_device *vdev,
					     const __le32 *val32, u64 size)
{
	u32 hdm_gcap;
	u32 new_val = le32_to_cpu(*val32);

	if (WARN_ON_ONCE(size != CXL_REG_SIZE_DWORD))
		return -EINVAL;

	/* Bit [31:2] are reserved. */
	new_val &= ~CXL_HDM_DECODER_GLOBAL_CTRL_RESERVED_MASK;

	/* Poison On Decode Error Enable (bit 0) is RO=0 if not supported. */
	hdm_gcap = le32_to_cpu(*hdm_reg_ptr(vdev->cxl,
					    CXL_HDM_DECODER_CAP_OFFSET));
	if (!(hdm_gcap & CXL_HDM_DECODER_POISON_ON_DECODE_ERR))
		new_val &= ~CXL_HDM_DECODER_GLOBAL_CTRL_POISON_EN_BIT;

	*hdm_reg_ptr(vdev->cxl, CXL_HDM_DECODER_CTRL_OFFSET) =
		cpu_to_le32(new_val);

	return size;
}

/**
 * hdm_decoder_n_ctrl_write - Write handler for HDM decoder CTRL register.
 * @vdev:   VFIO PCI core device
 * @val32:  New register value supplied by userspace (little-endian)
 * @offset: Byte offset within the HDM block for this decoder's CTRL register
 * @size:   Access size in bytes; must equal CXL_REG_SIZE_DWORD
 *
 * The COMMIT bit (bit 9) is the key: setting it requests the hardware to
 * lock the decoder.  The emulated COMMITTED bit (bit 10) mirrors COMMIT
 * immediately to allow QEMU's notify_change to detect the transition and
 * map/unmap the DPA MemoryRegion in the guest address space.
 *
 * Note: the actual hardware HDM decoder programming (writing the real
 * BASE/SIZE with host physical addresses) happens in the QEMU notify_change
 * callback BEFORE this write reaches the hardware.  This ordering is
 * correct because vfio_region_write() calls notify_change() first.
 *
 * Return: @size on success, %-EINVAL if @size is not %CXL_REG_SIZE_DWORD.
 */
static ssize_t hdm_decoder_n_ctrl_write(struct vfio_pci_core_device *vdev,
					const __le32 *val32, u64 offset, u64 size)
{
	u32 hdm_gcap;
	u32 ro_mask = CXL_HDM_DECODER_CTRL_RO_BITS_MASK;
	u32 rev_mask = CXL_HDM_DECODER_CTRL_RESERVED_MASK;
	u32 new_val = le32_to_cpu(*val32);
	u32 cur_val;

	if (WARN_ON_ONCE(size != CXL_REG_SIZE_DWORD))
		return -EINVAL;

	cur_val = le32_to_cpu(*hdm_reg_ptr(vdev->cxl, offset));
	if (cur_val & CXL_HDM_DECODER0_CTRL_LOCK) {
		if (new_val & CXL_HDM_DECODER0_CTRL_LOCK)
			return size;

		/* LOCK_0 only: preserve all other bits, clear LOCK */
		*hdm_reg_ptr(vdev->cxl, offset) = cpu_to_le32(
			cur_val & ~CXL_HDM_DECODER0_CTRL_LOCK);
		return size;
	}

	hdm_gcap = le32_to_cpu(*hdm_reg_ptr(vdev->cxl,
					    CXL_HDM_DECODER_CAP_OFFSET));
	ro_mask |= CXL_HDM_DECODER_CTRL_DEVICE_BITS_RO;
	rev_mask |= CXL_HDM_DECODER_CTRL_DEVICE_RESERVED;

	if (!(hdm_gcap & CXL_HDM_DECODER_UIO_CAPABLE))
		rev_mask |= CXL_HDM_DECODER_CTRL_UIO_RESERVED;

	/*
	 * BI (bit 13) is RsvdP for devices without CXL.cache.  HDM-D decoders
	 * on a CXL.mem-only device must not see BI set in shadow.
	 */
	if (!vdev->cxl->cache_capable)
		rev_mask |= CXL_HDM_DECODER_CTRL_BI_RESERVED;

	new_val &= ~rev_mask;
	cur_val &= ro_mask;
	new_val = (new_val & ~ro_mask) | cur_val;

	/*
	 * Mirror COMMIT to COMMITTED immediately in the emulated state.
	 */
	if (new_val & CXL_HDM_DECODER0_CTRL_COMMIT)
		new_val |= CXL_HDM_DECODER0_CTRL_COMMITTED;
	else
		new_val &= ~CXL_HDM_DECODER0_CTRL_COMMITTED;

	*hdm_reg_ptr(vdev->cxl, offset) = cpu_to_le32(new_val);

	return size;
}

/*
 * Dispatch table for COMP_REGS region writes. Indexed by byte offset within
 * the HDM decoder block. Returns the appropriate write handler.
 *
 * Layout:
 *   0x00	  HDM Decoder Capability  (RO)
 *   0x04	  HDM Global Control	  (RW with reserved masking)
 *   0x08-0x0f	  (reserved)		  (ignored)
 *   Per decoder N, base = 0x10 + N*0x20:
 *     base+0x00  BASE_LO  (RW, [27:0] reserved)
 *     base+0x04  BASE_HI  (RW)
 *     base+0x08  SIZE_LO  (RW, [27:0] reserved)
 *     base+0x0c  SIZE_HI  (RW)
 *     base+0x10  CTRL	   (RW, complex rules)
 *     base+0x14  TARGET_LIST_LO  (ignored for Type-2)
 *     base+0x18  TARGET_LIST_HI  (ignored for Type-2)
 *     base+0x1c  (reserved)	 (ignored)
 */
static ssize_t comp_regs_dispatch_write(struct vfio_pci_core_device *vdev,
					u32 off, const __le32 *val32, u32 size)
{
	struct vfio_pci_cxl_state *cxl = vdev->cxl;
	u32 dec_base, dec_off;

	/* HDM Decoder Capability (0x00): RO */
	if (off == CXL_HDM_DECODER_CAP_OFFSET)
		return size;

	/* HDM Global Control (0x04) */
	if (off == CXL_HDM_DECODER_CTRL_OFFSET)
		return hdm_decoder_global_ctrl_write(vdev, val32, size);

	/*
	 * Offsets 0x08-0x0f are reserved per CXL 4.0 Table 8-115.
	 * Per-decoder registers start at 0x10, stride 0x20
	 */
	if (off < CXL_HDM_DECODER_FIRST_BLOCK_OFFSET)
		return size; /* reserved gap */

	dec_base = CXL_HDM_DECODER_FIRST_BLOCK_OFFSET;
	/*
	 * Reject accesses beyond the last implemented HDM decoder.
	 * Without this check an out-of-bounds offset would silently
	 * corrupt comp_reg_virt[] memory past the end of the allocation.
	 */
	if ((off - dec_base) / CXL_HDM_DECODER_BLOCK_STRIDE >= cxl->hdm_count)
		return size;

	dec_off = (off - dec_base) % CXL_HDM_DECODER_BLOCK_STRIDE;

	switch (dec_off) {
	case CXL_HDM_DECODER_N_BASE_LOW_OFFSET:	 /* BASE_LO */
	case CXL_HDM_DECODER_N_SIZE_LOW_OFFSET:	 /* SIZE_LO */
		return hdm_decoder_n_lo_write(vdev, val32, off, size);
	case CXL_HDM_DECODER_N_BASE_HIGH_OFFSET: /* BASE_HI */
	case CXL_HDM_DECODER_N_SIZE_HIGH_OFFSET: /* SIZE_HI */
	{
		/* Full 32-bit write, no reserved bits; frozen when COMMIT_LOCK set */
		u32 ctrl_off = off - dec_off + CXL_HDM_DECODER_N_CTRL_OFFSET;
		u32 ctrl = le32_to_cpu(*hdm_reg_ptr(cxl, ctrl_off));

		if (ctrl & CXL_HDM_DECODER0_CTRL_LOCK)
			return size;
		*hdm_reg_ptr(cxl, off) = *val32;
		return size;
	}
	case CXL_HDM_DECODER_N_CTRL_OFFSET:	  /* CTRL */
		return hdm_decoder_n_ctrl_write(vdev, val32, off, size);
	case CXL_HDM_DECODER_N_TARGET_LIST_LOW_OFFSET:
	case CXL_HDM_DECODER_N_TARGET_LIST_HIGH_OFFSET:
	case CXL_HDM_DECODER_N_REV_OFFSET:
		return virt_hdm_rev_reg_write(vdev, val32, off, size);
	default:
		return size;
	}
}

/*
 * vfio_cxl_comp_regs_rw - regops rw handler for
 * VFIO_REGION_SUBTYPE_CXL_COMP_REGS.
 *
 * Reads return the emulated HDM state (comp_reg_virt[]).
 * Writes go through comp_regs_dispatch_write() for bit-field enforcement.
 * Only 4-byte aligned 4-byte accesses are supported (hardware requirement).
 */
static ssize_t vfio_cxl_comp_regs_rw(struct vfio_pci_core_device *vdev,
				     char __user *buf, size_t count,
				     loff_t *ppos, bool iswrite)
{
	struct vfio_pci_cxl_state *cxl = vdev->cxl;
	loff_t pos = *ppos & VFIO_PCI_OFFSET_MASK;
	size_t done = 0;

	if (!count)
		return 0;

	/* Clamp to total region size: cap array prefix + HDM block */
	if (pos >= cxl->hdm_reg_offset + cxl->hdm_reg_size)
		return -EINVAL;
	count = min(count,
		    (size_t)(cxl->hdm_reg_offset + cxl->hdm_reg_size - pos));

	while (done < count) {
		u32 sz	 = count - done;
		u32 off	 = pos + done;
		__le32 v;

		/* Enforce exactly 4-byte, 4-byte-aligned accesses */
		if (sz != CXL_REG_SIZE_DWORD || (off & 0x3))
			return done ? (ssize_t)done : -EINVAL;

		if (iswrite) {
			if (off < cxl->hdm_reg_offset) {
				/* Cap array area is read-only; discard writes */
				done += sizeof(v);
				continue;
			}
			if (copy_from_user(&v, buf + done, sizeof(v)))
				return done ? (ssize_t)done : -EFAULT;
			comp_regs_dispatch_write(vdev,
						 off - cxl->hdm_reg_offset,
						 &v, sizeof(v));
		} else {
			/* Read from extended buffer _ covers cap array and HDM */
			v = cxl->comp_reg_virt[off / sizeof(__le32)];
			if (copy_to_user(buf + done, &v, sizeof(v)))
				return done ? (ssize_t)done : -EFAULT;
		}
		done += sizeof(v);
	}

	*ppos += done;
	return done;
}

static void vfio_cxl_comp_regs_release(struct vfio_pci_core_device *vdev,
				       struct vfio_pci_region *region)
{
	/* comp_reg_virt is freed in vfio_cxl_clean_virt_regs() */
}

static const struct vfio_pci_regops vfio_cxl_comp_regs_ops = {
	.rw	 = vfio_cxl_comp_regs_rw,
	.release = vfio_cxl_comp_regs_release,
};

/*
 * vfio_cxl_setup_virt_regs - Allocate emulated HDM register state.
 *
 * Allocates comp_reg_virt as a compact __le32 array covering only
 * hdm_reg_size bytes of HDM decoder registers. The initial values
 * are read from hardware via the BAR ioremap established by the caller.
 *
 * DVSEC state is accessed via vdev->vconfig (see the following patch).
 */
int vfio_cxl_setup_virt_regs(struct vfio_pci_core_device *vdev,
			     struct vfio_pci_cxl_state *cxl,
			     void __iomem *cap_base,
			     resource_size_t max_size)
{
	size_t total_size, nregs, i;

	if (WARN_ON(!cxl->hdm_reg_size))
		return -EINVAL;

	total_size = cxl->hdm_reg_offset + cxl->hdm_reg_size;

	/*
	 * The caller's map covers [comp_reg_offset, comp_reg_offset+max_size)
	 * inside the BAR; the HDM block ends at CXL_CM_OFFSET + total_size
	 * relative to that map.  Reject HDM blocks that walk past the
	 * advertised map size; pci_resource_len() would happily allow a stale
	 * BAR-wide window and the subsequent readl()s would run off the
	 * ioremap range.
	 */
	if (CXL_CM_OFFSET + total_size > max_size)
		return -ENODEV;

	nregs = total_size / sizeof(__le32);
	cxl->comp_reg_virt = kcalloc(nregs, sizeof(__le32), GFP_KERNEL);
	if (!cxl->comp_reg_virt)
		return -ENOMEM;

	/*
	 * Snapshot the CXL.mem register area from the caller's mapping.
	 * cap_base maps the component register block from comp_reg_offset.
	 * The CXL.mem registers start at CXL_CM_OFFSET (= 0x1000) within that
	 * block; reading from cap_base + CXL_CM_OFFSET ensures comp_reg_virt[0]
	 * holds the CXL Capability Array Header required by guest drivers.
	 */
	for (i = 0; i < nregs; i++)
		cxl->comp_reg_virt[i] =
			cpu_to_le32(readl(cap_base + CXL_CM_OFFSET +
					  i * sizeof(__le32)));

	/*
	 * Establish persistent mapping; kept alive until
	 * vfio_cxl_clean_virt_regs().
	 */
	cxl->hdm_iobase = ioremap(pci_resource_start(vdev->pdev,
						     cxl->comp_reg_bar) +
				  cxl->comp_reg_offset + CXL_CM_OFFSET +
				  cxl->hdm_reg_offset,
				  cxl->hdm_reg_size);
	if (!cxl->hdm_iobase) {
		kfree(cxl->comp_reg_virt);
		cxl->comp_reg_virt = NULL;
		return -ENOMEM;
	}

	return 0;
}

/*
 * Called with memory_lock write side held (from vfio_cxl_reactivate_region).
 * Uses the pre-established hdm_iobase, no ioremap() under the lock,
 * which would deadlock on PREEMPT_RT where ioremap() can sleep.
 */
void vfio_cxl_reinit_comp_regs(struct vfio_pci_cxl_state *cxl)
{
	size_t i, nregs;
	u32 n;

	if (!cxl || !cxl->comp_reg_virt || !cxl->hdm_iobase)
		return;

	nregs = cxl->hdm_reg_size / sizeof(__le32);

	for (i = 0; i < nregs; i++)
		*hdm_reg_ptr(cxl, i * sizeof(__le32)) =
			cpu_to_le32(readl(cxl->hdm_iobase +
					  i * sizeof(__le32)));

	/*
	 * For firmware-committed decoders, clear COMMIT_LOCK (bit 8) and zero
	 * BASE in comp_reg_virt[] so QEMU can write the correct guest GPA via
	 * setup_locked_hdm() before guest DPA access begins.
	 *
	 * Check the COMMITTED bit (bit 10) directly from the freshly-snapshotted
	 * ctrl register rather than relying on cxl->precommitted.  At probe time
	 * this function is called before cxl->precommitted is set (it is set
	 * after vfio_cxl_read_committed_decoder_size() succeeds), so using
	 * cxl->precommitted here would silently skip the LOCK clearing and leave
	 * the hardware HPA in comp_reg_virt[].
	 */
	for (n = 0; n < cxl->hdm_count; n++) {
		u32 ctrl_off = CXL_HDM_DECODER_FIRST_BLOCK_OFFSET +
			n * CXL_HDM_DECODER_BLOCK_STRIDE +
			CXL_HDM_DECODER_N_CTRL_OFFSET;
		u32 base_lo_off = CXL_HDM_DECODER_FIRST_BLOCK_OFFSET +
			n * CXL_HDM_DECODER_BLOCK_STRIDE +
			CXL_HDM_DECODER_N_BASE_LOW_OFFSET;
		u32 base_hi_off = CXL_HDM_DECODER_FIRST_BLOCK_OFFSET +
			n * CXL_HDM_DECODER_BLOCK_STRIDE +
			CXL_HDM_DECODER_N_BASE_HIGH_OFFSET;
		u32 ctrl = le32_to_cpu(*hdm_reg_ptr(cxl, ctrl_off));

		if (!(ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED))
			continue;

		if (ctrl & CXL_HDM_DECODER0_CTRL_LOCK) {
			*hdm_reg_ptr(cxl, ctrl_off) =
				cpu_to_le32(ctrl &
					    ~CXL_HDM_DECODER0_CTRL_LOCK);
			*hdm_reg_ptr(cxl, base_lo_off) = 0;
			*hdm_reg_ptr(cxl, base_hi_off) = 0;
		}
	}
}

void vfio_cxl_clean_virt_regs(struct vfio_pci_cxl_state *cxl)
{
	if (cxl->hdm_iobase) {
		iounmap(cxl->hdm_iobase);
		cxl->hdm_iobase = NULL;
	}
	kfree(cxl->comp_reg_virt);
	cxl->comp_reg_virt = NULL;
}
