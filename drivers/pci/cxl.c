// SPDX-License-Identifier: GPL-2.0
/*
 * CXL PCI state save/restore support.
 *
 * Saves and restores CXL DVSEC and HDM decoder registers across PCI resets
 * and link disable/enable transitions. Hooked into pci_save_state() /
 * pci_restore_state() via the PCI capability save chain.
 */
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/cleanup.h>
#include <cxl/cxl.h>
#include <cxl/pci.h>
#include "pci.h"

#define CXL_HDM_MAX_DECODERS 32

struct cxl_hdm_decoder_snapshot {
	u32 base_lo;
	u32 base_hi;
	u32 size_lo;
	u32 size_hi;
	u32 ctrl;
	u32 tl_lo;
	u32 tl_hi;
};

struct cxl_pci_state {
	/* DVSEC saved state */
	u16 dvsec;
	u16 dvsec_ctrl;
	u16 dvsec_ctrl2;
	u32 range_base_hi[CXL_DVSEC_RANGE_MAX];
	u32 range_base_lo[CXL_DVSEC_RANGE_MAX];
	u16 dvsec_lock;
	bool dvsec_valid;

	/* HDM decoder saved state */
	int hdm_bar;
	unsigned long hdm_bar_offset;
	unsigned long hdm_map_size;
	u32 hdm_global_ctrl;
	int hdm_count;
	struct cxl_hdm_decoder_snapshot decoders[CXL_HDM_MAX_DECODERS];
	bool hdm_valid;
};

static void cxl_save_dvsec(struct pci_dev *pdev, struct cxl_pci_state *state)
{
	int rc_ctrl, rc_ctrl2;
	u16 dvsec;
	int i;

	dvsec = pci_find_dvsec_capability(pdev, PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_DEVICE);
	if (!dvsec)
		return;

	state->dvsec = dvsec;
	rc_ctrl = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CTRL,
				       &state->dvsec_ctrl);
	rc_ctrl2 = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CTRL2,
					&state->dvsec_ctrl2);
	if (rc_ctrl || rc_ctrl2) {
		pci_warn(pdev,
			 "CXL: DVSEC read failed (ctrl rc=%d, ctrl2 rc=%d)\n",
			 rc_ctrl, rc_ctrl2);
		return;
	}

	for (i = 0; i < CXL_DVSEC_RANGE_MAX; i++) {
		pci_read_config_dword(pdev,
			dvsec + PCI_DVSEC_CXL_RANGE_BASE_HIGH(i),
			&state->range_base_hi[i]);
		pci_read_config_dword(pdev,
			dvsec + PCI_DVSEC_CXL_RANGE_BASE_LOW(i),
			&state->range_base_lo[i]);
	}

	pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_LOCK,
			     &state->dvsec_lock);

	state->dvsec_valid = true;
}

static u32 cxl_merge_rwl(u32 saved, u32 current_hw, u32 rwl_mask)
{
	return (current_hw & rwl_mask) | (saved & ~rwl_mask);
}

static void cxl_restore_dvsec(struct pci_dev *pdev,
			      const struct cxl_pci_state *state)
{
	u16 lock_reg = 0;
	int i;

	if (!state->dvsec_valid)
		return;

	pci_read_config_word(pdev, state->dvsec + PCI_DVSEC_CXL_LOCK,
			     &lock_reg);

	if (lock_reg & PCI_DVSEC_CXL_LOCK_CONFIG) {
		u16 hw_ctrl;
		u32 hw_range_hi, hw_range_lo;

		pci_read_config_word(pdev,
				     state->dvsec + PCI_DVSEC_CXL_CTRL,
				     &hw_ctrl);
		pci_write_config_word(pdev,
			state->dvsec + PCI_DVSEC_CXL_CTRL,
			cxl_merge_rwl(state->dvsec_ctrl, hw_ctrl,
				      PCI_DVSEC_CXL_CTRL_RWL));

		pci_write_config_word(pdev,
			state->dvsec + PCI_DVSEC_CXL_CTRL2,
			state->dvsec_ctrl2);

		for (i = 0; i < CXL_DVSEC_RANGE_MAX; i++) {
			pci_read_config_dword(pdev,
				state->dvsec + PCI_DVSEC_CXL_RANGE_BASE_HIGH(i),
				&hw_range_hi);
			pci_write_config_dword(pdev,
				state->dvsec + PCI_DVSEC_CXL_RANGE_BASE_HIGH(i),
				cxl_merge_rwl(state->range_base_hi[i],
					      hw_range_hi,
					      PCI_DVSEC_CXL_RANGE_BASE_HI_RWL));

			pci_read_config_dword(pdev,
				state->dvsec + PCI_DVSEC_CXL_RANGE_BASE_LOW(i),
				&hw_range_lo);
			pci_write_config_dword(pdev,
				state->dvsec + PCI_DVSEC_CXL_RANGE_BASE_LOW(i),
				cxl_merge_rwl(state->range_base_lo[i],
					      hw_range_lo,
					      PCI_DVSEC_CXL_RANGE_BASE_LO_RWL));
		}
	} else {
		pci_write_config_word(pdev,
				      state->dvsec + PCI_DVSEC_CXL_CTRL,
				      state->dvsec_ctrl);
		pci_write_config_word(pdev,
				      state->dvsec + PCI_DVSEC_CXL_CTRL2,
				      state->dvsec_ctrl2);
		for (i = 0; i < CXL_DVSEC_RANGE_MAX; i++) {
			pci_write_config_dword(pdev,
				state->dvsec + PCI_DVSEC_CXL_RANGE_BASE_HIGH(i),
				state->range_base_hi[i]);
			pci_write_config_dword(pdev,
				state->dvsec + PCI_DVSEC_CXL_RANGE_BASE_LOW(i),
				state->range_base_lo[i]);
		}

		pci_write_config_word(pdev,
			state->dvsec + PCI_DVSEC_CXL_LOCK,
			state->dvsec_lock);
	}
}

struct pci_cmd_saved {
	struct pci_dev *pdev;
	u16 cmd;
};

DEFINE_FREE(restore_pci_cmd, struct pci_cmd_saved,
	    if (!(_T.cmd & PCI_COMMAND_MEMORY))
		    pci_write_config_word(_T.pdev, PCI_COMMAND, _T.cmd))

/**
 * cxl_find_component_regblock - Find the Component Register Block via
 *                               the Register Locator DVSEC
 * @pdev: PCI device to scan
 * @bir: output BAR index
 * @offset: output offset within the BAR
 *
 * Parses the Register Locator DVSEC (ID 8) directly via PCI config space
 * reads.  No dependency on CXL module symbols.
 *
 * Return: 0 on success, -ENODEV if not found.
 */
static int cxl_find_component_regblock(struct pci_dev *pdev,
				       int *bir, u64 *offset)
{
	u32 regloc_size, regblocks;
	u16 regloc;
	int i;

	regloc = pci_find_dvsec_capability(pdev, PCI_VENDOR_ID_CXL,
					   PCI_DVSEC_CXL_REG_LOCATOR);
	if (!regloc)
		return -ENODEV;

	pci_read_config_dword(pdev, regloc + PCI_DVSEC_HEADER1, &regloc_size);
	regloc_size = PCI_DVSEC_HEADER1_LEN(regloc_size);
	regblocks = (regloc_size - PCI_DVSEC_CXL_REG_LOCATOR_BLOCK1) / 8;

	for (i = 0; i < regblocks; i++) {
		u32 reg_lo, reg_hi;
		unsigned int off;

		off = regloc + PCI_DVSEC_CXL_REG_LOCATOR_BLOCK1 + i * 8;
		pci_read_config_dword(pdev, off, &reg_lo);
		pci_read_config_dword(pdev, off + 4, &reg_hi);

		if (FIELD_GET(PCI_DVSEC_CXL_REG_LOCATOR_BLOCK_ID, reg_lo) !=
		    CXL_REGLOC_RBI_COMPONENT)
			continue;

		*bir = FIELD_GET(PCI_DVSEC_CXL_REG_LOCATOR_BIR, reg_lo);
		*offset = ((u64)reg_hi << 32) |
			  (reg_lo & PCI_DVSEC_CXL_REG_LOCATOR_BLOCK_OFF_LOW);
		return 0;
	}

	return -ENODEV;
}

/*
 * Discover and map HDM decoder registers.
 * Caller must pci_iounmap() the returned pointer.
 */
static void __iomem *cxl_hdm_map(struct pci_dev *pdev, int *bar_out,
				  unsigned long *offset_out,
				  unsigned long *size_out)
{
	int bir;
	u64 reg_offset;
	void __iomem *comp_base, *cm_base;
	u32 cap_hdr;
	int cap, cap_count;
	unsigned long hdm_offset = 0, hdm_size = 0;
	void __iomem *hdm;

	if (cxl_find_component_regblock(pdev, &bir, &reg_offset))
		return NULL;

	comp_base = pci_iomap_range(pdev, bir, reg_offset,
				    CXL_CM_OFFSET + SZ_4K);
	if (!comp_base)
		return NULL;

	cm_base = comp_base + CXL_CM_OFFSET;
	cap_hdr = readl(cm_base);

	if (FIELD_GET(CXL_CM_CAP_HDR_ID_MASK, cap_hdr) != CM_CAP_HDR_CAP_ID) {
		pci_iounmap(pdev, comp_base);
		return NULL;
	}

	cap_count = FIELD_GET(CXL_CM_CAP_HDR_ARRAY_SIZE_MASK, cap_hdr);

	for (cap = 1; cap <= cap_count; cap++) {
		u32 hdr = readl(cm_base + cap * 4);
		u16 cap_id = FIELD_GET(CXL_CM_CAP_HDR_ID_MASK, hdr);
		u32 cap_off = FIELD_GET(CXL_CM_CAP_PTR_MASK, hdr);

		if (cap_id != CXL_CM_CAP_CAP_ID_HDM)
			continue;

		hdr = readl(cm_base + cap_off);
		hdm_offset = CXL_CM_OFFSET + cap_off;
		hdm_size = 0x20 * cxl_hdm_decoder_count(hdr) + 0x10;
		break;
	}

	pci_iounmap(pdev, comp_base);

	if (!hdm_size)
		return NULL;

	hdm = pci_iomap_range(pdev, bir, reg_offset + hdm_offset, hdm_size);
	if (!hdm)
		return NULL;

	*bar_out = bir;
	*offset_out = reg_offset + hdm_offset;
	*size_out = hdm_size;
	return hdm;
}

static void cxl_save_hdm(struct pci_dev *pdev, void __iomem *hdm,
			  struct cxl_pci_state *state, int count)
{
	int i;

	state->hdm_count = min_t(int, count, CXL_HDM_MAX_DECODERS);
	state->hdm_global_ctrl = readl(hdm + CXL_HDM_DECODER_CTRL_OFFSET);

	for (i = 0; i < state->hdm_count; i++) {
		struct cxl_hdm_decoder_snapshot *d = &state->decoders[i];

		d->base_lo = readl(hdm + CXL_HDM_DECODER0_BASE_LOW_OFFSET(i));
		d->base_hi = readl(hdm + CXL_HDM_DECODER0_BASE_HIGH_OFFSET(i));
		d->size_lo = readl(hdm + CXL_HDM_DECODER0_SIZE_LOW_OFFSET(i));
		d->size_hi = readl(hdm + CXL_HDM_DECODER0_SIZE_HIGH_OFFSET(i));
		d->ctrl    = readl(hdm + CXL_HDM_DECODER0_CTRL_OFFSET(i));
		d->tl_lo   = readl(hdm + CXL_HDM_DECODER0_TL_LOW(i));
		d->tl_hi   = readl(hdm + CXL_HDM_DECODER0_TL_HIGH(i));
	}
}

static void cxl_restore_hdm(struct pci_dev *pdev, void __iomem *hdm,
			     const struct cxl_pci_state *state)
{
	int i;

	writel(state->hdm_global_ctrl, hdm + CXL_HDM_DECODER_CTRL_OFFSET);

	for (i = 0; i < state->hdm_count; i++) {
		const struct cxl_hdm_decoder_snapshot *d = &state->decoders[i];
		unsigned long timeout;
		u32 ctrl;

		if (!(d->ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED))
			continue;

		ctrl = readl(hdm + CXL_HDM_DECODER0_CTRL_OFFSET(i));
		if ((ctrl & CXL_HDM_DECODER0_CTRL_LOCK) &&
		    (ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED))
			continue;

		if (ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED) {
			ctrl &= ~CXL_HDM_DECODER0_CTRL_COMMIT;
			writel(ctrl, hdm + CXL_HDM_DECODER0_CTRL_OFFSET(i));
		}

		writel(d->base_lo, hdm + CXL_HDM_DECODER0_BASE_LOW_OFFSET(i));
		writel(d->base_hi, hdm + CXL_HDM_DECODER0_BASE_HIGH_OFFSET(i));
		writel(d->size_lo, hdm + CXL_HDM_DECODER0_SIZE_LOW_OFFSET(i));
		writel(d->size_hi, hdm + CXL_HDM_DECODER0_SIZE_HIGH_OFFSET(i));
		writel(d->tl_lo, hdm + CXL_HDM_DECODER0_TL_LOW(i));
		writel(d->tl_hi, hdm + CXL_HDM_DECODER0_TL_HIGH(i));

		wmb();

		ctrl = d->ctrl & ~(CXL_HDM_DECODER0_CTRL_COMMITTED |
				   CXL_HDM_DECODER0_CTRL_COMMIT_ERROR);
		ctrl |= CXL_HDM_DECODER0_CTRL_COMMIT;
		writel(ctrl, hdm + CXL_HDM_DECODER0_CTRL_OFFSET(i));

		timeout = jiffies + msecs_to_jiffies(10);
		for (;;) {
			ctrl = readl(hdm + CXL_HDM_DECODER0_CTRL_OFFSET(i));
			if (ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED)
				break;
			if (ctrl & CXL_HDM_DECODER0_CTRL_COMMIT_ERROR) {
				pci_warn(pdev,
					 "HDM decoder %d commit error on restore\n",
					 i);
				break;
			}
			if (time_after(jiffies, timeout)) {
				pci_warn(pdev,
					 "HDM decoder %d commit timeout on restore\n",
					 i);
				break;
			}
			cpu_relax();
		}
	}
}

static void cxl_save_hdm_decoders(struct pci_dev *pdev,
				   struct cxl_pci_state *state)
{
	int hdm_bar;
	unsigned long hdm_bar_offset, hdm_map_size;
	void __iomem *hdm;
	u16 cmd;
	u32 cap;
	struct pci_cmd_saved saved __free(restore_pci_cmd) = {
		.pdev = pdev, .cmd = PCI_COMMAND_MEMORY,
	};

	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	saved.cmd = cmd;
	if (!(cmd & PCI_COMMAND_MEMORY))
		pci_write_config_word(pdev, PCI_COMMAND,
				      cmd | PCI_COMMAND_MEMORY);

	hdm = cxl_hdm_map(pdev, &hdm_bar, &hdm_bar_offset, &hdm_map_size);
	if (!hdm)
		return;

	cap = readl(hdm + CXL_HDM_DECODER_CAP_OFFSET);
	cxl_save_hdm(pdev, hdm, state, cxl_hdm_decoder_count(cap));
	state->hdm_bar = hdm_bar;
	state->hdm_bar_offset = hdm_bar_offset;
	state->hdm_map_size = hdm_map_size;
	state->hdm_valid = true;
	pci_iounmap(pdev, hdm);
}

static void cxl_restore_hdm_decoders(struct pci_dev *pdev,
				      const struct cxl_pci_state *state)
{
	void __iomem *hdm;
	u16 cmd;
	struct pci_cmd_saved saved __free(restore_pci_cmd) = {
		.pdev = pdev, .cmd = PCI_COMMAND_MEMORY,
	};

	if (!state->hdm_valid)
		return;

	pci_read_config_word(pdev, PCI_COMMAND, &cmd);
	saved.cmd = cmd;
	if (!(cmd & PCI_COMMAND_MEMORY))
		pci_write_config_word(pdev, PCI_COMMAND,
				      cmd | PCI_COMMAND_MEMORY);

	hdm = pci_iomap_range(pdev, state->hdm_bar, state->hdm_bar_offset,
			      state->hdm_map_size);
	if (!hdm) {
		pci_warn(pdev, "CXL: failed to map HDM for restore\n");
		return;
	}

	cxl_restore_hdm(pdev, hdm, state);
	pci_iounmap(pdev, hdm);
}

void pci_allocate_cxl_save_buffer(struct pci_dev *dev)
{
	if (!pcie_is_cxl(dev))
		return;

	if (pci_add_virtual_ext_cap_save_buffer(dev,
			PCI_EXT_CAP_ID_CXL_DVSEC_VIRTUAL,
			sizeof(struct cxl_pci_state)))
		pci_err(dev, "unable to allocate CXL save buffer\n");
}

void pci_save_cxl_state(struct pci_dev *pdev)
{
	struct pci_cap_saved_state *save_state;
	struct cxl_pci_state *state;

	save_state = pci_find_saved_ext_cap(pdev,
					    PCI_EXT_CAP_ID_CXL_DVSEC_VIRTUAL);
	if (!save_state)
		return;

	state = (struct cxl_pci_state *)save_state->cap.data;
	state->dvsec_valid = false;
	state->hdm_valid = false;

	cxl_save_dvsec(pdev, state);
	cxl_save_hdm_decoders(pdev, state);
}

void pci_restore_cxl_state(struct pci_dev *pdev)
{
	struct pci_cap_saved_state *save_state;
	struct cxl_pci_state *state;

	save_state = pci_find_saved_ext_cap(pdev,
					    PCI_EXT_CAP_ID_CXL_DVSEC_VIRTUAL);
	if (!save_state)
		return;

	state = (struct cxl_pci_state *)save_state->cap.data;
	if (!state->dvsec_valid && !state->hdm_valid)
		return;

	cxl_restore_dvsec(pdev, state);
	cxl_restore_hdm_decoders(pdev, state);
}
