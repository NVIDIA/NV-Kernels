// SPDX-License-Identifier: GPL-2.0
/*
 * CXL PCI state save/restore support.
 *
 * Saves and restores CXL DVSEC registers across PCI resets and link
 * disable/enable transitions. Hooked into pci_save_state() /
 * pci_restore_state() via the PCI capability save chain.
 */
#include <linux/pci.h>
#include <cxl/pci.h>
#include "pci.h"

struct cxl_pci_state {
	u16 dvsec;
	u16 dvsec_ctrl;
	u16 dvsec_ctrl2;
	u32 range_base_hi[CXL_DVSEC_RANGE_MAX];
	u32 range_base_lo[CXL_DVSEC_RANGE_MAX];
	u16 dvsec_lock;
	bool dvsec_valid;
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

	cxl_save_dvsec(pdev, state);
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
	if (!state->dvsec_valid)
		return;

	cxl_restore_dvsec(pdev, state);
}
