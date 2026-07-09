// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2026 NVIDIA Corporation. All rights reserved. */
#include <linux/delay.h>
#include <linux/bug.h>
#include <linux/bitfield.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include <cxlpci.h>

#include "cxl.h"
#include "core.h"

struct cxl_rwsem cxl_rwsem = {
	.region = __RWSEM_INITIALIZER(cxl_rwsem.region),
	.dpa = __RWSEM_INITIALIZER(cxl_rwsem.dpa),
};
EXPORT_SYMBOL_FOR_MODULES(cxl_rwsem, "cxl_core");

static void cxld_set_interleave(struct cxl_decoder_settings *settings, u32 *ctrl)
{
	u16 eig;
	u8 eiw;

	/*
	 * Input validation ensures these warns never fire, but otherwise
	 * suppress uninitialized variable usage warnings.
	 */
	if (WARN_ONCE(ways_to_eiw(settings->interleave_ways, &eiw),
		      "invalid interleave_ways: %d\n",
		      settings->interleave_ways))
		return;
	if (WARN_ONCE(granularity_to_eig(settings->interleave_granularity, &eig),
		      "invalid interleave_granularity: %d\n",
		      settings->interleave_granularity))
		return;

	u32p_replace_bits(ctrl, eig, CXL_HDM_DECODER0_CTRL_IG_MASK);
	u32p_replace_bits(ctrl, eiw, CXL_HDM_DECODER0_CTRL_IW_MASK);
	*ctrl |= CXL_HDM_DECODER0_CTRL_COMMIT;
}

static void cxld_set_type(struct cxl_decoder_settings *settings, u32 *ctrl)
{
	u32p_replace_bits(ctrl,
			  !!(settings->target_type == CXL_DECODER_HOSTONLYMEM),
			  CXL_HDM_DECODER0_CTRL_HOSTONLY);
}

/*
 * Per CXL 2.0 8.2.5.12.20 Committing Decoder Programming, hardware must set
 * committed or error within 10ms, but just be generous with 20ms to account for
 * clock skew and other marginal behavior.
 */
#define COMMIT_TIMEOUT_MS 20
static int cxld_await_commit(void __iomem *hdm, int id)
{
	u32 ctrl;
	int i;

	for (i = 0; i < COMMIT_TIMEOUT_MS; i++) {
		ctrl = readl(hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));
		if (FIELD_GET(CXL_HDM_DECODER0_CTRL_COMMIT_ERROR, ctrl)) {
			ctrl &= ~CXL_HDM_DECODER0_CTRL_COMMIT;
			writel(ctrl, hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));
			return -EIO;
		}
		if (FIELD_GET(CXL_HDM_DECODER0_CTRL_COMMITTED, ctrl))
			return 0;
		fsleep(1000);
	}

	return -ETIMEDOUT;
}

static void setup_hw_decoder(struct cxl_decoder_settings *settings,
			     void __iomem *hdm)
{
	int id = settings->id;
	u64 target_or_skip;
	u64 base, size;
	u32 ctrl;

	ctrl = readl(hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));
	cxld_set_interleave(settings, &ctrl);
	cxld_set_type(settings, &ctrl);
	base = settings->hpa_range.start;
	size = range_len(&settings->hpa_range);
	target_or_skip = settings->targets;

	writel(upper_32_bits(base), hdm + CXL_HDM_DECODER0_BASE_HIGH_OFFSET(id));
	writel(lower_32_bits(base), hdm + CXL_HDM_DECODER0_BASE_LOW_OFFSET(id));
	writel(upper_32_bits(size), hdm + CXL_HDM_DECODER0_SIZE_HIGH_OFFSET(id));
	writel(lower_32_bits(size), hdm + CXL_HDM_DECODER0_SIZE_LOW_OFFSET(id));
	/* Target-list and endpoint-skip registers alias the same slot. */
	writel(upper_32_bits(target_or_skip),
	       hdm + CXL_HDM_DECODER0_TL_HIGH(id));
	writel(lower_32_bits(target_or_skip),
	       hdm + CXL_HDM_DECODER0_TL_LOW(id));

	writel(ctrl, hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));
}

int cxl_commit(struct cxl_decoder_settings *settings, void __iomem *hdm)
{
	int rc;

	scoped_guard(rwsem_read, &cxl_rwsem.dpa) {
		setup_hw_decoder(settings, hdm);
	}

	rc = cxld_await_commit(hdm, settings->id);
	if (rc)
		return rc;

	settings->flags |= CXL_DECODER_F_ENABLE;

	return 0;
}
EXPORT_SYMBOL_FOR_MODULES(cxl_commit, "cxl_core");

int cxl_hdm_decode_decoder(struct cxl_decoder_settings *settings, int id,
			   u32 ctrl, u64 base, u64 size, u64 target_or_skip,
			   bool *committed)
{
	bool enabled = FIELD_GET(CXL_HDM_DECODER0_CTRL_COMMITTED, ctrl);
	int rc;

	*settings = (struct cxl_decoder_settings) {
		.id = id,
		.targets = target_or_skip,
		.target_type = FIELD_GET(CXL_HDM_DECODER0_CTRL_HOSTONLY, ctrl) ?
			       CXL_DECODER_HOSTONLYMEM : CXL_DECODER_DEVMEM,
	};

	if (committed)
		*committed = enabled;
	if (!enabled)
		size = 0;
	if (base == U64_MAX || size == U64_MAX ||
	    (size && base > U64_MAX - (size - 1)))
		return -ENXIO;
	if (enabled && !size)
		return -ENXIO;

	settings->hpa_range = (struct range) {
		.start = base,
		.end = base + size - 1,
	};
	if (enabled) {
		settings->flags = CXL_DECODER_F_ENABLE;
		if (ctrl & CXL_HDM_DECODER0_CTRL_LOCK)
			settings->flags |= CXL_DECODER_F_LOCK;
	}

	rc = eiw_to_ways(FIELD_GET(CXL_HDM_DECODER0_CTRL_IW_MASK, ctrl),
			 &settings->interleave_ways);
	if (rc)
		return rc;

	return eig_to_granularity(FIELD_GET(CXL_HDM_DECODER0_CTRL_IG_MASK,
				    ctrl),
				  &settings->interleave_granularity);
}
EXPORT_SYMBOL_FOR_MODULES(cxl_hdm_decode_decoder, "cxl_core");

struct cxl_hdm_decoder_state {
	u32 ctrl;
	u32 base_low;
	u32 base_high;
	u32 size_low;
	u32 size_high;
	u32 target_low;
	u32 target_high;
};

void pci_cxl_hdm_release(struct pci_dev *pdev)
{
	struct cxl_hdm_info *info;

	scoped_guard(rwsem_write, &cxl_rwsem.dpa) {
		info = pdev->hdm;
		pdev->hdm = NULL;
	}
	if (!info)
		return;

	kfree(info->decoder_state);
	kfree(info);
}

static int cxl_pci_hdm_find_bar(struct pci_dev *pdev, resource_size_t hdm_start,
				resource_size_t hdm_size, int *bar,
				resource_size_t *offset)
{
	resource_size_t hdm_end = hdm_start + hdm_size - 1;

	for (int i = 0; i < PCI_STD_NUM_BARS; i++) {
		struct resource *res = &pdev->resource[i];

		if (!pci_resource_len(pdev, i))
			continue;
		if (resource_type(res) != IORESOURCE_MEM)
			continue;
		if (hdm_start < res->start || hdm_end > res->end)
			continue;

		*bar = i;
		*offset = hdm_start - res->start;
		return 0;
	}

	return -ENODEV;
}

static void __iomem *cxl_pci_hdm_map(struct pci_dev *pdev,
				     struct cxl_register_map *map,
				     struct cxl_hdm_info *info)
{
	struct cxl_reg_map *hdm_map = &map->component_map.hdm_decoder;
	resource_size_t hdm_start;
	void __iomem *hdm;
	int rc;

	hdm_start = map->resource + hdm_map->offset;
	info->hdm_size = hdm_map->size;

	rc = cxl_pci_hdm_find_bar(pdev, hdm_start, info->hdm_size,
				  &info->hdm_bar, &info->hdm_offset);
	if (rc)
		return ERR_PTR(rc);

	hdm = ioremap(hdm_start, info->hdm_size);
	if (!hdm) {
		pci_err(pdev, "failed to map CXL HDM decoder registers\n");
		return ERR_PTR(-ENOMEM);
	}

	return hdm;
}

static void cxl_pci_hdm_read_decoder_state(struct cxl_hdm_decoder_state *state,
					   void __iomem *hdm, int id)
{
	state->ctrl = readl(hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));
	state->base_low = readl(hdm + CXL_HDM_DECODER0_BASE_LOW_OFFSET(id));
	state->base_high = readl(hdm + CXL_HDM_DECODER0_BASE_HIGH_OFFSET(id));
	state->size_low = readl(hdm + CXL_HDM_DECODER0_SIZE_LOW_OFFSET(id));
	state->size_high = readl(hdm + CXL_HDM_DECODER0_SIZE_HIGH_OFFSET(id));
	state->target_low = readl(hdm + CXL_HDM_DECODER0_TL_LOW(id));
	state->target_high = readl(hdm + CXL_HDM_DECODER0_TL_HIGH(id));
}

static int cxl_pci_hdm_read_decoder(struct pci_dev *pdev,
				    struct cxl_hdm_decoder_state *state,
				    struct cxl_decoder_settings *settings,
				    void __iomem *hdm, int id)
{
	u64 target_or_skip, base, size;
	bool committed;
	int rc;

	cxl_pci_hdm_read_decoder_state(state, hdm, id);

	base = ((u64)state->base_high << 32) | state->base_low;
	size = ((u64)state->size_high << 32) | state->size_low;
	target_or_skip = ((u64)state->target_high << 32) | state->target_low;

	rc = cxl_hdm_decode_decoder(settings, id, state->ctrl, base, size,
				    target_or_skip, &committed);
	if (rc) {
		pci_err(pdev, "CXL HDM decoder %d has invalid configuration: %d\n",
			id, rc);
		return rc;
	}
	if (!committed)
		return 0;

	return 0;
}

static int cxl_pci_hdm_capable(struct pci_dev *pdev)
{
	u16 cap;
	int dvsec;
	int rc;

	dvsec = pci_find_dvsec_capability(pdev, PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_DEVICE);
	if (!dvsec)
		return -ENOTTY;

	rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CAP, &cap);
	if (rc)
		return pcibios_err_to_errno(rc);

	if (!(cap & PCI_DVSEC_CXL_MEM_CAPABLE))
		return -ENOTTY;

	return 0;
}

static int __pci_cxl_hdm_init(struct pci_dev *pdev)
{
	struct cxl_decoder_settings *settings;
	struct cxl_register_map map = { 0 };
	struct cxl_hdm_info *info;
	void __iomem *hdm = NULL;
	bool restore_command = false;
	bool allocated_info = false;
	int decoder_count;
	u16 command;
	int rc;

	scoped_guard(rwsem_read, &cxl_rwsem.dpa) {
		info = pdev->hdm;
		if (info)
			return 0;
	}

	rc = cxl_pci_hdm_capable(pdev);
	if (rc)
		return rc;

	rc = pci_read_config_word(pdev, PCI_COMMAND, &command);
	if (rc)
		return pcibios_err_to_errno(rc);

	if (!(command & PCI_COMMAND_MEMORY))
		restore_command = true;

	if (restore_command) {
		rc = pci_write_config_word(pdev, PCI_COMMAND,
					   command | PCI_COMMAND_MEMORY);
		if (rc)
			return pcibios_err_to_errno(rc);
	}

	if (!info) {
		info = kzalloc_obj(*info, GFP_KERNEL);
		if (!info)
			goto err_nomem;
		allocated_info = true;
	}

	rc = cxl_find_regblock(pdev, CXL_REGLOC_RBI_COMPONENT, &map);
	if (rc)
		goto out_restore_command;

	rc = cxl_setup_regs(&map);
	if (rc)
		goto out_restore_command;

	if (!map.component_map.hdm_decoder.valid) {
		rc = -ENODEV;
		goto out_restore_command;
	}

	hdm = cxl_pci_hdm_map(pdev, &map, info);
	if (IS_ERR(hdm)) {
		rc = PTR_ERR(hdm);
		hdm = NULL;
		goto out_restore_command;
	}

	decoder_count = cxl_hdm_decoder_count(readl(hdm +
						    CXL_HDM_DECODER_CAP_OFFSET));
	if (decoder_count < 0) {
		rc = decoder_count;
		goto out_unmap;
	}

	if (decoder_count > CXL_HDM_DECODER_MAX_COUNT) {
		rc = -ENXIO;
		goto out_unmap;
	}

	if (info->decoder_count && info->decoder_count != decoder_count) {
		rc = -ENXIO;
		goto out_unmap;
	}

	info->decoder_count = decoder_count;
	info->global_ctrl = readl(hdm + CXL_HDM_DECODER_CTRL_OFFSET);
	info->decoder_state = kcalloc(decoder_count,
				      sizeof(*info->decoder_state),
				      GFP_KERNEL);
	if (!info->decoder_state) {
		rc = -ENOMEM;
		goto out_unmap;
	}

	settings = info->settings;
	for (int i = 0; i < info->decoder_count; i++) {
		rc = cxl_pci_hdm_read_decoder(pdev, &info->decoder_state[i],
					      &settings[i], hdm, i);
		if (rc)
			goto out_unmap;
	}

	if (restore_command) {
		rc = pci_write_config_word(pdev, PCI_COMMAND, command);
		if (rc)
			goto out_restore_failed;
	}

	scoped_guard(rwsem_write, &cxl_rwsem.dpa) {
		if (pdev->hdm)
			goto out_unmap;
		pdev->hdm = info;
	}
	iounmap(hdm);
	return 0;

out_restore_failed:
	rc = pcibios_err_to_errno(rc);
	goto out_unmap;
err_nomem:
	rc = -ENOMEM;
	goto out_restore_command;
out_unmap:
	if (hdm)
		iounmap(hdm);
out_restore_command:
	if (allocated_info) {
		kfree(info->decoder_state);
		kfree(info);
	}
	if (restore_command) {
		int rc2;

		rc2 = pci_write_config_word(pdev, PCI_COMMAND, command);
		if (rc2 && !rc)
			rc = pcibios_err_to_errno(rc2);
	}
	return rc;
}

void pci_cxl_hdm_init(struct pci_dev *pdev)
{
	int rc;

	rc = __pci_cxl_hdm_init(pdev);
	if (rc && rc != -ENOTTY && rc != -ENODEV)
		pci_dbg(pdev, "CXL HDM cache init failed: %d\n", rc);
}
