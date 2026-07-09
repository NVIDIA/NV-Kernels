// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2026 NVIDIA Corporation. All rights reserved. */
#include <linux/bitmap.h>
#include <linux/delay.h>
#include <linux/bug.h>
#include <linux/bitfield.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/iommu.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/memregion.h>
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

static int cxld_await_uncommit(void __iomem *hdm, int id)
{
	u32 ctrl;
	int i;

	for (i = 0; i < COMMIT_TIMEOUT_MS; i++) {
		ctrl = readl(hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));
		if (!FIELD_GET(CXL_HDM_DECODER0_CTRL_COMMITTED, ctrl))
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
	ctrl &= ~(CXL_HDM_DECODER0_CTRL_COMMIT |
		  CXL_HDM_DECODER0_CTRL_COMMIT_ERROR);
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

static void __iomem *cxl_pci_hdm_ioremap_current(struct pci_dev *pdev,
						 int bar,
						 resource_size_t offset,
						 resource_size_t size)
{
	resource_size_t hdm_start, bar_len;
	void __iomem *hdm;

	if (bar < 0 || bar >= PCI_STD_NUM_BARS || !size)
		return ERR_PTR(-EINVAL);

	bar_len = pci_resource_len(pdev, bar);
	if (!bar_len || offset > bar_len || size > bar_len - offset)
		return ERR_PTR(-ENODEV);

	hdm_start = pci_resource_start(pdev, bar) + offset;
	hdm = ioremap(hdm_start, size);
	if (!hdm) {
		pci_err(pdev, "failed to remap CXL HDM decoder registers\n");
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

static int cxl_hdm_enable_mem(struct pci_dev *pdev, u16 *command,
			      bool *restore_command)
{
	int rc;

	*restore_command = false;

	rc = pci_read_config_word(pdev, PCI_COMMAND, command);
	if (rc)
		return pcibios_err_to_errno(rc);

	if (*command & PCI_COMMAND_MEMORY)
		return 0;

	rc = pci_write_config_word(pdev, PCI_COMMAND,
				   *command | PCI_COMMAND_MEMORY);
	if (rc)
		return pcibios_err_to_errno(rc);

	*restore_command = true;
	return 0;
}

static int cxl_hdm_restore_command(struct pci_dev *pdev, u16 command)
{
	int rc;

	rc = pci_write_config_word(pdev, PCI_COMMAND, command);
	if (rc)
		return pcibios_err_to_errno(rc);

	return 0;
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

static int cxl_hdm_decoder_uncommit(struct pci_dev *pdev, void __iomem *hdm,
				    int id, bool *locked_committed)
{
	u32 ctrl;
	int rc;

	*locked_committed = false;
	ctrl = readl(hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));
	if (ctrl & CXL_HDM_DECODER0_CTRL_LOCK) {
		if (ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED) {
			pci_dbg(pdev,
				"CXL HDM decoder %d retained locked committed state\n",
				id);
			*locked_committed = true;
			return 0;
		}

		pci_err(pdev, "CXL HDM decoder %d is locked\n", id);
		return -EBUSY;
	}

	if (!(ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED))
		return 0;

	ctrl &= ~CXL_HDM_DECODER0_CTRL_COMMIT;
	writel(ctrl, hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));

	rc = cxld_await_uncommit(hdm, id);
	if (rc)
		pci_err(pdev, "CXL HDM decoder %d uncommit failed: %d\n",
			id, rc);

	return rc;
}

static void cxl_restore_hdm_decoder_state(struct cxl_hdm_decoder_state *state,
					  void __iomem *hdm, int id)
{
	u32 ctrl = state->ctrl;

	ctrl &= ~(CXL_HDM_DECODER0_CTRL_COMMIT |
		  CXL_HDM_DECODER0_CTRL_COMMITTED |
		  CXL_HDM_DECODER0_CTRL_COMMIT_ERROR);

	writel(state->base_high, hdm + CXL_HDM_DECODER0_BASE_HIGH_OFFSET(id));
	writel(state->base_low, hdm + CXL_HDM_DECODER0_BASE_LOW_OFFSET(id));
	writel(state->size_high, hdm + CXL_HDM_DECODER0_SIZE_HIGH_OFFSET(id));
	writel(state->size_low, hdm + CXL_HDM_DECODER0_SIZE_LOW_OFFSET(id));
	writel(state->target_high, hdm + CXL_HDM_DECODER0_TL_HIGH(id));
	writel(state->target_low, hdm + CXL_HDM_DECODER0_TL_LOW(id));
	/* Ensure raw decoder fields are visible before restoring control. */
	wmb();
	writel(ctrl, hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));
}

static int cxl_restore_hdm_decoder(struct pci_dev *pdev,
				   struct cxl_hdm_decoder_state *state,
				   struct cxl_decoder_settings *settings,
				   void __iomem *hdm)
{
	bool locked_committed;
	int rc;

	rc = cxl_hdm_decoder_uncommit(pdev, hdm, settings->id,
				      &locked_committed);
	if (rc)
		return rc;
	if (locked_committed)
		return 0;

	cxl_restore_hdm_decoder_state(state, hdm, settings->id);

	if (!(settings->flags & CXL_DECODER_F_ENABLE))
		return 0;

	rc = cxl_commit(settings, hdm);
	if (rc)
		pci_err(pdev, "CXL HDM decoder %d restore failed: %d\n",
			settings->id, rc);

	return rc;
}

static int cxl_restore_hdm(struct pci_dev *pdev)
{
	struct cxl_hdm_decoder_state *decoder_state __free(kfree) = NULL;
	struct cxl_decoder_settings *settings __free(kfree) = NULL;
	struct cxl_hdm_info *info;
	resource_size_t hdm_offset;
	resource_size_t hdm_size;
	void __iomem *hdm;
	int decoder_count;
	int first_rc = 0;
	u32 global_ctrl;
	bool restore_command = false;
	u16 command;
	int hdm_bar;
	int rc;

	scoped_guard(rwsem_read, &cxl_rwsem.dpa) {
		info = pdev->hdm;
		if (!info)
			return 0;

		decoder_count = info->decoder_count;
		hdm_bar = info->hdm_bar;
		hdm_offset = info->hdm_offset;
		hdm_size = info->hdm_size;
		global_ctrl = info->global_ctrl;
		settings = kmemdup_array(info->settings, decoder_count,
					 sizeof(*settings), GFP_KERNEL);
		if (!settings)
			return -ENOMEM;
		decoder_state = kmemdup_array(info->decoder_state,
					      decoder_count,
					      sizeof(*decoder_state),
					      GFP_KERNEL);
		if (!decoder_state)
			return -ENOMEM;
	}

	rc = cxl_hdm_enable_mem(pdev, &command, &restore_command);
	if (rc)
		return rc;

	hdm = cxl_pci_hdm_ioremap_current(pdev, hdm_bar, hdm_offset, hdm_size);
	if (IS_ERR(hdm)) {
		first_rc = PTR_ERR(hdm);
		goto out_restore_command;
	}

	/*
	 * Restore global HDM control before per-decoder commit. PCI config
	 * memory decoding is enabled for MMIO access, but IOMMU reset blocks
	 * remain active until HDM restore completes.
	 */
	writel(global_ctrl, hdm + CXL_HDM_DECODER_CTRL_OFFSET);

	for (int i = 0; i < decoder_count; i++) {
		int rc;

		rc = cxl_restore_hdm_decoder(pdev, &decoder_state[i],
					     &settings[i], hdm);
		if (rc && !first_rc)
			first_rc = rc;
	}

	iounmap(hdm);
out_restore_command:
	if (restore_command) {
		rc = cxl_hdm_restore_command(pdev, command);
		if (rc && !first_rc)
			first_rc = rc;
	}

	return first_rc;
}

/*
 * CXL r4.0 sec 9.7.2 defines the reset completion timeout encodings.
 * Sec 9.7.3 leaves config-space access behavior undefined for 100 ms after
 * initiating CXL Reset, then limits software to CXL Status2 access until
 * reset completion, timeout, or error.
 */
#define CXL_RESET_RRS_WAIT_MS 100
#define CXL_RESET_STATUS_POLL_MS 20
static const u32 cxl_reset_timeout_ms[] = {
	10, 100, 1000, 10000, 100000,
};

#define CXL_CACHE_WBI_TIMEOUT_US 100000
#define CXL_CACHE_WBI_POLL_US 100

/* CXL r4.0 sec 8.1.4 defines 256 bits of Non-CXL Function Map. */
#define CXL_RESET_MAX_FUNCTIONS 256
#define CXL_RESET_FUNCTION_MAP_REGS (CXL_RESET_MAX_FUNCTIONS / 32)

struct cxl_reset_context {
	struct pci_dev *target;
	bool target_prepared;
};

struct cxl_reset_walk_context {
	struct cxl_reset_context *ctx;
	DECLARE_BITMAP(non_cxl_func_map, CXL_RESET_MAX_FUNCTIONS);
	bool ari;
	int rc;
};

struct cxl_hdm_range {
	struct list_head list;
	struct pci_dev *pdev;
	struct range hpa_range;
	struct resource *res;
};

struct cxl_hdm_range_context {
	struct list_head ranges;
};

static void cxl_reset_context_init(struct cxl_reset_context *ctx,
				   struct pci_dev *pdev)
{
	*ctx = (struct cxl_reset_context) {
		.target = pdev,
	};
}

static void cxl_reset_read_non_cxl_func_map(struct pci_dev *pdev,
					    unsigned long *map)
{
	u32 words[CXL_RESET_FUNCTION_MAP_REGS];
	int dvsec, reg;

	bitmap_zero(map, CXL_RESET_MAX_FUNCTIONS);

	dvsec = pci_find_dvsec_capability(pdev, PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_FUNCTION_MAP);
	if (!dvsec)
		return;

	for (reg = 0; reg < CXL_RESET_FUNCTION_MAP_REGS; reg++) {
		int offset = dvsec + PCI_DVSEC_CXL_FUNCTION_MAP_REG +
			     reg * sizeof(u32);
		int rc;

		rc = pci_read_config_dword(pdev, offset, &words[reg]);
		if (rc) {
			pci_warn(pdev,
				 "failed to read Non-CXL Function Map; treating same-scope functions as CXL\n");
			bitmap_zero(map, CXL_RESET_MAX_FUNCTIONS);
			return;
		}
	}

	bitmap_from_arr32(map, words, CXL_RESET_MAX_FUNCTIONS);
}

static int cxl_reset_func_map_bit(struct pci_dev *sibling, bool ari)
{
	if (ari)
		return sibling->devfn;

	/*
	 * Without ARI, the Function Map is organized as 32 device slots per
	 * conventional 3-bit function number.
	 */
	return PCI_FUNC(sibling->devfn) * 32 + PCI_SLOT(sibling->devfn);
}

static int cxl_reset_read_cxl_cap(struct pci_dev *pdev, u16 *cap)
{
	int dvsec, rc;

	dvsec = pci_find_dvsec_capability(pdev, PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_DEVICE);
	if (!dvsec)
		return -ENODEV;

	rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CAP, cap);
	if (rc) {
		rc = pcibios_err_to_errno(rc);
		pci_warn(pdev, "failed to read CXL capability: %d\n", rc);
		return rc;
	}

	return 0;
}

static int cxl_reset_has_cache_or_mem(struct pci_dev *pdev)
{
	u16 cap;
	int rc;

	rc = cxl_reset_read_cxl_cap(pdev, &cap);
	if (rc == -ENODEV)
		return 0;
	if (rc)
		return rc;

	return !!(cap & (PCI_DVSEC_CXL_CACHE_CAPABLE |
			 PCI_DVSEC_CXL_MEM_CAPABLE));
}

static int cxl_reset_validate_function_scope(struct pci_dev *sibling,
					     void *data)
{
	struct cxl_reset_walk_context *wctx = data;
	struct cxl_reset_context *ctx = wctx->ctx;
	struct pci_dev *pdev = ctx->target;
	int fn, rc;

	if (sibling == pdev)
		return 0;

	if (sibling->bus != pdev->bus)
		return 0;

	if (!wctx->ari && PCI_SLOT(sibling->devfn) != PCI_SLOT(pdev->devfn))
		return 0;

	fn = cxl_reset_func_map_bit(sibling, wctx->ari);
	if (test_bit(fn, wctx->non_cxl_func_map))
		return 0;

	rc = cxl_reset_has_cache_or_mem(sibling);
	if (rc < 0) {
		wctx->rc = rc;
		return rc;
	}
	if (!rc)
		return 0;

	wctx->rc = -ENOTTY;
	return wctx->rc;
}

static int cxl_reset_validate_function_scoped(struct cxl_reset_context *ctx)
{
	struct pci_dev *pdev = ctx->target;
	struct cxl_reset_walk_context wctx = {
		.ctx = ctx,
		.ari = pci_ari_enabled(pdev->bus),
	};

	cxl_reset_read_non_cxl_func_map(pdev, wctx.non_cxl_func_map);
	pci_walk_bus(pdev->bus, cxl_reset_validate_function_scope, &wctx);

	return wctx.rc;
}

static void cxl_pci_target_reset_done(struct cxl_reset_context *ctx)
{
	if (!ctx->target_prepared)
		return;

	pci_dev_reset_iommu_done(ctx->target);
	ctx->target_prepared = false;
}

static int cxl_pci_target_reset_prepare(struct cxl_reset_context *ctx)
{
	struct pci_dev *pdev = ctx->target;
	int rc;

	if (!pci_wait_for_pending_transaction(pdev))
		pci_err(pdev, "timed out waiting for pending transactions\n");

	rc = pci_dev_reset_iommu_prepare(pdev);
	if (rc) {
		pci_err(pdev, "failed to stop IOMMU for CXL reset: %d\n", rc);
		return rc;
	}

	ctx->target_prepared = true;
	return 0;
}

static int cxl_restore_hdm_decoders(struct cxl_reset_context *ctx)
{
	return cxl_restore_hdm(ctx->target);
}

int cxl_restore_hdm_after_pci_reset(struct pci_dev *pdev)
{
	return cxl_restore_hdm(pdev);
}

static void cxl_hdm_range_context_init(struct cxl_hdm_range_context *ctx)
{
	INIT_LIST_HEAD(&ctx->ranges);
}

static void cxl_hdm_range_context_destroy(struct cxl_hdm_range_context *ctx)
{
	struct cxl_hdm_range *range, *next;

	list_for_each_entry_safe(range, next, &ctx->ranges, list) {
		list_del(&range->list);
		if (range->res)
			release_mem_region(range->hpa_range.start,
					   resource_size(range->res));
		kfree(range);
	}
}

static int cxl_hdm_range_add(struct cxl_hdm_range_context *ctx,
			     struct pci_dev *pdev, const struct range *hpa_range)
{
	struct cxl_hdm_range *range;

	if (hpa_range->end < hpa_range->start)
		return -EINVAL;

	list_for_each_entry(range, &ctx->ranges, list)
		if (range->hpa_range.start == hpa_range->start &&
		    range->hpa_range.end == hpa_range->end)
			return 0;

	range = kzalloc_obj(*range);
	if (!range)
		return -ENOMEM;

	range->pdev = pdev;
	range->hpa_range = *hpa_range;
	list_add_tail(&range->list, &ctx->ranges);

	return 0;
}

static int cxl_hdm_ranges_collect(struct cxl_hdm_range_context *ctx,
				  struct pci_dev *pdev)
{
	struct cxl_hdm_info *info;
	int rc;

	guard(rwsem_read)(&cxl_rwsem.dpa);
	info = pdev->hdm;
	if (!info) {
		pci_err(pdev, "CXL HDM decoder state unavailable\n");
		return -ENXIO;
	}

	for (int i = 0; i < info->decoder_count; i++) {
		struct cxl_decoder_settings *settings = &info->settings[i];

		if (!(settings->flags & CXL_DECODER_F_ENABLE))
			continue;

		if (settings->flags & CXL_DECODER_F_NORMALIZED_ADDRESSING) {
			pci_err(pdev,
				"CXL reset does not support normalized address decoders\n");
			return -EOPNOTSUPP;
		}

		rc = cxl_hdm_range_add(ctx, pdev, &settings->hpa_range);
		if (rc)
			return rc;
	}

	return 0;
}

static int cxl_hdm_range_len(struct pci_dev *pdev,
			     const struct range *hpa_range, u64 *len)
{
	if (sizeof(resource_size_t) < sizeof(hpa_range->start) &&
	    (hpa_range->start > (resource_size_t)~0ULL ||
	     hpa_range->end > (resource_size_t)~0ULL)) {
		pci_err(pdev,
			"CXL reset range [%#llx-%#llx] exceeds resource address size\n",
			hpa_range->start, hpa_range->end);
		return -EOVERFLOW;
	}

	if (hpa_range->end < hpa_range->start)
		return -EINVAL;

	if (!hpa_range->start && hpa_range->end == U64_MAX) {
		pci_err(pdev,
			"CXL reset range [%#llx-%#llx] exceeds resource size\n",
			hpa_range->start, hpa_range->end);
		return -EOVERFLOW;
	}

	*len = range_len(hpa_range);
	if (sizeof(resource_size_t) < sizeof(*len) &&
	    *len > (resource_size_t)~0ULL) {
		pci_err(pdev,
			"CXL reset range [%#llx-%#llx] exceeds resource size\n",
			hpa_range->start, hpa_range->end);
		return -EOVERFLOW;
	}

	if (sizeof(size_t) < sizeof(*len) && *len > SIZE_MAX) {
		pci_err(pdev,
			"CXL reset range [%#llx-%#llx] exceeds cache flush size\n",
			hpa_range->start, hpa_range->end);
		return -EOVERFLOW;
	}

	return 0;
}

static int cxl_hdm_range_request(struct cxl_hdm_range *range)
{
	struct pci_dev *pdev = range->pdev;
	const struct range *hpa_range = &range->hpa_range;
	u64 len;
	int rc;

	rc = cxl_hdm_range_len(pdev, hpa_range, &len);
	if (rc)
		return rc;

	range->res = request_mem_region(hpa_range->start, len, "cxl_reset");
	if (!range->res) {
		pci_err(pdev,
			"cannot reset while CXL memory range is busy [%#llx-%#llx]\n",
			hpa_range->start, hpa_range->end);
		return -EBUSY;
	}

	return 0;
}

static int cxl_hdm_ranges_request(struct cxl_hdm_range_context *ctx)
{
	struct cxl_hdm_range *range;
	int rc;

	lockdep_assert_held_write(&cxl_rwsem.region);

	list_for_each_entry(range, &ctx->ranges, list) {
		rc = cxl_hdm_range_request(range);
		if (rc)
			return rc;
	}

	return 0;
}

static int cxl_hdm_range_flush_cache(struct cxl_hdm_range *range)
{
	struct pci_dev *pdev = range->pdev;
	const struct range *hpa_range = &range->hpa_range;
	u64 len;
	int rc;

	rc = cxl_hdm_range_len(pdev, hpa_range, &len);
	if (rc)
		return rc;

	rc = cpu_cache_invalidate_memregion(hpa_range->start, len);
	if (rc)
		pci_err(pdev,
			"failed to invalidate CPU cache [%#llx-%#llx]: %d\n",
			hpa_range->start, hpa_range->end, rc);

	return rc;
}

static int cxl_hdm_ranges_flush_cpu_caches(struct cxl_hdm_range_context *ctx,
					   struct pci_dev *pdev)
{
	struct cxl_hdm_range *range;
	int rc;

	if (list_empty(&ctx->ranges))
		return 0;

	if (!cpu_cache_has_invalidate_memregion()) {
		pci_warn(pdev,
			 "CPU cache synchronization unavailable; continuing without cache invalidation\n");
		return 0;
	}

	list_for_each_entry(range, &ctx->ranges, list) {
		rc = cxl_hdm_range_flush_cache(range);
		if (rc)
			return rc;
	}

	return 0;
}

static int cxl_hdm_ranges_prepare(struct cxl_hdm_range_context *ctx,
				  struct cxl_reset_context *reset_ctx)
{
	struct pci_dev *pdev = reset_ctx->target;
	int rc;

	lockdep_assert_held_write(&cxl_rwsem.region);

	rc = cxl_hdm_ranges_collect(ctx, pdev);
	if (rc)
		return rc;

	rc = cxl_hdm_ranges_request(ctx);
	if (rc)
		return rc;

	return cxl_hdm_ranges_flush_cpu_caches(ctx, pdev);
}

static int cxl_reset_dvsec(struct pci_dev *pdev)
{
	int dvsec, rc;
	u16 cap;

	dvsec = pci_find_dvsec_capability(pdev, PCI_VENDOR_ID_CXL,
					  PCI_DVSEC_CXL_DEVICE);
	if (!dvsec)
		return -ENOTTY;

	rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CAP, &cap);
	if (rc)
		return pcibios_err_to_errno(rc);

	if ((cap & (PCI_DVSEC_CXL_CACHE_CAPABLE |
		    PCI_DVSEC_CXL_MEM_CAPABLE)) !=
	    (PCI_DVSEC_CXL_CACHE_CAPABLE | PCI_DVSEC_CXL_MEM_CAPABLE))
		return -ENOTTY;

	if (!(cap & PCI_DVSEC_CXL_RST_CAPABLE))
		return -ENOTTY;

	return dvsec;
}

static bool cxl_reset_hdm_available(struct pci_dev *pdev)
{
	struct cxl_hdm_info *info;

	/*
	 * pdev->hdm is owned by the PCI device and released with pci_dev, so
	 * reset-method probes and reset requests can test availability without
	 * a CXL driver bound to the device.
	 */
	guard(rwsem_read)(&cxl_rwsem.dpa);
	info = pdev->hdm;
	return info && info->hdm_size;
}

static bool cxl_reset_scope_hdm_available(struct cxl_reset_context *ctx)
{
	return cxl_reset_hdm_available(ctx->target);
}

static int cxl_reset_update_ctrl2(struct pci_dev *pdev, int dvsec, u16 set,
				  u16 clear)
{
	u16 cmd = PCI_DVSEC_CXL_INIT_CACHE_WBI | PCI_DVSEC_CXL_INIT_CXL_RST;
	u16 ctrl2;
	int rc;

	rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CTRL2, &ctrl2);
	if (rc)
		return pcibios_err_to_errno(rc);

	ctrl2 &= ~cmd;
	ctrl2 |= set;
	ctrl2 &= ~clear;

	rc = pci_write_config_word(pdev, dvsec + PCI_DVSEC_CXL_CTRL2, ctrl2);
	if (rc)
		return pcibios_err_to_errno(rc);

	return 0;
}

static int cxl_reset_enable_cache(struct pci_dev *pdev, int dvsec)
{
	return cxl_reset_update_ctrl2(pdev, dvsec, 0,
				      PCI_DVSEC_CXL_DISABLE_CACHING);
}

static int cxl_reset_disable_cache(struct pci_dev *pdev, int dvsec, u16 cap)
{
	int remaining_us = CXL_CACHE_WBI_TIMEOUT_US;
	u16 status2;
	int rc, rc2;

	rc = cxl_reset_update_ctrl2(pdev, dvsec,
				    PCI_DVSEC_CXL_DISABLE_CACHING, 0);
	if (rc)
		return rc;

	if (!(cap & PCI_DVSEC_CXL_CACHE_WBI_CAPABLE))
		return 0;

	rc = cxl_reset_update_ctrl2(pdev, dvsec,
				    PCI_DVSEC_CXL_INIT_CACHE_WBI, 0);
	if (rc)
		goto err_enable_cache;

	do {
		usleep_range(CXL_CACHE_WBI_POLL_US, CXL_CACHE_WBI_POLL_US + 1);
		remaining_us -= CXL_CACHE_WBI_POLL_US;

		rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_STATUS2,
					  &status2);
		if (rc) {
			rc = pcibios_err_to_errno(rc);
			goto err_enable_cache;
		}
	} while (!(status2 & PCI_DVSEC_CXL_CACHE_INV) && remaining_us > 0);

	if (!(status2 & PCI_DVSEC_CXL_CACHE_INV)) {
		rc = -ETIMEDOUT;
		goto err_enable_cache;
	}

	return 0;

err_enable_cache:
	/*
	 * DISABLE_CACHING can be rolled back here. INIT_CACHE_WBI is
	 * self-clearing on completion, so leave any in-flight writeback alone.
	 */
	rc2 = cxl_reset_enable_cache(pdev, dvsec);
	if (rc2)
		pci_warn(pdev, "failed to re-enable CXL caching: %d\n", rc2);
	return rc;
}

static int cxl_reset_wait_done(struct pci_dev *pdev, int dvsec, u16 cap)
{
	unsigned long deadline;
	u32 timeout_ms;
	u16 status2;
	int idx, rc;

	idx = FIELD_GET(PCI_DVSEC_CXL_RST_TIMEOUT, cap);
	if (idx >= ARRAY_SIZE(cxl_reset_timeout_ms)) {
		int last = ARRAY_SIZE(cxl_reset_timeout_ms) - 1;

		pci_warn(pdev,
			 "unknown CXL reset timeout encoding %d; using %u ms\n",
			 idx, cxl_reset_timeout_ms[last]);
		idx = last;
	}

	timeout_ms = max_t(u32, cxl_reset_timeout_ms[idx],
			   CXL_RESET_RRS_WAIT_MS);
	deadline = jiffies + msecs_to_jiffies(timeout_ms);
	msleep(CXL_RESET_RRS_WAIT_MS);

	do {
		rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_STATUS2,
					  &status2);
		if (rc || status2 == U16_MAX)
			goto not_ready;

		if (status2 & PCI_DVSEC_CXL_RST_ERR)
			return -EIO;

		if (status2 & PCI_DVSEC_CXL_RST_DONE)
			return 0;

not_ready:
		if (time_after_eq(jiffies, deadline))
			return -ETIMEDOUT;

		msleep(CXL_RESET_STATUS_POLL_MS);
	} while (true);
}

static int cxl_reset_execute(struct pci_dev *pdev, int dvsec)
{
	bool cache_disabled = false;
	u16 cap;
	int rc;

	rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CAP, &cap);
	if (rc)
		return pcibios_err_to_errno(rc);

	rc = cxl_reset_disable_cache(pdev, dvsec, cap);
	if (rc)
		return rc;
	cache_disabled = true;

	rc = cxl_reset_update_ctrl2(pdev, dvsec, PCI_DVSEC_CXL_INIT_CXL_RST,
				    PCI_DVSEC_CXL_RST_MEM_CLR_EN);
	if (rc)
		goto out;

	rc = cxl_reset_wait_done(pdev, dvsec, cap);
	if (rc)
		goto out;

out:
	if (cache_disabled) {
		int rc2;

		rc2 = cxl_reset_enable_cache(pdev, dvsec);
		if (rc2 && rc)
			pci_warn(pdev, "failed to re-enable CXL caching: %d\n",
				 rc2);
		else if (rc2)
			rc = rc2;
	}

	return rc;
}

int cxl_reset_function(struct pci_dev *pdev, bool probe)
{
	struct cxl_hdm_range_context range_ctx;
	struct cxl_reset_context ctx;
	int dvsec;
	int rc;

	dvsec = cxl_reset_dvsec(pdev);
	if (dvsec < 0)
		return dvsec;

	cxl_reset_context_init(&ctx, pdev);
	if (probe)
		return cxl_reset_validate_function_scoped(&ctx);

	cxl_hdm_range_context_init(&range_ctx);

	if (!cxl_reset_scope_hdm_available(&ctx)) {
		rc = -ENOTTY;
		goto out;
	}

	rc = cxl_pci_target_reset_prepare(&ctx);
	if (rc)
		goto out;

	scoped_guard(rwsem_write, &cxl_rwsem.region) {
		rc = cxl_hdm_ranges_prepare(&range_ctx, &ctx);
		if (!rc)
			rc = cxl_reset_execute(pdev, dvsec);
		if (!rc)
			rc = cxl_restore_hdm_decoders(&ctx);
	}

	cxl_pci_target_reset_done(&ctx);
out:
	cxl_hdm_range_context_destroy(&range_ctx);
	return rc;
}
