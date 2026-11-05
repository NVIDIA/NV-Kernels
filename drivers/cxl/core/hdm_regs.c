// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 NVIDIA Corporation & Affiliates */
#include <linux/delay.h>
#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/kernel.h>

#include <cxl/hdm.h>

#include "cxl.h"
#include "core.h"

/*
 * HDM decoder register helpers are built in whenever CXL_BUS is enabled,
 * including when cxl_core is modular. Callers provide any required locking.
 */

static void cxld_set_interleave(const struct cxl_decoder_config *config, u32 *ctrl)
{
	u16 eig;
	u8 eiw;

	/*
	 * Input validation ensures these warns never fire, but otherwise
	 * suppress unititalized variable usage warnings.
	 */
	if (WARN_ONCE(ways_to_eiw(config->interleave_ways, &eiw),
		      "invalid interleave_ways: %d\n", config->interleave_ways))
		return;
	if (WARN_ONCE(granularity_to_eig(config->interleave_granularity, &eig),
		      "invalid interleave_granularity: %d\n",
		      config->interleave_granularity))
		return;

	u32p_replace_bits(ctrl, eig, CXL_HDM_DECODER0_CTRL_IG_MASK);
	u32p_replace_bits(ctrl, eiw, CXL_HDM_DECODER0_CTRL_IW_MASK);
	*ctrl |= CXL_HDM_DECODER0_CTRL_COMMIT;
}

static void cxld_set_type(const struct cxl_decoder_config *config, u32 *ctrl)
{
	u32p_replace_bits(ctrl,
			  !!(config->target_type == CXL_DECODER_HOSTONLYMEM),
			  CXL_HDM_DECODER0_CTRL_HOSTONLY);
}

/*
 * Per CXL 2.0 8.2.5.12.20 Committing Decoder Programming, hardware must set
 * committed or error within 10ms, but just be generous with 20ms to account for
 * clock skew and other marginal behavior
 */
#define COMMIT_TIMEOUT_MS 20
int cxld_await_commit(void __iomem *hdm, int id)
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
EXPORT_SYMBOL_FOR_MODULES(cxld_await_commit, "cxl_core");

static u32 cxl_hdm_write_range(void __iomem *hdm,
			       const struct cxl_decoder_config *config)
{
	u64 size = range_len(&config->hpa_range);
	u64 base = config->hpa_range.start;
	int id = config->id;
	u32 ctrl;

	ctrl = readl(hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));
	cxld_set_interleave(config, &ctrl);
	cxld_set_type(config, &ctrl);

	writel(upper_32_bits(base), hdm + CXL_HDM_DECODER0_BASE_HIGH_OFFSET(id));
	writel(lower_32_bits(base), hdm + CXL_HDM_DECODER0_BASE_LOW_OFFSET(id));
	writel(upper_32_bits(size), hdm + CXL_HDM_DECODER0_SIZE_HIGH_OFFSET(id));
	writel(lower_32_bits(size), hdm + CXL_HDM_DECODER0_SIZE_LOW_OFFSET(id));
	return ctrl;
}

void cxl_commit_start_endpoint(const struct cxl_endpoint_decoder_settings *settings,
			       void __iomem *hdm)
{
	int id = settings->config.id;
	u32 ctrl;

	ctrl = cxl_hdm_write_range(hdm, &settings->config);
	writel(upper_32_bits(settings->skip), hdm + CXL_HDM_DECODER0_SKIP_HIGH(id));
	writel(lower_32_bits(settings->skip), hdm + CXL_HDM_DECODER0_SKIP_LOW(id));
	writel(ctrl, hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));
}
EXPORT_SYMBOL_FOR_MODULES(cxl_commit_start_endpoint, "cxl_core");

void cxl_commit_start_switch(const struct cxl_decoder_config *config,
			     u64 targets, void __iomem *hdm)
{
	int id = config->id;
	u32 ctrl;

	ctrl = cxl_hdm_write_range(hdm, config);
	writel(upper_32_bits(targets), hdm + CXL_HDM_DECODER0_TL_HIGH(id));
	writel(lower_32_bits(targets), hdm + CXL_HDM_DECODER0_TL_LOW(id));
	writel(ctrl, hdm + CXL_HDM_DECODER0_CTRL_OFFSET(id));
}
EXPORT_SYMBOL_FOR_MODULES(cxl_commit_start_switch, "cxl_core");

int cxl_hdm_unpack_decoder(struct cxl_decoder_config *config, int id,
			   u32 ctrl, u64 base, u64 size)
{
	bool committed = FIELD_GET(CXL_HDM_DECODER0_CTRL_COMMITTED, ctrl);
	enum cxl_decoder_type target_type = 0;
	int interleave_granularity;
	unsigned long flags = 0;
	struct range hpa_range;
	int interleave_ways;
	u64 end;
	int rc;

	if (!committed)
		size = 0;
	if (base == U64_MAX || size == U64_MAX)
		return -ENXIO;
	/* A zero-size decoder maps no HPA; its range is empty at @base. */
	end = base - 1;
	if (size && check_add_overflow(base, size - 1, &end))
		return -ENXIO;

	hpa_range = (struct range) {
		.start = base,
		.end = end,
	};

	if (committed) {
		flags |= CXL_DECODER_F_ENABLE;
		if (ctrl & CXL_HDM_DECODER0_CTRL_LOCK)
			flags |= CXL_DECODER_F_LOCK;
		if (FIELD_GET(CXL_HDM_DECODER0_CTRL_HOSTONLY, ctrl))
			target_type = CXL_DECODER_HOSTONLYMEM;
		else
			target_type = CXL_DECODER_DEVMEM;
	}

	rc = eiw_to_ways(FIELD_GET(CXL_HDM_DECODER0_CTRL_IW_MASK, ctrl),
			 &interleave_ways);
	if (rc)
		return rc;
	rc = eig_to_granularity(FIELD_GET(CXL_HDM_DECODER0_CTRL_IG_MASK, ctrl),
				&interleave_granularity);
	if (rc)
		return rc;

	*config = (struct cxl_decoder_config) {
		.id = id,
		.hpa_range = hpa_range,
		.interleave_ways = interleave_ways,
		.interleave_granularity = interleave_granularity,
		.target_type = target_type,
		.flags = flags,
	};

	return 0;
}
EXPORT_SYMBOL_FOR_MODULES(cxl_hdm_unpack_decoder, "cxl_core");

int cxl_hdm_read_decoder(struct cxl_decoder_config *config, void __iomem *hdm,
			 int id, u32 ctrl)
{
	u64 lo, hi, base, size;

	lo = readl(hdm + CXL_HDM_DECODER0_BASE_LOW_OFFSET(id));
	hi = readl(hdm + CXL_HDM_DECODER0_BASE_HIGH_OFFSET(id));
	base = (hi << 32) | lo;
	lo = readl(hdm + CXL_HDM_DECODER0_SIZE_LOW_OFFSET(id));
	hi = readl(hdm + CXL_HDM_DECODER0_SIZE_HIGH_OFFSET(id));
	size = (hi << 32) | lo;

	return cxl_hdm_unpack_decoder(config, id, ctrl, base, size);
}
EXPORT_SYMBOL_FOR_MODULES(cxl_hdm_read_decoder, "cxl_core");
