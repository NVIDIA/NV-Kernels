// SPDX-License-Identifier: GPL-2.0
/*
 * mtk-sdw-chipglue.c -- chip-specific selection for the MediaTek
 * SoundWire controller driver.
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 */

#include <linux/device.h>
#include "mtk-sdw-common.h"

#if IS_ENABLED(CONFIG_SOUNDWIRE_MTK_MT8901_CLK)
#include "mt8901-afe-clk.h"
#endif

int mtk_sdw_clk_ops_select(struct mtk_sdw *mst, int hw_ver)
{
	switch (hw_ver) {
#if IS_ENABLED(CONFIG_SOUNDWIRE_MTK_MT8901_CLK)
	case MTK_SDW_HW_VER_MT8901:
	case MTK_SDW_HW_VER_MT8971:
		mst->clk_ops = &mt8901_clk_ops;
		break;
#endif
	default:
		dev_err(mst->dev,
			"no clock control ops for hw-ver %u (unsupported or not compiled in)\n",
			hw_ver);
		return -EINVAL;
	}

	return 0;
}
