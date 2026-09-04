/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MediaTek SoundWire master driver header.
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 */
#ifndef __MTK_SDW_H
#define __MTK_SDW_H

#include "mtk-sdw-common.h"

enum mt8901_afe_clk_domain {
	MT8901_HOPPING_CLK_DOMAIN = 0,
	MT8901_APLL_CLK_DOMAIN = 1,
};

enum mtk_sdw_sample_rate {
	RATE_384000 = 384000,
	RATE_352800 = 352800,
	RATE_192000 = 192000,
	RATE_176400 = 176400,
	RATE_96000 = 96000,
	RATE_88200 = 88200,
	RATE_48000 = 48000,
	RATE_44100 = 44100,
	RATE_32000 = 32000,
	RATE_29400 = 29400,
	RATE_24000 = 24000,
	RATE_22050 = 22050,
	RATE_16000 = 16000,
	RATE_14700 = 14700,
	RATE_12000 = 12000,
	RATE_11025 = 11025,
	RATE_8000 = 8000,
	RATE_7350 = 7350,
};

enum mt8901_afe_fs_mode {
	MT8901_FS_8K = 0,
	MT8901_FS_11D025K = 1,
	MT8901_FS_12K = 2,
	MT8901_FS_16K = 4,
	MT8901_FS_22D05K = 5,
	MT8901_FS_24K = 6,
	MT8901_FS_32K = 8,
	MT8901_FS_44D1K = 9,
	MT8901_FS_48K = 10,
	MT8901_FS_88D2K = 13,
	MT8901_FS_96K = 14,
	MT8901_FS_176D4K = 17,
	MT8901_FS_192K = 18,
	MT8901_FS_352D8K = 21,
	MT8901_FS_384K = 22,
	MT8901_ETDM_OUT0_HOPPING_DOMAIN = 4,
	MT8901_ETDM_OUT5_HOPPING_DOMAIN = 9,
	MT8901_ETDM_IN0_HOPPING_DOMAIN = 12,
	MT8901_ETDM_IN5_HOPPING_DOMAIN = 17,
	MT8901_FS_TOP_PDI_IP0_PDI0 = 24,
	MT8901_FS_TOP_PDI_IP1_PDI0 = 25,
	MT8901_FS_TOP_PDI_IP0_PDI1 = 26,
	MT8901_FS_TOP_PDI_IP1_PDI1 = 27,
};

#define IS_48K_RATE_DOMAIN(x) (((x) % 8000) == 0)

#define SDW_DEFAULT_CH_PER_PDI 2

#define AFE_SDW_TOP_PDI_REG_BASE (0x9000)
#define AFE_SDW_TOP_CON_REG_BASE (0x9048)

#define SDW_DEFAULT_MAX_BUS_CLK_FREQ    (6144000)
#define SDW_DEFAULT_MCLK_CLK_FREQ       (24576000)
#define SDW_DEFAULT_FRAME_RATE          (24000)
#define SDW_DEFAULT_FRAME_SHAPE_ROW     (64)
#define SDW_DEFAULT_FRAME_SHAPE_COL     (8)

#define MTK_SDW_DP_SOURCE_BASE   2   /* DP2..  (master source / playback) */
#define MTK_SDW_DP_SOURCE_NUM    5
#define MTK_SDW_DP_SINK_BASE     7   /* DP7..  (master sink / capture)    */
#define MTK_SDW_DP_SINK_NUM      9
#define MTK_SDW_MAX_DAIS \
	((MTK_SDW_DP_SOURCE_NUM) + (MTK_SDW_DP_SINK_NUM)) /* BRA not included */

struct mtk_sdw_acpi_cb_context {
	struct device *dev;
	int err;
};

#endif /* __MTK_SDW_H */
