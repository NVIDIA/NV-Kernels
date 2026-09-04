/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MediaTek SoundWire master — shared driver structure.
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 */
#ifndef __MTK_SDW_COMMON_H
#define __MTK_SDW_COMMON_H

#include "mtk-sdw-core.h"

struct mtk_sdw;
struct mtk_sdw_top_cfg;
struct mtk_sdw_top_pdi_params;

enum mtk_sdw_hw_ver {
	MTK_SDW_HW_VER_MT8195 = 0,   /* first chip       */
	MTK_SDW_HW_VER_MT8901,       /* second chip      */
	MTK_SDW_HW_VER_MT8971,
	MTK_SDW_HW_VER_MAX,
};

#define SDW_MAX_HWIP_NUM (2)
#define SDW_PDI_CONFIG_NUM (8)
#define MTK_SDW_MAX_GROUP_SYNC  4
#define MTK_SDW_MAX_DP   16

struct mtk_sdw_link {
	struct mtk_sdw_core core;
	struct mtk_sdw *master;
	int ip_idx;
	int irq;
	u32 src_base;
	u32 src_num;
	u32 sink_base;
	u32 sink_num;
};

struct mtk_sdw_dai {
	struct mtk_sdw_link *link;
	unsigned int port_num;
	struct sdw_stream_runtime *sruntime;
	unsigned int pdi_count;
	struct mtk_sdw_pdi_params pdi_params[SDW_PDI_CONFIG_NUM];
	struct mtk_sdw_top_pdi_params *top_pdi_params;
	bool use_group_sync;
	unsigned int group_sync_id;
	bool need_enable_delay;
};

struct mtk_sdw {
	struct device *dev;
	void __iomem *base; /* full AFE MMIO */
	struct mtk_sdw_link links[SDW_MAX_HWIP_NUM];
	int num_links;
	u32 controller_en_list;
	const struct mtk_sdw_top_cfg *top_cfg;
	void __iomem *top_pdi; /* base + top_cfg->pdi_base */
	void __iomem *top_con; /* base + top_cfg->con_base */
	u32 hw_ver;
	/* group_lock: serializes group_refcnt[] group-sync allocation */
	struct mutex group_lock;
	int group_refcnt[MTK_SDW_MAX_GROUP_SYNC];
	u32 tzd_delay;
	bool tzd_inverse;
	u32 phy_delay;
	u32 phy_double_delay;
	struct mtk_sdw_dai *dais;
	int num_dais;
	u16 dp_pdi_mask[MTK_SDW_MAX_DP];
	struct platform_device *mach_dev;
};

#endif /* __MTK_SDW_COMMON_H */
