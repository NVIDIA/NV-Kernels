/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MediaTek SoundWire master — AFE TOP control.
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 */
#ifndef __MTK_SDW_TOP_H
#define __MTK_SDW_TOP_H

#include "mtk-sdw-common.h"

enum mtk_sdw_group_sync_sel {
	GROUP_SYNC_NONE = 0,
	GROUP_1_SYNC,
	GROUP_2_SYNC,
	GROUP_3_SYNC,
	GROUP_4_SYNC,
};

enum mtk_sdw_top_ver {
	MTK_SDW_TOP_VER_0 = 0,
	MTK_SDW_TOP_VER_MAX,
};

/* ---- AFE TOP registers (offsets that DON'T vary stay as #defines) ----
 */
#define SDW_TOP_PDIN_CON0(n)              ((n) * 4)   /* rel. top_pdi */
#define SDW_TOP_PDI_EN                    BIT(0)
#define SDW_TOP_PDI_FS                    GENMASK(5, 1)
#define SDW_TOP_PDI_DOMAIN                GENMASK(8, 6)
#define SDW_TOP_PDI_IP_SEL                BIT(9)
#define SDW_TOP_PDI_PDM2PCM               BIT(10)
#define SDW_TOP_PDI_CLOCK                 BIT(11)
#define SDW_TOP_PDI_HD_SEL                BIT(12)
#define SDW_TOP_PDI_PDM_MODE              BIT(13)
#define SDW_TOP_PDI_PDM_ONE_WIRE          BIT(14)
#define SDW_TOP_PDI_DMIC_1XEN             BIT(16)
#define SDW_TOP_PDI_BRA_MODE              BIT(17)
#define SDW_TOP_PDI_BRA_EOP               BIT(18)
#define SDW_TOP_PDI_BRA_SLAVE             BIT(19)
#define SDW_TOP_PDI_SLAVE_MODE            GENMASK(21, 20)
#define SDW_TOP_PDI_GROUP_SYNC_ON         BIT(22)
#define SDW_TOP_PDI_GROUP_SYNC            GENMASK(26, 23)

#define SDW_TOP_CON0                      0x0000      /* rel. top_con */
#define SDW_TOP_CON0_GSYNC_DIR_CTRL       BIT(7)

#define SDW_TOP_CON1                      0x0004

#define TOP_GROUP_SYNC_TX_MIN_ID      1
#define TOP_GROUP_SYNC_TX_MAX_ID      2
#define TOP_GROUP_SYNC_RX_MIN_ID      1
#define TOP_GROUP_SYNC_RX_MAX_ID      4

struct mtk_sdw_top_pdi_params {
	u32 group_sync;
	u32 slave_mode;
	u32 bra_slave;
	u32 bra_eop;
	u32 bra_mode;
	u32 dmic_1xen;
	u32 pdm_one_wire;
	u32 pdm_mode;
	u32 hd_sel;
	u32 clock;
	u32 pdm2pcm;
	u32 sdw_ip_sel;
	u32 domain;
	u32 fs;
};

struct mtk_sdw_top_reg {
	u32 tzd_delay_reg;
	u32 tzd_delay_sel;
	u32 tzd_inverse;
	u32 tzd_delay_en;
	u32 phy_delay_reg;
	u32 phy_delay_sel;
	u32 phy_double_delay_sel;
};

struct mtk_sdw_top_cfg {
	const char *name;
	struct mtk_sdw_top_reg reg;
	/*
	 * u32 features;
	 * can be added for a bitfield if new features are supported
	 * in the future.
	 *
	 */
};

int mtk_sdw_top_config_select(struct mtk_sdw *mst, int hw_ver);
void mtk_sdw_top_init_settings(struct mtk_sdw *mst);
void mtk_sdw_top_configure_delays(struct mtk_sdw *mst);
void mtk_sdw_top_configure_pdi(struct mtk_sdw *mst, u32 pdi,
			       struct mtk_sdw_top_pdi_params *param);
int mtk_sdw_top_group_sync_config_get(struct mtk_sdw *mst, u8 id, u32 *cfg);
int mtk_sdw_top_group_sync_acquire(struct mtk_sdw *mst, bool is_tx);
void mtk_sdw_top_group_sync_release(struct mtk_sdw *mst, u8 id);
int mtk_sdw_top_enable_stream(struct mtk_sdw *mst, int dai_id);
int mtk_sdw_top_disable_stream(struct mtk_sdw *mst, int dai_id);

#endif /* __MTK_SDW_TOP_H */
