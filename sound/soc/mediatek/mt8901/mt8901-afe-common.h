/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mt8901-afe-common.h  --  MediaTek 8901 audio driver definitions
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 *         Weiyi Hsieh <weiyi.hsieh@mediatek.com>
 */
#ifndef _MT_8901_AFE_COMMON_H_
#define _MT_8901_AFE_COMMON_H_

#include <linux/list.h>
#include <linux/regmap.h>
#include <sound/soc.h>
#include "../common/mtk-base-afe.h"

enum {
	MT8901_DAI_START,
	MT8901_AFE_MEMIF_START = MT8901_DAI_START,
	MT8901_AFE_MEMIF_DL0 = MT8901_AFE_MEMIF_START,
	MT8901_AFE_MEMIF_DL1,
	MT8901_AFE_MEMIF_DL2,
	MT8901_AFE_MEMIF_DL3,
	MT8901_AFE_MEMIF_DL4,
	MT8901_AFE_MEMIF_DL5,
	MT8901_AFE_MEMIF_DL_24CH_0,
	MT8901_AFE_MEMIF_UL_START,
	MT8901_AFE_MEMIF_UL0 = MT8901_AFE_MEMIF_UL_START,
	MT8901_AFE_MEMIF_UL1,
	MT8901_AFE_MEMIF_UL2,
	MT8901_AFE_MEMIF_UL3,
	MT8901_AFE_MEMIF_UL4,
	MT8901_AFE_MEMIF_UL5,
	MT8901_AFE_MEMIF_VUL_CM0,
	MT8901_AFE_MEMIF_VUL_CM1,
	MT8901_AFE_MEMIF_VUL_CM2,
	MT8901_AFE_MEMIF_END,
	MT8901_AFE_MEMIF_NUM = (MT8901_AFE_MEMIF_END - MT8901_AFE_MEMIF_START),
	MT8901_DAI_END = MT8901_AFE_MEMIF_END,
	MT8901_DAI_NUM = (MT8901_DAI_END - MT8901_DAI_START),
};

enum {
	MT8901_AFE_IRQ_0 = 0,
	MT8901_AFE_IRQ_1,
	MT8901_AFE_IRQ_2,
	MT8901_AFE_IRQ_3,
	MT8901_AFE_IRQ_4,
	MT8901_AFE_IRQ_5,
	MT8901_AFE_IRQ_6,
	MT8901_AFE_IRQ_7,
	MT8901_AFE_IRQ_8,
	MT8901_AFE_IRQ_9,
	MT8901_AFE_IRQ_10,
	MT8901_AFE_IRQ_11,
	MT8901_AFE_IRQ_12,
	MT8901_AFE_IRQ_13,
	MT8901_AFE_IRQ_14,
	MT8901_AFE_IRQ_15,
	MT8901_AFE_IRQ_16,
	MT8901_AFE_IRQ_17,
	MT8901_AFE_IRQ_18,
	MT8901_AFE_IRQ_19,
	MT8901_AFE_IRQ_20,
	MT8901_AFE_IRQ_21,
	MT8901_AFE_IRQ_NUM,
};

enum {
	MT8901_DOMAIN_HOPPING = 0,
	MT8901_DOMAIN_APLL,
};

struct mtk_dai_memif_irq_priv {
	unsigned int asys_timing_sel;
};

struct mt8901_afe_private {
	u32 hw_ver;               /* acpi-asd-hw-ver from _DSD */
	struct mtk_dai_memif_irq_priv irq_priv[MT8901_AFE_IRQ_NUM];
	int pm_runtime_bypass_reg_ctl;

	/* dai */
	void *dai_priv[MT8901_DAI_NUM];
};

int mt8901_afe_fs_timing(struct device *dev, unsigned int rate);
/* dai register */
int mt8901_dai_soundwire_register(struct mtk_base_afe *afe);

#define MT8901_SOC_ENUM_EXT(xname, xenum, xhandler_get, xhandler_put, id) \
{ \
	.iface = SNDRV_CTL_ELEM_IFACE_MIXER, .name = xname, \
	.info = snd_soc_info_enum_double, \
	.get = xhandler_get, .put = xhandler_put, \
	.device = id, \
	.private_value = (unsigned long)&(xenum), \
}

#endif
