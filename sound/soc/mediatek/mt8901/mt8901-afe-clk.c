// SPDX-License-Identifier: GPL-2.0
/*
 * mt8901-afe-clk.c  --  MediaTek 8901 afe clock ctrl
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 *         Weiyi Hsieh <weiyi.hsieh@mediatek.com>
 */

#include "mt8901-afe-common.h"
#include "mt8901-afe-clk.h"
#include "mt8901-reg.h"

static int mt8901_afe_enable_afe_on(struct mtk_base_afe *afe)
{
	unsigned int mask;

	mask = AUDIO_ENGEN_CON0_APLL2_MASK |
	       AUDIO_ENGEN_CON0_APLL1_MASK |
	       AUDIO_ENGEN_CON0_26M_MASK;
	regmap_update_bits(afe->regmap, AUDIO_ENGEN_CON0, mask, mask);
	return 0;
}

static int mt8901_afe_disable_afe_on(struct mtk_base_afe *afe)
{
	unsigned int mask;

	mask = AUDIO_ENGEN_CON0_APLL2_MASK |
	       AUDIO_ENGEN_CON0_APLL1_MASK |
	       AUDIO_ENGEN_CON0_26M_MASK;
	regmap_update_bits(afe->regmap, AUDIO_ENGEN_CON0, mask, 0x0);
	return 0;
}

int mt8901_afe_enable_main_clock(struct mtk_base_afe *afe)
{
	mt8901_afe_enable_afe_on(afe);
	return 0;
}

int mt8901_afe_disable_main_clock(struct mtk_base_afe *afe)
{
	mt8901_afe_disable_afe_on(afe);
	return 0;
}
