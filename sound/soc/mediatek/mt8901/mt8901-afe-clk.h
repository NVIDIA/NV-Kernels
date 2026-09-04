/* SPDX-License-Identifier: GPL-2.0 */
/*
 * mt8901-afe-clk.h  --  MediaTek 8901 afe clock ctrl definition
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 *         Weiyi Hsieh <weiyi.hsieh@mediatek.com>
 */

#ifndef _MT8901_AFE_CLK_H_
#define _MT8901_AFE_CLK_H_

struct mtk_base_afe;

int mt8901_afe_enable_main_clock(struct mtk_base_afe *afe);
int mt8901_afe_disable_main_clock(struct mtk_base_afe *afe);

#endif
