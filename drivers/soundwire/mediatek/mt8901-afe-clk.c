// SPDX-License-Identifier: GPL-2.0
/*
 * mt8901-afe-clk.c  --  MediaTek 8901 afe clock ctrl
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 *         Weiyi Hsieh <weiyi.hsieh@mediatek.com>
 */

#include <linux/device.h>
#include <linux/string.h>
#include "mtk-sdw-common.h"
#include "mt8901-afe-clk.h"
#include <linux/soc/mediatek/mtk-pwrap.h>

#define AUDIO_ENGEN_CON0_USER1   (0x0018)
#define AUDIO_ENGEN_CON0_APLL2_MASK         BIT(3)
#define AUDIO_ENGEN_CON0_APLL1_MASK         BIT(2)
#define AUDIO_ENGEN_CON0_26M_MASK           BIT(0)

static const unsigned int mt8901_sdw_common_clk_muxes[] = {
	AFE_CLK_VLP_CKSYS_TOP_AUDIO_H_SEL,
	AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN2_SEL,
	AFE_CLK_VLP_CKSYS_TOP_AUD_INTBUS_SEL,
	AFE_CLK_VLP_CKSYS_TOP_VADSP_SEL,
};

static const unsigned int mt8901_sdw0_main_clk_muxes[] = {
	AFE_CLK_VLP_CKSYS_TOP_AUD_SOUNDWIRE0_SEL,
	AFE_CLK_VLP_CKSYS_TOP_AUD_SOUNDWIRE0_PHY_SEL,
	AFE_CLK_VLP_CKSYS_TOP_VADSP_SEL,
};

static const unsigned int mt8901_sdw1_main_clk_muxes[] = {
	AFE_CLK_VLP_CKSYS_TOP_AUD_SOUNDWIRE1_SEL,
	AFE_CLK_VLP_CKSYS_TOP_AUD_SOUNDWIRE1_PHY_SEL,
	AFE_CLK_VLP_CKSYS_TOP_VADSP_SEL,
};

static const unsigned int mt8901_apll_top_con_cgs[] = {
	AUD_CG_APLL1_CK,
	AUD_CG_APLL2_CK,
	AUD_CG_APLL_TUNER1,
	AUD_CG_APLL_TUNER2,
};

static const struct {
	unsigned int mux;
	const char *parent_name;
	unsigned int level;
} mt8901_clk_parent_map[] = {
	{ AFE_CLK_VLP_CKSYS_TOP_AUDIO_H_SEL,
	  CLK_PARENT_TCX_26M_MX9_CK_NAME, 0 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUDIO_H_SEL,
	  CLK_PARENT_OSC_D20_NAME, 1 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUDIO_H_SEL,
	  CLK_PARENT_APLL1_D2_NAME, 2 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUDIO_H_SEL,
	  CLK_PARENT_APLL2_D2_NAME, 3 },

	{ AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN1_SEL,
	  CLK_PARENT_TCX_26M_MX9_CK_NAME, 0 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN1_SEL,
	  CLK_PARENT_OSC_D20_NAME, 1 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN1_SEL,
	  CLK_PARENT_APLL1_D8_NAME, 2 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN1_SEL,
	  CLK_PARENT_APLL1_D4_NAME, 3 },

	{ AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN2_SEL,
	  CLK_PARENT_TCX_26M_MX9_CK_NAME, 0 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN2_SEL,
	  CLK_PARENT_OSC_D20_NAME, 1 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN2_SEL,
	  CLK_PARENT_APLL2_D8_NAME, 2 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN2_SEL,
	  CLK_PARENT_APLL2_D4_NAME, 3 },

	{ AFE_CLK_VLP_CKSYS_TOP_AUD_INTBUS_SEL,
	  CLK_PARENT_TCX_26M_MX9_CK_NAME, 0 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_INTBUS_SEL,
	  CLK_PARENT_OSC_D20_NAME, 1 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_INTBUS_SEL,
	  CLK_PARENT_MAINPLL2_D7_D4_NAME, 2 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_INTBUS_SEL,
	  CLK_PARENT_MAINPLL2_D4_D4_NAME, 3 },

	{ AFE_CLK_VLP_CKSYS_TOP_AUD_1_SEL,
	  CLK_PARENT_TCX_26M_MX9_CK_NAME, 0 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_1_SEL,
	  CLK_PARENT_APLL1_NAME, 1 },

	{ AFE_CLK_VLP_CKSYS_TOP_AUD_2_SEL,
	  CLK_PARENT_TCX_26M_MX9_CK_NAME, 0 },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_2_SEL,
	  CLK_PARENT_APLL2_NAME, 1 },
};

static const struct {
	unsigned int mux;
	const char *idle_parent_name;
	const char *active_parent_name;
} idle_clk_muxes[] = {
	{ AFE_CLK_VLP_CKSYS_TOP_AUDIO_H_SEL,
	  CLK_PARENT_OSC_D20_NAME, CLK_PARENT_APLL2_D2_NAME },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_INTBUS_SEL,
	  CLK_PARENT_OSC_D20_NAME, CLK_PARENT_MAINPLL2_D4_D4_NAME },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_1_SEL,
	  CLK_PARENT_TCX_26M_MX9_CK_NAME, CLK_PARENT_APLL1_NAME },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_2_SEL,
	  CLK_PARENT_TCX_26M_MX9_CK_NAME, CLK_PARENT_APLL2_NAME },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN1_SEL,
	  CLK_PARENT_OSC_D20_NAME, CLK_PARENT_APLL1_D4_NAME },
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN2_SEL,
	  CLK_PARENT_OSC_D20_NAME, CLK_PARENT_APLL2_D4_NAME },
};

struct sdw_clk_parent_info {
	unsigned int mux;
	const char *apll_parent_name;
	const char *lp_parent_name;
};

struct sdw_clk_parent_info sdw0_clk_parent_info[] = {
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_SOUNDWIRE0_SEL,
	  CLK_PARENT_APLL2_D8_NAME,
	  CLK_PARENT_OSC_D20_NAME},
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_SOUNDWIRE0_PHY_SEL,
	  CLK_PARENT_APLL2_NAME,
	  CLK_PARENT_OSC_D20_NAME},
};

struct sdw_clk_parent_info sdw1_clk_parent_info[] = {
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_SOUNDWIRE1_SEL,
	  CLK_PARENT_APLL2_D8_NAME,
	  CLK_PARENT_OSC_D20_NAME},
	{ AFE_CLK_VLP_CKSYS_TOP_AUD_SOUNDWIRE1_PHY_SEL,
	  CLK_PARENT_APLL2_NAME,
	  CLK_PARENT_OSC_D20_NAME},
};

static const char * const mt8901_cg_names[] = {
	[AUD_CG_HW_GAIN01]           = "HW_GAIN01",
	[AUD_CG_HW_GAIN23]           = "HW_GAIN23",
	[AUD_CG_CM0]                 = "CM0",
	[AUD_CG_CM1]                 = "CM1",
	[AUD_CG_CM2]                 = "CM2",
	[AUD_CG_HW_GAIN_DL0_DL1]     = "HW_GAIN_DL0_DL1",
	[AUD_CG_HW_GAIN_DL2_DL3]     = "HW_GAIN_DL2_DL3",
	[AUD_CG_HW_GAIN_DL4_DL5]     = "HW_GAIN_DL4_DL5",
	[AUD_CG_HW_GAIN_DL24CH]      = "HW_GAIN_DL24CH",
	[AUD_CG_UL0_ADC]             = "UL0_ADC",
	[AUD_CG_UL0_TML]             = "UL0_TML",
	[AUD_CG_UL0_ADC_HIRES]       = "UL0_ADC_HIRES",
	[AUD_CG_UL0_ADC_HIRES_TML]   = "UL0_ADC_HIRES_TML",
	[AUD_CG_UL1_ADC]             = "UL1_ADC",
	[AUD_CG_UL1_TML]             = "UL1_TML",
	[AUD_CG_UL1_ADC_HIRES]       = "UL1_ADC_HIRES",
	[AUD_CG_UL1_ADC_HIRES_TML]   = "UL1_ADC_HIRES_TML",
	[AUD_CG_ETDM_OUT0]           = "ETDM_OUT0",
	[AUD_CG_ETDM_OUT5]           = "ETDM_OUT5",
	[AUD_CG_ETDM_IN0]            = "ETDM_IN0",
	[AUD_CG_ETDM_IN5]            = "ETDM_IN5",
	[AUD_CG_GENERAL0_ASRC]       = "GASRC0",
	[AUD_CG_GENERAL1_ASRC]       = "GASRC1",
	[AUD_CG_GENERAL2_ASRC]       = "GASRC2",
	[AUD_CG_GENERAL3_ASRC]       = "GASRC3",
	[AUD_CG_GENERAL4_ASRC]       = "GASRC4",
	[AUD_CG_GENERAL5_ASRC]       = "GASRC5",
	[AUD_CG_GENERAL6_ASRC]       = "GASRC6",
	[AUD_CG_GENERAL7_ASRC]       = "GASRC7",
	[AUD_CG_APLL_TUNER1]         = "APLL_TUNER1",
	[AUD_CG_APLL_TUNER2]         = "APLL_TUNER2",
	[AUD_CG_H208M_CK]            = "H208M",
	[AUD_CG_APLL2_CK]            = "APLL2",
	[AUD_CG_APLL1_CK]            = "APLL1",
	[AUD_CG_AUDIO_F26M_CK]       = "F26M",
	[AUD_CG_AUDIO_HOPPING_CK]    = "HOPPING",
	[AUD_CG_SOUNDWIRE_DMIC0_ADC] = "SDW_DMIC0_ADC",
	[AUD_CG_SOUNDWIRE_DMIC0_TML] = "SDW_DMIC0_TML",
	[AUD_CG_SOUNDWIRE_DMIC1_ADC] = "SDW_DMIC1_ADC",
	[AUD_CG_SOUNDWIRE_DMIC1_TML] = "SDW_DMIC1_TML",
	[AUD_CG_SOUNDWIRE_DMIC2_ADC] = "SDW_DMIC2_ADC",
	[AUD_CG_SOUNDWIRE_DMIC2_TML] = "SDW_DMIC2_TML",
	[AUD_CG_SOUNDWIRE_DMIC3_ADC] = "SDW_DMIC3_ADC",
	[AUD_CG_SOUNDWIRE_DMIC3_TML] = "SDW_DMIC3_TML",
	[AUD_CG_SOUNDWIRE_DMIC4_ADC] = "SDW_DMIC4_ADC",
	[AUD_CG_SOUNDWIRE_DMIC4_TML] = "SDW_DMIC4_TML",
	[AUD_CG_SOUNDWIRE_DMIC5_ADC] = "SDW_DMIC5_ADC",
	[AUD_CG_SOUNDWIRE_DMIC5_TML] = "SDW_DMIC5_TML",
	[AUD_CG_SOUNDWIRE_DMIC6_ADC] = "SDW_DMIC6_ADC",
	[AUD_CG_SOUNDWIRE_DMIC6_TML] = "SDW_DMIC6_TML",
	[AUD_CG_SOUNDWIRE_DMIC7_ADC] = "SDW_DMIC7_ADC",
	[AUD_CG_SOUNDWIRE_DMIC7_TML] = "SDW_DMIC7_TML",
	[AUD_CG_SOUNDWIRE1]          = "SOUNDWIRE1",
	[AUD_CG_SOUNDWIRE0]          = "SOUNDWIRE0",
};

static int mt8901_afe_send_power_req(struct device *dev, u8 cmd,
				     u32 d0, u32 d1, u32 d2)
{
	struct power_cntl_scmi_data scmidata = {
		.requestId  = cmd,
		.customdata = { d0, d1, d2 },
	};
	struct _power_cntrl_request req = {
		.dev          = dev,
		.InBuffer     = &scmidata,
		.InBufferSize = sizeof(scmidata),
	};

	return mtk_send_power_control_req(&req);
}

static int mt8901_afe_pwr_ctrl_scene_req(struct device *dev, unsigned int scene)
{
	return mt8901_afe_send_power_req(dev, SSPM_AUD_CMD_PWR_CTRL_SCENE,
					 scene, 0, 0);
}

static int mt8901_afe_clk_cg_deinit_req(struct device *dev)
{
	return mt8901_afe_send_power_req(dev, SSPM_AUD_CMD_CLK_CG_DEINIT,
					 0, 0, 0);
}

static int mt8901_afe_cg_req(struct device *dev, unsigned int cg, bool enable)
{
	return mt8901_afe_send_power_req(dev, SSPM_AUD_CMD_CG, cg, enable, 0);
}

static int mt8901_afe_mtcmos_req(struct device *dev, unsigned int mtcmos,
				 bool enable)
{
	return mt8901_afe_send_power_req(dev, SSPM_AUD_CMD_MTCMOS, mtcmos,
					 enable, 0);
}

static int mt8901_afe_afe_spm_ctrl_req(struct device *dev, unsigned int req,
				       bool enable)
{
	return mt8901_afe_send_power_req(dev, SSPM_AUD_CMD_AFE_SPM_CTRL,
					 req, enable, 0);
}

static int mt8901_afe_clk_mux_req(struct device *dev, unsigned int mux,
				  bool enable)
{
	return mt8901_afe_send_power_req(dev, SSPM_AUD_CMD_VLP_SYS_CLK_MUX,
					 mux, enable, 0);
}

static int mt8901_afe_clk_set_parent_req(struct device *dev, unsigned int mux,
					 unsigned int parent_level)
{
	return mt8901_afe_send_power_req(dev,
					 SSPM_AUD_CMD_VLP_SYS_CLK_SET_PARENT,
					 mux, parent_level, 0);
}

static int mt8901_afe_enable_afe_on(struct mtk_sdw *mst)
{
	void *reg;
	unsigned int mask;
	unsigned int val;

	reg = mst->base + AUDIO_ENGEN_CON0_USER1;
	mask = AUDIO_ENGEN_CON0_APLL2_MASK |
	       AUDIO_ENGEN_CON0_APLL1_MASK |
	       AUDIO_ENGEN_CON0_26M_MASK;

	guard(mutex)(&mst->afe_lock);

	mst->afe_on_refcnt++;
	if (mst->afe_on_refcnt == 1) {
		val = readl(reg);
		val &= ~mask;
		val |= mask;
		writel(val, reg);
	}

	return 0;
}

static int mt8901_afe_disable_afe_on(struct mtk_sdw *mst)
{
	void *reg;
	unsigned int mask;
	unsigned int val;

	reg = mst->base + AUDIO_ENGEN_CON0_USER1;
	mask = AUDIO_ENGEN_CON0_APLL2_MASK |
	       AUDIO_ENGEN_CON0_APLL1_MASK |
	       AUDIO_ENGEN_CON0_26M_MASK;

	guard(mutex)(&mst->afe_lock);

	if (mst->afe_on_refcnt > 0)
		mst->afe_on_refcnt--;

	if (mst->afe_on_refcnt == 0) {
		val = readl(reg);
		val &= ~mask;
		writel(val, reg);
	}

	return 0;
}

static int mt8901_afe_check_sspm_probe(struct mtk_sdw *mst)
{
	struct device *dev = mst->dev;
	int ret;

	ret = mt8901_afe_pwr_ctrl_scene_req(dev, AUDIO_PWR_SCEN_NORMAL);
	if (ret) {
		dev_err(dev, "SSPM probe failed: %d\n", ret);
		return ret;
	}

	dev_dbg(dev, "SSPM available\n");
	return 0;
}

static int mt8901_afe_disable_default_on_clk_and_top_cg(struct mtk_sdw *mst)
{
	struct device *dev = mst->dev;
	int ret;

	ret = mt8901_afe_clk_cg_deinit_req(dev);
	dev_dbg(dev, "disable_default_on_clk_and_top_cg: %d\n", ret);

	return ret;
}

static int mt8901_sdw_init_clock(struct mtk_sdw *mst)
{
	struct device *dev = mst->dev;
	int ret;

	ret = mt8901_afe_check_sspm_probe(mst);
	if (ret)
		return ret;

	ret = mt8901_afe_disable_default_on_clk_and_top_cg(mst);
	if (ret) {
		dev_err(dev, "disable_default_on_clk_and_top_cg failed: %d\n",
			ret);
		return ret;
	}

	return ret;
}

static int mt8901_afe_enable_top_cg(struct mtk_sdw *mst, unsigned int cg)
{
	struct device *dev = mst->dev;
	const char *name;
	int ret;

	if (cg >= AUD_CG_NUMS)
		return -EINVAL;

	name = mt8901_cg_names[cg];

	ret = mt8901_afe_cg_req(dev, cg, true);

	dev_dbg(dev, "enable_top_cg %s: %d\n", name, ret);
	return ret;
}

static int mt8901_afe_disable_top_cg(struct mtk_sdw *mst, unsigned int cg)
{
	struct device *dev = mst->dev;
	const char *name;
	int ret;

	if (cg >= AUD_CG_NUMS)
		return -EINVAL;

	name = mt8901_cg_names[cg];

	ret = mt8901_afe_cg_req(dev, cg, false);

	dev_dbg(dev, "disable_top_cg %s: %d\n", name, ret);
	return ret;
}

static int mt8901_afe_enable_mtcmos(struct mtk_sdw *mst, unsigned int mtcmos)
{
	struct device *dev = mst->dev;
	int ret;

	if (mtcmos >= AUDIO_PD_NUM)
		return -EINVAL;

	ret = mt8901_afe_mtcmos_req(dev, mtcmos, true);
	dev_dbg(dev, "enable_mtcmos %u: %d\n", mtcmos, ret);
	return ret;
}

static int mt8901_afe_disable_mtcmos(struct mtk_sdw *mst, unsigned int mtcmos)
{
	struct device *dev = mst->dev;
	int ret;

	if (mtcmos >= AUDIO_PD_NUM)
		return -EINVAL;

	ret = mt8901_afe_mtcmos_req(dev, mtcmos, false);
	dev_dbg(dev, "disable_mtcmos %u: %d\n", mtcmos, ret);
	return ret;
}

static int mt8901_afe_send_spm_req(struct mtk_sdw *mst, unsigned int req,
				   bool enable)
{
	struct device *dev = mst->dev;
	int ret;

	if (req >= AFE_SPM_CTRL_REQ_NUMS)
		return -EINVAL;

	ret = mt8901_afe_afe_spm_ctrl_req(dev, req, enable);
	dev_dbg(dev, "send_spm_req %u en=%d: %d\n", req, enable, ret);
	return ret;
}

static int mt8901_afe_enable_main_clk_muxes(struct mtk_sdw *mst)
{
	struct device *dev = mst->dev;
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(mt8901_sdw_common_clk_muxes); i++) {
		ret = mt8901_afe_clk_mux_req(dev,
					     mt8901_sdw_common_clk_muxes[i],
					     true);
		dev_dbg(dev, "enable main_clk mux[%d]: %d\n", i, ret);
		if (ret)
			goto err_ret;
	}

	return 0;
err_ret:
	while (i-- > 0)
		mt8901_afe_clk_mux_req(dev, mt8901_sdw_common_clk_muxes[i],
				       false);

	return ret;
}

static int mt8901_afe_disable_main_clk_muxes(struct mtk_sdw *mst)
{
	struct device *dev = mst->dev;
	int i, ret;
	int last_ret = 0;

	for (i = 0; i < ARRAY_SIZE(mt8901_sdw_common_clk_muxes); i++) {
		ret = mt8901_afe_clk_mux_req(dev,
					     mt8901_sdw_common_clk_muxes[i],
					     false);
		dev_dbg(dev, "disable main_clk mux[%d]: %d\n", i, ret);
		if (ret) {
			dev_warn(dev, "disable main_clk mux[%d] failed: %d\n",
				 i, ret);
			last_ret = ret;
		}
	}

	return last_ret;
}

static int mt8901_afe_enable_main_clock(struct mtk_sdw *mst)
{
	struct device *dev = mst->dev;
	int ret;

	ret = mt8901_afe_enable_main_clk_muxes(mst);
	if (ret) {
		dev_err(dev, "enable_main_clk_muxes failed: %d\n", ret);
		return ret;
	}

	ret = mt8901_afe_enable_top_cg(mst, AUD_CG_AUDIO_HOPPING_CK);
	if (ret) {
		dev_err(dev, "enable_top_cg HOPPING failed: %d\n", ret);
		goto err_muxes;
	}

	ret = mt8901_afe_enable_top_cg(mst, AUD_CG_AUDIO_F26M_CK);
	if (ret) {
		dev_err(dev, "enable_top_cg F26M failed: %d\n", ret);
		goto err_hopping;
	}

	ret = mt8901_afe_enable_afe_on(mst);
	if (ret) {
		dev_err(dev, "enable_afe_on failed: %d\n", ret);
		goto err_f26m;
	}

	return 0;

err_f26m:
	mt8901_afe_disable_top_cg(mst, AUD_CG_AUDIO_F26M_CK);
err_hopping:
	mt8901_afe_disable_top_cg(mst, AUD_CG_AUDIO_HOPPING_CK);
err_muxes:
	mt8901_afe_disable_main_clk_muxes(mst);

	return ret;
}

static int mt8901_afe_disable_main_clock(struct mtk_sdw *mst)
{
	struct device *dev = mst->dev;
	int ret;
	int last_ret = 0;

	ret = mt8901_afe_disable_afe_on(mst);
	if (ret) {
		dev_err(dev, "disable_afe_on failed: %d\n", ret);
		last_ret = ret;
	}

	ret = mt8901_afe_disable_top_cg(mst, AUD_CG_AUDIO_F26M_CK);
	if (ret) {
		dev_err(dev, "disable_top_cg F26M failed: %d\n", ret);
		last_ret = ret;
	}

	ret = mt8901_afe_disable_top_cg(mst, AUD_CG_AUDIO_HOPPING_CK);
	if (ret) {
		dev_err(dev, "disable_top_cg HOPPING failed: %d\n", ret);
		last_ret = ret;
	}

	ret = mt8901_afe_disable_main_clk_muxes(mst);
	if (ret) {
		dev_err(dev, "disable_main_clk_muxes failed: %d\n", ret);
		last_ret = ret;
	}

	return last_ret;
}

static int mt8901_afe_enable_reg_rw_clk(struct mtk_sdw *mst)
{
	struct device *dev = mst->dev;
	int ret;

	ret = mt8901_afe_clk_mux_req(dev, AFE_CLK_VLP_CKSYS_TOP_AUD_INTBUS_SEL,
				     true);
	if (ret) {
		dev_err(dev, "enable reg_rw_clk INTBUS failed: %d\n", ret);
		return ret;
	}

	ret = mt8901_afe_clk_mux_req(dev, AFE_CLK_VLP_CKSYS_TOP_VADSP_SEL,
				     true);
	if (ret) {
		dev_err(dev, "enable reg_rw_clk VADSP failed: %d\n", ret);
		goto err_intbus;
	}

	ret = mt8901_afe_enable_top_cg(mst, AUD_CG_AUDIO_F26M_CK);
	if (ret) {
		dev_err(dev, "enable_top_cg F26M failed: %d\n", ret);
		goto err_vadsp;
	}

	return 0;

err_vadsp:
	mt8901_afe_clk_mux_req(dev, AFE_CLK_VLP_CKSYS_TOP_VADSP_SEL, false);
err_intbus:
	mt8901_afe_clk_mux_req(dev, AFE_CLK_VLP_CKSYS_TOP_AUD_INTBUS_SEL,
			       false);

	return ret;
}

static int mt8901_afe_disable_reg_rw_clk(struct mtk_sdw *mst)
{
	struct device *dev = mst->dev;
	int ret;
	int last_ret = 0;

	ret = mt8901_afe_disable_top_cg(mst, AUD_CG_AUDIO_F26M_CK);
	if (ret) {
		dev_err(dev, "disable_top_cg F26M failed: %d\n", ret);
		last_ret = ret;
	}

	ret = mt8901_afe_clk_mux_req(dev, AFE_CLK_VLP_CKSYS_TOP_VADSP_SEL,
				     false);
	if (ret) {
		dev_err(dev, "disable reg_rw_clk VADSP failed: %d\n", ret);
		last_ret = ret;
	}

	ret = mt8901_afe_clk_mux_req(dev, AFE_CLK_VLP_CKSYS_TOP_AUD_INTBUS_SEL,
				     false);
	if (ret) {
		dev_err(dev, "disable reg_rw_clk INTBUS failed: %d\n", ret);
		last_ret = ret;
	}

	return last_ret;
}

static int mt8901_afe_map_clk_parent(unsigned int mux, const char *parent_name,
				     unsigned int *level)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mt8901_clk_parent_map); i++) {
		if (mt8901_clk_parent_map[i].mux == mux &&
		    !strcmp(mt8901_clk_parent_map[i].parent_name,
			    parent_name)) {
			*level = mt8901_clk_parent_map[i].level;
			return 0;
		}
	}

	return -EINVAL;
}

static int mt8901_afe_set_clock_parent(struct mtk_sdw *mst, unsigned int mux,
				       const char *parent_name)
{
	struct device *dev = mst->dev;
	int ret;
	unsigned int parent_level;

	ret = mt8901_afe_map_clk_parent(mux, parent_name, &parent_level);
	if (ret) {
		dev_err(dev, "map_clock_parent mux=%u parent=%s failed %d\n",
			mux, parent_name, ret);
		return ret;
	}

	ret = mt8901_afe_clk_set_parent_req(dev, mux, parent_level);
	dev_dbg(dev, "set_clock_parent mux=%u parent=%u: %d\n",
		mux, parent_level, ret);

	return ret;
}

static int mt8901_afe_enable_sdw_top_clock(struct mtk_sdw *mst, int link)
{
	struct device *dev = mst->dev;
	const unsigned int *clk_array;
	unsigned int clk_array_size;
	int i, ret;

	switch (link) {
	case MTK_SDW_CONTROLLER_0:
		clk_array = mt8901_sdw0_main_clk_muxes;
		clk_array_size = ARRAY_SIZE(mt8901_sdw0_main_clk_muxes);
		break;
	case MTK_SDW_CONTROLLER_1:
		clk_array = mt8901_sdw1_main_clk_muxes;
		clk_array_size = ARRAY_SIZE(mt8901_sdw1_main_clk_muxes);
		break;
	default:
		return -EINVAL;
	}

	for (i = 0; i < clk_array_size; i++) {
		ret = mt8901_afe_clk_mux_req(dev, clk_array[i], true);
		if (ret)
			goto err_ret;
		dev_dbg(dev, "enable sdw_top_clk mux[%d]\n", i);
	}

	return 0;
err_ret:
	while (i-- > 0)
		mt8901_afe_clk_mux_req(dev, clk_array[i], false);
	return ret;
}

static int mt8901_afe_disable_sdw_top_clock(struct mtk_sdw *mst, int link)
{
	struct device *dev = mst->dev;
	const unsigned int *clk_array;
	unsigned int clk_array_size;
	int i, ret;
	int last_ret = 0;

	switch (link) {
	case MTK_SDW_CONTROLLER_0:
		clk_array = mt8901_sdw0_main_clk_muxes;
		clk_array_size = ARRAY_SIZE(mt8901_sdw0_main_clk_muxes);
		break;
	case MTK_SDW_CONTROLLER_1:
		clk_array = mt8901_sdw1_main_clk_muxes;
		clk_array_size = ARRAY_SIZE(mt8901_sdw1_main_clk_muxes);
		break;
	default:
		return -EINVAL;
	}

	for (i = 0; i < clk_array_size; i++) {
		ret = mt8901_afe_clk_mux_req(dev, clk_array[i], false);
		if (ret)
			last_ret = ret;
		dev_dbg(dev, "disable sdw_top_clk mux[%u]\n", i);
	}

	return last_ret;
}

static int mt8901_afe_enable_sdw_active_clock(struct mtk_sdw *mst)
{
	int ret;

	ret = mt8901_afe_clk_mux_req(mst->dev,
				     AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN1_SEL,
				     true);
	if (ret)
		return ret;

	dev_dbg(mst->dev, "enable active_clk mux\n");

	return 0;
}

static int mt8901_afe_disable_sdw_active_clock(struct mtk_sdw *mst)
{
	int ret;

	ret = mt8901_afe_clk_mux_req(mst->dev,
				     AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN1_SEL,
				     false);
	if (ret)
		return ret;

	dev_dbg(mst->dev, "disable active_clk mux\n");
	return 0;
}

static int mt8901_sdw_enable_spm_request(struct mtk_sdw *mst, int link)
{
	int ret;

	ret = mt8901_afe_send_spm_req(mst, AFE_SPM_CTRL_SRCCLKENA_REQ, true);
	if (ret) {
		dev_err(mst->dev, "[%d]request SRCCLKENA failed\n", link);
		return ret;
	}

	if (link == MTK_SDW_CONTROLLER_1) {
		/* Link1 requires VCORE because the PINs are not AO */
		ret = mt8901_afe_send_spm_req(mst, AFE_SPM_CTRL_VCORE_REQ,
					      true);
		if (ret) {
			dev_err(mst->dev, "[%d]request VCORE failed\n", link);
			mt8901_afe_send_spm_req(mst, AFE_SPM_CTRL_SRCCLKENA_REQ,
						false);
			return ret;
		}
	}

	return 0;
}

static int mt8901_sdw_disable_spm_request(struct mtk_sdw *mst, int link)
{
	int ret;
	int last_ret = 0;

	ret = mt8901_afe_send_spm_req(mst, AFE_SPM_CTRL_SRCCLKENA_REQ, false);
	if (ret) {
		dev_err(mst->dev, "[%d]release SRCCLKENA failed\n", link);
		last_ret = ret;
	}

	if (link == MTK_SDW_CONTROLLER_1) {
		ret = mt8901_afe_send_spm_req(mst, AFE_SPM_CTRL_VCORE_REQ,
					      false);
		if (ret) {
			dev_err(mst->dev, "[%d]release VCORE failed\n", link);
			last_ret = ret;
		}
	}

	return last_ret;
}

static int mt8901_sdw_enable_link_clock(struct mtk_sdw *mst, int link)
{
	struct mtk_sdw_link *sdw_link = &mst->links[link];
	int ret;

	ret = mt8901_afe_enable_sdw_top_clock(mst, link);
	if (ret) {
		dev_err(mst->dev, "failed to enable sdw_top clock, ret %d\n",
			ret);
		return ret;
	}

	ret = mt8901_afe_enable_main_clock(mst);
	if (ret) {
		dev_err(mst->dev, "failed to enable main clock, ret %d\n", ret);
		mt8901_afe_disable_sdw_top_clock(mst, link);
		return ret;
	}

	if (!sdw_link->active_clk_enabled) {
		ret = mt8901_afe_enable_sdw_active_clock(mst);
		if (ret) {
			dev_err(mst->dev,
				"failed to enable main clock, ret %d\n", ret);
			goto err_ret;
		}
		sdw_link->active_clk_enabled = true;
	}

	if (link == MTK_SDW_CONTROLLER_0) {
		ret = mt8901_afe_enable_top_cg(mst, AUD_CG_SOUNDWIRE0);
		if (ret) {
			dev_err(mst->dev, "failed to enable top cg %d, ret %d\n",
				AUD_CG_SOUNDWIRE0, ret);
			goto err_ret;
		}
	} else {
		ret = mt8901_afe_enable_top_cg(mst, AUD_CG_SOUNDWIRE0);
		if (ret) {
			dev_err(mst->dev, "failed to enable top cg %d, ret %d\n",
				AUD_CG_SOUNDWIRE0, ret);
			goto err_ret;
		}
		ret = mt8901_afe_enable_top_cg(mst, AUD_CG_SOUNDWIRE1);
		if (ret) {
			dev_err(mst->dev, "failed to enable top cg %d, ret %d\n",
				AUD_CG_SOUNDWIRE1, ret);
			mt8901_afe_disable_top_cg(mst, AUD_CG_SOUNDWIRE0);
			goto err_ret;
		}
	}

	ret = mt8901_afe_enable_top_cg(mst, AUD_CG_APLL2_CK);
	if (ret) {
		dev_err(mst->dev, "failed to enable top cg %d, ret %d\n",
			AUD_CG_APLL2_CK, ret);
		goto err_ret_cg;
	}

	return 0;
err_ret_cg:
	if (link == MTK_SDW_CONTROLLER_0) {
		mt8901_afe_disable_top_cg(mst, AUD_CG_SOUNDWIRE0);
	} else {
		mt8901_afe_disable_top_cg(mst, AUD_CG_SOUNDWIRE0);
		mt8901_afe_disable_top_cg(mst, AUD_CG_SOUNDWIRE1);
	}
err_ret:
	if (sdw_link->active_clk_enabled) {
		mt8901_afe_disable_sdw_active_clock(mst);
		sdw_link->active_clk_enabled = false;
	}

	mt8901_afe_disable_main_clock(mst);
	mt8901_afe_disable_sdw_top_clock(mst, link);

	return ret;
}

static int mt8901_sdw_disable_link_clock(struct mtk_sdw *mst, int link)
{
	struct mtk_sdw_link *sdw_link = &mst->links[link];
	int ret;
	int last_ret = 0;

	ret = mt8901_afe_disable_top_cg(mst, AUD_CG_APLL2_CK);
	if (ret) {
		dev_err(mst->dev, "failed to disable top cg %d, ret %d\n",
			AUD_CG_APLL2_CK, ret);
		last_ret = ret;
	}

	if (link == MTK_SDW_CONTROLLER_0) {
		ret = mt8901_afe_disable_top_cg(mst, AUD_CG_SOUNDWIRE0);
		if (ret) {
			dev_err(mst->dev,
				"failed to disable top cg %d, ret %d\n",
				AUD_CG_SOUNDWIRE0, ret);
			last_ret = ret;
		}
	} else {
		ret = mt8901_afe_disable_top_cg(mst, AUD_CG_SOUNDWIRE0);
		if (ret) {
			dev_err(mst->dev,
				"failed to disable top cg %d, ret %d\n",
				AUD_CG_SOUNDWIRE0, ret);
			last_ret = ret;
		}
		ret = mt8901_afe_disable_top_cg(mst, AUD_CG_SOUNDWIRE1);
		if (ret) {
			dev_err(mst->dev,
				"failed to disable top cg %d, ret %d\n",
				AUD_CG_SOUNDWIRE1, ret);
			last_ret = ret;
		}
	}

	ret = mt8901_afe_disable_main_clock(mst);
	if (ret) {
		dev_err(mst->dev, "failed to disable main clock, ret %d\n",
			ret);
		last_ret = ret;
	}

	if (sdw_link->active_clk_enabled) {
		ret = mt8901_afe_disable_sdw_active_clock(mst);
		if (ret) {
			dev_err(mst->dev,
				"failed to disable main clock, ret %d\n", ret);
			last_ret = ret;
		}
		sdw_link->active_clk_enabled = false;
	}

	ret = mt8901_afe_disable_sdw_top_clock(mst, link);
	if (ret) {
		dev_err(mst->dev, "failed to disable sdw_top clock, ret %d\n",
			ret);
		last_ret = ret;
	}

	return last_ret;
}

static int mt8901_sdw_enable_reg_rw_clk(struct mtk_sdw *mst)
{
	return mt8901_afe_enable_reg_rw_clk(mst);
}

static int mt8901_sdw_disable_reg_rw_clk(struct mtk_sdw *mst)
{
	return mt8901_afe_disable_reg_rw_clk(mst);
}

static int mt8901_sdw_enable_power_domain(struct mtk_sdw *mst)
{
	return mt8901_afe_enable_mtcmos(mst, AUDIO_PD);
}

static int mt8901_sdw_disable_power_domain(struct mtk_sdw *mst)
{
	return mt8901_afe_disable_mtcmos(mst, AUDIO_PD);
}

const struct mtk_sdw_clk_ops mt8901_clk_ops = {
	.init_clock            = mt8901_sdw_init_clock,
	.enable_reg_rw_clk      = mt8901_sdw_enable_reg_rw_clk,
	.disable_reg_rw_clk     = mt8901_sdw_disable_reg_rw_clk,
	.enable_link_clock      = mt8901_sdw_enable_link_clock,
	.disable_link_clock     = mt8901_sdw_disable_link_clock,
	.enable_power_domain    = mt8901_sdw_enable_power_domain,
	.disable_power_domain   = mt8901_sdw_disable_power_domain,
	.enable_spm_request     = mt8901_sdw_enable_spm_request,
	.disable_spm_request    = mt8901_sdw_disable_spm_request,
};
