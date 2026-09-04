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
#include "mt8901-afe-common.h"
#include "mt8901-afe-clk.h"
#include "mt8901-reg.h"
#include <linux/soc/mediatek/mtk-pwrap.h>

static const unsigned int mt8901_main_clk_muxes[] = {
	AFE_CLK_VLP_CKSYS_TOP_AUDIO_H_SEL,
	AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN1_SEL,
	AFE_CLK_VLP_CKSYS_TOP_AUD_ENGEN2_SEL,
	AFE_CLK_VLP_CKSYS_TOP_AUD_INTBUS_SEL,
	AFE_CLK_VLP_CKSYS_TOP_AUD_1_SEL,
	AFE_CLK_VLP_CKSYS_TOP_AUD_2_SEL,
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

static int mt8901_afe_enable_afe_on(struct mtk_base_afe *afe)
{
	unsigned int mask;

	mask = AUDIO_ENGEN_CON0_APLL2_MASK |
	       AUDIO_ENGEN_CON0_APLL1_MASK |
	       AUDIO_ENGEN_CON0_26M_MASK;
	return regmap_update_bits(afe->regmap, AUDIO_ENGEN_CON0, mask, mask);
}

static int mt8901_afe_disable_afe_on(struct mtk_base_afe *afe)
{
	unsigned int mask;

	mask = AUDIO_ENGEN_CON0_APLL2_MASK |
	       AUDIO_ENGEN_CON0_APLL1_MASK |
	       AUDIO_ENGEN_CON0_26M_MASK;
	return regmap_update_bits(afe->regmap, AUDIO_ENGEN_CON0, mask, 0x0);
}

static int mt8901_afe_check_sspm_probe(struct mtk_base_afe *afe)
{
	struct device *dev = afe->dev;
	int ret;

	ret = mt8901_afe_pwr_ctrl_scene_req(dev, AUDIO_PWR_SCEN_NORMAL);
	if (ret) {
		dev_err(dev, "SSPM probe failed: %d\n", ret);
		return ret;
	}

	dev_dbg(dev, "SSPM available\n");
	return 0;
}

int mt8901_afe_disable_default_on_clk_and_top_cg(struct mtk_base_afe *afe)
{
	struct device *dev = afe->dev;
	int ret;

	ret = mt8901_afe_clk_cg_deinit_req(dev);
	dev_dbg(dev, "disable_default_on_clk_and_top_cg: %d\n", ret);

	return ret;
}

int mt8901_afe_init_clock(struct mtk_base_afe *afe)
{
	struct device *dev = afe->dev;
	int ret;

	ret = mt8901_afe_check_sspm_probe(afe);
	if (ret)
		return ret;

	ret = mt8901_afe_disable_default_on_clk_and_top_cg(afe);
	if (ret) {
		dev_err(dev, "disable_default_on_clk_and_top_cg failed: %d\n",
			ret);
		return ret;
	}

	return ret;
}

int mt8901_afe_enable_top_cg(struct mtk_base_afe *afe, unsigned int cg)
{
	struct device *dev = afe->dev;
	const char *name;
	int ret;

	if (cg >= AUD_CG_NUMS)
		return -EINVAL;

	name = mt8901_cg_names[cg];

	ret = mt8901_afe_cg_req(dev, cg, true);

	dev_dbg(dev, "enable_top_cg %s: %d\n", name, ret);
	return ret;
}

int mt8901_afe_disable_top_cg(struct mtk_base_afe *afe, unsigned int cg)
{
	struct device *dev = afe->dev;
	const char *name;
	int ret;

	if (cg >= AUD_CG_NUMS)
		return -EINVAL;

	name = mt8901_cg_names[cg];

	ret = mt8901_afe_cg_req(dev, cg, false);

	dev_dbg(dev, "disable_top_cg %s: %d\n", name, ret);
	return ret;
}

int mt8901_afe_enable_apll_top_con_cg(struct mtk_base_afe *afe)
{
	struct device *dev = afe->dev;
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(mt8901_apll_top_con_cgs); i++) {
		ret = mt8901_afe_enable_top_cg(afe, mt8901_apll_top_con_cgs[i]);
		if (ret) {
			dev_err(dev, "enable_top_cg %s failed: %d\n",
				mt8901_cg_names[mt8901_apll_top_con_cgs[i]],
				ret);
			goto err;
		}
	}

	return 0;

err:
	while (i-- > 0)
		mt8901_afe_disable_top_cg(afe, mt8901_apll_top_con_cgs[i]);

	return ret;
}

int mt8901_afe_disable_apll_top_con_cg(struct mtk_base_afe *afe)
{
	struct device *dev = afe->dev;
	int i, ret;
	int last_ret = 0;

	for (i = ARRAY_SIZE(mt8901_apll_top_con_cgs) - 1; i >= 0; i--) {
		ret = mt8901_afe_disable_top_cg(afe,
						mt8901_apll_top_con_cgs[i]);
		if (ret) {
			dev_warn(dev, "disable_top_cg %s failed: %d\n",
				 mt8901_cg_names[mt8901_apll_top_con_cgs[i]],
				 ret);
			last_ret = ret;
		}
	}

	return last_ret;
}

int mt8901_afe_enable_mtcmos(struct mtk_base_afe *afe, unsigned int mtcmos)
{
	struct device *dev = afe->dev;
	int ret;

	if (mtcmos >= AUDIO_PD_NUM)
		return -EINVAL;

	ret = mt8901_afe_mtcmos_req(dev, mtcmos, true);
	dev_dbg(dev, "enable_mtcmos %u: %d\n", mtcmos, ret);
	return ret;
}

int mt8901_afe_disable_mtcmos(struct mtk_base_afe *afe, unsigned int mtcmos)
{
	struct device *dev = afe->dev;
	int ret;

	if (mtcmos >= AUDIO_PD_NUM)
		return -EINVAL;

	ret = mt8901_afe_mtcmos_req(dev, mtcmos, false);
	dev_dbg(dev, "disable_mtcmos %u: %d\n", mtcmos, ret);
	return ret;
}

int mt8901_afe_send_spm_req(struct mtk_base_afe *afe, unsigned int req,
			    bool enable)
{
	struct device *dev = afe->dev;
	int ret;

	if (req >= AFE_SPM_CTRL_REQ_NUMS)
		return -EINVAL;

	ret = mt8901_afe_afe_spm_ctrl_req(dev, req, enable);
	dev_dbg(dev, "send_spm_req %u en=%d: %d\n", req, enable, ret);
	return ret;
}

static int mt8901_afe_enable_main_clk_muxes(struct mtk_base_afe *afe)
{
	struct device *dev = afe->dev;
	int i, ret;

	for (i = 0; i < ARRAY_SIZE(mt8901_main_clk_muxes); i++) {
		ret = mt8901_afe_clk_mux_req(dev, mt8901_main_clk_muxes[i],
					     true);
		dev_dbg(dev, "enable main_clk mux[%d]: %d\n", i, ret);
		if (ret)
			goto err_ret;
	}

	return 0;
err_ret:
	while (i-- > 0)
		mt8901_afe_clk_mux_req(dev, mt8901_main_clk_muxes[i], false);

	return ret;
}

static int mt8901_afe_disable_main_clk_muxes(struct mtk_base_afe *afe)
{
	struct device *dev = afe->dev;
	int i, ret;
	int last_ret = 0;

	for (i = 0; i < ARRAY_SIZE(mt8901_main_clk_muxes); i++) {
		ret = mt8901_afe_clk_mux_req(dev, mt8901_main_clk_muxes[i],
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

int mt8901_afe_enable_main_clock(struct mtk_base_afe *afe)
{
	struct device *dev = afe->dev;
	int ret;

	ret = mt8901_afe_enable_main_clk_muxes(afe);
	if (ret) {
		dev_err(dev, "enable_main_clk_muxes failed: %d\n", ret);
		return ret;
	}

	ret = mt8901_afe_enable_top_cg(afe, AUD_CG_AUDIO_HOPPING_CK);
	if (ret) {
		dev_err(dev, "enable_top_cg HOPPING failed: %d\n", ret);
		goto err_muxes;
	}

	ret = mt8901_afe_enable_top_cg(afe, AUD_CG_AUDIO_F26M_CK);
	if (ret) {
		dev_err(dev, "enable_top_cg F26M failed: %d\n", ret);
		goto err_hopping;
	}

	ret = mt8901_afe_enable_afe_on(afe);
	if (ret) {
		dev_err(dev, "enable_afe_on failed: %d\n", ret);
		goto err_f26m;
	}

	return 0;

err_f26m:
	mt8901_afe_disable_top_cg(afe, AUD_CG_AUDIO_F26M_CK);
err_hopping:
	mt8901_afe_disable_top_cg(afe, AUD_CG_AUDIO_HOPPING_CK);
err_muxes:
	mt8901_afe_disable_main_clk_muxes(afe);

	return ret;
}

int mt8901_afe_disable_main_clock(struct mtk_base_afe *afe)
{
	struct device *dev = afe->dev;
	int ret;
	int last_ret = 0;

	ret = mt8901_afe_disable_afe_on(afe);
	if (ret) {
		dev_err(dev, "disable_afe_on failed: %d\n", ret);
		last_ret = ret;
	}

	ret = mt8901_afe_disable_top_cg(afe, AUD_CG_AUDIO_F26M_CK);
	if (ret) {
		dev_err(dev, "disable_top_cg F26M failed: %d\n", ret);
		last_ret = ret;
	}

	ret = mt8901_afe_disable_top_cg(afe, AUD_CG_AUDIO_HOPPING_CK);
	if (ret) {
		dev_err(dev, "disable_top_cg HOPPING failed: %d\n", ret);
		last_ret = ret;
	}

	ret = mt8901_afe_disable_main_clk_muxes(afe);
	if (ret) {
		dev_err(dev, "disable_main_clk_muxes failed: %d\n", ret);
		last_ret = ret;
	}

	return last_ret;
}

int mt8901_afe_enable_reg_rw_clk(struct mtk_base_afe *afe)
{
	struct device *dev = afe->dev;
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

	ret = mt8901_afe_enable_top_cg(afe, AUD_CG_AUDIO_F26M_CK);
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

int mt8901_afe_disable_reg_rw_clk(struct mtk_base_afe *afe)
{
	struct device *dev = afe->dev;
	int ret;
	int last_ret = 0;

	ret = mt8901_afe_disable_top_cg(afe, AUD_CG_AUDIO_F26M_CK);
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

int mt8901_afe_set_clock_parent(struct mtk_base_afe *afe, unsigned int mux,
				const char *parent_name)
{
	struct device *dev = afe->dev;
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

int mt8901_afe_set_idle_clock_parent(struct mtk_base_afe *afe, bool idle)
{
	const char *parent_name;
	int i, j, ret;

	for (i = 0; i < ARRAY_SIZE(idle_clk_muxes); i++) {
		parent_name = idle ? idle_clk_muxes[i].idle_parent_name :
				     idle_clk_muxes[i].active_parent_name;

		ret = mt8901_afe_set_clock_parent(afe, idle_clk_muxes[i].mux,
						  parent_name);
		if (ret)
			goto err_rollback;
	}

	return 0;

err_rollback:
	/*
	 * Best effort: re-parent the muxes already switched back to the
	 * other set, so a failed transition does not leave a mixed
	 * idle/active clock topology.
	 */
	for (j = i - 1; j >= 0; j--) {
		parent_name = idle ? idle_clk_muxes[j].active_parent_name :
				     idle_clk_muxes[j].idle_parent_name;
		mt8901_afe_set_clock_parent(afe, idle_clk_muxes[j].mux,
					    parent_name);
	}

	return ret;
}
