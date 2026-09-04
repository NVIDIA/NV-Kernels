// SPDX-License-Identifier: GPL-2.0
/*
 * MediaTek SoundWire master driver
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 */

#include <linux/acpi.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/property.h>
#include <linux/soc/mediatek/mtk-pinctrl.h>
#include <linux/soundwire/sdw.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/soc.h>
#include <sound/soc-acpi.h>
#include <sound/soc-dai.h>
#include "mtk-sdw.h"
#include "mtk-sdw-mach.h"
#include "mtk-sdw-top.h"

static acpi_status mtk_sdw_apply_pin_bias_cb(struct acpi_resource *res,
					     void *context)
{
	struct mtk_sdw_acpi_cb_context *ctx = context;
	struct device *dev = ctx->dev;
	struct acpi_resource_pin_function *pf;
	u32 pullup;
	int i, err;

	if (res->type != ACPI_RESOURCE_TYPE_PIN_FUNCTION)
		return AE_OK;

	pf = &res->data.pin_function;

	switch (pf->pin_config) {
	case MTK_SDW_PIN_CFG_BUS_HOLD:
		pullup = MTK_PIN_BUS_HOLD;
		break;
	case MTK_SDW_PIN_CFG_PD:
		pullup = MTK_PIN_PULLDOWN;
		break;
	default:
		dev_dbg(dev,
			"SDW _CRS PinFunction pin_cfg=0x%02x - leaving default bias\n",
			pf->pin_config);
		return AE_OK;
	}

	for (i = 0; i < pf->pin_table_length; i++) {
		unsigned int pin = pf->pin_table[i];

		err = mtk_pinctrl_program_bias_by_gpio(pin, pullup,
						       MTK_PIN_ENABLE);
		if (err == -EPROBE_DEFER) {
			ctx->err = -EPROBE_DEFER;
			return AE_CTRL_TERMINATE;
		} else if (err == -ENODEV) {
			dev_warn(dev,
				 "SDW pin %u: no pinctrl owns this GPIO - DSDT/SoC mismatch\n",
				 pin);
		} else if (err) {
			dev_warn(dev,
				 "SDW pin %u: bias program failed (pin_cfg=0x%02x, err=%d)\n",
				 pin, pf->pin_config, err);
		} else {
			dev_dbg(dev,
				"SDW pin %u: pin_cfg=0x%02x -> pullup=%u applied\n",
				pin, pf->pin_config, pullup);
		}
	}

	return AE_OK;
}

static int mtk_sdw_apply_pin_config(struct device *dev)
{
	acpi_handle handle = ACPI_HANDLE(dev);
	acpi_status status;
	struct mtk_sdw_acpi_cb_context ctx = {
		.dev = dev,
		.err = 0,
	};

	if (!handle) {
		dev_info(dev, "No ACPI handle\n");
		return 0;
	}

	/* pin bias */
	status = acpi_walk_resources(handle, METHOD_NAME__CRS,
				     mtk_sdw_apply_pin_bias_cb, &ctx);

	if (ACPI_FAILURE(status)) {
		dev_warn(dev,
			 "SDW _CRS walk failed (0x%x) - pin bias not programmed from DSDT\n",
			 status);
		return -EIO;
	}

	/* only handle a defer probe error*/
	if (ctx.err == -EPROBE_DEFER)
		return -EPROBE_DEFER;

	return 0;
}

static int mtk_sdw_parse_dp_allocation(struct mtk_sdw *mst, int idx)
{
	struct mtk_sdw_link *link = &mst->links[idx];
	struct fwnode_handle *node;
	char key[32];
	u32 dp[4];
	int ret;

	snprintf(key, sizeof(key), "acpi-scd-%d-subproperties", idx);
	node = device_get_named_child_node(mst->dev, key);
	if (!node)
		return dev_err_probe(mst->dev, -ENODEV,
				     "link %d: missing %s node\n", idx, key);

	ret = fwnode_property_read_u32_array(node, "acpi-scd-dp-allocation", dp,
					     ARRAY_SIZE(dp));
	fwnode_handle_put(node);
	if (ret)
		return dev_err_probe(mst->dev, ret,
				     "link %d: bad acpi-scd-dp-allocation\n",
				     idx);

	/* { source_base, source_num, sink_base, sink_num } */
	link->src_base = dp[0];
	link->src_num = dp[1];
	link->sink_base = dp[2];
	link->sink_num = dp[3];

	dev_dbg(mst->dev, "link %d DP alloc: src %u..%u, sink %u..%u\n", idx,
		link->src_base, link->src_base + link->src_num - 1,
		link->sink_base, link->sink_base + link->sink_num - 1);
	return 0;
}

static int mtk_sdw_init_clock(struct mtk_sdw *mst)
{
	int ret;

	ret = mst->clk_ops->init_clock(mst);
	if (ret)
		dev_err(mst->dev, "failed to init clock, ret %d\n", ret);

	return ret;
}

static int mtk_sdw_enable_top_clock(struct mtk_sdw *mst, int link)
{
	int ret;

	ret = mst->clk_ops->enable_link_clock(mst, link);
	if (ret)
		dev_err(mst->dev, "failed to enable top clock, ret %d\n", ret);

	return ret;
}

static int mtk_sdw_disable_top_clock(struct mtk_sdw *mst, int link)
{
	int ret;

	ret = mst->clk_ops->disable_link_clock(mst, link);
	if (ret)
		dev_err(mst->dev, "failed to disable top clock, ret %d\n", ret);

	return ret;
}

static int mtk_sdw_enable_reg_clock(struct mtk_sdw *mst)
{
	int ret;

	ret = mst->clk_ops->enable_reg_rw_clk(mst);
	if (ret)
		dev_err(mst->dev, "failed to enable reg clock, ret %d\n", ret);

	return ret;
}

static int mtk_sdw_disable_reg_clock(struct mtk_sdw *mst)
{
	int ret;

	ret = mst->clk_ops->disable_reg_rw_clk(mst);
	if (ret)
		dev_err(mst->dev, "failed to disable reg clock, ret %d\n", ret);

	return ret;
}

static int mtk_sdw_enable_power(struct mtk_sdw *mst)
{
	int ret;

	ret = mst->clk_ops->enable_power_domain(mst);
	if (ret)
		dev_err(mst->dev, "failed to enable power, ret %d\n", ret);

	return ret;
}

static int mtk_sdw_disable_power(struct mtk_sdw *mst)
{
	int ret;

	ret = mst->clk_ops->disable_power_domain(mst);
	if (ret)
		dev_err(mst->dev, "failed to disable power, ret %d\n", ret);

	return ret;
}

/* =======================================================================
 * ASoC DAI layer  (ALSA <-> SoundWire stream binding)
 * =======================================================================
 */

static int mtk_sdw_set_sdw_stream(struct snd_soc_dai *dai, void *stream,
				  int direction)
{
	struct mtk_sdw *mst = snd_soc_dai_get_drvdata(dai);

	mst->dais[dai->id].sruntime = stream;
	return 0;
}

static void *mtk_sdw_get_sdw_stream(struct snd_soc_dai *dai, int direction)
{
	struct mtk_sdw *mst = snd_soc_dai_get_drvdata(dai);

	return mst->dais[dai->id].sruntime;
}

static unsigned int derive_afe_fs_timing(unsigned int rate)
{
	unsigned int fs = 0;

	switch (rate) {
	case RATE_384000:
		fs = MT8901_FS_384K;
		break;
	case RATE_352800:
		fs = MT8901_FS_352D8K;
		break;
	case RATE_192000:
		fs = MT8901_FS_192K;
		break;
	case RATE_176400:
		fs = MT8901_FS_176D4K;
		break;
	case RATE_96000:
		fs = MT8901_FS_96K;
		break;
	case RATE_88200:
		fs = MT8901_FS_88D2K;
		break;
	case RATE_48000:
		fs = MT8901_FS_48K;
		break;
	case RATE_44100:
		fs = MT8901_FS_44D1K;
		break;
	case RATE_32000:
		fs = MT8901_FS_32K;
		break;
	case RATE_24000:
		fs = MT8901_FS_24K;
		break;
	case RATE_22050:
		fs = MT8901_FS_22D05K;
		break;
	case RATE_16000:
		fs = MT8901_FS_16K;
		break;
	case RATE_12000:
		fs = MT8901_FS_12K;
		break;
	case RATE_8000:
		fs = MT8901_FS_8K;
		break;
	default:
		break;
	}

	return fs;
}

static int mtk_sdw_dai_hw_params(struct snd_pcm_substream *substream,
				 struct snd_pcm_hw_params *params,
				 struct snd_soc_dai *dai)
{
	struct mtk_sdw *mst = snd_soc_dai_get_drvdata(dai);
	struct mtk_sdw_dai *mdai = &mst->dais[dai->id];
	struct sdw_stream_config sconfig = { 0 };
	struct sdw_port_config pconfig = { 0 };
	struct mtk_sdw_port_params mtk_port_param = { 0 };
	struct mtk_sdw_top_pdi_params *top_params;
	int dir, ret, i;
	unsigned long pdis;
	unsigned int pdi;
	unsigned int channels = params_channels(params);
	unsigned int rate = params_rate(params);
	unsigned int pdi_count;
	unsigned int ch_per_pdi = SDW_DEFAULT_CH_PER_PDI;
	unsigned int tmp = 0;
	unsigned int group_sync_config = 0;
	unsigned int pdi_begin;
	unsigned int last_pdi;

	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE)
		dir = SDW_DATA_DIR_RX;
	else
		dir = SDW_DATA_DIR_TX;

	pdis = (mdai->port_num < MTK_SDW_MAX_DP) ?
		mst->dp_pdi_mask[mdai->port_num] : 0;
	for_each_set_bit(pdi, &pdis, MTK_SDW_MAX_DP) {
		dev_dbg(dai->dev, "DP%u <- PDI%u\n", mdai->port_num, pdi);
		if (tmp++) {
			if (pdi != last_pdi + 1) {
				dev_dbg(dai->dev, "unexpected last PDI %u, PDI%u\n",
					last_pdi, pdi);
				return -EINVAL;
			}
		} else {
			pdi_begin = pdi;
		}
		last_pdi = pdi;
	}

	pdi_count = (channels + ch_per_pdi - 1) / ch_per_pdi;
	if (tmp != pdi_count) {
		dev_err(dai->dev, "pdi mask 0x%x\n doesn't match channel %u",
			mst->dp_pdi_mask[mdai->port_num], channels);
		return -EINVAL;
	}

	mdai->use_group_sync = false;

	if (pdi_count > 1) {
		mdai->use_group_sync = true;

		ret = mtk_sdw_top_group_sync_acquire(mst,
						     dir == SDW_DATA_DIR_TX);
		if (ret < 0)
			return ret;
		mdai->group_sync_id = ret;

		ret = mtk_sdw_top_group_sync_config_get(mst,
							mdai->group_sync_id,
							&group_sync_config);
		if (ret < 0) {
			mtk_sdw_top_group_sync_release(mst,
						       mdai->group_sync_id);
			mdai->group_sync_id = 0;
			return ret;
		}
	}

	/* update pdi_params */
	mdai->top_pdi_params = devm_kcalloc(mst->dev, pdi_count,
					    sizeof(*mdai->top_pdi_params),
					    GFP_KERNEL);
	if (!mdai->top_pdi_params) {
		ret = -ENOMEM;
		goto err_group_sync;
	}
	mdai->pdi_count = pdi_count;
	mdai->need_enable_delay = TRUE;
	for (i = 0; i < pdi_count; i++) {
		mdai->pdi_params[i].pdi_num = pdi_begin++;
		mdai->pdi_params[i].port_num = mdai->port_num;
		mdai->pdi_params[i].ch_mask = (1 << (i * ch_per_pdi)) |
			(1 << (i * ch_per_pdi + 1));

		top_params = &mdai->top_pdi_params[i];
		top_params->group_sync = group_sync_config;
		//top_params->slave_mode = 0;
		top_params->bra_slave = 0; //ToDo : BRA
		top_params->bra_mode = 0; //ToDo : BRA
		top_params->bra_eop = (top_params->bra_mode != 0) ? 1 : 0;
		top_params->dmic_1xen = 0;
		top_params->pdm_one_wire = 0;
		top_params->pdm_mode = 0;
		//top_params->hd_sel = 0;
		top_params->clock = IS_48K_RATE_DOMAIN(rate) ? 1 : 0;
		top_params->pdm2pcm = 0;
		top_params->sdw_ip_sel = mdai->link->ip_idx;
		/* ToDo: SpecifyPdiMode for BRA */
		top_params->domain = MT8901_APLL_CLK_DOMAIN;
		/* ToDo: SpecifyPdiFs for BRA */
		top_params->fs = derive_afe_fs_timing(rate);

		if (top_params->bra_mode != 0 && top_params->bra_slave != 0)
			mdai->need_enable_delay = FALSE;
	}

	pconfig.num = mdai->port_num;
	pconfig.ch_mask = GENMASK(channels - 1, 0);

	sconfig.frame_rate = rate;
	sconfig.ch_count = channels;
	sconfig.bps = snd_pcm_format_width(params_format(params));
	sconfig.direction = dir;
	sconfig.type = SDW_STREAM_PCM;

	mtk_port_param.port_num = pconfig.num;
	mtk_port_param.bpt_payload_type = 0;
	mtk_port_param.bpt_en = true;
	mtk_sdw_configure_port_params(&mdai->link->core, &mtk_port_param, dir);

	for (i = 0; i < mdai->pdi_count; i++) {
		top_params = &mdai->top_pdi_params[i];
		mtk_sdw_top_configure_pdi(mst, mdai->pdi_params[i].pdi_num,
					  top_params);
		mtk_sdw_configure_pdi_params(&mdai->link->core,
					     &mdai->pdi_params[i]);
	}

	ret = sdw_stream_add_master(&mdai->link->core.bus, &sconfig, &pconfig,
				    1, mdai->sruntime);
	if (ret)
		goto err_group_sync;

	return 0;

err_group_sync:
	if (mdai->group_sync_id > 0) {
		mtk_sdw_top_group_sync_release(mst, mdai->group_sync_id);
		mdai->group_sync_id = 0;
	}
	mdai->use_group_sync = false;
	return ret;
}

static int mtk_sdw_dai_hw_free(struct snd_pcm_substream *substream,
			       struct snd_soc_dai *dai)
{
	struct mtk_sdw *mst = snd_soc_dai_get_drvdata(dai);
	struct mtk_sdw_dai *mdai = &mst->dais[dai->id];
	int i, ret;

	ret = sdw_stream_remove_master(&mdai->link->core.bus, mdai->sruntime);
	if (ret < 0)
		dev_err(dai->dev, "remove manager from stream %s failed: %d\n",
			mdai->sruntime->name, ret);

	for (i = 0; i < mdai->pdi_count; i++)
		mtk_sdw_clear_pdi_settings(&mdai->link->core,
					   &mdai->pdi_params[i]);

	if (mdai->group_sync_id > 0) {
		mtk_sdw_top_group_sync_release(mst, mdai->group_sync_id);
		mdai->group_sync_id = 0;
	}
	mdai->use_group_sync = false;

	devm_kfree(mst->dev, mdai->top_pdi_params);
	return ret;
}

/* configure top stream here, it can be called before dai_link ops */
static int mtk_sdw_dai_trigger(struct snd_pcm_substream *substream, int cmd,
			       struct snd_soc_dai *dai)
{
	struct mtk_sdw *mst = snd_soc_dai_get_drvdata(dai);
	struct mtk_sdw_dai *mdai = &mst->dais[dai->id];

	mtk_sdw_core_dump_dpn_regs(&mdai->link->core, mdai->port_num,
				   "trigger");

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
		return mtk_sdw_top_enable_stream(mst, dai->id);
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
		return mtk_sdw_top_disable_stream(mst, dai->id);
	default:
		return -EINVAL;
	}
}

static const struct snd_soc_dai_ops mtk_sdw_dai_ops = {
	.hw_params = mtk_sdw_dai_hw_params,
	.hw_free = mtk_sdw_dai_hw_free,
	.trigger = mtk_sdw_dai_trigger,
	.set_stream = mtk_sdw_set_sdw_stream,
	.get_stream = mtk_sdw_get_sdw_stream,
};

/* =======================================================================
 * DAPM: PDI <-> DP routing
 * =======================================================================
 */

/* Playback DEMUX target DPs (item 0 == "None"). */
static const char * const mtk_sdw_playback_dp_texts[] = {
	"None", "DP2", "DP3", "DP4", "DP5", "DP6",
};

/* Capture MUX source DPs (item 0 == "None"). */
static const char * const mtk_sdw_capture_dp_texts[] = {
	"None", "DP7", "DP8", "DP9", "DP10",
	"DP11", "DP12", "DP13", "DP14", "DP15",
};

static int mtk_sdw_pdi_route_put(struct snd_kcontrol *kc,
				 struct snd_ctl_elem_value *uc)
{
	struct snd_soc_dapm_context *dapm = snd_soc_dapm_kcontrol_to_dapm(kc);
	struct snd_soc_component *comp = snd_soc_dapm_to_component(dapm);
	struct mtk_sdw *mst = snd_soc_component_get_drvdata(comp);
	struct soc_enum *e = (struct soc_enum *)kc->private_value;
	unsigned int item = uc->value.enumerated.item[0];
	unsigned int pdi, dp, d;

	if (sscanf(kc->id.name, "PDI%u", &pdi) != 1)
		return -EINVAL;
	if (pdi >= BITS_PER_TYPE(mst->dp_pdi_mask[0]))
		return -EINVAL;
	if (item >= e->items)
		return -EINVAL;

	for (d = 0; d < MTK_SDW_MAX_DP; d++)
		mst->dp_pdi_mask[d] &= ~BIT(pdi);

	if (item && sscanf(e->texts[item], "DP%u", &dp) == 1 &&
	    dp < MTK_SDW_MAX_DP)
		mst->dp_pdi_mask[dp] |= BIT(pdi);

	return snd_soc_dapm_put_enum_double(kc, uc);
}

/* Playback: PGA(PDIn) -> DEMUX(PDIn) -> one of DP2..DP6. */
#define MTK_SDW_PLAYBACK_PDI(pdi) \
static SOC_ENUM_SINGLE_VIRT_DECL(mtk_sdw_pdi##pdi##_enum, \
				 mtk_sdw_playback_dp_texts); \
static const struct snd_kcontrol_new mtk_sdw_pdi##pdi##_demux = \
	SOC_DAPM_ENUM_EXT("PDI" #pdi " Demux Select", \
			  mtk_sdw_pdi##pdi##_enum, \
			  snd_soc_dapm_get_enum_double, \
			  mtk_sdw_pdi_route_put)

/* Capture: one of DP7..DP15 -> MUX(PDIn) -> PGA(PDIn). */
#define MTK_SDW_CAPTURE_PDI(pdi) \
static SOC_ENUM_SINGLE_VIRT_DECL(mtk_sdw_pdi##pdi##_enum, \
				 mtk_sdw_capture_dp_texts); \
static const struct snd_kcontrol_new mtk_sdw_pdi##pdi##_mux = \
	SOC_DAPM_ENUM_EXT("PDI" #pdi " Mux Select", \
			  mtk_sdw_pdi##pdi##_enum, \
			  snd_soc_dapm_get_enum_double, \
			  mtk_sdw_pdi_route_put)

MTK_SDW_PLAYBACK_PDI(2);
MTK_SDW_PLAYBACK_PDI(3);
MTK_SDW_PLAYBACK_PDI(4);
MTK_SDW_PLAYBACK_PDI(5);
MTK_SDW_PLAYBACK_PDI(6);

MTK_SDW_CAPTURE_PDI(7);
MTK_SDW_CAPTURE_PDI(8);
MTK_SDW_CAPTURE_PDI(9);
MTK_SDW_CAPTURE_PDI(10);
MTK_SDW_CAPTURE_PDI(11);
MTK_SDW_CAPTURE_PDI(12);
MTK_SDW_CAPTURE_PDI(13);
MTK_SDW_CAPTURE_PDI(14);
MTK_SDW_CAPTURE_PDI(15);

/* PDI node + its selector. */
#define MTK_SDW_PDI_PGA(pdi) \
	SND_SOC_DAPM_PGA("PDI" #pdi, SND_SOC_NOPM, 0, 0, NULL, 0)
#define MTK_SDW_PLAYBACK_PDI_DEMUX(pdi) \
	SND_SOC_DAPM_DEMUX("PDI" #pdi " Demux", SND_SOC_NOPM, 0, 0, \
			   &mtk_sdw_pdi##pdi##_demux)
#define MTK_SDW_CAPTURE_PDI_MUX(pdi) \
	SND_SOC_DAPM_MUX("PDI" #pdi " Mux", SND_SOC_NOPM, 0, 0, \
			 &mtk_sdw_pdi##pdi##_mux)

/* DP node. */
#define MTK_SDW_DP_WIDGET(dp)						\
	SND_SOC_DAPM_PGA("DP" #dp, SND_SOC_NOPM, 0, 0, NULL, 0)

static const struct snd_soc_dapm_widget mtk_sdw_dapm_widgets[] = {
	/* BRA PDIs, no DP connection */
	SND_SOC_DAPM_PGA("PDI0", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_PGA("PDI1", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_PGA("PDI16", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_PGA("PDI17", SND_SOC_NOPM, 0, 0, NULL, 0),

	/* Playback PDIs + demuxes */
	MTK_SDW_PDI_PGA(2),  MTK_SDW_PLAYBACK_PDI_DEMUX(2),
	MTK_SDW_PDI_PGA(3),  MTK_SDW_PLAYBACK_PDI_DEMUX(3),
	MTK_SDW_PDI_PGA(4),  MTK_SDW_PLAYBACK_PDI_DEMUX(4),
	MTK_SDW_PDI_PGA(5),  MTK_SDW_PLAYBACK_PDI_DEMUX(5),
	MTK_SDW_PDI_PGA(6),  MTK_SDW_PLAYBACK_PDI_DEMUX(6),
	/* Capture PDIs + muxes */
	MTK_SDW_PDI_PGA(7),  MTK_SDW_CAPTURE_PDI_MUX(7),
	MTK_SDW_PDI_PGA(8),  MTK_SDW_CAPTURE_PDI_MUX(8),
	MTK_SDW_PDI_PGA(9),  MTK_SDW_CAPTURE_PDI_MUX(9),
	MTK_SDW_PDI_PGA(10), MTK_SDW_CAPTURE_PDI_MUX(10),
	MTK_SDW_PDI_PGA(11), MTK_SDW_CAPTURE_PDI_MUX(11),
	MTK_SDW_PDI_PGA(12), MTK_SDW_CAPTURE_PDI_MUX(12),
	MTK_SDW_PDI_PGA(13), MTK_SDW_CAPTURE_PDI_MUX(13),
	MTK_SDW_PDI_PGA(14), MTK_SDW_CAPTURE_PDI_MUX(14),
	MTK_SDW_PDI_PGA(15), MTK_SDW_CAPTURE_PDI_MUX(15),
	/* DP nodes */
	MTK_SDW_DP_WIDGET(2),  MTK_SDW_DP_WIDGET(3),  MTK_SDW_DP_WIDGET(4),
	MTK_SDW_DP_WIDGET(5),  MTK_SDW_DP_WIDGET(6),  MTK_SDW_DP_WIDGET(7),
	MTK_SDW_DP_WIDGET(8),  MTK_SDW_DP_WIDGET(9),  MTK_SDW_DP_WIDGET(10),
	MTK_SDW_DP_WIDGET(11), MTK_SDW_DP_WIDGET(12), MTK_SDW_DP_WIDGET(13),
	MTK_SDW_DP_WIDGET(14), MTK_SDW_DP_WIDGET(15),
};

/*
 * Playback edge: PDIn -> PDIn Demux -> DPx (active when demux selects "DPx").
 */
#define MTK_SDW_PLAYBACK_DEMUX_OUT(pdi, dp) \
	{ "DP" #dp, "DP" #dp, "PDI" #pdi " Demux" }
#define MTK_SDW_PLAYBACK_PDI_LINK(pdi) \
	{ "PDI" #pdi " Demux", NULL, "PDI" #pdi }

/* Capture edge: DPx -> PDIn Mux -> PDIn (active when mux selects "DPx"). */
#define MTK_SDW_CAPTURE_MUX_IN(pdi, dp) \
	{ "PDI" #pdi " Mux", "DP" #dp, "DP" #dp }
#define MTK_SDW_CAPTURE_PDI_LINK(pdi) \
	{ "PDI" #pdi, NULL, "PDI" #pdi " Mux" }

static const struct snd_soc_dapm_route mtk_sdw_dapm_routes[] = {
	/* Playback: PDI2..PDI6 -> DP2..DP6 */
	MTK_SDW_PLAYBACK_PDI_LINK(2),
	MTK_SDW_PLAYBACK_DEMUX_OUT(2, 2), MTK_SDW_PLAYBACK_DEMUX_OUT(2, 3),
	MTK_SDW_PLAYBACK_DEMUX_OUT(2, 4), MTK_SDW_PLAYBACK_DEMUX_OUT(2, 5),
	MTK_SDW_PLAYBACK_DEMUX_OUT(2, 6),
	MTK_SDW_PLAYBACK_PDI_LINK(3),
	MTK_SDW_PLAYBACK_DEMUX_OUT(3, 2), MTK_SDW_PLAYBACK_DEMUX_OUT(3, 3),
	MTK_SDW_PLAYBACK_DEMUX_OUT(3, 4), MTK_SDW_PLAYBACK_DEMUX_OUT(3, 5),
	MTK_SDW_PLAYBACK_DEMUX_OUT(3, 6),
	MTK_SDW_PLAYBACK_PDI_LINK(4),
	MTK_SDW_PLAYBACK_DEMUX_OUT(4, 2), MTK_SDW_PLAYBACK_DEMUX_OUT(4, 3),
	MTK_SDW_PLAYBACK_DEMUX_OUT(4, 4), MTK_SDW_PLAYBACK_DEMUX_OUT(4, 5),
	MTK_SDW_PLAYBACK_DEMUX_OUT(4, 6),
	MTK_SDW_PLAYBACK_PDI_LINK(5),
	MTK_SDW_PLAYBACK_DEMUX_OUT(5, 2), MTK_SDW_PLAYBACK_DEMUX_OUT(5, 3),
	MTK_SDW_PLAYBACK_DEMUX_OUT(5, 4), MTK_SDW_PLAYBACK_DEMUX_OUT(5, 5),
	MTK_SDW_PLAYBACK_DEMUX_OUT(5, 6),
	MTK_SDW_PLAYBACK_PDI_LINK(6),
	MTK_SDW_PLAYBACK_DEMUX_OUT(6, 2), MTK_SDW_PLAYBACK_DEMUX_OUT(6, 3),
	MTK_SDW_PLAYBACK_DEMUX_OUT(6, 4), MTK_SDW_PLAYBACK_DEMUX_OUT(6, 5),
	MTK_SDW_PLAYBACK_DEMUX_OUT(6, 6),
	/* Capture: DP7..DP15 -> PDI7..PDI15 */
	MTK_SDW_CAPTURE_MUX_IN(7, 7), MTK_SDW_CAPTURE_MUX_IN(7, 8),
	MTK_SDW_CAPTURE_MUX_IN(7, 9), MTK_SDW_CAPTURE_MUX_IN(7, 10),
	MTK_SDW_CAPTURE_MUX_IN(7, 11), MTK_SDW_CAPTURE_MUX_IN(7, 12),
	MTK_SDW_CAPTURE_MUX_IN(7, 13), MTK_SDW_CAPTURE_MUX_IN(7, 14),
	MTK_SDW_CAPTURE_MUX_IN(7, 15),
	MTK_SDW_CAPTURE_PDI_LINK(7),
	MTK_SDW_CAPTURE_MUX_IN(8, 7), MTK_SDW_CAPTURE_MUX_IN(8, 8),
	MTK_SDW_CAPTURE_MUX_IN(8, 9), MTK_SDW_CAPTURE_MUX_IN(8, 10),
	MTK_SDW_CAPTURE_MUX_IN(8, 11), MTK_SDW_CAPTURE_MUX_IN(8, 12),
	MTK_SDW_CAPTURE_MUX_IN(8, 13), MTK_SDW_CAPTURE_MUX_IN(8, 14),
	MTK_SDW_CAPTURE_MUX_IN(8, 15),
	MTK_SDW_CAPTURE_PDI_LINK(8),
	MTK_SDW_CAPTURE_MUX_IN(9, 7), MTK_SDW_CAPTURE_MUX_IN(9, 8),
	MTK_SDW_CAPTURE_MUX_IN(9, 9), MTK_SDW_CAPTURE_MUX_IN(9, 10),
	MTK_SDW_CAPTURE_MUX_IN(9, 11), MTK_SDW_CAPTURE_MUX_IN(9, 12),
	MTK_SDW_CAPTURE_MUX_IN(9, 13), MTK_SDW_CAPTURE_MUX_IN(9, 14),
	MTK_SDW_CAPTURE_MUX_IN(9, 15),
	MTK_SDW_CAPTURE_PDI_LINK(9),
	MTK_SDW_CAPTURE_MUX_IN(10, 7), MTK_SDW_CAPTURE_MUX_IN(10, 8),
	MTK_SDW_CAPTURE_MUX_IN(10, 9), MTK_SDW_CAPTURE_MUX_IN(10, 10),
	MTK_SDW_CAPTURE_MUX_IN(10, 11), MTK_SDW_CAPTURE_MUX_IN(10, 12),
	MTK_SDW_CAPTURE_MUX_IN(10, 13), MTK_SDW_CAPTURE_MUX_IN(10, 14),
	MTK_SDW_CAPTURE_MUX_IN(10, 15),
	MTK_SDW_CAPTURE_PDI_LINK(10),
	MTK_SDW_CAPTURE_MUX_IN(11, 7), MTK_SDW_CAPTURE_MUX_IN(11, 8),
	MTK_SDW_CAPTURE_MUX_IN(11, 9), MTK_SDW_CAPTURE_MUX_IN(11, 10),
	MTK_SDW_CAPTURE_MUX_IN(11, 11), MTK_SDW_CAPTURE_MUX_IN(11, 12),
	MTK_SDW_CAPTURE_MUX_IN(11, 13), MTK_SDW_CAPTURE_MUX_IN(11, 14),
	MTK_SDW_CAPTURE_MUX_IN(11, 15),
	MTK_SDW_CAPTURE_PDI_LINK(11),
	MTK_SDW_CAPTURE_MUX_IN(12, 7), MTK_SDW_CAPTURE_MUX_IN(12, 8),
	MTK_SDW_CAPTURE_MUX_IN(12, 9), MTK_SDW_CAPTURE_MUX_IN(12, 10),
	MTK_SDW_CAPTURE_MUX_IN(12, 11), MTK_SDW_CAPTURE_MUX_IN(12, 12),
	MTK_SDW_CAPTURE_MUX_IN(12, 13), MTK_SDW_CAPTURE_MUX_IN(12, 14),
	MTK_SDW_CAPTURE_MUX_IN(12, 15),
	MTK_SDW_CAPTURE_PDI_LINK(12),
	MTK_SDW_CAPTURE_MUX_IN(13, 7), MTK_SDW_CAPTURE_MUX_IN(13, 8),
	MTK_SDW_CAPTURE_MUX_IN(13, 9), MTK_SDW_CAPTURE_MUX_IN(13, 10),
	MTK_SDW_CAPTURE_MUX_IN(13, 11), MTK_SDW_CAPTURE_MUX_IN(13, 12),
	MTK_SDW_CAPTURE_MUX_IN(13, 13), MTK_SDW_CAPTURE_MUX_IN(13, 14),
	MTK_SDW_CAPTURE_MUX_IN(13, 15),
	MTK_SDW_CAPTURE_PDI_LINK(13),
	MTK_SDW_CAPTURE_MUX_IN(14, 7), MTK_SDW_CAPTURE_MUX_IN(14, 8),
	MTK_SDW_CAPTURE_MUX_IN(14, 9), MTK_SDW_CAPTURE_MUX_IN(14, 10),
	MTK_SDW_CAPTURE_MUX_IN(14, 11), MTK_SDW_CAPTURE_MUX_IN(14, 12),
	MTK_SDW_CAPTURE_MUX_IN(14, 13), MTK_SDW_CAPTURE_MUX_IN(14, 14),
	MTK_SDW_CAPTURE_MUX_IN(14, 15),
	MTK_SDW_CAPTURE_PDI_LINK(14),
	MTK_SDW_CAPTURE_MUX_IN(15, 7), MTK_SDW_CAPTURE_MUX_IN(15, 8),
	MTK_SDW_CAPTURE_MUX_IN(15, 9), MTK_SDW_CAPTURE_MUX_IN(15, 10),
	MTK_SDW_CAPTURE_MUX_IN(15, 11), MTK_SDW_CAPTURE_MUX_IN(15, 12),
	MTK_SDW_CAPTURE_MUX_IN(15, 13), MTK_SDW_CAPTURE_MUX_IN(15, 14),
	MTK_SDW_CAPTURE_MUX_IN(15, 15),
	MTK_SDW_CAPTURE_PDI_LINK(15),
};

static int mtk_sdw_add_dai_routes(struct snd_soc_component *comp)
{
	struct mtk_sdw *mst = snd_soc_component_get_drvdata(comp);
	struct snd_soc_dapm_context *dapm = snd_soc_component_to_dapm(comp);
	int i, p, ret;

	for (i = 0; i < mst->num_links; i++) {
		struct mtk_sdw_link *link = &mst->links[i];
		int offset;

		offset = 0;
		for (p = 0; p < link->src_num; p++, offset++) {
			char dai[32], dp[8];
			struct snd_soc_dapm_route r = { dai, NULL, dp };

			snprintf(dai, sizeof(dai), "SDW%d_Playback%u",
				 link->ip_idx, offset);
			snprintf(dp, sizeof(dp), "DP%u", link->src_base + p);
			ret = snd_soc_dapm_add_routes(dapm, &r, 1);
			if (ret)
				return ret;
		}

		offset = 0;
		for (p = 0; p < link->sink_num; p++, offset++) {
			char dai[32], dp[8];
			struct snd_soc_dapm_route r = { dp, NULL, dai };

			snprintf(dai, sizeof(dai), "SDW%d_Capture%u",
				 link->ip_idx, offset);
			snprintf(dp, sizeof(dp), "DP%u", link->sink_base + p);
			ret = snd_soc_dapm_add_routes(dapm, &r, 1);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int mtk_sdw_component_probe(struct snd_soc_component *comp)
{
	return mtk_sdw_add_dai_routes(comp);
}

static const struct snd_soc_component_driver mtk_sdw_component = {
	.name             = "mtk-soundwire",
	.probe            = mtk_sdw_component_probe,
	.dapm_widgets     = mtk_sdw_dapm_widgets,
	.num_dapm_widgets = ARRAY_SIZE(mtk_sdw_dapm_widgets),
	.dapm_routes      = mtk_sdw_dapm_routes,
	.num_dapm_routes  = ARRAY_SIZE(mtk_sdw_dapm_routes),
};

static int mtk_sdw_init_dai(struct mtk_sdw *mst, struct snd_soc_dai_driver *drv,
			    int idx, struct mtk_sdw_link *link,
			    unsigned int port, int offset, bool playback)
{
	struct snd_soc_pcm_stream *stream;

	drv->id   = idx;
	drv->ops  = &mtk_sdw_dai_ops;

	if (playback) {
		drv->name = devm_kasprintf(mst->dev, GFP_KERNEL,
					   "SDW%d_Playback%u",
					   link->ip_idx, offset);
		if (!drv->name)
			return -ENOMEM;

		stream = &drv->playback;
	} else {
		drv->name = devm_kasprintf(mst->dev, GFP_KERNEL,
					   "SDW%d_Capture%u",
					   link->ip_idx, offset);
		if (!drv->name)
			return -ENOMEM;

		stream = &drv->capture;
	}

	stream->channels_min = 2;
	stream->channels_max = 8;
	stream->rates = SNDRV_PCM_RATE_48000;
	stream->rates = SNDRV_PCM_RATE_8000_384000;
	/* S32 dropped: the AFE path is 24-bit internally, see MTK_PCM_FORMATS */
	stream->formats = SNDRV_PCM_FMTBIT_S16_LE |
			  SNDRV_PCM_FMTBIT_S24_LE;

	stream->stream_name = drv->name;

	mst->dais[idx].link      = link;
	mst->dais[idx].port_num  = port;

	return 0;
}

static int mtk_sdw_register_dais(struct mtk_sdw *mst)
{
	struct snd_soc_dai_driver *drvs;
	struct device *dev = mst->dev;
	int i, p, idx = 0, num = 0, ret;

	for (i = 0; i < mst->num_links; i++)
		num += mst->links[i].src_num + mst->links[i].sink_num;
	if (!num)
		return dev_err_probe(dev, -EINVAL, "no data ports allocated\n");

	mst->dais = devm_kcalloc(dev, num, sizeof(*mst->dais), GFP_KERNEL);
	if (!mst->dais)
		return -ENOMEM;

	drvs      = devm_kcalloc(dev, num, sizeof(*drvs), GFP_KERNEL);
	if (!drvs)
		return -ENOMEM;

	for (i = 0; i < mst->num_links; i++) {
		struct mtk_sdw_link *link = &mst->links[i];
		int offset;

		offset = 0;
		/* Source ports -> playback DAIs */
		for (p = 0; p < link->src_num; p++, idx++, offset++) {
			ret = mtk_sdw_init_dai(mst, &drvs[idx], idx, link,
					       link->src_base + p, offset,
					       true);
			if (ret)
				return ret;
		}

		offset = 0;
		/* Sink ports -> capture DAIs */
		for (p = 0; p < link->sink_num; p++, idx++, offset++) {
			ret = mtk_sdw_init_dai(mst, &drvs[idx], idx, link,
					       link->sink_base + p, offset,
					       false);
			if (ret)
				return ret;
		}
	}
	mst->num_dais = num;

	return devm_snd_soc_register_component(dev, &mtk_sdw_component, drvs,
					       num);
}

/* =======================================================================
 * Per-IP bring-up
 * =======================================================================
 */

static int mtk_sdw_link_init(struct mtk_sdw *mst, int idx)
{
	struct mtk_sdw_link *link = &mst->links[idx];
	struct mtk_sdw_core *core = &link->core;
	struct sdw_master_prop *prop;
	int ret;

	link->master = mst;
	link->ip_idx = idx;

	core->dev          = mst->dev;
	core->priv         = link;

	core->bus.link_id  = idx;
	core->bus.prop.mclk_freq = SDW_DEFAULT_MCLK_CLK_FREQ;

	ret = mtk_sdw_core_init(core);
	if (ret)
		return ret;

	ret = mtk_sdw_enable_top_clock(mst, idx);
	if (ret) {
		dev_err(mst->dev, "IP%d: enable top clock failed: %d\n",
			idx, ret);
		return ret;
	}

	core->bus.dev = mst->dev;
	ret = sdw_bus_master_add(&core->bus, mst->dev, mst->dev->fwnode);
	if (ret) {
		dev_err(mst->dev, "IP%d: bus_master_add failed: %d\n",
			idx, ret);
		goto err_disable_top_clock;
	}

	//property ready here.
	prop = &core->bus.prop;
	if (!prop->max_clk_freq)
		prop->max_clk_freq = SDW_DEFAULT_MAX_BUS_CLK_FREQ;
	if (!prop->default_frame_rate)
		prop->default_frame_rate = SDW_DEFAULT_FRAME_RATE;
	if (!prop->default_row)
		prop->default_row = SDW_DEFAULT_FRAME_SHAPE_ROW;
	if (!prop->default_col)
		prop->default_col = SDW_DEFAULT_FRAME_SHAPE_COL;

	ret = mtk_sdw_core_hw_init(core);
	if (ret) {
		sdw_bus_master_delete(&core->bus);
		goto err_disable_top_clock;
	}

	mtk_sdw_enable_irq(core, true);
	dev_info(mst->dev, "IP%d: SoundWire bus ready\n", idx);
	return 0;

err_disable_top_clock:
	mtk_sdw_disable_top_clock(mst, idx);
	return ret;
}

static void mtk_sdw_link_deinit(struct mtk_sdw *mst, int idx)
{
	struct mtk_sdw_core *core = &mst->links[idx].core;

	mtk_sdw_enable_irq(core, false);
	sdw_bus_master_delete(&core->bus);
}

static void mtk_init_sdw_master(struct mtk_sdw *mst)
{
	int i;

	mst->tzd_delay = 3;
	mst->tzd_inverse = 0;
	mst->phy_delay = 2;
	mst->phy_double_delay = 0;
	mst->num_links = MTK_SDW_CONTROLLE_NUM;

	for (i = 0; i < MTK_SDW_CONTROLLE_NUM; i++)
		mst->controller_en_list |= (1UL << i);
}

static int mtk_sdw_register_machine(struct mtk_sdw *mst)
{
	struct snd_soc_acpi_mach *mach;

	mach = mtk_sdw_machine_select(mst);
	if (!mach) {
		dev_info(mst->dev, "no card from this controller\n");
		return 0;   /* no card from this controller; not an error */
	}

	mst->mach_dev = platform_device_register_data(mst->dev, mach->drv_name,
						      PLATFORM_DEVID_NONE,
						      mach, sizeof(*mach));
	if (IS_ERR(mst->mach_dev)) {
		dev_err(mst->dev, "failed to register machine %s\n",
			mach->drv_name);
		return PTR_ERR(mst->mach_dev);
	}

	dev_info(mst->dev, "registered SoundWire machine %s\n", mach->drv_name);
	return 0;
}

static int mtk_sdw_probe_controller(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mtk_sdw *mst;
	u32 hw_ver = MTK_SDW_HW_VER_MT8901;
	u32 mmio[2];
	int i, ret;
	bool clk_on;

	mst = devm_kzalloc(dev, sizeof(*mst), GFP_KERNEL);
	if (!mst)
		return -ENOMEM;

	/* Ignore other errors except for EPROBE_DEFER */
	ret = mtk_sdw_apply_pin_config(dev);
	if (ret == -EPROBE_DEFER)
		return ret;
	else if (ret)
		dev_info(dev, "fail to apply pin config\n");

	mtk_init_sdw_master(mst);

	mst->dev = dev;
	mutex_init(&mst->group_lock);
	mutex_init(&mst->afe_lock);
	platform_set_drvdata(pdev, mst);

	ret = device_property_read_u32_array(dev, "afe-base", mmio, 2);
	if (ret)
		return dev_err_probe(dev, ret,
				     "missing/invalid afe-base property\n");
	dev_info(dev, "address %x, size %d\n", mmio[0], mmio[1]);

	mst->base = devm_ioremap(dev, mmio[0], mmio[1]);
	if (!mst->base)
		return -ENOMEM;
	mst->top_pdi = mst->base + AFE_SDW_TOP_PDI_REG_BASE;
	mst->top_con = mst->base + AFE_SDW_TOP_CON_REG_BASE;

	device_property_read_u32(dev, "acpi-scd-hw-ver", &hw_ver);
	if (hw_ver >= MTK_SDW_HW_VER_MAX)
		return dev_err_probe(dev, -EINVAL,
				     "unknown acpi-scd-hw-ver %u\n", hw_ver);

	mst->hw_ver = hw_ver;

	ret = mtk_sdw_top_config_select(mst, mst->hw_ver);
	if (ret)
		return ret;

	ret = mtk_sdw_clk_ops_select(mst, mst->hw_ver);
	if (ret)
		return ret;

	/* Timing delays from ACPI _DSD. */
	device_property_read_u32(dev, "acpi-scd-tzd-delay", &mst->tzd_delay);
	device_property_read_u32(dev, "acpi-scd-phy-delay", &mst->phy_delay);
	device_property_read_u32(dev, "acpi-scd-phy-double-delay",
				 &mst->phy_double_delay);

	if (mst->tzd_delay <= mst->phy_delay) {
		dev_err(dev, "invalid delay, tzd %u - phy %u", mst->tzd_delay,
			mst->phy_delay);
		return -EINVAL;
	}

	ret = mtk_sdw_init_clock(mst);
	if (ret)
		return ret;

	ret = mtk_sdw_enable_reg_clock(mst);
	if (ret)
		return ret;

	clk_on = true;

	mtk_sdw_top_init_settings(mst);
	mtk_sdw_top_configure_delays(mst);

	for (i = 0; i < mst->num_links; i++) {
		int irq = platform_get_irq(pdev, i);
		struct mtk_sdw_core *core = &mst->links[i].core;

		if (irq < 0) {
			ret = irq;
			goto err;
		}
		mst->links[i].irq = irq;
		mst->links[i].ip_idx = i;

		ret = mtk_sdw_parse_dp_allocation(mst, i);
		if (ret)
			goto err;

		core->regs = devm_platform_ioremap_resource(pdev, i);
		if (IS_ERR(core->regs)) {
			ret = PTR_ERR(core->regs);
			goto err;
		}

		ret = devm_request_irq(dev, irq, mtk_sdw_core_irq, IRQF_SHARED,
				       dev_name(dev), core);
		if (ret) {
			dev_err(dev, "IP%d: request_irq failed: %d\n", i, ret);
			goto err;
		}

		ret = mtk_sdw_link_init(mst, i);
		if (ret)
			goto err;
	}

	ret = mtk_sdw_disable_reg_clock(mst);
	if (ret)
		goto err;
	clk_on = false;

	ret = mtk_sdw_register_dais(mst);
	if (ret) {
		dev_err(dev, "failed to register DAIs: %d\n", ret);
		goto err;
	}

	dev_info(dev, "MediaTek SoundWire ready, %d link(s), %d DAI(s)\n",
		 mst->num_links, mst->num_dais);

	return 0;

err:
	while (--i >= 0)
		mtk_sdw_link_deinit(mst, i);

	if (clk_on)
		mtk_sdw_disable_reg_clock(mst);

	return ret;
}

static int mtk_sdw_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mtk_sdw *mst;
	int i, ret;

	ret = mtk_sdw_probe_controller(pdev);
	if (ret) {
		dev_err(dev, "failed to probe_controller %d\n", ret);
		return ret;
	}

	mst = platform_get_drvdata(pdev);

	ret = mtk_sdw_register_machine(mst);
	if (ret) {
		for (i = mst->num_links - 1; i >= 0; i--)
			mtk_sdw_link_deinit(mst, i);

		return ret;
	}

	return 0;
}

static void mtk_sdw_remove(struct platform_device *pdev)
{
	struct mtk_sdw *mst = platform_get_drvdata(pdev);
	int i;

	if (mst->mach_dev)
		platform_device_unregister(mst->mach_dev);
	for (i = mst->num_links - 1; i >= 0; i--)
		mtk_sdw_link_deinit(mst, i);
}

static int __maybe_unused mtk_sdw_suspend(struct device *dev)
{
	struct mtk_sdw *mst = dev_get_drvdata(dev);
	int i, ret;

	for (i = 0; i < mst->num_links; i++) {
		struct mtk_sdw_core *core = &mst->links[i].core;

		mtk_sdw_enable_irq(core, false);

		ret = mtk_sdw_disable_top_clock(mst, i);
		if (ret) {
			dev_err(dev, "mtk_sdw_disable_top_clock failed: %d\n",
				ret);
			goto err_reenable;
		}

		/*
		 * The SSPM power refcount is one vote per link (the firmware
		 * initializes it to the link count, and the Windows driver
		 * relinquishes once per SoundWire IP), so vote per link, not
		 * per master, or the count never reaches zero and the SoC
		 * cannot enter PPS7/PPS8.
		 */
		ret = mtk_sdw_disable_power(mst);
		if (ret) {
			mtk_sdw_enable_top_clock(mst, i);
			goto err_reenable;
		}
	}

	return 0;

err_reenable:
	while (--i >= 0) {
		mtk_sdw_enable_power(mst);
		mtk_sdw_enable_top_clock(mst, i);
	}
	for (i = 0; i < mst->num_links; i++)
		mtk_sdw_enable_irq(&mst->links[i].core, true);

	return ret;
}

static int __maybe_unused mtk_sdw_resume(struct device *dev)
{
	struct mtk_sdw *mst = dev_get_drvdata(dev);
	int i, ret;

	for (i = 0; i < mst->num_links; i++) {
		struct mtk_sdw_core *core = &mst->links[i].core;

		/* One power vote per link; see mtk_sdw_suspend(). */
		ret = mtk_sdw_enable_power(mst);
		if (ret)
			goto err_disable;

		ret = mtk_sdw_enable_top_clock(mst, i);
		if (ret) {
			dev_err(dev, "mtk_sdw_enable_top_clock failed: %d\n",
				ret);
			mtk_sdw_disable_power(mst);
			goto err_disable;
		}

		mtk_sdw_enable_irq(core, true);
	}

	return 0;

err_disable:
	while (--i >= 0) {
		mtk_sdw_enable_irq(&mst->links[i].core, false);
		mtk_sdw_disable_top_clock(mst, i);
		mtk_sdw_disable_power(mst);
	}

	return ret;
}

static const struct acpi_device_id mtk_sdw_acpi_match[] = {
	{ "NVDA9100", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, mtk_sdw_acpi_match);

static const struct dev_pm_ops mtk_sdw_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(mtk_sdw_suspend, mtk_sdw_resume)
};

static struct platform_driver mtk_sdw_driver = {
	.probe  = mtk_sdw_probe,
	.remove = mtk_sdw_remove,
	.driver = {
		.name             = "mtk-soundwire",
		.acpi_match_table = mtk_sdw_acpi_match,
		.pm = &mtk_sdw_pm_ops,
	},
};
module_platform_driver(mtk_sdw_driver);

MODULE_DESCRIPTION("MediaTek SoundWire master");
MODULE_AUTHOR("Trevor Wu <trevor.wu@mediatek.com>");
MODULE_LICENSE("GPL");
