// SPDX-License-Identifier: GPL-2.0
/*
 * MediaTek ALSA SoC AFE platform driver for 8901
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 *         Weiyi Hsieh <weiyi.hsieh@mediatek.com>
 */

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/acpi.h>
#include <sound/pcm_params.h>
#include "mt8901-afe-common.h"
#include "mt8901-afe-clk.h"
#include "mt8901-reg.h"
#include "../common/mtk-afe-platform-driver.h"
#include "../common/mtk-afe-fe-dai.h"

#define MICROSECONDS_PER_SECOND (1000000UL)
#define STEREO_CH 2
#define CLK_RATE_26M		26000000
#define CM_UPDATE_CNT_OFFSET	10

/* hardware constants */
#define MT8901_DMA_ADDR_BITS 33 //ToDo: check 40bits
#define MT8901_MEMIF_MINLEN 64
#define MT8901_MEMIF_MAXLEN 64
#define MT8901_CM0_MAX_CH 8
#define MT8901_CM1_MAX_CH 16
/* CM2 exposes 16 wired inputs (O064-O079 <- I170-I185), not the HW max 32 */
#define MT8901_CM2_MAX_CH 16
#define MT8901_MEMIF_BUFFER_BYTES_ALIGN (0x10)

/* experience values */
#define IO_INTF_DELAY_IN_SAMPLES 3
#define SERIAL_TO_PARALLEL_DELAY_IN_SAMPLES 1
#define CHANNEL_MERGE_DELAY_IN_SAMPLES 1
#define INTERCONN_DELAY_IN_SAMPLES 1

#define MTK_PCM_RATES (SNDRV_PCM_RATE_8000_48000 |\
		       SNDRV_PCM_RATE_88200 |\
		       SNDRV_PCM_RATE_96000 |\
		       SNDRV_PCM_RATE_176400 |\
		       SNDRV_PCM_RATE_192000 |\
		       SNDRV_PCM_RATE_352800 |\
		       SNDRV_PCM_RATE_384000)

#define MTK_PCM_FORMATS (SNDRV_PCM_FMTBIT_S16_LE |\
			 SNDRV_PCM_FMTBIT_S24_LE |\
			 SNDRV_PCM_FMTBIT_S32_LE)

struct mtk_dai_memif_priv {
	unsigned int fs_timing;
	unsigned int domain;
	unsigned int minlen;
	unsigned int maxlen;
};

static const struct snd_pcm_hardware mt8901_afe_hardware = {
	.info = SNDRV_PCM_INFO_MMAP |
		SNDRV_PCM_INFO_INTERLEAVED |
		SNDRV_PCM_INFO_MMAP_VALID |
		SNDRV_PCM_INFO_NO_PERIOD_WAKEUP,
	.formats = SNDRV_PCM_FMTBIT_S16_LE |
		   SNDRV_PCM_FMTBIT_S24_LE |
		   SNDRV_PCM_FMTBIT_S32_LE,
	.period_bytes_min = 64,
	.period_bytes_max = 256 * 1024,
	.periods_min = 2,
	.periods_max = 256,
	.buffer_bytes_max = 256 * 2 * 1024,
};

struct mt8901_afe_rate {
	unsigned int rate;
	unsigned int reg_value;
};

static const struct mt8901_afe_rate mt8901_afe_rates[] = {
	{ .rate = 8000, .reg_value = 0, },
	{ .rate = 11025, .reg_value = 1, },
	{ .rate = 12000, .reg_value = 2, },
	{ .rate = 16000, .reg_value = 4, },
	{ .rate = 22050, .reg_value = 5, },
	{ .rate = 24000, .reg_value = 6, },
	{ .rate = 32000, .reg_value = 8, },
	{ .rate = 44100, .reg_value = 9, },
	{ .rate = 48000, .reg_value = 10, },
	{ .rate = 88200, .reg_value = 13, },
	{ .rate = 96000, .reg_value = 14, },
	{ .rate = 176400, .reg_value = 17, },
	{ .rate = 192000, .reg_value = 18, },
	{ .rate = 352800, .reg_value = 21, },
	{ .rate = 384000, .reg_value = 22, },
};

int mt8901_afe_fs_timing(struct device *dev, unsigned int rate)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mt8901_afe_rates); i++)
		if (mt8901_afe_rates[i].rate == rate)
			return mt8901_afe_rates[i].reg_value;

	dev_err(dev, "rate %u invalid!!!\n", rate);

	return -EINVAL;
}

static int mt8901_memif_fs(struct snd_pcm_substream *substream,
			   unsigned int rate)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_soc_component *component = NULL;
	struct mtk_base_afe *afe = NULL;

	component = snd_soc_rtdcom_lookup(rtd, AFE_PCM_NAME);
	if (!component)
		return -EINVAL;

	afe = snd_soc_component_get_drvdata(component);
	if (!afe)
		return -EINVAL;

	return mt8901_afe_fs_timing(afe->dev, rate);
}

static int mt8901_irq_fs(struct snd_pcm_substream *substream,
			 unsigned int rate)
{
	return mt8901_memif_fs(substream, rate);
}

enum {
	MT8901_AFE_CM0,
	MT8901_AFE_CM1,
	MT8901_AFE_CM2,
	MT8901_AFE_CM_NUM,
};

struct mt8901_afe_channel_merge {
	int id;
	int reg;
	unsigned int sel_shift;
	unsigned int sel_maskbit;
	unsigned int sel_default;
	unsigned int ch_num_shift;
	unsigned int ch_num_maskbit;
	unsigned int en_shift;
	unsigned int en_maskbit;
	unsigned int update_cnt_shift;
	unsigned int update_cnt_maskbit;
	unsigned int update_cnt_default;
	unsigned int domain_shift;
	unsigned int domain_maskbit;
	unsigned int fs_shift;
	unsigned int fs_maskbit;
	unsigned int output_mux_shift;
	unsigned int output_mux_maskbit;
};

static const struct mt8901_afe_channel_merge
	mt8901_afe_cm[MT8901_AFE_CM_NUM] = {
	[MT8901_AFE_CM0] = {
		.id = MT8901_AFE_CM0,
		.reg = AFE_CM0_CON0,
		.sel_shift = 31,
		.sel_maskbit = 0x1,
		.sel_default = 0,
		.ch_num_shift = 2,
		.ch_num_maskbit = 0x1f,
		.en_shift = 0,
		.en_maskbit = 0x1,
		.update_cnt_shift = 16,
		.update_cnt_maskbit = 0x7fff,
		.update_cnt_default = 0x6,
		.domain_shift = 13,
		.domain_maskbit = 0x7,
		.fs_shift = 8,
		.fs_maskbit = 0x1f,
		.output_mux_shift = 7,
		.output_mux_maskbit = 0x1,
	},
	[MT8901_AFE_CM1] = {
		.id = MT8901_AFE_CM1,
		.reg = AFE_CM1_CON0,
		.sel_shift = 31,
		.sel_maskbit = 0x1,
		.sel_default = 0,
		.ch_num_shift = 2,
		.ch_num_maskbit = 0x1f,
		.en_shift = 0,
		.en_maskbit = 0x1,
		.update_cnt_shift = 16,
		.update_cnt_maskbit = 0x7fff,
		.update_cnt_default = 0x6,
		.domain_shift = 13,
		.domain_maskbit = 0x7,
		.fs_shift = 8,
		.fs_maskbit = 0x1f,
		.output_mux_shift = 7,
		.output_mux_maskbit = 0x1,
	},
	[MT8901_AFE_CM2] = {
		.id = MT8901_AFE_CM2,
		.reg = AFE_CM2_CON0,
		.sel_shift = 31,
		.sel_maskbit = 0x1,
		.sel_default = 0,
		.ch_num_shift = 2,
		.ch_num_maskbit = 0x1f,
		.en_shift = 0,
		.en_maskbit = 0x1,
		.update_cnt_shift = 16,
		.update_cnt_maskbit = 0x7fff,
		.update_cnt_default = 0x6,
		.domain_shift = 13,
		.domain_maskbit = 0x7,
		.fs_shift = 8,
		.fs_maskbit = 0x1f,
		.output_mux_shift = 7,
		.output_mux_maskbit = 0x1,
	},
};

static int mt8901_afe_memif_is_ul(int id)
{
	if (id >= MT8901_AFE_MEMIF_UL_START && id < MT8901_AFE_MEMIF_END)
		return 1;
	else
		return 0;
}

static const struct mt8901_afe_channel_merge *
	mt8901_afe_found_cm(struct snd_soc_dai *dai)
{
	struct mtk_base_afe *afe = snd_soc_dai_get_drvdata(dai);
	int id = -EINVAL;

	if (mt8901_afe_memif_is_ul(dai->id) == 0)
		return NULL;

	switch (dai->id) {
	case MT8901_AFE_MEMIF_VUL_CM0:
		id = MT8901_AFE_CM0;
		break;
	case MT8901_AFE_MEMIF_VUL_CM1:
		id = MT8901_AFE_CM1;
		break;
	case MT8901_AFE_MEMIF_VUL_CM2:
		id = MT8901_AFE_CM2;
		break;
	default:
		break;
	}

	if (id < 0) {
		dev_dbg(afe->dev, "%s, memif %d cannot find CM!\n",
			__func__, dai->id);
		return NULL;
	}

	return &mt8901_afe_cm[id];
}

static unsigned int mt8901_afe_cm_derive_update_cnt(unsigned int rate,
						    unsigned int channels)
{
	unsigned int cnt;

	if (!rate || !channels)
		return 0;

	/* ((26M/fs) - 10) / ceil(ch/2) - 1 */
	cnt = CLK_RATE_26M / rate;
	if (cnt <= CM_UPDATE_CNT_OFFSET)
		return 0;

	cnt = (cnt - CM_UPDATE_CNT_OFFSET) / ((channels + 1) / 2);
	if (cnt <= 1)
		return 0;

	return cnt - 1;
}

static int mt8901_afe_config_cm(struct mtk_base_afe *afe,
				const struct mt8901_afe_channel_merge *cm,
				unsigned int channels, unsigned int rate,
				unsigned int domain)
{
	unsigned int update_cnt;
	int fs_index;

	if (!cm)
		return -EINVAL;

	fs_index = mt8901_afe_fs_timing(afe->dev, rate);
	if (fs_index < 0)
		return fs_index;

	regmap_update_bits(afe->regmap,
			   cm->reg,
			   cm->sel_maskbit << cm->sel_shift,
			   cm->sel_default << cm->sel_shift);

	regmap_update_bits(afe->regmap,
			   cm->reg,
			   cm->ch_num_maskbit << cm->ch_num_shift,
			   (channels - 1) << cm->ch_num_shift);

	update_cnt = mt8901_afe_cm_derive_update_cnt(rate, channels);
	regmap_update_bits(afe->regmap,
			   cm->reg,
			   cm->update_cnt_maskbit << cm->update_cnt_shift,
			   update_cnt << cm->update_cnt_shift);

	regmap_update_bits(afe->regmap,
			   cm->reg,
			   cm->domain_maskbit << cm->domain_shift,
			   domain << cm->domain_shift);

	regmap_update_bits(afe->regmap,
			   cm->reg,
			   cm->fs_maskbit << cm->fs_shift,
			   (unsigned int)fs_index << cm->fs_shift);

	return 0;
}

static int mt8901_afe_enable_cm(struct mtk_base_afe *afe,
				const struct mt8901_afe_channel_merge *cm,
				bool enable)
{
	if (!cm)
		return -EINVAL;

	regmap_update_bits(afe->regmap,
			   cm->reg,
			   cm->en_maskbit << cm->en_shift,
			   enable << cm->en_shift);

	return 0;
}

struct mt8901_afe_memif_minlen {
	unsigned int len;
	unsigned int reg_value;
};

static const struct mt8901_afe_memif_minlen mt8901_memif_minlen[] = {
	{ .len = 0, .reg_value = 0, },
	{ .len = 16, .reg_value = 1, },
	{ .len = 32, .reg_value = 2, },
	{ .len = 64, .reg_value = 3, },
};

static int mt8901_memif_set_minlen(struct mtk_base_afe *afe,
				   int id, unsigned int len)
{
	int i, value = 0;
	struct mtk_base_afe_memif *memif = &afe->memif[id];
	const struct mtk_base_memif_data *data = memif->data;

	if (data->minlen_reg < 0)
		return 0;

	for (i = 0; i < ARRAY_SIZE(mt8901_memif_minlen); i++)
		if (mt8901_memif_minlen[i].len == len)
			value = mt8901_memif_minlen[i].reg_value;

	regmap_update_bits(afe->regmap, data->minlen_reg,
			   data->minlen_mask << data->minlen_shift,
			   value << data->minlen_shift);
	return 0;
}

struct mt8901_afe_memif_maxlen {
	unsigned int len;
	unsigned int reg_value;
};

static const struct mt8901_afe_memif_maxlen mt8901_memif_maxlen[] = {
	{ .len = 4, .reg_value = 0, },
	{ .len = 16, .reg_value = 1, },
	{ .len = 32, .reg_value = 2, },
	{ .len = 64, .reg_value = 3, },
};

static int mt8901_memif_set_maxlen(struct mtk_base_afe *afe,
				   int id, unsigned int len)
{
	int i, value = 0;
	struct mtk_base_afe_memif *memif = &afe->memif[id];
	const struct mtk_base_memif_data *data = memif->data;

	if (data->maxlen_reg < 0)
		return 0;

	for (i = 0; i < ARRAY_SIZE(mt8901_memif_maxlen); i++)
		if (mt8901_memif_maxlen[i].len == len)
			value = mt8901_memif_maxlen[i].reg_value;

	regmap_update_bits(afe->regmap, data->maxlen_reg,
			   data->maxlen_mask << data->maxlen_shift,
			   value << data->maxlen_shift);

	return 0;
}

static int mt8901_memif_set_domain(struct mtk_base_afe *afe,
				   int id, unsigned int domain)
{
	struct mtk_base_afe_memif *memif = &afe->memif[id];
	const struct mtk_base_memif_data *data = memif->data;

	if (data->domain_reg >= 0)
		regmap_update_bits(afe->regmap, data->domain_reg,
				   data->domain_mask << data->domain_shift,
				   domain << data->domain_shift);

	return 0;
}

static void mt8901_afe_irq_clear(struct mtk_base_afe *afe,
				 const struct mtk_base_irq_data *irq_data)
{
	unsigned int val = 0;

	regmap_read(afe->regmap, irq_data->irq_clr_reg, &val);
	regmap_update_bits(afe->regmap, irq_data->irq_clr_reg,
			   BIT(irq_data->irq_clr_shift),
			   ~val & BIT(irq_data->irq_clr_shift));
}

static void mt8901_afe_irq_enable(struct mtk_base_afe *afe,
				  const struct mtk_base_irq_data *irq_data)
{
	if (irq_data->irq_mask_reg >= 0)
		regmap_set_bits(afe->regmap, irq_data->irq_mask_reg,
				BIT(irq_data->irq_mask_shift));

	if (irq_data->irq_en_reg >= 0)
		regmap_set_bits(afe->regmap, irq_data->irq_en_reg,
				BIT(irq_data->irq_en_shift));
}

static void mt8901_afe_irq_disable(struct mtk_base_afe *afe,
				   const struct mtk_base_irq_data *irq_data)
{
	if (irq_data->irq_en_reg >= 0)
		regmap_clear_bits(afe->regmap, irq_data->irq_en_reg,
				  BIT(irq_data->irq_en_shift));

	/* clear pending IRQ */
	mt8901_afe_irq_clear(afe, irq_data);

	if (irq_data->irq_mask_reg >= 0)
		regmap_clear_bits(afe->regmap, irq_data->irq_mask_reg,
				  BIT(irq_data->irq_mask_shift));
}

static void mt8901_afe_irq_configure(struct mtk_base_afe *afe, int id,
				     int fs, unsigned int domain,
				     unsigned int counter)
{
	struct mtk_base_afe_memif *memif = &afe->memif[id];
	struct mtk_base_afe_irq *irqs = &afe->irqs[memif->irq_usage];
	const struct mtk_base_irq_data *irq_data = irqs->irq_data;
	int msk, shift;

	/* set irq counter */
	msk = irq_data->irq_cnt_maskbit;
	shift = irq_data->irq_cnt_shift;
	regmap_update_bits(afe->regmap, irq_data->irq_cnt_reg,
			   msk << shift, counter << shift);

	if (irq_data->irq_fs_reg >= 0) {
		msk = irq_data->irq_fs_maskbit;
		shift = irq_data->irq_fs_shift;
		regmap_update_bits(afe->regmap, irq_data->irq_fs_reg,
				   msk << shift, fs << shift);
	}

	if (irq_data->irq_domain_reg >= 0) {
		msk = irq_data->irq_domain_maskbit;
		shift = irq_data->irq_domain_shift;
		regmap_update_bits(afe->regmap, irq_data->irq_domain_reg,
				   msk << shift, domain << shift);
	}
}

static unsigned long mt8901_get_prefetch_delay(struct mtk_base_afe *afe,
					       int id, unsigned int minlen,
					       unsigned int rate,
					       unsigned int channel,
					       unsigned int bitwidth)
{
	unsigned long delay_us = 0;
	unsigned long pbuf_delay;

	if (rate == 0 || channel == 0 || bitwidth == 0) {
		dev_warn(afe->dev,
			 "%s(), unexpected parameter rate %u, ch %u, bit %u\n",
			 __func__, rate, channel, bitwidth);
		return 0;
	}

	delay_us = IO_INTF_DELAY_IN_SAMPLES +
		   SERIAL_TO_PARALLEL_DELAY_IN_SAMPLES +
		   CHANNEL_MERGE_DELAY_IN_SAMPLES +
		   INTERCONN_DELAY_IN_SAMPLES;

	pbuf_delay = minlen * BITS_PER_BYTE / (channel * bitwidth);
	delay_us += pbuf_delay;
	delay_us = delay_us * MICROSECONDS_PER_SECOND / rate;

	return delay_us;
}

static int mt8901_afe_fe_startup(struct snd_pcm_substream *substream,
				 struct snd_soc_dai *dai)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	int ret;

	ret = mtk_afe_fe_startup(substream, dai);

	snd_pcm_hw_constraint_step(runtime, 0,
				   SNDRV_PCM_HW_PARAM_BUFFER_BYTES,
				   MT8901_MEMIF_BUFFER_BYTES_ALIGN);

	return ret;
}

static int mt8901_afe_fe_hw_params(struct snd_pcm_substream *substream,
				   struct snd_pcm_hw_params *params,
				   struct snd_soc_dai *dai)
{
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct mtk_base_afe *afe = snd_soc_dai_get_drvdata(dai);
	struct mt8901_afe_private *afe_priv = afe->platform_priv;
	int id = snd_soc_rtd_to_cpu(rtd, 0)->id;
	const struct mt8901_afe_channel_merge *cm = mt8901_afe_found_cm(dai);
	struct mtk_dai_memif_priv *memif_priv = afe_priv->dai_priv[id];
	unsigned int channels = params_channels(params);
	unsigned int rate = params_rate(params);
	unsigned int domain = memif_priv->domain;

	mt8901_afe_config_cm(afe, cm, channels, rate, domain);

	mt8901_memif_set_domain(afe, id, domain);

	mt8901_memif_set_minlen(afe, id, memif_priv->minlen);

	mt8901_memif_set_maxlen(afe, id, memif_priv->maxlen);

	return mtk_afe_fe_hw_params(substream, params, dai);
}

static int mt8901_afe_fe_trigger(struct snd_pcm_substream *substream, int cmd,
				 struct snd_soc_dai *dai)
{
	struct mtk_base_afe *afe = snd_soc_dai_get_drvdata(dai);
	const struct mt8901_afe_channel_merge *cm = mt8901_afe_found_cm(dai);
	struct snd_soc_pcm_runtime *rtd = snd_soc_substream_to_rtd(substream);
	struct snd_pcm_runtime * const runtime = substream->runtime;
	int id = snd_soc_rtd_to_cpu(rtd, 0)->id;
	struct mtk_base_afe_memif *memif = &afe->memif[id];
	struct mtk_base_afe_irq *irqs = &afe->irqs[memif->irq_usage];
	const struct mtk_base_irq_data *irq_data = irqs->irq_data;
	unsigned int counter = runtime->period_size;
	struct mt8901_afe_private *afe_priv = afe->platform_priv;
	struct mtk_dai_memif_priv *memif_priv = afe_priv->dai_priv[id];
	int fs;
	int ret;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_RESUME:
		ret = mtk_memif_set_enable(afe, id);
		if (ret) {
			dev_err(afe->dev,
				"%s(), error, id %d, memif enable, ret %d\n",
				__func__, id, ret);
			return ret;
		}

		mt8901_afe_enable_cm(afe, cm, true);

		/* set irq fs */
		fs = afe->irq_fs(substream, runtime->rate);
		if (fs < 0)
			return -EINVAL;

		mt8901_afe_irq_configure(afe, id, fs, memif_priv->domain,
					 counter);

		/* delay for uplink */
		if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
			unsigned long prefetch_delay =
				mt8901_get_prefetch_delay(afe, id,
							  memif_priv->minlen,
							  runtime->rate,
							  runtime->channels,
							  runtime->sample_bits);

			udelay(prefetch_delay);
		}

		/* enable interrupt */
		mt8901_afe_irq_enable(afe, irq_data);
		return 0;
	case SNDRV_PCM_TRIGGER_STOP:
	case SNDRV_PCM_TRIGGER_SUSPEND:
		mt8901_afe_enable_cm(afe, cm, false);

		ret = mtk_memif_set_disable(afe, id);
		if (ret)
			dev_err(afe->dev, "%s(), error, id %d, memif enable, ret %d\n",
				__func__, id, ret);

		/* disable interrupt */
		mt8901_afe_irq_disable(afe, irq_data);
		return ret;
	default:
		return -EINVAL;
	}
}

static const struct snd_soc_dai_ops mt8901_afe_fe_dai_ops = {
	.startup	= mt8901_afe_fe_startup,
	.shutdown	= mtk_afe_fe_shutdown,
	.hw_params	= mt8901_afe_fe_hw_params,
	.hw_free	= mtk_afe_fe_hw_free,
	.prepare	= mtk_afe_fe_prepare,
	.trigger	= mt8901_afe_fe_trigger,
};

static struct snd_soc_dai_driver mt8901_memif_dai_driver[] = {
	/* FE DAIs: memory intefaces to CPU */
	{
		.name = "DL0",
		.id = MT8901_AFE_MEMIF_DL0,
		.playback = {
			.stream_name = "DL0",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "DL1",
		.id = MT8901_AFE_MEMIF_DL1,
		.playback = {
			.stream_name = "DL1",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "DL2",
		.id = MT8901_AFE_MEMIF_DL2,
		.playback = {
			.stream_name = "DL2",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "DL3",
		.id = MT8901_AFE_MEMIF_DL3,
		.playback = {
			.stream_name = "DL3",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "DL4",
		.id = MT8901_AFE_MEMIF_DL4,
		.playback = {
			.stream_name = "DL4",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "DL5",
		.id = MT8901_AFE_MEMIF_DL5,
		.playback = {
			.stream_name = "DL5",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "DL_24CH",
		.id = MT8901_AFE_MEMIF_DL_24CH_0,
		.playback = {
			.stream_name = "DL_24CH",
			.channels_min = 1,
			.channels_max = MT8901_CM0_MAX_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "UL0",
		.id = MT8901_AFE_MEMIF_UL0,
		.capture = {
			.stream_name = "UL0",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "UL1",
		.id = MT8901_AFE_MEMIF_UL1,
		.capture = {
			.stream_name = "UL1",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "UL2",
		.id = MT8901_AFE_MEMIF_UL2,
		.capture = {
			.stream_name = "UL2",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "UL3",
		.id = MT8901_AFE_MEMIF_UL3,
		.capture = {
			.stream_name = "UL3",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "UL4",
		.id = MT8901_AFE_MEMIF_UL4,
		.capture = {
			.stream_name = "UL4",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "UL5",
		.id = MT8901_AFE_MEMIF_UL5,
		.capture = {
			.stream_name = "UL5",
			.channels_min = 1,
			.channels_max = STEREO_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "VUL_CM0",
		.id = MT8901_AFE_MEMIF_VUL_CM0,
		.capture = {
			.stream_name = "VUL_CM0",
			.channels_min = 1,
			.channels_max = MT8901_CM0_MAX_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "VUL_CM1",
		.id = MT8901_AFE_MEMIF_VUL_CM1,
		.capture = {
			.stream_name = "VUL_CM1",
			.channels_min = 1,
			.channels_max = MT8901_CM1_MAX_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
	{
		.name = "VUL_CM2",
		.id = MT8901_AFE_MEMIF_VUL_CM2,
		.capture = {
			.stream_name = "VUL_CM2",
			.channels_min = 1,
			.channels_max = MT8901_CM2_MAX_CH,
			.rates = MTK_PCM_RATES,
			.formats = MTK_PCM_FORMATS,
		},
		.ops = &mt8901_afe_fe_dai_ops,
	},
};

/*
 * VUL_2CH_0: Mic 2CH
 *   first-fit: PDI8 (I170/I171); contention: PDI12 (I178/I179),
 *              PDI13 (I180/I181)
 */
static const struct snd_kcontrol_new o018_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I170 Switch", AFE_CONN018_5, 10, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I178 Switch", AFE_CONN018_5, 18, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I180 Switch", AFE_CONN018_5, 20, 1, 0),
};

static const struct snd_kcontrol_new o019_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I171 Switch", AFE_CONN019_5, 11, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I179 Switch", AFE_CONN019_5, 19, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I181 Switch", AFE_CONN019_5, 21, 1, 0),
};

/*
 * VUL_2CH_1: HeadsetMic 2CH
 *   first-fit: PDI7 (I168/I169); contention: PDI12~14 (I178~I183)
 */
static const struct snd_kcontrol_new o020_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I168 Switch", AFE_CONN020_5, 8, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I178 Switch", AFE_CONN020_5, 18, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I180 Switch", AFE_CONN020_5, 20, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I182 Switch", AFE_CONN020_5, 22, 1, 0),
};

static const struct snd_kcontrol_new o021_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I169 Switch", AFE_CONN021_5, 9, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I179 Switch", AFE_CONN021_5, 19, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I181 Switch", AFE_CONN021_5, 21, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I183 Switch", AFE_CONN021_5, 23, 1, 0),
};

/* VUL_2CH_4: BRA RX SDW0 — I186/I187 exclusive non-SDCA path */
static const struct snd_kcontrol_new o026_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I186 Switch", AFE_CONN026_5, 26, 1, 0),
};

static const struct snd_kcontrol_new o027_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I187 Switch", AFE_CONN027_5, 27, 1, 0),
};

/* VUL_2CH_5: BRA RX SDW1 — I166/I167 exclusive non-SDCA path */
static const struct snd_kcontrol_new o028_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I166 Switch", AFE_CONN028_5, 6, 1, 0),
};

static const struct snd_kcontrol_new o029_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I167 Switch", AFE_CONN029_5, 7, 1, 0),
};

/*
 * VUL_CM2: Mic >2CH, max 16CH (PDI8~PDI15, I170~I185).
 * O064~O079 each connect to one I port (no contention fallback in CM path).
 */
static const struct snd_kcontrol_new o064_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I170 Switch", AFE_CONN064_5, 10, 1, 0),
};

static const struct snd_kcontrol_new o065_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I171 Switch", AFE_CONN065_5, 11, 1, 0),
};

static const struct snd_kcontrol_new o066_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I172 Switch", AFE_CONN066_5, 12, 1, 0),
};

static const struct snd_kcontrol_new o067_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I173 Switch", AFE_CONN067_5, 13, 1, 0),
};

static const struct snd_kcontrol_new o068_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I174 Switch", AFE_CONN068_5, 14, 1, 0),
};

static const struct snd_kcontrol_new o069_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I175 Switch", AFE_CONN069_5, 15, 1, 0),
};

static const struct snd_kcontrol_new o070_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I176 Switch", AFE_CONN070_5, 16, 1, 0),
};

static const struct snd_kcontrol_new o071_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I177 Switch", AFE_CONN071_5, 17, 1, 0),
};

static const struct snd_kcontrol_new o072_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I178 Switch", AFE_CONN072_5, 18, 1, 0),
};

static const struct snd_kcontrol_new o073_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I179 Switch", AFE_CONN073_5, 19, 1, 0),
};

static const struct snd_kcontrol_new o074_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I180 Switch", AFE_CONN074_5, 20, 1, 0),
};

static const struct snd_kcontrol_new o075_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I181 Switch", AFE_CONN075_5, 21, 1, 0),
};

static const struct snd_kcontrol_new o076_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I182 Switch", AFE_CONN076_5, 22, 1, 0),
};

static const struct snd_kcontrol_new o077_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I183 Switch", AFE_CONN077_5, 23, 1, 0),
};

static const struct snd_kcontrol_new o078_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I184 Switch", AFE_CONN078_5, 24, 1, 0),
};

static const struct snd_kcontrol_new o079_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I185 Switch", AFE_CONN079_5, 25, 1, 0),
};

static const char * const mt8901_afe_domain_sel_text[] = {
	"hopping", "apll",
};

static const unsigned int mt8901_afe_domain_sel_values[] = {
	MT8901_DOMAIN_HOPPING, MT8901_DOMAIN_APLL,
};

static int mt8901_memif_domain_sel_get(struct snd_kcontrol *kcontrol,
				       struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component = snd_kcontrol_chip(kcontrol);
	struct mtk_base_afe *afe = snd_soc_component_get_drvdata(component);
	struct mt8901_afe_private *afe_priv = afe->platform_priv;
	unsigned int dai_id = kcontrol->id.device;
	struct mtk_dai_memif_priv *priv = afe_priv->dai_priv[dai_id];
	int i;

	for (i = 0; i < ARRAY_SIZE(mt8901_afe_domain_sel_values); i++) {
		if (mt8901_afe_domain_sel_values[i] == priv->domain) {
			ucontrol->value.enumerated.item[0] = i;
			return 0;
		}
	}
	return -EINVAL;
}

static int mt8901_memif_domain_sel_put(struct snd_kcontrol *kcontrol,
				       struct snd_ctl_elem_value *ucontrol)
{
	struct snd_soc_component *component = snd_kcontrol_chip(kcontrol);
	struct mtk_base_afe *afe = snd_soc_component_get_drvdata(component);
	struct mt8901_afe_private *afe_priv = afe->platform_priv;
	unsigned int dai_id = kcontrol->id.device;
	struct mtk_dai_memif_priv *priv = afe_priv->dai_priv[dai_id];
	unsigned long idx = ucontrol->value.enumerated.item[0];
	unsigned int reg_val;

	if (idx >= ARRAY_SIZE(mt8901_afe_domain_sel_values))
		return -EINVAL;
	reg_val = mt8901_afe_domain_sel_values[idx];
	if (reg_val == priv->domain)
		return 0;
	priv->domain = reg_val;
	return 1;
}

static SOC_ENUM_SINGLE_EXT_DECL(mt8901_domain_sel_enum,
				mt8901_afe_domain_sel_text);

static const struct snd_kcontrol_new mt8901_memif_controls[] = {
	MT8901_SOC_ENUM_EXT("DL0_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_DL0),
	MT8901_SOC_ENUM_EXT("DL1_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_DL1),
	MT8901_SOC_ENUM_EXT("DL2_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_DL2),
	MT8901_SOC_ENUM_EXT("DL3_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_DL3),
	MT8901_SOC_ENUM_EXT("DL4_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_DL4),
	MT8901_SOC_ENUM_EXT("DL5_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_DL5),
	MT8901_SOC_ENUM_EXT("DL_24CH_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_DL_24CH_0),
	MT8901_SOC_ENUM_EXT("UL0_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_UL0),
	MT8901_SOC_ENUM_EXT("UL1_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_UL1),
	MT8901_SOC_ENUM_EXT("UL2_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_UL2),
	MT8901_SOC_ENUM_EXT("UL3_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_UL3),
	MT8901_SOC_ENUM_EXT("UL4_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_UL4),
	MT8901_SOC_ENUM_EXT("UL5_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_UL5),
	MT8901_SOC_ENUM_EXT("VUL_CM0_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_VUL_CM0),
	MT8901_SOC_ENUM_EXT("VUL_CM1_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_VUL_CM1),
	MT8901_SOC_ENUM_EXT("VUL_CM2_Domain_Sel", mt8901_domain_sel_enum,
			    mt8901_memif_domain_sel_get,
			    mt8901_memif_domain_sel_put,
			    MT8901_AFE_MEMIF_VUL_CM2),
};

static const struct snd_soc_dapm_widget mt8901_memif_widgets[] = {
	/* DL0 */
	SND_SOC_DAPM_MIXER("I032", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I033", SND_SOC_NOPM, 0, 0, NULL, 0),

	/* DL1 */
	SND_SOC_DAPM_MIXER("I034", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I035", SND_SOC_NOPM, 0, 0, NULL, 0),

	/* DL4 */
	SND_SOC_DAPM_MIXER("I040", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I041", SND_SOC_NOPM, 0, 0, NULL, 0),

	/* DL5 */
	SND_SOC_DAPM_MIXER("I042", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I043", SND_SOC_NOPM, 0, 0, NULL, 0),

	/* DL_24CH */
	SND_SOC_DAPM_MIXER("I054", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I055", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I056", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I057", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I058", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I059", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I060", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I061", SND_SOC_NOPM, 0, 0, NULL, 0),

	/* UL0 */
	SND_SOC_DAPM_MIXER("O018", SND_SOC_NOPM, 0, 0,
			   o018_mix, ARRAY_SIZE(o018_mix)),
	SND_SOC_DAPM_MIXER("O019", SND_SOC_NOPM, 0, 0,
			   o019_mix, ARRAY_SIZE(o019_mix)),

	/* UL1 */
	SND_SOC_DAPM_MIXER("O020", SND_SOC_NOPM, 0, 0,
			   o020_mix, ARRAY_SIZE(o020_mix)),
	SND_SOC_DAPM_MIXER("O021", SND_SOC_NOPM, 0, 0,
			   o021_mix, ARRAY_SIZE(o021_mix)),

	/* UL4 */
	SND_SOC_DAPM_MIXER("O026", SND_SOC_NOPM, 0, 0,
			   o026_mix, ARRAY_SIZE(o026_mix)),
	SND_SOC_DAPM_MIXER("O027", SND_SOC_NOPM, 0, 0,
			   o027_mix, ARRAY_SIZE(o027_mix)),

	/* UL5 */
	SND_SOC_DAPM_MIXER("O028", SND_SOC_NOPM, 0, 0,
			   o028_mix, ARRAY_SIZE(o028_mix)),
	SND_SOC_DAPM_MIXER("O029", SND_SOC_NOPM, 0, 0,
			   o029_mix, ARRAY_SIZE(o029_mix)),

	/* VUL_CM2: O64~O79 (SCD0 UL pool PDI8~PDI15, max 16ch) */
	SND_SOC_DAPM_MIXER("O064", SND_SOC_NOPM, 0, 0,
			   o064_mix, ARRAY_SIZE(o064_mix)),
	SND_SOC_DAPM_MIXER("O065", SND_SOC_NOPM, 0, 0,
			   o065_mix, ARRAY_SIZE(o065_mix)),
	SND_SOC_DAPM_MIXER("O066", SND_SOC_NOPM, 0, 0,
			   o066_mix, ARRAY_SIZE(o066_mix)),
	SND_SOC_DAPM_MIXER("O067", SND_SOC_NOPM, 0, 0,
			   o067_mix, ARRAY_SIZE(o067_mix)),
	SND_SOC_DAPM_MIXER("O068", SND_SOC_NOPM, 0, 0,
			   o068_mix, ARRAY_SIZE(o068_mix)),
	SND_SOC_DAPM_MIXER("O069", SND_SOC_NOPM, 0, 0,
			   o069_mix, ARRAY_SIZE(o069_mix)),
	SND_SOC_DAPM_MIXER("O070", SND_SOC_NOPM, 0, 0,
			   o070_mix, ARRAY_SIZE(o070_mix)),
	SND_SOC_DAPM_MIXER("O071", SND_SOC_NOPM, 0, 0,
			   o071_mix, ARRAY_SIZE(o071_mix)),
	SND_SOC_DAPM_MIXER("O072", SND_SOC_NOPM, 0, 0,
			   o072_mix, ARRAY_SIZE(o072_mix)),
	SND_SOC_DAPM_MIXER("O073", SND_SOC_NOPM, 0, 0,
			   o073_mix, ARRAY_SIZE(o073_mix)),
	SND_SOC_DAPM_MIXER("O074", SND_SOC_NOPM, 0, 0,
			   o074_mix, ARRAY_SIZE(o074_mix)),
	SND_SOC_DAPM_MIXER("O075", SND_SOC_NOPM, 0, 0,
			   o075_mix, ARRAY_SIZE(o075_mix)),
	SND_SOC_DAPM_MIXER("O076", SND_SOC_NOPM, 0, 0,
			   o076_mix, ARRAY_SIZE(o076_mix)),
	SND_SOC_DAPM_MIXER("O077", SND_SOC_NOPM, 0, 0,
			   o077_mix, ARRAY_SIZE(o077_mix)),
	SND_SOC_DAPM_MIXER("O078", SND_SOC_NOPM, 0, 0,
			   o078_mix, ARRAY_SIZE(o078_mix)),
	SND_SOC_DAPM_MIXER("O079", SND_SOC_NOPM, 0, 0,
			   o079_mix, ARRAY_SIZE(o079_mix)),
};

static const struct snd_soc_dapm_route mt8901_memif_routes[] = {
	{"I032", NULL, "DL0"},
	{"I033", NULL, "DL0"},

	{"I034", NULL, "DL1"},
	{"I035", NULL, "DL1"},

	{"I040", NULL, "DL4"},
	{"I041", NULL, "DL4"},

	{"I042", NULL, "DL5"},
	{"I043", NULL, "DL5"},

	{"I054", NULL, "DL_24CH"},
	{"I055", NULL, "DL_24CH"},
	{"I056", NULL, "DL_24CH"},
	{"I057", NULL, "DL_24CH"},
	{"I058", NULL, "DL_24CH"},
	{"I059", NULL, "DL_24CH"},
	{"I060", NULL, "DL_24CH"},
	{"I061", NULL, "DL_24CH"},

	{"UL0", NULL, "O018"},
	{"UL0", NULL, "O019"},

	{"UL1", NULL, "O020"},
	{"UL1", NULL, "O021"},

	{"UL4", NULL, "O026"},
	{"UL4", NULL, "O027"},

	{"UL5", NULL, "O028"},
	{"UL5", NULL, "O029"},

	{"VUL_CM2", NULL, "O064"},
	{"VUL_CM2", NULL, "O065"},
	{"VUL_CM2", NULL, "O066"},
	{"VUL_CM2", NULL, "O067"},
	{"VUL_CM2", NULL, "O068"},
	{"VUL_CM2", NULL, "O069"},
	{"VUL_CM2", NULL, "O070"},
	{"VUL_CM2", NULL, "O071"},
	{"VUL_CM2", NULL, "O072"},
	{"VUL_CM2", NULL, "O073"},
	{"VUL_CM2", NULL, "O074"},
	{"VUL_CM2", NULL, "O075"},
	{"VUL_CM2", NULL, "O076"},
	{"VUL_CM2", NULL, "O077"},
	{"VUL_CM2", NULL, "O078"},
	{"VUL_CM2", NULL, "O079"},

	/* UL5: BRA RX SDW1 — I166/I167 exclusive */
	{"O028", "I166 Switch", "I166"},
	{"O029", "I167 Switch", "I167"},

	/* UL1: HeadsetMic 2CH — I168/I169 first-fit (PDI7),
	 * I178~I183 contention (PDI12~14)
	 */
	{"O020", "I168 Switch", "I168"},
	{"O020", "I178 Switch", "I178"},
	{"O020", "I180 Switch", "I180"},
	{"O020", "I182 Switch", "I182"},
	{"O021", "I169 Switch", "I169"},
	{"O021", "I179 Switch", "I179"},
	{"O021", "I181 Switch", "I181"},
	{"O021", "I183 Switch", "I183"},

	/* UL0: Mic 2CH — I170/I171 first-fit (PDI8),
	 * I178~I181 contention (PDI12/13)
	 */
	{"O018", "I170 Switch", "I170"},
	{"O018", "I178 Switch", "I178"},
	{"O018", "I180 Switch", "I180"},
	{"O019", "I171 Switch", "I171"},
	{"O019", "I179 Switch", "I179"},
	{"O019", "I181 Switch", "I181"},

	/* VUL_CM2: Mic >2CH — I170~I185 (PDI8~PDI15, max 16CH) */
	{"O064", "I170 Switch", "I170"},
	{"O065", "I171 Switch", "I171"},
	{"O066", "I172 Switch", "I172"},
	{"O067", "I173 Switch", "I173"},
	{"O068", "I174 Switch", "I174"},
	{"O069", "I175 Switch", "I175"},
	{"O070", "I176 Switch", "I176"},
	{"O071", "I177 Switch", "I177"},
	{"O072", "I178 Switch", "I178"},
	{"O073", "I179 Switch", "I179"},
	{"O074", "I180 Switch", "I180"},
	{"O075", "I181 Switch", "I181"},
	{"O076", "I182 Switch", "I182"},
	{"O077", "I183 Switch", "I183"},
	{"O078", "I184 Switch", "I184"},
	{"O079", "I185 Switch", "I185"},

	/* UL4: BRA RX SDW0 — I186/I187 exclusive */
	{"O026", "I186 Switch", "I186"},
	{"O027", "I187 Switch", "I187"},
};

#define MT8901_MEMIF_DL(n) \
[MT8901_AFE_MEMIF_DL##n] = { \
	.name = "DL" #n, \
	.id = MT8901_AFE_MEMIF_DL##n, \
	.reg_ofs_base = AFE_DL##n##_BASE, \
	.reg_ofs_cur = AFE_DL##n##_CUR, \
	.reg_ofs_end = AFE_DL##n##_END, \
	.reg_ofs_base_msb = AFE_DL##n##_BASE_MSB, \
	.reg_ofs_cur_msb = AFE_DL##n##_CUR_MSB, \
	.reg_ofs_end_msb = AFE_DL##n##_END_MSB, \
	.fs_reg = AFE_DL##n##_CON0, \
	.fs_shift = DL_SEL_FS_SFT, \
	.fs_maskbit = DL_SEL_FS_MASK, \
	.mono_reg = AFE_DL##n##_CON0, \
	.mono_shift = DL_MONO_SFT, \
	.enable_reg = AFE_DL##n##_CON0, \
	.enable_shift = DL_ON_SFT, \
	.hd_reg = AFE_DL##n##_CON0, \
	.hd_shift = DL_HD_MODE_SFT, \
	.hd_align_reg = AFE_DL##n##_CON0, \
	.hd_align_mshift = 2, \
	.pbuf_reg = AFE_DL##n##_CON0, \
	.pbuf_shift = DL_PBUF_SIZE_SFT, \
	.pbuf_mask = GENMASK(1, 0), \
	.minlen_reg = AFE_DL##n##_CON0, \
	.minlen_shift = DL_MINLEN_SFT, \
	.minlen_mask = GENMASK(1, 0), \
	.ch_num_reg = -1, \
	.ch_num_shift = 0, \
	.ch_num_maskbit = 0, \
	.maxlen_reg = AFE_DL##n##_CON0, \
	.maxlen_shift = DL_MAXLEN_SFT, \
	.maxlen_mask = GENMASK(1, 0), \
	.domain_reg = AFE_DL##n##_CON0, \
	.domain_shift = DL_SEL_DOMAIN_SFT, \
	.domain_mask = DL_SEL_DOMAIN_MASK, \
	.one_heart_mode_sel_reg = AFE_DL##n##_CON0, \
	.one_heart_mode_shift = DL_ONE_HEART_SEL_SFT, \
	.one_heart_mode_mask_shift = DL_ONE_HEART_SEL_MASK_SFT, \
}

/* MT8901_MEMIF_UL(n) is the same idea for ULn (n = 0..5). */
#define MT8901_MEMIF_UL(n) \
[MT8901_AFE_MEMIF_UL##n] = { \
	.name = "UL" #n, \
	.id = MT8901_AFE_MEMIF_UL##n, \
	.reg_ofs_base = AFE_VUL##n##_BASE, \
	.reg_ofs_cur = AFE_VUL##n##_CUR, \
	.reg_ofs_end = AFE_VUL##n##_END, \
	.reg_ofs_base_msb = AFE_VUL##n##_BASE_MSB, \
	.reg_ofs_cur_msb = AFE_VUL##n##_CUR_MSB, \
	.reg_ofs_end_msb = AFE_VUL##n##_END_MSB, \
	.fs_reg = AFE_VUL##n##_CON0, \
	.fs_shift = VUL_SEL_FS_SFT, \
	.fs_maskbit = VUL_SEL_FS_MASK, \
	.mono_reg = AFE_VUL##n##_CON0, \
	.mono_shift = VUL_MONO_SFT, \
	.enable_reg = AFE_VUL##n##_CON0, \
	.enable_shift = VUL_ON_SFT, \
	.hd_reg = AFE_VUL##n##_CON0, \
	.hd_shift = VUL_HD_MODE_SFT, \
	.hd_align_reg = AFE_VUL##n##_CON0, \
	.hd_align_mshift = VUL_HALIGN_SFT, \
	.minlen_reg = AFE_VUL##n##_CON0, \
	.minlen_shift = UL_MINLEN_SFT, \
	.minlen_mask = GENMASK(1, 0), \
	.ch_num_reg = -1, \
	.ch_num_shift = 0, \
	.ch_num_maskbit = 0, \
	.maxlen_reg = AFE_VUL##n##_CON0, \
	.maxlen_shift = UL_MAXLEN_SFT, \
	.maxlen_mask = GENMASK(1, 0), \
	.domain_reg = AFE_VUL##n##_CON0, \
	.domain_shift = VUL_SEL_DOMAIN_SFT, \
	.domain_mask = VUL_SEL_DOMAIN_MASK, \
}

#define MT8901_MEMIF_VUL_CM(n) \
[MT8901_AFE_MEMIF_VUL_CM##n] = { \
	.name = "VUL_CM" #n, \
	.id = MT8901_AFE_MEMIF_VUL_CM##n, \
	.reg_ofs_base = AFE_VUL_CM##n##_BASE, \
	.reg_ofs_cur = AFE_VUL_CM##n##_CUR, \
	.reg_ofs_end = AFE_VUL_CM##n##_END, \
	.reg_ofs_base_msb = AFE_VUL_CM##n##_BASE_MSB, \
	.reg_ofs_cur_msb = AFE_VUL_CM##n##_CUR_MSB, \
	.reg_ofs_end_msb = AFE_VUL_CM##n##_END_MSB, \
	.fs_reg = -1, \
	.fs_shift = 0, \
	.fs_maskbit = 0, \
	.mono_reg = -1, \
	.mono_shift = 0, \
	.int_odd_flag_reg = AFE_VUL_CM##n##_CON0, \
	.int_odd_flag_shift = 0, \
	.enable_reg = AFE_VUL_CM##n##_CON0, \
	.enable_shift = 28, \
	.hd_reg = AFE_VUL_CM##n##_CON0, \
	.hd_shift = 4, \
	.hd_align_reg = AFE_VUL_CM##n##_CON0, \
	.hd_align_mshift = 7, \
	.agent_disable_reg = -1, \
	.agent_disable_shift = 0, \
	.ch_num_reg = -1, \
	.ch_num_shift = 0, \
	.ch_num_maskbit = 0, \
	.msb_reg = -1, \
	.msb_shift = 0, \
	.msb_end_reg = -1, \
	.msb_end_shift = 0, \
	.minlen_reg = AFE_VUL_CM##n##_CON0, \
	.minlen_shift = UL_CM_MINLEN_SFT, \
	.minlen_mask = GENMASK(1, 0), \
	.maxlen_reg = AFE_VUL_CM##n##_CON0, \
	.maxlen_shift = UL_CM_MAXLEN_SFT, \
	.maxlen_mask = GENMASK(1, 0), \
}

static const struct mtk_base_memif_data memif_data[MT8901_AFE_MEMIF_NUM] = {
	MT8901_MEMIF_DL(0),
	MT8901_MEMIF_DL(1),
	MT8901_MEMIF_DL(2),
	MT8901_MEMIF_DL(3),
	MT8901_MEMIF_DL(4),
	MT8901_MEMIF_DL(5),
	[MT8901_AFE_MEMIF_DL_24CH_0] = {
		.name = "DL_24CH",
		.id = MT8901_AFE_MEMIF_DL_24CH_0,
		.reg_ofs_base = AFE_DL_24CH_BASE,
		.reg_ofs_cur = AFE_DL_24CH_CUR,
		.reg_ofs_end = AFE_DL_24CH_END,
		.reg_ofs_base_msb = AFE_DL_24CH_BASE_MSB,
		.reg_ofs_cur_msb = AFE_DL_24CH_CUR_MSB,
		.reg_ofs_end_msb = AFE_DL_24CH_END_MSB,
		.fs_reg = AFE_DL_24CH_CON0,
		.fs_shift = DL_SEL_FS_SFT,
		.fs_maskbit = DL_SEL_FS_MASK,
		.mono_reg = -1,
		.mono_shift = 0,
		.enable_reg = AFE_DL_24CH_CON0,
		.enable_shift = 31,
		.hd_reg = AFE_DL_24CH_CON0,
		.hd_shift = DL_HD_MODE_SFT,
		.hd_align_reg = AFE_DL_24CH_CON0,
		.hd_align_mshift = 2,
		.ch_num_reg = AFE_DL_24CH_CON0,
		.ch_num_shift = 24,
		.ch_num_maskbit = GENMASK(5, 0),
		.pbuf_reg = AFE_DL_24CH_CON0,
		.pbuf_shift = DL_PBUF_SIZE_SFT,
		.pbuf_mask = GENMASK(1, 0),
		.minlen_reg = AFE_DL_24CH_CON0,
		.minlen_shift = DL_MINLEN_SFT,
		.minlen_mask = GENMASK(1, 0),
		.maxlen_reg = AFE_DL_24CH_CON0,
		.maxlen_shift = DL_MAXLEN_SFT,
		.maxlen_mask = GENMASK(1, 0),
		.domain_reg = AFE_DL_24CH_CON0,
		.domain_shift = DL_SEL_DOMAIN_SFT,
		.domain_mask = DL_SEL_DOMAIN_MASK,
		.one_heart_mode_sel_reg = AFE_DL_24CH_CON0,
		.one_heart_mode_shift = DL_ONE_HEART_SEL_SFT,
		.one_heart_mode_mask_shift = DL_ONE_HEART_SEL_MASK_SFT,
	},
	MT8901_MEMIF_UL(0),
	MT8901_MEMIF_UL(1),
	MT8901_MEMIF_UL(2),
	MT8901_MEMIF_UL(3),
	MT8901_MEMIF_UL(4),
	MT8901_MEMIF_UL(5),

	MT8901_MEMIF_VUL_CM(0),
	MT8901_MEMIF_VUL_CM(1),
	MT8901_MEMIF_VUL_CM(2),
};

#define MT8901_AFE_IRQ(n) \
[MT8901_AFE_IRQ_##n] = { \
	.id = MT8901_AFE_IRQ_##n, \
	.irq_cnt_reg = AFE_IRQ##n##_MCU_CFG1, \
	.irq_cnt_shift = 0, \
	.irq_cnt_maskbit = GENMASK(23, 0), \
	.irq_fs_reg = AFE_IRQ##n##_MCU_CFG0, \
	.irq_fs_shift = 4, \
	.irq_fs_maskbit = GENMASK(4, 0), \
	.irq_en_reg = AFE_IRQ##n##_MCU_CFG0, \
	.irq_en_shift = 0, \
	.irq_clr_reg = AFE_IRQ##n##_MCU_CFG1, \
	.irq_clr_shift = 31, \
	.irq_status_shift = n, \
	.irq_domain_reg = AFE_IRQ##n##_MCU_CFG0, \
	.irq_domain_shift = 9, \
	.irq_domain_maskbit = 0x7, \
	.irq_mask_reg = AFE_IRQ_MCU_EN, \
	.irq_mask_shift = n, \
}

static const struct mtk_base_irq_data irq_data[MT8901_AFE_IRQ_NUM] = {
	MT8901_AFE_IRQ(0),
	MT8901_AFE_IRQ(1),
	MT8901_AFE_IRQ(2),
	MT8901_AFE_IRQ(3),
	MT8901_AFE_IRQ(4),
	MT8901_AFE_IRQ(5),
	MT8901_AFE_IRQ(6),
	MT8901_AFE_IRQ(7),
	MT8901_AFE_IRQ(8),
	MT8901_AFE_IRQ(9),
	MT8901_AFE_IRQ(10),
	MT8901_AFE_IRQ(11),
	MT8901_AFE_IRQ(12),
	MT8901_AFE_IRQ(13),
	MT8901_AFE_IRQ(14),
	MT8901_AFE_IRQ(15),
	MT8901_AFE_IRQ(16),
	MT8901_AFE_IRQ(17),
	MT8901_AFE_IRQ(18),
	MT8901_AFE_IRQ(19),
	MT8901_AFE_IRQ(20),
	MT8901_AFE_IRQ(21),
};

static const int mt8901_afe_memif_const_irqs[MT8901_AFE_MEMIF_NUM] = {
	[MT8901_AFE_MEMIF_DL0] = MT8901_AFE_IRQ_0,
	[MT8901_AFE_MEMIF_DL1] = MT8901_AFE_IRQ_1,
	[MT8901_AFE_MEMIF_DL2] = MT8901_AFE_IRQ_2,
	[MT8901_AFE_MEMIF_DL3] = MT8901_AFE_IRQ_3,
	[MT8901_AFE_MEMIF_DL4] = MT8901_AFE_IRQ_4,
	[MT8901_AFE_MEMIF_DL5] = MT8901_AFE_IRQ_5,
	[MT8901_AFE_MEMIF_DL_24CH_0] = MT8901_AFE_IRQ_6,
	[MT8901_AFE_MEMIF_UL0] = MT8901_AFE_IRQ_7,
	[MT8901_AFE_MEMIF_UL1] = MT8901_AFE_IRQ_8,
	[MT8901_AFE_MEMIF_UL2] = MT8901_AFE_IRQ_9,
	[MT8901_AFE_MEMIF_UL3] = MT8901_AFE_IRQ_10,
	[MT8901_AFE_MEMIF_UL4] = MT8901_AFE_IRQ_11,
	[MT8901_AFE_MEMIF_UL5] = MT8901_AFE_IRQ_12,
	[MT8901_AFE_MEMIF_VUL_CM0] = MT8901_AFE_IRQ_13,
	[MT8901_AFE_MEMIF_VUL_CM1] = MT8901_AFE_IRQ_14,
	[MT8901_AFE_MEMIF_VUL_CM2] = MT8901_AFE_IRQ_15,
};

static bool mt8901_is_volatile_reg(struct device *dev, unsigned int reg)
{
	/* registers with read-only bits cannot be cached */
	switch (reg) {
	/* AUDIO_TOP: contains RO status bits */
	case AUDIO_TOP_CON0:
	case AUDIO_TOP_CON1:
	case AUDIO_TOP_CON3:
	case AUDIO_TOP_CON4:
	case AUDIO_TOP_CON5:
	/* CM monitor */
	case AFE_CM0_MON:
	case AFE_CM1_MON:
	case AFE_CM2_MON:
	/* DL current pointer and monitor registers */
	case AFE_DL0_CUR_MSB:
	case AFE_DL0_CUR:
	case AFE_DL0_RCH_MON:
	case AFE_DL0_LCH_MON:
	case AFE_DL0_MON0:
	case AFE_DL1_CUR_MSB:
	case AFE_DL1_CUR:
	case AFE_DL1_RCH_MON:
	case AFE_DL1_LCH_MON:
	case AFE_DL1_MON0:
	case AFE_DL2_CUR_MSB:
	case AFE_DL2_CUR:
	case AFE_DL2_RCH_MON:
	case AFE_DL2_LCH_MON:
	case AFE_DL2_MON0:
	case AFE_DL3_CUR_MSB:
	case AFE_DL3_CUR:
	case AFE_DL3_RCH_MON:
	case AFE_DL3_LCH_MON:
	case AFE_DL3_MON0:
	case AFE_DL4_CUR_MSB:
	case AFE_DL4_CUR:
	case AFE_DL4_RCH_MON:
	case AFE_DL4_LCH_MON:
	case AFE_DL4_MON0:
	case AFE_DL5_CUR_MSB:
	case AFE_DL5_CUR:
	case AFE_DL5_RCH_MON:
	case AFE_DL5_LCH_MON:
	case AFE_DL5_MON0:
	case AFE_DL_24CH_CUR_MSB:
	case AFE_DL_24CH_CUR:
	case AFE_DL_24CH_MON0:
	/* VUL current pointer and monitor registers */
	case AFE_VUL0_CUR_MSB:
	case AFE_VUL0_CUR:
	case AFE_VUL0_RCH_MON:
	case AFE_VUL0_LCH_MON:
	case AFE_VUL0_MON0:
	case AFE_VUL1_CUR_MSB:
	case AFE_VUL1_CUR:
	case AFE_VUL1_RCH_MON:
	case AFE_VUL1_LCH_MON:
	case AFE_VUL1_MON0:
	case AFE_VUL2_CUR_MSB:
	case AFE_VUL2_CUR:
	case AFE_VUL2_RCH_MON:
	case AFE_VUL2_LCH_MON:
	case AFE_VUL2_MON0:
	case AFE_VUL3_CUR_MSB:
	case AFE_VUL3_CUR:
	case AFE_VUL3_RCH_MON:
	case AFE_VUL3_LCH_MON:
	case AFE_VUL3_MON0:
	case AFE_VUL4_CUR_MSB:
	case AFE_VUL4_CUR:
	case AFE_VUL4_RCH_MON:
	case AFE_VUL4_LCH_MON:
	case AFE_VUL4_MON0:
	case AFE_VUL5_CUR_MSB:
	case AFE_VUL5_CUR:
	case AFE_VUL5_RCH_MON:
	case AFE_VUL5_LCH_MON:
	case AFE_VUL5_MON0:
	case AFE_VUL8_CUR_MSB:
	case AFE_VUL8_CUR:
	case AFE_VUL8_RCH_MON:
	case AFE_VUL8_LCH_MON:
	case AFE_VUL8_MON0:
	case AFE_VUL9_CUR_MSB:
	case AFE_VUL9_CUR:
	case AFE_VUL9_RCH_MON:
	case AFE_VUL9_LCH_MON:
	case AFE_VUL9_MON0:
	case AFE_VUL10_CUR_MSB:
	case AFE_VUL10_CUR:
	case AFE_VUL10_RCH_MON:
	case AFE_VUL10_LCH_MON:
	case AFE_VUL10_MON0:
	/* VUL_CM current pointer (MON0 not defined in reg.h) */
	case AFE_VUL_CM0_CUR_MSB:
	case AFE_VUL_CM0_CUR:
	case AFE_VUL_CM1_CUR_MSB:
	case AFE_VUL_CM1_CUR:
	case AFE_VUL_CM2_CUR_MSB:
	case AFE_VUL_CM2_CUR:
	/* IRQ status and monitor registers */
	case AFE_IRQ_MCU_STATUS:
	case AFE_CUSTOM_IRQ_MCU_STATUS:
	case AFE_IRQ0_CNT_MON:
	case AFE_IRQ1_CNT_MON:
	case AFE_IRQ2_CNT_MON:
	case AFE_IRQ3_CNT_MON:
	case AFE_IRQ4_CNT_MON:
	case AFE_IRQ5_CNT_MON:
	case AFE_IRQ6_CNT_MON:
	case AFE_IRQ7_CNT_MON:
	case AFE_IRQ8_CNT_MON:
	case AFE_IRQ9_CNT_MON:
	case AFE_IRQ10_CNT_MON:
	case AFE_IRQ11_CNT_MON:
	case AFE_IRQ12_CNT_MON:
	case AFE_IRQ13_CNT_MON:
	case AFE_IRQ14_CNT_MON:
	case AFE_IRQ15_CNT_MON:
	case AFE_IRQ16_CNT_MON:
	case AFE_IRQ17_CNT_MON:
	case AFE_IRQ18_CNT_MON:
	case AFE_IRQ19_CNT_MON:
	case AFE_IRQ20_CNT_MON:
	case AFE_IRQ21_CNT_MON:
	case AFE_IRQ22_CNT_MON:
	case AFE_IRQ23_CNT_MON:
	case AFE_IRQ24_CNT_MON:
	case AFE_IRQ25_CNT_MON:
	case AFE_IRQ26_CNT_MON:
	case AFE_IRQ_MCU_MON3:
	case AFE_IRQ_MCU_MON0:
	case AFE_IRQ_MCU_MON1:
	case AFE_IRQ_MCU_MON2:
	/* GASRC ratio/status monitor registers */
	case AFE_GASRC0_NEW_CON8:
	case AFE_GASRC0_NEW_CON9:
	case AFE_GASRC0_NEW_CON12:
	case AFE_GASRC0_NEW_IP_VERSION:
	case AFE_GASRC1_NEW_CON8:
	case AFE_GASRC1_NEW_CON9:
	case AFE_GASRC1_NEW_CON12:
	case AFE_GASRC1_NEW_IP_VERSION:
	case AFE_GASRC2_NEW_CON8:
	case AFE_GASRC2_NEW_CON9:
	case AFE_GASRC2_NEW_CON12:
	case AFE_GASRC2_NEW_IP_VERSION:
	case AFE_GASRC3_NEW_CON8:
	case AFE_GASRC3_NEW_CON9:
	case AFE_GASRC3_NEW_CON12:
	case AFE_GASRC3_NEW_IP_VERSION:
	case AFE_GASRC4_NEW_CON8:
	case AFE_GASRC4_NEW_CON9:
	case AFE_GASRC4_NEW_CON12:
	case AFE_GASRC4_NEW_IP_VERSION:
	case AFE_GASRC5_NEW_CON8:
	case AFE_GASRC5_NEW_CON9:
	case AFE_GASRC5_NEW_CON12:
	case AFE_GASRC5_NEW_IP_VERSION:
	case AFE_GASRC6_NEW_CON8:
	case AFE_GASRC6_NEW_CON9:
	case AFE_GASRC6_NEW_CON12:
	case AFE_GASRC6_NEW_IP_VERSION:
	case AFE_GASRC7_NEW_CON8:
	case AFE_GASRC7_NEW_CON9:
	case AFE_GASRC7_NEW_CON12:
	case AFE_GASRC7_NEW_IP_VERSION:
	case AFE_GASRC8_NEW_CON8:
	case AFE_GASRC8_NEW_CON9:
	case AFE_GASRC8_NEW_CON12:
	case AFE_GASRC8_NEW_IP_VERSION:
	case AFE_GASRC9_NEW_CON8:
	case AFE_GASRC9_NEW_CON9:
	case AFE_GASRC9_NEW_CON12:
	case AFE_GASRC9_NEW_IP_VERSION:
	case AFE_GASRC10_NEW_CON8:
	case AFE_GASRC10_NEW_CON9:
	case AFE_GASRC10_NEW_CON12:
	case AFE_GASRC10_NEW_IP_VERSION:
	case AFE_GASRC11_NEW_CON8:
	case AFE_GASRC11_NEW_CON9:
	case AFE_GASRC11_NEW_CON12:
	case AFE_GASRC11_NEW_IP_VERSION:
		return true;
	default:
		return false;
	};
}

static const struct regmap_config mt8901_afe_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,
	.volatile_reg = mt8901_is_volatile_reg,
	.max_register = AFE_MAX_REGISTER,
	.num_reg_defaults_raw = ((AFE_MAX_REGISTER / 4) + 1),
	.cache_type = REGCACHE_FLAT,
};

static irqreturn_t mt8901_afe_irq_handler(int irq_id, void *dev_id)
{
	struct mtk_base_afe *afe = dev_id;
	unsigned int val = 0;
	unsigned int mcu_irq_en = 0;
	int i = 0;
	int ret = 0;

	ret = regmap_read(afe->regmap, AFE_IRQ_MCU_STATUS, &val);
	if (ret) {
		dev_err(afe->dev, "%s irq status err\n", __func__);
		goto err_irq;
	}

	ret = regmap_read(afe->regmap, AFE_IRQ_MCU_EN, &mcu_irq_en);
	if (ret) {
		dev_err(afe->dev, "%s read irq en err\n", __func__);
		goto err_irq;
	}

	/* only handle MCU-enabled IRQs */
	val &= mcu_irq_en;

	for (i = 0; i < MT8901_AFE_MEMIF_NUM; i++) {
		struct mtk_base_afe_memif *memif = &afe->memif[i];
		struct mtk_base_irq_data const *irq_data;

		if (memif->irq_usage < 0)
			continue;

		irq_data = afe->irqs[memif->irq_usage].irq_data;

		if (!(val & BIT(irq_data->irq_status_shift)))
			continue;

		/* clear IRQ by writing bit 31 of each IRQ's CFG1 register */
		mt8901_afe_irq_clear(afe, irq_data);

		snd_pcm_period_elapsed(memif->substream);
	}

	return IRQ_HANDLED;

err_irq:
	/* clear all enabled IRQs on error */
	for (i = 0; i < MT8901_AFE_IRQ_NUM; i++)
		mt8901_afe_irq_clear(afe, &irq_data[i]);

	return IRQ_HANDLED;
}

static int init_memif_priv_data(struct mtk_base_afe *afe)
{
	struct mt8901_afe_private *afe_priv = afe->platform_priv;
	struct mtk_dai_memif_priv *memif_priv;
	int i;

	for (i = MT8901_AFE_MEMIF_START; i < MT8901_AFE_MEMIF_END; i++) {
		memif_priv = devm_kzalloc(afe->dev,
					  sizeof(struct mtk_dai_memif_priv),
					  GFP_KERNEL);
		if (!memif_priv)
			return -ENOMEM;

		memif_priv->domain = MT8901_DOMAIN_APLL;
		/* burst mode: minlen = 64-byte, maxlen = 64-byte burst */
		memif_priv->minlen = MT8901_MEMIF_MINLEN;
		memif_priv->maxlen = MT8901_MEMIF_MAXLEN;
		afe_priv->dai_priv[i] = memif_priv;
	}

	return 0;
}

static int mt8901_dai_memif_register(struct mtk_base_afe *afe)
{
	struct mtk_base_afe_dai *dai;

	dai = devm_kzalloc(afe->dev, sizeof(*dai), GFP_KERNEL);
	if (!dai)
		return -ENOMEM;

	list_add(&dai->list, &afe->sub_dais);

	dai->dai_drivers = mt8901_memif_dai_driver;
	dai->num_dai_drivers = ARRAY_SIZE(mt8901_memif_dai_driver);

	dai->dapm_widgets = mt8901_memif_widgets;
	dai->num_dapm_widgets = ARRAY_SIZE(mt8901_memif_widgets);
	dai->dapm_routes = mt8901_memif_routes;
	dai->num_dapm_routes = ARRAY_SIZE(mt8901_memif_routes);
	dai->controls = mt8901_memif_controls;
	dai->num_controls = ARRAY_SIZE(mt8901_memif_controls);
	return init_memif_priv_data(afe);
}

typedef int (*dai_register_cb)(struct mtk_base_afe *);
static const dai_register_cb dai_register_cbs[] = {
	mt8901_dai_soundwire_register,
	mt8901_dai_memif_register,
};

static int mt8901_afe_init_regs(struct mtk_base_afe *afe)
{
	static const struct reg_sequence init_regs[] = {
		{ AFE_IRQ_MCU_EN,      0xffffffff },
		{ AFE_APLL1_TUNER_CFG, 0x332 },
		{ AFE_APLL2_TUNER_CFG, 0x374 },
		{ AFE_MEMIF_CON0,      0x9 },
	};

	return regmap_multi_reg_write(afe->regmap,
				      init_regs, ARRAY_SIZE(init_regs));
}

static int mt8901_afe_pcm_dev_probe(struct platform_device *pdev)
{
	struct mtk_base_afe *afe;
	struct mt8901_afe_private *afe_priv;
	struct device *dev = &pdev->dev;
	int i, irq_id, ret;

	ret = dma_set_mask_and_coherent(dev,
					DMA_BIT_MASK(MT8901_DMA_ADDR_BITS));
	if (ret)
		return ret;

	afe = devm_kzalloc(dev, sizeof(*afe), GFP_KERNEL);
	if (!afe)
		return -ENOMEM;

	afe->platform_priv = devm_kzalloc(dev, sizeof(*afe_priv),
					  GFP_KERNEL);
	if (!afe->platform_priv)
		return -ENOMEM;

	afe_priv = afe->platform_priv;
	afe->dev = &pdev->dev;

	afe->base_addr = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(afe->base_addr))
		return dev_err_probe(dev, PTR_ERR(afe->base_addr),
				     "AFE base_addr not found\n");

	mutex_init(&afe->irq_alloc_lock);

	/* irq initialize */
	afe->irqs_size = MT8901_AFE_IRQ_NUM;
	afe->irqs = devm_kcalloc(dev, afe->irqs_size, sizeof(*afe->irqs),
				 GFP_KERNEL);
	if (!afe->irqs)
		return -ENOMEM;

	for (i = 0; i < afe->irqs_size; i++)
		afe->irqs[i].irq_data = &irq_data[i];

	/* init memif */
	afe->memif_size = MT8901_AFE_MEMIF_NUM;
	afe->memif = devm_kcalloc(dev, afe->memif_size, sizeof(*afe->memif),
				  GFP_KERNEL);
	if (!afe->memif)
		return -ENOMEM;

	for (i = 0; i < afe->memif_size; i++) {
		afe->memif[i].data = &memif_data[i];
		afe->memif[i].irq_usage = mt8901_afe_memif_const_irqs[i];
		afe->memif[i].const_irq = 1;
		afe->irqs[afe->memif[i].irq_usage].irq_occupyed = true;
	}

	irq_id = platform_get_irq(pdev, 0);
	if (irq_id < 0)
		return dev_err_probe(dev, irq_id, "no irq found");

	/* init sub_dais */
	INIT_LIST_HEAD(&afe->sub_dais);

	for (i = 0; i < ARRAY_SIZE(dai_register_cbs); i++) {
		ret = dai_register_cbs[i](afe);
		if (ret)
			return dev_err_probe(dev, ret,
					     "dai register i %d fail\n", i);
	}

	/* init dai_driver and component_driver */
	ret = mtk_afe_combine_sub_dai(afe);
	if (ret)
		return dev_err_probe(dev, ret,
				     "mtk_afe_combine_sub_dai fail\n");

	afe->mtk_afe_hardware = &mt8901_afe_hardware;
	afe->memif_fs = mt8901_memif_fs;
	afe->irq_fs = mt8901_irq_fs;
	afe->memif_32bit_supported = 1;

	platform_set_drvdata(pdev, afe);

	device_property_read_u32(dev, "acpi-asd-hw-ver", &afe_priv->hw_ver);

	dev_info(dev, "acpi-asd-hw-ver = %u\n", afe_priv->hw_ver);

	afe->regmap = devm_regmap_init_mmio(&pdev->dev, afe->base_addr,
					    &mt8901_afe_regmap_config);
	if (IS_ERR(afe->regmap)) {
		ret = PTR_ERR(afe->regmap);
		return ret;
	}

	ret = mt8901_afe_init_clock(afe);
	if (ret) {
		dev_err(dev, "afe init clock failed: %d\n", ret);
		return ret;
	}

	/* ToDo: check if we need to enable clock here */
	ret = mt8901_afe_enable_main_clock(afe);
	if (ret) {
		dev_err(dev, "mt8901_afe_enable_main_clock failed: %d\n", ret);
		return ret;
	}

	ret = mt8901_afe_enable_apll_top_con_cg(afe);
	if (ret) {
		dev_err(dev, "mt8901_afe_enable_apll_top_con_cg failed: %d\n",
			ret);
		mt8901_afe_disable_main_clock(afe);
		return ret;
	}

	ret = mt8901_afe_init_regs(afe);
	if (ret) {
		dev_err(dev, "afe init regs failed: %d\n", ret);
		mt8901_afe_disable_apll_top_con_cg(afe);
		mt8901_afe_disable_main_clock(afe);
		return ret;
	}

	/*
	 * Request the IRQ only once the regmap exists and the IRQ enable
	 * state has been initialized: the handler dereferences afe->regmap
	 * unconditionally and firmware (UEFI POST audio) may leave interrupt
	 * state asserted, so an earlier request can fire into a half-set-up
	 * driver.
	 */
	ret = devm_request_threaded_irq(dev, irq_id, NULL,
					mt8901_afe_irq_handler,
					IRQF_ONESHOT,
					"AFE_ISR_Handle", (void *)afe);
	if (ret) {
		mt8901_afe_disable_apll_top_con_cg(afe);
		mt8901_afe_disable_main_clock(afe);
		return dev_err_probe(dev, ret,
				     "could not request_irq for AFE_ISR_Handle\n");
	}

	/* register component after regcache is in cache-only mode */
	ret = devm_snd_soc_register_component(dev, &mtk_afe_pcm_platform,
					      afe->dai_drivers,
					      afe->num_dai_drivers);
	if (ret) {
		mt8901_afe_disable_apll_top_con_cg(afe);
		mt8901_afe_disable_main_clock(afe);
		return dev_err_probe(dev, ret, "err_platform\n");
	}

	return 0;
}

/* ACPI match: ASD0 device in Audio.asl (_HID = "NVDA9022") */
static const struct acpi_device_id mt8901_afe_acpi_match[] = {
	{ "NVDA9022", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, mt8901_afe_acpi_match);

static struct platform_driver mt8901_afe_pcm_driver = {
	.driver = {
		   .name = "mt8901-audio",
		   .acpi_match_table = ACPI_PTR(mt8901_afe_acpi_match),
	},
	.probe = mt8901_afe_pcm_dev_probe,
};

module_platform_driver(mt8901_afe_pcm_driver);

MODULE_DESCRIPTION("MediaTek SoC AFE platform driver for ALSA 8901");
MODULE_AUTHOR("Weiyi Hsieh <weiyi.hsieh@mediatek.com>");
MODULE_AUTHOR("Trevor Wu <trevor.wu@mediatek.com>");
MODULE_LICENSE("GPL");
