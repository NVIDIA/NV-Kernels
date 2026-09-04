// SPDX-License-Identifier: GPL-2.0
/*
 * ALSA SoC machine driver for ACPI legacy path
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 *         Weiyi Hsieh <weiyi.hsieh@mediatek.com>
 */

#include <linux/device.h>
#include <linux/module.h>
#include <sound/soc.h>
#include <sound/soc-acpi.h>
#include <sound/soc_sdw_utils.h>

static unsigned long soc_sdw_quirk;
static int quirk_override = -1;
module_param_named(quirk, quirk_override, int, 0444);
MODULE_PARM_DESC(quirk, "Board-specific quirk override");

#define MT8901_SDW_MAX_LINKS 2
#define PCM_STREAM_NUM (SNDRV_PCM_STREAM_LAST + 1)

static struct snd_soc_dai_link_component afe_platform_component[] = {
	{ .name = "NVDA9022:00" }
};

struct mtk_mc_ctx {
	unsigned int sdw_pin_index[MT8901_SDW_MAX_LINKS][PCM_STREAM_NUM];
};

static void log_quirks(struct device *dev)
{
	if (SOC_SDW_JACK_JDSRC(soc_sdw_quirk))
		dev_dbg(dev, "quirk realtek,jack-detect-source %ld\n",
			SOC_SDW_JACK_JDSRC(soc_sdw_quirk));
	if (soc_sdw_quirk & SOC_SDW_CODEC_SPKR)
		dev_dbg(dev, "quirk SOC_SDW_CODEC_SPKR enabled\n");
	if (soc_sdw_quirk & SOC_SDW_CODEC_MIC)
		dev_dbg(dev, "quirk SOC_SDW_CODEC_MIC enabled\n");
}

static const struct snd_soc_dapm_route mt8901_card_routes[] = {
	/* TX: AFE O-ports -> SDW PDIs (playback) */
	{"PDI0",  NULL, "O148"}, {"PDI0",  NULL, "O149"},
	{"PDI2",  NULL, "O150"}, {"PDI2",  NULL, "O151"},
	{"PDI3",  NULL, "O152"}, {"PDI3",  NULL, "O153"},
	{"PDI4",  NULL, "O154"}, {"PDI4",  NULL, "O155"},
	{"PDI5",  NULL, "O156"}, {"PDI5",  NULL, "O157"},
	{"PDI6",  NULL, "O158"}, {"PDI6",  NULL, "O159"},
	{"PDI16", NULL, "O160"}, {"PDI16", NULL, "O161"},

	/* RX: SDW PDIs -> AFE I-ports (capture) */
	{"I166", NULL, "PDI1"},  {"I167", NULL, "PDI1"},
	{"I168", NULL, "PDI7"},  {"I169", NULL, "PDI7"},
	{"I170", NULL, "PDI8"},  {"I171", NULL, "PDI8"},
	{"I172", NULL, "PDI9"},  {"I173", NULL, "PDI9"},
	{"I174", NULL, "PDI10"}, {"I175", NULL, "PDI10"},
	{"I176", NULL, "PDI11"}, {"I177", NULL, "PDI11"},
	{"I178", NULL, "PDI12"}, {"I179", NULL, "PDI12"},
	{"I180", NULL, "PDI13"}, {"I181", NULL, "PDI13"},
	{"I182", NULL, "PDI14"}, {"I183", NULL, "PDI14"},
	{"I184", NULL, "PDI15"}, {"I185", NULL, "PDI15"},
	{"I186", NULL, "PDI17"}, {"I187", NULL, "PDI17"},
};

static const struct snd_soc_ops sdw_ops = {
	.startup = asoc_sdw_startup,
	.prepare = asoc_sdw_prepare,
	.trigger = asoc_sdw_trigger,
	.hw_params = asoc_sdw_hw_params,
	.hw_free = asoc_sdw_hw_free,
	.shutdown = asoc_sdw_shutdown,
};

static const char * const type_strings[] = {
	"SimpleJack", "SmartAmp", "SmartMic"};

struct mtk_fe_dai {
	const char *dai_name;	/* AFE CPU DAI name, see mt8901-afe-pcm.c */
	int playback;		/* 1 = playback FE, 0 = capture FE */
};

static const struct mtk_fe_dai mt8901_fe_dais[] = {
	{ "DL0",     1 },
	{ "DL1",     1 },
	{ "DL2",     1 },
	{ "DL3",     1 },
	{ "DL4",     1 },
	{ "DL5",     1 },
	{ "DL_24CH", 1 },
	{ "UL0",     0 },
	{ "UL1",     0 },
	{ "UL2",     0 },
	{ "UL3",     0 },
	{ "UL4",     0 },
	{ "UL5",     0 },
	{ "VUL_CM0", 0 },
	{ "VUL_CM1", 0 },
	{ "VUL_CM2", 0 },
};

static int create_FE_dailinks(struct snd_soc_card *card,
			      struct snd_soc_dai_link **dai_links)
{
	struct device *dev = card->dev;
	int i;

	for (i = 0; i < ARRAY_SIZE(mt8901_fe_dais); i++) {
		const struct mtk_fe_dai *fe = &mt8901_fe_dais[i];
		struct snd_soc_dai_link_component *cpus;
		struct snd_soc_dai_link *link = *dai_links;

		cpus = devm_kzalloc(dev, sizeof(*cpus), GFP_KERNEL);
		if (!cpus)
			return -ENOMEM;

		/* CPU = AFE memif DAI; platform = AFE; codec = shared dummy. */
		cpus->dai_name = fe->dai_name;

		link->name = devm_kasprintf(dev, GFP_KERNEL, "%s_FE",
					    fe->dai_name);
		if (!link->name)
			return -ENOMEM;
		link->stream_name =
			devm_kasprintf(dev, GFP_KERNEL, "%s %s",
				       fe->dai_name,
				       fe->playback ? "Playback" : "Capture");
		if (!link->stream_name)
			return -ENOMEM;

		link->cpus          = cpus;
		link->num_cpus      = 1;
		link->codecs        = &snd_soc_dummy_dlc;
		link->num_codecs    = 1;
		link->platforms     = afe_platform_component;
		link->num_platforms = 1;

		link->dynamic   = 1; /* DPCM front end */
		link->nonatomic = 1; /* same as BE */
		link->trigger[0] = SND_SOC_DPCM_TRIGGER_POST;
		link->trigger[1] = SND_SOC_DPCM_TRIGGER_POST;
		if (fe->playback)
			link->playback_only = 1;
		else
			link->capture_only = 1;

		(*dai_links)++;
	}

	return 0;
}

static int create_sdw_dailink(struct snd_soc_card *card,
			      struct asoc_sdw_dailink *soc_dai,
			      struct snd_soc_dai_link **dai_links,
			      int *be_id,
			      struct snd_soc_codec_conf **codec_conf)
{
	struct device *dev = card->dev;
	struct asoc_sdw_mc_private *ctx = snd_soc_card_get_drvdata(card);
	struct mtk_mc_ctx *mtk_ctx = (struct mtk_mc_ctx *)ctx->private;
	struct asoc_sdw_endpoint *soc_end;
	int stream;
	int ret;

	list_for_each_entry(soc_end, &soc_dai->endpoints, list) {
		if (soc_end->name_prefix) {
			(*codec_conf)->dlc.name = soc_end->codec_name;
			(*codec_conf)->name_prefix = soc_end->name_prefix;
			(*codec_conf)++;
		}

		if (soc_end->include_sidecar &&
		    soc_end->codec_info &&
		    soc_end->codec_info->add_sidecar) {
			ret = soc_end->codec_info->add_sidecar(card, dai_links,
							       codec_conf);
			if (ret)
				return ret;
		}
	}

	for_each_pcm_streams(stream) {
		static const char * const sdw_stream_name[] = {
			"SDW%d-PLAYBACK",
			"SDW%d-CAPTURE",
			"SDW%d-PLAYBACK-%s",
			"SDW%d-CAPTURE-%s",
		};
		struct snd_soc_dai_link_ch_map *codec_maps;
		struct snd_soc_dai_link_component *codecs;
		struct snd_soc_dai_link_component *cpus;
		int num_cpus = hweight32(soc_dai->link_mask[stream]);
		int num_codecs = soc_dai->num_devs[stream];
		int playback, capture;
		int cur_link = 0;
		int i = 0, j = 0;
		int dai_type;
		char *name;
		const int str_name_with_type_offset = 2;
		int str_offset = stream;

		if (!soc_dai->num_devs[stream])
			continue;

		soc_end = list_first_entry(&soc_dai->endpoints,
					   struct asoc_sdw_endpoint, list);

		*be_id = soc_end->dai_info->dailink[stream];
		if (*be_id < 0) {
			dev_err(dev, "Invalid dailink id %d\n", *be_id);
			return -EINVAL;
		}

		/* create stream name according to first link id */
		if (ctx->append_dai_type) {
			str_offset += str_name_with_type_offset;
			dai_type = soc_end->dai_info->dai_type;
			if (dai_type >= ARRAY_SIZE(type_strings)) {
				dev_err(dev, "Invalid dai_type %d\n", dai_type);
				return -EINVAL;
			}
			name = devm_kasprintf(dev, GFP_KERNEL,
					      sdw_stream_name[str_offset],
					      ffs(soc_end->link_mask) - 1,
					      type_strings[dai_type]);
		} else {
			name = devm_kasprintf(dev, GFP_KERNEL,
					      sdw_stream_name[str_offset],
					      ffs(soc_end->link_mask) - 1);
		}
		if (!name)
			return -ENOMEM;

		cpus = devm_kcalloc(dev, num_cpus, sizeof(*cpus), GFP_KERNEL);
		if (!cpus)
			return -ENOMEM;

		codecs = devm_kcalloc(dev, num_codecs, sizeof(*codecs),
				      GFP_KERNEL);
		if (!codecs)
			return -ENOMEM;

		codec_maps = devm_kcalloc(dev, num_codecs, sizeof(*codec_maps),
					  GFP_KERNEL);
		if (!codec_maps)
			return -ENOMEM;

		list_for_each_entry(soc_end, &soc_dai->endpoints, list) {
			if (!soc_end->dai_info->direction[stream])
				continue;

			if (cur_link != soc_end->link_mask) {
				int link = ffs(soc_end->link_mask) - 1;
				int pin;

				if (link < 0 || link >= MT8901_SDW_MAX_LINKS) {
					dev_err(dev, "Invalid link index %d",
						link);
					return -EINVAL;
				}

				pin = mtk_ctx->sdw_pin_index[link][stream]++;

				cur_link = soc_end->link_mask;
				if (stream == SNDRV_PCM_STREAM_PLAYBACK) {
					cpus[i].dai_name =
						devm_kasprintf(dev, GFP_KERNEL,
							       "SDW%d_Playback%d",
							       link, pin);
				} else {
					cpus[i].dai_name =
						devm_kasprintf(dev, GFP_KERNEL,
							       "SDW%d_Capture%d",
							       link, pin);
				}
				if (!cpus[i].dai_name)
					return -ENOMEM;
				i++;
			}

			codec_maps[j].cpu = i - 1;
			codec_maps[j].codec = j;

			codecs[j].name = soc_end->codec_name;
			codecs[j].dai_name = soc_end->dai_info->dai_name;
			j++;
		}

		WARN_ON(i != num_cpus || j != num_codecs);

		playback = (stream == SNDRV_PCM_STREAM_PLAYBACK);
		capture = (stream == SNDRV_PCM_STREAM_CAPTURE);

		asoc_sdw_init_dai_link(dev, *dai_links, be_id, name,
				       playback, capture,
				       cpus, num_cpus, &snd_soc_dummy_dlc,
				       1, codecs, num_codecs,
				       1, asoc_sdw_rtd_init, &sdw_ops);

		(*dai_links)->nonatomic = true;
		(*dai_links)->ch_maps = codec_maps;

		list_for_each_entry(soc_end, &soc_dai->endpoints, list) {
			if (soc_end->dai_info->init)
				soc_end->dai_info->init(card, *dai_links,
							soc_end->codec_info,
							playback);
		}

		(*dai_links)++;
	}

	return 0;
}

static int create_sdw_dailinks(struct snd_soc_card *card,
			       struct snd_soc_dai_link **dai_links, int *be_id,
			       struct asoc_sdw_dailink *soc_dais,
			       struct snd_soc_codec_conf **codec_conf)
{
	struct asoc_sdw_mc_private *ctx = snd_soc_card_get_drvdata(card);
	struct mtk_mc_ctx *mtk_ctx = (struct mtk_mc_ctx *)ctx->private;
	int ret, i, stream;

	for (i = 0; i < MT8901_SDW_MAX_LINKS; i++)
		for_each_pcm_streams(stream)
			mtk_ctx->sdw_pin_index[i][stream] = 0;

	/* generate DAI links by each sdw link */
	while (soc_dais->initialised) {
		int current_be_id = 0;

		ret = create_sdw_dailink(card, soc_dais, dai_links,
					 &current_be_id, codec_conf);
		if (ret)
			return ret;

		/* Update the be_id to match the highest ID used for SDW link */
		if (*be_id < current_be_id)
			*be_id = current_be_id;

		soc_dais++;
	}

	return 0;
}

static int soc_card_dai_links_create(struct snd_soc_card *card)
{
	struct device *dev = card->dev;
	int sdw_be_num = 0;
	struct asoc_sdw_endpoint *soc_ends __free(kfree) = NULL;
	struct asoc_sdw_dailink *soc_dais __free(kfree) = NULL;
	struct snd_soc_aux_dev *soc_aux;
	struct snd_soc_codec_conf *codec_conf;
	struct snd_soc_dai_link *dai_links;
	int num_devs = 0;
	int num_ends = 0;
	int num_confs;
	int num_aux = 0;
	int num_links;
	int be_id = 0;
	int ret;

	ret = asoc_sdw_count_sdw_endpoints(card, &num_devs, &num_ends,
					   &num_aux);
	if (ret < 0) {
		dev_err(dev, "failed to count sdw devices/endpoints: %d\n",
			ret);
		return ret;
	}

	/*
	 * One codec_conf entry is consumed per surviving endpoint (each
	 * endpoint of a multi-endpoint codec carries the name prefix), so the
	 * budget must start from the endpoint count, not the device count.
	 * asoc_sdw_parse_sdw_endpoints() decrements it for each endpoint it
	 * skips. Same accounting as upstream sof_sdw.
	 */
	num_confs = num_ends;

	/* One per DAI link, worst case is a DAI link for every endpoint */
	soc_dais = kcalloc(num_ends, sizeof(*soc_dais), GFP_KERNEL);
	if (!soc_dais)
		return -ENOMEM;

	/* One per endpoint, ie. each DAI on each codec/amp */
	soc_ends = kcalloc(num_ends, sizeof(*soc_ends), GFP_KERNEL);
	if (!soc_ends)
		return -ENOMEM;

	soc_aux = devm_kcalloc(dev, num_aux, sizeof(*soc_aux), GFP_KERNEL);
	if (!soc_aux)
		return -ENOMEM;

	ret = asoc_sdw_parse_sdw_endpoints(card, soc_aux, soc_dais, soc_ends,
					   &num_confs);
	if (ret < 0) {
		dev_err(dev, "failed to parse sdw devices/endpoints: %d\n",
			ret);
		return ret;
	}

	sdw_be_num = ret;
	dev_dbg(dev, "sdw be %d", sdw_be_num);

	codec_conf = devm_kcalloc(dev, num_confs, sizeof(*codec_conf),
				  GFP_KERNEL);
	if (!codec_conf)
		return -ENOMEM;

	/* allocate FE + BE dailinks */
	num_links = ARRAY_SIZE(mt8901_fe_dais) + sdw_be_num;
	dai_links = devm_kcalloc(dev, num_links, sizeof(*dai_links),
				 GFP_KERNEL);
	if (!dai_links)
		return -ENOMEM;

	card->codec_conf = codec_conf;
	card->num_configs = num_confs;
	card->dai_link = dai_links;
	card->num_links = num_links;

	/* FE (AFE front ends) first, then BE (SoundWire). */
	ret = create_FE_dailinks(card, &dai_links);
	if (ret)
		return ret;

	/* SDW */
	if (sdw_be_num) {
		ret = create_sdw_dailinks(card, &dai_links, &be_id,
					  soc_dais, &codec_conf);
		if (ret)
			return ret;
	}

	WARN_ON(codec_conf != card->codec_conf + card->num_configs);
	WARN_ON(dai_links != card->dai_link + card->num_links);

	return ret;
}

static int mt8901_card_probe(struct platform_device *pdev)
{
	struct snd_soc_acpi_mach *mach = dev_get_platdata(&pdev->dev);
	struct snd_soc_card *card;
	struct mtk_mc_ctx *mtk_ctx;
	struct asoc_sdw_mc_private *ctx;
	int amp_num = 0;
	int i, ret;

	mtk_ctx = devm_kzalloc(&pdev->dev, sizeof(*mtk_ctx), GFP_KERNEL);
	if (!mtk_ctx)
		return -ENOMEM;

	ctx = devm_kzalloc(&pdev->dev, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	ctx->codec_info_list_count = asoc_sdw_get_codec_info_list_count();
	ctx->private = mtk_ctx;
	card = &ctx->card;
	card->dev = &pdev->dev;
	card->name = "mt8901-soundwire";
	card->owner = THIS_MODULE;
	card->late_probe = asoc_sdw_card_late_probe;
	card->dapm_routes     = mt8901_card_routes;
	card->num_dapm_routes = ARRAY_SIZE(mt8901_card_routes);

	snd_soc_card_set_drvdata(card, ctx);

	if (quirk_override != -1) {
		dev_info(card->dev, "Overriding quirk 0x%lx => 0x%x\n",
			 soc_sdw_quirk, quirk_override);
		soc_sdw_quirk = (unsigned int)quirk_override;
	}

	log_quirks(card->dev);

	ctx->mc_quirk = soc_sdw_quirk;
	dev_dbg(card->dev, "legacy quirk 0x%lx\n", ctx->mc_quirk);
	/* reset amp_num to ensure amp_num++ starts from 0 in each probe */
	for (i = 0; i < ctx->codec_info_list_count; i++)
		codec_info_list[i].amp_num = 0;

	ret = soc_card_dai_links_create(card);
	if (ret < 0)
		return ret;

	/*
	 * the default amp_num is zero for each codec and
	 * amp_num will only be increased for active amp
	 * codecs on used platform
	 */
	for (i = 0; i < ctx->codec_info_list_count; i++)
		amp_num += codec_info_list[i].amp_num;

	card->components = devm_kasprintf(card->dev, GFP_KERNEL,
					  "cfg-amp:%d", amp_num);
	if (!card->components)
		return -ENOMEM;
	if (mach && mach->mach_params.dmic_num) {
		card->components = devm_kasprintf(card->dev, GFP_KERNEL,
						  "%s mic:dmic cfg-mics:%d",
						  card->components,
						  mach->mach_params.dmic_num);
		if (!card->components)
			return -ENOMEM;
	}

	/* Register the card */
	ret = devm_snd_soc_register_card(card->dev, card);
	if (ret) {
		dev_err_probe(card->dev, ret,
			      "snd_soc_register_card failed %d\n", ret);
		asoc_sdw_mc_dailink_exit_loop(card);
		return ret;
	}

	platform_set_drvdata(pdev, card);

	return ret;
}

static void mt8901_card_remove(struct platform_device *pdev)
{
	struct snd_soc_card *card = platform_get_drvdata(pdev);

	asoc_sdw_mc_dailink_exit_loop(card);
}

static const struct platform_device_id mc_id_table[] = {
	{ "mtk_sdw_mc", },
	{}
};
MODULE_DEVICE_TABLE(platform, mc_id_table);

static struct platform_driver soc_sdw_driver = {
	.driver = {
		.name = "mtk_sdw_mc",
		.pm = &snd_soc_pm_ops,
	},
	.probe = mt8901_card_probe,
	.remove = mt8901_card_remove,
	.id_table = mc_id_table,
};

module_platform_driver(soc_sdw_driver);

MODULE_DESCRIPTION("MTK SoundWire legacy MT8901 machine driver");
MODULE_AUTHOR("Trevor Wu <trevor.wu@mediatek.com>");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS("SND_SOC_SDW_UTILS");
