// SPDX-License-Identifier: GPL-2.0
/*
 * MediaTek MT8901 SoundWire DAI driver
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 *         Weiyi Hsieh <weiyi.hsieh@mediatek.com>
 */

#include "mt8901-afe-common.h"
#include "mt8901-reg.h"

/* BRA TX SDW1: DL5 I042/I043 -> O148/O149 */
static const struct snd_kcontrol_new mtk_dai_sndw_o148_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I042 Switch", AFE_CONN148_1, 10, 1, 0),
};

static const struct snd_kcontrol_new mtk_dai_sndw_o149_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I043 Switch", AFE_CONN149_1, 11, 1, 0),
};

/* SCD0 DL: O150/O151 <- DL0 I032/I033 (2CH), DL_24CH I054/I055 (>2CH) */
static const struct snd_kcontrol_new mtk_dai_sndw_o150_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I032 Switch", AFE_CONN150_1, 0, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I054 Switch", AFE_CONN150_1, 22, 1, 0),
};

static const struct snd_kcontrol_new mtk_dai_sndw_o151_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I033 Switch", AFE_CONN151_1, 1, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I055 Switch", AFE_CONN151_1, 23, 1, 0),
};

/* PDI3 mix: O152/O153 <- DL0 I032/I033 (2CH aggr), DL_24CH I056/I057 (>2CH) */
static const struct snd_kcontrol_new mtk_dai_sndw_o152_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I032 Switch", AFE_CONN152_1, 0, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I056 Switch", AFE_CONN152_1, 24, 1, 0),
};

static const struct snd_kcontrol_new mtk_dai_sndw_o153_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I033 Switch", AFE_CONN153_1, 1, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I057 Switch", AFE_CONN153_1, 25, 1, 0),
};

/* PDI4 mix: O154/O155 <- DL_24CH I058/I059 (>2CH ch5~6) */
static const struct snd_kcontrol_new mtk_dai_sndw_o154_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I058 Switch", AFE_CONN154_1, 26, 1, 0),
};

static const struct snd_kcontrol_new mtk_dai_sndw_o155_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I059 Switch", AFE_CONN155_1, 27, 1, 0),
};

/* PDI5 mix: O156/O157 <- DL1 I034/I035 (HP/HSO first-fit),
 * DL_24CH I060/I061 (>2CH ch7~8)
 */
static const struct snd_kcontrol_new mtk_dai_sndw_o156_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I034 Switch", AFE_CONN156_1, 2, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I060 Switch", AFE_CONN156_1, 28, 1, 0),
};

static const struct snd_kcontrol_new mtk_dai_sndw_o157_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I035 Switch", AFE_CONN157_1, 3, 1, 0),
	SOC_DAPM_SINGLE_AUTODISABLE("I061 Switch", AFE_CONN157_1, 29, 1, 0),
};

/* PDI6 mix: O158/O159 <- DL1 I034/I035 (Headphone/HeadsetOutput contention) */
static const struct snd_kcontrol_new mtk_dai_sndw_o158_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I034 Switch", AFE_CONN158_1, 2, 1, 0),
};

static const struct snd_kcontrol_new mtk_dai_sndw_o159_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I035 Switch", AFE_CONN159_1, 3, 1, 0),
};

/* BRA TX SDW0: O160/O161 <- DL4 I040/I041 */
static const struct snd_kcontrol_new mtk_dai_sndw_o160_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I040 Switch", AFE_CONN160_1, 8, 1, 0),
};

static const struct snd_kcontrol_new mtk_dai_sndw_o161_mix[] = {
	SOC_DAPM_SINGLE_AUTODISABLE("I041 Switch", AFE_CONN161_1, 9, 1, 0),
};

static const struct snd_soc_dapm_widget mtk_dai_soundwire_widgets[] = {
	/* BRA TX SDW1: O148/O149 */
	SND_SOC_DAPM_MIXER("O148", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o148_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o148_mix)),
	SND_SOC_DAPM_MIXER("O149", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o149_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o149_mix)),

	/* TX O port widgets: O150~O161 */
	SND_SOC_DAPM_MIXER("O150", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o150_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o150_mix)),
	SND_SOC_DAPM_MIXER("O151", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o151_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o151_mix)),
	SND_SOC_DAPM_MIXER("O152", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o152_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o152_mix)),
	SND_SOC_DAPM_MIXER("O153", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o153_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o153_mix)),
	SND_SOC_DAPM_MIXER("O154", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o154_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o154_mix)),
	SND_SOC_DAPM_MIXER("O155", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o155_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o155_mix)),
	SND_SOC_DAPM_MIXER("O156", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o156_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o156_mix)),
	SND_SOC_DAPM_MIXER("O157", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o157_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o157_mix)),
	SND_SOC_DAPM_MIXER("O158", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o158_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o158_mix)),
	SND_SOC_DAPM_MIXER("O159", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o159_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o159_mix)),
	SND_SOC_DAPM_MIXER("O160", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o160_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o160_mix)),
	SND_SOC_DAPM_MIXER("O161", SND_SOC_NOPM, 0, 0,
			   mtk_dai_sndw_o161_mix,
			   ARRAY_SIZE(mtk_dai_sndw_o161_mix)),

	/* RX I port widgets */
	/* SNDW1 exclusive: I166/I167 */
	SND_SOC_DAPM_MIXER("I166", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I167", SND_SOC_NOPM, 0, 0, NULL, 0),

	/* Shared PDI7~PDI15: I168~I185 */
	SND_SOC_DAPM_MIXER("I168", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I169", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I170", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I171", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I172", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I173", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I174", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I175", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I176", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I177", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I178", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I179", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I180", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I181", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I182", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I183", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I184", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I185", SND_SOC_NOPM, 0, 0, NULL, 0),

	/* SNDW0 exclusive: I186/I187 */
	SND_SOC_DAPM_MIXER("I186", SND_SOC_NOPM, 0, 0, NULL, 0),
	SND_SOC_DAPM_MIXER("I187", SND_SOC_NOPM, 0, 0, NULL, 0),
};

static const struct snd_soc_dapm_route mtk_dai_sndw_routes[] = {
	/* BRA TX SDW1: DL5 -> O148/O149 */
	{"O148", "I042 Switch", "I042"},
	{"O149", "I043 Switch", "I043"},

	/* Speaker 2CH: DL0 -> PDI2 */
	{"O150", "I032 Switch", "I032"},
	{"O151", "I033 Switch", "I033"},

	/* Speaker 2CH aggregation: DL0 -> PDI3 */
	{"O152", "I032 Switch", "I032"},
	{"O153", "I033 Switch", "I033"},

	/* Speaker >2CH max 8CH: DL_24CH -> PDI2~PDI5 (O150~O157) */
	{"O150", "I054 Switch", "I054"},
	{"O151", "I055 Switch", "I055"},
	{"O152", "I056 Switch", "I056"},
	{"O153", "I057 Switch", "I057"},
	{"O154", "I058 Switch", "I058"},
	{"O155", "I059 Switch", "I059"},
	{"O156", "I060 Switch", "I060"},
	{"O157", "I061 Switch", "I061"},

	/* BRA TX SDW0: DL4 -> O160/O161 */
	{"O160", "I040 Switch", "I040"},
	{"O161", "I041 Switch", "I041"},

	/* Headphone/HeadsetOutput: DL1 -> PDI5 (first-fit) */
	{"O156", "I034 Switch", "I034"},
	{"O157", "I035 Switch", "I035"},

	/* Headphone/HeadsetOutput: DL1 -> PDI6 (contention) */
	{"O158", "I034 Switch", "I034"},
	{"O159", "I035 Switch", "I035"},
};

int mt8901_dai_soundwire_register(struct mtk_base_afe *afe)
{
	struct mtk_base_afe_dai *dai;

	dai = devm_kzalloc(afe->dev, sizeof(*dai), GFP_KERNEL);
	if (!dai)
		return -ENOMEM;

	list_add(&dai->list, &afe->sub_dais);

	dai->dapm_widgets = mtk_dai_soundwire_widgets;
	dai->num_dapm_widgets = ARRAY_SIZE(mtk_dai_soundwire_widgets);
	dai->dapm_routes = mtk_dai_sndw_routes;
	dai->num_dapm_routes = ARRAY_SIZE(mtk_dai_sndw_routes);

	return 0;
}
