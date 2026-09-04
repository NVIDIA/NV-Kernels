// SPDX-License-Identifier: GPL-2.0
/*
 * MediaTek SoundWire audio machine selection (codec-combination tables).
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 */
#include <linux/slab.h>
#include <linux/soundwire/sdw.h>
#include <sound/soc-acpi.h>
#include "mtk-sdw-mach.h"

static const struct snd_soc_acpi_endpoint rt1320_endpoints[] = {
	{
		.num = 0,
		.aggregated = 1,
		.group_position = 0,
		.group_id = 1,
	},
	{
		.num = 0,
		.aggregated = 1,
		.group_position = 1,
		.group_id = 1,
	},
};

static const struct snd_soc_acpi_endpoint rt712_endpoints[] = {
	{
		.num = 0,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
	{
		.num = 2,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
};

/*
 * Config 0: SDW0 = RT1320 (amp), SDW1 = RT712 (jack codec).
 */
static const struct snd_soc_acpi_adr_device rt1320_l0_adr[] = {
	{
		.adr = 0x000030025D132001ull,
		.num_endpoints = 1,
		.endpoints = &rt1320_endpoints[0],
		.name_prefix = "rt1320-1",
	},
	{
		.adr = 0x000032025D132001ull,
		.num_endpoints = 1,
		.endpoints = &rt1320_endpoints[1],
		.name_prefix = "rt1320-2",
	},
};

static const struct snd_soc_acpi_adr_device rt712_l1_adr[] = {
	{
		.adr = 0x000130025D071201ull,
		.num_endpoints = ARRAY_SIZE(rt712_endpoints),
		.endpoints = rt712_endpoints,
		.name_prefix = "rt712",
	},
};

static const struct snd_soc_acpi_link_adr mtk_sdw_rt1320_l0_rt712_l1[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(rt1320_l0_adr),
		.adr_d = rt1320_l0_adr,
	},
	{
		.mask = BIT(1),
		.num_adr = ARRAY_SIZE(rt712_l1_adr),
		.adr_d = rt712_l1_adr,
	},
	{}
};

/*
 * Config 1: SDW0 = 4x CS35L56 (amps, aggregated), SDW1 = CS42L43 (jack codec).
 * Topology: uids 0x30-0x33 on link0, 0x30 on
 * link1. Speaker position vs uid mapping to be confirmed on hardware; the
 * group positions below assume uid order.
 */
static const struct snd_soc_acpi_endpoint cs35l56_endpoints[] = {
	{
		.num = 0,
		.aggregated = 1,
		.group_position = 0,
		.group_id = 1,
	},
	{
		.num = 0,
		.aggregated = 1,
		.group_position = 1,
		.group_id = 1,
	},
	{
		.num = 0,
		.aggregated = 1,
		.group_position = 2,
		.group_id = 1,
	},
	{
		.num = 0,
		.aggregated = 1,
		.group_position = 3,
		.group_id = 1,
	},
};

static const struct snd_soc_acpi_endpoint cs42l43_endpoints[] = {
	{ /* Jack Playback Endpoint */
		.num = 0,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
	{ /* DMIC Capture Endpoint */
		.num = 1,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
	{ /* Jack Capture Endpoint */
		.num = 2,
		.aggregated = 0,
		.group_position = 0,
		.group_id = 0,
	},
};

static const struct snd_soc_acpi_adr_device cs35l56x4_l0_adr[] = {
	{
		.adr = 0x00003001FA355601ull,
		.num_endpoints = 1,
		.endpoints = &cs35l56_endpoints[0],
		.name_prefix = "AMP1",
	},
	{
		.adr = 0x00003101FA355601ull,
		.num_endpoints = 1,
		.endpoints = &cs35l56_endpoints[1],
		.name_prefix = "AMP2",
	},
	{
		.adr = 0x00003201FA355601ull,
		.num_endpoints = 1,
		.endpoints = &cs35l56_endpoints[2],
		.name_prefix = "AMP3",
	},
	{
		.adr = 0x00003301FA355601ull,
		.num_endpoints = 1,
		.endpoints = &cs35l56_endpoints[3],
		.name_prefix = "AMP4",
	},
};

static const struct snd_soc_acpi_adr_device cs42l43_l1_adr[] = {
	{
		.adr = 0x00013001FA424301ull,
		/*
		 * The cs42l43 Speaker Playback endpoint (num 3, the sidecar-amp
		 * path) is intentionally not in cs42l43_endpoints: on these
		 * boards the speaker amps are separate SoundWire peripherals.
		 */
		.num_endpoints = ARRAY_SIZE(cs42l43_endpoints),
		.endpoints = cs42l43_endpoints,
		.name_prefix = "cs42l43",
	},
};

static const struct snd_soc_acpi_link_adr mtk_sdw_cs35l56_l0_cs42l43_l1[] = {
	{
		.mask = BIT(0),
		.num_adr = ARRAY_SIZE(cs35l56x4_l0_adr),
		.adr_d = cs35l56x4_l0_adr,
	},
	{
		.mask = BIT(1),
		.num_adr = ARRAY_SIZE(cs42l43_l1_adr),
		.adr_d = cs42l43_l1_adr,
	},
	{}
};

static struct snd_soc_acpi_mach mtk_sdw_machines[] = {
	{
		.link_mask = BIT(0) | BIT(1),
		.links     = mtk_sdw_rt1320_l0_rt712_l1,
		.drv_name  = "mtk_sdw_mc",
	},
	{
		.link_mask = BIT(0) | BIT(1),
		.links     = mtk_sdw_cs35l56_l0_cs42l43_l1,
		.drv_name  = "mtk_sdw_mc",
	},
	{}
};

static void mtk_sdw_log_peripheral(struct device *dev,
				   struct sdw_slave *slave)
{
	dev_info(dev,
		 "[%d] class=0x%02x mfg=0x%04x part=0x%04x uniq=0x%x ver=0x%x\n",
		 slave->bus->link_id, slave->id.class_id, slave->id.mfg_id,
		 slave->id.part_id, slave->id.unique_id, slave->id.sdw_version);
}

static struct sdw_peripherals *mtk_sdw_get_peripherals(struct mtk_sdw *mst)
{
	struct sdw_peripherals *peripherals;
	struct sdw_slave *slave;
	struct sdw_bus *bus;
	int max_peripherals_num;
	int i, idx = 0;

	max_peripherals_num = mst->num_links * SDW_MAX_DEVICES;

	peripherals = kmalloc_flex(*peripherals, array, max_peripherals_num,
				   GFP_KERNEL);
	if (!peripherals)
		return NULL;

	for (i = 0; i < mst->num_links; i++) {
		bus = &mst->links[i].core.bus;
		mutex_lock(&bus->bus_lock);
		list_for_each_entry(slave, &bus->slaves, node) {
			if (idx >= max_peripherals_num) {
				dev_warn(mst->dev, "slave count exceeds capacity, truncating");
				break;
			}
			peripherals->array[idx++] = slave;
			mtk_sdw_log_peripheral(mst->dev, slave);
		}
		mutex_unlock(&bus->bus_lock);
	}
	peripherals->num_peripherals = idx;

	return peripherals;
}

struct snd_soc_acpi_mach *mtk_sdw_machine_select(struct mtk_sdw *mst)
{
	struct sdw_peripherals *peripherals;
	struct snd_soc_acpi_mach *mach;
	const struct snd_soc_acpi_link_adr *link;

	peripherals = mtk_sdw_get_peripherals(mst);
	if (!peripherals)
		return NULL;

	if (!peripherals->num_peripherals) {
		dev_dbg(mst->dev, "no SoundWire peripherals enumerated\n");
		kfree(peripherals);
		return NULL;
	}

	for (mach = mtk_sdw_machines; mach->link_mask; mach++) {
		for (link = mach->links; link && link->num_adr; link++) {
			if (!snd_soc_acpi_sdw_link_slaves_found(mst->dev, link,
								peripherals))
				break;
		}
		if (link && !link->num_adr) {
			mach->mach_params.links     = mach->links;
			mach->mach_params.link_mask = mach->link_mask;
			kfree(peripherals);
			return mach;
		}
	}
	dev_dbg(mst->dev, "no SoundWire machine matched\n");
	kfree(peripherals);
	return NULL;
}
