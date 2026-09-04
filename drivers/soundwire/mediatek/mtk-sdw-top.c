// SPDX-License-Identifier: GPL-2.0
/*
 * MediaTek SoundWire master — AFE TOP control
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 */

#include <linux/bitfield.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include "mtk-sdw-top.h"

/* these two arrays cover everything written by top_init and configure_pdi */
static const unsigned int mtk_sdw_top_con_backup_regs[] = {
	SDW_TOP_CON0,
	SDW_TOP_CON1,
};

static const unsigned int mtk_sdw_top_pdi_backup_regs[] = {
	SDW_TOP_PDIN_CON0(0),
	SDW_TOP_PDIN_CON0(1),
	SDW_TOP_PDIN_CON0(2),
	SDW_TOP_PDIN_CON0(3),
	SDW_TOP_PDIN_CON0(4),
	SDW_TOP_PDIN_CON0(5),
	SDW_TOP_PDIN_CON0(6),
	SDW_TOP_PDIN_CON0(7),
	SDW_TOP_PDIN_CON0(8),
	SDW_TOP_PDIN_CON0(9),
	SDW_TOP_PDIN_CON0(10),
	SDW_TOP_PDIN_CON0(11),
	SDW_TOP_PDIN_CON0(12),
	SDW_TOP_PDIN_CON0(13),
	SDW_TOP_PDIN_CON0(14),
	SDW_TOP_PDIN_CON0(15),
	SDW_TOP_PDIN_CON0(16),
	SDW_TOP_PDIN_CON0(17),
};

static const struct mtk_sdw_top_cfg mtk_sdw_top_cfgs[MTK_SDW_TOP_VER_MAX] = {
	[MTK_SDW_TOP_VER_0] = {
		.name     = "hw_8901",
		.reg = {
			.tzd_delay_reg = SDW_TOP_CON0,
			.tzd_delay_sel = GENMASK(5, 3),
			.tzd_inverse = BIT(2),
			.tzd_delay_en = BIT(1),
			.phy_delay_reg = SDW_TOP_CON1,
			.phy_delay_sel = GENMASK(3, 1),
			.phy_double_delay_sel = GENMASK(6, 4),
		},
	},
};

static u32 topcon_readl(struct mtk_sdw *mst, u32 off)
{
	return readl(mst->top_con + off);
}

static void topcon_writel(struct mtk_sdw *mst, u32 off, u32 val)
{
	writel(val, mst->top_con + off);
}

static void topcon_updatel(struct mtk_sdw *mst, u32 off, u32 mask, u32 val)
{
	u32 tmp = topcon_readl(mst, off);

	topcon_writel(mst, off, (tmp & ~mask) | (val & mask));
}

static u32 toppdi_readl(struct mtk_sdw *mst, u32 off)
{
	return readl(mst->top_pdi + off);
}

static void toppdi_writel(struct mtk_sdw *mst, u32 off, u32 val)
{
	writel(val, mst->top_pdi + off);
}

static void toppdi_updatel(struct mtk_sdw *mst, u32 off, u32 mask, u32 val)
{
	u32 tmp = toppdi_readl(mst, off);

	toppdi_writel(mst, off, (tmp & ~mask) | (val & mask));
}

static inline u32 mtk_field_prep(u32 mask, u32 val)
{
	if (!mask)
		return 0;
	return (val << __bf_shf(mask)) & mask;
}

int mtk_sdw_top_config_select(struct mtk_sdw *mst, int hw_ver)
{
	int ver_id;

	switch (hw_ver) {
	case MTK_SDW_HW_VER_MT8901:
	case MTK_SDW_HW_VER_MT8971:
		ver_id = MTK_SDW_TOP_VER_0;
		break;
	default:
		dev_err(mst->dev, "unsupported  hw-ver %d\n", hw_ver);
		return -EINVAL;
	}

	mst->top_cfg = &mtk_sdw_top_cfgs[ver_id];
	dev_info(mst->dev, "AFE TOP variant: %s (hw-ver %u)\n",
		 mst->top_cfg->name, mst->hw_ver);
	return 0;
}

static void mtk_sdw_top_init_settings(struct mtk_sdw *mst)
{
	topcon_updatel(mst, SDW_TOP_CON0, SDW_TOP_CON0_GSYNC_DIR_CTRL,
		       SDW_TOP_CON0_GSYNC_DIR_CTRL);
}

static void mtk_sdw_top_configure_delays(struct mtk_sdw *mst)
{
	u32 val = 0;
	u32 mask;
	const struct mtk_sdw_top_reg *top_reg = &mst->top_cfg->reg;

	mask = top_reg->tzd_delay_sel | top_reg->tzd_inverse |
		top_reg->tzd_delay_en;
	val |= mtk_field_prep(top_reg->tzd_delay_sel, mst->tzd_delay - 1);
	if (mst->tzd_inverse)
		val |= top_reg->tzd_inverse;
	if (mst->tzd_delay)
		val |= top_reg->tzd_delay_en;
	topcon_updatel(mst, top_reg->tzd_delay_reg, mask, val);

	val = 0;
	mask = top_reg->phy_delay_sel | top_reg->phy_double_delay_sel;
	val |= mtk_field_prep(top_reg->phy_delay_sel, mst->phy_delay);
	val |= mtk_field_prep(top_reg->phy_double_delay_sel,
			   mst->phy_double_delay);

	topcon_updatel(mst, top_reg->phy_delay_reg, mask, val);
}

int mtk_sdw_top_init(struct mtk_sdw *mst)
{
	struct device *dev = mst->dev;

	mst->top_pdi_reg_backup_num = ARRAY_SIZE(mtk_sdw_top_pdi_backup_regs);
	mst->top_con_reg_backup_num = ARRAY_SIZE(mtk_sdw_top_con_backup_regs);

	mst->top_pdi_reg_backup =
		devm_kcalloc(dev, mst->top_pdi_reg_backup_num,
			     sizeof(*mst->top_pdi_reg_backup),
			     GFP_KERNEL);
	if (!mst->top_pdi_reg_backup)
		return -ENOMEM;

	mst->top_con_reg_backup =
		devm_kcalloc(dev, mst->top_con_reg_backup_num,
			     sizeof(*mst->top_con_reg_backup),
			     GFP_KERNEL);
	if (!mst->top_con_reg_backup)
		return -ENOMEM;

	mtk_sdw_top_init_settings(mst);
	mtk_sdw_top_configure_delays(mst);

	return 0;
}

void mtk_sdw_top_configure_pdi(struct mtk_sdw *mst, u32 pdi,
			       struct mtk_sdw_top_pdi_params *param)
{
	u32 val = 0;
	u32 mask = 0;

	mask |= SDW_TOP_PDI_GROUP_SYNC;

	val |= FIELD_PREP(SDW_TOP_PDI_SLAVE_MODE, param->slave_mode);
	mask |= SDW_TOP_PDI_SLAVE_MODE;

	val |= FIELD_PREP(SDW_TOP_PDI_BRA_SLAVE, param->bra_slave);
	mask |= SDW_TOP_PDI_BRA_SLAVE;

	val |= FIELD_PREP(SDW_TOP_PDI_BRA_EOP, param->bra_eop);
	mask |= SDW_TOP_PDI_BRA_EOP;

	val |= FIELD_PREP(SDW_TOP_PDI_BRA_MODE, param->bra_mode);
	mask |= SDW_TOP_PDI_BRA_MODE;

	val |= FIELD_PREP(SDW_TOP_PDI_DMIC_1XEN, param->dmic_1xen);
	mask |= SDW_TOP_PDI_DMIC_1XEN;

	val |= FIELD_PREP(SDW_TOP_PDI_PDM_ONE_WIRE, param->pdm_one_wire);
	mask |= SDW_TOP_PDI_PDM_ONE_WIRE;

	val |= FIELD_PREP(SDW_TOP_PDI_PDM_MODE, param->pdm_mode);
	mask |= SDW_TOP_PDI_PDM_MODE;

	val |= FIELD_PREP(SDW_TOP_PDI_HD_SEL, param->hd_sel);
	mask |= SDW_TOP_PDI_HD_SEL;

	val |= FIELD_PREP(SDW_TOP_PDI_CLOCK, param->clock);
	mask |= SDW_TOP_PDI_CLOCK;

	val |= FIELD_PREP(SDW_TOP_PDI_PDM2PCM, param->pdm2pcm);
	mask |= SDW_TOP_PDI_PDM2PCM;

	val |= FIELD_PREP(SDW_TOP_PDI_IP_SEL, param->sdw_ip_sel);
	mask |= SDW_TOP_PDI_IP_SEL;

	val |= FIELD_PREP(SDW_TOP_PDI_DOMAIN, param->domain);
	mask |= SDW_TOP_PDI_DOMAIN;

	val |= FIELD_PREP(SDW_TOP_PDI_FS, param->fs);
	mask |= SDW_TOP_PDI_FS;

	toppdi_updatel(mst, SDW_TOP_PDIN_CON0(pdi), mask, val);
}

static void mtk_sdw_top_enable_pdi_engen(struct mtk_sdw *mst, u32 pdi,
					 bool enable)
{
	toppdi_updatel(mst, SDW_TOP_PDIN_CON0(pdi), SDW_TOP_PDI_EN,
		       enable ? SDW_TOP_PDI_EN : 0);
}

static void mtk_sdw_top_enable_group_sync(struct mtk_sdw *mst, u32 pdi,
					  bool enable)
{
	toppdi_updatel(mst, SDW_TOP_PDIN_CON0(pdi), SDW_TOP_PDI_GROUP_SYNC_ON,
		       enable ? SDW_TOP_PDI_GROUP_SYNC_ON : 0);
}

static void mtk_sdw_top_config_group_sync(struct mtk_sdw *mst, u32 pdi,
					  u32 group)
{
	toppdi_updatel(mst, SDW_TOP_PDIN_CON0(pdi), SDW_TOP_PDI_GROUP_SYNC,
		       FIELD_PREP(SDW_TOP_PDI_GROUP_SYNC, group));
}

int mtk_sdw_top_group_sync_config_get(struct mtk_sdw *mst, u8 id, u32 *cfg)
{
	if (id > MTK_SDW_MAX_GROUP_SYNC)
		return -EINVAL;
	else if (id == GROUP_SYNC_NONE)
		*cfg = 0;
	else
		*cfg = BIT(id - 1);

	return 0;
}

int mtk_sdw_top_group_sync_acquire(struct mtk_sdw *mst, bool is_tx)
{
	u8 min_id = is_tx ? TOP_GROUP_SYNC_TX_MIN_ID : TOP_GROUP_SYNC_RX_MIN_ID;
	u8 max_id = is_tx ? TOP_GROUP_SYNC_TX_MAX_ID : TOP_GROUP_SYNC_RX_MAX_ID;
	int best = -1;
	int best_refcnt = INT_MAX;
	int i, idx;

	guard(mutex)(&mst->group_lock);

	for (i = 0; i < MTK_SDW_MAX_GROUP_SYNC; i++) {
		idx = is_tx ? i : (MTK_SDW_MAX_GROUP_SYNC - 1 - i);

		if (idx < min_id - 1 || idx > max_id - 1)
			continue;
		if (mst->group_refcnt[idx] < best_refcnt) {
			best = idx;
			best_refcnt = mst->group_refcnt[idx];
		}
	}
	if (best < 0)
		return -EINVAL;

	mst->group_refcnt[best]++;
	return best + 1;        /* 1-based id */
}

void mtk_sdw_top_group_sync_release(struct mtk_sdw *mst, u8 id)
{
	if (id == 0 || id > MTK_SDW_MAX_GROUP_SYNC)
		return;

	guard(mutex)(&mst->group_lock);

	if (mst->group_refcnt[id - 1] <= 0) {
		dev_err(mst->dev, "unexpected refcnt %d\n",
			mst->group_refcnt[id - 1]);
		return;
	}
	mst->group_refcnt[id - 1]--;
}

int mtk_sdw_top_enable_stream(struct mtk_sdw *mst, int dai_id)
{
	struct mtk_sdw_dai *mdai = &mst->dais[dai_id];
	int i;
	u32 pdi_num, group_sync;

	for (i = 0; i < mdai->pdi_count; i++) {
		pdi_num = mdai->pdi_params[i].pdi_num;
		mtk_sdw_top_enable_pdi_engen(mst, pdi_num, true);
	}

	if (mdai->need_enable_delay)
		usleep_range(1000, 1100);

	if (mdai->use_group_sync) {
		for (i = 0; i < mdai->pdi_count; i++) {
			pdi_num = mdai->pdi_params[i].pdi_num;
			group_sync = mdai->top_pdi_params[i].group_sync;
			mtk_sdw_top_config_group_sync(mst, pdi_num, group_sync);
		}
		for (i = 0; i < mdai->pdi_count; i++) {
			pdi_num = mdai->pdi_params[i].pdi_num;
			mtk_sdw_top_enable_group_sync(mst, pdi_num, true);
		}
	}

	return 0;
}

int mtk_sdw_top_disable_stream(struct mtk_sdw *mst, int dai_id)
{
	struct mtk_sdw_dai *mdai = &mst->dais[dai_id];
	int i;
	u32 pdi_num;

	for (i = 0; i < mdai->pdi_count; i++) {
		pdi_num = mdai->pdi_params[i].pdi_num;
		mtk_sdw_top_enable_pdi_engen(mst, pdi_num, false);
	}

	if (mdai->use_group_sync) {
		for (i = 0; i < mdai->pdi_count; i++) {
			pdi_num = mdai->pdi_params[i].pdi_num;
			mtk_sdw_top_enable_group_sync(mst, pdi_num, false);
		}

		for (i = 0; i < mdai->pdi_count; i++) {
			pdi_num = mdai->pdi_params[i].pdi_num;
			mtk_sdw_top_config_group_sync(mst, pdi_num, 0);
		}
	}

	return 0;
}

void mtk_sdw_top_backup_regs(struct mtk_sdw *mst)
{
	int i;

	for (i = 0; i < mst->top_con_reg_backup_num; i++)
		mst->top_con_reg_backup[i] =
			topcon_readl(mst, mtk_sdw_top_con_backup_regs[i]);

	for (i = 0; i < mst->top_pdi_reg_backup_num; i++)
		mst->top_pdi_reg_backup[i] =
			toppdi_readl(mst, mtk_sdw_top_pdi_backup_regs[i]);
}

void mtk_sdw_top_restore_regs(struct mtk_sdw *mst)
{
	int i;

	for (i = 0; i < mst->top_con_reg_backup_num; i++)
		topcon_writel(mst, mtk_sdw_top_con_backup_regs[i],
			      mst->top_con_reg_backup[i]);

	for (i = 0; i < mst->top_pdi_reg_backup_num; i++)
		toppdi_writel(mst, mtk_sdw_top_pdi_backup_regs[i],
			      mst->top_pdi_reg_backup[i]);
}
