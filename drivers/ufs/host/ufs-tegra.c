// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// NVIDIA Tegra264 UFS host controller driver.

#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/of.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/reset.h>

#include <ufs/ufshcd.h>
#include <ufs/ufshci.h>
#include <ufs/unipro.h>

#include "ufshcd-dwc.h"
#include "ufshcd-pltfrm.h"
#include "ufshci-dwc.h"

#define UFSHC_DWC_BLOCK_BUSTHRTL		0xc0
#define MBL(x)					(((x) & 0x7) << 13)
#define MBL_MASK				(0x7 << 13)

#define HCLKDIV(x)				((x) & 0xff)

#define UFSHC_AUX_SW_EN_CLK_SLCG		0x08
#define CLK_OVR_ON				BIT(0)

#define UFSHC_AUX_DEV_CTRL			0x14
#define DEV_CTRL_CLK_EN				BIT(0)
#define DEV_CTRL_RESET				BIT(1)

#define UFS_TEGRA_UPHY_PLL_HS_RATE_HZ		5840000000UL

/* DWC UFSHC BUSTHRTL max AXI burst length. */
#define UFS_TEGRA_MBL_MAX			0x5

/* DWC UniPro save-config-time reference and value fields. */
#define UFS_TEGRA_SAVECONFIGTIME_TREF		0x6
#define UFS_TEGRA_SAVECONFIGTIME_SCT		0x3

/* HS G1..G4 sync burst length advertised to the peer. */
#define UFS_TEGRA_HSG_SYNC_LEN			0x4f

/* Local UniPro DME timeout values sent to the peer via PA_PWRMODEUSERDATA. */
#define UFS_TEGRA_FC0_TIMEOUT			0x1fff
#define UFS_TEGRA_TC0_TIMEOUT			0xffff
#define UFS_TEGRA_AFC0_TIMEOUT			0x7fff

struct ufs_tegra {
	void __iomem *aux;

	struct reset_control_bulk_data *resets;
	unsigned int num_resets;

	struct clk *core_clk;
	struct clk *uphy_pll_clk;

	struct phy *mphy_l0_rx;
	struct phy *mphy_l0_tx;
	struct phy *mphy_l1_rx;
	struct phy *mphy_l1_tx;

	bool mphy_on;

	struct ufs_host_params host_params;
};

static int ufs_tegra_init_resources(struct ufs_hba *hba)
{
	struct platform_device *pdev = to_platform_device(hba->dev);
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);

	ufs->aux = devm_platform_ioremap_resource_byname(pdev, "aux");
	if (IS_ERR(ufs->aux))
		return PTR_ERR(ufs->aux);

	return 0;
}

static const struct reset_control_bulk_data ufs_tegra_resets[] = {
	{ .id = "ufs" },
	{ .id = "axi" },
	{ .id = "lp" },
};

static int ufs_tegra_parse_reset_info(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	struct device *dev = hba->dev;

	ufs->num_resets = ARRAY_SIZE(ufs_tegra_resets);

	ufs->resets = devm_kmemdup(dev, ufs_tegra_resets, sizeof(ufs_tegra_resets), GFP_KERNEL);
	if (!ufs->resets)
		return -ENOMEM;

	return devm_reset_control_bulk_get_exclusive(dev, ufs->num_resets, ufs->resets);
}

static int ufs_tegra_parse_clock_info(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	struct ufs_clk_info *clki;

	list_for_each_entry(clki, &hba->clk_list_head, list) {
		if (!strcmp(clki->name, "core"))
			ufs->core_clk = clki->clk;

		if (!strcmp(clki->name, "uphy-pll"))
			ufs->uphy_pll_clk = clki->clk;
	}

	if (!ufs->core_clk || !ufs->uphy_pll_clk)
		return -ENODEV;

	return 0;
}

static int ufs_tegra_parse_phy_info(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	struct device *dev = hba->dev;

	ufs->mphy_l0_rx = devm_phy_get(dev, "mphy-l0-rx");
	if (IS_ERR(ufs->mphy_l0_rx))
		return PTR_ERR(ufs->mphy_l0_rx);

	ufs->mphy_l0_tx = devm_phy_get(dev, "mphy-l0-tx");
	if (IS_ERR(ufs->mphy_l0_tx))
		return PTR_ERR(ufs->mphy_l0_tx);

	ufs->mphy_l1_rx = devm_phy_get(dev, "mphy-l1-rx");
	if (IS_ERR(ufs->mphy_l1_rx))
		return PTR_ERR(ufs->mphy_l1_rx);

	ufs->mphy_l1_tx = devm_phy_get(dev, "mphy-l1-tx");
	if (IS_ERR(ufs->mphy_l1_tx))
		return PTR_ERR(ufs->mphy_l1_tx);

	return 0;
}

static void ufs_tegra_set_caps(struct ufs_hba *hba)
{
	hba->caps |= UFSHCD_CAP_INTR_AGGR;
	hba->caps |= UFSHCD_CAP_WB_EN;

	hba->spm_lvl = UFS_PM_LVL_5;
}

static void ufs_tegra_configure_aux(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	u32 value;

	value = readl(ufs->aux + UFSHC_AUX_DEV_CTRL);
	value |= DEV_CTRL_CLK_EN;
	writel(value, ufs->aux + UFSHC_AUX_DEV_CTRL);

	/* Let the reference clock stabilise before deasserting device reset. */
	usleep_range(1000, 2000);

	value |= DEV_CTRL_RESET;
	writel(value, ufs->aux + UFSHC_AUX_DEV_CTRL);
}

static void ufs_tegra_aux_init(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	u32 value;

	value = readl(ufs->aux + UFSHC_AUX_DEV_CTRL);
	value &= ~(DEV_CTRL_CLK_EN | DEV_CTRL_RESET);
	writel(value, ufs->aux + UFSHC_AUX_DEV_CTRL);

	/* Ensure the clear is observed before we re-enable. */
	usleep_range(100, 200);

	ufs_tegra_configure_aux(hba);
}

static void ufs_tegra_update_hclk_div(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	u32 core_clk_mhz;

	core_clk_mhz = clk_get_rate(ufs->core_clk) / USEC_PER_SEC;
	ufshcd_writel(hba, HCLKDIV(core_clk_mhz), DWC_UFS_REG_HCLKDIV);
}

static int ufs_tegra_init(struct ufs_hba *hba)
{
	struct platform_device *pdev = to_platform_device(hba->dev);
	struct device *dev = &pdev->dev;
	struct ufs_tegra *ufs;
	int err;

	ufs = devm_kzalloc(dev, sizeof(*ufs), GFP_KERNEL);
	if (!ufs)
		return -ENOMEM;

	ufshcd_set_variant(hba, ufs);

	err = ufs_tegra_init_resources(hba);
	if (err)
		return err;

	err = ufs_tegra_parse_clock_info(hba);
	if (err)
		return err;

	err = ufs_tegra_parse_reset_info(hba);
	if (err)
		return err;

	err = ufs_tegra_parse_phy_info(hba);
	if (err)
		return err;

	ufs_tegra_set_caps(hba);

	ufshcd_init_host_params(&ufs->host_params);
	ufs->host_params.hs_rx_gear = UFS_HS_G4;
	ufs->host_params.hs_tx_gear = UFS_HS_G4;

	err = reset_control_bulk_deassert(ufs->num_resets, ufs->resets);
	if (err)
		return err;

	ufs_tegra_aux_init(hba);
	ufs_tegra_update_hclk_div(hba);

	return 0;
}

static int ufs_tegra_mphy_init(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	int err;

	err = phy_init(ufs->mphy_l0_rx);
	if (err) {
		dev_err(hba->dev, "failed to initialize mphy-l0-rx\n");
		return err;
	}

	err = phy_init(ufs->mphy_l0_tx);
	if (err) {
		dev_err(hba->dev, "failed to initialize mphy-l0-tx\n");
		goto out_exit_l0_rx;
	}

	err = phy_init(ufs->mphy_l1_rx);
	if (err) {
		dev_err(hba->dev, "failed to initialize mphy-l1-rx\n");
		goto out_exit_l0_tx;
	}

	err = phy_init(ufs->mphy_l1_tx);
	if (err) {
		dev_err(hba->dev, "failed to initialize mphy-l1-tx\n");
		goto out_exit_l1_rx;
	}

	return 0;

out_exit_l1_rx:
	phy_exit(ufs->mphy_l1_rx);
out_exit_l0_tx:
	phy_exit(ufs->mphy_l0_tx);
out_exit_l0_rx:
	phy_exit(ufs->mphy_l0_rx);

	return err;
}

static void ufs_tegra_mphy_exit(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);

	phy_exit(ufs->mphy_l0_rx);
	phy_exit(ufs->mphy_l0_tx);
	phy_exit(ufs->mphy_l1_rx);
	phy_exit(ufs->mphy_l1_tx);
}

static int ufs_tegra_mphy_power_on(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	int err;

	err = phy_power_on(ufs->mphy_l0_rx);
	if (err) {
		dev_err(hba->dev, "failed to power on mphy-l0-rx\n");
		return err;
	}

	err = phy_power_on(ufs->mphy_l0_tx);
	if (err) {
		dev_err(hba->dev, "failed to power on mphy-l0-tx\n");
		goto out_power_off_l0_rx;
	}

	err = phy_power_on(ufs->mphy_l1_rx);
	if (err) {
		dev_err(hba->dev, "failed to power on mphy-l1-rx\n");
		goto out_power_off_l0_tx;
	}

	err = phy_power_on(ufs->mphy_l1_tx);
	if (err) {
		dev_err(hba->dev, "failed to power on mphy-l1-tx\n");
		goto out_power_off_l1_rx;
	}

	return 0;

out_power_off_l1_rx:
	phy_power_off(ufs->mphy_l1_rx);
out_power_off_l0_tx:
	phy_power_off(ufs->mphy_l0_tx);
out_power_off_l0_rx:
	phy_power_off(ufs->mphy_l0_rx);

	return err;
}

static void ufs_tegra_mphy_power_off(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);

	phy_power_off(ufs->mphy_l0_rx);
	phy_power_off(ufs->mphy_l0_tx);
	phy_power_off(ufs->mphy_l1_rx);
	phy_power_off(ufs->mphy_l1_tx);
}

static int ufs_tegra_mphy_enable(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	int err;

	if (ufs->mphy_on)
		return 0;

	err = ufs_tegra_mphy_init(hba);
	if (err)
		return err;

	err = ufs_tegra_mphy_power_on(hba);
	if (err) {
		ufs_tegra_mphy_exit(hba);
		return err;
	}

	ufs->mphy_on = true;

	/* Allow M-PHY to settle after power-on. */
	usleep_range(500, 600);

	return 0;
}

static void ufs_tegra_mphy_disable(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);

	if (!ufs->mphy_on)
		return;

	ufs_tegra_mphy_power_off(hba);
	ufs_tegra_mphy_exit(hba);

	ufs->mphy_on = false;
}

static int ufs_tegra_mphy_configure_tx(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	int err;

	err = phy_configure(ufs->mphy_l0_tx, NULL);
	if (err)
		return err;

	return phy_configure(ufs->mphy_l1_tx, NULL);
}

static int ufs_tegra_mphy_calibrate_tx(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	int err;

	err = phy_calibrate(ufs->mphy_l0_tx);
	if (err)
		return err;

	return phy_calibrate(ufs->mphy_l1_tx);
}

static int ufs_tegra_mphy_calibrate_rx(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	int err;

	err = phy_configure(ufs->mphy_l1_rx, NULL);
	if (err)
		return err;

	err = phy_configure(ufs->mphy_l0_rx, NULL);
	if (err)
		return err;

	err = phy_calibrate(ufs->mphy_l1_rx);
	if (err)
		return err;

	return phy_calibrate(ufs->mphy_l0_rx);
}

static void ufs_tegra_exit(struct ufs_hba *hba)
{
	ufs_tegra_mphy_disable(hba);
}

static int ufs_tegra_suspend(struct ufs_hba *hba, enum ufs_pm_op pm_op,
			     enum ufs_notify_change_status status)
{
	if (status == PRE_CHANGE)
		return 0;

	/* Runtime H8 park keeps the M-PHY powered; only tear it down
	 * on the full-teardown paths (system suspend, shutdown, or
	 * runtime PM with LINK_OFF).
	 */
	if (pm_op == UFS_RUNTIME_PM && !ufshcd_is_link_off(hba))
		return 0;

	ufs_tegra_mphy_disable(hba);

	if (pm_op != UFS_RUNTIME_PM)
		ufshcd_set_link_off(hba);

	return 0;
}

static int ufs_tegra_resume(struct ufs_hba *hba, enum ufs_pm_op pm_op)
{
	/* Skip when the M-PHY was left powered by the suspend path. */
	if (ufshcd_is_link_active(hba) || ufshcd_is_link_hibern8(hba))
		return 0;

	return ufs_tegra_mphy_enable(hba);
}

static int ufs_tegra_reset(struct ufs_tegra *ufs)
{
	int err;

	err = reset_control_bulk_assert(ufs->num_resets, ufs->resets);
	if (err)
		return err;

	usleep_range(100, 200);

	err = reset_control_bulk_deassert(ufs->num_resets, ufs->resets);
	if (err)
		return err;

	usleep_range(500, 600);

	return 0;
}

static int ufs_tegra_power_up_sequence(struct ufs_hba *hba)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	int err;

	err = ufs_tegra_reset(ufs);
	if (err)
		return err;

	return ufs_tegra_mphy_enable(hba);
}

static void ufs_tegra_setup(struct ufs_hba *hba)
{
	ufs_tegra_configure_aux(hba);
	ufs_tegra_update_hclk_div(hba);
	ufshcd_rmwl(hba, MBL_MASK, MBL(UFS_TEGRA_MBL_MAX), UFSHC_DWC_BLOCK_BUSTHRTL);
}

static int ufs_tegra_hce_enable_notify(struct ufs_hba *hba, enum ufs_notify_change_status status)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	u32 value;
	int err;

	switch (status) {
	case PRE_CHANGE:
		err = ufs_tegra_power_up_sequence(hba);
		if (err)
			return err;

		/* Assert device reset; POST_CHANGE releases it via
		 * ufs_tegra_configure_aux() so the HCE toggle pulses it.
		 */
		value = readl(ufs->aux + UFSHC_AUX_DEV_CTRL);
		value &= ~DEV_CTRL_RESET;
		writel(value, ufs->aux + UFSHC_AUX_DEV_CTRL);
		break;
	case POST_CHANGE:
		value = readl(ufs->aux + UFSHC_AUX_SW_EN_CLK_SLCG);
		value &= ~CLK_OVR_ON;
		writel(value, ufs->aux + UFSHC_AUX_SW_EN_CLK_SLCG);

		ufs_tegra_setup(hba);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int ufs_tegra_link_startup_notify(struct ufs_hba *hba, enum ufs_notify_change_status status)
{
	static const struct ufshcd_dme_attr_val post_change_attrs[] = {
		{ UIC_ARG_MIB(T_CONNECTIONSTATE), 0x1, DME_LOCAL },
		{ UIC_ARG_MIB(PA_TXHSG1SYNCLENGTH), UFS_TEGRA_HSG_SYNC_LEN, DME_LOCAL },
		{ UIC_ARG_MIB(PA_TXHSG2SYNCLENGTH), UFS_TEGRA_HSG_SYNC_LEN, DME_LOCAL },
		{ UIC_ARG_MIB(PA_TXHSG3SYNCLENGTH), UFS_TEGRA_HSG_SYNC_LEN, DME_LOCAL },
		{ UIC_ARG_MIB(PA_TXHSG4SYNCLENGTH), UFS_TEGRA_HSG_SYNC_LEN, DME_LOCAL },
		{ UIC_ARG_MIB(DME_LocalFC0ProtectionTimeOutVal), UFS_TEGRA_FC0_TIMEOUT, DME_LOCAL },
		{ UIC_ARG_MIB(DME_LocalTC0ReplayTimeOutVal), UFS_TEGRA_TC0_TIMEOUT, DME_LOCAL },
		{ UIC_ARG_MIB(DME_LocalAFC0ReqTimeOutVal), UFS_TEGRA_AFC0_TIMEOUT, DME_LOCAL },
		{ UIC_ARG_MIB(PA_PWRMODEUSERDATA0), UFS_TEGRA_FC0_TIMEOUT, DME_LOCAL },
		{ UIC_ARG_MIB(PA_PWRMODEUSERDATA1), UFS_TEGRA_TC0_TIMEOUT, DME_LOCAL },
		{ UIC_ARG_MIB(PA_PWRMODEUSERDATA2), UFS_TEGRA_AFC0_TIMEOUT, DME_LOCAL },
	};
	int err;

	switch (status) {
	case PRE_CHANGE:
		/* Arm TX calibration; RX capabilities are advertised in
		 * tegra_mphy_rx_power_on().
		 */
		err = ufs_tegra_mphy_configure_tx(hba);
		if (err)
			return err;
		break;

	case POST_CHANGE:
		err = ufs_tegra_mphy_calibrate_tx(hba);
		if (err)
			return err;

		err = ufshcd_dwc_dme_set_attrs(hba, post_change_attrs,
					       ARRAY_SIZE(post_change_attrs));
		if (err)
			return err;

		err = ufs_tegra_mphy_calibrate_rx(hba);
		if (err)
			return err;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static int ufs_tegra_negotiate_pwr_mode(struct ufs_hba *hba,
					const struct ufs_pa_layer_attr *dev_max_params,
					struct ufs_pa_layer_attr *dev_req_params)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);

	return ufshcd_negotiate_pwr_params(&ufs->host_params, dev_max_params, dev_req_params);
}

static int ufs_tegra_pwr_change_notify(struct ufs_hba *hba,
				       enum ufs_notify_change_status status,
				       struct ufs_pa_layer_attr *dev_req_params)
{
	struct ufs_tegra *ufs = ufshcd_get_variant(hba);
	u32 value;
	int err;

	if (status != PRE_CHANGE)
		return 0;

	err = ufshcd_dme_get(hba, UIC_ARG_MIB(VS_DEBUGSAVECONFIGTIME), &value);
	if (err)
		return err;

	value &= ~VS_DEBUGSAVECONFIGTIME_TREF;
	value |= FIELD_PREP(VS_DEBUGSAVECONFIGTIME_TREF, UFS_TEGRA_SAVECONFIGTIME_TREF);
	value &= ~VS_DEBUGSAVECONFIGTIME_SCT;
	value |= FIELD_PREP(VS_DEBUGSAVECONFIGTIME_SCT, UFS_TEGRA_SAVECONFIGTIME_SCT);

	err = ufshcd_dme_set(hba, UIC_ARG_MIB(VS_DEBUGSAVECONFIGTIME), value);
	if (err)
		return err;

	if (dev_req_params->hs_rate == PA_HS_MODE_A ||
	    dev_req_params->hs_rate == PA_HS_MODE_B) {
		err = clk_set_rate(ufs->uphy_pll_clk, UFS_TEGRA_UPHY_PLL_HS_RATE_HZ);
		if (err)
			return err;
	}

	err = ufshcd_dme_configure_adapt(hba, dev_req_params->gear_tx, PA_INITIAL_ADAPT);
	if (err)
		return err;

	return 0;
}

static int ufs_tegra_set_dma_mask(struct ufs_hba *hba)
{
	return dma_set_mask_and_coherent(hba->dev, DMA_BIT_MASK(32));
}

static const struct ufs_hba_variant_ops ufs_tegra_vops = {
	.name = "ufs-tegra",
	.init = ufs_tegra_init,
	.exit = ufs_tegra_exit,
	.suspend = ufs_tegra_suspend,
	.resume = ufs_tegra_resume,
	.hce_enable_notify = ufs_tegra_hce_enable_notify,
	.negotiate_pwr_mode = ufs_tegra_negotiate_pwr_mode,
	.pwr_change_notify = ufs_tegra_pwr_change_notify,
	.link_startup_notify = ufs_tegra_link_startup_notify,
	.set_dma_mask = ufs_tegra_set_dma_mask,
};

static int ufs_tegra_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	int err;

	err = ufshcd_pltfrm_init(pdev, &ufs_tegra_vops);
	if (err)
		return dev_err_probe(dev, err, "ufshcd platform init failed\n");

	return 0;
}

static void ufs_tegra_remove(struct platform_device *pdev)
{
	ufshcd_pltfrm_remove(pdev);
}

static const struct dev_pm_ops ufs_tegra_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(ufshcd_system_suspend, ufshcd_system_resume)
	SET_RUNTIME_PM_OPS(ufshcd_runtime_suspend, ufshcd_runtime_resume, NULL)
};

static const struct of_device_id ufs_tegra_of_match[] = {
	{ .compatible = "nvidia,tegra264-ufs" },
	{ }
};
MODULE_DEVICE_TABLE(of, ufs_tegra_of_match);

static struct platform_driver ufs_tegra_driver = {
	.probe = ufs_tegra_probe,
	.remove = ufs_tegra_remove,
	.driver = {
		.name = "ufs-tegra",
		.pm = &ufs_tegra_pm_ops,
		.of_match_table = ufs_tegra_of_match,
	},
};
module_platform_driver(ufs_tegra_driver);

MODULE_AUTHOR("Thierry Reding <treding@nvidia.com>");
MODULE_AUTHOR("Kartik Rajput <kkartik@nvidia.com>");
MODULE_DESCRIPTION("NVIDIA Tegra UFS host controller driver");
MODULE_LICENSE("GPL");
