// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
/*
 * Copyright (c) 2026 MediaTek Inc.
 */

/*
 * ACPI platform driver for MT8901 audio DSP devices
 */

#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>

#include <linux/soc/mediatek/mtk-pwrap.h>

#define MT8901_AUTOSUSPEND_DELAY_MS	100

struct sof_mt8901_priv {
	void *pwrap_ctrl;
};

#ifdef CONFIG_ACPI
static const struct acpi_device_id sof_mt8901_match[] = {
	{ "NVDA8301" },
	{ "NVDA8302" },
	{ "NVDA8303" },
	{ }
};
MODULE_DEVICE_TABLE(acpi, sof_mt8901_match);
#endif

static int sof_mt8901_probe(struct platform_device *pdev)
{
	const struct acpi_device_id *id;
	struct acpi_device *adev;
	struct acpi_buffer acpi_path = { ACPI_ALLOCATE_BUFFER, NULL };
	struct device *dev = &pdev->dev;
	struct sof_mt8901_priv *priv;
	acpi_status status;
	int ret;

	id = acpi_match_device(dev->driver->acpi_match_table, dev);
	if (!id) {
		dev_err(dev, "failed to match ACPI device\n");
		return -ENODEV;
	}

	dev_dbg(dev, "matched ACPI device %s\n", id->id);

	adev = ACPI_COMPANION(dev);
	if (!adev)
		return -ENODEV;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	status = acpi_get_name(adev->handle, ACPI_FULL_PATHNAME, &acpi_path);
	if (ACPI_FAILURE(status)) {
		dev_err(dev, "failed to get ACPI device path\n");
		return -EINVAL;
	}

	priv->pwrap_ctrl = mtk_pwrap_dev_probe(acpi_path.pointer);
	if (!priv->pwrap_ctrl) {
		ret = dev_err_probe(dev, -ENODEV,
				    "pwrap probe failed for %s\n",
				    (char *)acpi_path.pointer);
		kfree(acpi_path.pointer);
		return ret;
	}
	dev_dbg(dev, "pwrap probe succeeded for %s\n",
		(char *)acpi_path.pointer);

	kfree(acpi_path.pointer);
	platform_set_drvdata(pdev, priv);

	pm_runtime_set_autosuspend_delay(dev, MT8901_AUTOSUSPEND_DELAY_MS);
	pm_runtime_use_autosuspend(dev);

	ret = pm_runtime_set_active(dev);
	if (ret) {
		dev_err(dev, "failed to set runtime active (%d)\n", ret);
		pm_runtime_dont_use_autosuspend(dev);
		goto err_pwrap_remove;
	}

	pm_runtime_enable(dev);
	pm_runtime_mark_last_busy(dev);
	pm_runtime_idle(dev);

	return 0;

err_pwrap_remove:
	if (priv->pwrap_ctrl) {
		mtk_pwrap_dev_remove(priv->pwrap_ctrl);
		priv->pwrap_ctrl = NULL;
	}

	return ret;
}

static void sof_mt8901_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct sof_mt8901_priv *priv = platform_get_drvdata(pdev);
	int ret;

	/* SSPM transitions the DSP to D3 as part of abandoning the device. */
	ret = pm_runtime_resume_and_get(dev);
	if (ret < 0)
		dev_warn(dev, "failed to resume before remove (%d)\n", ret);

	pm_runtime_dont_use_autosuspend(dev);
	pm_runtime_disable(dev);

	if (priv && priv->pwrap_ctrl) {
		mtk_pwrap_dev_remove(priv->pwrap_ctrl);
		priv->pwrap_ctrl = NULL;
	}

	if (ret >= 0)
		pm_runtime_put_noidle(dev);
}

static int sof_mt8901_runtime_suspend(struct device *dev)
{
	struct sof_mt8901_priv *priv = dev_get_drvdata(dev);
	int ret;

	if (priv && priv->pwrap_ctrl) {
		ret = mtk_pwrap_dev_suspend(priv->pwrap_ctrl, 0);
		if (ret) {
			dev_err(dev, "pwrap suspend failed (%d)\n", ret);
			return ret;
		}
	}

	return 0;
}

static int sof_mt8901_runtime_resume(struct device *dev)
{
	struct sof_mt8901_priv *priv = dev_get_drvdata(dev);
	int ret;

	if (priv && priv->pwrap_ctrl) {
		ret = mtk_pwrap_dev_resume(priv->pwrap_ctrl, 0);
		if (ret) {
			dev_err(dev, "pwrap resume failed (%d)\n", ret);
			return ret;
		}
	}

	return 0;
}

static const struct dev_pm_ops sof_mt8901_pm = {
	SYSTEM_SLEEP_PM_OPS(pm_runtime_force_suspend,
			    pm_runtime_force_resume)
	RUNTIME_PM_OPS(sof_mt8901_runtime_suspend,
		       sof_mt8901_runtime_resume, NULL)
};

static struct platform_driver snd_sof_acpi_mt8901_driver = {
	.probe = sof_mt8901_probe,
	.remove = sof_mt8901_remove,
	.driver = {
		.name = "sof-audio-acpi-mt8901",
		.pm = pm_ptr(&sof_mt8901_pm),
		.acpi_match_table = ACPI_PTR(sof_mt8901_match),
	},
};
module_platform_driver(snd_sof_acpi_mt8901_driver);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("MT8901 ACPI audio DSP driver");
