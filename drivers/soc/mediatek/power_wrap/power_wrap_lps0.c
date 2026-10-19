// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include <linux/acpi.h>
#include <linux/bits.h>
#include <linux/device.h>
#include <linux/pm.h>

#include "power_wrap.h"

static const guid_t pwrap_lps0_guid = GUID_INIT(0x11e00d56, 0xce64, 0x47ce,
					     0x83, 0x7b, 0x1f, 0x89, 0x8f, 0x9a, 0xa4, 0x61);

enum pwrap_lps0_function {
	PWRAP_LPS0_SCREEN_OFF = 3,
	PWRAP_LPS0_SCREEN_ON = 4,
	PWRAP_LPS0_ENTRY = 5,
	PWRAP_LPS0_EXIT = 6,
	PWRAP_LPS0_MS_ENTRY = 7,
	PWRAP_LPS0_MS_EXIT = 8,
	PWRAP_LPS0_DISPLAY_ON = 9,
};

struct pwrap_lps0 {
	struct device *dev;
	u64 functions;
	bool screen_off;
	bool ms_entered;
	bool lps0_entered;
};

static int pwrap_lps0_dsm(struct pwrap_lps0 *lps0, unsigned int function)
{
	union acpi_object *obj;

	obj = acpi_evaluate_dsm(ACPI_HANDLE(lps0->dev), &pwrap_lps0_guid,
				0, function, NULL);
	/* acpi_evaluate_dsm() already reports AML evaluation failures. */
	if (!obj)
		return -EIO;
	ACPI_FREE(obj);
	return 0;
}

static void pwrap_lps0_restore(struct pwrap_lps0 *lps0)
{
	/* Keep the Microsoft LPS0 exit ordering used by ACPI on x86. */
	if (lps0->lps0_entered)
		pwrap_lps0_dsm(lps0, PWRAP_LPS0_EXIT);
	if (lps0->screen_off &&
	    (lps0->functions & BIT_ULL(PWRAP_LPS0_DISPLAY_ON)))
		pwrap_lps0_dsm(lps0, PWRAP_LPS0_DISPLAY_ON);
	if (lps0->ms_entered)
		pwrap_lps0_dsm(lps0, PWRAP_LPS0_MS_EXIT);
	if (lps0->screen_off)
		pwrap_lps0_dsm(lps0, PWRAP_LPS0_SCREEN_ON);
	lps0->lps0_entered = false;
	lps0->ms_entered = false;
	lps0->screen_off = false;
}

static void pwrap_lps0_prepare(struct pwrap_lps0 *lps0)
{
	/* AML may have side effects even when evaluating the method fails. */
	lps0->screen_off = true;
	if (pwrap_lps0_dsm(lps0, PWRAP_LPS0_SCREEN_OFF))
		goto restore;
	if (lps0->functions & BIT_ULL(PWRAP_LPS0_MS_ENTRY)) {
		lps0->ms_entered = true;
		if (pwrap_lps0_dsm(lps0, PWRAP_LPS0_MS_ENTRY))
			goto restore;
	}
	if (lps0->functions & BIT_ULL(PWRAP_LPS0_ENTRY)) {
		lps0->lps0_entered = true;
		if (pwrap_lps0_dsm(lps0, PWRAP_LPS0_ENTRY))
			goto restore;
	}
	return;

restore:
	/* Restore attempted notifications, but do not veto system suspend. */
	pwrap_lps0_restore(lps0);
}

static int pwrap_lps0_suspend_noirq(struct device *dev)
{
	struct pwrap_driver_data *priv = dev_get_drvdata(dev);

	if (priv->lps0)
		pwrap_lps0_prepare(priv->lps0);
	return 0;
}

static int pwrap_lps0_resume_noirq(struct device *dev)
{
	struct pwrap_driver_data *priv = dev_get_drvdata(dev);

	if (priv->lps0)
		pwrap_lps0_restore(priv->lps0);
	return 0;
}

/* The PM core also calls resume_noirq() when a later suspend step fails. */
const struct dev_pm_ops pwrap_lps0_pm_ops = {
	.suspend_noirq = pwrap_lps0_suspend_noirq,
	.resume_noirq = pwrap_lps0_resume_noirq,
};

int pwrap_lps0_init(struct pwrap_driver_data *priv)
{
	struct device *dev = priv->dev;
	struct pwrap_lps0 *lps0;
	u64 functions = BIT_ULL(PWRAP_LPS0_SCREEN_OFF) | BIT_ULL(PWRAP_LPS0_SCREEN_ON);
	u64 lps0_pair = BIT_ULL(PWRAP_LPS0_ENTRY) | BIT_ULL(PWRAP_LPS0_EXIT);
	u64 ms_pair = BIT_ULL(PWRAP_LPS0_MS_ENTRY) | BIT_ULL(PWRAP_LPS0_MS_EXIT);

	/*
	 * MT8901 firmware uses these notifications to arm EC lid wake for
	 * both s2idle and PSCI SYSTEM_SUSPEND. The normal LPS0 caller is x86
	 * only, so the EC otherwise delivers the lid event after another
	 * source has already resumed Linux. Use the device noirq callbacks
	 * to keep these notifications close to the sleep transition, after
	 * userspace is frozen and before CPUs go offline. The FF-A bridge
	 * uses synchronous requests and has no system-sleep callbacks that
	 * disable the transport during device suspend.
	 */
	if (priv->plid != PWRAP_PLID_MT8901) {
		dev_info(dev, "LPS0 EC sleep notifications skipped for platform id %#llx\n",
			 priv->plid);
		return 0;
	}
	if (!acpi_check_dsm(ACPI_HANDLE(dev), &pwrap_lps0_guid, 0, functions)) {
		dev_info(dev, "LPS0 EC sleep notifications disabled: screen off/on functions unavailable\n");
		return 0;
	}
	/* Other notifications are optional, but entry/exit must be paired. */
	if (acpi_check_dsm(ACPI_HANDLE(dev), &pwrap_lps0_guid, 0, lps0_pair))
		functions |= lps0_pair;
	if (acpi_check_dsm(ACPI_HANDLE(dev), &pwrap_lps0_guid, 0, ms_pair))
		functions |= ms_pair;
	if (acpi_check_dsm(ACPI_HANDLE(dev), &pwrap_lps0_guid, 0,
			   BIT_ULL(PWRAP_LPS0_DISPLAY_ON)))
		functions |= BIT_ULL(PWRAP_LPS0_DISPLAY_ON);

	lps0 = devm_kzalloc(dev, sizeof(*lps0), GFP_KERNEL);
	if (!lps0)
		return -ENOMEM;
	lps0->dev = dev;
	lps0->functions = functions;
	priv->lps0 = lps0;
	dev_info(dev, "LPS0 EC sleep notifications enabled (functions %#llx)\n",
		 functions);
	return 0;
}
