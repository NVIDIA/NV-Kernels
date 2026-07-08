/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 MediaTek Inc.
 *
 * Cross-driver interface into MediaTek pinctrl for programming pad
 * bias by absolute SoC GPIO number, for drivers that receive pad
 * configuration through their own ACPI resources rather than pinctrl
 * states.
 */
#ifndef __LINUX_SOC_MEDIATEK_MTK_PINCTRL_H
#define __LINUX_SOC_MEDIATEK_MTK_PINCTRL_H

#include <linux/types.h>

/* Pull-mode values accepted by mtk_pinctrl_program_bias_by_gpio(). */
#define MTK_PIN_PULLDOWN	0
#define MTK_PIN_PULLUP		1
#define MTK_PIN_BUS_HOLD	2

/* Enable/disable values accepted by mtk_pinctrl_program_bias_by_gpio(). */
#define MTK_PIN_DISABLE		0
#define MTK_PIN_ENABLE		1

/**
 * mtk_pinctrl_program_bias_by_gpio - program pad bias by absolute GPIO
 * @gpio:   absolute SoC pin number (matches the ACPI PinFunction
 *          pin_table entry).
 * @pullup: one of MTK_PIN_PULLDOWN, MTK_PIN_PULLUP, MTK_PIN_BUS_HOLD.
 * @arg:    MTK_PIN_ENABLE to apply, MTK_PIN_DISABLE to release.
 *
 * Returns 0 on success, -EPROBE_DEFER if no mtk_pinctrl instance has
 * registered yet, -EINVAL if @pullup or @arg is not one of the values
 * listed above or if more than one registered mtk_pinctrl owns @gpio,
 * -ENODEV if no registered mtk_pinctrl owns @gpio, -EOPNOTSUPP if the
 * owning controller has no bias_set_combo, or a negative error code from
 * the underlying bias operation.
 */
int mtk_pinctrl_program_bias_by_gpio(unsigned int gpio, u32 pullup, u32 arg);

#endif /* __LINUX_SOC_MEDIATEK_MTK_PINCTRL_H */
