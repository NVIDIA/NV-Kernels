/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 MediaTek Inc.
 *
 * Cross-driver interface into MediaTek pinctrl for programming pad
 * bias by absolute SoC GPIO number.
 *
 * Intended for client drivers (for example mtk-soundwire) that consume
 * ACPI PinFunction() vendor encodings from their own _CRS and need to
 * apply the resulting pad bias without going through the pinctrl-state
 * machinery.
 */
#ifndef __LINUX_SOC_MEDIATEK_MTK_PINCTRL_H
#define __LINUX_SOC_MEDIATEK_MTK_PINCTRL_H

#include <linux/types.h>

/*
 * Vendor-specific pin configuration values carried in the ACPI
 * PinFunction() descriptor:
 *
 *   0x90 -> PD=1, PU=0 (plain pull-down)
 *   0xF0 -> PD=1, PU=1 (bus-keeper)
 *
 *   The Audio.asl entries look like:
 *   PinFunction(Exclusive, 0x90, 1, "\_SB.GIO0", 0, ..., ...) { 66 }
 *     // SOUNDWIRE0_CLK,  PD=1, PU=0
 *   PinFunction(Exclusive, 0xF0, 1, "\_SB.GIO0", 0, ..., ...) { 67 }
 *     // SOUNDWIRE0_DAT0, PD=1, PU=1
 */
#define MTK_SDW_PIN_CFG_PD		0x90
#define MTK_SDW_PIN_CFG_BUS_HOLD	0xF0

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
 * Returns 0 on success, -ENODEV if no registered mtk_pinctrl owns @gpio,
 * or a negative error code from the underlying bias operation.
 */
int mtk_pinctrl_program_bias_by_gpio(unsigned int gpio, u32 pullup, u32 arg);

#endif /* __LINUX_SOC_MEDIATEK_MTK_PINCTRL_H */
