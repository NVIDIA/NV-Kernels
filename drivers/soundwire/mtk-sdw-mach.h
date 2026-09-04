/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MediaTek SoundWire audio machine selection (codec-combination tables).
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 */
#ifndef __MTK_SDW_MACH_H
#define __MTK_SDW_MACH_H

#include "mtk-sdw-common.h"

struct snd_soc_acpi_mach;

/* mtk-sdw-mach.c: match enumerated SoundWire peripherals against the codec-
 * combination tables; returns the machine row to spawn, or NULL.
 */
struct snd_soc_acpi_mach *mtk_sdw_machine_select(struct mtk_sdw *mst);

#endif /* __MTK_SDW_MACH_H */
