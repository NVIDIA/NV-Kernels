/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Arm Ltd. */

#include <asm/mpam.h>

#include <linux/jump_label.h>

DEFINE_STATIC_KEY_FALSE(arm64_mpam_has_hcr);
