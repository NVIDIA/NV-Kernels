/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Arm Ltd. */

#include <asm/mpam.h>

#include <linux/arm_mpam.h>
#include <linux/jump_label.h>

DEFINE_STATIC_KEY_FALSE(arm64_mpam_has_hcr);

static int __init arm64_mpam_register_cpus(void)
{
	u64 mpamidr = read_sanitised_ftr_reg(SYS_MPAMIDR_EL1);
	u16 partid_max = FIELD_GET(MPAMIDR_PARTID_MAX, mpamidr);
	u8 pmg_max = FIELD_GET(MPAMIDR_PMG_MAX, mpamidr);

	return mpam_register_requestor(partid_max, pmg_max);
}
arch_initcall(arm64_mpam_register_cpus)
