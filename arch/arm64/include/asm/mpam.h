/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Arm Ltd. */

#ifndef __ASM__MPAM_H
#define __ASM__MPAM_H

#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/jump_label.h>

#include <asm/cpucaps.h>
#include <asm/cpufeature.h>
#include <asm/sysreg.h>

DECLARE_STATIC_KEY_FALSE(arm64_mpam_has_hcr);

/* check whether all CPUs have MPAM virtualisation support */
static inline bool mpam_cpus_have_mpam_hcr(void)
{
	if (IS_ENABLED(CONFIG_ARM64_MPAM))
		return static_branch_unlikely(&arm64_mpam_has_hcr);
	return false;
}

/* enable MPAM virtualisation support */
static inline void __init __enable_mpam_hcr(void)
{
	if (IS_ENABLED(CONFIG_ARM64_MPAM))
		static_branch_enable(&arm64_mpam_has_hcr);
}

#endif /* __ASM__MPAM_H */
