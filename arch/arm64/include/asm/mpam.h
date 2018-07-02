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

/* CPU Registers */
#define MPAM_SYSREG_EN			BIT_ULL(63)
#define MPAM_SYSREG_TRAP_IDR		BIT_ULL(58)
#define MPAM_SYSREG_TRAP_MPAM0_EL1	BIT_ULL(49)
#define MPAM_SYSREG_TRAP_MPAM1_EL1	BIT_ULL(48)
#define MPAM_SYSREG_PMG_D		GENMASK(47, 40)
#define MPAM_SYSREG_PMG_I		GENMASK(39, 32)
#define MPAM_SYSREG_PARTID_D		GENMASK(31, 16)
#define MPAM_SYSREG_PARTID_I		GENMASK(15, 0)

#define MPAMIDR_PMG_MAX			GENMASK(40, 32)
#define MPAMIDR_PMG_MAX_SHIFT		32
#define MPAMIDR_PMG_MAX_LEN		8
#define MPAMIDR_VPMR_MAX		GENMASK(20, 18)
#define MPAMIDR_VPMR_MAX_SHIFT		18
#define MPAMIDR_VPMR_MAX_LEN		3
#define MPAMIDR_HAS_HCR			BIT(17)
#define MPAMIDR_HAS_HCR_SHIFT		17
#define MPAMIDR_PARTID_MAX		GENMASK(15, 0)
#define MPAMIDR_PARTID_MAX_SHIFT	0
#define MPAMIDR_PARTID_MAX_LEN		15

#define MPAMHCR_EL0_VPMEN		BIT_ULL(0)
#define MPAMHCR_EL1_VPMEN		BIT_ULL(1)
#define MPAMHCR_GSTAPP_PLK		BIT_ULL(8)
#define MPAMHCR_TRAP_MPAMIDR		BIT_ULL(31)

/* Properties of the VPM registers */
#define MPAM_VPM_NUM_REGS		8
#define MPAM_VPM_PARTID_LEN		16
#define MPAM_VPM_PARTID_MASK		0xffff
#define MPAM_VPM_REG_LEN		64
#define MPAM_VPM_PARTIDS_PER_REG	(MPAM_VPM_REG_LEN / MPAM_VPM_PARTID_LEN)
#define MPAM_VPM_MAX_PARTID		(MPAM_VPM_NUM_REGS * MPAM_VPM_PARTIDS_PER_REG)


DECLARE_STATIC_KEY_FALSE(arm64_mpam_has_hcr);

/* check whether all CPUs have MPAM support */
static inline bool mpam_cpus_have_feature(void)
{
	if (IS_ENABLED(CONFIG_ARM64_MPAM))
		return cpus_have_final_cap(ARM64_MPAM);
	return false;
}

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
