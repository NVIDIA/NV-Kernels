/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Arm Ltd. */

#ifndef __ASM__MPAM_H
#define __ASM__MPAM_H

#include <linux/arm_mpam.h>
#include <linux/bitops.h>
#include <linux/bitfield.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/percpu.h>
#include <linux/sched.h>

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
DECLARE_STATIC_KEY_FALSE(mpam_enabled);
DECLARE_PER_CPU(u64, arm64_mpam_default);
DECLARE_PER_CPU(u64, arm64_mpam_current);

/* check whether all CPUs have MPAM support */
static __always_inline bool mpam_cpus_have_feature(void)
{
	if (IS_ENABLED(CONFIG_ARM64_MPAM))
		return cpus_have_final_cap(ARM64_MPAM);
	return false;
}

/* check whether all CPUs have MPAM virtualisation support */
static __always_inline bool mpam_cpus_have_mpam_hcr(void)
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

/*
 * The resctrl filesystem writes to the partid/pmg values for threads and CPUs,
 * which may race with reads in __mpam_sched_in(). Ensure only one of the old
 * or new values are used. Particular care should be taken with the pmg field
 * as __mpam_sched_in() may read a partid and pmg that don't match, causing
 * this value to be stored with cache allocations, despite being considered
 * 'free' by resctrl.
 *
 * A value in struct thread_info is used instead of struct task_struct as the
 * cpu's u64 register format is used, but struct task_struct has two u32'.
 */
 static inline void mpam_set_cpu_defaults(int cpu, u16 partid_d, u16 partid_i,
					  u8 pmg_d, u8 pmg_i)
{
	u64 default_val;

	default_val = FIELD_PREP(MPAM_SYSREG_PARTID_D, partid_d);
	default_val |= FIELD_PREP(MPAM_SYSREG_PARTID_I, partid_i);
	default_val |= FIELD_PREP(MPAM_SYSREG_PMG_D, pmg_d);
	default_val |= FIELD_PREP(MPAM_SYSREG_PMG_I, pmg_i);

	WRITE_ONCE(per_cpu(arm64_mpam_default, cpu), default_val);
}

static inline void mpam_set_task_partid_pmg(struct task_struct *tsk,
					    u16 partid_d, u16 partid_i,
					    u8 pmg_d, u8 pmg_i)
{
#ifdef CONFIG_ARM64_MPAM
	u64 regval;

	regval = FIELD_PREP(MPAM_SYSREG_PARTID_D, partid_d);
	regval |= FIELD_PREP(MPAM_SYSREG_PARTID_I, partid_i);
	regval |= FIELD_PREP(MPAM_SYSREG_PMG_D, pmg_d);
	regval |= FIELD_PREP(MPAM_SYSREG_PMG_I, pmg_i);

	WRITE_ONCE(task_thread_info(tsk)->mpam_partid_pmg, regval);
#endif
}

static inline u64 mpam_get_regval(struct task_struct *tsk)
{
#ifdef CONFIG_ARM64_MPAM
	return READ_ONCE(task_thread_info(tsk)->mpam_partid_pmg);
#else
	return 0;
#endif
}

static inline void resctrl_arch_set_rmid(struct task_struct *tsk, u32 rmid)
{
#ifdef CONFIG_ARM64_MPAM
	u64 regval = mpam_get_regval(tsk);

	regval &= ~MPAM_SYSREG_PMG_D;
	regval &= ~MPAM_SYSREG_PMG_I;
	regval |= FIELD_PREP(MPAM_SYSREG_PMG_D, rmid);
	regval |= FIELD_PREP(MPAM_SYSREG_PMG_I, rmid);

	WRITE_ONCE(task_thread_info(tsk)->mpam_partid_pmg, regval);
#endif
}

static inline void mpam_thread_switch(struct task_struct *tsk)
{
	u64 oldregval;
	int cpu = smp_processor_id();
	u64 regval = mpam_get_regval(tsk);

	if (!IS_ENABLED(CONFIG_ARM64_MPAM) ||
	    !static_branch_likely(&mpam_enabled))
		return;

	if (regval == READ_ONCE(mpam_resctrl_default_group))
		regval = READ_ONCE(per_cpu(arm64_mpam_default, cpu));

	oldregval = READ_ONCE(per_cpu(arm64_mpam_current, cpu));
	if (oldregval == regval)
		return;

	/* Synchronising this write is left until the ERET to EL0 */
	write_sysreg_s(regval, SYS_MPAM0_EL1);
	WRITE_ONCE(per_cpu(arm64_mpam_current, cpu), regval);
}
#endif /* __ASM__MPAM_H */
