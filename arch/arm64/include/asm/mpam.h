/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2025 Arm Ltd. */

#ifndef __ASM__MPAM_H
#define __ASM__MPAM_H

#include <linux/bitops.h>
#include <linux/bitfield.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/percpu.h>
#include <linux/sched.h>

#include <asm/cpucaps.h>
#include <asm/cpufeature.h>
#include <asm/sysreg.h>

DECLARE_STATIC_KEY_FALSE(mpam_enabled);
DECLARE_PER_CPU(u64, arm64_mpam_default);
DECLARE_PER_CPU(u64, arm64_mpam_current);

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

	default_val = FIELD_PREP(MPAM0_EL1_PARTID_D, partid_d);
	default_val |= FIELD_PREP(MPAM0_EL1_PARTID_I, partid_i);
	default_val |= FIELD_PREP(MPAM0_EL1_PMG_D, pmg_d);
	default_val |= FIELD_PREP(MPAM0_EL1_PMG_I, pmg_i);

	WRITE_ONCE(per_cpu(arm64_mpam_default, cpu), default_val);
}

static inline void mpam_set_task_partid_pmg(struct task_struct *tsk,
					    u16 partid_d, u16 partid_i,
					    u8 pmg_d, u8 pmg_i)
{
#ifdef CONFIG_ARM64_MPAM
	u64 regval;

	regval = FIELD_PREP(MPAM0_EL1_PARTID_D, partid_d);
	regval |= FIELD_PREP(MPAM0_EL1_PARTID_I, partid_i);
	regval |= FIELD_PREP(MPAM0_EL1_PMG_D, pmg_d);
	regval |= FIELD_PREP(MPAM0_EL1_PMG_I, pmg_i);

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

static inline void mpam_thread_switch(struct task_struct *tsk)
{
	u64 oldregval;
	int cpu = smp_processor_id();
	u64 regval = mpam_get_regval(tsk);

	if (!IS_ENABLED(CONFIG_ARM64_MPAM) ||
	    !static_branch_likely(&mpam_enabled))
		return;

	if (!regval)
		regval = READ_ONCE(per_cpu(arm64_mpam_default, cpu));

	oldregval = READ_ONCE(per_cpu(arm64_mpam_current, cpu));
	if (oldregval == regval)
		return;

	/* Synchronising this write is left until the ERET to EL0 */
	write_sysreg_s(regval, SYS_MPAM0_EL1);
	WRITE_ONCE(per_cpu(arm64_mpam_current, cpu), regval);
}
#endif /* __ASM__MPAM_H */
