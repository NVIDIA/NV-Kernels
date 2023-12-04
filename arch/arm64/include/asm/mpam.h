/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 Arm Ltd. */

#ifndef __ASM__MPAM_H
#define __ASM__MPAM_H

#include <linux/bitops.h>
#include <linux/init.h>
#include <linux/jump_label.h>
#include <linux/percpu.h>
#include <linux/sched.h>

#include <asm/cpucaps.h>
#include <asm/cpufeature.h>
#include <asm/sysreg.h>

DECLARE_STATIC_KEY_FALSE(arm64_mpam_has_hcr);
DECLARE_STATIC_KEY_FALSE(mpam_enabled);
DECLARE_PER_CPU(u64, arm64_mpam_default);
DECLARE_PER_CPU(u64, arm64_mpam_current);

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
