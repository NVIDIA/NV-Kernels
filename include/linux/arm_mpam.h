// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2021 Arm Ltd.

#ifndef __LINUX_ARM_MPAM_H
#define __LINUX_ARM_MPAM_H

#include <linux/acpi.h>
#include <linux/resctrl_types.h>
#include <linux/types.h>

/*
 * The value of the MPAM1_EL1 sysreg when a task is in the default group.
 * This is used by the context switch code to use the resctrl CPU property
 * instead. The value is modified when CDP is enabled/disabled by mounting
 * the resctrl filesystem.
 */
extern u64 mpam_resctrl_default_group;

#include <asm/mpam.h>

struct mpam_msc;

enum mpam_msc_iface {
	MPAM_IFACE_MMIO,	/* a real MPAM MSC */
	MPAM_IFACE_PCC,		/* a fake MPAM MSC */
};

enum mpam_class_types {
	MPAM_CLASS_CACHE,       /* Well known caches, e.g. L2 */
	MPAM_CLASS_MEMORY,      /* Main memory */
	MPAM_CLASS_UNKNOWN,     /* Everything else, e.g. SMMU */
};

#ifdef CONFIG_ACPI_MPAM
/* Parse the ACPI description of resources entries for this MSC. */
int acpi_mpam_parse_resources(struct mpam_msc *msc,
			      struct acpi_mpam_msc_node *tbl_msc);
int acpi_mpam_count_msc(void);
#else
static inline int acpi_mpam_parse_resources(struct mpam_msc *msc,
					    struct acpi_mpam_msc_node *tbl_msc)
{
	return -EINVAL;
}
static inline int acpi_mpam_count_msc(void) { return -EINVAL; }
#endif

int mpam_register_requestor(u16 partid_max, u8 pmg_max);

int mpam_ris_create(struct mpam_msc *msc, u8 ris_idx,
		    enum mpam_class_types type, u8 class_id, int component_id);


bool resctrl_arch_alloc_capable(void);
bool resctrl_arch_mon_capable(void);
bool resctrl_arch_is_llc_occupancy_enabled(void);
bool resctrl_arch_is_mbm_local_enabled(void);

static inline bool resctrl_arch_is_mbm_total_enabled(void)
{
	return false;
}

/* reset cached configurations, then all devices */
void resctrl_arch_reset_resources(void);

bool resctrl_arch_get_cdp_enabled(enum resctrl_res_level ignored);
int resctrl_arch_set_cdp_enabled(enum resctrl_res_level ignored, bool enable);
bool resctrl_arch_match_closid(struct task_struct *tsk, u32 closid);
bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid);
void resctrl_arch_set_cpu_default_closid(int cpu, u32 closid);
void resctrl_arch_set_closid_rmid(struct task_struct *tsk, u32 closid, u32 rmid);
void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 pmg);
void resctrl_sched_in(struct task_struct *tsk);
u32 resctrl_arch_rmid_idx_encode(u32 closid, u32 rmid);
void resctrl_arch_rmid_idx_decode(u32 idx, u32 *closid, u32 *rmid);
u32 resctrl_arch_system_num_rmid_idx(void);

#endif /* __LINUX_ARM_MPAM_H */
