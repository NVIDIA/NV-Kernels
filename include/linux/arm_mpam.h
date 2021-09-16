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

static inline unsigned int resctrl_arch_round_mon_val(unsigned int val)
{
	return val;
}

/* MPAM counters requires a monitor to be allocated */
static inline bool resctrl_arch_event_is_free_running(enum resctrl_event_id evt)
{
	return false;
}

bool resctrl_arch_alloc_capable(void);
bool resctrl_arch_mon_capable(void);
bool resctrl_arch_is_llc_occupancy_enabled(void);
bool resctrl_arch_is_mbm_local_enabled(void);
bool resctrl_arch_is_mbm_total_enabled(void);

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

struct rdt_resource;
void *resctrl_arch_mon_ctx_alloc_no_wait(struct rdt_resource *r, int evtid);
void resctrl_arch_mon_ctx_free(struct rdt_resource *r, int evtid, void *ctx);

int resctrl_arch_set_iommu_closid_rmid(struct iommu_group *group, u32 closid,
				       u32 rmid);
bool resctrl_arch_match_iommu_closid(struct iommu_group *group, u32 closid);
bool resctrl_arch_match_iommu_closid_rmid(struct iommu_group *group, u32 closid,
					  u32 rmid);

/* Pseudo lock is not supported by MPAM */
static inline int resctrl_arch_pseudo_lock_fn(void *_plr) { return 0; }
static inline int resctrl_arch_measure_l2_residency(void *_plr) { return 0; }
static inline int resctrl_arch_measure_l3_residency(void *_plr) { return 0; }
static inline int resctrl_arch_measure_cycles_lat_fn(void *_plr) { return 0; }
static inline u64 resctrl_arch_get_prefetch_disable_bits(void) { return 0; }

/*
 * The CPU configuration for MPAM is cheap to write, and is only written if it
 * has changed. No need for fine grained enables.
 */
static inline void resctrl_arch_enable_mon(void) { }
static inline void resctrl_arch_disable_mon(void) { }
static inline void resctrl_arch_enable_alloc(void) { }
static inline void resctrl_arch_disable_alloc(void) { }

#endif /* __LINUX_ARM_MPAM_H */
