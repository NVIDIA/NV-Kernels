/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FS_RESCTRL_INTERNAL_H
#define _FS_RESCTRL_INTERNAL_H

#include <linux/resctrl.h>
#include <linux/sched.h>
#include <linux/kernfs.h>
#include <linux/fs_context.h>
#include <linux/jump_label.h>
#include <linux/tick.h>

#include <asm/resctrl.h>

/**
 * cpumask_any_housekeeping() - Choose any CPU in @mask, preferring those that
 *			        aren't marked nohz_full
 * @mask:	The mask to pick a CPU from.
 *
 * Returns a CPU in @mask. If there are housekeeping CPUs that don't use
 * nohz_full, these are preferred.
 */
static inline unsigned int cpumask_any_housekeeping(const struct cpumask *mask)
{
	unsigned int cpu, hk_cpu;

	cpu = cpumask_any(mask);
	if (tick_nohz_full_cpu(cpu)) {
		hk_cpu = cpumask_nth_andnot(0, mask, tick_nohz_full_mask);
		if (hk_cpu < nr_cpu_ids)
			cpu = hk_cpu;
	}

	return cpu;
}

/**
 * cpumask_any_housekeeping_but() - Chose any cpu in @mask, preferring those
 *			            that aren't marked nohz_full, excluding
 *				    the provided CPU
 * @mask:	The mask to pick a CPU from.
 * @exclude_cpu:The CPU to avoid picking.
 *
 * Returns a CPU from @mask, but not @but. If there are housekeeping CPUs that
 * don't use nohz_full, these are preferred.
 * Returns >= nr_cpu_ids if no CPUs are available.
 */
static inline unsigned int
cpumask_any_housekeeping_but(const struct cpumask *mask, int exclude_cpu)
{
	unsigned int cpu, hk_cpu;

	cpu = cpumask_any_but(mask, exclude_cpu);
	if (!tick_nohz_full_cpu(cpu))
		return cpu;

	hk_cpu = cpumask_nth_andnot(0, mask, tick_nohz_full_mask);
	if  (hk_cpu == exclude_cpu)
		hk_cpu = cpumask_nth_andnot(1, mask, tick_nohz_full_mask);

	if (hk_cpu < nr_cpu_ids)
		cpu = hk_cpu;

	return cpu;
}

struct rdt_fs_context {
	struct kernfs_fs_context	kfc;
	bool				enable_cdpl2;
	bool				enable_cdpl3;
	bool				enable_mba_mbps;
	bool				enable_abi_playground;
};

static inline struct rdt_fs_context *rdt_fc2context(struct fs_context *fc)
{
	struct kernfs_fs_context *kfc = fc->fs_private;

	return container_of(kfc, struct rdt_fs_context, kfc);
}

/**
 * struct mon_evt - Entry in the event list of a resource
 * @evtid:		event id
 * @name:		name of the event
 * @configurable:	true if the event is configurable
 * @list:		entry in &rdt_resource->evt_list
 */
struct mon_evt {
	enum resctrl_event_id	evtid;
	char			*name;
	bool			configurable;
	struct list_head	list;
};

/**
 * union mon_data_bits - Monitoring details for each event file
 * @priv:              Used to store monitoring event data in @u
 *                     as kernfs private data
 * @rid:               Resource id associated with the event file
 * @evtid:             Event id associated with the event file
 * @domid:             The domain to which the event file belongs
 * @u:                 Name of the bit fields struct
 */
union mon_data_bits {
	void *priv;
	struct {
		unsigned int rid		: 10;
		enum resctrl_event_id evtid	: 8;
		unsigned int domid		: 14;
	} u;
};

struct rmid_read {
	struct rdtgroup		*rgrp;
	struct rdt_resource	*r;
	struct rdt_domain	*d;
	enum resctrl_event_id	evtid;
	bool			first;
	int			err;
	u64			val;
	void			*arch_mon_ctx;
};

extern struct list_head resctrl_schema_all;
extern bool resctrl_mounted;

enum rdt_group_type {
	RDTCTRL_GROUP = 0,
	RDTMON_GROUP,
	RDT_NUM_GROUP,
};

/**
 * enum rdtgrp_mode - Mode of a RDT resource group
 * @RDT_MODE_SHAREABLE: This resource group allows sharing of its allocations
 * @RDT_MODE_EXCLUSIVE: No sharing of this resource group's allocations allowed
 * @RDT_MODE_PSEUDO_LOCKSETUP: Resource group will be used for Pseudo-Locking
 * @RDT_MODE_PSEUDO_LOCKED: No sharing of this resource group's allocations
 *                          allowed AND the allocations are Cache Pseudo-Locked
 * @RDT_NUM_MODES: Total number of modes
 *
 * The mode of a resource group enables control over the allowed overlap
 * between allocations associated with different resource groups (classes
 * of service). User is able to modify the mode of a resource group by
 * writing to the "mode" resctrl file associated with the resource group.
 *
 * The "shareable", "exclusive", and "pseudo-locksetup" modes are set by
 * writing the appropriate text to the "mode" file. A resource group enters
 * "pseudo-locked" mode after the schemata is written while the resource
 * group is in "pseudo-locksetup" mode.
 */
enum rdtgrp_mode {
	RDT_MODE_SHAREABLE = 0,
	RDT_MODE_EXCLUSIVE,
	RDT_MODE_PSEUDO_LOCKSETUP,
	RDT_MODE_PSEUDO_LOCKED,

	/* Must be last */
	RDT_NUM_MODES,
};

/**
 * struct mongroup - store mon group's data in resctrl fs.
 * @mon_data_kn:		kernfs node for the mon_data directory
 * @parent:			parent rdtgrp
 * @crdtgrp_list:		child rdtgroup node list
 * @rmid:			rmid for this rdtgroup
 */
struct mongroup {
	struct kernfs_node	*mon_data_kn;
	struct rdtgroup		*parent;
	struct list_head	crdtgrp_list;
	u32			rmid;
};

/**
 * struct rdtgroup - store rdtgroup's data in resctrl file system.
 * @kn:				kernfs node
 * @rdtgroup_list:		linked list for all rdtgroups
 * @closid:			closid for this rdtgroup
 * @cpu_mask:			CPUs assigned to this rdtgroup
 * @flags:			status bits
 * @waitcount:			how many cpus expect to find this
 *				group when they acquire rdtgroup_mutex
 * @type:			indicates type of this rdtgroup - either
 *				monitor only or ctrl_mon group
 * @mon:			mongroup related data
 * @mode:			mode of resource group
 * @plr:			pseudo-locked region
 */
struct rdtgroup {
	struct kernfs_node		*kn;
	struct list_head		rdtgroup_list;
	u32				closid;
	struct cpumask			cpu_mask;
	int				flags;
	atomic_t			waitcount;
	enum rdt_group_type		type;
	struct mongroup			mon;
	enum rdtgrp_mode		mode;
	struct pseudo_lock_region	*plr;
};

/* List of all resource groups */
extern struct list_head rdt_all_groups;

extern int max_name_width, max_data_width;

/**
 * struct rftype - describe each file in the resctrl file system
 * @name:	File name
 * @mode:	Access mode
 * @kf_ops:	File operations
 * @flags:	File specific RFTYPE_FLAGS_* flags
 * @fflags:	File specific RF_* or RFTYPE_* flags
 * @seq_show:	Show content of the file
 * @write:	Write to the file
 */
struct rftype {
	char			*name;
	umode_t			mode;
	const struct kernfs_ops	*kf_ops;
	unsigned long		flags;
	unsigned long		fflags;

	int (*seq_show)(struct kernfs_open_file *of,
			struct seq_file *sf, void *v);
	/*
	 * write() is the generic write callback which maps directly to
	 * kernfs write operation and overrides all other operations.
	 * Maximum write size is determined by ->max_write_len.
	 */
	ssize_t (*write)(struct kernfs_open_file *of,
			 char *buf, size_t nbytes, loff_t off);
};

/**
 * struct mbm_state - status for each MBM counter in each domain
 * @prev_bw_bytes: Previous bytes value read for bandwidth calculation
 * @prev_bw:	The most recent bandwidth in MBps
 * @delta_bw:	Difference between the current and previous bandwidth
 * @delta_comp:	Indicates whether to compute the delta_bw
 */
struct mbm_state {
	u64	prev_bw_bytes;
	u32	prev_bw;
	u32	delta_bw;
	bool	delta_comp;
};

static inline  bool is_mba_sc(struct rdt_resource *r)
{
	if (!r)
		r = resctrl_arch_get_resource(RDT_RESOURCE_MBA);

	/*
	 * The software controller support is only applicable to MBA resource.
	 * Make sure to check for resource type.
	 */
	if (r->rid != RDT_RESOURCE_MBA)
		return false;

	return r->membw.mba_sc;
}

DECLARE_STATIC_KEY_FALSE(resctrl_abi_playground);

extern struct mutex rdtgroup_mutex;
extern struct rdtgroup rdtgroup_default;
extern struct dentry *debugfs_resctrl;

void rdt_last_cmd_clear(void);
void rdt_last_cmd_puts(const char *s);
__printf(1, 2)
void rdt_last_cmd_printf(const char *fmt, ...);

struct rdtgroup *rdtgroup_kn_lock_live(struct kernfs_node *kn);
void rdtgroup_kn_unlock(struct kernfs_node *kn);
int rdtgroup_kn_mode_restrict(struct rdtgroup *r, const char *name);
int rdtgroup_kn_mode_restore(struct rdtgroup *r, const char *name,
			     umode_t mask);
ssize_t rdtgroup_schemata_write(struct kernfs_open_file *of,
				char *buf, size_t nbytes, loff_t off);
int rdtgroup_schemata_show(struct kernfs_open_file *of,
			   struct seq_file *s, void *v);
bool rdtgroup_cbm_overlaps(struct resctrl_schema *s, struct rdt_domain *d,
			   unsigned long cbm, int closid, bool exclusive);
unsigned int rdtgroup_cbm_to_size(struct rdt_resource *r, struct rdt_domain *d,
				  unsigned long cbm);
enum rdtgrp_mode rdtgroup_mode_by_closid(int closid);
int rdtgroup_tasks_assigned(struct rdtgroup *r);
int rdtgroup_locksetup_enter(struct rdtgroup *rdtgrp);
int rdtgroup_locksetup_exit(struct rdtgroup *rdtgrp);
bool rdtgroup_cbm_overlaps_pseudo_locked(struct rdt_domain *d, unsigned long cbm);
bool rdtgroup_pseudo_locked_in_hierarchy(struct rdt_domain *d);
int rdt_pseudo_lock_init(void);
void rdt_pseudo_lock_release(void);
int rdtgroup_pseudo_lock_create(struct rdtgroup *rdtgrp);
void rdtgroup_pseudo_lock_remove(struct rdtgroup *rdtgrp);
int closids_supported(void);
bool closid_allocated(unsigned int closid);
bool resctrl_closid_is_dirty(u32 closid);
void closid_free(int closid);
int alloc_rmid(u32 closid);
void free_rmid(u32 closid, u32 rmid);
void mon_event_count(void *info);
int rdtgroup_mondata_show(struct seq_file *m, void *arg);
void mon_event_read(struct rmid_read *rr, struct rdt_resource *r,
		    struct rdt_domain *d, struct rdtgroup *rdtgrp,
		    int evtid, int first);
int resctrl_mon_resource_init(void);
void mbm_setup_overflow_handler(struct rdt_domain *dom,
				unsigned long delay_ms,
				int exclude_cpu);
void mbm_handle_overflow(struct work_struct *work);
void setup_default_ctrlval(struct rdt_resource *r, u32 *dc);
void cqm_setup_limbo_handler(struct rdt_domain *dom, unsigned long delay_ms,
			     int exclude_cpu);
void cqm_handle_limbo(struct work_struct *work);
bool has_busy_rmid(struct rdt_domain *d);
void __check_limbo(struct rdt_domain *d, bool force_free);
void mbm_config_rftype_init(const char *config);
void rdt_staged_configs_clear(void);
bool resctrl_closid_is_free(u32 closid);
int resctrl_find_cleanest_closid(void);

void resctrl_cgroup_relabel_task(struct task_struct *task, u32 closid, u32 rmid, struct cpumask *dirty_cpus);
void resctrl_sync_task(void *task);

#endif /* _FS_RESCTRL_INTERNAL_H */
