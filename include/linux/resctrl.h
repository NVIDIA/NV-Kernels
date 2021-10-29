/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RESCTRL_H
#define _RESCTRL_H

#include <linux/bitfield.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/pid.h>
#include <linux/resctrl_types.h>

#ifdef CONFIG_ARCH_HAS_CPU_RESCTRL
#include <asm/resctrl.h>
#endif

/* CLOSID, RMID value used by the default control group */
#define RESCTRL_RESERVED_CLOSID		0
#define RESCTRL_RESERVED_RMID		0

#define RESCTRL_PICK_ANY_CPU		-1

#ifdef CONFIG_PROC_CPU_RESCTRL

int proc_resctrl_show(struct seq_file *m,
		      struct pid_namespace *ns,
		      struct pid *pid,
		      struct task_struct *tsk);

#endif

/* max value for struct rdt_domain's mbps_val */
#define MBA_MAX_MBPS   U32_MAX

/*
 * Resctrl uses a u32 as a closid bitmap. The maximum closid is 128.
 */
#define RESCTRL_MAX_CLOSID		128

/*
 * Resctrl uses u32 to hold the user-space config. The maximum bitmap size is
 * 32.
 */
#define RESCTRL_MAX_CBM			32

/* The format for packing fields into the u64 'id' exposed to user-space */
#define RESCTRL_ID_CLOSID	GENMASK_ULL(31, 0)
#define RESCTRL_ID_RMID		GENMASK_ULL(63, 32)

extern unsigned int resctrl_rmid_realloc_limit;
extern unsigned int resctrl_rmid_realloc_threshold;

/*
 * Value for XORing the id presented to user-space. This is to prevent
 * user-space from depening on the layout, ensuring it is only used for passing
 * back to kernel interfaces.
 */
extern u64 resctrl_id_obsfucation;

/**
 * struct pseudo_lock_region - pseudo-lock region information
 * @s:			Resctrl schema for the resource to which this
 *			pseudo-locked region belongs
 * @closid:		The closid that this pseudo-locked region uses
 * @d:			RDT domain to which this pseudo-locked region
 *			belongs
 * @cbm:		bitmask of the pseudo-locked region
 * @lock_thread_wq:	waitqueue used to wait on the pseudo-locking thread
 *			completion
 * @thread_done:	variable used by waitqueue to test if pseudo-locking
 *			thread completed
 * @cpu:		core associated with the cache on which the setup code
 *			will be run
 * @line_size:		size of the cache lines
 * @size:		size of pseudo-locked region in bytes
 * @kmem:		the kernel memory associated with pseudo-locked region
 * @minor:		minor number of character device associated with this
 *			region
 * @debugfs_dir:	pointer to this region's directory in the debugfs
 *			filesystem
 * @pm_reqs:		Power management QoS requests related to this region
 */
struct pseudo_lock_region {
	struct resctrl_schema	*s;
	u32			closid;
	struct rdt_domain	*d;
	u32			cbm;
	wait_queue_head_t	lock_thread_wq;
	int			thread_done;
	int			cpu;
	unsigned int		line_size;
	unsigned int		size;
	void			*kmem;
	unsigned int		minor;
	struct dentry		*debugfs_dir;
	struct list_head	pm_reqs;
};

/**
 * struct resctrl_staged_config - parsed configuration to be applied
 * @new_ctrl:		new ctrl value to be loaded
 * @have_new_ctrl:	whether the user provided new_ctrl is valid
 */
struct resctrl_staged_config {
	u32			new_ctrl;
	bool			have_new_ctrl;
};

/**
 * struct rdt_domain - group of CPUs sharing a resctrl resource
 * @list:		all instances of this resource
 * @id:			unique id for this instance
 * @cpu_mask:		which CPUs share this resource
 * @rmid_busy_llc:	bitmap of which limbo RMIDs are above threshold
 * @mbm_total:		saved state for MBM total bandwidth
 * @mbm_local:		saved state for MBM local bandwidth
 * @mbm_over:		worker to periodically read MBM h/w counters
 * @cqm_limbo:		worker to periodically read CQM h/w counters
 * @mbm_work_cpu:	worker CPU for MBM h/w counters
 * @cqm_work_cpu:	worker CPU for CQM h/w counters
 * @plr:		pseudo-locked region (if any) associated with domain
 * @staged_config:	parsed configuration to be applied
 * @mbps_val:		When mba_sc is enabled, this holds the array of user
 *			specified control values for mba_sc in MBps, indexed
 *			by closid
 */
struct rdt_domain {
	struct list_head		list;
	int				id;
	struct cpumask			cpu_mask;
	unsigned long			*rmid_busy_llc;
	struct mbm_state		*mbm_total;
	struct mbm_state		*mbm_local;
	struct delayed_work		mbm_over;
	struct delayed_work		cqm_limbo;
	int				mbm_work_cpu;
	int				cqm_work_cpu;
	struct pseudo_lock_region	*plr;
	struct resctrl_staged_config	staged_config[CDP_NUM_TYPES];
	u32				*mbps_val;
};

/**
 * struct resctrl_cache - Cache allocation related data
 * @cbm_len:		Length of the cache bit mask
 * @min_cbm_bits:	Minimum number of consecutive bits to be set.
 *			The value 0 means the architecture can support
 *			zero CBM.
 * @shareable_bits:	Bitmask of shareable resource with other
 *			executing entities
 * @arch_has_sparse_bitmasks:	True if a bitmask like f00f is valid.
 * @arch_has_per_cpu_cfg:	True if QOS_CFG register for this cache
 *				level has CPU scope.
 */
struct resctrl_cache {
	unsigned int	cbm_len;
	unsigned int	min_cbm_bits;
	unsigned int	shareable_bits;
	bool		arch_has_sparse_bitmasks;
	bool		arch_has_per_cpu_cfg;
};

/**
 * enum membw_throttle_mode - System's memory bandwidth throttling mode
 * @THREAD_THROTTLE_UNDEFINED:	Not relevant to the system
 * @THREAD_THROTTLE_MAX:	Memory bandwidth is throttled at the core
 *				always using smallest bandwidth percentage
 *				assigned to threads, aka "max throttling"
 * @THREAD_THROTTLE_PER_THREAD:	Memory bandwidth is throttled at the thread
 */
enum membw_throttle_mode {
	THREAD_THROTTLE_UNDEFINED = 0,
	THREAD_THROTTLE_MAX,
	THREAD_THROTTLE_PER_THREAD,
};

/**
 * struct resctrl_membw - Memory bandwidth allocation related data
 * @min_bw:		Minimum memory bandwidth percentage user can request
 * @bw_gran:		Granularity at which the memory bandwidth is allocated
 * @delay_linear:	True if memory B/W delay is in linear scale
 * @arch_needs_linear:	True if we can't configure non-linear resources
 * @throttle_mode:	Bandwidth throttling mode when threads request
 *			different memory bandwidths
 * @mba_sc:		True if MBA software controller(mba_sc) is enabled
 * @mb_map:		Mapping of memory B/W percentage to memory B/W delay
 */
struct resctrl_membw {
	u32				min_bw;
	u32				bw_gran;
	u32				delay_linear;
	bool				arch_needs_linear;
	enum membw_throttle_mode	throttle_mode;
	bool				mba_sc;
	u32				*mb_map;
};

/**
 * struct rdt_resource - attributes of a resctrl resource
 * @rid:		The index of the resource
 * @alloc_capable:	Is allocation available on this machine
 * @mon_capable:	Is monitor feature available on this machine
 * @num_rmid:		Number of RMIDs available
 * @cache_level:	Which cache level defines scope of this resource
 * @cache:		Cache allocation related data
 * @membw:		If the component has bandwidth controls, their properties.
 * @domains:		RCU list of all domains for this resource
 * @name:		Name to use in "schemata" file.
 * @data_width:		Character width of data when displaying
 * @default_ctrl:	Specifies default cache cbm or memory B/W percent.
 * @format_str:		Per resource format string to show domain value
 * @evt_list:		List of monitoring events
 * @fflags:		flags to choose base and info files
 * @cdp_capable:	Is the CDP feature available on this resource
 */
struct rdt_resource {
	int			rid;
	bool			alloc_capable;
	bool			mon_capable;
	int			num_rmid;
	int			cache_level;
	struct resctrl_cache	cache;
	struct resctrl_membw	membw;
	struct list_head	domains;
	char			*name;
	int			data_width;
	u32			default_ctrl;
	const char		*format_str;
	struct list_head	evt_list;
	unsigned long		fflags;
	bool			cdp_capable;
};

/*
 * Get the resource that exists at this level. If the level is not supproted
 * a dummy/not-capable resource can be returned. Levels >= RDT_NUM_RESOURCES
 * will return NULL.
 */
struct rdt_resource *resctrl_arch_get_resource(enum resctrl_res_level l);

/**
 * struct resctrl_schema - configuration abilities of a resource presented to
 *			   user-space
 * @list:	Member of resctrl_schema_all.
 * @name:	The name to use in the "schemata" file.
 * @conf_type:	Whether this schema is specific to code/data.
 * @res:	The resource structure exported by the architecture to describe
 *		the hardware that is configured by this schema.
 * @num_closid:	The number of closid that can be used with this schema. When
 *		features like CDP are enabled, this will be lower than the
 *		hardware supports for the resource.
 */
struct resctrl_schema {
	struct list_head		list;
	char				name[8];
	enum resctrl_conf_type		conf_type;
	struct rdt_resource		*res;
	u32				num_closid;
};

/*
 * Wait-queue for tasks waiting for a monitoring context to become available.
 */
extern struct wait_queue_head resctrl_mon_ctx_waiters;

struct resctrl_cpu_sync
{
	u32 closid;
	u32 rmid;
};

struct resctrl_mon_config_info {
	struct rdt_resource *r;
	struct rdt_domain   *d;
	u32                  evtid;
	u32                  mon_config;

	int                  err;
};

/*
 * Update and re-load this CPUs defaults. Called via IPI, takes a pointer to
 * struct resctrl_cpu_sync, or NULL.
 */
void resctrl_arch_sync_cpu_defaults(void *info);

/**
 * resctrl_id_encode() - pack a closid and rmid into a u64 that can be used
 *                      to identify a rdtgroup.
 * @closid:    The closid to encode.
 * @rmid:      The rmid to encode.
 */
static inline u64 resctrl_id_encode(u32 closid, u32 rmid)
{
	u64 id;

	id = FIELD_PREP(RESCTRL_ID_CLOSID, closid) |
	     FIELD_PREP(RESCTRL_ID_RMID, rmid);

	return id ^ resctrl_id_obsfucation;
}

/**
 * __resctrl_id_decode() - unpack a known-good id that has been checked by
 *                         resctrl_id_decode().
 * @id:		The value originally passed by user-space.
 * @closid:	Returned closid.
 * @rmid:	Returned rmid.
 *
 * Decodes the id field with no error checking. resctrl_id_decode() must have
 * been used to check the id produces values that are in range and are
 * allocated at the time of first use.
 */
static inline void __resctrl_id_decode(u64 id, u32 *closid, u32 *rmid)
{
	id ^= resctrl_id_obsfucation;

	*closid = FIELD_GET(RESCTRL_ID_CLOSID, id);
	*rmid = FIELD_GET(RESCTRL_ID_RMID, id);
}

/**
 * resctrl_id_decode() - unpack an id passed by user-space.
 * @id:		The value passed by user-space.
 * @closid:	Returned closid.
 * @rmid:	Returned rmid.
 *
 * Returns -EINVAL if @id doesn't correspond to an allocated control
 * or monitor group. Returns 0 on success.
 *
 * Takes a mutex, call in process context.
 */
int resctrl_id_decode(u64 id, u32 *closid, u32 *rmid);

/* The number of closid supported by this resource regardless of CDP */
u32 resctrl_arch_get_num_closid(struct rdt_resource *r);

struct rdt_domain *resctrl_arch_find_domain(struct rdt_resource *r, int id);
int resctrl_arch_update_domains(struct rdt_resource *r, u32 closid);

bool resctrl_arch_is_evt_configurable(enum resctrl_event_id evt);
void resctrl_arch_mon_event_config_write(void *info);
void resctrl_arch_mon_event_config_read(void *info);

/* For use by arch code that needs to remap resctrl's smaller CDP closid */
static inline u32 resctrl_get_config_index(u32 closid,
					   enum resctrl_conf_type type)
{
	switch (type) {
	default:
	case CDP_NONE:
		return closid;
	case CDP_CODE:
			return (closid * 2) + 1;
	case CDP_DATA:
			return (closid * 2);
	}
}

/*
 * Caller must be in a RCU read-side critical section, or hold the
 * cpuhp read lock to prevent the struct rdt_domain being freed.
 */
static inline struct rdt_domain *
resctrl_get_domain_from_cpu(int cpu, struct rdt_resource *r)
{
	struct rdt_domain *d;

	list_for_each_entry_rcu(d, &r->domains, list) {
		/* Find the domain that contains this CPU */
		if (cpumask_test_cpu(cpu, &d->cpu_mask))
			return d;
	}

	return NULL;
}

/*
 * Update the ctrl_val and apply this config right now.
 * Must be called on one of the domain's CPUs.
 */
int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_domain *d,
			    u32 closid, enum resctrl_conf_type t, u32 cfg_val);

u32 resctrl_arch_get_config(struct rdt_resource *r, struct rdt_domain *d,
			    u32 closid, enum resctrl_conf_type type);
int resctrl_online_domain(struct rdt_resource *r, struct rdt_domain *d);
void resctrl_offline_domain(struct rdt_resource *r, struct rdt_domain *d);
int resctrl_online_cpu(unsigned int cpu);
void resctrl_offline_cpu(unsigned int cpu);

/**
 * resctrl_arch_mon_ctx_alloc() - Allocate architecture specific resources need
 * 				  to use the monitors. This might sleep.
 * @r:			resource that will be used to read the counter.
 * @evtid:		the event that will be read, e.g. L3 occupancy.
 *
 * Call from process context, this might sleep until a context becomes
 * available.
 */
void *resctrl_arch_mon_ctx_alloc(struct rdt_resource *r, int evtid);

/**
 * resctrl_arch_rmid_read() - Read the eventid counter corresponding to rmid
 *			      for this resource and domain.
 * @r:			resource that the counter should be read from.
 * @d:			domain that the counter should be read from.
 * @closid:		closid that matches the rmid. Depending on the architecture, the
 *			counter may match traffic of both @closid and @rmid, or @rmid
 *			only.
 * @rmid:		rmid of the counter to read.
 * @eventid:		eventid to read, e.g. L3 occupancy.
 * @val:		result of the counter read in bytes.
 * @arch_mon_ctx:	An architecture specific value from
 *			resctrl_arch_mon_ctx_alloc(), for MPAM this identifies
 *			the hardware monitor allocated for this read request.
 *
 * Some architectures need to sleep when first programming some of the counters.
 * (specifically: arm64's MPAM cache occupancy counters can return 'not ready'
 *  for a short period of time). Call from a non-migrateable process context on
 * a CPU that belongs to domain @d. e.g. use smp_call_on_cpu() or
 * schedule_work_on(). This function can be called with interrupts masked,
 * e.g. using smp_call_function_any(), but may consistently return an error.
 *
 * Return:
 * 0 on success, or -EIO, -EINVAL etc on error.
 */
int resctrl_arch_rmid_read(struct rdt_resource *r, struct rdt_domain *d,
			   u32 closid, u32 rmid, enum resctrl_event_id eventid,
			   u64 *val, void *arch_mon_ctx);

/**
 * resctrl_arch_rmid_read_context_check()  - warn about invalid contexts
 *
 * When built with CONFIG_DEBUG_ATOMIC_SLEEP generate a warning when
 * resctrl_arch_rmid_read() is called with preemption disabled.
 */
static inline void resctrl_arch_rmid_read_context_check(void)
{
	if (!irqs_disabled())
		might_sleep();
}

/**
 * resctrl_arch_reset_rmid() - Reset any private state associated with rmid
 *			       and eventid.
 * @r:		The domain's resource.
 * @d:		The rmid's domain.
 * @closid:	closid that matches the rmid. Depending on the architecture, the
 *		counter may match traffic of both @closid and @rmid, or @rmid only.
 * @rmid:	The rmid whose counter values should be reset.
 * @eventid:	The eventid whose counter values should be reset.
 *
 * This can be called from any CPU.
 */
void resctrl_arch_reset_rmid(struct rdt_resource *r, struct rdt_domain *d,
			     u32 closid, u32 rmid,
			     enum resctrl_event_id eventid);

/**
 * resctrl_arch_reset_rmid_all() - Reset all private state associated with
 *				   all rmids and eventids.
 * @r:		The resctrl resource.
 * @d:		The domain for which all architectural counter state will
 *		be cleared.
 *
 * This can be called from any CPU.
 */
void resctrl_arch_reset_rmid_all(struct rdt_resource *r, struct rdt_domain *d);

extern unsigned int resctrl_rmid_realloc_threshold;
extern unsigned int resctrl_rmid_realloc_limit;

int resctrl_init(void);
void resctrl_exit(void);

#endif /* _RESCTRL_H */
