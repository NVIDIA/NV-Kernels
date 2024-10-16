/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_RESCTRL_INTERNAL_H
#define _ASM_X86_RESCTRL_INTERNAL_H

#include <linux/atomic.h>
#include <linux/resctrl.h>
#include <linux/sched.h>
#include <linux/kernfs.h>
#include <linux/fs_context.h>
#include <linux/jump_label.h>
#include <linux/tick.h>
#include <asm/resctrl.h>

#define L3_QOS_CDP_ENABLE		0x01ULL

#define L2_QOS_CDP_ENABLE		0x01ULL

#define MAX_MBA_BW_AMD			0x800
#define MBM_CNTR_WIDTH_OFFSET_AMD	20

#define RMID_VAL_ERROR			BIT_ULL(63)
#define RMID_VAL_UNAVAIL		BIT_ULL(62)
/*
 * With the above fields in use 62 bits remain in MSR_IA32_QM_CTR for
 * data to be returned. The counter width is discovered from the hardware
 * as an offset from MBM_CNTR_WIDTH_BASE.
 */
#define MBM_CNTR_WIDTH_OFFSET_MAX (62 - MBM_CNTR_WIDTH_BASE)

/**
 * struct arch_mbm_state - values used to compute resctrl_arch_rmid_read()s
 *			   return value.
 * @chunks:	Total data moved (multiply by rdt_group.mon_scale to get bytes)
 * @prev_msr:	Value of IA32_QM_CTR last time it was read for the RMID used to
 *		find this struct.
 */
struct arch_mbm_state {
	atomic64_t	chunks;
	atomic64_t	prev_msr;
};

/**
 * struct rdt_hw_domain - Arch private attributes of a set of CPUs that share
 *			  a resource
 * @d_resctrl:	Properties exposed to the resctrl file system
 * @ctrl_val:	array of cache or mem ctrl values (indexed by CLOSID)
 * @arch_mbm_total:	arch private state for MBM total bandwidth
 * @arch_mbm_local:	arch private state for MBM local bandwidth
 *
 * Members of this structure are accessed via helpers that provide abstraction.
 */
struct rdt_hw_domain {
	struct rdt_domain		d_resctrl;
	u32				*ctrl_val;
	struct arch_mbm_state		*arch_mbm_total;
	struct arch_mbm_state		*arch_mbm_local;
};

static inline struct rdt_hw_domain *resctrl_to_arch_dom(struct rdt_domain *r)
{
	return container_of(r, struct rdt_hw_domain, d_resctrl);
}

/**
 * struct msr_param - set a range of MSRs from a domain
 * @res:       The resource to use
 * @low:       Beginning index from base MSR
 * @high:      End index
 */
struct msr_param {
	struct rdt_resource	*res;
	u32			low;
	u32			high;
};

static inline bool is_llc_occupancy_enabled(void)
{
	return (rdt_mon_features & (1 << QOS_L3_OCCUP_EVENT_ID));
}

static inline bool is_mbm_event(int e)
{
	return (e >= QOS_L3_MBM_TOTAL_EVENT_ID &&
		e <= QOS_L3_MBM_LOCAL_EVENT_ID);
}

/**
 * struct rdt_hw_resource - arch private attributes of a resctrl resource
 * @r_resctrl:		Attributes of the resource used directly by resctrl.
 * @num_closid:		Maximum number of closid this hardware can support,
 *			regardless of CDP. This is exposed via
 *			resctrl_arch_get_num_closid() to avoid confusion
 *			with struct resctrl_schema's property of the same name,
 *			which has been corrected for features like CDP.
 * @msr_base:		Base MSR address for CBMs
 * @msr_update:		Function pointer to update QOS MSRs
 * @mon_scale:		cqm counter * mon_scale = occupancy in bytes
 * @mbm_width:		Monitor width, to detect and correct for overflow.
 * @mbm_cfg_mask:	Bandwidth sources that can be tracked when Bandwidth
 *			Monitoring Event Configuration (BMEC) is supported.
 * @cdp_enabled:	CDP state of this resource
 *
 * Members of this structure are either private to the architecture
 * e.g. mbm_width, or accessed via helpers that provide abstraction. e.g.
 * msr_update and msr_base.
 */
struct rdt_hw_resource {
	struct rdt_resource	r_resctrl;
	u32			num_closid;
	unsigned int		msr_base;
	void (*msr_update)	(struct rdt_domain *d, struct msr_param *m,
				 struct rdt_resource *r);
	unsigned int		mon_scale;
	unsigned int		mbm_width;
	unsigned int		mbm_cfg_mask;
	bool			cdp_enabled;
};

static inline struct rdt_hw_resource *resctrl_to_arch_res(struct rdt_resource *r)
{
	return container_of(r, struct rdt_hw_resource, r_resctrl);
}

extern struct rdt_hw_resource rdt_resources_all[];

static inline struct rdt_resource *resctrl_inc(struct rdt_resource *res)
{
	struct rdt_hw_resource *hw_res = resctrl_to_arch_res(res);

	hw_res++;
	return &hw_res->r_resctrl;
}

/*
 * To return the common struct rdt_resource, which is contained in struct
 * rdt_hw_resource, walk the resctrl member of struct rdt_hw_resource.
 */
#define for_each_rdt_resource(r)					      \
	for (r = &rdt_resources_all[0].r_resctrl;			      \
	     r <= &rdt_resources_all[RDT_NUM_RESOURCES - 1].r_resctrl;	      \
	     r = resctrl_inc(r))

#define for_each_capable_rdt_resource(r)				      \
	for_each_rdt_resource(r)					      \
		if (r->alloc_capable || r->mon_capable)

#define for_each_alloc_capable_rdt_resource(r)				      \
	for_each_rdt_resource(r)					      \
		if (r->alloc_capable)

#define for_each_mon_capable_rdt_resource(r)				      \
	for_each_rdt_resource(r)					      \
		if (r->mon_capable)

/* CPUID.(EAX=10H, ECX=ResID=1).EAX */
union cpuid_0x10_1_eax {
	struct {
		unsigned int cbm_len:5;
	} split;
	unsigned int full;
};

/* CPUID.(EAX=10H, ECX=ResID=3).EAX */
union cpuid_0x10_3_eax {
	struct {
		unsigned int max_delay:12;
	} split;
	unsigned int full;
};

/* CPUID.(EAX=10H, ECX=ResID).ECX */
union cpuid_0x10_x_ecx {
	struct {
		unsigned int reserved:3;
		unsigned int noncont:1;
	} split;
	unsigned int full;
};

/* CPUID.(EAX=10H, ECX=ResID).EDX */
union cpuid_0x10_x_edx {
	struct {
		unsigned int cos_max:16;
	} split;
	unsigned int full;
};

void rdt_ctrl_update(void *arg);
int rdt_get_mon_l3_config(struct rdt_resource *r);
void __init intel_rdt_mbm_apply_quirk(void);
void rdt_domain_reconfigure_cdp(struct rdt_resource *r);

#endif /* _ASM_X86_RESCTRL_INTERNAL_H */
