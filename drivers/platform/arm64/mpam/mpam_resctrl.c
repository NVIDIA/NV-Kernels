// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 Arm Ltd.

#define pr_fmt(fmt) "mpam: resctrl: " fmt

#include <linux/arm_mpam.h>
#include <linux/cacheinfo.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/resctrl.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <asm/mpam.h>

#include "mpam_internal.h"

/*
 * The classes we've picked to map to resctrl resources, wrapped
 * in with their resctrl structure.
 * Class pointer may be NULL.
 */
static struct mpam_resctrl_res mpam_resctrl_controls[RDT_NUM_RESOURCES];

static bool exposed_alloc_capable;
static bool exposed_mon_capable;

/*
 * MPAM emulates CDP by setting different PARTID in the I/D fields of MPAM1_EL1.
 * This applies globally to all traffic the CPU generates.
 */
static bool cdp_enabled;

bool resctrl_arch_alloc_capable(void)
{
	return exposed_alloc_capable;
}

bool resctrl_arch_mon_capable(void)
{
	return exposed_mon_capable;
}

bool resctrl_arch_get_cdp_enabled(enum resctrl_res_level ignored)
{
	return cdp_enabled;
}

/**
 * resctrl_reset_task_closids() - Reset the PARTID/PMG values for all tasks.
 *
 * At boot, all existing tasks use partid zero for D and I.
 * To enable/disable CDP emulation, all these tasks need relabelling.
 */
static void resctrl_reset_task_closids(void)
{
	struct task_struct *p, *t;

	read_lock(&tasklist_lock);
	for_each_process_thread(p, t) {
		resctrl_arch_set_closid_rmid(t, RESCTRL_RESERVED_CLOSID,
					     RESCTRL_RESERVED_RMID);
	}
	read_unlock(&tasklist_lock);
}

int resctrl_arch_set_cdp_enabled(enum resctrl_res_level ignored, bool enable)
{
	u64 regval;
	u32 partid, partid_i, partid_d;

	cdp_enabled = enable;

	partid = RESCTRL_RESERVED_CLOSID;

	if (enable) {
		partid_d = resctrl_get_config_index(partid, CDP_CODE);
		partid_i = resctrl_get_config_index(partid, CDP_DATA);
		regval = FIELD_PREP(MPAM1_EL1_PARTID_D, partid_d) |
			 FIELD_PREP(MPAM1_EL1_PARTID_I, partid_i);
	} else {
		regval = FIELD_PREP(MPAM1_EL1_PARTID_D, partid) |
			 FIELD_PREP(MPAM1_EL1_PARTID_I, partid);
	}

	resctrl_reset_task_closids();

	WRITE_ONCE(arm64_mpam_global_default, regval);

	return 0;
}

/*
 * MSC may raise an error interrupt if it sees an out or range partid/pmg,
 * and go on to truncate the value. Regardless of what the hardware supports,
 * only the system wide safe value is safe to use.
 */
u32 resctrl_arch_get_num_closid(struct rdt_resource *ignored)
{
	return min((u32)mpam_partid_max + 1, (u32)RESCTRL_MAX_CLOSID);
}

u32 resctrl_arch_system_num_rmid_idx(void)
{
	u8 closid_shift = fls(mpam_pmg_max);
	u32 num_partid = resctrl_arch_get_num_closid(NULL);

	return num_partid << closid_shift;
}

u32 resctrl_arch_rmid_idx_encode(u32 closid, u32 rmid)
{
	u8 closid_shift = fls(mpam_pmg_max);

	BUG_ON(closid_shift > 8);

	return (closid << closid_shift) | rmid;
}

void resctrl_arch_rmid_idx_decode(u32 idx, u32 *closid, u32 *rmid)
{
	u8 closid_shift = fls(mpam_pmg_max);
	u32 pmg_mask = ~(~0 << closid_shift);

	BUG_ON(closid_shift > 8);

	*closid = idx >> closid_shift;
	*rmid = idx & pmg_mask;
}

void resctrl_arch_sched_in(struct task_struct *tsk)
{
	lockdep_assert_preemption_disabled();

	mpam_thread_switch(tsk);
}

void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 pmg)
{
	BUG_ON(closid > U16_MAX);
	BUG_ON(pmg > U8_MAX);

	if (!cdp_enabled) {
		mpam_set_cpu_defaults(cpu, closid, closid, pmg, pmg);
	} else {
		/*
		 * When CDP is enabled, resctrl halves the closid range and we
		 * use odd/even partid for one closid.
		 */
		u32 partid_d = resctrl_get_config_index(closid, CDP_DATA);
		u32 partid_i = resctrl_get_config_index(closid, CDP_CODE);

		mpam_set_cpu_defaults(cpu, partid_d, partid_i, pmg, pmg);
	}
}

void resctrl_arch_sync_cpu_closid_rmid(void *info)
{
	struct resctrl_cpu_defaults *r = info;

	lockdep_assert_preemption_disabled();

	if (r) {
		resctrl_arch_set_cpu_default_closid_rmid(smp_processor_id(),
							 r->closid, r->rmid);
	}

	resctrl_arch_sched_in(current);
}

void resctrl_arch_set_closid_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	BUG_ON(closid > U16_MAX);
	BUG_ON(rmid > U8_MAX);

	if (!cdp_enabled) {
		mpam_set_task_partid_pmg(tsk, closid, closid, rmid, rmid);
	} else {
		u32 partid_d = resctrl_get_config_index(closid, CDP_DATA);
		u32 partid_i = resctrl_get_config_index(closid, CDP_CODE);

		mpam_set_task_partid_pmg(tsk, partid_d, partid_i, rmid, rmid);
	}
}

bool resctrl_arch_match_closid(struct task_struct *tsk, u32 closid)
{
	u64 regval = mpam_get_regval(tsk);
	u32 tsk_closid = FIELD_GET(MPAM1_EL1_PARTID_D, regval);

	if (cdp_enabled)
		tsk_closid >>= 1;

	return tsk_closid == closid;
}

/* The task's pmg is not unique, the partid must be considered too */
bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	u64 regval = mpam_get_regval(tsk);
	u32 tsk_closid = FIELD_GET(MPAM1_EL1_PARTID_D, regval);
	u32 tsk_rmid = FIELD_GET(MPAM1_EL1_PMG_D, regval);

	if (cdp_enabled)
		tsk_closid >>= 1;

	return (tsk_closid == closid) && (tsk_rmid == rmid);
}

struct rdt_resource *resctrl_arch_get_resource(enum resctrl_res_level l)
{
	if (l >= RDT_NUM_RESOURCES)
		return NULL;

	return &mpam_resctrl_controls[l].resctrl_res;
}

static bool cache_has_usable_cpor(struct mpam_class *class)
{
	struct mpam_props *cprops = &class->props;

	if (!mpam_has_feature(mpam_feat_cpor_part, cprops))
		return false;

	/* TODO: Scaling is not yet supported */
	return (class->props.cpbm_wd <= RESCTRL_MAX_CBM);
}

/* Test whether we can export MPAM_CLASS_CACHE:{2,3}? */
static void mpam_resctrl_pick_caches(void)
{
	int idx;
	struct mpam_class *class;
	struct mpam_resctrl_res *res;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(class, &mpam_classes, classes_list) {
		if (class->type != MPAM_CLASS_CACHE) {
			pr_debug("pick_caches: Class is not a cache\n");
			continue;
		}

		if (class->level != 2 && class->level != 3) {
			pr_debug("pick_caches: not L2 or L3\n");
			continue;
		}

		if (!cache_has_usable_cpor(class)) {
			pr_debug("pick_caches: Cache misses CPOR\n");
			continue;
		}

		if (!cpumask_equal(&class->affinity, cpu_possible_mask)) {
			pr_debug("pick_caches: Class has missing CPUs\n");
			continue;
		}

		if (class->level == 2)
			res = &mpam_resctrl_controls[RDT_RESOURCE_L2];
		else
			res = &mpam_resctrl_controls[RDT_RESOURCE_L3];
		res->class = class;
		exposed_alloc_capable = true;
	}
	srcu_read_unlock(&mpam_srcu, idx);
}

static int mpam_resctrl_control_init(struct mpam_resctrl_res *res,
				     enum resctrl_res_level type)
{
	struct mpam_class *class = res->class;
	struct rdt_resource *r = &res->resctrl_res;

	switch (res->resctrl_res.rid){
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		r->alloc_capable = true;
		r->schema_fmt = RESCTRL_SCHEMA_BITMAP;
		r->cache.arch_has_sparse_bitmasks = true;

		/* TODO: Scaling is not yet supported */
		r->cache.cbm_len = class->props.cpbm_wd;
		/* mpam_devices will reject empty bitmaps */
		r->cache.min_cbm_bits = 1;

		if (r->rid == RDT_RESOURCE_L2)
			r->name = "L2";
		else
			r->name = "L3";

		/*
		 * Which bits are shared with other ...things...
		 * Unknown devices use partid-0 which uses all the bitmap
		 * fields. Until we configured the SMMU and GIC not to do this
		 * 'all the bits' is the correct answer here.
		 */
		r->cache.shareable_bits = resctrl_get_default_ctrl(r);
		break;
	default:
		break;
	}

	return 0;
}

int mpam_resctrl_setup(void)
{
	int err = 0;
	enum resctrl_res_level i;
	struct mpam_resctrl_res *res;

	cpus_read_lock();
	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &mpam_resctrl_controls[i];
		INIT_LIST_HEAD(&res->resctrl_res.ctrl_domains);
		INIT_LIST_HEAD(&res->resctrl_res.mon_domains);
		INIT_LIST_HEAD(&res->resctrl_res.evt_list);
		res->resctrl_res.rid = i;
	}

	/* Find some classes to use for controls */
	mpam_resctrl_pick_caches();

	/* Initialise the resctrl structures from the classes */
	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &mpam_resctrl_controls[i];
		if (!res->class)
			continue;	// dummy resource

		err = mpam_resctrl_control_init(res, i);
		if (err)
			break;
	}
	cpus_read_unlock();

	if (!err && !exposed_alloc_capable && !exposed_mon_capable)
		err = -EOPNOTSUPP;

	if (!err) {
		if (!is_power_of_2(mpam_pmg_max + 1)) {
			/*
			 * If not all the partid*pmg values are valid indexes,
			 * resctrl may allocate pmg that don't exist. This
			 * should cause an error interrupt.
			 */
			pr_warn("Number of PMG is not a power of 2! resctrl may misbehave");
		}

		/* TODO: call resctrl_init() */
	}

	return err;
}

u32 resctrl_arch_get_config(struct rdt_resource *r, struct rdt_ctrl_domain *d,
			    u32 closid, enum resctrl_conf_type type)
{
	u32 partid;
	struct mpam_config *cfg;
	struct mpam_props *cprops;
	struct mpam_resctrl_res *res;
	struct mpam_resctrl_dom *dom;
	enum mpam_device_features configured_by;

	lockdep_assert_cpus_held();

	if (!mpam_is_enabled())
		return resctrl_get_default_ctrl(r);

	res = container_of(r, struct mpam_resctrl_res, resctrl_res);
	dom = container_of(d, struct mpam_resctrl_dom, resctrl_ctrl_dom);
	cprops = &res->class->props;

	partid = resctrl_get_config_index(closid, type);
	cfg = &dom->comp->cfg[partid];

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		configured_by = mpam_feat_cpor_part;
		break;
	default:
		return -EINVAL;
	}

	if (!r->alloc_capable || partid >= resctrl_arch_get_num_closid(r) ||
	    !mpam_has_feature(configured_by, cfg))
		return resctrl_get_default_ctrl(r);

	switch (configured_by) {
	case mpam_feat_cpor_part:
		/* TODO: Scaling is not yet supported */
		return cfg->cpbm;
	default:
		return -EINVAL;
	}
}

int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_ctrl_domain *d,
			    u32 closid, enum resctrl_conf_type t, u32 cfg_val)
{
	u32 partid;
	struct mpam_config cfg;
	struct mpam_props *cprops;
	struct mpam_resctrl_res *res;
	struct mpam_resctrl_dom *dom;

	lockdep_assert_cpus_held();
	lockdep_assert_irqs_enabled();

	/* NOTE: don't check the CPU as mpam_apply_config() doesn't care,
	 * and resctrl_arch_update_domains() depends on this. */
	res = container_of(r, struct mpam_resctrl_res, resctrl_res);
	dom = container_of(d, struct mpam_resctrl_dom, resctrl_ctrl_dom);
	cprops = &res->class->props;

	partid = resctrl_get_config_index(closid, t);
	if (!r->alloc_capable || partid >= resctrl_arch_get_num_closid(r))
		return -EINVAL;

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		/* TODO: Scaling is not yet supported */
		cfg.cpbm = cfg_val;
		mpam_set_feature(mpam_feat_cpor_part, &cfg);
		break;
	default:
		return -EINVAL;
	}

	return mpam_apply_config(dom->comp, partid, &cfg);
}

/* TODO: this is IPI heavy */
int resctrl_arch_update_domains(struct rdt_resource *r, u32 closid)
{
	int err = 0;
	enum resctrl_conf_type t;
	struct rdt_ctrl_domain *d;
	struct resctrl_staged_config *cfg;

	lockdep_assert_cpus_held();
	lockdep_assert_irqs_enabled();

	list_for_each_entry(d, &r->ctrl_domains, hdr.list) {
		for (t = 0; t < CDP_NUM_TYPES; t++) {
			cfg = &d->staged_config[t];
			if (!cfg->have_new_ctrl)
				continue;

			err = resctrl_arch_update_one(r, d, closid, t,
						      cfg->new_ctrl);
			if (err)
				return err;
		}
	}

	return err;
}

void resctrl_arch_reset_resources(void)
{
	int i, idx;
	struct mpam_class *class;
	struct mpam_resctrl_res *res;

	lockdep_assert_cpus_held();

	if (!mpam_is_enabled())
		return;

	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &mpam_resctrl_controls[i];
		if (!res->class)
			continue;	// dummy resource

		if (!res->resctrl_res.alloc_capable)
			continue;

		idx = srcu_read_lock(&mpam_srcu);
		list_for_each_entry_rcu(class, &mpam_classes, classes_list)
			mpam_reset_class(class);
		srcu_read_unlock(&mpam_srcu, idx);
	}
}

static void mpam_resctrl_domain_hdr_init(int cpu, struct mpam_class *class,
					 struct mpam_component *comp,
					 struct rdt_domain_hdr *hdr)
{

	INIT_LIST_HEAD(&hdr->list);
	if (class->type == MPAM_CLASS_CACHE) {
		hdr->id = comp->comp_id;
	} else {
		/* TODO: repaint domain ids to match the L3 domain ids */
		/* TODO: if this matches the numa topology, use the nid to look
		 * like SNC */
		/*
		 * Otherwise, expose the ID used by the firmware table code.
		 */
		hdr->id = comp->comp_id;
	}
	cpumask_set_cpu(cpu, &hdr->cpu_mask);
}

static bool mpam_resctrl_offline_domain_hdr(unsigned int cpu,
					    struct rdt_domain_hdr *hdr)
{
	cpumask_clear_cpu(cpu, &hdr->cpu_mask);
	if (cpumask_empty(&hdr->cpu_mask)) {
		list_del(&hdr->list);
		return true;
	}

	return false;
}

static struct mpam_resctrl_dom *
mpam_resctrl_alloc_domain(unsigned int cpu, struct mpam_resctrl_res *res)
{
	struct mpam_resctrl_dom *dom;
	struct rdt_mon_domain *mon_d;
	struct rdt_ctrl_domain *ctrl_d;
	struct mpam_class *class = res->class;
	struct mpam_component *comp_iter, *comp;

	comp = NULL;
	list_for_each_entry(comp_iter, &class->components, class_list) {
		if (cpumask_test_cpu(cpu, &comp_iter->affinity)) {
			comp = comp_iter;
			break;
		}
	}

	/* cpu with unknown exported component? */
	if (WARN_ON_ONCE(!comp))
		return ERR_PTR(-EINVAL);

	dom = kzalloc_node(sizeof(*dom), GFP_KERNEL, cpu_to_node(cpu));
	if (!dom)
		return ERR_PTR(-ENOMEM);

	dom->comp = comp;

	ctrl_d = &dom->resctrl_ctrl_dom;
	mpam_resctrl_domain_hdr_init(cpu, class, comp, &ctrl_d->hdr);
	ctrl_d->hdr.type = RESCTRL_CTRL_DOMAIN;
	/* TODO: this list should be sorted */
	list_add_tail(&ctrl_d->hdr.list, &res->resctrl_res.ctrl_domains);

	mon_d = &dom->resctrl_mon_dom;
	mpam_resctrl_domain_hdr_init(cpu, class, comp, &mon_d->hdr);
	mon_d->hdr.type = RESCTRL_MON_DOMAIN;
	/* TODO: this list should be sorted */
	list_add_tail(&mon_d->hdr.list, &res->resctrl_res.mon_domains);

	return dom;
}

/* Like resctrl_get_domain_from_cpu(), but for offline CPUs */
static struct mpam_resctrl_dom *
mpam_get_domain_from_cpu(int cpu, struct mpam_resctrl_res *res)
{
	struct rdt_ctrl_domain *d;
	struct mpam_resctrl_dom *dom;

	lockdep_assert_cpus_held();

	list_for_each_entry(d, &res->resctrl_res.ctrl_domains, hdr.list) {
		dom = container_of(d, struct mpam_resctrl_dom, resctrl_ctrl_dom);

		if (cpumask_test_cpu(cpu, &dom->comp->affinity))
			return dom;
	}

	return NULL;
}

struct rdt_domain_hdr *resctrl_arch_find_domain(struct list_head *domain_list, int id)
{
	struct rdt_domain_hdr *hdr;

	lockdep_assert_cpus_held();

	list_for_each_entry(hdr, domain_list, list) {
		if (hdr->id == id)
			return hdr;
	}

	return NULL;
}

int mpam_resctrl_online_cpu(unsigned int cpu)
{
	int i;
	struct mpam_resctrl_dom *dom;
	struct mpam_resctrl_res *res;

	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &mpam_resctrl_controls[i];
		if (!res->class)
			continue;	// dummy_resource;

		dom = mpam_get_domain_from_cpu(cpu, res);
		if (!dom)
			dom = mpam_resctrl_alloc_domain(cpu, res);
		if (IS_ERR(dom))
			return PTR_ERR(dom);

		cpumask_set_cpu(cpu, &dom->resctrl_ctrl_dom.hdr.cpu_mask);
		cpumask_set_cpu(cpu, &dom->resctrl_mon_dom.hdr.cpu_mask);
	}

	return 0;
}

int mpam_resctrl_offline_cpu(unsigned int cpu)
{
	int i;
	struct mpam_resctrl_res *res;
	struct mpam_resctrl_dom *dom;
	struct rdt_mon_domain *mon_d;
	struct rdt_ctrl_domain *ctrl_d;

	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &mpam_resctrl_controls[i];
		if (!res->class)
			continue;	// dummy resource

		ctrl_d = resctrl_get_ctrl_domain_from_cpu(cpu, &res->resctrl_res);
		if (WARN_ON_ONCE(!ctrl_d))
			continue;
		if (!mpam_resctrl_offline_domain_hdr(cpu, &ctrl_d->hdr))
			continue;

		dom = container_of(ctrl_d, struct mpam_resctrl_dom, resctrl_ctrl_dom);
		mon_d = &dom->resctrl_mon_dom;
		if (!mpam_resctrl_offline_domain_hdr(cpu, &mon_d->hdr))
			continue;

		kfree(dom);
	}

	return 0;
}
