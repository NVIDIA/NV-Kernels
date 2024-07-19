// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2025 Arm Ltd.

#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

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
 * MPAM emulates CDP by setting different PARTID in the I/D fields of MPAM0_EL1.
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

bool resctrl_arch_get_cdp_enabled(enum resctrl_res_level rid)
{
	switch (rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		return cdp_enabled;
	case RDT_RESOURCE_MBA:
	default:
		/*
		 * x86's MBA control doesn't support CDP, so user-space doesn't
		 * expect it.
		 */
		return false;
	}
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
		regval = FIELD_PREP(MPAM0_EL1_PARTID_D, partid_d) |
			 FIELD_PREP(MPAM0_EL1_PARTID_I, partid_i);
	} else {
		regval = FIELD_PREP(MPAM0_EL1_PARTID_D, partid) |
			 FIELD_PREP(MPAM0_EL1_PARTID_I, partid);
	}

	resctrl_reset_task_closids();

	WRITE_ONCE(arm64_mpam_global_default, regval);

	return 0;
}

static bool mpam_resctrl_hide_cdp(enum resctrl_res_level rid)
{
	return cdp_enabled && !resctrl_arch_get_cdp_enabled(rid);
}

/*
 * MSC may raise an error interrupt if it sees an out or range partid/pmg,
 * and go on to truncate the value. Regardless of what the hardware supports,
 * only the system wide safe value is safe to use.
 */
u32 resctrl_arch_get_num_closid(struct rdt_resource *ignored)
{
	return mpam_partid_max + 1;
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

	WARN_ON_ONCE(closid_shift > 8);

	return (closid << closid_shift) | rmid;
}

void resctrl_arch_rmid_idx_decode(u32 idx, u32 *closid, u32 *rmid)
{
	u8 closid_shift = fls(mpam_pmg_max);
	u32 pmg_mask = ~(~0 << closid_shift);

	WARN_ON_ONCE(closid_shift > 8);

	*closid = idx >> closid_shift;
	*rmid = idx & pmg_mask;
}

void resctrl_arch_sched_in(struct task_struct *tsk)
{
	lockdep_assert_preemption_disabled();

	mpam_thread_switch(tsk);
}

void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid, u32 rmid)
{
	WARN_ON_ONCE(closid > U16_MAX);
	WARN_ON_ONCE(rmid > U8_MAX);

	if (!cdp_enabled) {
		mpam_set_cpu_defaults(cpu, closid, closid, rmid, rmid);
	} else {
		/*
		 * When CDP is enabled, resctrl halves the closid range and we
		 * use odd/even partid for one closid.
		 */
		u32 partid_d = resctrl_get_config_index(closid, CDP_DATA);
		u32 partid_i = resctrl_get_config_index(closid, CDP_CODE);

		mpam_set_cpu_defaults(cpu, partid_d, partid_i, rmid, rmid);
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
	WARN_ON_ONCE(closid > U16_MAX);
	WARN_ON_ONCE(rmid > U8_MAX);

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
	u32 tsk_closid = FIELD_GET(MPAM0_EL1_PARTID_D, regval);

	if (cdp_enabled)
		tsk_closid >>= 1;

	return tsk_closid == closid;
}

/* The task's pmg is not unique, the partid must be considered too */
bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	u64 regval = mpam_get_regval(tsk);
	u32 tsk_closid = FIELD_GET(MPAM0_EL1_PARTID_D, regval);
	u32 tsk_rmid = FIELD_GET(MPAM0_EL1_PMG_D, regval);

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
	/* resctrl uses u32 for all bitmap configurations */
	return (class->props.cpbm_wd <= 32);
}

static bool mba_class_use_mbw_part(struct mpam_props *cprops)
{
	return (mpam_has_feature(mpam_feat_mbw_part, cprops) &&
		cprops->mbw_pbm_bits);
}

static bool mba_class_use_mbw_max(struct mpam_props *cprops)
{
	return (mpam_has_feature(mpam_feat_mbw_max, cprops) &&
		cprops->bwa_wd);
}

static bool class_has_usable_mba(struct mpam_props *cprops)
{
	return mba_class_use_mbw_part(cprops) || mba_class_use_mbw_max(cprops);
}

/*
 * Calculate the percentage change from each implemented bit in the control
 * This can return 0 when BWA_WD is greater than 6. (100 / (1<<7) == 0)
 */
static u32 get_mba_granularity(struct mpam_props *cprops)
{
	if (mba_class_use_mbw_part(cprops)) {
		return max(MAX_MBA_BW / cprops->mbw_pbm_bits, 1);
	} else if (mba_class_use_mbw_max(cprops)) {
		/*
		 * bwa_wd is the number of bits implemented in the 0.xxx
		 * fixed point fraction. 1 bit is 50%, 2 is 25% etc.
		 */
		return max(MAX_MBA_BW / (1 << cprops->bwa_wd), 1);
	}

	return 0;
}

static u32 mbw_pbm_to_percent(const unsigned long mbw_pbm, struct mpam_props *cprops)
{
	u32 num_bits = bitmap_weight(&mbw_pbm, (unsigned int)cprops->mbw_pbm_bits);

	if (cprops->mbw_pbm_bits == 0)
		return 0;

	return (num_bits * MAX_MBA_BW) / cprops->mbw_pbm_bits;
}

static u32 mbw_max_to_percent(u16 mbw_max, struct mpam_props *cprops)
{
	u32 max_fract = 0xffff;

	max_fract >>= 16 - cprops->bwa_wd;
	mbw_max >>= 16 - cprops->bwa_wd;

	return DIV_ROUND_CLOSEST((mbw_max * 100), max_fract);
}

static u32 percent_to_mbw_pbm(u8 pc, struct mpam_props *cprops)
{
	u8 num_bits = (pc * cprops->mbw_pbm_bits) / MAX_MBA_BW;

	if (!num_bits)
		return 0;

	/* TODO: pick bits at random to avoid contention */
	return (1 << num_bits) - 1;
}

static u16 percent_to_mbw_max(u8 pc, struct mpam_props *cprops)
{
	u32 value;

	if (WARN_ON_ONCE(cprops->bwa_wd > 16))
		return 100;

	value = ((pc << cprops->bwa_wd) + 50) / 100;

	if (value < 1)
		return 0;
	return (value - 1) << (16 - cprops->bwa_wd);
}

/* Find the L3 cache that has affinity with this CPU */
static int find_l3_equivalent_bitmask(int cpu, cpumask_var_t tmp_cpumask)
{
	int err;
	u32 cache_id = get_cpu_cacheinfo_id(cpu, 3);

	lockdep_assert_cpus_held();

	err = mpam_get_cpumask_from_cache_id(cache_id, 3, tmp_cpumask);
	return err;
}

DEFINE_FREE(cpumask, cpumask_var_t, if (_T) free_cpumask_var(_T));

/*
 * topology_matches_l3() - Is the provided class the same shape as L3
 * @victim:		The class we'd like to pretend is L3.
 *
 * resctrl expects all the worlds a Xeon, and all counters are on the
 * L3. We play fast and loose with this, mapping counters on other
 * classes - provided the CPU->domain mapping is the same kind of shape.
 *
 * Using cacheinfo directly would make this work even if resctrl can't
 * use the L3 - but cacheinfo can't tell us anything about offline CPUs.
 * Using the L3 resctrl domain list also depends on CPUs being online.
 * Using the mpam_class we picked for L3 so we can use its domain list
 * assumes that there are MPAM controls on the L3.
 * Instead, this path eventually uses the mpam_get_cpumask_from_cache_id()
 * helper. This relies on at least one CPU per L3 cache being online at
 * boot.
 *
 * Walk the two component lists and compare the affinity masks. The topology
 * matches if each victim:component has a corresponding L3:component with the
 * same affinity mask. These lists/masks are computed from firmware tables so
 * don't change at runtime.
 */
static bool topology_matches_l3(struct mpam_class *victim)
{
	int cpu, err;
	struct mpam_component *victim_iter;
	cpumask_var_t __free(cpumask) tmp_cpumask = NULL;

	if (!alloc_cpumask_var(&tmp_cpumask, GFP_KERNEL))
		return false;

	list_for_each_entry(victim_iter, &victim->components, class_list) {
		if (cpumask_empty(&victim_iter->affinity)) {
			pr_debug("class %u has CPU-less component %u - can't match L3!\n",
				 victim->level, victim_iter->comp_id);
			return false;
		}

		cpu = cpumask_any(&victim_iter->affinity);
		if (WARN_ON_ONCE(cpu >= nr_cpu_ids))
			return false;

		cpumask_clear(tmp_cpumask);
		err = find_l3_equivalent_bitmask(cpu, tmp_cpumask);
		if (err) {
			pr_debug("Failed to find L3's equivalent component to class %u component %u\n",
				 victim->level, victim_iter->comp_id);
			return false;
		}

		/* Any differing bits in the affinity mask? */
		if (!cpumask_equal(tmp_cpumask, &victim_iter->affinity)) {
			pr_debug("class %u component %u has Mismatched CPU mask with L3 equivalent\n"
				 "L3:%*pbl != victim:%*pbl\n",
				 victim->level, victim_iter->comp_id,
				 cpumask_pr_args(tmp_cpumask),
				 cpumask_pr_args(&victim_iter->affinity));

			return false;
		}
	}

	return true;
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
			pr_debug("class %u is not a cache\n", class->level);
			continue;
		}

		if (class->level != 2 && class->level != 3) {
			pr_debug("class %u is not L2 or L3\n", class->level);
			continue;
		}

		if (!cache_has_usable_cpor(class)) {
			pr_debug("class %u cache misses CPOR\n", class->level);
			continue;
		}

		if (!cpumask_equal(&class->affinity, cpu_possible_mask)) {
			pr_debug("class %u Class has missing CPUs\n", class->level);
			pr_debug("class %u mask %*pb != %*pb\n", class->level,
				 cpumask_pr_args(&class->affinity),
				 cpumask_pr_args(cpu_possible_mask));
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

static void mpam_resctrl_pick_mba(void)
{
	struct mpam_class *class, *candidate_class = NULL;
	struct mpam_resctrl_res *res;
	int idx;

	lockdep_assert_cpus_held();

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(class, &mpam_classes, classes_list) {
		struct mpam_props *cprops = &class->props;

		if (class->level < 3) {
			pr_debug("class %u is before L3\n", class->level);
			continue;
		}

		if (!class_has_usable_mba(cprops)) {
			pr_debug("class %u has no bandwidth control\n", class->level);
			continue;
		}

		if (!cpumask_equal(&class->affinity, cpu_possible_mask)) {
			pr_debug("class %u has missing CPUs\n", class->level);
			continue;
		}

		if (!topology_matches_l3(class)) {
			pr_debug("class %u topology doesn't match L3\n", class->level);
			continue;
		}

		/*
		 * mba_sc reads the mbm_local counter, and waggles the MBA controls.
		 * mbm_local is implicitly part of the L3, pick a resource to be MBA
		 * that as close as possible to the L3.
		 */
		if (!candidate_class || class->level < candidate_class->level)
			candidate_class = class;
	}
	srcu_read_unlock(&mpam_srcu, idx);

	if (candidate_class) {
		pr_debug("selected class %u to back MBA\n", candidate_class->level);
		res = &mpam_resctrl_controls[RDT_RESOURCE_MBA];
		res->class = candidate_class;
		exposed_alloc_capable = true;
	}
}

static int mpam_resctrl_control_init(struct mpam_resctrl_res *res,
				     enum resctrl_res_level type)
{
	struct mpam_class *class = res->class;
	struct mpam_props *cprops = &class->props;
	struct rdt_resource *r = &res->resctrl_res;

	switch (res->resctrl_res.rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		r->alloc_capable = true;
		r->schema_fmt = RESCTRL_SCHEMA_BITMAP;
		r->cache.arch_has_sparse_bitmasks = true;

		/* TODO: Scaling is not yet supported */
		r->cache.cbm_len = class->props.cpbm_wd;
		/* mpam_devices will reject empty bitmaps */
		r->cache.min_cbm_bits = 1;

		if (r->rid == RDT_RESOURCE_L2) {
			r->name = "L2";
			r->ctrl_scope = RESCTRL_L2_CACHE;
		} else {
			r->name = "L3";
			r->ctrl_scope = RESCTRL_L3_CACHE;
		}

		/*
		 * Which bits are shared with other ...things...
		 * Unknown devices use partid-0 which uses all the bitmap
		 * fields. Until we configured the SMMU and GIC not to do this
		 * 'all the bits' is the correct answer here.
		 */
		r->cache.shareable_bits = resctrl_get_default_ctrl(r);
		break;
	case RDT_RESOURCE_MBA:
		r->alloc_capable = true;
		r->schema_fmt = RESCTRL_SCHEMA_RANGE;
		r->ctrl_scope = RESCTRL_L3_CACHE;

		r->membw.delay_linear = true;
		r->membw.throttle_mode = THREAD_THROTTLE_UNDEFINED;
		r->membw.min_bw = get_mba_granularity(cprops);
		r->membw.max_bw = MAX_MBA_BW;
		r->membw.bw_gran = get_mba_granularity(cprops);

		r->name = "MB";

		/* Round up to at least 1% */
		if (!r->membw.bw_gran)
			r->membw.bw_gran = 1;

		break;
	default:
		break;
	}

	return 0;
}

static int mpam_resctrl_pick_domain_id(int cpu, struct mpam_component *comp)
{
	struct mpam_class *class = comp->class;

	if (class->type == MPAM_CLASS_CACHE) {
		return comp->comp_id;
	} else if (topology_matches_l3(class)) {
		/* Use the corresponding L3 component ID as the domain ID */
		int id = get_cpu_cacheinfo_id(cpu, 3);

		if (id != -1)
			return id;
		else
			return comp->comp_id;
	} else {
		/*
		 * Otherwise, expose the ID used by the firmware table code.
		 */
		return comp->comp_id;
	}
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

	/*
	 * When CDP is enabled, but the resource doesn't support it,
	 * the control is cloned across both partids.
	 * Pick one at random to read:
	 */
	if (mpam_resctrl_hide_cdp(r->rid))
		type = CDP_DATA;

	partid = resctrl_get_config_index(closid, type);
	cfg = &dom->comp->cfg[partid];

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		configured_by = mpam_feat_cpor_part;
		break;
	case RDT_RESOURCE_MBA:
		if (mba_class_use_mbw_part(cprops)) {
			configured_by = mpam_feat_mbw_part;
			break;
		} else if (mpam_has_feature(mpam_feat_mbw_max, cprops)) {
			configured_by = mpam_feat_mbw_max;
			break;
		}
		fallthrough;
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
	case mpam_feat_mbw_part:
		/* TODO: Scaling is not yet supported */
		return mbw_pbm_to_percent(cfg->mbw_pbm, cprops);
	case mpam_feat_mbw_max:
		return mbw_max_to_percent(cfg->mbw_max, cprops);
	default:
		return -EINVAL;
	}
}

int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_ctrl_domain *d,
			    u32 closid, enum resctrl_conf_type t, u32 cfg_val)
{
	int err;
	u32 partid;
	struct mpam_config cfg;
	struct mpam_props *cprops;
	struct mpam_resctrl_res *res;
	struct mpam_resctrl_dom *dom;

	lockdep_assert_cpus_held();
	lockdep_assert_irqs_enabled();

	/*
	 * NOTE: don't check the CPU as mpam_apply_config() doesn't care,
	 * and resctrl_arch_update_domains() depends on this.
	 */
	res = container_of(r, struct mpam_resctrl_res, resctrl_res);
	dom = container_of(d, struct mpam_resctrl_dom, resctrl_ctrl_dom);
	cprops = &res->class->props;

	partid = resctrl_get_config_index(closid, t);
	if (!r->alloc_capable || partid >= resctrl_arch_get_num_closid(r))
		return -EINVAL;

       /*
	* Copy the current config to avoid clearing other resources when the
	* same component is exposed multiple times through resctrl.
	*/
	cfg = dom->comp->cfg[partid];

	switch (r->rid) {
	case RDT_RESOURCE_L2:
	case RDT_RESOURCE_L3:
		/* TODO: Scaling is not yet supported */
		cfg.cpbm = cfg_val;
		mpam_set_feature(mpam_feat_cpor_part, &cfg);
		break;
	case RDT_RESOURCE_MBA:
		if (mba_class_use_mbw_part(cprops)) {
			cfg.mbw_pbm = percent_to_mbw_pbm(cfg_val, cprops);
			mpam_set_feature(mpam_feat_mbw_part, &cfg);
			break;
		} else if (mpam_has_feature(mpam_feat_mbw_max, cprops)) {
			cfg.mbw_max = percent_to_mbw_max(cfg_val, cprops);
			mpam_set_feature(mpam_feat_mbw_max, &cfg);
			break;
		}
		fallthrough;
	default:
		return -EINVAL;
	}

	/*
	 * When CDP is enabled, but the resource doesn't support it, we need to
	 * apply the same configuration to the other partid.
	 */
	if (mpam_resctrl_hide_cdp(r->rid)) {
		partid = resctrl_get_config_index(closid, CDP_CODE);
		err = mpam_apply_config(dom->comp, partid, &cfg);
		if (err)
			return err;

		partid = resctrl_get_config_index(closid, CDP_DATA);
		return mpam_apply_config(dom->comp, partid, &cfg);

	} else {
		return mpam_apply_config(dom->comp, partid, &cfg);
	}
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

void resctrl_arch_reset_all_ctrls(struct rdt_resource *r)
{
	struct mpam_resctrl_res *res;

	lockdep_assert_cpus_held();

	if (!mpam_is_enabled())
		return;

	res = container_of(r, struct mpam_resctrl_res, resctrl_res);
	mpam_reset_class_locked(res->class);
}

static void mpam_resctrl_domain_hdr_init(int cpu, struct mpam_component *comp,
					 struct rdt_domain_hdr *hdr)
{
	lockdep_assert_cpus_held();

	INIT_LIST_HEAD(&hdr->list);
	hdr->id = mpam_resctrl_pick_domain_id(cpu, comp);
	cpumask_set_cpu(cpu, &hdr->cpu_mask);
}

/**
 * mpam_resctrl_offline_domain_hdr() - Update the domain header to remove a CPU.
 * @cpu:	The CPU to remove from the domain.
 * @hdr:	The domain's header.
 *
 * Removes @cpu from the header mask. If this was the last CPU in the domain,
 * the domain header is removed from its parent list and true is returned,
 * indicating the parent structure can be freed.
 * If there are other CPUs in the domain, returns false.
 */
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
	mpam_resctrl_domain_hdr_init(cpu, comp, &ctrl_d->hdr);
	ctrl_d->hdr.type = RESCTRL_CTRL_DOMAIN;
	/* TODO: this list should be sorted */
	list_add_tail(&ctrl_d->hdr.list, &res->resctrl_res.ctrl_domains);

	mon_d = &dom->resctrl_mon_dom;
	mpam_resctrl_domain_hdr_init(cpu, comp, &mon_d->hdr);
	mon_d->hdr.type = RESCTRL_MON_DOMAIN;
	/* TODO: this list should be sorted */
	list_add_tail(&mon_d->hdr.list, &res->resctrl_res.mon_domains);

	return dom;
}

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
	bool ctrl_dom_empty, mon_dom_empty;

	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &mpam_resctrl_controls[i];
		if (!res->class)
			continue;	// dummy resource

		dom = mpam_get_domain_from_cpu(cpu, res);
		if (WARN_ON_ONCE(!dom))
			continue;

		mpam_reset_component_locked(dom->comp);

		ctrl_d = &dom->resctrl_ctrl_dom;
		ctrl_dom_empty = mpam_resctrl_offline_domain_hdr(cpu, &ctrl_d->hdr);

		mon_d = &dom->resctrl_mon_dom;
		mon_dom_empty = mpam_resctrl_offline_domain_hdr(cpu, &mon_d->hdr);

		if (ctrl_dom_empty && mon_dom_empty)
			kfree(dom);
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
	mpam_resctrl_pick_mba();

	/* Initialise the resctrl structures from the classes */
	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &mpam_resctrl_controls[i];
		if (!res->class)
			continue;	// dummy resource

		err = mpam_resctrl_control_init(res, i);
		if (err) {
			pr_debug("Failed to initialise rid %u\n", i);
			break;
		}
	}
	cpus_read_unlock();

	if (!err && !exposed_alloc_capable && !exposed_mon_capable) {
		pr_debug("Internal error, or no usable resctrl resources found\n");
		err = -EOPNOTSUPP;
	}

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
