// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2021 Arm Ltd.

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

u64 mpam_resctrl_default_group;

/*
 * The classes we've picked to map to resctrl resources.
 * Class pointer may be NULL.
 */
static struct mpam_resctrl_res mpam_resctrl_exports[RDT_NUM_RESOURCES];

static bool exposed_alloc_capable;
static bool exposed_mon_capable;
static struct mpam_class *mbm_local_class;
static struct mpam_class *mbm_total_class;

/*
 * MPAM emulates CDP by setting different PARTID in the I/D fields of MPAM1_EL1.
 * This applies globally to all traffic the CPU generates.
 */
static bool cdp_enabled;

/* A dummy mon context to use when the monitors were allocated up front */
u32 __mon_is_rmid_idx = USE_RMID_IDX;
void *mon_is_rmid_idx = &__mon_is_rmid_idx;

bool resctrl_arch_alloc_capable(void)
{
	return exposed_alloc_capable;
}

bool resctrl_arch_mon_capable(void)
{
	return exposed_mon_capable;
}

bool resctrl_arch_is_mbm_local_enabled(void)
{
	return mbm_local_class;
}

bool resctrl_arch_is_mbm_total_enabled(void)
{
	return mbm_total_class;
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

int resctrl_arch_set_cdp_enabled(enum resctrl_res_level ignored, bool enable)
{
	u64 regval;
	u32 partid, partid_i, partid_d;

	cdp_enabled = enable;

	partid = RESCTRL_RESERVED_CLOSID;

	if (enable) {
		partid_d = resctrl_get_config_index(partid, CDP_CODE);
		partid_i = resctrl_get_config_index(partid, CDP_DATA);
		regval = FIELD_PREP(MPAM_SYSREG_PARTID_D, partid_d) |
			 FIELD_PREP(MPAM_SYSREG_PARTID_I, partid_i);

	} else {
		regval = FIELD_PREP(MPAM_SYSREG_PARTID_D, partid) |
			 FIELD_PREP(MPAM_SYSREG_PARTID_I, partid);
	}

	WRITE_ONCE(mpam_resctrl_default_group, regval);

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

void resctrl_sched_in(struct task_struct *tsk)
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

void resctrl_arch_sync_cpu_defaults(void *info)
{
	struct resctrl_cpu_sync *r = info;

	lockdep_assert_preemption_disabled();

	if (r) {
		resctrl_arch_set_cpu_default_closid_rmid(smp_processor_id(),
							 r->closid, r->rmid);
	}

	resctrl_sched_in(current);
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
	u32 tsk_closid = FIELD_GET(MPAM_SYSREG_PARTID_D, regval);

	if (cdp_enabled)
		tsk_closid >>= 1;

	return tsk_closid == closid;
}

/* The task's pmg is not unique, the partid must be considered too */
bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 closid, u32 rmid)
{
	u64 regval = mpam_get_regval(tsk);
	u32 tsk_closid = FIELD_GET(MPAM_SYSREG_PARTID_D, regval);
	u32 tsk_rmid = FIELD_GET(MPAM_SYSREG_PMG_D, regval);

	if (cdp_enabled)
		tsk_closid >>= 1;

	return (tsk_closid == closid) && (tsk_rmid == rmid);
}

struct rdt_resource *resctrl_arch_get_resource(enum resctrl_res_level l)
{
	if (l >= RDT_NUM_RESOURCES)
		return NULL;

	return &mpam_resctrl_exports[l].resctrl_res;
}

void *resctrl_arch_mon_ctx_alloc_no_wait(struct rdt_resource *r, int evtid)
{
	struct mpam_resctrl_res *res;
	u32 *ret = kmalloc(sizeof(*ret), GFP_KERNEL);

	if (!ret)
		return ERR_PTR(-ENOMEM);

	switch (evtid) {
	case QOS_L3_OCCUP_EVENT_ID:
		res = container_of(r, struct mpam_resctrl_res, resctrl_res);

		*ret = mpam_alloc_csu_mon(res->class);
		return ret;
	case QOS_L3_MBM_LOCAL_EVENT_ID:
	case QOS_L3_MBM_TOTAL_EVENT_ID:
		return mon_is_rmid_idx;
	}

	return ERR_PTR(-EOPNOTSUPP);
}

void resctrl_arch_mon_ctx_free(struct rdt_resource *r, int evtid,
			       void *arch_mon_ctx)
{
	struct mpam_resctrl_res *res;
	u32 mon = *(u32 *)arch_mon_ctx;

	if (mon == USE_RMID_IDX)
		return;
	kfree(arch_mon_ctx);
	arch_mon_ctx = NULL;

	res = container_of(r, struct mpam_resctrl_res, resctrl_res);

	switch (evtid) {
	case QOS_L3_OCCUP_EVENT_ID:
		mpam_free_csu_mon(res->class, mon);
		wake_up(&resctrl_mon_ctx_waiters);
		return;
	case QOS_L3_MBM_TOTAL_EVENT_ID:
	case QOS_L3_MBM_LOCAL_EVENT_ID:
		return;
	}
}

static enum mon_filter_options resctrl_evt_config_to_mpam(u32 local_evt_cfg)
{
	switch (local_evt_cfg) {
	case READS_TO_LOCAL_MEM:
		return COUNT_READ;
	case NON_TEMP_WRITE_TO_LOCAL_MEM:
		return COUNT_WRITE;
	default:
		return COUNT_BOTH;
	}
}

int resctrl_arch_rmid_read(struct rdt_resource	*r, struct rdt_domain *d,
			   u32 closid, u32 rmid, enum resctrl_event_id eventid,
			   u64 *val, void *arch_mon_ctx)
{
	int err;
	u64 cdp_val;
	struct mon_cfg cfg;
	struct mpam_resctrl_dom *dom;
	u32 mon = *(u32 *)arch_mon_ctx;
	enum mpam_device_features type;

	resctrl_arch_rmid_read_context_check();

	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);

	switch (eventid) {
	case QOS_L3_OCCUP_EVENT_ID:
		type = mpam_feat_msmon_csu;
		break;
	case QOS_L3_MBM_LOCAL_EVENT_ID:
	case QOS_L3_MBM_TOTAL_EVENT_ID:
		type = mpam_feat_msmon_mbwu;
		break;
	default:
		return -EINVAL;
	}

	cfg.mon = mon;
	if (cfg.mon == USE_RMID_IDX)
		cfg.mon = resctrl_arch_rmid_idx_encode(closid, rmid);

	cfg.match_pmg = true;
	cfg.pmg = rmid;
	cfg.opts = resctrl_evt_config_to_mpam(dom->mbm_local_evt_cfg);

	if (cdp_enabled) {
		cfg.partid = closid << 1;
		err = mpam_msmon_read(dom->comp, &cfg, type, val);
		if (err)
			return err;

		cfg.partid += 1;
		err = mpam_msmon_read(dom->comp, &cfg, type, &cdp_val);
		if (!err)
			*val += cdp_val;
	} else {
		cfg.partid = closid;
		err = mpam_msmon_read(dom->comp, &cfg, type, val);
	}

	return err;
}

void resctrl_arch_reset_rmid(struct rdt_resource *r, struct rdt_domain *d,
			     u32 closid, u32 rmid, enum resctrl_event_id eventid)
{
	struct mon_cfg cfg;
	struct mpam_resctrl_dom *dom;

	if (eventid != QOS_L3_MBM_LOCAL_EVENT_ID)
		return;

	cfg.mon = resctrl_arch_rmid_idx_encode(closid, rmid);
	cfg.match_pmg = true;
	cfg.pmg = rmid;

	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);

	if (cdp_enabled) {
		cfg.partid = closid << 1;
		mpam_msmon_reset_mbwu(dom->comp, &cfg);

		cfg.partid += 1;
		mpam_msmon_reset_mbwu(dom->comp, &cfg);
	} else {
		cfg.partid = closid;
		mpam_msmon_reset_mbwu(dom->comp, &cfg);
	}
}

static bool cache_has_usable_cpor(struct mpam_class *class)
{
	struct mpam_props *cprops = &class->props;

	if (!mpam_has_feature(mpam_feat_cpor_part, cprops))
		return false;

	/* TODO: Scaling is not yet supported */
	return (class->props.cpbm_wd <= RESCTRL_MAX_CBM);
}

static bool cache_has_usable_csu(struct mpam_class *class)
{
	struct mpam_props *cprops;

	if (!class)
		return false;

	cprops = &class->props;

	if (!mpam_has_feature(mpam_feat_msmon_csu, cprops))
		return false;

	/*
	 * CSU counters settle on the value, so we can get away with
	 * having only one.
	 */
	if (!cprops->num_csu_mon)
		return false;

	return (mpam_partid_max > 1) || (mpam_pmg_max != 0);
}

bool resctrl_arch_is_llc_occupancy_enabled(void)
{
	return cache_has_usable_csu(mpam_resctrl_exports[RDT_RESOURCE_L3].class);
}

static bool class_has_usable_mbwu(struct mpam_class *class)
{
	struct mpam_props *cprops = &class->props;

	if (!mpam_has_feature(mpam_feat_msmon_mbwu, cprops))
		return false;

	/*
	 * resctrl expects the bandwidth counters to be free running,
	 * which means we need as many monitors as resctrl has
	 * control/monitor groups.
	 */
	if (cprops->num_mbwu_mon < resctrl_arch_system_num_rmid_idx())
		return false;

	return (mpam_partid_max > 1) || (mpam_pmg_max != 0);
}

static bool mba_class_use_mbw_part(struct mpam_props *cprops)
{
	/* TODO: Scaling is not yet supported */
	return (mpam_has_feature(mpam_feat_mbw_part, cprops) &&
		cprops->mbw_pbm_bits < MAX_MBA_BW);
}

static bool class_has_usable_mba(struct mpam_props *cprops)
{
	if (mba_class_use_mbw_part(cprops) ||
	    mpam_has_feature(mpam_feat_mbw_max, cprops))
		return true;

	return false;
}

/*
 * Calculate the percentage change from each implemented bit in the control
 * This can return 0 when BWA_WD is greater than 6. (100 / (1<<7) == 0)
 */
static u32 get_mba_granularity(struct mpam_props *cprops)
{
	if (mba_class_use_mbw_part(cprops)) {
		return MAX_MBA_BW / cprops->mbw_pbm_bits;
	} else if (mpam_has_feature(mpam_feat_mbw_max, cprops)) {
		/*
		 * bwa_wd is the number of bits implemented in the 0.xxx
		 * fixed point fraction. 1 bit is 50%, 2 is 25% etc.
		 */
		return MAX_MBA_BW / (cprops->bwa_wd + 1);
	}

	return 0;
}

static u32 mbw_pbm_to_percent(unsigned long mbw_pbm, struct mpam_props *cprops)
{
	u32 bit, result = 0, granularity = get_mba_granularity(cprops);

	for_each_set_bit(bit, &mbw_pbm, cprops->mbw_pbm_bits % 32) {
		result += granularity;
	}

	return result;
}

static u32 mbw_max_to_percent(u16 mbw_max, struct mpam_props *cprops)
{
	u8 bit;
	u32 divisor = 2, value = 0;

	for (bit = 15; bit; bit--) {
		if (mbw_max & BIT(bit))
			value += MAX_MBA_BW / divisor;
		divisor <<= 1;
	}

	return value;
}

static u32 percent_to_mbw_pbm(u8 pc, struct mpam_props *cprops)
{
	u32 granularity = get_mba_granularity(cprops);
	u8 num_bits = pc / granularity;

	if (!num_bits)
		return 0;

	/* TODO: pick bits at random to avoid contention */
	return (1 << num_bits) - 1;
}

static u16 percent_to_mbw_max(u8 pc, struct mpam_props *cprops)
{
	u8 bit;
	u32 divisor = 2, value = 0;

	if (WARN_ON_ONCE(cprops->bwa_wd > 15))
		return MAX_MBA_BW;

	for (bit = 15; bit; bit--) {
		if (pc >= MAX_MBA_BW / divisor) {
			pc -= MAX_MBA_BW / divisor;
			value |= BIT(bit);
		}
		divisor <<= 1;

		if (!pc || !(MAX_MBA_BW / divisor))
			break;
	}

	value &= GENMASK(15, 15 - cprops->bwa_wd);

	return value;
}

/* Test whether we can export MPAM_CLASS_CACHE:{2,3}? */
static void mpam_resctrl_pick_caches(void)
{
	int idx;
	struct mpam_class *class;
	struct mpam_resctrl_res *res;

	idx = srcu_read_lock(&mpam_srcu);
	list_for_each_entry_rcu(class, &mpam_classes, classes_list) {
		bool has_cpor = cache_has_usable_cpor(class);

		if (class->type != MPAM_CLASS_CACHE) {
			pr_debug("pick_caches: Class is not a cache\n");
			continue;
		}

		if (class->level != 2 && class->level != 3) {
			pr_debug("pick_caches: not L2 or L3\n");
			continue;
		}

		if (class->level == 2 && !has_cpor) {
			pr_debug("pick_caches: L2 missing CPOR\n");
			continue;
		}
		else if (!has_cpor && !cache_has_usable_csu(class)) {
			pr_debug("pick_caches: Cache misses CPOR and CSU\n");
			continue;
		}

		if (!cpumask_equal(&class->affinity, cpu_possible_mask)) {
			pr_debug("pick_caches: Class has missing CPUs\n");
			continue;
		}

		if (class->level == 2) {
			res = &mpam_resctrl_exports[RDT_RESOURCE_L2];
			res->resctrl_res.name = "L2";
		} else {
			res = &mpam_resctrl_exports[RDT_RESOURCE_L3];
			res->resctrl_res.name = "L3";
		}
		res->class = class;
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

		if (class->level < 3)
			continue;

		if (!class_has_usable_mba(cprops))
			continue;

		if (!cpumask_equal(&class->affinity, cpu_possible_mask))
			continue;

		/*
		 * mba_sc reads the mbm_local counter, and waggles the MBA controls.
		 * mbm_local is implicitly part of the L3, pick a resouce to be MBA
		 * that as close as possible to the L3.
		 */
		if (!candidate_class || class->level < candidate_class->level)
			candidate_class = class;
	}
	srcu_read_unlock(&mpam_srcu, idx);

	if (candidate_class) {
		res = &mpam_resctrl_exports[RDT_RESOURCE_MBA];
		res->class = candidate_class;
		res->resctrl_res.name = "MB";
	}
}

bool resctrl_arch_is_evt_configurable(enum resctrl_event_id evt)
{
	switch (evt) {
        case QOS_L3_MBM_LOCAL_EVENT_ID:
		struct mpam_props *cprops;

		if (!mbm_local_class)
			return false;
		cprops = &mbm_local_class->props;

		return mpam_has_feature(mpam_feat_msmon_mbwu_rwbw, cprops);
	default:
		return false;
	}
}

void resctrl_arch_mon_event_config_read(void *info)
{
	struct mpam_resctrl_dom *dom;
	struct resctrl_mon_config_info *mon_info = info;

	dom = container_of(mon_info->d, struct mpam_resctrl_dom, resctrl_dom);
	mon_info->mon_config = dom->mbm_local_evt_cfg & MAX_EVT_CONFIG_BITS;
}

void resctrl_arch_mon_event_config_write(void *info)
{
	struct mpam_resctrl_dom *dom;
	struct resctrl_mon_config_info *mon_info = info;

	if (mon_info->mon_config & ~MPAM_RESTRL_EVT_CONFIG_VALID) {
		mon_info->err = -EOPNOTSUPP;
		return;
	}

	dom = container_of(mon_info->d, struct mpam_resctrl_dom, resctrl_dom);
	dom->mbm_local_evt_cfg = mon_info->mon_config & MPAM_RESTRL_EVT_CONFIG_VALID;
}

void resctrl_arch_reset_rmid_all(struct rdt_resource *r, struct rdt_domain *d)
{
	struct mpam_resctrl_dom *dom;

	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);
	dom->mbm_local_evt_cfg = MPAM_RESTRL_EVT_CONFIG_VALID;
	mpam_msmon_reset_all_mbwu(dom->comp);
}

static int mpam_resctrl_resource_init(struct mpam_resctrl_res *res)
{
	struct mpam_class *class = res->class;
	struct rdt_resource *r = &res->resctrl_res;
	bool has_mbwu = class_has_usable_mbwu(class);

	/* Is this one of the two well-known caches? */
	if (res->resctrl_res.rid == RDT_RESOURCE_L2 ||
	    res->resctrl_res.rid == RDT_RESOURCE_L3) {
		bool has_csu = cache_has_usable_csu(class);

		/* TODO: Scaling is not yet supported */
		r->cache.cbm_len = class->props.cpbm_wd;
		r->cache.arch_has_sparse_bitmasks = true;

		/* mpam_devices will reject empty bitmaps */
		r->cache.min_cbm_bits = 1;

		/* TODO: kill these properties off as they are derivatives */
		r->format_str = "%d=%0*x";
		r->fflags = RFTYPE_RES_CACHE;
		r->default_ctrl = BIT_MASK(class->props.cpbm_wd) - 1;
		r->data_width = (class->props.cpbm_wd + 3) / 4;

		/*
		 * Which bits are shared with other ...things...
		 * Unknown devices use partid-0 which uses all the bitmap
		 * fields. Until we configured the SMMU and GIC not to do this
		 * 'all the bits' is the correct answer here.
		 */
		r->cache.shareable_bits = r->default_ctrl;

		if (mpam_has_feature(mpam_feat_cpor_part, &class->props)) {
			r->alloc_capable = true;
			exposed_alloc_capable = true;
		}

		/*
		 * MBWU counters may be 'local' or 'total' depending on where
		 * they are in the topology. Counters on caches are assumed to
		 * be local. If it's on the memory controller, its assumed to
		 * be global.
		 */
		if (has_mbwu && class->level >= 3) {
			mbm_local_class = class;
			r->mon_capable = true;
		}

		/*
		 * CSU counters only make sense on a cache. The file is called
		 * llc_occupancy, but its expected to the on the L3.
		 */
		if (has_csu && class->type == MPAM_CLASS_CACHE &&
		    class->level == 3) {
			r->mon_capable = true;
		}
	} else if (res->resctrl_res.rid == RDT_RESOURCE_MBA) {
		struct mpam_props *cprops = &class->props;

		/* TODO: kill these properties off as they are derivatives */
		r->format_str = "%d=%0*u";
		r->fflags = RFTYPE_RES_MB;
		r->default_ctrl = MAX_MBA_BW;
		r->data_width = 3;

		r->membw.delay_linear = true;
		r->membw.throttle_mode = THREAD_THROTTLE_UNDEFINED;
		r->membw.bw_gran = get_mba_granularity(cprops);

		/* Round up to at least 1% */
		if (!r->membw.bw_gran)
			r->membw.bw_gran = 1;

		if (class_has_usable_mba(cprops)) {
			r->alloc_capable = true;
			exposed_alloc_capable = true;
		}

		if (has_mbwu && class->type == MPAM_CLASS_MEMORY) {
			mbm_total_class = class;
			r->mon_capable = true;
		}
	}

	if (r->mon_capable) {
		exposed_mon_capable = true;

		/*
		 * Unfortunately, num_rmid doesn't mean anything for
		 * mpam, and its exposed to user-space!
		 * num-rmid is supposed to mean the number of groups
		 * that can be created, both control or monitor groups.
		 * For mpam, each control group has its own pmg/rmid
		 * space.
		 */
		r->num_rmid = 1;
	}

	return 0;
}

int mpam_resctrl_setup(void)
{
	int err = 0;
	struct mpam_resctrl_res *res;
	enum resctrl_res_level i;

	cpus_read_lock();
	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &mpam_resctrl_exports[i];
		INIT_LIST_HEAD(&res->resctrl_res.domains);
		INIT_LIST_HEAD(&res->resctrl_res.evt_list);
		res->resctrl_res.rid = i;
	}

	mpam_resctrl_pick_caches();
	mpam_resctrl_pick_mba();
	/* TODO: mpam_resctrl_pick_counters(); */

	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &mpam_resctrl_exports[i];
		if (!res->class)
			continue;	// dummy resource

		err = mpam_resctrl_resource_init(res);
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

u32 resctrl_arch_get_config(struct rdt_resource *r, struct rdt_domain *d,
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
		return r->default_ctrl;

	res = container_of(r, struct mpam_resctrl_res, resctrl_res);
	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);
	cprops = &res->class->props;

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
		return r->default_ctrl;

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

int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_domain *d,
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

	/* NOTE: don't check the CPU as mpam_apply_config() doesn't care,
	 * and resctrl_arch_update_domains() depends on this. */
	res = container_of(r, struct mpam_resctrl_res, resctrl_res);
	dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);
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
	struct rdt_domain *d;
	enum resctrl_conf_type t;
	struct resctrl_staged_config *cfg;

	lockdep_assert_cpus_held();
	lockdep_assert_irqs_enabled();

	list_for_each_entry(d, &r->domains, list) {
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
		res = &mpam_resctrl_exports[i];

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

static struct mpam_resctrl_dom *
mpam_resctrl_alloc_domain(unsigned int cpu, struct mpam_resctrl_res *res)
{
	struct mpam_resctrl_dom *dom;
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
	INIT_LIST_HEAD(&dom->resctrl_dom.list);
	dom->resctrl_dom.id = comp->comp_id;
	dom->mbm_local_evt_cfg = MPAM_RESTRL_EVT_CONFIG_VALID;
	cpumask_set_cpu(cpu, &dom->resctrl_dom.cpu_mask);

	/* TODO: this list should be sorted */
	list_add_tail(&dom->resctrl_dom.list, &res->resctrl_res.domains);

	return dom;
}

/* Like resctrl_get_domain_from_cpu(), but for offline CPUs */
static struct mpam_resctrl_dom *
mpam_get_domain_from_cpu(int cpu, struct mpam_resctrl_res *res)
{
	struct rdt_domain *d;
	struct mpam_resctrl_dom *dom;

	lockdep_assert_cpus_held();

	list_for_each_entry(d, &res->resctrl_res.domains, list) {
		dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);

		if (cpumask_test_cpu(cpu, &dom->comp->affinity))
			return dom;
	}

	return NULL;
}

struct rdt_domain *resctrl_arch_find_domain(struct rdt_resource *r, int id)
{
	struct rdt_domain *d;
	struct mpam_resctrl_dom *dom;

	lockdep_assert_cpus_held();

	list_for_each_entry(d, &r->domains, list) {
		dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);
		if (dom->comp->comp_id == id)
			return &dom->resctrl_dom;
	}

	return NULL;
}

int mpam_resctrl_online_cpu(unsigned int cpu)
{
	int i;
	struct mpam_resctrl_dom *dom;
	struct mpam_resctrl_res *res;

	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &mpam_resctrl_exports[i];

		if (!res->class)
			continue;	// dummy_resource;

		dom = mpam_get_domain_from_cpu(cpu, res);
		if (dom) {
			cpumask_set_cpu(cpu, &dom->resctrl_dom.cpu_mask);
			continue;
		}

		dom = mpam_resctrl_alloc_domain(cpu, res);
		if (IS_ERR(dom))
			return PTR_ERR(dom);
	}

	return 0;
}

int mpam_resctrl_offline_cpu(unsigned int cpu)
{
	int i;
	struct rdt_domain *d;
	struct mpam_resctrl_res *res;
	struct mpam_resctrl_dom *dom;

	for (i = 0; i < RDT_NUM_RESOURCES; i++) {
		res = &mpam_resctrl_exports[i];

		if (!res->class)
			continue;	// dummy resource

		d = resctrl_get_domain_from_cpu(cpu, &res->resctrl_res);
		dom = container_of(d, struct mpam_resctrl_dom, resctrl_dom);

		/* The last one standing was ahead of us... */
		if (WARN_ON_ONCE(!d))
			continue;

		cpumask_clear_cpu(cpu, &d->cpu_mask);

		if (!cpumask_empty(&d->cpu_mask))
			continue;

		list_del(&d->list);
		kfree(dom);
	}

	return 0;
}
