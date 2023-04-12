// SPDX-License-Identifier: GPL-2.0-only
/*
 * Resource Director Technology(RDT)
 * - Monitoring code
 *
 * Copyright (C) 2017 Intel Corporation
 *
 * Author:
 *    Vikas Shivappa <vikas.shivappa@intel.com>
 *
 * This replaces the cqm.c based on perf but we reuse a lot of
 * code and datastructures originally from Peter Zijlstra and Matt Fleming.
 *
 * More information about RDT be found in the Intel (R) x86 Architecture
 * Software Developer Manual June 2016, volume 3, section 17.17.
 */

#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include "internal.h"

struct rmid_entry {
	/*
	 * Some architectures's resctrl_arch_rmid_read() needs the CLOSID value
	 * in order to access the correct monitor. This field provides the
	 * value to list walkers like __check_limbo(). On x86 this is ignored.
	 */
	u32				closid;
	u32				rmid;
	int				busy;
	struct list_head		list;
};

/**
 * @rmid_free_lru    A least recently used list of free RMIDs
 *     These RMIDs are guaranteed to have an occupancy less than the
 *     threshold occupancy
 */
static LIST_HEAD(rmid_free_lru);

/**
 * @closid_num_dirty_rmid    The number of dirty RMID each CLOSID has.
 * Only allocated when CONFIG_RESCTRL_RMID_DEPENDS_ON_CLOSID is defined.
 * Indexed by CLOSID. Protected by rdtgroup_mutex.
 */
static int *closid_num_dirty_rmid;

/**
 * @rmid_limbo_count     count of currently unused but (potentially)
 *     dirty RMIDs.
 *     This counts RMIDs that no one is currently using but that
 *     may have a occupancy value > resctrl_rmid_realloc_threshold. User can
 *     change the threshold occupancy value.
 */
static unsigned int rmid_limbo_count;

/**
 * @rmid_entry - The entry in the limbo and free lists.
 */
static struct rmid_entry	*rmid_ptrs;

/*
 * This is the threshold cache occupancy in bytes at which we will consider an
 * RMID available for re-allocation.
 */
unsigned int resctrl_rmid_realloc_threshold;

/*
 * This is the maximum value for the reallocation threshold, in bytes.
 */
unsigned int resctrl_rmid_realloc_limit;

/*
 * x86 and arm64 differ in their handling of monitoring.
 * x86's RMID are an independent number, there is only one source of traffic
 * with an RMID value of '1'.
 * arm64's PMG extend the PARTID/CLOSID space, there are multiple sources of
 * traffic with a PMG value of '1', one for each CLOSID, meaning the RMID
 * value is no longer unique.
 * To account for this, resctrl uses an index. On x86 this is just the RMID,
 * on arm64 it encodes the CLOSID and RMID. This gives a unique number.
 *
 * The domain's rmid_busy_llc and rmid_ptrs[] are sized by index. The arch code
 * must accept an attempt to read every index.
 */
static inline struct rmid_entry *__rmid_entry(u32 idx)
{
	struct rmid_entry *entry;
	u32 closid, rmid;

	entry = &rmid_ptrs[idx];
	resctrl_arch_rmid_idx_decode(idx, &closid, &rmid);

	WARN_ON_ONCE(entry->closid != closid);
	WARN_ON_ONCE(entry->rmid != rmid);

	return entry;
}

static void limbo_release_entry(struct rmid_entry *entry)
{
	lockdep_assert_held(&rdtgroup_mutex);

	rmid_limbo_count--;
	list_add_tail(&entry->list, &rmid_free_lru);

	if (IS_ENABLED(CONFIG_RESCTRL_RMID_DEPENDS_ON_CLOSID))
		closid_num_dirty_rmid[entry->closid]--;
}

/*
 * Check the RMIDs that are marked as busy for this domain. If the
 * reported LLC occupancy is below the threshold clear the busy bit and
 * decrement the count. If the busy count gets to zero on an RMID, we
 * free the RMID
 */
void __check_limbo(struct rdt_domain *d, bool force_free)
{
	struct rdt_resource *r = resctrl_arch_get_resource(RDT_RESOURCE_L3);
	u32 idx_limit = resctrl_arch_system_num_rmid_idx();
	struct rmid_entry *entry;
	u32 idx, cur_idx = 1;
	void *arch_mon_ctx;
	bool rmid_dirty;
	u64 val = 0;

	arch_mon_ctx = resctrl_arch_mon_ctx_alloc(r, QOS_L3_OCCUP_EVENT_ID);
	if (IS_ERR(arch_mon_ctx))
		return;

	/*
	 * Skip RMID 0 and start from RMID 1 and check all the RMIDs that
	 * are marked as busy for occupancy < threshold. If the occupancy
	 * is less than the threshold decrement the busy counter of the
	 * RMID and move it to the free list when the counter reaches 0.
	 */
	for (;;) {
		idx = find_next_bit(d->rmid_busy_llc, idx_limit, cur_idx);
		if (idx >= idx_limit)
			break;

		entry = __rmid_entry(idx);
		if (resctrl_arch_rmid_read(r, d, entry->closid, entry->rmid,
					   QOS_L3_OCCUP_EVENT_ID, &val,
					   arch_mon_ctx)) {
			rmid_dirty = true;
		} else {
			rmid_dirty = (val >= resctrl_rmid_realloc_threshold);
		}

		if (force_free || !rmid_dirty) {
			clear_bit(idx, d->rmid_busy_llc);
			if (!--entry->busy)
				limbo_release_entry(entry);
		}
		cur_idx = idx + 1;
	}

	resctrl_arch_mon_ctx_free(r, QOS_L3_OCCUP_EVENT_ID, arch_mon_ctx);
}

bool has_busy_rmid(struct rdt_domain *d)
{
	u32 idx_limit = resctrl_arch_system_num_rmid_idx();

	return find_first_bit(d->rmid_busy_llc, idx_limit) != idx_limit;
}

static struct rmid_entry *resctrl_find_free_rmid(u32 closid)
{
	struct rmid_entry *itr;
	u32 itr_idx, cmp_idx;

	if (list_empty(&rmid_free_lru))
		return rmid_limbo_count ? ERR_PTR(-EBUSY) : ERR_PTR(-ENOSPC);

	list_for_each_entry(itr, &rmid_free_lru, list) {
		/*
		 * Get the index of this free RMID, and the index it would need
		 * to be if it were used with this CLOSID.
		 * If the CLOSID is irrelevant on this architecture, these will
		 * always be the same meaning the compiler can reduce this loop
		 * to a single list_entry_first() call.
		 */
		itr_idx = resctrl_arch_rmid_idx_encode(itr->closid, itr->rmid);
		cmp_idx = resctrl_arch_rmid_idx_encode(closid, itr->rmid);

		if (itr_idx == cmp_idx)
			return itr;
	}

	return ERR_PTR(-ENOSPC);
}

/**
 * resctrl_find_cleanest_closid() - Find a CLOSID where all the associated
 *                                  RMID are clean, or the CLOSID that has
 *                                  the most clean RMID.
 *
 * MPAM's equivalent of RMID are per-CLOSID, meaning a freshly allocated CLOSID
 * may not be able to allocate clean RMID. To avoid this the allocator will
 * choose the CLOSID with the most clean RMID.
 *
 * When the CLOSID and RMID are independent numbers, the first free CLOSID will
 * be returned.
 */
int resctrl_find_cleanest_closid(void)
{
	u32 cleanest_closid = ~0, iter_num_dirty;
	int i = 0;

	lockdep_assert_held(&rdtgroup_mutex);

	if (!IS_ENABLED(CONFIG_RESCTRL_RMID_DEPENDS_ON_CLOSID))
		return -EIO;

	for (i = 0; i < closids_supported(); i++) {
		if (closid_allocated(i))
			continue;

		iter_num_dirty = closid_num_dirty_rmid[i];
		if (iter_num_dirty == 0)
			return i;

		if (cleanest_closid == ~0)
			cleanest_closid = i;

		if (iter_num_dirty < closid_num_dirty_rmid[cleanest_closid])
			cleanest_closid = i;
	}

	if (cleanest_closid == ~0)
		return -ENOSPC;
	return cleanest_closid;
}

/*
 * For MPAM the RMID value is not unique, and has to be considered with
 * the CLOSID. The (CLOSID, RMID) pair is allocated on all domains, which
 * allows all domains to be managed by a single limbo list.
 * Each domain also has a rmid_busy_llc to reduce the work of the limbo handler.
 */
int alloc_rmid(u32 closid)
{
	struct rmid_entry *entry;

	lockdep_assert_held(&rdtgroup_mutex);

	entry = resctrl_find_free_rmid(closid);
	if (IS_ERR(entry))
		return PTR_ERR(entry);

	list_del(&entry->list);
	return entry->rmid;
}

static void add_rmid_to_limbo(struct rmid_entry *entry)
{
	struct rdt_resource *r = resctrl_arch_get_resource(RDT_RESOURCE_L3);
	struct rdt_domain *d;
	u32 idx;

	lockdep_assert_held(&rdtgroup_mutex);

	/* Walking r->domains, ensure it can't race with cpuhp */
	lockdep_assert_cpus_held();

	idx = resctrl_arch_rmid_idx_encode(entry->closid, entry->rmid);

	entry->busy = 0;
	list_for_each_entry(d, &r->domains, list) {
		/*
		 * For the first limbo RMID in the domain,
		 * setup up the limbo worker.
		 */
		if (!has_busy_rmid(d))
			cqm_setup_limbo_handler(d, CQM_LIMBOCHECK_INTERVAL,
						RESCTRL_PICK_ANY_CPU);
		set_bit(idx, d->rmid_busy_llc);
		entry->busy++;
	}

	rmid_limbo_count++;
	if (IS_ENABLED(CONFIG_RESCTRL_RMID_DEPENDS_ON_CLOSID))
		closid_num_dirty_rmid[entry->closid]++;
}

void free_rmid(u32 closid, u32 rmid)
{
	u32 idx = resctrl_arch_rmid_idx_encode(closid, rmid);
	struct rmid_entry *entry;

	lockdep_assert_held(&rdtgroup_mutex);

	/* do not allow the default rmid to be free'd */
	if (idx == resctrl_arch_rmid_idx_encode(RESCTRL_RESERVED_CLOSID,
						RESCTRL_RESERVED_RMID))
		return;

	entry = __rmid_entry(idx);

	if (resctrl_arch_is_llc_occupancy_enabled())
		add_rmid_to_limbo(entry);
	else
		list_add_tail(&entry->list, &rmid_free_lru);
}

static struct mbm_state *get_mbm_state(struct rdt_domain *d, u32 closid,
				       u32 rmid, enum resctrl_event_id evtid)
{
	u32 idx = resctrl_arch_rmid_idx_encode(closid, rmid);

	switch (evtid) {
	case QOS_L3_MBM_TOTAL_EVENT_ID:
		return &d->mbm_total[idx];
	case QOS_L3_MBM_LOCAL_EVENT_ID:
		return &d->mbm_local[idx];
	default:
		return NULL;
	}
}

static int __mon_event_count(u32 closid, u32 rmid, struct rmid_read *rr)
{
	struct mbm_state *m;
	u64 tval = 0;

	if (rr->first) {
		resctrl_arch_reset_rmid(rr->r, rr->d, closid, rmid, rr->evtid);
		m = get_mbm_state(rr->d, closid, rmid, rr->evtid);
		if (m)
			memset(m, 0, sizeof(struct mbm_state));
		return 0;
	}

	rr->err = resctrl_arch_rmid_read(rr->r, rr->d, closid, rmid, rr->evtid,
					 &tval, rr->arch_mon_ctx);
	if (rr->err)
		return rr->err;

	rr->val += tval;

	return 0;
}

/*
 * mbm_bw_count() - Update bw count from values previously read by
 *		    __mon_event_count().
 * @rmid:	The rmid used to identify the cached mbm_state.
 * @rr:		The struct rmid_read populated by __mon_event_count().
 *
 * Supporting function to calculate the memory bandwidth
 * and delta bandwidth in MBps. The chunks value previously read by
 * __mon_event_count() is compared with the chunks value from the previous
 * invocation. This must be called once per second to maintain values in MBps.
 */
static void mbm_bw_count(u32 closid, u32 rmid, struct rmid_read *rr)
{
	u32 idx = resctrl_arch_rmid_idx_encode(closid, rmid);
	struct mbm_state *m = &rr->d->mbm_local[idx];
	u64 cur_bw, bytes, cur_bytes;

	cur_bytes = rr->val;
	bytes = cur_bytes - m->prev_bw_bytes;
	m->prev_bw_bytes = cur_bytes;

	cur_bw = bytes / SZ_1M;

	if (m->delta_comp)
		m->delta_bw = abs(cur_bw - m->prev_bw);
	m->delta_comp = false;
	m->prev_bw = cur_bw;
}

/*
 * This is scheduled by mon_event_read() to read the CQM/MBM counters
 * on a domain.
 */
void mon_event_count(void *info)
{
	struct rdtgroup *rdtgrp, *entry;
	struct rmid_read *rr = info;
	struct list_head *head;
	int ret;

	rdtgrp = rr->rgrp;

	ret = __mon_event_count(rdtgrp->closid, rdtgrp->mon.rmid, rr);

	/*
	 * For Ctrl groups read data from child monitor groups and
	 * add them together. Count events which are read successfully.
	 * Discard the rmid_read's reporting errors.
	 */
	head = &rdtgrp->mon.crdtgrp_list;

	if (rdtgrp->type == RDTCTRL_GROUP) {
		list_for_each_entry(entry, head, mon.crdtgrp_list) {
			if (__mon_event_count(rdtgrp->closid, entry->mon.rmid,
					      rr) == 0)
				ret = 0;
		}
	}

	/*
	 * __mon_event_count() calls for newly created monitor groups may
	 * report -EINVAL/Unavailable if the monitor hasn't seen any traffic.
	 * Discard error if any of the monitor event reads succeeded.
	 */
	if (ret == 0)
		rr->err = 0;
}

/*
 * Feedback loop for MBA software controller (mba_sc)
 *
 * mba_sc is a feedback loop where we periodically read MBM counters and
 * adjust the bandwidth percentage values via the IA32_MBA_THRTL_MSRs so
 * that:
 *
 *   current bandwidth(cur_bw) < user specified bandwidth(user_bw)
 *
 * This uses the MBM counters to measure the bandwidth and MBA throttle
 * MSRs to control the bandwidth for a particular rdtgrp. It builds on the
 * fact that resctrl rdtgroups have both monitoring and control.
 *
 * The frequency of the checks is 1s and we just tag along the MBM overflow
 * timer. Having 1s interval makes the calculation of bandwidth simpler.
 *
 * Although MBA's goal is to restrict the bandwidth to a maximum, there may
 * be a need to increase the bandwidth to avoid unnecessarily restricting
 * the L2 <-> L3 traffic.
 *
 * Since MBA controls the L2 external bandwidth where as MBM measures the
 * L3 external bandwidth the following sequence could lead to such a
 * situation.
 *
 * Consider an rdtgroup which had high L3 <-> memory traffic in initial
 * phases -> mba_sc kicks in and reduced bandwidth percentage values -> but
 * after some time rdtgroup has mostly L2 <-> L3 traffic.
 *
 * In this case we may restrict the rdtgroup's L2 <-> L3 traffic as its
 * throttle MSRs already have low percentage values.  To avoid
 * unnecessarily restricting such rdtgroups, we also increase the bandwidth.
 */
static void update_mba_bw(struct rdtgroup *rgrp, struct rdt_domain *dom_mbm)
{
	u32 closid, rmid, cur_msr_val, new_msr_val;
	struct mbm_state *pmbm_data, *cmbm_data;
	u32 cur_bw, delta_bw, user_bw, idx;
	struct rdt_resource *r_mba;
	struct rdt_domain *dom_mba;
	struct list_head *head;
	struct rdtgroup *entry;

	if (!resctrl_arch_is_mbm_local_enabled())
		return;

	r_mba = resctrl_arch_get_resource(RDT_RESOURCE_MBA);

	closid = rgrp->closid;
	rmid = rgrp->mon.rmid;
	idx = resctrl_arch_rmid_idx_encode(closid, rmid);
	pmbm_data = &dom_mbm->mbm_local[idx];

	dom_mba = resctrl_get_domain_from_cpu(smp_processor_id(), r_mba);
	if (!dom_mba) {
		pr_warn_once("Failure to get domain for MBA update\n");
		return;
	}

	cur_bw = pmbm_data->prev_bw;
	user_bw = dom_mba->mbps_val[closid];
	delta_bw = pmbm_data->delta_bw;

	/* MBA resource doesn't support CDP */
	cur_msr_val = resctrl_arch_get_config(r_mba, dom_mba, closid, CDP_NONE);

	/*
	 * For Ctrl groups read data from child monitor groups.
	 */
	head = &rgrp->mon.crdtgrp_list;
	list_for_each_entry(entry, head, mon.crdtgrp_list) {
		cmbm_data = &dom_mbm->mbm_local[entry->mon.rmid];
		cur_bw += cmbm_data->prev_bw;
		delta_bw += cmbm_data->delta_bw;
	}

	/*
	 * Scale up/down the bandwidth linearly for the ctrl group.  The
	 * bandwidth step is the bandwidth granularity specified by the
	 * hardware.
	 *
	 * The delta_bw is used when increasing the bandwidth so that we
	 * dont alternately increase and decrease the control values
	 * continuously.
	 *
	 * For ex: consider cur_bw = 90MBps, user_bw = 100MBps and if
	 * bandwidth step is 20MBps(> user_bw - cur_bw), we would keep
	 * switching between 90 and 110 continuously if we only check
	 * cur_bw < user_bw.
	 */
	if (cur_msr_val > r_mba->membw.min_bw && user_bw < cur_bw) {
		new_msr_val = cur_msr_val - r_mba->membw.bw_gran;
	} else if (cur_msr_val < MAX_MBA_BW &&
		   (user_bw > (cur_bw + delta_bw))) {
		new_msr_val = cur_msr_val + r_mba->membw.bw_gran;
	} else {
		return;
	}

	resctrl_arch_update_one(r_mba, dom_mba, closid, CDP_NONE, new_msr_val);

	/*
	 * Delta values are updated dynamically package wise for each
	 * rdtgrp every time the throttle MSR changes value.
	 *
	 * This is because (1)the increase in bandwidth is not perfectly
	 * linear and only "approximately" linear even when the hardware
	 * says it is linear.(2)Also since MBA is a core specific
	 * mechanism, the delta values vary based on number of cores used
	 * by the rdtgrp.
	 */
	pmbm_data->delta_comp = true;
	list_for_each_entry(entry, head, mon.crdtgrp_list) {
		cmbm_data = &dom_mbm->mbm_local[entry->mon.rmid];
		cmbm_data->delta_comp = true;
	}
}

static void mbm_update(struct rdt_resource *r, struct rdt_domain *d,
		       u32 closid, u32 rmid)
{
	struct rmid_read rr;

	rr.first = false;
	rr.r = r;
	rr.d = d;

	/*
	 * This is protected from concurrent reads from user
	 * as both the user and we hold the global mutex.
	 */
	if (resctrl_arch_is_mbm_total_enabled()) {
		rr.evtid = QOS_L3_MBM_TOTAL_EVENT_ID;
		rr.val = 0;
		rr.arch_mon_ctx = resctrl_arch_mon_ctx_alloc(rr.r, rr.evtid);
		if (IS_ERR(rr.arch_mon_ctx))
			return;

		__mon_event_count(closid, rmid, &rr);

		resctrl_arch_mon_ctx_free(rr.r, rr.evtid, rr.arch_mon_ctx);
	}
	if (resctrl_arch_is_mbm_local_enabled()) {
		rr.evtid = QOS_L3_MBM_LOCAL_EVENT_ID;
		rr.val = 0;
		rr.arch_mon_ctx = resctrl_arch_mon_ctx_alloc(rr.r, rr.evtid);
		if (IS_ERR(rr.arch_mon_ctx))
			return;

		__mon_event_count(closid, rmid, &rr);

		/*
		 * Call the MBA software controller only for the
		 * control groups and when user has enabled
		 * the software controller explicitly.
		 */
		if (is_mba_sc(NULL))
			mbm_bw_count(closid, rmid, &rr);
		resctrl_arch_mon_ctx_free(rr.r, rr.evtid, rr.arch_mon_ctx);
	}
}

/*
 * Handler to scan the limbo list and move the RMIDs
 * to free list whose occupancy < threshold_occupancy.
 */
void cqm_handle_limbo(struct work_struct *work)
{
	unsigned long delay = msecs_to_jiffies(CQM_LIMBOCHECK_INTERVAL);
	struct rdt_resource *r;
	struct rdt_domain *d;
	int cpu;

	mutex_lock(&rdtgroup_mutex);

	r = resctrl_arch_get_resource(RDT_RESOURCE_L3);
	d = container_of(work, struct rdt_domain, cqm_limbo.work);

	__check_limbo(d, false);

	if (has_busy_rmid(d)) {
		cpu = cpumask_any_housekeeping(&d->cpu_mask);
		schedule_delayed_work_on(cpu, &d->cqm_limbo, delay);
	}

	mutex_unlock(&rdtgroup_mutex);
}

/**
 * cqm_setup_limbo_handler() - Schedule the limbo handler to run for this
 *                             domain.
 * @delay_ms:      How far in the future the handler should run.
 * @exclude_cpu:   Which CPU the handler should not run on,
 *		   RESCTRL_PICK_ANY_CPU to pick any CPU.
 */
void cqm_setup_limbo_handler(struct rdt_domain *dom, unsigned long delay_ms,
			     int exclude_cpu)
{
	unsigned long delay = msecs_to_jiffies(delay_ms);
	int cpu;

	if (exclude_cpu == RESCTRL_PICK_ANY_CPU)
		cpu = cpumask_any_housekeeping(&dom->cpu_mask);
	else
		cpu = cpumask_any_housekeeping_but(&dom->cpu_mask,
						   exclude_cpu);
	dom->cqm_work_cpu = cpu;

	if (cpu < nr_cpu_ids)
		schedule_delayed_work_on(cpu, &dom->cqm_limbo, delay);
}

void mbm_handle_overflow(struct work_struct *work)
{
	unsigned long delay = msecs_to_jiffies(MBM_OVERFLOW_INTERVAL);
	struct rdtgroup *prgrp, *crgrp;
	struct list_head *head;
	struct rdt_resource *r;
	struct rdt_domain *d;
	int cpu;

	mutex_lock(&rdtgroup_mutex);

	/*
	 * If the filesystem has been unmounted this work no longer needs to
	 * run.
	 */
	if (!resctrl_mounted || !resctrl_arch_mon_capable())
		goto out_unlock;

	r = resctrl_arch_get_resource(RDT_RESOURCE_L3);
	d = container_of(work, struct rdt_domain, mbm_over.work);

	list_for_each_entry(prgrp, &rdt_all_groups, rdtgroup_list) {
		mbm_update(r, d, prgrp->closid, prgrp->mon.rmid);

		head = &prgrp->mon.crdtgrp_list;
		list_for_each_entry(crgrp, head, mon.crdtgrp_list)
			mbm_update(r, d, crgrp->closid, crgrp->mon.rmid);

		if (is_mba_sc(NULL))
			update_mba_bw(prgrp, d);
	}

	/*
	 * Re-check for housekeeping CPUs. This allows the overflow handler to
	 * move off a nohz_full CPU quickly.
	 */
	cpu = cpumask_any_housekeeping(&d->cpu_mask);
	schedule_delayed_work_on(cpu, &d->mbm_over, delay);

out_unlock:
	mutex_unlock(&rdtgroup_mutex);
}

/**
 * mbm_setup_overflow_handler() - Schedule the overflow handler to run for this
 *                                domain.
 * @delay_ms:      How far in the future the handler should run.
 * @exclude_cpu:   Which CPU the handler should not run on,
 *		   RESCTRL_PICK_ANY_CPU to pick any CPU.
 */
void mbm_setup_overflow_handler(struct rdt_domain *dom, unsigned long delay_ms,
				int exclude_cpu)
{
	unsigned long delay = msecs_to_jiffies(delay_ms);
	int cpu;

	/*
	 * When a domain comes online there is no guarantee the filesystem is
	 * mounted. If not, there is no need to catch counter overflow.
	 */
	if (!resctrl_mounted || !resctrl_arch_mon_capable())
		return;
	if (exclude_cpu == RESCTRL_PICK_ANY_CPU)
		cpu = cpumask_any_housekeeping(&dom->cpu_mask);
	else
		cpu = cpumask_any_housekeeping_but(&dom->cpu_mask,
						   exclude_cpu);
	dom->mbm_work_cpu = cpu;

	if (cpu < nr_cpu_ids)
		schedule_delayed_work_on(cpu, &dom->mbm_over, delay);
}

static int dom_data_init(struct rdt_resource *r)
{
	u32 idx_limit = resctrl_arch_system_num_rmid_idx();
	u32 num_closid = resctrl_arch_get_num_closid(r);
	struct rmid_entry *entry = NULL;
	u32 idx;
	int i;

	if (IS_ENABLED(CONFIG_RESCTRL_RMID_DEPENDS_ON_CLOSID)) {
		int *tmp;

		tmp = kcalloc(num_closid, sizeof(int), GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;

		mutex_lock(&rdtgroup_mutex);
		closid_num_dirty_rmid = tmp;
		mutex_unlock(&rdtgroup_mutex);
	}

	rmid_ptrs = kcalloc(idx_limit, sizeof(struct rmid_entry), GFP_KERNEL);
	if (!rmid_ptrs) {
		kfree(closid_num_dirty_rmid);
		return -ENOMEM;
	}

	for (i = 0; i < idx_limit; i++) {
		entry = &rmid_ptrs[i];
		INIT_LIST_HEAD(&entry->list);

		resctrl_arch_rmid_idx_decode(i, &entry->closid, &entry->rmid);
		list_add_tail(&entry->list, &rmid_free_lru);
	}

	/*
	 * CLOSID 0 and RMID 0 are special and are always allocated. These are
	 * used for rdtgroup_default control group, which will be setup later.
	 * See rdtgroup_setup_root().
	 */
	idx = resctrl_arch_rmid_idx_encode(RESCTRL_RESERVED_CLOSID,
					   RESCTRL_RESERVED_RMID);
	entry = __rmid_entry(idx);
	list_del(&entry->list);

	return 0;
}

static struct mon_evt llc_occupancy_event = {
	.name		= "llc_occupancy",
	.evtid		= QOS_L3_OCCUP_EVENT_ID,
};

static struct mon_evt mbm_total_event = {
	.name		= "mbm_total_bytes",
	.evtid		= QOS_L3_MBM_TOTAL_EVENT_ID,
};

static struct mon_evt mbm_local_event = {
	.name		= "mbm_local_bytes",
	.evtid		= QOS_L3_MBM_LOCAL_EVENT_ID,
};

/*
 * Initialize the event list for the resource.
 *
 * Note that MBM events are also part of RDT_RESOURCE_L3 resource
 * because as per the SDM the total and local memory bandwidth
 * are enumerated as part of L3 monitoring.
 */
static void l3_mon_evt_init(struct rdt_resource *r)
{
	INIT_LIST_HEAD(&r->evt_list);

	if (resctrl_arch_is_llc_occupancy_enabled())
		list_add_tail(&llc_occupancy_event.list, &r->evt_list);
	if (resctrl_arch_is_mbm_total_enabled())
		list_add_tail(&mbm_total_event.list, &r->evt_list);
	if (resctrl_arch_is_mbm_local_enabled())
		list_add_tail(&mbm_local_event.list, &r->evt_list);
}

int resctrl_mon_resource_init(void)
{
	struct rdt_resource *r = resctrl_arch_get_resource(RDT_RESOURCE_L3);
	int ret;

	ret = dom_data_init(r);
	if (ret)
		return ret;

	if (!r->mon_capable)
		return 0;

	l3_mon_evt_init(r);

	if (resctrl_arch_is_evt_configurable(QOS_L3_MBM_TOTAL_EVENT_ID)) {
		mbm_total_event.configurable = true;
		mbm_config_rftype_init("mbm_total_bytes_config");
	}
	if (resctrl_arch_is_evt_configurable(QOS_L3_MBM_LOCAL_EVENT_ID)) {
		mbm_local_event.configurable = true;
		mbm_config_rftype_init("mbm_local_bytes_config");
	}

	return 0;
}
