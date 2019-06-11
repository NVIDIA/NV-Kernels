// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2021 Arm Ltd.

#define pr_fmt(fmt) "mpam: resctrl: " fmt

#include <linux/arm_mpam.h>
#include <linux/cacheinfo.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/printk.h>
#include <linux/rculist.h>
#include <linux/resctrl.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <asm/mpam.h>

#include "mpam_internal.h"

/*
 * The classes we've picked to map to resctrl resources.
 * Class pointer may be NULL.
 */
static struct mpam_resctrl_res mpam_resctrl_exports[RDT_NUM_RESOURCES];

static bool exposed_alloc_capable;
static bool exposed_mon_capable;

bool resctrl_arch_alloc_capable(void)
{
	return exposed_alloc_capable;
}

bool resctrl_arch_mon_capable(void)
{
	return exposed_mon_capable;
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

struct rdt_resource *resctrl_arch_get_resource(enum resctrl_res_level l)
{
	if (l >= RDT_NUM_RESOURCES)
		return NULL;

	return &mpam_resctrl_exports[l].resctrl_res;
}

static int mpam_resctrl_resource_init(struct mpam_resctrl_res *res)
{
	/* TODO: initialise the resctrl resources */

	return 0;
}

/* Called with the mpam classes lock held */
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

	/* TODO: pick MPAM classes to map to resctrl resources */

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
		err = resctrl_init();
	}

	return err;
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
