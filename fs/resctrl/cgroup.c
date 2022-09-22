// SPDX-License-Identifier: GPL-2.0-only
/*
 * Cgroup controller for resctrl.
 *
 * Copyright (C) 2022 ARM ltd.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sched/task.h>

#include <linux/resctrl.h>
#include "internal.h"

/*
 * Protects the closid/rmid parameters in resctrl_group.
 * Hold when reading or writing.
 */
static DEFINE_SPINLOCK(resctrl_cgroup_param_lock);

struct resctrl_cgroup {
	struct cgroup_subsys_state	css;

	u32				closid;
	u32				rmid;
};

static struct resctrl_cgroup *css_to_group(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct resctrl_cgroup, css) : NULL;
}

static struct cgroup_subsys_state *
resctrl_cgroup_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct resctrl_cgroup *group;

	group = kmalloc(sizeof(*group), GFP_KERNEL | __GFP_ZERO);
	if (!group)
		return ERR_PTR(-ENOMEM);

	return &group->css;
}

static void resctrl_cgroup_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_to_group(css));
}

static void resctrl_cgroup_task_move(struct task_struct *task)
{
	struct cgroup_subsys_state *css = task_css_check(task, resctrl_cgrp_id, true);
	struct resctrl_cgroup *group = css_to_group(css);

	if (!static_branch_unlikely(&resctrl_abi_playground))
		return;

	spin_lock(&resctrl_cgroup_param_lock);
	resctrl_arch_set_closid_rmid(task, group->closid, group->rmid);
	spin_unlock(&resctrl_cgroup_param_lock);
}

static void resctrl_cgroup_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *css;
	struct task_struct *task;

	if (!static_branch_unlikely(&resctrl_abi_playground))
		return;

	cgroup_taskset_for_each(task, css, tset)
		resctrl_cgroup_task_move(task);
}

static u64 resctrl_cgroup_id_read_u64(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct resctrl_cgroup *group = css_to_group(css);

	if (!static_branch_unlikely(&resctrl_abi_playground))
		return -EOPNOTSUPP;

	return resctrl_id_encode(group->closid, group->rmid);
}

static void resctrl_cgroup_relabel_group(struct resctrl_cgroup *group,
					 u32 closid, u32 rmid,
					 struct cpumask *dirty_cpus)
{

	struct task_struct *it_task;
	struct css_task_iter it;

	/* Update the group first to catch new tasks */
	spin_lock(&resctrl_cgroup_param_lock);
	group->closid = closid;
	group->rmid = rmid;
	spin_unlock(&resctrl_cgroup_param_lock);

	/* then re-label all the existing tasks */
	css_task_iter_start(&group->css, CSS_TASK_ITER_PROCS, &it);
	while ((it_task = css_task_iter_next(&it))) {
		resctrl_cgroup_task_move(it_task);

		/*
		 * Running tasks that got moved need to be interrupted to have
		 * the CPU settings updated. It's harmless if the CPU is updated
		 * unnecessarily.
		 */
		if (IS_ENABLED(CONFIG_SMP) && dirty_cpus && task_curr(it_task))
			cpumask_set_cpu(task_cpu(it_task), dirty_cpus);

	}
	css_task_iter_end(&it);
}

static int resctrl_cgroup_id_write_u64(struct cgroup_subsys_state *css,
				       struct cftype *cft, u64 val)
{
	struct resctrl_cgroup *group = css_to_group(css);
	cpumask_var_t dirty_cpus;
	u32 closid, rmid;
	int err;

	if (!static_branch_unlikely(&resctrl_abi_playground))
		return -EOPNOTSUPP;

	if (!zalloc_cpumask_var(&dirty_cpus, GFP_KERNEL))
		return -ENOMEM;

	err = resctrl_id_decode(val, &closid, &rmid);
	if (err)
		return err;

	resctrl_cgroup_relabel_group(group, closid, rmid, dirty_cpus);
	preempt_disable();
	smp_call_function_many(dirty_cpus, resctrl_sync_task, NULL, 1);
	preempt_enable();
	free_cpumask_var(dirty_cpus);

	return 0;
}

static int resctrl_cgroup_path_show(struct seq_file *sf, void *v)
{
	struct resctrl_cgroup *group = css_to_group(seq_css(sf));
	u32 closid, rmid;

	spin_lock(&resctrl_cgroup_param_lock);
	closid = group->closid;
	rmid = group->rmid;
	spin_unlock(&resctrl_cgroup_param_lock);

	return resctrl_rdtgroup_show(sf, closid, rmid);
}

static struct cftype resctrl_cgroup_files[] = {
	{
		.name = "id",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = resctrl_cgroup_id_read_u64,
		.write_u64 = resctrl_cgroup_id_write_u64,
	},
	{
		.name = "path",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_show = resctrl_cgroup_path_show,
	},
	{ }	/* terminate */
};


struct cgroup_subsys resctrl_cgrp_subsys = {
	.css_alloc	= resctrl_cgroup_css_alloc,
	.css_free	= resctrl_cgroup_css_free,

	/*
	 * On fork, the task's closid and rmid are inherited from the
	 * cgroup.
	 */
	.fork		= resctrl_cgroup_task_move,

	.attach		= resctrl_cgroup_attach,
	.dfl_cftypes	= resctrl_cgroup_files,
	.threaded	= true,
};

/*
 * Called by resctrl when an rdtgroup is deleted.
 * Relabel this task's group, and all it's siblings to the specified group.
 * Sets bits in dirty_cpus if a task was running on this CPU at the time of
 * the call.
 */
void resctrl_cgroup_relabel_task(struct task_struct *task,
				 u32 closid, u32 rmid, struct cpumask *dirty_cpus)
{
	struct cgroup_subsys_state *css = task_css_check(task, resctrl_cgrp_id, true);
	struct resctrl_cgroup *group = css_to_group(css);

	resctrl_cgroup_relabel_group(group, closid, rmid, dirty_cpus);
}
