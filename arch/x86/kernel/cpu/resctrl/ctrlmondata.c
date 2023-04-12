// SPDX-License-Identifier: GPL-2.0-only
/*
 * Resource Director Technology(RDT)
 * - Cache Allocation code.
 *
 * Copyright (C) 2016 Intel Corporation
 *
 * Authors:
 *    Fenghua Yu <fenghua.yu@intel.com>
 *    Tony Luck <tony.luck@intel.com>
 *
 * More information about RDT be found in the Intel (R) x86 Architecture
 * Software Developer Manual June 2016, volume 3, section 17.17.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/cpu.h>
#include <linux/kernfs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/tick.h>

#include "internal.h"

static bool apply_config(struct rdt_hw_domain *hw_dom,
			 struct resctrl_staged_config *cfg, u32 idx,
			 cpumask_var_t cpu_mask)
{
	struct rdt_domain *dom = &hw_dom->d_resctrl;

	if (cfg->new_ctrl != hw_dom->ctrl_val[idx]) {
		cpumask_set_cpu(cpumask_any(&dom->cpu_mask), cpu_mask);
		hw_dom->ctrl_val[idx] = cfg->new_ctrl;

		return true;
	}

	return false;
}

int resctrl_arch_update_one(struct rdt_resource *r, struct rdt_domain *d,
			    u32 closid, enum resctrl_conf_type t, u32 cfg_val)
{
	struct rdt_hw_resource *hw_res = resctrl_to_arch_res(r);
	struct rdt_hw_domain *hw_dom = resctrl_to_arch_dom(d);
	u32 idx = resctrl_get_config_index(closid, t);
	struct msr_param msr_param;

	if (!cpumask_test_cpu(smp_processor_id(), &d->cpu_mask))
		return -EINVAL;

	hw_dom->ctrl_val[idx] = cfg_val;

	msr_param.res = r;
	msr_param.low = idx;
	msr_param.high = idx + 1;
	hw_res->msr_update(d, &msr_param, r);

	return 0;
}

int resctrl_arch_update_domains(struct rdt_resource *r, u32 closid)
{
	struct resctrl_staged_config *cfg;
	struct rdt_hw_domain *hw_dom;
	struct msr_param msr_param;
	enum resctrl_conf_type t;
	cpumask_var_t cpu_mask;
	struct rdt_domain *d;
	u32 idx;

	/* Walking r->domains, ensure it can't race with cpuhp */
	lockdep_assert_cpus_held();

	if (!zalloc_cpumask_var(&cpu_mask, GFP_KERNEL))
		return -ENOMEM;

	msr_param.res = NULL;
	list_for_each_entry(d, &r->domains, list) {
		hw_dom = resctrl_to_arch_dom(d);
		for (t = 0; t < CDP_NUM_TYPES; t++) {
			cfg = &hw_dom->d_resctrl.staged_config[t];
			if (!cfg->have_new_ctrl)
				continue;

			idx = resctrl_get_config_index(closid, t);
			if (!apply_config(hw_dom, cfg, idx, cpu_mask))
				continue;

			if (!msr_param.res) {
				msr_param.low = idx;
				msr_param.high = msr_param.low + 1;
				msr_param.res = r;
			} else {
				msr_param.low = min(msr_param.low, idx);
				msr_param.high = max(msr_param.high, idx + 1);
			}
		}
	}

	if (cpumask_empty(cpu_mask))
		goto done;

	/* Update resource control msr on all the CPUs. */
	on_each_cpu_mask(cpu_mask, rdt_ctrl_update, &msr_param, 1);

done:
	free_cpumask_var(cpu_mask);

	return 0;
}

u32 resctrl_arch_get_config(struct rdt_resource *r, struct rdt_domain *d,
			    u32 closid, enum resctrl_conf_type type)
{
	struct rdt_hw_domain *hw_dom = resctrl_to_arch_dom(d);
	u32 idx = resctrl_get_config_index(closid, type);

	return hw_dom->ctrl_val[idx];
}
