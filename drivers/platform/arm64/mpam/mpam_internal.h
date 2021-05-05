/* SPDX-License-Identifier: GPL-2.0 */
// Copyright (C) 2024 Arm Ltd.

#ifndef MPAM_INTERNAL_H
#define MPAM_INTERNAL_H

#include <linux/arm_mpam.h>
#include <linux/cpumask.h>
#include <linux/io.h>
#include <linux/llist.h>
#include <linux/mailbox_client.h>
#include <linux/mutex.h>
#include <linux/resctrl.h>
#include <linux/sizes.h>
#include <linux/srcu.h>

/*
 * Structures protected by SRCU may not be freed for a surprising amount of
 * time (especially if perf is running). To ensure the MPAM error interrupt can
 * tear down all the structures, build a list of objects that can be gargbage
 * collected once synchronize_srcu() has returned.
 * If pdev is non-NULL, use devm_kfree().
 */
struct mpam_garbage {
	/* member of mpam_garbage */
	struct llist_node	llist;

	void			*to_free;
	struct platform_device	*pdev;
};

struct mpam_msc {
	/* member of mpam_all_msc */
	struct list_head        glbl_list;

	int			id;
	struct platform_device *pdev;

	/* Not modified after mpam_is_enabled() becomes true */
	enum mpam_msc_iface	iface;
	u32			pcc_subspace_id;
	struct mbox_client	pcc_cl;
	struct pcc_mbox_chan	*pcc_chan;
	u32			nrdy_usec;
	cpumask_t		accessibility;

	/*
	 * probe_lock is only take during discovery. After discovery these
	 * properties become read-only and the lists are protected by SRCU.
	 */
	struct mutex		probe_lock;
	unsigned long		ris_idxs[128 / BITS_PER_LONG];
	u32			ris_max;

	/* mpam_msc_ris of this component */
	struct list_head	ris;

	/*
	 * part_sel_lock protects access to the MSC hardware registers that are
	 * affected by MPAMCFG_PART_SEL. (including the ID registers that vary
	 * by RIS).
	 * If needed, take msc->lock first.
	 */
	struct mutex		part_sel_lock;

	/*
	 * mon_sel_lock protects access to the MSC hardware registers that are
	 * affeted by MPAMCFG_MON_SEL.
	 * If needed, take msc->lock first.
	 */
	struct mutex		outer_mon_sel_lock;
	raw_spinlock_t		inner_mon_sel_lock;
	unsigned long		inner_mon_sel_flags;

	void __iomem		*mapped_hwpage;
	size_t			mapped_hwpage_sz;

	struct mpam_garbage	garbage;
};

struct mpam_class {
	/* mpam_components in this class */
	struct list_head	components;

	cpumask_t		affinity;

	u8			level;
	enum mpam_class_types	type;

	/* member of mpam_classes */
	struct list_head	classes_list;

	struct mpam_garbage	garbage;
};

struct mpam_component {
	u32			comp_id;

	/* mpam_vmsc in this component */
	struct list_head	vmsc;

	cpumask_t		affinity;

	/* member of mpam_class:components */
	struct list_head	class_list;

	/* parent: */
	struct mpam_class	*class;

	struct mpam_garbage	garbage;
};

struct mpam_vmsc {
	/* member of mpam_component:vmsc_list */
	struct list_head	comp_list;

	/* mpam_msc_ris in this vmsc */
	struct list_head	ris;

	/* All RIS in this vMSC are members of this MSC */
	struct mpam_msc		*msc;

	/* parent: */
	struct mpam_component	*comp;

	struct mpam_garbage	garbage;
};

struct mpam_msc_ris {
	u8			ris_idx;

	cpumask_t		affinity;

	/* member of mpam_vmsc:ris */
	struct list_head	vmsc_list;

	/* member of mpam_msc:ris */
	struct list_head	msc_list;

	/* parent: */
	struct mpam_vmsc	*vmsc;

	struct mpam_garbage	garbage;
};

/* List of all classes - protected by srcu*/
extern struct srcu_struct mpam_srcu;
extern struct list_head mpam_classes;

int mpam_get_cpumask_from_cache_id(unsigned long cache_id, u32 cache_level,
				   cpumask_t *affinity);

#endif /* MPAM_INTERNAL_H */
