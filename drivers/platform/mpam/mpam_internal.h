// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2021 Arm Ltd.

#ifndef MPAM_INTERNAL_H
#define MPAM_INTERNAL_H

#include <linux/arm_mpam.h>
#include <linux/cpumask.h>
#include <linux/io.h>
#include <linux/mailbox_client.h>
#include <linux/mutex.h>
#include <linux/resctrl.h>
#include <linux/sizes.h>

struct mpam_msc
{
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

	struct mutex		lock;
	unsigned long		ris_idxs[128 / BITS_PER_LONG];
	u32			ris_max;

	/* mpam_msc_ris of this component */
	struct list_head	ris;

	/*
	 * part_sel_lock protects access to the MSC hardware registers that are
	 * affected by MPAMCFG_PART_SEL. (including the ID registers)
	 * If needed, take msc->lock first.
	 */
	spinlock_t		part_sel_lock;
	void __iomem *		mapped_hwpage;
	size_t			mapped_hwpage_sz;
};

#endif /* MPAM_INTERNAL_H */
