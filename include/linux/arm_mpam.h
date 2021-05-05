// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025 Arm Ltd. */

#ifndef __LINUX_ARM_MPAM_H
#define __LINUX_ARM_MPAM_H

#include <linux/acpi.h>
#include <linux/types.h>

struct mpam_msc;

enum mpam_msc_iface {
	MPAM_IFACE_MMIO,	/* a real MPAM MSC */
	MPAM_IFACE_PCC,		/* a fake MPAM MSC */
};

enum mpam_class_types {
	MPAM_CLASS_CACHE,       /* Well known caches, e.g. L2 */
	MPAM_CLASS_MEMORY,      /* Main memory */
	MPAM_CLASS_UNKNOWN,     /* Everything else, e.g. SMMU */
};

#ifdef CONFIG_ACPI_MPAM
/* Parse the ACPI description of resources entries for this MSC. */
int acpi_mpam_parse_resources(struct mpam_msc *msc,
			      struct acpi_mpam_msc_node *tbl_msc);

int acpi_mpam_count_msc(void);
#else
static inline int acpi_mpam_parse_resources(struct mpam_msc *msc,
					    struct acpi_mpam_msc_node *tbl_msc)
{
	return -EINVAL;
}

static inline int acpi_mpam_count_msc(void) { return -EINVAL; }
#endif

int mpam_ris_create(struct mpam_msc *msc, u8 ris_idx,
		    enum mpam_class_types type, u8 class_id, int component_id);

#endif /* __LINUX_ARM_MPAM_H */
