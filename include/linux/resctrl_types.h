/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 Arm Ltd.
 * Based on arch/x86/kernel/cpu/resctrl/internal.h
 */

#ifndef __LINUX_RESCTRL_TYPES_H
#define __LINUX_RESCTRL_TYPES_H

#define CQM_LIMBOCHECK_INTERVAL	1000

#define MBM_CNTR_WIDTH_BASE		24
#define MBM_OVERFLOW_INTERVAL		1000
#define MAX_MBA_BW			100u
#define MBA_IS_LINEAR			0x4

/* rdtgroup.flags */
#define	RDT_DELETED		1

/* rftype.flags */
#define RFTYPE_FLAGS_CPUS_LIST	1

/*
 * Define the file type flags for base and info directories.
 */
#define RFTYPE_INFO			BIT(0)
#define RFTYPE_BASE			BIT(1)
#define RFTYPE_CTRL			BIT(4)
#define RFTYPE_MON			BIT(5)
#define RFTYPE_TOP			BIT(6)
#define RFTYPE_RES_CACHE		BIT(8)
#define RFTYPE_RES_MB			BIT(9)
#define RFTYPE_DEBUG			BIT(10)
#define RFTYPE_CTRL_INFO		(RFTYPE_INFO | RFTYPE_CTRL)
#define RFTYPE_MON_INFO			(RFTYPE_INFO | RFTYPE_MON)
#define RFTYPE_TOP_INFO			(RFTYPE_INFO | RFTYPE_TOP)
#define RFTYPE_CTRL_BASE		(RFTYPE_BASE | RFTYPE_CTRL)
#define RFTYPE_MON_BASE			(RFTYPE_BASE | RFTYPE_MON)

/* Reads to Local DRAM Memory */
#define READS_TO_LOCAL_MEM		BIT(0)

/* Reads to Remote DRAM Memory */
#define READS_TO_REMOTE_MEM		BIT(1)

/* Non-Temporal Writes to Local Memory */
#define NON_TEMP_WRITE_TO_LOCAL_MEM	BIT(2)

/* Non-Temporal Writes to Remote Memory */
#define NON_TEMP_WRITE_TO_REMOTE_MEM	BIT(3)

/* Reads to Local Memory the system identifies as "Slow Memory" */
#define READS_TO_LOCAL_S_MEM		BIT(4)

/* Reads to Remote Memory the system identifies as "Slow Memory" */
#define READS_TO_REMOTE_S_MEM		BIT(5)

/* Dirty Victims to All Types of Memory */
#define DIRTY_VICTIMS_TO_ALL_MEM	BIT(6)

/* Max event bits supported */
#define MAX_EVT_CONFIG_BITS		GENMASK(6, 0)

/**
 * enum resctrl_conf_type - The type of configuration.
 * @CDP_NONE:	No prioritisation, both code and data are controlled or monitored.
 * @CDP_CODE:	Configuration applies to instruction fetches.
 * @CDP_DATA:	Configuration applies to reads and writes.
 */
enum resctrl_conf_type {
	CDP_NONE,
	CDP_CODE,
	CDP_DATA,
};

enum resctrl_res_level {
	RDT_RESOURCE_L3,
	RDT_RESOURCE_L2,
	RDT_RESOURCE_MBA,
	RDT_RESOURCE_SMBA,

	/* Must be the last */
	RDT_NUM_RESOURCES,
};

#define CDP_NUM_TYPES	(CDP_DATA + 1)

/*
 * Event IDs, the values match those used to program IA32_QM_EVTSEL before
 * reading IA32_QM_CTR on RDT systems.
 */
enum resctrl_event_id {
	QOS_L3_OCCUP_EVENT_ID		= 0x01,
	QOS_L3_MBM_TOTAL_EVENT_ID	= 0x02,
	QOS_L3_MBM_LOCAL_EVENT_ID	= 0x03,
};

#endif /* __LINUX_RESCTRL_TYPES_H */
