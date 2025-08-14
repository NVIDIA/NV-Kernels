// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2014 Intel Corporation
 *
 * Authors:
 *	Chen, Gong <gong.chen@linux.intel.com>
 */

#include <linux/init.h>
#include <linux/ras.h>
#include <linux/uuid.h>

#define CREATE_TRACE_POINTS
#define TRACE_INCLUDE_PATH ../../include/ras
#include <ras/ras_event.h>

void log_non_standard_event(const guid_t *sec_type, const guid_t *fru_id,
			    const char *fru_text, const u8 sev, const u8 *err,
			    const u32 len)
{
	trace_non_standard_event(sec_type, fru_id, fru_text, sev, err, len);
}

void log_arm_hw_error(struct cper_sec_proc_arm *err, const u8 sev)
{
	struct cper_arm_err_info *err_info;
	struct cper_arm_ctx_info *ctx_info;
	u8 *ven_err_data;
	u32 ctx_len = 0;
	int n, sz, cpu;
	s32 vsei_len;
	u32 pei_len;
	u8 *pei_err, *ctx_err;

	pei_len = sizeof(struct cper_arm_err_info) * err->err_info_num;
	pei_err = (u8 *)(err + 1);

	err_info = (struct cper_arm_err_info *)(err + 1);
	ctx_info = (struct cper_arm_ctx_info *)(err_info + err->err_info_num);
	ctx_err = (u8 *)ctx_info;

	for (n = 0; n < err->context_info_num; n++) {
		sz = sizeof(struct cper_arm_ctx_info) + ctx_info->size;
		ctx_info = (struct cper_arm_ctx_info *)((long)ctx_info + sz);
		ctx_len += sz;
	}

	vsei_len = err->section_length - (sizeof(struct cper_sec_proc_arm) + pei_len + ctx_len);
	if (vsei_len < 0) {
		pr_warn(FW_BUG "section length: %d\n", err->section_length);
		pr_warn(FW_BUG "section length is too small\n");
		pr_warn(FW_BUG "firmware-generated error record is incorrect\n");
		vsei_len = 0;
	}
	ven_err_data = (u8 *)ctx_info;

	cpu = GET_LOGICAL_INDEX(err->mpidr);
	if (cpu < 0)
		cpu = -1;

	trace_arm_event(err, pei_err, pei_len, ctx_err, ctx_len,
			ven_err_data, (u32)vsei_len, sev, cpu);
}

static int __init ras_init(void)
{
	int rc = 0;

	ras_debugfs_init();
	rc = ras_add_daemon_trace();

	return rc;
}
subsys_initcall(ras_init);

#if defined(CONFIG_ACPI_EXTLOG) || defined(CONFIG_ACPI_EXTLOG_MODULE)
EXPORT_TRACEPOINT_SYMBOL_GPL(extlog_mem_event);
#endif
EXPORT_TRACEPOINT_SYMBOL_GPL(mc_event);
EXPORT_TRACEPOINT_SYMBOL_GPL(non_standard_event);
EXPORT_TRACEPOINT_SYMBOL_GPL(arm_event);

static int __init parse_ras_param(char *str)
{
#ifdef CONFIG_RAS_CEC
	parse_cec_param(str);
#endif

	return 1;
}
__setup("ras", parse_ras_param);
