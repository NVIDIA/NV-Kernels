/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 MediaTek Inc.
 */
#ifndef __MTK_PWRAP_H__
#define __MTK_PWRAP_H__

#include <linux/acpi.h>
#include <linux/platform_device.h>

#include "pwrap_scmi.h"
#include <linux/soc/mediatek/mtk-pwrap.h>

#define PWRAP_MAX_COMP_NUM 20
/* Number of scalar constraint fields before the comp_states array */
#define PWRAP_IDLE_CONSTRAINT_SCALARS  3

/*
 * Max length of a normalized ACPI device path string.
 * The longest path on MT8901 is "\_SB_.PCI2.RP0_.NVM_" (20 chars);
 * 64 leaves ample headroom for deeper hierarchies.
 */
#define PWRAP_DEV_PATH_MAX 64

extern const guid_t pwrap_dsm_dpm_uuid;

enum pwrap_control_type {
	CTRL_NONE     = 0,
	CTRL_BY_PWRAP = 1,
	CTRL_BY_SCMI  = 2,
};

enum pwrap_dsm_dpm_func_rev {
	DSM_DPM_REV_0 = 0,
};

enum pwrap_dsm_dpm_func_idx {
	DSM_DPM_GET_SUPPORT_FUNC = 0,
	DSM_DPM_GET_DEV_CTRL_INFO,
};

enum pwrap_dsm_dpm_dpmt_idx {
	DSM_DPM_DPMT_REV = 0,
	DSM_DPM_DPMT_COUNT,
	DSM_DPM_DPMT_DCFG,
};

/*
 * Field layout of one device package inside the DPMT (DSM_DPM_DPMT_DCFG+).
 * ASL (Cpu.asl, UUID 64B66B51, Case 1):
 *   Package(){ "<path>", "<type>", Package(){constraints}, <control_type> }
 */
enum pwrap_dpm_dev_pkg_idx {
	DPM_DEV_PATH = 0,
	DPM_DEV_TYPE,
	DPM_DEV_CONSTRAINTS,
	DPM_DEV_CONTROL_TYPE,
	DPM_DEV_PKG_COUNT,
};

struct pwrap_idle_constraints {
	union {
		struct {
			u64 enable;
			u64 device_state;
			u64 comp_count;
			u64 comp_states[PWRAP_MAX_COMP_NUM];
		};
		u64 values[PWRAP_MAX_COMP_NUM + 3];
	};
};

/* Device configuration data structure */
struct pwrap_dev_config {
	char *device_path;
	char *device_type;
	struct pwrap_idle_constraints constraints;
	enum pwrap_control_type control_type;
	struct pwrap_scmi_config scmi_config;
};

/* Device control structure */
struct pwrap_dev_ctrl {
	u64 revision;
	u64 count;
	struct pwrap_dev_config *configs;
};

struct mtk_pwrap_device {
	const char *name;
	unsigned int dev_id;
};

/* Driver private data */
struct pwrap_driver_data {
	struct device *dev;
	//struct pwrap_dev_ctrl dev_ctrl;
	struct platform_device *pdev;
	struct acpi_buffer acpi_path;
};

/* Create the sysfs debug/test nodes (non-fatal; group is devm-managed) */
int pwrap_create_sys_files(struct platform_device *pdev);

/* Getter for static pwrap_dev_ctrl */
struct pwrap_dev_ctrl *pwrap_get_dev_ctrl(void);
void *pwrap_query_dev_config(const char *dev_path);

/* ============================================================
 * DPM device-control config from ACPI (UUID 64B66B51)
 * ============================================================
 *
 * Implemented in acpiutil.c. Declared here because they operate on
 * struct pwrap_dev_ctrl / pwrap_scmi_config, which are defined above.
 */

/**
 * pwrap_acpi_normalize_path() - Pad ACPI NameSegs to 4 chars with '_'
 * @in:  source path as written in the _DSM literal (e.g. "\\_SB.DSP1")
 * @out: destination buffer of size @out_sz (>= PWRAP_DEV_PATH_MAX)
 * @out_sz: size of @out
 *
 * ACPI NameSegs are fixed 4 bytes, short names trailing-padded with '_'
 * (ACPI spec 19.2.2 / 5.3). acpi_get_name(ACPI_FULL_PATHNAME) emits the
 * padded form, but _DSM string literals are unpadded. Normalizing makes
 * the fetched path match the keys used by pwrap_query_dev_config().
 *
 * Return: 0 on success, -EINVAL on bad input, -ENOSPC if too long.
 */
int pwrap_acpi_normalize_path(const char *in, char *out, size_t out_sz);

/**
 * pwrap_acpi_fetch_dpm_config() - Populate pwrap_dev_ctrl from DPM _DSM
 * @dev:  PEPD ACPI device
 * @ctrl: device-control table to fill (configs[] is kalloc'd here)
 *
 * Evaluates UUID 64B66B51 function 1 (DPMT), parses every device package
 * (path/type/constraints/control_type), normalizes the path, and for
 * CTRL_BY_SCMI devices fetches the per-device SCMI dev_id via GDSC().
 *
 * Return: 0 on success, negative errno on failure.
 */
int pwrap_acpi_fetch_dpm_config(struct device *dev,
				struct pwrap_dev_ctrl *ctrl);

/**
 * pwrap_acpi_dpm_config_free() - Free a pwrap_dev_ctrl built from ACPI
 * @ctrl: table previously filled by pwrap_acpi_fetch_dpm_config()
 *
 * Frees each kstrdup'd device_path/device_type and the configs[] array.
 */
void pwrap_acpi_dpm_config_free(struct pwrap_dev_ctrl *ctrl);

#endif
