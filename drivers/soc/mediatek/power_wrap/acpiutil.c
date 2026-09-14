// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 MediaTek Inc.
 *
 * acpiutil.c - ACPI utility functions for power_wrap driver
 *
 * This module builds the device-control (DPM) table from the PEPD
 * device's ACPI _DSM method (UUID 64B66B51), including the per-device
 * SCMI dev_id fetched via GDSC().
 */

#include <linux/acpi.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "power_wrap.h"

/* ACPI NameSeg is always exactly 4 characters, trailing-padded with '_' */
#define PWRAP_ACPI_NAMESEG_LEN  4

/* ============================================================
 * DPM UUID (64B66B51) - Device-control config from ACPI
 * ============================================================
 *
 * Builds the device-control table at probe by parsing the DPMT package
 * returned by UUID 64B66B51 function 1 (Case 1 in Cpu.asl).
 *
 * Note: the DPMT package does NOT carry the per-device SCMI dev_id; that
 * lives in a separate ASL method, GDSC(path), which writes the global
 * SRTP package. So for CTRL_BY_SCMI devices we make a second ACPI call to
 * GDSC() to obtain dev_id.
 */

/* GDSC return package (SRTP) layout - see Cpu.asl Name(SRTP, ...) */
enum pwrap_gdsc_srtp_idx {
	GDSC_SRTP_FEAT_ID = 0,	/* SCMI feature id (0x0D; 0xFFFFFFFF = unsupported) */
	GDSC_SRTP_DEV_ID,	/* SCMI device id (the per-device value we need) */
	GDSC_SRTP_PREPARE,	/* Package(4): prepare action payloads */
	GDSC_SRTP_DSTATE,	/* Package(4): d-state action payloads */
	GDSC_SRTP_FSTATE,	/* Package(4): f-state action payloads */
	GDSC_SRTP_REQ,		/* Package(4): request action payloads */
	GDSC_SRTP_ABANDON,	/* Package(4): abandon action payloads */
	GDSC_SRTP_COUNT,
};

#define GDSC_FEAT_ID_UNSUPPORTED	0xFFFFFFFFU

/*
 * pwrap_acpi_normalize_path() - Pad ACPI NameSegs to 4 chars with '_'
 *
 * ACPI NameSegs are fixed at 4 bytes; names shorter than 4 chars are
 * trailing-padded with '_' (ACPI spec 19.2.2 / 5.3). The kernel's
 * acpi_get_name(ACPI_FULL_PATHNAME) - used to key device lookups - emits
 * the padded form ("\_SB_.PCI0.RP0_"), but the _DSM string literals are
 * written unpadded ("\_SB.PCI0.RP0"). Normalizing makes the two agree.
 *
 * Leading root '\' and parent '^' prefix chars are copied verbatim; each
 * '.'-separated NameSeg is then padded to 4 chars.
 */
int pwrap_acpi_normalize_path(const char *in, char *out, size_t out_sz)
{
	size_t o = 0;
	const char *p = in;

	if (!in || !out || out_sz == 0)
		return -EINVAL;

	/* Copy leading root/parent prefix ('\' and any '^') verbatim. */
	while (*p == '\\' || *p == '^') {
		if (o + 1 >= out_sz)
			return -ENOSPC;
		out[o++] = *p++;
	}

	/* Process each '.'-separated NameSeg, padding short ones to 4. */
	while (*p) {
		size_t seg_len = strcspn(p, ".");
		size_t pad = (seg_len < PWRAP_ACPI_NAMESEG_LEN) ?
			     (PWRAP_ACPI_NAMESEG_LEN - seg_len) : 0;

		if (o + seg_len + pad + 1 >= out_sz)
			return -ENOSPC;

		memcpy(&out[o], p, seg_len);
		o += seg_len;
		while (pad--)
			out[o++] = '_';

		p += seg_len;
		if (*p == '.') {
			out[o++] = '.';
			p++;
		}
	}

	out[o] = '\0';
	return 0;
}

/*
 * pwrap_acpi_fetch_scmi_dev_id() - Get per-device SCMI dev_id via GDSC()
 * @dev:        PEPD ACPI device
 * @raw_path:   UNPADDED device path as it appears in the _DSM literal
 *              (GDSC's ASL ElseIf compares against unpadded names)
 * @dev_id_out: receives the SCMI device id on success
 *
 * Evaluates \_SB.PEPD.GDSC(raw_path), which returns the SRTP package
 * {feat_id, dev_id, <5 action payload packages>}. We only consume dev_id;
 * feat_id and the action IDs are invariant and supplied by SCMI_CONFIG_INIT().
 *
 * Return: 0 on success, -ENODEV if the firmware reports the path as
 * unsupported (feat_id == 0xFFFFFFFF), negative errno otherwise.
 */
static int pwrap_acpi_fetch_scmi_dev_id(struct device *dev,
					const char *raw_path, u32 *dev_id_out)
{
	acpi_handle handle = ACPI_HANDLE(dev);
	struct acpi_object_list args;
	union acpi_object arg, *pkg, *feat, *devid;
	struct acpi_buffer out = { ACPI_ALLOCATE_BUFFER, NULL };
	acpi_status status;
	int ret = 0;

	arg.type = ACPI_TYPE_STRING;
	arg.string.pointer = (char *)raw_path;
	arg.string.length = strlen(raw_path);
	args.count = 1;
	args.pointer = &arg;

	status = acpi_evaluate_object(handle, "GDSC", &args, &out);
	if (ACPI_FAILURE(status)) {
		dev_warn(dev, "GDSC(%s) evaluation failed: %s\n",
			 raw_path, acpi_format_exception(status));
		return -EIO;
	}

	pkg = out.pointer;
	if (!pkg || pkg->type != ACPI_TYPE_PACKAGE ||
		pkg->package.count < GDSC_SRTP_COUNT) {
		dev_warn(dev, "GDSC(%s): unexpected return (type/count)\n",
			 raw_path);
		ret = -EINVAL;
		goto out_free;
	}

	feat = &pkg->package.elements[GDSC_SRTP_FEAT_ID];
	devid = &pkg->package.elements[GDSC_SRTP_DEV_ID];
	if (feat->type != ACPI_TYPE_INTEGER ||
		devid->type != ACPI_TYPE_INTEGER) {
		dev_warn(dev, "GDSC(%s): feat_id/dev_id not integers\n",
			 raw_path);
		ret = -EINVAL;
		goto out_free;
	}

	if ((u32)feat->integer.value == GDSC_FEAT_ID_UNSUPPORTED) {
		dev_warn(dev, "GDSC(%s): firmware reports path unsupported\n",
			 raw_path);
		ret = -ENODEV;
		goto out_free;
	}

	*dev_id_out = (u32)devid->integer.value;

out_free:
	ACPI_FREE(out.pointer);
	return ret;
}

/*
 * pwrap_parse_constraints() - Flatten the constraints sub-package
 *
 * ASL forms (Cpu.asl Case 1):
 *   Package(0x3){enable, device_state, comp_count}
 *   Package(0x4){enable, device_state, comp_count, Package(){comp_states...}}
 *
 * Maps onto pwrap_idle_constraints.values[] = {enable, device_state,
 * comp_count, comp_states[0..comp_count-1]}.
 */
static void pwrap_parse_constraints(struct device *dev,
					union acpi_object *pkg,
					struct pwrap_idle_constraints *c)
{
	u32 i, n;

	memset(c, 0, sizeof(*c));

	if (!pkg || pkg->type != ACPI_TYPE_PACKAGE)
		return;

	n = pkg->package.count;
	if (n > PWRAP_IDLE_CONSTRAINT_SCALARS &&
		pkg->package.elements[PWRAP_IDLE_CONSTRAINT_SCALARS].type == ACPI_TYPE_PACKAGE) {
		/* 4-element form: scalars + nested comp_states package */
		union acpi_object *comp =
			&pkg->package.elements[PWRAP_IDLE_CONSTRAINT_SCALARS];
		u32 j;

		for (i = 0; i < PWRAP_IDLE_CONSTRAINT_SCALARS; i++) {
			union acpi_object *e = &pkg->package.elements[i];

			if (e->type == ACPI_TYPE_INTEGER)
				c->values[i] = e->integer.value;
		}
		for (j = 0; j < comp->package.count &&
			 (PWRAP_IDLE_CONSTRAINT_SCALARS + j) <
			 (PWRAP_MAX_COMP_NUM + PWRAP_IDLE_CONSTRAINT_SCALARS); j++) {
			union acpi_object *e = &comp->package.elements[j];

			if (e->type == ACPI_TYPE_INTEGER)
				c->values[PWRAP_IDLE_CONSTRAINT_SCALARS + j] =
					e->integer.value;
		}
	} else {
		/* Flat form: copy each integer scalar in order */
		for (i = 0; i < n &&
			 i < (PWRAP_MAX_COMP_NUM + PWRAP_IDLE_CONSTRAINT_SCALARS); i++) {
			union acpi_object *e = &pkg->package.elements[i];

			if (e->type == ACPI_TYPE_INTEGER)
				c->values[i] = e->integer.value;
		}
	}

	/* Clamp comp_count to the number of entries actually written into
	 * comp_states[]. Firmware may report a larger value than PWRAP_MAX_COMP_NUM
	 * but the parse loops above cap writes at that limit. Without this clamp,
	 * consumers iterating comp_states[] up to comp_count would read beyond the
	 * array bounds into adjacent struct fields.
	 */
	if (c->comp_count > PWRAP_MAX_COMP_NUM)
		c->comp_count = PWRAP_MAX_COMP_NUM;
}

/*
 * pwrap_parse_dev_package() - Parse one DPMT device package into a config
 *
 * Package layout (DPM_DEV_* enum): {path, type, constraints, control_type}.
 * On success @cfg->device_path / @cfg->device_type are kstrdup'd (freed by
 * pwrap_acpi_dpm_config_free()).
 */
static int pwrap_parse_dev_package(struct device *dev,
				   union acpi_object *pkg,
				   struct pwrap_dev_config *cfg)
{
	union acpi_object *path_obj, *type_obj, *ctrl_obj;
	char norm_path[PWRAP_DEV_PATH_MAX];
	const char *raw_path;
	u64 control_type;
	int ret;

	if (pkg->type != ACPI_TYPE_PACKAGE ||
		pkg->package.count < DPM_DEV_PKG_COUNT) {
		dev_warn(dev, "DPMT device package: bad type/count\n");
		return -EINVAL;
	}

	path_obj = &pkg->package.elements[DPM_DEV_PATH];
	type_obj = &pkg->package.elements[DPM_DEV_TYPE];
	ctrl_obj = &pkg->package.elements[DPM_DEV_CONTROL_TYPE];

	if (path_obj->type != ACPI_TYPE_STRING || !path_obj->string.pointer ||
		ctrl_obj->type != ACPI_TYPE_INTEGER) {
		dev_warn(dev, "DPMT device package: bad path/control_type\n");
		return -EINVAL;
	}
	raw_path = path_obj->string.pointer;

	/* Normalize the (unpadded) _DSM path into the padded lookup key. */
	ret = pwrap_acpi_normalize_path(raw_path, norm_path, sizeof(norm_path));
	if (ret) {
		dev_warn(dev, "DPMT: cannot normalize path \"%s\": %d\n",
			 raw_path, ret);
		return ret;
	}

	cfg->device_path = kstrdup(norm_path, GFP_KERNEL);
	if (!cfg->device_path)
		return -ENOMEM;

	if (type_obj->type == ACPI_TYPE_STRING && type_obj->string.pointer) {
		cfg->device_type = kstrdup(type_obj->string.pointer, GFP_KERNEL);
		if (!cfg->device_type) {
			kfree(cfg->device_path);
			cfg->device_path = NULL;
			return -ENOMEM;
		}
	}

	pwrap_parse_constraints(dev, &pkg->package.elements[DPM_DEV_CONSTRAINTS],
				&cfg->constraints);

	control_type = ctrl_obj->integer.value;
	switch (control_type) {
	case CTRL_NONE:
		cfg->control_type = CTRL_NONE;
		break;
	case CTRL_BY_PWRAP:
		cfg->control_type = CTRL_BY_PWRAP;
		break;
	case CTRL_BY_SCMI:
		cfg->control_type = CTRL_BY_SCMI;
		break;
	default:
		dev_warn(dev, "DPMT: \"%s\" unknown control_type %llu -> NONE\n",
			 norm_path, control_type);
		cfg->control_type = CTRL_NONE;
		break;
	}

	/*
	 * SCMI devices need the per-device dev_id, which is not in the DPMT.
	 * Seed the invariant SCMI payload (feat_id + action IDs) the same way
	 * the static table does, then fetch dev_id from GDSC() using the RAW
	 * (unpadded) path the ASL compares against.
	 */
	if (cfg->control_type == CTRL_BY_SCMI) {
		struct pwrap_scmi_config seed = SCMI_CONFIG_INIT(0);
		u32 dev_id = 0;

		cfg->scmi_config = seed;

		ret = pwrap_acpi_fetch_scmi_dev_id(dev, raw_path, &dev_id);
		if (ret) {
			dev_warn(dev, "DPMT: \"%s\" SCMI but no dev_id (%d); "
				 "demoting to CTRL_NONE\n", norm_path, ret);
			cfg->control_type = CTRL_NONE;
		} else {
			cfg->scmi_config.dev_id = dev_id;
			dev_info(dev, "DPMT: \"%s\" SCMI dev_id=0x%x\n",
				 norm_path, dev_id);
		}
	}

	return 0;
}

int pwrap_acpi_fetch_dpm_config(struct device *dev,
				struct pwrap_dev_ctrl *ctrl)
{
	acpi_handle handle = ACPI_HANDLE(dev);
	union acpi_object *obj, *rev_obj, *cnt_obj;
	u64 count;
	u32 i;
	int ret = 0;

	if (!dev || !ctrl)
		return -EINVAL;

	obj = acpi_evaluate_dsm(handle, &pwrap_dsm_dpm_uuid,
				DSM_DPM_REV_0, DSM_DPM_GET_DEV_CTRL_INFO, NULL);
	if (!obj) {
		dev_err(dev, "Failed to evaluate DPM _DSM func %d\n",
			DSM_DPM_GET_DEV_CTRL_INFO);
		return -EINVAL;
	}

	if (obj->type != ACPI_TYPE_PACKAGE ||
		obj->package.count <= DSM_DPM_DPMT_DCFG) {
		dev_err(dev, "DPMT: expected package with devices, got type %d count %d\n",
			obj->type, obj->type == ACPI_TYPE_PACKAGE ?
			obj->package.count : -1);
		ret = -EINVAL;
		goto out_free;
	}

	rev_obj = &obj->package.elements[DSM_DPM_DPMT_REV];
	cnt_obj = &obj->package.elements[DSM_DPM_DPMT_COUNT];
	if (rev_obj->type != ACPI_TYPE_INTEGER ||
		cnt_obj->type != ACPI_TYPE_INTEGER) {
		dev_err(dev, "DPMT: revision/count not integers\n");
		ret = -EINVAL;
		goto out_free;
	}

	count = cnt_obj->integer.value;
	if (count != obj->package.count - DSM_DPM_DPMT_DCFG) {
		dev_err(dev, "DPMT: count %llu != package devices %u\n",
			count, obj->package.count - DSM_DPM_DPMT_DCFG);
		ret = -EINVAL;
		goto out_free;
	}

	ctrl->configs = kcalloc(count, sizeof(*ctrl->configs), GFP_KERNEL);
	if (!ctrl->configs) {
		ret = -ENOMEM;
		goto out_free;
	}
	ctrl->revision = rev_obj->integer.value;
	ctrl->count = count;

	dev_info(dev, "DPM config from ACPI: revision=%llu, %llu devices\n",
		 ctrl->revision, count);

	for (i = 0; i < count; i++) {
		union acpi_object *pkg =
			&obj->package.elements[DSM_DPM_DPMT_DCFG + i];

		ret = pwrap_parse_dev_package(dev, pkg, &ctrl->configs[i]);
		if (ret) {
			dev_err(dev, "DPMT: failed to parse device %u: %d\n",
				i, ret);
			pwrap_acpi_dpm_config_free(ctrl);
			goto out_free;
		}
	}

out_free:
	ACPI_FREE(obj);
	return ret;
}

void pwrap_acpi_dpm_config_free(struct pwrap_dev_ctrl *ctrl)
{
	u64 i;

	if (!ctrl || !ctrl->configs)
		return;

	for (i = 0; i < ctrl->count; i++) {
		kfree(ctrl->configs[i].device_path);
		kfree(ctrl->configs[i].device_type);
	}
	kfree(ctrl->configs);
	ctrl->configs = NULL;
	ctrl->count = 0;
	ctrl->revision = 0;
}
