// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 MediaTek Inc.
 *
 * power_wrap_sysfs.c - sysfs interface for the power_wrap driver
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/slab.h>

#include "power_wrap.h"

#define SYSFS_BUF_SIZE         128

/*
 * search_path caches the last path written via pwrap_dev_config_query_store()
 * for the paired _show() to look up. It is shared state, so serialize all
 * store/show access under search_path_lock to prevent a concurrent writer from
 * tearing the string a reader is parsing.
 */
static char search_path[SYSFS_BUF_SIZE];
static DEFINE_MUTEX(search_path_lock);

/**
 * pwrap_sysfs_get_cfg() - Parse an ACPI path from a sysfs write and look it up
 * @buf:     sysfs write buffer (NOT NUL-terminated; @count valid bytes)
 * @count:   number of bytes written
 * @path:    caller-provided output buffer of size SYSFS_BUF_SIZE
 * @out_cfg: receives the matching struct pwrap_dev_config pointer on success
 *
 * Copies @count bytes into @path, NUL-terminates, strips a trailing newline,
 * logs the parsed path, and looks up the device config via
 * pwrap_query_dev_config().
 *
 * Return: 0 and sets *@out_cfg on success, -EINVAL if the input exceeds the
 *         buffer, -ENODEV if no device config matches the path.
 */
static int pwrap_sysfs_get_cfg(const char *buf, size_t count, char *path,
				   void **out_cfg)
{
	if (count >= SYSFS_BUF_SIZE)
		return -EINVAL;

	memcpy(path, buf, count);
	path[count] = '\0';
	if (count > 0 && path[count - 1] == '\n')
		path[count - 1] = '\0';

	pr_info("power_wrap sysfs: user input acpi device path = %s\n", path);

	*out_cfg = pwrap_query_dev_config(path);
	if (!*out_cfg) {
		pr_warn("power_wrap sysfs: no device config for path %s\n", path);
		return -ENODEV;
	}

	return 0;
}

static ssize_t pwrap_dev_probe_show(struct device *dev,
						  struct device_attribute *attr,
						  char *buf)
{
	int len = 0;
	struct pwrap_dev_ctrl *ctrl = pwrap_get_dev_ctrl();

	if (!ctrl) {
		len += scnprintf(buf + len, PAGE_SIZE - len,
			"pwrap_dev_ctrl not available\n");
		return len;
	}

	len += scnprintf(buf + len, PAGE_SIZE - len,
		"revision = %llu\ncount = %llu\n", ctrl->revision, ctrl->count);

	if (ctrl->count > 0 && ctrl->configs) {
		len += scnprintf(buf + len, PAGE_SIZE - len,
			"Device List:\n");
		for (int i = 0; i < ctrl->count && len < PAGE_SIZE - 1; ++i) {
			const char *path = ctrl->configs[i].device_path ?
				ctrl->configs[i].device_path : "(null)";
			int type = ctrl->configs[i].control_type;

			len += scnprintf(buf + len, PAGE_SIZE - len,
				"  [%d] device_path = %s, control_type = %d", i, path, type);
			switch (type) {
			case CTRL_NONE:
				len += scnprintf(buf + len, PAGE_SIZE - len, " (CTRL_NONE)");
				break;
			case CTRL_BY_PWRAP:
				len += scnprintf(buf + len, PAGE_SIZE - len, " (CTRL_BY_PWRAP)");
				break;
			case CTRL_BY_SCMI:
				len += scnprintf(buf + len, PAGE_SIZE - len, " (CTRL_BY_SCMI)");
				break;
			default:
				len += scnprintf(buf + len, PAGE_SIZE - len, " (UNKNOWN)");
				break;
			}
			len += scnprintf(buf + len, PAGE_SIZE - len, "\n");
			if (len >= PAGE_SIZE - 1) {
				len += scnprintf(buf + len, PAGE_SIZE - len, "[truncated]\n");
				break;
			}
		}
	}

	return len;
}

static ssize_t pwrap_dev_probe_store(struct device *dev,
							struct device_attribute *attr,
							const char *buf, size_t count)
{
	char acpi_path[SYSFS_BUF_SIZE];
	void *dev_cfg;

	if (count >= SYSFS_BUF_SIZE)
		return -EINVAL;

	memcpy(acpi_path, buf, count);
	acpi_path[count] = '\0';
	if (count > 0 && acpi_path[count - 1] == '\n')
		acpi_path[count - 1] = '\0';

	pr_info("power_wrap sysfs: user input acpi device path = %s\n", acpi_path);

	dev_cfg = mtk_pwrap_dev_probe(acpi_path);
	if (!dev_cfg) {
		pr_warn("power_wrap sysfs: device probe failed for path %s\n",
			acpi_path);
		return -ENODEV;
	}

	return count;
}
DEVICE_ATTR_RW(pwrap_dev_probe);

static ssize_t pwrap_dev_remove_store(struct device *dev,
							struct device_attribute *attr,
							const char *buf, size_t count)
{
	char acpi_path[SYSFS_BUF_SIZE];
	void *dev_cfg;
	int err;

	err = pwrap_sysfs_get_cfg(buf, count, acpi_path, &dev_cfg);
	if (err)
		return err;

	err = mtk_pwrap_dev_remove(dev_cfg);
	if (err)
		return err;

	return count;
}
DEVICE_ATTR_WO(pwrap_dev_remove);

static ssize_t pwrap_dev_request_store(struct device *dev,
							struct device_attribute *attr,
							const char *buf, size_t count)
{
	char acpi_path[SYSFS_BUF_SIZE];
	void *dev_cfg;
	int err;

	err = pwrap_sysfs_get_cfg(buf, count, acpi_path, &dev_cfg);
	if (err)
		return err;

	err = mtk_pwrap_dev_request(dev_cfg);
	if (err)
		return err;

	return count;
}
DEVICE_ATTR_WO(pwrap_dev_request);

static ssize_t pwrap_dev_suspend_store(struct device *dev,
							struct device_attribute *attr,
							const char *buf, size_t count)
{
	char acpi_path[SYSFS_BUF_SIZE];
	void *dev_cfg;
	int err;

	err = pwrap_sysfs_get_cfg(buf, count, acpi_path, &dev_cfg);
	if (err)
		return err;

	err = mtk_pwrap_dev_suspend(dev_cfg, 0);
	if (err)
		return err;

	return count;
}
DEVICE_ATTR_WO(pwrap_dev_suspend);

static ssize_t pwrap_dev_resume_store(struct device *dev,
							struct device_attribute *attr,
							const char *buf, size_t count)
{
	char acpi_path[SYSFS_BUF_SIZE];
	void *dev_cfg;
	int err;

	err = pwrap_sysfs_get_cfg(buf, count, acpi_path, &dev_cfg);
	if (err)
		return err;

	err = mtk_pwrap_dev_resume(dev_cfg, 0);
	if (err)
		return err;

	return count;
}
DEVICE_ATTR_WO(pwrap_dev_resume);

static ssize_t pwrap_com_idle_store(struct device *dev,
							struct device_attribute *attr,
							const char *buf, size_t count)
{
	char acpi_path[SYSFS_BUF_SIZE];
	void *dev_cfg;
	int err;

	err = pwrap_sysfs_get_cfg(buf, count, acpi_path, &dev_cfg);
	if (err)
		return err;

	err = mtk_pwrap_com_idle(dev_cfg, 0);
	if (err)
		return err;

	return count;
}
DEVICE_ATTR_WO(pwrap_com_idle);

static ssize_t pwrap_com_active_store(struct device *dev,
							struct device_attribute *attr,
							const char *buf, size_t count)
{
	char acpi_path[SYSFS_BUF_SIZE];
	void *dev_cfg;
	int err;

	err = pwrap_sysfs_get_cfg(buf, count, acpi_path, &dev_cfg);
	if (err)
		return err;

	err = mtk_pwrap_com_active(dev_cfg, 0);
	if (err)
		return err;

	return count;
}
DEVICE_ATTR_WO(pwrap_com_active);

static ssize_t pwrap_dev_config_query_show(struct device *dev,
							struct device_attribute *attr,
							char *buf)
{
	struct pwrap_dev_config *dev_cfg;
	int len = 0;
	int i, j;

	mutex_lock(&search_path_lock);

	if (search_path[0] == '\0') {
		len += scnprintf(buf + len, PAGE_SIZE - len,
			"No device path set for search\n");
		mutex_unlock(&search_path_lock);
		return len;
	}

	dev_cfg = (struct pwrap_dev_config *) pwrap_query_dev_config(search_path);
	mutex_unlock(&search_path_lock);
	if (!dev_cfg)
		return -ENODEV;

	len += scnprintf(buf + len, PAGE_SIZE - len,
		"device_path = %s\n", dev_cfg->device_path ? dev_cfg->device_path : "(null)");
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"device_type = %s\n", dev_cfg->device_type ? dev_cfg->device_type : "(null)");

	// constraints
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"constraints:\n");
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"  enable = %llu\n", dev_cfg->constraints.enable);
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"  device_state = %llu\n", dev_cfg->constraints.device_state);
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"  comp_count = %llu\n", dev_cfg->constraints.comp_count);
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"  comp_states = [");
	for (i = 0; i < dev_cfg->constraints.comp_count; i++) {
		len += scnprintf(buf + len, PAGE_SIZE - len,
			"%llu%s", dev_cfg->constraints.comp_states[i],
			(i < dev_cfg->constraints.comp_count - 1) ? ", " : "");
	}
	len += scnprintf(buf + len, PAGE_SIZE - len, "]\n");

	// control_type
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"control_type = %d", dev_cfg->control_type);
	switch (dev_cfg->control_type) {
	case CTRL_NONE:
		len += scnprintf(buf + len, PAGE_SIZE - len, " (CTRL_NONE)\n");
		break;
	case CTRL_BY_PWRAP:
		len += scnprintf(buf + len, PAGE_SIZE - len, " (CTRL_BY_PWRAP)\n");
		break;
	case CTRL_BY_SCMI:
		len += scnprintf(buf + len, PAGE_SIZE - len, " (CTRL_BY_SCMI)\n");
		break;
	default:
		len += scnprintf(buf + len, PAGE_SIZE - len, " (UNKNOWN)\n");
		break;
	}

	// scmi_config
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"scmi_config:\n");
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"  feat_id = 0x%x\n", dev_cfg->scmi_config.feat_id);
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"  dev_id = 0x%x\n", dev_cfg->scmi_config.dev_id);
	len += scnprintf(buf + len, PAGE_SIZE - len,
		"  data = [\n");
	for (i = 0; i < SCMI_NOTIFY_NUMBER; i++) {
		len += scnprintf(buf + len, PAGE_SIZE - len, "    [");
		for (j = 0; j < SCMI_DATA_NUMBER; j++) {
			len += scnprintf(buf + len, PAGE_SIZE - len,
				"0x%x%s", dev_cfg->scmi_config.data[i][j],
				(j < SCMI_DATA_NUMBER - 1) ? ", " : "");
		}
		len += scnprintf(buf + len, PAGE_SIZE - len, "]\n");
	}
	len += scnprintf(buf + len, PAGE_SIZE - len, "  ]\n");

	return len;
}

static ssize_t pwrap_dev_config_query_store(struct device *dev,
							struct device_attribute *attr,
							const char *buf, size_t count)
{
	if (count >= SYSFS_BUF_SIZE)
		return -EINVAL;

	mutex_lock(&search_path_lock);

	memset(search_path, 0, sizeof(search_path));
	memcpy(search_path, buf, count);
	search_path[count] = '\0';
	if (count > 0 && search_path[count - 1] == '\n')
		search_path[count - 1] = '\0';

	pr_info("power_wrap sysfs: user input acpi device path = %s\n",
		search_path);

	mutex_unlock(&search_path_lock);

	return count;
}
DEVICE_ATTR_RW(pwrap_dev_config_query);

static struct attribute *pwrap_attrs[] = {
	&dev_attr_pwrap_dev_probe.attr,
	&dev_attr_pwrap_dev_remove.attr,
	&dev_attr_pwrap_dev_request.attr,
	&dev_attr_pwrap_dev_suspend.attr,
	&dev_attr_pwrap_dev_resume.attr,
	&dev_attr_pwrap_com_idle.attr,
	&dev_attr_pwrap_com_active.attr,
	&dev_attr_pwrap_dev_config_query.attr,
	NULL,
};

static const struct attribute_group pwrap_group = {
	.attrs = pwrap_attrs,
};

/**
 * pwrap_create_sys_files() - Create the sysfs debug/test nodes
 * @pdev: the power_wrap platform device
 *
 * Registers all nodes as one atomic attribute group: creation is
 * all-or-nothing, so there is never a partial sysfs ABI. The group is
 * devm-managed and removed automatically on unbind.
 *
 * These are debug/test nodes, so a creation failure must NOT fail probe or
 * disable the driver - the SCMI device-control path stays functional either
 * way. The caller logs and ignores the return value.
 *
 * Return: 0 on success, negative errno if the group could not be added.
 */
int pwrap_create_sys_files(struct platform_device *pdev)
{
	if (!pdev)
		return -EINVAL;

	return devm_device_add_group(&pdev->dev, &pwrap_group);
}
