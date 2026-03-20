// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, NVIDIA CORPORATION.
 */

#include <linux/acpi.h>
#include <linux/device.h>

#include <soc/tegra/bpmp.h>
#include <soc/tegra/bpmp-abi.h>

#include "bpmp-private.h"

struct bpmp_export {
	struct device child;
	struct tegra_bpmp *bpmp;
	u32 instance;
	u32 vc_type;
	bool vc_type_set;
};

static struct bpmp_export *child_to_bpmp_export(struct device *child)
{
	return container_of(child, struct bpmp_export, child);
}

static void bpmp_export_release(struct device *child)
{
	struct bpmp_export *export = child_to_bpmp_export(child);

	kfree(export);
}

static int tegra_sochub_set_mbwt(struct tegra_bpmp *bpmp,
				 unsigned int instance,
				 unsigned int vc_type,
				 unsigned int bandwidth)
{
	struct mrq_sochub_mbwt_request request;
	struct tegra_bpmp_message msg;
	int err;

	memset(&request, 0, sizeof(request));
	request.cmd = CMD_SOCHUB_MBWT_SET_BW;
	request.set_bw.instance = instance;
	request.set_bw.vc_type = vc_type;
	request.set_bw.bw = bandwidth;

	memset(&msg, 0, sizeof(msg));
	msg.mrq = MRQ_SOCHUB_MBWT;
	msg.tx.data = &request;
	msg.tx.size = sizeof(request);

	err = tegra_bpmp_transfer(bpmp, &msg);
	if (err) {
		dev_err(bpmp->dev,
			"Failed setting up the SocHub MBWT with error %d\n",
			err);
		return err;
	}

	if (msg.rx.ret < 0)
		return -EINVAL;

	return 0;
}

static int tegra_sochub_get_mbwt(struct tegra_bpmp *bpmp,
				 unsigned int instance,
				 unsigned int vc_type,
				 struct cmd_sochub_mbwt_get_bw_resp *bw)
{
	struct mrq_sochub_mbwt_request request;
	struct mrq_sochub_mbwt_response response;
	struct tegra_bpmp_message msg;
	int err;

	memset(&request, 0, sizeof(request));
	request.cmd = CMD_SOCHUB_MBWT_GET_BW;
	request.get_bw.instance = instance;
	request.get_bw.vc_type = vc_type;

	memset(&response, 0, sizeof(response));

	memset(&msg, 0, sizeof(msg));
	msg.mrq = MRQ_SOCHUB_MBWT;
	msg.tx.data = &request;
	msg.tx.size = sizeof(request);
	msg.rx.data = &response;
	msg.rx.size = sizeof(response);

	err = tegra_bpmp_transfer(bpmp, &msg);
	if (err) {
		dev_err(bpmp->dev,
			"Failed reading the SocHub MBWT with error %d\n",
			err);
		return err;
	}
	if (msg.rx.ret < 0)
		return -EINVAL;

	memcpy(bw, &response.get_bw, sizeof(response.get_bw));

	return 0;
}


static ssize_t vc_type_store(struct device *child,
			    struct device_attribute *attr,
			    const char *buf, size_t size)
{
	struct bpmp_export *export = child_to_bpmp_export(child);
	u32 val;
	int ret;

	ret = kstrtou32(buf, 0, &val);
	if (ret)
		return ret;

	export->vc_type = val;
	export->vc_type_set = true;
	return ret ? : size;

}
static DEVICE_ATTR_WO(vc_type);

static ssize_t bandwidth_show(struct device *child,
			      struct device_attribute *attr,
			      char *buf)
{
	struct bpmp_export *export = child_to_bpmp_export(child);
	struct cmd_sochub_mbwt_get_bw_resp mbwt;
	struct tegra_bpmp *bpmp = export->bpmp;
	int ret;

	if (!export->vc_type_set) {
		dev_err(bpmp->dev,
			"SoCHub VC type not set\n");
		return -EINVAL;
	}

	ret = tegra_sochub_get_mbwt(bpmp, export->instance,
				    export->vc_type, &mbwt);
	/*
	 * Clear vc_type to make sure the user sets it
	 * everytime before reading/writing to the bandwidth node
	 */
	export->vc_type_set = false;

	if (ret)
		return ret;

	return sysfs_emit(buf, "%u\n", mbwt.bw);

}

static ssize_t bandwidth_store(struct device *child,
			       struct device_attribute *attr,
			       const char *buf, size_t size)
{
	struct bpmp_export *export = child_to_bpmp_export(child);
	struct tegra_bpmp *bpmp = export->bpmp;
	u32 val;
	int ret;

	ret = kstrtou32(buf, 0, &val);
	if (ret)
		return ret;

	if (!export->vc_type_set) {
		dev_err(bpmp->dev,
			"SoCHub VC type not set\n");
		return -EINVAL;
	}

	ret = tegra_sochub_set_mbwt(bpmp, export->instance,
				    export->vc_type, val);

	/*
	 * Clear vc_type to make sure the user sets it
	 * everytime before reading/writing to the bandwidth node
	 */
	export->vc_type_set = false;

	return ret ? : size;

}
static DEVICE_ATTR_RW(bandwidth);

static struct attribute *bpmp_membw_attrs[] = {
	&dev_attr_vc_type.attr,
	&dev_attr_bandwidth.attr,
	NULL,
};
ATTRIBUTE_GROUPS(bpmp_membw);


static ssize_t export_store(struct device *parent,
			    struct device_attribute *attr,
			    const char *buf, size_t len)
{
	int ret;
	struct tegra_bpmp *bpmp = dev_get_drvdata(parent);
	struct bpmp_export *export;
	u32 instance;

	ret = kstrtouint(buf, 0, &instance);
	if (ret < 0)
		return ret;

	export = kzalloc(sizeof(*export), GFP_KERNEL);
	if (!export)
		return -ENOMEM;

	export->bpmp = bpmp;

	export->child.release = bpmp_export_release;
	export->child.parent = parent;
	export->child.devt = MKDEV(0, 0);
	export->child.groups = bpmp_membw_groups;
	export->instance = instance;
	dev_set_name(&export->child, "mbwt%u", instance);

	ret = device_register(&export->child);
	if (ret) {
		put_device(&export->child);
		export = NULL;
		return ret;
	}

	return ret ? : len;
}
static DEVICE_ATTR_WO(export);


static int bpmp_unexport_match(struct device *child, const void *data)
{
	struct bpmp_export *export = child_to_bpmp_export(child);

	return export->instance == *(unsigned int *)data;
}

static ssize_t unexport_store(struct device *parent,
			    struct device_attribute *attr,
			    const char *buf, size_t len)
{
	unsigned int instance;
	struct device *child;
	int ret;

	ret = kstrtouint(buf, 0, &instance);
	if (ret < 0)
		return ret;

	child = device_find_child(parent, &instance, bpmp_unexport_match);
	if (!child)
		return -ENODEV;

	put_device(child);
	device_unregister(child);

	return ret ? : len;
}
static DEVICE_ATTR_WO(unexport);

static struct attribute *bpmp_attrs[] = {
	&dev_attr_export.attr,
	&dev_attr_unexport.attr,
	NULL,
};
ATTRIBUTE_GROUPS(bpmp);

static struct class bpmp_class = {
	.name = "bpmp_mbwt",
	.dev_groups = bpmp_groups,
};

static int bpmp_sysfs_export(struct tegra_bpmp *bpmp)
{
	struct device *parent;

	if (!ACPI_HANDLE(bpmp->dev))
		return -EFAULT;

	parent = device_create(&bpmp_class, bpmp->dev, MKDEV(0, 0), bpmp,
			       "mbwt_control_%s", dev_name(bpmp->dev));
	if (IS_ERR(parent)) {
		dev_warn(bpmp->dev,
			 "failed creating device for bpmp sysfs export\n");
		return PTR_ERR(parent);
	}

	return 0;
}

static int tegra410_bpmp_init(struct tegra_bpmp *bpmp)
{
	return bpmp_sysfs_export(bpmp);
}

const struct tegra_bpmp_ops tegra410_bpmp_ops = {
	.init = tegra410_bpmp_init,
};
static int __init bpmp_sysfs_init(void)
{
	return class_register(&bpmp_class);
}
subsys_initcall(bpmp_sysfs_init);
