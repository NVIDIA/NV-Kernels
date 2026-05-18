// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, NVIDIA CORPORATION.
 */

#include <linux/acpi.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>

#include <soc/tegra/bpmp.h>
#include <soc/tegra/bpmp-abi.h>

#include "bpmp-private.h"

#define TEGRA_BPMP_MBWT_MAX_PCIE_INSTANCE	5U
#define TEGRA_BPMP_MBWT_MAX_VC_TYPE		2U

struct tegra_bpmp_mbwt_sysfs {
	struct kobject kobj;
	/* Serializes pcie_instance_id and vc_type stores and bandwidth I/O. */
	struct mutex lock;
	struct tegra_bpmp *bpmp;
	unsigned int pcie_instance_id;
	unsigned int vc_type;
};

#define to_mbwt_sysfs(k)	container_of((k), struct tegra_bpmp_mbwt_sysfs, kobj)

static void tegra_bpmp_mbwt_kobj_release(struct kobject *kobj)
{
	kfree(to_mbwt_sysfs(kobj));
}

static const struct kobj_type tegra_bpmp_mbwt_ktype = {
	.release = tegra_bpmp_mbwt_kobj_release,
	.sysfs_ops = &kobj_sysfs_ops,
};

/**
 * tegra_sochub_mbwt_query_abi() - Ask BPMP whether an MBWT sub-command is supported.
 * @bpmp: BPMP handle
 * @cmd_code: Sub-command to probe (e.g. CMD_SOCHUB_MBWT_SET_BW)
 *
 * Returns 0 if the firmware reports the sub-command is supported (MRQ error 0).
 * Returns a negative errno if the transfer fails, or %-EOPNOTSUPP if the
 * firmware reports the sub-command is not supported.
 */
static int tegra_sochub_mbwt_query_abi(struct tegra_bpmp *bpmp,
				       unsigned int cmd_code)
{
	struct mrq_sochub_mbwt_request request;
	struct tegra_bpmp_message msg;
	int err;

	memset(&request, 0, sizeof(request));
	request.cmd = CMD_SOCHUB_MBWT_QUERY_ABI;
	request.query_abi.cmd_code = cmd_code;

	memset(&msg, 0, sizeof(msg));
	msg.mrq = MRQ_SOCHUB_MBWT;
	msg.tx.data = &request;
	msg.tx.size = sizeof(request);

	err = tegra_bpmp_transfer(bpmp, &msg);
	if (err)
		return err;

	if (msg.rx.ret)
		return -EOPNOTSUPP;

	return 0;
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
				 unsigned int *bandwidth_out)
{
	struct mrq_sochub_mbwt_request request;
	struct mrq_sochub_mbwt_response response;
	struct cmd_sochub_mbwt_get_bw_resp mbwt;
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

	memcpy(&mbwt, &response.get_bw, sizeof(response.get_bw));
	if (bandwidth_out)
		*bandwidth_out = mbwt.bw;

	return 0;
}

static ssize_t pcie_instance_id_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	struct tegra_bpmp_mbwt_sysfs *mbwt = to_mbwt_sysfs(kobj);
	unsigned int id;

	mutex_lock(&mbwt->lock);
	id = mbwt->pcie_instance_id;
	mutex_unlock(&mbwt->lock);

	return sysfs_emit(buf, "%u\n", id);
}

static ssize_t pcie_instance_id_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	struct tegra_bpmp_mbwt_sysfs *mbwt = to_mbwt_sysfs(kobj);
	unsigned int val;
	int err;

	err = kstrtou32(buf, 0, &val);
	if (err)
		return err;
	if (val > TEGRA_BPMP_MBWT_MAX_PCIE_INSTANCE)
		return -EINVAL;

	mutex_lock(&mbwt->lock);
	mbwt->pcie_instance_id = val;
	mutex_unlock(&mbwt->lock);

	return count;
}

static ssize_t vc_type_show(struct kobject *kobj, struct kobj_attribute *attr,
			    char *buf)
{
	struct tegra_bpmp_mbwt_sysfs *mbwt = to_mbwt_sysfs(kobj);
	unsigned int vt;

	mutex_lock(&mbwt->lock);
	vt = mbwt->vc_type;
	mutex_unlock(&mbwt->lock);

	return sysfs_emit(buf, "%u\n", vt);
}

static ssize_t vc_type_store(struct kobject *kobj, struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	struct tegra_bpmp_mbwt_sysfs *mbwt = to_mbwt_sysfs(kobj);
	unsigned int val;
	int err;

	err = kstrtou32(buf, 0, &val);
	if (err)
		return err;
	if (val > TEGRA_BPMP_MBWT_MAX_VC_TYPE)
		return -EINVAL;

	mutex_lock(&mbwt->lock);
	mbwt->vc_type = val;
	mutex_unlock(&mbwt->lock);

	return count;
}

static ssize_t bandwidth_show(struct kobject *kobj, struct kobj_attribute *attr,
			      char *buf)
{
	struct tegra_bpmp_mbwt_sysfs *mbwt = to_mbwt_sysfs(kobj);
	unsigned int inst, vt, bw;
	ssize_t ret;
	int err;

	mutex_lock(&mbwt->lock);
	inst = mbwt->pcie_instance_id;
	vt = mbwt->vc_type;

	err = tegra_sochub_get_mbwt(mbwt->bpmp, inst, vt, &bw);
	if (err) {
		mutex_unlock(&mbwt->lock);
		return err;
	}

	ret = sysfs_emit(buf, "%u\n", bw);
	mutex_unlock(&mbwt->lock);

	return ret;
}

static ssize_t bandwidth_store(struct kobject *kobj, struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	struct tegra_bpmp_mbwt_sysfs *mbwt = to_mbwt_sysfs(kobj);
	unsigned int bw;
	unsigned int inst, vt;
	int err;

	err = kstrtou32(buf, 0, &bw);
	if (err)
		return err;

	mutex_lock(&mbwt->lock);
	inst = mbwt->pcie_instance_id;
	vt = mbwt->vc_type;

	err = tegra_sochub_set_mbwt(mbwt->bpmp, inst, vt, bw);
	if (err) {
		mutex_unlock(&mbwt->lock);
		return err;
	}

	mutex_unlock(&mbwt->lock);

	return count;
}

static struct kobj_attribute pcie_instance_id_attr =
	__ATTR(pcie_instance_id, 0644, pcie_instance_id_show, pcie_instance_id_store);
static struct kobj_attribute vc_type_attr =
	__ATTR(vc_type, 0644, vc_type_show, vc_type_store);
static struct kobj_attribute bandwidth_attr =
	__ATTR(bandwidth, 0644, bandwidth_show, bandwidth_store);

static struct attribute *mbwt_attrs[] = {
	&pcie_instance_id_attr.attr,
	&vc_type_attr.attr,
	&bandwidth_attr.attr,
	NULL,
};

static const struct attribute_group mbwt_attr_group = {
	.attrs = mbwt_attrs,
};

static void tegra_bpmp_mbwt_sysfs_teardown(void *data)
{
	struct tegra_bpmp_mbwt_sysfs *mbwt = data;

	sysfs_remove_group(&mbwt->kobj, &mbwt_attr_group);
	kobject_del(&mbwt->kobj);
	kobject_put(&mbwt->kobj);
}

int tegra_bpmp_sysfs_register(struct tegra_bpmp *bpmp)
{
	struct tegra_bpmp_mbwt_sysfs *mbwt;
	int err;

	if (!ACPI_HANDLE(bpmp->dev))
		return 0;

	err = tegra_sochub_mbwt_query_abi(bpmp, CMD_SOCHUB_MBWT_SET_BW);
	if (err)
		return 0;

	err = tegra_sochub_mbwt_query_abi(bpmp, CMD_SOCHUB_MBWT_GET_BW);
	if (err)
		return 0;

	mbwt = kzalloc(sizeof(*mbwt), GFP_KERNEL);
	if (!mbwt)
		return -ENOMEM;

	mbwt->bpmp = bpmp;
	mutex_init(&mbwt->lock);

	kobject_init(&mbwt->kobj, &tegra_bpmp_mbwt_ktype);
	err = kobject_add(&mbwt->kobj, &bpmp->dev->kobj, "mbwt_control");
	if (err) {
		kobject_put(&mbwt->kobj);
		return err;
	}

	err = sysfs_create_group(&mbwt->kobj, &mbwt_attr_group);
	if (err)
		goto err_put;

	err = devm_add_action(bpmp->dev, tegra_bpmp_mbwt_sysfs_teardown, mbwt);
	if (err) {
		sysfs_remove_group(&mbwt->kobj, &mbwt_attr_group);
		goto err_put;
	}

	return 0;

err_put:
	kobject_del(&mbwt->kobj);
	kobject_put(&mbwt->kobj);
	return err;
}
