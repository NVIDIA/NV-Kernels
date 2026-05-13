// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Arm Limited
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/arm-smccc.h>
#include <linux/psci.h>
#include <uapi/linux/psci.h>
#include <linux/uuid.h>
#include <linux/array_size.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/nmi.h>
#include <linux/ktime.h>
#include <linux/delay.h>

#undef pr_fmt
#define pr_fmt(fmt) "Arm LFA: " fmt

/* LFA v1.0b0 specification */
#define LFA_1_0_FN_BASE			0xc40002e0
#define LFA_1_0_FN(n)			(LFA_1_0_FN_BASE + (n))

#define LFA_1_0_FN_GET_VERSION		LFA_1_0_FN(0)
#define LFA_1_0_FN_CHECK_FEATURE	LFA_1_0_FN(1)
#define LFA_1_0_FN_GET_INFO		LFA_1_0_FN(2)
#define LFA_1_0_FN_GET_INVENTORY	LFA_1_0_FN(3)
#define LFA_1_0_FN_PRIME		LFA_1_0_FN(4)
#define LFA_1_0_FN_ACTIVATE		LFA_1_0_FN(5)
#define LFA_1_0_FN_CANCEL		LFA_1_0_FN(6)

/* CALL_AGAIN flags (returned by SMC) */
#define LFA_PRIME_CALL_AGAIN		BIT(0)
#define LFA_ACTIVATE_CALL_AGAIN		BIT(0)

/* Prime loop limits, TODO: tune after testing */
#define LFA_PRIME_BUDGET_US		30000000	/* 30s cap */
#define LFA_PRIME_POLL_DELAY_US		10		/* 10us between polls */

/* Activation loop limits, TODO: tune after testing */
#define LFA_ACTIVATE_BUDGET_US		20000000	/* 20s cap */
#define LFA_ACTIVATE_POLL_DELAY_US	10		/* 10us between polls */

/* LFA return values */
#define LFA_SUCCESS			0
#define LFA_NOT_SUPPORTED		1
#define LFA_BUSY			2
#define LFA_AUTH_ERROR			3
#define LFA_NO_MEMORY			4
#define LFA_CRITICAL_ERROR		5
#define LFA_DEVICE_ERROR		6
#define LFA_WRONG_STATE			7
#define LFA_INVALID_PARAMETERS		8
#define LFA_COMPONENT_WRONG_STATE	9
#define LFA_INVALID_ADDRESS		10
#define LFA_ACTIVATION_FAILED		11

#define LFA_ERROR_STRING(name) \
	[name] = #name

static const char * const lfa_error_strings[] = {
	LFA_ERROR_STRING(LFA_SUCCESS),
	LFA_ERROR_STRING(LFA_NOT_SUPPORTED),
	LFA_ERROR_STRING(LFA_BUSY),
	LFA_ERROR_STRING(LFA_AUTH_ERROR),
	LFA_ERROR_STRING(LFA_NO_MEMORY),
	LFA_ERROR_STRING(LFA_CRITICAL_ERROR),
	LFA_ERROR_STRING(LFA_DEVICE_ERROR),
	LFA_ERROR_STRING(LFA_WRONG_STATE),
	LFA_ERROR_STRING(LFA_INVALID_PARAMETERS),
	LFA_ERROR_STRING(LFA_COMPONENT_WRONG_STATE),
	LFA_ERROR_STRING(LFA_INVALID_ADDRESS),
	LFA_ERROR_STRING(LFA_ACTIVATION_FAILED)
};

enum image_attr_names {
	LFA_ATTR_NAME,
	LFA_ATTR_CURRENT_VERSION,
	LFA_ATTR_PENDING_VERSION,
	LFA_ATTR_ACT_CAPABLE,
	LFA_ATTR_ACT_PENDING,
	LFA_ATTR_MAY_RESET_CPU,
	LFA_ATTR_CPU_RENDEZVOUS,
	LFA_ATTR_FORCE_CPU_RENDEZVOUS,
	LFA_ATTR_ACTIVATE,
	LFA_ATTR_CANCEL,
	LFA_ATTR_NR_IMAGES
};

struct image_props {
	struct list_head image_node;
	const char *image_name;
	int fw_seq_id;
	u64 current_version;
	u64 pending_version;
	bool activation_capable;
	bool activation_pending;
	bool may_reset_cpu;
	bool cpu_rendezvous;
	bool cpu_rendezvous_forced;
	struct kobject *image_dir;
	struct kobj_attribute image_attrs[LFA_ATTR_NR_IMAGES];
};
static LIST_HEAD(lfa_fw_images);

/* A UUID split over two 64-bit registers */
struct uuid_regs {
	u64 uuid_lo;
	u64 uuid_hi;
};

static const struct fw_image_uuid {
	const char *name;
	const char *uuid;
} fw_images_uuids[] = {
	{
		.name = "TF-A BL31 runtime",
		.uuid = "47d4086d-4cfe-9846-9b95-2950cbbd5a00",
	},
	{
		.name = "BL33 non-secure payload",
		.uuid = "d6d0eea7-fcea-d54b-9782-9934f234b6e4",
	},
	{
		.name = "TF-RMM",
		.uuid = "6c0762a6-12f2-4b56-92cb-ba8f633606d9",
	},
};

static struct kobject *lfa_dir;
static DEFINE_MUTEX(lfa_lock);
static struct workqueue_struct *fw_images_update_wq;
static struct work_struct fw_images_update_work;

static int update_fw_images_tree(void);

static void delete_fw_image_node(struct image_props *attrs)
{
	int i;

	for (i = 0; i < LFA_ATTR_NR_IMAGES; i++)
		sysfs_remove_file(attrs->image_dir, &attrs->image_attrs[i].attr);

	kobject_put(attrs->image_dir);
	list_del(&attrs->image_node);
	kfree(attrs);
}

static void remove_invalid_fw_images(struct work_struct *work)
{
	struct image_props *attrs, *tmp;

	mutex_lock(&lfa_lock);

	/*
	 * Remove firmware images including directories that are no longer
	 * present in the LFA agent after updating the existing ones.
	 */
	list_for_each_entry_safe(attrs, tmp, &lfa_fw_images, image_node) {
		if (attrs->fw_seq_id == -1)
			delete_fw_image_node(attrs);
	}

	mutex_unlock(&lfa_lock);
}

static void set_image_flags(struct image_props *attrs, int seq_id,
			    u32 image_flags, u64 reg_current_ver,
			    u64 reg_pending_ver)
{
	attrs->fw_seq_id = seq_id;
	attrs->current_version = reg_current_ver;
	attrs->pending_version = reg_pending_ver;
	attrs->activation_capable = !!(image_flags & BIT(0));
	attrs->activation_pending = !!(image_flags & BIT(1));
	attrs->may_reset_cpu = !!(image_flags & BIT(2));
	/* cpu_rendezvous_optional bit has inverse logic in the spec */
	attrs->cpu_rendezvous = !(image_flags & BIT(3));
}

static unsigned long get_nr_lfa_components(void)
{
	struct arm_smccc_1_2_regs reg = { 0 };

	reg.a0 = LFA_1_0_FN_GET_INFO;
	reg.a1 = 0; /* lfa_info_selector = 0 */

	arm_smccc_1_2_invoke(&reg, &reg);
	if (reg.a0 != LFA_SUCCESS)
		return reg.a0;

	return reg.a1;
}

static int lfa_cancel(void *data)
{
	struct image_props *attrs = data;
	struct arm_smccc_1_2_regs reg = { 0 };

	reg.a0 = LFA_1_0_FN_CANCEL;
	reg.a1 = attrs->fw_seq_id;
	arm_smccc_1_2_invoke(&reg, &reg);

	/*
	 * When firmware activation is called with "skip_cpu_rendezvous=1",
	 * LFA_CANCEL can fail with LFA_BUSY if the activation could not be
	 * cancelled.
	 */
	if (reg.a0 == LFA_SUCCESS) {
		pr_info("Activation cancelled for image %s\n",
			attrs->image_name);
	} else {
		pr_err("Firmware activation could not be cancelled: %s\n",
		       lfa_error_strings[-reg.a0]);
		return -EINVAL;
	}

	return reg.a0;
}

static int call_lfa_activate(void *data)
{
	struct image_props *attrs = data;
	struct arm_smccc_1_2_regs args = { 0 };
	struct arm_smccc_1_2_regs res = { 0 };
	ktime_t end = ktime_add_us(ktime_get(), LFA_ACTIVATE_BUDGET_US);

	args.a0 = LFA_1_0_FN_ACTIVATE;
	args.a1 = attrs->fw_seq_id; /* fw_seq_id under consideration */
	/*
	 * As we do not support updates requiring a CPU reset (yet),
	 * we pass 0 in reg.a3 and reg.a4, holding the entry point and context
	 * ID respectively.
	 * cpu_rendezvous_forced is set by the administrator, via sysfs,
	 * cpu_rendezvous is dictated by each firmware component.
	 */
	args.a2 = !(attrs->cpu_rendezvous_forced || attrs->cpu_rendezvous);

	for (;;) {
		/* Touch watchdog, ACTIVATE shouldn't take longer than watchdog_thresh */
		touch_nmi_watchdog();
		arm_smccc_1_2_invoke(&args, &res);

		if ((long)res.a0 < 0) {
			pr_err("ACTIVATE for image %s failed: %s\n",
				attrs->image_name, lfa_error_strings[-res.a0]);
			return res.a0;
		}
		if (!(res.a1 & LFA_ACTIVATE_CALL_AGAIN))
			break; /* ACTIVATE successful */

		/* SMC returned with call_again flag set */
		if (ktime_before(ktime_get(), end)) {
			udelay(LFA_ACTIVATE_POLL_DELAY_US);
			continue;
		}

		pr_err("ACTIVATE for image %s timed out", attrs->image_name);
		return -ETIMEDOUT;
	}

	return res.a0;
}

static int activate_fw_image(struct image_props *attrs)
{
	int ret;

	mutex_lock(&lfa_lock);
	if (attrs->cpu_rendezvous_forced || attrs->cpu_rendezvous)
		ret = stop_machine(call_lfa_activate, attrs, cpu_online_mask);
	else
		ret = call_lfa_activate(attrs);

	if (ret != 0) {
		mutex_unlock(&lfa_lock);
		return lfa_cancel(attrs);
	}

	/*
	 * Invalidate fw_seq_ids (-1) for all images as the seq_ids and the
	 * number of firmware images in the LFA agent may change after a
	 * successful activation attempt. Negate all image flags as well.
	 */
	attrs = NULL;
	list_for_each_entry(attrs, &lfa_fw_images, image_node) {
		set_image_flags(attrs, -1, 0b1000, 0, 0);
	}

	update_fw_images_tree();

	/*
	 * Removing non-valid image directories at the end of an activation.
	 * We can't remove the sysfs attributes while in the respective
	 * _store() handler, so have to postpone the list removal to a
	 * workqueue.
	 */
	INIT_WORK(&fw_images_update_work, remove_invalid_fw_images);
	queue_work(fw_images_update_wq, &fw_images_update_work);
	mutex_unlock(&lfa_lock);

	return ret;
}

static int prime_fw_image(struct image_props *attrs)
{
	struct arm_smccc_1_2_regs args = { 0 };
	struct arm_smccc_1_2_regs res = { 0 };
	ktime_t end = ktime_add_us(ktime_get(), LFA_PRIME_BUDGET_US);
	int ret;

	mutex_lock(&lfa_lock);
	/* Avoid SMC calls on invalid firmware images */
	if (attrs->fw_seq_id == -1) {
		pr_err("Arm LFA: Invalid firmware sequence id\n");
		mutex_unlock(&lfa_lock);

		return -ENODEV;
	}

	if (attrs->may_reset_cpu) {
		pr_err("CPU reset not supported by kernel driver\n");
		mutex_unlock(&lfa_lock);

		return -EINVAL;
	}

	/*
	 * LFA_PRIME/ACTIVATE will return 1 in res.a1 if the firmware
	 * priming/activation is still in progress. In that case
	 * LFA_PRIME/ACTIVATE will need to be called again.
	 * res.a1 will become 0 once the prime/activate process completes.
	 */
	args.a0 = LFA_1_0_FN_PRIME;
	args.a1 = attrs->fw_seq_id; /* fw_seq_id under consideration */
	for (;;) {
		/* Touch watchdog, PRIME shouldn't take longer than watchdog_thresh */
		touch_nmi_watchdog();
		arm_smccc_1_2_invoke(&args, &res);

		if ((long)res.a0 < 0) {
			pr_err("LFA_PRIME for image %s failed: %s\n",
				attrs->image_name, lfa_error_strings[-res.a0]);
			mutex_unlock(&lfa_lock);

			return res.a0;
		}
		if (!(res.a1 & LFA_PRIME_CALL_AGAIN))
			break; /* PRIME successful */

		/* SMC returned with call_again flag set */
		if (ktime_before(ktime_get(), end)) {
			udelay(LFA_PRIME_POLL_DELAY_US);
			continue;
		}

		pr_err("LFA_PRIME for image %s timed out", attrs->image_name);
		mutex_unlock(&lfa_lock);

		ret = lfa_cancel(attrs);
		if (ret != 0)
			return ret;
		return -ETIMEDOUT;
	}

	mutex_unlock(&lfa_lock);
	return ret;
}

static ssize_t name_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	struct image_props *attrs = container_of(attr, struct image_props,
						 image_attrs[LFA_ATTR_NAME]);

	return sysfs_emit(buf, "%s\n", attrs->image_name);
}

static ssize_t activation_capable_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	struct image_props *attrs = container_of(attr, struct image_props,
					 image_attrs[LFA_ATTR_ACT_CAPABLE]);

	return sysfs_emit(buf, "%d\n", attrs->activation_capable);
}

static ssize_t activation_pending_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	struct image_props *attrs = container_of(attr, struct image_props,
					 image_attrs[LFA_ATTR_ACT_PENDING]);
	struct arm_smccc_1_2_regs reg = { 0 };

	/*
	 * Activation pending status can change anytime thus we need to update
	 * and return its current value
	 */
	reg.a0 = LFA_1_0_FN_GET_INVENTORY;
	reg.a1 = attrs->fw_seq_id;
	arm_smccc_1_2_invoke(&reg, &reg);
	if (reg.a0 == LFA_SUCCESS)
		attrs->activation_pending = !!(reg.a3 & BIT(1));

	return sysfs_emit(buf, "%d\n", attrs->activation_pending);
}

static ssize_t may_reset_cpu_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct image_props *attrs = container_of(attr, struct image_props,
					 image_attrs[LFA_ATTR_MAY_RESET_CPU]);

	return sysfs_emit(buf, "%d\n", attrs->may_reset_cpu);
}

static ssize_t cpu_rendezvous_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	struct image_props *attrs = container_of(attr, struct image_props,
					 image_attrs[LFA_ATTR_CPU_RENDEZVOUS]);

	return sysfs_emit(buf, "%d\n", attrs->cpu_rendezvous);
}

static ssize_t force_cpu_rendezvous_store(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct image_props *attrs = container_of(attr, struct image_props,
				image_attrs[LFA_ATTR_FORCE_CPU_RENDEZVOUS]);
	int ret;

	ret = kstrtobool(buf, &attrs->cpu_rendezvous_forced);
	if (ret)
		return ret;

	return count;
}

static ssize_t force_cpu_rendezvous_show(struct kobject *kobj,
					 struct kobj_attribute *attr, char *buf)
{
	struct image_props *attrs = container_of(attr, struct image_props,
				image_attrs[LFA_ATTR_FORCE_CPU_RENDEZVOUS]);

	return sysfs_emit(buf, "%d\n", attrs->cpu_rendezvous_forced);
}

static ssize_t current_version_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	struct image_props *attrs = container_of(attr, struct image_props,
				image_attrs[LFA_ATTR_CURRENT_VERSION]);
	u32 maj, min;

	maj = attrs->current_version >> 32;
	min = attrs->current_version & 0xffffffff;
	return sysfs_emit(buf, "%u.%u\n", maj, min);
}

static ssize_t pending_version_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	struct image_props *attrs = container_of(attr, struct image_props,
					 image_attrs[LFA_ATTR_ACT_PENDING]);
	struct arm_smccc_1_2_regs reg = { 0 };
	u32 maj, min;

	/*
	 * Similar to activation pending, this value can change following an
	 * update, we need to retrieve fresh info instead of stale information.
	 */
	reg.a0 = LFA_1_0_FN_GET_INVENTORY;
	reg.a1 = attrs->fw_seq_id;
	arm_smccc_1_2_invoke(&reg, &reg);
	if (reg.a0 == LFA_SUCCESS) {
		if (reg.a5 != 0 && attrs->activation_pending)
		{
			attrs->pending_version = reg.a5;
			maj = reg.a5 >> 32;
			min = reg.a5 & 0xffffffff;
		}
	}

	return sysfs_emit(buf, "%u.%u\n", maj, min);
}

static ssize_t activate_store(struct kobject *kobj, struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	struct image_props *attrs = container_of(attr, struct image_props,
					 image_attrs[LFA_ATTR_ACTIVATE]);
	int ret;

	ret = prime_fw_image(attrs);
	if (ret) {
		pr_err("Firmware prime failed: %s\n",
			lfa_error_strings[-ret]);
		return -ECANCELED;
	}

	ret = activate_fw_image(attrs);
	if (ret) {
		pr_err("Firmware activation failed: %s\n",
			lfa_error_strings[-ret]);
		return -ECANCELED;
	}

	pr_info("Firmware activation succeeded\n");

	return count;
}

static ssize_t cancel_store(struct kobject *kobj, struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	struct image_props *attrs = container_of(attr, struct image_props,
						 image_attrs[LFA_ATTR_CANCEL]);
	int ret;

	ret = lfa_cancel(attrs);
	if (ret != 0)
		return ret;

	return count;
}

static struct kobj_attribute image_attrs_group[LFA_ATTR_NR_IMAGES] = {
	[LFA_ATTR_NAME]			= __ATTR_RO(name),
	[LFA_ATTR_CURRENT_VERSION]	= __ATTR_RO(current_version),
	[LFA_ATTR_PENDING_VERSION]	= __ATTR_RO(pending_version),
	[LFA_ATTR_ACT_CAPABLE]		= __ATTR_RO(activation_capable),
	[LFA_ATTR_ACT_PENDING]		= __ATTR_RO(activation_pending),
	[LFA_ATTR_MAY_RESET_CPU]	= __ATTR_RO(may_reset_cpu),
	[LFA_ATTR_CPU_RENDEZVOUS]	= __ATTR_RO(cpu_rendezvous),
	[LFA_ATTR_FORCE_CPU_RENDEZVOUS]	= __ATTR_RW(force_cpu_rendezvous),
	[LFA_ATTR_ACTIVATE]		= __ATTR_WO(activate),
	[LFA_ATTR_CANCEL]		= __ATTR_WO(cancel)
};

static void clean_fw_images_tree(void)
{
	struct image_props *attrs, *tmp;

	list_for_each_entry_safe(attrs, tmp, &lfa_fw_images, image_node)
		delete_fw_image_node(attrs);
}

static int update_fw_image_node(char *fw_uuid, int seq_id,
					  u32 image_flags, u64 reg_current_ver,
					  u64 reg_pending_ver)
{
	const char *image_name = "(unknown)";
	struct image_props *attrs;
	int ret;

	/*
	 * If a fw_image is already in the images list then we just update
	 * its flags and seq_id instead of trying to recreate it.
	 */
	list_for_each_entry(attrs, &lfa_fw_images, image_node) {
		if (!strcmp(attrs->image_dir->name, fw_uuid)) {
			set_image_flags(attrs, seq_id, image_flags,
					reg_current_ver, reg_pending_ver);
			return 0;
		}
	}

	attrs = kzalloc(sizeof(*attrs), GFP_KERNEL);
	if (!attrs)
		return -ENOMEM;

	for (int i = 0; i < ARRAY_SIZE(fw_images_uuids); i++) {
		if (!strcmp(fw_images_uuids[i].uuid, fw_uuid))
			image_name = fw_images_uuids[i].name;
		else
			image_name = fw_uuid;
	}

	attrs->image_dir = kobject_create_and_add(fw_uuid, lfa_dir);
	if (!attrs->image_dir)
		return -ENOMEM;

	INIT_LIST_HEAD(&attrs->image_node);
	attrs->image_name = image_name;
	attrs->cpu_rendezvous_forced = 1;
	set_image_flags(attrs, seq_id, image_flags, reg_current_ver,
			reg_pending_ver);

	/*
	 * The attributes for each sysfs file are constant (handler functions,
	 * name and permissions are the same within each directory), but we
	 * need a per-directory copy regardless, to get a unique handle
	 * for each directory, so that container_of can do its magic.
	 * Also this requires an explicit sysfs_attr_init(), since it's a new
	 * copy, to make LOCKDEP happy.
	 */
	memcpy(attrs->image_attrs, image_attrs_group,
	       sizeof(attrs->image_attrs));
	for (int i = 0; i < LFA_ATTR_NR_IMAGES; i++) {
		struct attribute *attr = &attrs->image_attrs[i].attr;

		sysfs_attr_init(attr);
		ret = sysfs_create_file(attrs->image_dir, attr);
		if (ret) {
			pr_err("creating sysfs file for uuid %s: %d\n",
			       fw_uuid, ret);
			clean_fw_images_tree();

			return ret;
		}
	}
	list_add(&attrs->image_node, &lfa_fw_images);

	return ret;
}

static int update_fw_images_tree(void)
{
	struct arm_smccc_1_2_regs reg = { 0 };
	struct uuid_regs image_uuid;
	char image_id_str[40];
	int ret, num_of_components;

	num_of_components = get_nr_lfa_components();
	if (num_of_components <= 0) {
		pr_err("Error getting number of LFA components\n");
		return -ENODEV;
	}

	for (int i = 0; i < num_of_components; i++) {
		reg.a0 = LFA_1_0_FN_GET_INVENTORY;
		reg.a1 = i; /* fw_seq_id under consideration */
		arm_smccc_1_2_invoke(&reg, &reg);
		if (reg.a0 == LFA_SUCCESS) {
			image_uuid.uuid_lo = reg.a1;
			image_uuid.uuid_hi = reg.a2;

			snprintf(image_id_str, sizeof(image_id_str), "%pUb",
				 &image_uuid);
			ret = update_fw_image_node(image_id_str, i,
							reg.a3, reg.a4, reg.a5);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int __init lfa_init(void)
{
	struct arm_smccc_1_2_regs reg = { 0 };
	int err;

	reg.a0 = LFA_1_0_FN_GET_VERSION;
	arm_smccc_1_2_invoke(&reg, &reg);
	if (reg.a0 == -LFA_NOT_SUPPORTED) {
		pr_info("Live Firmware activation: no firmware agent found\n");
		return -ENODEV;
	}

	fw_images_update_wq = alloc_workqueue("fw_images_update_wq",
					     WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!fw_images_update_wq) {
		pr_err("Live Firmware Activation: Failed to allocate workqueue.\n");

		return -ENOMEM;
	}

	pr_info("Live Firmware Activation: detected v%ld.%ld\n",
		reg.a0 >> 16, reg.a0 & 0xffff);

	lfa_dir = kobject_create_and_add("lfa", firmware_kobj);
	if (!lfa_dir)
		return -ENOMEM;

	mutex_lock(&lfa_lock);
	err = update_fw_images_tree();
	if (err != 0)
		kobject_put(lfa_dir);

	mutex_unlock(&lfa_lock);
	return err;
}
module_init(lfa_init);

static void __exit lfa_exit(void)
{
	flush_workqueue(fw_images_update_wq);
	destroy_workqueue(fw_images_update_wq);

	mutex_lock(&lfa_lock);
	clean_fw_images_tree();
	mutex_unlock(&lfa_lock);

	kobject_put(lfa_dir);
}
module_exit(lfa_exit);

MODULE_DESCRIPTION("ARM Live Firmware Activation (LFA)");
MODULE_LICENSE("GPL");
