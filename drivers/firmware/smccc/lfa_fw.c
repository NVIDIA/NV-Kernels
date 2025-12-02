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
#include <linux/nmi.h>
#include <linux/ktime.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/acpi.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>

#define DRIVER_NAME	"ARM_LFA"
#define LFA_ERROR_STRING(name) \
	[name] = #name
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
		.name = "BL31 runtime",
		.uuid = "47d4086d-4cfe-9846-9b95-2950cbbd5a00",
	},
	{
		.name = "BL33 non-secure payload",
		.uuid = "d6d0eea7-fcea-d54b-9782-9934f234b6e4",
	},
	{
		.name = "RMM",
		.uuid = "6c0762a6-12f2-4b56-92cb-ba8f633606d9",
	},
};

static int update_fw_images_tree(void);
static struct kobject *lfa_dir;
static DEFINE_MUTEX(lfa_lock);

static int get_nr_lfa_components(void)
{
	struct arm_smccc_1_2_regs reg = { 0 };

	reg.a0 = LFA_1_0_FN_GET_INFO;
	reg.a1 = 0; /* lfa_info_selector = 0 */

	arm_smccc_1_2_invoke(&reg, &reg);
	if (reg.a0 != LFA_SUCCESS)
		return reg.a0;

	return reg.a1;
}

static int lfa_cancel(struct image_props *attrs)
{
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
	int ret;

	args.a0 = LFA_1_0_FN_ACTIVATE;
	args.a1 = attrs->fw_seq_id; /* fw_seq_id under consideration */
	/*
	 * As we do not support updates requiring a CPU reset (yet),
	 * we pass 0 in args.a3 and args.a4, holding the entry point and context
	 * ID respectively.
	 * We want to force CPU rendezvous if either cpu_rendezvous or
	 * cpu_rendezvous_forced is set. The flag value is flipped as
	 * it is called skip_cpu_rendezvous in the spec.
	 */
	args.a2 = !(attrs->cpu_rendezvous_forced || attrs->cpu_rendezvous);

	for (;;) {
		/* Touch watchdog, ACTIVATE shouldn't take longer than watchdog_thresh */
		touch_nmi_watchdog();
		arm_smccc_1_2_invoke(&args, &res);

		if ((long)res.a0 < 0) {
			pr_err("ACTIVATE for image %s failed: %s",
				attrs->image_name, lfa_error_strings[-res.a0]);
			return res.a0;
		}

		/* SMC returned with success */
		if (!(res.a1 & LFA_ACTIVATE_CALL_AGAIN))
			break; /* ACTIVATE successful */

		/* SMC returned with call_again flag set */
		if (ktime_before(ktime_get(), end)) {
			udelay(LFA_ACTIVATE_POLL_DELAY_US);
			continue;
		}

		pr_err("ACTIVATE timed out for image %s", attrs->image_name);
		ret = lfa_cancel(attrs);
		if (ret == 0)
			return -ETIMEDOUT;
		else
			return ret;
	}

	return res.a0;
}

static int activate_fw_image(struct image_props *attrs)
{
	struct arm_smccc_1_2_regs args = { 0 };
	struct arm_smccc_1_2_regs res = { 0 };
	ktime_t end = ktime_add_us(ktime_get(), LFA_PRIME_BUDGET_US);
	int ret;

	if (attrs->may_reset_cpu) {
		pr_err("CPU reset not supported by kernel driver\n");
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
			return res.a0;
		}
		if (!(res.a1 & LFA_PRIME_CALL_AGAIN))
			break; /* PRIME successful */

		/* SMC returned with call_again flag set */
		if (ktime_before(ktime_get(), end)) {
			udelay(LFA_PRIME_POLL_DELAY_US);
			continue;
		}

		pr_err("PRIME timed out for image %s", attrs->image_name);
		ret = lfa_cancel(attrs);
		if (ret == 0)
			return -ETIMEDOUT;
		else
			return ret;
	}

	if (attrs->cpu_rendezvous_forced || attrs->cpu_rendezvous)
		ret = stop_machine(call_lfa_activate, attrs, cpu_online_mask);
	else
		ret = call_lfa_activate(attrs);

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

static ssize_t activate_store(struct kobject *kobj, struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	struct image_props *attrs = container_of(attr, struct image_props,
					 image_attrs[LFA_ATTR_ACTIVATE]);
	int ret;

	if (!mutex_trylock(&lfa_lock)) {
		pr_err("Mutex locked, try again");
		return -EAGAIN;
	}

	ret = activate_fw_image(attrs);
	if (ret) {
		pr_err("Firmware activation failed: %s\n",
			lfa_error_strings[-ret]);
		mutex_unlock(&lfa_lock);
		return -ECANCELED;
	}

	pr_info("Firmware activation succeeded\n");

	ret = update_fw_images_tree();
	if (ret)
		pr_err("Failed to update FW images tree");
	mutex_unlock(&lfa_lock);
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
	[LFA_ATTR_ACT_CAPABLE]		= __ATTR_RO(activation_capable),
	[LFA_ATTR_ACT_PENDING]		= __ATTR_RO(activation_pending),
	[LFA_ATTR_MAY_RESET_CPU]	= __ATTR_RO(may_reset_cpu),
	[LFA_ATTR_CPU_RENDEZVOUS]	= __ATTR_RO(cpu_rendezvous),
	[LFA_ATTR_FORCE_CPU_RENDEZVOUS]	= __ATTR_RW(force_cpu_rendezvous),
	[LFA_ATTR_ACTIVATE]		= __ATTR_WO(activate),
	[LFA_ATTR_CANCEL]		= __ATTR_WO(cancel)
};

static void delete_fw_image_node(struct image_props *attrs)
{
	int i;

	for (i = 0; i < LFA_ATTR_NR_IMAGES; i++)
		sysfs_remove_file(attrs->image_dir, &attrs->image_attrs[i].attr);

	kobject_put(attrs->image_dir);
	attrs->image_dir = NULL;
	list_del(&attrs->image_node);
	kfree(attrs);
}

static void clean_fw_images_tree(void)
{
	struct image_props *attrs, *tmp;

	list_for_each_entry_safe(attrs, tmp, &lfa_fw_images, image_node)
		delete_fw_image_node(attrs);
}

static void update_fw_image_node(struct image_props *attrs, int seq_id,
			    char *fw_uuid, u32 image_flags)
{
	attrs->fw_seq_id = seq_id;
	attrs->image_name = fw_uuid;
	attrs->activation_capable = !!(image_flags & BIT(0));
	attrs->activation_pending = !!(image_flags & BIT(1));
	attrs->may_reset_cpu = !!(image_flags & BIT(2));
	/* cpu_rendezvous_optional bit has inverse logic in the spec */
	attrs->cpu_rendezvous = !(image_flags & BIT(3));
}

static int create_fw_image_node(int seq_id, char *fw_uuid, u32 image_flags)
{
	struct image_props *attrs;
	int ret;

	attrs = kzalloc(sizeof(*attrs), GFP_KERNEL);
	if (!attrs)
		return -ENOMEM;

	attrs->image_dir = kobject_create_and_add(fw_uuid, lfa_dir);
	if (!attrs->image_dir)
		return -ENOMEM;

	/* Update FW attributes */
	update_fw_image_node(attrs, seq_id, fw_uuid, image_flags);

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
	list_add_tail(&attrs->image_node, &lfa_fw_images);

	return ret;
}

static int update_fw_images_tree(void)
{
	struct arm_smccc_1_2_regs reg = { 0 };
	struct uuid_regs image_uuid;
	struct image_props *attrs, *tmp;
	char image_id_str[40];
	int ret, num_of_components;
	int node_idx = 0;

	num_of_components = get_nr_lfa_components();
	if (num_of_components <= 0) {
		pr_err("Error getting number of LFA components");
		return -ENODEV;
	}

	/*
	 * Pass 1:
	 *    For nodes < num_of_components, update fw_image_node
	 *    For nodes >= num_of_components, delete
	 */
	list_for_each_entry_safe(attrs, tmp, &lfa_fw_images, image_node) {
		if (attrs->fw_seq_id < num_of_components) {
			/* Update this FW image node */

			/* Get FW details */
			reg.a0 = LFA_1_0_FN_GET_INVENTORY;
			reg.a1 = attrs->fw_seq_id;
			arm_smccc_1_2_invoke(&reg, &reg);

			if (reg.a0 != LFA_SUCCESS)
				return -EINVAL;

			/* Build image name with UUID */
			image_uuid.uuid_lo = reg.a1;
			image_uuid.uuid_hi = reg.a2;
			snprintf(image_id_str, sizeof(image_id_str), "%pUb", &image_uuid);

			if (strcmp(attrs->image_name, image_id_str)) {
				/* UUID doesn't match previous UUID for given FW, not expected */
				pr_err("FW seq id %u: Previous UUID %s doesn't match current %s",
					attrs->fw_seq_id, attrs->image_name, image_id_str);
				return -EINVAL;
			}

			/* Update FW attributes */
			update_fw_image_node(attrs, attrs->fw_seq_id, image_id_str, reg.a3);
			node_idx++;
		} else {
			/* This node is beyond valid FW components list */
			delete_fw_image_node(attrs);
		}
	}

	/*
	 * Pass 2:
	 *    If current FW components number is more than previous list, add new component nodes.
	 */
	for (; node_idx < num_of_components; node_idx++) {
		/* Get FW details */
		reg.a0 = LFA_1_0_FN_GET_INVENTORY;
		reg.a1 = node_idx;
		arm_smccc_1_2_invoke(&reg, &reg);

		if (reg.a0 != LFA_SUCCESS)
			return -EINVAL;

		/* Build image name with UUID */
		image_uuid.uuid_lo = reg.a1;
		image_uuid.uuid_hi = reg.a2;
		snprintf(image_id_str, sizeof(image_id_str), "%pUb", &image_uuid);

		ret = create_fw_image_node(node_idx, image_id_str, reg.a3);
		if (ret)
			return ret;
	}

	return 0;
}

static irqreturn_t lfa_irq_thread(int irq, void *data)
{
	struct image_props *attrs = NULL;
	int ret;
	int num_of_components, curr_component;

	mutex_lock(&lfa_lock);

	/*
	 * As per LFA spec, after activation of a component, the caller
	 * is expected to re-enumerate the component states (using
	 * LFA_GET_INFO then LFA_GET_INVENTORY).
	 * Hence we need an unconditional loop.
	 */

	do {
		ret = update_fw_images_tree();
		if (ret)
			goto exit_unlock;

		/* Initialize counters to track list traversal  */
		num_of_components = get_nr_lfa_components();
		curr_component = 0;

		/* Execute PRIME and ACTIVATE for activable FW component */
		list_for_each_entry(attrs, &lfa_fw_images, image_node) {
			curr_component++;
			if ((!attrs->activation_capable) || (!attrs->activation_pending)) {
				/* LFA not applicable for this FW component */
				continue;
			}

			ret = activate_fw_image(attrs);
			if (ret) {
				pr_err("Firmware %s activation failed: %s\n",
					attrs->image_name, lfa_error_strings[-ret]);
				goto exit_unlock;
			}

			pr_info("Firmware %s activation succeeded", attrs->image_name);
			break;
		}
	} while (curr_component < num_of_components);

	ret = update_fw_images_tree();
	if (ret)
		goto exit_unlock;

exit_unlock:
	mutex_unlock(&lfa_lock);
	return IRQ_HANDLED;
}

static int lfa_probe(struct platform_device *pdev)
{
	int err;
	unsigned int irq;

	err = platform_get_irq_byname_optional(pdev, "fw-store-updated-interrupt");
	if (err < 0)
		err = platform_get_irq(pdev, 0);
	if (err < 0) {
		pr_err("Interrupt not found, functionality will be unavailable.");

		/* Bail out without failing the driver. */
		return 0;
	}
	irq = err;

	err = request_threaded_irq(irq, NULL, lfa_irq_thread, IRQF_ONESHOT, DRIVER_NAME, NULL);
	if (err != 0) {
		pr_err("Interrupt setup failed, functionality will be unavailable.");

		/* Bail out without failing the driver. */
		return 0;
	}

	return 0;
}

static const struct of_device_id lfa_of_ids[] = {
	{ .compatible = "arm,armhf000", },
	{ },
};
MODULE_DEVICE_TABLE(of, lfa_of_ids);

static const struct acpi_device_id lfa_acpi_ids[] = {
	{"ARMHF000"},
	{},
};
MODULE_DEVICE_TABLE(acpi, lfa_acpi_ids);

static struct platform_driver lfa_driver = {
	.probe = lfa_probe,
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = lfa_of_ids,
		.acpi_match_table = ACPI_PTR(lfa_acpi_ids),
	},
};

static int __init lfa_init(void)
{
	struct arm_smccc_1_2_regs reg = { 0 };
	int err;

	/* LFA requires SMCCC version >= 1.2 */
	if (arm_smccc_get_version() < ARM_SMCCC_VERSION_1_2) {
		pr_err("Not supported with SMCCC version %u", arm_smccc_get_version());
		return -ENODEV;
	}

	if (arm_smccc_1_1_get_conduit() == SMCCC_CONDUIT_NONE) {
		pr_err("Invalid SMCCC conduit");
		return -ENODEV;
	}

	reg.a0 = LFA_1_0_FN_GET_VERSION;
	arm_smccc_1_2_invoke(&reg, &reg);
	if (reg.a0 == -LFA_NOT_SUPPORTED) {
		pr_err("Arm Live Firmware activation(LFA): no firmware agent found\n");
		return -ENODEV;
	}

	pr_info("Arm Live Firmware Activation (LFA): detected v%ld.%ld\n",
		reg.a0 >> 16, reg.a0 & 0xffff);

	err = platform_driver_register(&lfa_driver);
	if (err < 0)
		pr_err("Platform driver register failed");

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
	mutex_lock(&lfa_lock);
	clean_fw_images_tree();
	mutex_unlock(&lfa_lock);

	kobject_put(lfa_dir);
	platform_driver_unregister(&lfa_driver);
}
module_exit(lfa_exit);

MODULE_DESCRIPTION("ARM Live Firmware Activation (LFA)");
MODULE_LICENSE("GPL");
