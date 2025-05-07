// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/acpi.h>
#include <linux/arm_ffa.h>
#include <linux/list.h>

#define DRV_NAME "nvidia-ffa-ec"

/* platform device for FFA ACPI device (HID MSFT000C) */
static struct platform_device *ffa_pdev;

static const uuid_t nvidia_ec_managment_service_uuid =
	UUID_INIT(0x330c1273, 0xfde5, 0x4757, 0x98, 0x19, 0x5b, 0x65, 0x39, 0x03, 0x75, 0x02);

static const uuid_t nvidia_ec_power_service_uuid =
	UUID_INIT(0x7157addf, 0x2fbe, 0x4c63, 0xae, 0x95, 0xef, 0xac, 0x16, 0xe3, 0xb0, 0x1c);

static const uuid_t nvidia_ec_battery_service_uuid =
	UUID_INIT(0x25cb5207, 0xac36, 0x427d, 0xaa, 0xef, 0x3a, 0xa7, 0x88, 0x77, 0xd2, 0x7e);

static const uuid_t nvidia_ec_thermal_service_uuid =
	UUID_INIT(0x31f56da7, 0x593c, 0x4d72, 0xa4, 0xb3, 0x8f, 0xc7, 0x17, 0x1a, 0xc0, 0x73);

static const uuid_t nvidia_ec_fan_service_uuid =
	UUID_INIT(0x7697530c, 0xd079, 0x4ec1, 0xa4, 0xc4, 0xcf, 0x0d, 0x2b, 0xdc, 0x93, 0xfa);

static const uuid_t nvidia_ec_ucsi_service_uuid =
	UUID_INIT(0x65467f50, 0x827f, 0x4e4f, 0x87, 0x70, 0xdb, 0xf4, 0xc3, 0xf7, 0x7f, 0x45);

static const uuid_t nvidia_ec_input_service_uuid =
	UUID_INIT(0xe3168a99, 0x4a57, 0x4a2b, 0x8c, 0x5e, 0x11, 0xbc, 0xfe, 0xc7, 0x34, 0x06);

static const uuid_t nvidia_ec_time_alarm_service_uuid =
	UUID_INIT(0x23ea63ed, 0xb593, 0x46ea, 0xb0, 0x27, 0x89, 0x24, 0xdf, 0x88, 0xe9, 0x2f);

/* EC service FFA device structure */
struct nvidia_ec_ffa_device {
	struct ffa_device *ffa_dev;
	struct list_head list;
};

/* List to contain all EC services FFA device */
static LIST_HEAD(nvidia_ec_ffa_dev_head);

/* Lock to serialize EC services FFA device list access */
static DEFINE_MUTEX(nvidia_ffa_lock);

static int nvidia_ffa_ec_service_probe(struct ffa_device *ffa_dev)
{
	struct nvidia_ec_ffa_device *nvidia_ec_ffa_dev;

	if (!ffa_pdev) {
		dev_err(&ffa_dev->dev, "nvidia ffa device not available\n");
		return -ENODEV;
	}

	nvidia_ec_ffa_dev = devm_kmalloc(&ffa_dev->dev,
					 sizeof(*nvidia_ec_ffa_dev),
					 GFP_KERNEL);
	if (!nvidia_ec_ffa_dev) {
		dev_err(&ffa_dev->dev, "Failed to allocate memory\n");
		return -ENOMEM;
	}

	nvidia_ec_ffa_dev->ffa_dev = ffa_dev;
	INIT_LIST_HEAD(&nvidia_ec_ffa_dev->list);

	mutex_lock(&nvidia_ffa_lock);
	list_add(&nvidia_ec_ffa_dev->list, &nvidia_ec_ffa_dev_head);
	mutex_unlock(&nvidia_ffa_lock);

	return 0;
}

static void nvidia_ffa_ec_service_remove(struct ffa_device *ffa_dev)
{
	struct nvidia_ec_ffa_device *cur, *tmp;

	mutex_lock(&nvidia_ffa_lock);
	list_for_each_entry_safe(cur, tmp, &nvidia_ec_ffa_dev_head, list) {
		if (cur->ffa_dev == ffa_dev) {
			list_del(&cur->list);
			devm_kfree(&ffa_dev->dev, cur);
			break;
		}
	}
	mutex_unlock(&nvidia_ffa_lock);
}

static const struct ffa_device_id nvidia_ffa_ec_service_ids[] = {
	{ nvidia_ec_managment_service_uuid },
	{ nvidia_ec_power_service_uuid },
	{ nvidia_ec_battery_service_uuid },
	{ nvidia_ec_thermal_service_uuid },
	{ nvidia_ec_fan_service_uuid },
	{ nvidia_ec_ucsi_service_uuid },
	{ nvidia_ec_input_service_uuid },
	{ nvidia_ec_time_alarm_service_uuid },
	{}
};

static struct ffa_driver nvidia_ffa_ec_service_driver = {
	.name = DRV_NAME,
	.probe = nvidia_ffa_ec_service_probe,
	.remove = nvidia_ffa_ec_service_remove,
	.id_table = nvidia_ffa_ec_service_ids,
};

static const struct acpi_device_id nvidia_ffa_device_ids[] = {
	/*
	 * Please refer
	 * https://github.com/OpenDevicePartnership/documentation/blob/main/bookshelf/Shelf%204%20Specifications/EC%20Interface/src/secure-ec-services-overview.md#hid-definition
	 * where MSFT000C is documented.
	 *
	 * The _HID 'MSFT000C' is reserved for FFA device which uses
	 * FFA interface for secure EC communication.
	 */
	{"MSFT000C", 0},
	{"", 0},
};

MODULE_DEVICE_TABLE(acpi, nvidia_ffa_device_ids);

static int nvidia_ffa_probe(struct platform_device *pdev)
{
	struct acpi_device *adev = ACPI_COMPANION(&pdev->dev);
	acpi_status status;
	unsigned long long data = 0;
	int ret;

	if (ffa_pdev) {
		dev_err(&pdev->dev, "FFA device already registered\n");
		return -EINVAL;
	}

	if (!adev) {
		dev_err(&pdev->dev, "No ACPI companion found\n");
		return -ENODEV;
	}

	status = acpi_evaluate_integer(adev->handle, "AVAL", NULL, &data);
	if (ACPI_FAILURE(status)) {
		dev_err(&pdev->dev, "Failed to execute AVAL method\n");
		return -ENODEV;
	}

	if (data != 1) {
		dev_err(&pdev->dev, "FFA not available\n");
		return -ENODEV;
	}

	ffa_pdev = pdev;

	ret = ffa_driver_register(&nvidia_ffa_ec_service_driver, THIS_MODULE, DRV_NAME);
	if (ret) {
		dev_err(&pdev->dev,
			"Failed to register ec service driver error=%d\n", ret);
		ffa_pdev = NULL;
		return ret;
	}

	return 0;
}

static void nvidia_ffa_remove(struct platform_device *pdev)
{
	ffa_driver_unregister(&nvidia_ffa_ec_service_driver);
	ffa_pdev = NULL;
}

static struct platform_driver nvidia_ffa_driver = {
	.probe = nvidia_ffa_probe,
	.remove = nvidia_ffa_remove,
	.driver = {
		.name = "nvidia-ffa",
		.acpi_match_table = nvidia_ffa_device_ids,
	},
};

static int __init nvidia_ffa_init(void)
{
	return platform_driver_register(&nvidia_ffa_driver);
}
module_init(nvidia_ffa_init);

static void __exit nvidia_ffa_exit(void)
{
	platform_driver_unregister(&nvidia_ffa_driver);
}
module_exit(nvidia_ffa_exit);

MODULE_SOFTDEP("pre: arm-ffa");
MODULE_AUTHOR("NVIDIA CORPORATION");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NVIDIA FFA EC services driver");
