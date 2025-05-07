// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/acpi.h>

#define DRV_NAME "nvidia-ffa-ec"

/* platform device for FFA ACPI device (HID MSFT000C) */
static struct platform_device *ffa_pdev;

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

	return 0;
}

static void nvidia_ffa_remove(struct platform_device *pdev)
{
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
