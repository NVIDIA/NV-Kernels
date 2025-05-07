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

/* EC secure services FFA packet structure sent via ACPI */
struct nvidia_ec_ffa_packet {
	u8 status;
	u8 length;
	u8 uuid[UUID_SIZE];
	u8 rawdata[];
} __packed;

/*
 * ACPI ASL code uses ToUUID() macro which encodes it in mixed-endian format.
 * Convert the AML UUID buffer into FFA UUID format.
 */
static uuid_t nvidia_get_uuid_from_aml_buf(const u8 *buf)
{
	return (uuid_t) {{ buf[3], buf[2], buf[1], buf[0],
			   buf[5], buf[4], buf[7], buf[6],
			   buf[8], buf[9], buf[10], buf[11],
			   buf[12], buf[13], buf[14], buf[15] }};
}

static int nvidia_ffa_rescan_acpi_device(struct device *dev, void *data)
{
	struct acpi_device *adev = to_acpi_device(dev);

	if (acpi_dev_hid_uid_match(adev, data, NULL)) {
		acpi_bus_scan(adev->handle);
		return 1;
	}

	return 0;
}

static const char *nvidia_get_acpi_id_from_uuid(uuid_t *uuid)
{
	if (uuid_equal(uuid, &nvidia_ec_battery_service_uuid))
		return "PNP0C0A";

	if (uuid_equal(uuid, &nvidia_ec_time_alarm_service_uuid))
		return "ACPI000E";

	if (uuid_equal(uuid, &nvidia_ec_fan_service_uuid))
		return "PNP0C0B";

	if (uuid_equal(uuid, &nvidia_ec_ucsi_service_uuid))
		return "PNP0CA0";

	return NULL;
}

/*
 * Handler function for FFH operation region offset 4.
 * When ACPI interpreter runs code with FFH operation region offset 4,
 * then this data is meant for EC secure services. The FFH buffer has
 * data in 'struct nvidia_ec_ffa_packet' format. In this packet, it has UUID
 * for EC secure service and then the service specific raw data.
 *
 * 1. Extract the UUID from this packet and get ffa_device for it.
 * 2. Fill raw data in 'struct ffa_send_direct_data2' and
 *    invoke sync_send_receive2() routine for the ffa_device.
 * 3. From response, fill the data in 'struct ffa_send_direct_data2'
 *    and return.
 */
static int nvidia_ffh_handler(struct acpi_ffh_info *info, acpi_integer *value, void *region_context)
{
	struct ffa_send_direct_data2 ffa_data = { 0 };
	struct nvidia_ec_ffa_packet *ffa_packet = (struct nvidia_ec_ffa_packet *)value;
	struct nvidia_ec_ffa_device *cur, *ec_dev =  NULL;
	int ret;
	uuid_t uuid;

	/* Only offset 4 is supported */
	if (info->offset != 4)
		return -EOPNOTSUPP;

	/* Length should not be less than header length */
	if (info->length < offsetof(struct nvidia_ec_ffa_packet, rawdata))
		return -EINVAL;

	/* Length should not be less than actual packet length */
	if (info->length <
	    ffa_packet->length + offsetof(struct nvidia_ec_ffa_packet, rawdata)) {
		ffa_packet->status = 1;
		return -EINVAL;
	}

	/* Packet length should not greater than FFA supported data length */
	if (ffa_packet->length > sizeof(ffa_data.data)) {
		ffa_packet->status = 1;
		return -EINVAL;
	}

	/* Convert AML UUID to FFA UUID */
	uuid = nvidia_get_uuid_from_aml_buf((u8 *)ffa_packet->uuid);

	mutex_lock(&nvidia_ffa_lock);
	/* Get nvidia_ec_ffa_device for the current UUID */
	list_for_each_entry(cur, &nvidia_ec_ffa_dev_head, list) {
		if (uuid_equal(&uuid, &cur->ffa_dev->uuid)) {
			ec_dev = cur;
			break;
		}
	}
	mutex_unlock(&nvidia_ffa_lock);

	if (!ec_dev) {
		ffa_packet->status = 1;
		return -EINVAL;
	}

	/* Copy the ACPI FFH packet data into FFA data */
	memcpy(ffa_data.data, ffa_packet->rawdata, ffa_packet->length);

	if (!ec_dev->ffa_dev->ops ||
	    !ec_dev->ffa_dev->ops->msg_ops ||
	    !ec_dev->ffa_dev->ops->msg_ops->sync_send_receive2) {
		return -EINVAL;
	}

	ret = ec_dev->ffa_dev->ops->msg_ops->sync_send_receive2(ec_dev->ffa_dev,
								&ffa_data);
	if (ret) {
		dev_err(&ec_dev->ffa_dev->dev,
			"Failed to send FFA messages error=%d\n", ret);
		ffa_packet->status = 1;
		return ret;
	}

	/* Set the status as success */
	ffa_packet->status = 0;

	/* Copy the ACPI FFA data back into ACPI FFH packet */
	memcpy(ffa_packet->rawdata, ffa_data.data, ffa_packet->length);

	return 0;
}

static int nvidia_ffa_ec_service_probe(struct ffa_device *ffa_dev)
{
	struct nvidia_ec_ffa_device *nvidia_ec_ffa_dev;
	const char *acpi_id = NULL;

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

	/*
	 * When acpi subsystem probe all ACPI devices, then it execute _STA
	 * method for each device. The _STA method fails at that time since
	 * custom FFA driver won't be ready. Get ACPI ID from UUID and
	 * rescan the device again.
	 */
	acpi_id = nvidia_get_acpi_id_from_uuid(&ffa_dev->uuid);
	if (acpi_id) {
		acpi_bus_for_each_dev(nvidia_ffa_rescan_acpi_device,
				      (void *)acpi_id);
	}

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

	ret = acpi_arm64_ffh_update_custom_offset_handler(nvidia_ffh_handler);
	if (ret) {
		dev_err(&pdev->dev,
			"Failed to register custom offset handler error=%d\n", ret);
		return ret;
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
	acpi_arm64_ffh_update_custom_offset_handler(NULL);
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
