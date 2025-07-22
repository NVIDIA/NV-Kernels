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

/* FFA device for EC notification service */
static struct ffa_device *notify_ffa_dev;

static const uuid_t nvidia_ec_notify_service_uuid =
	UUID_INIT(0xb510b3a3, 0x59f6, 0x4054, 0xba, 0x7a, 0xff, 0x2e, 0xb1, 0xea, 0xc7, 0x65);

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

static const guid_t nvidia_notify_bind_guid =
	GUID_INIT(0xdaffd814, 0x6eba, 0x4d8c, 0x8a, 0x91, 0xbc, 0x9b, 0xbf, 0x4a, 0xa3, 0x01);

static const guid_t nvidia_notify_dsm_guid =
	GUID_INIT(0x7681541e, 0x8827, 0x4239, 0x8d, 0x9d, 0x36, 0xbe, 0x7f, 0xe1, 0x25, 0x42);

#define NVIDIA_FFA_MAX_NOTIFICATIONS	64

/* EC service FFA device structure */
struct nvidia_ec_ffa_device {
	struct ffa_device *ffa_dev;
	u8 notification_count;
	u8 notification_id[NVIDIA_FFA_MAX_NOTIFICATIONS];
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

/*
 * ACPI ASL code uses ToUUID() macro which encodes it in mixed-endian format.
 * Convert UUID buffer to AML UUID.
 */
static void nvidia_uuid_to_aml_uuid_buf(const uuid_t *uuid, u8 *buf)
{
	const u8 *src = (u8 *)uuid;

	buf[0] = src[3];
	buf[1] = src[2];
	buf[2] = src[1];
	buf[3] = src[0];

	buf[4] = src[5];
	buf[5] = src[4];
	buf[6] = src[7];
	buf[7] = src[6];

	memcpy(buf + 8, src + 8, 8);
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
 * Fill the virtual notification IDs array supported by the current FFA device.
 * ACPI _DSD object contains notification mapping. It uses nexted package
 * acpi object.
 *
 * From the example given in
 * https://github.com/OpenDevicePartnership/documentation/blob/main/bookshelf/Shelf%204%20Specifications/EC%20Interface/src/secure-ec-services-overview.md#register-notification
 *
 * pkg1		        Name(_DSD, Package() {
 * pkg1_guid		  ToUUID("daffd814-6eba-4d8c-8a91-bc9bbf4aa301"), // Device Prop UUID
 * pkg2			    Package() {
 * pkg3			    Package(2) {
 * pkg3_prop		      "arm-arml0002-ffa-ntf-bind",
 * pkg4			      Package() {
 * pkg4_rev			1, // Revision
 * pkg4_count			1, // Count of following packages
 * pkg5				Package () {
 * pkg5_uuid			  ToUUID("330c1273-fde5-4757-9819-5b6539037502"), // Service1 UUID
 * pkg6				  Package () {
 * pkg6_notify_id[]		    0x01,     // Cookie1 (UINT32)
 *				    0x07,     // Cookie2
 *				  }
 *				},
 *			      }
 *			    }
 *			  }
 *			}) // _DSD()
 *
 * The variable names in this function are according to above.
 */
static int nvidia_ffa_fill_notification_map(struct nvidia_ec_ffa_device *ec_ffa_dev)
{
	struct acpi_device *adev = ACPI_COMPANION(&ffa_pdev->dev);
	struct acpi_buffer output = { ACPI_ALLOCATE_BUFFER, NULL };
	union acpi_object *pkg1, *pkg1_guid;
	union acpi_object *pkg2;
	union acpi_object *pkg3, *pkg3_prop;
	union acpi_object *pkg4, *pkg4_rev, *pkg4_count;
	acpi_status status;
	int i;

	status = acpi_evaluate_object_typed(adev->handle, "_DSD", NULL,
					    &output, ACPI_TYPE_PACKAGE);
	if (ACPI_FAILURE(status)) {
		dev_err(&ffa_pdev->dev, "ACPI _DSD object not found\n");
		return -ENODEV;
	}

	pkg1 = output.pointer;

	/*
	 * _DSD returns a Package() with one or more pairs of elements.
	 * The first element of each pair is a Universal Unique Identifier (UUID).
	 * The second element of each pair is another Package() Data Structure.
	 *
	 * The _DSD for FFA device will have only one pair of elements so
	 * pkg1 elements count should be 2.
	 */
	if (pkg1->package.count != 2) {
		kfree(output.pointer);
		return -EINVAL;
	}

	pkg1_guid = &pkg1->package.elements[0];
	pkg2 = &pkg1->package.elements[1];
	if (pkg1_guid->type != ACPI_TYPE_BUFFER ||
	    pkg1_guid->buffer.length != UUID_SIZE ||
	    pkg2->type != ACPI_TYPE_PACKAGE) {
		kfree(output.pointer);
		return -EINVAL;
	}

	/* Check if GUID macthes with notify device prop GUID */
	if (!guid_equal((guid_t *)pkg1_guid->buffer.pointer,
			&nvidia_notify_bind_guid)) {
		kfree(output.pointer);
		return -EINVAL;
	}

	/* pkg3 should conatin 1 element with package type */
	if (pkg2->package.count != 1) {
		kfree(output.pointer);
		return -EINVAL;
	}

	pkg3 = &pkg2->package.elements[0];
	if (pkg3->type != ACPI_TYPE_PACKAGE) {
		kfree(output.pointer);
		return -EINVAL;
	}

	pkg3_prop = &pkg3->package.elements[0];
	if (pkg3_prop->type != ACPI_TYPE_STRING ||
	    strncmp(pkg3_prop->string.pointer,
		    "arm-arml0002-ffa-ntf-bind",
		     pkg3_prop->string.length)) {
		kfree(output.pointer);
		return -EINVAL;
	}

	pkg4 = &pkg3->package.elements[1];
	/*
	 * pkg4 should have minimum 3 elements (revision, count and minimum
	 * one notification map package)
	 */
	if (pkg4->type != ACPI_TYPE_PACKAGE ||
	    pkg4->package.count < 3) {
		kfree(output.pointer);
		return -EINVAL;
	}

	pkg4_rev = &pkg4->package.elements[0];
	pkg4_count = &pkg4->package.elements[1];

	/* Check if revision is 1 */
	if (pkg4_rev->type != ACPI_TYPE_INTEGER ||
	    pkg4_rev->integer.value != 1) {
		kfree(output.pointer);
		return -EINVAL;
	}

	/*
	 * The pkg4_count represents the count of following packages.
	 * pkg4_count + 1 (for revision) + 1 (for pkg4_count itself) should
	 * match total number of elements in pkg4.
	 */
	if (pkg4_count->type != ACPI_TYPE_INTEGER ||
	    (pkg4_count->integer.value + 2) != pkg4->package.count) {
		kfree(output.pointer);
		return -EINVAL;
	}

	/*
	 * Traverse the array of notification map packages.
	 * Each notification map package contains 2 elements, UUID
	 * and notification ID array package. Check if there is a notification
	 * map for the FFA device by comparing UUID and update the
	 * notification_id[] and notification_count.
	 */
	for (i = 2; i < pkg4->package.count; i++) {
		union acpi_object *pkg5_uuid, *pkg5 = &pkg4->package.elements[2];
		union acpi_object *pkg6;
		uuid_t uuid;
		int j;

		if (pkg5->type != ACPI_TYPE_PACKAGE &&
		    pkg5->package.count != 2) {
			kfree(output.pointer);
			return -EINVAL;
		}

		pkg5_uuid =  &pkg5->package.elements[0];
		pkg6 = &pkg5->package.elements[1];
		if (pkg5_uuid->type != ACPI_TYPE_BUFFER ||
		    pkg5_uuid->buffer.length != UUID_SIZE ||
		    pkg6->type != ACPI_TYPE_PACKAGE) {
			kfree(output.pointer);
			return -EINVAL;
		}

		uuid = nvidia_get_uuid_from_aml_buf(pkg5_uuid->buffer.pointer);
		if (!uuid_equal(&uuid, &ec_ffa_dev->ffa_dev->uuid))
			continue;

		for (j = 0; j < pkg6->package.count; j++) {
			union acpi_object *pkg6_notify_id = &pkg6->package.elements[j];

			if (pkg6_notify_id->type != ACPI_TYPE_INTEGER) {
				kfree(output.pointer);
				return -EINVAL;
			}

			ec_ffa_dev->notification_id[j] = pkg6_notify_id->integer.value;
		}

		ec_ffa_dev->notification_count = pkg6->package.count;
		kfree(output.pointer);
		return 0;
	}

	kfree(output.pointer);
	return 0;
}

/*
 * Notification EC service callback.
 * Get the ffa device from callback data and invoke notification _DSM with
 * notify_id.
 *
 * The details regarding _DSM is documented in
 * https://github.com/OpenDevicePartnership/documentation/tree/main/bookshelf/Shelf%204%20Specifications#notification-events
 */
static void nvidia_ffa_ec_service_notif_callback(int notify_id, void *cb_data)
{
	struct acpi_device *adev = ACPI_COMPANION(&ffa_pdev->dev);
	struct ffa_device *ffa_dev = (struct ffa_device *)cb_data;
	union acpi_object args[2], input_pkg;
	union acpi_object  *output;
	u8 uuid[UUID_SIZE];

	nvidia_uuid_to_aml_uuid_buf(&ffa_dev->uuid, uuid);

	args[0].type = ACPI_TYPE_BUFFER;
	args[0].buffer.length = sizeof(uuid);
	args[0].buffer.pointer = uuid;

	args[1].type = ACPI_TYPE_INTEGER;
	args[1].integer.value = notify_id;

	input_pkg.type = ACPI_TYPE_PACKAGE;
	input_pkg.package.count = 2;
	input_pkg.package.elements = args;

	output = acpi_evaluate_dsm(adev->handle, &nvidia_notify_dsm_guid,
				   1, 1, &input_pkg);
	if (!output)
		dev_err(&ffa_pdev->dev, "Failed to execute notify\n");
	else
		ACPI_FREE(output);
}

/*
 * Create notification setup for the notification_id.
 *
 * The details regarding notification setup is documented in
 * https://github.com/OpenDevicePartnership/documentation/tree/main/bookshelf/Shelf%204%20Specifications#register-notification
 *
 * This function setup 1:1 mapping between hardware notification ID and
 * virtual notification ID.
 */
static int nvidia_ffa_notification_setup(struct nvidia_ec_ffa_device *ec_ffa_dev,
					 u8 notification_id)
{
	struct ffa_send_direct_data2 ffa_data = { 0 };
	u8 *uuid = (u8 *)&ec_ffa_dev->ffa_dev->uuid;
	int ret;

	/* X4 register, function 1 */
	ffa_data.data[0] = 1;

	BUILD_BUG_ON(UUID_SIZE != 16);
	BUILD_BUG_ON(sizeof(ffa_data.data[1]) < 8);

	/* X5 and X6 registers contain UUID */
	memcpy(&ffa_data.data[1], uuid, 8);
	memcpy(&ffa_data.data[2], uuid + 8, 8);

	/* X7 register, the number of notification mappings */
	ffa_data.data[3] = 1;

	/* X7 register, notification ID and notification bitmap bit number */
	ffa_data.data[4] = ((u64)notification_id << 32) | notification_id;

	if (!notify_ffa_dev->ops ||
	    !notify_ffa_dev->ops->msg_ops ||
	    !notify_ffa_dev->ops->msg_ops->sync_send_receive2) {
		return -EINVAL;
	}

	ret = notify_ffa_dev->ops->msg_ops->sync_send_receive2(notify_ffa_dev,
							       &ffa_data);
	if (ret) {
		dev_err(&ec_ffa_dev->ffa_dev->dev,
			"Failed to send NOTIFY_SETUP id=%d error=%d\n",
			notification_id, ret);
		return ret;
	}

	if (ffa_data.data[0]) {
		dev_err(&ec_ffa_dev->ffa_dev->dev,
			"NOTIFY_SETUP returned failure id=%d error=%ld\n",
			notification_id, ffa_data.data[0]);

		/*
		 * TODO: destroy operation is not yet implemented in the firmware
		 * So, if driver is reloaded, then the previous notification
		 * still exists and failure will be returned. Once destroy
		 * is implemented in firmware, update code here to return error
		 */
	}

	return 0;
}

/* Destroy notification setup for the notification_id */
static void nvidia_ffa_notification_destroy(struct nvidia_ec_ffa_device *ec_ffa_dev,
					    u8 notification_id)
{
	/*
	 * TODO: destroy operation is not yet implemented in the firmware.
	 *       Once implemented in firmware, update code here.
	 */
}

/*
 * Create notifications for the FFA device.
 *
 * 1. Get notification map array for FFA device.
 * 2. For each notification, setup notification with notify service and
 *    then invoke notify_request method to enable notification for FFA device.
 */
static int nvidia_ffa_create_notifications(struct nvidia_ec_ffa_device *ec_ffa_dev)
{
	int i, ret = 0;

	if (!ec_ffa_dev->ffa_dev->ops ||
	    !ec_ffa_dev->ffa_dev->ops->notifier_ops ||
	    !ec_ffa_dev->ffa_dev->ops->notifier_ops->notify_request ||
	    !ec_ffa_dev->ffa_dev->ops->notifier_ops->notify_relinquish) {
		return -EOPNOTSUPP;
	}

	ret = nvidia_ffa_fill_notification_map(ec_ffa_dev);
	if (ret) {
		dev_err(&ffa_pdev->dev, "Error in filling notification map error=%d\n", ret);
		return ret;
	}

	for (i = 0; i < ec_ffa_dev->notification_count; i++) {
		ret = nvidia_ffa_notification_setup(ec_ffa_dev,
						    ec_ffa_dev->notification_id[i]);
		if (ret) {
			dev_err(&ec_ffa_dev->ffa_dev->dev,
				"Failed to setup notification id=%d error=%d\n",
				ec_ffa_dev->notification_id[i], ret);
			break;
		}

		ret = ec_ffa_dev->ffa_dev->ops->notifier_ops->notify_request(
				ec_ffa_dev->ffa_dev, false,
				nvidia_ffa_ec_service_notif_callback,
				ec_ffa_dev->ffa_dev, ec_ffa_dev->notification_id[i]);
		if (ret) {
			nvidia_ffa_notification_destroy(ec_ffa_dev,
							ec_ffa_dev->notification_id[i]);
			dev_err(&ec_ffa_dev->ffa_dev->dev,
				"Failed to request notification id=%d error=%d\n",
				ec_ffa_dev->notification_id[i], ret);
			break;
		}
	}

	/* Remove already setup notification in case of error */
	if (ret) {
		int j;

		for (j = 0; j < i; j++) {
			ec_ffa_dev->ffa_dev->ops->notifier_ops->notify_relinquish(
				ec_ffa_dev->ffa_dev,
				ec_ffa_dev->notification_id[j]);
			nvidia_ffa_notification_destroy(ec_ffa_dev,
							ec_ffa_dev->notification_id[j]);
		}

		ec_ffa_dev->notification_count = 0;
	}

	return ret;
}

/* Remove notifications for the FFA device. */
static void nvidia_ffa_remove_notifications(struct nvidia_ec_ffa_device *ec_ffa_dev)
{
	int i;

	for (i = 0; i < ec_ffa_dev->notification_count; i++) {
		ec_ffa_dev->ffa_dev->ops->notifier_ops->notify_relinquish(
			ec_ffa_dev->ffa_dev,
			ec_ffa_dev->notification_id[i]);
		nvidia_ffa_notification_destroy(ec_ffa_dev,
						ec_ffa_dev->notification_id[i]);
	}
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
	unsigned int ffh_copy_len;
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

	/*
	 * Copy the ACPI FFA data back into ACPI FFH packet.
	 *
	 * ACPI FFH packet raw data length can't be fetched here, so copy
	 * all bytes from ffa_data.data
	 */
	ffh_copy_len = min(sizeof(ffa_data.data),
			   info->length - offsetof(struct nvidia_ec_ffa_packet, rawdata));

	memcpy(ffa_packet->rawdata, ffa_data.data, ffh_copy_len);
	return 0;
}

static int nvidia_ffa_ec_service_probe(struct ffa_device *ffa_dev)
{
	struct nvidia_ec_ffa_device *nvidia_ec_ffa_dev;
	const char *acpi_id = NULL;
	int ret;

	if (!ffa_pdev || !notify_ffa_dev) {
		dev_err(&ffa_dev->dev, "nvidia ffa or notify device not available\n");
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

	ret = nvidia_ffa_create_notifications(nvidia_ec_ffa_dev);
	if (ret) {
		dev_info(&ffa_dev->dev,
			 "Failed to create ffa notifications error=%d\n",
			  ret);
		devm_kfree(&ffa_dev->dev, nvidia_ec_ffa_dev);
		return ret;
	}

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
			nvidia_ffa_remove_notifications(cur);
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

static int nvidia_ffa_notify_service_probe(struct ffa_device *ffa_dev)
{
	int ret;

	if (!ffa_pdev) {
		dev_err(&ffa_dev->dev, "nvidia ffa device not available\n");
		return -ENODEV;
	}

	notify_ffa_dev = ffa_dev;

	ret = ffa_driver_register(&nvidia_ffa_ec_service_driver, THIS_MODULE, DRV_NAME);
	if (ret) {
		dev_err(&ffa_dev->dev,
			"Failed to register ec service driver error=%d\n", ret);
		notify_ffa_dev = NULL;
		return ret;
	}

	return 0;
}

static void nvidia_ffa_notify_service_remove(struct ffa_device *ffa_dev)
{
	ffa_driver_unregister(&nvidia_ffa_ec_service_driver);
	notify_ffa_dev = NULL;
}

static const struct ffa_device_id nvidia_ffa_notify_service_ids[] = {
	{ nvidia_ec_notify_service_uuid },
	{}
};

static struct ffa_driver nvidia_ffa_notify_service_driver = {
	.name = "nvidia-ffa-notify",
	.probe = nvidia_ffa_notify_service_probe,
	.remove = nvidia_ffa_notify_service_remove,
	.id_table = nvidia_ffa_notify_service_ids,
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

	ret = ffa_driver_register(&nvidia_ffa_notify_service_driver, THIS_MODULE, DRV_NAME);
	if (ret) {
		dev_err(&pdev->dev,
			"Failed to register notify service driver error=%d\n", ret);
		acpi_arm64_ffh_update_custom_offset_handler(NULL);
		ffa_pdev = NULL;
		return ret;
	}

	return 0;
}

static void nvidia_ffa_remove(struct platform_device *pdev)
{
	ffa_driver_unregister(&nvidia_ffa_notify_service_driver);
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
