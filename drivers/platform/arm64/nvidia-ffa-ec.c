// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025-2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/kernel.h>
#include <linux/cleanup.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/acpi.h>
#include <linux/arm_ffa.h>
#include <linux/list.h>

#define DRV_NAME "nvidia-ffa-ec"

/*
 * Spec version selected at probe time:
 *   true  - MSFT000C, OpenDevicePartnership legacy draft spec
 *           (https://github.com/OpenDevicePartnership/documentation/blob/0f7b6bad77a3eb07b66b66d0e3af718db2ec1c24/bookshelf/Shelf%204%20Specifications/EC%20Interface/src/secure-ec-services-overview.md)
 *   false - ARML0002, ARM DEN0077A v1.3 spec
 *           (https://support.arm.com/documentation/den0077)
 */
static bool ffa_ec_legacy_spec;

/* platform device for FFA ACPI device */
static struct platform_device *ffa_pdev;

/*
 * FFA device for the control-plane service used to register EC
 * notifications. A given platform's FF-A bridge only exposes one of the
 * two possible UUIDs:
 *
 *   MSFT000C: EC notification service UUID
 *             (b510b3a3-59f6-4054-ba7a-ff2eb1eac765)
 *   ARML0002: inter-partition setup protocol UUID
 *             (e474d87e-5731-4044-a727-cb3e8cf3c8df)
 */
static struct ffa_device *control_ffa_dev;

static const uuid_t nvidia_ec_notify_service_uuid =
	UUID_INIT(0xb510b3a3, 0x59f6, 0x4054, 0xba, 0x7a, 0xff, 0x2e, 0xb1, 0xea, 0xc7, 0x65);

/* Inter-partition setup protocol UUID (DEN0077A v1.3 section 18.7) */
static const uuid_t nvidia_ec_interpartition_setup_uuid =
	UUID_INIT(0xe474d87e, 0x5731, 0x4044, 0xa7, 0x27, 0xcb, 0x3e, 0x8c, 0xf3, 0xc8, 0xdf);

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

/*
 * Outer UUID identifying the payload as "Device Properties" in the ACPI
 * _DSD returned by the FFA bridge. DEN0077A v1.3 changed this GUID
 * between drafts:
 *
 *   ALP3 and earlier: daffd814-6eba-4d8c-8a91-bc9bbf4aa301
 *   ALP4 and later:   c08c3233-b316-4723-a9d7-e21b7ac0fb6a
 */
static const guid_t nvidia_notify_bind_guid_legacy =
	GUID_INIT(0xdaffd814, 0x6eba, 0x4d8c, 0x8a, 0x91, 0xbc, 0x9b, 0xbf, 0x4a, 0xa3, 0x01);

static const guid_t nvidia_notify_bind_guid =
	GUID_INIT(0xc08c3233, 0xb316, 0x4723, 0xa9, 0xd7, 0xe2, 0x1b, 0x7a, 0xc0, 0xfb, 0x6a);

static const guid_t nvidia_notify_dsm_guid =
	GUID_INIT(0x7681541e, 0x8827, 0x4239, 0x8d, 0x9d, 0x36, 0xbe, 0x7f, 0xe1, 0x25, 0x42);

#define NVIDIA_FFA_MAX_NOTIFICATIONS	64

/* Revision values for the "arm-arml0002-ffa-ntf-bind" property package */
#define NVIDIA_FFA_NTF_BIND_REV_MSFT000C		1
#define NVIDIA_FFA_NTF_BIND_REV_ARML0002	0x00010000

/*
 * Notification tuple encoding for ARML0002 (DEN0077A v1.3 section 18.7.1,
 * Table 18.25):
 *   bits[63:32] = cookie (u32)
 *   bits[31:23] = notification ID (9-bit field, LSB at bit 23)
 *   bits[22:1]  = Reserved (MBZ)
 *   bit[0]      = per-vCPU flag (0 = global)
 */
#define NVIDIA_EC_NOTIF_TUPLE(cookie, id) \
	(((u64)(cookie) << 32) | (((u64)(id) & 0x1FF) << 23))

/* Message info field: bits[2:0] = 0b010 means notification registration */
#define NVIDIA_EC_INTERPARTITION_MSG_NOTIF_REG	0x2

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

/*
 * EC secure services FFA packet structure — MSFT000C (FFH offset 4).
 * https://github.com/OpenDevicePartnership/documentation/blob/0f7b6bad77a3eb07b66b66d0e3af718db2ec1c24/bookshelf/Shelf%204%20Specifications/EC%20Interface/src/secure-ec-services-overview.md#operation-region-definition
 *
 * Byte layout:
 *   [0]      u8  status  — zero on input; 1 on error output
 *   [1]      u8  length  — payload byte count
 *   [2..17]  u8  uuid[16]
 *   [18+]    u8  rawdata[]
 */
struct nvidia_ec_ffa_packet_msft000c {
	u8 status;
	u8 length;
	u8 uuid[UUID_SIZE];
	u8 rawdata[];
} __packed;

/*
 * EC secure services FFA packet structure — ARML0002 (FFH offset 2).
 * Layout per the OpenDevicePartnership odp-embedded-controller
 * secure-ec-services-overview spec (Operation Region Definition).
 *
 *   [0..7]   u64 status  — AML writes 0; FFH handler sets 1 on error
 *   [8..15]  u64 recvid  — receiver endpoint ID, not touched by handler
 *   [16..31] u8  uuid[16] — target service UUID
 *   [32+]    u8  rawdata[] — payload copied to/from X4..X17
 */
struct nvidia_ec_ffa_packet_arml0002 {
	u64 status;
	u64 recvid;
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
 * ACPI _DSD object contains notification mapping via nested packages.
 *
 * Both MSFT000C and ARML0002 use the same property key
 * "arm-arml0002-ffa-ntf-bind" and the same nested package structure, but
 * differ in the revision field:
 *   MSFT000C: pkg4_rev = 1
 *   ARML0002: pkg4_rev = 0x00010000
 *
 * From the example given in DEN0077A v1.3 section 18.8.2:
 *
 * pkg1		        Name(_DSD, Package() {
 * pkg1_guid		  ToUUID("c08c3233-b316-4723-a9d7-e21b7ac0fb6a"),
 * pkg2			    Package() {
 * pkg3			    Package(2) {
 * pkg3_prop		      "arm-arml0002-ffa-ntf-bind",
 * pkg4			      Package() {
 * pkg4_rev			0x00010000,  // Revision (v1.0)
 * pkg4_count			1,           // Count of following packages
 * pkg5				Package () {
 * pkg5_uuid			  ToUUID("...service UUID..."),
 * pkg6				  Package () {
 * pkg6_notify_id[]		    0x01,    // Cookie1 (UINT32)
 *				  }
 *				},
 *			      }
 *			    }
 *			  }
 *			}) // _DSD()
 *
 * Local variable names below follow the pkgN_* labels in the diagram above.
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
	 * The first element of each pair is a UUID, the second is a Package().
	 * The FFA device _DSD has only one such pair so count must be 2.
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

	/* Check if GUID matches with notify device prop GUID */
	if (!guid_equal((guid_t *)pkg1_guid->buffer.pointer,
			&nvidia_notify_bind_guid) &&
	    !guid_equal((guid_t *)pkg1_guid->buffer.pointer,
			&nvidia_notify_bind_guid_legacy)) {
		kfree(output.pointer);
		return -EINVAL;
	}

	/* pkg2 should contain 1 element with package type */
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
	 * pkg4 must have at least 3 elements: revision, count, and one
	 * notification map package.
	 */
	if (pkg4->type != ACPI_TYPE_PACKAGE ||
	    pkg4->package.count < 3) {
		kfree(output.pointer);
		return -EINVAL;
	}

	pkg4_rev = &pkg4->package.elements[0];
	pkg4_count = &pkg4->package.elements[1];

	/* Accept both revision values */
	if (pkg4_rev->type != ACPI_TYPE_INTEGER ||
	    (pkg4_rev->integer.value != NVIDIA_FFA_NTF_BIND_REV_MSFT000C &&
	     pkg4_rev->integer.value != NVIDIA_FFA_NTF_BIND_REV_ARML0002)) {
		kfree(output.pointer);
		return -EINVAL;
	}

	/*
	 * pkg4_count + 1 (revision) + 1 (count itself) must equal total
	 * elements in pkg4.
	 */
	if (pkg4_count->type != ACPI_TYPE_INTEGER ||
	    (pkg4_count->integer.value + 2) != pkg4->package.count) {
		kfree(output.pointer);
		return -EINVAL;
	}

	/*
	 * Traverse the array of notification map packages. Each entry has a
	 * UUID and a package of cookie integers. Match UUID against the FFA
	 * device and populate notification_id[].
	 */
	for (i = 2; i < pkg4->package.count; i++) {
		union acpi_object *pkg5_uuid, *pkg5 = &pkg4->package.elements[i];
		union acpi_object *pkg6;
		uuid_t uuid;
		int j;

		if (pkg5->type != ACPI_TYPE_PACKAGE ||
		    pkg5->package.count != 2) {
			kfree(output.pointer);
			return -EINVAL;
		}

		pkg5_uuid = &pkg5->package.elements[0];
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
 * MSFT000C notification setup.
 *
 * The details regarding notification setup is documented in
 * https://github.com/OpenDevicePartnership/documentation/blob/0f7b6bad77a3eb07b66b66d0e3af718db2ec1c24/bookshelf/Shelf%204%20Specifications/EC%20Interface/src/secure-ec-services-overview.md#register-notification
 */
static int nvidia_ffa_notification_setup_msft000c(struct nvidia_ec_ffa_device *ec_ffa_dev,
						  u8 notification_id)
{
	struct ffa_send_direct_data2 ffa_data = { 0 };
	u8 *uuid = (u8 *)&ec_ffa_dev->ffa_dev->uuid;
	int ret;

	BUILD_BUG_ON(UUID_SIZE != 16);
	BUILD_BUG_ON(sizeof(ffa_data.data[1]) < 8);

	/* X4: function 1 (NOTIFY_SETUP) */
	ffa_data.data[0] = 1;

	/* X5, X6: EC service UUID */
	memcpy(&ffa_data.data[1], uuid, 8);
	memcpy(&ffa_data.data[2], uuid + 8, 8);

	/* X7: number of notification mappings */
	ffa_data.data[3] = 1;

	/* X8: notification ID used as both cookie and bitmap bit number */
	ffa_data.data[4] = ((u64)notification_id << 32) | notification_id;

	if (!control_ffa_dev->ops ||
	    !control_ffa_dev->ops->msg_ops ||
	    !control_ffa_dev->ops->msg_ops->sync_send_receive2)
		return -EINVAL;

	ret = control_ffa_dev->ops->msg_ops->sync_send_receive2(control_ffa_dev,
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

/*
 * ARML0002 notification setup (DEN0077A v1.3 section 18.7.1, Table 18.25).
 * Uses the inter-partition setup protocol UUID.
 */
static int nvidia_ffa_notification_setup_arml0002(struct nvidia_ec_ffa_device *ec_ffa_dev,
						  u8 notification_id)
{
	struct ffa_send_direct_data2 ffa_data = { 0 };
	u8 *svc_uuid = (u8 *)&ec_ffa_dev->ffa_dev->uuid;
	int ret;

	BUILD_BUG_ON(UUID_SIZE != 16);
	BUILD_BUG_ON(sizeof(ffa_data.data[1]) < 8);

	/* Sender UUID: not applicable for OS-side caller, left as zero */

	/* X7, X8: receiver (EC) service UUID */
	memcpy(&ffa_data.data[3], svc_uuid, 8);
	memcpy(&ffa_data.data[4], svc_uuid + 8, 8);

	/* X9: notification registration request */
	ffa_data.data[5] = NVIDIA_EC_INTERPARTITION_MSG_NOTIF_REG;

	/* X10: one tuple */
	ffa_data.data[6] = 1;

	/* X11: tuple — cookie = notification_id, bitmap position = notification_id */
	ffa_data.data[7] = NVIDIA_EC_NOTIF_TUPLE(notification_id, notification_id);

	if (!control_ffa_dev->ops ||
	    !control_ffa_dev->ops->msg_ops ||
	    !control_ffa_dev->ops->msg_ops->sync_send_receive2)
		return -EINVAL;

	ret = control_ffa_dev->ops->msg_ops->sync_send_receive2(control_ffa_dev,
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
		return -EIO;
	}

	return 0;
}

static int nvidia_ffa_notification_setup(struct nvidia_ec_ffa_device *ec_ffa_dev,
					 u8 notification_id)
{
	if (!ffa_ec_legacy_spec)
		return nvidia_ffa_notification_setup_arml0002(ec_ffa_dev, notification_id);

	return nvidia_ffa_notification_setup_msft000c(ec_ffa_dev, notification_id);
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
 * 2. For each notification, setup notification with the control service and
 *    then invoke notify_request to enable notification for the FFA device.
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
 * Common FFA send path shared by both FFH handlers.
 *
 * Looks up the EC device by UUID, copies input_len bytes from rawdata into
 * the FFA data registers, sends FFA_MSG_SEND_DIRECT_REQ2, then copies
 * output_len bytes of the response back into rawdata.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int nvidia_ffh_do_ffa_send(uuid_t uuid, u8 *rawdata,
				  unsigned int input_len, unsigned int output_len)
{
	struct ffa_send_direct_data2 ffa_data = { 0 };
	struct nvidia_ec_ffa_device *cur, *ec_dev = NULL;
	int ret;

	/*
	 * Hold nvidia_ffa_lock across the whole lookup + send so ec_dev
	 * cannot be freed by a concurrent nvidia_ffa_ec_service_remove()
	 * while its ->ffa_dev is still being dereferenced here.
	 */
	guard(mutex)(&nvidia_ffa_lock);

	list_for_each_entry(cur, &nvidia_ec_ffa_dev_head, list) {
		if (uuid_equal(&uuid, &cur->ffa_dev->uuid)) {
			ec_dev = cur;
			break;
		}
	}

	if (!ec_dev)
		return -ENODEV;

	if (!ec_dev->ffa_dev->ops ||
	    !ec_dev->ffa_dev->ops->msg_ops ||
	    !ec_dev->ffa_dev->ops->msg_ops->sync_send_receive2)
		return -EINVAL;

	memcpy(ffa_data.data, rawdata, input_len);

	ret = ec_dev->ffa_dev->ops->msg_ops->sync_send_receive2(ec_dev->ffa_dev, &ffa_data);
	if (ret) {
		dev_err(&ec_dev->ffa_dev->dev,
			"Failed to send FFA messages error=%d\n", ret);
		return ret;
	}

	memcpy(rawdata, ffa_data.data, output_len);
	return 0;
}

/* FFH handler — MSFT000C (FFH offset 4) */
static int nvidia_ffh_handler_msft000c(struct acpi_ffh_info *info, acpi_integer *value)
{
	struct nvidia_ec_ffa_packet_msft000c *pkt = (struct nvidia_ec_ffa_packet_msft000c *)value;
	unsigned int rawdata_buflen, ffh_copy_len;
	uuid_t uuid;
	int ret;

	/* Buffer must fit at least the fixed header */
	if (info->length < offsetof(struct nvidia_ec_ffa_packet_msft000c, rawdata))
		return -EINVAL;

	rawdata_buflen = info->length - offsetof(struct nvidia_ec_ffa_packet_msft000c, rawdata);

	/* Buffer must fit header + declared payload */
	if (rawdata_buflen < pkt->length) {
		pkt->status = 1;
		return -EINVAL;
	}

	/* Payload must fit in the 14 FFA data registers (112 bytes) */
	if (pkt->length > sizeof_field(struct ffa_send_direct_data2, data)) {
		pkt->status = 1;
		return -EINVAL;
	}

	/*
	 * MSFT000C responses can be larger than the request, and the FFH
	 * region does not carry a response length. Send pkt->length bytes to
	 * the SP, and copy back as much of the response register file as the
	 * AML buffer can hold, bounded by the 14 FFA data registers (112
	 * bytes).
	 */
	ffh_copy_len = min(rawdata_buflen,
			   sizeof_field(struct ffa_send_direct_data2, data));

	uuid = nvidia_get_uuid_from_aml_buf(pkt->uuid);
	ret = nvidia_ffh_do_ffa_send(uuid, pkt->rawdata, pkt->length,
				     ffh_copy_len);
	pkt->status = ret ? 1 : 0;
	return ret;
}

/* FFH handler — ARML0002 (FFH offset 2) */
static int nvidia_ffh_handler_arml0002(struct acpi_ffh_info *info, acpi_integer *value)
{
	struct nvidia_ec_ffa_packet_arml0002 *pkt = (struct nvidia_ec_ffa_packet_arml0002 *)value;
	unsigned int payload_len;
	uuid_t uuid;
	int ret;

	/* Buffer must fit the fixed header */
	if (info->length < offsetof(struct nvidia_ec_ffa_packet_arml0002, rawdata))
		return -EINVAL;

	payload_len = info->length - offsetof(struct nvidia_ec_ffa_packet_arml0002, rawdata);

	/* Payload must fit in the 14 FFA data registers (112 bytes) */
	if (payload_len > sizeof_field(struct ffa_send_direct_data2, data)) {
		pkt->status = 1;
		return -EINVAL;
	}

	uuid = nvidia_get_uuid_from_aml_buf(pkt->uuid);
	ret = nvidia_ffh_do_ffa_send(uuid, pkt->rawdata, payload_len, payload_len);
	pkt->status = ret ? 1 : 0;
	return ret;
}

/*
 * Dispatch to the correct FFH handler based on the spec version and FFH
 * operation-region offset. The offset selects the FFA packet layout the
 * SPMC expects:
 *   ARML0002: offset 2 — struct nvidia_ec_ffa_packet_arml0002
 *             operation-region defined by ARM DEN0048D "Arm Functional
 *             Fixed Hardware Specification (FFH)" v1.3 section 2.3
 *   MSFT000C: offset 4 — struct nvidia_ec_ffa_packet_msft000c
 *             operation-region defined by the OpenDevicePartnership
 *             draft (secure-ec-services-overview.md)
 */
static int nvidia_ffh_handler(struct acpi_ffh_info *info, acpi_integer *value,
			      void *region_context)
{
	if (!ffa_ec_legacy_spec && info->offset == 2)
		return nvidia_ffh_handler_arml0002(info, value);

	if (ffa_ec_legacy_spec && info->offset == 4)
		return nvidia_ffh_handler_msft000c(info, value);

	return -EOPNOTSUPP;
}

static int nvidia_ffa_ec_service_probe(struct ffa_device *ffa_dev)
{
	struct nvidia_ec_ffa_device *nvidia_ec_ffa_dev;
	const char *acpi_id = NULL;
	int ret;

	if (!ffa_pdev || !control_ffa_dev) {
		dev_err(&ffa_dev->dev, "nvidia ffa or control device not available\n");
		return -ENODEV;
	}

	nvidia_ec_ffa_dev = devm_kzalloc(&ffa_dev->dev,
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
		dev_err(&ffa_dev->dev,
			"Failed to create ffa notifications error=%d\n", ret);
		devm_kfree(&ffa_dev->dev, nvidia_ec_ffa_dev);
		return ret;
	}

	mutex_lock(&nvidia_ffa_lock);
	list_add(&nvidia_ec_ffa_dev->list, &nvidia_ec_ffa_dev_head);
	mutex_unlock(&nvidia_ffa_lock);

	/*
	 * When acpi subsystem probes all ACPI devices, it executes _STA
	 * method for each device. The _STA method fails at that time since
	 * the custom FFA driver won't be ready. Get ACPI ID from UUID and
	 * rescan the device again.
	 */
	acpi_id = nvidia_get_acpi_id_from_uuid(&ffa_dev->uuid);
	if (acpi_id)
		acpi_bus_for_each_dev(nvidia_ffa_rescan_acpi_device,
				      (void *)acpi_id);

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

/*
 * Unified control-plane service driver.
 *
 * The id_table lists both control-plane UUIDs; a given platform's FF-A
 * bridge only exposes one of them (chosen by the ACPI HID that also
 * seeds ffa_ec_legacy_spec at parent probe time):
 *
 * Whichever device the framework matches, the probe stores it in
 * control_ffa_dev and registers the shared EC service driver.
 */
static int nvidia_ffa_control_service_probe(struct ffa_device *ffa_dev)
{
	int ret;

	if (!ffa_pdev) {
		dev_err(&ffa_dev->dev, "nvidia ffa device not available\n");
		return -ENODEV;
	}

	if (control_ffa_dev) {
		dev_err(&ffa_dev->dev, "control FFA device already registered\n");
		return -EBUSY;
	}

	control_ffa_dev = ffa_dev;

	ret = ffa_driver_register(&nvidia_ffa_ec_service_driver, THIS_MODULE, DRV_NAME);
	if (ret) {
		dev_err(&ffa_dev->dev,
			"Failed to register ec service driver error=%d\n", ret);
		control_ffa_dev = NULL;
		return ret;
	}

	return 0;
}

static void nvidia_ffa_control_service_remove(struct ffa_device *ffa_dev)
{
	ffa_driver_unregister(&nvidia_ffa_ec_service_driver);
	control_ffa_dev = NULL;
}

static const struct ffa_device_id nvidia_ffa_control_service_ids[] = {
	{ nvidia_ec_notify_service_uuid },          /* MSFT000C */
	{ nvidia_ec_interpartition_setup_uuid },    /* ARML0002 */
	{}
};

static struct ffa_driver nvidia_ffa_control_service_driver = {
	.name = "nvidia-ffa-control",
	.probe = nvidia_ffa_control_service_probe,
	.remove = nvidia_ffa_control_service_remove,
	.id_table = nvidia_ffa_control_service_ids,
};

static const struct acpi_device_id nvidia_ffa_device_ids[] = {
	{"MSFT000C", true},
	{"ARML0002", false},
	{"", 0},
};

MODULE_DEVICE_TABLE(acpi, nvidia_ffa_device_ids);

static int nvidia_ffa_probe(struct platform_device *pdev)
{
	const struct acpi_device_id *acpi_id;
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

	acpi_id = acpi_match_device(nvidia_ffa_device_ids, &pdev->dev);
	if (!acpi_id) {
		dev_err(&pdev->dev, "No matching ACPI device ID\n");
		return -ENODEV;
	}
	ffa_ec_legacy_spec = acpi_id->driver_data;

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

	ret = ffa_driver_register(&nvidia_ffa_control_service_driver,
				  THIS_MODULE, DRV_NAME);
	if (ret) {
		dev_err(&pdev->dev,
			"Failed to register control service driver error=%d\n", ret);
		acpi_arm64_ffh_update_custom_offset_handler(NULL);
		ffa_pdev = NULL;
		return ret;
	}

	return 0;
}

static void nvidia_ffa_remove(struct platform_device *pdev)
{
	ffa_driver_unregister(&nvidia_ffa_control_service_driver);
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
arch_initcall(nvidia_ffa_init);

static void __exit nvidia_ffa_exit(void)
{
	platform_driver_unregister(&nvidia_ffa_driver);
}
module_exit(nvidia_ffa_exit);

MODULE_SOFTDEP("pre: arm-ffa");
MODULE_AUTHOR("NVIDIA CORPORATION");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("NVIDIA FFA EC services driver");
