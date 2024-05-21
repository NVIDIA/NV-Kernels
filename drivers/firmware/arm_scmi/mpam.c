// SPDX-License-Identifier: GPL-2.0
/*
 * System Control and Management Interface (SCMI) MPAM Protocol
 *
 * Copyright (C) 2024 ARM Ltd.
 */

#include "common.h"
#include <linux/scmi_protocol.h>

#define SCMI_PROTOCOL_SUPPORTED_VERSION		0x10000

static int scmi_mpam_transfer_buf(const struct scmi_protocol_handle *ph,
				  u8 msg_id, void *msg_buf, size_t msg_len,
				  u32 *ret_val)
{
	int ret;
	struct scmi_xfer *t;

	ret = ph->xops->xfer_get_init(ph, msg_id, msg_len,
				      ret_val ? sizeof(*ret_val) : 0, &t);
	if (ret)
		return ret;

	memcpy(t->tx.buf, msg_buf, msg_len);

	ret = ph->xops->do_xfer(ph, t);
	if (!ret && ret_val) {
		u32 value;

		memcpy(&value, t->rx.buf, sizeof(value));
		*ret_val = le32_to_cpu((__le32)value);
	}

	ph->xops->xfer_put(ph, t);

	return ret;
}

static const struct scmi_mpam_proto_ops mpam_proto_ops = {
	.mpam_transfer_buf = scmi_mpam_transfer_buf,
};

static int scmi_mpam_protocol_init(const struct scmi_protocol_handle *ph)
{
	int ret;
	u32 version;

	ret = ph->xops->version_get(ph, &version);
	if (ret)
		return ret;

	dev_dbg(ph->dev, "SCMI MPAM Version %d.%d\n",
		PROTOCOL_REV_MAJOR(version), PROTOCOL_REV_MINOR(version));

	return 0;
}

static const struct scmi_protocol scmi_mpam = {
	.id = SCMI_PROTOCOL_MPAM,
	.owner = THIS_MODULE,
	.instance_init = &scmi_mpam_protocol_init,
	.ops = &mpam_proto_ops,
	.supported_version = SCMI_PROTOCOL_SUPPORTED_VERSION,
};

DEFINE_SCMI_PROTOCOL_REGISTER_UNREGISTER(mpam, scmi_mpam)
