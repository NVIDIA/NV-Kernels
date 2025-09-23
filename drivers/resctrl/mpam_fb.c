// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2024 Arm Ltd.

#include <linux/arm_mpam.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/mailbox_client.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/printk.h>
#include <linux/scmi_protocol.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include <asm/mpam.h>

#include "mpam_fb.h"

#define MPAM_MSC_ATTRIBUTES	0x3
#define MPAM_MSC_READ		0x4
#define MPAM_MSC_WRITE		0x5

static const struct scmi_mpam_proto_ops *mpam_scmi_ops;

static DEFINE_MUTEX(scmi_agent_list_mutex);
static LIST_HEAD(smci_agent_list);

struct scmi_mpam_agent {
	struct list_head list;
	struct device_node *of_node;
	struct scmi_protocol_handle *ph_handle;
};

#define SCMI_BUF_LENGTH_IDX	4
#define SCMI_BUF_HEADER_IDX	5
#define SCMI_BUF_PAYLOAD_IDX	6
#define SCMI_READ_MSG_SIZE	9
#define SCMI_WRITE_MSG_SIZE	10

static int mpam_fb_build_read_message(int msc_id, int reg, u32 *msg_buf)
{
	memset(msg_buf, 0, SCMI_READ_MSG_SIZE * sizeof(u32));

	msg_buf[SCMI_BUF_LENGTH_IDX] = SCMI_READ_MSG_SIZE * sizeof(u32);
	msg_buf[SCMI_BUF_HEADER_IDX] = MPAM_MSC_READ | (0x1a << 10);
	msg_buf[SCMI_BUF_PAYLOAD_IDX + 0] = msc_id;
	msg_buf[SCMI_BUF_PAYLOAD_IDX + 2] = reg;

	return SCMI_READ_MSG_SIZE * sizeof(u32);
}

static int mpam_fb_build_write_message(int msc_id, int reg, u32 val,
				       u32 *msg_buf)
{
	memset(msg_buf, 0, SCMI_WRITE_MSG_SIZE * sizeof(u32));

	msg_buf[SCMI_BUF_LENGTH_IDX] = SCMI_WRITE_MSG_SIZE * sizeof(u32);
	msg_buf[SCMI_BUF_HEADER_IDX] = MPAM_MSC_WRITE | (0x1a << 10);
	msg_buf[SCMI_BUF_PAYLOAD_IDX + 0] = msc_id;
	msg_buf[SCMI_BUF_PAYLOAD_IDX + 2] = reg;
	msg_buf[SCMI_BUF_PAYLOAD_IDX + 3] = val;

	return SCMI_WRITE_MSG_SIZE * sizeof(u32);
}

static struct scmi_protocol_handle *scmi_agent_get_ph(const struct device_node *np)
{
	struct scmi_mpam_agent *agent;
	struct scmi_protocol_handle *ph = NULL;

	mutex_lock(&scmi_agent_list_mutex);

	list_for_each_entry(agent, &smci_agent_list, list) {
		if (np == agent->of_node) {
			ph = agent->ph_handle;
			break;
		}
	}

	mutex_unlock(&scmi_agent_list_mutex);

	return ph;
}

int mpam_fb_connect_channel(const struct device_node *of_node,
			    struct mpam_fb_channel *chan)
{
	int msc_id = 0;

	chan->ph_handle = scmi_agent_get_ph(of_node);
	if (!chan->ph_handle)
		return -EPROBE_DEFER;

	chan->use_scmi = true;

	return msc_id;
}

int mpam_fb_send_read_request(struct mpam_fb_channel *chan, int msc_id,
			      u16 reg, u32 *result)
{
	u32 msg_buf[12];
	int msg_len;

	msg_len = mpam_fb_build_read_message(msc_id, reg, msg_buf);

	if (chan->use_scmi) {
		/* The SCMI layer adds the shared memory header itself. */
		msg_len -= SCMI_BUF_PAYLOAD_IDX * sizeof(u32);

		mpam_scmi_ops->mpam_transfer_buf(chan->ph_handle,
						 MPAM_MSC_READ,
						 msg_buf + SCMI_BUF_PAYLOAD_IDX,
						 msg_len, result);

		return 0;
	}

	if (msg_len < chan->pcc_shmem_size)
		return -EINVAL;

	memcpy(chan->pcc_shmem, msg_buf, msg_len);
	mbox_send_message(chan->pcc_mbox, NULL);

	return 0;
}

int mpam_fb_send_write_request(struct mpam_fb_channel *chan, int msc_id,
			       u16 reg, u32 value)
{
	u32 msg_buf[12];
	int msg_len;

	msg_len = mpam_fb_build_write_message(msc_id, reg, value, msg_buf);
	if (msg_len < 0)
		return msg_len;

	if (chan->use_scmi) {
		/* The SCMI layer adds the shared memory header itself. */
		msg_len -= SCMI_BUF_PAYLOAD_IDX * sizeof(u32);

		mpam_scmi_ops->mpam_transfer_buf(chan->ph_handle,
						 MPAM_MSC_WRITE,
						 msg_buf + SCMI_BUF_PAYLOAD_IDX,
						 msg_len, NULL);

		return 0;
	}

	if (msg_len < chan->pcc_shmem_size)
		return -EINVAL;

	memcpy(chan->pcc_shmem, msg_buf, msg_len);
	mbox_send_message(chan->pcc_mbox, NULL);

	return 0;
}

static int scmi_mpam_probe(struct scmi_device *sdev)
{
	const struct scmi_handle *handle = sdev->handle;
	struct scmi_protocol_handle *ph;
	struct scmi_mpam_agent *agent;

	if (!handle)
		return -ENODEV;

	mpam_scmi_ops = handle->devm_protocol_get(sdev, SCMI_PROTOCOL_MPAM, &ph);
	if (IS_ERR(mpam_scmi_ops))
		return PTR_ERR(mpam_scmi_ops);

	agent = devm_kzalloc(&sdev->dev, sizeof(*agent), GFP_KERNEL);
	if (!agent)
		return -ENOMEM;

	agent->of_node = sdev->dev.of_node;
	agent->ph_handle = ph;

	mutex_lock(&scmi_agent_list_mutex);
	list_add(&agent->list, &smci_agent_list);
	mutex_unlock(&scmi_agent_list_mutex);

	return 0;
}

static void scmi_mpam_remove(struct scmi_device *sdev)
{
}

static const struct scmi_device_id scmi_id_table[] = {
	{ SCMI_PROTOCOL_MPAM, "mpam" },
	{},
};
MODULE_DEVICE_TABLE(scmi, scmi_id_table);

static struct scmi_driver scmi_mpam_driver = {
	.name = "scmi-mpam-driver",
	.probe = scmi_mpam_probe,
	.remove = scmi_mpam_remove,
	.id_table = scmi_id_table,
};
module_scmi_driver(scmi_mpam_driver);
