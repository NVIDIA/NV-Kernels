// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 MediaTek Inc.
 *
 * MediaTek SSPM control interfac driver
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/version.h>

#include "sspm_ci.h"

/* MBOX */
#define MBOX_BOX(id, ofs)	(sspm_mbox_iomap + (id * 0x10000) + ofs)
#define MBOX_IN_SET(id)		(sspm_mbox_iomap + (id * 0x10000) + 0x1000)
#define MBOX_OUT_CLR(id)	(sspm_mbox_iomap + (id * 0x10000) + 0x1004)

/* SCMI */
#define SCMI_MESSAGE_HEADER_MESSAGE_ID_POS		0
#define SCMI_MESSAGE_HEADER_MESSAGE_TYPE_POS	8
#define SCMI_MESSAGE_HEADER_PROTOCOL_ID_POS		10
#define SCMI_MESSAGE_HEADER_TOKEN_POS			18

#define SCMI_NOTIFY_RECV_LEN					20
#define SCMI_PAYLOAD_OFFSET						7

#define SCMI_MESSAGE_HEADER_MESSAGE_ID_MASK \
			((0xFF) << SCMI_MESSAGE_HEADER_MESSAGE_ID_POS)
#define SCMI_MESSAGE_HEADER_MESSAGE_TYPE_MASK \
			((0x3) << SCMI_MESSAGE_HEADER_MESSAGE_TYPE_POS)
#define SCMI_MESSAGE_HEADER_PROTOCOL_ID_MASK \
			((0xFF)  << SCMI_MESSAGE_HEADER_PROTOCOL_ID_POS)
#define SCMI_MESSAGE_HEADER_TOKEN_MASK  \
			((0x3FF) << SCMI_MESSAGE_HEADER_TOKEN_POS)

/* MISC */
#define SSPM_MBOX_NUM		(2)
#define SSPM_CI_SET_ID		(0)
#define SSPM_CI_GET_ID		(1)

#define SSPM_CI_MAGIC		(0x01)

/* 10000 iterations × mdelay(1) = 10 seconds max wait for SSPM firmware ack */
#define SSPM_CI_MAX_POLL_COUNT	(10000)

#define IRQ_NAME_LEN		(32)

enum scmi_tinysys_protocol_cmd {
	TINYSYS_COMMON_SET = 0x3,
	TINYSYS_COMMON_GET = 0x4,
	TINYSYS_POWER_STATE_NOTIFY = 0x5,
	TINYSYS_SLBC_CTRL = 0x6,
};

enum scmi_mtk_protocol {
	SCMI_PROTOCOL_TINYSYS = 0x80,
};

enum scmi_message_type {
	SCMI_MESSAGE_TYPE_COMMAND = 0,
	SCMI_MESSAGE_TYPE_DELAYED_RESPONSE = 2,
	SCMI_MESSAGE_TYPE_NOTIFICATION = 3,
};

struct scmi_tinysys_common_set_state {
	u32 reserv;
	u32 feature_id;
	u32 p1;
	u32 p2;
	u32 p3;
	u32 p4;
	u32 p5;
};

struct scmi_msg_t {
	u32 reserved0;
	u32 status;
	u64 reserved1;
	u32 flags;
	u32 length;
	u32 message_header;
	u32 payload[7];
};

struct ap_data {
	unsigned int irq_mbox[SSPM_MBOX_NUM];
	char irq_name[SSPM_MBOX_NUM][IRQ_NAME_LEN];
};

static void __iomem *sspm_mbox_iomap;

static struct ap_data apmcu = {
	.irq_mbox = {SSPM_CI_SET_ID,
				SSPM_CI_GET_ID},
	.irq_name = {"SSPM_CI_SET",
				"SSPM_CI_GET"},
};

static struct device *__dev;
static DEFINE_MUTEX(_hw_rsc);
static int _hw_ack;

/*
 * Per-transaction sequence number placed in the SCMI message header token
 * field. Incremented under _hw_rsc for every sspm_ci_set() so consecutive
 * transactions carry distinct tokens (a hardcoded 0 made all messages
 * indistinguishable). Packed as a u8 into the header token field; wraps
 * naturally.
 */
static u8 _scmi_token;

static void sspm_ci_clear_globals(void *data)
{
	mutex_lock(&_hw_rsc);
	sspm_mbox_iomap = NULL;
	__dev = NULL;
	mutex_unlock(&_hw_rsc);
}

static ssize_t sspm_alive_show(struct device *kobj,
	struct device_attribute *attr, char *buf)
{
	int ret;

	ret = sspm_ci_set(7,
		0xDEAD, 0, 0, 0, 0);

	return snprintf(buf, PAGE_SIZE, "%s\n",	ret ? "Dead" : "Alive");
}
DEVICE_ATTR_RO(sspm_alive);

static uint32_t pack_message_header(u8 message_id, u8 message_type, u8 protocol_id, u8 token)
{
	return ((((message_id) << SCMI_MESSAGE_HEADER_MESSAGE_ID_POS) &
		SCMI_MESSAGE_HEADER_MESSAGE_ID_MASK) |
		(((message_type) << SCMI_MESSAGE_HEADER_MESSAGE_TYPE_POS) &
			SCMI_MESSAGE_HEADER_MESSAGE_TYPE_MASK) |
		(((protocol_id) << SCMI_MESSAGE_HEADER_PROTOCOL_ID_POS) &
			SCMI_MESSAGE_HEADER_PROTOCOL_ID_MASK) |
		(((token) << SCMI_MESSAGE_HEADER_TOKEN_POS) &
			SCMI_MESSAGE_HEADER_TOKEN_MASK));
}

int sspm_ci_set(u32 feature_id,
	u32 p1, u32 p2, u32 p3, u32 p4, u32 p5)
{
	struct scmi_msg_t scmi_tx = {};
	u8 protocol_id, message_type;
	u8 token, message_id;
	u32 message_header;
	u32 count = 0;

	if (!sspm_mbox_iomap)
		return -ENODEV;

	scmi_tx.payload[0] = 0;
	scmi_tx.payload[1] = feature_id;
	scmi_tx.payload[2] = p1;
	scmi_tx.payload[3] = p2;
	scmi_tx.payload[4] = p3;
	scmi_tx.payload[5] = p4;
	scmi_tx.payload[6] = p5;
	scmi_tx.length = sizeof(struct scmi_tinysys_common_set_state) + sizeof(message_header);
	message_id = TINYSYS_COMMON_SET;
	protocol_id = SCMI_PROTOCOL_TINYSYS;
	message_type = SCMI_MESSAGE_TYPE_COMMAND;
	scmi_tx.status = 0;
	scmi_tx.flags = 0x1;

	mutex_lock(&_hw_rsc);

	if (!sspm_mbox_iomap) {
		mutex_unlock(&_hw_rsc);
		return -ENODEV;
	}

	/*
	 * Assign a fresh sequence token per transaction (under _hw_rsc so the
	 * counter is not raced). Distinct tokens let firmware/response tracing
	 * tell consecutive commands apart; the previous hardcoded 0 did not.
	 */
	token = _scmi_token++;
	message_header = pack_message_header(message_id, message_type,
					     protocol_id, token);
	scmi_tx.message_header = message_header;
	while (readl((void __iomem *)MBOX_IN_SET(SSPM_CI_SET_ID))) {
		count++;
		if (count > SSPM_CI_MAX_POLL_COUNT) {
			mutex_unlock(&_hw_rsc);
			dev_err(__dev, "scmi timeout\n");
			return -ETIMEDOUT;
		}
		mdelay(1);
	}
	memcpy_toio(MBOX_BOX(SSPM_CI_SET_ID, 0x0), &scmi_tx, sizeof(scmi_tx));
	/*
	 * Clear any stale ack a previous timed-out transaction may have left
	 * behind (e.g. a late IRQ that set _hw_ack after that call returned),
	 * immediately before triggering this send so the ack wait below cannot
	 * complete prematurely. Clearing here rather than before the (up-to-10s)
	 * mailbox-free poll above narrows the window in which a late ack from a
	 * timed-out transaction could be mistaken for this one to just the send
	 * trigger. It does not fully correlate completions - the handler still
	 * signals a bare flag without matching the response header/token; that
	 * correlation is a follow-up change.
	 */
	WRITE_ONCE(_hw_ack, 0);
	writel(SSPM_CI_MAGIC, (void __iomem *)MBOX_IN_SET(SSPM_CI_SET_ID));
	/* Wait sspm-side ack. */
	count = 0;
	while (READ_ONCE(_hw_ack) == 0) {
		count++;
		if (count > SSPM_CI_MAX_POLL_COUNT) {
			mutex_unlock(&_hw_rsc);
			dev_err(__dev, "scmi timeout\n");
			return -ETIMEDOUT;
		}
		mdelay(1);
	};
	WRITE_ONCE(_hw_ack, 0);
	mutex_unlock(&_hw_rsc);

	dev_dbg(__dev, "[%s] fid:%u p1:%u p2:%u p3:%u p4:%u p5:%u\n",
			__func__, feature_id, p1, p2, p3, p4, p5);
	return 0;
}
EXPORT_SYMBOL(sspm_ci_set);

static irqreturn_t _mbox_handler_(int irq, void *data)
{
	unsigned int id = *((unsigned int *)data);

	writel(SSPM_CI_MAGIC, (void __iomem *)MBOX_OUT_CLR(id));
	writel(0x0, (void __iomem *)MBOX_BOX(id, 0x4));

	/*
	 * Only the SET mailbox completes an sspm_ci_set() ack wait. The GET
	 * mailbox shares this handler but carries unsolicited firmware
	 * notifications; acking on it would let a GET interrupt complete an
	 * in-flight SET transaction early (before firmware consumed the SET
	 * message), so the ack is gated to the SET id.
	 */
	if (id == SSPM_CI_SET_ID)
		WRITE_ONCE(_hw_ack, 1);

	return IRQ_HANDLED;
}

static int sspm_ci_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	void __iomem *base;
	int id = 0, irq = 0, ret = 0;
	struct ap_data *data = &apmcu;
	struct resource *res;

	/*
	 * Use devm_ioremap() rather than devm_platform_ioremap_resource():
	 * the latter reserves the region via request_mem_region(), which fails
	 * with -EBUSY here because the ACPI core has already claimed the _CRS
	 * memory resource (see /proc/iomem "NVDA8400:00"). devm_ioremap() maps
	 * without exclusive reservation while still being devres-managed.
	 */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;
	base = devm_ioremap(dev, res->start, resource_size(res));
	if (!base)
		return -ENOMEM;

	mutex_lock(&_hw_rsc);
	sspm_mbox_iomap = base;
	__dev = dev;
	mutex_unlock(&_hw_rsc);

	ret = devm_add_action_or_reset(dev, sspm_ci_clear_globals, NULL);
	if (ret)
		return ret;

	for (id = 0; id < SSPM_MBOX_NUM; id++) {
		/* Get mbox device information. */
		irq = platform_get_irq(pdev, data->irq_mbox[id]);
		if (irq < 0) {
			dev_err(dev, "platform_get_irq(%d) fail.\n", id);
			return irq;
		}

		/* Register mbox handler. */
		ret = devm_request_irq(dev, irq, _mbox_handler_,
			IRQF_TRIGGER_NONE | IRQF_NO_SUSPEND, data->irq_name[id],
			&data->irq_mbox[id]);
		if (ret) {
			dev_err(dev, "request_irq(%s) fail=%d.\n", data->irq_name[id], ret);
			return ret;
		}
		dev_info(dev, "%s IRQ = %d.\n", data->irq_name[id], irq);
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 14, 0)
static void sspm_ci_remove(struct platform_device *pdev)
#else
static int sspm_ci_remove(struct platform_device *pdev)
#endif
{
	/*
	 * Resources are devm-managed. Probe registration order makes teardown:
	 * IRQs -> clear globals -> unmap MMIO.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
	return 0;
#endif
}

static const struct acpi_device_id sspm_ci_acpi_match[] = {
	{"MTKW8400", 0, 0, 0},
	{"NVDA8400", 0, 0, 0},
	{},
};
MODULE_DEVICE_TABLE(acpi, sspm_ci_acpi_match);

static struct platform_driver sspm_ci_driver = {
	.probe = sspm_ci_probe,
	.remove = sspm_ci_remove,
	.driver = {
		.name = "SSPM_CI",
		.acpi_match_table = ACPI_PTR(sspm_ci_acpi_match),
	},
};

static int __init sspm_ci_init(void)
{
	return platform_driver_register(&sspm_ci_driver);
}

subsys_initcall(sspm_ci_init);

MODULE_DESCRIPTION("MediaTek SSPM control interface driver");
MODULE_LICENSE("GPL");
