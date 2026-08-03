// SPDX-License-Identifier: GPL-2.0-only
/*
 * LSTP USB interface driver.
 *
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/cleanup.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/overflow.h>

#include "lstp-main.h"

enum lstp_ch0_cmd {
	LSTP_CH0_CMD_READ_CONFIG = 0x08,
	LSTP_CH0_CMD_WRITE_CONFIG = 0x09,
	LSTP_CH0_CMD_LOCK = 0x0A,
};

struct lstp_ch0_config {
	u8 lstp_version;
	u8 num_channels; /* does not include ch0 */
} __packed;

/**
 * struct lstp_channel_priv - Framework-private extension of struct lstp_channel.
 * @pub:                  Public, subsystem-visible part. Must be the first
 *                        member.
 * @ch_type:              LSTP channel type.
 * @subsys:               Owning subsystem descriptor.
 * @usb:                  Back-pointer to the LSTP USB device.
 * @tx_mutex:             Serializes outbound requests (one in flight per
 *                        channel).
 * @cfg_lock:             Serializes ch0 descriptor read-modify-write.
 * @resp_buffer_lock:     Bit lock guarding @resp_buf.
 * @irq_buffer_lock:      Bit lock guarding @irq_buf.
 * @irq_resp_buffer_lock: Bit lock guarding the IRQ response slot.
 * @rx_ready:             Set when a solicited response has been deposited
 *                        in @resp_buf.
 * @disconnected:         True once the USB device has been disconnected.
 * @started:              Gates RX dispatch and channel_stop(); set by
 *                        lstp_start_channels() after a successful
 *                        channel_start(). See lstp_start_channels()
 *                        and lstp_usb_rx_callback() for the
 *                        release/acquire pairing.
 * @tx_buf:               Bulk-out scratch buffer for requests.
 * @tx_resp_buf:          Bulk-out scratch buffer for IRQ responses.
 * @resp_buf:             Buffer for solicited responses, or NULL.
 * @irq_buf:              Buffer for unsolicited requests, or NULL.
 * @bulk_tx_urb:          URB for outbound requests.
 * @bulk_tx_resp_urb:     URB for IRQ responses.
 * @rx_wq:                Wait queue for solicited-response readers.
 * @kobj:                 /sys/.../lstp/channel/%d directory.
 * @child_dev:            Subsystem-side device backing the sysfs link.
 */
struct lstp_channel_priv {
	struct lstp_channel pub;

	u8 ch_type;
	const struct lstp_subsys *subsys;
	struct lstp_usb *usb;
	struct mutex tx_mutex; /* serializes outbound requests */
	struct mutex cfg_lock; /* serializes ch0 descriptor read-modify-write */
	unsigned long resp_buffer_lock;
	unsigned long irq_buffer_lock;
	unsigned long irq_resp_buffer_lock;
	bool rx_ready;
	bool disconnected;
	bool started;
	u8 *tx_buf;
	u8 *tx_resp_buf;
	u8 *resp_buf;
	u8 *irq_buf;
	struct urb *bulk_tx_urb;
	struct urb *bulk_tx_resp_urb;
	wait_queue_head_t rx_wq;
	struct kobject kobj;
	struct device *child_dev;
};

#define to_lstp_priv(ch) container_of((ch), struct lstp_channel_priv, pub)

/*
 * lstp_create_channel() returns &priv->pub and the framework stores
 * that pointer in dev->channels[]; to_lstp_priv() must recover the
 * exact same address, so @pub has to sit at offset 0.
 */
static_assert(offsetof(struct lstp_channel_priv, pub) == 0,
	      "struct lstp_channel must be the first member of struct lstp_channel_priv");

/*******************************************************************************
 * Forward declarations
 ******************************************************************************/

static void lstp_usb_rx_callback(struct urb *urb);
static void lstp_rx_retry_work(struct work_struct *work);
static void lstp_teardown(struct lstp_usb *dev);
static void lstp_kobj_release(struct kobject *kobj);
static void lstp_channel_kobj_release(struct kobject *kobj);
static ssize_t lstp_name_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t lstp_channel_enable_show(struct kobject *kobj, struct kobj_attribute *attr,
					char *buf);
static ssize_t lstp_channel_enable_store(struct kobject *kobj, struct kobj_attribute *attr,
					 const char *buf, size_t count);
static ssize_t lstp_channel_name_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);

/*
 * Framework-internal per-channel TX mutex guard. The mutex serializes
 * outbound requests so each lstp_request*() / lstp_send() helper
 * runs as a single atomic LSTP exchange. The guard is not exported:
 * subsystems compose multi-exchange behaviour at their own layer
 * (e.g. via tty drain or their own subsystem-local mutex) rather than
 * bracketing several framework helpers under the channel lock.
 */
DEFINE_GUARD(lstp_channel, struct lstp_channel *, mutex_lock(&to_lstp_priv(_T)->tx_mutex),
	     mutex_unlock(&to_lstp_priv(_T)->tx_mutex))

static struct kobj_attribute lstp_name_attr = __ATTR(name, 0444, lstp_name_show, NULL);

static struct attribute *lstp_attrs[] = {
	&lstp_name_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(lstp);

static const struct kobj_type lstp_ktype = {
	.release = lstp_kobj_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = lstp_groups,
};

static struct kobj_attribute lstp_enable_attr =
	__ATTR(enable, 0644, lstp_channel_enable_show, lstp_channel_enable_store);

static struct kobj_attribute lstp_channel_name_attr =
	__ATTR(name, 0444, lstp_channel_name_show, NULL);

static struct attribute *lstp_channel_attrs[] = {
	&lstp_enable_attr.attr,
	&lstp_channel_name_attr.attr,
	NULL,
};
ATTRIBUTE_GROUPS(lstp_channel);

static const struct kobj_type lstp_channel_ktype = {
	.release = lstp_channel_kobj_release,
	.sysfs_ops = &kobj_sysfs_ops,
	.default_groups = lstp_channel_groups,
};

/* clang-format off */
static const int lstp_errno_map[] = {
	[LSTP_SUCCESS] = 0,
	[LSTP_ERROR] = -EIO,
	[LSTP_TIMEOUT] = -ETIMEDOUT,
	[LSTP_BUSY] = -EBUSY,
	[LSTP_NACK] = -ENXIO,
	[LSTP_ARB_LOST] = -EAGAIN,
	[LSTP_NOT_SUPP] = -EOPNOTSUPP,
	[LSTP_TOO_LARGE] = -EFBIG,
}; /* clang-format on */

/**
 * lstp_status_to_errno() - Convert LSTP protocol status to Linux errno.
 * @status: LSTP status code from device response
 *
 * Return: Negative errno, or 0 on LSTP_SUCCESS.
 */
static int lstp_status_to_errno(u8 status)
{
	if (status < ARRAY_SIZE(lstp_errno_map))
		return lstp_errno_map[status];

	return -EIO;
}

/*******************************************************************************
 * Management channel (Channel 0)
 ******************************************************************************/

/**
 * lstp_validate_rx_pkt() - Generic validation for received LSTP packets.
 * @dev:           LSTP USB device structure
 * @rx_pkt:        Received packet to validate
 * @actual_length: Actual number of bytes received from USB
 *
 * Checks header size, channel ID range, and payload length.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_validate_rx_pkt(struct lstp_usb *dev, struct lstp_packet *rx_pkt,
				size_t actual_length)
{
	struct lstp_header *rx_hdr = &rx_pkt->hdr;
	size_t claimed_payload_len;
	size_t max_payload_len;
	u8 ch_id;

	/* Validate header size */
	if (actual_length < sizeof(struct lstp_header)) {
		dev_err(&dev->intf->dev, "%s: Packet without header (got %zu, need >=%lu)\n",
			__func__, actual_length, sizeof(struct lstp_header));
		return -EIO;
	}

	/* Validate channel ID */
	ch_id = rx_hdr->ch_id;
	if (ch_id > dev->max_ch_id) {
		dev_err(&dev->intf->dev, "%s: Invalid channel ID (got %u, max %u)\n", __func__,
			ch_id, dev->max_ch_id);
		return -EIO;
	}

	claimed_payload_len = le16_to_cpu(rx_hdr->length);
	max_payload_len = dev->bulk_rx_size - sizeof(struct lstp_header);

	/* Overflow protection: validate payload length against buffer capacity */
	/* TODO: remove/change these checks when we implement the multi-packet support */
	if (claimed_payload_len > max_payload_len) {
		dev_err(&dev->intf->dev, "%s: ch_%u: Payload too large (claims %zu, max %zu)\n",
			__func__, ch_id, claimed_payload_len, max_payload_len);
		return -EIO;
	}

	/* Underflow protection: validate received data matches claimed payload */
	if (sizeof(struct lstp_header) + claimed_payload_len > actual_length) {
		dev_err(&dev->intf->dev, "%s: ch_%u: Payload too short (claims %zu, got %zu)\n",
			__func__, ch_id, claimed_payload_len,
			actual_length - sizeof(struct lstp_header));
		return -EIO;
	}

	return 0;
}

/**
 * lstp_validate_resp() - Validate LSTP response packets.
 * @dev:             Device structure for error reporting
 * @rx_pkt:          Received packet to validate
 * @min_payload_len:  Minimum payload length, or LSTP_ANY_RX_LEN to accept any length
 * @lstp_status: Optional out-param. Set to the raw LSTP response status only
 *                    when the returned errno is derived from that status; left
 *                    untouched otherwise (payload/length validation failures).
 *
 * Assumes the packet has already been validated with lstp_validate_rx_pkt().
 *
 * Accepts payloads at least @min_payload_len bytes long; longer payloads are
 * permitted to allow forward compatibility with newer firmware that may
 * append additional fields.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_validate_resp(struct lstp_usb *dev, struct lstp_packet *rx_pkt,
			      size_t min_payload_len, int *lstp_status)
{
	int ret;
	struct lstp_header *rx_hdr = &rx_pkt->hdr;
	size_t payload_len;
	u8 ch_id = rx_hdr->ch_id;

	/* Validate LSTP status */
	ret = lstp_status_to_errno(GET_BIT_0_6(rx_hdr->status));
	if (ret) {
		if (lstp_status)
			*lstp_status = GET_BIT_0_6(rx_hdr->status);
		dev_dbg(&dev->intf->dev, "%s: ch_%u: LSTP error status %d (errno=%d)\n", __func__,
			ch_id, GET_BIT_0_6(rx_hdr->status), ret);
		return ret;
	}

	/* Validate payload length meets minimum */
	payload_len = le16_to_cpu(rx_hdr->length);
	if (payload_len < min_payload_len) {
		dev_err(&dev->intf->dev,
			"%s: ch_%u: Payload too short (need at least %zu, got %zu)\n", __func__,
			ch_id, min_payload_len, payload_len);
		return -EIO;
	}

	/*
	 * Surface oversized payloads under dynamic debug so wire-format mismatches
	 * are visible during investigation without spamming the kernel log on the
	 * normal forward-compat path. Suppressed when no minimum was requested.
	 */
	if (min_payload_len && payload_len > min_payload_len)
		dev_dbg(&dev->intf->dev,
			"%s: ch_%u: Payload longer than minimum (got %zu, min %zu) -- forward-compat extension?\n",
			__func__, ch_id, payload_len, min_payload_len);

	return 0;
}

/**
 * lstp_ch0_read_config() - Read a config slice via ch0 READ_CONFIG.
 * @ch:       Target LSTP channel to read config from
 * @offset:   Byte offset starting at ch_config[0]
 * @length:   Bytes to read from ch_config[], or LSTP_READ_CONFIG_MAX to read
 *            up to the per-packet ch_config[] limit starting at @offset.
 * @resp_out: On success, *@resp_out points to a kmalloc'd buffer holding the
 *            on-wire READ_CONFIG response (head + config bytes). Caller takes
 *            ownership and must kfree()
 * @len_out:  On success, total response bytes in *@resp_out. At least
 *            sizeof(struct lstp_ch0_read_resp); when @length is an explicit
 *            byte count (not LSTP_READ_CONFIG_MAX), at least @length bytes of
 *            ch_config[] are included.
 * @lstp_status: Optional out-param for the raw status from the final LSTP
 *               request; see lstp_request()
 *
 * Return: 0 on success, negative errno on failure.
 */
int lstp_ch0_read_config(struct lstp_channel *ch, u16 offset, u16 length,
			 struct lstp_ch0_read_resp **resp_out, size_t *len_out, int *lstp_status)
{
	struct lstp_channel *ch0;
	struct lstp_channel_priv *priv;
	size_t max_payload_len, actual, need;
	u16 max_config_len, config_len;
	struct lstp_ch0_read_req req;
	struct lstp_ch0_read_resp *resp __free(kfree) = NULL;
	int request_status = LSTP_NO_RESPONSE_STATUS;
	int ret;

	if (lstp_status)
		*lstp_status = LSTP_NO_RESPONSE_STATUS;
	if (!ch)
		return -ENODEV;
	priv = to_lstp_priv(ch);
	if (!priv->usb || !priv->usb->channels[0])
		return -ENODEV;
	if (!resp_out || !len_out)
		return -EINVAL;

	ch0 = priv->usb->channels[0];
	max_payload_len = ch0->max_rx_payload;
	max_config_len = max_payload_len - offsetof(struct lstp_ch0_read_resp, ch_config);

	config_len = length;
	if (length == LSTP_READ_CONFIG_MAX)
		config_len = max_config_len;
	else if (length > max_config_len)
		return -EINVAL;

	resp = kzalloc(max_payload_len, GFP_KERNEL);
	if (!resp)
		return -ENOMEM;

	req = (struct lstp_ch0_read_req){
		.ch_id = ch->ch_id,
		.offset = cpu_to_le16(offset),
		.length = cpu_to_le16(config_len),
	};

	ret = lstp_request(ch0, LSTP_CH0_CMD_READ_CONFIG, &req, sizeof(req), resp, max_payload_len,
			   &actual, &request_status);
	if (request_status == LSTP_ERROR && offset == 0 && length == LSTP_READ_CONFIG_MAX) {
		/*
		 * TODO: Legacy support - remove this at some point
		 * Fallback for old firmware that rejects an explicit
		 * max_config_len read; retry with length=0, which it
		 * treats as "read all that fits in one packet".
		 */
		dev_warn_ratelimited(ch->dev,
				     "%s: ch_%d: Falling back to deprecated READ_CONFIG_MAX\n",
				     __func__, ch->ch_id);
		req.length = cpu_to_le16(DEPRECATED_LSTP_READ_CONFIG_MAX);
		ret = lstp_request(ch0, LSTP_CH0_CMD_READ_CONFIG, &req, sizeof(req), resp,
				   max_payload_len, &actual, &request_status);
	}
	if (lstp_status)
		*lstp_status = request_status;
	if (ret) {
		dev_dbg(ch->dev, "%s: ch_%d: READ_CONFIG failed (%pe)\n", __func__, ch->ch_id,
			ERR_PTR(ret));
		return ret;
	}

	need = sizeof(*resp);
	if (length != LSTP_READ_CONFIG_MAX)
		need += length;
	if (actual < need) {
		dev_dbg(ch->dev, "%s: ch_%d: READ_CONFIG short reply: %zu < %zu\n", __func__,
			ch->ch_id, actual, need);
		return -EIO;
	}

	*resp_out = no_free_ptr(resp);
	*len_out = actual;
	return 0;
}

/**
 * lstp_read_config_table() - Walk a channel's variable-length config entry array.
 * @ch:                Target LSTP channel to read config from
 * @config_head_size:  Bytes before the entry array starts (sizeof the fixed config head)
 * @config_entry_size: Size of one wire config entry
 * @total_entries:     Number of entries to walk
 * @entry_fn:          Per-entry callback; @entry points into the READ_CONFIG
 *                     response and is valid only for the duration of the call
 * @entry_ctx:         Opaque context passed to @entry_fn
 *
 * Each chunk is fetched via ch0 READ_CONFIG at the computed offset into ch_config[].
 *
 * Return: 0 on success, or the first negative errno from a read or from @entry_fn.
 */
int lstp_read_config_table(struct lstp_channel *ch, size_t config_head_size,
			   size_t config_entry_size, unsigned int total_entries,
			   lstp_config_entry_fn entry_fn, void *entry_ctx)
{
	unsigned int max_entries, n_chunks, chunk, start_entry, n_entries, entry;
	size_t avail, max_entry_bytes, offset, length;
	int ret;

	if (!total_entries)
		return 0;

	avail = ch->max_rx_payload - sizeof(struct lstp_ch0_read_resp);
	if (!entry_fn || !config_entry_size || config_head_size > avail)
		return -EINVAL;

	/* Conservative cap: one response must hold the read head plus its entries. */
	max_entry_bytes = avail - config_head_size;
	max_entries = max_entry_bytes / config_entry_size; /* max entries per chunk */
	if (!max_entries)
		return -ENOSPC;

	n_chunks = DIV_ROUND_UP(total_entries, max_entries);
	for (chunk = 0; chunk < n_chunks; chunk++) {
		struct lstp_ch0_read_resp *resp __free(kfree) = NULL;
		size_t resp_len;

		start_entry = chunk * max_entries;
		n_entries = min(total_entries - start_entry, max_entries);
		offset = config_head_size + (size_t)start_entry * config_entry_size;
		if (check_mul_overflow(n_entries, config_entry_size, &length))
			return -EINVAL;

		ret = lstp_ch0_read_config(ch, offset, length, &resp, &resp_len, NULL);
		if (ret) {
			dev_err(ch->dev,
				"%s: ch_%d: config chunk %u (entries %u-%u) failed (%pe)\n",
				__func__, ch->ch_id, chunk, start_entry,
				start_entry + n_entries - 1, ERR_PTR(ret));
			return ret;
		}

		for (entry = 0; entry < n_entries; entry++) {
			ret = entry_fn(ch, start_entry + entry,
				       resp->ch_config + entry * config_entry_size, entry_ctx);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/**
 * lstp_ch0_read_desc() - Read a channel's current descriptor head from the device.
 * @ch:   Target LSTP channel whose descriptor to read
 * @desc: Out: descriptor head (ch_type/ch_flags/ch_name) from the READ_CONFIG reply
 *
 * Issues a ch0 READ_CONFIG for @ch and keeps only the descriptor head. Callers
 * that read-modify-write the descriptor hold priv->cfg_lock across this and the
 * subsequent write so the device stays the source of truth and the exchange is
 * atomic against other descriptor writers.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_ch0_read_desc(struct lstp_channel *ch, struct lstp_ch_desc *desc)
{
	struct lstp_channel_priv *priv;
	struct lstp_channel *ch0;
	struct lstp_ch0_read_req req;
	int ret;

	if (!ch)
		return -ENODEV;
	priv = to_lstp_priv(ch);
	if (!priv->usb || !priv->usb->channels[0])
		return -ENODEV;
	ch0 = priv->usb->channels[0];

	req = (struct lstp_ch0_read_req){
		.ch_id = ch->ch_id,
		.offset = cpu_to_le16(0),
		.length = cpu_to_le16(0),
	};

	/* Fixed read: firmware may append a config trailer; keep only the desc head. */
	ret = lstp_request(ch0, LSTP_CH0_CMD_READ_CONFIG, &req, sizeof(req), desc, sizeof(*desc),
			   NULL, NULL);
	if (ret)
		dev_err(ch->dev, "%s: ch_%d: READ_CONFIG failed (%pe)\n", __func__, ch->ch_id,
			ERR_PTR(ret));
	return ret;
}

/**
 * __lstp_ch0_write_config() - Raw WRITE_CONFIG sender with an explicit descriptor.
 * @ch:         Target LSTP channel to write config to
 * @offset:     Byte offset starting at ch_config[0]
 * @desc:       Channel descriptor head to send with the write
 * @config:     ch_config[] bytes to write; NULL iff @config_len == 0
 * @config_len: Bytes from @config to write
 *
 * Low-level helper that sends @desc verbatim. Every WRITE_CONFIG re-sends the
 * descriptor head, so callers that change the descriptor must serialize their
 * read-modify-write on priv->cfg_lock and re-read @desc from the device under
 * that lock. This raw helper stays file-local.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int __lstp_ch0_write_config(struct lstp_channel *ch, u16 offset,
				   const struct lstp_ch_desc *desc, const void *config,
				   u16 config_len)
{
	struct lstp_channel_priv *priv;
	struct lstp_channel *ch0;
	struct lstp_ch0_write_req *req __free(kfree) = NULL;
	size_t req_len;
	int ret;

	if (!ch || !desc)
		return -ENODEV;
	priv = to_lstp_priv(ch);
	if (!priv->usb || !priv->usb->channels[0])
		return -ENODEV;
	if (config_len && !config)
		return -EINVAL;

	ch0 = priv->usb->channels[0];
	if (check_add_overflow(offsetof(struct lstp_ch0_write_req, ch_config), config_len,
			       &req_len))
		return -EINVAL;

	req = kmalloc(req_len, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->ch_id = ch->ch_id;
	req->offset = cpu_to_le16(offset);
	req->desc = *desc;
	if (config_len)
		memcpy(req->ch_config, config, config_len);

	ret = lstp_request(ch0, LSTP_CH0_CMD_WRITE_CONFIG, req, req_len, NULL, 0, NULL, NULL);
	if (ret)
		dev_warn_ratelimited(ch->dev,
				     "%s: ch_%d: WRITE_CONFIG failed (%pe). Config locked?\n",
				     __func__, ch->ch_id, ERR_PTR(ret));

	return ret;
}

/**
 * lstp_ch0_set_enable() - Set/clear a channel's enable flag.
 * @ch:      Target LSTP channel to modify
 * @enable:  true to set LSTP_CH_FLAG_ENABLE, false to clear it
 *
 * Re-reads the descriptor from the device, flips LSTP_CH_FLAG_ENABLE, and
 * writes the descriptor head back via WRITE_CONFIG, all under priv->cfg_lock.
 * Re-reading under the lock keeps the device authoritative for ch_type/ch_name
 * and any other ch_flags bits, while serializing against concurrent descriptor
 * writers so an enable toggle is never lost.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_ch0_set_enable(struct lstp_channel *ch, bool enable)
{
	struct lstp_ch_desc desc;
	int ret;

	if (!ch)
		return -ENODEV;

	guard(mutex)(&to_lstp_priv(ch)->cfg_lock);

	ret = lstp_ch0_read_desc(ch, &desc);
	if (ret)
		return ret;

	/* Override only ch_flags; ch_type/ch_name come from the device. */
	if (enable)
		desc.ch_flags |= LSTP_CH_FLAG_ENABLE;
	else
		desc.ch_flags &= ~LSTP_CH_FLAG_ENABLE;

	return __lstp_ch0_write_config(ch, 0, &desc, NULL, 0);
}

/*******************************************************************************
 * Devres action callbacks
 ******************************************************************************/

/**
 * lstp_put_usb_dev() - Devres callback to release USB device reference.
 * @data: Pointer to USB device
 */
static void lstp_put_usb_dev(void *data)
{
	usb_put_dev((struct usb_device *)data);
}

/**
 * lstp_release_urb_slot() - Devres callback to kill, free, and NULL a URB slot.
 * @data: Pointer to the URB-pointer field (``struct urb **``) to release
 *
 * Reads the URB from ``*slot``, kills and frees it, and writes %NULL back
 * to ``*slot``. Designed to be registered with
 * devm_add_action_or_reset(); on registration failure the action fires
 * inline and leaves the slot %NULL, so callers may use the natural
 *
 *     slot = usb_alloc_urb(...);
 *     ret = devm_add_action_or_reset(dev, lstp_release_urb_slot, &slot);
 *     if (ret) return ret;
 *
 * pattern without risking a dangling pointer in ``slot`` on the error
 * path. The slot must live in a struct whose lifetime is at least as long
 * as the devres node (typically a devm-allocated struct on the same
 * device), since @data is dereferenced both on inline-fire and on
 * device-unwind.
 */
static void lstp_release_urb_slot(void *data)
{
	struct urb **slot = data;

	usb_kill_urb(*slot);
	usb_free_urb(*slot);
	*slot = NULL;
}

/**
 * lstp_kobj_del_put() - Remove kobject from sysfs and release reference.
 * @data: Pointer to kobject to clean up
 */
static void lstp_kobj_del_put(void *data)
{
	struct kobject *kobj = data;

	kobject_del(kobj);
	kobject_put(kobj);
}

/**
 * lstp_kobj_release() - Release callback for the lstp kobject.
 * @kobj: Kobject being released
 */
static void lstp_kobj_release(struct kobject *kobj)
{
	/* Intentionally empty: memory is devm-managed in struct lstp_usb */
}

/**
 * lstp_channel_kobj_release() - Release callback for channel kobjects.
 * @kobj: Kobject being released
 */
static void lstp_channel_kobj_release(struct kobject *kobj)
{
	/* Intentionally empty: channel memory is devm-managed */
}

/**
 * lstp_put_fwnode() - Devres callback to release firmware node reference.
 * @data: Pointer to fwnode_handle
 */
static void lstp_put_fwnode(void *data)
{
	fwnode_handle_put((struct fwnode_handle *)data);
}

/*******************************************************************************
 * Sysfs attributes for channels
 ******************************************************************************/

/**
 * lstp_sysfs_get_channel() - Get channel from sysfs kobject.
 * @kobj: Kobject passed to sysfs callback
 *
 * Return: Channel pointer, or ERR_PTR on failure.
 */
static struct lstp_channel *lstp_sysfs_get_channel(struct kobject *kobj)
{
	struct lstp_channel_priv *priv;

	priv = container_of(kobj, struct lstp_channel_priv, kobj);

	if (!priv->usb)
		return ERR_PTR(-ENODEV);

	return &priv->pub;
}

/**
 * lstp_name_show() - Read handler for ``lstp/name``.
 * @kobj: Kobject for the ``lstp`` sysfs directory (embedded in lstp_usb)
 * @attr: Sysfs kobject attribute
 * @buf:  Output buffer for sysfs read
 *
 * Emits the LSTP interface name from the channel-0 discovery response.
 *
 * Return: Number of bytes written to buf, or negative errno on failure.
 */
static ssize_t lstp_name_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct lstp_usb *lstp = container_of(kobj, struct lstp_usb, lstp_kobj);

	return sysfs_emit(buf, "%s\n", lstp->lstp_intf_name);
}

/**
 * lstp_channel_enable_show() - Show channel enable status via sysfs.
 * @kobj: Kobject for the channel (embedded in lstp_channel_priv)
 * @attr: Sysfs kobject attribute
 * @buf:  Output buffer for sysfs read
 *
 * Queries the management channel (ch0) for this channel's configuration
 * and extracts the enable bit (bit 0 of ch_flags in READ_CONFIG response).
 *
 * Return: Number of bytes written to buf, or negative errno on failure.
 */
static ssize_t lstp_channel_enable_show(struct kobject *kobj, struct kobj_attribute *attr,
					char *buf)
{
	struct lstp_channel *ch;
	struct lstp_ch_desc desc;
	u8 enable_bit;
	int ret;

	ch = lstp_sysfs_get_channel(kobj);
	if (IS_ERR(ch))
		return PTR_ERR(ch);

	ret = lstp_ch0_read_desc(ch, &desc);
	if (ret)
		return ret;

	enable_bit = (desc.ch_flags & LSTP_CH_FLAG_ENABLE) ? 1 : 0;

	return sysfs_emit(buf, "%u\n", enable_bit);
}

/**
 * lstp_channel_enable_store() - Set channel enable status via sysfs.
 * @kobj:  Kobject for the channel (embedded in lstp_channel_priv)
 * @attr:  Sysfs kobject attribute
 * @buf:   Input buffer containing "0" or "1"
 * @count: Number of bytes in buf
 *
 * Return: Bytes consumed, or negative errno.
 */
static ssize_t lstp_channel_enable_store(struct kobject *kobj, struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	struct lstp_channel *ch;
	unsigned int enable;
	int ret;

	ch = lstp_sysfs_get_channel(kobj);
	if (IS_ERR(ch))
		return PTR_ERR(ch);

	ret = kstrtouint(buf, 0, &enable);
	if (ret)
		return ret;

	if (enable > 1)
		return -EINVAL;

	ret = lstp_ch0_set_enable(ch, enable != 0);
	if (ret)
		return ret;

	return count;
}

/**
 * lstp_channel_name_show() - Show channel display name via sysfs "name" attr.
 * @kobj: Kobject for the channel (embedded in lstp_channel_priv)
 * @attr: Sysfs kobject attribute
 * @buf:  Output buffer for sysfs read
 *
 * Emits the channel's display_name.
 *
 * Return: Number of bytes written to buf, or negative errno on failure.
 */
static ssize_t lstp_channel_name_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct lstp_channel *ch;

	ch = lstp_sysfs_get_channel(kobj);
	if (IS_ERR(ch))
		return PTR_ERR(ch);

	return sysfs_emit(buf, "%s\n", ch->display_name);
}

/**
 * lstp_create_sysfs_hierarchy() - Create lstp sysfs ("name" + "channel/").
 * @dev: LSTP USB device structure
 *
 * Under the USB interface device sysfs directory, create:
 *     lstp/
 *     ├── name			(LSTP interface name, read-only)
 *     └── channel/		(per-channel sysfs parent directory)
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_create_sysfs_hierarchy(struct lstp_usb *dev)
{
	struct device *parent_dev = &dev->intf->dev;
	int ret;

	/* Create lstp directory (name attribute provided by lstp_ktype) */
	ret = kobject_init_and_add(&dev->lstp_kobj, &lstp_ktype, &parent_dev->kobj, "lstp");
	if (ret) {
		kobject_put(&dev->lstp_kobj);
		return ret;
	}

	ret = devm_add_action_or_reset(parent_dev, lstp_kobj_del_put, &dev->lstp_kobj);
	if (ret)
		return ret;

	/* Create channel directory under lstp */
	dev->channel_kobj = kobject_create_and_add("channel", &dev->lstp_kobj);
	if (!dev->channel_kobj)
		return -ENOMEM;

	return devm_add_action_or_reset(parent_dev, lstp_kobj_del_put, dev->channel_kobj);
}

/**
 * lstp_remove_device_link() - Devres callback to remove device symlink.
 * @data: Pointer to channel kobject
 */
static void lstp_remove_device_link(void *data)
{
	struct kobject *kobj = data;

	sysfs_remove_link(kobj, "device");
}

/**
 * lstp_channel_link_device() - Create symlink from channel to its child device.
 * @ch: LSTP channel (must have a child device set via
 *      deprecated_lstp_channel_publish_child_dev())
 *
 * Creates a symlink named "device" under the channel's sysfs directory
 * that points to the child device. This allows easy identification of
 * which subsystem device corresponds to each channel.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_channel_link_device(struct lstp_channel *ch)
{
	struct lstp_channel_priv *priv = to_lstp_priv(ch);
	struct device *parent_dev = ch->dev;
	int ret;

	if (WARN(!priv->child_dev, "lstp: ch_%d (%s): child_dev not set\n", ch->ch_id,
		 priv->subsys ? priv->subsys->name : "?"))
		return 0;

	ret = sysfs_create_link(&priv->kobj, &priv->child_dev->kobj, "device");
	if (ret) {
		dev_err(parent_dev, "%s: ch_%d: Failed to create device symlink (%pe)\n", __func__,
			ch->ch_id, ERR_PTR(ret));
		return ret;
	}

	return devm_add_action_or_reset(parent_dev, lstp_remove_device_link, &priv->kobj);
}

/**
 * lstp_create_channel_sysfs() - Create sysfs directory and attrs for channel.
 * @ch: LSTP channel
 *
 * Creates a directory "lstp/channel/N" (where N is the channel ID) with
 * "enable" and "name" attributes. "enable" is read-write and queries/updates
 * the device via the management channel. "name" is read-only and shows the
 * channel's display_name.
 *
 * Also creates a "device" symlink to the child device when one was
 * registered via deprecated_lstp_channel_publish_child_dev().
 *
 * The kobject cleanup is registered via devm_add_action_or_reset() so it
 * will be automatically handled when the USB interface is released.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_create_channel_sysfs(struct lstp_channel *ch)
{
	struct lstp_channel_priv *priv = to_lstp_priv(ch);
	struct device *dev = ch->dev;
	int ret;

	ret = kobject_init_and_add(&priv->kobj, &lstp_channel_ktype, priv->usb->channel_kobj, "%d",
				   ch->ch_id);
	if (ret) {
		dev_err(dev, "%s: Failed to create sysfs for ch_%d (%pe)\n", __func__, ch->ch_id,
			ERR_PTR(ret));
		kobject_put(&priv->kobj);
		return ret;
	}

	ret = devm_add_action_or_reset(dev, lstp_kobj_del_put, &priv->kobj);
	if (ret)
		return ret;

	return lstp_channel_link_device(ch);
}

/*******************************************************************************
 * Device Tree functions
 ******************************************************************************/

/**
 * lstp_find_channel_fwnode() - Find channel firmware node (DT or ACPI).
 * @usb_dev_fwnode: USB device firmware node
 * @intf_num:       Interface number
 * @channel_id:     Channel ID
 * @compatible:     Compatible string
 *
 * Finds a channel firmware node that matches the given parameters.
 * Works transparently with Device Tree, ACPI (_DSD properties), and
 * software nodes.
 *
 * Expected firmware hierarchy::
 *
 *   usb-device@X {                    // USB device node (usb_dev_fwnode)
 *       compatible = "usbVVVV,PPPP";  // USB VID:PID (e.g., "usb0955,cf11")
 *
 *       interface@N {                 // USB interface node
 *           reg = <N>;                // bInterfaceNumber (intf_num)
 *
 *           channel@M {               // LSTP channel node (returned)
 *               reg = <M>;            // Channel ID (channel_id)
 *               compatible = "...";   // Must match 'compatible' parameter
 *               // Channel-specific properties and child devices...
 *           };
 *       };
 *   };
 *
 * Return: fwnode_handle with incremented refcount on success, NULL on failure.
 */
static struct fwnode_handle *lstp_find_channel_fwnode(struct fwnode_handle *usb_dev_fwnode,
						      u8 intf_num, u8 channel_id,
						      const char *compatible)
{
	struct fwnode_handle *intf_node, *ch_node;
	u32 reg;

	if (!usb_dev_fwnode)
		return NULL;

	fwnode_for_each_child_node(usb_dev_fwnode, intf_node) {
		if (fwnode_property_read_u32(intf_node, "reg", &reg) || reg != intf_num)
			continue;

		fwnode_for_each_child_node(intf_node, ch_node) {
			if (fwnode_property_read_u32(ch_node, "reg", &reg) || reg != channel_id)
				continue;
			if (fwnode_property_match_string(ch_node, "compatible", compatible) < 0)
				continue;
			fwnode_handle_put(intf_node);
			return ch_node;
		}
		fwnode_handle_put(intf_node);
		break;
	}

	return NULL;
}

/**
 * lstp_init_channel_fwnode() - Initialize channel's firmware node (DT or ACPI).
 * @ch:         LSTP channel to initialize
 * @compatible: Compatible string to match in firmware description
 *
 * Finds and assigns the appropriate firmware node for this channel.
 * Works with Device Tree, ACPI, and software nodes.
 * Registers a devm action to automatically release the node reference.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_init_channel_fwnode(struct lstp_channel *ch, const char *compatible)
{
	struct lstp_channel_priv *priv = to_lstp_priv(ch);

	if (!compatible)
		return 0;

	ch->fwnode =
		lstp_find_channel_fwnode(dev_fwnode(&priv->usb->udev->dev),
					 priv->usb->intf->cur_altsetting->desc.bInterfaceNumber,
					 ch->ch_id, compatible);
	if (!ch->fwnode)
		return 0;

	return devm_add_action_or_reset(ch->dev, lstp_put_fwnode, ch->fwnode);
}

/**
 * lstp_alloc_channel_bufs() - Allocate framework-owned per-channel buffers.
 * @ch: LSTP channel whose subsystem may opt into framework-allocated buffers.
 *
 * Reads the LSTP_SUBSYS() descriptor on priv->subsys and devm-allocates the
 * matching framework-owned scratch buffers and URBs against @ch->dev so they
 * are torn down on disconnect. Called from lstp_init_subsys_channel() before
 * channel_init() so every slot is in place before any callback fires.
 *
 * Always allocates @priv->resp_buf, the solicited-response landing buffer
 * required by lstp_request*(); it is framework-private so subsystems cannot
 * own this allocation. Only subsystem channels reach this helper, so ch0
 * (which never lands a solicited response) never gets one.
 *
 * A non-NULL @irq_callback is the single signal that the subsystem handles
 * unsolicited packets, so it gates the whole IRQ-side slot:
 *   @priv->irq_buf           -- the RX completion hands the unsolicited
 *                               packet to the callback without reusing the
 *                               shared rx_buf for the next URB;
 *   @priv->tx_resp_buf +     -- lstp_send_irq_resp() can ACK the unsolicited
 *   @priv->bulk_tx_resp_urb     request from atomic context.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_alloc_channel_bufs(struct lstp_channel *ch)
{
	struct lstp_channel_priv *priv = to_lstp_priv(ch);
	int ret;

	priv->resp_buf = devm_kzalloc(ch->dev, priv->usb->bulk_rx_size, GFP_KERNEL);
	if (!priv->resp_buf)
		return -ENOMEM;

	if (priv->subsys->irq_callback) {
		priv->irq_buf = devm_kzalloc(ch->dev, priv->usb->bulk_rx_size, GFP_KERNEL);
		if (!priv->irq_buf)
			return -ENOMEM;

		priv->tx_resp_buf = devm_kzalloc(ch->dev, sizeof(struct lstp_header), GFP_KERNEL);
		if (!priv->tx_resp_buf)
			return -ENOMEM;

		priv->bulk_tx_resp_urb = usb_alloc_urb(0, GFP_KERNEL);
		if (!priv->bulk_tx_resp_urb)
			return -ENOMEM;
		ret = devm_add_action_or_reset(ch->dev, lstp_release_urb_slot,
					       &priv->bulk_tx_resp_urb);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * lstp_create_channel() - Allocate and initialize an LSTP channel.
 * @dev:   Parent LSTP USB device.
 * @ch_id: Channel ID to assign to the new channel.
 *
 * Return: Pointer to the new channel on success, NULL on allocation failure.
 */
static struct lstp_channel *lstp_create_channel(struct lstp_usb *dev, u8 ch_id)
{
	struct lstp_channel_priv *priv;
	struct lstp_channel *ch;

	priv = devm_kzalloc(&dev->intf->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;
	ch = &priv->pub;

	priv->tx_buf = devm_kzalloc(&dev->intf->dev, dev->bulk_tx_size, GFP_KERNEL);
	if (!priv->tx_buf)
		return NULL;

	priv->bulk_tx_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!priv->bulk_tx_urb)
		return NULL;
	if (devm_add_action_or_reset(&dev->intf->dev, lstp_release_urb_slot, &priv->bulk_tx_urb))
		return NULL;

	ch->ch_id = ch_id;
	priv->usb = dev;
	ch->dev = &dev->intf->dev;
	ch->max_tx_payload = dev->bulk_tx_size - sizeof(struct lstp_header);
	ch->max_rx_payload = dev->bulk_rx_size - sizeof(struct lstp_header);
	mutex_init(&priv->tx_mutex);
	mutex_init(&priv->cfg_lock);
	init_waitqueue_head(&priv->rx_wq);
	dev->channels[ch_id] = ch;
	return ch;
}

/**
 * lstp_ch0_init() - Create and initialize channel 0 (management).
 * @dev: LSTP USB device
 *
 * Creates ch0, reads its config via READ_CONFIG, and parses the LSTP
 * version, channel count and interface label into @dev.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_ch0_init(struct lstp_usb *dev)
{
	struct lstp_ch0_read_resp *resp __free(kfree) = NULL;
	const struct lstp_ch0_config *config;
	struct lstp_channel *ch0;
	struct lstp_channel_priv *priv0;
	size_t actual;
	int ret;

	/* Create CH_0 and get READ request */
	ch0 = lstp_create_channel(dev, 0);
	if (!ch0) {
		dev_err(&dev->intf->dev, "%s: Could not allocate channel 0\n", __func__);
		return -ENOMEM;
	}
	priv0 = to_lstp_priv(ch0);
	priv0->ch_type = LSTP_CHANNEL_TYPE_MGMT;
	priv0->resp_buf = devm_kzalloc(&dev->intf->dev, dev->bulk_rx_size, GFP_KERNEL);
	if (!priv0->resp_buf)
		return -ENOMEM;

	ret = lstp_ch0_read_config(ch0, 0, LSTP_READ_CONFIG_MAX, &resp, &actual, NULL);
	if (ret)
		return ret;

	/* Validate expected CH0 config size */
	if (actual < sizeof(*resp) + sizeof(struct lstp_ch0_config)) {
		dev_err(&dev->intf->dev, "%s: ch_0: READ_CONFIG short reply: %zu < %zu\n", __func__,
			actual, sizeof(*resp) + sizeof(struct lstp_ch0_config));
		return -EIO;
	}
	config = (const struct lstp_ch0_config *)resp->ch_config;

	/* Parse READ response for CH0 */
	if (resp->desc.ch_type != LSTP_CHANNEL_TYPE_MGMT) {
		dev_err(&dev->intf->dev, "%s: ch_0: Received wrong channel 0 type (got %d)\n",
			__func__, resp->desc.ch_type);
		return -EINVAL;
	}

	/* Validate interface name */
	if (resp->desc.ch_name[0] == '\0') {
		dev_warn(&dev->intf->dev,
			 "%s: ch_0: Empty LSTP interface name, consider fixing it! Using default 'LSTP'\n",
			 __func__);
		strscpy(dev->lstp_intf_name, "LSTP", sizeof(dev->lstp_intf_name));
	} else {
		snprintf(dev->lstp_intf_name, sizeof(dev->lstp_intf_name), "%.*s", LSTP_CH_NAME_LEN,
			 resp->desc.ch_name);
	}
	strscpy(ch0->display_name, dev->lstp_intf_name, sizeof(ch0->display_name));

	/* Validate LSTP version */
	if (config->lstp_version != LSTP_VERSION) {
		dev_err(&dev->intf->dev, "%s: ch_0: Invalid LSTP version\n", __func__);
		return -EINVAL;
	}
	dev->lstp_version = config->lstp_version;

	/* Validate channel count */
	if (config->num_channels == 0 || config->num_channels >= LSTP_MAX_CHANNELS) {
		dev_err(&dev->intf->dev, "%s: ch_0: Invalid channel count %d (min 1, max %d)\n",
			__func__, config->num_channels, LSTP_MAX_CHANNELS - 1);
		return -EINVAL;
	}
	dev->max_ch_id = config->num_channels;

	dev_info(&dev->intf->dev, "%s: LSTP v%d: device %s discovered with %d channels\n", __func__,
		 dev->lstp_version, dev->lstp_intf_name, dev->max_ch_id);
	return 0;
}

/* clang-format off */
static const char * const lstp_ch_type_tags[] = {
	[LSTP_CHANNEL_TYPE_SPI] = "SPI",
	[LSTP_CHANNEL_TYPE_GPIO] = "GPIO",
	[LSTP_CHANNEL_TYPE_I2C] = "I2C",
	[LSTP_CHANNEL_TYPE_UART] = "UART",
	[LSTP_CHANNEL_TYPE_IPMI] = "IPMI",
	[LSTP_CHANNEL_TYPE_MMIO] = "MMIO",
}; /* clang-format on */

/**
 * lstp_set_display_name() - Set ch->display_name from firmware or synthesize a default.
 * @ch:          Channel (ch_id and ch_type must already be set)
 * @ch_name:     Raw firmware ch_name (may not be NUL-terminated)
 * @ch_name_len: Size of @ch_name buffer (typically LSTP_CH_NAME_LEN)
 *
 * Format: "<intf_name>_<ch_name>" or "<intf_name>_<TYPE>_CH<id>" (with a warning).
 */
static void lstp_set_display_name(struct lstp_channel *ch, const char *ch_name, size_t ch_name_len)
{
	struct lstp_channel_priv *priv = to_lstp_priv(ch);
	size_t name_len = strnlen(ch_name, ch_name_len);
	const char *tag;

	if (name_len) {
		snprintf(ch->display_name, sizeof(ch->display_name), "%s_%.*s",
			 priv->usb->lstp_intf_name, (int)name_len, ch_name);
		return;
	}

	tag = (priv->ch_type < ARRAY_SIZE(lstp_ch_type_tags)) ? lstp_ch_type_tags[priv->ch_type] :
								NULL;
	if (!tag)
		tag = "UNKNOWN";

	snprintf(ch->display_name, sizeof(ch->display_name), "%s_%s_CH%u",
		 priv->usb->lstp_intf_name, tag, ch->ch_id);
	dev_warn(ch->dev, "%s: ch_%d: Empty channel name, consider fixing it! Using default '%s'\n",
		 __func__, ch->ch_id, ch->display_name);
}

/**
 * lstp_init_subsys_channel() - Bring up a single subsystem channel (1..N).
 * @dev:   LSTP USB device
 * @ch_id: Channel id to initialise
 *
 * Reads the channel descriptor and runs the matching subsystem's
 * channel_init(). Unsupported channel types are a no-op success.
 *
 * Return: 0 on success (including unsupported-type), negative errno on failure.
 */
static int lstp_init_subsys_channel(struct lstp_usb *dev, u8 ch_id)
{
	struct lstp_ch0_read_resp *resp __free(kfree) = NULL;
	struct lstp_channel_init_info info;
	struct lstp_channel_priv *priv;
	struct lstp_channel *ch;
	size_t resp_len;
	int ret;

	ch = lstp_create_channel(dev, ch_id);
	if (!ch)
		return -ENOMEM;
	priv = to_lstp_priv(ch);

	ret = lstp_ch0_read_config(ch, 0, LSTP_READ_CONFIG_MAX, &resp, &resp_len, NULL);
	if (ret)
		return ret;

	priv->ch_type = resp->desc.ch_type;
	lstp_set_display_name(ch, resp->desc.ch_name, LSTP_CH_NAME_LEN);

	priv->subsys = lstp_subsys_by_channel_type(priv->ch_type);
	if (!priv->subsys) {
		dev_warn(&dev->intf->dev, "%s: ch_%d: Unsupported channel type %d\n", __func__,
			 ch->ch_id, priv->ch_type);
		return 0;
	}

	ret = lstp_init_channel_fwnode(ch, priv->subsys->fwnode_compatible);
	if (ret)
		goto err_clear_subsys;

	ret = lstp_alloc_channel_bufs(ch);
	if (ret)
		goto err_clear_subsys;

	info = (struct lstp_channel_init_info){
		.config = resp->ch_config,
		.config_len = resp_len - sizeof(*resp),
	};
	ret = priv->subsys->channel_init(ch, &info);
	if (ret)
		goto err_clear_subsys;

	return 0;

err_clear_subsys:
	priv->subsys = NULL;
	return ret;
}

/**
 * lstp_init_channels() - Discover and initialize all LSTP channels.
 * @dev: LSTP USB device structure
 *
 * Calls lstp_ch0_init() then creates and initializes channels 1...max_ch_id.
 * Does NOT register with Linux subsystems; call lstp_start_channels() after.
 *
 * Return: 0 on success, negative errno if ch0 fails. Per-channel failures are
 * logged and skipped; whether any subsystem channel actually comes online is
 * determined by lstp_start_channels().
 */
static int lstp_init_channels(struct lstp_usb *dev)
{
	int ret;
	int ch_id;

	ret = lstp_ch0_init(dev);
	if (ret)
		return ret;

	for (ch_id = 1; ch_id <= dev->max_ch_id; ch_id++) {
		ret = lstp_init_subsys_channel(dev, ch_id);
		if (ret) {
			dev_err(&dev->intf->dev,
				"%s: ch_%d: Channel initialization failed. (%pe)\n", __func__,
				ch_id, ERR_PTR(ret));
			continue;
		}
	}

	return 0;
}

/**
 * lstp_start_channels() - Register all channels with Linux subsystems.
 * @dev: LSTP USB device structure
 *
 * Call after lstp_init_channels() and RX URB submission.
 *
 * Return: 0 if at least one subsystem channel starts; -ENODEV if none do
 * (every startable channel failed, or none were startable).
 */
static int lstp_start_channels(struct lstp_usb *dev)
{
	int started_count = 0;
	int ret;
	int i;
	struct lstp_channel *ch;

	for (i = 1; i < LSTP_MAX_CHANNELS; i++) {
		struct lstp_channel_priv *priv;

		ch = dev->channels[i];
		if (!ch)
			continue;
		priv = to_lstp_priv(ch);
		if (!priv->subsys)
			continue;

		ret = priv->subsys->channel_start(ch);
		if (ret) {
			dev_err(&dev->intf->dev, "%s: ch_%d: Channel failed to start. (%pe)\n",
				__func__, i, ERR_PTR(ret));
			priv->subsys = NULL;
			continue;
		}

		started_count++;

		smp_store_release(&priv->started, true); /* publish; RX dispatch load-acquires */

		ret = lstp_create_channel_sysfs(ch);
		if (ret) {
			/*
			 * Per-channel sysfs is diagnostic/control surface only. If it fails,
			 * keep the already-started subsystem online so the channel remains usable.
			 */
			dev_err(&dev->intf->dev,
				"%s: ch_%d: Channel sysfs creation failed. (%pe)\n", __func__, i,
				ERR_PTR(ret));
			continue;
		}
	}

	if (!started_count) {
		dev_err(&dev->intf->dev, "%s: No channels started\n", __func__);
		return -ENODEV;
	}

	return 0;
}

/**
 * lstp_probe() - USB driver probe function.
 * @intf: USB interface being probed
 * @id:   USB device ID that matched
 *
 * Two-phase init: lstp_init_channels() discovers/allocates, then after
 * RX URB setup, lstp_start_channels() registers with Linux subsystems.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	struct usb_device *udev = usb_get_dev(interface_to_usbdev(intf));
	struct usb_endpoint_descriptor *ep_in, *ep_out;
	struct lstp_usb *dev;
	int ret;

	dev = devm_kzalloc(&intf->dev, sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		usb_put_dev(udev);
		return -ENOMEM;
	}

	ret = devm_add_action_or_reset(&intf->dev, lstp_put_usb_dev, udev);
	if (ret)
		return ret;

	ret = usb_find_common_endpoints(intf->cur_altsetting, &ep_in, &ep_out, NULL, NULL);
	if (ret) {
		dev_err(&intf->dev, "%s: Could not find bulk endpoints\n", __func__);
		return ret;
	}

	dev->udev = udev;
	dev->intf = intf;
	dev->max_ch_id = 255; /* Maximum possible before device discovery */
	dev->bulk_in_ep = ep_in->bEndpointAddress;
	dev->bulk_out_ep = ep_out->bEndpointAddress;
	dev->bulk_tx_size = min_t(size_t, usb_endpoint_maxp(ep_out), LSTP_USB_EP_MAX_SIZE);
	dev->bulk_rx_size = min_t(size_t, usb_endpoint_maxp(ep_in), LSTP_USB_EP_MAX_SIZE);

	/* Validate minimum size */
	if (dev->bulk_tx_size < LSTP_USB_EP_MIN_SIZE || dev->bulk_rx_size < LSTP_USB_EP_MIN_SIZE) {
		dev_err(&intf->dev, "%s: Invalid endpoint sizes (tx=%zu, rx=%zu, min=%u)\n",
			__func__, dev->bulk_tx_size, dev->bulk_rx_size, LSTP_USB_EP_MIN_SIZE);
		return -EINVAL;
	}

	dev->rx_buf = devm_kzalloc(&intf->dev, dev->bulk_rx_size, GFP_KERNEL);
	if (!dev->rx_buf)
		return -ENOMEM;

	dev->bulk_rx_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!dev->bulk_rx_urb)
		return -ENOMEM;
	ret = devm_add_action_or_reset(&intf->dev, lstp_release_urb_slot, &dev->bulk_rx_urb);
	if (ret)
		return ret;

	usb_set_intfdata(intf, dev);

	INIT_DELAYED_WORK(&dev->bulk_rx_retry.work, lstp_rx_retry_work);

	usb_fill_bulk_urb(dev->bulk_rx_urb, dev->udev, usb_rcvbulkpipe(dev->udev, dev->bulk_in_ep),
			  dev->rx_buf, dev->bulk_rx_size, lstp_usb_rx_callback, dev);
	ret = usb_submit_urb(dev->bulk_rx_urb, GFP_KERNEL);
	if (ret) {
		dev_err(&intf->dev, "%s: Could not submit bulk RX URB (%pe)\n", __func__,
			ERR_PTR(ret));
		return ret;
	}

	ret = lstp_init_channels(dev);
	if (ret)
		goto err_teardown;

	ret = lstp_create_sysfs_hierarchy(dev);
	if (ret) {
		dev_err(&intf->dev, "%s: Failed to create sysfs hierarchy (%pe)\n", __func__,
			ERR_PTR(ret));
		goto err_teardown;
	}

	ret = lstp_start_channels(dev);
	if (ret)
		goto err_teardown;

	dev_info(&intf->dev, "%s: LSTP device initialized successfully\n", __func__);
	return 0;

err_teardown:
	dev_err(&intf->dev, "%s: Probe failed (%pe)\n", __func__, ERR_PTR(ret));
	lstp_teardown(dev);
	return ret;
}

/*******************************************************************************
 * Channel Signaling Helpers
 ******************************************************************************/

/**
 * lstp_signal_disconnect() - Signal all channels that the device is disconnected.
 * @dev: LSTP USB device structure
 */
static void lstp_signal_disconnect(struct lstp_usb *dev)
{
	for (int i = 0; i < LSTP_MAX_CHANNELS; i++) {
		struct lstp_channel_priv *priv;

		if (!dev->channels[i])
			continue;
		priv = to_lstp_priv(dev->channels[i]);
		/*
		 * Pairs with smp_load_acquire() in lstp_channel_disconnected().
		 * Ensures the flag is visible to the waiter before wake_up_all().
		 */
		smp_store_release(&priv->disconnected, true);
		wake_up_all(&priv->rx_wq);
	}
}

/**
 * lstp_ch_signal_response() - Signal that a response has been received on a channel.
 * @ch: LSTP channel that received the response
 */
static void lstp_ch_signal_response(struct lstp_channel *ch)
{
	struct lstp_channel_priv *priv = to_lstp_priv(ch);

	/*
	 * Pairs with smp_load_acquire() in lstp_ch_got_response().
	 * Release semantics ensure the memcpy into resp_buf is visible
	 * to readers before rx_ready becomes true.
	 */
	smp_store_release(&priv->rx_ready, true); /* release; pairs w/ got_response() */
	wake_up_all(&priv->rx_wq);
}

/**
 * lstp_ch_got_response() - Check if a solicited response has been received.
 * @ch: LSTP channel to check
 *
 * Return: true if a response is available in resp_buf.
 */
static inline bool lstp_ch_got_response(struct lstp_channel *ch)
{
	return smp_load_acquire(&to_lstp_priv(ch)->rx_ready); /* pairs w/ signal_response */
}

/**
 * lstp_ch_should_wake() - wait_event condition for lstp_request_xfer().
 * @ch: LSTP channel to check
 *
 * Return: true if the waiter should wake (response received or device disconnected).
 */
static inline bool lstp_ch_should_wake(struct lstp_channel *ch)
{
	return lstp_ch_got_response(ch) || lstp_channel_disconnected(ch);
}

/*******************************************************************************
 * Channel Lifecycle / Teardown
 ******************************************************************************/

/**
 * lstp_stop_rx() - Quiesce the RX path.
 * @dev: LSTP USB device structure
 *
 * Poison first so any racing resubmit (callback or worker) gets -EPERM,
 * then drain the worker.
 */
static void lstp_stop_rx(struct lstp_usb *dev)
{
	usb_poison_urb(dev->bulk_rx_urb);
	cancel_delayed_work_sync(&dev->bulk_rx_retry.work);
}

/**
 * lstp_stop_channels() - Stop all channels in reverse start order.
 * @dev: LSTP USB device structure
 *
 * Mirrors lstp_start_channels() so subsystems are torn down in the
 * opposite order they were brought up. Skips channels that never started.
 */
static void lstp_stop_channels(struct lstp_usb *dev)
{
	for (int i = LSTP_MAX_CHANNELS - 1; i >= 1; i--) {
		struct lstp_channel *ch = dev->channels[i];
		struct lstp_channel_priv *priv;

		if (!ch)
			continue;
		priv = to_lstp_priv(ch);

		if (priv->started && priv->subsys && priv->subsys->channel_stop)
			priv->subsys->channel_stop(ch);
	}
}

/**
 * lstp_stop_tx() - Quiesce all per-channel TX URBs.
 * @dev: LSTP USB device structure
 *
 * Poison the request and IRQ-response URBs on every initialised channel
 * so any racing usb_submit_urb() returns -EPERM. Safe on never-submitted
 * URBs.
 */
static void lstp_stop_tx(struct lstp_usb *dev)
{
	for (int i = 0; i < LSTP_MAX_CHANNELS; i++) {
		struct lstp_channel *ch = dev->channels[i];
		struct lstp_channel_priv *priv;

		if (!ch)
			continue;
		priv = to_lstp_priv(ch);

		usb_poison_urb(priv->bulk_tx_urb);
		usb_poison_urb(priv->bulk_tx_resp_urb);
	}
}

/**
 * lstp_drain_inflight() - Wait for in-flight per-channel I/O to complete.
 * @dev: LSTP USB device
 *
 * Called after lstp_signal_disconnect() so the disconnect flag is already
 * published. Acquires and immediately releases each channel's tx_mutex:
 * any caller currently holding the mutex finishes its USB submission and
 * drops the lock before this returns; any caller arriving afterwards
 * acquires the mutex uncontested, observes the disconnect flag while
 * holding it, and bails with -ENODEV.
 *
 * Pairs with the "check lstp_channel_disconnected() under tx_mutex"
 * contract followed by every public USB I/O helper. Together they
 * guarantee no caller is using priv->tx_buf or priv->resp_buf by the
 * time devres unwinds them on interface unbind.
 */
static void lstp_drain_inflight(struct lstp_usb *dev)
{
	for (int i = 0; i < LSTP_MAX_CHANNELS; i++) {
		struct lstp_channel *ch = dev->channels[i];
		struct lstp_channel_priv *priv;

		if (!ch)
			continue;
		priv = to_lstp_priv(ch);
		mutex_lock(&priv->tx_mutex);
		mutex_unlock(&priv->tx_mutex);
	}
}

/**
 * lstp_teardown() - Ordered driver-level teardown of the LSTP device.
 * @dev: LSTP USB device structure
 *
 * Shared by lstp_disconnect() and the lstp_probe() error path (USB core
 * does not call .disconnect() on probe failure). RX must stop before
 * channel_stop, or the dispatcher can race teardown. After
 * lstp_signal_disconnect() publishes the per-channel disconnect flag,
 * lstp_drain_inflight() drains any in-flight public USB I/O caller so
 * no caller is still touching a channel TX/RX buffer when devres
 * unwinds it on interface unbind.
 */
static void lstp_teardown(struct lstp_usb *dev)
{
	/* RX must stop before channel_stop, or the dispatcher can race teardown. */
	lstp_stop_rx(dev);

	lstp_signal_disconnect(dev);
	lstp_drain_inflight(dev);
	lstp_stop_channels(dev);
	lstp_stop_tx(dev);
}

/**
 * lstp_disconnect() - USB driver disconnect function.
 * @intf: USB interface being disconnected
 *
 * Ordered teardown; remaining cleanup runs via devres on interface unbind.
 */
static void lstp_disconnect(struct usb_interface *intf)
{
	struct lstp_usb *dev = usb_get_intfdata(intf);

	dev_info(&intf->dev, "%s: LSTP device disconnected\n", __func__);

	if (!dev)
		return;

	lstp_teardown(dev);
}

/*******************************************************************************
 * USB Helper Functions
 ******************************************************************************/

/**
 * lstp_usb_tx_callback() - USB TX URB completion callback.
 * @urb: Completed transmit URB
 */
static void lstp_usb_tx_callback(struct urb *urb)
{
	struct lstp_channel *ch = urb->context;

	if (urb->status != 0 && urb->status != -ENOENT && urb->status != -ECONNRESET &&
	    urb->status != -ESHUTDOWN) {
		dev_warn(ch->dev, "%s: ch_%d: TX URB error (%pe)\n", __func__, ch->ch_id,
			 ERR_PTR(urb->status));
	}
}

/**
 * lstp_usb_resp_tx_callback() - Completion callback for @bulk_tx_resp_urb.
 * @urb: Completed transmit URB
 *
 * Clears @priv->irq_resp_buffer_lock on every completion path (including kill
 * paths -ENOENT / -ECONNRESET / -ESHUTDOWN) so the bit never gets stuck
 * across disconnect/re-probe.
 */
static void lstp_usb_resp_tx_callback(struct urb *urb)
{
	struct lstp_channel *ch = urb->context;

	if (urb->status != 0 && urb->status != -ENOENT && urb->status != -ECONNRESET &&
	    urb->status != -ESHUTDOWN) {
		dev_warn(ch->dev, "%s: ch_%d: RX response TX URB error (%pe)\n", __func__,
			 ch->ch_id, ERR_PTR(urb->status));
	}

	clear_bit(LSTP_BUFFER_LOCK_BIT, &to_lstp_priv(ch)->irq_resp_buffer_lock);
}

/**
 * lstp_send_irq_resp() - Post a zero-payload response for an unsolicited RX packet.
 * @ch:     LSTP channel that received the IRQ packet
 * @status: Status byte to return to firmware (bit 7 is forced to 1 = response)
 *
 * Builds a header-only response packet in the framework-private TX response
 * buffer and submits it on the framework-private TX response URB with
 * GFP_ATOMIC. The response slot exists for exactly the channels whose
 * subsystem declares an @irq_callback (see lstp_alloc_channel_bufs()), which
 * are the only channels from which this helper is reachable.
 *
 * Intended to be called from an ``irq_callback`` handler (atomic context,
 * USB RX completion path), where the caller has no meaningful recovery for
 * a submission failure - errors are logged here and the function returns
 * void (fire-and-forget).
 *
 * @priv->irq_resp_buffer_lock serializes the per-channel response slot,
 * preventing concurrent reuse while a previous response is still DMA'ing.
 * Under a strictly 1-in-flight firmware contract the guard should never
 * trip; any hit is logged (ratelimited) as an actionable anomaly.
 */
void lstp_send_irq_resp(struct lstp_channel *ch, u8 status)
{
	struct lstp_channel_priv *priv;
	struct lstp_packet *tx_pkt;
	int ret;

	if (!ch)
		return;
	priv = to_lstp_priv(ch);
	if (!priv->usb || !priv->usb->udev)
		return;

	/*
	 * The response slot is allocated only for channels whose subsystem
	 * declares an irq_callback (see lstp_alloc_channel_bufs()). Bail
	 * explicitly rather than relying on that invariant by static review.
	 */
	if (!priv->tx_resp_buf || !priv->bulk_tx_resp_urb)
		return;

	if (test_and_set_bit(LSTP_BUFFER_LOCK_BIT, &priv->irq_resp_buffer_lock)) {
		dev_warn_ratelimited(ch->dev,
				     "%s: ch_%d: Dropping response - prior URB in flight\n",
				     __func__, ch->ch_id);
		return;
	}

	tx_pkt = (struct lstp_packet *)priv->tx_resp_buf;
	tx_pkt->hdr.ch_id = ch->ch_id;
	tx_pkt->hdr.length = cpu_to_le16(0);
	tx_pkt->hdr.status = SET_U8_BYTE(status, 1);

	usb_fill_bulk_urb(priv->bulk_tx_resp_urb, priv->usb->udev,
			  usb_sndbulkpipe(priv->usb->udev, priv->usb->bulk_out_ep), tx_pkt,
			  sizeof(struct lstp_header), lstp_usb_resp_tx_callback, ch);

	ret = usb_submit_urb(priv->bulk_tx_resp_urb, GFP_ATOMIC);
	if (ret) {
		clear_bit(LSTP_BUFFER_LOCK_BIT, &priv->irq_resp_buffer_lock);
		dev_err_ratelimited(ch->dev, "%s: ch_%d: Failed to submit TX URB (%pe)\n", __func__,
				    ch->ch_id, ERR_PTR(ret));
	}
}

/*
 * Retry indefinitely with bounded exponential backoff. No attempt budget:
 * giving up on transient pressure (-ENOMEM, etc.) would permanently kill
 * RX even when the underlying condition would self-heal.
 *
 * BASE_DELAY: minimum gap before the worker reposts the RX URB. Used both
 *             as the entry delay after a usb_submit_urb() failure and as a
 *             throttle for URB completion errors (e.g. -EPROTO from a
 *             babbling / mid-disconnect device) so we don't tight-loop the
 *             HCD from the completion callback. Kept well under
 *             LSTP_USB_RESPONSE_TIMEOUT_MS so a single transient blip does
 *             not burn the protocol's response budget.
 * MAX_DELAY:  ceiling for repeated submit failures' exponential backoff.
 */
#define LSTP_RX_RETRY_BASE_DELAY_MS 50
#define LSTP_RX_RETRY_MAX_DELAY_MS 1000
#define LSTP_RX_RETRY_MAX_BACKOFF_SHIFT 5

/**
 * lstp_rx_retry_backoff_ms() - Compute next RX retry delay.
 * @failures: Consecutive submit failure count (0 == first attempt)
 *
 * Doubles per attempt up to LSTP_RX_RETRY_MAX_DELAY_MS.
 *
 * Return: Delay in milliseconds before the next retry attempt.
 */
static unsigned long lstp_rx_retry_backoff_ms(unsigned int failures)
{
	unsigned int shift = failures ? min(failures - 1, LSTP_RX_RETRY_MAX_BACKOFF_SHIFT) : 0;
	unsigned long ms = (unsigned long)LSTP_RX_RETRY_BASE_DELAY_MS << shift;

	return min_t(unsigned long, ms, LSTP_RX_RETRY_MAX_DELAY_MS);
}

/**
 * lstp_rx_handle_err() - Defer or terminate RX after a URB error.
 * @dev:      LSTP USB device structure
 * @ret:      Errno from a usb_submit_urb() failure or a URB completion
 * @delay_ms: Backoff delay if scheduling a retry
 *
 * Records @ret in @bulk_rx_retry.last_err so the worker can act on it
 * (e.g. clear the endpoint halt for -EPIPE). Terminal teardown errnos
 * signal disconnect silently; everything else schedules the worker.
 */
static void lstp_rx_handle_err(struct lstp_usb *dev, int ret, unsigned long delay_ms)
{
	struct lstp_rx_retry *rxr = &dev->bulk_rx_retry;

	WRITE_ONCE(rxr->last_err, ret);

	/*
	 * -EPERM is the usb_poison_urb() fence set in lstp_stop_rx();
	 * -ENODEV/-ESHUTDOWN mean the device or HCD is gone. All three are
	 * the expected outcome of disconnect, not failures: signal the
	 * disconnect path and stop reposting. lstp_disconnect() already
	 * logs the device removal, so no message here.
	 */
	if (ret == -ENODEV || ret == -ESHUTDOWN || ret == -EPERM) {
		lstp_signal_disconnect(dev);
		return;
	}

	/*
	 * Wire-side completion errors (-EPROTO/-EOVERFLOW/-EILSEQ) come
	 * from a babbling or otherwise misbehaving device and can fire
	 * back-to-back, so ratelimit them. Everything else (notably
	 * submit-side -ENOMEM/-EAGAIN/-EINVAL from the worker) is rare and
	 * per-event diagnostic, so log unconditionally; the worker's
	 * exponential backoff already throttles repeats.
	 */
	if (ret == -EPROTO || ret == -EOVERFLOW || ret == -EILSEQ)
		dev_warn_ratelimited(&dev->intf->dev,
				     "%s: RX URB transient error (%pe), retry in %lums\n", __func__,
				     ERR_PTR(ret), delay_ms);
	else
		dev_warn(&dev->intf->dev, "%s: RX URB transient error (%pe), retry in %lums\n",
			 __func__, ERR_PTR(ret), delay_ms);

	schedule_delayed_work(&rxr->work, msecs_to_jiffies(delay_ms));
}

/**
 * lstp_rx_retry_work() - Process-context fallback for the RX completion
 *                        callback's atomic-context resubmit.
 * @work: &struct lstp_rx_retry.work embedded in &struct lstp_usb
 *
 * Clears endpoint halts on -EPIPE, then retries the RX URB with GFP_KERNEL.
 * Failures are handed to lstp_rx_handle_err() with an exponential
 * backoff.
 */
static void lstp_rx_retry_work(struct work_struct *work)
{
	struct lstp_rx_retry *rxr = container_of(to_delayed_work(work), struct lstp_rx_retry, work);
	struct lstp_usb *dev = container_of(rxr, struct lstp_usb, bulk_rx_retry);
	int last_err = READ_ONCE(rxr->last_err);
	int ret;

	if (last_err == -EPIPE) {
		ret = usb_clear_halt(dev->udev, usb_rcvbulkpipe(dev->udev, dev->bulk_in_ep));
		if (ret)
			dev_warn(&dev->intf->dev, "%s: usb_clear_halt failed (%pe)\n", __func__,
				 ERR_PTR(ret));
	}

	ret = usb_submit_urb(dev->bulk_rx_urb, GFP_KERNEL);
	if (ret == 0) {
		if (rxr->failures)
			dev_info(&dev->intf->dev, "%s: RX URB resubmitted after %u failure(s)\n",
				 __func__, rxr->failures);
		rxr->failures = 0;
		return;
	}

	rxr->failures++;
	lstp_rx_handle_err(dev, ret, lstp_rx_retry_backoff_ms(rxr->failures));
}

/**
 * lstp_usb_rx_callback() - USB RX URB completion callback.
 * @urb: Completed receive URB
 *
 * Routes requests (bit7=0) to irq_callback, responses (bit7=1) to waiters.
 */
static void lstp_usb_rx_callback(struct urb *urb)
{
	struct lstp_usb *dev = urb->context;
	int ret;

	/* URB killed during disconnect */
	if (urb->status == -ENOENT || urb->status == -ECONNRESET || urb->status == -ESHUTDOWN) {
		lstp_signal_disconnect(dev);
		return;
	}

	/*
	 * Persistent HCD errors (e.g. -EPROTO from a babbling or mid-disconnect
	 * device) can fire back-to-back. Defer resubmit to the worker instead
	 * of tight-looping the HCD from atomic context.
	 */
	if (urb->status) {
		lstp_rx_handle_err(dev, urb->status, LSTP_RX_RETRY_BASE_DELAY_MS);
		return;
	}

	struct lstp_packet *rx_pkt = (struct lstp_packet *)dev->rx_buf;

	if (lstp_validate_rx_pkt(dev, rx_pkt, urb->actual_length))
		goto resubmit;

	/* Get channel - ch_id already bound checked by lstp_validate_rx_pkt() */
	u8 ch_id = rx_pkt->hdr.ch_id;
	struct lstp_channel *ch = dev->channels[ch_id];
	struct lstp_channel_priv *priv;

	if (!ch) {
		dev_err(&dev->intf->dev, "%s: ch_%d: Channel not registered\n", __func__, ch_id);
		goto resubmit;
	}
	priv = to_lstp_priv(ch);

	bool in_service = smp_load_acquire(&priv->started); /* pairs w/ start_channels */

	if (in_service && GET_BIT_7(rx_pkt->hdr.status) == 0 && priv->subsys &&
	    priv->subsys->irq_callback && priv->irq_buf) {
		/* Unsolicited request -> irq_buf + callback */
		if (test_and_set_bit(LSTP_BUFFER_LOCK_BIT, &priv->irq_buffer_lock)) {
			dev_warn(ch->dev, "%s: ch_%d: Dropping request - irq buffer busy\n",
				 __func__, ch_id);
		} else {
			dev_dbg(ch->dev, "%s: ch_%d: Received unsolicited request (IRQ event)\n",
				__func__, ch_id);
			memcpy(priv->irq_buf, dev->rx_buf, urb->actual_length);
			priv->subsys->irq_callback(ch, (struct lstp_packet *)priv->irq_buf);
			clear_bit(LSTP_BUFFER_LOCK_BIT, &priv->irq_buffer_lock);
		}
	} else if (GET_BIT_7(rx_pkt->hdr.status) == 1 && priv->resp_buf) {
		/* Solicited response -> rx_buf + wake helper */
		if (!test_bit(LSTP_BUFFER_LOCK_BIT, &priv->resp_buffer_lock)) {
			dev_warn(ch->dev, "%s: ch_%d: Dropping response - no one waiting\n",
				 __func__, ch_id);
		} else {
			memcpy(priv->resp_buf, dev->rx_buf, urb->actual_length);
			lstp_ch_signal_response(ch);
		}
	} else {
		dev_err_ratelimited(ch->dev, "%s: ch_%d: Dropping packet - channel misconfigured\n",
				    __func__, ch_id);
	}

resubmit:
	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (ret)
		lstp_rx_handle_err(dev, ret, LSTP_RX_RETRY_BASE_DELAY_MS);
}

/**
 * lstp_channel_disconnected() - Check if the channel's USB device has been disconnected.
 * @ch: LSTP channel to check.
 *
 * Return: true if the USB device has been disconnected.
 */
bool lstp_channel_disconnected(const struct lstp_channel *ch)
{
	/* Pairs with smp_store_release() in lstp_signal_disconnect(). */
	return smp_load_acquire(&to_lstp_priv(ch)->disconnected);
}

/**
 * lstp_send() - Send a one-way LSTP packet on the bulk-out endpoint.
 * @ch:      LSTP channel to send on
 * @cmd:     LSTP command byte. Bit 7 is forced to 0 (request direction)
 * @payload: Payload bytes to copy into the channel's TX buffer; may be NULL
 *           if @len == 0
 * @len:     Payload length in bytes
 *
 * Fire-and-forget bulk-out send. Serializes on the per-channel TX
 * mutex across header build and USB submission, and checks
 * lstp_channel_disconnected() under that lock so the test and the
 * actual usb_bulk_msg() submission live on the same side of the lock.
 * Pairs with the lstp_drain_inflight() teardown barrier so no caller
 * is using the channel's TX buffer when devres unwinds it on interface
 * unbind.
 *
 * Context: Process context. May sleep.
 *
 * Return: 0 on success; -ENODEV if @ch is not initialized for I/O or
 *         the channel is disconnected; -EINVAL if @payload is NULL with
 *         @len > 0; -EMSGSIZE if @len exceeds the TX buffer; otherwise
 *         the errno from usb_bulk_msg().
 */
int lstp_send(struct lstp_channel *ch, u8 cmd, const void *payload, size_t len)
{
	struct lstp_channel_priv *priv;
	struct lstp_packet *tx_pkt;
	size_t total;

	if (!ch)
		return -ENODEV;
	priv = to_lstp_priv(ch);
	if (!priv->usb || !priv->tx_buf)
		return -ENODEV;

	if (len && !payload)
		return -EINVAL;

	if (len > ch->max_tx_payload || check_add_overflow(sizeof(struct lstp_header), len, &total))
		return -EMSGSIZE;

	guard(lstp_channel)(ch);
	if (lstp_channel_disconnected(ch))
		return -ENODEV;

	tx_pkt = (struct lstp_packet *)priv->tx_buf;
	tx_pkt->hdr.ch_id = ch->ch_id;
	tx_pkt->hdr.cmd = SET_U8_BYTE(cmd, 0); /* bit 7 = 0 for request */
	tx_pkt->hdr.length = cpu_to_le16(len);
	if (len)
		memcpy(tx_pkt->payload, payload, len);

	return usb_bulk_msg(priv->usb->udev,
			    usb_sndbulkpipe(priv->usb->udev, priv->usb->bulk_out_ep), priv->tx_buf,
			    total, NULL, LSTP_USB_REQUEST_TIMEOUT_MS);
}

/**
 * deprecated_lstp_channel_publish_child_dev() - Record the subsystem-side
 *	device the channel exposes.
 * @ch:        LSTP channel.
 * @child_dev: Device the subsystem registered with the kernel
 *             (i2c_adapter->dev, spi_controller->dev, gpio_device's device,
 *             miscdevice->this_device, ...). May be NULL to clear.
 *
 * Stored on @ch so the framework can publish a "device" symlink under
 * /sys/.../lstp/channel/N pointing at the subsystem-facing device.
 * Typically called once from the subsystem's channel_start() after the
 * underlying device has been registered.
 *
 * @ch stores @child_dev as a raw pointer; the caller retains ownership
 * and must keep it registered for the channel's lifetime.
 *
 * The deprecated_ prefix marks this as compat scaffolding: it exists only to
 * back the channel/N/device symlink and is grep-removable once that symlink
 * is retired. It also cannot represent channels that expose zero or several
 * peer devices.
 *
 * Context: Any.
 */
void deprecated_lstp_channel_publish_child_dev(struct lstp_channel *ch, struct device *child_dev)
{
	if (!ch)
		return;
	to_lstp_priv(ch)->child_dev = child_dev;
}

/**
 * lstp_request_xfer() - Run one LSTP request/response exchange on @ch.
 * @ch:       LSTP channel.
 * @cmd:      LSTP command byte. Bit 7 is forced to 0 (request direction).
 * @req_len:  Request payload length already populated in priv->tx_buf.
 * @resp:     Caller buffer to receive the response payload, or NULL when
 *            @resp_cap == 0.
 * @resp_cap: Capacity of @resp in bytes. See lstp_request() for the
 *            strict / variable mode semantics.
 * @resp_len: Strict / variable mode selector; see lstp_request().
 * @lstp_status: Optional out-param for the raw LSTP response status; see
 *            lstp_request(). Publishes LSTP_SUCCESS only once the exchange is
 *            fully validated.
 *
 * File-static engine used by lstp_request() / lstp_requestv() after they
 * have taken priv->tx_mutex via guard(lstp_channel)(). Owns
 * priv->resp_buffer_lock end-to-end: claims it on entry with
 * test_and_set_bit() and releases it at out_release: on every exit
 * path. The caller does not see the lock.
 *
 * Preconditions (file-local helper, no defensive re-checks):
 *
 * * @ch fully initialized (priv->usb, priv->tx_buf, priv->resp_buf non-NULL).
 * * @req_len <= @ch->max_tx_payload.
 * * @resp_cap <= @ch->max_rx_payload.
 * * Caller holds priv->tx_mutex via guard(lstp_channel)().
 * * Caller has verified the channel is not disconnected under that lock,
 *   so the shared TX URB is not reused after a kill-skipped timeout.
 * * priv->tx_buf->payload already carries the request payload bytes.
 *
 * Return: 0 on success; -EBUSY if the inflight slot was somehow already
 *         claimed; -ENODEV on disconnect-raced URB submit; -ETIMEDOUT
 *         on no-response; -EMSGSIZE in variable mode when the device
 *         reports more than @resp_cap bytes; otherwise the errno from
 *         lstp_validate_resp() or usb_submit_urb().
 */
static int lstp_request_xfer(struct lstp_channel *ch, u8 cmd, u16 req_len, void *resp,
			     size_t resp_cap, size_t *resp_len, int *lstp_status)
{
	struct lstp_channel_priv *priv = to_lstp_priv(ch);
	struct lstp_packet *tx_pkt = (struct lstp_packet *)priv->tx_buf;
	struct lstp_packet *rx_pkt = (struct lstp_packet *)priv->resp_buf;
	/*
	 * Strict mode pushes the floor down to the wire so under-reads fail
	 * at lstp_validate_resp(); variable mode disables the wire floor and
	 * enforces the ceiling below.
	 */
	u16 wire_min = resp_len ? LSTP_ANY_RX_LEN : (u16)resp_cap;
	size_t to_copy = 0;
	size_t actual;
	int ret;

	/* Try to claim rx buffer - if already in use, that's a bug */
	if (test_and_set_bit(LSTP_BUFFER_LOCK_BIT, &priv->resp_buffer_lock)) {
		dev_err(ch->dev, "%s: ch_%d: BUG - rx buffer already in use\n", __func__,
			ch->ch_id);
		return -EBUSY;
	}

	tx_pkt->hdr.ch_id = ch->ch_id;
	tx_pkt->hdr.cmd = SET_U8_BYTE(cmd, 0); /* bit 7 = 0 for request */
	tx_pkt->hdr.length = cpu_to_le16(req_len);

	if (req_len > 0)
		dev_dbg(ch->dev, "%s: ch_%d: TX cmd=0x%02x, tx_len=%u, rx_min=%u, payload=0x%*ph\n",
			__func__, ch->ch_id, cmd, req_len, wire_min, req_len, tx_pkt->payload);
	else
		dev_dbg(ch->dev, "%s: ch_%d: TX cmd=0x%02x, tx_len=0, rx_min=%u\n", __func__,
			ch->ch_id, cmd, wire_min);

	usb_fill_bulk_urb(priv->bulk_tx_urb, priv->usb->udev,
			  usb_sndbulkpipe(priv->usb->udev, priv->usb->bulk_out_ep), priv->tx_buf,
			  sizeof(struct lstp_header) + req_len, lstp_usb_tx_callback, ch);

	/* Pairs with smp_store_release()/smp_load_acquire() on rx_ready. */
	WRITE_ONCE(priv->rx_ready, false);

	ret = usb_submit_urb(priv->bulk_tx_urb, GFP_KERNEL);
	if (ret) {
		/*
		 * If teardown raced our submit, return -ENODEV (same as the
		 * disconnect branch below) instead of leaking -EPERM/-ESHUTDOWN
		 * to userspace.
		 */
		if (ret == -EPERM || ret == -ESHUTDOWN)
			ret = -ENODEV;
		goto out_release;
	}

	wait_event_timeout(priv->rx_wq, lstp_ch_should_wake(ch),
			   msecs_to_jiffies(LSTP_USB_RESPONSE_TIMEOUT_MS));

	if (!lstp_ch_got_response(ch)) {
		if (lstp_channel_disconnected(ch)) {
			/*
			 * usb_kill_urb() blocks until the URB is retired. A
			 * synchronous accessor can reach here holding a lock that
			 * teardown waits on (e.g. gpiolib's SRCU section, drained
			 * by gpiochip_remove()); under load the wait can exceed
			 * the hung-task timeout and wedge teardown. Leave the
			 * queued URB for lstp_stop_tx() to reclaim.
			 */
			ret = -ENODEV;
		} else {
			/* Live timeout: reclaim the URB so tx_buf can be reused. */
			usb_kill_urb(priv->bulk_tx_urb);
			ret = -ETIMEDOUT;
		}
		dev_err_ratelimited(ch->dev, "%s: ch_%d: No response (%pe)\n", __func__, ch->ch_id,
				    ERR_PTR(ret));
		goto out_release;
	}

	ret = lstp_validate_resp(priv->usb, rx_pkt, wire_min, lstp_status);
	if (ret)
		goto out_release;

	actual = le16_to_cpu(rx_pkt->hdr.length);
	dev_dbg(ch->dev, "%s: ch_%d: RX rx_len=%zu\n", __func__, ch->ch_id, actual);

	if (resp_len) {
		if (actual > resp_cap) {
			ret = -EMSGSIZE;
			goto out_release;
		}
		to_copy = actual;
		*resp_len = actual;
	} else {
		/*
		 * Forward-compat: device may legitimately reply with more than
		 * @resp_cap bytes when firmware extends the response; consume
		 * only what the caller asked for.
		 */
		to_copy = resp_cap;
	}

	if (resp && to_copy)
		memcpy(resp, rx_pkt->payload, to_copy);

	/* Publish success only once the whole exchange is validated. */
	if (lstp_status)
		*lstp_status = LSTP_SUCCESS;

out_release:
	clear_bit(LSTP_BUFFER_LOCK_BIT, &priv->resp_buffer_lock);
	return ret;
}

/**
 * lstp_request() - Issue an LSTP request/response exchange.
 * @ch:       LSTP channel
 * @cmd:      LSTP command byte. Bit 7 is forced to 0 (request direction)
 * @req:      Request payload to copy into the channel's TX buffer; may be
 *            NULL if @req_len == 0
 * @req_len:  Request payload length in bytes
 * @resp:     Caller buffer that receives the response payload; may be NULL
 *            if @resp_cap == 0, or when @resp_len is non-NULL to discard
 *            the response payload
 * @resp_cap: Capacity of @resp in bytes. Treated as the exact expected
 *            response length when @resp_len is NULL; treated as an upper
 *            bound on the device-reported length when @resp_len is
 *            non-NULL
 * @resp_len: Out-param for the on-wire response length, or NULL. The
 *            pointer doubles as the fixed/variable mode selector:
 *
 *            * NULL (fixed): The device must reply with at least
 *              @resp_cap bytes (-EIO on under-read). Longer replies are
 *              silently accepted for forward compatibility with newer
 *              firmware and only the first @resp_cap bytes are copied
 *              into @resp
 *
 *            * non-NULL (variable): No lower bound on the response
 *              length. If the device reports more than @resp_cap bytes
 *              the call fails with -EMSGSIZE; otherwise the reported
 *              length is written to *@resp_len and that many bytes are
 *              copied into @resp
 * @lstp_status: Optional out-param for the raw LSTP response status.
 *            Set to the device status when the exchange succeeds
 *            (LSTP_SUCCESS) or when the returned errno is derived from that
 *            status. Set to LSTP_NO_RESPONSE_STATUS when the result is not
 *            associated with a response status, such as transport errors or
 *            payload/length validation failures. Unmodified if NULL.
 *
 * Issues one atomic LSTP request/response exchange. Channel locking and
 * RX-buffer release are internal; the caller only owns @req and @resp.
 *
 * For request payloads that span multiple caller-owned buffers (a
 * fixed header struct followed by a caller-managed body, etc.) use
 * lstp_requestv() with a struct kvec vector to skip the
 * bounce-buffer concatenation step.
 *
 * Context: Process context. May sleep.
 *
 * Return: 0 on success; -ENODEV if @ch is not initialized for I/O;
 *         -EINVAL if @req is NULL with @req_len > 0, or if @resp is NULL
 *         with @resp_cap > 0 in fixed mode; -EMSGSIZE if the framed
 *         request or response would exceed the channel's bulk TX/RX
 *         buffer, or (in variable mode) the device reply exceeds
 *         @resp_cap; -EIO if (in fixed mode) the device reply is
 *         shorter than @resp_cap; otherwise the errno from the
 *         underlying USB I/O.
 */
int lstp_request(struct lstp_channel *ch, u8 cmd, const void *req, size_t req_len, void *resp,
		 size_t resp_cap, size_t *resp_len, int *lstp_status)
{
	return lstp_requestv(ch, cmd,
			     &(const struct kvec){
				     .iov_base = (void *)req,
				     .iov_len = req_len,
			     },
			     1, resp, resp_cap, resp_len, lstp_status);
}

/**
 * lstp_requestv() - Vectored variant of lstp_request().
 * @ch:       LSTP channel
 * @cmd:      LSTP command byte; see lstp_request()
 * @vecs:     Input kvec vector; concatenated into the TX payload in
 *            order. Each entry's @iov_base may be NULL only when its
 *            @iov_len is 0. May be NULL if @nvecs is 0
 * @nvecs:    Number of entries in @vecs. May be 0 for an empty
 *            request
 * @resp:     see lstp_request()
 * @resp_cap: see lstp_request()
 * @resp_len: see lstp_request()
 * @lstp_status: see lstp_request()
 *
 * Identical to lstp_request() except that the request payload is the
 * concatenation of @vecs[0..@nvecs-1] rather than a single buffer.
 * Each entry is copied directly into the channel TX buffer at its
 * position in the concatenation; no intermediate bounce is allocated.
 *
 * Callers typically build the kvec array on the stack and pass it with
 * ARRAY_SIZE(), for example::
 *
 *	struct kvec vecs[] = {
 *		{ .iov_base = &hdr,    .iov_len = sizeof(hdr) },
 *		{ .iov_base = msg->buf, .iov_len = msg->len  },
 *	};
 *
 *	ret = lstp_requestv(ch, cmd, vecs, ARRAY_SIZE(vecs),
 *			    NULL, 0, NULL, NULL);
 *
 * Context: Process context. May sleep.
 *
 * Return: see lstp_request().
 */
int lstp_requestv(struct lstp_channel *ch, u8 cmd, const struct kvec *vecs, size_t nvecs,
		  void *resp, size_t resp_cap, size_t *resp_len, int *lstp_status)
{
	struct lstp_channel_priv *priv;
	struct lstp_packet *tx_pkt;
	size_t req_total = 0;
	size_t off = 0;
	size_t i;

	/* Fail-safe default: only the xfer/validation publish a real status. */
	if (lstp_status)
		*lstp_status = LSTP_NO_RESPONSE_STATUS;

	if (!ch)
		return -ENODEV;
	priv = to_lstp_priv(ch);
	if (!priv->usb || !priv->tx_buf || !priv->resp_buf)
		return -ENODEV;

	if (nvecs && !vecs)
		return -EINVAL;
	if (!resp_len && resp_cap && !resp)
		return -EINVAL;

	for (i = 0; i < nvecs; i++) {
		if (vecs[i].iov_len && !vecs[i].iov_base)
			return -EINVAL;
		if (check_add_overflow(req_total, vecs[i].iov_len, &req_total))
			return -EMSGSIZE;
	}

	if (req_total > ch->max_tx_payload || resp_cap > ch->max_rx_payload)
		return -EMSGSIZE;

	guard(lstp_channel)(ch);
	if (lstp_channel_disconnected(ch))
		return -ENODEV;

	tx_pkt = (struct lstp_packet *)priv->tx_buf;
	for (i = 0; i < nvecs; i++) {
		if (vecs[i].iov_len) {
			memcpy(tx_pkt->payload + off, vecs[i].iov_base, vecs[i].iov_len);
			off += vecs[i].iov_len;
		}
	}

	return lstp_request_xfer(ch, cmd, (u16)req_total, resp, resp_cap, resp_len, lstp_status);
}

/*******************************************************************************
 * Driver Registration
 ******************************************************************************/

static const struct usb_device_id lstp_id_table[] = {
	{ USB_VENDOR_AND_INTERFACE_INFO(0x0955, 0xFF, 0x3F, LSTP_VERSION) },
	{}
};
MODULE_DEVICE_TABLE(usb, lstp_id_table);

static struct usb_driver lstp_usb_driver = {
	.name = "lstp",
	.probe = lstp_probe,
	.disconnect = lstp_disconnect,
	.id_table = lstp_id_table,
};

LSTP_SUBSYS_DECLARE(spi);
LSTP_SUBSYS_DECLARE(gpio);
LSTP_SUBSYS_DECLARE(i2c);
LSTP_SUBSYS_DECLARE(uart);
LSTP_SUBSYS_DECLARE(ipmi);
LSTP_SUBSYS_DECLARE(mmio);

/* clang-format off */
static const struct lstp_subsys *const lstp_subsystems[] = {
	LSTP_SUBSYS_REF(spi),
	LSTP_SUBSYS_REF(gpio),
	LSTP_SUBSYS_REF(i2c),
	LSTP_SUBSYS_REF(uart),
	LSTP_SUBSYS_REF(ipmi),
	LSTP_SUBSYS_REF(mmio),
};

/* clang-format on */

const struct lstp_subsys *lstp_subsys_by_channel_type(u8 channel_type)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(lstp_subsystems); i++)
		if (lstp_subsystems[i]->channel_type == channel_type)
			return lstp_subsystems[i];
	return NULL;
}

static int __init lstp_module_init(void)
{
	size_t i;
	int ret;

	for (i = 0; i < ARRAY_SIZE(lstp_subsystems); i++) {
		ret = lstp_subsystems[i]->init ? lstp_subsystems[i]->init() : 0;
		if (ret) {
			pr_err("lstp: subsys %s init failed: %pe\n", lstp_subsystems[i]->name,
			       ERR_PTR(ret));
			goto unwind_subsys;
		}
	}

	ret = usb_register(&lstp_usb_driver);
	if (ret)
		goto unwind_subsys;

	return 0;

unwind_subsys:
	while (i-- > 0)
		if (lstp_subsystems[i]->exit)
			lstp_subsystems[i]->exit();
	return ret;
}

static void __exit lstp_module_exit(void)
{
	size_t i = ARRAY_SIZE(lstp_subsystems);

	usb_deregister(&lstp_usb_driver);

	while (i-- > 0)
		if (lstp_subsystems[i]->exit)
			lstp_subsystems[i]->exit();
}

module_init(lstp_module_init);
module_exit(lstp_module_exit);

bool lstp_auto_bind_spidev = IS_ENABLED(CONFIG_USB_LSTP_SPI_SPIDEV);
module_param_named(auto_bind_spidev, lstp_auto_bind_spidev, bool, 0444);
/* clang-format off */
MODULE_PARM_DESC(auto_bind_spidev, "Auto-create spidev devices on SPI channels without firmware nodes (default: CONFIG_USB_LSTP_SPI_SPIDEV)");
/* clang-format on */

MODULE_DESCRIPTION("LSTP USB device driver");
MODULE_LICENSE("GPL");
