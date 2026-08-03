/* SPDX-License-Identifier: GPL-2.0-only */
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

#ifndef __LSTP_MAIN_H
#define __LSTP_MAIN_H

#include <linux/build_bug.h>
#include <linux/mutex.h>
#include <linux/property.h>
#include <linux/uio.h>
#include <linux/usb.h>
#include <linux/workqueue.h>

#define LSTP_VERSION 1
#define LSTP_USB_RESPONSE_TIMEOUT_MS 1000
#define LSTP_USB_REQUEST_TIMEOUT_MS 1000
#define LSTP_USB_EP_MIN_SIZE 64
#define LSTP_USB_EP_MAX_SIZE 512
#define LSTP_MAX_CHANNELS 256 /* Includes channel 0 */
#define LSTP_ANY_RX_LEN 0 /* "no minimum" -- callers without a known min payload length */
#define LSTP_READ_CONFIG_MAX U16_MAX /* sentinel: max ch_config bytes per USB RX packet */
#define DEPRECATED_LSTP_READ_CONFIG_MAX 0 /* Noncompliant firmware workaround TODO: remove */
#define LSTP_CH_NAME_LEN 16
#define LSTP_INTF_NAME_LEN (LSTP_CH_NAME_LEN + 1) /* ch0_name + '\0' */
#define LSTP_DISPLAY_NAME_LEN (LSTP_CH_NAME_LEN * 2 + 2) /* intf_name + '_' + ch_name + '\0' */

#define GET_BIT_7(u8_byte) (((u8_byte) >> 7) & 0x01)
#define GET_BIT_0_6(u8_byte) ((u8_byte) & 0x7F)
#define SET_U8_BYTE(bit_0_6, bit_7) ((((bit_7) & 0x01) << 7) | ((bit_0_6) & 0x7F))

#define LSTP_GET_PAYLOAD(pkt, type)                                  \
	({                                                           \
		typeof(pkt) _p = (pkt);                              \
		size_t _len = (size_t)le16_to_cpu(_p->hdr.length);   \
		(_len >= sizeof(type)) ? (type *)_p->payload : NULL; \
	})

/* Channel flags bit definitions */
#define LSTP_CH_FLAG_ENABLE BIT(0)

/* Buffer lock bit (resp_buffer_lock and irq_buffer_lock) */
#define LSTP_BUFFER_LOCK_BIT 0

/* Channel state bits */
#define LSTP_CHANNEL_DISABLED_BIT 0

enum lstp_channel_type {
	LSTP_CHANNEL_TYPE_MGMT = 0x00,
	LSTP_CHANNEL_TYPE_SPI = 0x01,
	LSTP_CHANNEL_TYPE_GPIO = 0x02,
	LSTP_CHANNEL_TYPE_I2C = 0x03,
	LSTP_CHANNEL_TYPE_UART = 0x04,
	LSTP_CHANNEL_TYPE_IPMI = 0x05,
	LSTP_CHANNEL_TYPE_MMIO = 0x06,
	LSTP_CHANNEL_TYPE_MAX, /* sentinel, not a wire value; keep last */
};

enum lstp_status {
	LSTP_SUCCESS = 0x00,
	LSTP_ERROR = 0x01,
	LSTP_TIMEOUT = 0x02,
	LSTP_BUSY = 0x03,
	LSTP_NACK = 0x04,
	LSTP_ARB_LOST = 0x05,
	LSTP_NOT_SUPP = 0x06,
	LSTP_TOO_LARGE = 0x07,
};

/*
 * lstp_status out-param sentinel: the request result is not associated
 * with an LSTP response status byte (transport/local error, or no response).
 * Distinct from any valid status (0x00..0x7f from GET_BIT_0_6()).
 */
#define LSTP_NO_RESPONSE_STATUS (-1)

struct lstp_ch0_read_req {
	u8 ch_id;
	__le16 offset;
	__le16 length;
} __packed;

/*
 * Channel descriptor block: the firmware-controlled identity triple
 * (type, flags, name) carried by every ch0 config exchange. Appears
 * as a leading prefix inside lstp_ch0_write_req and as the fixed head
 * of lstp_ch0_read_resp; extracted so callers can stack-allocate just
 * this fixed-size piece (the flex-array trailer cannot live in
 * automatic storage).
 */
struct lstp_ch_desc {
	u8 ch_type;
	u8 ch_flags;
	char ch_name[LSTP_CH_NAME_LEN];
} __packed;

struct lstp_ch0_write_req {
	u8 ch_id;
	__le16 offset;
	struct lstp_ch_desc desc;
	u8 ch_config[];
} __packed;

struct lstp_ch0_read_resp {
	struct lstp_ch_desc desc;
	u8 ch_config[];
} __packed;

struct lstp_header {
	u8 ch_id;
	union { /* [0:6] cmd/status, [7] 0=request/1=response */
		u8 cmd;
		u8 status;
	};
	__le16 length;
} __packed;

struct lstp_packet {
	struct lstp_header hdr;
	u8 payload[];
} __packed;

/*
 * Process-context fallback for the RX completion callback when
 * usb_submit_urb() fails atomically (e.g. -ENOMEM, -EPIPE).
 */
struct lstp_rx_retry {
	struct delayed_work work;
	int last_err;
	unsigned int failures;
};

struct lstp_usb {
	struct usb_device *udev;
	struct usb_interface *intf;
	u8 bulk_in_ep;
	u8 bulk_out_ep;
	struct urb *bulk_rx_urb;
	struct lstp_rx_retry bulk_rx_retry;
	u8 *rx_buf;
	size_t bulk_tx_size;
	size_t bulk_rx_size;
	u8 lstp_version;
	char lstp_intf_name[LSTP_INTF_NAME_LEN];
	u8 max_ch_id;
	struct lstp_channel *channels[LSTP_MAX_CHANNELS];
	struct kobject lstp_kobj; /* /sys/.../lstp */
	struct kobject *channel_kobj; /* /sys/.../lstp/channel */
};

/**
 * typedef lstp_irq_callback - Callback for unsolicited packets.
 * @ch:  Channel that received the unsolicited request.
 * @pkt: Received LSTP packet. The framework guarantees that pkt->hdr and
 *       le16_to_cpu(pkt->hdr.length) bytes of pkt->payload are valid, so
 *       the callback can read them without rechecking. Valid only for the
 *       duration of the call; the same buffer is reused for the next
 *       unsolicited packet on this channel. The callback must not retain
 *       the pointer and must not modify packet contents.
 *
 * Called in atomic context - must not sleep.
 */
typedef void (*lstp_irq_callback)(struct lstp_channel *ch, struct lstp_packet *pkt);

struct lstp_subsys;

/**
 * struct lstp_channel - Per-channel state visible to LSTP subsystems.
 * @ch_id:          LSTP channel id assigned by the device. ch0 is the
 *                  management channel; subsystem channels run 1..max_ch_id.
 * @display_name:   Human-readable channel name built by the framework from
 *                  the interface and channel names. Suitable as a
 *                  Linux-subsystem display string (i2c_adapter.name,
 *                  gpio_chip.label, ...). NUL-terminated; valid for the
 *                  channel's full lifetime.
 * @fwnode:         Firmware node describing this channel (i2c-adapter,
 *                  gpio-chip, spi-controller, ipmi label, ...). NULL if no
 *                  firmware match.
 * @dev:            Stable struct device pointer for dev_*() / devm_*();
 *                  points at the underlying USB interface device.
 * @max_tx_payload: Largest LSTP request payload (excluding the header)
 *                  that fits in one bulk-out URB on this channel.
 *                  Per-channel constant.
 * @max_rx_payload: Largest LSTP response payload (excluding the header)
 *                  that fits in one bulk-in URB on this channel.
 *                  Per-channel constant.
 * @priv:           Subsystem-owned private data, allocated by the subsystem
 *                  in its channel_init(). Opaque to the framework
 *                  (e.g. i2c_adapter, gpio_chip).
 *
 * Framework-private state lives in the container that wraps this struct;
 * subsystems see only the fields documented above.
 */
struct lstp_channel {
	u8 ch_id;
	char display_name[LSTP_DISPLAY_NAME_LEN];
	struct fwnode_handle *fwnode;
	struct device *dev;
	size_t max_tx_payload;
	size_t max_rx_payload;
	void *priv;
};

/**
 * struct lstp_channel_init_info - Per-call data passed to channel_init().
 * @config:     Subsystem-specific config blob (e.g. struct lstp_spi_config),
 *              pointing into the framework's ch0 READ_CONFIG scratch.
 *              The framework does not validate its contents; subsystems
 *              MUST gate any access on @config_len before dereferencing.
 * @config_len: On-wire blob length in bytes (may be 0).
 *
 * Both fields are valid only for the duration of channel_init();
 * subsystems that need to retain data must copy.
 */
struct lstp_channel_init_info {
	const void *config;
	size_t config_len;
};

/*
 * Subsystem registration table. Each sub-component defines its own
 * descriptor via LSTP_SUBSYS() at file scope; lstp-main.c collects them
 * into a static array (lstp_subsystems[]) and drives module lifecycle
 * and per-channel dispatch from it.
 *
 * Required (positional macro args):
 *   _tag / channel_type / channel_init / channel_start
 *                         Per-channel dispatch for LSTP_CHANNEL_TYPE_*.
 * Optional (designated initializers in ...):
 *   .fwnode_compatible    Firmware node matching.
 *   .irq_callback         Handler for unsolicited LSTP requests on this
 *                         subsystem's channels, invoked from the USB RX
 *                         completion path (atomic context).
 *   .channel_stop         Undoes channel_start(); invoked only after
 *                         channel_start() returned success. Use it to
 *                         quiesce activity that depends on the LSTP device
 *                         still being reachable
 *                         (unregister userspace-facing nodes, drop refs the
 *                         device side holds, etc.). Resources owned by the
 *                         channel itself -- allocations, workqueues, IRQ
 *                         registrations, gpiochip/tty/etc. add_data calls --
 *                         should be devres-managed instead, so they:
 *                           - clean up on channel_init/start failure too,
 *                             where channel_stop never runs, and
 *                           - benefit from devres LIFO ordering vs. other
 *                             devres cleanups.
 *   .init / .exit         Module-level hooks.
 */
struct lstp_subsys {
	const char *name;

	u8 channel_type;
	const char *fwnode_compatible;

	lstp_irq_callback irq_callback;

	int (*channel_init)(struct lstp_channel *ch, const struct lstp_channel_init_info *info);
	int (*channel_start)(struct lstp_channel *ch);
	void (*channel_stop)(struct lstp_channel *ch);

	int (*init)(void);
	void (*exit)(void);
};

/*
 * LSTP_SUBSYS() emits a single externally-visible descriptor named
 * lstp_<tag>_subsys. lstp-main.c declares matching externs via
 * LSTP_SUBSYS_DECLARE() and pulls them into lstp_subsystems[] via
 * LSTP_SUBSYS_REF(). Adding a new channel type therefore requires one
 * entry in that central array in addition to the per-file LSTP_SUBSYS()
 * definition -- intentional visibility for maintainers.
 */
/* clang-format off */
#define LSTP_SUBSYS(_tag, _ch_type, _init, _start, ...)                      \
	static_assert((_ch_type) > LSTP_CHANNEL_TYPE_MGMT &&                 \
		      (_ch_type) < LSTP_CHANNEL_TYPE_MAX,                    \
		      #_tag ": channel_type out of range");                  \
	const struct lstp_subsys lstp_##_tag##_subsys = {                    \
		.name = #_tag,                                               \
		.channel_type = (_ch_type),                                  \
		.channel_init = (_init),                                     \
		.channel_start = (_start),                                   \
		__VA_ARGS__                                                  \
	}
/* clang-format on */

/* Companions to LSTP_SUBSYS(): declare the extern / take its address by tag. */
#define LSTP_SUBSYS_DECLARE(_tag) extern const struct lstp_subsys lstp_##_tag##_subsys
#define LSTP_SUBSYS_REF(_tag) (&lstp_##_tag##_subsys)

/* Subsystem dispatch */
const struct lstp_subsys *lstp_subsys_by_channel_type(u8 channel_type);

/* Module parameters */
extern bool lstp_auto_bind_spidev;

/* Channel state probe */
bool lstp_channel_disconnected(const struct lstp_channel *ch);

/* USB I/O helpers: bulk-out send and request/response exchanges */
int lstp_send(struct lstp_channel *ch, u8 cmd, const void *payload, size_t len);

int lstp_request(struct lstp_channel *ch, u8 cmd, const void *req, size_t req_len, void *resp,
		 size_t resp_cap, size_t *resp_len, int *lstp_status);

int lstp_requestv(struct lstp_channel *ch, u8 cmd, const struct kvec *vecs, size_t nvecs,
		  void *resp, size_t resp_cap, size_t *resp_len, int *lstp_status);

/* Unsolicited-request response (atomic context, called from irq_callback) */
void lstp_send_irq_resp(struct lstp_channel *ch, u8 status);

/* ch0 READ_CONFIG helpers (lstp_request-based) */
int lstp_ch0_read_config(struct lstp_channel *ch, u16 offset, u16 length,
			 struct lstp_ch0_read_resp **resp_out, size_t *len_out, int *lstp_status);

typedef int (*lstp_config_entry_fn)(struct lstp_channel *ch, unsigned int entry_idx,
				    const void *entry, void *entry_ctx);
int lstp_read_config_table(struct lstp_channel *ch, size_t config_head_size,
			   size_t config_entry_size, unsigned int total_entries,
			   lstp_config_entry_fn entry_fn, void *entry_ctx);

/* Subsystem-side device pin (compat scaffolding; see definition) */
void deprecated_lstp_channel_publish_child_dev(struct lstp_channel *ch, struct device *child_dev);

#endif
