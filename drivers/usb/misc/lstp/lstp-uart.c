// SPDX-License-Identifier: GPL-2.0-only
/*
 * UART driver for LSTP USB interface.
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
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/serial.h>
#include <linux/termios.h>
#include <linux/tty.h>
#include <linux/tty_buffer.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>
#include <linux/xarray.h>

#include "lstp-main.h"

/*****************************************************************************
 * Protocol constants
 *****************************************************************************/

enum lstp_uart_cmd {
	LSTP_UART_CMD_WRITE = 0x00,
};

struct lstp_uart_config {
	__le32 speed;
	u8 data_bits;
	u8 stop_bits;
	u8 parity_flow; /* [3:0] parity, [7:4] flow control */
} __packed;

#define LSTP_UART_CFG_PARITY(pf) ((pf) & 0x0F)
#define LSTP_UART_CFG_FLOW(pf) (((pf) >> 4) & 0x0F)

enum lstp_uart_parity {
	LSTP_UART_PARITY_NONE = 0,
	LSTP_UART_PARITY_ODD = 1,
	LSTP_UART_PARITY_EVEN = 2,
	LSTP_UART_PARITY_MARK = 3,
	LSTP_UART_PARITY_SPACE = 4,
};

enum lstp_uart_flow {
	LSTP_UART_FLOW_NONE = 0,
	LSTP_UART_FLOW_XONXOFF = 1,
	LSTP_UART_FLOW_RTSCTS = 2,
	LSTP_UART_FLOW_DTRDSR = 3,
};

/* clang-format off */

/* Tag bits OR'd into the WRITE command byte. */
#define LSTP_UART_TAG_CARRIER_DOWN BIT(6) /* dev→host: carrier lost */
#define LSTP_UART_TAG_TX_OVERRUN   BIT(5) /* dev→host: TX data dropped */
#define LSTP_UART_TAG_BREAK_DET    BIT(4) /* dev→host: break detected */
#define LSTP_UART_TAG_GEN_BREAK    BIT(3) /* host→dev: send break */

/* clang-format on */

/* Bits [1:0] = command; [6:2] = tags; [7] = req/resp flag. */
#define LSTP_UART_CMD_MASK GENMASK(1, 0)

/*
 * NACK retry: firmware NACKs when its TX FIFO is full.
 * 5 × 10 ms covers one drain cycle at 115200 baud (~43 ms / 500 bytes).
 */
#define LSTP_UART_NAK_MAX_RETRIES 5
#define LSTP_UART_NAK_RETRY_DELAY_MS 10

#define LSTP_UART_MINORS 256

/*****************************************************************************
 * Per-channel context
 *****************************************************************************/

/*
 * TX uses two-stage coalescing:
 *
 *   write() --> [ coal_buf ] --drain--> [ tx_pkt ] --USB--> device
 *
 * write() appends to coal_buf and schedules write_work. The USB
 * round-trip (~1 ms) acts as the natural coalescing window — while
 * a TX is in-flight, further writes accumulate for the next batch.
 */
struct lstp_uart_ctx {
	struct tty_port port;
	struct lstp_channel *ch;
	int minor;
	size_t max_payload;
	tcflag_t hw_cflag;
	tcflag_t hw_iflag;

	spinlock_t write_lock; /* protects all fields below */
	u8 *coal_buf;
	u8 *tx_snapshot; /* stable copy handed to lstp_request() */
	size_t coal_len;
	size_t tx_inflight_len;
	bool tx_in_flight;
	struct work_struct write_work;

	struct serial_icounter_struct iocount; /* per-field single-writer */
};

static struct tty_driver *lstp_tty_driver;

static DEFINE_XARRAY_ALLOC(lstp_minors);
static DEFINE_MUTEX(lstp_minors_lock);

/*****************************************************************************
 * Minor number management
 *****************************************************************************/

static int lstp_alloc_minor(struct lstp_channel *ch)
{
	u32 minor;
	int ret;

	guard(mutex)(&lstp_minors_lock);
	ret = xa_alloc(&lstp_minors, &minor, ch, XA_LIMIT(0, LSTP_UART_MINORS - 1), GFP_KERNEL);

	return ret ? ret : minor;
}

/*
 * Look up a live channel by minor and take a tty_port reference.
 * Returns NULL if the minor is unregistered or the channel disconnected.
 */
static struct lstp_channel *lstp_get_by_minor(unsigned int minor)
{
	struct lstp_uart_ctx *ctx;
	struct lstp_channel *ch;

	guard(mutex)(&lstp_minors_lock);
	ch = xa_load(&lstp_minors, minor);
	if (!ch)
		return NULL;

	ctx = ch->priv;
	if (!ctx || lstp_channel_disconnected(ch))
		return NULL;

	tty_port_get(&ctx->port);
	return ch;
}

/*****************************************************************************
 * Firmware config → termios helpers
 *****************************************************************************/

/* clang-format off */
static speed_t lstp_baud_to_speed(u32 baud)
{
	static const struct {
		u32     baud;
		speed_t speed;
	} map[] = {
		{      50, B50      }, {      75, B75      }, {     110, B110     },
		{     134, B134     }, {     150, B150     }, {     200, B200     },
		{     300, B300     }, {     600, B600     }, {    1200, B1200    },
		{    1800, B1800    }, {    2400, B2400    }, {    4800, B4800    },
		{    9600, B9600    }, {   19200, B19200   }, {   38400, B38400   },
		{   57600, B57600   }, {  115200, B115200  }, {  230400, B230400  },
		{  460800, B460800  }, {  500000, B500000  }, {  576000, B576000  },
		{  921600, B921600  }, { 1000000, B1000000 }, { 1152000, B1152000 },
		{ 1500000, B1500000 }, { 2000000, B2000000 }, { 2500000, B2500000 },
		{ 3000000, B3000000 }, { 3500000, B3500000 }, { 4000000, B4000000 },
	};

	for (size_t i = 0; i < ARRAY_SIZE(map); i++)
		if (map[i].baud == baud)
			return map[i].speed;

	return B0;
}

/* clang-format on */

static tcflag_t lstp_build_cflag(const struct lstp_uart_config *cfg)
{
	tcflag_t cflag = CREAD | HUPCL | CLOCAL;
	u8 parity = LSTP_UART_CFG_PARITY(cfg->parity_flow);
	u8 flow = LSTP_UART_CFG_FLOW(cfg->parity_flow);

	cflag |= lstp_baud_to_speed(le32_to_cpu(cfg->speed));

	switch (cfg->data_bits) {
	case 5:
		cflag |= CS5;
		break;
	case 6:
		cflag |= CS6;
		break;
	case 7:
		cflag |= CS7;
		break;
	default:
		cflag |= CS8;
		break;
	}

	if (cfg->stop_bits == 2)
		cflag |= CSTOPB;

	switch (parity) {
	case LSTP_UART_PARITY_ODD:
		cflag |= PARENB | PARODD;
		break;
	case LSTP_UART_PARITY_EVEN:
		cflag |= PARENB;
		break;
	case LSTP_UART_PARITY_MARK:
		cflag |= PARENB | PARODD | CMSPAR;
		break;
	case LSTP_UART_PARITY_SPACE:
		cflag |= PARENB | CMSPAR;
		break;
	}

	if (flow == LSTP_UART_FLOW_RTSCTS)
		cflag |= CRTSCTS;

	return cflag;
}

static tcflag_t lstp_build_iflag(const struct lstp_uart_config *cfg)
{
	if (LSTP_UART_CFG_FLOW(cfg->parity_flow) == LSTP_UART_FLOW_XONXOFF)
		return IXON | IXOFF;
	return 0;
}

static int lstp_uart_parse_config(struct lstp_uart_ctx *ctx, struct lstp_channel *ch,
				  const struct lstp_uart_config *cfg)
{
	ctx->hw_cflag = lstp_build_cflag(cfg);
	ctx->hw_iflag = lstp_build_iflag(cfg);

	{
		static const char parity_ch[] = "NOEMS";
		u8 p = LSTP_UART_CFG_PARITY(cfg->parity_flow);

		dev_info(ch->dev, "%s: ch_%d: %u baud, %u%c%c, parity %u, flow %u\n", __func__,
			 ch->ch_id, le32_to_cpu(cfg->speed), cfg->data_bits,
			 cfg->stop_bits == 2 ? '2' : '1',
			 p < sizeof(parity_ch) - 1 ? parity_ch[p] : '?', p,
			 LSTP_UART_CFG_FLOW(cfg->parity_flow));
	}

	return 0;
}

/*****************************************************************************
 * TX path
 *****************************************************************************/

static int lstp_uart_send_with_retry(struct lstp_uart_ctx *ctx, u8 cmd, const void *payload,
				     size_t len)
{
	struct lstp_channel *ch = ctx->ch;
	int lstp_status = LSTP_NACK;
	int ret = 0;
	int attempt;

	for (attempt = 0; lstp_status == LSTP_NACK && attempt < LSTP_UART_NAK_MAX_RETRIES;
	     attempt++) {
		if (attempt)
			fsleep(LSTP_UART_NAK_RETRY_DELAY_MS * USEC_PER_MSEC);

		ret = lstp_request(ch, cmd, payload, len, NULL, 0, NULL, &lstp_status);
	}

	if (ret)
		dev_warn(ch->dev, "%s: ch_%d: Failed to write after %d attempt(s) (%pe)\n",
			 __func__, ch->ch_id, attempt, ERR_PTR(ret));

	return ret;
}

/*
 * Drain coal_buf into one LSTP WRITE, send over USB, reschedule if
 * new data arrived during the round-trip. tx_snapshot is a private,
 * single-writer buffer (write_work only) so it stays stable across
 * the retry loop while lstp_tty_write() keeps appending to coal_buf.
 */
static void lstp_uart_write_work(struct work_struct *work)
{
	struct lstp_uart_ctx *ctx = container_of(work, struct lstp_uart_ctx, write_work);
	size_t len;
	int ret;

	scoped_guard(spinlock_irqsave, &ctx->write_lock) {
		len = ctx->coal_len;
		if (len == 0)
			return;
		memcpy(ctx->tx_snapshot, ctx->coal_buf, len);
		ctx->coal_len = 0;
		ctx->tx_in_flight = true;
		ctx->tx_inflight_len = len;
	}

	tty_port_tty_wakeup(&ctx->port);

	ret = lstp_uart_send_with_retry(ctx, LSTP_UART_CMD_WRITE, ctx->tx_snapshot, len);

	scoped_guard(spinlock_irqsave, &ctx->write_lock) {
		ctx->tx_in_flight = false;
		if (!ret)
			ctx->iocount.tx += len;
		if (ctx->coal_len > 0)
			schedule_work(&ctx->write_work);
	}

	tty_port_tty_wakeup(&ctx->port);
}

/*****************************************************************************
 * RX path
 *****************************************************************************/

/**
 * lstp_uart_irq_callback() - Push unsolicited UART RX bytes into the TTY layer.
 * @ch:  LSTP channel that received the request.
 * @pkt: Received LSTP packet (header + payload).
 *
 * Push RX bytes into the TTY flip buffer. NACK if the buffer is full
 * so firmware retries. Serialized by irq_buffer_lock in the USB RX
 * callback — no local locking needed.
 */
static void lstp_uart_irq_callback(struct lstp_channel *ch, struct lstp_packet *pkt)
{
	struct lstp_uart_ctx *ctx = ch->priv;
	u16 rx_len = le16_to_cpu(pkt->hdr.length);
	u8 cmd = pkt->hdr.cmd;
	bool have_break = cmd & LSTP_UART_TAG_BREAK_DET;
	bool carrier_down = cmd & LSTP_UART_TAG_CARRIER_DOWN;
	bool tx_overrun = cmd & LSTP_UART_TAG_TX_OVERRUN;
	size_t need_room = rx_len + (have_break ? 1 : 0);
	u8 status = LSTP_SUCCESS;
	size_t room;

	if ((cmd & LSTP_UART_CMD_MASK) != LSTP_UART_CMD_WRITE) {
		dev_warn_ratelimited(ch->dev, "%s: ch_%d: unexpected UART command 0x%02x\n",
				     __func__, ch->ch_id, cmd);
		lstp_send_irq_resp(ch, LSTP_NOT_SUPP);
		return;
	}

	room = tty_buffer_request_room(&ctx->port, need_room);
	if (room < need_room) {
		ctx->iocount.buf_overrun++;
		status = LSTP_NACK;
	} else {
		if (have_break) {
			ctx->iocount.brk++;
			tty_insert_flip_char(&ctx->port, 0, TTY_BREAK);
		}
		if (rx_len) {
			tty_insert_flip_string(&ctx->port, pkt->payload, rx_len);
			ctx->iocount.rx += rx_len;
		}
		tty_flip_buffer_push(&ctx->port);
	}

	if (tx_overrun) {
		ctx->iocount.overrun++;
		dev_warn_ratelimited(ch->dev,
				     "%s: ch_%d: RX overrun on link (firmware dropped bytes)\n",
				     __func__, ch->ch_id);
	}

	if (carrier_down) {
		ctx->iocount.dcd++;
		/* Honors CLOCAL: no-op when userspace asked to ignore carrier. */
		tty_port_tty_hangup(&ctx->port, true);
	}

	lstp_send_irq_resp(ch, status);
}

/*****************************************************************************
 * TTY port operations
 *****************************************************************************/

static int lstp_port_activate(struct tty_port *port, struct tty_struct *tty)
{
	struct lstp_uart_ctx *ctx = container_of(port, struct lstp_uart_ctx, port);

	tty->termios.c_cflag = ctx->hw_cflag;
	tty->termios.c_iflag = ctx->hw_iflag;

	/* Let N_TTY pass large writes through instead of byte-at-a-time. */
	set_bit(TTY_NO_WRITE_SPLIT, &tty->flags);
	return 0;
}

static void lstp_port_shutdown(struct tty_port *port)
{
	struct lstp_uart_ctx *ctx = container_of(port, struct lstp_uart_ctx, port);

	cancel_work_sync(&ctx->write_work);
}

static void lstp_port_destruct(struct tty_port *port)
{
	struct lstp_uart_ctx *ctx = container_of(port, struct lstp_uart_ctx, port);

	if (ctx->minor >= 0) {
		scoped_guard(mutex, &lstp_minors_lock)
			xa_erase(&lstp_minors, ctx->minor);
	}
	kfree(ctx->tx_snapshot);
	kfree(ctx->coal_buf);
	kfree(ctx);
}

static const struct tty_port_operations lstp_port_ops = {
	.activate = lstp_port_activate,
	.shutdown = lstp_port_shutdown,
	.destruct = lstp_port_destruct,
};

/*****************************************************************************
 * TTY operations
 *****************************************************************************/

static int lstp_tty_install(struct tty_driver *driver, struct tty_struct *tty)
{
	struct lstp_channel *ch = lstp_get_by_minor(tty->index);
	struct lstp_uart_ctx *ctx;
	int ret;

	if (!ch)
		return -ENODEV;

	ctx = ch->priv;
	ret = tty_standard_install(driver, tty);
	if (ret) {
		tty_port_put(&ctx->port);
		return ret;
	}

	tty->driver_data = ch;
	return 0;
}

static int lstp_tty_open(struct tty_struct *tty, struct file *filp)
{
	return tty_port_open(tty->port, tty, filp);
}

static void lstp_tty_close(struct tty_struct *tty, struct file *filp)
{
	tty_port_close(tty->port, tty, filp);
}

static void lstp_tty_hangup(struct tty_struct *tty)
{
	tty_port_hangup(tty->port);
}

static void lstp_tty_cleanup(struct tty_struct *tty)
{
	tty_port_put(tty->port);
}

static ssize_t lstp_tty_write(struct tty_struct *tty, const unsigned char *buf, size_t count)
{
	struct lstp_channel *ch = tty->driver_data;
	struct lstp_uart_ctx *ctx = ch->priv;
	size_t room;

	if (!count)
		return 0;

	guard(spinlock_irqsave)(&ctx->write_lock);

	if (lstp_channel_disconnected(ch))
		return -EIO;

	room = ctx->max_payload - ctx->coal_len;
	if (!room)
		return 0;

	count = min(count, room);
	memcpy(ctx->coal_buf + ctx->coal_len, buf, count);
	ctx->coal_len += count;

	schedule_work(&ctx->write_work);

	return count;
}

static unsigned int lstp_tty_write_room(struct tty_struct *tty)
{
	struct lstp_channel *ch = tty->driver_data;
	struct lstp_uart_ctx *ctx = ch->priv;

	guard(spinlock_irqsave)(&ctx->write_lock);

	if (lstp_channel_disconnected(ch))
		return 0;
	return ctx->max_payload - ctx->coal_len;
}

static unsigned int lstp_tty_chars_in_buffer(struct tty_struct *tty)
{
	struct lstp_channel *ch = tty->driver_data;
	struct lstp_uart_ctx *ctx = ch->priv;
	unsigned int count;

	guard(spinlock_irqsave)(&ctx->write_lock);

	if (lstp_channel_disconnected(ch))
		return 0;
	count = ctx->coal_len;
	if (ctx->tx_in_flight)
		count += ctx->tx_inflight_len;
	return count;
}

static void lstp_tty_flush_buffer(struct tty_struct *tty)
{
	struct lstp_channel *ch = tty->driver_data;
	struct lstp_uart_ctx *ctx = ch->priv;

	scoped_guard(spinlock_irqsave, &ctx->write_lock)
		ctx->coal_len = 0;
	/* Does not cancel an already in-flight TX. */
	cancel_work(&ctx->write_work);
}

/*
 * Firmware config is fixed; preserve hw-set bits on userspace stty.
 *
 * tty_termios_copy_hw() restores c_cflag hardware bits and speeds
 * but leaves c_iflag untouched — restore flow-control bits manually.
 */
static void lstp_tty_set_termios(struct tty_struct *tty, const struct ktermios *old_termios)
{
	struct lstp_channel *ch = tty->driver_data;
	struct lstp_uart_ctx *ctx = ch->priv;

	tty_termios_copy_hw(&tty->termios, old_termios);

	/* XON/XOFF is a hardware property of the link — don't let stty change it. */
	tty->termios.c_iflag &= ~(IXON | IXOFF | IXANY);
	tty->termios.c_iflag |= ctx->hw_iflag & (IXON | IXOFF | IXANY);
}

/*
 * Firmware fires a fixed-duration break; continuous-break semantics
 * collapse to "fire on any non-zero state" (matching cdc-acm / ftdi_sio).
 */
static int lstp_tty_break_ctl(struct tty_struct *tty, int state)
{
	struct lstp_channel *ch = tty->driver_data;
	struct lstp_uart_ctx *ctx = ch->priv;

	if (!state)
		return 0;

	return lstp_uart_send_with_retry(ctx, LSTP_UART_CMD_WRITE | LSTP_UART_TAG_GEN_BREAK, NULL,
					 0);
}

static int lstp_tty_get_icount(struct tty_struct *tty, struct serial_icounter_struct *icount)
{
	struct lstp_channel *ch = tty->driver_data;
	struct lstp_uart_ctx *ctx = ch->priv;

	*icount = ctx->iocount;
	return 0;
}

static const struct tty_operations lstp_ops = {
	.install = lstp_tty_install,
	.open = lstp_tty_open,
	.close = lstp_tty_close,
	.cleanup = lstp_tty_cleanup,
	.hangup = lstp_tty_hangup,
	.write = lstp_tty_write,
	.write_room = lstp_tty_write_room,
	.chars_in_buffer = lstp_tty_chars_in_buffer,
	.flush_buffer = lstp_tty_flush_buffer,
	.set_termios = lstp_tty_set_termios,
	.break_ctl = lstp_tty_break_ctl,
	.get_icount = lstp_tty_get_icount,
};

/*****************************************************************************
 * Device lifecycle
 *****************************************************************************/

static void lstp_uart_port_put(void *data)
{
	tty_port_put(data);
}

/**
 * lstp_uart_init() - Initialize an LSTP UART channel.
 * @ch:   LSTP channel to initialize as UART
 * @info: config blob (struct lstp_uart_config)
 *
 * Sets up the tty_port, coalescing buffer, and minor number.
 *
 * Context: Process context. Called during probe before RX URB is active.
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_uart_init(struct lstp_channel *ch, const struct lstp_channel_init_info *info)
{
	struct lstp_uart_ctx *ctx;
	int ret;

	if (info->config_len < sizeof(struct lstp_uart_config)) {
		dev_err(ch->dev, "%s: ch_%d: UART config too short: %zu < %zu\n", __func__,
			ch->ch_id, info->config_len, sizeof(struct lstp_uart_config));
		return -EINVAL;
	}

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return -ENOMEM;

	tty_port_init(&ctx->port);
	ctx->port.ops = &lstp_port_ops;
	ctx->minor = -1;
	ctx->max_payload = ch->max_tx_payload;
	spin_lock_init(&ctx->write_lock);

	ret = devm_add_action_or_reset(ch->dev, lstp_uart_port_put, &ctx->port);
	if (ret)
		return ret;

	ret = lstp_uart_parse_config(ctx, ch, info->config);
	if (ret)
		return ret;

	ctx->coal_buf = kzalloc(ctx->max_payload, GFP_KERNEL);
	if (!ctx->coal_buf)
		return -ENOMEM;

	ctx->tx_snapshot = kzalloc(ctx->max_payload, GFP_KERNEL);
	if (!ctx->tx_snapshot)
		return -ENOMEM;

	ret = lstp_alloc_minor(ch);
	if (ret < 0) {
		dev_err(ch->dev, "%s: ch_%d: Failed to allocate minor (%pe)\n", __func__, ch->ch_id,
			ERR_PTR(ret));
		return ret;
	}
	ctx->minor = ret;

	INIT_WORK(&ctx->write_work, lstp_uart_write_work);
	ctx->ch = ch;
	ch->priv = ctx;

	dev_info(ch->dev, "%s: ch_%d: Initialized\n", __func__, ch->ch_id);
	return 0;
}

/**
 * lstp_uart_start() - Register the TTY device for an LSTP UART channel.
 * @ch: LSTP channel (must have been successfully initialized)
 *
 * Context: Process context. Called during probe after RX URB is active.
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_uart_start(struct lstp_channel *ch)
{
	struct lstp_uart_ctx *ctx = ch->priv;
	struct device *tty_dev;

	tty_dev = tty_port_register_device(&ctx->port, lstp_tty_driver, ctx->minor, ch->dev);
	if (IS_ERR(tty_dev)) {
		dev_err(ch->dev, "%s: ch_%d: Failed to register TTY (%pe)\n", __func__, ch->ch_id,
			tty_dev);
		return PTR_ERR(tty_dev);
	}

	if (ch->fwnode)
		device_set_node(tty_dev, ch->fwnode);

	deprecated_lstp_channel_publish_child_dev(ch, tty_dev);

	dev_info(ch->dev, "%s: ch_%d: Started as %s\n", __func__, ch->ch_id, ch->display_name);
	return 0;
}

/**
 * lstp_uart_stop() - Hang up the tty and unregister the device node.
 * @ch: LSTP channel previously started by lstp_uart_start()
 *
 * ctx/coal_buf/minor are released later via the devres-registered
 * tty_port_put() once the tty layer drops its last reference.
 */
static void lstp_uart_stop(struct lstp_channel *ch)
{
	struct lstp_uart_ctx *ctx = ch->priv;
	struct tty_struct *tty;

	tty = tty_port_tty_get(&ctx->port);
	if (tty) {
		/*
		 * Synchronously quiesces the tty: blocks new userspace writes,
		 * waits for in-flight ones, and runs lstp_port_shutdown() which
		 * drains ctx->write_work. After this no further write
		 * submissions can outrun teardown.
		 */
		tty_vhangup(tty);
		tty_kref_put(tty);
	}

	tty_unregister_device(lstp_tty_driver, ctx->minor);
}

/*****************************************************************************
 * Module-level TTY driver registration
 *****************************************************************************/

static int __init lstp_uart_driver_init(void)
{
	int ret;

	lstp_tty_driver =
		tty_alloc_driver(LSTP_UART_MINORS, TTY_DRIVER_REAL_RAW | TTY_DRIVER_DYNAMIC_DEV);
	if (IS_ERR(lstp_tty_driver))
		return PTR_ERR(lstp_tty_driver);

	lstp_tty_driver->driver_name = "lstp";
	lstp_tty_driver->name = "ttyLSTP";
	lstp_tty_driver->major = 0;
	lstp_tty_driver->minor_start = 0;
	lstp_tty_driver->type = TTY_DRIVER_TYPE_SERIAL;
	lstp_tty_driver->subtype = SERIAL_TYPE_NORMAL;
	lstp_tty_driver->init_termios = tty_std_termios;
	/* Overridden per-device in port_activate; this is the visible default. */
	lstp_tty_driver->init_termios.c_cflag = B115200 | CS8 | CREAD | HUPCL | CLOCAL;
	tty_set_operations(lstp_tty_driver, &lstp_ops);

	ret = tty_register_driver(lstp_tty_driver);
	if (ret) {
		tty_driver_kref_put(lstp_tty_driver);
		return ret;
	}

	return 0;
}

static void lstp_uart_driver_exit(void)
{
	tty_unregister_driver(lstp_tty_driver);
	tty_driver_kref_put(lstp_tty_driver);
	xa_destroy(&lstp_minors);
}

/* clang-format off */
LSTP_SUBSYS(uart, LSTP_CHANNEL_TYPE_UART, lstp_uart_init, lstp_uart_start,
	    .fwnode_compatible = "nvidia,lstp-uart",
	    .irq_callback = lstp_uart_irq_callback,
	    .channel_stop = lstp_uart_stop,
	    .init = lstp_uart_driver_init,
	    .exit = lstp_uart_driver_exit,
);
/* clang-format on */
