// SPDX-License-Identifier: GPL-2.0-only
/*
 * IPMI driver for LSTP USB interface.
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

#include <linux/poll.h>
#include <linux/err.h>
#include <linux/miscdevice.h>
#include <linux/kfifo.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/slab.h>

#include "lstp-main.h"
#include "lstp-ipmi-postcodes.h"

/*
 * Byte capacity of the pending-request fifo. One PAGE_SIZE-equivalent
 * allocation: cheap from the buddy allocator, and at typical OpenBMC IPMI
 * rates (~100 req/s, ~25 B avg payload) it absorbs ~1 s of userspace
 * stall before drop-oldest kicks in -- around the host's IPMI retry
 * timeout, so deeper buffering would just queue stale work.
 */
#define BUFFER_SIZE 4096

static DEFINE_IDA(lstp_ipmi_ida);

/* IPMI message constants and structures */

#define IPMI_LSTP_PAYLOAD_MAX 254
#define IPMI_MIN_MSG_LEN 2 /* netfn/lun + cmd */

struct ipmi_lstp_msg_header {
	unsigned int len;
	u8 msg_num;
} __packed;

struct ipmi_lstp_msg {
	struct ipmi_lstp_msg_header header;
	__u8 payload[IPMI_LSTP_PAYLOAD_MAX];
};

/**
 * struct lstp_ipmi_ctx - Per-channel IPMI userspace state.
 * @kref:      Refcount. Open fds and the channel's devres action each hold
 *             one, so @ctx outlives disconnect while any fd is open.
 * @ch:        Owning channel. Freed by devres after disconnect, before
 *             @ctx; only safe to dereference under @tx_mutex while
 *             @stopped is clear.
 * @miscdev:   /dev/ipmi-lstpN node. Lifecycle managed via devres (see
 *             lstp_ipmi_stop_and_deregister()), independent of @kref.
 * @ida_id:    Auto-generated name suffix, or -1 if a firmware "label"
 *             supplied the name.
 * @running:   Exclusive-open flag. Protected by @lock.
 * @stopped:   Disconnect-quiesce flag. Set under both @tx_mutex and @lock.
 *             Distinct from the framework's disconnect flag (read via
 *             lstp_channel_disconnected()).
 * @tx_mutex:  Serializes lstp_ipmi_write() against lstp_ipmi_stop().
 *             Owned by @ctx (kref-pinned) rather than @ch -- see the
 *             rationale in lstp_ipmi_write().
 * @lock:      Serializes @running, @msg_count and the @fifo producer/
 *             consumer paths. Held only across kfifo_in / kfifo_out;
 *             copy_to_user() in lstp_ipmi_read() runs after the unlock.
 * @req_wq:    Wait queue for blocked readers / pollers.
 * @fifo:      Inbound IPMI requests pending read(), one variable-size
 *             record per message (2-byte length prefix per record).
 *             Drops oldest records on overflow until the new one fits.
 * @msg_count: Per-message tag echoed back on write() to drop responses
 *             to stale requests.
 * @postcodes: Embedded postcodes sub-device.
 */
struct lstp_ipmi_ctx {
	struct kref kref;
	struct lstp_channel *ch;
	struct miscdevice miscdev;
	int ida_id;
	bool running;
	bool stopped;
	struct mutex tx_mutex; /* serializes write() vs lstp_ipmi_stop() */
	spinlock_t lock; /* protects @running, @msg_count, @fifo */
	wait_queue_head_t req_wq;
	struct kfifo_rec_ptr_2 fifo;
	u8 msg_count;
	struct lstp_ipmi_postcodes postcodes;
};

enum lstp_ipmi_cmd {
	LSTP_IPMI_CMD_MESSAGE = 0x00,
};

/*******************************************************************************
 * Lifetime management
 ******************************************************************************/

/**
 * lstp_ipmi_stopped() - Test whether the IPMI channel has been quiesced.
 * @ctx: IPMI context
 *
 * Return: true after lstp_ipmi_quiesce() has set @stopped.
 */
static inline bool lstp_ipmi_stopped(struct lstp_ipmi_ctx *ctx)
{
	/* Pairs with smp_store_release() in lstp_ipmi_quiesce(). */
	return smp_load_acquire(&ctx->stopped);
}

/**
 * lstp_ipmi_readable() - wait_event condition for lstp_ipmi_read().
 * @ctx: IPMI context
 *
 * Return: true when the FIFO has data or the channel is stopped.
 */
static inline bool lstp_ipmi_readable(struct lstp_ipmi_ctx *ctx)
{
	return !kfifo_is_empty(&ctx->fifo) || lstp_ipmi_stopped(ctx);
}

/**
 * lstp_ipmi_ctx_release() - kref release callback for @ctx.
 * @kref: kref embedded in &struct lstp_ipmi_ctx
 *
 * Frees @ctx-owned resources once the last open fd and devres ref drop.
 */
static void lstp_ipmi_ctx_release(struct kref *kref)
{
	struct lstp_ipmi_ctx *ctx = container_of(kref, struct lstp_ipmi_ctx, kref);

	lstp_ipmi_postcodes_destroy(&ctx->postcodes);
	kfifo_free(&ctx->fifo);
	if (ctx->ida_id >= 0)
		ida_free(&lstp_ipmi_ida, ctx->ida_id);
	kfree(ctx->miscdev.name);
	mutex_destroy(&ctx->tx_mutex);
	kfree(ctx);
}

/**
 * lstp_ipmi_ctx_get() - Acquire a reference on @ctx.
 * @ctx: IPMI context
 */
static void lstp_ipmi_ctx_get(struct lstp_ipmi_ctx *ctx)
{
	kref_get(&ctx->kref);
}

/**
 * lstp_ipmi_ctx_put() - Release a reference on @ctx.
 * @ctx: IPMI context
 *
 * May invoke lstp_ipmi_ctx_release() when the refcount reaches zero.
 */
static void lstp_ipmi_ctx_put(struct lstp_ipmi_ctx *ctx)
{
	kref_put(&ctx->kref, lstp_ipmi_ctx_release);
}

/**
 * lstp_ipmi_ctx_get_cb() - void * trampoline for lstp_ipmi_ctx_get().
 * @data: &struct lstp_ipmi_ctx
 */
static void lstp_ipmi_ctx_get_cb(void *data)
{
	lstp_ipmi_ctx_get(data);
}

/**
 * lstp_ipmi_ctx_put_cb() - void * trampoline for lstp_ipmi_ctx_put().
 * @data: &struct lstp_ipmi_ctx
 *
 * Devres action that drops the channel's initial kref from lstp_ipmi_init().
 */
static void lstp_ipmi_ctx_put_cb(void *data)
{
	lstp_ipmi_ctx_put(data);
}

/*******************************************************************************
 * Helper functions
 ******************************************************************************/

/**
 * to_ctx() - Get IPMI context from file pointer.
 * @file: File pointer from file operations
 *
 * Retrieves the lstp_ipmi_ctx structure from the file's private_data
 * using container_of on the embedded miscdevice.
 *
 * Context: Any context.
 *
 * Return: Pointer to the lstp_ipmi_ctx structure
 */
static inline struct lstp_ipmi_ctx *to_ctx(struct file *file)
{
	return container_of(file->private_data, struct lstp_ipmi_ctx, miscdev);
}

/*******************************************************************************
 * Character device file operations
 ******************************************************************************/

/**
 * lstp_ipmi_open() - Open the IPMI character device.
 * @inode: Unused
 * @file:  File for the opened device
 *
 * Exclusive-open. Bumps @ctx->kref so the fd can outlive disconnect, and
 * rejects the post-stop / pre-misc_deregister window with -ENODEV.
 *
 * Context: Process context.
 *
 * Return: 0, -EBUSY if already open, -ENODEV if torn down.
 */
static int lstp_ipmi_open(struct inode *inode, struct file *file)
{
	struct lstp_ipmi_ctx *ctx = to_ctx(file);
	int ret = 0;

	spin_lock_irq(&ctx->lock);
	if (lstp_ipmi_stopped(ctx))
		ret = -ENODEV;
	else if (ctx->running)
		ret = -EBUSY;
	else
		ctx->running = true;
	spin_unlock_irq(&ctx->lock);

	if (ret)
		return ret;

	lstp_ipmi_ctx_get(ctx);
	return 0;
}

/**
 * lstp_ipmi_read() - Read IPMI request from the device.
 * @file:  File for the device
 * @buf:   User buffer
 * @count: Maximum bytes to read
 * @ppos:  Unused
 *
 * Drains the FIFO; blocks until data arrives or the channel is torn down
 * unless O_NONBLOCK is set. Output format is &struct ipmi_lstp_msg_header
 * followed by the IPMI payload.
 *
 * Context: Process context. May sleep.
 *
 * Return: Bytes read, or -EAGAIN / -ERESTARTSYS / -ENODEV.
 */
static ssize_t lstp_ipmi_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct lstp_ipmi_ctx *ctx = to_ctx(file);
	struct ipmi_lstp_msg msg;
	unsigned long flags;
	unsigned int len = 0;
	int ret;

	/*
	 * Drain into a stack-local @msg under @ctx->lock, then copy_to_user
	 * outside the lock since it may sleep. Loop to handle two threads
	 * sharing an fd both winning the wait_event() but only one the
	 * kfifo_out().
	 */
	while (!len) {
		if (kfifo_is_empty(&ctx->fifo)) {
			if (lstp_ipmi_stopped(ctx))
				return -ENODEV;
			if (file->f_flags & O_NONBLOCK)
				return -EAGAIN;
			ret = wait_event_interruptible(ctx->req_wq, lstp_ipmi_readable(ctx));
			if (ret)
				return ret;
		}

		spin_lock_irqsave(&ctx->lock, flags);
		len = kfifo_out(&ctx->fifo, &msg, sizeof(msg));
		spin_unlock_irqrestore(&ctx->lock, flags);
	}

	len = min_t(unsigned int, count, len);
	if (copy_to_user(buf, &msg, len))
		return -EFAULT;
	return len;
}

/**
 * lstp_ipmi_write() - Write IPMI response to the device.
 * @file:  File for the device
 * @buf:   User buffer holding &struct ipmi_lstp_msg_header + payload
 * @count: Bytes available in @buf
 * @ppos:  Unused
 *
 * Forwards a response to the remote endpoint. Writes whose @msg_num
 * doesn't match the current request tag are silently dropped (return
 * @count) so userspace doesn't have to track the race against new
 * incoming requests.
 *
 * Context: Process context. Takes @ctx->tx_mutex. Performs blocking USB I/O.
 *
 * Return: @count, or -EINVAL / -EFAULT / -ENODEV.
 */
static ssize_t lstp_ipmi_write(struct file *file, const char __user *buf, size_t count,
			       loff_t *ppos)
{
	struct lstp_ipmi_ctx *ctx = to_ctx(file);
	struct lstp_channel *ch;
	struct ipmi_lstp_msg msg;
	ssize_t ret;

	if (count < sizeof(struct ipmi_lstp_msg_header) || count > sizeof(struct ipmi_lstp_msg))
		return -EINVAL;

	if (copy_from_user(&msg, buf, count))
		return -EFAULT;

	/* Stale tag read is fine; pairs with WRITE_ONCE in the IRQ producer. */
	if (msg.header.msg_num != READ_ONCE(ctx->msg_count))
		return count;

	if (!msg.header.len || msg.header.len > IPMI_LSTP_PAYLOAD_MAX ||
	    count < sizeof(struct ipmi_lstp_msg_header) + msg.header.len)
		return -EINVAL;

	/*
	 * Lock on @ctx, not @ch: open fds kref-pin @ctx, but @ch is freed
	 * by devres once lstp_disconnect() returns, so the framework's
	 * channel TX mutex would itself UAF for a writer preempted between
	 * the @ctx->ch load and mutex_lock(). lstp_ipmi_stop() flips
	 * @stopped under the same mutex, so once we hold it @ch is either
	 * declared dead (bail) or pinned alive until we unlock.
	 *
	 * TODO: drop this private mutex+flag once the lstp_subsys API
	 * exposes a kref-pinned tx fence with fd-lifetime semantics; the
	 * per-subsystem duplication of the framework channel TX mutex
	 * disappears then.
	 */
	mutex_lock(&ctx->tx_mutex);

	if (ctx->stopped) {
		ret = -ENODEV;
		goto out_unlock;
	}

	ch = ctx->ch;

	ret = lstp_send(ch, LSTP_IPMI_CMD_MESSAGE, msg.payload, msg.header.len);
	if (ret)
		dev_err(ch->dev, "%s: ch_%d: Could not forward response (%pe)\n", __func__,
			ch->ch_id, ERR_PTR(ret));

out_unlock:
	mutex_unlock(&ctx->tx_mutex);

	return (ret < 0) ? ret : count;
}

/**
 * lstp_ipmi_release() - Release the IPMI character device.
 * @inode: Unused
 * @file:  File for the device
 *
 * Drops the @ctx->kref taken by lstp_ipmi_open(); the last fd to release
 * after disconnect is what triggers lstp_ipmi_ctx_release().
 *
 * Return: 0.
 */
static int lstp_ipmi_release(struct inode *inode, struct file *file)
{
	struct lstp_ipmi_ctx *ctx = to_ctx(file);

	spin_lock_irq(&ctx->lock);
	ctx->running = false;
	spin_unlock_irq(&ctx->lock);

	lstp_ipmi_ctx_put(ctx);

	return 0;
}

/**
 * lstp_ipmi_poll() - Poll for readable data on the device.
 * @file: File for the device
 * @wait: Poll table
 *
 * Returns POLLIN | POLLRDNORM when the FIFO has data, EPOLLHUP after
 * disconnect.
 */
static __poll_t lstp_ipmi_poll(struct file *file, poll_table *wait)
{
	struct lstp_ipmi_ctx *ctx = to_ctx(file);

	poll_wait(file, &ctx->req_wq, wait);
	if (lstp_ipmi_stopped(ctx))
		return EPOLLHUP;
	if (!kfifo_is_empty(&ctx->fifo))
		return POLLIN | POLLRDNORM;

	return 0;
}

static const struct file_operations lstp_ipmi_fops = {
	.owner = THIS_MODULE,
	.open = lstp_ipmi_open,
	.read = lstp_ipmi_read,
	.write = lstp_ipmi_write,
	.release = lstp_ipmi_release,
	.poll = lstp_ipmi_poll,
};

/*******************************************************************************
 * Devres action callbacks
 ******************************************************************************/

/**
 * lstp_ipmi_quiesce() - Mark the IPMI channel stopped and wake waiters.
 * @ctx: IPMI context
 *
 * Sets @stopped under @tx_mutex and @ctx->lock so in-flight write() and
 * blocked read()/poll() paths observe teardown.
 *
 * Context: Process context. Takes @tx_mutex.
 */
static void lstp_ipmi_quiesce(struct lstp_ipmi_ctx *ctx)
{
	/* Lock order: @tx_mutex (sleeping) outer, @ctx->lock (irq-safe) inner. */
	mutex_lock(&ctx->tx_mutex);
	spin_lock_irq(&ctx->lock);
	/* Pairs with smp_load_acquire() in lstp_ipmi_stopped(). */
	smp_store_release(&ctx->stopped, true);
	spin_unlock_irq(&ctx->lock);
	mutex_unlock(&ctx->tx_mutex);

	wake_up_all(&ctx->req_wq);
}

/**
 * lstp_ipmi_stop_and_deregister() - Devres action: stop opens and drop the miscdev.
 * @data: &struct lstp_ipmi_ctx
 *
 * @ctx-owned allocations (kfifo, ida slot, miscdev.name, @ctx itself)
 * are freed by lstp_ipmi_ctx_release() once the last fd drops the kref,
 * so they outlive disconnect for any still-open fds.
 */
static void lstp_ipmi_stop_and_deregister(void *data)
{
	struct lstp_ipmi_ctx *ctx = data;

	lstp_ipmi_quiesce(ctx);
	misc_deregister(&ctx->miscdev);
}

/*******************************************************************************
 * RX callback for unsolicited IPMI requests
 ******************************************************************************/

/**
 * lstp_ipmi_irq_callback() - Handle incoming IPMI requests from the device.
 * @ch:  LSTP channel that received the data.
 * @pkt: Received LSTP packet (header + payload).
 *
 * Callback invoked when an unsolicited IPMI request is received from the
 * remote endpoint. Validates the message length, filters out postcode
 * messages (netfn=0x2c, cmd=0x02, group=0xAE), and queues valid requests
 * to the FIFO for userspace to read.
 *
 * If the FIFO is full, oldest queued messages are dropped one at a time
 * until the new message fits, so stale messages don't block fresh ones.
 *
 * Context: Interrupt context (called from USB RX completion). Acquires
 *          @ctx->lock with irqsave. Must not sleep.
 */
static void lstp_ipmi_irq_callback(struct lstp_channel *ch, struct lstp_packet *pkt)
{
	struct lstp_ipmi_ctx *ctx = ch->priv;
	u16 rx_len = le16_to_cpu(pkt->hdr.length);
	struct ipmi_lstp_msg msg;
	unsigned long flags;
	unsigned int msg_size;
	unsigned int dropped = 0;

	if (rx_len < IPMI_MIN_MSG_LEN || rx_len > IPMI_LSTP_PAYLOAD_MAX) {
		dev_warn(ch->dev, "%s: ch_%d: Invalid IPMI request length %u\n", __func__,
			 ch->ch_id, rx_len);
		return;
	}

	if (lstp_ipmi_postcodes_is_postcode(pkt->payload, rx_len)) {
		lstp_ipmi_postcodes_send(&ctx->postcodes, pkt->payload, rx_len);
		return;
	}

	if (!kfifo_initialized(&ctx->fifo))
		return;

	msg_size = sizeof(msg.header) + rx_len;
	msg.header.len = rx_len;
	memcpy(msg.payload, pkt->payload, rx_len);

	spin_lock_irqsave(&ctx->lock, flags);
	/* WRITE_ONCE pairs with the lockless READ_ONCE in lstp_ipmi_write(). */
	msg.header.msg_num = ctx->msg_count + 1;
	WRITE_ONCE(ctx->msg_count, msg.header.msg_num);
	/* Drop oldest first: stale requests have likely timed out host-side. */
	while (kfifo_avail(&ctx->fifo) < msg_size) {
		kfifo_skip(&ctx->fifo);
		dropped++;
	}
	kfifo_in(&ctx->fifo, &msg, msg_size);
	spin_unlock_irqrestore(&ctx->lock, flags);

	if (dropped)
		dev_warn_ratelimited(ch->dev, "%s: ch_%d: FIFO full, dropped %u stale request(s)\n",
				     __func__, ch->ch_id, dropped);

	wake_up_all(&ctx->req_wq);
}

/*******************************************************************************
 * IPMI channel initialization, start, and stop
 ******************************************************************************/

/**
 * lstp_ipmi_init() - Initialize an LSTP IPMI channel.
 * @ch:   LSTP channel to initialize as IPMI
 * @info: unused
 *
 * Allocates and initializes the IPMI context structure, FIFO buffer, and
 * prepares the miscdevice for the channel. The device name is either taken
 * from the firmware node "label" property (DT or ACPI) or auto-generated
 * as "ipmi-lstpN".
 *
 * Expected firmware node structure (optional)::
 *
 *   channel@M {
 *       compatible = "nvidia,lstp-ipmi";
 *       reg = <M>;                  // Channel ID
 *       label = "ipmi-custom-name"; // Device name (optional)
 *                                   // If omitted, uses "ipmi-lstpN"
 *   };
 *
 * @ctx is kref-refcounted; the channel's initial ref is dropped via the
 * lstp_ipmi_ctx_put_cb() devres action. @ctx-owned allocations (kfifo,
 * ida slot, miscdev.name) are freed by the kref release callback, not
 * via devres, so they outlive disconnect for still-open fds.
 *
 * Context: Process context. Called during probe before RX URB is active.
 *
 * Return: 0 on success, negative errno on failure
 */
static int lstp_ipmi_init(struct lstp_channel *ch, const struct lstp_channel_init_info *info)
{
	int ret;
	struct lstp_ipmi_ctx *ctx;
	const char *label;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return -ENOMEM;

	/* Init fields the release path may touch; failed devres call invokes it. */
	kref_init(&ctx->kref);
	ctx->ida_id = -1;
	ctx->ch = ch;
	spin_lock_init(&ctx->lock);
	mutex_init(&ctx->tx_mutex);
	init_waitqueue_head(&ctx->req_wq);

	ret = devm_add_action_or_reset(ch->dev, lstp_ipmi_ctx_put_cb, ctx);
	if (ret)
		return ret;

	ch->priv = ctx;

	ret = kfifo_alloc(&ctx->fifo, BUFFER_SIZE, GFP_KERNEL);
	if (ret)
		return ret;

	/* Get device name from firmware node label (DT or ACPI) or generate one */
	if (ctx->ch->fwnode && !fwnode_property_read_string(ctx->ch->fwnode, "label", &label)) {
		ctx->miscdev.name = kstrdup(label, GFP_KERNEL);
	} else {
		ctx->ida_id = ida_alloc(&lstp_ipmi_ida, GFP_KERNEL);
		if (ctx->ida_id < 0)
			return ctx->ida_id;
		ctx->miscdev.name = kasprintf(GFP_KERNEL, "ipmi-lstp%d", ctx->ida_id);
	}
	if (!ctx->miscdev.name)
		return -ENOMEM;

	ctx->miscdev.minor = MISC_DYNAMIC_MINOR;
	ctx->miscdev.fops = &lstp_ipmi_fops;
	ctx->miscdev.parent = ch->dev;

	/* Initialize postcodes support (name derived from miscdev.name) */
	ret = lstp_ipmi_postcodes_init(&ctx->postcodes, ch->dev, ctx->miscdev.name, ctx,
				       lstp_ipmi_ctx_get_cb, lstp_ipmi_ctx_put_cb);
	if (ret)
		return ret;

	dev_dbg(ch->dev, "%s: ch_%d: Initialized as %s\n", __func__, ch->ch_id, ch->display_name);
	return 0;
}

/**
 * lstp_ipmi_start() - Start an LSTP IPMI channel.
 * @ch: LSTP channel to start
 *
 * Registers the miscdevice to make the IPMI interface available to userspace
 * and arms the lstp_ipmi_stop_and_deregister() devres action so the node is
 * torn down on disconnect or on later probe failure. This should be called
 * after the RX URB is active so the channel can properly receive unsolicited
 * IPMI requests.
 *
 * Context: Process context. Called during probe after RX URB is active.
 *
 * Return: 0 on success, negative errno on failure
 */
static int lstp_ipmi_start(struct lstp_channel *ch)
{
	struct lstp_ipmi_ctx *ctx = (struct lstp_ipmi_ctx *)ch->priv;
	int ret;

	if (!ctx) {
		dev_err(ch->dev, "%s: ch_%d: IPMI context not initialized\n", __func__, ch->ch_id);
		return -EINVAL;
	}

	ret = misc_register(&ctx->miscdev);
	if (ret) {
		dev_err(ch->dev, "%s: ch_%d: Could not register miscdevice (%pe)\n", __func__,
			ch->ch_id, ERR_PTR(ret));
		return ret;
	}

	ret = devm_add_action_or_reset(ch->dev, lstp_ipmi_stop_and_deregister, ctx);
	if (ret)
		return ret;

	/* Start postcodes device */
	ret = lstp_ipmi_postcodes_start(&ctx->postcodes);
	if (ret) {
		devm_release_action(ch->dev, lstp_ipmi_stop_and_deregister, ctx);
		return ret;
	}

	deprecated_lstp_channel_publish_child_dev(ch, ctx->miscdev.this_device);

	dev_info(ch->dev, "%s: ch_%d: Started as %s\n", __func__, ch->ch_id, ch->display_name);
	return 0;
}

/**
 * lstp_ipmi_stop() - Quiesce the IPMI channel on disconnect.
 * @ch: LSTP channel being stopped
 *
 * Flips @ctx->stopped and wakes blocked readers/pollers. The main miscdev is
 * unregistered later by the lstp_ipmi_stop_and_deregister() devres action;
 * opens that race the window are rejected via @stopped in lstp_ipmi_open().
 */
static void lstp_ipmi_stop(struct lstp_channel *ch)
{
	struct lstp_ipmi_ctx *ctx = ch->priv;

	lstp_ipmi_postcodes_stop(&ctx->postcodes);
	lstp_ipmi_quiesce(ctx);
}

/* clang-format off */
LSTP_SUBSYS(ipmi, LSTP_CHANNEL_TYPE_IPMI, lstp_ipmi_init, lstp_ipmi_start,
	    .fwnode_compatible = "nvidia,lstp-ipmi",
	    .irq_callback = lstp_ipmi_irq_callback,
	    .channel_stop = lstp_ipmi_stop,
);
/* clang-format on */
