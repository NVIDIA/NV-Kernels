// SPDX-License-Identifier: GPL-2.0-only
/*
 * MMIO channel for LSTP USB interface.
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

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/limits.h>
#include <linux/miscdevice.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/cleanup.h>

#include "lstp-main.h"

static DEFINE_IDA(lstp_mmio_ida);

enum lstp_mmio_cmd {
	LSTP_MMIO_CMD_READ = 0x00,
	LSTP_MMIO_CMD_WRITE = 0x01,
};

struct lstp_mmio_read_req {
	__le32 offset;
	__le16 length;
} __packed;

struct lstp_mmio_write_req {
	__le32 offset;
	u8 data[];
} __packed;

struct lstp_mmio_ctx {
	struct kref kref;
	struct lstp_channel *ch;
	struct miscdevice miscdev;
	int ida_id;
	struct mutex lock; /* Protects stopped and ch use for open fds */
	u8 *xfer_buf;
	bool stopped;
};

static void lstp_mmio_ctx_release(struct kref *kref)
{
	struct lstp_mmio_ctx *ctx = container_of(kref, struct lstp_mmio_ctx, kref);

	if (ctx->ida_id >= 0)
		ida_free(&lstp_mmio_ida, ctx->ida_id);
	kfree(ctx->miscdev.name);
	mutex_destroy(&ctx->lock);
	kfree(ctx->xfer_buf);
	kfree(ctx);
}

static void lstp_mmio_ctx_get(struct lstp_mmio_ctx *ctx)
{
	kref_get(&ctx->kref);
}

static void lstp_mmio_ctx_put(struct lstp_mmio_ctx *ctx)
{
	kref_put(&ctx->kref, lstp_mmio_ctx_release);
}

static void lstp_mmio_ctx_put_cb(void *data)
{
	lstp_mmio_ctx_put(data);
}

static struct lstp_mmio_ctx *lstp_mmio_file_ctx(struct file *file)
{
	return file->private_data;
}

static int lstp_mmio_validate_range(loff_t caller_offset, size_t count)
{
	if (caller_offset < 0 || caller_offset > U32_MAX)
		return -EINVAL;
	if ((u64)count > (u64)U32_MAX - caller_offset + 1)
		return -EINVAL;

	return 0;
}

static int lstp_mmio_open(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = file->private_data;
	struct lstp_mmio_ctx *ctx = container_of(miscdev, struct lstp_mmio_ctx, miscdev);

	if (READ_ONCE(ctx->stopped))
		return -ENODEV;

	lstp_mmio_ctx_get(ctx);
	file->private_data = ctx;
	return 0;
}

static ssize_t lstp_mmio_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct lstp_mmio_ctx *ctx = lstp_mmio_file_ctx(file);
	struct lstp_channel *ch;
	struct lstp_mmio_read_req req;
	loff_t caller_offset = *ppos;
	size_t done = 0;
	ssize_t ret;

	ret = lstp_mmio_validate_range(caller_offset, count);
	if (ret)
		return ret;

	mutex_lock(&ctx->lock);
	if (ctx->stopped) {
		ret = -ENODEV;
		goto out_unlock;
	}

	ch = ctx->ch;

	/* Probe enforces bulk_rx_size >= LSTP_USB_EP_MIN_SIZE; anchor the fixed request here. */
	BUILD_BUG_ON(sizeof(struct lstp_header) + sizeof(req) > LSTP_USB_EP_MIN_SIZE);

	if (!count) {
		req = (struct lstp_mmio_read_req){
			.offset = cpu_to_le32((u32)caller_offset),
			.length = cpu_to_le16(0),
		};

		ret = lstp_request(ch, LSTP_MMIO_CMD_READ, &req, sizeof(req), NULL, 0, NULL, NULL);
		goto out_unlock;
	}

	while (done < count) {
		size_t chunk = min3(count - done, ch->max_rx_payload, (size_t)U16_MAX);

		if (signal_pending(current)) {
			ret = done ?: -ERESTARTSYS;
			goto out;
		}

		req = (struct lstp_mmio_read_req){
			.offset = cpu_to_le32((u32)(caller_offset + done)),
			.length = cpu_to_le16((u16)chunk),
		};

		ret = lstp_request(ch, LSTP_MMIO_CMD_READ, &req, sizeof(req), ctx->xfer_buf, chunk,
				   NULL, NULL);
		if (ret) {
			ret = done ?: ret;
			goto out;
		}

		if (copy_to_user(buf + done, ctx->xfer_buf, chunk)) {
			ret = done ?: -EFAULT;
			goto out;
		}

		done += chunk;
	}

	ret = done;

out:
	if (done)
		*ppos = caller_offset + done;
out_unlock:
	mutex_unlock(&ctx->lock);
	return ret;
}

static ssize_t lstp_mmio_write(struct file *file, const char __user *buf, size_t count,
			       loff_t *ppos)
{
	struct lstp_mmio_ctx *ctx = lstp_mmio_file_ctx(file);
	struct lstp_mmio_write_req *req;
	struct lstp_channel *ch;
	loff_t caller_offset = *ppos;
	size_t done = 0;
	ssize_t ret;

	ret = lstp_mmio_validate_range(caller_offset, count);
	if (ret)
		return ret;

	mutex_lock(&ctx->lock);
	if (ctx->stopped) {
		ret = -ENODEV;
		goto out_unlock;
	}

	ch = ctx->ch;
	req = (struct lstp_mmio_write_req *)ctx->xfer_buf;

	/* Probe enforces bulk_tx_size >= LSTP_USB_EP_MIN_SIZE; anchor the fixed request here. */
	BUILD_BUG_ON(sizeof(struct lstp_header) + sizeof(*req) > LSTP_USB_EP_MIN_SIZE);

	if (!count) {
		req->offset = cpu_to_le32((u32)caller_offset);

		ret = lstp_request(ch, LSTP_MMIO_CMD_WRITE, req, sizeof(*req), NULL, 0, NULL, NULL);
		goto out_unlock;
	}

	while (done < count) {
		size_t chunk = min(count - done, ch->max_tx_payload - sizeof(*req));

		if (signal_pending(current)) {
			ret = done ?: -ERESTARTSYS;
			goto out;
		}

		if (copy_from_user(req->data, buf + done, chunk)) {
			ret = done ?: -EFAULT;
			goto out;
		}

		req->offset = cpu_to_le32((u32)(caller_offset + done));

		ret = lstp_request(ch, LSTP_MMIO_CMD_WRITE, req, struct_size(req, data, chunk),
				   NULL, 0, NULL, NULL);
		if (ret) {
			ret = done ?: ret;
			goto out;
		}

		done += chunk;
	}

	ret = done;

out:
	if (done)
		*ppos = caller_offset + done;
out_unlock:
	mutex_unlock(&ctx->lock);
	return ret;
}

static loff_t lstp_mmio_llseek(struct file *file, loff_t offset, int whence)
{
	return fixed_size_llseek(file, offset, whence, U32_MAX);
}

static int lstp_mmio_release(struct inode *inode, struct file *file)
{
	lstp_mmio_ctx_put(lstp_mmio_file_ctx(file));

	return 0;
}

static const struct file_operations lstp_mmio_fops = {
	.owner = THIS_MODULE,
	.open = lstp_mmio_open,
	.read = lstp_mmio_read,
	.write = lstp_mmio_write,
	.llseek = lstp_mmio_llseek,
	.release = lstp_mmio_release,
};

static int lstp_mmio_init(struct lstp_channel *ch, const struct lstp_channel_init_info *info)
{
	struct lstp_mmio_ctx *ctx;
	int ret;

	ctx = kzalloc_obj(*ctx);
	if (!ctx)
		return -ENOMEM;

	kref_init(&ctx->kref);
	ctx->ch = ch;
	ctx->ida_id = -1;
	mutex_init(&ctx->lock);

	ret = devm_add_action_or_reset(ch->dev, lstp_mmio_ctx_put_cb, ctx);
	if (ret)
		return ret;

	ctx->xfer_buf = kmalloc(max(min_t(size_t, ch->max_rx_payload, U16_MAX), ch->max_tx_payload),
				GFP_KERNEL);
	if (!ctx->xfer_buf)
		return -ENOMEM;

	ctx->ida_id = ida_alloc(&lstp_mmio_ida, GFP_KERNEL);
	if (ctx->ida_id < 0)
		return ctx->ida_id;

	ctx->miscdev.name = kasprintf(GFP_KERNEL, "lstp_mmio_%d", ctx->ida_id);
	if (!ctx->miscdev.name)
		return -ENOMEM;

	ctx->miscdev.minor = MISC_DYNAMIC_MINOR;
	ctx->miscdev.fops = &lstp_mmio_fops;
	ctx->miscdev.parent = ch->dev;
	ctx->miscdev.mode = 0600;
	ch->priv = ctx;

	dev_dbg(ch->dev, "%s: ch_%d: Initialized as %s\n", __func__, ch->ch_id, ch->display_name);
	return 0;
}

static void lstp_mmio_deregister(void *data)
{
	struct lstp_mmio_ctx *ctx = data;

	scoped_guard(mutex, &ctx->lock)
		WRITE_ONCE(ctx->stopped, true);

	misc_deregister(&ctx->miscdev);
}

static int lstp_mmio_start(struct lstp_channel *ch)
{
	struct lstp_mmio_ctx *ctx = ch->priv;
	int ret;

	if (!ctx) {
		dev_err(ch->dev, "%s: ch_%d: MMIO context not initialized\n", __func__, ch->ch_id);
		return -EINVAL;
	}

	ret = misc_register(&ctx->miscdev);
	if (ret) {
		dev_err(ch->dev, "%s: ch_%d: Could not register miscdevice (%pe)\n", __func__,
			ch->ch_id, ERR_PTR(ret));
		return ret;
	}

	ret = devm_add_action_or_reset(ch->dev, lstp_mmio_deregister, ctx);
	if (ret)
		return ret;

	deprecated_lstp_channel_publish_child_dev(ch, ctx->miscdev.this_device);

	dev_info(ch->dev, "%s: ch_%d: Started as %s\n", __func__, ch->ch_id, ch->display_name);
	return 0;
}

/* clang-format off */
LSTP_SUBSYS(mmio, LSTP_CHANNEL_TYPE_MMIO, lstp_mmio_init, lstp_mmio_start);
/* clang-format on */
