/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * IPMI postcodes support for LSTP USB interface.
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

#ifndef __LSTP_IPMI_POSTCODES_H
#define __LSTP_IPMI_POSTCODES_H

#include <linux/types.h>

#ifdef CONFIG_SEPARATE_LSTP_IPMI_POSTCODES

#include <linux/miscdevice.h>
#include <linux/kfifo.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/uaccess.h>

/*
 * Postcode message format (OEM Group Extension):
 * Byte 0: netfn/lun (netfn 0x2C = Group Extension)
 * Byte 1: cmd (0x02 = OEM command)
 * Byte 2: group (0xAE = OEM group identifier)
 * Bytes 3-11: 9 bytes of postcode data
 */
#define LSTP_IPMI_POST_NETFN 0x2C
#define LSTP_IPMI_POST_CMD 0x02
#define LSTP_IPMI_POST_GROUP 0xAE
#define LSTP_IPMI_POST_MIN_LEN 3 /* netfn + cmd + group */
#define LSTP_IPMI_POST_CODE_SIZE 9 /* postcode data length */
#define LSTP_IPMI_POST_CODE_OFFSET 3 /* offset to postcode data */
#define LSTP_IPMI_POST_BUFFER_SIZE 1024

/**
 * struct lstp_ipmi_postcodes - Postcodes device context.
 * @miscdev:     Userspace miscdev.
 * @lock:        Protects @fifo and @running.
 * @wait_queue:  Blocked readers / pollers.
 * @fifo:        Inbound postcode bytes pending read().
 * @running:     Exclusive-open flag.
 * @initialized: Init succeeded; gates _start / _stop / _destroy.
 * @stopped:     Set by lstp_ipmi_postcodes_stop() to fence file ops.
 * @parent:      Opaque enclosing object pinned while any fd is open.
 * @parent_get:  Bumps @parent's refcount; invoked from open().
 * @parent_put:  Drops @parent's refcount; invoked from release().
 */
struct lstp_ipmi_postcodes {
	struct miscdevice miscdev;
	spinlock_t lock; /* Protects FIFO and running flag */
	wait_queue_head_t wait_queue;
	struct kfifo fifo;
	bool running;
	bool initialized;
	bool stopped;
	void *parent;
	void (*parent_get)(void *parent);
	void (*parent_put)(void *parent);
};

/* Helper to get postcodes context from file */
static inline struct lstp_ipmi_postcodes *lstp_ipmi_postcodes_to_ctx(struct file *file)
{
	return container_of(file->private_data, struct lstp_ipmi_postcodes, miscdev);
}

static inline bool lstp_ipmi_postcodes_stopped(struct lstp_ipmi_postcodes *post)
{
	/* Pairs with smp_store_release() in lstp_ipmi_postcodes_stop(). */
	return smp_load_acquire(&post->stopped);
}

static int lstp_ipmi_postcodes_open(struct inode *inode, struct file *file)
{
	struct lstp_ipmi_postcodes *post = lstp_ipmi_postcodes_to_ctx(file);
	int ret = 0;

	spin_lock_irq(&post->lock);
	if (post->running)
		ret = -EBUSY;
	else
		post->running = true;
	spin_unlock_irq(&post->lock);

	if (ret)
		return ret;

	if (post->parent_get)
		post->parent_get(post->parent);

	return 0;
}

static ssize_t lstp_ipmi_postcodes_read(struct file *file, char __user *buf, size_t count,
					loff_t *ppos)
{
	struct lstp_ipmi_postcodes *post = lstp_ipmi_postcodes_to_ctx(file);
	u8 tmp_buf[LSTP_IPMI_POST_CODE_SIZE];
	unsigned long flags;
	unsigned int copied;
	ssize_t ret;

	if (kfifo_is_empty(&post->fifo)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(post->wait_queue,
					       !kfifo_is_empty(&post->fifo) ||
						       lstp_ipmi_postcodes_stopped(post));
		if (ret == -ERESTARTSYS)
			return ret;
		if (lstp_ipmi_postcodes_stopped(post))
			return -ENODEV;
	}

	/*
	 * Copy to kernel buffer under spinlock, then copy to user without lock.
	 * This avoids calling copy_to_user() with spinlock held (which can sleep
	 * on page fault).
	 */
	spin_lock_irqsave(&post->lock, flags);
	copied = kfifo_out(&post->fifo, tmp_buf, min_t(size_t, count, LSTP_IPMI_POST_CODE_SIZE));
	spin_unlock_irqrestore(&post->lock, flags);

	if (copied == 0)
		return -EAGAIN;

	if (copy_to_user(buf, tmp_buf, copied))
		return -EFAULT;

	return copied;
}

static int lstp_ipmi_postcodes_release(struct inode *inode, struct file *file)
{
	struct lstp_ipmi_postcodes *post = lstp_ipmi_postcodes_to_ctx(file);

	spin_lock_irq(&post->lock);
	post->running = false;
	spin_unlock_irq(&post->lock);

	if (post->parent_put)
		post->parent_put(post->parent);

	return 0;
}

static __poll_t lstp_ipmi_postcodes_poll(struct file *file, poll_table *wait)
{
	struct lstp_ipmi_postcodes *post = lstp_ipmi_postcodes_to_ctx(file);

	poll_wait(file, &post->wait_queue, wait);
	if (lstp_ipmi_postcodes_stopped(post))
		return EPOLLHUP;
	if (!kfifo_is_empty(&post->fifo))
		return POLLIN | POLLRDNORM;

	return 0;
}

static const struct file_operations lstp_ipmi_postcodes_fops = {
	.owner = THIS_MODULE,
	.open = lstp_ipmi_postcodes_open,
	.read = lstp_ipmi_postcodes_read,
	.release = lstp_ipmi_postcodes_release,
	.poll = lstp_ipmi_postcodes_poll,
};

/**
 * lstp_ipmi_postcodes_init() - Initialize postcodes support.
 * @post:       Postcodes context.
 * @dev:        Parent device for the miscdev (sysfs hierarchy).
 * @base_name:  Device name; "-postcodes" is appended.
 * @parent:     See &struct lstp_ipmi_postcodes.
 * @parent_get: See &struct lstp_ipmi_postcodes.
 * @parent_put: See &struct lstp_ipmi_postcodes.
 *
 * Context: Process context.
 *
 * Return: 0 on success, negative errno on failure.
 */
static inline int lstp_ipmi_postcodes_init(struct lstp_ipmi_postcodes *post, struct device *dev,
					   const char *base_name, void *parent,
					   void (*parent_get)(void *parent),
					   void (*parent_put)(void *parent))
{
	int ret;

	memset(post, 0, sizeof(*post));

	ret = kfifo_alloc(&post->fifo, LSTP_IPMI_POST_BUFFER_SIZE, GFP_KERNEL);
	if (ret)
		return ret;

	spin_lock_init(&post->lock);
	init_waitqueue_head(&post->wait_queue);

	post->miscdev.name = kasprintf(GFP_KERNEL, "%s-postcodes", base_name);
	if (!post->miscdev.name) {
		kfifo_free(&post->fifo);
		return -ENOMEM;
	}

	post->miscdev.minor = MISC_DYNAMIC_MINOR;
	post->miscdev.fops = &lstp_ipmi_postcodes_fops;
	post->miscdev.parent = dev;

	post->parent = parent;
	post->parent_get = parent_get;
	post->parent_put = parent_put;

	post->initialized = true;

	return 0;
}

/**
 * lstp_ipmi_postcodes_start - Register the postcodes misc device
 * @post: Postcodes context
 *
 * Registers the postcodes misc device to make it available to userspace.
 *
 * Context: Process context.
 *
 * Return: 0 on success, negative errno on failure.
 */
static inline int lstp_ipmi_postcodes_start(struct lstp_ipmi_postcodes *post)
{
	if (!post->initialized)
		return -EINVAL;

	return misc_register(&post->miscdev);
}

/**
 * lstp_ipmi_postcodes_stop() - Quiesce the postcodes miscdev on disconnect.
 * @post: Postcodes context.
 *
 * Deregisters the miscdev, sets @stopped, and wakes blocked readers.
 * Open fds keep @parent alive via @parent_put until they release.
 *
 * Context: Process context.
 */
static inline void lstp_ipmi_postcodes_stop(struct lstp_ipmi_postcodes *post)
{
	if (!post->initialized)
		return;

	misc_deregister(&post->miscdev);
	/* Pairs with smp_load_acquire() in lstp_ipmi_postcodes_stopped(). */
	smp_store_release(&post->stopped, true);
	wake_up_all(&post->wait_queue);
}

/**
 * lstp_ipmi_postcodes_destroy() - Free postcodes-owned resources.
 * @post: Postcodes context.
 *
 * Caller must ensure _stop() has run and no fds remain.
 */
static inline void lstp_ipmi_postcodes_destroy(struct lstp_ipmi_postcodes *post)
{
	if (!post->initialized)
		return;

	kfifo_free(&post->fifo);
	kfree(post->miscdev.name);
	post->miscdev.name = NULL;
	post->initialized = false;
}

/**
 * lstp_ipmi_postcodes_is_postcode - Check if IPMI message is a postcode
 * @payload: IPMI message payload
 * @len: Payload length
 *
 * Checks if the IPMI message matches the OEM Group Extension postcode
 * signature (netfn=0x2C, cmd=0x02, group=0xAE).
 *
 * Context: Any context (lock-free, no side effects).
 *
 * Return: true if message is a postcode, false otherwise.
 */
static inline bool lstp_ipmi_postcodes_is_postcode(const u8 *payload, u16 len)
{
	if (len < LSTP_IPMI_POST_MIN_LEN)
		return false;

	return ((payload[0] >> 2) == LSTP_IPMI_POST_NETFN && payload[1] == LSTP_IPMI_POST_CMD &&
		payload[2] == LSTP_IPMI_POST_GROUP);
}

/**
 * lstp_ipmi_postcodes_send - Queue a postcode message
 * @post: Postcodes context
 * @payload: IPMI message payload containing postcode data
 * @len: Payload length
 *
 * Extracts postcode data from the IPMI payload and queues it to the FIFO.
 * The postcode is POST_CODE_SIZE bytes starting at POST_CODE_OFFSET.
 *
 * Context: Interrupt context safe. Acquires post->lock with irqsave.
 */
static inline void lstp_ipmi_postcodes_send(struct lstp_ipmi_postcodes *post, const u8 *payload,
					    u16 len)
{
	unsigned long flags;
	unsigned int rc;

	if (!post->initialized)
		return;

	if (len < (LSTP_IPMI_POST_CODE_OFFSET + LSTP_IPMI_POST_CODE_SIZE))
		return;

	spin_lock_irqsave(&post->lock, flags);

	/* Reset FIFO if there's not enough space */
	if ((LSTP_IPMI_POST_BUFFER_SIZE - kfifo_len(&post->fifo)) < LSTP_IPMI_POST_CODE_SIZE)
		kfifo_reset(&post->fifo);

	rc = kfifo_in(&post->fifo, &payload[LSTP_IPMI_POST_CODE_OFFSET], LSTP_IPMI_POST_CODE_SIZE);
	if (rc != LSTP_IPMI_POST_CODE_SIZE) {
		kfifo_reset(&post->fifo);
		spin_unlock_irqrestore(&post->lock, flags);
		return;
	}

	spin_unlock_irqrestore(&post->lock, flags);

	wake_up_all(&post->wait_queue);
}

#else /* !CONFIG_SEPARATE_LSTP_IPMI_POSTCODES */

/* Stub implementation when CONFIG_SEPARATE_LSTP_IPMI_POSTCODES is not defined */

struct lstp_ipmi_postcodes {
	char __dummy; /* Avoid empty struct warnings */
};

static inline int lstp_ipmi_postcodes_init(struct lstp_ipmi_postcodes *, struct device *,
					   const char *, void *, void (*)(void *), void (*)(void *))
{
	return 0;
}

static inline int lstp_ipmi_postcodes_start(struct lstp_ipmi_postcodes *)
{
	return 0;
}

static inline void lstp_ipmi_postcodes_stop(struct lstp_ipmi_postcodes *)
{
}

static inline void lstp_ipmi_postcodes_destroy(struct lstp_ipmi_postcodes *)
{
}

static inline bool lstp_ipmi_postcodes_is_postcode(const u8 *, u16)
{
	return false;
}

static inline void lstp_ipmi_postcodes_send(struct lstp_ipmi_postcodes *, const u8 *, u16)
{
}

#endif /* CONFIG_SEPARATE_LSTP_IPMI_POSTCODES */

#endif /* __LSTP_IPMI_POSTCODES_H */
