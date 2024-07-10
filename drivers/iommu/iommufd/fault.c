// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2024 Intel Corporation
 */
#define pr_fmt(fmt) "iommufd: " fmt

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/iommufd.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/anon_inodes.h>
#include <uapi/linux/iommufd.h>

#include "../iommu-priv.h"
#include "iommufd_private.h"

static int iommufd_event_iopf_enable(struct iommufd_device *idev)
{
	struct device *dev = idev->dev;
	int ret;

	/*
	 * Once we turn on PCI/PRI support for VF, the response failure code
	 * should not be forwarded to the hardware due to PRI being a shared
	 * resource between PF and VFs. There is no coordination for this
	 * shared capability. This waits for a vPRI reset to recover.
	 */
	if (dev_is_pci(dev) && to_pci_dev(dev)->is_virtfn)
		return -EINVAL;

	mutex_lock(&idev->iopf_lock);
	/* Device iopf has already been on. */
	if (++idev->iopf_enabled > 1) {
		mutex_unlock(&idev->iopf_lock);
		return 0;
	}

	ret = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_IOPF);
	if (ret)
		--idev->iopf_enabled;
	mutex_unlock(&idev->iopf_lock);

	return ret;
}

static void iommufd_event_iopf_disable(struct iommufd_device *idev)
{
	mutex_lock(&idev->iopf_lock);
	if (!WARN_ON(idev->iopf_enabled == 0)) {
		if (--idev->iopf_enabled == 0)
			iommu_dev_disable_feature(idev->dev, IOMMU_DEV_FEAT_IOPF);
	}
	mutex_unlock(&idev->iopf_lock);
}

static int __iopf_domain_attach_dev(struct iommufd_hw_pagetable *hwpt,
				    struct iommufd_device *idev)
{
	struct iommufd_attach_handle *handle;
	int ret;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return -ENOMEM;

	handle->idev = idev;
	ret = iommu_attach_group_handle(hwpt->domain, idev->igroup->group,
					&handle->handle);
	if (ret)
		kfree(handle);

	return ret;
}

int iommufd_event_iopf_domain_attach_dev(struct iommufd_hw_pagetable *hwpt,
					 struct iommufd_device *idev)
{
	int ret;

	if (!hwpt->fault)
		return -EINVAL;

	ret = iommufd_event_iopf_enable(idev);
	if (ret)
		return ret;

	ret = __iopf_domain_attach_dev(hwpt, idev);
	if (ret)
		iommufd_event_iopf_disable(idev);

	return ret;
}

static void iommufd_event_iopf_auto_response(struct iommufd_hw_pagetable *hwpt,
					     struct iommufd_attach_handle *handle)
{
	struct iommufd_event *fault = hwpt->fault;
	struct iopf_group *group, *next;
	unsigned long index;

	if (!fault)
		return;

	mutex_lock(&fault->mutex);
	list_for_each_entry_safe(group, next, &fault->deliver, node) {
		if (group->attach_handle != &handle->handle)
			continue;
		list_del(&group->node);
		iopf_group_response(group, IOMMU_PAGE_RESP_INVALID);
		iopf_free_group(group);
	}

	xa_for_each(&fault->response, index, group) {
		if (group->attach_handle != &handle->handle)
			continue;
		xa_erase(&fault->response, index);
		iopf_group_response(group, IOMMU_PAGE_RESP_INVALID);
		iopf_free_group(group);
	}
	mutex_unlock(&fault->mutex);
}

static struct iommufd_attach_handle *
iommufd_device_get_attach_handle(struct iommufd_device *idev)
{
	struct iommu_attach_handle *handle;

	handle = iommu_attach_handle_get(idev->igroup->group, IOMMU_NO_PASID, 0);
	if (!handle)
		return NULL;

	return to_iommufd_handle(handle);
}

void iommufd_event_iopf_domain_detach_dev(struct iommufd_hw_pagetable *hwpt,
					  struct iommufd_device *idev)
{
	struct iommufd_attach_handle *handle;

	handle = iommufd_device_get_attach_handle(idev);
	iommu_detach_group_handle(hwpt->domain, idev->igroup->group);
	iommufd_event_iopf_auto_response(hwpt, handle);
	iommufd_event_iopf_disable(idev);
	kfree(handle);
}

static int __iopf_domain_replace_dev(struct iommufd_device *idev,
				     struct iommufd_hw_pagetable *hwpt,
				     struct iommufd_hw_pagetable *old)
{
	struct iommufd_attach_handle *handle, *curr = NULL;
	int ret;

	if (old->fault)
		curr = iommufd_device_get_attach_handle(idev);

	if (hwpt->fault) {
		handle = kzalloc(sizeof(*handle), GFP_KERNEL);
		if (!handle)
			return -ENOMEM;

		handle->handle.domain = hwpt->domain;
		handle->idev = idev;
		ret = iommu_replace_group_handle(idev->igroup->group,
						 hwpt->domain, &handle->handle);
	} else {
		ret = iommu_replace_group_handle(idev->igroup->group,
						 hwpt->domain, NULL);
	}

	if (!ret && curr) {
		iommufd_event_iopf_auto_response(old, curr);
		kfree(curr);
	}

	return ret;
}

int iommufd_event_iopf_domain_replace_dev(struct iommufd_device *idev,
					  struct iommufd_hw_pagetable *hwpt,
					  struct iommufd_hw_pagetable *old)
{
	bool iopf_off = !hwpt->fault && old->fault;
	bool iopf_on = hwpt->fault && !old->fault;
	int ret;

	if (iopf_on) {
		ret = iommufd_event_iopf_enable(idev);
		if (ret)
			return ret;
	}

	ret = __iopf_domain_replace_dev(idev, hwpt, old);
	if (ret) {
		if (iopf_on)
			iommufd_event_iopf_disable(idev);
		return ret;
	}

	if (iopf_off)
		iommufd_event_iopf_disable(idev);

	return 0;
}

void iommufd_event_destroy(struct iommufd_object *obj)
{
	struct iommufd_event *fault = container_of(obj, struct iommufd_event, obj);
	struct iopf_group *group, *next;

	/*
	 * The iommufd object's reference count is zero at this point.
	 * We can be confident that no other threads are currently
	 * accessing this pointer. Therefore, acquiring the mutex here
	 * is unnecessary.
	 */
	list_for_each_entry_safe(group, next, &fault->deliver, node) {
		list_del(&group->node);
		iopf_group_response(group, IOMMU_PAGE_RESP_INVALID);
		iopf_free_group(group);
	}
}

static void iommufd_compose_fault_message(struct iommu_fault *fault,
					  struct iommu_hwpt_pgfault *hwpt_fault,
					  struct iommufd_device *idev,
					  u32 cookie)
{
	hwpt_fault->flags = fault->prm.flags;
	hwpt_fault->dev_id = idev->obj.id;
	hwpt_fault->pasid = fault->prm.pasid;
	hwpt_fault->grpid = fault->prm.grpid;
	hwpt_fault->perm = fault->prm.perm;
	hwpt_fault->addr = fault->prm.addr;
	hwpt_fault->length = 0;
	hwpt_fault->cookie = cookie;
}

static ssize_t iommufd_event_fops_read(struct file *filep, char __user *buf,
				       size_t count, loff_t *ppos)
{
	size_t fault_size = sizeof(struct iommu_hwpt_pgfault);
	struct iommufd_event *fault = filep->private_data;
	struct iommu_hwpt_pgfault data;
	struct iommufd_device *idev;
	struct iopf_group *group;
	struct iopf_fault *iopf;
	size_t done = 0;
	int rc = 0;

	if (*ppos || count % fault_size)
		return -ESPIPE;

	mutex_lock(&fault->mutex);
	while (!list_empty(&fault->deliver) && count > done) {
		group = list_first_entry(&fault->deliver,
					 struct iopf_group, node);

		if (group->fault_count * fault_size > count - done)
			break;

		rc = xa_alloc(&fault->response, &group->cookie, group,
			      xa_limit_32b, GFP_KERNEL);
		if (rc)
			break;

		idev = to_iommufd_handle(group->attach_handle)->idev;
		list_for_each_entry(iopf, &group->faults, list) {
			iommufd_compose_fault_message(&iopf->fault,
						      &data, idev,
						      group->cookie);
			if (copy_to_user(buf + done, &data, fault_size)) {
				xa_erase(&fault->response, group->cookie);
				rc = -EFAULT;
				break;
			}
			done += fault_size;
		}

		list_del(&group->node);
	}
	mutex_unlock(&fault->mutex);

	return done == 0 ? rc : done;
}

static ssize_t iommufd_event_fops_write(struct file *filep, const char __user *buf,
					size_t count, loff_t *ppos)
{
	size_t response_size = sizeof(struct iommu_hwpt_page_response);
	struct iommufd_event *fault = filep->private_data;
	struct iommu_hwpt_page_response response;
	struct iopf_group *group;
	size_t done = 0;
	int rc = 0;

	if (*ppos || count % response_size)
		return -ESPIPE;

	mutex_lock(&fault->mutex);
	while (count > done) {
		rc = copy_from_user(&response, buf + done, response_size);
		if (rc)
			break;

		group = xa_erase(&fault->response, response.cookie);
		if (!group) {
			rc = -EINVAL;
			break;
		}

		iopf_group_response(group, response.code);
		iopf_free_group(group);
		done += response_size;
	}
	mutex_unlock(&fault->mutex);

	return done == 0 ? rc : done;
}

static __poll_t iommufd_event_fops_poll(struct file *filep,
					struct poll_table_struct *wait)
{
	struct iommufd_event *event = filep->private_data;
	__poll_t pollflags = EPOLLOUT;

	poll_wait(filep, &event->wait_queue, wait);
	mutex_lock(&event->mutex);
	if (!list_empty(&event->deliver))
		pollflags |= EPOLLIN | EPOLLRDNORM;
	mutex_unlock(&event->mutex);

	return pollflags;
}

static int iommufd_event_fops_release(struct inode *inode, struct file *filep)
{
	struct iommufd_event *event = filep->private_data;

	refcount_dec(&event->obj.users);
	iommufd_ctx_put(event->ictx);
	return 0;
}

static const struct file_operations iommufd_event_fops = {
	.owner		= THIS_MODULE,
	.open		= nonseekable_open,
	.read		= iommufd_event_fops_read,
	.write		= iommufd_event_fops_write,
	.poll		= iommufd_event_fops_poll,
	.release	= iommufd_event_fops_release,
	.llseek		= no_llseek,
};

int iommufd_event_alloc(struct iommufd_ucmd *ucmd)
{
	struct iommu_fault_alloc *cmd = ucmd->cmd;
	struct iommufd_event *event;
	struct file *filep;
	int fdno;
	int rc;

	if (cmd->flags)
		return -EOPNOTSUPP;

	event = iommufd_object_alloc(ucmd->ictx, event, IOMMUFD_OBJ_EVENT);
	if (IS_ERR(event))
		return PTR_ERR(event);

	event->ictx = ucmd->ictx;
	INIT_LIST_HEAD(&event->deliver);
	xa_init_flags(&event->response, XA_FLAGS_ALLOC1);
	mutex_init(&event->mutex);
	init_waitqueue_head(&event->wait_queue);

	filep = anon_inode_getfile("[iommufd-pgfault]", &iommufd_event_fops,
				   event, O_RDWR);
	if (IS_ERR(filep)) {
		rc = PTR_ERR(filep);
		goto out_abort;
	}

	refcount_inc(&event->obj.users);
	iommufd_ctx_get(event->ictx);
	event->filep = filep;

	fdno = get_unused_fd_flags(O_CLOEXEC);
	if (fdno < 0) {
		rc = fdno;
		goto out_fput;
	}

	cmd->out_fault_id = event->obj.id;
	cmd->out_fault_fd = fdno;

	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_put_fdno;
	iommufd_object_finalize(ucmd->ictx, &event->obj);

	fd_install(fdno, event->filep);

	return 0;
out_put_fdno:
	put_unused_fd(fdno);
out_fput:
	fput(filep);
	refcount_dec(&event->obj.users);
	iommufd_ctx_put(event->ictx);
out_abort:
	iommufd_object_abort_and_destroy(ucmd->ictx, &event->obj);

	return rc;
}

int iommufd_event_iopf_handler(struct iopf_group *group)
{
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_event *event;

	hwpt = group->attach_handle->domain->fault_data;
	event = hwpt->fault;

	mutex_lock(&event->mutex);
	list_add_tail(&group->node, &event->deliver);
	mutex_unlock(&event->mutex);

	wake_up_interruptible(&event->wait_queue);

	return 0;
}
