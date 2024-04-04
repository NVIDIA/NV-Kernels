// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */

#include "iommufd_private.h"

void iommufd_viommu_lock_vdev_id(struct iommufd_viommu *viommu)
{
	down_read(&viommu->vdev_ids_rwsem);
}
EXPORT_SYMBOL_NS_GPL(iommufd_viommu_lock_vdev_id, IOMMUFD);

void iommufd_viommu_unlock_vdev_id(struct iommufd_viommu *viommu)
{
	up_read(&viommu->vdev_ids_rwsem);
}
EXPORT_SYMBOL_NS_GPL(iommufd_viommu_unlock_vdev_id, IOMMUFD);

/*
 * Find a device attached to an VIOMMU object using a virtual device ID that was
 * set via an IOMMUFD_CMD_VIOMMU_SET_VDEV_ID. Callers of this function must call
 * iommufd_viommu_lock_vdev_id() prior and iommufd_viommu_unlock_vdev_id() after
 *
 * Return device or NULL.
 */
struct device *iommufd_viommu_find_device(struct iommufd_viommu *viommu, u64 id)
{
	struct iommufd_vdev_id *vdev_id;

	lockdep_assert_held(&viommu->vdev_ids_rwsem);

	xa_lock(&viommu->vdev_ids);
	vdev_id = xa_load(&viommu->vdev_ids, (unsigned long)id);
	xa_unlock(&viommu->vdev_ids);
	if (!vdev_id || vdev_id->id != id)
		return NULL;
	return vdev_id->idev->dev;
}
EXPORT_SYMBOL_NS_GPL(iommufd_viommu_find_device, IOMMUFD);

/*
 * Convert a viommu to its encapsulated nest parent domain. Caller must be aware
 * of the lifecycle of the viommu pointer. Only call this function in a callback
 * function where viommu is passed in by the iommu/iommufd core.
 */
struct iommu_domain *
iommufd_viommu_to_parent_domain(struct iommufd_viommu *viommu)
{
	if (!viommu || !viommu->hwpt)
		return NULL;
	return viommu->hwpt->common.domain;
}
EXPORT_SYMBOL_NS_GPL(iommufd_viommu_to_parent_domain, IOMMUFD);

/*
 * Fetch the dev pointer in the vdev_id structure. Caller must make ensure the
 * lifecycle of the vdev_id structure, likely by adding a driver-level lock to
 * protect the passed-in vdev_id for any race against a potential unset_vdev_id
 * callback.
 */
struct device *iommufd_vdev_id_to_dev(struct iommufd_vdev_id *vdev_id)
{
	if (!vdev_id || !vdev_id->viommu)
		return NULL;
	return vdev_id->idev->dev;
}
EXPORT_SYMBOL_NS_GPL(iommufd_vdev_id_to_dev, IOMMUFD);

/**
 * IOMMU drivers can call this helper to report a per-VIOMMU virtual IRQ. Caller
 * must ensure the lifecycle of the viommu object, likely by passing it from a
 * vdev_id structure that was set via a set_vdev_id callback and by holding the
 * same driver-level lock to protect the passed-in vdev_id from any race against
 * a potential unset_vdev_id callback.
 */
void iommufd_viommu_report_irq(struct iommufd_viommu *viommu, unsigned int type,
			       void *irq_ptr, size_t irq_len)
{
	struct iommufd_event_virq *event_virq;
	struct iommufd_viommu_irq *virq;
	void *irq_data;

	might_sleep();

	if (!viommu)
		return;

	down_read(&viommu->virqs_rwsem);

	event_virq = iommufd_viommu_find_event_virq(viommu, type);
	if (!event_virq)
		goto out_unlock_vdev_ids;

	virq = kzalloc(sizeof(*virq) + irq_len, GFP_KERNEL);
	if (!virq)
		goto out_unlock_vdev_ids;
	irq_data = (void *)virq + sizeof(*virq);
	memcpy(irq_data, irq_ptr, irq_len);

	virq->event_virq = event_virq;
	virq->irq_len = irq_len;

	iommufd_event_virq_handler(virq);
out_unlock_vdev_ids:
	up_read(&viommu->virqs_rwsem);
}
EXPORT_SYMBOL_NS_GPL(iommufd_viommu_report_irq, IOMMUFD);

struct iommufd_object *iommufd_object_alloc_elm(struct iommufd_ctx *ictx,
						size_t size,
						enum iommufd_object_type type)
{
	struct iommufd_object *obj;
	int rc;

	obj = kzalloc(size, GFP_KERNEL_ACCOUNT);
	if (!obj)
		return ERR_PTR(-ENOMEM);
	obj->type = type;
	/* Starts out bias'd by 1 until it is removed from the xarray */
	refcount_set(&obj->shortterm_users, 1);
	refcount_set(&obj->users, 1);

	/*
	 * Reserve an ID in the xarray but do not publish the pointer yet since
	 * the caller hasn't initialized it yet. Once the pointer is published
	 * in the xarray and visible to other threads we can't reliably destroy
	 * it anymore, so the caller must complete all errorable operations
	 * before calling iommufd_object_finalize().
	 */
	rc = xa_alloc(&ictx->objects, &obj->id, XA_ZERO_ENTRY,
		      xa_limit_31b, GFP_KERNEL_ACCOUNT);
	if (rc)
		goto out_free;
	return obj;
out_free:
	kfree(obj);
	return ERR_PTR(rc);
}
EXPORT_SYMBOL_NS_GPL(iommufd_object_alloc_elm, IOMMUFD);

struct iommufd_viommu *
__iommufd_viommu_alloc(struct iommufd_ctx *ictx, size_t size,
		       const struct iommufd_viommu_ops *ops)
{
	struct iommufd_viommu *viommu;
	struct iommufd_object *obj;

	if (WARN_ON(size < sizeof(*viommu)))
		return ERR_PTR(-EINVAL);
	obj = iommufd_object_alloc_elm(ictx, size, IOMMUFD_OBJ_VIOMMU);
	if (IS_ERR(obj))
		return ERR_CAST(obj);
	viommu = container_of(obj, struct iommufd_viommu, obj);
	if (ops)
		viommu->ops = ops;
	return viommu;
}
EXPORT_SYMBOL_NS_GPL(__iommufd_viommu_alloc, IOMMUFD);

struct iommufd_vdev_id *__iommufd_vdev_id_alloc(size_t size)
{
	struct iommufd_vdev_id *vdev_id;

	if (WARN_ON(size < sizeof(*vdev_id)))
		return ERR_PTR(-EINVAL);
	vdev_id = kzalloc(size, GFP_KERNEL);
	if (!vdev_id)
		return ERR_PTR(-ENOMEM);
	return vdev_id;
}
EXPORT_SYMBOL_NS_GPL(__iommufd_vdev_id_alloc, IOMMUFD);

struct iommufd_vqueue *
__iommufd_vqueue_alloc(struct iommufd_viommu *viommu, size_t size)
{
	struct iommufd_vqueue *vqueue;
	struct iommufd_object *obj;

	if (WARN_ON(size < sizeof(*vqueue)))
		return ERR_PTR(-EINVAL);
	obj = iommufd_object_alloc_elm(viommu->ictx, size, IOMMUFD_OBJ_VQUEUE);
	if (IS_ERR(obj))
		return ERR_CAST(obj);
	vqueue = container_of(obj, struct iommufd_vqueue, obj);
	return vqueue;
}
EXPORT_SYMBOL_NS_GPL(__iommufd_vqueue_alloc, IOMMUFD);
