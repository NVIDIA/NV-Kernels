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
