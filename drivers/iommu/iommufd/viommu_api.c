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
