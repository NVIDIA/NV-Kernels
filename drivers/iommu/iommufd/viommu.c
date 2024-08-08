// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */

#include "iommufd_private.h"

void iommufd_viommu_destroy(struct iommufd_object *obj)
{
	struct iommufd_viommu *viommu =
		container_of(obj, struct iommufd_viommu, obj);
	struct iommufd_vdev_id *vdev_id;
	unsigned long index;

	xa_for_each(&viommu->vdev_ids, index, vdev_id) {
		/* Unlocked since there should be no race in a destroy() */
		vdev_id->idev->vdev_id = NULL;
		kfree(vdev_id);
	}
	xa_destroy(&viommu->vdev_ids);

	refcount_dec(&viommu->hwpt->common.obj.users);
}

int iommufd_viommu_alloc_ioctl(struct iommufd_ucmd *ucmd)
{
	struct iommu_viommu_alloc *cmd = ucmd->cmd;
	struct iommufd_hwpt_paging *hwpt_paging;
	struct iommufd_viommu *viommu;
	struct iommufd_device *idev;
	struct iommu_domain *domain;
	int rc;

	if (cmd->flags)
		return -EOPNOTSUPP;

	idev = iommufd_get_device(ucmd, cmd->dev_id);
	if (IS_ERR(idev))
		return PTR_ERR(idev);

	hwpt_paging = iommufd_get_hwpt_paging(ucmd, cmd->hwpt_id);
	if (IS_ERR(hwpt_paging)) {
		rc = PTR_ERR(hwpt_paging);
		goto out_put_idev;
	}

	if (!hwpt_paging->nest_parent) {
		rc = -EINVAL;
		goto out_put_hwpt;
	}
	domain = hwpt_paging->common.domain;

	if (cmd->type != IOMMU_VIOMMU_TYPE_DEFAULT) {
		rc = -EOPNOTSUPP;
		goto out_put_hwpt;
	}

	viommu = iommufd_object_alloc(ucmd->ictx, viommu, IOMMUFD_OBJ_VIOMMU);
	if (IS_ERR(viommu)) {
		rc = PTR_ERR(viommu);
		goto out_put_hwpt;
	}

	viommu->type = cmd->type;
	viommu->ictx = ucmd->ictx;
	viommu->hwpt = hwpt_paging;
	viommu->ops = domain->ops->default_viommu_ops;

	xa_init(&viommu->vdev_ids);
	init_rwsem(&viommu->vdev_ids_rwsem);
	INIT_LIST_HEAD(&viommu->virqs);
	init_rwsem(&viommu->virqs_rwsem);

	refcount_inc(&viommu->hwpt->common.obj.users);

	cmd->out_viommu_id = viommu->obj.id;
	rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	if (rc)
		goto out_abort;
	iommufd_object_finalize(ucmd->ictx, &viommu->obj);
	goto out_put_hwpt;

out_abort:
	iommufd_object_abort_and_destroy(ucmd->ictx, &viommu->obj);
out_put_hwpt:
	iommufd_put_object(ucmd->ictx, &hwpt_paging->common.obj);
out_put_idev:
	iommufd_put_object(ucmd->ictx, &idev->obj);
	return rc;
}

int iommufd_viommu_set_vdev_id(struct iommufd_ucmd *ucmd)
{
	struct iommu_viommu_set_vdev_id *cmd = ucmd->cmd;
	struct iommufd_vdev_id *vdev_id, *curr;
	struct iommufd_viommu *viommu;
	struct iommufd_device *idev;
	int rc = 0;

	if (cmd->vdev_id > ULONG_MAX)
		return -EINVAL;

	viommu = iommufd_get_viommu(ucmd, cmd->viommu_id);
	if (IS_ERR(viommu))
		return PTR_ERR(viommu);

	idev = iommufd_get_device(ucmd, cmd->dev_id);
	if (IS_ERR(idev)) {
		rc = PTR_ERR(idev);
		goto out_put_viommu;
	}

	down_write(&viommu->vdev_ids_rwsem);
	mutex_lock(&idev->igroup->lock);
	if (idev->vdev_id) {
		rc = -EEXIST;
		goto out_unlock_igroup;
	}

	vdev_id = kzalloc(sizeof(*vdev_id), GFP_KERNEL);
	if (!vdev_id) {
		rc = -ENOMEM;
		goto out_unlock_igroup;
	}

	vdev_id->idev = idev;
	vdev_id->viommu = viommu;
	vdev_id->id = cmd->vdev_id;

	curr = xa_cmpxchg(&viommu->vdev_ids, cmd->vdev_id, NULL, vdev_id,
			  GFP_KERNEL);
	if (curr) {
		rc = xa_err(curr) ? : -EBUSY;
		goto out_free;
	}

	idev->vdev_id = vdev_id;
	goto out_unlock_igroup;

out_free:
	kfree(vdev_id);
out_unlock_igroup:
	mutex_unlock(&idev->igroup->lock);
	up_write(&viommu->vdev_ids_rwsem);
	iommufd_put_object(ucmd->ictx, &idev->obj);
out_put_viommu:
	iommufd_put_object(ucmd->ictx, &viommu->obj);
	return rc;
}

int iommufd_viommu_unset_vdev_id(struct iommufd_ucmd *ucmd)
{
	struct iommu_viommu_unset_vdev_id *cmd = ucmd->cmd;
	struct iommufd_viommu *viommu;
	struct iommufd_vdev_id *old;
	struct iommufd_device *idev;
	int rc = 0;

	if (cmd->vdev_id > ULONG_MAX)
		return -EINVAL;

	viommu = iommufd_get_viommu(ucmd, cmd->viommu_id);
	if (IS_ERR(viommu))
		return PTR_ERR(viommu);

	idev = iommufd_get_device(ucmd, cmd->dev_id);
	if (IS_ERR(idev)) {
		rc = PTR_ERR(idev);
		goto out_put_viommu;
	}

	down_write(&viommu->vdev_ids_rwsem);
	mutex_lock(&idev->igroup->lock);
	if (!idev->vdev_id) {
		rc = -ENOENT;
		goto out_unlock_igroup;
	}
	if (idev->vdev_id->id != cmd->vdev_id) {
		rc = -EINVAL;
		goto out_unlock_igroup;
	}

	old = xa_cmpxchg(&viommu->vdev_ids, idev->vdev_id->id,
			 idev->vdev_id, NULL, GFP_KERNEL);
	if (xa_is_err(old)) {
		rc = xa_err(old);
		goto out_unlock_igroup;
	}
	kfree(old);
	idev->vdev_id = NULL;

out_unlock_igroup:
	mutex_unlock(&idev->igroup->lock);
	up_write(&viommu->vdev_ids_rwsem);
	iommufd_put_object(ucmd->ictx, &idev->obj);
out_put_viommu:
	iommufd_put_object(ucmd->ictx, &viommu->obj);
	return rc;
}
