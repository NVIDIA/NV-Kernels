// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */

#include <linux/iommufd.h>

#include "iommufd_private.h"

void iommufd_viommu_destroy(struct iommufd_object *obj)
{
	struct iommufd_viommu *viommu =
		container_of(obj, struct iommufd_viommu, obj);
	struct iommufd_vdev_id *vdev_id;
	unsigned long index;

	xa_for_each(&viommu->vdev_ids, index, vdev_id) {
		list_del(&vdev_id->idev_item);
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
	viommu->iommu_dev = idev->dev->iommu->iommu_dev;

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
	struct iommufd_hwpt_nested *hwpt_nested;
	struct iommufd_vdev_id *vdev_id, *curr;
	struct iommufd_hw_pagetable *hwpt;
	struct iommufd_viommu *viommu;
	struct iommufd_device *idev;
	int rc = 0;

	if (cmd->vdev_id > ULONG_MAX)
		return -EINVAL;

	idev = iommufd_get_device(ucmd, cmd->dev_id);
	if (IS_ERR(idev))
		return PTR_ERR(idev);
	hwpt = idev->igroup->hwpt;

	if (hwpt == NULL || hwpt->obj.type != IOMMUFD_OBJ_HWPT_NESTED) {
		rc = -EINVAL;
		goto out_put_idev;
	}
	hwpt_nested = container_of(hwpt, struct iommufd_hwpt_nested, common);

	viommu = iommufd_get_viommu(ucmd, cmd->viommu_id);
	if (IS_ERR(viommu)) {
		rc = PTR_ERR(viommu);
		goto out_put_idev;
	}

	if (hwpt_nested->viommu != viommu) {
		rc = -EINVAL;
		goto out_put_viommu;
	}

	vdev_id = kzalloc(sizeof(*vdev_id), GFP_KERNEL);
	if (IS_ERR(vdev_id)) {
		rc = PTR_ERR(vdev_id);
		goto out_put_viommu;
	}

	vdev_id->viommu = viommu;
	vdev_id->dev = idev->dev;
	vdev_id->vdev_id = cmd->vdev_id;

	curr = xa_cmpxchg(&viommu->vdev_ids, cmd->vdev_id,
			  NULL, vdev_id, GFP_KERNEL);
	if (curr) {
		rc = xa_err(curr) ? : -EBUSY;
		goto out_free_vdev_id;
	}

	list_add_tail(&vdev_id->idev_item, &idev->vdev_id_list);
	goto out_put_viommu;

out_free_vdev_id:
	kfree(vdev_id);
out_put_viommu:
	iommufd_put_object(ucmd->ictx, &viommu->obj);
out_put_idev:
	iommufd_put_object(ucmd->ictx, &idev->obj);
	return rc;
}

static struct device *
iommufd_viommu_find_device(struct iommufd_viommu *viommu, u64 id)
{
	struct iommufd_vdev_id *vdev_id;

	xa_lock(&viommu->vdev_ids);
	vdev_id = xa_load(&viommu->vdev_ids, (unsigned long)id);
	xa_unlock(&viommu->vdev_ids);
	if (!vdev_id || vdev_id->vdev_id != id)
		return NULL;
	return vdev_id->dev;
}

int iommufd_viommu_unset_vdev_id(struct iommufd_ucmd *ucmd)
{
	struct iommu_viommu_unset_vdev_id *cmd = ucmd->cmd;
	struct iommufd_vdev_id *vdev_id;
	struct iommufd_viommu *viommu;
	struct iommufd_device *idev;
	int rc = 0;

	idev = iommufd_get_device(ucmd, cmd->dev_id);
	if (IS_ERR(idev))
		return PTR_ERR(idev);

	viommu = iommufd_get_viommu(ucmd, cmd->viommu_id);
	if (IS_ERR(viommu)) {
		rc = PTR_ERR(viommu);
		goto out_put_idev;
	}

	if (idev->dev != iommufd_viommu_find_device(viommu, cmd->vdev_id)) {
		rc = -EINVAL;
		goto out_put_viommu;
	}

	vdev_id = xa_erase(&viommu->vdev_ids, cmd->vdev_id);
	list_del(&vdev_id->idev_item);
	kfree(vdev_id);

out_put_viommu:
	iommufd_put_object(ucmd->ictx, &viommu->obj);
out_put_idev:
	iommufd_put_object(ucmd->ictx, &idev->obj);
	return rc;
}

int iommufd_viommu_invalidate(struct iommufd_ucmd *ucmd)
{
	struct iommu_viommu_invalidate *cmd = ucmd->cmd;
	struct iommu_user_data_array data_array = {
		.type = cmd->data_type,
		.uptr = u64_to_user_ptr(cmd->data_uptr),
		.entry_len = cmd->entry_len,
		.entry_num = cmd->entry_num,
	};
	struct iommufd_viommu *viommu;
	u32 done_num = 0;
	int rc;

	if (cmd->__reserved) {
		rc = -EOPNOTSUPP;
		goto out;
	}

	if (cmd->entry_num && (!cmd->data_uptr || !cmd->entry_len)) {
		rc = -EINVAL;
		goto out;
	}

	viommu = iommufd_get_viommu(ucmd, cmd->viommu_id);
	if (IS_ERR(viommu))
		return PTR_ERR(viommu);

	if (!viommu->ops || !viommu->ops->cache_invalidate) {
		rc = -EOPNOTSUPP;
		goto out_put_viommu;
	}

	rc = viommu->ops->cache_invalidate(viommu, &data_array);

	done_num = data_array.entry_num;

out_put_viommu:
	iommufd_put_object(ucmd->ictx, &viommu->obj);
out:
	cmd->entry_num = done_num;
	if (iommufd_ucmd_respond(ucmd, sizeof(*cmd)))
		return -EFAULT;
	return rc;
}
