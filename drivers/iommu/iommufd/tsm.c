// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#include "iommufd_private.h"
#include <linux/tsm.h>

int iommufd_vdevice_tsm_op_ioctl(struct iommufd_ucmd *ucmd)
{
	struct iommu_vdevice_tsm_op *cmd = ucmd->cmd;
	struct iommufd_vdevice *vdev;
	struct kvm *kvm;
	int rc = -ENODEV;

	if (cmd->flags)
		return -EOPNOTSUPP;

	vdev = container_of(iommufd_get_object(ucmd->ictx, cmd->vdevice_id,
					       IOMMUFD_OBJ_VDEVICE),
			    struct iommufd_vdevice, obj);
	if (IS_ERR(vdev))
		return PTR_ERR(vdev);

	kvm = vdev->viommu->kvm_filp->private_data;
	if (kvm) {
		/*  tsm layer will take care of parallel calls to tsm_bind/unbind */
		if (cmd->op == IOMMU_VDEVICE_TSM_BIND)
			rc = tsm_bind(vdev->idev->dev, kvm, vdev->virt_id);
		else if (cmd->op == IOMMU_VDEVICE_TSM_UNBIND)
			rc = tsm_unbind(vdev->idev->dev);

		if (rc)
			goto out_put_vdev;

		rc = iommufd_ucmd_respond(ucmd, sizeof(*cmd));
	}

out_put_vdev:
	iommufd_put_object(ucmd->ictx, &vdev->obj);
	return rc;
}
