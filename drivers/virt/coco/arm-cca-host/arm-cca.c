// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#include <linux/auxiliary_bus.h>
#include <linux/pci-tsm.h>
#include <linux/pci-ide.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/tsm.h>
#include <linux/vmalloc.h>
#include <linux/cleanup.h>
#include <linux/kvm_host.h>
#include <linux/pci.h>
#include <asm/rmi-da.h>

#include "rmi-da.h"

/* Total number of stream id supported at root port level */
#define MAX_STREAM_ID	256


static struct pci_tsm *cca_tsm_pci_probe(struct tsm_dev *tsm_dev, struct pci_dev *pdev)
{
	int rc;

	if (!is_pci_tsm_pf0(pdev)) {
		struct cca_host_fn_dsc *fn_dsc __free(kfree) =
			kzalloc(sizeof(*fn_dsc), GFP_KERNEL);

		if (!fn_dsc)
			return NULL;

		rc = pci_tsm_link_constructor(pdev, &fn_dsc->pci, tsm_dev);
		if (rc)
			return NULL;

		return &no_free_ptr(fn_dsc)->pci;
	}

	if (!pdev->ide_cap)
		return NULL;

	struct cca_host_pf0_dsc *pf0_dsc __free(kfree) =
					kzalloc(sizeof(*pf0_dsc), GFP_KERNEL);
	if (!pf0_dsc)
		return NULL;

	rc = pci_tsm_pf0_constructor(pdev, &pf0_dsc->pci, tsm_dev);
	if (rc)
		return NULL;
	mutex_init(&pf0_dsc->object_lock);

	pci_dbg(pdev, "tsm enabled\n");
	return &no_free_ptr(pf0_dsc)->pci.base_tsm;
}

static void cca_tsm_pci_remove(struct pci_tsm *tsm)
{
	struct pci_dev *pdev = tsm->pdev;

	if (is_pci_tsm_pf0(pdev)) {
		struct cca_host_pf0_dsc *pf0_dsc = to_cca_pf0_dsc(pdev);

		pci_tsm_pf0_destructor(&pf0_dsc->pci);
		kfree(pf0_dsc);
	} else {
		kfree(to_cca_fn_dsc(pdev));
	}
}

static int init_dev_communication_buffers(struct pci_dev *pdev,
					  struct cca_host_comm_data *comm_data)
{
	int ret = -ENOMEM;

	comm_data->io_params = (struct rmi_dev_comm_data *)get_zeroed_page(GFP_KERNEL);
	if (!comm_data->io_params)
		goto err_out;

	comm_data->rsp_buff = (void *)__get_free_page(GFP_KERNEL);
	if (!comm_data->rsp_buff)
		goto err_res_buff;

	comm_data->req_buff = (void *)__get_free_page(GFP_KERNEL);
	if (!comm_data->req_buff)
		goto err_req_buff;

	comm_data->work_queue = alloc_ordered_workqueue("%s %s DEV_COMM", 0,
						dev_bus_name(&pdev->dev),
						pci_name(pdev));
	if (!comm_data->work_queue)
		goto err_work_queue;

	comm_data->io_params->enter.status = RMI_DEV_COMM_NONE;
	comm_data->io_params->enter.resp_addr = virt_to_phys(comm_data->rsp_buff);
	comm_data->io_params->enter.req_addr  = virt_to_phys(comm_data->req_buff);
	comm_data->io_params->enter.resp_len = 0;

	return 0;

err_work_queue:
	free_page((unsigned long)comm_data->req_buff);
err_req_buff:
	free_page((unsigned long)comm_data->rsp_buff);
err_res_buff:
	free_page((unsigned long)comm_data->io_params);
err_out:
	return ret;
}

static inline void free_dev_communication_buffers(struct cca_host_comm_data *comm_data)
{
	destroy_workqueue(comm_data->work_queue);

	free_page((unsigned long)comm_data->req_buff);
	free_page((unsigned long)comm_data->rsp_buff);
	free_page((unsigned long)comm_data->io_params);
}

/* For now global for simplicity. Protected by pci_tsm_rwsem */
static DECLARE_BITMAP(cca_stream_ids, MAX_STREAM_ID);

static int cca_tsm_connect(struct pci_dev *pdev)
{
	struct pci_dev *rp = pcie_find_root_port(pdev);
	struct cca_host_pf0_dsc *pf0_dsc;
	struct pci_ide *ide;
	int rc, stream_id;

	/* Only function 0 supports connect in host */
	if (WARN_ON(!is_pci_tsm_pf0(pdev)))
		return -EIO;

	pf0_dsc = to_cca_pf0_dsc(pdev);
	/* Allocate stream id */
	stream_id = find_first_zero_bit(cca_stream_ids, MAX_STREAM_ID);
	if (stream_id == MAX_STREAM_ID)
		return -EBUSY;
	set_bit(stream_id, cca_stream_ids);

	ide = pci_ide_stream_alloc(pdev);
	if (!ide) {
		rc = -ENOMEM;
		goto err_stream_alloc;
	}

	pf0_dsc->sel_stream = ide;
	ide->stream_id = stream_id;
	rc = pci_ide_stream_register(ide);
	if (rc)
		goto err_stream;

	pci_ide_stream_setup(pdev, ide);
	pci_ide_stream_setup(rp, ide);

	rc = tsm_ide_stream_register(ide);
	if (rc)
		goto err_tsm;

	rc = init_dev_communication_buffers(pdev, &pf0_dsc->comm_data);
	if (rc)
		goto err_comm_buff;
	rc = cca_pdev_create(pdev);
	if (rc)
		goto err_pdev_create;

	rc = cca_pdev_ide_setup(pdev);
	if (rc)
		goto err_ide_setup;
	/*
	 * Once ide is setup, enable the stream at the endpoint
	 * Root port will be done by RMM
	 */
	pci_ide_stream_enable(pdev, ide);
	return 0;

err_ide_setup:
	cca_pdev_stop_and_destroy(pdev);
err_pdev_create:
	free_dev_communication_buffers(&pf0_dsc->comm_data);
err_comm_buff:
	tsm_ide_stream_unregister(ide);
err_tsm:
	pci_ide_stream_teardown(rp, ide);
	pci_ide_stream_teardown(pdev, ide);
	pci_ide_stream_unregister(ide);
err_stream:
	pci_ide_stream_free(ide);
	pf0_dsc->sel_stream = NULL;
err_stream_alloc:
	clear_bit(stream_id, cca_stream_ids);

	return rc;
}

static void cca_tsm_disconnect(struct pci_dev *pdev)
{
	int stream_id;
	struct pci_ide *ide;
	struct cca_host_pf0_dsc *pf0_dsc;

	pf0_dsc = to_cca_pf0_dsc(pdev);
	if (!pf0_dsc)
		return;

	ide = pf0_dsc->sel_stream;
	stream_id = ide->stream_id;

	cca_pdev_stop_and_destroy(pdev);
	free_dev_communication_buffers(&pf0_dsc->comm_data);

	pci_ide_stream_release(ide);
	pf0_dsc->sel_stream = NULL;
	clear_bit(stream_id, cca_stream_ids);
}

static struct pci_tdi *cca_tsm_bind(struct pci_dev *pdev, struct kvm *kvm, u32 tdi_id)
{
	void *rmm_vdev;
	struct pci_dev *dsm_dev = pdev->tsm->dsm_dev;
	struct realm *realm = &kvm->arch.realm;

	struct cca_host_tdi *host_tdi __free(kfree) =
		kzalloc(sizeof(struct cca_host_tdi), GFP_KERNEL);
	if (!host_tdi)
		return ERR_PTR(-ENOMEM);

	pci_tsm_tdi_constructor(pdev, &host_tdi->tdi, kvm, tdi_id);
	/* Assign the tdi such that vdev_create can use that to lookup */
	pdev->tsm->tdi = &host_tdi->tdi;
	rmm_vdev = cca_vdev_create(realm, pdev, dsm_dev, tdi_id);
	if (IS_ERR_OR_NULL(rmm_vdev)) {
		pdev->tsm->tdi = NULL;
		return rmm_vdev;
	}

	return &no_free_ptr(host_tdi)->tdi;
}

/*
 * All device memory should be unmapped by now.
 * 1. A pci device destroy will cause a driver remove (vfio) which will have
 *    done a dmabuf based unmap
 * 2. A vdevice/idevice destroy from VMM should have done a unmap_private_range
 *    vm ioctl before
 * 3. A guest unlock request should have done a rsi_invalidiate_mem_mapping
 *    before unlock rhi
 * 4. vfio_pci_core_close_device() should trigger tsm unbind if vdevice is not
 *    already distroyed and that path involves vfio_pci_dma_buf_cleanup() which
 *    should get kvm to unmap the devmap
 */
static void cca_tsm_unbind(struct pci_tdi *tdi)
{
	struct cca_host_tdi *host_tdi;
	struct realm *realm = &tdi->kvm->arch.realm;

	host_tdi = container_of(tdi, struct cca_host_tdi, tdi);
	cca_vdev_unlock_and_destroy(realm, tdi->pdev, tdi->pdev->tsm->dsm_dev);
	kvfree(host_tdi->interface_report);
	kvfree(host_tdi->measurements);
	kfree(host_tdi);
}

static ssize_t cca_tsm_guest_req(struct pci_tdi *tdi, enum pci_tsm_req_scope scope,
				 sockptr_t req, size_t req_len,
				 sockptr_t resp, size_t resp_len,
				 u64 *tsm_code)
{
	struct pci_dev *pdev = tdi->pdev;

	if (req.is_kernel || resp.is_kernel)
		return -EINVAL;

	switch (scope) {
	case PCI_TSM_REQ_INFO: {
		u32 req_type;

		if (get_user(req_type, (u32 __user *)req.user))
			return -EFAULT;

		switch (req_type) {
		case __RHI_DA_OBJECT_SIZE: {
			int object_size;
			struct arm64_vdev_object_size_guest_req req_obj;

			if (req_len > sizeof(req_obj))
				return -EINVAL;

			if (copy_from_user((void *)&req_obj, req.user, req_len))
				return -EFAULT;
			object_size = cca_vdev_get_object_size(pdev, req_obj.object_type);
			if (object_size > 0) {
				if (resp_len < sizeof(object_size))
					return -EINVAL;
				if (copy_to_user(resp.user, &object_size, sizeof(object_size)))
					return -EFAULT;

				if (resp_len != sizeof(object_size))
					return resp_len - sizeof(object_size);
				return 0;
			}
			/* error */
			return object_size;
		}
		case __RHI_DA_OBJECT_READ:
		{
			int len;
			struct arm64_vdev_object_read_guest_req req_obj;

			if (req_len > sizeof(req_obj))
				return -EINVAL;

			if (copy_from_user((void *)&req_obj, req.user, req_len))
				return -EFAULT;

			len = cca_vdev_read_cached_object(pdev,
							  req_obj.object_type,
							  req_obj.offset,
							  resp_len, resp.user);
			if (len > 0) {
				if (resp_len != len)
					return resp_len - len;
				return 0;
			}
			/* error */
			return len;
		}
		case __RHI_DA_VDEV_GET_INTERFACE_REPORT:
		{
			return cca_vdev_get_interface_report(pdev);
		}
		case __RHI_DA_VDEV_GET_MEASUREMENTS:
		{
			int ret;
			struct arm64_vdev_device_measurement_guest_req req_obj;

			if (req_len > sizeof(req_obj))
				return -EINVAL;

			if (copy_from_user((void *)&req_obj, req.user, req_len))
				return -EFAULT;

			ret = cca_vdev_get_device_measurements(pdev,
							       req_obj.flags,
							       req_obj.indices,
							       req_obj.nonce);
			return ret;
		}
		default:
			return -EINVAL;
		}
	}
	default:
		return -EINVAL;
	}
}

static struct pci_tsm_ops cca_link_pci_ops = {
	.probe = cca_tsm_pci_probe,
	.remove = cca_tsm_pci_remove,
	.connect = cca_tsm_connect,
	.disconnect = cca_tsm_disconnect,
	.bind = cca_tsm_bind,
	.unbind = cca_tsm_unbind,
	.guest_req = cca_tsm_guest_req,
};

static void cca_link_tsm_remove(void *tsm_dev)
{
	tsm_unregister(tsm_dev);
}

static int cca_link_tsm_probe(struct auxiliary_device *adev,
			      const struct auxiliary_device_id *id)
{
	struct tsm_dev *tsm_dev;

	if (!kvm_has_da_feature())
		return -ENODEV;

	tsm_dev = tsm_register(&adev->dev, &cca_link_pci_ops);
	if (IS_ERR(tsm_dev))
		return PTR_ERR(tsm_dev);

	return devm_add_action_or_reset(&adev->dev, cca_link_tsm_remove,
					tsm_dev);
}

static const struct auxiliary_device_id cca_link_tsm_id_table[] = {
	{ .name =  KBUILD_MODNAME "." RMI_DEV_NAME },
	{}
};
MODULE_DEVICE_TABLE(auxiliary, cca_link_tsm_id_table);

static struct auxiliary_driver cca_link_tsm_driver = {
	.probe = cca_link_tsm_probe,
	.id_table = cca_link_tsm_id_table,
};
module_auxiliary_driver(cca_link_tsm_driver);
MODULE_IMPORT_NS("PCI_IDE");
MODULE_AUTHOR("Aneesh Kumar <aneesh.kumar@kernel.org>");
MODULE_DESCRIPTION("ARM CCA Host TSM driver");
MODULE_LICENSE("GPL");
