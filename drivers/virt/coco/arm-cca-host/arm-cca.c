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

static __maybe_unused int init_dev_communication_buffers(struct pci_dev *pdev,
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

	/*
	 * Once ide is setup, enable the stream at the endpoint
	 * Root port will be done by RMM
	 */
	pci_ide_stream_enable(pdev, ide);
	return 0;

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

	pci_ide_stream_release(ide);
	pf0_dsc->sel_stream = NULL;
	clear_bit(stream_id, cca_stream_ids);
}

static struct pci_tsm_ops cca_link_pci_ops = {
	.probe = cca_tsm_pci_probe,
	.remove = cca_tsm_pci_remove,
	.connect = cca_tsm_connect,
	.disconnect = cca_tsm_disconnect,
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
