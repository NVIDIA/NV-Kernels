// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#include <linux/pci.h>
#include <linux/pci-ecam.h>
#include <linux/pci-doe.h>
#include <linux/delay.h>
#include <asm/rmi_cmds.h>

#include "rmi-da.h"

static int pci_ide_aassoc_register_to_pdev_addr(struct rmi_pdev_addr_range *pdev_addr,
						unsigned int naddr, struct pci_ide_partner *partner)
{
	pdev_addr[0].base = partner->mem_assoc.start;
	pdev_addr[0].top  = partner->mem_assoc.end + 1;
	naddr--;

	if (!naddr)
		return 1;

	pdev_addr[1].base = partner->pref_assoc.start;
	pdev_addr[1].top  = partner->pref_assoc.end + 1;

	return 2;
}

static void free_aux_pages(int cnt, void *aux[])
{
	int ret;

	while (cnt--) {
		ret = rmi_granule_undelegate(virt_to_phys(aux[cnt]));
		if (!ret)
			free_page((unsigned long)aux[cnt]);
	}
}

static int init_pdev_params(struct pci_dev *pdev, struct rmi_pdev_params *params)
{
	int rid, ret, i;
	phys_addr_t aux_phys;
	struct pci_config_window *cfg = pdev->bus->sysdata;
	struct cca_host_pf0_dsc *pf0_dsc = to_cca_pf0_dsc(pdev);
	struct pci_ide *ide = pf0_dsc->sel_stream;

	/* assign the ep device with RMM */
	rid = pci_dev_id(pdev);
	params->pdev_id = rid;
	/* slot number for certificate chain */
	params->cert_id = 0;
	/* io coherent spdm/ide and non p2p */
	params->flags = RMI_PDEV_FLAGS_SPDM | RMI_PDEV_FLAGS_NCOH_IDE |
			RMI_PDEV_FLAGS_NCOH_ADDR;
	params->ncoh_ide_sid = ide->stream_id;
	params->hash_algo = RMI_HASH_SHA_256;
	/* use the rid and MMIO resources of the end point pdev */
	params->rid_base = rid;
	params->rid_top = params->rid_base + 1;
	params->ecam_addr = cfg->res.start;
	params->root_id = pci_dev_id(pcie_find_root_port(pdev));

	params->ncoh_num_addr_range =
		pci_ide_aassoc_register_to_pdev_addr(params->ncoh_addr_range,
						     ARRAY_SIZE(params->ncoh_addr_range),
						     &ide->partner[PCI_IDE_RP]);

	rmi_pdev_aux_count(params->flags, &params->num_aux);
	pf0_dsc->num_aux = params->num_aux;
	for (i = 0; i < params->num_aux; i++) {
		void *aux = (void *)__get_free_page(GFP_KERNEL);

		if (!aux) {
			ret = -ENOMEM;
			goto err_free_aux;
		}

		aux_phys = virt_to_phys(aux);
		if (rmi_granule_delegate(aux_phys)) {
			ret = -ENXIO;
			free_page((unsigned long)aux);
			goto err_free_aux;
		}
		params->aux_granule[i] = aux_phys;
		pf0_dsc->aux[i] = aux;
	}
	return 0;

err_free_aux:
	free_aux_pages(i, pf0_dsc->aux);
	return ret;
}

int cca_pdev_create(struct pci_dev *pci_dev)
{
	int ret;
	void *rmm_pdev;
	bool should_free = true;
	phys_addr_t rmm_pdev_phys;
	struct rmi_pdev_params *params;
	struct cca_host_pf0_dsc *pf0_dsc = to_cca_pf0_dsc(pci_dev);

	rmm_pdev = (void *)get_zeroed_page(GFP_KERNEL);
	if (!rmm_pdev)
		return -ENOMEM;

	rmm_pdev_phys = virt_to_phys(rmm_pdev);
	if (rmi_granule_delegate(rmm_pdev_phys)) {
		ret = -ENXIO;
		goto err_granule_delegate;
	}

	params = (struct rmi_pdev_params *)get_zeroed_page(GFP_KERNEL);
	if (!params) {
		ret = -ENOMEM;
		goto err_param_alloc;
	}

	ret = init_pdev_params(pci_dev, params);
	if (ret)
		goto err_init_pdev_params;

	if (rmi_pdev_create(rmm_pdev_phys, virt_to_phys(params))) {
		ret = -ENXIO;
		goto err_pdev_create;
	}

	pf0_dsc->rmm_pdev = rmm_pdev;
	free_page((unsigned long)params);
	return 0;

err_pdev_create:
	free_aux_pages(pf0_dsc->num_aux, pf0_dsc->aux);
err_init_pdev_params:
	free_page((unsigned long)params);
err_param_alloc:
	if (rmi_granule_undelegate(rmm_pdev_phys))
		should_free = false;
err_granule_delegate:
	if (should_free)
		free_page((unsigned long)rmm_pdev);
	return ret;
}

static int doe_send_req_resp(struct pci_tsm *tsm)
{
	int data_obj_type;
	struct cca_host_comm_data *comm_data = to_cca_comm_data(tsm->pdev);
	struct rmi_dev_comm_exit *io_exit = &comm_data->io_params->exit;
	u8 protocol = io_exit->protocol;

	if (protocol == RMI_PROTOCOL_SPDM)
		data_obj_type = PCI_DOE_FEATURE_CMA;
	else if (protocol == RMI_PROTOCOL_SECURE_SPDM)
		data_obj_type = PCI_DOE_FEATURE_SSESSION;
	else
		return -EINVAL;

	/* delay the send */
	if (io_exit->req_delay)
		fsleep(io_exit->req_delay);

	return pci_tsm_doe_transfer(tsm->dsm_dev, data_obj_type,
				    comm_data->req_buff, io_exit->req_len,
				    comm_data->rsp_buff, PAGE_SIZE);
}

static inline bool pending_dev_communicate(struct rmi_dev_comm_exit *io_exit)
{
	bool pending = io_exit->flags & (RMI_DEV_COMM_EXIT_CACHE_REQ |
					 RMI_DEV_COMM_EXIT_CACHE_RSP |
					 RMI_DEV_COMM_EXIT_SEND |
					 RMI_DEV_COMM_EXIT_WAIT |
					 RMI_DEV_COMM_EXIT_MULTI);
	return pending;
}

static inline gfp_t cache_obj_id_to_gfp_flags(u8 cache_obj_id)
{
	/* These two cache objects are system objects. */
	if (cache_obj_id == RMI_DEV_VCA || cache_obj_id == RMI_DEV_CERTIFICATE)
		return GFP_KERNEL;
	/* rest are per TDI which is associated to a VM */
	return GFP_KERNEL_ACCOUNT;
}

static int _do_dev_communicate(enum dev_comm_type type, struct pci_tsm *tsm)
{
	unsigned long rmi_ret;
	gfp_t cache_alloc_flags;
	int nbytes, cp_len;
	struct cache_object **cache_objp, *cache_obj;
	struct cca_host_pf0_dsc *pf0_dsc = to_cca_pf0_dsc(tsm->dsm_dev);
	struct cca_host_comm_data *comm_data = to_cca_comm_data(tsm->pdev);
	struct rmi_dev_comm_enter *io_enter = &comm_data->io_params->enter;
	struct rmi_dev_comm_exit *io_exit = &comm_data->io_params->exit;

redo_communicate:

	if (type == PDEV_COMMUNICATE)
		rmi_ret = rmi_pdev_communicate(virt_to_phys(pf0_dsc->rmm_pdev),
					       virt_to_phys(comm_data->io_params));
	else
		rmi_ret = RMI_ERROR_INPUT;
	if (rmi_ret != RMI_SUCCESS) {
		if (rmi_ret == RMI_BUSY)
			return -EBUSY;
		return -ENXIO;
	}

	if (io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_REQ ||
	    io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_RSP) {

		switch (io_exit->cache_obj_id) {
		case RMI_DEV_VCA:
			cache_objp = &pf0_dsc->vca;
			break;
		case RMI_DEV_CERTIFICATE:
			cache_objp = &pf0_dsc->cert_chain.cache;
			break;
		default:
			return -EINVAL;
		}
		cache_obj = *cache_objp;
		cache_alloc_flags = cache_obj_id_to_gfp_flags(io_exit->cache_obj_id);
	}

	if (io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_REQ)
		cp_len = io_exit->req_cache_len;
	else
		cp_len = io_exit->rsp_cache_len;

	/* response and request len should be <= SZ_4k */
	if (cp_len > CACHE_CHUNK_SIZE)
		return -EINVAL;

	if (io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_REQ ||
	    io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_RSP) {
		int cache_remaining;

		/* new allocation */
		if (!cache_obj) {
			int obj_size = struct_size(cache_obj, buf,
						   CACHE_CHUNK_SIZE);

			cache_obj = kvmalloc(obj_size, cache_alloc_flags);
			if (!cache_obj)
				return -ENOMEM;

			cache_obj->size = CACHE_CHUNK_SIZE;
			cache_obj->offset = 0;
			*cache_objp = cache_obj;
		}

		cache_remaining = cache_obj->size - cache_obj->offset;
		if (cp_len > cache_remaining) {
			struct cache_object *new_obj;
			int new_size = struct_size(cache_obj, buf,
						   cache_obj->size +
						   CACHE_CHUNK_SIZE);

			if (cache_obj->size + CACHE_CHUNK_SIZE > MAX_CACHE_OBJ_SIZE)
				return -EINVAL;

			new_obj = kvrealloc(cache_obj, new_size, cache_alloc_flags);
			if (!new_obj)
				return -ENOMEM;
			new_obj->size = cache_obj->size + CACHE_CHUNK_SIZE;
			*cache_objp = new_obj;
		}

		/* cache object can change above. */
		cache_obj = *cache_objp;
	}


	if (io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_REQ) {
		memcpy(cache_obj->buf + cache_obj->offset,
		       (comm_data->req_buff + io_exit->req_cache_offset), io_exit->req_cache_len);
		cache_obj->offset += io_exit->req_cache_len;
	}

	if (io_exit->flags & RMI_DEV_COMM_EXIT_CACHE_RSP) {
		memcpy(cache_obj->buf + cache_obj->offset,
		       (comm_data->rsp_buff + io_exit->rsp_cache_offset), io_exit->rsp_cache_len);
		cache_obj->offset += io_exit->rsp_cache_len;
	}

	/*
	 * wait for last packet request from RMM.
	 * We should not find this because our device communication is synchronous
	 */
	if (io_exit->flags & RMI_DEV_COMM_EXIT_WAIT)
		return -ENXIO;

	/* next packet to send */
	if (io_exit->flags & RMI_DEV_COMM_EXIT_SEND) {
		nbytes = doe_send_req_resp(tsm);
		if (nbytes < 0) {
			/* report error back to RMM */
			io_enter->status = RMI_DEV_COMM_ERROR;
		} else {
			/* send response back to RMM */
			io_enter->resp_len = nbytes;
			io_enter->status = RMI_DEV_COMM_RESPONSE;
		}
	} else {
		/* no data transmitted => no data received */
		io_enter->resp_len = 0;
		io_enter->status = RMI_DEV_COMM_NONE;
	}

	if (pending_dev_communicate(io_exit))
		goto redo_communicate;

	return 0;
}

static int do_dev_communicate(enum dev_comm_type type,
				struct pci_tsm *tsm, unsigned long error_state)
{
	int ret, state = error_state;
	struct rmi_dev_comm_enter *io_enter;
	struct cca_host_pf0_dsc *pf0_dsc = to_cca_pf0_dsc(tsm->dsm_dev);

	io_enter = &pf0_dsc->comm_data.io_params->enter;
	io_enter->resp_len = 0;
	io_enter->status = RMI_DEV_COMM_NONE;

	ret = _do_dev_communicate(type, tsm);
	if (ret) {
		if (type == PDEV_COMMUNICATE)
			rmi_pdev_abort(virt_to_phys(pf0_dsc->rmm_pdev));
	} else {
		/*
		 * Some device communication error will transition the
		 * device to error state. Report that.
		 */
		if (type == PDEV_COMMUNICATE) {
			if (rmi_pdev_get_state(virt_to_phys(pf0_dsc->rmm_pdev),
					       (enum rmi_pdev_state *)&state))
				state = error_state;
		}
	}

	if (state == error_state)
		pci_err(tsm->pdev, "device communication error\n");

	return state;
}

static int wait_for_dev_state(enum dev_comm_type type, struct pci_tsm *tsm,
			      unsigned long target_state,
			      unsigned long error_state)
{
	int state;

	do {
		state = do_dev_communicate(type, tsm, error_state);

		if (state == target_state || state == error_state)
			return state;
	} while (1);

	/* can't reach */
	return error_state;
}

static int wait_for_pdev_state(struct pci_tsm *tsm, enum rmi_pdev_state target_state)
{
	return wait_for_dev_state(PDEV_COMMUNICATE, tsm, target_state, RMI_PDEV_ERROR);
}

static void pdev_state_transition_workfn(struct work_struct *work)
{
	unsigned long state;
	struct pci_tsm *tsm;
	struct dev_comm_work *setup_work;
	struct cca_host_pf0_dsc *pf0_dsc;

	setup_work = container_of(work, struct dev_comm_work, work);
	tsm = setup_work->tsm;
	pf0_dsc = to_cca_pf0_dsc(tsm->dsm_dev);

	guard(mutex)(&pf0_dsc->object_lock);
	state = wait_for_pdev_state(tsm, setup_work->target_state);
	WARN_ON(state != setup_work->target_state);

	complete(&setup_work->complete);
}

static int submit_pdev_state_transition_work(struct pci_dev *pdev, int target_state)
{
	enum rmi_pdev_state state;
	struct dev_comm_work comm_work;
	struct cca_host_pf0_dsc *pf0_dsc = to_cca_pf0_dsc(pdev);
	struct cca_host_comm_data *comm_data = to_cca_comm_data(pdev);

	INIT_WORK_ONSTACK(&comm_work.work, pdev_state_transition_workfn);
	init_completion(&comm_work.complete);
	comm_work.tsm = pdev->tsm;
	comm_work.target_state = target_state;

	queue_work(comm_data->work_queue, &comm_work.work);

	wait_for_completion(&comm_work.complete);
	destroy_work_on_stack(&comm_work.work);

	/* check if we reached target state */
	if (rmi_pdev_get_state(virt_to_phys(pf0_dsc->rmm_pdev), &state))
		return -ENXIO;

	if (state != target_state)
		/* no specific error for this */
		return -1;
	return 0;
}

int cca_pdev_ide_setup(struct pci_dev *pdev)
{
	return submit_pdev_state_transition_work(pdev, RMI_PDEV_NEEDS_KEY);
}
