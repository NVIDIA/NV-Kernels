// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#include <linux/pci.h>
#include <linux/pci-ecam.h>
#include <linux/pci-doe.h>
#include <linux/delay.h>
#include <asm/rmi_cmds.h>
#include <crypto/internal/rsa.h>
#include <keys/asymmetric-type.h>
#include <keys/x509-parser.h>
#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <asm/kvm_rmi.h>

#include "rmi-da.h"

static int pci_dev_addr_range(struct pci_dev *pdev,
			      struct rmi_pdev_addr_range *pdev_addr)
{
	int naddr = 0;
	struct pci_dev *br;
	struct resource *mem, *pref;

	br = pci_upstream_bridge(pdev);
	if (!br)
		return 0;

	mem = pci_resource_n(br, PCI_BRIDGE_MEM_WINDOW);
	if (resource_assigned(mem)) {
		pdev_addr[naddr].base = mem->start;
		pdev_addr[naddr].top  = mem->end + 1;
		naddr++;
	}

	pref = pci_resource_n(br, PCI_BRIDGE_PREF_MEM_WINDOW);
	if (resource_assigned(pref)) {
		pdev_addr[naddr].base = pref->start;
		pdev_addr[naddr].top  = pref->end + 1;
		naddr++;
	}

	return naddr;
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
		pci_dev_addr_range(pdev, params->ncoh_addr_range);

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
	struct cca_host_tdi *host_tdi = to_cca_host_tdi(tsm->pdev);
	struct cca_host_comm_data *comm_data = to_cca_comm_data(tsm->pdev);
	struct rmi_dev_comm_enter *io_enter = &comm_data->io_params->enter;
	struct rmi_dev_comm_exit *io_exit = &comm_data->io_params->exit;

redo_communicate:

	if (type == PDEV_COMMUNICATE)
		rmi_ret = rmi_pdev_communicate(virt_to_phys(pf0_dsc->rmm_pdev),
					       virt_to_phys(comm_data->io_params));
	else
		rmi_ret = rmi_vdev_communicate(virt_to_phys(host_tdi->realm->rd),
					       virt_to_phys(pf0_dsc->rmm_pdev),
					       virt_to_phys(host_tdi->rmm_vdev),
					       virt_to_phys(comm_data->io_params));

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
		case RMI_DEV_INTERFACE_REPORT:
			cache_objp = &host_tdi->interface_report;
			break;
		case RMI_DEV_MEASUREMENTS:
			cache_objp = &host_tdi->measurements;
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
	int ret, state;
	unsigned long rmi_ret;
	struct rmi_dev_comm_enter *io_enter;
	struct cca_host_pf0_dsc *pf0_dsc = to_cca_pf0_dsc(tsm->dsm_dev);
	struct cca_host_tdi *host_tdi = to_cca_host_tdi(tsm->pdev);

	io_enter = &pf0_dsc->comm_data.io_params->enter;
	io_enter->resp_len = 0;
	io_enter->status = RMI_DEV_COMM_NONE;

	ret = _do_dev_communicate(type, tsm);
	if (ret) {
		if (type == PDEV_COMMUNICATE)
			rmi_pdev_abort(virt_to_phys(pf0_dsc->rmm_pdev));
		else
			rmi_vdev_abort(virt_to_phys(host_tdi->rmm_vdev));

		state = error_state;
	} else {
		/*
		 * Some device communication error will transition the
		 * device to error state. Report that.
		 */
		if (type == PDEV_COMMUNICATE)
			rmi_ret = rmi_pdev_get_state(virt_to_phys(pf0_dsc->rmm_pdev),
						     (enum rmi_pdev_state *)&state);
		else
			rmi_ret = rmi_vdev_get_state(virt_to_phys(host_tdi->rmm_vdev),
						     (enum rmi_vdev_state *)&state);
		if (rmi_ret)
			state = error_state;
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

static int parse_certificate_chain(struct pci_tsm *tsm)
{
	struct cca_host_pf0_dsc *pf0_dsc;
	unsigned int chain_size;
	unsigned int offset = 0;
	u8 *chain_data;

	pf0_dsc = to_cca_pf0_dsc(tsm->pdev);

	/* If device communication didn't results in certificate caching. */
	if (!pf0_dsc->cert_chain.cache || !pf0_dsc->cert_chain.cache->offset)
		return -EINVAL;

	chain_size = pf0_dsc->cert_chain.cache->offset;
	chain_data = pf0_dsc->cert_chain.cache->buf;

	while (offset < chain_size) {
		ssize_t cert_len =
			x509_get_certificate_length(chain_data + offset,
						    chain_size - offset);
		if (cert_len < 0)
			return cert_len;

		struct x509_certificate *cert __free(x509_free_certificate) =
			x509_cert_parse(chain_data + offset, cert_len);

		if (IS_ERR(cert)) {
			pci_warn(tsm->pdev, "parsing of certificate chain not successful\n");
			return PTR_ERR(cert);
		}

		/* The key in the last cert in the chain is used */
		if (offset + cert_len == chain_size) {
			void *public_key __free(kfree) =
				kzalloc(cert -> pub->keylen, GFP_KERNEL);

			if (!public_key)
				return -ENOMEM;

			if (!strcmp("ecdsa-nist-p256", cert->pub->pkey_algo))
				pf0_dsc->rmi_signature_algorithm = RMI_SIG_ECDSA_P256;
			else if (!strcmp("ecdsa-nist-p384", cert->pub->pkey_algo))
				pf0_dsc->rmi_signature_algorithm = RMI_SIG_ECDSA_P384;
			else if (!strcmp("rsa", cert->pub->pkey_algo))
				pf0_dsc->rmi_signature_algorithm = RMI_SIG_RSASSA_3072;
			else
				return -ENXIO;

			memcpy(public_key, cert->pub->key, cert->pub->keylen);
			pf0_dsc->cert_chain.public_key = no_free_ptr(public_key);
			pf0_dsc->cert_chain.public_key_size = cert->pub->keylen;
			pf0_dsc->cert_chain.valid = true;
			return 0;
		}

		offset += cert_len;
	}

	/* something wrong with chain size and parsing. */
	return -EINVAL;
}

static inline void key_param_free(struct rmi_public_key_params *param)
{
	return free_page((unsigned long)param);
}

DEFINE_FREE(key_param_free, struct rmi_public_key_params *, if (_T) key_param_free(_T))
static int pdev_set_public_key(struct pci_tsm *tsm)
{
	struct cca_host_pf0_dsc *pf0_dsc;

	pf0_dsc = to_cca_pf0_dsc(tsm->pdev);
	/* Check that all the necessary information was captured from communication */
	if (!pf0_dsc->cert_chain.valid)
		return -EINVAL;

	struct rmi_public_key_params *key_params __free(key_param_free) =
		(struct rmi_public_key_params *)get_zeroed_page(GFP_KERNEL);
	if (!key_params)
		return -ENOMEM;

	key_params->rmi_signature_algorithm = pf0_dsc->rmi_signature_algorithm;

	switch (key_params->rmi_signature_algorithm) {
	case RMI_SIG_ECDSA_P384:
	case RMI_SIG_ECDSA_P256:
	{
		key_params->public_key_len = pf0_dsc->cert_chain.public_key_size;
		memcpy(key_params->public_key,
		       pf0_dsc->cert_chain.public_key,
		       pf0_dsc->cert_chain.public_key_size);
		key_params->metadata_len = 0;
		break;
	}
	case RMI_SIG_RSASSA_3072:
	{
		int ret;
		struct rsa_key rsa_key = {0};

		ret = rsa_parse_pub_key(&rsa_key,
					pf0_dsc->cert_chain.public_key,
					pf0_dsc->cert_chain.public_key_size);
		if (ret)
			return ret;

		key_params->public_key_len = rsa_key.n_sz;
		key_params->metadata_len = rsa_key.e_sz;
		memcpy(key_params->public_key, rsa_key.n, rsa_key.n_sz);
		memcpy(key_params->metadata, rsa_key.e, rsa_key.e_sz);
		break;
	}
	default:
		return -EINVAL;
	}

	if (rmi_pdev_set_pubkey(virt_to_phys(pf0_dsc->rmm_pdev),
				virt_to_phys(key_params)))
		return -ENXIO;
	return 0;
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
	int ret;

	ret = submit_pdev_state_transition_work(pdev, RMI_PDEV_NEEDS_KEY);
	if (ret)
		return ret;
	/*
	 * we now have certificate chain in dsm->cert_chain. Parse that and set
         * the pubkey.
	 */
	ret = parse_certificate_chain(pdev->tsm);
	if (ret)
		return ret;

	ret = pdev_set_public_key(pdev->tsm);
	if (ret)
		return ret;

	return submit_pdev_state_transition_work(pdev, RMI_PDEV_READY);
}

void cca_pdev_stop_and_destroy(struct pci_dev *pdev)
{
	int ret;
	struct cca_host_pf0_dsc *pf0_dsc = to_cca_pf0_dsc(pdev);
	phys_addr_t rmm_pdev_phys = virt_to_phys(pf0_dsc->rmm_pdev);

	if (WARN_ON(rmi_pdev_stop(rmm_pdev_phys)))
		return;

	ret = submit_pdev_state_transition_work(pdev, RMI_PDEV_STOPPED);
	if (ret)
		return;

	if (WARN_ON(rmi_pdev_destroy(rmm_pdev_phys)))
		return;

	kfree(pf0_dsc->cert_chain.public_key);
	kvfree(pf0_dsc->cert_chain.cache);
	kvfree(pf0_dsc->vca);
	pf0_dsc->cert_chain.cache = NULL;
	pf0_dsc->vca = NULL;

	/* Free the aux granules */
	free_aux_pages(pf0_dsc->num_aux, pf0_dsc->aux);
	pf0_dsc->num_aux = 0;
	if (!rmi_granule_undelegate(rmm_pdev_phys))
		free_page((unsigned long)pf0_dsc->rmm_pdev);
	pf0_dsc->rmm_pdev = NULL;
}

static int wait_for_vdev_state(struct pci_tsm *tsm, enum rmi_vdev_state target_state)
{
	return wait_for_dev_state(VDEV_COMMUNICATE, tsm, target_state, RMI_VDEV_ERROR);
}

static void vdev_state_transition_workfn(struct work_struct *work)
{
	unsigned long state;
	struct pci_tsm *tsm;
	struct dev_comm_work *setup_work;
	struct cca_host_pf0_dsc *pf0_dsc;

	setup_work = container_of(work, struct dev_comm_work, work);
	tsm = setup_work->tsm;

	pf0_dsc = to_cca_pf0_dsc(tsm->dsm_dev);
	guard(mutex)(&pf0_dsc->object_lock);

	state = wait_for_vdev_state(tsm, setup_work->target_state);
	WARN_ON(state != setup_work->target_state);

	complete(&setup_work->complete);
}

static int submit_vdev_state_transition_work(struct pci_dev *pdev, int target_state)
{
	enum rmi_vdev_state state;
	struct dev_comm_work comm_work;
	struct cca_host_comm_data *comm_data = to_cca_comm_data(pdev);
	struct cca_host_tdi *host_tdi = to_cca_host_tdi(pdev);

	INIT_WORK_ONSTACK(&comm_work.work, vdev_state_transition_workfn);
	init_completion(&comm_work.complete);
	comm_work.tsm = pdev->tsm;
	comm_work.target_state = target_state;

	queue_work(comm_data->work_queue, &comm_work.work);

	wait_for_completion(&comm_work.complete);
	destroy_work_on_stack(&comm_work.work);

	/* check if we reached target state */
	if (rmi_vdev_get_state(virt_to_phys(host_tdi->rmm_vdev), &state))
		return -ENXIO;

	if (state != target_state)
		/* no specific error for this */
		return -1;
	return 0;
}

static unsigned long pci_get_tdi_id(struct pci_dev *pdev)
{
	/* requester segment is marked reserved. */
	return pci_dev_id(pdev);
}

void *cca_vdev_create(struct realm *realm, struct pci_dev *pdev,
		      struct pci_dev *pf0_dev, u32 guest_rid)
{
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	struct rmi_vdev_params *params = NULL;
	struct cca_host_pf0_dsc *pf0_dsc;
	struct cca_host_tdi *host_tdi;
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	bool should_free = true;
	void *rmm_vdev;
	int ret;

	pf0_dsc = to_cca_pf0_dsc(pf0_dev);
	if (!pf0_dsc->rmm_pdev) {
		ret = -EINVAL;
		goto err_out;
	}

	rmm_vdev = (void *)get_zeroed_page(GFP_KERNEL);
	if (!rmm_vdev) {
		ret =  -ENOMEM;
		goto err_out;
	}

	rmm_vdev_phys = virt_to_phys(rmm_vdev);
	if (rmi_granule_delegate(rmm_vdev_phys)) {
		ret = -ENXIO;
		goto err_granule_delegate;
	}

	params = (struct rmi_vdev_params *)get_zeroed_page(GFP_KERNEL);
	if (!params) {
		ret = -ENOMEM;
		goto err_params_alloc;
	}

	params->flags = 0;
	params->vdev_id = guest_rid;
	params->tdi_id = pci_get_tdi_id(pdev);
	params->num_aux = 0;

	rmm_pdev_phys = virt_to_phys(pf0_dsc->rmm_pdev);
	if (rmi_vdev_create(rd_phys, rmm_pdev_phys,
			    rmm_vdev_phys, virt_to_phys(params))) {
		ret = -ENXIO;
		goto err_vdev_create;
	}

	/* setup host_tdi before call to device communicate */
	host_tdi = to_cca_host_tdi(pdev);
	host_tdi->rmm_vdev = rmm_vdev;
	host_tdi->realm = realm;

	ret = submit_vdev_state_transition_work(pdev, RMI_VDEV_UNLOCKED);
	/* failure is treated as rmi_vdev_create failure */
	if (ret)
		goto err_vdev_comm;

	if (rmi_vdev_lock(rd_phys, rmm_pdev_phys, rmm_vdev_phys)) {
		ret = -ENXIO;
		goto err_vdev_comm;
	}

	ret = submit_vdev_state_transition_work(pdev, RMI_VDEV_LOCKED);
	if (ret)
		goto err_vdev_comm;

	free_page((unsigned long)params);
	return rmm_vdev;

err_vdev_comm:
	rmi_vdev_destroy(rd_phys, rmm_pdev_phys, rmm_vdev_phys);
err_vdev_create:
	free_page((unsigned long)params);
err_params_alloc:
	if (rmi_granule_undelegate(rmm_vdev_phys))
		should_free = false;
err_granule_delegate:
	if (should_free)
		free_page((unsigned long)rmm_vdev);
err_out:
	return ERR_PTR(ret);
}

void cca_vdev_unlock_and_destroy(struct realm *realm,
				 struct pci_dev *pdev, struct pci_dev *pf0_dev)
{
	int ret;
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	struct cca_host_pf0_dsc *pf0_dsc;
	struct cca_host_tdi *host_tdi;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);

	host_tdi = to_cca_host_tdi(pdev);
	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);

	pf0_dsc = to_cca_pf0_dsc(pf0_dev);
	rmm_pdev_phys = virt_to_phys(pf0_dsc->rmm_pdev);
	if (rmi_vdev_unlock(rd_phys, rmm_pdev_phys, rmm_vdev_phys)) {
		pci_err(pdev, "failed to unlock vdev\n");
		return;
	}

	ret = submit_vdev_state_transition_work(pdev, RMI_VDEV_UNLOCKED);
	if (ret) {
		pci_err(pdev, "failed to unlock vdev (%d)\n", ret);
		return;
	}

	if (rmi_vdev_destroy(rd_phys, rmm_pdev_phys, rmm_vdev_phys))
		pci_err(pdev, "failed to destroy vdev\n");

	if (!rmi_granule_undelegate(rmm_vdev_phys))
		free_page((unsigned long)host_tdi->rmm_vdev);
	host_tdi->rmm_vdev = NULL;
	host_tdi->realm = NULL;
}

static void vdev_fetch_object_workfn(struct work_struct *work)
{
	int state;
	struct pci_tsm *tsm;
	struct cca_host_pf0_dsc *pf0_dsc;
	struct dev_comm_work *setup_work;

	setup_work = container_of(work, struct dev_comm_work, work);
	tsm = setup_work->tsm;
	pf0_dsc = to_cca_pf0_dsc(tsm->dsm_dev);

	guard(mutex)(&pf0_dsc->object_lock);

	if (setup_work->cache_size) {
		memset(setup_work->cache_buf, 0, setup_work->cache_size);
		*setup_work->cache_offset = 0;
	}
	state = do_dev_communicate(VDEV_COMMUNICATE, tsm, RMI_VDEV_ERROR);
	/* return status through dev_comm_work.cache_cache */
	if (state == RMI_VDEV_ERROR)
		setup_work->cache_size = 0;
	else
		/* indicate success. This value is not used. */
		setup_work->cache_size = CACHE_CHUNK_SIZE;

	complete(&setup_work->complete);
}

int cca_vdev_get_object_size(struct pci_dev *pdev, int type)
{
	long len;
	struct pci_tsm *tsm = pdev->tsm;
	struct cca_host_pf0_dsc *pf0_dsc;
	struct cca_host_tdi *host_tdi;

	if (!tsm)
		return -EINVAL;

	pf0_dsc = to_cca_pf0_dsc(tsm->dsm_dev);
	host_tdi = to_cca_host_tdi(pdev);

	guard(mutex)(&pf0_dsc->object_lock);
	/* Determine the buffer that should be used */
	if (type == RHI_DA_OBJECT_INTERFACE_REPORT) {
		if (!host_tdi->interface_report)
			return -EINVAL;
		len = host_tdi->interface_report->offset;
	} else if (type == RHI_DA_OBJECT_MEASUREMENT) {
		if (!host_tdi->measurements)
			return -EINVAL;
		len = host_tdi->measurements->offset;
	} else if (type == RHI_DA_OBJECT_CERTIFICATE) {
		if (!pf0_dsc->cert_chain.cache)
			return -EINVAL;
		len = pf0_dsc->cert_chain.cache->offset;
	} else if (type == RHI_DA_OBJECT_VCA) {
		if (!pf0_dsc->vca)
			return -EINVAL;
		len = pf0_dsc->vca->offset;
	} else {
		return -EINVAL;
	}

	return len;
}

int cca_vdev_read_cached_object(struct pci_dev *pdev, int type,
				unsigned long offset,
				unsigned long max_len, void __user *user_buf)
{
	void *buf;
	unsigned long len;
	struct cca_host_pf0_dsc *pf0_dsc;
	struct cca_host_tdi *host_tdi;
	struct pci_tsm *tsm = pdev->tsm;

	if (!tsm)
		return -EINVAL;

	pf0_dsc = to_cca_pf0_dsc(tsm->dsm_dev);
	host_tdi = to_cca_host_tdi(pdev);

	guard(mutex)(&pf0_dsc->object_lock);
	/* Determine the buffer that should be used */
	if (type == RHI_DA_OBJECT_INTERFACE_REPORT) {
		if (!host_tdi->interface_report)
			return -EINVAL;
		len = host_tdi->interface_report->offset;
		buf = host_tdi->interface_report->buf;
	} else if (type == RHI_DA_OBJECT_MEASUREMENT) {
		if (!host_tdi->measurements)
			return -EINVAL;
		len = host_tdi->measurements->offset;
		buf = host_tdi->measurements->buf;
	} else if (type == RHI_DA_OBJECT_CERTIFICATE) {
		if (!pf0_dsc->cert_chain.cache)
			return -EINVAL;
		len = pf0_dsc->cert_chain.cache->offset;
		buf = pf0_dsc->cert_chain.cache->buf;
	} else if (type == RHI_DA_OBJECT_VCA) {
		if (!pf0_dsc->vca)
			return -EINVAL;
		len = pf0_dsc->vca->offset;
		buf = pf0_dsc->vca->buf;
	} else {
		return -EINVAL;
	}

	/* Assume that the buffer is large enough for the whole report */
	if ((max_len - offset) < len)
		return -E2BIG;

	if (copy_to_user(user_buf + offset, buf, len))
		return -EIO;

	return len;
}

static int vdev_update_interface_report_cache(struct pci_dev *pdev)
{
	struct dev_comm_work comm_work;
	struct cca_host_tdi *host_tdi = to_cca_host_tdi(pdev);
	struct cca_host_comm_data *comm_data = to_cca_comm_data(pdev);

	INIT_WORK_ONSTACK(&comm_work.work, vdev_fetch_object_workfn);
	init_completion(&comm_work.complete);
	comm_work.tsm = pdev->tsm;
	if (host_tdi->interface_report) {
		comm_work.cache_buf = host_tdi->interface_report->buf;
		comm_work.cache_offset = &host_tdi->interface_report->offset;
		comm_work.cache_size = host_tdi->interface_report->size;
	} else {
		comm_work.cache_buf = NULL;
		comm_work.cache_offset = NULL;
		comm_work.cache_size = 0;
	}

	queue_work(comm_data->work_queue, &comm_work.work);
	wait_for_completion(&comm_work.complete);
	destroy_work_on_stack(&comm_work.work);

	if (comm_work.cache_size == 0)
		return -ENXIO;
	return 0;
}

int cca_vdev_get_interface_report(struct pci_dev *pdev)
{
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	struct cca_host_pf0_dsc *pf0_dsc;
	struct cca_host_tdi *host_tdi;
	struct realm *realm;
	phys_addr_t rd_phys;

	host_tdi = to_cca_host_tdi(pdev);
	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);
	realm = &host_tdi->tdi.kvm->arch.realm;
	rd_phys = virt_to_phys(realm->rd);

	pf0_dsc = to_cca_pf0_dsc(pdev->tsm->dsm_dev);
	rmm_pdev_phys = virt_to_phys(pf0_dsc->rmm_pdev);

	if (rmi_vdev_get_interface_report(rd_phys,
					  rmm_pdev_phys, rmm_vdev_phys))
		return -ENXIO;

	/* get and update the interface report cache. */
	return vdev_update_interface_report_cache(pdev);
}

static int vdev_update_device_measurements_cache(struct pci_dev *pdev)
{
	struct dev_comm_work comm_work;
	struct cca_host_tdi *host_tdi = to_cca_host_tdi(pdev);
	struct cca_host_comm_data *comm_data = to_cca_comm_data(pdev);

	INIT_WORK_ONSTACK(&comm_work.work, vdev_fetch_object_workfn);
	init_completion(&comm_work.complete);
	comm_work.tsm = pdev->tsm;
	if (host_tdi->measurements) {
		comm_work.cache_buf = host_tdi->measurements->buf;
		comm_work.cache_offset = &host_tdi->measurements->offset;
		comm_work.cache_size = host_tdi->measurements->size;
	} else {
		comm_work.cache_buf = NULL;
		comm_work.cache_offset = NULL;
		comm_work.cache_size = 0;
	}

	queue_work(comm_data->work_queue, &comm_work.work);
	wait_for_completion(&comm_work.complete);
	destroy_work_on_stack(&comm_work.work);

	if (comm_work.cache_size == 0)
		return -ENXIO;
	return 0;
}

static inline void vdev_measurement_param_free(struct rmi_vdev_measurement_params *param)
{
	return free_page((unsigned long)param);
}
DEFINE_FREE(measurement_param_free, struct rmi_vdev_measurement_params *, if (_T) vdev_measurement_param_free(_T))

int cca_vdev_get_device_measurements(struct pci_dev *pdev, unsigned long flags,
				     u8 *indices, u8 *nonce)
{
	struct realm *realm;
	phys_addr_t rd_phys;
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	struct cca_host_tdi *host_tdi;
	struct cca_host_pf0_dsc *pf0_dsc;

	host_tdi = to_cca_host_tdi(pdev);
	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);
	realm = &host_tdi->tdi.kvm->arch.realm;
	rd_phys = virt_to_phys(realm->rd);

	pf0_dsc = to_cca_pf0_dsc(pdev->tsm->dsm_dev);
	rmm_pdev_phys = virt_to_phys(pf0_dsc->rmm_pdev);

	struct rmi_vdev_measurement_params *params __free(measurement_param_free) =
		(struct rmi_vdev_measurement_params *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!params)
		return -ENOMEM;

	params->flags = flags;
	if (copy_from_user(params->indices, indices, sizeof(params->indices)))
		return -EFAULT;

	if (copy_from_user(params->nonce, nonce, sizeof(params->nonce)))
		return -EFAULT;

	if (rmi_vdev_get_device_measurements(rd_phys, rmm_pdev_phys,
					     rmm_vdev_phys, virt_to_phys(params)))
		return -ENXIO;

	/* get and update the interface report cache. */
	return vdev_update_device_measurements_cache(pdev);
}

int cca_vdev_device_request(struct pci_dev *pdev, unsigned long vcpu_fd)
{
	struct kvm *kvm;
	struct kvm_vcpu *vcpu;
	unsigned long rec_phys;
	struct cca_host_tdi *host_tdi = NULL;
	struct file *vcpu_filp __free(fput) = fget(vcpu_fd);

	if (!file_is_vcpu(vcpu_filp))
		return -EINVAL;

	vcpu = vcpu_filp->private_data;
	if (!vcpu)
		return -EINVAL;

	rec_phys = virt_to_phys(vcpu->arch.rec.rec_page);
	host_tdi = to_cca_host_tdi(pdev);
	if (!host_tdi)
		return -EINVAL;

	kvm = host_tdi->tdi.kvm;
	/* make sure this is the same vm */
	if (vcpu->kvm != kvm)
		return -EINVAL;

	if (rmi_vdev_complete(rec_phys, virt_to_phys(host_tdi->rmm_vdev)))
		return -ENXIO;
	return 0;
}

int cca_vdev_device_map_validate(struct pci_dev *pdev, unsigned long vcpu_fd,
				 unsigned long gpa_base, unsigned long gpa_top,
				 unsigned long pa_base)
{
	struct kvm *kvm;
	struct realm *realm;
	phys_addr_t rec_phys;
	struct kvm_vcpu *vcpu;
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	struct cca_host_tdi *host_tdi;
	struct cca_host_pf0_dsc *pf0_dsc;
	struct file *vcpu_filp __free(fput) = fget(vcpu_fd);

	if (!file_is_vcpu(vcpu_filp))
		return -EINVAL;

	vcpu = vcpu_filp->private_data;
	if (!vcpu)
		return -EINVAL;

	host_tdi = to_cca_host_tdi(pdev);
	pf0_dsc = to_cca_pf0_dsc(pdev->tsm->dsm_dev);
	kvm = host_tdi->tdi.kvm;
	realm = &kvm->arch.realm;
	rec_phys = virt_to_phys(vcpu->arch.rec.rec_page);
	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);
	rmm_pdev_phys = virt_to_phys(pf0_dsc->rmm_pdev);

	/* make sure this is the same vm */
	if (vcpu->kvm != kvm)
		return -EINVAL;

	return realm_dev_mem_map(kvm, rec_phys, rmm_pdev_phys,
				 rmm_vdev_phys, gpa_base, gpa_top, pa_base);
}

int cca_vdev_device_start(struct pci_dev *pdev)
{
	phys_addr_t rmm_pdev_phys;
	phys_addr_t rmm_vdev_phys;
	struct cca_host_pf0_dsc *pf0_dsc;
	struct cca_host_tdi *host_tdi;
	struct realm *realm;
	phys_addr_t rd_phys;

	host_tdi = to_cca_host_tdi(pdev);
	rmm_vdev_phys = virt_to_phys(host_tdi->rmm_vdev);
	realm = &host_tdi->tdi.kvm->arch.realm;
	rd_phys = virt_to_phys(realm->rd);

	pf0_dsc = to_cca_pf0_dsc(pdev->tsm->dsm_dev);
	rmm_pdev_phys = virt_to_phys(pf0_dsc->rmm_pdev);

	if (rmi_vdev_start(rd_phys, rmm_pdev_phys, rmm_vdev_phys))
		return -ENXIO;
	return submit_vdev_state_transition_work(pdev, RMI_VDEV_STARTED);
}
