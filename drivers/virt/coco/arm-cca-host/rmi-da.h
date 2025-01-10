/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025 ARM Ltd.
 */

#ifndef _VIRT_COCO_RMM_DA_H_
#define _VIRT_COCO_RMM_DA_H_

#include <linux/pci.h>
#include <linux/pci-ide.h>
#include <linux/pci-tsm.h>
#include <linux/sizes.h>
#include <asm/rmi_smc.h>

#define MAX_CACHE_OBJ_SIZE	SZ_16M
#define CACHE_CHUNK_SIZE	SZ_4K
struct cache_object {
	int size;
	int offset;
	u8 buf[] __counted_by(size);
};

struct dev_comm_work {
	struct pci_tsm *tsm;
	int target_state;
	struct work_struct work;
	struct completion complete;
};

struct cca_host_comm_data {
	void *rsp_buff;
	void *req_buff;
	struct rmi_dev_comm_data *io_params;
	/*
	 * Only one device communication request can be active at
	 * a time. This limitation comes from using the DOE mailbox
	 * at the pdev level. Requests such as get_measurements may
	 * span multiple mailbox messages, which must not be
	 * interleaved with other SPDM requests.
	 */
	struct workqueue_struct *work_queue;
};

/**
 * struct cca_host_pf0_dsc - Device Security Context for physical function 0.
 * @comm_data: Device communication context
 * @pci: Physical Function 0 TDISP link context
 * @sel_stream: Selective IDE Stream descriptor
 * @rmm_pdev: Delegated granule address of rmm pdev object
 * @num_ax: Number of auxiliary granules allocated for pdev
 * @aux: Delegated auxiliary granules
 * @rmi_signature_algorith: Signature algorith used for public key
 * @object_lock: lock used to protect access to cached obects in PF0 and TDIs
 * @cert_chain: cetrificate chain
 * @vca: SPDM's Version-Capabilities-Algorithms cache object
 */
struct cca_host_pf0_dsc {
	struct cca_host_comm_data comm_data;
	struct pci_tsm_pf0 pci;
	struct pci_ide *sel_stream;

	void *rmm_pdev;
	int num_aux;
	void *aux[MAX_PDEV_AUX_GRANULES];

	uint8_t rmi_signature_algorithm;
	struct mutex object_lock;
	struct {
		struct cache_object *cache;

		void *public_key;
		size_t public_key_size;

		bool valid;
	} cert_chain;
	struct cache_object *vca;
};

struct cca_host_fn_dsc {
	struct pci_tsm pci;
};

enum dev_comm_type {
	PDEV_COMMUNICATE = 0x1,
	VDEV_COMMUNICATE = 0x2,
};

struct cca_host_tdi {
	struct pci_tdi tdi;
	struct realm *realm;
	void *rmm_vdev;
	/* protected by cca_host_pf0_dsc.object_lock */
	struct cache_object *interface_report;
	struct cache_object *measurements;
};

static inline struct cca_host_pf0_dsc *to_cca_pf0_dsc(struct pci_dev *pdev)
{
	struct pci_tsm *tsm = pdev->tsm;

	if (!tsm || !is_pci_tsm_pf0(pdev))
		return NULL;

	return container_of(tsm, struct cca_host_pf0_dsc, pci.base_tsm);
}

static inline struct cca_host_fn_dsc *to_cca_fn_dsc(struct pci_dev *pdev)
{
	struct pci_tsm *tsm = pdev->tsm;

	return container_of(tsm, struct cca_host_fn_dsc, pci);
}

static inline struct cca_host_comm_data *to_cca_comm_data(struct pci_dev *pdev)
{
	struct cca_host_pf0_dsc *pf0_dsc;

	pf0_dsc = to_cca_pf0_dsc(pdev);
	if (pf0_dsc)
		return &pf0_dsc->comm_data;

	pf0_dsc = to_cca_pf0_dsc(pdev->tsm->dsm_dev);
	if (pf0_dsc)
		return &pf0_dsc->comm_data;

	return NULL;
}

static inline struct cca_host_tdi *to_cca_host_tdi(struct pci_dev *pdev)
{
	struct pci_tsm *tsm = pdev->tsm;

	if (!tsm || !tsm->tdi)
		return NULL;

	return container_of(tsm->tdi, struct cca_host_tdi, tdi);
}

int cca_pdev_create(struct pci_dev *pdev);
int cca_pdev_ide_setup(struct pci_dev *pdev);
void cca_pdev_stop_and_destroy(struct pci_dev *pdev);
void *cca_vdev_create(struct realm *realm, struct pci_dev *pdev,
		      struct pci_dev *pf0_dev, u32 guest_rid);
#endif
