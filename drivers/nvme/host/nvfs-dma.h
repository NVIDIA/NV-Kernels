/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef NVFS_DMA_H
#define NVFS_DMA_H

/* Forward declarations for functions from pci.c that we need */
static blk_status_t nvme_pci_setup_data_prp(struct request *req,
		struct blk_dma_iter *iter);
static blk_status_t nvme_pci_setup_data_sgl(struct request *req,
		struct blk_dma_iter *iter);
static inline struct dma_pool *nvme_dma_pool(struct nvme_queue *nvmeq,
		struct nvme_iod *iod);
static inline dma_addr_t nvme_pci_first_desc_dma_addr(struct nvme_command *cmd);

static inline bool nvme_nvfs_unmap_sgls(struct request *req)
{
	struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
	struct nvme_queue *nvmeq = req->mq_hctx->driver_data;
	struct device *dma_dev = nvmeq->dev->dev;
	dma_addr_t sqe_dma_addr = le64_to_cpu(iod->cmd.common.dptr.sgl.addr);
	unsigned int sqe_dma_len = le32_to_cpu(iod->cmd.common.dptr.sgl.length);
	struct nvme_sgl_desc *sg_list = iod->descriptors[0];
	enum dma_data_direction dir = rq_dma_dir(req);
        
	if (iod->nr_descriptors) {
                unsigned int nr_entries = sqe_dma_len / sizeof(*sg_list), i;

                for (i = 0; i < nr_entries; i++) {
			nvfs_ops->nvfs_dma_unmap_page(dma_dev, 
					              iod->nvfs_cookie, 
						      le64_to_cpu(sg_list[i].addr), 
						      le32_to_cpu(sg_list[i].length), 
						      dir);
		}
        } else
		nvfs_ops->nvfs_dma_unmap_page(dma_dev, iod->nvfs_cookie, sqe_dma_addr, sqe_dma_len, dir);
        
	
	
	return true;
}

static inline bool nvme_nvfs_unmap_prps(struct request *req)
{
	struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
	struct nvme_queue *nvmeq = req->mq_hctx->driver_data;
	struct device *dma_dev = nvmeq->dev->dev;
	enum dma_data_direction dma_dir = rq_dma_dir(req);
	unsigned int i;

	/* Check if dma_vecs was allocated - if setup failed early, it might be NULL */
	if (!iod->dma_vecs)
		return true;

	/* Unmap all DMA vectors - pass page pointer from dma_vecs */
	for (i = 0; i < iod->nr_dma_vecs; i++) {
		nvfs_ops->nvfs_dma_unmap_page(dma_dev, 
				              iod->nvfs_cookie, 
					      iod->dma_vecs[i].addr,
					      iod->dma_vecs[i].len,
				              dma_dir);
	}
	
	/* Free the dma_vecs mempool allocation */
	mempool_free(iod->dma_vecs, nvmeq->dev->dmavec_mempool);
	iod->dma_vecs = NULL;
	iod->nr_dma_vecs = 0;
	
	return true;
}

static inline void nvme_nvfs_free_descriptors(struct request *req)
{
	struct nvme_queue *nvmeq = req->mq_hctx->driver_data;
	const int last_prp = NVME_CTRL_PAGE_SIZE / sizeof(__le64) - 1;
	struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
	dma_addr_t dma_addr = nvme_pci_first_desc_dma_addr(&iod->cmd);
	int i;

	if (iod->nr_descriptors == 1) {
		dma_pool_free(nvme_dma_pool(nvmeq, iod), iod->descriptors[0],
				dma_addr);
		return;
	}

	for (i = 0; i < iod->nr_descriptors; i++) {
		__le64 *prp_list = iod->descriptors[i];
		dma_addr_t next_dma_addr = le64_to_cpu(prp_list[last_prp]);

		dma_pool_free(nvmeq->descriptor_pools.large, prp_list,
				dma_addr);
		dma_addr = next_dma_addr;
	}
}

static inline bool nvme_nvfs_unmap_data(struct request *req)
{
	struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
	bool ret;

	/* Check if this was an NVFS I/O by checking the IOD_NVFS_IO flag */
	if (!(iod->flags & IOD_NVFS_IO))
		return false;

	/* Clear the NVFS flag */
	iod->flags &= ~IOD_NVFS_IO;

	/* Call appropriate unmap function based on command type */
	if (nvme_pci_cmd_use_sgl(&iod->cmd))
		ret = nvme_nvfs_unmap_sgls(req);
	else
		ret = nvme_nvfs_unmap_prps(req);
	
	if (iod->nr_descriptors)
		nvme_nvfs_free_descriptors(req);

	nvfs_put_ops();
	return ret;
}

static inline blk_status_t nvme_nvfs_map_data(struct request *req, 
		bool *is_nvfs_io)
{
	struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
	struct nvme_queue *nvmeq = req->mq_hctx->driver_data;
	struct nvme_dev *dev = nvmeq->dev;
	struct device *dma_dev = nvmeq->dev->dev;
	enum nvme_use_sgl use_sgl = nvme_pci_use_sgls(dev, req);
	struct blk_dma_iter iter;
	blk_status_t ret = BLK_STS_RESOURCE;

	*is_nvfs_io = false;

	/* Check integrity and try to get nvfs_ops */
	if (blk_integrity_rq(req) || !nvfs_get_ops()) {
		return ret;
	}

	/* Initialize total_len for this request */
	iod->total_len = 0;

	if (!nvfs_ops->nvfs_blk_rq_dma_map_iter_start(req, dma_dev, 
						       &iod->dma_state, &iter, &iod->nvfs_cookie)) {
		nvfs_put_ops();
		ret = BLK_STS_IOERR;
		return ret;
	}

	/* NVFS can handle this request, set the flag */
	*is_nvfs_io = true;
	iod->flags |= IOD_NVFS_IO;

	if (use_sgl == SGL_FORCED ||
	    (use_sgl == SGL_SUPPORTED &&
	     (sgl_threshold && nvme_pci_avg_seg_size(req) >= sgl_threshold)))
		ret = nvme_pci_setup_data_sgl(req, &iter);
         else
		ret = nvme_pci_setup_data_prp(req, &iter);

	/* If setup failed, cleanup: unmap DMA, clear flag, release ops */
	if (ret != BLK_STS_OK) {
		nvme_nvfs_unmap_data(req);
	}

	return ret;
}

#endif /* NVFS_DMA_H */
