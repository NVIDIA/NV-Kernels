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

#ifndef NVFS_RDMA_H
#define NVFS_RDMA_H

#define NVFS_GPU_PAGE_SIZE	(64UL * 1024)

static bool nvme_rdma_nvfs_unmap_data(struct ib_device *ibdev,
		struct request *rq)

{
	struct nvme_rdma_request *req = blk_mq_rq_to_pdu(rq);
	enum dma_data_direction dma_dir = rq_dma_dir(rq);
	int count;

	if (!blk_integrity_rq(rq) && nvfs_ops != NULL) {
		count = nvfs_ops->nvfs_dma_unmap_sg(ibdev->dma_device, req->data_sgl.sg_table.sgl, req->data_sgl.nents,
				dma_dir);
		if (count) {
			nvfs_put_ops();
			sg_free_table_chained(&req->data_sgl.sg_table, NVME_INLINE_SG_CNT);
			return true;
		}
	}
	return false;
}

static bool nvme_rdma_nvfs_first_page_is_gpu(struct request *rq)
{
	struct req_iterator iter;
	struct bio_vec bvec;

	rq_for_each_segment(bvec, rq, iter)
		return nvfs_ops->nvfs_is_gpu_page(bvec.bv_page);

	return false;
}

static int nvme_rdma_nvfs_map_data(struct ib_device *ibdev,
				   struct request *rq, bool *is_nvfs_io,
				   bool *sg_allocated, int *count)
{
	struct nvme_rdma_request *req = blk_mq_rq_to_pdu(rq);
	enum dma_data_direction dma_dir = rq_dma_dir(rq);
	unsigned int nr_sg, gpu_nr_sg;
	int ret = 0;

	*is_nvfs_io = false;
	*sg_allocated = false;
	*count = 0;

	/*
	 * rq_for_each_segment() does not iterate RQF_SPECIAL_PAYLOAD.  Keep
	 * those requests, and operations NVFS does not support, on the normal
	 * block mapping path.  In particular, NVMe discard uses a data-less bio
	 * and stores its DSM descriptor in rq->special_vec.
	 */
	if (blk_integrity_rq(rq) ||
	    (rq->rq_flags & RQF_SPECIAL_PAYLOAD) ||
	    (req_op(rq) != REQ_OP_READ && req_op(rq) != REQ_OP_WRITE))
		return 0;

	if (nvfs_get_ops()) {
		nr_sg = blk_rq_nr_phys_segments(rq);

		/*
		 * Use the first bvec only to select the SGL allocation size.  Every
		 * eligible request still goes through the NVFS mapper so it can
		 * validate the complete request and reject mixed CPU/GPU I/O.
		 *
		 * If page classification is unavailable, retain the conservative
		 * allocation required for a possible GPU request.
		 */
		if (!NVIDIA_FS_CHECK_FT_GPU_PAGE(nvfs_ops) ||
		    !nvfs_ops->nvfs_is_gpu_page ||
		    nvme_rdma_nvfs_first_page_is_gpu(rq)) {
			/*
			 * The block layer may merge physically contiguous proxy pages
			 * into fewer segments.  GPU physical pages need not have the
			 * same contiguity.  Allow one entry per 64K GPU page, plus one
			 * for a request that starts at an offset within a GPU page.
			 */
			gpu_nr_sg = DIV_ROUND_UP(blk_rq_payload_bytes(rq),
						 NVFS_GPU_PAGE_SIZE);
			nr_sg = max_t(unsigned int, nr_sg, gpu_nr_sg + 1);
		}

		ret = sg_alloc_table_chained(&req->data_sgl.sg_table, nr_sg,
					     req->data_sgl.sg_table.sgl,
					     NVME_INLINE_SG_CNT);
		if (ret) {
			nvfs_put_ops();
			return -ENOMEM;
		}
		*sg_allocated = true;

		// associates bio pages to scatterlist
		*count = nvfs_ops->nvfs_blk_rq_map_sg(rq->q, rq , req->data_sgl.sg_table.sgl);
		if (!*count) {
			nvfs_put_ops();
			return 0; // fall to cpu path
		}

		*is_nvfs_io = true;
		if (unlikely((*count == NVFS_IO_ERR))) {
			nvfs_put_ops();
			pr_err("%s: failed to map sg_nents=:%d\n", __func__, req->data_sgl.nents);
			return -EIO;
		}
		req->data_sgl.nents = *count;

		*count = nvfs_ops->nvfs_dma_map_sg_attrs(ibdev->dma_device,
				req->data_sgl.sg_table.sgl,
				req->data_sgl.nents,
				dma_dir,
				DMA_ATTR_NO_WARN);

		if (unlikely((*count == NVFS_IO_ERR))) {
			nvfs_put_ops();
			return -EIO;
		}

		if (unlikely(*count == NVFS_CPU_REQ)) {
			nvfs_put_ops();
			return -EIO;
		}

		return ret;
	}

	// Fall to CPU path
	return 0;
}

#endif
