/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

static blk_status_t nvme_pci_setup_prps(struct nvme_dev *dev,
                struct request *req, struct nvme_rw_command *cmnd);

static blk_status_t nvme_pci_setup_sgls(struct nvme_dev *dev,
                struct request *req, struct nvme_rw_command *cmnd);

static bool nvme_nvfs_unmap_data(struct nvme_dev *dev, struct request *req)
{
        struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
        enum dma_data_direction dma_dir = rq_dma_dir(req);

        if (!iod || !iod->sgt.nents)
                return false;

        if (iod->sgt.sgl && !is_pci_p2pdma_page(sg_page(iod->sgt.sgl)) &&
                !blk_integrity_rq(req) &&
                !iod->dma_len &&
                nvfs_ops != NULL) {
                int count;
                count = nvfs_ops->nvfs_dma_unmap_sg(dev->dev, iod->sgt.sgl, iod->sgt.nents, dma_dir);
                if (!count)
                        return false;

                nvfs_put_ops();
                return true;
        }

        return false;
}

static blk_status_t nvme_nvfs_map_data(struct nvme_dev *dev, struct request *req,
               struct nvme_command *cmnd, bool *is_nvfs_io)
{
       struct nvme_iod *iod = blk_mq_rq_to_pdu(req);
       struct request_queue *q = req->q;
       enum dma_data_direction dma_dir = rq_dma_dir(req);
       blk_status_t ret = BLK_STS_RESOURCE;
       int nr_mapped;

       nr_mapped = 0;
       *is_nvfs_io = false;

       if (!blk_integrity_rq(req) && nvfs_get_ops()) {
                iod->dma_len = 0;
                iod->sgt.sgl = mempool_alloc(dev->iod_mempool, GFP_ATOMIC);
                if (!iod->sgt.sgl) {
                        nvfs_put_ops();
                        return BLK_STS_RESOURCE;
                }

               sg_init_table(iod->sgt.sgl, blk_rq_nr_phys_segments(req));
               // associates bio pages to scatterlist
               iod->sgt.orig_nents = nvfs_ops->nvfs_blk_rq_map_sg(q, req, iod->sgt.sgl);
               if (!iod->sgt.orig_nents) {
                       mempool_free(iod->sgt.sgl, dev->iod_mempool);
                       nvfs_put_ops();
                       return BLK_STS_IOERR; // reset to original ret
               }
               *is_nvfs_io = true;

               if (unlikely((iod->sgt.orig_nents == NVFS_IO_ERR))) {
                       pr_err("%s: failed to map sg_nents=:%d\n", __func__, iod->sgt.nents);
                       mempool_free(iod->sgt.sgl, dev->iod_mempool);
                       nvfs_put_ops();
                       return BLK_STS_IOERR;
               }

               nr_mapped = nvfs_ops->nvfs_dma_map_sg_attrs(dev->dev,
                               iod->sgt.sgl,
                               iod->sgt.orig_nents,
                               dma_dir,
                               DMA_ATTR_NO_WARN);


               if (unlikely((nr_mapped == NVFS_IO_ERR))) {
                       mempool_free(iod->sgt.sgl, dev->iod_mempool);
                       nvfs_put_ops();
                       pr_err("%s: failed to dma map sglist=:%d\n", __func__, iod->sgt.nents);
                       return BLK_STS_IOERR;
               }

               if (unlikely(nr_mapped == NVFS_CPU_REQ)) {
                       mempool_free(iod->sgt.sgl, dev->iod_mempool);
                       nvfs_put_ops();
                       BUG();
               }

	       iod->sgt.nents = nr_mapped;

                if (nvme_pci_use_sgls(dev, req, iod->sgt.nents)) { // TBD: not tested on SGL mode supporting drive
		       ret = nvme_pci_setup_sgls(dev, req, &cmnd->rw);
	       } else {
		       // push dma address to hw registers
                       ret = nvme_pci_setup_prps(dev, req, &cmnd->rw);
               }

               if (ret != BLK_STS_OK) {
                        nvme_nvfs_unmap_data(dev, req);
                        mempool_free(iod->sgt.sgl, dev->iod_mempool);
               }
               return ret;
       }
       return ret;
}

#endif /* NVFS_DMA_H */
