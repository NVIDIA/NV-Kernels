/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef NVFS_RPCRDMA_H
#define NVFS_RPCRDMA_H

#ifdef NVFS_FRWR
static int rpcrdma_nvfs_map_data(struct device *dev, struct scatterlist *sg,
				 int nents, enum dma_data_direction dma_dir,
				 bool *is_nvfs_io)
{
	int count;

	*is_nvfs_io = false;
	count = 0;
	if (nvfs_get_ops()) {
		count = nvfs_ops->nvfs_dma_map_sg_attrs(dev,
				sg,
				nents,
				dma_dir,
				DMA_ATTR_NO_WARN);

		if (unlikely(count == NVFS_IO_ERR)) {
			nvfs_put_ops();
			return -EIO;
		}

		if (unlikely(count == NVFS_CPU_REQ)) {
			nvfs_put_ops();
			return 0;
		}
		*is_nvfs_io = true;
	}
	return count;
}
#endif

static bool rpcrdma_nvfs_unmap_data(struct device *dev, struct scatterlist *sg,
				    int nents, enum dma_data_direction dma_dir)
{
	int count;

	if (nvfs_ops != NULL) {
		count = nvfs_ops->nvfs_dma_unmap_sg(dev, sg, nents,
				dma_dir);
		if (count > 0) {
			nvfs_put_ops();
			return true;
		}
	}
	return false;
}

#endif /* NVFS_RPCRDMA_H */
