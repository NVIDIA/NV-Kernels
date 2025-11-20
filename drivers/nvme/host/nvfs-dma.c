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
#ifdef CONFIG_NVFS
#define NVFS_USE_DMA_ITER_API
#define MODULE_PREFIX nvme_v2
#include "nvfs.h"

struct nvfs_dma_rw_blk_iter_ops *nvfs_ops = NULL;

atomic_t nvfs_shutdown = ATOMIC_INIT(1);

DEFINE_PER_CPU(long, nvfs_n_ops);

#define NVIDIA_FS_COMPAT_FT(ops) \
	(NVIDIA_FS_CHECK_FT_BLK_DMA_MAP_ITER_START(ops) && NVIDIA_FS_CHECK_FT_BLK_DMA_MAP_ITER_NEXT(ops))

// protected via nvfs_module_mutex
int REGISTER_FUNC(struct nvfs_dma_rw_blk_iter_ops *ops)
{
	if (NVIDIA_FS_COMPAT_FT(ops)) {
		nvfs_ops = ops;
		atomic_set(&nvfs_shutdown, 0);
		return 0;
	} else
		return -EOPNOTSUPP;

}
EXPORT_SYMBOL_GPL(REGISTER_FUNC);

// protected via nvfs_module_mutex
void UNREGISTER_FUNC(void)
{
	(void) atomic_cmpxchg(&nvfs_shutdown, 0, 1);
	do {
		msleep(NVFS_HOLD_TIME_MS);
	} while(nvfs_count_ops());
	nvfs_ops = NULL;
}
EXPORT_SYMBOL_GPL(UNREGISTER_FUNC);
#endif
