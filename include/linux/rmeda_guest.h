/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SPDX-FileCopyrightText: Copyright (C) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef RMEDA_GUEST_H
#define RMEDA_GUEST_H

#include <linux/types.h>

struct pci_dev;
struct rmeda_guest;
struct rmeda_guest_mapping;

#if IS_ENABLED(CONFIG_RMEDA_GUEST)

struct rmeda_guest *rmeda_guest_start_tdisp(struct pci_dev *dev);
void rmeda_guest_stop_tdisp(struct rmeda_guest *priv);
struct rmeda_guest_mapping *rmeda_guest_validate_mapping(struct rmeda_guest *priv,
							 resource_size_t start,
							 size_t size,
							 bool coherent);
void rmeda_guest_release_mapping(struct rmeda_guest_mapping *mapping);

#else

static inline struct rmeda_guest *rmeda_guest_start_tdisp(struct pci_dev *dev)
{
	return NULL;
}

static inline void rmeda_guest_stop_tdisp(struct rmeda_guest *priv)
{
}

static inline struct rmeda_guest_mapping *rmeda_guest_validate_mapping(
		struct rmeda_guest *priv,
		resource_size_t start,
		size_t size,
		bool coherent)
{
	return NULL;
}

void rmeda_guest_release_mapping(struct rmeda_guest_mapping *mapping)
{
	return -ENOTTY;
}

#endif /* defined(CONFIG_RMEDA_GUEST) || defined(CONFIG_RMEDA_GUEST_MODULE) */

#endif /* RMEDA_GUEST_H */

