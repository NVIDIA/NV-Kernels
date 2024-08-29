// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef NVGRACE_EGM_H
#define NVGRACE_EGM_H

int register_egm_node(struct pci_dev *pdev);
void unregister_egm_node(int egm_node);

#endif /* NVGRACE_EGM_H */
