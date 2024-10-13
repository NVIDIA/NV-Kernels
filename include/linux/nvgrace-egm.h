/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#ifndef _NVGRACE_EGM_H
#define _NVGRACE_EGM_H

int register_egm_node(struct pci_dev *pdev);
void unregister_egm_node(int egm_node);

#endif /* _NVGRACE_EGM_H */
