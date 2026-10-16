/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2020 Intel Corporation. All rights reserved. */

#ifndef __CXL_CXL_PCI_H__
#define __CXL_CXL_PCI_H__

#include <linux/types.h>

/* Register Block Identifier (RBI) */
enum cxl_regloc_type {
	CXL_REGLOC_RBI_EMPTY = 0,
	CXL_REGLOC_RBI_COMPONENT,
	CXL_REGLOC_RBI_VIRT,
	CXL_REGLOC_RBI_MEMDEV,
	CXL_REGLOC_RBI_PMU,
	CXL_REGLOC_RBI_TYPES
};

struct cxl_register_map;
struct pci_dev;
struct resource;

int cxl_pci_setup_regs(struct pci_dev *pdev, enum cxl_regloc_type type,
		       struct cxl_register_map *map);
int cxl_reg_map_set_owned_resource(struct cxl_register_map *map,
				   struct resource *res);
int cxl_find_regblock(struct pci_dev *pdev, enum cxl_regloc_type type,
		      struct cxl_register_map *map);
int cxl_setup_regs(struct cxl_register_map *map);
/*
 * CXL r4.0 sec 8.1.3.1: a CXL.mem capable device reports one or two HDM
 * ranges. 00b is illegal when Mem_Capable is set and 11b is reserved.
 */
static inline bool cxl_dvsec_hdm_count_valid(unsigned int hdm_count)
{
	return hdm_count == 1 || hdm_count == 2;
}
#endif
