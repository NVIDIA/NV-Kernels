/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2020 Intel Corporation. All rights reserved. */

#ifndef __CXL_CXL_PCI_H__
#define __CXL_CXL_PCI_H__

#include <linux/errno.h>
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

struct cxl_hdm_info;
struct cxl_pci_cache;
#ifdef CONFIG_CXL_RESET
struct cxl_hdm_info *pci_cxl_hdm_snapshot(struct pci_dev *pdev);
struct cxl_hdm_info *pci_cxl_reset_prepare(struct pci_dev *pdev,
					struct cxl_pci_cache **cachep);
int cxl_restore_state_after_pci_reset(struct pci_dev *pdev,
				      const struct cxl_hdm_info *snapshot,
				      struct cxl_pci_cache *cache,
				      bool reset_attempted, int rc, u16 *command);
int cxl_restore_command_after_pci_reset(struct pci_dev *pdev, u16 command);
bool pci_cxl_reset_capable(struct pci_dev *pdev);
int pci_cxl_reset_owned(struct pci_dev *pdev, const struct resource *owned);
#else
static inline struct cxl_hdm_info *pci_cxl_hdm_snapshot(struct pci_dev *pdev)
{
	return NULL;
}

static inline struct cxl_hdm_info *
pci_cxl_reset_prepare(struct pci_dev *pdev, struct cxl_pci_cache **cachep)
{
	*cachep = NULL;
	return NULL;
}

static inline int
cxl_restore_state_after_pci_reset(struct pci_dev *pdev,
				  const struct cxl_hdm_info *snapshot,
				  struct cxl_pci_cache *cache,
				  bool reset_attempted, int rc, u16 *command)
{
	return rc;
}

static inline int cxl_restore_command_after_pci_reset(struct pci_dev *pdev,
						      u16 command)
{
	return 0;
}

static inline bool pci_cxl_reset_capable(struct pci_dev *pdev)
{
	return false;
}

static inline int pci_cxl_reset_owned(struct pci_dev *pdev,
				      const struct resource *owned)
{
	return -ENOTTY;
}
#endif
/*
 * CXL r4.0 sec 8.1.3.1: a CXL.mem capable device reports one or two HDM
 * ranges. 00b is illegal when Mem_Capable is set and 11b is reserved.
 */
static inline bool cxl_dvsec_hdm_count_valid(unsigned int hdm_count)
{
	return hdm_count == 1 || hdm_count == 2;
}
#endif
