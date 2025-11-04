// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2024 - 2025 Intel Corporation. All rights reserved.

#include <linux/pci.h>
#include <linux/export.h>

/*
 * devsec_bus and devsec_tsm need a common location for this data to
 * avoid depending on each other. Enables load order testing
 */
struct pci_sysdata *devsec_sysdata;
EXPORT_SYMBOL_GPL(devsec_sysdata);

static int __init common_init(void)
{
	return 0;
}
module_init(common_init);

static void __exit common_exit(void)
{
}
module_exit(common_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Device Security Sample Infrastructure: Shared data");
