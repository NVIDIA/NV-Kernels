/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MEMORY_FAILURE_H
#define _LINUX_MEMORY_FAILURE_H

#include <linux/interval_tree.h>

struct pfn_address_space;

struct pfn_address_space_ops {
	void (*failure)(struct pfn_address_space *pfn_space, unsigned long pfn);
};

struct pfn_address_space {
	struct interval_tree_node node;
	const struct pfn_address_space_ops *ops;
	struct address_space *mapping;
};

int register_pfn_address_space(struct pfn_address_space *pfn_space);
void unregister_pfn_address_space(struct pfn_address_space *pfn_space);

#endif /* _LINUX_MEMORY_FAILURE_H */
