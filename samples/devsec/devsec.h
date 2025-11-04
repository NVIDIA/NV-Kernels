/* SPDX-License-Identifier: GPL-2.0-only */
// Copyright(c) 2024 - 2025 Intel Corporation. All rights reserved.

#ifndef __DEVSEC_H__
#define __DEVSEC_H__
struct devsec_sysdata {
#ifdef CONFIG_X86
	/*
	 * Must be first member to that x86::pci_domain_nr() can type
	 * pun devsec_sysdata and pci_sysdata.
	 */
	struct pci_sysdata sd;
#else
	int domain_nr;
#endif
};

#ifdef CONFIG_X86
static inline void devsec_set_domain_nr(struct devsec_sysdata *sd,
					int domain_nr)
{
	sd->sd.domain = domain_nr;
}
static inline int devsec_get_domain_nr(struct devsec_sysdata *sd)
{
	return sd->sd.domain;
}
#else
static inline void devsec_set_domain_nr(struct devsec_sysdata *sd,
					int domain_nr)
{
	sd->domain_nr = domain_nr;
}
static inline int devsec_get_domain_nr(struct devsec_sysdata *sd)
{
	return sd->domain_nr;
}
#endif
extern struct devsec_sysdata *devsec_sysdata;
#endif /* __DEVSEC_H__ */
