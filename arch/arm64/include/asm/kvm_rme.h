/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#ifndef __ASM_KVM_RME_H
#define __ASM_KVM_RME_H

#include <asm/rmi_smc.h>
#include <uapi/linux/kvm.h>

/**
 * enum realm_state - State of a Realm
 */
enum realm_state {
	/**
	 * @REALM_STATE_NONE:
	 *      Realm has not yet been created. rmi_realm_create() may be
	 *      called to create the realm.
	 */
	REALM_STATE_NONE,
	/**
	 * @REALM_STATE_NEW:
	 *      Realm is under construction, not eligible for execution. Pages
	 *      may be populated with rmi_data_create().
	 */
	REALM_STATE_NEW,
	/**
	 * @REALM_STATE_ACTIVE:
	 *      Realm has been created and is eligible for execution with
	 *      rmi_rec_enter(). Pages may no longer be populated with
	 *      rmi_data_create().
	 */
	REALM_STATE_ACTIVE,
	/**
	 * @REALM_STATE_DYING:
	 *      Realm is in the process of being destroyed or has already been
	 *      destroyed.
	 */
	REALM_STATE_DYING,
	/**
	 * @REALM_STATE_DEAD:
	 *      Realm has been destroyed.
	 */
	REALM_STATE_DEAD
};

/**
 * struct realm - Additional per VM data for a Realm
 *
 * @state: The lifetime state machine for the realm
 * @rd: Kernel mapping of the Realm Descriptor (RD)
 * @params: Parameters for the RMI_REALM_CREATE command
 * @spare_page: A physical page that has been delegated to the Realm world but
 *              is otherwise free. Used to avoid temporary allocation during
 *              RTT operations.
 * @num_aux: The number of auxiliary pages required by the RMM
 * @vmid: VMID to be used by the RMM for the realm
 * @ia_bits: Number of valid Input Address bits in the IPA
 */
struct realm {
	enum realm_state state;

	void *rd;
	struct realm_params *params;

	phys_addr_t spare_page;

	unsigned long num_aux;
	unsigned int vmid;
	unsigned int ia_bits;
};

/**
 * struct realm_rec - Additional per VCPU data for a Realm
 *
 * @mpidr: MPIDR (Multiprocessor Affinity Register) value to identify this VCPU
 * @rec_page: Kernel VA of the RMM's private page for this REC
 * @aux_pages: Additional pages private to the RMM for this REC
 * @run: Kernel VA of the RmiRecRun structure shared with the RMM
 */
struct realm_rec {
	unsigned long mpidr;
	void *rec_page;
	struct page *aux_pages[REC_PARAMS_AUX_GRANULES];
	struct rec_run *run;
};

void kvm_init_rme(void);
u32 kvm_realm_ipa_limit(void);

int kvm_realm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap);
int kvm_init_realm_vm(struct kvm *kvm);
void kvm_destroy_realm(struct kvm *kvm);
void kvm_realm_destroy_rtts(struct kvm *kvm, u32 ia_bits);
int kvm_create_rec(struct kvm_vcpu *vcpu);
void kvm_destroy_rec(struct kvm_vcpu *vcpu);

void kvm_realm_unmap_range(struct kvm *kvm,
			   unsigned long ipa,
			   u64 size,
			   bool unmap_private);
int realm_set_ipa_state(struct kvm_vcpu *vcpu,
			unsigned long addr, unsigned long end,
			unsigned long ripas,
			unsigned long *top_ipa);

#define RME_RTT_BLOCK_LEVEL	2
#define RME_RTT_MAX_LEVEL	3

#define RME_PAGE_SHIFT		12
#define RME_PAGE_SIZE		BIT(RME_PAGE_SHIFT)
/* See ARM64_HW_PGTABLE_LEVEL_SHIFT() */
#define RME_RTT_LEVEL_SHIFT(l)	\
	((RME_PAGE_SHIFT - 3) * (4 - (l)) + 3)
#define RME_L2_BLOCK_SIZE	BIT(RME_RTT_LEVEL_SHIFT(2))

static inline unsigned long rme_rtt_level_mapsize(int level)
{
	if (WARN_ON(level > RME_RTT_MAX_LEVEL))
		return RME_PAGE_SIZE;

	return (1UL << RME_RTT_LEVEL_SHIFT(level));
}

static inline bool realm_is_addr_protected(struct realm *realm,
					   unsigned long addr)
{
	unsigned int ia_bits = realm->ia_bits;

	return !(addr & ~(BIT(ia_bits - 1) - 1));
}

#endif
