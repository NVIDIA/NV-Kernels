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
 * @num_aux: The number of auxiliary pages required by the RMM
 * @vmid: VMID to be used by the RMM for the realm
 * @ia_bits: Number of valid Input Address bits in the IPA
 */
struct realm {
	enum realm_state state;

	void *rd;
	struct realm_params *params;

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
	/*
	 * REC_PARAMS_AUX_GRANULES is the maximum number of 4K granules that
	 * the RMM can require. The array is sized to be large enough for the
	 * maximum number of host sized pages that could be required.
	 */
	struct page *aux_pages[(REC_PARAMS_AUX_GRANULES * SZ_4K) >> PAGE_SHIFT];
	struct rec_run *run;
};

void kvm_init_rme(void);
u32 kvm_realm_ipa_limit(void);
u32 kvm_realm_vgic_nr_lr(void);

int kvm_realm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap);
int kvm_init_realm_vm(struct kvm *kvm);
void kvm_destroy_realm(struct kvm *kvm);
void kvm_realm_destroy_rtts(struct kvm *kvm, u32 ia_bits);
int kvm_create_rec(struct kvm_vcpu *vcpu);
void kvm_destroy_rec(struct kvm_vcpu *vcpu);

int kvm_rec_enter(struct kvm_vcpu *vcpu);
int kvm_rec_pre_enter(struct kvm_vcpu *vcpu);
int handle_rec_exit(struct kvm_vcpu *vcpu, int rec_run_status);

void kvm_realm_unmap_range(struct kvm *kvm,
			   unsigned long ipa,
			   unsigned long size,
			   bool unmap_private,
			   bool may_block);
int realm_map_protected(struct realm *realm,
			unsigned long base_ipa,
			kvm_pfn_t pfn,
			unsigned long size,
			struct kvm_mmu_memory_cache *memcache);
int realm_map_non_secure(struct realm *realm,
			 unsigned long ipa,
			 kvm_pfn_t pfn,
			 unsigned long size,
			 struct kvm_mmu_memory_cache *memcache);
int realm_psci_complete(struct kvm_vcpu *source,
			struct kvm_vcpu *target,
			unsigned long status);

static inline bool kvm_realm_is_private_address(struct realm *realm,
						unsigned long addr)
{
	return !(addr & BIT(realm->ia_bits - 1));
}

#endif /* __ASM_KVM_RME_H */
