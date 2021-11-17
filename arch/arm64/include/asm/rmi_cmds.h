/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#ifndef __ASM_RMI_CMDS_H
#define __ASM_RMI_CMDS_H

#include <linux/arm-smccc.h>

#include <asm/rmi_smc.h>

struct rtt_entry {
	unsigned long walk_level;
	unsigned long desc;
	int state;
	int ripas;
};

/**
 * rmi_data_create() - Create a Data Granule
 * @rd: PA of the RD
 * @data: PA of the target granule
 * @ipa: IPA at which the granule will be mapped in the guest
 * @src: PA of the source granule
 * @flags: RMI_MEASURE_CONTENT if the contents should be measured
 *
 * Create a new Data Granule, copying contents from a Non-secure Granule.
 *
 * Return: RMI return code
 */
static inline int rmi_data_create(unsigned long rd, unsigned long data,
				  unsigned long ipa, unsigned long src,
				  unsigned long flags)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_DATA_CREATE, rd, data, ipa, src,
			     flags, &res);

	return res.a0;
}

/**
 * rmi_data_create_unknown() - Create a Data Granule with unknown contents
 * @rd: PA of the RD
 * @data: PA of the target granule
 * @ipa: IPA at which the granule will be mapped in the guest
 *
 * Create a new Data Granule with unknown contents
 *
 * Return: RMI return code
 */
static inline int rmi_data_create_unknown(unsigned long rd,
					  unsigned long data,
					  unsigned long ipa)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_DATA_CREATE_UNKNOWN, rd, data, ipa, &res);

	return res.a0;
}

/**
 * rmi_data_destroy() - Destroy a Data Granule
 * @rd: PA of the RD
 * @ipa: IPA at which the granule is mapped in the guest
 * @data_out: PA of the granule which was destroyed
 * @top_out: Top IPA of non-live RTT entries
 *
 * Unmap a protected IPA from stage 2, transitioning it to DESTROYED.
 * The IPA cannot be used by the guest unless it is transitioned to RAM again
 * by the Realm guest.
 *
 * Return: RMI return code
 */
static inline int rmi_data_destroy(unsigned long rd, unsigned long ipa,
				   unsigned long *data_out,
				   unsigned long *top_out)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_DATA_DESTROY, rd, ipa, &res);

	if (data_out)
		*data_out = res.a1;
	if (top_out)
		*top_out = res.a2;

	return res.a0;
}

/**
 * rmi_features() - Read feature register
 * @index: Feature register index
 * @out: Feature register value is written to this pointer
 *
 * Return: RMI return code
 */
static inline int rmi_features(unsigned long index, unsigned long *out)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_FEATURES, index, &res);

	if (out)
		*out = res.a1;
	return res.a0;
}

/**
 * rmi_granule_delegate() - Delegate a Granule
 * @phys: PA of the Granule
 *
 * Delegate a Granule for use by the Realm World.
 *
 * Return: RMI return code
 */
static inline int rmi_granule_delegate(unsigned long phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_GRANULE_DELEGATE, phys, &res);

	return res.a0;
}

/**
 * rmi_granule_undelegate() - Undelegate a Granule
 * @phys: PA of the Granule
 *
 * Undelegate a Granule to allow use by the Normal World. Will fail if the
 * Granule is in use.
 *
 * Return: RMI return code
 */
static inline int rmi_granule_undelegate(unsigned long phys)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_GRANULE_UNDELEGATE, phys, &res);

	return res.a0;
}

/**
 * rmi_psci_complete() - Complete pending PSCI command
 * @calling_rec: PA of the calling REC
 * @target_rec: PA of the target REC
 * @status: Status of the PSCI request
 *
 * Completes a pending PSCI command which was called with an MPIDR argument, by
 * providing the corresponding REC.
 *
 * Return: RMI return code
 */
static inline int rmi_psci_complete(unsigned long calling_rec,
				    unsigned long target_rec,
				    unsigned long status)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_PSCI_COMPLETE, calling_rec, target_rec,
			     status, &res);

	return res.a0;
}

/**
 * rmi_realm_activate() - Active a Realm
 * @rd: PA of the RD
 *
 * Mark a Realm as Active signalling that creation is complete and allowing
 * execution of the Realm.
 *
 * Return: RMI return code
 */
static inline int rmi_realm_activate(unsigned long rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REALM_ACTIVATE, rd, &res);

	return res.a0;
}

/**
 * rmi_realm_create() - Create a Realm
 * @rd: PA of the RD
 * @params_ptr: PA of Realm parameters
 *
 * Create a new Realm using the given parameters.
 *
 * Return: RMI return code
 */
static inline int rmi_realm_create(unsigned long rd, unsigned long params_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REALM_CREATE, rd, params_ptr, &res);

	return res.a0;
}

/**
 * rmi_realm_destroy() - Destroy a Realm
 * @rd: PA of the RD
 *
 * Destroys a Realm, all objects belonging to the Realm must be destroyed first.
 *
 * Return: RMI return code
 */
static inline int rmi_realm_destroy(unsigned long rd)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REALM_DESTROY, rd, &res);

	return res.a0;
}

/**
 * rmi_rec_aux_count() - Get number of auxiliary Granules required
 * @rd: PA of the RD
 * @aux_count: Number of pages written to this pointer
 *
 * A REC may require extra auxiliary pages to be delegated for the RMM to
 * store metadata (not visible to the normal world) in. This function provides
 * the number of pages that are required.
 *
 * Return: RMI return code
 */
static inline int rmi_rec_aux_count(unsigned long rd, unsigned long *aux_count)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REC_AUX_COUNT, rd, &res);

	if (aux_count)
		*aux_count = res.a1;
	return res.a0;
}

/**
 * rmi_rec_create() - Create a REC
 * @rd: PA of the RD
 * @rec: PA of the target REC
 * @params_ptr: PA of REC parameters
 *
 * Create a REC using the parameters specified in the struct rec_params pointed
 * to by @params_ptr.
 *
 * Return: RMI return code
 */
static inline int rmi_rec_create(unsigned long rd, unsigned long rec,
				 unsigned long params_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REC_CREATE, rd, rec, params_ptr, &res);

	return res.a0;
}

/**
 * rmi_rec_destroy() - Destroy a REC
 * @rec: PA of the target REC
 *
 * Destroys a REC. The REC must not be running.
 *
 * Return: RMI return code
 */
static inline int rmi_rec_destroy(unsigned long rec)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REC_DESTROY, rec, &res);

	return res.a0;
}

/**
 * rmi_rec_enter() - Enter a REC
 * @rec: PA of the target REC
 * @run_ptr: PA of RecRun structure
 *
 * Starts (or continues) execution within a REC.
 *
 * Return: RMI return code
 */
static inline int rmi_rec_enter(unsigned long rec, unsigned long run_ptr)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_REC_ENTER, rec, run_ptr, &res);

	return res.a0;
}

/**
 * rmi_rtt_create() - Creates an RTT
 * @rd: PA of the RD
 * @rtt: PA of the target RTT
 * @ipa: Base of the IPA range described by the RTT
 * @level: Depth of the RTT within the tree
 *
 * Creates an RTT (Realm Translation Table) at the specified level for the
 * translation of the specified address within the Realm.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_create(unsigned long rd, unsigned long rtt,
				 unsigned long ipa, long level)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_CREATE, rd, rtt, ipa, level, &res);

	return res.a0;
}

/**
 * rmi_rtt_destroy() - Destroy an RTT
 * @rd: PA of the RD
 * @ipa: Base of the IPA range described by the RTT
 * @level: Depth of the RTT within the tree
 * @out_rtt: Pointer to write the PA of the RTT which was destroyed
 * @out_top: Pointer to write the top IPA of non-live RTT entries
 *
 * Destroys an RTT. The RTT must be non-live, i.e. none of the entries in the
 * table are in ASSIGNED or TABLE state.
 *
 * Return: RMI return code.
 */
static inline int rmi_rtt_destroy(unsigned long rd,
				  unsigned long ipa,
				  long level,
				  unsigned long *out_rtt,
				  unsigned long *out_top)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_DESTROY, rd, ipa, level, &res);

	if (out_rtt)
		*out_rtt = res.a1;
	if (out_top)
		*out_top = res.a2;

	return res.a0;
}

/**
 * rmi_rtt_fold() - Fold an RTT
 * @rd: PA of the RD
 * @ipa: Base of the IPA range described by the RTT
 * @level: Depth of the RTT within the tree
 * @out_rtt: Pointer to write the PA of the RTT which was destroyed
 *
 * Folds an RTT. If all entries with the RTT are 'homogeneous' the RTT can be
 * folded into the parent and the RTT destroyed.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_fold(unsigned long rd, unsigned long ipa,
			       long level, unsigned long *out_rtt)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_FOLD, rd, ipa, level, &res);

	if (out_rtt)
		*out_rtt = res.a1;

	return res.a0;
}

/**
 * rmi_rtt_init_ripas() - Set RIPAS for new Realm
 * @rd: PA of the RD
 * @base: Base of target IPA region
 * @top: Top of target IPA region
 * @out_top: Top IPA of range whose RIPAS was modified
 *
 * Sets the RIPAS of a target IPA range to RAM, for a Realm in the NEW state.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_init_ripas(unsigned long rd, unsigned long base,
				     unsigned long top, unsigned long *out_top)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_INIT_RIPAS, rd, base, top, &res);

	if (out_top)
		*out_top = res.a1;

	return res.a0;
}

/**
 * rmi_rtt_map_unprotected() - Map NS pages into a Realm
 * @rd: PA of the RD
 * @ipa: Base IPA of the mapping
 * @level: Depth within the RTT tree
 * @desc: RTTE descriptor
 *
 * Create a mapping from an Unprotected IPA to a Non-secure PA.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_map_unprotected(unsigned long rd,
					  unsigned long ipa,
					  long level,
					  unsigned long desc)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_MAP_UNPROTECTED, rd, ipa, level,
			     desc, &res);

	return res.a0;
}

/**
 * rmi_rtt_read_entry() - Read an RTTE
 * @rd: PA of the RD
 * @ipa: IPA for which to read the RTTE
 * @level: RTT level at which to read the RTTE
 * @rtt: Output structure describing the RTTE
 *
 * Reads a RTTE (Realm Translation Table Entry).
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_read_entry(unsigned long rd, unsigned long ipa,
				     long level, struct rtt_entry *rtt)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_RTT_READ_ENTRY,
		rd, ipa, level
	};

	arm_smccc_1_2_smc(&regs, &regs);

	rtt->walk_level = regs.a1;
	rtt->state = regs.a2 & 0xFF;
	rtt->desc = regs.a3;
	rtt->ripas = regs.a4 & 0xFF;

	return regs.a0;
}

/**
 * rmi_rtt_set_ripas() - Set RIPAS for an running Realm
 * @rd: PA of the RD
 * @rec: PA of the REC making the request
 * @base: Base of target IPA region
 * @top: Top of target IPA region
 * @out_top: Pointer to write top IPA of range whose RIPAS was modified
 *
 * Completes a request made by the Realm to change the RIPAS of a target IPA
 * range.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_set_ripas(unsigned long rd, unsigned long rec,
				    unsigned long base, unsigned long top,
				    unsigned long *out_top)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_SET_RIPAS, rd, rec, base, top, &res);

	if (out_top)
		*out_top = res.a1;

	return res.a0;
}

/**
 * rmi_rtt_unmap_unprotected() - Remove a NS mapping
 * @rd: PA of the RD
 * @ipa: Base IPA of the mapping
 * @level: Depth within the RTT tree
 * @out_top: Pointer to write top IPA of non-live RTT entries
 *
 * Removes a mapping at an Unprotected IPA.
 *
 * Return: RMI return code
 */
static inline int rmi_rtt_unmap_unprotected(unsigned long rd,
					    unsigned long ipa,
					    long level,
					    unsigned long *out_top)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(SMC_RMI_RTT_UNMAP_UNPROTECTED, rd, ipa,
			     level, &res);

	if (out_top)
		*out_top = res.a1;

	return res.a0;
}

#endif
