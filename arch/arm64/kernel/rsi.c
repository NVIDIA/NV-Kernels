// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#include <linux/jump_label.h>
#include <linux/memblock.h>
#include <linux/psci.h>
#include <asm/rsi.h>

struct realm_config config;

unsigned long prot_ns_shared;
EXPORT_SYMBOL(prot_ns_shared);

DEFINE_STATIC_KEY_FALSE_RO(rsi_present);
EXPORT_SYMBOL(rsi_present);

static bool rsi_version_matches(void)
{
	unsigned long ver_lower, ver_higher;
	unsigned long ret = rsi_request_version(RSI_ABI_VERSION,
						&ver_lower,
						&ver_higher);

	if (ret == SMCCC_RET_NOT_SUPPORTED)
		return false;

	if (ret != RSI_SUCCESS) {
		pr_err("RME: RMM doesn't support RSI version %lu.%lu. Supported range: %lu.%lu-%lu.%lu\n",
		       RSI_ABI_VERSION_MAJOR, RSI_ABI_VERSION_MINOR,
		       RSI_ABI_VERSION_GET_MAJOR(ver_lower),
		       RSI_ABI_VERSION_GET_MINOR(ver_lower),
		       RSI_ABI_VERSION_GET_MAJOR(ver_higher),
		       RSI_ABI_VERSION_GET_MINOR(ver_higher));
		return false;
	}

	pr_info("RME: Using RSI version %lu.%lu\n",
		RSI_ABI_VERSION_GET_MAJOR(ver_lower),
		RSI_ABI_VERSION_GET_MINOR(ver_lower));

	return true;
}

void __init arm64_rsi_setup_memory(void)
{
	u64 i;
	phys_addr_t start, end;

	if (!is_realm_world())
		return;

	/*
	 * Iterate over the available memory ranges and convert the state to
	 * protected memory. We should take extra care to ensure that we DO NOT
	 * permit any "DESTROYED" pages to be converted to "RAM".
	 *
	 * BUG_ON is used because if the attempt to switch the memory to
	 * protected has failed here, then future accesses to the memory are
	 * simply going to be reflected as a SEA (Synchronous External Abort)
	 * which we can't handle.  Bailing out early prevents the guest limping
	 * on and dying later.
	 */
	for_each_mem_range(i, &start, &end) {
		BUG_ON(rsi_set_memory_range_protected_safe(start, end));
	}
}

bool arm64_rsi_is_protected_mmio(phys_addr_t base, size_t size)
{
	enum ripas ripas;
	phys_addr_t end, top;

	/* Overflow ? */
	if (WARN_ON(base + size < base))
		return false;

	end = ALIGN(base + size, RSI_GRANULE_SIZE);
	base = ALIGN_DOWN(base, RSI_GRANULE_SIZE);

	while (base < end) {
		if (WARN_ON(rsi_ipa_state_get(base, end, &ripas, &top)))
			break;
		if (WARN_ON(top <= base))
			break;
		if (ripas != RSI_RIPAS_IO)
			break;
		base = top;
	}

	return (size && base >= end);
}
EXPORT_SYMBOL(arm64_rsi_is_protected_mmio);

void __init arm64_rsi_init(void)
{
	if (!rsi_version_matches())
		return;
	if (rsi_get_realm_config(&config))
		return;
	prot_ns_shared = BIT(config.ipa_bits - 1);

	static_branch_enable(&rsi_present);
}

