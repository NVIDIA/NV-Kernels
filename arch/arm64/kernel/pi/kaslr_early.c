// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 Google LLC
// Author: Ard Biesheuvel <ardb@google.com>

// NOTE: code in this file runs *very* early, and is not permitted to use
// global variables or anything that relies on absolute addressing.

#include <linux/libfdt.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/sizes.h>
#include <linux/string.h>

#include <asm/archrandom.h>
#include <asm/drtm.h>
#include <asm/memory.h>
#include <asm/pgtable.h>

#include "pi.h"

static u64 __init get_fdt_seed(void *fdt, int node)
{
	static char const seed_str[] __initconst = "kaslr-seed";
	fdt64_t *prop;
	u64 ret;
	int len;

	if (node < 0)
		return 0;

	prop = fdt_getprop_w(fdt, node, seed_str, &len);
	if (!prop || len != sizeof(u64))
		return 0;

	ret = fdt64_to_cpu(*prop);
	*prop = 0;
	return ret;
}

static u64 __init get_rndr_seed(void)
{
	u64 seed;

	if (__early_cpu_has_rndr() &&
	    __arm64_rndr((unsigned long *)&seed))
		return seed;

	return 0;
}

#ifdef CONFIG_ARM64_SECURE_LAUNCH

/*
 * SMCCC TRNG_RND64 (DEN0098) == ARM_SMCCC_TRNG_RND64; hardcoded to avoid the
 * heavy arm-smccc.h include in this position-independent early code.
 */
#define PI_SMCCC_TRNG_RND64	0xC4000053UL
#define PI_SMCCC_RET_SUCCESS		0
#define PI_SMCCC_RET_TRNG_NO_ENTROPY	(-3)

static bool __init __early_el3_present(void)
{
	/* ID_AA64PFR0_EL1.EL3 [15:12] != 0 => EL3 implemented => smc is legal */
	return ((read_sysreg_s(SYS_ID_AA64PFR0_EL1) >> 12) & 0xf) != 0;
}

static long __init __early_trng_rnd64(u64 *out)
{
	register u64 x0 asm("x0") = PI_SMCCC_TRNG_RND64;
	register u64 x1 asm("x1") = 64;	/* request 64 bits */
	register u64 x2 asm("x2") = 0;
	register u64 x3 asm("x3") = 0;

	asm volatile("smc #0"
		     : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
		     : : "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
			 "x12", "x13", "x14", "x15", "x16", "x17", "memory");
	if ((long)x0 == PI_SMCCC_RET_SUCCESS)
		*out = x3;	/* 64 bits requested -> entropy in X3 */

	return (long)x0;
}

static u64 __init get_trng_seed(void)
{
	long status;
	u64 seed;
	int tries;

	if (!__early_el3_present())
		return 0;

	for (tries = 0; tries < 10; tries++) {
		status = __early_trng_rnd64(&seed);
		if (status == PI_SMCCC_RET_SUCCESS)
			return seed;
		if (status != PI_SMCCC_RET_TRNG_NO_ENTROPY)
			break;
	}

	return 0;
}

#endif

static u64 __init get_kaslr_seed(void *fdt, int node)
{
	u64 fdt_seed = get_fdt_seed(fdt, node);
	u64 seed;

#ifdef CONFIG_ARM64_SECURE_LAUNCH
	if (slaunch_active()) {
		seed = get_trng_seed();
		if (!seed)
			seed = get_rndr_seed();
		return seed ? seed : fdt_seed;
	}
#endif

	return fdt_seed ? fdt_seed : get_rndr_seed();
}

u64 __init kaslr_early_init(void *fdt, int chosen)
{
	u64 seed, range;

	if (kaslr_disabled_cmdline())
		return 0;

	seed = get_kaslr_seed(fdt, chosen);
	if (!seed)
		return 0;

	/*
	 * OK, so we are proceeding with KASLR enabled. Calculate a suitable
	 * kernel image offset from the seed. Let's place the kernel in the
	 * 'middle' half of the VMALLOC area, and stay clear of the lower and
	 * upper quarters to avoid colliding with other allocations.
	 */
	range = (VMALLOC_END - KIMAGE_VADDR) / 2;
	return range / 2 + (((__uint128_t)range * seed) >> 64);
}
