// SPDX-License-Identifier: GPL-2.0-only
/*
 * Early Arm FIRME transport for ARM64 DRTM measurements.
 */

#include <linux/arm-smccc.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/string.h>

#include <asm/drtm.h>
#include <asm/memory.h>

/* DEN0149 ATTEST_EXT_CLAIMS, SMC64 fast call in the standard-service range. */
#define FIRME_ATTEST_EXT_CLAIMS					\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL, ARM_SMCCC_SMC_64,\
			   ARM_SMCCC_OWNER_STANDARD, 0x040b)
#define FIRME_MAX_MEASUREMENT_SIZE	48

/*
 * TF-A maps the page-rounded caller range. Keep the handoff in a dedicated
 * page so that validating and mapping it cannot include unrelated objects.
 */
static u8 firme_measurement_page[PAGE_SIZE] __initdata __aligned(PAGE_SIZE);

long __init slaunch_extend_measurement(const u8 *digest, size_t digest_size)
{
	struct arm_smccc_res res;

	if (!digest || !digest_size ||
	    digest_size > FIRME_MAX_MEASUREMENT_SIZE)
		return -EINVAL;

	memcpy(firme_measurement_page, digest, digest_size);

	/*
	 * setup_arch() reaches this point before the generic SMCCC conduit is
	 * initialized. FIRME is an EL3 service, so issue the SMC directly.
	 */
	arm_smccc_1_1_smc(FIRME_ATTEST_EXT_CLAIMS,
			  __pa_symbol(firme_measurement_page), digest_size,
			  CONFIG_ARM64_SECURE_LAUNCH_FIRME_SLOT, 0, &res);

	return (long)res.a0;
}
