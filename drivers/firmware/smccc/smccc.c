// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Arm Limited
 */

#define pr_fmt(fmt) "smccc: " fmt

#include <linux/cache.h>
#include <linux/init.h>
#include <linux/arm-smccc.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/auxiliary_bus.h>

#include <asm/archrandom.h>
#ifdef CONFIG_ARM64
#include <asm/rsi_cmds.h>
#endif

static u32 smccc_version = ARM_SMCCC_VERSION_1_0;
static enum arm_smccc_conduit smccc_conduit = SMCCC_CONDUIT_NONE;

bool __ro_after_init smccc_trng_available = false;
s32 __ro_after_init smccc_soc_id_version = SMCCC_RET_NOT_SUPPORTED;
s32 __ro_after_init smccc_soc_id_revision = SMCCC_RET_NOT_SUPPORTED;

void __init arm_smccc_version_init(u32 version, enum arm_smccc_conduit conduit)
{
	struct arm_smccc_res res;

	smccc_version = version;
	smccc_conduit = conduit;

	smccc_trng_available = smccc_probe_trng();

	if ((smccc_version >= ARM_SMCCC_VERSION_1_2) &&
	    (smccc_conduit != SMCCC_CONDUIT_NONE)) {
		arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_FEATURES_FUNC_ID,
				     ARM_SMCCC_ARCH_SOC_ID, &res);
		if ((s32)res.a0 >= 0) {
			arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_SOC_ID, 0, &res);
			smccc_soc_id_version = (s32)res.a0;
			arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_SOC_ID, 1, &res);
			smccc_soc_id_revision = (s32)res.a0;
		}
	}
}

enum arm_smccc_conduit arm_smccc_1_1_get_conduit(void)
{
	if (smccc_version < ARM_SMCCC_VERSION_1_1)
		return SMCCC_CONDUIT_NONE;

	return smccc_conduit;
}
EXPORT_SYMBOL_GPL(arm_smccc_1_1_get_conduit);

u32 arm_smccc_get_version(void)
{
	return smccc_version;
}
EXPORT_SYMBOL_GPL(arm_smccc_get_version);

s32 arm_smccc_get_soc_id_version(void)
{
	return smccc_soc_id_version;
}

s32 arm_smccc_get_soc_id_revision(void)
{
	return smccc_soc_id_revision;
}
EXPORT_SYMBOL_GPL(arm_smccc_get_soc_id_revision);

bool arm_smccc_hypervisor_has_uuid(const uuid_t *hyp_uuid)
{
	struct arm_smccc_res res = {};
	uuid_t uuid;

	arm_smccc_1_1_invoke(ARM_SMCCC_VENDOR_HYP_CALL_UID_FUNC_ID, &res);
	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		return false;

	uuid = smccc_res_to_uuid(res.a0, res.a1, res.a2, res.a3);
	return uuid_equal(&uuid, hyp_uuid);
}
EXPORT_SYMBOL_GPL(arm_smccc_hypervisor_has_uuid);

#ifdef CONFIG_ARM64
static void __init register_rsi_device(struct platform_device *pdev)
{
	unsigned long ver_lower, ver_higher;
	unsigned long ret = rsi_request_version(RSI_ABI_VERSION,
						&ver_lower,
						&ver_higher);

	if (ret == RSI_SUCCESS)
		__devm_auxiliary_device_create(&pdev->dev,
					"arm_cca_guest", RSI_DEV_NAME, NULL, 0);

}
#else
static void __init register_rsi_device(struct platform_device *pdev)
{

}
#endif

static int __init smccc_devices_init(void)
{
	struct platform_device *pdev;

	pdev = platform_device_register_simple("arm-smccc",
					PLATFORM_DEVID_NONE, NULL, 0);
	if (IS_ERR(pdev)) {
		pr_err("arm-smccc: could not register device: %ld\n", PTR_ERR(pdev));
	} else {
		/*
		 * Register the RMI and RSI devices only when firmware exposes
		 * the required SMCCC function IDs at a supported revision.
		 */
		register_rsi_device(pdev);
	}

	if (smccc_trng_available) {
		pdev = platform_device_register_simple("smccc_trng", -1,
						       NULL, 0);
		if (IS_ERR(pdev))
			pr_err("smccc_trng: could not register device: %ld\n",
			       PTR_ERR(pdev));
	}

	return 0;
}
device_initcall(smccc_devices_init);
