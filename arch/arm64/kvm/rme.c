// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 ARM Ltd.
 */

#include <linux/kvm_host.h>

#include <asm/rmi_cmds.h>
#include <asm/virt.h>

static int rmi_check_version(void)
{
	struct arm_smccc_res res;
	int version_major, version_minor;
	unsigned long host_version = RMI_ABI_VERSION(RMI_ABI_MAJOR_VERSION,
						     RMI_ABI_MINOR_VERSION);

	arm_smccc_1_1_invoke(SMC_RMI_VERSION, host_version, &res);

	if (res.a0 == SMCCC_RET_NOT_SUPPORTED)
		return -ENXIO;

	version_major = RMI_ABI_VERSION_GET_MAJOR(res.a1);
	version_minor = RMI_ABI_VERSION_GET_MINOR(res.a1);

	if (res.a0 != RMI_SUCCESS) {
		kvm_err("Unsupported RMI ABI (v%d.%d) host supports v%d.%d\n",
			version_major, version_minor,
			RMI_ABI_MAJOR_VERSION,
			RMI_ABI_MINOR_VERSION);
		return -ENXIO;
	}

	kvm_info("RMI ABI version %d.%d\n", version_major, version_minor);

	return 0;
}

void kvm_init_rme(void)
{
	if (PAGE_SIZE != SZ_4K)
		/* Only 4k page size on the host is supported */
		return;

	if (rmi_check_version())
		/* Continue without realm support */
		return;

	/* Future patch will enable static branch kvm_rme_is_available */
}
