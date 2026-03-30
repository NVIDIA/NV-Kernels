/* SPDX-License-Identifier: GPL-2.0
 * SPDX-FileCopyrightText: Copyright (C) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef __ASM_RHI_CMDS_H_
#define __ASM_RHI_CMDS_H_

#include <linux/arm-smccc.h>

#include <asm/rsi_smc.h>
#include <asm/rsi_cmds.h>
#include <asm/rhi.h>

static inline int rhi_da_object_read(unsigned long vdev_id,
				     unsigned long type,
				     unsigned long ipa,
				     unsigned long max_size,
				     unsigned long offset,
				     unsigned long *size)
{
	struct rsi_host_call *rsi_host_call_params =
		(void *)__get_free_page(GFP_KERNEL);
	struct arm_smccc_res res;
	int ret;

	if (!rsi_host_call_params)
		return -ENOMEM;

	rsi_host_call_params->imm = 0;
	rsi_host_call_params->gprs[0] = RHI_DA_OBJECT_READ;
	rsi_host_call_params->gprs[1] = vdev_id;
	rsi_host_call_params->gprs[2] = type;
	rsi_host_call_params->gprs[3] = (unsigned long)ipa;
	rsi_host_call_params->gprs[4] = max_size;
	rsi_host_call_params->gprs[5] = offset;

	arm_smccc_smc(SMC_RSI_HOST_CALL, virt_to_phys(rsi_host_call_params),
		      0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == RSI_SUCCESS) {
		ret = rsi_host_call_params->gprs[0];
		*size = rsi_host_call_params->gprs[1];
	} else {
		ret = -ENODEV;
	}

	free_page((unsigned long)rsi_host_call_params);

	return ret;
}

static inline int rhi_da_vdev_continue(unsigned long vdev_id)
{
	struct rsi_host_call *rsi_host_call_params =
		(void *)__get_free_page(GFP_KERNEL);
	struct arm_smccc_res res;
	int ret;

	if (!rsi_host_call_params)
		return -ENOMEM;

	rsi_host_call_params->imm = 0;
	rsi_host_call_params->gprs[0] = RHI_DA_VDEV_CONTINUE;
	rsi_host_call_params->gprs[1] = vdev_id;

	arm_smccc_smc(SMC_RSI_HOST_CALL, virt_to_phys(rsi_host_call_params),
		      0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == RSI_SUCCESS)
		ret = rsi_host_call_params->gprs[0];
	else
		ret = -ENODEV;

	free_page((unsigned long)rsi_host_call_params);

	return ret;
}

static inline int rhi_da_vdev_get_measurements(unsigned long vdev_id,
					       unsigned long params_ipa)
{
	struct rsi_host_call *rsi_host_call_params =
		(void *)__get_free_page(GFP_KERNEL);
	struct arm_smccc_res res;
	int ret;

	if (!rsi_host_call_params)
		return -ENOMEM;

	rsi_host_call_params->imm = 0;
	rsi_host_call_params->gprs[0] = RHI_DA_VDEV_GET_MEASUREMENTS;
	rsi_host_call_params->gprs[1] = vdev_id;
	rsi_host_call_params->gprs[2] = params_ipa;

	arm_smccc_smc(SMC_RSI_HOST_CALL, virt_to_phys(rsi_host_call_params),
		      0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == RSI_SUCCESS)
		ret = rsi_host_call_params->gprs[0];
	else
		ret = -ENODEV;

	free_page((unsigned long)rsi_host_call_params);

	return ret;
}

static inline int rhi_da_vdev_get_interface_report(unsigned long vdev_id)
{
	struct rsi_host_call *rsi_host_call_params =
		(void *)__get_free_page(GFP_KERNEL);
	struct arm_smccc_res res;
	int ret;

	if (!rsi_host_call_params)
		return -ENOMEM;

	rsi_host_call_params->imm = 0;
	rsi_host_call_params->gprs[0] = RHI_DA_VDEV_GET_INTERFACE_REPORT;
	rsi_host_call_params->gprs[1] = vdev_id;

	arm_smccc_smc(SMC_RSI_HOST_CALL, virt_to_phys(rsi_host_call_params),
		      0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == RSI_SUCCESS)
		ret = rsi_host_call_params->gprs[0];
	else
		ret = -ENODEV;

	free_page((unsigned long)rsi_host_call_params);

	return ret;
}

static inline int rhi_da_vdev_set_tdi_state(unsigned long vdev_id,
					    unsigned long tdi_state)
{
	struct rsi_host_call *rsi_host_call_params =
		(void *)__get_free_page(GFP_KERNEL);
	struct arm_smccc_res res;
	int ret;

	if (!rsi_host_call_params)
		return -ENOMEM;

	rsi_host_call_params->imm = 0;
	rsi_host_call_params->gprs[0] = RHI_DA_VDEV_SET_TDI_STATE;
	rsi_host_call_params->gprs[1] = vdev_id;
	rsi_host_call_params->gprs[2] = tdi_state;

	arm_smccc_smc(SMC_RSI_HOST_CALL, virt_to_phys(rsi_host_call_params),
		      0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == RSI_SUCCESS)
		ret = rsi_host_call_params->gprs[0];
	else
		ret = -ENODEV;

	free_page((unsigned long)rsi_host_call_params);

	return ret;
}

#endif /* __ASM_RHI_CMDS_H_ */
