/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 MediaTek Inc.
 */
#ifndef __MTK_PWRAP_PUBLIC_H__
#define __MTK_PWRAP_PUBLIC_H__

#include <linux/errno.h>
#include <linux/types.h>

struct device;

/*
 * Number of caller-supplied custom data words carried in a power control
 * request. These are OR'd into scmi_config.data[SCMI_DEV_REQUEST][SCMI_DATA_01..03]
 * before being handed to sspm_ci_set(), so the count matches the three
 * trailing data words of the SCMI_DEV_REQUEST action slot.
 */
#define POWER_WRAP_SCMI_DATA_MAX_INDEX 3

/*
 * Power control request descriptor.
 *
 * A client driver that wants to send a power control command to SSPM
 * allocates and fills one of these, then passes it to
 * mtk_send_power_control_req(). @dev identifies the target device (used to
 * resolve its ACPI path and, from there, its per-device SCMI config).
 * @InBuffer must point to a struct power_cntl_scmi_data.
 *
 * The Out* / BytesReturned fields mirror the Windows IOCTL-style buffer
 * contract this driver is ported from; they are reserved for future use.
 */
struct _power_cntrl_request {
	struct device *dev;
	void	*InBuffer;
	size_t	 InBufferSize;
	void	*OutBuffer;
	size_t	 OutBufferSize;
	size_t	 BytesReturned;
};

/*
 * Payload the client places in _power_cntrl_request.InBuffer.
 *
 * @requestId    - OR'd into the SCMI_DATA_00 word (action id) of the request.
 * @customdata[] - OR'd into the SCMI_DATA_01..03 words of the request.
 */
struct power_cntl_scmi_data {
	u8	requestId;
	u32	customdata[POWER_WRAP_SCMI_DATA_MAX_INDEX];
};

enum mtk_pwrap_dev_state {
	DEV_STA_UNKNOWN = 0,
	DEV_STA_D0,
	DEV_STA_D1,
	DEV_STA_D2,
	DEV_STA_D3,
	DEV_STA_MAX
};

enum mtk_pwrap_com_state {
	COM_STA_L0 = 0,
	COM_STA_L1,
	COM_STA_L2,
	COM_STA_L3,
	COM_STA_MAX
};

#ifdef CONFIG_MTK_POWER_WRAP
int mtk_send_power_control_req(struct _power_cntrl_request *pwrctlreq);
int mtk_pwrap_dev_request(void *dev_ctrl);
int mtk_pwrap_dev_remove(void *dev_ctrl);
int mtk_pwrap_dev_suspend(void *dev_ctrl, u8 sys_trans);
int mtk_pwrap_dev_resume(void *dev_ctrl, u8 sys_trans);
int mtk_pwrap_com_idle(void *dev_ctrl, u8 com_idx);
int mtk_pwrap_com_active(void *dev_ctrl, u8 com_idx);
void *mtk_pwrap_dev_probe(const char *acpi_path);
#else
static inline int mtk_send_power_control_req(struct _power_cntrl_request *pwrctlreq)
{
	return -ENODEV;
}

static inline int mtk_pwrap_dev_request(void *dev_ctrl)
{
	return -ENODEV;
}

static inline int mtk_pwrap_dev_remove(void *dev_ctrl)
{
	return -ENODEV;
}

static inline int mtk_pwrap_dev_suspend(void *dev_ctrl, u8 sys_trans)
{
	return -ENODEV;
}

static inline int mtk_pwrap_dev_resume(void *dev_ctrl, u8 sys_trans)
{
	return -ENODEV;
}

static inline int mtk_pwrap_com_idle(void *dev_ctrl, u8 com_idx)
{
	return -ENODEV;
}

static inline int mtk_pwrap_com_active(void *dev_ctrl, u8 com_idx)
{
	return -ENODEV;
}

static inline void *mtk_pwrap_dev_probe(const char *acpi_path)
{
	return NULL;
}
#endif /* CONFIG_MTK_POWER_WRAP */

#endif
