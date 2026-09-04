/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 MediaTek Inc.
 */
#ifndef __MTK_PWRAP_SCMI_H__
#define __MTK_PWRAP_SCMI_H__

#include <linux/errno.h>
#include <linux/types.h>

#ifdef CONFIG_MTK_SSPM_CI
int sspm_ci_set(u32 feature_id,
	u32 p1, u32 p2, u32 p3, u32 p4, u32 p5);
#else
static inline int sspm_ci_set(u32 feature_id,
	u32 p1, u32 p2, u32 p3, u32 p4, u32 p5)
{
	return -ENODEV;
}
#endif /* CONFIG_MTK_SSPM_CI */

#define PWRAP_SCMI_DEV_ACT_ID(_a)		((_a) & (U8_MAX << 24))
#define PWRAP_SCMI_DEV_STATE(_s)		(((u8) (_s) & U8_MAX) << 16)
#define PWRAP_SCMI_DEV_DRIV_CMPLT(_c)	(((u8) (_c) & U8_MAX) << 8)
#define PWRAP_SCMI_SYS_TRANS(_t)		((u8) (_t) & U8_MAX)

#define PWRAP_SCMI_DEV_ACT_PAYLOAD(_a, _s, _c, _t) \
		(PWRAP_SCMI_DEV_ACT_ID(_a) | PWRAP_SCMI_DEV_STATE(_s) | \
		PWRAP_SCMI_DEV_DRIV_CMPLT(_c) | PWRAP_SCMI_SYS_TRANS(_t))

#define PWRAP_SCMI_COM_ACT_ID(_a)		((_a) & (U8_MAX << 24))
#define PWRAP_SCMI_COM_IDX(_c)			(((u8) (_c) & U8_MAX) << 16)
#define PWRAP_SCMI_COM_STATE(_s)		(((u8) (_s) & U8_MAX) << 8)
#define PWRAP_COM_DRIV_NOTIFIED(_d)		((u8) (_d) & U8_MAX)

#define PWRAP_SCMI_COM_ACT_PAYLOAD(_a, _c, _s, _d) \
		(PWRAP_SCMI_COM_ACT_ID(_a) | PWRAP_SCMI_COM_IDX(_c) | \
		PWRAP_SCMI_COM_STATE(_s) | PWRAP_COM_DRIV_NOTIFIED(_d))

#define SCMI_PROBE_ACTION_ID		0x01000000
#define SCMI_DEV_STATE_ACTION_ID	0x02000000
#define SCMI_COM_IDLE_ACTION_ID		0x03000000
#define SCMI_DEV_REQUEST_ACTION_ID	0x04000000
#define SCMI_DEV_ABANDON_ACTION_ID	0x05000000

#define SCMI_CONFIG_INIT(_dev)  { \
		.feat_id = 0x0D, \
		.dev_id = _dev, \
		.data = { \
			[SCMI_DEV_PROBE] = {SCMI_PROBE_ACTION_ID}, \
			[SCMI_DEV_STATE] = {SCMI_DEV_STATE_ACTION_ID}, \
			[SCMI_COM_IDLE] = {SCMI_COM_IDLE_ACTION_ID}, \
			[SCMI_DEV_REQUEST] = {SCMI_DEV_REQUEST_ACTION_ID}, \
			[SCMI_DEV_ADANDON] = {SCMI_DEV_ABANDON_ACTION_ID}, \
		} \
	}

enum mtk_pwrap_scmi_notify {
	SCMI_DEV_PROBE = 0,
	SCMI_DEV_STATE,
	SCMI_COM_IDLE,
	SCMI_DEV_REQUEST,
	SCMI_DEV_ADANDON,
	SCMI_NOTIFY_NUMBER,
};

enum mtk_pwrap_scmi_data {
	SCMI_DATA_00 = 0,
	SCMI_DATA_01,
	SCMI_DATA_02,
	SCMI_DATA_03,
	SCMI_DATA_NUMBER,
};

struct pwrap_scmi_config  {
	u32 feat_id;
	u32 dev_id;
	u32 data[SCMI_NOTIFY_NUMBER][SCMI_DATA_NUMBER];
};

#endif
