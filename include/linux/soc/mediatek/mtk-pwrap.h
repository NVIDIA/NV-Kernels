/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 MediaTek Inc.
 */
#ifndef __MTK_PWRAP_PUBLIC_H__
#define __MTK_PWRAP_PUBLIC_H__

#include <linux/errno.h>
#include <linux/types.h>

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
int mtk_pwrap_dev_request(void *dev_ctrl);
int mtk_pwrap_dev_remove(void *dev_ctrl);
int mtk_pwrap_dev_suspend(void *dev_ctrl, u8 sys_trans);
int mtk_pwrap_dev_resume(void *dev_ctrl, u8 sys_trans);
int mtk_pwrap_com_idle(void *dev_ctrl, u8 com_idx);
int mtk_pwrap_com_active(void *dev_ctrl, u8 com_idx);
void *mtk_pwrap_dev_probe(const char *acpi_path);
#else
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
