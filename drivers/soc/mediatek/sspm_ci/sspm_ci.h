/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 MediaTek Inc.
 *
 * MediaTek SSPM control interface driver
 */

#ifndef _SSPM_CI_H_
#define _SSPM_CI_H_

int sspm_ci_set(u32 feature_id,
	u32 p1, u32 p2, u32 p3, u32 p4, u32 p5);
#endif /* _SSPM_CI_H_ */
