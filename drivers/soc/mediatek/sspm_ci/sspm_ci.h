/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 MediaTek Inc.
 *
 * MediaTek SSPM control interface driver
 */

#ifndef _SSPM_CI_H_
#define _SSPM_CI_H_

/*
 * Returns 0 on ack, -ENODEV without a mailbox, -EBUSY if the command could not
 * be submitted (nothing sent, caller state unchanged), -ETIMEDOUT if it was
 * sent but not acknowledged in time (completion unknown).
 */
int sspm_ci_set(u32 feature_id,
	u32 p1, u32 p2, u32 p3, u32 p4, u32 p5);
#endif /* _SSPM_CI_H_ */
