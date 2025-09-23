/* SPDX-License-Identifier: GPL-2.0 */
// Copyright (C) 2024 Arm Ltd.

#ifndef MPAM_FB_H_
#define MPAM_FB_H_

#include <linux/of.h>
#include <linux/scmi_protocol.h>
#include <linux/types.h>

struct mpam_fb_channel {
	bool				use_scmi;
	struct scmi_protocol_handle	*ph_handle;
	void __iomem			*pcc_shmem;
	size_t				pcc_shmem_size;
	struct mbox_chan		*pcc_mbox;
};

int mpam_fb_connect_channel(const struct device_node *of_node,
			    struct mpam_fb_channel *chan);
int mpam_fb_send_read_request(struct mpam_fb_channel *chan, int msc_id,
			      u16 reg, u32 *result);
int mpam_fb_send_write_request(struct mpam_fb_channel *chan, int msc_id,
			       u16 reg, u32 value);

#endif
