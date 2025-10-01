/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _UAPI__ASM_RMI_DA_H
#define _UAPI__ASM_RMI_DA_H

#include <linux/types.h>

struct arm64_vdev_object_size_guest_req {
	__u32 req_type;
	__u32 object_type;
};

struct arm64_vdev_object_read_guest_req {
	__u32 req_type;
	__u32 object_type;
	__aligned_u64 offset;
};

#endif
