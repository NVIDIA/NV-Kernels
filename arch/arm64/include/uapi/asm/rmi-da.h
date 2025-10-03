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

struct arm64_vdev_device_measurement_guest_req {
	__u32 req_type;
	__aligned_u64 flags;
	__u8 *indices;
	__u8 *nonce;
};

struct arm64_vdev_device_idmap_guest_req {
	__u32 req_type;
	__s32 vcpu_fd;
};

struct arm64_vdev_device_memmap_guest_req {
	__u32 req_type;
	__s32 vcpu_fd;
	__aligned_u64 gpa_base;
	__aligned_u64 gpa_top;
	__aligned_u64 pa_base;
};

struct arm64_vdev_set_tdi_state_guest_req {
	__u32 req_type;
	__u32 tdi_state;
};

#endif
