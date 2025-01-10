/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 ARM Ltd.
 *
 * The values and structures in this file are from the Realm Management Monitor
 * specification (DEN0137) version 1.0-rel0:
 * https://developer.arm.com/documentation/den0137/1-0rel0/
 */

#ifndef __ASM_RMI_SMC_H
#define __ASM_RMI_SMC_H

#include <linux/arm-smccc.h>

#define RMI_DEV_NAME "arm-rmi-dev"

#define SMC_RMI_CALL(func)				\
	ARM_SMCCC_CALL_VAL(ARM_SMCCC_FAST_CALL,		\
			   ARM_SMCCC_SMC_64,		\
			   ARM_SMCCC_OWNER_STANDARD,	\
			   (func))

#define SMC_RMI_VERSION			SMC_RMI_CALL(0x0150)
#define SMC_RMI_GRANULE_DELEGATE	SMC_RMI_CALL(0x0151)
#define SMC_RMI_GRANULE_UNDELEGATE	SMC_RMI_CALL(0x0152)
#define SMC_RMI_DATA_CREATE		SMC_RMI_CALL(0x0153)
#define SMC_RMI_DATA_CREATE_UNKNOWN	SMC_RMI_CALL(0x0154)
#define SMC_RMI_DATA_DESTROY		SMC_RMI_CALL(0x0155)
#define SMC_RMI_PDEV_AUX_COUNT		SMC_RMI_CALL(0x0156)
#define SMC_RMI_REALM_ACTIVATE		SMC_RMI_CALL(0x0157)
#define SMC_RMI_REALM_CREATE		SMC_RMI_CALL(0x0158)
#define SMC_RMI_REALM_DESTROY		SMC_RMI_CALL(0x0159)
#define SMC_RMI_REC_CREATE		SMC_RMI_CALL(0x015a)
#define SMC_RMI_REC_DESTROY		SMC_RMI_CALL(0x015b)
#define SMC_RMI_REC_ENTER		SMC_RMI_CALL(0x015c)
#define SMC_RMI_RTT_CREATE		SMC_RMI_CALL(0x015d)
#define SMC_RMI_RTT_DESTROY		SMC_RMI_CALL(0x015e)
#define SMC_RMI_RTT_MAP_UNPROTECTED	SMC_RMI_CALL(0x015f)

#define SMC_RMI_RTT_READ_ENTRY		SMC_RMI_CALL(0x0161)
#define SMC_RMI_RTT_UNMAP_UNPROTECTED	SMC_RMI_CALL(0x0162)

#define SMC_RMI_PSCI_COMPLETE		SMC_RMI_CALL(0x0164)
#define SMC_RMI_FEATURES		SMC_RMI_CALL(0x0165)
#define SMC_RMI_RTT_FOLD		SMC_RMI_CALL(0x0166)
#define SMC_RMI_REC_AUX_COUNT		SMC_RMI_CALL(0x0167)
#define SMC_RMI_RTT_INIT_RIPAS		SMC_RMI_CALL(0x0168)
#define SMC_RMI_RTT_SET_RIPAS		SMC_RMI_CALL(0x0169)

#define SMC_RMI_PDEV_ABORT		SMC_RMI_CALL(0x0174)
#define SMC_RMI_PDEV_COMMUNICATE        SMC_RMI_CALL(0x0175)
#define SMC_RMI_PDEV_CREATE             SMC_RMI_CALL(0x0176)
#define SMC_RMI_PDEV_DESTROY		SMC_RMI_CALL(0x0177)
#define SMC_RMI_PDEV_GET_STATE		SMC_RMI_CALL(0x0178)
#define SMC_RMI_PDEV_SET_PUBKEY		SMC_RMI_CALL(0x017b)
#define SMC_RMI_PDEV_STOP		SMC_RMI_CALL(0x017c)
#define SMC_RMI_VDEV_ABORT		SMC_RMI_CALL(0x0185)
#define SMC_RMI_VDEV_COMMUNICATE	SMC_RMI_CALL(0x0186)
#define SMC_RMI_VDEV_CREATE		SMC_RMI_CALL(0x0187)
#define SMC_RMI_VDEV_DESTROY		SMC_RMI_CALL(0x0188)
#define SMC_RMI_VDEV_GET_STATE		SMC_RMI_CALL(0x0189)
#define SMC_RMI_VDEV_UNLOCK		SMC_RMI_CALL(0x018A)

#define SMC_RMI_VDEV_LOCK		SMC_RMI_CALL(0x01D2)

#define RMI_ABI_MAJOR_VERSION	1
#define RMI_ABI_MINOR_VERSION	0

#define RMI_ABI_VERSION_GET_MAJOR(version) ((version) >> 16)
#define RMI_ABI_VERSION_GET_MINOR(version) ((version) & 0xFFFF)
#define RMI_ABI_VERSION(major, minor)      (((major) << 16) | (minor))

#define RMI_UNASSIGNED			0
#define RMI_ASSIGNED			1
#define RMI_TABLE			2

#define RMI_RETURN_STATUS(ret)		((ret) & 0xFF)
#define RMI_RETURN_INDEX(ret)		(((ret) >> 8) & 0xFF)

#define RMI_SUCCESS		0
#define RMI_ERROR_INPUT		1
#define RMI_ERROR_REALM		2
#define RMI_ERROR_REC		3
#define RMI_ERROR_RTT		4
#define RMI_BUSY		10

enum rmi_ripas {
	RMI_EMPTY = 0,
	RMI_RAM = 1,
	RMI_DESTROYED = 2,
};

#define RMI_NO_MEASURE_CONTENT	0
#define RMI_MEASURE_CONTENT	1

#define RMI_FEATURE_REGISTER_0_S2SZ		GENMASK(7, 0)
#define RMI_FEATURE_REGISTER_0_LPA2		BIT(8)
#define RMI_FEATURE_REGISTER_0_SVE_EN		BIT(9)
#define RMI_FEATURE_REGISTER_0_SVE_VL		GENMASK(13, 10)
#define RMI_FEATURE_REGISTER_0_NUM_BPS		GENMASK(19, 14)
#define RMI_FEATURE_REGISTER_0_NUM_WPS		GENMASK(25, 20)
#define RMI_FEATURE_REGISTER_0_PMU_EN		BIT(26)
#define RMI_FEATURE_REGISTER_0_PMU_NUM_CTRS	GENMASK(31, 27)
#define RMI_FEATURE_REGISTER_0_HASH_SHA_256	BIT(32)
#define RMI_FEATURE_REGISTER_0_HASH_SHA_512	BIT(33)
#define RMI_FEATURE_REGISTER_0_GICV3_NUM_LRS	GENMASK(37, 34)
#define RMI_FEATURE_REGISTER_0_MAX_RECS_ORDER	GENMASK(41, 38)
#define RMI_FEATURE_REGISTER_0_DA		BIT(42)
#define RMI_FEATURE_REGISTER_0_Reserved		GENMASK(63, 61)

#define RMI_REALM_PARAM_FLAG_LPA2		BIT(0)
#define RMI_REALM_PARAM_FLAG_SVE		BIT(1)
#define RMI_REALM_PARAM_FLAG_PMU		BIT(2)

/*
 * Note many of these fields are smaller than u64 but all fields have u64
 * alignment, so use u64 to ensure correct alignment.
 */
struct realm_params {
	union { /* 0x0 */
		struct {
			u64 flags;
			u64 s2sz;
			u64 sve_vl;
			u64 num_bps;
			u64 num_wps;
			u64 pmu_num_ctrs;
			u64 hash_algo;
		};
		u8 padding0[0x400];
	};
	union { /* 0x400 */
		u8 rpv[64];
		u8 padding1[0x400];
	};
	union { /* 0x800 */
		struct {
			u64 vmid;
			u64 rtt_base;
			s64 rtt_level_start;
			u64 rtt_num_start;
		};
		u8 padding2[0x800];
	};
};

/*
 * The number of GPRs (starting from X0) that are
 * configured by the host when a REC is created.
 */
#define REC_CREATE_NR_GPRS		8

#define REC_PARAMS_FLAG_RUNNABLE	BIT_ULL(0)

#define REC_PARAMS_AUX_GRANULES		16

struct rec_params {
	union { /* 0x0 */
		u64 flags;
		u8 padding0[0x100];
	};
	union { /* 0x100 */
		u64 mpidr;
		u8 padding1[0x100];
	};
	union { /* 0x200 */
		u64 pc;
		u8 padding2[0x100];
	};
	union { /* 0x300 */
		u64 gprs[REC_CREATE_NR_GPRS];
		u8 padding3[0x500];
	};
	union { /* 0x800 */
		struct {
			u64 num_rec_aux;
			u64 aux[REC_PARAMS_AUX_GRANULES];
		};
		u8 padding4[0x800];
	};
};

#define REC_ENTER_FLAG_EMULATED_MMIO	BIT(0)
#define REC_ENTER_FLAG_INJECT_SEA	BIT(1)
#define REC_ENTER_FLAG_TRAP_WFI		BIT(2)
#define REC_ENTER_FLAG_TRAP_WFE		BIT(3)
#define REC_ENTER_FLAG_RIPAS_RESPONSE	BIT(4)

#define REC_RUN_GPRS			31
#define REC_MAX_GIC_NUM_LRS		16

#define RMI_PERMITTED_GICV3_HCR_BITS	(ICH_HCR_EL2_UIE |		\
					 ICH_HCR_EL2_LRENPIE |		\
					 ICH_HCR_EL2_NPIE |		\
					 ICH_HCR_EL2_VGrp0EIE |		\
					 ICH_HCR_EL2_VGrp0DIE |		\
					 ICH_HCR_EL2_VGrp1EIE |		\
					 ICH_HCR_EL2_VGrp1DIE |		\
					 ICH_HCR_EL2_TDIR)

struct rec_enter {
	union { /* 0x000 */
		u64 flags;
		u8 padding0[0x200];
	};
	union { /* 0x200 */
		u64 gprs[REC_RUN_GPRS];
		u8 padding1[0x100];
	};
	union { /* 0x300 */
		struct {
			u64 gicv3_hcr;
			u64 gicv3_lrs[REC_MAX_GIC_NUM_LRS];
		};
		u8 padding2[0x100];
	};
	u8 padding3[0x400];
};

#define RMI_EXIT_SYNC			0x00
#define RMI_EXIT_IRQ			0x01
#define RMI_EXIT_FIQ			0x02
#define RMI_EXIT_PSCI			0x03
#define RMI_EXIT_RIPAS_CHANGE		0x04
#define RMI_EXIT_HOST_CALL		0x05
#define RMI_EXIT_SERROR			0x06

struct rec_exit {
	union { /* 0x000 */
		u8 exit_reason;
		u8 padding0[0x100];
	};
	union { /* 0x100 */
		struct {
			u64 esr;
			u64 far;
			u64 hpfar;
		};
		u8 padding1[0x100];
	};
	union { /* 0x200 */
		u64 gprs[REC_RUN_GPRS];
		u8 padding2[0x100];
	};
	union { /* 0x300 */
		struct {
			u64 gicv3_hcr;
			u64 gicv3_lrs[REC_MAX_GIC_NUM_LRS];
			u64 gicv3_misr;
			u64 gicv3_vmcr;
		};
		u8 padding3[0x100];
	};
	union { /* 0x400 */
		struct {
			u64 cntp_ctl;
			u64 cntp_cval;
			u64 cntv_ctl;
			u64 cntv_cval;
		};
		u8 padding4[0x100];
	};
	union { /* 0x500 */
		struct {
			u64 ripas_base;
			u64 ripas_top;
			u8 ripas_value;
			u8 padding8[7];
		};
		u8 padding5[0x100];
	};
	union { /* 0x600 */
		u16 imm;
		u8 padding6[0x100];
	};
	union { /* 0x700 */
		struct {
			u8 pmu_ovf_status;
		};
		u8 padding7[0x100];
	};
};

struct rec_run {
	struct rec_enter enter;
	struct rec_exit exit;
};

enum rmi_pdev_state {
	RMI_PDEV_NEW,
	RMI_PDEV_NEEDS_KEY,
	RMI_PDEV_HAS_KEY,
	RMI_PDEV_READY,
	RMI_PDEV_IDE_RESETTING,
	RMI_PDEV_COMMUNICATING,
	RMI_PDEV_STOPPING,
	RMI_PDEV_STOPPED,
	RMI_PDEV_ERROR,
};

#define MAX_PDEV_AUX_GRANULES	32
#define MAX_IOCOH_ADDR_RANGE	16
#define MAX_FCOH_ADDR_RANGE	4

#define RMI_PDEV_FLAGS_SPDM		BIT(0)
#define RMI_PDEV_FLAGS_NCOH_IDE		BIT(1)
#define RMI_PDEV_FLAGS_NCOH_ADDR	BIT(2)
#define RMI_PDEV_FLAGS_COH_IDE		BIT(3)
#define RMI_PDEV_FLAGS_COH_ADDR		BIT(4)
#define RMI_PDEV_FLAGS_P2P		BIT(5)
#define RMI_PDEV_FLAGS_COMP_TRUST	BIT(6)
#define RMI_PDEV_FLAGS_CATEGORY_MASK	GENMASK(8, 7)
#define RMI_PDEV_FLAGS_CATEGORY_SHIFT	7

#define RMI_PDEV_FLAGS_CATEGORY_CMEM_CXL	0x1

#define RMI_HASH_SHA_256	0
#define RMI_HASH_SHA_512	1

struct rmi_pdev_addr_range {
	u64 base;
	u64 top;
};

struct rmi_pdev_params {
	union {
		struct {
			u64 flags;
			u64 pdev_id;
			union {
				u8 segment_id;
				u64 padding0;
			};
			u64 ecam_addr;
			union {
				u16 root_id;
				u64 padding1;
			};
			u64 cert_id;
			union {
				u16 rid_base;
				u64 padding2;
			};
			union {
				u16 rid_top;
				u64 padding3;
			};
			union {
				u8 hash_algo;
				u64 padding4;
			};
			u64 num_aux;
			u64 ncoh_ide_sid;
			u64 ncoh_num_addr_range;
			u64 coh_num_addr_range;
		};
		u8 padding5[0x100];
	};

	union { /* 0x100 */
		u64 aux_granule[MAX_PDEV_AUX_GRANULES];
		u8 padding6[0x100];
	};

	union { /* 0x200 */
		struct {
			struct rmi_pdev_addr_range ncoh_addr_range[MAX_IOCOH_ADDR_RANGE];
		};
		u8 padding7[0x100];
	};
	union { /* 0x300 */
		struct {
			struct rmi_pdev_addr_range coh_addr_range[MAX_FCOH_ADDR_RANGE];
		};
		u8 padding8[0x100];
	};
};

#define RMI_DEV_COMM_EXIT_CACHE_REQ	BIT(0)
#define RMI_DEV_COMM_EXIT_CACHE_RSP	BIT(1)
#define RMI_DEV_COMM_EXIT_SEND		BIT(2)
#define RMI_DEV_COMM_EXIT_WAIT		BIT(3)
#define RMI_DEV_COMM_EXIT_RSP_RESET	BIT(4)
#define RMI_DEV_COMM_EXIT_MULTI		BIT(5)

#define RMI_DEV_COMM_NONE	0
#define RMI_DEV_COMM_RESPONSE	1
#define RMI_DEV_COMM_ERROR	2

#define RMI_PROTOCOL_SPDM		0
#define RMI_PROTOCOL_SECURE_SPDM	1

#define RMI_DEV_VCA			0
#define RMI_DEV_CERTIFICATE		1
#define RMI_DEV_MEASUREMENTS		2
#define RMI_DEV_INTERFACE_REPORT	3

struct rmi_dev_comm_enter {
	union {
		u8 status;
		u64 padding0;
	};
	u64 req_addr;
	u64 resp_addr;
	u64 resp_len;
};

struct rmi_dev_comm_exit {
	u64 flags;
	u64 req_cache_offset;
	u64 req_cache_len;
	u64 rsp_cache_offset;
	u64 rsp_cache_len;
	union {
		u8 cache_obj_id;
		u64 padding0;
	};

	union {
		u8 protocol;
		u64 padding1;
	};
	u64 req_delay;
	u64 req_len;
	u64 rsp_timeout;
};

struct rmi_dev_comm_data {
	union { /* 0x0 */
		struct rmi_dev_comm_enter enter;
		u8 padding0[0x800];
	};
	union { /* 0x800 */
		struct rmi_dev_comm_exit exit;
		u8 padding1[0x800];
	};
};

#define RMI_SIG_RSASSA_3072	0
#define RMI_SIG_ECDSA_P256	1
#define RMI_SIG_ECDSA_P384	2

struct rmi_public_key_params {
	union {
		struct {
			u8 public_key[1024];
			u8 metadata[1024];
			u64 public_key_len;
			u64 metadata_len;
			u8 rmi_signature_algorithm;
		} __packed;
		u8 padding[0x1000];
	};
};

enum rmi_vdev_state {
	RMI_VDEV_NEW,
	RMI_VDEV_UNLOCKED,
	RMI_VDEV_LOCKED,
	RMI_VDEV_STARTED,
	RMI_VDEV_ERROR,
};

#define MAX_VDEV_AUX_GRANULES	32

struct rmi_vdev_params {
	union {
		struct {
			u64 flags;
			u64 vdev_id;
			u64 tdi_id;
			u64 num_aux;
		};
		u8 padding1[0x100];
	};
	union {	/* 0x100 */
		struct {
			unsigned long aux[MAX_VDEV_AUX_GRANULES];
		};
		u8 padding2[0x900];
	};
};

#endif /* __ASM_RMI_SMC_H */
