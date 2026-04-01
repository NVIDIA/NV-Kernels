/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2020 Intel Corporation. */
/* Copyright(c) 2025 Advanced Micro Devices, Inc. */

#ifndef __CXL_CXL_H__
#define __CXL_CXL_H__

#include <linux/bitfield.h>
#include <linux/node.h>
#include <linux/ioport.h>
#include <linux/range.h>
#include <cxl/mailbox.h>

/**
 * enum cxl_devtype - delineate type-2 from a generic type-3 device
 * @CXL_DEVTYPE_DEVMEM: Vendor specific CXL Type-2 device implementing HDM-D or
 *			 HDM-DB, no requirement that this device implements a
 *			 mailbox, or other memory-device-standard manageability
 *			 flows.
 * @CXL_DEVTYPE_CLASSMEM: Common class definition of a CXL Type-3 device with
 *			   HDM-H and class-mandatory memory device registers
 */
enum cxl_devtype {
	CXL_DEVTYPE_DEVMEM,
	CXL_DEVTYPE_CLASSMEM,
};

struct device;

/*
 * Using struct_group() allows for per register-block-type helper routines,
 * without requiring block-type agnostic code to include the prefix.
 */
struct cxl_regs {
	/*
	 * Common set of CXL Component register block base pointers
	 * @hdm_decoder: CXL 2.0 8.2.5.12 CXL HDM Decoder Capability Structure
	 * @ras: CXL 2.0 8.2.5.9 CXL RAS Capability Structure
	 */
	struct_group_tagged(cxl_component_regs, component,
		void __iomem *hdm_decoder;
		void __iomem *ras;
	);
	/*
	 * Common set of CXL Device register block base pointers
	 * @status: CXL 2.0 8.2.8.3 Device Status Registers
	 * @mbox: CXL 2.0 8.2.8.4 Mailbox Registers
	 * @memdev: CXL 2.0 8.2.8.5 Memory Device Registers
	 */
	struct_group_tagged(cxl_device_regs, device_regs,
		void __iomem *status, *mbox, *memdev;
	);

	struct_group_tagged(cxl_pmu_regs, pmu_regs,
		void __iomem *pmu;
	);

	/*
	 * RCH downstream port specific RAS register
	 * @aer: CXL 3.0 8.2.1.1 RCH Downstream Port RCRB
	 */
	struct_group_tagged(cxl_rch_regs, rch_regs,
		void __iomem *dport_aer;
	);

	/*
	 * RCD upstream port specific PCIe cap register
	 * @pcie_cap: CXL 3.0 8.2.1.2 RCD Upstream Port RCRB
	 */
	struct_group_tagged(cxl_rcd_regs, rcd_regs,
		void __iomem *rcd_pcie_cap;
	);
};

#define   CXL_CM_CAP_CAP_ID_RAS 0x2
#define   CXL_CM_CAP_CAP_ID_HDM 0x5
#define   CXL_CM_CAP_CAP_HDM_VERSION 1

/* CXL 2.0 8.2.4 CXL Component Register Layout and Definition */
#define CXL_COMPONENT_REG_BLOCK_SIZE SZ_64K

/* CXL 2.0 8.2.5 CXL.cache and CXL.mem Registers */
#define CXL_CM_OFFSET 0x1000
#define CXL_CM_CAP_HDR_OFFSET 0x0
#define   CXL_CM_CAP_HDR_ID_MASK GENMASK(15, 0)
#define     CM_CAP_HDR_CAP_ID 1
#define   CXL_CM_CAP_HDR_VERSION_MASK GENMASK(19, 16)
#define     CM_CAP_HDR_CAP_VERSION 1
#define   CXL_CM_CAP_HDR_CACHE_MEM_VERSION_MASK GENMASK(23, 20)
#define     CM_CAP_HDR_CACHE_MEM_VERSION 1
#define   CXL_CM_CAP_HDR_ARRAY_SIZE_MASK GENMASK(31, 24)
#define CXL_CM_CAP_PTR_MASK GENMASK(31, 20)

/* HDM decoders CXL 2.0 8.2.5.12 CXL HDM Decoder Capability Structure */
#define CXL_HDM_DECODER_CAP_OFFSET 0x0
#define   CXL_HDM_DECODER_COUNT_MASK GENMASK(3, 0)
#define   CXL_HDM_DECODER_TARGET_COUNT_MASK GENMASK(7, 4)
#define   CXL_HDM_DECODER_INTERLEAVE_11_8 BIT(8)
#define   CXL_HDM_DECODER_INTERLEAVE_14_12 BIT(9)
#define   CXL_HDM_DECODER_INTERLEAVE_3_6_12_WAY BIT(11)
#define   CXL_HDM_DECODER_INTERLEAVE_16_WAY BIT(12)
#define CXL_HDM_DECODER_CTRL_OFFSET 0x4
#define   CXL_HDM_DECODER_ENABLE BIT(1)
#define CXL_HDM_DECODER0_BASE_LOW_OFFSET(i) (0x20 * (i) + 0x10)
#define CXL_HDM_DECODER0_BASE_HIGH_OFFSET(i) (0x20 * (i) + 0x14)
#define CXL_HDM_DECODER0_SIZE_LOW_OFFSET(i) (0x20 * (i) + 0x18)
#define CXL_HDM_DECODER0_SIZE_HIGH_OFFSET(i) (0x20 * (i) + 0x1c)
#define CXL_HDM_DECODER0_CTRL_OFFSET(i) (0x20 * (i) + 0x20)
#define   CXL_HDM_DECODER0_CTRL_IG_MASK GENMASK(3, 0)
#define   CXL_HDM_DECODER0_CTRL_IW_MASK GENMASK(7, 4)
#define   CXL_HDM_DECODER0_CTRL_LOCK BIT(8)
#define   CXL_HDM_DECODER0_CTRL_COMMIT BIT(9)
#define   CXL_HDM_DECODER0_CTRL_COMMITTED BIT(10)
#define   CXL_HDM_DECODER0_CTRL_COMMIT_ERROR BIT(11)
#define   CXL_HDM_DECODER0_CTRL_HOSTONLY BIT(12)
#define CXL_HDM_DECODER0_TL_LOW(i) (0x20 * (i) + 0x24)
#define CXL_HDM_DECODER0_TL_HIGH(i) (0x20 * (i) + 0x28)
#define CXL_HDM_DECODER0_SKIP_LOW(i) CXL_HDM_DECODER0_TL_LOW(i)
#define CXL_HDM_DECODER0_SKIP_HIGH(i) CXL_HDM_DECODER0_TL_HIGH(i)

/* HDM decoder control register constants CXL 3.0 8.2.5.19.7 */
#define CXL_DECODER_MIN_GRANULARITY 256
#define CXL_DECODER_MAX_ENCODED_IG 6

static inline int cxl_hdm_decoder_count(u32 cap_hdr)
{
	int val = FIELD_GET(CXL_HDM_DECODER_COUNT_MASK, cap_hdr);

	return val ? val * 2 : 1;
}

struct cxl_reg_map {
	bool valid;
	int id;
	unsigned long offset;
	unsigned long size;
	u8 count;
};

struct cxl_component_reg_map {
	struct cxl_reg_map hdm_decoder;
	struct cxl_reg_map ras;
};

struct cxl_device_reg_map {
	struct cxl_reg_map status;
	struct cxl_reg_map mbox;
	struct cxl_reg_map memdev;
};

struct cxl_pmu_reg_map {
	struct cxl_reg_map pmu;
};

/**
 * struct cxl_register_map - DVSEC harvested register block mapping parameters
 * @host: device for devm operations and logging
 * @base: virtual base of the register-block-BAR + @block_offset
 * @resource: physical resource base of the register block
 * @max_size: maximum mapping size to perform register search
 * @reg_type: see enum cxl_regloc_type
 * @component_map: cxl_reg_map for component registers
 * @device_map: cxl_reg_maps for device registers
 * @pmu_map: cxl_reg_maps for CXL Performance Monitoring Units
 */
struct cxl_register_map {
	struct device *host;
	void __iomem *base;
	resource_size_t resource;
	resource_size_t max_size;
	u8 reg_type;
	union {
		struct cxl_component_reg_map component_map;
		struct cxl_device_reg_map device_map;
		struct cxl_pmu_reg_map pmu_map;
	};
};

/**
 * struct cxl_dpa_perf - DPA performance property entry
 * @dpa_range: range for DPA address
 * @coord: QoS performance data (i.e. latency, bandwidth)
 * @cdat_coord: raw QoS performance data from CDAT
 * @qos_class: QoS Class cookies
 */
struct cxl_dpa_perf {
	struct range dpa_range;
	struct access_coordinate coord[ACCESS_COORDINATE_MAX];
	struct access_coordinate cdat_coord[ACCESS_COORDINATE_MAX];
	int qos_class;
};

enum cxl_partition_mode {
	CXL_PARTMODE_RAM,
	CXL_PARTMODE_PMEM,
};

/**
 * struct cxl_dpa_partition - DPA partition descriptor
 * @res: shortcut to the partition in the DPA resource tree (cxlds->dpa_res)
 * @perf: performance attributes of the partition from CDAT
 * @mode: operation mode for the DPA capacity, e.g. ram, pmem, dynamic...
 */
struct cxl_dpa_partition {
	struct resource res;
	struct cxl_dpa_perf perf;
	enum cxl_partition_mode mode;
};

#define CXL_NR_PARTITIONS_MAX 2

/*
 * cxl_decoder flags that define the type of memory / devices this
 * decoder supports as well as configuration lock status See "CXL 2.0
 * 8.2.5.12.7 CXL HDM Decoder 0 Control Register" for details.
 * Additionally indicate whether decoder settings were autodetected,
 * user customized.
 */
#define CXL_DECODER_F_RAM   BIT(0)
#define CXL_DECODER_F_PMEM  BIT(1)
#define CXL_DECODER_F_TYPE2 BIT(2)
#define CXL_DECODER_F_TYPE3 BIT(3)
#define CXL_DECODER_F_LOCK  BIT(4)
#define CXL_DECODER_F_ENABLE    BIT(5)
#define CXL_DECODER_F_MASK  GENMASK(5, 0)

struct cxl_memdev_attach {
	int (*probe)(struct cxl_memdev *cxlmd);
};

/**
 * struct cxl_dev_state - The driver device state
 *
 * cxl_dev_state represents the CXL driver/device state.  It provides an
 * interface to mailbox commands as well as some cached data about the device.
 * Currently only memory devices are represented.
 *
 * @dev: The device associated with this CXL state
 * @cxlmd: The device representing the CXL.mem capabilities of @dev
 * @reg_map: component and ras register mapping parameters
 * @regs: Parsed register blocks
 * @cxl_dvsec: Offset to the PCIe device DVSEC
 * @rcd: operating in RCD mode (CXL 3.0 9.11.8 CXL Devices Attached to an RCH)
 * @media_ready: Indicate whether the device media is usable
 * @dpa_res: Overall DPA resource tree for the device
 * @part: DPA partition array
 * @nr_partitions: Number of DPA partitions
 * @serial: PCIe Device Serial Number
 * @type: Generic Memory Class device or Vendor Specific Memory device
 * @cxl_mbox: CXL mailbox context
 * @cxlfs: CXL features context
 */
struct cxl_dev_state {
	/* public for Type2 drivers */
	struct device *dev;
	struct cxl_memdev *cxlmd;

	/* private for Type2 drivers */
	struct cxl_register_map reg_map;
	struct cxl_regs regs;
	int cxl_dvsec;
	bool rcd;
	bool media_ready;
	struct resource dpa_res;
	struct cxl_dpa_partition part[CXL_NR_PARTITIONS_MAX];
	unsigned int nr_partitions;
	u64 serial;
	enum cxl_devtype type;
	struct cxl_mailbox cxl_mbox;
#ifdef CONFIG_CXL_FEATURES
	struct cxl_features_state *cxlfs;
#endif
};

struct cxl_dev_state *_devm_cxl_dev_state_create(struct device *dev,
						 enum cxl_devtype type,
						 u64 serial, u16 dvsec,
						 size_t size, bool has_mbox);

/**
 * cxl_dev_state_create - safely create and cast a cxl dev state embedded in a
 * driver specific struct.
 *
 * @parent: device behind the request
 * @type: CXL device type
 * @serial: device identification
 * @dvsec: dvsec capability offset
 * @drv_struct: driver struct embedding a cxl_dev_state struct
 * @member: drv_struct member as cxl_dev_state
 * @mbox: true if mailbox supported
 *
 * Returns a pointer to the drv_struct allocated and embedding a cxl_dev_state
 * struct initialized.
 *
 * Introduced for Type2 driver support.
 */
#define devm_cxl_dev_state_create(parent, type, serial, dvsec, drv_struct, member, mbox)	\
	({										\
		static_assert(__same_type(struct cxl_dev_state,				\
			      ((drv_struct *)NULL)->member));				\
		static_assert(offsetof(drv_struct, member) == 0);			\
		(drv_struct *)_devm_cxl_dev_state_create(parent, type, serial, dvsec,	\
						      sizeof(drv_struct), mbox);	\
	})

/**
 * cxl_map_component_regs - map cxl component registers
 *
 * @map: cxl register map to update with the mappings
 * @regs: cxl component registers to work with
 * @map_mask: cxl component regs to map
 *
 * Returns integer: success (0) or error (-ENOMEM)
 *
 * Made public for Type2 driver support.
 */
int cxl_map_component_regs(const struct cxl_register_map *map,
			   struct cxl_component_regs *regs,
			   unsigned long map_mask);
int cxl_set_capacity(struct cxl_dev_state *cxlds, u64 capacity);
struct cxl_memdev *devm_cxl_add_memdev(struct cxl_dev_state *cxlds,
				       const struct cxl_memdev_attach *attach);
struct cxl_region;
struct cxl_endpoint_decoder *cxl_get_committed_decoder(struct cxl_memdev *cxlmd,
						       struct cxl_region **cxlr);
struct range;
int cxl_get_region_range(struct cxl_region *region, struct range *range);
void cxl_unregister_region(struct cxl_region *cxlr);
struct cxl_port;
struct cxl_root_decoder *cxl_get_hpa_freespace(struct cxl_memdev *cxlmd,
					       int interleave_ways,
					       unsigned long flags,
					       resource_size_t *max);
void cxl_put_root_decoder(struct cxl_root_decoder *cxlrd);
struct cxl_endpoint_decoder *cxl_request_dpa(struct cxl_memdev *cxlmd,
					     enum cxl_partition_mode mode,
					     resource_size_t alloc);
int cxl_dpa_free(struct cxl_endpoint_decoder *cxled);
struct cxl_region *cxl_create_region(struct cxl_root_decoder *cxlrd,
				     struct cxl_endpoint_decoder **cxled,
				     int ways);

#ifdef CONFIG_CXL_BUS

int cxl_get_hdm_info(struct cxl_dev_state *cxlds, u8 *count,
		     resource_size_t *offset, resource_size_t *size);

#else

static inline
int cxl_get_hdm_info(struct cxl_dev_state *cxlds, u8 *count,
		     resource_size_t *offset, resource_size_t *size)
{ return -EOPNOTSUPP; }

#endif /* CONFIG_CXL_BUS */

#endif /* __CXL_CXL_H__ */
