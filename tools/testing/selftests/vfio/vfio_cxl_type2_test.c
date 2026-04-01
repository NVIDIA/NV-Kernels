// SPDX-License-Identifier: GPL-2.0-only
/*
 * vfio_cxl_type2_test - selftests for CXL Type-2 device passthrough via vfio-pci
 *
 * Tests the UAPI and emulation layer introduced by CONFIG_VFIO_CXL_CORE
 *
 * Usage:
 *   ./vfio_cxl_type2_test <BDF>
 * or set the environment variable VFIO_SELFTESTS_BDF before running.
 *
 * The device must be a CXL Type-2 device (e.g. a GPU with coherent memory).
 * Tests adapt automatically to firmware-committed (COMMITTED/COMMIT_LOCK set)
 * and CONFIG_LOCK-set hardware states instead of skipping.
 *
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/pci_regs.h>
#include <cxl/cxl_regs.h>
#include <linux/sizes.h>
#include <linux/vfio.h>

#include <libvfio.h>

#include "kselftest_harness.h"

/* Userspace equivalents of kernel helpers not available in user headers */
#ifndef BIT
#define BIT(n)			(1u << (n))
#endif
#ifndef GENMASK
#define GENMASK(h, l)		(((~0u) >> (31 - (h))) & ((~0u) << (l)))
#endif
#define VFIO_PCI_INDEX_TO_OFFSET(idx)	((uint64_t)(idx) << 40)

static const char *device_bdf;

/* ------------------------------------------------------------------ */
/* CXL UAPI constants (mirrors include/uapi/linux/vfio.h)             */
/* ------------------------------------------------------------------ */

#define VFIO_DEVICE_INFO_CAP_CXL	6

#define PCI_VENDOR_ID_CXL		0x1e98

#ifndef VFIO_REGION_SUBTYPE_CXL
#define VFIO_REGION_SUBTYPE_CXL		1
#endif
#ifndef VFIO_REGION_SUBTYPE_CXL_COMP_REGS
#define VFIO_REGION_SUBTYPE_CXL_COMP_REGS 2
#endif

/*
 * HDM Decoder register layout within the component register block.
 * Offsets relative to the start of the HDM decoder capability block.
 * The HDM decoder block begins at hdm_decoder_offset within the COMP_REGS
 * region; add hdm_decoder_offset before indexing into the region.
 */
#define HDM_GLOBAL_CTRL_OFFSET		0x04
#define HDM_DECODER_FIRST_OFFSET	0x10
#define HDM_DECODER_STRIDE		0x20
#define HDM_DECODER_BASE_LO		0x00
#define HDM_DECODER_BASE_HI		0x04
#define HDM_DECODER_SIZE_LO		0x08
#define HDM_DECODER_SIZE_HI		0x0c
#define HDM_DECODER_CTRL		0x10

#define HDM_CTRL_COMMIT			BIT(9)
#define HDM_CTRL_COMMITTED		BIT(10)
#define HDM_CTRL_RESERVED_MASK		(BIT(15) | GENMASK(31, 28))

#define CXL_LOCK_RESERVED_MASK GENMASK(15, 1)

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/*
 * Walk the vfio_device_info capability chain embedded in @buf.
 * Returns a pointer to the capability with the given @id, or NULL.
 */
static const struct vfio_info_cap_header *
find_device_cap(const void *buf, size_t bufsz, uint16_t id)
{
	const struct vfio_device_info *info = buf;
	const struct vfio_info_cap_header *cap;

	if (!(info->flags & VFIO_DEVICE_FLAGS_CAPS) || !info->cap_offset)
		return NULL;

	cap = (const struct vfio_info_cap_header *)
		((const char *)buf + info->cap_offset);

	while (true) {
		if (cap->id == id)
			return cap;
		if (!cap->next)
			return NULL;
		cap = (const struct vfio_info_cap_header *)
			((const char *)buf + cap->next);
		if ((const char *)cap + sizeof(*cap) > (const char *)buf + bufsz)
			return NULL;
	}
}

/*
 * Walk the vfio_region_info capability chain embedded in @buf.
 * Returns a pointer to the capability with the given @id, or NULL.
 * @buf must have been obtained from VFIO_DEVICE_GET_REGION_INFO with
 * argsz large enough to hold the full capability chain.
 */
static const struct vfio_info_cap_header *
find_region_cap(const void *buf, size_t bufsz, uint16_t id)
{
	const struct vfio_region_info *info = buf;
	const struct vfio_info_cap_header *cap;

	if (!(info->flags & VFIO_REGION_INFO_FLAG_CAPS) || !info->cap_offset)
		return NULL;

	cap = (const struct vfio_info_cap_header *)
		((const char *)buf + info->cap_offset);

	while (true) {
		if (cap->id == id)
			return cap;
		if (!cap->next)
			return NULL;
		cap = (const struct vfio_info_cap_header *)
			((const char *)buf + cap->next);
		if ((const char *)cap + sizeof(*cap) > (const char *)buf + bufsz)
			return NULL;
	}
}

/*
 * Read a 32-bit value from the COMP_REGS region at @offset (HDM-relative).
 */
static uint32_t comp_regs_read32(struct vfio_pci_device *dev,
				 uint32_t region_idx, uint64_t offset)
{
	uint32_t val;
	loff_t pos = (loff_t)VFIO_PCI_INDEX_TO_OFFSET(region_idx) + offset;
	ssize_t r;

	r = pread(dev->fd, &val, sizeof(val), pos);
	if (r != sizeof(val))
		return ~0u;
	return val;
}

/*
 * Write a 32-bit value to the COMP_REGS region at @offset.
 * Mirrors the error-propagation contract of comp_regs_read32() which returns
 * ~0u on a short or failed pread.
 */
static ssize_t comp_regs_write32(struct vfio_pci_device *dev,
				 uint32_t region_idx, uint64_t offset,
				 uint32_t val)
{
	loff_t pos = (loff_t)VFIO_PCI_INDEX_TO_OFFSET(region_idx) + offset;

	return pwrite(dev->fd, &val, sizeof(val), pos);
}

/*
 * HDM register accessors.
 *
 * The COMP_REGS region starts at the CXL component register block
 * start (comp_reg_offset).  The HDM decoder capability block begins at
 * hdm_decoder_offset within this region. These helpers add
 * hdm_decoder_offset so that callers can continue to use the HDM-relative
 * offsets defined by the macros above.
 */
static uint32_t hdm_regs_read32(struct vfio_pci_device *dev,
				uint32_t region_idx,
				uint64_t hdm_decoder_offset,
				uint64_t hdm_off)
{
	return comp_regs_read32(dev, region_idx, hdm_decoder_offset + hdm_off);
}

static ssize_t hdm_regs_write32(struct vfio_pci_device *dev,
				uint32_t region_idx,
				uint64_t hdm_decoder_offset,
				uint64_t hdm_off,
				uint32_t val)
{
	return comp_regs_write32(dev, region_idx, hdm_decoder_offset + hdm_off, val);
}

/*
 * Traverse the CXL Capability Array at COMP_REGS region offset 0 to find the
 * HDM Decoder capability block offset and decoder count.
 *
 * COMP_REGS region layout at offset 0 (CXL Capability Array):
 *   Dword 0 bits[31:24] (CXL_CM_CAP_HDR_ARRAY_SIZE_MASK): entry count N.
 *   Dwords 1..N at offset (cap*4): bits[15:0] = cap ID (CXL_CM_CAP_HDR_ID_MASK),
 *   bits[31:20] = byte offset from COMP_REGS start (CXL_CM_CAP_PTR_MASK).
 *
 * HDM Decoder cap ID = 0x5 (CXL_CM_CAP_CAP_ID_HDM).
 * HDMC at hdm_decoder_offset+0 bits[3:0]: count = (field==0) ? 1 : field*2.
 *
 * Returns true on success; sets *hdm_off and *hdm_cnt.
 */
static bool find_hdm_decoder_info(struct vfio_pci_device *dev,
				  uint32_t comp_regs_idx,
				  uint64_t *hdm_off, uint8_t *hdm_cnt)
{
	uint32_t hdr, num_caps, i;

	/* Read CXL Capability Array Header (dword 0) */
	hdr = comp_regs_read32(dev, comp_regs_idx, 0);
	if (hdr == ~0u)
		return false;

	/* Validate: bits[15:0] must be CM_CAP_HDR_CAP_ID (1) */
	if ((hdr & 0xffff) != 1)
		return false;

	/* bits[31:24] = number of capability entries */
	num_caps = (hdr >> 24) & 0xff;

	for (i = 1; i <= num_caps; i++) {
		uint32_t entry = comp_regs_read32(dev, comp_regs_idx, i * 4);
		uint32_t cap_id = entry & 0xffff; /* CXL_CM_CAP_HDR_ID_MASK */

		if (cap_id == 0x5) { /* CXL_CM_CAP_CAP_ID_HDM */
			uint32_t hdmc;
			uint32_t field;

			/* bits[31:20]: byte offset from COMP_REGS start */
			*hdm_off = (entry >> 20) & 0xfff;

			/* Read HDMC register at hdm_decoder_offset + 0 */
			hdmc = comp_regs_read32(dev, comp_regs_idx, *hdm_off);
			if (hdmc == ~0u)
				return false;

			/* bits[3:0]: 0 = 1 decoder, N = N*2 decoders */
			field = hdmc & 0xf;
			*hdm_cnt = field ? (uint8_t)(field * 2) : 1;
			return true;
		}
	}
	return false;
}

/*
 * Find the CXL DVSEC capability base in config space.
 */
#define PCI_DVSEC_VENDOR_ID_CXL	0x1e98
#define PCI_DVSEC_ID_CXL_DEVICE	0x0000
#define PCI_EXT_CAP_ID_DVSEC	0x23

static uint16_t find_cxl_dvsec(struct vfio_pci_device *dev)
{
	uint16_t pos = PCI_CFG_SPACE_SIZE; /* 0x100 */
	int iter = 0;

	while (pos && iter++ < 64) {
		uint32_t hdr  = vfio_pci_config_readl(dev, pos);
		uint32_t hdr1, hdr2;
		uint16_t cap_id	 = hdr & 0xffff;
		uint16_t next	 = (hdr >> 20) & 0xffc;

		if (cap_id == PCI_EXT_CAP_ID_DVSEC) {
			hdr1 = vfio_pci_config_readl(dev, pos + 4);
			hdr2 = vfio_pci_config_readl(dev, pos + 8);
			/*
			 * PCIe DVSEC Header 1 layout (Table 9-16):
			 *   Bits [15: 0] = DVSEC Vendor ID
			 *   Bits [19:16] = DVSEC Revision
			 *   Bits [31:20] = DVSEC Length
			 * DVSEC Header 2 layout:
			 *   Bits [15: 0] = DVSEC ID
			 */
			if ((hdr1 & 0xffff) == PCI_DVSEC_VENDOR_ID_CXL &&
			    (hdr2 & 0xffff) == PCI_DVSEC_ID_CXL_DEVICE)
				return pos;
		}
		pos = next;
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Fixture                                                            */
/* ------------------------------------------------------------------ */

FIXTURE(cxl_type2) {
	struct iommu *iommu;
	struct vfio_pci_device *dev;

	/* Filled in during FIXTURE_SETUP from the CXL cap */
	struct vfio_device_info_cap_cxl cxl_cap;
	uint16_t dvsec_base;

	/*
	 * Sizes derived from VFIO_DEVICE_GET_REGION_INFO at setup time.
	 * These are not in the CXL cap struct; query the region directly.
	 */
	uint64_t dpa_size;       /* size of the DPA region */
	uint64_t hdm_regs_size;  /* size of the COMP_REGS region */

	/*
	 * HDM decoder info derived from the COMP_REGS region at setup time.
	 * hdm_count and hdm_decoder_offset are no longer in the UAPI cap struct;
	 * they are derived by traversing the CXL Capability Array and reading
	 * the HDM Decoder Capability register (HDMC).
	 */
	uint64_t hdm_decoder_offset; /* byte offset in COMP_REGS to HDM block */
	uint8_t  hdm_count;          /* number of HDM decoders */

	/* DPA mmap pointer (may be NULL if test skips mmap sub-tests) */
	void *dpa_mmap;
	size_t dpa_mmap_size;
};

FIXTURE_SETUP(cxl_type2)
{
	uint8_t infobuf[512] = {};
	struct vfio_device_info *info = (void *)infobuf;
	const struct vfio_device_info_cap_cxl *cap;

	self->iommu = iommu_init(default_iommu_mode);
	self->dev   = vfio_pci_device_init(device_bdf, self->iommu);

	/* Query device info with space for capability chain */
	info->argsz = sizeof(infobuf);
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_INFO, info));

	if (!(info->flags & VFIO_DEVICE_FLAGS_CXL)) {
		printf("Device %s is not a CXL Type-2 device — skipping\n",
		       device_bdf);
		SKIP(return, "not a CXL Type-2 device");
	}

	cap = (const struct vfio_device_info_cap_cxl *)
		find_device_cap(infobuf, sizeof(infobuf),
				VFIO_DEVICE_INFO_CAP_CXL);
	ASSERT_NE(NULL, cap);
	memcpy(&self->cxl_cap, cap, sizeof(*cap));

	/*
	 * Populate dpa_size and hdm_regs_size from region queries.
	 */
	{
		struct vfio_region_info ri = { .argsz = sizeof(ri) };

		ri.index = cap->dpa_region_index;
		ASSERT_EQ(0, ioctl(self->dev->fd,
				   VFIO_DEVICE_GET_REGION_INFO, &ri));
		self->dpa_size = ri.size;

		ri.index = cap->comp_regs_region_index;
		ASSERT_EQ(0, ioctl(self->dev->fd,
				   VFIO_DEVICE_GET_REGION_INFO, &ri));
		self->hdm_regs_size = ri.size;
	}

	/*
	 * Derive hdm_decoder_offset and hdm_count from the COMP_REGS region.
	 * These fields were removed from vfio_device_info_cap_cxl to keep the
	 * UAPI minimal; userspace derives them via the CXL Capability Array.
	 */
	ASSERT_TRUE(find_hdm_decoder_info(self->dev,
					  cap->comp_regs_region_index,
					  &self->hdm_decoder_offset,
					  &self->hdm_count));

	self->dvsec_base    = find_cxl_dvsec(self->dev);
	self->dpa_mmap      = MAP_FAILED;
	self->dpa_mmap_size = 0;
}

FIXTURE_TEARDOWN(cxl_type2)
{
	if (self->dpa_mmap != MAP_FAILED && self->dpa_mmap_size)
		munmap(self->dpa_mmap, self->dpa_mmap_size);
	vfio_pci_device_cleanup(self->dev);
	iommu_cleanup(self->iommu);
}

/* ------------------------------------------------------------------ */
/* Tests: VFIO_DEVICE_GET_INFO                                        */
/* ------------------------------------------------------------------ */

/*
 * CXL and PCI flags must both be set; CAPS must be set since we have a cap.
 */
TEST_F(cxl_type2, device_flags)
{
	uint8_t infobuf[512] = {};
	struct vfio_device_info *info = (void *)infobuf;

	info->argsz = sizeof(infobuf);
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_INFO, info));

	ASSERT_TRUE(info->flags & VFIO_DEVICE_FLAGS_CXL);
	ASSERT_TRUE(info->flags & VFIO_DEVICE_FLAGS_PCI);
	ASSERT_TRUE(info->flags & VFIO_DEVICE_FLAGS_CAPS);

	printf("device flags: 0x%x  num_regions: %u\n",
	       info->flags, info->num_regions);
}

/*
 * The CXL capability must report sane HDM and DPA values.
 * hdm_count and hdm_decoder_offset are no longer in the cap struct; they
 * are derived from the COMP_REGS region in FIXTURE_SETUP and stored in
 * self->hdm_count and self->hdm_decoder_offset.
 */
TEST_F(cxl_type2, cxl_cap_fields)
{
	const struct vfio_device_info_cap_cxl *c = &self->cxl_cap;

	ASSERT_EQ(VFIO_DEVICE_INFO_CAP_CXL, c->header.id);
	ASSERT_EQ(1, c->header.version);

	/* Must have at least one HDM decoder (derived from HDMC bits[3:0]) */
	ASSERT_GT(self->hdm_count, 0);

	/* COMP_REGS region size must be non-zero and 4-byte aligned */
	ASSERT_GT(self->hdm_regs_size, 0ULL);
	ASSERT_EQ(0ULL, self->hdm_regs_size % 4);

	/*
	 * hdm_decoder_offset is derived from the CXL Capability Array.
	 * It must be:
	 *   - non-zero (the CXL Capability Array Header precedes the HDM block)
	 *   - dword-aligned
	 *   - strictly less than hdm_regs_size (HDM block fits in the region)
	 */
	ASSERT_GT(self->hdm_decoder_offset, 0ULL);
	ASSERT_EQ(0ULL, self->hdm_decoder_offset % 4);
	ASSERT_LT(self->hdm_decoder_offset, self->hdm_regs_size);

	/* Region indices must not be ~0U (sentinel for "not found") */
	ASSERT_NE(~0U, c->dpa_region_index);
	ASSERT_NE(~0U, c->comp_regs_region_index);

	/* The two regions must be distinct */
	ASSERT_NE(c->dpa_region_index, c->comp_regs_region_index);

	/*
	 * FIRMWARE_COMMITTED: decoder was pre-programmed by firmware; DPA
	 * region is immediately live.  dpa_size must be non-zero in this case.
	 */
	if (c->flags & VFIO_CXL_CAP_FIRMWARE_COMMITTED)
		ASSERT_GT(self->dpa_size, 0ULL);

	printf("hdm_count=%u dpa_size=0x%llx hdm_regs_size=0x%llx "
	       "hdm_decoder_offset=0x%llx "
	       "dpa_idx=%u comp_regs_idx=%u flags=0x%x "
	       "(firmware_committed=%d cache_capable=%d)\n",
	       self->hdm_count, (unsigned long long)self->dpa_size,
	       (unsigned long long)self->hdm_regs_size,
	       (unsigned long long)self->hdm_decoder_offset,
	       c->dpa_region_index, c->comp_regs_region_index, c->flags,
	       !!(c->flags & VFIO_CXL_CAP_FIRMWARE_COMMITTED),
	       !!(c->flags & VFIO_CXL_CAP_CACHE_CAPABLE));
}

/* ------------------------------------------------------------------ */
/* Tests: VFIO_DEVICE_GET_REGION_INFO                                 */
/* ------------------------------------------------------------------ */

/*
 * The component register BAR must report its real (non-zero) size with
 * READ/WRITE/MMAP flags and a VFIO_REGION_INFO_CAP_SPARSE_MMAP capability.
 * The sparse areas advertise the GPU/accelerator register windows — the
 * mmappable parts of the BAR that do NOT contain CXL component registers.
 *
 * Three topologies are possible depending on where comp_regs sits in the BAR:
 *   Topology A [gpu_regs | comp_regs]      → 1 area: [0, comp_reg_offset)
 *   Topology B [comp_regs | gpu_regs]      → 1 area: [comp_end, bar_len)
 *   Topology C [gpu_regs | comp_regs | gpu_regs] → 2 areas
 *
 * In all cases each sparse area is a GPU register window; no area may overlap
 * the CXL component register block at [comp_reg_offset, comp_reg_offset +
 * comp_reg_size).
 */
TEST_F(cxl_type2, component_bar_sparse_mmap)
{
	struct vfio_region_info probe = { .argsz = sizeof(probe) };
	struct vfio_region_info *reg;
	const struct vfio_region_info_cap_sparse_mmap *sparse;
	uint32_t bar_idx = self->cxl_cap.hdm_regs_bar_index;
	uint64_t comp_reg_offset;
	uint64_t total_gpu_size;
	uint8_t *buf;
	uint32_t needed;
	uint32_t i;

	/* First probe: learn required buffer size and basic flags */
	probe.index = bar_idx;
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_REGION_INFO, &probe));

	ASSERT_GT(probe.size, 0ULL);
	ASSERT_TRUE(probe.flags & VFIO_REGION_INFO_FLAG_READ);
	ASSERT_TRUE(probe.flags & VFIO_REGION_INFO_FLAG_WRITE);
	ASSERT_TRUE(probe.flags & VFIO_REGION_INFO_FLAG_MMAP);

	/* Kernel must signal caps are present by expanding argsz */
	ASSERT_GT(probe.argsz, (uint32_t)sizeof(probe));
	needed = probe.argsz;

	buf = calloc(1, needed);
	ASSERT_NE(NULL, buf);
	reg = (struct vfio_region_info *)buf;
	reg->argsz = needed;
	reg->index = bar_idx;
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_REGION_INFO, reg));

	/* Must carry a sparse-mmap cap */
	sparse = (const struct vfio_region_info_cap_sparse_mmap *)
		find_region_cap(buf, needed, VFIO_REGION_INFO_CAP_SPARSE_MMAP);
	ASSERT_NE(NULL, sparse);

	/* 1 area (topology A or B) or 2 areas (topology C); never more */
	ASSERT_GE(sparse->nr_areas, 1U);
	ASSERT_LE(sparse->nr_areas, 2U);

	/*
	 * comp_reg_offset = hdm_regs_offset - CXL_CM_OFFSET.
	 * hdm_regs_offset is the BAR-relative address of the CXL.mem area
	 * start, which sits CXL_CM_OFFSET (0x1000) bytes into the component
	 * register block.
	 */
	ASSERT_GE(self->cxl_cap.hdm_regs_offset, (uint64_t)CXL_CM_OFFSET);
	comp_reg_offset = self->cxl_cap.hdm_regs_offset - CXL_CM_OFFSET;

	total_gpu_size = 0;
	for (i = 0; i < sparse->nr_areas; i++) {
		uint64_t area_start = sparse->areas[i].offset;
		uint64_t area_end   = area_start + sparse->areas[i].size;

		/* Each area must be non-empty and fit within the BAR */
		ASSERT_GT(sparse->areas[i].size, 0ULL);
		ASSERT_LE(area_end, reg->size);

		/*
		 * No sparse area may overlap the CXL component register block.
		 * Use hdm_regs_offset as a witness point: it is comp_reg_offset
		 * + CXL_CM_OFFSET, guaranteed inside the block.
		 */
		ASSERT_FALSE(area_start <= self->cxl_cap.hdm_regs_offset &&
			     self->cxl_cap.hdm_regs_offset < area_end);

		total_gpu_size += sparse->areas[i].size;

		printf("  sparse area[%u]: offset=0x%llx size=0x%llx\n", i,
		       (unsigned long long)area_start,
		       (unsigned long long)sparse->areas[i].size);
	}

	/* GPU windows together must be strictly smaller than the full BAR */
	ASSERT_LT(total_gpu_size, reg->size);

	printf("component BAR %u: bar_size=0x%llx comp_reg_offset=0x%llx "
	       "nr_areas=%u total_gpu=0x%llx flags=0x%x\n",
	       bar_idx, (unsigned long long)reg->size,
	       (unsigned long long)comp_reg_offset,
	       sparse->nr_areas, (unsigned long long)total_gpu_size,
	       reg->flags);

	free(buf);
}

/*
 * DPA region must be readable and writable.  MMAP is optional because kernels
 * may withhold it until the DPA backing is known to be CPU-mappable safely.
 * Its size must be non-zero (verified in fixture setup via self->dpa_size).
 */
TEST_F(cxl_type2, dpa_region_info)
{
	struct vfio_region_info reg = { .argsz = sizeof(reg) };

	reg.index = self->cxl_cap.dpa_region_index;
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_REGION_INFO, &reg));

	ASSERT_EQ(self->dpa_size, reg.size);
	ASSERT_TRUE(reg.flags & VFIO_REGION_INFO_FLAG_READ);
	ASSERT_TRUE(reg.flags & VFIO_REGION_INFO_FLAG_WRITE);

	printf("DPA region: size=0x%llx offset=0x%llx flags=0x%x\n",
	       (unsigned long long)reg.size,
	       (unsigned long long)reg.offset, reg.flags);
}

/*
 * COMP_REGS region must be readable and writable but not mmappable.
 * Its size covers [comp_reg_offset, comp_reg_offset + hdm_regs_size), which
 * includes both the CXL Capability Array prefix (hdm_decoder_offset bytes)
 * and the HDM decoder block. Size is available in self->hdm_regs_size
 * (populated from this same region query at fixture setup time).
 */
TEST_F(cxl_type2, comp_regs_region_info)
{
	struct vfio_region_info reg = { .argsz = sizeof(reg) };

	reg.index = self->cxl_cap.comp_regs_region_index;
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_REGION_INFO, &reg));

	ASSERT_EQ(self->hdm_regs_size, reg.size);
	ASSERT_TRUE(reg.flags  & VFIO_REGION_INFO_FLAG_READ);
	ASSERT_TRUE(reg.flags  & VFIO_REGION_INFO_FLAG_WRITE);
	ASSERT_FALSE(reg.flags & VFIO_REGION_INFO_FLAG_MMAP);

	printf("COMP_REGS region: size=0x%llx offset=0x%llx flags=0x%x\n",
	       (unsigned long long)reg.size,
	       (unsigned long long)reg.offset, reg.flags);
}

/* ------------------------------------------------------------------ */
/* Tests: DPA region mmap                                             */
/* ------------------------------------------------------------------ */

/*
 * mmap() the DPA region and verify the first page can be read.
 * The region uses lazy fault insertion so the first access triggers the
 * vfio_cxl_region_page_fault path.
 */
TEST_F(cxl_type2, dpa_mmap_fault)
{
	struct vfio_region_info reg = { .argsz = sizeof(reg) };
	size_t map_size;
	void *ptr;
	uint8_t *p;
	uint8_t val;

	reg.index = self->cxl_cap.dpa_region_index;
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_REGION_INFO, &reg));

	if (!(reg.flags & VFIO_REGION_INFO_FLAG_MMAP))
		SKIP(return, "DPA region does not advertise mmap");

	/* Map just the first 2MB or the full region, whichever is smaller */
	map_size = (size_t)reg.size < (size_t)(2 * SZ_1M)
		 ? (size_t)reg.size : (size_t)(2 * SZ_1M);

	ptr = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, self->dev->fd, (off_t)reg.offset);
	ASSERT_NE(MAP_FAILED, ptr);

	self->dpa_mmap = ptr;
	self->dpa_mmap_size = map_size;

	/* First access - triggers vmf_insert_pfn */
	p = (uint8_t *)ptr;
	val = *p;
	(void)val;

	printf("DPA mmap: ptr=%p size=0x%zx first byte=0x%02x\n",
	       ptr, map_size, (uint8_t)val);

	/* Write a pattern and read it back */
	*p = 0xab;
	ASSERT_EQ(0xab, *p);
}

/*
 * mmap() of the COMP_REGS region (no MMAP flag) must fail.
 */
TEST_F(cxl_type2, comp_regs_no_mmap)
{
	struct vfio_region_info reg = { .argsz = sizeof(reg) };
	void *ptr;

	reg.index = self->cxl_cap.comp_regs_region_index;
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_REGION_INFO, &reg));

	ptr = mmap(NULL, (size_t)reg.size, PROT_READ,
		   MAP_SHARED, self->dev->fd, (off_t)reg.offset);
	ASSERT_EQ(MAP_FAILED, ptr);

	printf("mmap of COMP_REGS correctly failed (errno=%d)\n", errno);
}

/*
 * mmap() of the CXL component register block within the component BAR must
 * fail with EINVAL.  The kernel blocks any mmap request whose range overlaps
 * [comp_reg_offset, comp_reg_offset + comp_reg_size) even though the BAR as
 * a whole carries the MMAP flag (GPU windows are mmappable).
 *
 * hdm_regs_offset (= comp_reg_offset + CXL_CM_OFFSET) is a page-aligned
 * address guaranteed to lie inside the component register block.
 */
TEST_F(cxl_type2, comp_reg_mmap_blocked)
{
	struct vfio_region_info bar_reg = { .argsz = sizeof(bar_reg) };
	void *ptr;

	bar_reg.index = self->cxl_cap.hdm_regs_bar_index;
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_REGION_INFO, &bar_reg));
	ASSERT_TRUE(bar_reg.flags & VFIO_REGION_INFO_FLAG_MMAP);

	/*
	 * hdm_regs_offset is page-aligned and is comp_reg_offset + CXL_CM_OFFSET
	 * (0x1000), so it is always within the component register block.
	 */
	ASSERT_EQ(0ULL, self->cxl_cap.hdm_regs_offset % SZ_4K);

	ptr = mmap(NULL, (size_t)SZ_4K, PROT_READ,
		   MAP_SHARED, self->dev->fd,
		   (off_t)(bar_reg.offset + self->cxl_cap.hdm_regs_offset));
	ASSERT_EQ(MAP_FAILED, ptr);
	ASSERT_EQ(EINVAL, errno);

	printf("comp_reg_mmap_blocked: hdm_regs_offset=0x%llx correctly blocked "
	       "(errno=%d)\n",
	       (unsigned long long)self->cxl_cap.hdm_regs_offset, errno);
}

/* ------------------------------------------------------------------ */
/* Tests: COMP_REGS region (HDM decoder emulation)                    */
/* ------------------------------------------------------------------ */

/*
 * Reading HDM Capability (offset 0x00) must return a non-zero value
 * consistent with at least one decoder being present.
 * Bits [3:0] encode the HDM decoder count.
 */
TEST_F(cxl_type2, hdm_cap_read)
{
	uint32_t cap;
	uint32_t idx = self->cxl_cap.comp_regs_region_index;
	uint64_t hdm_off = self->hdm_decoder_offset;

	cap = hdm_regs_read32(self->dev, idx, hdm_off, CXL_HDM_DECODER_CAP_OFFSET);
	ASSERT_NE(~0u, cap);

	/*
	 * Verify the live HDMC register matches the count we derived in setup.
	 * Encoding: bits[3:0] = 0 → 1 decoder; N → N*2 decoders.
	 */
	{
		uint32_t field = cap & 0xf;
		uint8_t expected = field ? (uint8_t)(field * 2) : 1;

		ASSERT_EQ(self->hdm_count, expected);
	}

	printf("HDM Capability register: 0x%08x  decoder_count_field=%u  hdm_count=%u\n",
	       cap, cap & 0xf, self->hdm_count);
}

/*
 * HDM decoder COMMIT -> COMMITTED transition.
 *
 * On firmware-committed hardware (COMMITTED already set) the COMMIT path
 * is not exercisable.  Instead verify the committed state is self-consistent:
 * COMMITTED set, BASE/SIZE non-zero and large enough to cover dpa_size, and
 * reserved bits cleared by the emulation layer.
 *
 * On hardware where the decoder is not yet committed, exercise the full
 * COMMIT=1 -> COMMITTED=1 path followed by COMMIT=0 -> COMMITTED=0.
 */
TEST_F(cxl_type2, hdm_ctrl_commit_to_committed)
{
	uint32_t idx = self->cxl_cap.comp_regs_region_index;
	uint64_t hdm_off = self->hdm_decoder_offset;
	uint64_t base_lo_off = HDM_DECODER_FIRST_OFFSET + HDM_DECODER_BASE_LO;
	uint64_t base_hi_off = HDM_DECODER_FIRST_OFFSET + HDM_DECODER_BASE_HI;
	uint64_t size_lo_off = HDM_DECODER_FIRST_OFFSET + HDM_DECODER_SIZE_LO;
	uint64_t size_hi_off = HDM_DECODER_FIRST_OFFSET + HDM_DECODER_SIZE_HI;
	uint64_t ctrl_off    = HDM_DECODER_FIRST_OFFSET + HDM_DECODER_CTRL;
	uint32_t ctrl_readback;
	uint32_t base_lo, base_hi, size_lo, size_hi;
	uint64_t dec_base, dec_size;

	ctrl_readback = hdm_regs_read32(self->dev, idx, hdm_off, ctrl_off);

	if (ctrl_readback & HDM_CTRL_COMMITTED) {
		/*
		 * Firmware-committed decoder: verify the committed state is
		 * self-consistent.
		 *
		 * BASE is expected to be zero: the kernel clears BASE_LO/HI in
		 * the shadow for firmware-committed decoders so that the host
		 * HPA does not leak to the guest.  The VMM will write the guest
		 * GPA into BASE before booting the VM.
		 *
		 * SIZE must cover at least dpa_size, and reserved bits must be
		 * clear (the emulation scrubs them on every write).
		 */
		base_lo = hdm_regs_read32(self->dev, idx, hdm_off, base_lo_off);
		base_hi = hdm_regs_read32(self->dev, idx, hdm_off, base_hi_off);
		size_lo = hdm_regs_read32(self->dev, idx, hdm_off, size_lo_off);
		size_hi = hdm_regs_read32(self->dev, idx, hdm_off, size_hi_off);
		dec_base = ((uint64_t)base_hi << 32) | (base_lo & ~GENMASK(27, 0));
		dec_size = ((uint64_t)size_hi << 32) | (size_lo & ~GENMASK(27, 0));

		ASSERT_EQ(0ULL, dec_base);
		ASSERT_GE(dec_size, self->dpa_size);
		ASSERT_EQ(0u, ctrl_readback & HDM_CTRL_RESERVED_MASK);

		printf("Decoder 0 firmware-committed: ctrl=0x%08x "
		       "base=0x%llx (zeroed by kernel) size=0x%llx dpa_size=0x%llx\n",
		       ctrl_readback,
		       (unsigned long long)dec_base,
		       (unsigned long long)dec_size,
		       (unsigned long long)self->dpa_size);
		return;
	}

	/* Decoder not committed: exercise COMMIT=1 -> COMMITTED=1 path */
	ASSERT_EQ(4, hdm_regs_write32(self->dev, idx, hdm_off, base_lo_off, 0x10000000));
	ASSERT_EQ(4, hdm_regs_write32(self->dev, idx, hdm_off, base_hi_off, 0));
	ASSERT_EQ(4, hdm_regs_write32(self->dev, idx, hdm_off, size_lo_off, 0x10000000));
	ASSERT_EQ(4, hdm_regs_write32(self->dev, idx, hdm_off, size_hi_off, 0));

	ASSERT_EQ(4, hdm_regs_write32(self->dev, idx, hdm_off, ctrl_off, HDM_CTRL_COMMIT));
	ctrl_readback = hdm_regs_read32(self->dev, idx, hdm_off, ctrl_off);
	ASSERT_TRUE(ctrl_readback & HDM_CTRL_COMMITTED);

	printf("HDM decoder 0 CTRL after COMMIT=1: 0x%08x (COMMITTED set)\n",
	       ctrl_readback);

	ASSERT_EQ(4, hdm_regs_write32(self->dev, idx, hdm_off, ctrl_off, 0));
	ctrl_readback = hdm_regs_read32(self->dev, idx, hdm_off, ctrl_off);
	ASSERT_FALSE(ctrl_readback & HDM_CTRL_COMMITTED);

	printf("HDM decoder 0 CTRL after COMMIT=0: 0x%08x (COMMITTED cleared)\n",
	       ctrl_readback);
}

/*
 * CXL Lock (DVSEC offset 0x14):
 *   - Reserved bits GENMASK(15,1) must be cleared.
 *   - Once locked, CXL Control writes must be discarded.
 *
 * On firmware-committed hardware CONFIG_LOCK is set before OS load by the
 * BIOS.
 * In this case verify:
 * (a) Lock reserved bits are zero,
 * (b) a write to CXL Control is silently discarded by the emulation.
 * Both are directly testable without needing to transition from unlocked
 * to locked.
 *
 * On hardware where CONFIG_LOCK is not yet set, exercise the full sequence:
 * write reserved bits (must be cleared), set CONFIG_LOCK, verify Control
 * writes are then discarded.
 */
TEST_F(cxl_type2, dvsec_lock_semantics)
{
	uint16_t dvsec = self->dvsec_base;
	uint16_t lock_val, ctrl_before, ctrl_after;

	if (!dvsec)
		SKIP(return, "CXL DVSEC not found in config space");

	lock_val = vfio_pci_config_readw(self->dev,
					 dvsec + CXL_DVSEC_LOCK_OFFSET);

	if (lock_val & CXL_DVSEC_LOCK_CONFIG_LOCK) {
		/*
		 * Lock is already set: verify reserved bits are zero in the
		 * current shadow, then verify a Control write is discarded.
		 */
		ASSERT_EQ(0u, lock_val & CXL_LOCK_RESERVED_MASK);

		ctrl_before = vfio_pci_config_readw(self->dev,
						    dvsec + CXL_DVSEC_CONTROL_OFFSET);
		/* Attempt to flip CXL_Mem_Enable (bit 2) */
		vfio_pci_config_writew(self->dev, dvsec + CXL_DVSEC_CONTROL_OFFSET,
				       ctrl_before ^ BIT(2));
		ctrl_after = vfio_pci_config_readw(self->dev,
						   dvsec + CXL_DVSEC_CONTROL_OFFSET);
		ASSERT_EQ(ctrl_before, ctrl_after);

		printf("CONFIG_LOCK set: lock=0x%04x, "
		       "Control write discarded (ctrl=0x%04x unchanged)\n",
		       lock_val, ctrl_after);
		return;
	}

	/* Lock is not set: exercise reserved-bit masking and lock-set sequence */
	vfio_pci_config_writew(self->dev, dvsec + CXL_DVSEC_LOCK_OFFSET,
			       CXL_LOCK_RESERVED_MASK);
	lock_val = vfio_pci_config_readw(self->dev,
					 dvsec + CXL_DVSEC_LOCK_OFFSET);
	ASSERT_EQ(0u, lock_val & CXL_LOCK_RESERVED_MASK);
	ASSERT_FALSE(lock_val & CXL_DVSEC_LOCK_CONFIG_LOCK);

	ctrl_before = vfio_pci_config_readw(self->dev,
					    dvsec + CXL_DVSEC_CONTROL_OFFSET);
	vfio_pci_config_writew(self->dev, dvsec + CXL_DVSEC_LOCK_OFFSET,
			       CXL_DVSEC_LOCK_CONFIG_LOCK);
	lock_val = vfio_pci_config_readw(self->dev,
					 dvsec + CXL_DVSEC_LOCK_OFFSET);
	ASSERT_TRUE(lock_val & CXL_DVSEC_LOCK_CONFIG_LOCK);

	vfio_pci_config_writew(self->dev, dvsec + CXL_DVSEC_CONTROL_OFFSET,
			       ctrl_before ^ BIT(0));
	ctrl_after = vfio_pci_config_readw(self->dev,
					   dvsec + CXL_DVSEC_CONTROL_OFFSET);
	ASSERT_EQ(ctrl_before, ctrl_after);

	printf("Lock set, Control write discarded: "
	       "lock=0x%04x ctrl_before=0x%04x ctrl_after=0x%04x\n",
	       lock_val, ctrl_before, ctrl_after);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
	device_bdf = vfio_selftests_get_bdf(&argc, argv);
	return test_harness_run(argc, argv);
}
