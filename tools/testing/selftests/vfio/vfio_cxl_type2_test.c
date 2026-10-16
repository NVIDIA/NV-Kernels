// SPDX-License-Identifier: GPL-2.0-only
/*
 * vfio_cxl_type2_test - corner-case tests for the vfio-cxl kernel contract.
 *
 * Exercises the user-visible surface the vfio-cxl module adds to a CXL Type-2
 * device: the two VFIO regions (HDM memory and the trapped HDM decoder block),
 * the component-register geometry capability, the dma-buf export of the HDM
 * memory, and the guest decoder view.
 *
 * The host commits and locks the physical decoder before the guest sees the
 * device, so the trapped block is served by a live read and a guest write is
 * absorbed.
 *
 * Usage: ./vfio_cxl_type2_test <BDF>  (or export VFIO_SELFTESTS_BDF=<BDF>).
 * The device must be bound to vfio-pci with the vfio-cxl module available.
 *
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/pci_regs.h>
#include <linux/sizes.h>
#include <linux/vfio.h>

#include <cxl/cxl_regs.h>

#include <libvfio.h>

#include "kselftest_harness.h"

#define PCI_DVSEC_VENDOR_ID_CXL		0x1e98
#define PCI_DVSEC_ID_CXL_DEVICE		0x0000

/* CXL r4.0 sec 8.1.9.1: Register Block Identifier of the component regs */
#define CXL_REGLOC_RBI_COMPONENT	1

/* Register Locator DVSEC block-1 field masks. */
#define REG_LOCATOR_BIR_MASK		0x00000007
#define REG_LOCATOR_BLOCK_ID_MASK	0x0000ff00
#define REG_LOCATOR_BLOCK_OFF_LOW_MASK	0xffff0000

/* vfio-pci region-offset packing is kernel-internal, not UAPI; define locally. */
#ifndef VFIO_PCI_OFFSET_SHIFT
#define VFIO_PCI_OFFSET_SHIFT		40
#endif
#ifndef VFIO_PCI_INDEX_TO_OFFSET
#define VFIO_PCI_INDEX_TO_OFFSET(i)	((uint64_t)(i) << VFIO_PCI_OFFSET_SHIFT)
#endif

static const char *device_bdf;

/* Locate a region-info capability by id inside a GET_REGION_INFO buffer. */
static const struct vfio_info_cap_header *
find_region_cap(const void *buf, size_t bufsz, uint16_t id)
{
	const struct vfio_region_info *ri = buf;
	const struct vfio_info_cap_header *cap;
	size_t off = ri->cap_offset;

	while (off && off + sizeof(*cap) <= bufsz) {
		cap = (const void *)((const char *)buf + off);
		if (cap->id == id)
			return cap;
		off = cap->next;
	}
	return NULL;
}

/* Find a CXL region by subtype; returns the region index or -1, @buf left holding its info. */
static int find_cxl_region(int fd, uint32_t nregions, uint32_t subtype,
			   void *buf, size_t bufsz)
{
	uint32_t i;

	for (i = 0; i < nregions; i++) {
		struct vfio_region_info *ri = buf;
		const struct vfio_region_info_cap_type *t;
		const struct vfio_info_cap_header *hdr;

		memset(buf, 0, bufsz);
		ri->argsz = bufsz;
		ri->index = i;
		if (ioctl(fd, VFIO_DEVICE_GET_REGION_INFO, ri))
			continue;
		if (!(ri->flags & VFIO_REGION_INFO_FLAG_CAPS))
			continue;

		hdr = find_region_cap(buf, bufsz, VFIO_REGION_INFO_CAP_TYPE);
		if (!hdr)
			continue;
		t = (const void *)hdr;
		if (t->type == (VFIO_REGION_TYPE_PCI_VENDOR_TYPE |
				PCI_DVSEC_VENDOR_ID_CXL) &&
		    t->subtype == subtype)
			return i;
	}
	return -1;
}

/* Walk the PCI extended capability list for the CXL Device DVSEC. */
static uint16_t find_cxl_dvsec(struct vfio_pci_device *dev)
{
	uint16_t pos = PCI_CFG_SPACE_SIZE;
	int iter = 0;

	while (pos && iter++ < 64) {
		uint32_t hdr = vfio_pci_config_readl(dev, pos);
		uint16_t cap_id = hdr & 0xffff;
		uint16_t next = (hdr >> 20) & 0xffc;
		uint32_t h1, h2;

		if (cap_id == PCI_EXT_CAP_ID_DVSEC) {
			h1 = vfio_pci_config_readl(dev, pos + 4);
			h2 = vfio_pci_config_readl(dev, pos + 8);
			if ((h1 & 0xffff) == PCI_DVSEC_VENDOR_ID_CXL &&
			    (h2 & 0xffff) == PCI_DVSEC_ID_CXL_DEVICE)
				return pos;
		}
		pos = next;
	}
	return 0;
}

/* Read config space from sysfs, which is the hardware, not the vfio view. */
static int sysfs_config_read(uint32_t off, void *buf, size_t len)
{
	char path[128];
	ssize_t n;
	int fd;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/config",
		 device_bdf);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	n = pread(fd, buf, len, off);
	close(fd);
	return n == (ssize_t)len ? 0 : -EIO;
}

FIXTURE(vfio_cxl) {
	struct iommu *iommu;
	struct vfio_pci_device *dev;

	int mem_idx;
	uint64_t mem_size;
	uint32_t mem_flags;
	int comp_idx;
	uint64_t comp_size;
	uint32_t comp_bar;
	uint64_t comp_offset;	/* HDM block offset within comp_bar */
	uint64_t comp_off;	/* mmap/rw base offset of the comp region */
	uint16_t dvsec;
};

FIXTURE_SETUP(vfio_cxl)
{
	uint8_t infobuf[512] = {};
	struct vfio_device_info *info = (void *)infobuf;
	const struct vfio_region_info_cap_cxl_comp_regs *geo;
	const struct vfio_info_cap_header *hdr;
	uint8_t rbuf[1024];
	uint16_t cmd;

	self->iommu = iommu_init(default_iommu_mode);
	self->dev = vfio_pci_device_init(device_bdf, self->iommu);

	info->argsz = sizeof(infobuf);
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_INFO, info));

	if (!(info->flags & VFIO_DEVICE_FLAGS_CXL))
		SKIP(return, "not a CXL Type-2 device");

	self->mem_idx = find_cxl_region(self->dev->fd, info->num_regions,
					VFIO_REGION_SUBTYPE_CXL_MEM,
					rbuf, sizeof(rbuf));
	ASSERT_GE(self->mem_idx, 0);
	self->mem_size = ((struct vfio_region_info *)rbuf)->size;
	self->mem_flags = ((struct vfio_region_info *)rbuf)->flags;

	self->comp_idx = find_cxl_region(self->dev->fd, info->num_regions,
					 VFIO_REGION_SUBTYPE_CXL_COMP_REGS,
					 rbuf, sizeof(rbuf));
	ASSERT_GE(self->comp_idx, 0);
	self->comp_size = ((struct vfio_region_info *)rbuf)->size;

	/* The geometry cap rides on the component-register region. */
	hdr = find_region_cap(rbuf, sizeof(rbuf),
			      VFIO_REGION_INFO_CAP_CXL_COMP_REGS);
	ASSERT_NE(NULL, hdr);
	geo = (const void *)hdr;
	self->comp_bar = geo->bar;
	self->comp_offset = geo->offset;

	self->comp_off = VFIO_PCI_INDEX_TO_OFFSET(self->comp_idx);
	self->dvsec = find_cxl_dvsec(self->dev);

	/* Enable PCI Memory-Space so the HDM mmap tests can touch the mapping. */
	cmd = vfio_pci_config_readw(self->dev, PCI_COMMAND);
	vfio_pci_config_writew(self->dev, PCI_COMMAND,
			       cmd | PCI_COMMAND_MEMORY);
}

FIXTURE_TEARDOWN(vfio_cxl)
{
	vfio_pci_device_cleanup(self->dev);
	iommu_cleanup(self->iommu);
}

/* GET_INFO advertises the flag and both CXL regions with a sane geometry cap. */
TEST_F(vfio_cxl, device_is_cxl)
{
	ASSERT_NE(self->mem_idx, self->comp_idx);
	ASSERT_GT(self->mem_size, 0);
	ASSERT_GT(self->comp_size, 0);
	ASSERT_LT(self->comp_bar, PCI_STD_NUM_BARS);
	/* The HDM memory must advertise mmap; a VMM needs it for stage-2. */
	ASSERT_NE(0, self->mem_flags & VFIO_REGION_INFO_FLAG_MMAP);
}

/*
 * The component BAR carries the physical HDM decoder block, which vfio traps
 * and excludes from mmap so the guest cannot reprogram it. The whole-BAR map
 * must fail; the ranges around the excluded block must map.
 */
TEST_F(vfio_cxl, comp_bar_sparse_mmap)
{
	size_t page_size = getpagesize();
	uint8_t rbuf[1024] = {};
	struct vfio_region_info *ri = (void *)rbuf;
	const struct vfio_region_info_cap_sparse_mmap *sm;
	const struct vfio_info_cap_header *hdr;
	uint64_t bar_off, decoder_page, hole_end;
	bool covered;
	void *map;
	uint32_t i;

	ri->argsz = sizeof(rbuf);
	ri->index = self->comp_bar;
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_REGION_INFO, ri));
	ASSERT_NE(0, ri->flags & VFIO_REGION_INFO_FLAG_MMAP);
	bar_off = ri->offset;

	/* The trapped decoder block splits the BAR, so it must be sparse. */
	hdr = find_region_cap(rbuf, sizeof(rbuf),
			      VFIO_REGION_INFO_CAP_SPARSE_MMAP);
	ASSERT_NE(NULL, hdr);
	sm = (const void *)hdr;

	/*
	 * mmap is page granular, so the hole is the decoder block rounded out
	 * to pages. With 64 KiB pages it can cover a small component BAR
	 * entirely; then there is nothing left to map and no area.
	 */
	decoder_page = self->comp_offset & ~(uint64_t)(page_size - 1);
	hole_end = (self->comp_offset + self->comp_size + page_size - 1) &
		   ~(uint64_t)(page_size - 1);
	covered = decoder_page == 0 && hole_end >= ri->size;
	ASSERT_EQ(covered, sm->nr_areas == 0);

	/* Mapping the whole BAR must fail: it covers the excluded block. */
	map = mmap(NULL, ri->size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   self->dev->fd, bar_off);
	ASSERT_EQ(MAP_FAILED, map);

	/* Every advertised area is page aligned and must map. */
	for (i = 0; i < sm->nr_areas; i++) {
		uint64_t ao = sm->areas[i].offset;
		uint64_t as = sm->areas[i].size;

		if (!as)
			continue;
		ASSERT_EQ(0, ao & (page_size - 1));
		ASSERT_EQ(0, as & (page_size - 1));

		map = mmap(NULL, as, PROT_READ | PROT_WRITE, MAP_SHARED,
			   self->dev->fd, bar_off + ao);
		ASSERT_NE(MAP_FAILED, map);
		ASSERT_EQ(0, munmap(map, as));
	}

	/* The page holding the decoder block must never be mmappable. */
	map = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   self->dev->fd, bar_off + decoder_page);
	ASSERT_EQ(MAP_FAILED, map);
}

/* Basic HDM memory mmap read/write round-trip. */
TEST_F(vfio_cxl, hdm_mem_mmap_rw)
{
	uint64_t off = VFIO_PCI_INDEX_TO_OFFSET(self->mem_idx);
	uint32_t pattern = 0xdeadbeefU, readback = 0;
	void *map;

	if (self->mem_size < SZ_4K)
		SKIP(return, "HDM memory < 4K");

	map = mmap(NULL, SZ_4K, PROT_READ | PROT_WRITE, MAP_SHARED,
		   self->dev->fd, off);
	ASSERT_NE(MAP_FAILED, map);

	memcpy(map, &pattern, sizeof(pattern));
	memcpy(&readback, map, sizeof(readback));
	ASSERT_EQ(pattern, readback);

	ASSERT_EQ(0, munmap(map, SZ_4K));
}

/*
 * read() and write() on the HDM region copy through a kernel buffer in page
 * chunks: a transfer that spans several chunks and ends mid-page round-trips.
 * Size it in pages of the running kernel, so a 64K-page kernel also crosses
 * chunk boundaries. The zero-length read is answered by vfio-pci-core.
 */
TEST_F(vfio_cxl, hdm_mem_rw_multi_chunk)
{
	uint64_t off = VFIO_PCI_INDEX_TO_OFFSET(self->mem_idx);
	size_t pg = getpagesize();
	size_t len = 3 * pg + 100;
	uint8_t *src, *dst;
	size_t i;

	if (self->mem_size < 4 * pg)
		SKIP(return, "HDM memory < 4 pages");

	src = malloc(len);
	dst = calloc(1, len);
	ASSERT_NE(NULL, src);
	ASSERT_NE(NULL, dst);
	for (i = 0; i < len; i++)
		src[i] = i * 7 + 3;

	ASSERT_EQ((ssize_t)len, pwrite(self->dev->fd, src, len, off + 64));
	ASSERT_EQ((ssize_t)len, pread(self->dev->fd, dst, len, off + 64));
	ASSERT_EQ(0, memcmp(src, dst, len));
	ASSERT_EQ(0, pread(self->dev->fd, dst, 0, off));

	free(src);
	free(dst);
}

/*
 * The user buffer of a read() may itself be an mmap of the HDM region. The
 * copy to it faults the page in through the region's fault handler, which
 * takes memory_lock; the read must not hold memory_lock across that copy.
 * Run with lockdep to catch the recursive acquisition.
 */
TEST_F(vfio_cxl, hdm_mem_rw_into_own_mmap)
{
	uint64_t off = VFIO_PCI_INDEX_TO_OFFSET(self->mem_idx);
	uint32_t pattern = 0xc0ffee11U, readback = 0;
	uint8_t *map;

	if (self->mem_size < 2 * SZ_4K)
		SKIP(return, "HDM memory < 8K");

	map = mmap(NULL, SZ_4K, PROT_READ | PROT_WRITE, MAP_SHARED,
		   self->dev->fd, off);
	ASSERT_NE(MAP_FAILED, map);

	ASSERT_EQ((ssize_t)sizeof(pattern),
		  pwrite(self->dev->fd, &pattern, sizeof(pattern),
			 off + SZ_4K));
	/* map is not faulted in yet: the copy to user faults it here. */
	ASSERT_EQ((ssize_t)sizeof(pattern),
		  pread(self->dev->fd, map, sizeof(pattern), off + SZ_4K));
	memcpy(&readback, map, sizeof(readback));
	ASSERT_EQ(pattern, readback);

	ASSERT_EQ(0, munmap(map, SZ_4K));
}

/* A 2 MB-aligned HDM window mapped as a huge (PMD) fault. */
TEST_F(vfio_cxl, hdm_mem_huge_mmap)
{
	uint64_t off = VFIO_PCI_INDEX_TO_OFFSET(self->mem_idx);
	uint32_t pattern = 0x5a5a5a5aU, readback = 0;
	void *map, *last;

	if (self->mem_size < SZ_2M)
		SKIP(return, "HDM memory < 2M");

	map = mmap(NULL, SZ_2M, PROT_READ | PROT_WRITE, MAP_SHARED,
		   self->dev->fd, off);
	ASSERT_NE(MAP_FAILED, map);

	last = (char *)map + SZ_2M - sizeof(pattern);
	memcpy(last, &pattern, sizeof(pattern));
	memcpy(&readback, last, sizeof(readback));
	ASSERT_EQ(pattern, readback);

	ASSERT_EQ(0, munmap(map, SZ_2M));
}

/*
 * A VMM maps the HDM range into the guest IOAS by fd (the struct-page-less
 * range cannot be pinned through a VA): export it as a dma-buf and map that fd
 * with IOMMU_IOAS_MAP_FILE.
 */
TEST_F(vfio_cxl, hdm_mem_ioas_map)
{
	uint8_t buf[sizeof(struct vfio_device_feature) +
		    sizeof(struct vfio_device_feature_dma_buf) +
		    sizeof(struct vfio_region_dma_range)] = {};
	struct vfio_device_feature *feat = (void *)buf;
	struct vfio_device_feature_dma_buf *db = (void *)feat->data;
	struct iova_allocator *iova_alloc;
	int dmabuf_fd;
	iova_t iova;
	int ret;

	if (!self->iommu->iommufd)
		SKIP(return, "IOMMU_IOAS_MAP_FILE needs the iommufd backend");
	if (self->mem_size < SZ_2M)
		SKIP(return, "HDM memory < 2M");

	feat->argsz = sizeof(buf);
	feat->flags = VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_DMA_BUF;
	db->region_index = self->mem_idx;
	db->nr_ranges = 1;
	db->dma_ranges[0].offset = 0;
	db->dma_ranges[0].length = SZ_2M;

	ret = ioctl(self->dev->fd, VFIO_DEVICE_FEATURE, feat);
	if (ret < 0 && (errno == EINVAL || errno == EOPNOTSUPP))
		SKIP(return, "kernel has no CXL dma-buf exporter");
	ASSERT_GE(ret, 0);
	dmabuf_fd = ret;

	iova_alloc = iova_allocator_init(self->iommu);
	iova = iova_allocator_alloc(iova_alloc, SZ_2M);

	ASSERT_EQ(0, __iommu_map_file(self->iommu, dmabuf_fd, 0, SZ_2M, iova));
	iommu_unmap_all(self->iommu);

	iova_allocator_cleanup(iova_alloc);
	ASSERT_EQ(0, close(dmabuf_fd));
}

/*
 * The HDM dma-buf follows the HDM region, not Memory Space Enable: one
 * exported while Memory Space is off starts armed and maps with
 * IOMMU_IOAS_MAP_FILE once Memory Space is back on, without another export.
 */
TEST_F(vfio_cxl, hdm_dmabuf_export_memory_off)
{
	uint8_t buf[sizeof(struct vfio_device_feature) +
		    sizeof(struct vfio_device_feature_dma_buf) +
		    sizeof(struct vfio_region_dma_range)] = {};
	struct vfio_device_feature *feat = (void *)buf;
	struct vfio_device_feature_dma_buf *db = (void *)feat->data;
	struct iova_allocator *iova_alloc;
	int dmabuf_fd;
	uint16_t cmd;
	iova_t iova;

	if (!self->iommu->iommufd)
		SKIP(return, "IOMMU_IOAS_MAP_FILE needs the iommufd backend");
	if (self->mem_size < SZ_2M)
		SKIP(return, "HDM memory < 2M");

	feat->argsz = sizeof(buf);
	feat->flags = VFIO_DEVICE_FEATURE_GET | VFIO_DEVICE_FEATURE_DMA_BUF;
	db->region_index = self->mem_idx;
	db->nr_ranges = 1;
	db->dma_ranges[0].offset = 0;
	db->dma_ranges[0].length = SZ_2M;

	cmd = vfio_pci_config_readw(self->dev, PCI_COMMAND);
	vfio_pci_config_writew(self->dev, PCI_COMMAND,
			       cmd & ~PCI_COMMAND_MEMORY);
	dmabuf_fd = ioctl(self->dev->fd, VFIO_DEVICE_FEATURE, feat);
	vfio_pci_config_writew(self->dev, PCI_COMMAND, cmd);
	if (dmabuf_fd < 0 && (errno == EINVAL || errno == EOPNOTSUPP))
		SKIP(return, "kernel has no CXL dma-buf exporter");
	ASSERT_GE(dmabuf_fd, 0);

	iova_alloc = iova_allocator_init(self->iommu);
	iova = iova_allocator_alloc(iova_alloc, SZ_2M);

	ASSERT_EQ(0, __iommu_map_file(self->iommu, dmabuf_fd, 0, SZ_2M, iova));
	iommu_unmap_all(self->iommu);

	iova_allocator_cleanup(iova_alloc);
	ASSERT_EQ(0, close(dmabuf_fd));
}

/* The trapped block starts at the HDM decoder registers; CTRL 0 reads back. */
TEST_F(vfio_cxl, comp_regs_hdm_read)
{
	uint64_t ctrl = self->comp_off + CXL_HDM_DECODER0_CTRL_OFFSET(0);
	uint32_t val = 0;

	ASSERT_GE(self->comp_size, CXL_HDM_DECODER0_CTRL_OFFSET(0) + 4);
	ASSERT_EQ((ssize_t)sizeof(val),
		  pread(self->dev->fd, &val, sizeof(val), ctrl));
}

/*
 * The decoder block is BAR MMIO, so its region reads only with PCI Memory
 * Space enabled; with it disabled the read fails with EIO.
 */
TEST_F(vfio_cxl, comp_regs_read_needs_memory)
{
	uint64_t ctrl = self->comp_off + CXL_HDM_DECODER0_CTRL_OFFSET(0);
	uint16_t cmd;
	uint32_t val;
	ssize_t ret;

	cmd = vfio_pci_config_readw(self->dev, PCI_COMMAND);
	vfio_pci_config_writew(self->dev, PCI_COMMAND,
			       cmd & ~PCI_COMMAND_MEMORY);
	ret = pread(self->dev->fd, &val, sizeof(val), ctrl);
	vfio_pci_config_writew(self->dev, PCI_COMMAND, cmd);

	ASSERT_EQ(-1, ret);
	ASSERT_EQ(EIO, errno);
}

/*
 * A multi-dword read of the decoder block returns what the same registers
 * return one dword at a time (decoder 0 BASE_LOW, BASE_HIGH, SIZE_LOW,
 * SIZE_HIGH).
 */
TEST_F(vfio_cxl, comp_regs_read_multi_dword)
{
	uint64_t base = self->comp_off + CXL_HDM_DECODER0_BASE_LOW_OFFSET(0);
	uint32_t block[4], one;
	int i;

	ASSERT_GE(self->comp_size,
		  CXL_HDM_DECODER0_BASE_LOW_OFFSET(0) + sizeof(block));
	ASSERT_EQ((ssize_t)sizeof(block),
		  pread(self->dev->fd, block, sizeof(block), base));
	for (i = 0; i < 4; i++) {
		ASSERT_EQ((ssize_t)sizeof(one),
			  pread(self->dev->fd, &one, sizeof(one),
				base + i * sizeof(one)));
		ASSERT_EQ(block[i], one);
	}
}

/* The decoder registers only take aligned dword accesses. */
TEST_F(vfio_cxl, comp_regs_reject_unaligned)
{
	uint32_t val = 0;
	uint16_t half = 0;

	ASSERT_EQ(-1, pread(self->dev->fd, &val, sizeof(val),
			    self->comp_off + 1));
	ASSERT_EQ(-1, pread(self->dev->fd, &half, sizeof(half),
			    self->comp_off));
}

/* Accesses past the region end are rejected. */
TEST_F(vfio_cxl, comp_regs_reject_out_of_range)
{
	uint32_t val = 0;

	ASSERT_EQ(-1, pread(self->dev->fd, &val, sizeof(val),
			    self->comp_off + self->comp_size));
}

/*
 * Commit handshake: the host committed and locked the physical decoder, so the
 * trapped block reads back COMMITTED and a guest decommit request is absorbed.
 */
TEST_F(vfio_cxl, hdm_commit_fsm)
{
	uint64_t ctrl = self->comp_off + CXL_HDM_DECODER0_CTRL_OFFSET(0);
	uint32_t v, orig;

	ASSERT_EQ((ssize_t)sizeof(orig),
		  pread(self->dev->fd, &orig, sizeof(orig), ctrl));

	if (!(orig & CXL_HDM_DECODER0_CTRL_COMMITTED))
		SKIP(return, "HDM decoder 0 not committed by firmware");

	/* A decommit request is absorbed; the decoder stays committed. */
	v = orig & ~CXL_HDM_DECODER0_CTRL_COMMIT;
	ASSERT_EQ((ssize_t)sizeof(v),
		  pwrite(self->dev->fd, &v, sizeof(v), ctrl));
	ASSERT_EQ((ssize_t)sizeof(v),
		  pread(self->dev->fd, &v, sizeof(v), ctrl));
	ASSERT_TRUE(v & CXL_HDM_DECODER0_CTRL_COMMITTED);
}

/*
 * Lock on commit: a guest write of COMMIT | LOCK, and then of 0, is absorbed,
 * so the decoder stays committed and its LOCK bit stays as firmware left it.
 */
TEST_F(vfio_cxl, hdm_lock_on_commit)
{
	uint64_t ctrl = self->comp_off + CXL_HDM_DECODER0_CTRL_OFFSET(0);
	uint32_t before, v;

	ASSERT_EQ((ssize_t)sizeof(before),
		  pread(self->dev->fd, &before, sizeof(before), ctrl));
	if (!(before & CXL_HDM_DECODER0_CTRL_LOCK))
		TH_LOG("decoder 0 not locked by firmware; checking absorption only");

	v = CXL_HDM_DECODER0_CTRL_COMMIT | CXL_HDM_DECODER0_CTRL_LOCK;
	ASSERT_EQ((ssize_t)sizeof(v),
		  pwrite(self->dev->fd, &v, sizeof(v), ctrl));
	ASSERT_EQ((ssize_t)sizeof(v),
		  pread(self->dev->fd, &v, sizeof(v), ctrl));
	ASSERT_TRUE(v & CXL_HDM_DECODER0_CTRL_COMMITTED);
	ASSERT_EQ(before & CXL_HDM_DECODER0_CTRL_LOCK,
		  v & CXL_HDM_DECODER0_CTRL_LOCK);

	/* Attempt to decommit the decoder; it must stay committed. */
	v = 0;
	ASSERT_EQ((ssize_t)sizeof(v),
		  pwrite(self->dev->fd, &v, sizeof(v), ctrl));
	ASSERT_EQ((ssize_t)sizeof(v),
		  pread(self->dev->fd, &v, sizeof(v), ctrl));
	ASSERT_TRUE(v & CXL_HDM_DECODER0_CTRL_COMMITTED);
	ASSERT_EQ(before & CXL_HDM_DECODER0_CTRL_LOCK,
		  v & CXL_HDM_DECODER0_CTRL_LOCK);
}

/*
 * The committed decoder holds its base read-only: a guest write to the base is
 * absorbed and reads back the host-committed value.
 */
TEST_F(vfio_cxl, hdm_base_write_absorbed)
{
	uint64_t lo_off = self->comp_off + CXL_HDM_DECODER0_BASE_LOW_OFFSET(0);
	uint64_t ctrl_off = self->comp_off + CXL_HDM_DECODER0_CTRL_OFFSET(0);
	uint32_t v = 0x30000000U;	/* 256 MB-aligned low base bits */
	uint32_t rb = 0, orig = 0, ctrl = 0;

	ASSERT_GE(self->comp_size, CXL_HDM_DECODER0_BASE_LOW_OFFSET(0) + 4);
	ASSERT_EQ((ssize_t)sizeof(ctrl),
		  pread(self->dev->fd, &ctrl, sizeof(ctrl), ctrl_off));
	if (!(ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED))
		SKIP(return, "HDM decoder 0 not committed by firmware");

	ASSERT_EQ((ssize_t)sizeof(orig),
		  pread(self->dev->fd, &orig, sizeof(orig), lo_off));

	/* The write is absorbed; the base reads back unchanged. */
	ASSERT_EQ((ssize_t)sizeof(v),
		  pwrite(self->dev->fd, &v, sizeof(v), lo_off));
	ASSERT_EQ((ssize_t)sizeof(rb),
		  pread(self->dev->fd, &rb, sizeof(rb), lo_off));
	ASSERT_EQ(orig, rb);
}

/*
 * The CXL Device DVSEC body is virtualized by the kernel; a config read is
 * served from the shadow.
 */
TEST_F(vfio_cxl, dvsec_body_read)
{
	uint32_t v;

	if (!self->dvsec)
		SKIP(return, "CXL Device DVSEC not found");

	v = vfio_pci_config_readl(self->dev, self->dvsec + PCI_DVSEC_HEADER1);
	ASSERT_NE(0xffffffffU, v);
}

/*
 * Guest-initiated CXL reset: the DVSEC Initiate_CXL_Reset write runs the real
 * reset, self-clears, and STATUS2 in the shadow reports the outcome.
 */
TEST_F(vfio_cxl, guest_cxl_reset)
{
	uint16_t cap, ctrl2, status2;

	if (!self->dvsec)
		SKIP(return, "CXL Device DVSEC not found");

	cap = vfio_pci_config_readw(self->dev, self->dvsec + PCI_DVSEC_CXL_CAP);
	if (!(cap & PCI_DVSEC_CXL_RST_CAPABLE))
		SKIP(return, "device does not support CXL reset");

	ctrl2 = vfio_pci_config_readw(self->dev,
				      self->dvsec + PCI_DVSEC_CXL_CTRL2);
	vfio_pci_config_writew(self->dev, self->dvsec + PCI_DVSEC_CXL_CTRL2,
			       ctrl2 | PCI_DVSEC_CXL_INIT_CXL_RST);

	/* Initiate_CXL_Reset self-clears once the sequence has run. */
	ctrl2 = vfio_pci_config_readw(self->dev,
				      self->dvsec + PCI_DVSEC_CXL_CTRL2);
	ASSERT_FALSE(ctrl2 & PCI_DVSEC_CXL_INIT_CXL_RST);

	/* STATUS2 reports the outcome; a completed reset sets RESET_COMPLETE. */
	status2 = vfio_pci_config_readw(self->dev,
					self->dvsec + PCI_DVSEC_CXL_STATUS2);
	ASSERT_TRUE(status2 & PCI_DVSEC_CXL_RST_DONE);
	ASSERT_FALSE(status2 & PCI_DVSEC_CXL_RST_ERR);
}

/*
 * A real reset must run end to end, not just the shadow DVSEC path
 * guest_cxl_reset covers: a CXL Type-2 device must advertise
 * VFIO_DEVICE_FLAGS_RESET and complete a real VFIO_DEVICE_RESET.
 */
TEST_F(vfio_cxl, device_reset)
{
	uint8_t infobuf[512] = {};
	struct vfio_device_info *info = (void *)infobuf;
	int ret, retries = 20;

	info->argsz = sizeof(infobuf);
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_INFO, info));

	ASSERT_NE(0, info->flags & VFIO_DEVICE_FLAGS_RESET);

	/* Drive the real reset, retrying the transient device-lock contention. */
	do {
		ret = __vfio_pci_device_reset(self->dev);
		if (ret == -EAGAIN)
			usleep(10000);
	} while (ret == -EAGAIN && retries-- > 0);
	ASSERT_EQ(0, ret);
}

/*
 * The component BAR is reachable by fd read except the trapped decoder block,
 * which is served only through the comp-regs region; a VMM relies on this split.
 */
TEST_F(vfio_cxl, comp_bar_rdwr_split)
{
	uint64_t bar_off = VFIO_PCI_INDEX_TO_OFFSET(self->comp_bar);
	uint32_t val;

	/* A non-decoder dword of the BAR reads back through the fd. */
	ASSERT_EQ((ssize_t)sizeof(val),
		  pread(self->dev->fd, &val, sizeof(val), bar_off));

	/*
	 * The trapped decoder block is off-limits to raw BAR fd access: the read
	 * returns all-ones, not the real decoder contents.
	 */
	val = 0;
	ASSERT_EQ((ssize_t)sizeof(val),
		  pread(self->dev->fd, &val, sizeof(val),
			bar_off + self->comp_offset));
	ASSERT_EQ(0xffffffffU, val);
}

/*
 * Mirror the guest's HDM discovery, which does not use VFIO's geometry cap: it
 * finds the range by walking the config-space DVSECs and the component-register
 * array to the HDM decoder itself.
 */
TEST_F(vfio_cxl, guest_hdm_discovery)
{
	uint64_t bar_off = VFIO_PCI_INDEX_TO_OFFSET(self->comp_bar);
	uint32_t reg_lo, reg_hi, cap_array, cap_count, hdr;
	uint32_t bl, bh, sl, sh, ctrl;
	uint64_t block_off, cm, hdm_off = 0, base, size;
	uint16_t pos = PCI_CFG_SPACE_SIZE, regloc = 0, block1;
	int iter = 0, bar, i;

	/* 1. Find the CXL Register Locator DVSEC in config space. */
	while (pos && iter++ < 64) {
		uint32_t h = vfio_pci_config_readl(self->dev, pos);

		if ((h & 0xffff) == PCI_EXT_CAP_ID_DVSEC) {
			uint32_t h1 = vfio_pci_config_readl(self->dev, pos + 4);
			uint32_t h2 = vfio_pci_config_readl(self->dev, pos + 8);

			if ((h1 & 0xffff) == PCI_DVSEC_VENDOR_ID_CXL &&
			    (h2 & 0xffff) == PCI_DVSEC_CXL_REG_LOCATOR) {
				regloc = pos;
				break;
			}
		}
		pos = (h >> 20) & 0xffc;
	}
	ASSERT_NE(0, regloc);

	/* 2. Take the component register block BAR and offset from block 1. */
	block1 = regloc + PCI_DVSEC_CXL_REG_LOCATOR_BLOCK1;
	reg_lo = vfio_pci_config_readl(self->dev, block1);
	reg_hi = vfio_pci_config_readl(self->dev, block1 + 4);

	ASSERT_EQ(CXL_REGLOC_RBI_COMPONENT,
		  (reg_lo & REG_LOCATOR_BLOCK_ID_MASK) >> 8);
	bar = reg_lo & REG_LOCATOR_BIR_MASK;
	block_off = ((uint64_t)reg_hi << 32) |
		    (reg_lo & REG_LOCATOR_BLOCK_OFF_LOW_MASK);

	/* The DVSEC must name the same BAR the geometry cap reported. */
	ASSERT_EQ(self->comp_bar, bar);

	/* 3. Walk the CM capability array over the BAR to find the HDM cap. */
	cm = block_off + CXL_CM_OFFSET;
	ASSERT_EQ((ssize_t)sizeof(cap_array),
		  pread(self->dev->fd, &cap_array, sizeof(cap_array),
			bar_off + cm + CXL_CM_CAP_HDR_OFFSET));
	ASSERT_EQ(CM_CAP_HDR_CAP_ID, cap_array & CXL_CM_CAP_HDR_ID_MASK);

	cap_count = (cap_array & CXL_CM_CAP_HDR_ARRAY_SIZE_MASK) >> 24;
	for (i = 1; i <= (int)cap_count; i++) {
		ASSERT_EQ((ssize_t)sizeof(hdr),
			  pread(self->dev->fd, &hdr, sizeof(hdr),
				bar_off + cm + i * 4));
		if ((hdr & CXL_CM_CAP_HDR_ID_MASK) == CXL_CM_CAP_CAP_ID_HDM) {
			hdm_off = cm + ((hdr & CXL_CM_CAP_PTR_MASK) >> 20);
			break;
		}
	}
	ASSERT_NE(0, hdm_off);

	/* The guest's manual walk must land on the decoder the kernel traps. */
	ASSERT_EQ(self->comp_offset, hdm_off);

	/* 4. Read decoder 0 through the trapped region and derive base/size. */
	ASSERT_EQ((ssize_t)sizeof(bl),
		  pread(self->dev->fd, &bl, sizeof(bl),
			self->comp_off + CXL_HDM_DECODER0_BASE_LOW_OFFSET(0)));
	ASSERT_EQ((ssize_t)sizeof(bh),
		  pread(self->dev->fd, &bh, sizeof(bh),
			self->comp_off + CXL_HDM_DECODER0_BASE_HIGH_OFFSET(0)));
	ASSERT_EQ((ssize_t)sizeof(sl),
		  pread(self->dev->fd, &sl, sizeof(sl),
			self->comp_off + CXL_HDM_DECODER0_SIZE_LOW_OFFSET(0)));
	ASSERT_EQ((ssize_t)sizeof(sh),
		  pread(self->dev->fd, &sh, sizeof(sh),
			self->comp_off + CXL_HDM_DECODER0_SIZE_HIGH_OFFSET(0)));
	ASSERT_EQ((ssize_t)sizeof(ctrl),
		  pread(self->dev->fd, &ctrl, sizeof(ctrl),
			self->comp_off + CXL_HDM_DECODER0_CTRL_OFFSET(0)));

	base = ((uint64_t)bh << 32) | bl;
	size = ((uint64_t)sh << 32) | sl;

	/* A guest only accepts a committed decoder; the derived range must be non-empty. */
	if (!(ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED))
		SKIP(return, "HDM decoder 0 not committed by firmware");

	ASSERT_GT(size, 0);
	ASSERT_LT(base, base + size);
}

/*
 * Tie the committed decoder's geometry to the HDM memory region a VMM hands the
 * guest: confirm the mmap-able region covers exactly the decoder's range, then
 * map the advertised base and touch it.
 */
TEST_F(vfio_cxl, hdm_mem_touch_committed_base)
{
	uint64_t mem_off = VFIO_PCI_INDEX_TO_OFFSET(self->mem_idx);
	uint32_t pattern = 0xc0ffee11U, readback = 0;
	uint32_t bl, bh, sl, sh, ctrl;
	uint64_t base, size;
	void *map;

	ASSERT_EQ((ssize_t)sizeof(ctrl),
		  pread(self->dev->fd, &ctrl, sizeof(ctrl),
			self->comp_off + CXL_HDM_DECODER0_CTRL_OFFSET(0)));
	if (!(ctrl & CXL_HDM_DECODER0_CTRL_COMMITTED))
		SKIP(return, "HDM decoder 0 not committed by firmware");

	ASSERT_EQ((ssize_t)sizeof(bl),
		  pread(self->dev->fd, &bl, sizeof(bl),
			self->comp_off + CXL_HDM_DECODER0_BASE_LOW_OFFSET(0)));
	ASSERT_EQ((ssize_t)sizeof(bh),
		  pread(self->dev->fd, &bh, sizeof(bh),
			self->comp_off + CXL_HDM_DECODER0_BASE_HIGH_OFFSET(0)));
	ASSERT_EQ((ssize_t)sizeof(sl),
		  pread(self->dev->fd, &sl, sizeof(sl),
			self->comp_off + CXL_HDM_DECODER0_SIZE_LOW_OFFSET(0)));
	ASSERT_EQ((ssize_t)sizeof(sh),
		  pread(self->dev->fd, &sh, sizeof(sh),
			self->comp_off + CXL_HDM_DECODER0_SIZE_HIGH_OFFSET(0)));

	base = ((uint64_t)bh << 32) | bl;
	size = ((uint64_t)sh << 32) | sl;

	ASSERT_GT(size, 0);
	ASSERT_LT(base, base + size);
	/* The mmap-able HDM region must cover exactly the committed decoder. */
	ASSERT_EQ(size, self->mem_size);

	if (self->mem_size < SZ_4K)
		SKIP(return, "HDM memory < 4K");

	/* Region offset 0 is the decoder's advertised base; map it and touch it. */
	map = mmap(NULL, SZ_4K, PROT_READ | PROT_WRITE, MAP_SHARED,
		   self->dev->fd, mem_off);
	ASSERT_NE(MAP_FAILED, map);

	memcpy(map, &pattern, sizeof(pattern));
	memcpy(&readback, map, sizeof(readback));
	ASSERT_EQ(pattern, readback);

	ASSERT_EQ(0, munmap(map, SZ_4K));
}

/*
 * The CXL Device DVSEC is served from a shadow: Control is guest-programmable
 * but Capability keeps its firmware snapshot, so a guest cannot reprogram the
 * device through the DVSEC.
 */
TEST_F(vfio_cxl, dvsec_write_virtualized)
{
	uint16_t cap, ctrl, v;

	if (!self->dvsec)
		SKIP(return, "CXL Device DVSEC not found");

	/* A write to the read-only Capability register is absorbed. */
	cap = vfio_pci_config_readw(self->dev, self->dvsec + PCI_DVSEC_CXL_CAP);
	vfio_pci_config_writew(self->dev, self->dvsec + PCI_DVSEC_CXL_CAP,
			       cap ^ 0xffff);
	v = vfio_pci_config_readw(self->dev, self->dvsec + PCI_DVSEC_CXL_CAP);
	ASSERT_EQ(cap, v);

	/* Control is guest-programmable; a write reads back from the shadow. */
	ctrl = vfio_pci_config_readw(self->dev, self->dvsec + PCI_DVSEC_CXL_CTRL);
	vfio_pci_config_writew(self->dev, self->dvsec + PCI_DVSEC_CXL_CTRL,
			       ctrl ^ 0x1);
	v = vfio_pci_config_readw(self->dev, self->dvsec + PCI_DVSEC_CXL_CTRL);
	ASSERT_EQ((uint16_t)(ctrl ^ 0x1), v);

	/* The write stayed in the shadow: hardware Control is unchanged. */
	if (!sysfs_config_read(self->dvsec + PCI_DVSEC_CXL_CTRL, &v, sizeof(v)))
		ASSERT_EQ(ctrl, v);
	vfio_pci_config_writew(self->dev, self->dvsec + PCI_DVSEC_CXL_CTRL, ctrl);
}

/*
 * Region-info contract: the HDM memory region is readable, writable and
 * mmappable; the trapped comp-regs region is fd-only and carries the geometry
 * capability.
 */
TEST_F(vfio_cxl, region_flags)
{
	const uint32_t rw = VFIO_REGION_INFO_FLAG_READ |
			    VFIO_REGION_INFO_FLAG_WRITE;
	const struct vfio_info_cap_header *geo;
	uint8_t rbuf[1024] = {};
	struct vfio_region_info *ri = (void *)rbuf;

	ri->argsz = sizeof(rbuf);
	ri->index = self->mem_idx;
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_REGION_INFO, ri));
	ASSERT_EQ(rw | VFIO_REGION_INFO_FLAG_MMAP,
		  ri->flags & (rw | VFIO_REGION_INFO_FLAG_MMAP));

	memset(rbuf, 0, sizeof(rbuf));
	ri->argsz = sizeof(rbuf);
	ri->index = self->comp_idx;
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_GET_REGION_INFO, ri));
	ASSERT_EQ(rw, ri->flags & rw);
	ASSERT_EQ(0, ri->flags & VFIO_REGION_INFO_FLAG_MMAP);
	geo = find_region_cap(rbuf, sizeof(rbuf),
			      VFIO_REGION_INFO_CAP_CXL_COMP_REGS);
	ASSERT_NE(NULL, geo);
}

/* True when decoder 0 reads back committed and the HDM region is readable. */
static bool hdm_back_after(int fd, uint64_t comp_off, int mem_idx)
{
	uint64_t ctrl = comp_off + CXL_HDM_DECODER0_CTRL_OFFSET(0);
	uint64_t mem = VFIO_PCI_INDEX_TO_OFFSET(mem_idx);
	uint32_t val = 0;

	if (pread(fd, &val, sizeof(val), ctrl) != sizeof(val))
		return false;
	if (!(val & CXL_HDM_DECODER0_CTRL_COMMITTED))
		return false;

	return pread(fd, &val, sizeof(val), mem) == sizeof(val);
}

/*
 * Low power loses the committed decoder; the host restores it when the device
 * returns to D0, so the decoder reads back committed and HDM access works.
 */
TEST_F(vfio_cxl, low_power_restores_decoder)
{
	struct vfio_device_feature feature = {
		.argsz = sizeof(feature),
		.flags = VFIO_DEVICE_FEATURE_SET |
			 VFIO_DEVICE_FEATURE_LOW_POWER_ENTRY,
	};

	if (ioctl(self->dev->fd, VFIO_DEVICE_FEATURE, &feature))
		SKIP(return, "low power entry not supported (%d)", errno);

	feature.flags = VFIO_DEVICE_FEATURE_SET |
			VFIO_DEVICE_FEATURE_LOW_POWER_EXIT;
	ASSERT_EQ(0, ioctl(self->dev->fd, VFIO_DEVICE_FEATURE, &feature));

	ASSERT_TRUE(hdm_back_after(self->dev->fd, self->comp_off,
				   self->mem_idx));
}

/* Read or write the physical config space through sysfs, bypassing vfio. */
static int sysfs_config(bool wr, off_t off, void *buf, size_t len)
{
	char path[128];
	ssize_t ret;
	int fd;

	snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/config",
		 device_bdf);
	fd = open(path, wr ? O_WRONLY : O_RDONLY);
	if (fd < 0)
		return -errno;
	ret = wr ? pwrite(fd, buf, len, off) : pread(fd, buf, len, off);
	close(fd);
	return ret == (ssize_t)len ? 0 : -EIO;
}

/*
 * The close path restores the config state saved at open: Memory Space on
 * (pci_enable_device()) and Bus Master off (pci_clear_master()). The close
 * time CXL Reset must not replace it with the post-use state, where
 * vfio_pci_core_disable() has left only INTx Disable set.
 */
TEST(close_restores_open_time_command)
{
	struct vfio_device_info info = { .argsz = sizeof(info) };
	struct vfio_pci_device *dev;
	struct iommu *iommu;
	uint16_t cmd = 0;
	bool cxl;

	iommu = iommu_init(default_iommu_mode);
	dev = vfio_pci_device_init(device_bdf, iommu);
	ASSERT_EQ(0, ioctl(dev->fd, VFIO_DEVICE_GET_INFO, &info));
	cxl = info.flags & VFIO_DEVICE_FLAGS_CXL;
	if (cxl)
		vfio_pci_cmd_set(dev, PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	vfio_pci_device_cleanup(dev);
	iommu_cleanup(iommu);
	if (!cxl)
		SKIP(return, "not a CXL Type-2 device");

	ASSERT_EQ(0, sysfs_config(false, PCI_COMMAND, &cmd, sizeof(cmd)));
	ASSERT_NE(0, cmd & PCI_COMMAND_MEMORY);
	ASSERT_EQ(0, cmd & PCI_COMMAND_MASTER);
}

/* Find a standard capability through the vfio config view. */
static uint8_t find_std_cap(struct vfio_pci_device *dev, uint8_t id)
{
	uint8_t pos = vfio_pci_config_readb(dev, PCI_CAPABILITY_LIST) & ~3;
	int iter = 0;

	while (pos && iter++ < 48) {
		if (vfio_pci_config_readb(dev, pos + PCI_CAP_LIST_ID) == id)
			return pos;
		pos = vfio_pci_config_readb(dev, pos + PCI_CAP_LIST_NEXT) & ~3;
	}
	return 0;
}

/*
 * A D3hot write to the PM control register closes the HDM gate and the D0
 * write reopens it with the decoder restored. If D3hot entry fails or a quirk
 * keeps the device in D0, the gate must still reopen at once.
 */
TEST_F(vfio_cxl, pm_d3hot_restores_decoder)
{
	uint8_t pm = find_std_cap(self->dev, PCI_CAP_ID_PM);
	uint16_t ctrl;

	if (!pm)
		SKIP(return, "no PCI PM capability");

	ctrl = vfio_pci_config_readw(self->dev, pm + PCI_PM_CTRL);
	vfio_pci_config_writew(self->dev, pm + PCI_PM_CTRL,
			       (ctrl & ~PCI_PM_CTRL_STATE_MASK) | 3);
	vfio_pci_config_writew(self->dev, pm + PCI_PM_CTRL,
			       ctrl & ~PCI_PM_CTRL_STATE_MASK);

	ASSERT_TRUE(hdm_back_after(self->dev->fd, self->comp_off,
				   self->mem_idx));
}

int main(int argc, char *argv[])
{
	device_bdf = vfio_selftests_get_bdf(&argc, argv);
	return test_harness_run(argc, argv);
}
