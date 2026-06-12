// SPDX-License-Identifier: GPL-2.0-only
/*
 * ARM64 DRTM Secure Launch support. Processes DRTM state when the kernel
 * is launched as a DLME via DRTM dynamic launch; called early in
 * setup_arch(). Copyright (c) 2025-2026, NVIDIA Corporation.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/io.h>
#include <linux/efi.h>
#include <linux/of_fdt.h>
#include <linux/libfdt.h>
#include <linux/arm-smccc.h>
#include <linux/overflow.h>
#include <linux/initrd.h>
#include <crypto/sha2.h>

#include <asm/drtm.h>
#include <asm/setup.h>

/* FDT magic number (big-endian 0xd00dfeed at offset 0) */
#define FDT_HEADER_MAGIC	0xd00dfeed

/*
 * D-CRTM address map in the DLME data region (populated by D-CRTM,
 * memblock_reserve'd by slaunch_setup()). Mapped once in early_init;
 * pointer kept for all validation. No copy, no region-count cap.
 */
static struct drtm_mem_region *dcrtm_regions;
static u32 dcrtm_num_regions;

/*
 * DLME data extent saved at slaunch_setup() time so that
 * slaunch_measure_post_efi() can re-reserve the region after efi_init()'s
 * memblock_remove(0, PHYS_ADDR_MAX) wipes our earlier reservation.
 */
static phys_addr_t sl_dlme_data_pa;
static u64 sl_dlme_data_size;

/*
 * Close TPM locality 2 — the DLME's locality, per DEN0113 v1.2 §4.6.1.
 * Locality 3 is the DCE's; it's closed by the DCE, not the DLME.
 */
static void __init slaunch_tpm_setup(void)
{
	struct arm_smccc_res res;

	arm_smccc_smc(DRTM_SMC_CLOSE_LOCALITY, 2, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == (unsigned long)DRTM_NOT_SUPPORTED)
		pr_warn("slaunch: CLOSE_LOCALITY not supported (no TPM backend)\n");
	else if (res.a0 != DRTM_SUCCESS)
		pr_err("slaunch: CLOSE_LOCALITY failed: %ld\n", (long)res.a0);
	else
		pr_info("slaunch: TPM locality 2 closed\n");
}

/*
 * Parse the D-CRTM address map (at header_size + protected_regions_size
 * within DLME data). A trusted EL3-populated input describing physical
 * memory layout; stored for validating untrusted data (DTB, EFI mmap).
 * Returns true on success.
 */
static bool __init slaunch_parse_address_map(phys_addr_t dlme_data_pa,
					     struct dlme_data_header *hdr)
{
	phys_addr_t map_pa;
	u64 map_size;
	u64 hdr_size, prot_size;
	struct drtm_mem_region_hdr *map_hdr;
	struct drtm_mem_region *regions;
	u32 num_regions, i;

	/*
	 * All offset arithmetic below assumes the v1 dlme_data_header
	 * layout; a later revision would target wrong bytes. Reject != v1.
	 */
	if (le16_to_cpu(hdr->version) != 1)
		panic("slaunch: DLME data header version %u; only v1 supported\n",
		      le16_to_cpu(hdr->version));

	hdr_size = le16_to_cpu(hdr->this_hdr_size);
	prot_size = le64_to_cpu(hdr->protected_regions_size);
	map_size = le64_to_cpu(hdr->address_map_size);

	if (map_size == 0) {
		pr_err("slaunch: D-CRTM address map is empty\n");
		return false;
	}

	if (map_size < sizeof(struct drtm_mem_region_hdr)) {
		pr_err("slaunch: address map too small (%llu bytes)\n",
		       map_size);
		return false;
	}

	map_pa = dlme_data_pa + hdr_size + prot_size;

	/* Map temporarily to validate and log */
	map_hdr = early_memremap(map_pa, (size_t)map_size);
	if (!map_hdr) {
		pr_err("slaunch: failed to map address map at 0x%llx\n",
		       (u64)map_pa);
		return false;
	}

	num_regions = le32_to_cpu(map_hdr->num_regions);
	pr_info("slaunch: D-CRTM address map: revision=%u, %u regions\n",
		le16_to_cpu(map_hdr->revision), num_regions);

	if (sizeof(struct drtm_mem_region_hdr) +
	    (u64)num_regions * sizeof(struct drtm_mem_region) > map_size) {
		pr_err("slaunch: address map regions overflow map size\n");
		early_memunmap(map_hdr, (size_t)map_size);
		return false;
	}

	/* Log regions for debug */
	regions = (struct drtm_mem_region *)((u8 *)map_hdr +
					     sizeof(struct drtm_mem_region_hdr));
	for (i = 0; i < num_regions; i++) {
		u64 addr = le64_to_cpu(regions[i].start_address);
		u64 st = le64_to_cpu(regions[i].size_and_type);
		u64 pages = DRTM_MEM_REGION_PAGE_COUNT(st);
		u32 type = DRTM_MEM_REGION_TYPE(st);

		pr_info("slaunch:   [%u] 0x%012llx - 0x%012llx  %s (%llu pages)\n",
			i, addr, addr + pages * DRTM_PAGE_SIZE,
			type == DRTM_REGION_TYPE_NORMAL        ? "NORMAL" :
			type == DRTM_REGION_TYPE_NORMAL_CACHED ? "NORMAL_CACHED" :
			type == DRTM_REGION_TYPE_DEVICE        ? "DEVICE" :
			type == DRTM_REGION_TYPE_NV            ? "NV" :
			type == DRTM_REGION_TYPE_RSVD          ? "RSVD" :
			"UNKNOWN", pages);
	}

	early_memunmap(map_hdr, (size_t)map_size);

	/*
	 * Map regions and keep the pointer (physical memory is in DLME
	 * data, memblock_reserve'd later); validators use it directly.
	 */
	dcrtm_regions = early_memremap_ro(map_pa + sizeof(struct drtm_mem_region_hdr),
					  num_regions * sizeof(struct drtm_mem_region));
	if (!dcrtm_regions) {
		pr_err("slaunch: failed to map address map regions\n");
		return false;
	}
	dcrtm_num_regions = num_regions;
	return true;
}

/*
 * Verify D-CRTM published full-range DMA protection (DEN0113 v1.2
 * §4.6.2). Walks the protected_regions sub-region and requires the
 * spec-conformant "single entry, start=0, full-range" encoding; partial
 * lockdown breaks the measure-then-parse soundness model.
 */
static void __init slaunch_assert_full_lockdown(phys_addr_t dlme_data_pa,
						u64 hdr_size, u64 prot_size)
{
	const struct drtm_mem_region_hdr *phdr;
	const struct drtm_mem_region *regs;
	phys_addr_t prot_pa;
	u32 num;
	u64 start, st;

	if (prot_size == 0)
		panic("slaunch: DCE published empty protected_regions; cannot verify SMMU lockdown\n");
	if (prot_size < sizeof(*phdr) + sizeof(*regs))
		panic("slaunch: protected_regions size %llu too small for 1 entry\n",
		      prot_size);

	prot_pa = dlme_data_pa + hdr_size;
	phdr = early_memremap_ro(prot_pa, (size_t)prot_size);
	if (!phdr)
		panic("slaunch: cannot map protected_regions at 0x%llx\n",
		      (u64)prot_pa);

	num = le32_to_cpu(phdr->num_regions);
	regs = (const struct drtm_mem_region *)((const u8 *)phdr + sizeof(*phdr));
	start = le64_to_cpu(regs[0].start_address);
	st = le64_to_cpu(regs[0].size_and_type);

	/*
	 * Strict spec match (DEN0113 v1.2 §3.15 R314110 + §4.6.2): single
	 * entry, start=0, size_and_type = DRTM_MEM_PROT_FULL_RANGE. Anything
	 * else is partial lockdown or non-conformant — fatal.
	 */
	if (num != 1 || start != 0 || st != DRTM_MEM_PROT_FULL_RANGE)
		panic("slaunch: SMMU lockdown not full-range (num=%u start=0x%llx st=0x%llx; want 1/0/0x%llx); DRTM secure launch requires full DRAM coverage\n",
		      num, start, st, (u64)DRTM_MEM_PROT_FULL_RANGE);

	early_memunmap(phdr, (size_t)prot_size);
	pr_info("slaunch: SMMU lockdown verified: full NS-DRAM coverage\n");
}

/*
 * True if [start, start+size) falls entirely within normal memory of
 * the D-CRTM address map. Normal = type 0 or type 1 (cacheability);
 * DEVICE/NV/RSVD are rejected (DEN0113 v1.2 §3.14 Table 11 + R314100).
 * Supports ranges spanning multiple adjacent/overlapping regions.
 */
static bool __init dcrtm_range_in_normal(u64 start, u64 size)
{
	u64 pos = start;
	u64 end;

	if (!size || !dcrtm_regions)
		return false;
	/* Reject ranges that wrap u64 (attacker-controlled inputs). */
	if (check_add_overflow(start, size, &end))
		return false;

	while (pos < end) {
		bool advanced = false;
		u32 i;

		for (i = 0; i < dcrtm_num_regions; i++) {
			u64 st = le64_to_cpu(dcrtm_regions[i].size_and_type);
			u32 type = DRTM_MEM_REGION_TYPE(st);
			u64 pages = DRTM_MEM_REGION_PAGE_COUNT(st);
			u64 rstart = le64_to_cpu(dcrtm_regions[i].start_address);
			u64 rsize, rend;

			if (type != DRTM_REGION_TYPE_NORMAL &&
			    type != DRTM_REGION_TYPE_NORMAL_CACHED)
				continue;

			/* Skip malformed regions whose size or end wraps. */
			if (check_mul_overflow(pages, (u64)DRTM_PAGE_SIZE, &rsize))
				continue;
			if (check_add_overflow(rstart, rsize, &rend))
				continue;

			if (pos >= rstart && pos < rend) {
				pos = (rend < end) ? rend : end;
				advanced = true;
				break;
			}
		}

		if (!advanced)
			return false;
	}
	return true;
}

/*
 * Check if a range overlaps any non-normal region (DEVICE, NV, RSVD);
 * type 0/1 normal memory is skipped (DEN0113 v1.2 §3.14 Table 11).
 * Returns the region type if overlap found, -1 otherwise.
 */
static int __init dcrtm_range_overlaps_non_normal(u64 start, u64 size)
{
	u32 i;
	u64 end;

	if (!dcrtm_regions)
		return -1;
	/* Wrapping range — fail closed: pretend it overlaps an RSVD region. */
	if (check_add_overflow(start, size, &end))
		return DRTM_REGION_TYPE_RSVD;

	for (i = 0; i < dcrtm_num_regions; i++) {
		u64 st = le64_to_cpu(dcrtm_regions[i].size_and_type);
		u32 type = DRTM_MEM_REGION_TYPE(st);
		u64 pages = DRTM_MEM_REGION_PAGE_COUNT(st);
		u64 rstart = le64_to_cpu(dcrtm_regions[i].start_address);
		u64 rsize, rend;

		if (type == DRTM_REGION_TYPE_NORMAL ||
		    type == DRTM_REGION_TYPE_NORMAL_CACHED)
			continue;

		/* Malformed region whose size or end wraps: fail closed
		 * (assume it overlaps).
		 */
		if (check_mul_overflow(pages, (u64)DRTM_PAGE_SIZE, &rsize))
			return type;
		if (check_add_overflow(rstart, rsize, &rend))
			return type;

		if (start < rend && end > rstart)
			return type;
	}
	return -1;
}

static const char * __init dcrtm_type_name(int type)
{
	switch (type) {
	case DRTM_REGION_TYPE_NORMAL:		return "NORMAL";
	case DRTM_REGION_TYPE_NORMAL_CACHED:	return "NORMAL_CACHED";
	case DRTM_REGION_TYPE_DEVICE:		return "DEVICE";
	case DRTM_REGION_TYPE_NV:		return "NV";
	case DRTM_REGION_TYPE_RSVD:		return "RSVD";
	default: return "UNKNOWN";
	}
}

/*
 * Check if two EFI memory regions overlap.
 */
static bool __init efi_regions_overlap(u64 s1, u64 sz1, u64 s2, u64 sz2)
{
	u64 e1, e2;

	/* Either range wraps u64 -> fail closed (report overlap). */
	if (check_add_overflow(s1, sz1, &e1) ||
	    check_add_overflow(s2, sz2, &e2))
		return true;
	return (s1 < e2) && (s2 < e1);
}

/*
 * slaunch_early_init() -- earliest DRTM validation, called BEFORE
 * setup_machine_fdt() (after early_ioremap_init). Parses the D-CRTM
 * address map, then validates the DTB PA/magic/size against it. Panics
 * on any failure: the DTB is untrusted until validated.
 */
void __init slaunch_early_init(void)
{
	struct dlme_data_header *hdr;
	phys_addr_t dlme_data_pa;
	phys_addr_t dtb_pa;
	u32 *dtb_hdr;
	u32 fdt_magic, fdt_size;

	if (!sl_dlme_region_pa)
		return;

	pr_info("slaunch: DRTM early init -- validating DTB before consumption\n");
	pr_info("slaunch: DLME region PA: 0x%lx, data offset: 0x%lx\n",
		sl_dlme_region_pa, sl_dlme_data_offset);

	/* Step 1: Map DLME data header and parse address map */
	dlme_data_pa = sl_dlme_region_pa + sl_dlme_data_offset;
	hdr = early_memremap(dlme_data_pa, sizeof(*hdr));
	if (!hdr)
		panic("slaunch: failed to map DLME data header at 0x%llx\n",
		      (u64)dlme_data_pa);

	if (!slaunch_parse_address_map(dlme_data_pa, hdr))
		panic("slaunch: failed to parse D-CRTM address map -- cannot validate untrusted data\n");

	early_memunmap(hdr, sizeof(*hdr));

	/* Step 2: Validate DTB PA is in a NORMAL region */
	dtb_pa = __fdt_pointer;
	if (!dtb_pa)
		panic("slaunch: no DTB physical address available for validation\n");

	pr_info("slaunch: DTB PA: 0x%llx\n", (u64)dtb_pa);

	/*
	 * Check the FDT header (magic + totalsize) is in a NORMAL region;
	 * the full-size check follows once fdt_totalsize is read.
	 */
	if (!dcrtm_range_in_normal(dtb_pa, sizeof(u32) * 2))
		panic("slaunch: DTB PA 0x%llx is NOT in a D-CRTM NORMAL region\n",
		      (u64)dtb_pa);

	/* Step 3: Map DTB header and verify FDT magic + size */
	dtb_hdr = early_memremap(dtb_pa, sizeof(u32) * 2);
	if (!dtb_hdr)
		panic("slaunch: failed to map DTB header at 0x%llx\n",
		      (u64)dtb_pa);

	fdt_magic = be32_to_cpu(dtb_hdr[0]);
	fdt_size = be32_to_cpu(dtb_hdr[1]);

	early_memunmap(dtb_hdr, sizeof(u32) * 2);

	if (fdt_magic != FDT_HEADER_MAGIC)
		panic("slaunch: DTB at 0x%llx has invalid FDT magic: 0x%08x (expected 0x%08x)\n",
		      (u64)dtb_pa, fdt_magic, FDT_HEADER_MAGIC);

	if (fdt_size == 0)
		panic("slaunch: DTB at 0x%llx reports zero totalsize\n",
		      (u64)dtb_pa);

	/*
	 * Validate the full DTB range is in NORMAL memory; containment also
	 * caps fdt_size, so an over-large totalsize fails.
	 */
	if (!dcrtm_range_in_normal(dtb_pa, fdt_size))
		panic("slaunch: DTB range [0x%llx - 0x%llx] extends outside D-CRTM NORMAL region\n",
		      (u64)dtb_pa, (u64)(dtb_pa + fdt_size));

	pr_info("slaunch: DTB validated: magic=0x%08x, size=%u bytes, in NORMAL region\n",
		fdt_magic, fdt_size);
}

/* Placeholder; populated by a subsequent patch. */
void __init slaunch_setup(void) { }

/* Placeholder; populated by a subsequent patch. */
void __init slaunch_measure_post_efi(void) { }

/* Placeholder; populated by a subsequent patch. */
void slaunch_exit(void) { }
