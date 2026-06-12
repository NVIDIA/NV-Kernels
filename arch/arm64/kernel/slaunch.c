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

/*
 * Validate all untrusted EFI inputs BEFORE efi_init() consumes them
 * (it reads systab tables and walks the EFI mmap into memblock). The
 * early validators below operate on the raw firmware buffers, not
 * efi.memmap, which does not exist yet at this stage.
 */
struct sl_efi_info {
	bool present;
	u64  systab_pa;
	u64  mmap_pa;
	u64  mmap_size;
	u32  desc_size;
	u32  desc_ver;
};

/* Forward decls — bodies defined later (or stubbed out by #ifdef
 * gating below).
 */
#ifdef CONFIG_ARM64_SECURE_LAUNCH_FAULT_INJECT
static void __init slaunch_inject_fault(struct sl_efi_info *info);
#else
static inline void slaunch_inject_fault(struct sl_efi_info *info) { }
#endif
#ifdef CONFIG_ARM64_SECURE_LAUNCH_SELFTEST
static void __init slaunch_selftest(void);
#else
static inline void slaunch_selftest(void) { }
#endif

static void __init slaunch_read_chosen_efi(struct sl_efi_info *info)
{
	const void *fdt = initial_boot_params;
	const __be64 *p64;
	const __be32 *p32;
	int node, len;

	memset(info, 0, sizeof(*info));
	if (!fdt)
		return;
	node = fdt_path_offset(fdt, "/chosen");
	if (node < 0)
		return;

#define _GET64(name, field)							\
	do {									\
		p64 = fdt_getprop(fdt, node, name, &len);			\
		if (!p64 || len < (int)sizeof(__be64))				\
			return;							\
		info->field = be64_to_cpu(*p64);				\
	} while (0)
#define _GET32(name, field)							\
	do {									\
		p32 = fdt_getprop(fdt, node, name, &len);			\
		if (!p32 || len < (int)sizeof(__be32))				\
			return;							\
		info->field = be32_to_cpu(*p32);				\
	} while (0)
	_GET64("linux,uefi-system-table",   systab_pa);
	_GET64("linux,uefi-mmap-start",     mmap_pa);
	_GET32("linux,uefi-mmap-size",      mmap_size);
	_GET32("linux,uefi-mmap-desc-size", desc_size);
	_GET32("linux,uefi-mmap-desc-ver",  desc_ver);
#undef _GET64
#undef _GET32
	info->present = true;
}

/*
 * Per-GUID minimum sizes for known EFI ConfigurationTable entries (spec
 * entry-point minimums, e.g. RSDP v2.0+ = 36 B); the validator checks
 * NORMAL containment of this size, not a flat 4 KB. Unknown GUIDs use
 * SL_CFGTBL_UNKNOWN_BOUND.
 */
struct sl_cfgtbl_size_entry {
	efi_guid_t	guid;
	u32		min_size;
};

static const struct sl_cfgtbl_size_entry sl_cfgtbl_sizes[] __initconst = {
	{ ACPI_20_TABLE_GUID,			36 },	/* RSDP v2.0+ */
	{ SMBIOS3_TABLE_GUID,			24 },	/* SMBIOS3 entry point */
	{ EFI_RT_PROPERTIES_TABLE_GUID,		8  },	/* version + flags */
	{ LINUX_EFI_MEMRESERVE_TABLE_GUID,	32 },	/* header struct */
	{ LINUX_EFI_RANDOM_SEED_TABLE_GUID,	32 },	/* header struct */
};

#define SL_CFGTBL_UNKNOWN_BOUND		EFI_PAGE_SIZE

static u32 __init sl_cfgtbl_min_size(const efi_guid_t *guid)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(sl_cfgtbl_sizes); i++) {
		if (efi_guidcmp(*guid, sl_cfgtbl_sizes[i].guid) == 0)
			return sl_cfgtbl_sizes[i].min_size;
	}
	return SL_CFGTBL_UNKNOWN_BOUND;
}

/* Validate System Table + ConfigurationTable pointers against D-CRTM
 * map. Runs pre-efi_init, panics on bad input.
 */
static void __init slaunch_validate_raw_systab(u64 systab_pa)
{
	efi_system_table_t *systab;
	efi_config_table_t *cfgtbl;
	unsigned long tables_pa;
	unsigned long nr_tables;
	size_t tbl_size;
	unsigned long j;

	if (!dcrtm_range_in_normal(systab_pa, sizeof(efi_system_table_t)))
		panic("slaunch: EFI System Table PA 0x%llx NOT in NORMAL region\n",
		      systab_pa);

	systab = early_memremap_ro(systab_pa, sizeof(efi_system_table_t));
	if (!systab)
		panic("slaunch: failed to map EFI System Table at 0x%llx\n",
		      systab_pa);

	nr_tables = systab->nr_tables;
	tables_pa = (unsigned long)systab->tables;
	early_memunmap(systab, sizeof(efi_system_table_t));

	if (nr_tables == 0 || !tables_pa) {
		pr_info("slaunch: EFI System Table has no ConfigurationTable entries\n");
		return;
	}
	/*
	 * Reject nr_tables that overflow when multiplied by the per-entry
	 * size; NORMAL containment then caps any structurally too-large value.
	 */
	if (check_mul_overflow(nr_tables,
			       (unsigned long)sizeof(efi_config_table_t),
			       &tbl_size))
		panic("slaunch: EFI System Table nr_tables=%lu overflows tbl_size\n",
		      nr_tables);

	if (!dcrtm_range_in_normal(tables_pa, tbl_size))
		panic("slaunch: EFI ConfigurationTable array at 0x%lx NOT in NORMAL region\n",
		      tables_pa);

	cfgtbl = early_memremap_ro(tables_pa, tbl_size);
	if (!cfgtbl)
		panic("slaunch: failed to map ConfigurationTable at 0x%lx\n",
		      tables_pa);

	for (j = 0; j < nr_tables; j++) {
		unsigned long tbl_ptr = (unsigned long)cfgtbl[j].table;
		u32 size;

		if (!tbl_ptr)
			continue;
		size = sl_cfgtbl_min_size(&cfgtbl[j].guid);
		if (!dcrtm_range_in_normal(tbl_ptr, size))
			panic("slaunch: EFI ConfigurationTable[%lu] 0x%lx [size %u] NOT in NORMAL region\n",
			      j, tbl_ptr, size);
	}
	early_memunmap(cfgtbl, tbl_size);
	pr_info("slaunch: early EFI System Table validation PASSED (%lu entries)\n",
		nr_tables);
}

/*
 * Validate the raw EFI memory map at /chosen/linux,uefi-mmap-start.
 * Walks descriptors at desc-size stride (NOT sizeof(efi_memory_desc_t),
 * which can differ for forward compatibility), pre-efi_init.
 */
static void __init slaunch_validate_raw_mmap(const struct sl_efi_info *info)
{
	void *mmap;
	u64 offset;
	u32 ndesc, nchecked = 0;

	/* Validate desc-size / desc-ver / mmap-size sanity. */
	if (info->desc_ver != 1)
		panic("slaunch: linux,uefi-mmap-desc-ver=%u (expected 1)\n",
		      info->desc_ver);
	if (info->desc_size < sizeof(efi_memory_desc_t) || info->desc_size > 128)
		panic("slaunch: linux,uefi-mmap-desc-size=%u out of sane range\n",
		      info->desc_size);
	if (info->mmap_size == 0 ||
	    info->mmap_size % info->desc_size != 0)
		panic("slaunch: linux,uefi-mmap-size=%llu not a multiple of desc-size=%u\n",
		      info->mmap_size, info->desc_size);

	/*
	 * mmap_pa + mmap_size must not wrap u64 and must lie in a NORMAL
	 * region; containment caps mmap_size, rejecting over-large values.
	 */
	{
		u64 mmap_end;

		if (check_add_overflow(info->mmap_pa, info->mmap_size, &mmap_end))
			panic("slaunch: linux,uefi-mmap [0x%llx + %llu] wraps u64\n",
			      info->mmap_pa, info->mmap_size);
	}

	/* The full mmap buffer must be in NORMAL memory. */
	if (!dcrtm_range_in_normal(info->mmap_pa, info->mmap_size))
		panic("slaunch: linux,uefi-mmap [0x%llx+0x%llx] NOT entirely in NORMAL\n",
		      info->mmap_pa, info->mmap_size);

	mmap = early_memremap_ro(info->mmap_pa, info->mmap_size);
	if (!mmap)
		panic("slaunch: failed to map raw EFI mmap at 0x%llx (size %llu)\n",
		      info->mmap_pa, info->mmap_size);

	ndesc = (u32)(info->mmap_size / info->desc_size);
	for (offset = 0; offset < info->mmap_size; offset += info->desc_size) {
		efi_memory_desc_t *md = (efi_memory_desc_t *)((u8 *)mmap + offset);
		u64 phys = md->phys_addr;
		u64 region_size, phys_end;
		int otype;

		/* Skip MMIO and EfiReservedMemoryType: secure carveouts are
		 * reserved in the UEFI map but excluded from the NS-DRAM D-CRTM
		 * map and never ingested as usable RAM, so need not be NORMAL. */
		if (md->type == EFI_MEMORY_MAPPED_IO ||
		    md->type == EFI_MEMORY_MAPPED_IO_PORT_SPACE ||
		    md->type == EFI_RESERVED_TYPE)
			continue;

		/* num_pages * page_size overflow guard. */
		if (check_mul_overflow(md->num_pages, (u64)EFI_PAGE_SIZE,
				       &region_size))
			panic("slaunch: raw EFI mmap[%llu]: type=%u num_pages=%llu overflows u64\n",
			      offset / info->desc_size, md->type, md->num_pages);
		/* phys_addr + region_size address-wrap guard. */
		if (region_size &&
		    check_add_overflow(phys, region_size, &phys_end))
			panic("slaunch: raw EFI mmap[%llu]: [0x%012llx + 0x%llx] type=%u wraps u64\n",
			      offset / info->desc_size, phys, region_size,
			      md->type);

		if (!dcrtm_range_in_normal(phys, region_size))
			panic("slaunch: raw EFI mmap[%llu]: region [0x%012llx-0x%012llx] type=%u NOT in NORMAL\n",
			      offset / info->desc_size, phys,
			      phys + region_size, md->type);

		otype = dcrtm_range_overlaps_non_normal(phys, region_size);
		if (otype >= 0)
			panic("slaunch: raw EFI mmap[%llu]: region [0x%012llx-0x%012llx] type=%u OVERLAPS %s\n",
			      offset / info->desc_size, phys,
			      phys + region_size, md->type,
			      dcrtm_type_name(otype));
		nchecked++;
	}
	early_memunmap(mmap, info->mmap_size);
	pr_info("slaunch: early raw EFI mmap validation PASSED (%u of %u descriptors checked)\n",
		nchecked, ndesc);
}

static void __init slaunch_validate_efi_early(const struct sl_efi_info *info)
{
	if (!info->present) {
		pr_info("slaunch: /chosen does not have all linux,uefi-* properties — skipping early EFI validation\n");
		return;
	}
	slaunch_validate_raw_systab(info->systab_pa);
	slaunch_validate_raw_mmap(info);
}

/*
 * Process DRTM state early in setup_arch() (address map already parsed
 * by slaunch_early_init): reserve DLME data in memblock, CLOSE_LOCALITY,
 * disable EFI runtime services, and validate the DTB /chosen EFI pointers.
 */
void __init slaunch_setup(void)
{
	struct dlme_data_header *hdr;
	phys_addr_t dlme_data_pa;

	if (!sl_dlme_region_pa)
		return;

	pr_info("slaunch: DRTM Secure Launch detected\n");

	/* Map DLME data header for reservation */
	dlme_data_pa = sl_dlme_region_pa + sl_dlme_data_offset;
	hdr = early_memremap(dlme_data_pa, sizeof(*hdr));
	if (!hdr) {
		pr_err("slaunch: failed to map DLME data header at 0x%llx\n",
		       (u64)dlme_data_pa);
		return;
	}

	pr_info("slaunch: DLME data version: %u\n",
		le16_to_cpu(hdr->version));
	pr_info("slaunch: DLME data size: %llu\n",
		le64_to_cpu(hdr->dlme_data_size));
	pr_info("slaunch: Event log size: %llu\n",
		le64_to_cpu(hdr->drtm_event_log_size));

	/* Enforce full-lockdown assumption per DEN0113 v1.2 §4.6.2.
	 * Called from slaunch_setup (not slaunch_early_init) so panic
	 * prints — earlycon is registered by this point.
	 */
	slaunch_assert_full_lockdown(dlme_data_pa,
				     le16_to_cpu(hdr->this_hdr_size),
				     le64_to_cpu(hdr->protected_regions_size));

	/* Reserve DLME data region in memblock so kernel won't reuse it.
	 * NOTE: efi_init() runs after us and calls memblock_remove(0,
	 * PHYS_ADDR_MAX) which wipes this reservation. slaunch_validate_efi
	 * re-reserves using the saved values below.
	 */
	sl_dlme_data_pa = dlme_data_pa;
	sl_dlme_data_size = le64_to_cpu(hdr->dlme_data_size);
	memblock_reserve(sl_dlme_data_pa, sl_dlme_data_size);

	early_memunmap(hdr, sizeof(*hdr));

	slaunch_tpm_setup();

	/*
	 * Unconditionally disable EFI runtime services: their pointers come
	 * from untrusted pre-DRTM firmware. Defense-in-depth backstop to the
	 * stub's efi=noruntime gate. Clearing EFI_RUNTIME_SERVICES and
	 * runtime_supported_mask makes all runtime dispatch see "unsupported".
	 */
	clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
	efi.runtime_supported_mask = 0;
	pr_info("slaunch: EFI runtime services unconditionally disabled\n");

	/*
	 * Validate all untrusted EFI inputs before efi_init() consumes them:
	 * read /chosen, optionally inject a fault, then run the validators.
	 */
	{
		struct sl_efi_info efi_info;

		slaunch_read_chosen_efi(&efi_info);
		slaunch_inject_fault(&efi_info);
		slaunch_validate_efi_early(&efi_info);
	}
}

/* Placeholder; populated by a subsequent patch. */
void __init slaunch_measure_post_efi(void) { }

/* Placeholder; populated by a subsequent patch. */
void slaunch_exit(void) { }
