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
#include <linux/security.h>
#include <crypto/sha2.h>

#include <asm/drtm.h>
#include <asm/memory.h>
#include <asm/setup.h>

/*
 * Hash algorithm dispatch. The DLME must match the D-CRTM firmware hash
 * algo (DRTM_FEATURES feature 0x1) or the event-log chain cannot replay.
 * Supports SHA-256 (0x000B) and SHA-384 (0x000C) via the kernel library
 * API, whose arch SIMD paths are static-key gated until subsys_initcall.
 */
#define SL_TPM_ALG_SHA256		0x000B
#define SL_TPM_ALG_SHA384		0x000C

enum sl_hash_algo {
	SL_HASH_SHA256 = 0,
	SL_HASH_SHA384 = 1,
};

#define SL_HASH_MAX_DIGEST_SIZE		SHA512_DIGEST_SIZE	/* 64 */

struct sl_hash_alg_info {
	const char	*name;
	u16		tpm_alg_id;
	u8		digest_size;
};

static const struct sl_hash_alg_info sl_hash_algs[] = {
	[SL_HASH_SHA256] = {
		.name		= "SHA-256",
		.tpm_alg_id	= SL_TPM_ALG_SHA256,
		.digest_size	= SHA256_DIGEST_SIZE,
	},
	[SL_HASH_SHA384] = {
		.name		= "SHA-384",
		.tpm_alg_id	= SL_TPM_ALG_SHA384,
		.digest_size	= SHA384_DIGEST_SIZE,
	},
};

/* Active algo for the lifetime of this boot. Default SHA-256 until
 * slaunch_verify_hash_algo() updates it from DRTM_FEATURES.
 */
static enum sl_hash_algo sl_active_algo __initdata = SL_HASH_SHA256;

static inline const struct sl_hash_alg_info *sl_active_alg_info(void)
{
	return &sl_hash_algs[sl_active_algo];
}

/*
 * Hash one contiguous in-RAM buffer with the active algorithm; out must
 * hold sl_active_alg_info()->digest_size bytes. Uses sha256()/sha384()
 * (safe in setup_arch(); see the dispatch comment above).
 */
static void __init sl_hash_data(const void *data, size_t size, u8 *out)
{
	if (sl_active_algo == SL_HASH_SHA384)
		sha384(data, size, out);
	else
		sha256(data, size, out);
}

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
 * Validated UEFI SRTM TPM event log location, captured in
 * slaunch_validate_raw_systab() so the main-vs-final-events "last writer
 * wins" selection can prefer the primary log. The SRTM log is a pre-DRTM
 * (untrusted) artifact, so it is validated for in-bounds extent only, not
 * measured. Zero when firmware published no GUID (e.g. FVP without Tcg2Dxe).
 */
static phys_addr_t sl_srtm_log_pa;
static size_t      sl_srtm_log_size;	/* includes sizeof(linux_efi_tpm_eventlog) */

/*
 * Raw EFI memory map extent saved by slaunch_validate_raw_mmap() and
 * read by slaunch_validate_srtm_log() so the SRTM log extent can be
 * rejected if it overlaps the raw mmap buffer.
 *
 * sl_efi_mmap_desc_size and sl_efi_nr_tables are additionally consumed
 * by slaunch_extend_drtm_event_log() to compute a runtime upper bound
 * for the kernel-side event-log buffer allocation. The bound scales with
 * the firmware-reported UEFI input counts (one event per memory-map
 * descriptor / ConfigurationTable entry in the upper bound), plus a small
 * fixed-event budget for ACPI/CMDLINE/initrd/SRTM.
 *
 * These values come from pre-DRTM untrusted UEFI inputs; an attacker
 * inflating them can only waste memory, not escalate (the kernel image
 * hash covers these statics' writes via the past-_edata placement of
 * EFI-stub writable globals).
 */
static phys_addr_t sl_efi_mmap_pa;
static u64         sl_efi_mmap_size;
static u32         sl_efi_mmap_desc_size;
static unsigned long sl_efi_nr_tables;

/*
 * Kernel-side DRTM event log buffer (memblock_alloc'd in
 * slaunch_measure_post_efi(), not __initdata so securityfs can read it
 * at runtime). DCE bytes are copied in first, then DLME TCG_PCR_EVENT2
 * records are appended here; the DCE buffer is never written back.
 */
static u8 *sl_kernel_evlog;
static size_t sl_kernel_evlog_size;
static size_t sl_kernel_evlog_capacity;

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

/* True when @pa is kernel RAM or in the measured DLME extent; such a PA
 * must never be device-mapped from the untrusted EFI map. False when DRTM
 * is inactive; runtime-callable since the DLME handoff values persist. */
bool slaunch_phys_is_protected_ram(phys_addr_t pa)
{
	if (!sl_dlme_region_pa)
		return false;
	if (memblock_is_map_memory(pa))
		return true;
	return sl_dlme_data_size &&
	       pa >= sl_dlme_region_pa &&
	       pa < sl_dlme_data_pa + sl_dlme_data_size;
}

/* True if [pa, pa+size) touches kernel RAM or the measured DLME extent.
 * A range that wraps is refused. Used by the ACPI ioremap path, where a
 * span may start outside protected memory and extend into it. */
bool slaunch_phys_range_overlaps_protected_ram(phys_addr_t pa, size_t size)
{
	phys_addr_t p, end;

	if (!sl_dlme_region_pa)
		return false;
	if (check_add_overflow(pa, (phys_addr_t)size, &end))
		return true;

	if (sl_dlme_data_size &&
	    pa < sl_dlme_data_pa + sl_dlme_data_size &&
	    sl_dlme_region_pa < end)
		return true;

	for (p = ALIGN_DOWN(pa, PAGE_SIZE); p < end; p += PAGE_SIZE)
		if (memblock_is_map_memory(p))
			return true;
	return false;
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

/* Forward decl — definition lives near slaunch_measure_initrd. */
static bool __init slaunch_ranges_overlap(u64 a_start, u64 a_size,
					  u64 b_start, u64 b_size);

/*
 * Validate a UEFI SRTM TPM event log Configuration Table entry against
 * the D-CRTM address map: cover the full header+body extent and reject
 * overlap with DLME/DTB/mmap so firmware cannot alias an input. The log
 * is a pre-DRTM artifact, so this validates its extent only (it is not
 * measured); on success captures sl_srtm_log_pa/size.
 */
static void __init slaunch_validate_srtm_log(u64 log_pa,
					     const efi_guid_t *guid)
{
	efi_guid_t main_guid  = LINUX_EFI_TPM_EVENT_LOG_GUID;
	efi_guid_t final_guid = EFI_TCG2_FINAL_EVENTS_TABLE_GUID;
	size_t hdr_size;
	u64 body_size;
	u64 total_size;
	u64 dlme_size;
	u64 fdt_size = 0;
	phys_addr_t dtb_pa = __fdt_pointer;
	bool is_main = (efi_guidcmp(*guid, main_guid) == 0);
	bool is_final = (efi_guidcmp(*guid, final_guid) == 0);

	if (!is_main && !is_final)
		return;

	if (!log_pa)
		panic("slaunch: SRTM log GUID entry has NULL vendor_table\n");

	hdr_size = is_main ? sizeof(struct linux_efi_tpm_eventlog)
			   : sizeof(struct efi_tcg2_final_events_table);

	/* Header extent must be in NORMAL before we can read the size
	 * field. dcrtm_range_in_normal rejects size==0 and u64 wrap. */
	if (!dcrtm_range_in_normal(log_pa, hdr_size))
		panic("slaunch: SRTM log PA 0x%llx (header %zu B) NOT in NORMAL region\n",
		      log_pa, hdr_size);

	/* Header extent must not alias the DLME region, DTB, or raw EFI
	 * mmap buffer (an attacker could otherwise coerce the validator
	 * into mis-interpreting attestation-critical bytes). */
	dlme_size = (sl_dlme_data_pa + sl_dlme_data_size) - sl_dlme_region_pa;
	if (slaunch_ranges_overlap(log_pa, hdr_size,
				   sl_dlme_region_pa, dlme_size))
		panic("slaunch: SRTM log header [0x%llx+%zu] overlaps DLME region [0x%llx+%llu]\n",
		      log_pa, hdr_size, (u64)sl_dlme_region_pa, dlme_size);

	if (dtb_pa) {
		/* Read fdt_totalsize from the (already-validated) DTB. */
		u32 *p = early_memremap(dtb_pa, sizeof(u32) * 2);

		if (p) {
			fdt_size = be32_to_cpu(p[1]);
			early_memunmap(p, sizeof(u32) * 2);
		}
	}
	if (fdt_size && slaunch_ranges_overlap(log_pa, hdr_size,
					       dtb_pa, fdt_size))
		panic("slaunch: SRTM log header [0x%llx+%zu] overlaps DTB [0x%llx+%llu]\n",
		      log_pa, hdr_size, (u64)dtb_pa, fdt_size);

	if (sl_efi_mmap_size &&
	    slaunch_ranges_overlap(log_pa, hdr_size,
				   sl_efi_mmap_pa, sl_efi_mmap_size))
		panic("slaunch: SRTM log header [0x%llx+%zu] overlaps raw EFI mmap [0x%llx+%llu]\n",
		      log_pa, hdr_size, (u64)sl_efi_mmap_pa,
		      sl_efi_mmap_size);

	/* Read the firmware-published body size from the header. */
	if (is_main) {
		struct linux_efi_tpm_eventlog *log_tbl;

		log_tbl = early_memremap(log_pa, hdr_size);
		if (!log_tbl)
			panic("slaunch: SRTM log header remap failed at 0x%llx\n",
			      log_pa);
		body_size = log_tbl->size;
		early_memunmap(log_tbl, hdr_size);
	} else {
		struct efi_tcg2_final_events_table *final_tbl;

		final_tbl = early_memremap(log_pa, hdr_size);
		if (!final_tbl)
			panic("slaunch: SRTM final-events header remap failed at 0x%llx\n",
			      log_pa);
		/*
		 * Final-events per-event encoding needs the primary log's
		 * algorithm-set descriptor we may not have seen, so treat
		 * events[] as opaque. version must be 1 per TCG2 ACPI spec;
		 * reject otherwise before nr_events.
		 */
		if (final_tbl->version != 1)
			panic("slaunch: SRTM final-events table version %llu != 1\n",
			      final_tbl->version);
		body_size = 0;
		(void)final_tbl->nr_events;
		early_memunmap(final_tbl, hdr_size);
	}

	if (check_add_overflow(log_pa, (u64)hdr_size + body_size,
			       &total_size))
		panic("slaunch: SRTM log PA + size wraps u64 (pa 0x%llx + %zu + %llu)\n",
		      log_pa, hdr_size, body_size);

	total_size = (u64)hdr_size + body_size;

	if (!dcrtm_range_in_normal(log_pa, total_size))
		panic("slaunch: SRTM log [0x%llx+%llu] NOT in NORMAL region (full extent)\n",
		      log_pa, total_size);

	if (slaunch_ranges_overlap(log_pa, total_size,
				   sl_dlme_region_pa, dlme_size))
		panic("slaunch: SRTM log [0x%llx+%llu] overlaps DLME region [0x%llx+%llu]\n",
		      log_pa, total_size, (u64)sl_dlme_region_pa, dlme_size);
	if (fdt_size &&
	    slaunch_ranges_overlap(log_pa, total_size, dtb_pa, fdt_size))
		panic("slaunch: SRTM log [0x%llx+%llu] overlaps DTB [0x%llx+%llu]\n",
		      log_pa, total_size, (u64)dtb_pa, fdt_size);
	if (sl_efi_mmap_size &&
	    slaunch_ranges_overlap(log_pa, total_size,
				   sl_efi_mmap_pa, sl_efi_mmap_size))
		panic("slaunch: SRTM log [0x%llx+%llu] overlaps raw EFI mmap [0x%llx+%llu]\n",
		      log_pa, total_size, (u64)sl_efi_mmap_pa,
		      sl_efi_mmap_size);

	/* Last writer wins when both GUIDs are present — both are
	 * structurally validated above; the main TPM event log is the
	 * preferred measurement target. */
	if (is_main || !sl_srtm_log_pa) {
		sl_srtm_log_pa   = log_pa;
		sl_srtm_log_size = (size_t)total_size;
	}
	pr_info("slaunch: SRTM TPM event log validated: PA 0x%llx, %llu B (%s)\n",
		log_pa, total_size,
		is_main ? "LINUX_EFI_TPM_EVENT_LOG" : "EFI_TCG2_FINAL_EVENTS");
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
		/* If the entry advertises an SRTM TPM event log (header
		 * + variable-length body), extend the structural check to
		 * cover the full body extent (validate-only; the log is a
		 * pre-DRTM artifact and is not measured). */
		slaunch_validate_srtm_log((u64)tbl_ptr, &cfgtbl[j].guid);
	}
	early_memunmap(cfgtbl, tbl_size);
	/*
	 * Save validated nr_tables so slaunch_extend_drtm_event_log() can
	 * scale the kernel event-log buffer allocation by the count of
	 * ConfigurationTable entries (upper bound on per-entry events).
	 */
	sl_efi_nr_tables = nr_tables;
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

	/* Defense-in-depth: warn on any overlapping descriptor pair.
	 * First-match attribute lookups would let a planted MMIO descriptor
	 * order-pick the type for a measured PA; the acpi_os_ioremap consumer
	 * guard blocks the RAM/DLME case regardless, so this is non-fatal. */
	for (offset = 0; offset < info->mmap_size; offset += info->desc_size) {
		efi_memory_desc_t *a = (efi_memory_desc_t *)((u8 *)mmap + offset);
		u64 asz, off2;

		if (check_mul_overflow(a->num_pages, (u64)EFI_PAGE_SIZE, &asz))
			continue;
		for (off2 = offset + info->desc_size; off2 < info->mmap_size;
		     off2 += info->desc_size) {
			efi_memory_desc_t *b =
				(efi_memory_desc_t *)((u8 *)mmap + off2);
			u64 bsz;

			if (check_mul_overflow(b->num_pages,
					       (u64)EFI_PAGE_SIZE, &bsz))
				continue;
			if (efi_regions_overlap(a->phys_addr, asz,
						b->phys_addr, bsz))
				pr_warn("slaunch: raw EFI mmap descriptors [%llu]/[%llu] OVERLAP @ 0x%012llx (types %u/%u)\n",
					offset / info->desc_size,
					off2 / info->desc_size,
					a->phys_addr, a->type, b->type);
		}
	}

	early_memunmap(mmap, info->mmap_size);
	pr_info("slaunch: early raw EFI mmap validation PASSED (%u of %u descriptors checked)\n",
		nchecked, ndesc);

	/* Remember raw mmap extent for later overlap checks (e.g. the SRTM
	 * TPM event log validator must reject a published log PA that aliases
	 * the firmware-provided memory map buffer). desc_size is also saved
	 * so slaunch_extend_drtm_event_log() can compute the descriptor count
	 * as part of the kernel event-log buffer sizing formula. */
	sl_efi_mmap_pa        = info->mmap_pa;
	sl_efi_mmap_size      = info->mmap_size;
	sl_efi_mmap_desc_size = info->desc_size;
}

static void __init slaunch_validate_efi_early(const struct sl_efi_info *info)
{
	if (!info->present) {
		pr_info("slaunch: /chosen does not have all linux,uefi-* properties — skipping early EFI validation\n");
		return;
	}
	/*
	 * Stage the raw EFI mmap extent before the systab validator so
	 * slaunch_validate_srtm_log() can reject an SRTM log PA aliasing it;
	 * validate_raw_mmap() re-publishes these after its own checks.
	 * desc_size is pre-staged for the event-log buffer sizing formula.
	 */
	sl_efi_mmap_pa        = info->mmap_pa;
	sl_efi_mmap_size      = info->mmap_size;
	sl_efi_mmap_desc_size = info->desc_size;
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

	/* Stash for slaunch_reserve_dlme_data() to reserve post-efi_init. */
	sl_dlme_data_pa = dlme_data_pa;
	sl_dlme_data_size = le64_to_cpu(hdr->dlme_data_size);

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

/* Reserve DLME data after efi_init's memblock_remove(0, PHYS_ADDR_MAX). */
void __init slaunch_reserve_dlme_data(void)
{
	if (!sl_dlme_data_pa || !sl_dlme_data_size)
		return;
	memblock_reserve(sl_dlme_data_pa, sl_dlme_data_size);
}

/*
 * Record an in-memory SHA-256 measurement into slaunch_measurements[]
 * for later replay into the DRTM event log on PCR 18. The table is
 * memblock_alloc-backed and grows geometrically, so platforms with many
 * ACPI tables are not capped (seeded by slaunch_measurements_init()).
 */
/*
 * hash is sized for the largest digest (SHA-512, 64 B) so one struct
 * serves SHA-256 and SHA-384; digest_size marks the live bytes and
 * tpm_alg_id records the algorithm at measurement time.
 */
struct slaunch_measurement {
	char	desc[16];
	u8	hash[SL_HASH_MAX_DIGEST_SIZE];
	u8	digest_size;
	u16	tpm_alg_id;
};

static struct slaunch_measurement *slaunch_measurements __initdata;
static unsigned int slaunch_measurement_count __initdata;
static unsigned int slaunch_measurement_capacity __initdata;

static void __init slaunch_measurements_init(void)
{
	size_t bytes;

	if (slaunch_measurements)
		return;

	slaunch_measurement_capacity = 256;
	bytes = (size_t)slaunch_measurement_capacity *
		sizeof(*slaunch_measurements);
	slaunch_measurements = memblock_alloc(bytes, SMP_CACHE_BYTES);
	if (!slaunch_measurements)
		panic("slaunch: memblock_alloc for measurement table failed (%zu bytes)\n",
		      bytes);
}

static void __init slaunch_measurements_reserve(unsigned int needed)
{
	struct slaunch_measurement *new_arr;
	unsigned int new_cap;
	size_t new_bytes, old_bytes;

	if (needed <= slaunch_measurement_capacity)
		return;

	new_cap = slaunch_measurement_capacity ?
		  slaunch_measurement_capacity : 1;
	while (new_cap < needed)
		new_cap *= 2;

	new_bytes = (size_t)new_cap * sizeof(*slaunch_measurements);
	old_bytes = (size_t)slaunch_measurement_capacity *
		    sizeof(*slaunch_measurements);

	new_arr = memblock_alloc(new_bytes, SMP_CACHE_BYTES);
	if (!new_arr)
		panic("slaunch: measurement table grow failed at %u entries\n",
		      slaunch_measurement_count);

	if (slaunch_measurements && old_bytes) {
		memcpy(new_arr, slaunch_measurements,
		       slaunch_measurement_count *
		       sizeof(*slaunch_measurements));
		memblock_free(slaunch_measurements, old_bytes);
	}

	slaunch_measurements = new_arr;
	slaunch_measurement_capacity = new_cap;
}

static void __init slaunch_measure(const char *desc, const void *data,
				   size_t size)
{
	const struct sl_hash_alg_info *ainfo = sl_active_alg_info();
	u8 hash[SL_HASH_MAX_DIGEST_SIZE];
	struct slaunch_measurement *m;

	/*
	 * Hash with the active algorithm via sl_hash_data() (sha256()/
	 * sha384()), safe in setup_arch() since the arch SIMD fast-paths
	 * are static-key gated until subsys_initcall.
	 */
	sl_hash_data(data, size, hash);

	pr_info("slaunch: measured %s (%zu bytes) %s: %*phN\n",
		desc, size, ainfo->name,
		(int)ainfo->digest_size, hash);

	/* Future revision: also extend this hash into a hardware measurement
	 * engine (TPM HASH_START or platform-specific equivalent) so the
	 * measurement is anchored beyond the in-memory event log.
	 */

	slaunch_measurements_reserve(slaunch_measurement_count + 1);

	m = &slaunch_measurements[slaunch_measurement_count++];
	strscpy(m->desc, desc, sizeof(m->desc));
	memcpy(m->hash, hash, ainfo->digest_size);
	if (ainfo->digest_size < SL_HASH_MAX_DIGEST_SIZE)
		memset(m->hash + ainfo->digest_size, 0,
		       SL_HASH_MAX_DIGEST_SIZE - ainfo->digest_size);
	m->digest_size = ainfo->digest_size;
	m->tpm_alg_id = ainfo->tpm_alg_id;
}

/*
 * Measure ACPI tables (RSDP, XSDT, and each XSDT-referenced table) while
 * DMA protection is still active (before the slaunch_unprotect_memory
 * late_initcall), so no device can tamper with them. The hashes are
 * attestation evidence a remote verifier compares to known-good values.
 */
/*
 * RSDP layout (ACPI 2.0+): we only need xsdt_physical_address at offset 24
 * and length at offset 20. Avoid depending on <acpi/acpi.h> for the struct.
 */
/* Minimal ACPI table header — avoid full <acpi/acpi.h> dependency.
 * Full header is 36 bytes; XSDT entries follow after this.
 */
struct slaunch_acpi_hdr {
	char signature[4];
	u32 length;
	u8 revision;
	u8 checksum;
	char oem_id[6];
	char oem_table_id[8];
	u32 oem_revision;
	u32 creator_id;
	u32 creator_revision;
} __packed;

#define RSDP_SIZE_V1	20
#define RSDP_OFF_LEN	20	/* u32 length (ACPI 2.0+) */
#define RSDP_OFF_XSDT	24	/* u64 xsdt_physical_address */
#define RSDP_MIN_MAP	36	/* enough to read through xsdt_physical_address */

/* FADT field offsets (ACPI 6.x §5.2.9) — used to follow indirection
 * to DSDT and FACS. Local copies to avoid pulling in <acpi/actbl.h>.
 */
#define FADT_FIRMWARE_CTRL_OFF		36	/* u32 */
#define FADT_DSDT_OFF			40	/* u32 */
#define FADT_X_FIRMWARE_CTRL_OFF	132	/* u64, ACPI 2.0+ */
#define FADT_X_DSDT_OFF			140	/* u64, ACPI 2.0+ */

/* Validate PA + length against D-CRTM map, then measure. Every
 * failure is fatal — silent skip breaks attestation soundness.
 */
static void __init slaunch_measure_one_acpi(phys_addr_t pa, const char *desc)
{
	struct slaunch_acpi_hdr *tbl;
	u32 tbl_len;

	if (!pa)
		panic("slaunch: %s PA is 0 — cannot measure\n", desc);
	if (!dcrtm_range_in_normal(pa, sizeof(*tbl)))
		panic("slaunch: %s PA 0x%llx (header) NOT in NORMAL region\n",
		      desc, (u64)pa);

	tbl = early_memremap(pa, sizeof(*tbl));
	if (!tbl)
		panic("slaunch: %s header remap failed at 0x%llx\n",
		      desc, (u64)pa);
	tbl_len = tbl->length;
	early_memunmap(tbl, sizeof(*tbl));

	if (tbl_len < sizeof(*tbl))
		panic("slaunch: %s length %u < header size %zu\n",
		      desc, tbl_len, sizeof(*tbl));
	if (!dcrtm_range_in_normal(pa, tbl_len))
		panic("slaunch: %s [0x%llx+%u] NOT in NORMAL region\n",
		      desc, (u64)pa, tbl_len);

	tbl = early_memremap(pa, tbl_len);
	if (!tbl)
		panic("slaunch: %s full remap failed at 0x%llx (size %u)\n",
		      desc, (u64)pa, tbl_len);
	slaunch_measure(desc, tbl, tbl_len);
	early_memunmap(tbl, tbl_len);
}

/*
 * Query the D-CRTM TPM hash algorithm (DRTM_FEATURES feature 0x1,
 * DEN0113 v1.2 §3.3), setting sl_active_algo so later measurements use
 * the matching path; refuse to proceed on mismatch. Supports 0xB SHA-256
 * / 0xC SHA-384. FAULT_INJECT adds sha384_force / sha_algo_bad tokens.
 */
#define SL_DRTM_FW_HASH_MASK		0xFFFFULL

#ifdef CONFIG_ARM64_SECURE_LAUNCH_FAULT_INJECT
static bool __init sl_cmdline_has(const char *tok);
#endif

static void __init slaunch_verify_hash_algo(void)
{
	struct arm_smccc_res res;
	u64 features;
	u32 algo;
	bool fw_features_supported = true;

	/*
	 * Feature 0x1 = TPM features (bit 63 set per spec). TF-A returns
	 * a0 = 1 or DRTM_NOT_SUPPORTED, a1 = the tpm_features bitfield.
	 */
	arm_smccc_smc(DRTM_SMC_FEATURES, (1ULL << 63) | 0x1,
		      0, 0, 0, 0, 0, 0, &res);
	if ((s64)res.a0 == DRTM_NOT_SUPPORTED) {
		pr_warn("slaunch: DRTM_FEATURES(TPM) not supported; assuming SHA-256\n");
		fw_features_supported = false;
		algo = SL_TPM_ALG_SHA256;
	} else {
		features = res.a1;
		algo = features & SL_DRTM_FW_HASH_MASK;
	}

	pr_info("slaunch: DCE firmware hash algorithm: 0x%x\n", algo);

#ifdef CONFIG_ARM64_SECURE_LAUNCH_FAULT_INJECT
	/*
	 * Fault-injection override (FAULT_INJECT only): coerce a SHA-256
	 * firmware (FVP) into the SHA-384 path to regression-test it without
	 * a separate TF-A build, plus a "bad algo" token to check the
	 * dispatch panics on an unsupported algorithm.
	 */
	if (sl_cmdline_has("slaunch_inject=sha384_force")) {
		pr_warn("slaunch: INJECT: overriding hash algo -> SHA-384\n");
		algo = SL_TPM_ALG_SHA384;
	} else if (sl_cmdline_has("slaunch_inject=sha_algo_bad")) {
		pr_warn("slaunch: INJECT: overriding hash algo -> 0xDEAD (unsupported)\n");
		algo = 0xDEAD;
	}
#endif

	switch (algo) {
	case SL_TPM_ALG_SHA256:
		sl_active_algo = SL_HASH_SHA256;
		break;
	case SL_TPM_ALG_SHA384:
		sl_active_algo = SL_HASH_SHA384;
		break;
	default:
		panic("slaunch: DCE reports hash algo 0x%x; kernel only implements SHA-256 (0xB) and SHA-384 (0xC). Add new algo to sl_hash_algs[] or use a supported DCE.\n",
		      algo);
	}

	pr_info("slaunch: DLME will use %s for the measurement chain%s\n",
		sl_active_alg_info()->name,
		fw_features_supported ? "" : " (DRTM_FEATURES unavailable)");
}

static void __init slaunch_measure_acpi(void)
{
	struct slaunch_acpi_hdr *xsdt;
	phys_addr_t rsdp_pa, xsdt_pa;
	phys_addr_t dsdt_pa = 0, facs_pa = 0;
	u32 rsdp_len, xsdt_len, num_entries, i;
	u64 *entry_ptrs;
	void *rsdp;

	/* Every failure below is fatal. The "kernel acts on unmeasured
	 * bytes" case breaks the attestation-based trust model.
	 */
	rsdp_pa = efi.acpi20;
	if (rsdp_pa == EFI_INVALID_TABLE_ADDR || !rsdp_pa)
		panic("slaunch: no ACPI RSDP in EFI System Table (DRTM requires ACPI)\n");

	if (!dcrtm_range_in_normal(rsdp_pa, RSDP_MIN_MAP))
		panic("slaunch: RSDP PA 0x%llx NOT in NORMAL region\n",
		      (u64)rsdp_pa);

	rsdp = early_memremap(rsdp_pa, RSDP_MIN_MAP);
	if (!rsdp)
		panic("slaunch: RSDP header remap failed at 0x%llx\n",
		      (u64)rsdp_pa);

	/* ACPI 2.0+ RSDP must be >= 36 bytes so xsdt_pa (offset 24-31) is measured. */
	rsdp_len = *(u32 *)((u8 *)rsdp + RSDP_OFF_LEN);
	if (rsdp_len < RSDP_MIN_MAP)
		panic("slaunch: RSDP length %u < %u\n",
		      rsdp_len, (u32)RSDP_MIN_MAP);
	xsdt_pa = *(u64 *)((u8 *)rsdp + RSDP_OFF_XSDT);
	early_memunmap(rsdp, RSDP_MIN_MAP);

	if (!dcrtm_range_in_normal(rsdp_pa, rsdp_len))
		panic("slaunch: RSDP [0x%llx+%u] NOT in NORMAL region\n",
		      (u64)rsdp_pa, rsdp_len);
	rsdp = early_memremap(rsdp_pa, rsdp_len);
	if (!rsdp)
		panic("slaunch: RSDP full remap failed at 0x%llx (size %u)\n",
		      (u64)rsdp_pa, rsdp_len);
	slaunch_measure("RSDP", rsdp, rsdp_len);
	early_memunmap(rsdp, rsdp_len);

	if (!dcrtm_range_in_normal(xsdt_pa, sizeof(*xsdt)))
		panic("slaunch: XSDT PA 0x%llx NOT in NORMAL region\n", xsdt_pa);
	xsdt = early_memremap(xsdt_pa, sizeof(*xsdt));
	if (!xsdt)
		panic("slaunch: XSDT header remap failed at 0x%llx\n", xsdt_pa);
	xsdt_len = xsdt->length;
	early_memunmap(xsdt, sizeof(*xsdt));

	if (xsdt_len < sizeof(*xsdt))
		panic("slaunch: XSDT length %u < header size %zu\n",
		      xsdt_len, sizeof(*xsdt));
	if (!dcrtm_range_in_normal(xsdt_pa, xsdt_len))
		panic("slaunch: XSDT [0x%llx+%u] NOT in NORMAL region\n",
		      xsdt_pa, xsdt_len);
	xsdt = early_memremap(xsdt_pa, xsdt_len);
	if (!xsdt)
		panic("slaunch: XSDT full remap failed at 0x%llx (size %u)\n",
		      xsdt_pa, xsdt_len);
	slaunch_measure("XSDT", xsdt, xsdt_len);

	/* Walk XSDT entries. Each is a 64-bit PA to a top-level ACPI table. */
	num_entries = (xsdt_len - sizeof(*xsdt)) / sizeof(u64);
	entry_ptrs = (u64 *)((u8 *)xsdt + sizeof(*xsdt));

	for (i = 0; i < num_entries; i++) {
		struct slaunch_acpi_hdr *tbl;
		u64 tbl_pa = entry_ptrs[i];
		u32 tbl_len;
		char desc[32];

		if (!dcrtm_range_in_normal(tbl_pa, sizeof(*tbl)))
			panic("slaunch: XSDT entry[%u] PA 0x%llx (hdr) NOT in NORMAL\n",
			      i, tbl_pa);
		tbl = early_memremap(tbl_pa, sizeof(*tbl));
		if (!tbl)
			panic("slaunch: XSDT entry[%u] header remap failed at 0x%llx\n",
			      i, tbl_pa);
		tbl_len = tbl->length;
		early_memunmap(tbl, sizeof(*tbl));

		if (tbl_len < sizeof(*tbl))
			panic("slaunch: XSDT entry[%u] length %u < header size %zu\n",
			      i, tbl_len, sizeof(*tbl));
		if (!dcrtm_range_in_normal(tbl_pa, tbl_len))
			panic("slaunch: XSDT entry[%u] [0x%llx+%u] NOT in NORMAL\n",
			      i, tbl_pa, tbl_len);
		tbl = early_memremap(tbl_pa, tbl_len);
		if (!tbl)
			panic("slaunch: XSDT entry[%u] full remap failed at 0x%llx (size %u)\n",
			      i, tbl_pa, tbl_len);

		snprintf(desc, sizeof(desc), "ACPI:%.4s", tbl->signature);
		slaunch_measure(desc, tbl, tbl_len);

		/* Capture FADT indirection while FADT is mapped. Prefer
		 * 64-bit X_* fields (ACPI 2.0+); fall back to 32-bit
		 * fields if FADT length is too short to carry them.
		 */
		if (!memcmp(tbl->signature, "FACP", 4)) {
			if (tbl_len >= FADT_X_DSDT_OFF + sizeof(u64))
				memcpy(&dsdt_pa,
				       (u8 *)tbl + FADT_X_DSDT_OFF,
				       sizeof(u64));
			if (!dsdt_pa &&
			    tbl_len >= FADT_DSDT_OFF + sizeof(u32)) {
				u32 d32;

				memcpy(&d32,
				       (u8 *)tbl + FADT_DSDT_OFF,
				       sizeof(u32));
				dsdt_pa = d32;
			}
			if (tbl_len >= FADT_X_FIRMWARE_CTRL_OFF + sizeof(u64))
				memcpy(&facs_pa,
				       (u8 *)tbl + FADT_X_FIRMWARE_CTRL_OFF,
				       sizeof(u64));
			if (!facs_pa &&
			    tbl_len >= FADT_FIRMWARE_CTRL_OFF + sizeof(u32)) {
				u32 f32;

				memcpy(&f32,
				       (u8 *)tbl + FADT_FIRMWARE_CTRL_OFF,
				       sizeof(u32));
				facs_pa = f32;
			}
		}
		early_memunmap(tbl, tbl_len);
	}

	early_memunmap(xsdt, xsdt_len);

	/*
	 * Follow FADT indirections (not in XSDT): DSDT carries the AML
	 * executed by ACPICA — mandatory; FACS is optional on HW-reduced
	 * ACPI. Other indirect tables (BERT/ERST/HEST/EINJ/PCCT) are data,
	 * not boot-TCB, so they are deliberately not followed.
	 */
	if (!dsdt_pa)
		panic("slaunch: FADT present but X_Dsdt/Dsdt both zero — DSDT cannot be measured\n");
	slaunch_measure_one_acpi(dsdt_pa, "DSDT");
	if (facs_pa)
		slaunch_measure_one_acpi(facs_pa, "FACS");
	else
		pr_info("slaunch: FACS absent (HW-reduced ACPI) — no measurement needed\n");
}

/* Half-open range overlap. Fails closed (returns true) on u64 wrap of
 * either range — refuse to consume rather than silently miscompute. */
static bool __init slaunch_ranges_overlap(u64 a_start, u64 a_size,
					  u64 b_start, u64 b_size)
{
	u64 a_end, b_end;

	if (check_add_overflow(a_start, a_size, &a_end))
		return true;
	if (check_add_overflow(b_start, b_size, &b_end))
		return true;
	return a_start < b_end && b_start < a_end;
}

#ifdef CONFIG_ARM64_SECURE_LAUNCH_FAULT_INJECT
static bool __init sl_cmdline_has(const char *tok);
static void __init slaunch_inject_initrd(u64 *start, u64 *size);
#endif

/*
 * Measure the bootloader-supplied initramfs. The buffer sits in
 * untrusted DRAM not covered by D-CRTM, so its extent is validated
 * before any read and failures are fatal. Absence is legitimate and
 * logged (no marker hash); the verifier infers coverage from the event.
 */
/* Returns validated (post-inject) start/size, or false if no initrd. */
static bool __init slaunch_validate_initrd_extents(u64 *out_start, u64 *out_size)
{
	u64 start = phys_initrd_start;
	u64 size = phys_initrd_size;
	u64 end, dlme_size;

	if (!start || !size)
		return false;

#ifdef CONFIG_ARM64_SECURE_LAUNCH_FAULT_INJECT
	slaunch_inject_initrd(&start, &size);
#endif

	if (!IS_ALIGNED(start, PAGE_SIZE))
		panic("slaunch: initrd start 0x%llx not page-aligned\n",
		      start);

	if (check_add_overflow(start, size, &end))
		panic("slaunch: initrd [0x%llx + %llu] wraps u64\n",
		      start, size);

	if (!dcrtm_range_in_normal(start, size))
		panic("slaunch: initrd [0x%llx+%llu] NOT in NORMAL region\n",
		      start, size);

	dlme_size = (sl_dlme_data_pa + sl_dlme_data_size) - sl_dlme_region_pa;
	if (slaunch_ranges_overlap(start, size,
				   sl_dlme_region_pa, dlme_size))
		panic("slaunch: initrd [0x%llx+%llu] overlaps DLME region [0x%llx+%llu]\n",
		      start, size, (u64)sl_dlme_region_pa, dlme_size);

	*out_start = start;
	*out_size = size;
	return true;
}

/* Called from slaunch_setup, before arm64_memblock_init consumes the extents. */
void __init slaunch_validate_initrd(void)
{
	u64 start, size;

	if (!sl_dlme_region_pa)
		return;
	if (!slaunch_validate_initrd_extents(&start, &size))
		pr_info("slaunch: no initrd present, skipping measurement\n");
}

static void __init slaunch_measure_initrd(void)
{
	const struct sl_hash_alg_info *ainfo = sl_active_alg_info();
	u64 start, size;
	u64 off = 0, remaining;
	struct sha256_ctx sctx256;
	struct sha384_ctx sctx384;
	u8 hash[SL_HASH_MAX_DIGEST_SIZE];
	struct slaunch_measurement *m;
	void *p;

	if (!slaunch_validate_initrd_extents(&start, &size))
		return;

	/*
	 * Chunked early_memremap + streaming hash with the active algorithm:
	 * map one page at a time, feed into the streaming context, finalise.
	 * Both APIs (sha256/sha384_init/update/final) are safe in setup_arch()
	 * (see the sl_hash_data() comment).
	 */
	if (sl_active_algo == SL_HASH_SHA384)
		sha384_init(&sctx384);
	else
		sha256_init(&sctx256);

	remaining = size;
	while (remaining > 0) {
		size_t chunk = min_t(u64, remaining, (u64)PAGE_SIZE);

		p = early_memremap(start + off, chunk);
		if (!p)
			panic("slaunch: initrd chunk remap failed at 0x%llx (chunk %zu)\n",
			      start + off, chunk);
		if (sl_active_algo == SL_HASH_SHA384)
			sha384_update(&sctx384, p, chunk);
		else
			sha256_update(&sctx256, p, chunk);
		early_memunmap(p, chunk);
		off += chunk;
		remaining -= chunk;
	}
	if (sl_active_algo == SL_HASH_SHA384)
		sha384_final(&sctx384, hash);
	else
		sha256_final(&sctx256, hash);

	pr_info("slaunch: measured initrd (%llu bytes) %s: %*phN\n",
		size, ainfo->name, (int)ainfo->digest_size, hash);

	slaunch_measurements_reserve(slaunch_measurement_count + 1);
	m = &slaunch_measurements[slaunch_measurement_count++];
	strscpy(m->desc, "initrd", sizeof(m->desc));
	memcpy(m->hash, hash, ainfo->digest_size);
	if (ainfo->digest_size < SL_HASH_MAX_DIGEST_SIZE)
		memset(m->hash + ainfo->digest_size, 0,
		       SL_HASH_MAX_DIGEST_SIZE - ainfo->digest_size);
	m->digest_size = ainfo->digest_size;
	m->tpm_alg_id = ainfo->tpm_alg_id;
}

/*
 * Extend the DRTM event log with DLME-side measurements. The kernel
 * allocates its OWN buffer (sl_kernel_evlog), copies the DCE-published
 * bytes in (read-only), and appends one bounds-checked TCG_PCR_EVENT2
 * per measurement; the combined log is exposed via securityfs.
 */
/*
 * TODO: no Arm event type (DEN0113 v1.2 §3.17.2 Table 19, base 0x9000)
 * matches a DLME-side ACPI measurement, so generic TCG
 * EV_PLATFORM_CONFIG_FLAGS (0x0A) is used; switch to a dedicated
 * EVTYPE_ARM_* once one is registered.
 */
#define SL_EV_PLATFORM_CONFIG_FLAGS	0x0000000A
#define SL_DRTM_PCR_INDEX		18	/* DEN0113 v1.2: PCR[18] DLME schema, §4.8.4 Table 40 */

/*
 * Per-event upper bound (TCG PFP §10.2.2): PCRIndex/EventType/count
 * (12) + alg_id (2) + max digest (64) + EventSize (4) + desc (16) = 98,
 * rounded to 128. Describes one event's shape, not a total-buffer cap.
 */
#define SL_TCG_EVENT2_MAX_BYTES		128

/*
 * Fixed-event budget: events not scaled by efi_nr_tables/efi_mmap_descs
 * (CMDLINE, initrd, SRTM_TPM_LOG) plus headroom. 16 covers the existing
 * 4 with margin.
 */
#define SL_DLME_FIXED_EVENTS		16

/*
 * Constant headroom for small overhead beyond pure TCG_PCR_EVENT2
 * records (future header prefix or padding); 1 KiB, not a buffer cap.
 */
#define SL_KEVLOG_HEADROOM		1024

/*
 * Sanity cap on the DCE-published event log size the kernel copies: an
 * absolute structural bound (1 MiB, well above any realistic log) to
 * refuse pathological firmware sizes arithmetic could miss.
 */
#define SL_DCE_EVLOG_MAX		(1ULL * 1024 * 1024)

/*
 * Write one TCG_PCR_EVENT2 at *off in buf (advances *off); -ENOSPC if no
 * room within max. Packed LE: u32 PCRIndex, EventType, digest_count;
 * per digest u16 hashAlg + hash[digest_size]; u32 EventSize + Event[].
 * digest_size/alg are variable (SHA-256 32 B, SHA-384 48 B) per record.
 */
static int __init sl_evlog_append_event2(u8 *buf, size_t *off, size_t max,
					 u32 pcr, u32 type,
					 u16 tpm_alg_id,
					 const u8 *hash, u8 digest_size,
					 const void *event_data,
					 u32 event_size)
{
	size_t need;
	u8 *p;

	if (digest_size == 0 || digest_size > SL_HASH_MAX_DIGEST_SIZE)
		return -EINVAL;

	need = 4 + 4 + 4 + 2 + digest_size + 4 + event_size;

	if (*off + need > max)
		return -ENOSPC;

	p = buf + *off;
	*(__le32 *)(p +  0) = cpu_to_le32(pcr);
	*(__le32 *)(p +  4) = cpu_to_le32(type);
	*(__le32 *)(p +  8) = cpu_to_le32(1);
	*(__le16 *)(p + 12) = cpu_to_le16(tpm_alg_id);
	memcpy(p + 14, hash, digest_size);
	*(__le32 *)(p + 14 + digest_size) = cpu_to_le32(event_size);
	if (event_size)
		memcpy(p + 14 + digest_size + 4, event_data, event_size);
	*off += need;
	return 0;
}

static void __init slaunch_extend_drtm_event_log(void)
{
	phys_addr_t dlme_data_pa, evlog_pa;
	struct dlme_data_header *hdr;
	u64 hdr_size, prot_size, map_size, dlme_data_size;
	u64 evlog_size_initial;
	size_t evlog_max, evlog_off;
	u8 *evlog_va;
	unsigned int i;
	u64 efi_mmap_descs;
	size_t kbuf_cap;
	u64 per_event_budget;

	if (!sl_dlme_region_pa)
		return;

	dlme_data_pa = sl_dlme_region_pa + sl_dlme_data_offset;

	/* Read offsets from the DLME data header. Unmap before we touch
	 * the event log to avoid fixmap-slot overlap on the same page.
	 */
	hdr = early_memremap(dlme_data_pa, sizeof(*hdr));
	if (!hdr)
		panic("slaunch: event log: cannot map DLME data header\n");
	hdr_size            = le16_to_cpu(hdr->this_hdr_size);
	prot_size           = le64_to_cpu(hdr->protected_regions_size);
	map_size            = le64_to_cpu(hdr->address_map_size);
	dlme_data_size      = le64_to_cpu(hdr->dlme_data_size);
	evlog_size_initial  = le64_to_cpu(hdr->drtm_event_log_size);
	early_memunmap(hdr, sizeof(*hdr));

	if (evlog_size_initial == 0)
		panic("slaunch: DCE published empty DRTM event log\n");

	/*
	 * DCE event log runs from after header+protected_regions+address_map
	 * to the end of the DLME data region; guard the sub-region
	 * arithmetic against u64 wrap/underflow before subtracting.
	 */
	{
		u64 sub_total;

		if (check_add_overflow(hdr_size, prot_size, &sub_total) ||
		    check_add_overflow(sub_total, map_size, &sub_total))
			panic("slaunch: DLME header sub-region sizes wrap u64 (hdr=%llu prot=%llu map=%llu)\n",
			      hdr_size, prot_size, map_size);
		if (sub_total > sl_dlme_data_size)
			panic("slaunch: DLME header sub-region total %llu exceeds dlme_data_size %llu\n",
			      sub_total, sl_dlme_data_size);

		evlog_pa  = dlme_data_pa + sub_total;
		evlog_max = (size_t)(sl_dlme_data_size - sub_total);
	}

	if (evlog_size_initial > SL_DCE_EVLOG_MAX)
		panic("slaunch: DCE-published event log size %llu exceeds 1 MiB sanity cap\n",
		      evlog_size_initial);
	if (evlog_size_initial > (u64)evlog_max)
		panic("slaunch: DCE-published event log size %llu exceeds DLME-data event_log capacity %zu\n",
		      evlog_size_initial, evlog_max);

	/*
	 * Allocate the kernel event-log buffer: dce_evlog_size +
	 * (efi_nr_tables + efi_mmap_descs + SL_DLME_FIXED_EVENTS) *
	 * SL_TCG_EVENT2_MAX_BYTES + SL_KEVLOG_HEADROOM. Untrusted UEFI counts
	 * only bound the size; appended bytes are all validated.
	 */
	efi_mmap_descs = sl_efi_mmap_desc_size ?
			 sl_efi_mmap_size / sl_efi_mmap_desc_size : 0;

	per_event_budget = (u64)sl_efi_nr_tables + efi_mmap_descs +
			   SL_DLME_FIXED_EVENTS;
	/*
	 * Multiplication guard for per_event_budget * SL_TCG_EVENT2_MAX_BYTES;
	 * bounded in practice, but check explicitly before use.
	 */
	if (per_event_budget > SIZE_MAX / SL_TCG_EVENT2_MAX_BYTES)
		panic("slaunch: event log capacity formula overflow (nr_tables=%lu mmap_descs=%llu)\n",
		      sl_efi_nr_tables, efi_mmap_descs);

	kbuf_cap = (size_t)evlog_size_initial +
		   (size_t)per_event_budget * SL_TCG_EVENT2_MAX_BYTES +
		   SL_KEVLOG_HEADROOM;

	sl_kernel_evlog = memblock_alloc(kbuf_cap, SMP_CACHE_BYTES);
	if (!sl_kernel_evlog)
		panic("slaunch: memblock_alloc for kernel event log buffer failed (%zu bytes)\n",
		      kbuf_cap);
	sl_kernel_evlog_capacity = kbuf_cap;
	sl_kernel_evlog_size = 0;

	pr_info("slaunch: kernel event log: VA %p, capacity %zu B (DCE=%llu + (tables=%lu + mmap=%llu + fixed=%u)*%u + headroom=%u)\n",
		sl_kernel_evlog, kbuf_cap, evlog_size_initial,
		sl_efi_nr_tables, efi_mmap_descs,
		SL_DLME_FIXED_EVENTS, SL_TCG_EVENT2_MAX_BYTES,
		SL_KEVLOG_HEADROOM);

	pr_info("slaunch: DCE event log: PA 0x%llx, DLME-data sub-region capacity %zu B, DCE-published %llu B\n",
		(u64)evlog_pa, evlog_max, evlog_size_initial);

	/*
	 * Copy DCE's published event log into the kernel buffer (the only
	 * read of the DCE buffer; later appends target sl_kernel_evlog).
	 * Done while DLME-data is still under SMMU DMA protection
	 * (unprotect is a late_initcall), so no DMA TOCTOU is possible.
	 */
	evlog_va = early_memremap(evlog_pa, (size_t)evlog_size_initial);
	if (!evlog_va)
		panic("slaunch: cannot map DCE event log at 0x%llx (%llu B)\n",
		      (u64)evlog_pa, evlog_size_initial);
	memcpy(sl_kernel_evlog, evlog_va, (size_t)evlog_size_initial);
	early_memunmap(evlog_va, (size_t)evlog_size_initial);
	sl_kernel_evlog_size = (size_t)evlog_size_initial;

	/*
	 * Append DLME-side measurements into the kernel buffer (NOT the
	 * DCE buffer). Every sl_evlog_append_event2() call bounds-checks
	 * against sl_kernel_evlog_capacity.
	 */
	evlog_off = sl_kernel_evlog_size;
	for (i = 0; i < slaunch_measurement_count; i++) {
		const struct slaunch_measurement *m = &slaunch_measurements[i];
		size_t dlen = strnlen(m->desc, sizeof(m->desc));

		if (sl_evlog_append_event2(sl_kernel_evlog, &evlog_off,
					   sl_kernel_evlog_capacity,
					   SL_DRTM_PCR_INDEX,
					   SL_EV_PLATFORM_CONFIG_FLAGS,
					   m->tpm_alg_id,
					   m->hash, m->digest_size,
					   m->desc, (u32)dlen))
			panic("slaunch: kernel event log overflow at DLME entry %u (%s) — buffer cap=%zu, off=%zu\n",
			      i, m->desc, sl_kernel_evlog_capacity, evlog_off);
	}
	sl_kernel_evlog_size = evlog_off;

	pr_info("slaunch: kernel event log: copied %llu B from DCE, appended %u DLME entries (total %zu B, slack %zu B)\n",
		evlog_size_initial, slaunch_measurement_count,
		sl_kernel_evlog_size,
		sl_kernel_evlog_capacity - sl_kernel_evlog_size);

	/* Canonical event-log bytes (DCE + DLME) are what a verifier
	 * replays; exposed via securityfs rather than dumped to the log.
	 */
	pr_info("slaunch: DRTM event log canonical size (DCE + DLME): %zu B\n",
		sl_kernel_evlog_size);

	pr_info("slaunch: DLME event log entries (PCR %u, EV_PLATFORM_CONFIG_FLAGS):\n",
		SL_DRTM_PCR_INDEX);
	for (i = 0; i < slaunch_measurement_count; i++) {
		const struct slaunch_measurement *m = &slaunch_measurements[i];
		const char *algo_name =
			(m->tpm_alg_id == SL_TPM_ALG_SHA384) ? "SHA-384" :
			(m->tpm_alg_id == SL_TPM_ALG_SHA256) ? "SHA-256" :
			"UNKNOWN";

		pr_info("slaunch:   [%2u] %-12s %s: %*phN\n",
			i, m->desc, algo_name,
			(int)m->digest_size, m->hash);
	}
}

#ifdef CONFIG_ARM64_SECURE_LAUNCH_FAULT_INJECT
/*
 * Negative-test fault injection (slaunch_inject=<token>): mutates the
 * raw EFI mmap/systab/SRTM-log before slaunch_validate_efi_early so the
 * validator panics. Tokens: mmap_*, systab_nr_tables_huge, srtm_log_*,
 * sha384_force, sha_algo_bad. Not for production.
 */
static bool __init sl_cmdline_has(const char *tok)
{
	return strstr(boot_command_line, tok);
}

/* Mutate one descriptor in the raw EFI mmap buffer. Returns true if
 * we found a CONVENTIONAL_MEMORY descriptor and applied the mutation.
 */
typedef void (*sl_md_mutator_t)(efi_memory_desc_t *md);

static bool __init slaunch_inject_raw_mmap(const struct sl_efi_info *info,
					   sl_md_mutator_t mutate)
{
	void *mmap;
	u64 offset;
	bool applied = false;

	mmap = early_memremap(info->mmap_pa, info->mmap_size);
	if (!mmap) {
		pr_warn("slaunch: INJECT: failed to map raw mmap\n");
		return false;
	}
	for (offset = 0; offset < info->mmap_size; offset += info->desc_size) {
		efi_memory_desc_t *md =
			(efi_memory_desc_t *)((u8 *)mmap + offset);

		if (md->type != EFI_CONVENTIONAL_MEMORY)
			continue;
		mutate(md);
		applied = true;
		break;
	}
	early_memunmap(mmap, info->mmap_size);
	return applied;
}

static void __init sl_mutate_mmap_wrap(efi_memory_desc_t *md)
{
	/* phys_addr + num_pages*4096 wraps past U64_MAX */
	md->num_pages = (~md->phys_addr / EFI_PAGE_SIZE) + 2;
	pr_warn("slaunch: INJECT mmap_wrap on phys=0x%llx -> num_pages=%llu (expect panic 'wraps u64')\n",
		md->phys_addr, md->num_pages);
}

static void __init sl_mutate_mmap_pages_overflow(efi_memory_desc_t *md)
{
	/* num_pages * EFI_PAGE_SIZE itself overflows */
	md->num_pages = (U64_MAX / EFI_PAGE_SIZE) + 2;
	pr_warn("slaunch: INJECT mmap_pages_overflow on phys=0x%llx -> num_pages=%llu (expect panic 'overflows u64')\n",
		md->phys_addr, md->num_pages);
}

/* Force two CONVENTIONAL descriptors to overlap so the overlap
 * detector in slaunch_validate_raw_mmap fires its WARN (non-fatal). */
static void __init slaunch_inject_mmap_overlap(const struct sl_efi_info *info)
{
	void *mmap;
	u64 off;
	efi_memory_desc_t *first = NULL;

	mmap = early_memremap(info->mmap_pa, info->mmap_size);
	if (!mmap) {
		pr_warn("slaunch: INJECT mmap_overlap: map failed\n");
		return;
	}
	for (off = 0; off < info->mmap_size; off += info->desc_size) {
		efi_memory_desc_t *md =
			(efi_memory_desc_t *)((u8 *)mmap + off);

		if (md->type != EFI_CONVENTIONAL_MEMORY)
			continue;
		if (!first) {
			first = md;
			continue;
		}
		md->phys_addr = first->phys_addr;
		if (!md->num_pages)
			md->num_pages = 1;
		pr_warn("slaunch: INJECT mmap_overlap: 2nd CONV desc -> phys=0x%llx (expect 'OVERLAP')\n",
			md->phys_addr);
		early_memunmap(mmap, info->mmap_size);
		return;
	}
	pr_warn("slaunch: INJECT mmap_overlap: <2 CONVENTIONAL descriptors\n");
	early_memunmap(mmap, info->mmap_size);
}

/* Overwrite the first non-null EFI ConfigurationTable entry in the raw
 * systab's cfgtbl array with a synthetic SRTM-log entry. Returns true
 * if we managed to plant the entry. Used by srtm_log_* injectors only;
 * not safe for production. */
static bool __init slaunch_inject_srtm_cfgtbl(const struct sl_efi_info *info,
					      u64 vendor_pa)
{
	efi_guid_t srtm_guid = LINUX_EFI_TPM_EVENT_LOG_GUID;
	efi_system_table_t *systab;
	efi_config_table_t *cfgtbl;
	unsigned long tables_pa;
	unsigned long nr_tables;
	size_t tbl_size;
	unsigned long j;
	bool applied = false;

	systab = early_memremap(info->systab_pa, sizeof(*systab));
	if (!systab) {
		pr_warn("slaunch: INJECT srtm_log: systab remap failed\n");
		return false;
	}
	nr_tables = systab->nr_tables;
	tables_pa = (unsigned long)systab->tables;
	early_memunmap(systab, sizeof(*systab));

	if (!nr_tables || !tables_pa) {
		pr_warn("slaunch: INJECT srtm_log: systab has no cfgtbl entries\n");
		return false;
	}
	tbl_size = nr_tables * sizeof(*cfgtbl);
	cfgtbl = early_memremap(tables_pa, tbl_size);
	if (!cfgtbl) {
		pr_warn("slaunch: INJECT srtm_log: cfgtbl remap failed\n");
		return false;
	}
	for (j = 0; j < nr_tables; j++) {
		if (!cfgtbl[j].table)
			continue;
		cfgtbl[j].guid = srtm_guid;
		cfgtbl[j].table = (void *)(unsigned long)vendor_pa;
		applied = true;
		break;
	}
	early_memunmap(cfgtbl, tbl_size);
	return applied;
}

static void __init slaunch_inject_srtm_log(const struct sl_efi_info *info)
{
	u64 vendor_pa;
	const char *tag = NULL;

	if (sl_cmdline_has("slaunch_inject=srtm_log_overlap_dlme")) {
		/* Aim the entry at the start of the DLME region. The header
		 * extent overlap check in slaunch_validate_srtm_log fires
		 * before any size field is read. */
		vendor_pa = sl_dlme_region_pa;
		tag = "srtm_log_overlap_dlme";
	} else if (sl_cmdline_has("slaunch_inject=srtm_log_outside_normal")) {
		/* FVP PL011 UART base — a DEVICE region per DEN0113 v1.2
		 * Table 11. dcrtm_range_in_normal must reject. */
		vendor_pa = 0x1c090000ULL;
		tag = "srtm_log_outside_normal";
	} else if (sl_cmdline_has("slaunch_inject=srtm_log_overlap_mmap")) {
		/*
		 * Aim the entry at the raw EFI mmap PA: it is NORMAL so the
		 * range check passes and only the overlap-with-mmap guard in
		 * slaunch_validate_srtm_log rejects it.
		 */
		vendor_pa = info->mmap_pa;
		tag = "srtm_log_overlap_mmap";
	} else {
		return;
	}

	if (!slaunch_inject_srtm_cfgtbl(info, vendor_pa))
		pr_warn("slaunch: INJECT %s: could not plant cfgtbl entry\n",
			tag);
	else
		pr_warn("slaunch: INJECT %s: planted SRTM-log entry PA=0x%llx (expect panic)\n",
			tag, vendor_pa);
}

static void __init slaunch_inject_fault(struct sl_efi_info *info)
{
	if (!info->present) {
		/* Nothing to inject into. */
		return;
	}

	slaunch_inject_srtm_log(info);

	if (sl_cmdline_has("slaunch_inject=mmap_wrap")) {
		if (!slaunch_inject_raw_mmap(info, sl_mutate_mmap_wrap))
			pr_warn("slaunch: INJECT mmap_wrap: no EFI_CONVENTIONAL_MEMORY descriptor found\n");
		return;
	}
	if (sl_cmdline_has("slaunch_inject=mmap_pages_overflow")) {
		if (!slaunch_inject_raw_mmap(info, sl_mutate_mmap_pages_overflow))
			pr_warn("slaunch: INJECT mmap_pages_overflow: no EFI_CONVENTIONAL_MEMORY descriptor found\n");
		return;
	}
	if (sl_cmdline_has("slaunch_inject=mmap_overlap")) {
		slaunch_inject_mmap_overlap(info);
		return;
	}
	if (sl_cmdline_has("slaunch_inject=mmap_size_huge")) {
		/*
		 * Inflate the local mmap size (a 48-multiple, so the
		 * multiple-of-desc guard is not what trips) past any NORMAL
		 * region so the containment check in validate_raw_mmap fires.
		 */
		info->mmap_size = (0x10000000000ULL / 48ULL) * 48ULL;
		pr_warn("slaunch: INJECT mmap_size_huge: info->mmap_size=%llu (expect panic 'NOT entirely in NORMAL')\n",
			info->mmap_size);
		return;
	}
	if (sl_cmdline_has("slaunch_inject=systab_nr_tables_huge")) {
		/*
		 * Inflate nr_tables in-place so nr_tables * sizeof(entry)
		 * overflows and check_mul_overflow in validate_raw_systab panics.
		 */
		efi_system_table_t *systab;

		systab = early_memremap(info->systab_pa,
					sizeof(efi_system_table_t));
		if (!systab) {
			pr_warn("slaunch: INJECT systab_nr_tables_huge: remap failed\n");
			return;
		}
		systab->nr_tables =
			(ULONG_MAX / sizeof(efi_config_table_t)) + 1UL;
		pr_warn("slaunch: INJECT systab_nr_tables_huge: nr_tables=%lu (expect panic 'overflows tbl_size')\n",
			(unsigned long)systab->nr_tables);
		early_memunmap(systab, sizeof(efi_system_table_t));
		return;
	}
}

/*
 * Negative-test fault injection for initrd measurement (cmdline
 * slaunch_inject=<token>). Mutates the local start/size copies before
 * validation, exercising the same path an attacker-controlled DTB would.
 * Tokens: initrd_wrap, initrd_size_huge, initrd_outside_normal, _overlap_dlme.
 */
static void __init slaunch_inject_initrd(u64 *start, u64 *size)
{
	if (sl_cmdline_has("slaunch_inject=initrd_wrap")) {
		*size = (~(*start)) + 2;
		pr_warn("slaunch: INJECT initrd_wrap: start=0x%llx size=%llu (expect panic 'wraps u64')\n",
			*start, *size);
		return;
	}
	if (sl_cmdline_has("slaunch_inject=initrd_size_huge")) {
		/*
		 * Force the initrd end past its NORMAL region with a size just
		 * below the u64 wrap, so check_add_overflow passes and the
		 * NORMAL-containment check is what panics.
		 */
		if (*start && U64_MAX - *start > 1ULL)
			*size = U64_MAX - *start - 1ULL;
		else
			*size = (1ULL << 62);
		pr_warn("slaunch: INJECT initrd_size_huge: size=%llu (expect panic 'NOT in NORMAL region')\n",
			*size);
		return;
	}
	if (sl_cmdline_has("slaunch_inject=initrd_outside_normal")) {
		*start = 0x1c090000ULL;
		*size = PAGE_SIZE;
		pr_warn("slaunch: INJECT initrd_outside_normal: start=0x%llx (expect panic 'NOT in NORMAL region')\n",
			*start);
		return;
	}
	if (sl_cmdline_has("slaunch_inject=initrd_overlap_dlme")) {
		*start = sl_dlme_region_pa;
		*size = PAGE_SIZE;
		pr_warn("slaunch: INJECT initrd_overlap_dlme: start=0x%llx (expect panic 'overlaps DLME')\n",
			*start);
		return;
	}
}
#endif /* CONFIG_ARM64_SECURE_LAUNCH_FAULT_INJECT */

#ifdef CONFIG_ARM64_SECURE_LAUNCH_SELFTEST
/*
 * Self-test of the validation guards (end of slaunch_measure_post_efi).
 * Calls the helpers with crafted wrapping inputs plus valid ones; the
 * helpers must reject the bad and accept the good, else panic with a
 * "selftest:" prefix that the harness flags as a regression.
 */
static void __init slaunch_selftest(void)
{
	/* T1: dcrtm_range_in_normal MUST reject wrapping start+size */
	if (dcrtm_range_in_normal(0xFFFFFFFFFFFFE000ULL, 0x10000ULL))
		panic("selftest: dcrtm_range_in_normal accepted wrapping range\n");

	/* T2: dcrtm_range_in_normal MUST reject size==0 */
	if (dcrtm_range_in_normal(0x80000000ULL, 0))
		panic("selftest: dcrtm_range_in_normal accepted size=0\n");

	/* T3: dcrtm_range_in_normal MUST accept a known-good NORMAL range
	 * (one page in NS DRAM). Regression check.
	 */
	if (!dcrtm_range_in_normal(0x80000000ULL, EFI_PAGE_SIZE))
		panic("selftest: dcrtm_range_in_normal rejected known NORMAL range (regression)\n");

	/* T4: dcrtm_range_overlaps_non_normal MUST fail closed on wrap
	 * (returns RSVD instead of -1).
	 */
	if (dcrtm_range_overlaps_non_normal(0xFFFFFFFFFFFFE000ULL,
					    0x10000ULL) != DRTM_REGION_TYPE_RSVD)
		panic("selftest: dcrtm_range_overlaps_non_normal did not fail closed on wrap\n");

	/* T5: efi_regions_overlap MUST fail closed (true) on either wrap */
	if (!efi_regions_overlap(0xFFFFFFFFFFFFE000ULL, 0x10000ULL,
				 0x80000000ULL, EFI_PAGE_SIZE))
		panic("selftest: efi_regions_overlap did not fail closed on wrap\n");

	/* T6: efi_regions_overlap on disjoint ranges MUST return false */
	if (efi_regions_overlap(0x80000000ULL, 0x1000ULL,
				0x90000000ULL, 0x1000ULL))
		panic("selftest: efi_regions_overlap reported false overlap on disjoint ranges\n");

	/* T7: efi_regions_overlap on truly-overlapping ranges MUST return true */
	if (!efi_regions_overlap(0x80000000ULL, 0x10000ULL,
				 0x80008000ULL, 0x10000ULL))
		panic("selftest: efi_regions_overlap missed real overlap\n");

	/* T8: check_mul_overflow catches num_pages * EFI_PAGE_SIZE wrap
	 * (the macro behind the slaunch_validate_efi guard).
	 */
	{
		u64 out;

		if (!check_mul_overflow((u64)0x10000000000000ULL,
					(u64)EFI_PAGE_SIZE, &out))
			panic("selftest: check_mul_overflow missed num_pages*PAGE_SIZE wrap\n");
	}

	/* T9: slaunch_phys_is_protected_ram is the exact predicate
	 * acpi_os_ioremap/__acpi_get_mem_attribute gate on. It MUST flag the
	 * measured DLME region and MUST NOT flag a non-RAM PA. */
	if (sl_dlme_region_pa) {
		if (!slaunch_phys_is_protected_ram(sl_dlme_region_pa))
			panic("selftest: slaunch_phys_is_protected_ram missed DLME region\n");
		if (slaunch_phys_is_protected_ram(0))
			panic("selftest: slaunch_phys_is_protected_ram flagged non-RAM PA\n");
	}

	pr_info("slaunch: ALL SELFTESTS PASSED (9/9)\n");
}
#endif /* CONFIG_ARM64_SECURE_LAUNCH_SELFTEST */

/*
 * Post-efi_init jobs that need efi_init's outputs: re-reserve DLME data
 * (efi_init's memblock_remove wiped the slaunch_setup reservation),
 * measure ACPI tables via efi.acpi20, and run the validation-helper
 * self-test. Untrusted EFI inputs were already validated in slaunch_setup().
 */
void __init slaunch_measure_post_efi(void)
{
	if (!sl_dlme_region_pa)
		return;

	if (sl_dlme_data_size)
		memblock_reserve(sl_dlme_data_pa, sl_dlme_data_size);

	slaunch_measurements_init();
	slaunch_selftest();
	slaunch_verify_hash_algo();
	slaunch_measure_acpi();

	/*
	 * Measure the effective kernel command line (boot_command_line, the
	 * post-/chosen cmdline the kernel actually used). Per-deployment
	 * variance makes the hash vary, so verifier policy must allow for it
	 * (or pin it via CONFIG_CMDLINE_FORCE).
	 */
	slaunch_measure("CMDLINE", boot_command_line, strlen(boot_command_line));

	slaunch_measure_initrd();
	slaunch_extend_drtm_event_log();

	/*
	 * Release the dcrtm_regions early_memremap_ro slot; no further
	 * validators consume it. NULLing the pointer makes any stray
	 * post-init caller fail-fast in dcrtm_range_in_normal's guard.
	 */
	if (dcrtm_regions) {
		early_memunmap(dcrtm_regions,
			       dcrtm_num_regions * sizeof(*dcrtm_regions));
		dcrtm_regions = NULL;
	}
}

/*
 * Securityfs exposure for the kernel-side DRTM event log, mirroring the
 * TPM "binary_bios_measurements" file. Same information-disclosure
 * surface: measurement hashes are not secrets but the attestation
 * primitive a remote verifier fetches.
 */
static ssize_t slaunch_evlog_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	if (!sl_kernel_evlog || !sl_kernel_evlog_size)
		return 0;
	return simple_read_from_buffer(buf, count, ppos,
				       sl_kernel_evlog,
				       sl_kernel_evlog_size);
}

static const struct file_operations slaunch_evlog_fops = {
	.owner	= THIS_MODULE,
	.read	= slaunch_evlog_read,
	.llseek	= default_llseek,
};

static struct dentry *sl_securityfs_dir;
static struct dentry *sl_securityfs_evlog;

static int __init slaunch_securityfs_init(void)
{
	if (!sl_kernel_evlog || !sl_kernel_evlog_size)
		return 0;

	sl_securityfs_dir = securityfs_create_dir("slaunch", NULL);
	if (IS_ERR(sl_securityfs_dir)) {
		pr_warn("slaunch: securityfs_create_dir failed: %ld\n",
			PTR_ERR(sl_securityfs_dir));
		sl_securityfs_dir = NULL;
		return 0;
	}

	sl_securityfs_evlog = securityfs_create_file("drtm_event_log",
						     0440,
						     sl_securityfs_dir,
						     NULL,
						     &slaunch_evlog_fops);
	if (IS_ERR(sl_securityfs_evlog)) {
		pr_warn("slaunch: securityfs_create_file failed: %ld\n",
			PTR_ERR(sl_securityfs_evlog));
		securityfs_remove(sl_securityfs_dir);
		sl_securityfs_dir = NULL;
		sl_securityfs_evlog = NULL;
		return 0;
	}

	pr_info("slaunch: securityfs/slaunch/drtm_event_log exposed (%zu B)\n",
		sl_kernel_evlog_size);
	return 0;
}
late_initcall(slaunch_securityfs_init);

/*
 * Release DRTM DMA protection after IOMMU/SMMU drivers have
 * established their own DMA isolation.
 */
static int __init slaunch_unprotect_memory(void)
{
	struct arm_smccc_res res;

	if (!sl_dlme_region_pa)
		return 0;

	pr_info("slaunch: Calling DRTM_UNPROTECT_MEMORY\n");
	arm_smccc_smc(DRTM_SMC_UNPROTECT_MEMORY, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 != DRTM_SUCCESS) {
		pr_err("slaunch: UNPROTECT_MEMORY failed: %ld\n",
		       (long)res.a0);
		return -EIO;
	}

	pr_info("slaunch: DMA protection released\n");
	return 0;
}
late_initcall(slaunch_unprotect_memory);

/*
 * Clean up DRTM state before kexec or reboot. Do not call
 * DRTM_SET_ERROR(0): per DEN0113 v1.2 §3.8 its argument is the persisted
 * error code, zero is reserved, and no "clear errors" semantics exists.
 */
void slaunch_exit(void)
{
	if (!sl_dlme_region_pa)
		return;

	pr_info("slaunch: Cleaning DRTM state before kexec/reboot\n");
	sl_dlme_region_pa = 0;
}
