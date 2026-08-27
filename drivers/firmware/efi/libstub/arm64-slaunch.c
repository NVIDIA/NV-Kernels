// SPDX-License-Identifier: GPL-2.0-only
/*
 * ARM64 DRTM Secure Launch — EFI stub component. Builds DRTM_PARAMETERS
 * and issues DRTM_DYNAMIC_LAUNCH when requested by the drtm= command-line
 * option. The SMC does not return on success: D-CRTM measures the image and
 * ERETs to sl_entry. Copyright (c) 2025-2026, NVIDIA Corporation.
 */

#include <linux/efi.h>
#include <linux/pe.h>
#include <linux/unaligned.h>
#include <asm/drtm.h>
#include <asm/efi.h>
#include <asm/image.h>
#include <asm/sections.h>

#include "efistub.h"

/* DRTM SMC IDs — duplicated here for EFI stub isolation */
#define SL_DRTM_SMC_FEATURES		0xC4000111UL
#define SL_DRTM_SMC_DYNAMIC_LAUNCH	0xC4000114UL
#define SL_DRTM_PAGE_SIZE		0x1000
#define SL_ROUND_UP_PAGE(x)		(((x) + SL_DRTM_PAGE_SIZE - 1) & \
					 ~(SL_DRTM_PAGE_SIZE - 1ULL))

/*
 * Preamble<->DLME DTB-PA convention slot (mirrors SL_DLME_DTB_SLOT_OFFSET
 * in arch/arm64/include/asm/drtm.h — keep them in sync).
 */
#define SL_DLME_DTB_SLOT_OFFSET		(-8)

/* From sl_stub.S — accessible via __efistub_ alias in image-vars.h */
extern char sl_entry[];

#define SL_PE_DEBUG_DIRECTORY_INDEX	6

struct sl_pe_debug_directory_entry {
	__le32	characteristics;
	__le32	timestamp;
	__le16	major_version;
	__le16	minor_version;
	__le32	type;
	__le32	size_of_data;
	__le32	address_of_raw_data;
	__le32	pointer_to_raw_data;
} __packed;

static u64 sl_smc_ret(u64 fn, u64 arg1)
{
	register u64 x0 __asm__("x0") = fn;
	register u64 x1 __asm__("x1") = arg1;
	register u64 x2 __asm__("x2") = 0;
	register u64 x3 __asm__("x3") = 0;

	asm volatile("smc #0"
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
		:
		: "x4", "x5", "x6", "x7", "x8", "x9", "x10",
		  "x11", "x12", "x13", "x14", "x15", "x16", "x17",
		  "memory");
	return x0;
}

/* Read CTR_EL0.DminLine and return cache line size in bytes. */
static inline unsigned int sl_dcache_line_size(void)
{
	u64 ctr;

	asm volatile("mrs %0, ctr_el0" : "=r"(ctr));
	return 4U << ((ctr >> 16) & 0xfU);
}

/*
 * Clean (cvac) a range to PoC at cache-line granularity so TF-A sees
 * the stub's freshly-written value from EL3.
 */
static inline void sl_dc_cvac_range(unsigned long start, unsigned long len)
{
	unsigned int line = sl_dcache_line_size();
	unsigned long mask = (unsigned long)line - 1UL;
	unsigned long end = start + len;
	unsigned long addr;

	start &= ~mask;
	for (addr = start; addr < end; addr += line)
		asm volatile("dc cvac, %0" : : "r"(addr) : "memory");
}

/*
 * DLME data reserve (from DRTM_FEATURES) and whether D-CRTM advertised
 * DRTM support. Consumed by arm64-stub.c and the launch gate in fdt.c.
 */
unsigned long sl_dlme_data_reserve;
bool sl_drtm_available;

/*
 * Query DRTM_FEATURES (DEN0113 v1.2 Table 6, feature 0x2) for the minimum
 * DLME data size. Best-effort: failure leaves DRTM unavailable (normal
 * boot). Called before ExitBootServices.
 */
void efi_slaunch_get_dlme_data_size(void)
{
	register u64 x0 __asm__("x0") = SL_DRTM_SMC_FEATURES;
	register u64 x1 __asm__("x1") = (1ULL << 63) | 0x2;
	register u64 x2 __asm__("x2") = 0;
	register u64 x3 __asm__("x3") = 0;
	u32 min_pages, nw_dce_pages;

	asm volatile("smc #0"
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
		:
		: "x4", "x5", "x6", "x7", "x8", "x9", "x10",
		  "x11", "x12", "x13", "x14", "x15", "x16", "x17",
		  "memory");

	/*
	 * DRTM_FEATURES success is x0 > 0. X1[31:0] is the minimum
	 * DLME data size and X1[63:32] is the Normal-world DCE region
	 * size, both in 4 KiB pages.
	 */
	if ((s64)x0 <= 0)
		return;
	nw_dce_pages = (u32)(x1 >> 32);
	if (nw_dce_pages) {
		efi_warn("DRTM: %u-page Normal-world DCE region requested but not supported\n",
			 nw_dce_pages);
		return;
	}

	min_pages = (u32)x1;
	if (min_pages == 0)
		return;

	sl_dlme_data_reserve = (unsigned long)min_pages * SL_DRTM_PAGE_SIZE;
	sl_drtm_available = true;
	efi_info("DRTM: min DLME data size %lu KB (%u pages)\n",
		 sl_dlme_data_reserve / 1024, min_pages);
}

static bool sl_range_in_image(unsigned long offset, unsigned long size,
			      unsigned long image_size)
{
	return offset <= image_size && size <= image_size - offset;
}

/*
 * Prepare the final DLME image after relocation but before efi_remap_image().
 * The arm64 PE header emits zero for ImageBase and every debug-record RVA,
 * but UEFI PE loaders may replace those fields with runtime addresses. Restore
 * the emitted values so the measured image is independent of its load PA.
 *
 * The source buffer is firmware-controlled. Bound every header and table that
 * is consumed here and refuse the DRTM launch if it is not the expected arm64
 * Linux PE32+ image. The destination is a fresh writable allocation, so this
 * does not depend on EFI_MEMORY_ATTRIBUTE_PROTOCOL being implemented.
 */
efi_status_t efi_slaunch_prepare_image(unsigned long kernel_addr,
				       unsigned long kernel_size)
{
	u8 *image = (u8 *)kernel_addr;
	struct mz_hdr *mz;
	struct pe_hdr *pe;
	struct pe32plus_opt_hdr *opt;
	struct data_dirent *dirs;
	struct data_dirent *debug_dir;
	struct sl_pe_debug_directory_entry *debug_entries = NULL;
	unsigned long pe_offset, opt_offset;
	unsigned long debug_offset = 0, debug_size = 0;
	unsigned long debug_count = 0, i;
	u16 opt_size;
	u32 data_dirs;

	if (!kernel_addr ||
	    !sl_range_in_image(0, sizeof(*mz), kernel_size))
		goto invalid;

	mz = (struct mz_hdr *)image;
	if (get_unaligned_le16(&mz->magic) != IMAGE_DOS_SIGNATURE ||
	    memcmp(image + offsetof(struct arm64_image_header, magic),
		   ARM64_IMAGE_MAGIC, sizeof(ARM64_IMAGE_MAGIC) - 1))
		goto invalid;

	pe_offset = get_unaligned_le32(&mz->peaddr);
	if (!sl_range_in_image(pe_offset, sizeof(*pe), kernel_size))
		goto invalid;

	pe = (struct pe_hdr *)(image + pe_offset);
	if (get_unaligned_le32(&pe->magic) != IMAGE_NT_SIGNATURE ||
	    get_unaligned_le16(&pe->machine) != IMAGE_FILE_MACHINE_ARM64)
		goto invalid;

	opt_size = get_unaligned_le16(&pe->opt_hdr_size);
	opt_offset = pe_offset + sizeof(*pe);
	if (opt_size < sizeof(*opt) ||
	    !sl_range_in_image(opt_offset, opt_size, kernel_size))
		goto invalid;

	opt = (struct pe32plus_opt_hdr *)(image + opt_offset);
	if (get_unaligned_le16(&opt->magic) !=
	    IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		goto invalid;

	data_dirs = get_unaligned_le32(&opt->data_dirs);
	if (data_dirs > (opt_size - sizeof(*opt)) / sizeof(*dirs))
		goto invalid;

	if (data_dirs > SL_PE_DEBUG_DIRECTORY_INDEX) {
		dirs = (struct data_dirent *)((u8 *)opt + sizeof(*opt));
		debug_dir = &dirs[SL_PE_DEBUG_DIRECTORY_INDEX];
		debug_offset = get_unaligned_le32(&debug_dir->virtual_address);
		debug_size = get_unaligned_le32(&debug_dir->size);

		if (!!debug_offset != !!debug_size)
			goto invalid;
		if (debug_size) {
			if (debug_size % sizeof(*debug_entries) ||
			    !sl_range_in_image(debug_offset, debug_size,
					       kernel_size))
				goto invalid;
			debug_entries = (void *)(image + debug_offset);
			debug_count = debug_size / sizeof(*debug_entries);
		}
	}

	put_unaligned_le64(0, &opt->image_base);
	for (i = 0; i < debug_count; i++)
		put_unaligned_le32(0, &debug_entries[i].address_of_raw_data);

	sl_dc_cvac_range((unsigned long)&opt->image_base,
			 sizeof(opt->image_base));
	if (debug_size)
		sl_dc_cvac_range((unsigned long)debug_entries, debug_size);
	asm volatile("dsb sy" : : : "memory");

	efi_info("DRTM: canonicalized PE ImageBase and %lu debug record(s)\n",
		 debug_count);
	return EFI_SUCCESS;

invalid:
	efi_err("DRTM: malformed PE/COFF image; refusing Secure Launch\n");
	return EFI_LOAD_ERROR;
}

enum sl_drtm_policy {
	SL_DRTM_OFF,
	SL_DRTM_ON,
	SL_DRTM_ENFORCE,
};

static enum sl_drtm_policy sl_parse_drtm_policy(const char *cmdline)
{
	enum sl_drtm_policy policy = SL_DRTM_OFF;
	const char *p = cmdline;

	if (!p)
		return policy;

	while (*p) {
		const char *end;
		size_t len;

		while (*p == ' ' || *p == '\t')
			p++;
		end = p;
		while (*end && *end != ' ' && *end != '\t')
			end++;
		len = end - p;

		if (len == sizeof("drtm=off") - 1 &&
		    !memcmp(p, "drtm=off", len))
			policy = SL_DRTM_OFF;
		else if (len == sizeof("drtm=on") - 1 &&
			 !memcmp(p, "drtm=on", len))
			policy = SL_DRTM_ON;
		else if (len == sizeof("drtm=enforce") - 1 &&
			 !memcmp(p, "drtm=enforce", len))
			policy = SL_DRTM_ENFORCE;

		p = end;
	}

	return policy;
}

static enum sl_drtm_policy sl_policy;

/*
 * Parse the canonical converted command line once. This avoids a second
 * efi_convert_cmdline(), which would measure the EFI LoadOptions a second
 * time and add a duplicate PCR 9 event.
 */
void efi_slaunch_set_cmdline(const char *cmdline)
{
	sl_policy = sl_parse_drtm_policy(cmdline);
}

/*
 * True iff the recorded command line requests a DRTM launch. Gates the
 * DRTM_FEATURES probe: an SMC faults on a platform with no EL3 monitor,
 * so it must not be issued on boots that never asked for a launch.
 */
bool efi_slaunch_requested(void)
{
	return sl_policy != SL_DRTM_OFF;
}

bool efi_slaunch_enforced(void)
{
	return sl_policy == SL_DRTM_ENFORCE;
}

/*
 * TF-A requires DRTM_PARAMETERS to be 4KB-aligned; we are past
 * ExitBootServices so cannot allocate — use a static buffer.
 */
static struct drtm_parameters sl_params __aligned(SL_DRTM_PAGE_SIZE);

void efi_slaunch_drtm(unsigned long kernel_addr, unsigned long fdt_addr)
{
	struct drtm_parameters *params = &sl_params;
	unsigned long image_size, kernel_memsize;
	unsigned long dlme_data_offset;
	unsigned long sl_entry_offset;

	/*
	 * Store DTB PA just below the DLME data area (dlme_data_offset - 8);
	 * sl_entry finds it via X0 + X1 - 8. Direct physical write avoids
	 * EFI-stub symbol resolution, which can fail under PIC/GOT.
	 */

	/* Compute sl_entry offset from kernel image base */
	sl_entry_offset = (unsigned long)sl_entry - (unsigned long)_text;

	/*
	 * DLME region layout: [_text.._edata] measured image, [_edata.._end]
	 * BSS, then D-CRTM-populated DLME data after _end. FDT is separate
	 * (wherever efi_allocate_pages() put it).
	 */
	image_size = (unsigned long)(_edata - _text);
	kernel_memsize = (unsigned long)(_end - _text);
	dlme_data_offset = SL_ROUND_UP_PAGE(kernel_memsize) + SL_DLME_DTB_SLOT_GAP;

	/*
	 * Write DTB PA into the Preamble->DLME slot at (kernel_addr +
	 * dlme_data_offset + SL_DLME_DTB_SLOT_OFFSET); sl_entry reads it via
	 * X0 + X1 + SL_DLME_DTB_SLOT_OFFSET after the D-CRTM ERET.
	 */
	*(volatile u64 *)(kernel_addr + dlme_data_offset +
			  SL_DLME_DTB_SLOT_OFFSET) = fdt_addr;

	/* Build DRTM_PARAMETERS */
	params->revision = cpu_to_le16(DRTM_PARAMS_REVISION);
	params->reserved = cpu_to_le16(0);
	/* bits[5:3]=0: complete DMA protection. bit 7: request Secure-interrupt
	 * disable for the launch window (DEN0113 Table 9); the DLME re-enables
	 * post-launch via DRTM_ENABLE_SECURE_INTERRUPTS. */
	params->launch_features = cpu_to_le32(DRTM_LAUNCH_FEAT_MEM_PROT_ALL | DRTM_LAUNCH_FEAT_SEC_INT_DISABLE);
	params->dlme_region_address = cpu_to_le64(kernel_addr);
	params->dlme_region_size = cpu_to_le64(dlme_data_offset + sl_dlme_data_reserve);
	params->dlme_image_start = cpu_to_le64(0);
	params->dlme_entry_point_offset = cpu_to_le64(sl_entry_offset);
	params->dlme_image_size = cpu_to_le64(image_size);
	params->dlme_data_offset = cpu_to_le64(dlme_data_offset);
	params->nw_dce_region_address = cpu_to_le64(0);
	params->nw_dce_region_size = cpu_to_le64(0);
	/* Complete DMA protection: table must be zero (DEN0113 v1.2 Table 9). */
	params->mem_prot_table_address = cpu_to_le64(0);
	params->mem_prot_table_size = cpu_to_le64(0);

	/*
	 * Clean to DRAM what the D-CRTM reads after the SMC: the params
	 * struct and the DTB PA slot (outside TF-A's own DLME flush).
	 */
	sl_dc_cvac_range((unsigned long)params, sizeof(*params));
	sl_dc_cvac_range(kernel_addr + dlme_data_offset +
			 SL_DLME_DTB_SLOT_OFFSET, sizeof(u64));
	/* The final image was canonicalized and cache-cleaned before remapping. */
	asm volatile("dsb sy" : : : "memory");

	/*
	 * DRTM_DYNAMIC_LAUNCH — does not return on success.
	 * D-CRTM: measures kernel, populates DLME data, ERETs to sl_entry
	 */
	sl_smc_ret(SL_DRTM_SMC_DYNAMIC_LAUNCH, (u64)params);

	/*
	 * The launch SMC returns only on failure (success ERETs to sl_entry).
	 * With drtm=on, return to the EFI boot path for a normal boot. With
	 * drtm=enforce, fail closed. Boot services are gone, so the pre-EBS
	 * notice is the last diagnostic available in the enforced case.
	 */
	if (!efi_slaunch_enforced())
		return;

	for (;;)
		asm volatile("wfi");
}
