// SPDX-License-Identifier: GPL-2.0-only
/*
 * ARM64 DRTM Secure Launch — EFI stub component. Builds DRTM_PARAMETERS
 * and issues DRTM_DYNAMIC_LAUNCH when the cmdline has "drtm=on". The SMC
 * does not return on success: D-CRTM measures the image and ERETs to
 * sl_entry. Copyright (c) 2025-2026, NVIDIA Corporation.
 */

#include <linux/efi.h>
#include <asm/drtm.h>
#include <asm/efi.h>
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

/*
 * DRTM Parameters (DEN0113 v1.2 §3.13 / Table 9)
 * Struct must be packed — passed directly to TF-A via SMC.
 */
struct sl_drtm_params {
	u16	revision;
	u16	reserved;
	u32	launch_features;
	u64	dlme_region_address;
	u64	dlme_region_size;
	u64	dlme_image_start;
	u64	dlme_entry_point_offset;
	u64	dlme_image_size;
	u64	dlme_data_offset;
	u64	nw_dce_region_address;
	u64	nw_dce_region_size;
	u64	mem_prot_table_address;
	u64	mem_prot_table_size;
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

static void sl_smc(u64 fn, u64 arg1)
{
	sl_smc_ret(fn, arg1);
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
	u32 min_pages;

	asm volatile("smc #0"
		: "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3)
		:
		: "x4", "x5", "x6", "x7", "x8", "x9", "x10",
		  "x11", "x12", "x13", "x14", "x15", "x16", "x17",
		  "memory");

	/* DRTM_FEATURES success is x0 > 0; x1[31:0] = min DLME data pages. */
	if ((s64)x0 <= 0)
		return;
	min_pages = (u32)(x1 & 0xFFFFFFFF);
	if (min_pages == 0)
		return;

	sl_dlme_data_reserve = (unsigned long)min_pages * SL_DRTM_PAGE_SIZE;
	sl_drtm_available = true;
	efi_info("DRTM: min DLME data size %lu KB (%u pages)\n",
		 sl_dlme_data_reserve / 1024, min_pages);
}

/*
 * Zero the PE/COFF Optional Header ImageBase on the relocated kernel
 * buffer (pre-EBS): LoadImage patched it with the load PA, diverging the
 * D-CRTM-measured bytes from the on-disk Image. Pre-EBS because
 * efi_remap_image() marked the header RO; flip RW, zero, restore RO.
 */
void efi_slaunch_scrub_imagebase(unsigned long kernel_addr)
{
	efi_guid_t guid = EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID;
	efi_memory_attribute_protocol_t *memattr;
	efi_status_t status;
	u32 e_lfanew;
	volatile u64 *image_base_ptr;
	unsigned long page_base;

	if (!kernel_addr)
		return;

	e_lfanew = *(volatile u32 *)((char *)kernel_addr + 0x3c);
	image_base_ptr = (volatile u64 *)((char *)kernel_addr +
					  e_lfanew + 4 + 20 + 0x18);
	page_base = (unsigned long)image_base_ptr & ~(SL_DRTM_PAGE_SIZE - 1UL);

	status = efi_bs_call(locate_protocol, &guid, NULL, (void **)&memattr);
	if (status != EFI_SUCCESS) {
		efi_warn("DRTM: no EFI_MEMORY_ATTRIBUTE_PROTOCOL; "
			 "skipping PE ImageBase scrub\n");
		return;
	}

	status = memattr->clear_memory_attributes(memattr, page_base,
						  SL_DRTM_PAGE_SIZE,
						  EFI_MEMORY_RO);
	if (status != EFI_SUCCESS) {
		efi_warn("DRTM: clear EFI_MEMORY_RO failed for PE header page: 0x%lx\n",
			 status);
		return;
	}

	*image_base_ptr = 0;
	sl_dc_cvac_range((unsigned long)image_base_ptr, 8);
	asm volatile("dsb sy" : : : "memory");

	status = memattr->set_memory_attributes(memattr, page_base,
						SL_DRTM_PAGE_SIZE,
						EFI_MEMORY_RO);
	if (status != EFI_SUCCESS)
		efi_warn("DRTM: restore EFI_MEMORY_RO on PE header page failed: 0x%lx\n",
			 status);

	efi_info("DRTM: PE ImageBase zeroed at 0x%lx\n",
		 (unsigned long)image_base_ptr);
}

/*
 * Token-aware cmdline match: true iff `tok` is a standalone
 * whitespace-delimited word in `cmdline`, not a substring of another
 * option (so "drtm=on" does not match "nodrtm=on" or "root=...drtm=on").
 */
static bool sl_cmdline_token(const char *cmdline, const char *tok)
{
	size_t toklen = strlen(tok);
	const char *p = cmdline;

	while ((p = strstr(p, tok)) != NULL) {
		bool start_ok = (p == cmdline) || p[-1] == ' ' || p[-1] == '\t';
		bool end_ok = p[toklen] == '\0' || p[toklen] == ' ' ||
			      p[toklen] == '\t';

		if (start_ok && end_ok)
			return true;
		p += toklen;
	}
	return false;
}

bool efi_slaunch_enabled(const char *cmdline)
{
	if (!cmdline)
		return false;
	if (!sl_cmdline_token(cmdline, "drtm=on"))
		return false;

	/*
	 * drtm=on requires efi=noruntime, else the post-DRTM kernel could
	 * call unmeasured UEFI runtime services. If missing, skip DRTM.
	 */
	if (!sl_cmdline_token(cmdline, "efi=noruntime")) {
		efi_warn("DRTM: drtm=on needs efi=noruntime; skipping DRTM\n");
		return false;
	}
	return true;
}

/*
 * TF-A requires DRTM_PARAMETERS to be 4KB-aligned; we are past
 * ExitBootServices so cannot allocate — use a static buffer.
 */
static struct sl_drtm_params sl_params __aligned(SL_DRTM_PAGE_SIZE);

void __noreturn efi_slaunch_drtm(unsigned long kernel_addr,
				 unsigned long fdt_addr)
{
	struct sl_drtm_params *params = &sl_params;
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
	dlme_data_offset = SL_ROUND_UP_PAGE(kernel_memsize);

	/*
	 * Write DTB PA into the Preamble->DLME slot at (kernel_addr +
	 * dlme_data_offset + SL_DLME_DTB_SLOT_OFFSET); sl_entry reads it via
	 * X0 + X1 + SL_DLME_DTB_SLOT_OFFSET after the D-CRTM ERET.
	 */
	*(volatile u64 *)(kernel_addr + dlme_data_offset +
			  SL_DLME_DTB_SLOT_OFFSET) = fdt_addr;

	/* Build DRTM_PARAMETERS */
	params->revision = DRTM_PARAMS_REVISION;
	params->reserved = 0;
	/* bits[5:3]=0: complete DMA protection. bit 7: request Secure-interrupt
	 * disable for the launch window (DEN0113 Table 9); the DLME re-enables
	 * post-launch via DRTM_ENABLE_SECURE_INTERRUPTS. */
	params->launch_features = DRTM_LAUNCH_FEAT_MEM_PROT_ALL | DRTM_LAUNCH_FEAT_SEC_INT_DISABLE;
	params->dlme_region_address = kernel_addr;
	params->dlme_region_size = dlme_data_offset + sl_dlme_data_reserve;
	params->dlme_image_start = 0;
	params->dlme_entry_point_offset = sl_entry_offset;
	params->dlme_image_size = image_size;
	params->dlme_data_offset = dlme_data_offset;
	params->nw_dce_region_address = 0;
	params->nw_dce_region_size = 0;
	/* Complete DMA protection: table must be zero (DEN0113 v1.2 Table 9). */
	params->mem_prot_table_address = 0;
	params->mem_prot_table_size = 0;

	/*
	 * Clean to DRAM what the D-CRTM reads after the SMC: the params
	 * struct and the DTB PA slot (outside TF-A's own DLME flush).
	 */
	sl_dc_cvac_range((unsigned long)params, sizeof(*params));
	sl_dc_cvac_range(kernel_addr + dlme_data_offset +
			 SL_DLME_DTB_SLOT_OFFSET, sizeof(u64));
	/*
	 * NOTE: the PE ImageBase scrub happens pre-EBS in
	 * efi_slaunch_scrub_imagebase(); the memory-attribute protocol used
	 * to unprotect the header page is unreachable after boot services exit.
	 */
	asm volatile("dsb sy" : : : "memory");

	/*
	 * DRTM_DYNAMIC_LAUNCH — does not return on success.
	 * D-CRTM: measures kernel, populates DLME data, ERETs to sl_entry
	 */
	sl_smc(SL_DRTM_SMC_DYNAMIC_LAUNCH, (u64)params);

	/* If we reach here, the SMC failed. Halt. */
	efi_err("DRTM: dynamic launch did not occur\n");
	for (;;)
		asm volatile("wfi");
}
