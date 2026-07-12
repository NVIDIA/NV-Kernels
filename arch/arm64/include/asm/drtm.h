/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ARM64 DRTM (Dynamic Root of Trust for Measurement) definitions.
 * Based on DEN0113 v1.2 — Arm DRTM Architecture Specification.
 */
#ifndef _ASM_ARM64_DRTM_H
#define _ASM_ARM64_DRTM_H

#ifndef __ASSEMBLY__
#include <linux/types.h>
#endif

/* DRTM SMC Function IDs (DEN0113 v1.2 §3.2-3.10) */
#define DRTM_SMC_FN_BASE		0xC4000110UL
#define DRTM_SMC_VERSION		(DRTM_SMC_FN_BASE + 0x00)
#define DRTM_SMC_FEATURES		(DRTM_SMC_FN_BASE + 0x01)
#define DRTM_SMC_UNPROTECT_MEMORY	(DRTM_SMC_FN_BASE + 0x03)
#define DRTM_SMC_DYNAMIC_LAUNCH		(DRTM_SMC_FN_BASE + 0x04)
#define DRTM_SMC_CLOSE_LOCALITY		(DRTM_SMC_FN_BASE + 0x05)
#define DRTM_SMC_GET_ERROR		(DRTM_SMC_FN_BASE + 0x06)
#define DRTM_SMC_SET_ERROR		(DRTM_SMC_FN_BASE + 0x07)
#define DRTM_SMC_SET_TCB_HASH		(DRTM_SMC_FN_BASE + 0x08)
#define DRTM_SMC_LOCK_TCB_HASH		(DRTM_SMC_FN_BASE + 0x09)
#define DRTM_SMC_ENABLE_SECURE_INTERRUPTS (DRTM_SMC_FN_BASE + 0x0A) /* 0xC400011A */

/* DRTM Return Codes (DEN0113 v1.2 §3.18, Table 20) */
#define DRTM_SUCCESS			0
#define DRTM_NOT_SUPPORTED		(-1)
#define DRTM_INVALID_PARAMETERS		(-2)
#define DRTM_DENIED			(-3)
#define DRTM_INTERNAL_ERROR		(-5)

/* DEN0113 v1.2 Table 9: DRTM_PARAMETERS revision is 2 */
#define DRTM_PARAMS_REVISION		2

/* Launch features */
#define DRTM_LAUNCH_FEAT_MEM_PROT_ALL	(0x0 << 3)
#define DRTM_LAUNCH_FEAT_SEC_INT_DISABLE (0x1 << 7) /* DEN0113 Table 9 */

/* DRTM page size */
#define DRTM_PAGE_SIZE			0x1000

/*
 * Preamble->DLME DTB-PA handoff slot: DTB PA written 8 bytes below the
 * DLME data region; sl_entry reads it via X0+X1-8 after D-CRTM ERET.
 * Private contract (not DEN0113); DTB PA validated before FDT is parsed.
 */
#define SL_DLME_DTB_SLOT_OFFSET		(-8)

/*
 * Full-range DMA protection sentinel (DEN0113 v1.2 §3.14 Table 11 +
 * §4.6.2): type = NORMAL, start = 0, page count = 2^52 - 1.
 */
#define DRTM_MEM_PROT_FULL_RANGE	\
	((0x0ULL << 55) | (0x0ULL << 52) | ((1ULL << 52) - 1ULL))

#ifndef __ASSEMBLY__
/*
 * Memory Region Descriptor Table (DEN0113 v1.2 §3.14, Table 11): header
 * followed by num_regions descriptors, consumed in place from the DLME
 * data region (no fixed-size copy, no region-count cap).
 */
struct drtm_mem_region_hdr {
	__le16	revision;
	__le16	reserved;
	__le32	num_regions;
} __packed;

struct drtm_mem_region {
	__le64	start_address;
	__le64	size_and_type;
} __packed;

/*
 * Address map region types in size_and_type bits [54:52] (DEN0113 v1.2
 * §3.14 Table 11): 0 normal, 1 normal+cacheability, 2 device/MMIO,
 * 3 non-volatile, 4 reserved.
 */
#define DRTM_REGION_TYPE_NORMAL			0
#define DRTM_REGION_TYPE_NORMAL_CACHED		1
#define DRTM_REGION_TYPE_DEVICE			2
#define DRTM_REGION_TYPE_NV			3
#define DRTM_REGION_TYPE_RSVD			4

/*
 * size_and_type field helpers (DEN0113 v1.2 §3.14 Table 11): page count
 * [51:0], region type [54:52], cacheability [56:55] (valid for
 * NORMAL_CACHED), reserved [63:57].
 */
#define DRTM_MEM_REGION_PAGE_COUNT(x)	((x) & ((1ULL << 52) - 1))
#define DRTM_MEM_REGION_TYPE(x)		(((x) >> 52) & 0x7)
#define DRTM_MEM_REGION_CACHEABILITY(x)	(((x) >> 55) & 0x3)

/* DLME Data Header (DEN0113 v1.2 §3.15, Table 14) — populated by D-CRTM */
struct dlme_data_header {
	__le16	version;
	__le16	this_hdr_size;
	__le32	reserved;
	__le64	dlme_data_size;
	__le64	protected_regions_size;
	__le64	address_map_size;
	__le64	drtm_event_log_size;
	__le64	tcb_hash_table_size;
	__le64	acpi_table_region_size;
	__le64	impl_defined_region_size;
};

#ifdef CONFIG_ARM64_SECURE_LAUNCH
extern unsigned long sl_dlme_region_pa;
extern unsigned long sl_dlme_data_offset;

void slaunch_early_init(void);
void slaunch_setup(void);
void slaunch_validate_initrd(void);
void slaunch_reserve_dlme_data(void);
void slaunch_measure_post_efi(void);
bool slaunch_phys_is_protected_ram(phys_addr_t pa);
bool slaunch_phys_range_overlaps_protected_ram(phys_addr_t pa, size_t size);
#else
static inline void slaunch_early_init(void) { }
static inline void slaunch_setup(void) { }
static inline void slaunch_validate_initrd(void) { }
static inline void slaunch_reserve_dlme_data(void) { }
static inline void slaunch_measure_post_efi(void) { }
static inline bool slaunch_phys_is_protected_ram(phys_addr_t pa) { return false; }
static inline bool slaunch_phys_range_overlaps_protected_ram(phys_addr_t pa, size_t size) { return false; }
#endif

#endif /* __ASSEMBLY__ */

#endif /* _ASM_ARM64_DRTM_H */
