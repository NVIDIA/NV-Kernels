/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ARM64 DRTM Secure Launch entry stub — DLME entry point. D-CRTM (TF-A)
 * ERETs here per DEN0113 v1.2 §4.6.1 Table 33 with X0 = DLME region PA,
 * X1 = data offset, MMU/D-cache off; recovers the DTB PA, branches to
 * primary_entry for normal boot.
 */

#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/drtm.h>

	.section ".idmap.text","a"

/*
 * sl_entry — DRTM dynamic launch entry point. Only reached via DRTM
 * ERET (DRTM_PARAMETERS entry_point_offset); never during normal boot.
 */
SYM_CODE_START(sl_entry)
	/*
	 * Save DLME region PA for slaunch_setup(). MMU/D-cache off
	 * (DEN0113 v1.2 §4.6.1 Table 33), so the str hits DRAM; dc ivac
	 * (not cvac) drops the stale cache line so the kernel re-reads
	 * the fresh value once caches are on.
	 */
	adr_l	x9, sl_dlme_region_pa
	str	x0, [x9]
	dc	ivac, x9

	/* Same for DLME data offset. */
	adr_l	x9, sl_dlme_data_offset
	str	x1, [x9]
	dc	ivac, x9
	dsb	sy

	/*
	 * Load DTB PA from the Preamble->DLME slot at
	 * (region_base + data_offset + SL_DLME_DTB_SLOT_OFFSET).
	 */
	add	x9, x0, x1
	ldr	x0, [x9, #SL_DLME_DTB_SLOT_OFFSET]	/* X0 = DTB PA */

	/* Clear X1-X3 per arm64 boot protocol */
	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr

	/* Enter normal kernel boot with X0 = DTB PA */
	b	primary_entry
SYM_CODE_END(sl_entry)

	.section .data
	.align 3
SYM_DATA(sl_dlme_region_pa,	.quad 0)
SYM_DATA(sl_dlme_data_offset,	.quad 0)
