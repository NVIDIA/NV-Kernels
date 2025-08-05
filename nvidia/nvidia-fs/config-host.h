/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Kernel compatibility definitions for nvidia-fs
 * Generated for in-tree kernel build
 */

#ifndef CONFIG_HOST_H
#define CONFIG_HOST_H

/* Kernel 6.14 compatibility flags */
/* #define HAVE_STRUCT_FD_FILE_PARAM 1 - Changed to fd_file() macro in 6.14 */
#define HAVE_ACCESS_OK_2_PARAMS 1
#define HAVE_BLK_RQ_PAYLOAD_BYTES 1
/* #define HAVE_CALL_READ_WRITE_ITER 1 - Removed in 6.14 */
#define HAVE_FILEMAP_RANGE_HAS_PAGE 1
#define HAVE_KI_COMPLETE 1
#define HAVE_VM_FAULT 1
#define HAVE_PCIE_SPEED_32_0GT 1
#define HAVE_PCIE_SPEED_64_0GT 1
#define HAVE_STRUCT_PROC_OPS 1
#define HAVE_VM_OPS_MREMAP_ONE_PARAM 1
#define HAVE_BLK_INTEGRITY_H 1
#define HAVE_PIN_USER_PAGES_FAST 1

#endif /* CONFIG_HOST_H */