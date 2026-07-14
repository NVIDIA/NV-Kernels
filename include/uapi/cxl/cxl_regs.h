/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * CXL Standard defines
 *
 * Hardware register offsets and bit-field masks for the CXL Component
 * Register block, as defined by the CXL Specification r4.0.
 */

#ifndef _UAPI_CXL_REGS_H_
#define _UAPI_CXL_REGS_H_

#include <asm/bitsperlong.h>  /* __BITS_PER_LONG; needed by __GENMASK() */
#include <linux/const.h>     /* _BITUL(), _BITULL() */
#include <linux/bits.h>      /* __GENMASK() */

/* CXL 4.0 8.2.3 CXL Component Register Layout and Definition */
#define CXL_COMPONENT_REG_BLOCK_SIZE 0x00010000

/* CXL 4.0 8.2.4 CXL.cache and CXL.mem Registers*/
#define CXL_CM_OFFSET 0x1000
#define CXL_CM_CAP_HDR_OFFSET 0x0
#define   CXL_CM_CAP_HDR_ID_MASK __GENMASK(15, 0)
#define     CM_CAP_HDR_CAP_ID 1
#define   CXL_CM_CAP_HDR_VERSION_MASK __GENMASK(19, 16)
#define     CM_CAP_HDR_CAP_VERSION 1
#define   CXL_CM_CAP_HDR_CACHE_MEM_VERSION_MASK __GENMASK(23, 20)
#define     CM_CAP_HDR_CACHE_MEM_VERSION 1
#define   CXL_CM_CAP_HDR_ARRAY_SIZE_MASK __GENMASK(31, 24)
#define CXL_CM_CAP_PTR_MASK __GENMASK(31, 20)

/* CXL HDM Decoder Capability Structure */
#define CXL_HDM_DECODER_CAP_OFFSET 0x0
#define   CXL_HDM_DECODER_COUNT_MASK __GENMASK(3, 0)
#define   CXL_HDM_DECODER_TARGET_COUNT_MASK __GENMASK(7, 4)
#define   CXL_HDM_DECODER_INTERLEAVE_11_8 _BITUL(8)
#define   CXL_HDM_DECODER_INTERLEAVE_14_12 _BITUL(9)
#define   CXL_HDM_DECODER_POISON_ON_DECODE_ERR _BITUL(10)
#define   CXL_HDM_DECODER_INTERLEAVE_3_6_12_WAY _BITUL(11)
#define   CXL_HDM_DECODER_INTERLEAVE_16_WAY _BITUL(12)
#define   CXL_HDM_DECODER_UIO_CAPABLE _BITUL(13)
#define   CXL_HDM_DECODER_UIO_COUNT_MASK __GENMASK(19, 16)
#define   CXL_HDM_DECODER_MEMDATA_NXM _BITUL(20)
#define   CXL_HDM_DECODER_COHERENCY_MODELS_MASK    __GENMASK(22, 21)
#define CXL_HDM_DECODER_CTRL_OFFSET 0x4
#define   CXL_HDM_DECODER_ENABLE _BITUL(1)
#define CXL_HDM_DECODER0_BASE_LOW_OFFSET(i) (0x20 * (i) + 0x10)
#define CXL_HDM_DECODER0_BASE_HIGH_OFFSET(i) (0x20 * (i) + 0x14)
#define CXL_HDM_DECODER0_SIZE_LOW_OFFSET(i) (0x20 * (i) + 0x18)
#define CXL_HDM_DECODER0_SIZE_HIGH_OFFSET(i) (0x20 * (i) + 0x1c)
#define CXL_HDM_DECODER0_CTRL_OFFSET(i) (0x20 * (i) + 0x20)
#define   CXL_HDM_DECODER0_CTRL_IG_MASK __GENMASK(3, 0)
#define   CXL_HDM_DECODER0_CTRL_IW_MASK __GENMASK(7, 4)
#define   CXL_HDM_DECODER0_CTRL_LOCK _BITUL(8)
#define   CXL_HDM_DECODER0_CTRL_COMMIT _BITUL(9)
#define   CXL_HDM_DECODER0_CTRL_COMMITTED _BITUL(10)
#define   CXL_HDM_DECODER0_CTRL_COMMIT_ERROR _BITUL(11)
#define   CXL_HDM_DECODER0_CTRL_HOSTONLY _BITUL(12)
#define CXL_HDM_DECODER0_TL_LOW(i) (0x20 * (i) + 0x24)
#define CXL_HDM_DECODER0_TL_HIGH(i) (0x20 * (i) + 0x28)
#define CXL_HDM_DECODER0_SKIP_LOW(i) CXL_HDM_DECODER0_TL_LOW(i)
#define CXL_HDM_DECODER0_SKIP_HIGH(i) CXL_HDM_DECODER0_TL_HIGH(i)

#endif /* _UAPI_CXL_REGS_H_ */
