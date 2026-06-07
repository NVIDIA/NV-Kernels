// SPDX-License-Identifier: GPL-2.0-only
/*
 * NVIDIA FIRME Attestation Driver
 *
 * TSM report backend and TSM measurement register backend for ARM FIRME
 * (DEN0149) on NVIDIA Grace (TH500) platforms.
 *
 * - TSM Reports: invokes FIRME_ATTEST_PAT_GET (0xC4000408) to retrieve
 *   platform attestation tokens from EL3/PSC via configfs.
 * - TSM MR: invokes FIRME_ATTEST_EXT_CLAIMS (0xC400040B) to extend
 *   measurement registers and submit BMDR device reports to PSC
 *   via sysfs.
 *
 * Copyright (c) 2025-2026, NVIDIA Corporation. All rights reserved.
 */

#include <linux/arm-smccc.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/tsm.h>
#include <linux/tsm-mr.h>
#include <linux/types.h>
#include <crypto/hash_info.h>

/* FIRME SMC Function IDs — DEN0149, SMC64, Fast call, OEN=4 (Std Svc) */
#define FIRME_FID(fn)			(0xC4000000UL | (fn))
#define FIRME_SERVICE_VERSION		FIRME_FID(0x0400)
#define FIRME_ATTEST_PAT_GET		FIRME_FID(0x0408)
#define FIRME_ATTEST_EXTEND		FIRME_FID(0x040B)

/* FIRME return codes (DEN0149 Table 8.24) */
#define FIRME_SUCCESS			0L
#define FIRME_NOT_SUPPORTED		(-1L)
#define FIRME_INVALID_PARAMETERS	(-2L)
#define FIRME_ABORTED			(-3L)
#define FIRME_INCOMPLETE		(-4L)
#define FIRME_DENIED			(-5L)
#define FIRME_RETRY			(-6L)

/* SHA-384 digest size */
#define SHA384_DIGEST_SIZE		48

/*
 * BMDR (Baremetal Device Report) entry size for slot 0.
 * Layout: [48 identity_digest][48 mexchange_digest][1 gpu_id][3 reserved]
 */
#define FIRME_BMDR_SIZE			100

/*
 * Shared buffer sizing.  ATF computes: size = (page_count + 1) * 4KB.
 * page_count=3 → 16KB buffer, sufficient for most tokens.
 */
#define FIRME_BUF_PAGE_COUNT		3
#define FIRME_MIN_SHARED_BUF_SZ	SZ_4K
#define FIRME_BUF_SIZE			((FIRME_BUF_PAGE_COUNT + 1) * \
					 FIRME_MIN_SHARED_BUF_SZ)
#define FIRME_MAX_TOKEN_SIZE		SZ_32K
#define FIRME_MAX_RETRIES		5

static bool nvidia_firme_available(void)
{
	struct arm_smccc_res res;

	arm_smccc_1_1_invoke(FIRME_SERVICE_VERSION, 0, 0, 0, 0, &res);
	if ((long)res.a0 == FIRME_NOT_SUPPORTED)
		return false;

	pr_info("nvidia-firme: FIRME service version %lu.%lu\n",
		res.a0 >> 16, res.a0 & 0xffff);
	return true;
}

/**
 * nvidia_firme_report_new - Generate an attestation report via FIRME SMC.
 * @report: TSM report structure; inblob is used as the challenge nonce.
 * @data: unused private data.
 *
 * Allocates a physically contiguous NS buffer, places the optional
 * challenge at offset 0, then calls FIRME_ATTEST_PAT_GET in a loop
 * to retrieve the full platform attestation token.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int nvidia_firme_report_new(struct tsm_report *report, void *data)
{
	struct tsm_report_desc *desc = &report->desc;
	struct arm_smccc_res res;
	void *buf;
	phys_addr_t buf_phys;
	u8 *token __free(kvfree) = NULL;
	u64 offset = 0;
	u64 challenge_sz = 0;
	size_t token_size = 0;
	int retries;

	buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
				       get_order(FIRME_BUF_SIZE));
	if (!buf)
		return -ENOMEM;

	buf_phys = virt_to_phys(buf);

	/* Place challenge/nonce at offset 0 of the shared buffer */
	if (desc->inblob_len > 0) {
		if (desc->inblob_len > FIRME_BUF_SIZE) {
			free_pages((unsigned long)buf, get_order(FIRME_BUF_SIZE));
			return -EINVAL;
		}
		memcpy(buf, desc->inblob, desc->inblob_len);
		challenge_sz = desc->inblob_len;
	}

	token = kvzalloc(FIRME_MAX_TOKEN_SIZE, GFP_KERNEL);
	if (!token) {
		free_pages((unsigned long)buf, get_order(FIRME_BUF_SIZE));
		return -ENOMEM;
	}

	/* Chunked retrieval loop per DEN0149 Section 8.12 */
	do {
		retries = 0;
retry:
		pr_info("nvidia-firme: FIRME_ATTEST_PAT_GET SMC: buf=0x%llx offset=%llu page_count=%d challenge_sz=%llu\n",
			(u64)buf_phys, offset, FIRME_BUF_PAGE_COUNT,
			challenge_sz);

		arm_smccc_1_1_invoke(FIRME_ATTEST_PAT_GET,
				     buf_phys,
				     offset,
				     FIRME_BUF_PAGE_COUNT,
				     challenge_sz,
				     &res);

		pr_info("nvidia-firme: SMC returned: status=%ld written=%lu remaining=%lu\n",
			(long)res.a0, res.a1, res.a2);

		if ((long)res.a0 == FIRME_RETRY) {
			pr_warn("nvidia-firme: ATF returned RETRY (%d/%d)\n",
				retries + 1, FIRME_MAX_RETRIES);
			if (++retries > FIRME_MAX_RETRIES) {
				pr_err("nvidia-firme: too many RETRYs\n");
				free_pages((unsigned long)buf,
					   get_order(FIRME_BUF_SIZE));
				return -EAGAIN;
			}
			cond_resched();
			goto retry;
		}

		if ((long)res.a0 == FIRME_ABORTED) {
			pr_err("nvidia-firme: ATF returned ABORTED (-3). PSC token not available (PSC task may not be running)\n");
			free_pages((unsigned long)buf, get_order(FIRME_BUF_SIZE));
			return -ENODATA;
		}

		if ((long)res.a0 != FIRME_SUCCESS &&
		    (long)res.a0 != FIRME_INCOMPLETE) {
			pr_err("nvidia-firme: SMC failed, status=%ld (NOT_SUPPORTED=%ld, INVALID_PARAMS=%ld, DENIED=%ld)\n",
			       (long)res.a0, FIRME_NOT_SUPPORTED,
			       FIRME_INVALID_PARAMETERS, (long)-5);
			free_pages((unsigned long)buf, get_order(FIRME_BUF_SIZE));
			return -EIO;
		}

		/* res.a1 = bytes written this call, starting at offset in buf */
		if (token_size + res.a1 > FIRME_MAX_TOKEN_SIZE) {
			pr_err("nvidia-firme: token exceeds max size\n");
			free_pages((unsigned long)buf, get_order(FIRME_BUF_SIZE));
			return -ENOSPC;
		}

		memcpy(&token[token_size], buf + offset, res.a1);
		token_size += res.a1;
		offset += res.a1;

		/* Clear challenge after first call */
		challenge_sz = 0;
	} while (res.a2 > 0);  /* res.a2 = remaining bytes */

	free_pages((unsigned long)buf, get_order(FIRME_BUF_SIZE));

	report->outblob = no_free_ptr(token);
	report->outblob_len = token_size;

	pr_info("nvidia-firme: attestation token retrieved, %zu bytes\n",
		token_size);
	return 0;
}

static const struct tsm_report_ops nvidia_firme_tsm_ops = {
	.name = KBUILD_MODNAME,
	.report_new = nvidia_firme_report_new,
};

/* ================================================================
 * TSM Measurement Registers (MR) — FIRME_ATTEST_EXT_CLAIMS backend
 *
 * Exposes PSC measurement slots via sysfs. Writing to a slot sends
 * data to PSC by calling FIRME_ATTEST_EXT_CLAIMS SMC (0xC400040B).
 *
 * Slot 0 (bmdr): 100-byte BMDR device report per GPU
 *   [0-47]  identity_digest  (SHA-384 of device cert chain)
 *   [48-95] mexchange_digest (SHA-384 of SPDM measurement exchange)
 *   [96]    gpu_device_id
 *   [97-99] reserved (0)
 *
 * Slot 1+ (rem0-rem2): 48-byte SHA-384 extensible measurement slots
 * ================================================================ */

#define FIRME_MR_NUM_SLOTS		4

static u8 firme_mr_bmdr_value[FIRME_BMDR_SIZE];
static u8 firme_mr_rem_values[FIRME_MR_NUM_SLOTS - 1][SHA384_DIGEST_SIZE];

/**
 * firme_mr_extend - Submit data to PSC via FIRME_ATTEST_EXT_CLAIMS SMC.
 *
 * For slot 0 (bmdr): sends a 100-byte BMDR device report per GPU.
 * For slot 1+ (rem): sends a 48-byte SHA-384 digest for REM extension.
 */
static int firme_mr_extend(const struct tsm_measurements *tm,
			    const struct tsm_measurement_register *mr,
			    const u8 *data)
{
	struct arm_smccc_res res;
	unsigned int slot_index = mr - tm->mrs;
	void *buf;
	phys_addr_t buf_phys;

	buf = (void *)get_zeroed_page(GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, data, mr->mr_size);
	buf_phys = virt_to_phys(buf);

	pr_info("nvidia-firme: EXT_CLAIMS SMC: slot=%u buf=0x%llx size=%u\n",
		slot_index, (u64)buf_phys, mr->mr_size);

	arm_smccc_1_1_invoke(FIRME_ATTEST_EXTEND,
			     buf_phys,
			     mr->mr_size,
			     slot_index,
			     0,
			     &res);

	free_page((unsigned long)buf);

	pr_info("nvidia-firme: EXT_CLAIMS returned status=%ld\n", (long)res.a0);

	if ((long)res.a0 == FIRME_SUCCESS) {
		memcpy(mr->mr_value, data, mr->mr_size);
		return 0;
	}

	if ((long)res.a0 == FIRME_INVALID_PARAMETERS) {
		pr_err("nvidia-firme: EXT_CLAIMS failed: invalid parameters (slot=%u size=%u)\n",
		       slot_index, mr->mr_size);
		return -EINVAL;
	}

	if ((long)res.a0 == FIRME_DENIED) {
		pr_err("nvidia-firme: EXT_CLAIMS failed: denied (slot %u)\n",
		       slot_index);
		return -EACCES;
	}

	pr_err("nvidia-firme: EXT_CLAIMS failed: status=%ld\n", (long)res.a0);
	return -EIO;
}

static int firme_mr_refresh(const struct tsm_measurements *tm)
{
	/* MR values are cached locally after each extend call.
	 * PSC doesn't provide a read-back API, so refresh is a no-op. */
	return 0;
}

static struct tsm_measurement_register firme_mrs[FIRME_MR_NUM_SLOTS] = {
	{
		.mr_name = "bmdr",
		.mr_value = firme_mr_bmdr_value,
		.mr_size = FIRME_BMDR_SIZE,
		.mr_flags = TSM_MR_F_READABLE | TSM_MR_F_WRITABLE
			    | TSM_MR_F_NOHASH,
		.mr_hash = 0,
	},
	{
		.mr_name = "rem0",
		.mr_value = firme_mr_rem_values[0],
		.mr_size = SHA384_DIGEST_SIZE,
		.mr_flags = TSM_MR_F_READABLE | TSM_MR_F_WRITABLE,
		.mr_hash = HASH_ALGO_SHA384,
	},
	{
		.mr_name = "rem1",
		.mr_value = firme_mr_rem_values[1],
		.mr_size = SHA384_DIGEST_SIZE,
		.mr_flags = TSM_MR_F_READABLE | TSM_MR_F_WRITABLE,
		.mr_hash = HASH_ALGO_SHA384,
	},
	{
		.mr_name = "rem2",
		.mr_value = firme_mr_rem_values[2],
		.mr_size = SHA384_DIGEST_SIZE,
		.mr_flags = TSM_MR_F_READABLE | TSM_MR_F_WRITABLE,
		.mr_hash = HASH_ALGO_SHA384,
	},
};

static struct tsm_measurements firme_measurements = {
	.mrs = firme_mrs,
	.nr_mrs = FIRME_MR_NUM_SLOTS,
	.refresh = firme_mr_refresh,
	.write = firme_mr_extend,
};

static const struct attribute_group *firme_mr_grp;
static struct kobject *firme_kobj;

/* ================================================================
 * Module init/exit
 * ================================================================ */

static int __init nvidia_firme_init(void)
{
	int ret;

	if (!nvidia_firme_available()) {
		pr_info("nvidia-firme: FIRME service not available\n");
		return -ENODEV;
	}

	ret = tsm_report_register(&nvidia_firme_tsm_ops, NULL);
	if (ret < 0) {
		pr_err("nvidia-firme: failed to register TSM reports (%d)\n", ret);
		return ret;
	}

	firme_mr_grp = tsm_mr_create_attribute_group(&firme_measurements);
	if (IS_ERR(firme_mr_grp)) {
		pr_err("nvidia-firme: failed to create TSM MR group (%ld)\n",
		       PTR_ERR(firme_mr_grp));
		firme_mr_grp = NULL;
	} else {
		firme_kobj = kobject_create_and_add("nvidia-firme",
						    firmware_kobj);
		if (!firme_kobj) {
			pr_err("nvidia-firme: failed to create sysfs kobject\n");
			tsm_mr_free_attribute_group(firme_mr_grp);
			firme_mr_grp = NULL;
		} else {
			ret = sysfs_create_group(firme_kobj, firme_mr_grp);
			if (ret) {
				pr_err("nvidia-firme: failed to create MR sysfs group (%d)\n", ret);
				kobject_put(firme_kobj);
				firme_kobj = NULL;
				tsm_mr_free_attribute_group(firme_mr_grp);
				firme_mr_grp = NULL;
			} else {
				pr_info("nvidia-firme: measurement registers at /sys/firmware/nvidia-firme/\n");
			}
		}
	}

	pr_info("nvidia-firme: registered with TSM framework\n");
	return 0;
}
module_init(nvidia_firme_init);

static void __exit nvidia_firme_exit(void)
{
	if (firme_mr_grp && firme_kobj)
		sysfs_remove_group(firme_kobj, firme_mr_grp);
	if (firme_kobj)
		kobject_put(firme_kobj);
	if (firme_mr_grp)
		tsm_mr_free_attribute_group(firme_mr_grp);
	tsm_report_unregister(&nvidia_firme_tsm_ops);
	pr_info("nvidia-firme: unregistered from TSM\n");
}
module_exit(nvidia_firme_exit);

MODULE_AUTHOR("Hyder Ali <mhyderali@nvidia.com>");
MODULE_DESCRIPTION("NVIDIA FIRME (DEN0149) Attestation and Measurement Driver");
MODULE_LICENSE("GPL");
