// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 NVIDIA Corporation
 *
 * Arm SMCCC cache maintenance provider using the cache clean+invalidate
 * interface defined by Arm DEN0028 v1.7.
 */

#include <linux/arm-smccc.h>
#include <linux/arm-smccc-bus.h>
#include <linux/cache_coherency.h>
#include <linux/cleanup.h>
#include <linux/container_of.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nmi.h>
#include <linux/time64.h>
#include <linux/types.h>

#define SMCCC_CACHE_MAX_RETRIES		5
#define SMCCC_CACHE_DEFAULT_DELAY_US	1000UL
#define SMCCC_CACHE_MAX_DELAY_US	20000UL

struct smccc_cache {
	/* Must be first member */
	struct cache_coherency_ops_inst cci;
	struct mutex lock; /* Serializes SMCCC cache maintenance calls. */
	u64 rate_limit;
};

static int smccc_cache_status_to_errno(s32 status)
{
	switch (status) {
	case SMCCC_RET_SUCCESS:
		return 0;
	case SMCCC_RET_NOT_SUPPORTED:
		return -EOPNOTSUPP;
	case SMCCC_RET_INVALID_PARAMETER:
		return -EINVAL;
	case SMCCC_RET_RATE_LIMITED:
		return -EAGAIN;
	case SMCCC_RET_BUSY:
		return -EBUSY;
	default:
		return -EIO;
	}
}

static unsigned long smccc_cache_delay_us(const struct smccc_cache *cache)
{
	unsigned long delay_us = 0;

	if (cache->rate_limit)
		delay_us = DIV_ROUND_UP_ULL(USEC_PER_SEC, cache->rate_limit);

	/*
	 * Firmware may not advertise a rate limit; use a small bounded backoff
	 * instead of retrying in a tight loop.
	 */
	if (!delay_us)
		delay_us = SMCCC_CACHE_DEFAULT_DELAY_US;

	return min(delay_us, SMCCC_CACHE_MAX_DELAY_US);
}

static int smccc_cache_wbinv(struct cache_coherency_ops_inst *cci,
			     struct cc_inval_params *invp)
{
	struct smccc_cache *cache = container_of(cci, struct smccc_cache, cci);
	unsigned long delay_us = smccc_cache_delay_us(cache);
	struct arm_smccc_res res = {};
	int ret;

	if (!invp->size)
		return -EINVAL;

	/*
	 * Serialize the full retry sequence. With the default bounds, a caller
	 * may hold the mutex across up to five 20ms backoff sleeps.
	 */
	guard(mutex)(&cache->lock);

	for (unsigned int i = 0; i < SMCCC_CACHE_MAX_RETRIES; i++) {
		/* Long firmware operations can trigger watchdog checks. */
		touch_nmi_watchdog();

		arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_CLEAN_INV_MEMREGION,
				     invp->addr, invp->size, 0UL, &res);

		ret = smccc_cache_status_to_errno((s32)res.a0);
		if (!ret)
			return 0;

		if (ret != -EBUSY && ret != -EAGAIN)
			return ret;

		fsleep(delay_us);
	}

	return ret;
}

static const struct cache_coherency_ops smccc_cache_ops = {
	.wbinv = smccc_cache_wbinv,
};

static int smccc_cache_probe(struct arm_smccc_device *sdev)
{
	struct arm_smccc_res res = {};
	struct smccc_cache *cache;
	int ret;

	arm_smccc_1_1_invoke(ARM_SMCCC_ARCH_CLEAN_INV_MEMREGION_ATTRIBUTES,
			     &res);
	if ((s32)res.a0)
		return -ENODEV;

	cache = cache_coherency_ops_instance_alloc(&smccc_cache_ops,
						   struct smccc_cache, cci);
	if (!cache)
		return -ENOMEM;

	mutex_init(&cache->lock);
	cache->rate_limit = res.a3;

	ret = cache_coherency_ops_instance_register(&cache->cci);
	if (ret) {
		mutex_destroy(&cache->lock);
		cache_coherency_ops_instance_put(&cache->cci);
		return ret;
	}

	dev_set_drvdata(&sdev->dev, cache);

	return 0;
}

static void smccc_cache_remove(struct arm_smccc_device *sdev)
{
	struct smccc_cache *cache = dev_get_drvdata(&sdev->dev);

	/*
	 * Unregister takes the framework write lock, so it waits for any
	 * read-locked invalidation callback before the instance is freed.
	 */
	cache_coherency_ops_instance_unregister(&cache->cci);
	mutex_destroy(&cache->lock);
	cache_coherency_ops_instance_put(&cache->cci);
}

static const struct arm_smccc_device_id smccc_cache_id_table[] = {
	{ .func_id = ARM_SMCCC_ARCH_CLEAN_INV_MEMREGION_ATTRIBUTES },
	{}
};
MODULE_DEVICE_TABLE(arm_smccc, smccc_cache_id_table);

static struct arm_smccc_driver smccc_cache_driver = {
	.name = KBUILD_MODNAME,
	.probe = smccc_cache_probe,
	.remove = smccc_cache_remove,
	.id_table = smccc_cache_id_table,
};
module_arm_smccc_driver(smccc_cache_driver);

MODULE_IMPORT_NS("CACHE_COHERENCY");
MODULE_AUTHOR("Srirangan Madhavan");
MODULE_DESCRIPTION("Arm SMCCC cache maintenance provider");
MODULE_LICENSE("GPL");
