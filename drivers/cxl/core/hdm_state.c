// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 NVIDIA Corporation & Affiliates */
#include <linux/cleanup.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/list.h>
#include <linux/memregion.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/rwsem.h>
#include <linux/slab.h>

#include <cxl/hdm.h>
#include "cxl.h"
#include "core.h"

/*
 * CXL state that must stay available while no CXL driver is bound: the CXL
 * locks, the per-device HDM cache filled during PCI enumeration, and the
 * region quiesce used around a reset.
 */
struct cxl_rwsem cxl_rwsem = {
	.region = __RWSEM_INITIALIZER(cxl_rwsem.region),
	.dpa = __RWSEM_INITIALIZER(cxl_rwsem.dpa),
};
EXPORT_SYMBOL_FOR_MODULES(cxl_rwsem, "cxl_core");

void cxl_hdm_cache_set_dvsec_ctrl(struct pci_dev *pdev, u16 ctrl)
{
	guard(rwsem_write)(&cxl_rwsem.dpa);
	if (!pdev->hdm)
		return;

	pdev->hdm->dvsec_ctrl = ctrl;
	pdev->hdm->dvsec_ctrl_valid = true;
}
EXPORT_SYMBOL_FOR_MODULES(cxl_hdm_cache_set_dvsec_ctrl, "cxl_core");

void cxl_hdm_cache_refresh_decoder(struct pci_dev *pdev, void __iomem *hdm,
				   struct cxl_endpoint_decoder *cxled)
{
	struct cxl_endpoint_decoder_settings *settings;
	struct cxl_decoder *cxld = &cxled->cxld;
	struct cxl_hdm_info *info;
	u32 global_ctrl;
	int id;

	guard(rwsem_write)(&cxl_rwsem.dpa);
	id = cxld->config.id;
	info = pdev->hdm;
	if (!info)
		return;
	if (id < 0 || id >= info->decoder_count) {
		pci_warn(pdev, "CXL HDM decoder %d exceeds cached count %d\n",
			 id, info->decoder_count);
		return;
	}

	/* Preserve the last good value when the device does not respond. */
	global_ctrl = readl(hdm + CXL_HDM_DECODER_CTRL_OFFSET);
	if (global_ctrl != U32_MAX)
		info->global_ctrl = global_ctrl;
	settings = &info->settings[id];

	/*
	 * A disabled decoder's software object may retain its old range and
	 * skip state. Leave only the decoder id in the cached settings so stale
	 * state is not restored as an enabled decode.
	 */
	*settings = (struct cxl_endpoint_decoder_settings) {
		.config.id = id,
	};
	if (cxld->config.flags & CXL_DECODER_F_ENABLE) {
		settings->config = cxld->config;
		settings->skip = cxled->skip;
	}
}
EXPORT_SYMBOL_FOR_MODULES(cxl_hdm_cache_refresh_decoder, "cxl_core");

int cxl_hdm_cache_check_decoder_count(struct pci_dev *pdev, int count)
{
	guard(rwsem_read)(&cxl_rwsem.dpa);
	if (pdev->hdm && pdev->hdm->decoder_count != count) {
		pci_warn(pdev,
			 "CXL HDM cache decoder count mismatch: cached=%d hdm=%d\n",
			 pdev->hdm->decoder_count, count);
		return -ENXIO;
	}

	return 0;
}
EXPORT_SYMBOL_FOR_MODULES(cxl_hdm_cache_check_decoder_count, "cxl_core");

/**
 * cxl_hdm_cache_set_normalized() - record Normalized Addressing in the cache
 * @pdev: endpoint that owns the cache
 * @id: endpoint decoder id
 *
 * Normalized Addressing is determined during region discovery, after the
 * cache was filled, so the cached decoder lacks it. Record only that flag: the
 * decoder's software lock must not become a hardware Lock On Commit when the
 * cache is restored.
 */
void cxl_hdm_cache_set_normalized(struct pci_dev *pdev, int id)
{
	guard(rwsem_write)(&cxl_rwsem.dpa);
	if (!pdev->hdm || id < 0 || id >= pdev->hdm->decoder_count)
		return;

	pdev->hdm->settings[id].config.flags |=
		CXL_DECODER_F_NORMALIZED_ADDRESSING;
}
EXPORT_SYMBOL_FOR_MODULES(cxl_hdm_cache_set_normalized, "cxl_core");

/**
 * cxl_hdm_cache_release() - unpublish and free cached HDM state
 * @slot: cache pointer owned by the device
 *
 * Take the DPA write lock to exclude readers while clearing @slot, then
 * free the unpublished cache after releasing the lock.
 */
void cxl_hdm_cache_release(struct cxl_hdm_info **slot)
{
	struct cxl_hdm_info *info;

	scoped_guard(rwsem_write, &cxl_rwsem.dpa) {
		info = *slot;
		/* Unpublish before freeing so readers cannot see stale state. */
		*slot = NULL;
	}
	kfree(info);
}

/**
 * cxl_hdm_cache_dvsec_decode() - check for memory decoded by DVSEC ranges
 * @slot: cache pointer owned by the device
 *
 * Return: true if the published state shows CXL.mem enabled while HDM
 * decoders are globally disabled, so that the device decodes memory through
 * its DVSEC ranges, which the cache does not describe.
 */
bool cxl_hdm_cache_dvsec_decode(struct cxl_hdm_info *const *slot)
{
	struct cxl_hdm_info *info;

	guard(rwsem_read)(&cxl_rwsem.dpa);
	info = *slot;
	return info && (info->dvsec_ctrl & PCI_DVSEC_CXL_MEM_ENABLE) &&
	       !(info->global_ctrl & CXL_HDM_DECODER_ENABLE);
}

/**
 * cxl_hdm_cache_snapshot() - copy the published HDM state
 * @slot: cache pointer owned by the device
 *
 * Return: a copy the caller frees with kfree(), ERR_PTR(-ENXIO) when nothing
 * is published, or another ERR_PTR() on failure.
 */
struct cxl_hdm_info *cxl_hdm_cache_snapshot(struct cxl_hdm_info *const *slot)
{
	struct cxl_hdm_info *info, *copy;
	size_t size;

	guard(rwsem_read)(&cxl_rwsem.dpa);
	info = *slot;
	if (!info)
		return ERR_PTR(-ENXIO);
	if (info->decoder_count <= 0)
		return ERR_PTR(-EINVAL);

	size = struct_size(info, settings, info->decoder_count);
	if (size == SIZE_MAX)
		return ERR_PTR(-EOVERFLOW);

	copy = kmemdup(info, size, GFP_KERNEL);
	if (!copy)
		return ERR_PTR(-ENOMEM);

	return copy;
}

/**
 * cxl_hdm_cache_copy_decoders() - refresh the decoders of a snapshot
 * @slot: cache pointer owned by the device
 * @dst: snapshot of the same device from cxl_hdm_cache_snapshot()
 *
 * Copy only the per-decoder settings, which region commit and teardown keep
 * current. Leave the rest of @dst, including global and DVSEC control, as
 * captured: a refresh during a reset may have read those registers from a
 * device that returned all-ones.
 *
 * Return: 0 on success, -ENXIO when nothing is published, or -EINVAL when
 * @dst holds a different number of decoders.
 */
int cxl_hdm_cache_copy_decoders(struct cxl_hdm_info *const *slot,
				struct cxl_hdm_info *dst)
{
	struct cxl_hdm_info *info;

	lockdep_assert_held_write(&cxl_rwsem.region);
	guard(rwsem_read)(&cxl_rwsem.dpa);
	info = *slot;
	if (!info)
		return -ENXIO;
	if (info->decoder_count != dst->decoder_count)
		return -EINVAL;

	memcpy(dst->settings, info->settings,
	       flex_array_size(info, settings, info->decoder_count));
	return 0;
}

void cxl_region_quiesce_lock(void)
	__acquires(cxl_region_quiesce)
	__context_unsafe(token maps to cxl_rwsem.region)
{
	down_write(&cxl_rwsem.region);
	__acquire(cxl_region_quiesce);
}

void cxl_region_quiesce_unlock(void)
	__releases(cxl_region_quiesce)
	__context_unsafe(token maps to cxl_rwsem.region)
{
	__release(cxl_region_quiesce);
	up_write(&cxl_rwsem.region);
}

/*
 * Bound the range twice: request_mem_region() takes resource_size_t while
 * cpu_cache_invalidate_memregion() takes size_t, and the two differ on
 * 32-bit builds with CONFIG_PHYS_ADDR_T_64BIT. range_len() can also reach
 * RESOURCE_SIZE_MAX + 1 for a full-width range, and wraps to zero when
 * resource_size_t is 64-bit, which the !len test catches.
 */
static int cxl_hdm_range_validate(const struct range *hpa_range)
{
	u64 len = range_len(hpa_range);

	if (!len)
		return -EINVAL;
	if (hpa_range->end > RESOURCE_SIZE_MAX || len > RESOURCE_SIZE_MAX ||
	    len > SIZE_MAX)
		return -EOVERFLOW;

	return 0;
}

static int cxl_hdm_range_add(struct cxl_hdm_quiesce *q,
			     const struct range *hpa_range)
{
	struct cxl_hdm_range *range, *next, *new_range;
	int rc;

	rc = cxl_hdm_range_validate(hpa_range);
	if (rc)
		return rc;

	list_for_each_entry(range, &q->ranges, list)
		if (range_contains(&range->hpa_range, hpa_range))
			return 0;

	new_range = kzalloc_obj(*new_range);
	if (!new_range)
		return -ENOMEM;

	new_range->hpa_range = *hpa_range;
	new_range->len = range_len(hpa_range);

	list_for_each_entry_safe(range, next, &q->ranges, list) {
		if (range_contains(hpa_range, &range->hpa_range)) {
			list_del(&range->list);
			kfree(range);
		}
	}
	list_add_tail(&new_range->list, &q->ranges);

	return 0;
}

static int cxl_hdm_ranges_collect(struct cxl_hdm_quiesce *q,
				  const struct cxl_hdm_info *snapshot)
{
	int rc;

	for (int i = 0; i < snapshot->decoder_count; i++) {
		const struct cxl_decoder_config *config =
			&snapshot->settings[i].config;

		/* A committed zero-size decoder maps no HPA. */
		if (!(config->flags & CXL_DECODER_F_ENABLE) ||
		    !range_len(&config->hpa_range))
			continue;

		if (config->flags & CXL_DECODER_F_NORMALIZED_ADDRESSING)
			return -EOPNOTSUPP;

		rc = cxl_hdm_range_add(q, &config->hpa_range);
		if (rc)
			return rc;
	}

	return 0;
}

static int cxl_hdm_ranges_request(struct cxl_hdm_quiesce *q)
{
	struct cxl_hdm_range *range;

	lockdep_assert_held_write(&cxl_rwsem.region);

	list_for_each_entry(range, &q->ranges, list) {
		const struct range *hpa_range = &range->hpa_range;

		range->res = request_mem_region(hpa_range->start, range->len,
						"cxl_reset");
		if (!range->res)
			return -EBUSY;
	}

	return 0;
}

static int cxl_hdm_ranges_invalidate(struct cxl_hdm_quiesce *q)
{
	struct cxl_hdm_range *range;
	int rc = 0;

	lockdep_assert_held_write(&cxl_rwsem.region);

	if (!cpu_cache_has_invalidate_memregion() &&
	    IS_ENABLED(CONFIG_CXL_REGION_INVALIDATION_TEST)) {
		pr_info_once("CXL reset: bypassing CPU cache invalidation for testing\n");
		return 0;
	}

	list_for_each_entry(range, &q->ranges, list) {
		const struct range *hpa_range = &range->hpa_range;
		int rc2;

		rc2 = cpu_cache_invalidate_memregion(hpa_range->start,
						     range->len);
		rc = rc ?: rc2;
	}

	return rc;
}

/**
 * cxl_hdm_quiesce_prepare() - take the HPA ranges of a device out of use
 * @q: quiesce state to initialize
 * @snapshot: HDM state from cxl_hdm_cache_snapshot()
 *
 * Reserve every enabled system-physical range in @snapshot exclusively, then
 * write back and invalidate CPU caches for them. Call
 * cxl_hdm_quiesce_destroy() afterwards whether or not this succeeds.
 *
 * Return: 0 on success, or a negative errno.
 */
int cxl_hdm_quiesce_prepare(struct cxl_hdm_quiesce *q,
			    const struct cxl_hdm_info *snapshot)
{
	int rc;

	lockdep_assert_held_write(&cxl_rwsem.region);
	INIT_LIST_HEAD(&q->ranges);

	if (!cpu_cache_has_invalidate_memregion() &&
	    !IS_ENABLED(CONFIG_CXL_REGION_INVALIDATION_TEST))
		return -ENXIO;

	rc = cxl_hdm_ranges_collect(q, snapshot);
	if (rc)
		return rc;

	rc = cxl_hdm_ranges_request(q);
	if (rc)
		return rc;

	return cxl_hdm_ranges_invalidate(q);
}

/* Evict lines fetched during reset before DMA exclusion ends. */
int cxl_hdm_quiesce_flush(struct cxl_hdm_quiesce *q)
{
	return cxl_hdm_ranges_invalidate(q);
}

void cxl_hdm_quiesce_destroy(struct cxl_hdm_quiesce *q)
{
	struct cxl_hdm_range *range, *next;

	list_for_each_entry_safe(range, next, &q->ranges, list) {
		list_del(&range->list);
		if (range->res)
			release_mem_region(range->hpa_range.start,
					   resource_size(range->res));
		kfree(range);
	}
}
