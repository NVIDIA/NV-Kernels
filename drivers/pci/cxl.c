// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 NVIDIA Corporation & Affiliates */
/*
 * CXL reset support in the PCI core. Cache the HDM decoder state of a CXL
 * memory device at enumeration, so it can be restored after a reset without
 * a CXL driver, and implement CXL Device Reset. HDM register formats and
 * programming live in drivers/cxl.
 */
#include <linux/bitfield.h>
#include <linux/cleanup.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/iommu.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/memregion.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include <cxl/hdm.h>
#include <cxl/pci.h>

#include "pci.h"

struct cxl_pci_cache {
	struct cxl_hdm_quiesce quiesce;
	u16 saved_ctrl2;
	/* A cache-policy write was attempted and may need undoing. */
	bool cache_disabled;
};

/* Find the CXL Device DVSEC and read its capability register. */
static int cxl_pci_device_dvsec(struct pci_dev *pdev, u16 *dvsec, u16 *cap)
{
	int rc;

	*dvsec = pci_find_dvsec_capability(pdev, PCI_VENDOR_ID_CXL,
					   PCI_DVSEC_CXL_DEVICE);
	if (!*dvsec)
		return -ENOTTY;

	rc = pci_read_config_word(pdev, *dvsec + PCI_DVSEC_CXL_CAP, cap);
	if (rc)
		return pcibios_err_to_errno(rc);
	if (PCI_POSSIBLE_ERROR(*cap))
		return -ENODEV;

	return 0;
}

static bool cxl_pci_bar_assigned(struct pci_dev *pdev, int bar)
{
	struct resource *res = &pdev->resource[bar];

	return pci_resource_len(pdev, bar) &&
	       !(res->flags & (IORESOURCE_UNSET | IORESOURCE_DISABLED)) &&
	       resource_type(res) == IORESOURCE_MEM && res->start && res->end;
}

static void __iomem *cxl_pci_hdm_map_regs(struct pci_dev *pdev,
					  struct cxl_register_map *map,
					  resource_size_t *hdm_offset,
					  int *decoder_count)
{
	struct cxl_reg_map *hdm_map = &map->component_map.hdm_decoder;
	void __iomem *hdm;
	int rc;

	/* cxl_setup_regs() populates hdm_map, including its valid bit. */
	rc = cxl_setup_regs(map);
	if (rc)
		return ERR_PTR(rc);
	if (!hdm_map->valid)
		return ERR_PTR(-ENODEV);
	if (hdm_map->offset > map->max_size ||
	    hdm_map->size > map->max_size - hdm_map->offset)
		return ERR_PTR(-ENXIO);
	if (check_add_overflow(map->bar_offset,
			       (resource_size_t)hdm_map->offset, hdm_offset))
		return ERR_PTR(-EOVERFLOW);

	hdm = ioremap(map->resource + hdm_map->offset, hdm_map->size);
	if (!hdm)
		return ERR_PTR(-ENOMEM);

	*decoder_count = cxl_hdm_decoder_count_mapped(&pdev->dev, hdm,
						      hdm_map->size);
	if (*decoder_count < 0) {
		iounmap(hdm);
		return ERR_PTR(*decoder_count);
	}

	return hdm;
}

static struct cxl_hdm_info *__cxl_pci_hdm_read_info(struct pci_dev *pdev,
						    struct cxl_register_map *map,
						    int dvsec)
{
	struct cxl_reg_map *hdm_map = &map->component_map.hdm_decoder;
	struct cxl_hdm_info *info;
	resource_size_t hdm_offset;
	void __iomem *hdm;
	int decoder_count;
	u16 dvsec_ctrl;
	int rc;

	hdm = cxl_pci_hdm_map_regs(pdev, map, &hdm_offset, &decoder_count);
	if (IS_ERR(hdm))
		return ERR_CAST(hdm);

	rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CTRL,
				  &dvsec_ctrl);
	if (rc) {
		rc = pcibios_err_to_errno(rc);
		goto out_unmap;
	}

	info = kzalloc_flex(*info, settings, decoder_count, GFP_KERNEL);
	if (!info) {
		rc = -ENOMEM;
		goto out_unmap;
	}

	info->decoder_count = decoder_count;
	info->hdm_bar = map->bar;
	info->hdm_offset = hdm_offset;
	info->hdm_size = hdm_map->size;
	info->dvsec = dvsec;
	info->dvsec_ctrl = dvsec_ctrl;
	info->dvsec_ctrl_valid = true;

	rc = cxl_hdm_read_state(&pdev->dev, hdm, info);
	if (rc)
		goto out_free;

	iounmap(hdm);
	return info;

out_free:
	kfree(info);
out_unmap:
	iounmap(hdm);
	return ERR_PTR(rc);
}

static struct cxl_hdm_info *cxl_pci_hdm_read_info(struct pci_dev *pdev,
						  struct cxl_register_map *map,
						  int dvsec)
{
	struct cxl_hdm_info *info;
	u16 command;
	int rc;

	rc = pci_read_config_word(pdev, PCI_COMMAND, &command);
	if (rc)
		return ERR_PTR(pcibios_err_to_errno(rc));

	if (!(command & PCI_COMMAND_MEMORY)) {
		rc = pci_write_config_word(pdev, PCI_COMMAND,
					   command | PCI_COMMAND_MEMORY);
		if (rc)
			return ERR_PTR(pcibios_err_to_errno(rc));
	}

	info = __cxl_pci_hdm_read_info(pdev, map, dvsec);
	if (!(command & PCI_COMMAND_MEMORY)) {
		rc = pci_write_config_word(pdev, PCI_COMMAND, command);
		if (rc)
			pci_err(pdev,
				"failed to restore PCI_COMMAND after CXL HDM cache init: %d\n",
				pcibios_err_to_errno(rc));
	}
	return info;
}

static int __pci_cxl_hdm_cache_init(struct pci_dev *pdev)
{
	struct cxl_register_map map = { };
	struct cxl_hdm_info *read_info;
	u16 dvsec, cap;
	int rc;

	guard(pci_dev)(pdev);

	/* Avoid duplicate MMIO reads when the cache is already present. */
	if (pdev->hdm)
		return 0;

	rc = cxl_pci_device_dvsec(pdev, &dvsec, &cap);
	if (rc == -ENOTTY)
		return 0;
	if (rc)
		return rc;
	if (!(cap & PCI_DVSEC_CXL_CACHE_CAPABLE) ||
	    !(cap & PCI_DVSEC_CXL_MEM_CAPABLE) ||
	    !(cap & PCI_DVSEC_CXL_RST_CAPABLE) ||
	    !(cap & PCI_DVSEC_CXL_RST_MEM_CLR_CAPABLE) ||
	    !cxl_dvsec_hdm_count_valid(FIELD_GET(PCI_DVSEC_CXL_HDM_COUNT, cap)))
		return 0;

	rc = cxl_find_regblock(pdev, CXL_REGLOC_RBI_COMPONENT, &map);
	if (rc)
		return rc;
	if (map.bar < 0 || map.bar >= PCI_STD_NUM_BARS ||
	    !cxl_pci_bar_assigned(pdev, map.bar))
		return -ENODEV;

	read_info = cxl_pci_hdm_read_info(pdev, &map, dvsec);
	if (IS_ERR(read_info))
		return PTR_ERR(read_info);

	/*
	 * The PCI device lock held since the cache check excludes other
	 * initializers. CXL drivers bind only after enumeration, so no cache
	 * mutator can run yet and cxl_rwsem.dpa is not needed to publish.
	 */
	pdev->hdm = read_info;

	return 0;
}

void pci_cxl_hdm_cache_init(struct pci_dev *pdev)
{
	int rc;

	rc = __pci_cxl_hdm_cache_init(pdev);
	if (rc)
		pci_dbg(pdev, "CXL HDM cache init failed: %d\n", rc);
}

void pci_cxl_hdm_cache_release(struct pci_dev *pdev)
{
	cxl_hdm_cache_release(&pdev->hdm);
}

/*
 * CXL r4.0 sec 9.7.2 defines the reset completion timeout encodings.
 * Sec 9.7.3 leaves config-space access behavior undefined for 100 ms after
 * initiating CXL Reset, then limits software to CXL Status2 access until
 * reset completion, timeout, or error. Wait for the full advertised timeout
 * so that Control2 is not accessed while the device may still be resetting.
 */
#define CXL_RESET_RRS_WAIT_MS 100
#define CXL_RESET_STATUS_POLL_MS 20
static const u32 cxl_reset_timeout_ms[] = {
	10, 100, 1000, 10000, 100000,
};

/*
 * CXL 4.0 section 9.6 permits using the device cache size to determine
 * a timeout. Use a conservative fixed estimate of 100 ms.
 */
#define CXL_CACHE_WBI_TIMEOUT_US 100000
#define CXL_CACHE_WBI_POLL_US 100

#define CXL_RESET_CTRL2_CMD_MASK \
	(PCI_DVSEC_CXL_INIT_CACHE_WBI | PCI_DVSEC_CXL_INIT_CXL_RST)

static int cxl_reset_update_ctrl2(struct pci_dev *pdev, int dvsec,
				  u16 set, u16 clear)
{
	u16 ctrl2;
	int rc;

	rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CTRL2, &ctrl2);
	if (rc)
		return pcibios_err_to_errno(rc);
	if (PCI_POSSIBLE_ERROR(ctrl2))
		return -ENODEV;

	/*
	 * INIT_CACHE_WBI and INIT_CXL_RST are commands. Do not replay a command
	 * that remains set in the value read back while updating persistent
	 * Control2 state.
	 */
	ctrl2 &= ~CXL_RESET_CTRL2_CMD_MASK;
	ctrl2 &= ~clear;
	ctrl2 |= set;

	rc = pci_write_config_word(pdev, dvsec + PCI_DVSEC_CXL_CTRL2, ctrl2);
	if (rc)
		return pcibios_err_to_errno(rc);

	return 0;
}

static int cxl_reset_wait_cache_wbi(struct pci_dev *pdev, int dvsec)
{
	unsigned long deadline;
	u16 status2;
	int rc;

	rc = cxl_reset_update_ctrl2(pdev, dvsec,
				    PCI_DVSEC_CXL_INIT_CACHE_WBI, 0);
	if (rc)
		return rc;

	deadline = jiffies + usecs_to_jiffies(CXL_CACHE_WBI_TIMEOUT_US);
	while (time_before(jiffies, deadline)) {
		usleep_range(CXL_CACHE_WBI_POLL_US,
			     CXL_CACHE_WBI_POLL_US * 2);

		rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_STATUS2,
					  &status2);
		if (rc)
			return pcibios_err_to_errno(rc);
		if (PCI_POSSIBLE_ERROR(status2))
			return -ENODEV;
		if (status2 & PCI_DVSEC_CXL_CACHE_INV)
			return 0;
	}

	pci_warn(pdev, "timed out waiting for CXL cache writeback and invalidate\n");
	return -ETIMEDOUT;
}

static int cxl_reset_disable_cache(struct pci_dev *pdev, int dvsec, u16 cap)
{
	int rc;

	rc = cxl_reset_update_ctrl2(pdev, dvsec,
				    PCI_DVSEC_CXL_DISABLE_CACHING, 0);
	if (rc || !(cap & PCI_DVSEC_CXL_CACHE_WBI_CAPABLE))
		return rc;

	return cxl_reset_wait_cache_wbi(pdev, dvsec);
}

static int cxl_reset_restore_cache_policy(struct pci_dev *pdev, int dvsec,
					  u16 saved_ctrl2)
{
	int rc;

	rc = cxl_reset_update_ctrl2(pdev, dvsec,
				    saved_ctrl2 & PCI_DVSEC_CXL_DISABLE_CACHING,
				    PCI_DVSEC_CXL_DISABLE_CACHING);
	if (rc)
		pci_err(pdev, "failed to restore CXL cache policy: %d\n", rc);

	return rc;
}

/* Shared range reservation, host invalidation, and device cache writeback. */
static int cxl_reset_cache_prepare(struct pci_dev *pdev, int dvsec, u16 cap,
				   const struct cxl_hdm_info *snapshot,
				   struct cxl_pci_cache *cache)
	__must_hold(cxl_region_quiesce)
{
	int rc;

	rc = cxl_hdm_quiesce_prepare(&cache->quiesce, snapshot);
	if (rc)
		return rc;

	/* Track an attempted change so partial failures still restore policy. */
	cache->cache_disabled = true;
	return cxl_reset_disable_cache(pdev, dvsec, cap);
}

static int cxl_reset_wait_done(struct pci_dev *pdev, int dvsec, u16 cap)
{
	unsigned long deadline;
	u32 timeout_ms;
	u16 status2;
	int idx, rc;

	idx = FIELD_GET(PCI_DVSEC_CXL_RST_TIMEOUT, cap);
	if (idx >= ARRAY_SIZE(cxl_reset_timeout_ms)) {
		idx = ARRAY_SIZE(cxl_reset_timeout_ms) - 1;
		pci_warn(pdev,
			 "unknown CXL reset timeout encoding; using %u ms\n",
			 cxl_reset_timeout_ms[idx]);
	}

	/* Allow one retry after the mandatory 100 ms quiet period. */
	timeout_ms = max_t(u32, cxl_reset_timeout_ms[idx],
			   CXL_RESET_RRS_WAIT_MS + CXL_RESET_STATUS_POLL_MS);
	pci_info(pdev, "CXL reset timeout: %u ms\n", timeout_ms);
	msleep(CXL_RESET_RRS_WAIT_MS);
	deadline = jiffies + msecs_to_jiffies(timeout_ms -
					      CXL_RESET_RRS_WAIT_MS);

	for (;;) {
		rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_STATUS2,
					  &status2);
		if (rc)
			return pcibios_err_to_errno(rc);
		if (status2 != U16_MAX) {
			if (status2 & PCI_DVSEC_CXL_RST_ERR)
				return -EIO;
			if (status2 & PCI_DVSEC_CXL_RST_DONE)
				return 0;
		}

		if (time_after_eq(jiffies, deadline))
			return -ETIMEDOUT;

		msleep(CXL_RESET_STATUS_POLL_MS);
	}
}

static int cxl_clear_memory(struct pci_dev *pdev, int dvsec, bool initiate)
{
	if (initiate)
		return cxl_reset_update_ctrl2(pdev, dvsec,
					      PCI_DVSEC_CXL_INIT_CXL_RST |
					      PCI_DVSEC_CXL_RST_MEM_CLR_EN,
					      0);

	return cxl_reset_update_ctrl2(pdev, dvsec, 0,
				      PCI_DVSEC_CXL_RST_MEM_CLR_EN);
}

static int __cxl_reset_execute(struct pci_dev *pdev, int dvsec, u16 cap,
			      struct cxl_hdm_quiesce *q)
	__must_hold(cxl_region_quiesce)
{
	int rc, rc2;

	if (!pci_wait_for_pending_transaction(pdev)) {
		pci_err(pdev, "timed out waiting for pending transactions\n");
		return -ETIMEDOUT;
	}

	rc = pci_dev_reset_iommu_prepare(pdev);
	if (rc) {
		pci_err(pdev, "failed to stop IOMMU for CXL reset: %d\n", rc);
		return rc;
	}

	rc = cxl_clear_memory(pdev, dvsec, true);
	if (!rc)
		rc = cxl_reset_wait_done(pdev, dvsec, cap);

	/* Always clear Memory Clear; successful cleanup must not hide reset failure. */
	rc2 = cxl_clear_memory(pdev, dvsec, false);
	if (rc2)
		pci_err(pdev, "failed to clear CXL Reset Memory Clear: %d\n", rc2);
	rc = rc ?: rc2;

	rc2 = cxl_hdm_quiesce_flush(q);
	if (rc2)
		pci_err(pdev, "failed to invalidate CPU cache after CXL reset: %d\n", rc2);
	rc = rc ?: rc2;

	pci_dev_reset_iommu_done(pdev);
	return rc;
}

static int cxl_reset_quiesced(struct pci_dev *pdev, int dvsec, u16 cap)
	__must_hold(cxl_region_quiesce)
{
	struct cxl_hdm_info *snapshot __free(kfree) = NULL;
	struct cxl_pci_cache cache = {};
	int rc, rc2;

	rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CTRL2,
				  &cache.saved_ctrl2);
	if (rc)
		return pcibios_err_to_errno(rc);
	if (PCI_POSSIBLE_ERROR(cache.saved_ctrl2))
		return -ENODEV;

	snapshot = cxl_hdm_cache_snapshot(&pdev->hdm);
	if (IS_ERR(snapshot)) {
		pci_err(pdev, "CXL HDM decoder state unavailable: %ld\n",
			PTR_ERR(snapshot));
		return PTR_ERR(snapshot);
	}

	rc = cxl_reset_cache_prepare(pdev, dvsec, cap, snapshot, &cache);
	if (rc && !cache.cache_disabled) {
		pci_err(pdev, "failed to prepare CXL reset ranges: %d\n", rc);
		cxl_hdm_quiesce_destroy(&cache.quiesce);
		return rc;
	}
	if (!rc)
		rc = __cxl_reset_execute(pdev, dvsec, cap, &cache.quiesce);
	/* Restore cache policy after any attempt to disable caching. */
	rc2 = cxl_reset_restore_cache_policy(pdev, dvsec, cache.saved_ctrl2);
	cxl_hdm_quiesce_destroy(&cache.quiesce);
	return rc ?: rc2;
}

static int cxl_reset_execute(struct pci_dev *pdev, int dvsec, u16 cap)
{
	int rc;

	cxl_region_quiesce_lock();
	rc = cxl_reset_quiesced(pdev, dvsec, cap);
	cxl_region_quiesce_unlock();

	return rc;
}

int cxl_reset_function(struct pci_dev *pdev, bool probe)
{
	u16 dvsec, cap, ctrl;
	int rc;

	rc = cxl_pci_device_dvsec(pdev, &dvsec, &cap);
	if (rc)
		return rc;
	if (!(cap & PCI_DVSEC_CXL_CACHE_CAPABLE) ||
	    !(cap & PCI_DVSEC_CXL_MEM_CAPABLE) ||
	    !(cap & PCI_DVSEC_CXL_RST_CAPABLE) ||
	    !(cap & PCI_DVSEC_CXL_RST_MEM_CLR_CAPABLE))
		return -ENOTTY;

	rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CTRL, &ctrl);
	if (rc)
		return pcibios_err_to_errno(rc);
	if (PCI_POSSIBLE_ERROR(ctrl))
		return -ENODEV;
	if (!(ctrl & PCI_DVSEC_CXL_CACHE_ENABLE) ||
	    !(ctrl & PCI_DVSEC_CXL_MEM_ENABLE))
		return -ENOTTY;

	if (probe)
		return 0;

	/* The cache is owned by @pdev and does not require a bound CXL driver. */
	if (!pdev->hdm)
		return -ENOTTY;

	/* Memory decoded through DVSEC ranges has no HPA ranges to quiesce. */
	if (cxl_hdm_cache_dvsec_decode(&pdev->hdm))
		return -ENOTTY;

	if (!cpu_cache_has_invalidate_memregion() &&
	    !IS_ENABLED(CONFIG_CXL_REGION_INVALIDATION_TEST))
		return -ENOTTY;

	return cxl_reset_execute(pdev, dvsec, cap);
}
