// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 NVIDIA Corporation & Affiliates */
/*
 * CXL reset support in the PCI core: cache the HDM decoder state of a CXL
 * memory device at enumeration, implement CXL Device Reset, and restore the
 * cached state afterwards without a CXL driver. HDM register formats and
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
#include <linux/overflow.h>
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

static void __iomem *cxl_pci_hdm_ioremap_current(struct pci_dev *pdev,
						 int bar,
						 resource_size_t offset,
						 resource_size_t size)
{
	struct resource *res;
	resource_size_t hdm_start;
	void __iomem *hdm;

	if (bar < 0 || bar >= PCI_STD_NUM_BARS || !size)
		return IOMEM_ERR_PTR(-EINVAL);
	if (!cxl_pci_bar_assigned(pdev, bar))
		return IOMEM_ERR_PTR(-ENODEV);

	res = &pdev->resource[bar];
	if (offset > resource_size(res) || size > resource_size(res) - offset)
		return IOMEM_ERR_PTR(-ENODEV);
	if (check_add_overflow(res->start, offset, &hdm_start))
		return IOMEM_ERR_PTR(-EOVERFLOW);

	hdm = ioremap(hdm_start, size);
	if (!hdm) {
		pci_err(pdev, "failed to remap CXL HDM decoder registers\n");
		return IOMEM_ERR_PTR(-ENOMEM);
	}

	return hdm;
}

static void cxl_restore_pci_state_for_hdm_restore(struct pci_dev *pdev,
						  u16 *command)
{
	u32 saved_config = pdev->saved_config_space[PCI_COMMAND / 4];
	u32 restore_config;

	device_lock_assert(&pdev->dev);
	*command = saved_config & 0xffff;

	/*
	 * Restore BARs and the related PCI state needed to reach HDM MMIO.
	 * Temporarily alter the saved command value so that
	 * pci_restore_state() enables MSE but cannot enable BME or INTx before
	 * CXL state restoration completes. Preserve the original saved value
	 * for the outer PCI reset path.
	 */
	restore_config = saved_config | PCI_COMMAND_MEMORY |
			 PCI_COMMAND_INTX_DISABLE;
	restore_config &= ~PCI_COMMAND_MASTER;

	pdev->saved_config_space[PCI_COMMAND / 4] = restore_config;
	pci_restore_state(pdev);
	pdev->saved_config_space[PCI_COMMAND / 4] = saved_config;
}

static int cxl_restore_dvsec_ctrl(struct pci_dev *pdev,
				  const struct cxl_hdm_info *snapshot)
{
	int rc;

	if (!snapshot->dvsec_ctrl_valid) {
		pci_err(pdev, "CXL DVSEC control snapshot is invalid\n");
		return -ENXIO;
	}

	rc = pci_write_config_word(pdev, snapshot->dvsec + PCI_DVSEC_CXL_CTRL,
				   snapshot->dvsec_ctrl);
	if (rc) {
		rc = pcibios_err_to_errno(rc);
		pci_err(pdev, "failed to restore CXL DVSEC control: %d\n", rc);
	}

	return rc;
}

static int cxl_restore_state(struct pci_dev *pdev,
			     const struct cxl_hdm_info *snapshot)
{
	void __iomem *hdm;
	int rc;

	hdm = cxl_pci_hdm_ioremap_current(pdev, snapshot->hdm_bar,
					  snapshot->hdm_offset,
					  snapshot->hdm_size);
	if (IS_ERR(hdm)) {
		pci_err(pdev, "failed to map CXL HDM state for restore: %ld\n",
			PTR_ERR(hdm));
		return PTR_ERR(hdm);
	}

	rc = cxl_hdm_restore_state(hdm, snapshot);
	iounmap(hdm);
	if (rc) {
		pci_err(pdev, "failed to restore CXL HDM state: %d\n", rc);
		return rc;
	}

	return cxl_restore_dvsec_ctrl(pdev, snapshot);
}

static void cxl_reset_save_disabled_state(struct pci_dev *pdev)
{
	u32 *saved_command = &pdev->saved_config_space[PCI_COMMAND / 4];
	int rc;

	rc = pci_write_config_word(pdev, PCI_COMMAND, PCI_COMMAND_INTX_DISABLE);
	if (rc)
		pci_err(pdev,
			"failed to disable device after CXL reset failure: %d\n",
			pcibios_err_to_errno(rc));

	/* Preserve the pre-reset snapshot if PCI state has not been restored. */
	if (!pdev->state_saved) {
		rc = pci_save_state(pdev);
		if (rc)
			pci_err(pdev,
				"failed to save disabled state after CXL reset failure: %d\n",
				rc);
	}

	/* Ensure the outer PCI restore cannot re-enable MSE or BME. */
	*saved_command &= GENMASK(31, 16);
	*saved_command |= PCI_COMMAND_INTX_DISABLE;
}

static int cxl_reset_save_restored_state(struct pci_dev *pdev, u16 command)
{
	int rc;

	rc = pci_write_config_word(pdev, PCI_COMMAND, command);
	if (rc) {
		rc = pcibios_err_to_errno(rc);
		pci_err(pdev, "failed to restore PCI command state: %d\n", rc);
		cxl_reset_save_disabled_state(pdev);
		return rc;
	}

	rc = pci_save_state(pdev);
	if (rc) {
		pci_err(pdev, "failed to save restored state after CXL reset: %d\n",
			rc);
		cxl_reset_save_disabled_state(pdev);
	}

	return rc;
}

/* Caller holds the region lock and keeps device traffic isolated. */
static int pci_cxl_restore_state(struct pci_dev *pdev,
			  const struct cxl_hdm_info *snapshot, u16 *command)
	__must_hold(cxl_region_quiesce)
{
	device_lock_assert(&pdev->dev);
	cxl_restore_pci_state_for_hdm_restore(pdev, command);
	return cxl_restore_state(pdev, snapshot);
}

static int cxl_reset_restore_cache_policy(struct pci_dev *pdev, int dvsec,
					  u16 saved_ctrl2);
static int cxl_reset_cache_prepare(struct pci_dev *pdev, int dvsec, u16 cap,
				   const struct cxl_hdm_info *snapshot,
				   struct cxl_pci_cache *cache,
				   const struct resource *owned);

/**
 * pci_cxl_hdm_snapshot() - copy the HDM state cached at enumeration
 * @pdev: CXL device
 *
 * The cache is read under cxl_rwsem.dpa, so the caller needs no device
 * lock. A driver can call this from probe, which the PCI core may run in a
 * worker on the device's NUMA node while the binding task holds the lock.
 *
 * Return: a copy to free with kfree(); NULL when @pdev has no cached HDM
 * state; or an ERR_PTR() on failure.
 */
struct cxl_hdm_info *pci_cxl_hdm_snapshot(struct pci_dev *pdev)
{
	struct cxl_hdm_info *snapshot;

	snapshot = cxl_hdm_cache_snapshot(&pdev->hdm);
	if (IS_ERR(snapshot) && PTR_ERR(snapshot) == -ENXIO)
		return NULL;

	return snapshot;
}
EXPORT_SYMBOL_FOR_MODULES(pci_cxl_hdm_snapshot, "vfio-cxl");

/**
 * pci_cxl_reset_prepare() - allocate HDM state storage ahead of a bus reset
 * @pdev: device about to be reset
 * @cachep: receives cache state owning the region quiesce on success
 *
 * Capture HDM state under the region quiesce, reserve its ranges, and complete
 * host and device cache maintenance. Hold the quiesce through reset and
 * cxl_restore_state_after_pci_reset(), which consumes *@cachep.
 *
 * Return: snapshot to be freed with kfree(), NULL when no cached HDM state is
 * present, or an ERR_PTR() on failure. A cached device without a valid DVSEC
 * snapshot is rejected because its cache-maintenance scope is unknown.
 * Only a successful non-NULL snapshot returns with the region quiesce held
 * and *@cachep set. The caller must pass both to
 * cxl_restore_state_after_pci_reset() even if reset is never attempted.
 * The snapshot remains caller-owned. All other returns leave the quiesce
 * unheld and *@cachep NULL.
 */
struct cxl_hdm_info *pci_cxl_reset_prepare(struct pci_dev *pdev,
					struct cxl_pci_cache **cachep)
{
	struct cxl_hdm_info *snapshot;
	struct cxl_pci_cache *cache;
	u16 dvsec, cap, command;
	int rc;

	device_lock_assert(&pdev->dev);
	*cachep = NULL;
	if (!pdev->hdm)
		return NULL;

	rc = cxl_pci_device_dvsec(pdev, &dvsec, &cap);
	if (rc == -ENOTTY)
		return ERR_PTR(-ENODEV);
	if (rc)
		return ERR_PTR(rc);
	/* Raw reset callers may not have saved the PCI state needed for restore. */
	if (!pdev->state_saved) {
		pci_err(pdev, "CXL bus reset requires saved PCI state\n");
		return ERR_PTR(-EINVAL);
	}

	cache = kzalloc_obj(*cache);
	if (!cache)
		return ERR_PTR(-ENOMEM);
	cxl_region_quiesce_lock();
	snapshot = cxl_hdm_cache_snapshot(&pdev->hdm);
	if (IS_ERR(snapshot)) {
		rc = PTR_ERR(snapshot);
		goto unlock;
	}
	if (!snapshot->dvsec_ctrl_valid) {
		rc = -ENXIO;
		goto free_snapshot;
	}
	if (cxl_hdm_cache_dvsec_decode(&pdev->hdm) ||
	    (snapshot->dvsec_ctrl & PCI_DVSEC_CXL_CACHE_ENABLE &&
	     !(cap & PCI_DVSEC_CXL_CACHE_WBI_CAPABLE))) {
		rc = -EOPNOTSUPP;
		goto free_snapshot;
	}

	if (cap & PCI_DVSEC_CXL_CACHE_CAPABLE) {
		rc = pci_read_config_word(pdev, dvsec + PCI_DVSEC_CXL_CTRL2,
					  &cache->saved_ctrl2);
		if (rc || PCI_POSSIBLE_ERROR(cache->saved_ctrl2)) {
			rc = rc ? pcibios_err_to_errno(rc) : -ENODEV;
			goto free_snapshot;
		}
	}

	rc = cxl_reset_cache_prepare(pdev, dvsec, cap, snapshot, cache, NULL);
	if (rc) {
		if (cache->cache_disabled)
			goto finish;
		pci_err(pdev, "failed to prepare CXL bus reset ranges: %d\n", rc);
		cxl_hdm_quiesce_destroy(&cache->quiesce);
		goto free_snapshot;
	}
	if (!pci_wait_for_pending_transaction(pdev)) {
		rc = -ETIMEDOUT;
		goto finish;
	}
	*cachep = cache;
	return snapshot;

finish:
	rc = cxl_restore_state_after_pci_reset(pdev, snapshot, cache, false, rc,
					       &command);
	kfree(snapshot);
	return ERR_PTR(rc);
free_snapshot:
	kfree(snapshot);
unlock:
	cxl_region_quiesce_unlock();
	kfree(cache);
	return ERR_PTR(rc);
}

/**
 * cxl_restore_state_after_pci_reset() - finish a prepared reset and release its quiesce
 * @pdev: device that was reset
 * @snapshot: storage from pci_cxl_reset_prepare()
 * @cache: quiesce state from pci_cxl_reset_prepare()
 * @reset_attempted: reset helper was invoked and may have affected hardware
 * @rc: preparation or PCI reset result
 * @command: returns the saved PCI_COMMAND value to apply once the IOMMU is
 *	     restored
 *
 * Restore state through pci_cxl_restore_state(), complete host invalidation,
 * and restore the cache policy changed by planned-reset preparation. When
 * @reset_attempted is false, undo preparation without changing the saved PCI
 * command, unless cleanup itself fails. After an attempted reset, keep caching
 * and the device disabled if state restoration or host invalidation fails.
 * A reset-helper error does not prove that hardware was untouched.
 * Unplanned recovery uses pci_cxl_restore_state() directly and owns its own
 * quiesce and cache-maintenance sequencing.
 *
 * Bus mastering stays off, because the caller has not yet restored IOMMU
 * translation and a DMA request now would hit the blocking domain. The caller
 * calls cxl_restore_command_after_pci_reset() once the IOMMU is restored.
 *
 * The quiesce blocks region commit and teardown throughout reset. Complete
 * host cache invalidation before PCI operation resumes, then release the
 * quiesce and free @cache on every exit. @snapshot remains caller-owned.
 */
int cxl_restore_state_after_pci_reset(struct pci_dev *pdev,
				      const struct cxl_hdm_info *snapshot,
				      struct cxl_pci_cache *cache,
				      bool reset_attempted, int rc, u16 *command)
{
	int rc2, policy_rc = 0;

	*command = 0;
	if (!cache)
		return rc;
	device_lock_assert(&pdev->dev);
	if (reset_attempted && !rc)
		rc = pci_cxl_restore_state(pdev, snapshot, command);

	/* Complete host invalidation before ending IOMMU exclusion. */
	rc2 = cxl_hdm_quiesce_flush(&cache->quiesce);
	if (rc2)
		pci_err(pdev, "failed to invalidate CPU cache after CXL bus reset: %d\n", rc2);
	/* Undo preparation on abort; enable caching after reset only if safe. */
	if (cache->cache_disabled && (!reset_attempted || (!rc && !rc2)))
		policy_rc = cxl_reset_restore_cache_policy(pdev, snapshot->dvsec,
							  cache->saved_ctrl2);
	if (reset_attempted) {
		rc = rc ?: rc2 ?: policy_rc;
		if (rc)
			cxl_reset_save_disabled_state(pdev);
	} else {
		/* An aborted reset alone must not poison the saved PCI command. */
		if (rc2 || policy_rc)
			cxl_reset_save_disabled_state(pdev);
		rc = rc ?: rc2 ?: policy_rc;
	}

	cxl_hdm_quiesce_destroy(&cache->quiesce);
	cxl_region_quiesce_unlock();
	kfree(cache);
	return rc;
}
EXPORT_SYMBOL_FOR_MODULES(cxl_restore_state_after_pci_reset, "vfio-cxl");

/**
 * cxl_restore_command_after_pci_reset() - re-enable the device after a bus reset
 * @pdev: device that was reset
 * @command: PCI_COMMAND value from cxl_restore_state_after_pci_reset()
 *
 * Call after the IOMMU is restored: this can enable bus mastering. Save the
 * restored PCI state, and leave @pdev disabled on failure.
 */
int cxl_restore_command_after_pci_reset(struct pci_dev *pdev, u16 command)
{
	device_lock_assert(&pdev->dev);
	return cxl_reset_save_restored_state(pdev, command);
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
				   struct cxl_pci_cache *cache,
				   const struct resource *owned)
	__must_hold(cxl_region_quiesce)
{
	int rc;

	rc = cxl_hdm_quiesce_prepare(&cache->quiesce, snapshot, owned);
	if (rc || !(cap & PCI_DVSEC_CXL_CACHE_CAPABLE))
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
			      const struct cxl_hdm_info *snapshot,
			      struct cxl_hdm_quiesce *q,
			      u16 *command, bool *attempted)
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

	/*
	 * Everything above can still be rolled back. From the reset command
	 * onwards the device state is in doubt, so the caller must not
	 * re-enable caching or the device on a failure.
	 */
	*attempted = true;
	rc = cxl_clear_memory(pdev, dvsec, true);
	if (!rc)
		rc = cxl_reset_wait_done(pdev, dvsec, cap);

	/* Always clear Memory Clear; successful cleanup must not hide reset failure. */
	rc2 = cxl_clear_memory(pdev, dvsec, false);
	if (rc2)
		pci_err(pdev, "failed to clear CXL Reset Memory Clear: %d\n", rc2);
	rc = rc ?: rc2;

	if (!rc)
		rc = pci_cxl_restore_state(pdev, snapshot, command);

	rc2 = cxl_hdm_quiesce_flush(q);
	if (rc2)
		pci_err(pdev, "failed to invalidate CPU cache after CXL reset: %d\n", rc2);
	rc = rc ?: rc2;
	if (rc)
		cxl_reset_save_disabled_state(pdev);

	pci_dev_reset_iommu_done(pdev);
	return rc;
}

static int cxl_reset_quiesced(struct pci_dev *pdev, int dvsec, u16 cap,
			      const struct resource *owned)
	__must_hold(cxl_region_quiesce)
{
	struct cxl_hdm_info *snapshot __free(kfree) = NULL;
	struct cxl_pci_cache cache = {};
	bool reset_attempted = false;
	u16 command = 0;
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

	rc = cxl_reset_cache_prepare(pdev, dvsec, cap, snapshot, &cache, owned);
	if (rc && !cache.cache_disabled) {
		pci_err(pdev, "failed to prepare CXL reset ranges: %d\n", rc);
		cxl_hdm_quiesce_destroy(&cache.quiesce);
		return rc;
	}
	if (!rc)
		rc = __cxl_reset_execute(pdev, dvsec, cap, snapshot, &cache.quiesce,
					 &command, &reset_attempted);
	/* Undo preparation on abort; enable caching after reset only if safe. */
	rc2 = 0;
	if (cache.cache_disabled && (!reset_attempted || !rc))
		rc2 = cxl_reset_restore_cache_policy(pdev, dvsec, cache.saved_ctrl2);
	cxl_hdm_quiesce_destroy(&cache.quiesce);

	if (!reset_attempted) {
		/* An aborted reset alone must not poison the saved PCI command. */
		if (rc2)
			cxl_reset_save_disabled_state(pdev);
		return rc ?: rc2;
	}
	if (rc || rc2) {
		cxl_reset_save_disabled_state(pdev);
		return rc ?: rc2;
	}

	return cxl_reset_save_restored_state(pdev, command);
}

static int cxl_reset_execute(struct pci_dev *pdev, int dvsec, u16 cap,
			     const struct resource *owned)
{
	int rc;

	/* Raw reset callers may not have saved the PCI state needed for restore. */
	if (!pdev->state_saved) {
		pci_err(pdev, "CXL reset requires saved PCI state\n");
		return -EINVAL;
	}

	cxl_region_quiesce_lock();
	rc = cxl_reset_quiesced(pdev, dvsec, cap, owned);
	cxl_region_quiesce_unlock();

	return rc;
}

static int cxl_reset_check(struct pci_dev *pdev, bool probe, u16 *dvsec,
			   u16 *cap)
{
	u16 ctrl;
	int rc;

	if (pdev->is_virtfn || pdev->multifunction || pci_num_vf(pdev))
		return -ENOTTY;

	rc = cxl_pci_device_dvsec(pdev, dvsec, cap);
	if (rc)
		return probe ? -ENOTTY : rc;
	if (!(*cap & PCI_DVSEC_CXL_CACHE_CAPABLE) ||
	    !(*cap & PCI_DVSEC_CXL_MEM_CAPABLE) ||
	    !(*cap & PCI_DVSEC_CXL_RST_CAPABLE) ||
	    !(*cap & PCI_DVSEC_CXL_RST_MEM_CLR_CAPABLE))
		return -ENOTTY;

	rc = pci_read_config_word(pdev, *dvsec + PCI_DVSEC_CXL_CTRL, &ctrl);
	if (rc)
		return probe ? -ENOTTY : pcibios_err_to_errno(rc);
	if (PCI_POSSIBLE_ERROR(ctrl))
		return probe ? -ENOTTY : -ENODEV;
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

	return 0;
}

int cxl_reset_function(struct pci_dev *pdev, bool probe)
{
	u16 dvsec, cap;
	int rc;

	rc = cxl_reset_check(pdev, probe, &dvsec, &cap);
	if (rc || probe)
		return rc;

	return cxl_reset_execute(pdev, dvsec, cap, NULL);
}

/**
 * pci_cxl_reset_capable() - check whether CXL Reset can run on a device now
 * @pdev: CXL device
 *
 * Unlike the reset-method probe, this also checks the cached HDM state and
 * the CPU cache invalidation that the reset needs.
 *
 * Return: true when pci_cxl_reset_owned() can attempt the reset.
 */
bool pci_cxl_reset_capable(struct pci_dev *pdev)
{
	u16 dvsec, cap;

	return !cxl_reset_check(pdev, false, &dvsec, &cap);
}
EXPORT_SYMBOL_FOR_MODULES(pci_cxl_reset_capable, "vfio-cxl");

/**
 * pci_cxl_reset_owned() - CXL Reset for the driver that owns the HDM range
 * @pdev: CXL device, with its device lock held and PCI state saved
 * @owned: resource the caller reserved over the device's HPA range with
 *	   request_mem_region_exclusive(), or NULL
 *
 * Run the same sequence as the cxl_reset method. Ranges inside @owned are not
 * requested again, so a driver that keeps the HPA range reserved while it
 * exposes the memory can reset the device. The CPU caches are still
 * invalidated for every range before and after the reset.
 *
 * Return: 0 on success, or a negative errno. Unlike the reset method, a
 * device that cannot be reset returns an error to the caller instead of
 * falling through to another reset method. -EINVAL if @owned is not a busy,
 * exclusive reservation.
 */
int pci_cxl_reset_owned(struct pci_dev *pdev, const struct resource *owned)
{
	const unsigned long held = IORESOURCE_BUSY | IORESOURCE_EXCLUSIVE;
	u16 dvsec, cap;
	int rc;

	device_lock_assert(&pdev->dev);

	/* Only a busy, exclusive reservation keeps other users off the range. */
	if (owned && WARN_ON_ONCE((owned->flags & held) != held))
		return -EINVAL;

	rc = cxl_reset_check(pdev, false, &dvsec, &cap);
	if (rc)
		return rc;

	return cxl_reset_execute(pdev, dvsec, cap, owned);
}
EXPORT_SYMBOL_FOR_MODULES(pci_cxl_reset_owned, "vfio-cxl");
