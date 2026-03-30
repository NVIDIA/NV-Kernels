// SPDX-License-Identifier: GPL-2.0-only
/*
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/log2.h>

#include <linux/mem_encrypt.h>

#include <crypto/hash.h>

#include <asm/rsi.h>
#include <asm/rsi_cmds.h>

#include <asm/rhi.h>

#include <linux/rmeda_guest.h>

#include "rhi_cmds.h"

/*
 * Need to access device private data without helpers. The helpers
 * expect driveer not to be bound.
 */
#include "../../base/base.h"

#define PCI_TDISP_MESSAGE_VERSION_10	0x10

struct rmeda_guest_mapping_range {
	unsigned long pa;
	unsigned long pa_range_size;
	resource_size_t start;
	resource_size_t end;
	bool coherent;
};

struct rmeda_guest {
	unsigned long vdev_id;

	struct pci_dev *dev;

	void *interface_report;
	size_t interface_report_size;
	void *measurements;
	size_t measurements_size;
	void *certificate_chain;
	size_t certificate_chain_size;
	struct rsi_vdevice_info *device_info;

	bool report_offset_in_pages;
	bool workaround_bar_ranges;

	struct rmeda_guest_mapping_range *ranges;
	size_t n_ranges;

	struct list_head mappings_list;
	struct mutex mappings_mutex;
};

struct rmeda_guest_mapping {
	struct rmeda_guest *rmeda_guest;
	struct list_head list;

	resource_size_t start;
	size_t size;
};

static void *get_report(struct pci_dev *dev,
			unsigned long vdev_id,
			unsigned long report_id,
			size_t *size)
{
	void *report_shared, *report;
	int ret;

	report = (void *)__get_free_page(GFP_KERNEL);
	if (!report) {
		pci_err(dev, "failed to allocate interface report buffer\n");
		ret = -ENOMEM;
		goto err_out;
	}

	report_shared = (void *)__get_free_page(GFP_KERNEL);
	if (!report_shared) {
		pci_err(dev, "failed to allocate interface report buffer\n");
		ret = -ENOMEM;
		goto err_release_report_buffer;
	}

	ret = set_memory_decrypted((unsigned long)report_shared, 1);
	if (ret) {
		pci_err(dev, "failed to set memory decrypted (%d)\n", ret);
		goto err_release_report_shared_buffer;
	}

	ret = rhi_da_object_read(vdev_id, report_id,
				 virt_to_phys(report_shared),
				 PAGE_SIZE, 0, size);
	if (ret != 0) {
		pci_err(dev, "host call failed (%d)\n", ret);
		goto err_decrypt_memory;
	}

	/* Copy data to encyrpted memory before setting the page encrypted. */
	memcpy(report, report_shared, *size);

	/* Revoke host access to page. This also wiped the memory content. */
	ret = set_memory_encrypted((unsigned long)report_shared, 1);
	if (ret) {
		pci_err(dev, "failed to set memory encrypted (%d)\n", ret);
		/* NOTE: Leak the decrypted page instead of releasing it */
		goto err_release_report_buffer;
	}

	/* Not needed anymore */
	free_page((unsigned long)report_shared);
	report_shared = NULL;

	return report;

err_decrypt_memory:
	set_memory_encrypted((unsigned long)report_shared, 1);
err_release_report_shared_buffer:
	free_page((unsigned long)report_shared);
err_release_report_buffer:
	free_page((unsigned long)report);
err_out:
	return NULL;
}

void rmeda_guest_stop_tdisp(struct rmeda_guest *priv)
{
	struct rmeda_guest_mapping *mapping, *next_mapping;
	struct pci_dev *dev;
	unsigned long a0;
	int ret = 0;

	if (!priv)
		return;

	dev = priv->dev;

	/* Remove mappings established earlier */
	list_for_each_entry_safe(mapping,
				 next_mapping,
				 &priv->mappings_list,
				 list)
		rmeda_guest_release_mapping(mapping);

	/* Attempt disabling DMA */
	a0 = rsi_vdev_dma_disable(priv->vdev_id);
	if (a0 != RSI_SUCCESS)
		pci_warn(dev, "failed to disable DMA\n");

	ret = rhi_da_vdev_set_tdi_state(priv->vdev_id, RHI_DA_TDI_CONFIG_UNLOCKED);
	 if (ret != RHI_DA_SUCCESS && ret != RHI_DA_ERROR_INCOMPLETE) {
		pci_err(dev, "failed to stop the device (%d)\n", ret);
		return;
	}

	while (ret == RHI_DA_ERROR_INCOMPLETE)
		ret = rhi_da_vdev_continue(priv->vdev_id);
	if (ret)
		pci_err(dev, "failed to communicate with the device (%d)\n", ret);

	dev->dev.p->cc_accepted = false;

	if (priv->ranges)
		kfree(priv->ranges);

	if (priv->measurements)
		free_page((unsigned long)priv->measurements);
	if (priv->certificate_chain)
		free_page((unsigned long)priv->certificate_chain);
	if (priv->interface_report)
		free_page((unsigned long)priv->interface_report);
	if (priv->device_info)
		free_page((unsigned long)priv->device_info);

	kfree(priv);
}
EXPORT_SYMBOL_GPL(rmeda_guest_stop_tdisp);

struct pci_tdisp_device_interface_report {
	u16 interface_info;
	u16 reserved;
	u16 msi_x_message_control;
	u16 lnr_control;
	u32 tph_control;
	u32 mmio_range_count;
	/*
	 * struct pci_tdisp_mmio_range mmio_range[mmio_range_count];
	 * uint32_t device_specific_info_len;
	 * uint8_t device_specific_info[device_specific_info_len];
	 */
};

struct pci_tdisp_mmio_range {
	u64 first_page;
	u32 number_of_pages;
	u16 range_attributes;
	u16 range_id;
};

static void dump_interface_report(struct pci_tdisp_device_interface_report
				  *interface_report)
{
	struct pci_tdisp_mmio_range *mmio_range;
	u32 *device_specific_info_len;
	u8 *device_specific_info;
	unsigned int i;

	pr_info("interface_report:\n");
	pr_info("  interface_info  - 0x%04x\n", interface_report->interface_info);
	pr_info("  msi_x_message_control - 0x%04x\n", interface_report->msi_x_message_control);
	pr_info("  lnr_control	- 0x%04x\n", interface_report->lnr_control);
	pr_info("  tph_control	- 0x%08x\n", interface_report->tph_control);
	pr_info("  mmio_range_count	  - 0x%08x\n", interface_report->mmio_range_count);

	mmio_range = (struct pci_tdisp_mmio_range *)(interface_report + 1);
	for (i = 0; i < interface_report->mmio_range_count; i++) {
		pr_info("  mmio_range(%u):\n", i);
		pr_info("  first_page      - 0x%016llx\n", mmio_range[i].first_page);
		pr_info("  number_of_pages  - 0x%08x\n", mmio_range[i].number_of_pages);
		pr_info("  range_attributes	- 0x%04x\n", mmio_range[i].range_attributes);
		pr_info("  range_id	- 0x%04x\n", mmio_range[i].range_id);
	}

	device_specific_info_len = (u32 *)&mmio_range[i];
	pr_info("  device_info_len    - 0x%08x\n", *device_specific_info_len);
	device_specific_info = (u8 *)(device_specific_info_len + 1);
	pr_info("  device_info		- ");
	for (i = 0; i < *device_specific_info_len && i < 10; i++)
		pr_info("%02x ", device_specific_info[i]);
}

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static int verify_digests(struct pci_dev *dev, struct rmeda_guest *priv)
{
	struct {
		uint8_t *report;
		size_t size;
		uint8_t *digest;
	} reports[] = {
		{
			priv->measurements,
			priv->measurements_size,
			priv->device_info->meas_digest
		},
		{
			priv->interface_report,
			priv->interface_report_size,
			priv->device_info->report_digest
		},
		{
			priv->certificate_chain,
			priv->certificate_chain_size,
			priv->device_info->cert_digest
		}
	};

	struct sdesc *sdesc;
	struct crypto_shash *alg;
	char *hash_alg_name;
	int hash_algo;
	u8 digest[64];
	size_t digest_size;
	int sdesc_size;
	int ret;
	int i;

	hash_algo = priv->device_info->hash_algo;
	if (hash_algo == RSI_HASH_SHA_256) {
		hash_alg_name = "sha256";
		digest_size = 32;
	} else if (hash_algo == RSI_HASH_SHA_512) {
		hash_alg_name = "sha512";
		digest_size = 64;
	} else {
		pci_err(dev, "unknown realm hash algorithm!\n");
		ret = -ENXIO;
		goto err_out;
	}

	alg = crypto_alloc_shash(hash_alg_name, 0, 0);
	if (IS_ERR(alg)) {
		pci_err(dev, "cannot allocate %s\n", hash_alg_name);
		return PTR_ERR(alg);
	}

	sdesc_size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(sdesc_size, GFP_KERNEL);
	if (!sdesc) {
		pci_err(dev, "cannot allocate sdesc\n");
		goto err_free_shash;
	}
	sdesc->shash.tfm = alg;

	for (i = 0; i < ARRAY_SIZE(reports); i++) {
		/*
		 * Allow reports to be missing - but warn the user if that
		 * happens.
		 */
		if (reports[i].report == NULL || reports[i].size == 0) {
			pci_warn(dev, "report #%d missing. cannot verify digest\n",
				 i);
			continue;
		}

		ret = crypto_shash_digest(&sdesc->shash, reports[i].report,
					  reports[i].size, digest);
		if (ret) {
			pci_err(dev, "failed to compute digest, %d\n", ret);
			goto err_free_sdesc;
		}

		if (memcmp(reports[i].digest, digest, digest_size)) {
			pci_err(dev, "invalid digest at #%d\n", i);
			ret = -EINVAL;
			goto err_free_sdesc;
		}
	}

	kfree(sdesc);
	crypto_free_shash(alg);

	return 0;

err_free_sdesc:
	kfree(sdesc);
err_free_shash:
	crypto_free_shash(alg);
err_out:
	return ret;
}

static int rmeda_guest_create_mapping_ranges(struct rmeda_guest *priv)
{

	struct pci_tdisp_device_interface_report *report =
		(struct pci_tdisp_device_interface_report *)
		priv->interface_report;
	const size_t n_ranges = report->mmio_range_count;
	struct pci_tdisp_mmio_range *mmio_range =
		(struct pci_tdisp_mmio_range *)(report + 1);
	bool coherent_range_added = false;
	struct pci_dev *dev = priv->dev;
	bool rmm_generated;
	size_t i;

	if (n_ranges == 0) {
		pci_warn(dev, "interface report does not contain ranges\n");
		return 0;
	}

	/* Detect RMM-generated report */
	rmm_generated = mmio_range[0].range_id == 0xff00 ? true : false;

	priv->ranges =
		kzalloc(sizeof(struct rmeda_guest_mapping_range) * n_ranges,
			GFP_KERNEL);
	if (!priv->ranges)
		return -ENOMEM;

	priv->n_ranges = n_ranges;

	for (i = 0; i < n_ranges; i++) {
		bool coherent;
		int res_id = 0;

		/* Find the mapping from range id to resource id */
		if (rmm_generated) {
			int j = 0;
			for (; res_id < PCI_NUM_RESOURCES; res_id++) {
				if (!pci_resource_start(dev, res_id))
					continue;
				if (j == i)
					break;
				j++;
			}

			if (res_id == PCI_NUM_RESOURCES) {
				pci_err(dev, "interface report range %ld type is unknown. treating as coherent.\n",
					 i);
				res_id = 0xffff;
			}
		} else {
			res_id = mmio_range[i].range_id;
			if (priv->workaround_bar_ranges) {
				pci_err(dev, "applying workaround. interface report range %ld updated from %u to %u.\n",
					 i, res_id, res_id * 2);
				res_id = res_id * 2;
			}
			if (!pci_resource_start(dev, res_id)) {
				pci_err(dev, "interface report range %ld refers to non-existing resource %u.\n",
					 i, mmio_range[i].range_id);
				goto err_release;
			}
		}

		coherent = res_id == 0xffff;

		if (coherent) {
			/*
			 * Only a single coherent range is supported:
			 * There is no way to identify which
			 * range should be used when associating IPA
			 * to PA.
			 */
			if (!rmm_generated && coherent_range_added) {
				pci_err(dev, "more than one coherent range defined in the interface report. aborting.\n");
				goto err_release;
			}

			/*
			 * The RMM generated report does not denote explicitly
			 * which ranges are coherent and which are not. The
			 * code simply assumes that there should be BAR ranges
			 * and an optional coherent range. However, the interface
			 * report may also contain ranges which aren't advertised
			 * as BARs (e.g., VF ranges). There is no way to distinguish
			 * this case, so allow it... The Host should guarantee
			 * unambiguity if coherent ranges are used.
			 */
			if (rmm_generated && coherent_range_added) {
				pci_err(dev, "more than one unknown range defined in the generated report. ignoring.\n");
				continue;
			}

			coherent_range_added = true;
		}

		priv->ranges[i].pa = mmio_range[i].first_page;
		priv->ranges[i].pa *= priv->report_offset_in_pages ? SZ_4K : 1UL;
		priv->ranges[i].coherent = coherent;
		priv->ranges[i].pa_range_size = ((u64)mmio_range[i].number_of_pages) * SZ_4K;

		if (!coherent) {
			resource_size_t range_size =
				pci_resource_end(dev, res_id) -
				pci_resource_start(dev, res_id) + 1;

			/*
			 * The range must be nautrally aligned as per the PCIe
			 * specification, and its size must be power-of-2.
			 * Compute the start IPA.
			 */
			priv->ranges[i].start =
				pci_resource_start(dev, res_id) +
				(priv->ranges[i].pa % range_size);

			priv->ranges[i].end =
				priv->ranges[i].start +
				priv->ranges[i].pa_range_size;
		}

		pci_info(dev, "range: start=0x%llx, end=0x%llx, pa=0x%lx, pa_range_size=0x%lx (0x%lx), coherent=%d\n",
			 priv->ranges[i].start, priv->ranges[i].end,
			 priv->ranges[i].pa, priv->ranges[i].pa_range_size,
			 roundup_pow_of_two(priv->ranges[i].pa_range_size),
			 priv->ranges[i].coherent);
	}

	return 0;

err_release:
	kfree(priv->ranges);
	priv->n_ranges = 0;
	priv->ranges = NULL;
	return -EINVAL;
}

struct rmeda_guest *rmeda_guest_start_tdisp(struct pci_dev *dev)
{
	struct pci_tdisp_device_interface_report *interface_report;
	struct pci_tdisp_mmio_range *mmio_range;
	struct rhi_vdev_measurement_params *device_measurements_params;
	struct rmeda_guest *priv;
	unsigned long a0;
	int ret;

	if (!dev)
		return NULL;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->dev = dev;
	priv->vdev_id =
		(unsigned long)pci_dev_id(dev) |
		(unsigned long)pci_domain_nr(dev->bus) << 16;
	priv->report_offset_in_pages = true;
	INIT_LIST_HEAD(&priv->mappings_list);
	mutex_init(&priv->mappings_mutex);

	/* Workaround known defects in ARM FVP */
	if (dev->vendor == 0x13b5) {
		priv->report_offset_in_pages = false;
		priv->workaround_bar_ranges = true;
	}

	ret = rhi_da_vdev_set_tdi_state(priv->vdev_id, RHI_DA_TDI_CONFIG_LOCKED);
	if (ret != RHI_DA_SUCCESS && ret != RHI_DA_ERROR_INCOMPLETE) {
		pci_err(dev, "failed to lock the device (%d)\n", ret);
		goto err_free_buffers;
	}

	while (ret == RHI_DA_ERROR_INCOMPLETE)
		ret = rhi_da_vdev_continue(priv->vdev_id);
	if (ret) {
		pci_err(dev, "failed to communicate with the device (%d)\n", ret);
		goto err_free_buffers;
	}

	ret = rhi_da_vdev_get_interface_report(priv->vdev_id);
	 if (ret != RHI_DA_SUCCESS && ret != RHI_DA_ERROR_INCOMPLETE) {
		pci_err(dev, "failed to get interface report (%d)\n", ret);
		goto err_unlock;
	}

	while (ret == RHI_DA_ERROR_INCOMPLETE)
		ret = rhi_da_vdev_continue(priv->vdev_id);
	if (ret) {
		pci_err(dev, "failed to communicate with the device (%d)\n", ret);
		goto err_unlock;
	}

	device_measurements_params = (void *)__get_free_page(GFP_KERNEL);
	if (!device_measurements_params) {
		pci_err(dev, "failed to allocate measurement parameters\n");
		goto err_unlock;
	}

	ret = set_memory_decrypted((unsigned long)device_measurements_params, 1);
	if (ret) {
		pci_err(dev, "failed to set memory decrypted (%d)\n", ret);
		goto err_unlock;
	}

	device_measurements_params->flags = RHI_VDEV_MEASURE_RAW |
					    RHI_VDEV_MEASURE_SIGNED;
	memset(device_measurements_params->nonce, 0,
	       sizeof(device_measurements_params->nonce));
	memset(device_measurements_params->indices, 0,
	       sizeof(device_measurements_params->indices));

	/* Request all measurements */
	device_measurements_params->indices[31] = 0x40;

	/*
	 * Measurement request may fail. That is ok since not all devices
	 * support them.
	 */

	ret = rhi_da_vdev_get_measurements(priv->vdev_id,
					   virt_to_phys(device_measurements_params));
	 if (ret != RHI_DA_SUCCESS && ret != RHI_DA_ERROR_INCOMPLETE)
		pci_err(dev, "failed to get measurements (%d)\n", ret);

	if (ret == RHI_DA_ERROR_INCOMPLETE) {
		while (ret == RHI_DA_ERROR_INCOMPLETE)
			ret = rhi_da_vdev_continue(priv->vdev_id);
		if (ret)
			pci_err(dev, "failed to communicate with the device (%d)\n", ret);
	}

	ret = set_memory_encrypted((unsigned long)device_measurements_params, 1);
	if (ret) {
		pci_warn(dev, "failed to set memory encrypted (%d)\n", ret);
		/* NOTE: Leak the decrypted page instead of releasing it */
		goto err_unlock;
	}

	free_page((unsigned long)device_measurements_params);
	device_measurements_params = NULL;

	/*
	 * Read interface report. The report is mandatory for
	 * RMI_RDEV_VALIDATE_MAPPING.
	 */
	priv->interface_report = get_report(dev, priv->vdev_id, RHI_DA_OBJECT_INTERFACE_REPORT,
					    &priv->interface_report_size);
	if (priv->interface_report == NULL) {
		pci_err(dev, "failed to get the interface report\n");
		goto err_unlock;
	}

	/*
	 * Measurements may not be available if the device is platform
	 * attested. Just warn the user.
	 */
	priv->measurements = get_report(dev, priv->vdev_id, RHI_DA_OBJECT_MEASUREMENT,
					&priv->measurements_size);
	if (priv->measurements == NULL)
		pci_err(dev, "failed to get the measurements\n\n");

	/*
	 * Certificate chain is unavailable when the device is platform
	 * attested. Warn the user.
	 */
	priv->certificate_chain = get_report(dev, priv->vdev_id, RHI_DA_OBJECT_CERTIFICATE,
					     &priv->certificate_chain_size);
	if (priv->certificate_chain == NULL)
		pci_err(dev, "failed to get the certificates report\n");

	/* Read the device information from RMM */
	priv->device_info = (void *)__get_free_page(GFP_KERNEL);
	if (priv->device_info == NULL) {
		pci_err(dev, "failed to allocate a page for the device_info\n");
		goto err_unlock;
	}
	memset(priv->device_info, 0, PAGE_SIZE);
	a0 = rsi_vdev_get_info(priv->vdev_id, virt_to_phys(priv->device_info));
	if (a0 != RSI_SUCCESS) {
		pci_err(dev, "failed to get device device_info (%lu)\n", a0);
		goto err_unlock;
	}

	/*
	 * Verify that the device_info of the provided reports match with the
	 * device_info from RMM
	 */

	ret = verify_digests(dev, priv);
	if (ret) {
		pci_err(dev, "device digest validation failed (%d)\n", ret);
		goto err_unlock;
	}

	/* Digests match. The data can be used */

	interface_report = (struct pci_tdisp_device_interface_report *)
		priv->interface_report;
	mmio_range = (struct pci_tdisp_mmio_range *)(interface_report + 1);
	dump_interface_report(interface_report);

	ret = rmeda_guest_create_mapping_ranges(priv);
	if (ret) {
		pci_err(dev, "failed to parse the interface report (%d)\n", ret);
		goto err_unlock;
	}

	if (interface_report->mmio_range_count == 0) {
		pci_err(dev, "interface report does not include ranges\n");
		goto err_free_ranges;
	}

	ret = rhi_da_vdev_set_tdi_state(priv->vdev_id, RHI_DA_TDI_CONFIG_RUN);
	 if (ret != RHI_DA_SUCCESS && ret != RHI_DA_ERROR_INCOMPLETE) {
		pci_err(dev, "failed to start the device (%d)\n", ret);
		goto err_free_ranges;
	}
	while (ret == RHI_DA_ERROR_INCOMPLETE)
		ret = rhi_da_vdev_continue(priv->vdev_id);
	if (ret) {
		pci_err(dev, "failed to communicate with the device (%d)\n", ret);
		goto err_free_ranges;
	}

	a0 = __rsi_vdev_dma_enable(priv->vdev_id,
				 RSI_VDEV_DMA_FLAGS_ATS, 0,
				 priv->device_info->lock_nonce,
				 priv->device_info->meas_nonce,
				 priv->device_info->report_nonce);
	if (a0 != RSI_SUCCESS) {
		pci_err(dev, "failed to enable DMA (%lu)\n", a0);
		goto err_free_ranges;
	}

	dev->dev.p->cc_accepted = true;

	pci_info(dev, "TDISP enabled\n");

	return priv;

err_free_ranges:
	kfree(priv->ranges);
	rmeda_guest_stop_tdisp(priv);
	return NULL;

err_unlock:
	rmeda_guest_stop_tdisp(priv);
	return NULL;

err_free_buffers:
	if (priv->measurements)
		free_page((unsigned long)priv->measurements);
	if (priv->certificate_chain)
		free_page((unsigned long)priv->certificate_chain);
	if (priv->interface_report)
		free_page((unsigned long)priv->interface_report);
	if (priv->device_info)
		free_page((unsigned long)priv->device_info);

	kfree(priv);
	return NULL;
}
EXPORT_SYMBOL_GPL(rmeda_guest_start_tdisp);

static inline int
rsi_validate_dev_mapping(unsigned long vdev_id, phys_addr_t start_ipa,
			 phys_addr_t end_ipa, phys_addr_t io_pa,
			 unsigned long flags, unsigned long lock_nonce,
			 unsigned long meas_nonce, unsigned long report_nonce)
{
	unsigned long ret;
	phys_addr_t next_ipa;

	while (start_ipa < end_ipa) {
		ret = rsi_vdev_validate_mapping(vdev_id, start_ipa, end_ipa,
						io_pa, &next_ipa, flags,
						lock_nonce, meas_nonce, report_nonce);
		if (ret || next_ipa <= start_ipa || next_ipa > end_ipa)
			return -EINVAL;
		io_pa += next_ipa - start_ipa;
		start_ipa = next_ipa;
	}
	return 0;
}

struct rmeda_guest_mapping *rmeda_guest_validate_mapping(struct rmeda_guest *priv,
							 resource_size_t start,
							 size_t size,
							 bool coherent)
{
	unsigned long flags = coherent ? RSI_DEV_MEM_COHERENT : 0;
	struct rmeda_guest_mapping *mapping;
	unsigned int range_id;
	unsigned long start_phys;
	struct pci_dev *dev;

	if (!priv)
		return NULL;

	dev = priv->dev;

	/* Validations cannot be performed without valid ranges */
	if (priv->n_ranges == 0)
		return NULL;

	/*
	 * Determine if the range is reported as a BAR range,
	 * and update resource_id if necessary
	 */
	for (range_id = 0; range_id < priv->n_ranges; range_id++) {
		/*
		 * range start and end are invalid for coherent ranges.
		 * If the coherent range is defined as a BAR, it will
		 * still be found in this loop.
		 */
		if (priv->ranges[range_id].coherent)
			continue;

		/* Does the range start from this region? */
		if ((start < priv->ranges[range_id].start) ||
		    (start > priv->ranges[range_id].end))
			continue;

		/* Does the range end in this region? */
		if ((start + size - 1) > priv->ranges[range_id].end)
			continue;

		break;
	}

	/*
	 * If the range was not found and coherent mapping was requested,
	 * search for a coherent mapping. This conditions identifies
	 * coherent mappings in CXL mode.
	 */
	if (coherent && range_id == priv->n_ranges) {
		for (range_id = 0; range_id < priv->n_ranges; range_id++)
			if (coherent && priv->ranges[range_id].coherent)
				break;
	}

	if (range_id == priv->n_ranges) {
		pci_err(dev, "range for mapping 0x%llx (size 0x%lx) not found\n",
			 start, size);
		return NULL;
	}

	/*
	 * If the range is coherent, the IPA base is unknown.
	 * Assume that the range is naturally aligned with its
	 * size in both PA and IPA. If the range is non-coherent,
	 * pick up the range offset from the start address.
	 */
	if (priv->ranges[range_id].coherent) {
		unsigned long range_size =
			roundup_pow_of_two(priv->ranges[range_id].pa_range_size);
		start_phys =
			priv->ranges[range_id].pa +
			(start % range_size);
	} else {
		start_phys = priv->ranges[range_id].pa +
			     (start - priv->ranges[range_id].start);
	}

	mapping = kzalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping)
	        return NULL;

	pci_info(dev, "creating mapping: start=0x%llx, size=0x%lx, start_phys=0x%lx, coherent=%d\n",
		 start, size, start_phys, coherent);

	if (rsi_validate_dev_mapping(priv->vdev_id,
				     start, start + size,
				     start_phys, flags,
				     priv->device_info->lock_nonce,
				     priv->device_info->meas_nonce,
				     priv->device_info->report_nonce)) {
		pci_err(dev, "failed to set protection attributes for the address range\n");
		kfree(mapping);
		return NULL;
	}

	mapping->rmeda_guest = priv;
	mapping->start = start;
	mapping->size = size;
	INIT_LIST_HEAD(&mapping->list);

	mutex_lock(&priv->mappings_mutex);
	list_add(&mapping->list, &priv->mappings_list);
	mutex_unlock(&priv->mappings_mutex);

	return mapping;
}
EXPORT_SYMBOL_GPL(rmeda_guest_validate_mapping);

void rmeda_guest_release_mapping(struct rmeda_guest_mapping *mapping)
{
	struct rmeda_guest *rmeda_guest;
	unsigned long a0;
	phys_addr_t top;

	if (!mapping)
		return;

	rmeda_guest = mapping->rmeda_guest;

	mutex_lock(&rmeda_guest->mappings_mutex);
	list_del(&mapping->list);
	mutex_unlock(&rmeda_guest->mappings_mutex);

	a0 = rsi_set_addr_range_state(mapping->start,
				      mapping->start + mapping->size,
				      RSI_RIPAS_EMPTY,
				      RSI_CHANGE_DESTROYED,
				      &top);
	if (a0 != RSI_SUCCESS)
		pci_err(rmeda_guest->dev,
			"failed to set ripas (%lu)\n",
			a0);

	kfree(mapping);
}
EXPORT_SYMBOL_GPL(rmeda_guest_release_mapping);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arto Merilainen <amerilainen@nvidia.com>");
MODULE_DESCRIPTION("Routines to authenticate the device from realm");
