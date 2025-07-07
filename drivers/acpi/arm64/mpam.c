// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2025 Arm Ltd.

/* Parse the MPAM ACPI table feeding the discovered nodes into the driver */

#define pr_fmt(fmt) "ACPI MPAM: " fmt

#include <linux/acpi.h>
#include <linux/arm_mpam.h>
#include <linux/bits.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/platform_device.h>

#include <acpi/processor.h>

/*
 * Flags for acpi_table_mpam_msc.*_interrupt_flags.
 * See 2.1.1 Interrupt Flags, Table 5, of DEN0065B_MPAM_ACPI_3.0-bet.
 */
#define ACPI_MPAM_MSC_IRQ_MODE_MASK                    BIT(0)
#define ACPI_MPAM_MSC_IRQ_TYPE_MASK                    GENMASK(2, 1)
#define ACPI_MPAM_MSC_IRQ_TYPE_WIRED                   0
#define ACPI_MPAM_MSC_IRQ_AFFINITY_PROCESSOR_CONTAINER BIT(3)
#define ACPI_MPAM_MSC_IRQ_AFFINITY_VALID               BIT(4)

static bool acpi_mpam_register_irq(struct platform_device *pdev, int intid,
				   u32 flags, int *irq,
				   u32 processor_container_uid)
{
	int sense;

	if (!intid)
		return false;

	if (FIELD_GET(ACPI_MPAM_MSC_IRQ_TYPE_MASK, flags) !=
	    ACPI_MPAM_MSC_IRQ_TYPE_WIRED)
		return false;

	sense = FIELD_GET(ACPI_MPAM_MSC_IRQ_MODE_MASK, flags);

	if (16 <= intid && intid < 32 && processor_container_uid != GLOBAL_AFFINITY) {
		pr_err_once("Partitioned interrupts not supported\n");
		return false;
	}

	*irq = acpi_register_gsi(&pdev->dev, intid, sense, ACPI_ACTIVE_HIGH);
	if (*irq <= 0) {
		pr_err_once("Failed to register interrupt 0x%x with ACPI\n",
			    intid);
		return false;
	}

	return true;
}

static void acpi_mpam_parse_irqs(struct platform_device *pdev,
				 struct acpi_mpam_msc_node *tbl_msc,
				 struct resource *res, int *res_idx)
{
	u32 flags, aff;
	int irq;

	flags = tbl_msc->overflow_interrupt_flags;
	if (flags & ACPI_MPAM_MSC_IRQ_AFFINITY_VALID &&
	    flags & ACPI_MPAM_MSC_IRQ_AFFINITY_PROCESSOR_CONTAINER)
		aff = tbl_msc->overflow_interrupt_affinity;
	else
		aff = GLOBAL_AFFINITY;
	if (acpi_mpam_register_irq(pdev, tbl_msc->overflow_interrupt, flags, &irq, aff))
		res[(*res_idx)++] = DEFINE_RES_IRQ_NAMED(irq, "overflow");

	flags = tbl_msc->error_interrupt_flags;
	if (flags & ACPI_MPAM_MSC_IRQ_AFFINITY_VALID &&
	    flags & ACPI_MPAM_MSC_IRQ_AFFINITY_PROCESSOR_CONTAINER)
		aff = tbl_msc->error_interrupt_affinity;
	else
		aff = GLOBAL_AFFINITY;
	if (acpi_mpam_register_irq(pdev, tbl_msc->error_interrupt, flags, &irq, aff))
		res[(*res_idx)++] = DEFINE_RES_IRQ_NAMED(irq, "error");
}

static int acpi_mpam_parse_resource(struct mpam_msc *msc,
				    struct acpi_mpam_resource_node *res)
{
	int level, nid;
	u32 cache_id;

	switch (res->locator_type) {
	case ACPI_MPAM_LOCATION_TYPE_PROCESSOR_CACHE:
		cache_id = res->locator.cache_locator.cache_reference;
		level = find_acpi_cache_level_from_id(cache_id);
		if (level <= 0) {
			pr_err_once("Bad level (%u) for cache with id %u\n", level, cache_id);
			return -EINVAL;
		}
		return mpam_ris_create(msc, res->ris_index, MPAM_CLASS_CACHE,
				       level, cache_id);
	case ACPI_MPAM_LOCATION_TYPE_MEMORY:
		nid = pxm_to_node(res->locator.memory_locator.proximity_domain);
		if (nid == NUMA_NO_NODE)
			nid = 0;
		return mpam_ris_create(msc, res->ris_index, MPAM_CLASS_MEMORY,
				       255, nid);
	default:
		/* These get discovered later and treated as unknown */
		return 0;
	}
}

int acpi_mpam_parse_resources(struct mpam_msc *msc,
			      struct acpi_mpam_msc_node *tbl_msc)
{
	int i, err;
	char *ptr, *table_end;
	struct acpi_mpam_resource_node *resource;

	ptr = (char *)(tbl_msc + 1);
	table_end = ptr + tbl_msc->length;
	for (i = 0; i < tbl_msc->num_resource_nodes; i++) {
		u64 max_deps, remaining_table;

		if (ptr + sizeof(*resource) > table_end)
			return -EINVAL;

		resource = (struct acpi_mpam_resource_node *)ptr;

		remaining_table = table_end - ptr;
		max_deps = remaining_table / sizeof(struct acpi_mpam_func_deps);
		if (resource->num_functional_deps > max_deps) {
			pr_debug("MSC has impossible number of functional dependencies\n");
			return -EINVAL;
		}

		err = acpi_mpam_parse_resource(msc, resource);
		if (err)
			return err;

		ptr += sizeof(*resource);
		ptr += resource->num_functional_deps * sizeof(struct acpi_mpam_func_deps);
	}

	return 0;
}

static bool __init parse_msc_pm_link(struct acpi_mpam_msc_node *tbl_msc,
				     struct platform_device *pdev,
				     u32 *acpi_id)
{
	char hid[sizeof(tbl_msc->hardware_id_linked_device) + 1];
	bool acpi_id_valid = false;
	struct acpi_device *buddy;
	char uid[11];
	int err;

	memset(&hid, 0, sizeof(hid));
	memcpy(hid, &tbl_msc->hardware_id_linked_device,
	       sizeof(tbl_msc->hardware_id_linked_device));

	if (!strcmp(hid, ACPI_PROCESSOR_CONTAINER_HID)) {
		*acpi_id = tbl_msc->instance_id_linked_device;
		acpi_id_valid = true;
	}

	err = snprintf(uid, sizeof(uid), "%u",
		       tbl_msc->instance_id_linked_device);
	if (err >= sizeof(uid)) {
		pr_debug("Failed to convert uid of device for power management.");
		return acpi_id_valid;
	}

	buddy = acpi_dev_get_first_match_dev(hid, uid, -1);
	if (buddy)
		device_link_add(&pdev->dev, &buddy->dev, DL_FLAG_STATELESS);

	return acpi_id_valid;
}

static int decode_interface_type(struct acpi_mpam_msc_node *tbl_msc,
				 enum mpam_msc_iface *iface)
{
	switch (tbl_msc->interface_type) {
	case 0:
		*iface = MPAM_IFACE_MMIO;
		return 0;
	case 0xa:
		*iface = MPAM_IFACE_PCC;
		return 0;
	default:
		return -EINVAL;
	}
}

static int __init acpi_mpam_parse(void)
{
	struct acpi_table_header *table __free(acpi_table) = acpi_get_table_ret(ACPI_SIG_MPAM, 0);
	char *table_end, *table_offset = (char *)(table + 1);
	struct property_entry props[4]; /* needs a sentinel */
	struct acpi_mpam_msc_node *tbl_msc;
	int next_res, next_prop, err = 0;
	struct acpi_device *companion;
	struct platform_device *pdev;
	enum mpam_msc_iface iface;
	struct resource res[3];
	char uid[16];
	u32 acpi_id;

	if (acpi_disabled || !system_supports_mpam() || IS_ERR(table))
		return 0;

	if (table->revision < 1)
		return 0;

	table_end = (char *)table + table->length;

	while (table_offset < table_end) {
		tbl_msc = (struct acpi_mpam_msc_node *)table_offset;
		table_offset += tbl_msc->length;

		if (table_offset > table_end) {
			pr_debug("MSC entry overlaps end of ACPI table\n");
			break;
		}

		/*
		 * If any of the reserved fields are set, make no attempt to
		 * parse the MSC structure. This MSC will still be counted,
		 * meaning the MPAM driver can't probe against all MSC, and
		 * will never be enabled. There is no way to enable it safely,
		 * because we cannot determine safe system-wide partid and pmg
		 * ranges in this situation.
		 */
		if (tbl_msc->reserved || tbl_msc->reserved1 || tbl_msc->reserved2) {
			pr_err_once("Unrecognised MSC, MPAM not usable\n");
			pr_debug("MSC.%u: reserved field set\n", tbl_msc->identifier);
			continue;
		}

		if (!tbl_msc->mmio_size) {
			pr_debug("MSC.%u: marked as disabled\n", tbl_msc->identifier);
			continue;
		}

		if (decode_interface_type(tbl_msc, &iface)) {
			pr_debug("MSC.%u: unknown interface type\n", tbl_msc->identifier);
			continue;
		}

		next_res = 0;
		next_prop = 0;
		memset(res, 0, sizeof(res));
		memset(props, 0, sizeof(props));

		pdev = platform_device_alloc("mpam_msc", tbl_msc->identifier);
		if (!pdev) {
			err = -ENOMEM;
			break;
		}

		if (tbl_msc->length < sizeof(*tbl_msc)) {
			err = -EINVAL;
			break;
		}

		/* Some power management is described in the namespace: */
		err = snprintf(uid, sizeof(uid), "%u", tbl_msc->identifier);
		if (err > 0 && err < sizeof(uid)) {
			companion = acpi_dev_get_first_match_dev("ARMHAA5C", uid, -1);
			if (companion)
				ACPI_COMPANION_SET(&pdev->dev, companion);
			else
				pr_debug("MSC.%u: missing namespace entry\n", tbl_msc->identifier);
		}

		if (iface == MPAM_IFACE_MMIO) {
			res[next_res++] = DEFINE_RES_MEM_NAMED(tbl_msc->base_address,
							       tbl_msc->mmio_size,
							       "MPAM:MSC");
		} else if (iface == MPAM_IFACE_PCC) {
			props[next_prop++] = PROPERTY_ENTRY_U32("pcc-channel",
								tbl_msc->base_address);
			next_prop++;
		}

		acpi_mpam_parse_irqs(pdev, tbl_msc, res, &next_res);
		err = platform_device_add_resources(pdev, res, next_res);
		if (err)
			break;

		props[next_prop++] = PROPERTY_ENTRY_U32("arm,not-ready-us",
							tbl_msc->max_nrdy_usec);

		/*
		 * The MSC's CPU affinity is described via its linked power
		 * management device, but only if it points at a Processor or
		 * Processor Container.
		 */
		if (parse_msc_pm_link(tbl_msc, pdev, &acpi_id)) {
			props[next_prop++] = PROPERTY_ENTRY_U32("cpu_affinity",
								acpi_id);
		}

		err = device_create_managed_software_node(&pdev->dev, props,
							  NULL);
		if (err)
			break;

		/* Come back later if you want the RIS too */
		err = platform_device_add_data(pdev, tbl_msc, tbl_msc->length);
		if (err)
			break;

		err = platform_device_add(pdev);
		if (err)
			break;
	}

	if (err)
		platform_device_put(pdev);

	return err;
}

int acpi_mpam_count_msc(void)
{
	struct acpi_table_header *table __free(acpi_table) = acpi_get_table_ret(ACPI_SIG_MPAM, 0);
	char *table_end, *table_offset = (char *)(table + 1);
	struct acpi_mpam_msc_node *tbl_msc;
	int count = 0;

	if (IS_ERR(table))
		return 0;

	if (table->revision < 1)
		return 0;

	table_end = (char *)table + table->length;

	while (table_offset < table_end) {
		tbl_msc = (struct acpi_mpam_msc_node *)table_offset;
		if (!tbl_msc->mmio_size)
			continue;

		if (tbl_msc->length < sizeof(*tbl_msc))
			return -EINVAL;
		if (tbl_msc->length > table_end - table_offset)
			return -EINVAL;
		table_offset += tbl_msc->length;

		count++;
	}

	return count;
}

/*
 * Call after ACPI devices have been created, which happens behind acpi_scan_init()
 * called from subsys_initcall(). PCC requires the mailbox driver, which is
 * initialised from postcore_initcall().
 */
subsys_initcall_sync(acpi_mpam_parse);
