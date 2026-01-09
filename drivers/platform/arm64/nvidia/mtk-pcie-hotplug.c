// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014-2025 MediaTek Inc.
 * Copyright (c) 2025-2026 NVIDIA Corporation
 *
 * CX7 PCIe Hotplug Driver
 *
 * Manages PCIe device hotplug using GPIO interrupts and ACPI resources.
 * Supports cable insertion/removal detection and device power management.
 */

#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/gpio.h>
#include <linux/gpio/driver.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pinctrl/consumer.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/property.h>
#include <linux/string.h>
#include <linux/uuid.h>

#define HP_PORT_MAX		3
#define HP_POLL_CNT_MAX		200
#define MAX_VENDOR_DATA_LEN	16
#define CX7_HP_MMIO_REGION_COUNT	5	/* TOP, PROTECT, CKM, MAC Port 0, MAC Port 1 */
#define CX7_HP_MIN_GPIO_COUNT	4	/* Minimum required: BOOT, PRSNT, PERST, EN */
#define PINCTRL_MAPPING_ENTRY_SIZE 5	/* dev_name, state, ctrl_dev, group, function */
/* Indices for pinctrl mapping entry strings */
#define PINCTRL_IDX_DEV_NAME	0
#define PINCTRL_IDX_STATE	1
#define PINCTRL_IDX_CTRL_DEV	2
#define PINCTRL_IDX_GROUP	3
#define PINCTRL_IDX_FUNCTION	4

/* Hardware timing requirements (in microseconds unless noted) */
#define CX7_HP_DELAY_SHORT_US		10	/* Short delay for register writes */
#define CX7_HP_DELAY_STANDARD_US	10000	/* Standard delay (10ms) */
#define CX7_HP_DELAY_BUS_PROTECT_US	5000	/* Bus protection setup delay */
#define CX7_HP_DELAY_PHY_RESET_US	3000	/* PHY reset delay */
#define CX7_HP_DELAY_LINK_STABLE_MS	100	/* Link stabilization delay (ms) */
#define CX7_HP_POLL_SLEEP_US		10000	/* Polling loop sleep interval */

#define PLUG_IN_EVT "HOTPLUG_STATE=plugin"
#define REMOVAL_EVT "HOTPLUG_STATE=removal"

/* Bus protection stages to prevent PCIe core reset glitches */
#define BUS_PROTECT_INIT		0
#define BUS_PROTECT_CABLE_REMOVAL	1
#define BUS_PROTECT_CABLE_PLUGIN	2
#define BUS_PROTECT_CLEANUP		3

enum cx7_hp_state {
	STATE_READY = 0,
	STATE_PLUG_OUT,		/* Cable plug-out */
	STATE_DEV_POWER_OFF,	/* Device is powered off */
	STATE_PLUG_IN,		/* Cable plug-in detected */
	STATE_DEV_POWER_ON,	/* Device is powered on */
	STATE_DEV_FW_START,	/* Device firmware is running */
	STATE_RESCAN,		/* Device ready, can perform bus rescan */
	STATE_UNKNOWN
};

enum pcie_pin_index {
	PCIE_PIN_BOOT = 0,	/* Device boot status pin */
	PCIE_PIN_PRSNT,		/* Presence detection pin */
	PCIE_PIN_PERST,		/* PCIe reset pin */
	PCIE_PIN_EN,		/* Power enable pin */
	PCIE_PIN_CLQ0,		/* Clock request pin 0 */
	PCIE_PIN_CLQ1,		/* Clock request pin 1 */
	PCIE_PIN_MAX
};

struct pcie_port_info {
	int domain;
	int bus;
	int devfn;
};

struct rp_bus_mmio_top {
	u32 ctrl;
	u32 port_bits[HP_PORT_MAX];
	u32 update_bit;
};

struct rp_bus_mmio_protect {
	u32 mode;
	u32 enable;
	u32 port_bits[HP_PORT_MAX];
};

struct rp_bus_mmio_mac {
	u32 init_ctrl;
	u32 ltssm_bit;
	u32 phy_rst_bit;
};

struct rp_bus_mmio_ckm {
	u32 ctrl;
	u32 disable_bit;
};

struct rp_bus_mmio_info {
	struct rp_bus_mmio_top top;
	struct rp_bus_mmio_protect protect;
	struct rp_bus_mmio_mac mac;
	struct rp_bus_mmio_ckm ckm;
};

struct gpio_acpi_context {
	struct device *dev;
	unsigned int debounce_timeout_us;
	int pin;
	int wake_capable;
	int triggering;
	int polarity;
	unsigned long irq_flags;
	int valid;
	unsigned int connection_type;
	char vendor_data[MAX_VENDOR_DATA_LEN + 1];
};

struct cx7_hp_dev;

/**
 * struct cx7_hp_plat_data - Platform configuration data parsed from ACPI
 *
 * Platform-specific configuration parsed from ACPI devices:
 * - RES0 device (PNP0C02): PCIe configuration and MMIO register offsets via _DSD
 * - PEDE device (MTKP0001): Pinctrl mappings via _DSD
 */
struct cx7_hp_plat_data {
	int port_nums;
	struct pcie_port_info ports[HP_PORT_MAX];
	u32 vendor_id;
	u32 device_id;
	int num_devices;
	struct rp_bus_mmio_info rp_bus_mmio;
	u32 ltssm_reg;
	u32 ltssm_l0_state;
	int pin_nums;
	struct pinctrl_map *parsed_pinmap;
};

struct cx7_hp_gpio_ctx {
	struct gpio_desc *desc;
	struct gpio_acpi_context *ctx;
	struct cx7_hp_dev *hp_dev;
};

struct acpi_gpio_parse_context {
	struct gpio_acpi_context *ctx;
	struct cx7_hp_dev *hp_dev;
};

struct acpi_gpio_walk_context {
	struct device *dev;
	struct gpio_info {
		unsigned int pin;
		unsigned int connection_type;
		unsigned int triggering;
		unsigned int polarity;
		unsigned int debounce_timeout;
		unsigned int wake_capable;
		char vendor_data[MAX_VENDOR_DATA_LEN + 1];
		char resource_source[16];
		unsigned int resource_source_index;
	} gpios[PCIE_PIN_MAX];
	int count;
};

struct cx7_hp_acpi_mmio {
	struct acpi_resource_fixed_memory32
	    mmio_regions[CX7_HP_MMIO_REGION_COUNT];
	int count;
	struct device *dev;
};

enum cx7_hp_debug_val {
	CX7_HP_DEBUG_PLUG_OUT = 0,
	CX7_HP_DEBUG_PLUG_IN,
	CX7_HP_DEBUG_MAX_VAL
};

struct cx7_hp_mmio_runtime {
	void __iomem *top_base;
	void __iomem *protect_base;
	void __iomem *ckm_base;
	void __iomem *mac_port_base[HP_PORT_MAX];
};

/**
 * cx7_hp_dev - Hotplug device structure
 *
 * ACPI resource sources:
 * - MMIO addresses: RES0 device (PNP0C02) _CRS, stored in mmio field
 * - GPIO resources: PEDE device (MTKP0001) _CRS, stored in pins field
 */
struct cx7_hp_dev {
	struct cx7_hp_gpio_ctx *pins;
	struct cx7_hp_plat_data *pd;
	struct platform_device *pdev;
	enum cx7_hp_state state;
	int gpio_count;
	int boot_pin;
	int prsnt_pin;
	enum cx7_hp_debug_val debug_state;
	bool hotplug_enabled;
	spinlock_t lock;
	struct pci_dev *cached_root_ports[HP_PORT_MAX];
	struct cx7_hp_mmio_runtime mmio;
	struct gpio_device *gdev;
	struct notifier_block pci_notifier;
};

/* ACPI _DSD device properties GUID: daffd814-6eba-4d8c-8a91-bc9bbf4aa301 */
static const guid_t device_properties_guid =
GUID_INIT(0xdaffd814, 0x6eba, 0x4d8c,
	  0x8a, 0x91, 0xbc, 0x9b,
	  0xbf, 0x4a, 0xa3, 0x01);

/**
 * cx7_hp_parse_pinctrl_config_dsd - Parse pinctrl configuration from PEDE device _DSD
 * @hp_dev: hotplug device
 *
 * Parses pin-nums and pinctrl-mappings from _DSD.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int cx7_hp_parse_pinctrl_config_dsd(struct cx7_hp_dev *hp_dev)
{
	struct acpi_device *adev;
	struct device *dev = &hp_dev->pdev->dev;
	const union acpi_object *mappings_pkg, *mapping_entry;
	struct pinctrl_map *pinmap;
	u32 pin_nums = 0;
	int k;
	const char *strings[PINCTRL_MAPPING_ENTRY_SIZE];

	adev = ACPI_COMPANION(dev);
	if (!adev) {
		dev_err(dev, "Failed to get ACPI companion device\n");
		return -ENODEV;
	}

	struct acpi_buffer buffer = { ACPI_ALLOCATE_BUFFER, NULL };
	acpi_status status;
	const union acpi_object *dsd_pkg, *props_pkg = NULL;
	int i, j;

	status = acpi_evaluate_object_typed(adev->handle, "_DSD", NULL, &buffer,
					    ACPI_TYPE_PACKAGE);
	if (ACPI_FAILURE(status)) {
		dev_err(dev, "Failed to evaluate _DSD: %s\n",
			acpi_format_exception(status));
		return -ENODEV;
	}

	dsd_pkg = buffer.pointer;
	if (!dsd_pkg || dsd_pkg->type != ACPI_TYPE_PACKAGE) {
		dev_err(dev, "Invalid _DSD package\n");
		ACPI_FREE(buffer.pointer);
		return -EINVAL;
	}
	/* Find Device Properties GUID package */
	for (i = 0; i + 1 < dsd_pkg->package.count; i += 2) {
		const union acpi_object *guid = &dsd_pkg->package.elements[i];
		const union acpi_object *pkg =
		    &dsd_pkg->package.elements[i + 1];

		/* Verify GUID matches Device Properties GUID */
		if (guid->type == ACPI_TYPE_BUFFER && guid->buffer.length == 16 &&
		    pkg->type == ACPI_TYPE_PACKAGE &&
		    guid_equal((guid_t *)guid->buffer.pointer,
			      &device_properties_guid)) {
			props_pkg = pkg;
			break;
		}
	}

	if (!props_pkg) {
		dev_err(dev,
			"Device Properties GUID package not found in _DSD\n");
		ACPI_FREE(buffer.pointer);
		return -EINVAL;
	}

	for (j = 0; j < props_pkg->package.count; j++) {
		const union acpi_object *prop = &props_pkg->package.elements[j];

		if (prop->type != ACPI_TYPE_PACKAGE ||
		    prop->package.count != 2 ||
		    prop->package.elements[0].type != ACPI_TYPE_STRING)
			continue;

		const char *prop_name =
		    prop->package.elements[0].string.pointer;
		const union acpi_object *prop_value =
		    &prop->package.elements[1];

		if (!strcmp(prop_name, "pin-nums")) {
			if (prop_value->type == ACPI_TYPE_INTEGER) {
				pin_nums = prop_value->integer.value;
			}
		} else if (!strcmp(prop_name, "pinctrl-mappings")) {
			if (prop_value->type == ACPI_TYPE_PACKAGE)
				mappings_pkg = prop_value;
		}
	}

	if (pin_nums == 0) {
		hp_dev->pd->pin_nums = 0;
		ACPI_FREE(buffer.pointer);
		return 0;
	}

	if (!mappings_pkg) {
		dev_err(dev,
			"Missing required _DSD property: pinctrl-mappings\n");
		ACPI_FREE(buffer.pointer);
		return -EINVAL;
	}

	if (mappings_pkg->package.count != pin_nums) {
		dev_err(dev,
			"pinctrl-mappings count mismatch: expected %u, got %u\n",
			pin_nums, mappings_pkg->package.count);
		ACPI_FREE(buffer.pointer);
		return -EINVAL;
	}

	/* Allocate pinmap array */
	pinmap = devm_kcalloc(dev, pin_nums, sizeof(*pinmap), GFP_KERNEL);
	if (!pinmap) {
		ACPI_FREE(buffer.pointer);
		return -ENOMEM;
	}

	/* Parse each mapping entry */
	for (k = 0; k < pin_nums; k++) {
		mapping_entry = &mappings_pkg->package.elements[k];
		if (mapping_entry->type != ACPI_TYPE_PACKAGE ||
		    mapping_entry->package.count != ARRAY_SIZE(strings)) {
			dev_err(dev,
				"Invalid pinctrl mapping entry %d: expected Package(%zu), "
				"got %s(count=%u)\n",
				k, ARRAY_SIZE(strings),
				mapping_entry->type == ACPI_TYPE_PACKAGE ?
				"Package" : "non-Package",
				mapping_entry->type == ACPI_TYPE_PACKAGE ?
				mapping_entry->package.count : 0);
			ACPI_FREE(buffer.pointer);
			return -EINVAL;
		}

		/* Extract strings: dev_name, state, ctrl_dev, group, function */
		for (int l = 0; l < ARRAY_SIZE(strings); l++) {
			if (mapping_entry->package.elements[l].type !=
			    ACPI_TYPE_STRING) {
				dev_err(dev,
					"Mapping entry %d element %d is not a string\n",
					k, l);
				ACPI_FREE(buffer.pointer);
				return -EINVAL;
			}
			strings[l] =
			    mapping_entry->package.elements[l].string.pointer;
		}

		/* Populate pinctrl_map structure */
		pinmap[k].dev_name =
		    devm_kstrdup(dev, strings[PINCTRL_IDX_DEV_NAME],
				 GFP_KERNEL);
		pinmap[k].name =
		    devm_kstrdup(dev, strings[PINCTRL_IDX_STATE], GFP_KERNEL);
		pinmap[k].type = PIN_MAP_TYPE_MUX_GROUP;
		pinmap[k].ctrl_dev_name =
		    devm_kstrdup(dev, strings[PINCTRL_IDX_CTRL_DEV],
				 GFP_KERNEL);
		pinmap[k].data.mux.group =
		    devm_kstrdup(dev, strings[PINCTRL_IDX_GROUP], GFP_KERNEL);
		pinmap[k].data.mux.function =
		    devm_kstrdup(dev, strings[PINCTRL_IDX_FUNCTION],
				 GFP_KERNEL);

		if (!pinmap[k].dev_name || !pinmap[k].name ||
		    !pinmap[k].ctrl_dev_name || !pinmap[k].data.mux.group ||
		    !pinmap[k].data.mux.function) {
			dev_err(dev,
				"Failed to allocate memory for mapping %d\n",
				k);
			ACPI_FREE(buffer.pointer);
			return -ENOMEM;
		}
	}

	hp_dev->pd->pin_nums = pin_nums;
	hp_dev->pd->parsed_pinmap = pinmap;
	ACPI_FREE(buffer.pointer);
	dev_dbg(dev, "Successfully parsed %u pinctrl mappings from ACPI\n",
		pin_nums);
	return 0;
}

/**
 * cx7_hp_pinctrl_init - Register pinctrl mappings for the device
 * @hp_dev: hotplug device
 *
 * Parses pinctrl mappings from _DSD and registers them.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int cx7_hp_pinctrl_init(struct cx7_hp_dev *hp_dev)
{
	int ret;

	ret = cx7_hp_parse_pinctrl_config_dsd(hp_dev);
	if (ret) {
		dev_err(&hp_dev->pdev->dev,
			"Failed to parse pinctrl configuration from ACPI: %d\n",
			ret);
		return ret;
	}

	if (!hp_dev->pd->pin_nums)
		return 0;

	ret =
	    pinctrl_register_mappings(hp_dev->pd->parsed_pinmap,
				      hp_dev->pd->pin_nums);
	if (ret) {
		dev_err(&hp_dev->pdev->dev,
			"Failed to register pinctrl mappings\n");
		return ret;
	}

	dev_dbg(&hp_dev->pdev->dev, "Registered %u pinctrl mappings\n",
		hp_dev->pd->pin_nums);
	return 0;
}

/**
 * cx7_hp_pinctrl_remove - Unregister pinctrl mappings
 * @hp_dev: hotplug device
 */
static void cx7_hp_pinctrl_remove(struct cx7_hp_dev *hp_dev)
{
	if (!hp_dev->pd->pin_nums)
		return;

	pinctrl_unregister_mappings(hp_dev->pd->parsed_pinmap);
}

/**
 * cx7_hp_change_pinctrl_state - Change pinctrl state
 * @hp_dev: hotplug device
 * @new_state: new pinctrl state name
 *
 * Returns: 0 on success, negative error code on failure
 */
static int cx7_hp_change_pinctrl_state(struct cx7_hp_dev *hp_dev,
				       const char *new_state)
{
	struct pinctrl *pinctrl;
	struct pinctrl_state *state;
	int ret;

	pinctrl = devm_pinctrl_get(&hp_dev->pdev->dev);
	if (IS_ERR(pinctrl)) {
		dev_err(&hp_dev->pdev->dev, "Failed to get pinctrl\n");
		return PTR_ERR(pinctrl);
	}

	state = pinctrl_lookup_state(pinctrl, new_state);
	if (IS_ERR(state)) {
		dev_err(&hp_dev->pdev->dev, "Failed to lookup state:%s\n",
			new_state);
		return PTR_ERR(state);
	}

	ret = pinctrl_select_state(pinctrl, state);
	if (ret) {
		dev_err(&hp_dev->pdev->dev,
			"Failed to select pinctrl state:%s\n", new_state);
		return ret;
	}

	return 0;
}

/**
 * cx7_hp_send_uevent - Send uevent to userspace
 * @hp_dev: hotplug device
 * @msg: uevent message string
 */
static void cx7_hp_send_uevent(struct cx7_hp_dev *hp_dev, const char *msg)
{
	char *uevent = NULL;
	char *envp[2];

	uevent = kasprintf(GFP_KERNEL, msg);
	if (!uevent) {
		dev_err(&hp_dev->pdev->dev,
			"Failed to allocate uevent string\n");
		return;
	}

	envp[0] = uevent;
	envp[1] = NULL;

	if (kobject_uevent_env(&hp_dev->pdev->dev.kobj, KOBJ_CHANGE, envp))
		dev_err(&hp_dev->pdev->dev, "Failed to send uevent\n");

	kfree(uevent);
}

/**
 * cx7_hp_reg_update_bits - Update specific bits in a register
 * @base: MMIO base address
 * @offset: Register offset
 * @mask: Bits to modify
 * @set: true to set bits, false to clear bits
 */
static inline void cx7_hp_reg_update_bits(void __iomem *base, u32 offset,
					  u32 mask, bool set)
{
	u32 val = readl(base + offset);

	if (set)
		val |= mask;
	else
		val &= ~mask;

	writel(val, base + offset);
}

/**
 * cx7_hp_toggle_update_bit - Toggle control register update bit
 * @base: MMIO base address
 * @ctrl_offset: Control register offset
 * @bits: Bits to set/clear before toggling update
 * @update_bit: Update bit mask
 * @set: true to set bits, false to clear bits
 *
 * Performs the sequence: modify bits, clear update bit, set update bit
 */
static void cx7_hp_toggle_update_bit(void __iomem *base, u32 ctrl_offset,
				     u32 bits, u32 update_bit, bool set)
{
	cx7_hp_reg_update_bits(base, ctrl_offset, bits, set);
	cx7_hp_reg_update_bits(base, ctrl_offset, update_bit, false);
	cx7_hp_reg_update_bits(base, ctrl_offset, update_bit, true);
}

/**
 * cx7_hp_bus_protect_enable - Enable bus protection for a port
 * @dev: hotplug device
 * @port_idx: Port index
 */
static void cx7_hp_bus_protect_enable(struct cx7_hp_dev *dev, int port_idx)
{
	struct rp_bus_mmio_info *mmio_info = &dev->pd->rp_bus_mmio;
	u32 port_bit = mmio_info->protect.port_bits[port_idx];

	cx7_hp_reg_update_bits(dev->mmio.protect_base,
			       mmio_info->protect.mode, port_bit, true);
	cx7_hp_reg_update_bits(dev->mmio.protect_base,
			       mmio_info->protect.enable, port_bit, true);
}

/**
 * cx7_hp_bus_protect_disable - Disable bus protection for a port
 * @dev: hotplug device
 * @port_idx: Port index
 */
static void cx7_hp_bus_protect_disable(struct cx7_hp_dev *dev, int port_idx)
{
	struct rp_bus_mmio_info *mmio_info = &dev->pd->rp_bus_mmio;
	u32 port_bit = mmio_info->protect.port_bits[port_idx];

	cx7_hp_reg_update_bits(dev->mmio.protect_base,
			       mmio_info->protect.enable, port_bit, false);
	cx7_hp_reg_update_bits(dev->mmio.protect_base,
			       mmio_info->protect.mode, port_bit, false);
}

/**
 * cx7_hp_ckm_control - Control clock module
 * @dev: hotplug device
 * @disable: true to disable clock, false to enable
 */
static void cx7_hp_ckm_control(struct cx7_hp_dev *dev, bool disable)
{
	struct rp_bus_mmio_info *mmio_info = &dev->pd->rp_bus_mmio;

	if (!dev->mmio.ckm_base)
		return;

	cx7_hp_reg_update_bits(dev->mmio.ckm_base, mmio_info->ckm.ctrl,
			       mmio_info->ckm.disable_bit, disable);
}

/**
 * cx7_hp_parse_mmio_resources - ACPI resource callback for parsing MMIO from _CRS
 * @ares: ACPI resource being processed
 * @data: pointer to cx7_hp_acpi_mmio structure
 *
 * Returns: AE_OK to continue iteration, AE_ERROR on error
 */
static acpi_status cx7_hp_parse_mmio_resources(struct acpi_resource *ares,
					       void *data)
{
	struct cx7_hp_acpi_mmio *parsed = data;

	switch (ares->type) {
	case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
		if (parsed->count >= CX7_HP_MMIO_REGION_COUNT) {
			dev_warn(parsed->dev,
				 "More than %d MMIO regions found in platform configuration device, ignoring extras\n",
				 CX7_HP_MMIO_REGION_COUNT);
			break;
		}
		parsed->mmio_regions[parsed->count] = ares->data.fixed_memory32;
		parsed->count++;
		break;
	default:
		break;
	}

	return AE_OK;
}

/**
 * cx7_hp_find_pcie_config_device - Find PCIe configuration device by HID
 *
 * Finds the ACPI device that provides PCIe configuration via _DSD properties
 * and MMIO resources via _CRS.
 *
 * Returns: acpi_device pointer on success (with reference), NULL on failure
 */
static struct acpi_device *cx7_hp_find_pcie_config_device(void)
{
	return acpi_dev_get_first_match_dev("PNP0C02", NULL, -1);
}

/**
 * cx7_hp_parse_pcie_config_dsd - Parse PCIe configuration from _DSD
 * @pdev: platform device
 * @pd: platform data to populate
 *
 * Parses PCIe MMIO register offsets, bit positions, port configuration, and PCIe device
 * identification from PCIe configuration device _DSD.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int cx7_hp_parse_pcie_config_dsd(struct platform_device *pdev,
					struct cx7_hp_plat_data *pd)
{
	struct acpi_device *config_adev;
	struct device *dev = &pdev->dev;
	u32 val, bit1;

	config_adev = cx7_hp_find_pcie_config_device();
	if (!config_adev) {
		dev_err(dev,
			"Platform configuration device (PNP0C02) not found - _DSD is required\n");
		return -ENODEV;
	}

	if (!acpi_dev_has_props(config_adev)) {
		dev_err(dev,
			"Platform configuration device has no _DSD properties. Check DSDT.\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "mac-init-ctrl-offset", &val)) {
		dev_err(dev,
			"Missing required _DSD property: mac-init-ctrl-offset\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.mac.init_ctrl = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "mac-ltssm-bit", &val)) {
		dev_err(dev, "Missing required _DSD property: mac-ltssm-bit\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.mac.ltssm_bit = BIT(val);

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "mac-phy-rst-bit", &val)) {
		dev_err(dev,
			"Missing required _DSD property: mac-phy-rst-bit\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.mac.phy_rst_bit = BIT(val);

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "top-ctrl-offset", &val)) {
		dev_err(dev,
			"Missing required _DSD property: top-ctrl-offset\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.top.ctrl = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "top-update-bit", &val)) {
		dev_err(dev,
			"Missing required _DSD property: top-update-bit\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.top.update_bit = BIT(val);

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "top-port0-bit", &val)) {
		dev_err(dev, "Missing required _DSD property: top-port0-bit\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.top.port_bits[0] = BIT(val);

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "top-port1-bit", &val)) {
		dev_err(dev, "Missing required _DSD property: top-port1-bit\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.top.port_bits[1] = BIT(val);

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "protect-mode-offset", &val)) {
		dev_err(dev,
			"Missing required _DSD property: protect-mode-offset\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.protect.mode = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "protect-enable-offset", &val)) {
		dev_err(dev,
			"Missing required _DSD property: protect-enable-offset\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.protect.enable = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "protect-port0-bit", &val)) {
		dev_err(dev,
			"Missing required _DSD property: protect-port0-bit\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.protect.port_bits[0] = BIT(val);

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "protect-port1-bit", &val)) {
		dev_err(dev,
			"Missing required _DSD property: protect-port1-bit\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.protect.port_bits[1] = BIT(val);

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "ckm-ctrl-offset", &val)) {
		dev_err(dev,
			"Missing required _DSD property: ckm-ctrl-offset\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.ckm.ctrl = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "ckm-disable-bit0", &val)) {
		dev_err(dev,
			"Missing required _DSD property: ckm-disable-bit0\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "ckm-disable-bit1", &bit1)) {
		dev_err(dev,
			"Missing required _DSD property: ckm-disable-bit1\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->rp_bus_mmio.ckm.disable_bit = BIT(val) | BIT(bit1);

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "ltssm-reg-offset", &val)) {
		dev_err(dev,
			"Missing required _DSD property: ltssm-reg-offset\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->ltssm_reg = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "ltssm-l0-state", &val)) {
		dev_err(dev,
			"Missing required _DSD property: ltssm-l0-state\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->ltssm_l0_state = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "port-nums", &val)) {
		dev_err(dev, "Missing required _DSD property: port-nums\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	if (val == 0 || val > HP_PORT_MAX) {
		dev_err(dev,
			"Invalid _DSD property port-nums: %u (must be 1-%d)\n",
			val, HP_PORT_MAX);
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->port_nums = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "port0-domain", &val)) {
		dev_err(dev, "Missing required _DSD property: port0-domain\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->ports[0].domain = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "port0-bus", &val)) {
		dev_err(dev, "Missing required _DSD property: port0-bus\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->ports[0].bus = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "port0-devfn", &val)) {
		dev_err(dev, "Missing required _DSD property: port0-devfn\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->ports[0].devfn = val;

	if (pd->port_nums >= 2) {
		if (fwnode_property_read_u32
		    (acpi_fwnode_handle(config_adev), "port1-domain", &val)) {
			dev_err(dev,
				"Missing required _DSD property: port1-domain\n");
			acpi_dev_put(config_adev);
			return -EINVAL;
		}
		pd->ports[1].domain = val;

		if (fwnode_property_read_u32
		    (acpi_fwnode_handle(config_adev), "port1-bus", &val)) {
			dev_err(dev,
				"Missing required _DSD property: port1-bus\n");
			acpi_dev_put(config_adev);
			return -EINVAL;
		}
		pd->ports[1].bus = val;

		if (fwnode_property_read_u32
		    (acpi_fwnode_handle(config_adev), "port1-devfn", &val)) {
			dev_err(dev,
				"Missing required _DSD property: port1-devfn\n");
			acpi_dev_put(config_adev);
			return -EINVAL;
		}
		pd->ports[1].devfn = val;
	}

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "vendor-id", &val)) {
		dev_err(dev, "Missing required _DSD property: vendor-id\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->vendor_id = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "device-id", &val)) {
		dev_err(dev, "Missing required _DSD property: device-id\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->device_id = val;

	if (fwnode_property_read_u32
	    (acpi_fwnode_handle(config_adev), "num-devices", &val)) {
		dev_err(dev, "Missing required _DSD property: num-devices\n");
		acpi_dev_put(config_adev);
		return -EINVAL;
	}
	pd->num_devices = val;

	dev_dbg(dev, "Successfully parsed all required _DSD properties\n");

	acpi_dev_put(config_adev);
	return 0;
}

/**
 * cx7_hp_parse_mmio_resources_from_acpi - Parse MMIO regions from _CRS
 * @dev: hotplug device
 * @parsed: pointer to parsed MMIO structure
 *
 * Returns: 0 on success, negative error code on failure
 */
static int cx7_hp_parse_mmio_resources_from_acpi(struct cx7_hp_dev *dev,
						 struct cx7_hp_acpi_mmio
						 *parsed)
{
	struct acpi_device *config_adev;
	acpi_status status;
	int ret = 0;

	if (!dev || !dev->pdev) {
		return -EINVAL;
	}

	config_adev = cx7_hp_find_pcie_config_device();
	if (!config_adev)
		return -ENODEV;

	parsed->count = 0;
	memset(parsed->mmio_regions, 0, sizeof(parsed->mmio_regions));

	status =
	    acpi_walk_resources(config_adev->handle, METHOD_NAME__CRS,
				cx7_hp_parse_mmio_resources, parsed);
	if (ACPI_FAILURE(status)) {
		dev_err(&dev->pdev->dev,
			"Failed to walk platform configuration resources: %s\n",
			acpi_format_exception(status));
		ret = -ENODEV;
		goto out;
	}

	if (parsed->count < CX7_HP_MMIO_REGION_COUNT) {
		dev_warn(&dev->pdev->dev,
			 "Expected %d MMIO regions from platform configuration device, found %d\n",
			 CX7_HP_MMIO_REGION_COUNT, parsed->count);
		ret = -ENODEV;
		goto out;
	}

out:
	acpi_dev_put(config_adev);
	return ret;
}

/**
 * cx7_hp_map_mmio_resources - Map all MMIO regions from ACPI _CRS
 * @dev: hotplug device
 *
 * Returns: 0 on success, negative error code on failure
 */
static int cx7_hp_map_mmio_resources(struct cx7_hp_dev *dev)
{
	struct platform_device *pdev = dev->pdev;
	struct cx7_hp_acpi_mmio parsed = {.count = 0, .dev = &pdev->dev };
	int ret;
	int i;

	ret = cx7_hp_parse_mmio_resources_from_acpi(dev, &parsed);
	if (ret) {
		dev_err(&pdev->dev,
			"Failed to get MMIO regions from platform configuration device\n");
		return ret;
	}

	dev_dbg(&pdev->dev, "Found %d MMIO regions in _CRS, mapping...\n",
		parsed.count);

	int mapped_count = 0;
	for (i = 0; i < parsed.count; i++) {
		void __iomem *base = NULL;
		u32 addr = parsed.mmio_regions[i].address;
		u32 size = parsed.mmio_regions[i].address_length;

		switch (i) {
		case 0:
			if (dev->pd->port_nums >= 1) {
				base = devm_ioremap(&pdev->dev, addr, size);
				if (!base) {
					dev_err(&pdev->dev,
						"Failed to map MAC Port 0 region (0x%08x)\n",
						addr);
					return -ENOMEM;
				}
				dev->mmio.mac_port_base[0] = base;
				mapped_count++;
			}
			break;
		case 1:
			if (dev->pd->port_nums >= 2) {
				base = devm_ioremap(&pdev->dev, addr, size);
				if (!base) {
					dev_err(&pdev->dev,
						"Failed to map MAC Port 1 region (0x%08x)\n",
						addr);
					return -ENOMEM;
				}
				dev->mmio.mac_port_base[1] = base;
				mapped_count++;
			}
			break;
		case 2:
			base = devm_ioremap(&pdev->dev, addr, size);
			if (!base) {
				dev_err(&pdev->dev,
					"Failed to map TOP region (0x%08x)\n",
					addr);
				return -ENOMEM;
			}
			dev->mmio.top_base = base;
			mapped_count++;
			break;
		case 3:
			base = devm_ioremap(&pdev->dev, addr, size);
			if (!base) {
				dev_err(&pdev->dev,
					"Failed to map PROTECT region (0x%08x)\n",
					addr);
				return -ENOMEM;
			}
			dev->mmio.protect_base = base;
			mapped_count++;
			break;
		case 4:
			base = devm_ioremap(&pdev->dev, addr, size);
			if (!base) {
				dev_err(&pdev->dev,
					"Failed to map CKM region (0x%08x)\n",
					addr);
				return -ENOMEM;
			}
			dev->mmio.ckm_base = base;
			mapped_count++;
			break;
		default:
			dev_warn(&pdev->dev,
				 "Unexpected MMIO region at 0x%08x (size 0x%x), skipping\n",
				 addr, size);
			break;
		}
	}

	if (!dev->mmio.top_base || !dev->mmio.protect_base
	    || !dev->mmio.ckm_base || (dev->pd->port_nums >= 1
				       && !dev->mmio.mac_port_base[0])
	    || (dev->pd->port_nums >= 2 && !dev->mmio.mac_port_base[1])) {
		dev_err(&pdev->dev,
			"Required MMIO regions not mapped from ACPI _CRS (mapped %d)\n",
			mapped_count);
		if (!dev->mmio.top_base)
			dev_err(&pdev->dev, "  Missing: TOP\n");
		if (!dev->mmio.protect_base)
			dev_err(&pdev->dev, "  Missing: PROTECT\n");
		if (!dev->mmio.ckm_base)
			dev_err(&pdev->dev, "  Missing: CKM\n");
		if (dev->pd->port_nums >= 1 && !dev->mmio.mac_port_base[0])
			dev_err(&pdev->dev,
				"  Missing: MAC Port 0 (port_nums=%d)\n",
				dev->pd->port_nums);
		if (dev->pd->port_nums >= 2 && !dev->mmio.mac_port_base[1])
			dev_err(&pdev->dev,
				"  Missing: MAC Port 1 (port_nums=%d)\n",
				dev->pd->port_nums);
		dev->mmio.top_base = NULL;
		dev->mmio.protect_base = NULL;
		dev->mmio.ckm_base = NULL;
		for (i = 0; i < HP_PORT_MAX; i++)
			dev->mmio.mac_port_base[i] = NULL;
		return -ENODEV;
	}

	dev_dbg(&pdev->dev,
		"Successfully mapped all MMIO regions from ACPI _CRS\n");
	return 0;
}

/**
 * cx7_hp_rp_bus_protect - Bus protection handler
 * @dev: hotplug device
 * @port_idx: port index (0-based)
 * @stage: protection stage (BUS_PROTECT_INIT, BUS_PROTECT_CLEANUP, etc.)
 */
static void cx7_hp_rp_bus_protect(struct cx7_hp_dev *dev, int port_idx,
				  int stage)
{
	switch (stage) {
	case BUS_PROTECT_INIT:
		{
			int ret;

			ret = cx7_hp_map_mmio_resources(dev);
			if (ret) {
				dev_err(&dev->pdev->dev,
					"Failed to map MMIO resources during bus init: %d\n",
					ret);
				return;
			}
		}
		return;

	case BUS_PROTECT_CLEANUP:
		{
			int i;

			for (i = 0; i < HP_PORT_MAX; i++) {
				if (dev->mmio.mac_port_base[i])
					dev->mmio.mac_port_base[i] = NULL;
			}
			if (dev->mmio.top_base)
				dev->mmio.top_base = NULL;
			if (dev->mmio.protect_base)
				dev->mmio.protect_base = NULL;
			if (dev->mmio.ckm_base)
				dev->mmio.ckm_base = NULL;
		}
		return;

	case BUS_PROTECT_CABLE_REMOVAL:
	case BUS_PROTECT_CABLE_PLUGIN:
		{
			struct rp_bus_mmio_info *mmio_info =
			    &dev->pd->rp_bus_mmio;
			void __iomem *mac_base;

			if (port_idx >= dev->pd->port_nums)
				return;

			mac_base = dev->mmio.mac_port_base[port_idx];
			if (!mac_base)
				return;

			if (stage == BUS_PROTECT_CABLE_REMOVAL) {
				cx7_hp_reg_update_bits(mac_base,
						       mmio_info->mac.init_ctrl,
						       mmio_info->mac.ltssm_bit,
						       false);
				cx7_hp_reg_update_bits(mac_base,
						       mmio_info->mac.init_ctrl,
						       mmio_info->mac.
						       phy_rst_bit, false);
				return;
			}

			cx7_hp_toggle_update_bit(dev->mmio.top_base,
						 mmio_info->top.ctrl,
						 mmio_info->top.
						 port_bits[port_idx],
						 mmio_info->top.update_bit,
						 false);
			udelay(CX7_HP_DELAY_SHORT_US);

			cx7_hp_bus_protect_enable(dev, port_idx);
			usleep_range(CX7_HP_DELAY_BUS_PROTECT_US,
				     CX7_HP_DELAY_BUS_PROTECT_US + 1000);

			cx7_hp_reg_update_bits(mac_base,
					       mmio_info->mac.init_ctrl,
					       mmio_info->mac.phy_rst_bit,
					       true);
			cx7_hp_reg_update_bits(mac_base,
					       mmio_info->mac.init_ctrl,
					       mmio_info->mac.ltssm_bit, true);
			usleep_range(CX7_HP_DELAY_PHY_RESET_US,
				     CX7_HP_DELAY_PHY_RESET_US + 1000);

			cx7_hp_bus_protect_disable(dev, port_idx);

			cx7_hp_toggle_update_bit(dev->mmio.top_base,
						 mmio_info->top.ctrl,
						 mmio_info->top.
						 port_bits[port_idx],
						 mmio_info->top.update_bit,
						 true);
		}
		break;

	default:
		dev_warn(&dev->pdev->dev, "Unknown bus protect stage: %d\n",
			 stage);
		break;
	}
}

/**
 * retrain_pcie_link - Retrain PCIe link
 * @dev: PCI device
 */
static void retrain_pcie_link(struct pci_dev *dev)
{
	u16 link_control, lnksta;
	int pos, i = 0;

	pos = pci_find_capability(dev, PCI_CAP_ID_EXP);
	if (!pos) {
		dev_err(&dev->dev, "PCIe capability not found\n");
		return;
	}

	pci_read_config_word(dev, pos + PCI_EXP_LNKCTL, &link_control);
	link_control |= PCI_EXP_LNKCTL_RL;

	pci_write_config_word(dev, pos + PCI_EXP_LNKCTL, link_control);

	while (i < HP_POLL_CNT_MAX) {
		i++;
		pcie_capability_read_word(dev, PCI_EXP_LNKSTA, &lnksta);
		if (lnksta & PCI_EXP_LNKSTA_DLLLA)
			break;
		usleep_range(CX7_HP_POLL_SLEEP_US, CX7_HP_POLL_SLEEP_US + 1000);
	}

	pcie_capability_write_word(dev, PCI_EXP_LNKSTA, PCI_EXP_LNKSTA_LBMS);
}

/**
 * get_port_root_port - Get PCI root port device for a port
 * @hp_dev: hotplug device
 * @port_idx: port index
 *
 * Returns cached or newly found root port, or NULL if not found.
 */
static struct pci_dev *get_port_root_port(struct cx7_hp_dev *hp_dev,
					  int port_idx)
{
	struct pcie_port_info *port;

	if (!hp_dev->pd || port_idx >= hp_dev->pd->port_nums)
		return NULL;

	port = &hp_dev->pd->ports[port_idx];

	if (!hp_dev->cached_root_ports[port_idx]) {
		hp_dev->cached_root_ports[port_idx] =
		    pci_get_domain_bus_and_slot(port->domain,
						port->bus, port->devfn);
		if (!hp_dev->cached_root_ports[port_idx]) {
			dev_warn(&hp_dev->pdev->dev,
				 "Root port not found for domain %d bus %d\n",
				 port->domain, port->bus);
			return NULL;
		}
	}

	return hp_dev->cached_root_ports[port_idx];
}

/**
 * remove_device - Remove PCIe devices and power down hardware
 * @dev: hotplug device
 */
static void remove_device(struct cx7_hp_dev *dev)
{
	int i;

	dev_info(&dev->pdev->dev, "Cable removal\n");

	for (i = 0; i < dev->pd->port_nums; i++)
		cx7_hp_rp_bus_protect(dev, i, BUS_PROTECT_CABLE_REMOVAL);

	gpiod_set_value(dev->pins[PCIE_PIN_PERST].desc, 0);
	cx7_hp_change_pinctrl_state(dev, "default");
	cx7_hp_ckm_control(dev, true);
	gpiod_set_value(dev->pins[PCIE_PIN_EN].desc, 0);
}

/**
 * polling_link_to_l0 - Poll until all PCIe ports reach L0 state
 * @dev: hotplug device
 *
 * Returns: 0 on success, negative error code on failure
 */
static int polling_link_to_l0(struct cx7_hp_dev *dev)
{
	struct pci_dev *pci_dev;
	u32 ltssm_reg;
	u32 l0_state;
	u32 ltssm_vals[HP_PORT_MAX] = { 0 };
	int count = 0;
	int i;
	bool all_l0;

	ltssm_reg = dev->pd->ltssm_reg;
	l0_state = dev->pd->ltssm_l0_state;

	if (!ltssm_reg || !l0_state)
		return 0;	/* Skip if not configured */

	/* Poll until all ports reach L0 state */
	all_l0 = false;
	while (!all_l0) {
		all_l0 = true;

		for (i = 0; i < dev->pd->port_nums; i++) {
			pci_dev = get_port_root_port(dev, i);
			if (!pci_dev) {
				all_l0 = false;
				continue;
			}

			pci_read_config_dword(pci_dev, ltssm_reg,
					      &ltssm_vals[i]);
			if ((ltssm_vals[i] & l0_state) != l0_state)
				all_l0 = false;
		}

		if (all_l0)
			break;

		usleep_range(CX7_HP_POLL_SLEEP_US, CX7_HP_POLL_SLEEP_US + 1000);
		count++;

		if (count > HP_POLL_CNT_MAX) {
			dev_err(&dev->pdev->dev,
				"Timeout waiting for link to reach L0 (reached max count)\n");
			break;
		}
	}

	if (count > HP_POLL_CNT_MAX) {
		return -ETIMEDOUT;
	}

	return 0;
}

/**
 * rescan_device - Rescan PCIe bus to discover devices
 * @dev: hotplug device
 *
 * Returns: 0 on success, negative error code on failure
 */
static int rescan_device(struct cx7_hp_dev *dev)
{
	struct pci_dev *pci_dev;
	int i, err;

	err = cx7_hp_change_pinctrl_state(dev, "clkreqn");
	if (err)
		return err;

	cx7_hp_ckm_control(dev, false);
	usleep_range(CX7_HP_DELAY_STANDARD_US, CX7_HP_DELAY_STANDARD_US + 1000);

	for (i = 0; i < dev->pd->port_nums; i++) {
		pci_dev = get_port_root_port(dev, i);
		if (!pci_dev)
			continue;

		err = pm_runtime_resume_and_get(&pci_dev->dev);
		if (err < 0) {
			dev_err(&dev->pdev->dev,
				"Runtime resume failed for %s: %d\n",
				pci_name(pci_dev), err);
		}
	}

	gpiod_set_value(dev->pins[PCIE_PIN_PERST].desc, 1);

	for (i = 0; i < dev->pd->port_nums; i++)
		cx7_hp_rp_bus_protect(dev, i, BUS_PROTECT_CABLE_PLUGIN);

	err = polling_link_to_l0(dev);
	if (err)
		return err;

	for (i = 0; i < dev->pd->port_nums; i++) {
		pci_dev = get_port_root_port(dev, i);
		if (pci_dev)
			retrain_pcie_link(pci_dev);
	}

	msleep(CX7_HP_DELAY_LINK_STABLE_MS);

	return 0;
}

/**
 * cx7_hp_work - Work queue handler for hotplug state machine
 * @irq: interrupt number
 * @dev_id: GPIO context pointer
 *
 * Processes hotplug state transitions based on current state.
 */
static irqreturn_t cx7_hp_work(int irq, void *dev_id)
{
	struct cx7_hp_gpio_ctx *app_ctx = dev_id;
	struct cx7_hp_dev *hp_dev;
	enum cx7_hp_state state;
	unsigned long flags;
	int ret;

	if (!app_ctx || !app_ctx->hp_dev)
		return IRQ_NONE;

	hp_dev = app_ctx->hp_dev;

	spin_lock_irqsave(&hp_dev->lock, flags);
	if (!hp_dev->hotplug_enabled) {
		spin_unlock_irqrestore(&hp_dev->lock, flags);
		return IRQ_HANDLED;
	}
	state = hp_dev->state;
	spin_unlock_irqrestore(&hp_dev->lock, flags);

	switch (state) {
	case STATE_PLUG_OUT:
		remove_device(hp_dev);
		break;
	case STATE_PLUG_IN:
		dev_info(&hp_dev->pdev->dev, "Cable plugin\n");
		gpiod_set_value(hp_dev->pins[PCIE_PIN_EN].desc, 1);
		break;
	case STATE_DEV_POWER_OFF:
	case STATE_DEV_POWER_ON:
	case STATE_DEV_FW_START:
		break;
	case STATE_RESCAN:
		ret = rescan_device(hp_dev);
		spin_lock_irqsave(&hp_dev->lock, flags);
		if (ret)
			dev_err(app_ctx->ctx->dev, "Rescan failed: %d\n", ret);
		else
			hp_dev->state = STATE_READY;
		spin_unlock_irqrestore(&hp_dev->lock, flags);
		break;
	default:
		dev_err(app_ctx->ctx->dev, "Unknown state: %d\n", state);
		break;
	}

	return IRQ_HANDLED;
}

/**
 * hotplug_irq_handler - GPIO interrupt handler for hotplug events
 * @irq: interrupt number
 * @dev_id: GPIO context pointer
 *
 * Handles presence detection and boot status GPIO interrupts.
 */
static irqreturn_t hotplug_irq_handler(int irq, void *dev_id)
{
	struct cx7_hp_gpio_ctx *app_ctx = dev_id;
	struct cx7_hp_dev *hp_dev = app_ctx->hp_dev;
	struct gpio_acpi_context *gpio_ctx = app_ctx->ctx;
	unsigned long flags;
	int value;
	enum cx7_hp_state state;

	value = gpiod_get_value(app_ctx->desc);

	if (gpio_ctx->pin == hp_dev->prsnt_pin) {
		if (value) {
			cx7_hp_send_uevent(hp_dev, REMOVAL_EVT);
		} else {
			cx7_hp_send_uevent(hp_dev, PLUG_IN_EVT);
		}
		return IRQ_HANDLED;
	}

	spin_lock_irqsave(&hp_dev->lock, flags);
	if (!hp_dev->hotplug_enabled) {
		spin_unlock_irqrestore(&hp_dev->lock, flags);
		return IRQ_HANDLED;
	}
	state = hp_dev->state;

	if (gpio_ctx->pin == hp_dev->boot_pin) {
		if (value && state == STATE_PLUG_IN) {
			hp_dev->state = STATE_DEV_POWER_ON;
		} else if (value && state == STATE_DEV_FW_START) {
			hp_dev->state = STATE_RESCAN;
		} else if (!value && state == STATE_DEV_POWER_ON) {
			hp_dev->state = STATE_DEV_FW_START;
		} else if (!value && state == STATE_PLUG_OUT) {
			hp_dev->state = STATE_DEV_POWER_OFF;
		} else {
			spin_unlock_irqrestore(&hp_dev->lock, flags);
			return IRQ_HANDLED;
		}
		spin_unlock_irqrestore(&hp_dev->lock, flags);
		return IRQ_WAKE_THREAD;
	}

	dev_err(gpio_ctx->dev,
		"Unknown GPIO pin event: pin=%d irq=%d value=%d\n",
		gpio_ctx->pin, irq, value);
	spin_unlock_irqrestore(&hp_dev->lock, flags);
	return IRQ_HANDLED;
}

/**
 * acpi_gpio_collect_handler - ACPI resource handler to collect all GPIO resources
 * @ares: ACPI resource structure
 * @context: Pointer to acpi_gpio_walk_context
 *
 * Returns: AE_OK to continue iteration
 */
static acpi_status acpi_gpio_collect_handler(struct acpi_resource *ares,
					     void *context)
{
	struct acpi_gpio_walk_context *walk_ctx = context;
	struct acpi_resource_gpio *agpio;
	int length;

	if (ares->type != ACPI_RESOURCE_TYPE_GPIO)
		return AE_OK;

	if (walk_ctx->count >= PCIE_PIN_MAX) {
		dev_warn(walk_ctx->dev,
			 "Too many GPIO resources, truncating at %d\n",
			 PCIE_PIN_MAX);
		return AE_OK;
	}

	agpio = &ares->data.gpio;

	if (!agpio->pin_table || agpio->pin_table_length == 0) {
		dev_warn(walk_ctx->dev, "GPIO resource has no pin table\n");
		return AE_OK;
	}

	walk_ctx->gpios[walk_ctx->count].pin = agpio->pin_table[0];
	walk_ctx->gpios[walk_ctx->count].connection_type =
	    agpio->connection_type;
	walk_ctx->gpios[walk_ctx->count].triggering = agpio->triggering;
	walk_ctx->gpios[walk_ctx->count].polarity = agpio->polarity;
	walk_ctx->gpios[walk_ctx->count].debounce_timeout =
	    agpio->debounce_timeout;
	walk_ctx->gpios[walk_ctx->count].wake_capable = agpio->wake_capable;

	if (agpio->vendor_length && agpio->vendor_data) {
		length = min_t(int, agpio->vendor_length, MAX_VENDOR_DATA_LEN);
		memcpy(walk_ctx->gpios[walk_ctx->count].vendor_data,
		       agpio->vendor_data, length);
		walk_ctx->gpios[walk_ctx->count].vendor_data[length] = '\0';
	} else {
		walk_ctx->gpios[walk_ctx->count].vendor_data[0] = '\0';
	}

	if (agpio->resource_source.string_ptr) {
		length = min_t(int, agpio->resource_source.string_length, 15);
		memcpy(walk_ctx->gpios[walk_ctx->count].resource_source,
		       agpio->resource_source.string_ptr, length);
		walk_ctx->gpios[walk_ctx->count].resource_source[length] = '\0';
	} else {
		walk_ctx->gpios[walk_ctx->count].resource_source[0] = '\0';
	}
	walk_ctx->gpios[walk_ctx->count].resource_source_index =
	    agpio->resource_source.index;
	walk_ctx->count++;
	return AE_OK;
}

/**
 * cx7_hp_walk_acpi_gpios - Walk ACPI _CRS to collect all GPIO resources
 * @pdev: Platform device
 * @walk_ctx: Context structure to fill with GPIO information
 *
 * Returns: 0 on success, negative error code on failure
 */
static int cx7_hp_walk_acpi_gpios(struct platform_device *pdev,
				  struct acpi_gpio_walk_context *walk_ctx)
{
	struct acpi_device *adev;
	acpi_status status;

	adev = ACPI_COMPANION(&pdev->dev);
	if (!adev) {
		dev_err(&pdev->dev, "Failed to get ACPI companion device\n");
		return -ENODEV;
	}

	memset(walk_ctx, 0, sizeof(*walk_ctx));
	walk_ctx->dev = &pdev->dev;

	status = acpi_walk_resources(adev->handle, METHOD_NAME__CRS,
				     acpi_gpio_collect_handler, walk_ctx);
	if (ACPI_FAILURE(status)) {
		dev_err(&pdev->dev, "Failed to walk ACPI GPIO resources: %s\n",
			acpi_format_exception(status));
		return -EIO;
	}

	dev_dbg(&pdev->dev, "Found %d GPIO resources via ACPI walk\n",
		walk_ctx->count);

	if (walk_ctx->count == 0) {
		dev_err(&pdev->dev, "No GPIO resources found in ACPI _CRS\n");
		return -ENODEV;
	}

	return 0;
}

/**
 * acpi_gpio_lookup_handler - ACPI resource handler to look up a specific GPIO pin
 * @ares: ACPI resource being processed
 * @context: Pointer to acpi_gpio_parse_context
 *
 * Returns: AE_OK to continue iteration
 */
static acpi_status acpi_gpio_lookup_handler(struct acpi_resource *ares,
					    void *context)
{
	struct acpi_gpio_parse_context *parse_ctx = context;
	struct gpio_acpi_context *ctx = parse_ctx->ctx;
	struct cx7_hp_dev *hp_dev = parse_ctx->hp_dev;
	struct acpi_resource_gpio *agpio;
	int length;

	if (ares->type != ACPI_RESOURCE_TYPE_GPIO)
		return AE_OK;

	agpio = &ares->data.gpio;

	if (ctx->pin != agpio->pin_table[0])
		return AE_OK;

	ctx->valid = 1;
	ctx->debounce_timeout_us = agpio->debounce_timeout * 10;
	ctx->wake_capable = agpio->wake_capable;
	ctx->triggering = agpio->triggering;
	ctx->polarity = agpio->polarity;
	ctx->connection_type = agpio->connection_type;

	if (agpio->vendor_length && agpio->vendor_data && hp_dev) {
		length = min_t(int, agpio->vendor_length, MAX_VENDOR_DATA_LEN);
		memcpy(&ctx->vendor_data[0], agpio->vendor_data, length);
		ctx->vendor_data[length] = '\0';

		if (!strncmp("BOOT", ctx->vendor_data, strlen("BOOT")))
			hp_dev->boot_pin = ctx->pin;
		else if (!strncmp("PRSNT", ctx->vendor_data, strlen("PRSNT")))
			hp_dev->prsnt_pin = ctx->pin;
	}

	if (agpio->triggering == ACPI_EDGE_SENSITIVE) {
		if (agpio->polarity == ACPI_ACTIVE_LOW)
			ctx->irq_flags = IRQF_TRIGGER_FALLING;
		else if (agpio->polarity == ACPI_ACTIVE_HIGH)
			ctx->irq_flags = IRQF_TRIGGER_RISING;
		else
			ctx->irq_flags =
			    (IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING);
	} else {
		if (agpio->polarity == ACPI_ACTIVE_LOW)
			ctx->irq_flags = IRQF_TRIGGER_LOW;
		else
			ctx->irq_flags = IRQF_TRIGGER_HIGH;
	}

	return AE_OK;
}

/**
 * pci_devices_present_on_domain() - Check if PCI devices exist on a domain
 * @domain: PCI domain number to check
 *
 * Returns: true if any PCI devices are present on the specified domain,
 * false otherwise. This is used as a safety check before hardware shutdown.
 */
static bool pci_devices_present_on_domain(int domain)
{
	struct pci_bus *bus;
	struct pci_dev *dev;
	bool has_endpoint_devices = false;

	bus = pci_find_bus(domain, 1);
	if (!bus)
		return false;

	list_for_each_entry(dev, &bus->devices, bus_list) {
		has_endpoint_devices = true;
		break;
	}

	return has_endpoint_devices;
}

static ssize_t debug_state_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct cx7_hp_dev *hp_dev = dev_get_drvdata(dev);

	if (!hp_dev)
		return -EINVAL;

	return scnprintf(buf, PAGE_SIZE, "%d\n", hp_dev->debug_state);
}

static ssize_t debug_state_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct cx7_hp_dev *hp_dev = dev_get_drvdata(dev);
	unsigned long val, flags;
	int err, i;

	if (!hp_dev || !hp_dev->pd)
		return -EINVAL;

	err = kstrtoul(buf, 10, &val);
	if (err)
		return err;

	spin_lock_irqsave(&hp_dev->lock, flags);
	if (!hp_dev->hotplug_enabled) {
		spin_unlock_irqrestore(&hp_dev->lock, flags);
		dev_info(dev, "Hotplug is disabled.\n");
		return -EPERM;
	}
	spin_unlock_irqrestore(&hp_dev->lock, flags);

	switch (val) {
	case CX7_HP_DEBUG_PLUG_OUT:
		/* Safety check: Verify no devices on the bus before hardware shutdown. */
		for (i = 0; i < hp_dev->pd->port_nums; i++) {
			if (pci_devices_present_on_domain
			    (hp_dev->pd->ports[i].domain)) {
				dev_err(dev,
					"PCI devices still present, remove them first\n");
				return -EBUSY;
			}
		}

		spin_lock_irqsave(&hp_dev->lock, flags);
		hp_dev->state = STATE_PLUG_OUT;
		hp_dev->debug_state = val;
		spin_unlock_irqrestore(&hp_dev->lock, flags);
		remove_device(hp_dev);
		return count;

	case CX7_HP_DEBUG_PLUG_IN:
		for (i = 0; i < hp_dev->pd->port_nums; i++) {
			if (pci_devices_present_on_domain
			    (hp_dev->pd->ports[i].domain)) {
				dev_err(dev,
					"PCI devices already present, cannot reinitialize hardware\n");
				return -EBUSY;
			}
		}

		spin_lock_irqsave(&hp_dev->lock, flags);
		hp_dev->state = STATE_PLUG_IN;
		hp_dev->debug_state = val;
		spin_unlock_irqrestore(&hp_dev->lock, flags);
		dev_info(dev, "Cable plugin\n");
		gpiod_set_value(hp_dev->pins[PCIE_PIN_EN].desc, 1);
		return count;

	default:
		return -EINVAL;
	}

	return count;
}

DEVICE_ATTR_RW(debug_state);

static ssize_t hotplug_enabled_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct cx7_hp_dev *hp_dev = dev_get_drvdata(dev);

	if (!hp_dev)
		return -EINVAL;

	return scnprintf(buf, PAGE_SIZE, "%d\n", hp_dev->hotplug_enabled ? 1 : 0);
}

static ssize_t hotplug_enabled_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct cx7_hp_dev *hp_dev = dev_get_drvdata(dev);
	unsigned long val;
	int err;

	if (!hp_dev)
		return -EINVAL;

	err = kstrtoul(buf, 10, &val);
	if (err)
		return err;

	hp_dev->hotplug_enabled = (val != 0);
	dev_info(dev, "Hotplug %s\n", hp_dev->hotplug_enabled ? "enabled" : "disabled");

	return count;
}

DEVICE_ATTR_RW(hotplug_enabled);

static struct attribute *cx7_hp_attrs[] = {
	&dev_attr_debug_state.attr,
	&dev_attr_hotplug_enabled.attr,
	NULL
};

static const struct attribute_group cx7_hp_attr_group = {
	.name = "pcie_hotplug",
	.attrs = cx7_hp_attrs
};

/**
 * gpio_acpi_setup - Setup GPIO ACPI context from _CRS
 * @pdev: platform device
 * @desc: GPIO descriptor
 * @hp_dev: hotplug device
 * @gpio_index: GPIO index
 *
 * Returns: GPIO ACPI context on success, NULL on failure
 */
static struct gpio_acpi_context *gpio_acpi_setup(struct platform_device *pdev,
						 struct gpio_desc *desc,
						 struct cx7_hp_dev *hp_dev,
						 int gpio_index)
{
	struct acpi_gpio_parse_context parse_ctx;
	struct gpio_acpi_context *ctx;
	struct acpi_device *adev;
	acpi_status status;

	adev = ACPI_COMPANION(&pdev->dev);
	if (!adev) {
		dev_err(&pdev->dev, "Failed to get ACPI companion device\n");
		return NULL;
	}

	ctx = devm_kzalloc(&pdev->dev, sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->pin =
	    desc_to_gpio(desc) -
	    gpio_device_get_base(gpiod_to_gpio_device(desc));
	ctx->dev = &pdev->dev;

	parse_ctx.ctx = ctx;
	parse_ctx.hp_dev = hp_dev;

	status = acpi_walk_resources(adev->handle, METHOD_NAME__CRS,
				     acpi_gpio_lookup_handler, &parse_ctx);
	if (ACPI_FAILURE(status)) {
		devm_kfree(&pdev->dev, ctx);
		return NULL;
	}

	if (ctx->valid) {
		if (gpio_index == PCIE_PIN_BOOT && hp_dev->boot_pin == -1) {
			hp_dev->boot_pin = ctx->pin;
		} else if (gpio_index == PCIE_PIN_PRSNT
			   && hp_dev->prsnt_pin == -1) {
			hp_dev->prsnt_pin = ctx->pin;
		}
		return ctx;
	}

	devm_kfree(&pdev->dev, ctx);
	return NULL;
}

/**
 * cx7_hp_setup_irq - Setup IRQ for GPIO
 * @app_ctx: GPIO context
 *
 * Returns: 0 on success, negative error code on failure
 */
static int cx7_hp_setup_irq(struct cx7_hp_gpio_ctx *app_ctx)
{
	struct gpio_acpi_context *ctx = app_ctx->ctx;
	int irq, ret;

	irq = gpiod_to_irq(app_ctx->desc);
	if (irq < 0) {
		dev_err(ctx->dev, "Failed to get IRQ for GPIO\n");
		return irq;
	}

	if (ctx->wake_capable)
		enable_irq_wake(irq);

	ret = devm_request_threaded_irq(ctx->dev, irq,
					hotplug_irq_handler, cx7_hp_work,
					ctx->irq_flags | IRQF_ONESHOT,
					"pcie_hotplug", app_ctx);
	if (ret)
		dev_err(ctx->dev, "Failed to request IRQ %d: %d\n", irq, ret);

	return ret;
}

/**
 * cx7_hp_put_gpio_device - Release GPIO device reference
 * @data: GPIO device pointer
 */
static void cx7_hp_put_gpio_device(void *data)
{
	struct gpio_device *gdev = data;

	gpio_device_put(gdev);
}

/**
 * cx7_hp_discover_pcie_devices - Discover existing PCI devices on managed ports
 * @pdev: platform device
 * @pd: platform data
 *
 * Returns: 0 on success, negative error code on failure
 */
static int cx7_hp_discover_pcie_devices(struct platform_device *pdev,
					struct cx7_hp_plat_data *pd)
{
	struct pci_dev *pci_dev = NULL;
	int device_count = 0;
	int i;

	if (!pd->vendor_id || !pd->device_id)
		return 0;

	while ((pci_dev = pci_get_device(pd->vendor_id,
					 pd->device_id, pci_dev)) != NULL) {
		if (!pci_dev->state_saved) {
			pci_dev_put(pci_dev);
			return -EPROBE_DEFER;
		}

		for (i = 0; i < pd->port_nums; i++) {
			if (pci_domain_nr(pci_dev->bus) == pd->ports[i].domain)
				break;
		}

		if (i == pd->port_nums) {
			dev_err(&pdev->dev,
				"Device %s found on unexpected domain %d\n",
				pci_name(pci_dev), pci_domain_nr(pci_dev->bus));
			pci_dev_put(pci_dev);
			return -ENODEV;
		}

		device_count++;
	}

	if (pd->num_devices && device_count != pd->num_devices) {
		dev_err(&pdev->dev,
			"Required number of devices not found. Expected=%d Actual=%d\n",
			pd->num_devices, device_count);
		return -ENODEV;
	}

	return 0;
}

/**
 * cx7_hp_init_pcie_data - Initialize PCIe data from _DSD and discover devices
 * @pdev: platform device
 * @pd: platform data to populate
 *
 * Returns: 0 on success, negative error code on failure
 */
static int cx7_hp_init_pcie_data(struct platform_device *pdev,
				 struct cx7_hp_plat_data *pd)
{
	int ret;

	ret = cx7_hp_parse_pcie_config_dsd(pdev, pd);
	if (ret) {
		dev_err(&pdev->dev,
			"Failed to parse PCIe configuration _DSD properties: %d\n",
			ret);
		return ret;
	}

	if (pd->port_nums == 0 || pd->port_nums >= HP_PORT_MAX) {
		dev_err(&pdev->dev,
			"Invalid port count from _DSD: %d (must be 1-%d)\n",
			pd->port_nums, HP_PORT_MAX - 1);
		return -EINVAL;
	}

	ret = cx7_hp_discover_pcie_devices(pdev, pd);
	if (ret) {
		dev_dbg(&pdev->dev, "Device discovery failed: %d\n", ret);
		return ret;
	}

	return 0;
}

/**
 * cx7_hp_enumerate_gpios - Enumerate GPIOs from ACPI
 * @pdev: Platform device
 * @hp_dev: Hotplug device structure
 *
 * Returns: Number of GPIOs found, or negative error code
 */
static int cx7_hp_enumerate_gpios(struct platform_device *pdev,
				  struct cx7_hp_dev *hp_dev)
{
	struct acpi_gpio_walk_context walk_ctx;
	struct fwnode_handle *gpio_fwnode = NULL;
	struct acpi_device *gpio_adev = NULL;
	acpi_handle gpio_handle;
	acpi_status status;
	int ret, i;

	ret = cx7_hp_walk_acpi_gpios(pdev, &walk_ctx);
	if (ret) {
		dev_err(&pdev->dev, "Failed to walk ACPI GPIO resources: %d\n",
			ret);
		return ret;
	}

	if (walk_ctx.count < CX7_HP_MIN_GPIO_COUNT) {
		dev_err(&pdev->dev,
			"Insufficient GPIOs from ACPI: required at least %d, got %d\n",
			CX7_HP_MIN_GPIO_COUNT, walk_ctx.count);
		return -ENODEV;
	}

	/* Find GPIO device using resource_source from first GPIO */
	if (walk_ctx.count == 0 || walk_ctx.gpios[0].resource_source[0] == '\0') {
		dev_err(&pdev->dev,
			"No resource_source in ACPI GPIO resources\n");
		return -ENODEV;
	}

	status =
	    acpi_get_handle(NULL, walk_ctx.gpios[0].resource_source,
			    &gpio_handle);
	if (ACPI_FAILURE(status)) {
		dev_err(&pdev->dev,
			"Failed to get ACPI handle for GPIO controller %s\n",
			walk_ctx.gpios[0].resource_source);
		return -ENODEV;
	}

	gpio_adev = acpi_fetch_acpi_dev(gpio_handle);
	if (!gpio_adev) {
		dev_err(&pdev->dev,
			"Failed to get ACPI device for GPIO controller %s\n",
			walk_ctx.gpios[0].resource_source);
		return -ENODEV;
	}

	gpio_fwnode = acpi_fwnode_handle(gpio_adev);
	hp_dev->gdev = gpio_device_find_by_fwnode(gpio_fwnode);
	if (!hp_dev->gdev) {
		return dev_err_probe(&pdev->dev, -EPROBE_DEFER,
				     "GPIO controller not available\n");
	}

	/* Successfully found GPIO device - manage reference */
	ret = devm_add_action_or_reset(&pdev->dev, cx7_hp_put_gpio_device,
				       hp_dev->gdev);
	if (ret) {
		gpio_device_put(hp_dev->gdev);
		hp_dev->gdev = NULL;
		dev_err(&pdev->dev, "Failed to register GPIO device cleanup\n");
		return ret;
	}

	hp_dev->gpio_count = walk_ctx.count;

	hp_dev->pins = devm_kzalloc(&pdev->dev,
				    sizeof(struct cx7_hp_gpio_ctx) *
				    hp_dev->gpio_count, GFP_KERNEL);
	if (!hp_dev->pins) {
		dev_err(&pdev->dev, "Failed to allocate memory for GPIOs\n");
		return -ENOMEM;
	}

	for (i = 0; i < hp_dev->gpio_count; i++) {
		struct cx7_hp_gpio_ctx *app_ctx = &hp_dev->pins[i];

		app_ctx->desc =
		    gpio_device_get_desc(hp_dev->gdev, walk_ctx.gpios[i].pin);
		if (IS_ERR(app_ctx->desc)) {
			dev_err(&pdev->dev,
				"Failed to get GPIO descriptor for ACPI pin %u (index %d): %ld\n",
				walk_ctx.gpios[i].pin, i,
				PTR_ERR(app_ctx->desc));
			return PTR_ERR(app_ctx->desc);
		}

		app_ctx->hp_dev = hp_dev;
	}

	return hp_dev->gpio_count;
}

/**
 * cx7_hp_pci_notifier - PCI bus notifier to configure MPS for CX7 devices
 * @nb: notifier block
 * @action: bus notification action
 * @data: pointer to device being added/removed
 *
 * Returns: NOTIFY_OK on success, NOTIFY_DONE if not a CX7 device
 */
static int cx7_hp_pci_notifier(struct notifier_block *nb, unsigned long action,
				void *data)
{
	struct device *dev = data;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct cx7_hp_dev *hp_dev;
	unsigned long flags;

	if (action != BUS_NOTIFY_ADD_DEVICE)
		return NOTIFY_DONE;

	hp_dev = container_of(nb, struct cx7_hp_dev, pci_notifier);
	if (!hp_dev || !hp_dev->pd)
		return NOTIFY_DONE;

	spin_lock_irqsave(&hp_dev->lock, flags);
	if (!hp_dev->hotplug_enabled) {
		spin_unlock_irqrestore(&hp_dev->lock, flags);
		return NOTIFY_DONE;
	}
	spin_unlock_irqrestore(&hp_dev->lock, flags);

	if (!pdev || !hp_dev->pd->vendor_id || !hp_dev->pd->device_id)
		return NOTIFY_DONE;

	if (pdev->vendor != hp_dev->pd->vendor_id ||
	    pdev->device != hp_dev->pd->device_id)
		return NOTIFY_DONE;

	if (pdev->bus)
		pcie_bus_configure_settings(pdev->bus);

	return NOTIFY_OK;
}

/**
 * cx7_hp_probe - Platform device probe function
 * @pdev: platform device
 *
 * Initializes the PCIe hotplug driver, parses ACPI resources, and sets up
 * GPIO interrupts and sysfs interface.
 *
 * Returns: 0 on success, negative error code on failure
 */
static int cx7_hp_probe(struct platform_device *pdev)
{
	struct cx7_hp_plat_data *pd;
	struct cx7_hp_gpio_ctx *app_ctx;
	struct cx7_hp_dev *hp_dev;
	int ret, i;

	pd = devm_kzalloc(&pdev->dev, sizeof(*pd), GFP_KERNEL);
	if (!pd) {
		dev_err(&pdev->dev,
			"Failed to allocate memory for platform data\n");
		return -ENOMEM;
	}

	ret = cx7_hp_init_pcie_data(pdev, pd);
	if (ret)
		return ret;

	hp_dev = devm_kzalloc(&pdev->dev, sizeof(*hp_dev), GFP_KERNEL);
	if (!hp_dev) {
		dev_err(&pdev->dev,
			"Failed to allocate memory for hotplug device\n");
		return -ENOMEM;
	}

	hp_dev->pdev = pdev;
	hp_dev->pd = pd;
	hp_dev->state = STATE_READY;
	hp_dev->boot_pin = -1;
	hp_dev->prsnt_pin = -1;
	hp_dev->hotplug_enabled = false;
	spin_lock_init(&hp_dev->lock);

	for (i = 0; i < HP_PORT_MAX; i++)
		hp_dev->cached_root_ports[i] = NULL;

	ret = cx7_hp_enumerate_gpios(pdev, hp_dev);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to enumerate GPIOs from ACPI: %d\n",
			ret);
		return ret;
	}

	for (i = 0; i < hp_dev->gpio_count; i++) {
		app_ctx = &hp_dev->pins[i];

		app_ctx->ctx = gpio_acpi_setup(pdev, app_ctx->desc, hp_dev, i);
		if (!app_ctx->ctx) {
			dev_err(&pdev->dev, "Failed to setup GPIO %d\n", i);
			return -ENODEV;
		}

		gpiod_set_debounce(app_ctx->desc,
				   app_ctx->ctx->debounce_timeout_us);

		if (app_ctx->ctx->connection_type ==
		    ACPI_RESOURCE_GPIO_TYPE_INT) {
			ret = cx7_hp_setup_irq(app_ctx);
			if (ret) {
				dev_err(&pdev->dev,
					"Failed to setup IRQ for GPIO %d\n", i);
				return ret;
			}
		}
	}

	platform_set_drvdata(pdev, hp_dev);

	ret = cx7_hp_pinctrl_init(hp_dev);
	if (ret) {
		dev_err(&pdev->dev, "Pinmux init failed, ret: %d\n", ret);
		return ret;
	}

	ret = sysfs_create_group(&pdev->dev.kobj, &cx7_hp_attr_group);
	if (ret) {
		dev_err(&pdev->dev, "Sysfs creation failed: %d\n", ret);
		goto pinctrl_remove;
	}

	cx7_hp_rp_bus_protect(hp_dev, 0, BUS_PROTECT_INIT);

	hp_dev->pci_notifier.notifier_call = cx7_hp_pci_notifier;
	ret = bus_register_notifier(&pci_bus_type, &hp_dev->pci_notifier);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register PCI bus notifier: %d\n",
			ret);
		goto sysfs_remove;
	}

	if (gpiod_get_value(hp_dev->pins[PCIE_PIN_PRSNT].desc)) {
		hp_dev->debug_state = CX7_HP_DEBUG_PLUG_OUT;
		cx7_hp_send_uevent(hp_dev, REMOVAL_EVT);
	} else {
		hp_dev->debug_state = CX7_HP_DEBUG_PLUG_IN;
		cx7_hp_send_uevent(hp_dev, PLUG_IN_EVT);
	}

	dev_info(&pdev->dev, "PCIe hotplug driver initialized successfully\n");
	return 0;

sysfs_remove:
	sysfs_remove_group(&pdev->dev.kobj, &cx7_hp_attr_group);
pinctrl_remove:
	cx7_hp_pinctrl_remove(hp_dev);
	return ret;
}

/**
 * cx7_hp_remove - Platform device remove function
 * @pdev: platform device
 *
 * Cleans up GPIO pins, pinctrl, sysfs interface, and bus protection.
 */
static void cx7_hp_remove(struct platform_device *pdev)
{
	struct cx7_hp_dev *hp_dev = platform_get_drvdata(pdev);
	int i;

	if (!hp_dev)
		return;

	sysfs_remove_group(&pdev->dev.kobj, &cx7_hp_attr_group);

	bus_unregister_notifier(&pci_bus_type, &hp_dev->pci_notifier);

	cx7_hp_rp_bus_protect(hp_dev, 0, BUS_PROTECT_CLEANUP);

	cx7_hp_pinctrl_remove(hp_dev);

	for (i = 0; i < hp_dev->pd->port_nums; i++) {
		if (hp_dev->cached_root_ports[i])
			pci_dev_put(hp_dev->cached_root_ports[i]);
	}

	platform_set_drvdata(pdev, NULL);
}

static const struct acpi_device_id cx7_hp_acpi_match[] = {
	{"MTKP0001", 0},
	{}
};

MODULE_DEVICE_TABLE(acpi, cx7_hp_acpi_match);

static struct platform_driver cx7_hp_driver = {
	.probe = cx7_hp_probe,
	.remove = cx7_hp_remove,
	.driver = {
		.name = "cx7-pcie-hotplug",
		.acpi_match_table = ACPI_PTR(cx7_hp_acpi_match),
	},
};

module_platform_driver(cx7_hp_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CX7 PCIe Hotplug Driver for NVIDIA DGX Systems");
