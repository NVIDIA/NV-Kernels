// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2014-2025 MediaTek Inc.
/*
 * MediaTek EINT driver for NVIDIA CX7 NIC hotplug management
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

#define HP_PORT_MAX		3
#define HP_POLL_CNT_MAX		200
#define MT8901_PCIE_REG_SIZE	0x1000
#define MAX_VENDOR_DATA_LEN	16

#define PLUG_IN_EVT "HOTPLUG_STATE=plugin"
#define REMOVAL_EVT "HOTPLUG_STATE=removal"

/*
 * Use bus protect to prevent pcie core_reset glitch issue.
 * stage 1: disable pcie ltssm
 * stage 2: set bus protection and enable pcie ltssm
 */
#define BUS_PROTECT_CABLE_REMOVAL	1
#define BUS_PROTECT_CABLE_PLUGIN	2

#define CX7_PCI_VENDOR_ID	PCI_VENDOR_ID_MELLANOX
#define CX7_PCI_DEVICE_ID	0x1021

static int gp_boot_pin, gp_prsnt_pin;

static void __iomem *hp_mac_base[HP_PORT_MAX];
static void __iomem *hp_top_base;
static void __iomem *hp_protect_base;
static void __iomem *hp_ckm_base;

enum cx7_hp_state {
	STATE_READY = 0,
	STATE_PLUG_OUT,		/* both QSFP plug-out */
	STATE_DEV_POWER_OFF,	/* device is power off */
	STATE_PLUG_IN,		/* one QSFP plug-in */
	STATE_DEV_POWER_ON,	/* device is power on */
	STATE_DEV_FW_START,     /* device fw is running */
	STATE_RESCAN,		/* device fw is ready, we can perform rescan */
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

struct rp_bus_mmio_top {
	phys_addr_t addr;
	u32 ctrl;
	u32 port_bits[HP_PORT_MAX];
	u32 update_bit;
};

struct rp_bus_mmio_protect {
	phys_addr_t addr;
	u32 mode;
	u32 enable;
	u32 port_bits[HP_PORT_MAX];
};

struct rp_bus_mmio_mac {
	phys_addr_t addr[HP_PORT_MAX];
	u32 init_ctrl;
	u32 ltssm_bit;
	u32 phy_rst_bit;
};

struct rp_bus_mmio_ckm {
	phys_addr_t addr;
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
	unsigned int debounce_timeout_us; /* in microseconds */
	int pin;
	int wake_capable;
	int triggering;
	int polarity;
	unsigned long irq_flags;
	int valid;
	unsigned int connection_type;
	char vendor_data[MAX_VENDOR_DATA_LEN + 1];
};

struct cx7_hp_plat_data {
	int port_nums;
	int ports[HP_PORT_MAX];
	int num_cx7_devices;
	/* rp bus protect */
	struct rp_bus_mmio_info rp_bus_mmio;
	void (*rp_bus_prepare)(struct platform_device *pdev, bool init);
	void (*rp_bus_protect)(struct platform_device *pdev, int domain, int stage);
	u32 ltssm;
	u32 S_L0;
	/* pinctrl */
	int pin_nums;
	struct pinctrl_map pinmap[];
};

struct cx7_eint_app_ctx {
	struct gpio_desc *desc;
	struct gpio_acpi_context *ctx;
	struct cx7_hp_dev *hp_dev;
};

struct cx7_hp_dev {
	struct cx7_eint_app_ctx *pins;
	struct cx7_hp_plat_data *pd;
	struct platform_device *pdev;
	enum cx7_hp_state state;
	int gpio_count;
};

enum cx7_debug_simulation_val {
	CX7_DEBUG_SIMULATION_PLUG_OUT = 0,
	CX7_DEBUG_SIMULATION_PLUG_IN,
	CX7_DEBUG_SIMULATION_REMOVE_DEVICES,
	CX7_DEBUG_SIMULATION_RESCAN_DEVICES,
	CX7_DEBUG_SIMULATION_MAX_VAL
};

enum cx7_debug_simulation_val dbg_plugin_global;

static struct cx7_hp_dev *hp_dev_global;

static int cx7_hp_pinctrl_init(struct platform_device *pdev)
{
	int ret;

	struct cx7_hp_dev *hp_dev =
		(struct cx7_hp_dev *)pdev->dev.platform_data;

	ret = pinctrl_register_mappings(hp_dev->pd->pinmap, hp_dev->pd->pin_nums);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register pinctrl mappings\n");
		return ret;
	}

	return 0;
}

static void cx7_hp_pinctrl_remove(struct platform_device *pdev)
{
	struct cx7_hp_dev *hp_dev =
		(struct cx7_hp_dev *)pdev->dev.platform_data;

	pinctrl_unregister_mappings(hp_dev->pd->pinmap);
}

static int cx7_hp_change_state(struct platform_device *pdev, const char *new_state)
{
	struct pinctrl *pinctrl;
	struct pinctrl_state *state;
	int ret;

	pinctrl = devm_pinctrl_get(&pdev->dev);
	if (IS_ERR(pinctrl)) {
		dev_err(&pdev->dev, "Failed to get pinctrl\n");
		return PTR_ERR(pinctrl);
	}

	state = pinctrl_lookup_state(pinctrl, new_state);
	if (IS_ERR(state)) {
		dev_err(&pdev->dev, "Failed to lookup state:%s\n", new_state);
		return PTR_ERR(state);
	}

	ret = pinctrl_select_state(pinctrl, state);
	if (ret) {
		dev_err(&pdev->dev, "Failed to select pinctrl state:%s\n", new_state);
		return ret;
	}

	return 0;
}

static void cx7_send_uevent(struct platform_device *pdev, const char *msg)
{
	char *uevent = NULL;
	char *envp[2];

	uevent = kasprintf(GFP_KERNEL, msg);
	if (!uevent) {
		dev_err(&pdev->dev, "Failed to allocate uevent string\n");
		return;
	}

	envp[0] = uevent;
	envp[1] = NULL;

	if (kobject_uevent_env(&pdev->dev.kobj, KOBJ_CHANGE, envp))
		dev_err(&pdev->dev, "Failed to send uevent\n");

	kfree(uevent);
}

static void cx7_hp_ckm_control(struct cx7_hp_dev *dev, bool disable)
{
	struct rp_bus_mmio_info *mmio_info = &dev->pd->rp_bus_mmio;
	void __iomem *addr;
	u32 val;

	addr = hp_ckm_base + mmio_info->ckm.ctrl;
	if (disable) {
		val = readl(addr);
		val = val | mmio_info->ckm.disable_bit;
		writel(val, addr);
	} else {
		val = readl(addr);
		val = val & (~mmio_info->ckm.disable_bit);
		writel(val, addr);
	}
}

static void mt8901_rp_bus_prepare(struct platform_device *pdev, bool init)
{
	struct cx7_hp_dev *dev = (struct cx7_hp_dev *)pdev->dev.platform_data;
	struct rp_bus_mmio_info *mmio_info = &dev->pd->rp_bus_mmio;
	int i;

	if (init) {
		for (i = 0; i < HP_PORT_MAX; i++) {
			if (mmio_info->mac.addr[i])
				hp_mac_base[i] = ioremap(mmio_info->mac.addr[i],
							 MT8901_PCIE_REG_SIZE);
		}
		hp_top_base = ioremap(mmio_info->top.addr, MT8901_PCIE_REG_SIZE);
		hp_protect_base = ioremap(mmio_info->protect.addr, MT8901_PCIE_REG_SIZE);
		hp_ckm_base = ioremap(mmio_info->ckm.addr, MT8901_PCIE_REG_SIZE);
	} else {
		for (i = 0; i < HP_PORT_MAX; i++) {
			if (hp_mac_base[i])
				iounmap(hp_mac_base[i]);
		}
		if (hp_top_base)
			iounmap(hp_top_base);
		if (hp_protect_base)
			iounmap(hp_protect_base);
		if (hp_ckm_base)
			iounmap(hp_ckm_base);
	}
}

static void mt8901_rp_bus_protect(struct platform_device *pdev, int domain, int stage)
{
	struct cx7_hp_dev *dev = (struct cx7_hp_dev *)pdev->dev.platform_data;
	struct rp_bus_mmio_info *mmio_info = &dev->pd->rp_bus_mmio;
	int port;
	u32 val;

	for (port = 0; port < HP_PORT_MAX; port++) {
		if (domain == dev->pd->ports[port])
			break;
	}

	if (port == HP_PORT_MAX)
		return;

	if (stage == BUS_PROTECT_CABLE_REMOVAL) {
		/* deassert ltssm_en */
		val = readl(hp_mac_base[port] + mmio_info->mac.init_ctrl);
		val &= ~mmio_info->mac.ltssm_bit;
		writel(val, hp_mac_base[port] + mmio_info->mac.init_ctrl);
		val &= ~mmio_info->mac.phy_rst_bit;
		writel(val, hp_mac_base[port] + mmio_info->mac.init_ctrl);
	}

	if (stage == BUS_PROTECT_CABLE_PLUGIN) {
		/* deassert way_en */
		val = readl(hp_top_base + mmio_info->top.ctrl);
		val &= ~mmio_info->top.port_bits[port];
		writel(val, hp_top_base + mmio_info->top.ctrl);
		val &= ~mmio_info->top.update_bit;
		writel(val, hp_top_base + mmio_info->top.ctrl);
		val |= mmio_info->top.update_bit;
		writel(val, hp_top_base + mmio_info->top.ctrl);
		udelay(10);

		/* assert bus_protect_en_bits */
		val = readl(hp_protect_base + mmio_info->protect.mode);
		val |= mmio_info->protect.port_bits[port];
		writel(val, hp_protect_base + mmio_info->protect.mode);
		val = readl(hp_protect_base + mmio_info->protect.enable);
		val |= mmio_info->protect.port_bits[port];
		writel(val, hp_protect_base + mmio_info->protect.enable);
		usleep_range(5000, 6000);

		/* assert ltssm_en */
		val = readl(hp_mac_base[port] + mmio_info->mac.init_ctrl);
		val |= mmio_info->mac.phy_rst_bit;
		writel(val, hp_mac_base[port] + mmio_info->mac.init_ctrl);
		val |= mmio_info->mac.ltssm_bit;
		writel(val, hp_mac_base[port] + mmio_info->mac.init_ctrl);
		usleep_range(3000, 4000);

		/* deassert bus_protect_en_bits */
		val = readl(hp_protect_base + mmio_info->protect.enable);
		val &= ~mmio_info->protect.port_bits[port];
		writel(val, hp_protect_base + mmio_info->protect.enable);
		val = readl(hp_protect_base + mmio_info->protect.mode);
		val &= ~mmio_info->protect.port_bits[port];
		writel(val, hp_protect_base + mmio_info->protect.mode);

		/* assert way_en */
		val = readl(hp_top_base + mmio_info->top.ctrl);
		val |= mmio_info->top.port_bits[port];
		writel(val, hp_top_base + mmio_info->top.ctrl);
		val &= ~mmio_info->top.update_bit;
		writel(val, hp_top_base + mmio_info->top.ctrl);
		val |= mmio_info->top.update_bit;
		writel(val, hp_top_base + mmio_info->top.ctrl);
	}
}

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
		usleep_range(10000, 11000);
	}

	pcie_capability_write_word(dev, PCI_EXP_LNKSTA, PCI_EXP_LNKSTA_LBMS);
}

static struct pci_dev *
find_device_by_bus_devfn(struct device *dev, int domain, int bus, int devfn)
{
	struct pci_dev *pdev;

	pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
	if (!pdev) {
		dev_err(dev, "PCI device not found by %x:%x:%x\n", domain, bus, devfn);
		return NULL;
	}

	return pdev;
}

static void remove_device_by_domain_bus(int domain, unsigned int bus)
{
	struct pci_dev *dev;

	for_each_pci_dev(dev) {
		if (pci_domain_nr(dev->bus) == domain && dev->bus->number == bus)
			pci_stop_and_remove_bus_device_locked(dev);
	}
}

static void remove_device(struct cx7_hp_dev *dev)
{
	int port;

	if (dev->pd->rp_bus_protect) {
		for (int i = 0; i < dev->pd->port_nums; i++) {
			port = dev->pd->ports[i];
			dev->pd->rp_bus_protect(dev->pdev, port, BUS_PROTECT_CABLE_REMOVAL);
		}
	}

	gpiod_set_value(dev->pins[PCIE_PIN_PERST].desc, 0);
	cx7_hp_change_state(dev->pdev, "default");
	cx7_hp_ckm_control(dev, true);
	gpiod_set_value(dev->pins[PCIE_PIN_EN].desc, 0);
}

static void polling_link_to_l0(struct cx7_hp_dev *dev)
{
	struct pci_dev *pci_dev;
	u32 ltssm = dev->pd->ltssm;
	u32 STATE_L0 = dev->pd->S_L0;
	u32 ltssm_p0 = 0;
	u32 ltssm_p2 = 0;
	int count = 0;

	while (((ltssm_p0 & STATE_L0) != STATE_L0) ||
	       ((ltssm_p2 & STATE_L0) != STATE_L0)) {
		pci_dev = find_device_by_bus_devfn(&dev->pdev->dev, 0, 0, 0);
		pci_read_config_dword(pci_dev, ltssm, &ltssm_p0);
		pci_dev = find_device_by_bus_devfn(&dev->pdev->dev, 2, 0, 0);
		pci_read_config_dword(pci_dev, ltssm, &ltssm_p2);
		usleep_range(10000, 11000);
		count++;
		if (count > HP_POLL_CNT_MAX) {
			dev_err(&dev->pdev->dev, "reach max count\n");
			break;
		}
	}
}

static void rescan_device(struct cx7_hp_dev *dev)
{
	struct pci_dev *pci_dev;
	int port, err;

	cx7_hp_change_state(dev->pdev, "clkreqn");
	cx7_hp_ckm_control(dev, false);
	usleep_range(10000, 11000);

	for (int i = 0; i < dev->pd->port_nums; i++) {
		port = dev->pd->ports[i];
		pci_dev = find_device_by_bus_devfn(&dev->pdev->dev, port, 0, 0);
		err = pm_runtime_resume_and_get(&pci_dev->dev);
		if (err < 0)
			dev_err(&dev->pdev->dev, "runtime resume failed: %s\n", pci_name(pci_dev));
	}

	gpiod_set_value(dev->pins[PCIE_PIN_PERST].desc, 1);

	if (dev->pd->rp_bus_protect) {
		for (int i = 0; i < dev->pd->port_nums; i++) {
			port = dev->pd->ports[i];
			dev->pd->rp_bus_protect(dev->pdev, port, BUS_PROTECT_CABLE_PLUGIN);
		}
	}

	polling_link_to_l0(dev);
	for (int i = 0; i < dev->pd->port_nums; i++) {
		port = dev->pd->ports[i];
		pci_dev = find_device_by_bus_devfn(&dev->pdev->dev, port, 0, 0);
		retrain_pcie_link(pci_dev);
	}

	/* wait 100ms to ensure gen5 link is stable */
	msleep(100);
}

static irqreturn_t pci_hp_work(int irq, void *dev_id)
{
	struct cx7_eint_app_ctx *app_ctx = dev_id;
	enum cx7_hp_state *state;

	state = &app_ctx->hp_dev->state;

	switch (*state) {
	case STATE_PLUG_OUT:
		dev_dbg(app_ctx->ctx->dev, "Cable plug out\n");
		remove_device(app_ctx->hp_dev);
		break;
	case STATE_PLUG_IN:
		dev_dbg(app_ctx->ctx->dev, "Enable device power\n");
		gpiod_set_value(app_ctx->hp_dev->pins[PCIE_PIN_EN].desc, 1);
		break;
	case STATE_DEV_POWER_OFF:
	case STATE_DEV_POWER_ON:
	case STATE_DEV_FW_START:
		dev_dbg(app_ctx->ctx->dev, "Do nothing, keep current state\n");
		break;
	case STATE_RESCAN:
		dev_dbg(app_ctx->ctx->dev, "Cable plug in\n");
		rescan_device(app_ctx->hp_dev);
		app_ctx->hp_dev->state = STATE_READY;
		break;
	default:
		dev_err(app_ctx->ctx->dev, "Error: Unknown State !!!\n");
		break;
	}

	return IRQ_HANDLED;
}

static irqreturn_t hotplug_irq_handler(int irq, void *dev_id)
{
	struct cx7_eint_app_ctx *app_ctx = dev_id;
	struct gpio_acpi_context *gpio_ctx = app_ctx->ctx;
	int value;
	enum cx7_hp_state *state;

	state = &app_ctx->hp_dev->state;
	value = gpiod_get_value(app_ctx->desc);

	if (gpio_ctx->pin == gp_prsnt_pin && value) {
		dev_dbg(app_ctx->ctx->dev, "PRSNT_FROM_0_TO_1, cable removal\n");
		cx7_send_uevent(app_ctx->hp_dev->pdev, REMOVAL_EVT);
		return IRQ_HANDLED;
	} else if (gpio_ctx->pin == gp_prsnt_pin) {
		dev_dbg(app_ctx->ctx->dev, "PRSNT_FROM_1_TO_0, cable plug-in\n");
		cx7_send_uevent(app_ctx->hp_dev->pdev, PLUG_IN_EVT);
		return IRQ_HANDLED;
	} else if (gpio_ctx->pin == gp_boot_pin && value && *state == STATE_PLUG_IN) {
		dev_dbg(app_ctx->ctx->dev, "BOOT_FROM_0_TO_1, device is power on\n");
		*state = STATE_DEV_POWER_ON;
	} else if (gpio_ctx->pin == gp_boot_pin && value && *state == STATE_DEV_FW_START) {
		dev_dbg(app_ctx->ctx->dev, "BOOT_FROM_0_TO_1, device is ready\n");
		*state = STATE_RESCAN;
	} else if (gpio_ctx->pin == gp_boot_pin && *state == STATE_DEV_POWER_ON) {
		dev_dbg(app_ctx->ctx->dev, "BOOT_FROM_1_TO_0, device fw is start\n");
		*state = STATE_DEV_FW_START;
	} else if (gpio_ctx->pin == gp_boot_pin && *state == STATE_PLUG_OUT) {
		dev_dbg(app_ctx->ctx->dev, "Device power is off\n");
		*state = STATE_DEV_POWER_OFF;
	} else {
		dev_err(app_ctx->ctx->dev, "Unknown event: gpio pin = %d, IRQ = %d, value = %d\n",
			gpio_ctx->pin, irq, value);
		return IRQ_HANDLED;
	}

	return IRQ_WAKE_THREAD;
}

static acpi_status acpi_gpio_resource_handler(struct acpi_resource *ares, void *context)
{
	struct gpio_acpi_context *ctx = context;
	struct acpi_resource_gpio *agpio;
	int length;

	if (ares->type == ACPI_RESOURCE_TYPE_GPIO) {
		agpio = &ares->data.gpio;

		if (ctx->pin != agpio->pin_table[0])
			return AE_OK;

		ctx->valid = 1;
		ctx->debounce_timeout_us = agpio->debounce_timeout * 10;
		ctx->wake_capable = agpio->wake_capable;
		ctx->triggering = agpio->triggering;
		ctx->polarity = agpio->polarity;
		ctx->connection_type = agpio->connection_type;

		if (agpio->vendor_length) {
			length = agpio->vendor_length;

			if (length > MAX_VENDOR_DATA_LEN)
				length = MAX_VENDOR_DATA_LEN;

			memcpy(&ctx->vendor_data[0], agpio->vendor_data, length);
			ctx->vendor_data[MAX_VENDOR_DATA_LEN] = 0;

			if (!strncmp("BOOT", ctx->vendor_data, strlen("BOOT")))
				gp_boot_pin = ctx->pin;

			else if (!strncmp("PRSNT", ctx->vendor_data, strlen("PRSNT")))
				gp_prsnt_pin = ctx->pin;
		}

		if (agpio->triggering == ACPI_EDGE_SENSITIVE) {
			if (agpio->polarity == ACPI_ACTIVE_LOW)
				ctx->irq_flags = IRQF_TRIGGER_FALLING;
			else if (agpio->polarity == ACPI_ACTIVE_HIGH)
				ctx->irq_flags = IRQF_TRIGGER_RISING;
			else
				ctx->irq_flags = (IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING);
		} else {
			if (agpio->polarity == ACPI_ACTIVE_LOW)
				ctx->irq_flags = IRQF_TRIGGER_LOW;
			else
				ctx->irq_flags = IRQF_TRIGGER_HIGH;
		}
	}

	return AE_OK;
}

static ssize_t plugin_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", dbg_plugin_global);
}

static ssize_t plugin_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct pci_dev *pci_dev;
	struct pci_bus *bus;
	unsigned long val;
	int err;

	err = kstrtoul(buf, 10, &val);
	if (err)
		return err;

	switch (val) {
	case CX7_DEBUG_SIMULATION_PLUG_OUT:
		dev_dbg(dev, "Plug out simulation\n");
		hp_dev_global->state = STATE_PLUG_OUT;
		remove_device(hp_dev_global);
		break;

	case CX7_DEBUG_SIMULATION_PLUG_IN:
		dev_dbg(dev, "Plug in simulation\n");
		hp_dev_global->state = STATE_PLUG_IN;
		gpiod_set_value(hp_dev_global->pins[PCIE_PIN_EN].desc, 1);
		break;

	case CX7_DEBUG_SIMULATION_REMOVE_DEVICES:
		dev_dbg(dev, "Remove devices simulation\n");
		pci_dev = find_device_by_bus_devfn(dev, 0, 1, 0);
		if (pci_dev)
			pci_stop_and_remove_bus_device_locked(pci_dev);

		remove_device_by_domain_bus(2, 1);
		break;

	case CX7_DEBUG_SIMULATION_RESCAN_DEVICES:
		dev_dbg(dev, "Rescan devices simulation\n");
		bus = pci_find_bus(0, 0);
		if (bus) {
			pci_lock_rescan_remove();
			pci_rescan_bus(bus);
			pci_unlock_rescan_remove();
		}

		bus = pci_find_bus(2, 0);
		if (bus) {
			pci_lock_rescan_remove();
			pci_rescan_bus(bus);
			pci_unlock_rescan_remove();
		}
		break;

	default:
		return -EINVAL;
	}

	dbg_plugin_global = val;

	return count;
}

DEVICE_ATTR_RW(plugin);

static struct attribute *root_attrs[] = {
	&dev_attr_plugin.attr,
	NULL
};

static const struct attribute_group root_attr_group = {
	.name = "cx7_dbg",
	.attrs = root_attrs
};

static struct gpio_acpi_context *gpio_acpi_setup(struct platform_device *pdev,
						 struct gpio_desc *desc)
{
	struct gpio_acpi_context *ctx;
	struct acpi_device *adev;

	adev = ACPI_COMPANION(&pdev->dev);
	if (!adev) {
		dev_err(&pdev->dev, "Failed to get ACPI companion device\n");
		return NULL;
	}

	ctx = devm_kzalloc(&pdev->dev, sizeof(*ctx), GFP_KERNEL);
	ctx->pin = desc_to_gpio(desc) - gpio_device_get_base(gpiod_to_gpio_device(desc));
	ctx->dev = &pdev->dev;

	acpi_walk_resources(adev->handle, METHOD_NAME__CRS,
			    acpi_gpio_resource_handler, ctx);

	if (ctx->valid)
		return ctx;

	devm_kfree(&pdev->dev, ctx);
	return NULL;
}

static int cx7_hp_setup_irq(struct cx7_eint_app_ctx *app_ctx)
{
	struct gpio_acpi_context *ctx = app_ctx->ctx;
	int irq, ret;

	irq = gpiod_to_irq(app_ctx->desc);

	if (ctx->wake_capable)
		enable_irq_wake(irq);

	ret = devm_request_threaded_irq(ctx->dev, irq,
					hotplug_irq_handler, pci_hp_work,
					ctx->irq_flags | IRQF_ONESHOT, "cx7 hotplug", app_ctx);
	if (ret)
		dev_err(ctx->dev, "Failed to request IRQ: %d\n", irq);

	return ret;
}

static int cx7_hp_probe_io_info(struct platform_device *pdev)
{
	struct gpio_desc *desc;
	int count = 0;

	for (;;) {
		desc = gpiod_get_index(&pdev->dev, NULL, count, GPIOD_ASIS);
		if (IS_ERR(desc))
			break;
		count++;
		gpiod_put(desc);
	}

	return count;
}

static int cx7_hp_probe(struct platform_device *pdev)
{
	struct cx7_hp_plat_data *pd = (struct cx7_hp_plat_data *)device_get_match_data(&pdev->dev);
	struct cx7_eint_app_ctx *app_ctx;
	struct cx7_hp_dev *hp_dev;
	struct pci_dev *pci_dev = NULL;
	int ret, i, cx7_device_count = 0;

	if (hp_dev_global) {
		dev_err(&pdev->dev, "CX7 hotplug already registered\n");
		return -EINVAL;
	}

	if (!pd || pd->port_nums >= HP_PORT_MAX) {
		dev_err(&pdev->dev, "CX7 hotplug platform data invalid\n");
		return -EINVAL;
	}

	while ((pci_dev = pci_get_device(CX7_PCI_VENDOR_ID, CX7_PCI_DEVICE_ID, pci_dev)) != NULL) {
		if (!pci_dev->state_saved)
			return -EPROBE_DEFER;

		for (i = 0; i < pd->port_nums; i++) {
			if (pci_domain_nr(pci_dev->bus) == pd->ports[i])
				break;
		}

		if (i == pd->port_nums) {
			dev_err(&pdev->dev,
				"CX7 device found in unexpected port %d\n",
				pci_domain_nr(pci_dev->bus));
			return -ENODEV;
		}

		cx7_device_count++;
	}

	if (cx7_device_count != pd->num_cx7_devices) {
		dev_err(&pdev->dev,
			"Required number of CX7 devices not found. Expected=%d Actual=%d\n",
			pd->num_cx7_devices, cx7_device_count);
		return -ENODEV;
	}

	hp_dev = devm_kzalloc(&pdev->dev, sizeof(*hp_dev), GFP_KERNEL);
	if (!hp_dev) {
		dev_err(&pdev->dev, "Failed to allocate memory for hotplug device\n");
		return -ENOMEM;
	}

	hp_dev->gpio_count = cx7_hp_probe_io_info(pdev);
	if (!hp_dev->gpio_count) {
		dev_err(&pdev->dev, "Failed to get gpio descriptors\n");
		return -ENODEV;
	}

	hp_dev->pins = devm_kzalloc(&pdev->dev,
				    sizeof(struct cx7_eint_app_ctx) * hp_dev->gpio_count,
				    GFP_KERNEL);
	if (!hp_dev->pins) {
		dev_err(&pdev->dev, "Failed to allocate memory for GPIOs\n");
		return -ENOMEM;
	}

	hp_dev->pdev = pdev;
	hp_dev->pd = pd;

	for (i = 0; i < hp_dev->gpio_count; i++) {
		app_ctx = &hp_dev->pins[i];
		app_ctx->desc = gpiod_get_index(&pdev->dev, NULL, i, GPIOD_ASIS);
		if (IS_ERR(app_ctx->desc)) {
			dev_err(&pdev->dev, "Failed to get GPIO descriptor: %d\n", i);
			ret = PTR_ERR(app_ctx->desc);
			app_ctx->desc = NULL;
			goto gpio_release;
		}

		app_ctx->ctx = gpio_acpi_setup(pdev, app_ctx->desc);
		if (!app_ctx->ctx) {
			dev_err(&pdev->dev, "Failed to setup GPIO descriptor: %d\n", i);
			ret = -ENODEV;
			goto gpio_release;
		}

		gpiod_set_debounce(app_ctx->desc, app_ctx->ctx->debounce_timeout_us);
		if (app_ctx->ctx->connection_type == ACPI_RESOURCE_GPIO_TYPE_INT) {
			app_ctx->hp_dev = hp_dev;
			ret = cx7_hp_setup_irq(app_ctx);
			if (ret) {
				dev_err(&pdev->dev, "Failed to setup IRQ: %d\n", i);
				goto gpio_release;
			}
		}
	}

	pdev->dev.platform_data = (void *)hp_dev;

	ret = cx7_hp_pinctrl_init(pdev);
	if (ret) {
		dev_err(&pdev->dev, "Pinmux init failed, ret: %d\n", ret);
		goto gpio_release;
	}

	hp_dev_global = hp_dev;

	/* sysfs */
	ret = sysfs_create_group(&pdev->dev.kobj, &root_attr_group);
	if (ret) {
		dev_err(&pdev->dev, "Sysfs create failed, ret: %d\n", ret);
		goto pinctrl_remove;
	}

	if (hp_dev->pd->rp_bus_prepare)
		hp_dev->pd->rp_bus_prepare(pdev, true);

	/* Send uevent for cable removal or plug-in */
	if (gpiod_get_value(hp_dev->pins[PCIE_PIN_PRSNT].desc)) {
		dbg_plugin_global = CX7_DEBUG_SIMULATION_PLUG_OUT;
		cx7_send_uevent(pdev, REMOVAL_EVT);
	} else {
		dbg_plugin_global = CX7_DEBUG_SIMULATION_PLUG_IN;
		cx7_send_uevent(pdev, PLUG_IN_EVT);
	}

	return 0;

pinctrl_remove:
	cx7_hp_pinctrl_remove(pdev);
gpio_release:
	for (i = 0; i < hp_dev->gpio_count; i++) {
		app_ctx = &hp_dev->pins[i];
		if (app_ctx->desc)
			gpiod_put(app_ctx->desc);
	}

	hp_dev_global = NULL;
	return ret;
}

static void cx7_hp_remove(struct platform_device *pdev)
{
	struct cx7_hp_dev *hp_dev =
		(struct cx7_hp_dev *)pdev->dev.platform_data;
	struct cx7_eint_app_ctx *app_ctx;

	if (!hp_dev)
		return;

	/* sysfs */
	sysfs_remove_group(&pdev->dev.kobj, &root_attr_group);
	if (hp_dev->pd->rp_bus_prepare)
		hp_dev->pd->rp_bus_prepare(pdev, false);
	cx7_hp_pinctrl_remove(pdev);
	for (int i = 0; i < hp_dev->gpio_count; i++) {
		app_ctx = &hp_dev->pins[i];
		if (app_ctx->desc)
			gpiod_put(app_ctx->desc);
	}
	pdev->dev.platform_data = 0;
	hp_dev_global = NULL;
}

static const struct cx7_hp_plat_data mt8901_plat_data = {
	.port_nums = 2,
	.ports = {0, 2},
	.num_cx7_devices = 4,
	.rp_bus_mmio = {
		.top = {
			.addr = 0x1d600000,
			.ctrl = 0x400,
			.update_bit = BIT(24),
			.port_bits = {BIT(6), BIT(2)},
		},
		.protect = {
			.addr = 0x1d640000,
			.mode = 0x38,
			.enable = 0x40,
			.port_bits = {BIT(20), BIT(16)},
		},
		.mac = {
			.addr = {0x1d790000, 0x1d690000},
			.init_ctrl = 0x008,
			.ltssm_bit = BIT(0),
			.phy_rst_bit = BIT(8),
		},
		.ckm = {
			.addr = 0x16bd0000,
			.ctrl = 0xa8,
			.disable_bit = BIT(5) | BIT(7),
		},
	},
	.rp_bus_prepare = mt8901_rp_bus_prepare,
	.rp_bus_protect = mt8901_rp_bus_protect,
	.ltssm = 0x728,
	.S_L0 = 0x11,
	.pin_nums = 4,
	.pinmap = {
		PIN_MAP_MUX_GROUP("MTKP0001:00", "default", "NVDA9221:00", "GPIO177", "func0"),
		PIN_MAP_MUX_GROUP("MTKP0001:00", "default", "NVDA9221:00", "GPIO178", "func0"),
		PIN_MAP_MUX_GROUP("MTKP0001:00", "clkreqn", "NVDA9221:00", "GPIO177", "func1"),
		PIN_MAP_MUX_GROUP("MTKP0001:00", "clkreqn", "NVDA9221:00", "GPIO178", "func1"),
	}
};

static const struct acpi_device_id cx7_hp_acpi_match[] = {
	{"MTKP0001", (kernel_ulong_t)&mt8901_plat_data},
	{}
};

MODULE_DEVICE_TABLE(acpi, cx7_hp_acpi_match);

static struct platform_driver cx7_hp_driver = {
	.probe = cx7_hp_probe,
	.remove = cx7_hp_remove,
	.driver = {
		.name = "cx7_hp",
		.acpi_match_table = ACPI_PTR(cx7_hp_acpi_match),
	},
};

module_platform_driver(cx7_hp_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MediaTek EINT driver for NVIDIA CX7 hotplug");
