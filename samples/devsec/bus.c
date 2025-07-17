// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2024 - 2025 Intel Corporation. All rights reserved.

#include <linux/bitfield.h>
#include <linux/cleanup.h>
#include <linux/device/faux.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci-ide.h>
#include <linux/range.h>
#include <uapi/linux/pci_regs.h>

#include "../../drivers/pci/pci-bridge-emul.h"
#include "devsec.h"

#define NR_DEVSEC_BUSES 1
#define NR_DEVICES_PER_BUS 1
#define NR_FUNCTIONS 2
#define NR_DEVICES (NR_DEVICES_PER_BUS * NR_FUNCTIONS * NR_DEVSEC_BUSES)
#define NR_PLATFORM_STREAMS 4
#define NR_PORT_STREAMS 1
#define NR_PORT_LINK_STREAMS 4
#define NR_ADDR_ASSOC 1

struct devsec {
	struct pci_host_bridge hb;
	struct devsec_sysdata sysdata;
	struct resource busnr_res;
	struct resource mmio_res;
	struct resource prefetch_res;
	struct pci_bus *bus;
	struct device *dev;
	struct devsec_port {
		union {
			struct devsec_ide {
				u32 cap;
				u32 ctl;
				struct devsec_link_stream {
					u32 ctl;
					u32 status;
				} link_stream[NR_PORT_LINK_STREAMS];
				struct devsec_stream {
					u32 cap;
					u32 ctl;
					u32 status;
					u32 rid1;
					u32 rid2;
					struct devsec_addr_assoc {
						u32 assoc1;
						u32 assoc2;
						u32 assoc3;
					} assoc[NR_ADDR_ASSOC];
				} stream[NR_PORT_STREAMS];
			} ide __packed;
			char ide_regs[sizeof(struct devsec_ide)];
		};
		struct pci_bridge_emul bridge;
	} *devsec_ports[NR_DEVSEC_BUSES];
	struct devsec_dev {
		struct devsec *devsec;
		struct range mmio_range;
		u8 __cfg[SZ_4K];
		struct devsec_dev_doe {
			int cap;
			u32 req[SZ_4K / sizeof(u32)];
			u32 rsp[SZ_4K / sizeof(u32)];
			int write, read, read_ttl;
		} doe;
		u16 ide_pos;
		union {
			struct devsec_ide ide __packed;
			char ide_regs[sizeof(struct devsec_ide)];
		};
	} *devsec_devs[NR_DEVICES];
};

#define devsec_base(x) ((void __force __iomem *) &(x)->__cfg[0])

static struct devsec *bus_to_devsec(struct pci_bus *bus)
{
	return container_of(bus->sysdata, struct devsec, sysdata);
}

static int devsec_dev_config_read(struct devsec *devsec, struct pci_bus *bus,
				  unsigned int devfn, int pos, int size,
				  u32 *val)
{
	int fn = PCI_SLOT(devfn) * NR_FUNCTIONS + PCI_FUNC(devfn);
	struct devsec_dev *devsec_dev;
	struct devsec_dev_doe *doe;
	void __iomem *base;

	if (PCI_FUNC(devfn) > NR_FUNCTIONS ||
	    PCI_SLOT(devfn) > NR_DEVICES_PER_BUS ||
	    fn >= ARRAY_SIZE(devsec->devsec_devs))
		return PCIBIOS_DEVICE_NOT_FOUND;

	devsec_dev = devsec->devsec_devs[fn];
	base = devsec_base(devsec_dev);
	doe = &devsec_dev->doe;

	if (doe->cap && pos == doe->cap + PCI_DOE_READ) {
		if (doe->read_ttl > 0) {
			*val = doe->rsp[doe->read];
			dev_dbg(&bus->dev, "devfn: %#x doe read[%d]\n", devfn,
				doe->read);
		} else {
			*val = 0;
			dev_dbg(&bus->dev, "devfn: %#x doe no data\n", devfn);
		}
		return PCIBIOS_SUCCESSFUL;
	} else if (doe->cap && pos == doe->cap + PCI_DOE_STATUS) {
		if (doe->read_ttl > 0) {
			*val = PCI_DOE_STATUS_DATA_OBJECT_READY;
			dev_dbg(&bus->dev, "devfn: %#x object ready\n", devfn);
		} else if (doe->read_ttl < 0) {
			*val = PCI_DOE_STATUS_ERROR;
			dev_dbg(&bus->dev, "devfn: %#x error\n", devfn);
		} else {
			*val = 0;
			dev_dbg(&bus->dev, "devfn: %#x idle\n", devfn);
		}
		return PCIBIOS_SUCCESSFUL;
	} else if (devsec_dev->ide_pos && pos >= devsec_dev->ide_pos &&
		   pos < devsec_dev->ide_pos + sizeof(struct devsec_ide)) {
		*val = *(u32 *) &devsec_dev->ide_regs[pos - devsec_dev->ide_pos];
		return PCIBIOS_SUCCESSFUL;
	}

	switch (size) {
	case 1:
		*val = readb(base + pos);
		break;
	case 2:
		*val = readw(base + pos);
		break;
	case 4:
		*val = readl(base + pos);
		break;
	default:
		PCI_SET_ERROR_RESPONSE(val);
		return PCIBIOS_BAD_REGISTER_NUMBER;
	}
	return PCIBIOS_SUCCESSFUL;
}

static int devsec_port_config_read(struct devsec *devsec, unsigned int devfn,
				   int pos, int size, u32 *val)
{
	struct devsec_port *devsec_port;

	if (PCI_FUNC(devfn) != 0 ||
	    PCI_SLOT(devfn) >= ARRAY_SIZE(devsec->devsec_ports))
		return PCIBIOS_DEVICE_NOT_FOUND;

	devsec_port = devsec->devsec_ports[PCI_SLOT(devfn)];
	return pci_bridge_emul_conf_read(&devsec_port->bridge, pos, size, val);
}

static int devsec_pci_read(struct pci_bus *bus, unsigned int devfn, int pos,
			   int size, u32 *val)
{
	struct devsec *devsec = bus_to_devsec(bus);

	dev_vdbg(&bus->dev, "devfn: %#x pos: %#x size: %d\n", devfn, pos, size);

	if (bus == devsec->hb.bus)
		return devsec_port_config_read(devsec, devfn, pos, size, val);
	else if (bus->parent == devsec->hb.bus)
		return devsec_dev_config_read(devsec, bus, devfn, pos, size,
					      val);

	return PCIBIOS_DEVICE_NOT_FOUND;
}

#ifndef PCI_DOE_PROTOCOL_DISCOVERY
#define PCI_DOE_PROTOCOL_DISCOVERY 0
#define PCI_DOE_FEATURE_CMA 1
#endif

/* just indicate support for CMA */
static void doe_process(struct devsec_dev_doe *doe)
{
	u8 type;
	u16 vid;

	vid = FIELD_GET(PCI_DOE_DATA_OBJECT_HEADER_1_VID, doe->req[0]);
	type = FIELD_GET(PCI_DOE_DATA_OBJECT_HEADER_1_TYPE, doe->req[0]);

	if (vid != PCI_VENDOR_ID_PCI_SIG) {
		doe->read_ttl = -1;
		return;
	}

	if (type != PCI_DOE_PROTOCOL_DISCOVERY) {
		doe->read_ttl = -1;
		return;
	}

	doe->rsp[0] = doe->req[0];
	doe->rsp[1] = FIELD_PREP(PCI_DOE_DATA_OBJECT_HEADER_2_LENGTH, 3);
	doe->read_ttl = 3;
	doe->rsp[2] = FIELD_PREP(PCI_DOE_DATA_OBJECT_DISC_RSP_3_VID,
				 PCI_VENDOR_ID_PCI_SIG) |
		      FIELD_PREP(PCI_DOE_DATA_OBJECT_DISC_RSP_3_PROTOCOL,
				 PCI_DOE_FEATURE_CMA) |
		      FIELD_PREP(PCI_DOE_DATA_OBJECT_DISC_RSP_3_NEXT_INDEX, 0);
}

static int devsec_dev_config_write(struct devsec *devsec, struct pci_bus *bus,
				   unsigned int devfn, int pos, int size,
				   u32 val)
{
	int fn = PCI_SLOT(devfn) * NR_FUNCTIONS + PCI_FUNC(devfn);
	struct devsec_dev *devsec_dev;
	struct devsec_dev_doe *doe;
	struct devsec_ide *ide;
	void __iomem *base;

	dev_vdbg(&bus->dev, "devfn: %#x pos: %#x size: %d\n", devfn, pos, size);

	if (PCI_FUNC(devfn) > NR_FUNCTIONS ||
	    PCI_SLOT(devfn) > NR_DEVICES_PER_BUS ||
	    fn >= ARRAY_SIZE(devsec->devsec_devs))
		return PCIBIOS_DEVICE_NOT_FOUND;

	devsec_dev = devsec->devsec_devs[fn];
	base = devsec_base(devsec_dev);
	doe = &devsec_dev->doe;
	ide = &devsec_dev->ide;

	if (pos >= PCI_BASE_ADDRESS_0 && pos <= PCI_BASE_ADDRESS_5) {
		if (size != 4)
			return PCIBIOS_BAD_REGISTER_NUMBER;
		/* only one 64-bit mmio bar emulated for now */
		if (pos == PCI_BASE_ADDRESS_0)
			val &= ~lower_32_bits(range_len(&devsec_dev->mmio_range) - 1);
		else if (pos == PCI_BASE_ADDRESS_1)
			val &= ~upper_32_bits(range_len(&devsec_dev->mmio_range) - 1);
		else
			val = 0;
	} else if (pos == PCI_ROM_ADDRESS) {
		val = 0;
	} else if (doe->cap && pos == doe->cap + PCI_DOE_CTRL) {
		if (val & PCI_DOE_CTRL_GO) {
			dev_dbg(&bus->dev, "devfn: %#x doe go\n", devfn);
			doe_process(doe);
		}
		if (val & PCI_DOE_CTRL_ABORT) {
			dev_dbg(&bus->dev, "devfn: %#x doe abort\n", devfn);
			doe->write = 0;
			doe->read = 0;
			doe->read_ttl = 0;
		}
		return PCIBIOS_SUCCESSFUL;
	} else if (doe->cap && pos == doe->cap + PCI_DOE_WRITE) {
		if (doe->write < ARRAY_SIZE(doe->req))
			doe->req[doe->write++] = val;
		dev_dbg(&bus->dev, "devfn: %#x doe write[%d]\n", devfn,
			doe->write - 1);
		return PCIBIOS_SUCCESSFUL;
	} else if (doe->cap && pos == doe->cap + PCI_DOE_READ) {
		if (doe->read_ttl > 0) {
			doe->read_ttl--;
			doe->read++;
			dev_dbg(&bus->dev, "devfn: %#x doe ack[%d]\n", devfn,
				doe->read - 1);
		}
		return PCIBIOS_SUCCESSFUL;
	} else if (devsec_dev->ide_pos && pos >= devsec_dev->ide_pos &&
		   pos < devsec_dev->ide_pos + sizeof(struct devsec_ide)) {

		*(u32 *) &devsec_dev->ide_regs[pos - devsec_dev->ide_pos] = val;

		/*
		 * Check if the control register is written and update the
		 * status register accordingly
		 */
		for (int i = 0; i < NR_PORT_STREAMS; i++) {
			struct devsec_stream *stream = &ide->stream[i];
			u16 ide_off = pos - devsec_dev->ide_pos;

			if (ide_off != offsetof(typeof(*ide), stream[i].ctl))
				continue;

			stream->status &= ~PCI_IDE_SEL_STS_STATE;
			if (val & PCI_IDE_SEL_CTL_EN)
				stream->status |= FIELD_PREP(
					PCI_IDE_SEL_STS_STATE,
					PCI_IDE_SEL_STS_STATE_SECURE);
			else
				stream->status |= FIELD_PREP(
					PCI_IDE_SEL_STS_STATE,
					PCI_IDE_SEL_STS_STATE_INSECURE);
			break;
		}
		return PCIBIOS_SUCCESSFUL;
	}

	switch (size) {
	case 1:
		writeb(val, base + pos);
		break;
	case 2:
		writew(val, base + pos);
		break;
	case 4:
		writel(val, base + pos);
		break;
	default:
		return PCIBIOS_BAD_REGISTER_NUMBER;
	}
	return PCIBIOS_SUCCESSFUL;
}

static int devsec_port_config_write(struct devsec *devsec, struct pci_bus *bus,
				    unsigned int devfn, int pos, int size,
				    u32 val)
{
	struct devsec_port *devsec_port;

	dev_vdbg(&bus->dev, "devfn: %#x pos: %#x size: %d\n", devfn, pos, size);

	if (PCI_FUNC(devfn) != 0 ||
	    PCI_SLOT(devfn) >= ARRAY_SIZE(devsec->devsec_ports))
		return PCIBIOS_DEVICE_NOT_FOUND;

	devsec_port = devsec->devsec_ports[PCI_SLOT(devfn)];
	return pci_bridge_emul_conf_write(&devsec_port->bridge, pos, size, val);
}

static int devsec_pci_write(struct pci_bus *bus, unsigned int devfn, int pos,
			    int size, u32 val)
{
	struct devsec *devsec = bus_to_devsec(bus);

	dev_vdbg(&bus->dev, "devfn: %#x pos: %#x size: %d\n", devfn, pos, size);

	if (bus == devsec->hb.bus)
		return devsec_port_config_write(devsec, bus, devfn, pos, size,
						val);
	else if (bus->parent == devsec->hb.bus)
		return devsec_dev_config_write(devsec, bus, devfn, pos, size,
					       val);
	return PCIBIOS_DEVICE_NOT_FOUND;
}

static struct pci_ops devsec_ops = {
	.read = devsec_pci_read,
	.write = devsec_pci_write,
};

static void destroy_bus(void *data)
{
	struct pci_host_bridge *hb = data;

	pci_stop_root_bus(hb->bus);
	pci_remove_root_bus(hb->bus);
}

static u32 build_ext_cap_header(u32 id, u32 ver, u32 next)
{
	return FIELD_PREP(GENMASK(15, 0), id) |
	       FIELD_PREP(GENMASK(19, 16), ver) |
	       FIELD_PREP(GENMASK(31, 20), next);
}

static void init_ide(struct devsec_ide *ide)
{
	ide->cap =
		PCI_IDE_CAP_LINK | PCI_IDE_CAP_SELECTIVE | PCI_IDE_CAP_IDE_KM |
		PCI_IDE_CAP_TEE_LIMITED |
		FIELD_PREP(PCI_IDE_CAP_LINK_TC_NUM, NR_PORT_LINK_STREAMS - 1) |
		FIELD_PREP(PCI_IDE_CAP_SEL_NUM, NR_PORT_STREAMS - 1);

	for (int i = 0; i < NR_PORT_STREAMS; i++)
		ide->stream[i].cap =
			FIELD_PREP(PCI_IDE_SEL_CAP_ASSOC_NUM, NR_ADDR_ASSOC);
}

static void init_dev_cfg(struct devsec_dev *devsec_dev, int fn)
{
	void __iomem *base = devsec_base(devsec_dev), *cap_base;
	int pos, next;

	/* BAR space */
	writew(0x8086, base + PCI_VENDOR_ID);
	writew(0xffff, base + PCI_DEVICE_ID);
	writew(PCI_CLASS_ACCELERATOR_PROCESSING, base + PCI_CLASS_DEVICE);
	writel(lower_32_bits(devsec_dev->mmio_range.start) |
		       PCI_BASE_ADDRESS_MEM_TYPE_64 |
		       PCI_BASE_ADDRESS_MEM_PREFETCH,
	       base + PCI_BASE_ADDRESS_0);
	writel(upper_32_bits(devsec_dev->mmio_range.start),
	       base + PCI_BASE_ADDRESS_1);

	/* PF0 is a DSM for this multifunction device */
	writeb(PCI_HEADER_TYPE_MFD, base + PCI_HEADER_TYPE);

	/* Capability init */
	writew(PCI_STATUS_CAP_LIST, base + PCI_STATUS);
	pos = 0x40;
	writew(pos, base + PCI_CAPABILITY_LIST);

	/* PCI-E Capability */
	cap_base = base + pos;
	writeb(PCI_CAP_ID_EXP, cap_base);
	writew(PCI_EXP_TYPE_ENDPOINT, cap_base + PCI_EXP_FLAGS);
	writew(PCI_EXP_LNKSTA_CLS_2_5GB | PCI_EXP_LNKSTA_NLW_X1, cap_base + PCI_EXP_LNKSTA);
	writel(PCI_EXP_DEVCAP_FLR | PCI_EXP_DEVCAP_TEE, cap_base + PCI_EXP_DEVCAP);

	/* PF0 has DOE and IDE, the rest of the functions are assignable TDIs */
	if (fn > 0)
		return;

	/* DOE Extended Capability */
	pos = PCI_CFG_SPACE_SIZE;
	next = pos + PCI_DOE_CAP_SIZEOF;
	cap_base = base + pos;
	devsec_dev->doe.cap = pos;
	writel(build_ext_cap_header(PCI_EXT_CAP_ID_DOE, 2, next), cap_base);

	/* IDE Extended Capability */
	pos = next;
	cap_base = base + pos;
	writel(build_ext_cap_header(PCI_EXT_CAP_ID_IDE, 1, 0), cap_base);
	devsec_dev->ide_pos = pos + 4;
	init_ide(&devsec_dev->ide);
}

#define MMIO_SIZE SZ_2M
#define PREFETCH_SIZE SZ_2M

static void destroy_devsec_dev(void *devsec_dev)
{
	kfree(devsec_dev);
}

static struct devsec_dev *devsec_dev_alloc(struct devsec *devsec, int hb, int fn)
{
	struct devsec_dev *devsec_dev __free(kfree) =
		kzalloc(sizeof(*devsec_dev), GFP_KERNEL);
	u64 start = devsec->prefetch_res.start +
		    (hb * NR_FUNCTIONS + fn) * PREFETCH_SIZE;

	if (!devsec_dev)
		return ERR_PTR(-ENOMEM);

	*devsec_dev = (struct devsec_dev) {
		.mmio_range = {
			.start = start,
			.end = start + PREFETCH_SIZE - 1,
		},
		.devsec = devsec,
	};
	init_dev_cfg(devsec_dev, fn);

	return_ptr(devsec_dev);
}

static int alloc_dev(struct devsec *devsec, int hb, int fn)
{
	struct devsec_dev *devsec_dev = devsec_dev_alloc(devsec, hb, fn);
	int rc;

	if (IS_ERR(devsec_dev))
		return PTR_ERR(devsec_dev);
	rc = devm_add_action_or_reset(devsec->dev, destroy_devsec_dev,
				      devsec_dev);
	if (rc)
		return rc;
	devsec->devsec_devs[hb * NR_FUNCTIONS + fn] = devsec_dev;

	dev_dbg(devsec->dev, "added: hb: %d fn: %d mmio: %pra\n",
		hb, fn, &devsec_dev->mmio_range);
	return 0;
}

static pci_bridge_emul_read_status_t
devsec_bridge_read_base(struct pci_bridge_emul *bridge, int pos, u32 *val)
{
	return PCI_BRIDGE_EMUL_NOT_HANDLED;
}

static pci_bridge_emul_read_status_t
devsec_bridge_read_pcie(struct pci_bridge_emul *bridge, int pos, u32 *val)
{
	return PCI_BRIDGE_EMUL_NOT_HANDLED;
}

static pci_bridge_emul_read_status_t
devsec_bridge_read_ext(struct pci_bridge_emul *bridge, int pos, u32 *val)
{
	struct devsec_port *devsec_port = bridge->data;

	/* only one extended capability, IDE... */
	if (pos == 0) {
		*val = build_ext_cap_header(PCI_EXT_CAP_ID_IDE, 1, 0);
		return PCI_BRIDGE_EMUL_HANDLED;
	}

	if (pos < 4)
		return PCI_BRIDGE_EMUL_NOT_HANDLED;

	pos -= 4;
	if (pos < sizeof(struct devsec_ide)) {
		*val = *(u32 *)(&devsec_port->ide_regs[pos]);
		return PCI_BRIDGE_EMUL_HANDLED;
	}

	return PCI_BRIDGE_EMUL_NOT_HANDLED;
}

static void devsec_bridge_write_base(struct pci_bridge_emul *bridge, int pos,
				     u32 old, u32 new, u32 mask)
{
}

static void devsec_bridge_write_pcie(struct pci_bridge_emul *bridge, int pos,
				     u32 old, u32 new, u32 mask)
{
}

static void devsec_bridge_write_ext(struct pci_bridge_emul *bridge, int pos,
				    u32 old, u32 new, u32 mask)
{
	struct devsec_port *devsec_port = bridge->data;

	if (pos < sizeof(struct devsec_ide))
		*(u32 *)(&devsec_port->ide_regs[pos]) = new;
}

static const struct pci_bridge_emul_ops devsec_bridge_ops = {
	.read_base = devsec_bridge_read_base,
	.write_base = devsec_bridge_write_base,
	.read_pcie = devsec_bridge_read_pcie,
	.write_pcie = devsec_bridge_write_pcie,
	.read_ext = devsec_bridge_read_ext,
	.write_ext = devsec_bridge_write_ext,
};

static int init_port(struct devsec *devsec, struct devsec_port *devsec_port,
		     int hb)
{
	const struct resource *mres = &devsec->mmio_res;
	const struct resource *pres = &devsec->prefetch_res;
	struct pci_bridge_emul *bridge = &devsec_port->bridge;
	u16 membase = cpu_to_le16(upper_16_bits(mres->start + MMIO_SIZE * hb) &
				  0xfff0);
	u16 memlimit =
		cpu_to_le16(upper_16_bits(mres->end + MMIO_SIZE * hb) & 0xfff0);
	u16 pref_mem_base =
		cpu_to_le16((upper_16_bits(lower_32_bits(pres->start +
							 PREFETCH_SIZE * hb)) &
			     0xfff0) |
			    PCI_PREF_RANGE_TYPE_64);
	u16 pref_mem_limit = cpu_to_le16(
		(upper_16_bits(lower_32_bits(pres->end + PREFETCH_SIZE * hb)) &
		 0xfff0) |
		PCI_PREF_RANGE_TYPE_64);
	u32 prefbaseupper =
		cpu_to_le32(upper_32_bits(pres->start + PREFETCH_SIZE * hb));
	u32 preflimitupper =
		cpu_to_le32(upper_32_bits(pres->end + PREFETCH_SIZE * hb));

	*bridge = (struct pci_bridge_emul) {
		.conf = {
			.vendor = cpu_to_le16(0x8086),
			.device = cpu_to_le16(0xffff),
			.class_revision = cpu_to_le32(0x1),
			.primary_bus = 0,
			.secondary_bus = hb + 1,
			.subordinate_bus = hb + 1,
			.membase = membase,
			.memlimit = memlimit,
			.pref_mem_base = pref_mem_base,
			.pref_mem_limit = pref_mem_limit,
			.prefbaseupper = prefbaseupper,
			.preflimitupper = preflimitupper,
		},
		.pcie_conf = {
			.devcap = cpu_to_le16(PCI_EXP_DEVCAP_FLR),
			.lnksta = cpu_to_le16(PCI_EXP_LNKSTA_CLS_2_5GB),
		},
		.subsystem_vendor_id = cpu_to_le16(0x8086),
		.has_pcie = true,
		.data = devsec_port,
		.ops = &devsec_bridge_ops,
	};

	init_ide(&devsec_port->ide);

	return pci_bridge_emul_init(bridge, PCI_BRIDGE_EMUL_NO_IO_FORWARD);
}

static void destroy_port(void *data)
{
	struct devsec_port *devsec_port = data;

	pci_bridge_emul_cleanup(&devsec_port->bridge);
	kfree(devsec_port);
}

static struct devsec_port *devsec_port_alloc(struct devsec *devsec, int hb)
{
	int rc;

	struct devsec_port *devsec_port __free(kfree) =
		kzalloc(sizeof(*devsec_port), GFP_KERNEL);

	if (!devsec_port)
		return ERR_PTR(-ENOMEM);

	rc = init_port(devsec, devsec_port, hb);
	if (rc)
		return ERR_PTR(rc);

	return_ptr(devsec_port);
}

static int alloc_port(struct devsec *devsec, int hb)
{
	struct devsec_port *devsec_port = devsec_port_alloc(devsec, hb);
	int rc;

	if (IS_ERR(devsec_port))
		return PTR_ERR(devsec_port);
	rc = devm_add_action_or_reset(devsec->dev, destroy_port, devsec_port);
	if (rc)
		return rc;
	devsec->devsec_ports[hb] = devsec_port;

	return 0;
}

static void release_mmio_region(void *res)
{
	remove_resource(res);
}

static void release_prefetch_region(void *res)
{
	remove_resource(res);
}

static int __init devsec_bus_probe(struct faux_device *fdev)
{
	int rc;
	struct pci_bus *bus;
	struct devsec *devsec;
	struct devsec_sysdata *sd;
	struct pci_host_bridge *hb;
	struct device *dev = &fdev->dev;

	hb = devm_pci_alloc_host_bridge(
		dev, sizeof(*devsec) - sizeof(struct pci_host_bridge));
	if (!hb)
		return -ENOMEM;

	devsec = container_of(hb, struct devsec, hb);
	devsec->dev = dev;

	devsec->mmio_res.name = "DEVSEC MMIO";
	devsec->mmio_res.flags = IORESOURCE_MEM;
	rc = allocate_resource(&iomem_resource, &devsec->mmio_res,
			       MMIO_SIZE * NR_DEVICES, 0, SZ_4G, MMIO_SIZE,
			       NULL, NULL);
	if (rc)
		return rc;

	rc = devm_add_action_or_reset(dev, release_mmio_region,
				      &devsec->mmio_res);
	if (rc)
		return rc;

	devsec->prefetch_res.name = "DEVSEC PREFETCH";
	devsec->prefetch_res.flags = IORESOURCE_MEM | IORESOURCE_MEM_64 |
				     IORESOURCE_PREFETCH;
	rc = allocate_resource(&iomem_resource, &devsec->prefetch_res,
			       PREFETCH_SIZE * NR_DEVICES, SZ_4G, U64_MAX,
			       PREFETCH_SIZE, NULL, NULL);
	if (rc)
		return rc;

	rc = devm_add_action_or_reset(dev, release_prefetch_region,
				      &devsec->prefetch_res);
	if (rc)
		return rc;

	for (int i = 0; i < NR_DEVSEC_BUSES; i++) {
		rc = alloc_port(devsec, i);
		if (rc)
			return rc;

		for (int j = 0; j < NR_FUNCTIONS; j++) {
			rc = alloc_dev(devsec, i, j);
			if (rc)
				return rc;
		}
	}

	devsec->busnr_res = (struct resource) {
		.name = "DEVSEC BUSES",
		.start = 0,
		.end = NR_DEVSEC_BUSES + 1 - 1, /* 1 RP per HB */
		.flags = IORESOURCE_BUS | IORESOURCE_PCI_FIXED,
	};
	pci_add_resource(&hb->windows, &devsec->busnr_res);
	pci_add_resource(&hb->windows, &devsec->mmio_res);
	pci_add_resource(&hb->windows, &devsec->prefetch_res);

	sd = &devsec->sysdata;
	devsec_sysdata = sd;

	/* Start devsec_bus emulation above the last ACPI segment */
	hb->domain_nr = pci_bus_find_emul_domain_nr(0, 0x10000, INT_MAX);
	if (hb->domain_nr < 0)
		return hb->domain_nr;

	/*
	 * Note, domain_nr is set in devsec_sysdata for
	 * !CONFIG_PCI_DOMAINS_GENERIC platforms
	 */
	devsec_set_domain_nr(sd, hb->domain_nr);

	hb->dev.parent = dev;
	hb->sysdata = sd;
	hb->ops = &devsec_ops;
	pci_ide_set_nr_streams(hb, NR_PLATFORM_STREAMS);

	rc = pci_scan_root_bus_bridge(hb);
	if (rc)
		return rc;

	bus = hb->bus;
	rc = devm_add_action_or_reset(dev, destroy_bus, no_free_ptr(hb));
	if (rc)
		return rc;

	pci_assign_unassigned_bus_resources(bus);
	pci_bus_add_devices(bus);

	return 0;
}

static struct faux_device *devsec_bus;

static struct faux_device_ops devsec_bus_ops = {
	.probe = devsec_bus_probe,
};

static int __init devsec_bus_init(void)
{
	devsec_bus = faux_device_create("devsec_bus", NULL, &devsec_bus_ops);
	if (!devsec_bus)
		return -ENODEV;
	return 0;
}
module_init(devsec_bus_init);

static void __exit devsec_bus_exit(void)
{
	faux_device_destroy(devsec_bus);
}
module_exit(devsec_bus_exit);

MODULE_IMPORT_NS("PCI_IDE");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Device Security Sample Infrastructure: TDISP Device Emulation");
