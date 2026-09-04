// SPDX-License-Identifier: GPL-2.0
/*
 * MediaTek SoundWire master — STABLE controller core.
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 */

#include <linux/bitfield.h>
#include <linux/interrupt.h>
#include <linux/iopoll.h>
#include <linux/soundwire/sdw.h>
#include <linux/soundwire/sdw_registers.h>

#include "bus.h"
#include "mtk-sdw-core.h"

/* ---- register helpers ---- */
static u32 core_readl(struct mtk_sdw_core *core, u32 off)
{
	return readl(core->regs + off);
}

static void core_writel(struct mtk_sdw_core *core, u32 off, u32 val)
{
	writel(val, core->regs + off);
}

static void core_updatel(struct mtk_sdw_core *core, u32 off, u32 mask, u32 val)
{
	u32 tmp = core_readl(core, off);

	core_writel(core, off, (tmp & ~mask) | (val & mask));
}

static u32 core_get_slave_status(struct mtk_sdw_core *core, u32 dev_addr)
{
	u32 slave_stat = 0;

	if (dev_addr > SDW_MAX_DEVICES) {
		dev_err(core->dev, "Unexpected device id %u\n", dev_addr);
		return slave_stat;
	}
	slave_stat = core_readl(core, MCP_SLAVESTAT);
	slave_stat = MCP_SLAVESTAT_STATUS(slave_stat, dev_addr);

	return slave_stat;
}

#define CORE_CMD_TIMEOUT_US   50000
#define CORE_CMD_POLL_US        10

static int core_send_cmd(struct mtk_sdw_core *core, u32 cmd, u8 *rdata)
{
	u32 resp;
	int ret;

	core_writel(core, MCP_COMMAND(0), cmd);

	ret = readl_poll_timeout(core->regs + MCP_STAT, resp,
				 resp & MCP_STAT_RX_NE,
				 CORE_CMD_POLL_US, CORE_CMD_TIMEOUT_US);
	if (ret) {
		dev_err(core->dev, "cmd 0x%08x timeout\n", cmd);
		return SDW_CMD_TIMEOUT;
	}

	resp = core_readl(core, MCP_COMMAND(0));
	if (FIELD_GET(MCP_RESP_NAK, resp))
		return SDW_CMD_FAIL;
	if (!FIELD_GET(MCP_RESP_ACK, resp))
		return SDW_CMD_IGNORED;
	if (rdata)
		*rdata = FIELD_GET(MCP_RESP_RDATA, resp);

	return SDW_CMD_OK;
}

static enum sdw_command_response
mtk_program_scp_addr(struct mtk_sdw_core *core, struct sdw_msg *msg)
{
	int ret;
	u32 p1 = FIELD_PREP(MCP_CMD_FIELD,    MCP_CMD_WRITE)     |
		 FIELD_PREP(MCP_CMD_DEV_ADDR, msg->dev_num)      |
		 FIELD_PREP(MCP_CMD_REG_ADDR, SDW_SCP_ADDRPAGE1) |
		 FIELD_PREP(MCP_CMD_REG_DATA, msg->addr_page1);
	u32 p2 = FIELD_PREP(MCP_CMD_FIELD,    MCP_CMD_WRITE)     |
		 FIELD_PREP(MCP_CMD_DEV_ADDR, msg->dev_num)      |
		 FIELD_PREP(MCP_CMD_REG_ADDR, SDW_SCP_ADDRPAGE2) |
		 FIELD_PREP(MCP_CMD_REG_DATA, msg->addr_page2);

	ret = core_send_cmd(core, p1, NULL);
	if (ret == SDW_CMD_OK)
		ret = core_send_cmd(core, p2, NULL);

	return ret;
}

static int mtk_core_prep_msg(struct mtk_sdw_core *core, struct sdw_msg *msg)
{
	int ret;

	if (msg->page) {
		ret = mtk_program_scp_addr(core, msg);
		if (ret) {
			msg->len = 0;
			return ret;
		}
	}

	switch (msg->flags) {
	case SDW_MSG_FLAG_READ:
	case SDW_MSG_FLAG_WRITE:
		break;
	default:
		dev_err(core->dev, "Invalid msg cmd: %d\n", msg->flags);
		return -EINVAL;
	}

	return 0;
}

/* =======================================================================
 * sdw_master_ops
 * =======================================================================
 */
static enum sdw_command_response
mtk_sdw_xfer_msg(struct sdw_bus *bus, struct sdw_msg *msg)
{
	struct mtk_sdw_core *core = bus_to_core(bus);
	int i, ret = 0;

	ret = mtk_core_prep_msg(core, msg);
	if (ret)
		return SDW_CMD_FAIL_OTHER;

	for (i = 0; i < msg->len; i++) {
		u32 cmd = FIELD_PREP(MCP_CMD_DEV_ADDR, msg->dev_num) |
			  FIELD_PREP(MCP_CMD_REG_ADDR, msg->addr + i) |
			  FIELD_PREP(MCP_CMD_SSP_TAG, msg->ssp_sync);

		if (msg->flags == SDW_MSG_FLAG_READ) {
			cmd |= FIELD_PREP(MCP_CMD_FIELD, MCP_CMD_READ);
			ret = core_send_cmd(core, cmd, &msg->buf[i]);
		} else {
			cmd |= FIELD_PREP(MCP_CMD_FIELD, MCP_CMD_WRITE) |
			       FIELD_PREP(MCP_CMD_REG_DATA, msg->buf[i]);
			ret = core_send_cmd(core, cmd, NULL);
		}
		if (ret)
			break;
	}

	return ret;
}

static u32 mtk_sdw_read_ping_status(struct sdw_bus *bus)
{
	struct mtk_sdw_core *core = bus_to_core(bus);

	return core_readl(core, MCP_SLAVESTAT);
}

static bool mipi_fwnode_property_read_bool(const struct fwnode_handle *fwnode,
					   const char *propname)
{
	int ret;
	u8 val;

	if (!fwnode_property_present(fwnode, propname))
		return false;
	ret = fwnode_property_read_u8_array(fwnode, propname, &val, 1);
	if (ret < 0)
		return false;
	return !!val;
}

static int mtk_sdw_read_prop(struct sdw_bus *bus)
{
	struct sdw_master_prop *prop = &bus->prop;
	struct fwnode_handle *link;
	char name[32];
	int nval;
	int ret;
	int i;
	int id = 0;

	snprintf(name, sizeof(name), "mipi-sdw-%d-sw-interface-revision",
		 bus->link_id);

	device_property_read_u32(bus->dev, name, &prop->revision);

	/* Find master handle */
	snprintf(name, sizeof(name),
		 "mipi-sdw-%d-link-%d-subproperties", bus->link_id, id);

	link = device_get_named_child_node(bus->dev, name);
	if (!link) {
		dev_err(bus->dev, "Master node %s not found\n", name);
		return -EIO;
	}

	for (i = SDW_CLK_STOP_MODE0; i <= SDW_CLK_STOP_MODE1; i++) {
		snprintf(name, sizeof(name),
			 "mipi-sdw-clock-stop-mode%d-supported", i);
		if (mipi_fwnode_property_read_bool(link, name))
			prop->clk_stop_modes |= BIT(i);
	}

	fwnode_property_read_u32(link,
				 "mipi-sdw-max-clock-frequency",
				 &prop->max_clk_freq);

	nval = fwnode_property_count_u32(link,
					 "mipi-sdw-clock-frequencies-supported");
	if (nval > 0) {
		prop->num_clk_freq = nval;
		prop->clk_freq = devm_kcalloc(bus->dev, prop->num_clk_freq,
					      sizeof(*prop->clk_freq),
					      GFP_KERNEL);
		if (!prop->clk_freq) {
			fwnode_handle_put(link);
			return -ENOMEM;
		}

		ret = fwnode_property_read_u32_array(link,
						     "mipi-sdw-clock-frequencies-supported",
						     prop->clk_freq,
						     prop->num_clk_freq);
		if (ret < 0) {
			fwnode_handle_put(link);
			return ret;
		}
	}

	/*
	 * Check the frequencies supported. If FW doesn't provide max
	 * freq, then populate here by checking values.
	 */
	if (!prop->max_clk_freq && prop->clk_freq) {
		prop->max_clk_freq = prop->clk_freq[0];
		for (i = 1; i < prop->num_clk_freq; i++) {
			if (prop->clk_freq[i] > prop->max_clk_freq)
				prop->max_clk_freq = prop->clk_freq[i];
		}
	}

	fwnode_property_read_u32(link, "mipi-sdw-default-frame-rate",
				 &prop->default_frame_rate);

	fwnode_property_read_u32(link, "mipi-sdw-default-frame-row-size",
				 &prop->default_row);

	fwnode_property_read_u32(link, "mipi-sdw-default-frame-col-size",
				 &prop->default_col);

	fwnode_handle_put(link);

	return 0;
}

static int mtk_sdw_set_bus_conf(struct sdw_bus *bus,
				struct sdw_bus_params *params)
{
	struct mtk_sdw_core *core = bus_to_core(bus);
	struct sdw_master_prop *prop = &bus->prop;
	u8 next = params->next_bank ? 1 : 0;
	u32 mclkd;

	/* curr_dr_freq is the *double* rate; halve it to get the bus clock. */
	if (params->curr_dr_freq && prop->mclk_freq) {
		mclkd = (prop->mclk_freq / params->curr_dr_freq);
		if (mclkd > 0)
			mclkd--;
		core_updatel(core, MCP_CLOCKCTRL(next), MCP_CLOCKCTRL_MCLKD,
			     FIELD_PREP(MCP_CLOCKCTRL_MCLKD, mclkd));
		core->curr_clk_freq = params->curr_dr_freq / 2;
	}
	return 0;
}

/* =======================================================================
 * Port ops
 * =======================================================================
 */

/* Source: word length, flow mode, data mode */
static int mtk_sdw_dpn_set_port_params(struct sdw_bus *bus,
				       struct sdw_port_params *params,
				       unsigned int bank)
{
	struct mtk_sdw_core *core = bus_to_core(bus);
	unsigned int p = params->num;
	u32 cfg;

	cfg = core_readl(core, MCP_DPN_CONFIG(p, bank));

	/* Bits per sample: encoded as (bps - 1). */
	u32p_replace_bits(&cfg, params->bps - 1, MCP_DPN_CONFIG_WL);
	/* Port flow mode (isochronous=0 / async=1).*/
	u32p_replace_bits(&cfg, params->flow_mode, MCP_DPN_CONFIG_PFM);
	/* Test/normal data mode. */
	u32p_replace_bits(&cfg, params->data_mode, MCP_DPN_CONFIG_PDM);

	core_writel(core, MCP_DPN_CONFIG(p, bank), cfg);
	return 0;
}

/* sample interval, block offsets, h-ctrl, BGC/BPM */
static int
mtk_sdw_dpn_set_port_transport_params(struct sdw_bus *bus,
				      struct sdw_transport_params *params,
				      enum sdw_reg_bank bank)
{
	struct mtk_sdw_core *core = bus_to_core(bus);
	unsigned int p  = params->port_num;
	u8 bk = (bank == SDW_BANK1) ? 1 : 0;
	u32 cfg, offsetctrl, hctrl;

	/* BGC and BPM live in DPN_CONFIG alongside WL/PFM/PDM. */
	cfg = core_readl(core, MCP_DPN_CONFIG(p, bk));
	u32p_replace_bits(&cfg, params->blk_grp_ctrl, MCP_DPN_CONFIG_BGC);
	u32p_replace_bits(&cfg, params->blk_pkg_mode, MCP_DPN_CONFIG_BPM);
	core_writel(core, MCP_DPN_CONFIG(p, bk), cfg);

	/* Sample interval: encoded as (interval - 1). */
	core_writel(core, MCP_DPN_SAMPLECTRL(p, bk),
		    FIELD_PREP(MCP_DPN_SAMPLECTRL_INTERVAL,
			       params->sample_interval - 1));

	/* Block offsets 1 and 2. */
	offsetctrl = FIELD_PREP(MCP_DPN_OFFSETCTRL_OFFSET1, params->offset1) |
		     FIELD_PREP(MCP_DPN_OFFSETCTRL_OFFSET2, params->offset2);
	core_writel(core, MCP_DPN_OFFSETCTRL(p, bk), offsetctrl);

	/* Horizontal start/stop and lane control. */
	hctrl = FIELD_PREP(MCP_DPN_HCTRL_HSTART,   params->hstart)  |
		FIELD_PREP(MCP_DPN_HCTRL_HSTOP,    params->hstop)   |
		FIELD_PREP(MCP_DPN_HCTRL_LANECTRL, params->lane_ctrl);
	core_writel(core, MCP_DPN_HCTRL(p, bk), hctrl);

	return 0;
}

static int mtk_sdw_dpn_port_enable_ch(struct sdw_bus *bus,
				      struct sdw_enable_ch *enable_ch,
				      unsigned int bank)
{
	struct mtk_sdw_core *core = bus_to_core(bus);
	unsigned int p = enable_ch->port_num;
	u32 val = 0;

	if (enable_ch->enable)
		val = FIELD_PREP(MCP_DPN_CHANNELEN_EN, enable_ch->ch_mask);

	core_writel(core, MCP_DPN_CHANNELEN(p, bank), val);
	return 0;
}

void mtk_sdw_core_dump_dpn_regs(struct mtk_sdw_core *core, unsigned int port,
				const char *tag)
{
	struct sdw_bus *bus = &core->bus;
	int bk;

	dev_info(core->dev,
		 "%s: port %u curr_bank=%d next_bank=%d\n",
		 tag, port, bus->params.curr_bank, bus->params.next_bank);

	for (bk = 0; bk < 2; bk++) {
		u32 config     = core_readl(core, MCP_DPN_CONFIG(port, bk));
		u32 channelen  = core_readl(core, MCP_DPN_CHANNELEN(port, bk));
		u32 samplectrl = core_readl(core, MCP_DPN_SAMPLECTRL(port, bk));
		u32 offsetctrl = core_readl(core, MCP_DPN_OFFSETCTRL(port, bk));
		u32 hctrl      = core_readl(core, MCP_DPN_HCTRL(port, bk));

		dev_info(core->dev,
			 "%s: port %u bank%d:\n"
			 "CONFIG=0x%08x (wl=%lu pfm=%lu pdm=%lu bgc=%lu bpm=%lu)\n"
			 "CHANNELEN=0x%08x\n"
			 "SAMPLECTRL=0x%08x (interval=%lu)\n"
			 "OFFSETCTRL=0x%08x (off1=%lu off2=%lu)\n"
			 "HCTRL=0x%08x (hstart=%lu hstop=%lu lane=%lu)\n",
			 tag, port, bk, config,
			 FIELD_GET(MCP_DPN_CONFIG_WL, config) + 1,
			 FIELD_GET(MCP_DPN_CONFIG_PFM, config),
			 FIELD_GET(MCP_DPN_CONFIG_PDM, config),
			 FIELD_GET(MCP_DPN_CONFIG_BGC, config),
			 FIELD_GET(MCP_DPN_CONFIG_BPM, config),
			 channelen, samplectrl,
			 FIELD_GET(MCP_DPN_SAMPLECTRL_INTERVAL, samplectrl) + 1,
			 offsetctrl,
			 FIELD_GET(MCP_DPN_OFFSETCTRL_OFFSET1, offsetctrl),
			 FIELD_GET(MCP_DPN_OFFSETCTRL_OFFSET2, offsetctrl),
			 hctrl,
			 FIELD_GET(MCP_DPN_HCTRL_HSTART, hctrl),
			 FIELD_GET(MCP_DPN_HCTRL_HSTOP, hctrl),
			 FIELD_GET(MCP_DPN_HCTRL_LANECTRL, hctrl));
	}
}
EXPORT_SYMBOL_GPL(mtk_sdw_core_dump_dpn_regs);

const struct sdw_master_port_ops mtk_sdw_core_port_ops = {
	.dpn_set_port_params           = mtk_sdw_dpn_set_port_params,
	.dpn_set_port_transport_params = mtk_sdw_dpn_set_port_transport_params,
	.dpn_port_enable_ch = mtk_sdw_dpn_port_enable_ch,
};

const struct sdw_master_ops mtk_sdw_core_ops = {
	.read_prop        = mtk_sdw_read_prop,
	.read_ping_status = mtk_sdw_read_ping_status,
	.xfer_msg         = mtk_sdw_xfer_msg,
	.set_bus_conf     = mtk_sdw_set_bus_conf,
};

static int mtk_do_config_update(struct mtk_sdw_core *core)
{
	u32 val;
	int ret;

	core_updatel(core, MCP_CONFIGUPDATE, MCP_CONFIGUPDATE_CU,
		     MCP_CONFIGUPDATE_CU);
	ret = readl_poll_timeout(core->regs + MCP_CONFIGUPDATE, val,
				 !(val & MCP_CONFIGUPDATE_CU), 100, 2000);
	if (ret) {
		dev_err(core->dev, "config update timeout\n");
		return ret;
	}
	return 0;
}

static int mtk_init_clock_ctrl(struct mtk_sdw_core *core)
{
	struct sdw_bus *bus = &core->bus;
	struct sdw_master_prop *prop = &bus->prop;
	int c;
	int r;
	u32 val;

	dev_dbg(core->dev, "mclk %d max %d row %d col %d\n",
		prop->mclk_freq,
		prop->max_clk_freq,
		prop->default_row,
		prop->default_col);

	/* Set clock divider */
	if (bus->params.curr_dr_freq && prop->mclk_freq) {
		u32 mclkd = (prop->mclk_freq / bus->params.curr_dr_freq);

		if (mclkd > 0)
			mclkd--;
		core_updatel(core, MCP_CLOCKCTRL_B0, MCP_CLOCKCTRL_MCLKD,
			     FIELD_PREP(MCP_CLOCKCTRL_MCLKD, mclkd));
		core_updatel(core, MCP_CLOCKCTRL_B1, MCP_CLOCKCTRL_MCLKD,
			     FIELD_PREP(MCP_CLOCKCTRL_MCLKD, mclkd));
	}

	r = sdw_find_row_index(prop->default_row);
	c = sdw_find_col_index(prop->default_col);
	val = FIELD_PREP(MCP_FRAMESHAPE_NC, c) |
	      FIELD_PREP(MCP_FRAMESHAPE_NR, r);

	core_updatel(core, MCP_FRAMESHAPEINIT,
		     (MCP_FRAMESHAPE_NC | MCP_FRAMESHAPE_NR), val);

	if (prop->default_frame_rate % SDW_GSYNC_HZ) {
		dev_warn(core->dev,
			 "[%u] FrameRate:%u not aligned with GSYNC:%d",
			 bus->link_id, prop->default_frame_rate, SDW_GSYNC_HZ);
	}

	val = prop->default_frame_rate / SDW_GSYNC_HZ;
	val = FIELD_PREP(MCP_SSP_CTRL_SSP_INTERVAL, val);

	core_updatel(core, MCP_SSP_CTRL_B0, MCP_SSP_CTRL_SSP_INTERVAL, val);
	core_updatel(core, MCP_SSP_CTRL_B1, MCP_SSP_CTRL_SSP_INTERVAL, val);

	return 0;
}

static int mtk_init_control_setting(struct mtk_sdw_core *core)
{
	u32 val;
	u32 mask;

	mask = MCP_CONTROL_RST_DELAY | MCP_CONTROL_CMD_RST |
	       MCP_CONTROL_CMD_ACCEPT_MODE;

	val = FIELD_PREP(MCP_CONTROL_RST_DELAY, 1) | MCP_CONTROL_CMD_RST;

	core_updatel(core, MCP_CONTROL, mask, val);

	return mtk_do_config_update(core);
}

static int mtk_init_config_setting(struct mtk_sdw_core *core)
{
	u32 val;
	u32 mask;

	mask = MCP_CONFIG_MCR | MCP_CONFIG_OP_MODE;

	val = FIELD_PREP(MCP_CONFIG_MCR, SDW_DEFAULT_MAX_CMD_RETRY) |
	      FIELD_PREP(MCP_CONFIG_OP_MODE, MCP_OP_MODE_NORMAL);

	core_updatel(core, MCP_CONFIG, mask, val);

	return mtk_do_config_update(core);
}

static void mtk_sdw_enable_master_irq(struct mtk_sdw_core *core, bool enable)
{
	core_updatel(core, MCP_INTMASK, (MCP_INT_MST_ERR_MASK | MCP_INT_WAKEUP),
		     enable ? (MCP_INT_MST_ERR_MASK | MCP_INT_WAKEUP) : 0);
}

void mtk_sdw_enable_irq(struct mtk_sdw_core *core, bool enable)
{
	if (enable) {
		core_writel(core, MCP_SLAVEINTMASK0, MCP_SLAVE_INTMASK0_MASK);
		core_writel(core, MCP_SLAVEINTMASK1, MCP_SLAVE_INTMASK1_MASK);
	} else {
		core_writel(core, MCP_SLAVEINTMASK0, 0);
		core_writel(core, MCP_SLAVEINTMASK1, 0);
	}

	mtk_sdw_enable_slave_irq(core, enable);

	mtk_sdw_enable_master_irq(core, enable);

	core->interrupt_enabled = enable;

	if (!enable)
		cancel_work_sync(&core->work);

	core_updatel(core, MCP_INTMASK, MCP_INT_IRQ,
		     enable ? MCP_INT_IRQ : 0);
}

void mtk_sdw_enable_slave_irq(struct mtk_sdw_core *core, bool enable)
{
	core_updatel(core, MCP_INTMASK, MCP_INT_SLV_MASK,
		     enable ? MCP_INT_SLV_MASK : 0);
}

/*
 * slave IRQ handling
 */
static int mtk_sdw_update_slave_status(struct mtk_sdw_core *core,
				       u64 slave_intstat)
{
	enum sdw_slave_status status[SDW_MAX_DEVICES + 1];
	bool need_handle_slave = false;
	u32 intstat;
	u32 val;
	int i, set_status;

	memset(status, 0, sizeof(status));

	for (i = 0; i <= SDW_MAX_DEVICES; i++) {
		intstat = MCP_SLAVEINTSTAT_STATUS(slave_intstat, i);

		set_status = 0;

		if (intstat) {
			need_handle_slave = true;

			if (intstat & MCP_SLAVEINTSTAT_RESERVED) {
				status[i] = SDW_SLAVE_RESERVED;
				set_status++;
			}

			if (intstat & MCP_SLAVEINTSTAT_ALERT) {
				status[i] = SDW_SLAVE_ALERT;
				set_status++;
			}

			if (intstat & MCP_SLAVEINTSTAT_ATTACHED) {
				status[i] = SDW_SLAVE_ATTACHED;
				set_status++;
			}

			if (intstat & MCP_SLAVEINTSTAT_NOT_PRESENT) {
				status[i] = SDW_SLAVE_UNATTACHED;
				set_status++;
			}
		}

		if (set_status != 1) {
			val = core_get_slave_status(core, i);

			switch (val) {
			case 0:
				status[i] = SDW_SLAVE_UNATTACHED;
				break;
			case 1:
				status[i] = SDW_SLAVE_ATTACHED;
				break;
			case 2:
				status[i] = SDW_SLAVE_ALERT;
				break;
			case 3:
			default:
				status[i] = SDW_SLAVE_RESERVED;
				break;
			}
		}
	}

	if (need_handle_slave)
		return sdw_handle_slave_status(&core->bus, status);

	return 0;
}

static void mtk_sdw_slave_status_work(struct work_struct *work)
{
	struct mtk_sdw_core *core =
		container_of(work, struct mtk_sdw_core, work);
	u32 stat0;
	u32 stat1;
	u32 dev0_stat;
	int retries = 0;
	u64 slv_intstat;

	core_writel(core, MCP_INTSTAT, MCP_INT_SLV_MASK);

	stat0 = core_readl(core, MCP_SLAVEINTSTAT0);
	stat1 = core_readl(core, MCP_SLAVEINTSTAT1);

	core_writel(core, MCP_SLAVEINTSTAT0, stat0);
	core_writel(core, MCP_SLAVEINTSTAT1, stat1);
	dev_dbg_ratelimited(core->dev, "Slave intstat0: 0x%x, intstat1 0x%x\n",
			    stat0, stat1);

	slv_intstat = ((u64)stat1 << 32) | stat0;

	do {
		mtk_sdw_update_slave_status(core, slv_intstat);

		dev0_stat = core_get_slave_status(core, 0);

		if (dev0_stat == MCP_SLAVESTAT_ATTACHED) {
			slv_intstat = MCP_SLAVEINTSTAT_ATTACHED;
			dev_info(core->dev,
				 "[%u] slave attached Dev0Stat:0x%x Retries:%d",
				 core->bus.link_id, dev0_stat, retries);
		} else {
			break;
		}

	} while (retries++ < SDW_MAX_DEVICES);

	mtk_sdw_enable_slave_irq(core, true);
}

static void mtk_sdw_handle_master_dp_interrupt(struct mtk_sdw_core *core)
{
	u32 portintstatus = core_readl(core, MCP_PORTINTSTAT);
	u32 pdistatus = core_readl(core, MCP_PDISTAT);
	struct sdw_bus *bus = &core->bus;

	dev_info(core->dev, "[%u]PortIntStatus:0x%x PdiStatus:0x%x\n",
		 bus->link_id, portintstatus, pdistatus);

	if (portintstatus)
		core_writel(core, MCP_PORTINTSTAT, portintstatus);

	if (pdistatus)
		core_writel(core, MCP_PDISTAT, pdistatus);
}

static void mtk_sdw_recalc_block_offset(struct sdw_port_runtime *p_rt)
{
	struct sdw_transport_params *tp = &p_rt->transport_params;
	int offset;

	offset = (tp->offset2 << 8) + tp->offset1;
	offset -= 1;

	tp->offset1 = offset & 0xFF;
	tp->offset2 = offset >> 8;
}

static int mtk_sdw_compute_params(struct sdw_bus *bus,
				  struct sdw_stream_runtime *stream)
{
	struct sdw_master_runtime *m_rt;
	struct sdw_slave_runtime *s_rt;
	struct sdw_port_runtime *p_rt;
	int ret;

	ret = sdw_compute_params(bus, stream);
	if (ret)
		return ret;

	/* block offset should begin from 0 */
	list_for_each_entry(m_rt, &bus->m_rt_list, bus_node) {
		list_for_each_entry(p_rt, &m_rt->port_list, port_node)
			mtk_sdw_recalc_block_offset(p_rt);

		list_for_each_entry(s_rt, &m_rt->slave_rt_list, m_rt_node)
			list_for_each_entry(p_rt, &s_rt->port_list, port_node)
				mtk_sdw_recalc_block_offset(p_rt);
	}

	return 0;
}

int mtk_sdw_core_init(struct mtk_sdw_core *core)
{
	core->bus.ops            = &mtk_sdw_core_ops;
	core->bus.port_ops       = &mtk_sdw_core_port_ops;
	core->bus.compute_params = mtk_sdw_compute_params;

	INIT_WORK(&core->work, mtk_sdw_slave_status_work);
	return 0;
}

int mtk_sdw_core_hw_init(struct mtk_sdw_core *core)
{
	int ret;

	ret = mtk_init_clock_ctrl(core);
	if (ret)
		return ret;

	ret = mtk_init_control_setting(core);
	if (ret)
		return ret;

	ret = mtk_init_config_setting(core);
	if (ret)
		return ret;

	return 0;
}

irqreturn_t mtk_sdw_core_irq(int irq, void *data)
{
	struct mtk_sdw_core *core = data;
	struct sdw_bus *bus = &core->bus;
	u32 intstat = core_readl(core, MCP_INTSTAT);
	u32 clearstat;

	if (!(intstat & MCP_INT_IRQ)) {
		dev_warn(core->dev,
			 "[%u]interrupt request not enabled IntStatus:0x%x",
			 bus->link_id, intstat);
		return IRQ_NONE;
	}

	clearstat = intstat;

	if (intstat & MCP_INT_WAKEUP)
		dev_err(core->dev, "[%u]wakeup IntStatus:0x%x\n",
			bus->link_id, intstat);

	if (intstat & MCP_INT_SLV_MASK) {
		if (intstat & MCP_INT_SLV_RESERVED) {
			dev_info(core->dev, "[%u]slave reserved int IntStatus:0x%x\n",
				 bus->link_id, intstat);
		}

		if (intstat & MCP_INT_SLV_ALERT) {
			dev_info(core->dev,
				 "[%u]slave alert int IntStatus:0x%x\n",
				 bus->link_id, intstat);
		}

		if (intstat & MCP_INT_SLV_ATTACHED) {
			dev_info(core->dev,
				 "[%u]slave attached int IntStatus:0x%x\n",
				 bus->link_id, intstat);
		}

		if (intstat & MCP_INT_SLV_NOT_ATTACH) {
			dev_info(core->dev,
				 "[%u]slave not attached int IntStatus:0x%x\n",
				 bus->link_id, intstat);
		}
		if (core->interrupt_enabled) {
			schedule_work(&core->work);
			mtk_sdw_enable_slave_irq(core, false);
			clearstat &= ~MCP_INT_SLV_MASK;
		}
	}
	if (intstat & MCP_INT_DP_INT) {
		dev_info(core->dev, "[%u]dp int IntStatus:0x%x\n", bus->link_id,
			 intstat);

		mtk_sdw_handle_master_dp_interrupt(core);
	}

	if (intstat & (MCP_INT_CTL_BUS_CLASH))
		dev_err(core->dev, "[%u]control bus clash 0x%x\n", bus->link_id,
			intstat);

	if (intstat & (MCP_INT_DATA_BUS_CLASH))
		dev_err(core->dev, "[%u]data bus clash 0x%x\n", bus->link_id,
			intstat);

	if (intstat & MCP_INT_PARITY_ERR)
		dev_err(core->dev, "[%u]parity error 0x%x\n", bus->link_id,
			intstat);

	if (intstat & MCP_INT_CMD_ERR)
		dev_err(core->dev, "[%u]command error 0x%x\n", bus->link_id,
			intstat);

	if (intstat & MCP_INT_RXWL)
		dev_info(core->dev, "[%u]rw wl 0x%x\n", bus->link_id, intstat);

	dev_info(core->dev, "[%u]ClearStatus 0x%x, IntStatus 0x%x\n",
		 bus->link_id, clearstat, intstat);

	core_writel(core, MCP_INTSTAT, clearstat);

	return IRQ_HANDLED;
}

void mtk_sdw_configure_pdi_params(struct mtk_sdw_core *core,
				  struct mtk_sdw_pdi_params *params)
{
	u32 offset;
	u32 val;
	u32 mask;

	offset = MCP_PDIN_CONFIG(params->pdi_num);

	mask = MCP_PDIN_CONFIG_SOFTRST | MCP_PDIN_CONFIG_CHANNELMASK |
	       MCP_PDIN_CONFIG_PORTNUM;

	val = MCP_PDIN_CONFIG_SOFTRST |
	      FIELD_PREP(MCP_PDIN_CONFIG_CHANNELMASK, params->ch_mask) |
	      FIELD_PREP(MCP_PDIN_CONFIG_PORTNUM, params->port_num);

	core_updatel(core, offset, mask, val);
}

void mtk_sdw_clear_pdi_settings(struct mtk_sdw_core *core,
				struct mtk_sdw_pdi_params *pdi)
{
	u32 offset;
	u32 val;
	u32 mask;

	offset = MCP_PDIN_CONFIG(pdi->pdi_num);

	/* clear pdi fifo */
	mask = MCP_PDIN_CONFIG_SOFTRST;
	val = MCP_PDIN_CONFIG_SOFTRST;
	core_updatel(core, offset, mask, val);

	/* clear pdi channel mask */
	mask = MCP_PDIN_CONFIG_CHANNELMASK;
	val = FIELD_PREP(MCP_PDIN_CONFIG_CHANNELMASK, 0);
	core_updatel(core, offset, mask, val);
}

void mtk_sdw_configure_port_params(struct mtk_sdw_core *core,
				   struct mtk_sdw_port_params *params, u32 dir)
{
	u32 offset;
	u32 val = 0;
	u32 mask;

	offset = MCP_DPN_PORTCTRL(params->port_num);
	mask = MCP_DPN_PORTCTRL_DIR | MCP_DPN_PORTCTRL_BPT_EN |
	       MCP_DPN_PORTCTRL_BPT_TYPE;
	if (dir == SDW_DATA_DIR_RX)
		val |= MCP_DPN_PORTCTRL_DIR;

	if (params->port_num == 0) /* bpt rx? */
		val |= FIELD_PREP(MCP_DPN_PORTCTRL_BPT_EN, params->bpt_en) |
		       FIELD_PREP(MCP_DPN_PORTCTRL_BPT_TYPE,
				  params->bpt_payload_type);

	core_updatel(core, offset, mask, val);
}
