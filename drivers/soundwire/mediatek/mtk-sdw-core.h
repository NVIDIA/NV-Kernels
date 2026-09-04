/* SPDX-License-Identifier: GPL-2.0 */
/*
 * MediaTek SoundWire master — STABLE controller core.
 *
 * Copyright (c) 2026 MediaTek Inc.
 * Author: Trevor Wu <trevor.wu@mediatek.com>
 */
#ifndef __MTK_SDW_CORE_H
#define __MTK_SDW_CORE_H

#include <linux/soundwire/sdw.h>

#define SDW_GSYNC_HZ (8000)
#define SDW_DEFAULT_MAX_CMD_RETRY (5)
/* =======================================================================
 * MCP (Master Control Port) registers
 * =======================================================================
 */
#define MCP_DP_SIZE                 128
#define MCP_PDI_SIZE                 16

#define MCP_CONFIG                  0x0000
#define MCP_CONTROL                 0x0004
#define MCP_CMDCTRL                 0x0008
#define MCP_SSPSTAT                 0x000c
#define MCP_FRAMESHAPE              0x0010
#define MCP_FRAMESHAPEINIT          0x0014
#define MCP_CONFIGUPDATE            0x0018
#define MCP_PHYCTRL                 0x001c
#define MCP_SSP_CTRL_B0             0x0020
#define MCP_SSP_CTRL_B1             0x0028
#define MCP_CLOCKCTRL_B0            0x0030
#define MCP_CLOCKCTRL_B1            0x0038
#define MCP_STAT                    0x0040
#define MCP_INTSTAT                 0x0044
#define MCP_INTMASK                 0x0048
#define MCP_INTSET                  0x004c
#define MCP_SLAVESTAT               0x0050
#define MCP_SLAVEINTSTAT0           0x0054
#define MCP_SLAVEINTSTAT1           0x0058
#define MCP_SLAVEINTMASK0           0x005c
#define MCP_SLAVEINTMASK1           0x0060
#define MCP_PORTINTSTAT             0x0064
#define MCP_PDISTAT                 0x006c
#define MCP_FIFOLEVEL               0x0078
#define MCP_FIFOSTAT                0x007c
#define MCP_COMMAND(n)              (0x0080 + (n) * 4)

#define MCP_DPN_CONFIG_B0(n)        (0x0100 + (n) * MCP_DP_SIZE)
#define MCP_DPN_CHANNELEN_B0(n)     (0x0104 + (n) * MCP_DP_SIZE)
#define MCP_DPN_SAMPLECTRL_B0(n)    (0x0108 + (n) * MCP_DP_SIZE)
#define MCP_DPN_OFFSETCTRL_B0(n)    (0x010c + (n) * MCP_DP_SIZE)
#define MCP_DPN_HCTRL_B0(n)         (0x0110 + (n) * MCP_DP_SIZE)
#define MCP_DPN_CONFIG_B1(n)        (0x0118 + (n) * MCP_DP_SIZE)
#define MCP_DPN_CHANNELEN_B1(n)     (0x011c + (n) * MCP_DP_SIZE)
#define MCP_DPN_SAMPLECTRL_B1(n)    (0x0120 + (n) * MCP_DP_SIZE)
#define MCP_DPN_OFFSETCTRL_B1(n)    (0x0124 + (n) * MCP_DP_SIZE)
#define MCP_DPN_HCTRL_B1(n)         (0x0128 + (n) * MCP_DP_SIZE)
#define MCP_DPN_PORTCTRL(n)         (0x0130 + ((n) & 0xf) * MCP_DP_SIZE)
#define MCP_PDIN_CONFIG(n)          (0x1100 + ((n) & 0xf) * MCP_PDI_SIZE)

/* Bank selectors: each takes (port, bank) / (bank) */
#define MCP_DPN_CONFIG(n, b) \
	((b) ? MCP_DPN_CONFIG_B1(n) : MCP_DPN_CONFIG_B0(n))
#define MCP_DPN_CHANNELEN(n, b) \
	((b) ? MCP_DPN_CHANNELEN_B1(n) : MCP_DPN_CHANNELEN_B0(n))
#define MCP_DPN_SAMPLECTRL(n, b) \
	((b) ? MCP_DPN_SAMPLECTRL_B1(n) : MCP_DPN_SAMPLECTRL_B0(n))
#define MCP_DPN_OFFSETCTRL(n, b) \
	((b) ? MCP_DPN_OFFSETCTRL_B1(n) : MCP_DPN_OFFSETCTRL_B0(n))
#define MCP_DPN_HCTRL(n, b) \
	((b) ? MCP_DPN_HCTRL_B1(n) : MCP_DPN_HCTRL_B0(n))
#define MCP_CLOCKCTRL(b) ((b) ? MCP_CLOCKCTRL_B1 : MCP_CLOCKCTRL_B0)

/* MCP_CONFIG */
#define MCP_CONFIG_OP_MODE          GENMASK(2, 0)
#define MCP_CONFIG_MCR              GENMASK(27, 24)
#define MCP_OP_MODE_NORMAL          0

/* MCP_CONTROL */
#define MCP_CONTROL_CMD_ACCEPT_MODE BIT(1)
#define MCP_CONTROL_CLOCK_STOP_CLR  BIT(2)
#define MCP_CONTROL_HW_BUS_RST      BIT(4)
#define MCP_CONTROL_SOFT_RST        BIT(6)
#define MCP_CONTROL_CMD_RST         BIT(7)
#define MCP_CONTROL_RST_DELAY       GENMASK(10, 8)

/* MCP_FRAMESHAPE(INIT) */
#define MCP_FRAMESHAPE_NC           GENMASK(2, 0) /* columns index */
#define MCP_FRAMESHAPE_NR           GENMASK(7, 3) /* rows, encoded (rows/2-1) */

/* MCP_CONFIGUPDATE */
#define MCP_CONFIGUPDATE_CU         BIT(0)

/* MCP_SSP_CTRL */
#define MCP_SSP_CTRL_SSP_INTERVAL   GENMASK(7, 0)

/* MCP_CLOCKCTRL */
#define MCP_CLOCKCTRL_MCLKD         GENMASK(7, 0)

/* MCP_STAT */
#define MCP_STAT_RX_NE              BIT(3)
#define MCP_STAT_CLK_STOP           BIT(16)

/* MCP_INTMASK / MCP_INTSTAT */
#define MCP_INT_RXWL                BIT(2)
#define MCP_INT_RXNE                BIT(3)
#define MCP_INT_CMD_ERR             BIT(7)
#define MCP_INT_PARITY_ERR          BIT(8)
#define MCP_INT_DATA_BUS_CLASH      BIT(9)
#define MCP_INT_CTL_BUS_CLASH       BIT(10)
#define MCP_INT_DP_INT              BIT(11)
#define MCP_INT_SLV_NOT_ATTACH      BIT(12)
#define MCP_INT_SLV_ATTACHED        BIT(13)
#define MCP_INT_SLV_ALERT           BIT(14)
#define MCP_INT_SLV_RESERVED        BIT(15)
#define MCP_INT_WAKEUP              BIT(16)
#define MCP_INT_IRQ                 BIT(31)
#define MCP_INT_SLV_MASK            (MCP_INT_SLV_RESERVED | \
				     MCP_INT_SLV_ALERT | \
				     MCP_INT_SLV_ATTACHED | \
				     MCP_INT_SLV_NOT_ATTACH)
#define MCP_INT_MST_ERR_MASK        (MCP_INT_RXWL | \
				     MCP_INT_PARITY_ERR | \
				     MCP_INT_DATA_BUS_CLASH | \
				     MCP_INT_CTL_BUS_CLASH)

/* MCP_SLAVESTAT: 2 bits/slave; MCP_SLAVEINTSTAT: 4 bits/slave */
#define MCP_SLAVESTAT_STATUS(x, n)    (((x) >> ((n) * 2)) & 0x3)
#define MCP_SLAVESTAT_UNATTACHED      0x0
#define MCP_SLAVESTAT_ATTACHED        0x1
#define MCP_SLAVESTAT_ALERT           0x2
#define MCP_SLAVEINTSTAT_STATUS(x, n) (((x) >> ((n) * 4)) & 0xf)
#define MCP_SLAVEINTSTAT_NOT_PRESENT  BIT(0)
#define MCP_SLAVEINTSTAT_ATTACHED     BIT(1)
#define MCP_SLAVEINTSTAT_ALERT        BIT(2)
#define MCP_SLAVEINTSTAT_RESERVED     BIT(3)

/* MCP_SLAVEINTMASK  */
#define MCP_SLAVE_INTMASK0_MASK GENMASK(31, 0)
#define MCP_SLAVE_INTMASK1_MASK GENMASK(15, 0)

/* MCP command word. CONFIRMED: dev_addr is 4-bit [27:24]. */
#define MCP_CMD_READ                0x2
#define MCP_CMD_WRITE               0x3
#define MCP_CMD_SSP_TAG             BIT(31)
#define MCP_CMD_FIELD               GENMASK(30, 28)
#define MCP_CMD_DEV_ADDR            GENMASK(27, 24)
#define MCP_CMD_REG_ADDR            GENMASK(23, 8)
#define MCP_CMD_REG_DATA            GENMASK(7, 0)

/* MCP command response. CONFIRMED. */
#define MCP_RESP_ACK                BIT(0)
#define MCP_RESP_NAK                BIT(1)
#define MCP_RESP_RDATA              GENMASK(15, 8)

/* Per-port transport fields (used by streaming) */
#define MCP_DPN_CONFIG_PFM          GENMASK(1, 0)    /* port flow mode  */
#define MCP_DPN_CONFIG_PDM          GENMASK(3, 2)    /* port data mode  */
/* word length, encoded (wl-1) */
#define MCP_DPN_CONFIG_WL           GENMASK(12, 8)
#define MCP_DPN_CONFIG_BGC          GENMASK(17, 16)  /* block group control */
#define MCP_DPN_CONFIG_BPM          BIT(18)          /* block packing mode  */
#define MCP_DPN_CHANNELEN_EN        GENMASK(7, 0)
#define MCP_DPN_SAMPLECTRL_INTERVAL GENMASK(15, 0)   /* encoded (interval-1) */
#define MCP_DPN_OFFSETCTRL_OFFSET1  GENMASK(7, 0)
#define MCP_DPN_OFFSETCTRL_OFFSET2  GENMASK(15, 8)
#define MCP_DPN_HCTRL_HSTOP         GENMASK(3, 0)
#define MCP_DPN_HCTRL_HSTART        GENMASK(7, 4)
#define MCP_DPN_HCTRL_LANECTRL      GENMASK(10, 8)   /* data lane select */

#define MCP_DPN_PORTCTRL_BPT_TYPE   GENMASK(23, 22)
#define MCP_DPN_PORTCTRL_BPT_EN	    BIT(16)
#define MCP_DPN_PORTCTRL_DIR        BIT(7)

#define MCP_PDIN_CONFIG_SOFTRST     BIT(24)
#define MCP_PDIN_CONFIG_CHANNELMASK GENMASK(15, 8)
#define MCP_PDIN_CONFIG_PORTNUM     GENMASK(4, 0)

/* =======================================================================
 * Core object
 * =======================================================================
 */
struct mtk_sdw_core {
	struct sdw_bus bus;
	struct device *dev;
	void __iomem *regs;
	unsigned int curr_clk_freq;
	bool interrupt_enabled;
	u16 attached_slaves;
	void *priv;
	struct delayed_work work;
	unsigned int dev0_repoll_count;
};

struct mtk_sdw_pdi_params {
	u32 pdi_num;
	u32 port_num;
	u32 ch_mask;
};

struct mtk_sdw_port_params {
	u32 port_num;
	u32 bpt_payload_type;
	bool bpt_en;
};

static inline struct mtk_sdw_core *bus_to_core(struct sdw_bus *bus)
{
	return container_of(bus, struct mtk_sdw_core, bus);
}

/* =======================================================================
 * Core API — called by the glue
 * =======================================================================
 */
extern const struct sdw_master_ops      mtk_sdw_core_ops;
extern const struct sdw_master_port_ops mtk_sdw_core_port_ops;

int  mtk_sdw_core_init(struct mtk_sdw_core *core);
int mtk_sdw_core_hw_init(struct mtk_sdw_core *core);
void mtk_sdw_enable_irq(struct mtk_sdw_core *core, bool enable);
void mtk_sdw_enable_slave_irq(struct mtk_sdw_core *core, bool enable);
irqreturn_t mtk_sdw_core_irq(int irq, void *data);
void mtk_sdw_configure_port_params(struct mtk_sdw_core *core,
				   struct mtk_sdw_port_params *params, u32 dir);

void mtk_sdw_configure_pdi_params(struct mtk_sdw_core *core,
				  struct mtk_sdw_pdi_params *params);
void mtk_sdw_clear_pdi_settings(struct mtk_sdw_core *core,
				struct mtk_sdw_pdi_params *pdi);
void mtk_sdw_core_dump_dpn_regs(struct mtk_sdw_core *core, unsigned int port,
				const char *tag);

#endif /* __MTK_SDW_CORE_H */
