// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 MediaTek Inc.
 *
 * Author: Chunfeng Yun <chunfeng.yun@mediatek.com>
 */

#include <linux/io.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/soc/mediatek/mtk-pwrap.h>

#include <linux/usb.h>
#include <linux/usb/hcd.h>

#include "xhci.h"
#include "xhci-plat.h"
#include "xhci-mtk-v2.h"

/* IPPC (IP Port Control) registers */
#define IPPC_IP_PW_CTRL0			0x00
#define CTRL0_IP_SW_RST				BIT(0)

#define IPPC_IP_PW_CTRL1			0x04
#define CTRL1_IP_HOST_PDN			BIT(0)

#define IPPC_IP_PW_CTRL2			0x08
/* U3D_SSUSB_IP_PW_CTRL2 */
#define CTRL2_IP_DEV_PDN			BIT(0)

#define IPPC_IP_PW_STS1				0x10
#define STS1_SYSPLL_STABLE			BIT(0)
#define STS1_REF_RST				BIT(8)
#define STS1_SYS125_RST				BIT(10)
#define STS1_XHCI_RST				BIT(11)
#define STS1_U3_MAC_RST				BIT(16)
#define U3_MAC3_CSR_PLL_STB			(STS1_SYSPLL_STABLE | STS1_U3_MAC_RST)
#define U3_MAC2_CSR_PLL_STB			(STS1_SYSPLL_STABLE | STS1_SYS125_RST)
#define STS1_IP_SLEEP				BIT(30)

#define IPPC_IP_XHCI_CAP			0x24
#define CAP_U3_PORT_NUM(p)			((p) & 0xff)
#define CAP_U2_PORT_NUM(p)			(((p) >> 8) & 0xff)

#define IPPC_U3_CTRL_P0				0x30
#define CTRL_U3_PORT_DIS			BIT(0)
#define CTRL_U3_PORT_PDN			BIT(1)
#define CTRL_U3_PORT_HOST_SEL			BIT(2)
#define CTRL_U3_PORT_SS_GEN2			BIT(9)
#define CTRL_U3_PORT_SS_2LANE			BIT(10)

#define IPPC_U2_CTRL_P0				0x50
#define IPPC_U2_CTRL_P1				0x58
#define CTRL_U2_PORT_DIS			BIT(0)
#define CTRL_U2_PORT_PDN			BIT(1)
#define CTRL_U2_PORT_HOST_SEL			BIT(2)

#define IPPC_CSR_CK_CTRL			0x88
#define CK_CSR_BUS_CK_GATE_EN			BIT(0)
#define CK_PHY_BUS_CK_GATE_EN			BIT(1)

/* Test Bank */
#define XHCI_VTIO_TEST_BASE			0

#define TEST_HSRAM_DBGCTL			(XHCI_VTIO_TEST_BASE + 0x00)
#define THDC_SRAM_DBG_EN			BIT(0)
#define THDC_SRAM_DBG_WP			BIT(1)

#define TEST_HSRAM_DBGMODE			(XHCI_VTIO_TEST_BASE + 0x04)
#define THDM_SRAM_DM_EP_SLOT			BIT(3)

#define TEST_HSRAM_DBGSEL			(XHCI_VTIO_TEST_BASE + 0x08)
#define THDS_SRAM_DS_EP_SLOT			BIT(3)

#define TEST_HSRAM_DBGADR			(XHCI_VTIO_TEST_BASE + 0x0C)
#define THDA_SRAM_DWSEL_MSK			GENMASK(2, 0)
#define THDA_SRAM_DWSEL_VAL(x)			((x) & THDA_SRAM_DWSEL_MSK)
#define THDA_DWSEL_32B_TO_64B			1
#define THDA_SRAM_ADDR_MSK			GENMASK(16, 3)
#define THDA_SRAM_ADDR_VAL(x)			(((x) << 3) & THDA_SRAM_ADDR_MSK)

#define TEST_HSRAM_DBGDR			(XHCI_VTIO_TEST_BASE + 0x10)

#define TEST_XACT3_CFG				(XHCI_VTIO_TEST_BASE + 0x48)
#define TXC_TX_TMOUT_MSK			GENMASK(7, 0)
#define TXC_TX_TMOUT_VAL(x)			((x) & TXC_TX_TMOUT_MSK)
#define TXC_TX_TMOUT_VAL_DFT			0x40

#define TEST_HSCH_CFG1				(XHCI_VTIO_TEST_BASE + 0x60)
#define THC1_PORT_IDLE_WITH_ISO			BIT(0)
#define THC1_BURST_TD_OFF			BIT(2)
#define THC1_OUT_NUMP_REF			BIT(4)
#define THC1_SCH3_INT_PING_TD_CHK		BIT(12)
#define THC1_PORT_IDLE_WITH_INT			BIT(13)

#define TEST_CMD_CFG				(XHCI_VTIO_TEST_BASE + 0x64)
#define TCC_PARAM_ERR_CHK_DIS			BIT(0)

#define TEST_EP_CFG				(XHCI_VTIO_TEST_BASE + 0x68)
#define TEC_STOP_EP_OPT				BIT(2)

#define TEST_TRBQ_CFG				(XHCI_VTIO_TEST_BASE + 0x70)
#define TTC_TRB_ERR_CHK_DIS			BIT(0)

#define TEST_RST_CTRL0				(XHCI_VTIO_TEST_BASE + 0xB0)
#define TRC_HCRST_RXDETECT_EN			BIT(7)

#define TEST_SCH_CFG5				(XHCI_VTIO_TEST_BASE + 0x114)
#define TSC5_OH_FS_INT_IN_MSK			GENMASK(7, 0)
#define TSC5_OH_FS_INT_IN_VAL(x)		((x) & TSC5_OH_FS_INT_IN_MSK)
#define TSC5_OH_FS_INT_OUT_MSK			GENMASK(15, 8)
#define TSC5_OH_FS_INT_OUT_VAL(x)		(((x) << 8) & TSC5_OH_FS_INT_OUT_MSK)
#define TSC5_OH_FS_INT_DFT				0xA
#define TSC5_OH_FS_ISO_IN_MSK			GENMASK(23, 16)
#define TSC5_OH_FS_ISO_IN_VAL(x)		(((x) << 16) & TSC5_OH_FS_ISO_IN_MSK)
#define TSC5_OH_FS_ISO_OUT_MSK			GENMASK(31, 24)
#define TSC5_OH_FS_ISO_OUT_VAL(x)		(((x) << 24) & TSC5_OH_FS_ISO_OUT_MSK)
#define TSC5_OH_FS_ISO_DFT			0x8

#define TEST_SCH_CFG6				(XHCI_VTIO_TEST_BASE + 0x118)
#define TSC6_OH_LS_INT_IN_MSK			GENMASK(7, 0)
#define TSC6_OH_LS_INT_IN_VAL(x)		((x) & TSC6_OH_LS_INT_IN_MSK)
#define TSC6_OH_LS_INT_OUT_MSK			GENMASK(15, 8)
#define TSC6_OH_LS_INT_OUT_VAL(x)		(((x) << 8) & TSC6_OH_LS_INT_OUT_MSK)
#define TSC6_OH_LS_INT_DFT			0xA

#define IPPC_U3_CTRL(p)				(IPPC_U3_CTRL_P0 + ((p) << 3))
#define IPPC_U2_CTRL(p)				(IPPC_U2_CTRL_P0 + ((p) << 3))

#define SPHY_U3_BASE_OFFSET			0x3000
#define SPHY_PORT_BANKS_SIZE			0x4000

/* S-PHY sub-banks offset base address */
/* u2 phy banks */
#define SPHY_U2_MISC				0x000
#define SPHY_U2_FREQ				0x100
#define SPHY_U2_COM				0x300

/* u3/pcie phy banks */
#define SPHY_U3_DIG_GLB				0x000
#define SPHY_U3_PHYA_GLB			0x100
/* u3 phy banks, ln0/1 */
#define SPHY_LN0_OFFSET				0x400
#define SPHY_LN_BANKS_SIZE			0x600
/* ln0/1 banks */
#define SPHY_LN_DIG_TOP				0x000
#define SPHY_LN_DIG_TX0				0x100
#define SPHY_LN_DIG_RX0				0x200
#define SPHY_LN_DIG_DAIF			0x300
#define SPHY_LN_PHYA				0x400
#define SPHY_LN_FEDIG				0x500

#define U2P_MISC_REG1				(SPHY_U2_MISC + 0x04)
#define MR1_RG_EFUSE_AUTO_LOAD_DIS		BIT(6)

#define U2P_USBPHYACR0				(SPHY_U2_COM + 0x000)
#define PA0_RG_U2_INTR_EN			BIT(5)

#define U2P_USBPHYACR2				(SPHY_U2_COM + 0x008)
#define PA2_RG_U2_CLKREF_REV1_MSK		GENMASK(15, 8)
#define PA2_RG_U2_CLKREF_REV1_VAL(x)		((0xff & (x)) << 8)
#define PA2_RG_U2_CLKREF_DFT			PA2_RG_U2_CLKREF_REV1_VAL(0x32)

#define U2P_USBPHYACR5				(SPHY_U2_COM + 0x014)
#define PA5_RG_U2_HSTX_SRCTRL_MSK		GENMASK(14, 12)
#define PA5_RG_U2_HSTX_SRCTRL_VAL(x)		((0x7 & (x)) << 12)
#define PA5_RG_U2_DE_EMPHASIS_MSK		GENMASK(9, 8)
#define PA5_RG_U2_DE_EMPHASIS(x)		((0x3 & (x)) << 8)

#define U2P_USBPHYACR6				(SPHY_U2_COM + 0x018)
#define PA6_RG_U2_BC11_SW_EN			BIT(23)
#define PA6_RG_U2_OTG_VBUSCMP_EN		BIT(20)
#define PA6_RG_U2_DISCTH_MSK			GENMASK(7, 4)
#define PA6_RG_U2_DISCTH_VAL(x)			((0xf & (x)) << 4)
#define PA6_RG_U2_SQTH_MSK			GENMASK(3, 0)
#define PA6_RG_U2_SQTH_VAL(x)			(0xf & (x))

#define U2P_U2PHYACR4				(SPHY_U2_COM + 0x020)
#define P2C_RG_U2_GPIO_CTL			BIT(9)
#define P2C_RG_U2_GPIO_MODE			BIT(8)
#define P2C_U2_GPIO_CTR_MSK			(P2C_RG_U2_GPIO_CTL | P2C_RG_U2_GPIO_MODE)

#define U2P_U2PHYACR5				(SPHY_U2_COM + 0x050)
#define PA5_RG_LDO_VREF_SEL_MSK			GENMASK(2, 0)
#define PA5_RG_LDO_VREF_SEL_VAL(x)		((0x7 & (x)) << 0)
#define PA5_RG_LDO_VREF_SEL_VAL_MAX		(0x7)
#define PA5_RG_TERM_CAL_P_MSK			GENMASK(19, 16)
#define PA5_RG_TERM_CAL_P_VAL(x)		((0xF & (x)) << 16)
#define PA5_RG_HSTX_LDO_OUT_SEL_MSK		GENMASK(29, 28)
#define PA5_RG_HSTX_LDO_OUT_SEL_VAL(x)		((0x3 & (x)) << 28)

#define U2P_U2PHYDTM0				(SPHY_U2_COM + 0x068)
#define P2C_FORCE_UART_EN			BIT(26)
#define P2C_FORCE_DATAIN			BIT(23)
#define P2C_FORCE_DM_PULLDOWN			BIT(21)
#define P2C_FORCE_DP_PULLDOWN			BIT(20)
#define P2C_FORCE_XCVRSEL			BIT(19)
#define P2C_FORCE_SUSPENDM			BIT(18)
#define P2C_FORCE_TERMSEL			BIT(17)
#define P2C_RG_DATAIN_MSK			GENMASK(13, 10)
#define P2C_RG_DATAIN_VAL(x)			((0xf & (x)) << 10)
#define P2C_RG_DMPULLDOWN			BIT(7)
#define P2C_RG_DPPULLDOWN			BIT(6)
#define P2C_RG_XCVRSEL_MSK			GENMASK(5, 4)
#define P2C_RG_XCVRSEL_VAL(x)			((0x3 & (x)) << 4)
#define P2C_RG_SUSPENDM				BIT(3)
#define P2C_RG_TERMSEL				BIT(2)
#define P2C_DTM0_PART_MSK	  \
		(P2C_FORCE_DATAIN | P2C_FORCE_DM_PULLDOWN |	\
		 P2C_FORCE_DP_PULLDOWN | P2C_FORCE_XCVRSEL |	\
		 P2C_FORCE_TERMSEL | P2C_RG_DMPULLDOWN |	\
		 P2C_RG_DPPULLDOWN | P2C_RG_TERMSEL)

#define U2P_U2PHYDTM1				(SPHY_U2_COM + 0x06C)
#define P2C_RG_UART_EN				BIT(16)
#define P2C_FORCE_IDDIG				BIT(9)
#define P2C_RG_VBUSVALID			BIT(5)
#define P2C_RG_SESSEND				BIT(4)
#define P2C_RG_AVALID				BIT(2)
#define P2C_RG_IDDIG				BIT(1)

/*	u3 phy bit fileds */
#define U3P_DIG_GLB_38				(SPHY_U3_DIG_GLB + 0x38)
#define P3D_TX_DET_P3_TRACK_OPTION		BIT(14)

#define U3P_DIG_GLB_60				(SPHY_U3_DIG_GLB + 0x60)
#define P3D_CKM_GATED_BIAS_DIS			BIT(13)
#define P3D_CKM_XTAL_CK_DETECT_DIS		BIT(14)

#define U3P_DIG_LN_RX_34			(SPHY_LN_DIG_RX0 + 0x34)
#define P3LR_RXLFPS_G1_FWAKE_TH			GENMASK(7, 0)
#define P3LR_RXLFPS_G1_FWAKE_TH_VAL(x)		((0xFF & (x)) << 0)
#define P3LR_RXLFPS_G2_FWAKE_TH			GENMASK(15, 8)
#define P3LR_RXLFPS_G2_FWAKE_TH_VAL(x)		((0xFF & (x)) << 8)
#define P3LR_RXLFPS_FILTER_VAL_DFT		0x46
#define P3LR_RXLFPS_FWAKE_SYS_TH		GENMASK(23, 16)
#define P3LR_RXLFPS_FWAKE_SYS_TH_VAL(x)	((0xFF & (x)) << 16)
#define P3LR_RXLFPS_FWAKE_SYS_TH_DFT		0xB9

#define U3P_FEDIG_RG_29				(SPHY_LN_FEDIG + 0x74)
#define P3FE_LN_RX_DFE_AUTO_OFF_EN		BIT(30)

/* SPHY3-only LN0 SI tuning (N1A P4U3 P0/P1) */
#define U3P_DIG_LN_RX_70			(SPHY_LN_DIG_RX0 + 0x70)
#define P3LR_PPATH_DVN_G2_LTD0_MSK		GENMASK(7, 0)
#define P3LR_PPATH_DVN_G2_LTD0_VAL		(0x28 << 0)
#define P3LR_PPATH_DVN_G2_LTD1_MSK		GENMASK(15, 8)
#define P3LR_PPATH_DVN_G2_LTD1_VAL		(0x58 << 8)

#define U3P_DIG_LN_RX_7C			(SPHY_LN_DIG_RX0 + 0x7C)
#define P3LR_STB_GAIN_G2_LTD0_MSK		GENMASK(15, 14)
#define P3LR_STB_GAIN_G2_LTD0_VAL		(0x2 << 14)

#define U3P_DIG_LN_DAIF_44			(SPHY_LN_DIG_DAIF + 0x44)
#define P3LD_G2_CDR_IIR_GAIN_MSK		GENMASK(15, 13)
#define P3LD_G2_CDR_IIR_GAIN_VAL		(0x2 << 13)

#define U3P_DIG_LN_DAIF_58			(SPHY_LN_DIG_DAIF + 0x58)
#define P3LD_G2_RX_CDR_FASTP_GAIN_MSK		GENMASK(31, 28)
#define P3LD_G2_RX_CDR_FASTP_GAIN_VAL		(0xF << 28)

#define U3P_DIG_LN_DAIF_60			(SPHY_LN_DIG_DAIF + 0x60)
#define P3LD_G2_RX_LF_CTLE_CSEL_MSK		GENMASK(23, 21)
#define P3LD_G2_RX_LF_CTLE_CSEL_VAL		(0x1 << 21)
#define P3LD_G2_RX_LF_CTLE_RSEL_MSK		GENMASK(31, 28)
#define P3LD_G2_RX_LF_CTLE_RSEL_VAL		(0x3 << 28)

#define U3P_PHYA_LN_0C				(SPHY_LN_PHYA + 0x0C)
#define P3L_RX_FE_RESERVE_MSK			GENMASK(23, 22)
#define P3L_RX_FE_RESERVE_VAL			(0x0 << 22)

// sw macros
#define U3_CLK_WAIT_MS			10
#define MS_TO_US			1000
#define WAIT_UNIT_US			10
#define TEST_HSRAM_ARRAY_SIZE		32

static inline void usb_write(void __iomem *base, u32 offset, u32 val)
{
	writel(val, base + offset);
}

static inline u32 usb_read(void __iomem *base, u32 offset)
{
	return readl(base + offset);
}

static inline void usb_clr_bits(void __iomem *base, u32 offset, u32 bits)
{
	u32 tmp;

	tmp = readl(base + offset);
	tmp &= ~bits;
	writel(tmp, base + offset);
}

static inline void usb_set_bits(void __iomem *base, u32 offset, u32 bits)
{
	u32 tmp;

	tmp = readl(base + offset);
	tmp |= bits;
	writel(tmp, base + offset);
}

static inline void usb_update_bits(void __iomem *base, u32 offset, u32 mask, u32 bits)
{
	u32 tmp;

	tmp = readl(base + offset);
	tmp &= ~mask;
	tmp |= bits;
	writel(tmp, base + offset);
}

static inline int
usb_read_poll_timeout(void __iomem *base, u32 offset, u32 check_val, int timeout_ms)
{
	int times = timeout_ms * MS_TO_US / WAIT_UNIT_US;
	u32 val;

	do {
		val = usb_read(base, offset);
		if (check_val == (val & check_val))
			break;

		udelay(WAIT_UNIT_US);
	} while (--times > 0);

	return times > 0 ? 0 : -1;
}

static void sphy_u2_init(struct mtk_usb_phy *phy)
{
	void __iomem *pbase = phy->port_base;

	// switch to USB function, and enable usb pll
	usb_clr_bits(pbase, U2P_U2PHYDTM0, P2C_FORCE_UART_EN | P2C_FORCE_SUSPENDM);

	usb_clr_bits(pbase, U2P_U2PHYDTM1, P2C_RG_UART_EN);

	usb_set_bits(pbase, U2P_USBPHYACR0, PA0_RG_U2_INTR_EN);

	usb_clr_bits(pbase, U2P_U2PHYACR4, P2C_U2_GPIO_CTR_MSK);

	// DP/DM BC1.1 path Disable
	usb_clr_bits(pbase, U2P_USBPHYACR6, PA6_RG_U2_BC11_SW_EN);

	//usb_update_bits(pbase, U2P_USBPHYACR6, PA6_RG_U2_SQTH_MSK, PA6_RG_U2_SQTH_VAL(2));

	// set HS slew rate
	//usb_update_bits(pbase, U2P_USBPHYACR5,
	//		PA5_RG_U2_HSTX_SRCTRL_MSK, PA5_RG_U2_HSTX_SRCTRL_VAL(4));

	// set de-emphasis (from sphy3/4)
	usb_update_bits(pbase, U2P_USBPHYACR5, PA5_RG_U2_DE_EMPHASIS_MSK, PA5_RG_U2_DE_EMPHASIS(1));
	// set LDO output follow de-emphasis  (from sphy3/4)
	usb_update_bits(pbase, U2P_U2PHYACR5, PA5_RG_HSTX_LDO_OUT_SEL_MSK,
			PA5_RG_HSTX_LDO_OUT_SEL_VAL(1));

	usb_clr_bits(pbase, U2P_U2PHYDTM0, P2C_DTM0_PART_MSK);

	usb_update_bits(pbase, U2P_USBPHYACR2, PA2_RG_U2_CLKREF_REV1_MSK, PA2_RG_U2_CLKREF_DFT);

	/* OTG Enable */
	usb_set_bits(pbase, U2P_USBPHYACR6, PA6_RG_U2_OTG_VBUSCMP_EN);

	usb_set_bits(pbase, U2P_U2PHYDTM1, P2C_RG_VBUSVALID | P2C_RG_AVALID);

	usb_clr_bits(pbase, U2P_U2PHYDTM1, P2C_RG_SESSEND);

	pr_debug(" %s (%u)\n", __func__, phy->pid);
}

static void sphy_u2_exit(struct mtk_usb_phy *phy)
{
	/* OTG Enable */
	usb_clr_bits(phy->port_base, U2P_USBPHYACR6, PA6_RG_U2_OTG_VBUSCMP_EN);

	usb_clr_bits(phy->port_base, U2P_U2PHYDTM1, P2C_RG_VBUSVALID | P2C_RG_AVALID);

	usb_set_bits(phy->port_base, U2P_U2PHYDTM1, P2C_RG_SESSEND);

	pr_debug(" %s (%u)\n", __func__, phy->pid);
}

static void sphy_u2_param_tune(struct mtk_usb_phy *phy)
{
	void __iomem *pbase = phy->port_base;

	pr_debug(" %s (%u)\n", __func__, phy->pid);

	if (phy->u2p_disconnect_threshold) {
		usb_update_bits(pbase, U2P_USBPHYACR6, PA6_RG_U2_DISCTH_MSK,
				PA6_RG_U2_DISCTH_VAL(phy->u2p_disconnect_threshold));
	}

	if (phy->u2p_eye_rising_deemphasis) {
		// set de-emphasis (from sphy3/4)
		usb_update_bits(pbase, U2P_USBPHYACR5, PA5_RG_U2_DE_EMPHASIS_MSK,
				PA5_RG_U2_DE_EMPHASIS(phy->u2p_eye_rising_deemphasis));
	}

	if (phy->u2p_eye_rising_txldoout) {
		// it's better to set LDO-out as de-emphasis  (from sphy3/4)
		usb_update_bits(pbase, U2P_U2PHYACR5, PA5_RG_HSTX_LDO_OUT_SEL_MSK,
				PA5_RG_HSTX_LDO_OUT_SEL_VAL(phy->u2p_eye_rising_txldoout));
	}

	if (phy->u2p_eye_swing_vref) {
		// disable efuse auto-load first
		usb_set_bits(pbase, U2P_MISC_REG1, MR1_RG_EFUSE_AUTO_LOAD_DIS);
		usb_update_bits(pbase, U2P_U2PHYACR5, PA5_RG_LDO_VREF_SEL_MSK,
				PA5_RG_LDO_VREF_SEL_VAL(phy->u2p_eye_swing_vref));
		// shall update Term only when Verf is max 7
		if (phy->u2p_eye_swing_term &&
			(phy->u2p_eye_swing_vref == PA5_RG_LDO_VREF_SEL_VAL_MAX)) {
			usb_update_bits(pbase, U2P_U2PHYACR5, PA5_RG_TERM_CAL_P_MSK,
					PA5_RG_TERM_CAL_P_VAL(phy->u2p_eye_swing_term));
		}
	}
}

static void sphy3_u3_lane0_init(struct mtk_usb_phy *phy)
{
	void __iomem *lane_base = phy->port_base + phy->u3p_offset + SPHY_LN0_OFFSET;

	pr_debug("sphy3: %s\n", __func__);

	usb_update_bits(lane_base, U3P_DIG_LN_RX_70,
			P3LR_PPATH_DVN_G2_LTD0_MSK | P3LR_PPATH_DVN_G2_LTD1_MSK,
			P3LR_PPATH_DVN_G2_LTD0_VAL | P3LR_PPATH_DVN_G2_LTD1_VAL);
	usb_update_bits(lane_base, U3P_DIG_LN_RX_7C,
			P3LR_STB_GAIN_G2_LTD0_MSK,
			P3LR_STB_GAIN_G2_LTD0_VAL);
	usb_update_bits(lane_base, U3P_DIG_LN_DAIF_44,
			P3LD_G2_CDR_IIR_GAIN_MSK,
			P3LD_G2_CDR_IIR_GAIN_VAL);
	usb_update_bits(lane_base, U3P_DIG_LN_DAIF_58,
			P3LD_G2_RX_CDR_FASTP_GAIN_MSK,
			P3LD_G2_RX_CDR_FASTP_GAIN_VAL);
	usb_update_bits(lane_base, U3P_DIG_LN_DAIF_60,
			P3LD_G2_RX_LF_CTLE_CSEL_MSK | P3LD_G2_RX_LF_CTLE_RSEL_MSK,
			P3LD_G2_RX_LF_CTLE_CSEL_VAL | P3LD_G2_RX_LF_CTLE_RSEL_VAL);
	usb_clr_bits(lane_base, U3P_PHYA_LN_0C, P3L_RX_FE_RESERVE_MSK);
}

static void sphy4_u3_lane_init(struct mtk_usb_phy *phy, u32 lane_num)
{
	void __iomem *lane_base;

	pr_debug(" %s (%u)\n", __func__, lane_num);

	lane_base = phy->port_base + phy->u3p_offset + SPHY_LN0_OFFSET;
	if (lane_num != 0)
		lane_base = lane_base + SPHY_LN_BANKS_SIZE;

	usb_update_bits(lane_base, U3P_DIG_LN_RX_34,
			P3LR_RXLFPS_G1_FWAKE_TH | P3LR_RXLFPS_G2_FWAKE_TH |
			P3LR_RXLFPS_FWAKE_SYS_TH,
			(P3LR_RXLFPS_G1_FWAKE_TH_VAL(P3LR_RXLFPS_FILTER_VAL_DFT) |
			 P3LR_RXLFPS_G2_FWAKE_TH_VAL(P3LR_RXLFPS_FILTER_VAL_DFT) |
			 P3LR_RXLFPS_FWAKE_SYS_TH_VAL(P3LR_RXLFPS_FWAKE_SYS_TH_DFT)));

	// disable DFE auto off function
	usb_clr_bits(lane_base, U3P_FEDIG_RG_29, P3FE_LN_RX_DFE_AUTO_OFF_EN);
}

static void sphy_u3_init(struct mtk_usb_phy *phy)
{
	void __iomem *pbase = phy->port_base + phy->u3p_offset;

	pr_debug(" %s (%u)\n", __func__, phy->pid);

	if (phy->hw_type == PHY_HWIP_SPHY3) {
		usb_set_bits(pbase, U3P_DIG_GLB_60, P3D_CKM_XTAL_CK_DETECT_DIS);
		usb_clr_bits(pbase, U3P_DIG_GLB_60, P3D_CKM_GATED_BIAS_DIS);
		sphy3_u3_lane0_init(phy);
	} else if (phy->hw_type == PHY_HWIP_SPHY4) {
		// Apply detection option in P3 and backs to sleep
		usb_set_bits(pbase, U3P_DIG_GLB_38, P3D_TX_DET_P3_TRACK_OPTION);

		sphy4_u3_lane_init(phy, 0);
		sphy4_u3_lane_init(phy, 1);
	}
}

static void sphy_u3_exit(struct mtk_usb_phy *phy)
{}

static int sphy_power_on(struct usb3_sphy *sphy)
{
	struct mtk_usb_phy *phy;
	int i;

	if (!sphy)
		return 0;

	for (i = 0; i < sphy->phy_cnt; i++) {
		phy = &sphy->phys[i];

		sphy_u2_init(phy);
		sphy_u2_param_tune(phy);

		if (phy->type == PHY_TYPE_USB3)
			sphy_u3_init(phy);
	}

	pr_debug(" %s\n", __func__);
	return 0;
}

static int sphy_power_off(struct usb3_sphy *sphy)
{
	struct mtk_usb_phy *phy;
	int i;

	if (!sphy)
		return 0;

	for (i = 0; i < sphy->phy_cnt; i++) {
		phy = &sphy->phys[i];

		sphy_u2_exit(phy);

		if (phy->type == PHY_TYPE_USB3)
			sphy_u3_exit(phy);
	}

	pr_debug(" %s\n", __func__);
	return 0;
}

static void usb3_ippc_disable(struct xhci_plat_priv *priv)
{
	void __iomem *ibase = priv->ippc_base;
	u32 i;

	dev_dbg(priv->dev, " %s\n", __func__);

	// power down and disable u3 ports
	for (i = 0; i < priv->u3port_cnt; i++) {
		if (BIT(i) & priv->u3port_disable_mask)
			continue;

		usb_set_bits(ibase, IPPC_U3_CTRL(i), CTRL_U3_PORT_PDN | CTRL_U3_PORT_DIS);
	}

	// power down and disable all u2 ports
	for (i = 0; i < priv->u2port_cnt; i++)
		usb_set_bits(ibase, IPPC_U2_CTRL(i), CTRL_U2_PORT_PDN | CTRL_U2_PORT_DIS);

	// power down host ip
	usb_set_bits(ibase, IPPC_IP_PW_CTRL1, CTRL1_IP_HOST_PDN);
}

static int usb3_ippc_enable(struct xhci_plat_priv *priv)
{
	void __iomem *ibase = priv->ippc_base;
	u32 check_val;
	u32 u3port_dis_cnt = 0;
	u32 i;
	int status;

	dev_dbg(priv->dev, " %s\n", __func__);

	// disable ck gate
	usb_clr_bits(ibase, IPPC_CSR_CK_CTRL, CK_CSR_BUS_CK_GATE_EN | CK_PHY_BUS_CK_GATE_EN);

	// power on host ip
	usb_clr_bits(ibase, IPPC_IP_PW_CTRL1, CTRL1_IP_HOST_PDN);

	// power on and enable u3 ports
	for (i = 0; i < priv->u3port_cnt; i++) {
		if (BIT(i) & priv->u3port_disable_mask) {
			usb_set_bits(ibase, IPPC_U3_CTRL(i), CTRL_U3_PORT_PDN | CTRL_U3_PORT_DIS);
			u3port_dis_cnt++;
			continue;
		}

		usb_update_bits(ibase, IPPC_U3_CTRL(i),
				CTRL_U3_PORT_PDN | CTRL_U3_PORT_DIS | CTRL_U3_PORT_HOST_SEL,
				CTRL_U3_PORT_HOST_SEL);
	}

	// power on and enable all u2 ports
	for (i = 0; i < priv->u2port_cnt; i++) {
		usb_update_bits(ibase, IPPC_U2_CTRL(i),
				CTRL_U2_PORT_PDN | CTRL_U2_PORT_DIS | CTRL_U2_PORT_HOST_SEL,
				CTRL_U2_PORT_HOST_SEL);
	}

	//
	// wait for clocks to be stable, and clock domains reset to
	// be inactive after power on and enable ports
	//
	check_val = STS1_SYSPLL_STABLE | STS1_REF_RST | STS1_SYS125_RST | STS1_XHCI_RST;
	if (priv->u3port_cnt > u3port_dis_cnt)
		check_val |= STS1_U3_MAC_RST;

	status = usb_read_poll_timeout(ibase, IPPC_IP_PW_STS1, check_val, U3_CLK_WAIT_MS);
	if (status)
		dev_warn(priv->dev, " xHCI wait clocks timeout\n");

	return status;
}

static int usb3_ippc_enter_lps(struct xhci_plat_priv *priv)
{
	void __iomem *ibase = priv->ippc_base;
	u32 i;
	int status;

	// power down u3 ports
	for (i = 0; i < priv->u3port_cnt; i++) {
		if (BIT(i) & priv->u3port_disable_mask)
			continue;

		usb_set_bits(ibase, IPPC_U3_CTRL(i), CTRL_U3_PORT_PDN);
	}

	// power down all u2 ports
	for (i = 0; i < priv->u2port_cnt; i++)
		usb_set_bits(ibase, IPPC_U2_CTRL(i), CTRL_U2_PORT_PDN);

	// power down host ip
	usb_set_bits(ibase, IPPC_IP_PW_CTRL1, CTRL1_IP_HOST_PDN);

	status = usb_read_poll_timeout(ibase, IPPC_IP_PW_STS1, STS1_IP_SLEEP, 10);
	if (status)
		dev_err(priv->dev, " xHCI sleep failed\n");

	dev_info(priv->dev, " ip-sleep %d\n",
		!!(usb_read(ibase, IPPC_IP_PW_STS1) & STS1_IP_SLEEP));

	return status;
}

static int usb3_ippc_exit_lps(struct xhci_plat_priv *priv)
{
	void __iomem *ibase = priv->ippc_base;
	u32 i;
	int status;

	dev_info(priv->dev, " ip-sleep %d\n",
		!!(usb_read(ibase, IPPC_IP_PW_STS1) & STS1_IP_SLEEP));

	// clear reset
	usb_clr_bits(ibase, IPPC_IP_PW_CTRL0, CTRL0_IP_SW_RST);

	// disable ck gate
	usb_clr_bits(ibase, IPPC_CSR_CK_CTRL, CK_CSR_BUS_CK_GATE_EN | CK_PHY_BUS_CK_GATE_EN);

	// power on host ip
	usb_clr_bits(ibase, IPPC_IP_PW_CTRL1, CTRL1_IP_HOST_PDN);

	// power on u3 ports
	for (i = 0; i < priv->u3port_cnt; i++) {
		if (BIT(i) & priv->u3port_disable_mask) {
			usb_set_bits(ibase, IPPC_U3_CTRL(i), CTRL_U3_PORT_PDN | CTRL_U3_PORT_DIS);
			continue;
		}

		usb_update_bits(ibase, IPPC_U3_CTRL(i),
				CTRL_U3_PORT_PDN | CTRL_U3_PORT_DIS | CTRL_U3_PORT_HOST_SEL,
				CTRL_U3_PORT_HOST_SEL);
	}

	// power on all u2 ports
	for (i = 0; i < priv->u2port_cnt; i++) {
		usb_update_bits(ibase, IPPC_U2_CTRL(i),
				CTRL_U2_PORT_PDN | CTRL_U2_PORT_DIS | CTRL_U2_PORT_HOST_SEL,
				CTRL_U2_PORT_HOST_SEL);
	}

	status = usb_read_poll_timeout(ibase, IPPC_IP_PW_STS1,
				       STS1_SYSPLL_STABLE | STS1_XHCI_RST, U3_CLK_WAIT_MS);
	if (status)
		dev_err(priv->dev, " xHCI wait clocks timeout\n");

	return status;
}

static void usb3_ippc_get_port_cnt(struct xhci_plat_priv *priv)
{
	u32 cap;

	cap = usb_read(priv->ippc_base, IPPC_IP_XHCI_CAP);
	priv->u2port_cnt = CAP_U2_PORT_NUM(cap);
	priv->u3port_cnt = CAP_U3_PORT_NUM(cap);

	dev_dbg(priv->dev, " xHCI - u2 ports:%u, u3 ports:%u\n",
		priv->u2port_cnt, priv->u3port_cnt);
}

static void usb3_ip_reset(struct xhci_plat_priv *priv)
{
	// Todo: peri top reset?

	// reset whole ip
	usb_set_bits(priv->ippc_base, IPPC_IP_PW_CTRL0, CTRL0_IP_SW_RST);
	udelay(1);
	usb_clr_bits(priv->ippc_base, IPPC_IP_PW_CTRL0, CTRL0_IP_SW_RST);

	// power down device ip, otherwise ip-sleep will fail
	usb_set_bits(priv->ippc_base, IPPC_IP_PW_CTRL2, CTRL2_IP_DEV_PDN);
}

static void usb3_hsram_init(struct xhci_plat_priv *priv)
{
	void __iomem *embase = priv->ext_mac_base;
	int i;

	usb_write(embase, TEST_HSRAM_DBGCTL, THDC_SRAM_DBG_EN);
	usb_write(embase, TEST_HSRAM_DBGMODE, THDM_SRAM_DM_EP_SLOT);
	usb_write(embase, TEST_HSRAM_DBGSEL, THDS_SRAM_DS_EP_SLOT);

	for (i = 0; i < TEST_HSRAM_ARRAY_SIZE; i++) {
		usb_write(embase, TEST_HSRAM_DBGADR,
			  THDA_SRAM_ADDR_VAL(i) | THDA_SRAM_DWSEL_VAL(THDA_DWSEL_32B_TO_64B));
		usb_write(embase, TEST_HSRAM_DBGDR, 0);
	}

	// restore default value
	usb_write(embase, TEST_HSRAM_DBGCTL, THDC_SRAM_DBG_WP);
	usb_write(embase, TEST_HSRAM_DBGMODE, 0);
	usb_write(embase, TEST_HSRAM_DBGSEL, 0);
}

static void usb3_mac_ext_init(struct xhci_plat_priv *priv)
{
	void __iomem *embase = priv->ext_mac_base;

	// workaround:
	// SSUSB INTR EP not resume link after doorbell issue, can't enter u1/u2
	// when isoc is active;
	usb_set_bits(embase, TEST_HSCH_CFG1, THC1_PORT_IDLE_WITH_ISO);
	usb_set_bits(embase, TEST_HSCH_CFG1, THC1_PORT_IDLE_WITH_INT);
	// SSUSB ISO ACK missing due to unexpected PING reject issue
	// don't check TD status, just resume anyway
	usb_clr_bits(embase, TEST_HSCH_CFG1, THC1_SCH3_INT_PING_TD_CHK);
	// isoc miss service error when run multi ep stress test(bulk/intr/isoc)
	usb_set_bits(embase, TEST_HSCH_CFG1, THC1_BURST_TD_OFF | THC1_OUT_NUMP_REF);
	// decrease LS/FS default BW overhead
	usb_update_bits(embase, TEST_SCH_CFG6,
			(TSC6_OH_LS_INT_IN_MSK | TSC6_OH_LS_INT_OUT_MSK),
			(TSC6_OH_LS_INT_IN_VAL(TSC6_OH_LS_INT_DFT) |
			 TSC6_OH_LS_INT_OUT_VAL(TSC6_OH_LS_INT_DFT)));
	usb_update_bits(embase, TEST_SCH_CFG5,
			(TSC5_OH_FS_INT_IN_MSK | TSC5_OH_FS_INT_OUT_MSK),
			(TSC5_OH_FS_INT_IN_VAL(TSC5_OH_FS_INT_DFT) |
			 TSC5_OH_FS_INT_OUT_VAL(TSC5_OH_FS_INT_DFT)));
	usb_update_bits(embase, TEST_SCH_CFG5,
			(TSC5_OH_FS_ISO_IN_MSK | TSC5_OH_FS_ISO_OUT_MSK),
			(TSC5_OH_FS_ISO_IN_VAL(TSC5_OH_FS_ISO_DFT) |
			 TSC5_OH_FS_ISO_OUT_VAL(TSC5_OH_FS_ISO_DFT)));

	// fix Gen2 SSD UASP Read performance low issue
	usb_update_bits(embase, TEST_XACT3_CFG, TXC_TX_TMOUT_MSK,
			TXC_TX_TMOUT_VAL(TXC_TX_TMOUT_VAL_DFT));

	// WA for xhcicv test
	usb_set_bits(embase, TEST_CMD_CFG, TCC_PARAM_ERR_CHK_DIS);
	usb_clr_bits(embase, TEST_RST_CTRL0, TRC_HCRST_RXDETECT_EN);
	usb_set_bits(embase, TEST_EP_CFG, TEC_STOP_EP_OPT);
	usb_set_bits(embase, TEST_TRBQ_CFG, TTC_TRB_ERR_CHK_DIS);

	usb3_hsram_init(priv);
}

static int xhci_mtk_restore_local(struct xhci_plat_priv *priv)
{
	int ret;

	sphy_power_on(&priv->sphy);

	usb3_ippc_get_port_cnt(priv);

	ret = usb3_ippc_exit_lps(priv);
	if (ret)
		return ret;

	usb3_mac_ext_init(priv);

	return 0;
}

int xhci_mtk_exit_lps(struct xhci_hcd *xhci)
{
	struct xhci_plat_priv *priv = xhci_to_priv(xhci);
	int ret;

	dev_dbg(priv->dev, " %s\n", __func__);

	ret = mtk_pwrap_dev_resume(priv->pwrap_cfg, 0);
	if (ret) {
		dev_err(priv->dev, "pwrap resume failed (%d)\n", ret);
		return ret;
	}

	return xhci_mtk_restore_local(priv);
}

int xhci_mtk_enter_lps(struct xhci_hcd *xhci)
{
	struct xhci_plat_priv *priv = xhci_to_priv(xhci);
	int ret, rollback_ret;

	ret = usb3_ippc_enter_lps(priv);
	if (ret)
		goto restore_local;

	sphy_power_off(&priv->sphy);

	ret = mtk_pwrap_dev_suspend(priv->pwrap_cfg, 0);
	if (!ret)
		return 0;

	dev_err(priv->dev, "pwrap suspend failed (%d)\n", ret);

	/*
	 * A failed Power Wrap request may still have reached firmware. Confirm
	 * D0 before accessing local USB registers during rollback.
	 */
	rollback_ret = mtk_pwrap_dev_resume(priv->pwrap_cfg, 0);
	if (rollback_ret) {
		dev_err(priv->dev, "pwrap suspend rollback failed (%d)\n",
			rollback_ret);
		/* Let the normal resume callback retry D0 before touching MMIO. */
		return 0;
	}

restore_local:
	rollback_ret = xhci_mtk_restore_local(priv);
	if (rollback_ret) {
		dev_err(priv->dev, "failed to restore local hardware (%d)\n",
			rollback_ret);
		/* Keep PM bookkeeping suspended for a later recovery attempt. */
		return 0;
	}

	return ret;
}

int xhci_mtk_prepare_hw(struct xhci_hcd *xhci)
{
	struct xhci_plat_priv *priv = xhci_to_priv(xhci);
	int ret;

	dev_dbg(priv->dev, " %s\n", __func__);

	// power up
	priv->pwrap_cfg = mtk_pwrap_dev_probe((char *)priv->acpi_path.pointer);
	if (!priv->pwrap_cfg) {
		dev_err(priv->dev, "Not find power wrap config data\n");
		return -EINVAL;
	}

	sphy_power_on(&priv->sphy);

	usb3_ip_reset(priv);

	usb3_ippc_get_port_cnt(priv);

	ret = usb3_ippc_enable(priv);
	if (ret) {
		xhci_mtk_release_hw(xhci);
		return ret;
	}

	usb3_mac_ext_init(priv);

	return 0;
}

void xhci_mtk_release_hw(struct xhci_hcd *xhci)
{
	struct xhci_plat_priv *priv = xhci_to_priv(xhci);

	usb3_ippc_disable(priv);

	sphy_power_off(&priv->sphy);

	mtk_pwrap_dev_remove(priv->pwrap_cfg);
	priv->pwrap_cfg = NULL;
}

int xhci_mtk_get_resources(struct platform_device *pdev, struct xhci_hcd *xhci)
{
	struct xhci_plat_priv *priv = xhci_to_priv(xhci);
	struct device *dev = &pdev->dev;
	struct acpi_device *adev = ACPI_COMPANION(dev);
	acpi_status status;
	void __iomem *phy_base;
	struct usb3_sphy *sphy;
	struct mtk_usb_phy *phy;
	u32 phy_type = 0;
	u32 eye_swing[2] = {0, };
	u32 disth = 0;
	u32 deemph = 0;
	u32 txldo = 0;
	int ret;

	if (!adev)
		return dev_err_probe(dev, -ENODEV, "missing ACPI companion\n");

	// required
	ret = device_property_read_u32(dev, "mtk-phy-type", &phy_type);
	if (ret)
		return dev_err_probe(dev, ret, "missing mtk-phy-type\n");
	dev_info(dev, "mtk-phy-type: %x\n", phy_type);

	priv->ext_mac_base = devm_platform_ioremap_resource(pdev, 1);
	if (IS_ERR(priv->ext_mac_base)) {
		ret = PTR_ERR(priv->ext_mac_base);
		goto err_ext_mac;
	}

	priv->ippc_base = devm_platform_ioremap_resource(pdev, 2);
	if (IS_ERR(priv->ippc_base)) {
		ret = PTR_ERR(priv->ippc_base);
		goto err_ippc;
	}

	phy_base = devm_platform_ioremap_resource(pdev, 3);
	if (IS_ERR(phy_base)) {
		ret = PTR_ERR(phy_base);
		goto err_phy;
	}

	priv->dev = dev;
	priv->acpi_path.length = ACPI_ALLOCATE_BUFFER;
	priv->acpi_path.pointer = NULL;
	status = acpi_get_name(adev->handle, ACPI_FULL_PATHNAME, &priv->acpi_path);
	if (ACPI_FAILURE(status)) {
		dev_err(&pdev->dev, "Failed to get ACPI device path\n");
		return -EINVAL;
	}

	ret = acpi_dev_uid_to_integer(adev, &priv->uid);
	if (ret)
		dev_err(&pdev->dev, "error: no _UID found\n");
	else
		dev_info(&pdev->dev, "find acpi _UID: %x\n", (int)priv->uid);

	// optional
	device_property_read_u32(dev, "mtk-u3port-disable-mask", &priv->u3port_disable_mask);
	dev_info(&pdev->dev, "mtk-u3port-disable-mask: %x\n", priv->u3port_disable_mask);

	// optional
	device_property_read_u32(dev, "mtk-u2phy-discth", &disth);
	dev_info(&pdev->dev, "mtk-u2phy-discth: %x\n", disth);

	// optional
	device_property_read_u32(dev, "mtk-u2phy-de-emphasis", &deemph);
	dev_info(&pdev->dev, "mtk-u2phy-de-emphasis: %x\n", deemph);

	// optional
	device_property_read_u32(dev, "mtk-u2phy-tx-ldo-out", &txldo);
	dev_info(&pdev->dev, "mtk-u2phy-tx-ldo-out: %x\n", txldo);

	/*
	 * get u2phy eye swing adjust, optional
	 * Note: tune Term only when Vref is max 7, otherwise Term is ignored
	 */
	device_property_read_u32_array(dev, "mtk-u2phy-eye-swing", eye_swing, 2);
	dev_info(dev, "eye swing: val[0]=0x%x, val[1]=0x%x\n", eye_swing[0], eye_swing[1]);

	sphy = &priv->sphy;
	sphy->phy_cnt = 1; // by default
	phy = &sphy->phys[0];
	phy->port_base = phy_base;
	phy->hw_type = phy_type;
	phy->pid = PHY_ID_U3_P0;
	phy->type = PHY_TYPE_USB3;
	phy->u3p_offset = SPHY_U3_BASE_OFFSET;
	phy->u2p_eye_swing_vref = eye_swing[0];
	phy->u2p_eye_swing_term = eye_swing[1];
	phy->u2p_eye_rising_deemphasis = deemph;
	phy->u2p_eye_rising_txldoout = txldo;
	phy->u2p_disconnect_threshold = disth;

	// p4u3 port-1 has the 2nd u2 port
	if (priv->uid == 0x5) {
		sphy->phy_cnt = 2;
		phy = &sphy->phys[1];
		phy->port_base = phy_base + SPHY_PORT_BANKS_SIZE;
		phy->hw_type = phy_type;
		phy->pid = PHY_ID_U2_P1;
		phy->type = PHY_TYPE_USB2;
		phy->u2p_eye_swing_vref = eye_swing[0];
		phy->u2p_eye_swing_term = eye_swing[1];
		phy->u2p_eye_rising_deemphasis = deemph;
		phy->u2p_eye_rising_txldoout = txldo;
		phy->u2p_disconnect_threshold = disth;
	}

	return 0;

err_ext_mac:
err_ippc:
err_phy:
	return ret;
}

void xhci_mtk_free_resources(struct platform_device *pdev, struct xhci_hcd *xhci)
{
	struct xhci_plat_priv *priv = xhci_to_priv(xhci);

	ACPI_FREE(priv->acpi_path.pointer);
	priv->acpi_path.pointer = NULL;
	priv->acpi_path.length = 0;
}
