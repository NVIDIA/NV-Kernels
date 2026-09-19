/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 MediaTek Inc.
 *
 * Author: Chunfeng Yun <chunfeng.yun@mediatek.com>
 */

#ifndef __LINUX_XHCI_MTK_V2_H
#define __LINUX_XHCI_MTK_V2_H

#include <dt-bindings/phy/phy.h>
#include <linux/acpi.h>

#include "xhci.h"

enum phy_hwip_type {
	PHY_HWIP_SPHY3 = 3,
	PHY_HWIP_SPHY4,
};

enum usb_phy_id {
	PHY_ID_U3_P0 = 0,
	PHY_ID_U2_P1,
	PHY_ID_U2_P2,
	PHY_ID_U2_P3,
};

struct mtk_usb_phy {
	void __iomem *port_base;
	u32 u3p_offset;	// when support u3
	u32 pid;
	u32 type;
	enum phy_hwip_type hw_type;
	u32  u2p_disconnect_threshold;
	u32  u2p_eye_swing_vref;
	u32  u2p_eye_swing_term;
	u32  u2p_eye_rising_deemphasis;
	u32  u2p_eye_rising_txldoout;
};

struct usb3_sphy {
	int phy_cnt;	 // total number of hw port, 'u2 + u3' pair or u2 only
	struct mtk_usb_phy phys[4];
};

#if IS_ENABLED(CONFIG_USB_XHCI_MTK_V2)
int xhci_mtk_exit_lps(struct xhci_hcd *xhci);
int xhci_mtk_enter_lps(struct xhci_hcd *xhci);
int xhci_mtk_prepare_hw(struct xhci_hcd *xhci);
void xhci_mtk_release_hw(struct xhci_hcd *xhci);
int xhci_mtk_get_resources(struct platform_device *pdev, struct xhci_hcd *xhci);
void xhci_mtk_free_resources(struct platform_device *pdev, struct xhci_hcd *xhci);

#else

static inline int xhci_mtk_exit_lps(struct xhci_hcd *xhci)
{
	return 0;
}

static inline int xhci_mtk_enter_lps(struct xhci_hcd *xhci)
{
	return 0;
}

static inline int xhci_mtk_prepare_hw(struct xhci_hcd *xhci)
{
	return 0;
}

static inline void xhci_mtk_release_hw(struct xhci_hcd *xhci)
{}

static inline int xhci_mtk_get_resources(struct platform_device *pdev, struct xhci_hcd *xhci)
{
	return 0;
}

static inline void xhci_mtk_free_resources(struct platform_device *pdev, struct xhci_hcd *xhci)
{}

#endif

#endif /* __LINUX_XHCI_MTK_V2_H */
