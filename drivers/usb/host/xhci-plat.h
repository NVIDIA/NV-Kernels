/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xhci-plat.h - xHCI host controller driver platform Bus Glue.
 *
 * Copyright (C) 2015 Renesas Electronics Corporation
 */

#ifndef _XHCI_PLAT_H
#define _XHCI_PLAT_H

#include "xhci-mtk-v2.h"

struct device;
struct platform_device;
struct usb_hcd;

struct xhci_plat_priv {
	const char *firmware_name;
	unsigned long long quirks;
	bool power_lost;
	unsigned sideband_at_suspend:1;
	unsigned is_mtk_v2:1;
	void (*plat_start)(struct usb_hcd *);
	int (*init_quirk)(struct usb_hcd *);
	int (*suspend_quirk)(struct usb_hcd *);
	int (*resume_quirk)(struct usb_hcd *);
	int (*post_resume_quirk)(struct usb_hcd *);
	struct device *dev;
	void __iomem *ippc_base;
	void __iomem *ext_mac_base;
	void *pwrap_cfg;                /* power wrap scmi configuration */
	struct acpi_buffer acpi_path;   /* ACPI name */
	struct usb3_sphy sphy;
	u64 uid;
	u32 u2port_cnt;
	u32 u3port_cnt;
	u32 u3port_disable_mask;
};

#define hcd_to_xhci_priv(h) ((struct xhci_plat_priv *)hcd_to_xhci(h)->priv)
#define xhci_to_priv(x) ((struct xhci_plat_priv *)(x)->priv)

int xhci_plat_probe(struct platform_device *pdev, struct device *sysdev,
		    const struct xhci_plat_priv *priv_match);

void xhci_plat_remove(struct platform_device *dev);
extern const struct dev_pm_ops xhci_plat_pm_ops;

#endif	/* _XHCI_PLAT_H */
