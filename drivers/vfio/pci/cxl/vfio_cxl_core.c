// SPDX-License-Identifier: GPL-2.0-only
/*
 * VFIO CXL Core - CXL.mem passthrough for vendor-specific CXL devices
 *
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 *
 * This module extends vfio-pci-core to pass through CXL.mem regions for
 * vendor-specific CXL devices (CXL_DEVTYPE_DEVMEM) that implement HDM-D or
 * HDM-DB decoders but do not report the standard CXL memory expander class
 * code (PCI_CLASS_MEMORY_CXL, 0x0502).  This covers both CXL Type-2
 * accelerators (with CXL.cache) and non-class-code Type-3 variants (e.g.
 * compressed memory devices) which cannot be paravirtualized by the host
 * CXL subsystem and require direct DPA region access from the guest.
 */

#include <linux/vfio_pci_core.h>
#include <linux/pci.h>
#include <cxl/cxl.h>
#include <cxl/pci.h>

#include "../vfio_pci_priv.h"
#include "vfio_cxl_priv.h"

/**
 * vfio_pci_cxl_detect_and_init - Detect and initialize a vendor-specific
 *                                CXL.mem device
 * @vdev: VFIO PCI device
 *
 * Called from vfio_pci_core_register_device(). Detects CXL DVSEC capability
 * and initializes CXL features. On failure vdev->cxl remains NULL and the
 * device operates as a standard PCI device.
 */
void vfio_pci_cxl_detect_and_init(struct vfio_pci_core_device *vdev)
{
}

void vfio_pci_cxl_cleanup(struct vfio_pci_core_device *vdev)
{
}

MODULE_IMPORT_NS("CXL");
