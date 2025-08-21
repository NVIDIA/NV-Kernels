// SPDX-License-Identifier: GPL-2.0
#include <linux/device.h>
#include <linux/dev_printk.h>
#include <linux/lockdep.h>
#include "base.h"

/*
 * Confidential devices implement encrypted + integrity protected MMIO and have
 * the ability to issue DMA to encrypted + integrity protected System RAM. The
 * device_cc_*() helpers aid buses in setting the acceptance state, drivers in
 * preparing and probing the acceptance state, and other kernel subsystem in
 * augmenting behavior in the presence of accepted devices (e.g.
 * ioremap_encrypted()).
 */

/**
 * device_cc_accept(): Mark a device as accepted for TEE operation
 * @dev: device to accept
 *
 * Confidential bus drivers use this helper to accept devices at initial
 * enumeration, or dynamically one attestation has been performed.
 *
 * Given that moving a device into confidential / private operation implicates
 * any of MMIO mapping attributes, physical address, and IOMMU mappings this
 * transition must be done while the device is idle (driver detached).
 *
 * This is an internal helper for buses not device drivers.
 */
int device_cc_accept(struct device *dev)
{
	lockdep_assert_held(&dev->mutex);

	if (dev->driver)
		return -EBUSY;
	dev->p->cc_accepted = true;

	return 0;
}

int device_cc_reject(struct device *dev)
{
	lockdep_assert_held(&dev->mutex);

	if (dev->driver)
		return -EBUSY;
	dev->p->cc_accepted = false;

	return 0;
}

/**
 * device_cc_accepted(): Get the TEE operational state of a device
 * @dev: device to check
 *
 * Various subsystems, mm/ioremap, drivers/iommu, drivers/vfio, kernel/dma...
 * need to augment their behavior in the presence of confidential devices. This
 * simple, deliberately not exported, helper is for those built-in consumers.
 *
 * This is an internal helper for subsystems not device drivers.
 */
bool device_cc_accepted(struct device *dev)
{
	return dev->p->cc_accepted;
}

/**
 * device_cc_probe(): Coordinate dynamic acceptance with a device driver
 * @dev: device to defer probing while acceptance pending
 *
 * Dynamically accepted devices may need a driver to perform initial
 * configuration to get the device into a state where it can be accepted. Use
 * this helper to exit driver probe at that partial device-init point and log
 * this TEE acceptance specific deferral reason.
 *
 * This is an exported helper for device drivers that need to coordinate device
 * configuration state and acceptance.
 */
int device_cc_probe(struct device *dev)
{
	/*
	 * See work_on_cpu() in local_pci_probe() for one reason why
	 * lockdep_assert_held() can not be used here.
	 */
	WARN_ON_ONCE(!mutex_is_locked(&dev->mutex));

	if (!dev->driver)
		return -EINVAL;

	if (dev->p->cc_accepted)
		return 0;

	dev_err_probe(dev, -EPROBE_DEFER, "TEE acceptance pending\n");

	return -EPROBE_DEFER;
}
EXPORT_SYMBOL_GPL(device_cc_probe);
