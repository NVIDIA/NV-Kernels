// SPDX-License-Identifier: GPL-2.0
/*
 * MediaTek Power Wrap coordination for PCIe system suspend.
 *
 * Copyright (c) 2026 MediaTek Inc.
 */

#include <linux/acpi.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/pm_wakeup.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/soc/mediatek/mtk-pwrap.h>
#include <linux/string.h>

#include "pci.h"

struct mtk_pci_pwrap_ctrl {
	void *dev_ctrl;
	char *acpi_path;
	struct pci_bus *root_bus;
	unsigned int port_count;
	unsigned int ready_count;
	enum mtk_pwrap_dev_state dstate;
	struct list_head list;
};

struct mtk_pci_pwrap_port {
	struct pci_dev *pdev;
	struct mtk_pci_pwrap_ctrl *ctrl;
	struct list_head list;
	bool system_ready;
};

static DEFINE_MUTEX(mtk_pci_pwrap_lock);
static DEFINE_MUTEX(mtk_pci_pwrap_gate_lock);
static LIST_HEAD(mtk_pci_pwrap_ctrls);
static LIST_HEAD(mtk_pci_pwrap_ports);

static bool mtk_pci_pwrap_is_root_port(struct pci_dev *pdev)
{
	return pci_is_pcie(pdev) &&
	       pci_pcie_type(pdev) == PCI_EXP_TYPE_ROOT_PORT;
}

static bool mtk_pci_pwrap_port_can_gate(struct pci_dev *pdev)
{
	/*
	 * PCI config space remains accessible through D3hot.  Only extend an
	 * already config-inaccessible D3cold hierarchy to whole-host gating.
	 */
	return !pdev->skip_bus_pm && pdev->current_state == PCI_D3cold &&
	       !device_may_wakeup(&pdev->dev) &&
	       !device_wakeup_path(&pdev->dev);
}

/* Called with pci_bus_sem held for reading. */
static bool mtk_pci_pwrap_bus_can_gate(struct pci_bus *bus)
{
	struct pci_dev *pdev;

	list_for_each_entry(pdev, &bus->devices, bus_list) {
		if (device_may_wakeup(&pdev->dev) ||
		    device_wakeup_path(&pdev->dev) ||
		    !pciehp_is_safe_for_poweroff(pdev))
			return false;

		if (pdev->subordinate &&
		    !mtk_pci_pwrap_bus_can_gate(pdev->subordinate))
			return false;
	}

	return true;
}

static char *mtk_pci_pwrap_get_host_path(struct pci_dev *pdev,
					 struct pci_bus **root_bus)
{
	struct pci_host_bridge *host;
	struct acpi_buffer buf = { ACPI_ALLOCATE_BUFFER, NULL };
	acpi_handle handle;
	acpi_status status;

	host = pci_find_host_bridge(pdev->bus);
	if (!host || !host->bus)
		return ERR_PTR(-ENODEV);

	/*
	 * A controller driver may access its registers outside the child PCI
	 * callbacks.  Only firmware-created root buses have no such parent and
	 * can be safely bracketed here.
	 */
	if (host->dev.parent)
		return ERR_PTR(-EOPNOTSUPP);

	handle = ACPI_HANDLE(&host->dev);
	if (!handle)
		return ERR_PTR(-ENODEV);

	status = acpi_get_name(handle, ACPI_FULL_PATHNAME, &buf);
	if (ACPI_FAILURE(status))
		return ERR_PTR(-ENODEV);

	*root_bus = host->bus;
	return buf.pointer;
}

static struct mtk_pci_pwrap_port *
mtk_pci_pwrap_find_port_locked(struct pci_dev *pdev)
{
	struct mtk_pci_pwrap_port *port;

	list_for_each_entry(port, &mtk_pci_pwrap_ports, list) {
		if (port->pdev == pdev)
			return port;
	}

	return NULL;
}

static struct mtk_pci_pwrap_ctrl *
mtk_pci_pwrap_find_ctrl_locked(const char *path)
{
	struct mtk_pci_pwrap_ctrl *ctrl;

	list_for_each_entry(ctrl, &mtk_pci_pwrap_ctrls, list) {
		if (!strcmp(ctrl->acpi_path, path))
			return ctrl;
	}

	return NULL;
}

static void mtk_pci_pwrap_clear_ready_locked(struct mtk_pci_pwrap_ctrl *ctrl)
{
	struct mtk_pci_pwrap_port *port;

	list_for_each_entry(port, &mtk_pci_pwrap_ports, list) {
		if (port->ctrl == ctrl)
			port->system_ready = false;
	}
	ctrl->ready_count = 0;
}

/*
 * Power Wrap removes config and MMIO access for the complete host segment.
 * Every function directly on the root bus must therefore be a tracked Root
 * Port that has finished its PCI noirq suspend work.
 */
static bool
mtk_pci_pwrap_host_ready_locked(struct mtk_pci_pwrap_ctrl *ctrl)
{
	struct mtk_pci_pwrap_port *port;
	struct pci_dev *child;
	unsigned int count = 0;

	list_for_each_entry(child, &ctrl->root_bus->devices, bus_list) {
		port = mtk_pci_pwrap_find_port_locked(child);
		if (!port || port->ctrl != ctrl || !port->system_ready ||
		    !mtk_pci_pwrap_port_can_gate(child))
			return false;
		count++;
	}

	return count && count == ctrl->port_count &&
	       ctrl->ready_count == ctrl->port_count &&
	       mtk_pci_pwrap_bus_can_gate(ctrl->root_bus);
}

static void mtk_pci_pwrap_free_ctrl_locked(struct mtk_pci_pwrap_ctrl *ctrl)
{
	list_del(&ctrl->list);
	ACPI_FREE(ctrl->acpi_path);
	kfree(ctrl);
}

static void mtk_pci_pwrap_put_ctrl_locked(struct mtk_pci_pwrap_ctrl *ctrl,
					  struct device *dev)
{
	int ret;

	if (--ctrl->port_count)
		return;

	ret = mtk_pwrap_dev_remove(ctrl->dev_ctrl);
	if (ret)
		dev_warn(dev, "pwrap remove failed: %d\n", ret);

	mtk_pci_pwrap_free_ctrl_locked(ctrl);
}

static void mtk_pci_pwrap_release_port(void *data)
{
	struct mtk_pci_pwrap_port *port = data;
	struct mtk_pci_pwrap_ctrl *ctrl = port->ctrl;

	mutex_lock(&mtk_pci_pwrap_lock);
	if (port->system_ready && ctrl->ready_count)
		ctrl->ready_count--;
	list_del(&port->list);
	mtk_pci_pwrap_put_ctrl_locked(ctrl, &port->pdev->dev);
	mutex_unlock(&mtk_pci_pwrap_lock);
}

void mtk_pci_pwrap_init(struct pci_dev *pdev)
{
	struct mtk_pci_pwrap_ctrl *ctrl;
	struct mtk_pci_pwrap_port *port;
	struct pci_bus *root_bus;
	char *path;
	int ret;

	if (!mtk_pci_pwrap_is_root_port(pdev))
		return;

	path = mtk_pci_pwrap_get_host_path(pdev, &root_bus);
	if (IS_ERR(path)) {
		dev_dbg(&pdev->dev, "unsupported pwrap host: %ld\n",
			PTR_ERR(path));
		return;
	}

	port = devm_kzalloc(&pdev->dev, sizeof(*port), GFP_KERNEL);
	if (!port)
		goto out_free_path;

	mutex_lock(&mtk_pci_pwrap_lock);
	if (mtk_pci_pwrap_find_port_locked(pdev))
		goto out_unlock;

	ctrl = mtk_pci_pwrap_find_ctrl_locked(path);
	if (ctrl && ctrl->root_bus != root_bus) {
		dev_warn(&pdev->dev, "pwrap path %s belongs to another host\n",
			 path);
		goto out_unlock;
	}

	if (!ctrl) {
		ctrl = kzalloc_obj(*ctrl);
		if (!ctrl)
			goto out_unlock;

		ctrl->acpi_path = path;
		path = NULL;
		ctrl->root_bus = root_bus;
		ctrl->dev_ctrl = mtk_pwrap_dev_probe(ctrl->acpi_path);
		if (!mtk_pwrap_dev_supports_state_control(ctrl->dev_ctrl)) {
			dev_dbg(&pdev->dev, "no pwrap state control for %s\n",
				ctrl->acpi_path);
			ACPI_FREE(ctrl->acpi_path);
			kfree(ctrl);
			goto out_unlock;
		}

		ctrl->dstate = DEV_STA_D0;
		list_add(&ctrl->list, &mtk_pci_pwrap_ctrls);
	}

	port->pdev = pdev;
	port->ctrl = ctrl;
	list_add(&port->list, &mtk_pci_pwrap_ports);
	ctrl->port_count++;

	ret = devm_add_action(&pdev->dev, mtk_pci_pwrap_release_port, port);
	if (ret) {
		list_del(&port->list);
		mtk_pci_pwrap_put_ctrl_locked(ctrl, &pdev->dev);
		dev_warn(&pdev->dev,
			 "pwrap cleanup registration failed: %d\n", ret);
	}

out_unlock:
	mutex_unlock(&mtk_pci_pwrap_lock);
out_free_path:
	ACPI_FREE(path);
}

bool mtk_pci_pwrap_is_managed(struct pci_dev *pdev)
{
	bool managed;

	if (!mtk_pci_pwrap_is_root_port(pdev))
		return false;

	mutex_lock(&mtk_pci_pwrap_lock);
	managed = !!mtk_pci_pwrap_find_port_locked(pdev);
	mutex_unlock(&mtk_pci_pwrap_lock);

	return managed;
}

static void __noreturn mtk_pci_pwrap_fail_stop(void)
{
	/*
	 * Do not return to PCI when host accessibility is unknown.  Avoid the
	 * panic and restart paths because their dump, notifier, and reset
	 * handlers may touch a device below the host.  MTK_POWER_WRAP is arm64
	 * only, where machine_halt() disables local IRQs and stops other CPUs.
	 */
	machine_halt();
	for (;;)
		cpu_relax();
}

void mtk_pci_pwrap_suspend_noirq(struct pci_dev *pdev)
{
	struct mtk_pci_pwrap_ctrl *ctrl;
	struct mtk_pci_pwrap_port *port;
	bool fatal = false;
	int ret;

	if (!mtk_pci_pwrap_is_root_port(pdev))
		return;

	if (!mtk_pci_pwrap_port_can_gate(pdev))
		return;

	mutex_lock(&mtk_pci_pwrap_lock);
	port = mtk_pci_pwrap_find_port_locked(pdev);
	if (!port || port->system_ready)
		goto out_ready;

	ctrl = port->ctrl;
	if (ctrl->dstate != DEV_STA_D0)
		goto out_ready;

	port->system_ready = true;
	ctrl->ready_count++;
	if (ctrl->ready_count != ctrl->port_count)
		goto out_ready;
	mutex_unlock(&mtk_pci_pwrap_lock);

	/*
	 * PCI devices suspend asynchronously.  Only the final ready port may
	 * compete for the topology locks.  Serialize final ports from different
	 * hosts so one Power Wrap operation cannot make another host miss its
	 * only gating opportunity on the global rescan lock.
	 *
	 * Contention with a real topology operation means the host is not stable
	 * enough to remove ECAM.  Clear the ready set and leave it in D0.
	 */
	mutex_lock(&mtk_pci_pwrap_gate_lock);
	if (!mutex_trylock(&pci_rescan_remove_lock))
		goto clear_ready_gate;
	if (!down_read_trylock(&pci_bus_sem))
		goto clear_ready_rescan;

	mutex_lock(&mtk_pci_pwrap_lock);
	port = mtk_pci_pwrap_find_port_locked(pdev);
	if (!port || !port->system_ready)
		goto out_unlock;

	ctrl = port->ctrl;
	if (ctrl->dstate != DEV_STA_D0) {
		mtk_pci_pwrap_clear_ready_locked(ctrl);
		goto out_unlock;
	}

	if (!mtk_pci_pwrap_host_ready_locked(ctrl)) {
		mtk_pci_pwrap_clear_ready_locked(ctrl);
		goto out_unlock;
	}

	ret = mtk_pwrap_dev_suspend(ctrl->dev_ctrl, true);
	if (ret == -ETIMEDOUT) {
		/*
		 * The command may have completed after the transport timed out, so
		 * neither PM unwind nor a later uncorrelated D0 acknowledgment can
		 * prove the host accessible.  Fail-stop after dropping PCI topology
		 * locks, without logging through a possibly inaccessible device.
		 */
		ctrl->dstate = DEV_STA_UNKNOWN;
		fatal = true;
	} else if (ret) {
		dev_warn(&pdev->dev, "pwrap D3 failed: %d\n", ret);
		/* The host stayed in D0; keep PM unwind callbacks balanced. */
		mtk_pci_pwrap_clear_ready_locked(ctrl);
	} else {
		ctrl->dstate = DEV_STA_D3;
	}

out_unlock:
	mutex_unlock(&mtk_pci_pwrap_lock);
	up_read(&pci_bus_sem);
	mutex_unlock(&pci_rescan_remove_lock);
	if (fatal)
		mtk_pci_pwrap_fail_stop();
	mutex_unlock(&mtk_pci_pwrap_gate_lock);
	return;

clear_ready_rescan:
	mutex_unlock(&pci_rescan_remove_lock);
clear_ready_gate:
	mutex_unlock(&mtk_pci_pwrap_gate_lock);
	mutex_lock(&mtk_pci_pwrap_lock);
	port = mtk_pci_pwrap_find_port_locked(pdev);
	if (port && port->system_ready)
		mtk_pci_pwrap_clear_ready_locked(port->ctrl);
out_ready:
	mutex_unlock(&mtk_pci_pwrap_lock);
}

void mtk_pci_pwrap_resume_noirq(struct pci_dev *pdev)
{
	struct mtk_pci_pwrap_ctrl *ctrl;
	struct mtk_pci_pwrap_port *port;
	int ret = 0;

	if (!mtk_pci_pwrap_is_root_port(pdev))
		return;

	mutex_lock(&mtk_pci_pwrap_lock);
	port = mtk_pci_pwrap_find_port_locked(pdev);
	if (!port)
		goto out_unlock;

	ctrl = port->ctrl;
	if (ctrl->dstate == DEV_STA_UNKNOWN) {
		ret = -EIO;
		goto out_unlock;
	}

	if (ctrl->dstate != DEV_STA_D0) {
		ret = mtk_pwrap_dev_resume(ctrl->dev_ctrl, true);
		if (ret) {
			/* Prevent an asynchronous sibling from retrying D0. */
			ctrl->dstate = DEV_STA_UNKNOWN;
			goto out_unlock;
		}
		ctrl->dstate = DEV_STA_D0;
	}

	mtk_pci_pwrap_clear_ready_locked(ctrl);

out_unlock:
	mutex_unlock(&mtk_pci_pwrap_lock);
	if (ret)
		mtk_pci_pwrap_fail_stop();
}
