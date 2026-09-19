// SPDX-License-Identifier: GPL-2.0
/*
 * MediaTek power-wrap hooks for PCIe segments.
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
#include <linux/slab.h>
#include <linux/soc/mediatek/mtk-pwrap.h>
#include <linux/string.h>

#include "pci.h"

struct mtk_pci_pwrap_ctrl {
	void *dev_ctrl;
	char *acpi_path;
	unsigned int port_count;
	unsigned int suspended_count;
	int dstate;
	struct list_head list;
};

struct mtk_pci_pwrap_port {
	struct pci_dev *pdev;
	struct mtk_pci_pwrap_ctrl *ctrl;
	struct list_head list;
	bool suspended;
};

static DEFINE_MUTEX(mtk_pci_pwrap_lock);
static LIST_HEAD(mtk_pci_pwrap_ctrls);
static LIST_HEAD(mtk_pci_pwrap_ports);

static char *mtk_pci_pwrap_get_host_path(struct pci_dev *pdev)
{
	struct pci_host_bridge *host;
	struct acpi_buffer buf = { ACPI_ALLOCATE_BUFFER, NULL };
	acpi_handle handle;
	acpi_status status;

	host = pci_find_host_bridge(pdev->bus);
	if (!host)
		return ERR_PTR(-ENODEV);

	handle = ACPI_HANDLE(&host->dev);
	if (!handle)
		return ERR_PTR(-ENODEV);

	status = acpi_get_name(handle, ACPI_FULL_PATHNAME, &buf);
	if (ACPI_FAILURE(status))
		return ERR_PTR(-ENODEV);

	return buf.pointer;
}

static bool mtk_pci_pwrap_is_root_port(struct pci_dev *pdev)
{
	return pci_is_pcie(pdev) &&
	       pci_pcie_type(pdev) == PCI_EXP_TYPE_ROOT_PORT;
}

static bool mtk_pci_pwrap_should_manage(struct pci_dev *pdev)
{
	bool populated;

	if (!mtk_pci_pwrap_is_root_port(pdev))
		return false;

	down_read(&pci_bus_sem);
	populated = pdev->subordinate &&
		    !list_empty(&pdev->subordinate->devices);
	up_read(&pci_bus_sem);

	return !populated;
}

/*
 * Count every PCIe Root Port the host bridge exposes, including populated
 * ones we deliberately skip at registration.  Segment gating is only safe
 * when the tracked port count equals this full topology count; otherwise
 * an untracked port on the segment could still be active.
 */
static unsigned int mtk_pci_pwrap_host_rp_count(struct pci_dev *pdev)
{
	struct pci_host_bridge *host = pci_find_host_bridge(pdev->bus);
	struct pci_dev *child;
	unsigned int count = 0;

	if (!host || !host->bus)
		return 0;

	down_read(&pci_bus_sem);
	list_for_each_entry(child, &host->bus->devices, bus_list) {
		if (mtk_pci_pwrap_is_root_port(child))
			count++;
	}
	up_read(&pci_bus_sem);

	return count;
}

static struct mtk_pci_pwrap_port *mtk_pci_pwrap_find_port_locked(struct pci_dev *pdev)
{
	struct mtk_pci_pwrap_port *port;

	list_for_each_entry(port, &mtk_pci_pwrap_ports, list) {
		if (port->pdev == pdev)
			return port;
	}

	return NULL;
}

static struct mtk_pci_pwrap_ctrl *mtk_pci_pwrap_find_ctrl_locked(const char *path)
{
	struct mtk_pci_pwrap_ctrl *ctrl;

	list_for_each_entry(ctrl, &mtk_pci_pwrap_ctrls, list) {
		if (!strcmp(ctrl->acpi_path, path))
			return ctrl;
	}

	return NULL;
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
	if (port->suspended && ctrl->suspended_count)
		ctrl->suspended_count--;
	list_del(&port->list);
	mtk_pci_pwrap_put_ctrl_locked(ctrl, &port->pdev->dev);
	mutex_unlock(&mtk_pci_pwrap_lock);
}

void mtk_pci_pwrap_init(struct pci_dev *pdev)
{
	struct mtk_pci_pwrap_ctrl *node;
	struct mtk_pci_pwrap_port *port;
	char *path;
	int ret;

	if (!mtk_pci_pwrap_should_manage(pdev))
		return;

	path = mtk_pci_pwrap_get_host_path(pdev);
	if (IS_ERR(path)) {
		dev_dbg(&pdev->dev, "failed to get ACPI host path: %ld\n",
			PTR_ERR(path));
		return;
	}

	port = devm_kzalloc(&pdev->dev, sizeof(*port), GFP_KERNEL);
	if (!port) {
		ACPI_FREE(path);
		return;
	}

	mutex_lock(&mtk_pci_pwrap_lock);
	if (mtk_pci_pwrap_find_port_locked(pdev))
		goto out_unlock;

	node = mtk_pci_pwrap_find_ctrl_locked(path);
	if (!node) {
		node = kzalloc_obj(*node);
		if (!node)
			goto out_unlock;

		node->acpi_path = path;
		path = NULL;
		node->dstate = DEV_STA_UNKNOWN;
		node->dev_ctrl = mtk_pwrap_dev_probe(node->acpi_path);
		if (!node->dev_ctrl) {
			dev_dbg(&pdev->dev, "no pwrap config for %s\n",
				node->acpi_path);
			ACPI_FREE(node->acpi_path);
			kfree(node);
			goto out_unlock;
		}

		node->dstate = DEV_STA_D0;
		list_add(&node->list, &mtk_pci_pwrap_ctrls);
	}

	port->pdev = pdev;
	port->ctrl = node;
	list_add(&port->list, &mtk_pci_pwrap_ports);
	node->port_count++;

	ret = devm_add_action(&pdev->dev, mtk_pci_pwrap_release_port, port);
	if (ret) {
		list_del(&port->list);
		mtk_pci_pwrap_put_ctrl_locked(node, &pdev->dev);
		dev_warn(&pdev->dev, "pwrap: cleanup registration failed: %d\n", ret);
	}

out_unlock:
	mutex_unlock(&mtk_pci_pwrap_lock);
	ACPI_FREE(path);
}

bool mtk_pci_pwrap_is_managed(struct pci_dev *pdev)
{
	bool managed;

	if (!mtk_pci_pwrap_should_manage(pdev))
		return false;

	mutex_lock(&mtk_pci_pwrap_lock);
	managed = !!mtk_pci_pwrap_find_port_locked(pdev);
	mutex_unlock(&mtk_pci_pwrap_lock);

	return managed;
}

int mtk_pci_pwrap_suspend(struct pci_dev *pdev, bool system_transition)
{
	struct mtk_pci_pwrap_ctrl *node;
	struct mtk_pci_pwrap_port *port;
	int ret = 0;

	if (!mtk_pci_pwrap_should_manage(pdev))
		return 0;

	mutex_lock(&mtk_pci_pwrap_lock);
	port = mtk_pci_pwrap_find_port_locked(pdev);
	if (!port)
		goto out_unlock;

	node = port->ctrl;
	if (!node->dev_ctrl || port->suspended)
		goto out_unlock;

	port->suspended = true;
	node->suspended_count++;

	if (node->suspended_count != node->port_count)
		goto out_unlock;

	if (node->port_count != mtk_pci_pwrap_host_rp_count(pdev))
		goto out_unlock;

	if (node->dstate != DEV_STA_D0)
		goto out_unlock;

	ret = mtk_pwrap_dev_suspend(node->dev_ctrl, system_transition);
	if (ret) {
		if (ret == -ETIMEDOUT) {
			dev_warn(&pdev->dev,
				 "pwrap suspend timed out; assuming D3\n");
			node->dstate = DEV_STA_D3;
			ret = 0;
		} else {
			dev_warn(&pdev->dev, "pwrap suspend failed: %d\n", ret);
			port->suspended = false;
			node->suspended_count--;
		}
		goto out_unlock;
	}

	node->dstate = DEV_STA_D3;

out_unlock:
	mutex_unlock(&mtk_pci_pwrap_lock);
	return ret;
}

int mtk_pci_pwrap_resume(struct pci_dev *pdev, bool system_transition)
{
	struct mtk_pci_pwrap_ctrl *node;
	struct mtk_pci_pwrap_port *port;
	int ret = 0;

	if (!mtk_pci_pwrap_should_manage(pdev))
		return 0;

	mutex_lock(&mtk_pci_pwrap_lock);
	port = mtk_pci_pwrap_find_port_locked(pdev);
	if (!port)
		goto out_unlock;

	node = port->ctrl;
	if (!node->dev_ctrl || !port->suspended)
		goto out_unlock;
	if (node->dstate == DEV_STA_D3) {
		ret = mtk_pwrap_dev_resume(node->dev_ctrl, system_transition);
		if (ret) {
			dev_warn(&pdev->dev, "pwrap resume failed: %d\n", ret);
			goto out_unlock;
		}
		node->dstate = DEV_STA_D0;
	}

	port->suspended = false;
	if (node->suspended_count)
		node->suspended_count--;

out_unlock:
	mutex_unlock(&mtk_pci_pwrap_lock);
	return ret;
}
