// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/vfio_pci_core.h>
#include "egm.h"

#define MAX_EGM_NODES 256

struct egm_region {
	struct list_head list;
	int egmpxm;
	atomic_t open_count;
	phys_addr_t egmphys;
	size_t egmlength;
	struct device device;
	struct cdev cdev;
};

static dev_t dev;
static struct class *class;
static struct list_head egm_list;

static int nvgrace_egm_open(struct inode *inode, struct file *file)
{
	void *memaddr;
	struct egm_region *region = container_of(inode->i_cdev,
						 struct egm_region, cdev);

	if (!region)
		return -EINVAL;

	if (atomic_inc_return(&region->open_count) > 1)
		return 0;

	memaddr = memremap(region->egmphys, region->egmlength, MEMREMAP_WB);
	if (!memaddr) {
		atomic_dec(&region->open_count);
		return -EINVAL;
	}

	memset((u8 *)memaddr, 0, region->egmlength);
	memunmap(memaddr);
	file->private_data = region;

	return 0;
}

static int nvgrace_egm_release(struct inode *inode, struct file *file)
{
	struct egm_region *region = container_of(inode->i_cdev,
						 struct egm_region, cdev);

	if (!region)
		return -EINVAL;

	if (atomic_dec_and_test(&region->open_count))
		file->private_data = NULL;

	return 0;
}

static int nvgrace_egm_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret = 0;
	struct egm_region *region = file->private_data;

	if (!region)
		return -EINVAL;

	ret = remap_pfn_range(vma, vma->vm_start,
			      PHYS_PFN(region->egmphys),
			      (vma->vm_end - vma->vm_start),
			      vma->vm_page_prot);
	return ret;
}

static const struct file_operations file_ops = {
	.owner = THIS_MODULE,
	.open = nvgrace_egm_open,
	.release = nvgrace_egm_release,
	.mmap = nvgrace_egm_mmap,
};

static int setup_egm_chardev(struct egm_region *region)
{
	int ret = 0;

	device_initialize(&region->device);

	/*
	 * Use the proximity domain number as the device minor
	 * number. So the EGM corresponding to node X would be
	 * /dev/egmX.
	 */
	region->device.devt = MKDEV(MAJOR(dev), region->egmpxm);
	region->device.class = class;
	cdev_init(&region->cdev, &file_ops);
	region->cdev.owner = THIS_MODULE;

	ret = dev_set_name(&region->device, "egm%d", region->egmpxm);
	if (ret)
		return ret;

	ret = cdev_device_add(&region->cdev, &region->device);

	return ret;
}

static int
nvgrace_gpu_fetch_egm_property(struct pci_dev *pdev, u64 *pegmphys,
			       u64 *pegmlength, u64 *pegmpxm)
{
	int ret;

	/*
	 * The memory information is present in the system ACPI tables as DSD
	 * properties nvidia,egm-base-pa and nvidia,egmm-size.
	 */
	ret = device_property_read_u64(&pdev->dev, "nvidia,egm-size",
				       pegmlength);
	if (ret)
		return ret;

	if (*pegmlength > type_max(size_t))
		return -EOVERFLOW;

	ret = device_property_read_u64(&pdev->dev, "nvidia,egm-base-pa",
				       pegmphys);
	if (ret)
		return ret;

	if (*pegmphys > type_max(phys_addr_t))
		return -EOVERFLOW;

	ret = device_property_read_u64(&pdev->dev, "nvidia,egm-pxm",
				       pegmpxm);

	if (*pegmpxm > type_max(phys_addr_t))
		return -EOVERFLOW;

	return ret;
}

int register_egm_node(struct pci_dev *pdev)
{
	struct egm_region *region = NULL;
	u64 egmphys, egmlength, egmpxm;
	int ret;

	ret = nvgrace_gpu_fetch_egm_property(pdev, &egmphys, &egmlength, &egmpxm);
	if (ret)
		return ret;

	list_for_each_entry(region, &egm_list, list) {
		if (region->egmphys == egmphys)
			return 0;
	}

	region = kvzalloc(sizeof(*region), GFP_KERNEL);
	region->egmphys = egmphys;
	region->egmlength = egmlength;
	region->egmpxm = egmpxm;

	atomic_set(&region->open_count, 0);

	list_add_tail(&region->list, &egm_list);

	setup_egm_chardev(region);

	return 0;
}
EXPORT_SYMBOL_GPL(register_egm_node);

static void destroy_egm_chardev(struct egm_region *region)
{
	cdev_device_del(&region->cdev, &region->device);
}

void unregister_egm_node(int egm_node)
{
	struct egm_region *region, *temp_region;

	list_for_each_entry_safe(region, temp_region, &egm_list, list) {
		if (egm_node == region->egmpxm) {
			destroy_egm_chardev(region);
			list_del(&region->list);
		}
	}
}
EXPORT_SYMBOL_GPL(unregister_egm_node);

static char *egm_devnode(const struct device *device, umode_t *mode)
{
	if (mode)
		*mode = 0600;

	return NULL;
}

static int __init nvgrace_egm_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&dev,
				  0, MAX_EGM_NODES, "egm");
	if (ret < 0)
		return ret;

	class = class_create("egm");
	if (IS_ERR(class)) {
		unregister_chrdev_region(dev, MAX_EGM_NODES);
		return PTR_ERR(class);
	}

	class->devnode = egm_devnode;

	INIT_LIST_HEAD(&egm_list);

	return 0;
}

static void __exit nvgrace_egm_cleanup(void)
{
	class_destroy(class);
	unregister_chrdev_region(dev, MAX_EGM_NODES);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ankit Agrawal <ankita@nvidia.com>");
MODULE_DESCRIPTION("NVGRACE EGM - Helper module of NVGRACE GPU to support Extended GPU Memory");

module_init(nvgrace_egm_init);
module_exit(nvgrace_egm_cleanup);
