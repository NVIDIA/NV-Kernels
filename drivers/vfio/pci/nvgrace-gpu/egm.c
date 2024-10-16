// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/vfio_pci_core.h>
#include <linux/hashtable.h>
#include <linux/egm.h>
#include <linux/nvgrace-egm.h>

#ifdef CONFIG_MEMORY_FAILURE
#include <linux/bitmap.h>
#include <linux/memory-failure.h>
#endif

#define MAX_EGM_NODES 256

struct egm_region {
	struct list_head list;
	int egmpxm;
	atomic_t open_count;
	phys_addr_t egmphys;
	size_t egmlength;
	struct device device;
	struct cdev cdev;
	DECLARE_HASHTABLE(htbl, 0x10);
#ifdef CONFIG_MEMORY_FAILURE
	struct pfn_address_space pfn_address_space;
#endif
};

struct h_node {
	unsigned long mem_offset;
	struct hlist_node node;
};

static dev_t dev;
static struct class *class;
static struct list_head egm_list;

#ifdef CONFIG_MEMORY_FAILURE
static void
nvgrace_egm_pfn_memory_failure(struct pfn_address_space *pfn_space,
			       unsigned long pfn)
{
	struct egm_region *region =
		container_of(pfn_space, struct egm_region, pfn_address_space);
	unsigned long mem_offset = PFN_PHYS(pfn - pfn_space->node.start);
	struct h_node *ecc;

	if (mem_offset >= region->egmlength)
		return;

	/*
	 * MM has called to notify a poisoned page. Track that in the hastable.
	 */
	ecc = (struct h_node *)(vzalloc(sizeof(struct h_node)));
	ecc->mem_offset = mem_offset;
	hash_add(region->htbl, &ecc->node, ecc->mem_offset);
}

struct pfn_address_space_ops nvgrace_egm_pas_ops = {
	.failure = nvgrace_egm_pfn_memory_failure,
};

static int
nvgrace_egm_register_pfn_range(struct egm_region *region,
			       struct vm_area_struct *vma)
{
	unsigned long nr_pages = region->egmlength >> PAGE_SHIFT;

	region->pfn_address_space.node.start = vma->vm_pgoff;
	region->pfn_address_space.node.last = vma->vm_pgoff + nr_pages - 1;
	region->pfn_address_space.ops = &nvgrace_egm_pas_ops;
	region->pfn_address_space.mapping = vma->vm_file->f_mapping;

	return register_pfn_address_space(&region->pfn_address_space);
}

static vm_fault_t nvgrace_egm_fault(struct vm_fault *vmf)
{
	unsigned long mem_offset = PFN_PHYS(vmf->pgoff - vmf->vma->vm_pgoff);
	struct egm_region *region = vmf->vma->vm_file->private_data;
	struct h_node *cur;

	/*
	 * Check if the page is poisoned.
	 */
	if (mem_offset < region->egmlength) {
		hash_for_each_possible(region->htbl, cur, node, mem_offset) {
			if (cur->mem_offset == mem_offset)
				return VM_FAULT_HWPOISON;
		}
	}

	return VM_FAULT_ERROR;
}

static const struct vm_operations_struct nvgrace_egm_mmap_ops = {
	 .fault = nvgrace_egm_fault,
};

#endif

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

	if (atomic_dec_and_test(&region->open_count)) {
#ifdef CONFIG_MEMORY_FAILURE
		unregister_pfn_address_space(&region->pfn_address_space);
#endif
		file->private_data = NULL;
	}

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
	if (ret)
		return ret;

	vma->vm_pgoff = PHYS_PFN(region->egmphys);

#ifdef CONFIG_MEMORY_FAILURE
	vma->vm_ops = &nvgrace_egm_mmap_ops;

	ret = nvgrace_egm_register_pfn_range(region, vma);
#endif
	return ret;
}

static long nvgrace_egm_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned long minsz = offsetofend(struct egm_bad_pages_list, count);
	struct egm_bad_pages_list info;
	void __user *uarg = (void __user *)arg;
	struct egm_region *region = file->private_data;

	if (copy_from_user(&info, uarg, minsz))
		return -EFAULT;

	if (info.argsz < minsz)
		return -EINVAL;

	if (!region)
		return -EINVAL;

	switch (cmd) {
	case EGM_BAD_PAGES_LIST:
		int ret;
		unsigned long bad_page_struct_size = sizeof(struct egm_bad_pages_info);
		struct egm_bad_pages_info tmp;
		struct h_node *cur_page;
		struct hlist_node *tmp_node;
		unsigned long bkt;
		int count = 0, index = 0;

		hash_for_each_safe(region->htbl, bkt, tmp_node, cur_page, node)
			count++;

		if (info.argsz < (minsz + count * bad_page_struct_size)) {
			info.argsz = minsz + count * bad_page_struct_size;
			info.count = 0;
			goto done;
		} else {
			hash_for_each_safe(region->htbl, bkt, tmp_node, cur_page, node) {
				/*
				 * This check fails if there was an ECC error
				 * after the usermode app read the count of
				 * bad pages through this ioctl.
				 */
				if (minsz + index * bad_page_struct_size >= info.argsz) {
					info.argsz = minsz + index * bad_page_struct_size;
					info.count = index;
					goto done;
				}

				tmp.offset = cur_page->mem_offset;
				tmp.size = PAGE_SIZE;

				ret = copy_to_user(uarg + minsz +
						   index * bad_page_struct_size,
						   &tmp, bad_page_struct_size);
				if (ret)
					return ret;
				index++;
			}

			info.count = index;
		}
		break;
	default:
		return -EINVAL;
	}

done:
	return copy_to_user(uarg, &info, minsz) ? -EFAULT : 0;
}

static const struct file_operations file_ops = {
	.owner = THIS_MODULE,
	.open = nvgrace_egm_open,
	.release = nvgrace_egm_release,
	.mmap = nvgrace_egm_mmap,
	.unlocked_ioctl = nvgrace_egm_ioctl,
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

static void nvgrace_egm_fetch_bad_pages(struct pci_dev *pdev,
					struct egm_region *region)
{
	u64 retiredpagesphys, count;
	void *memaddr;
	int index;

	if (device_property_read_u64(&pdev->dev,
				     "nvidia,egm-retired-pages-data-base",
				     &retiredpagesphys))
		return;

	memaddr = memremap(retiredpagesphys, PAGE_SIZE, MEMREMAP_WB);
	if (!memaddr)
		return;

	count = *(u64 *)memaddr;

	hash_init(region->htbl);

	for (index = 0; index < count; index++) {
		struct h_node *retired_page;

		/*
		 * Since the EGM is linearly mapped, the offset in the
		 * carveout is the same offset in the VM system memory.
		 *
		 * Calculate the offset to communicate to the usermode
		 * apps.
		 */
		retired_page = (struct h_node *)(vzalloc(sizeof(struct h_node)));
		retired_page->mem_offset = *((u64 *)memaddr + index + 1) -
					   region->egmphys;
		hash_add(region->htbl, &retired_page->node, retired_page->mem_offset);
	}

	memunmap(memaddr);
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

	nvgrace_egm_fetch_bad_pages(pdev, region);

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
	struct h_node *cur_page;
	unsigned long bkt;
	struct hlist_node *temp_node;

	list_for_each_entry_safe(region, temp_region, &egm_list, list) {
		if (egm_node == region->egmpxm) {
			hash_for_each_safe(region->htbl, bkt, temp_node, cur_page, node) {
				hash_del(&cur_page->node);
				vfree(cur_page);
			}

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
