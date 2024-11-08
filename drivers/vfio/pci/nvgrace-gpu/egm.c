// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/vfio_pci_core.h>
#include <linux/hashtable.h>
#include <linux/egm.h>
#include <linux/nvgrace-egm.h>
#include <linux/memory-failure.h>
#include <linux/vmalloc.h>

#define MAX_EGM_NODES 256

struct gpu_node {
       struct list_head list;
       struct pci_dev *pdev;
};

struct egm_region {
	struct list_head list;
	int egmpxm;
	atomic_t open_count;
	phys_addr_t egmphys;
	size_t egmlength;
	struct device device;
	struct cdev cdev;
	struct list_head gpus;
	DECLARE_HASHTABLE(htbl, 0x10);
	struct pfn_address_space pfn_address_space;
};

struct h_node {
	unsigned long mem_offset;
	struct hlist_node node;
};

static dev_t dev;
static struct class *class;
static struct list_head egm_list;

static int pfn_memregion_offset(struct egm_region *region,
				unsigned long pfn,
				pgoff_t *pfn_offset_in_region)
{
	unsigned long start_pfn, num_pages;

	start_pfn = PHYS_PFN(region->egmphys);
	num_pages = region->egmlength >> PAGE_SHIFT;

	if (pfn < start_pfn || pfn >= start_pfn + num_pages)
		return -EFAULT;

	*pfn_offset_in_region = pfn - start_pfn;

	return 0;
}

static int track_ecc_offset(struct egm_region *region,
			    unsigned long mem_offset)
{
	struct h_node *cur_page, *ecc_page;
	unsigned long bkt;

	hash_for_each(region->htbl, bkt, cur_page, node) {
		if (cur_page->mem_offset == mem_offset)
			return 0;
	}

	ecc_page = (struct h_node *)(vzalloc(sizeof(struct h_node)));
	if (!ecc_page)
		return -ENOMEM;

	ecc_page->mem_offset = mem_offset;

	hash_add(region->htbl, &ecc_page->node, ecc_page->mem_offset);

	return 0;
}

static int nvgrace_egm_pfn_to_vma_pgoff(struct vm_area_struct *vma,
					unsigned long pfn,
					pgoff_t *pgoff)
{
	struct egm_region *region = vma->vm_file->private_data;
	pgoff_t vma_offset_in_region = vma->vm_pgoff &
		((1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	pgoff_t pfn_offset_in_region;
	int ret;

	ret = pfn_memregion_offset(region, pfn, &pfn_offset_in_region);
	if (ret)
		return ret;

	/* Ensure PFN is not before VMA's start within the region */
	if (pfn_offset_in_region < vma_offset_in_region)
		return -EFAULT;

	/* Calculate offset from VMA start */
	*pgoff = vma->vm_pgoff +
		 (pfn_offset_in_region - vma_offset_in_region);

	/* Track and save the poisoned offset */
	return track_ecc_offset(region, *pgoff << PAGE_SHIFT);
}

static int
nvgrace_egm_vfio_pci_register_pfn_range(struct inode *inode,
					struct egm_region *region)
{
	int ret;
	unsigned long pfn, nr_pages;

	pfn = PHYS_PFN(region->egmphys);
	nr_pages = region->egmlength >> PAGE_SHIFT;

	region->pfn_address_space.node.start = pfn;
	region->pfn_address_space.node.last = pfn + nr_pages - 1;
	region->pfn_address_space.mapping = inode->i_mapping;
	region->pfn_address_space.pfn_to_vma_pgoff = nvgrace_egm_pfn_to_vma_pgoff;

	ret = register_pfn_address_space(&region->pfn_address_space);

	return ret;
}

static int nvgrace_egm_open(struct inode *inode, struct file *file)
{
	void *memaddr;
	struct egm_region *region = container_of(inode->i_cdev,
						 struct egm_region, cdev);
	int ret;

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

	ret = nvgrace_egm_vfio_pci_register_pfn_range(inode, region);
	if (ret && ret != -EOPNOTSUPP) {
		file->private_data = NULL;
		return ret;
	}

	return 0;
}

static int nvgrace_egm_release(struct inode *inode, struct file *file)
{
	struct egm_region *region = container_of(inode->i_cdev,
						 struct egm_region, cdev);

	if (atomic_dec_and_test(&region->open_count)) {
		unregister_pfn_address_space(&region->pfn_address_space);

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
	{
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
					return -EFAULT;
				index++;
			}

			info.count = index;
		}
		break;
	}
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

static void destroy_egm_chardev(struct egm_region *region)
{
	cdev_device_del(&region->cdev, &region->device);
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

	if (overflows_type(*pegmlength, size_t))
		return -EOVERFLOW;

	ret = device_property_read_u64(&pdev->dev, "nvidia,egm-base-pa",
				       pegmphys);
	if (ret)
		return ret;

	if (overflows_type(*pegmphys, phys_addr_t))
		return -EOVERFLOW;

	ret = device_property_read_u64(&pdev->dev, "nvidia,egm-pxm",
				       pegmpxm);
	if (ret)
		return ret;

	if (overflows_type(*pegmpxm, int))
		return -EOVERFLOW;

	return 0;
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

	/* Catch firmware bug and avoid a crash */
	if (WARN_ON_ONCE(retiredpagesphys == 0))
		return;

	memaddr = memremap(retiredpagesphys, PAGE_SIZE, MEMREMAP_WB);
	if (!memaddr)
		return;

	count = *(u64 *)memaddr;

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

static ssize_t gpu_devices_show(struct device *dev, struct device_attribute *attr,
                               char *buf)
{
       struct egm_region *region =
               container_of(dev, struct egm_region, device);
       struct gpu_node *node, *temp_node;
       int len = 0;

       list_for_each_entry_safe(node, temp_node, &region->gpus, list) {
               struct pci_dev *pdev = node->pdev;

               len += sysfs_emit_at(buf, len, "%04x:%02x:%02x.%x\n",
                                    pci_domain_nr(pdev->bus),
                                    pdev->bus->number,
                                    PCI_SLOT(pdev->devfn),
                                    PCI_FUNC(pdev->devfn));
       }

       return len;
}

static DEVICE_ATTR_RO(gpu_devices);

static ssize_t egm_size_show(struct device *dev, struct device_attribute *attr,
                            char *buf)
{
       struct egm_region *region =
               container_of(dev, struct egm_region, device);
       return sysfs_emit(buf, "0x%lx\n", region->egmlength);
}

static DEVICE_ATTR_RO(egm_size);

static struct attribute *attrs[] = {
       &dev_attr_gpu_devices.attr,
       &dev_attr_egm_size.attr,
       NULL,
};

static struct attribute_group attr_group = {
       .attrs = attrs,
};

static int add_gpu(struct egm_region *region, struct pci_dev *pdev)
{
       struct gpu_node *node;

       node = kvzalloc(sizeof(*node), GFP_KERNEL);
       if (!node)
               return -ENOMEM;

       node->pdev = pdev;

       list_add_tail(&node->list, &region->gpus);
       return 0;
}

static void remove_gpu(struct egm_region *region, struct pci_dev *pdev)
{
       struct gpu_node *node, *tmp;

       list_for_each_entry_safe(node, tmp, &region->gpus, list) {
               if (node->pdev == pdev) {
                       list_del(&node->list);
                       kvfree(node);
               }
       }
}

int register_egm_node(struct pci_dev *pdev)
{
	struct egm_region *region = NULL;
	u64 egmphys, egmlength, egmpxm;
	int ret;

	ret = nvgrace_gpu_fetch_egm_property(pdev, &egmphys, &egmlength, &egmpxm);
	if (ret)
		return ret;

	/* Check if region already exists */
	list_for_each_entry(region, &egm_list, list) {
		if (region->egmphys == egmphys) {
			/* Add GPU to existing region */
			return add_gpu(region, pdev);
		}
	}

	/* Create new region */
	region = kvzalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;

	region->egmphys = egmphys;
	region->egmlength = egmlength;
	region->egmpxm = egmpxm;

	hash_init(region->htbl);
	INIT_LIST_HEAD(&region->gpus);

	atomic_set(&region->open_count, 0);

	nvgrace_egm_fetch_bad_pages(pdev, region);

	ret = setup_egm_chardev(region);
	if (ret)
		goto err_free_region;

	list_add_tail(&region->list, &egm_list);

	ret = sysfs_create_group(&region->device.kobj, &attr_group);
	if (ret)
		goto err_remove_from_list;

	ret = add_gpu(region, pdev);
	if (ret)
		goto err_remove_sysfs;

	return 0;

err_remove_sysfs:
        sysfs_remove_group(&region->device.kobj, &attr_group);
err_remove_from_list:
	list_del(&region->list);
	destroy_egm_chardev(region);
err_free_region:
	kfree(region);
	return ret;
}
EXPORT_SYMBOL_GPL(register_egm_node);

void unregister_egm_node(struct pci_dev *pdev)
{
	struct egm_region *region, *temp_region;
	struct h_node *cur_page;
	unsigned long bkt;
	struct hlist_node *temp_node;
	u64 egmphys, egmlength, egmpxm;
	int ret;

	ret = nvgrace_gpu_fetch_egm_property(pdev, &egmphys, &egmlength, &egmpxm);
	if (ret)
		return;

	list_for_each_entry_safe(region, temp_region, &egm_list, list) {
		if (egmpxm == region->egmpxm) {
			remove_gpu(region, pdev);
			if (!list_empty(&region->gpus))
				break;

			hash_for_each_safe(region->htbl, bkt, temp_node, cur_page, node) {
				hash_del(&cur_page->node);
				vfree(cur_page);
			}

			sysfs_remove_group(&region->device.kobj, &attr_group);
			destroy_egm_chardev(region);
			list_del(&region->list);
			kfree(region);
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
