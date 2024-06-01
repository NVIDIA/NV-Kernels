/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Intel Corporation
 * Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES
 */
#ifndef __LINUX_IOMMUFD_H
#define __LINUX_IOMMUFD_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/refcount.h>
#include <linux/xarray.h>

struct device;
struct iommufd_device;
struct page;
struct iommufd_ctx;
struct iommufd_access;
struct iommufd_hwpt_paging;
struct file;
struct iommu_group;
struct iommu_user_data_array;

/* Base struct for all objects with a userspace ID handle. */
struct iommufd_object {
	refcount_t shortterm_users;
	refcount_t users;
	unsigned int type; /* enum iommufd_object_type in iommufd_private.h */
	unsigned int id;
};

struct iommufd_viommu {
	struct iommufd_object obj;
	struct iommufd_ctx *ictx;
	struct iommu_device *iommu_dev;
	struct iommufd_hwpt_paging *hwpt;
	struct xarray vdev_ids;

	const struct iommufd_viommu_ops *ops;

	unsigned int type;
};

struct iommufd_vdev_id {
	struct iommufd_viommu *viommu;
	struct device *dev;
	u64 vdev_id;

	struct list_head idev_item;
};

/**
 * struct iommufd_viommu_ops - viommu specific operations
 * @free: Free all driver-specific parts of an iommufd_viommu. The memory
 *        of the entire viommu will be free-ed by iommufd core
 * @set_vdev_id: Set a virtual device id for a device assigned to a viommu.
 *               Driver allocates an iommufd_vdev_id and return its pointer.
 * @unset_vdev_id: Unset a virtual device id for a device assigned to a viommu.
 *                 iommufd core frees the memory pointed by an iommufd_vdev_id.
 * @cache_invalidate: Flush hardware cache used by a viommu. It can be used for
 *                    any IOMMU hardware specific cache as long as a viommu has
 *                    enough information to identify it: for example, a VMID or
 *                    a vdev_id lookup table.
 *                    The @array passes in the cache invalidation requests, in
 *                    form of a driver data structure. A driver must update the
 *                    array->entry_num to report the number of handled requests.
 *                    The data structure of the array entry must be defined in
 *                    include/uapi/linux/iommufd.h
 */
struct iommufd_viommu_ops {
	void (*free)(struct iommufd_viommu *viommu);
	struct iommufd_vdev_id *(*set_vdev_id)(struct iommufd_viommu *viommu,
					       struct device *dev, u64 vdev_id);
	void (*unset_vdev_id)(struct iommufd_vdev_id *vdev_id);
	int (*cache_invalidate)(struct iommufd_viommu *viommu,
				struct iommu_user_data_array *array);
};

struct iommufd_device *iommufd_device_bind(struct iommufd_ctx *ictx,
					   struct device *dev, u32 *id);
void iommufd_device_unbind(struct iommufd_device *idev);

int iommufd_device_attach(struct iommufd_device *idev, u32 *pt_id);
int iommufd_device_replace(struct iommufd_device *idev, u32 *pt_id);
void iommufd_device_detach(struct iommufd_device *idev);

struct iommufd_ctx *iommufd_device_to_ictx(struct iommufd_device *idev);
u32 iommufd_device_to_id(struct iommufd_device *idev);

struct iommufd_access_ops {
	u8 needs_pin_pages : 1;
	void (*unmap)(void *data, unsigned long iova, unsigned long length);
};

enum {
	IOMMUFD_ACCESS_RW_READ = 0,
	IOMMUFD_ACCESS_RW_WRITE = 1 << 0,
	/* Set if the caller is in a kthread then rw will use kthread_use_mm() */
	IOMMUFD_ACCESS_RW_KTHREAD = 1 << 1,

	/* Only for use by selftest */
	__IOMMUFD_ACCESS_RW_SLOW_PATH = 1 << 2,
};

struct iommufd_access *
iommufd_access_create(struct iommufd_ctx *ictx,
		      const struct iommufd_access_ops *ops, void *data, u32 *id);
void iommufd_access_destroy(struct iommufd_access *access);
int iommufd_access_attach(struct iommufd_access *access, u32 ioas_id);
int iommufd_access_replace(struct iommufd_access *access, u32 ioas_id);
void iommufd_access_detach(struct iommufd_access *access);

void iommufd_ctx_get(struct iommufd_ctx *ictx);

#if IS_ENABLED(CONFIG_IOMMUFD)
struct iommufd_ctx *iommufd_ctx_from_file(struct file *file);
struct iommufd_ctx *iommufd_ctx_from_fd(int fd);
void iommufd_ctx_put(struct iommufd_ctx *ictx);
bool iommufd_ctx_has_group(struct iommufd_ctx *ictx, struct iommu_group *group);

int iommufd_access_pin_pages(struct iommufd_access *access, unsigned long iova,
			     unsigned long length, struct page **out_pages,
			     unsigned int flags);
void iommufd_access_unpin_pages(struct iommufd_access *access,
				unsigned long iova, unsigned long length);
int iommufd_access_rw(struct iommufd_access *access, unsigned long iova,
		      void *data, size_t len, unsigned int flags);
int iommufd_vfio_compat_ioas_get_id(struct iommufd_ctx *ictx, u32 *out_ioas_id);
int iommufd_vfio_compat_ioas_create(struct iommufd_ctx *ictx);
int iommufd_vfio_compat_set_no_iommu(struct iommufd_ctx *ictx);

struct iommufd_viommu *
__iommufd_viommu_alloc(struct iommufd_ctx *ictx, size_t size,
		       const struct iommufd_viommu_ops *ops);
struct iommufd_vdev_id *__iommufd_vdev_id_alloc(size_t size);
struct device *
iommufd_viommu_find_device(struct iommufd_viommu *viommu, u64 id);
struct iommu_domain *
iommufd_viommu_to_parent_domain(struct iommufd_viommu *viommu);
#else /* !CONFIG_IOMMUFD */
static inline struct iommufd_ctx *iommufd_ctx_from_file(struct file *file)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void iommufd_ctx_put(struct iommufd_ctx *ictx)
{
}

static inline int iommufd_access_pin_pages(struct iommufd_access *access,
					   unsigned long iova,
					   unsigned long length,
					   struct page **out_pages,
					   unsigned int flags)
{
	return -EOPNOTSUPP;
}

static inline void iommufd_access_unpin_pages(struct iommufd_access *access,
					      unsigned long iova,
					      unsigned long length)
{
}

static inline int iommufd_access_rw(struct iommufd_access *access, unsigned long iova,
		      void *data, size_t len, unsigned int flags)
{
	return -EOPNOTSUPP;
}

static inline int iommufd_vfio_compat_ioas_create(struct iommufd_ctx *ictx)
{
	return -EOPNOTSUPP;
}

static inline int iommufd_vfio_compat_set_no_iommu(struct iommufd_ctx *ictx)
{
	return -EOPNOTSUPP;
}

static inline struct iommufd_viommu *
__iommufd_viommu_alloc(struct iommufd_ctx *ictx, size_t size,
		       const struct iommufd_viommu_ops *ops)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline struct iommufd_vdev_id *__iommufd_vdev_id_alloc(size_t size)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline struct device *
iommufd_viommu_find_device(struct iommufd_viommu *viommu, u64 id)
{
	return NULL;
}

static inline struct iommu_domain *
iommufd_viommu_to_parent_domain(struct iommufd_viommu *viommu)
{
	return NULL;
}
#endif /* CONFIG_IOMMUFD */

/*
 * Helpers for IOMMU driver to allocate driver structures that will be freed by
 * the iommufd core. Yet, a driver is responsible for its own struct cleanup.
 */
#define iommufd_viommu_alloc(ictx, drv_struct, member, ops)                    \
	container_of(__iommufd_viommu_alloc(ictx,                              \
					    sizeof(struct drv_struct) +        \
					    BUILD_BUG_ON_ZERO(offsetof(        \
						struct drv_struct, member)),   \
					    ops),                              \
		     struct drv_struct, member)
#define iommufd_vdev_id_alloc(drv_struct, member)                              \
	container_of(__iommufd_vdev_id_alloc(sizeof(struct drv_struct) +       \
					     BUILD_BUG_ON_ZERO(offsetof(       \
						struct drv_struct, member))),  \
		     struct drv_struct, member)
#endif
