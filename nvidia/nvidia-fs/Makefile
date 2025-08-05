# SPDX-License-Identifier: GPL-2.0
#
# Makefile for NVIDIA GPU Direct Storage (GDS) filesystem driver
#

# Core nvidia-fs object files
nvidia-fs-y := nvfs-core.o nvfs-dma.o nvfs-mmap.o nvfs-pci.o nvfs-proc.o nvfs-mod.o nvfs-kernel-interface.o

# Conditional compilation based on kernel config
nvidia-fs-$(CONFIG_NVIDIA_FS_STATS) += nvfs-stat.o
nvidia-fs-$(CONFIG_NVIDIA_FS_RDMA) += nvfs-rdma.o
nvidia-fs-$(CONFIG_NVIDIA_FS_BATCH) += nvfs-batch.o
nvidia-fs-$(CONFIG_FAULT_INJECTION) += nvfs-fault.o

# Main module target
obj-$(CONFIG_NVIDIA_FS) += nvidia-fs.o

# Compiler flags
ccflags-y += -Wall

# NVIDIA driver headers path (required for nv-p2p.h)
NVIDIA_VERSION := $(shell ls -1d /usr/src/nvidia-* 2>/dev/null | sort -V | tail -1 | xargs basename 2>/dev/null | sed 's/nvidia-//')
NVIDIA_SRC_DIR := /usr/src/nvidia-$(NVIDIA_VERSION)/nvidia
ccflags-y += -I$(NVIDIA_SRC_DIR)

# Read GDS version from file
GDS_VERSION := $(shell cat $(src)/GDS_VERSION 2>/dev/null || echo "0.0")
ccflags-y += -DGDS_VERSION=$(GDS_VERSION)

# Enable statistics by default if CONFIG_NVIDIA_FS_STATS is set
ifdef CONFIG_NVIDIA_FS_STATS
ccflags-y += -DCONFIG_NVFS_STATS=1
endif

# Enable RDMA support if configured
ifdef CONFIG_NVIDIA_FS_RDMA
ccflags-y += -DNVFS_ENABLE_KERN_RDMA_SUPPORT
endif

# Enable batch support if configured
ifdef CONFIG_NVIDIA_FS_BATCH
ccflags-y += -DNVFS_BATCH_SUPPORT=1
endif

# Architecture-specific flags
ifeq ($(CONFIG_ARM64),y)
ccflags-y += -DAARCH64_PLATFORM
endif

# Code coverage support (if enabled)
ifdef CONFIG_GCOV_KERNEL
GCOV_PROFILE := y
endif
