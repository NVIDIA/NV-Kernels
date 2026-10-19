# SPDX-License-Identifier: GPL-2.0

# Composite name power_wrap_drv avoids colliding with the source file power_wrap.o
obj-y += power_wrap_drv.o
power_wrap_drv-y += power_wrap.o
power_wrap_drv-y += power_wrap_sysfs.o
power_wrap_drv-y += acpiutil.o
power_wrap_drv-$(CONFIG_SUSPEND) += power_wrap_lps0.o

ccflags-y += -Wall
ccflags-y += -I$(src)/inc
