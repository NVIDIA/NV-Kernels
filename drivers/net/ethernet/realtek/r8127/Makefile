# SPDX-License-Identifier: GPL-2.0-only
################################################################################
#
# r8127 is the Linux device driver released for Realtek 10 Gigabit Ethernet
# controllers with PCI-Express interface.
#
# Copyright(c) 2025 Realtek Semiconductor Corp. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses/>.
#
# Author:
# Realtek NIC software team <nicfae@realtek.com>
# No. 2, Innovation Road II, Hsinchu Science Park, Hsinchu 300, Taiwan
#
################################################################################

################################################################################
#  This product is covered by one or more of the following patents:
#  US6,570,884, US6,115,776, and US6,327,625.
################################################################################

ccflags-y += -DCONFIG_SOC_LAN -DCONFIG_R8127_NAPI -DCONFIG_R8127_VLAN -DCONFIG_ASPM -DENABLE_S5WOL -DENABLE_EEE -DENABLE_TX_NO_CLOSE -DENABLE_GIGA_LITE -DENABLE_PTP_SUPPORT
obj-$(CONFIG_R8127) += r8127.o
r8127-y := r8127_n.o rtl_eeprom.o rtltool.o r8127_ptp.o
