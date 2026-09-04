# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for MediaTek SoundWire driver
#

soundwire-mtk-y := mtk-sdw.o mtk-sdw-top.o mtk-sdw-core.o mtk-sdw-mach.o mtk-sdw-chipglue.o
soundwire-mtk-$(CONFIG_SOUNDWIRE_MTK_MT8901_CLK) += mt8901-afe-clk.o
obj-$(CONFIG_SOUNDWIRE_MTK) += soundwire-mtk.o
