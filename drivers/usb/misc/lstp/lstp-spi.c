// SPDX-License-Identifier: GPL-2.0-only
/*
 * SPI driver for LSTP USB interface.
 *
 * Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/err.h>
#include <linux/kmod.h>
#include <linux/spi/spi.h>

#include "lstp-main.h"

/*******************************************************************************
 * SPI command definitions
 ******************************************************************************/

enum lstp_spi_cmd {
	LSTP_SPI_CMD_READ = 0x01,
	LSTP_SPI_CMD_WRITE = 0x02,
	LSTP_SPI_CMD_WRITE_READ = 0x03,
	LSTP_SPI_CMD_POSTED_WRITE = 0x04
};

/* clang-format off */
enum lstp_spi_cmd_cs_toggle {
	LSTP_SPI_CMD_CS_ASSERT = 0x20,
	LSTP_SPI_CMD_CS_DEASSERT = 0x10
}; /* clang-format on */

/* clang-format off */
enum lstp_spi_cmd_cs_sel {
	LSTP_SPI_CMD_CS0 = 0x00,
	LSTP_SPI_CMD_CS1 = 0x40
}; /* clang-format on */
/* clang-format off */
static const u8 lstp_spi_cs_map[] = {
	LSTP_SPI_CMD_CS0,
	LSTP_SPI_CMD_CS1
}; /* clang-format on */

struct lstp_spi_read_req {
	__le32 len;
} __packed;

struct lstp_spi_config {
	u8 num_devices;
	__le32 speed_hz;
} __packed;

/* Private data for SPI controller */
struct lstp_spi_priv {
	struct spi_controller *ctrl;
	u32 current_speed_hz;
};

/* Defaults for backwards compatibility with firmware lacking SPI channel config */
#define LSTP_SPI_DEFAULT_NUM_DEVICES 2
#define LSTP_SPI_DEFAULT_SPEED_HZ 18750000 /* 18.75 MHz */

/*******************************************************************************
 * SPI controller callbacks
 ******************************************************************************/

/**
 * lstp_spi_do_transfer() - Execute a single SPI transfer with CS flags.
 * @ch:       LSTP channel to transfer on
 * @xfer:     SPI transfer descriptor containing tx/rx buffers and length
 * @cs_bits:  Chip select selection bits (LSTP_SPI_CMD_CS0..CS1)
 * @cs_flags: Chip select toggle flags (LSTP_SPI_CMD_CS_ASSERT/DEASSERT)
 *
 * Core transfer routine shared by lstp_spi_transfer_one_message(). Supports
 * three modes based on which buffers are provided:
 * - Write-Read (full duplex): Both tx_buf and rx_buf set
 * - Write only: Only tx_buf set
 * - Read only: Only rx_buf set
 *
 * Caller serialization: provided by spi_controller->io_mutex
 * (transfer_one_message is the only entry point).
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_spi_do_transfer(struct lstp_channel *ch, struct spi_transfer *xfer, u8 cs_bits,
				u8 cs_flags)
{
	struct lstp_spi_priv *priv = ch->priv;
	u8 cmd;
	int ret;

	if (xfer->word_delay.value)
		dev_warn_once(ch->dev, "%s: ch_%d: word_delay not supported, ignoring\n", __func__,
			      ch->ch_id);

	xfer->error = SPI_TRANS_FAIL_NO_START;

	xfer->effective_speed_hz = priv->current_speed_hz;

	if (xfer->tx_buf && xfer->len > ch->max_tx_payload) {
		dev_err(ch->dev, "%s: ch_%d: TX transfer length %u exceeds capacity %zu\n",
			__func__, ch->ch_id, xfer->len, ch->max_tx_payload);
		return -EINVAL;
	}
	if (xfer->rx_buf && xfer->len > ch->max_rx_payload) {
		dev_err(ch->dev, "%s: ch_%d: RX transfer length %u exceeds capacity %zu\n",
			__func__, ch->ch_id, xfer->len, ch->max_rx_payload);
		return -EINVAL;
	}

	if (xfer->tx_buf && xfer->rx_buf) {
		cmd = LSTP_SPI_CMD_WRITE_READ | cs_bits | cs_flags;
		ret = lstp_request(ch, cmd, xfer->tx_buf, xfer->len, xfer->rx_buf, xfer->len, NULL,
				   NULL);
	} else if (xfer->tx_buf) {
		cmd = LSTP_SPI_CMD_WRITE | cs_bits | cs_flags;
		ret = lstp_request(ch, cmd, xfer->tx_buf, xfer->len, NULL, 0, NULL, NULL);
	} else if (xfer->rx_buf) {
		struct lstp_spi_read_req req = { .len = cpu_to_le32(xfer->len) };

		cmd = LSTP_SPI_CMD_READ | cs_bits | cs_flags;
		ret = lstp_request(ch, cmd, &req, sizeof(req), xfer->rx_buf, xfer->len, NULL, NULL);
	} else {
		return -EINVAL;
	}

	if (ret) {
		dev_err(ch->dev, "%s: ch_%d: Transfer failed (%pe)\n", __func__, ch->ch_id,
			ERR_PTR(ret));
		xfer->error = SPI_TRANS_FAIL_IO;
		return ret;
	}

	xfer->error = 0;
	return 0;
}

/**
 * lstp_spi_transfer_one_message() - Execute a complete SPI message.
 * @ctrl: SPI controller performing the transfer
 * @mesg: SPI message containing one or more transfers
 *
 * Processes all transfers in a message, embedding chip select assert/deassert
 * flags directly into each transfer command. This avoids the separate USB
 * round-trips that would be needed if the SPI core managed CS via a set_cs
 * callback.
 *
 * CS management follows standard SPI semantics:
 * - CS is asserted before the first transfer
 * - CS is deasserted after the last transfer
 * - xfer->cs_change inverts the default: deasserts mid-message, or leaves
 *   CS asserted after the last transfer
 *
 * On completion (success or failure), calls spi_finalize_current_message()
 * so the subsystem can issue the next queued message.
 *
 * Context: Process context. Performs blocking USB I/O. Caller
 * serialization is provided by spi_controller->io_mutex.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_spi_transfer_one_message(struct spi_controller *ctrl, struct spi_message *mesg)
{
	struct lstp_channel *ch = spi_controller_get_devdata(ctrl);
	struct spi_transfer *xfer;
	u8 chip_select = spi_get_chipselect(mesg->spi, 0);
	u8 cs_bits;
	int ret = 0;
	bool cs_active = false;

	if (chip_select >= ctrl->num_chipselect) {
		dev_err(ch->dev, "%s: ch_%d: Invalid chip select %u (max %u)\n", __func__,
			ch->ch_id, chip_select, ctrl->num_chipselect - 1);
		ret = -EINVAL;
		goto finalize;
	}
	cs_bits = lstp_spi_cs_map[chip_select];

	list_for_each_entry(xfer, &mesg->transfers, transfer_list) {
		u8 cs_flags = 0;
		bool is_last = list_is_last(&xfer->transfer_list, &mesg->transfers);

		if (!cs_active) {
			cs_flags |= LSTP_SPI_CMD_CS_ASSERT;
			cs_active = true;
		}

		if ((is_last && !xfer->cs_change) || (!is_last && xfer->cs_change)) {
			cs_flags |= LSTP_SPI_CMD_CS_DEASSERT;
			cs_active = false;
		}

		ret = lstp_spi_do_transfer(ch, xfer, cs_bits, cs_flags);
		if (ret)
			break;

		mesg->actual_length += xfer->len;

		if (!is_last && xfer->cs_change)
			spi_transfer_cs_change_delay_exec(mesg, xfer);

		spi_transfer_delay_exec(xfer);
	}

finalize:
	mesg->status = ret;
	spi_finalize_current_message(ctrl);
	return ret;
}

/**
 * lstp_spi_set_cs_timing() - Validate CS timing parameters for an SPI device.
 * @spi: SPI device whose CS timing is being configured
 *
 * Called by spi_setup(). The LSTP firmware manages CS assertion internally, so
 * fine-grained cs_setup / cs_hold / cs_inactive delays cannot be honoured.
 * Accept the configuration but warn if non-zero values were requested.
 *
 * Return: 0 always (timing is silently ignored).
 */
static int lstp_spi_set_cs_timing(struct spi_device *spi)
{
	struct lstp_channel *ch = spi_controller_get_devdata(spi->controller);

	if (spi->cs_setup.value || spi->cs_hold.value || spi->cs_inactive.value)
		dev_warn(ch->dev, "%s: ch_%d: CS timing delays not supported, ignoring\n", __func__,
			 ch->ch_id);
	return 0;
}

/**
 * lstp_spi_max_xfer_size() - Report maximum transfer size for the SPI controller.
 * @spi: SPI device querying the maximum size
 *
 * Returns the maximum number of bytes that can be transferred in a single
 * SPI transaction. This is limited by the USB endpoint buffer size minus
 * the LSTP header overhead.
 *
 * Context: Any context.
 *
 * Return: Maximum transfer size in bytes.
 */
static size_t lstp_spi_max_xfer_size(struct spi_device *spi)
{
	struct lstp_channel *ch;

	if (spi) {
		ch = spi_controller_get_devdata(spi->controller);
		return min(ch->max_tx_payload, ch->max_rx_payload);
	}

	return LSTP_USB_EP_MAX_SIZE - sizeof(struct lstp_header);
}

/*******************************************************************************
 * SPI channel initialization and start
 ******************************************************************************/

/**
 * lstp_spi_create_spidev() - Create spidev devices for the SPI controller.
 * @ctrl: SPI controller to create spidev devices for
 * @ch:   LSTP channel to create spidev devices for
 *
 * Creates spidev devices on a SPI controller based on the number of chip selects.
 * The generic "spidev" modalias is not in spidev's device ID table, so set a
 * driver override before registering each device.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_spi_create_spidev(struct spi_controller *ctrl, struct lstp_channel *ch)
{
	struct lstp_spi_priv *priv = ch->priv;
	struct spi_device *spi;
	int ret;
	u8 cs;

	/* driver_override does not provide a module alias, so load spidev first. */
	request_module("spidev");

	for (cs = 0; cs < ctrl->num_chipselect; cs++) {
		spi = spi_alloc_device(ctrl);
		if (!spi)
			return -ENOMEM;

		spi_set_chipselect(spi, 0, cs);
		spi->cs_index_mask = BIT(0);
		spi->max_speed_hz = priv->current_speed_hz;
		spi->mode = SPI_MODE_0;
		strscpy(spi->modalias, "spidev", sizeof(spi->modalias));

		ret = device_set_driver_override(&spi->dev, "spidev");
		if (ret)
			goto err_put;

		ret = spi_add_device(spi);
		if (ret)
			goto err_put;

		if (!device_is_bound(&spi->dev)) {
			dev_err(ch->dev, "%s: ch_%d: Could not bind spidev for CS%u\n", __func__,
				ch->ch_id, cs);
			spi_unregister_device(spi);
			return -ENODEV;
		}
	}

	return 0;

err_put:
	spi_dev_put(spi);
	dev_err(ch->dev, "%s: ch_%d: Could not create spidev for CS%u (%pe)\n", __func__,
		ch->ch_id, cs, ERR_PTR(ret));
	return ret;
}

/**
 * lstp_spi_init() - Initialize an LSTP SPI channel.
 * @ch:   LSTP channel to initialize as SPI controller
 * @info: config blob (struct lstp_spi_config); legacy defaults if absent or short
 *
 * Allocates and initializes the SPI controller but does not register it; call
 * lstp_spi_start() once the RX URB is active to register it and create a spidev
 * for each chip select.
 *
 * Context: Process context. Called during probe before RX URB is active.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_spi_init(struct lstp_channel *ch, const struct lstp_channel_init_info *info)
{
	struct lstp_spi_priv *priv;
	struct spi_controller *ctrl;
	const struct lstp_spi_config *config = info->config_len >= sizeof(*config) ? info->config :
										     NULL;
	u8 num_devices;
	u32 speed_hz;

	priv = devm_kzalloc(ch->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	ctrl = devm_spi_alloc_host(ch->dev, 0);
	if (!ctrl)
		return -ENOMEM;

	/* Parse SPI config (uses defaults if no config is present) */
	if (config) {
		num_devices = config->num_devices;
		speed_hz = le32_to_cpu(config->speed_hz);
	} else {
		/* TODO: Legacy support - remove this at some point */
		dev_err(ch->dev, "%s: ch_%d: No SPI channel config, using defaults\n", __func__,
			ch->ch_id);
		num_devices = LSTP_SPI_DEFAULT_NUM_DEVICES;
		speed_hz = LSTP_SPI_DEFAULT_SPEED_HZ;
	}

	if (num_devices == 0 || num_devices > ARRAY_SIZE(lstp_spi_cs_map)) {
		dev_err(ch->dev, "%s: ch_%d: Invalid num_devices %u (max %zu)\n", __func__,
			ch->ch_id, num_devices, ARRAY_SIZE(lstp_spi_cs_map));
		return -EINVAL;
	}

	if (speed_hz == 0) {
		dev_err(ch->dev, "%s: ch_%d: Device returned SPI speed of %u Hz\n", __func__,
			ch->ch_id, speed_hz);
		return -EINVAL;
	}

	spi_controller_set_devdata(ctrl, ch);
	ctrl->bus_num = -1;
	ctrl->num_chipselect = num_devices;
	ctrl->bits_per_word_mask = SPI_BPW_MASK(8);
	ctrl->min_speed_hz = speed_hz;
	ctrl->max_speed_hz = speed_hz;
	ctrl->transfer_one_message = lstp_spi_transfer_one_message;
	ctrl->max_transfer_size = lstp_spi_max_xfer_size;
	ctrl->set_cs_timing = lstp_spi_set_cs_timing;

	/* Set firmware node so SPI core auto-enumerates child devices (DT or ACPI) */
	device_set_node(&ctrl->dev, ch->fwnode);

	priv->ctrl = ctrl;
	priv->current_speed_hz = speed_hz;

	ch->priv = priv;

	dev_dbg(ch->dev, "%s: ch_%d: Initialized as %s\n", __func__, ch->ch_id, ch->display_name);
	return 0;
}

/**
 * lstp_spi_start() - Start an LSTP SPI channel.
 * @ch: LSTP channel to start
 *
 * Registers the SPI controller with the Linux SPI subsystem and creates
 * a spidev device for each chip select so that userspace can access the
 * bus via /dev/spidevN.CS.
 *
 * Context: Process context. Called during probe after RX URB is active.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_spi_start(struct lstp_channel *ch)
{
	int ret;
	struct lstp_spi_priv *priv = ch->priv;
	struct spi_controller *ctrl;

	if (!priv || !priv->ctrl) {
		dev_err(ch->dev, "%s: ch_%d: SPI controller not initialized\n", __func__,
			ch->ch_id);
		return -EINVAL;
	}

	ctrl = priv->ctrl;

	ret = devm_spi_register_controller(ch->dev, ctrl);
	if (ret) {
		dev_err(ch->dev, "%s: ch_%d: Could not register SPI controller (%pe)\n", __func__,
			ch->ch_id, ERR_PTR(ret));
		return ret;
	}

	if (ch->fwnode) {
		unsigned int child_count = 0;
		struct fwnode_handle *child;

		fwnode_for_each_available_child_node(ch->fwnode, child)
			child_count++;

		if (child_count == 0) {
			dev_warn(ch->dev,
				 "%s: ch_%d: Firmware node present but defines no SPI devices\n",
				 __func__, ch->ch_id);
		} else {
			dev_info(ch->dev, "%s: ch_%d: Firmware node present with %u SPI devices\n",
				 __func__, ch->ch_id, child_count);
		}
	} else if (lstp_auto_bind_spidev) {
		ret = lstp_spi_create_spidev(ctrl, ch);
		if (ret)
			return ret;
	}

	deprecated_lstp_channel_publish_child_dev(ch, &ctrl->dev);

	dev_info(ch->dev, "%s: ch_%d: Started as %s (devices=%u, speed=%u Hz)\n", __func__,
		 ch->ch_id, ch->display_name, ctrl->num_chipselect, priv->current_speed_hz);
	return 0;
}

/* clang-format off */
LSTP_SUBSYS(spi, LSTP_CHANNEL_TYPE_SPI, lstp_spi_init, lstp_spi_start,
	    .fwnode_compatible = "nvidia,lstp-spi",
);
/* clang-format on */
