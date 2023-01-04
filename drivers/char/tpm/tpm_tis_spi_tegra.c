// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023 NVIDIA CORPORATION.
 *
 * This device driver implements TEGRA QSPI hw wait detection for chips
 *
 * It is based on tpm_tis_spi driver by Peter Huewe and Christophe Ricard.
 */

#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pm.h>
#include <linux/spi/spi.h>
#include <linux/wait.h>

#include "tpm_tis_core.h"
#include "tpm_tis_spi.h"

#define MAX_SPI_FRAMESIZE 64

int tpm_tis_spi_tegra_transfer(struct tpm_tis_data *data, u32 addr, u16 len,
			 u8 *in, const u8 *out)
{
	struct tpm_tis_spi_phy *phy = to_tpm_tis_spi_phy(data);
	int ret = 0;
	struct spi_message m;
	struct spi_transfer spi_xfer[3];
	u8 transfer_len;

	spi_bus_lock(phy->spi_device->master);

	while (len) {
		transfer_len = min_t(u16, len, MAX_SPI_FRAMESIZE);

		spi_message_init(&m);
		phy->iobuf[0] = (in ? 0x80 : 0) | (transfer_len - 1);
		phy->iobuf[1] = 0xd4;
		phy->iobuf[2] = addr >> 8;
		phy->iobuf[3] = addr;

		memset(&spi_xfer, 0, sizeof(spi_xfer));

		spi_xfer[0].tx_buf = phy->iobuf;
		spi_xfer[0].len = 1;
		spi_message_add_tail(&spi_xfer[0], &m);

		spi_xfer[1].tx_buf = phy->iobuf + 1;
		spi_xfer[1].len = 3;
		spi_message_add_tail(&spi_xfer[1], &m);

		if (out) {
			spi_xfer[2].tx_buf = &phy->iobuf[4];
			spi_xfer[2].rx_buf = NULL;
			memcpy(&phy->iobuf[4], out, transfer_len);
			out += transfer_len;
		}
		if (in) {
			spi_xfer[2].tx_buf = NULL;
			spi_xfer[2].rx_buf = &phy->iobuf[4];
		}
		spi_xfer[2].len = transfer_len;
		spi_message_add_tail(&spi_xfer[2], &m);

		reinit_completion(&phy->ready);
		ret = spi_sync_locked(phy->spi_device, &m);
		if (ret < 0)
			goto exit;

		if (in) {
			memcpy(in, &phy->iobuf[4], transfer_len);
			in += transfer_len;
		}

		len -= transfer_len;
	}

exit:
	spi_bus_unlock(phy->spi_device->master);
	return ret;
}

static int tpm_tis_spi_tegra_read_bytes(struct tpm_tis_data *data, u32 addr,
				       u16 len, u8 *result, enum tpm_tis_io_mode io_mode)
{
	return tpm_tis_spi_tegra_transfer(data, addr, len, result, NULL);
}

static int tpm_tis_spi_tegra_write_bytes(struct tpm_tis_data *data, u32 addr,
					u16 len, const u8 *value, enum tpm_tis_io_mode io_mode)
{
	return tpm_tis_spi_tegra_transfer(data, addr, len, NULL, value);
}

static const struct tpm_tis_phy_ops tegra_tpm_spi_phy_ops = {
	.read_bytes = tpm_tis_spi_tegra_read_bytes,
	.write_bytes = tpm_tis_spi_tegra_write_bytes,
};

int tegra_tpm_spi_probe(struct spi_device *dev)
{
	struct tpm_tis_spi_phy *phy;
	int irq;

	phy = devm_kzalloc(&dev->dev, sizeof(struct tpm_tis_spi_phy),
			   GFP_KERNEL);
	if (!phy)
		return -ENOMEM;

	phy->flow_control = NULL;

	/* If the SPI device has an IRQ then use that */
	if (dev->irq > 0)
		irq = dev->irq;
	else
		irq = -1;

	init_completion(&phy->ready);
	return tpm_tis_spi_init(dev, phy, irq, &tegra_tpm_spi_phy_ops);
}
