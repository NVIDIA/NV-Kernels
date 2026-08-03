// SPDX-License-Identifier: GPL-2.0-only
/*
 * I2C driver for LSTP USB interface.
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

#include <linux/i2c.h>
#include <linux/err.h>
#include <linux/overflow.h>
#include <linux/version.h>

#include "lstp-main.h"

enum lstp_i2c_cmd {
	LSTP_I2C_CMD_BUS_RECOVERY = 0x00,
	LSTP_I2C_CMD_READ = 0x01,
	LSTP_I2C_CMD_WRITE = 0x02,
	LSTP_I2C_CMD_READ_RECVLEN_DEPRECATED = 0x03, /* Do not use */
	LSTP_I2C_CMD_WRITE_READ = 0x04,
	LSTP_I2C_CMD_SMBUS_BLOCK_READ = 0x05
} __packed;

enum lstp_i2c_cmd_flags { LSTP_I2C_CMD_FLAG_NO_STOP = 0x40 };

enum lstp_i2c_smbus_block_read_flags {
	LSTP_I2C_SMBUS_BLOCK_READ_FLAG_PEC = BIT(0),
} __packed;

struct lstp_i2c_read_req {
	u8 addr;
	__le16 rd_len;
} __packed;

struct lstp_i2c_write_req {
	u8 addr;
	u8 wr_data[];
} __packed;

struct lstp_i2c_rd_recvlen_deprecated_req {
	u8 addr;
} __packed;

struct lstp_i2c_wr_rd_req {
	u8 addr;
	__le16 rd_len;
	u8 wr_data[]; /* Write length inferred from length in header */
} __packed;

struct lstp_i2c_smbus_block_read_req {
	u8 addr;
	__le16 flags; /* lstp_i2c_smbus_block_read_flags */
	u8 wr_data[]; /* Write length inferred from length in header */
} __packed;

/*
 * Largest write phase the block-read opcode carries: an SMBus command byte and a block count
 * ahead of a maximum-size block.
 */
#define LSTP_I2C_SMBUS_BLOCK_READ_WR_MAX (2 + I2C_SMBUS_BLOCK_MAX)

enum lstp_i2c_speed {
	LSTP_I2C_SPEED_100KHZ = 0x00,
	LSTP_I2C_SPEED_400KHZ = 0x01,
	LSTP_I2C_SPEED_1000KHZ = 0x02,
	LSTP_I2C_SPEED_3400KHZ = 0x03,
};

struct lstp_i2c_config {
	u8 speed;
	__le16 output_drive_strength; /* in mA */
	__le16 slew_rate; /* in 100 ps (0.1 ns) increments */
	__le16 input_debounce_time; /* in us */
	__le16 glitch_filter_width; /* in ns */
	u8 bus_low_timeout; /* in ms */
	u8 bus_arbitration_retries;
} __packed;

#define LSTP_I2C_LEGACY_CONFIG_LEN offsetofend(struct lstp_i2c_config, speed)

struct lstp_i2c_priv {
	struct i2c_adapter *adap;
	bool use_smbus_block_read; /* False once MCU has rejected LSTP_I2C_CMD_SMBUS_BLOCK_READ */
};

static bool lstp_i2c_can_retry(int lstp_status)
{
	return lstp_status == LSTP_BUSY || lstp_status == LSTP_ARB_LOST;
}

static bool lstp_i2c_suppress_error_logs(int lstp_status)
{
	return lstp_status == LSTP_NACK || lstp_i2c_can_retry(lstp_status);
}

/**
 * lstp_i2c_bus_recovery() - Perform I2C bus recovery procedure.
 * @adap: I2C adapter to recover
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_i2c_bus_recovery(struct i2c_adapter *adap)
{
	struct lstp_channel *ch = adap->algo_data;
	int lstp_status = LSTP_NO_RESPONSE_STATUS;
	int ret;

	ret = lstp_request(ch, LSTP_I2C_CMD_BUS_RECOVERY, NULL, 0, NULL, 0, NULL, &lstp_status);
	if (ret && !lstp_i2c_suppress_error_logs(lstp_status))
		dev_err(&adap->dev, "%s: ch_%d: Bus recovery failed (%pe)\n", __func__, ch->ch_id,
			ERR_PTR(ret));
	if (ret && lstp_i2c_can_retry(lstp_status))
		return -EAGAIN;
	return ret;
}

/**
 * lstp_i2c_validate_msg() - Validate an I2C message before transmission.
 * @msg: I2C message to validate
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_i2c_validate_msg(struct i2c_msg *msg)
{
	if (!msg->buf && msg->len > 0)
		return -EINVAL;

	if (msg->flags & I2C_M_TEN)
		return -EAFNOSUPPORT; /* 10-bit address not supported */

	if (msg->addr > 0x7F)
		return -EINVAL; /* Only 7-bit address supported */

	if ((msg->flags & I2C_M_RECV_LEN) && (!(msg->flags & I2C_M_RD) || msg->len < 1))
		return -EINVAL;

	return 0;
}

/**
 * lstp_i2c_read() - Perform an I2C read transaction.
 * @adap:    I2C adapter to use
 * @msg:     I2C message describing the read
 * @no_stop: If true, omit STOP for repeated START
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_i2c_read(struct i2c_adapter *adap, struct i2c_msg *msg, bool no_stop)
{
	u8 cmd = LSTP_I2C_CMD_READ;
	struct lstp_channel *ch = adap->algo_data;
	struct lstp_i2c_read_req req = {
		.addr = msg->addr,
		.rd_len = cpu_to_le16(msg->len),
	};
	int lstp_status = LSTP_NO_RESPONSE_STATUS;
	int ret;

	ret = lstp_i2c_validate_msg(msg);
	if (ret) {
		dev_err(&adap->dev, "%s: ch_%d: Invalid message to addr=0x%02x (%pe)\n", __func__,
			ch->ch_id, msg->addr, ERR_PTR(ret));
		return ret;
	}

	if (msg->len > ch->max_rx_payload) {
		dev_err(&adap->dev,
			"%s: ch_%d: Read request message to addr=0x%02x too long (%u bytes, max %zu)\n",
			__func__, ch->ch_id, msg->addr, msg->len, ch->max_rx_payload);
		return -EINVAL;
	}

	dev_dbg(&adap->dev, "%s: ch_%d: addr=0x%02x, len=%d\n", __func__, ch->ch_id, msg->addr,
		msg->len);

	if (no_stop)
		cmd |= LSTP_I2C_CMD_FLAG_NO_STOP;

	ret = lstp_request(ch, cmd, &req, sizeof(req), msg->buf, msg->len, NULL, &lstp_status);
	if (ret && !lstp_i2c_suppress_error_logs(lstp_status))
		dev_err_ratelimited(&adap->dev, "%s: ch_%d: READ to addr=0x%02x failed (%pe)\n",
				    __func__, ch->ch_id, msg->addr, ERR_PTR(ret));
	if (ret && lstp_i2c_can_retry(lstp_status))
		return -EAGAIN;
	return ret;
}

/**
 * lstp_i2c_write() - Perform an I2C write transaction.
 * @adap:    I2C adapter to use
 * @msg:     I2C message describing the write
 * @no_stop: If true, omit STOP for repeated START
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_i2c_write(struct i2c_adapter *adap, struct i2c_msg *msg, bool no_stop)
{
	u8 cmd = LSTP_I2C_CMD_WRITE;
	struct lstp_channel *ch = adap->algo_data;
	struct lstp_i2c_write_req req_head = { .addr = msg->addr };
	struct kvec vecs[2] = {
		{ .iov_base = &req_head, .iov_len = sizeof(req_head) },
		{ .iov_base = msg->buf, .iov_len = msg->len },
	};
	int lstp_status = LSTP_NO_RESPONSE_STATUS;
	int ret;

	ret = lstp_i2c_validate_msg(msg);
	if (ret) {
		dev_err(&adap->dev, "%s: ch_%d: Invalid message to addr=0x%02x (%pe)\n", __func__,
			ch->ch_id, msg->addr, ERR_PTR(ret));
		return ret;
	}

	if (sizeof(req_head) + msg->len > ch->max_tx_payload) {
		dev_err(&adap->dev,
			"%s: ch_%d: Write message to addr=0x%02x too long (%u bytes, max %zu)\n",
			__func__, ch->ch_id, msg->addr, msg->len,
			ch->max_tx_payload - sizeof(req_head));
		return -EINVAL;
	}

	if (msg->len > 0)
		dev_dbg(&adap->dev, "%s: ch_%d: addr=0x%02x, len=%d, data=0x%*ph\n", __func__,
			ch->ch_id, msg->addr, msg->len, msg->len, msg->buf);
	else
		dev_dbg(&adap->dev, "%s: ch_%d: addr=0x%02x, len=%d\n", __func__, ch->ch_id,
			msg->addr, msg->len);

	if (no_stop)
		cmd |= LSTP_I2C_CMD_FLAG_NO_STOP;

	ret = lstp_requestv(ch, cmd, vecs, ARRAY_SIZE(vecs), NULL, 0, NULL, &lstp_status);
	if (ret && !lstp_i2c_suppress_error_logs(lstp_status))
		dev_err_ratelimited(&adap->dev, "%s: ch_%d: WRITE to addr=0x%02x failed (%pe)\n",
				    __func__, ch->ch_id, msg->addr, ERR_PTR(ret));
	if (ret && lstp_i2c_can_retry(lstp_status))
		return -EAGAIN;
	return ret;
}

/**
 * lstp_i2c_read_recvlen_deprecated() - Deprecated SMBus block read (slave indicates length). Does
 * not support PEC.
 * @adap:    I2C adapter to use
 * @msg:     I2C message; msg->len updated to actual bytes received
 * @no_stop: If true, omit STOP for repeated START
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_i2c_read_recvlen_deprecated(struct i2c_adapter *adap, struct i2c_msg *msg,
					    bool no_stop)
{
	u8 cmd = LSTP_I2C_CMD_READ_RECVLEN_DEPRECATED;
	struct lstp_channel *ch = adap->algo_data;
	struct lstp_i2c_rd_recvlen_deprecated_req req = { .addr = msg->addr };
	size_t pkt_len = 0;
	/* I2C_M_RECV_LEN: msg->len is framing (count [+ PEC]); caller guarantees +BLOCK_MAX room.
	 */
	size_t rx_buf_len = (size_t)msg->len + I2C_SMBUS_BLOCK_MAX;
	u16 rx_len;
	u8 block_len;
	int lstp_status = LSTP_NO_RESPONSE_STATUS;
	int ret;

	ret = lstp_i2c_validate_msg(msg);
	if (ret) {
		dev_err(&adap->dev, "%s: ch_%d: Invalid message to addr=0x%02x (%pe)\n", __func__,
			ch->ch_id, msg->addr, ERR_PTR(ret));
		return ret;
	}

	if (rx_buf_len > ch->max_rx_payload) {
		dev_err(&adap->dev,
			"%s: ch_%d: Read recvlen message to addr=0x%02x too long (%zu bytes, max %zu)\n",
			__func__, ch->ch_id, msg->addr, rx_buf_len, ch->max_rx_payload);
		return -EINVAL;
	}

	if (no_stop)
		cmd |= LSTP_I2C_CMD_FLAG_NO_STOP;

	ret = lstp_request(ch, cmd, &req, sizeof(req), msg->buf, rx_buf_len, &pkt_len,
			   &lstp_status);
	if (ret) {
		if (!lstp_i2c_suppress_error_logs(lstp_status))
			dev_err_ratelimited(&adap->dev,
					    "%s: ch_%d: READ_RECVLEN to addr=0x%02x failed (%pe)\n",
					    __func__, ch->ch_id, msg->addr, ERR_PTR(ret));
		if (lstp_i2c_can_retry(lstp_status))
			return -EAGAIN;
		return ret;
	}

	if (pkt_len == 0) {
		dev_err(&adap->dev, "%s: ch_%d: Empty response packet\n", __func__, ch->ch_id);
		return -EIO;
	}

	block_len = msg->buf[0];
	if (block_len > I2C_SMBUS_BLOCK_MAX) {
		dev_err(&adap->dev, "%s: ch_%d: Invalid block length %u\n", __func__, ch->ch_id,
			block_len);
		return -EPROTO;
	}

	rx_len = block_len + 1;
	if (pkt_len < rx_len) {
		dev_err(&adap->dev, "%s: ch_%d: Invalid response length (%zu)\n", __func__,
			ch->ch_id, pkt_len);
		return -EIO;
	}

	msg->len = rx_len;
	return 0;
}

/**
 * lstp_i2c_write_read() - Atomic write-then-read with repeated START.
 * @adap:   I2C adapter to use
 * @wr_msg: I2C message describing the write phase (addr, buf, len)
 * @rd_msg: I2C message describing the read phase (addr, buf, len)
 * @no_stop: If true, omit STOP so another message can follow
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_i2c_write_read(struct i2c_adapter *adap, struct i2c_msg *wr_msg,
			       struct i2c_msg *rd_msg, bool no_stop)
{
	u8 cmd = LSTP_I2C_CMD_WRITE_READ;
	struct lstp_channel *ch = adap->algo_data;
	struct lstp_i2c_wr_rd_req req_head = {
		.addr = wr_msg->addr,
		.rd_len = cpu_to_le16(rd_msg->len),
	};
	struct kvec vecs[2] = {
		{ .iov_base = &req_head, .iov_len = sizeof(req_head) },
		{ .iov_base = wr_msg->buf, .iov_len = wr_msg->len },
	};
	int lstp_status = LSTP_NO_RESPONSE_STATUS;
	int ret;

	ret = lstp_i2c_validate_msg(wr_msg);
	if (ret) {
		dev_err(&adap->dev, "%s: ch_%d: Invalid write message to addr=0x%02x (%pe)\n",
			__func__, ch->ch_id, wr_msg->addr, ERR_PTR(ret));
		return ret;
	}

	if (sizeof(req_head) + wr_msg->len > ch->max_tx_payload) {
		dev_err(&adap->dev,
			"%s: ch_%d: Write message to addr=0x%02x too long (%u bytes, max %zu)\n",
			__func__, ch->ch_id, wr_msg->addr, wr_msg->len,
			ch->max_tx_payload - sizeof(req_head));
		return -EINVAL;
	}

	ret = lstp_i2c_validate_msg(rd_msg);
	if (ret) {
		dev_err(&adap->dev, "%s: ch_%d: Invalid read message to addr=0x%02x (%pe)\n",
			__func__, ch->ch_id, rd_msg->addr, ERR_PTR(ret));
		return ret;
	}

	if (rd_msg->len > ch->max_rx_payload) {
		dev_err(&adap->dev,
			"%s: ch_%d: Read message to addr=0x%02x too long (%u bytes, max %zu)\n",
			__func__, ch->ch_id, rd_msg->addr, rd_msg->len, ch->max_rx_payload);
		return -EINVAL;
	}

	if (wr_msg->addr != rd_msg->addr) {
		dev_err(&adap->dev, "%s: ch_%d: Write/read addr mismatch (wr=0x%02x, rd=0x%02x)\n",
			__func__, ch->ch_id, wr_msg->addr, rd_msg->addr);
		return -EINVAL;
	}

	if (no_stop)
		cmd |= LSTP_I2C_CMD_FLAG_NO_STOP;

	ret = lstp_requestv(ch, cmd, vecs, ARRAY_SIZE(vecs), rd_msg->buf, rd_msg->len, NULL,
			    &lstp_status);
	if (ret && !lstp_i2c_suppress_error_logs(lstp_status))
		dev_err_ratelimited(&adap->dev,
				    "%s: ch_%d: WRITE_READ to addr=0x%02x failed (%pe)\n", __func__,
				    ch->ch_id, wr_msg->addr, ERR_PTR(ret));
	if (ret && lstp_i2c_can_retry(lstp_status))
		return -EAGAIN;
	return ret;
}

/**
 * lstp_i2c_smbus_block_read() - SMBus block read with optional write phase (slave indicates
 * length).
 * @adap:    I2C adapter to use
 * @wr_msg:  Optional write phase (addr, buf, len). If non-NULL, must target the same slave as
 * rd_msg.
 * @rd_msg:  I2C message describing the read phase; rd_msg->len updated to actual bytes received
 * @no_stop: If true, omit STOP for repeated START
 * @lstp_status_out: Optional out-param for the raw LSTP response status; see lstp_request()
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_i2c_smbus_block_read(struct i2c_adapter *adap, struct i2c_msg *wr_msg,
				     struct i2c_msg *rd_msg, bool no_stop, int *lstp_status_out)
{
	u8 cmd = LSTP_I2C_CMD_SMBUS_BLOCK_READ;
	struct lstp_channel *ch = adap->algo_data;
	DEFINE_RAW_FLEX(struct lstp_i2c_smbus_block_read_req, req, wr_data,
			LSTP_I2C_SMBUS_BLOCK_READ_WR_MAX);
	size_t pkt_len = 0;
	u16 rx_len;
	u16 wr_len = wr_msg ? wr_msg->len : 0;
	u8 *wr_buf = wr_msg ? wr_msg->buf : NULL;
	u8 block_len;
	bool pec = rd_msg->flags & I2C_CLIENT_PEC;
	/* I2C_M_RECV_LEN: rd_msg->len is framing (count [+ PEC]); caller guarantees +BLOCK_MAX
	 * room.
	 */
	size_t rx_buf_len = (size_t)rd_msg->len + I2C_SMBUS_BLOCK_MAX;
	int lstp_status = LSTP_NO_RESPONSE_STATUS;
	int ret;

	if (lstp_status_out)
		*lstp_status_out = LSTP_NO_RESPONSE_STATUS;

	ret = lstp_i2c_validate_msg(rd_msg);
	if (ret) {
		dev_err(&adap->dev, "%s: ch_%d: Invalid read message to addr=0x%02x (%pe)\n",
			__func__, ch->ch_id, rd_msg->addr, ERR_PTR(ret));
		return ret;
	}

	/* A PEC read frames a trailing byte on top of the count byte, so it needs room for both. */
	if (pec && rd_msg->len < 2) {
		dev_err(&adap->dev,
			"%s: ch_%d: PEC read from addr=0x%02x leaves no room for the PEC byte\n",
			__func__, ch->ch_id, rd_msg->addr);
		return -EINVAL;
	}

	if (wr_msg) {
		ret = lstp_i2c_validate_msg(wr_msg);
		if (ret) {
			dev_err(&adap->dev,
				"%s: ch_%d: Invalid write message to addr=0x%02x (%pe)\n", __func__,
				ch->ch_id, wr_msg->addr, ERR_PTR(ret));
			return ret;
		}

		if (wr_msg->addr != rd_msg->addr) {
			dev_err(&adap->dev,
				"%s: ch_%d: Write/read addr mismatch (wr=0x%02x, rd=0x%02x)\n",
				__func__, ch->ch_id, wr_msg->addr, rd_msg->addr);
			return -EINVAL;
		}
	}

	if (wr_len > LSTP_I2C_SMBUS_BLOCK_READ_WR_MAX) {
		dev_err(&adap->dev,
			"%s: ch_%d: SMBus write phase to addr=0x%02x too long (%u bytes, max %u)\n",
			__func__, ch->ch_id, rd_msg->addr, wr_len,
			LSTP_I2C_SMBUS_BLOCK_READ_WR_MAX);
		return -EINVAL;
	}

	if (rx_buf_len > ch->max_rx_payload) {
		dev_err(&adap->dev,
			"%s: ch_%d: Read message to addr=0x%02x too long (%zu bytes, max %zu)\n",
			__func__, ch->ch_id, rd_msg->addr, rx_buf_len, ch->max_rx_payload);
		return -EINVAL;
	}

	if (struct_size(req, wr_data, wr_len) > ch->max_tx_payload) {
		dev_err(&adap->dev,
			"%s: ch_%d: SMBus write phase to addr=0x%02x too long (%zu bytes, max %zu)\n",
			__func__, ch->ch_id, rd_msg->addr, struct_size(req, wr_data, wr_len),
			ch->max_tx_payload);
		return -EMSGSIZE;
	}

	*req = (struct lstp_i2c_smbus_block_read_req){
		.addr = rd_msg->addr,
		.flags = cpu_to_le16(pec ? LSTP_I2C_SMBUS_BLOCK_READ_FLAG_PEC : 0),
	};
	if (wr_len)
		memcpy(req->wr_data, wr_buf, wr_len);

	if (no_stop)
		cmd |= LSTP_I2C_CMD_FLAG_NO_STOP;

	ret = lstp_request(ch, cmd, req, struct_size(req, wr_data, wr_len), rd_msg->buf, rx_buf_len,
			   &pkt_len, &lstp_status);
	if (lstp_status_out)
		*lstp_status_out = lstp_status;
	if (ret) {
		if (lstp_status != LSTP_NOT_SUPP && !lstp_i2c_suppress_error_logs(lstp_status))
			dev_err_ratelimited(&adap->dev,
					    "%s: ch_%d: SMBUS_BLOCK_READ to addr=0x%02x failed (%pe)\n",
					    __func__, ch->ch_id, rd_msg->addr, ERR_PTR(ret));
		if (lstp_i2c_can_retry(lstp_status))
			return -EAGAIN;
		return ret;
	}

	if (pkt_len == 0) {
		dev_err(&adap->dev, "%s: ch_%d: Empty response packet\n", __func__, ch->ch_id);
		return -EIO;
	}

	block_len = rd_msg->buf[0];
	if (block_len > I2C_SMBUS_BLOCK_MAX) {
		dev_err(&adap->dev, "%s: ch_%d: Invalid block length %u\n", __func__, ch->ch_id,
			block_len);
		return -EPROTO;
	}

	rx_len = block_len + (pec ? 2 : 1);
	if (pkt_len < rx_len) {
		dev_err(&adap->dev, "%s: ch_%d: Invalid response length (%zu)\n", __func__,
			ch->ch_id, pkt_len);
		return -EIO;
	}

	rd_msg->len = rx_len;
	return 0;
}

/**
 * lstp_i2c_smbus_block_read_wrapper() - SMBus block read with legacy fallback.
 * @adap:    I2C adapter to use
 * @wr_msg:  Optional write phase. If non-NULL, must target the same slave as @rd_msg
 * @rd_msg:  Read phase message; rd_msg->len is updated to actual bytes received
 * @no_stop: If true, omit STOP for repeated START on the read phase
 *
 * Tries the atomic SMBUS_BLOCK_READ opcode first. If the device
 * rejects it (or has done so previously this session), falls back to a
 * lstp_i2c_write() + lstp_i2c_read_recvlen_deprecated() transaction.
 * PEC clients are rejected on the fallback path because the deprecated path cannot transport the
 * trailing PEC byte.
 *
 * TODO: remove the fallback path (and lstp_i2c_read_recvlen_deprecated()) once
 * all deployed devices support SMBUS_BLOCK_READ.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_i2c_smbus_block_read_wrapper(struct i2c_adapter *adap, struct i2c_msg *wr_msg,
					     struct i2c_msg *rd_msg, bool no_stop)
{
	struct lstp_channel *ch = adap->algo_data;
	struct lstp_i2c_priv *priv = ch->priv;
	u16 wr_len = wr_msg ? wr_msg->len : 0;
	int lstp_status = LSTP_NO_RESPONSE_STATUS;
	int ret;

	if (READ_ONCE(priv->use_smbus_block_read)) {
		ret = lstp_i2c_smbus_block_read(adap, wr_msg, rd_msg, no_stop, &lstp_status);
		if (lstp_status != LSTP_NOT_SUPP)
			return ret;

		/*
		 * MCU rejected the new opcode; cache the result so subsequent
		 * calls skip straight to the legacy chain.
		 */
		dev_warn_once(&adap->dev,
			      "%s: ch_%d: Using deprecated recvlen path! -- Update LSTP Device\n",
			      __func__, ch->ch_id);
		WRITE_ONCE(priv->use_smbus_block_read, false);
	}

	/* Deprecated fallback path */
	if (rd_msg->flags & I2C_CLIENT_PEC) {
		dev_err(&adap->dev,
			"%s: ch_%d: PEC client at addr=0x%02x not supported by deprecated recv-len opcode; update MCU firmware to support LSTP_I2C_CMD_SMBUS_BLOCK_READ\n",
			__func__, ch->ch_id, rd_msg->addr);
		return -EOPNOTSUPP;
	}

	if (wr_msg && wr_len > 0) {
		ret = lstp_i2c_write(adap, wr_msg, true /* no_stop */);
		if (ret)
			return ret;
	}
	return lstp_i2c_read_recvlen_deprecated(adap, rd_msg, no_stop);
}

/*
 * A write immediately followed by a read to the same target is one combined transaction: the write
 * carries the command and the read collects the answer after a repeated START.
 */
static bool lstp_i2c_is_combined_pair(const struct i2c_msg *wr_msg, const struct i2c_msg *rd_msg)
{
	return !(wr_msg->flags & I2C_M_RD) && (rd_msg->flags & I2C_M_RD) &&
	       wr_msg->addr == rd_msg->addr;
}

/**
 * lstp_i2c_xfer() - Main I2C transfer function for the adapter.
 * @adap: I2C adapter to use
 * @msgs: Array of I2C messages to transfer
 * @num:  Number of messages in the array
 *
 * Implements the i2c_algorithm.xfer callback. Processes an array of I2C
 * messages, handling read, write, and combined transactions.
 *
 * Return: Number of messages transferred on success, negative errno on failure.
 */
static int lstp_i2c_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs, int num)
{
	int ret = 0;
	int i;
	struct lstp_channel *ch = adap->algo_data;

	if (!msgs || num <= 0)
		return -EINVAL;

	dev_dbg(&adap->dev, "%s: ch_%d: I2C transfer with %d message(s)\n", __func__, ch->ch_id,
		num);

	for (i = 0; i < num; i++) {
		bool no_stop;

		if (i + 1 < num && lstp_i2c_is_combined_pair(&msgs[i], &msgs[i + 1])) {
			struct i2c_msg *wr_msg = &msgs[i++];
			struct i2c_msg *rd_msg = &msgs[i];

			no_stop = i != num - 1;
			if (rd_msg->flags & I2C_M_RECV_LEN)
				ret = lstp_i2c_smbus_block_read_wrapper(adap, wr_msg, rd_msg,
									no_stop);
			else
				ret = lstp_i2c_write_read(adap, wr_msg, rd_msg, no_stop);
		} else {
			no_stop = i != num - 1;

			if (msgs[i].flags & I2C_M_RD) {
				if (msgs[i].flags & I2C_M_RECV_LEN)
					ret = lstp_i2c_smbus_block_read_wrapper(adap, NULL,
										&msgs[i], no_stop);
				else
					ret = lstp_i2c_read(adap, &msgs[i], no_stop);
			} else {
				ret = lstp_i2c_write(adap, &msgs[i], no_stop);
			}
		}

		if (ret)
			return ret;
	}

	return num;
}

/**
 * lstp_i2c_functionality() - Report I2C adapter capabilities.
 * @adap: I2C adapter to query
 *
 * Return: Bitmask of supported I2C_FUNC_* flags.
 */
static u32 lstp_i2c_functionality(struct i2c_adapter *adap)
{
	/* TODO: This needs to be discoverable, also need separate commands for 10-bit address */
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL_ALL;
}

static struct i2c_bus_recovery_info lstp_i2c_recovery_info = {
	.recover_bus = lstp_i2c_bus_recovery,
};

static const struct i2c_algorithm lstp_i2c_algorithm = {
	.xfer = lstp_i2c_xfer,
	.functionality = lstp_i2c_functionality,
};

#define LSTP_I2C_DEFAULT_RETRIES 3

/**
 * lstp_i2c_configure_retry_policy() - Set adapter retry count and timeout.
 * @adap:       I2C adapter to configure (firmware node must already be set)
 * @cfg:        Channel config blob from firmware
 * @config_len: Length of @cfg in bytes
 *
 * Sets adap->retries / adap->timeout for I2C-core -EAGAIN reissues, which
 * cover both LSTP_BUSY and LSTP_ARB_LOST. A non-zero bus_arbitration_retries
 * means the device performs its own bus retries, so the host adds none;
 * otherwise use DT "retries", else LSTP_I2C_DEFAULT_RETRIES. Timeout is
 * (retries + 1) USB response windows.
 */
static void lstp_i2c_configure_retry_policy(struct i2c_adapter *adap,
					    const struct lstp_i2c_config *cfg, size_t config_len)
{
	u32 retries = LSTP_I2C_DEFAULT_RETRIES;
	u32 configured_retries;

	if (config_len >= offsetofend(struct lstp_i2c_config, bus_arbitration_retries) &&
	    cfg->bus_arbitration_retries) {
		if (!device_property_read_u32(&adap->dev, "retries", &configured_retries) &&
		    configured_retries)
			dev_warn(&adap->dev,
				 "Ignoring DT retries=%u; device already retries the bus %u time(s)\n",
				 configured_retries, cfg->bus_arbitration_retries);
		retries = 0;
	} else if (!device_property_read_u32(&adap->dev, "retries", &configured_retries)) {
		if (configured_retries <= U8_MAX)
			retries = configured_retries;
		else
			dev_warn(&adap->dev, "Ignoring retries value %u; maximum is %u\n",
				 configured_retries, U8_MAX);
	}

	adap->retries = retries;
	adap->timeout = msecs_to_jiffies((retries + 1) * LSTP_USB_RESPONSE_TIMEOUT_MS);
}

/**
 * lstp_i2c_init() - Initialize I2C adapter for an LSTP channel.
 * @ch:   LSTP channel configured as I2C type
 * @info: Channel config blob (struct lstp_i2c_config; legacy speed-only OK)
 *
 * Allocates adapter and parses config. Adapter stored in
 * ch->priv but not registered; call lstp_i2c_start() after RX URB setup.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_i2c_init(struct lstp_channel *ch, const struct lstp_channel_init_info *info)
{
	struct i2c_adapter *adap;
	struct lstp_i2c_priv *priv;
	const struct lstp_i2c_config *cfg = info->config;

	if (info->config_len < LSTP_I2C_LEGACY_CONFIG_LEN) {
		dev_err(ch->dev, "%s: ch_%d: I2C config too short: %zu < %zu\n", __func__,
			ch->ch_id, info->config_len, LSTP_I2C_LEGACY_CONFIG_LEN);
		return -EINVAL;
	}

	/* Allocate memory */
	priv = devm_kzalloc(ch->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	adap = devm_kzalloc(ch->dev, sizeof(*adap), GFP_KERNEL);
	if (!adap)
		return -ENOMEM;

	/* Initialize I2C adapter */
	adap->owner = THIS_MODULE;
	adap->class = I2C_CLASS_HWMON;
	adap->algo = &lstp_i2c_algorithm;
	adap->algo_data = ch;
	adap->dev.parent = ch->dev;
	adap->bus_recovery_info = &lstp_i2c_recovery_info;
	device_set_node(&adap->dev, ch->fwnode);
	lstp_i2c_configure_retry_policy(adap, cfg, info->config_len);
	strscpy(adap->name, ch->display_name, sizeof(adap->name));
	/* TODO: save i2c speed from config */

	priv->adap = adap;
	priv->use_smbus_block_read = true;
	ch->priv = priv;

	dev_dbg(ch->dev, "%s: ch_%d: Initialized as %s\n", __func__, ch->ch_id, adap->name);
	return 0;
}

/**
 * lstp_i2c_start() - Register I2C adapter with Linux I2C core.
 * @ch: LSTP channel with initialized adapter (from lstp_i2c_init)
 *
 * When the adapter's firmware node is set (from lstp_i2c_init), the
 * I2C core resolves bus numbers via aliases and auto-enumerates child
 * devices from firmware (DT or ACPI) child nodes.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_i2c_start(struct lstp_channel *ch)
{
	int ret;
	struct lstp_i2c_priv *priv = ch->priv;
	struct i2c_adapter *adap = priv ? priv->adap : NULL;

	if (!adap) {
		dev_err(ch->dev, "%s: ch_%d: I2C adapter not initialized\n", __func__, ch->ch_id);
		return -EINVAL;
	}

	ret = devm_i2c_add_adapter(ch->dev, adap);
	if (ret) {
		dev_err(ch->dev, "%s: ch_%d: Could not register I2C adapter (%pe)\n", __func__,
			ch->ch_id, ERR_PTR(ret));
		return ret;
	}

	deprecated_lstp_channel_publish_child_dev(ch, &adap->dev);

	dev_info(ch->dev, "%s: ch_%d: Started as %s\n", __func__, ch->ch_id, adap->name);
	return 0;
}

/* clang-format off */
LSTP_SUBSYS(i2c, LSTP_CHANNEL_TYPE_I2C, lstp_i2c_init, lstp_i2c_start,
	    .fwnode_compatible = "nvidia,lstp-i2c",
);
/* clang-format on */
