// SPDX-License-Identifier: GPL-2.0-only
/*
 * GPIO driver for LSTP USB interface.
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

#include <linux/bitmap.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/gpio/consumer.h>
#include <linux/gpio/driver.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/leds.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/workqueue.h>
#include <uapi/linux/gpio.h>

#include "lstp-main.h"

#define LSTP_GPIO_PIN_NAME_LEN 32
#define LSTP_LED_REPEAT_FOREVER 0 /* wire: repeats == 0 plays forever */
#define LSTP_LED_LINUX_REPEAT_FOREVER (-1) /* LED-class pattern_set: repeat == -1 plays forever */
#define LSTP_LED_DEFAULT_HOLD_TIME_MS 1 /* delta_t for single-step holds */
#define LSTP_LED_DEFAULT_BLINK_MS 500 /* LED-class default when delay_on/off are both 0 */

enum lstp_gpio_cmd {
	LSTP_GPIO_CMD_GET_VALUE = 0x00,
	LSTP_GPIO_CMD_SET_VALUE = 0x01,
	LSTP_GPIO_CMD_GET_IRQ_CONFIG = 0x02,
	LSTP_GPIO_CMD_SET_IRQ_CONFIG = 0x03,
	LSTP_GPIO_CMD_IRQ_EVENT = 0x04,
	LSTP_GPIO_CMD_SET_LED_PATTERN = 0x05,
} __packed;

struct lstp_led_pattern {
	u8 brightness;
	__le32 time_ms;
} __packed;

struct lstp_gpio_get_value_req {
	__le16 pin;
} __packed;

struct lstp_gpio_set_value_req {
	__le16 pin;
	u8 value;
} __packed;

struct lstp_gpio_get_irq_config_req {
	__le16 pin;
} __packed;

struct lstp_gpio_set_irq_config_req {
	__le16 pin;
	u8 irq_type;
} __packed;

struct lstp_gpio_irq_event_req {
	__le16 pin;
	u8 value;
} __packed;

struct lstp_gpio_set_led_pattern_req {
	__le16 pin;
	__le32 repeats;
	u8 num_steps;
	struct lstp_led_pattern pattern[];
} __packed;

struct lstp_gpio_get_value_resp {
	u8 value;
} __packed;

struct lstp_gpio_get_irq_config_resp {
	u8 irq_type;
} __packed;

enum lstp_gpio_irq_type {
	LSTP_GPIO_IRQ_NONE = 0x00,
	LSTP_GPIO_IRQ_RISING = 0x01,
	LSTP_GPIO_IRQ_FALLING = 0x02,
	LSTP_GPIO_IRQ_BOTH = 0x03,
	LSTP_GPIO_IRQ_HIGH = 0x04,
	LSTP_GPIO_IRQ_LOW = 0x05,
	LSTP_GPIO_IRQ_MAX = LSTP_GPIO_IRQ_LOW,
} __packed;

struct lstp_gpio_pin_config {
	u8 direction;
	u8 default_output;
	u8 output_drive_config;
	u8 output_persist_state; /* bool */
	u8 bias_pull_config;
	__le16 bias_pull_strength; /* 16 ohm increments */
	__le16 output_drive_strength; /* in mA */
	__le16 slew_rate; /* in 100 ps (0.1 ns) increments */
	__le16 input_debounce_time; /* in us */
	u8 led_support;
	u8 reserved_0xE;
	u8 reserved_0xF;
} __packed;

struct lstp_gpio_pin {
	char pin_name[LSTP_GPIO_PIN_NAME_LEN];
	struct lstp_gpio_pin_config config;
} __packed;

struct lstp_gpio_config {
	u8 npins;
	struct lstp_gpio_pin pin_info[];
} __packed;

/* clang-format off */
enum lstp_gpio_direction {
	LSTP_GPIO_OUTPUT = 0x00,
	LSTP_GPIO_INPUT = 0x01
} __packed;
enum lstp_gpio_pin_state {
	LSTP_GPIO_LOW = 0x00,
	LSTP_GPIO_HIGH = 0x01
} __packed;
enum lstp_gpio_drive_config {
	LSTP_GPIO_PUSH_PULL = 0x00,
	LSTP_GPIO_OPEN_DRAIN = 0x01,
	LSTP_GPIO_OPEN_SOURCE = 0x02
} __packed;
enum lstp_gpio_bias_config {
	LSTP_GPIO_NO_PULL = 0x00,
	LSTP_GPIO_PULL_UP = 0x01,
	LSTP_GPIO_PULL_DOWN = 0x02
} __packed;
enum lstp_gpio_led_support {
	LSTP_GPIO_NOT_LED = 0x00,
	LSTP_GPIO_LED_MODE_HOLD = 0x01, /* pattern brightness jumps between steps */
	LSTP_GPIO_LED_MODE_INTERPOLATE = 0x02, /* pattern brightness interpolates between steps */
} __packed; /* clang-format on */

/* Private data for GPIO channel */
struct lstp_gpio_priv {
	struct lstp_channel *ch;
	struct gpio_chip gc;
	struct workqueue_struct *wq; /* Ordered workqueue for IRQ event handling, FIFO */
	struct mutex irq_lock; /* Serializes irq_chip callbacks (irq_bus_lock/sync_unlock) */
	u8 *shadow_irq_type; /* Pending IRQ type per pin [npins] */
	u8 *hw_irq_type; /* Last successfully committed IRQ type per pin [npins] */
	const char **pin_names; /* Line names [npins] */
	struct lstp_gpio_led **leds; /* [npins], NULL if not an LED pin */
	u16 npins; /* Pin count from device config */
	u16 ngpio; /* Non-LED GPIO pin count */
	u16 nleds; /* LED class device count */
};

/* One work item per unsolicited RX batch; raw payload parsed in process context */
struct lstp_gpio_irq_event_work {
	struct work_struct work;
	struct lstp_gpio_priv *priv;
	u16 payload_len;
	u8 payload[];
};

/* Per-LED wrapper around led_classdev for a single LED pin */
struct lstp_gpio_led {
	struct led_classdev cdev;
	struct lstp_gpio_priv *priv; /* Back-pointer to owning GPIO channel */
	u16 pin;
};

/**
 * lstp_gpio_read_direction() - Read @pin's direction from device config.
 * @priv:      GPIO channel private data
 * @pin:       Pin index
 * @direction: Out: LSTP_GPIO_INPUT or LSTP_GPIO_OUTPUT
 *
 * Tries a partial read of the direction byte first; falls back to a whole-pin
 * read on firmware that rejects partial config reads.
 *
 * Return: 0 on success, -EINVAL if @pin invalid, or other negative errno.
 */
static int lstp_gpio_read_direction(struct lstp_gpio_priv *priv, unsigned int pin, u8 *direction)
{
	struct lstp_channel *ch = priv->ch;
	struct lstp_ch0_read_resp *resp __free(kfree) = NULL;
	u16 pin_offset = sizeof(struct lstp_gpio_config) + pin * sizeof(struct lstp_gpio_pin);
	u16 offset = pin_offset + offsetof(struct lstp_gpio_pin, config) +
		     offsetof(struct lstp_gpio_pin_config, direction);
	size_t actual;
	int lstp_status;
	int ret;

	if (pin >= priv->npins)
		return -EINVAL;

	ret = lstp_ch0_read_config(ch, offset, sizeof(*direction), &resp, &actual, &lstp_status);
	if (lstp_status == LSTP_ERROR || lstp_status == LSTP_NOT_SUPP) {
		/*
		 * TODO: Legacy support - remove this at some point
		 * Fallback for firmware that only supports whole pin reads.
		 */
		dev_warn_ratelimited(ch->dev, "%s: ch_%d: Partial pin config read rejected.\n",
				     __func__, ch->ch_id);
		ret = lstp_ch0_read_config(ch, pin_offset, sizeof(struct lstp_gpio_pin), &resp,
					   &actual, NULL);
		if (ret)
			return ret;
		*direction = ((const struct lstp_gpio_pin *)resp->ch_config)->config.direction;
		return 0;
	} else if (ret) {
		dev_err(ch->dev, "%s: ch_%d: Failed to read direction config for pin %u (%pe)\n",
			__func__, ch->ch_id, pin, ERR_PTR(ret));
		return ret;
	}

	*direction = *(const u8 *)resp->ch_config;
	return 0;
}

/**
 * lstp_gpio_get_value() - Read GPIO pin value. (blocking)
 * @gc:  GPIO chip
 * @pin: Pin index
 *
 * Return: 1 for logical high, 0 for logical low, negative errno on failure.
 */
static int lstp_gpio_get_value(struct gpio_chip *gc, unsigned int pin)
{
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);
	struct lstp_channel *ch = priv->ch;
	struct lstp_gpio_get_value_req req = { .pin = cpu_to_le16(pin) };
	struct lstp_gpio_get_value_resp resp;
	int ret;

	ret = lstp_request(ch, LSTP_GPIO_CMD_GET_VALUE, &req, sizeof(req), &resp, sizeof(resp),
			   NULL, NULL);
	if (ret) {
		dev_err(ch->dev, "%s: ch_%d: Could not get value for pin %u (%pe)\n", __func__,
			ch->ch_id, pin, ERR_PTR(ret));
		return ret;
	}

	dev_dbg(ch->dev, "%s: ch_%d: pin=%u, value=%d\n", __func__, ch->ch_id, pin, resp.value);
	return resp.value;
}

/**
 * lstp_gpio_set_value() - Set GPIO pin output value. (blocking)
 * @gc:    GPIO chip
 * @pin:   Pin index
 * @value: Logical output value (0 = low, non-zero = high)
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_gpio_set_value(struct gpio_chip *gc, unsigned int pin, int value)
{
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);
	struct lstp_channel *ch = priv->ch;
	struct lstp_gpio_set_value_req req = {
		.pin = cpu_to_le16(pin),
		.value = !!value,
	};
	int ret;

	ret = lstp_request(ch, LSTP_GPIO_CMD_SET_VALUE, &req, sizeof(req), NULL, 0, NULL, NULL);
	if (ret)
		dev_err(ch->dev, "%s: ch_%d: Could not set value %d for pin %u (%pe)\n", __func__,
			ch->ch_id, value, pin, ERR_PTR(ret));
	else
		dev_dbg(ch->dev, "%s: ch_%d: pin=%u, value=%d\n", __func__, ch->ch_id, pin, value);
	return ret;
}

/**
 * lstp_gpio_get_multiple() - Read multiple GPIO pin values. (blocking)
 * @gc:   GPIO chip
 * @mask: Bitmask of pins to read
 * @bits: Pointer to store logical values (bitmask)
 *
 * Sends GET_VALUE payloads, chunked across multiple packets if the number of
 * pins exceeds what fits in one request. Fills @bits from responses. Each
 * chunk is one LSTP exchange that serializes on the per-channel TX mutex
 * via lstp_request(); the framework does not bracket the chunks under a
 * shared lock, so a concurrent reader or writer may observe state from
 * between two chunks. Matches the gpiolib per-pin fallback contract; the
 * gpiolib API is silent on cross-call atomicity.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_gpio_get_multiple(struct gpio_chip *gc, unsigned long *mask, unsigned long *bits)
{
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);
	struct lstp_channel *ch = priv->ch;
	struct lstp_gpio_get_value_req *req = NULL;
	struct lstp_gpio_get_value_resp *resp = NULL;
	int max_pins_per_tx = ch->max_tx_payload / sizeof(*req);
	int max_pins_per_rx = ch->max_rx_payload / sizeof(*resp);
	int max_pins_per_pkt = min(max_pins_per_tx, max_pins_per_rx);
	int total_pins = bitmap_weight(mask, gc->ngpio);
	unsigned int bit_off = 0;
	int pins_sent = 0;
	int pins_in_pkt;
	int ret;

	/* Probe enforces bulk_*_size >= LSTP_USB_EP_MIN_SIZE; anchor it here. */
	BUILD_BUG_ON(sizeof(struct lstp_header) + sizeof(*req) > LSTP_USB_EP_MIN_SIZE);
	BUILD_BUG_ON(sizeof(struct lstp_header) + sizeof(*resp) > LSTP_USB_EP_MIN_SIZE);

	if (total_pins == 0)
		return 0;

	if (max_pins_per_pkt < 1) {
		dev_err(ch->dev, "%s: ch_%d: Payload capacity too small for a single pin\n",
			__func__, ch->ch_id);
		return -EINVAL;
	}

	req = kmalloc_array(max_pins_per_pkt, sizeof(*req), GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_free;
	}
	resp = kmalloc_array(max_pins_per_pkt, sizeof(*resp), GFP_KERNEL);
	if (!resp) {
		ret = -ENOMEM;
		goto out_free;
	}

	bitmap_zero(bits, gc->ngpio);

	while (pins_sent < total_pins) {
		pins_in_pkt = min(max_pins_per_pkt, total_pins - pins_sent);

		for (int i = 0; i < pins_in_pkt; i++) {
			bit_off = find_next_bit(mask, gc->ngpio, bit_off);
			req[i].pin = cpu_to_le16(bit_off);
			bit_off++;
		}

		ret = lstp_request(ch, LSTP_GPIO_CMD_GET_VALUE, req, pins_in_pkt * sizeof(*req),
				   resp, pins_in_pkt * sizeof(*resp), NULL, NULL);
		if (ret) {
			dev_err(ch->dev, "%s: ch_%d: Could not get values for %d pins (%pe)\n",
				__func__, ch->ch_id, pins_in_pkt, ERR_PTR(ret));
			goto out_free;
		}

		for (int i = 0; i < pins_in_pkt; i++) {
			if (resp[i].value)
				__set_bit(le16_to_cpu(req[i].pin), bits);
		}
		pins_sent += pins_in_pkt;
	}

	dev_dbg(ch->dev, "%s: ch_%d: Get %d pins, mask=%*pb, bits=%*pb\n", __func__, ch->ch_id,
		total_pins, gc->ngpio, mask, gc->ngpio, bits);
	ret = 0;

out_free:
	kfree(resp);
	kfree(req);
	return ret;
}

/**
 * lstp_gpio_set_multiple() - Set multiple GPIO pin output values. (blocking)
 * @gc:   GPIO chip
 * @mask: Bitmask of pins to set
 * @bits: Bitmask of logical output values (0 = low, 1 = high)
 *
 * Sends SET_VALUE payloads (pin + logical value per pin), chunked across
 * multiple packets if the number of pins exceeds what fits in one request.
 * Each chunk is one LSTP exchange that serializes on the per-channel TX
 * mutex via lstp_request(); the framework does not bracket the chunks
 * under a shared lock, so a concurrent reader or writer may observe state
 * from between two chunks. Matches the gpiolib per-pin fallback contract;
 * the gpiolib API is silent on cross-call atomicity.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_gpio_set_multiple(struct gpio_chip *gc, unsigned long *mask, unsigned long *bits)
{
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);
	struct lstp_channel *ch = priv->ch;
	struct lstp_gpio_set_value_req *req = NULL;
	int max_pins_per_pkt = ch->max_tx_payload / sizeof(*req);
	int total_pins = bitmap_weight(mask, gc->ngpio);
	unsigned int bit_off = 0;
	int pins_sent = 0;
	int pins_in_pkt;
	int ret = 0;

	/* Probe enforces bulk_tx_size >= LSTP_USB_EP_MIN_SIZE; anchor it here. */
	BUILD_BUG_ON(sizeof(struct lstp_header) + sizeof(*req) > LSTP_USB_EP_MIN_SIZE);

	if (total_pins == 0)
		goto done;

	if (max_pins_per_pkt < 1) {
		dev_err(ch->dev, "%s: ch_%d: Payload capacity too small for a single pin\n",
			__func__, ch->ch_id);
		ret = -EINVAL;
		goto done;
	}

	req = kmalloc_array(max_pins_per_pkt, sizeof(*req), GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto done;
	}

	while (pins_sent < total_pins) {
		pins_in_pkt = min(max_pins_per_pkt, total_pins - pins_sent);

		for (int i = 0; i < pins_in_pkt; i++) {
			bit_off = find_next_bit(mask, gc->ngpio, bit_off);
			req[i].pin = cpu_to_le16(bit_off);
			req[i].value = test_bit(bit_off, bits) ? 1 : 0;
			bit_off++;
		}

		ret = lstp_request(ch, LSTP_GPIO_CMD_SET_VALUE, req, pins_in_pkt * sizeof(*req),
				   NULL, 0, NULL, NULL);
		if (ret) {
			dev_err(ch->dev,
				"%s: ch_%d: Could not set values for pins (mask=%*pb) (%pe)\n",
				__func__, ch->ch_id, gc->ngpio, mask, ERR_PTR(ret));
			goto out_free;
		}
		pins_sent += pins_in_pkt;
	}

	dev_dbg(ch->dev, "%s: ch_%d: Set %d pins, mask=%*pb, bits=%*pb\n", __func__, ch->ch_id,
		total_pins, gc->ngpio, mask, gc->ngpio, bits);

out_free:
	kfree(req);
done:
	return ret;
}

/**
 * lstp_gpio_get_irq_config() - Query IRQ config of a single GPIO. (blocking)
 * @priv: GPIO channel private data
 * @pin:  Pin index
 *
 * Return: IRQ type on success, negative errno on failure.
 */
static int lstp_gpio_get_irq_config(struct lstp_gpio_priv *priv, u16 pin)
{
	struct lstp_channel *ch = priv->ch;
	struct lstp_gpio_get_irq_config_req req = { .pin = cpu_to_le16(pin) };
	struct lstp_gpio_get_irq_config_resp resp;
	int ret;

	ret = lstp_request(ch, LSTP_GPIO_CMD_GET_IRQ_CONFIG, &req, sizeof(req), &resp, sizeof(resp),
			   NULL, NULL);
	if (ret) {
		dev_err(ch->dev, "%s: ch_%d: GET_IRQ_CONFIG failed for pin %u (%pe)\n", __func__,
			ch->ch_id, pin, ERR_PTR(ret));
		return ret;
	}

	return resp.irq_type;
}

/**
 * lstp_gpio_set_irq_config() - Set IRQ config of a single GPIO. (blocking)
 * @priv:     GPIO channel private data
 * @pin:      Pin index
 * @irq_type: Interrupt type (LSTP_GPIO_IRQ_* constants)
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_gpio_set_irq_config(struct lstp_gpio_priv *priv, u16 pin, u8 irq_type)
{
	struct lstp_channel *ch = priv->ch;
	struct lstp_gpio_set_irq_config_req req = {
		.pin = cpu_to_le16(pin),
		.irq_type = irq_type,
	};
	int ret;

	ret = lstp_request(ch, LSTP_GPIO_CMD_SET_IRQ_CONFIG, &req, sizeof(req), NULL, 0, NULL,
			   NULL);
	if (ret)
		dev_err(ch->dev, "%s: ch_%d: SET_IRQ_CONFIG failed for pin %u (%pe)\n", __func__,
			ch->ch_id, pin, ERR_PTR(ret));
	return ret;
}

/**
 * lstp_led_set_pattern() - SET_LED_PATTERN. (blocking)
 * @led:       LED instance
 * @repeats:   LSTP_LED_REPEAT_FOREVER or N (play N times, then hold last brightness)
 * @pattern:   Steps array (NULL iff @num_steps == 0); step.delta_t in ms
 * @num_steps: Element count of @pattern. 0 clears; 1 holds forever
 *
 * Return: 0 on success, negative errno on failure. Returns 0 without I/O when
 * LED_UNREGISTERING is set (avoids LED-core warnings during unregister).
 */
static int lstp_led_set_pattern(struct lstp_gpio_led *led, u32 repeats,
				const struct led_pattern *pattern, u8 num_steps)
{
	struct lstp_gpio_priv *priv = led->priv;
	struct lstp_channel *ch = priv->ch;
	struct lstp_gpio_set_led_pattern_req *req;
	size_t req_len = struct_size(req, pattern, num_steps);
	unsigned int max_brightness = led->cdev.max_brightness;
	int ret;
	u8 i;

	/* Probe enforces bulk_tx_size >= LSTP_USB_EP_MIN_SIZE; anchor base here. */
	BUILD_BUG_ON(sizeof(struct lstp_header) + sizeof(*req) > LSTP_USB_EP_MIN_SIZE);

	if (led->cdev.flags & LED_UNREGISTERING)
		return 0;

	for (i = 0; i < num_steps; i++) {
		if (pattern[i].brightness > max_brightness)
			return -EINVAL;
	}

	if (req_len > ch->max_tx_payload) {
		dev_err(ch->dev,
			"%s: ch_%d: SET_LED_PATTERN too long for led '%s' (%zu bytes, max %zu)\n",
			__func__, ch->ch_id, led->cdev.name, req_len, ch->max_tx_payload);
		return -EMSGSIZE;
	}

	req = kmalloc(req_len, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	req->pin = cpu_to_le16(led->pin);
	req->repeats = cpu_to_le32(repeats);
	req->num_steps = num_steps;
	for (i = 0; i < num_steps; i++) {
		req->pattern[i].brightness = (u8)pattern[i].brightness;
		req->pattern[i].time_ms = cpu_to_le32(pattern[i].delta_t);
	}

	ret = lstp_request(ch, LSTP_GPIO_CMD_SET_LED_PATTERN, req, req_len, NULL, 0, NULL, NULL);
	if (ret)
		dev_err(ch->dev,
			"%s: ch_%d: SET_LED_PATTERN failed for led '%s' (repeats=%u, num_steps=%u) (%pe)\n",
			__func__, ch->ch_id, led->cdev.name, repeats, num_steps, ERR_PTR(ret));

	kfree(req);
	return ret;
}

/*******************************************************************************
 * General GPIO functions
 ******************************************************************************/

/**
 * lstp_gpio_require_direction() - Require @pin's current device direction.
 * @priv:      GPIO channel private data
 * @pin:       Pin index (already bounds-checked by gpiolib via gpio_chip
 *             ->direction_input/output callers)
 * @direction: LSTP_GPIO_INPUT or LSTP_GPIO_OUTPUT
 *
 * Return: 0 if the current direction matches, -EOPNOTSUPP if the current
 * direction differs, or another negative errno on transport failure.
 */
static int lstp_gpio_require_direction(struct lstp_gpio_priv *priv, unsigned int pin, u8 direction)
{
	u8 cur_direction;
	int ret;

	ret = lstp_gpio_read_direction(priv, pin, &cur_direction);
	if (ret)
		return ret;

	if (cur_direction == direction)
		return 0;

	return -EOPNOTSUPP;
}

/**
 * lstp_gpio_get_direction() - Query GPIO pin direction.
 * @gc:  GPIO chip
 * @pin: Pin index
 *
 * Return: GPIO_LINE_DIRECTION_IN or GPIO_LINE_DIRECTION_OUT on success,
 * -EINVAL if @pin invalid, or other negative errno on transport failure.
 */
static int lstp_gpio_get_direction(struct gpio_chip *gc, unsigned int pin)
{
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);
	u8 direction;
	int ret;

	ret = lstp_gpio_read_direction(priv, pin, &direction);
	if (ret)
		return ret;

	if (direction == LSTP_GPIO_INPUT)
		return GPIO_LINE_DIRECTION_IN;

	return GPIO_LINE_DIRECTION_OUT;
}

/**
 * lstp_gpio_direction_input() - Accept GPIO as input if already configured so.
 * @gc:  GPIO chip
 * @pin: Pin index
 *
 * Return: 0 on success, -EINVAL if @pin invalid, -EOPNOTSUPP if the current
 * device direction differs, or other negative errno on transport failure.
 */
static int lstp_gpio_direction_input(struct gpio_chip *gc, unsigned int pin)
{
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);

	return lstp_gpio_require_direction(priv, pin, LSTP_GPIO_INPUT);
}

/**
 * lstp_gpio_direction_output() - Accept GPIO as output and set initial value.
 * @gc:    GPIO chip
 * @pin:   Pin index
 * @value: Initial logical output value (0 = low, non-zero = high)
 *
 * Return: 0 on success, -EINVAL if @pin invalid, -EOPNOTSUPP if the current
 * device direction differs, or other negative errno on transport failure.
 */
static int lstp_gpio_direction_output(struct gpio_chip *gc, unsigned int pin, int value)
{
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);
	int ret;

	ret = lstp_gpio_require_direction(priv, pin, LSTP_GPIO_OUTPUT);
	if (ret)
		return ret;

	return lstp_gpio_set_value(gc, pin, value);
}

/*******************************************************************************
 * GPIO IRQ functions
 ******************************************************************************/

/**
 * lstp_gpio_linux_irq_to_lstp() - Map Linux IRQ type to LSTP IRQ type.
 * @type:     Linux IRQ type (IRQ_TYPE_EDGE_*, IRQ_TYPE_LEVEL_*)
 * @irq_type: Output LSTP IRQ type
 *
 * Return: 0 on success, -EINVAL if type unsupported.
 */
static int lstp_gpio_linux_irq_to_lstp(unsigned int type, u8 *irq_type)
{
	switch (type & IRQ_TYPE_SENSE_MASK) {
	case IRQ_TYPE_NONE:
		*irq_type = LSTP_GPIO_IRQ_NONE;
		break;
	case IRQ_TYPE_EDGE_RISING:
		*irq_type = LSTP_GPIO_IRQ_RISING;
		break;
	case IRQ_TYPE_EDGE_FALLING:
		*irq_type = LSTP_GPIO_IRQ_FALLING;
		break;
	case IRQ_TYPE_EDGE_BOTH:
		*irq_type = LSTP_GPIO_IRQ_BOTH;
		break;
	case IRQ_TYPE_LEVEL_HIGH:
		*irq_type = LSTP_GPIO_IRQ_HIGH;
		break;
	case IRQ_TYPE_LEVEL_LOW:
		*irq_type = LSTP_GPIO_IRQ_LOW;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/**
 * lstp_gpio_irq_event_matches() - Check whether a wire event matches IRQ config.
 * @irq_type: Committed LSTP_GPIO_IRQ_* type for the pin (hw_irq_type)
 * @value:    Logical line level reported with the event
 *
 * Host-side defense against stale batches or firmware that skips filtering.
 */
static bool lstp_gpio_irq_event_matches(u8 irq_type, u8 value)
{
	switch (irq_type) {
	case LSTP_GPIO_IRQ_NONE:
		return false;
	case LSTP_GPIO_IRQ_RISING:
		return value == LSTP_GPIO_HIGH;
	case LSTP_GPIO_IRQ_FALLING:
		return value == LSTP_GPIO_LOW;
	case LSTP_GPIO_IRQ_BOTH:
		return true;
	case LSTP_GPIO_IRQ_HIGH:
		return value == LSTP_GPIO_HIGH;
	case LSTP_GPIO_IRQ_LOW:
		return value == LSTP_GPIO_LOW;
	default:
		return false;
	}
}

/**
 * lstp_gpio_sync_hw_irq_state() - Read device IRQ state for all GPIO lines at probe time.
 * @priv: GPIO channel private data (shadow_irq_type and hw_irq_type must be
 *        allocated)
 *
 * Queries GET_IRQ_CONFIG for each gpiochip line and populates both hw_irq_type
 * and shadow_irq_type so the driver starts in sync with the device, even after
 * a module reload without a device reset.
 *
 * Return: 0 on success, negative errno on first failure.
 */
static int lstp_gpio_sync_hw_irq_state(struct lstp_gpio_priv *priv)
{
	struct lstp_channel *ch = priv->ch;
	unsigned int active = 0;
	unsigned int pin;
	int ret;

	for (pin = 0; pin < priv->npins; pin++) {
		if (priv->leds[pin])
			continue;

		ret = lstp_gpio_get_irq_config(priv, pin);
		if (ret < 0)
			return ret;
		if (ret > LSTP_GPIO_IRQ_MAX)
			dev_warn(ch->dev, "%s: ch_%d: pin %u has unknown IRQ type %u\n", __func__,
				 ch->ch_id, pin, ret);
		priv->hw_irq_type[pin] = ret;
		priv->shadow_irq_type[pin] = ret;
		if (ret != LSTP_GPIO_IRQ_NONE)
			active++;
	}

	if (active)
		dev_info(ch->dev,
			 "%s: ch_%d: Synced IRQ state, %u/%u pins with active IRQ config\n",
			 __func__, ch->ch_id, active, priv->ngpio);

	return 0;
}

/**
 * lstp_gpio_irq_mask() - Mask (disable) a GPIO interrupt.
 * @d: IRQ data
 *
 * Sets shadow to IRQ_NONE; SET_IRQ_CONFIG sent in irq_bus_sync_unlock().
 */
static void lstp_gpio_irq_mask(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);
	unsigned int pin = irqd_to_hwirq(d);

	priv->shadow_irq_type[pin] = LSTP_GPIO_IRQ_NONE;
	gpiochip_disable_irq(gc, pin);
}

/**
 * lstp_gpio_irq_unmask() - Unmask (enable) a GPIO interrupt.
 * @d: IRQ data
 *
 * Restores shadow to trigger type from IRQ descriptor.
 * SET_IRQ_CONFIG sent in irq_bus_sync_unlock().
 */
static void lstp_gpio_irq_unmask(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);
	unsigned int pin = irqd_to_hwirq(d);
	unsigned int type = irqd_get_trigger_type(d);
	u8 irq_type;

	if (lstp_gpio_linux_irq_to_lstp(type, &irq_type)) {
		dev_err(gc->parent, "%s: Invalid trigger type %u for gpio %u\n", __func__, type,
			pin);
		return;
	}

	gpiochip_enable_irq(gc, pin);
	priv->shadow_irq_type[pin] = irq_type;
}

/**
 * lstp_gpio_irq_set_type() - Set GPIO interrupt trigger type.
 * @d:    IRQ data
 * @type: IRQ type flags (IRQ_TYPE_EDGE_*, IRQ_TYPE_LEVEL_*)
 *
 * IRQCHIP_SET_TYPE_MASKED ensures the IRQ is masked, so this only validates
 * the type; the shadow update is deferred to irq_unmask().
 *
 * Return: 0 on success, -EINVAL if type unsupported.
 */
static int lstp_gpio_irq_set_type(struct irq_data *d, unsigned int type)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);
	unsigned int pin = irqd_to_hwirq(d);
	u8 irq_type;
	int ret;

	ret = lstp_gpio_linux_irq_to_lstp(type, &irq_type);
	if (ret)
		return ret;

	if (irqd_irq_masked(d))
		return 0;

	priv->shadow_irq_type[pin] = irq_type;
	return 0;
}

/**
 * lstp_gpio_irq_bus_lock() - Acquire IRQ configuration lock.
 * @d: IRQ data
 *
 * Serializes irq_chip callbacks in a sleepable context (bus_lock pattern).
 */
static void lstp_gpio_irq_bus_lock(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);

	mutex_lock(&priv->irq_lock);
}

/**
 * lstp_gpio_irq_bus_sync_unlock() - Commit pending IRQ config and release lock.
 * @d: IRQ data for the pin that was modified
 *
 * Sends SET_IRQ_CONFIG if shadow differs from hardware for this pin.
 * On failure, reverts shadow to previous known state. Releases priv->irq_lock.
 */
static void lstp_gpio_irq_bus_sync_unlock(struct irq_data *d)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);
	struct lstp_gpio_priv *priv = gpiochip_get_data(gc);
	u16 pin = irqd_to_hwirq(d);

	if (priv->shadow_irq_type[pin] != priv->hw_irq_type[pin]) {
		if (lstp_gpio_set_irq_config(priv, pin, priv->shadow_irq_type[pin]))
			priv->shadow_irq_type[pin] = priv->hw_irq_type[pin];
		else
			priv->hw_irq_type[pin] = priv->shadow_irq_type[pin];
	}

	mutex_unlock(&priv->irq_lock);
}

/**
 * lstp_gpio_irq_print_chip() - Print GPIO chip label in /proc/interrupts.
 * @d: IRQ data
 * @p: Seq file to write to
 */
static void lstp_gpio_irq_print_chip(struct irq_data *d, struct seq_file *p)
{
	struct gpio_chip *gc = irq_data_get_irq_chip_data(d);

	seq_puts(p, gc->label ? gc->label : d->chip->name);
}

static const struct irq_chip lstp_gpio_irq_chip = {
	.name = "lstp-gpio",
	.irq_mask = lstp_gpio_irq_mask,
	.irq_unmask = lstp_gpio_irq_unmask,
	.irq_set_type = lstp_gpio_irq_set_type,
	.irq_bus_lock = lstp_gpio_irq_bus_lock,
	.irq_bus_sync_unlock = lstp_gpio_irq_bus_sync_unlock,
	.irq_print_chip = lstp_gpio_irq_print_chip,
	.flags = IRQCHIP_SET_TYPE_MASKED | IRQCHIP_MASK_ON_SUSPEND | IRQCHIP_IMMUTABLE,
	GPIOCHIP_IRQ_RESOURCE_HELPERS,
};

/**
 * lstp_gpio_irq_event_work() - Deferred GPIO interrupt batch handler.
 * @work: Work structure containing a snapshot of one unsolicited RX payload
 *
 * Delivers matching events in payload order via handle_nested_irq();
 * synchronize_irq() after each keeps threaded handlers from reordering.
 * The ordered workqueue serializes batches in USB receive order.
 */
static void lstp_gpio_irq_event_work(struct work_struct *work)
{
	struct lstp_gpio_irq_event_work *batch =
		container_of(work, struct lstp_gpio_irq_event_work, work);
	struct lstp_gpio_priv *priv = batch->priv;
	struct lstp_channel *ch = priv->ch;
	struct gpio_chip *gc = &priv->gc;
	const struct lstp_gpio_irq_event_req *event;
	const struct lstp_gpio_irq_event_req *end;
	u16 pin;
	u8 value;
	int irq;

	/* Probe enforces bulk_rx_size >= LSTP_USB_EP_MIN_SIZE; anchor base here. */
	BUILD_BUG_ON(sizeof(struct lstp_header) + sizeof(*event) > LSTP_USB_EP_MIN_SIZE);

	if (batch->payload_len < sizeof(*event)) {
		dev_err(ch->dev, "%s: ch_%d: IRQ event packet too small (got %u, need >=%zu)\n",
			__func__, ch->ch_id, batch->payload_len, sizeof(*event));
		goto out;
	}

	if (batch->payload_len % sizeof(*event)) {
		dev_err(ch->dev,
			"%s: ch_%d: Malformed IRQ event payload (len %u, record size %zu)\n",
			__func__, ch->ch_id, batch->payload_len, sizeof(*event));
		goto out;
	}

	end = (void *)(batch->payload + batch->payload_len);
	for (event = (void *)batch->payload; event < end; event++) {
		pin = le16_to_cpu(event->pin);
		if (pin >= priv->npins || priv->leds[pin]) {
			dev_warn_ratelimited(ch->dev, "%s: ch_%d: IRQ on non-GPIO pin %u\n",
					     __func__, ch->ch_id, pin);
			continue;
		}

		value = event->value;
		dev_dbg(ch->dev, "%s: ch=%d: IRQ event: pin=%u, value=%u\n", __func__, ch->ch_id,
			pin, value);

		if (!lstp_gpio_irq_event_matches(priv->hw_irq_type[pin], value)) {
			dev_dbg(gc->parent, "%s: Skipping pin %u value %u (irq_type %u)\n",
				__func__, pin, value, priv->hw_irq_type[pin]);
			continue;
		}

		if (!gc->irq.domain) {
			dev_warn_ratelimited(gc->parent, "%s: IRQ domain not ready for pin %u\n",
					     __func__, pin);
			continue;
		}

		irq = irq_find_mapping(gc->irq.domain, pin);
		if (irq) {
			handle_nested_irq(irq);
			synchronize_irq(irq);
			dev_dbg(gc->parent, "%s: Nested IRQ %d handled for pin %u\n", __func__, irq,
				pin);
		} else {
			dev_warn_ratelimited(gc->parent, "%s: No IRQ mapping found for pin %u\n",
					     __func__, pin);
		}
	}

out:
	kfree(batch);
}

/**
 * lstp_gpio_irq_event() - Process GPIO interrupt event from unsolicited RX packet.
 * @ch:  LSTP channel that received the request.
 * @pkt: Received LSTP packet (header + payload).
 *
 * Copies the payload out of @pkt and returns immediately so USB RX can
 * dequeue the next packet. All GPIO-specific validation and ordered delivery run
 * in the ordered workqueue handler. Must not block (atomic context).
 */
static void lstp_gpio_irq_event(struct lstp_channel *ch, struct lstp_packet *pkt)
{
	struct lstp_gpio_priv *priv = ch->priv;
	struct lstp_gpio_irq_event_work *batch;
	u16 payload_len;

	if (!priv) {
		dev_err(ch->dev, "%s: ch_%d: No GPIO private data found in channel\n", __func__,
			ch->ch_id);
		return;
	}

	payload_len = le16_to_cpu(pkt->hdr.length);
	if (!payload_len)
		return;

	if (payload_len > ch->max_rx_payload) {
		dev_warn_ratelimited(ch->dev,
				     "%s: ch_%d: Dropping IRQ payload too large (%u > %zu bytes)\n",
				     __func__, ch->ch_id, payload_len, ch->max_rx_payload);
		return;
	}

	batch = kzalloc(struct_size(batch, payload, payload_len), GFP_ATOMIC);
	if (!batch)
		return;

	batch->priv = priv;
	batch->payload_len = payload_len;
	memcpy(batch->payload, pkt->payload, payload_len);

	INIT_WORK(&batch->work, lstp_gpio_irq_event_work);
	if (!queue_work(priv->wq, &batch->work)) {
		dev_warn(ch->dev, "%s: ch_%d: Failed to queue IRQ event work (%u bytes)\n",
			 __func__, ch->ch_id, payload_len);
		kfree(batch);
	}
}

/*******************************************************************************
 * LED class functions
 ******************************************************************************/

/**
 * lstp_led_blink_set() - blink_set callback. (blocking)
 * @cdev:      LED class device
 * @delay_on:  in/out; on-time in ms (0 -> hold OFF; 0/0 -> 500 ms default)
 * @delay_off: in/out; off-time in ms (0 -> hold ON; 0/0 -> 500 ms default)
 *
 * On-brightness uses @cdev->brightness if non-zero, else @cdev->max_brightness.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_led_blink_set(struct led_classdev *cdev, unsigned long *delay_on,
			      unsigned long *delay_off)
{
	struct lstp_gpio_led *led = container_of(cdev, struct lstp_gpio_led, cdev);
	u8 on_value = cdev->brightness ? (u8)cdev->brightness : (u8)cdev->max_brightness;
	struct led_pattern steps[2];
	u8 len;

	if (*delay_on == 0 && *delay_off == 0) {
		*delay_on = LSTP_LED_DEFAULT_BLINK_MS;
		*delay_off = LSTP_LED_DEFAULT_BLINK_MS;
	}

	if (*delay_on == 0) {
		steps[0].delta_t = LSTP_LED_DEFAULT_HOLD_TIME_MS;
		steps[0].brightness = LED_OFF;
		len = 1;
	} else if (*delay_off == 0) {
		steps[0].delta_t = LSTP_LED_DEFAULT_HOLD_TIME_MS;
		steps[0].brightness = on_value;
		len = 1;
	} else {
		steps[0].delta_t = *delay_on;
		steps[0].brightness = on_value;
		steps[1].delta_t = *delay_off;
		steps[1].brightness = LED_OFF;
		len = 2;
	}
	return lstp_led_set_pattern(led, LSTP_LED_REPEAT_FOREVER, steps, len);
}

/**
 * lstp_led_pattern_set() - pattern_set callback. (blocking)
 * @cdev:    LED class device
 * @pattern: Array of @len steps (delta_t in ms, brightness)
 * @len:     Number of steps (must fit wire's u8 num_steps)
 * @repeat:  LSTP_LED_LINUX_REPEAT_FOREVER or N >= 1; anything else is invalid
 *
 * Return: 0 on success, -EMSGSIZE if @len exceeds u8, -EINVAL on invalid
 * @repeat, negative errno on other failure.
 */
static int lstp_led_pattern_set(struct led_classdev *cdev, struct led_pattern *pattern, u32 len,
				int repeat)
{
	struct lstp_gpio_led *led = container_of(cdev, struct lstp_gpio_led, cdev);
	u32 mapped_repeat;

	if (len > U8_MAX)
		return -EMSGSIZE;
	if (repeat == 0 || repeat < LSTP_LED_LINUX_REPEAT_FOREVER)
		return -EINVAL;
	mapped_repeat = (repeat == LSTP_LED_LINUX_REPEAT_FOREVER) ? LSTP_LED_REPEAT_FOREVER :
								    (u32)repeat;
	return lstp_led_set_pattern(led, mapped_repeat, pattern, (u8)len);
}

/**
 * lstp_led_pattern_clear() - pattern_clear callback. (blocking)
 * @cdev: LED class device
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_led_pattern_clear(struct led_classdev *cdev)
{
	struct lstp_gpio_led *led = container_of(cdev, struct lstp_gpio_led, cdev);

	return lstp_led_set_pattern(led, LSTP_LED_REPEAT_FOREVER, NULL, 0);
}

/**
 * lstp_led_brightness_set_blocking() - brightness_set_blocking callback. (blocking)
 * @cdev:       LED class device
 * @brightness: Already clamped by LED core to @cdev->max_brightness
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_led_brightness_set_blocking(struct led_classdev *cdev,
					    enum led_brightness brightness)
{
	struct lstp_gpio_led *led = container_of(cdev, struct lstp_gpio_led, cdev);
	struct led_pattern step = { .delta_t = LSTP_LED_DEFAULT_HOLD_TIME_MS,
				    .brightness = brightness };

	return lstp_led_set_pattern(led, LSTP_LED_REPEAT_FOREVER, &step, 1);
}

/*******************************************************************************
 * GPIO channel initialization
 ******************************************************************************/

/**
 * lstp_gpio_pin_is_led() - Return whether @led_support marks a pin as LED.
 * @led_support: led_support byte from pin config
 *
 * HOLD and INTERPOLATE differ only in device-side rendering; the host treats both
 * as LED pins, excluded from the gpiochip.
 */
static bool lstp_gpio_pin_is_led(u8 led_support)
{
	return led_support == LSTP_GPIO_LED_MODE_HOLD ||
	       led_support == LSTP_GPIO_LED_MODE_INTERPOLATE;
}

/**
 * lstp_gpio_clear_led_valid_mask() - Clear LED pins from a valid mask.
 * @priv:       GPIO channel private data
 * @valid_mask: Pre-filled bitmap of length @ngpios
 * @ngpios:     Number of lines on the chip (priv->npins)
 */
static void lstp_gpio_clear_led_valid_mask(struct lstp_gpio_priv *priv, unsigned long *valid_mask,
					   unsigned int ngpios)
{
	unsigned int i;

	for (i = 0; i < ngpios; i++) {
		if (priv->leds[i])
			clear_bit(i, valid_mask);
	}
}

/**
 * lstp_gpio_init_valid_mask() - gpio_chip callback to mark LED pins invalid.
 * @gc:         GPIO chip
 * @valid_mask: Pre-filled bitmap of length @ngpios
 * @ngpios:     Number of lines on the chip (priv->npins)
 *
 * Return: 0.
 */
static int lstp_gpio_init_valid_mask(struct gpio_chip *gc, unsigned long *valid_mask,
				     unsigned int ngpios)
{
	lstp_gpio_clear_led_valid_mask(gpiochip_get_data(gc), valid_mask, ngpios);
	return 0;
}

/**
 * lstp_gpio_irq_init_valid_mask() - gpio_irq_chip callback to mark LED pins invalid.
 * @gc:         GPIO chip
 * @valid_mask: Pre-filled bitmap of length @ngpios
 * @ngpios:     Number of lines on the chip (priv->npins)
 */
static void lstp_gpio_irq_init_valid_mask(struct gpio_chip *gc, unsigned long *valid_mask,
					  unsigned int ngpios)
{
	lstp_gpio_clear_led_valid_mask(gpiochip_get_data(gc), valid_mask, ngpios);
}

/**
 * lstp_gpio_destroy_wq() - Devres callback to destroy the GPIO IRQ workqueue.
 * @wq: Workqueue to destroy
 */
static void lstp_gpio_destroy_wq(void *wq)
{
	destroy_workqueue(wq);
}

/**
 * lstp_gpio_create_gpiochip() - Initialize gpio_chip.
 * @priv: GPIO channel private data (ch, npins, and pin_names must be set)
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_gpio_create_gpiochip(struct lstp_gpio_priv *priv)
{
	struct lstp_channel *ch = priv->ch;
	struct device *dev = ch->dev;
	struct gpio_chip *gc = &priv->gc;

	gc->label = ch->display_name;
	gc->owner = THIS_MODULE;
	gc->names = priv->pin_names;
	gc->base = -1;
	gc->ngpio = priv->npins;
	gc->get = lstp_gpio_get_value;
	gc->set = lstp_gpio_set_value;
	gc->can_sleep = true;
	gc->get_multiple = lstp_gpio_get_multiple;
	gc->set_multiple = lstp_gpio_set_multiple;
	gc->get_direction = lstp_gpio_get_direction;
	gc->direction_input = lstp_gpio_direction_input;
	gc->direction_output = lstp_gpio_direction_output;
	gc->init_valid_mask = lstp_gpio_init_valid_mask;
	gc->parent = dev;

	if (ch->fwnode)
		gc->fwnode = ch->fwnode;

	return 0;
}

/**
 * lstp_gpio_create_irq_chip() - Allocate IRQ state and initialize gpio_irq_chip.
 * @priv: GPIO channel private data
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_gpio_create_irq_chip(struct lstp_gpio_priv *priv)
{
	struct lstp_channel *ch = priv->ch;
	struct device *dev = ch->dev;
	struct gpio_chip *gc = &priv->gc;
	struct gpio_irq_chip *girq = &gc->irq;
	int ret;

	if (!priv->ngpio)
		return 0;

	priv->shadow_irq_type =
		devm_kcalloc(dev, priv->npins, sizeof(*priv->shadow_irq_type), GFP_KERNEL);
	if (!priv->shadow_irq_type)
		return -ENOMEM;

	priv->hw_irq_type = devm_kcalloc(dev, priv->npins, sizeof(*priv->hw_irq_type), GFP_KERNEL);
	if (!priv->hw_irq_type)
		return -ENOMEM;

	gpio_irq_chip_set_chip(girq, &lstp_gpio_irq_chip);
	girq->init_valid_mask = lstp_gpio_irq_init_valid_mask;
	girq->parent_handler = NULL;
	girq->num_parents = 0;
	girq->parents = NULL;
	girq->default_type = IRQ_TYPE_NONE;
	girq->handler = handle_simple_irq;
	girq->threaded = true;

	mutex_init(&priv->irq_lock);

	priv->wq = alloc_ordered_workqueue("lstp_gpio_wq", 0);
	if (!priv->wq) {
		dev_err(dev, "%s: ch_%d: Failed to create ordered IRQ workqueue\n", __func__,
			ch->ch_id);
		return -ENOMEM;
	}

	ret = devm_add_action_or_reset(dev, lstp_gpio_destroy_wq, priv->wq);
	if (ret)
		return ret;

	return 0;
}

/**
 * lstp_gpio_create_led() - Create an LED cdev for a pin at probe.
 * @priv:        GPIO private data
 * @pin:         Pin index
 * @name:        Sysfs name (caller-owned for channel lifetime; do not free)
 * @direction:   Direction byte from the pin's config
 * @led_support: LED support byte from the pin's config
 *
 * Allocate an LED cdev for output + HOLD/INTERPOLATE pins. Register in lstp_gpio_register_led().
 *
 * Return: 0 on success; -EINVAL if LED config is rejected (caller falls back to GPIO);
 * -ENOMEM on allocation failure.
 */
static int lstp_gpio_create_led(struct lstp_gpio_priv *priv, u16 pin, const char *name,
				u8 direction, u8 led_support)
{
	struct lstp_channel *ch = priv->ch;
	struct device *parent = ch->dev;
	struct lstp_gpio_led *led;

	if (!lstp_gpio_pin_is_led(led_support))
		return -EINVAL;

	if (direction != LSTP_GPIO_OUTPUT) {
		dev_warn(parent,
			 "%s: ch_%d: led_support=0x%02x for pin %u but direction is input, treating as GPIO\n",
			 __func__, ch->ch_id, led_support, pin);
		return -EINVAL;
	}
	if (priv->leds[pin]) {
		dev_dbg(parent, "%s: ch_%d: LED '%s', pin %u already created, skipping\n", __func__,
			ch->ch_id, priv->leds[pin]->cdev.name, pin);
		return 0;
	}

	led = devm_kzalloc(parent, sizeof(*led), GFP_KERNEL);
	if (!led)
		return -ENOMEM;

	led->priv = priv;
	led->pin = pin;
	led->cdev.name = name;
	led->cdev.max_brightness = U8_MAX;
	led->cdev.brightness_set_blocking = lstp_led_brightness_set_blocking;
	led->cdev.blink_set = lstp_led_blink_set;
	led->cdev.pattern_set = lstp_led_pattern_set;
	led->cdev.pattern_clear = lstp_led_pattern_clear;

	priv->leds[pin] = led;
	dev_dbg(parent, "%s: ch_%d: Created LED '%s'\n", __func__, ch->ch_id, name);
	return 0;
}

/**
 * lstp_gpio_register_led() - Register @pin's LED with the LED class core.
 * @priv: GPIO private data
 * @pin:  Pin index
 *
 * Best-effort: skips if no cdev or already registered. Registration is
 * devres-managed; on failure logs and LED stays unregistered.
 *
 * Return: 0 on success or nothing to register; negative errno on failure.
 */
static int lstp_gpio_register_led(struct lstp_gpio_priv *priv, unsigned int pin)
{
	struct device *parent = priv->ch->dev;
	int ret;

	if (pin >= priv->npins || !priv->leds[pin] || priv->leds[pin]->cdev.dev)
		return 0;

	ret = devm_led_classdev_register(parent, &priv->leds[pin]->cdev);
	if (ret)
		dev_warn(parent, "%s: ch_%d: Could not register LED '%s', pin %u (%pe)\n", __func__,
			 priv->ch->ch_id, priv->leds[pin]->cdev.name, pin, ERR_PTR(ret));
	return ret;
}

/**
 * lstp_gpio_pin_setup_on_entry() - Classify a config entry as GPIO or LED.
 * @ch:    LSTP channel
 * @pin:   Pin index
 * @entry: Config entry (struct lstp_gpio_pin)
 * @ctx:   GPIO channel private data (struct lstp_gpio_priv)
 *
 * Return: 0 on success.
 */
static int lstp_gpio_pin_setup_on_entry(struct lstp_channel *ch, unsigned int pin,
					const void *entry, void *ctx)
{
	struct lstp_gpio_priv *priv = ctx;
	const struct lstp_gpio_pin *pin_cfg = entry;
	char *name;
	u8 led_support = pin_cfg->config.led_support;
	int ret;

	name = devm_kzalloc(ch->dev, GPIO_MAX_NAME_SIZE, GFP_KERNEL);
	if (!name)
		return -ENOMEM;
	snprintf(name, GPIO_MAX_NAME_SIZE, "%.*s", (int)LSTP_GPIO_PIN_NAME_LEN, pin_cfg->pin_name);
	priv->pin_names[pin] = name;

	if (lstp_gpio_pin_is_led(led_support)) {
		ret = lstp_gpio_create_led(priv, pin, name, pin_cfg->config.direction, led_support);
		if (ret == -ENOMEM)
			return ret;
		if (!ret) {
			priv->nleds++;
			return 0;
		}
		/* LED config rejected (create_led logged why); fall back to GPIO. */
	} else if (led_support != LSTP_GPIO_NOT_LED) {
		dev_warn(ch->dev,
			 "%s: ch_%d: Unknown led_support=0x%02x for pin %u, treating as GPIO\n",
			 __func__, ch->ch_id, led_support, pin);
	}

	priv->ngpio++;
	return 0;
}

/**
 * lstp_gpio_init() - Initialize GPIO channel.
 * @ch:   LSTP channel configured for GPIO
 * @info: Channel config blob (struct lstp_gpio_config)
 *
 * Sets up the gpio_chip and irq_chip and classifies each configured pin as a
 * GPIO or an LED. Does not register the chip; call lstp_gpio_start() once the
 * RX URB is active.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_gpio_init(struct lstp_channel *ch, const struct lstp_channel_init_info *info)
{
	int ret;
	struct lstp_gpio_priv *priv;
	const struct lstp_gpio_config *config = info->config;

	if (info->config_len < sizeof(*config)) {
		dev_err(ch->dev, "%s: ch_%d: GPIO config too short: %zu < %zu\n", __func__,
			ch->ch_id, info->config_len, sizeof(*config));
		return -EINVAL;
	}
	if (config->npins == 0) {
		dev_err(ch->dev, "%s: ch_%d: Invalid npins of 0\n", __func__, ch->ch_id);
		return -EINVAL;
	}

	priv = devm_kzalloc(ch->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->pin_names =
		devm_kcalloc(ch->dev, config->npins, sizeof(*priv->pin_names), GFP_KERNEL);
	if (!priv->pin_names)
		return -ENOMEM;

	priv->leds = devm_kcalloc(ch->dev, config->npins, sizeof(*priv->leds), GFP_KERNEL);
	if (!priv->leds)
		return -ENOMEM;

	priv->ch = ch;
	priv->npins = config->npins;
	ch->priv = priv;

	/* Truncate display_name to fit GPIO_MAX_NAME_SIZE (32 bytes including '\0') */
	if (strlen(ch->display_name) >= GPIO_MAX_NAME_SIZE) {
		dev_warn(ch->dev, "%s: ch_%d: display_name truncated to '%.*s' (max %d chars)\n",
			 __func__, ch->ch_id, GPIO_MAX_NAME_SIZE - 1, ch->display_name,
			 GPIO_MAX_NAME_SIZE - 1);
		ch->display_name[GPIO_MAX_NAME_SIZE - 1] = '\0';
	}

	ret = lstp_gpio_create_gpiochip(priv);
	if (ret)
		return ret;

	/* Setup all pins from device config */
	ret = lstp_read_config_table(ch, sizeof(struct lstp_gpio_config),
				     sizeof(struct lstp_gpio_pin), priv->npins,
				     lstp_gpio_pin_setup_on_entry, priv);
	if (ret) {
		dev_err(ch->dev, "%s: ch_%d: Could not setup pins (%pe)\n", __func__, ch->ch_id,
			ERR_PTR(ret));
		return ret;
	}
	if (priv->ngpio == 0 && priv->nleds == 0) {
		dev_err(ch->dev, "%s: ch_%d: No GPIO or LED pins discovered\n", __func__,
			ch->ch_id);
		return -EINVAL;
	}

	ret = lstp_gpio_create_irq_chip(priv);
	if (ret)
		return ret;

	dev_dbg(ch->dev, "%s: ch_%d: Initialized as %s\n", __func__, ch->ch_id, priv->gc.label);
	return 0;
}

/**
 * lstp_gpio_start() - Register GPIO chip and LED cdevs with kernel.
 * @ch: LSTP channel (from lstp_gpio_init)
 *
 * Register gpiochip and probe-time LED cdevs. LED classdevs are devres-managed
 * and unregister on interface release.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int lstp_gpio_start(struct lstp_channel *ch)
{
	int ret;
	struct lstp_gpio_priv *priv = ch->priv;
	struct gpio_chip *gc;
	unsigned int pin;

	if (!priv) {
		dev_err(ch->dev, "%s: ch_%d: GPIO chip not initialized\n", __func__, ch->ch_id);
		return -EINVAL;
	}

	gc = &priv->gc;

	if (priv->ngpio) {
		ret = lstp_gpio_sync_hw_irq_state(priv);
		if (ret)
			return ret;

		ret = gpiochip_add_data(gc, priv);
		if (ret) {
			dev_err(ch->dev, "%s: ch_%d: Could not register GPIO chip (%pe)\n",
				__func__, ch->ch_id, ERR_PTR(ret));
			return ret;
		}

		deprecated_lstp_channel_publish_child_dev(ch, gpio_device_to_device(gc->gpiodev));
	}

	for (pin = 0; pin < priv->npins; pin++)
		lstp_gpio_register_led(priv, pin);

	/*
	 * The channel's "device" symlink needs a target. A GPIO channel points
	 * it at the gpiochip (above); a pure-LED channel has no gpiochip, so
	 * link the first registered LED instead. The single-peer link cannot
	 * name every LED, but some target is required: the framework warns when
	 * a channel exposes no device.
	 */
	for (pin = 0; !priv->ngpio && pin < priv->npins; pin++) {
		if (priv->leds[pin] && priv->leds[pin]->cdev.dev) {
			deprecated_lstp_channel_publish_child_dev(ch, priv->leds[pin]->cdev.dev);
			break;
		}
	}

	dev_info(ch->dev, "%s: ch_%d: Started as %s with %u GPIOs and %u LEDs\n", __func__,
		 ch->ch_id, gc->label, priv->ngpio, priv->nleds);
	return 0;
}

/**
 * lstp_gpio_stop() - Tear down the GPIO channel.
 * @ch: LSTP channel previously started by lstp_gpio_start()
 *
 * Drains pending IRQ-event work, then unregisters the gpio_chip.
 */
static void lstp_gpio_stop(struct lstp_channel *ch)
{
	struct lstp_gpio_priv *priv = ch->priv;

	if (!priv)
		return;

	/* Drain RX-queued IRQ-event work while gc->irq.domain is still valid. */
	if (priv->wq)
		flush_workqueue(priv->wq);

	if (priv->ngpio)
		gpiochip_remove(&priv->gc);
}

/* clang-format off */
LSTP_SUBSYS(gpio, LSTP_CHANNEL_TYPE_GPIO, lstp_gpio_init, lstp_gpio_start,
	    .fwnode_compatible = "nvidia,lstp-gpio",
	    .irq_callback = lstp_gpio_irq_event,
	    .channel_stop = lstp_gpio_stop,
);
/* clang-format on */
