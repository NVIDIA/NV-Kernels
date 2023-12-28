// SPDX-License-Identifier: GPL-2.0-only
/*
 * Driver for M058SSAN I2C GPO expander
 *
 * Copyright (C) 2023 Filippo Copetti <filippo.copetti@eurotech.com>
 *
 * Based on gpio-tpic2810.c
 * Copyright (C) 2015 Texas Instruments Incorporated - http://www.ti.com/
 *	Andrew F. Davis <afd@ti.com>
 */

#include <linux/gpio/driver.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/property.h>

/*
 * GPIO bank #1 (offset 0...7) is configured as output
 * GPIO bank #2 (offset 8...15) is configured as input
 */

#define M058SSAN_OUTPUT_BANK            0x01
#define M058SSAN_INPUT_BANK             0x02
#define M058SSAN_INPUT_OUTPUT_OFFSET    0x07

/**
 * m058ssan_read(gpio, &gpio->out, 0x02);
 * o->out * struct m058ssan - GPIO driver data
 * @chip: GPIO controller chip
 * @lock: Protects write sequences
 * @out: Buffer for device register
 */
struct m058ssan {
	struct gpio_chip chip;
	struct mutex lock;
	u8 out;
};

static int m058ssan_read(struct m058ssan *gpio, u8 *value, u8 address)
{
	struct i2c_client *client = to_i2c_client(gpio->chip.parent);
	int ret;

	ret = i2c_smbus_read_byte_data(client, address);

	if (ret < 0)
		return ret;

	*value = ret;

	return 0;
}

static int m058ssan_write(struct m058ssan *gpio, u8 value, u8 address)
{
	struct i2c_client *client = to_i2c_client(gpio->chip.parent);

	return i2c_smbus_write_byte_data(client, address, value);
}

static int m058ssan_get_direction(struct gpio_chip *chip, unsigned int offset)
{
	if (offset > M058SSAN_INPUT_OUTPUT_OFFSET)
		return GPIO_LINE_DIRECTION_IN;
	else
		return GPIO_LINE_DIRECTION_OUT;
}

static int m058ssan_gpio_direction_input(struct gpio_chip *gc, unsigned int offset)
{
	if (offset > M058SSAN_INPUT_OUTPUT_OFFSET)
		return 0;
	else
		return -1;
}

static int m058ssan_gpio_direction_output(struct gpio_chip *gc, unsigned int offset, int value)
{
	if (offset > M058SSAN_INPUT_OUTPUT_OFFSET)
		return -1;
	else
		return 0;
}

static int m058ssan_get(struct gpio_chip *chip, unsigned int offset)
{
	struct m058ssan *gpio = gpiochip_get_data(chip);
	u8 buffer;
	int ret;

	if (offset > M058SSAN_INPUT_OUTPUT_OFFSET) {
		ret = m058ssan_read(gpio, &buffer, M058SSAN_INPUT_BANK);
		offset -= (M058SSAN_INPUT_OUTPUT_OFFSET + 1);
	} else {
		ret = m058ssan_read(gpio, &buffer, M058SSAN_OUTPUT_BANK);
	}
	if (ret)
		return ret;

	return buffer & BIT(offset);
}

static void m058ssan_set(struct gpio_chip *chip, unsigned int offset, int value)
{
	struct m058ssan *gpio = gpiochip_get_data(chip);
	u8 buffer;
	int ret;

	if (offset > M058SSAN_INPUT_OUTPUT_OFFSET)
		return;

	mutex_lock(&gpio->lock);

	buffer = gpio->out;

	if (value)
		buffer |= BIT(offset);
	else
		buffer &= ~BIT(offset);

	ret = m058ssan_write(gpio, buffer, M058SSAN_OUTPUT_BANK);

	if (ret)
		goto out;

	gpio->out = buffer;

out:
	mutex_unlock(&gpio->lock);
}

static int m058ssan_probe(struct i2c_client *client)
{
	struct m058ssan *gpio;

	gpio = devm_kzalloc(&client->dev, sizeof(*gpio), GFP_KERNEL);

	if (!gpio)
		return -ENOMEM;

	gpio->chip.label = client->name;
	gpio->chip.parent = &client->dev;
	gpio->chip.owner = THIS_MODULE;
	gpio->chip.get_direction = m058ssan_get_direction;
	gpio->chip.direction_input = m058ssan_gpio_direction_input;
	gpio->chip.direction_output = m058ssan_gpio_direction_output;
	gpio->chip.get = m058ssan_get;
	gpio->chip.set = m058ssan_set;
	gpio->chip.base = -1;
	gpio->chip.ngpio = 16;
	gpio->chip.can_sleep = true;

	mutex_init(&gpio->lock);

	/* Read the current output level */
	if (gpio->out > M058SSAN_INPUT_OUTPUT_OFFSET)
		m058ssan_read(gpio, &gpio->out, M058SSAN_INPUT_BANK);
	else
		m058ssan_read(gpio, &gpio->out, M058SSAN_OUTPUT_BANK);

	return devm_gpiochip_add_data(&client->dev, &gpio->chip, gpio);
}

static const struct i2c_device_id m058ssan_id_table[] = {
	{"m058ssan", 4},
	{ /* sentinel */ }
};

MODULE_DEVICE_TABLE(i2c, m058ssan_id_table);

static const struct of_device_id m058ssan_of_match_table[] = {
	{.compatible = "nuvoton,m058ssan", .data = (void *)4},
	{ /* sentinel */ }
};

MODULE_DEVICE_TABLE(of, m058ssan_of_match_table);

static struct i2c_driver m058ssan_driver = {
	.driver = {
		   .name = "m058ssan",
		   .of_match_table = m058ssan_of_match_table,
		   },
	.probe_new = m058ssan_probe,
	.id_table = m058ssan_id_table,
};

module_i2c_driver(m058ssan_driver);

MODULE_AUTHOR("Filippo Copetti <filippo.copetti@eurotech.com>");
MODULE_DESCRIPTION("GPIO expander driver for M058SSAN");
MODULE_LICENSE("GPL v2");
