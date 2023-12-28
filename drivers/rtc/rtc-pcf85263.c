// SPDX-License-Identifier: GPL-2.0
/*
 * NXP PCF85263 RTC driver
 * Copyright (C) 2015 Eurotech Ltd Fabrizio Castro
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>
 */
#define DEBUG 0

#include <linux/i2c.h>
#include <linux/bcd.h>
#include <linux/rtc.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/gpio.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/watchdog.h>
#include <linux/pm.h>
#include <linux/pm_wakeup.h>
#include <linux/io.h>
#include "rtc-pcf85263.h"

/*
 * This driver implements only a subset of the HW capabilities:
 * - RTC
 * - Alarm 1
 * - watchdog
 * - timestamps
 * - RAM byte
 * - Battery management
 * - Oscillator
 */
/*
 * workaround for the sleep/wakeup issue
 * resuming from sleep we need to set the gpio0_19 bit
 * in this registers. Due to pcb routing there is no need
 * to configure something
 */
#define GPIO0_IRQSTATUS_0_ADDR	0x44E0702C
#define GPIO0_IRQSTATUS_1_ADDR	0x44E07030
#define GPIO0_19_SET_BIT_ACK	0x00080000

#define RTC_WAIT_FOR_INTERRUPTS     _IOW('p', 0x15, unsigned char)
#define RTC_WAIT_FOR_ANY_INTERRUPT  _IOR('p', 0x16, unsigned char)
#define RTC_CLEAR_INTERRUPT_FLAGS   _IOW('p', 0x17, unsigned char)

#define WATCHDOG_TIMEOUT	60
#define TAMPER_LEVEL		1
#define VOLTAGE_THRE		0
#define WDT_ENABLE		0
#define WAKE_ENABLE		1
#define INT_BATT_DEF		"INTA"
#define INT_WDT_DEF		"NO_INTERRUPT"
#define INT_TST_DEF		"INTB"
#define INT_APM_DEF		"INTAPM_INTA"
#define TSPM_DEF		"TSPM_INPUT_MODE"

static int timeout = WATCHDOG_TIMEOUT;
module_param(timeout, int, 0);
MODULE_PARM_DESC(timeout,
		 "Watchdog timeout in seconds. (1<=timeout<=124, default="
		 __MODULE_STRING(WATCHDOG_TIMEOUT) ")");

static bool nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, bool, 0);
MODULE_PARM_DESC(nowayout,
		 "Watchdog cannot be stopped once started (default="
		 __MODULE_STRING(WATCHDOG_NOWAYOUT) ")");

static bool tsl = TAMPER_LEVEL;
module_param(tsl, bool, 0);
MODULE_PARM_DESC(tsl,
		 "Tamper level, 0 low, 1 high (default="
		 __MODULE_STRING(TAMPER_LEVEL) ")");

static bool vth = VOLTAGE_THRE;
module_param(vth, bool, 0);
MODULE_PARM_DESC(vth,
		 "Voltage threshold level, 0 -> 1.5V, 1 -> 2.8V (default="
		 __MODULE_STRING(VOLTAGE_THRE) ")");

static bool wdten = WDT_ENABLE;
module_param(wdten, bool, 0);
MODULE_PARM_DESC(wdten,
		 "Watchdog timer enable, 0 disabled, 1 enabled (default="
		 __MODULE_STRING(WDT_ENABLE) ")");

static bool wakeen = WAKE_ENABLE;
module_param(wakeen, bool, 0);
MODULE_PARM_DESC(wakeen,
		 "Wakeup function enable, 0 disabled, 1 enabled (default="
		 __MODULE_STRING(WAKE_ENABLE) ")");

static char *int_batt = INT_BATT_DEF;
module_param(int_batt, charp, 0);
MODULE_PARM_DESC(int_batt,
		 "Battery connection configuration, INTA, INTB, NO_INTERRUPT (default="
		 __MODULE_STRING(INT_BATT_DEF) ")");

static char *int_wdt = INT_WDT_DEF;
module_param(int_wdt, charp, 0);
MODULE_PARM_DESC(int_wdt,
		 "Watchdog connection configuration, INTA, INTB, NO_INTERRUPT (default="
		 __MODULE_STRING(INT_WDT_DEF) ")");

static char *int_tst = INT_TST_DEF;
module_param(int_tst, charp, 0);
MODULE_PARM_DESC(int_tst,
		 "Timestamp connection configuration, INTA, INTB, NO_INTERRUPT (default="
		 __MODULE_STRING(INT_TST_DEF) ")");

static char *intapm_conf = INT_APM_DEF;
module_param(intapm_conf, charp, 0);
MODULE_PARM_DESC(intapm_conf,
		 "INTA Pin mode, INTAPM_CLK_OUTPUT, INTAPM_BATTERY_MODE_INDICATION, INTAPM_INTA, INTAPM_HIGH_IMPEDANCE (default="
		 __MODULE_STRING(INT_APM_DEF) ")");

static char *tspm = TSPM_DEF;
module_param(tspm, charp, 0);
MODULE_PARM_DESC(tspm,
		 "Timestamp pin mode, TSPM_DISABLED, TSPM_INT, TSPM_CLK_OUTPUT, TSPM_INPUT_MODE (default="
		 __MODULE_STRING(TSPM_DEF) ")");

static struct i2c_driver pcf85263_driver;

struct pcf85263 {
	struct i2c_client *client;
	struct rtc_device *rtc;
	struct mutex mutex;
	int ram_byte_file_created;
	int registers_file_created;
	int resets_file_created;
	int inta_gpio;
	int intb_gpio;
	int inta_irq;
	int intb_irq;
	int interrupt_alarm;
	int clock_frequency;
	int clk_pin;
	int inta_pin;
	int ts_pin;
	int ts_pin_pull;
	int ts_pin_level;
	int ts_pin_input_type;
	int watchdog_timeout;
	int watchdog_disable_on_boot;
	int interrupt_watchdog;
	int flags_file_created;
	int timestamp1_file_created;
	int timestamp2_file_created;
	int timestamp3_file_created;
	int timestamp1_mode;
	int timestamp2_mode;
	int timestamp3_mode;
	int interrupt_timestamp;
	int battery_switch;
	int battery_vth;
	int interrupt_battery;
	wait_queue_head_t event_queue;
	unsigned char event_interrupt;
	struct work_struct work;
	int irq;
};

/*******************************************************************************
 *  Utils
 */
static int pcf85263_read_register(struct i2c_client *client,
				  unsigned char address,
				  unsigned char *value)
{
	int err;

	err = i2c_master_send(client, &address, sizeof(address));
	if (err != sizeof(address))
		return err;
	err = i2c_master_recv(client, value, sizeof(unsigned char));
	if (err != sizeof(unsigned char))
		return err;
	return 0;
}

static int pcf85263_read_registers(struct i2c_client *client,
				   unsigned char address,
				   unsigned char *values, int count)
{
	int err;

	err = i2c_master_send(client, &address, sizeof(address));
	if (err != sizeof(address))
		return err;
	err = i2c_master_recv(client, values, count);
	if (err != count)
		return err;
	return 0;
}

static int pcf85263_write_register(struct i2c_client *client,
				   unsigned char address,
				   unsigned char value)
{
	int err;
	unsigned char data[2] = { address, value };

	err = i2c_master_send(client, data, sizeof(data));
	if (err != sizeof(data))
		return err;
	return 0;
}

static int pcf85263_first_one_index(unsigned char value)
{
	int first_one_index = 0;

	if (value == 0)
		return -EINVAL;
	while ((value & 0x01) == 0) {
		value = value >> 1;
		first_one_index++;
	}
	return first_one_index;
}

/*******************************************************************************
 * Watchdog
 */

static int pcf85263_watchdog_enable(struct i2c_client *client, int enable)
{
	int err = 0;
	unsigned char value;
	struct pcf85263 *pcf85263;

	pcf85263 = i2c_get_clientdata(client);
	if (pcf85263->interrupt_watchdog == INTA) {
		err =
		    pcf85263_read_register(client, REGISTER_INTA_ENABLE,
					   &value);
		if (err)
			return err;
		value &= ~WDIEA;
		value |= (enable ? WDIEA_ENABLE : WDIEA_DISABLE);
		err =
		    pcf85263_write_register(client, REGISTER_INTA_ENABLE,
					    value);
	} else if (pcf85263->interrupt_watchdog == INTB) {
		err =
		    pcf85263_read_register(client, REGISTER_INTB_ENABLE,
					   &value);
		if (err)
			return err;
		value &= ~WDIEB;
		value |= (enable ? WDIEB_ENABLE : WDIEB_DISABLE);
		err =
		    pcf85263_write_register(client, REGISTER_INTB_ENABLE,
					    value);
	} else {
		dev_dbg(&client->dev, "[%s] no interrupt registered\n",
			__func__);
	}
	return err;
}

static int pcf85263_watchdog_compute_seconds(int *seconds,
					     unsigned char *_wdr_value,
					     unsigned char *_wds_value)
{
	unsigned char wdr_value, wds_value;

	/* WatchDog-duration = WDR x stepsize */
	if (*seconds > 120) {
		wdr_value = 31;
		wds_value = WDS_4_SECONDS;
	} else if (*seconds > 31) {
		wdr_value = (unsigned char)(*seconds / 4);
		if (((int)wdr_value * 4) != *seconds)
			wdr_value++;
		wds_value = WDS_4_SECONDS;
	} else if (*seconds >= 0) {
		wdr_value = (unsigned char)*seconds;
		wds_value = WDS_1_SECOND;
	} else {
		return -EINVAL;
	}
	if (wds_value == WDS_4_SECONDS)
		*seconds = (int)wdr_value * 4;
	else
		*seconds = wdr_value;
	if (_wdr_value)
		*_wdr_value = wdr_value;

	if (_wds_value)
		*_wds_value = wds_value;
	return 0;
}

static int pcf85263_watchdog_set_time(struct i2c_client *client,
				      int *seconds)
{
	int err;
	unsigned char wdr_value, wds_value, value;
	struct pcf85263 *pcf85263;

	dev_dbg(&client->dev, "[%s] [input] seconds = %d\n", __func__,
		*seconds);
	pcf85263 = i2c_get_clientdata(client);
	err =
	    pcf85263_watchdog_compute_seconds(seconds, &wdr_value,
					      &wds_value);
	if (err) {
		dev_dbg(&client->dev,
			"[%s] problems while computing actual timeout\n",
			__func__);
		return err;
	}
	err = pcf85263_read_register(client, REGISTER_WATCHDOG, &value);
	if (err)
		return err;
	value &= ~WDR;
	value |= (wdr_value << pcf85263_first_one_index(WDR));
	value &= ~WDS;
	value |= (wds_value << pcf85263_first_one_index(WDS));
	err = pcf85263_write_register(client, REGISTER_WATCHDOG, value);
	if (err)
		return err;
	dev_dbg(&client->dev, "[%s] [output] seconds = %d\n", __func__,
		*seconds);
	return 0;
}

static int pcf85263_watchdog_get_current_time(struct i2c_client *client,
					      int *seconds)
{
	int err = 0;
	unsigned char wdr_value, wds_value, value;
	struct pcf85263 *pcf85263;

	pcf85263 = i2c_get_clientdata(client);
	err = pcf85263_read_register(client, REGISTER_WATCHDOG, &value);
	if (err)
		return err;
	wdr_value = (value & WDR) >> pcf85263_first_one_index(WDR);
	wds_value = (value & WDS) >> pcf85263_first_one_index(WDS);
	if (wds_value == WDS_4_SECONDS)
		*seconds = wdr_value * 4;
	else if (wds_value == WDS_1_SECOND)
		*seconds = wdr_value;
	else
		err = -EILSEQ;

	return err;
}

static int pcf85263_watchdog_ping(struct i2c_client *client)
{
	struct pcf85263 *pcf85263 = i2c_get_clientdata(client);

	return pcf85263_watchdog_set_time(client,
					  &pcf85263->watchdog_timeout);
}

/*
 * Watchdog subsystem
 */
static int pcf85263_watchdog_start_op(struct watchdog_device *device)
{
	int err;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = watchdog_get_drvdata(device);
	pcf85263 = i2c_get_clientdata(client);

	mutex_lock(&pcf85263->mutex);
	err =
	    pcf85263_watchdog_set_time(client,
				       &pcf85263->watchdog_timeout);
	if (err)
		goto exit;
	err = pcf85263_watchdog_enable(client, 1);
exit:
	mutex_unlock(&pcf85263->mutex);
	return err;
}

static int pcf85263_watchdog_stop_op(struct watchdog_device *device)
{
	int err, seconds = 0;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = watchdog_get_drvdata(device);
	pcf85263 = i2c_get_clientdata(client);

	mutex_lock(&pcf85263->mutex);
	err = pcf85263_watchdog_enable(client, 0);
	if (err)
		goto exit;
	err = pcf85263_watchdog_set_time(client, &seconds);
exit:
	mutex_unlock(&pcf85263->mutex);
	return err;
}

static int pcf85263_watchdog_ping_op(struct watchdog_device *device)
{
	int err;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = watchdog_get_drvdata(device);
	pcf85263 = i2c_get_clientdata(client);
	mutex_lock(&pcf85263->mutex);
	err = pcf85263_watchdog_ping(client);
	mutex_unlock(&pcf85263->mutex);
	return err;
}

static int pcf85263_watchdog_set_timeout_op(struct watchdog_device *device,
					    unsigned int timeout)
{
	int seconds, err;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = watchdog_get_drvdata(device);
	pcf85263 = i2c_get_clientdata(client);
	seconds = (int)timeout;
	mutex_lock(&pcf85263->mutex);
	err = pcf85263_watchdog_compute_seconds(&seconds, NULL, NULL);
	if (!err) {
		device->timeout = (unsigned int)seconds;
		pcf85263->watchdog_timeout = seconds;
	}
	mutex_unlock(&pcf85263->mutex);
	return 0;
}

static unsigned int pcf85263_watchdog_get_timeleft_op(struct
						      watchdog_device
						      * device)
{
	int err, seconds = 0;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = watchdog_get_drvdata(device);
	pcf85263 = i2c_get_clientdata(client);
	mutex_lock(&pcf85263->mutex);
	err = pcf85263_watchdog_get_current_time(client, &seconds);
	mutex_unlock(&pcf85263->mutex);
	return (unsigned int)seconds;
}

static struct watchdog_info pcf85263_watchdog_info = {
	.options =
	    WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING | WDIOF_MAGICCLOSE,
	.identity = "PCF85263 Watchdog",
};

static struct watchdog_ops pcf85263_watchdog_ops = {
	.owner = THIS_MODULE,
	.start = pcf85263_watchdog_start_op,
	.stop = pcf85263_watchdog_stop_op,
	.ping = pcf85263_watchdog_ping_op,
	.set_timeout = pcf85263_watchdog_set_timeout_op,
	.get_timeleft = pcf85263_watchdog_get_timeleft_op,
};

static struct watchdog_device pcf85263_watchdog_device = {
	.info = &pcf85263_watchdog_info,
	.ops = &pcf85263_watchdog_ops,
	.timeout = WATCHDOG_TIMEOUT,
	.min_timeout = 1,
	.max_timeout = 124,
};

/*******************************************************************************
 * Timestamps
 */
static int pcf85263_read_timestamp(struct device *dev, int tsr_number,
				   int *seconds, int *minutes, int *hours,
				   int *days, int *months, int *years)
{
	int err;
	unsigned char tsr_register, values[6];
	struct i2c_client *client = to_i2c_client(dev);

	if (tsr_number < 1 || tsr_number > 3)
		return -EINVAL;
	if (tsr_number == 1)
		tsr_register = REGISTER_TSR1_SECONDS;
	else if (tsr_number == 2)
		tsr_register = REGISTER_TSR2_SECONDS;
	else
		tsr_register = REGISTER_TSR3_SECONDS;
	err =
	    pcf85263_read_registers(client, tsr_register, values,
				    sizeof(values));
	if (err)
		return err;
	*seconds = bcd2bin(values[0] & SECONDS_BITS);
	*minutes = bcd2bin(values[1] & MINUTES_BITS);
	*hours = bcd2bin(values[2] & HOURS_BITS);
	*days = bcd2bin(values[3] & DAYS_BITS);
	*months = bcd2bin(values[4] & MONTHS_BITS);
	*years = bcd2bin(values[5] & YEARS_BITS) + 2000;
	return 0;
}

static ssize_t pcf85263_timestamp_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buf, int tsr_number)
{
	int err, seconds = 0, minutes = 0, hours = 0, days = 0, months = 0,
	    years = 0;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;
	unsigned char value;
	char *event_message;
	char *no_timestamp_defined = "No timestamp defined";
	char *first_ts_event = "First TS event";
	char *last_ts_event = "Last TS event";
	char *first_switch_to_battery = "First switch to battery";
	char *last_switch_to_battery = "Last switch to battery";
	char *last_switch_to_vdd = "Last switch to Vdd";

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s] timestamp %d\n", __func__, tsr_number);

	mutex_lock(&pcf85263->mutex);
	err =
	    pcf85263_read_timestamp(dev, tsr_number, &seconds, &minutes,
				    &hours, &days, &months, &years);
	if (!err)
		err =
		    pcf85263_read_register(client, REGISTER_TSR_MODE,
					   &value);
	mutex_unlock(&pcf85263->mutex);
	if (err)
		return err;
	if (tsr_number == 1) {
		switch (value & TSR1M) {
		case TSR1M_FIRST_TS_EVENT:
			event_message = first_ts_event;
			break;
		case TSR1M_LAST_TS_EVENT:
			event_message = last_ts_event;
			break;
		default:
			event_message = no_timestamp_defined;
		}
	} else if (tsr_number == 2) {
		switch (value & TSR2M) {
		case TSR2M_FIRST_TS_EVENT:
			event_message = first_ts_event;
			break;
		case TSR2M_LAST_TS_EVENT:
			event_message = last_ts_event;
			break;
		case TSR2M_FIRST_SWITCH_TO_BATTERY:
			event_message = first_switch_to_battery;
			break;
		case TSR2M_LAST_SWITCH_TO_BATTERY:
			event_message = last_switch_to_battery;
			break;
		case TSR2M_LAST_SWITCH_TO_VDD:
			event_message = last_switch_to_vdd;
			break;
		default:
			event_message = no_timestamp_defined;
		}
	} else {
		switch (value & TSR3M) {
		case TSR3M_FIRST_SWITCH_TO_BATTERY:
			event_message = first_switch_to_battery;
			break;
		case TSR3M_LAST_SWITCH_TO_BATTERY:
			event_message = last_switch_to_battery;
			break;
		case TSR3M_LAST_SWITCH_TO_VDD:
			event_message = last_switch_to_vdd;
			break;
		default:
			event_message = no_timestamp_defined;
		}
	}

	if (days == 0) {
		return sprintf(buf,
			       "yyyy/mm/dd hh:mm:ss Event\n----/--/-- --:--:-- %s\n",
			       event_message);
	} else {
		return sprintf(buf,
			       "yyyy/mm/dd hh:mm:ss Event\n%04d/%02d/%02d %02d:%02d:%02d %s\n",
			       years, months, days, hours, minutes,
			       seconds, event_message);
	}
}

//================================================================================================
static ssize_t pcf85263_flags_show(struct device *dev,
				   struct device_attribute *attr,
				   char *buf)
{
	unsigned char value;
	struct i2c_client *client;

	client = to_i2c_client(dev);

	if (pcf85263_read_register(client, REGISTER_FLAGS, &value) == 0)
		return sprintf(buf, "%d\n", value);

	return -1;
}

static ssize_t pcf85263_flags_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	int n;
	unsigned char value;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	value = 0;
	for (n = 0; n < count; n++) {
		if ((*buf >= '0') && (*buf <= '9'))
			value = (value * 10) + (*buf++ - '0');
	}

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
	if (value != 0) {
		mutex_lock(&pcf85263->mutex);
		if (pcf85263_write_register(client, REGISTER_FLAGS, value ^ 0xff) == 0) {
			mutex_unlock(&pcf85263->mutex);
			return count;
		}
		mutex_unlock(&pcf85263->mutex);
	}
	return -1;
}

static const struct device_attribute pcf85263_flags_attribute = {
	.attr.name	= "flags",
	.attr.mode	= 0600,
	.show		= pcf85263_flags_show,
	.store		= pcf85263_flags_store,
};

static ssize_t pcf85263_timestamp1_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	return pcf85263_timestamp_show(dev, attr, buf, 1);
}

static const struct device_attribute pcf85263_timestamp1_attribute = {
	.attr.name	= "timestamp1",
	.attr.mode	= 0400,
	.show		= pcf85263_timestamp1_show,
};

static ssize_t pcf85263_timestamp2_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	return pcf85263_timestamp_show(dev, attr, buf, 2);
}

static const struct device_attribute pcf85263_timestamp2_attribute = {
	.attr.name = "timestamp2",
	.attr.mode = 0400,
	.show = pcf85263_timestamp2_show,
};

static ssize_t pcf85263_timestamp3_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	return pcf85263_timestamp_show(dev, attr, buf, 3);
}

static const struct device_attribute pcf85263_timestamp3_attribute = {
	.attr.name = "timestamp3",
	.attr.mode = 0400,
	.show = pcf85263_timestamp3_show,

};

/*******************************************************************************
 * Resets
 */
static ssize_t pcf85263_resets_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	return sprintf(buf, "software prescaler timestamps\n");
}

static ssize_t pcf85263_resets_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	int err = 0;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;
	char buffer[11];
	size_t chars_count;

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
	if (count < 8 || count > 11 || (count == 11 && buf[count - 1] != '\n'))
		return -EINVAL;

	chars_count = count;
	if (buf[count - 1] == '\n')
		chars_count--;
	memcpy(buffer, buf, chars_count);
	buffer[chars_count] = '\0';
	mutex_lock(&pcf85263->mutex);
	if (strcmp(buffer, "software") == 0) {
		err =
		    pcf85263_write_register(client, REGISTER_RESETS,
					    SR_CMD);
	} else if (strcmp(buffer, "prescaler") == 0) {
		err =
		    pcf85263_write_register(client, REGISTER_RESETS,
					    CPR_CMD);
	} else if (strcmp(buffer, "timestamps") == 0) {
		err =
		    pcf85263_write_register(client, REGISTER_RESETS,
					    CTS_CMD);
	} else {
		err = -EINVAL;
	}
	mutex_unlock(&pcf85263->mutex);
	if (err)
		return err;
	return count;
}

static const struct device_attribute pcf85263_resets_attribute = {
	.attr.name = "resets",
	.attr.mode = S_IRUSR | S_IWUSR,
	.show = pcf85263_resets_show,
	.store = pcf85263_resets_store,
};

/*******************************************************************************
 * RTC
 */
static int pcf85263_rtc_read_time(struct device *dev, struct rtc_time *tm)
{
	int err;
	unsigned char data[8];
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);

	mutex_lock(&pcf85263->mutex);
	err =
	    pcf85263_read_registers(client, REGISTER_CENTS_OF_SECOND, data,
				    sizeof(data));
	mutex_unlock(&pcf85263->mutex);
	if (err)
		return err;
	tm->tm_sec = bcd2bin(data[REGISTER_SECONDS] & SECONDS_BITS);
	tm->tm_min = bcd2bin(data[REGISTER_MINUTES] & MINUTES_BITS);
	tm->tm_hour = bcd2bin(data[REGISTER_HOURS] & HOURS_BITS);
	tm->tm_mday = bcd2bin(data[REGISTER_DAYS] & DAYS_BITS);
	tm->tm_mon = bcd2bin(data[REGISTER_MONTHS] & MONTHS_BITS) - 1;
	tm->tm_year = bcd2bin(data[REGISTER_YEARS] & YEARS_BITS) + 100;
	tm->tm_wday = bcd2bin(data[REGISTER_WEEKDAYS] & WEEKDAYS_BITS);
	tm->tm_yday = rtc_year_days(tm->tm_mday, tm->tm_mon, tm->tm_year);
	/* Daylight Saving Time */
	tm->tm_isdst = -1;
	if (rtc_valid_tm(tm) < 0)
		dev_err(dev, "retrieved date/time is not valid.\n");
	return 0;
}

static int pcf85263_rtc_set_time(struct device *dev, struct rtc_time *tm)
{
	int err;
	unsigned char data[11];
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
	if (tm->tm_year < 100)
		return -EINVAL;
	data[0] = REGISTER_STOP_ENABLE;
	data[1] = STOP_RTC_STOPPED;
	data[2] = CPR_CMD;
	data[3] = 0;		// cents of second
	data[4] = bin2bcd(tm->tm_sec); // this will clear OS bit as well,
	// which makes the oscillator start
	// if it was stopped
	data[5] = bin2bcd(tm->tm_min);
	data[6] = bin2bcd(tm->tm_hour);
	data[7] = bin2bcd(tm->tm_mday);
	data[8] = bin2bcd(tm->tm_wday);
	data[9] = bin2bcd(tm->tm_mon + 1);
	data[10] = bin2bcd(tm->tm_year - 100);
	mutex_lock(&pcf85263->mutex);
	err = i2c_master_send(client, data, sizeof(data));
	if (err != sizeof(data))
		err = -EIO;
	else
		err =
		    pcf85263_write_register(client, REGISTER_STOP_ENABLE,
					    STOP_RTC_RUN);
	mutex_unlock(&pcf85263->mutex);
	return err;
}

/*******************************************************************************
 * Alarm
 */

static int pcf85263_rtc_alarm_irq_enable(struct device *dev,
					 unsigned int enabled)
{
	int err = 0;
	unsigned char value;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "[%s] enabled = %u\n", __func__, enabled);
	mutex_lock(&pcf85263->mutex);
	if (pcf85263->interrupt_alarm != NO_INTERRUPT) {
		/* enable/disable alarm1 */
		if (pcf85263_read_register
		    (client, REGISTER_ALARM_ENABLES, &value))
			goto exit;
		if (enabled)
			value = (value & ~(ALARM1_BITS)) | ALARM1_ENABLE;
		else
			value = (value & ~(ALARM1_BITS)) | ALARM1_DISABLE;
		if (pcf85263_write_register
		    (client, REGISTER_ALARM_ENABLES, value))
			goto exit;
		/* enabled/disable irq for alarm1 */
		if (pcf85263->interrupt_alarm == INTA) {
			if (pcf85263_read_register
			    (client, REGISTER_INTA_ENABLE, &value))
				goto exit;
			value &= ~A1IEA;
			value |= (enabled ? A1IEA_ENABLE : A1IEA_DISABLE);
			value &= ~ILPA;
			value |= ILPA_PERMANENT_SIGNAL;
			if (pcf85263_write_register
			    (client, REGISTER_INTA_ENABLE, value))
				goto exit;
		} else {
			if (pcf85263_read_register
			    (client, REGISTER_INTB_ENABLE, &value))
				goto exit;
			value &= ~A1IEB;
			value |= (enabled ? A1IEB_ENABLE : A1IEB_DISABLE);
			value &= ~ILPB;
			value |= ILPB_PERMANENT_SIGNAL;
			if (pcf85263_write_register
			    (client, REGISTER_INTB_ENABLE, value))
				goto exit;
		}
		/* clean up interrupt flag when disabling */
		if (!enabled) {
			if (pcf85263_read_register
			    (client, REGISTER_FLAGS, &value))
				goto exit;
			value =
			    (value & ~(ALARM1_FLAG)) | ALARM1_FLAG_CLEAR;
			if (pcf85263_write_register
			    (client, REGISTER_FLAGS, value))
				goto exit;
		}
	}
exit:
	mutex_unlock(&pcf85263->mutex);
	return err;
}

static int pcf85263_rtc_read_alarm(struct device *dev,
				   struct rtc_wkalrm *alarm)
{
	int err;
	unsigned char data[5];
	unsigned char value;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
	mutex_lock(&pcf85263->mutex);
	err = pcf85263_read_registers(client, REGISTER_SECOND_ALARM1, data,
				      sizeof(data));
	if (err)
		goto exit;
	alarm->time.tm_sec = bcd2bin(data[0] & SECONDS_BITS);
	alarm->time.tm_min = bcd2bin(data[1] & MINUTES_BITS);
	alarm->time.tm_hour = bcd2bin(data[2] & HOURS_BITS);
	alarm->time.tm_mday = bcd2bin(data[3] & DAYS_BITS);
	alarm->time.tm_mon = bcd2bin(data[4] & MONTHS_BITS) - 1;
	err =
	    pcf85263_read_register(client, REGISTER_ALARM_ENABLES, &value);
	if (err)
		goto exit;
	alarm->enabled = ((value & ALARM1_BITS) == ALARM1_ENABLE) ?
	    ALARM_ENABLED : ALARM_DISABLED;
exit:
	mutex_unlock(&pcf85263->mutex);
	return err;
}

static int pcf85263_rtc_set_alarm(struct device *dev,
				  struct rtc_wkalrm *alarm)
{
	int err;
	unsigned char data[6];
	unsigned char value;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
	data[0] = REGISTER_SECOND_ALARM1;
	data[1] = bin2bcd(alarm->time.tm_sec);
	data[2] = bin2bcd(alarm->time.tm_min);
	data[3] = bin2bcd(alarm->time.tm_hour);
	data[4] = bin2bcd(alarm->time.tm_mday);
	data[5] = bin2bcd(alarm->time.tm_mon + 1);
	mutex_lock(&pcf85263->mutex);
	err = i2c_master_send(client, data, sizeof(data));
	if (err != sizeof(data)) {
		err = -EIO;
		goto exit;
	}
	if (alarm->enabled) {
		err =
		    pcf85263_write_register(client, REGISTER_ALARM_ENABLES,
					    ALARM1_ENABLE |
					    ALARM2_DISABLE);
	} else {
		err =
		    pcf85263_write_register(client, REGISTER_ALARM_ENABLES,
					    ALARM1_DISABLE |
					    ALARM2_DISABLE);
	}
	if (err)
		goto exit;

	/* enabled/disable irq for alarm1 */
	if (pcf85263->interrupt_alarm == INTA) {
		if (pcf85263_read_register
		    (client, REGISTER_INTA_ENABLE, &value))
			goto exit;
		value &= ~A1IEA;
		value |= (alarm->enabled ? A1IEA_ENABLE : A1IEA_DISABLE);
		value &= ~ILPA;
		value |= ILPA_PERMANENT_SIGNAL;
		if (pcf85263_write_register
		    (client, REGISTER_INTA_ENABLE, value))
			goto exit;
	} else if (pcf85263->interrupt_alarm == INTB) {
		if (pcf85263_read_register
		    (client, REGISTER_INTB_ENABLE, &value))
			goto exit;
		value &= ~A1IEB;
		value |= (alarm->enabled ? A1IEB_ENABLE : A1IEB_DISABLE);
		value &= ~ILPB;
		value |= ILPB_PERMANENT_SIGNAL;
		if (pcf85263_write_register
		    (client, REGISTER_INTB_ENABLE, value))
			goto exit;
	}
	/* clean up interrupt flag when disabling */
	if (!alarm->enabled) {
		if (pcf85263_read_register(client, REGISTER_FLAGS, &value))
			goto exit;
		value = (value & ~(ALARM1_FLAG)) | ALARM1_FLAG_CLEAR;
		if (pcf85263_write_register(client, REGISTER_FLAGS, value))
			goto exit;
	}

exit:
	mutex_unlock(&pcf85263->mutex);
	return err;
}

static int pcf85263_rtc_ioctl(struct device *dev,
			      unsigned int cmd, unsigned long arg)
{
	int ret;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;
	unsigned char user_value;

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
	switch (cmd) {
	case RTC_WAIT_FOR_INTERRUPTS:
		if (copy_from_user
		    (&user_value, (unsigned char __user *)arg,
		     sizeof(unsigned char)))
			return -EFAULT;
		ret = wait_event_interruptible(pcf85263->event_queue,
					       ((user_value &
						 pcf85263->event_interrupt)
						== user_value));
		if (ret)
			return -ERESTARTSYS;
		mutex_lock(&pcf85263->mutex);
		pcf85263->event_interrupt &= ~user_value;
		mutex_unlock(&pcf85263->mutex);
		return 0;
	case RTC_WAIT_FOR_ANY_INTERRUPT:
		ret = wait_event_interruptible(pcf85263->event_queue,
					       (pcf85263->event_interrupt
						!= 0));
		if (ret)
			return -ERESTARTSYS;
		mutex_lock(&pcf85263->mutex);
		user_value = pcf85263->event_interrupt;
		pcf85263->event_interrupt = 0;
		mutex_unlock(&pcf85263->mutex);
		if (copy_to_user((unsigned char __user *)arg, &user_value,
				 sizeof(unsigned char)))
			return -EFAULT;
		return 0;
	case RTC_CLEAR_INTERRUPT_FLAGS:
		if (copy_from_user
		    (&user_value, (unsigned char __user *)arg,
		     sizeof(unsigned char)))
			return -EFAULT;
		mutex_lock(&pcf85263->mutex);
		pcf85263->event_interrupt &= ~user_value;
		mutex_unlock(&pcf85263->mutex);
		return 0;
	default:
		return -ENOIOCTLCMD;
	}
}

static const struct rtc_class_ops pcf85263_rtc_ops = {
	/* RTC callbacks */
	.set_time = pcf85263_rtc_set_time,
	.read_time = pcf85263_rtc_read_time,
	/* alarm callbacks */
	.set_alarm = pcf85263_rtc_set_alarm,
	.read_alarm = pcf85263_rtc_read_alarm,
	.alarm_irq_enable = pcf85263_rtc_alarm_irq_enable,
	/* custom APIs */
	.ioctl = pcf85263_rtc_ioctl,
};

/*******************************************************************************
 * RAM byte
 */
static ssize_t pcf85263_ram_byte_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buf)
{
	int err;
	unsigned char ram_byte;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
	mutex_lock(&pcf85263->mutex);
	err = pcf85263_read_register(client, REGISTER_RAM_BYTE, &ram_byte);
	mutex_unlock(&pcf85263->mutex);
	if (err)
		return err;
	return sprintf(buf, "%hhu\n", ram_byte);
}

static ssize_t pcf85263_ram_byte_store(struct device *dev,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	int err;
	unsigned char ram_byte;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
	err = kstrtou8(buf, 10, &ram_byte);
	if (err)
		return err;
	mutex_lock(&pcf85263->mutex);
	err = pcf85263_write_register(client, REGISTER_RAM_BYTE, ram_byte);
	mutex_unlock(&pcf85263->mutex);
	if (err)
		return err;
	return count;
}

static const struct device_attribute pcf85263_ram_byte_device_attribute = {
	.attr.name = "ram_byte",
	.attr.mode = S_IRUSR | S_IWUSR,
	.show = pcf85263_ram_byte_show,
	.store = pcf85263_ram_byte_store,
};

/*******************************************************************************
 * REGISTERS utility
 */
static ssize_t pcf85263_registers_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	int err;
	unsigned char i, data[48];
	size_t printed_chars = 0;
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
	mutex_lock(&pcf85263->mutex);
	err = pcf85263_read_registers(client, REGISTER_CENTS_OF_SECOND,
				      data, sizeof(data));
	mutex_unlock(&pcf85263->mutex);
	if (err)
		return err;
	err = sprintf(buf, "Reg  Val\n");
	if (err < 0)
		return err;
	printed_chars += err;
	for (i = 0; i < sizeof(data); i++) {
		err =
		    sprintf(&buf[printed_chars], "0x%02hhx 0x%02hhx\n", i,
			    data[i]);
		if (err < 0)
			return err;
		printed_chars += err;
	}
	return printed_chars;
}

static ssize_t pcf85263_registers_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	int err;
	unsigned char address, value;
	char address_string[3], value_string[3];
	struct i2c_client *client;
	struct pcf85263 *pcf85263;

	client = to_i2c_client(dev);
	pcf85263 = i2c_get_clientdata(client);
#define is_hexadecimal(x)       ((x >= '0' && x <= '9') || \
				(x >= 'a' && x <= 'f') || \
				(x >= 'A' && x <= 'F'))
	if (count != 10)
		return -EINVAL;
	if (!(buf[0] == '0' && (buf[1] == 'x' || buf[1] == 'X') &&
	    buf[5] == '0' && (buf[6] == 'x' || buf[6] == 'X') &&
	    is_hexadecimal(buf[2]) &&
	    is_hexadecimal(buf[3]) &&
	    is_hexadecimal(buf[7]) && is_hexadecimal(buf[8])))
		return -EINVAL;
	address_string[0] = buf[2];
	address_string[1] = buf[3];
	address_string[2] = '\0';
	value_string[0] = buf[7];
	value_string[1] = buf[8];
	value_string[2] = '\0';
	err = kstrtou8(address_string, 16, &address);
	if (err)
		return err;
	err = kstrtou8(value_string, 16, &value);
	if (err)
		return err;
	if (address > REGISTER_RESETS)
		return -EINVAL;
	mutex_lock(&pcf85263->mutex);
	err = pcf85263_write_register(client, address, value);
	mutex_unlock(&pcf85263->mutex);
	if (err)
		return err;
	return count;
}

static const struct device_attribute pcf85263_registers_device_attribute = {
	.attr.name = "registers",
	.attr.mode = S_IRUSR | S_IWUSR,
	.show = pcf85263_registers_show,
	.store = pcf85263_registers_store,
};

/*******************************************************************************
 * HW initialization
 */
static int pcf85263_init(struct i2c_client *client)
{
	int err;
	unsigned char value;
	struct pcf85263 *pcf85263;

	pcf85263 = i2c_get_clientdata(client);
	/*
	 * Start the OSC if required. This operation can tamper with time.
	 */
	err = pcf85263_read_register(client, REGISTER_SECONDS, &value);
	if (err)
		return err;

	// We should only write to this register if the OS bit is high otherwise we risk the
	// SECONDS changing between the read and the write which will cause us to lose a second.
	if (value & OS_SET) {
		//If the OS bit is high, clear the bit to start the Oscillator
		value &= ~OS;

		err = pcf85263_write_register(client, REGISTER_SECONDS, value);
		if (err)
			return err;
	}

	/*
	 * Initializing function register
	 */
	err = pcf85263_read_register(client, REGISTER_FUNCTION, &value);
	if (err)
		return err;
	/* We don't support stop-watch mode, setting RTC mode. */
	value &= ~RTCM;
	value |= RTCM_RTC_MODE;
	value &= ~COF;
	value |= (unsigned char)pcf85263->clock_frequency;
	err = pcf85263_write_register(client, REGISTER_FUNCTION, value);
	if (err)
		return err;

	/*
	 * We don't support 12 hour mode, setting 24 hour mode.
	 */
	err = pcf85263_read_register(client, REGISTER_OSCILLATOR, &value);
	if (err)
		return err;
	value &= ~AMPM_12_24;
	value |= AMPM_24_HOUR_MODE;
	value &= ~XTAL_CAP_LOAD;
	value |= XTAL_CAP_12_5_pf;	//We use a 12.5pF load capacitance
	err = pcf85263_write_register(client, REGISTER_OSCILLATOR, value);
	if (err)
		return err;

	/*
	 * Initializing battery switch register
	 */
	err =
	    pcf85263_read_register(client, REGISTER_BATTERY_SWITCH,
				   &value);
	if (err)
		return err;
	value &= ~BSRR;
	value |= BSRR_LOW;
	value &= ~BSOFF;
	if (pcf85263->battery_switch == BATTERY_SWITCH_OFF) {
		value |= BSOFF_DISABLE;
	} else {
		value |= BSOFF_ENABLE;
		value &= ~BSM;
		if (pcf85263->battery_switch == BATTERY_SWITCH_VTH)
			value |= BSM_VTH;
		else if (pcf85263->battery_switch == BATTERY_SWITCH_VBAT)
			value |= BSM_VBAT;
		else if (pcf85263->battery_switch == BATTERY_SWITCH_HIGHER)
			value |= BSM_HIGHER;
		else
			value |= BSM_LOWER;
		value &= ~BSTH;
		if (pcf85263->battery_vth == BATTERY_VTH_1_5)
			value |= BSTH_1_5;
		else
			value |= BSTH_2_8;
	}
	err = pcf85263_write_register(client, REGISTER_BATTERY_SWITCH, value);
	if (err)
		return err;

	/*
	 * Timestamps initialization
	 */
	err = pcf85263_read_register(client, REGISTER_TSR_MODE, &value);
	if (err)
		return err;
	value &= ~TSR1M;
	value |= (unsigned char)pcf85263->timestamp1_mode;
	value &= ~TSR2M;
	value |= (unsigned char)pcf85263->timestamp2_mode;
	value &= ~TSR3M;
	value |= (unsigned char)pcf85263->timestamp3_mode;
	err = pcf85263_write_register(client, REGISTER_TSR_MODE, value);
	if (err)
		return err;

	/*
	 * INTA enable register initialization
	 */
	err = pcf85263_read_register(client, REGISTER_INTA_ENABLE, &value);
	if (err)
		return err;
	if (pcf85263->watchdog_disable_on_boot) {
		dev_info(&client->dev, "disabling watchdog interrupt\n");
		value &= ~WDIEA;
		value |= WDIEA_DISABLE;
	}
	value &= ~BSIEA;
	if (pcf85263->interrupt_battery == INTA)
		value |= BSIEA_ENABLE;
	else
		value |= BSIEA_DISABLE;
	value &= ~TSRIEA;
	if (pcf85263->interrupt_timestamp == INTA)
		value |= TSRIEA_ENABLE;
	else
		value |= TSRIEA_DISABLE;
	err = pcf85263_write_register(client, REGISTER_INTA_ENABLE, value);
	if (err)
		return err;

	/*
	 * INTB enable register initialization
	 */
	err = pcf85263_read_register(client, REGISTER_INTB_ENABLE, &value);
	if (err)
		return err;
	if (pcf85263->watchdog_disable_on_boot) {
		value &= ~WDIEB;
		value |= WDIEB_DISABLE;
	}
	value &= ~BSIEB;
	if (pcf85263->interrupt_battery == INTB)
		value |= BSIEB_ENABLE;
	else
		value |= BSIEB_DISABLE;
	value &= ~TSRIEB;
	if (pcf85263->interrupt_timestamp == INTB)
		value |= TSRIEB_ENABLE;
	else
		value |= TSRIEB_DISABLE;
	err = pcf85263_write_register(client, REGISTER_INTB_ENABLE, value);
	if (err)
		return err;

	/*
	 * Watchdog register initialization
	 */
	err = pcf85263_read_register(client, REGISTER_WATCHDOG, &value);
	if (err)
		return err;
	value &= ~WDM;
	value |= WDM_SINGLE_SHOT;
	err = pcf85263_write_register(client, REGISTER_WATCHDOG, value);
	if (err)
		return err;

	/*
	 * Initializing Pin I/O
	 */
	err = pcf85263_read_register(client, REGISTER_PIN_IO, &value);
	if (err)
		return err;
	/* CLKPM */
	value &= ~CLKPM;
	value |= (unsigned char)pcf85263->clk_pin;
	/* TSPULL */
	value &= ~TSPULL;
	value |= (unsigned char)pcf85263->ts_pin_pull;
	/* TSL */
	value &= ~TSL;
	value |= (unsigned char)pcf85263->ts_pin_level;
	/* TSIM */
	value &= ~TSIM;
	value |= (unsigned char)pcf85263->ts_pin_input_type;
	/* TSPM */
	value &= ~TSPM;
	value |= (unsigned char)pcf85263->ts_pin;
	/* INTAPM */
	value &= ~INTAPM;
	value |= (unsigned char)pcf85263->inta_pin;
	err = pcf85263_write_register(client, REGISTER_PIN_IO, value);
	if (err)
		return err;

// Clear interrupt flags, but leave the time stamp flags
	err = pcf85263_write_register(client, REGISTER_FLAGS, 0x07);

	return err;
}

static void pcf85263_unload(struct i2c_client *client)
{
	struct pcf85263 *pcf85263;
	int err;

	pcf85263 = i2c_get_clientdata(client);
	if (pcf85263->ram_byte_file_created) {
		sysfs_remove_file(&client->dev.kobj,
				  &pcf85263_ram_byte_device_attribute.attr);
	}

	if (pcf85263->flags_file_created) {
		sysfs_remove_file(&client->dev.kobj,
				  &pcf85263_flags_attribute.attr);
	}

	if (pcf85263->registers_file_created) {
		sysfs_remove_file(&client->dev.kobj,
				  &pcf85263_registers_device_attribute.attr);
	}
	if (pcf85263->timestamp1_file_created) {
		sysfs_remove_file(&client->dev.kobj,
				  &pcf85263_timestamp1_attribute.attr);
		pcf85263->timestamp1_file_created = 0;
	}
	if (pcf85263->timestamp2_file_created) {
		sysfs_remove_file(&client->dev.kobj,
				  &pcf85263_timestamp2_attribute.attr);
		pcf85263->timestamp2_file_created = 0;
	}
	if (pcf85263->timestamp3_file_created) {
		sysfs_remove_file(&client->dev.kobj,
				  &pcf85263_timestamp3_attribute.attr);
		pcf85263->timestamp3_file_created = 0;
	}
	if (pcf85263->resets_file_created) {
		sysfs_remove_file(&client->dev.kobj,
				  &pcf85263_resets_attribute.attr);
		pcf85263->resets_file_created = 0;
	}
	if (wdten == 1) {
		dev_dbg(&client->dev, "[%s] watchdog unregister\n",
			__func__);
		watchdog_unregister_device(&pcf85263_watchdog_device);
	}
	dev_dbg(&client->dev, "[%s] pinctrl sleep state\n", __func__);
	pinctrl_pm_select_sleep_state(&client->dev);
	dev_dbg(&client->dev, "[%s] devm_kfree\n", __func__);
	err = device_init_wakeup(&client->dev, false);
	if (err)
		dev_err(&client->dev, "dev_init_wakeup [%d] FAIL\n", err);
	devm_kfree(&client->dev, pcf85263);
}

/*
 * Driver hooks
 */
static int pcf85263_probe(struct i2c_client *client,
			  const struct i2c_device_id *id)
{
	int err;
	struct pcf85263 *pcf85263;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C))
		return -ENODEV;

	pcf85263 =
	    devm_kzalloc(&client->dev, sizeof(struct pcf85263),
			 GFP_KERNEL);
	if (!pcf85263) {
		dev_dbg(&client->dev,
			"[%s] Impossible to allocate memory\n", __func__);
		return -ENOMEM;
	}
	pcf85263->ram_byte_file_created = 0;
	pcf85263->registers_file_created = 0;
	pcf85263->timestamp1_file_created = 0;
	pcf85263->timestamp2_file_created = 0;
	pcf85263->timestamp3_file_created = 0;
	pcf85263->resets_file_created = 0;
	pcf85263->inta_irq = -1;
	pcf85263->intb_irq = -1;
	pcf85263->battery_switch = BATTERY_SWITCH_OFF;
	pcf85263->battery_vth = BATTERY_VTH_1_5;
	init_waitqueue_head(&pcf85263->event_queue);
	if (timeout < 1 || timeout > 124) {
		dev_dbg(&client->dev,
			"[%s] timeout (= %d) out of bounds ([1,124])\n",
			__func__, timeout);
		timeout = WATCHDOG_TIMEOUT;
	}
	pcf85263->watchdog_timeout = timeout;
	mutex_init(&pcf85263->mutex);

	dev_info(&client->dev,
		 "chip found, driver version " DRIVER_VERSION "\n");

	i2c_set_clientdata(client, pcf85263);
	pcf85263->client = client;
	pcf85263->rtc = devm_rtc_device_register(&client->dev,
						 pcf85263_driver.driver.name,
						 &pcf85263_rtc_ops,
						 THIS_MODULE);
	err = PTR_ERR_OR_ZERO(pcf85263->rtc);
	if (err) {
		dev_err(&client->dev, "unable to register RTC device\n");
		goto exit;
	}

	pcf85263->rtc->uie_unsupported = 1;
	/* RAM byte initialization */
	err = sysfs_create_file(&client->dev.kobj,
				&pcf85263_ram_byte_device_attribute.attr);
	if (err) {
		dev_err(&client->dev,
			"unable to create sysfs file \"%s\"\n",
			pcf85263_ram_byte_device_attribute.attr.name);
		goto exit;
	}
	pcf85263->ram_byte_file_created = 1;

	/* Registers debug initialization */
	err = sysfs_create_file(&client->dev.kobj,
				&pcf85263_registers_device_attribute.attr);
	if (err) {
		dev_err(&client->dev,
			"unable to create sysfs file \"%s\"\n",
			pcf85263_registers_device_attribute.attr.name);
		goto exit;
	}
	pcf85263->registers_file_created = 1;

	/* flags initialization */
	err =
	    sysfs_create_file(&client->dev.kobj,
			      &pcf85263_flags_attribute.attr);
	if (err) {
		dev_err(&client->dev,
			"unable to create sysfs file \"%s\"\n",
			pcf85263_flags_attribute.attr.name);
		goto exit;
	}
	pcf85263->flags_file_created = 1;

	/* Timestamp 1 initialization */
	err = sysfs_create_file(&client->dev.kobj,
				&pcf85263_timestamp1_attribute.attr);
	if (err) {
		dev_err(&client->dev,
			"unable to create sysfs file \"%s\"\n",
			pcf85263_timestamp1_attribute.attr.name);
		goto exit;
	}
	pcf85263->timestamp1_file_created = 1;

	/* Timestamp 2 initialization */
	err = sysfs_create_file(&client->dev.kobj,
				&pcf85263_timestamp2_attribute.attr);
	if (err) {
		dev_err(&client->dev,
			"unable to create sysfs file \"%s\"\n",
			pcf85263_timestamp2_attribute.attr.name);
		goto exit;
	}
	pcf85263->timestamp2_file_created = 1;

	/* Timestamp 3 initialization */
	err = sysfs_create_file(&client->dev.kobj,
				&pcf85263_timestamp3_attribute.attr);
	if (err) {
		dev_err(&client->dev,
			"unable to create sysfs file \"%s\"\n",
			pcf85263_timestamp3_attribute.attr.name);
		goto exit;
	}
	pcf85263->timestamp3_file_created = 1;

	/* Create resets file */
	err = sysfs_create_file(&client->dev.kobj,
				&pcf85263_resets_attribute.attr);
	if (err) {
		dev_err(&client->dev,
			"unable to create sysfs file \"%s\"\n",
			pcf85263_resets_attribute.attr.name);
	}
	pcf85263->resets_file_created = 1;

	/* Battery switch specific device tree properties */
	pcf85263->battery_switch = BATTERY_SWITCH_VTH;
	if (vth == 0)
		pcf85263->battery_vth = BATTERY_VTH_1_5;
	else
		pcf85263->battery_vth = BATTERY_VTH_2_8;
	/* Battery switch interrupt initialization */

	pcf85263->interrupt_battery = INTA;
	if (strcmp(int_batt, "INTA"))
		pcf85263->interrupt_battery = INTA;
	else if (strcmp(int_batt, "INTB"))
		pcf85263->interrupt_battery = INTB;
	else if (strcmp(int_batt, "NO_INTERRUPT"))
		pcf85263->interrupt_battery = NO_INTERRUPT;

	/* Timestamps specific device tree properties setup */
	pcf85263->timestamp1_mode = TSR1M_LAST_TS_EVENT;
	pcf85263->timestamp2_mode = TSR2M_LAST_SWITCH_TO_BATTERY;
	pcf85263->timestamp3_mode = TSR3M_LAST_SWITCH_TO_VDD;
	pcf85263->interrupt_timestamp = INTB;
	if (strcmp(int_tst, "INTA"))
		pcf85263->interrupt_timestamp = INTA;
	else if (strcmp(int_tst, "INTB"))
		pcf85263->interrupt_timestamp = INTB;
	else if (strcmp(int_tst, "NO_INTERRUPT"))
		pcf85263->interrupt_timestamp = NO_INTERRUPT;

	pcf85263->interrupt_watchdog = NO_INTERRUPT;
	if (strcmp(int_wdt, "INTA"))
		pcf85263->interrupt_watchdog = INTA;
	else if (strcmp(int_wdt, "INTB"))
		pcf85263->interrupt_watchdog = INTB;
	else if (strcmp(int_wdt, "NO_INTERRUPT"))
		pcf85263->interrupt_watchdog = NO_INTERRUPT;

	/* INTA pin configuration */

	pcf85263->inta_pin = INTAPM_INTA;
	if (strcmp(intapm_conf, "INTAPM_CLK_OUTPUT"))
		pcf85263->inta_pin = INTA;
	else if (strcmp(intapm_conf, "INTAPM_BATTERY_MODE_INDICATION"))
		pcf85263->inta_pin = INTB;
	else if (strcmp(intapm_conf, "INTAPM_INTA"))
		pcf85263->inta_pin = INTAPM_INTA;
	else if (strcmp(intapm_conf, "INTAPM_HIGH_IMPEDANCE"))
		pcf85263->inta_pin = INTAPM_HIGH_IMPEDANCE;

	pcf85263->ts_pin = TSPM_DISABLED;
	if (strcmp(tspm, "TSPM_DISABLED") == 0)
		pcf85263->ts_pin = TSPM_DISABLED;
	else if (strcmp(tspm, "TSPM_INT") == 0)
		pcf85263->ts_pin = TSPM_INTB;
	else if (strcmp(tspm, "TSPM_CLK_OUTPUT") == 0)
		pcf85263->ts_pin = TSPM_CLK_OUTPUT;
	else if (strcmp(tspm, "TSPM_INPUT_MODE") == 0)
		pcf85263->ts_pin = TSPM_INPUT_MODE;

	pcf85263->clock_frequency = COF_32768;
	pcf85263->clk_pin = CLKPM_ENABLE;

	/* TS pin configuration */
	pcf85263->ts_pin_pull = TSPULL_80_K_OHM;

	if (tsl == 0)
		pcf85263->ts_pin_level = TSL_ACTIVE_LOW;
	else
		pcf85263->ts_pin_level = TSL_ACTIVE_HIGH;

	pcf85263->ts_pin_input_type = TSIM_MECHANICAL_SWITCH_MODE;
	/* Watchdog specific device tree properties setup */
	pcf85263->watchdog_disable_on_boot = 0;
	/* Init the chip with the desired configuration */
	err = pcf85263_init(client);
	if (err) {
		dev_err(&client->dev, "unable to init RTC device\n");
		goto exit;
	}

	if (pinctrl_pm_select_default_state(&client->dev))
		goto exit;

	if (wakeen == 1) {
		err = device_init_wakeup(&client->dev, true);
		if (err)
			dev_err(&client->dev,
				"dev_init_wakeup [%d] FAIL\n", err);
	}

	if (wdten == 1) {
		watchdog_set_drvdata(&pcf85263_watchdog_device, client);
		watchdog_init_timeout(&pcf85263_watchdog_device,
				      pcf85263->watchdog_timeout, NULL);
		watchdog_set_nowayout(&pcf85263_watchdog_device, nowayout);
		err = watchdog_register_device(&pcf85263_watchdog_device);
		if (err)
			goto exit;
		dev_info(&client->dev, "registered %s as watchdog%d\n",
			 pcf85263_driver.driver.name,
			 pcf85263_watchdog_device.id);
	}
	dev_info(&client->dev, "probe_end, init OK\n");
	return 0;
exit:
	pcf85263_unload(client);
	return err;
}

static int pcf85263_remove(struct i2c_client *client)
{
	pcf85263_unload(client);
	return 0;
}

static const struct i2c_device_id pcf85263_id[] = {
	{"pcf85263", 0},
	{}
};

MODULE_DEVICE_TABLE(i2c, pcf85263_id);

static struct of_device_id pcf85263_of_match[] = {
	{.compatible = "nxp,pcf85263"},
	{}
};

MODULE_DEVICE_TABLE(of, pcf85263_of_match);

#ifdef CONFIG_PM_SLEEP
static int pcf85263_suspend(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct pcf85263 *pcf85263;

	pcf85263 = i2c_get_clientdata(client);

	if (pcf85263->inta_irq >= 0 && device_may_wakeup(&client->dev))
		enable_irq_wake(pcf85263->inta_irq);

	return 0;
}

static int pcf85263_resume(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct pcf85263 *pcf85263;
	void __iomem *reg0 = ioremap(GPIO0_IRQSTATUS_0_ADDR, 4);
	void __iomem *reg1 = ioremap(GPIO0_IRQSTATUS_1_ADDR, 4);

	pcf85263 = i2c_get_clientdata(client);

	if (pcf85263->inta_irq >= 0 && device_may_wakeup(&client->dev)) {
		disable_irq_wake(pcf85263->inta_irq);
		writel(GPIO0_19_SET_BIT_ACK, reg0);
		writel(GPIO0_19_SET_BIT_ACK, reg1);
	}
	return 0;
}
#endif

static SIMPLE_DEV_PM_OPS(pcf85263_pm, pcf85263_suspend, pcf85263_resume);

static struct i2c_driver pcf85263_driver = {
	.driver = {
		   .name = "rtc-pcf85263",
		   .owner = THIS_MODULE,
		   .pm = &pcf85263_pm,
		   .of_match_table = of_match_ptr(pcf85263_of_match),
		   },
	.probe = pcf85263_probe,
	.remove = pcf85263_remove,
	.id_table = pcf85263_id,
};

module_i2c_driver(pcf85263_driver);

MODULE_AUTHOR("Fabrizio Castro <fabrizio.castro@eurotech.com>");
MODULE_DESCRIPTION("NXP PCF85263 driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRIVER_VERSION);
