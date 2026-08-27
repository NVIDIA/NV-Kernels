// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBSA(Server Base System Architecture) Generic Watchdog driver
 *
 * Copyright (c) 2015, Linaro Ltd.
 * Author: Fu Wei <fu.wei@linaro.org>
 *         Suravee Suthikulpanit <Suravee.Suthikulpanit@amd.com>
 *         Al Stone <al.stone@linaro.org>
 *         Timur Tabi <timur@codeaurora.org>
 *
 * ARM SBSA Generic Watchdog has two stage timeouts:
 * the first signal (WS0) is for alerting the system by interrupt,
 * the second one (WS1) is a real hardware reset.
 * More details about the hardware specification of this device:
 * ARM DEN0029B - Server Base System Architecture (SBSA)
 *
 * This driver can operate ARM SBSA Generic Watchdog as a single stage watchdog
 * or a two stages watchdog, it's set up by the module parameter "action".
 * In the single stage mode, when the timeout is reached, your system
 * will be reset by WS1. The first signal (WS0) is ignored.
 * In the two stages mode, when the timeout is reached, the first signal (WS0)
 * will trigger panic. If the system is getting into trouble and cannot be reset
 * by panic or restart properly by the kdump kernel(if supported), then the
 * second stage (as long as the first stage) will be reached, system will be
 * reset by WS1. This function can help administrator to backup the system
 * context info by panic console output or kdump.
 *
 * SBSA GWDT:
 * if action is 1 (the two stages mode):
 * |--------WOR-------WS0--------WOR-------WS1
 * |----timeout-----(panic)----timeout-----reset
 *
 * if action is 0 (the single stage mode):
 * |------WOR-----WS0(ignored)-----WOR------WS1
 * |--------------timeout-------------------reset
 *
 * Note: Since this watchdog timer has two stages, and each stage is determined
 * by WOR, in the single stage mode, the timeout is (WOR * 2); in the two
 * stages mode, the timeout is WOR. The maximum timeout in the two stages mode
 * is half of that in the single stage mode.
 */

#include <linux/io.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/interrupt.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>
#include <linux/suspend.h>
#include <linux/uaccess.h>
#include <linux/watchdog.h>
#include <asm/arch_timer.h>

#define DRV_NAME		"sbsa-gwdt"
#define WATCHDOG_NAME		"SBSA Generic Watchdog"

/* SBSA Generic Watchdog register definitions */
/* refresh frame */
#define SBSA_GWDT_WRR		0x000

/* control frame */
#define SBSA_GWDT_WCS		0x000
#define SBSA_GWDT_WOR		0x008
#define SBSA_GWDT_WCV		0x010

/* refresh/control frame */
#define SBSA_GWDT_W_IIDR	0xfcc
#define SBSA_GWDT_IDR		0xfd0

/* Watchdog Control and Status Register */
#define SBSA_GWDT_WCS_EN	BIT(0)
#define SBSA_GWDT_WCS_WS0	BIT(1)
#define SBSA_GWDT_WCS_WS1	BIT(2)

#define SBSA_GWDT_VERSION_MASK  GENMASK(3, 0)
#define SBSA_GWDT_VERSION_SHIFT 16

#define SBSA_GWDT_IMPL_MASK	GENMASK(11, 0)
#define SBSA_GWDT_IMPL_SHIFT	0
#define SBSA_GWDT_IMPL_MEDIATEK	0x426

/**
 * struct sbsa_gwdt - Internal representation of the SBSA GWDT
 * @wdd:		kernel watchdog_device structure
 * @clk:		store the System Counter clock frequency, in Hz.
 * @version:            store the architecture version
 * @need_ws0_race_workaround:
 *			indicate whether to adjust wdd->timeout to avoid a race with WS0
 * @refresh_base:	Virtual address of the watchdog refresh frame
 * @control_base:	Virtual address of the watchdog control frame
 * @lock:		Serializes the watchdog ops against the system sleep hooks
 * @hw_armed:		The watchdog is logically running (started by firmware,
 *			early_enable or userspace); the hardware follows it except
 *			while a system sleep transition is in progress
 * @sleeping:		A system sleep transition is in progress: the hardware
 *			stays stopped and hw_armed is applied at PM_POST_*
 * @pm_nb:		PM notifier stopping the watchdog across system sleep
 */
struct sbsa_gwdt {
	struct watchdog_device	wdd;
	u32			clk;
	int			version;
	bool			need_ws0_race_workaround;
	void __iomem		*refresh_base;
	void __iomem		*control_base;
	spinlock_t		lock; /* hw_armed, sleeping */
	bool			hw_armed;
	bool			sleeping;
	struct notifier_block	pm_nb;
};

#define DEFAULT_TIMEOUT		10 /* seconds */

static unsigned int timeout;
module_param(timeout, uint, 0);
MODULE_PARM_DESC(timeout,
		 "Watchdog timeout in seconds. (>=0, default="
		 __MODULE_STRING(DEFAULT_TIMEOUT) ")");

/*
 * action refers to action taken when watchdog gets WS0
 * 0 = skip
 * 1 = panic
 * defaults to skip (0)
 */
static int action;
module_param(action, int, 0);
MODULE_PARM_DESC(action, "after watchdog gets WS0 interrupt, do: "
		 "0 = skip(*)  1 = panic");

static bool nowayout = WATCHDOG_NOWAYOUT;
module_param(nowayout, bool, S_IRUGO);
MODULE_PARM_DESC(nowayout,
		 "Watchdog cannot be stopped once started (default="
		 __MODULE_STRING(WATCHDOG_NOWAYOUT) ")");

static bool early_enable;
module_param(early_enable, bool, 0);
MODULE_PARM_DESC(early_enable,
		 "Watchdog is started on module insertion (default=0)");

/*
 * Arm Base System Architecture 1.0 introduces watchdog v1 which
 * increases the length watchdog offset register to 48 bits.
 * - For version 0: WOR is 32 bits;
 * - For version 1: WOR is 48 bits which comprises the register
 * offset 0x8 and 0xC, and the bits [63:48] are reserved which are
 * Read-As-Zero and Writes-Ignored.
 */
static u64 sbsa_gwdt_reg_read(struct sbsa_gwdt *gwdt)
{
	if (gwdt->version == 0)
		return readl(gwdt->control_base + SBSA_GWDT_WOR);
	else
		return lo_hi_readq(gwdt->control_base + SBSA_GWDT_WOR);
}

static void sbsa_gwdt_reg_write(u64 val, struct sbsa_gwdt *gwdt)
{
	if (gwdt->version == 0)
		writel((u32)val, gwdt->control_base + SBSA_GWDT_WOR);
	else
		lo_hi_writeq(val, gwdt->control_base + SBSA_GWDT_WOR);
}

/*
 * watchdog operation functions
 */
static int sbsa_gwdt_set_timeout(struct watchdog_device *wdd,
				 unsigned int timeout)
{
	struct sbsa_gwdt *gwdt = watchdog_get_drvdata(wdd);

	wdd->timeout = timeout;
	timeout = clamp_t(unsigned int, timeout, 1, wdd->max_hw_heartbeat_ms / 1000);

	if (action)
		sbsa_gwdt_reg_write((u64)gwdt->clk * timeout, gwdt);
	else
		/*
		 * In the single stage mode, The first signal (WS0) is ignored,
		 * the timeout is (WOR * 2), so the WOR should be configured
		 * to half value of timeout.
		 */
		sbsa_gwdt_reg_write(((u64)gwdt->clk / 2) * timeout, gwdt);

	/*
	 * Some watchdog hardware has a race condition where it will ignore
	 * sbsa_gwdt_keepalive() if it is called at the exact moment that a
	 * timeout occurs and WS0 is being asserted. Unfortunately, the default
	 * behavior of the watchdog core is very likely to trigger this race
	 * when action=0 because it programs WOR to be half of the desired
	 * timeout, and watchdog_next_keepalive() chooses the exact same time to
	 * send keepalive pings.
	 *
	 * This triggers a race where sbsa_gwdt_keepalive() can be called right
	 * as WS0 is being asserted, and affected hardware will ignore that
	 * write and continue to assert WS0. After another (timeout / 2)
	 * seconds, the same race happens again. If the driver wins then the
	 * explicit refresh will reset WS0 to false but if the hardware wins,
	 * then WS1 is asserted and the system resets.
	 *
	 * Avoid the problem by scheduling keepalive heartbeats one second later
	 * than the WOR timeout.
	 *
	 * This workaround might not be needed in a future revision of the
	 * hardware.
	 */
	if (gwdt->need_ws0_race_workaround)
		wdd->min_hw_heartbeat_ms = timeout * 500 + 1000;

	return 0;
}

static unsigned int sbsa_gwdt_get_timeleft(struct watchdog_device *wdd)
{
	struct sbsa_gwdt *gwdt = watchdog_get_drvdata(wdd);
	u64 timeleft = 0;

	/*
	 * In the single stage mode, if WS0 is deasserted
	 * (watchdog is in the first stage),
	 * timeleft = WOR + (WCV - system counter)
	 */
	if (!action &&
	    !(readl(gwdt->control_base + SBSA_GWDT_WCS) & SBSA_GWDT_WCS_WS0))
		timeleft += sbsa_gwdt_reg_read(gwdt);

	timeleft += lo_hi_readq(gwdt->control_base + SBSA_GWDT_WCV) -
		    arch_timer_read_counter();

	do_div(timeleft, gwdt->clk);

	return timeleft;
}

static int sbsa_gwdt_keepalive(struct watchdog_device *wdd)
{
	struct sbsa_gwdt *gwdt = watchdog_get_drvdata(wdd);

	/*
	 * Writing WRR for an explicit watchdog refresh.
	 * You can write anyting (like 0).
	 */
	writel(0, gwdt->refresh_base + SBSA_GWDT_WRR);

	return 0;
}

static void sbsa_gwdt_get_version(struct watchdog_device *wdd)
{
	struct sbsa_gwdt *gwdt = watchdog_get_drvdata(wdd);
	int iidr, ver, impl;

	iidr = readl(gwdt->control_base + SBSA_GWDT_W_IIDR);
	ver = (iidr >> SBSA_GWDT_VERSION_SHIFT) & SBSA_GWDT_VERSION_MASK;
	impl = (iidr >> SBSA_GWDT_IMPL_SHIFT) & SBSA_GWDT_IMPL_MASK;

	gwdt->version = ver;
	gwdt->need_ws0_race_workaround =
		!action && (impl == SBSA_GWDT_IMPL_MEDIATEK);
}

static void sbsa_gwdt_hw_start(struct sbsa_gwdt *gwdt)
{
	/* writing WCS will cause an explicit watchdog refresh */
	writel(SBSA_GWDT_WCS_EN, gwdt->control_base + SBSA_GWDT_WCS);
}

static void sbsa_gwdt_hw_stop(struct sbsa_gwdt *gwdt)
{
	/* Simply write 0 to WCS to clean WCS_EN bit */
	writel(0, gwdt->control_base + SBSA_GWDT_WCS);
}

static int sbsa_gwdt_start(struct watchdog_device *wdd)
{
	struct sbsa_gwdt *gwdt = watchdog_get_drvdata(wdd);
	unsigned long flags;

	spin_lock_irqsave(&gwdt->lock, flags);
	gwdt->hw_armed = true;
	/*
	 * While a system sleep transition is in progress nobody can refresh
	 * the watchdog: leave the hardware stopped and let the PM_POST_*
	 * notifier arm it once everything has resumed.
	 */
	if (!gwdt->sleeping)
		sbsa_gwdt_hw_start(gwdt);
	spin_unlock_irqrestore(&gwdt->lock, flags);

	return 0;
}

static int sbsa_gwdt_stop(struct watchdog_device *wdd)
{
	struct sbsa_gwdt *gwdt = watchdog_get_drvdata(wdd);
	unsigned long flags;

	spin_lock_irqsave(&gwdt->lock, flags);
	gwdt->hw_armed = false;
	sbsa_gwdt_hw_stop(gwdt);
	spin_unlock_irqrestore(&gwdt->lock, flags);

	return 0;
}

static irqreturn_t sbsa_gwdt_interrupt(int irq, void *dev_id)
{
	panic(WATCHDOG_NAME " timeout");

	return IRQ_HANDLED;
}

static const struct watchdog_info sbsa_gwdt_info = {
	.identity	= WATCHDOG_NAME,
	.options	= WDIOF_SETTIMEOUT |
			  WDIOF_KEEPALIVEPING |
			  WDIOF_MAGICCLOSE |
			  WDIOF_CARDRESET,
};

static const struct watchdog_ops sbsa_gwdt_ops = {
	.owner		= THIS_MODULE,
	.start		= sbsa_gwdt_start,
	.stop		= sbsa_gwdt_stop,
	.ping		= sbsa_gwdt_keepalive,
	.set_timeout	= sbsa_gwdt_set_timeout,
	.get_timeleft	= sbsa_gwdt_get_timeleft,
};

/*
 * Per-device suspend/resume callbacks alone would stop the watchdog only
 * once this device itself is suspended, one of the last steps of suspend
 * entry, and restart it during device resume, before tasks are thawed. A
 * watchdog running from boot (early_enable) would therefore be armed, with
 * nobody refreshing it, through task freezing and every other device's
 * suspend callback on the way down, and again from device resume until
 * userspace runs on the way up; anything stalling past the timeout in
 * either window resets the system.
 *
 * Own the transition from a PM notifier instead: stop at the *_PREPARE
 * events, before anything is frozen, and restart at PM_POST_*, after
 * everything has resumed. The driver state (hw_armed, sleeping) is kept
 * under a lock shared with the watchdog ops so that a userspace stop or
 * magic close after thaw cannot race the restart, and a start requested
 * while the transition is in progress is deferred to PM_POST_*. The
 * transition is recorded at *_PREPARE whether or not the watchdog was
 * armed at that moment, so a start between *_PREPARE and task freezing
 * is deferred as well instead of arming hardware nobody refreshes.
 *
 * A probe can overlap a transition whose *_PREPARE event has already run.
 * Two guards cover it: once its notifier is registered, the probe checks
 * for a suspend already past task freezing and stops the hardware itself,
 * and the device ->prepare callback, which the PM core runs after waiting
 * for outstanding probes and before any device suspend callback, applies
 * the same stop. Neither has a resume counterpart: PM_POST_* is the only
 * place that re-arms the hardware.
 */
static void sbsa_gwdt_sleep_stop(struct sbsa_gwdt *gwdt)
{
	unsigned long flags;

	spin_lock_irqsave(&gwdt->lock, flags);
	/*
	 * Idempotent on purpose: the *_PREPARE notifier, the probe-time
	 * catch-up and the device ->prepare callback all land here, and a
	 * probe that adopted a firmware-armed watchdog after *_PREPARE
	 * relies on a later call actually stopping the hardware.
	 */
	gwdt->sleeping = true;
	if (gwdt->hw_armed)
		sbsa_gwdt_hw_stop(gwdt);
	spin_unlock_irqrestore(&gwdt->lock, flags);
}

static void sbsa_gwdt_sleep_restart(struct sbsa_gwdt *gwdt)
{
	unsigned long flags;

	spin_lock_irqsave(&gwdt->lock, flags);
	if (gwdt->sleeping) {
		gwdt->sleeping = false;
		if (gwdt->hw_armed)
			sbsa_gwdt_hw_start(gwdt);
	}
	spin_unlock_irqrestore(&gwdt->lock, flags);
}

static int sbsa_gwdt_pm_notify(struct notifier_block *nb, unsigned long mode,
			       void *data)
{
	struct sbsa_gwdt *gwdt = container_of(nb, struct sbsa_gwdt, pm_nb);

	switch (mode) {
	case PM_SUSPEND_PREPARE:
	case PM_HIBERNATION_PREPARE:
	case PM_RESTORE_PREPARE:
		sbsa_gwdt_sleep_stop(gwdt);
		break;
	case PM_POST_SUSPEND:
	case PM_POST_HIBERNATION:
	case PM_POST_RESTORE:
		sbsa_gwdt_sleep_restart(gwdt);
		break;
	}

	return NOTIFY_DONE;
}

static void sbsa_gwdt_unregister_pm_notifier(void *data)
{
	struct sbsa_gwdt *gwdt = data;

	unregister_pm_notifier(&gwdt->pm_nb);
	/*
	 * No PM_POST_* will reach this device any more. If a transition
	 * stopped the hardware, put it back into the state the last start or
	 * stop asked for, so a probe that fails while the system heads into
	 * sleep does not leave a firmware-started watchdog silently disabled;
	 * without a driver such a watchdog is armed and unrefreshed whether
	 * or not a transition is in progress, exactly as a probe failure
	 * outside a transition leaves it.
	 */
	sbsa_gwdt_sleep_restart(gwdt);
}

static int sbsa_gwdt_prepare(struct device *dev)
{
	sbsa_gwdt_sleep_stop(dev_get_drvdata(dev));

	return 0;
}

static const struct dev_pm_ops sbsa_gwdt_pm_ops = {
	.prepare = pm_sleep_ptr(sbsa_gwdt_prepare),
};

static int sbsa_gwdt_probe(struct platform_device *pdev)
{
	void __iomem *rf_base, *cf_base;
	struct device *dev = &pdev->dev;
	struct watchdog_device *wdd;
	struct sbsa_gwdt *gwdt;
	unsigned long flags;
	int ret, irq;
	u32 status;
	bool early_action;

	gwdt = devm_kzalloc(dev, sizeof(*gwdt), GFP_KERNEL);
	if (!gwdt)
		return -ENOMEM;
	platform_set_drvdata(pdev, gwdt);

	cf_base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(cf_base))
		return PTR_ERR(cf_base);

	rf_base = devm_platform_ioremap_resource(pdev, 1);
	if (IS_ERR(rf_base))
		return PTR_ERR(rf_base);

	/*
	 * Get the frequency of system counter from the cp15 interface of ARM
	 * Generic timer. We don't need to check it, because if it returns "0",
	 * system would panic in very early stage.
	 */
	gwdt->clk = arch_timer_get_cntfrq();
	gwdt->refresh_base = rf_base;
	gwdt->control_base = cf_base;
	spin_lock_init(&gwdt->lock);

	/*
	 * Adopt the firmware state before the sleep hook can observe it: a
	 * watchdog already running when the driver binds must be seen as
	 * armed by a *_PREPARE that lands right after registration, or it
	 * would keep running, unrefreshed, into the transition.
	 */
	status = readl(cf_base + SBSA_GWDT_WCS);
	gwdt->hw_armed = !!(status & SBSA_GWDT_WCS_EN);

	/*
	 * Register the sleep hook before anything else can arm the watchdog,
	 * and treat its failure as fatal: without it a running watchdog would
	 * survive into system sleep with nobody refreshing it.
	 */
	gwdt->pm_nb.notifier_call = sbsa_gwdt_pm_notify;
	ret = register_pm_notifier(&gwdt->pm_nb);
	if (!ret)
		ret = devm_add_action_or_reset(dev,
					       sbsa_gwdt_unregister_pm_notifier,
					       gwdt);
	if (ret)
		return dev_err_probe(dev, ret,
				     "Failed to register PM notifier\n");

	/*
	 * Catch up with a suspend whose PM_SUSPEND_PREPARE ran before the
	 * hook was registered. pm_suspend_in_progress() is true from the end
	 * of task freezing until the devices have resumed, and
	 * PM_POST_SUSPEND always follows its clearing, so a transition seen
	 * here is one the hook will see the end of; the check runs under the
	 * lock so that a PM_POST_SUSPEND racing it finds 'sleeping' set. The
	 * hibernation counterpart stays true past PM_POST_HIBERNATION and
	 * would record a transition nobody ends, so hibernation, like the
	 * interval between *_PREPARE and the end of task freezing, relies on
	 * the device ->prepare callback instead.
	 */
	spin_lock_irqsave(&gwdt->lock, flags);
	if (pm_suspend_in_progress()) {
		gwdt->sleeping = true;
		if (gwdt->hw_armed)
			sbsa_gwdt_hw_stop(gwdt);
	}
	spin_unlock_irqrestore(&gwdt->lock, flags);

	wdd = &gwdt->wdd;
	wdd->parent = dev;
	wdd->info = &sbsa_gwdt_info;
	wdd->ops = &sbsa_gwdt_ops;
	wdd->min_timeout = 1;
	wdd->timeout = DEFAULT_TIMEOUT;
	watchdog_set_drvdata(wdd, gwdt);
	watchdog_set_nowayout(wdd, nowayout);
	sbsa_gwdt_get_version(wdd);
	if (gwdt->version == 0)
		wdd->max_hw_heartbeat_ms = U32_MAX / gwdt->clk * 1000;
	else
		wdd->max_hw_heartbeat_ms = GENMASK_ULL(47, 0) / gwdt->clk * 1000;

	if (gwdt->need_ws0_race_workaround) {
		/*
		 * A timeout of 3 seconds means that WOR will be set to 1.5
		 * seconds and the heartbeat will be scheduled every 2.5
		 * seconds.
		 */
		wdd->min_timeout = 3;
	}

	if (status & SBSA_GWDT_WCS_WS1) {
		dev_warn(dev, "System reset by WDT.\n");
		wdd->bootstatus |= WDIOF_CARDRESET;
	}
	/*
	 * hw_armed already reflects WCS_EN (adopted above, before the sleep
	 * hook was registered); a transition that started since then, or
	 * that the catch-up above found in progress, has stopped the
	 * hardware and PM_POST_* re-arms it.
	 */
	if (status & SBSA_GWDT_WCS_EN)
		set_bit(WDOG_HW_RUNNING, &wdd->status);

	if (action) {
		irq = platform_get_irq(pdev, 0);
		if (irq < 0) {
			action = 0;
			dev_warn(dev, "unable to get ws0 interrupt.\n");
		} else {
			/*
			 * In case there is a pending ws0 interrupt, just ping
			 * the watchdog before registering the interrupt routine
			 */
			writel(0, rf_base + SBSA_GWDT_WRR);
			if (devm_request_irq(dev, irq, sbsa_gwdt_interrupt, 0,
					     pdev->name, gwdt)) {
				action = 0;
				dev_warn(dev, "unable to request IRQ %d.\n",
					 irq);
			}
		}
		if (!action)
			dev_warn(dev, "falling back to single stage mode.\n");
	}
	/*
	 * In the single stage mode, The first signal (WS0) is ignored,
	 * the timeout is (WOR * 2), so the maximum timeout should be doubled.
	 */
	if (!action)
		wdd->max_hw_heartbeat_ms *= 2;

	watchdog_init_timeout(wdd, timeout, dev);
	/*
	 * Update timeout to WOR.
	 * Because of the explicit watchdog refresh mechanism,
	 * it's also a ping, if watchdog is enabled.
	 */
	sbsa_gwdt_set_timeout(wdd, wdd->timeout);

	early_action = early_enable && !(status & SBSA_GWDT_WCS_EN);
	if (early_action) {
		sbsa_gwdt_start(wdd);
		set_bit(WDOG_HW_RUNNING, &wdd->status);
	}

	watchdog_stop_on_reboot(wdd);
	ret = devm_watchdog_register_device(dev, wdd);
	if (ret) {
		if (early_action)
			sbsa_gwdt_stop(wdd);
		return ret;
	}

	dev_info(dev, "Initialized with %ds timeout @ %u Hz, action=%d.%s\n",
		 wdd->timeout, gwdt->clk, action,
		 watchdog_hw_running(wdd) ? " [enabled]" : "");

	return 0;
}

static const struct of_device_id sbsa_gwdt_of_match[] = {
	{ .compatible = "arm,sbsa-gwdt", },
	{},
};
MODULE_DEVICE_TABLE(of, sbsa_gwdt_of_match);

static const struct platform_device_id sbsa_gwdt_pdev_match[] = {
	{ .name = DRV_NAME, },
	{},
};
MODULE_DEVICE_TABLE(platform, sbsa_gwdt_pdev_match);

static struct platform_driver sbsa_gwdt_driver = {
	.driver = {
		.name = DRV_NAME,
		.pm = pm_sleep_ptr(&sbsa_gwdt_pm_ops),
		.of_match_table = sbsa_gwdt_of_match,
	},
	.probe = sbsa_gwdt_probe,
	.id_table = sbsa_gwdt_pdev_match,
};

module_platform_driver(sbsa_gwdt_driver);

MODULE_DESCRIPTION("SBSA Generic Watchdog Driver");
MODULE_AUTHOR("Fu Wei <fu.wei@linaro.org>");
MODULE_AUTHOR("Suravee Suthikulpanit <Suravee.Suthikulpanit@amd.com>");
MODULE_AUTHOR("Al Stone <al.stone@linaro.org>");
MODULE_AUTHOR("Timur Tabi <timur@codeaurora.org>");
MODULE_LICENSE("GPL v2");
