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

#include <linux/delay.h>
#include <linux/io.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/interrupt.h>
#include <linux/list.h>
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
 * @no_hw_stop:		MediaTek implementation: clearing WCS.EN does not stop
 *			the compare, so the watchdog cannot be stopped. No stop
 *			op is offered and system sleep parks it instead (version
 *			1 only: a version 0 WOR cannot hold a park period)
 * @refresh_base:	Virtual address of the watchdog refresh frame
 * @control_base:	Virtual address of the watchdog control frame
 * @node:		Entry in the list of instances the sleep notifier owns
 * @hw_armed:		The watchdog is logically running (started by firmware,
 *			early_enable or userspace); the hardware follows it except
 *			while a system sleep transition is in progress
 */
struct sbsa_gwdt {
	struct watchdog_device	wdd;
	u32			clk;
	int			version;
	bool			need_ws0_race_workaround;
	bool			no_hw_stop;
	void __iomem		*refresh_base;
	void __iomem		*control_base;
	struct list_head	node;
	bool			hw_armed;
};

/*
 * System sleep state shared by all instances. The notifier recording a
 * transition is registered once, at driver init, before any device can be
 * probed, so a probe at any later point finds the transition already
 * recorded instead of racing its own registration against *_PREPARE.
 */
static LIST_HEAD(sbsa_gwdt_list);
static DEFINE_SPINLOCK(sbsa_gwdt_lock); /* list, sleeping, hw_armed */
static bool sbsa_gwdt_sleeping;

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
/* Program WOR for @timeout seconds; returns the hardware timeout used. */
static unsigned int sbsa_gwdt_program_wor(struct sbsa_gwdt *gwdt,
					  unsigned int timeout)
{
	struct watchdog_device *wdd = &gwdt->wdd;

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
	 * Make sure the new period has landed before the caller, or the
	 * watchdog core right behind it (WDIOC_SETTIMEOUT is followed by a
	 * ping), refreshes: a refresh reloads with whatever period the block
	 * holds at that moment, and the MediaTek block commits WOR on a slow
	 * clock, well after the MMIO write has completed.
	 */
	sbsa_gwdt_reg_read(gwdt);
	if (gwdt->no_hw_stop)
		udelay(500);

	return timeout;
}

static int sbsa_gwdt_set_timeout(struct watchdog_device *wdd,
				 unsigned int timeout)
{
	struct sbsa_gwdt *gwdt = watchdog_get_drvdata(wdd);
	unsigned int hw_timeout;
	unsigned long flags;

	/*
	 * Keep the requested value: the core extends timeouts beyond the
	 * hardware maximum with its own keepalives, and reports this value.
	 * Only the hardware programming below is clamped.
	 */
	wdd->timeout = timeout;
	hw_timeout = clamp_t(unsigned int, timeout, 1,
			     wdd->max_hw_heartbeat_ms / 1000);

	/*
	 * Leave WOR alone while a sleep transition is in progress: a parked
	 * watchdog must keep its parked period (a probe during the
	 * transition would otherwise re-arm a short countdown that nobody
	 * refreshes); the restart at PM_POST_* programs the timeout. At any
	 * other time program it, so the register holds a valid period
	 * before the first start (on a MediaTek block the write is only
	 * latched while enabled, and sbsa_gwdt_hw_start() repeats it).
	 */
	spin_lock_irqsave(&sbsa_gwdt_lock, flags);
	if (!sbsa_gwdt_sleeping)
		sbsa_gwdt_program_wor(gwdt, hw_timeout);
	spin_unlock_irqrestore(&sbsa_gwdt_lock, flags);

	timeout = hw_timeout;

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
	/* The MediaTek block cannot be stopped, see sbsa_gwdt_hw_stop(). */
	gwdt->no_hw_stop = impl == SBSA_GWDT_IMPL_MEDIATEK;
}

/*
 * The control and refresh frames are two MMIO regions. Writes to different
 * regions may complete out of order, and the MediaTek block latches WOR
 * only while WCS.EN is set and reloads on WRR with whatever period it holds
 * at that moment, so every control-frame write below is read back before
 * the refresh frame is written. The refresh frame itself is never read:
 * reads there are not inert on this implementation.
 */
static void sbsa_gwdt_refresh(struct sbsa_gwdt *gwdt)
{
	writel(0, gwdt->refresh_base + SBSA_GWDT_WRR);
}

static void sbsa_gwdt_hw_start(struct sbsa_gwdt *gwdt)
{
	bool was_enabled;

	/*
	 * Enable first. On the MediaTek implementation a WOR write is only
	 * latched into the countdown while WCS.EN is set (the register reads
	 * back the written value either way), so the configured timeout has
	 * to be programmed after the enable, not before.
	 *
	 * The order of the refresh and the timeout write depends on the
	 * state the block is in:
	 *
	 * - Already enabled (the restart after a system sleep, or a start
	 *   while the hardware is running): the block holds a recent reload
	 *   with the parked or configured period. Refresh first, so the
	 *   reload moves to now with that long period, then program the
	 *   timeout and refresh again so the countdown starts from now with
	 *   the configured period. Programming the short period first would
	 *   latch it onto the old reload and give a deadline that is already
	 *   in the past.
	 *
	 * - Disabled (the first start): the period the block holds is
	 *   whatever firmware left, possibly zero or already expired, so a
	 *   refresh with it could assert WS0 or reset at once. Program the
	 *   timeout first, then refresh. On the MediaTek block the old
	 *   reload is long past and never matches, and the WOR write is
	 *   only latched once WCS.EN is set, hence enable, program, refresh.
	 *
	 * The extra refreshes are harmless on other implementations.
	 */
	was_enabled = readl(gwdt->control_base + SBSA_GWDT_WCS) &
		      SBSA_GWDT_WCS_EN;
	writel(SBSA_GWDT_WCS_EN, gwdt->control_base + SBSA_GWDT_WCS);
	readl(gwdt->control_base + SBSA_GWDT_WCS);
	if (was_enabled)
		sbsa_gwdt_refresh(gwdt);
	sbsa_gwdt_program_wor(gwdt, gwdt->wdd.timeout);
	sbsa_gwdt_refresh(gwdt);
	if (!was_enabled) {
		if (gwdt->no_hw_stop)
			udelay(500);
		sbsa_gwdt_refresh(gwdt);
	}
}

static void sbsa_gwdt_hw_stop(struct sbsa_gwdt *gwdt)
{
	u64 wor_max;

	/*
	 * Clearing WCS.EN does not stop the countdown on the MediaTek
	 * implementation: it keeps comparing against the last reload
	 * regardless of the enable bit, so a "stopped" watchdog that was
	 * refreshed a few seconds earlier still fires when its period
	 * elapses and resets the platform. The watchdog cannot be stopped,
	 * and the driver does not pretend otherwise: such an instance has no
	 * stop op, so a userspace disable or magic close leaves it running
	 * with the core refreshing it (WDOG_HW_RUNNING), and this function is
	 * reached only from the system sleep path and from driver removal.
	 *
	 * Around a sleep nobody can refresh the hardware, and a reload with
	 * a period far in the future is harmless. Park the watchdog: program
	 * WOR to the largest value this version supports while WCS.EN is set
	 * (a WOR write is only latched while enabled) and refresh so the
	 * reload happens with that period.
	 *
	 * Leave WCS.EN set while parked. The period latch and the reload are
	 * not synchronous with the MMIO writes, and a refresh that reaches
	 * the block before the new period reloads with the old, short one.
	 * With the enable bit kept, every later refresh (the second one here,
	 * and the core's keepalives until the CPUs go offline) reloads again
	 * with the parked period and heals that race; with the bit cleared
	 * nothing can be latched any more and the short reload stands. A
	 * parked, enabled watchdog cannot fire for days, which is also the
	 * state the firmware of these platforms expects through a sleep. The
	 * restart on resume restores the configured timeout.
	 *
	 * Only the MediaTek implementation needs this; other implementations
	 * keep the architectural disable, on stop and around a sleep. The
	 * 32-bit WOR of a version 0 watchdog caps the period at about 4 s at
	 * 1 GHz, which cannot cover a sleep, so parking needs the 48-bit
	 * register of version 1; a version 0 MediaTek block (none measured)
	 * is left with the architectural disable around a sleep, the only
	 * thing its register set allows.
	 *
	 * Known limitation: a parked watchdog stays enabled through the sleep
	 * and its period is finite, about 78 hours at 1 GHz, so a sleep longer
	 * than that asserts WS0 before the resume path restores the timeout.
	 */
	if (!gwdt->no_hw_stop || gwdt->version == 0) {
		writel(0, gwdt->control_base + SBSA_GWDT_WCS);
		return;
	}

	/*
	 * WOR is written as two 32-bit halves and the block commits them on
	 * its own clock, so a refresh can latch a mixed value: one half new,
	 * the other still old. Write the high half first when parking, so a
	 * mixed value is new-high:old-low, which is at least 2^32 ticks with
	 * an all-ones high half, i.e. still days. (sbsa_gwdt_program_wor()
	 * writes low then high for the same reason in the other direction:
	 * a mixed value there is old-high:new-low, the parked period again,
	 * and the next keepalive reloads with the restored one.)
	 */
	wor_max = GENMASK_ULL(47, 0);
	writel(upper_32_bits(wor_max), gwdt->control_base + SBSA_GWDT_WOR + 4);
	writel(lower_32_bits(wor_max), gwdt->control_base + SBSA_GWDT_WOR);
	sbsa_gwdt_reg_read(gwdt);
	/*
	 * Give the block time to commit the new period before the refresh
	 * that has to reload with it, and refresh twice: a refresh that
	 * still races the commit reloads with the old period, and the
	 * second one, well after the commit, replaces that reload. The
	 * commit happens on a clock in the tens of kHz range, so the wait
	 * is in the hundreds of microseconds.
	 */
	udelay(500);
	sbsa_gwdt_refresh(gwdt);
	udelay(500);
	sbsa_gwdt_refresh(gwdt);
}

static int sbsa_gwdt_start(struct watchdog_device *wdd)
{
	struct sbsa_gwdt *gwdt = watchdog_get_drvdata(wdd);
	unsigned long flags;

	spin_lock_irqsave(&sbsa_gwdt_lock, flags);
	gwdt->hw_armed = true;
	/*
	 * While a system sleep transition is in progress nobody can refresh
	 * the watchdog: leave the hardware stopped and let the PM_POST_*
	 * notifier arm it once everything has resumed.
	 */
	if (!sbsa_gwdt_sleeping)
		sbsa_gwdt_hw_start(gwdt);
	spin_unlock_irqrestore(&sbsa_gwdt_lock, flags);

	return 0;
}

static int sbsa_gwdt_stop(struct watchdog_device *wdd)
{
	struct sbsa_gwdt *gwdt = watchdog_get_drvdata(wdd);
	unsigned long flags;

	spin_lock_irqsave(&sbsa_gwdt_lock, flags);
	gwdt->hw_armed = false;
	sbsa_gwdt_hw_stop(gwdt);
	spin_unlock_irqrestore(&sbsa_gwdt_lock, flags);

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
 * For an implementation that cannot be stopped (see sbsa_gwdt_hw_stop()).
 * Without a stop op the core keeps the watchdog running and refreshes it
 * itself when userspace disables it or closes the device.
 */
static const struct watchdog_ops sbsa_gwdt_ops_no_stop = {
	.owner		= THIS_MODULE,
	.start		= sbsa_gwdt_start,
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
 * everything has resumed. The state (hw_armed per instance, one sleeping
 * flag) is kept under a lock shared with the watchdog ops so that a
 * userspace stop or magic close after thaw cannot race the restart, and a
 * start requested while the transition is in progress is deferred to
 * PM_POST_*. The transition is recorded at *_PREPARE whether or not the
 * watchdog was armed at that moment, so a start between *_PREPARE and
 * task freezing is deferred as well instead of arming hardware nobody
 * refreshes.
 *
 * The notifier is registered at driver init, so a probe that runs while
 * the driver is loaded finds a transition already recorded, whatever its
 * interleaving with *_PREPARE, and applies it when it adopts the hardware
 * state. What remains is the driver being loaded after PM_SUSPEND_PREPARE
 * has run: the probe then checks for a suspend already past task freezing
 * and stops the hardware itself, and the device ->prepare callback, which
 * the PM core runs after waiting for outstanding probes and before any
 * device suspend callback, applies the same stop. Neither has a resume
 * counterpart: PM_POST_* is the only place that re-arms the hardware.
 */
static int sbsa_gwdt_sleep_stop(void)
{
	struct sbsa_gwdt *gwdt;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&sbsa_gwdt_lock, flags);
	/*
	 * An armed watchdog that can neither be stopped nor parked (a
	 * version 0 MediaTek block: its 32-bit WOR cannot cover a sleep)
	 * would fire while nobody can refresh it. Refuse the transition
	 * rather than proceed into a reset.
	 */
	list_for_each_entry(gwdt, &sbsa_gwdt_list, node) {
		if (gwdt->hw_armed && gwdt->no_hw_stop && gwdt->version == 0) {
			dev_err(gwdt->wdd.parent,
				"watchdog cannot be parked across a system sleep\n");
			ret = -EBUSY;
		}
	}
	if (ret)
		goto out;

	/*
	 * Idempotent on purpose: the *_PREPARE notifier and the device
	 * ->prepare callback both land here, and a probe that adopted a
	 * firmware-armed watchdog after *_PREPARE relies on a later call
	 * actually stopping the hardware.
	 */
	sbsa_gwdt_sleeping = true;
	list_for_each_entry(gwdt, &sbsa_gwdt_list, node)
		if (gwdt->hw_armed)
			sbsa_gwdt_hw_stop(gwdt);
out:
	spin_unlock_irqrestore(&sbsa_gwdt_lock, flags);

	return ret;
}

static void sbsa_gwdt_sleep_restart(void)
{
	struct sbsa_gwdt *gwdt;
	unsigned long flags;

	spin_lock_irqsave(&sbsa_gwdt_lock, flags);
	if (sbsa_gwdt_sleeping) {
		sbsa_gwdt_sleeping = false;
		list_for_each_entry(gwdt, &sbsa_gwdt_list, node)
			if (gwdt->hw_armed)
				sbsa_gwdt_hw_start(gwdt);
	}
	spin_unlock_irqrestore(&sbsa_gwdt_lock, flags);
}

static int sbsa_gwdt_pm_notify(struct notifier_block *nb, unsigned long mode,
			       void *data)
{
	switch (mode) {
	case PM_SUSPEND_PREPARE:
	case PM_HIBERNATION_PREPARE:
	case PM_RESTORE_PREPARE:
		return notifier_from_errno(sbsa_gwdt_sleep_stop());
	case PM_POST_SUSPEND:
	case PM_POST_HIBERNATION:
	case PM_POST_RESTORE:
		sbsa_gwdt_sleep_restart();
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block sbsa_gwdt_pm_nb = {
	.notifier_call = sbsa_gwdt_pm_notify,
};

static void sbsa_gwdt_remove_instance(void *data)
{
	struct sbsa_gwdt *gwdt = data;
	unsigned long flags;

	spin_lock_irqsave(&sbsa_gwdt_lock, flags);
	list_del(&gwdt->node);
	/*
	 * PM_POST_* no longer applies to this instance. If a transition
	 * stopped the hardware, put it back into the state the last start or
	 * stop asked for, so a probe that fails while the system heads into
	 * sleep does not leave a firmware-started watchdog silently disabled;
	 * without a driver such a watchdog is armed and unrefreshed whether
	 * or not a transition is in progress, exactly as a probe failure
	 * outside a transition leaves it.
	 *
	 * A version 1 implementation that cannot be stopped is left parked
	 * instead: armed with nobody to refresh it, the short period would
	 * reset the system within seconds of the removal. A version 0 block
	 * cannot be parked and is left armed, and the warning says so. Only
	 * a probe failure gets here with the hardware armed: the driver
	 * suppresses the bind attributes, and the watchdog core holds a
	 * module reference while the hardware runs, so a running watchdog
	 * cannot lose its driver by unbind or module unload.
	 */
	if (gwdt->no_hw_stop) {
		if (gwdt->hw_armed) {
			sbsa_gwdt_hw_stop(gwdt);
			dev_warn(gwdt->wdd.parent,
				 "watchdog cannot be stopped, left %s\n",
				 gwdt->version ? "parked" : "armed");
		}
	} else if (sbsa_gwdt_sleeping && gwdt->hw_armed) {
		sbsa_gwdt_hw_start(gwdt);
	}
	spin_unlock_irqrestore(&sbsa_gwdt_lock, flags);
}

static int sbsa_gwdt_prepare(struct device *dev)
{
	return sbsa_gwdt_sleep_stop();
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
	wdd = &gwdt->wdd;
	watchdog_set_drvdata(wdd, gwdt);
	/* The stop path below needs the version to decide whether it can park. */
	sbsa_gwdt_get_version(wdd);
	status = readl(cf_base + SBSA_GWDT_WCS);

	wdd->parent = dev;
	wdd->info = &sbsa_gwdt_info;
	wdd->ops = gwdt->no_hw_stop ? &sbsa_gwdt_ops_no_stop : &sbsa_gwdt_ops;
	wdd->min_timeout = 1;
	wdd->timeout = DEFAULT_TIMEOUT;
	watchdog_set_nowayout(wdd, nowayout);
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
	 * A firmware-started watchdog is adopted below, once the timeout
	 * and the mode are known; a transition recorded before or since
	 * then stops the hardware and PM_POST_* re-arms it.
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

	/*
	 * Adopt the firmware state and join the list under the lock, now
	 * that the timeout, the heartbeat limits and the mode are final: a
	 * PM_POST_* landing after this point restarts the hardware with the
	 * configured timeout, not with an uninitialised one. A transition
	 * the notifier has already recorded applies to this instance at
	 * once, and a *_PREPARE landing after this point finds hw_armed
	 * set. pm_suspend_in_progress() covers the driver being
	 * loaded after PM_SUSPEND_PREPARE ran: it is true from the end of
	 * task freezing until the devices have resumed, and PM_POST_SUSPEND
	 * always follows its clearing, so a transition seen here is one the
	 * notifier will see the end of; read under the lock, a PM_POST_SUSPEND
	 * racing it finds the flag set. The hibernation counterpart stays
	 * true past PM_POST_HIBERNATION and would record a transition nobody
	 * ends, so that case, like the interval between *_PREPARE and the end
	 * of task freezing, relies on the device ->prepare callback instead.
	 */
	spin_lock_irqsave(&sbsa_gwdt_lock, flags);
	gwdt->hw_armed = !!(status & SBSA_GWDT_WCS_EN);
	if (pm_suspend_in_progress())
		sbsa_gwdt_sleeping = true;
	if (sbsa_gwdt_sleeping && gwdt->hw_armed)
		sbsa_gwdt_hw_stop(gwdt);
	list_add(&gwdt->node, &sbsa_gwdt_list);
	spin_unlock_irqrestore(&sbsa_gwdt_lock, flags);

	ret = devm_add_action_or_reset(dev, sbsa_gwdt_remove_instance, gwdt);
	if (ret)
		return ret;

	early_action = early_enable && !(status & SBSA_GWDT_WCS_EN);
	if (early_action) {
		sbsa_gwdt_start(wdd);
		set_bit(WDOG_HW_RUNNING, &wdd->status);
	}

	/*
	 * The reboot notifier calls the stop op directly, and an
	 * implementation that cannot be stopped has none; clearing WCS.EN
	 * would not stop it either.
	 */
	if (!gwdt->no_hw_stop)
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
		/*
		 * A watchdog that is running when its driver goes away is
		 * armed with nobody to refresh it and resets the system when
		 * the period elapses (after the parked period on an
		 * implementation that cannot be stopped). The core already
		 * pins the module while the hardware runs; close the sysfs
		 * unbind path as well.
		 */
		.suppress_bind_attrs = true,
	},
	.probe = sbsa_gwdt_probe,
	.id_table = sbsa_gwdt_pdev_match,
};

static int __init sbsa_gwdt_init(void)
{
	int ret;

	/*
	 * Register the sleep notifier before any device can be probed, so
	 * that every transition from here on is recorded before a probe
	 * adopts a running watchdog. Its failure is fatal: without it a
	 * running watchdog would survive into system sleep unrefreshed.
	 */
	ret = register_pm_notifier(&sbsa_gwdt_pm_nb);
	if (ret)
		return ret;

	ret = platform_driver_register(&sbsa_gwdt_driver);
	if (ret)
		unregister_pm_notifier(&sbsa_gwdt_pm_nb);

	return ret;
}
module_init(sbsa_gwdt_init);

static void __exit sbsa_gwdt_exit(void)
{
	platform_driver_unregister(&sbsa_gwdt_driver);
	unregister_pm_notifier(&sbsa_gwdt_pm_nb);
}
module_exit(sbsa_gwdt_exit);

MODULE_DESCRIPTION("SBSA Generic Watchdog Driver");
MODULE_AUTHOR("Fu Wei <fu.wei@linaro.org>");
MODULE_AUTHOR("Suravee Suthikulpanit <Suravee.Suthikulpanit@amd.com>");
MODULE_AUTHOR("Al Stone <al.stone@linaro.org>");
MODULE_AUTHOR("Timur Tabi <timur@codeaurora.org>");
MODULE_LICENSE("GPL v2");
