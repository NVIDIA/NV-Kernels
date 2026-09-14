// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * processor_idle - idle state submodule to the ACPI processor driver
 *
 *  Copyright (C) 2001, 2002 Andy Grover <andrew.grover@intel.com>
 *  Copyright (C) 2001, 2002 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2004, 2005 Dominik Brodowski <linux@brodo.de>
 *  Copyright (C) 2004  Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
 *  			- Added processor hotplug support
 *  Copyright (C) 2005  Venkatesh Pallipadi <venkatesh.pallipadi@intel.com>
 *  			- Added support for C3 on SMP
 */
#define pr_fmt(fmt) "ACPI: " fmt

#include <linux/module.h>
#include <linux/acpi.h>
#include <linux/device.h>
#include <linux/dmi.h>
#include <linux/sched.h>       /* need_resched() */
#include <linux/tick.h>
#include <linux/cpuidle.h>
#include <linux/cpu.h>
#include <linux/minmax.h>
#include <linux/mutex.h>
#include <linux/perf_event.h>
#include <linux/pm_domain.h>
#include <acpi/processor.h>
#include <linux/context_tracking.h>

#include "internal.h"

/*
 * Include the apic definitions for x86 to have the APIC timer related defines
 * available also for UP (on SMP it gets magically included via linux/smp.h).
 * asm/acpi.h is not an option, as it would require more include magic. Also
 * creating an empty asm-ia64/apic.h would just trade pest vs. cholera.
 */
#ifdef CONFIG_X86
#include <asm/apic.h>
#include <asm/cpu.h>
#endif

#define ACPI_IDLE_STATE_START	(IS_ENABLED(CONFIG_ARCH_HAS_CPU_RELAX) ? 1 : 0)

struct acpi_lpi_genpd_map_entry {
	struct list_head node;
	acpi_handle handle;
	struct generic_pm_domain *genpd;
	struct acpi_lpi_state *lpi_states;
	unsigned int lpi_state_count;
};

struct acpi_idle_data {
	struct acpi_lpi_genpd_map_entry *base_map_entry;
	unsigned int leaf_lpi_count;
};

static unsigned int max_cstate __read_mostly = ACPI_PROCESSOR_MAX_POWER;
module_param(max_cstate, uint, 0400);
static bool nocst __read_mostly;
module_param(nocst, bool, 0400);
static bool bm_check_disable __read_mostly;
module_param(bm_check_disable, bool, 0400);

static unsigned int latency_factor __read_mostly = 2;
module_param(latency_factor, uint, 0644);

static DEFINE_PER_CPU(struct cpuidle_device *, acpi_cpuidle_device);
static DEFINE_MUTEX(acpi_idle_rebuild_lock);
static DEFINE_PER_CPU(struct acpi_idle_data *, acpi_idle_data);

static LIST_HEAD(domain_map);
static DEFINE_MUTEX(domain_map_lock);

#define ACPI_LPI_STATE_FLAGS_ENABLED			BIT(0)

#ifdef CONFIG_PM_GENERIC_DOMAINS
#define ACPI_LPI_GENPD_GOVERNOR			(&pm_domain_cpu_gov)
#else
#define ACPI_LPI_GENPD_GOVERNOR			NULL
#endif

static struct cpuidle_driver acpi_idle_driver = {
	.name =		"acpi_idle",
	.owner =	THIS_MODULE,
};

/*
 * The legacy ACPI idle path uses one driver for every CPU. Hierarchical LPI
 * systems may describe a different CPU-local state table for each CPU, so use
 * CPU-scoped drivers when the cpuidle core and the architecture support them.
 */
static DEFINE_PER_CPU(struct cpuidle_driver *, acpi_idle_cpu_driver);
static bool acpi_idle_uses_per_cpu_drivers;

static struct cpuidle_driver *acpi_idle_driver_for_cpu(unsigned int cpu)
{
	if (READ_ONCE(acpi_idle_uses_per_cpu_drivers))
		return per_cpu(acpi_idle_cpu_driver, cpu);

	return &acpi_idle_driver;
}

static bool acpi_idle_driver_is_registered(unsigned int cpu)
{
	struct cpuidle_device dev = { .cpu = cpu };
	struct cpuidle_driver *drv = acpi_idle_driver_for_cpu(cpu);

	return drv && cpuidle_get_cpu_driver(&dev) == drv;
}

#ifdef CONFIG_ACPI_PROCESSOR_CSTATE
void acpi_idle_rescan_dead_smt_siblings(void)
{
	if (cpuidle_get_driver() == &acpi_idle_driver)
		arch_cpu_rescan_dead_smt_siblings();
}

static
DEFINE_PER_CPU(struct acpi_processor_cx * [CPUIDLE_STATE_MAX], acpi_cstate);

static int disabled_by_idle_boot_param(void)
{
	return boot_option_idle_override == IDLE_POLL ||
		boot_option_idle_override == IDLE_HALT;
}

/*
 * IBM ThinkPad R40e crashes mysteriously when going into C2 or C3.
 * For now disable this. Probably a bug somewhere else.
 *
 * To skip this limit, boot/load with a large max_cstate limit.
 */
static int set_max_cstate(const struct dmi_system_id *id)
{
	if (max_cstate > ACPI_PROCESSOR_MAX_POWER)
		return 0;

	pr_notice("%s detected - limiting to C%ld max_cstate."
		  " Override with \"processor.max_cstate=%d\"\n", id->ident,
		  (long)id->driver_data, ACPI_PROCESSOR_MAX_POWER + 1);

	max_cstate = (long)id->driver_data;

	return 0;
}

static const struct dmi_system_id processor_power_dmi_table[] = {
	{ set_max_cstate, "Clevo 5600D", {
	  DMI_MATCH(DMI_BIOS_VENDOR,"Phoenix Technologies LTD"),
	  DMI_MATCH(DMI_BIOS_VERSION,"SHE845M0.86C.0013.D.0302131307")},
	 (void *)2},
	{ set_max_cstate, "Pavilion zv5000", {
	  DMI_MATCH(DMI_SYS_VENDOR, "Hewlett-Packard"),
	  DMI_MATCH(DMI_PRODUCT_NAME,"Pavilion zv5000 (DS502A#ABA)")},
	 (void *)1},
	{ set_max_cstate, "Asus L8400B", {
	  DMI_MATCH(DMI_SYS_VENDOR, "ASUSTeK Computer Inc."),
	  DMI_MATCH(DMI_PRODUCT_NAME,"L8400B series Notebook PC")},
	 (void *)1},
	{},
};


/*
 * Callers should disable interrupts before the call and enable
 * interrupts after return.
 */
static void __cpuidle acpi_safe_halt(void)
{
	if (!tif_need_resched()) {
		raw_safe_halt();
		raw_local_irq_disable();
	}
}

#ifdef ARCH_APICTIMER_STOPS_ON_C3

/*
 * Some BIOS implementations switch to C3 in the published C2 state.
 * This seems to be a common problem on AMD boxen, but other vendors
 * are affected too. We pick the most conservative approach: we assume
 * that the local APIC stops in both C2 and C3.
 */
static void lapic_timer_check_state(int state, struct acpi_processor *pr,
				   struct acpi_processor_cx *cx)
{
	struct acpi_processor_power *pwr = &pr->power;
	u8 type = local_apic_timer_c2_ok ? ACPI_STATE_C3 : ACPI_STATE_C2;

	if (cpu_has(&cpu_data(pr->id), X86_FEATURE_ARAT))
		return;

	if (boot_cpu_has_bug(X86_BUG_AMD_APIC_C1E))
		type = ACPI_STATE_C1;

	/*
	 * Check, if one of the previous states already marked the lapic
	 * unstable
	 */
	if (pwr->timer_broadcast_on_state < state)
		return;

	if (cx->type >= type)
		pr->power.timer_broadcast_on_state = state;
}

static void __lapic_timer_propagate_broadcast(void *arg)
{
	struct acpi_processor *pr = arg;

	if (pr->power.timer_broadcast_on_state < INT_MAX)
		tick_broadcast_enable();
	else
		tick_broadcast_disable();
}

static void lapic_timer_propagate_broadcast(struct acpi_processor *pr)
{
	smp_call_function_single(pr->id, __lapic_timer_propagate_broadcast,
				 (void *)pr, 1);
}

/* Power(C) State timer broadcast control */
static bool lapic_timer_needs_broadcast(struct acpi_processor *pr,
					struct acpi_processor_cx *cx)
{
	return cx - pr->power.states >= pr->power.timer_broadcast_on_state;
}

#else

static void lapic_timer_check_state(int state, struct acpi_processor *pr,
				   struct acpi_processor_cx *cstate) { }
static void lapic_timer_propagate_broadcast(struct acpi_processor *pr) { }

static bool lapic_timer_needs_broadcast(struct acpi_processor *pr,
					struct acpi_processor_cx *cx)
{
	return false;
}

#endif

#if defined(CONFIG_X86)
static void tsc_check_state(int state)
{
	switch (boot_cpu_data.x86_vendor) {
	case X86_VENDOR_HYGON:
	case X86_VENDOR_AMD:
	case X86_VENDOR_INTEL:
	case X86_VENDOR_CENTAUR:
	case X86_VENDOR_ZHAOXIN:
		/*
		 * AMD Fam10h TSC will tick in all
		 * C/P/S0/S1 states when this bit is set.
		 */
		if (boot_cpu_has(X86_FEATURE_NONSTOP_TSC))
			return;
		fallthrough;
	default:
		/* TSC could halt in idle, so notify users */
		if (state > ACPI_STATE_C1)
			mark_tsc_unstable("TSC halts in idle");
	}
}
#else
static void tsc_check_state(int state) { return; }
#endif

static int acpi_processor_get_power_info_fadt(struct acpi_processor *pr)
{

	if (!pr->pblk)
		return -ENODEV;

	/* if info is obtained from pblk/fadt, type equals state */
	pr->power.states[ACPI_STATE_C2].type = ACPI_STATE_C2;
	pr->power.states[ACPI_STATE_C3].type = ACPI_STATE_C3;

#ifndef CONFIG_HOTPLUG_CPU
	/*
	 * Check for P_LVL2_UP flag before entering C2 and above on
	 * an SMP system.
	 */
	if ((num_online_cpus() > 1) &&
	    !(acpi_gbl_FADT.flags & ACPI_FADT_C2_MP_SUPPORTED))
		return -ENODEV;
#endif

	/* determine C2 and C3 address from pblk */
	pr->power.states[ACPI_STATE_C2].address = pr->pblk + 4;
	pr->power.states[ACPI_STATE_C3].address = pr->pblk + 5;

	/* determine latencies from FADT */
	pr->power.states[ACPI_STATE_C2].latency = acpi_gbl_FADT.c2_latency;
	pr->power.states[ACPI_STATE_C3].latency = acpi_gbl_FADT.c3_latency;

	/*
	 * FADT specified C2 latency must be less than or equal to
	 * 100 microseconds.
	 */
	if (acpi_gbl_FADT.c2_latency > ACPI_PROCESSOR_MAX_C2_LATENCY) {
		acpi_handle_debug(pr->handle, "C2 latency too large [%d]\n",
				  acpi_gbl_FADT.c2_latency);
		/* invalidate C2 */
		pr->power.states[ACPI_STATE_C2].address = 0;
	}

	/*
	 * FADT supplied C3 latency must be less than or equal to
	 * 1000 microseconds.
	 */
	if (acpi_gbl_FADT.c3_latency > ACPI_PROCESSOR_MAX_C3_LATENCY) {
		acpi_handle_debug(pr->handle, "C3 latency too large [%d]\n",
				  acpi_gbl_FADT.c3_latency);
		/* invalidate C3 */
		pr->power.states[ACPI_STATE_C3].address = 0;
	}

	acpi_handle_debug(pr->handle, "lvl2[0x%08x] lvl3[0x%08x]\n",
			  pr->power.states[ACPI_STATE_C2].address,
			  pr->power.states[ACPI_STATE_C3].address);

	snprintf(pr->power.states[ACPI_STATE_C2].desc,
			 ACPI_CX_DESC_LEN, "ACPI P_LVL2 IOPORT 0x%x",
			 pr->power.states[ACPI_STATE_C2].address);
	snprintf(pr->power.states[ACPI_STATE_C3].desc,
			 ACPI_CX_DESC_LEN, "ACPI P_LVL3 IOPORT 0x%x",
			 pr->power.states[ACPI_STATE_C3].address);

	if (!pr->power.states[ACPI_STATE_C2].address &&
	    !pr->power.states[ACPI_STATE_C3].address)
		return -ENODEV;

	return 0;
}

static int acpi_processor_get_power_info_default(struct acpi_processor *pr)
{
	if (!pr->power.states[ACPI_STATE_C1].valid) {
		/* set the first C-State to C1 */
		/* all processors need to support C1 */
		pr->power.states[ACPI_STATE_C1].type = ACPI_STATE_C1;
		pr->power.states[ACPI_STATE_C1].valid = 1;
		pr->power.states[ACPI_STATE_C1].entry_method = ACPI_CSTATE_HALT;

		snprintf(pr->power.states[ACPI_STATE_C1].desc,
			 ACPI_CX_DESC_LEN, "ACPI HLT");
	}
	/* the C0 state only exists as a filler in our array */
	pr->power.states[ACPI_STATE_C0].valid = 1;
	return 0;
}

static int acpi_processor_get_power_info_cst(struct acpi_processor *pr)
{
	int ret;

	if (nocst)
		return -ENODEV;

	ret = acpi_processor_evaluate_cst(pr->handle, pr->id, &pr->power);
	if (ret)
		return ret;

	if (!pr->power.count)
		return -EFAULT;

	pr->flags.has_cst = 1;
	return 0;
}

static void acpi_processor_power_verify_c3(struct acpi_processor *pr,
					   struct acpi_processor_cx *cx)
{
	static int bm_check_flag = -1;
	static int bm_control_flag = -1;


	if (!cx->address)
		return;

	/*
	 * PIIX4 Erratum #18: We don't support C3 when Type-F (fast)
	 * DMA transfers are used by any ISA device to avoid livelock.
	 * Note that we could disable Type-F DMA (as recommended by
	 * the erratum), but this is known to disrupt certain ISA
	 * devices thus we take the conservative approach.
	 */
	if (errata.piix4.fdma) {
		acpi_handle_debug(pr->handle,
				  "C3 not supported on PIIX4 with Type-F DMA\n");
		return;
	}

	/* All the logic here assumes flags.bm_check is same across all CPUs */
	if (bm_check_flag == -1) {
		/* Determine whether bm_check is needed based on CPU  */
		acpi_processor_power_init_bm_check(&(pr->flags), pr->id);
		bm_check_flag = pr->flags.bm_check;
		bm_control_flag = pr->flags.bm_control;
	} else {
		pr->flags.bm_check = bm_check_flag;
		pr->flags.bm_control = bm_control_flag;
	}

	if (pr->flags.bm_check) {
		if (!pr->flags.bm_control) {
			if (pr->flags.has_cst != 1) {
				/* bus mastering control is necessary */
				acpi_handle_debug(pr->handle,
						  "C3 support requires BM control\n");
				return;
			} else {
				/* Here we enter C3 without bus mastering */
				acpi_handle_debug(pr->handle,
						  "C3 support without BM control\n");
			}
		}
	} else {
		/*
		 * WBINVD should be set in fadt, for C3 state to be
		 * supported on when bm_check is not required.
		 */
		if (!(acpi_gbl_FADT.flags & ACPI_FADT_WBINVD)) {
			acpi_handle_debug(pr->handle,
					  "Cache invalidation should work properly"
					  " for C3 to be enabled on SMP systems\n");
			return;
		}
	}

	/*
	 * Otherwise we've met all of our C3 requirements.
	 * Normalize the C3 latency to expidite policy.  Enable
	 * checking of bus mastering status (bm_check) so we can
	 * use this in our C3 policy
	 */
	cx->valid = 1;

	/*
	 * On older chipsets, BM_RLD needs to be set
	 * in order for Bus Master activity to wake the
	 * system from C3.  Newer chipsets handle DMA
	 * during C3 automatically and BM_RLD is a NOP.
	 * In either case, the proper way to
	 * handle BM_RLD is to set it and leave it set.
	 */
	acpi_write_bit_register(ACPI_BITREG_BUS_MASTER_RLD, 1);
}

static void acpi_cst_latency_sort(struct acpi_processor_cx *states, size_t length)
{
	int i, j, k;

	for (i = 1; i < length; i++) {
		if (!states[i].valid)
			continue;

		for (j = i - 1, k = i; j >= 0; j--) {
			if (!states[j].valid)
				continue;

			if (states[j].latency > states[k].latency)
				swap(states[j].latency, states[k].latency);

			k = j;
		}
	}
}

static int acpi_processor_power_verify(struct acpi_processor *pr)
{
	unsigned int i;
	unsigned int working = 0;
	unsigned int last_latency = 0;
	unsigned int last_type = 0;
	bool buggy_latency = false;

	pr->power.timer_broadcast_on_state = INT_MAX;

	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER && i <= max_cstate; i++) {
		struct acpi_processor_cx *cx = &pr->power.states[i];

		switch (cx->type) {
		case ACPI_STATE_C1:
			cx->valid = 1;
			break;

		case ACPI_STATE_C2:
			if (!cx->address)
				break;
			cx->valid = 1;
			break;

		case ACPI_STATE_C3:
			acpi_processor_power_verify_c3(pr, cx);
			break;
		}
		if (!cx->valid)
			continue;
		if (cx->type >= last_type && cx->latency < last_latency)
			buggy_latency = true;
		last_latency = cx->latency;
		last_type = cx->type;

		lapic_timer_check_state(i, pr, cx);
		tsc_check_state(cx->type);
		working++;
	}

	if (buggy_latency) {
		pr_notice("FW issue: working around C-state latencies out of order\n");
		acpi_cst_latency_sort(&pr->power.states[1], max_cstate);
	}

	lapic_timer_propagate_broadcast(pr);

	return working;
}

static int acpi_processor_get_cstate_info(struct acpi_processor *pr)
{
	int result;

	/* NOTE: the idle thread may not be running while calling
	 * this function */

	/* Zero initialize all the C-states info. */
	memset(pr->power.states, 0, sizeof(pr->power.states));

	result = acpi_processor_get_power_info_cst(pr);
	if (result == -ENODEV)
		result = acpi_processor_get_power_info_fadt(pr);

	if (result)
		return result;

	acpi_processor_get_power_info_default(pr);

	pr->power.count = acpi_processor_power_verify(pr);
	pr->flags.power = 1;

	return 0;
}

/**
 * acpi_idle_bm_check - checks if bus master activity was detected
 */
static int acpi_idle_bm_check(void)
{
	u32 bm_status = 0;

	if (bm_check_disable)
		return 0;

	acpi_read_bit_register(ACPI_BITREG_BUS_MASTER_STATUS, &bm_status);
	if (bm_status)
		acpi_write_bit_register(ACPI_BITREG_BUS_MASTER_STATUS, 1);
	/*
	 * PIIX4 Erratum #18: Note that BM_STS doesn't always reflect
	 * the true state of bus mastering activity; forcing us to
	 * manually check the BMIDEA bit of each IDE channel.
	 */
	else if (errata.piix4.bmisx) {
		if ((inb_p(errata.piix4.bmisx + 0x02) & 0x01)
		    || (inb_p(errata.piix4.bmisx + 0x0A) & 0x01))
			bm_status = 1;
	}
	return bm_status;
}

static __cpuidle void io_idle(unsigned long addr)
{
	/* IO port based C-state */
	inb(addr);

#ifdef	CONFIG_X86
	/* No delay is needed if we are in guest */
	if (boot_cpu_has(X86_FEATURE_HYPERVISOR))
		return;
	/*
	 * Modern (>=Nehalem) Intel systems use ACPI via intel_idle,
	 * not this code.  Assume that any Intel systems using this
	 * are ancient and may need the dummy wait.  This also assumes
	 * that the motivating chipset issue was Intel-only.
	 */
	if (boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		return;
#endif
	/*
	 * Dummy wait op - must do something useless after P_LVL2 read
	 * because chipsets cannot guarantee that STPCLK# signal gets
	 * asserted in time to freeze execution properly
	 *
	 * This workaround has been in place since the original ACPI
	 * implementation was merged, circa 2002.
	 *
	 * If a profile is pointing to this instruction, please first
	 * consider moving your system to a more modern idle
	 * mechanism.
	 */
	inl(acpi_gbl_FADT.xpm_timer_block.address);
}

/**
 * acpi_idle_do_entry - enter idle state using the appropriate method
 * @cx: cstate data
 *
 * Caller disables interrupt before call and enables interrupt after return.
 */
static void __cpuidle acpi_idle_do_entry(struct acpi_processor_cx *cx)
{
	perf_lopwr_cb(true);

	if (cx->entry_method == ACPI_CSTATE_FFH) {
		/* Call into architectural FFH based C-state */
		acpi_processor_ffh_cstate_enter(cx);
	} else if (cx->entry_method == ACPI_CSTATE_HALT) {
		acpi_safe_halt();
	} else {
		io_idle(cx->address);
	}

	perf_lopwr_cb(false);
}

/**
 * acpi_idle_play_dead - enters an ACPI state for long-term idle (i.e. off-lining)
 * @dev: the target CPU
 * @index: the index of suggested state
 */
static void acpi_idle_play_dead(struct cpuidle_device *dev, int index)
{
	struct acpi_processor_cx *cx = per_cpu(acpi_cstate[index], dev->cpu);

	ACPI_FLUSH_CPU_CACHE();

	while (1) {

		if (cx->entry_method == ACPI_CSTATE_HALT)
			raw_safe_halt();
		else if (cx->entry_method == ACPI_CSTATE_SYSTEMIO) {
			io_idle(cx->address);
		} else if (cx->entry_method == ACPI_CSTATE_FFH) {
			acpi_processor_ffh_play_dead(cx);
		} else
			return;
	}
}

static __always_inline bool acpi_idle_fallback_to_c1(struct acpi_processor *pr)
{
	return IS_ENABLED(CONFIG_HOTPLUG_CPU) && !pr->flags.has_cst &&
		!(acpi_gbl_FADT.flags & ACPI_FADT_C2_MP_SUPPORTED);
}

static int c3_cpu_count;
static DEFINE_RAW_SPINLOCK(c3_lock);

/**
 * acpi_idle_enter_bm - enters C3 with proper BM handling
 * @drv: cpuidle driver
 * @pr: Target processor
 * @cx: Target state context
 * @index: index of target state
 */
static int __cpuidle acpi_idle_enter_bm(struct cpuidle_driver *drv,
			       struct acpi_processor *pr,
			       struct acpi_processor_cx *cx,
			       int index)
{
	static struct acpi_processor_cx safe_cx = {
		.entry_method = ACPI_CSTATE_HALT,
	};

	/*
	 * disable bus master
	 * bm_check implies we need ARB_DIS
	 * bm_control implies whether we can do ARB_DIS
	 *
	 * That leaves a case where bm_check is set and bm_control is not set.
	 * In that case we cannot do much, we enter C3 without doing anything.
	 */
	bool dis_bm = pr->flags.bm_control;

	instrumentation_begin();

	/* If we can skip BM, demote to a safe state. */
	if (!cx->bm_sts_skip && acpi_idle_bm_check()) {
		dis_bm = false;
		index = drv->safe_state_index;
		if (index >= 0) {
			cx = this_cpu_read(acpi_cstate[index]);
		} else {
			cx = &safe_cx;
			index = -EBUSY;
		}
	}

	if (dis_bm) {
		raw_spin_lock(&c3_lock);
		c3_cpu_count++;
		/* Disable bus master arbitration when all CPUs are in C3 */
		if (c3_cpu_count == num_online_cpus())
			acpi_write_bit_register(ACPI_BITREG_ARB_DISABLE, 1);
		raw_spin_unlock(&c3_lock);
	}

	ct_cpuidle_enter();

	acpi_idle_do_entry(cx);

	ct_cpuidle_exit();

	/* Re-enable bus master arbitration */
	if (dis_bm) {
		raw_spin_lock(&c3_lock);
		acpi_write_bit_register(ACPI_BITREG_ARB_DISABLE, 0);
		c3_cpu_count--;
		raw_spin_unlock(&c3_lock);
	}

	instrumentation_end();

	return index;
}

static int __cpuidle acpi_idle_enter(struct cpuidle_device *dev,
			   struct cpuidle_driver *drv, int index)
{
	struct acpi_processor_cx *cx = per_cpu(acpi_cstate[index], dev->cpu);
	struct acpi_processor *pr;

	pr = __this_cpu_read(processors);
	if (unlikely(!pr))
		return -EINVAL;

	if (cx->type != ACPI_STATE_C1) {
		if (cx->type == ACPI_STATE_C3 && pr->flags.bm_check)
			return acpi_idle_enter_bm(drv, pr, cx, index);

		/* C2 to C1 demotion. */
		if (acpi_idle_fallback_to_c1(pr) && num_online_cpus() > 1) {
			index = ACPI_IDLE_STATE_START;
			cx = per_cpu(acpi_cstate[index], dev->cpu);
		}
	}

	if (cx->type == ACPI_STATE_C3)
		ACPI_FLUSH_CPU_CACHE();

	acpi_idle_do_entry(cx);

	return index;
}

static int __cpuidle acpi_idle_enter_s2idle(struct cpuidle_device *dev,
				  struct cpuidle_driver *drv, int index)
{
	struct acpi_processor_cx *cx = per_cpu(acpi_cstate[index], dev->cpu);

	if (cx->type == ACPI_STATE_C3) {
		struct acpi_processor *pr = __this_cpu_read(processors);

		if (unlikely(!pr))
			return 0;

		if (pr->flags.bm_check) {
			u8 bm_sts_skip = cx->bm_sts_skip;

			/* Don't check BM_STS, do an unconditional ARB_DIS for S2IDLE */
			cx->bm_sts_skip = 1;
			acpi_idle_enter_bm(drv, pr, cx, index);
			cx->bm_sts_skip = bm_sts_skip;

			return 0;
		} else {
			ACPI_FLUSH_CPU_CACHE();
		}
	}
	acpi_idle_do_entry(cx);

	return 0;
}

static void acpi_processor_setup_cpuidle_cx(struct acpi_processor *pr,
					    struct cpuidle_device *dev)
{
	int i, count = ACPI_IDLE_STATE_START;
	struct acpi_processor_cx *cx;

	if (max_cstate == 0)
		max_cstate = 1;

	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER && i <= max_cstate; i++) {
		cx = &pr->power.states[i];

		if (!cx->valid)
			continue;

		per_cpu(acpi_cstate[count], dev->cpu) = cx;

		count++;
		if (count == CPUIDLE_STATE_MAX)
			break;
	}
}

static void acpi_processor_setup_cstates(struct acpi_processor *pr,
					 struct cpuidle_driver *drv)
{
	int i, count;
	struct acpi_processor_cx *cx;
	struct cpuidle_state *state;

	if (max_cstate == 0)
		max_cstate = 1;

	if (IS_ENABLED(CONFIG_ARCH_HAS_CPU_RELAX)) {
		cpuidle_poll_state_init(drv);
		count = 1;
	} else {
		count = 0;
	}

	for (i = 1; i < ACPI_PROCESSOR_MAX_POWER && i <= max_cstate; i++) {
		cx = &pr->power.states[i];

		if (!cx->valid)
			continue;

		state = &drv->states[count];
		snprintf(state->name, CPUIDLE_NAME_LEN, "C%d", i);
		strscpy(state->desc, cx->desc, CPUIDLE_DESC_LEN);
		state->exit_latency = cx->latency;
		state->target_residency = cx->latency * latency_factor;
		state->enter = acpi_idle_enter;

		state->flags = 0;

		state->enter_dead = acpi_idle_play_dead;

		if (cx->type == ACPI_STATE_C1 || cx->type == ACPI_STATE_C2)
			drv->safe_state_index = count;

		/*
		 * Halt-induced C1 is not good for ->enter_s2idle, because it
		 * re-enables interrupts on exit.  Moreover, C1 is generally not
		 * particularly interesting from the suspend-to-idle angle, so
		 * avoid C1 and the situations in which we may need to fall back
		 * to it altogether.
		 */
		if (cx->type != ACPI_STATE_C1 && !acpi_idle_fallback_to_c1(pr))
			state->enter_s2idle = acpi_idle_enter_s2idle;

		if (lapic_timer_needs_broadcast(pr, cx))
			state->flags |= CPUIDLE_FLAG_TIMER_STOP;

		if (cx->type == ACPI_STATE_C3) {
			state->flags |= CPUIDLE_FLAG_TLB_FLUSHED;
			if (pr->flags.bm_check)
				state->flags |= CPUIDLE_FLAG_RCU_IDLE;
		}

		count++;
		if (count == CPUIDLE_STATE_MAX)
			break;
	}

	drv->state_count = count;
}

static inline void acpi_processor_update_max_cstate(void)
{
	dmi_check_system(processor_power_dmi_table);
	max_cstate = acpi_processor_cstate_check(max_cstate);
	if (max_cstate < ACPI_C_STATES_MAX)
		pr_notice("processor limited to max C-state %d\n", max_cstate);

	if (nocst)
		return;

	acpi_processor_claim_cst_control();
}
#else

static inline int disabled_by_idle_boot_param(void) { return 0; }
static inline void acpi_processor_update_max_cstate(void) { }
static int acpi_processor_get_cstate_info(struct acpi_processor *pr)
{
	return -ENODEV;
}

static int acpi_processor_setup_cpuidle_cx(struct acpi_processor *pr,
					   struct cpuidle_device *dev)
{
	return -EINVAL;
}

static void acpi_processor_setup_cstates(struct acpi_processor *pr,
					 struct cpuidle_driver *drv)
{
}

#endif /* CONFIG_ACPI_PROCESSOR_CSTATE */

int __weak acpi_processor_ffh_lpi_probe(unsigned int cpu)
{
	return -EOPNOTSUPP;
}

bool __weak
acpi_processor_ffh_lpi_is_wfi(const struct acpi_lpi_state *lpi)
{
	return false;
}

bool __weak acpi_processor_ffh_lpi_hierarchy_supported(void)
{
	return false;
}

int __weak acpi_processor_ffh_lpi_set_mode(bool enable)
{
	return -EOPNOTSUPP;
}

int __weak acpi_processor_ffh_lpi_prepare_state(struct acpi_lpi_state *lpi)
{
	return -EOPNOTSUPP;
}

static bool acpi_lpi_can_coordinate(void)
{
	/* The arm64 FFH hooks are intentionally not linked to processor.ko. */
	return IS_BUILTIN(CONFIG_ACPI_PROCESSOR) &&
	       acpi_processor_ffh_lpi_hierarchy_supported();
}

static struct acpi_lpi_genpd_map_entry *acpi_lpi_get_domain(acpi_handle handle)
{
	struct acpi_lpi_genpd_map_entry *entry;

	list_for_each_entry(entry, &domain_map, node)
		if (entry->handle == handle)
			return entry;

	return NULL;
}

static void acpi_lpi_pd_free_states(struct genpd_power_state *states,
				    unsigned int state_count)
{
	kfree(states);
}

static bool acpi_lpi_state_enabled(const struct acpi_lpi_state *lpi)
{
	return lpi->flags & ACPI_LPI_STATE_FLAGS_ENABLED;
}

static bool acpi_lpi_is_usable_leaf_state(const struct acpi_lpi_state *lpi)
{
	return acpi_lpi_state_enabled(lpi) &&
	       lpi->entry_method != ACPI_CSTATE_INTEGER;
}

static int
acpi_lpi_prepare_leaf_domain_states(const struct acpi_lpi_state *lpi_states,
				    unsigned int lpi_state_count,
				    unsigned int *leaf_lpi_count,
				    struct acpi_lpi_state **domain_states,
				    unsigned int *domain_state_count)
{
	const struct acpi_lpi_state *deepest = NULL;
	unsigned int i;

	/*
	 * WFI remains a direct cpuidle state because it does not suspend the
	 * CPU power domain or compose with parent states. The CPU leaf domain
	 * contains only the deepest non-WFI local state used to trigger domain
	 * coordination.
	 */
	*leaf_lpi_count = 0;
	*domain_state_count = 0;
	for (i = 0; i < lpi_state_count; i++) {
		const struct acpi_lpi_state *lpi = &lpi_states[i];

		if (!acpi_lpi_is_usable_leaf_state(lpi))
			continue;
		if (*leaf_lpi_count >= ACPI_PROCESSOR_MAX_POWER)
			break;

		(*leaf_lpi_count)++;
		if (!acpi_processor_ffh_lpi_is_wfi(lpi))
			deepest = lpi;
	}

	if (!deepest)
		return 0;

	*domain_states = kmemdup(deepest, sizeof(*deepest), GFP_KERNEL);
	if (!*domain_states)
		return -ENOMEM;

	*domain_state_count = 1;
	return 0;
}

static int acpi_lpi_create_domain(acpi_handle handle,
				  const struct acpi_lpi_state *lpi_states,
				  unsigned int lpi_state_count,
				  struct acpi_lpi_genpd_map_entry **map_entry)
{
	struct acpi_lpi_genpd_map_entry *entry;
	struct genpd_power_state *genpd_states;
	struct generic_pm_domain *pd;
	struct acpi_device *adev;
	const char *hid, *name, *uid;
	unsigned int i;
	int ret;

	if (acpi_lpi_get_domain(handle))
		return -EEXIST;

	adev = acpi_fetch_acpi_dev(handle);
	if (!adev)
		return -ENODEV;

	pd = kzalloc_obj(*pd);
	if (!pd)
		return -ENOMEM;

	genpd_states = kzalloc_objs(*genpd_states, lpi_state_count);
	if (!genpd_states) {
		ret = -ENOMEM;
		goto free_pd;
	}

	for (i = 0; i < lpi_state_count; i++) {
		const struct acpi_lpi_state *lpi = &lpi_states[i];

		genpd_states[i].power_on_latency_ns =
			(u64)lpi->wake_latency * NSEC_PER_USEC;
		genpd_states[i].residency_ns =
			(u64)lpi->min_residency * NSEC_PER_USEC;
		genpd_states[i].fwnode = acpi_fwnode_handle(adev);
	}

	hid = acpi_device_hid(adev);
	name = hid;
	if (!name || !name[0])
		name = acpi_dev_name(adev);
	uid = acpi_device_uid(adev);
	if (!uid || !uid[0])
		uid = acpi_dev_name(adev);

	pd->name = kasprintf(GFP_KERNEL, "%s:%s", name, uid);
	if (!pd->name) {
		ret = -ENOMEM;
		goto free_states;
	}

	pd->states = genpd_states;
	pd->state_count = lpi_state_count;
	pd->flags = GENPD_FLAG_CPU_DOMAIN | GENPD_FLAG_MIN_RESIDENCY |
		    GENPD_FLAG_IRQ_SAFE | GENPD_FLAG_ACTIVE_WAKEUP |
		    GENPD_FLAG_NO_STAY_ON;
	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		pd->flags |= GENPD_FLAG_RPM_ALWAYS_ON;
	pd->free_states = acpi_lpi_pd_free_states;

	entry = kzalloc_obj(*entry);
	if (!entry) {
		ret = -ENOMEM;
		goto free_name;
	}
	entry->lpi_states = kmemdup_array(lpi_states, lpi_state_count,
					  sizeof(*lpi_states), GFP_KERNEL);
	if (!entry->lpi_states) {
		ret = -ENOMEM;
		goto free_entry;
	}
	entry->lpi_state_count = lpi_state_count;

	ret = pm_genpd_init(pd, ACPI_LPI_GENPD_GOVERNOR, false);
	if (ret)
		goto free_lpi_states;

	entry->handle = handle;
	entry->genpd = pd;
	list_add_tail(&entry->node, &domain_map);
	*map_entry = entry;
	return 0;

free_lpi_states:
	kfree(entry->lpi_states);
free_entry:
	kfree(entry);
free_name:
	kfree(pd->name);
free_states:
	kfree(genpd_states);
free_pd:
	kfree(pd);
	return ret;
}

static int acpi_lpi_remove_domain(struct acpi_lpi_genpd_map_entry *entry)
{
	struct generic_pm_domain *pd = entry->genpd;
	struct acpi_idle_data *data;
	int cpu;
	int ret;

	lockdep_assert_held(&domain_map_lock);

	for_each_possible_cpu(cpu) {
		data = per_cpu(acpi_idle_data, cpu);
		if (data && data->base_map_entry == entry)
			return -EBUSY;
	}
	if (!cpumask_empty(pd->cpus))
		return -EBUSY;

	ret = pm_genpd_remove(pd);
	if (ret)
		return ret;

	list_del(&entry->node);
	kfree(entry->lpi_states);
	kfree(pd->name);
	kfree(pd);
	kfree(entry);
	return 0;
}

static int acpi_lpi_remove_unused_domains(void)
{
	struct acpi_lpi_genpd_map_entry *entry, *tmp;
	int first_ret = 0;
	int ret;

	mutex_lock(&domain_map_lock);
	list_for_each_entry_safe(entry, tmp, &domain_map, node) {
		ret = acpi_lpi_remove_domain(entry);
		if (ret == -EBUSY)
			continue;
		if (ret && !first_ret)
			first_ret = ret;
	}
	mutex_unlock(&domain_map_lock);

	return first_ret;
}

struct acpi_lpi_leaf_init_data {
	struct acpi_idle_data *data;
};

static int acpi_lpi_leaf_init_cb(acpi_handle handle,
				 const struct acpi_lpi_state *lpi_states,
				 unsigned int lpi_state_count,
				 unsigned int level, void *arg)
{
	struct acpi_lpi_leaf_init_data *init_data = arg;
	struct acpi_lpi_state *domain_states = NULL;
	unsigned int domain_state_count;
	int ret;

	if (level)
		return 0;

	ret = acpi_lpi_prepare_leaf_domain_states(lpi_states, lpi_state_count,
						  &init_data->data->leaf_lpi_count,
						  &domain_states,
						  &domain_state_count);
	if (ret || !domain_state_count)
		goto out;

	mutex_lock(&domain_map_lock);
	ret = acpi_lpi_create_domain(handle, domain_states,
				     domain_state_count,
				     &init_data->data->base_map_entry);
	mutex_unlock(&domain_map_lock);

out:
	kfree(domain_states);
	return ret;
}

static int acpi_processor_free_idle_data(struct acpi_processor *pr)
{
	struct acpi_idle_data *data = per_cpu(acpi_idle_data, pr->id);
	struct acpi_lpi_genpd_map_entry *base;
	int ret;

	if (!data)
		return 0;

	base = data->base_map_entry;
	data->base_map_entry = NULL;
	ret = acpi_lpi_remove_unused_domains();
	if (ret) {
		data->base_map_entry = base;
		return ret;
	}

	kfree(data);
	per_cpu(acpi_idle_data, pr->id) = NULL;
	return 0;
}

static int acpi_processor_lpi_fallback_flat(struct acpi_processor *pr)
{
	int ret;

	ret = acpi_processor_free_idle_data(pr);
	if (ret)
		return ret;

	ret = acpi_processor_extract_lpi_info(pr->handle, &pr->power, false);
	if (ret)
		return ret;

	pr->flags.has_lpi = 1;
	pr->flags.power = 1;
	return 0;
}

static int acpi_processor_get_lpi_info(struct acpi_processor *pr)
{
	struct acpi_lpi_leaf_init_data init_data;
	struct acpi_idle_data *data;
	int ret;

	ret = acpi_processor_free_idle_data(pr);
	if (ret)
		return ret;

	pr->flags.has_lpi = 0;
	pr->flags.power = 0;

	/* make sure our architecture has support */
	ret = acpi_processor_ffh_lpi_probe(pr->id);
	if (ret == -EOPNOTSUPP)
		return ret;

	if (!IS_ENABLED(CONFIG_PM_GENERIC_DOMAINS) ||
	    !acpi_lpi_can_coordinate())
		return acpi_processor_lpi_fallback_flat(pr);

	data = kzalloc_obj(*data);
	if (!data)
		return -ENOMEM;
	per_cpu(acpi_idle_data, pr->id) = data;
	init_data.data = data;

	ret = acpi_processor_extract_lpi_info_cb(pr->handle, &pr->power, false,
						 acpi_lpi_leaf_init_cb,
						 &init_data);
	if (ret)
		return acpi_processor_lpi_fallback_flat(pr);
	if (!data->base_map_entry)
		return acpi_processor_lpi_fallback_flat(pr);

	/* Tell driver that _LPI is supported. */
	pr->flags.has_lpi = 1;
	pr->flags.power = 1;

	return 0;
}

int __weak __cpuidle acpi_processor_ffh_lpi_enter(struct acpi_lpi_state *lpi)
{
	return -ENODEV;
}

/**
 * acpi_idle_lpi_enter_direct - enter an ACPI LPI state directly
 * @dev: the target CPU
 * @drv: cpuidle driver containing cpuidle state info
 * @index: index of target state
 *
 * Return: cpuidle state index on success or negative value on error
 */
static int __cpuidle
acpi_idle_lpi_enter_direct(struct cpuidle_device *dev,
			   struct cpuidle_driver *drv, int index)
{
	struct acpi_processor *pr;
	struct acpi_lpi_state *lpi;
	int ret;

	pr = __this_cpu_read(processors);

	if (unlikely(!pr))
		return -EINVAL;

	lpi = &pr->power.lpi_states[index];
	if (lpi->entry_method != ACPI_CSTATE_FFH)
		return -EINVAL;

	ret = acpi_processor_ffh_lpi_enter(lpi);
	return ret < 0 ? ret : index;
}

static void acpi_processor_setup_lpi_states(struct acpi_processor *pr,
					    struct cpuidle_driver *drv)
{
	int i;
	struct acpi_lpi_state *lpi;
	struct cpuidle_state *state;

	if (!pr->flags.has_lpi)
		return;

	for (i = 0; i < pr->power.count && i < CPUIDLE_STATE_MAX; i++) {
		lpi = &pr->power.lpi_states[i];

		state = &drv->states[i];
		snprintf(state->name, CPUIDLE_NAME_LEN, "LPI-%d", i);
		strscpy(state->desc, lpi->desc, CPUIDLE_DESC_LEN);
		state->exit_latency = lpi->wake_latency;
		state->target_residency = lpi->min_residency;
		state->exit_latency_ns =
			mul_u32_u32(state->exit_latency, NSEC_PER_USEC);
		state->target_residency_ns =
			(u64)state->target_residency * NSEC_PER_USEC;
		state->flags = arch_get_idle_state_flags(lpi->arch_flags);
		if (i != 0 && lpi->entry_method == ACPI_CSTATE_FFH)
			state->flags |= CPUIDLE_FLAG_RCU_IDLE;
		state->enter = acpi_idle_lpi_enter_direct;
		drv->safe_state_index = i;
	}

	drv->state_count = i;
}

/**
 * acpi_processor_setup_cpuidle_states- prepares and configures cpuidle
 * global state data i.e. idle routines
 *
 * @pr: the ACPI processor
 */
static void acpi_processor_setup_cpuidle_states(struct acpi_processor *pr)
{
	int i;
	struct cpuidle_driver *drv = acpi_idle_driver_for_cpu(pr->id);

	if (!drv || !pr->flags.power_setup_done || !pr->flags.power)
		return;

	drv->safe_state_index = -1;
	for (i = ACPI_IDLE_STATE_START; i < CPUIDLE_STATE_MAX; i++)
		memset(&drv->states[i], 0, sizeof(drv->states[i]));

	if (pr->flags.has_lpi) {
		acpi_processor_setup_lpi_states(pr, drv);
		return;
	}

	acpi_processor_setup_cstates(pr, drv);
}

/**
 * acpi_processor_setup_cpuidle_dev - configures CPUIDLE
 * device i.e. per-cpu data
 *
 * @pr: the ACPI processor
 * @dev : the cpuidle device
 */
static void acpi_processor_setup_cpuidle_dev(struct acpi_processor *pr,
					     struct cpuidle_device *dev)
{
	if (!pr->flags.power_setup_done || !pr->flags.power || !dev)
		return;

	dev->cpu = pr->id;
	if (!pr->flags.has_lpi)
		acpi_processor_setup_cpuidle_cx(pr, dev);
}

static int acpi_processor_get_power_info(struct acpi_processor *pr)
{
	int ret;

	ret = acpi_processor_get_lpi_info(pr);
	if (ret)
		return acpi_processor_get_cstate_info(pr);

	if (pr->flags.has_lpi) {
		ret = acpi_processor_ffh_lpi_probe(pr->id);
		if (ret)
			pr_err("CPU%u: Invalid FFH LPI data\n", pr->id);
	}

	return ret;
}

int acpi_processor_hotplug(struct acpi_processor *pr)
{
	struct cpuidle_device *dev = per_cpu(acpi_cpuidle_device, pr->id);
	int ret = 0;

	if (disabled_by_idle_boot_param())
		return 0;

	if (!pr->flags.power_setup_done || !dev)
		return -ENODEV;

	cpuidle_pause_and_lock();
	cpuidle_disable_device(dev);
	ret = acpi_processor_get_power_info(pr);
	if (!ret && pr->flags.power) {
		if (READ_ONCE(acpi_idle_uses_per_cpu_drivers))
			acpi_processor_setup_cpuidle_states(pr);
		acpi_processor_setup_cpuidle_dev(pr, dev);
		ret = cpuidle_enable_device(dev);
	}
	cpuidle_resume_and_unlock();

	return ret;
}

int acpi_processor_power_state_has_changed(struct acpi_processor *pr)
{
	int cpu;
	int ret = 0;
	struct acpi_processor *_pr;
	struct cpuidle_device *dev;

	if (disabled_by_idle_boot_param())
		return 0;
	if (pr->id != 0)
		return 0;

	mutex_lock(&acpi_idle_rebuild_lock);
	if (!pr->flags.power_setup_done) {
		ret = -ENODEV;
		goto out;
	}

	/*
	 * FIXME:  Design the ACPI notification to make it once per
	 * system instead of once per-cpu.  This condition is a hack
	 * to make the code that updates C-States be called once.
	 */

	if (acpi_idle_driver_is_registered(pr->id)) {
		/* Protect against cpu-hotplug */
		cpus_read_lock();

		/* Unregister cpuidle device of all CPUs */
		cpuidle_pause_and_lock();
		for_each_possible_cpu(cpu) {
			dev = per_cpu(acpi_cpuidle_device, cpu);
			_pr = per_cpu(processors, cpu);
			if (!_pr || !_pr->flags.power || !dev)
				continue;

			cpuidle_unregister_device_no_lock(dev);
			per_cpu(acpi_cpuidle_device, cpu) = NULL;
			kfree(dev);
			_pr->flags.power = 0;
		}
		cpuidle_resume_and_unlock();

		/*
		 * Unregister ACPI idle driver, reinitialize ACPI idle states
		 * and register ACPI idle driver again.
		 */
		acpi_processor_unregister_idle_driver();
		acpi_processor_register_idle_driver();

		/*
		 * Reinitialize power information of all CPUs and re-register
		 * all cpuidle devices. Now idle states is ok to use, can enable
		 * cpuidle of each CPU safely one by one.
		 */
		for_each_possible_cpu(cpu) {
			_pr = per_cpu(processors, cpu);
			if (!_pr)
				continue;
			acpi_processor_power_init(_pr);
		}

		cpus_read_unlock();
	}

out:
	mutex_unlock(&acpi_idle_rebuild_lock);
	return ret;
}

static int acpi_processor_free_all_idle_data(void)
{
	struct acpi_processor *pr;
	int first_ret = 0;
	int ret;
	int cpu;

	for_each_possible_cpu(cpu) {
		pr = per_cpu(processors, cpu);
		if (!pr)
			continue;

		ret = acpi_processor_free_idle_data(pr);
		if (ret && !first_ret)
			first_ret = ret;
	}

	return first_ret;
}

static void acpi_processor_unregister_cpu_idle_drivers(void)
{
	struct cpuidle_driver *drv;
	int cpu;

	for_each_possible_cpu(cpu) {
		drv = per_cpu(acpi_idle_cpu_driver, cpu);
		if (!drv)
			continue;

		cpuidle_unregister_driver(drv);
		per_cpu(acpi_idle_cpu_driver, cpu) = NULL;
		kfree(drv);
	}

	WRITE_ONCE(acpi_idle_uses_per_cpu_drivers, false);
}

static int
acpi_processor_register_cpu_idle_drivers(struct acpi_processor *first_pr)
{
	struct cpuidle_driver *drv;
	struct acpi_processor *pr;
	bool found = false;
	int cleanup_ret;
	int ret = -ENODEV;
	int cpu;

	WRITE_ONCE(acpi_idle_uses_per_cpu_drivers, true);
	for_each_possible_cpu(cpu) {
		pr = per_cpu(processors, cpu);
		if (!pr)
			continue;

		if (pr != first_pr) {
			ret = acpi_processor_get_power_info(pr);
			if (ret)
				goto unregister;
			pr->flags.power_setup_done = 1;
		}

		if (!pr->flags.power || !pr->flags.has_lpi) {
			ret = -ENODEV;
			goto unregister;
		}

		drv = kzalloc_obj(*drv);
		if (!drv) {
			ret = -ENOMEM;
			goto unregister;
		}

		drv->name = "acpi_idle";
		drv->owner = THIS_MODULE;
		drv->cpumask = (struct cpumask *)cpumask_of(cpu);
		per_cpu(acpi_idle_cpu_driver, cpu) = drv;
		acpi_processor_setup_cpuidle_states(pr);

		ret = cpuidle_register_driver(drv);
		if (ret) {
			per_cpu(acpi_idle_cpu_driver, cpu) = NULL;
			kfree(drv);
			goto unregister;
		}

		found = true;
	}

	return found ? 0 : -ENODEV;

unregister:
	acpi_processor_unregister_cpu_idle_drivers();
	cleanup_ret = acpi_processor_free_all_idle_data();
	for_each_possible_cpu(cpu) {
		pr = per_cpu(processors, cpu);
		if (pr)
			pr->flags.power_setup_done = 0;
	}

	return cleanup_ret ?: ret;
}

void acpi_processor_register_idle_driver(void)
{
	struct acpi_processor *pr;
	int ret = -ENODEV;
	int cpu;

	/*
	 * If a cpuidle driver is already registered, there is no need to
	 * evaluate _CST or attempt to register the ACPI idle driver.
	 */
	if (cpuidle_get_driver()) {
		pr_debug("cpuidle driver %pS already registered.\n", cpuidle_get_driver());
		return;
	}

	acpi_processor_update_max_cstate();

	/*
	 * Use one processor's power information to select the driver model.
	 * Hierarchical LPI uses CPU-scoped drivers, while the legacy path uses
	 * that processor to initialize the shared driver. The existing idle
	 * handler is retained on platforms that only support C1.
	 */
	for_each_possible_cpu(cpu) {
		pr = per_cpu(processors, cpu);
		if (!pr)
			continue;

		ret = acpi_processor_get_power_info(pr);
		if (!ret) {
			pr->flags.power_setup_done = 1;
			if (IS_ENABLED(CONFIG_CPU_IDLE_MULTIPLE_DRIVERS) &&
			    pr->flags.has_lpi && acpi_lpi_can_coordinate()) {
				ret = acpi_processor_register_cpu_idle_drivers(pr);
				if (!ret) {
					pr_debug("per-CPU ACPI LPI drivers registered.\n");
					return;
				}

				/* A shared driver cannot represent unknown CPU tables. */
				pr_warn("per-CPU ACPI LPI driver setup failed: %d\n",
					ret);
				return;
			}
			acpi_processor_setup_cpuidle_states(pr);
			break;
		}
	}

	if (ret) {
		pr_debug("No ACPI power information from any CPUs.\n");
		return;
	}

	ret = cpuidle_register_driver(&acpi_idle_driver);
	if (ret) {
		int free_ret = acpi_processor_free_idle_data(pr);

		if (free_ret)
			pr_warn("failed to clean up CPU%u idle data: %d\n",
				pr->id, free_ret);
		pr->flags.power_setup_done = 0;
		pr_debug("register %s failed.\n", acpi_idle_driver.name);
		return;
	}
	pr_debug("%s registered with cpuidle.\n", acpi_idle_driver.name);
}

void acpi_processor_unregister_idle_driver(void)
{
	struct acpi_processor *pr;
	int ret;
	int cpu;

	ret = acpi_processor_free_all_idle_data();
	if (ret)
		pr_warn("failed to clean up ACPI idle domains: %d\n", ret);

	if (READ_ONCE(acpi_idle_uses_per_cpu_drivers))
		acpi_processor_unregister_cpu_idle_drivers();
	else
		cpuidle_unregister_driver(&acpi_idle_driver);

	for_each_possible_cpu(cpu) {
		pr = per_cpu(processors, cpu);
		if (!pr)
			continue;
		pr->flags.power_setup_done = 0;
	}
}

void acpi_processor_power_init(struct acpi_processor *pr)
{
	struct cpuidle_device *dev;
	int ret;

	/*
	 * The code below only works if this CPU is assigned to an ACPI idle
	 * driver.
	 */
	if (!acpi_idle_driver_is_registered(pr->id))
		return;

	if (disabled_by_idle_boot_param())
		return;

	ret = acpi_processor_get_power_info(pr);
	if (ret) {
		acpi_processor_free_idle_data(pr);
		pr->flags.power_setup_done = 0;
		return;
	}
	pr->flags.power_setup_done = 1;
	if (READ_ONCE(acpi_idle_uses_per_cpu_drivers))
		acpi_processor_setup_cpuidle_states(pr);

	if (!pr->flags.power)
		return;

	dev = kzalloc_obj(*dev);
	if (!dev) {
		acpi_processor_free_idle_data(pr);
		pr->flags.power_setup_done = 0;
		return;
	}

	per_cpu(acpi_cpuidle_device, pr->id) = dev;

	acpi_processor_setup_cpuidle_dev(pr, dev);

	/*
	 * Register a cpuidle device for this CPU.  The cpuidle driver using
	 * this device is expected to be registered.
	 */
	ret = cpuidle_register_device(dev);
	if (ret) {
		per_cpu(acpi_cpuidle_device, pr->id) = NULL;
		acpi_processor_free_idle_data(pr);
		pr->flags.power_setup_done = 0;
		kfree(dev);
	}
}

void acpi_processor_power_exit(struct acpi_processor *pr)
{
	struct cpuidle_device *dev = per_cpu(acpi_cpuidle_device, pr->id);
	int ret;

	if (disabled_by_idle_boot_param())
		return;

	if (pr->flags.power) {
		cpuidle_unregister_device(dev);
		per_cpu(acpi_cpuidle_device, pr->id) = NULL;
		kfree(dev);
	}

	ret = acpi_processor_free_idle_data(pr);
	if (ret)
		pr_warn("CPU%u: failed to clean up idle data: %d\n",
			pr->id, ret);

	pr->flags.power_setup_done = 0;
}

MODULE_IMPORT_NS("ACPI_PROCESSOR_IDLE");
