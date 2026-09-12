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
#include <linux/dmi.h>
#include <linux/sched.h>       /* need_resched() */
#include <linux/tick.h>
#include <linux/cpuidle.h>
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <linux/list.h>
#include <linux/minmax.h>
#include <linux/perf_event.h>
#include <acpi/processor.h>
#include <linux/context_tracking.h>
#include <linux/pm_domain.h>
#include <linux/pm_runtime.h>
#include <linux/smp.h>
#include <linux/string.h>
#include <linux/suspend.h>
#include <linux/syscore_ops.h>

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
	struct acpi_lpi_genpd_map_entry *parent_map_entry;
	struct acpi_lpi_state *lpi_states;
	unsigned int lpi_state_count;
	unsigned int child_count;
};

struct acpi_lpi_ffh_state {
	u64 address;
	u64 level_id;
	u32 arch_flags;
	u8 index;
	u8 entry_method;
};

struct acpi_lpi_runtime_state {
	struct list_head node;
	struct generic_pm_domain *genpd;
	unsigned int state_idx;
	struct acpi_lpi_ffh_state state;
	bool selected;
};

struct acpi_idle_data {
	struct acpi_lpi_runtime_state *domain_state;
	struct acpi_lpi_genpd_map_entry *base_map_entry;
	struct device *domain_dev;
	struct list_head runtime_states;
	unsigned int leaf_lpi_count;
	bool runtime_pm_active;
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
static DEFINE_PER_CPU(struct acpi_idle_data *, acpi_idle_data);

static LIST_HEAD(domain_map);
static DEFINE_MUTEX(domain_map_lock);

enum acpi_lpi_lifecycle_state {
	ACPI_LPI_BUILDING,
	ACPI_LPI_DIRECT,
	ACPI_LPI_UPDATING,
	ACPI_LPI_COORDINATED,
};

static DEFINE_MUTEX(acpi_lpi_lifecycle_lock);
static enum acpi_lpi_lifecycle_state acpi_lpi_lifecycle = ACPI_LPI_BUILDING;
static enum cpuhp_state acpi_lpi_cpuhp_state = CPUHP_INVALID;
static cpumask_t acpi_lpi_syscore_suspended_cpus;
static cpumask_t acpi_lpi_excluded_cpus;
static bool acpi_lpi_system_sleep;
static bool acpi_lpi_syscore_suspending;

static void acpi_lpi_rebuild_workfn(struct work_struct *work);
static DECLARE_WORK(acpi_lpi_rebuild_work, acpi_lpi_rebuild_workfn);

static void __acpi_processor_power_init(struct acpi_processor *pr);
static void acpi_processor_power_exit_locked(struct acpi_processor *pr);

#define ACPI_LPI_STATE_FLAGS_ENABLED			BIT(0)

static bool acpi_lpi_can_coordinate(void)
{
	/* The arm64 FFH hooks are intentionally not linked to processor.ko. */
	return IS_BUILTIN(CONFIG_ACPI_PROCESSOR) &&
	       acpi_processor_ffh_lpi_hierarchy_supported();
}

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

static const struct bus_type acpi_idle_bus_type = {
	.name		= "acpi_lpi_domain",
};

int acpi_processor_idle_bus_init(void)
{
	return bus_register(&acpi_idle_bus_type);
}

void acpi_processor_idle_bus_exit(void)
{
	bus_unregister(&acpi_idle_bus_type);
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
		state->exit_latency_ns =
			mul_u32_u32(state->exit_latency, NSEC_PER_USEC);
		state->target_residency_ns =
			(u64)state->target_residency * NSEC_PER_USEC;
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

static struct acpi_lpi_genpd_map_entry *acpi_lpi_get_domain(acpi_handle handle)
{
	struct acpi_lpi_genpd_map_entry *entry;

	list_for_each_entry(entry, &domain_map, node)
		if (entry->handle == handle)
			return entry;

	return NULL;
}

static void acpi_lpi_save_runtime_ffh_state(struct acpi_lpi_ffh_state *dst,
					    const struct acpi_lpi_state *src)
{
	dst->address = src->address;
	dst->level_id = src->level_id;
	dst->arch_flags = src->arch_flags;
	dst->index = src->index;
	dst->entry_method = src->entry_method;
}

static void
acpi_lpi_prepare_ffh_entry_state(struct acpi_lpi_state *dst,
				 const struct acpi_lpi_ffh_state *src)
{
	memset(dst, 0, sizeof(*dst));
	dst->address = src->address;
	dst->level_id = src->level_id;
	dst->arch_flags = src->arch_flags;
	dst->index = src->index;
	dst->entry_method = src->entry_method;
}

static struct acpi_lpi_runtime_state *
acpi_lpi_find_runtime_state(struct acpi_idle_data *data,
			    struct generic_pm_domain *genpd,
			    unsigned int state_idx)
{
	struct acpi_lpi_runtime_state *runtime_state;

	list_for_each_entry(runtime_state, &data->runtime_states, node)
		if (runtime_state->genpd == genpd &&
		    runtime_state->state_idx == state_idx)
			return runtime_state;

	return NULL;
}

static void acpi_lpi_clear_selected_states(struct acpi_idle_data *data)
{
	struct acpi_lpi_runtime_state *runtime_state;

	list_for_each_entry(runtime_state, &data->runtime_states, node)
		runtime_state->selected = false;
	data->domain_state = NULL;
}

static void acpi_lpi_reject_selected_states(struct acpi_idle_data *data,
					    bool s2idle)
{
	struct acpi_lpi_runtime_state *runtime_state;

	list_for_each_entry(runtime_state, &data->runtime_states, node) {
		if (!runtime_state->selected)
			continue;

		pm_genpd_inc_rejected(runtime_state->genpd,
				      runtime_state->state_idx, s2idle);
	}

	acpi_lpi_clear_selected_states(data);
}

static int acpi_lpi_validate_runtime_states(struct acpi_processor *pr,
					    struct acpi_idle_data *data)
{
	struct acpi_lpi_runtime_state *runtime_state;
	struct acpi_lpi_state lpi;
	unsigned int i;
	int ret;

	if (!acpi_lpi_can_coordinate())
		return -EOPNOTSUPP;

	/*
	 * The leaf genpd contains only the deepest CPU power state, but every
	 * non-WFI state in the CPU-local cpuidle prefix uses the leaf entry
	 * callback. Validate all of them before publishing coordinated mode.
	 */
	for (i = 0; i < data->leaf_lpi_count; i++) {
		lpi = pr->power.lpi_states[i];
		if (acpi_processor_ffh_lpi_is_wfi(&lpi))
			continue;
		if (lpi.entry_method != ACPI_CSTATE_FFH)
			return -EINVAL;

		ret = acpi_processor_ffh_lpi_prepare_state(&lpi);
		if (ret)
			return ret;
	}

	list_for_each_entry(runtime_state, &data->runtime_states, node) {
		acpi_lpi_prepare_ffh_entry_state(&lpi, &runtime_state->state);
		if (lpi.entry_method != ACPI_CSTATE_FFH)
			return -EINVAL;

		ret = acpi_processor_ffh_lpi_prepare_state(&lpi);
		if (ret)
			return ret;
	}

	return 0;
}

static int acpi_lpi_add_runtime_states(struct acpi_idle_data *data,
				       struct generic_pm_domain *genpd,
				       const struct acpi_lpi_state *lpi_states,
				       unsigned int state_count)
{
	struct acpi_lpi_runtime_state *runtime_state, *tmp;
	LIST_HEAD(new_states);
	unsigned int existing_count = 0;
	unsigned int i;

	if (genpd->state_count != state_count)
		return -EINVAL;

	list_for_each_entry(runtime_state, &data->runtime_states, node) {
		if (runtime_state->genpd == genpd)
			existing_count++;
	}

	if (existing_count && existing_count != state_count)
		return -EINVAL;

	if (existing_count) {
		for (i = 0; i < state_count; i++) {
			if (!acpi_lpi_find_runtime_state(data, genpd, i))
				return -EINVAL;
		}
	}

	for (i = 0; i < state_count; i++) {
		runtime_state = kzalloc_obj(*runtime_state);
		if (!runtime_state)
			goto free_new_states;

		runtime_state->genpd = genpd;
		runtime_state->state_idx = i;
		acpi_lpi_save_runtime_ffh_state(&runtime_state->state,
						&lpi_states[i]);
		list_add_tail(&runtime_state->node, &new_states);
	}

	data->domain_state = NULL;
	list_for_each_entry_safe(runtime_state, tmp, &data->runtime_states, node) {
		if (runtime_state->genpd != genpd)
			continue;

		list_del(&runtime_state->node);
		kfree(runtime_state);
	}
	list_splice_tail_init(&new_states, &data->runtime_states);
	return 0;

free_new_states:
	list_for_each_entry_safe(runtime_state, tmp, &new_states, node) {
		list_del(&runtime_state->node);
		kfree(runtime_state);
	}
	return -ENOMEM;
}

static void acpi_lpi_free_runtime_states(struct acpi_idle_data *data)
{
	struct acpi_lpi_runtime_state *runtime_state, *tmp;

	if (!data)
		return;

	list_for_each_entry_safe(runtime_state, tmp, &data->runtime_states, node) {
		list_del(&runtime_state->node);
		kfree(runtime_state);
	}
}

static int acpi_lpi_pd_power_off(struct generic_pm_domain *domain)
{
	struct acpi_idle_data *data;
	struct acpi_lpi_runtime_state *runtime_state;
	unsigned int cpu = raw_smp_processor_id();

	/* Outside coordinated mode this callback only updates genpd state. */
	if (READ_ONCE(acpi_lpi_lifecycle) != ACPI_LPI_COORDINATED)
		return 0;

	if (!cpumask_test_cpu(cpu, domain->cpus)) {
		/*
		 * Runtime PM can account a domain from another CPU after all of
		 * its members are offline. No CPU enters firmware in that case,
		 * so there is no per-CPU FFH state to select. Syscore performs the
		 * same accounting after secondary CPUs have stopped, while the
		 * online mask still describes their pre-suspend state.
		 */
		if (READ_ONCE(acpi_lpi_syscore_suspending))
			return 0;
		if (!cpumask_empty(domain->cpus) &&
		    !cpumask_intersects(domain->cpus, cpu_online_mask))
			return 0;

		return -EXDEV;
	}

	data = this_cpu_read(acpi_idle_data);
	if (!data)
		return -ENODEV;

	runtime_state = acpi_lpi_find_runtime_state(data, domain,
						    domain->state_idx);
	if (!runtime_state)
		return -EXDEV;

	runtime_state->selected = true;
	data->domain_state = runtime_state;
	return 0;
}

static int acpi_lpi_pd_power_on(struct generic_pm_domain *domain)
{
	struct acpi_idle_data *data;
	unsigned int cpu = raw_smp_processor_id();

	if (READ_ONCE(acpi_lpi_lifecycle) != ACPI_LPI_COORDINATED)
		return 0;

	if (!cpumask_test_cpu(cpu, domain->cpus))
		return 0;

	data = this_cpu_read(acpi_idle_data);
	if (!data)
		return -ENODEV;
	if (!acpi_lpi_find_runtime_state(data, domain, domain->state_idx))
		return -EXDEV;

	return 0;
}

static void acpi_lpi_pd_free_states(struct genpd_power_state *states,
				    unsigned int state_count)
{
	kfree(states);
}

static bool
acpi_lpi_pd_states_match(struct acpi_lpi_genpd_map_entry *entry,
			 const struct acpi_lpi_state *lpi_states,
			 unsigned int lpi_state_count)
{
	struct generic_pm_domain *pd = entry->genpd;
	unsigned int i;

	if (pd->state_count != lpi_state_count ||
	    entry->lpi_state_count != lpi_state_count)
		return false;

	for (i = 0; i < lpi_state_count; i++) {
		const struct acpi_lpi_state *lpi = &lpi_states[i];
		const struct acpi_lpi_state *saved = &entry->lpi_states[i];
		const struct genpd_power_state *state = &pd->states[i];

		if (state->power_off_latency_ns ||
		    state->residency_ns !=
				(u64)lpi->min_residency * NSEC_PER_USEC)
			return false;

		if (saved->min_residency != lpi->min_residency ||
		    saved->wake_latency != lpi->wake_latency ||
		    saved->flags != lpi->flags ||
		    saved->arch_flags != lpi->arch_flags ||
		    saved->res_cnt_freq != lpi->res_cnt_freq ||
		    saved->enable_parent_state != lpi->enable_parent_state ||
		    saved->address != lpi->address ||
		    saved->level_id != lpi->level_id ||
		    saved->index != lpi->index ||
		    saved->entry_method != lpi->entry_method)
			return false;
	}

	return true;
}

static void
acpi_lpi_pd_merge_wake_latencies(struct acpi_lpi_genpd_map_entry *entry,
				 const struct acpi_lpi_state *runtime_states,
				 unsigned int state_count)
{
	struct generic_pm_domain *pd = entry->genpd;
	unsigned int i;

	lockdep_assert_held(&domain_map_lock);

	for (i = 0; i < state_count; i++) {
		s64 latency_ns =
			(u64)runtime_states[i].wake_latency * NSEC_PER_USEC;

		pd->states[i].power_on_latency_ns =
			max(pd->states[i].power_on_latency_ns, latency_ns);
	}
}

static void acpi_lpi_release_device(struct device *dev)
{
	kfree(dev);
}

static int acpi_lpi_pd_init(acpi_handle handle,
			    const struct acpi_lpi_state *lpi_states,
			    const struct acpi_lpi_state *runtime_states,
			    unsigned int lpi_state_count,
			    struct acpi_lpi_genpd_map_entry **map_entry,
			    bool *existing)
{
	struct acpi_lpi_genpd_map_entry *entry;
	struct genpd_power_state *genpd_states;
	struct acpi_device *adev;
	struct generic_pm_domain *pd;
	const char *hid, *name, *uid;
	unsigned int i;
	int ret;

	adev = acpi_fetch_acpi_dev(handle);
	if (!adev)
		return -ENODEV;

	entry = acpi_lpi_get_domain(handle);
	if (entry) {
		if (!acpi_lpi_pd_states_match(entry, lpi_states,
					      lpi_state_count))
			return -EINVAL;

		/* Use the worst composite latency among all CPU paths. */
		acpi_lpi_pd_merge_wake_latencies(entry, runtime_states,
						 lpi_state_count);
		*map_entry = entry;
		if (existing)
			*existing = true;
		return 0;
	}
	if (existing)
		*existing = false;

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
		const struct acpi_lpi_state *runtime = &runtime_states[i];

		/*
		 * _LPI defines the worst-case latency to return from this
		 * state. Account it as power-on latency so the genpd governor
		 * does not count the same wake latency in both directions.
		 */
		genpd_states[i].power_off_latency_ns = 0;
		genpd_states[i].power_on_latency_ns =
			(u64)runtime->wake_latency * NSEC_PER_USEC;
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

	pd->power_off = acpi_lpi_pd_power_off;
	pd->power_on = acpi_lpi_pd_power_on;
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

static int acpi_lpi_attach_domain_device(struct acpi_processor *pr,
					 struct acpi_idle_data *data,
					 struct acpi_lpi_genpd_map_entry *entry)
{
	struct device *cpu_dev;
	struct device *dev;
	int ret;

	if (data->domain_dev)
		return data->base_map_entry == entry ? 0 : -EINVAL;

	cpu_dev = get_cpu_device(pr->id);
	if (!cpu_dev)
		return -ENODEV;

	dev = kzalloc_obj(*dev);
	if (!dev)
		return -ENOMEM;

	dev->bus = &acpi_idle_bus_type;
	dev->release = acpi_lpi_release_device;
	ret = dev_set_name(dev, "acpi_lpi:CPU%u", pr->id);
	if (ret) {
		kfree(dev);
		return ret;
	}

	ret = device_register(dev);
	if (ret) {
		put_device(dev);
		return ret;
	}

	ret = pm_genpd_add_device_with_base(entry->genpd, dev, cpu_dev);
	if (ret) {
		device_unregister(dev);
		return ret;
	}

	pm_runtime_enable(dev);
	pm_runtime_irq_safe(dev);
	pm_runtime_put_noidle(dev);
	dev_pm_syscore_device(dev, true);
	data->domain_dev = dev;
	return 0;
}

static int acpi_processor_lpi_runtime_get(struct acpi_idle_data *data)
{
	int ret;

	if (!data || !data->domain_dev)
		return -ENODEV;
	if (data->runtime_pm_active)
		return 0;

	if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
		dev_pm_genpd_resume(data->domain_dev);
	} else {
		ret = pm_runtime_resume_and_get(data->domain_dev);
		if (ret < 0)
			return ret;
	}

	data->runtime_pm_active = true;
	return 0;
}

static int acpi_processor_lpi_runtime_put(struct acpi_idle_data *data)
{
	int ret;

	if (!data || !data->domain_dev || !data->runtime_pm_active)
		return 0;

	if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
		dev_pm_genpd_suspend(data->domain_dev);
	} else {
		ret = pm_runtime_put_sync_suspend(data->domain_dev);
		if (ret < 0) {
			pm_runtime_get_noresume(data->domain_dev);
			return ret;
		}
	}

	data->runtime_pm_active = false;
	data->domain_state = NULL;
	return 0;
}

static int acpi_lpi_detach_domain_device(struct acpi_idle_data *data)
{
	struct generic_pm_domain *pd;
	struct device *dev;
	int ret;

	if (!data || !data->domain_dev)
		return 0;
	if (data->runtime_pm_active)
		return -EBUSY;

	dev = data->domain_dev;
	pd = data->base_map_entry ? data->base_map_entry->genpd : NULL;

	dev_pm_syscore_device(dev, false);
	pm_runtime_disable(dev);

	ret = pm_genpd_remove_device(dev);
	if (ret) {
		if (pd)
			pr_warn("%s: failed to detach %s from %s: %d\n",
				__func__, dev_name(dev), pd->name, ret);
		else
			pr_warn("%s: failed to detach %s: %d\n",
				__func__, dev_name(dev), ret);
		pm_runtime_enable(dev);
		dev_pm_syscore_device(dev, true);
		return ret;
	}

	device_unregister(dev);
	data->domain_dev = NULL;
	return 0;
}

static int
acpi_lpi_remove_domain(struct acpi_lpi_genpd_map_entry *entry)
{
	struct acpi_lpi_genpd_map_entry *parent;
	struct generic_pm_domain *pd;
	int restore_ret;
	int ret;

	lockdep_assert_held(&domain_map_lock);

	parent = entry->parent_map_entry;
	pd = entry->genpd;

	if (!cpumask_empty(pd->cpus) || entry->child_count)
		return -EBUSY;

	if (parent) {
		ret = pm_genpd_remove_subdomain(parent->genpd, pd);
		if (ret)
			return ret;
	}

	ret = pm_genpd_remove(pd);
	if (ret) {
		if (!parent)
			return ret;

		restore_ret = pm_genpd_add_subdomain(parent->genpd, pd);
		if (!restore_ret)
			return ret;

		/* Keep the software map consistent with the failed restore. */
		entry->parent_map_entry = NULL;
		parent->child_count--;
		pr_err("%s: failed to restore %s below %s: %d\n", __func__,
		       pd->name, parent->genpd->name, restore_ret);
		return restore_ret;
	}

	if (parent) {
		entry->parent_map_entry = NULL;
		parent->child_count--;
	}

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
	bool removed;
	int pass_ret;
	int ret;

	mutex_lock(&domain_map_lock);
	do {
		removed = false;
		pass_ret = 0;
		list_for_each_entry_safe(entry, tmp, &domain_map, node) {
			if (!cpumask_empty(entry->genpd->cpus) ||
			    entry->child_count)
				continue;

			ret = acpi_lpi_remove_domain(entry);
			if (!ret) {
				removed = true;
				break;
			}
			if (!pass_ret)
				pass_ret = ret;
		}
	} while (removed);
	mutex_unlock(&domain_map_lock);

	return pass_ret;
}

static int acpi_processor_lpi_detach(struct acpi_processor *pr)
{
	struct acpi_idle_data *data = per_cpu(acpi_idle_data, pr->id);
	bool was_active;
	int pm_ret;
	int ret;

	if (!data)
		return 0;

	was_active = data->runtime_pm_active;
	ret = acpi_processor_lpi_runtime_put(data);
	if (ret)
		return ret;

	ret = acpi_lpi_detach_domain_device(data);
	if (ret) {
		if (was_active) {
			pm_ret = acpi_processor_lpi_runtime_get(data);
			if (pm_ret)
				pr_warn("%s: failed to restore CPU%u runtime PM: %d\n",
					__func__, pr->id, pm_ret);
		}
		return ret;
	}

	data->base_map_entry = NULL;
	data->domain_state = NULL;
	acpi_lpi_free_runtime_states(data);

	return acpi_lpi_remove_unused_domains();
}

static int acpi_lpi_pd_add_subdomain(struct generic_pm_domain *parent,
				     struct generic_pm_domain *child)
{
	int ret;

	ret = pm_genpd_add_subdomain(parent, child);
	if (ret) {
		pr_err("%s: failed to add %s as subdomain of %s: %d\n",
		       __func__, child->name, parent->name, ret);
		return ret;
	}

	return 0;
}

struct acpi_lpi_domain_states {
	struct acpi_lpi_state *power_states;
	struct acpi_lpi_state *runtime_states;
	unsigned int count;
};

static bool acpi_lpi_state_enabled(const struct acpi_lpi_state *lpi)
{
	return lpi->flags & ACPI_LPI_STATE_FLAGS_ENABLED;
}

static bool acpi_lpi_is_usable_leaf_state(const struct acpi_lpi_state *lpi)
{
	return acpi_lpi_state_enabled(lpi) &&
	       lpi->entry_method != ACPI_CSTATE_INTEGER;
}

static int acpi_lpi_alloc_domain_states(struct acpi_lpi_domain_states *states,
					unsigned int state_count)
{
	states->power_states = kzalloc_objs(*states->power_states, state_count);
	if (!states->power_states)
		return -ENOMEM;

	states->runtime_states = kzalloc_objs(*states->runtime_states,
					      state_count);
	if (!states->runtime_states) {
		kfree(states->power_states);
		states->power_states = NULL;
		return -ENOMEM;
	}

	return 0;
}

static void acpi_lpi_free_domain_states(struct acpi_lpi_domain_states *states)
{
	kfree(states->power_states);
	kfree(states->runtime_states);
	states->power_states = NULL;
	states->runtime_states = NULL;
	states->count = 0;
}

static int
acpi_lpi_prepare_leaf_domain_states(const struct acpi_lpi_state *lpi_states,
				    unsigned int lpi_state_count,
				    unsigned int *leaf_lpi_count,
				    struct acpi_lpi_domain_states *states)
{
	const struct acpi_lpi_state *deepest = NULL;
	unsigned int i;
	int ret;

	/*
	 * Match the hierarchical PSCI topology used for DT: the CPU device is
	 * attached to a per-CPU leaf domain, which is then linked below the
	 * shared domains. WFI remains a direct cpuidle state because it does not
	 * suspend the CPU power domain or compose with parent states. The leaf
	 * genpd therefore contains only the deepest CPU power-domain state used
	 * to trigger coordination.
	 *
	 * Track the complete CPU-local cpuidle prefix separately. It includes
	 * WFI and may be larger than the leaf genpd state table.
	 */
	*leaf_lpi_count = 0;
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

	ret = acpi_lpi_alloc_domain_states(states, 1);
	if (ret)
		return ret;

	memcpy(&states->power_states[0], deepest, sizeof(*deepest));
	memcpy(&states->runtime_states[0], deepest, sizeof(*deepest));
	states->count = 1;

	return 0;
}

static int
acpi_lpi_prepare_parent_domain_states(const struct acpi_lpi_state *lpi_states,
				      unsigned int lpi_state_count,
				      const struct acpi_lpi_state *child_state,
				      struct acpi_lpi_domain_states *states)
{
	unsigned int i;
	int ret;

	ret = acpi_lpi_alloc_domain_states(states, lpi_state_count);
	if (ret)
		return ret;

	/*
	 * A shared domain needs one ordered state table. If different children
	 * enable different parent-state subsets, exact reuse fails and hierarchy
	 * activation safely falls back to the CPU-local direct path.
	 */
	for (i = 0; i < lpi_state_count; i++) {
		const struct acpi_lpi_state *parent = &lpi_states[i];
		struct acpi_lpi_state *runtime_state;

		if (!acpi_lpi_state_enabled(parent))
			continue;

		if (parent->index > child_state->enable_parent_state)
			continue;

		runtime_state = &states->runtime_states[states->count];
		if (!acpi_processor_combine_lpi_states(child_state, parent,
						       runtime_state))
			continue;

		/*
		 * Keep the raw parent state as the shared-domain identity. The
		 * runtime state remains specific to this CPU path, while genpd
		 * conservatively merges the worst composite wake latency from all
		 * children that reuse the domain.
		 */
		memcpy(&states->power_states[states->count], parent,
		       sizeof(*parent));
		states->count++;
	}

	if (!states->count)
		acpi_lpi_free_domain_states(states);

	return 0;
}

struct acpi_lpi_pd_txn_entry {
	struct list_head node;
	struct acpi_lpi_genpd_map_entry *entry;
	struct acpi_lpi_genpd_map_entry *child;
	bool domain_created;
	bool link_created;
};

struct acpi_lpi_pd_init_data {
	struct acpi_idle_data *data;
	struct acpi_lpi_genpd_map_entry *child_map_entry;
	struct acpi_lpi_state child_state;
	struct list_head transaction;
	bool child_state_valid;
	bool hierarchy_closed;
};

static void acpi_lpi_pd_free_transaction(struct acpi_lpi_pd_init_data *data)
{
	struct acpi_lpi_pd_txn_entry *step, *tmp;

	list_for_each_entry_safe(step, tmp, &data->transaction, node) {
		list_del(&step->node);
		kfree(step);
	}
}

static int acpi_lpi_pd_remove_created(struct acpi_lpi_genpd_map_entry *entry)
{
	return acpi_lpi_remove_domain(entry);
}

static int acpi_lpi_pd_rollback(struct acpi_lpi_pd_init_data *data)
{
	struct acpi_lpi_pd_txn_entry *step, *tmp;
	int ret;

	lockdep_assert_held(&domain_map_lock);

	list_for_each_entry_safe_reverse(step, tmp, &data->transaction, node) {
		if (step->link_created) {
			ret = pm_genpd_remove_subdomain(step->entry->genpd,
							step->child->genpd);
			if (ret)
				goto fail;

			step->child->parent_map_entry = NULL;
			step->entry->child_count--;
		}

		if (step->domain_created) {
			ret = acpi_lpi_pd_remove_created(step->entry);
			if (ret)
				goto fail;
		}

		list_del(&step->node);
		kfree(step);
	}

	data->data->base_map_entry = NULL;
	return 0;

fail:
	pr_err("%s: failed to roll back LPI hierarchy: %d\n", __func__, ret);
	acpi_lpi_pd_free_transaction(data);
	return ret;
}

static int acpi_lpi_pd_init_cb(acpi_handle handle,
			       const struct acpi_lpi_state *lpi_states,
			       unsigned int lpi_state_count,
			       unsigned int level, void *arg)
{
	struct acpi_lpi_pd_init_data *init_data = arg;
	struct acpi_lpi_domain_states domain_states = {};
	struct acpi_lpi_genpd_map_entry *map_entry;
	struct acpi_lpi_pd_txn_entry *step;
	bool existing;
	int ret;

	if (level == 0) {
		ret = acpi_lpi_prepare_leaf_domain_states(lpi_states,
							  lpi_state_count,
							  &init_data->data->leaf_lpi_count,
							  &domain_states);
		if (ret)
			return ret;

		if (!domain_states.count) {
			init_data->hierarchy_closed = true;
			goto out;
		}

		step = kzalloc_obj(*step);
		if (!step) {
			ret = -ENOMEM;
			goto out;
		}

		ret = acpi_lpi_pd_init(handle, domain_states.power_states,
				       domain_states.runtime_states,
				       domain_states.count, &map_entry, &existing);
		if (ret) {
			kfree(step);
			goto out;
		}

		step->entry = map_entry;
		step->domain_created = !existing;
		list_add_tail(&step->node, &init_data->transaction);

		if (init_data->data->base_map_entry &&
		    init_data->data->base_map_entry != map_entry) {
			ret = -EINVAL;
			goto out;
		}
		init_data->data->base_map_entry = map_entry;
		ret = acpi_lpi_add_runtime_states(init_data->data,
						  map_entry->genpd,
						  domain_states.runtime_states,
						  domain_states.count);
		if (ret)
			goto out;

		init_data->child_map_entry = map_entry;
		init_data->child_state =
			domain_states.runtime_states[domain_states.count - 1];
		init_data->child_state_valid = true;
		goto out;
	}

	if (init_data->hierarchy_closed || !init_data->child_state_valid)
		return 0;

	ret = acpi_lpi_prepare_parent_domain_states(lpi_states,
						    lpi_state_count,
						    &init_data->child_state,
						    &domain_states);
	if (ret)
		return ret;

	if (!domain_states.count) {
		init_data->hierarchy_closed = true;
		return 0;
	}

	step = kzalloc_obj(*step);
	if (!step) {
		ret = -ENOMEM;
		goto out;
	}

	ret = acpi_lpi_pd_init(handle, domain_states.power_states,
			       domain_states.runtime_states,
			       domain_states.count, &map_entry, &existing);
	if (ret) {
		kfree(step);
		goto out;
	}

	step->entry = map_entry;
	step->domain_created = !existing;
	list_add_tail(&step->node, &init_data->transaction);

	if (!init_data->child_map_entry->parent_map_entry) {
		ret = acpi_lpi_pd_add_subdomain(map_entry->genpd,
						init_data->child_map_entry->genpd);
		if (ret)
			goto out;

		init_data->child_map_entry->parent_map_entry = map_entry;
		map_entry->child_count++;
		step->child = init_data->child_map_entry;
		step->link_created = true;
	} else if (init_data->child_map_entry->parent_map_entry != map_entry) {
		ret = -EINVAL;
		goto out;
	}

	ret = acpi_lpi_add_runtime_states(init_data->data, map_entry->genpd,
					  domain_states.runtime_states,
					  domain_states.count);
	if (ret)
		goto out;
	init_data->child_map_entry = map_entry;
	init_data->child_state = domain_states.runtime_states[domain_states.count - 1];
	init_data->child_state_valid = true;

out:
	acpi_lpi_free_domain_states(&domain_states);
	return ret;
}

static int acpi_processor_free_idle_data(struct acpi_processor *pr)
{
	struct acpi_idle_data *data = per_cpu(acpi_idle_data, pr->id);
	int ret;

	if (!data)
		return 0;

	ret = acpi_processor_lpi_detach(pr);
	if (ret)
		return ret;

	kfree(data);
	per_cpu(acpi_idle_data, pr->id) = NULL;
	return ret;
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
	struct acpi_lpi_pd_init_data init_data = {};
	struct acpi_idle_data *data;
	int detach_ret;
	int rollback_ret;
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
	    !acpi_lpi_can_coordinate()) {
		ret = acpi_processor_extract_lpi_info(pr->handle, &pr->power,
						      false);
		if (ret)
			return ret;

		pr->flags.has_lpi = 1;
		pr->flags.power = 1;
		return 0;
	}

	data = kzalloc_obj(*data);
	if (!data)
		return -ENOMEM;

	INIT_LIST_HEAD(&data->runtime_states);
	per_cpu(acpi_idle_data, pr->id) = data;
	init_data.data = data;
	INIT_LIST_HEAD(&init_data.transaction);

	mutex_lock(&domain_map_lock);
	ret = acpi_processor_extract_lpi_info_cb(pr->handle, &pr->power, false,
						 acpi_lpi_pd_init_cb,
						 &init_data);
	if (ret) {
		rollback_ret = acpi_lpi_pd_rollback(&init_data);
		if (rollback_ret)
			ret = rollback_ret;
	}
	mutex_unlock(&domain_map_lock);

	if (ret)
		return rollback_ret ? ret :
			acpi_processor_lpi_fallback_flat(pr);

	if (!data->base_map_entry) {
		acpi_lpi_pd_free_transaction(&init_data);
		return acpi_processor_lpi_fallback_flat(pr);
	}

	/*
	 * Attach after constructing the complete hierarchy, so genpd can
	 * propagate the CPU association from the leaf to every parent.
	 */
	ret = acpi_lpi_attach_domain_device(pr, data, data->base_map_entry);
	if (ret)
		goto rollback;

	ret = acpi_processor_lpi_runtime_get(data);
	if (ret) {
		detach_ret = acpi_lpi_detach_domain_device(data);
		if (detach_ret) {
			acpi_lpi_pd_free_transaction(&init_data);
			return detach_ret;
		}
		goto rollback;
	}

	ret = acpi_lpi_validate_runtime_states(pr, data);
	if (ret) {
		if (ret != -EOPNOTSUPP)
			pr_warn("CPU%u: invalid hierarchical FFH state: %d\n",
				pr->id, ret);

		acpi_lpi_pd_free_transaction(&init_data);
		return acpi_processor_lpi_fallback_flat(pr);
	}

	acpi_lpi_pd_free_transaction(&init_data);
	/* Tell driver that _LPI is supported. */
	pr->flags.has_lpi = 1;
	pr->flags.power = 1;

	return 0;

rollback:
	mutex_lock(&domain_map_lock);
	rollback_ret = acpi_lpi_pd_rollback(&init_data);
	mutex_unlock(&domain_map_lock);
	if (rollback_ret)
		return rollback_ret;

	return acpi_processor_lpi_fallback_flat(pr);
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
#ifdef CONFIG_ACPI_PROCESSOR_CSTATE
	if (lpi->entry_method == ACPI_CSTATE_SYSTEMIO) {
		io_idle(lpi->address);
		return index;
	}
#endif

	if (lpi->entry_method != ACPI_CSTATE_FFH)
		return -EINVAL;

	ret = acpi_processor_ffh_lpi_enter(lpi);
	return ret < 0 ? ret : index;
}

static int __cpuidle
acpi_idle_lpi_enter_leaf(struct cpuidle_device *dev,
			 struct cpuidle_driver *drv, int index)
{
	struct acpi_lpi_state lpi;
	struct acpi_processor *pr;
	int ret;

	pr = __this_cpu_read(processors);
	if (unlikely(!pr))
		return -EINVAL;

	lpi = pr->power.lpi_states[index];
	if (lpi.entry_method != ACPI_CSTATE_FFH)
		return -EINVAL;

	ret = acpi_processor_ffh_lpi_prepare_state(&lpi);
	if (ret)
		return ret;

	ret = acpi_processor_ffh_lpi_enter(&lpi);
	return ret < 0 ? ret : index;
}

static int __cpuidle
__acpi_idle_lpi_enter_domain(struct cpuidle_device *dev,
			     struct cpuidle_driver *drv, int index,
			     bool s2idle)
{
	struct acpi_lpi_runtime_state *domain_state;
	struct acpi_processor *pr;
	struct acpi_idle_data *data;
	struct acpi_lpi_state lpi;
	int resume_ret;
	int ret;

	pr = __this_cpu_read(processors);
	data = this_cpu_read(acpi_idle_data);
	if (unlikely(!pr || !data || !data->domain_dev))
		return -ENODEV;

	/* Device PM owns the shared hierarchy after system sleep begins. */
	if (!s2idle &&
	    (READ_ONCE(acpi_lpi_system_sleep) ||
	     READ_ONCE(pm_suspend_target_state) != PM_SUSPEND_ON))
		return acpi_idle_lpi_enter_leaf(dev, drv, index);

	acpi_lpi_clear_selected_states(data);

	if (s2idle) {
		dev_pm_genpd_suspend(data->domain_dev);
		ret = 0;
	} else {
		ret = pm_runtime_put_sync_suspend(data->domain_dev);
		if (ret < 0)
			pm_runtime_get_noresume(data->domain_dev);
	}
	if (ret < 0) {
		acpi_lpi_clear_selected_states(data);
		return ret;
	}

	domain_state = data->domain_state;
	if (domain_state)
		acpi_lpi_prepare_ffh_entry_state(&lpi, &domain_state->state);
	else
		lpi = pr->power.lpi_states[index];

	if (lpi.entry_method != ACPI_CSTATE_FFH) {
		ret = -EINVAL;
	} else {
		ret = acpi_processor_ffh_lpi_prepare_state(&lpi);
		if (!ret) {
			ret = acpi_processor_ffh_lpi_enter(&lpi);
			if (ret >= 0)
				ret = index;
		}
	}
	if (ret < 0)
		acpi_lpi_reject_selected_states(data, s2idle);

	if (s2idle) {
		dev_pm_genpd_resume(data->domain_dev);
		resume_ret = 0;
	} else {
		resume_ret = pm_runtime_resume_and_get(data->domain_dev);
		if (resume_ret < 0)
			pm_runtime_get_noresume(data->domain_dev);
	}

	acpi_lpi_clear_selected_states(data);
	return resume_ret < 0 ? resume_ret : ret;
}

static int __cpuidle
acpi_idle_lpi_enter_domain(struct cpuidle_device *dev,
			   struct cpuidle_driver *drv, int index)
{
	return __acpi_idle_lpi_enter_domain(dev, drv, index, false);
}

static int __cpuidle
acpi_idle_lpi_enter_s2idle(struct cpuidle_device *dev,
			   struct cpuidle_driver *drv, int index)
{
	return __acpi_idle_lpi_enter_domain(dev, drv, index, true);
}

static void acpi_processor_setup_lpi_states(struct acpi_processor *pr,
					    struct cpuidle_driver *drv,
					    bool coordinated)
{
	struct acpi_idle_data *data = per_cpu(acpi_idle_data, pr->id);
	struct acpi_lpi_state *lpi;
	struct cpuidle_state *state;
	unsigned int count = pr->power.count;
	unsigned int i;

	if (!pr->flags.has_lpi)
		return;
	if (coordinated) {
		if (!data || !data->base_map_entry)
			return;
		count = data->leaf_lpi_count;
	}

	for (i = 0; i < count && i < CPUIDLE_STATE_MAX; i++) {
		lpi = &pr->power.lpi_states[i];

		state = &drv->states[i];
		snprintf(state->name, CPUIDLE_NAME_LEN, "LPI-%u", i);
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
		if (coordinated && lpi->entry_method == ACPI_CSTATE_FFH &&
		    !acpi_processor_ffh_lpi_is_wfi(lpi))
			state->enter = acpi_idle_lpi_enter_leaf;
		else
			state->enter = acpi_idle_lpi_enter_direct;
		drv->safe_state_index = i;
	}

	if (coordinated && i) {
		drv->states[i - 1].enter_s2idle = acpi_idle_lpi_enter_s2idle;
		if (!IS_ENABLED(CONFIG_PREEMPT_RT))
			drv->states[i - 1].enter = acpi_idle_lpi_enter_domain;
	}

	drv->state_count = i;
}

/**
 * acpi_processor_setup_cpuidle_states_mode - configure CPU idle states
 *
 * @pr: the ACPI processor
 * @coordinated: whether to install hierarchical LPI callbacks
 */
static void
acpi_processor_setup_cpuidle_states_mode(struct acpi_processor *pr,
					 bool coordinated)
{
	struct cpuidle_driver *drv = acpi_idle_driver_for_cpu(pr->id);
	int i;

	if (!drv || !pr->flags.power_setup_done || !pr->flags.power)
		return;

	drv->safe_state_index = -1;
	for (i = ACPI_IDLE_STATE_START; i < CPUIDLE_STATE_MAX; i++)
		memset(&drv->states[i], 0, sizeof(drv->states[i]));

	if (pr->flags.has_lpi) {
		acpi_processor_setup_lpi_states(pr, drv, coordinated);
		return;
	}

	acpi_processor_setup_cstates(pr, drv);
}

static void acpi_processor_setup_cpuidle_states(struct acpi_processor *pr)
{
	acpi_processor_setup_cpuidle_states_mode(pr, false);
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

static void acpi_lpi_disable_cpuidle_devices(struct cpumask *disabled)
{
	struct cpuidle_device *dev;
	int cpu;

	cpumask_clear(disabled);
	for_each_possible_cpu(cpu) {
		dev = per_cpu(acpi_cpuidle_device, cpu);
		if (!dev || !dev->enabled)
			continue;

		cpuidle_disable_device(dev);
		cpumask_set_cpu(cpu, disabled);
	}
}

static int acpi_lpi_enable_cpuidle_devices(struct cpumask *disabled)
{
	struct cpuidle_device *dev;
	int first_ret = 0;
	int cpu;
	int ret;

	for_each_cpu(cpu, disabled) {
		dev = per_cpu(acpi_cpuidle_device, cpu);
		if (!dev)
			continue;

		ret = cpuidle_enable_device(dev);
		if (ret)
			pr_warn("CPU%d: failed to re-enable cpuidle: %d\n",
				cpu, ret);
		else
			cpumask_clear_cpu(cpu, disabled);
		if (ret && !first_ret)
			first_ret = ret;
	}

	return first_ret;
}

static bool acpi_lpi_complete_cpu_coverage(void)
{
	struct acpi_lpi_genpd_map_entry *base;
	struct acpi_processor *pr;
	struct acpi_idle_data *data;
	bool found = false;
	int cpu;

	for_each_present_cpu(cpu) {
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

		pr = per_cpu(processors, cpu);
		data = per_cpu(acpi_idle_data, cpu);
		if (!pr || !pr->flags.power_setup_done || !pr->flags.has_lpi ||
		    !data || !data->domain_dev || !data->base_map_entry)
			return false;
		if (!acpi_idle_driver_is_registered(cpu))
			return false;

		base = data->base_map_entry;
		if (!base->genpd || base->genpd->state_count != 1 ||
		    !data->leaf_lpi_count ||
		    data->leaf_lpi_count > pr->power.count ||
		    data->leaf_lpi_count > CPUIDLE_STATE_MAX ||
		    !acpi_processor_ffh_lpi_is_wfi(&pr->power.lpi_states[0]))
			return false;

		found = true;
	}

	return found;
}

static void acpi_lpi_setup_cpuidle_states(bool coordinated)
{
	struct acpi_processor *pr;
	int cpu;

	for_each_present_cpu(cpu) {
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

		pr = per_cpu(processors, cpu);
		if (pr)
			acpi_processor_setup_cpuidle_states_mode(pr, coordinated);
	}
}

static struct acpi_processor *acpi_lpi_find_representative(void)
{
	struct acpi_processor *pr;
	int cpu;

	for_each_possible_cpu(cpu) {
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

		pr = per_cpu(processors, cpu);
		if (pr && pr->flags.power_setup_done && pr->flags.has_lpi)
			return pr;
	}

	return NULL;
}

static int acpi_lpi_restore_runtime_pm(const struct cpumask *active)
{
	struct acpi_idle_data *data;
	bool should_be_active;
	int restore_ret;
	int ret = 0;
	int cpu;

	for_each_present_cpu(cpu) {
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

		data = per_cpu(acpi_idle_data, cpu);
		if (!data || !data->domain_dev)
			continue;

		should_be_active = cpumask_test_cpu(cpu, active);
		if (data->runtime_pm_active == should_be_active)
			continue;

		if (should_be_active)
			restore_ret = acpi_processor_lpi_runtime_get(data);
		else
			restore_ret = acpi_processor_lpi_runtime_put(data);
		if (restore_ret) {
			pr_warn("CPU%d: failed to restore LPI runtime PM: %d\n",
				cpu, restore_ret);
			if (!ret)
				ret = restore_ret;
		}
	}

	return ret;
}

static int acpi_lpi_sync_runtime_pm(struct cpumask *was_active)
{
	struct acpi_idle_data *data;
	bool should_be_active;
	int restore_ret;
	int ret;
	int cpu;

	cpumask_clear(was_active);
	for_each_present_cpu(cpu) {
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

		data = per_cpu(acpi_idle_data, cpu);
		if (!data)
			return -ENODEV;
		if (data->runtime_pm_active)
			cpumask_set_cpu(cpu, was_active);
	}

	for_each_present_cpu(cpu) {
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

		data = per_cpu(acpi_idle_data, cpu);
		if (!data)
			return -ENODEV;
		should_be_active = cpu_online(cpu);
		if (data->runtime_pm_active == should_be_active)
			continue;

		if (should_be_active)
			ret = acpi_processor_lpi_runtime_get(data);
		else
			ret = acpi_processor_lpi_runtime_put(data);
		if (!ret)
			continue;

		restore_ret = acpi_lpi_restore_runtime_pm(was_active);
		return restore_ret ?: ret;
	}

	return 0;
}

static int acpi_idle_cpuhp_up(unsigned int cpu)
{
	struct acpi_idle_data *data;
	int ret;

	if (READ_ONCE(acpi_lpi_lifecycle) != ACPI_LPI_COORDINATED)
		return 0;
	if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
		return 0;

	data = per_cpu(acpi_idle_data, cpu);
	if (!data || !data->domain_dev)
		return 0;

	ret = acpi_processor_lpi_runtime_get(data);
	if (ret)
		pr_warn("CPU%u: failed to resume LPI domain: %d\n", cpu, ret);

	return ret;
}

static int acpi_idle_cpuhp_down(unsigned int cpu)
{
	struct acpi_idle_data *data;
	int ret;

	if (READ_ONCE(acpi_lpi_lifecycle) != ACPI_LPI_COORDINATED)
		return 0;
	if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
		return 0;

	data = per_cpu(acpi_idle_data, cpu);
	if (!data || !data->domain_dev)
		return 0;

	ret = acpi_processor_lpi_runtime_put(data);
	if (ret)
		pr_warn("CPU%u: failed to suspend LPI domain: %d\n", cpu, ret);

	/* CPU hotplug teardown callbacks cannot veto the transition. */
	return 0;
}

static void acpi_idle_syscore_resume_devices(void)
{
	struct acpi_idle_data *data;
	int cpu;

	for_each_cpu(cpu, &acpi_lpi_syscore_suspended_cpus) {
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

		data = per_cpu(acpi_idle_data, cpu);
		if (!data || !data->domain_dev)
			continue;

		dev_pm_genpd_resume(data->domain_dev);
		if (pm_runtime_status_suspended(data->domain_dev))
			pm_runtime_set_active(data->domain_dev);
		data->domain_state = NULL;
	}

	cpumask_clear(&acpi_lpi_syscore_suspended_cpus);
	WRITE_ONCE(acpi_lpi_syscore_suspending, false);
}

static int acpi_idle_syscore_suspend(void *unused)
{
	struct acpi_idle_data *data;
	int cpu;

	if (READ_ONCE(acpi_lpi_lifecycle) != ACPI_LPI_COORDINATED)
		return 0;

	cpumask_clear(&acpi_lpi_syscore_suspended_cpus);
	WRITE_ONCE(acpi_lpi_syscore_suspending, true);
	for_each_possible_cpu(cpu) {
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

		data = per_cpu(acpi_idle_data, cpu);
		if (!data || !data->domain_dev)
			continue;

		dev_pm_genpd_suspend(data->domain_dev);
		cpumask_set_cpu(cpu, &acpi_lpi_syscore_suspended_cpus);
	}

	return 0;
}

static void acpi_idle_syscore_resume(void *unused)
{
	if (READ_ONCE(acpi_lpi_lifecycle) == ACPI_LPI_COORDINATED)
		acpi_idle_syscore_resume_devices();
}

static const struct syscore_ops acpi_idle_syscore_ops = {
	.suspend = acpi_idle_syscore_suspend,
	.resume = acpi_idle_syscore_resume,
};

static struct syscore acpi_idle_syscore = {
	.ops = &acpi_idle_syscore_ops,
};

static int acpi_idle_pm_notify(struct notifier_block *nb,
			       unsigned long action, void *unused)
{
	switch (action) {
	case PM_HIBERNATION_PREPARE:
	case PM_RESTORE_PREPARE:
	case PM_SUSPEND_PREPARE:
		WRITE_ONCE(acpi_lpi_system_sleep, true);
		if (READ_ONCE(acpi_lpi_lifecycle) == ACPI_LPI_COORDINATED)
			kick_all_cpus_sync();
		break;
	case PM_POST_HIBERNATION:
	case PM_POST_RESTORE:
	case PM_POST_SUSPEND:
		WRITE_ONCE(acpi_lpi_system_sleep, false);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block acpi_idle_pm_notifier = {
	.notifier_call = acpi_idle_pm_notify,
};

static int acpi_lpi_activate_locked(void)
{
	cpumask_var_t disabled;
	cpumask_var_t runtime_active;
	enum cpuhp_state hp_state;
	bool syscore_registered = false;
	bool notifier_registered = false;
	bool runtime_synced = false;
	int cleanup_ret;
	int ret;

	lockdep_assert_held(&acpi_lpi_lifecycle_lock);

	if (acpi_lpi_lifecycle != ACPI_LPI_DIRECT)
		return 0;
	if (!acpi_lpi_can_coordinate())
		return -EOPNOTSUPP;
	if (!READ_ONCE(acpi_idle_uses_per_cpu_drivers))
		return -ENODEV;
	if (READ_ONCE(pm_suspend_target_state) != PM_SUSPEND_ON)
		return -EBUSY;
	if (!alloc_cpumask_var(&disabled, GFP_KERNEL))
		return -ENOMEM;
	if (!alloc_cpumask_var(&runtime_active, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_disabled;
	}

	ret = register_pm_notifier(&acpi_idle_pm_notifier);
	if (ret)
		goto free_mask;
	notifier_registered = true;

	register_syscore(&acpi_idle_syscore);
	syscore_registered = true;

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					"acpi/idle:online",
					acpi_idle_cpuhp_up,
					acpi_idle_cpuhp_down);
	if (ret < 0)
		goto unregister_hooks;
	hp_state = ret;

	/* The CPUHP state now excludes CPU-set changes through publication. */
	cpus_read_lock();
	if (!acpi_lpi_complete_cpu_coverage()) {
		ret = -ENODEV;
		goto remove_cpuhp;
	}
	ret = acpi_lpi_sync_runtime_pm(runtime_active);
	if (ret)
		goto remove_cpuhp;
	runtime_synced = true;

	cpuidle_pause_and_lock();
	acpi_lpi_disable_cpuidle_devices(disabled);
	ret = acpi_processor_ffh_lpi_set_mode(true);
	if (ret) {
		cleanup_ret = acpi_lpi_enable_cpuidle_devices(disabled);
		cpuidle_resume_and_unlock();
		if (cleanup_ret)
			ret = cleanup_ret;
		goto remove_cpuhp;
	}

	acpi_lpi_setup_cpuidle_states(true);
	ret = acpi_lpi_enable_cpuidle_devices(disabled);
	if (ret) {
		cleanup_ret = acpi_processor_ffh_lpi_set_mode(false);
		if (!cleanup_ret) {
			acpi_lpi_setup_cpuidle_states(false);
			cleanup_ret = acpi_lpi_enable_cpuidle_devices(disabled);
			cpuidle_resume_and_unlock();
			if (cleanup_ret)
				ret = cleanup_ret;
			goto remove_cpuhp;
		}

		/* OSI mode is still active, so retain all coordination hooks. */
		pr_err("failed to restore direct PSCI mode: %d\n", cleanup_ret);
		acpi_lpi_cpuhp_state = hp_state;
		WRITE_ONCE(acpi_lpi_lifecycle, ACPI_LPI_COORDINATED);
		cleanup_ret = acpi_lpi_enable_cpuidle_devices(disabled);
		if (cleanup_ret)
			ret = cleanup_ret;
		cpuidle_resume_and_unlock();
		cpus_read_unlock();
		free_cpumask_var(runtime_active);
		free_cpumask_var(disabled);
		return ret;
	}

	acpi_lpi_cpuhp_state = hp_state;
	WRITE_ONCE(acpi_lpi_lifecycle, ACPI_LPI_COORDINATED);
	cpuidle_resume_and_unlock();
	cpus_read_unlock();
	free_cpumask_var(runtime_active);
	free_cpumask_var(disabled);

	pr_info("hierarchical LPI coordination enabled\n");
	return 0;

remove_cpuhp:
	if (runtime_synced) {
		cleanup_ret = acpi_lpi_restore_runtime_pm(runtime_active);
		if (cleanup_ret)
			ret = cleanup_ret;
	}
	cpuhp_remove_state_nocalls_cpuslocked(hp_state);
	cpus_read_unlock();
unregister_hooks:
	if (syscore_registered)
		unregister_syscore(&acpi_idle_syscore);
	if (notifier_registered)
		unregister_pm_notifier(&acpi_idle_pm_notifier);
	WRITE_ONCE(acpi_lpi_system_sleep, false);
free_mask:
	free_cpumask_var(runtime_active);

free_disabled:
	free_cpumask_var(disabled);
	return ret;
}

static void acpi_lpi_try_activate(void)
{
	unsigned int sleep_flags;
	int ret;

	sleep_flags = lock_system_sleep();
	mutex_lock(&acpi_lpi_lifecycle_lock);
	ret = acpi_lpi_activate_locked();
	mutex_unlock(&acpi_lpi_lifecycle_lock);
	unlock_system_sleep(sleep_flags);

	if (ret && ret != -EOPNOTSUPP && ret != -ENODEV)
		pr_warn("hierarchical LPI activation failed: %d\n", ret);
}

static int acpi_lpi_deactivate_locked(void)
{
	cpumask_var_t disabled;
	int enable_ret;
	int ret;

	lockdep_assert_held(&acpi_lpi_lifecycle_lock);

	if (acpi_lpi_lifecycle != ACPI_LPI_COORDINATED)
		return 0;
	if (!alloc_cpumask_var(&disabled, GFP_KERNEL))
		return -ENOMEM;

	cpus_read_lock();
	cpuidle_pause_and_lock();
	acpi_lpi_disable_cpuidle_devices(disabled);
	ret = acpi_processor_ffh_lpi_set_mode(false);
	if (ret) {
		enable_ret = acpi_lpi_enable_cpuidle_devices(disabled);
		cpuidle_resume_and_unlock();
		goto out_unlock_cpus;
	}

	acpi_lpi_setup_cpuidle_states(false);
	WRITE_ONCE(acpi_lpi_lifecycle, ACPI_LPI_DIRECT);
	enable_ret = acpi_lpi_enable_cpuidle_devices(disabled);
	cpuidle_resume_and_unlock();

	cpuhp_remove_state_nocalls_cpuslocked(acpi_lpi_cpuhp_state);
	acpi_lpi_cpuhp_state = CPUHP_INVALID;
	cpus_read_unlock();

	unregister_syscore(&acpi_idle_syscore);
	unregister_pm_notifier(&acpi_idle_pm_notifier);
	WRITE_ONCE(acpi_lpi_syscore_suspending, false);
	WRITE_ONCE(acpi_lpi_system_sleep, false);
	cpumask_clear(&acpi_lpi_syscore_suspended_cpus);
	free_cpumask_var(disabled);
	pr_info("hierarchical LPI coordination disabled\n");
	return enable_ret;

out_unlock_cpus:
	cpus_read_unlock();
	free_cpumask_var(disabled);
	return enable_ret ?: ret;
}

static int acpi_lpi_begin_update(bool *started, unsigned int *sleep_flags)
{
	int ret = 0;

	*started = false;
	*sleep_flags = lock_system_sleep();
	mutex_lock(&acpi_lpi_lifecycle_lock);
	switch (acpi_lpi_lifecycle) {
	case ACPI_LPI_BUILDING:
		ret = -EBUSY;
		break;
	case ACPI_LPI_UPDATING:
		ret = -EBUSY;
		break;
	case ACPI_LPI_DIRECT:
	case ACPI_LPI_COORDINATED:
		ret = acpi_lpi_deactivate_locked();
		if (acpi_lpi_lifecycle == ACPI_LPI_DIRECT) {
			if (ret)
				pr_warn("continuing LPI update with cpuidle disabled: %d\n",
					ret);
			WRITE_ONCE(acpi_lpi_lifecycle, ACPI_LPI_UPDATING);
			*started = true;
			ret = 0;
		}
		break;
	}
	mutex_unlock(&acpi_lpi_lifecycle_lock);
	if (!*started)
		unlock_system_sleep(*sleep_flags);

	return ret;
}

static void acpi_lpi_end_update(bool started, unsigned int sleep_flags,
				bool reactivate)
{
	int ret = 0;

	if (!started)
		return;

	mutex_lock(&acpi_lpi_lifecycle_lock);
	if (WARN_ON_ONCE(acpi_lpi_lifecycle != ACPI_LPI_UPDATING))
		goto out;

	WRITE_ONCE(acpi_lpi_lifecycle, ACPI_LPI_DIRECT);
	if (reactivate)
		ret = acpi_lpi_activate_locked();
out:
	mutex_unlock(&acpi_lpi_lifecycle_lock);
	unlock_system_sleep(sleep_flags);

	if (ret && ret != -EOPNOTSUPP && ret != -ENODEV)
		pr_warn("hierarchical LPI reactivation failed: %d\n", ret);
}

void acpi_processor_power_init_complete(void)
{
	struct acpi_processor *pr;
	int cpu;

	mutex_lock(&acpi_lpi_lifecycle_lock);
	if (acpi_lpi_lifecycle == ACPI_LPI_BUILDING) {
		/* Initial CPUHP callbacks only mark failed processor starts. */
		cpus_read_lock();
		for_each_cpu(cpu, &acpi_lpi_excluded_cpus) {
			pr = per_cpu(processors, cpu);
			if (pr)
				acpi_processor_power_exit_locked(pr);
		}
		cpus_read_unlock();
		WRITE_ONCE(acpi_lpi_lifecycle, ACPI_LPI_DIRECT);
	}
	mutex_unlock(&acpi_lpi_lifecycle_lock);

	acpi_lpi_try_activate();
}

void acpi_processor_power_work_cancel(void)
{
	cancel_work_sync(&acpi_lpi_rebuild_work);
}

static int acpi_processor_get_power_info(struct acpi_processor *pr)
{
	int ret;

	ret = acpi_processor_get_lpi_info(pr);
	if (ret) {
		if (per_cpu(acpi_idle_data, pr->id))
			return ret;

		pr->flags.has_lpi = 0;
		pr->flags.power = 0;
		return acpi_processor_get_cstate_info(pr);
	}

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
	int ret;

	if (disabled_by_idle_boot_param())
		return 0;

	if (!pr->flags.power_setup_done || !dev)
		return -ENODEV;

	/* The dedicated LPI CPUHP state balances runtime PM in this mode. */
	if (READ_ONCE(acpi_lpi_lifecycle) == ACPI_LPI_COORDINATED)
		return 0;
	if (READ_ONCE(acpi_lpi_lifecycle) == ACPI_LPI_UPDATING)
		return -EBUSY;

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

static int acpi_lpi_rebuild_idle_states(void)
{
	struct acpi_processor *_pr;
	struct cpuidle_device *dev;
	unsigned int sleep_flags;
	bool update_started;
	int cpu;
	int ret;

	ret = acpi_lpi_begin_update(&update_started, &sleep_flags);
	if (ret)
		return ret;

	/* Resolve processor pointers only while CPU removal is excluded. */
	cpus_read_lock();
	_pr = acpi_lpi_find_representative();
	if (!_pr || !_pr->flags.power_setup_done ||
	    !acpi_idle_driver_is_registered(_pr->id)) {
		ret = -ENODEV;
		goto out;
	}

	/*
	 * Coordinated callbacks have been replaced by direct callbacks. Tear
	 * down hierarchy data before destroying cpuidle devices, so a cleanup
	 * failure leaves every CPU with a usable direct-idle path.
	 */
	for_each_possible_cpu(cpu) {
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

		_pr = per_cpu(processors, cpu);
		if (!_pr)
			continue;

		ret = acpi_processor_free_idle_data(_pr);
		if (ret)
			goto out;
	}

	/* Unregister cpuidle devices only after all hierarchy data is gone. */
	cpuidle_pause_and_lock();
	for_each_possible_cpu(cpu) {
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

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

	/* Rebuild the ACPI drivers and each CPU's idle device. */
	acpi_processor_unregister_idle_driver();
	acpi_processor_register_idle_driver();
	for_each_possible_cpu(cpu) {
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

		_pr = per_cpu(processors, cpu);
		if (_pr)
			__acpi_processor_power_init(_pr);
	}
	ret = 0;

out:
	cpus_read_unlock();
	acpi_lpi_end_update(update_started, sleep_flags, true);
	return ret;
}

int acpi_processor_power_state_has_changed(struct acpi_processor *pr)
{
	if (disabled_by_idle_boot_param())
		return 0;

	if (!pr->flags.power_setup_done)
		return -ENODEV;

	/* Any CPU-local table may have changed, so rebuild the complete topology. */
	if (!acpi_idle_driver_is_registered(pr->id))
		return 0;

	return acpi_lpi_rebuild_idle_states();
}

static void acpi_lpi_rebuild_workfn(struct work_struct *work)
{
	int ret;

	ret = acpi_lpi_rebuild_idle_states();
	if (ret)
		pr_warn("deferred LPI hierarchy rebuild failed: %d\n", ret);
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
		if (ret) {
			pr_warn("CPU%u: failed to clean up idle data: %d\n",
				pr->id, ret);
			if (!first_ret)
				first_ret = ret;
		}
		pr->flags.power_setup_done = 0;
	}

	return first_ret;
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
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

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
		if (cpumask_test_cpu(cpu, &acpi_lpi_excluded_cpus))
			continue;

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

				/* A shared driver cannot safely represent unknown CPU tables. */
				pr_warn("per-CPU ACPI LPI driver setup failed: %d\n", ret);
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
	int ret;

	/*
	 * Driver registration may have constructed the hierarchy before the
	 * processor driver itself is registered. Tear it down on every idle-driver
	 * unwind so the private bus never outlives registered virtual devices.
	 */
	ret = acpi_processor_free_all_idle_data();
	if (ret)
		pr_warn("failed to clean up ACPI idle hierarchy: %d\n", ret);

	if (READ_ONCE(acpi_idle_uses_per_cpu_drivers))
		acpi_processor_unregister_cpu_idle_drivers();
	else
		cpuidle_unregister_driver(&acpi_idle_driver);
}

static void __acpi_processor_power_init(struct acpi_processor *pr)
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
		pr->flags.power_setup_done = 0;
		return;
	}
	pr->flags.power_setup_done = 1;
	if (READ_ONCE(acpi_idle_uses_per_cpu_drivers))
		acpi_processor_setup_cpuidle_states(pr);

	if (!pr->flags.power) {
		acpi_processor_free_idle_data(pr);
		return;
	}

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
		return;
	}
}

void acpi_processor_power_init(struct acpi_processor *pr)
{
	/* A runtime CPU addition is rebuilt after its full start succeeds. */
	if (READ_ONCE(acpi_lpi_lifecycle) != ACPI_LPI_BUILDING)
		return;

	__acpi_processor_power_init(pr);
}

void acpi_processor_power_rebuild_deferred(struct acpi_processor *pr)
{
	/* CPU hotplug serializes this update against rebuild and activation. */
	cpumask_clear_cpu(pr->id, &acpi_lpi_excluded_cpus);
	if (READ_ONCE(acpi_lpi_lifecycle) != ACPI_LPI_BUILDING)
		schedule_work(&acpi_lpi_rebuild_work);
}

static void acpi_processor_power_exit_locked(struct acpi_processor *pr)
{
	struct cpuidle_device *dev = per_cpu(acpi_cpuidle_device, pr->id);
	struct acpi_idle_data *data;
	int ret;

	lockdep_assert_held(&acpi_lpi_lifecycle_lock);
	cpumask_set_cpu(pr->id, &acpi_lpi_excluded_cpus);

	/* Stop callbacks from this CPU before releasing any hierarchy data. */
	if (dev) {
		cpuidle_pause_and_lock();
		cpuidle_unregister_device_no_lock(dev);
		per_cpu(acpi_cpuidle_device, pr->id) = NULL;
		kfree(dev);
		cpuidle_resume_and_unlock();
	}

	ret = acpi_processor_free_idle_data(pr);
	if (ret) {
		data = per_cpu(acpi_idle_data, pr->id);
		/* A detached CPU no longer owns globally retained idle domains. */
		if (data && !data->domain_dev) {
			kfree(data);
			per_cpu(acpi_idle_data, pr->id) = NULL;
		}
		pr_warn("CPU%u: retained LPI resources after cleanup failure: %d\n",
			pr->id, ret);
	}

	pr->flags.power = 0;
	pr->flags.power_setup_done = 0;
}

void acpi_processor_power_init_abort(struct acpi_processor *pr)
{
	if (disabled_by_idle_boot_param())
		return;

	/* The caller holds the CPU hotplug writer lock; cleanup is deferred. */
	cpumask_set_cpu(pr->id, &acpi_lpi_excluded_cpus);
}

void acpi_processor_power_exit(struct acpi_processor *pr)
{
	unsigned int sleep_flags;

	if (disabled_by_idle_boot_param())
		return;

	sleep_flags = lock_system_sleep();
	mutex_lock(&acpi_lpi_lifecycle_lock);
	acpi_processor_power_exit_locked(pr);
	mutex_unlock(&acpi_lpi_lifecycle_lock);
	unlock_system_sleep(sleep_flags);
}

MODULE_IMPORT_NS("ACPI_PROCESSOR_IDLE");
