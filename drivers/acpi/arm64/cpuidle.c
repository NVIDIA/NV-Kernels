// SPDX-License-Identifier: GPL-2.0-only
/*
 * ARM64 CPU idle arch support
 *
 * Copyright (C) 2014 ARM Ltd.
 * Author: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
 */

#include <linux/acpi.h>
#include <linux/cpuidle.h>
#include <linux/cpu_pm.h>
#include <linux/overflow.h>
#include <linux/psci.h>
#include <acpi/processor.h>

#define ARM64_LPI_IS_RETENTION_STATE(arch_flags) (!(arch_flags))
#define ARM64_LPI_WFI_ADDRESS			0xffffffffULL

bool acpi_processor_ffh_lpi_is_wfi(const struct acpi_lpi_state *lpi)
{
	return lpi->entry_method == ACPI_CSTATE_FFH &&
	       lpi->address == ARM64_LPI_WFI_ADDRESS;
}

static int psci_acpi_cpu_init_idle(unsigned int cpu)
{
	int i;
	struct acpi_lpi_state *lpi;
	struct acpi_processor *pr = per_cpu(processors, cpu);

	if (unlikely(!pr || !pr->flags.has_lpi))
		return -EINVAL;

	/*
	 * If the PSCI cpu_suspend function hook has not been initialized
	 * idle states must not be enabled, so bail out
	 */
	if (!psci_ops.cpu_suspend)
		return -EOPNOTSUPP;

	for (i = 1; i < pr->power.count; i++) {
		u32 state;

		lpi = &pr->power.lpi_states[i];
		/*
		 * Only bits[31:0] represent a PSCI power_state while
		 * bits[63:32] must be 0x0 as per ARM ACPI FFH Specification
		 */
		state = lpi->address;
		if (!psci_power_state_is_valid(state)) {
			pr_warn("Invalid PSCI power state %#x\n", state);
			return -EINVAL;
		}
	}

	return 0;
}

int acpi_processor_ffh_lpi_probe(unsigned int cpu)
{
	return psci_acpi_cpu_init_idle(cpu);
}

bool acpi_processor_ffh_lpi_hierarchy_supported(void)
{
	return psci_has_osi_support();
}

int acpi_processor_ffh_lpi_set_mode(bool enable)
{
	return psci_set_osi_mode(enable);
}

int acpi_processor_ffh_lpi_prepare_state(struct acpi_lpi_state *lpi)
{
	if (lpi->entry_method != ACPI_CSTATE_FFH)
		return -EINVAL;

	if (check_add_overflow(lpi->address, lpi->level_id, &lpi->address))
		return -EOVERFLOW;
	if (upper_32_bits(lpi->address))
		return -ERANGE;
	if (!psci_power_state_is_valid(lower_32_bits(lpi->address)))
		return -EINVAL;

	return 0;
}

__cpuidle int acpi_processor_ffh_lpi_enter(struct acpi_lpi_state *lpi)
{
	u32 state = lpi->address;

	if (ARM64_LPI_IS_RETENTION_STATE(lpi->arch_flags))
		return CPU_PM_CPU_IDLE_ENTER_RETENTION_PARAM_RCU(psci_cpu_suspend_enter,
						lpi->index, state);
	else
		return CPU_PM_CPU_IDLE_ENTER_PARAM_RCU(psci_cpu_suspend_enter,
					     lpi->index, state);
}
