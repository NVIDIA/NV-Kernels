.. SPDX-License-Identifier: GPL-2.0

==================================================
Collaborative Processor Performance Control (CPPC)
==================================================

.. _cppc_sysfs:

CPPC
====

CPPC defined in the ACPI spec describes a mechanism for the OS to manage the
performance of a logical processor on a contiguous and abstract performance
scale. CPPC exposes a set of registers to describe abstract performance scale,
to request performance levels and to measure per-cpu delivered performance.

For more details on CPPC please refer to the ACPI specification at:

http://uefi.org/specifications

Some of the CPPC registers are exposed via sysfs under::

  /sys/devices/system/cpu/cpuX/acpi_cppc/

for each cpu X::

  $ ls -lR  /sys/devices/system/cpu/cpu0/acpi_cppc/
  /sys/devices/system/cpu/cpu0/acpi_cppc/:
  total 0
  -r--r--r-- 1 root root 65536 Mar  5 19:38 auto_activity_window
  -rw-r--r-- 1 root root 65536 Mar  5 19:38 auto_sel
  -rw-r--r-- 1 root root 65536 Mar  5 19:38 energy_perf
  -r--r--r-- 1 root root 65536 Mar  5 19:38 feedback_ctrs
  -r--r--r-- 1 root root 65536 Mar  5 19:38 guaranteed_perf
  -r--r--r-- 1 root root 65536 Mar  5 19:38 highest_perf
  -r--r--r-- 1 root root 65536 Mar  5 19:38 lowest_freq
  -r--r--r-- 1 root root 65536 Mar  5 19:38 lowest_nonlinear_perf
  -r--r--r-- 1 root root 65536 Mar  5 19:38 lowest_perf
  -rw-r--r-- 1 root root 65536 Mar  5 19:38 max_perf
  -rw-r--r-- 1 root root 65536 Mar  5 19:38 min_perf
  -r--r--r-- 1 root root 65536 Mar  5 19:38 nominal_freq
  -r--r--r-- 1 root root 65536 Mar  5 19:38 nominal_perf
  -r--r--r-- 1 root root 65536 Mar  5 19:38 per_limited
  -r--r--r-- 1 root root 65536 Mar  5 19:38 reference_perf
  -r--r--r-- 1 root root 65536 Mar  5 19:38 wraparound_time

Performance Capabilities / Thresholds:
* highest_perf : Highest performance of this processor (abstract scale).
* nominal_perf : Highest sustained performance of this processor
  (abstract scale).
* lowest_nonlinear_perf : Lowest performance of this processor with nonlinear
  power savings (abstract scale).
* lowest_perf : Lowest performance of this processor (abstract scale).
* guaranteed_perf : Current maximum sustained performance level of a processor,
  taking into account all known external constraints. All processors are expected
  to be able to sustain their guaranteed performance levels simultaneously.

* lowest_freq : CPU frequency corresponding to lowest_perf (in MHz).
* nominal_freq : CPU frequency corresponding to nominal_perf (in MHz).
  The above frequencies should only be used to report processor performance in
  frequency instead of abstract scale. These values should not be used for any
  functional decisions.

Performance Feedback:
* feedback_ctrs : Includes both Reference and delivered performance counter.
  Reference counter ticks up proportional to processor's reference performance.
  Delivered counter ticks up proportional to processor's delivered performance.
* wraparound_time: Minimum time for the feedback counters to wraparound
  (seconds).
* reference_perf : Performance level at which reference performance counter
  accumulates (abstract scale).
* perf_limited : Set when Delivered Performance has been constrained due to an
  unpredictable event. It is not utilized when Autonomous Selection is enabled.

Performance Controls:
* max_perf : Maximum performance level at which the platform may run in the
  range [Lowest Performance, Highest Performance], inclusive.
* min_perf : Minimum performance level at which the platform may run in the
  range [Lowest Performance, Highest Performance], inclusive but must be set
  to a value that is less than or equal to that specified by the max_perf.
* auto_sel : Enable Autonomous Performance Level Selection on this processor.
* auto_activity_window : Indicates a moving utilization sensitivity window to
  the platform’s autonomous selection policy.
* energy_perf: Provides a value ranging from 0 (performance preference) to
  0xFF (energy efficiency preference) that influences the rate of performance
  increase / decrease and the result of the hardware's energy efficiency and
  performance optimization policies.


Computing Average Delivered Performance
=======================================

Below describes the steps to compute the average performance delivered by
taking two different snapshots of feedback counters at time T1 and T2.

  T1: Read feedback_ctrs as fbc_t1
      Wait or run some workload

  T2: Read feedback_ctrs as fbc_t2

::

  delivered_counter_delta = fbc_t2[del] - fbc_t1[del]
  reference_counter_delta = fbc_t2[ref] - fbc_t1[ref]

  delivered_perf = (reference_perf x delivered_counter_delta) / reference_counter_delta
