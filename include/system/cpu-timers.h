/*
 * CPU timers state API
 *
 * Copyright 2020 SUSE LLC
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */
#ifndef SYSTEM_CPU_TIMERS_H
#define SYSTEM_CPU_TIMERS_H

#include "qemu/timer.h"

/* init the whole cpu timers API, including icount, ticks, and cpu_throttle */
void cpu_timers_init(void);

/* icount - Instruction Counter API */

/**
 * ICountMode: icount enablement state:
 *
 * @ICOUNT_DISABLED: Disabled - Do not count executed instructions.
 * @ICOUNT_PRECISE: Enabled - Fixed conversion of insn to ns via "shift" option
 * @ICOUNT_ADAPTATIVE: Enabled - Runtime adaptive algorithm to compute shift
 */
typedef enum {
    ICOUNT_DISABLED = 0,
    ICOUNT_PRECISE,
    ICOUNT_ADAPTATIVE,
} ICountMode;

#if defined(CONFIG_TCG) && !defined(CONFIG_USER_ONLY)
extern ICountMode use_icount;
#define icount_enabled() (use_icount)
#else
#define icount_enabled() ICOUNT_DISABLED
#endif

/*
 * Update the icount with the executed instructions. Called by
 * cpus-tcg vCPU thread so the main-loop can see time has moved forward.
 */
void icount_update(CPUState *cpu);

/* get raw icount value */
int64_t icount_get_raw(void);

/* return the virtual CPU time in ns, based on the instruction counter. */
int64_t icount_get(void);
/*
 * convert an instruction counter value to ns, based on the icount shift.
 * This shift is set as a fixed value with the icount "shift" option
 * (precise mode), or it is constantly approximated and corrected at
 * runtime in adaptive mode.
 */
int64_t icount_to_ns(int64_t icount);

/**
 * icount_configure: configure the icount options, including "shift"
 * @opts: Options to parse
 * @errp: pointer to a NULL-initialized error object
 *
 * Return: true on success, else false setting @errp with error
 */
bool icount_configure(QemuOpts *opts, Error **errp);

/* used by tcg vcpu thread to calc icount budget */
int64_t icount_round(int64_t count);

/* if the CPUs are idle, start accounting real time to virtual clock. */
void icount_start_warp_timer(void);
void icount_account_warp_timer(void);
void icount_notify_exit(void);

#ifdef CONFIG_PLUGIN
/**
 * IcountFreeze: saved instruction-counter position across a plugin clock freeze
 *
 * Opaque to callers; only icount_plugin_freeze/_thaw interpret it.  @active
 * distinguishes "nothing was captured" (icount off, or an unbalanced thaw)
 * from a captured position of zero.
 */
typedef struct IcountFreeze {
    int64_t budget;
    int64_t extra;
    int64_t qemu_icount;
    uint16_t decr_low;
    bool active;
} IcountFreeze;

/**
 * icount_plugin_freeze: capture the instruction-counter position
 * @cpu: the vCPU entering the freeze (must be the caller's own vCPU)
 * @st: save area, filled in
 *
 * Companion to cpu_disable_ticks() for -icount runs.  With icount enabled the
 * guest's virtual clock is driven by RETIRED INSTRUCTIONS, not by the host
 * wall clock, so stopping the wall clock does not stop guest time: the
 * instructions a plugin executes speculatively would advance
 * QEMU_CLOCK_VIRTUAL exactly as correct-path ones do.  Capture the position
 * here and restore it with icount_plugin_thaw() so the frozen window consumes
 * zero icount as well as zero wall time -- the same freeze-and-resync
 * principle, applied to the other clock source.
 *
 * No-op (and leaves @st inactive) when icount is disabled.  Must be called
 * with the BQL held.
 */
void icount_plugin_freeze(CPUState *cpu, IcountFreeze *st);

/**
 * icount_plugin_thaw: restore a captured instruction-counter position
 * @cpu: the vCPU leaving the freeze
 * @st: save area filled by icount_plugin_freeze(); consumed (deactivated)
 *
 * Rewinds both the per-vCPU in-flight counters and the global accumulator to
 * the captured position, so no instruction executed inside the window is
 * visible to QEMU_CLOCK_VIRTUAL.  Must be called with the BQL held.
 */
void icount_plugin_thaw(CPUState *cpu, IcountFreeze *st);
#endif /* CONFIG_PLUGIN */

/*
 * CPU Ticks and Clock
 */

/* Caller must hold BQL */
void cpu_enable_ticks(void);
/* Caller must hold BQL */
void cpu_disable_ticks(void);

#ifdef CONFIG_PLUGIN
/*
 * Force cpu_get_ticks() (the guest TSC source) to read @target_tsc right now by
 * re-basing cpu_ticks_offset, without touching cpu_clock_offset.  Used by the
 * wrong-path tracer to re-lock the guest TSC to QEMU_CLOCK_VIRTUAL after each
 * speculative excursion: the guest TSC is derived from the host rdtsc and the
 * guest HPET from host CLOCK_MONOTONIC, two host oscillators whose ratio drifts
 * across excursions, so without re-locking they diverge and the guest's
 * clocksource watchdog marks the TSC unstable.  No-op while ticks are disabled.
 * Caller must hold BQL.
 */
void cpu_plugin_pin_tsc(int64_t target_tsc);
#endif

/*
 * return the time elapsed in VM between vm_start and vm_stop.
 * cpu_get_ticks() uses units of the host CPU cycle counter.
 */
int64_t cpu_get_ticks(void);

/*
 * Returns the monotonic time elapsed in VM, i.e.,
 * the time between vm_start and vm_stop
 */
int64_t cpu_get_clock(void);

void qemu_timer_notify_cb(void *opaque, QEMUClockType type);

/* get/set VIRTUAL clock and VM elapsed ticks via the cpus accel interface */
int64_t cpus_get_virtual_clock(void);
void cpus_set_virtual_clock(int64_t new_time);
int64_t cpus_get_elapsed_ticks(void);

#endif /* SYSTEM_CPU_TIMERS_H */
