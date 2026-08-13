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
/**
 * cpu_plugin_ticks_freeze: stop the guest clock for a plugin window
 * @cpu_index: the vCPU taking the reference
 *
 * cpu_enable_ticks()/cpu_disable_ticks() drive a single VM-GLOBAL boolean,
 * but a plugin freeze is entered and left per-vCPU: a wrong-path excursion
 * on one vCPU and a correct-path instrumentation window on another are two
 * independent owners of that one boolean.  Called directly, the second owner
 * to leave re-enables the clock while the first is still inside its window,
 * so the first one's window is not time-transparent after all and its exit
 * finds the clock resumed from a base that moved.  These two entry points
 * reference-count the freeze across every vCPU, so ticks stop on the first
 * entry and restart only when the last window closes.
 *
 * Caller must hold the BQL.
 */
void cpu_plugin_ticks_freeze(int cpu_index);

/**
 * cpu_plugin_ticks_thaw: leave a plugin clock freeze
 * @cpu_index: the vCPU giving back the reference it took
 *
 * Returns true if this call actually restarted the clock, i.e. it was the
 * last outstanding freeze and the VM is running.  Returns false when another
 * freeze is still outstanding, or when a vm_stop owns the stopped clock (it
 * calls cpu_disable_ticks() before pausing the vCPUs, and vm_start() is what
 * restarts them) -- a plugin freeze must never fight that owner.
 *
 * Caller must hold the BQL.
 */
bool cpu_plugin_ticks_thaw(int cpu_index);

/**
 * cpu_plugin_ticks_peer_only_thaws: how often a freeze was left entirely to peers
 *
 * Counts the thaws that left the clock stopped with EVERY remaining freeze held
 * by a different vCPU.  Each one is an occasion on which restarting the clock
 * from this vCPU's own view -- which is all cpu_enable_ticks() behind a
 * per-vCPU guard can see -- would have run the guest clock inside a peer's
 * window.  A residual that still contains one of this vCPU's own windows is
 * deliberately excluded: a per-vCPU guard gets that case right.  Zero by
 * construction on a single-vCPU machine.  UINT64_MAX means the holder array
 * overflowed and the figure is not trustworthy; it is never silently capped.
 */
uint64_t cpu_plugin_ticks_peer_only_thaws(void);

/*
 * Ceiling, in host TSC ticks, on how far apart the pin's virtual-clock sample
 * and host-TSC sample may be taken; the pair is retaken while it is exceeded.
 * Orders of magnitude above an uncontended back-to-back read and far below a
 * host scheduling slice, so it separates "the two reads happened together"
 * from "this thread was descheduled between them" on any plausible host TSC
 * frequency without this header needing to know what that frequency is.
 */
#define CPU_PIN_TSC_READ_WINDOW 1000000

/*
 * Re-lock cpu_get_ticks() (the guest TSC source) to QEMU_CLOCK_VIRTUAL by
 * re-basing cpu_ticks_offset, without touching cpu_clock_offset.  The guest
 * TSC is derived from the host rdtsc and the guest HPET/LAPIC from host
 * CLOCK_MONOTONIC, two host oscillators whose ratio drifts across the tracer's
 * clock freezes, so without re-locking they diverge and the guest's
 * clocksource watchdog marks the TSC unstable.
 *
 * The caller passes the LINE -- an anchor point (@ref_tsc, @ref_clk) and its
 * slope @tsc_hz in host TSC ticks per second -- not a target computed from a
 * virtual-clock read of its own.  The clock sample and the host-TSC sample
 * must describe the same instant, which only the writer of the offset can
 * arrange; a target handed in from outside carries whatever host time elapsed
 * between the caller's read and this write, and subtracts it from the guest
 * TSC alone.  Guest-visible monotonicity is enforced against the value a
 * reader would have received, so the guest TSC never steps backwards.
 *
 * No-op while ticks are disabled.  Caller must hold BQL.
 */
void cpu_plugin_pin_tsc(int64_t ref_tsc, int64_t ref_clk, double tsc_hz);
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
