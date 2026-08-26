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

/**
 * cpu_plugin_spec_ticks_freeze: freeze the guest clock for a SPECULATIVE window
 * @cpu_index: the vCPU taking the reference
 *
 * The wrong-path form of cpu_plugin_ticks_freeze(), and the only form that
 * stops the clock's PROCESSING as well as its value.
 *
 * There are two kinds of plugin clock freeze in this tree and they are not the
 * same event.  A CORRECT-PATH instrumentation window brackets a plugin
 * callback that runs beside guest execution the guest itself performed: the
 * guest is between two of its own instructions, its clock must not absorb the
 * callback's host cost, and that is the whole requirement -- freezing the
 * VALUE meets it.  A SPECULATIVE window brackets execution the guest never
 * performed.  Inside it there is no guest instruction stream at all, so an
 * event derived from guest time has no legal position: a virtual-clock
 * deadline evaluated there is evaluated against a clock that is not running,
 * and a callback entered there runs on the wrong path's watch, writing state
 * the excursion's restore then rolls back.
 *
 * So the processing stall is scoped to this pair and to nothing else.  Riding
 * it on the machine-wide freeze reference instead -- which the correct-path
 * window also takes, once per translation block -- was measured: the guest's
 * timer processing was then suspended for most of the run rather than for the
 * excursions, and the x86 system marker cell went from 0 to 5 stalled cells in
 * 12 with a new 24.2-24.4k-instruction stall cluster.  The correct-path window
 * keeps its value-only freeze.
 *
 * Machine-wide, for the same reason cpu_plugin_ticks_freeze() is: one clock,
 * many windows.  A peer's translation callback takes no exec lock and would
 * otherwise run a guest timer callback inside another vCPU's excursion.
 *
 * Ordering, which is the substance of the pair: the stall is taken BEFORE the
 * value freeze and released AFTER the thaw, so the state that must not exist
 * -- value stopped while deadlines are still being evaluated against it -- has
 * zero width at both edges.
 *
 * Caller must hold the BQL.
 */
void cpu_plugin_spec_ticks_freeze(int cpu_index);

/**
 * cpu_plugin_spec_ticks_thaw: leave a speculative clock freeze
 * @cpu_index: the vCPU giving back the reference it took
 *
 * The processing stall is released on every path, including the one where the
 * value stays frozen because a vm_stop owns it -- a stall outliving the freeze
 * that justified it would silence the guest's virtual clock for the rest of
 * the run, and a stopped machine runs no guest-visible timers anyway.
 *
 * Returns nothing, unlike cpu_plugin_ticks_thaw(): that one's bool tells the
 * correct-path window whether it was the call that restarted the clock, and
 * an excursion has no use for the answer.
 *
 * Caller must hold the BQL.
 */
void cpu_plugin_spec_ticks_thaw(int cpu_index);

/**
 * cpu_plugin_tsc_lock_to_vclock: derive cpu_get_ticks() from cpu_get_clock()
 * @tsc_hz: slope of the lock, in ticks per second of QEMU_CLOCK_VIRTUAL
 *
 * cpu_get_ticks() (the guest TSC source on x86, and the cycle/time CSR source
 * elsewhere) normally accumulates the host cycle counter, while
 * cpu_get_clock() -- QEMU_CLOCK_VIRTUAL, and with it every QEMUTimer-backed
 * device clock -- accumulates host CLOCK_MONOTONIC.  Two oscillators, and a
 * freeze/thaw pair samples them at four different instants and subtracts the
 * two intervals in two different units, so each pair displaces one guest
 * clock relative to the other.  Under a plugin that freezes per
 * instrumentation window the displacement is repeated tens of thousands of
 * times a second and, because an architectural counter that may not run
 * backwards can only be corrected upwards, it is rectified rather than
 * averaged.
 *
 * Arming this makes the tick counter a fixed affine function of the virtual
 * clock, so freezing the clock freezes the counter by construction and no
 * reconciliation is needed.  See the long form in system/cpu-timers.c.
 *
 * Continuous and idempotent: the first call anchors the line at the current
 * value of the pair, later ones do nothing.  Caller must hold the BQL.
 */
void cpu_plugin_tsc_lock_to_vclock(double tsc_hz);
#endif

/**
 * vclock_agency_consume: run due QEMU_CLOCK_VIRTUAL timers in-thread
 * @cpu: the vCPU whose slice breakout this is
 * @breakout_site: site witness -- true = the slice-breakout site in
 * cpu_loop_exec_tb(), the ONLY product site; false survives so the
 * consume_dispatch counter can prove the retired dispatch-top site
 * stays gone (it must read 0 forever)
 *
 * The event-agency discipline's consumption body (see
 * qemu/vclock-agency.h): called from a vCPU-owned slice breakout when
 * the fresh qemu_clock_deadline_ns_all(VIRTUAL, ATTR_ALL) == 0 read
 * says a deadline is due.  Takes the BQL if not held; skips (and
 * counts) inside spec mode.
 *
 * DECLARED OUTSIDE CONFIG_PLUGIN ON PURPOSE.  The definition in
 * system/cpu-timers.c is unconditional and the sole call site --
 * cpu_loop_exec_tb()'s slice breakout in accel/tcg/cpu-exec.c -- is
 * guarded by !CONFIG_USER_ONLY alone, so a plugin-less system build
 * compiles and calls it.  Declaring it beside the cpu_plugin_* group
 * left that build with a definition and no prototype and it failed on
 * -Werror=missing-prototypes.
 */
void vclock_agency_consume(CPUState *cpu, bool breakout_site);

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
