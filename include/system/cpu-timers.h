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
 * The guest clock discipline.  Its contract is one sentence:
 *
 *     the guest's virtual clock advances across guest execution, and across
 *     nothing else.
 *
 * The implementation and the reasoning behind it are in system/cpu-timers.c;
 * what a caller needs is below.  None of these require the BQL -- deliberately,
 * because a blocking wait taken with the guest clock running is charged to the
 * guest, and that is the defect the discipline exists to make unrepresentable.
 */

/**
 * cpu_plugin_ticks_freeze / cpu_plugin_ticks_thaw: open and close a plugin
 * clock window
 * @cpu_index: unused; retained so call sites read as being about a vCPU
 *
 * Any open window anywhere on the machine stops the guest clock, so a
 * wrong-path excursion on one vCPU and a correct-path instrumentation window
 * on another compose without either having to know about the other.  Balanced
 * pairs, nestable.  The thaw returns true unconditionally; nothing may depend
 * on which call restarted the clock, because that is decided by the whole
 * machine's state and not by this caller's.
 */
void cpu_plugin_ticks_freeze(int cpu_index);
bool cpu_plugin_ticks_thaw(int cpu_index);

/**
 * cpu_plugin_guest_exec_enter / _exit: bracket the execution of guest code
 *
 * Called around tcg_qemu_tb_exec() -- the one call through which QEMU enters
 * translated guest code -- so that being inside that call is what makes a host
 * interval count as guest time.  Everything else the emulator does between
 * guest instructions (block lookup, translation, exception dispatch, a plugin's
 * callbacks) is outside the bracket and is therefore not charged to the guest,
 * without anyone having to enumerate it.
 */
void cpu_plugin_guest_exec_enter(void);
void cpu_plugin_guest_exec_exit(void);

/**
 * cpu_plugin_guest_loop_enter / _exit: bracket a vCPU's stay in cpu_exec()
 *
 * The idle escape.  A vCPU that has left cpu_exec() is halted or out in the
 * main loop, and its next wake is a timer deadline expressed on this very
 * clock -- so when no vCPU is inside cpu_exec() the clock runs, whatever the
 * discipline would otherwise say.  Without this, a guest that executes hlt
 * would wait on a clock only its own execution could advance.
 */
void cpu_plugin_guest_loop_enter(void);
void cpu_plugin_guest_loop_exit(void);

/**
 * cpu_plugin_clock_discipline_arm: switch the guest clock to the discipline
 *
 * Called once, when a plugin is loaded.  Before it, the clock behaves exactly
 * as an unplugged QEMU's does and only an explicit window stops it; after it,
 * the clock is stopped by default and guest execution is what starts it.  It
 * is armed by the mere presence of a plugin rather than by a plugin asking:
 * an instrumented run's host cost is not the guest's to pay, and a plugin that
 * had to opt in could forget to.
 */
void cpu_plugin_clock_discipline_arm(void);
bool cpu_plugin_clock_discipline_armed(void);

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
