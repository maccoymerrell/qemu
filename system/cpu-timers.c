/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/host-utils.h"
#include "migration/vmstate.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "system/cpus.h"
#include "qemu/main-loop.h"
#include "qemu/option.h"
#include "qemu/seqlock.h"
#include "system/replay.h"
#include "system/runstate.h"
#include "hw/core/cpu.h"
#include "system/cpu-timers.h"
#include "system/cpu-timers-internal.h"

/* clock and ticks */

#ifdef CONFIG_PLUGIN
/*
 * The tick counter as a function of the virtual clock -- see
 * cpu_plugin_tsc_lock_to_vclock().  Zero @plugin_tsc_per_ns_q32 means the
 * lock has never been armed and cpu_get_ticks_locked() keeps its own host
 * source.  All four are written once, under the seqlock write lock with the
 * BQL held, and read under whichever of the two the reader already holds.
 */
static uint64_t plugin_tsc_per_ns_q32;      /* ticks per clock ns, 32.32 */
static int64_t plugin_tsc_ref_ticks;        /* ticks at the arming instant */
static int64_t plugin_tsc_ref_clk;          /* clock at the arming instant */

/*
 * The host instant at which the guest clock was stopped, or 0 while it runs.
 * Written by plugin_clock_state_add() and by cpu_enable_ticks(); read by every
 * clock reader.  See the discipline's own comment further down.
 */
static int64_t plugin_clock_frozen_at;
static bool plugin_clock_should_stop(void);

static int64_t plugin_tsc_from_clock(int64_t clk)
{
    uint64_t lo, hi;

    /*
     * @clk is cpu_get_clock_locked(), which never decreases, and @ref_clk was
     * sampled from it, so the delta cannot be negative.  The multiply is done
     * in 128 bits because a 32.32 rate times a nanosecond count overflows 64
     * for any run longer than a few seconds.
     */
    mulu64(&lo, &hi, (uint64_t)(clk - plugin_tsc_ref_clk),
           plugin_tsc_per_ns_q32);
    return plugin_tsc_ref_ticks + (int64_t)((hi << 32) | (lo >> 32));
}
#endif

static int64_t cpu_get_ticks_locked(void)
{
    int64_t ticks;

#ifdef CONFIG_PLUGIN
    if (plugin_tsc_per_ns_q32) {
        /*
         * One oscillator.  No monotonicity clamp is needed or wanted here:
         * the value is an increasing function of cpu_get_clock_locked(),
         * which is itself non-decreasing across freezes, thaws and host
         * software suspend, so the result cannot step backwards and
         * cpu_ticks_prev has nothing to correct.
         */
        return plugin_tsc_from_clock(cpu_get_clock_locked());
    }
#endif

    ticks = timers_state.cpu_ticks_offset;
    if (timers_state.cpu_ticks_enabled) {
        ticks += cpu_get_host_ticks();
    }

    if (timers_state.cpu_ticks_prev > ticks) {
        /* Non increasing ticks may happen if the host uses software suspend. */
        timers_state.cpu_ticks_offset += timers_state.cpu_ticks_prev - ticks;
        ticks = timers_state.cpu_ticks_prev;
    }

    timers_state.cpu_ticks_prev = ticks;
    return ticks;
}

/*
 * return the time elapsed in VM between vm_start and vm_stop.
 * cpu_get_ticks() uses units of the host CPU cycle counter.
 */
int64_t cpu_get_ticks(void)
{
    int64_t ticks;

    qemu_spin_lock(&timers_state.vm_clock_lock);
    ticks = cpu_get_ticks_locked();
    qemu_spin_unlock(&timers_state.vm_clock_lock);
    return ticks;
}

int64_t cpu_get_clock_locked(void)
{
    int64_t time;

    time = timers_state.cpu_clock_offset;
    if (timers_state.cpu_ticks_enabled) {
#ifdef CONFIG_PLUGIN
        /*
         * While the plugin clock discipline holds the guest clock stopped, the
         * clock reads the host instant at which it was stopped rather than the
         * host instant now.  One word decides it, so the stopping side needs no
         * lock -- see plugin_clock_state_add().
         */
        int64_t frozen = qatomic_read(&plugin_clock_frozen_at);
        time += frozen ? frozen : get_clock();
#else
        time += get_clock();
#endif
    }

    return time;
}

/*
 * Return the monotonic time elapsed in VM, i.e.,
 * the time between vm_start and vm_stop
 */
int64_t cpu_get_clock(void)
{
    int64_t ti;
    unsigned start;

    do {
        start = seqlock_read_begin(&timers_state.vm_clock_seqlock);
        ti = cpu_get_clock_locked();
    } while (seqlock_read_retry(&timers_state.vm_clock_seqlock, start));

    return ti;
}

/*
 * enable cpu_get_ticks()
 * Caller must hold BQL which serves as mutex for vm_clock_seqlock.
 */
void cpu_enable_ticks(void)
{
    seqlock_write_lock(&timers_state.vm_clock_seqlock,
                       &timers_state.vm_clock_lock);
    if (!timers_state.cpu_ticks_enabled) {
        int64_t now = get_clock();

        timers_state.cpu_ticks_offset -= cpu_get_host_ticks();
        timers_state.cpu_clock_offset -= now;
        timers_state.cpu_ticks_enabled = 1;
#ifdef CONFIG_PLUGIN
        /*
         * vm_stop owns cpu_ticks_enabled; the plugin discipline owns
         * plugin_clock_frozen_at.  They are separate variables with separate
         * owners precisely so neither has to arbitrate for the other -- but the
         * clock coming back up must land in whichever state the discipline is
         * in, or a machine restarted mid-freeze would run the guest's clock
         * through the rest of that freeze.  The SAME @now is used for both, so
         * the pair is exact rather than a second sample apart.
         */
        qatomic_set(&plugin_clock_frozen_at,
                    plugin_clock_should_stop() ? now : 0);
#endif
    }
    seqlock_write_unlock(&timers_state.vm_clock_seqlock,
                       &timers_state.vm_clock_lock);
}

/*
 * disable cpu_get_ticks() : the clock is stopped. You must not call
 * cpu_get_ticks() after that.
 * Caller must hold BQL which serves as mutex for vm_clock_seqlock.
 */
void cpu_disable_ticks(void)
{
    seqlock_write_lock(&timers_state.vm_clock_seqlock,
                       &timers_state.vm_clock_lock);
    if (timers_state.cpu_ticks_enabled) {
        timers_state.cpu_ticks_offset += cpu_get_host_ticks();
        /* Reads plugin_clock_frozen_at, so the stopped value is carried over. */
        timers_state.cpu_clock_offset = cpu_get_clock_locked();
        timers_state.cpu_ticks_enabled = 0;
#ifdef CONFIG_PLUGIN
        /* Absorbed into the offset above; a stale stamp must not be reused. */
        qatomic_set(&plugin_clock_frozen_at, 0);
#endif
    }
    seqlock_write_unlock(&timers_state.vm_clock_seqlock,
                         &timers_state.vm_clock_lock);
}

#ifdef CONFIG_PLUGIN
/*
 * THE GUEST CLOCK DISCIPLINE
 * ==========================
 *
 * Contract, and it is an equivalence, not an exclusion list:
 *
 *     The guest's virtual clock advances across guest execution, and across
 *     nothing else.
 *
 * The predecessor of this code stated the same intent the other way round --
 * it named the regions that must NOT advance the clock (a plugin's per-TB
 * callback, its translation callback, a wrong-path excursion) and stopped the
 * clock across each.  An exclusion list is only ever as complete as its
 * author's enumeration, and this one was not complete: measured on the x86_64
 * system marker shape, 47.6% of all the guest virtual time a traced run
 * produced elapsed while the vCPU was not inside translated code at all, and
 * 96.6% of that was inside tb_gen_code() -- translation, which no bracket
 * covered because no plugin callback is running there.  Per translated block
 * the guest was charged 63.5 us of its own time against 13.2 us for the same
 * block with no plugin loaded.  A guest whose clock is charged for work its
 * instructions did not do reads its own scheduling quantum as already spent
 * on every pass, and the quantity that decides it -- host time per guest
 * instruction -- is not something the enumeration can bound, because it is
 * set by the host.
 *
 * So the enumeration is gone.  The clock is stopped by default and the ONE
 * place that starts it is the entry to translated guest code, cpu_tb_exec().
 * A region can only be charged to the guest by being inside that call; there
 * is nothing to keep in sync and nothing to forget, and a future callback
 * added anywhere else is covered on the day it is written.
 *
 * The state is three counters, packed into one word so that a mutator sees
 * the whole predicate change atomically:
 *
 *   windows    plugin clock windows open anywhere (the correct-path
 *              instrumentation window, a wrong-path excursion).  Any open
 *              window stops the clock.  This is the predecessor's counter and
 *              its meaning is unchanged.
 *   in_loop    vCPUs inside cpu_exec().  When this is zero every vCPU is
 *              halted or out in the main loop, and the clock MUST run: a
 *              guest waiting in hlt for a timer deadline it computed on this
 *              clock will never be woken by a clock that is stopped.  This is
 *              the idle escape and it is what makes "stopped by default" safe.
 *   in_guest   vCPUs inside tcg_qemu_tb_exec() at the top level.  Non-zero
 *              means some vCPU is executing guest instructions.
 *
 *     stopped  <=>  windows > 0
 *                   || (armed && in_loop > 0 && in_guest == 0)
 *
 * A wrong-path excursion dispatches through cpu_tb_exec() too, so it raises
 * in_guest -- and it is correctly still frozen, because the excursion holds a
 * window and windows dominate.  Nothing special is needed for it.
 *
 * WHY THE STOPPING SIDE TAKES NO LOCK.  Stopping writes exactly one word
 * (@plugin_clock_frozen_at); cpu_clock_offset does not move.  A reader
 * therefore sees either the running form or the stopped form and both name
 * the same instant to within the gap between the get_clock() call and the
 * store that follows it -- two adjacent statements.  The predecessor took the
 * BQL here, and a BQL acquisition is a blocking wait, taken with the clock
 * still running, whose whole duration was charged to the guest: 2.13 ms in a
 * single window on a loaded host.  A wait that the guest pays for is exactly
 * the defect, so the stopping side may not contain one, and this one does not.
 *
 * WHY THE STARTING SIDE MAY.  Starting moves two words (it subtracts the
 * elapsed frozen span from cpu_clock_offset and clears the stamp), so it
 * needs the seqlock the clock's readers already use.  It runs with the clock
 * ALREADY STOPPED, so however long it waits for that lock, the guest is
 * charged nothing -- and the instant it resumes from is sampled inside the
 * lock, as late as possible, so the wait is excluded rather than billed.  The
 * asymmetry is the whole design: a wait is free when the clock is stopped and
 * ruinous when it is not.
 *
 * OWNERSHIP.  vm_stop/vm_start own cpu_ticks_enabled; this discipline owns
 * plugin_clock_frozen_at.  Two variables, two owners, so neither has to
 * arbitrate for the other.  The predecessor had both driving cpu_ticks_enabled
 * and needed a runstate_is_running() special case to keep a plugin thaw from
 * restarting a clock a vm_stop owned -- a case that could drop the last
 * reference and return with the clock stopped and no owner left to restart it.
 * That case cannot be expressed here.
 *
 * SMP RESIDUAL, stated rather than hidden: the counters are updated with one
 * atomic each and the stamp with a separate store, so two vCPUs transitioning
 * in opposite directions in the same handful of nanoseconds can leave the
 * clock stopped or running for that handful.  The error is bounded by the
 * distance between two adjacent instructions, it is not proportional to any
 * wait, and it cannot accumulate: every start subtracts the whole span the
 * stamp describes.  -smp 1, which is what the system-mode marker workflow
 * runs, has no such window at all.
 */
#define PC_WIN_SHIFT    0
#define PC_LOOP_SHIFT  20
#define PC_GUEST_SHIFT 40
#define PC_FIELD_MASK  0xfffffULL
#define PC_ONE(shift)  (1ULL << (shift))
#define PC_FIELD(s, shift) (((s) >> (shift)) & PC_FIELD_MASK)

static uint64_t plugin_clock_state;
static bool plugin_clock_armed;

static bool plugin_clock_state_stopped(uint64_t st)
{
    if (PC_FIELD(st, PC_WIN_SHIFT) != 0) {
        return true;
    }
    return plugin_clock_armed &&
           PC_FIELD(st, PC_LOOP_SHIFT) != 0 &&
           PC_FIELD(st, PC_GUEST_SHIFT) == 0;
}

static bool plugin_clock_should_stop(void)
{
    return plugin_clock_state_stopped(qatomic_read(&plugin_clock_state));
}

/* Start the clock again from the instant it was stopped.  See above. */
static void plugin_clock_start(void)
{
    seqlock_write_lock(&timers_state.vm_clock_seqlock,
                       &timers_state.vm_clock_lock);
    if (plugin_clock_frozen_at) {
        /*
         * Sampled here, holding the lock, with nothing left to do but publish:
         * everything this function waited for happened while the clock was
         * stopped and is therefore excluded from guest time, which is the
         * point.
         */
        if (timers_state.cpu_ticks_enabled) {
            timers_state.cpu_clock_offset -=
                get_clock() - plugin_clock_frozen_at;
        }
        qatomic_set(&plugin_clock_frozen_at, 0);
    }
    /*
     * A peer may have re-stopped the machine while this thread waited.  Land
     * in whichever state the counters now describe rather than in the one
     * they described on entry.
     */
    if (plugin_clock_should_stop()) {
        qatomic_set(&plugin_clock_frozen_at, get_clock());
    }
    seqlock_write_unlock(&timers_state.vm_clock_seqlock,
                         &timers_state.vm_clock_lock);
}

/*
 * @delta: the packed counter change, added atomically.
 * @at:    the host instant the caller sampled BEFORE doing anything else, or 0
 *         when the transition this call can cause is a start (which samples
 *         its own instant, late, inside the lock).
 */
static void plugin_clock_state_add(uint64_t delta, int64_t at)
{
    uint64_t old = qatomic_fetch_add(&plugin_clock_state, delta);
    bool was = plugin_clock_state_stopped(old);
    bool now = plugin_clock_state_stopped(old + delta);

    if (was == now) {
        return;
    }
    if (now) {
        /*
         * Enforced rather than reasoned: a caller that passes at == 0 is
         * asserting this call cannot stop the clock, and 0 is the running
         * sentinel, so a wrong assertion would publish "running" while the
         * counters say stopped and the clock would run until the next
         * transition.  The three stopping directions all sample first.
         */
        assert(at != 0);
        /* One word, no lock: the guest may not pay for a wait.  See above. */
        qatomic_set(&plugin_clock_frozen_at, at);
    } else {
        plugin_clock_start();
    }
}

void cpu_plugin_ticks_freeze(int cpu_index)
{
    int64_t at = get_clock();     /* FIRST statement: nothing ahead of it */

    plugin_clock_state_add(PC_ONE(PC_WIN_SHIFT), at);
}

bool cpu_plugin_ticks_thaw(int cpu_index)
{
    plugin_clock_state_add(-PC_ONE(PC_WIN_SHIFT), 0);
    return true;
}

void cpu_plugin_guest_loop_enter(void)
{
    int64_t at = get_clock();     /* FIRST statement: nothing ahead of it */

    plugin_clock_state_add(PC_ONE(PC_LOOP_SHIFT), at);
}

void cpu_plugin_guest_loop_exit(void)
{
    plugin_clock_state_add(-PC_ONE(PC_LOOP_SHIFT), 0);
}

void cpu_plugin_guest_exec_enter(void)
{
    plugin_clock_state_add(PC_ONE(PC_GUEST_SHIFT), 0);
}

void cpu_plugin_guest_exec_exit(void)
{
    int64_t at = get_clock();     /* FIRST statement: nothing ahead of it */

    plugin_clock_state_add(-PC_ONE(PC_GUEST_SHIFT), at);
}

void cpu_plugin_clock_discipline_arm(void)
{
    int64_t at = get_clock();
    uint64_t st;

    /*
     * Arming can only ever move the predicate towards stopped, and only for a
     * vCPU already inside cpu_exec() and outside translated code.  Sampling
     * first keeps that transition honest for a machine armed mid-run; the
     * ordinary case arms before any vCPU starts, where the counters are zero
     * and nothing transitions.
     */
    qatomic_set(&plugin_clock_armed, true);
    st = qatomic_read(&plugin_clock_state);
    if (plugin_clock_state_stopped(st) && !qatomic_read(&plugin_clock_frozen_at)) {
        qatomic_set(&plugin_clock_frozen_at, at);
    }
}

bool cpu_plugin_clock_discipline_armed(void)
{
    return qatomic_read(&plugin_clock_armed);
}

/*
 * cpu_plugin_tsc_lock_to_vclock: make the tick counter a function of the
 * virtual clock, so that one freeze stops both.
 * @tsc_hz: the slope, in ticks per second of QEMU_CLOCK_VIRTUAL.
 *
 * cpu_get_ticks() and cpu_get_clock() are two independent HOST oscillators:
 * the first accumulates cpu_get_host_ticks() (the host cycle counter), the
 * second get_clock() (host CLOCK_MONOTONIC).  A guest built on both -- x86
 * takes its TSC from the first and its LAPIC, HPET, PIT and ACPI PM timers
 * from the second -- only holds together while the two agree, and a plugin
 * freeze is where they stop agreeing:
 *
 *     cpu_disable_ticks()      reads the host cycle counter at instant a,
 *                              then CLOCK_MONOTONIC at instant b > a.
 *     cpu_enable_ticks()       reads the host cycle counter at instant c,
 *                              then CLOCK_MONOTONIC at instant d > c.
 *
 * The pair subtracts [a, c] from the tick counter and [b, d] from the virtual
 * clock.  Those are DIFFERENT REAL INTERVALS -- they differ by
 * (d - c) - (b - a), the difference of the two functions' own read gaps --
 * and they are subtracted in DIFFERENT UNITS, at a ratio this code never
 * measures.  Neither term is noise: the gap is a property of the compiled
 * shape of each function, so its sign is fixed and every freeze/thaw pair
 * moves the guest's tick counter the same way relative to the guest's virtual
 * clock.  A plugin that freezes once per instrumentation window performs tens
 * of thousands of pairs per second, and nothing in the pair ever gives the
 * displacement back.
 *
 * Reconciling the two afterwards cannot close this.  An architectural counter
 * that may not run backwards -- the x86 TSC -- can only be corrected upwards,
 * so a correction step ADDS agreement when the counter is behind and declines
 * when it is ahead: the disagreement is rectified rather than averaged, and
 * accumulates without bound.  Measured on the x86_64 system marker shape over
 * 556 cells with such a correction in place: the counter stood above its own
 * reference line at 100.00% of correction points in the median cell, by a
 * median 0.97 ms and a maximum 11.20 ms inside a ~20 s run.
 *
 * So the fix is not a better correction, it is removing the second
 * oscillator.  Once armed, cpu_get_ticks_locked() computes the tick counter
 * from cpu_get_clock_locked() alone.  Both then stop on the same
 * cpu_ticks_enabled and resume from the same cpu_clock_offset, so a freeze
 * removes exactly the same real interval from both BY CONSTRUCTION, whatever
 * either function's read gap is, and the two can no longer separate.
 *
 * Arming is continuous: the reference point is the pair's value at the
 * arming instant, so the guest sees no step, and the slope is the caller's
 * measured host ratio, so it sees no rate change either.  Idempotent -- the
 * first caller fixes the line; a later one must not move it, since the
 * counter would jump.  No-op for @tsc_hz <= 0.  Caller must hold the BQL.
 */
void cpu_plugin_tsc_lock_to_vclock(double tsc_hz)
{
    if (!(tsc_hz > 0)) {
        return;
    }
    seqlock_write_lock(&timers_state.vm_clock_seqlock,
                       &timers_state.vm_clock_lock);
    if (!plugin_tsc_per_ns_q32) {
        /*
         * Order matters only for readability: the reference tick value is
         * still taken from the host-sourced path, because the lock is not
         * armed until the rate is stored last.
         */
        plugin_tsc_ref_ticks = cpu_get_ticks_locked();
        plugin_tsc_ref_clk = cpu_get_clock_locked();
        plugin_tsc_per_ns_q32 =
            (uint64_t)(tsc_hz * 4294967296.0 / 1000000000.0);
    }
    seqlock_write_unlock(&timers_state.vm_clock_seqlock,
                         &timers_state.vm_clock_lock);
}
#endif

static bool icount_state_needed(void *opaque)
{
    return icount_enabled();
}

static bool warp_timer_state_needed(void *opaque)
{
    TimersState *s = opaque;
    return s->icount_warp_timer != NULL;
}

static bool adjust_timers_state_needed(void *opaque)
{
    TimersState *s = opaque;
    return s->icount_rt_timer != NULL;
}

static bool icount_shift_state_needed(void *opaque)
{
    return icount_enabled() == ICOUNT_ADAPTATIVE;
}

/*
 * Subsection for warp timer migration is optional, because may not be created
 */
static const VMStateDescription icount_vmstate_warp_timer = {
    .name = "timer/icount/warp_timer",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = warp_timer_state_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_INT64(vm_clock_warp_start, TimersState),
        VMSTATE_TIMER_PTR(icount_warp_timer, TimersState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription icount_vmstate_adjust_timers = {
    .name = "timer/icount/timers",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = adjust_timers_state_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_TIMER_PTR(icount_rt_timer, TimersState),
        VMSTATE_TIMER_PTR(icount_vm_timer, TimersState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription icount_vmstate_shift = {
    .name = "timer/icount/shift",
    .version_id = 2,
    .minimum_version_id = 2,
    .needed = icount_shift_state_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_INT16(icount_time_shift, TimersState),
        VMSTATE_INT64(last_delta, TimersState),
        VMSTATE_END_OF_LIST()
    }
};

/*
 * This is a subsection for icount migration.
 */
static const VMStateDescription icount_vmstate_timers = {
    .name = "timer/icount",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = icount_state_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_INT64(qemu_icount_bias, TimersState),
        VMSTATE_INT64(qemu_icount, TimersState),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &icount_vmstate_warp_timer,
        &icount_vmstate_adjust_timers,
        &icount_vmstate_shift,
        NULL
    }
};

static const VMStateDescription vmstate_timers = {
    .name = "timer",
    .version_id = 2,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_INT64(cpu_ticks_offset, TimersState),
        VMSTATE_UNUSED(8),
        VMSTATE_INT64_V(cpu_clock_offset, TimersState, 2),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &icount_vmstate_timers,
        NULL
    }
};

static void do_nothing(CPUState *cpu, run_on_cpu_data unused)
{
}

void qemu_timer_notify_cb(void *opaque, QEMUClockType type)
{
    if (!icount_enabled() || type != QEMU_CLOCK_VIRTUAL) {
        qemu_notify_event();
        return;
    }

    if (qemu_in_vcpu_thread()) {
        /*
         * A CPU is currently running; kick it back out to the
         * tcg_cpu_exec() loop so it will recalculate its
         * icount deadline immediately.
         */
        qemu_cpu_kick(current_cpu);
    } else if (first_cpu) {
        /*
         * qemu_cpu_kick is not enough to kick a halted CPU out of
         * qemu_tcg_wait_io_event.  async_run_on_cpu, instead,
         * causes cpu_thread_is_idle to return false.  This way,
         * handle_icount_deadline can run.
         * If we have no CPUs at all for some reason, we don't
         * need to do anything.
         */
        async_run_on_cpu(first_cpu, do_nothing, RUN_ON_CPU_NULL);
    }
}

TimersState timers_state;

/* initialize timers state and the cpu throttle for convenience */
void cpu_timers_init(void)
{
    seqlock_init(&timers_state.vm_clock_seqlock);
    qemu_spin_init(&timers_state.vm_clock_lock);
    vmstate_register(NULL, 0, &vmstate_timers, &timers_state);
}
