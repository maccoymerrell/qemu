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
        time += get_clock();
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
        timers_state.cpu_ticks_offset -= cpu_get_host_ticks();
        timers_state.cpu_clock_offset -= get_clock();
        timers_state.cpu_ticks_enabled = 1;
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
        timers_state.cpu_clock_offset = cpu_get_clock_locked();
        timers_state.cpu_ticks_enabled = 0;
    }
    seqlock_write_unlock(&timers_state.vm_clock_seqlock,
                         &timers_state.vm_clock_lock);
}

#ifdef CONFIG_PLUGIN
/*
 * Outstanding plugin clock freezes, across every vCPU.  Guarded by the BQL,
 * which both entry points below require and which cpu_enable_ticks() and
 * cpu_disable_ticks() already require for the seqlock they write.
 *
 * The count exists because the thing being counted is global while its owners
 * are not.  timers_state is one clock for the whole machine and
 * cpu_ticks_enabled is one boolean, while a plugin freeze is opened and
 * closed per-vCPU: the wrong-path excursion pause in cpu_plugin_spec_vtime_
 * pause() belongs to the excursion's vCPU, and the correct-path
 * instrumentation window in cpu_plugin_vclock_pause() belongs to whichever
 * vCPU is running a plugin callback -- including a translation callback,
 * which is not serialised against a peer's excursion at all.  With both
 * calling cpu_disable_ticks()/cpu_enable_ticks() directly, the peer's window
 * closing restarted the guest clock in the middle of the excursion, and the
 * excursion's own thaw then found the clock already running and did nothing:
 * the guest clock advanced by the excursion's remaining host wall time,
 * which is exactly what the freeze exists to prevent.
 *
 * The holder array alongside it exists to MEASURE the defect this count
 * closes, rather than assert it: each entry names the vCPU that took one
 * outstanding reference, so a thaw can tell that the freeze it is leaving
 * behind is held ONLY by other vCPUs.  That is exactly the predecessor's
 * failure condition -- its own guards saw this vCPU's windows and nothing
 * else, so it called cpu_enable_ticks() precisely then.  A residual that
 * still includes this vCPU's own outer window is NOT counted: the
 * predecessor handled that case correctly.  Structurally zero on a
 * single-vCPU machine.
 */
#define PLUGIN_TICKS_HOLDERS_MAX 64
static int plugin_ticks_freeze_depth;
static int plugin_ticks_holder[PLUGIN_TICKS_HOLDERS_MAX];
static bool plugin_ticks_holders_overflowed;
static uint64_t plugin_ticks_peer_only_thaws;

void cpu_plugin_ticks_freeze(int cpu_index)
{
    assert(bql_locked());
    if (plugin_ticks_freeze_depth < PLUGIN_TICKS_HOLDERS_MAX) {
        plugin_ticks_holder[plugin_ticks_freeze_depth] = cpu_index;
    } else {
        plugin_ticks_holders_overflowed = true;
    }
    if (plugin_ticks_freeze_depth++ == 0) {
        cpu_disable_ticks();
    }
}

bool cpu_plugin_ticks_thaw(int cpu_index)
{
    assert(bql_locked());
    assert(plugin_ticks_freeze_depth > 0);

    /* Drop one reference belonging to @cpu_index, keeping the array packed. */
    int n = MIN(plugin_ticks_freeze_depth, PLUGIN_TICKS_HOLDERS_MAX);
    for (int i = n - 1; i >= 0; i--) {
        if (plugin_ticks_holder[i] == cpu_index) {
            plugin_ticks_holder[i] = plugin_ticks_holder[n - 1];
            break;
        }
    }
    if (--plugin_ticks_freeze_depth > 0) {
        bool mine_remains = false;
        n = MIN(plugin_ticks_freeze_depth, PLUGIN_TICKS_HOLDERS_MAX);
        for (int i = 0; i < n; i++) {
            if (plugin_ticks_holder[i] == cpu_index) {
                mine_remains = true;
                break;
            }
        }
        if (!mine_remains) {
            plugin_ticks_peer_only_thaws++;
        }
        return false;
    }
    if (!runstate_is_running()) {
        return false;
    }
    cpu_enable_ticks();
    return true;
}

uint64_t cpu_plugin_ticks_peer_only_thaws(void)
{
    return plugin_ticks_holders_overflowed ? UINT64_MAX
                                           : plugin_ticks_peer_only_thaws;
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
