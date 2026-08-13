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

static int64_t cpu_get_ticks_locked(void)
{
    int64_t ticks = timers_state.cpu_ticks_offset;
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
 * CST_TSCLOCK: the guest's TSC and the guest's QEMU_CLOCK_VIRTUAL are a
 * DERIVED-VS-SOURCE PAIR -- one is computed from the host cycle counter, the
 * other from host CLOCK_MONOTONIC, and the only thing that keeps them telling
 * the same story is the pin below.  A guest whose sched_clock comes from one
 * and whose tick comes from the other cannot be reasoned about at all once
 * they disagree, so the disagreement is measured rather than assumed absent.
 *
 * Sampled at the one place both halves are read at a single instant under the
 * seqlock write lock, so the figure is the pair's real separation and not the
 * interval between two reads:
 *
 *     skew = (what a reader would get now) - (where the lock line says it is)
 *
 * AHEAD (skew > 0) is the direction the pin cannot correct: it may only push
 * the guest TSC up, since x86 forbids a backwards TSC.  BEHIND is corrected
 * in one step, and the size of that step is the guest-visible forward jump.
 * Both counters must be non-zero on a healthy run -- a zero in either column
 * means the comparison is stuck, not that the clocks agree.
 *
 * Control: CST_NOPIN measures the same pair with the offset write skipped, so
 * the skew is known to grow.  An instrument that reports a small figure under
 * CST_NOPIN is broken and its quiet reading under the pin means nothing.
 */
static bool cst_nopin(void)
{
    static int v = -1;
    if (v < 0) {
        v = getenv("CST_NOPIN") != NULL;
    }
    return v > 0;
}

/*
 * CST_TSCJUMP="<ns>:<period_pins>[:both]" -- the discriminating falsifier for
 * the whole "guest-visible time discontinuity" family, and the only way to
 * study a 1-in-370 outcome with any power.  Every @period pins, hand the guest
 * a forward step of @ns:
 *
 *   tsc   (default)  the TSC alone steps forward.  The guest's TSC-derived
 *                    sched_clock and its QEMU_CLOCK_VIRTUAL-derived LAPIC tick
 *                    now disagree by @ns: a PAIR INCONSISTENCY.
 *   both             the TSC and QEMU_CLOCK_VIRTUAL step forward together, so
 *                    every guest clock agrees that @ns elapsed: a CONSISTENT
 *                    LOSS, exactly what a host SMI or a descheduled vCPU looks
 *                    like, and something the guest is built to survive.
 *
 * The two arms separate "the guest lost time" from "the guest's clocks stopped
 * agreeing".  Diagnostic only; unset, not one branch of this is taken.
 */
static bool cst_tscjump_cfg(int64_t *ns, uint64_t *period, bool *both)
{
    static int on = -1;
    static int64_t g_ns;
    static uint64_t g_period;
    static bool g_both;

    if (on < 0) {
        const char *e = getenv("CST_TSCJUMP");
        on = 0;
        if (e && *e) {
            char *end = NULL;
            g_ns = strtoll(e, &end, 0);
            if (end && *end == ':') {
                g_period = strtoull(end + 1, &end, 0);
            }
            g_both = end && strstr(end, "both") != NULL;
            if (g_ns != 0 && g_period != 0) {
                on = 1;
                fprintf(stderr, "[tscjump] armed: %+" PRId64 " ns every %"
                        PRIu64 " pins, arm=%s\n", g_ns, g_period,
                        g_both ? "both" : "tsc");
                fflush(stderr);
            } else {
                fprintf(stderr, "[tscjump] CST_TSCJUMP=\"%s\" is not "
                        "<ns>:<period>[:both]; refused\n", e);
                fflush(stderr);
            }
        }
    }
    *ns = g_ns;
    *period = g_period;
    *both = g_both;
    return on > 0;
}

static void cst_tsclock_note(int64_t line, int64_t readable, double tsc_hz)
{
    static int on = -1;
    static uint64_t n, n_ahead, n_behind, every;
    static int64_t max_ahead, max_behind, last;

    if (on < 0) {
        const char *e = getenv("CST_TSCLOCK");
        on = e ? 1 : 0;
        every = (e && *e) ? strtoull(e, NULL, 0) : 0;
        if (every == 0) {
            every = 200000;
        }
    }
    if (!on) {
        return;
    }
    int64_t skew = readable - line;
    last = skew;
    n++;
    if (skew > 0) {
        n_ahead++;
        if (skew > max_ahead) {
            max_ahead = skew;
        }
    } else if (skew < 0) {
        n_behind++;
        if (-skew > max_behind) {
            max_behind = -skew;
        }
    }
    if ((n % every) == 0) {
        double hz = tsc_hz > 0 ? tsc_hz : 1e9;
        fprintf(stderr, "[tsclock] pins=%" PRIu64 " ahead=%" PRIu64
                " behind=%" PRIu64 " max_ahead=%.4fms max_behind=%.4fms "
                "last=%.4fms tsc_hz=%.6fGHz\n", n, n_ahead, n_behind,
                (double)max_ahead / hz * 1e3, (double)max_behind / hz * 1e3,
                (double)last / hz * 1e3, hz / 1e9);
        fflush(stderr);
    }
}

void cpu_plugin_tsc_anchor(int64_t *ref_tsc, int64_t *ref_clk)
{
    /*
     * The anchor is a POINT, so its two coordinates have to be read at one
     * instant, for the same reason the pin below evaluates the line where it
     * writes the offset.  Taken as two separate calls -- cpu_get_ticks() then
     * cpu_get_clock() -- the guest TSC is sampled before the virtual clock,
     * and the host time between the two reads becomes a PERMANENT constant
     * offset in the lock line: the line is planted that far below the
     * free-running TSC and, having the same slope, never catches up.  Since
     * the pin refuses any target below what a reader would receive, a line
     * biased low is a pin that mostly declines to act, which is not a
     * property anybody chose.
     *
     * Both coordinates are read here under the seqlock write lock the pin
     * uses, from the *_locked accessors, so no reader can observe the pair
     * half-taken and no caller can deadlock on the spinlock its own
     * cpu_get_ticks() would take.  Caller must hold BQL.
     */
    seqlock_write_lock(&timers_state.vm_clock_seqlock,
                       &timers_state.vm_clock_lock);
    *ref_tsc = cpu_get_ticks_locked();
    *ref_clk = cpu_get_clock_locked();
    seqlock_write_unlock(&timers_state.vm_clock_seqlock,
                         &timers_state.vm_clock_lock);
}

void cpu_plugin_pin_tsc(int64_t ref_tsc, int64_t ref_clk, double tsc_hz)
{
    seqlock_write_lock(&timers_state.vm_clock_seqlock,
                       &timers_state.vm_clock_lock);
    if (timers_state.cpu_ticks_enabled) {
        /*
         * The line is evaluated HERE, from a virtual-clock sample taken
         * beside the host-TSC sample the offset is derived from, because the
         * two have to describe the same instant.  A caller that computes
         * "where the virtual clock says the TSC should be" and hands the
         * answer in has already separated them: the offset written below is
         * then `where the clock was THEN` minus `the host TSC NOW`, and every
         * nanosecond between the two reads is subtracted from the guest TSC
         * and from nothing else.  The pin plants the guest TSC that far below
         * its own line, and the next pin -- which recomputes from the
         * reference point -- shoves it back up in one step.
         *
         * That is not a small effect at plugin cadence.  Measured over 38
         * cells of the x86_64 system marker shape (agentJ, lc/agentJ/pin):
         * 726 pins left the guest's architectural TSC LOWER than the previous
         * pin had set it -- the largest by 3,416,524 ticks, 1.55 ms, over a
         * 36 us real interval -- and the corrective steps reached
         * 536,335,461 ticks, 244 ms handed to the guest in one instant, with
         * 138.9 M ticks (63 ms) injected per cell at the median.  x86
         * requires the TSC to be monotonic and this class of guest marks
         * TSC-derived sched_clock stable, so it consumes both directions
         * unclamped.
         *
         * The interval between the two reads is bounded by re-reading rather
         * than assumed short: a host preemption landing between them is
         * exactly the case that produced the milliseconds above, and "rare"
         * is not a bound.  After a few attempts the pin proceeds anyway --
         * under pathological load a spin here would be worse than the
         * residual, and the residual is still clamped below.
         */
        int64_t host_tsc = 0, vclock = 0;
        for (int tries = 0; ; tries++) {
            int64_t after;
            host_tsc = cpu_get_host_ticks();
            vclock = cpu_get_clock_locked();
            after = cpu_get_host_ticks();
            if (after - host_tsc < CPU_PIN_TSC_READ_WINDOW || tries >= 8) {
                break;
            }
        }
        int64_t target = ref_tsc +
            (int64_t)(tsc_hz * (double)(vclock - ref_clk) / 1e9);
        /*
         * Guest-visible TSC monotonicity is an invariant here, not an
         * observation, and the value it must be measured against is what a
         * reader would ACTUALLY have received at @host_tsc with the offset
         * standing now -- not cpu_ticks_prev, which this function last wrote
         * as a target rather than as anything a reader was handed.  A target
         * below the free-running value is therefore refused, and refusing it
         * costs only the lock's precision: the guest TSC then runs at the
         * host rate until the line catches up, which is the same slope, since
         * tsc_hz is calibrated from that very host ratio.
         */
        int64_t readable = timers_state.cpu_ticks_offset + host_tsc;
        cst_tsclock_note(target, readable, tsc_hz);
        {
            int64_t jns; uint64_t jper; bool jboth;
            if (cst_tscjump_cfg(&jns, &jper, &jboth)) {
                static uint64_t jn;
                if ((++jn % jper) == 0) {
                    target += (int64_t)(tsc_hz * (double)jns / 1e9);
                    if (jboth) {
                        timers_state.cpu_clock_offset += jns;
                    }
                }
            }
        }
        if (target < readable) {
            target = readable;
        }
        if (target < timers_state.cpu_ticks_prev) {
            target = timers_state.cpu_ticks_prev;
        }
        if (cst_nopin()) {
            /*
             * Diagnostic arm: measure the pair without locking it, so the
             * instrument above has a control in which the skew is known to
             * grow.  Never on by default.
             */
            seqlock_write_unlock(&timers_state.vm_clock_seqlock,
                                 &timers_state.vm_clock_lock);
            return;
        }
        /* Choose the offset so cpu_get_ticks_locked() == target at the
         * instant @host_tsc was read, and keep the monotonicity clamp
         * consistent so the next read does not snap the value back forward. */
        timers_state.cpu_ticks_offset = target - host_tsc;
        timers_state.cpu_ticks_prev = target;
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
