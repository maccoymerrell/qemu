/*
 * Event-evaluation agency for QEMU_CLOCK_VIRTUAL -- state and
 * counters.  See include/qemu/vclock-agency.h for the
 * design; the timerlist-coupled halves (the exclusion predicate, the
 * arming folds, the resync walk) live in util/qemu-timer.c, the
 * consumption body in system/cpu-timers.c, and the arm/disarm decision
 * in plugins/{system,user}.c.
 *
 * Copyright (C) 2026, Maccoy Merrell
 *
 * This TU is linked into libqemuutil (qemu-timer.o references it), so
 * like the timer core itself it keeps no QEMU-coupled state: plain
 * globals, a QEMUTimer pointer it only ever passes back to the timer
 * API, and counters.  Nothing here is env-gated; the arming condition
 * is the runtime one (plugin loaded/instrumenting, system mode, TCG,
 * not icount) decided at the plugin loader's install/uninstall edges.
 */
#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h"
#include "qemu/vclock-agency.h"

int64_t vclock_agency_next_due = INT64_MAX;
int vclock_agency_active;
unsigned int vclock_agency_unparked;

/*
 * Depth-counted TLS bracket around the vCPU boundary's timer run, so
 * the pass classifier in timerlist_run_timers() can tell an in-thread
 * consumption from a foreign (iothread) one without linking
 * thread-identity machinery into the tools.
 */
static __thread unsigned int vagency_in_boundary_tls;

/* Set once per vCPU thread; gates park/unpark so a non-TCG accel's
 * qemu_wait_io_event() cannot unbalance the running count. */
static __thread bool vagency_thread_online_tls;

static uint64_t vagency_consume_runs;
static uint64_t vagency_spec_mode_skips;
static uint64_t vagency_stall_fence_hits;
static uint64_t vagency_foreign_vruns;
static uint64_t vagency_aio_virtual_arms;

/* Site witnesses: breakout is the one product site; dispatch is the
 * retired dispatch-top site's zero witness.  The two sum to
 * vagency_consume_runs exactly (spec-mode skips count neither). */
static uint64_t vagency_consume_dispatch;
static uint64_t vagency_consume_breakout;

/*
 * Tripwires count; they never gate, delay or abort (a mid-run abort
 * would fabricate a failure).  Each warns exactly once so a violated
 * invariant is loud in the run log, then keeps counting silently.
 */
static void vagency_warn_once(int *flag, const char *what)
{
    if (qatomic_cmpxchg(flag, 0, 1) == 0) {
        fprintf(stderr, "qemu: vclock-agency: %s (invariant violated; "
                "counting, see vclock_agency_counters)\n", what);
    }
}

/*
 * Exit report: printed only when a tripwire fired, so healthy runs stay
 * silent.  Registered lazily at first arming (system mode only).
 */
static void vclock_agency_exit_report(void)
{
    if (qatomic_read(&vagency_spec_mode_skips) ||
        qatomic_read(&vagency_stall_fence_hits) ||
        qatomic_read(&vagency_foreign_vruns) ||
        qatomic_read(&vagency_aio_virtual_arms)) {
        fprintf(stderr,
                "qemu: vclock-agency: tripwire totals: consume_runs=%"
                PRIu64 " spec_mode_skips=%" PRIu64 " stall_fence_hits=%"
                PRIu64 " foreign_vruns=%" PRIu64 " aio_virtual_arms=%"
                PRIu64 "\n",
                qatomic_read(&vagency_consume_runs),
                qatomic_read(&vagency_spec_mode_skips),
                qatomic_read(&vagency_stall_fence_hits),
                qatomic_read(&vagency_foreign_vruns),
                qatomic_read(&vagency_aio_virtual_arms));
    }
}

void vclock_agency_set_active(bool active)
{
    static bool report_registered;

    if (active) {
        if (!report_registered) {
            report_registered = true;
            atexit(vclock_agency_exit_report);
        }
        qatomic_set(&vclock_agency_active, 1);
        /* the caller (plugins/system.c) resyncs next, deriving the slot
         * from timers armed before the plugin loaded */
    } else {
        qatomic_set(&vclock_agency_active, 0);
        qatomic_set_i64(&vclock_agency_next_due, INT64_MAX);
    }
}

void vclock_agency_slot_reset(void)
{
    qatomic_set_i64(&vclock_agency_next_due, INT64_MAX);
}

/*
 * Monotone lower fold: the slot only ever moves DOWN here; only the
 * resync walk raises it (via slot_reset + refold from the lists), so a
 * concurrent arming can never be lost upward -- the slot is stale-early
 * at worst, never stale-late.
 */
void vclock_agency_fold(int64_t expire, bool main_list)
{
    int64_t cur;

    if (!qatomic_read(&vclock_agency_active)) {
        return;
    }
    if (!main_list) {
        /*
         * Design open item 3: an AioContext-attached VIRTUAL timerlist
         * is a non-vCPU consumer whose home context no longer polls on
         * VIRTUAL while engaged; its delivery bound degrades to the
         * next main-list boundary.  None exist in our machines today
         * (verified); if one appears, say so loudly.  It is still
         * folded into the slot and woken by the boundary's
         * qemu_clock_notify(VIRTUAL), exactly as icount wakes them.
         */
        static int warned;
        qatomic_inc(&vagency_aio_virtual_arms);
        vagency_warn_once(&warned, "a QEMU_CLOCK_VIRTUAL timer was armed "
                          "on a non-main-loop (AioContext) timerlist "
                          "while the event-agency discipline is active");
    }
    do {
        cur = qatomic_read_i64(&vclock_agency_next_due);
        if (expire >= cur) {
            return;
        }
    } while (qatomic_cmpxchg__nocheck(&vclock_agency_next_due,
                                      cur, expire) != cur);
}

void vclock_agency_thread_online(void)
{
    vagency_thread_online_tls = true;
    qatomic_inc(&vclock_agency_unparked);
}

void vclock_agency_thread_offline(void)
{
    if (vagency_thread_online_tls) {
        vagency_thread_online_tls = false;
        vclock_agency_vcpu_park();
    }
}

/*
 * THE HALT RULE (SMP-complete): a vCPU thread parks when it enters its
 * idle wait and unparks when it leaves.  While ANY vCPU thread is
 * unparked the exclusion holds and that thread's slice breakouts
 * consume; a halted PEER is woken by the guest interrupt the
 * consumption raises, through the stock cpu_interrupt/halt_cond path.
 * When the LAST thread parks, engaged flips false: the iothread owns
 * VIRTUAL again (there are no boundaries left to consume at, and with
 * no guest running there are no excursions, so the race this design
 * removes cannot occur).  The park edge must notify the iothread --
 * its current poll timeout was computed WITHOUT VIRTUAL; the unpark
 * edge needs no wake of its own (the breakout cadence resumes with
 * execution).  Both edges run under the BQL (the halt loops hold it),
 * serializing them against the iothread's timer dispatch.
 */
void vclock_agency_vcpu_park(void)
{
    if (!vagency_thread_online_tls) {
        return;
    }
    if (qatomic_fetch_dec(&vclock_agency_unparked) == 1 &&
        qatomic_read(&vclock_agency_active)) {
        /* engaged -> lifted: hand VIRTUAL back to the iothread NOW */
        qemu_notify_event();
    }
}

void vclock_agency_vcpu_unpark(void)
{
    if (!vagency_thread_online_tls) {
        return;
    }
    /*
     * lifted -> engaged happens on the bare increment: the exclusion
     * predicate reads unparked directly, and the iothread's stale
     * VIRTUAL wake (armed while lifted) declines through the same
     * use_for_deadline gate.  The next slice breakout consumes.
     */
    qatomic_fetch_inc(&vclock_agency_unparked);
}

void vclock_agency_boundary_begin(void)
{
    vagency_in_boundary_tls++;
}

void vclock_agency_boundary_end(void)
{
    vagency_in_boundary_tls--;
}

bool vclock_agency_in_boundary(void)
{
    return vagency_in_boundary_tls > 0;
}

void vclock_agency_note_consume(void)
{
    qatomic_inc(&vagency_consume_runs);
}

void vclock_agency_note_consume_site(bool breakout_site)
{
    if (breakout_site) {
        qatomic_inc(&vagency_consume_breakout);
    } else {
        qatomic_inc(&vagency_consume_dispatch);
    }
}

void vclock_agency_note_spec_skip(void)
{
    static int warned;

    qatomic_inc(&vagency_spec_mode_skips);
    vagency_warn_once(&warned, "a deadline boundary was reached inside "
                      "wrong-path (spec) mode -- consumption skipped; "
                      "this is a spec-escape witness");
}

void vclock_agency_note_fence_hit(void)
{
    static int warned;

    qatomic_inc(&vagency_stall_fence_hits);
    vagency_warn_once(&warned, "the wrong-path stall gate confirmed a "
                      "VIRTUAL deadline hide while the event-agency "
                      "discipline was engaged -- the excluded iothread "
                      "evaluated a VIRTUAL deadline");
}

/*
 * Pass classifier, called at every VIRTUAL timerlist_run_timers() exit
 * while active.  In-thread (under the boundary bracket) is the design;
 * an AioContext list running in its home context is icount's own
 * ungated behaviour; a MAIN-LOOP list pass outside the bracket while
 * engaged is the invariant the LX wave proved must read zero
 * (iothread_passes==0 in all six clean cells).
 */
void vclock_agency_note_vpass(bool main_list)
{
    static int warned;

    if (main_list && !vclock_agency_in_boundary() &&
        vclock_agency_engaged()) {
        qatomic_inc(&vagency_foreign_vruns);
        vagency_warn_once(&warned, "a main-loop VIRTUAL timer pass ran "
                          "outside a vCPU boundary while engaged -- the "
                          "sole-consumer invariant broke");
    }
}

void vclock_agency_counters(uint64_t out[5])
{
    out[0] = qatomic_read(&vagency_consume_runs);
    out[1] = qatomic_read(&vagency_spec_mode_skips);
    out[2] = qatomic_read(&vagency_stall_fence_hits);
    out[3] = qatomic_read(&vagency_foreign_vruns);
    out[4] = qatomic_read(&vagency_aio_virtual_arms);
}
