/*
 * timerlist_run_timers(): a timer callback cannot wedge the iothread.
 *
 * timerlist_run_timers() samples current_time ONCE and timer_expired_ns()
 * counts expire_time <= current_time as expired, so a callback that re-arms
 * a timer at a deadline that is already in the past hands the loop its own
 * input back.  The loop runs on the iothread holding the BQL, so a device
 * that does that stops the whole machine, and a running clock hides it (@now
 * moves and the loop ends by accident).  hw/timer/mips_gictimer.c did
 * exactly that and wedged 9 of 33 traced boots once a TCG plugin froze
 * QEMU_CLOCK_VIRTUAL.
 *
 * These tests hold no clock still: they arm at a FIXED PAST TIMESTAMP, which
 * is expired against any current_time whatsoever, so they reproduce the
 * shape on a clock that is running as fast as it likes.  Each one loops
 * forever on a tree without the bound.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h"

/* Far enough back that no clock reaches it during the test. */
#define PAST_NS  1000

static QEMUTimerListGroup tlg;
static QEMUTimer ta, tb;
static unsigned n_a, n_b;
static int64_t creep_a;

static void notify_nop(void *opaque, QEMUClockType type)
{
}

/* The mips_gictimer shape: re-arm MYSELF at a deadline already passed. */
static void cb_self(void *opaque)
{
    n_a++;
    timer_mod_ns(&ta, PAST_NS);
}

/* The shape the previous bound did not cover: two devices arming EACH OTHER. */
static void cb_mutual_a(void *opaque)
{
    n_a++;
    timer_mod_ns(&tb, PAST_NS);
}

static void cb_mutual_b(void *opaque)
{
    n_b++;
    timer_mod_ns(&ta, PAST_NS);
}

/*
 * The shape the deadline test alone does NOT catch: the deadline moves
 * forward every time, so the timer is making progress by that measure --
 * just one nanosecond of it, against a backlog of seconds.  Only the
 * absolute per-pass ceiling bounds this one.
 */
static void cb_creep(void *opaque)
{
    n_a++;
    timer_mod_ns(&ta, ++creep_a);
}

static void run_once(void)
{
    timerlist_run_timers(tlg.tl[QEMU_CLOCK_REALTIME]);
}

static void test_self_rearm(void)
{
    n_a = 0;
    timer_init_full(&ta, &tlg, QEMU_CLOCK_REALTIME, SCALE_NS, 0,
                    cb_self, NULL);
    timer_mod_ns(&ta, PAST_NS);

    run_once();

    /*
     * The callback ran, so the pass really did reach the mechanism -- and it
     * ran a bounded number of times.  Two is what the deadline test costs:
     * the first re-arm may land later than the deadline it fired for (the
     * timer can be run late), and the second cannot.
     */
    g_assert_cmpuint(n_a, >, 0);
    g_assert_cmpuint(n_a, <, 8);
    timer_del(&ta);
}

static void test_mutual_rearm(void)
{
    n_a = n_b = 0;
    timer_init_full(&ta, &tlg, QEMU_CLOCK_REALTIME, SCALE_NS, 0,
                    cb_mutual_a, NULL);
    timer_init_full(&tb, &tlg, QEMU_CLOCK_REALTIME, SCALE_NS, 0,
                    cb_mutual_b, NULL);
    timer_mod_ns(&ta, PAST_NS);

    run_once();

    g_assert_cmpuint(n_a, >, 0);
    g_assert_cmpuint(n_b, >, 0);
    g_assert_cmpuint(n_a + n_b, <, 16);
    timer_del(&ta);
    timer_del(&tb);
}

static void test_creeping_rearm(void)
{
    n_a = 0;
    creep_a = PAST_NS;
    timer_init_full(&ta, &tlg, QEMU_CLOCK_REALTIME, SCALE_NS, 0,
                    cb_creep, NULL);
    timer_mod_ns(&ta, PAST_NS);

    run_once();

    /* Bounded by the ceiling, not by the device's good behaviour. */
    g_assert_cmpuint(n_a, >, 0);
    g_assert_cmpuint(n_a, <=, 100001);
    timer_del(&ta);
}

/*
 * The bound must not fire on a healthy device.  hw/timer/i8254.c's
 * pit_irq_timer catches up by re-arming at fired-for + period, strictly
 * forward, and an earlier version of this bound stopped it (and burned the
 * one warning the process prints on it).  Model that: a backlog of ten
 * periods must be delivered as ten callbacks in ONE pass.
 */
static unsigned n_catchup;
static int64_t catchup_at;

static void cb_catchup(void *opaque)
{
    n_catchup++;
    catchup_at += 1000000;               /* one "period" later */
    timer_mod_ns(&ta, catchup_at);
}

static void test_catchup_not_penalised(void)
{
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    n_catchup = 0;
    catchup_at = now - 10 * 1000000;
    timer_init_full(&ta, &tlg, QEMU_CLOCK_REALTIME, SCALE_NS, 0,
                    cb_catchup, NULL);
    timer_mod_ns(&ta, catchup_at);

    run_once();

    /* Ten periods behind: ten deliveries, all in this pass. */
    g_assert_cmpuint(n_catchup, >=, 10);
    timer_del(&ta);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    init_clocks(notify_nop);
    timerlistgroup_init(&tlg, notify_nop, NULL);

    g_test_add_func("/timer/rearm-bound/self", test_self_rearm);
    g_test_add_func("/timer/rearm-bound/mutual", test_mutual_rearm);
    g_test_add_func("/timer/rearm-bound/creeping", test_creeping_rearm);
    g_test_add_func("/timer/rearm-bound/catchup", test_catchup_not_penalised);

    return g_test_run();
}
