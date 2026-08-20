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
#include "qemu/main-loop.h"
#include "qemu/timer.h"
#include "qemu/lockable.h"
#include "qemu/error-report.h"
#include "system/cpu-timers.h"
#include "system/replay.h"
#include "system/cpus.h"
#include "qemu/vclock-agency.h"

#ifdef CONFIG_POSIX
#include <pthread.h>
#endif

#ifdef CONFIG_PPOLL
#include <poll.h>
#endif

#ifdef CONFIG_PRCTL_PR_SET_TIMERSLACK
#include <sys/prctl.h>
#endif

/***********************************************************/
/* timers */

typedef struct QEMUClock {
    /* We rely on BQL to protect the timerlists */
    QLIST_HEAD(, QEMUTimerList) timerlists;

    QEMUClockType type;
    bool enabled;
} QEMUClock;

QEMUTimerListGroup main_loop_tlg;
static QEMUClock qemu_clocks[QEMU_CLOCK_MAX];

/* A QEMUTimerList is a list of timers attached to a clock. More
 * than one QEMUTimerList can be attached to each clock, for instance
 * used by different AioContexts / threads. Each clock also has
 * a list of the QEMUTimerLists associated with it, in order that
 * reenabling the clock can call all the notifiers.
 */

struct QEMUTimerList {
    QEMUClock *clock;
    QemuMutex active_timers_lock;
    QEMUTimer *active_timers;
    QLIST_ENTRY(QEMUTimerList) list;
    QEMUTimerListNotifyCB *notify_cb;
    void *notify_opaque;

    /* lightweight method to mark the end of timerlist's running */
    QemuEvent timers_done_ev;

    /*
     * Generation counter for timerlist_run_timers(): bumped once per pass,
     * stamped into every timer whose callback that pass runs.  Only ever
     * compared for equality, so wrap is irrelevant.
     */
    uint64_t run_pass;
};

/**
 * qemu_clock_ptr:
 * @type: type of clock
 *
 * Translate a clock type into a pointer to QEMUClock object.
 *
 * Returns: a pointer to the QEMUClock object
 */
static inline QEMUClock *qemu_clock_ptr(QEMUClockType type)
{
    return &qemu_clocks[type];
}

static bool timer_expired_ns(QEMUTimer *timer_head, int64_t current_time)
{
    return timer_head && (timer_head->expire_time <= current_time);
}

QEMUTimerList *timerlist_new(QEMUClockType type,
                             QEMUTimerListNotifyCB *cb,
                             void *opaque)
{
    QEMUTimerList *timer_list;
    QEMUClock *clock = qemu_clock_ptr(type);

    timer_list = g_new0(QEMUTimerList, 1);
    qemu_event_init(&timer_list->timers_done_ev, true);
    timer_list->clock = clock;
    timer_list->notify_cb = cb;
    timer_list->notify_opaque = opaque;
    qemu_mutex_init(&timer_list->active_timers_lock);
    QLIST_INSERT_HEAD(&clock->timerlists, timer_list, list);
    return timer_list;
}

void timerlist_free(QEMUTimerList *timer_list)
{
    assert(!timerlist_has_timers(timer_list));
    if (timer_list->clock) {
        QLIST_REMOVE(timer_list, list);
    }
    qemu_mutex_destroy(&timer_list->active_timers_lock);
    g_free(timer_list);
}

static void qemu_clock_init(QEMUClockType type, QEMUTimerListNotifyCB *notify_cb)
{
    QEMUClock *clock = qemu_clock_ptr(type);

    /* Assert that the clock of type TYPE has not been initialized yet. */
    assert(main_loop_tlg.tl[type] == NULL);

    clock->type = type;
    clock->enabled = (type == QEMU_CLOCK_VIRTUAL ? false : true);
    QLIST_INIT(&clock->timerlists);
    main_loop_tlg.tl[type] = timerlist_new(type, notify_cb, NULL);
}

bool qemu_clock_use_for_deadline(QEMUClockType type)
{
    /*
     * Event-agency discipline (PRODUCT; see qemu/vclock-agency.h):
     * while a TCG plugin is active and a vCPU thread is unparked, the
     * vCPU class is the sole consumer of VIRTUAL deadlines and this
     * predicate excludes VIRTUAL exactly as icount's own gate does --
     * one predicate, both gated callers (the poll-timeout computation
     * via timerlistgroup_deadline_ns and qemu_clock_run_all_timers).
     * The halt rule lifts the exclusion when every vCPU thread parks
     * (vclock_agency_engaged then reads false): with no boundaries
     * left to consume at and no guest running, the iothread's stock
     * consumption is race-free and required.
     */
    return !((icount_enabled() || vclock_agency_engaged()) &&
             (type == QEMU_CLOCK_VIRTUAL));
}

void qemu_clock_notify(QEMUClockType type)
{
    QEMUTimerList *timer_list;
    QEMUClock *clock = qemu_clock_ptr(type);
    QLIST_FOREACH(timer_list, &clock->timerlists, list) {
        timerlist_notify(timer_list);
    }
}

/* Disabling the clock will wait for related timerlists to stop
 * executing qemu_run_timers.  Thus, this functions should not
 * be used from the callback of a timer that is based on @clock.
 * Doing so would cause a deadlock.
 *
 * Caller should hold BQL.
 */
void qemu_clock_enable(QEMUClockType type, bool enabled)
{
    QEMUClock *clock = qemu_clock_ptr(type);
    QEMUTimerList *tl;
    bool old = clock->enabled;
    clock->enabled = enabled;
    if (enabled && !old) {
        qemu_clock_notify(type);
    } else if (!enabled && old) {
        QLIST_FOREACH(tl, &clock->timerlists, list) {
            qemu_event_wait(&tl->timers_done_ev);
        }
    }
}

/*
 * The guest-visible virtual-clock PROCESSING stall.  See
 * qemu_clock_plugin_stall_set() in qemu/timer.h for the contract; this is
 * the state it sets and the four places that read it.
 *
 * Those four are not a list of the sites that seemed to matter.  Every
 * evaluation of a QEMU_CLOCK_VIRTUAL deadline in this file is a comparison
 * of a timer's expire_time against qemu_clock_get_ns(clock->type), and there
 * are exactly four such comparisons reachable from outside:
 *
 *     timerlist_expired()        <- qemu_clock_expired()
 *     timerlist_deadline_ns()    <- timerlistgroup_deadline_ns()
 *     qemu_clock_deadline_ns_all()
 *     timerlist_run_timers()     <- qemu_clock_run_timers(),
 *                                   timerlistgroup_run_timers(),
 *                                   qemu_clock_run_all_timers()
 *
 * Every other public entry point in this file funnels into one of them, so
 * gating these four gates the clock rather than gating a set of callers.
 * The remaining comparison, in timer_mod_ns_locked(), sorts a new deadline
 * against the ones already on the list and never reads the clock at all.
 * timer_expired() takes its current_time from its caller and is likewise not
 * an evaluation of the clock by this file.  Re-derive with:
 *
 *     grep -n 'qemu_clock_get_ns\|timer_expired_ns' util/qemu-timer.c
 *
 * The handshake with the release is Dekker's, and it is here because the
 * cost of losing it is a hang.  A reader that hides a deadline from the main
 * loop leaves the main loop parked on an infinite poll, so the release MUST
 * see the flag of every reader that hid one.  Reader: publish the flag, then
 * re-read the stall.  Releaser: clear the stall, then read the flag.  With a
 * full barrier on each side at least one of the two sees the other, so a
 * reader that still observes the stall is guaranteed to be notified, and a
 * reader that observes the release computes the real deadline instead of
 * hiding one.  A doubled notify is possible and costs a wakeup; a missed one
 * is not possible, and that is the asymmetry worth paying a fence for.
 */
static bool plugin_vclock_stall;
static bool plugin_vclock_deadline_hidden;

static bool vclock_processing_stalled(QEMUClockType type)
{
    if (type != QEMU_CLOCK_VIRTUAL) {
        return false;
    }
    if (!qatomic_read(&plugin_vclock_stall)) {
        return false;
    }
    qatomic_set(&plugin_vclock_deadline_hidden, true);
    smp_mb();
    if (qatomic_read(&plugin_vclock_stall)) {
        /*
         * Event-agency witness: with the discipline engaged the
         * iothread never evaluates a VIRTUAL deadline, so this
         * per-excursion fence is redundant and a confirmed hide here
         * must not happen.  Counted, never asserted (see the flatten
         * criterion: the stall/hidden/Dekker machinery is only
         * deleted once this counter has its witnesses).
         */
        if (vclock_agency_engaged()) {
            vclock_agency_note_fence_hit();
        }
        return true;
    }
    return false;
}

void qemu_clock_plugin_stall_set(bool on)
{
    if (on) {
        qatomic_set(&plugin_vclock_stall, true);
        return;
    }

    qatomic_set(&plugin_vclock_stall, false);
    smp_mb();
    /*
     * Notify ONLY if the stall actually hid something.  The release runs once
     * per wrong-path excursion, which on a system trace is hundreds of
     * thousands to millions of times per run, and an unconditional notify is
     * a main-loop wakeup for each one; when this switch was briefly driven
     * from the clock-value freeze instead -- once per translation block --
     * the same unconditional notify turned a 14-second fixture into a
     * 79-second one.  The wakeup belongs to the deadline that was hidden, not
     * to the freeze that hid nothing.
     */
    if (qatomic_read(&plugin_vclock_deadline_hidden) &&
        qatomic_xchg(&plugin_vclock_deadline_hidden, false)) {
        qemu_clock_notify(QEMU_CLOCK_VIRTUAL);
    }
}

bool timerlist_has_timers(QEMUTimerList *timer_list)
{
    return !!qatomic_read(&timer_list->active_timers);
}

bool qemu_clock_has_timers(QEMUClockType type)
{
    return timerlist_has_timers(
        main_loop_tlg.tl[type]);
}

bool timerlist_expired(QEMUTimerList *timer_list)
{
    int64_t expire_time = 0;

    if (!qatomic_read(&timer_list->active_timers)) {
        return false;
    }

    if (vclock_processing_stalled(timer_list->clock->type)) {
        return false;
    }

    WITH_QEMU_LOCK_GUARD(&timer_list->active_timers_lock) {
        if (!timer_list->active_timers) {
            return false;
        }
        expire_time = timer_list->active_timers->expire_time;
    }

    return expire_time <= qemu_clock_get_ns(timer_list->clock->type);
}

bool qemu_clock_expired(QEMUClockType type)
{
    return timerlist_expired(
        main_loop_tlg.tl[type]);
}

/*
 * As above, but return -1 for no deadline, and do not cap to 2^32
 * as we know the result is always positive.
 */

int64_t timerlist_deadline_ns(QEMUTimerList *timer_list)
{
    int64_t delta;
    int64_t expire_time = 0;

    if (!qatomic_read(&timer_list->active_timers)) {
        return -1;
    }

    if (!timer_list->clock->enabled) {
        return -1;
    }

    if (vclock_processing_stalled(timer_list->clock->type)) {
        return -1;
    }

    /* The active timers list may be modified before the caller uses our return
     * value but ->notify_cb() is called when the deadline changes.  Therefore
     * the caller should notice the change and there is no race condition.
     */
    WITH_QEMU_LOCK_GUARD(&timer_list->active_timers_lock) {
        if (!timer_list->active_timers) {
            return -1;
        }
        expire_time = timer_list->active_timers->expire_time;
    }

    delta = expire_time - qemu_clock_get_ns(timer_list->clock->type);

    if (delta <= 0) {
        return 0;
    }

    return delta;
}

/* Calculate the soonest deadline across all timerlists attached
 * to the clock. This is used for the icount timeout so we
 * ignore whether or not the clock should be used in deadline
 * calculations.
 */
int64_t qemu_clock_deadline_ns_all(QEMUClockType type, int attr_mask)
{
    int64_t deadline = -1;
    int64_t delta;
    int64_t expire_time;
    QEMUTimer *ts;
    QEMUTimerList *timer_list;
    QEMUClock *clock = qemu_clock_ptr(type);

    if (!clock->enabled) {
        return -1;
    }

    if (vclock_processing_stalled(type)) {
        return -1;
    }

    QLIST_FOREACH(timer_list, &clock->timerlists, list) {
        if (!qatomic_read(&timer_list->active_timers)) {
            continue;
        }
        qemu_mutex_lock(&timer_list->active_timers_lock);
        ts = timer_list->active_timers;
        /* Skip all external timers */
        while (ts && (ts->attributes & ~attr_mask)) {
            ts = ts->next;
        }
        if (!ts) {
            qemu_mutex_unlock(&timer_list->active_timers_lock);
            continue;
        }
        expire_time = ts->expire_time;
        qemu_mutex_unlock(&timer_list->active_timers_lock);

        delta = expire_time - qemu_clock_get_ns(type);
        if (delta <= 0) {
            delta = 0;
        }
        deadline = qemu_soonest_timeout(deadline, delta);
    }
    return deadline;
}

void timerlist_notify(QEMUTimerList *timer_list)
{
    if (timer_list->notify_cb) {
        timer_list->notify_cb(timer_list->notify_opaque, timer_list->clock->type);
    } else {
        qemu_notify_event();
    }
}

/* Transition function to convert a nanosecond timeout to ms
 * This is used where a system does not support ppoll
 */
int qemu_timeout_ns_to_ms(int64_t ns)
{
    int64_t ms;
    if (ns < 0) {
        return -1;
    }

    if (!ns) {
        return 0;
    }

    /* Always round up, because it's better to wait too long than to wait too
     * little and effectively busy-wait
     */
    ms = DIV_ROUND_UP(ns, SCALE_MS);

    /* To avoid overflow problems, limit this to 2^31, i.e. approx 25 days */
    return MIN(ms, INT32_MAX);
}


/* qemu implementation of g_poll which uses a nanosecond timeout but is
 * otherwise identical to g_poll
 */
int qemu_poll_ns(GPollFD *fds, guint nfds, int64_t timeout)
{
#ifdef CONFIG_PPOLL
    if (timeout < 0) {
        return ppoll((struct pollfd *)fds, nfds, NULL, NULL);
    } else {
        struct timespec ts;
        int64_t tvsec = timeout / 1000000000LL;
        /* Avoid possibly overflowing and specifying a negative number of
         * seconds, which would turn a very long timeout into a busy-wait.
         */
        if (tvsec > (int64_t)INT32_MAX) {
            tvsec = INT32_MAX;
        }
        ts.tv_sec = tvsec;
        ts.tv_nsec = timeout % 1000000000LL;
        return ppoll((struct pollfd *)fds, nfds, &ts, NULL);
    }
#else
    return g_poll(fds, nfds, qemu_timeout_ns_to_ms(timeout));
#endif
}


void timer_init_full(QEMUTimer *ts,
                     QEMUTimerListGroup *timer_list_group, QEMUClockType type,
                     int scale, int attributes,
                     QEMUTimerCB *cb, void *opaque)
{
    if (!timer_list_group) {
        timer_list_group = &main_loop_tlg;
    }
    ts->timer_list = timer_list_group->tl[type];
    ts->cb = cb;
    ts->opaque = opaque;
    ts->scale = scale;
    ts->attributes = attributes;
    ts->expire_time = -1;
    /* Never ran, so it cannot match any pass; see timerlist_run_timers(). */
    ts->last_run_pass = 0;
    ts->last_run_expire = -1;
    ts->armed_by = NULL;
}

void timer_deinit(QEMUTimer *ts)
{
    assert(ts->expire_time == -1);
    ts->timer_list = NULL;
}

static void timer_del_locked(QEMUTimerList *timer_list, QEMUTimer *ts)
{
    QEMUTimer **pt, *t;

    ts->expire_time = -1;
    pt = &timer_list->active_timers;
    for(;;) {
        t = *pt;
        if (!t)
            break;
        if (t == ts) {
            qatomic_set(pt, t->next);
            break;
        }
        pt = &t->next;
    }
}

/*
 * The timer callback this thread is currently running out of
 * timerlist_run_timers(), or NULL when no timer callback is on its stack.
 * A timer armed while this is set was armed BY that callback, which is the
 * fact the no-progress report needs and the only place it can be observed:
 * once the arming returns, the run loop can no longer tell which callback
 * put a timer back on the list.  Thread-local because timer lists belonging
 * to different AioContexts run concurrently, and saved and restored around
 * the call so a callback that runs a nested pass gets its identity back.
 */
static __thread QEMUTimerCB *timer_running_cb;

static bool timer_mod_ns_locked(QEMUTimerList *timer_list,
                                QEMUTimer *ts, int64_t expire_time)
{
    QEMUTimer **pt, *t;

    /* add the timer in the sorted list */
    pt = &timer_list->active_timers;
    for (;;) {
        t = *pt;
        if (!timer_expired_ns(t, expire_time)) {
            break;
        }
        pt = &t->next;
    }
    ts->expire_time = MAX(expire_time, 0);
    ts->armed_by = timer_running_cb;
    ts->next = *pt;
    qatomic_set(pt, ts);

    return pt == &timer_list->active_timers;
}

static void timerlist_rearm(QEMUTimerList *timer_list)
{
    timerlist_notify(timer_list);
}

/* stop a timer, but do not dealloc it */
void timer_del(QEMUTimer *ts)
{
    QEMUTimerList *timer_list = ts->timer_list;

    if (timer_list) {
        qemu_mutex_lock(&timer_list->active_timers_lock);
        timer_del_locked(timer_list, ts);
        qemu_mutex_unlock(&timer_list->active_timers_lock);
    }
}

/* modify the current timer so that it will be fired when current_time
   >= expire_time. The corresponding callback will be called. */
void timer_mod_ns(QEMUTimer *ts, int64_t expire_time)
{
    QEMUTimerList *timer_list = ts->timer_list;
    bool rearm;

    qemu_mutex_lock(&timer_list->active_timers_lock);
    timer_del_locked(timer_list, ts);
    rearm = timer_mod_ns_locked(timer_list, ts, expire_time);
    qemu_mutex_unlock(&timer_list->active_timers_lock);

    if (rearm) {
        /*
         * Event-agency slot maintenance: a rearm means this timer
         * became its list's head, i.e. a candidate clock-wide minimum.
         * Fold it BEFORE timerlist_rearm's notify, so a reader woken
         * by the notify sees a slot that already contains this
         * deadline (witness only -- the product consumes on the fresh
         * breakout-site read, never from the slot).
         */
        if (unlikely(qatomic_read(&vclock_agency_active)) &&
            timer_list->clock->type == QEMU_CLOCK_VIRTUAL) {
            vclock_agency_fold(expire_time,
                               timer_list ==
                               main_loop_tlg.tl[QEMU_CLOCK_VIRTUAL]);
        }
        timerlist_rearm(timer_list);
    }
}

/* modify the current timer so that it will be fired when current_time
   >= expire_time or the current deadline, whichever comes earlier.
   The corresponding callback will be called. */
void timer_mod_anticipate_ns(QEMUTimer *ts, int64_t expire_time)
{
    QEMUTimerList *timer_list = ts->timer_list;
    bool rearm = false;

    WITH_QEMU_LOCK_GUARD(&timer_list->active_timers_lock) {
        if (ts->expire_time == -1 || ts->expire_time > expire_time) {
            if (ts->expire_time != -1) {
                timer_del_locked(timer_list, ts);
            }
            rearm = timer_mod_ns_locked(timer_list, ts, expire_time);
        } else {
            rearm = false;
        }
    }
    if (rearm) {
        /* Event-agency slot maintenance -- see timer_mod_ns. */
        if (unlikely(qatomic_read(&vclock_agency_active)) &&
            timer_list->clock->type == QEMU_CLOCK_VIRTUAL) {
            vclock_agency_fold(expire_time,
                               timer_list ==
                               main_loop_tlg.tl[QEMU_CLOCK_VIRTUAL]);
        }
        timerlist_rearm(timer_list);
    }
}

void timer_mod(QEMUTimer *ts, int64_t expire_time)
{
    timer_mod_ns(ts, expire_time * ts->scale);
}

void timer_mod_anticipate(QEMUTimer *ts, int64_t expire_time)
{
    timer_mod_anticipate_ns(ts, expire_time * ts->scale);
}

bool timer_pending(QEMUTimer *ts)
{
    return ts->expire_time >= 0;
}

bool timer_expired(QEMUTimer *timer_head, int64_t current_time)
{
    return timer_expired_ns(timer_head, current_time * timer_head->scale);
}

/*
 * Report a timer whose deadline did not move forward (see the bound in
 * timerlist_run_timers()).
 *
 * TWO callbacks are named because two are involved and they are not always
 * the same one.  @deferred is the callback of the timer being put off.
 * @armer is the callback that ARMED that timer, taken from the timer's own
 * @armed_by stamp rather than guessed from the run loop's position: they
 * coincide for a device re-arming its OWN timer, they differ for a cycle of
 * devices arming EACH OTHER, and naming only the deferred timer points at
 * the victim and leaves the device that armed it unnamed.
 *
 * The stamp is what makes the two cases distinguishable at all.  The run
 * loop only sees an armed timer once it reaches the head of the list, and
 * ANY other timer due in the same pass is popped in between -- so "the
 * callback that just finished running" is a bystander as often as it is the
 * offender, and using it accuses whichever unrelated device happened to be
 * due alongside the broken one.  @armed_by is recorded by the arming itself
 * and cannot be confused by what ran in between.  NULL means the timer was
 * armed from outside any timer callback, which names no device model and
 * must not be dressed up as one.
 *
 * Once PER PAIR, not once per process: a warn_report_once() here would be
 * silenced by whichever device happened to be first, and keying on the
 * deferred callback alone would let one victim consume the report for every
 * offender that arms it.  The table is tiny and never grows -- past its end
 * the report degrades to once-per-process, which is still louder than
 * nothing.  Called with a list lock held, and different lists run
 * concurrently, so the slot is published with a release store and read with
 * an acquire load.  That orders the slot against the count but does not make
 * claiming a slot exclusive: two lists tripping at once can write the same
 * index, so a duplicate line can print and, if their writes interleave, one
 * slot can end up holding one pair's armer beside the other's deferred --
 * which would silence a later report for exactly that crossed pair.  Both
 * outcomes are diagnostic-only and neither can silence the first report of
 * anything, but the exclusion is not there and should not be claimed.
 */
static void timer_warn_no_progress(QEMUTimerCB *armer, QEMUTimerCB *deferred,
                                   int64_t expire)
{
    static struct { QEMUTimerCB *armer, *deferred; } warned[8];
    static unsigned n_warned;
    unsigned i, n = qatomic_load_acquire(&n_warned);

    for (i = 0; i < n && i < ARRAY_SIZE(warned); i++) {
        if (warned[i].armer == armer && warned[i].deferred == deferred) {
            return;
        }
    }
    if (n < ARRAY_SIZE(warned)) {
        warned[n].armer = armer;
        warned[n].deferred = deferred;
        qatomic_store_release(&n_warned, n + 1);
        if (armer == deferred) {
            warn_report("timer callback %p re-armed its own timer for a "
                        "deadline it had already been run for (%" PRId64 "); "
                        "deferring it to the next pass rather than looping on "
                        "it -- this is a bug in that device model", deferred,
                        expire);
        } else if (!armer) {
            warn_report("the timer of callback %p was armed for a deadline it "
                        "had already been run for (%" PRId64 ") from outside "
                        "any timer callback, so no device model is named; "
                        "deferring it to the next pass rather than looping on "
                        "it", deferred, expire);
        } else {
            warn_report("timer callback %p armed the timer of callback %p for "
                        "a deadline that timer had already been run for "
                        "(%" PRId64 "); deferring it to the next pass rather "
                        "than looping on it -- these two device models are "
                        "arming each other and neither is making progress",
                        armer, deferred, expire);
        }
    } else {
        warn_report_once("timer callback %p made no progress; deferring "
                         "(and the report table is full)", deferred);
    }
}

/*
 * Ceiling on callbacks run in a single timerlist_run_timers() pass.  See the
 * total bound in the loop; sized far above any legitimate backlog.
 */
#define TIMERLIST_MAX_CB_PER_PASS 100000

bool timerlist_run_timers(QEMUTimerList *timer_list)
{
    QEMUTimer *ts, *head;
    QEMUTimerCB *outer_cb;
    int64_t current_time;
    int64_t ran_expire;
    uint64_t pass;
    unsigned n_run = 0;
    bool progress = false;
    QEMUTimerCB *cb;
    void *opaque;

    if (!qatomic_read(&timer_list->active_timers)) {
        return false;
    }

    qemu_event_reset(&timer_list->timers_done_ev);
    if (!timer_list->clock->enabled) {
        goto out;
    }
    if (vclock_processing_stalled(timer_list->clock->type)) {
        goto out;
    }

    switch (timer_list->clock->type) {
    case QEMU_CLOCK_REALTIME:
        break;
    default:
    case QEMU_CLOCK_VIRTUAL:
        break;
    case QEMU_CLOCK_HOST:
        if (!replay_checkpoint(CHECKPOINT_CLOCK_HOST)) {
            goto out;
        }
        break;
    case QEMU_CLOCK_VIRTUAL_RT:
        if (!replay_checkpoint(CHECKPOINT_CLOCK_VIRTUAL_RT)) {
            goto out;
        }
        break;
    }

    /*
     * Extract expired timers from active timers list and process them.
     *
     * In rr mode we need "filtered" checkpointing for virtual clock.  The
     * checkpoint must be recorded/replayed before processing any non-EXTERNAL timer,
     * and that must only be done once since the clock value stays the same. Because
     * non-EXTERNAL timers may appear in the timers list while it being processed,
     * the checkpoint can be issued at a time until no timers are left and we are
     * done".
     */
    current_time = qemu_clock_get_ns(timer_list->clock->type);
    qemu_mutex_lock(&timer_list->active_timers_lock);
    pass = ++timer_list->run_pass;
    while ((ts = timer_list->active_timers)) {
        /*
         * The stall can be taken while this pass is already running -- the
         * BQL excludes a main-loop pass from overlapping a freeze entry, but
         * an iothread-owned virtual timerlist is not covered by that
         * argument.  Stop before the next pop and leave the remainder
         * armed; the release notifies, and the pass resumes from the same
         * head against the same clock value.  A callback already executing
         * runs to completion: this stops the next one, it does not drain
         * the current one, which is the whole reason it is not
         * qemu_clock_enable().
         */
        if (vclock_processing_stalled(timer_list->clock->type)) {
            qemu_mutex_unlock(&timer_list->active_timers_lock);
            goto out;
        }
        if (!timer_expired_ns(ts, current_time)) {
            /* No expired timers left.  The checkpoint can be skipped
             * if no timers fired or they were all external.
             */
            break;
        }
        /*
         * TOTAL bound, above the per-timer no-progress bound below.  That
         * one rests on a property of the device -- "the deadline moved
         * forward" -- and a device that advances its deadline by a
         * nanosecond against a backlog of seconds satisfies it while still
         * running for hours inside one pass, holding the BQL.  This bound
         * rests on nothing but arithmetic: however pathological the
         * devices, the iothread leaves this loop.  Deferring the rest costs
         * one main_loop_wait poll and drops the BQL in between, and a
         * legitimate backlog (a long vm_stop, a clock warp) is a few
         * hundred ticks, not a hundred thousand -- so nothing real is
         * throttled and the ceiling is still low enough to be a ceiling.
         */
        if (++n_run > TIMERLIST_MAX_CB_PER_PASS) {
            warn_report_once("timer list for clock %d ran %d callbacks in one "
                             "pass without draining; deferring the rest to "
                             "the next pass",
                             timer_list->clock->type,
                             TIMERLIST_MAX_CB_PER_PASS);
            qemu_mutex_unlock(&timer_list->active_timers_lock);
            goto out;
        }
        /* Checkpoint for virtual clock is redundant in cases where
         * it's being triggered with only non-EXTERNAL timers, because
         * these timers don't change guest state directly.
         */
        if (replay_mode != REPLAY_MODE_NONE
            && timer_list->clock->type == QEMU_CLOCK_VIRTUAL
            && !(ts->attributes & QEMU_TIMER_ATTR_EXTERNAL)
            && !replay_checkpoint(CHECKPOINT_CLOCK_VIRTUAL)) {
            qemu_mutex_unlock(&timer_list->active_timers_lock);
            goto out;
        }

        /* remove timer from the list before calling the callback */
        timer_list->active_timers = ts->next;
        ts->next = NULL;
        ran_expire = ts->expire_time;
        ts->expire_time = -1;
        ts->last_run_pass = pass;
        ts->last_run_expire = ran_expire;
        cb = ts->cb;
        opaque = ts->opaque;

        /*
         * Run the callback (the timer list can be modified).  Publish which
         * callback is running first: anything it arms is stamped with it, so
         * the no-progress report below can name the device that did the
         * arming instead of guessing.  Restored rather than cleared, because
         * a callback is free to run a nested pass of its own.
         */
        qemu_mutex_unlock(&timer_list->active_timers_lock);
        outer_cb = timer_running_cb;
        timer_running_cb = cb;
        cb(opaque);
        timer_running_cb = outer_cb;
        qemu_mutex_lock(&timer_list->active_timers_lock);

        progress = true;

        /*
         * NO-PROGRESS BOUND.  @current_time is sampled ONCE, before the loop,
         * and timer_expired_ns() counts expire_time <= current_time as
         * expired -- so a timer that is re-armed during this pass to a
         * deadline it has ALREADY BEEN RUN FOR is popped straight back out
         * and its callback runs again on identical inputs, forever.  The
         * iothread runs this loop holding the BQL, so the whole machine
         * stops: every vCPU starves and the guest makes no architectural
         * progress while the process burns 100% of a core.
         *
         * A running clock used to hide it (@now moves a nanosecond and the
         * loop ends), which is why such a device could sit in the tree
         * unnoticed.  A clock that does NOT run -- a TCG plugin freezing
         * QEMU_CLOCK_VIRTUAL to keep its own instrumentation cost out of
         * guest time -- removes that accident and the wedge is permanent.
         * Measured, not hypothesised: hw/timer/mips_gictimer.c re-armed at
         * exactly @now whenever the guest programmed compare == count.
         *
         * The test is whether the DEADLINE MOVED FORWARD, not whether the
         * timer came back.  A timer coming back is the normal, terminating
         * shape: a periodic device that fell behind re-arms at
         * fired-for + period, which is strictly greater every time, so it
         * catches up to @current_time in a bounded number of iterations and
         * the loop ends by itself.  hw/timer/i8254.c's pit_irq_timer does
         * exactly that on every x86 boot -- an earlier version of this bound
         * tested only "is it back at the head and expired", so the PIT ate
         * the one warning the process ever prints and a device with the real
         * defect would then have wedged the machine in silence.  A bound
         * whose alarm is consumed by a healthy device is not a bound.
         *
         * Testing the deadline rather than the identity also covers timers
         * that arm EACH OTHER: whichever of them comes round first inside a
         * cycle is being re-run for a deadline it already ran for, which is
         * the condition below.
         *
         * On a hit, leave it for the NEXT pass instead of running it again
         * here, and drop the BQL in between.  Nothing is dropped and the
         * rest of the process runs: the iothread, the monitor, and -- where
         * the vCPU is not budget-gated -- the vCPUs, which is what lets
         * whatever was freezing the clock unfreeze it and the deadline come
         * good.  Say so, and say it once per pair rather than once per
         * process, so a second offending device is still reported.
         *
         * WHAT DEFERRAL CANNOT DO is make a device ask for a later
         * deadline.  A callback that re-arms at an ABSOLUTE time already
         * behind the clock asks for the same past deadline on every pass,
         * and under -icount the guest then stops for good:
         * qemu_clock_deadline_ns_all() clamps an expired deadline to 0,
         * icount_get_limit() rounds that to a budget of 0, and
         * rr_cpu_thread_fn answers a zero deadline through
         * icount_handle_deadline() by calling qemu_clock_run_timers()
         * itself -- so the pass this bound ends is re-entered from the vCPU
         * thread with the vCPU having retired nothing in between.  What is
         * bounded is the pass, not the machine.  Measured on
         * target/riscv/debug.c as it stood before 346910c7c5, which armed
         * this timer with a raw instruction count: with the bound in, the
         * offender is named and the monitor still answers, and the guest is
         * parked all the same -- icount_get_raw() reads 19 after five
         * thousand callbacks and the PC never leaves the instruction after
         * the arming csrw.  With both bounds compiled out the same build
         * prints no warning and the monitor cannot be reached at all,
         * because this loop never returns and so never drops the BQL.
         * Deferral buys the diagnosis and the management plane; only
         * repairing the device buys the guest.
         *
         * The report names the head's ARMER as well as the head's callback.
         * In the mutual case those are DIFFERENT devices, and the deferred
         * timer belongs to the one that did not arm it: reporting the head
         * alone names the victim, tells the operator it "re-armed its own
         * timer" when it did not, and spends the pair's single report on it
         * while the device that actually armed it is never mentioned.
         *
         * The armer is @head->armed_by, recorded by the arming itself, NOT
         * @cb.  @cb is merely whatever ran last, and the loop reaches this
         * test once per callback: any other timer due in the same pass is
         * popped between the arming and the moment the armed timer surfaces
         * at the head, so @cb is a bystander as often as it is the offender.
         * Two timers on one list with the same deadline are enough -- the
         * re-armed one sorts behind the other, the other runs in between,
         * and @cb accuses a device that armed nothing at all.
         *
         * @head is only dereferenced after it is read back off the list, so
         * a callback that deleted its own timer is never touched.
         */
        head = timer_list->active_timers;
        if (head && head->last_run_pass == pass &&
            timer_expired_ns(head, current_time) &&
            head->expire_time <= head->last_run_expire) {
            timer_warn_no_progress(head->armed_by, head->cb,
                                   head->expire_time);
            qemu_mutex_unlock(&timer_list->active_timers_lock);
            goto out;
        }
    }
    qemu_mutex_unlock(&timer_list->active_timers_lock);

out:
    /*
     * Event-agency (PRODUCT): every VIRTUAL pass is classified (the
     * foreign-consumer tripwire) and the slot re-derived -- running
     * timers consumed heads, so the cached minimum must be raised to
     * the new true head.  This is the only place the slot moves UP.
     */
    if (unlikely(qatomic_read(&vclock_agency_active)) &&
        timer_list->clock->type == QEMU_CLOCK_VIRTUAL) {
        vclock_agency_note_vpass(
            timer_list == main_loop_tlg.tl[QEMU_CLOCK_VIRTUAL]);
        vclock_agency_resync();
    }
    qemu_event_set(&timer_list->timers_done_ev);
    return progress;
}

bool qemu_clock_run_timers(QEMUClockType type)
{
    return timerlist_run_timers(main_loop_tlg.tl[type]);
}

void timerlistgroup_init(QEMUTimerListGroup *tlg,
                         QEMUTimerListNotifyCB *cb, void *opaque)
{
    QEMUClockType type;
    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        tlg->tl[type] = timerlist_new(type, cb, opaque);
    }
}

void timerlistgroup_deinit(QEMUTimerListGroup *tlg)
{
    QEMUClockType type;
    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        timerlist_free(tlg->tl[type]);
    }
}

bool timerlistgroup_run_timers(QEMUTimerListGroup *tlg)
{
    QEMUClockType type;
    bool progress = false;
    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        progress |= timerlist_run_timers(tlg->tl[type]);
    }
    return progress;
}

int64_t timerlistgroup_deadline_ns(QEMUTimerListGroup *tlg)
{
    int64_t deadline = -1;
    QEMUClockType type;
    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        if (qemu_clock_use_for_deadline(type)) {
            deadline = qemu_soonest_timeout(deadline,
                                            timerlist_deadline_ns(tlg->tl[type]));
        }
    }
    return deadline;
}

int64_t qemu_clock_get_ns(QEMUClockType type)
{
    switch (type) {
    case QEMU_CLOCK_REALTIME:
        return get_clock();
    default:
    case QEMU_CLOCK_VIRTUAL:
        return cpus_get_virtual_clock();
    case QEMU_CLOCK_HOST:
        return REPLAY_CLOCK(REPLAY_CLOCK_HOST, get_clock_realtime());
    case QEMU_CLOCK_VIRTUAL_RT:
        return REPLAY_CLOCK(REPLAY_CLOCK_VIRTUAL_RT, cpu_get_clock());
    }
}

static void qemu_virtual_clock_set_ns(int64_t time)
{
    return cpus_set_virtual_clock(time);
}

void init_clocks(QEMUTimerListNotifyCB *notify_cb)
{
    QEMUClockType type;
    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        qemu_clock_init(type, notify_cb);
    }

#ifdef CONFIG_PRCTL_PR_SET_TIMERSLACK
    prctl(PR_SET_TIMERSLACK, 1, 0, 0, 0);
#endif
}

uint64_t timer_expire_time_ns(QEMUTimer *ts)
{
    return timer_pending(ts) ? ts->expire_time : -1;
}

bool qemu_clock_run_all_timers(void)
{
    bool progress = false;
    QEMUClockType type;

    for (type = 0; type < QEMU_CLOCK_MAX; type++) {
        if (qemu_clock_use_for_deadline(type)) {
            progress |= qemu_clock_run_timers(type);
        }
    }

    return progress;
}

int64_t qemu_clock_advance_virtual_time(int64_t dest)
{
    int64_t clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    AioContext *aio_context;
    aio_context = qemu_get_aio_context();
    while (clock < dest) {
        int64_t deadline = qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL,
                                                      QEMU_TIMER_ATTR_ALL);
        int64_t warp = qemu_soonest_timeout(dest - clock, deadline);

        qemu_virtual_clock_set_ns(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + warp);

        qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL);
        timerlist_run_timers(aio_context->tlg.tl[QEMU_CLOCK_VIRTUAL]);
        clock = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    }
    qemu_clock_notify(QEMU_CLOCK_VIRTUAL);

    return clock;
}

/*
 * Event-agency resync: re-derive the cached next-due VIRTUAL witness
 * slot from the timerlists themselves (the icount budget-recompute
 * pattern without the ns->insn identity).  Protocol: reset the slot to
 * INT64_MAX, then fold every list head under its lock.  A concurrent
 * armer folds too (timer_mod inserts under the list lock BEFORE
 * folding), so any timer armed before its fold is visible to this
 * walk, and the fold itself is a monotone lower bound -- the slot can
 * end stale-early, never stale-late.  Lives here because this file
 * owns qemu_clocks[] and the per-list locks.
 */
void vclock_agency_resync(void)
{
    QEMUTimerList *tl;

    if (!qatomic_read(&vclock_agency_active)) {
        return;
    }
    vclock_agency_slot_reset();
    QLIST_FOREACH(tl, &qemu_clocks[QEMU_CLOCK_VIRTUAL].timerlists, list) {
        bool has = false;
        int64_t expire = 0;

        qemu_mutex_lock(&tl->active_timers_lock);
        if (tl->active_timers) {
            has = true;
            expire = tl->active_timers->expire_time;
        }
        qemu_mutex_unlock(&tl->active_timers_lock);
        if (has) {
            vclock_agency_fold(expire,
                               tl == main_loop_tlg.tl[QEMU_CLOCK_VIRTUAL]);
        }
    }
}
