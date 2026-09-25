/*
 * Event-evaluation agency for QEMU_CLOCK_VIRTUAL under an instrumenting
 * TCG plugin.
 *
 * Copyright (C) 2026, Maccoy Merrell
 *
 * The problem: under the default clock, VIRTUAL deadlines have a second
 * concurrent consumer besides the vCPUs -- the iothread.  A plugin that
 * runs wrong-path excursions pauses the guest clock and hides deadlines
 * from that consumer, so every excursion races it.  While a TCG plugin
 * is loaded and instrumenting in system mode, this module makes the vCPU
 * class the sole consumer of VIRTUAL deadlines instead: they are
 * evaluated at translation-block boundaries the vCPU owns, in guest
 * order.  It is icount's deadline-consumption discipline without
 * icount's timekeeping (no ns-to-insn identity, bias, warp or
 * deadline-derived slice budget).  Four mechanisms:
 *
 *   1. Slice bounding (qemu/tcg-slice.h): every TB bills its
 *      instruction count against icount_decr.u16.low as icount's
 *      prologue does, and an exhausted slice breaks the TB chain out to
 *      cpu_loop_exec_tb.  The quantum (default 65535, the u16 cadence
 *      icount itself runs at; CST_BUDGET_QUANTUM overrides within
 *      [512, 65535]) is the delivery bound in guest instructions.  The
 *      slice is armed at plugin install (system mode, TCG, not icount)
 *      and stays armed for the life of the process, because translated
 *      TBs carry the billing prologue.  A wrong-path excursion saves the
 *      correct-path budget at its open and restores it at its close, and
 *      every wrong-path dispatch runs on a full quantum, so wrong-path
 *      depth never drains the correct-path slice.  Armed together with
 *      -icount (two writers of u16.low) or in a user-mode binary (no
 *      excursion save and restore) is fatal at the first exec-loop entry.
 *   2. Consumption at the slice breakout: the vCPU reads a fresh
 *      qemu_clock_deadline_ns_all(VIRTUAL, ATTR_ALL) and, when it is 0,
 *      runs the VIRTUAL timers in-thread under the BQL
 *      (vclock_agency_consume).
 *   3. Exclusion: while engaged, qemu_clock_use_for_deadline(VIRTUAL) is
 *      false -- the same predicate icount extends -- so the iothread
 *      neither polls on nor runs main-loop VIRTUAL timers, and
 *      qemu_timer_notify_cb turns a VIRTUAL notify into a vCPU kick.
 *   4. The halt rule: while every vCPU thread is parked idle, the
 *      exclusion lifts and the iothread consumes VIRTUAL normally; with
 *      no guest running there is no excursion to race.  The park edge
 *      that empties the running set calls qemu_notify_event() so the
 *      iothread recomputes its poll timeout with VIRTUAL; the unpark
 *      edge re-engages, and a stale iothread VIRTUAL wake declines
 *      through the same gate.  The lift is exact, not timed.
 *
 * vclock_agency_next_due is a stale-early lower bound on the earliest
 * armed VIRTUAL deadline, folded down at every arming and re-derived
 * after every VIRTUAL run.  No consumption decision reads it; the
 * breakout predicate is the fresh read of mechanism 2.
 *
 * In user mode the discipline is never armed:
 * plugin_vclock_agency_set_active() is a no-op there (plugins/user.c),
 * every hook site is softmmu-only, and the slot stays INT64_MAX.
 *
 * Tripwire counters count and never gate; each warns once on its first
 * hit and is reported at exit by vclock_agency_exit_report():
 *   vagency_consume_runs      boundary consumptions; > 0 on any busy
 *                             traced system run
 *   vagency_spec_mode_skips   a boundary reached inside wrong-path mode;
 *                             non-zero means an excursion escaped
 *   vagency_stall_fence_hits  the wrong-path stall gate found a hidden
 *                             deadline while engaged; non-zero means the
 *                             excluded iothread evaluated VIRTUAL
 *   vagency_foreign_vruns     a main-loop VIRTUAL pass ran outside a vCPU
 *                             boundary while engaged; non-zero means the
 *                             sole-consumer invariant broke
 *   vagency_aio_virtual_arms  a VIRTUAL timer was armed on an AioContext
 *                             timerlist while active; such a consumer is
 *                             outside the discipline's delivery bound
 */
#ifndef QEMU_VCLOCK_AGENCY_H
#define QEMU_VCLOCK_AGENCY_H

#include "qemu/atomic.h"

typedef struct QEMUTimer QEMUTimer;

/*
 * Stale-early lower bound on the earliest armed VIRTUAL deadline.
 * INT64_MAX = plugin inactive or no VIRTUAL timer armed.  Maintained
 * only; nothing reads it to decide consumption.
 */
extern int64_t vclock_agency_next_due;

/* Plugin loaded/instrumenting (runtime condition, never an env knob). */
extern int vclock_agency_active;

/* vCPU threads not parked in their idle wait. */
extern unsigned int vclock_agency_unparked;


/*
 * ENGAGED = the exclusion is in force: the plugin is active and at
 * least one vCPU thread is unparked to own boundaries.  This is the
 * predicate qemu_clock_use_for_deadline() and qemu_timer_notify_cb()
 * extend, and the one the halt rule releases.
 */
static inline bool vclock_agency_engaged(void)
{
    return qatomic_read(&vclock_agency_active) &&
           qatomic_read(&vclock_agency_unparked) > 0;
}

/* Arm/disarm (plugins/system.c via plugin_vclock_agency_set_active). */
void vclock_agency_set_active(bool active);

/* Maintenance of vclock_agency_next_due (util/qemu-timer.c). */
void vclock_agency_slot_reset(void);
void vclock_agency_fold(int64_t expire, bool main_list);
void vclock_agency_resync(void);        /* defined in util/qemu-timer.c */

/* vCPU thread accounting (tcg-accel-ops-{mttcg,rr}.c, system/cpus.c). */
void vclock_agency_thread_online(void);
void vclock_agency_thread_offline(void);
void vclock_agency_vcpu_park(void);
void vclock_agency_vcpu_unpark(void);

/* Boundary bracket + counters. */
void vclock_agency_boundary_begin(void);
void vclock_agency_boundary_end(void);
void vclock_agency_note_consume(void);
void vclock_agency_note_spec_skip(void);
void vclock_agency_note_fence_hit(void);
void vclock_agency_note_vpass(bool main_list);

/*
 * Counts a consumption by site: breakout_site true is the slice
 * breakout, the only site that consumes.  The two site counts sum to
 * consume_runs.
 */
void vclock_agency_note_consume_site(bool breakout_site);

/**
 * vclock_agency_consume: run due QEMU_CLOCK_VIRTUAL timers in-thread
 * @cpu: the vCPU whose slice breakout this is
 * @breakout_site: site witness -- true = the slice-breakout site in
 * cpu_loop_exec_tb(), the ONLY product site; false survives so the
 * consume_dispatch counter can prove the retired dispatch-top site
 * stays gone (it must read 0 forever)
 *
 * The event-agency discipline's consumption body: called from a
 * vCPU-owned slice breakout when the fresh
 * qemu_clock_deadline_ns_all(VIRTUAL, ATTR_ALL) == 0 read says a
 * deadline is due.  Takes the BQL if not held; skips (and counts)
 * inside spec mode.  Defined in system/cpu-timers.c.
 */
void vclock_agency_consume(CPUState *cpu, bool breakout_site);

#endif
