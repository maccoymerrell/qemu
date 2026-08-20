/*
 * Event-evaluation agency for QEMU_CLOCK_VIRTUAL under an instrumenting
 * TCG plugin -- PRODUCT behaviour, the shipping form of the diagnostic
 * exclusive-consumption (LX) prototype (intervention-proven:
 * wave/locus, LX 0/6 no-stall on the default clock vs LA 6/6 with the
 * async consumer kept).
 *
 * Copyright (C) 2026, Maccoy Merrell
 *
 * THE DESIGN (one decision surface): while a TCG plugin is loaded and
 * instrumenting in system mode, the vCPU class is the sole consumer of
 * QEMU_CLOCK_VIRTUAL deadlines, evaluating them at translation-block
 * boundaries it owns, in guest order.  A real core is the sole,
 * synchronous evaluator of its pending events; the default clock instead
 * leaves evaluation with a second concurrent agent (the iothread), and
 * every wrong-path excursion pauses/hides-from/races that agent.  This
 * module removes the agent rather than fencing it per-excursion.
 *
 * Mechanically it is icount's deadline-consumption discipline WITHOUT
 * icount's timekeeping: no ns->insn identity, no bias, no warp, no
 * deadline-derived slice budget.  Four pieces:
 *
 *   1. GUEST-INSN SLICE BOUNDING (see qemu/cst_bqslice.h): while the
 *      discipline is armed, every TB bills its instruction count
 *      against icount_decr.u16.low exactly as icount's translated
 *      prologue does, and an exhausted slice breaks the TB chain out
 *      to cpu_loop_exec_tb's refill.  The slice quantum IS the
 *      discipline's delivery bound, stated in guest instructions
 *      (default 65535 -- the u16 cadence icount itself runs at when a
 *      deadline exceeds the u16; CST_BUDGET_QUANTUM overrides, range
 *      [512, 65535]).  A chained run can therefore never outrun its
 *      deadlines by more than one quantum of guest instructions.
 *   2. CONSUMPTION AT THE SLICE BREAKOUT: at each slice exhaustion the
 *      vCPU evaluates a FRESH qemu_clock_deadline_ns_all(VIRTUAL,
 *      ATTR_ALL) == 0 read (icount_handle_deadline's own test) and,
 *      when due, runs VIRTUAL timers in-thread under the BQL
 *      (vclock_agency_consume).  This site+predicate pair is the
 *      intervention-proven one: the archival LX geometry (wave/locus
 *      LX 0/6) replicated by the trigger-site wave (wave/proddr PTB
 *      0/6 and VLX 0/6, with the dispatch-top trigger P 6/6 and the
 *      disarmed control VOFF 6/6).  The formerly-shipped dispatch-top
 *      trigger (cached-slot compare at cpu_exec_loop's C-level
 *      dispatch) and its VIRTUAL_RT nudge timer are the DISPROVEN
 *      geometry and are gone from the product path.
 *   3. Exclusion: while ENGAGED (plugin active AND at least one vCPU
 *      thread unparked), qemu_clock_use_for_deadline(VIRTUAL) is false
 *      -- the identical single predicate icount extends -- so the
 *      iothread neither polls on nor runs main-loop VIRTUAL timers.
 *      qemu_timer_notify_cb's icount branch (VIRTUAL notify -> vCPU
 *      kick) is extended by the same predicate.
 *   4. THE HALT RULE: while ALL vCPU threads are parked idle, the
 *      exclusion LIFTS (engaged == false) and the iothread consumes
 *      VIRTUAL normally.  No boundaries exist to consume at, and no
 *      guest runs, so no excursion can race the iothread -- the race
 *      this design removes cannot occur while lifted.  The park edge
 *      that empties the running set calls qemu_notify_event() so the
 *      iothread recomputes its poll timeout WITH VIRTUAL; the unpark
 *      edge re-engages (the iothread's stale VIRTUAL wake, if any,
 *      declines through the same use_for_deadline gate).  This
 *      deliberately replaces the diagnostic prototype's
 *      deadline-BOUNDED halt wait: no timed wait, no watchdog shape --
 *      the lift is exact.
 *
 * THE CACHED SLOT (vclock_agency_next_due) is now a WITNESS, not a
 * trigger input: maintained from the timer arming paths by monotone
 * folding and re-derived after every VIRTUAL run (stale-early at
 * worst, never stale-late), it lets the wave sampler read the head
 * deadline the discipline is working against.  Nothing in the product
 * consumes from it -- the breakout predicate is the fresh read above.
 *
 * USER MODE / TOOLS: this TU carries no QEMU-coupled state and is never
 * armed there -- qemu_plugin_vclock_agency_mode() is a no-op in
 * user-mode builds (plugins/user.c), every hook site is softmmu-only,
 * and the slot stays INT64_MAX, so the discipline no-ops cleanly under
 * CONFIG_USER_ONLY (there is no iothread/VIRTUAL consumption split to
 * move in user mode).
 *
 * TRIPWIRE COUNTERS (count, never a watchdog; each warns once on first
 * hit and is re-read by vclock_agency_counters()):
 *   vagency_consume_runs      liveness: boundary consumptions (must be
 *                             > 0 on any traced busy system run)
 *   vagency_spec_mode_skips   a boundary observed inside spec mode
 *                             (expected 0; nonzero = spec-escape witness)
 *   vagency_stall_fence_hits  the wrong-path stall gate CONFIRMED a
 *                             deadline hide while engaged (expected 0:
 *                             with the iothread excluded, the per-
 *                             excursion stall/hidden/Dekker machinery
 *                             is redundant -- this is its witness, kept
 *                             until the flatten criterion retires it)
 *   vagency_foreign_vruns     a main-loop VIRTUAL timer pass ran
 *                             OUTSIDE a vCPU boundary while engaged
 *                             (expected 0: the LX excl_ok invariant as
 *                             product tripwire)
 *   vagency_aio_virtual_arms  a VIRTUAL timer was armed on a non-main-
 *                             loop (AioContext) timerlist while active
 *                             (none exist in our machines today; such a
 *                             consumer is outside this discipline's
 *                             delivery bound -- gate loudly)
 */
#ifndef QEMU_VCLOCK_AGENCY_H
#define QEMU_VCLOCK_AGENCY_H

#include "qemu/atomic.h"

typedef struct QEMUTimer QEMUTimer;

/*
 * The cached next-due VIRTUAL deadline.  INT64_MAX = plugin inactive or
 * no VIRTUAL timer armed -- the TB-entry fast path is this single load
 * and compare.
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

/* Arm/disarm (plugins/system.c via qemu_plugin_vclock_agency_mode). */
void vclock_agency_set_active(bool active);

/* Witness-slot maintenance (util/qemu-timer.c). */
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
bool vclock_agency_in_boundary(void);
void vclock_agency_note_consume(void);
void vclock_agency_note_spec_skip(void);
void vclock_agency_note_fence_hit(void);
void vclock_agency_note_vpass(bool main_list);

/*
 * Site witness: consume_breakout counts the one product site;
 * consume_dispatch survives as the retired dispatch-top site's zero
 * witness (it must read 0 forever).  The two sum to consume_runs
 * exactly.
 */
void vclock_agency_note_consume_site(bool breakout_site);

/*
 * Counter snapshot, in declaration order: consume_runs, spec_mode_skips,
 * stall_fence_hits, foreign_vruns, aio_virtual_arms.
 */
void vclock_agency_counters(uint64_t out[5]);

#endif
