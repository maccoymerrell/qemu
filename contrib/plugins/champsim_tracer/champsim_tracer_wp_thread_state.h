/*
 * Wrong-Path Tracing Plugin — per-thread wrong-path simulator state.
 *
 * Each QEMU vCPU thread carries one WPThreadState.  Set during
 * simulate_wrong_path_ext(): the in_progress flag gates plugin
 * callbacks (mem callback routes to mem_accesses, reg-snap callback
 * suppresses, vcpu_tb_exec early-outs), and saved_* hold a snapshot
 * of the per-vCPU scoreboard fields the WP simulator clobbers and
 * later restores.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_WP_THREAD_STATE_H
#define CHAMPSIM_TRACER_WP_THREAD_STATE_H

#include <vector>

#include "champsim_tracer.h"

struct WPThreadState {
    /* Set by simulate_wrong_path_ext while a WP simulation is running.
     * Read by the mem/insn-snap callbacks and the tb-exec orchestrator
     * to gate CP-only logic. */
    bool in_progress = false;

    /* Memops captured during the in-flight WP simulation.  Filled by
     * MemAccessRecorder::record while in_progress is true; cleared by
     * simulate_wrong_path_ext at end-of-sim. */
    std::vector<WPMemAccess> mem_accesses;

    /* WP-side per-insn memop cap (MemAccessRecorder::record).
     * cur_insn_pc = PC of the last memop; cur_insn_count = run length
     * of consecutive same-PC memops.  Past CST_FID_SLOT_COUNT, further
     * same-PC memops are dropped; both reset on a different insn_pc. */
    uint64_t cur_insn_pc = 0;
    uint32_t cur_insn_count = 0;

    /* Snapshot of scoreboard state at WP-sim entry, restored at exit. */
    unsigned int saved_cpu_index = 0;
    uint64_t saved_insn_count = 0;
    uint64_t saved_prev_start_pc = 0;
    uint64_t saved_prev_fall_through = 0;
    /* Budget slot is decremented per spec-mode TB via the inline_add;
     * save+restore so the WP simulation doesn't trip
     * vcpu_tb_check_budget after returning to CP. */
    uint64_t saved_budget = 0;

    /* Template of the TB the WP simulator most recently ran via
     * qemu_plugin_exec_tb.  Set by vcpu_tb_exec from its own per-TB
     * udata in the WP-mode early-out.  The WP walker reads this
     * after each exec_tb to get the exact-shape template that
     * actually executed — symmetric with how the CP path picks up
     * its current TB. */
    BBTemplate *last_executed_tb = nullptr;
};

extern thread_local WPThreadState g_wp_state CST_TLS_HOT;

/*
 * Capture sink (rearchitecture M3): the per-TB async-exclusion decision,
 * latched ONCE at the top of the CP step in vcpu_tb_exec from
 * qemu_plugin_in_async_int() and cleared at both async_int_reset sites.
 * The flag is constant across one TB's body (it changes only at exception
 * delivery / the departure-PC close, both between TBs), so the per-insn
 * capture callbacks (memops, reg snaps, synthetic EAs) read this bool
 * instead of each making a cross-DSO call — one exclusion decision, one
 * owner, identical semantics.  true = mute (drop async-handler capture).
 */
extern thread_local bool g_capture_mute CST_TLS_HOT;

/*
 * Architectural self-loop accounting for the TB that just finished, latched
 * from QEMU (qemu_plugin_rep_iterations / _complete / _reenter / _pc).
 *
 * The number of iterations an x86 REP performed is a property of the
 * instruction's loop counter, not of how many memop callbacks a translation
 * happened to deliver: do_gen_rep emits a single iteration whenever
 * CF_USE_ICOUNT or CF_SINGLE_STEP is set on the TB, or EFLAGS.TF or the
 * interrupt shadow is live, and an exception between iterations splits an
 * already-looping REP the same way.
 *
 * Latched rather than read at emission time because the emission point is
 * not reachable without clobbering the source: emit_finalized_bb runs the
 * whole wrong-path excursion for a sealed BB's branch before it calls
 * emit_body_entry, and any speculative REP on that path overwrites QEMU's
 * fields.  There are two independent latches for the same reason -- the
 * correct-path one is read after the excursion that would have overwritten
 * it, so the wrong path keeps its own.
 */
struct RepArchFacts {
    uint64_t pc       = 0;      /* REP insn this describes; 0 = none */
    uint64_t iters    = 0;      /* iterations retired in that execution */
    bool     complete = false;  /* repetition ended in that execution */
    bool     reenter  = false;  /* QEMU jumped back to the insn, not past */
};

/*
 * Which REP instruction is mid-flight, i.e. one QEMU has begun and not yet
 * advanced past.  A REP translated as a single iteration is re-entered once
 * more after its final iteration, and that trailing pass performs zero
 * iterations: it is the same instruction finishing, not a new one, and must
 * not reach the wire as an extra entry.  A REP entered with a zero counter
 * performs zero iterations too but is a real retired instruction -- this
 * latch is what separates the two.
 */
struct RepInFlight {
    uint64_t pc          = 0;
    bool     in_progress = false;
};

/*
 * Per-vCPU, and deliberately NOT thread-local.  The plugin's static TLS block
 * is a hard loader limit that the existing hot per-insn state already sits
 * against -- adding even one more thread_local object here makes dlopen fail
 * with "cannot allocate memory in static TLS block".  A plain per-vCPU array
 * indexed by cpu_index is the same pattern the pinned-process state uses, has
 * the same one-writer-per-vCPU discipline, and costs no TLS at all.
 */
struct RepSelfLoopState {
    RepArchFacts cp_facts;      /* raw per-callback latch: describes the TB
                                 * that finished immediately before this
                                 * vcpu_tb_exec dispatch */
    RepInFlight  cp_in_flight;
    RepArchFacts wp_facts;      /* wrong-path latch (independent walk) */
    RepInFlight  wp_in_flight;

    /*
     * Emission handoff: the facts for the entry emit_body_entry is being
     * asked to write, set by the PathBuilder immediately before each emit
     * and CONSUMED (invalidated) by emit_body_entry.  This exists because
     * the raw latch above is only valid for an entry emitted in the same
     * callback that latched it — and the PathBuilder defers emissions
     * across fault frames, foreign-ASID suspensions and async windows, by
     * which time the latch describes some other TB (measured: kernel
     * fault-path REPs republish the fields, so a fault-deferred user REP
     * emission fell back to the memop-derived count).  Consume-once: a
     * path that forgot to set it falls back to the memop-derived count
     * and is counted, never silently mis-attributed.
     *
     * emit_pre_iters / emit_pre_memops carry a fault-split REP's pre-fault
     * prefix (iterations retired and REP memops delivered before the
     * fault), so the merged emission renders the architectural total and
     * pairs the re-delivered partial iteration's memops onto the iteration
     * that faulted — the same rendering the single-iteration translation's
     * whole-BB merge produces for the same fault.
     */
    RepArchFacts emit_facts;
    bool     emit_facts_valid = false;
    uint64_t emit_pre_iters = 0;
    uint64_t emit_pre_memops = 0;

    /*
     * Window-clock ruling (maintainer, 2026-07-29): the marker window's
     * user-instruction clock counts ARCHITECTURAL instructions — a REP is
     * one tick however many executions QEMU splits it into.  A counted
     * execution that ends by re-entering the instruction (reenter=true: a
     * single-iteration translation's per-iteration pass, or a REP_MAX
     * chunk boundary) has its REP tick withheld; the instruction ticks on
     * the execution that leaves past it (reenter=false — the sole
     * execution of a looping translation, a flag-break, a zero-count REP,
     * or the trailing pass).  These remember, per vCPU, whether the
     * previous counted TB is eligible: prev_tb_counted = it advanced the
     * user clock; prev_tb_rep_pc = the fan-out insn terminating it (0 for
     * none), so a foreign REP executed between two owned dispatches
     * cannot trigger the correction.
     */
    bool     prev_tb_counted = false;
    uint64_t prev_tb_rep_pc = 0;

    /*
     * Self-loop facts travelling with the PathBuilder's pending-seal prev,
     * in lockstep with its prev_tb_ / walk_prev_.  QEMU's fields describe
     * the TB that finished immediately before the CURRENT dispatch, so a
     * freshly promoted prev's facts only become readable at the NEXT
     * dispatched step: promote arms the absorb, and the first step_events
     * entry after it copies the raw latch in.  Steps that do not promote
     * (async window, foreign span, dropped TBs) leave the pending facts
     * untouched — the facts survive exactly as long as the prev they
     * describe.  pb_walk_facts is the seal-phase snapshot, taken where
     * walk_prev_ is.  Housed here rather than in the thread_local
     * PathBuilder deliberately: growing that object grows the plugin's
     * TLS template, and qemu-system-* has no static-TLS surplus left to
     * absorb it (dlopen refuses the .so). */
    RepArchFacts pb_prev_facts;
    bool         pb_prev_facts_armed = false;
    RepArchFacts pb_walk_facts;
};

/* Defined in champsim_tracer.cc, sized CST_PIN_MAX_VCPUS like its siblings. */
extern RepSelfLoopState g_rep_state[];
RepSelfLoopState &rep_state(unsigned int cpu_index);

#endif /* CHAMPSIM_TRACER_WP_THREAD_STATE_H */
