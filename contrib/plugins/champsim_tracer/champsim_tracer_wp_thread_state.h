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
    uint64_t iters    = 0;      /* iterations retired in that execution.
                                 * For an AArch64 FEAT_MOPS bulk op — whose
                                 * fan-out unit is one memory access, not an
                                 * architectural element — this is the number
                                 * of accesses that execution reported, each
                                 * derived from the helper's own byte
                                 * progress (see arm_plugin_emit_pieces). */
    uint64_t bytes    = 0;      /* FEAT_MOPS only: architectural bytes that
                                 * execution moved, from the instruction's
                                 * own size-register decrement
                                 * (qemu_plugin_rep_bytes).  The delivered
                                 * access sizes must sum to it — the
                                 * register-derived truth the access-unit
                                 * fan-out count is verified against.  x86
                                 * REP leaves it 0. */
    bool     complete = false;  /* repetition ended in that execution */
    bool     reenter  = false;  /* QEMU jumped back to the insn, not past */
    bool     chunk    = false;  /* ...and did so at a canonical chunk
                                 * boundary — the exit the looping
                                 * translation itself takes (counter
                                 * writeback 65536*m + 1, m >= 1).
                                 * Qualifies reenter; meaningless without
                                 * it.  Chunk re-entries keep their window
                                 * tick (the bbv plugin bills them in the
                                 * simpoint-generation regime); all other
                                 * re-entries have theirs withheld. */
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
 * Warmup-boundary hold: is a fan-out instruction ARCHITECTURALLY in
 * flight (begun, not yet retired)?  Distinct from RepInFlight, whose
 * predicate is reenter (what the trailing-pass suppression needs): a
 * mid-instruction fault publishes reenter=false while the instruction
 * is still unfinished, so reenter cannot anchor the warmup boundary's
 * never-split-an-instruction rule.  active = last consumed emission of
 * this pc had complete=false; cleared when the instruction retires.
 */
struct RepBoundaryHold {
    /* Guest thread that owns the in-flight instruction, stamped by its
     * own emissions (CST_HOLD_TID_UNKNOWN until one lands: a dispatch
     * arm precedes the first emission).  The deferred-close release keys
     * on it — a PEER thread's user TB on this vCPU proves nothing about
     * the holder's instruction, so only the holder's own thread at a
     * different user pc releases (measured: a 50M-iteration REP on
     * thread A split mid-instruction by a budget crossing detected on
     * spinner thread B, 651390 of 50000000 iterations on the wire —
     * cst_runs/x86s2, probes/threadrep.S). */
    static const uint32_t CST_HOLD_TID_UNKNOWN = UINT32_MAX;
    uint64_t pc     = 0;
    uint32_t tid    = CST_HOLD_TID_UNKNOWN;
    bool     active = false;
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
    /* Per-piece (iterations, memops) breakdown of the pre-fault prefix, in
     * fault order (CtxFrame::rep_pieces, moved here by the handoff).  The
     * scalars above are its sums.  Needed because each piece's aborted-
     * attempt surplus pairs onto the iteration that faulted at THAT
     * piece's boundary: totals alone shift every slice after the first
     * fault of a multi-piece split.  Consumed (cleared) with the facts. */
    std::vector<std::pair<uint64_t, uint64_t>> emit_pre_pieces;

    /*
     * Window-clock ruling (maintainer, 2026-07-29, refined 2026-07-30):
     * the window clock counts instructions THE WAY THE BBV PLUGIN COUNTS
     * THEM in the simpoint-generation regime (user mode, canonical loop
     * translation) — SimPoint offsets are selected from bbv counts, so
     * any other rule misaligns every simpoint-anchored window.  Measured
     * on the bbv plugin itself: an x86 REP instance bills one count per
     * TB entry the loop translation makes — 1 + floor((N-2)/65536) for
     * an N-iteration counter-terminated REP.  So: a counted execution
     * that ends by re-entering a fan-out instruction keeps its tick when
     * the re-entry sits on a canonical chunk boundary (chunk=true; bbv
     * bills that entry in the reference regime too) and has it withheld
     * otherwise; the completing execution always ticks.  The carve-out
     * is x86-REP-only by construction: only do_gen_rep publishes chunk.
     * An AArch64 MOPS re-entry (cpu_loop_exit_requested split,
     * mid-instruction fault) is a timing artifact the reference regime
     * never bills — deterministic in nothing — so MOPS re-entries always
     * withhold, the landed MOPS rule.  Under canonical translation the
     * correction is exactly zero; under -icount / single-step / TF it
     * reproduces the canonical count from architectural state.
     *
     * These remember, per vCPU, whether the previous counted TB is
     * eligible: prev_tb_counted = it advanced the user clock;
     * prev_tb_rep_pcs[] = the fan-out insns it contains, so a foreign
     * REP executed between two owned dispatches cannot trigger the
     * correction.  A small set rather than one pc because FEAT_MOPS bulk
     * instructions do not end their TB the way an x86 REP does: a
     * SETP/SETM/SETE trio translates into one TB as three mid-TB
     * fragment terminators, and the execution a cpu_loop_exit_requested
     * split re-enters resumes at the SPLIT instruction's own pc, not a
     * TB-terminating one.  The splitter seals a fragment at every
     * self-loop insn, so the collection walk is one pc per fragment.
     * Overflow past the fixed capacity loses the withhold for the
     * surplus insns — an overcount, never an undercount — and eight
     * exceeds any real TB's fan-out population.
     */
    static constexpr unsigned REP_CLK_PCS = 8;
    bool     prev_tb_counted = false;
    uint8_t  prev_tb_rep_n = 0;
    uint64_t prev_tb_rep_pcs[REP_CLK_PCS] = {};

    bool prev_tb_rep_contains(uint64_t pc) const
    {
        for (unsigned i = 0; i < prev_tb_rep_n; i++) {
            if (prev_tb_rep_pcs[i] == pc) {
                return true;
            }
        }
        return false;
    }

    /*
     * Header §2.13 warmup-boundary holds (CP): which fan-out instructions
     * are architecturally in flight (begun, not retired) on this vCPU.
     * One slot per fan-out insn for the same reason as prev_tb_rep_pcs[]:
     * a MOPS trio is three mid-TB terminators, each independently able to
     * straddle the warmup crossing through its own fault/split re-entry.
     * Armed at dispatch (a counted TB containing the terminator), updated
     * or released by the owning instruction's depth-0 user emission
     * (in_flight = !retired — the architectural predicate, which survives
     * mid-instruction faults where reenter reads false).  Slot overflow
     * drops the arm: the boundary may then land one record early beside a
     * >8-fan-out TB (never a wrong split-side value for held insns);
     * eight exceeds any real TB's fan-out population.
     */
    RepBoundaryHold warmup_hold[REP_CLK_PCS];

    void warmup_hold_update(uint64_t pc, bool in_flight,
                            uint32_t tid = RepBoundaryHold::
                                           CST_HOLD_TID_UNKNOWN)
    {
        int free_slot = -1;
        for (unsigned i = 0; i < REP_CLK_PCS; i++) {
            if (warmup_hold[i].active && warmup_hold[i].pc == pc) {
                warmup_hold[i].active = in_flight;
                /* The emission stream stamps the owner; a dispatch arm
                 * (unknown tid) must not erase a known one. */
                if (tid != RepBoundaryHold::CST_HOLD_TID_UNKNOWN) {
                    warmup_hold[i].tid = tid;
                }
                return;
            }
            if (free_slot < 0 && !warmup_hold[i].active) {
                free_slot = (int)i;
            }
        }
        if (in_flight && free_slot >= 0) {
            warmup_hold[free_slot].pc = pc;
            warmup_hold[free_slot].tid = tid;
            warmup_hold[free_slot].active = true;
        }
    }

    bool warmup_hold_any() const
    {
        for (unsigned i = 0; i < REP_CLK_PCS; i++) {
            if (warmup_hold[i].active) {
                return true;
            }
        }
        return false;
    }

    bool warmup_hold_matches(uint64_t pc) const
    {
        for (unsigned i = 0; i < REP_CLK_PCS; i++) {
            if (warmup_hold[i].active && warmup_hold[i].pc == pc) {
                return true;
            }
        }
        return false;
    }

    void warmup_hold_reset()
    {
        for (unsigned i = 0; i < REP_CLK_PCS; i++) {
            warmup_hold[i] = RepBoundaryHold{};
        }
    }

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
