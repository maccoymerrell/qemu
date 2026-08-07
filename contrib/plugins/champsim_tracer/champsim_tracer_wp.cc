/*
 * Wrong-Path Tracing Plugin — wrong-path simulator.
 *
 * Runs speculative basic blocks starting from a mispredicted branch
 * target, records their memory accesses and any faults, and rolls
 * back CPU state when done.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>
#include <stdlib.h>

#include <atomic>
#include <unordered_set>
#include <utility>
#include <vector>

#include "champsim_tracer.h"
#include "champsim_tracer_bb_template_cache.h"
#include "champsim_tracer_reg_snap_collector.h"
#include "champsim_tracer_scoreboard.h"
#include "champsim_tracer_stats.h"
#include "champsim_tracer_wp_thread_state.h"

/*
 * Per-BB accumulator for the wrong-path walk.  Each spec-mode exec_tb runs
 * a (possibly multi-insn) wrong-path fragment up to its branch terminator;
 * the fragment walk appends exactly the insns that executed into these
 * parallel arrays and commits a true BB at each branch fire.  bb_fields /
 * bb_regnames are non-owning pointers into the source template's stable
 * storage (commit_true_bb_refs copies only on a first-sighting commit).
 */
struct WpAccum {
    std::vector<uint64_t>             bb_pcs;
    std::vector<uint8_t>              bb_sizes;
    std::vector<uint8_t>              bb_bytes;
    std::vector<const InsnFields *>   bb_fields;
    std::vector<const InsnRegNames *> bb_regnames;
    std::vector<DynParam>             bb_dyn_params;
    std::vector<RegSnap>              bb_reg_snaps;
    uint64_t    bb_start_pc      = 0;
    const char *bb_symbol_name   = nullptr;
    /* A true BB always ends in a branch, so a spec-mode fault inside a BB
     * does not terminate it: the walk skips past the faulting insn and
     * accumulates to the natural branch end.  bb_first_fault_idx marks the
     * uop speculation would actually squash on. */
    bool        bb_has_fault     = false;
    uint32_t    bb_first_fault_idx = 0;

    /* Reset per-BB state.  bb_reg_snaps is intentionally NOT cleared here:
     * its lifecycle is caller-managed (cleared after a no-template drop,
     * transferred + realloc'd after a successful commit). */
    void clear()
    {
        bb_pcs.clear();
        bb_sizes.clear();
        bb_bytes.clear();
        bb_fields.clear();
        bb_regnames.clear();
        bb_dyn_params.clear();
        bb_start_pc = 0;
        bb_symbol_name = nullptr;
        bb_has_fault = false;
        bb_first_fault_idx = 0;
    }

    /* Build a WPBBEntry from the current accumulator, moving bb_dyn_params /
     * bb_reg_snaps into it (those vectors are empty after; the caller still
     * runs clear() to reset bb_pcs/etc.). */
    WPBBEntry make_entry(BBTemplate *bb_tmpl, bool fault,
                         uint32_t fault_insn_index)
    {
        WPBBEntry e;
        e.template_id = bb_tmpl ? bb_tmpl->template_id : 0;
        e.start_pc = bb_start_pc;
        e.dyn_params = std::move(bb_dyn_params);
        e.n_insns_executed = (uint32_t)bb_pcs.size();
        e.fault = fault;
        e.translation_unavailable = false;
        e.fault_insn_index = fault_insn_index;
        e.tmpl = bb_tmpl;
        if (g_features.reg_data) {
            e.reg_snaps = std::move(bb_reg_snaps);
        }
        return e;
    }
};

/*
 * All of simulate_wrong_path_ext's loop-carried, per-iteration and
 * per-excursion-context state, folded into one struct so each phase of the
 * walk can move into a helper taking WpWalkState & while its body stays
 * verbatim.  Same-name references at the driver top (auto &bb_pcs =
 * acc.bb_pcs; and friends) keep the moved logic byte-for-byte unchanged.
 * Field groups:
 *   - context      : set once before the walk (never mutated in the loop)
 *   - accumulator  : the in-flight BB accumulator + result chain + poison set
 *   - loop-carried : state that persists across outer-while iterations
 *   - per-iter     : scratch reset at the top of each outer-while iteration
 */
struct WpWalkState {
    /* --- immutable per-excursion context --- */
    unsigned int cpu_index           = 0;
    uint64_t     wrong_target        = 0;
    bool         excursion_is_kernel = false;
    bool        *flush_interrupted   = nullptr;
    bool        *first_tb_unavail    = nullptr;
    Stats       *stats               = nullptr;
    Stats       *hist                = nullptr;
    unsigned int initial_insn_cap    = 0;

    /* --- accumulator + result chain (loop-carried) --- */
    WpAccum                      acc;
    std::vector<WPBBEntry>       chain;
    std::unordered_set<uint64_t> poisoned_targets;

    /* --- loop-carried scalars --- */
    uint64_t     sim_insns           = 0;
    bool         early_exit          = false;
    uint64_t     last_fault_pc       = UINT64_MAX;
    unsigned int repeated_fault_pc   = 0;
    bool         awaiting_delay_slot = false;
    uint64_t     prev_pre_pc         = UINT64_MAX;
    uint32_t     same_pre_pc_count   = 0;
    uint32_t     wp_noprogress_count = 0;
    size_t       prev_mem_size       = 0;

    /* --- per-iteration / per-walk scratch --- */
    uint64_t     pre_pc              = 0;
    size_t       mem_start_idx       = 0;
    BBTemplate  *tmpl                = nullptr;
    bool         tb_ok               = false;
    uint64_t     post_pc_now         = 0;
    bool         fault_consumed      = false;
    bool         walk_done           = false;
    size_t       wp_snap_cursor      = 0;
};

/*
 * Status a WP-walk phase hands back to its caller.  Each value makes one of
 * the former monolith's break/continue/fall-through exits explicit, so the
 * driver dispatches on a named outcome instead of steering a ~900-line scope
 * with raw continue/break.  Two scopes consume it:
 *   - the outer driver loop: PROCEED (run the next phase this iteration),
 *     NEXT_ITER (continue the outer while), or a terminal reason
 *     (DOMAIN_CROSS / TRANSLATION_UNAVAIL / STUCK_BAIL / RETRY_SESSION) —
 *     for every terminal the phase has already latched st.early_exit,
 *     exactly as the monolith did, so the driver's tail break fires;
 *   - the inner fragment loop (in wp_walk_fragments): BREAK_WALK (break the
 *     fragment for-loop) or PROCEED (fall through to the commit).
 */
enum class WpStep {
    PROCEED,              // fall through to the next phase / the commit
    NEXT_ITER,            // continue the outer while loop
    BREAK_WALK,           // break the inner fragment for-loop
    RETRY_SESSION,        // flush unwound exec_tb: caller re-runs the whole WP
    DOMAIN_CROSS,         // SMEP/PXN cross-domain terminate
    TRANSLATION_UNAVAIL,  // wrong-path target unfetchable / null template
    STUCK_BAIL,           // no-forward-progress / poison / nop-slide / wild store
    FAULT_STOP,           // unused: reserved, not returned by any phase today
};

/*
 * Enter a wrong-path speculative session: snapshot the scoreboard cursor
 * into g_wp_state (so the nested vcpu_tb_exec on this thread observes WP
 * mode and can restore the cursor afterwards), flip spec mode on, and
 * redirect the PC to the wrong target.  The caller has already saved the
 * CPU register state (@saved_state) and reset the WP chain/mem accumulator.
 */
static void wp_enter_spec_session(unsigned int cpu_index, uint64_t wrong_target,
                                  struct qemu_plugin_cpu_state *saved_state)
{
    g_wp_state.mem_accesses.clear();
    g_wp_state.cur_insn_pc = 0;
    g_wp_state.cur_insn_count = 0;

    /* Each excursion is an independent speculative walk: nothing is mid-flight
     * in it yet.  Without this reset a stale latch from a previous excursion
     * that ended inside a REP would make this excursion's first block at that
     * PC look like a continuation and drop it. */
    rep_state(cpu_index).wp_in_flight = RepInFlight();
    rep_state(cpu_index).wp_facts     = RepArchFacts();

    g_wp_state.saved_cpu_index = cpu_index;
    g_wp_state.saved_insn_count = qemu_plugin_u64_get(g_scoreboard.insn_count, cpu_index);
    g_wp_state.saved_prev_start_pc = qemu_plugin_u64_get(g_scoreboard.prev_start_pc, cpu_index);
    g_wp_state.saved_prev_fall_through = qemu_plugin_u64_get(g_scoreboard.prev_fall_through,
                                                     cpu_index);
    g_wp_state.saved_budget = qemu_plugin_u64_get(g_scoreboard.budget, cpu_index);
    g_wp_in_progress = true;
    /* Per-vCPU mirror of in_progress for consumers keyed by the EXECUTING
     * vCPU rather than the walker's host thread (the marker callbacks'
     * third fence leg — see champsim_tracer_wp_thread_state.h). */
    if (cpu_index < CST_PIN_MAX_VCPUS) {
        g_wp_session_vcpu[cpu_index].store(true, std::memory_order_relaxed);
    }

    /* Freeze the guest virtual clock for the whole excursion (system mode):
     * the speculative run burns host wall-clock time but is outside guest
     * time, so it must not advance the guest's architected timer counters.
     * Paused at the outer boundary — not in spec_mode_begin — so a
     * fault-skip's spec_mode teardown/re-entry does not leak ticks.  No-op
     * in user mode.
     *
     * The caller already issued this immediately BEFORE taking the register
     * snapshot, because the pause is also what opens the excursion window a
     * target uses to record externally-raised interrupts for replay across the
     * snapshot's rollback (see the comment at the snapshot site).  The call is
     * idempotent on the per-CPU paused flag, so this one keeps the invariant
     * "wp_enter_spec_session leaves the excursion window open" true on its own
     * terms and costs a flag test when the caller has already paused. */
    qemu_plugin_spec_vtime_pause();
    qemu_plugin_spec_mode_begin(saved_state);
    qemu_plugin_set_pc(wrong_target);
}

/*
 * CST_FENCE_FORCE_SESSION=<n> — directed control (diagnostic, off by
 * default): when the n-th excursion ends (default 1), do NOT clear this
 * vCPU's wrong-path session bracket.  From then on the CORRECT path runs
 * carrying a flag that says it is speculative — precisely the leak the
 * third fence gate exists to catch, and the shape in which a window stays
 * open forever because every marker callback on that vCPU is dropped.
 *
 * It is the POSITIVE CONTROL for the three tripwires that name that leak
 * and had never been seen to fire: `WP session flag on correct path`
 * (tested on every correct-path step), `marker fence session-only` (tested
 * at the marker callbacks' fence) and `marker END with no close` (whose
 * correct-path suppression test sits ahead of that fence — see
 * vcpu_marker_end_cb).  Nothing else in the plugin reads the bracket, so
 * with the variable unset this is one cached-int load per excursion.
 */
static bool wp_force_session_leak(void)
{
    static int lim = -1;
    if (lim < 0) {
        const char *e = getenv("CST_FENCE_FORCE_SESSION");
        int v = e ? atoi(e) : 0;
        lim = (e && v <= 0) ? 1 : v;
    }
    if (lim <= 0) {
        return false;
    }
    static std::atomic<int> n{0};
    return n.fetch_add(1, std::memory_order_relaxed) + 1 >= lim;
}

/*
 * Exit the wrong-path speculative session: restore the scoreboard cursor
 * from the snapshot wp_enter_spec_session took, leave spec mode, and restore
 * + free the saved CPU register state.  The symmetric counterpart to
 * wp_enter_spec_session; WP-result stats are the caller's concern.
 */
static void wp_end_spec_session(unsigned int cpu_index,
                                struct qemu_plugin_cpu_state *saved_state)
{
    g_wp_in_progress = false;
    if (cpu_index < CST_PIN_MAX_VCPUS && !wp_force_session_leak()) {
        g_wp_session_vcpu[cpu_index].store(false, std::memory_order_relaxed);
    }

    qemu_plugin_u64_set(g_scoreboard.insn_count, cpu_index, g_wp_state.saved_insn_count);
    qemu_plugin_u64_set(g_scoreboard.prev_start_pc, cpu_index, g_wp_state.saved_prev_start_pc);
    qemu_plugin_u64_set(g_scoreboard.prev_fall_through, cpu_index,
                        g_wp_state.saved_prev_fall_through);
    qemu_plugin_u64_set(g_scoreboard.budget, cpu_index, g_wp_state.saved_budget);

    qemu_plugin_spec_mode_end();
    qemu_plugin_cpu_state_restore(saved_state);
    qemu_plugin_cpu_state_free(saved_state);
    /* Resume the guest virtual clock, discarding the excursion's wall-clock
     * time (outer-boundary twin of the pause in wp_enter_spec_session). */
    qemu_plugin_spec_vtime_resume();

    g_wp_state.mem_accesses.clear();
}

/*
 * Append the executed prefix [0, n_executed_in_cur) of fragment @cur into
 * the WP accumulator, de-duplicating against the accumulator tail (a
 * self-looping single-insn TB re-appends the same insn) and recording
 * per-execution WP attribution stats.  Advances @wp_snap_cursor over the
 * per-insn reg snaps the exec_tb callbacks captured (every executed insn
 * except each fragment's last, which falls back to a live regfile read).
 * Returns the number of insns actually appended (post-dedup).
 */
static uint32_t wp_append_fragment_insns(WpAccum &acc, BBTemplate *cur,
                                         uint32_t n_executed_in_cur,
                                         size_t &wp_snap_cursor,
                                         unsigned int cpu_index,
                                         Stats &stats, Stats *hist)
{
    auto &bb_pcs       = acc.bb_pcs;
    auto &bb_sizes     = acc.bb_sizes;
    auto &bb_bytes     = acc.bb_bytes;
    auto &bb_fields    = acc.bb_fields;
    auto &bb_regnames  = acc.bb_regnames;
    auto &bb_reg_snaps = acc.bb_reg_snaps;
    /* Stable zeroed sentinel for the rare reg-data-on-but-template-has-no-
     * regnames case (keeps a valid pointer to push). */
    static const InsnRegNames kEmptyRegNames{g_zero_regkeys,
                                             g_zero_regkeys};

    uint32_t appended_insns = 0;
    for (uint32_t i = 0; i < n_executed_in_cur; i++) {
        uint64_t insn_pc = cur->insn_pcs[i];
        uint8_t isz = cur->insn_sizes[i];
        bool duplicate = false;
        if (!bb_pcs.empty()) {
            size_t prev = bb_pcs.size() - 1;
            duplicate = bb_pcs[prev] == insn_pc &&
                        bb_sizes[prev] == isz &&
                        memcmp(&bb_bytes[prev * MAX_INSN_BYTES],
                               &cur->insn_bytes[(size_t)i *
                                                MAX_INSN_BYTES],
                               MAX_INSN_BYTES) == 0;
        }
        if (duplicate) {
            /* The per-insn callback fired for this insn (if it is not the
             * fragment's last executed insn) regardless of dedup, so advance
             * the WP snap cursor past its slot to keep alignment with
             * subsequent insns' captures. */
            if (g_features.wp_reg_data &&
                i + 1 < n_executed_in_cur) {
                wp_snap_cursor +=
                    cur->insn_fields[i].n_dst_regs;
            }
            continue;
        }

        bb_pcs.push_back(insn_pc);
        bb_sizes.push_back(isz);
        bb_bytes.insert(bb_bytes.end(),
                        &cur->insn_bytes[i * MAX_INSN_BYTES],
                        &cur->insn_bytes[i * MAX_INSN_BYTES] +
                        MAX_INSN_BYTES);
        bb_fields.push_back(&cur->insn_fields[i]);

        /* WP-side per-execution attribution: mirrors the CP walk in
         * vcpu_tb_exec, scoped to non-duplicate WP insns. */
        {
            const InsnFields *f = &cur->insn_fields[i];
            stats.wp_insns_by_opcode[f->opcode]++;
            if (hist) hist->wp_insns_by_opcode[f->opcode]++;
            if (f->branch_type != BRANCH_NONE) {
                stats.wp_branches_by_type[f->branch_type]++;
                if (hist) hist->wp_branches_by_type[f->branch_type]++;
            }
            for (uint8_t k = 0; k < f->n_src_regs; k++) {
                stats.wp_src_reg_uses[f->src_regs[k]]++;
                if (hist) hist->wp_src_reg_uses[f->src_regs[k]]++;
            }
            for (uint8_t d = 0; d < f->n_dst_regs; d++) {
                stats.wp_dst_reg_writes[f->dst_regs[d]]++;
                if (hist) hist->wp_dst_reg_writes[f->dst_regs[d]]++;
            }
        }

        if (g_features.reg_data) {
            bb_regnames.push_back(cur->insn_reg_names
                                  ? &cur->insn_reg_names[i]
                                  : &kEmptyRegNames);
        }
        if (g_features.wp_reg_data) {
            const InsnFields *f = &cur->insn_fields[i];
            if (i + 1 < n_executed_in_cur) {
                /* Per-insn-accurate snap from the WP scratch buffer:
                 * captured at insn (i+1)'s pre-exec during the just-finished
                 * exec_tb, i.e. exactly the post-this-insn / pre-next-insn
                 * regfile state.  Mirrors CP regdata semantics for all but
                 * each fragment's last executed insn. */
                for (uint8_t k = 0; k < f->n_dst_regs; k++) {
                    if (wp_snap_cursor <
                        wp_pending_reg_snaps.size()) {
                        bb_reg_snaps.push_back(
                            wp_pending_reg_snaps[
                                wp_snap_cursor++]);
                    } else {
                        /* Underrun fallback: a missed callback (shouldn't
                         * happen for executed insns) — push a zeroed snap so
                         * downstream indexing stays aligned with
                         * bb_regnames. */
                        bb_reg_snaps.emplace_back(RegSnap{});
                    }
                }
            } else {
                /* Last executed insn of this fragment: no successor pre-exec
                 * hook inside the fragment to capture it.  Fall back to a
                 * live read from current (post-exec_tb) regfile state.  For
                 * a multi-fragment exec_tb this captures the
                 * post-everything-in-exec_tb state, so later fragments'
                 * writes can shadow this insn's writes (the one residual
                 * case where WP regdata loses per-insn precision). */
                g_reg_snaps.capture_insn_snaps_live(cpu_index,
                                                    cur, i,
                                                    bb_reg_snaps);
            }
        }
        appended_insns++;
    }
    return appended_insns;
}

/*
 * Forward-progress / poison / domain-cross guard for one outer-while
 * iteration, run before the speculative exec_tb.  Returns:
 *   NEXT_ITER     — a rep-string overrun was nudged past; retry the iteration
 *   STUCK_BAIL    — poisoned PC, no-forward-progress, or an already-poisoned
 *                   target: the accumulator was dropped and early_exit latched
 *   DOMAIN_CROSS  — an SMEP/PXN cross-domain fetch terminated the excursion
 *   PROCEED       — clear to fetch/execute this iteration
 * The body is moved verbatim from the monolith; break -> return terminal,
 * continue -> return NEXT_ITER.
 */
static WpStep wp_check_forward_progress(WpWalkState &st)
{
    auto &acc               = st.acc;
    auto &bb_pcs            = acc.bb_pcs;
    auto &bb_reg_snaps      = acc.bb_reg_snaps;
    auto &wp_chain          = st.chain;
    auto &poisoned_targets  = st.poisoned_targets;
    auto &pre_pc            = st.pre_pc;
    auto &early_exit        = st.early_exit;
    auto &prev_pre_pc       = st.prev_pre_pc;
    auto &same_pre_pc_count = st.same_pre_pc_count;
    auto &wp_noprogress_count = st.wp_noprogress_count;
    auto &prev_mem_size     = st.prev_mem_size;
    const bool excursion_is_kernel = st.excursion_is_kernel;
    bool *first_tb_unavail  = st.first_tb_unavail;

        /* Refuse to speculate into a previously-poisoned PC.  A PC
         * gets poisoned when vcpu_tb_trans detects either a Capstone
         * decode failure or a bytes-changed-since-first-sighting at
         * any of the TB's canonical insns — both signals that the
         * region is dynamic data, not real code.  Drop the in-flight
         * accumulator and end this WP simulation; chain so far is
         * preserved.
         *
         * EXCEPT on the very first iteration (empty chain): the branch
         * predictor deliberately chose this wrong_target, so a stale
         * global poison (keyed by TB start_pc, sometimes never erased
         * because the correct path only reaches this VA mid-TB) must not
         * veto the excursion's entry and produce a 0-block truncation.
         * The per-TB detect_tb_poison in vcpu_tb_trans still refuses a
         * genuinely-garbage first TB (Capstone-fail -> null tmpl below),
         * so dropping the global check here only recovers real code. */
        if (!(wp_chain.empty() && bb_pcs.empty()) &&
            cst_pc_is_poisoned(pre_pc)) {
            acc.clear();
            bb_reg_snaps.clear();
            poisoned_targets.insert(pre_pc);
            early_exit = true;
            return WpStep::STUCK_BAIL;
        }

        /* Forward-progress guard.  An x86 REP iter in spec mode can
         * decrement RCX while the sandboxed write keeps PC anchored, so
         * exec_tb returns without advancing PC; dedup skips appending
         * and the loop spins forever until a downstream NULL-deref.
         * Force PC past the offending insn after CST_FID_SLOT_COUNT
         * same-PC iterations (same threshold as the per-insn memop cap). */
        if (pre_pc == prev_pre_pc) {
            same_pre_pc_count++;
            /*
             * A legitimate same-PC repeat is a rep-string op: PC stays
             * anchored while each sandboxed iteration advances state
             * (its memop grows g_wp_state.mem_accesses).  A repeat with
             * NO such progress is a genuinely stuck excursion — a
             * degenerate wrong-path target that re-faults or self-loops
             * on every fetch, making no forward progress at all.  Those
             * must die fast: in a system-mode kernel a stuck excursion
             * recurs on essentially every BB, and at the old
             * per-insn memop cap each wasted a full cap's worth of steps,
             * so the trace never advanced (observed: ~900k degenerate
             * kernel excursions pinning an aarch64 system-mode run).
             * Bail after two no-progress repeats; rep-string keeps the
             * higher tolerance because its memop count climbs. */
            if (g_wp_state.mem_accesses.size() == prev_mem_size) {
                if (++wp_noprogress_count >= 2) {
                    poisoned_targets.insert(pre_pc);
                    acc.clear();
                    bb_reg_snaps.clear();
                    early_exit = true;
                    return WpStep::STUCK_BAIL;
                }
            } else {
                wp_noprogress_count = 0;
            }
        } else {
            prev_pre_pc = pre_pc;
            same_pre_pc_count = 1;
            wp_noprogress_count = 0;
        }
        prev_mem_size = g_wp_state.mem_accesses.size();
        if (same_pre_pc_count > CST_FID_SLOT_COUNT) {
            /* rep-string overrun guard (PC anchored, memops climbing
             * past the per-insn cap): nudge past the offending insn. */
            BBTemplate *stuck = g_wp_state.last_executed_tb;
            uint8_t isz = (stuck && stuck->n_insns > 0)
                ? stuck->insn_sizes[0] : 1;
            qemu_plugin_set_pc(pre_pc + isz);
            same_pre_pc_count = 0;
            prev_pre_pc = UINT64_MAX;
            return WpStep::NEXT_ITER;
        }

        if (poisoned_targets.count(pre_pc)) {
            early_exit = true;
            return WpStep::STUCK_BAIL;
        }

        /*
         * Privilege-domain-switch terminate — the faithful SMEP/PXN model.
         * The excursion speculates at the launching context's privilege
         * (excursion_is_kernel); a mispredicted fetch that reaches a code VA
         * in the OTHER domain (kernel-context excursion reaching a user-VA
         * fetch, or the reverse) is architecturally forbidden — the
         * speculative fetch faults and the pipeline recovers — so no real core
         * follows it.  End the excursion cleanly here, the same shape as the
         * translation-unavailable terminate: the sealed chain so far is
         * preserved and its last entry marked, and the crossing block is NOT
         * fetched.  It is the one remaining wrong-path terminate that a
         * BLOCK can trigger — a syscall no longer ends the walk, it continues
         * at its fall-through — and it eliminates the cross-domain mis-stamp
         * at its source, so a
         * committed wrong-path block's VA class is always its true domain.
         */
        if (cst_va_is_kernel_code(pre_pc) != excursion_is_kernel) {
            if (!wp_chain.empty()) {
                wp_chain.back().translation_unavailable = true;
            } else {
                /* Crossing on the very first target (e.g. an indirect branch
                 * mispredicted across the boundary): no entry to mark, so the
                 * emitter writes a chain-level CST_WP_EVENT_TRANSLATION_UNAVAIL.
                 * Not the wp_first_tb_unavail "bug" counter — this is an
                 * expected architectural terminate, not an unfetchable target. */
                *first_tb_unavail = true;
            }
            acc.clear();
            bb_reg_snaps.clear();
            early_exit = true;
            return WpStep::DOMAIN_CROSS;
        }

    return WpStep::PROCEED;
}

/*
 * Run one speculative exec_tb and classify its outcome.  Returns:
 *   RETRY_SESSION       — a tb_flush unwound the exec_tb before any guest
 *                         insn ran (*flush_interrupted set); the caller
 *                         re-runs the whole WP from a fresh spec session
 *   TRANSLATION_UNAVAIL — genuine null template: the wrong-path target could
 *                         not be fetched/translated; the chain (or
 *                         *first_tb_unavail) carries the truncation marker
 *   STUCK_BAIL          — a wild speculative store overflowed the sandbox
 *   PROCEED             — a template ran; st.tmpl / st.tb_ok are set for the
 *                         fragment walk
 * The body is moved verbatim; each terminal break -> return, all latching
 * st.early_exit exactly as the monolith did.
 */
static WpStep wp_exec_one_tb(WpWalkState &st)
{
    auto &tb_ok        = st.tb_ok;
    auto &tmpl         = st.tmpl;
    auto &acc          = st.acc;
    auto &bb_reg_snaps = acc.bb_reg_snaps;
    auto &wp_chain     = st.chain;
    auto &early_exit   = st.early_exit;
    bool *flush_interrupted = st.flush_interrupted;
    bool *first_tb_unavail  = st.first_tb_unavail;
    uint64_t wrong_target   = st.wrong_target;

        /*
         * Use the TB-fragment template vcpu_tb_exec stashed in
         * g_wp_state.last_executed_tb rather than a bb_map_ lookup: the
         * fragment template is branch-terminated identically (next_tb_fragment
         * chains the mid-TB splits) and yields the same WPBBEntry shape after
         * the fragment walk, while skipping the global data_lock a cache
         * lookup takes on every WP iter (~100ns × tens of millions of iters
         * on full mcf runs).
         *
         * Per-insn regdata: clear the per-thread WP scratch buffer here;
         * exec_tb then fires the per-insn callbacks (registered at
         * translation time) that append dst snaps in execution order during
         * WP (see vcpu_insn_reg_snap_cb).  The fragment walk pulls them FIFO
         * for every insn except each fragment's last executed insn, which
         * has no in-fragment successor hook and falls back to a live read.
         */
        if (g_features.wp_reg_data) {
            wp_pending_reg_snaps.clear();
        }
        g_wp_state.last_executed_tb = nullptr;
        g_last_spec_refusal = SpecRefusal::FETCH;   /* refined by translation */
        uint64_t flush_before =
            g_tb_flush_count.load(std::memory_order_acquire);
        tb_ok = qemu_plugin_exec_tb();
        tmpl = g_wp_state.last_executed_tb;
        /*
         * Latch the architectural self-loop accounting of the TB just
         * speculated.  The wrong path executes every TB through
         * cpu_plugin_exec_tb, which sets CF_SINGLE_STEP, so do_gen_rep
         * always translates a single iteration there: a REP that the
         * correct path renders as one execution of N iterations arrives
         * here as N executions of one iteration, plus one trailing
         * execution of zero iterations once the counter is exhausted.
         * Reading the same numbers the correct path reads is what lets
         * wp_commit_bb produce the same structure from them — the wrong
         * path may be operating on deterministic garbage in ECX, but
         * whatever ECX holds must yield the shape the correct path would
         * yield from that same ECX.
         */
        rep_state(g_wp_state.saved_cpu_index).wp_facts.pc       = qemu_plugin_rep_pc();
        rep_state(g_wp_state.saved_cpu_index).wp_facts.iters    = qemu_plugin_rep_iterations();
        rep_state(g_wp_state.saved_cpu_index).wp_facts.bytes    = qemu_plugin_rep_bytes();
        rep_state(g_wp_state.saved_cpu_index).wp_facts.complete = qemu_plugin_rep_complete();
        rep_state(g_wp_state.saved_cpu_index).wp_facts.reenter  = qemu_plugin_rep_reenter();

        if (!tmpl) {
            /* A tb_flush during this exec_tb unwound it (via cpu_loop_exit,
             * caught by cpu_plugin_exec_tb's local guard) before the guest
             * insn ran, so nothing executed.  Signal the caller to re-run
             * the whole WP from a fresh spec session in the now-fresh
             * cache; do NOT continue this session (the flush dropped the
             * spec-mode translation, and resuming would run wrong-path
             * code outside the sandbox).  A genuine null (no flush) means
             * the wrong-path target could not be fetched/translated —
             * un-resident code under demand paging, or a refused garbage
             * region — and truncates the chain: mark the last completed WP
             * BB translation_unavailable so the truncation is explicit on
             * the wire (CST_WP_EVENT_TRANSLATION_UNAVAIL) instead of
             * indistinguishable from a clean depth-budget end.  The
             * validator reads the marker to tell an honest boundary from a
             * silently short chain. */
            if (g_tb_flush_count.load(std::memory_order_acquire) !=
                    flush_before) {
                *flush_interrupted = true;
            } else if (!wp_chain.empty()) {
                wp_chain.back().translation_unavailable = true;
            } else {
                /* Genuine null on the FIRST target: the wrong-path entry
                 * point itself could not be fetched/translated and there
                 * is no chain to carry the truncation marker.  Hand the
                 * condition to the caller via @first_tb_unavail so the
                 * emitter makes it explicit on the wire as a chain-level
                 * CST_WP_EVENT_TRANSLATION_UNAVAIL event (§4.4) instead
                 * of leaving an indistinguishable silent 0-block chain.
                 * Also count it (a nonzero count against resident
                 * targets is a bug) and expose the instance under
                 * CST_WP_DIAG. */
                *first_tb_unavail = true;
                thread_stats_get().wp_first_tb_unavail++;
                if (Stats *h = g_current_hist_bucket) {
                    h->wp_first_tb_unavail++;
                }
                if (getenv("CST_WP_DIAG")) {
                    fprintf(stderr, "[wpdiag] first-TB unavailable: "
                            "target=0x%" PRIx64 " wrong_target=0x%" PRIx64
                            " reason=%s\n",
                            qemu_plugin_get_pc(), wrong_target,
                            g_last_spec_refusal == SpecRefusal::POISON
                                ? "poison" : "fetch");
                }
            }
            acc.clear();
            bb_reg_snaps.clear();
            early_exit = true;
            return *flush_interrupted ? WpStep::RETRY_SESSION
                                      : WpStep::TRANSLATION_UNAVAIL;
        }

        /*
         * Wild speculative store: a garbage-size memop the wrong path just
         * executed wrote past the spec-store soft budget into the sandbox
         * without faulting (it is buffered, not real).  The wrong path has
         * diverged into nonsense — a real CPU's wrong-path store would fault and
         * mispredict-recover — so terminate the excursion rather than fill the
         * sandbox to its hard cap and start dropping stores.  Drop the in-flight
         * chain; the correct-path BBs already emitted are preserved. */
        if (qemu_plugin_spec_store_overflowed()) {
            acc.clear();
            bb_reg_snaps.clear();
            early_exit = true;
            return WpStep::STUCK_BAIL;
        }

    return WpStep::PROCEED;
}

/*
 * Attribute the speculative memory accesses recorded during this exec_tb to
 * the just-appended fragment's insns (by matching insn_pc), pushing a
 * DynParam per matched access and marking the BB synthetic-faulted on the
 * first faulted access.  @bb_idx_base is bb_pcs.size() sampled BEFORE the
 * fragment's insns were appended, so bb_idx_base + i is the WP BB-local
 * index of fragment insn i.  A void leaf, moved verbatim.
 */
static void wp_attribute_memops(WpWalkState &st, BBTemplate *cur,
                                uint32_t n_executed_in_cur, uint32_t bb_idx_base)
{
    auto &bb_has_fault       = st.acc.bb_has_fault;
    auto &bb_first_fault_idx = st.acc.bb_first_fault_idx;
    auto &bb_dyn_params      = st.acc.bb_dyn_params;
    auto &mem_start_idx      = st.mem_start_idx;
    Stats &stats = *st.stats;
    Stats *hist  = st.hist;

            /* Attribute mem accesses to this fragment's insns by
             * matching insn_pc.  Only walk the @n_executed_in_cur
             * prefix — mem callbacks past the fault / partial-exec
             * boundary never fired. */
            for (size_t m = mem_start_idx;
                 m < g_wp_state.mem_accesses.size(); m++) {
                const WPMemAccess &acc = g_wp_state.mem_accesses[m];
                uint16_t insn_idx = (uint16_t)bb_idx_base;
                bool matched = false;
                for (uint32_t i = 0; i < n_executed_in_cur; i++) {
                    if (cur->insn_pcs[i] == acc.insn_pc) {
                        insn_idx = (uint16_t)(bb_idx_base + i);
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    /* Memop belongs to a different fragment in this
                     * exec_tb; the loop iteration for THAT fragment
                     * will pick it up. */
                    continue;
                }
                /* Synthetic-data memory fault (new wrong-path policy): this
                 * access hit an absent/unreadable page and ran on a
                 * deterministic placeholder value.  Mark the owning WP BB
                 * entry as faulted at this insn (the FIRST such insn is
                 * sufficient — everything downstream is synthetic anyway) and
                 * let the excursion CONTINUE.  wp_synthetic_marking gates the
                 * marking for A/B (CST_NO_FAULT); the access still runs on
                 * garbage either way. */
                if (acc.faulted && g_features.wp_synthetic_marking &&
                    !bb_has_fault) {
                    bb_has_fault = true;
                    bb_first_fault_idx = insn_idx;
                    stats.wp_synthetic_faults++;
                    if (hist) {
                        hist->wp_synthetic_faults++;
                    }
                }
                DynParam dp = {
                    .type = (uint8_t)(acc.is_store ? DYN_STORE_ADDR
                                                    : DYN_LOAD_ADDR),
                    .insn_index = insn_idx,
                    .value = acc.mem_vaddr,
                    .data_size = acc.data_size,
                    .data = acc.data,
                    .ppage = acc.ppage,
                    .ppage_valid = acc.ppage_valid,
                };
                bb_dyn_params.push_back(dp);
                stats.wp_total_mem_accesses++;
                if (hist) {
                    hist->wp_total_mem_accesses++;
                }
            }
}

/*
 * Seal a completed true BB discovered on the wrong path: pick its landing
 * PC, compute the architectural fall-through, commit it into the shared
 * template cache (seeding is_system from its VA class), record the
 * terminal-branch taken edge for non-indirect branches, and push the
 * WPBBEntry onto the chain.  Reports the block's landing PC in
 * @commit_post_pc (consumed by the fragment loop's terminal checks, which run
 * after acc.clear()).  Body moved verbatim.
 */
static void wp_commit_bb(WpWalkState &st, BBTemplate *cur,
                         uint32_t n_executed_in_cur, uint8_t last_insn_size,
                         uint64_t fault_redispatch_pc,
                         uint64_t &commit_post_pc)
{
    auto &acc               = st.acc;
    auto &bb_pcs            = acc.bb_pcs;
    auto &bb_sizes          = acc.bb_sizes;
    auto &bb_bytes          = acc.bb_bytes;
    auto &bb_fields         = acc.bb_fields;
    auto &bb_regnames       = acc.bb_regnames;
    auto &bb_start_pc       = acc.bb_start_pc;
    auto &bb_symbol_name    = acc.bb_symbol_name;
    auto &bb_has_fault      = acc.bb_has_fault;
    auto &bb_first_fault_idx = acc.bb_first_fault_idx;
    auto &wp_chain          = st.chain;
    auto &pre_pc            = st.pre_pc;
    auto &post_pc_now       = st.post_pc_now;
    auto &repeated_fault_pc = st.repeated_fault_pc;
    auto &last_fault_pc     = st.last_fault_pc;

            /* Branch fired: commit completed BB.  Still a true
             * branch-bounded BB (basic_block.md), so it goes into
             * bb_map_ unconditionally; bb_has_fault carries any
             * earlier in-BB fault and the WPBBEntry's fault flag
             * tells the consumer speculation would have squashed at
             * fault_insn_index. */
            if (fault_redispatch_pc != UINT64_MAX) {
                /* A direct-match execution fault landed on this BB's terminator
                 * (a conditional trap).  The trap itself never redirected — the
                 * excursion continues at its architectural fall-through — so
                 * land at skip_pc, not the trap's own PC (which post_pc_now
                 * holds and which we just poisoned). */
                commit_post_pc = fault_redispatch_pc;
            } else if (cur->next_tb_fragment) {
                /* Mid-TB fragment whose branch we just classified as
                 * fired: by construction (only the trap-fires path
                 * stops the walk via fault_consumed) we never reach
                 * here for a no-trap intermediate; if execution did
                 * continue past this fragment, branch_fired wouldn't
                 * really have fired and we'd not be on this code
                 * path.  Use the next fragment's start_pc as the
                 * landing point. */
                commit_post_pc = cur->next_tb_fragment->start_pc;
            } else {
                commit_post_pc = post_pc_now;
            }
            repeated_fault_pc = 0;
            last_fault_pc = UINT64_MAX;

            /*
             * Architectural fall-through = PC after the BB's LAST
             * INSTRUCTION (the branch), NOT @pre_pc + last_insn_size.
             * @pre_pc is the START of the current TB fragment; for a
             * multi-insn fragment that's some insn BEFORE the branch
             * and gives a fall_through that lands INSIDE the BB.
             * Use the branch's own PC + its size instead.  Because
             * WP-discovered BBs are committed to the shared
             * bb_template_cache BEFORE the CP-side commit (WP runs
             * inside emit_finalized_bb), a wrong value here is
             * inherited by every subsequent CP lookup of the same BB.
             */
            uint64_t last_insn_pc = n_executed_in_cur > 0
                ? cur->insn_pcs[n_executed_in_cur - 1]
                : pre_pc;
            uint64_t fall_through = last_insn_pc + last_insn_size;

            g_mutex_lock(&data_lock);
            /* The shared-kernel-bucket key is chosen from bb_start_pc's VA
             * class inside commit_true_bb_refs (store_asid_root): a kernel-VA
             * block joins the one shared kernel template even when only the
             * wrong path ever discovers it, while a user VA can never reach
             * the sentinel (kernel/user VA ranges are disjoint), so a
             * speculative is_system mis-stamp cannot conflate two processes'
             * user code.  The domain-switch terminate above guarantees this
             * committed block was fetched entirely within one privilege
             * domain, so its VA class is its true domain. */
            /* Wrong-path commit: cp_confirmed=false — a speculative
             * translation observing mid-write bytes must NEVER version a
             * template (smc_plan.md §1.4).  A byte-drifted block reuses the
             * live template silently, exactly as before SMC support. */
            BBTemplate *bb_tmpl = g_template_store.commit_true_bb_refs(
                bb_start_pc, (uint32_t)bb_pcs.size(),
                bb_pcs.data(),
                bb_fields.data(),
                bb_sizes.data(),
                bb_bytes.data(),
                g_features.reg_data ? bb_regnames.data() : nullptr,
                bb_symbol_name, fall_through,
                /* cp_confirmed= */ false);
            /* Privilege seed for WP-only-discovered BBs.  Seed from the
             * architectural VA class of the block's start, not the wrong-path
             * priv level: a kernel-VA block IS kernel code regardless of what
             * a speculative translation observed, so this is a reliable seed
             * (SMEP/PXN forbid kernel-context execution of user pages, and the
             * domain-switch terminate ends any excursion that would cross the
             * boundary).  A correct-path finalize of the same BB still
             * overrides and latches the authoritative value (see
             * BBTemplate::is_system). */
            if (bb_tmpl && !bb_tmpl->is_system_cp_confirmed) {
                bb_tmpl->is_system = cst_va_is_kernel_code(bb_start_pc);
            }
            g_mutex_unlock(&data_lock);

            /*
             * Record the terminal-branch taken edge for NON-indirect
             * branches found on the wrong path (see the pre-splitter
             * comment).
             */
            if (bb_tmpl && bb_tmpl->taken_pc == 0 && !bb_fields.empty()) {
                const InsnFields *lf = bb_fields.back();
                if (lf->branch_type == BRANCH_NONE && bb_fields.size() >= 2) {
                    /* Delay-slot tail: terminator is the insn before
                     * the trailing delay slot. */
                    lf = bb_fields[bb_fields.size() - 2];
                }
                bool indirect =
                    lf->branch_type == BRANCH_INDIRECT_JUMP ||
                    lf->branch_type == BRANCH_RETURN ||
                    lf->branch_type == BRANCH_INDIRECT_CALL;
                if (!indirect) {
                    bool cond = lf->branch_type == BRANCH_COND_DIRECT ||
                                (lf->branch_type == BRANCH_DIRECT_JUMP &&
                                 lf->branch_conditional);
                    uint64_t taken;
                    if (commit_post_pc != fall_through) {
                        taken = commit_post_pc;
                    } else if (cond && lf->has_immediate &&
                               (uint64_t)lf->immediate != fall_through) {
                        taken = (uint64_t)lf->immediate;
                    } else {
                        taken = commit_post_pc;
                    }
                    if (taken != 0) {
                        bb_tmpl->taken_pc = taken;
                    }
                }
            }

            /* Terminal-branch outcome for the CST_FID_BRANCH_* singletons on
             * this WP block.  commit_post_pc is the PC the block's terminating
             * branch actually reached — the next chain block's start_pc (and,
             * for the chain's last block, where the excursion would continue).
             * Stamped verbatim; direction/target are derived at wire-emit time
             * and delta-encode through the per-chain WP overlay (correction:
             * WP now carries these, delta'd against the last WP emission, not
             * a fresh baseline). */
            /*
             * Self-loop accounting on the wrong path.  The correct path's
             * fan-out already renders one entry per architectural iteration
             * of a REP; the wrong path gets the same shape for free, because
             * CF_SINGLE_STEP makes each iteration its own speculated TB and
             * therefore its own block.  The one place the two diverge is
             * QEMU's trailing pass: after the iteration that exhausts the
             * counter it re-enters the instruction once more and takes the
             * zero-count exit, doing no architectural work.  That block is
             * the same instruction finishing, not a new one, so dropping it
             * here is what makes the wrong-path rendering of a REP identical
             * to the correct-path rendering of the same REP — and the
             * divergence is invisible to every external reference check,
             * which validates the correct path only.
             *
             * The exit edge gets the same treatment: the retiring iteration's
             * observed successor is the instruction's own PC (QEMU jumps back
             * before taking that exit), while architecturally it fell through.
             */
            bool rep_drop = false;
            if (bb_tmpl && bb_tmpl->n_insns > 0) {
                uint32_t rlast = bb_tmpl->n_insns - 1;
                uint64_t rpc   = bb_tmpl->insn_pcs[rlast];
                if (bb_tmpl->insn_fields[rlast].rep_memops_per_iter > 0 &&
                    rep_state(g_wp_state.saved_cpu_index).wp_facts.pc != 0 && rep_state(g_wp_state.saved_cpu_index).wp_facts.pc == rpc) {
                    bool cont = rep_state(g_wp_state.saved_cpu_index).wp_in_flight.in_progress &&
                                rep_state(g_wp_state.saved_cpu_index).wp_in_flight.pc == rpc;
                    rep_state(g_wp_state.saved_cpu_index).wp_in_flight.pc          = rpc;
                    rep_state(g_wp_state.saved_cpu_index).wp_in_flight.in_progress = rep_state(g_wp_state.saved_cpu_index).wp_facts.reenter;
                    if (rep_state(g_wp_state.saved_cpu_index).wp_facts.iters == 0 && cont) {
                        rep_drop = true;
                        g_stats.rep_trailing_pass_dropped++;
                    } else if (rep_state(g_wp_state.saved_cpu_index).wp_facts.complete &&
                               rep_state(g_wp_state.saved_cpu_index).wp_facts.iters >= 1 &&
                               commit_post_pc == rpc) {
                        commit_post_pc = bb_tmpl->fall_through_pc;
                        g_stats.rep_exit_edge_recovered++;
                    }
                }
            }
            if (!rep_drop) {
                WPBBEntry wp_entry = acc.make_entry(bb_tmpl,
                                                    bb_has_fault,
                                                    bb_first_fault_idx);
                wp_entry.branch_successor_pc    = commit_post_pc;
                wp_entry.branch_successor_known = true;
                wp_chain.push_back(std::move(wp_entry));
            }

            /*
             * Opportunistic branch-alternate minting (static_templates=1).
             * A branch INSIDE a wrong-path block resolves ONE direction (the
             * excursion follows commit_post_pc); its untaken side is never
             * walked, so an executed-only + wrong-path dictionary misses it.
             * Decode+mint that side as a never-executed template.  No-op
             * unless the feature is on; the terminal is the last insn (or the
             * insn before a trailing delay slot).  data_lock is NOT held here
             * (released after the commit_true_bb_refs above), so altmint_pc's
             * own lock discipline is safe.
             *
             * bb_tmpl->alt_checked_wp latches this to ONCE per WP block: the
             * same block is re-walked on every excursion (millions of commits
             * per trace), but its untaken side is invariant, so a per-visit
             * hash lookup + lock would be the dominant cost.  The in-hand flag
             * read skips all but the first visit; the flag is set
             * unconditionally (even for non-mintable terminators) so a block
             * is never re-examined.
             */
            if (g_features.alt_mint && bb_tmpl && !bb_tmpl->alt_checked_wp &&
                !bb_fields.empty()) {
                bb_tmpl->alt_checked_wp = true;
                const InsnFields *lf = bb_fields.back();
                if (lf->branch_type == BRANCH_NONE && bb_fields.size() >= 2) {
                    lf = bb_fields[bb_fields.size() - 2];
                }
                altmint_conditional_alternate(lf, fall_through, commit_post_pc);
            }
}

/*
 * Handle a fragment on which a synchronous back-end exception longjmped out
 * of spec mode.  Records the repeated-fault bookkeeping, marks the block
 * synthetic, and splits on fault_direct_match:
 *   - post-completion (SVC/ECALL retired, kernel-entry failed): keep the
 *     interim graceful stop, or bail on a bare-branch / stuck fragment;
 *   - direct execution fault: skip the faulting insn and either seal the BB
 *     at a syscall-boundary terminator or resume the outer iteration mid-BB.
 * Mutates bb_complete / fault_redispatch_pc (and st's fault/poison/awaiting
 * state).  Returns BREAK_WALK to break the fragment loop (every such path
 * has latched walk_done, and early_exit where the monolith did) or PROCEED
 * to fall through to the completed-BB commit.  Body moved verbatim.
 */
static WpStep wp_handle_fault_fragment(WpWalkState &st, BBTemplate *cur,
                                       uint32_t n_executed_in_cur,
                                       uint8_t last_insn_size,
                                       bool branch_fired,
                                       bool fault_direct_match,
                                       bool &bb_complete,
                                       uint64_t &fault_redispatch_pc)
{
    auto &acc                = st.acc;
    auto &bb_pcs             = acc.bb_pcs;
    auto &bb_reg_snaps       = acc.bb_reg_snaps;
    auto &bb_has_fault       = acc.bb_has_fault;
    auto &bb_first_fault_idx = acc.bb_first_fault_idx;
    auto &poisoned_targets   = st.poisoned_targets;
    auto &pre_pc             = st.pre_pc;
    auto &post_pc_now        = st.post_pc_now;
    auto &last_fault_pc      = st.last_fault_pc;
    auto &repeated_fault_pc  = st.repeated_fault_pc;
    auto &awaiting_delay_slot = st.awaiting_delay_slot;
    auto &early_exit         = st.early_exit;
    auto &walk_done          = st.walk_done;
    Stats &stats = *st.stats;
    Stats *hist  = st.hist;

                /*
                 * A synchronous back-end exception longjmped out of spec mode
                 * inside this BB.  Memory faults never reach here (the load /
                 * store seam garbage-fills inline and keeps tb_ok true); this
                 * is either an EXECUTION-TIME fault at a retiring insn — x86
                 * #DE/#UD/#GP/#AC, a conditional trap; MIPS arithmetic
                 * overflow; or a syscall-class kernel entry (syscall / int /
                 * svc / ecall / break) — reported as a DIRECT match when the
                 * unwind rewinds the PC to the instruction itself, or as a
                 * POST-COMPLETION match when the architecture leaves the PC at
                 * the following instruction (AArch64 SVC, whose ELR already
                 * points past it).
                 *
                 * Nothing retires on a wrong path, so NO synchronous exception
                 * truncates the excursion — a kernel entry least of all.  A
                 * real out-of-order core fetches straight past a syscall and
                 * squashes it at retire; the wrong path models that by taking
                 * the syscall's unfollowable kernel edge as the taken side of
                 * an ordinary branch and continuing on the NOT-taken side, its
                 * architectural fall-through.  So every case here does the
                 * same thing: mark the block synthetic, clear the pending
                 * exception, skip the faulting instruction, and re-dispatch at
                 * its fall-through until the wpdepth budget runs out.  The
                 * skipped instruction's destinations stay stale — the
                 * deterministic placeholder the dominant memory case already
                 * uses — so its dependents still execute.
                 *
                 * The call itself is never performed.  In *-linux-user the
                 * unwind lands in cpu_plugin_exec_tb()'s pad rather than
                 * cpu_loop(), so the host-side dispatcher is unreachable (and
                 * do_syscall()'s wrong-path barrier stands as the proof); in
                 * system mode the x86 inline escalation unwinds here too
                 * instead of loading LSTAR.
                 */
                uint64_t fault_pc = post_pc_now;

                if (pre_pc == last_fault_pc) {
                    repeated_fault_pc++;
                } else {
                    repeated_fault_pc = 0;
                    last_fault_pc = pre_pc;
                }

                /* Mark the faulting insn synthetic, gated for A/B: CST_NO_FAULT
                 * (wp_synthetic_marking off) leaves the fault detected and
                 * skipped but unmarked, matching the pre-policy shape. */
                if (g_features.wp_synthetic_marking && !bb_has_fault) {
                    bb_has_fault = true;
                    bb_first_fault_idx = bb_pcs.empty()
                        ? 0 : (uint32_t)(bb_pcs.size() - 1);
                    stats.wp_synthetic_faults++;
                    if (hist) {
                        hist->wp_synthetic_faults++;
                    }
                }

                /* Size of the faulting insn = the last insn appended for this
                 * fragment (n_executed_in_cur - 1). */
                uint64_t skip_pc = fault_pc + last_insn_size;

                if (!fault_direct_match) {
                    /*
                     * POST-COMPLETION match: the exception was raised with the
                     * PC ALREADY past the instruction that raised it, which is
                     * how AArch64 reports a kernel entry (SVC leaves ELR at
                     * SVC+4) and how a downstream handler-entry failure
                     * surfaces.  @fault_pc is therefore the raising
                     * instruction's own architectural fall-through — precisely
                     * where the wrong path continues — so there is nothing to
                     * skip: drop the pending exception and let the walk run on
                     * from the PC it already holds.
                     *
                     * Poison the RAISING instruction, not @fault_pc: poisoning
                     * the fall-through would abort the excursion at the very
                     * block we are about to commit.
                     */
                    qemu_plugin_spec_clear_exception();
                    /* Same exemption as the direct-match path below: a
                     * syscall-class instruction raises every time by design, so
                     * poisoning it would kill the excursion the second time
                     * speculation reached the same syscall.  AArch64 lands
                     * here rather than there -- SVC raises with ELR already at
                     * SVC+4 -- so without this the exemption would cover every
                     * ISA but the one whose kernel entry is most common. */
                    bool syscall_class_raiser =
                        n_executed_in_cur > 0 &&
                        cur->insn_fields[n_executed_in_cur - 1].branch_type
                            == BRANCH_SYSCALL_TYPE;
                    if (n_executed_in_cur > 0 && !syscall_class_raiser) {
                        poisoned_targets.insert(
                            cur->insn_pcs[n_executed_in_cur - 1]);
                    }

                    /* Don't force-commit a BARE_BRANCH fragment that faulted:
                     * its delay slot is in the next QEMU TB and never landed
                     * here, so a commit now would write the wrong (n-1 insns,
                     * no delay slot) shape into bb_map_ and collide with the
                     * natural full-BB shape.  With the retired branch's
                     * delay-slot hflags pending in the unwound state (set_pc
                     * not clearing MIPS_HFLAG_BMASK), a skip-resume would
                     * translate skip_pc as-if-in-a-delay-slot; end the
                     * excursion instead — committed WP BBs are preserved. */
                    bool bare_branch_pending = branch_fired &&
                        cur->terminus == TB_TERMINUS_BARE_BRANCH;
                    if (bare_branch_pending) {
                        acc.clear();
                        bb_reg_snaps.clear();
                        early_exit = true;
                        walk_done = true;
                        return WpStep::BREAK_WALK;
                    }
                    if (branch_fired || bb_complete) {
                        /* Force bb_complete so the post-fault commit fires
                         * even when only the branch (no delay slot) ran. */
                        bb_complete = true;
                        awaiting_delay_slot = false;
                    } else {
                        /* Mid-BB: resume where the unwind already left the PC.
                         * @skip_pc would be wrong here -- it is built for the
                         * direct match, where the PC sits ON the raising insn
                         * and one instruction length has to be added to step
                         * over it.  In a post-completion match that step has
                         * already happened, so adding it again would skip the
                         * instruction AFTER the raiser, silently dropping it
                         * from the wrong path. */
                        if (repeated_fault_pc >= 16) {
                            early_exit = true;
                            walk_done = true;
                            return WpStep::BREAK_WALK;
                        }
                        if (poisoned_targets.count(fault_pc)) {
                            early_exit = true;
                            walk_done = true;
                            return WpStep::BREAK_WALK;
                        }
                        qemu_plugin_set_pc(fault_pc);
                        walk_done = true;
                        return WpStep::BREAK_WALK;
                    }
                } else {
                    /*
                     * DIRECT match: an execution-time exception fired AT insn
                     * fault_idx.  Skip it and CONTINUE the excursion.
                     */
                    if (repeated_fault_pc >= 16) {
                        /* Forward-progress guard: the same PC re-faults despite
                         * the +len advance (shouldn't happen — PC advances —
                         * but bound wandering anyway). */
                        early_exit = true;
                        walk_done = true;
                        return WpStep::BREAK_WALK;
                    }
                    /* A bare delay-slot branch (slot in the next TB, so a skip
                     * would mistranslate skip_pc as-if-in-a-delay-slot) or a
                     * fall-through that is itself a poisoned target: end the
                     * excursion cleanly rather than guess. */
                    bool bare_branch_pending = branch_fired &&
                        cur->terminus == TB_TERMINUS_BARE_BRANCH;
                    if (bare_branch_pending ||
                        poisoned_targets.count(skip_pc)) {
                        acc.clear();
                        bb_reg_snaps.clear();
                        early_exit = true;
                        walk_done = true;
                        return WpStep::BREAK_WALK;
                    }

                    /*
                     * Clear the pending guest exception (new plugin API) so the
                     * next spec exec_tb starts clean, then step past the
                     * faulting insn.  The fault unwind (cpu_loop_exit_restore ->
                     * restore_state_to_opc) already re-synced the register file
                     * to the faulting insn's boundary and restored the PC to it;
                     * only the faulted insn's dst is stale, and the BB is marked
                     * synthetic so the consumer knows.  The spec session stays
                     * live so the sandboxed store buffer and spec TLB installs
                     * survive the skip.
                     */
                    qemu_plugin_spec_clear_exception();
                    qemu_plugin_set_pc(skip_pc);

                    /*
                     * Poison the faulting PC so a wrong path that circles back
                     * to it gives up instead of re-faulting forever — but NOT
                     * for a syscall-class instruction.  That one does not
                     * "fault": it raises every single time, by design, and the
                     * skip past it is its defined wrong-path behaviour.
                     * Poisoning it would kill the excursion the second time the
                     * speculation reached the same syscall — the exact chain
                     * truncation this policy exists to remove, and a common
                     * shape (glibc's _exit issues exit_group then exit in a
                     * loop, and a retry loop around any syscall does the same).
                     * Forward progress is still bounded by repeated_fault_pc
                     * above and, ultimately, by the depth budget.
                     */
                    bool syscall_class_fault =
                        n_executed_in_cur > 0 &&
                        cur->insn_fields[n_executed_in_cur - 1].branch_type
                            == BRANCH_SYSCALL_TYPE;
                    if (!syscall_class_fault) {
                        poisoned_targets.insert(fault_pc);
                    }

                    if (branch_fired || bb_complete) {
                        /*
                         * The faulting insn IS the BB terminator: a deliberate
                         * control transfer to the kernel that raised out of
                         * spec mode — a syscall or software interrupt
                         * (syscall/int/svc/ecall/break), or a trap
                         * (BRANCH_SYSCALL_TYPE either way) — since a plain
                         * branch never raises.
                         *
                         * Its architectural resolution is a privilege
                         * escalation the single-address-space, side-effect-free
                         * spec model cannot follow.  That makes the kernel edge
                         * the UNFOLLOWABLE side of a two-way instruction, not a
                         * reason to stop: a real out-of-order core fetches
                         * straight past the syscall and squashes it at retire,
                         * so the wrong path takes the other side — the
                         * architectural fall-through at skip_pc — exactly as it
                         * takes the not-taken side of any other branch.  Seal
                         * the true BB here (the terminator did terminate a
                         * block) and land the excursion at skip_pc, marked
                         * synthetic because the syscall's own results are the
                         * deterministic placeholder its dependents will read.
                         */
                        bb_complete = true;
                        awaiting_delay_slot = false;
                        fault_redispatch_pc = skip_pc;
                    } else {
                        /* Mid-BB fault: run the BB out to its natural branch
                         * (no partial, template-polluting commit).  Resume the
                         * outer iter from skip_pc; the accumulator persists. */
                        walk_done = true;
                        return WpStep::BREAK_WALK;
                    }
                }

    return WpStep::PROCEED;
}

/*
 * Walk the fragment list one speculative exec_tb produced, committing each
 * true BB it completes.  Owns the per-exec_tb fragment loop and its
 * abnormal-exit tail; all outcomes land in st (early_exit / walk_done /
 * fault_consumed), which the driver inspects after the call.
 * The former outer-while break in the fault-PC-outside-TB tail becomes a
 * return (early_exit is latched, so the driver's tail break fires); every
 * break/continue inside the for-loop keeps steering the fragment loop.
 * Body moved verbatim.
 */
static void wp_walk_fragments(WpWalkState &st)
{
    auto &acc                = st.acc;
    auto &bb_pcs             = acc.bb_pcs;
    auto &bb_fields          = acc.bb_fields;
    auto &bb_reg_snaps       = acc.bb_reg_snaps;
    auto &bb_start_pc        = acc.bb_start_pc;
    auto &bb_symbol_name     = acc.bb_symbol_name;
    auto &tmpl               = st.tmpl;
    auto &tb_ok              = st.tb_ok;
    auto &post_pc_now        = st.post_pc_now;
    auto &fault_consumed     = st.fault_consumed;
    auto &walk_done          = st.walk_done;
    auto &wp_snap_cursor     = st.wp_snap_cursor;
    auto &sim_insns          = st.sim_insns;
    auto &awaiting_delay_slot = st.awaiting_delay_slot;
    auto &early_exit         = st.early_exit;
    auto &poisoned_targets   = st.poisoned_targets;
    unsigned int cpu_index   = st.cpu_index;
    Stats &stats = *st.stats;
    Stats *hist  = st.hist;

        /*
         * Walk the fragment list produced by the mid-TB-branch
         * splitter (see split_tb_into_fragments).  A single
         * exec_tb may execute multiple fragments (no trap, control
         * flows through), or only a prefix (trap fires mid-TB, or a
         * fragment's branch terminator fires).  We process each
         * fragment that ran, appending its insns and checking
         * bb_complete after each one — multiple BB commits per
         * exec_tb call are possible when one TB contains multiple
         * branch terminators.
         *
         * For singleton TBs (no mid-TB branch) and true-BB cache
         * hits, next_tb_fragment is nullptr so the loop runs once
         * with identical behavior to the pre-splitter walker.
         *
         * @post_pc_now is where execution actually landed; the
         * matching logic below identifies which fragment that PC
         * sits inside.  Fragments fully past @post_pc_now in the
         * chain ran completely; the fragment containing @post_pc_now
         * partially ran and ends the walk.  On fault (!tb_ok), the
         * fault_pc match plays the same role.
         */
        post_pc_now = qemu_plugin_get_pc();
        fault_consumed = false;
        walk_done = false;
        /* Cursor into wp_pending_reg_snaps, advanced as the walk
         * consumes per-insn snaps in execution order across all
         * fragments executed in this exec_tb.  Bumped by every insn
         * the callback captured (i.e., every executed insn except the
         * last of each fragment), whether or not WP appends that insn
         * after dedup. */
        wp_snap_cursor = 0;

        for (BBTemplate *cur = tmpl; cur != nullptr && !walk_done;
             cur = cur->next_tb_fragment) {
            uint32_t n_executed_in_cur = cur->n_insns;
            bool stop_after_this = false;
            bool cur_is_fault_fragment = false;
            /* Direct match = an execution-time exception fired AT insn
             * fault_idx (div0/overflow, illegal opcode, conditional trap,
             * alignment).  Post-completion match = the insn retired and a
             * downstream event failed out of spec mode (a system-mode SVC/ECALL
             * kernel-entry).  Only the direct match is skipped-and-continued to
             * the budget; post-completion keeps the interim graceful stop. */
            bool fault_direct_match = false;
            /* Set when a direct-match execution fault lands ON the BB
             * terminator (a conditional trap): the sealed BB then continues at
             * the trap's architectural fall-through, not its own PC. */
            uint64_t fault_redispatch_pc = UINT64_MAX;

            if (tb_ok) {
                /* Identify the fragment containing post_pc.  Match at
                 * insn_pcs[i] for i >= 1 means execution stopped INSIDE
                 * this fragment at insn i.  post_pc == insn_pcs[0] reads
                 * as a full run (loop-back-to-entry), consistent with
                 * the pre-splitter behavior.  No match means this
                 * fragment ran fully and execution either continued
                 * into the next fragment or left the TB. */
                for (uint32_t i = 1; i < cur->n_insns; i++) {
                    if (cur->insn_pcs[i] == post_pc_now) {
                        n_executed_in_cur = i;
                        stop_after_this = true;
                        break;
                    }
                }
            } else {
                /* Fault path: locate fault_pc in this fragment.
                 * Direct match (faulted before retiring insn k) or
                 * post-completion match (faulted after retiring insn k:
                 * e.g. SVC/ECALL retires then handler fails out of spec
                 * mode, PC = SVC_PC + size).  If neither matches, the
                 * fault is past this fragment — fragment ran fully,
                 * keep walking. */
                uint64_t fault_pc = post_pc_now;
                uint32_t fault_idx = UINT32_MAX;
                for (uint32_t i = 0; i < cur->n_insns; i++) {
                    if (cur->insn_pcs[i] == fault_pc) {
                        fault_idx = i;
                        fault_direct_match = true;
                        break;
                    }
                }
                if (fault_idx == UINT32_MAX) {
                    for (uint32_t i = 0; i < cur->n_insns; i++) {
                        uint64_t post = cur->insn_pcs[i] +
                                        cur->insn_sizes[i];
                        if (post == fault_pc) {
                            fault_idx = i;
                            break;
                        }
                    }
                }
                if (fault_idx != UINT32_MAX) {
                    n_executed_in_cur = fault_idx + 1;
                    stop_after_this = true;
                    cur_is_fault_fragment = true;
                    fault_consumed = true;
                }
            }

            uint32_t bb_idx_base = (uint32_t)bb_pcs.size();
            if (bb_pcs.empty()) {
                /* New WP BB accumulator starts at THIS fragment's
                 * start_pc.  Resetting here (not just at outer-iter
                 * top) lets mid-iter commits — when one exec_tb's
                 * fragments include multiple branch terminators —
                 * each anchor their accumulated BB at the correct
                 * fragment entry, instead of mis-attributing the
                 * second fragment's BB to the outer iter's pre_pc. */
                bb_start_pc = cur->start_pc;
                if (cur->symbol_name) {
                    bb_symbol_name = cur->symbol_name;
                }
            }
            uint32_t appended_insns =
                wp_append_fragment_insns(acc, cur, n_executed_in_cur,
                                         wp_snap_cursor, cpu_index,
                                         stats, hist);

            /*
             * Wrong-path fault policy (retired poison/dep-branch-kill).  A
             * back-end fault on a mispredicted path is never taken by a real
             * core, so it no longer squashes the excursion at a dependent
             * branch.  MEMORY faults never even reach here (the load/store
             * seam garbage-fills and continues, tb_ok stays true; the memop
             * drain above marks the BB synthetic).  An EXECUTION-TIME fault —
             * arithmetic overflow / divide-by-zero, illegal opcode, alignment,
             * a conditional trap — still longjmps (tb_ok=false,
             * cur_is_fault_fragment); the fault block below marks it synthetic,
             * skips the faulting insn, and re-dispatches to the depth budget,
             * mirroring the memory case.  Only a post-completion system-mode
             * kernel-entry (SVC/ECALL handler) keeps the interim graceful stop.
             */
            uint8_t last_insn_size = n_executed_in_cur > 0
                ? cur->insn_sizes[n_executed_in_cur - 1]
                : 0;
            /* Nop-slide bound (#91): an unsealed wrong-path BB growing past
             * any real block size means the speculation is running a
             * branchless straight line through non-code — typically zeroed
             * pages, which decode as nop streams — far past the depth
             * budget (the walk continues while the BB is unsealed).  Left
             * unbounded it commits multi-thousand-insn garbage templates
             * (~3.3 KB/insn) into the trace per excursion.  DROP the
             * accumulator (never commit a slide) and end the excursion;
             * the cap leaves generous headroom over the largest legitimate
             * generated blocks so exact-chain validation is unaffected. */
            if (bb_pcs.size() > 2048) {
                acc.clear();
                bb_reg_snaps.clear();
                early_exit = true;
                walk_done = true;
                break;
            }

            /*
             * Budget accounting.  Charge AT LEAST 1 per exec_tb even
             * when every appended insn dedup'd against the prior tail,
             * else a self-looping single-insn REP TB spins forever
             * (see the forward-progress guard above).  Only counted
             * once per outer iter — first fragment to actually contribute.
             */
            if (cur == tmpl) {
                sim_insns += appended_insns ? appended_insns : 1;
            } else {
                sim_insns += appended_insns;
            }

            wp_attribute_memops(st, cur, n_executed_in_cur, bb_idx_base);

            /* Per-fragment bb_complete computation.  Each fragment's
             * terminus drives whether the in-flight WP BB completes
             * now.  Mid-TB branch fragments (e.g. conditional traps
             * with terminus=COMPLETE) commit their own BB here even
             * though more fragments in this exec_tb may follow.
             *
             * branch_fired: the just-appended slice ended on a
             *   branch-classified insn (used by the fault path to
             *   distinguish "fault on a branch terminator" from
             *   "fault on a middle insn").
             * bb_complete: the in-flight WP BB is now complete and
             *   ready to commit.  TB_TERMINUS_BARE_BRANCH (delay-slot
             *   ISA, slot in next TB) defers completion until that
             *   next-TB's first fragment lands here. */
            bool branch_fired = false;
            if (!bb_pcs.empty()) {
                size_t last_local = bb_pcs.size() - 1;
                if (bb_fields[last_local]->branch_type != BRANCH_NONE) {
                    branch_fired = true;
                } else if (last_local >= 1 &&
                           bb_fields[last_local - 1]->branch_type
                               != BRANCH_NONE) {
                    /* Delay-slot tail [branch, delay-slot] in true
                     * execution order: the just-appended delay slot
                     * completes the BB whose terminating branch is the
                     * prior insn.  (On non-delay-slot ISAs the branch is
                     * always the last insn, handled above.) */
                    branch_fired = true;
                }
            }
            bool bb_complete = false;
            if (awaiting_delay_slot) {
                awaiting_delay_slot = false;
                bb_complete = true;
            } else if (branch_fired) {
                if (cur->terminus == TB_TERMINUS_BARE_BRANCH) {
                    awaiting_delay_slot = true;
                } else {
                    bb_complete = true;
                }
            }

            if (cur_is_fault_fragment) {
                WpStep fs = wp_handle_fault_fragment(
                    st, cur, n_executed_in_cur, last_insn_size,
                    branch_fired, fault_direct_match, bb_complete,
                    fault_redispatch_pc);
                if (fs == WpStep::BREAK_WALK) {
                    break;
                }
            }

            if (!bb_complete) {
                if (stop_after_this) {
                    walk_done = true;
                }
                continue;
            }

            uint64_t commit_post_pc;
            wp_commit_bb(st, cur, n_executed_in_cur, last_insn_size,
                         fault_redispatch_pc, commit_post_pc);

            acc.clear();

            /*
             * No synchronous exception ends the excursion here.  Memory faults
             * run on a deterministic placeholder; execution-time arithmetic,
             * illegal-instruction and trap faults skip the faulting insn; and
             * a syscall-class kernel entry continues at its architectural
             * fall-through.  All three carry CST_WP_EVENT_FAULT at
             * fault_insn_index so the consumer knows where speculation would
             * have squashed, and all three run on to the depth budget.
             */
            if (poisoned_targets.count(commit_post_pc)) {
                early_exit = true;
                walk_done = true;
                break;
            }

            if (stop_after_this) {
                walk_done = true;
            }
        }

        if (!tb_ok && !fault_consumed && !walk_done) {
            /* Fault PC truly outside the TB.  Give up the chain
             * rather than guess; this is a real abnormal exit
             * (e.g. translation-unavailable cousin). */
            acc.clear();
            bb_reg_snaps.clear();
            early_exit = true;
            return;
        }
}

std::vector<WPBBEntry> simulate_wrong_path_ext(uint64_t branch_pc,
                                               uint64_t correct_target,
                                               uint64_t wrong_target,
                                               unsigned int cpu_index,
                                               bool *flush_interrupted,
                                               bool *first_tb_unavail)
{
    (void)correct_target;

    /* All loop-carried, per-iteration and per-excursion context lives in one
     * WpWalkState.  Each phase of the walk is a helper taking WpWalkState &
     * (wp_check_forward_progress / wp_exec_one_tb / wp_walk_fragments and the
     * leaves those call); the same-name references below keep the driver's
     * few remaining statements reading the accumulator verbatim (the
     * auto &bb_pcs = acc.bb_pcs; pattern). */
    WpWalkState st;
    st.cpu_index         = cpu_index;
    st.wrong_target      = wrong_target;
    st.flush_interrupted = flush_interrupted;
    st.first_tb_unavail  = first_tb_unavail;

    /*
     * Privilege domain the excursion speculates in: the launching correct-path
     * context's, fixed by branch_pc's VA class.  Spec mode redirects only PC
     * and sandboxes memory — it never writes the paging/privilege registers —
     * so the architectural VA classifier (qemu_plugin_vaddr_is_kernel) reports
     * the same kernel/user split for every fetch on the walk.  A wrong-path
     * fetch that lands in the OTHER domain is SMEP/PXN-forbidden on real
     * hardware and terminates the excursion (see the loop body).
     */
    st.excursion_is_kernel = cst_va_is_kernel_code(branch_pc);
    /* Set true if a tb_flush unwound a spec-mode exec_tb before its guest
     * insn ran (last_executed_tb stayed null while the flush count moved).
     * The caller cleanly re-runs the whole WP in the now-fresh code cache
     * — re-running across the flush IN-PLACE would execute wrong-path code
     * after the flush dropped its translation, unsandboxed; restarting a
     * fresh spec session avoids that. */
    *flush_interrupted = false;
    /* Set true only by the genuine-null empty-chain arm below (the one
     * that bumps wp_first_tb_unavail): the wrong path's FIRST target
     * could not be fetched/translated, so the returned chain is empty
     * and there is no WPBBEntry to carry the truncation marker.  The
     * emitter reads this and writes the chain-level
     * CST_WP_EVENT_TRANSLATION_UNAVAIL event instead.  Saved-state
     * failure, fault-loop exits, and flush interruption do NOT set it. */
    *first_tb_unavail = false;

    /* Cache the per-thread Stats ref once: g_stats expands to a
     * thread_stats_get()/__tls_get_addr call, ~1% of total time from
     * this function alone (10+ bumps per WP chain).  Named "stats" to
     * avoid shadowing inner `s` loop indices. */
    st.stats = &thread_stats_get();
    st.hist  = g_current_hist_bucket;
    Stats &stats = *st.stats;
    Stats *hist = st.hist;

    st.initial_insn_cap = max_wrong_path_depth > 16
        ? (unsigned int)max_wrong_path_depth : 16;
    unsigned int initial_insn_cap = st.initial_insn_cap;
    auto &wp_chain = st.chain;
    wp_chain.reserve(initial_insn_cap);
    auto &sim_insns = st.sim_insns;
    auto &early_exit = st.early_exit;
    /* A POST-COMPLETION system-mode wrong-path fault (an SVC/ECALL kernel-entry
     * that failed out of spec mode) committed its BB with the synthetic-fault
     * marker and the excursion is ending cleanly at that block — the interim
     * graceful-stop.  Execution-time arithmetic / illegal / trap faults do NOT
     * set this: they skip the faulting insn and continue to the budget.
     * Distinct from early_exit (an abnormal drop): the chain so far is honest
     * and terminated on a marked fault, not truncated. */
    /* last_fault_pc / repeated_fault_pc / awaiting_delay_slot live in st,
     * owned by the fault / walk phases. */

    /*
     * OPEN THE EXCURSION WINDOW BEFORE TAKING THE SNAPSHOT.  The order of
     * these two calls is load-bearing, not stylistic.
     *
     * The register snapshot is what the excursion is rolled back to, and
     * env-resident pending-interrupt state rides inside it (riscv env->mip is
     * the whole storage for a pending machine software interrupt — the ACLINT
     * keeps no latch of its own).  A device raise that lands inside the
     * excursion is NOT speculative and must survive the rollback, so the
     * target records externally-caused raises for replay; the record is gated
     * on the excursion being open, and vtime_pause is what opens it (it sets
     * plugin_spec_vtime_paused, under the BQL that the raiser also holds).
     *
     * Taking the snapshot first leaves a window between the snapshot and that
     * flag in which a raise is captured by NEITHER: not by the snapshot (it
     * was already taken) and not by the record (the window is not open yet).
     * The restore then erases it.  For MIP_MSIP that is unrecoverable — OpenSBI
     * writes the ACLINT MSIP only right after a successful rfence enqueue and
     * never re-raises, so the target hart sleeps in wfi forever with the
     * request queued and the sender spins on `outstanding` — a guest deadlock.
     *
     * Pausing first closes the window with nothing left over: the replay is a
     * bitmask OR, so a raise landing between the flag and the snapshot lands in
     * BOTH, and applying it twice is idempotent.
     */
    qemu_plugin_spec_vtime_pause();

    struct qemu_plugin_cpu_state *saved_state = qemu_plugin_cpu_state_save();
    if (!saved_state) {
        /* Close the window again: no excursion is going to run. */
        qemu_plugin_spec_vtime_resume();
        stats.wp_early_exits++;
        stats.wp_simulations++;
        if (hist) {
            hist->wp_early_exits++;
            hist->wp_simulations++;
        }
        return wp_chain;
    }

    wp_enter_spec_session(cpu_index, wrong_target, saved_state);

    /*
     * Per-insn accumulator for the BB being built.  Each exec_tb runs a
     * multi-insn wrong-path TB up to its branch terminator — CF_SINGLE_STEP
     * bounds rep-string ops to one iteration per exec_tb, it does NOT limit
     * the TB to a single instruction — and a fault or partial run can stop
     * inside it.  The fragment walk below accumulates exactly the insns that
     * executed (post_pc matching) into raw arrays and commits a true BB at
     * each branch fire via commit_true_bb_refs().
     */
    auto &acc = st.acc;
    /* Same-name references keep the walk body below verbatim. */
    auto &bb_pcs             = acc.bb_pcs;
    auto &bb_sizes           = acc.bb_sizes;
    auto &bb_bytes           = acc.bb_bytes;
    auto &bb_fields          = acc.bb_fields;
    auto &bb_regnames        = acc.bb_regnames;
    auto &bb_dyn_params      = acc.bb_dyn_params;
    auto &bb_reg_snaps       = acc.bb_reg_snaps;
    auto &bb_start_pc        = acc.bb_start_pc;
    /* bb_symbol_name / bb_has_fault / bb_first_fault_idx live in st.acc,
     * owned by the walk / memop / fault / commit phases. */
    /* Stable zeroed sentinel for the rare reg-data-on-but-template-has-no-
     * regnames case (keeps a valid pointer to push). */
    bb_pcs.reserve(initial_insn_cap);
    bb_sizes.reserve(initial_insn_cap);
    bb_bytes.reserve(initial_insn_cap * MAX_INSN_BYTES);
    bb_fields.reserve(initial_insn_cap);
    bb_dyn_params.reserve(initial_insn_cap);
    if (g_features.reg_data) {
        bb_regnames.reserve(initial_insn_cap);
    }
    if (g_features.wp_reg_data) {
        bb_reg_snaps.reserve((size_t)initial_insn_cap * MAX_SRC_REGS);
    }

    /* No-forward-progress detection: a same-PC repeat with no memop
     * growth is a stuck excursion; bail after two (see the stuck-PC
     * handler below).  prev_mem_size tracks the spec memop count to
     * tell a stuck loop from a legitimately-advancing rep-string.
     * prev_pre_pc / same_pre_pc_count / wp_noprogress_count / prev_mem_size
     * live in st and are owned by wp_check_forward_progress now. */
    st.prev_mem_size = g_wp_state.mem_accesses.size();
    /* Per-iteration scratch reset at the iteration top below; the rest
     * (tb_ok / post_pc_now / fault_consumed / walk_done / wp_snap_cursor)
     * live in st and are owned by wp_exec_one_tb / wp_walk_fragments. */
    auto &pre_pc = st.pre_pc;
    auto &mem_start_idx = st.mem_start_idx;
    auto &tmpl = st.tmpl;
    /*
     * WP-walk driver.  Each outer iteration runs the phase pipeline over one
     * speculative step and dispatches on the WpStep each phase returns:
     * NEXT_ITER retries the iteration, PROCEED advances to the next phase,
     * and any terminal reason has already latched st.early_exit
     * so the tail break ends the excursion.  This compact dispatch is the
     * SealedBB -> simulate_wrong_path seam a future WpScheduler (task #92)
     * slots into.
     *
     *   wp_check_forward_progress  poison / stuck / rep-overrun / domain-cross
     *   wp_exec_one_tb             one spec exec_tb + null/flush/wild-store
     *   wp_walk_fragments          per-fragment append / memops / fault / commit
     */
    while (sim_insns < (uint64_t)max_wrong_path_depth ||
           !bb_pcs.empty()) {
        pre_pc = qemu_plugin_get_pc();
        cst_ring_push('W', pre_pc);  /* #77 ring (gated) */
        mem_start_idx = g_wp_state.mem_accesses.size();
        tmpl = nullptr;

        WpStep fp = wp_check_forward_progress(st);
        if (fp == WpStep::NEXT_ITER) {
            continue;
        }
        if (fp != WpStep::PROCEED) {
            /* STUCK_BAIL / DOMAIN_CROSS: the guard already dropped the
             * accumulator and latched early_exit — end the excursion. */
            break;
        }

        if (bb_pcs.empty()) {
            bb_start_pc = pre_pc;
        }

        WpStep ex = wp_exec_one_tb(st);
        if (ex != WpStep::PROCEED) {
            /* RETRY_SESSION / TRANSLATION_UNAVAIL / STUCK_BAIL: the exec
             * phase already dropped the accumulator and latched early_exit
             * (and, for a flush, *flush_interrupted). */
            break;
        }

        wp_walk_fragments(st);

        if (early_exit) {
            break;
        }
    }

    wp_end_spec_session(cpu_index, saved_state);

    stats.wp_simulations++;
    stats.wp_total_insns += sim_insns;
    if (early_exit) {
        stats.wp_early_exits++;
    }
    if (hist) {
        hist->wp_simulations++;
        hist->wp_total_insns += sim_insns;
        if (early_exit) {
            hist->wp_early_exits++;
        }
    }

    return std::move(wp_chain);
}
