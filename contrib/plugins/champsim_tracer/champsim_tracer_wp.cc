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
 * Execute wrong-path basic blocks starting from @wrong_target.
 *
 * Per iteration: exec one TB via qemu_plugin_exec_tb() (triggers
 * vcpu_tb_trans + vcpu_mem_cb, not vcpu_tb_exec/inline stores), look up
 * its template, build a WPBBEntry, pick next PC, repeat until depth or
 * fault.  Returns the WPBBEntry chain by value (callers move it into
 * BodyEntry::wp_entries).
 */
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

    g_wp_state.saved_cpu_index = cpu_index;
    g_wp_state.saved_insn_count = qemu_plugin_u64_get(g_scoreboard.insn_count, cpu_index);
    g_wp_state.saved_prev_start_pc = qemu_plugin_u64_get(g_scoreboard.prev_start_pc, cpu_index);
    g_wp_state.saved_prev_fall_through = qemu_plugin_u64_get(g_scoreboard.prev_fall_through,
                                                     cpu_index);
    g_wp_state.saved_budget = qemu_plugin_u64_get(g_scoreboard.budget, cpu_index);
    g_wp_state.in_progress = true;

    /* Freeze the guest virtual clock for the whole excursion (system mode):
     * the speculative run burns host wall-clock time but is outside guest
     * time, so it must not advance the guest's architected timer counters.
     * Paused here at the outer boundary — not in spec_mode_begin — so a
     * fault-skip's spec_mode teardown/re-entry does not leak ticks.  No-op
     * in user mode. */
    qemu_plugin_spec_vtime_pause();
    qemu_plugin_spec_mode_begin(saved_state);
    qemu_plugin_set_pc(wrong_target);
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
    g_wp_state.in_progress = false;

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

std::vector<WPBBEntry> simulate_wrong_path_ext(uint64_t branch_pc,
                                               uint64_t correct_target,
                                               uint64_t wrong_target,
                                               unsigned int cpu_index,
                                               bool *flush_interrupted)
{
    (void)branch_pc;
    (void)correct_target;
    /* Set true if a tb_flush unwound a spec-mode exec_tb before its guest
     * insn ran (last_executed_tb stayed null while the flush count moved).
     * The caller cleanly re-runs the whole WP in the now-fresh code cache
     * — re-running across the flush IN-PLACE would execute wrong-path code
     * after the flush dropped its translation, unsandboxed; restarting a
     * fresh spec session avoids that. */
    *flush_interrupted = false;

    /* Cache the per-thread Stats ref once: g_stats expands to a
     * thread_stats_get()/__tls_get_addr call, ~1% of total time from
     * this function alone (10+ bumps per WP chain).  Named "stats" to
     * avoid shadowing inner `s` loop indices. */
    Stats &stats = thread_stats_get();
    Stats *hist = g_current_hist_bucket;

    unsigned int initial_insn_cap = max_wrong_path_depth > 16
        ? (unsigned int)max_wrong_path_depth : 16;
    std::vector<WPBBEntry> wp_chain;
    wp_chain.reserve(initial_insn_cap);
    std::unordered_set<uint64_t> poisoned_targets;
    uint64_t sim_insns = 0;
    bool early_exit = false;
    uint64_t last_fault_pc = UINT64_MAX;
    unsigned int repeated_fault_pc = 0;
    /* Set when the previously appended TB ended with a bare delay-
     * slot branch (TB_TERMINUS_BARE_BRANCH): its delay slot lives in
     * the NEXT TB, so the BB is not yet complete.  Cleared when the
     * next TB is appended, signalling the BB-complete commit. */
    bool awaiting_delay_slot = false;

    struct qemu_plugin_cpu_state *saved_state = qemu_plugin_cpu_state_save();
    if (!saved_state) {
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
    WpAccum acc;
    /* Same-name references keep the walk body below verbatim. */
    auto &bb_pcs             = acc.bb_pcs;
    auto &bb_sizes           = acc.bb_sizes;
    auto &bb_bytes           = acc.bb_bytes;
    auto &bb_fields          = acc.bb_fields;
    auto &bb_regnames        = acc.bb_regnames;
    auto &bb_dyn_params      = acc.bb_dyn_params;
    auto &bb_reg_snaps       = acc.bb_reg_snaps;
    auto &bb_start_pc        = acc.bb_start_pc;
    auto &bb_symbol_name     = acc.bb_symbol_name;
    auto &bb_has_fault       = acc.bb_has_fault;
    auto &bb_first_fault_idx = acc.bb_first_fault_idx;
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

    uint64_t prev_pre_pc = UINT64_MAX;
    uint32_t same_pre_pc_count = 0;
    /* No-forward-progress detection: a same-PC repeat with no memop
     * growth is a stuck excursion; bail after two (see the stuck-PC
     * handler below).  prev_mem_size tracks the spec memop count to
     * tell a stuck loop from a legitimately-advancing rep-string. */
    uint32_t wp_noprogress_count = 0;
    size_t   prev_mem_size = g_wp_state.mem_accesses.size();
    while (sim_insns < (uint64_t)max_wrong_path_depth ||
           !bb_pcs.empty()) {
        uint64_t pre_pc = qemu_plugin_get_pc();
        cst_ring_push('W', pre_pc);  /* #77 ring (gated) */
        size_t mem_start_idx = g_wp_state.mem_accesses.size();
        BBTemplate *tmpl = nullptr;
        bool tb_ok;

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
            break;
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
             * CST_FID_SLOT_COUNT (64) threshold each wasted ~64 steps,
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
                    break;
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
            continue;
        }

        if (poisoned_targets.count(pre_pc)) {
            early_exit = true;
            break;
        }

        if (bb_pcs.empty()) {
            bb_start_pc = pre_pc;
        }

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
        uint64_t flush_before =
            g_tb_flush_count.load(std::memory_order_acquire);
        tb_ok = qemu_plugin_exec_tb();
        tmpl = g_wp_state.last_executed_tb;

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
            }
            acc.clear();
            bb_reg_snaps.clear();
            early_exit = true;
            break;
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
            break;
        }

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
        uint64_t post_pc_now = qemu_plugin_get_pc();
        bool fault_consumed = false;
        bool walk_done = false;
        /* Cursor into wp_pending_reg_snaps, advanced as the walk
         * consumes per-insn snaps in execution order across all
         * fragments executed in this exec_tb.  Bumped by every insn
         * the callback captured (i.e., every executed insn except the
         * last of each fragment), whether or not WP appends that insn
         * after dedup. */
        size_t wp_snap_cursor = 0;

        for (BBTemplate *cur = tmpl; cur != nullptr && !walk_done;
             cur = cur->next_tb_fragment) {
            uint32_t n_executed_in_cur = cur->n_insns;
            bool stop_after_this = false;
            bool cur_is_fault_fragment = false;

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
                DynParam dp = {
                    .type = (uint8_t)(acc.is_store ? DYN_STORE_ADDR
                                                    : DYN_LOAD_ADDR),
                    .insn_index = insn_idx,
                    .value = acc.mem_vaddr,
                    .data_size = acc.data_size,
                    .data = acc.data,
                };
                bb_dyn_params.push_back(dp);
                stats.wp_total_mem_accesses++;
                if (hist) {
                    hist->wp_total_mem_accesses++;
                }
            }

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
                /* Trace past the fault.  bb_pcs has insns 0..fault for
                 * this fragment.  Mark fault metadata for the BB
                 * committed at the natural branch end; if the faulting
                 * insn IS the branch terminator (e.g. faulting
                 * BRANCH_SYSCALL_TYPE), branch_fired catches it and
                 * the normal commit path handles bb_has_fault. */
                uint64_t fault_pc = post_pc_now;

                if (pre_pc == last_fault_pc) {
                    repeated_fault_pc++;
                } else {
                    repeated_fault_pc = 0;
                    last_fault_pc = pre_pc;
                }

                if (!bb_has_fault) {
                    bb_has_fault = true;
                    bb_first_fault_idx = bb_pcs.empty()
                        ? 0 : (uint32_t)(bb_pcs.size() - 1);
                }

                poisoned_targets.insert(fault_pc);

                /* Don't force-commit a BARE_BRANCH fragment that
                 * faulted: its delay slot is in the next QEMU TB and
                 * never landed here, so a commit now would write the
                 * wrong (n-1 insns, no delay slot) shape into bb_map_
                 * and collide with the natural full-BB shape from the
                 * non-fault path.  Fall through to the skip-past-fault
                 * branch so the next iter can re-attempt landing the
                 * delay slot from skip_pc. */
                bool bare_branch_pending = branch_fired &&
                    cur->terminus == TB_TERMINUS_BARE_BRANCH;

                if ((branch_fired || bb_complete) && !bare_branch_pending) {
                    /* Force bb_complete so the post-fault commit fires
                     * even when only the branch (no delay slot) ran. */
                    bb_complete = true;
                    awaiting_delay_slot = false;
                } else {
                    if (repeated_fault_pc >= 16) {
                        early_exit = true;
                        walk_done = true;
                        break;
                    }
                    uint64_t skip_pc = fault_pc + last_insn_size;
                    if (poisoned_targets.count(skip_pc)) {
                        early_exit = true;
                        walk_done = true;
                        break;
                    }
                    qemu_plugin_spec_mode_end();
                    qemu_plugin_cpu_state_restore(saved_state);
                    qemu_plugin_spec_mode_begin(saved_state);
                    qemu_plugin_set_pc(skip_pc);
                    /* Skip the rest of this exec_tb's fragments and
                     * resume the outer iter from skip_pc. */
                    walk_done = true;
                    /* `continue` would go to the next fragment; we
                     * want to break out of the fragment loop and let
                     * the outer iter `continue` semantic apply.  The
                     * outer loop's per-iter setup re-reads pre_pc. */
                    break;
                }
            }

            if (!bb_complete) {
                if (stop_after_this) {
                    walk_done = true;
                }
                continue;
            }

            /* Branch fired: commit completed BB.  Still a true
             * branch-bounded BB (basic_block.md), so it goes into
             * bb_map_ unconditionally; bb_has_fault carries any
             * earlier in-BB fault and the WPBBEntry's fault flag
             * tells the consumer speculation would have squashed at
             * fault_insn_index. */
            uint64_t commit_post_pc;
            if (cur->next_tb_fragment) {
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
            BBTemplate *bb_tmpl = g_bb_template_cache.commit_true_bb_refs(
                bb_start_pc, (uint32_t)bb_pcs.size(),
                bb_pcs.data(),
                bb_fields.data(),
                bb_sizes.data(),
                bb_bytes.data(),
                g_features.reg_data ? bb_regnames.data() : nullptr,
                bb_symbol_name, fall_through);
            /* Privilege seed for WP-only-discovered BBs.  The WP walk
             * can speculate across the privilege boundary, so this is
             * only a guess; a correct-path finalize of the same BB
             * overrides and latches it (see BBTemplate::is_system). */
            if (bb_tmpl && !bb_tmpl->is_system_cp_confirmed) {
                bb_tmpl->is_system = cur->is_system;
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

            wp_chain.push_back(acc.make_entry(bb_tmpl,
                                             bb_has_fault,
                                             bb_first_fault_idx));

            acc.clear();

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
            break;
        }
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

    return wp_chain;
}
