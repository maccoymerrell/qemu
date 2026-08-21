/*
 * Wrong-Path Tracing Plugin — human-readable statistics report formatting.
 *
 * Extracted verbatim from champsim_tracer.cc: the append_* helpers that
 * render a Stats aggregate (and an optional per-interval histogram) into
 * the textual report emitted at segment finish and plugin exit.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <algorithm>
#include <cstddef>
#include <inttypes.h>
#include <tuple>
#include <vector>

#include <glib.h>

#include "champsim_tracer.h"
#include "champsim_tracer_stats.h"
#include "champsim_tracer_stats_report.h"

static void append_branch_breakdown(GString *report, const Stats &stats)
{
    uint64_t cp_total = 0, wp_total = 0;
    for (size_t i = 0; i < BRANCH_TYPE_COUNT; i++) {
        if (i == BRANCH_NONE) continue;
        cp_total += stats.cp_branches_by_type[i];
        wp_total += stats.wp_branches_by_type[i];
    }
    if (cp_total == 0 && wp_total == 0) return;
    g_string_append_printf(report,
        "Branch type breakdown:\n"
        "  %-22s %14s %8s   %14s %8s\n",
        "type", "CP count", "%CP", "WP count", "%WP");
    for (size_t i = 0; i < BRANCH_TYPE_COUNT; i++) {
        if (i == BRANCH_NONE) continue;
        uint64_t cv = stats.cp_branches_by_type[i];
        uint64_t wv = stats.wp_branches_by_type[i];
        if (cv == 0 && wv == 0) continue;
        double cp_pct = cp_total
            ? 100.0 * (double)cv / (double)cp_total : 0.0;
        double wp_pct = wp_total
            ? 100.0 * (double)wv / (double)wp_total : 0.0;
        g_string_append_printf(report,
            "  %-22s %14" PRIu64 " %7.2f%%   %14" PRIu64 " %7.2f%%\n",
            branch_type_name_or_unknown((unsigned)i),
            cv, cp_pct, wv, wp_pct);
    }
}

/*
 * THE UNSEALED-AT-CLOSE BOUND, as measured by this run.
 *
 * The peak is per CLOSE, so it cannot come from the summed Stats
 * aggregate (see the ledger in champsim_tracer_stats.h); it is read from
 * the ledger's own record, together with the bounded sample of individual
 * blocks.  The sample is what turns a number into an account: each row
 * names the vCPU and guest thread that was standing inside the block, the
 * block itself, and the close ROUTE that stopped it — which is the only
 * thing that distinguishes a terminal event the guest cannot run past
 * (SHUTDOWN, RESET, the process exiting) from a stopping point where the
 * policy says keep dispatching until the block seals (END, BUDGET,
 * CEILING).
 *
 * Printed whenever anything was recorded, or whenever the falsifier arm
 * was on, so a run that legitimately leaves nothing unsealed prints
 * nothing here and its zero is read off the counter rows above.
 */
static void append_unsealed_at_close(GString *report)
{
    const CloseUnsealedSummary s = close_unsealed_summary();
    const std::vector<CloseUnsealedRow> &rows = close_unsealed_rows();
    if (s.blocks == 0 && !s.falsified) {
        return;
    }
    g_string_append_printf(report,
        "Unsealed true-BBs at a close%s:\n"
        "  closes observed              %14" PRIu64 "\n"
        "  closes leaving one unsealed  %14" PRIu64 "\n"
        "  unsealed blocks (all closes) %14" PRIu64 "\n"
        "  PEAK blocks at one close     %14" PRIu64 "\n"
        "  PEAK contexts at one close   %14" PRIu64 "  (close #%" PRIu64
        ", %s)\n",
        s.falsified ? "  [CST_UNSEALED_FALSIFY — NOT A MEASUREMENT]" : "",
        s.closes, s.closes_with, s.blocks, s.peak_blocks, s.peak_contexts,
        s.peak_close_seq, s.peak_reason ? s.peak_reason : "-");
    if (s.rows_dropped) {
        g_string_append_printf(report,
            "  sample rows past the cap     %14" PRIu64 "\n",
            s.rows_dropped);
    }
    if (rows.empty()) {
        return;
    }
    g_string_append_printf(report,
        "  %-6s %-10s %5s %8s %-18s %6s %-8s %s\n",
        "close", "route", "vcpu", "thread", "entry_pc", "insns", "priv",
        "shape");
    for (const CloseUnsealedRow &r : rows) {
        g_string_append_printf(report,
            "  %-6" PRIu64 " %-10s %5u %8u 0x%-16" PRIx64 " %6u %-8s %s\n",
            r.close_seq, r.reason ? r.reason : "-", r.cpu_index,
            r.thread_id, r.entry_pc, r.n_insns,
            r.is_system ? "system" : "user",
            r.shape == CST_UNSEALED_CUT_FRAG ? "cut-mid-TB" : "tb-edge");
    }
}

/* Generic opcode breakdown, CP and WP side-by-side.  Sorted by
 * (CP+WP) total so the busiest opcodes come first regardless of
 * which path drives them. */
static void append_opcode_breakdown(GString *report, const Stats &stats)
{
    uint64_t cp_total = 0, wp_total = 0;
    for (size_t i = 0; i < GEN_OP_COUNT; i++) {
        cp_total += stats.cp_insns_by_opcode[i];
        wp_total += stats.wp_insns_by_opcode[i];
    }
    if (cp_total == 0 && wp_total == 0) return;
    std::vector<std::tuple<uint64_t, uint8_t>> rows;
    for (size_t i = 0; i < GEN_OP_COUNT; i++) {
        uint64_t s = stats.cp_insns_by_opcode[i] +
                     stats.wp_insns_by_opcode[i];
        if (s) rows.emplace_back(s, (uint8_t)i);
    }
    std::sort(rows.begin(), rows.end(),
              std::greater<std::tuple<uint64_t, uint8_t>>());
    g_string_append_printf(report,
        "Generic opcode breakdown (%zu non-zero):\n"
        "  %-20s %14s %8s   %14s %8s\n",
        rows.size(), "opcode", "CP count", "%CP", "WP count", "%WP");
    for (const auto &r : rows) {
        uint8_t op = std::get<1>(r);
        uint64_t cv = stats.cp_insns_by_opcode[op];
        uint64_t wv = stats.wp_insns_by_opcode[op];
        double cp_pct = cp_total
            ? 100.0 * (double)cv / (double)cp_total : 0.0;
        double wp_pct = wp_total
            ? 100.0 * (double)wv / (double)wp_total : 0.0;
        g_string_append_printf(report,
            "  %-20s %14" PRIu64 " %7.2f%%   %14" PRIu64 " %7.2f%%\n",
            generic_opcode_name_or_unknown((unsigned)op),
            cv, cp_pct, wv, wp_pct);
    }
}

void append_stats_summary(GString *report, const char *label,
                                 const Stats &stats)
{
    const struct { const char *name; uint64_t value; } counters[] = {
        { "SMC revisions minted",                stats.smc_revisions_minted },
        { "SMC revision id reuses",              stats.smc_revision_reuses },
        { "SMC revision overflow events",        stats.smc_overflow_events },
        { "SMC revision overflow PCs",           stats.smc_overflow_pcs },
        { "SMC extent-only artifacts",           stats.smc_extent_artifacts },
        { "Branch transitions observed",         stats.branches_observed },
        { "  Taken",                             stats.branches_taken },
        { "  Not-taken",                         stats.branches_not_taken },
        { "CP total memory accesses",            stats.cp_total_mem_accesses },
        { "CP orphan memops dropped",            stats.cp_orphan_mem_accesses },
        { "CP impossible-slot memops",           stats.cp_impossible_slot_memops },
        { "Memops over slot ceiling",            stats.memops_over_slot_ceiling },
        { "CP reg-snap slice dropped",           stats.reg_snap_slice_dropped },
        { "  of which at end-marker close",
                                                stats.reg_snap_slice_dropped_end_close },
        { "  reg deltas discarded by those drops",
                                                stats.reg_snap_slice_drop_discarded },
        { "CP reg-snap leak trimmed",            stats.reg_snap_leak_trimmed },
        { "CP chains dropped on discontinuity",  stats.reg_snap_chain_drops },
        { "CP reg-snaps dropped with the chain",
                                                stats.reg_snap_chain_drop_discarded },
        { "  insns lost with those chains",      stats.reg_snap_chain_drop_insns },
        { "    of them user",                   stats.reg_snap_chain_drop_user_insns },
        { "    of them kernel",                 stats.reg_snap_chain_drop_sys_insns },
        { "CP blocks sealed where control left them", stats.cut_blocks_sealed },
        { "  insns they carried",               stats.cut_block_insns },
        { "    of them user",                   stats.cut_block_user_insns },
        { "    of them kernel",                 stats.cut_block_sys_insns },
        { "  excluded by faults=0",             stats.cut_blocks_excluded },
        { "  >1 in one seal walk (must be 0)",   stats.cut_blocks_multi_per_walk },
        { "CP chains dropped in the close walk", stats.reg_snap_chain_drops_flush },
        { "  reg-snaps orphaned by those",
                                                stats.reg_snap_chain_flush_orphaned },
        { "  insns lost with those chains",      stats.reg_snap_chain_flush_insns },
        { "CP chains destroyed by reset",        stats.reg_snap_chain_reset_drops },
        { "  fragments lost with them",          stats.reg_snap_chain_reset_frags },
        { "  insns lost with them",              stats.reg_snap_chain_reset_insns },
        { "    of them user",                    stats.reg_snap_chain_reset_user_insns },
        { "    of them kernel",                  stats.reg_snap_chain_reset_sys_insns },
        { "    entry pc of the first such chain", stats.reg_snap_chain_reset_first_pc },
        { "fault fold kept a continuing prefix",  stats.fold_prev_prefix_kept },
        { "  insns it would have dropped",        stats.fold_prev_prefix_kept_insns },
        { "fault fold destroyed a discontinuous chain (must be 0)",
                                                  stats.fold_prev_prefix_discontinuous },
        { "  insns lost with it",                 stats.fold_prev_prefix_discontinuous_insns },
        { "fault fold met a translation-cut head", stats.fold_prev_head_incomplete },
        { "  completed from the cached whole block",
                                                  stats.fold_prev_whole_substituted },
        { "  carried as cut frames (prefix completed)",
                                                  stats.fold_prev_cut_frames },
        { "  suffix insns published whole at their merge",
                                                  stats.merge_cut_frame_suffix_insns },
        { "merge suffix overhung its frame (must be 0)",
                                                  stats.merge_suffix_overhang },
        { "user insns billed to window clock",   stats.user_clock_billed_insns },
        { "  TBs billed",                        stats.user_clock_billed_tbs },
        { "  bills not equal to the billed TB",  stats.user_clock_bill_mismatch_tbs },
        { "  excess insns in those bills",       stats.user_clock_bill_excess_insns },
        { "  bills with no template",            stats.user_clock_bill_no_template },
        { "user insns actually executed",        stats.user_clock_retired_insns },
        { "  retired folds above their TB (must be 0)",
                                                 stats.user_clock_retired_over_tb },
        { "  insns in those folds",              stats.user_clock_retired_over_insns },
        { "  re-credited: faults re-executing",  stats.user_clock_fault_recredits },
        { "    insns re-credited",               stats.user_clock_fault_recredit_insns },
        { "    resume pc not in the attempt",
                                                 stats.user_clock_fault_recredit_unplaced },
        { "    attempt had no measured extent",
                                                 stats.user_clock_fault_recredit_unmeasured },
        { "  re-credited: rewound, no exception",
                                                 stats.user_clock_abort_recredits },
        { "    insns re-credited",               stats.user_clock_abort_recredit_insns },
        { "  close credits: unfolded slots billed at their published extent",
                                                 stats.user_clock_close_credits },
        { "    insns credited",                  stats.user_clock_close_credit_insns },
        { "user budget close: final entries cut at the remaining budget",
                                                 stats.user_budget_final_partial },
        { "  insns the cut kept off the wire",   stats.user_budget_final_cut_insns },
        { "  entries past the budget not emitted",
                                                 stats.user_budget_entries_suppressed },
        { "    insns in them",                   stats.user_budget_insns_suppressed },
        { "  REP fan-out overran the exact budget (exempt from the cut)",
                                                 stats.user_budget_rep_overrun_insns },
        { "user raw clock: unpublished insns unbilled at the close",
                                                 stats.user_raw_unbilled_insns },
        { "user raw clock: published open-boundary insns billed before the window",
                                                 stats.user_raw_open_prebilled_insns },
        { "close-walk blocks truncated to what ran",
                                                 stats.close_walk_blocks_truncated },
        { "  insns the truncation kept off the wire",
                                                 stats.close_walk_insns_not_executed },
        { "close walks with an unknown extent (must be 0)",
                                                 stats.close_walk_extent_unknown },
        { "user entries emitted under a FOREIGN live address space",
                                                 stats.emit_asid_foreign_context },
        { "peer vCPU seal slots flushed at close",
                                                 stats.close_peer_slots_flushed },
        { "  insns those flushes actually emitted",
                                                 stats.close_peer_insns_recovered },
        { "    of them user",                     stats.close_peer_user_insns_recovered },
        { "  peer slots that emitted nothing",    stats.close_peer_slots_emitted_nothing },
        { "SMP dup: adjacent re-claims of the same instructions (must be 0)",
                                                 stats.smp_dup_adjacent_claims },
        { "SMP dup: CFG-impossible re-emissions one entry later (must be 0)",
                                                 stats.smp_dup_wrongpc_reemit },
        { "  claim-ledger checks performed",      stats.smp_dup_ledger_checks },
        { "  falsifier fires (CST_SMP_DUP_FALSIFY)",
                                                 stats.smp_dup_falsifier_fires },
        { "SMP cond: seals whose successor came from another thread's dispatch",
                                                 stats.smp_seal_cross_thread_succ },
        { "SMP cond: guest-thread migrations between vCPUs",
                                                 stats.smp_thread_migrations },
        { "  of them leaving an unsealed slot behind",
                                                 stats.smp_migrated_holder_pending },
        { "SMP cond: close peer-slot extents from the stash",
                                                 stats.smp_close_peer_stash_extent },
        { "SMP cond: close peer-slot extents from the LIVE cursor",
                                                 stats.smp_close_peer_live_cursor },
        { "  of them the peer's current in-flight head",
                                                 stats.smp_close_peer_inflight_head },
        { "    that peer ran on past the close-time sample",
                                                 stats.smp_close_peer_inflight_drift },
        { "    unobserved insns the snapshot kept off the wire",
                                                 stats.smp_close_peer_inflight_drift_insns },
        { "SMP migrated holders drained at the thread's next promote",
                                                 stats.smp_migrated_holders_drained },
        { "  insns those drains published",       stats.smp_migrated_holder_insns },
        { "  drains with no answerable extent (must be 0)",
                                                 stats.smp_migrate_drain_extent_unknown },
        { "SMP close THREAD_END stamp mispredictions",
                                                 stats.smp_close_stamp_mispredict },
        { "seal-walk blocks truncated to what ran",
                                                 stats.seal_walk_blocks_truncated },
        { "  insns the truncation kept off the wire",
                                                 stats.seal_walk_insns_not_executed },
        { "  of them a rewound instruction re-executed later",
                                                 stats.seal_walk_aborted_tails },
        { "seal walks with an unknown extent (must be 0)",
                                                 stats.seal_walk_extent_unknown },
        { "  extent taken from the deferred-step measurement",
                                                 stats.seal_walk_extent_from_stash },
        { "  of them resumed INSIDE the folded block (must be 0)",
                                                 stats.seal_walk_extent_unknown_interior },
        { "    insns that fold over-claimed",
                                                 stats.seal_walk_extent_unknown_interior_insns },
        { "  interior-PC probe hits where the extent WAS known",
                                                 stats.seal_walk_interior_probe_hits },
        { "cut-short block templates minted",    stats.partial_bb_templates_created },
        { "  mid-run extent-only mints (block WAS sealed)",
                                                 stats.extent_only_mints },
        { "  mid-run fault-cut head prefixes",   stats.fault_cut_head_prefixes },
        { "unsealed true-BBs sealed at a close",  stats.close_unsealed_blocks },
        { "  the extent cut a fragment mid-TB",  stats.close_unsealed_cut_frag },
        { "  the chain was open at a TB edge",   stats.close_unsealed_tb_edge },
        { "unsealed blocks sealed at a DEPARTURE (not a close)",
                                                 stats.departure_unsealed_blocks },
        { "closes that left a true-BB unsealed", stats.close_unsealed_closes },
        { "  contributing (vCPU,thread) contexts, summed",
                                                 stats.close_unsealed_contexts },
        { "user insns attributed at the seal",   stats.cp_user_seal_insns },
        { "user insns emitted to the wire",      stats.wire_user_arch_insns },
        { "  of them self-loop fan-out surplus", stats.wire_user_rep_extra_insns },
        { "REP iters from arch state",           stats.rep_iters_architectural },
        { "REP iters inferred from memops",      stats.rep_iters_inferred },
        { "REP iters/memop mismatch",            stats.rep_iters_memop_mismatch },
        { "REP fan-out reg snaps reconstructed (iters)",
                                                 stats.rep_fanout_reg_iters_reconstructed },
        { "REP fan-out reg slots underived",     stats.rep_fanout_reg_slots_underived },
        { "REP piece table degenerate",          stats.rep_piece_table_degenerate },
        { "window close in fan-out",             stats.window_close_in_fanout },
        { "window close fan-out hold capped",    stats.window_close_fanout_hold_capped },
        { "deferred-close THREAD_END stamped at the seal",
                                                 stats.close_thread_end_stamped_at_seal },
        { "deferred-close THREAD_END missed",    stats.close_thread_end_missed },
        { "warmup boundary hold defers",         stats.warmup_boundary_hold_defers },
        { "warmup boundary unplaced at finish",  stats.warmup_boundary_unplaced_at_finish },
        { "warmup boundary in fan-out",          stats.warmup_boundary_in_fanout },
        { "marker gate refreshes",               stats.marker_gate_refresh_events },
        /* Predicate: prior gate bit set + same live root as the carried
         * last-GATED label + marker bytes unreadable = the marked process
         * lost its marker page.  Foreign mm's land in NOT traced alone. */
        { "gated context lost marker page residency (must be 0)",
                                                stats.marker_page_unreadable_at_refresh },
        { "gate refresh evaluated NOT traced",   stats.refresh_evaluated_not_traced },
        { "marker END in an ungated context",    stats.marker_end_no_close },
        { "marker END forced close (unattributed)", stats.marker_end_forced_close },
        { "WP session flag on correct path (must be 0)", stats.wp_session_on_cp },
        { "user clock worst stall (arch insns)", stats.user_clock_worst_stall },
        { "stall ceiling closes",                stats.stall_ceiling_closes },
        { "user clock worst stall, any context", stats.user_clock_worst_stall_any },
        { "any-context stall closes",            stats.stall_any_closes },
        { "dead-latch closes (wall clock)",      stats.dead_latch_closes_ms },
        { "dead-latch closes (idle insns)",      stats.dead_latch_closes_insns },
        { "closed by machine shutdown",          stats.vm_shutdown_closes },
        { "closed by machine reset",             stats.vm_reset_closes },
        { "REP trailing pass dropped",           stats.rep_trailing_pass_dropped },
        { "REP exit edge recovered",             stats.rep_exit_edge_recovered },
        { "REP clock ticks withheld",            stats.rep_clock_ticks_withheld },
        { "REP unretired pass dropped",          stats.rep_unretired_pass_dropped },
        { "REP unretired pass kept",             stats.rep_unretired_pass_kept },
        { "REP retired iters dropped at a fault (must be 0)",
                                                 stats.rep_split_retired_iters_dropped },
        { "  drop events",                       stats.rep_split_retired_drops },
        { "MOPS bytes checked",                  stats.mops_bytes_checked },
        { "MOPS bytes mismatch",                 stats.mops_bytes_mismatch },
        { "MOPS bytes unchecked",                stats.mops_bytes_unchecked },
        { "REP FF ticks withheld",               stats.rep_ff_ticks_withheld },
        { "WP simulations performed",            stats.wp_simulations },
        { "WP simulations skipped",              stats.wp_skipped },
        { "WP total instructions",               stats.wp_total_insns },
        { "WP total memory accesses",            stats.wp_total_mem_accesses },
        { "WP early exits (fault)",              stats.wp_early_exits },
        { "WP synthetic faults",                 stats.wp_synthetic_faults },
        { "WP last blocks cut at the wpdepth budget",
                                                 stats.wp_budget_cut_blocks },
        { "  insns the cut kept off the wire",   stats.wp_budget_cut_insns },
        { "WP flush re-runs",                    stats.wp_flush_reruns },
        /* Host-side, process-wide: how hard the wrong path leaned on the
         * shared translation buffer.  An OPEN is a walk that filled the
         * buffer and had to be handed the reserve, which costs a full
         * tb_flush the moment it unwinds — the whole correct-path code
         * cache, retranslated, for one excursion.  An EXHAUSTION is a walk
         * the reserve could not hold either: the chain was cut at a depth
         * set by buffer occupancy rather than by anything architectural,
         * and the walker cannot tell that cut from an unfetchable target.
         * The second is an invariant, not a measurement. */
        { "WP spec-reserve opens (cache evicted)",
          qemu_plugin_spec_reserve_opens() },
        { "WP spec-reserve exhausted (must be 0)",
          qemu_plugin_spec_reserve_exhausted() },
        { "WP first-TB unavailable",             stats.wp_first_tb_unavail },
        { "WP chain cut by code-buffer (must be 0)",
                                            stats.wp_xlat_buffer_truncations },
        { "WP resume PC not representable",      stats.wp_pc_not_representable },
        /* Invariant, not a measurement: the wrong path walks past syscalls but
         * never performs one, so this must read 0.  See
         * qemu_plugin_spec_syscall_blocked_count(). */
        { "WP host syscalls blocked (must be 0)",
          qemu_plugin_spec_syscall_blocked_count() },
        { "Unknown-instruction warnings",        stats.unknown_insn_warnings },
        { "DEVIO FIFO kicks dropped (overflow)", stats.devio_fifo_kicks_dropped },
        /* Invariant, not a measurement: a cut says the address space moved
         * away, so it cannot stand while the entry value is loaded. */
        { "thread ids aliased at a kernel entry edge",
                                                stats.tid_task_aliased },
        { "kernel-thread identities minted",     stats.tid_kernel_task_minted },
        { "thread-id alias arms expired unresolved",
                                                stats.tid_alias_expired },
        { "endpoint identity armed (rev3 degenerate case)",
                                                stats.ep_rule_armed },
        { "endpoint identity return endpoints observed",
                                                stats.ep_return_endpoints },
        { "endpoint identity strands minted (user-SP regions)",
                                                stats.ep_strands_minted },
        { "endpoint identity refusals (loud, must accompany stderr)",
                                                stats.ep_refusals },
        { "departure emits (foreign/abandoned)", stats.departure_emits },
        { "departure emit insns",                stats.departure_emit_insns },
        { "departure extent unknown",            stats.departure_extent_unknown },
        { "departure emits from an abandoned async window",
                                                stats.departure_emits_abandoned_async },
        { "post-merge depth re-stamps",          stats.depth_restamp_corrections },
        { "post-merge depth re-stamps >=2 (JUMPs averted)",
                                                stats.depth_restamp_jumps },
        { "post-merge depth re-stamp max delta", stats.depth_restamp_max_delta },
        { "merges whose async level rose across the excursion",
                                                stats.merge_async_level_gained },
        { "merges whose async level fell across the excursion",
                                                stats.merge_async_level_dropped },
        { "merge async decomposition invalid (must be 0)",
                                                stats.merge_async_decomp_invalid },
        { "abandon releases re-stamping an in-hand block",
                                                stats.async_abandon_stamp_stripped },
        { "abandon releases with the owner's merge pending",
                                                stats.async_abandon_merge_pending },
        { "abandon residual >=2 after the release (uncloseable step)",
                                                stats.async_abandon_residual_ge2 },
        { "abandon residual max level after the release",
                                                stats.async_abandon_residual_max },
        { "abandons with no in-hand block to carry the release",
                                                stats.async_abandon_no_carrier },
        { "peer-thread frames disowned at a depth stamp",
                                                stats.depth_tid_foreign_inflight },
        { "depth stamps a peer thread's excursion crossed",
                                                stats.depth_tid_stamps_corrected },
        { "widest peer-thread inheritance averted",
                                                stats.depth_tid_max_foreign },
        { "peer-thread frames spared by the user leak sweep",
                                                stats.depth_tid_sweep_spared },
        { "peer-thread frames spared by a merge unwind",
                                                stats.depth_tid_deeper_spared },
        { "async capture windows opened",        stats.async_captures },
        { "async capture windows re-opened",     stats.async_captures_reopened },
        { "async captures with an unseen owner",
                                                stats.async_capture_owner_unseen },
        { "async windows closed by a return",    stats.async_closed_by_return },
        { "async returns in a peer context",     stats.async_return_peer_ctx },
        { "async windows abandoned by the owner",
                                                stats.async_abandon_owner },
        { "async windows a peer left alone",
                                                stats.async_abandon_peer_spared },
        { "async level stamped for its owner",   stats.async_level_own_stamps },
        { "async level dormant for a peer",      stats.async_level_peer_stamps },
        { "ASID writes inside an async window",
                                                stats.async_asid_write_in_window },
        { "async windows w/ peer stamp + ASID write",
                                                stats.async_win_peer_with_asidw },
        { "async windows w/ peer stamp, no ASID write",
                                                stats.async_win_peer_no_asidw },
        { "faults classified inside a captured window",
                                                stats.fault_enter_classified_in_win },
        { "fault entries skipped as window interior",
                                                stats.fault_enter_skipped_in_async },
        { "user-priv faults kept, window outstanding",
                                                stats.async_interior_user_priv_kept },
        { "kernel-priv faults refused as interior",
                                                stats.async_interior_kernel_refused },
        { "abandoned windows that closed the cursor",
                                                stats.async_abandon_cursor_closed },
        { "evq drain calls",                     stats.evq_drain_calls },
        { "evq drain events",                    stats.evq_drain_events },
        { "evq drain batch peak",                stats.evq_batch_peak },
        { "evq drain icount gap peak",           stats.evq_gap_peak },
        { "evq oversized drains (must be 0)",    stats.evq_bigdrains },
        { "evq absorber calls",                  stats.evq_absorb_calls },
        { "evq absorber events",                 stats.evq_absorb_events },
        { "evq absorber batch peak",             stats.evq_absorb_batch_peak },
        { "evq queue length peak (qemu-side)",   stats.evq_qmax_len },
        { "evq queue pushes (qemu-side)",        stats.evq_q_pushes },
        { "evq queue drains (qemu-side)",        stats.evq_q_drains },
        { "fault frames peak",                   stats.frames_peak },
        { "retention peak entries",              stats.retention_peak },
        { "retention entries walked",            stats.retention_scan_events },
        { "retention events owned",              stats.retention_events_owned },
        { "retention events refused",            stats.retention_events_refused },
        { "retention appends from untraced events (must be 0)",
                                                stats.retention_appends_from_untraced_events },
        { "seal successor from foreign fault (must be 0)",
                                                stats.seal_successor_from_foreign_fault },
        { "rcheck seals compared",               stats.rcheck_seals },
        { "rcheck ENTER in-async compared",      stats.rcheck_cmp_enter_in_async },
        { "rcheck ENTER not-in-async compared",  stats.rcheck_cmp_enter_not_async },
        { "rcheck RETURN in-async compared",     stats.rcheck_cmp_return_in_async },
        { "rcheck RETURN not-in-async compared", stats.rcheck_cmp_return_not_async },
        { "rcheck events ours",                  stats.rcheck_cmp_ours },
        { "rcheck events foreign",               stats.rcheck_cmp_foreign },
        { "rcheck resume-pc mismatches",         stats.rcheck_mismatch_resume_pc },
        { "rcheck in-async mismatches",          stats.rcheck_mismatch_in_async },
        /* ---- close census (see Stats: CLOSE CENSUS) ---- */
        { "census closes",                       stats.census_closes },
        { "census frames opened",                stats.census_frames_opened },
        { "census frames merged",                stats.census_frames_merged },
        { "census frames unwound-dropped",       stats.census_frames_unwound_dropped },
        { "census frames diverted (fixup return)", stats.census_frames_diverted },
        { "census frames orphan-dropped",        stats.census_frames_orphan_dropped },
        { "census frames HELD at close",         stats.census_frames_held_at_close },
        { "census prev promoted",                stats.census_prev_promoted },
        { "census prev walked at close",         stats.census_prev_close_walked },
        { "census prev DROPPED at close",        stats.census_prev_close_dropped },
        { "census prev insns DROPPED at close (must be 0)",
                                                stats.census_prev_close_dropped_insns },
        { "census walk_prev HELD at close",      stats.census_walkprev_held_at_close },
        { "census chains HELD at close",         stats.census_chain_held_at_close },
        { "census chain insns HELD at close (must be 0)",
                                                stats.census_chain_held_insns },
        { "census reg-snaps HELD at close",      stats.census_snaps_held_at_close },
        { "census chain snap-mark HELD at close", stats.census_snapmark_held_at_close },
        { "census CP memops HELD at close",      stats.census_cpmem_held_at_close },
        { "census CP memop carry HELD at close", stats.census_cpcarry_held_at_close },
        { "census retained events HELD at close", stats.census_evs_held_at_close },
        { "census self-loop facts HELD at close", stats.census_repfacts_held_at_close },
        { "census warmup holds HELD at close",   stats.census_wmhold_held_at_close },
        { "census devio records HELD at close (must be 0)",
                                                stats.census_devio_held_at_close },
        { "census WP session open at close",     stats.census_wpmem_held_at_close },
        { "census fate identity BROKEN (must be 0)",
                                                stats.census_balance_broken },
        /* ---- the close drains (see Stats: THE CLOSE DRAINS) ---- */
        { "peer holder builders flushed at close (empty slot)",
                                                stats.close_peer_holder_flushes },
        { "  insns those flushes emitted",
                                                stats.close_peer_holder_insns_recovered },
        { "peer builders holding work and NOT flushed (must be 0)",
                                                stats.close_peer_holders_skipped },
        { "closes that flushed a peer AHEAD of the closing vCPU",
                                                stats.close_flush_reordered },
        { "  builders the dispatch clock moved ahead",
                                                stats.close_flush_reordered_builders },
        { "close in-flight insns the stop rule subtracted",
                                                stats.close_deferred_prev_inflight_trimmed },
        { "deferred-close prev with an unmeasured extent (must be 0)",
                                                stats.close_deferred_prev_extent_unknown },
        { "close reg-snap residue discarded",    stats.close_snaps_dropped },
        { "close CP memop residue discarded",    stats.close_cpmem_dropped },
        { "close CP memop carry discarded",      stats.close_cpcarry_dropped },
        { "close retained events discarded",     stats.close_evs_dropped },
        { "close self-loop fact latches discarded",
                                                stats.close_repfacts_dropped },
        { "WP session open at a close (must be 0)",
                                                stats.close_wp_session_open },
        { "builders holding RETIRED work after every close drain (must be 0)",
                                                stats.close_holder_undrained },
        { "  insns they were still holding",
                                                stats.close_holder_undrained_insns },
        { "foreign user TBs dropped (ungated context)",
                                                stats.pin_unverified_dropped },
    };
    const struct { const char *name; uint64_t value; } bin_counters[] = {
        { "  Header bits",        stats.bin_header_bits },
        { "  Body bits",          stats.bin_body_bits },
        { "  Dyn CP bits",        stats.bin_dyn_cp_bits },
        { "  Dyn WP bits",        stats.bin_dyn_wp_bits },
    };

    g_string_append_printf(report,
        "\n=== Wrong-Path Trace Plugin Statistics: %s ===\n"
        "Target architecture: %s\n"
        "Max wrong-path depth: %d instructions\n"
        "TB fragments translated: %" PRIu64 "\n"
        "BB templates created: %" PRIu64 "\n"
        "Unique branch PCs: %" PRIu64 "\n",
        label,
        target_name ? target_name : "unknown",
        max_wrong_path_depth,
        stats.tb_templates_created,
        stats.bb_templates_created,
        stats.unique_branch_pcs);

    for (size_t i = 0; i < G_N_ELEMENTS(counters); i++) {
        g_string_append_printf(report, "%-40s %" PRIu64 "\n",
                               counters[i].name, counters[i].value);
    }

    if (stats.wp_simulations > 0) {
        g_string_append_printf(report,
            "Average wrong-path length: %.1f instructions\n",
            (double)stats.wp_total_insns / stats.wp_simulations);
    }

    if (stats.bin_total_bits > 0) {
        g_string_append_printf(report,
            "Total binary bits: %" PRIu64 " (%.2f MiB)\n",
            stats.bin_total_bits,
            (double)stats.bin_total_bits / 8.0 / (1024.0 * 1024.0));
        for (size_t i = 0; i < G_N_ELEMENTS(bin_counters); i++) {
            g_string_append_printf(report,
                "%-40s %" PRIu64 " (%.2f%%)\n",
                bin_counters[i].name, bin_counters[i].value,
                100.0 * (double)bin_counters[i].value /
                       (double)stats.bin_total_bits);
        }
    }

    append_branch_breakdown(report, stats);
    append_opcode_breakdown(report, stats);

    /* Per-register attribution, CP and WP side-by-side, src and dst
     * separately. */
    auto print_reg_table = [&](const char *table_label,
                               const uint64_t *cp_arr,
                               const uint64_t *wp_arr) {
        uint64_t cp_total = 0, wp_total = 0;
        for (size_t i = 0; i < REG_ID_COUNT; i++) {
            cp_total += cp_arr[i];
            wp_total += wp_arr[i];
        }
        if (cp_total == 0 && wp_total == 0) return;
        std::vector<std::tuple<uint64_t, uint8_t>> rows;
        for (size_t i = 0; i < REG_ID_COUNT; i++) {
            uint64_t s = cp_arr[i] + wp_arr[i];
            if (s) rows.emplace_back(s, (uint8_t)i);
        }
        std::sort(rows.begin(), rows.end(),
                  std::greater<std::tuple<uint64_t, uint8_t>>());
        g_string_append_printf(report,
            "%s (%zu non-zero):\n"
            "  %-12s %14s %8s   %14s %8s\n",
            table_label, rows.size(),
            "register", "CP count", "%CP", "WP count", "%WP");
        for (const auto &r : rows) {
            uint8_t reg = std::get<1>(r);
            uint64_t cv = cp_arr[reg];
            uint64_t wv = wp_arr[reg];
            double cp_pct = cp_total
                ? 100.0 * (double)cv / (double)cp_total : 0.0;
            double wp_pct = wp_total
                ? 100.0 * (double)wv / (double)wp_total : 0.0;
            g_string_append_printf(report,
                "  %-12s %14" PRIu64 " %7.2f%%   %14" PRIu64 " %7.2f%%\n",
                generic_reg_name_or_unknown((unsigned)reg),
                cv, cp_pct, wv, wp_pct);
        }
    };
    print_reg_table("Src register attribution",
                    stats.cp_src_reg_uses, stats.wp_src_reg_uses);
    print_reg_table("Dst register attribution",
                    stats.cp_dst_reg_writes, stats.wp_dst_reg_writes);
    append_unsealed_at_close(report);

    g_string_append_printf(report,
        "==========================================\n");
}

/* Per-interval breakdown: a headline table (CP/WP insns+memops,
 * branches per interval) then transposed top-K tables for opcode /
 * branch type / src reg / dst reg.  @buckets is partitioned by
 * interval and sums to the segment totals; per-interval insn counts
 * are approximated by summing *_insns_by_opcode. */
void append_histogram(GString *report, const char *segment_label,
                             const std::vector<Stats> &buckets,
                             uint64_t segment_start,
                             uint64_t interval_size)
{
    if (buckets.empty()) {
        return;
    }
    size_t n = buckets.size();

    /* Per-bucket array sum, for the headline CP/WP insn columns. */
    auto sum_arr = [](const uint64_t *arr, size_t len) {
        uint64_t s = 0;
        for (size_t i = 0; i < len; i++) s += arr[i];
        return s;
    };

    g_string_append_printf(report,
        "\n--- Histogram: %s (%zu intervals of %" PRIu64 " insns) ---\n"
        "  %-4s %-22s %14s %14s %14s %14s %14s\n",
        segment_label, n, interval_size,
        "iv", "icount range",
        "CP insns", "CP memops", "WP insns", "WP memops", "branches");
    for (size_t i = 0; i < n; i++) {
        const Stats &b = buckets[i];
        uint64_t lo = segment_start + i * interval_size;
        uint64_t hi = lo + interval_size;
        g_autofree char *range =
            g_strdup_printf("%" PRIu64 "..%" PRIu64, lo, hi);
        uint64_t cp_ins = sum_arr(b.cp_insns_by_opcode, GEN_OP_COUNT);
        uint64_t wp_ins = sum_arr(b.wp_insns_by_opcode, GEN_OP_COUNT);
        g_string_append_printf(report,
            "  %-4zu %-22s %14" PRIu64 " %14" PRIu64
            " %14" PRIu64 " %14" PRIu64 " %14" PRIu64 "\n",
            i, range, cp_ins, b.cp_total_mem_accesses,
            wp_ins, b.wp_total_mem_accesses, b.branches_observed);
    }

    /* Transposed top-K: rows = top items by total CP+WP activity
     * across all intervals, columns = intervals.  cp_off/wp_off pick
     * the Stats arrays; CP+WP summed for ranking and printed combined. */
    auto print_top_k = [&](const char *table_label, unsigned id_count,
                           const char *(*name_of)(unsigned),
                           size_t cp_off, size_t wp_off,
                           unsigned k) {
        std::vector<std::tuple<uint64_t, unsigned>> rows;
        for (unsigned id = 0; id < id_count; id++) {
            uint64_t s = 0;
            for (size_t i = 0; i < n; i++) {
                const uint64_t *cp_arr =
                    (const uint64_t *)((const uint8_t *)&buckets[i] + cp_off);
                const uint64_t *wp_arr =
                    (const uint64_t *)((const uint8_t *)&buckets[i] + wp_off);
                s += cp_arr[id] + wp_arr[id];
            }
            if (s) rows.emplace_back(s, id);
        }
        if (rows.empty()) {
            return;
        }
        std::sort(rows.begin(), rows.end(),
                  std::greater<std::tuple<uint64_t, unsigned>>());
        if (rows.size() > k) {
            rows.resize(k);
        }
        g_string_append_printf(report,
            "\n  %s (top %zu, CP+WP per interval):\n    %-20s",
            table_label, rows.size(), "id");
        for (size_t i = 0; i < n; i++) {
            g_string_append_printf(report, " %12zu", i);
        }
        g_string_append_c(report, '\n');
        for (const auto &r : rows) {
            unsigned id = std::get<1>(r);
            const char *name = name_of(id);
            g_string_append_printf(report, "    %-20s",
                                   name ? name : "?");
            for (size_t i = 0; i < n; i++) {
                const uint64_t *cp_arr =
                    (const uint64_t *)((const uint8_t *)&buckets[i] + cp_off);
                const uint64_t *wp_arr =
                    (const uint64_t *)((const uint8_t *)&buckets[i] + wp_off);
                g_string_append_printf(report, " %12" PRIu64,
                                       cp_arr[id] + wp_arr[id]);
            }
            g_string_append_c(report, '\n');
        }
    };

    print_top_k("Opcode", GEN_OP_COUNT, generic_opcode_name_or_unknown,
                offsetof(Stats, cp_insns_by_opcode),
                offsetof(Stats, wp_insns_by_opcode), 10);
    print_top_k("Branch type", BRANCH_TYPE_COUNT, branch_type_name_or_unknown,
                offsetof(Stats, cp_branches_by_type),
                offsetof(Stats, wp_branches_by_type), BRANCH_TYPE_COUNT);
    print_top_k("Src register", REG_ID_COUNT, generic_reg_name_or_unknown,
                offsetof(Stats, cp_src_reg_uses),
                offsetof(Stats, wp_src_reg_uses), 12);
    print_top_k("Dst register", REG_ID_COUNT, generic_reg_name_or_unknown,
                offsetof(Stats, cp_dst_reg_writes),
                offsetof(Stats, wp_dst_reg_writes), 12);

    g_string_append_printf(report,
        "------------------------------------------\n");
}
