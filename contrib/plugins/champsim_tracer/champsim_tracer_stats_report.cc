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
        { "CP reg-snap leak trimmed",            stats.reg_snap_leak_trimmed },
        { "REP iters from arch state",           stats.rep_iters_architectural },
        { "REP iters inferred from memops",      stats.rep_iters_inferred },
        { "REP iters/memop mismatch",            stats.rep_iters_memop_mismatch },
        { "REP piece table degenerate",          stats.rep_piece_table_degenerate },
        { "window close in fan-out",             stats.window_close_in_fanout },
        { "window close fan-out hold capped",    stats.window_close_fanout_hold_capped },
        { "warmup boundary hold defers",         stats.warmup_boundary_hold_defers },
        { "warmup boundary unplaced at finish",  stats.warmup_boundary_unplaced_at_finish },
        { "warmup boundary in fan-out",          stats.warmup_boundary_in_fanout },
        { "marker cb WP-fenced (start)",         stats.marker_wp_fenced_start },
        { "marker cb WP-fenced (end)",           stats.marker_wp_fenced_end },
        { "marker fence session-only (must be 0)", stats.marker_fence_session_only },
        { "marker run broken (must be 0)",       stats.marker_run_broken },
        { "marker run adopted across vCPUs",     stats.marker_run_adopted },
        { "marker run incomplete at exit (must be 0)", stats.marker_run_incomplete },
        { "marker handoff evicted (must be 0)",  stats.marker_handoff_evicted },
        { "marker local run slot evicted",       stats.marker_local_evicted },
        { "marker local run stale (migrated)",   stats.marker_local_stale },
        { "marker END with no close (must be 0)", stats.marker_end_no_close },
        { "WP session flag on correct path (must be 0)", stats.wp_session_on_cp },
        { "user clock worst stall (arch insns)", stats.user_clock_worst_stall },
        { "stall ceiling closes",                stats.stall_ceiling_closes },
        { "user clock worst stall, any context", stats.user_clock_worst_stall_any },
        { "any-context stall closes",            stats.stall_any_closes },
        { "closed by machine shutdown",          stats.vm_shutdown_closes },
        { "REP trailing pass dropped",           stats.rep_trailing_pass_dropped },
        { "REP exit edge recovered",             stats.rep_exit_edge_recovered },
        { "REP clock ticks withheld",            stats.rep_clock_ticks_withheld },
        { "REP unretired pass dropped",          stats.rep_unretired_pass_dropped },
        { "REP unretired pass kept",             stats.rep_unretired_pass_kept },
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
        { "WP flush re-runs",                    stats.wp_flush_reruns },
        { "WP first-TB unavailable",             stats.wp_first_tb_unavail },
        /* Invariant, not a measurement: the wrong path walks past syscalls but
         * never performs one, so this must read 0.  See
         * qemu_plugin_spec_syscall_blocked_count(). */
        { "WP host syscalls blocked (must be 0)",
          qemu_plugin_spec_syscall_blocked_count() },
        { "Unknown-instruction warnings",        stats.unknown_insn_warnings },
        { "DEVIO FIFO kicks dropped (overflow)", stats.devio_fifo_kicks_dropped },
        { "kexc ASID-write events",              stats.kexc_asid_writes },
        { "kexc overlays installed",             stats.kexc_overlays },
        { "kexc committed-switch cuts",          stats.kexc_cuts },
        { "kexc kernel TBs kept",                stats.kexc_kernel_kept },
        { "kexc kernel TBs dropped",             stats.kexc_kernel_dropped },
        { "kexc write storms",                   stats.kexc_write_storm },
        { "kexc entry-ASID restores",            stats.kexc_entry_restores },
        { "kexc cuts retired by a restore",      stats.kexc_cut_retired_by_restore },
        /* Invariant, not a measurement: a cut says the address space moved
         * away, so it cannot stand while the entry value is loaded. */
        { "kexc cut declines at entry ASID (must be 0)",
                                                stats.kexc_cut_declined_at_entry_asid },
        { "kexc post-restore kernel TBs kept",   stats.kexc_post_restore_kept_tbs },
        { "kexc post-restore kernel insns kept", stats.kexc_post_restore_kept_insns },
        { "kexc post-restore kept off entry/overlay ASID (must be 0)",
                                                stats.kexc_post_restore_kept_foreign_live },
        { "kexc decline reason: no user owner",  stats.kexc_decl_no_user },
        { "kexc decline reason: entry not owned", stats.kexc_decl_not_owned },
        { "kexc decline reason: committed cut",  stats.kexc_decl_cut },
        { "kexc decline not-owned at pinned ASID",
                                                stats.kexc_decl_not_owned_live_pinned },
        { "kexc async-window ownership snapshots", stats.kexc_async_snapshots },
        { "kexc async-return ownership re-latches", stats.kexc_async_relatches },
        { "kexc async re-latch skipped (owner unproven)",
                                                stats.kexc_async_relatch_skipped },
        { "kexc post-re-latch kernel TBs kept",  stats.kexc_post_relatch_kept_tbs },
        { "kexc post-re-latch kernel insns kept", stats.kexc_post_relatch_kept_insns },
        { "kexc live-root recovered TBs (edge refused)",
                                                stats.kexc_root_recovered_tbs },
        { "kexc live-root recovered insns",      stats.kexc_root_recovered_insns },
        { "kexc live-root recovered over a standing cut",
                                                stats.kexc_root_recovered_over_cut },
        { "kexc decline cut at pinned ASID",     stats.kexc_decl_cut_live_pinned },
        { "kexc task-identity kernel TBs kept",  stats.kexc_tp_kept_tbs },
        { "kexc task-identity kernel TBs refused", stats.kexc_tp_dropped_tbs },
        { "kexc task-identity recovered TBs (edge refused)",
                                                stats.kexc_tp_recovered_tbs },
        { "kexc task-identity recovered insns",  stats.kexc_tp_recovered_insns },
        { "kexc task-identity excluded TBs (edge leaked)",
                                                stats.kexc_tp_excluded_tbs },
        { "kexc task-identity excluded insns",   stats.kexc_tp_excluded_insns },
        { "kexc excluded, executing thread known but foreign space",
                                                stats.kexc_tp_excluded_known_thread },
        { "kexc excluded, executing thread never owned",
                                                stats.kexc_tp_excluded_unknown_thread },
        { "kexc recovered span returned to an owned user TB",
                                                stats.kexc_recovered_span_owned_user },
        { "kexc recovered span returned to a foreign user TB (must be 0)",
                                                stats.kexc_recovered_span_foreign_user },
        { "thread ids aliased at a kernel entry edge",
                                                stats.tid_task_aliased },
        { "kernel-thread identities minted",     stats.tid_kernel_task_minted },
        { "thread-id alias arms expired unresolved",
                                                stats.tid_alias_expired },
        { "kexc edge not-owned refusals of an owned task",
                                                stats.kexc_decl_not_owned_tp_owned },
        { "kexc owned-thread map inserts",       stats.kexc_tp_map_inserts },
        { "kexc owned-thread map invalidations", stats.kexc_tp_map_invalidations },
        { "kexc thread-pointer samples with no identity (0)",
                                                stats.kexc_tp_null_samples },
        { "kexc kept span ended at a foreign user TB (must be 0)",
                                                stats.kexc_kept_span_foreign_user },
        { "kexc kept span ended foreign at the pinned ASID value (must be 0)",
                                                stats.kexc_kept_span_foreign_user_pinned_val },
        { "narrow-ASID identity generation bumps",
                                                stats.asid_identity_gen_bumps },
        { "kexc ASID writes in a stale value generation",
                                                stats.kexc_stale_gen_writes },
        { "kexc entry-VALUE collisions after a rollover",
                                                stats.kexc_entry_value_collisions },
        { "kexc async snapshots stale at their return",
                                                stats.kexc_async_snap_stale_gen },
        { "kexc entry-value restores refused (value recycled)",
                                                stats.kexc_entry_restore_refused_stale_gen },
        { "kexc async re-latches refused (snapshot values recycled)",
                                                stats.kexc_async_relatch_refused_stale_gen },
        { "kexc M-mode TBs dropped",             stats.kexc_mmode_dropped },
        { "suspend-or-seal prev suspended",      stats.susp_pushed },
        { "suspend-or-seal prev resumed",        stats.susp_resumed },
        { "suspend-or-seal abandoned-async",     stats.susp_abandoned },
        { "suspend-or-seal displaced (over-cap)", stats.susp_displaced },
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
        { "suspend-or-seal stale-retired",       stats.susp_stale_retired },
        { "suspend-or-seal orphan-dropped",      stats.susp_orphan_dropped },
        { "pin ASID reuse suspected",            stats.pin_asid_reuse_suspected },
        { "pin re-acquisitions (new ASID)",      stats.pin_repins },
        { "pin content-mismatch user TBs dropped", stats.pin_phys_mismatch_dropped },
        { "pin re-fault frames repaired",        stats.pin_refault_repaired },
        { "pin unverified user TBs dropped",     stats.pin_unverified_dropped },
        { "pin code pages mapped",               stats.pin_pages_mapped },
        { "pin multi-vCPU observed (segments)",  stats.pin_multivcpu_observed },
    };
    const struct { const char *name; uint64_t value; } bin_counters[] = {
        { "  Header bits",        stats.bin_header_bits },
        { "  Body bits",          stats.bin_body_bits },
        { "  Dyn CP bits",        stats.bin_dyn_cp_bits },
        { "  Dyn WP bits",        stats.bin_dyn_wp_bits },
        { "  WP exception bits",  stats.bin_wp_exception_bits },
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
