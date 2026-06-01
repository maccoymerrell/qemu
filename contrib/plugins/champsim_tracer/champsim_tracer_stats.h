/*
 * Wrong-Path Tracing Plugin — exit-time statistics.
 *
 * Plain aggregate of plugin-wide counters.  Producers bump fields on
 * the calling thread's per-thread instance (no locks on the hot
 * path); stats_snapshot() sums every registered thread's slot once at
 * exit under stats_registry_lock.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_STATS_H
#define CHAMPSIM_TRACER_STATS_H

#include <inttypes.h>
#include <stdint.h>

#include "champsim_tracer_generic_ids.h"  /* GEN_OP_COUNT, BRANCH_TYPE_COUNT, REG_ID_COUNT */

struct Stats {
    /* Cache populations, bumped on insert.  Mirrored as POD counters
     * because g_bb_template_cache / g_branch_history containers are
     * destroyed before plugin_exit runs (QEMU's atexit hook fires
     * before the .so's __cxa_atexit dtors), so .size() returns 0 at
     * exit-time; these survive that ordering. */
    uint64_t tb_templates_created = 0;
    uint64_t bb_templates_created = 0;
    uint64_t unique_branch_pcs = 0;

    /* Branch transitions observed at vcpu_tb_exec time. */
    uint64_t branches_observed = 0;
    uint64_t branches_taken = 0;
    uint64_t branches_not_taken = 0;

    /* Wrong-path simulator. */
    uint64_t wp_simulations = 0;
    uint64_t wp_skipped = 0;
    uint64_t wp_total_insns = 0;
    uint64_t wp_early_exits = 0;
    uint64_t wp_total_mem_accesses = 0;

    /* Correct-path memops observed by the per-thread mem callback.
     * Counted before the loads-vs-stores split, so it covers both. */
    uint64_t cp_total_mem_accesses = 0;

    /* Binary writer byte-count breakdown. */
    uint64_t bin_total_bits = 0;
    uint64_t bin_header_bits = 0;
    uint64_t bin_body_bits = 0;
    uint64_t bin_dyn_cp_bits = 0;
    uint64_t bin_dyn_wp_bits = 0;
    uint64_t bin_wp_exception_bits = 0;

    /* Decode-side warning count. */
    uint64_t unknown_insn_warnings = 0;

    /* Per-execution attribution.  cp_* bumped at vcpu_tb_exec walking
     * the prev TB's template; wp_* inside the WP per-iteration loop.
     * Sized by the generic enum sentinels to stay in lockstep. */
    uint64_t cp_insns_by_opcode[GEN_OP_COUNT] = {};
    uint64_t cp_branches_by_type[BRANCH_TYPE_COUNT] = {};
    uint64_t cp_src_reg_uses[REG_ID_COUNT] = {};
    uint64_t cp_dst_reg_writes[REG_ID_COUNT] = {};

    uint64_t wp_insns_by_opcode[GEN_OP_COUNT] = {};
    uint64_t wp_branches_by_type[BRANCH_TYPE_COUNT] = {};
    uint64_t wp_src_reg_uses[REG_ID_COUNT] = {};
    uint64_t wp_dst_reg_writes[REG_ID_COUNT] = {};
};

/* Field-wise subtraction (a - b) into @out, iterating Stats as a
 * uint64_t array.  Used at finish-segment to compute the segment's
 * contribution given a snapshot taken at its start. */
static inline void stats_diff(Stats *out, const Stats &a, const Stats &b)
{
    static_assert(sizeof(Stats) % sizeof(uint64_t) == 0,
                  "Stats must be exactly an array of uint64_t fields "
                  "for the field-wise subtract to be valid");
    const uint64_t *pa = reinterpret_cast<const uint64_t *>(&a);
    const uint64_t *pb = reinterpret_cast<const uint64_t *>(&b);
    uint64_t *pout = reinterpret_cast<uint64_t *>(out);
    size_t n = sizeof(Stats) / sizeof(uint64_t);
    for (size_t i = 0; i < n; i++) {
        pout[i] = pa[i] - pb[i];
    }
}

/*
 * Per-thread accumulator accessor.  Returns the calling thread's
 * Stats slot, lazily registering it on first call.  Hot-path bumps
 * touch only thread-local memory; the registry mutex is taken once
 * per thread at first touch and again at thread exit (folding into a
 * graveyard) — both off the hot path.
 */
Stats &thread_stats_get();

/* Pre-size the per-thread stats registry on the calling thread.  Call
 * once from the main thread at plugin install (before vCPUs run) so the
 * registry's backing buffer is allocated in the main malloc arena and
 * never reallocated cross-thread at teardown.  See the definition in
 * champsim_tracer_stats.cc for the system-mode rationale. */
void stats_registry_reserve(size_t n);

/* Hot-path callers write `g_stats.foo++` and the macro forwards to
 * the per-thread slot.  Read-side aggregation is via stats_snapshot()
 * below; never read `g_stats` directly when you need a process-wide
 * total. */
#define g_stats (::thread_stats_get())

/* Read-side: returns a Stats value summing every live thread's slot
 * plus contributions from threads that have already exited.
 * Acquires the registry mutex briefly; the bump path is unaffected.
 * Call from per-segment summary and at plugin_exit. */
Stats stats_snapshot();

/* Histogram bucket for the currently-executing TB.  Refreshed atop
 * vcpu_tb_exec from icount; null when histograms are off or no
 * segment active.  CP/WP attribution sites mirror their bumps here
 * when non-null.  Memory is segment-owned (not per-thread) and
 * written only under exec_lock, so no separate aggregation.  See
 * select_histogram_bucket in champsim_tracer.cc. */
extern Stats *g_current_hist_bucket;

#endif /* CHAMPSIM_TRACER_STATS_H */
