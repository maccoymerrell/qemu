/*
 * Wrong-Path Tracing Plugin — exit-time statistics.
 *
 * Plain aggregate of plugin-wide counters.  Producers update fields
 * directly via the calling thread's per-thread instance (g_stats_tls);
 * the exit handler in tracer.cc reads stats_snapshot() to obtain a
 * coherent process-wide aggregate by summing across every vCPU
 * thread that has registered.  No locks on the hot bump path; the
 * sum is computed once at exit-time under stats_registry_lock.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_STATS_H
#define CHAMPSIM_TRACER_STATS_H

#include <inttypes.h>
#include <stdint.h>

#include "champsim_tracer_generic_ids.h"  /* GEN_OP_COUNT, BRANCH_TYPE_COUNT, REG_ID_COUNT */

struct Stats {
    /* Cache populations.  Bumped on insert, read at exit-time print.
     * Mirroring these as POD uint64_t works around an atexit/static-
     * destructor ordering issue: g_bb_template_cache and
     * g_branch_history get their containers destroyed before
     * plugin_exit runs (because QEMU dispatches plugin atexit hooks
     * via a host atexit handler registered earlier than the .so's
     * own __cxa_atexit destructors), so calling .size() at exit-time
     * returns 0.  These counters survive that ordering. */
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

    /* Per-execution attribution.  cp_* are bumped at vcpu_tb_exec time
     * when walking the previous TB's template; wp_* are bumped inside
     * the WP simulator's per-iteration append loop.  Both are sized by
     * the corresponding generic enum sentinels so the arrays grow in
     * lockstep with the enum domain. */
    uint64_t cp_insns_by_opcode[GEN_OP_COUNT] = {};
    uint64_t cp_branches_by_type[BRANCH_TYPE_COUNT] = {};
    uint64_t cp_src_reg_uses[REG_ID_COUNT] = {};
    uint64_t cp_dst_reg_writes[REG_ID_COUNT] = {};

    uint64_t wp_insns_by_opcode[GEN_OP_COUNT] = {};
    uint64_t wp_branches_by_type[BRANCH_TYPE_COUNT] = {};
    uint64_t wp_src_reg_uses[REG_ID_COUNT] = {};
    uint64_t wp_dst_reg_writes[REG_ID_COUNT] = {};
};

/* Field-wise subtraction (a - b) into @out.  Since Stats is a POD
 * aggregate with no padding holes that affect counters, we iterate
 * the address space as uint64_t and subtract.  Used at finish-segment
 * time to compute "this segment's contribution" given a snapshot
 * taken at segment start. */
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
 * Stats slot, lazily registering it on first call.  All hot-path
 * bumps go through here via the g_stats macro: no atomics, no locks
 * on the bump path; only thread-local memory is touched.  The
 * registry is acquired under a mutex exactly once per thread (at
 * first touch) and again at thread exit (to fold the contributions
 * into a graveyard) — both off the hot path.
 */
Stats &thread_stats_get();

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

/* Histogram bucket pointer for the currently-executing TB.  Refreshed
 * at the top of vcpu_tb_exec from the current icount; null when
 * histograms are disabled or no segment is active.  CP and WP
 * attribution sites mirror their g_stats_tls bumps into
 * *g_current_hist_bucket when non-null.  See start_trace_segment /
 * select_histogram_bucket in champsim_tracer.cc.  Histogram bucket
 * memory is owned by the segment, not per-thread; under exec_lock
 * (which serializes the only writers), so no separate aggregation. */
extern Stats *g_current_hist_bucket;

#endif /* CHAMPSIM_TRACER_STATS_H */
