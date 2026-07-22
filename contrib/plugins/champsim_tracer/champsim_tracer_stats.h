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
     * because g_template_store / g_branch_history containers are
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
    /* Excursions re-run from scratch after a tb_flush unwound a spec-mode
     * exec_tb mid-walk (the truncated chain is discarded; the re-run's
     * complete chain replaces it). */
    uint64_t wp_flush_reruns = 0;
    /* Excursions whose FIRST spec exec_tb returned no translation with no
     * flush in flight: the wrong-path entry point itself could not be
     * fetched/translated.  Correct output only when the target is
     * genuinely unmapped in the current address space; a nonzero count on
     * a workload whose targets are resident indicates a bug. */
    uint64_t wp_first_tb_unavail = 0;
    /* Wrong-path BBs marked with a SYNTHETIC-DATA fault: a speculative memory
     * access to an absent/unreadable page served a deterministic placeholder
     * value, or a non-memory synchronous fault (arithmetic / illegal opcode)
     * stopped the excursion cleanly.  Emitted as CST_WP_EVENT_FAULT. */
    uint64_t wp_synthetic_faults = 0;
    uint64_t wp_total_mem_accesses = 0;

    /* Correct-path memops observed by the per-thread mem callback.
     * Counted before the loads-vs-stores split, so it covers both. */
    uint64_t cp_total_mem_accesses = 0;
    /* CP memops whose insn_pc matched nothing in the draining entry's
     * template — orphans from an executed-but-never-emitted path
     * (foreign-TB drops clear their memops at the source; anything
     * still surfacing here indicates a leak).  Dropped at drain
     * instead of mis-slotted onto insn 0. */
    uint64_t cp_orphan_mem_accesses = 0;
    /* CP memops whose insn_pc DID match a template slot, but the slot's
     * instruction cannot physically touch memory (static max loads and
     * stores both zero; atomics and synthetic-EA opcode classes
     * exempt).  The memop is still emitted — the trace records what
     * was observed — but a nonzero count means attribution corruption
     * upstream of the drain, the class the offline lint (cst_lint.h)
     * fails traces on. */
    uint64_t cp_impossible_slot_memops = 0;
    /* Emitted entries whose pending reg-snap count did not equal the
     * template's Σ n_dst_regs — the positional reg-snap invariant the wire
     * relies on (build_entry_view prefix-sums n_dst_regs).  The entry's
     * reg_snaps are DROPPED rather than mis-sliced (a code address landing
     * on an ALU dst, metaflags read from the wrong slot).  A backstop for
     * the eager-tail / foreign-drop / segment-boundary capture fixes; must
     * be 0 on a correct run. */
    uint64_t reg_snap_slice_dropped = 0;
    /* Emitted entries whose surplus reg-snaps (a leaked prefix from a chain
     * the assembler abandoned on a sync-fault-storm TB discontinuity) were
     * TRIMMED at the front to recover this block's own correct positional
     * reg-data (the dataflow oracle validates the recovered stream).  A
     * recovered leak, not a dropped slice; distinct from reg_snap_slice_
     * dropped, which is only the unrecoverable shortfall. */
    uint64_t reg_snap_leak_trimmed = 0;

    /* Binary writer byte-count breakdown. */
    uint64_t bin_total_bits = 0;
    uint64_t bin_header_bits = 0;
    uint64_t bin_body_bits = 0;
    uint64_t bin_dyn_cp_bits = 0;
    uint64_t bin_dyn_wp_bits = 0;
    uint64_t bin_wp_exception_bits = 0;

    /* Decode-side warning count. */
    uint64_t unknown_insn_warnings = 0;

    /* Kernel-excursion ownership (kexc=1; all zero when off).  Writes is
     * every ASID_WRITE path event consumed; overlays counts excursions
     * that installed a kernel overlay ASID (a PTI entry switch or a
     * TLB-maintenance save/probe value); cuts counts committed context
     * switches (a third distinct value inside one excursion); kept /
     * dropped split the kernel (priv!=0) TBs the ownership rule
     * admitted vs refused; write_storm counts excursions whose distinct
     * new-value count hit the storm threshold. */
    uint64_t kexc_asid_writes = 0;
    uint64_t kexc_overlays = 0;
    uint64_t kexc_cuts = 0;
    uint64_t kexc_kernel_kept = 0;
    uint64_t kexc_kernel_dropped = 0;
    uint64_t kexc_write_storm = 0;
    /* Kernel (priv!=0) TBs dropped because they executed at the target's
     * translation-bypassing privilege level (RISC-V M-mode firmware, which
     * satp does not govern; see g_xlate_bypass_priv).  Counted on both
     * attribution rules (kexc on and off), separately from
     * kexc_kernel_dropped — these TBs never consult the ownership rule. */
    uint64_t kexc_mmode_dropped = 0;
    /* Rewrites of the pinned ASID value observed after enough DISTINCT
     * other values to imply the target's narrow ASID space wrapped (a
     * generation rollover recycled the pinned value).  Detection stat;
     * the physical-page identity below is what actually adjudicates
     * ownership — see pin_reuse_track in champsim_tracer.cc. */
    uint64_t pin_asid_reuse_suspected = 0;

    /* Physical-page process identity (narrow-ASID targets; all zero on
     * the wide-register targets and in user mode).  The pin's authority
     * is the map of user-code pages (virtual page -> physical page) the
     * pinned process has executed; the per-vCPU ASID value is only a
     * dwell tag.  repins counts dwells where the pinned process was
     * re-acquired under a DIFFERENT ASID value (generation rollover
     * re-numbering it, or a migration onto a vCPU where its per-CPU
     * ASID differs); phys_mismatch counts user TBs refused because a
     * mapped virtual page ran DIFFERENT BYTES (a foreign process
     * aliasing the pinned value's VAs — a frame mismatch alone is not
     * enough, the page's content signature must also differ);
     * refault_repaired counts mapped pages whose frame moved but whose
     * bytes matched (a clean code page evicted and re-faulted), re-tied
     * to the new frame instead of refused; unverified counts user TBs
     * dropped while a dwell awaited its first map hit (a foreign
     * process that never touches mapped pages parks here forever,
     * traced never); pages is the map's final size. */
    uint64_t pin_repins = 0;
    uint64_t pin_phys_mismatch_dropped = 0;
    uint64_t pin_refault_repaired = 0;
    uint64_t pin_unverified_dropped = 0;
    uint64_t pin_pages_mapped = 0;

    /* Pinned-process migration-detect guard (system-mode pin, SMP guests).
     * Set once per segment when the pinned process is seen executing USER
     * code on more than one vCPU within a segment — a pinned-process-mode
     * misuse the diagnostic makes loud: pin the workload to a core
     * (cst_attach does this by default) for stable per-thread identity.  A
     * migrating pinned process is outside the single-address-space tracer's
     * clean-attribution envelope.  Zero on single-vCPU guests, in user
     * mode, and on any unpinned run. */
    uint64_t pin_multivcpu_observed = 0;

    /* Suspend-or-seal, foreign-ASID arrow (Stage 3).  A foreign span
     * suspends the deferred prev onto a bounded per-thread stack instead
     * of dropping it, so the pinned process's resume seals the interrupted
     * (fault-handler) block at its own depth.  pushed/resumed count the
     * suspend and matching-resume arrows; displaced counts an over-cap
     * eviction retired at return (the oldest suspension flushed at its
     * depth to free the slot); stale_retired counts a suspension the
     * pinned context reached user privilege past without resuming, flushed
     * at its depth by the sweep; orphan_dropped counts entries discarded
     * (no emit) at a segment-open boundary.  All zero off the contention
     * path (no foreign drops -> no suspensions). */
    uint64_t susp_pushed = 0;
    uint64_t susp_resumed = 0;
    uint64_t susp_displaced = 0;
    uint64_t susp_stale_retired = 0;
    uint64_t susp_orphan_dropped = 0;

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
