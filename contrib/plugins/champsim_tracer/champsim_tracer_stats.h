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

    /* Self-modifying-code revisioning (smc_plan.md).  A CP re-execution of a
     * (asid_root, start_pc) slot whose committed template holds different
     * bytes mints a new template revision; a state the guest later restores
     * reuses its original revision id.  smc_overflow_* count the cap backstop
     * (a per-PC distinct-state count above g_smc_revision_cap = a bug signal,
     * §5-B).  All zero unless code self-modifies. */
    uint64_t smc_revisions_minted = 0;
    uint64_t smc_revision_reuses = 0;
    uint64_t smc_overflow_events = 0;
    uint64_t smc_overflow_pcs = 0;
    /* Commits at an already-committed slot whose overlapping instructions are
     * byte-identical and whose EXTENT alone differs — the chain-length
     * artifact the revision discriminator deliberately does NOT version (a
     * fault-interrupted or wrong-path-budget-cut chain, a page-split
     * fragment).  Nonzero on ordinary workloads; it is the negative control
     * for revision minting, not an error signal. */
    uint64_t smc_extent_artifacts = 0;

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
     * skipped the faulting insn and let the excursion continue to the depth
     * budget.  Emitted as CST_WP_EVENT_FAULT. */
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
    /* Memops an entry could not address, because the instruction issued
     * more than CST_FID_SLOT_COUNT of one direction and the wire has no
     * slot to hold them.  The entry reports the capped count so it stays
     * self-describing (see extr_n_loads); this counts what the cap left
     * out.  The unbounded issuers are the AArch64 FEAT_MOPS bulk-memory
     * instructions — SETM / CPYM transfer the whole page-aligned body of
     * a memset / memcpy in a single execution — for which the
     * per-template profile still carries the untruncated memop totals
     * and the full touched address extent. */
    uint64_t memops_over_slot_ceiling = 0;
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

    /* DEVIO exact-owner attribution (devio=1, system mode; zero otherwise).
     * A doorbell kick is queued on its kicking vCPU's bounded FIFO
     * (kDevioKickFifoCap entries, champsim_tracer_output.cc) and matched
     * at block-backend issue by device token, oldest kick first.
     * devio_fifo_kicks_dropped counts kicks refused because that vCPU's
     * FIFO was already full — the dropped kick's own request loses exact
     * attribution (falls back to POSITIONAL) but no request is ever
     * matched to the wrong owner.  Zero on a healthy run; a nonzero count
     * means one vCPU is kicking a device far faster than the block
     * backend drains it. */
    uint64_t devio_fifo_kicks_dropped = 0;

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
    /* Suspend-or-seal, abandoned-async arrow (Stage 4).  The stuck-window
     * recovery's no-departure-PC arm suspends the deferred prev instead of
     * dropping it, so the interrupted block seals at its own depth when the
     * pinned context resumes (rather than the block's fault level being lost
     * to a drop).  A subset of susp_pushed, tagged separately because it is a
     * distinct drop site with its own (async-storm) contention signature; the
     * abandoned arm falls through to the promote, so its suspension defers to
     * a LATER resume (the same step's resume arrow is held off — cur is the
     * force-closed window's OTHER thread, not this prev's successor).  Zero
     * off the async-recovery path. */
    uint64_t susp_abandoned = 0;

    /* Post-merge depth re-stamp (the seal takes the depth stamp again after
     * its merge completions retire frames).  corrections counts the steps
     * where the second stamp DIFFERS from the first — i.e. a completing
     * frame was still flagged in-flight when the current TB was first
     * stamped, because the guest's exception return was suppressed by the
     * host's strict-LIFO fault pop.  max_delta is the largest such
     * correction: a delta >= 2 is exactly a syscall_fault_nesting depth-JUMP
     * that would have reached the wire (the block after the reassembled
     * faulting BB emitted two or more levels above its neighbours), a delta
     * of 1 a silent one-level over-count.  Zero on any run whose fault
     * returns are all observed, which is every uncontended run — so a
     * nonzero value is a direct, per-step measure of the contention
     * condition, not of the rare end-to-end oracle failure it produces. */
    uint64_t depth_restamp_corrections = 0;
    uint64_t depth_restamp_jumps = 0;
    uint32_t depth_restamp_max_delta = 0;

    /* Per-guest-thread frame ownership, measured at the condition rather
     * than at the oracle failure it produces.  foreign_inflight counts, per
     * depth stamp, the un-returned fault frames a guest thread OTHER than the
     * executing one entered — every one of them a level the executing block
     * would have inherited before frames carried an owner; stamps_corrected
     * is the number of stamps where at least one did.  max_foreign is the
     * widest such inheritance (>= 2 is a depth-JUMP's worth).  sweep_spared
     * counts frames the pinned-user leak sweep left to their own thread, and
     * deeper_spared the frames a merge completion did not unwind because a
     * peer thread, not a nested fault, put them above it on the ledger.  All
     * zero on a single-threaded guest, so a nonzero value is exactly the
     * multi-thread condition. */
    uint64_t depth_tid_foreign_inflight = 0;
    uint64_t depth_tid_stamps_corrected = 0;
    uint32_t depth_tid_max_foreign = 0;
    uint64_t depth_tid_sweep_spared = 0;
    uint64_t depth_tid_deeper_spared = 0;

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
