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
    /* Wrong-path steps whose speculative translation was refused because the
     * HOST's TCG code buffer had no room left, not because the guest could
     * not supply the code.  A walk may not tb_flush (see
     * qemu_plugin_spec_reserve_exhausted), so TCG hands it a bounded reserve
     * and then declines; the chain is cut at whatever depth the buffer
     * happened to allow.  MUST BE 0 in any capture whose wrong-path content
     * is expected to be reproducible: the cut point is host state, so the
     * same guest run traced twice can produce different chains. */
    uint64_t wp_xlat_buffer_truncations = 0;
    /* Wrong-path resume addresses the target refused to hold verbatim: a PC
     * the walk computed (a faulting PC plus an instruction length, or a stuck
     * PC nudged by one) that qemu_plugin_set_pc() re-interpreted instead of
     * taking, so the walk would have resumed somewhere other than where it
     * asked.  The live case is a MIPS code address with bit 0 set: that bit
     * selects the MIPS16/microMIPS ISA mode rather than naming the address.
     * Each one ends its excursion; the WP BBs already committed are kept. */
    uint64_t wp_pc_not_representable = 0;
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
     * out.
     *
     * Must be 0 on a correct run.  The only instructions with no
     * fan-out bound at all — x86 REP string ops and the AArch64
     * FEAT_MOPS bulk copy/set family — are fanned out into a
     * per-iteration self-loop before they reach the slot tables, so
     * every memop they issue lands in a slot.  Everything else is
     * bounded well below the ceiling (XSAVE ~320, AVX-512
     * gather/scatter 16, SVE2 64, RISC-V V 64).  A nonzero count means
     * a new unbounded issuer has appeared and wants the same fan-out
     * treatment; until then the per-template profile still carries the
     * untruncated memop totals and the full touched address extent. */
    uint64_t memops_over_slot_ceiling = 0;
    /* Emitted entries whose pending reg-snap count did not equal the
     * template's Σ n_dst_regs — the positional reg-snap invariant the wire
     * relies on (build_entry_view prefix-sums n_dst_regs).  The entry's
     * reg_snaps are DROPPED rather than mis-sliced (a code address landing
     * on an ALU dst, metaflags read from the wrong slot).  A backstop for
     * the eager-tail / foreign-drop / segment-boundary capture fixes; must
     * be 0 on a correct run.
     *
     * THIS IS THE TOTAL.  It counts EVERY dropped slice, including the ones
     * taken during an end-marker close.  It did not always: the bump used to
     * sit behind `if (!g_seg_end_marker_close)` while the drop itself ran
     * unconditionally, so on a marker-window trace — where the segment
     * ALWAYS closes on the END marker — the counter was structurally unable
     * to observe the one drop that happens on every single run.  A reader
     * who saw 0 concluded "nothing was dropped" and was wrong.  The
     * end-marker-close subset is still separable, below, but it is no longer
     * separable from the total by being invisible. */
    uint64_t reg_snap_slice_dropped = 0;
    /* Subset of reg_snap_slice_dropped taken while the segment was closing
     * on the guest's END marker.  Attribution only — an END-truncated block
     * loses its tail dst snaps because the marker exits the process before
     * the block's later instructions run, which is a real loss of register
     * deltas from an entry the trace still emits at full n_insns.  Counted
     * apart so the "expected" case can be told from a capture bug without
     * either of them being silent. */
    uint64_t reg_snap_slice_dropped_end_close = 0;
    /* How many RegSnap values those drops actually threw away.  The event
     * count above says a slice was lost; this says how much register delta
     * went with it.  One drop of four snaps and four drops of one snap are
     * the same number in the event counter and are not the same loss. */
    uint64_t reg_snap_slice_drop_discarded = 0;
    /* Emitted entries whose surplus reg-snaps (a leaked prefix from a chain
     * the assembler abandoned on a sync-fault-storm TB discontinuity) were
     * TRIMMED at the front to recover this block's own correct positional
     * reg-data (the dataflow oracle validates the recovered stream).  A
     * recovered leak, not a dropped slice; distinct from reg_snap_slice_
     * dropped, which is only the unrecoverable shortfall. */
    uint64_t reg_snap_leak_trimmed = 0;
    /* In-flight CP chains the assembler discarded on a discontinuity (a
     * true BB whose remainder ran inside content the trace excludes), and
     * the per-insn dst snaps discarded WITH them.  Those fragments never
     * reach the wire, so their snaps must not either: left in the
     * positional sink they became the next block's leaked prefix, which
     * the emit-time backstop then "recovered" by trimming.  These two are
     * the condition; reg_snap_leak_trimmed is what the condition used to
     * turn into.
     *
     * SCOPE.  These two count the per-exec seal walk's append site
     * (cp_chain_append) only, and they now count the chain event even when
     * regdata is off — the chain IS dropped either way, and a counter that
     * reports 0 because a feature is disabled reports the wrong thing.  The
     * other two ways an in-flight chain dies have their own counters below,
     * because this one cannot see them. */
    uint64_t reg_snap_chain_drops = 0;
    uint64_t reg_snap_chain_drop_discarded = 0;
    /* ARCHITECTURAL INSTRUCTIONS in the fragments those drops threw away.
     * The event count says a chain died; this says how much of the
     * instruction stream died with it — which is the quantity that has to
     * reconcile against the window clock, since the clock billed those
     * instructions on their own dispatch and the wire never received
     * them. */
    uint64_t reg_snap_chain_drop_insns = 0;
    /* The same instructions split by the privilege of the block that
     * lost them.  Only the user half is inside the window clock's
     * quantity, so a single total cannot say whether a clock-vs-wire
     * residual is these drops or a second mechanism. */
    uint64_t reg_snap_chain_drop_user_insns = 0;
    uint64_t reg_snap_chain_drop_sys_insns = 0;
    /* Chains the seal walk SEALED instead of discarding, because control
     * left the block before its terminating branch: the instructions ran, so
     * the block is emitted at the extent that ran.  reg_snap_chain_drops
     * above is what this replaces and must now be 0 at the seal site.
     * cut_blocks_excluded are the ones the faults=0 policy drops with every
     * other block from a synchronous handler's context — a policy exclusion,
     * not a loss of something the trace was meant to carry. */
    uint64_t cut_blocks_sealed = 0;
    uint64_t cut_block_insns = 0;
    uint64_t cut_block_user_insns = 0;
    uint64_t cut_block_sys_insns = 0;
    uint64_t cut_blocks_excluded = 0;
    /* Seal walks that sealed MORE THAN ONE cut block.  Impossible while
     * fragments inside a TB stay contiguous; if it fires, the body stream is
     * out of program order.  Must be 0. */
    uint64_t cut_blocks_multi_per_walk = 0;
    /* In-flight chains dropped by the append inside PathBuilder::flush_final
     * — the SEGMENT-CLOSE walk, which calls BBChainAssembler::append_fragment
     * directly and discarded the drop verdict.  That is the walk every
     * marker-window run finishes through, so this site was invisible to
     * reg_snap_chain_drops by construction.  Counted here; the snaps such a
     * drop orphans in the positional sink are counted beside it — the sink's
     * whole depth at the drop, an UPPER BOUND, because that walk keeps no
     * per-chain snap mark.  Counting only: the sink is deliberately left
     * alone so this instrument does not also change what reaches the
     * wire. */
    uint64_t reg_snap_chain_drops_flush = 0;
    uint64_t reg_snap_chain_flush_orphaned = 0;
    uint64_t reg_snap_chain_flush_insns = 0;
    /* In-flight chains destroyed by BBChainAssembler::reset() rather than by
     * an append discontinuity — the fault-fold path (fold_prev_full_bb
     * explicitly resets a live chain), the segment resets, and the seal
     * walk's own post-emit resets.  reset() returns nothing, so every one of
     * these was silent.  Fragments already appended to such a chain never
     * reach the wire. */
    uint64_t reg_snap_chain_reset_drops = 0;
    uint64_t reg_snap_chain_reset_frags = 0;
    uint64_t reg_snap_chain_reset_insns = 0;
    /* The same loss split by privilege, and the entry PC of the FIRST chain
     * lost this way.  "One instruction lost" is a different finding
     * depending on whose instruction it was: a user instruction of the
     * pinned process is a hole in the trace's own subject, a kernel one is
     * a hole in its context.  A single aggregate could not tell them apart,
     * and the PC is what turns "somewhere" into an address to look at. */
    uint64_t reg_snap_chain_reset_user_insns = 0;
    uint64_t reg_snap_chain_reset_sys_insns = 0;
    uint64_t reg_snap_chain_reset_first_pc = 0;
    /* The case-(b) fault fold's own arms.  _kept is the in-flight prefix the
     * fold now folds INTO the merged true BB because it continues into the
     * faulting TB — the instructions the old unconditional reset dropped.
     * _discontinuous is the arm that is still destroyed: a live chain that
     * does not continue into @prev is a different block, and sealing it
     * needs an emission path the event context does not have.  It is
     * counted separately so it is a named work item with a tripwire rather
     * than a residue folded into the general reset counter. */
    uint64_t fold_prev_prefix_kept = 0;
    uint64_t fold_prev_prefix_kept_insns = 0;
    uint64_t fold_prev_prefix_discontinuous = 0;
    uint64_t fold_prev_prefix_discontinuous_insns = 0;

    /*
     * WINDOW-CLOCK vs WIRE accounting.
     *
     * The comparison this arc has been quoting is OWNED_CP (Σ over the
     * trace's non-system templates of exec_cp × n_insns, read back out of
     * the wire by cst_decode --templates-only) against user_covered
     * (g_user_icount at the segment's close, scraped from the finish line).
     * Read as "everything the window billed reached the wire", that
     * comparison is weaker than it looks in two ways, and neither is visible
     * from either number:
     *
     *   - Both sides are TB-entry arithmetic over the same template
     *     n_insns.  The window clock bills a dispatched TB's whole
     *     instruction count from the unconditional inline-add; the wire
     *     records the emitted entry's whole template n_insns.  A block that
     *     is entered and does NOT run to its end — the END-marker block is
     *     one on every marker run — is over-counted by exactly the same
     *     amount on both sides, so the two agree precisely because they are
     *     wrong together.  Agreement is not evidence of retirement.
     *
     *   - The clock's bill is a DELTA of consecutive insn_count reads, not
     *     the dispatched TB's own instruction count.  Anything that retires
     *     instructions between two owned dispatches without being billed on
     *     its own dispatch lands inside the next owned TB's delta and is
     *     billed to the owned process.  Subtracting OWNED_CP from
     *     user_covered shows a residual but names nothing.
     *
     * These count both sides at their source so the residual is measured
     * rather than inferred, and so the second effect is caught where it
     * happens instead of at the end.
     */
    /* User (non-system) architectural instructions actually EMITTED to the
     * body stream this segment — the plugin-side twin of OWNED_CP, with no
     * decoder in the loop. */
    uint64_t wire_user_arch_insns = 0;
    /* Of wire_user_arch_insns, the entries produced by SELF-LOOP FAN-OUT
     * beyond the instruction's single architectural start: Σ(n_iter - 1)
     * over user blocks whose terminal instruction was fanned out.  See the
     * increment site for why the retired cursor cannot see these. */
    uint64_t wire_user_rep_extra_insns = 0;
    /* User architectural instructions ATTRIBUTED BY THE PER-EXEC SEAL WALK,
     * counted per TB fragment before chain folding.
     *
     * What it cannot count: the segment-close walk (PathBuilder::flush_final)
     * and the fault-fold emissions do not run attribute_cp_insns, so their
     * blocks reach the wire without passing through here.  It is therefore a
     * LOWER bound on what was emitted and can read BELOW wire_user_arch_insns
     * — on a marker cell by exactly the END block's instruction count.  Read
     * it as "the per-exec walk's own view", not as a checkpoint every
     * emission passes. */
    uint64_t cp_user_seal_insns = 0;
    /* TBs whose delta was folded into g_user_icount, and the instructions
     * folded.  wire_user_arch_insns minus this is the residual OWNED_CP vs
     * user_covered was standing in for. */
    uint64_t user_clock_billed_tbs = 0;
    uint64_t user_clock_billed_insns = 0;
    /* Bills whose delta did NOT equal the dispatched TB's own architectural
     * instruction count, and the excess instructions in them.  This is the
     * clock billing the owned process for work that was not the owned TB —
     * a foreign process's user instructions retired since the last owned
     * dispatch, most visibly a fork child's. */
    uint64_t user_clock_bill_mismatch_tbs = 0;
    uint64_t user_clock_bill_excess_insns = 0;
    /* Bills taken with no template for the dispatched TB.  Such a TB cannot
     * reach the wire, so every instruction billed here is billed-not-traced
     * by construction. */
    uint64_t user_clock_bill_no_template = 0;
    /* What the owned process's dispatches ACTUALLY EXECUTED, from the
     * per-instruction insn_started slot rather than the per-TB inline add
     * (see VCPUScoreBoard::insn_started).  Lagged one dispatch — the
     * instructions observed at dispatch N belong to the TB dispatched at
     * N-1 — and completed by the segment close, which folds the in-flight
     * block's own executed prefix.
     *
     * user_clock_billed_insns minus this is the phantom bill: instructions
     * the window clock charged the owned process for that no instruction
     * ever executed.  It is not a rounding term; it is exactly the tail of
     * every TB the guest entered and did not run to the end. */
    uint64_t user_clock_retired_insns = 0;
    /* Retired folds whose delta exceeded the TB they were attributed to, and
     * by how much: instructions that executed between two dispatches without
     * being dispatched themselves (a context the trace_this_ctx gate skips)
     * and so were charged to the owned process.  The retired clock has
     * exactly the exposure the TB-entry bill had; this is what keeps it
     * measured rather than assumed.  Must be 0. */
    uint64_t user_clock_retired_over_tb = 0;
    uint64_t user_clock_retired_over_insns = 0;
    /*
     * THE RE-CREDIT insn_started's contract promises.
     *
     * The slot counts instructions BEGUN.  Every mid-flight abandonment the
     * guest takes re-runs the instruction it abandoned, so that instruction
     * is counted twice while it retires once:
     *
     *   user_clock_fault_recredit* — a re-executing FAULT.  QEMU pushes a
     *     FAULT_ENTER only for those, and the merge emits the faulting block
     *     whole exactly once, so the bill is over by (instructions started
     *     in the aborted attempt) - (the index the handler resumes at): 1
     *     for an ordinary data fault, 2 on a MIPS branch-delay-slot fault.
     *   user_clock_abort_recredit* — an abandonment with NO exception
     *     (cpu_io_recompile, cpu_loop_exit_atomic, a MOPS / REP re-entry),
     *     recognised at the fold by the guest standing on the abandoned
     *     instruction for its re-execution.  Always exactly 1.
     *
     * The two *unplaced / *unmeasured counters are the correction's own
     * blind spots, named rather than absorbed: a resume PC that is not an
     * instruction of the attempt, and a seal deferred past its own dispatch
     * (no retired delta of its own to read).  Both leave the clock reading
     * high by the amount they could not place.
     */
    uint64_t user_clock_fault_recredits = 0;
    uint64_t user_clock_fault_recredit_insns = 0;
    uint64_t user_clock_fault_recredit_unplaced = 0;
    uint64_t user_clock_fault_recredit_unmeasured = 0;
    uint64_t user_clock_abort_recredits = 0;
    uint64_t user_clock_abort_recredit_insns = 0;
    /* Templates minted for blocks the guest ENTERED AND DID NOT FINISH (see
     * TemplateStore::commit_partial_bb).  Keyed by extent, so repeated cuts
     * at the same point share one; a run where nothing is ever cut short
     * mints none. */
    uint64_t partial_bb_templates_created = 0;
    /* Blocks emitted at a TRUNCATED extent by the segment-close walk, and
     * the instructions the truncation kept off the wire because they never
     * executed.  A marker-window run has exactly one such block — the END
     * block — on every single run; a reading of zero here on a marker cell
     * means the close stopped truncating, not that nothing was cut. */
    uint64_t close_walk_blocks_truncated = 0;
    uint64_t close_walk_insns_not_executed = 0;
    /* Segment-close walks that could not learn how much of the in-flight
     * block executed, and so emitted it at its full translated extent.  The
     * retired cursor answers for the two dispatch positions a close can
     * land on; anything else is an unmeasured close and this is the only
     * thing standing between it and a silent over-claim.  Must be 0. */
    uint64_t close_walk_extent_unknown = 0;
    /* Close walks whose extent came from the measurement taken at the first
     * dispatch after prev, because the retired cursor had rolled past it
     * (see PathBuilder::note_prev_extent).  Non-zero is ordinary on an SMP
     * guest whose pinned process migrated; it is what keeps
     * close_walk_extent_unknown at 0 there instead of folding a peer's
     * block at its full translated length on no evidence. */
    uint64_t close_walk_extent_from_stash = 0;
    /* Pending-seal slots flushed at a segment close from a vCPU OTHER than
     * the closing one.  Each is a TB the pinned process executed on a vCPU
     * it then left; they used to be dropped.  Non-zero exactly when the
     * process migrated.
     *
     * close_peer_insns_recovered is the DELTA IN EMITTED ARCH INSTRUCTIONS
     * across the flush, minus the share the frame drain claims — what
     * reached the wire, not what the slot held.  It used to be
     * tb_head_insns(prev) added BEFORE the flush and never checked against
     * it, which reported "1 peer slot flushed / 3 insns recovered" in 24 of
     * 24 single-core cells where nothing was at risk and nothing was
     * emitted, and quoted the slot's FULL translated length even where the
     * flush correctly truncated to what ran.
     *
     * close_peer_slots_emitted_nothing is that case named: a slot held a
     * block and the flush emitted none of it.  Non-zero is not by itself a
     * defect (a peer slot whose block the walk truncates to zero has nothing
     * to emit, and the clock never billed it either), but it is the number
     * the old instrument was silently reporting as a recovery. */
    uint64_t close_peer_slots_flushed = 0;
    uint64_t close_peer_insns_recovered = 0;
    uint64_t close_peer_user_insns_recovered = 0;
    uint64_t close_peer_slots_emitted_nothing = 0;

    /* ---- CLOSE CENSUS (CST_CLOSEDROP) --------------------------------
     *
     * THE WHOLE CLASS, NOT ONE HOLDER AT A TIME.  Five rounds each fixed a
     * single structure that was holding retired-but-unemitted work at a
     * segment close, and each time the next verifier found another one.
     * These are the ledger side of the census that enumerates them: for
     * every holder, how many occupants ENTERED it and how each one LEFT,
     * so "entered == fated + held_at_close" is an arithmetic identity a
     * run either satisfies or visibly breaks.  A holder whose occupants
     * are still in it at the close is a DROP unless a drain named below
     * emitted them.
     *
     * The occupancy half is printed per close by
     * PathBuilder::close_state_report (pre-flush and post-flush lines);
     * these counters are what make the two halves add up across a run.
     *
     * Frames (PathBuilder::frames_):
     *   opened               classify_fault_enter pushed a CtxFrame
     *   merged               complete_merge emitted the reassembled BB
     *   unwound_emitted      flush_frame_unwound put its prefix on the wire
     *   unwound_dropped      flush_frame_unwound had no stream / no
     *                        template and erased it silently — an
     *                        UNCOUNTED drop before this census
     *   faults0_dropped      faults=0 nested-handler frame discarded
     *   orphan_dropped       on_segment_open cleared it (its full_tmpl
     *                        dangles into the cleared bb_map_) — likewise
     *                        uncounted before this census, and the
     *                        susp_stack_ twin HAS had a counter since
     *                        Stage 3
     *   held_at_close        still in frames_ at a close, summed over the
     *                        POST-flush census (so the close-flush's own
     *                        recoveries are already subtracted)
     *
     * Pending-seal slot (PathBuilder::prev_tb_):
     *   prev_promoted        set_prev installed a block
     *   prev_close_walked    a close's flush_final walked it
     *   prev_close_dropped   a close did NOT walk it although it held a
     *                        block (the prev_executed=false routes), with
     *                        the RETIRED extent that went with it
     *
     * The remaining holders have no lifecycle counter of their own because
     * they are sinks, not queues: what matters is the depth left in them
     * when the last drain has run, which is exactly what the post-flush
     * census records here. */
    uint64_t census_closes = 0;
    uint64_t census_frames_opened = 0;
    uint64_t census_frames_merged = 0;
    uint64_t census_frames_unwound_emitted = 0;
    uint64_t census_frames_unwound_dropped = 0;
    uint64_t census_frames_faults0_dropped = 0;
    uint64_t census_frames_orphan_dropped = 0;
    uint64_t census_frames_held_at_close = 0;
    uint64_t census_frames_held_insns = 0;
    uint64_t census_prev_promoted = 0;
    uint64_t census_prev_close_walked = 0;
    uint64_t census_prev_close_dropped = 0;
    uint64_t census_prev_close_dropped_insns = 0;
    uint64_t census_walkprev_held_at_close = 0;
    uint64_t census_susp_held_at_close = 0;
    uint64_t census_susp_held_insns = 0;
    uint64_t census_chain_held_at_close = 0;
    uint64_t census_chain_held_insns = 0;
    uint64_t census_snaps_held_at_close = 0;
    uint64_t census_snapmark_held_at_close = 0;
    uint64_t census_cpmem_held_at_close = 0;
    uint64_t census_cpcarry_held_at_close = 0;
    uint64_t census_evs_held_at_close = 0;
    uint64_t census_repfacts_held_at_close = 0;
    uint64_t census_wmhold_held_at_close = 0;
    uint64_t census_devio_held_at_close = 0;
    uint64_t census_wpmem_held_at_close = 0;
    /* Closes at which the fate identity above did NOT hold for some
     * holder.  Must be 0; any other value means a fate exists that this
     * census cannot name, which is the exact failure mode of every
     * previous one-holder-at-a-time round. */
    uint64_t census_balance_broken = 0;

    /* ---- THE CLOSE DRAINS (one per holder the census enumerated) ------
     *
     * The census's job was to name every structure that can hold work the
     * guest RETIRED and the tracer has not put on the wire at a segment
     * close.  These are the drains: each empties one holder onto the wire,
     * each has a falsifier env var that turns it off so the defect it
     * removes can be made to reappear, and each has a row below that MUST
     * BE 0 for "held something at the close and could not emit it".
     *
     * SUSPENSIONS (PathBuilder::susp_stack_).  A suspension freezes five
     * things at once: the deferred prev block and its retired extent, its
     * committed CP memops, its per-insn dst snaps and their chain mark, the
     * in-flight chain prefix, and its self-loop facts.  No close route read
     * it; its only exits were a resume, an over-cap displacement, a stale
     * sweep and the next segment open's orphan drop -- and the two middle
     * ones emit the FRAME whose resume suffix the prev is, never the
     * suspension's own contents.  flush_suspensions_at_close walks each one
     * at its frozen extent, from its own frozen sinks, at its own depth. */
    uint64_t close_susp_flushed = 0;
    uint64_t close_susp_insns_recovered = 0;
    uint64_t close_susp_user_insns_recovered = 0;
    uint64_t close_susp_sys_insns_recovered = 0;
    uint64_t close_susp_empty = 0;          /* held a block that ran 0 insns */
    /* A suspension whose frozen extent measurement was invalid: the walk
     * cannot name what retired, so it folds the block whole.  Must be 0 --
     * a non-zero row means the wire may claim instructions the guest did
     * not execute (the suspend-side twin of close_walk_extent_unknown). */
    uint64_t close_susp_extent_unknown = 0;
    /* A suspension held at a close with no body stream to emit into.  This
     * IS the drop and nothing can undo it; must be 0. */
    uint64_t close_susp_unflushable = 0;

    /* PEER BUILDERS.  The peer loop gated on the pending-seal slot alone
     * (`if (!b || !b->prev()) continue;`), so a peer vCPU holding open
     * fault frames, a suspension, an in-flight chain or a reg-snap sink
     * with an EMPTY slot was skipped whole -- and with it
     * flush_frames_at_close, which is reachable only through flush_final.
     * Measured: sd_smp4 vCPUs 2 and 3, ceil2 vCPUs 1 and 2, each holding a
     * frame and a suspension behind prev=0x0.  The gate now asks whether
     * the builder holds ANYTHING. */
    uint64_t close_peer_holder_flushes = 0;
    uint64_t close_peer_holder_insns_recovered = 0;
    /* A peer builder that held work at the close and was NOT flushed.
     * Reachable only through CST_NO_PEER_FLUSH / CST_NO_PEER_HOLDERS; must
     * be 0 on any capture. */
    uint64_t close_peer_holders_skipped = 0;

    /* THE DEFERRED ROUTE'S PENDING-SEAL SLOT.  flush_final(walk_prev=false)
     * did not walk the slot at all.  For the budget / simpoint close that
     * is right -- the slot holds the TB about to dispatch, measured ran=0.
     * For the SHUTDOWN close it is a drop: the slot holds the block the
     * device write interrupted, and its retired prefix goes with it.
     *
     * The prefix is exactly what retired and nothing more.  insn_started is
     * added at the TOP of an instruction, so a close taken from a MID-
     * INSTRUCTION callback (the device write) reads the in-flight
     * instruction as already begun; the drain subtracts it, because an
     * instruction that has not completed has not delivered all its memops
     * (the bimodality oracle that vetoed emitting this slot whole). */
    uint64_t close_deferred_prev_walked = 0;
    uint64_t close_deferred_prev_insns = 0;
    uint64_t close_deferred_prev_inflight_trimmed = 0;
    /* The deferred route held a block and no extent could be measured for
     * it, so nothing could be emitted without guessing.  Must be 0. */
    uint64_t close_deferred_prev_extent_unknown = 0;

    /* THE SINKS, after every drain above has run.  These are residues, not
     * queues: whatever is left once the last block is emitted belonged to
     * an instruction that did not reach the wire.  Counted at the tail of
     * flush_final, where they used to be discarded silently.
     *
     * cpmem/cpcarry are NOT must-be-0: a close taken mid-instruction leaves
     * the in-flight instruction's partial memops behind by design, and they
     * are correctly discarded (the instruction did not retire). */
    uint64_t close_snaps_dropped = 0;
    uint64_t close_cpmem_dropped = 0;
    uint64_t close_cpcarry_dropped = 0;
    uint64_t close_evs_dropped = 0;
    uint64_t close_repfacts_dropped = 0;

    /* THE WHOLE-CLASS GATE.  Read on the POST-flush census pass, per
     * builder: after every drain this close performs, is any structure
     * that can contain RETIRED instructions still occupied?  A pending-seal
     * slot with a measured retired extent, an open fault frame with an
     * executed prefix, any suspension, an in-flight chain with
     * instructions.  Must be 0 -- this is the row that fails the cell when
     * a holder is added, or when a falsifier turns a drain off, and it does
     * not depend on remembering to add a row per new holder. */
    uint64_t close_holder_undrained = 0;
    uint64_t close_holder_undrained_insns = 0;

    /* THE LATENT HOLDER (PathBuilder::walk_prev_).  The cross-phase
     * snapshot the seal walk folds is undrained and non-zero at nearly
     * every close, but in every close route that exists today it is
     * POST-SEAL: already emitted.  It becomes a live drop the instant a
     * close is taken between step_events and step_seal -- the window
     * tw_manage_window occupies.  Nothing asserted that ordering; this
     * does.  Must be 0. */
    uint64_t close_in_mid_step = 0;

    /* A wrong-path session still open on a vCPU at a close.  While one is,
     * MemAccessRecorder::record routes CORRECT-path memops into the WP
     * buffer, so this is a correct-path holder wearing a speculative hat.
     * Must be 0. */
    uint64_t close_wp_session_open = 0;
    /* The same three quantities for the PER-EXECUTION seal walk
     * (collect_finalized_bbs).  A guest instruction that touches device
     * MMIO from anywhere but its TB's last slot, an atomic that needs
     * serial execution, a MOPS / REP re-entry — each abandons the TB with
     * NO exception (cpu_io_recompile -> cpu_loop_exit_noexc and friends), so
     * no fault or async event exists and the seal used to fold the fragment
     * at its full translated length: instructions the dispatch never ran
     * reached the wire, the next block re-covered them, and the short
     * reg-snap slice was thrown away wholesale by the emit-time backstop.
     *
     * seal_walk_aborted_tails is the subset where the abandoned instruction
     * had already STARTED (its insn_started add fired) and the guest is
     * standing on it for the re-execution — i.e. where the retired cursor
     * had to be read one short.  Unlike the close walk's, these do NOT have
     * to be zero: they are the condition being handled, and a run through
     * kernel device code has them.  What must be zero is what they used to
     * cost — reg_snap_slice_dropped and the wire's duplicate instructions.
     *
     * seal_walk_extent_unknown MUST be 0.  It used to be excused — a seal
     * DEFERRED past its own dispatch has no retired delta of its own to
     * read, so the walk folded prev at its FULL translated length on the
     * argument that an interrupt or a foreign span is taken at a TB
     * boundary.  That argument is unfalsifiable from inside the walk: the
     * successor PC being interior to the folded block is ambiguous (a block
     * abandoned mid-flight and a block that ran whole and branched into its
     * own middle look identical), so the only sound answer is to never be
     * without a measurement.  There always is one — it is taken at the first
     * dispatch after prev (PathBuilder::note_prev_extent), which is exactly
     * the step whose seal was deferred — and every reading of this counter
     * has turned out to be a path that THREW THAT MEASUREMENT AWAY rather
     * than a genuinely unanswerable question:
     *   - a seal with no prev at all (the segment's first walk) asked the
     *     question about a null block and counted the non-answer;
     *   - a SELF-BRANCHING TB (cur == prev) skipped set_prev's carry
     *     entirely, so the walk asked about the block it was folding while
     *     the answer sat filed under the previous block's name.
     * Both are closed.  CST_NO_SEAL_STASH is the falsifier arm that shows
     * this counter can still fire: with the stash refused it reads 16-19 per
     * riscv64 system cell and drags seal_walk_extent_unknown_interior with
     * it. */
    uint64_t seal_walk_blocks_truncated = 0;
    uint64_t seal_walk_insns_not_executed = 0;
    uint64_t seal_walk_aborted_tails = 0;
    uint64_t seal_walk_extent_unknown = 0;
    /* Deferred seals whose extent came from the measurement taken at the
     * first dispatch after prev (PathBuilder::seal_prev_extent) instead of
     * from the retired cursor, which cannot answer for them.  Non-zero is
     * ordinary; it is what keeps seal_walk_extent_unknown_interior at 0
     * rather than folding a deferred prev at its full translated length. */
    uint64_t seal_walk_extent_from_stash = 0;
    /* The unknown-extent argument's own falsifier, and the proof that the
     * probe which states it can fire.
     *
     * seal_walk_extent_unknown_interior counts unknown-extent seals whose
     * successor PC is one of the folded block's OWN instructions past its
     * first — i.e. the guest was standing inside the block the walk had just
     * claimed ran to completion.  That is an over-claim on the wire and a
     * duplicate in the block that resumes there, so this one MUST be 0;
     * _insns is what it would have cost.
     *
     * seal_walk_interior_probe_hits is the same lookup performed where the
     * retired cursor already knows the answer (the aborted-tail arm).  It is
     * there so the zero above is a zero from an instrument shown able to
     * fire, not a zero from one that never looked. */
    uint64_t seal_walk_extent_unknown_interior = 0;
    uint64_t seal_walk_extent_unknown_interior_insns = 0;
    uint64_t seal_walk_interior_probe_hits = 0;

    /* Self-loop fan-out: where the iteration count came from.
     *
     * rep_iters_architectural — QEMU published an iteration count for this
     *   instruction (x86 REP: the loop counter's own decrement) and it was
     *   used.  The count is then independent of how QEMU translated the REP,
     *   so a run under -icount / single-step and one under neither produce
     *   the same number of entries.
     * rep_iters_inferred — no architectural count was available and the
     *   count came from delivered memops / the fan-out unit.  Expected for
     *   the AArch64 FEAT_MOPS family, whose fan-out unit is one memory
     *   access rather than an architectural element; on x86 it means the
     *   accounting did not reach the emission (a deferred or merged
     *   emission) and should be rare.
     * rep_iters_memop_mismatch — the delivered REP memop stream is not the
     *   length the architectural count calls for, which is n_iter*mpi PLUS
     *   the aborted-attempt surplus the fault-split prefix recorded.  It
     *   means capture was suppressed for part of the stream, and nothing
     *   else: a COMPLETENESS check.
     *
     *   It is specifically NOT a fault detector.  A fault landing inside an
     *   iteration delivers that iteration's completed part and then
     *   re-delivers the whole iteration on resume; both runs are inside the
     *   prefix totals, so they cancel out of the expected length exactly.
     *   The same holds per piece when several faults split one REP.
     *   Measured (cst_runs/x86close, probes/multifault.S): a rep movsb
     *   taking FOUR mid-iteration demand faults leaves this counter at 0 on
     *   a build whose per-iteration memop pairing is wrong for 12289 of its
     *   12800 iterations.  Pairing is carried by the piece table
     *   (CtxFrame::rep_pieces), never by this counter, and a reader who
     *   treats a zero here as evidence about fault handling is reading a
     *   number that cannot answer the question.
     * rep_trailing_pass_dropped — a zero-iteration re-entry of a REP already
     *   in flight, i.e. the extra pass a single-iteration translation makes
     *   after the final iteration.  Not a retired instruction; suppressed so
     *   the trace's instruction count does not depend on the translation.
     * rep_exit_edge_recovered — a retiring REP whose observed successor was
     *   its own PC (the same single-iteration translation jumps back before
     *   taking the zero-count exit); the emitted terminal edge was restored
     *   to the architectural fall-through. */
    uint64_t rep_iters_architectural = 0;
    uint64_t rep_iters_inferred = 0;
    uint64_t rep_iters_memop_mismatch = 0;
    uint64_t rep_trailing_pass_dropped = 0;
    uint64_t rep_exit_edge_recovered = 0;
    /* rep_piece_table_degenerate — a fault-split REP emission arrived with a
     * per-piece prefix table it could not use, so the emission fell back to
     * the total-based split rather than mis-place slices.
     *
     * The nominal condition is a piece delivering fewer REP memops than its
     * own retired iterations require: capture suppressed part-way through
     * that piece, so its recorded boundary is not where the stream's
     * boundary is.  Audited unreachable-by-construction (x86s2 item E, and
     * 0 across the whole adversarial corpus with the PRECONDITION counter
     * rep_iters_memop_mismatch also 0): a piece table exists only for
     * pinned faults=1 content, whose sync services never mute; interrupts=1
     * never mutes; interrupts=0 mutes handler interiors only and the
     * abandoned-window recovery force-unmutes the resume TB at its own
     * dispatch, before its body callbacks; foreign and wrong-path capture
     * never reaches the pinned CP recorder.  Every suppression mechanism is
     * therefore disjoint from the retired iterations of a piece-carrying
     * instruction.  Both this and the accompanying sum check (a seam
     * tripwire — collect_piece appends each pair in the statement that adds
     * it to the totals) guard FUTURE capture-gating edits; a firing is a
     * mis-pairing emission and is reported to the unknown-warnings sidecar,
     * never just counted. */
    uint64_t rep_piece_table_degenerate = 0;
    /* window_close_in_fanout — a deferred window close was taken while this
     * vCPU still had a fan-out instruction architecturally in flight (any
     * privilege, any fault depth — the hold table arms from every
     * emission carrying an architectural iteration count, and holds
     * through kernel services and peer-thread user TBs).  Reachable only
     * through the hold's numeric ceiling, so a nonzero here always pairs
     * with window_close_fanout_hold_capped and names a close that DID end
     * the trace inside an instruction (bounded-overrun by design, never a
     * hang).  Counted from the pc-keyed hold table, not the cp_in_flight
     * scalar: that latch is last-writer-wins and an interleaved completing
     * REP masks the in-flight one (measured reading 0 across a
     * 651390-of-50000000 on-wire split — cst_runs/x86s2 item B). */
    uint64_t window_close_in_fanout = 0;
    /* window_close_fanout_hold_capped — the fan-out hold on a deferred window
     * close hit its consecutive-evaluation ceiling and was abandoned, so that
     * close was taken with an instruction still latched in flight.  Nonzero
     * means either a hold that never released (a fan-out the guest abandoned)
     * or a legitimate span longer than the ceiling; either way the window
     * ended where the hold was supposed to prevent, and the ceiling is what
     * kept it from ending never. */
    uint64_t window_close_fanout_hold_capped = 0;
    /* warmup_boundary_hold_defers — a §2.13 warmup-boundary placement was
     * deferred past one record because a fan-out instruction was
     * architecturally in flight (the record was the held pc itself, a
     * kernel service, or a PEER guest thread's user record — the same
     * per-slot predicate as the deferred-close hold).  Condition counter:
     * proves the hold engaged; one bump per record deferred past. */
    uint64_t warmup_boundary_hold_defers = 0;
    /* warmup_boundary_unplaced_at_finish — the segment closed with the
     * §2.13 crossing latched, the boundary still deferred by the
     * fan-out hold, and at least one record deferred past: the header
     * keeps the sentinel (no placement provably avoids splitting an
     * instruction whose end was never observed), and this counter plus
     * a stderr line name it.  The boundary hold has NO numeric ceiling
     * (unlike the close hold's CST_FANOUT_HOLD_MAX): it is a header
     * field, not a liveness event, and a forced placement would
     * re-introduce the split. */
    uint64_t warmup_boundary_unplaced_at_finish = 0;
    /* warmup_boundary_in_fanout — the §2.13 warmup boundary was placed
     * while a hold slot was still active, i.e. every live slot was
     * structurally released (an ownerless dispatch arm, or the holder's
     * own thread at another user pc — which includes the
     * identity-indistinguishable no-SETTLS peer).  Names a POSSIBLE
     * split of one architectural instruction's records across the
     * warmup/measure line; the cross-thread silent split this replaces
     * was measured on probes/threadrep.S (cst_runs/x86s2 item B,
     * ported here). */
    uint64_t warmup_boundary_in_fanout = 0;
    /* marker_wp_fenced_start / _end — invocations of the START/END
     * marker exec callbacks dropped by the wrong-path fence
     * (speculation routinely runs the marker bytes: the wrong path of a
     * spin-wait branch falls straight into the END sequence).  Condition
     * counters: a zero over a run with WP enabled means the workload's
     * marker bytes were never speculatively executed, NOT that the
     * fence is idle-safe. */
    uint64_t marker_wp_fenced_start = 0;
    uint64_t marker_wp_fenced_end = 0;
    /* marker_fence_session_only — a marker callback was dropped where
     * ONLY the per-vCPU WP-session gate fired: the QEMU-side spec-mode
     * flag AND the walker thread's g_wp_state.in_progress both read
     * false while this vCPU was inside a wrong-path session bracket.
     * This is exactly the leak shape the pre-fence 385k-insn END close
     * (matrix_prepush/tt_sys_x86b) implied and the two-flag fence could
     * not name; MUST be 0 — nonzero means a speculative invocation
     * reached the run-state machine's doorstep past both flags and was
     * stopped only by the session gate. */
    uint64_t marker_fence_session_only = 0;

    /*
     * INVARIANT TRIPWIRES and CONDITION COUNTERS.
     *
     * The marker is decided in the bytes at translation time and fires from
     * one instruction (see champsim_tracer_marker_detect.h), so there is no
     * run to break, hand off or leave outstanding.  What remains are the
     * ways a correct-path marker can still be LOST, which are about the
     * wrong-path fence, not about detection.
     *
     * marker_prefix_unreadable — CONDITION, not a tripwire.  An instruction
     *   that IS the terminating instruction of a marker sequence, whose
     *   preceding slots could not be read from guest memory when it
     *   executed.  It does NOT mean those slots did not execute: on a
     *   software-managed TLB (mipsel) the read fails for a page that is
     *   still mapped, once its TLB entry has been evicted by the kernel code
     *   that ran between the two halves of the sequence.  This counter is
     *   therefore how often the exact source could not be consulted, and
     *   nothing more; a straddling sequence is decided from its physical
     *   page pair instead (marker_straddle_*).  See
     *   champsim_tracer_marker_detect.h for the measurement that falsified
     *   the older reading of this counter.
     * marker_straddle_pair_resolved — CONDITION.  Reads that could not be
     *   serviced and were answered by the sequence's physical page pair.
     *   Every one of these is a marker that the read alone would have lost.
     * marker_straddle_conflicts — MUST BE 0 in a single-binary capture.  Two
     *   DIFFERENT predecessor physical pages recorded behind the same tail
     *   physical page: the address-space reuse case.  Nonzero is not a bug —
     *   it is the guard firing — but it means the tail no longer determines
     *   the pair and those sequences fall back to the read alone.
     * marker_straddle_undecided — CONDITION, and the sharp one.  A
     *   marker-shaped instruction whose sequence spans two pages, whose read
     *   could not be serviced, AND for which no physical page pair was ever
     *   witnessed.  Nonzero has exactly one benign shape: a LONE
     *   marker-terminating instruction at the start of a page whose
     *   predecessor page was never executed as marker prefix — the bytes
     *   before it are not a sequence and nothing should be claimed.  The
     *   adversarial `chaff` cell builds that on purpose and reads 2 per
     *   execution of it (one per armed callback).  What it can NOT be is a
     *   sequence that really ran: the predecessor page's own translation
     *   witnesses it while that page is resident, and the witness is what
     *   the pair is built from.  So on any cell WITHOUT a deliberate lone
     *   tail this is 0, and a nonzero there is the missed-marker defect
     *   coming back.
     * marker_end_suppressed  — MUST BE 0.  An END marker executed on the
     *   CORRECT PATH and the wrong-path fence dropped it anyway: the
     *   execution was demonstrably not speculative (QEMU's spec-mode flag
     *   clear AND this thread not inside the walker), so only a LEAKED
     *   session bracket can have suppressed it, and the window it should
     *   have closed is still open.  Tested ahead of the fence's return in
     *   vcpu_marker_end_cb, which is the only place it CAN be tested: the
     *   drop is the violation, and a counter placed after it is
     *   structurally blind to the case it exists to name.  Positive
     *   control: CST_FENCE_FORCE_END.
     * marker_end_no_close    — CONDITION, not a tripwire.  An END marker
     *   completed on the correct path in an address space this trace does
     *   not own, so nothing closed.  Expected whenever a process this trace
     *   does not own runs an END sequence, which byte-decided detection
     *   sees and the old adjacency run usually did not.  Split from
     *   marker_end_suppressed for exactly that reason: fusing an expected
     *   condition with a violated invariant makes the invariant
     *   unenforceable.
     * wp_session_on_cp       — MUST BE 0.  A wrong-path session bracket was
     *   still flagged while this vCPU ran the CORRECT path: a leaked fence
     *   flag, which would silently drop every subsequent marker callback on
     *   that vCPU and leave its window open forever.  Tested at TWO points,
     *   and it needs both: the correct-path step (which the JIT dispatches
     *   only for an owned context inside a window, and not at all during the
     *   pinned-simpoint fast-forward), and every committed address-space
     *   write (which fires regardless of ownership, window and
     *   fast-forward).  Positive control: CST_FENCE_FORCE_SESSION.
     */
    uint64_t marker_prefix_unreadable = 0;
    uint64_t marker_straddle_pair_resolved = 0;
    uint64_t marker_straddle_conflicts = 0;
    uint64_t marker_straddle_undecided = 0;
    uint64_t marker_end_suppressed = 0;
    uint64_t marker_end_no_close = 0;
    /* An END that executed on the correct path, could not be attributed to
     * any owner, and closed the capture anyway.  MAINTAINER RULING
     * (2026-08-02): "END kills the tracer, regardless of simpoints, just
     * like a program ending in user mode would do."  Nonzero means the
     * ownership machinery could not name the ender — worth investigating —
     * but the trace still ends where its workload does, which is the
     * invariant that cannot be traded. */
    uint64_t marker_end_forced_close = 0;
    /* An END whose owner the learned-code-page probe could not name, and
     * which the SOLE open window claimed instead.  Narrow-ASID (MIPS) only:
     * an END running out of a page mapped after the START — a JIT stub, a
     * run-time-built sequence — is invisible to a page map.  Nonzero is
     * ordinary; it is what keeps marker_end_forced_close at 0. */
    uint64_t wp_session_on_cp = 0;
    /* Worst stall: architectural instructions retired in an owned context
     * between two advances of the pinned user clock (diagnostic — the
     * quantity the stall ceiling bounds).  stall_ceiling_closes counts
     * segments the ceiling ended. */
    uint64_t user_clock_worst_stall = 0;
    uint64_t stall_ceiling_closes = 0;
    /* The same quantity counted over EVERY context, so it keeps rising
     * while the traced process is not running at all; and the closes the
     * any-context ceiling raised. */
    uint64_t user_clock_worst_stall_any = 0;
    uint64_t stall_any_closes = 0;
    /* Owned marker windows retired by the dead-latch detector, split by
     * which denominator crossed: the wall-clock timeout (latch_timeout) or
     * the guest-instruction idle (latch_idle_insns).  Both are per-window,
     * not per-segment: several may be counted before the set empties and
     * the segment closes.  Nonzero on either means at least one traced
     * process was judged dead WITHOUT having run its END marker, so its
     * strand of the trace stops where the detector fired rather than where
     * the workload finished. */
    uint64_t dead_latch_closes_ms = 0;
    uint64_t dead_latch_closes_insns = 0;
    /* Segments closed by the machine-shutdown backstop: the guest powered
     * off (or QEMU was asked to exit) with a capture still open, so the
     * window was closed and finalised there rather than abandoned.  A
     * nonzero value means the trace is TRUNCATED at that point and the
     * workload never reached its END marker. */
    uint64_t vm_shutdown_closes = 0;

    /*
     * rep_unretired_pass_dropped — an empty leading pass of a fan-out
     * instruction (nothing retired, nothing delivered — a FEAT_MOPS bulk
     * op whose first byte faulted) was suppressed; its re-execution
     * carries the instruction's single rendering.
     *
     * rep_unretired_pass_kept — the same facts arrived on a shape the
     * drop does not cover (multi-insn block or with deliveries); kept on
     * the wire and counted for visibility.
     *
     * mops_bytes_checked / _mismatch / _unchecked — FEAT_MOPS anchor:
     * on a cleanly completed single-execution bulk op the delivered
     * access sizes must sum to the architectural byte progress QEMU
     * published from the size register's own decrement.  _mismatch is a
     * reporting defect (or a dropped stale run after an abandoned bulk
     * op) and the MOPS probes gate on it staying 0; _unchecked counts
     * instances whose access sizes were not captured (memdata off).
     */
    uint64_t rep_unretired_pass_dropped = 0;
    uint64_t rep_unretired_pass_kept = 0;
    uint64_t mops_bytes_checked = 0;
    uint64_t mops_bytes_mismatch = 0;
    uint64_t mops_bytes_unchecked = 0;
    /* rep_clock_ticks_withheld — user-clock ticks withheld from counted REP
     * executions that ended by re-entering the instruction OFF a canonical
     * chunk boundary (per-iteration translation passes under icount /
     * single-step / TF).  Chunk-boundary re-entries keep their tick: the
     * window clock counts what the bbv plugin counts in the simpoint-
     * generation regime (canonical loop translation), which bills one
     * count per TB entry — the completing execution plus each REP_MAX
     * chunk — so the clock is translation-invariant AND bbv-coherent.
     * Under canonical translation this counter stays 0 by construction. */
    uint64_t rep_clock_ticks_withheld = 0;
    /* rep_ff_ticks_withheld — the same correction applied on the pinned-
     * simpoint fast-forward positioning clock (the exact per-TB phase and
     * the coarse countdown's REP add-back), where the traced-window fold
     * above never runs.  Splitting the counter keeps "positioning moved"
     * distinguishable from "window coverage moved". */
    uint64_t rep_ff_ticks_withheld = 0;

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
    /* Restore-to-entry accounting.  An ASID write whose new value is the
     * excursion's ENTRY value puts the entering address space back in force,
     * so the excursion's ownership continues: entry_restores counts every
     * such write and cut_retired_by_restore the subset that found a
     * committed-switch cut standing (the cut described an address space that
     * is no longer loaded, so the restore retires it).
     *
     * cut_declined_at_entry_asid is the INVARIANT: a kernel TB refused for a
     * committed switch while the live address-space register nonetheless
     * holds the excursion's own entry value.  Nothing can be both switched
     * away and switched back, so this must read 0 — it is the tripwire for
     * the sticky-cut defect (a cut that outlives the switch it describes).
     * It is stated in architectural terms on purpose: a flag-shaped version
     * ("declined in an excursion that once restored") cannot tell the defect
     * from a legitimate SECOND switch after the restore.
     *
     * post_restore_kept_* is the recovery census — kernel TBs admitted in an
     * excursion whose cut a restore retired, i.e. exactly the population the
     * defect refused; post_restore_kept_foreign_live is its own tripwire, the
     * subset admitted while the live register held neither the entry value
     * nor the kernel overlay (a genuine foreign leak would land here). */
    uint64_t kexc_entry_restores = 0;
    uint64_t kexc_cut_retired_by_restore = 0;
    uint64_t kexc_cut_declined_at_entry_asid = 0;
    uint64_t kexc_post_restore_kept_tbs = 0;
    uint64_t kexc_post_restore_kept_insns = 0;
    uint64_t kexc_post_restore_kept_foreign_live = 0;
    /* Decline-reason census: every refused kernel TB lands in exactly one of
     * no_user (the segment has not seen a user TB yet, so nothing owns the
     * excursion), not_owned (it was entered from a foreign user TB — the
     * dominant and CORRECT reason in a single-address-space trace) and cut (a
     * committed switch moved the address space mid-excursion).
     * not_owned_live_pinned narrows the middle one to the blocks whose live
     * address space is nonetheless the pinned process's: an excursion the
     * pinned process re-enters without an intervening user TB is latched to
     * the foreign entry, which is a SEPARATE attribution question from the
     * cut and is not adjudicated here. */
    uint64_t kexc_decl_no_user = 0;
    uint64_t kexc_decl_not_owned = 0;
    uint64_t kexc_decl_cut = 0;
    uint64_t kexc_decl_not_owned_live_pinned = 0;
    /* Async re-latch (interrupts=1 + kexc=1): a captured window snapshots
     * the excursion-ownership state at ASYNC_ENTER, and a genuine
     * ASYNC_RETURN in the owner's context restores it — the producer fires
     * only on a departure-PC re-fetch with the departure thread pointer, so
     * the machine is provably back in the interrupted excursion, and
     * whatever the window's foreign interleave did to the entry edge no
     * longer describes it.  The census mirrors the cut-restore one: TBs
     * kept after a re-latch are exactly the pinned excursion's post-window
     * tail a foreign-latched edge would have refused. */
    uint64_t kexc_async_snapshots = 0;
    uint64_t kexc_async_relatches = 0;
    uint64_t kexc_async_relatch_skipped = 0;
    uint64_t kexc_post_relatch_kept_tbs = 0;
    uint64_t kexc_post_relatch_kept_insns = 0;
    /* Task-identity kernel ownership (kexc=1, thread-pointer-tracking
     * targets).  A kernel TB is the work of the task EXECUTING it, and on a
     * target whose thread-pointer register still names the current task at
     * kernel privilege that identity is directly readable — where the
     * entry-edge inference (ownership of the last user TB this vCPU ran)
     * mis-latches whenever the pinned process re-enters the kernel with no
     * intervening own user TB, the register does not.  kept/dropped
     * partition every kernel keep decision the identity rule made; the
     * disagreement pair measures exactly where it and the entry-edge rule
     * differ (recovered = edge refused / identity kept: the foreign-latch
     * refusals; excluded = edge kept / identity refused: the borrowed-mm
     * kthread and post-switch foreign tails the edge rule leaked). */
    uint64_t kexc_tp_kept_tbs = 0;
    uint64_t kexc_tp_dropped_tbs = 0;
    uint64_t kexc_tp_recovered_tbs = 0;
    uint64_t kexc_tp_recovered_insns = 0;
    uint64_t kexc_tp_excluded_tbs = 0;
    uint64_t kexc_tp_excluded_insns = 0;
    /* The excluded population partitioned by WHY the (tp, asid) pair missed.
     * known_thread: the executing thread pointer IS a recorded owned thread
     * but the live address space is not the one it was recorded under — the
     * context-switch window, where the kernel has installed the next task's
     * page tables and not yet switched register state.  unknown_thread: the
     * executing thread pointer was never an owned thread at all, so the
     * block is unambiguously another task's kernel work that the entry-edge
     * rule admitted. */
    uint64_t kexc_tp_excluded_known_thread = 0;
    uint64_t kexc_tp_excluded_unknown_thread = 0;
    /* Recovered-span RETURN witness (both rules).  A kernel excursion ends
     * by returning to the user context that owns it, so a span containing a
     * task-identity recovery must land on an OWNED user TB.  The foreign
     * flavour MUST be 0 — a non-zero count would mean the recovery admitted
     * a foreign task's blocks.  This corroborates the recovery on the wire,
     * independently of the (tp, asid) pair that decided it. */
    uint64_t kexc_recovered_span_owned_user = 0;
    uint64_t kexc_recovered_span_foreign_user = 0;
    /* Thread-identity ruling census (system mode).  aliased: kernel task
     * values joined to the ENTERING thread's tid at a user->kernel
     * exception edge — kernel-on-behalf keeping the thread's id where the
     * raw register value changes at the privilege boundary (a TLS-less
     * thread).  kernel_task_minted: task values first resolved in kernel
     * mode with no user identity to join — kernel threads' own strands,
     * each a distinct id.  alias_expired: arms that ran out of budget on a
     * target with no kernel task source (x86-64) — the honest no-alias
     * outcome, never a wrong join. */
    uint64_t tid_task_aliased = 0;
    uint64_t tid_kernel_task_minted = 0;
    uint64_t tid_alias_expired = 0;
    /* Condition census for the entry-edge foreign latch, measured on both
     * rules: kernel TBs the edge rule refuses as not-owned while the
     * executing task's (thread-pointer, live asid) identity is a recorded
     * owned thread — i.e. the latch refusing the pinned process's own
     * kernel work. */
    uint64_t kexc_decl_not_owned_tp_owned = 0;
    /* Live-root recovery (the non-async entry-edge foreign latch).  Kernel
     * TBs the entry-edge rule refused while the PINNED address-space root
     * was installed — the pinned process re-entering the kernel with no
     * intervening user TB of its own.  On a wide-register target the root
     * is a per-process identity, so these are recovered, not guessed; the
     * _over_cut flavour counts the ones whose excursion also carried a
     * standing committed-switch cut (the switch moved the space away and
     * back, and the root says the process is running again). */
    uint64_t kexc_root_recovered_tbs = 0;
    uint64_t kexc_root_recovered_insns = 0;
    uint64_t kexc_root_recovered_over_cut = 0;
    /* The cut-side twin of kexc_decl_not_owned_live_pinned: kernel TBs a
     * standing cut refused while the pinned root was live.  Same false
     * refusal, reached through the other decline arm. */
    uint64_t kexc_decl_cut_live_pinned = 0;
    /* Owned-thread identity map churn.  Invalidations are the rollover
     * defence: ASID-write storm, narrow-ASID dwell re-pin, or a foreign
     * user TB carrying the pinned ASID value each clear the map, so a
     * recycled raw value can never satisfy a stale (tp, asid) pair. */
    uint64_t kexc_tp_map_inserts = 0;
    uint64_t kexc_tp_map_invalidations = 0;
    /* Thread-pointer samples that read back 0 — the architectural "no
     * identity" value (MIPS CP0 UserLocal on a model without Config3.ULRI,
     * a TLS-less task's aarch64 TPIDR_EL0 or x86 FS.base).  Never seeded
     * into the map and never matched against it, so those TBs stand down to
     * the entry-edge rule exactly as a non-tracking target does; a guest
     * reporting 0 on the PINNED process's own user TBs is one where the
     * identity rule cannot apply at all, and this counter says so. */
    uint64_t kexc_tp_null_samples = 0;
    /* Misattribution WITNESS, measured on both rules.  What it actually
     * tests, stated as the code tests it: the LAST kernel TB this vCPU
     * stepped was KEPT, and the next TB is a user TB whose ownership
     * verdict is FOREIGN, with no user TB of any kind in between — so the
     * kept span ran into another task's user code and its tail was that
     * task's kernel work.  Two properties follow, and neither is a
     * weakness of the invariant, only of its RESOLUTION: it speaks for the
     * span's last block rather than for every block of the span, and it
     * fires once per span however many blocks were misattributed.  It is
     * therefore a lower bound on the phenomenon — measured on the x86
     * system-clock cell, ONE count of this stood for 34,402 kernel TBs /
     * 229,826 instructions kept under a foreign root.  The block-level
     * measure is kexc_kernel_kept_foreign_root; this one remains because
     * it is the wire-side statement (a span that ENDS foreign), and it is
     * the only arm the narrow-ASID target has.  The _pinned_val flavour
     * counts the narrow-ASID collision: the foreign user TB carries the
     * pinned ASID VALUE (a rollover handed it over), the raw-value compare
     * defect's smoking gun. */
    uint64_t kexc_kept_span_foreign_user = 0;
    uint64_t kexc_kept_span_foreign_user_pinned_val = 0;
    /* The kept-span witness's CAUSE, measured at the block instead of at the
     * span's end: kernel TBs KEPT on a wide-register target while the live
     * address-space root was not the pinned one.  On such a target the root
     * IS the process — the very argument the live-root recovery rests on to
     * ADMIT — so a block executed under a foreign root is a foreign task's
     * kernel work whatever the vCPU's user-TB history says.  It MUST be 0:
     * the keep rule refuses those blocks, and this is what proves the
     * refusal complete rather than typical.  The narrow-ASID target is
     * deliberately absent — there a value match is a coincidence of recycled
     * bits rather than identity, in BOTH directions. */
    uint64_t kexc_kernel_kept_foreign_root = 0;
    uint64_t kexc_kernel_kept_foreign_root_insns = 0;
    /* Its complement, a condition counter: the kernel TBs that rule REFUSES,
     * and the instructions in them — foreign kernel work the trace no longer
     * carries.  Nonzero is health, not a defect. */
    uint64_t kexc_kernel_refused_foreign_root = 0;
    uint64_t kexc_kernel_refused_foreign_root_insns = 0;
    /* Narrow-ASID identity generation (see g_asid_identity_gen).  bumps
     * counts observations that the raw-value namespace recycled; the two
     * refusals count the raw-value comparisons that stood down because of
     * one — an excursion's entry value coming back in a later generation
     * (which would otherwise retire a cut and hand the rest of the
     * excursion to whoever now holds the value), and an async re-latch
     * whose snapshot of raw values aged out while its window was open. */
    uint64_t asid_identity_gen_bumps = 0;
    /* Committed ASID writes seen while an excursion's stored values were
     * already a generation behind (the exposure window), and — the sharp
     * one — writes of the excursion's OWN stored entry VALUE inside that
     * window.  The latter IS the narrow-ASID collision: those bits were
     * handed to another process, and the unguarded arrow reads them as the
     * excursion's address space returning.  Both are measured on BOTH arms;
     * the two "refused" counters below fire only where the guard acts. */
    uint64_t kexc_stale_gen_writes = 0;
    uint64_t kexc_entry_value_collisions = 0;
    uint64_t kexc_async_snap_stale_gen = 0;
    uint64_t kexc_entry_restore_refused_stale_gen = 0;
    uint64_t kexc_async_relatch_refused_stale_gen = 0;
    /* Kernel (priv!=0) TBs dropped because they executed at the target's
     * translation-bypassing privilege level (RISC-V M-mode firmware, which
     * satp does not govern; see g_xlate_bypass_priv).  Counted on both
     * attribution rules (kexc on and off), separately from
     * kexc_kernel_dropped — these TBs never consult the ownership rule. */
    uint64_t kexc_mmode_dropped = 0;
    /* DISTINCT raw EntryHi.ASID values committed since the pin, counted
     * unconditionally over the whole owned-window lifetime (see
     * asid_sweep_note in champsim_tracer.cc).  This is a WITNESS, not a
     * detector: it says how much of the guest's narrow ASID space burned
     * while the window was open, so a test that claims to have exercised a
     * rollover has to show >= the space's size here or FAIL as vacuous.  It
     * cannot be reset by the traced process being scheduled, and no
     * ownership decision reads it -- ownership keys on the page-table root.
     * Reaching the space's size means the guest reissued every name; it
     * does NOT mean anything went wrong. */
    uint64_t asid_names_committed_since_pin = 0;

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
    /* DISTINCT raw EntryHi.ASID values the OWNED address space was observed
     * executing user code under, when it exceeded one.  The second, and
     * independent, anti-vacuity witness: it is measured on the owned
     * execution path and depends on no ownership decision (there is no
     * re-bind rule to be a sub-event of), so >= 2 is direct evidence that
     * the guest renamed a live address space while the trace kept following
     * it -- which is exactly what keying on the page-table root buys. */
    uint64_t owned_asid_names_seen = 0;
    /* User TBs dropped because the address space they executed in is not
     * one this trace owns -- THE foreign-drop path.  A zero over a run
     * that contained foreign execution means the check never ran. */
    uint64_t pin_unverified_dropped = 0;
    /* This CPU model implements no architectural thread-pointer register, so
     * strands inside the window carry no thread name (see
     * pin_note_thread_naming).  Cross-ISA, and NOT an ownership problem:
     * ownership is the page-table root and never consults a thread name.
     * The window is not retired, nothing is dropped; only the per-strand
     * labelling is coarser. */
    uint64_t pin_thread_identity_absent = 0;

    /* Root-reuse guard, wide-register targets (x86 CR3 / AArch64 TTBR /
     * RISC-V SATP -- see the ROOT-REUSE GUARD note in champsim_tracer.cc).
     * Every committed write of an owned root re-walks that window's user
     * code-page anchors in the live address space.
     *
     *   anchors    is how many anchor pages the owned windows learned --
     *              zero means the walk had nothing to judge by, so a zero
     *              in the rows below proves nothing;
     *   verified   is a schedule-in the walk positively identified as the
     *              same process -- the positive control for the guard;
     *   unresolved is a schedule-in where no anchor page was mapped in the
     *              live space, so the guard could say nothing and FAILED
     *              OPEN (the window stays open; a live process whose text
     *              was reclaimed must not lose it);
     *   detected   is a root proven to hold a DIFFERENT process's code --
     *              the defect this guard exists for.  Nonzero is not a
     *              tracer fault: it means the traced process ended with its
     *              window open and the kernel handed its page-table root to
     *              a successor, whose blocks were excluded (and whose
     *              window was closed) instead of being recorded as the
     *              traced process's own. */
    /* User TBs excluded because the root running them was proven to belong
     * to a successor process.  These are the instructions the tracer used to
     * record as the traced process's own. */

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

    /* Async-level decomposition at frame emission (interrupts=1).  A fault
     * frame's depth stamp freezes the captured-async level in force when the
     * faulting block EXECUTED; its merge emits when the resume suffix seals,
     * and a captured window can open or close in between.  The emission
     * re-derives the level (the frame's synchronous component plus the
     * owner's level at completion) so the merged entry lands on the depth
     * staircase the wire is walking at ITS position.  gained counts merges
     * where a window opened across the excursion (the merge-before-tail
     * condition: creation level 0, completion level 1), dropped the reverse.
     * Both are the CONDITION census — they fire whether or not the
     * re-derivation is enabled. */
    uint64_t merge_async_level_gained = 0;
    uint64_t merge_async_level_dropped = 0;
    /* Must be 0: a frame whose recorded async component exceeds the stamp
     * it was decomposed from.  Structurally impossible (the stamp and its
     * sidecar are written together at every writer), counted so that an
     * unsigned wrap onto the wire could never be silent. */
    uint64_t merge_async_decomp_invalid = 0;
    /* Abandon-release rendering (interrupts=1): a window abandoned at the
     * owner's pinned user TB releases the captured level while the walked
     * (pending-emission) stamp still carries it frozen.  The release
     * re-stamps that in-hand block down one level, so the wire steps through
     * the level at the last position still in hand instead of jumping across
     * it at the user boundary.  stripped counts abandons that found such a
     * stamp (the abandon-collapse condition); merge_pending counts abandons
     * with a returned frame of the owner still awaiting its merge. */
    uint64_t async_abandon_stamp_stripped = 0;
    uint64_t async_abandon_merge_pending = 0;
    /* Residual census for the same abandon, arm-invariant: the level the
     * in-hand block still carries AFTER the async release — i.e. the step
     * the following depth-0 user entry makes.  >= 2 means synchronous frames
     * whose exception-returns were never observed (the strict-LIFO
     * suppression class) are still stacked on a single carrier block, which
     * no release rendering can step through without inventing entries;
     * no_carrier counts abandons with no block in hand to carry a release
     * at all. */
    uint64_t async_abandon_residual_ge2 = 0;
    uint32_t async_abandon_residual_max = 0;
    uint64_t async_abandon_no_carrier = 0;

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

    /* interrupts=1 captured-async-window ledger.  Every rate here has its
     * denominator in the same block, and every counter is bumped ONCE per
     * event (on the fresh drain) or ONCE per surviving depth stamp — never in
     * the retained-event rescan, which replays the same events on every
     * suspended dispatch and would inflate a per-event count by the length of
     * the foreign span.
     *
     *   async_captures            windows opened (the denominator)
     *   async_captures_reopened   ... opened while one was already open
     *   async_capture_owner_unseen ... whose delivering thread had not been
     *                             minted an id yet, so the level stays dormant
     *   async_closed_by_return    windows closed by an ASYNC_RETURN
     *   async_return_peer_ctx     ... where the closing context was NOT the
     *                             delivering thread.  The producer's test is a
     *                             bare per-vCPU PC equality, so a peer at the
     *                             same VA can close a window early: an
     *                             UPSTREAM defect, measured here, not masked.
     *   async_abandon_owner       windows closed by their owner reaching user
     *   async_abandon_peer_spared pinned user TBs of a PEER that left an
     *                             owner's window alone (a latch would have
     *                             destroyed the level here)
     *   async_level_own_stamps    depth stamps the open window contributed to
     *   async_level_peer_stamps   depth stamps it was dormant for -- each one
     *                             a level a thread-blind rule would have
     *                             borrowed
     *   async_asid_write_in_window address-space switches committed inside an
     *                             open window (the condition an
     *                             address-space-keyed rule would fire on)
     *   async_win_peer_with_asidw windows that served a peer stamp AND saw an
     *                             ASID write
     *   async_win_peer_no_asidw   windows that served a peer stamp with NO
     *                             ASID write at all -- context changes no
     *                             address-space rule can see (same-mm thread
     *                             switch, borrowed-mm kernel thread, recycled
     *                             narrow ASID).  Zero only means the condition
     *                             did not arise in this run. */
    uint64_t async_captures = 0;
    uint64_t async_captures_reopened = 0;
    uint64_t async_capture_owner_unseen = 0;
    uint64_t async_closed_by_return = 0;
    uint64_t async_return_peer_ctx = 0;
    uint64_t async_abandon_owner = 0;
    uint64_t async_abandon_peer_spared = 0;
    uint64_t async_level_own_stamps = 0;
    uint64_t async_level_peer_stamps = 0;
    uint64_t async_asid_write_in_window = 0;
    uint64_t async_win_peer_with_asidw = 0;
    uint64_t async_win_peer_no_asidw = 0;

    /* Async-window LIVENESS vs INTERIORITY (both interrupt modes).
     *
     * QEMU's window flag spans the scheduler by design, so "a window is
     * outstanding on this vCPU" and "this event came from inside the
     * handler" are different propositions.  Conflating them vetoed the
     * pinned process's own synchronous faults whenever another context's
     * interrupt was still outstanding, which discarded the interrupted
     * block's entire reg-delta slice.
     *
     *   async_interior_user_priv_kept   fault events admitted BECAUSE user
     *                             privilege disproves interiority (an
     *                             exception handler never runs there).  The
     *                             rescued population; 0 means the condition
     *                             did not arise, never that it cannot.
     *   async_interior_kernel_refused   fault events still refused as
     *                             window interior — kernel privilege, where
     *                             telling our own kernel entry from the
     *                             window owner's handler needs the owner's
     *                             thread, which is only tracked with
     *                             interrupts=1.  A KNOWN residue, measured
     *                             rather than assumed away.
     *   async_abandon_cursor_closed  abandoned-window recoveries that
     *                             lowered the retention cursor.  An
     *                             abandoned window emits no ASYNC_RETURN,
     *                             so without this the cursor could never
     *                             fall again and every later fault event on
     *                             the vCPU was stamped in-async. */
    uint64_t async_interior_user_priv_kept = 0;
    uint64_t async_interior_kernel_refused = 0;
    uint64_t async_abandon_cursor_closed = 0;

    /* Window-interior synchronous faults.  The producers push FAULT_ENTER
     * for every real synchronous fault, including one delivered while an
     * async window is open (they historically suppressed those, which made
     * a captured window's faulting block seal as a normal entry: a phantom
     * branch edge into the handler, no fault anchors, and an execution on
     * the wire with silently missing memops — the memop-bimodality lint's
     * flag).  The seal classifies a drained FAULT_ENTER by its position in
     * the batch relative to the async edges:
     *
     *   fault_enter_classified_in_win  classified normally while a captured
     *                             window was open (interrupts=1 content is
     *                             first-class, so its faults merge like any
     *                             other) — the condition the old producer
     *                             gate silently discarded
     *   fault_enter_skipped_in_async   consumed with no action because the
     *                             event sits between an ASYNC_ENTER and its
     *                             RETURN inside the batch: excluded-window
     *                             interior (interrupts=0), or content that
     *                             interposed after the window edge — never
     *                             prev's own fault.  Zero only means the
     *                             condition did not arise in this run. */
    uint64_t fault_enter_classified_in_win = 0;
    uint64_t fault_enter_skipped_in_async = 0;

    /* ---- Event retention (attribution-gated) ----------------------------
     *
     * retention_peak            largest |pending_evs_| this run.  Bounded by
     *                           the traced context's OWN trap nesting; it
     *                           must not grow with untraced execution.
     * retention_scan_events     total retained entries walked (the cost the
     *                           per-dispatch rescan used to charge).
     * retention_events_owned    fault events the attribution gate admitted.
     * retention_events_refused  fault events it refused (untraced context,
     *                           firmware, excluded-window interior).
     * retention_appends_from_untraced_events
     *                           refused events that were retained ANYWAY.
     *                           Reachable only in the CST_RETAIN_ALL
     *                           experiment arm; on a shipping run this is
     *                           exactly 0, and any other value is a failure.
     * seal_successor_from_foreign_fault
     *                           the seal's architectural-successor override
     *                           was taken from an event of another address
     *                           space — a foreign process's fault standing in
     *                           for the pinned block's branch target.  The
     *                           corruption the gate removes; must be 0.
     * case_b_frame_asid_mismatch
     *                           a fault-entry classification matched the
     *                           deferred prev by PC while naming a foreign
     *                           address space (identical text at identical
     *                           addresses).  Must be 0.
     */
    /* The OTHER per-vCPU structures a long untraced span could grow, peaked
     * so the claim "no retained structure grows with untraced execution" is
     * measured rather than asserted.  frames_ holds the traced process's own
     * in-flight fault excursions; susp_stack_ its suspended deferred-prev
     * blocks.  Both are fed only from downstream of the attribution gates. */
    uint64_t frames_peak = 0;
    uint64_t susp_stack_peak = 0;

    /* ---- What a segment close was still holding in frames_ -------------
     * A fault frame open at the close holds the EXECUTED pre-fault prefix of
     * its block: the merge that would have put the block on the wire whole
     * is waiting for a FAULT_RETURN that the close makes impossible.  Until
     * PathBuilder::flush_frames_at_close those instructions were dropped —
     * visible on the user side as clock_minus_wire > 0, and INVISIBLE for a
     * kernel frame, which the user-only residual cannot see.
     *
     * close_frames_flushed / _insns_recovered is what the close emitted;
     * the sys / user split is there because the user-only residual is not a
     * complete detector for this class.  Non-zero is ordinary: it means a
     * segment ended inside a fault handler, which any workload can do.
     *
     * close_frames_empty_prefix is the frame whose fault landed on its
     * block's FIRST instruction: nothing of it retired, so emitting nothing
     * is correct and no instruction is lost.
     *
     * close_frame_prefix_unplaced MUST be 0: it is a frame whose executed
     * extent could not be named (its resume PC is not one of its own block's
     * instructions) or whose truncated template would not commit — the one
     * shape in which this flush still drops what it is holding. */
    uint64_t close_frames_flushed = 0;
    uint64_t close_frame_insns_recovered = 0;
    uint64_t close_frame_user_insns_recovered = 0;
    uint64_t close_frame_sys_insns_recovered = 0;
    uint64_t close_frames_empty_prefix = 0;
    uint64_t close_frame_prefix_unplaced = 0;
    /* No body stream existed at the close, so the frames could not be
     * emitted anywhere.  MUST be 0 for the same reason. */
    uint64_t close_frames_unflushable = 0;

    /* ---- Event-queue drain instrument (the BIGDRAIN condition) --------
     * The queue is QEMU-side, grow-only and never drops; its length between
     * drains is exactly "events produced since the last drain".  These are
     * the numbers that showed the defect and are the numbers that show it
     * gone.
     *
     * evq_drain_calls / evq_drain_events   both drain sites (the heavy CP
     *                            step and the light per-TB absorber).
     * evq_batch_peak             largest single drain.  THIS is the
     *                            work-per-guest-instruction violation: one
     *                            guest instruction was charged 83,532
     *                            events' worth of O(n) passes on a mipsel
     *                            churn cell.  With a drain point at every
     *                            TB entry it cannot exceed one TB's worth
     *                            of pushes.
     * evq_gap_peak               largest guest-instruction distance between
     *                            two consecutive drain CALLS on one vCPU
     *                            (119,835,488 on that same cell).
     * evq_bigdrains              drains larger than TCG_MAX_INSNS; must be 0.
     * evq_absorb_*               the light path's own share.
     * evq_qmax_len / evq_q_pushes / evq_q_drains
     *                            read back from QEMU at exit
     *                            (qemu_plugin_cpu_events_stats): produced by
     *                            the producer, upstream of every plugin
     *                            attribution decision, so no plugin gate can
     *                            suppress them.  evq_qmax_len is the direct
     *                            measurement of the bound. */
    uint64_t evq_drain_calls = 0;
    uint64_t evq_drain_events = 0;
    uint64_t evq_batch_peak = 0;
    uint64_t evq_gap_peak = 0;
    uint64_t evq_bigdrains = 0;
    uint64_t evq_absorb_calls = 0;
    uint64_t evq_absorb_events = 0;
    uint64_t evq_absorb_batch_peak = 0;
    uint64_t evq_qmax_len = 0;
    uint64_t evq_q_pushes = 0;
    uint64_t evq_q_drains = 0;

    uint64_t retention_peak = 0;
    uint64_t retention_scan_events = 0;
    uint64_t retention_events_owned = 0;
    uint64_t retention_events_refused = 0;
    uint64_t retention_appends_from_untraced_events = 0;
    uint64_t seal_successor_from_foreign_fault = 0;
    uint64_t case_b_frame_asid_mismatch = 0;

    /* ---- CST_RETAIN_CHECK equivalence harness (test-only) ---------------
     * Cell populations of the compared events, so a zero mismatch count can
     * no longer be reported from a region where the answer is constant: a
     * cell that must be exercised and reads 0 is a FAILED check, not a pass.
     */
    uint64_t rcheck_seals = 0;
    uint64_t rcheck_cmp_enter_in_async = 0;
    uint64_t rcheck_cmp_enter_not_async = 0;
    uint64_t rcheck_cmp_return_in_async = 0;
    uint64_t rcheck_cmp_return_not_async = 0;
    uint64_t rcheck_cmp_ours = 0;
    uint64_t rcheck_cmp_foreign = 0;
    uint64_t rcheck_mismatch_resume_pc = 0;
    uint64_t rcheck_mismatch_in_async = 0;

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
