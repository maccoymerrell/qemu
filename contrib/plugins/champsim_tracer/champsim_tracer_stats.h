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

#include <vector>

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
     * budget.  Emitted as CST_BB_FLAG_SYNTHETIC_FAULT on the block. */
    uint64_t wp_synthetic_faults = 0;
    uint64_t wp_total_mem_accesses = 0;
    /* Chains whose LAST block ran past the wpdepth budget (block
     * atomicity finishes the in-flight block) and was published with its
     * own cut range [0, remainder) so the chain attributes EXACTLY the
     * budget; the insns row is what the cut kept off the wire. */
    uint64_t wp_budget_cut_blocks = 0;
    uint64_t wp_budget_cut_insns = 0;

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
     * to observe drops taken on that route at all.  A reader who saw 0
     * concluded "nothing was dropped" and had no way to be right or wrong.
     * The end-marker-close subset is still separable, below, but it is no
     * longer separable from the total by being invisible — which is what
     * makes today's zero worth reading. */
    uint64_t reg_snap_slice_dropped = 0;
    /* Subset of reg_snap_slice_dropped taken while the segment was closing
     * on the guest's END marker.  Attribution only, and its expected value
     * is now ZERO: the END close is deferred to the boundary of the block
     * the marker fired inside, so that block's later instructions DO run
     * and their dst snaps are taken by the ordinary dispatch prologue —
     * there is no truncated tail left for the emit to drop.  (Measured 0
     * on the system marker cell of all four ISAs.)  The bucket stays
     * because that is a claim an instrument should carry rather than a
     * reader assume: if a future close ever lands mid-block on this route
     * again, the drop it causes is named here instead of being averaged
     * into the total. */
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
    /* TRANSLATION-CUT FAULTING HEADS (the M20 class).  A translator that
     * stops at an instruction it knows will raise (a MIPS coprocessor-
     * unusable FPU store, an x86 #NM shape) hands the fault fold a prev
     * whose committed template ends AT the faulting instruction, not at
     * the block's terminal branch.  A frame continuation bounded by that
     * template can never cover the resumed suffix, so every resumed
     * instruction past the cut was billed to the window clock and never
     * published — the deterministic mipsel clock_minus_wire=+20.
     * _head_incomplete counts the condition (fires on every such fault);
     * _whole_substituted is the canonical repair (the cached complete
     * block replaces the cut, prefix and continuation share one
     * template); _cut_frames is the fallback (no cached whole: the
     * prefix completes as its own block and the completion publishes the
     * sealed suffix whole, counted in _cut_frame_suffix_insns).
     * merge_suffix_overhang is the tripwire on every OTHER completion:
     * a resumed suffix extending past its frame's coverage self-heals
     * through the suffix-whole path and must never happen. */
    uint64_t fold_prev_head_incomplete = 0;
    uint64_t fold_prev_whole_substituted = 0;
    uint64_t fold_prev_cut_frames = 0;
    uint64_t merge_cut_frame_suffix_insns = 0;
    uint64_t merge_suffix_overhang = 0;

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
     * beyond what the clock bills for the instruction: Σ(n_iter - 1) over
     * user blocks whose terminal instruction was fanned out, plus 1 for
     * each fault-cut rep-split piece (§4.2a overlap) — the cut piece's
     * parent range is wire whose execution's bill was re-credited at the
     * fault, the instruction's one kept count landing on the completing
     * piece.  See the increment sites for why the retired cursor cannot
     * see these.  finish_trace_segment folds the per-segment delta into
     * the printed clock_minus_wire; the term stays named here, never
     * slack. */
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
    /* Owned dispatches and the instructions the bill site charged them,
     * @delta -- the TB-ENTRY credit, which counts a block's whole
     * instruction count when the guest enters it.  NOT what the window
     * clock folds: g_user_icount folds @delta_retired (what executed), and
     * this row is kept as the phantom bill's numerator, this minus
     * user_clock_retired_insns.  Both rows carry the REP self-loop
     * withhold's correction (see the withhold in vcpu_tb_exec), so both
     * count architectural instructions rather than dispatches and their
     * difference is unchanged by it.  wire_user_arch_insns minus this is
     * the residual OWNED_CP vs user_covered was standing in for. */
    uint64_t user_clock_billed_tbs = 0;
    uint64_t user_clock_billed_insns = 0;
    /* Bills whose delta did NOT equal the dispatched TB's own architectural
     * instruction count, and the excess instructions in them.  This is the
     * clock billing the owned process for work that was not the owned TB —
     * a foreign process's user instructions retired since the last owned
     * dispatch.  (Under content gating a fork child maps the marker bytes
     * and is itself traced, so the canonical example is now an UNGATED
     * process's slice — an execve'd successor, a never-marked peer.) */
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
    /* BILLING AT EMIT, AT THE CLOSE (user_clock_close_credit): the
     * pending-seal slots whose dispatch fold never came, billed at close
     * with exactly the extent the flush PUBLISHED for them — the closing
     * vCPU's own block at an END/ceiling close, and any peer slot with no
     * dispatch after it.  The boundary instructions the flush's stop rule
     * excludes (the mid-callback END-firing insn, the un-snapped tail) are
     * outside this credit, which is what holds clock_minus_wire at 0. */
    uint64_t user_clock_close_credits = 0;
    uint64_t user_clock_close_credit_insns = 0;
    /*
     * USER-MODE EXACT-BUDGET WINDOW (billing at emit, §4.2a).  A finite
     * user-mode icount/simpoint window bills EXACTLY its budget: the
     * emission that crosses the remaining budget is published as the
     * partial range [start, start + remainder) — the S18 clean break, the
     * same stop rule the END-marker close applies — and anything after it
     * is outside the window and not emitted.  The *_cut_insns /
     * *_suppressed rows are instructions that RAN past the budget point
     * and are therefore outside every published range; the raw user clock
     * counted them at dispatch, so the segment-finish coverage subtracts
     * them (user_raw_unbilled_insns) and BILLED == PUBLISHED holds at the
     * user budget close too.  A REP fan-out parent is exempt from the cut
     * (its iterations are indivisible on the wire); the overrun row makes
     * that visible instead of silent.
     */
    uint64_t user_budget_final_partial = 0;
    uint64_t user_budget_final_cut_insns = 0;
    uint64_t user_budget_entries_suppressed = 0;
    uint64_t user_budget_insns_suppressed = 0;
    uint64_t user_budget_rep_overrun_insns = 0;
    /* User-mode raw-clock instructions excluded from billing because no
     * published range claims them: the exact-budget cut/suppression above,
     * plus each close-flushed pending-seal slot's unpublished tail (the
     * exit syscall dying mid-callback, the not-yet-run TB a deferred
     * budget close skips).  Subtracted from `covered` at segment finish in
     * user (raw-clock) mode — the user-mode twin of
     * user_clock_close_credit's identity. */
    uint64_t user_raw_unbilled_insns = 0;
    /* The open-boundary twin of user_raw_unbilled_insns, opposite sign: a
     * mid-run window open's crossing TB is traced whole (its body entry
     * keeps the wire aligned with the BBV count that positioned the
     * window) while the head insns it dispatched below window_start were
     * billed outside the segment.  Credited at the open
     * (user_raw_clock_open_credit) and added to `covered` at segment
     * finish, so BILLED == PUBLISHED holds at the open edge exactly as
     * the un-bill holds it at the close.  A named term, never slack: it
     * reads the measured straddle of each mid-run open, and 0 on every
     * boundary-aligned open (lo=0 first segments, marker/user-clock
     * modes). */
    uint64_t user_raw_open_prebilled_insns = 0;
    /* Templates minted for blocks the guest ENTERED AND DID NOT FINISH (see
     * TemplateStore::commit_partial_bb).  Keyed by extent, so repeated cuts
     * at the same point share one; a run where nothing is ever cut short
     * mints none. */
    uint64_t partial_bb_templates_created = 0;
    /*
     * WHAT partial_bb_templates_created ACTUALLY SUMS.
     *
     * That row counts DISTINCT (asid_root, entry_pc, extent, content)
     * shapes inserted into partial_bb_map_, cumulatively, and SEVEN
     * unrelated producers insert there:
     *
     *   1. a close-walk seal that cut a fragment mid-TB
     *   2. a close-walk seal of a chain left open at a TB edge
     *   3. a DEPARTURE / migration-drain seal (same walk, guest runs on)
     *   4. the mid-run seal walk truncating to what ran
     *      (seal_walk_blocks_truncated)
     *   5. the mid-run cut where control left the block
     *      (cut_blocks_sealed)
     *   6. an extent-only mint — a block that DID reach its branch
     *   7. a fault-cut head prefix
     *
     * A single cumulative shape count over all seven cannot answer "how
     * many true-BBs did this close have to seal itself", which is the
     * quantity the unsealed-at-close bound is stated in.  The rows below
     * complete the decomposition (1-3, 6, 7; 4 and 5 already had rows),
     * counted per EVENT rather than per distinct shape — so the events
     * are an upper bound on the shapes, and a run whose events sum to
     * zero while the shape row is non-zero has a producer nobody named,
     * which is exactly how producer 3 was found.
     *
     * MID-RUN EXTENT-ONLY MINTS.  TemplateStore::commit_true_bb_refs
     * assembled a complete chain at a pc where bb_map_ already holds a
     * template of a DIFFERENT length (resolve_true_bb's EXTENT_ONLY
     * verdict), so this execution's extent is minted into
     * partial_bb_map_ instead.  The block IS sealed — it reached its
     * terminating branch — and no close is involved; the mint exists
     * because bb_map_ is keyed by address alone and holds one extent per
     * pc.  Counted per COMMIT, not per distinct shape, so a run that
     * re-enters the same short extent a million times reads a million
     * here and one in partial_bb_templates_created. */
    uint64_t extent_only_mints = 0;
    /* FAULT-CUT HEAD PREFIXES.  A fault landed in a block whose head
     * template was itself cut by a translation boundary and no cached
     * whole block covers it, so the executed prefix is published as a
     * complete block of its own extent (PathBuilder::classify_fault_enter,
     * the cut_frame arm).  Mid-run, not a close; the guest resumes and the
     * frame's completion publishes the sealed suffix. */
    uint64_t fault_cut_head_prefixes = 0;
    /*
     * UNSEALED TRUE-BBs AT A CLOSE — the close-side population, counted
     * per BLOCK and per CLOSE rather than per template shape.
     *
     * A true BB is sealed by its terminating branch.  A close that lands
     * while a thread is standing inside one has no branch to seal with,
     * so PathBuilder::close_walk_emit finalizes the block at the extent
     * that ran (BBChainAssembler::finalize_truncated).  Two shapes reach
     * that call, and they are different situations:
     *
     *   _cut_frag   the close's measured extent cut a fragment part-way
     *               through — the guest was mid-TB
     *   _tb_edge    the walk consumed whole fragments and the chain was
     *               still open at a TB boundary, so the true BB was
     *               split across TBs (a page-straddling block) and its
     *               continuation never came
     *
     * BOTH shapes have real occupants.  _tb_edge's was found in the system
     * SMP-2 canon cell devio_sys_x86_64_smp2 (run 0 of the golden work
     * root): closes_unsealed 1, _tb_edge 1, _cut_frag 0, alongside "peer
     * vCPU seal slots flushed at close 1" and "close peer-slot extents from
     * the LIVE cursor 1".  The mechanism is the peer flush, not a
     * page-straddling block: an SMP close seals ANOTHER vCPU's slot, and
     * that peer's chain was simply open at a TB boundary because it had not
     * reached its branch yet.  Run 1 of the same cell reads 0, so it turns
     * on where the peer happens to be standing when the close lands.
     *
     * A SINGLE-vCPU probe CANNOT produce it, and the attempt is recorded so
     * it is not repeated: a budget close on the closing vCPU emits the block
     * at the extent that ran (the epoch-0x1E emit-at-extent rule) and so
     * never leaves one unsealed -- measured over eight budgets aimed by
     * residue arithmetic at a deliberately page-straddling true BB, every
     * one of which took the budget-cut route with both unsealed counters at
     * 0.  The unsealed shapes need a close that seals a chain belonging to
     * someone other than the vCPU being cut.
     *
     * _blocks is their sum.  _closes counts closes that produced at
     * least one, _contexts sums the distinct (vCPU, thread) identities
     * that contributed one, summed over closes — the per-close PEAK of
     * that same quantity is the bound's actual subject and cannot live
     * in Stats (every field here is summed across threads), so it is
     * kept beside the identity ledger; see close_unsealed_summary().
     *
     * Departure-time and migration-drain walks share close_walk_emit and
     * are NOT counted here: the guest keeps running past them, so they
     * are neither a close nor a stopping point. */
    uint64_t close_unsealed_blocks = 0;
    uint64_t close_unsealed_cut_frag = 0;
    uint64_t close_unsealed_tb_edge = 0;
    uint64_t close_unsealed_closes = 0;
    uint64_t close_unsealed_contexts = 0;
    /* The same walk run at a DEPARTURE (foreign-ASID dispatch, abandoned
     * async window) or a migration drain: the block is sealed at what ran
     * and published immediately, but the guest keeps executing, so it is
     * not a stopping point and not part of the bound above. */
    uint64_t departure_unsealed_blocks = 0;
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
    /* LABEL-FIDELITY witness: entries emitted while the live address-
     * space value differed from the carried label (emissions lag
     * execution — deferred seal, close flush — so the carry
     * g_vcpu_cur_asid_index names the block being emitted, and the live
     * value names whatever context happens to be current at the writer).
     * NOT must-be-0: it is the size of the set a live read would have
     * mis-stamped. */
    uint64_t emit_asid_foreign_context = 0;
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

    /* ---- SMP attribution pair: condition instruments ------------------
     *
     * The last exempted intermittent class on x86 -smp 4 churn: (A) a
     * mid-stream DUPLICATE entry — a BB re-emitted at a CFG-impossible
     * position one entry after its real emission — and (B) a duplicate
     * FINAL entry at the budget close.  Both are an instruction claimed
     * twice, which is trace-invalidating.  These counters instrument the
     * CONDITION at the suspected sites, not the outcome: the per-thread
     * claim ledger at the emission choke point (emit_body_entry) fires
     * the moment a second claim goes on the wire, with the emit-site
     * provenance of both claims, and the site counters below record the
     * cross-vCPU circumstances (a seal resolving a successor produced by
     * another thread's dispatch; a thread migrating off a vCPU whose
     * pending-seal slot still holds its unsealed block; a close reading
     * a peer's LIVE retired cursor) that can only produce the duplicate
     * under SMP scheduling.
     *
     * smp_dup_adjacent_claims: entry N+1 re-claims entry N's instructions
     * (same template, overlapping range, same thread, same depth) where
     * the template's own terminal branch makes self-succession impossible
     * (direct branch, both edges known, neither is the block's start).
     * smp_dup_wrongpc_reemit: entry N+1 exactly re-claims entry N-1 while
     * entry N's resolved direct terminal cannot reach it — shape (A).
     * Both must be 0; the ledger-checks row proves the checker ran, and a
     * falsifier wave proved the predicates able to fire. */
    uint64_t smp_dup_adjacent_claims = 0;
    uint64_t smp_dup_wrongpc_reemit = 0;
    uint64_t smp_dup_ledger_checks = 0;
    /* Seal resolved a block's terminal successor on a step whose executing
     * thread differs from the thread that ran the block (walk_tid !=
     * cur_tid) — the cross-thread successor read named by the prepush
     * taken-edge poisoning finding.  Condition, not defect: the gates may
     * refuse the evidence downstream; pairs with the duplicate rows. */
    uint64_t smp_seal_cross_thread_succ = 0;
    /* A guest thread's consecutive promotes landed on different vCPUs. */
    uint64_t smp_thread_migrations = 0;
    /* Of those, the vCPU it left still held an unsealed pending-seal slot
     * promoted by that same thread — the one-dispatch lookahead orphaned
     * mid-block by the migration. */
    uint64_t smp_migrated_holder_pending = 0;
    /* Close-time peer-slot extent provenance: the stash (measured at the
     * first dispatch after prev — definitively past) vs the LIVE retired
     * cursor of a vCPU that may still be executing, and the slot being
     * that vCPU's CURRENT in-flight head at the close.
     *
     * The three are a strict priority, not independent tallies.  Because
     * the stash is written by the FIRST dispatch after a promote — owned or
     * foreign — a peer still holding a slot at a close has usually
     * dispatched again since, which is precisely why the cursor can no
     * longer name it, and on x86_64 and mipsel only the stash row had ever
     * been seen above 0 (400 cells, 76 firing the stash, 0 firing either
     * other).  That was an ISA blind spot, not a reachability fact: a
     * 160-cell aarch64+riscv64 system wave with no arm anywhere classified
     * 98 peer slots as 77 stash and 21 LIVE CURSOR, over 21 cells (11
     * aarch64, 10 riscv64).  All 21 were also the in-flight head — the
     * stash is missing exactly when no dispatch followed the promote, and
     * then the slot still IS that vCPU's current dispatch, so the two rows
     * name one window from two sides.  A synthetic falsifier wave against
     * smp_close_peer_extent_note reached that window on demand on other
     * ISAs, so neither row is merely quiet.
     *
     * The in-flight case is what the close-time extent snapshot exists
     * for.  Peers are still not quiesced — the close holds exec_lock, so a
     * peer stops only at its next dispatch — but the extent the flush
     * publishes for such a slot is no longer read off a counter that vCPU
     * is advancing: retired_close_extent_arm samples every vCPU's
     * in-flight count before TraceSegmentManager::finish() shuts the
     * observation sinks, and every close-path reader is answered from that
     * sample (see the comment on retired_close_extent_arm,
     * champsim_tracer.cc).  The row is therefore a provenance fact about
     * WHERE the extent came from, not an alarm about it moving. */
    uint64_t smp_close_peer_stash_extent = 0;
    uint64_t smp_close_peer_live_cursor = 0;
    uint64_t smp_close_peer_inflight_head = 0;
    /* Of the in-flight-head slots, those whose retired cursor had moved
     * PAST the close-time sample by the time the flush read it, and the
     * instructions it had moved by.  That difference is what the peer ran
     * after the sinks were shut — instructions no memop, dst snap or
     * synthetic EA was recorded for — so it is exactly the extent a
     * live-cursor read would have published from the template with
     * inherited field values.  Reported, not enforced: the snapshot
     * already keeps it out of the wire, and the number says whether the
     * cell reached the condition at all. */
    uint64_t smp_close_peer_inflight_drift = 0;
    uint64_t smp_close_peer_inflight_drift_insns = 0;
    /* The thread-keyed migration drain (the fix the condition census
     * above caught in the act): holders drained at the owning thread's
     * first promote on another vCPU, the instructions they published,
     * and the drain finding no answerable extent (must be 0 — the stash
     * or the vacated vCPU's parked cursor answers for every observed
     * shape; an unanswerable one is a dropped block and must be seen).
     * A falsifier wave severed one drain's extent lookup and saw the row
     * move, so it is proven reachable rather than merely quiet. */
    uint64_t smp_migrated_holders_drained = 0;
    uint64_t smp_migrated_holder_insns = 0;
    uint64_t smp_migrate_drain_extent_unknown = 0;
    /* The close's thread-keyed THREAD_END pre-pass (only the context's
     * LAST emitting flush stamps) predicted a flush's emission wrongly —
     * the stamp may sit one flush early or the context's close-final may
     * be unstamped; the validator's thread_end oracle is the enforcement
     * and this row makes the prediction's misses visible in the run.
     * A falsifier wave inverted the COMPARISON's copy of the prediction —
     * leaving the stamping decision and therefore the wire unchanged — and
     * saw the row move, so it is proven able to fire. */
    uint64_t smp_close_stamp_mispredict = 0;

    /* ---- CLOSE CENSUS -------------------------------------------------
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
     * The occupancy half is read per close by
     * PathBuilder::close_state_report; these counters are what make the
     * two halves add up across a run.
     *
     * Under split emission a CtxFrame is an identity-and-depth ledger
     * entry — its block's executed prefix reached the wire at the fault —
     * so every frame fate below moves bookkeeping, never instructions:
     *
     * Frames (PathBuilder::frames_):
     *   opened               classify_fault_enter case (b) pushed a
     *                        CtxFrame after emitting the prefix
     *   merged               complete_continuation emitted the resumed
     *                        suffix as a continuation and erased the frame
     *   unwound_dropped      a completion retired a leaked same-thread
     *                        DEEPER entry (strict LIFO says it lost its
     *                        own continuation; nothing was emittable)
     *   orphan_dropped       on_segment_open or flush_final cleared it
     *                        (its full_tmpl dangles into the cleared
     *                        bb_map_ / the segment is over)
     *   held_at_close        still in frames_ at a close, summed over the
     *                        POST-flush census (so the close-flush's own
     *                        recoveries are already subtracted)
     *
     * Pending-seal slot (PathBuilder::prev_tb_):
     *   prev_promoted        set_prev installed a block
     *   prev_close_walked    a close's flush_final emitted it at a
     *                        measured nonzero extent
     *   prev_close_dropped   a close emitted nothing for it (extent zero
     *                        or unmeasurable), with the RETIRED extent
     *                        that went with it
     *
     * The remaining holders have no lifecycle counter of their own because
     * they are sinks, not queues: what matters is the depth left in them
     * when the last drain has run, which is exactly what the post-flush
     * census records here. */
    uint64_t census_closes = 0;
    uint64_t census_frames_opened = 0;
    uint64_t census_frames_merged = 0;
    uint64_t census_frames_unwound_dropped = 0;
    /* Excursion ended by an exception-table fixup: the guest re-entered the
     * frame's own template at an interior pc other than the resume PC (no
     * FAULT_RETURN can arrive — the ERET target was software-advanced), so
     * the frame was retired with its merge dead by construction. */
    uint64_t census_frames_diverted = 0;
    uint64_t census_frames_orphan_dropped = 0;
    uint64_t census_frames_held_at_close = 0;
    uint64_t census_prev_promoted = 0;
    uint64_t census_prev_close_walked = 0;
    uint64_t census_prev_close_dropped = 0;
    uint64_t census_prev_close_dropped_insns = 0;
    uint64_t census_walkprev_held_at_close = 0;
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

    /* ---- THE CLOSE DRAINS (one per holder the census enumerated) ---- */

    /* PEER BUILDERS.  The peer loop once gated on the pending-seal slot
     * alone (`if (!b || !b->prev()) continue;`), so a peer vCPU holding
     * work (then: frames and suspensions; now: an in-flight chain or a
     * reg-snap sink) behind an EMPTY slot was skipped whole.  Measured:
     * sd_smp4 vCPUs 2 and 3, ceil2 vCPUs 1 and 2, each holding work behind
     * prev=0x0.  The gate now asks whether the builder holds ANYTHING. */
    uint64_t close_peer_holder_flushes = 0;
    uint64_t close_peer_holder_insns_recovered = 0;

    /* THE ORDER THE CLOSE EMITS IN.  A close used to flush its own vCPU
     * first and the peers after it, which appends blocks the guest ran
     * EARLIER behind blocks it ran later -- and docs/format.rst promises a
     * consumer that one (asid, thread_id) context reads as a single
     * instruction stream in order, breaking only at nesting boundaries the
     * format makes visible.  The flushes are ordered by the shared dispatch
     * clock (g_promote_seq) instead.
     *
     * This is the CONDITION instrument for that ordering, not an outcome:
     * it counts the closes where the clock moved at least one builder AHEAD
     * of the closing vCPU, which is exactly the population whose wire order
     * the fix changes.  A run whose close found no peer holding work reads
     * zero here and is evidence of nothing either way -- which is the whole
     * reason it is reported. */
    uint64_t close_flush_reordered = 0;
    uint64_t close_flush_reordered_builders = 0;

    /* THE PENDING-SEAL SLOT'S STOP RULE AT A CLOSE (see
     * PathBuilder::flush_final).  A machine-shutdown close is taken from a
     * MID-INSTRUCTION callback (the device write), and insn_started is
     * added at the TOP of an instruction, so the retired cursor reads the
     * in-flight instruction as already begun; the close subtracts it,
     * because an instruction that has not completed has not delivered all
     * its memops — it is outside the fully-observed range by the stop
     * rule. */
    uint64_t close_deferred_prev_inflight_trimmed = 0;
    /* The slot held a block and no extent could be measured for it, so
     * nothing could be emitted without guessing.  Must be 0. */
    uint64_t close_deferred_prev_extent_unknown = 0;
    /* THREAD_END at a deferred budget/simpoint close.  The close itself
     * emits nothing for the closing vCPU, so the flag rides the last seal
     * before the take (stamped_at_seal); a take that fired without one —
     * merge-path seal, fan-out at the boundary, a peer holding close work
     * — is counted, never silent (missed). */
    uint64_t close_thread_end_stamped_at_seal = 0;
    uint64_t close_thread_end_missed = 0;

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
     * slot with a measured retired extent, an in-flight chain with
     * instructions.  Must be 0 -- this is the row that fails the cell when
     * a holder is added, or when a falsifier turns a drain off, and it does
     * not depend on remembering to add a row per new holder. */
    uint64_t close_holder_undrained = 0;
    uint64_t close_holder_undrained_insns = 0;

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
     * Both are closed.  The since-deleted CST_NO_SEAL_STASH falsifier arm
     * proved this counter able to fire (16-19 per riscv64 system cell with
     * the stash refused, dragging seal_walk_extent_unknown_interior with
     * it). */
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
     *   (RepSelfLoopState::emit_pre_pieces), never by this counter, and a
     *   reader who
     *   treats a zero here as evidence about fault handling is reading a
     *   number that cannot answer the question.
     * rep_trailing_pass_dropped — a zero-iteration re-entry of a REP already
     *   in flight, i.e. the extra pass a single-iteration translation makes
     *   after the final iteration.  Not a retired instruction; suppressed so
     *   the trace's instruction count does not depend on the translation.
     * rep_exit_edge_recovered — a retiring REP whose observed successor was
     *   its own PC (the same single-iteration translation jumps back before
     *   taking the zero-count exit); the emitted terminal edge was restored
     *   to the architectural fall-through.
     * rep_reg_writes_deferred — iterations that published NO
     *   destination register write, i.e. (iterations - 1) per repeating
     *   instruction (#174).  NOT a fan-out counter, despite where the
     *   larger share of it is counted: a single-iteration translation
     *   (-icount, single-step, TF, an interrupt shadow) never takes the
     *   fan-out path, yet each of its continuation passes defers a write
     *   just the same, so this reads the SAME total in both regimes while
     *   rep_fanout reads that total and zero.  Naming it for the fan-out
     *   would attribute the deferral to a mechanism that did not run —
     *   the mistake #173 records on the surplus term.  A repeating
     *   instruction updates its
     *   architectural registers ONCE, on completion; the fan-out renders
     *   one entry per iteration only so the per-iteration memops have
     *   somewhere to attach, and iteration N carries the whole
     *   instruction's observed result.  This counts the entries that
     *   correctly carry none — publishing intermediate values would inject
     *   rename pressure and an N-long serial dependency chain that no real
     *   machine has. */
    uint64_t rep_iters_architectural = 0;
    uint64_t rep_iters_inferred = 0;
    uint64_t rep_iters_memop_mismatch = 0;
    uint64_t rep_trailing_pass_dropped = 0;
    uint64_t rep_exit_edge_recovered = 0;
    uint64_t rep_reg_writes_deferred = 0;
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

    /*
     * MARKER COUNTERS (content-as-gate).
     *
     * The marker is decided in the bytes at translation time and the whole
     * open/release happens there too (never-split + whole-TB scan), so
     * there is no run to break, no fence and no straddle verdict left to
     * count.  What remains:
     *
     * marker_page_unreadable_at_refresh — WITNESS, must be 0 on a healthy
     *   run.  Predicate, exactly (R5): a gate refresh ran in the SAME
     *   context this vCPU was last gated ON for — prior per-vCPU gate bit
     *   still set AND the live architectural root equal to the carried
     *   last-GATED label — and a latched window's marker bytes were no
     *   longer readable through it.  That is a gated→unreadable
     *   TRANSITION: the marked process's marker page stopped being
     *   readable, i.e. the residency requirement (mlock(2) the sequence
     *   page before START; ops fallback: swap off) was broken.  The
     *   context gates OFF — honest and contract-visible — and this
     *   counter is what makes the violation loud.  A never-gated context
     *   that does not map the vaddr (every foreign mm) also reads as
     *   unreadable but is NOT a residency violation; it lands in
     *   refresh_evaluated_not_traced ALONE.  Stated boundary: a loss
     *   discovered only after a foreign round trip (the marked process
     *   returns to the vCPU with its page already gone) arrives with the
     *   prior bit OFF and is not counted — deliberately, because on a
     *   narrow-ASID guest (MIPS, 8-bit) a rolled-over generation hands
     *   recycled root values to foreign processes, and without the
     *   prior-bit requirement any such recycled root would false-fire
     *   this witness against a foreign mm.  That loss still gates the
     *   context off (honest), visible as the marked process ceasing to
     *   be traced.
     * refresh_evaluated_not_traced — CONDITION.  Every gate refresh that
     *   evaluated and concluded NOT traced (foreign mm's — readable or
     *   not — and residency losses alike): the size of the
     *   untraced-context refresh traffic, and the anti-vacuity witness
     *   that the content check actually runs.
     * marker_end_no_close    — CONDITION, not a tripwire.  An END reached
     *   translation in a context that maps no open window's marker bytes,
     *   so no window could be released.  Split from the forced close's
     *   tripwire shape: fusing an expected condition with a violated
     *   invariant makes the invariant unenforceable.
     * wp_session_on_cp       — MUST BE 0.  A wrong-path session bracket was
     *   still flagged while this vCPU ran the CORRECT path: a leaked fence
     *   flag.  Tested at TWO points, and it needs both: the correct-path
     *   step, and every committed address-space write (which fires
     *   regardless of ownership, window and fast-forward).
     */
    uint64_t marker_gate_refresh_events = 0;   /* the DENOMINATOR: every
                                    * content-gate re-evaluation (committed
                                    * root writes, window opens/releases,
                                    * vCPU init, peer seeds) */
    uint64_t marker_page_unreadable_at_refresh = 0;
    uint64_t refresh_evaluated_not_traced = 0;
    uint64_t marker_end_no_close = 0;
        /* An END that executed on the correct path, could not be attributed to
     * any owner, and closed the capture anyway.  MAINTAINER RULING
     * (2026-08-02): "END kills the tracer, regardless of simpoints, just
     * like a program ending in user mode would do."  Nonzero means the
     * ownership machinery could not name the ender — worth investigating —
     * but the trace still ends where its workload does, which is the
     * invariant that cannot be traded. */
    uint64_t marker_end_forced_close = 0;
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
    /* Segments closed by the idle backstop (the ONE global last-gated-
     * execution stamp), split by which denominator crossed: the wall-clock
     * timeout (latch_timeout) or the guest-instruction idle
     * (latch_idle_insns).  Nonzero means the capture was judged dead
     * WITHOUT an END marker having run, so the trace stops where the
     * backstop fired rather than where the workload finished. */
    uint64_t dead_latch_closes_ms = 0;
    uint64_t dead_latch_closes_insns = 0;
    /* Segments closed by the machine-shutdown backstop: the guest powered
     * off (or QEMU was asked to exit) with a capture still open, so the
     * window was closed and finalised there rather than abandoned.  A
     * nonzero value means the trace is TRUNCATED at that point and the
     * workload never reached its END marker. */
    uint64_t vm_shutdown_closes = 0;
    /* Segments closed by the machine-reset route: the guest (or a
     * watchdog / monitor request) RESET the machine with a capture still
     * open.  The reboot is a fresh world in the same process — new
     * kernel, every address-space name recycled — so the window is
     * closed at the reset request, while the machine it was recording
     * still exists, and the run then ends; recording across the teardown
     * would attribute the new world's execution to the dead pin. */
    uint64_t vm_reset_closes = 0;

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
    /*
     * rep_split_retired_iters_dropped / _drops — the rep-split LOSS
     * tripwire (must be 0).  A fan-out instruction that faults mid-loop
     * publishes its pre-fault retired iterations as the overlap-licensed
     * rep-split piece (format spec §4.2a); the piece exists exactly when
     * the architectural facts channel names those iterations.  These count
     * the COMPLETE iterations whose delivered memops sat in the CP
     * accumulator at the faulting instruction while the channel named
     * none — observations discarded with no piece claiming them, i.e.
     * retired guest work silently absent from the wire.  The measured
     * instance was the severed pb_prev_facts arm: 32 of 96 REP STOSB
     * iterations between two demand faults never reached the wire while
     * every other gate stayed green.  A falsifier wave severed that arm
     * and reproduced the shape, which is how this tripwire's firing is
     * proven.
     */
    uint64_t rep_split_retired_iters_dropped = 0;
    uint64_t rep_split_retired_drops = 0;
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

    /* Decode-side warning count. */
    uint64_t unknown_insn_warnings = 0;

    /* Guest-thread kernel-entry aliasing census (system mode; RULING 2/3's
     * primary anti-vacuity witness).  aliased: kernel task
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
    /*
     * rev3 ENDPOINT IDENTITY witnesses (the thread_identity_note.md rev3
     * degenerate case: the marked process's thread pointer reads 0, so
     * thread identity falls to user-SP regions observed at the endpoints
     * of kernel excursions, with thread-pointer WRITE events as switch
     * evidence).  Four load-bearing rows — rule-armed, return endpoints,
     * strands minted, refusals.  The kernel-span CUTTING arms that once
     * accompanied them died with kernel-span ownership (RULING 3): kernel
     * code in a gated space is traced, so there is no span to cut and no
     * exclusion census.
     */
    /* The endpoint rule ARMED at a window open (marked process degenerate,
     * capability verified).  0 on every TLS-ful workload. */
    uint64_t ep_rule_armed = 0;
    /* RETURN endpoints observed: a kernel->user crossing whose first user
     * TB re-sampled the user SP.  Kernel-interior SP is NEVER consulted —
     * this and a segment's first user sighting are the only SP
     * observation points (rev3: trampolines, IST stacks, per-CPU entry
     * stacks are not handled but unobserved). */
    uint64_t ep_return_endpoints = 0;
    /* Distinct user-SP regions minted as thread identities (rev3: two live
     * threads cannot share a user stack; a region is a thread; mint at
     * first sighting, reidentify by region). */
    uint64_t ep_strands_minted = 0;
    /* Loud refusals fired at a window open because the marked process was
     * degenerate and the endpoint rule could not arm (the user SP was
     * unreadable).  The refusal path _exit()s, so a
     * nonzero value is only ever seen if the refusal was downgraded — the
     * stderr message is the primary witness; this row exists so the
     * warn-path can never be silent. */
    uint64_t ep_refusals = 0;

        /* User TBs dropped because the context they executed in maps no
     * latched window's marker bytes (the content gate) -- THE foreign-drop
     * path.  A zero over a run that contained foreign execution means the
     * check never ran. */
    uint64_t pin_unverified_dropped = 0;

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

    /* Emit-at-departure (epoch 0x1E model): blocks the foreign-ASID /
     * abandoned-async arrows emitted at their measured extent the moment
     * they left the traced flow, and the instructions those emissions
     * carried.  The unknown row counts departures with no measurable
     * extent (nothing emitted; nothing was observable). */
    uint64_t departure_emits = 0;
    uint64_t departure_emit_insns = 0;
    uint64_t departure_extent_unknown = 0;
    /* Of departure_emits, the abandoned-async arrow's share: the stuck-
     * window recovery closed a window with no departure PC, so the pending
     * block's successor could never be resolved and it was emitted on the
     * spot.  A distinct site with its own (async-storm) contention
     * signature; zero off the async-recovery path. */
    uint64_t departure_emits_abandoned_async = 0;

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
     *                             ASID write at all -- a same-mm thread
     *                             switch, the one context change no
     *                             address-space-change event marks (the
     *                             other two old sources are gone: a
     *                             borrowed-mm kthread is traced by RULING 3
     *                             and narrow-ASID recycling is a
     *                             non-concept).  Zero only means the
     *                             condition did not arise in this run. */
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
     * seal_successor_from_foreign_fault
     *                           the seal's architectural-successor override
     *                           was taken from an event of a non-gated
     *                           context standing in for the traced block's
     *                           branch target.  The corruption the gate
     *                           removes; must be 0.
     */
    /* The OTHER per-vCPU structure a long untraced span could grow, peaked
     * so the claim "no retained structure grows with untraced execution" is
     * measured rather than asserted.  frames_ holds the traced process's
     * own in-flight fault excursions (identity-and-depth ledger entries;
     * their executed prefixes are already on the wire).  Fed only from
     * downstream of the attribution gates. */
    uint64_t frames_peak = 0;

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
    uint64_t seal_successor_from_foreign_fault = 0;

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

/*
 * ---- THE UNSEALED-AT-CLOSE LEDGER (peak + identities) ---------------
 *
 * The bound this measures is stated per CLOSE, not per run: N threads in
 * the traced window can leave at most N-1 true-BBs unsealed, because the
 * thread that reaches the stopping event keeps executing until its block
 * seals and only the OTHERS can be caught standing inside one.  A single
 * traced thread therefore reads zero.
 *
 * A per-close maximum cannot be a Stats field — stats_snapshot() sums
 * every field across threads, and a close taken on one vCPU while peers
 * were filled on theirs would add the peaks together.  So the peak, and
 * the identities behind it, live here: a process-wide record with its own
 * lock, written once per close (closes are rare) by the same code that
 * bumps the Stats rows.
 *
 * The ledger keeps a bounded sample of the individual unsealed blocks so
 * a run that exceeds the bound says WHICH contexts and WHICH blocks did
 * it, and names the close route that stopped them — the difference
 * between a legitimate terminal event and a policy gap is exactly that
 * route, and a bare count cannot tell them apart.
 */
enum CstUnsealedShape : uint8_t {
    CST_UNSEALED_CUT_FRAG = 0,   /* extent cut a fragment part-way */
    CST_UNSEALED_TB_EDGE  = 1,   /* chain still open at a TB boundary */
};

struct CloseUnsealedRow {
    uint64_t close_seq;      /* census_closes ordinal of the close */
    uint64_t entry_pc;       /* the unsealed true BB's entry */
    const char *reason;      /* close route ("END", "BUDGET", ...) */
    uint32_t n_insns;        /* extent the close sealed it at */
    uint32_t cpu_index;      /* builder that held it */
    uint32_t thread_id;      /* guest thread it is attributed to */
    uint8_t  shape;          /* CstUnsealedShape */
    uint8_t  is_system;
};

struct CloseUnsealedSummary {
    uint64_t closes;             /* closes observed by this instrument */
    uint64_t closes_with;        /* ... that left >= 1 block unsealed */
    uint64_t blocks;             /* unsealed blocks, all closes */
    uint64_t peak_blocks;        /* most blocks at any one close */
    uint64_t peak_contexts;      /* most distinct contexts at any one close */
    uint64_t peak_close_seq;     /* which close set peak_contexts */
    const char *peak_reason;     /* its route; nullptr when never set */
    uint64_t rows_dropped;       /* sample rows past the ledger's cap */
};

/* Open a close's accumulation window.  @reason is the close route
 * string, which must outlive the run (a literal). */
void close_unsealed_begin(const char *reason);
/* Record one true BB a close had to seal itself. */
void close_unsealed_note(unsigned int cpu_index, uint32_t thread_id,
                         uint64_t entry_pc, uint32_t n_insns,
                         bool is_system, uint8_t shape);
/* Fold the window into the summary and the Stats rows. */
void close_unsealed_end(void);
/* Is a close's accumulation window open right now? */
bool close_unsealed_window_open(void);
CloseUnsealedSummary close_unsealed_summary(void);
/* Bounded sample of the individual rows, oldest first. */
const std::vector<CloseUnsealedRow> &close_unsealed_rows(void);

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
