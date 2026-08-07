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
     * be 0 on a correct run. */
    uint64_t reg_snap_slice_dropped = 0;
    /* Emitted entries whose surplus reg-snaps (a leaked prefix from a chain
     * the assembler abandoned on a sync-fault-storm TB discontinuity) were
     * TRIMMED at the front to recover this block's own correct positional
     * reg-data (the dataflow oracle validates the recovered stream).  A
     * recovered leak, not a dropped slice; distinct from reg_snap_slice_
     * dropped, which is only the unrecoverable shortfall. */
    uint64_t reg_snap_leak_trimmed = 0;

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
