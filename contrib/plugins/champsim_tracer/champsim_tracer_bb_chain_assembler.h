/*
 * Wrong-Path Tracing Plugin — correct-path BB chain assembler.
 *
 * Accumulates per-TB fragments since the last branch-target boundary
 * and, on terminating-branch finalization, builds (or reuses) a true
 * BBTemplate via TemplateStore.
 *
 * QEMU emits TB fragments out of branch-target alignment (each starts
 * where the prev ended), but a true BB begins at a branch target and
 * ends at the next branch.  This class folds consecutive fragments into
 * one true BB.  A next-fragment pre_pc not matching the chain's last
 * fall-through is a control-flow discontinuity (interrupt, process
 * start) → reset and restart at the new pre_pc.
 *
 * Threading: one assembler per vCPU (cp_chain(cpu_index)).  CP
 * fragments chain only within one vCPU's dispatch stream, which
 * exec_lock serialises, so instance state needs no lock of its own;
 * finalize() calls the shared cache, which the caller locks via
 * data_lock.
 *
 * Across segments clear_bb_map() invalidates cached BBTemplate*s.  Each
 * chain stamps the monotonic g_segment_generation (bumped by
 * reset_segment_local_state) on every append_fragment; a mismatch on
 * the next append drops the stale fragments and starts a fresh chain.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_BB_CHAIN_ASSEMBLER_H
#define CHAMPSIM_TRACER_BB_CHAIN_ASSEMBLER_H

#include <atomic>
#include <vector>

#include "champsim_tracer.h"

class BBChainAssembler {
public:
    BBChainAssembler() = default;

    BBChainAssembler(const BBChainAssembler &) = delete;
    BBChainAssembler &operator=(const BBChainAssembler &) = delete;

    /* Append @frag (TB-fragment template at @entry_pc) to the in-flight
     * chain.  If @entry_pc != the chain's last fall-through (no chain,
     * or discontinuity), reset and start a new chain at @entry_pc.
     * @fall_through (PC right after the TB) validates the next fragment.
     * @terminus is how this TB contributes to true-BB assembly (see
     * TbTerminus): it drives whether bb_complete() now reports true.
     * Self-resets on a bumped segment generation so stale fragment
     * pointers are never followed.
     *
     * RETURNS true when this call DISCARDED a non-empty in-flight chain
     * (discontinuity, or a bumped segment generation).  Those fragments
     * will never be emitted, so the caller owes their already-captured
     * per-insn state the same fate: the reg-snap sink is a positional FIFO
     * and a silently orphaned prefix slides every later value onto the
     * wrong instruction.  Ignoring the return value is what made the
     * emit-time backstop see a SURPLUS and "recover" by trimming — a
     * misattribution dressed as a repair.
     *
     * @dropped_insns (optional) receives the ARCHITECTURAL INSTRUCTION
     * COUNT of the fragments this call discarded.  The chain-event counter
     * alone cannot answer the question a reader actually has — how much of
     * the instruction stream the window clock billed never reached the wire
     * — because one dropped chain can be one fragment or five. */
    bool append_fragment(uint64_t entry_pc,
                         BBTemplate *frag,
                         uint64_t fall_through,
                         TbTerminus terminus,
                         uint32_t *dropped_insns = nullptr);

    /* True once the accumulated chain forms a complete true BB — i.e.
     * the last appended TB completed the BB's terminating branch (and,
     * on delay-slot ISAs, its delay slot).  The caller finalizes only
     * when this is set. */
    bool bb_complete() const { return bb_complete_; }

    /* Finalize the in-flight chain into a true-BB template via the
     * cache.  nullptr if no chain in progress.  Does NOT reset (caller
     * must call reset()).  Caller must hold data_lock. */
    BBTemplate *finalize();

    /*
     * Finalize the in-flight chain PLUS the first @tail_insns instructions
     * of @tail_frag as a block whose EXECUTION was cut short.
     *
     * @tail_frag is a fragment execution entered and did not run to the end
     * of; it is deliberately NOT appended through append_fragment, because
     * the chain's fragment list is the input to the complete-block cache and
     * a clipped fragment must never become part of a cached complete block.
     * Pass tail_frag == nullptr to finalize just the chain (every appended
     * fragment ran in full, but no terminating branch was ever reached).
     *
     * Like finalize(), does NOT reset, and the caller must hold data_lock.
     */
    BBTemplate *finalize_truncated(BBTemplate *tail_frag, uint32_t tail_insns);

    /* Architectural instructions currently held in the in-flight chain. */
    uint32_t in_flight_insns() const;

    /* Drop the in-flight chain.
     *
     * Two callers mean two different things by this.  After finalize() it
     * is a COMMIT: the fragments became a true-BB template and the chain is
     * cleared for the next one.  Everywhere else it DESTROYS a live chain —
     * the fault fold (fold_prev_full_bb resets before re-appending prev),
     * the segment resets, the suspend arrows — and those fragments never
     * reach the wire.  reset() returns nothing, so every destroying reset
     * used to be silent.  It now counts them (Stats::reg_snap_chain_reset_
     * drops / _frags), telling the two apart by whether finalize() ran on
     * this chain since the last append. */
    void reset();

    bool has_active_chain() const {
        return entry_pc_ != 0 && !fragments_.empty();
    }

    /* Full snapshot of the in-flight chain state, for the suspend-or-seal
     * arrow (Stage 3): when a foreign-ASID span suspends the deferred prev
     * mid-true-BB (a page-split BB spanning TBs), the pre-prev fragments
     * live here and must survive the span so a resume continues that BB
     * rather than restarting it.  detach_state() moves the whole state out
     * (leaving *this reset/empty); attach_state() moves it back.  Between
     * most steps the chain is empty (the seal finalizes+resets), so this is
     * usually a no-op snapshot — it is byte-inert on every path that does
     * not suspend. */
    struct ChainState {
        uint64_t entry_pc = 0;
        uint64_t last_ft  = 0;
        uint32_t my_gen   = 0;
        bool     awaiting_delay_slot = false;
        bool     bb_complete = false;
        bool     finalized = false;
        std::vector<BBTemplate *> fragments;
    };
    ChainState detach_state();
    void attach_state(ChainState &&s);

private:
    uint64_t entry_pc_ = 0;
    uint64_t last_ft_  = 0;
    uint32_t my_gen_   = 0;
    /* Set when the previous TB ended in a bare branch (TB_TERMINUS_
     * BARE_BRANCH): the delay slot is the next TB's first insn, so the
     * BB is not complete until that next TB is appended. */
    bool     awaiting_delay_slot_ = false;
    /* True once the chain forms a complete true BB; see bb_complete(). */
    bool     bb_complete_ = false;
    /* Set by a successful finalize(), cleared by append_fragment().  Lets
     * reset() tell a commit from a destroy without changing any caller. */
    bool     finalized_ = false;
    std::vector<BBTemplate *> fragments_;
};

/* Per-vCPU CP chain, indexed by cpu_index (same pattern as g_rep_state);
 * a basic block doesn't span vCPUs, so cross-vCPU fragment mixing would
 * be incorrect.  Formerly thread_local, which is per-vCPU only under
 * MTTCG; round-robin TCG (-accel tcg,thread=single, and therefore
 * -icount) runs EVERY vCPU on one host thread, where a thread-keyed
 * chain would fold the vCPUs' interleaved fragment streams into one
 * bogus chain at each rr slice boundary. */
BBChainAssembler &cp_chain(unsigned int cpu_index);

/* Bumped by reset_segment_local_state() on segment switch.  Per-vCPU
 * chains compare against this on append_fragment() and self-reset
 * when their stamped generation lags. */
extern std::atomic<uint32_t> g_segment_generation;

#endif /* CHAMPSIM_TRACER_BB_CHAIN_ASSEMBLER_H */
