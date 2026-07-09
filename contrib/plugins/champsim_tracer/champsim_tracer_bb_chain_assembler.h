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
 * Threading: one assembler per vCPU thread (thread_local g_cp_chain).
 * CP fragments chain only within one thread, so instance state needs no
 * lock; finalize() calls the shared cache, which the caller locks via
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
     * pointers are never followed. */
    void append_fragment(uint64_t entry_pc,
                         BBTemplate *frag,
                         uint64_t fall_through,
                         TbTerminus terminus);

    /* True once the accumulated chain forms a complete true BB — i.e.
     * the last appended TB completed the BB's terminating branch (and,
     * on delay-slot ISAs, its delay slot).  The caller finalizes only
     * when this is set. */
    bool bb_complete() const { return bb_complete_; }

    /* Finalize the in-flight chain into a true-BB template via the
     * cache.  nullptr if no chain in progress.  Does NOT reset (caller
     * must call reset()).  Caller must hold data_lock. */
    BBTemplate *finalize();

    /* Drop the in-flight chain. */
    void reset();

    bool has_active_chain() const {
        return entry_pc_ != 0 && !fragments_.empty();
    }

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
    std::vector<BBTemplate *> fragments_;
};

/* Per-vCPU CP chain; a basic block doesn't span thread switches so
 * cross-vCPU fragment mixing would be incorrect anyway. */
extern thread_local BBChainAssembler g_cp_chain CST_TLS_HOT;

/* Bumped by reset_segment_local_state() on segment switch.  Per-vCPU
 * chains compare against this on append_fragment() and self-reset
 * when their stamped generation lags. */
extern std::atomic<uint32_t> g_segment_generation;

#endif /* CHAMPSIM_TRACER_BB_CHAIN_ASSEMBLER_H */
