/*
 * Wrong-Path Tracing Plugin — correct-path BB chain assembler.
 *
 * Accumulates the per-TB fragments executed since the last branch-target
 * boundary, and on terminating-branch finalization, builds (or reuses) a
 * true BBTemplate covering the chain via BBTemplateCache.
 *
 * QEMU emits TB fragments out of branch-target alignment: each fragment
 * starts where the previous one ended, but a "true basic block" begins
 * at a branch target and ends at the next branch.  This class folds
 * consecutive TB fragments into one true BB.
 *
 * If the next-fragment pre_pc does not match this chain's last fall-
 * through (a control-flow discontinuity, e.g. interrupt or first BB
 * after process start), the chain is reset and a new one started at
 * the new pre_pc.
 *
 * Threading: one assembler per vCPU thread (held in thread_local
 * g_cp_chain).  CP fragments only chain *within* a single thread of
 * execution, so the assembler's instance state (entry_pc_, fragments_)
 * is private to its thread and needs no lock.  finalize() calls into
 * the shared BBTemplateCache, which serialises itself via data_lock
 * — that lock is taken by the caller, not by this class.
 *
 * Across segment boundaries the cached BBTemplate * pointers are
 * invalidated by BBTemplateCache::clear_bb_map().  To avoid dangling
 * fragment pointers in any thread's in-flight chain after a switch,
 * each chain stamps its current segment generation on every
 * append_fragment(); a generation mismatch on the next append drops
 * the (now-stale) fragments and starts a fresh chain.  segment_gen()
 * is a monotonic counter bumped by reset_segment_local_state().
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

    /* Append @frag (a TB-fragment template starting at @entry_pc) to
     * the in-flight chain.  If @entry_pc does not match the chain's
     * last fall-through (no chain in progress, or a discontinuity),
     * reset the accumulator and start a new chain at @entry_pc.
     * @fall_through is the TB's fall-through PC (the address right
     * after the TB), used to validate the next fragment.
     *
     * Self-resets when the global segment generation has bumped since
     * the last append, so stale BBTemplate * fragment pointers from a
     * cleared-out segment are never followed. */
    void append_fragment(uint64_t entry_pc,
                         BBTemplate *frag,
                         uint64_t fall_through);

    /* Finalize the in-flight chain into a true-BB template via the BB
     * template cache.  Returns nullptr if no chain is in progress.
     * Does NOT reset the chain — caller must call reset() afterwards.
     * Caller must hold data_lock (the cache call mutates shared state). */
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
    std::vector<BBTemplate *> fragments_;
};

/* Per-vCPU CP chain.  Each QEMU vCPU thread gets its own assembler;
 * cross-vCPU mixing of fragments would be incorrect anyway since a
 * basic block doesn't span thread switches. */
extern thread_local BBChainAssembler g_cp_chain;

/* Bumped by reset_segment_local_state() on segment switch.  Per-vCPU
 * chains compare against this on append_fragment() and self-reset
 * when their stamped generation lags. */
extern std::atomic<uint32_t> g_segment_generation;

#endif /* CHAMPSIM_TRACER_BB_CHAIN_ASSEMBLER_H */
