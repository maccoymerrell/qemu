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
 * All access goes under the plugin's data_lock; the class itself does
 * not synchronize.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_BB_CHAIN_ASSEMBLER_H
#define CHAMPSIM_TRACER_BB_CHAIN_ASSEMBLER_H

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
     * after the TB), used to validate the next fragment. */
    void append_fragment(uint64_t entry_pc,
                         BBTemplate *frag,
                         uint64_t fall_through);

    /* Finalize the in-flight chain into a true-BB template via the BB
     * template cache.  Returns nullptr if no chain is in progress.
     * Does NOT reset the chain — caller must call reset() afterwards. */
    BBTemplate *finalize();

    /* Drop the in-flight chain. */
    void reset();

    bool has_active_chain() const {
        return entry_pc_ != 0 && !fragments_.empty();
    }

private:
    uint64_t entry_pc_ = 0;
    uint64_t last_ft_  = 0;
    std::vector<BBTemplate *> fragments_;
};

extern BBChainAssembler g_cp_chain;

#endif /* CHAMPSIM_TRACER_BB_CHAIN_ASSEMBLER_H */
