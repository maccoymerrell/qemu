/*
 * Wrong-Path Tracing Plugin — BBChainAssembler implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "champsim_tracer_bb_chain_assembler.h"
#include "champsim_tracer_bb_template_cache.h"

/* Per-vCPU assemblers, indexed by cpu_index (see the header comment on
 * cp_chain()).  Plain static array, same lifetime discipline as
 * g_rep_state: never destroyed before plugin_exit-ordered teardown. */
static BBChainAssembler g_cp_chains[CST_PIN_MAX_VCPUS];

BBChainAssembler &cp_chain(unsigned int cpu_index)
{
    return g_cp_chains[cpu_index < CST_PIN_MAX_VCPUS
                       ? cpu_index : CST_PIN_MAX_VCPUS - 1];
}

std::atomic<uint32_t> g_segment_generation{1};

void BBChainAssembler::append_fragment(uint64_t entry_pc,
                                       BBTemplate *frag,
                                       uint64_t fall_through,
                                       TbTerminus terminus)
{
    /*
     * On segment switch clear_bb_map() drops the unique_ptrs owning
     * fragments_'s BBTemplate*s, so a generation mismatch (bumped per
     * switch) means lazily drop the now-stale chain here — lets
     * reset_segment_local_state run against one vCPU's chain without
     * touching the other vCPUs'.
     */
    uint32_t cur_gen = g_segment_generation.load(std::memory_order_relaxed);
    if (my_gen_ != cur_gen) {
        fragments_.clear();
        entry_pc_ = 0;
        last_ft_ = 0;
        awaiting_delay_slot_ = false;
        my_gen_ = cur_gen;
    }
    if (entry_pc_ == 0 || last_ft_ != entry_pc) {
        /* Discontinuity: drop in-flight chain and start a new one.
         * A pending delay slot is abandoned with it — a discontinuity
         * means the delay slot never contiguously followed (abnormal:
         * interrupt / segment edge). */
        fragments_.clear();
        entry_pc_ = entry_pc;
        awaiting_delay_slot_ = false;
    }
    fragments_.push_back(frag);
    last_ft_ = fall_through;

    /*
     * Decide whether the chain now forms a complete true BB.
     *
     * Normal case: a TB_TERMINUS_COMPLETE TB ends a true BB on its
     * own — a branch (non-delay-slot ISA), or [branch, delay-slot]
     * with both insns in this TB (delay-slot ISA).
     *
     * Page-split case: a TB_TERMINUS_BARE_BRANCH TB ends with a
     * branch whose delay slot QEMU placed in the NEXT TB (a branch
     * landing on the last insn of a page).  The BB is not done — set
     * awaiting_delay_slot_; the next appended TB begins with that
     * delay slot, and appending it completes the BB.
     */
    if (awaiting_delay_slot_) {
        /* This fragment carries the pending branch's delay slot as
         * its first insn — the delay slot is the BB's final insn. */
        awaiting_delay_slot_ = false;
        bb_complete_ = true;
    } else if (terminus == TB_TERMINUS_COMPLETE) {
        bb_complete_ = true;
    } else if (terminus == TB_TERMINUS_BARE_BRANCH) {
        awaiting_delay_slot_ = true;
        bb_complete_ = false;
    } else {
        bb_complete_ = false;
    }
}

BBTemplate *BBChainAssembler::finalize()
{
    if (entry_pc_ == 0 || fragments_.empty()) {
        return nullptr;
    }
    return g_template_store.get_or_create_bb_template(
        entry_pc_, fragments_.data(), (unsigned int)fragments_.size());
}

void BBChainAssembler::reset()
{
    entry_pc_ = 0;
    last_ft_ = 0;
    awaiting_delay_slot_ = false;
    bb_complete_ = false;
    fragments_.clear();
}

BBChainAssembler::ChainState BBChainAssembler::detach_state()
{
    ChainState s;
    s.entry_pc = entry_pc_;
    s.last_ft = last_ft_;
    s.my_gen = my_gen_;
    s.awaiting_delay_slot = awaiting_delay_slot_;
    s.bb_complete = bb_complete_;
    s.fragments = std::move(fragments_);
    /* Leave *this in the reset state (fragments_ is moved-from -> cleared
     * below to be definite); a fresh chain starts cleanly after a detach. */
    fragments_.clear();
    entry_pc_ = 0;
    last_ft_ = 0;
    awaiting_delay_slot_ = false;
    bb_complete_ = false;
    return s;
}

void BBChainAssembler::attach_state(ChainState &&s)
{
    entry_pc_ = s.entry_pc;
    last_ft_ = s.last_ft;
    my_gen_ = s.my_gen;
    awaiting_delay_slot_ = s.awaiting_delay_slot;
    bb_complete_ = s.bb_complete;
    fragments_ = std::move(s.fragments);
}
