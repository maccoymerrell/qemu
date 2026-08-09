/*
 * Wrong-Path Tracing Plugin — BBChainAssembler implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "champsim_tracer_bb_chain_assembler.h"
#include "champsim_tracer_bb_template_cache.h"
#include <inttypes.h>

#include "champsim_tracer_stats.h"

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

/* Architectural instruction count currently held in flight. */
static inline uint32_t chain_insns(const std::vector<BBTemplate *> &frags)
{
    uint32_t n = 0;
    for (const BBTemplate *f : frags) {
        n += f ? f->n_insns : 0;
    }
    return n;
}

bool BBChainAssembler::append_fragment(uint64_t entry_pc,
                                       BBTemplate *frag,
                                       uint64_t fall_through,
                                       TbTerminus terminus,
                                       uint32_t *dropped_insns)
{
    bool dropped_in_flight = false;
    if (dropped_insns) {
        *dropped_insns = 0;
    }
    /*
     * On segment switch clear_bb_map() drops the unique_ptrs owning
     * fragments_'s BBTemplate*s, so a generation mismatch (bumped per
     * switch) means lazily drop the now-stale chain here — lets
     * reset_segment_local_state run against one vCPU's chain without
     * touching the other vCPUs'.
     */
    uint32_t cur_gen = g_segment_generation.load(std::memory_order_relaxed);
    if (my_gen_ != cur_gen) {
        dropped_in_flight = dropped_in_flight || !fragments_.empty();
        if (dropped_insns) {
            *dropped_insns += chain_insns(fragments_);
        }
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
        dropped_in_flight = dropped_in_flight || !fragments_.empty();
        if (dropped_insns) {
            *dropped_insns += chain_insns(fragments_);
        }
        fragments_.clear();
        entry_pc_ = entry_pc;
        awaiting_delay_slot_ = false;
    }
    fragments_.push_back(frag);
    last_ft_ = fall_through;
    /* A fragment appended after a finalize() belongs to the NEXT true BB;
     * the commit credit does not carry over to it (see reset()). */
    finalized_ = false;

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
    return dropped_in_flight;
}

BBTemplate *BBChainAssembler::finalize()
{
    if (entry_pc_ == 0 || fragments_.empty()) {
        return nullptr;
    }
    BBTemplate *bb = g_template_store.get_or_create_bb_template(
        entry_pc_, fragments_.data(), (unsigned int)fragments_.size());
    if (bb) {
        /* This chain's fragments became a template; the reset that follows
         * is a commit, not a loss.  See reset(). */
        finalized_ = true;
    }
    return bb;
}

uint32_t BBChainAssembler::in_flight_insns() const
{
    return chain_insns(fragments_);
}

bool BBChainAssembler::would_discard(uint64_t entry_pc) const
{
    if (fragments_.empty()) {
        return false;
    }
    if (my_gen_ != g_segment_generation.load(std::memory_order_relaxed)) {
        return true;
    }
    return entry_pc_ == 0 || last_ft_ != entry_pc;
}

bool BBChainAssembler::in_flight_is_system() const
{
    return !fragments_.empty() && fragments_.front() &&
           fragments_.front()->is_system;
}

void BBChainAssembler::describe_in_flight(std::FILE *out,
                                          uint64_t breaking_pc) const
{
    if (fragments_.empty()) {
        return;
    }
    std::fprintf(out,
        "champsim_tracer: [chaindrop] entry=0x%" PRIx64 " frags=%zu insns=%u "
        "last_ft=0x%" PRIx64 " breaking_pc=0x%" PRIx64 " is_sys=%d "
        "await_ds=%d gen=%s\n",
        entry_pc_, fragments_.size(), chain_insns(fragments_), last_ft_,
        breaking_pc, (int)in_flight_is_system(), (int)awaiting_delay_slot_,
        my_gen_ == g_segment_generation.load(std::memory_order_relaxed)
            ? "same" : "stale");
    for (const BBTemplate *f : fragments_) {
        if (!f) {
            continue;
        }
        std::fprintf(out,
            "champsim_tracer: [chaindrop]   frag pc=0x%" PRIx64 " n=%u "
            "ft=0x%" PRIx64 " terminus=%u\n",
            f->start_pc, f->n_insns, f->fall_through_pc,
            (unsigned)f->terminus);
    }
}

BBTemplate *BBChainAssembler::finalize_truncated(BBTemplate *tail_frag,
                                                 uint32_t tail_insns)
{
    uint64_t entry = entry_pc_;
    std::vector<BBTemplate *> frags = fragments_;
    if (tail_frag) {
        if (frags.empty()) {
            entry = tail_frag->start_pc;
        }
        frags.push_back(tail_frag);
    }
    if (frags.empty() || entry == 0) {
        return nullptr;
    }
    BBTemplate *bb = g_template_store.commit_partial_bb(
        entry, frags.data(), (unsigned int)frags.size(),
        tail_frag ? tail_insns : 0);
    if (bb) {
        /* Committed, so the reset that follows is not a loss (see reset()). */
        finalized_ = true;
    }
    return bb;
}

void BBChainAssembler::reset()
{
    /* A reset that has not been preceded by a successful finalize() throws
     * live fragments away — they will never be emitted.  Count it; the
     * commit case (finalize() then reset()) is not a loss and is not
     * counted. */
    if (!finalized_ && !fragments_.empty()) {
        g_stats.reg_snap_chain_reset_drops++;
        g_stats.reg_snap_chain_reset_frags += fragments_.size();
        g_stats.reg_snap_chain_reset_insns += chain_insns(fragments_);
    }
    entry_pc_ = 0;
    last_ft_ = 0;
    awaiting_delay_slot_ = false;
    bb_complete_ = false;
    finalized_ = false;
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
    s.finalized = finalized_;
    s.fragments = std::move(fragments_);
    /* Leave *this in the reset state (fragments_ is moved-from -> cleared
     * below to be definite); a fresh chain starts cleanly after a detach. */
    fragments_.clear();
    entry_pc_ = 0;
    last_ft_ = 0;
    awaiting_delay_slot_ = false;
    bb_complete_ = false;
    finalized_ = false;
    return s;
}

void BBChainAssembler::attach_state(ChainState &&s)
{
    entry_pc_ = s.entry_pc;
    last_ft_ = s.last_ft;
    my_gen_ = s.my_gen;
    awaiting_delay_slot_ = s.awaiting_delay_slot;
    bb_complete_ = s.bb_complete;
    finalized_ = s.finalized;
    fragments_ = std::move(s.fragments);
}
