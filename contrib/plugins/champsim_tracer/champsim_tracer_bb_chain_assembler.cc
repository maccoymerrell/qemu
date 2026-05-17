/*
 * Wrong-Path Tracing Plugin — BBChainAssembler implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "champsim_tracer_bb_chain_assembler.h"
#include "champsim_tracer_bb_template_cache.h"

thread_local BBChainAssembler g_cp_chain;
std::atomic<uint32_t> g_segment_generation{1};

void BBChainAssembler::append_fragment(uint64_t entry_pc,
                                       BBTemplate *frag,
                                       uint64_t fall_through)
{
    /*
     * On segment switch clear_bb_map() drops the unique_ptrs owning
     * fragments_'s BBTemplate*s, so a generation mismatch (bumped per
     * switch) means lazily drop the now-stale chain here — lets
     * reset_segment_local_state run on one thread without touching
     * other threads' thread_local chains.
     */
    uint32_t cur_gen = g_segment_generation.load(std::memory_order_relaxed);
    if (my_gen_ != cur_gen) {
        fragments_.clear();
        entry_pc_ = 0;
        last_ft_ = 0;
        my_gen_ = cur_gen;
    }
    if (entry_pc_ == 0 || last_ft_ != entry_pc) {
        /* Discontinuity: drop in-flight chain and start a new one. */
        fragments_.clear();
        entry_pc_ = entry_pc;
    }
    fragments_.push_back(frag);
    last_ft_ = fall_through;
}

BBTemplate *BBChainAssembler::finalize()
{
    if (entry_pc_ == 0 || fragments_.empty()) {
        return nullptr;
    }
    return g_bb_template_cache.get_or_create_bb_template(
        entry_pc_, fragments_.data(), (unsigned int)fragments_.size());
}

void BBChainAssembler::reset()
{
    entry_pc_ = 0;
    last_ft_ = 0;
    fragments_.clear();
}
