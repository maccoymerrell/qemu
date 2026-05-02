/*
 * Wrong-Path Tracing Plugin — BBChainAssembler implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "champsim_tracer_bb_chain_assembler.h"
#include "champsim_tracer_bb_template_cache.h"

BBChainAssembler g_cp_chain;

void BBChainAssembler::append_fragment(uint64_t entry_pc,
                                       BBTemplate *frag,
                                       uint64_t fall_through)
{
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
