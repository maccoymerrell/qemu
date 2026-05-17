/*
 * Wrong-Path Tracing Plugin — branch history implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>

#include "champsim_tracer_branch_history.h"
#include "champsim_tracer_stats.h"

BranchHistory g_branch_history;

namespace {

uint64_t best_target_except(const BranchRecord *br,
                            uint64_t correct_target,
                            bool *found)
{
    uint64_t best_target = 0;
    uint32_t best_count = 0;
    uint32_t best_seen = 0;
    bool have_best = false;

    if (!br) {
        *found = false;
        return 0;
    }

    for (unsigned i = 0; i < BRANCH_TARGET_HISTORY; i++) {
        const BranchTargetHistoryEntry *entry = &br->targets[i];
        if (!entry->valid || entry->target == correct_target) {
            continue;
        }
        if (!have_best || entry->count > best_count ||
            (entry->count == best_count && entry->last_seen > best_seen)) {
            best_target = entry->target;
            best_count = entry->count;
            best_seen = entry->last_seen;
            have_best = true;
        }
    }

    *found = have_best;
    return best_target;
}

} /* namespace */

BranchRecord *BranchHistory::get_or_create(uint64_t pc, uint64_t fall_through)
{
    auto [it, inserted] = records_.try_emplace(pc);
    BranchRecord *br = &it->second;
    if (inserted) {
        memset(br, 0, sizeof(*br));
        br->pc = pc;
        br->fall_through = fall_through;
        g_stats.unique_branch_pcs++;
    }
    return br;
}

BranchRecord *BranchHistory::find(uint64_t pc)
{
    auto it = records_.find(pc);
    return it == records_.end() ? nullptr : &it->second;
}

void BranchHistory::note_target(BranchRecord *br, uint64_t target)
{
    if (!br) {
        return;
    }

    /* Bump LRU clock; on wrap reset all last_seen so comparisons stay valid. */
    br->target_tick++;
    if (br->target_tick == 0) {
        br->target_tick = 1;
        for (unsigned i = 0; i < BRANCH_TARGET_HISTORY; i++) {
            br->targets[i].last_seen = 0;
        }
    }
    uint32_t now = br->target_tick;
    int free_idx = -1;
    int victim_idx = -1;
    uint32_t victim_count = UINT32_MAX;
    uint32_t victim_seen = UINT32_MAX;

    for (unsigned i = 0; i < BRANCH_TARGET_HISTORY; i++) {
        BranchTargetHistoryEntry *entry = &br->targets[i];
        if (!entry->valid) {
            if (free_idx < 0) {
                free_idx = (int)i;
            }
            continue;
        }

        if (entry->target == target) {
            if (entry->count < UINT32_MAX) {
                entry->count++;
            }
            entry->last_seen = now;
            return;
        }

        if (entry->count < victim_count ||
            (entry->count == victim_count && entry->last_seen < victim_seen)) {
            victim_count = entry->count;
            victim_seen = entry->last_seen;
            victim_idx = (int)i;
        }
    }

    int idx = free_idx >= 0 ? free_idx : victim_idx;
    if (idx < 0) {
        return;
    }

    BranchTargetHistoryEntry *entry = &br->targets[idx];
    if (!entry->valid) {
        br->n_targets++;
    }
    entry->target = target;
    entry->count = 1;
    entry->last_seen = now;
    entry->valid = true;
}

uint64_t BranchHistory::indirect_wrong_target(const BranchRecord *br,
                                              uint64_t correct_target,
                                              uint64_t fall_through)
{
    bool found = false;

    if (br && br->n_targets >= 2) {
        uint64_t target = best_target_except(br, correct_target, &found);
        if (found) {
            return target;
        }
    }

    if (fall_through != correct_target) {
        return fall_through;
    }

    return best_target_except(br, correct_target, &found);
}
