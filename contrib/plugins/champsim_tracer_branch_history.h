/*
 * Wrong-Path Tracing Plugin — branch history.
 *
 * Per-PC observed-target history for branches.  Used to:
 *  - record the targets a CP indirect branch has taken,
 *  - choose a wrong-path target when the CP took an indirect branch,
 *  - count distinct branch PCs for the exit-time stats line.
 *
 * Storage is a typed map keyed by branch PC.  Records are plain structs
 * (BranchRecord, defined in champsim_tracer.h) so the WP simulator and
 * any future consumer can read fields directly without going through
 * the map.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_BRANCH_HISTORY_H
#define CHAMPSIM_TRACER_BRANCH_HISTORY_H

#include <unordered_map>

#include "champsim_tracer.h"

class BranchHistory {
public:
    /* Get-or-create the record for branch @pc.  On first sight, the record
     * is zero-initialized with .pc = pc and .fall_through = fall_through.
     * Never returns nullptr. */
    BranchRecord *get_or_create(uint64_t pc, uint64_t fall_through);

    /* Lookup without create.  Returns nullptr if @pc has not been seen. */
    BranchRecord *find(uint64_t pc);

    /* Record that branch @br took target @target on this execution.
     * Maintains the bounded LRU/LFU history in br->targets[]. */
    static void note_target(BranchRecord *br, uint64_t target);

    /* Pick a plausible wrong-path target for an indirect branch whose CP
     * target was @correct_target.  Prefers the most-frequent observed
     * target that is not @correct_target; falls back to @fall_through if
     * that differs from @correct_target; else returns 0. */
    static uint64_t indirect_wrong_target(const BranchRecord *br,
                                          uint64_t correct_target,
                                          uint64_t fall_through);

    size_t size() const { return records_.size(); }

private:
    std::unordered_map<uint64_t, BranchRecord> records_;
};

extern BranchHistory g_branch_history;

#endif /* CHAMPSIM_TRACER_BRANCH_HISTORY_H */
