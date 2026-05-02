/*
 * Wrong-Path Tracing Plugin — SimPoint manager.
 *
 * Loads a SimPoints "selections" file (lines: <interval_id> <cluster_id>)
 * and an optional adjacent ".weights" file, sorts entries by start_insn,
 * and iterates them so the driver can start/stop trace segments at the
 * right instruction-count boundaries.
 *
 * Each entry's window is [interval_id*interval, interval_id*interval +
 * interval) instructions.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_SIMPOINT_MANAGER_H
#define CHAMPSIM_TRACER_SIMPOINT_MANAGER_H

#include "champsim_tracer.h"

class SimPointManager {
public:
    SimPointManager() = default;
    ~SimPointManager();

    SimPointManager(const SimPointManager &) = delete;
    SimPointManager &operator=(const SimPointManager &) = delete;

    /* Parse @path with @interval_insns instructions per simpoint interval.
     * Sorts entries by start_insn; loads the adjacent ".weights" file
     * (sibling of @path) if present.  Returns true if at least one entry
     * was loaded. */
    bool load(const char *path, uint64_t interval_insns);

    /* True if any simpoint entries are loaded.  Driving code uses this
     * to decide whether to apply the simpoint state machine in the
     * vcpu_tb_exec hot path. */
    bool is_active() const { return entries_ && entries_->len > 0; }

    /* Total entries loaded. */
    size_t size() const { return entries_ ? entries_->len : 0; }

    /* Index of the entry the iterator is currently pointing at.  After
     * exhausting all entries this equals size(). */
    size_t current_index() const { return current_idx_; }

    /* The entry the iterator currently points at, or nullptr once
     * iteration is complete. */
    const SimPointEntry *current() const;

    /* Advance to the next entry. */
    void advance() { current_idx_++; }

    /* True once iteration has consumed every entry. */
    bool exhausted() const {
        return entries_ && current_idx_ >= entries_->len;
    }

private:
    GArray  *entries_ = nullptr;
    unsigned int    current_idx_ = 0;
    uint64_t interval_insns_ = 0;
};

extern SimPointManager g_simpoints;

#endif /* CHAMPSIM_TRACER_SIMPOINT_MANAGER_H */
