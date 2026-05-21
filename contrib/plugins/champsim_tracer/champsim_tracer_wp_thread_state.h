/*
 * Wrong-Path Tracing Plugin — per-thread wrong-path simulator state.
 *
 * Each QEMU vCPU thread carries one WPThreadState.  Set during
 * simulate_wrong_path_ext(): the in_progress flag gates plugin
 * callbacks (mem callback routes to mem_accesses, reg-snap callback
 * suppresses, vcpu_tb_exec early-outs), and saved_* hold a snapshot
 * of the per-vCPU scoreboard fields the WP simulator clobbers and
 * later restores.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_WP_THREAD_STATE_H
#define CHAMPSIM_TRACER_WP_THREAD_STATE_H

#include <vector>

#include "champsim_tracer.h"

struct WPThreadState {
    /* Set by simulate_wrong_path_ext while a WP simulation is running.
     * Read by the mem/insn-snap callbacks and the tb-exec orchestrator
     * to gate CP-only logic. */
    bool in_progress = false;

    /* Memops captured during the in-flight WP simulation.  Filled by
     * MemAccessRecorder::record while in_progress is true; cleared by
     * simulate_wrong_path_ext at end-of-sim. */
    std::vector<WPMemAccess> mem_accesses;

    /* WP-side per-insn memop cap (MemAccessRecorder::record).
     * cur_insn_pc = PC of the last memop; cur_insn_count = run length
     * of consecutive same-PC memops.  Past CST_FID_SLOT_COUNT, further
     * same-PC memops are dropped; both reset on a different insn_pc. */
    uint64_t cur_insn_pc = 0;
    uint32_t cur_insn_count = 0;

    /* Snapshot of scoreboard state at WP-sim entry, restored at exit. */
    unsigned int saved_cpu_index = 0;
    uint64_t saved_insn_count = 0;
    uint64_t saved_prev_start_pc = 0;
    uint64_t saved_prev_fall_through = 0;
    uint64_t saved_prev_bb_terminus = 0;
};

extern thread_local WPThreadState g_wp_state;

#endif /* CHAMPSIM_TRACER_WP_THREAD_STATE_H */
