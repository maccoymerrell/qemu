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

    /* Set by MemAccessRecorder::record when mem_accesses crosses the
     * hard cap.  Read by simulate_wrong_path_ext on each loop iteration
     * to bail out early.  Speculatively executing one TB containing a
     * REP-prefixed string instruction (e.g. rep stosb / rep movsb) with
     * arbitrary CP-restored RCX can fire millions of memops in a
     * single qemu_plugin_exec_tb() call — without this cap the vector
     * grows without bound and eventually exhausts the heap, manifesting
     * as a NULL deref deep in QEMU's plugin machinery. */
    bool mem_overflow = false;

    /* Memops captured during the in-flight WP simulation.  Filled by
     * MemAccessRecorder::record while in_progress is true; cleared by
     * simulate_wrong_path_ext at end-of-sim. */
    std::vector<WPMemAccess> mem_accesses;

    /* Per-instruction memop counter for the cap check in
     * MemAccessRecorder::record.  cur_insn_pc tracks the PC the last
     * memop was attributed to; cur_insn_count is the run length of
     * consecutive same-PC memops.  Both reset whenever a memop arrives
     * with a different insn_pc. */
    uint64_t cur_insn_pc = 0;
    uint32_t cur_insn_count = 0;

    /* Snapshot of scoreboard state at WP-sim entry, restored at exit. */
    unsigned int saved_cpu_index = 0;
    uint64_t saved_insn_count = 0;
    uint64_t saved_prev_start_pc = 0;
    uint64_t saved_prev_last_pc = 0;
    uint64_t saved_prev_fall_through = 0;
    uint64_t saved_prev_bb_ends_in_branch = 0;
};

extern thread_local WPThreadState g_wp_state;

#endif /* CHAMPSIM_TRACER_WP_THREAD_STATE_H */
