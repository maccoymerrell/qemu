/*
 * Wrong-Path Tracing Plugin — per-vCPU scoreboard wrapper.
 *
 * QEMU's plugin scoreboard gives typed per-vCPU storage with O(1)
 * handle access from both C callbacks (qemu_plugin_u64_get/set) and
 * inline TCG ops (qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu).
 *
 * The handle fields MUST stay plain qemu_plugin_u64: the inline-TCG
 * registration takes the handle by value, not through a method.  The
 * wrapper only RAII-owns the scoreboard allocation and gives the
 * handles one typed home instead of six externs.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_SCOREBOARD_H
#define CHAMPSIM_TRACER_SCOREBOARD_H

#include "champsim_tracer.h"

class VCPUScoreboard {
public:
    VCPUScoreboard();
    ~VCPUScoreboard();

    VCPUScoreboard(const VCPUScoreboard &) = delete;
    VCPUScoreboard &operator=(const VCPUScoreboard &) = delete;

    /* Public so inline-TCG ops can take the handle by value. */
    qemu_plugin_u64 current_pc;
    qemu_plugin_u64 prev_start_pc;
    qemu_plugin_u64 prev_fall_through;
    qemu_plugin_u64 insn_count;
    /* is_active mirror (per-vCPU 0/1) for cond_cb gating of per-insn
     * heavy callbacks. */
    qemu_plugin_u64 is_active;
    /* live-ASID == pinned-ASID flag (per-vCPU 0/1); see the field
     * comment in champsim_tracer.h. */
    qemu_plugin_u64 asid_match;
    /* Context gate for the heavy per-TB capture callback and its light
     * re-acquisition probe (per-vCPU 0/1); see the field comments in
     * champsim_tracer.h. */
    qemu_plugin_u64 trace_this_ctx;
    qemu_plugin_u64 pin_probe;
    /* Signed budget that counts down by n_insns per TB exec (via
     * INLINE_ADD_U64 with imm = (uint64_t)(-n_insns)).  When it drops
     * below 1, a cond_cb fires (vcpu_tb_check_budget) to handle the
     * threshold crossing — opening the next segment or shutting down.
     * Set to a large positive value while in-segment so the cb does
     * not fire; reset by finish_trace_segment to (next_eff_start -
     * current_icount). */
    qemu_plugin_u64 budget;
    /* Per-vCPU user-clock cursor for the marker-mode pinned fold; see
     * the field comment in champsim_tracer.h. */
    qemu_plugin_u64 user_seen;

private:
    struct qemu_plugin_scoreboard *sb_;
};

extern VCPUScoreboard g_scoreboard;

#endif /* CHAMPSIM_TRACER_SCOREBOARD_H */
