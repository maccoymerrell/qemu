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
    qemu_plugin_u64 prev_last_pc;
    qemu_plugin_u64 prev_fall_through;
    qemu_plugin_u64 prev_bb_terminus;
    qemu_plugin_u64 insn_count;
    qemu_plugin_u64 last_counted_start_pc;

private:
    struct qemu_plugin_scoreboard *sb_;
};

extern VCPUScoreboard g_scoreboard;

#endif /* CHAMPSIM_TRACER_SCOREBOARD_H */
