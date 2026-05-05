/*
 * Wrong-Path Tracing Plugin — per-vCPU scoreboard wrapper.
 *
 * QEMU's plugin scoreboard mechanism gives the plugin a typed slab of
 * per-vCPU storage with O(1) handle-based access from both regular C
 * callbacks (qemu_plugin_u64_get/set) and inline TCG ops
 * (qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu).
 *
 * The handle fields here MUST remain plain qemu_plugin_u64 values: the
 * inline-TCG registration calls take the handle by value, not through
 * a method.  The wrapper class exists only to RAII-own the scoreboard
 * allocation and to give the handles a single typed home instead of
 * six top-level externs.
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
    qemu_plugin_u64 prev_bb_ends_in_branch;
    qemu_plugin_u64 insn_count;
    qemu_plugin_u64 last_counted_start_pc;

private:
    struct qemu_plugin_scoreboard *sb_;
};

extern VCPUScoreboard g_scoreboard;

#endif /* CHAMPSIM_TRACER_SCOREBOARD_H */
