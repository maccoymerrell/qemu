/*
 * Wrong-Path Tracing Plugin — VCPUScoreboard implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "champsim_tracer_scoreboard.h"

VCPUScoreboard g_scoreboard;

VCPUScoreboard::VCPUScoreboard()
    : sb_(qemu_plugin_scoreboard_new(sizeof(VCPUScoreBoard)))
{
    current_pc = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, current_pc);
    prev_start_pc = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, prev_start_pc);
    prev_last_pc = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, prev_last_pc);
    prev_fall_through = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, prev_fall_through);
    prev_bb_ends_in_branch = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, prev_bb_ends_in_branch);
    insn_count = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, insn_count);
}

VCPUScoreboard::~VCPUScoreboard()
{
    if (sb_) {
        qemu_plugin_scoreboard_free(sb_);
    }
}
