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
    prev_fall_through = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, prev_fall_through);
    insn_count = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, insn_count);
    insn_started = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, insn_started);
    is_active = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, is_active);
    asid_match = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, asid_match);
    trace_this_ctx = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, trace_this_ctx);
    pin_probe = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, pin_probe);
    evq_pending = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, evq_pending);
    budget = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, budget);
    user_seen = qemu_plugin_scoreboard_u64_in_struct(
        sb_, VCPUScoreBoard, user_seen);
}

VCPUScoreboard::~VCPUScoreboard()
{
    /*
     * Intentionally do NOT free the scoreboard here.
     *
     * g_scoreboard is a process-lifetime global, so this destructor runs
     * as a C++ static destructor at process teardown.  Its ordering versus
     * QEMU's libc-registered atexit handler that fires our QEMU_PLUGIN_EV_
     * ATEXIT callback (plugin_exit -> finish_trace_segment ->
     * PathBuilder::flush_final, which reads this scoreboard) is not
     * guaranteed.  In system-emulation teardown (qemu_default_main -> exit)
     * this destructor runs *before* plugin_exit; freeing here left
     * plugin_exit's final flush dereferencing a freed scoreboard -> SIGSEGV
     * (and no .cst produced).  In linux-user the order happened to be the
     * reverse, masking the bug.
     *
     * The scoreboard is a single allocation reclaimed by the OS at exit, so
     * leaving it for process teardown is harmless and removes the ordering
     * dependency entirely.  plugin_exit is the authoritative teardown hook
     * and runs while the scoreboard is still valid in both modes.
     */
}
