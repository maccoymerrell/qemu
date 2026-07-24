/*
 * Wrong-Path Tracing Plugin — memory access recorder.
 *
 * Holds the per-vCPU correct-path memop accumulator and the mem-data
 * read scratch.  The QEMU mem callback funnels here; record() routes
 * to the CP buffer or the WP buffer (owned by wp.cc) by
 * WPThreadState::in_progress.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_MEM_ACCESS_RECORDER_H
#define CHAMPSIM_TRACER_MEM_ACCESS_RECORDER_H

#include <vector>

#include "champsim_tracer.h"

class MemAccessRecorder {
public:
    /* Called from the QEMU mem callback once per memory access.
     * Builds a WPMemAccess (capturing data per g_features.mem_data on
     * the CP path, g_features.wp_mem_data on the WP path) and appends
     * it to the WP buffer if WPThreadState::in_progress, or to the CP
     * buffer if a trace segment is active. */
    void record(qemu_plugin_meminfo_t info,
                uint64_t vaddr,
                uint64_t insn_pc);

    /* Called from the per-insn synthetic-EA callback for prefetch /
     * cache-flush / TLB-flush instructions whose TCG translation does
     * not emit a memop.  Records the computed effective address as a
     * load-style WPMemAccess (no data, no store flag).  Same WP/CP
     * routing as record(). */
    void record_synthetic_load(uint64_t vaddr, uint64_t insn_pc);

    /* CP buffer accessors used by vcpu_tb_exec.  The CP buffer is a
     * thread_local std::vector that lazy-grows on first push. */
    size_t cp_count() const;
    void clear_cp();

    /* Set the CP buffer aside (move out, leaving it empty) across a
     * synchronous-fault excursion, and re-inject it on resume so the
     * faulting BB's memops accumulate across the detour.  See the .cc. */
    void take_cp(std::vector<WPMemAccess> &out);
    void prepend_cp(const std::vector<WPMemAccess> &front);

    /* Drain the CP accumulator into @dyn_params, attributing each
     * memop to the matching insn_pc within @bb_tmpl's insn list.
     * Empties the CP buffer on return. */
    void drain_cp_into_dyn_params(std::vector<DynParam> &dyn_params,
                                  const BBTemplate *bb_tmpl);

    /* Release the calling thread's read-scratch and CP buffer.  Same
     * pattern as RegSnapCollector::cleanup_current_thread. */
    static void cleanup_current_thread();
};

extern MemAccessRecorder g_mem_recorder;

#endif /* CHAMPSIM_TRACER_MEM_ACCESS_RECORDER_H */
