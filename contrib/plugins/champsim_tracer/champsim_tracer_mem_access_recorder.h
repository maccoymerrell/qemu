/*
 * Wrong-Path Tracing Plugin — memory access recorder.
 *
 * Holds the per-vCPU correct-path memop accumulator (cp_mem_accesses)
 * and the read scratch used to capture mem-data values via
 * qemu_plugin_read_memory_vaddr.  The QEMU mem callback funnels into
 * this recorder; routing between the CP buffer and the WP buffer
 * (owned by wp.cc, lifetime spans one wrong-path simulation) happens
 * inside record() based on wp_in_progress.
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
     * Builds a WPMemAccess (capturing data when CST_FLAG_MEM_DATA is
     * enabled) and appends it to the WP buffer if wp_in_progress, or
     * to the CP buffer if a trace segment is active. */
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
     * thread_local std::vector that lazy-grows on first push; no
     * explicit pre-allocation step is needed. */
    size_t cp_count() const;
    void clear_cp();

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
