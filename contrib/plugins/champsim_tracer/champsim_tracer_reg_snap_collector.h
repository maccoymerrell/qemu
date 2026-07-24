/*
 * Wrong-Path Tracing Plugin — register-value snapshot collector.
 *
 * Reads architectural register values via the QEMU plugin API into
 * RegSnap records for the trace's reg-data section.
 *
 * LIVE is the path in active use: read each named register on demand on
 * the calling thread.  Used by the per-insn CP snap callback and the WP
 * simulator, both via capture_insn_snaps_live() — per instruction, this
 * captures its DESTINATION registers (dst_qemu_reg_keys), read right
 * after the instruction executed.
 *
 * WIDE pre-fragment (capture_wide() / capture_insn_snaps()) has no
 * caller today; the wide-snapshot-then-index approach it implements was
 * dropped from the WP path in favor of the live per-insn dst reads
 * above.  Left in place for any future caller that needs a single
 * upfront snapshot instead of one read per instruction.
 *
 * Wide snap + read scratch are thread_local (one per vCPU thread);
 * cleanup_current_thread() releases them at plugin exit.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_REG_SNAP_COLLECTOR_H
#define CHAMPSIM_TRACER_REG_SNAP_COLLECTOR_H

#include <vector>

#include "champsim_tracer.h"

class RegSnapCollector {
public:
    /* Read register @key on @cpu_index live.  @out is zero-filled if
     * @key is invalid or QEMU does not expose the register. */
    void read_into_snap(unsigned int cpu_index,
                        const QemuRegKey *key,
                        RegSnap *out);

    /* Wide-snap path used by the wrong-path simulator. */
    WideRegSnap *capture_wide(unsigned int cpu_index);

    /* No-op for symmetry with the wp.cc API; wide snaps live in a
     * thread_local scratch and have no per-call lifetime. */
    static void free_wide(WideRegSnap *) {}

    /* Append dest-reg snaps for instruction @insn_idx of @tmpl into
     * @out_snaps, sourced from the wide pre-fragment snap @wide.
     * Unused today — see the file header. */
    void capture_insn_snaps(const WideRegSnap *wide,
                            const BBTemplate *tmpl,
                            uint32_t insn_idx,
                            std::vector<RegSnap> &out_snaps);

    /* Append dest-reg snaps live, reading @cpu_index's registers
     * directly. */
    void capture_insn_snaps_live(unsigned int cpu_index,
                                 const BBTemplate *tmpl,
                                 uint32_t insn_idx,
                                 std::vector<RegSnap> &out_snaps);

    /* Release the calling thread's wide-snap and read-scratch buffers.
     * Plugin exit calls this on the main thread; other threads' state
     * leaks to process exit, same as before the refactor. */
    static void cleanup_current_thread();
};

extern RegSnapCollector g_reg_snaps;

#endif /* CHAMPSIM_TRACER_REG_SNAP_COLLECTOR_H */
