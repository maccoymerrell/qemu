/*
 * Wrong-Path Tracing Plugin — memory access recorder implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>

#include "champsim_tracer_mem_access_recorder.h"
#include "champsim_tracer_trace_segment_manager.h"
#include "champsim_tracer_wp_thread_state.h"

MemAccessRecorder g_mem_recorder;

namespace {

thread_local std::vector<WPMemAccess> tls_cp_mem_accesses;
thread_local GByteArray              *tls_mem_read_buf = nullptr;

GByteArray *read_scratch()
{
    if (!tls_mem_read_buf) {
        tls_mem_read_buf = g_byte_array_sized_new(CST_MAX_WIDE_BYTES);
    }
    g_byte_array_set_size(tls_mem_read_buf, 0);
    return tls_mem_read_buf;
}

void capture_mem_value(qemu_plugin_meminfo_t info,
                       uint64_t vaddr,
                       WPMemAccess *acc)
{
    unsigned shift = qemu_plugin_mem_size_shift(info);
    size_t access_size = shift >= 6 ? CST_MAX_WIDE_BYTES
                                    : ((size_t)1 << shift);
    if (access_size > CST_MAX_WIDE_BYTES) {
        access_size = CST_MAX_WIDE_BYTES;
    }
    acc->data_size = (uint8_t)access_size;

    if (shift <= 4) {
        qemu_plugin_mem_value val = qemu_plugin_mem_get_value(info);
        switch (val.type) {
        case QEMU_PLUGIN_MEM_VALUE_U8:
            acc->data = cst_wide_from_u64(val.data.u8);
            break;
        case QEMU_PLUGIN_MEM_VALUE_U16:
            acc->data = cst_wide_from_u64(val.data.u16);
            break;
        case QEMU_PLUGIN_MEM_VALUE_U32:
            acc->data = cst_wide_from_u64(val.data.u32);
            break;
        case QEMU_PLUGIN_MEM_VALUE_U64:
            acc->data = cst_wide_from_u64(val.data.u64);
            break;
        case QEMU_PLUGIN_MEM_VALUE_U128:
            cst_wide_zero(&acc->data);
            acc->data.limb[0] = val.data.u128.low;
            acc->data.limb[1] = val.data.u128.high;
            break;
        }
        return;
    }

    GByteArray *buf = read_scratch();
    if (qemu_plugin_read_memory_vaddr(vaddr, buf, access_size)) {
        cst_wide_from_le_bytes(&acc->data, buf->data, buf->len);
    } else {
        acc->data_size = 0;
    }
}

} /* namespace */

void MemAccessRecorder::record(qemu_plugin_meminfo_t info,
                               uint64_t vaddr,
                               uint64_t insn_pc)
{
    /* WP-side opt-out.  When the user disables WP memop tracing we
     * skip ALL work for the WP path (no per-insn cap update, no value
     * capture, no push) — this is the dominant share of trace bytes
     * and runtime cost on speculation-heavy workloads. */
    if (g_wp_state.in_progress) {
        if (!enable_wp_mem_data) {
            return;
        }
        /* Per-instruction memop cap on the wrong path.  After the
         * CST_FID_SLOT_COUNT'th same-PC memop we have no wire-format
         * slots left for this insn anyway, so silently drop the rest.
         * The matching forward-progress guard in simulate_wrong_path_ext
         * handles redirecting PC past stuck spec-mode REP iterations. */
        if (insn_pc == g_wp_state.cur_insn_pc) {
            g_wp_state.cur_insn_count++;
        } else {
            g_wp_state.cur_insn_pc = insn_pc;
            g_wp_state.cur_insn_count = 1;
        }
        if (g_wp_state.cur_insn_count > CST_FID_SLOT_COUNT) {
            return;
        }
    } else if (!g_trace_segments.is_active_atomic()) {
        return;
    }

    WPMemAccess acc = {
        .insn_pc = insn_pc,
        .mem_vaddr = vaddr,
        .is_store = qemu_plugin_mem_is_store(info),
        .data_size = 0,
    };
    cst_wide_zero(&acc.data);

    /* CP path uses enable_mem_data; WP path uses enable_wp_mem_data
     * (already gated above to true if we reach here). */
    bool capture_data = g_wp_state.in_progress
        ? enable_wp_mem_data : enable_mem_data;
    if (capture_data) {
        capture_mem_value(info, vaddr, &acc);
    }

    if (g_wp_state.in_progress) {
        g_wp_state.mem_accesses.push_back(acc);
    } else {
        tls_cp_mem_accesses.push_back(acc);
    }
}

size_t MemAccessRecorder::cp_count() const
{
    return tls_cp_mem_accesses.size();
}

void MemAccessRecorder::clear_cp()
{
    tls_cp_mem_accesses.clear();
}

void MemAccessRecorder::drain_cp_into_dyn_params(
    std::vector<DynParam> &dyn_params,
    const BBTemplate *bb_tmpl)
{
    /*
     * memops are recorded in execution order; insns within a BB execute
     * sequentially, so insn_pc is monotonically non-decreasing across
     * memops of a single entry.  Walk the template's insn_pcs[] in
     * lockstep to assign insn_index.
     */
    unsigned int idx = 0;
    unsigned int n_insns = bb_tmpl ? bb_tmpl->n_insns : 0;
    for (const WPMemAccess &acc : tls_cp_mem_accesses) {
        while (idx < n_insns && bb_tmpl->insn_pcs[idx] != acc.insn_pc) {
            idx++;
        }
        DynParam dp = {
            .type = (uint8_t)(acc.is_store ? DYN_STORE_ADDR : DYN_LOAD_ADDR),
            .insn_index = (uint16_t)(idx < n_insns ? idx : 0),
            .value = acc.mem_vaddr,
            .data_size = acc.data_size,
            .data = acc.data,
        };
        dyn_params.push_back(dp);
    }
    tls_cp_mem_accesses.clear();
}

void MemAccessRecorder::cleanup_current_thread()
{
    /* tls_cp_mem_accesses is a thread_local vector.  We clear() it
     * here for symmetry with the tls_mem_read_buf release below, but
     * deliberately DO NOT call shrink_to_fit().  This function runs
     * from plugin_exit (atexit) before the TLS destructors fire; on
     * real workloads the CP buffer can be MiB-sized (e.g. one REP
     * STOSB iterating millions of times records millions of memops),
     * and at that size glibc backs the allocation with a direct mmap.
     * Forcing a free at atexit-time has been observed to SIGSEGV deep
     * in __libc_free during late process teardown, presumably because
     * some heap-management state is already torn down.  The TLS
     * destructor naturally walks the vector's destructor afterwards
     * and frees the buffer cleanly. */
    tls_cp_mem_accesses.clear();
    if (tls_mem_read_buf) {
        g_byte_array_unref(tls_mem_read_buf);
        tls_mem_read_buf = nullptr;
    }
}
