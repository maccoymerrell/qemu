/*
 * Wrong-Path Tracing Plugin — memory access recorder implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>

#include "champsim_tracer_mem_access_recorder.h"
#include "champsim_tracer_trace_segment_manager.h"

MemAccessRecorder g_mem_recorder;

namespace {

thread_local GArray     *tls_cp_mem_accesses = nullptr;
thread_local GByteArray *tls_mem_read_buf    = nullptr;

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
    WPMemAccess acc = {
        .insn_pc = insn_pc,
        .mem_vaddr = vaddr,
        .is_store = qemu_plugin_mem_is_store(info),
        .data_size = 0,
    };
    cst_wide_zero(&acc.data);

    if (enable_mem_data) {
        capture_mem_value(info, vaddr, &acc);
    }

    if (wp_in_progress && wp_mem_accesses) {
        g_array_append_val(wp_mem_accesses, acc);
        return;
    }

    if (g_trace_segments.is_active_atomic() && tls_cp_mem_accesses) {
        g_array_append_val(tls_cp_mem_accesses, acc);
    }
}

void MemAccessRecorder::ensure_cp_buffer()
{
    if (!tls_cp_mem_accesses) {
        tls_cp_mem_accesses = g_array_new(false, false, sizeof(WPMemAccess));
    }
}

size_t MemAccessRecorder::cp_count() const
{
    return tls_cp_mem_accesses ? tls_cp_mem_accesses->len : 0;
}

void MemAccessRecorder::clear_cp()
{
    if (tls_cp_mem_accesses) {
        g_array_set_size(tls_cp_mem_accesses, 0);
    }
}

void MemAccessRecorder::drain_cp_into_dyn_params(GArray *dyn_params,
                                                 const BBTemplate *bb_tmpl)
{
    if (!tls_cp_mem_accesses) {
        return;
    }
    /*
     * memops are recorded in execution order; insns within a BB execute
     * sequentially, so insn_pc is monotonically non-decreasing across
     * memops of a single entry.  Walk the template's insn_pcs[] in
     * lockstep to assign insn_index.
     */
    guint idx = 0;
    guint n_insns = bb_tmpl ? bb_tmpl->n_insns : 0;
    for (guint m = 0; m < tls_cp_mem_accesses->len; m++) {
        const WPMemAccess *acc = &g_array_index(tls_cp_mem_accesses,
                                                WPMemAccess, m);
        while (idx < n_insns && bb_tmpl->insn_pcs[idx] != acc->insn_pc) {
            idx++;
        }
        DynParam dp = {
            .type = (uint8_t)(acc->is_store ? DYN_STORE_ADDR : DYN_LOAD_ADDR),
            .insn_index = (uint16_t)(idx < n_insns ? idx : 0),
            .value = acc->mem_vaddr,
            .data_size = acc->data_size,
            .data = acc->data,
        };
        g_array_append_val(dyn_params, dp);
    }
    g_array_set_size(tls_cp_mem_accesses, 0);
}

void MemAccessRecorder::cleanup_current_thread()
{
    if (tls_cp_mem_accesses) {
        g_array_unref(tls_cp_mem_accesses);
        tls_cp_mem_accesses = nullptr;
    }
    if (tls_mem_read_buf) {
        g_byte_array_unref(tls_mem_read_buf);
        tls_mem_read_buf = nullptr;
    }
}
