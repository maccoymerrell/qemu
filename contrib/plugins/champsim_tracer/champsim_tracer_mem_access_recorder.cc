/*
 * Wrong-Path Tracing Plugin — memory access recorder implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>

#include "champsim_tracer_mem_access_recorder.h"
#include "champsim_tracer_stats.h"
#include "champsim_tracer_trace_segment_manager.h"
#include "champsim_tracer_wp_thread_state.h"

MemAccessRecorder g_mem_recorder;

namespace {

thread_local std::vector<WPMemAccess> tls_cp_mem_accesses CST_TLS_HOT;
/* Memops whose insn_pc missed the previous drain's template, retained
 * for exactly one more drain.  The legitimate producer is a split BB
 * (e.g. the MIPS page-split branch whose delay slot executes in the
 * next TB): the straggler belongs to the neighboring entry, whose
 * drain immediately follows and whose template does contain its PC.
 * A second miss means the memop is a true orphan — recorded by an
 * executed-but-never-emitted path — and is dropped and counted. */
thread_local std::vector<WPMemAccess> tls_cp_carry;
thread_local GByteArray              *tls_mem_read_buf CST_TLS_HOT = nullptr;

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
    /* WP path always records the access ADDRESS (full speculative
     * footprint); g_features.wp_mem_data gates only the VALUE capture.
     *
     * The per-insn memop cap is unconditional: a wire-format
     * constraint (CST_FID_SLOT_COUNT slots/insn) and a loop bound for
     * spec-mode REP iterations that don't advance PC.
     *
     * Cache g_wp_state once: the dlopen'd .so puts the thread_local in
     * the general-dynamic TLS model, so each access otherwise goes
     * through __tls_get_addr (~3% of runtime, mostly this per-memop
     * callback). */
    WPThreadState &wp = g_wp_state;
    if (wp.in_progress) {
        if (insn_pc == wp.cur_insn_pc) {
            wp.cur_insn_count++;
        } else {
            wp.cur_insn_pc = insn_pc;
            wp.cur_insn_count = 1;
        }
        if (wp.cur_insn_count > CST_FID_SLOT_COUNT) {
            return;
        }
    } else if (!g_trace_segments.is_active_atomic() || g_capture_mute) {
        /* CP path.  Drop memops issued inside an asynchronous interrupt
         * (timer / device IRQ / scheduler tick): the async excursion is
         * excluded from the trace entirely — vcpu_tb_exec bails at the
         * same gate so the handler's BODY never appears — but this
         * per-memop callback still fires for the handler's instructions.
         * Without this gate those kernel memops pile into the CP
         * accumulator and, having no matching PC in the interrupted user
         * BB's template, collapse onto insn_index 0 when that BB drains
         * (a phantom 64-load/64-store blob on, e.g., an adrp).  Sync
         * faults stay traced (qemu_plugin_in_async_int() is false for
         * them), so their memops are recorded and attributed normally. */
        return;
    }

    WPMemAccess acc = {
        .insn_pc = insn_pc,
        .mem_vaddr = vaddr,
        .is_store = qemu_plugin_mem_is_store(info),
        .data_size = 0,
    };
    cst_wide_zero(&acc.data);

    /* CP path uses g_features.mem_data; WP path uses g_features.wp_mem_data
     * (already gated above to true if we reach here). */
    bool capture_data = wp.in_progress
        ? g_features.wp_mem_data : g_features.mem_data;
    if (capture_data) {
        capture_mem_value(info, vaddr, &acc);
    }

    if (wp.in_progress) {
        wp.mem_accesses.push_back(acc);
    } else {
        tls_cp_mem_accesses.push_back(acc);
        Stats &s = thread_stats_get();
        s.cp_total_mem_accesses++;
        if (Stats *h = g_current_hist_bucket) {
            h->cp_total_mem_accesses++;
        }
    }
}

void MemAccessRecorder::record_synthetic_load(uint64_t vaddr, uint64_t insn_pc)
{
    /* TLS-cache rationale: see record() above. */
    WPThreadState &wp = g_wp_state;
    if (wp.in_progress) {
        if (insn_pc == wp.cur_insn_pc) {
            wp.cur_insn_count++;
        } else {
            wp.cur_insn_pc = insn_pc;
            wp.cur_insn_count = 1;
        }
        if (wp.cur_insn_count > CST_FID_SLOT_COUNT) {
            return;
        }
    } else if (!g_trace_segments.is_active_atomic() || g_capture_mute) {
        /* Drop synthetic-EA loads issued inside an async interrupt — see
         * the rationale in record(). */
        return;
    }

    WPMemAccess acc = {
        .insn_pc = insn_pc,
        .mem_vaddr = vaddr,
        .is_store = false,
        .data_size = 0,
    };
    cst_wide_zero(&acc.data);

    if (wp.in_progress) {
        wp.mem_accesses.push_back(acc);
    } else {
        tls_cp_mem_accesses.push_back(acc);
        Stats &s = thread_stats_get();
        s.cp_total_mem_accesses++;
        if (Stats *h = g_current_hist_bucket) {
            h->cp_total_mem_accesses++;
        }
    }
}

size_t MemAccessRecorder::cp_count() const
{
    return tls_cp_mem_accesses.size();
}

void MemAccessRecorder::clear_cp()
{
    tls_cp_mem_accesses.clear();
    /* Discard carried stragglers too: every clear_cp() caller is
     * abandoning the pending CP context (segment close, foreign-TB
     * drop), and a straggler must not outlive the path that would
     * have owned it. */
    tls_cp_carry.clear();
}

void MemAccessRecorder::take_cp(std::vector<WPMemAccess> &out)
{
    /* Move the CP buffer out (leaving it empty) so a fault excursion can set
     * it aside while the handler records its own memops, then restore it on
     * resume — the faulting BB's memops accumulate across the detour exactly
     * as the WP walk accumulates past a spec fault. */
    out = std::move(tls_cp_mem_accesses);
    tls_cp_mem_accesses.clear();
}

void MemAccessRecorder::prepend_cp(const std::vector<WPMemAccess> &front)
{
    /* Re-inject @front ahead of the current CP buffer.  Memops are keyed by
     * absolute insn_pc and drained by matching against the template's
     * insn_pcs, so prefix-then-suffix order is preserved and indices resolve
     * correctly regardless of the per-piece template the pieces ran under. */
    if (front.empty()) {
        return;
    }
    tls_cp_mem_accesses.insert(tls_cp_mem_accesses.begin(),
                               front.begin(), front.end());
}

void MemAccessRecorder::drain_cp_into_dyn_params(
    std::vector<DynParam> &dyn_params,
    const BBTemplate *bb_tmpl)
{
    /* memops are in execution order and insn_pc is monotonically
     * non-decreasing across an entry's memops, so walk the template's
     * insn_pcs[] in lockstep to assign insn_index.  A cursor miss gets
     * one rescan from the top (an intra-entry loop or a merge-reinjected
     * prefix can legitimately step the PC backwards).  A memop whose PC
     * is nowhere in the template is NOT slotted onto insn 0 (where it
     * would masquerade as the entry's own traffic and derail the
     * lockstep for everything after it): first-time misses are carried
     * to the NEXT drain — a split BB's straggler (MIPS page-split delay
     * slot executing in the following TB) belongs to the neighboring
     * entry, whose template does contain its PC — and a second miss
     * drops the memop as a true orphan, counted in the run stats. */
    unsigned int n_insns = bb_tmpl ? bb_tmpl->n_insns : 0;
    auto slot_for = [&](const WPMemAccess &acc, unsigned int &idx) -> int {
        while (idx < n_insns && bb_tmpl->insn_pcs[idx] != acc.insn_pc) {
            idx++;
        }
        if (idx < n_insns) {
            return (int)idx;
        }
        unsigned int j = 0;
        while (j < n_insns && bb_tmpl->insn_pcs[j] != acc.insn_pc) {
            j++;
        }
        if (j < n_insns) {
            idx = j;
            return (int)j;
        }
        idx = 0;
        return -1;
    };
    auto push_dp = [&](const WPMemAccess &acc, int slot) {
        DynParam dp = {
            .type = (uint8_t)(acc.is_store ? DYN_STORE_ADDR : DYN_LOAD_ADDR),
            .insn_index = (uint16_t)slot,
            .value = acc.mem_vaddr,
            .data_size = acc.data_size,
            .data = acc.data,
        };
        dyn_params.push_back(dp);
    };

    /* Carried stragglers first (they are older than the live buffer);
     * a second miss is terminal. */
    unsigned int idx = 0;
    for (const WPMemAccess &acc : tls_cp_carry) {
        int slot = slot_for(acc, idx);
        if (slot < 0) {
            thread_stats_get().cp_orphan_mem_accesses++;
            continue;
        }
        push_dp(acc, slot);
    }
    tls_cp_carry.clear();

    idx = 0;
    for (const WPMemAccess &acc : tls_cp_mem_accesses) {
        int slot = slot_for(acc, idx);
        if (slot < 0) {
            tls_cp_carry.push_back(acc);
            continue;
        }
        push_dp(acc, slot);
    }
    tls_cp_mem_accesses.clear();
}

void MemAccessRecorder::cleanup_current_thread()
{
    /* clear() only — deliberately NOT shrink_to_fit().  Runs from
     * plugin_exit (atexit) before TLS destructors fire.  The CP buffer
     * can be MiB-sized (mmap-backed by glibc); forcing a free here has
     * been seen to SIGSEGV in __libc_free during late teardown.  The
     * TLS destructor frees it cleanly afterwards. */
    tls_cp_mem_accesses.clear();
    tls_cp_carry.clear();
    if (tls_mem_read_buf) {
        g_byte_array_unref(tls_mem_read_buf);
        tls_mem_read_buf = nullptr;
    }
}
