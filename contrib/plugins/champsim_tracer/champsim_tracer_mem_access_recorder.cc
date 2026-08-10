/*
 * Wrong-Path Tracing Plugin — memory access recorder implementation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>

#include "champsim_tracer_bb_chain_assembler.h"
#include "champsim_tracer_mem_access_recorder.h"
#include "champsim_tracer_stats.h"
#include "champsim_tracer_trace_segment_manager.h"
#include "champsim_tracer_wp_thread_state.h"

MemAccessRecorder g_mem_recorder;

namespace {

/* Per-vCPU CP memop accumulator, indexed by cpu_index.  The capture-to-
 * drain lifetime crosses CP steps (a TB's memops are drained at that
 * vCPU's NEXT dispatch), so this must key by vCPU, not host thread:
 * round-robin TCG runs every vCPU on one thread, and the next dispatch
 * on that thread may belong to a different vCPU.  Under MTTCG the two
 * keyings coincide.  exec_lock (held around every producer's TB window
 * and every consumer) serialises access. */
std::vector<WPMemAccess> g_cp_mem_accesses[CST_PIN_MAX_VCPUS];
/* Memops whose insn_pc missed a drain's template, held for a later
 * one.  The legitimate producers are entries that follow the recording
 * entry in execution order: a split BB (the MIPS page-split branch
 * whose delay slot executes in the next TB), and a TB the splitter cut
 * into several memop-carrying fragments — the CPYFP/CPYFM/CPYFE
 * prologue/main/epilogue triple glibc's memcpy is on a FEAT_MOPS
 * guest becomes three consecutive entries whose memops all arrive in
 * one buffer, so the first entry's drain sees two entries' worth of
 * stragglers and the second entry's drain still sees one.
 *
 * A straggler is a true orphan — recorded by an executed-but-never-
 * emitted path — once the emission stream has moved PAST it, and the
 * evidence for that is a drain that claimed memops but none of the
 * carried ones: memops are drained in execution order, so an entry
 * claiming a NEWER memop while an older one goes unclaimed has left
 * the older one nothing to belong to.  A drain that claims nothing at
 * all is not that evidence and must not drop the carry — an
 * intermediate fan-out fragment legitimately moves no memory (a MOPS
 * main step with a sub-page transfer already finished by its prologue
 * is a routine case), and so does any memop-free BB.  Per-vCPU for
 * the same reason as the accumulator above. */
std::vector<WPMemAccess> g_cp_carries[CST_PIN_MAX_VCPUS];
thread_local GByteArray *tls_mem_read_buf CST_TLS_HOT = nullptr;

std::vector<WPMemAccess> &cp_mem(unsigned int cpu_index)
{
    return g_cp_mem_accesses[cpu_index < CST_PIN_MAX_VCPUS
                             ? cpu_index : CST_PIN_MAX_VCPUS - 1];
}

std::vector<WPMemAccess> &cp_carry(unsigned int cpu_index)
{
    return g_cp_carries[cpu_index < CST_PIN_MAX_VCPUS
                        ? cpu_index : CST_PIN_MAX_VCPUS - 1];
}

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
        case QEMU_PLUGIN_MEM_VALUE_INVALID:
        default:
            /* qemu_plugin_mem_get_value() degrades to this rather than
             * aborting when the access is wider than 128 bits (see
             * plugins/api.c).  Unreachable today -- the shift <= 4 guard
             * above already excludes anything past MO_128 -- but a
             * missing case here would silently mis-decode a future
             * wider MemOp instead of failing safe. */
            cst_wide_zero(&acc->data);
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

void MemAccessRecorder::record(unsigned int cpu_index,
                               qemu_plugin_meminfo_t info,
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
     * EARLY-OUT ORDER MATTERS: this callback fires for every guest
     * memop of the whole run, and outside a segment it must cost as
     * close to nothing as possible.  g_wp_in_progress and
     * g_capture_mute are POD __thread flags (one %fs load each; see
     * champsim_tracer_wp_thread_state.h), and is_active is one atomic
     * load — so the boot-long path is three loads and a return,
     * touching neither g_wp_state (whose thread_local wrapper +
     * dynamic-init guard measured ~3% of host cycles when it sat
     * first in this function) nor any other guarded TLS object. */
    bool wp_mode = g_wp_in_progress;
    if (!wp_mode && (!g_trace_segments.is_active_atomic() || g_capture_mute)) {
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
    if (wp_mode) {
        WPThreadState &wp = g_wp_state;
        if (insn_pc == wp.cur_insn_pc) {
            wp.cur_insn_count++;
        } else {
            wp.cur_insn_pc = insn_pc;
            wp.cur_insn_count = 1;
        }
        if (wp.cur_insn_count > CST_FID_SLOT_COUNT) {
            return;
        }
    }

    WPMemAccess acc = {
        .insn_pc = insn_pc,
        .mem_vaddr = vaddr,
        .is_store = qemu_plugin_mem_is_store(info),
        .data_size = 0,
    };
    cst_wide_zero(&acc.data);

    /* Synthetic-data fault tag: a wrong-path access to an absent/unreadable
     * page was served a deterministic placeholder value (never real memory).
     * The QEMU load/store path set the per-CPU sentinel for THIS access; the
     * memory callback fires immediately after it, so take+clear the flag here
     * and attribute it to this memop.  Only meaningful on the WP path (the
     * sentinel is never set on the correct path); clearing it unconditionally
     * keeps it from leaking. */
    bool mem_faulted = qemu_plugin_spec_mem_faulted_take();

    /* CP path uses g_features.mem_data; WP path uses g_features.wp_mem_data
     * (already gated above to true if we reach here). */
    bool capture_data = wp_mode
        ? g_features.wp_mem_data : g_features.mem_data;
    if (capture_data) {
        capture_mem_value(info, vaddr, &acc);
    }

    /* Physical-PAGE capture (physaddr=1, system mode).  Resolve the memop's
     * physical address through the live TLB entry and mask it to the page
     * granule.  qemu_plugin_get_hwaddr returns NULL for linux-user and for
     * any access with no resolvable RAM translation; MMIO is excluded (its
     * device traffic rides the DEVIO records, and it is not cacheable
     * memory).  A garbage-filled wrong-path access (absent/unreadable page
     * served a placeholder) has no real translation, so its ppage is
     * likewise omitted — the FID simply does not appear for that memop and
     * the delta stream keeps the last real translation as the baseline. */
    if (g_features.physaddr && !(wp_mode && mem_faulted)) {
        struct qemu_plugin_hwaddr *h = qemu_plugin_get_hwaddr(info, vaddr);
        if (h && !qemu_plugin_hwaddr_is_io(h)) {
            uint64_t pa = qemu_plugin_hwaddr_phys_addr(h);
            acc.ppage = pa & ~CST_PPAGE_OFFSET_MASK;
            acc.ppage_valid = true;
        }
    }

    if (wp_mode) {
        acc.faulted = mem_faulted;
        g_wp_state.mem_accesses.push_back(acc);
    } else {
        cp_mem(cpu_index).push_back(acc);
        Stats &s = thread_stats_get();
        s.cp_total_mem_accesses++;
        if (Stats *h = g_current_hist_bucket) {
            h->cp_total_mem_accesses++;
        }
    }
}

void MemAccessRecorder::record_synthetic_load(unsigned int cpu_index,
                                              uint64_t vaddr,
                                              uint64_t insn_pc)
{
    /* Early-out order rationale: see record() above. */
    bool wp_mode = g_wp_in_progress;
    if (!wp_mode && (!g_trace_segments.is_active_atomic() || g_capture_mute)) {
        /* Drop synthetic-EA loads issued inside an async interrupt — see
         * the rationale in record(). */
        return;
    }
    if (wp_mode) {
        WPThreadState &wp = g_wp_state;
        if (insn_pc == wp.cur_insn_pc) {
            wp.cur_insn_count++;
        } else {
            wp.cur_insn_pc = insn_pc;
            wp.cur_insn_count = 1;
        }
        if (wp.cur_insn_count > CST_FID_SLOT_COUNT) {
            return;
        }
    }

    WPMemAccess acc = {
        .insn_pc = insn_pc,
        .mem_vaddr = vaddr,
        .is_store = false,
        .data_size = 0,
    };
    cst_wide_zero(&acc.data);

    if (wp_mode) {
        g_wp_state.mem_accesses.push_back(acc);
    } else {
        cp_mem(cpu_index).push_back(acc);
        Stats &s = thread_stats_get();
        s.cp_total_mem_accesses++;
        if (Stats *h = g_current_hist_bucket) {
            h->cp_total_mem_accesses++;
        }
    }
}

size_t MemAccessRecorder::cp_count(unsigned int cpu_index) const
{
    return cp_mem(cpu_index).size();
}

size_t MemAccessRecorder::cp_carry_count(unsigned int cpu_index) const
{
    return cp_carry(cpu_index).size();
}

void MemAccessRecorder::clear_cp(unsigned int cpu_index)
{
    cp_mem(cpu_index).clear();
    /* Discard carried stragglers too: every clear_cp() caller is
     * abandoning the pending CP context (segment close, foreign-TB
     * drop), and a straggler must not outlive the path that would
     * have owned it. */
    cp_carry(cpu_index).clear();
}

void MemAccessRecorder::take_cp(unsigned int cpu_index,
                                std::vector<WPMemAccess> &out)
{
    /* Move the CP buffer out (leaving it empty) so a fault excursion can set
     * it aside while the handler records its own memops, then restore it on
     * resume — the faulting BB's memops accumulate across the detour exactly
     * as the WP walk accumulates past a spec fault. */
    out = std::move(cp_mem(cpu_index));
    cp_mem(cpu_index).clear();
}

void MemAccessRecorder::prepend_cp(unsigned int cpu_index,
                                   const std::vector<WPMemAccess> &front)
{
    /* Re-inject @front ahead of the current CP buffer.  Memops are keyed by
     * absolute insn_pc and drained by matching against the template's
     * insn_pcs, so prefix-then-suffix order is preserved and indices resolve
     * correctly regardless of the per-piece template the pieces ran under. */
    if (front.empty()) {
        return;
    }
    cp_mem(cpu_index).insert(cp_mem(cpu_index).begin(),
                             front.begin(), front.end());
}

void MemAccessRecorder::drain_cp_into_dyn_params(
    unsigned int cpu_index,
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
    /*
     * Impossibility check at emit, mirroring the offline lint
     * (tools/cst_lint.h): a memop resolving to a slot whose insn has
     * static max loads AND stores both zero cannot be that insn's own
     * traffic.  Exempt (see cst_lint.h for the full rationale):
     * atomics and the explicit memory classes (Capstone 6.0.0-Alpha7
     * leaves aarch64 register-offset / LSE-atomic MEM access flags
     * empty), PUSH / POP / RET (implicit stack traffic; corner
     * encodings like `pop %rsp` and `iretq` carry no static slot),
     * segment-register writers (the descriptor fetch QEMU's
     * segment-load helper performs is that mov's own load), and the
     * synthetic-EA classes (record_synthetic_load mints load-style
     * memops with no static slot).  A few byte tests on the hot path,
     * reached only for slots whose static counts are already zero.
     */
    static std::atomic<uint32_t> impossible_warned_gen{0};
    auto note_impossible_slot = [&](int slot) {
        const InsnFields *f = bb_tmpl->insn_fields
            ? &bb_tmpl->insn_fields[slot] : nullptr;
        if (!f || f->max_dep_loads != 0 || f->max_dep_stores != 0 ||
            f->is_atomic ||
            f->opcode == GEN_OP_LOAD ||
            f->opcode == GEN_OP_STORE ||
            f->opcode == GEN_OP_VEC_LOAD ||
            f->opcode == GEN_OP_VEC_STORE ||
            f->opcode == GEN_OP_PUSH ||
            f->opcode == GEN_OP_POP ||
            f->opcode == GEN_OP_RET ||
            f->opcode == GEN_OP_PREFETCH ||
            f->opcode == GEN_OP_CACHE_FLUSH ||
            f->opcode == GEN_OP_TLB_FLUSH) {
            return;
        }
        for (uint8_t d = 0; d < f->n_dst_regs; d++) {
            if (f->dst_regs[d] >= REG_SEG0 && f->dst_regs[d] < REG_SEG0 + 6) {
                return;
            }
        }
        thread_stats_get().cp_impossible_slot_memops++;
        uint32_t gen = g_segment_generation.load(std::memory_order_relaxed);
        uint32_t seen = impossible_warned_gen.load(std::memory_order_relaxed);
        if (seen != gen &&
            impossible_warned_gen.compare_exchange_strong(seen, gen)) {
            fprintf(stderr,
                    "champsim_tracer: WARNING memop attributed to a "
                    "memop-incapable insn (template %u insn[%d] "
                    "pc=0x%" PRIx64 ") — attribution corruption "
                    "upstream of the drain; counted in "
                    "cp_impossible_slot_memops (once per segment)\n",
                    bb_tmpl->template_id, slot, bb_tmpl->insn_pcs[slot]);
        }
    };
    auto push_dp = [&](const WPMemAccess &acc, int slot) {
        note_impossible_slot(slot);
        DynParam dp = {
            .type = (uint8_t)(acc.is_store ? DYN_STORE_ADDR : DYN_LOAD_ADDR),
            .insn_index = (uint16_t)slot,
            .value = acc.mem_vaddr,
            .data_size = acc.data_size,
            .data = acc.data,
            .ppage = acc.ppage,
            .ppage_valid = acc.ppage_valid,
        };
        dyn_params.push_back(dp);
    };

    /* Carried stragglers first (they are older than the live buffer).
     * Survivors compact to the front of the carry in place, so the
     * common case — nothing carried, or everything carried claimed —
     * allocates nothing. */
    std::vector<WPMemAccess> &carry = cp_carry(cpu_index);
    std::vector<WPMemAccess> &live = cp_mem(cpu_index);
    unsigned int idx = 0;
    bool claimed_carry = false;
    size_t n_stranded = 0;
    for (size_t r = 0; r < carry.size(); r++) {
        const WPMemAccess acc = carry[r];
        int slot = slot_for(acc, idx);
        if (slot < 0) {
            carry[n_stranded++] = acc;
            continue;
        }
        claimed_carry = true;
        push_dp(acc, slot);
    }
    carry.resize(n_stranded);

    idx = 0;
    bool claimed_live = false;
    for (const WPMemAccess &acc : live) {
        int slot = slot_for(acc, idx);
        if (slot < 0) {
            carry.push_back(acc);
            continue;
        }
        claimed_live = true;
        push_dp(acc, slot);
    }
    live.clear();

    /* This entry took memops, but none of the ones already waiting:
     * the stream has passed them (see cp_carry).  Drop exactly
     * those — the freshly-missed tail behind them is still in flight. */
    if (n_stranded && !claimed_carry && claimed_live) {
        thread_stats_get().cp_orphan_mem_accesses += n_stranded;
        carry.erase(carry.begin(), carry.begin() + n_stranded);
    }
}

void MemAccessRecorder::cleanup_current_thread()
{
    /* clear() only — deliberately NOT shrink_to_fit().  Runs from
     * plugin_exit (atexit) before static/TLS destructors fire.  The CP
     * buffers can be MiB-sized (mmap-backed by glibc); forcing a free
     * here has been seen to SIGSEGV in __libc_free during late
     * teardown.  The static-storage destructors free them cleanly
     * afterwards.  Clears EVERY vCPU's buffers (they are per-vCPU
     * statics now, reachable from any thread). */
    for (unsigned int i = 0; i < CST_PIN_MAX_VCPUS; i++) {
        g_cp_mem_accesses[i].clear();
        g_cp_carries[i].clear();
    }
    if (tls_mem_read_buf) {
        g_byte_array_unref(tls_mem_read_buf);
        tls_mem_read_buf = nullptr;
    }
}
