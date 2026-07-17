/*
 * Wrong-Path Tracing Plugin — marker byte-sequence detection.
 *
 * Extracted verbatim from champsim_tracer.cc: the per-ISA START/END marker
 * sequence build and the execution-time PC-adjacency runs that recognise a
 * marker in the user-space instruction stream.  The marker callbacks and the
 * per-thread run sets they own stay in champsim_tracer.cc.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <string.h>

#include "champsim_tracer.h"            /* trace_isa, TRACE_ISA_*, qemu-plugin */
#include "champsim_tracer_marker_detect.h"

MarkerSeq g_marker_seq;

void marker_seq_init(void)
{
    MarkerSeq &m = g_marker_seq;
    switch (trace_isa) {
    case TRACE_ISA_X86:
        static_assert(CST_MARKER_X86_SEQ_BYTES <= CST_MARKER_PAIR_SEQ_BYTES,
                      "MarkerSeq buffers sized by the pair sequence");
        cst_marker_x86_encode_seq_imm(m.start, CST_MARKER_MAGIC);
        cst_marker_x86_encode_seq_imm(m.end, CST_MARKER_END_MAGIC);
        m.insn_bytes = CST_MARKER_X86_INSN_BYTES;
        m.n_insns    = CST_MARKER_SEQ_LEN;
        m.valid      = true;
        break;
    case TRACE_ISA_AARCH64:
        cst_marker_a64_encode_seq_imm(m.start, CST_MARKER_MAGIC);
        cst_marker_a64_encode_seq_imm(m.end, CST_MARKER_END_MAGIC);
        m.insn_bytes = CST_MARKER_PAIR_INSN_BYTES;
        m.n_insns    = CST_MARKER_PAIR_SEQ_INSNS;
        m.valid      = true;
        break;
    case TRACE_ISA_RISCV:
        cst_marker_riscv_encode_seq_imm(m.start, CST_MARKER_MAGIC);
        cst_marker_riscv_encode_seq_imm(m.end, CST_MARKER_END_MAGIC);
        m.insn_bytes = CST_MARKER_PAIR_INSN_BYTES;
        m.n_insns    = CST_MARKER_PAIR_SEQ_INSNS;
        m.valid      = true;
        break;
    case TRACE_ISA_MIPS:
        cst_marker_mips_encode_seq_imm(m.start, CST_MARKER_MAGIC);
        cst_marker_mips_encode_seq_imm(m.end, CST_MARKER_END_MAGIC);
        m.insn_bytes = CST_MARKER_PAIR_INSN_BYTES;
        m.n_insns    = CST_MARKER_PAIR_SEQ_INSNS;
        m.valid      = true;
        break;
    default:
        m.valid = false;
        break;
    }
}

bool marker_word_match(const uint8_t *seq,
                       const uint8_t *bytes, uint8_t size)
{
    const MarkerSeq &m = g_marker_seq;
    if (size != m.insn_bytes) {
        return false;
    }
    for (uint32_t i = 0; i < m.n_insns; i++) {
        if (memcmp(bytes, seq + (size_t)i * m.insn_bytes, m.insn_bytes) == 0) {
            return true;
        }
    }
    return false;
}

/* Locate @asid's run slot in @set; when it has none, claim a slot — a free
 * one (run == 0) if any, else the least-recently-advanced — and reset it for
 * a fresh run.  The returned slot's asid always equals @asid. */
static inline MarkerExecRun *marker_run_slot(MarkerRunSet *set, uint64_t asid)
{
    int victim = 0;
    uint32_t victim_age = UINT32_MAX;
    for (int i = 0; i < MarkerRunSet::SLOTS; i++) {
        MarkerExecRun &r = set->runs[i];
        if (r.run > 0 && r.asid == asid) {
            return &r;                      /* this asid's live run */
        }
        /* A free slot is the ideal victim (age 0); otherwise the oldest. */
        uint32_t age = (r.run == 0) ? 0 : r.used;
        if (age < victim_age) {
            victim_age = age;
            victim = i;
        }
    }
    MarkerExecRun *r = &set->runs[victim];
    r->run = 0;                             /* fresh run for a new asid */
    r->asid = asid;
    r->next_pc = 0;
    return r;
}

const MarkerExecRun *marker_run_peek(const MarkerRunSet *set, uint64_t asid)
{
    for (int i = 0; i < MarkerRunSet::SLOTS; i++) {
        if (set->runs[i].run > 0 && set->runs[i].asid == asid) {
            return &set->runs[i];
        }
    }
    return nullptr;
}

bool marker_exec_step(MarkerRunSet *set, uint64_t pc, uint8_t size)
{
    if (qemu_plugin_get_priv_level() != 0) {
        return false;                       /* user-space stream only */
    }
    uint64_t asid = qemu_plugin_get_addr_space_id();
    uint32_t now = ++set->tick;
    MarkerExecRun *r = marker_run_slot(set, asid);
    /* The slot is keyed by asid, so adjacency is the only remaining test. */
    if (r->run > 0 && pc == r->next_pc) {
        r->run++;
    } else {
        r->run = 1;
    }
    r->used = now;
    r->next_pc = pc + size;
    if (r->run >= g_marker_seq.n_insns) {
        r->run = 0;
        return true;
    }
    return false;
}
