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

/* The x86 marker is CST_MARKER_SEQ_LEN 5-byte movs; the fixed-width ISAs
 * use the longer two-insn pair sequence.  MarkerSeq's buffers are sized by
 * the pair sequence, so every ISA's pattern fits. */
static_assert(CST_MARKER_X86_SEQ_BYTES <= CST_MARKER_PAIR_SEQ_BYTES,
              "MarkerSeq buffers sized by the pair sequence");

void marker_seq_init(void)
{
    MarkerSeq &m = g_marker_seq;
    /* The per-ISA marker sequence is a declarative isa_properties[] row:
     * the encoder plus the fixed insn width and count the adjacency
     * detector needs.  A NULL encoder (the unknown ISA) leaves it invalid. */
    const IsaProperties &p = isa_properties[trace_isa];
    if (p.marker_encode_seq) {
        p.marker_encode_seq(m.start, CST_MARKER_MAGIC);
        p.marker_encode_seq(m.end, CST_MARKER_END_MAGIC);
        m.insn_bytes = p.marker_insn_bytes;
        m.n_insns    = p.marker_seq_insns;
        m.valid      = true;
    } else {
        m.valid = false;
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

/*
 * Process-wide handoff bank, one per sequence: the last published partial
 * run per address space.  A guest task preempted between two marker
 * instructions can resume on a different vCPU, whose thread_local run set
 * knows nothing about the sequence in flight; without this, that sequence
 * is silently lost.  Small, mutex-guarded, and touched only when a marker
 * word actually executes (three per marker), so it is off every hot path.
 */
struct MarkerHandoff {
    uint64_t asid = 0;
    uint64_t next_pc = 0;
    uint32_t run = 0;
    uint32_t used = 0;
};
static constexpr int MK_HANDOFF_SLOTS = 8;
static MarkerHandoff g_handoff[2][MK_HANDOFF_SLOTS];
static uint32_t g_handoff_tick[2];
static GMutex g_handoff_lock;
static uint64_t g_marker_runs_broken;      /* CP run reset mid-sequence */
static uint64_t g_marker_runs_adopted;     /* runs picked up across vCPUs */

uint64_t marker_runs_broken(void)
{
    return g_marker_runs_broken;
}

uint64_t marker_runs_adopted(void)
{
    return g_marker_runs_adopted;
}

uint64_t marker_runs_incomplete(void)
{
    /* Sequences that advanced at least once and never completed: every
     * advance publishes into the bank and a completion clears it, so a
     * slot still holding a partial run is a sequence that started and was
     * lost.  This is the tripwire for the silent miss — a marker whose
     * instructions were split apart and never rejoined. */
    uint64_t n = 0;
    g_mutex_lock(&g_handoff_lock);
    for (int b = 0; b < 2; b++) {
        for (int i = 0; i < MK_HANDOFF_SLOTS; i++) {
            if (g_handoff[b][i].run > 0) {
                n++;
            }
        }
    }
    g_mutex_unlock(&g_handoff_lock);
    return n;
}

/* Publish @asid's partial run; run == 0 clears the slot. */
static void handoff_publish(int bank, uint64_t asid, uint64_t next_pc,
                            uint32_t run)
{
    g_mutex_lock(&g_handoff_lock);
    int victim = 0;
    uint32_t victim_age = UINT32_MAX;
    for (int i = 0; i < MK_HANDOFF_SLOTS; i++) {
        MarkerHandoff &h = g_handoff[bank][i];
        if (h.run > 0 && h.asid == asid) {
            victim = i;
            victim_age = 0;
            break;
        }
        uint32_t age = (h.run == 0) ? 0 : h.used;
        if (age < victim_age) {
            victim_age = age;
            victim = i;
        }
    }
    MarkerHandoff &h = g_handoff[bank][victim];
    h.asid = asid;
    h.next_pc = next_pc;
    h.run = run;
    h.used = ++g_handoff_tick[bank];
    g_mutex_unlock(&g_handoff_lock);
}

/* Adopt @asid's published partial run if it expects exactly @pc.  Returns
 * the adopted run length (0 = nothing to adopt) and consumes the slot. */
static uint32_t handoff_adopt(int bank, uint64_t asid, uint64_t pc)
{
    uint32_t got = 0;
    g_mutex_lock(&g_handoff_lock);
    for (int i = 0; i < MK_HANDOFF_SLOTS; i++) {
        MarkerHandoff &h = g_handoff[bank][i];
        if (h.run > 0 && h.asid == asid && h.next_pc == pc) {
            got = h.run;
            h.run = 0;
            break;
        }
    }
    g_mutex_unlock(&g_handoff_lock);
    return got;
}

/*
 * Directed controls for the cross-vCPU handoff (diagnostic, off by default).
 *   CST_FENCE_FORCE_SPLIT — after every non-final advance, wipe the LOCAL
 *     run, so the next word must be adopted from the handoff bank: the
 *     migration case, forced on every sequence.
 *   CST_FENCE_NO_HANDOFF  — refuse to adopt, i.e. the pre-handoff code.
 * The pair is the positive control: FORCE_SPLIT alone must still detect
 * every sequence; FORCE_SPLIT with NO_HANDOFF must lose them all.
 */
static bool handoff_force_split(void)
{
    static int v = -1;
    if (v < 0) {
        v = getenv("CST_FENCE_FORCE_SPLIT") ? 1 : 0;
    }
    return v != 0;
}
static bool handoff_disabled(void)
{
    static int v = -1;
    if (v < 0) {
        v = getenv("CST_FENCE_NO_HANDOFF") ? 1 : 0;
    }
    return v != 0;
}

bool marker_exec_step(MarkerRunSet *set, uint64_t pc, uint8_t size,
                      MarkerWhich which)
{
    if (qemu_plugin_get_priv_level() != 0) {
        return false;                       /* user-space stream only */
    }
    int bank = (which == MARKER_WHICH_END) ? 1 : 0;
    uint64_t asid = qemu_plugin_get_addr_space_id();
    uint32_t now = ++set->tick;
    MarkerExecRun *r = marker_run_slot(set, asid);
    /* The slot is keyed by asid, so adjacency is the only remaining test. */
    if (r->run > 0 && pc == r->next_pc) {
        r->run++;
    } else {
        if (r->run > 0) {
            /* A live run for this address space expected a different pc:
             * the sequence was broken between its instructions.  Named,
             * never silent (see marker_runs_broken). */
            g_marker_runs_broken++;
            r->run = 1;
        } else {
            /* No local run.  A sequence that started on ANOTHER vCPU is
             * resumed here after a migration; adopt it when its published
             * continuation is exactly this pc. */
            uint32_t adopted = handoff_disabled()
                ? 0 : handoff_adopt(bank, asid, pc);
            if (adopted) {
                g_marker_runs_adopted++;
                r->run = adopted + 1;
            } else {
                r->run = 1;
            }
        }
    }
    r->used = now;
    r->next_pc = pc + size;
    if (r->run >= g_marker_seq.n_insns) {
        r->run = 0;
        handoff_publish(bank, asid, 0, 0);
        return true;
    }
    handoff_publish(bank, asid, r->next_pc, r->run);
    if (handoff_force_split()) {
        r->run = 0;                         /* forced migration (control) */
    }
    return false;
}
