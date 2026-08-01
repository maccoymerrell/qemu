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

#include <atomic>
#include <stdlib.h>
#include <string.h>

#include "champsim_tracer.h"            /* trace_isa, TRACE_ISA_*, qemu-plugin */
#include "champsim_tracer_marker_detect.h"

MarkerSeq g_marker_seq;

/*
 * Detector counters are ATOMIC: every one of them is bumped from a marker
 * callback, which runs on the executing vCPU's own thread with no lock
 * held, so on an SMP guest plain increments lose updates and the numbers
 * these invariants are judged by would be wrong.
 */
static std::atomic<uint64_t> g_marker_runs_broken{0};   /* run reset mid-seq */
static std::atomic<uint64_t> g_marker_runs_adopted{0};  /* picked up cross-vCPU */
static std::atomic<uint64_t> g_marker_handoff_evicted{0}; /* live entry dropped */
static std::atomic<uint64_t> g_marker_local_evicted{0}; /* live LOCAL slot reused */
static std::atomic<uint64_t> g_marker_local_stale{0};  /* run left by a migration */


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
    if (r->run > 0) {
        /* A live run for another address space is being displaced.  The
         * bank still holds its partial state, so the sequence is
         * recoverable by adoption — a condition counter, not a loss. */
        g_marker_local_evicted.fetch_add(1, std::memory_order_relaxed);
    }
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
 * Process-wide handoff bank, one per sequence: every partial run in flight,
 * keyed by the address space AND the pc that run is waiting for.
 *
 * A guest task preempted between two marker instructions can resume on a
 * different vCPU, whose thread_local run set knows nothing about the
 * sequence in flight; without this, that sequence is silently lost.  Small,
 * mutex-guarded, and touched only when a marker word actually executes
 * (three per marker), so it is off every hot path.
 *
 * WHY (asid, next_pc) AND NOT asid ALONE.  Two threads of the SAME process
 * running marker sequences concurrently share one address space.  Keyed by
 * asid alone, each publish overwrote the other's entry, so a thread that
 * then migrated found its continuation gone and its sequence was lost with
 * nothing to say so.  Keyed by the position as well, concurrent threads
 * occupy separate entries; two threads at the SAME position hold identical
 * state (the sequence is linear, so the same pc implies the same run
 * length), which makes sharing one entry sound.
 *
 * THE ONLY WAY A PARTIAL RUN CAN NOW BE LOST is eviction from this bank —
 * every advance republishes immediately, including the advance that adopts.
 * So eviction of a LIVE entry is counted and tripwired (must be 0): after
 * that, no path drops an in-flight marker sequence silently.
 */
struct MarkerHandoff {
    uint64_t asid = 0;
    uint64_t next_pc = 0;
    uint32_t run = 0;
    uint32_t used = 0;
};
static constexpr int MK_HANDOFF_SLOTS = 64;
static MarkerHandoff g_handoff[2][MK_HANDOFF_SLOTS];
static uint32_t g_handoff_tick[2];
static GMutex g_handoff_lock;
uint64_t marker_runs_broken(void)
{
    return g_marker_runs_broken.load(std::memory_order_relaxed);
}

uint64_t marker_runs_adopted(void)
{
    return g_marker_runs_adopted.load(std::memory_order_relaxed);
}

uint64_t marker_handoff_evicted(void)
{
    return g_marker_handoff_evicted.load(std::memory_order_relaxed);
}

uint64_t marker_local_evicted(void)
{
    return g_marker_local_evicted.load(std::memory_order_relaxed);
}

uint64_t marker_local_stale(void)
{
    return g_marker_local_stale.load(std::memory_order_relaxed);
}

/*
 * CST_MKMIG_DIAG=<n> — log the first @n interesting detector events (an
 * adoption, a break, an eviction) with the vCPU that produced them, so a
 * cross-vCPU handoff can be read back to the migration that caused it.
 * Diagnostic only; nothing here changes a decision.
 */
static int mkmig_diag(void)
{
    static int v = -1;
    if (v < 0) {
        const char *e = getenv("CST_MKMIG_DIAG");
        v = e ? atoi(e) : 0;
    }
    return v;
}
static std::atomic<int> g_mkmig_printed{0};

static void mkmig_note(const char *what, unsigned int cpu_index, int bank,
                       uint64_t asid, uint64_t pc, uint64_t expect,
                       uint32_t run_before, uint32_t run_after)
{
    int lim = mkmig_diag();
    if (!lim) {
        return;
    }
    if (g_mkmig_printed.fetch_add(1, std::memory_order_relaxed) >= lim) {
        return;
    }
    fprintf(stderr, "[mkmig] %-7s vcpu=%u seq=%s asid=0x%" PRIx64
            " pc=0x%" PRIx64 " expected=0x%" PRIx64 " run %u->%u\n",
            what, cpu_index, bank ? "END" : "START", asid, pc, expect,
            run_before, run_after);
    fflush(stderr);
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

/*
 * Move @asid's partial run from @consumed_pc (the position it was waiting
 * at, which this word just satisfied) to @next_pc with length @run.  A
 * @run of 0 only retires the old entry — the sequence completed or died.
 */
static void handoff_update(int bank, uint64_t asid, uint64_t consumed_pc,
                           uint64_t next_pc, uint32_t run,
                           unsigned int cpu_index)
{
    g_mutex_lock(&g_handoff_lock);
    int free_slot = -1;
    int victim = 0;
    uint32_t victim_age = UINT32_MAX;
    for (int i = 0; i < MK_HANDOFF_SLOTS; i++) {
        MarkerHandoff &h = g_handoff[bank][i];
        if (h.run > 0 && h.asid == asid && h.next_pc == consumed_pc) {
            h.run = 0;                      /* our own previous position */
        }
        if (h.run == 0) {
            if (free_slot < 0) {
                free_slot = i;
            }
        } else if (h.used < victim_age) {
            victim_age = h.used;
            victim = i;
        }
    }
    if (run > 0) {
        int slot = free_slot >= 0 ? free_slot : victim;
        if (free_slot < 0) {
            /* A LIVE partial run is being dropped: the one remaining way a
             * marker sequence can go missing.  Never silent. */
            g_marker_handoff_evicted.fetch_add(1, std::memory_order_relaxed);
            mkmig_note("evict", cpu_index, bank, g_handoff[bank][slot].asid,
                       g_handoff[bank][slot].next_pc, next_pc,
                       g_handoff[bank][slot].run, 0);
        }
        MarkerHandoff &h = g_handoff[bank][slot];
        h.asid = asid;
        h.next_pc = next_pc;
        h.run = run;
        h.used = ++g_handoff_tick[bank];
    }
    g_mutex_unlock(&g_handoff_lock);
}

/* Is @asid's run at @next_pc still in the bank?  The bank is authoritative:
 * a per-vCPU run whose position is NO LONGER published was adopted by
 * another vCPU (the task migrated), so this vCPU's copy is a leftover, not
 * a broken sequence. */
static bool handoff_live(int bank, uint64_t asid, uint64_t next_pc)
{
    bool live = false;
    g_mutex_lock(&g_handoff_lock);
    for (int i = 0; i < MK_HANDOFF_SLOTS; i++) {
        const MarkerHandoff &h = g_handoff[bank][i];
        if (h.run > 0 && h.asid == asid && h.next_pc == next_pc) {
            live = true;
            break;
        }
    }
    g_mutex_unlock(&g_handoff_lock);
    return live;
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
                      MarkerWhich which, unsigned int cpu_index)
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
        /*
         * This vCPU's run cannot take this word.  ADOPTION IS TRIED FIRST,
         * whether or not a local run exists.
         *
         * A migration leaves the losing vCPU's local slot holding a run
         * that continued elsewhere.  When the task later migrates BACK
         * mid-sequence, that leftover is what the slot holds — at a
         * different position than the word now arriving — and treating it
         * as authoritative both reports a spurious break and, worse, drops
         * the live sequence on the floor: it restarts at 1 and the two or
         * three words remaining can never reach full length.  The bank
         * holds the live run, so ask the bank before believing the slot.
         */
        uint32_t adopted = handoff_disabled()
            ? 0 : handoff_adopt(bank, asid, pc);
        if (adopted) {
            g_marker_runs_adopted.fetch_add(1, std::memory_order_relaxed);
            mkmig_note("adopt", cpu_index, bank, asid, pc, pc,
                       adopted, adopted + 1);
            if (r->run > 0) {
                g_marker_local_stale.fetch_add(1, std::memory_order_relaxed);
            }
            r->run = adopted + 1;
        } else if (r->run > 0) {
            if (handoff_live(bank, asid, r->next_pc)) {
                /* The bank corroborates this run: a marker word really did
                 * arrive where a live sequence expected a different pc.
                 * Named, never silent (see marker_runs_broken). */
                g_marker_runs_broken.fetch_add(1, std::memory_order_relaxed);
                mkmig_note("broken", cpu_index, bank, asid, pc, r->next_pc,
                           r->run, 1);
            } else {
                /* Not published any more: this slot is the residue of a
                 * sequence that migrated away and completed elsewhere. */
                g_marker_local_stale.fetch_add(1, std::memory_order_relaxed);
            }
            r->run = 1;
        } else {
            r->run = 1;
        }
    }
    r->used = now;
    r->next_pc = pc + size;
    if (r->run >= g_marker_seq.n_insns) {
        r->run = 0;
        handoff_update(bank, asid, pc, 0, 0, cpu_index);
        return true;
    }
    handoff_update(bank, asid, pc, r->next_pc, r->run, cpu_index);
    if (handoff_force_split()) {
        r->run = 0;                         /* forced migration (control) */
    }
    return false;
}
