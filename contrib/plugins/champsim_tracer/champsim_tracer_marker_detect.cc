/*
 * ChampSim Tracer — marker detection.
 *
 * The whole marker is decided in the bytes; see the header for why that is
 * the mechanism and not an optimisation of one.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <atomic>
#include <stdlib.h>
#include <string.h>

#include <unordered_map>

#include "champsim_tracer.h"            /* trace_isa, TRACE_ISA_*, qemu-plugin */
#include "champsim_tracer_marker_detect.h"

MarkerSeq g_marker_seq;

/* The one case the byte match cannot decide for itself (header). */
static std::atomic<uint64_t> g_marker_prefix_unreadable{0};
static std::atomic<uint64_t> g_marker_straddle_resolved{0};
static std::atomic<uint64_t> g_marker_straddle_conflicts{0};
static std::atomic<uint64_t> g_marker_straddle_undecided{0};

/* The x86 marker is CST_MARKER_SEQ_LEN 5-byte movs; the fixed-width ISAs
 * use the longer two-insn pair sequence.  MarkerSeq's buffers are sized by
 * the pair sequence, so every ISA's pattern fits. */
static_assert(CST_MARKER_X86_SEQ_BYTES <= CST_MARKER_PAIR_SEQ_BYTES,
              "MarkerSeq buffers sized by the pair sequence");

void marker_seq_init(void)
{
    MarkerSeq &m = g_marker_seq;
    /* The per-ISA marker sequence is a declarative isa_properties[] row:
     * the encoder plus the fixed insn width and count.  A NULL encoder
     * (the unknown ISA) leaves it invalid. */
    const IsaProperties &p = isa_properties[trace_isa];
    if (p.marker_encode_seq) {
        p.marker_encode_seq(m.start, CST_MARKER_MAGIC);
        p.marker_encode_seq(m.end, CST_MARKER_END_MAGIC);
        m.insn_bytes    = p.marker_insn_bytes;
        m.n_insns       = p.marker_seq_insns;
        m.seq_bytes     = (uint16_t)(m.insn_bytes * m.n_insns);
        m.prefix_bytes  = (uint16_t)(m.seq_bytes - m.insn_bytes);
        m.valid         = true;
    } else {
        m.valid = false;
    }
    /* The backward look reads prefix_bytes before the terminating
     * instruction; the whole sequence must fit the buffers above and the
     * scratch the callers stack-allocate. */
    if (m.valid && (m.seq_bytes > CST_MARKER_PAIR_SEQ_BYTES ||
                    m.insn_bytes == 0 || m.n_insns < 2)) {
        m.valid = false;
    }
}

/* The terminating instruction of @seq. */
static inline const uint8_t *marker_tail(const uint8_t *seq)
{
    return seq + g_marker_seq.prefix_bytes;
}

bool marker_tail_word_match(const uint8_t *bytes, uint8_t size)
{
    const MarkerSeq &m = g_marker_seq;
    if (!m.valid || size != m.insn_bytes) {
        return false;
    }
    return memcmp(bytes, marker_tail(m.start), m.insn_bytes) == 0 ||
           memcmp(bytes, marker_tail(m.end),   m.insn_bytes) == 0;
}

MarkerWhich marker_whole_match(const uint8_t *bytes, uint8_t size,
                               const uint8_t *prefix)
{
    const MarkerSeq &m = g_marker_seq;
    if (!m.valid || size != m.insn_bytes) {
        return MARKER_WHICH_NONE;
    }
    /* Whole-sequence equality, immediates included: the terminating
     * instruction AND every slot before it.  The two magics differ inside
     * the prefix on every target, so at most one of these can match. */
    if (memcmp(bytes, marker_tail(m.start), m.insn_bytes) == 0 &&
        memcmp(prefix, m.start, m.prefix_bytes) == 0) {
        return MARKER_WHICH_START;
    }
    if (memcmp(bytes, marker_tail(m.end), m.insn_bytes) == 0 &&
        memcmp(prefix, m.end, m.prefix_bytes) == 0) {
        return MARKER_WHICH_END;
    }
    return MARKER_WHICH_NONE;
}

uint64_t marker_prefix_unreadable(void)
{
    return g_marker_prefix_unreadable.load(std::memory_order_relaxed);
}

void marker_prefix_unreadable_note(void)
{
    g_marker_prefix_unreadable.fetch_add(1, std::memory_order_relaxed);
}

/* ---------------------------------------------------------------------------
 * Straddle: the physical page pair (see the header for why it is the key).
 *
 * Both tables are written at TRANSLATION time and read at translation and
 * execution time, on vCPU threads, with no plugin lock asserted — so they
 * carry their own.  A plain GMutex: it is POD, zero-initialised, and has no
 * destructor to race a plugin_exit (see docs/architecture.rst, "Immortal
 * process-wide aggregates"); the maps behind it are immortal for the same
 * reason.
 * ------------------------------------------------------------------------- */

static GMutex g_straddle_lock;

/* The decided verdict, keyed by the TAIL's physical address. */
struct MarkerStraddlePair {
    uint64_t    prefix_paddr = 0;
    MarkerWhich which = MARKER_WHICH_NONE;
    bool        conflicting = false;   /* a second, different prefix page */
};

static std::unordered_map<uint64_t, MarkerStraddleWitness> *g_straddle_witness;
static std::unordered_map<uint64_t, MarkerStraddlePair>    *g_straddle_pair;

/* Both tables are translation-derived caches of a handful of code sites, so
 * they are tiny in every real workload.  The cap is a memory bound, not a
 * policy: a table at its cap stops LEARNING (it never evicts a live entry
 * out from under a decision), and a straddle it therefore could not witness
 * shows up in marker_straddle_undecided(), which must be 0. */
static constexpr size_t STRADDLE_MAX = 4096;

void marker_straddle_witness_note(uint64_t tail_vaddr,
                                  const MarkerStraddleWitness &w)
{
    if ((!w.match_start && !w.match_end) || w.head_slots == 0) {
        return;
    }
    g_mutex_lock(&g_straddle_lock);
    if (!g_straddle_witness) {
        g_straddle_witness =
            new std::unordered_map<uint64_t, MarkerStraddleWitness>();
    }
    auto it = g_straddle_witness->find(tail_vaddr);
    if (it != g_straddle_witness->end()) {
        it->second = w;                       /* freshest translation wins */
    } else if (g_straddle_witness->size() < STRADDLE_MAX) {
        g_straddle_witness->emplace(tail_vaddr, w);
    }
    g_mutex_unlock(&g_straddle_lock);
}

bool marker_straddle_witness_get(uint64_t tail_vaddr,
                                 MarkerStraddleWitness *out)
{
    bool got = false;
    g_mutex_lock(&g_straddle_lock);
    if (g_straddle_witness) {
        auto it = g_straddle_witness->find(tail_vaddr);
        if (it != g_straddle_witness->end()) {
            *out = it->second;
            got = true;
        }
    }
    g_mutex_unlock(&g_straddle_lock);
    return got;
}

void marker_straddle_pair_note(uint64_t tail_paddr, uint64_t prefix_paddr,
                               MarkerWhich which)
{
    if (which == MARKER_WHICH_NONE) {
        return;
    }
    g_mutex_lock(&g_straddle_lock);
    if (!g_straddle_pair) {
        g_straddle_pair = new std::unordered_map<uint64_t, MarkerStraddlePair>();
    }
    auto it = g_straddle_pair->find(tail_paddr);
    if (it == g_straddle_pair->end()) {
        if (g_straddle_pair->size() < STRADDLE_MAX) {
            MarkerStraddlePair p;
            p.prefix_paddr = prefix_paddr;
            p.which = which;
            g_straddle_pair->emplace(tail_paddr, p);
        }
        g_mutex_unlock(&g_straddle_lock);
        return;
    }
    if (it->second.prefix_paddr == prefix_paddr && it->second.which == which) {
        g_mutex_unlock(&g_straddle_lock);
        return;                               /* the same pair again */
    }
    /* A DIFFERENT predecessor page behind this same tail page: the very
     * reuse the execution-time recheck existed to catch.  The tail no longer
     * determines the pair, so it must not be allowed to decide one. */
    it->second.conflicting = true;
    g_marker_straddle_conflicts.fetch_add(1, std::memory_order_relaxed);
    g_mutex_unlock(&g_straddle_lock);
}

/*
 * @live_prefix_paddr is the predecessor page's physical address AS THE
 * RUNNING ADDRESS SPACE MAPS IT, or 0 when that could not be resolved —
 * which is the ordinary case here, since a page whose bytes cannot be read
 * usually cannot be translated either.  When it CAN be resolved the pair is
 * checked in full and a mismatch refuses: that is the reuse case caught
 * outright rather than merely guarded against.
 */
MarkerWhich marker_straddle_pair_lookup(uint64_t tail_paddr,
                                        uint64_t live_prefix_paddr)
{
    MarkerWhich which = MARKER_WHICH_NONE;
    bool mismatched = false;
    g_mutex_lock(&g_straddle_lock);
    if (g_straddle_pair) {
        auto it = g_straddle_pair->find(tail_paddr);
        if (it != g_straddle_pair->end() && !it->second.conflicting) {
            if (live_prefix_paddr &&
                live_prefix_paddr != it->second.prefix_paddr) {
                mismatched = true;
            } else {
                which = it->second.which;
            }
        }
    }
    g_mutex_unlock(&g_straddle_lock);
    if (mismatched) {
        g_marker_straddle_conflicts.fetch_add(1, std::memory_order_relaxed);
    }
    if (which != MARKER_WHICH_NONE) {
        g_marker_straddle_resolved.fetch_add(1, std::memory_order_relaxed);
    }
    return which;
}

void marker_straddle_reset(void)
{
    g_mutex_lock(&g_straddle_lock);
    if (g_straddle_witness) {
        g_straddle_witness->clear();
    }
    if (g_straddle_pair) {
        g_straddle_pair->clear();
    }
    g_mutex_unlock(&g_straddle_lock);
}

uint64_t marker_straddle_pair_resolved(void)
{
    return g_marker_straddle_resolved.load(std::memory_order_relaxed);
}

uint64_t marker_straddle_conflicts(void)
{
    return g_marker_straddle_conflicts.load(std::memory_order_relaxed);
}

uint64_t marker_straddle_undecided(void)
{
    return g_marker_straddle_undecided.load(std::memory_order_relaxed);
}

void marker_straddle_undecided_note(void)
{
    g_marker_straddle_undecided.fetch_add(1, std::memory_order_relaxed);
}
