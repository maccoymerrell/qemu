/*
 * ChampSim Tracer — marker detection.
 *
 * The whole marker is decided in the bytes; see the header for why that is
 * the mechanism and not an optimisation of one.
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
