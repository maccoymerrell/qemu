/*
 * ChampSim Tracer — guest trace-marker contract.
 *
 * Single source of truth for the marker byte pattern, shared by the two
 * sides that must agree on it: the plugin (which DETECTS the marker at
 * translation time, see vcpu_tb_trans/marker_mov_match) and cst_attach
 * (which INJECTS it into a target's address space, see tools/cst_attach.c).
 * Keeping the magic, sequence length, and per-arch encoding here means the
 * detector and the injector can never silently diverge.
 *
 * The marker is CST_MARKER_SEQ_LEN identical immediate-load instructions in
 * a row.  Three back-to-back loads of the same constant into the same
 * register are provably-dead redundant work that no compiler emits and a
 * human only writes deliberately, so the pattern cannot occur in real code
 * by accident — the collision guarantee is structural, not probabilistic.
 *
 * The marker must EXECUTE inside the target's address space (its CR3 etc.),
 * because the plugin pins the trace window to whatever ASID is current when
 * the marker fires.  A launcher that runs the marker then execve's the
 * target does not work: execve replaces the address space.  So the marker
 * is either compiled into a synthetic workload or injected at the target's
 * entry point post-execve by cst_attach.
 *
 * Plain C header (also valid C++): cst_attach may be built as C.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_MARKER_H
#define CHAMPSIM_TRACER_MARKER_H

#include <stdint.h>

/* Marker immediate ("CST\x01" little-endian) and how many identical
 * immediate-loads form the sequence. */
#define CST_MARKER_MAGIC    0x43535401u
#define CST_MARKER_SEQ_LEN  3u

/* x86 / x86-64: one `mov $CST_MARKER_MAGIC, %eax` is B8 imm32 (LE), 5 bytes.
 * The full marker is this insn repeated CST_MARKER_SEQ_LEN times. */
#define CST_MARKER_X86_INSN_BYTES 5
#define CST_MARKER_X86_SEQ_BYTES  (CST_MARKER_X86_INSN_BYTES * CST_MARKER_SEQ_LEN)

/* Encode one x86 marker insn into @out (must hold CST_MARKER_X86_INSN_BYTES).
 * Returns the byte count.  Used by the detector to build its comparison
 * pattern and by the injector to build the bytes it pokes into the target. */
static inline int cst_marker_x86_encode_one(uint8_t *out)
{
    out[0] = 0xB8;                                  /* mov imm32, %eax */
    out[1] = (uint8_t)(CST_MARKER_MAGIC);
    out[2] = (uint8_t)(CST_MARKER_MAGIC >> 8);
    out[3] = (uint8_t)(CST_MARKER_MAGIC >> 16);
    out[4] = (uint8_t)(CST_MARKER_MAGIC >> 24);
    return CST_MARKER_X86_INSN_BYTES;
}

/* Encode the full x86 marker sequence into @out (must hold
 * CST_MARKER_X86_SEQ_BYTES).  Returns the byte count. */
static inline int cst_marker_x86_encode_seq(uint8_t *out)
{
    for (unsigned i = 0; i < CST_MARKER_SEQ_LEN; i++) {
        cst_marker_x86_encode_one(out + i * CST_MARKER_X86_INSN_BYTES);
    }
    return CST_MARKER_X86_SEQ_BYTES;
}

#endif /* CHAMPSIM_TRACER_MARKER_H */
