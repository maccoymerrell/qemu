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

/* Two marker immediates ("CST\x01"/"CST\x02" little-endian): the START
 * marker opens the trace window and ASID-pins the process; the END marker,
 * emitted just before the process exits, closes the window so a workload
 * shorter than the icount/simpoint budget ends cleanly instead of running
 * past process exit (where the freed address space may be reused).  Both are
 * the same CST_MARKER_SEQ_LEN-long run of identical immediate-loads. */
#define CST_MARKER_MAGIC      0x43535401u
#define CST_MARKER_END_MAGIC  0x43535402u
#define CST_MARKER_SEQ_LEN    3u

/* x86 / x86-64: one `mov $imm, %eax` is B8 imm32 (LE), 5 bytes.  A marker is
 * this insn repeated CST_MARKER_SEQ_LEN times. */
#define CST_MARKER_X86_INSN_BYTES 5
#define CST_MARKER_X86_SEQ_BYTES  (CST_MARKER_X86_INSN_BYTES * CST_MARKER_SEQ_LEN)

/* Encode one x86 `mov $imm, %eax` into @out (>= CST_MARKER_X86_INSN_BYTES).
 * Returns the byte count.  Detector and injector both build their patterns
 * from this so they cannot diverge. */
static inline int cst_marker_x86_encode_imm(uint8_t *out, uint32_t imm)
{
    out[0] = 0xB8;                                  /* mov imm32, %eax */
    out[1] = (uint8_t)(imm);
    out[2] = (uint8_t)(imm >> 8);
    out[3] = (uint8_t)(imm >> 16);
    out[4] = (uint8_t)(imm >> 24);
    return CST_MARKER_X86_INSN_BYTES;
}

/* One START-marker insn (kept for callers that only need the start magic). */
static inline int cst_marker_x86_encode_one(uint8_t *out)
{
    return cst_marker_x86_encode_imm(out, CST_MARKER_MAGIC);
}

/* Encode a full x86 marker sequence for @imm into @out (must hold
 * CST_MARKER_X86_SEQ_BYTES).  Returns the byte count. */
static inline int cst_marker_x86_encode_seq_imm(uint8_t *out, uint32_t imm)
{
    for (unsigned i = 0; i < CST_MARKER_SEQ_LEN; i++) {
        cst_marker_x86_encode_imm(out + i * CST_MARKER_X86_INSN_BYTES, imm);
    }
    return CST_MARKER_X86_SEQ_BYTES;
}

/* Full START-marker sequence. */
static inline int cst_marker_x86_encode_seq(uint8_t *out)
{
    return cst_marker_x86_encode_seq_imm(out, CST_MARKER_MAGIC);
}

/*
 * AArch64 / RISC-V / MIPS markers.  None of these can load a 32-bit
 * immediate in one instruction, so the marker UNIT is the minimal
 * two-instruction load pair, and the sequence is the unit repeated
 * CST_MARKER_SEQ_LEN times (6 fixed-width instructions, 24 bytes).
 * The redundancy argument is unchanged: three back-to-back loads of
 * the same constant into the same register are provably-dead work no
 * compiler emits.
 *
 * The RISC-V pair uses the unadjusted hi20/lo12 split, which is only
 * correct while (magic & 0xfff) < 0x800 — true for both magics
 * (0x...401 / 0x...402); keep that property if the magics ever change.
 */
#define CST_MARKER_PAIR_INSN_BYTES 4
#define CST_MARKER_PAIR_SEQ_INSNS  (2u * CST_MARKER_SEQ_LEN)
#define CST_MARKER_PAIR_SEQ_BYTES  \
    (CST_MARKER_PAIR_INSN_BYTES * CST_MARKER_PAIR_SEQ_INSNS)

static inline void cst_marker_put_u32le(uint8_t *out, uint32_t w)
{
    out[0] = (uint8_t)(w);
    out[1] = (uint8_t)(w >> 8);
    out[2] = (uint8_t)(w >> 16);
    out[3] = (uint8_t)(w >> 24);
}

/* aarch64: movz w0, #(imm & 0xffff) ; movk w0, #(imm >> 16), lsl #16 */
static inline int cst_marker_a64_encode_seq_imm(uint8_t *out, uint32_t imm)
{
    uint32_t movz = 0x52800000u | ((imm & 0xffffu) << 5);
    uint32_t movk = 0x72a00000u | ((imm >> 16) << 5);
    for (unsigned i = 0; i < CST_MARKER_SEQ_LEN; i++) {
        cst_marker_put_u32le(out + i * 8, movz);
        cst_marker_put_u32le(out + i * 8 + 4, movk);
    }
    return CST_MARKER_PAIR_SEQ_BYTES;
}

/* riscv: lui a0, (imm >> 12) ; addi a0, a0, (imm & 0xfff) */
static inline int cst_marker_riscv_encode_seq_imm(uint8_t *out, uint32_t imm)
{
    uint32_t lui  = ((imm >> 12) << 12) | (10u << 7) | 0x37u;
    uint32_t addi = ((imm & 0xfffu) << 20) | (10u << 15) | (10u << 7) | 0x13u;
    for (unsigned i = 0; i < CST_MARKER_SEQ_LEN; i++) {
        cst_marker_put_u32le(out + i * 8, lui);
        cst_marker_put_u32le(out + i * 8 + 4, addi);
    }
    return CST_MARKER_PAIR_SEQ_BYTES;
}

/* mips: lui $t0, (imm >> 16) ; ori $t0, $t0, (imm & 0xffff)
 * (little-endian word stream — mipsel only, matching the traced target) */
static inline int cst_marker_mips_encode_seq_imm(uint8_t *out, uint32_t imm)
{
    uint32_t lui = 0x3c080000u | (imm >> 16);
    uint32_t ori = 0x35080000u | (imm & 0xffffu);
    for (unsigned i = 0; i < CST_MARKER_SEQ_LEN; i++) {
        cst_marker_put_u32le(out + i * 8, lui);
        cst_marker_put_u32le(out + i * 8 + 4, ori);
    }
    return CST_MARKER_PAIR_SEQ_BYTES;
}

#endif /* CHAMPSIM_TRACER_MARKER_H */
