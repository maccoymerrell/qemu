/*
 * SOURCE SURVIVORS, per decode identity -- GENERATED, DO NOT HAND-EDIT.
 *
 * Re-emit with tools/gen_src_survivors.py; see that file for what a row
 * means and where the measurement comes from.  Every row here is a
 * register the tracer's per-ISA decode publishes as a source that QEMU's
 * ordered read list does not state -- the population R12.1 forbids
 * dropping when the source list stops being the operand walk's.
 *
 * DERIVED FROM A SNAPSHOT, and a snapshot is not a closure.  The corpus
 * is /mnt/md0/QEMU/cst_runs/exec70/snap/srcsurv_snapshot, 112 sidecar(s):
 *   x86_64   34 sidecar(s), 8 row(s), 3 REFUSED (reason on each row below)
 *   aarch64  28 sidecar(s), 16 row(s)
 *   riscv64  25 sidecar(s), 15 row(s)
 *   mipsel   25 sidecar(s), 1 row(s), 2 REFUSED (reason on each row below)
 * Nothing here says anything about an instruction no sidecar executed.
 *
 * Author: Maccoy Merrell.
 */
#ifndef CHAMPSIM_TRACER_SRC_SURVIVORS_H
#define CHAMPSIM_TRACER_SRC_SURVIVORS_H

#include <stdint.h>

#include "champsim_tracer_generic_ids.h"

typedef enum {
    SRC_SURV_FIXED = 0,   /* @reg, the same register on every instance */
    SRC_SURV_SELF  = 1,   /* @dst_pos, ONE slot of this instance's own  */
                          /* destination list -- never the whole list   */
} SrcSurvivorKind;

typedef struct {
    uint32_t decode_id;
    uint8_t  kind;        /* SrcSurvivorKind */
    uint8_t  reg;         /* generic id; REG_NONE for SRC_SURV_SELF */
    uint8_t  dst_pos;     /* SRC_SURV_SELF: which destination slot;
                           * 0 and unread for SRC_SURV_FIXED */
    const char *rule;     /* annotation: QEMU's spelling of the rule */
} SrcSurvivorRow;

typedef struct {
    const SrcSurvivorRow *rows;
    unsigned              n;
} SrcSurvivorTable;

/* x86_64 -- 8 rows, 2671 census entries, from 34 sidecar(s) */
/* REFUSED, not carried: 0x0000054bu NOP REG_GPR2 (nopl x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x0000054bu NOP REG_GPR5 (nopl x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x0000054bu NOP REG_SSP (rdsspq x16) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
static const SrcSurvivorRow g_src_survivors_x86_64[] = {
    { 0x00000384u, SRC_SURV_SELF , REG_NONE      , 0, "PINSR" },   /* pinsrd x24 */
    { 0x000003fdu, SRC_SURV_SELF , REG_NONE      , 0, "VMOVLPx_ld" },   /* movlpd x21 */
    { 0x00000419u, SRC_SURV_SELF , REG_NONE      , 0, "VMOVHPx_ld" },   /* movhps x29 */
    { 0x0000041au, SRC_SURV_SELF , REG_NONE      , 0, "VMOVHPx_ld" },   /* movhpd x12 */
    { 0x000006dau, SRC_SURV_FIXED, REG_SEG5      , 0, "RET" },   /* retq x2370 */
    { 0x00000767u, SRC_SURV_SELF , REG_NONE      , 1, "LEAVE" },   /* leave x205 */
    { 0xe3014efcu, SRC_SURV_SELF , REG_NONE      , 0, "decode-new/VCVTSI2Sx@vex=1" },   /* vcvtsi2sdl x4 */
    { 0xecac981bu, SRC_SURV_SELF , REG_NONE      , 0, "decode-new/VMOVLPx@vex=0" },   /* movsd x6 */
};

/* aarch64 -- 16 rows, 104 census entries, from 28 sidecar(s) */
static const SrcSurvivorRow g_src_survivors_aarch64[] = {
    { 0x10fdc617u, SRC_SURV_SELF , REG_NONE      , 1, "disas_a64/FMUL_v@0.1011100.1.....110111.........." },   /* fmul x6 */
    { 0x13e03a7eu, SRC_SURV_SELF , REG_NONE      , 1, "disas_a64/FSUB_v@0.0011101.1.....110101.........." },   /* fsub x6 */
    { 0x1929eab9u, SRC_SURV_SELF , REG_NONE      , 0, "disas_a64/INS_general" },   /* mov x6 */
    { 0x30a7252au, SRC_SURV_FIXED, REG_FCSR      , 0, "disas_a64/FABS_s" },   /* fabs x31 */
    { 0x583d7c95u, SRC_SURV_SELF , REG_NONE      , 1, "disas_a64/FDIV_v@0.1011100.1.....111111.........." },   /* fdiv x6 */
    { 0x5c29c765u, SRC_SURV_FIXED, REG_SYSFPEN   , 0, "disas_a64/MSR_i_SVCR" },   /* smstop x1 */
    { 0x5c29c765u, SRC_SURV_SELF , REG_NONE      , 0, "disas_a64/MSR_i_SVCR" },   /* smstop x1 */
    { 0x62e8a5aeu, SRC_SURV_FIXED, REG_PRED1     , 0, "disas_sve/LD_zpri@1010010....0....101............." },   /* ld1b x1 */
    { 0x63e69d96u, SRC_SURV_FIXED, REG_SP        , 0, "disas_a64/NOP@1111100110......................" },   /* prfm x6 */
    { 0x8e2f807fu, SRC_SURV_FIXED, REG_SP        , 0, "disas_a64/NOP@11111000100.........00.........." },   /* prfum x6 */
    { 0xca9ff590u, SRC_SURV_FIXED, REG_FCSR      , 0, "disas_a64/FNEG_s" },   /* fneg x22 */
    { 0xe91326acu, SRC_SURV_SELF , REG_NONE      , 1, "disas_a64/FADD_v@0.0011100.1.....110101.........." },   /* fadd x6 */
    { 0xeba5bbf5u, SRC_SURV_FIXED, REG_PRED0     , 0, "disas_sve/ST_zpri@1110010....0....111............." },   /* st1b x1 */
    { 0xeba5bbf5u, SRC_SURV_FIXED, REG_PRED1     , 0, "disas_sve/ST_zpri@1110010....0....111............." },   /* st1b x2 */
    { 0xeba5bbf5u, SRC_SURV_FIXED, REG_VEC0      , 0, "disas_sve/ST_zpri@1110010....0....111............." },   /* st1b x2 */
    { 0xeba5bbf5u, SRC_SURV_FIXED, REG_VEC1      , 0, "disas_sve/ST_zpri@1110010....0....111............." },   /* st1b x1 */
};

/* riscv64 -- 15 rows, 325 census entries, from 25 sidecar(s) */
static const SrcSurvivorRow g_src_survivors_riscv64[] = {
    { 0x6832c275u, SRC_SURV_FIXED, REG_VEC4      , 0, "decode_insn32/vsub_vv" },   /* vsub.vv x3 */
    { 0x6832c275u, SRC_SURV_FIXED, REG_VEC5      , 0, "decode_insn32/vsub_vv" },   /* vsub.vv x3 */
    { 0x6832c275u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vsub_vv" },   /* vsub.vv x3 */
    { 0x6832c275u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vsub_vv" },   /* vsub.vv x3 */
    { 0x7ba73b05u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vmv_v_v" },   /* vmv.v.v x96 */
    { 0x7ba73b05u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vmv_v_v" },   /* vmv.v.v x96 */
    { 0xd2488b0eu, SRC_SURV_FIXED, REG_VEC1      , 0, "decode_insn32/vadd_vv" },   /* vadd.vv x3 */
    { 0xd2488b0eu, SRC_SURV_FIXED, REG_VEC2      , 0, "decode_insn32/vadd_vv" },   /* vadd.vv x3 */
    { 0xd2488b0eu, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vadd_vv" },   /* vadd.vv x3 */
    { 0xd2488b0eu, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vadd_vv" },   /* vadd.vv x3 */
    { 0xd6082df1u, SRC_SURV_FIXED, REG_VEC7      , 0, "decode_insn32/vmul_vv" },   /* vmul.vv x3 */
    { 0xd6082df1u, SRC_SURV_FIXED, REG_VEC8      , 0, "decode_insn32/vmul_vv" },   /* vmul.vv x3 */
    { 0xd6082df1u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vmul_vv" },   /* vmul.vv x3 */
    { 0xd6082df1u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vmul_vv" },   /* vmul.vv x3 */
    { 0xecf2c479u, SRC_SURV_FIXED, REG_SYS       , 0, "decode_insn32/fence" },   /* fence x97 */
};

/* mipsel -- 1 row, 298 census entries, from 25 sidecar(s) */
/* REFUSED, not carried: 0x00000000u ? REG_COPROC0 (swc2 x1) --
 * the census printed NO decode identity for this row (id 0,
 * rule `?`): QEMU named no decode rule for the bytes.  That
 * is not an identity to key on -- a row keyed on it fires on
 * EVERY instruction whose rule is unknown.  Measured to be
 * wrong-path wander over undefined bytes, and not
 * reproducible: 1 run in 12 of the same cell produced it,
 * with a differing row count.  It stays in the loss
 * direction. */
/* REFUSED, not carried: 0x00000000u ? REG_GPR7 (swc2 x1) --
 * the census printed NO decode identity for this row (id 0,
 * rule `?`): QEMU named no decode rule for the bytes.  That
 * is not an identity to key on -- a row keyed on it fires on
 * EVERY instruction whose rule is unknown.  Measured to be
 * wrong-path wander over undefined bytes, and not
 * reproducible: 1 run in 12 of the same cell produced it,
 * with a differing row count.  It stays in the loss
 * direction. */
static const SrcSurvivorRow g_src_survivors_mipsel[] = {
    { 0x20e7cdf6u, SRC_SURV_SELF , REG_NONE      , 0, "translate_mips/OPC_MTHC1" },   /* mthc1 x298 */
};

/* Indexed by TraceISA.  A null row pointer means the arrays above say
 * which of the two things it is for that ISA -- a measured `(none)` or
 * a corpus that never reached it. */
static const SrcSurvivorTable g_src_survivor_tables[] = {
    [TRACE_ISA_UNKNOWN] = { NULL, 0 },
    [TRACE_ISA_X86    ] = { g_src_survivors_x86_64,
                            G_N_ELEMENTS(g_src_survivors_x86_64) },
    [TRACE_ISA_AARCH64] = { g_src_survivors_aarch64,
                            G_N_ELEMENTS(g_src_survivors_aarch64) },
    [TRACE_ISA_RISCV  ] = { g_src_survivors_riscv64,
                            G_N_ELEMENTS(g_src_survivors_riscv64) },
    [TRACE_ISA_MIPS   ] = { g_src_survivors_mipsel,
                            G_N_ELEMENTS(g_src_survivors_mipsel) },
};

/* 40 rows over the four ISAs. */

#endif /* CHAMPSIM_TRACER_SRC_SURVIVORS_H */
