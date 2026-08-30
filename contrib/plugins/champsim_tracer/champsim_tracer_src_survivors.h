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
 * is /mnt/md0/QEMU/cst_runs/p3/arc3/exec55/pass2/snapshot, 32 sidecar(s):
 *   x86_64   10 sidecar(s), 13 row(s), 3 REFUSED on an ambiguous id
 *   aarch64  8 sidecar(s), 8 row(s)
 *   riscv64  7 sidecar(s), 10 row(s), 1 REFUSED on an ambiguous id
 *   mipsel   7 sidecar(s), 1 row(s)
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
    SRC_SURV_SELF  = 1,   /* the instance's own destination registers   */
} SrcSurvivorKind;

typedef struct {
    uint32_t decode_id;
    uint8_t  kind;        /* SrcSurvivorKind */
    uint8_t  reg;         /* generic id; REG_NONE for SRC_SURV_SELF */
    const char *rule;     /* annotation: QEMU's spelling of the rule */
} SrcSurvivorRow;

typedef struct {
    const SrcSurvivorRow *rows;
    unsigned              n;
} SrcSurvivorTable;

/* x86_64 -- 13 rows, 603 census entries, from 10 sidecar(s) */
/* REFUSED, not carried: 0x0000054bu NOP REG_GPR0 (rdsspq x3) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x0000054bu NOP REG_SSP (rdsspq x3) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x00000774u x87 SELF (fxch x14) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
static const SrcSurvivorRow g_src_survivors_x86_64[] = {
    { 0x00000384u, SRC_SURV_SELF , REG_NONE      , "PINSR" },   /* pinsrd x8 */
    { 0x000003cdu, SRC_SURV_SELF , REG_NONE      , "VMOVLPx" },   /* movsd x2 */
    { 0x000003fdu, SRC_SURV_SELF , REG_NONE      , "VMOVLPx_ld" },   /* movlpd x7 */
    { 0x00000419u, SRC_SURV_SELF , REG_NONE      , "VMOVHPx_ld" },   /* movhps x4 */
    { 0x0000041au, SRC_SURV_SELF , REG_NONE      , "VMOVHPx_ld" },   /* movhpd x4 */
    { 0x000006dau, SRC_SURV_FIXED, REG_SEG5      , "RET" },   /* retq x527 */
    { 0x00000745u, SRC_SURV_FIXED, REG_SEG0      , "MOV" },   /* movw x2 */
    { 0x00000745u, SRC_SURV_FIXED, REG_SEG1      , "MOV" },   /* movw x2 */
    { 0x00000745u, SRC_SURV_FIXED, REG_SEG2      , "MOV" },   /* movw x2 */
    { 0x00000745u, SRC_SURV_FIXED, REG_SEG3      , "MOV" },   /* movw x2 */
    { 0x00000745u, SRC_SURV_FIXED, REG_SEG4      , "MOV" },   /* movw x2 */
    { 0x00000745u, SRC_SURV_FIXED, REG_SEG5      , "MOV" },   /* movw x2 */
    { 0x00000767u, SRC_SURV_SELF , REG_NONE      , "LEAVE" },   /* leave x39 */
};

/* aarch64 -- 8 rows, 15 census entries, from 8 sidecar(s) */
static const SrcSurvivorRow g_src_survivors_aarch64[] = {
    { 0x10fdc617u, SRC_SURV_SELF , REG_NONE      , "disas_a64/FMUL_v@0.1011100.1.....110111.........." },   /* fmul x2 */
    { 0x13e03a7eu, SRC_SURV_SELF , REG_NONE      , "disas_a64/FSUB_v@0.0011101.1.....110101.........." },   /* fsub x2 */
    { 0x1929eab9u, SRC_SURV_SELF , REG_NONE      , "disas_a64/INS_general" },   /* mov x2 */
    { 0x30a7252au, SRC_SURV_FIXED, REG_FCSR      , "disas_a64/FABS_s" },   /* fabs x1 */
    { 0x583d7c95u, SRC_SURV_SELF , REG_NONE      , "disas_a64/FDIV_v@0.1011100.1.....111111.........." },   /* fdiv x2 */
    { 0x63e69d96u, SRC_SURV_FIXED, REG_SP        , "disas_a64/NOP@1111100110......................" },   /* prfm x2 */
    { 0x8e2f807fu, SRC_SURV_FIXED, REG_SP        , "disas_a64/NOP@11111000100.........00.........." },   /* prfum x2 */
    { 0xe91326acu, SRC_SURV_SELF , REG_NONE      , "disas_a64/FADD_v@0.0011100.1.....110101.........." },   /* fadd x2 */
};

/* riscv64 -- 10 rows, 76 census entries, from 7 sidecar(s) */
/* REFUSED, not carried: 0xecf2c479u decode_insn32/fence REG_SYS (fence x17) --
 * the census counts this row as ADJUDICATION-OWED: an open
 * maintainer question, measured against the external
 * references and reverted.  Carrying it would zero the
 * count that blocks the flip while the question is open,
 * which is answering it by arithmetic. */
static const SrcSurvivorRow g_src_survivors_riscv64[] = {
    { 0x6832c275u, SRC_SURV_FIXED, REG_VEC4      , "decode_insn32/vsub_vv" },   /* vsub.vv x1 */
    { 0x6832c275u, SRC_SURV_FIXED, REG_VEC5      , "decode_insn32/vsub_vv" },   /* vsub.vv x1 */
    { 0x6832c275u, SRC_SURV_SELF , REG_NONE      , "decode_insn32/vsub_vv" },   /* vsub.vv x2 */
    { 0x7ba73b05u, SRC_SURV_SELF , REG_NONE      , "decode_insn32/vmv_v_v" },   /* vmv.v.v x64 */
    { 0xd2488b0eu, SRC_SURV_FIXED, REG_VEC1      , "decode_insn32/vadd_vv" },   /* vadd.vv x1 */
    { 0xd2488b0eu, SRC_SURV_FIXED, REG_VEC2      , "decode_insn32/vadd_vv" },   /* vadd.vv x1 */
    { 0xd2488b0eu, SRC_SURV_SELF , REG_NONE      , "decode_insn32/vadd_vv" },   /* vadd.vv x2 */
    { 0xd6082df1u, SRC_SURV_FIXED, REG_VEC7      , "decode_insn32/vmul_vv" },   /* vmul.vv x1 */
    { 0xd6082df1u, SRC_SURV_FIXED, REG_VEC8      , "decode_insn32/vmul_vv" },   /* vmul.vv x1 */
    { 0xd6082df1u, SRC_SURV_SELF , REG_NONE      , "decode_insn32/vmul_vv" },   /* vmul.vv x2 */
};

/* mipsel -- 1 row, 2 census entries, from 7 sidecar(s) */
static const SrcSurvivorRow g_src_survivors_mipsel[] = {
    { 0x20e7cdf6u, SRC_SURV_SELF , REG_NONE      , "translate_mips/OPC_MTHC1" },   /* mthc1 x2 */
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

/* 32 rows over the four ISAs. */

#endif /* CHAMPSIM_TRACER_SRC_SURVIVORS_H */
