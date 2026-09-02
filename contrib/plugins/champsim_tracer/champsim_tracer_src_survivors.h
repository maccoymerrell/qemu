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
 * is /mnt/md0/QEMU/cst_runs/exec103/gensnap/snap, 80 sidecar(s):
 *   x86_64   24 sidecar(s), 8 row(s), 2 REFUSED (reason on each row below)
 *   aarch64  20 sidecar(s), 11 row(s), 6 REFUSED (reason on each row below)
 *   riscv64  18 sidecar(s), 25 row(s), 6 REFUSED (reason on each row below)
 *   mipsel   18 sidecar(s), 5 row(s)
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

/* x86_64 -- 8 rows, 517 census entries, from 24 sidecar(s) */
/* REFUSED, not carried: 0x0000054bu NOP REG_GPR2 (nopl x2) --
 * this decode id carries another FIXED row from the SAME
 * NUMBERED BANK, so the pair claims one rule reads two
 * different registers of that bank on every instance --
 * an ENCODED OPERAND frozen at whatever the deriving
 * corpus ran.  Measured fabricating on live instructions
 * (riscv64 RVV, x86 scalar FMA, aarch64 st4).  The
 * register the encoding names is published by the
 * emulator's own statement; this row published the
 * deriving corpus's instead.  An adjudicated correction
 * under R15/R16, not a loss under R12.1. */
/* REFUSED, not carried: 0x0000054bu NOP REG_GPR5 (nopl x2) --
 * this decode id carries another FIXED row from the SAME
 * NUMBERED BANK, so the pair claims one rule reads two
 * different registers of that bank on every instance --
 * an ENCODED OPERAND frozen at whatever the deriving
 * corpus ran.  Measured fabricating on live instructions
 * (riscv64 RVV, x86 scalar FMA, aarch64 st4).  The
 * register the encoding names is published by the
 * emulator's own statement; this row published the
 * deriving corpus's instead.  An adjudicated correction
 * under R15/R16, not a loss under R12.1. */
static const SrcSurvivorRow g_src_survivors_x86_64[] = {
    { 0x00000419u, SRC_SURV_SELF , REG_NONE      , 0, "VMOVHPx_ld" },   /* movhps x25 */
    { 0x0000041au, SRC_SURV_SELF , REG_NONE      , 0, "VMOVHPx_ld" },   /* movhpd x8 */
    { 0x000004c9u, SRC_SURV_FIXED, REG_SYSTIMER  , 0, "RDTSC" },   /* rdtsc x20 */
    { 0x00000507u, SRC_SURV_SELF , REG_NONE      , 0, "CPUID" },   /* cpuid x124 */
    { 0x00000507u, SRC_SURV_SELF , REG_NONE      , 2, "CPUID" },   /* cpuid x124 */
    { 0x00000767u, SRC_SURV_SELF , REG_NONE      , 1, "LEAVE" },   /* leave x201 */
    { 0xdb9bac2bu, SRC_SURV_FIXED, REG_SSP       , 0, "decode-new/NOP@f3=1,modrm=11001..." },   /* rdsspq x13 */
    { 0xe3014efcu, SRC_SURV_SELF , REG_NONE      , 0, "decode-new/VCVTSI2Sx@vex=1" },   /* vcvtsi2sdl x2 */
};

/* aarch64 -- 11 rows, 85 census entries, from 20 sidecar(s) */
/* REFUSED, not carried: 0x48fe989eu disas_a64/SYS@1101010100.11................... REG_FCSR (mrs x10) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x48fe989eu disas_a64/SYS@1101010100.11................... REG_SYS (mrs x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0xf38c59fcu disas_a64/ST_mult@0.001100.00.....0000............ REG_VEC5 (st4 x4) --
 * this decode id carries another FIXED row from the SAME
 * NUMBERED BANK, so the pair claims one rule reads two
 * different registers of that bank on every instance --
 * an ENCODED OPERAND frozen at whatever the deriving
 * corpus ran.  Measured fabricating on live instructions
 * (riscv64 RVV, x86 scalar FMA, aarch64 st4).  The
 * register the encoding names is published by the
 * emulator's own statement; this row published the
 * deriving corpus's instead.  An adjudicated correction
 * under R15/R16, not a loss under R12.1. */
/* REFUSED, not carried: 0xf38c59fcu disas_a64/ST_mult@0.001100.00.....0000............ REG_VEC6 (st4 x4) --
 * this decode id carries another FIXED row from the SAME
 * NUMBERED BANK, so the pair claims one rule reads two
 * different registers of that bank on every instance --
 * an ENCODED OPERAND frozen at whatever the deriving
 * corpus ran.  Measured fabricating on live instructions
 * (riscv64 RVV, x86 scalar FMA, aarch64 st4).  The
 * register the encoding names is published by the
 * emulator's own statement; this row published the
 * deriving corpus's instead.  An adjudicated correction
 * under R15/R16, not a loss under R12.1. */
/* REFUSED, not carried: 0xf38c59fcu disas_a64/ST_mult@0.001100.00.....0000............ REG_VEC7 (st4 x4) --
 * this decode id carries another FIXED row from the SAME
 * NUMBERED BANK, so the pair claims one rule reads two
 * different registers of that bank on every instance --
 * an ENCODED OPERAND frozen at whatever the deriving
 * corpus ran.  Measured fabricating on live instructions
 * (riscv64 RVV, x86 scalar FMA, aarch64 st4).  The
 * register the encoding names is published by the
 * emulator's own statement; this row published the
 * deriving corpus's instead.  An adjudicated correction
 * under R15/R16, not a loss under R12.1. */
/* REFUSED, not carried: 0xf38c59fcu disas_a64/ST_mult@0.001100.00.....0000............ REG_VEC8 (st4 x4) --
 * this decode id carries another FIXED row from the SAME
 * NUMBERED BANK, so the pair claims one rule reads two
 * different registers of that bank on every instance --
 * an ENCODED OPERAND frozen at whatever the deriving
 * corpus ran.  Measured fabricating on live instructions
 * (riscv64 RVV, x86 scalar FMA, aarch64 st4).  The
 * register the encoding names is published by the
 * emulator's own statement; this row published the
 * deriving corpus's instead.  An adjudicated correction
 * under R15/R16, not a loss under R12.1. */
static const SrcSurvivorRow g_src_survivors_aarch64[] = {
    { 0x1929eab9u, SRC_SURV_SELF , REG_NONE      , 0, "disas_a64/INS_general" },   /* mov x4 */
    { 0x30a7252au, SRC_SURV_FIXED, REG_FCSR      , 0, "disas_a64/FABS_s" },   /* fabs x33 */
    { 0x5c29c765u, SRC_SURV_FIXED, REG_SYSFPEN   , 0, "disas_a64/MSR_i_SVCR" },   /* smstop x1 */
    { 0x5c29c765u, SRC_SURV_SELF , REG_NONE      , 0, "disas_a64/MSR_i_SVCR" },   /* smstop x1 */
    { 0x63e69d96u, SRC_SURV_FIXED, REG_SP        , 0, "disas_a64/NOP@1111100110......................" },   /* prfm x4 */
    { 0x81b1e8f0u, SRC_SURV_FIXED, REG_GPR9      , 0, "disas_a64/LD_mult@0.001100.10.....0000............" },   /* ld4 x4 */
    { 0x81b1e8f0u, SRC_SURV_FIXED, REG_SYSFPEN   , 0, "disas_a64/LD_mult@0.001100.10.....0000............" },   /* ld4 x4 */
    { 0x8e2f807fu, SRC_SURV_FIXED, REG_SP        , 0, "disas_a64/NOP@11111000100.........00.........." },   /* prfum x4 */
    { 0xca9ff590u, SRC_SURV_FIXED, REG_FCSR      , 0, "disas_a64/FNEG_s" },   /* fneg x22 */
    { 0xf38c59fcu, SRC_SURV_FIXED, REG_GPR9      , 0, "disas_a64/ST_mult@0.001100.00.....0000............" },   /* st4 x4 */
    { 0xf38c59fcu, SRC_SURV_FIXED, REG_SYSFPEN   , 0, "disas_a64/ST_mult@0.001100.00.....0000............" },   /* st4 x4 */
};

/* riscv64 -- 25 rows, 262 census entries, from 18 sidecar(s) */
/* REFUSED, not carried: 0x24c5df69u decode_insn32/vmadc_vvm SELF@0 (vmadc.vv,vmadc.vvm x4) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x24c5df69u decode_insn32/vmadc_vvm SELF@1 (vmadc.vv,vmadc.vvm x4) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x2726f523u decode_insn32/csrrs REG_FCSR (frcsr x3) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x2b26fb6fu decode_insn32/csrrw SELF@1 (fscsr x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0xa0d6c6a1u decode_insn32/vmsbc_vvm SELF@0 (vmsbc.vv,vmsbc.vvm x4) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0xa0d6c6a1u decode_insn32/vmsbc_vvm SELF@1 (vmsbc.vv,vmsbc.vvm x4) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
static const SrcSurvivorRow g_src_survivors_riscv64[] = {
    { 0x1d7ee76bu, SRC_SURV_FIXED, REG_ZERO      , 0, "decode_insn32/vsetvli" },   /* vsetvli x6 */
    { 0x6832c275u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vsub_vv" },   /* vsub.vv x2 */
    { 0x6832c275u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vsub_vv" },   /* vsub.vv x2 */
    { 0x7ba73b05u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vmv_v_v" },   /* vmv.v.v x64 */
    { 0x7ba73b05u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vmv_v_v" },   /* vmv.v.v x64 */
    { 0x887129a3u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vfmadd_vv" },   /* vfmadd.vv x2 */
    { 0x887129a3u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vfmadd_vv" },   /* vfmadd.vv x2 */
    { 0x9179a794u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vfmsub_vv" },   /* vfmsub.vv x2 */
    { 0x9179a794u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vfmsub_vv" },   /* vfmsub.vv x2 */
    { 0x9179a794u, SRC_SURV_SELF , REG_NONE      , 2, "decode_insn32/vfmsub_vv" },   /* vfmsub.vv x2 */
    { 0xd2488b0eu, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vadd_vv" },   /* vadd.vv x2 */
    { 0xd2488b0eu, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vadd_vv" },   /* vadd.vv x2 */
    { 0xd33e245cu, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vmerge_vxm" },   /* vmerge.vxm x2 */
    { 0xd33e245cu, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vmerge_vxm" },   /* vmerge.vxm x2 */
    { 0xd6082df1u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vmul_vv" },   /* vmul.vv x2 */
    { 0xd6082df1u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vmul_vv" },   /* vmul.vv x2 */
    { 0xd757c28eu, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vmerge_vvm" },   /* vmerge.vvm x2 */
    { 0xd757c28eu, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vmerge_vvm" },   /* vmerge.vvm x2 */
    { 0xecf2c479u, SRC_SURV_FIXED, REG_SYS       , 0, "decode_insn32/fence" },   /* fence x86 */
    { 0xf9fe03f8u, SRC_SURV_FIXED, REG_VEC0      , 0, "decode_insn32/vsbc_vvm" },   /* vsbc.vvm x2 */
    { 0xf9fe03f8u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vsbc_vvm" },   /* vsbc.vvm x2 */
    { 0xf9fe03f8u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vsbc_vvm" },   /* vsbc.vvm x2 */
    { 0xfc9b7984u, SRC_SURV_FIXED, REG_VEC0      , 0, "decode_insn32/vadc_vvm" },   /* vadc.vvm x2 */
    { 0xfc9b7984u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vadc_vvm" },   /* vadc.vvm x2 */
    { 0xfc9b7984u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vadc_vvm" },   /* vadc.vvm x2 */
};

/* mipsel -- 5 rows, 335 census entries, from 18 sidecar(s) */
static const SrcSurvivorRow g_src_survivors_mipsel[] = {
    { 0x20e7cdf6u, SRC_SURV_SELF , REG_NONE      , 0, "translate_mips/OPC_MTHC1" },   /* mthc1 x309 */
    { 0x3e9bb316u, SRC_SURV_SELF , REG_NONE      , 1, "translate_mips/OPC_MADD_D" },   /* madd.d x2 */
    { 0x740ff847u, SRC_SURV_SELF , REG_NONE      , 1, "translate_mips/OPC_MSUB_D" },   /* msub.d x2 */
    { 0xa65bcb79u, SRC_SURV_SELF , REG_NONE      , 1, "translate_mips/OPC_DIV_D" },   /* div.d x20 */
    { 0xf2e998eeu, SRC_SURV_SELF , REG_NONE      , 1, "translate_mips/OPC_CVT_S_W" },   /* cvt.s.w x2 */
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

/* 49 rows over the four ISAs. */

#endif /* CHAMPSIM_TRACER_SRC_SURVIVORS_H */
