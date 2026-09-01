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
 * is /mnt/md0/QEMU/cst_runs/exec79/gensnap/snap, 176 sidecar(s):
 *   x86_64   54 sidecar(s), 24 row(s), 7 REFUSED (reason on each row below)
 *   aarch64  44 sidecar(s), 25 row(s), 3 REFUSED (reason on each row below)
 *   riscv64  39 sidecar(s), 47 row(s), 16 REFUSED (reason on each row below)
 *   mipsel   39 sidecar(s), 5 row(s), 2 REFUSED (reason on each row below)
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

/* x86_64 -- 24 rows, 4038 census entries, from 54 sidecar(s) */
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
/* REFUSED, not carried: 0x0000054bu NOP REG_SSP (rdsspq x19) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x00000569u VDIV REG_VEC1 (divsd x4) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x00000569u VDIV SELF@0 (divsd x4) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x00000632u IDIV SELF@0 (idivl x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x00000632u IDIV SELF@1 (idivl x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
static const SrcSurvivorRow g_src_survivors_x86_64[] = {
    { 0x000002e0u, SRC_SURV_FIXED, REG_VEC1      , 0, "VFMADD132Sx" },   /* vfmadd132sd x4 */
    { 0x000002e0u, SRC_SURV_FIXED, REG_VEC2      , 0, "VFMADD132Sx" },   /* vfmadd132sd x4 */
    { 0x000002e0u, SRC_SURV_SELF , REG_NONE      , 0, "VFMADD132Sx" },   /* vfmadd132sd x4 */
    { 0x000002e2u, SRC_SURV_FIXED, REG_VEC4      , 0, "VFMSUB132Sx" },   /* vfmsub132sd x4 */
    { 0x000002e2u, SRC_SURV_FIXED, REG_VEC5      , 0, "VFMSUB132Sx" },   /* vfmsub132sd x4 */
    { 0x000002e2u, SRC_SURV_SELF , REG_NONE      , 0, "VFMSUB132Sx" },   /* vfmsub132sd x4 */
    { 0x00000384u, SRC_SURV_SELF , REG_NONE      , 0, "PINSR" },   /* pinsrd x40 */
    { 0x000003fdu, SRC_SURV_SELF , REG_NONE      , 0, "VMOVLPx_ld" },   /* movlpd x35 */
    { 0x00000419u, SRC_SURV_SELF , REG_NONE      , 0, "VMOVHPx_ld" },   /* movhps x37 */
    { 0x0000041au, SRC_SURV_SELF , REG_NONE      , 0, "VMOVHPx_ld" },   /* movhpd x20 */
    { 0x000004c9u, SRC_SURV_FIXED, REG_SYSTIMER  , 0, "RDTSC" },   /* rdtsc x24 */
    { 0x00000507u, SRC_SURV_SELF , REG_NONE      , 0, "CPUID" },   /* cpuid x56 */
    { 0x00000507u, SRC_SURV_SELF , REG_NONE      , 2, "CPUID" },   /* cpuid x56 */
    { 0x00000535u, SRC_SURV_FIXED, REG_VEC1      , 0, "PMADDWD" },   /* pmaddwd x4 */
    { 0x00000535u, SRC_SURV_SELF , REG_NONE      , 0, "PMADDWD" },   /* pmaddwd x4 */
    { 0x000006dau, SRC_SURV_FIXED, REG_SEG5      , 0, "RET" },   /* retq x3422 */
    { 0x00000767u, SRC_SURV_SELF , REG_NONE      , 1, "LEAVE" },   /* leave x283 */
    { 0x36b0d666u, SRC_SURV_FIXED, REG_FPCW      , 0, "decode-new/x87@1101100111101010" },   /* fldl2e x4 */
    { 0xbbb3e65cu, SRC_SURV_FIXED, REG_FPCW      , 0, "decode-new/x87@1101100111101001" },   /* fldl2t x4 */
    { 0xdb9bac2bu, SRC_SURV_FIXED, REG_SSP       , 0, "decode-new/NOP@f3=1,modrm=11001..." },   /* rdsspq x3 */
    { 0xde1beaa4u, SRC_SURV_FIXED, REG_FPCW      , 0, "decode-new/x87@1101100111101100" },   /* fldlg2 x4 */
    { 0xdf1bec37u, SRC_SURV_FIXED, REG_FPCW      , 0, "decode-new/x87@1101100111101101" },   /* fldln2 x4 */
    { 0xe3014efcu, SRC_SURV_SELF , REG_NONE      , 0, "decode-new/VCVTSI2Sx@vex=1" },   /* vcvtsi2sdl x4 */
    { 0xecac981bu, SRC_SURV_SELF , REG_NONE      , 0, "decode-new/VMOVLPx@vex=0" },   /* movsd x10 */
};

/* aarch64 -- 25 rows, 170 census entries, from 44 sidecar(s) */
/* REFUSED, not carried: 0x48fe989eu disas_a64/SYS@1101010100.11................... REG_FCSR (mrs x10) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x48fe989eu disas_a64/SYS@1101010100.11................... REG_GPR19 (msr x1) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x48fe989eu disas_a64/SYS@1101010100.11................... REG_SYSID (mrs x3) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
static const SrcSurvivorRow g_src_survivors_aarch64[] = {
    { 0x085b7b49u, SRC_SURV_FIXED, REG_VEC4      , 0, "disas_a64/TBL_TBX" },   /* tbl x4 */
    { 0x10fdc617u, SRC_SURV_SELF , REG_NONE      , 1, "disas_a64/FMUL_v@0.1011100.1.....110111.........." },   /* fmul x10 */
    { 0x13e03a7eu, SRC_SURV_SELF , REG_NONE      , 1, "disas_a64/FSUB_v@0.0011101.1.....110101.........." },   /* fsub x10 */
    { 0x1929eab9u, SRC_SURV_SELF , REG_NONE      , 0, "disas_a64/INS_general" },   /* mov x10 */
    { 0x30a7252au, SRC_SURV_FIXED, REG_FCSR      , 0, "disas_a64/FABS_s" },   /* fabs x33 */
    { 0x583d7c95u, SRC_SURV_SELF , REG_NONE      , 1, "disas_a64/FDIV_v@0.1011100.1.....111111.........." },   /* fdiv x10 */
    { 0x5c29c765u, SRC_SURV_FIXED, REG_SYSFPEN   , 0, "disas_a64/MSR_i_SVCR" },   /* smstop x1 */
    { 0x5c29c765u, SRC_SURV_SELF , REG_NONE      , 0, "disas_a64/MSR_i_SVCR" },   /* smstop x1 */
    { 0x62e8a5aeu, SRC_SURV_FIXED, REG_PRED1     , 0, "disas_sve/LD_zpri@1010010....0....101............." },   /* ld1b x1 */
    { 0x63e69d96u, SRC_SURV_FIXED, REG_SP        , 0, "disas_a64/NOP@1111100110......................" },   /* prfm x10 */
    { 0x81b1e8f0u, SRC_SURV_FIXED, REG_GPR9      , 0, "disas_a64/LD_mult@0.001100.10.....0000............" },   /* ld4 x4 */
    { 0x81b1e8f0u, SRC_SURV_FIXED, REG_SYSFPEN   , 0, "disas_a64/LD_mult@0.001100.10.....0000............" },   /* ld4 x4 */
    { 0x8e2f807fu, SRC_SURV_FIXED, REG_SP        , 0, "disas_a64/NOP@11111000100.........00.........." },   /* prfum x10 */
    { 0xca9ff590u, SRC_SURV_FIXED, REG_FCSR      , 0, "disas_a64/FNEG_s" },   /* fneg x22 */
    { 0xe91326acu, SRC_SURV_SELF , REG_NONE      , 1, "disas_a64/FADD_v@0.0011100.1.....110101.........." },   /* fadd x10 */
    { 0xeba5bbf5u, SRC_SURV_FIXED, REG_PRED0     , 0, "disas_sve/ST_zpri@1110010....0....111............." },   /* st1b x1 */
    { 0xeba5bbf5u, SRC_SURV_FIXED, REG_PRED1     , 0, "disas_sve/ST_zpri@1110010....0....111............." },   /* st1b x2 */
    { 0xeba5bbf5u, SRC_SURV_FIXED, REG_VEC0      , 0, "disas_sve/ST_zpri@1110010....0....111............." },   /* st1b x2 */
    { 0xeba5bbf5u, SRC_SURV_FIXED, REG_VEC1      , 0, "disas_sve/ST_zpri@1110010....0....111............." },   /* st1b x1 */
    { 0xf38c59fcu, SRC_SURV_FIXED, REG_GPR9      , 0, "disas_a64/ST_mult@0.001100.00.....0000............" },   /* st4 x4 */
    { 0xf38c59fcu, SRC_SURV_FIXED, REG_SYSFPEN   , 0, "disas_a64/ST_mult@0.001100.00.....0000............" },   /* st4 x4 */
    { 0xf38c59fcu, SRC_SURV_FIXED, REG_VEC5      , 0, "disas_a64/ST_mult@0.001100.00.....0000............" },   /* st4 x4 */
    { 0xf38c59fcu, SRC_SURV_FIXED, REG_VEC6      , 0, "disas_a64/ST_mult@0.001100.00.....0000............" },   /* st4 x4 */
    { 0xf38c59fcu, SRC_SURV_FIXED, REG_VEC7      , 0, "disas_a64/ST_mult@0.001100.00.....0000............" },   /* st4 x4 */
    { 0xf38c59fcu, SRC_SURV_FIXED, REG_VEC8      , 0, "disas_a64/ST_mult@0.001100.00.....0000............" },   /* st4 x4 */
};

/* riscv64 -- 47 rows, 579 census entries, from 39 sidecar(s) */
/* REFUSED, not carried: 0x24c5df69u decode_insn32/vmadc_vvm REG_VEC0 (vmadc.vvm x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x24c5df69u decode_insn32/vmadc_vvm REG_VEC11 (vmadc.vvm x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x24c5df69u decode_insn32/vmadc_vvm REG_VEC12 (vmadc.vvm x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x24c5df69u decode_insn32/vmadc_vvm REG_VEC22 (vmadc.vv x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x24c5df69u decode_insn32/vmadc_vvm REG_VEC23 (vmadc.vv x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
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
/* REFUSED, not carried: 0x2726f523u decode_insn32/csrrs REG_FCSR (frcsr,frflags,frrm x5) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0x2b26fb6fu decode_insn32/csrrw SELF@1 (fscsr x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0xa0d6c6a1u decode_insn32/vmsbc_vvm REG_VEC0 (vmsbc.vvm x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0xa0d6c6a1u decode_insn32/vmsbc_vvm REG_VEC14 (vmsbc.vvm x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0xa0d6c6a1u decode_insn32/vmsbc_vvm REG_VEC15 (vmsbc.vvm x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0xa0d6c6a1u decode_insn32/vmsbc_vvm REG_VEC25 (vmsbc.vv x2) --
 * the census shows this decode id carrying more than one
 * instruction, so an id-keyed row would fire on the others
 * too.  It stays in the loss direction and blocks the flip
 * until the id is qualified. */
/* REFUSED, not carried: 0xa0d6c6a1u decode_insn32/vmsbc_vvm REG_VEC26 (vmsbc.vv x2) --
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
    { 0x51bfc656u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/fmsub_d" },   /* fmsub.d x2 */
    { 0x6832c275u, SRC_SURV_FIXED, REG_VEC4      , 0, "decode_insn32/vsub_vv" },   /* vsub.vv x5 */
    { 0x6832c275u, SRC_SURV_FIXED, REG_VEC5      , 0, "decode_insn32/vsub_vv" },   /* vsub.vv x5 */
    { 0x6832c275u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vsub_vv" },   /* vsub.vv x5 */
    { 0x6832c275u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vsub_vv" },   /* vsub.vv x5 */
    { 0x7ba73b05u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vmv_v_v" },   /* vmv.v.v x160 */
    { 0x7ba73b05u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vmv_v_v" },   /* vmv.v.v x160 */
    { 0x887129a3u, SRC_SURV_FIXED, REG_VEC10     , 0, "decode_insn32/vfmadd_vv" },   /* vfmadd.vv x2 */
    { 0x887129a3u, SRC_SURV_FIXED, REG_VEC11     , 0, "decode_insn32/vfmadd_vv" },   /* vfmadd.vv x2 */
    { 0x887129a3u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vfmadd_vv" },   /* vfmadd.vv x2 */
    { 0x887129a3u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vfmadd_vv" },   /* vfmadd.vv x2 */
    { 0x9179a794u, SRC_SURV_FIXED, REG_VEC13     , 0, "decode_insn32/vfmsub_vv" },   /* vfmsub.vv x2 */
    { 0x9179a794u, SRC_SURV_FIXED, REG_VEC14     , 0, "decode_insn32/vfmsub_vv" },   /* vfmsub.vv x2 */
    { 0x9179a794u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vfmsub_vv" },   /* vfmsub.vv x2 */
    { 0x9179a794u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vfmsub_vv" },   /* vfmsub.vv x2 */
    { 0x9179a794u, SRC_SURV_SELF , REG_NONE      , 2, "decode_insn32/vfmsub_vv" },   /* vfmsub.vv x2 */
    { 0xcfc5a63eu, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/fdiv_d" },   /* fdiv.d x2 */
    { 0xd2488b0eu, SRC_SURV_FIXED, REG_VEC1      , 0, "decode_insn32/vadd_vv" },   /* vadd.vv x5 */
    { 0xd2488b0eu, SRC_SURV_FIXED, REG_VEC2      , 0, "decode_insn32/vadd_vv" },   /* vadd.vv x5 */
    { 0xd2488b0eu, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vadd_vv" },   /* vadd.vv x5 */
    { 0xd2488b0eu, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vadd_vv" },   /* vadd.vv x5 */
    { 0xd33e245cu, SRC_SURV_FIXED, REG_VEC0      , 0, "decode_insn32/vmerge_vxm" },   /* vmerge.vxm x2 */
    { 0xd33e245cu, SRC_SURV_FIXED, REG_VEC20     , 0, "decode_insn32/vmerge_vxm" },   /* vmerge.vxm x2 */
    { 0xd33e245cu, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vmerge_vxm" },   /* vmerge.vxm x2 */
    { 0xd33e245cu, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vmerge_vxm" },   /* vmerge.vxm x2 */
    { 0xd6082df1u, SRC_SURV_FIXED, REG_VEC7      , 0, "decode_insn32/vmul_vv" },   /* vmul.vv x5 */
    { 0xd6082df1u, SRC_SURV_FIXED, REG_VEC8      , 0, "decode_insn32/vmul_vv" },   /* vmul.vv x5 */
    { 0xd6082df1u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vmul_vv" },   /* vmul.vv x5 */
    { 0xd6082df1u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vmul_vv" },   /* vmul.vv x5 */
    { 0xd757c28eu, SRC_SURV_FIXED, REG_VEC0      , 0, "decode_insn32/vmerge_vvm" },   /* vmerge.vvm x2 */
    { 0xd757c28eu, SRC_SURV_FIXED, REG_VEC17     , 0, "decode_insn32/vmerge_vvm" },   /* vmerge.vvm x2 */
    { 0xd757c28eu, SRC_SURV_FIXED, REG_VEC18     , 0, "decode_insn32/vmerge_vvm" },   /* vmerge.vvm x2 */
    { 0xd757c28eu, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vmerge_vvm" },   /* vmerge.vvm x2 */
    { 0xd757c28eu, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vmerge_vvm" },   /* vmerge.vvm x2 */
    { 0xde4e315bu, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/fsub_d" },   /* fsub.d x2 */
    { 0xecf2c479u, SRC_SURV_FIXED, REG_SYS       , 0, "decode_insn32/fence" },   /* fence x131 */
    { 0xf9fe03f8u, SRC_SURV_FIXED, REG_VEC0      , 0, "decode_insn32/vsbc_vvm" },   /* vsbc.vvm x2 */
    { 0xf9fe03f8u, SRC_SURV_FIXED, REG_VEC8      , 0, "decode_insn32/vsbc_vvm" },   /* vsbc.vvm x2 */
    { 0xf9fe03f8u, SRC_SURV_FIXED, REG_VEC9      , 0, "decode_insn32/vsbc_vvm" },   /* vsbc.vvm x2 */
    { 0xf9fe03f8u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vsbc_vvm" },   /* vsbc.vvm x2 */
    { 0xf9fe03f8u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vsbc_vvm" },   /* vsbc.vvm x2 */
    { 0xfc9b7984u, SRC_SURV_FIXED, REG_VEC0      , 0, "decode_insn32/vadc_vvm" },   /* vadc.vvm x2 */
    { 0xfc9b7984u, SRC_SURV_FIXED, REG_VEC5      , 0, "decode_insn32/vadc_vvm" },   /* vadc.vvm x2 */
    { 0xfc9b7984u, SRC_SURV_FIXED, REG_VEC6      , 0, "decode_insn32/vadc_vvm" },   /* vadc.vvm x2 */
    { 0xfc9b7984u, SRC_SURV_SELF , REG_NONE      , 0, "decode_insn32/vadc_vvm" },   /* vadc.vvm x2 */
    { 0xfc9b7984u, SRC_SURV_SELF , REG_NONE      , 1, "decode_insn32/vadc_vvm" },   /* vadc.vvm x2 */
};

/* mipsel -- 5 rows, 310 census entries, from 39 sidecar(s) */
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
    { 0x20e7cdf6u, SRC_SURV_SELF , REG_NONE      , 0, "translate_mips/OPC_MTHC1" },   /* mthc1 x302 */
    { 0x3e9bb316u, SRC_SURV_SELF , REG_NONE      , 1, "translate_mips/OPC_MADD_D" },   /* madd.d x2 */
    { 0x740ff847u, SRC_SURV_SELF , REG_NONE      , 1, "translate_mips/OPC_MSUB_D" },   /* msub.d x2 */
    { 0xa65bcb79u, SRC_SURV_SELF , REG_NONE      , 1, "translate_mips/OPC_DIV_D" },   /* div.d x2 */
    { 0xdffae667u, SRC_SURV_SELF , REG_NONE      , 1, "translate_mips/OPC_CMP_EQ_D" },   /* c.eq.d x2 */
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

/* 101 rows over the four ISAs. */

#endif /* CHAMPSIM_TRACER_SRC_SURVIVORS_H */
