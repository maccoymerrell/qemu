/*
 * SOURCE SURVIVORS, per decode identity -- GENERATED, DO NOT HAND-EDIT.
 *
 * Re-emit with tools/gen_src_survivors.py; see that file for what a row
 * means and where the measurement comes from.  Every row here is a
 * register the tracer's per-ISA decode publishes as a source that QEMU's
 * ordered read list does not state -- the population R12.1 forbids
 * dropping when the source list stops being the operand walk's.
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

/* x86_64 -- 7 rows, 584 census entries */
static const SrcSurvivorRow g_src_survivors_x86_64[] = {
    { 0x000003cdu, SRC_SURV_SELF , REG_NONE      , "VMOVLPx" },   /* movsd x2 */
    { 0x000003fdu, SRC_SURV_SELF , REG_NONE      , "VMOVLPx_ld" },   /* movlpd x7 */
    { 0x00000419u, SRC_SURV_SELF , REG_NONE      , "VMOVHPx_ld" },   /* movhps x4 */
    { 0x0000041au, SRC_SURV_SELF , REG_NONE      , "VMOVHPx_ld" },   /* movhpd x4 */
    { 0x000006dau, SRC_SURV_FIXED, REG_SEG5      , "RET" },   /* retq x526 */
    { 0x00000767u, SRC_SURV_SELF , REG_NONE      , "LEAVE" },   /* leave x39 */
    { 0x00000776u, SRC_SURV_FIXED, REG_FPR0      , "x87" },   /* fstpt x2 */
};

/* aarch64 -- 35 rows, 184 census entries */
static const SrcSurvivorRow g_src_survivors_aarch64[] = {
    { 0x07db0dd8u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/LD_mult@0.001100.10.....1010............" },   /* ld1 x2 */
    { 0x1b55859du, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/LDR_v_i@00111100110.........11.........." },   /* ldr x6 */
    { 0x1babbcc3u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/ABS_v" },   /* abs x2 */
    { 0x1bb429dau, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/LDR_v_i@0011110111......................" },   /* ldr x22 */
    { 0x22418e9fu, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/SHRN_v@0.00111100001...100001.........." },   /* shrn x9 */
    { 0x247a246bu, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/LDP_v@1010110101......................" },   /* ldp x20 */
    { 0x30a7252au, SRC_SURV_FIXED, REG_FCSR      , "disas_a64/FABS_s" },   /* fabs x1 */
    { 0x30a7252au, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/FABS_s" },   /* fabs x1 */
    { 0x41dbc9c5u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/SABD_v" },   /* sabd x2 */
    { 0x4fbbcf8bu, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/LDR_v_i@..11110101......................" },   /* ldr x10 */
    { 0x509c5f9eu, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/CMHS_v" },   /* cmhs x5 */
    { 0x515000c3u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/LDR_v_i@00111100110.........00.........." },   /* ldur x1 */
    { 0x58ec15fdu, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/PMUL_v" },   /* pmul x2 */
    { 0x601d078cu, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/ZIP1" },   /* zip1 x2 */
    { 0x605df073u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/MLA_v" },   /* mla x2 */
    { 0x6129f221u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/LD_mult@0.001100.10.....0010............" },   /* ld1 x2 */
    { 0x64cb0abdu, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/MLS_v" },   /* mls x2 */
    { 0x6c41b0f9u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/CMEQ_v" },   /* cmeq x12 */
    { 0x6c7a295du, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/Vimm" },   /* bic,movi,mvni x10 */
    { 0x757f650du, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/EXT_q" },   /* ext x3 */
    { 0x78d05764u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/FMOV_s" },   /* fmov x2 */
    { 0x7b4cfd32u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/LD_mult@0.001100.10.....0110............" },   /* ld1 x2 */
    { 0x88a5ca54u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/BIT_v" },   /* bit x7 */
    { 0x9271162du, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/LD_mult@0.001100.10.....0111............" },   /* ld1 x7 */
    { 0x93ea4495u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/TRN1" },   /* trn1 x2 */
    { 0xa895fe02u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/ADDP_v" },   /* addp x3 */
    { 0xb5dd7901u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/STP_v@1010110010......................" },   /* stp x1 */
    { 0xbb863ba4u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/DUP_general" },   /* dup x8 */
    { 0xc43e92d6u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/NOT_v" },   /* mvn x2 */
    { 0xc557a631u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/EOR_v" },   /* eor x8 */
    { 0xc7124336u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/BSL_v" },   /* bsl x2 */
    { 0xc8963eaau, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/UMAXP_v" },   /* umaxp x17 */
    { 0xcc384ebeu, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/UZP1" },   /* uzp1 x2 */
    { 0xd192549eu, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/ORR_v" },   /* mov x3 */
    { 0xf8b0ed76u, SRC_SURV_FIXED, REG_SYSFPEN   , "disas_a64/STP_v@1010110110......................" },   /* stp x2 */
};

/* riscv64 -- 0 rows, 0 census entries */
/* No array: every published source on this ISA is justified by
 * QEMU's read list, so the flip has nothing to carry.  An EMPTY
 * table is a RESULT here and the descriptor below says so with a
 * null pointer rather than a zero-length array. */

/* mipsel -- 1 row, 2 census entries */
static const SrcSurvivorRow g_src_survivors_mipsel[] = {
    { 0x20e7cdf6u, SRC_SURV_SELF , REG_NONE      , "translate_mips/OPC_MTHC1" },   /* mthc1 x2 */
};

/* Indexed by TraceISA.  A null row pointer is "this ISA has no
 * survivors", which is a measured answer and not a missing table. */
static const SrcSurvivorTable g_src_survivor_tables[] = {
    [TRACE_ISA_UNKNOWN] = { NULL, 0 },
    [TRACE_ISA_X86    ] = { g_src_survivors_x86_64,
                            G_N_ELEMENTS(g_src_survivors_x86_64) },
    [TRACE_ISA_AARCH64] = { g_src_survivors_aarch64,
                            G_N_ELEMENTS(g_src_survivors_aarch64) },
    [TRACE_ISA_RISCV  ] = { NULL, 0 },
    [TRACE_ISA_MIPS   ] = { g_src_survivors_mipsel,
                            G_N_ELEMENTS(g_src_survivors_mipsel) },
};

/* 43 rows over the four ISAs. */

#endif /* CHAMPSIM_TRACER_SRC_SURVIVORS_H */
