#ifndef WPTRACE_MNEMONICS_MIPS_H
#define WPTRACE_MNEMONICS_MIPS_H

/*
 * ISA-specific classification tables for wptrace — mips.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <capstone/mips.h>

/* MIPS: 63/136 classified, 73 REG_NONE */
static const RegClassification mips_reg_class[MIPS_REG_ENDING] = {
    [MIPS_REG_AT] = { REG_GPR1 },  /* at */
    [MIPS_REG_V0] = { REG_GPR2 },  /* v0 */
    [MIPS_REG_V1] = { REG_GPR3 },  /* v1 */
    [MIPS_REG_A0] = { REG_GPR4 },  /* a0 */
    [MIPS_REG_A1] = { REG_GPR5 },  /* a1 */
    [MIPS_REG_A2] = { REG_GPR6 },  /* a2 */
    [MIPS_REG_A3] = { REG_GPR7 },  /* a3 */
    [MIPS_REG_T0] = { REG_GPR8 },  /* t0 */
    [MIPS_REG_T1] = { REG_GPR9 },  /* t1 */
    [MIPS_REG_T2] = { REG_GPR10 },  /* t2 */
    [MIPS_REG_T3] = { REG_GPR11 },  /* t3 */
    [MIPS_REG_T4] = { REG_GPR12 },  /* t4 */
    [MIPS_REG_T5] = { REG_GPR13 },  /* t5 */
    [MIPS_REG_T6] = { REG_GPR14 },  /* t6 */
    [MIPS_REG_T7] = { REG_GPR15 },  /* t7 */
    [MIPS_REG_S0] = { REG_GPR16 },  /* s0 */
    [MIPS_REG_S1] = { REG_GPR17 },  /* s1 */
    [MIPS_REG_S2] = { REG_GPR18 },  /* s2 */
    [MIPS_REG_S3] = { REG_GPR19 },  /* s3 */
    [MIPS_REG_S4] = { REG_GPR20 },  /* s4 */
    [MIPS_REG_S5] = { REG_GPR21 },  /* s5 */
    [MIPS_REG_S6] = { REG_GPR22 },  /* s6 */
    [MIPS_REG_S7] = { REG_GPR23 },  /* s7 */
    [MIPS_REG_T8] = { REG_GPR24 },  /* t8 */
    [MIPS_REG_T9] = { REG_GPR25 },  /* t9 */
    [MIPS_REG_K0] = { REG_GPR26 },  /* k0 */
    [MIPS_REG_K1] = { REG_GPR27 },  /* k1 */
    [MIPS_REG_GP] = { REG_GPR28 },  /* gp */
    [MIPS_REG_SP] = { REG_SP },  /* sp */
    [MIPS_REG_FP] = { REG_FP_REG },  /* fp */
    [MIPS_REG_RA] = { REG_LR },  /* ra */
    [MIPS_REG_F0] = { REG_FPR0 },  /* f0 */
    [MIPS_REG_F1] = { REG_FPR1 },  /* f1 */
    [MIPS_REG_F2] = { REG_FPR2 },  /* f2 */
    [MIPS_REG_F3] = { REG_FPR3 },  /* f3 */
    [MIPS_REG_F4] = { REG_FPR4 },  /* f4 */
    [MIPS_REG_F5] = { REG_FPR5 },  /* f5 */
    [MIPS_REG_F6] = { REG_FPR6 },  /* f6 */
    [MIPS_REG_F7] = { REG_FPR7 },  /* f7 */
    [MIPS_REG_F8] = { REG_FPR8 },  /* f8 */
    [MIPS_REG_F9] = { REG_FPR9 },  /* f9 */
    [MIPS_REG_F10] = { REG_FPR10 },  /* f10 */
    [MIPS_REG_F11] = { REG_FPR11 },  /* f11 */
    [MIPS_REG_F12] = { REG_FPR12 },  /* f12 */
    [MIPS_REG_F13] = { REG_FPR13 },  /* f13 */
    [MIPS_REG_F14] = { REG_FPR14 },  /* f14 */
    [MIPS_REG_F15] = { REG_FPR15 },  /* f15 */
    [MIPS_REG_F16] = { REG_FPR16 },  /* f16 */
    [MIPS_REG_F17] = { REG_FPR17 },  /* f17 */
    [MIPS_REG_F18] = { REG_FPR18 },  /* f18 */
    [MIPS_REG_F19] = { REG_FPR19 },  /* f19 */
    [MIPS_REG_F20] = { REG_FPR20 },  /* f20 */
    [MIPS_REG_F21] = { REG_FPR21 },  /* f21 */
    [MIPS_REG_F22] = { REG_FPR22 },  /* f22 */
    [MIPS_REG_F23] = { REG_FPR23 },  /* f23 */
    [MIPS_REG_F24] = { REG_FPR24 },  /* f24 */
    [MIPS_REG_F25] = { REG_FPR25 },  /* f25 */
    [MIPS_REG_F26] = { REG_FPR26 },  /* f26 */
    [MIPS_REG_F27] = { REG_FPR27 },  /* f27 */
    [MIPS_REG_F28] = { REG_FPR28 },  /* f28 */
    [MIPS_REG_F29] = { REG_FPR29 },  /* f29 */
    [MIPS_REG_F30] = { REG_FPR30 },  /* f30 */
    [MIPS_REG_F31] = { REG_FPR31 },  /* f31 */
};

/* MIPS: 103/626 classified, 523 unknown */
static const InsnClassification mips_insn_class[MIPS_INS_ENDING] = {
    [MIPS_INS_ADD]                  = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ADDU]                 = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ADDI]                 = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ADDIU]                = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_AND]                  = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ANDI]                 = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_BAL]                  = { GEN_OP_CALL,      BRANCH_DIRECT_CALL,   MF_NONE },
    [MIPS_INS_BEQ]                  = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BEQL]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEZAL]               = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEZL]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGTZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGTZL]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLEZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLEZL]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTZAL]               = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTZL]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BNE]                  = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BNEL]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BREAK]                = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_CLZ]                  = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_BEQZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_B]                    = { GEN_OP_BRANCH,    BRANCH_DIRECT_JUMP,   MF_NONE },
    [MIPS_INS_BNEZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_DIV]                  = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DIVU]                 = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_EXT]                  = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_INS]                  = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MUL]                  = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SUB]                  = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_J]                    = { GEN_OP_BRANCH,    BRANCH_DIRECT_JUMP,   MF_NONE },
    [MIPS_INS_JAL]                  = { GEN_OP_CALL,      BRANCH_DIRECT_CALL,   MF_NONE },
    [MIPS_INS_JALR]                 = { GEN_OP_CALL,      BRANCH_INDIRECT_CALL, MF_NONE },
    [MIPS_INS_JALX]                 = { GEN_OP_CALL,      BRANCH_DIRECT_CALL,   MF_NONE },
    [MIPS_INS_JR]                   = { GEN_OP_BRANCH,    BRANCH_INDIRECT_JUMP, MF_NONE },
    [MIPS_INS_LB]                   = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LBU]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LD]                   = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LDC1]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LH]                   = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LHU]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LL]                   = { GEN_OP_LOAD,      BRANCH_NONE,          MF_ATOMIC },
    [MIPS_INS_LLD]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_ATOMIC },
    [MIPS_INS_LUI]                  = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LW]                   = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWC1]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWL]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWR]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LI]                   = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LSA]                  = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MFC1]                 = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MFHC1]                = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MFHI]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MFLO]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MOVE]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MOVF]                 = { GEN_OP_CMOV,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MOVN]                 = { GEN_OP_CMOV,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MOVZ]                 = { GEN_OP_CMOV,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTC1]                 = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTHC1]                = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTHI]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTLO]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MULT]                 = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MULTU]                = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_NOR]                  = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_OR]                   = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ORI]                  = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_NEGU]                 = { GEN_OP_NEG,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_PREF]                 = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_RDHWR]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SB]                   = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SC]                   = { GEN_OP_STORE,     BRANCH_NONE,          MF_ATOMIC },
    [MIPS_INS_SCD]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_ATOMIC },
    [MIPS_INS_SD]                   = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SDC1]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SEB]                  = { GEN_OP_MOVSX,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SEH]                  = { GEN_OP_MOVSX,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SH]                   = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLL]                  = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLLV]                 = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLT]                  = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLTI]                 = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLTIU]                = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLTU]                 = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SRA]                  = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SRAV]                 = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SRL]                  = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SRLV]                 = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SUBU]                 = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SW]                   = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWC1]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWL]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWR]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SYNC]                 = { GEN_OP_FENCE,     BRANCH_NONE,          MF_ATOMIC },
    [MIPS_INS_SYSCALL]              = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TEQ]                  = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TGE]                  = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TLT]                  = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_VSHF]                 = { GEN_OP_VEC_SHUF,  BRANCH_NONE,          MF_NONE },
    [MIPS_INS_XOR]                  = { GEN_OP_XOR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_XORI]                 = { GEN_OP_XOR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_NOP]                  = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
};

#endif /* WPTRACE_MNEMONICS_MIPS_H */
