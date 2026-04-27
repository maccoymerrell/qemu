#ifndef CHAMPSIM_TRACER_MNEMONICS_MIPS_H
#define CHAMPSIM_TRACER_MNEMONICS_MIPS_H

/*
 * ISA-specific classification tables for champsim_tracer — mips.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <capstone/capstone.h>
#include <capstone/mips.h>
#include "elf.h"
#include <qemu-plugin.h>

#include "champsim_tracer_elf_attrs.h"

/*
 * Pick the Capstone MIPS arch level from EF_MIPS_ARCH bits.  If the ELF
 * cannot be loaded (e.g. statically-linked test runner that hides the
 * guest binary path), fall back to MIPS32R2 — a strict superset of
 * MIPS32R1 and the GNU toolchain default for mips/mipsel.
 *
 * Note: Capstone 6 modes are NOT strict supersets of each other (e.g.
 * MIPS32R2 does not include all MIPS32R6-only encodings), so we honour
 * the binary's declared level rather than OR'ing everything together.
 */
static unsigned int cs_mips_mode_from_eflags(uint32_t eflags, bool is64)
{
    unsigned int mode;

    switch (eflags & EF_MIPS_ARCH) {
    case EF_MIPS_ARCH_64R6:
    case EF_MIPS_ARCH_32R6:
        mode = CS_MODE_MIPS32R6;
        break;
    case EF_MIPS_ARCH_64R2:
    case EF_MIPS_ARCH_32R2:
        mode = CS_MODE_MIPS32R2;
        break;
    case EF_MIPS_ARCH_64:
        mode = CS_MODE_MIPS64;
        break;
    case EF_MIPS_ARCH_32:
        mode = CS_MODE_MIPS32;
        break;
    default:
        /* Pre-R2 / unknown: pick the widest level that still decodes
         * the older binary cleanly. */
        mode = is64 ? CS_MODE_MIPS64 : CS_MODE_MIPS32R2;
        break;
    }

    if ((eflags & EF_MIPS_ARCH_ASE) == EF_MIPS_ARCH_ASE_MICROMIPS) {
        mode |= CS_MODE_MICRO;
    }
    return mode;
}

static unsigned int cap_mode_mips(const char *target_name)
{
    /*
     * Resolve arch level from the guest binary's e_flags.  This avoids
     * the cs6 pitfall where modes are not strict supersets — using
     * e.g. MIPS32R2 against an R6-only binary mis-decodes the new R6
     * branches, and using R6 against an R1/R2 binary mis-decodes the
     * branch-likely instructions removed in R6.
     */
    unsigned int mode;
    bool is64 = (g_str_has_prefix(target_name, "mips64")
              || g_str_has_prefix(target_name, "mipsn32"));

    const char *bin = qemu_plugin_path_to_binary();
    CsElfInfo info;
    if (cs_elf_load(bin, &info)) {
        mode = cs_mips_mode_from_eflags(info.e_flags, info.is64 || is64);
        cs_elf_unload(&info);
    } else {
        /* No ELF available: MIPS32R2 covers R1+R2 binaries. */
        mode = is64 ? CS_MODE_MIPS64 : CS_MODE_MIPS32R2;
    }

    mode |= g_str_has_suffix(target_name, "el")
          ? CS_MODE_LITTLE_ENDIAN
          : CS_MODE_BIG_ENDIAN;
    return mode;
}

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

/* MIPS: 626/626 classified (all instructions) */
static const InsnClassification mips_insn_class[MIPS_INS_ENDING] = {
    /* Integer ALU */
    [MIPS_INS_ADD]                  = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ADDU]                 = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ADDI]                 = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ADDIU]                = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SUB]                  = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SUBU]                 = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MUL]                  = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MULT]                 = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MULTU]                = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DIV]                  = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DIVU]                 = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MOD]                  = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MODU]                 = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MUH]                  = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MUHU]                 = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MULU]                 = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MADD]                 = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MADDU]                = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MSUB]                 = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MSUBU]                = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_AND]                  = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ANDI]                 = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_OR]                   = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ORI]                  = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_NOR]                  = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_XOR]                  = { GEN_OP_XOR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_XORI]                 = { GEN_OP_XOR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_NOT]                  = { GEN_OP_NOT,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLL]                  = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLLV]                 = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SRL]                  = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SRLV]                 = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SRA]                  = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SRAV]                 = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ROTR]                 = { GEN_OP_ROR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ROTRV]                = { GEN_OP_ROR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLT]                  = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLTI]                 = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLTIU]                = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLTU]                 = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_CMP]                  = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_CMPI]                 = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_CLZ]                  = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_CLO]                  = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_NEG]                  = { GEN_OP_NEG,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ABS]                  = { GEN_OP_NEG,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_EXT]                  = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_INS]                  = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_WSBH]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_BITSWAP]              = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_BITREV]               = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ALIGN]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SELEQZ]               = { GEN_OP_CMOV,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SELNEZ]               = { GEN_OP_CMOV,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SEQ]                  = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SEQI]                 = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SNE]                  = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SNEI]                 = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_POP]                  = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DPOP]                 = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    /* Move */
    [MIPS_INS_LUI]                  = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LI]                   = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MOVE]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MOVF]                 = { GEN_OP_CMOV,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MOVN]                 = { GEN_OP_CMOV,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MOVZ]                 = { GEN_OP_CMOV,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MOVT]                 = { GEN_OP_CMOV,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MOVEP]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MFHI]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MFLO]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTHI]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTLO]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_RDHWR]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MFC0]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTC0]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MFC1]                 = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTC1]                 = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MFHC1]                = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTHC1]                = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MFC2]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTC2]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMFC0]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMTC0]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMFC1]                = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMTC1]                = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMFC2]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMTC2]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_CFC1]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_CTC1]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SEB]                  = { GEN_OP_MOVSX,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SEH]                  = { GEN_OP_MOVSX,     BRANCH_NONE,          MF_NONE },
    /* Loads */
    [MIPS_INS_LB]                   = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LBU]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LH]                   = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LHU]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LW]                   = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWU]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWL]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWR]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LD]                   = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LDL]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LDR]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LDC1]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWC1]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LDC2]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LDC3]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWC2]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWC3]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LL]                   = { GEN_OP_LOAD,      BRANCH_NONE,          MF_ATOMIC },
    [MIPS_INS_LLD]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_ATOMIC },
    [MIPS_INS_LDXC1]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWXC1]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LUXC1]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LDPC]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWPC]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWUPC]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LBU16]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LHU16]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LW16]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LBUX]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LHX]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWX]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWXS]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LI16]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWM16]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWM32]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LWP]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    /* Stores */
    [MIPS_INS_SB]                   = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SH]                   = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SW]                   = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SD]                   = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWL]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWR]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SDL]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SDR]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SDC1]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWC1]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SDC2]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SDC3]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWC2]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWC3]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SC]                   = { GEN_OP_STORE,     BRANCH_NONE,          MF_ATOMIC },
    [MIPS_INS_SCD]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_ATOMIC },
    [MIPS_INS_SDXC1]                = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWXC1]                = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SUXC1]                = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SB16]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SH16]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SW16]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWM16]                = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWM32]                = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SWP]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    /* Branches */
    [MIPS_INS_B]                    = { GEN_OP_BRANCH,    BRANCH_DIRECT_JUMP,   MF_NONE },
    [MIPS_INS_B16]                  = { GEN_OP_BRANCH,    BRANCH_DIRECT_JUMP,   MF_NONE },
    [MIPS_INS_BAL]                  = { GEN_OP_CALL,      BRANCH_DIRECT_CALL,   MF_NONE },
    [MIPS_INS_BALC]                 = { GEN_OP_CALL,      BRANCH_DIRECT_CALL,   MF_NONE },
    [MIPS_INS_BC]                   = { GEN_OP_BRANCH,    BRANCH_DIRECT_JUMP,   MF_NONE },
    [MIPS_INS_BEQ]                  = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BEQL]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BEQZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BEQZ16]               = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BEQZALC]              = { GEN_OP_CALL,      BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BEQZC]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BEQC]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEZAL]               = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEZALC]              = { GEN_OP_CALL,      BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEZALL]              = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEZALS]              = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEZC]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEZL]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGTZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGTZALC]              = { GEN_OP_CALL,      BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGTZC]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGTZL]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEC]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BGEUC]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLEZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLEZALC]              = { GEN_OP_CALL,      BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLEZC]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLEZL]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTZAL]               = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTZALC]              = { GEN_OP_CALL,      BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTZALL]              = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTZALS]              = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTZC]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTZL]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTC]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BLTUC]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BNE]                  = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BNEL]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BNEZ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BNEZ16]               = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BNEZALC]              = { GEN_OP_CALL,      BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BNEZC]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BNEC]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BNVC]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BOVC]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BBIT0]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BBIT032]              = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BBIT1]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BBIT132]              = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BTEQZ]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BTNEZ]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BPOSGE32]             = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    /* FP conditional branches */
    [MIPS_INS_BC1EQZ]               = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BC1F]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BC1FL]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BC1NEZ]               = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BC1T]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BC1TL]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BC2EQZ]               = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [MIPS_INS_BC2NEZ]               = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    /* Jumps */
    [MIPS_INS_J]                    = { GEN_OP_BRANCH,    BRANCH_DIRECT_JUMP,   MF_NONE },
    [MIPS_INS_JAL]                  = { GEN_OP_CALL,      BRANCH_DIRECT_CALL,   MF_NONE },
    [MIPS_INS_JALR]                 = { GEN_OP_CALL,      BRANCH_INDIRECT_CALL, MF_NONE },
    [MIPS_INS_JALR_HB]              = { GEN_OP_CALL,      BRANCH_INDIRECT_CALL, MF_NONE },
    [MIPS_INS_JALRC]                = { GEN_OP_CALL,      BRANCH_INDIRECT_CALL, MF_NONE },
    [MIPS_INS_JALRS]                = { GEN_OP_CALL,      BRANCH_INDIRECT_CALL, MF_NONE },
    [MIPS_INS_JALRS16]              = { GEN_OP_CALL,      BRANCH_INDIRECT_CALL, MF_NONE },
    [MIPS_INS_JALS]                 = { GEN_OP_CALL,      BRANCH_DIRECT_CALL,   MF_NONE },
    [MIPS_INS_JALX]                 = { GEN_OP_CALL,      BRANCH_DIRECT_CALL,   MF_NONE },
    [MIPS_INS_JIALC]                = { GEN_OP_CALL,      BRANCH_INDIRECT_CALL, MF_NONE },
    [MIPS_INS_JIC]                  = { GEN_OP_BRANCH,    BRANCH_INDIRECT_JUMP, MF_NONE },
    [MIPS_INS_JR]                   = { GEN_OP_BRANCH,    BRANCH_INDIRECT_JUMP, MF_NONE },
    [MIPS_INS_JR16]                 = { GEN_OP_BRANCH,    BRANCH_INDIRECT_JUMP, MF_NONE },
    [MIPS_INS_JR_HB]                = { GEN_OP_BRANCH,    BRANCH_INDIRECT_JUMP, MF_NONE },
    [MIPS_INS_JRC]                  = { GEN_OP_BRANCH,    BRANCH_INDIRECT_JUMP, MF_NONE },
    [MIPS_INS_JRADDIUSP]            = { GEN_OP_BRANCH,    BRANCH_INDIRECT_JUMP, MF_NONE },
    /* FP scalar */
    /* FP compare */
    /* MIPS64 integer */
    [MIPS_INS_DADD]                 = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DADDI]                = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DADDIU]               = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DADDU]                = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSUB]                 = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSUBU]                = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMUL]                 = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMULT]                = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMULTU]               = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMULU]                = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMUH]                 = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMUHU]                = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DDIV]                 = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DDIVU]                = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMOD]                 = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DMODU]                = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSLL]                 = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSLL32]               = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSLLV]                = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSRL]                 = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSRL32]               = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSRLV]                = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSRA]                 = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSRA32]               = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSRAV]                = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DROTR]                = { GEN_OP_ROR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DROTR32]              = { GEN_OP_ROR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DROTRV]               = { GEN_OP_ROR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DEXT]                 = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DEXTM]                = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DEXTU]                = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DINS]                 = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DINSM]                = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DINSU]                = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSBH]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DSHD]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DBITSWAP]             = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DCLO]                 = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DCLZ]                 = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DLSA]                 = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_LSA]                  = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DALIGN]               = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DAHI]                 = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DATI]                 = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DAUI]                 = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_AUI]                  = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_CINS]                 = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_CINS32]               = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_EXTS]                 = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_EXTS32]               = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_BADDU]                = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    /* System / sync / trap */
    [MIPS_INS_SYNC]                 = { GEN_OP_FENCE,     BRANCH_NONE,          MF_ATOMIC },
    [MIPS_INS_SYNCI]                = { GEN_OP_FENCE,     BRANCH_NONE,          MF_ATOMIC },
    [MIPS_INS_SYSCALL]              = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_BREAK]                = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_BREAK16]              = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TEQ]                  = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TEQI]                 = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TGE]                  = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TGEI]                 = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TGEIU]                = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TGEU]                 = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TLT]                  = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TLTI]                 = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TLTIU]                = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TLTU]                 = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TNE]                  = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_TNEI]                 = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_SDBBP]                = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_SDBBP16]              = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [MIPS_INS_ERET]                 = { GEN_OP_RET,       BRANCH_RETURN,        MF_NONE },
    [MIPS_INS_DERET]                = { GEN_OP_RET,       BRANCH_RETURN,        MF_NONE },
    [MIPS_INS_WAIT]                 = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_PAUSE]                = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_EHB]                  = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SSNOP]                = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_NOP]                  = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_PREF]                 = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_CACHE]                = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_EI]                   = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_DI]                   = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_TLBP]                 = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_TLBR]                 = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_TLBWI]                = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_TLBWR]                = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    /* microMIPS 16-bit */
    [MIPS_INS_ADDU16]               = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SUBU16]               = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_AND16]                = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ANDI16]               = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_OR16]                 = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_XOR16]                = { GEN_OP_XOR,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_NOT16]                = { GEN_OP_NOT,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SLL16]                = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SRL16]                = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    /* PC-relative loads */
    [MIPS_INS_ADDIUPC]              = { GEN_OP_LEA,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ALUIPC]               = { GEN_OP_LEA,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_AUIPC]                = { GEN_OP_LEA,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ADDIUR1SP]            = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ADDIUR2]              = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ADDIUS5]              = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ADDIUSP]              = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    /* MSA (SIMD) integer */
    [MIPS_INS_DIV_S]                = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MAX_S]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MIN_S]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,          MF_NONE },
    [MIPS_INS_CFCMSA]               = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_CTCMSA]               = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    /* DSP */
    [MIPS_INS_ADDSC]                = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_ADDWC]                = { GEN_OP_INT_ADC,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MUL_S]                = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_APPEND]               = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_BALIGN]               = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_PREPEND]              = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MODSUB]               = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_INSV]                 = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [MIPS_INS_RDDSP]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_WRDSP]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SHILO]                = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_SHILOV]               = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_EXTP]                 = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_EXTPDP]               = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_EXTPDPV]              = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_EXTPV]                = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTHLIP]               = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    /* Octeon */
    [MIPS_INS_V3MULU]               = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_VMM0]                 = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_VMULU]                = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTM0]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTM1]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTM2]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTP0]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTP1]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [MIPS_INS_MTP2]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },

    /* ---- Capstone 6 scalar FP / FP-mem (auto-generated) ---- */
    /* Scalar/packed FP add/sub */
    [MIPS_INS_ADD_D]                  = { GEN_OP_FP_ADD, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_ADD_PS]                 = { GEN_OP_FP_ADD, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_ADD_S]                  = { GEN_OP_FP_ADD, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FADD_D]                 = { GEN_OP_FP_ADD, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FADD_W]                 = { GEN_OP_FP_ADD, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FSUB_D]                 = { GEN_OP_FP_SUB, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FSUB_W]                 = { GEN_OP_FP_SUB, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_SUB_D]                  = { GEN_OP_FP_SUB, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_SUB_PS]                 = { GEN_OP_FP_SUB, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_SUB_S]                  = { GEN_OP_FP_SUB, BRANCH_NONE,           MF_NONE },
    /* Scalar/packed FP mul/div/madd */
    [MIPS_INS_DIV_D]                  = { GEN_OP_FP_DIV, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FDIV_D]                 = { GEN_OP_FP_DIV, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FDIV_W]                 = { GEN_OP_FP_DIV, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FMADD_D]                = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FMADD_W]                = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FMSUB_D]                = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FMSUB_W]                = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FMUL_D]                 = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FMUL_W]                 = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MADD_D]                 = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MADD_S]                 = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MSUB_D]                 = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MSUB_S]                 = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MUL_D]                  = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MUL_PS]                 = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_NMADD_D]                = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_NMADD_S]                = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_NMSUB_D]                = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_NMSUB_S]                = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    /* FP sqrt/rsqrt/recip */
    [MIPS_INS_FRSQRT_D]               = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FRSQRT_W]               = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FSQRT_D]                = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FSQRT_W]                = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_RECIP_D]                = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_RECIP_S]                = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_RSQRT_D]                = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_RSQRT_S]                = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_SQRT_D]                 = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_SQRT_S]                 = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    /* FP move/neg/abs/sel/cfc1/ctc1 */
    [MIPS_INS_ABS_D]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_ABS_S]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MOV_D]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MOV_S]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_NEG_D]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_NEG_S]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_SEL_D]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_SEL_S]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    /* FP conversions (cvt/round/trunc/ceil/floor/ffint/frint) */
    [MIPS_INS_CEIL_L_D]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CEIL_L_S]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CEIL_W_D]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CEIL_W_S]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_D_L]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_D_S]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_D_W]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_L_D]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_L_S]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_PS_PW]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_PS_S]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_PW_PS]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_S_D]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_S_L]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_S_PL]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_S_PU]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_S_W]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_W_D]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CVT_W_S]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FFINT_S_D]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FFINT_S_W]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FFINT_U_D]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FFINT_U_W]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FLOOR_L_D]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FLOOR_L_S]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FLOOR_W_D]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FLOOR_W_S]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FRINT_D]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FRINT_W]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FTRUNC_S_D]             = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FTRUNC_S_W]             = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FTRUNC_U_D]             = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FTRUNC_U_W]             = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_ROUND_L_D]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_ROUND_L_S]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_ROUND_W_D]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_ROUND_W_S]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_TRUNC_L_D]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_TRUNC_L_S]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_TRUNC_W_D]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_TRUNC_W_S]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    /* FP compare/min/max/class */
    [MIPS_INS_CLASS_D]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CLASS_S]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_AF_D]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_AF_S]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_EQ_D]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_EQ_S]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_LE_D]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_LE_S]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_LT_D]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_LT_S]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SAF_D]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SAF_S]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SEQ_D]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SEQ_S]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SLE_D]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SLE_S]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SLT_D]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SLT_S]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SUEQ_D]             = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SUEQ_S]             = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SULE_D]             = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SULE_S]             = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SULT_D]             = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SULT_S]             = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SUN_D]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_SUN_S]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_UEQ_D]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_UEQ_S]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_ULE_D]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_ULE_S]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_ULT_D]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_ULT_S]              = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_UN_D]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_CMP_UN_S]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_EQ_D]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_EQ_S]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_F_D]                  = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_F_S]                  = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_LE_D]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_LE_S]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_LT_D]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_LT_S]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_NGE_D]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_NGE_S]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_NGLE_D]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_NGLE_S]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_NGL_D]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_NGL_S]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_NGT_D]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_NGT_S]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_OLE_D]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_OLE_S]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_OLT_D]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_OLT_S]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_SEQ_D]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_SEQ_S]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_SF_D]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_SF_S]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_UEQ_D]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_UEQ_S]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_ULE_D]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_ULE_S]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_ULT_D]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_ULT_S]                = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_UN_D]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_C_UN_S]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FCLASS_D]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_FCLASS_W]               = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MAXA_D]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MAXA_S]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MAX_D]                  = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MINA_D]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MINA_S]                 = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [MIPS_INS_MIN_D]                  = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
};

#endif /* CHAMPSIM_TRACER_MNEMONICS_MIPS_H */
