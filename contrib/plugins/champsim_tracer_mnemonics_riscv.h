#ifndef CHAMPSIM_TRACER_MNEMONICS_RISCV_H
#define CHAMPSIM_TRACER_MNEMONICS_RISCV_H

/*
 * ISA-specific classification tables for champsim_tracer — riscv.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <capstone/capstone.h>
#include <capstone/riscv.h>
#include "elf.h"
#include <qemu-plugin.h>

#include "champsim_tracer_elf_attrs.h"

/*
 * Map a single token of a Tag_RISCV_arch string (e.g. "c", "zba") to
 * the corresponding CS_MODE_RISCV_* bit, or 0 if Capstone has no
 * dedicated bit for it (decoded by the base ISA path).
 */
static unsigned int cs_riscv_token_to_mode(const char *tok)
{
    if (g_str_equal(tok, "c"))    return CS_MODE_RISCV_C;
    if (g_str_equal(tok, "f"))    return CS_MODE_RISCV_FD;
    if (g_str_equal(tok, "d"))    return CS_MODE_RISCV_FD;
    if (g_str_equal(tok, "a"))    return CS_MODE_RISCV_A;
    if (g_str_equal(tok, "v"))    return CS_MODE_RISCV_V;
    if (g_str_equal(tok, "zba"))  return CS_MODE_RISCV_ZBA;
    if (g_str_equal(tok, "zbb"))  return CS_MODE_RISCV_ZBB;
    if (g_str_equal(tok, "zbc"))  return CS_MODE_RISCV_ZBC;
    if (g_str_equal(tok, "zbkb")) return CS_MODE_RISCV_ZBKB;
    if (g_str_equal(tok, "zbkc")) return CS_MODE_RISCV_ZBKC;
    if (g_str_equal(tok, "zbkx")) return CS_MODE_RISCV_ZBKX;
    if (g_str_equal(tok, "zbs"))  return CS_MODE_RISCV_ZBS;
    /* Half-precision FP extensions imply the FD decoder path in cs6. */
    if (g_str_equal(tok, "zfh") || g_str_equal(tok, "zfhmin")) {
        return CS_MODE_RISCV_FD;
    }
    /* Tokens such as zicsr / zifencei / zicbom / ztso / zihintpause
     * are decoded by the base ISA path; no additional mode bit. */
    return 0;
}

/*
 * Parse a Tag_RISCV_arch string ("rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0
 * _zicsr2p0_zifencei2p0_zba1p0...") into a bitmask of CS_MODE_RISCV_*
 * bits.  Single-letter base extensions are concatenated without
 * separators in the first run; "zX..." / "sX..." tokens follow,
 * underscore-separated.  Each token may carry a trailing "<n>p<n>"
 * version that we strip.
 */
static unsigned int cs_riscv_parse_arch_string(const char *arch)
{
    if (!arch || !*arch) {
        return 0;
    }

    const char *q = arch;
    if (g_str_has_prefix(q, "rv32") || g_str_has_prefix(q, "rv64")) {
        q += 4;
    }

    unsigned int mode = 0;
    GString *tok = g_string_new(NULL);
    bool first_group = true;

    while (*q) {
        if (*q == '_') {
            if (tok->len) {
                gchar *t = g_ascii_strdown(tok->str, tok->len);
                gchar *vp = t;
                while (*vp && !g_ascii_isdigit(*vp)) vp++;
                if (vp > t) *vp = '\0';
                mode |= cs_riscv_token_to_mode(t);
                g_free(t);
                g_string_set_size(tok, 0);
            }
            first_group = false;
            q++;
            continue;
        }
        if (first_group) {
            if (g_ascii_isalpha(*q)) {
                gchar letter[2] = { (gchar)g_ascii_tolower(*q), '\0' };
                mode |= cs_riscv_token_to_mode(letter);
            }
            /* Digits and 'p' inside version markers are skipped. */
            q++;
            continue;
        }
        g_string_append_c(tok, *q);
        q++;
    }
    if (tok->len) {
        gchar *t = g_ascii_strdown(tok->str, tok->len);
        gchar *vp = t;
        while (*vp && !g_ascii_isdigit(*vp)) vp++;
        if (vp > t) *vp = '\0';
        mode |= cs_riscv_token_to_mode(t);
        g_free(t);
    }
    g_string_free(tok, TRUE);
    return mode;
}

static void cs_riscv_attr_cb(uint64_t tag, const void *value, bool is_string,
                             void *user)
{
    unsigned int *mode = (unsigned int *)user;
    if (tag == Tag_RISCV_arch && is_string) {
        *mode |= cs_riscv_parse_arch_string((const char *)value);
    }
}

static unsigned int cap_mode_riscv(const char *target_name)
{
    unsigned int base = g_str_has_prefix(target_name, "riscv32")
                      ? CS_MODE_RISCV32
                      : CS_MODE_RISCV64;

    /* Try to derive extension bits from the binary's .riscv.attributes. */
    const char *bin = qemu_plugin_path_to_binary();
    CsElfInfo info;
    unsigned int dyn = 0;
    if (cs_elf_load(bin, &info)) {
        const uint8_t *body;
        size_t body_size;
        if (cs_elf_find_section(&info, SHT_RISCV_ATTRIBUTES, &body,
                                &body_size)) {
            cs_elf_walk_attributes(body, body_size, "riscv",
                                   cs_riscv_attr_cb, &dyn);
        }
        cs_elf_unload(&info);
    }
    if (dyn) {
        return base | dyn;
    }

    /*
     * Fall back to the comprehensive ratified-extension default.  Vendor
     * extensions (XTHEAD*, XSF*, XCV*, SIFIVE, COREV) and conflicting
     * subsets (ZFINX/ZHINX/ZDINX/E/ZCMP-ZCE) are intentionally NOT
     * enabled — they shadow base-ISA encodings in cs6.
     */
    return base | CS_MODE_RISCV_C
                | CS_MODE_RISCV_FD
                | CS_MODE_RISCV_A
                | CS_MODE_RISCV_V
                | CS_MODE_RISCV_ZBA
                | CS_MODE_RISCV_ZBB
                | CS_MODE_RISCV_ZBC
                | CS_MODE_RISCV_ZBKB
                | CS_MODE_RISCV_ZBKC
                | CS_MODE_RISCV_ZBKX
                | CS_MODE_RISCV_ZBS;
}

/*
 * Refiner: disambiguate JALR / C.JR forms.
 *
 * Capstone returns the same insn_id for every JALR variant
 * (RISCV_INS_JALR) and the same id for every C.JR
 * (RISCV_INS_C_JR), so the table cannot tell them apart on its
 * own.  The encoding distinguishes:
 *   jalr rd, rs1, imm  rd != x0   -> indirect CALL  (link in rd)
 *   jalr x0, x1, 0     ("ret")    -> RETURN
 *   jalr x0, rs1, imm  rs1 != x1  -> indirect JUMP
 *   c.jr ra                       -> RETURN
 *   c.jr <other>                  -> indirect JUMP  (table default)
 *
 * The generic decoder strips x0 as REG_NONE, so the rd==x0 case
 * shows up here as n_dst_regs == 0.  rs1 == x1 shows up as REG_LR
 * in src_regs.  Any "ret" pseudo Capstone emits with no operands
 * is treated as RETURN.
 */
static void refine_riscv_indirect_jr(
    const struct qemu_plugin_insn_info *info, InsnFields *f)
{
    (void)info;
    if (f->n_dst_regs != 0) {
        return; /* keep table default (indirect CALL) */
    }

    bool src_is_lr = false;
    for (uint8_t i = 0; i < f->n_src_regs; i++) {
        if (f->src_regs[i] == REG_LR) {
            src_is_lr = true;
            break;
        }
    }

    if (src_is_lr || f->n_src_regs == 0) {
        f->opcode = GEN_OP_RET;
        f->branch_type = BRANCH_RETURN;
    } else {
        f->opcode = GEN_OP_BRANCH;
        f->branch_type = BRANCH_INDIRECT_JUMP;
    }
    f->branch_conditional = false;
}

/* RISCV: 95/96 classified, 1 REG_NONE */
static const RegClassification riscv_reg_class[RISCV_REG_ENDING] = {
    [RISCV_REG_X1] = { REG_LR },  /* ra */
    [RISCV_REG_X2] = { REG_SP },  /* sp */
    [RISCV_REG_X3] = { REG_GPR3 },  /* gp */
    [RISCV_REG_X4] = { REG_GPR4 },  /* tp */
    [RISCV_REG_X5] = { REG_GPR5 },  /* t0 */
    [RISCV_REG_X6] = { REG_GPR6 },  /* t1 */
    [RISCV_REG_X7] = { REG_GPR7 },  /* t2 */
    [RISCV_REG_X8] = { REG_FP_REG },  /* s0 */
    [RISCV_REG_X9] = { REG_GPR9 },  /* s1 */
    [RISCV_REG_X10] = { REG_GPR10 },  /* a0 */
    [RISCV_REG_X11] = { REG_GPR11 },  /* a1 */
    [RISCV_REG_X12] = { REG_GPR12 },  /* a2 */
    [RISCV_REG_X13] = { REG_GPR13 },  /* a3 */
    [RISCV_REG_X14] = { REG_GPR14 },  /* a4 */
    [RISCV_REG_X15] = { REG_GPR15 },  /* a5 */
    [RISCV_REG_X16] = { REG_GPR16 },  /* a6 */
    [RISCV_REG_X17] = { REG_GPR17 },  /* a7 */
    [RISCV_REG_X18] = { REG_GPR18 },  /* s2 */
    [RISCV_REG_X19] = { REG_GPR19 },  /* s3 */
    [RISCV_REG_X20] = { REG_GPR20 },  /* s4 */
    [RISCV_REG_X21] = { REG_GPR21 },  /* s5 */
    [RISCV_REG_X22] = { REG_GPR22 },  /* s6 */
    [RISCV_REG_X23] = { REG_GPR23 },  /* s7 */
    [RISCV_REG_X24] = { REG_GPR24 },  /* s8 */
    [RISCV_REG_X25] = { REG_GPR25 },  /* s9 */
    [RISCV_REG_X26] = { REG_GPR26 },  /* s10 */
    [RISCV_REG_X27] = { REG_GPR27 },  /* s11 */
    [RISCV_REG_X28] = { REG_GPR28 },  /* t3 */
    [RISCV_REG_X29] = { REG_GPR29 },  /* t4 */
    [RISCV_REG_X30] = { REG_GPR30 },  /* t5 */
    [RISCV_REG_X31] = { REG_GPR31 },  /* t6 */
    /*
     * Capstone 6 split FP register IDs by element width
     * (F*_F = single, F*_D = double, F*_H = half).  We classify all
     * three width-views as the same architectural register slot.
     */
    [RISCV_REG_F0_F]  = { REG_FPR0  },  [RISCV_REG_F0_D]  = { REG_FPR0  },  [RISCV_REG_F0_H]  = { REG_FPR0  },
    [RISCV_REG_F1_F]  = { REG_FPR1  },  [RISCV_REG_F1_D]  = { REG_FPR1  },  [RISCV_REG_F1_H]  = { REG_FPR1  },
    [RISCV_REG_F2_F]  = { REG_FPR2  },  [RISCV_REG_F2_D]  = { REG_FPR2  },  [RISCV_REG_F2_H]  = { REG_FPR2  },
    [RISCV_REG_F3_F]  = { REG_FPR3  },  [RISCV_REG_F3_D]  = { REG_FPR3  },  [RISCV_REG_F3_H]  = { REG_FPR3  },
    [RISCV_REG_F4_F]  = { REG_FPR4  },  [RISCV_REG_F4_D]  = { REG_FPR4  },  [RISCV_REG_F4_H]  = { REG_FPR4  },
    [RISCV_REG_F5_F]  = { REG_FPR5  },  [RISCV_REG_F5_D]  = { REG_FPR5  },  [RISCV_REG_F5_H]  = { REG_FPR5  },
    [RISCV_REG_F6_F]  = { REG_FPR6  },  [RISCV_REG_F6_D]  = { REG_FPR6  },  [RISCV_REG_F6_H]  = { REG_FPR6  },
    [RISCV_REG_F7_F]  = { REG_FPR7  },  [RISCV_REG_F7_D]  = { REG_FPR7  },  [RISCV_REG_F7_H]  = { REG_FPR7  },
    [RISCV_REG_F8_F]  = { REG_FPR8  },  [RISCV_REG_F8_D]  = { REG_FPR8  },  [RISCV_REG_F8_H]  = { REG_FPR8  },
    [RISCV_REG_F9_F]  = { REG_FPR9  },  [RISCV_REG_F9_D]  = { REG_FPR9  },  [RISCV_REG_F9_H]  = { REG_FPR9  },
    [RISCV_REG_F10_F] = { REG_FPR10 },  [RISCV_REG_F10_D] = { REG_FPR10 },  [RISCV_REG_F10_H] = { REG_FPR10 },
    [RISCV_REG_F11_F] = { REG_FPR11 },  [RISCV_REG_F11_D] = { REG_FPR11 },  [RISCV_REG_F11_H] = { REG_FPR11 },
    [RISCV_REG_F12_F] = { REG_FPR12 },  [RISCV_REG_F12_D] = { REG_FPR12 },  [RISCV_REG_F12_H] = { REG_FPR12 },
    [RISCV_REG_F13_F] = { REG_FPR13 },  [RISCV_REG_F13_D] = { REG_FPR13 },  [RISCV_REG_F13_H] = { REG_FPR13 },
    [RISCV_REG_F14_F] = { REG_FPR14 },  [RISCV_REG_F14_D] = { REG_FPR14 },  [RISCV_REG_F14_H] = { REG_FPR14 },
    [RISCV_REG_F15_F] = { REG_FPR15 },  [RISCV_REG_F15_D] = { REG_FPR15 },  [RISCV_REG_F15_H] = { REG_FPR15 },
    [RISCV_REG_F16_F] = { REG_FPR16 },  [RISCV_REG_F16_D] = { REG_FPR16 },  [RISCV_REG_F16_H] = { REG_FPR16 },
    [RISCV_REG_F17_F] = { REG_FPR17 },  [RISCV_REG_F17_D] = { REG_FPR17 },  [RISCV_REG_F17_H] = { REG_FPR17 },
    [RISCV_REG_F18_F] = { REG_FPR18 },  [RISCV_REG_F18_D] = { REG_FPR18 },  [RISCV_REG_F18_H] = { REG_FPR18 },
    [RISCV_REG_F19_F] = { REG_FPR19 },  [RISCV_REG_F19_D] = { REG_FPR19 },  [RISCV_REG_F19_H] = { REG_FPR19 },
    [RISCV_REG_F20_F] = { REG_FPR20 },  [RISCV_REG_F20_D] = { REG_FPR20 },  [RISCV_REG_F20_H] = { REG_FPR20 },
    [RISCV_REG_F21_F] = { REG_FPR21 },  [RISCV_REG_F21_D] = { REG_FPR21 },  [RISCV_REG_F21_H] = { REG_FPR21 },
    [RISCV_REG_F22_F] = { REG_FPR22 },  [RISCV_REG_F22_D] = { REG_FPR22 },  [RISCV_REG_F22_H] = { REG_FPR22 },
    [RISCV_REG_F23_F] = { REG_FPR23 },  [RISCV_REG_F23_D] = { REG_FPR23 },  [RISCV_REG_F23_H] = { REG_FPR23 },
    [RISCV_REG_F24_F] = { REG_FPR24 },  [RISCV_REG_F24_D] = { REG_FPR24 },  [RISCV_REG_F24_H] = { REG_FPR24 },
    [RISCV_REG_F25_F] = { REG_FPR25 },  [RISCV_REG_F25_D] = { REG_FPR25 },  [RISCV_REG_F25_H] = { REG_FPR25 },
    [RISCV_REG_F26_F] = { REG_FPR26 },  [RISCV_REG_F26_D] = { REG_FPR26 },  [RISCV_REG_F26_H] = { REG_FPR26 },
    [RISCV_REG_F27_F] = { REG_FPR27 },  [RISCV_REG_F27_D] = { REG_FPR27 },  [RISCV_REG_F27_H] = { REG_FPR27 },
    [RISCV_REG_F28_F] = { REG_FPR28 },  [RISCV_REG_F28_D] = { REG_FPR28 },  [RISCV_REG_F28_H] = { REG_FPR28 },
    [RISCV_REG_F29_F] = { REG_FPR29 },  [RISCV_REG_F29_D] = { REG_FPR29 },  [RISCV_REG_F29_H] = { REG_FPR29 },
    [RISCV_REG_F30_F] = { REG_FPR30 },  [RISCV_REG_F30_D] = { REG_FPR30 },  [RISCV_REG_F30_H] = { REG_FPR30 },
    [RISCV_REG_F31_F] = { REG_FPR31 },  [RISCV_REG_F31_D] = { REG_FPR31 },  [RISCV_REG_F31_H] = { REG_FPR31 },
};

/* RISCV: 273/273 classified (all instructions) */
static const InsnClassification riscv_insn_class[RISCV_INS_ENDING] = {
    /* RV64I base */
    [RISCV_INS_ADD]                 = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_ADDI]                = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_ADDIW]               = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_ADDW]                = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_AND]                 = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_ANDI]                = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_AUIPC]               = { GEN_OP_LEA,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_BEQ]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [RISCV_INS_BGE]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [RISCV_INS_BGEU]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [RISCV_INS_BLT]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [RISCV_INS_BLTU]                = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [RISCV_INS_BNE]                 = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [RISCV_INS_EBREAK]              = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [RISCV_INS_ECALL]               = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [RISCV_INS_FENCE]               = { GEN_OP_FENCE,     BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_FENCE_I]             = { GEN_OP_FENCE,     BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_FENCE_TSO]           = { GEN_OP_FENCE,     BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_JAL]                 = { GEN_OP_CALL,      BRANCH_DIRECT_CALL,   MF_NONE },
    /*
     * JALR encodes three distinct semantics depending on rd/rs1:
     *   rd != x0                  : indirect CALL (link saved in rd)
     *   rd == x0, rs1 == x1, imm 0: RETURN ("ret" pseudo)
     *   rd == x0, rs1 != x1       : indirect JUMP
     * Capstone gives all three the same insn_id, so the table
     * default here is the most common case (indirect call); the
     * rd==x0 forms are reclassified by refine_riscv_indirect_jr.
     */
    [RISCV_INS_JALR]                = { GEN_OP_CALL,      BRANCH_INDIRECT_CALL, MF_NONE,
                                        .refine = refine_riscv_indirect_jr },
    [RISCV_INS_LB]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_LBU]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_LD]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_LH]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_LHU]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_LUI]                 = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_LW]                  = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_LWU]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_OR]                  = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [RISCV_INS_ORI]                 = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SB]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SD]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SH]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SLL]                 = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SLLI]                = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SLLIW]               = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SLLW]                = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SLT]                 = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SLTI]                = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SLTIU]               = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SLTU]                = { GEN_OP_CMP,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SRA]                 = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SRAI]                = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SRAIW]               = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SRAW]                = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SRL]                 = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SRLI]                = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SRLIW]               = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SRLW]                = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SUB]                 = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SUBW]                = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SW]                  = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_XOR]                 = { GEN_OP_XOR,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_XORI]                = { GEN_OP_XOR,       BRANCH_NONE,          MF_NONE },
    /* RV64M */
    [RISCV_INS_DIV]                 = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_DIVU]                = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_DIVUW]               = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_DIVW]                = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_MUL]                 = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_MULH]                = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_MULHSU]              = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_MULHU]               = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_MULW]                = { GEN_OP_INT_MUL,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_REM]                 = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_REMU]                = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_REMUW]               = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_REMW]                = { GEN_OP_INT_DIV,   BRANCH_NONE,          MF_NONE },
    /* RV64A atomics */
    [RISCV_INS_AMOADD_D]            = { GEN_OP_INT_ADD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOADD_D_AQ]         = { GEN_OP_INT_ADD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOADD_D_RL]         = { GEN_OP_INT_ADD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOADD_W]            = { GEN_OP_INT_ADD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOADD_W_AQ]         = { GEN_OP_INT_ADD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOADD_W_RL]         = { GEN_OP_INT_ADD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOAND_D]            = { GEN_OP_AND,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOAND_D_AQ]         = { GEN_OP_AND,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOAND_D_RL]         = { GEN_OP_AND,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOAND_W]            = { GEN_OP_AND,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOAND_W_AQ]         = { GEN_OP_AND,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOAND_W_RL]         = { GEN_OP_AND,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAXU_D]           = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAXU_D_AQ]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAXU_D_RL]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAXU_W]           = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAXU_W_AQ]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAXU_W_RL]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAX_D]            = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAX_D_AQ]         = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAX_D_RL]         = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAX_W]            = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAX_W_AQ]         = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMAX_W_RL]         = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMINU_D]           = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMINU_D_AQ]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMINU_D_RL]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMINU_W]           = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMINU_W_AQ]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMINU_W_RL]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMIN_D]            = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMIN_D_AQ]         = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMIN_D_RL]         = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMIN_W]            = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMIN_W_AQ]         = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOMIN_W_RL]         = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOOR_D]             = { GEN_OP_OR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOOR_D_AQ]          = { GEN_OP_OR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOOR_D_RL]          = { GEN_OP_OR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOOR_W]             = { GEN_OP_OR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOOR_W_AQ]          = { GEN_OP_OR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOOR_W_RL]          = { GEN_OP_OR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOSWAP_D]           = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOSWAP_D_AQ]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOSWAP_D_RL]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOSWAP_W]           = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOSWAP_W_AQ]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOSWAP_W_RL]        = { GEN_OP_XCHG,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOXOR_D]            = { GEN_OP_XOR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOXOR_D_AQ]         = { GEN_OP_XOR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOXOR_D_RL]         = { GEN_OP_XOR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOXOR_W]            = { GEN_OP_XOR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOXOR_W_AQ]         = { GEN_OP_XOR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_AMOXOR_W_RL]         = { GEN_OP_XOR,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_LR_D]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_LR_D_AQ]             = { GEN_OP_LOAD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_LR_D_RL]             = { GEN_OP_LOAD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_LR_W]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_LR_W_AQ]             = { GEN_OP_LOAD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_LR_W_RL]             = { GEN_OP_LOAD,      BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_SC_D]                = { GEN_OP_STORE,     BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_SC_D_AQ]             = { GEN_OP_STORE,     BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_SC_D_RL]             = { GEN_OP_STORE,     BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_SC_W]                = { GEN_OP_STORE,     BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_SC_W_AQ]             = { GEN_OP_STORE,     BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_SC_W_RL]             = { GEN_OP_STORE,     BRANCH_NONE,          MF_ATOMIC },
    /* RV64F/D floating point */
    [RISCV_INS_FLD]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FLW]                 = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSD]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSW]                 = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FADD_S]              = { GEN_OP_FP_ADD,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FADD_D]              = { GEN_OP_FP_ADD,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSUB_S]              = { GEN_OP_FP_SUB,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSUB_D]              = { GEN_OP_FP_SUB,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMUL_S]              = { GEN_OP_FP_MUL,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMUL_D]              = { GEN_OP_FP_MUL,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FDIV_S]              = { GEN_OP_FP_DIV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FDIV_D]              = { GEN_OP_FP_DIV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSQRT_S]             = { GEN_OP_FP_SQRT,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSQRT_D]             = { GEN_OP_FP_SQRT,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMIN_S]              = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMIN_D]              = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMAX_S]              = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMAX_D]              = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMADD_S]             = { GEN_OP_FP_MUL,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMADD_D]             = { GEN_OP_FP_MUL,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMSUB_S]             = { GEN_OP_FP_MUL,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMSUB_D]             = { GEN_OP_FP_MUL,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FNMADD_S]            = { GEN_OP_FP_MUL,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FNMADD_D]            = { GEN_OP_FP_MUL,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FNMSUB_S]            = { GEN_OP_FP_MUL,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FNMSUB_D]            = { GEN_OP_FP_MUL,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSGNJ_S]             = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSGNJ_D]             = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSGNJN_S]            = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSGNJN_D]            = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSGNJX_S]            = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FSGNJX_D]            = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMV_W_X]             = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMV_X_W]             = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMV_D_X]             = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FMV_X_D]             = { GEN_OP_FP_MOV,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_S_D]            = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_D_S]            = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_W_S]            = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_W_D]            = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_WU_S]           = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_WU_D]           = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_L_S]            = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_L_D]            = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_LU_S]           = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_LU_D]           = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_S_W]            = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_S_WU]           = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_S_L]            = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_S_LU]           = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_D_W]            = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_D_WU]           = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_D_L]            = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCVT_D_LU]           = { GEN_OP_FP_CVT,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FEQ_S]               = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FEQ_D]               = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FLT_S]               = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FLT_D]               = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FLE_S]               = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FLE_D]               = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCLASS_S]            = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    [RISCV_INS_FCLASS_D]            = { GEN_OP_FP_CMP,    BRANCH_NONE,          MF_NONE },
    /* Zicsr */
    [RISCV_INS_CSRRW]               = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_CSRRS]               = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_CSRRC]               = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_CSRRWI]              = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_CSRRSI]              = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_CSRRCI]              = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    /* System */
    [RISCV_INS_MRET]                = { GEN_OP_RET,       BRANCH_RETURN,        MF_NONE },
    [RISCV_INS_SRET]                = { GEN_OP_RET,       BRANCH_RETURN,        MF_NONE },
    [RISCV_INS_WFI]                 = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_SFENCE_VMA]          = { GEN_OP_FENCE,     BRANCH_NONE,          MF_ATOMIC },
    [RISCV_INS_UNIMP]               = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    /* RV64C compressed */
    [RISCV_INS_C_ADD]               = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_ADDI]              = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_ADDI16SP]          = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_ADDI4SPN]          = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_ADDIW]             = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_ADDW]              = { GEN_OP_INT_ADD,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_AND]               = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_ANDI]              = { GEN_OP_AND,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_BEQZ]              = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [RISCV_INS_C_BNEZ]              = { GEN_OP_BRANCH,    BRANCH_COND_DIRECT,   MF_CONDITIONAL },
    [RISCV_INS_C_EBREAK]            = { GEN_OP_SYSCALL,   BRANCH_SYSCALL_TYPE,  MF_NONE },
    [RISCV_INS_C_FLD]               = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_FLDSP]             = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_FLW]               = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_FLWSP]             = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_FSD]               = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_FSDSP]             = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_FSW]               = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_FSWSP]             = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_J]                 = { GEN_OP_BRANCH,    BRANCH_DIRECT_JUMP,   MF_NONE },
    [RISCV_INS_C_JAL]               = { GEN_OP_CALL,      BRANCH_DIRECT_CALL,   MF_NONE },
    [RISCV_INS_C_JALR]              = { GEN_OP_CALL,      BRANCH_INDIRECT_CALL, MF_NONE },
    /*
     * C.JR rs1 is RETURN when rs1 == x1 (ra) and indirect JUMP
     * otherwise; both share the same insn_id, so the rs1==x1 case is
     * promoted to BRANCH_RETURN in decode_detail_to_generic().
     */
    [RISCV_INS_C_JR]                = { GEN_OP_BRANCH,    BRANCH_INDIRECT_JUMP, MF_NONE,
                                        .refine = refine_riscv_indirect_jr },
    [RISCV_INS_C_LD]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_LDSP]              = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_LI]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_LUI]               = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_LW]                = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_LWSP]              = { GEN_OP_LOAD,      BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_MV]                = { GEN_OP_MOV,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_NOP]               = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_OR]                = { GEN_OP_OR,        BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_SD]                = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_SDSP]              = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_SLLI]              = { GEN_OP_SHL,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_SRAI]              = { GEN_OP_SAR,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_SRLI]              = { GEN_OP_SHR,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_SUB]               = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_SUBW]              = { GEN_OP_INT_SUB,   BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_SW]                = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_SWSP]              = { GEN_OP_STORE,     BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_UNIMP]             = { GEN_OP_NOP,       BRANCH_NONE,          MF_NONE },
    [RISCV_INS_C_XOR]               = { GEN_OP_XOR,       BRANCH_NONE,          MF_NONE },
};

#endif /* CHAMPSIM_TRACER_MNEMONICS_RISCV_H */
