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


/* Register classification table. */
static const RegClassification riscv_reg_class[RISCV_REG_ENDING] = {
    /* Auto-generated by champsim_tracer_mnemonic_audit.py. */
    /* riscv regs: 458/459 mapped, 0 intentionally ignored */
    [RISCV_REG_FFLAGS] = { .reg_id = REG_FCSR },  /* fflags */
    [RISCV_REG_FRM] = { .reg_id = REG_FCSR },  /* frm */
    [RISCV_REG_SSP] = { .reg_id = REG_SP },  /* ssp */
    [RISCV_REG_VL] = { .reg_id = REG_VCTRL },  /* vl */
    [RISCV_REG_VLENB] = { .reg_id = REG_VCTRL },  /* vlenb */
    [RISCV_REG_VTYPE] = { .reg_id = REG_VCTRL },  /* vtype */
    [RISCV_REG_VXRM] = { .reg_id = REG_VCTRL },  /* vxrm */
    [RISCV_REG_VXSAT] = { .reg_id = REG_VCTRL },  /* vxsat */
    [RISCV_REG_DUMMY_REG_PAIR_WITH_X0] = { .reg_id = REG_ZERO },  /* dummy_reg_pair_with_x0 */
    [RISCV_REG_V0] = { .reg_id = REG_VEC0, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v0" } },  /* v0 */
    [RISCV_REG_V1] = { .reg_id = REG_VEC1, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v1" } },  /* v1 */
    [RISCV_REG_V2] = { .reg_id = REG_VEC2, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v2" } },  /* v2 */
    [RISCV_REG_V3] = { .reg_id = REG_VEC3, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v3" } },  /* v3 */
    [RISCV_REG_V4] = { .reg_id = REG_VEC4, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v4" } },  /* v4 */
    [RISCV_REG_V5] = { .reg_id = REG_VEC5, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v5" } },  /* v5 */
    [RISCV_REG_V6] = { .reg_id = REG_VEC6, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v6" } },  /* v6 */
    [RISCV_REG_V7] = { .reg_id = REG_VEC7, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v7" } },  /* v7 */
    [RISCV_REG_V8] = { .reg_id = REG_VEC8, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v8" } },  /* v8 */
    [RISCV_REG_V9] = { .reg_id = REG_VEC9, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v9" } },  /* v9 */
    [RISCV_REG_V10] = { .reg_id = REG_VEC10, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v10" } },  /* v10 */
    [RISCV_REG_V11] = { .reg_id = REG_VEC11, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v11" } },  /* v11 */
    [RISCV_REG_V12] = { .reg_id = REG_VEC12, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v12" } },  /* v12 */
    [RISCV_REG_V13] = { .reg_id = REG_VEC13, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v13" } },  /* v13 */
    [RISCV_REG_V14] = { .reg_id = REG_VEC14, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v14" } },  /* v14 */
    [RISCV_REG_V15] = { .reg_id = REG_VEC15, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v15" } },  /* v15 */
    [RISCV_REG_V16] = { .reg_id = REG_VEC16, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v16" } },  /* v16 */
    [RISCV_REG_V17] = { .reg_id = REG_VEC17, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v17" } },  /* v17 */
    [RISCV_REG_V18] = { .reg_id = REG_VEC18, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v18" } },  /* v18 */
    [RISCV_REG_V19] = { .reg_id = REG_VEC19, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v19" } },  /* v19 */
    [RISCV_REG_V20] = { .reg_id = REG_VEC20, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v20" } },  /* v20 */
    [RISCV_REG_V21] = { .reg_id = REG_VEC21, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v21" } },  /* v21 */
    [RISCV_REG_V22] = { .reg_id = REG_VEC22, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v22" } },  /* v22 */
    [RISCV_REG_V23] = { .reg_id = REG_VEC23, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v23" } },  /* v23 */
    [RISCV_REG_V24] = { .reg_id = REG_VEC24, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v24" } },  /* v24 */
    [RISCV_REG_V25] = { .reg_id = REG_VEC25, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v25" } },  /* v25 */
    [RISCV_REG_V26] = { .reg_id = REG_VEC26, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v26" } },  /* v26 */
    [RISCV_REG_V27] = { .reg_id = REG_VEC27, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v27" } },  /* v27 */
    [RISCV_REG_V28] = { .reg_id = REG_VEC28, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v28" } },  /* v28 */
    [RISCV_REG_V29] = { .reg_id = REG_VEC29, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v29" } },  /* v29 */
    [RISCV_REG_V30] = { .reg_id = REG_VEC30, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v30" } },  /* v30 */
    [RISCV_REG_V31] = { .reg_id = REG_VEC31, .qemu_reg = { .feature = "org.gnu.gdb.riscv.vector", .name = "v31" } },  /* v31 */
    [RISCV_REG_X0] = { .reg_id = REG_ZERO, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "zero" } },  /* x0 */
    [RISCV_REG_X1] = { .reg_id = REG_LR, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "ra" } },  /* x1 */
    [RISCV_REG_X2] = { .reg_id = REG_SP, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "sp" } },  /* x2 */
    [RISCV_REG_X3] = { .reg_id = REG_GPR3, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "gp" } },  /* x3 */
    [RISCV_REG_X4] = { .reg_id = REG_GPR4, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "tp" } },  /* x4 */
    [RISCV_REG_X5] = { .reg_id = REG_GPR5, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "t0" } },  /* x5 */
    [RISCV_REG_X6] = { .reg_id = REG_GPR6, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "t1" } },  /* x6 */
    [RISCV_REG_X7] = { .reg_id = REG_GPR7, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "t2" } },  /* x7 */
    [RISCV_REG_X8] = { .reg_id = REG_FP_REG, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "fp" } },  /* x8 */
    [RISCV_REG_X9] = { .reg_id = REG_GPR9, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "s1" } },  /* x9 */
    [RISCV_REG_X10] = { .reg_id = REG_GPR10, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "a0" } },  /* x10 */
    [RISCV_REG_X11] = { .reg_id = REG_GPR11, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "a1" } },  /* x11 */
    [RISCV_REG_X12] = { .reg_id = REG_GPR12, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "a2" } },  /* x12 */
    [RISCV_REG_X13] = { .reg_id = REG_GPR13, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "a3" } },  /* x13 */
    [RISCV_REG_X14] = { .reg_id = REG_GPR14, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "a4" } },  /* x14 */
    [RISCV_REG_X15] = { .reg_id = REG_GPR15, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "a5" } },  /* x15 */
    [RISCV_REG_X16] = { .reg_id = REG_GPR16, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "a6" } },  /* x16 */
    [RISCV_REG_X17] = { .reg_id = REG_GPR17, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "a7" } },  /* x17 */
    [RISCV_REG_X18] = { .reg_id = REG_GPR18, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "s2" } },  /* x18 */
    [RISCV_REG_X19] = { .reg_id = REG_GPR19, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "s3" } },  /* x19 */
    [RISCV_REG_X20] = { .reg_id = REG_GPR20, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "s4" } },  /* x20 */
    [RISCV_REG_X21] = { .reg_id = REG_GPR21, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "s5" } },  /* x21 */
    [RISCV_REG_X22] = { .reg_id = REG_GPR22, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "s6" } },  /* x22 */
    [RISCV_REG_X23] = { .reg_id = REG_GPR23, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "s7" } },  /* x23 */
    [RISCV_REG_X24] = { .reg_id = REG_GPR24, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "s8" } },  /* x24 */
    [RISCV_REG_X25] = { .reg_id = REG_GPR25, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "s9" } },  /* x25 */
    [RISCV_REG_X26] = { .reg_id = REG_GPR26, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "s10" } },  /* x26 */
    [RISCV_REG_X27] = { .reg_id = REG_GPR27, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "s11" } },  /* x27 */
    [RISCV_REG_X28] = { .reg_id = REG_GPR28, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "t3" } },  /* x28 */
    [RISCV_REG_X29] = { .reg_id = REG_GPR29, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "t4" } },  /* x29 */
    [RISCV_REG_X30] = { .reg_id = REG_GPR30, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "t5" } },  /* x30 */
    [RISCV_REG_X31] = { .reg_id = REG_GPR31, .qemu_reg = { .feature = "org.gnu.gdb.riscv.cpu", .name = "t6" } },  /* x31 */
    [RISCV_REG_F0_D] = { .reg_id = REG_FPR0, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft0" } },  /* f0_d */
    [RISCV_REG_F1_D] = { .reg_id = REG_FPR1, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft1" } },  /* f1_d */
    [RISCV_REG_F2_D] = { .reg_id = REG_FPR2, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft2" } },  /* f2_d */
    [RISCV_REG_F3_D] = { .reg_id = REG_FPR3, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft3" } },  /* f3_d */
    [RISCV_REG_F4_D] = { .reg_id = REG_FPR4, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft4" } },  /* f4_d */
    [RISCV_REG_F5_D] = { .reg_id = REG_FPR5, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft5" } },  /* f5_d */
    [RISCV_REG_F6_D] = { .reg_id = REG_FPR6, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft6" } },  /* f6_d */
    [RISCV_REG_F7_D] = { .reg_id = REG_FPR7, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft7" } },  /* f7_d */
    [RISCV_REG_F8_D] = { .reg_id = REG_FPR8, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs0" } },  /* f8_d */
    [RISCV_REG_F9_D] = { .reg_id = REG_FPR9, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs1" } },  /* f9_d */
    [RISCV_REG_F10_D] = { .reg_id = REG_FPR10, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa0" } },  /* f10_d */
    [RISCV_REG_F11_D] = { .reg_id = REG_FPR11, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa1" } },  /* f11_d */
    [RISCV_REG_F12_D] = { .reg_id = REG_FPR12, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa2" } },  /* f12_d */
    [RISCV_REG_F13_D] = { .reg_id = REG_FPR13, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa3" } },  /* f13_d */
    [RISCV_REG_F14_D] = { .reg_id = REG_FPR14, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa4" } },  /* f14_d */
    [RISCV_REG_F15_D] = { .reg_id = REG_FPR15, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa5" } },  /* f15_d */
    [RISCV_REG_F16_D] = { .reg_id = REG_FPR16, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa6" } },  /* f16_d */
    [RISCV_REG_F17_D] = { .reg_id = REG_FPR17, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa7" } },  /* f17_d */
    [RISCV_REG_F18_D] = { .reg_id = REG_FPR18, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs2" } },  /* f18_d */
    [RISCV_REG_F19_D] = { .reg_id = REG_FPR19, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs3" } },  /* f19_d */
    [RISCV_REG_F20_D] = { .reg_id = REG_FPR20, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs4" } },  /* f20_d */
    [RISCV_REG_F21_D] = { .reg_id = REG_FPR21, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs5" } },  /* f21_d */
    [RISCV_REG_F22_D] = { .reg_id = REG_FPR22, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs6" } },  /* f22_d */
    [RISCV_REG_F23_D] = { .reg_id = REG_FPR23, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs7" } },  /* f23_d */
    [RISCV_REG_F24_D] = { .reg_id = REG_FPR24, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs8" } },  /* f24_d */
    [RISCV_REG_F25_D] = { .reg_id = REG_FPR25, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs9" } },  /* f25_d */
    [RISCV_REG_F26_D] = { .reg_id = REG_FPR26, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs10" } },  /* f26_d */
    [RISCV_REG_F27_D] = { .reg_id = REG_FPR27, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs11" } },  /* f27_d */
    [RISCV_REG_F28_D] = { .reg_id = REG_FPR28, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft8" } },  /* f28_d */
    [RISCV_REG_F29_D] = { .reg_id = REG_FPR29, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft9" } },  /* f29_d */
    [RISCV_REG_F30_D] = { .reg_id = REG_FPR30, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft10" } },  /* f30_d */
    [RISCV_REG_F31_D] = { .reg_id = REG_FPR31, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft11" } },  /* f31_d */
    [RISCV_REG_F0_F] = { .reg_id = REG_FPR0, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft0" } },  /* f0_f */
    [RISCV_REG_F1_F] = { .reg_id = REG_FPR1, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft1" } },  /* f1_f */
    [RISCV_REG_F2_F] = { .reg_id = REG_FPR2, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft2" } },  /* f2_f */
    [RISCV_REG_F3_F] = { .reg_id = REG_FPR3, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft3" } },  /* f3_f */
    [RISCV_REG_F4_F] = { .reg_id = REG_FPR4, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft4" } },  /* f4_f */
    [RISCV_REG_F5_F] = { .reg_id = REG_FPR5, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft5" } },  /* f5_f */
    [RISCV_REG_F6_F] = { .reg_id = REG_FPR6, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft6" } },  /* f6_f */
    [RISCV_REG_F7_F] = { .reg_id = REG_FPR7, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft7" } },  /* f7_f */
    [RISCV_REG_F8_F] = { .reg_id = REG_FPR8, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs0" } },  /* f8_f */
    [RISCV_REG_F9_F] = { .reg_id = REG_FPR9, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs1" } },  /* f9_f */
    [RISCV_REG_F10_F] = { .reg_id = REG_FPR10, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa0" } },  /* f10_f */
    [RISCV_REG_F11_F] = { .reg_id = REG_FPR11, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa1" } },  /* f11_f */
    [RISCV_REG_F12_F] = { .reg_id = REG_FPR12, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa2" } },  /* f12_f */
    [RISCV_REG_F13_F] = { .reg_id = REG_FPR13, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa3" } },  /* f13_f */
    [RISCV_REG_F14_F] = { .reg_id = REG_FPR14, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa4" } },  /* f14_f */
    [RISCV_REG_F15_F] = { .reg_id = REG_FPR15, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa5" } },  /* f15_f */
    [RISCV_REG_F16_F] = { .reg_id = REG_FPR16, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa6" } },  /* f16_f */
    [RISCV_REG_F17_F] = { .reg_id = REG_FPR17, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa7" } },  /* f17_f */
    [RISCV_REG_F18_F] = { .reg_id = REG_FPR18, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs2" } },  /* f18_f */
    [RISCV_REG_F19_F] = { .reg_id = REG_FPR19, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs3" } },  /* f19_f */
    [RISCV_REG_F20_F] = { .reg_id = REG_FPR20, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs4" } },  /* f20_f */
    [RISCV_REG_F21_F] = { .reg_id = REG_FPR21, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs5" } },  /* f21_f */
    [RISCV_REG_F22_F] = { .reg_id = REG_FPR22, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs6" } },  /* f22_f */
    [RISCV_REG_F23_F] = { .reg_id = REG_FPR23, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs7" } },  /* f23_f */
    [RISCV_REG_F24_F] = { .reg_id = REG_FPR24, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs8" } },  /* f24_f */
    [RISCV_REG_F25_F] = { .reg_id = REG_FPR25, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs9" } },  /* f25_f */
    [RISCV_REG_F26_F] = { .reg_id = REG_FPR26, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs10" } },  /* f26_f */
    [RISCV_REG_F27_F] = { .reg_id = REG_FPR27, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs11" } },  /* f27_f */
    [RISCV_REG_F28_F] = { .reg_id = REG_FPR28, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft8" } },  /* f28_f */
    [RISCV_REG_F29_F] = { .reg_id = REG_FPR29, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft9" } },  /* f29_f */
    [RISCV_REG_F30_F] = { .reg_id = REG_FPR30, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft10" } },  /* f30_f */
    [RISCV_REG_F31_F] = { .reg_id = REG_FPR31, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft11" } },  /* f31_f */
    [RISCV_REG_F0_H] = { .reg_id = REG_FPR0, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft0" } },  /* f0_h */
    [RISCV_REG_F1_H] = { .reg_id = REG_FPR1, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft1" } },  /* f1_h */
    [RISCV_REG_F2_H] = { .reg_id = REG_FPR2, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft2" } },  /* f2_h */
    [RISCV_REG_F3_H] = { .reg_id = REG_FPR3, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft3" } },  /* f3_h */
    [RISCV_REG_F4_H] = { .reg_id = REG_FPR4, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft4" } },  /* f4_h */
    [RISCV_REG_F5_H] = { .reg_id = REG_FPR5, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft5" } },  /* f5_h */
    [RISCV_REG_F6_H] = { .reg_id = REG_FPR6, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft6" } },  /* f6_h */
    [RISCV_REG_F7_H] = { .reg_id = REG_FPR7, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft7" } },  /* f7_h */
    [RISCV_REG_F8_H] = { .reg_id = REG_FPR8, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs0" } },  /* f8_h */
    [RISCV_REG_F9_H] = { .reg_id = REG_FPR9, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs1" } },  /* f9_h */
    [RISCV_REG_F10_H] = { .reg_id = REG_FPR10, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa0" } },  /* f10_h */
    [RISCV_REG_F11_H] = { .reg_id = REG_FPR11, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa1" } },  /* f11_h */
    [RISCV_REG_F12_H] = { .reg_id = REG_FPR12, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa2" } },  /* f12_h */
    [RISCV_REG_F13_H] = { .reg_id = REG_FPR13, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa3" } },  /* f13_h */
    [RISCV_REG_F14_H] = { .reg_id = REG_FPR14, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa4" } },  /* f14_h */
    [RISCV_REG_F15_H] = { .reg_id = REG_FPR15, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa5" } },  /* f15_h */
    [RISCV_REG_F16_H] = { .reg_id = REG_FPR16, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa6" } },  /* f16_h */
    [RISCV_REG_F17_H] = { .reg_id = REG_FPR17, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fa7" } },  /* f17_h */
    [RISCV_REG_F18_H] = { .reg_id = REG_FPR18, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs2" } },  /* f18_h */
    [RISCV_REG_F19_H] = { .reg_id = REG_FPR19, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs3" } },  /* f19_h */
    [RISCV_REG_F20_H] = { .reg_id = REG_FPR20, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs4" } },  /* f20_h */
    [RISCV_REG_F21_H] = { .reg_id = REG_FPR21, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs5" } },  /* f21_h */
    [RISCV_REG_F22_H] = { .reg_id = REG_FPR22, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs6" } },  /* f22_h */
    [RISCV_REG_F23_H] = { .reg_id = REG_FPR23, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs7" } },  /* f23_h */
    [RISCV_REG_F24_H] = { .reg_id = REG_FPR24, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs8" } },  /* f24_h */
    [RISCV_REG_F25_H] = { .reg_id = REG_FPR25, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs9" } },  /* f25_h */
    [RISCV_REG_F26_H] = { .reg_id = REG_FPR26, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs10" } },  /* f26_h */
    [RISCV_REG_F27_H] = { .reg_id = REG_FPR27, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "fs11" } },  /* f27_h */
    [RISCV_REG_F28_H] = { .reg_id = REG_FPR28, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft8" } },  /* f28_h */
    [RISCV_REG_F29_H] = { .reg_id = REG_FPR29, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft9" } },  /* f29_h */
    [RISCV_REG_F30_H] = { .reg_id = REG_FPR30, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft10" } },  /* f30_h */
    [RISCV_REG_F31_H] = { .reg_id = REG_FPR31, .qemu_reg = { .feature = "org.gnu.gdb.riscv.fpu", .name = "ft11" } },  /* f31_h */
    [RISCV_REG_X0_PAIR] = { .reg_id = REG_ZERO },  /* x0_pair */
    [RISCV_REG_V0M2] = { .reg_id = REG_VEC0, .n_regs = 2, .regs = { REG_VEC0, REG_VEC1 } },  /* v0m2 */
    [RISCV_REG_V0M4] = { .reg_id = REG_VEC0, .n_regs = 4, .regs = { REG_VEC0, REG_VEC1, REG_VEC2, REG_VEC3 } },  /* v0m4 */
    [RISCV_REG_V0M8] = { .reg_id = REG_VEC0, .n_regs = 8, .regs = { REG_VEC0, REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v0m8 */
    [RISCV_REG_V2M2] = { .reg_id = REG_VEC2, .n_regs = 2, .regs = { REG_VEC2, REG_VEC3 } },  /* v2m2 */
    [RISCV_REG_V4M2] = { .reg_id = REG_VEC4, .n_regs = 2, .regs = { REG_VEC4, REG_VEC5 } },  /* v4m2 */
    [RISCV_REG_V4M4] = { .reg_id = REG_VEC4, .n_regs = 4, .regs = { REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v4m4 */
    [RISCV_REG_V6M2] = { .reg_id = REG_VEC6, .n_regs = 2, .regs = { REG_VEC6, REG_VEC7 } },  /* v6m2 */
    [RISCV_REG_V8M2] = { .reg_id = REG_VEC8, .n_regs = 2, .regs = { REG_VEC8, REG_VEC9 } },  /* v8m2 */
    [RISCV_REG_V8M4] = { .reg_id = REG_VEC8, .n_regs = 4, .regs = { REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11 } },  /* v8m4 */
    [RISCV_REG_V8M8] = { .reg_id = REG_VEC8, .n_regs = 8, .regs = { REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v8m8 */
    [RISCV_REG_V10M2] = { .reg_id = REG_VEC10, .n_regs = 2, .regs = { REG_VEC10, REG_VEC11 } },  /* v10m2 */
    [RISCV_REG_V12M2] = { .reg_id = REG_VEC12, .n_regs = 2, .regs = { REG_VEC12, REG_VEC13 } },  /* v12m2 */
    [RISCV_REG_V12M4] = { .reg_id = REG_VEC12, .n_regs = 4, .regs = { REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v12m4 */
    [RISCV_REG_V14M2] = { .reg_id = REG_VEC14, .n_regs = 2, .regs = { REG_VEC14, REG_VEC15 } },  /* v14m2 */
    [RISCV_REG_V16M2] = { .reg_id = REG_VEC16, .n_regs = 2, .regs = { REG_VEC16, REG_VEC17 } },  /* v16m2 */
    [RISCV_REG_V16M4] = { .reg_id = REG_VEC16, .n_regs = 4, .regs = { REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19 } },  /* v16m4 */
    [RISCV_REG_V16M8] = { .reg_id = REG_VEC16, .n_regs = 8, .regs = { REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v16m8 */
    [RISCV_REG_V18M2] = { .reg_id = REG_VEC18, .n_regs = 2, .regs = { REG_VEC18, REG_VEC19 } },  /* v18m2 */
    [RISCV_REG_V20M2] = { .reg_id = REG_VEC20, .n_regs = 2, .regs = { REG_VEC20, REG_VEC21 } },  /* v20m2 */
    [RISCV_REG_V20M4] = { .reg_id = REG_VEC20, .n_regs = 4, .regs = { REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v20m4 */
    [RISCV_REG_V22M2] = { .reg_id = REG_VEC22, .n_regs = 2, .regs = { REG_VEC22, REG_VEC23 } },  /* v22m2 */
    [RISCV_REG_V24M2] = { .reg_id = REG_VEC24, .n_regs = 2, .regs = { REG_VEC24, REG_VEC25 } },  /* v24m2 */
    [RISCV_REG_V24M4] = { .reg_id = REG_VEC24, .n_regs = 4, .regs = { REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27 } },  /* v24m4 */
    [RISCV_REG_V24M8] = { .reg_id = REG_VEC24, .n_regs = 8, .regs = { REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v24m8 */
    [RISCV_REG_V26M2] = { .reg_id = REG_VEC26, .n_regs = 2, .regs = { REG_VEC26, REG_VEC27 } },  /* v26m2 */
    [RISCV_REG_V28M2] = { .reg_id = REG_VEC28, .n_regs = 2, .regs = { REG_VEC28, REG_VEC29 } },  /* v28m2 */
    [RISCV_REG_V28M4] = { .reg_id = REG_VEC28, .n_regs = 4, .regs = { REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v28m4 */
    [RISCV_REG_V30M2] = { .reg_id = REG_VEC30, .n_regs = 2, .regs = { REG_VEC30, REG_VEC31 } },  /* v30m2 */
    [RISCV_REG_X2_X3] = { .reg_id = REG_SP, .n_regs = 2, .regs = { REG_SP, REG_GPR3 } },  /* x2_x3 */
    [RISCV_REG_X4_X5] = { .reg_id = REG_GPR4, .n_regs = 2, .regs = { REG_GPR4, REG_GPR5 } },  /* x4_x5 */
    [RISCV_REG_X6_X7] = { .reg_id = REG_GPR6, .n_regs = 2, .regs = { REG_GPR6, REG_GPR7 } },  /* x6_x7 */
    [RISCV_REG_X8_X9] = { .reg_id = REG_FP_REG, .n_regs = 2, .regs = { REG_FP_REG, REG_GPR9 } },  /* x8_x9 */
    [RISCV_REG_X10_X11] = { .reg_id = REG_GPR10, .n_regs = 2, .regs = { REG_GPR10, REG_GPR11 } },  /* x10_x11 */
    [RISCV_REG_X12_X13] = { .reg_id = REG_GPR12, .n_regs = 2, .regs = { REG_GPR12, REG_GPR13 } },  /* x12_x13 */
    [RISCV_REG_X14_X15] = { .reg_id = REG_GPR14, .n_regs = 2, .regs = { REG_GPR14, REG_GPR15 } },  /* x14_x15 */
    [RISCV_REG_X16_X17] = { .reg_id = REG_GPR16, .n_regs = 2, .regs = { REG_GPR16, REG_GPR17 } },  /* x16_x17 */
    [RISCV_REG_X18_X19] = { .reg_id = REG_GPR18, .n_regs = 2, .regs = { REG_GPR18, REG_GPR19 } },  /* x18_x19 */
    [RISCV_REG_X20_X21] = { .reg_id = REG_GPR20, .n_regs = 2, .regs = { REG_GPR20, REG_GPR21 } },  /* x20_x21 */
    [RISCV_REG_X22_X23] = { .reg_id = REG_GPR22, .n_regs = 2, .regs = { REG_GPR22, REG_GPR23 } },  /* x22_x23 */
    [RISCV_REG_X24_X25] = { .reg_id = REG_GPR24, .n_regs = 2, .regs = { REG_GPR24, REG_GPR25 } },  /* x24_x25 */
    [RISCV_REG_X26_X27] = { .reg_id = REG_GPR26, .n_regs = 2, .regs = { REG_GPR26, REG_GPR27 } },  /* x26_x27 */
    [RISCV_REG_X28_X29] = { .reg_id = REG_GPR28, .n_regs = 2, .regs = { REG_GPR28, REG_GPR29 } },  /* x28_x29 */
    [RISCV_REG_X30_X31] = { .reg_id = REG_GPR30, .n_regs = 2, .regs = { REG_GPR30, REG_GPR31 } },  /* x30_x31 */
    [RISCV_REG_V1_V2] = { .reg_id = REG_VEC1, .n_regs = 2, .regs = { REG_VEC1, REG_VEC2 } },  /* v1_v2 */
    [RISCV_REG_V2_V3] = { .reg_id = REG_VEC2, .n_regs = 2, .regs = { REG_VEC2, REG_VEC3 } },  /* v2_v3 */
    [RISCV_REG_V3_V4] = { .reg_id = REG_VEC3, .n_regs = 2, .regs = { REG_VEC3, REG_VEC4 } },  /* v3_v4 */
    [RISCV_REG_V4_V5] = { .reg_id = REG_VEC4, .n_regs = 2, .regs = { REG_VEC4, REG_VEC5 } },  /* v4_v5 */
    [RISCV_REG_V5_V6] = { .reg_id = REG_VEC5, .n_regs = 2, .regs = { REG_VEC5, REG_VEC6 } },  /* v5_v6 */
    [RISCV_REG_V6_V7] = { .reg_id = REG_VEC6, .n_regs = 2, .regs = { REG_VEC6, REG_VEC7 } },  /* v6_v7 */
    [RISCV_REG_V7_V8] = { .reg_id = REG_VEC7, .n_regs = 2, .regs = { REG_VEC7, REG_VEC8 } },  /* v7_v8 */
    [RISCV_REG_V8_V9] = { .reg_id = REG_VEC8, .n_regs = 2, .regs = { REG_VEC8, REG_VEC9 } },  /* v8_v9 */
    [RISCV_REG_V9_V10] = { .reg_id = REG_VEC9, .n_regs = 2, .regs = { REG_VEC9, REG_VEC10 } },  /* v9_v10 */
    [RISCV_REG_V10_V11] = { .reg_id = REG_VEC10, .n_regs = 2, .regs = { REG_VEC10, REG_VEC11 } },  /* v10_v11 */
    [RISCV_REG_V11_V12] = { .reg_id = REG_VEC11, .n_regs = 2, .regs = { REG_VEC11, REG_VEC12 } },  /* v11_v12 */
    [RISCV_REG_V12_V13] = { .reg_id = REG_VEC12, .n_regs = 2, .regs = { REG_VEC12, REG_VEC13 } },  /* v12_v13 */
    [RISCV_REG_V13_V14] = { .reg_id = REG_VEC13, .n_regs = 2, .regs = { REG_VEC13, REG_VEC14 } },  /* v13_v14 */
    [RISCV_REG_V14_V15] = { .reg_id = REG_VEC14, .n_regs = 2, .regs = { REG_VEC14, REG_VEC15 } },  /* v14_v15 */
    [RISCV_REG_V15_V16] = { .reg_id = REG_VEC15, .n_regs = 2, .regs = { REG_VEC15, REG_VEC16 } },  /* v15_v16 */
    [RISCV_REG_V16_V17] = { .reg_id = REG_VEC16, .n_regs = 2, .regs = { REG_VEC16, REG_VEC17 } },  /* v16_v17 */
    [RISCV_REG_V17_V18] = { .reg_id = REG_VEC17, .n_regs = 2, .regs = { REG_VEC17, REG_VEC18 } },  /* v17_v18 */
    [RISCV_REG_V18_V19] = { .reg_id = REG_VEC18, .n_regs = 2, .regs = { REG_VEC18, REG_VEC19 } },  /* v18_v19 */
    [RISCV_REG_V19_V20] = { .reg_id = REG_VEC19, .n_regs = 2, .regs = { REG_VEC19, REG_VEC20 } },  /* v19_v20 */
    [RISCV_REG_V20_V21] = { .reg_id = REG_VEC20, .n_regs = 2, .regs = { REG_VEC20, REG_VEC21 } },  /* v20_v21 */
    [RISCV_REG_V21_V22] = { .reg_id = REG_VEC21, .n_regs = 2, .regs = { REG_VEC21, REG_VEC22 } },  /* v21_v22 */
    [RISCV_REG_V22_V23] = { .reg_id = REG_VEC22, .n_regs = 2, .regs = { REG_VEC22, REG_VEC23 } },  /* v22_v23 */
    [RISCV_REG_V23_V24] = { .reg_id = REG_VEC23, .n_regs = 2, .regs = { REG_VEC23, REG_VEC24 } },  /* v23_v24 */
    [RISCV_REG_V24_V25] = { .reg_id = REG_VEC24, .n_regs = 2, .regs = { REG_VEC24, REG_VEC25 } },  /* v24_v25 */
    [RISCV_REG_V25_V26] = { .reg_id = REG_VEC25, .n_regs = 2, .regs = { REG_VEC25, REG_VEC26 } },  /* v25_v26 */
    [RISCV_REG_V26_V27] = { .reg_id = REG_VEC26, .n_regs = 2, .regs = { REG_VEC26, REG_VEC27 } },  /* v26_v27 */
    [RISCV_REG_V27_V28] = { .reg_id = REG_VEC27, .n_regs = 2, .regs = { REG_VEC27, REG_VEC28 } },  /* v27_v28 */
    [RISCV_REG_V28_V29] = { .reg_id = REG_VEC28, .n_regs = 2, .regs = { REG_VEC28, REG_VEC29 } },  /* v28_v29 */
    [RISCV_REG_V29_V30] = { .reg_id = REG_VEC29, .n_regs = 2, .regs = { REG_VEC29, REG_VEC30 } },  /* v29_v30 */
    [RISCV_REG_V30_V31] = { .reg_id = REG_VEC30, .n_regs = 2, .regs = { REG_VEC30, REG_VEC31 } },  /* v30_v31 */
    [RISCV_REG_V0_V1] = { .reg_id = REG_VEC0, .n_regs = 2, .regs = { REG_VEC0, REG_VEC1 } },  /* v0_v1 */
    [RISCV_REG_V2M2_V4M2] = { .reg_id = REG_VEC2, .n_regs = 4, .regs = { REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5 } },  /* v2m2_v4m2 */
    [RISCV_REG_V4M2_V6M2] = { .reg_id = REG_VEC4, .n_regs = 4, .regs = { REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v4m2_v6m2 */
    [RISCV_REG_V6M2_V8M2] = { .reg_id = REG_VEC6, .n_regs = 4, .regs = { REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9 } },  /* v6m2_v8m2 */
    [RISCV_REG_V8M2_V10M2] = { .reg_id = REG_VEC8, .n_regs = 4, .regs = { REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11 } },  /* v8m2_v10m2 */
    [RISCV_REG_V10M2_V12M2] = { .reg_id = REG_VEC10, .n_regs = 4, .regs = { REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13 } },  /* v10m2_v12m2 */
    [RISCV_REG_V12M2_V14M2] = { .reg_id = REG_VEC12, .n_regs = 4, .regs = { REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v12m2_v14m2 */
    [RISCV_REG_V14M2_V16M2] = { .reg_id = REG_VEC14, .n_regs = 4, .regs = { REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17 } },  /* v14m2_v16m2 */
    [RISCV_REG_V16M2_V18M2] = { .reg_id = REG_VEC16, .n_regs = 4, .regs = { REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19 } },  /* v16m2_v18m2 */
    [RISCV_REG_V18M2_V20M2] = { .reg_id = REG_VEC18, .n_regs = 4, .regs = { REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21 } },  /* v18m2_v20m2 */
    [RISCV_REG_V20M2_V22M2] = { .reg_id = REG_VEC20, .n_regs = 4, .regs = { REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v20m2_v22m2 */
    [RISCV_REG_V22M2_V24M2] = { .reg_id = REG_VEC22, .n_regs = 4, .regs = { REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25 } },  /* v22m2_v24m2 */
    [RISCV_REG_V24M2_V26M2] = { .reg_id = REG_VEC24, .n_regs = 4, .regs = { REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27 } },  /* v24m2_v26m2 */
    [RISCV_REG_V26M2_V28M2] = { .reg_id = REG_VEC26, .n_regs = 4, .regs = { REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29 } },  /* v26m2_v28m2 */
    [RISCV_REG_V28M2_V30M2] = { .reg_id = REG_VEC28, .n_regs = 4, .regs = { REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v28m2_v30m2 */
    [RISCV_REG_V0M2_V2M2] = { .reg_id = REG_VEC0, .n_regs = 4, .regs = { REG_VEC0, REG_VEC1, REG_VEC2, REG_VEC3 } },  /* v0m2_v2m2 */
    [RISCV_REG_V4M4_V8M4] = { .reg_id = REG_VEC4, .n_regs = 8, .regs = { REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11 } },  /* v4m4_v8m4 */
    [RISCV_REG_V8M4_V12M4] = { .reg_id = REG_VEC8, .n_regs = 8, .regs = { REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v8m4_v12m4 */
    [RISCV_REG_V12M4_V16M4] = { .reg_id = REG_VEC12, .n_regs = 8, .regs = { REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19 } },  /* v12m4_v16m4 */
    [RISCV_REG_V16M4_V20M4] = { .reg_id = REG_VEC16, .n_regs = 8, .regs = { REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v16m4_v20m4 */
    [RISCV_REG_V20M4_V24M4] = { .reg_id = REG_VEC20, .n_regs = 8, .regs = { REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27 } },  /* v20m4_v24m4 */
    [RISCV_REG_V24M4_V28M4] = { .reg_id = REG_VEC24, .n_regs = 8, .regs = { REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v24m4_v28m4 */
    [RISCV_REG_V0M4_V4M4] = { .reg_id = REG_VEC0, .n_regs = 8, .regs = { REG_VEC0, REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v0m4_v4m4 */
    [RISCV_REG_V1_V2_V3] = { .reg_id = REG_VEC1, .n_regs = 3, .regs = { REG_VEC1, REG_VEC2, REG_VEC3 } },  /* v1_v2_v3 */
    [RISCV_REG_V2_V3_V4] = { .reg_id = REG_VEC2, .n_regs = 3, .regs = { REG_VEC2, REG_VEC3, REG_VEC4 } },  /* v2_v3_v4 */
    [RISCV_REG_V3_V4_V5] = { .reg_id = REG_VEC3, .n_regs = 3, .regs = { REG_VEC3, REG_VEC4, REG_VEC5 } },  /* v3_v4_v5 */
    [RISCV_REG_V4_V5_V6] = { .reg_id = REG_VEC4, .n_regs = 3, .regs = { REG_VEC4, REG_VEC5, REG_VEC6 } },  /* v4_v5_v6 */
    [RISCV_REG_V5_V6_V7] = { .reg_id = REG_VEC5, .n_regs = 3, .regs = { REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v5_v6_v7 */
    [RISCV_REG_V6_V7_V8] = { .reg_id = REG_VEC6, .n_regs = 3, .regs = { REG_VEC6, REG_VEC7, REG_VEC8 } },  /* v6_v7_v8 */
    [RISCV_REG_V7_V8_V9] = { .reg_id = REG_VEC7, .n_regs = 3, .regs = { REG_VEC7, REG_VEC8, REG_VEC9 } },  /* v7_v8_v9 */
    [RISCV_REG_V8_V9_V10] = { .reg_id = REG_VEC8, .n_regs = 3, .regs = { REG_VEC8, REG_VEC9, REG_VEC10 } },  /* v8_v9_v10 */
    [RISCV_REG_V9_V10_V11] = { .reg_id = REG_VEC9, .n_regs = 3, .regs = { REG_VEC9, REG_VEC10, REG_VEC11 } },  /* v9_v10_v11 */
    [RISCV_REG_V10_V11_V12] = { .reg_id = REG_VEC10, .n_regs = 3, .regs = { REG_VEC10, REG_VEC11, REG_VEC12 } },  /* v10_v11_v12 */
    [RISCV_REG_V11_V12_V13] = { .reg_id = REG_VEC11, .n_regs = 3, .regs = { REG_VEC11, REG_VEC12, REG_VEC13 } },  /* v11_v12_v13 */
    [RISCV_REG_V12_V13_V14] = { .reg_id = REG_VEC12, .n_regs = 3, .regs = { REG_VEC12, REG_VEC13, REG_VEC14 } },  /* v12_v13_v14 */
    [RISCV_REG_V13_V14_V15] = { .reg_id = REG_VEC13, .n_regs = 3, .regs = { REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v13_v14_v15 */
    [RISCV_REG_V14_V15_V16] = { .reg_id = REG_VEC14, .n_regs = 3, .regs = { REG_VEC14, REG_VEC15, REG_VEC16 } },  /* v14_v15_v16 */
    [RISCV_REG_V15_V16_V17] = { .reg_id = REG_VEC15, .n_regs = 3, .regs = { REG_VEC15, REG_VEC16, REG_VEC17 } },  /* v15_v16_v17 */
    [RISCV_REG_V16_V17_V18] = { .reg_id = REG_VEC16, .n_regs = 3, .regs = { REG_VEC16, REG_VEC17, REG_VEC18 } },  /* v16_v17_v18 */
    [RISCV_REG_V17_V18_V19] = { .reg_id = REG_VEC17, .n_regs = 3, .regs = { REG_VEC17, REG_VEC18, REG_VEC19 } },  /* v17_v18_v19 */
    [RISCV_REG_V18_V19_V20] = { .reg_id = REG_VEC18, .n_regs = 3, .regs = { REG_VEC18, REG_VEC19, REG_VEC20 } },  /* v18_v19_v20 */
    [RISCV_REG_V19_V20_V21] = { .reg_id = REG_VEC19, .n_regs = 3, .regs = { REG_VEC19, REG_VEC20, REG_VEC21 } },  /* v19_v20_v21 */
    [RISCV_REG_V20_V21_V22] = { .reg_id = REG_VEC20, .n_regs = 3, .regs = { REG_VEC20, REG_VEC21, REG_VEC22 } },  /* v20_v21_v22 */
    [RISCV_REG_V21_V22_V23] = { .reg_id = REG_VEC21, .n_regs = 3, .regs = { REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v21_v22_v23 */
    [RISCV_REG_V22_V23_V24] = { .reg_id = REG_VEC22, .n_regs = 3, .regs = { REG_VEC22, REG_VEC23, REG_VEC24 } },  /* v22_v23_v24 */
    [RISCV_REG_V23_V24_V25] = { .reg_id = REG_VEC23, .n_regs = 3, .regs = { REG_VEC23, REG_VEC24, REG_VEC25 } },  /* v23_v24_v25 */
    [RISCV_REG_V24_V25_V26] = { .reg_id = REG_VEC24, .n_regs = 3, .regs = { REG_VEC24, REG_VEC25, REG_VEC26 } },  /* v24_v25_v26 */
    [RISCV_REG_V25_V26_V27] = { .reg_id = REG_VEC25, .n_regs = 3, .regs = { REG_VEC25, REG_VEC26, REG_VEC27 } },  /* v25_v26_v27 */
    [RISCV_REG_V26_V27_V28] = { .reg_id = REG_VEC26, .n_regs = 3, .regs = { REG_VEC26, REG_VEC27, REG_VEC28 } },  /* v26_v27_v28 */
    [RISCV_REG_V27_V28_V29] = { .reg_id = REG_VEC27, .n_regs = 3, .regs = { REG_VEC27, REG_VEC28, REG_VEC29 } },  /* v27_v28_v29 */
    [RISCV_REG_V28_V29_V30] = { .reg_id = REG_VEC28, .n_regs = 3, .regs = { REG_VEC28, REG_VEC29, REG_VEC30 } },  /* v28_v29_v30 */
    [RISCV_REG_V29_V30_V31] = { .reg_id = REG_VEC29, .n_regs = 3, .regs = { REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v29_v30_v31 */
    [RISCV_REG_V0_V1_V2] = { .reg_id = REG_VEC0, .n_regs = 3, .regs = { REG_VEC0, REG_VEC1, REG_VEC2 } },  /* v0_v1_v2 */
    [RISCV_REG_V2M2_V4M2_V6M2] = { .reg_id = REG_VEC2, .n_regs = 6, .regs = { REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v2m2_v4m2_v6m2 */
    [RISCV_REG_V4M2_V6M2_V8M2] = { .reg_id = REG_VEC4, .n_regs = 6, .regs = { REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9 } },  /* v4m2_v6m2_v8m2 */
    [RISCV_REG_V6M2_V8M2_V10M2] = { .reg_id = REG_VEC6, .n_regs = 6, .regs = { REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11 } },  /* v6m2_v8m2_v10m2 */
    [RISCV_REG_V8M2_V10M2_V12M2] = { .reg_id = REG_VEC8, .n_regs = 6, .regs = { REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13 } },  /* v8m2_v10m2_v12m2 */
    [RISCV_REG_V10M2_V12M2_V14M2] = { .reg_id = REG_VEC10, .n_regs = 6, .regs = { REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v10m2_v12m2_v14m2 */
    [RISCV_REG_V12M2_V14M2_V16M2] = { .reg_id = REG_VEC12, .n_regs = 6, .regs = { REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17 } },  /* v12m2_v14m2_v16m2 */
    [RISCV_REG_V14M2_V16M2_V18M2] = { .reg_id = REG_VEC14, .n_regs = 6, .regs = { REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19 } },  /* v14m2_v16m2_v18m2 */
    [RISCV_REG_V16M2_V18M2_V20M2] = { .reg_id = REG_VEC16, .n_regs = 6, .regs = { REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21 } },  /* v16m2_v18m2_v20m2 */
    [RISCV_REG_V18M2_V20M2_V22M2] = { .reg_id = REG_VEC18, .n_regs = 6, .regs = { REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v18m2_v20m2_v22m2 */
    [RISCV_REG_V20M2_V22M2_V24M2] = { .reg_id = REG_VEC20, .n_regs = 6, .regs = { REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25 } },  /* v20m2_v22m2_v24m2 */
    [RISCV_REG_V22M2_V24M2_V26M2] = { .reg_id = REG_VEC22, .n_regs = 6, .regs = { REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27 } },  /* v22m2_v24m2_v26m2 */
    [RISCV_REG_V24M2_V26M2_V28M2] = { .reg_id = REG_VEC24, .n_regs = 6, .regs = { REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29 } },  /* v24m2_v26m2_v28m2 */
    [RISCV_REG_V26M2_V28M2_V30M2] = { .reg_id = REG_VEC26, .n_regs = 6, .regs = { REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v26m2_v28m2_v30m2 */
    [RISCV_REG_V0M2_V2M2_V4M2] = { .reg_id = REG_VEC0, .n_regs = 6, .regs = { REG_VEC0, REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5 } },  /* v0m2_v2m2_v4m2 */
    [RISCV_REG_V1_V2_V3_V4] = { .reg_id = REG_VEC1, .n_regs = 4, .regs = { REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4 } },  /* v1_v2_v3_v4 */
    [RISCV_REG_V2_V3_V4_V5] = { .reg_id = REG_VEC2, .n_regs = 4, .regs = { REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5 } },  /* v2_v3_v4_v5 */
    [RISCV_REG_V3_V4_V5_V6] = { .reg_id = REG_VEC3, .n_regs = 4, .regs = { REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6 } },  /* v3_v4_v5_v6 */
    [RISCV_REG_V4_V5_V6_V7] = { .reg_id = REG_VEC4, .n_regs = 4, .regs = { REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v4_v5_v6_v7 */
    [RISCV_REG_V5_V6_V7_V8] = { .reg_id = REG_VEC5, .n_regs = 4, .regs = { REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8 } },  /* v5_v6_v7_v8 */
    [RISCV_REG_V6_V7_V8_V9] = { .reg_id = REG_VEC6, .n_regs = 4, .regs = { REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9 } },  /* v6_v7_v8_v9 */
    [RISCV_REG_V7_V8_V9_V10] = { .reg_id = REG_VEC7, .n_regs = 4, .regs = { REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10 } },  /* v7_v8_v9_v10 */
    [RISCV_REG_V8_V9_V10_V11] = { .reg_id = REG_VEC8, .n_regs = 4, .regs = { REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11 } },  /* v8_v9_v10_v11 */
    [RISCV_REG_V9_V10_V11_V12] = { .reg_id = REG_VEC9, .n_regs = 4, .regs = { REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12 } },  /* v9_v10_v11_v12 */
    [RISCV_REG_V10_V11_V12_V13] = { .reg_id = REG_VEC10, .n_regs = 4, .regs = { REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13 } },  /* v10_v11_v12_v13 */
    [RISCV_REG_V11_V12_V13_V14] = { .reg_id = REG_VEC11, .n_regs = 4, .regs = { REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14 } },  /* v11_v12_v13_v14 */
    [RISCV_REG_V12_V13_V14_V15] = { .reg_id = REG_VEC12, .n_regs = 4, .regs = { REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v12_v13_v14_v15 */
    [RISCV_REG_V13_V14_V15_V16] = { .reg_id = REG_VEC13, .n_regs = 4, .regs = { REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16 } },  /* v13_v14_v15_v16 */
    [RISCV_REG_V14_V15_V16_V17] = { .reg_id = REG_VEC14, .n_regs = 4, .regs = { REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17 } },  /* v14_v15_v16_v17 */
    [RISCV_REG_V15_V16_V17_V18] = { .reg_id = REG_VEC15, .n_regs = 4, .regs = { REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18 } },  /* v15_v16_v17_v18 */
    [RISCV_REG_V16_V17_V18_V19] = { .reg_id = REG_VEC16, .n_regs = 4, .regs = { REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19 } },  /* v16_v17_v18_v19 */
    [RISCV_REG_V17_V18_V19_V20] = { .reg_id = REG_VEC17, .n_regs = 4, .regs = { REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20 } },  /* v17_v18_v19_v20 */
    [RISCV_REG_V18_V19_V20_V21] = { .reg_id = REG_VEC18, .n_regs = 4, .regs = { REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21 } },  /* v18_v19_v20_v21 */
    [RISCV_REG_V19_V20_V21_V22] = { .reg_id = REG_VEC19, .n_regs = 4, .regs = { REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22 } },  /* v19_v20_v21_v22 */
    [RISCV_REG_V20_V21_V22_V23] = { .reg_id = REG_VEC20, .n_regs = 4, .regs = { REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v20_v21_v22_v23 */
    [RISCV_REG_V21_V22_V23_V24] = { .reg_id = REG_VEC21, .n_regs = 4, .regs = { REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24 } },  /* v21_v22_v23_v24 */
    [RISCV_REG_V22_V23_V24_V25] = { .reg_id = REG_VEC22, .n_regs = 4, .regs = { REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25 } },  /* v22_v23_v24_v25 */
    [RISCV_REG_V23_V24_V25_V26] = { .reg_id = REG_VEC23, .n_regs = 4, .regs = { REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26 } },  /* v23_v24_v25_v26 */
    [RISCV_REG_V24_V25_V26_V27] = { .reg_id = REG_VEC24, .n_regs = 4, .regs = { REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27 } },  /* v24_v25_v26_v27 */
    [RISCV_REG_V25_V26_V27_V28] = { .reg_id = REG_VEC25, .n_regs = 4, .regs = { REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28 } },  /* v25_v26_v27_v28 */
    [RISCV_REG_V26_V27_V28_V29] = { .reg_id = REG_VEC26, .n_regs = 4, .regs = { REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29 } },  /* v26_v27_v28_v29 */
    [RISCV_REG_V27_V28_V29_V30] = { .reg_id = REG_VEC27, .n_regs = 4, .regs = { REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30 } },  /* v27_v28_v29_v30 */
    [RISCV_REG_V28_V29_V30_V31] = { .reg_id = REG_VEC28, .n_regs = 4, .regs = { REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v28_v29_v30_v31 */
    [RISCV_REG_V0_V1_V2_V3] = { .reg_id = REG_VEC0, .n_regs = 4, .regs = { REG_VEC0, REG_VEC1, REG_VEC2, REG_VEC3 } },  /* v0_v1_v2_v3 */
    [RISCV_REG_V2M2_V4M2_V6M2_V8M2] = { .reg_id = REG_VEC2, .n_regs = 8, .regs = { REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9 } },  /* v2m2_v4m2_v6m2_v8m2 */
    [RISCV_REG_V4M2_V6M2_V8M2_V10M2] = { .reg_id = REG_VEC4, .n_regs = 8, .regs = { REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11 } },  /* v4m2_v6m2_v8m2_v10m2 */
    [RISCV_REG_V6M2_V8M2_V10M2_V12M2] = { .reg_id = REG_VEC6, .n_regs = 8, .regs = { REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13 } },  /* v6m2_v8m2_v10m2_v12m2 */
    [RISCV_REG_V8M2_V10M2_V12M2_V14M2] = { .reg_id = REG_VEC8, .n_regs = 8, .regs = { REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v8m2_v10m2_v12m2_v14m2 */
    [RISCV_REG_V10M2_V12M2_V14M2_V16M2] = { .reg_id = REG_VEC10, .n_regs = 8, .regs = { REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17 } },  /* v10m2_v12m2_v14m2_v16m2 */
    [RISCV_REG_V12M2_V14M2_V16M2_V18M2] = { .reg_id = REG_VEC12, .n_regs = 8, .regs = { REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19 } },  /* v12m2_v14m2_v16m2_v18m2 */
    [RISCV_REG_V14M2_V16M2_V18M2_V20M2] = { .reg_id = REG_VEC14, .n_regs = 8, .regs = { REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21 } },  /* v14m2_v16m2_v18m2_v20m2 */
    [RISCV_REG_V16M2_V18M2_V20M2_V22M2] = { .reg_id = REG_VEC16, .n_regs = 8, .regs = { REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v16m2_v18m2_v20m2_v22m2 */
    [RISCV_REG_V18M2_V20M2_V22M2_V24M2] = { .reg_id = REG_VEC18, .n_regs = 8, .regs = { REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25 } },  /* v18m2_v20m2_v22m2_v24m2 */
    [RISCV_REG_V20M2_V22M2_V24M2_V26M2] = { .reg_id = REG_VEC20, .n_regs = 8, .regs = { REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27 } },  /* v20m2_v22m2_v24m2_v26m2 */
    [RISCV_REG_V22M2_V24M2_V26M2_V28M2] = { .reg_id = REG_VEC22, .n_regs = 8, .regs = { REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29 } },  /* v22m2_v24m2_v26m2_v28m2 */
    [RISCV_REG_V24M2_V26M2_V28M2_V30M2] = { .reg_id = REG_VEC24, .n_regs = 8, .regs = { REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v24m2_v26m2_v28m2_v30m2 */
    [RISCV_REG_V0M2_V2M2_V4M2_V6M2] = { .reg_id = REG_VEC0, .n_regs = 8, .regs = { REG_VEC0, REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v0m2_v2m2_v4m2_v6m2 */
    [RISCV_REG_V1_V2_V3_V4_V5] = { .reg_id = REG_VEC1, .n_regs = 5, .regs = { REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5 } },  /* v1_v2_v3_v4_v5 */
    [RISCV_REG_V2_V3_V4_V5_V6] = { .reg_id = REG_VEC2, .n_regs = 5, .regs = { REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6 } },  /* v2_v3_v4_v5_v6 */
    [RISCV_REG_V3_V4_V5_V6_V7] = { .reg_id = REG_VEC3, .n_regs = 5, .regs = { REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v3_v4_v5_v6_v7 */
    [RISCV_REG_V4_V5_V6_V7_V8] = { .reg_id = REG_VEC4, .n_regs = 5, .regs = { REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8 } },  /* v4_v5_v6_v7_v8 */
    [RISCV_REG_V5_V6_V7_V8_V9] = { .reg_id = REG_VEC5, .n_regs = 5, .regs = { REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9 } },  /* v5_v6_v7_v8_v9 */
    [RISCV_REG_V6_V7_V8_V9_V10] = { .reg_id = REG_VEC6, .n_regs = 5, .regs = { REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10 } },  /* v6_v7_v8_v9_v10 */
    [RISCV_REG_V7_V8_V9_V10_V11] = { .reg_id = REG_VEC7, .n_regs = 5, .regs = { REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11 } },  /* v7_v8_v9_v10_v11 */
    [RISCV_REG_V8_V9_V10_V11_V12] = { .reg_id = REG_VEC8, .n_regs = 5, .regs = { REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12 } },  /* v8_v9_v10_v11_v12 */
    [RISCV_REG_V9_V10_V11_V12_V13] = { .reg_id = REG_VEC9, .n_regs = 5, .regs = { REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13 } },  /* v9_v10_v11_v12_v13 */
    [RISCV_REG_V10_V11_V12_V13_V14] = { .reg_id = REG_VEC10, .n_regs = 5, .regs = { REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14 } },  /* v10_v11_v12_v13_v14 */
    [RISCV_REG_V11_V12_V13_V14_V15] = { .reg_id = REG_VEC11, .n_regs = 5, .regs = { REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v11_v12_v13_v14_v15 */
    [RISCV_REG_V12_V13_V14_V15_V16] = { .reg_id = REG_VEC12, .n_regs = 5, .regs = { REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16 } },  /* v12_v13_v14_v15_v16 */
    [RISCV_REG_V13_V14_V15_V16_V17] = { .reg_id = REG_VEC13, .n_regs = 5, .regs = { REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17 } },  /* v13_v14_v15_v16_v17 */
    [RISCV_REG_V14_V15_V16_V17_V18] = { .reg_id = REG_VEC14, .n_regs = 5, .regs = { REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18 } },  /* v14_v15_v16_v17_v18 */
    [RISCV_REG_V15_V16_V17_V18_V19] = { .reg_id = REG_VEC15, .n_regs = 5, .regs = { REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19 } },  /* v15_v16_v17_v18_v19 */
    [RISCV_REG_V16_V17_V18_V19_V20] = { .reg_id = REG_VEC16, .n_regs = 5, .regs = { REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20 } },  /* v16_v17_v18_v19_v20 */
    [RISCV_REG_V17_V18_V19_V20_V21] = { .reg_id = REG_VEC17, .n_regs = 5, .regs = { REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21 } },  /* v17_v18_v19_v20_v21 */
    [RISCV_REG_V18_V19_V20_V21_V22] = { .reg_id = REG_VEC18, .n_regs = 5, .regs = { REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22 } },  /* v18_v19_v20_v21_v22 */
    [RISCV_REG_V19_V20_V21_V22_V23] = { .reg_id = REG_VEC19, .n_regs = 5, .regs = { REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v19_v20_v21_v22_v23 */
    [RISCV_REG_V20_V21_V22_V23_V24] = { .reg_id = REG_VEC20, .n_regs = 5, .regs = { REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24 } },  /* v20_v21_v22_v23_v24 */
    [RISCV_REG_V21_V22_V23_V24_V25] = { .reg_id = REG_VEC21, .n_regs = 5, .regs = { REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25 } },  /* v21_v22_v23_v24_v25 */
    [RISCV_REG_V22_V23_V24_V25_V26] = { .reg_id = REG_VEC22, .n_regs = 5, .regs = { REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26 } },  /* v22_v23_v24_v25_v26 */
    [RISCV_REG_V23_V24_V25_V26_V27] = { .reg_id = REG_VEC23, .n_regs = 5, .regs = { REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27 } },  /* v23_v24_v25_v26_v27 */
    [RISCV_REG_V24_V25_V26_V27_V28] = { .reg_id = REG_VEC24, .n_regs = 5, .regs = { REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28 } },  /* v24_v25_v26_v27_v28 */
    [RISCV_REG_V25_V26_V27_V28_V29] = { .reg_id = REG_VEC25, .n_regs = 5, .regs = { REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29 } },  /* v25_v26_v27_v28_v29 */
    [RISCV_REG_V26_V27_V28_V29_V30] = { .reg_id = REG_VEC26, .n_regs = 5, .regs = { REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30 } },  /* v26_v27_v28_v29_v30 */
    [RISCV_REG_V27_V28_V29_V30_V31] = { .reg_id = REG_VEC27, .n_regs = 5, .regs = { REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v27_v28_v29_v30_v31 */
    [RISCV_REG_V0_V1_V2_V3_V4] = { .reg_id = REG_VEC0, .n_regs = 5, .regs = { REG_VEC0, REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4 } },  /* v0_v1_v2_v3_v4 */
    [RISCV_REG_V1_V2_V3_V4_V5_V6] = { .reg_id = REG_VEC1, .n_regs = 6, .regs = { REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6 } },  /* v1_v2_v3_v4_v5_v6 */
    [RISCV_REG_V2_V3_V4_V5_V6_V7] = { .reg_id = REG_VEC2, .n_regs = 6, .regs = { REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v2_v3_v4_v5_v6_v7 */
    [RISCV_REG_V3_V4_V5_V6_V7_V8] = { .reg_id = REG_VEC3, .n_regs = 6, .regs = { REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8 } },  /* v3_v4_v5_v6_v7_v8 */
    [RISCV_REG_V4_V5_V6_V7_V8_V9] = { .reg_id = REG_VEC4, .n_regs = 6, .regs = { REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9 } },  /* v4_v5_v6_v7_v8_v9 */
    [RISCV_REG_V5_V6_V7_V8_V9_V10] = { .reg_id = REG_VEC5, .n_regs = 6, .regs = { REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10 } },  /* v5_v6_v7_v8_v9_v10 */
    [RISCV_REG_V6_V7_V8_V9_V10_V11] = { .reg_id = REG_VEC6, .n_regs = 6, .regs = { REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11 } },  /* v6_v7_v8_v9_v10_v11 */
    [RISCV_REG_V7_V8_V9_V10_V11_V12] = { .reg_id = REG_VEC7, .n_regs = 6, .regs = { REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12 } },  /* v7_v8_v9_v10_v11_v12 */
    [RISCV_REG_V8_V9_V10_V11_V12_V13] = { .reg_id = REG_VEC8, .n_regs = 6, .regs = { REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13 } },  /* v8_v9_v10_v11_v12_v13 */
    [RISCV_REG_V9_V10_V11_V12_V13_V14] = { .reg_id = REG_VEC9, .n_regs = 6, .regs = { REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14 } },  /* v9_v10_v11_v12_v13_v14 */
    [RISCV_REG_V10_V11_V12_V13_V14_V15] = { .reg_id = REG_VEC10, .n_regs = 6, .regs = { REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v10_v11_v12_v13_v14_v15 */
    [RISCV_REG_V11_V12_V13_V14_V15_V16] = { .reg_id = REG_VEC11, .n_regs = 6, .regs = { REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16 } },  /* v11_v12_v13_v14_v15_v16 */
    [RISCV_REG_V12_V13_V14_V15_V16_V17] = { .reg_id = REG_VEC12, .n_regs = 6, .regs = { REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17 } },  /* v12_v13_v14_v15_v16_v17 */
    [RISCV_REG_V13_V14_V15_V16_V17_V18] = { .reg_id = REG_VEC13, .n_regs = 6, .regs = { REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18 } },  /* v13_v14_v15_v16_v17_v18 */
    [RISCV_REG_V14_V15_V16_V17_V18_V19] = { .reg_id = REG_VEC14, .n_regs = 6, .regs = { REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19 } },  /* v14_v15_v16_v17_v18_v19 */
    [RISCV_REG_V15_V16_V17_V18_V19_V20] = { .reg_id = REG_VEC15, .n_regs = 6, .regs = { REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20 } },  /* v15_v16_v17_v18_v19_v20 */
    [RISCV_REG_V16_V17_V18_V19_V20_V21] = { .reg_id = REG_VEC16, .n_regs = 6, .regs = { REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21 } },  /* v16_v17_v18_v19_v20_v21 */
    [RISCV_REG_V17_V18_V19_V20_V21_V22] = { .reg_id = REG_VEC17, .n_regs = 6, .regs = { REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22 } },  /* v17_v18_v19_v20_v21_v22 */
    [RISCV_REG_V18_V19_V20_V21_V22_V23] = { .reg_id = REG_VEC18, .n_regs = 6, .regs = { REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v18_v19_v20_v21_v22_v23 */
    [RISCV_REG_V19_V20_V21_V22_V23_V24] = { .reg_id = REG_VEC19, .n_regs = 6, .regs = { REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24 } },  /* v19_v20_v21_v22_v23_v24 */
    [RISCV_REG_V20_V21_V22_V23_V24_V25] = { .reg_id = REG_VEC20, .n_regs = 6, .regs = { REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25 } },  /* v20_v21_v22_v23_v24_v25 */
    [RISCV_REG_V21_V22_V23_V24_V25_V26] = { .reg_id = REG_VEC21, .n_regs = 6, .regs = { REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26 } },  /* v21_v22_v23_v24_v25_v26 */
    [RISCV_REG_V22_V23_V24_V25_V26_V27] = { .reg_id = REG_VEC22, .n_regs = 6, .regs = { REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27 } },  /* v22_v23_v24_v25_v26_v27 */
    [RISCV_REG_V23_V24_V25_V26_V27_V28] = { .reg_id = REG_VEC23, .n_regs = 6, .regs = { REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28 } },  /* v23_v24_v25_v26_v27_v28 */
    [RISCV_REG_V24_V25_V26_V27_V28_V29] = { .reg_id = REG_VEC24, .n_regs = 6, .regs = { REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29 } },  /* v24_v25_v26_v27_v28_v29 */
    [RISCV_REG_V25_V26_V27_V28_V29_V30] = { .reg_id = REG_VEC25, .n_regs = 6, .regs = { REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30 } },  /* v25_v26_v27_v28_v29_v30 */
    [RISCV_REG_V26_V27_V28_V29_V30_V31] = { .reg_id = REG_VEC26, .n_regs = 6, .regs = { REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v26_v27_v28_v29_v30_v31 */
    [RISCV_REG_V0_V1_V2_V3_V4_V5] = { .reg_id = REG_VEC0, .n_regs = 6, .regs = { REG_VEC0, REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5 } },  /* v0_v1_v2_v3_v4_v5 */
    [RISCV_REG_V1_V2_V3_V4_V5_V6_V7] = { .reg_id = REG_VEC1, .n_regs = 7, .regs = { REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v1_v2_v3_v4_v5_v6_v7 */
    [RISCV_REG_V2_V3_V4_V5_V6_V7_V8] = { .reg_id = REG_VEC2, .n_regs = 7, .regs = { REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8 } },  /* v2_v3_v4_v5_v6_v7_v8 */
    [RISCV_REG_V3_V4_V5_V6_V7_V8_V9] = { .reg_id = REG_VEC3, .n_regs = 7, .regs = { REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9 } },  /* v3_v4_v5_v6_v7_v8_v9 */
    [RISCV_REG_V4_V5_V6_V7_V8_V9_V10] = { .reg_id = REG_VEC4, .n_regs = 7, .regs = { REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10 } },  /* v4_v5_v6_v7_v8_v9_v10 */
    [RISCV_REG_V5_V6_V7_V8_V9_V10_V11] = { .reg_id = REG_VEC5, .n_regs = 7, .regs = { REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11 } },  /* v5_v6_v7_v8_v9_v10_v11 */
    [RISCV_REG_V6_V7_V8_V9_V10_V11_V12] = { .reg_id = REG_VEC6, .n_regs = 7, .regs = { REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12 } },  /* v6_v7_v8_v9_v10_v11_v12 */
    [RISCV_REG_V7_V8_V9_V10_V11_V12_V13] = { .reg_id = REG_VEC7, .n_regs = 7, .regs = { REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13 } },  /* v7_v8_v9_v10_v11_v12_v13 */
    [RISCV_REG_V8_V9_V10_V11_V12_V13_V14] = { .reg_id = REG_VEC8, .n_regs = 7, .regs = { REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14 } },  /* v8_v9_v10_v11_v12_v13_v14 */
    [RISCV_REG_V9_V10_V11_V12_V13_V14_V15] = { .reg_id = REG_VEC9, .n_regs = 7, .regs = { REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v9_v10_v11_v12_v13_v14_v15 */
    [RISCV_REG_V10_V11_V12_V13_V14_V15_V16] = { .reg_id = REG_VEC10, .n_regs = 7, .regs = { REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16 } },  /* v10_v11_v12_v13_v14_v15_v16 */
    [RISCV_REG_V11_V12_V13_V14_V15_V16_V17] = { .reg_id = REG_VEC11, .n_regs = 7, .regs = { REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17 } },  /* v11_v12_v13_v14_v15_v16_v17 */
    [RISCV_REG_V12_V13_V14_V15_V16_V17_V18] = { .reg_id = REG_VEC12, .n_regs = 7, .regs = { REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18 } },  /* v12_v13_v14_v15_v16_v17_v18 */
    [RISCV_REG_V13_V14_V15_V16_V17_V18_V19] = { .reg_id = REG_VEC13, .n_regs = 7, .regs = { REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19 } },  /* v13_v14_v15_v16_v17_v18_v19 */
    [RISCV_REG_V14_V15_V16_V17_V18_V19_V20] = { .reg_id = REG_VEC14, .n_regs = 7, .regs = { REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20 } },  /* v14_v15_v16_v17_v18_v19_v20 */
    [RISCV_REG_V15_V16_V17_V18_V19_V20_V21] = { .reg_id = REG_VEC15, .n_regs = 7, .regs = { REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21 } },  /* v15_v16_v17_v18_v19_v20_v21 */
    [RISCV_REG_V16_V17_V18_V19_V20_V21_V22] = { .reg_id = REG_VEC16, .n_regs = 7, .regs = { REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22 } },  /* v16_v17_v18_v19_v20_v21_v22 */
    [RISCV_REG_V17_V18_V19_V20_V21_V22_V23] = { .reg_id = REG_VEC17, .n_regs = 7, .regs = { REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v17_v18_v19_v20_v21_v22_v23 */
    [RISCV_REG_V18_V19_V20_V21_V22_V23_V24] = { .reg_id = REG_VEC18, .n_regs = 7, .regs = { REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24 } },  /* v18_v19_v20_v21_v22_v23_v24 */
    [RISCV_REG_V19_V20_V21_V22_V23_V24_V25] = { .reg_id = REG_VEC19, .n_regs = 7, .regs = { REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25 } },  /* v19_v20_v21_v22_v23_v24_v25 */
    [RISCV_REG_V20_V21_V22_V23_V24_V25_V26] = { .reg_id = REG_VEC20, .n_regs = 7, .regs = { REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26 } },  /* v20_v21_v22_v23_v24_v25_v26 */
    [RISCV_REG_V21_V22_V23_V24_V25_V26_V27] = { .reg_id = REG_VEC21, .n_regs = 7, .regs = { REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27 } },  /* v21_v22_v23_v24_v25_v26_v27 */
    [RISCV_REG_V22_V23_V24_V25_V26_V27_V28] = { .reg_id = REG_VEC22, .n_regs = 7, .regs = { REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28 } },  /* v22_v23_v24_v25_v26_v27_v28 */
    [RISCV_REG_V23_V24_V25_V26_V27_V28_V29] = { .reg_id = REG_VEC23, .n_regs = 7, .regs = { REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29 } },  /* v23_v24_v25_v26_v27_v28_v29 */
    [RISCV_REG_V24_V25_V26_V27_V28_V29_V30] = { .reg_id = REG_VEC24, .n_regs = 7, .regs = { REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30 } },  /* v24_v25_v26_v27_v28_v29_v30 */
    [RISCV_REG_V25_V26_V27_V28_V29_V30_V31] = { .reg_id = REG_VEC25, .n_regs = 7, .regs = { REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v25_v26_v27_v28_v29_v30_v31 */
    [RISCV_REG_V0_V1_V2_V3_V4_V5_V6] = { .reg_id = REG_VEC0, .n_regs = 7, .regs = { REG_VEC0, REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6 } },  /* v0_v1_v2_v3_v4_v5_v6 */
    [RISCV_REG_V1_V2_V3_V4_V5_V6_V7_V8] = { .reg_id = REG_VEC1, .n_regs = 8, .regs = { REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8 } },  /* v1_v2_v3_v4_v5_v6_v7_v8 */
    [RISCV_REG_V2_V3_V4_V5_V6_V7_V8_V9] = { .reg_id = REG_VEC2, .n_regs = 8, .regs = { REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9 } },  /* v2_v3_v4_v5_v6_v7_v8_v9 */
    [RISCV_REG_V3_V4_V5_V6_V7_V8_V9_V10] = { .reg_id = REG_VEC3, .n_regs = 8, .regs = { REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10 } },  /* v3_v4_v5_v6_v7_v8_v9_v10 */
    [RISCV_REG_V4_V5_V6_V7_V8_V9_V10_V11] = { .reg_id = REG_VEC4, .n_regs = 8, .regs = { REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11 } },  /* v4_v5_v6_v7_v8_v9_v10_v11 */
    [RISCV_REG_V5_V6_V7_V8_V9_V10_V11_V12] = { .reg_id = REG_VEC5, .n_regs = 8, .regs = { REG_VEC5, REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12 } },  /* v5_v6_v7_v8_v9_v10_v11_v12 */
    [RISCV_REG_V6_V7_V8_V9_V10_V11_V12_V13] = { .reg_id = REG_VEC6, .n_regs = 8, .regs = { REG_VEC6, REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13 } },  /* v6_v7_v8_v9_v10_v11_v12_v13 */
    [RISCV_REG_V7_V8_V9_V10_V11_V12_V13_V14] = { .reg_id = REG_VEC7, .n_regs = 8, .regs = { REG_VEC7, REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14 } },  /* v7_v8_v9_v10_v11_v12_v13_v14 */
    [RISCV_REG_V8_V9_V10_V11_V12_V13_V14_V15] = { .reg_id = REG_VEC8, .n_regs = 8, .regs = { REG_VEC8, REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15 } },  /* v8_v9_v10_v11_v12_v13_v14_v15 */
    [RISCV_REG_V9_V10_V11_V12_V13_V14_V15_V16] = { .reg_id = REG_VEC9, .n_regs = 8, .regs = { REG_VEC9, REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16 } },  /* v9_v10_v11_v12_v13_v14_v15_v16 */
    [RISCV_REG_V10_V11_V12_V13_V14_V15_V16_V17] = { .reg_id = REG_VEC10, .n_regs = 8, .regs = { REG_VEC10, REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17 } },  /* v10_v11_v12_v13_v14_v15_v16_v17 */
    [RISCV_REG_V11_V12_V13_V14_V15_V16_V17_V18] = { .reg_id = REG_VEC11, .n_regs = 8, .regs = { REG_VEC11, REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18 } },  /* v11_v12_v13_v14_v15_v16_v17_v18 */
    [RISCV_REG_V12_V13_V14_V15_V16_V17_V18_V19] = { .reg_id = REG_VEC12, .n_regs = 8, .regs = { REG_VEC12, REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19 } },  /* v12_v13_v14_v15_v16_v17_v18_v19 */
    [RISCV_REG_V13_V14_V15_V16_V17_V18_V19_V20] = { .reg_id = REG_VEC13, .n_regs = 8, .regs = { REG_VEC13, REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20 } },  /* v13_v14_v15_v16_v17_v18_v19_v20 */
    [RISCV_REG_V14_V15_V16_V17_V18_V19_V20_V21] = { .reg_id = REG_VEC14, .n_regs = 8, .regs = { REG_VEC14, REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21 } },  /* v14_v15_v16_v17_v18_v19_v20_v21 */
    [RISCV_REG_V15_V16_V17_V18_V19_V20_V21_V22] = { .reg_id = REG_VEC15, .n_regs = 8, .regs = { REG_VEC15, REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22 } },  /* v15_v16_v17_v18_v19_v20_v21_v22 */
    [RISCV_REG_V16_V17_V18_V19_V20_V21_V22_V23] = { .reg_id = REG_VEC16, .n_regs = 8, .regs = { REG_VEC16, REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23 } },  /* v16_v17_v18_v19_v20_v21_v22_v23 */
    [RISCV_REG_V17_V18_V19_V20_V21_V22_V23_V24] = { .reg_id = REG_VEC17, .n_regs = 8, .regs = { REG_VEC17, REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24 } },  /* v17_v18_v19_v20_v21_v22_v23_v24 */
    [RISCV_REG_V18_V19_V20_V21_V22_V23_V24_V25] = { .reg_id = REG_VEC18, .n_regs = 8, .regs = { REG_VEC18, REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25 } },  /* v18_v19_v20_v21_v22_v23_v24_v25 */
    [RISCV_REG_V19_V20_V21_V22_V23_V24_V25_V26] = { .reg_id = REG_VEC19, .n_regs = 8, .regs = { REG_VEC19, REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26 } },  /* v19_v20_v21_v22_v23_v24_v25_v26 */
    [RISCV_REG_V20_V21_V22_V23_V24_V25_V26_V27] = { .reg_id = REG_VEC20, .n_regs = 8, .regs = { REG_VEC20, REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27 } },  /* v20_v21_v22_v23_v24_v25_v26_v27 */
    [RISCV_REG_V21_V22_V23_V24_V25_V26_V27_V28] = { .reg_id = REG_VEC21, .n_regs = 8, .regs = { REG_VEC21, REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28 } },  /* v21_v22_v23_v24_v25_v26_v27_v28 */
    [RISCV_REG_V22_V23_V24_V25_V26_V27_V28_V29] = { .reg_id = REG_VEC22, .n_regs = 8, .regs = { REG_VEC22, REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29 } },  /* v22_v23_v24_v25_v26_v27_v28_v29 */
    [RISCV_REG_V23_V24_V25_V26_V27_V28_V29_V30] = { .reg_id = REG_VEC23, .n_regs = 8, .regs = { REG_VEC23, REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30 } },  /* v23_v24_v25_v26_v27_v28_v29_v30 */
    [RISCV_REG_V24_V25_V26_V27_V28_V29_V30_V31] = { .reg_id = REG_VEC24, .n_regs = 8, .regs = { REG_VEC24, REG_VEC25, REG_VEC26, REG_VEC27, REG_VEC28, REG_VEC29, REG_VEC30, REG_VEC31 } },  /* v24_v25_v26_v27_v28_v29_v30_v31 */
    [RISCV_REG_V0_V1_V2_V3_V4_V5_V6_V7] = { .reg_id = REG_VEC0, .n_regs = 8, .regs = { REG_VEC0, REG_VEC1, REG_VEC2, REG_VEC3, REG_VEC4, REG_VEC5, REG_VEC6, REG_VEC7 } },  /* v0_v1_v2_v3_v4_v5_v6_v7 */
};

static const InsnClassification riscv_insn_class[RISCV_INS_ENDING] = {
    /* Auto-generated by champsim_tracer_mnemonic_audit.py. */
    /* riscv: 1674/1675 classified, 0 unknown */
    [RISCV_INS_ADD]                       = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CALL]                      = { GEN_OP_BRANCH, BRANCH_DIRECT_JUMP,    MF_NONE },
    [RISCV_INS_FLD]                       = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLH]                       = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLW]                       = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSD]                       = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSH]                       = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSW]                       = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_JUMP]                      = { GEN_OP_BRANCH, BRANCH_DIRECT_JUMP,    MF_NONE },
    [RISCV_INS_LA]                        = { GEN_OP_LEA,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LA_TLSDESC]                = { GEN_OP_LEA,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LA_TLS_GD]                 = { GEN_OP_LEA,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LA_TLS_IE]                 = { GEN_OP_LEA,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LB]                        = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LBU]                       = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LD]                        = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LGA]                       = { GEN_OP_LEA,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LH]                        = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LHU]                       = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LI]                        = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LLA]                       = { GEN_OP_LEA,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LW]                        = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_LWU]                       = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SB]                        = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SD]                        = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SEXT_B]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SEXT_H]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SH]                        = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SW]                        = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TAIL]                      = { GEN_OP_BRANCH, BRANCH_DIRECT_JUMP,    MF_NONE },
    [RISCV_INS_JALR]                      = { GEN_OP_BRANCH, BRANCH_INDIRECT_JUMP,  MF_NONE },
    [RISCV_INS_VMSGEU_VI]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSGEU_VX]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSGE_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSGE_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLTU_VI]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLT_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ZEXT_H]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ZEXT_W]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ADDI]                      = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ADDIW]                     = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ADDW]                      = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ADD_UW]                    = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AES32DSI]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AES32DSMI]                 = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AES32ESI]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AES32ESMI]                 = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AES64DS]                   = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AES64DSM]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AES64ES]                   = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AES64ESM]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AES64IM]                   = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AES64KS1I]                 = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AES64KS2]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AMOADD_D]                  = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOADD_D_AQ]               = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOADD_D_AQRL]             = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOADD_D_RL]               = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOADD_W]                  = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOADD_W_AQ]               = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOADD_W_AQRL]             = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOADD_W_RL]               = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOAND_D]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOAND_D_AQ]               = { GEN_OP_AND,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOAND_D_AQRL]             = { GEN_OP_AND,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOAND_D_RL]               = { GEN_OP_AND,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOAND_W]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOAND_W_AQ]               = { GEN_OP_AND,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOAND_W_AQRL]             = { GEN_OP_AND,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOAND_W_RL]               = { GEN_OP_AND,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_D]                  = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_D_AQ]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_D_AQRL]             = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_D_RL]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_Q]                  = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_Q_AQ]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_Q_AQRL]             = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_Q_RL]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_W]                  = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_W_AQ]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_W_AQRL]             = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOCAS_W_RL]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAXU_D]                 = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAXU_D_AQ]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAXU_D_AQRL]            = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAXU_D_RL]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAXU_W]                 = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAXU_W_AQ]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAXU_W_AQRL]            = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAXU_W_RL]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAX_D]                  = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAX_D_AQ]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAX_D_AQRL]             = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAX_D_RL]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAX_W]                  = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAX_W_AQ]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAX_W_AQRL]             = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMAX_W_RL]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMINU_D]                 = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMINU_D_AQ]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMINU_D_AQRL]            = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMINU_D_RL]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMINU_W]                 = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMINU_W_AQ]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMINU_W_AQRL]            = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMINU_W_RL]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMIN_D]                  = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMIN_D_AQ]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMIN_D_AQRL]             = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMIN_D_RL]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMIN_W]                  = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMIN_W_AQ]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMIN_W_AQRL]             = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOMIN_W_RL]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOOR_D]                   = { GEN_OP_OR,     BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOOR_D_AQ]                = { GEN_OP_OR,     BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOOR_D_AQRL]              = { GEN_OP_OR,     BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOOR_D_RL]                = { GEN_OP_OR,     BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOOR_W]                   = { GEN_OP_OR,     BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOOR_W_AQ]                = { GEN_OP_OR,     BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOOR_W_AQRL]              = { GEN_OP_OR,     BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOOR_W_RL]                = { GEN_OP_OR,     BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOSWAP_D]                 = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOSWAP_D_AQ]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOSWAP_D_AQRL]            = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOSWAP_D_RL]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOSWAP_W]                 = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOSWAP_W_AQ]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOSWAP_W_AQRL]            = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOSWAP_W_RL]              = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOXOR_D]                  = { GEN_OP_XOR,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOXOR_D_AQ]               = { GEN_OP_XOR,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOXOR_D_AQRL]             = { GEN_OP_XOR,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOXOR_D_RL]               = { GEN_OP_XOR,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOXOR_W]                  = { GEN_OP_XOR,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOXOR_W_AQ]               = { GEN_OP_XOR,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOXOR_W_AQRL]             = { GEN_OP_XOR,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AMOXOR_W_RL]               = { GEN_OP_XOR,    BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_AND]                       = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ANDI]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ANDN]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_AUIPC]                     = { GEN_OP_LEA,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_BCLR]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_BCLRI]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_BEQ]                       = { GEN_OP_BRANCH, BRANCH_COND_DIRECT,    MF_NONE },
    [RISCV_INS_BEXT]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_BEXTI]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_BGE]                       = { GEN_OP_BRANCH, BRANCH_COND_DIRECT,    MF_NONE },
    [RISCV_INS_BGEU]                      = { GEN_OP_BRANCH, BRANCH_COND_DIRECT,    MF_NONE },
    [RISCV_INS_BINV]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_BINVI]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_BLT]                       = { GEN_OP_BRANCH, BRANCH_COND_DIRECT,    MF_NONE },
    [RISCV_INS_BLTU]                      = { GEN_OP_BRANCH, BRANCH_COND_DIRECT,    MF_NONE },
    [RISCV_INS_BNE]                       = { GEN_OP_BRANCH, BRANCH_COND_DIRECT,    MF_NONE },
    [RISCV_INS_BREV8]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_BSET]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_BSETI]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CBO_CLEAN]                 = { GEN_OP_CACHE_FLUSH, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_CBO_FLUSH]                 = { GEN_OP_CACHE_FLUSH, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_CBO_INVAL]                 = { GEN_OP_CACHE_FLUSH, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_CBO_ZERO]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CLMUL]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CLMULH]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CLMULR]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CLZ]                       = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CLZW]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CMOP_1]                    = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CMOP_11]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CMOP_13]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CMOP_15]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CMOP_3]                    = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CMOP_5]                    = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CMOP_7]                    = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CMOP_9]                    = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CM_JALT]                   = { GEN_OP_BRANCH, BRANCH_INDIRECT_JUMP,  MF_NONE },
    [RISCV_INS_CM_JT]                     = { GEN_OP_BRANCH, BRANCH_INDIRECT_JUMP,  MF_NONE },
    [RISCV_INS_CM_MVA01S]                 = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CM_MVSA01]                 = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CM_POP]                    = { GEN_OP_POP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CM_POPRET]                 = { GEN_OP_RET,    BRANCH_RETURN,         MF_NONE },
    [RISCV_INS_CM_POPRETZ]                = { GEN_OP_RET,    BRANCH_RETURN,         MF_NONE },
    [RISCV_INS_CM_PUSH]                   = { GEN_OP_PUSH,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CPOP]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CPOPW]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CSRRC]                     = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CSRRCI]                    = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CSRRS]                     = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CSRRSI]                    = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CSRRW]                     = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CSRRWI]                    = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CTZ]                       = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CTZW]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ABS]                    = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ABS_B]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ABS_H]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADDN]                   = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADDNR]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADDRN]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADDRNR]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADDUN]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADDUNR]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADDURN]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADDURNR]                = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADD_B]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADD_DIV2]               = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADD_DIV4]               = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADD_DIV8]               = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADD_H]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADD_SCI_B]              = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADD_SCI_H]              = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADD_SC_B]               = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ADD_SC_H]               = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AND_B]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AND_H]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AND_SCI_B]              = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AND_SCI_H]              = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AND_SC_B]               = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AND_SC_H]               = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVGU_B]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVGU_H]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVGU_SCI_B]             = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVGU_SCI_H]             = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVGU_SC_B]              = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVGU_SC_H]              = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVG_B]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVG_H]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVG_SCI_B]              = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVG_SCI_H]              = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVG_SC_B]               = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_AVG_SC_H]               = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_BCLR]                   = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_BCLRR]                  = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_BEQIMM]                 = { GEN_OP_BRANCH, BRANCH_COND_DIRECT,    MF_NONE },
    [RISCV_INS_CV_BITREV]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_BNEIMM]                 = { GEN_OP_BRANCH, BRANCH_COND_DIRECT,    MF_NONE },
    [RISCV_INS_CV_BSET]                   = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_BSETR]                  = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CLB]                    = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CLIP]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CLIPR]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CLIPU]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CLIPUR]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPEQ_B]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPEQ_H]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPEQ_SCI_B]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPEQ_SCI_H]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPEQ_SC_B]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPEQ_SC_H]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGEU_B]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGEU_H]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGEU_SCI_B]           = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGEU_SCI_H]           = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGEU_SC_B]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGEU_SC_H]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGE_B]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGE_H]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGE_SCI_B]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGE_SCI_H]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGE_SC_B]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGE_SC_H]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGTU_B]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGTU_H]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGTU_SCI_B]           = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGTU_SCI_H]           = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGTU_SC_B]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGTU_SC_H]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGT_B]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGT_H]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGT_SCI_B]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGT_SCI_H]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGT_SC_B]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPGT_SC_H]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLEU_B]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLEU_H]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLEU_SCI_B]           = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLEU_SCI_H]           = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLEU_SC_B]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLEU_SC_H]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLE_B]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLE_H]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLE_SCI_B]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLE_SCI_H]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLE_SC_B]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLE_SC_H]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLTU_B]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLTU_H]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLTU_SCI_B]           = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLTU_SCI_H]           = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLTU_SC_B]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLTU_SC_H]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLT_B]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLT_H]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLT_SCI_B]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLT_SCI_H]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLT_SC_B]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPLT_SC_H]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPNE_B]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPNE_H]                = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPNE_SCI_B]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPNE_SCI_H]            = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPNE_SC_B]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CMPNE_SC_H]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CNT]                    = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CPLXCONJ]               = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CPLXMUL_I]              = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CPLXMUL_I_DIV2]         = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CPLXMUL_I_DIV4]         = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CPLXMUL_I_DIV8]         = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CPLXMUL_R]              = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CPLXMUL_R_DIV2]         = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CPLXMUL_R_DIV4]         = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_CPLXMUL_R_DIV8]         = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTSP_B]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTSP_H]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTSP_SCI_B]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTSP_SCI_H]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTSP_SC_B]             = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTSP_SC_H]             = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUP_B]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUP_H]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUP_SCI_B]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUP_SCI_H]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUP_SC_B]             = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUP_SC_H]             = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUSP_B]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUSP_H]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUSP_SCI_B]           = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUSP_SCI_H]           = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUSP_SC_B]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_DOTUSP_SC_H]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ELW]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTBS]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTBZ]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTHS]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTHZ]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTRACT]                = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTRACTR]               = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTRACTU]               = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTRACTUR]              = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTRACTU_B]             = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTRACTU_H]             = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTRACT_B]              = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_EXTRACT_H]              = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_FF1]                    = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_FL1]                    = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_INSERT]                 = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_INSERTR]                = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_INSERT_B]               = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_INSERT_H]               = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_LBU]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_LB]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_LHU]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_LH]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_LW]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAC]                    = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MACHHSN]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MACHHSRN]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MACHHUN]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MACHHURN]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MACSN]                  = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MACSRN]                 = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MACUN]                  = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MACURN]                 = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAX]                    = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAXU]                   = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAXU_B]                 = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAXU_H]                 = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAXU_SCI_B]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAXU_SCI_H]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAXU_SC_B]              = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAXU_SC_H]              = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAX_B]                  = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAX_H]                  = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAX_SCI_B]              = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAX_SCI_H]              = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAX_SC_B]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MAX_SC_H]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MIN]                    = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MINU]                   = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MINU_B]                 = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MINU_H]                 = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MINU_SCI_B]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MINU_SCI_H]             = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MINU_SC_B]              = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MINU_SC_H]              = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MIN_B]                  = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MIN_H]                  = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MIN_SCI_B]              = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MIN_SCI_H]              = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MIN_SC_B]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MIN_SC_H]               = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MSU]                    = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MULHHSN]                = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MULHHSRN]               = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MULHHUN]                = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MULHHURN]               = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MULSN]                  = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MULSRN]                 = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MULUN]                  = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_MULURN]                 = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_OR_B]                   = { GEN_OP_OR,     BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_OR_H]                   = { GEN_OP_OR,     BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_OR_SCI_B]               = { GEN_OP_OR,     BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_OR_SCI_H]               = { GEN_OP_OR,     BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_OR_SC_B]                = { GEN_OP_OR,     BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_OR_SC_H]                = { GEN_OP_OR,     BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_PACK]                   = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_PACKHI_B]               = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_PACKLO_B]               = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_PACK_H]                 = { GEN_OP_VEC_SHUF, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_ROR]                    = { GEN_OP_ROR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SB]                     = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTSP_B]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTSP_H]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTSP_SCI_B]           = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTSP_SCI_H]           = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTSP_SC_B]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTSP_SC_H]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUP_B]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUP_H]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUP_SCI_B]           = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUP_SCI_H]           = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUP_SC_B]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUP_SC_H]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUSP_B]              = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUSP_H]              = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUSP_SCI_B]          = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUSP_SCI_H]          = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUSP_SC_B]           = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SDOTUSP_SC_H]           = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SHUFFLE2_B]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SHUFFLE2_H]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SHUFFLEI0_SCI_B]        = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SHUFFLEI1_SCI_B]        = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SHUFFLEI2_SCI_B]        = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SHUFFLEI3_SCI_B]        = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SHUFFLE_B]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SHUFFLE_H]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SHUFFLE_SCI_H]          = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SH]                     = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SLET]                   = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SLETU]                  = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SLL_B]                  = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SLL_H]                  = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SLL_SCI_B]              = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SLL_SCI_H]              = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SLL_SC_B]               = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SLL_SC_H]               = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRA_B]                  = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRA_H]                  = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRA_SCI_B]              = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRA_SCI_H]              = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRA_SC_B]               = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRA_SC_H]               = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRL_B]                  = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRL_H]                  = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRL_SCI_B]              = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRL_SCI_H]              = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRL_SC_B]               = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SRL_SC_H]               = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBN]                   = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBNR]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBRN]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBRNR]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBROTMJ]               = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBROTMJ_DIV2]          = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBROTMJ_DIV4]          = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBROTMJ_DIV8]          = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBUN]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBUNR]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBURN]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUBURNR]                = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUB_B]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUB_DIV2]               = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUB_DIV4]               = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUB_DIV8]               = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUB_H]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUB_SCI_B]              = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUB_SCI_H]              = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUB_SC_B]               = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SUB_SC_H]               = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_SW]                     = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_XOR_B]                  = { GEN_OP_XOR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_XOR_H]                  = { GEN_OP_XOR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_XOR_SCI_B]              = { GEN_OP_XOR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_XOR_SCI_H]              = { GEN_OP_XOR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_XOR_SC_B]               = { GEN_OP_XOR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CV_XOR_SC_H]               = { GEN_OP_XOR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CZERO_EQZ]                 = { GEN_OP_CMOV,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_CZERO_NEZ]                 = { GEN_OP_CMOV,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_ADD]                     = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_ADDI]                    = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_ADDI16SP]                = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_ADDI4SPN]                = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_ADDIW]                   = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_ADDW]                    = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_AND]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_ANDI]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_BEQZ]                    = { GEN_OP_BRANCH, BRANCH_COND_DIRECT,    MF_NONE },
    [RISCV_INS_C_BNEZ]                    = { GEN_OP_BRANCH, BRANCH_COND_DIRECT,    MF_NONE },
    [RISCV_INS_C_EBREAK]                  = { GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE,   MF_NONE },
    [RISCV_INS_C_FLD]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_FLDSP]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_FLW]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_FLWSP]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_FSD]                     = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_FSDSP]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_FSW]                     = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_FSWSP]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_J]                       = { GEN_OP_BRANCH, BRANCH_DIRECT_JUMP,    MF_NONE },
    [RISCV_INS_C_JAL]                     = { GEN_OP_BRANCH, BRANCH_DIRECT_JUMP,    MF_NONE },
    [RISCV_INS_C_JALR]                    = { GEN_OP_BRANCH, BRANCH_INDIRECT_JUMP,  MF_NONE },
    [RISCV_INS_C_JR]                      = { GEN_OP_BRANCH, BRANCH_INDIRECT_JUMP,  MF_NONE },
    [RISCV_INS_C_LBU]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_LD]                      = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_LDSP]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_LH]                      = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_LHU]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_LI]                      = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_LUI]                     = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_LW]                      = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_LWSP]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_MUL]                     = { GEN_OP_INT_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_MV]                      = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_NOP]                     = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_NOT]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_OR]                      = { GEN_OP_OR,     BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SB]                      = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SD]                      = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SDSP]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SEXT_B]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SEXT_H]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SH]                      = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SLLI]                    = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SLLI64]                  = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SRAI]                    = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SRAI64]                  = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SRLI]                    = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SRLI64]                  = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SSPOPCHK]                = { GEN_OP_POP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SSPUSH]                  = { GEN_OP_PUSH,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SUB]                     = { GEN_OP_INT_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SUBW]                    = { GEN_OP_INT_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SW]                      = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_SWSP]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_UNIMP]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_XOR]                     = { GEN_OP_XOR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_ZEXT_B]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_ZEXT_H]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_C_ZEXT_W]                  = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_DIV]                       = { GEN_OP_INT_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_DIVU]                      = { GEN_OP_INT_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_DIVUW]                     = { GEN_OP_INT_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_DIVW]                      = { GEN_OP_INT_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_DRET]                      = { GEN_OP_RET,    BRANCH_RETURN,         MF_NONE },
    [RISCV_INS_EBREAK]                    = { GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE,   MF_NONE },
    [RISCV_INS_ECALL]                     = { GEN_OP_SYSCALL, BRANCH_SYSCALL_TYPE,   MF_NONE },
    [RISCV_INS_FADD_D]                    = { GEN_OP_FP_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FADD_H]                    = { GEN_OP_FP_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FADD_S]                    = { GEN_OP_FP_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCLASS_D]                  = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCLASS_H]                  = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCLASS_S]                  = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVTMOD_W_D]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_BF16_S]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_D_H]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_D_L]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_D_LU]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_D_S]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_D_W]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_D_WU]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_H_D]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_H_L]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_H_LU]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_H_S]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_H_W]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_H_WU]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_LU_D]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_LU_H]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_LU_S]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_L_D]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_L_H]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_L_S]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_S_BF16]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_S_D]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_S_H]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_S_L]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_S_LU]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_S_W]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_S_WU]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_WU_D]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_WU_H]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_WU_S]                 = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_W_D]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_W_H]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FCVT_W_S]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FDIV_D]                    = { GEN_OP_FP_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FDIV_H]                    = { GEN_OP_FP_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FDIV_S]                    = { GEN_OP_FP_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FENCE]                     = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_FENCE_I]                   = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_FENCE_TSO]                 = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_FEQ_D]                     = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FEQ_H]                     = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FEQ_S]                     = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLEQ_D]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLEQ_H]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLEQ_S]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLE_D]                     = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLE_H]                     = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLE_S]                     = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLI_D]                     = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLI_H]                     = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLI_S]                     = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLTQ_D]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLTQ_H]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLTQ_S]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLT_D]                     = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLT_H]                     = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FLT_S]                     = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMADD_D]                   = { GEN_OP_FP_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMADD_H]                   = { GEN_OP_FP_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMADD_S]                   = { GEN_OP_FP_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMAXM_D]                   = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMAXM_H]                   = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMAXM_S]                   = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMAX_D]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMAX_H]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMAX_S]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMINM_D]                   = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMINM_H]                   = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMINM_S]                   = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMIN_D]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMIN_H]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMIN_S]                    = { GEN_OP_FP_CMP, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMSUB_D]                   = { GEN_OP_FP_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMSUB_H]                   = { GEN_OP_FP_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMSUB_S]                   = { GEN_OP_FP_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMUL_D]                    = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMUL_H]                    = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMUL_S]                    = { GEN_OP_FP_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMVH_X_D]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMVP_D_X]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMV_D_X]                   = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMV_H_X]                   = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMV_W_X]                   = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMV_X_D]                   = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMV_X_H]                   = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FMV_X_W]                   = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FNMADD_D]                  = { GEN_OP_FP_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FNMADD_H]                  = { GEN_OP_FP_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FNMADD_S]                  = { GEN_OP_FP_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FNMSUB_D]                  = { GEN_OP_FP_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FNMSUB_H]                  = { GEN_OP_FP_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FNMSUB_S]                  = { GEN_OP_FP_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FROUNDNX_D]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FROUNDNX_H]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FROUNDNX_S]                = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FROUND_D]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FROUND_H]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FROUND_S]                  = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSGNJN_D]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSGNJN_H]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSGNJN_S]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSGNJX_D]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSGNJX_H]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSGNJX_S]                  = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSGNJ_D]                   = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSGNJ_H]                   = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSGNJ_S]                   = { GEN_OP_FP_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSQRT_D]                   = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSQRT_H]                   = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSQRT_S]                   = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSUB_D]                    = { GEN_OP_FP_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSUB_H]                    = { GEN_OP_FP_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_FSUB_S]                    = { GEN_OP_FP_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HFENCE_GVMA]               = { GEN_OP_TLB_FLUSH, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_HFENCE_VVMA]               = { GEN_OP_TLB_FLUSH, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_HINVAL_GVMA]               = { GEN_OP_TLB_FLUSH, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_HINVAL_VVMA]               = { GEN_OP_TLB_FLUSH, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_HLVX_HU]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HLVX_WU]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HLV_B]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HLV_BU]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HLV_D]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HLV_H]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HLV_HU]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HLV_W]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HLV_WU]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HSV_B]                     = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HSV_D]                     = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HSV_H]                     = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_HSV_W]                     = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_JAL]                       = { GEN_OP_BRANCH, BRANCH_DIRECT_JUMP,    MF_NONE },
    [RISCV_INS_LR_D]                      = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_LR_D_AQ]                   = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_LR_D_AQRL]                 = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_LR_D_RL]                   = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_LR_W]                      = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_LR_W_AQ]                   = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_LR_W_AQRL]                 = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_LR_W_RL]                   = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_LUI]                       = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MAX]                       = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MAXU]                      = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MIN]                       = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MINU]                      = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_0]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_1]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_10]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_11]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_12]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_13]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_14]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_15]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_16]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_17]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_18]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_19]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_2]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_20]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_21]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_22]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_23]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_24]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_25]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_26]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_27]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_28]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_29]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_3]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_30]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_31]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_4]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_5]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_6]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_7]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_8]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_R_9]                   = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_RR_0]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_RR_1]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_RR_2]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_RR_3]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_RR_4]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_RR_5]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_RR_6]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MOP_RR_7]                  = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MRET]                      = { GEN_OP_RET,    BRANCH_RETURN,         MF_NONE },
    [RISCV_INS_MUL]                       = { GEN_OP_INT_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MULH]                      = { GEN_OP_INT_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MULHSU]                    = { GEN_OP_INT_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MULHU]                     = { GEN_OP_INT_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_MULW]                      = { GEN_OP_INT_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_OR]                        = { GEN_OP_OR,     BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ORC_B]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ORI]                       = { GEN_OP_OR,     BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ORN]                       = { GEN_OP_OR,     BRANCH_NONE,           MF_NONE },
    [RISCV_INS_PACK]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_PACKH]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_PACKW]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_PREFETCH_I]                = { GEN_OP_PREFETCH, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_PREFETCH_R]                = { GEN_OP_PREFETCH, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_PREFETCH_W]                = { GEN_OP_PREFETCH, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_REM]                       = { GEN_OP_INT_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_REMU]                      = { GEN_OP_INT_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_REMUW]                     = { GEN_OP_INT_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_REMW]                      = { GEN_OP_INT_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_REV8]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ROL]                       = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ROLW]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ROR]                       = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_RORI]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_RORIW]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_RORW]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SC_D]                      = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SC_D_AQ]                   = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SC_D_AQRL]                 = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SC_D_RL]                   = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SC_W]                      = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SC_W_AQ]                   = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SC_W_AQRL]                 = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SC_W_RL]                   = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SFENCE_INVAL_IR]           = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SFENCE_VMA]                = { GEN_OP_TLB_FLUSH, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SFENCE_W_INVAL]            = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SH1ADD]                    = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SH1ADD_UW]                 = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SH2ADD]                    = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SH2ADD_UW]                 = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SH3ADD]                    = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SH3ADD_UW]                 = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA256SIG0]                = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA256SIG1]                = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA256SUM0]                = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA256SUM1]                = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA512SIG0]                = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA512SIG0H]               = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA512SIG0L]               = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA512SIG1]                = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA512SIG1H]               = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA512SIG1L]               = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA512SUM0]                = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA512SUM0R]               = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA512SUM1]                = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SHA512SUM1R]               = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SINVAL_VMA]                = { GEN_OP_TLB_FLUSH, BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SLL]                       = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SLLI]                      = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SLLIW]                     = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SLLI_UW]                   = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SLLW]                      = { GEN_OP_SHL,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SLT]                       = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SLTI]                      = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SLTIU]                     = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SLTU]                      = { GEN_OP_CMP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SM3P0]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SM3P1]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SM4ED]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SM4KS]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SRA]                       = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SRAI]                      = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SRAIW]                     = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SRAW]                      = { GEN_OP_SAR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SRET]                      = { GEN_OP_RET,    BRANCH_RETURN,         MF_NONE },
    [RISCV_INS_SRL]                       = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SRLI]                      = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SRLIW]                     = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SRLW]                      = { GEN_OP_SHR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SSAMOSWAP_D]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SSAMOSWAP_D_AQ]            = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SSAMOSWAP_D_AQRL]          = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SSAMOSWAP_D_RL]            = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SSAMOSWAP_W]               = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SSAMOSWAP_W_AQ]            = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SSAMOSWAP_W_AQRL]          = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SSAMOSWAP_W_RL]            = { GEN_OP_XCHG,   BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_SSPOPCHK]                  = { GEN_OP_POP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SSPUSH]                    = { GEN_OP_PUSH,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SSRDP]                     = { GEN_OP_MOV,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SUB]                       = { GEN_OP_INT_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SUBW]                      = { GEN_OP_INT_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_VMAQASU_VV]             = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_VMAQASU_VX]             = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_VMAQAUS_VX]             = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_VMAQAU_VV]              = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_VMAQAU_VX]              = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_VMAQA_VV]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_VMAQA_VX]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_ADDSL]                  = { GEN_OP_INT_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_DCACHE_CALL]            = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_CIALL]           = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_CIPA]            = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_CISW]            = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_CIVA]            = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_CPA]             = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_CPAL1]           = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_CSW]             = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_CVA]             = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_CVAL1]           = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_IALL]            = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_IPA]             = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_ISW]             = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_DCACHE_IVA]             = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_EXT]                    = { GEN_OP_MOVSX,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_EXTU]                   = { GEN_OP_MOVZX,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_FF0]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_FF1]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_FLRD]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_FLRW]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_FLURD]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_FLURW]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_FSRD]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_FSRW]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_FSURD]                  = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_FSURW]                  = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_ICACHE_IALL]            = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_ICACHE_IALLS]           = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_ICACHE_IPA]             = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_ICACHE_IVA]             = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_L2CACHE_CALL]           = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_L2CACHE_CIALL]          = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_L2CACHE_IALL]           = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_LBIA]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LBIB]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LBUIA]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LBUIB]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LDD]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LDIA]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LDIB]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LHIA]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LHIB]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LHUIA]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LHUIB]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LRB]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LRBU]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LRD]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LRH]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LRHU]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LRW]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LRWU]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LURB]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LURBU]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LURD]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LURH]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LURHU]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LURW]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LURWU]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LWD]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LWIA]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LWIB]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LWUD]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LWUIA]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_LWUIB]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_MULA]                   = { GEN_OP_INT_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_MULAH]                  = { GEN_OP_INT_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_MULAW]                  = { GEN_OP_INT_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_MULS]                   = { GEN_OP_INT_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_MULSH]                  = { GEN_OP_INT_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_MULSW]                  = { GEN_OP_INT_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_MVEQZ]                  = { GEN_OP_CMOV,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_MVNEZ]                  = { GEN_OP_CMOV,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_REV]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_REVW]                   = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SBIA]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SBIB]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SDD]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SDIA]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SDIB]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SFENCE_VMAS]            = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_SHIA]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SHIB]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SRB]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SRD]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SRH]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SRRI]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SRRIW]                  = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SRW]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SURB]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SURD]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SURH]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SURW]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SWD]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SWIA]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SWIB]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_SYNC]                   = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_SYNC_I]                 = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_SYNC_IS]                = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_SYNC_S]                 = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_TH_TST]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_TH_TSTNBZ]                 = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_UNIMP]                     = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_UNZIP]                     = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAADDU_VV]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAADDU_VX]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAADD_VV]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAADD_VX]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VADC_VIM]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VADC_VVM]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VADC_VXM]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VADD_VI]                   = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VADD_VV]                   = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VADD_VX]                   = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAESDF_VS]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAESDF_VV]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAESDM_VS]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAESDM_VV]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAESEF_VS]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAESEF_VV]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAESEM_VS]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAESEM_VV]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAESKF1_VI]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAESKF2_VI]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAESZ_VS]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VANDN_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VANDN_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAND_VI]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAND_VV]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VAND_VX]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VASUBU_VV]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VASUBU_VX]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VASUB_VV]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VASUB_VX]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VBREV8_V]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VBREV_V]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VCLMULH_VV]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VCLMULH_VX]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VCLMUL_VV]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VCLMUL_VX]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VCLZ_V]                    = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VCOMPRESS_VM]              = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VCPOP_M]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VCPOP_V]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VCTZ_V]                    = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_FV]                  = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_FVV]                 = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_FVW]                 = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_I]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_IV]                  = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_IVV]                 = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_IVW]                 = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_VV]                  = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_VVV]                 = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_VVW]                 = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_FV]                = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_FVV]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_FVW]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_I]                 = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_IV]                = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_IVV]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_IVW]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_VV]                = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_VVV]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_VVW]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_X]                 = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_XV]                = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_XVV]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_V_XVW]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_X]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_XV]                  = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_XVV]                 = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VC_XVW]                 = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VDIVU_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VDIVU_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VDIV_VV]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VDIV_VX]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFADD_VF]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFADD_VV]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFCLASS_V]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFCVT_F_XU_V]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFCVT_F_X_V]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFCVT_RTZ_XU_F_V]          = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFCVT_RTZ_X_F_V]           = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFCVT_XU_F_V]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFCVT_X_F_V]               = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFDIV_VF]                  = { GEN_OP_FP_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFDIV_VV]                  = { GEN_OP_FP_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFIRST_M]                  = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMACC_VF]                 = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMACC_VV]                 = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMADD_VF]                 = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMADD_VV]                 = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMAX_VF]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMAX_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMERGE_VFM]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMIN_VF]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMIN_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMSAC_VF]                 = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMSAC_VV]                 = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMSUB_VF]                 = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMSUB_VV]                 = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMUL_VF]                  = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMUL_VV]                  = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMV_F_S]                  = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMV_S_F]                  = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFMV_V_F]                  = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNCVTBF16_F_F_W]          = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNCVT_F_F_W]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNCVT_F_XU_W]             = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNCVT_F_X_W]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNCVT_ROD_F_F_W]          = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNCVT_RTZ_XU_F_W]         = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNCVT_RTZ_X_F_W]          = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNCVT_XU_F_W]             = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNCVT_X_F_W]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNMACC_VF]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNMACC_VV]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNMADD_VF]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNMADD_VV]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNMSAC_VF]                = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNMSAC_VV]                = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNMSUB_VF]                = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFNMSUB_VV]                = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VFNRCLIP_XU_F_QF]       = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VFNRCLIP_X_F_QF]        = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFRDIV_VF]                 = { GEN_OP_FP_DIV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFREC7_V]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFREDMAX_VS]               = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFREDMIN_VS]               = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFREDOSUM_VS]              = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFREDUSUM_VS]              = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFRSQRT7_V]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFRSUB_VF]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFSGNJN_VF]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFSGNJN_VV]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFSGNJX_VF]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFSGNJX_VV]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFSGNJ_VF]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFSGNJ_VV]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFSLIDE1DOWN_VF]           = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFSLIDE1UP_VF]             = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFSQRT_V]                  = { GEN_OP_FP_SQRT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFSUB_VF]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFSUB_VV]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWADD_VF]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWADD_VV]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWADD_WF]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWADD_WV]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWCVTBF16_F_F_V]          = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWCVT_F_F_V]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWCVT_F_XU_V]             = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWCVT_F_X_V]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWCVT_RTZ_XU_F_V]         = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWCVT_RTZ_X_F_V]          = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWCVT_XU_F_V]             = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWCVT_X_F_V]              = { GEN_OP_FP_CVT, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWMACCBF16_VF]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWMACCBF16_VV]            = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VFWMACC_4X4X4]          = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWMACC_VF]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWMACC_VV]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWMSAC_VF]                = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWMSAC_VV]                = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWMUL_VF]                 = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWMUL_VV]                 = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWNMACC_VF]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWNMACC_VV]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWNMSAC_VF]               = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWNMSAC_VV]               = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWREDOSUM_VS]             = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWREDUSUM_VS]             = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWSUB_VF]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWSUB_VV]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWSUB_WF]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VFWSUB_WV]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VGHSH_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VGMUL_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VID_V]                     = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VIOTA_M]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL1RE16_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL1RE32_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL1RE64_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL1RE8_V]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL2RE16_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL2RE32_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL2RE64_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL2RE8_V]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL4RE16_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL4RE32_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL4RE64_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL4RE8_V]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL8RE16_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL8RE32_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL8RE64_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VL8RE8_V]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLE16FF_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLE16_V]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLE32FF_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLE32_V]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLE64FF_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLE64_V]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLE8FF_V]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLE8_V]                    = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLM_V]                     = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXEI16_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXEI32_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXEI64_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXEI8_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG2EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG2EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG2EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG2EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG3EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG3EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG3EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG3EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG4EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG4EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG4EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG4EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG5EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG5EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG5EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG5EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG6EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG6EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG6EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG6EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG7EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG7EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG7EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG7EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG8EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG8EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG8EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLOXSEG8EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSE16_V]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSE32_V]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSE64_V]                  = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSE8_V]                   = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG2E16FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG2E16_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG2E32FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG2E32_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG2E64FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG2E64_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG2E8FF_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG2E8_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG3E16FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG3E16_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG3E32FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG3E32_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG3E64FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG3E64_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG3E8FF_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG3E8_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG4E16FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG4E16_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG4E32FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG4E32_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG4E64FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG4E64_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG4E8FF_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG4E8_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG5E16FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG5E16_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG5E32FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG5E32_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG5E64FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG5E64_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG5E8FF_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG5E8_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG6E16FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG6E16_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG6E32FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG6E32_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG6E64FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG6E64_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG6E8FF_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG6E8_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG7E16FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG7E16_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG7E32FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG7E32_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG7E64FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG7E64_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG7E8FF_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG7E8_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG8E16FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG8E16_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG8E32FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG8E32_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG8E64FF_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG8E64_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG8E8FF_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSEG8E8_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG2E16_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG2E32_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG2E64_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG2E8_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG3E16_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG3E32_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG3E64_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG3E8_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG4E16_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG4E32_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG4E64_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG4E8_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG5E16_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG5E32_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG5E64_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG5E8_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG6E16_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG6E32_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG6E64_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG6E8_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG7E16_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG7E32_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG7E64_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG7E8_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG8E16_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG8E32_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG8E64_V]              = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLSSEG8E8_V]               = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXEI16_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXEI32_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXEI64_V]                = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXEI8_V]                 = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG2EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG2EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG2EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG2EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG3EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG3EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG3EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG3EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG4EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG4EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG4EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG4EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG5EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG5EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG5EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG5EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG6EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG6EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG6EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG6EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG7EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG7EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG7EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG7EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG8EI16_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG8EI32_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG8EI64_V]            = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VLUXSEG8EI8_V]             = { GEN_OP_LOAD,   BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMACC_VV]                  = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMACC_VX]                  = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMADC_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMADC_VIM]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMADC_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMADC_VVM]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMADC_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMADC_VXM]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMADD_VV]                  = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMADD_VX]                  = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMANDN_MM]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMAND_MM]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMAXU_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMAXU_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMAX_VV]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMAX_VX]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMERGE_VIM]                = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMERGE_VVM]                = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMERGE_VXM]                = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMFEQ_VF]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMFEQ_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMFGE_VF]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMFGT_VF]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMFLE_VF]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMFLE_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMFLT_VF]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMFLT_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMFNE_VF]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMFNE_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMINU_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMINU_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMIN_VV]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMIN_VX]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMNAND_MM]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMNOR_MM]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMORN_MM]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMOR_MM]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSBC_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSBC_VVM]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSBC_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSBC_VXM]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSBF_M]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSEQ_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSEQ_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSEQ_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSGTU_VI]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSGTU_VX]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSGT_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSGT_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSIF_M]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLEU_VI]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLEU_VV]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLEU_VX]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLE_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLE_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLE_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLTU_VV]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLTU_VX]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLT_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSLT_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSNE_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSNE_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSNE_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMSOF_M]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMULHSU_VV]                = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMULHSU_VX]                = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMULHU_VV]                 = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMULHU_VX]                 = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMULH_VV]                  = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMULH_VX]                  = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMUL_VV]                   = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMUL_VX]                   = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMV1R_V]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMV2R_V]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMV4R_V]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMV8R_V]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMV_S_X]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMV_V_I]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMV_V_V]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMV_V_X]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMV_X_S]                   = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMXNOR_MM]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VMXOR_MM]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNCLIPU_WI]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNCLIPU_WV]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNCLIPU_WX]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNCLIP_WI]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNCLIP_WV]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNCLIP_WX]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNMSAC_VV]                 = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNMSAC_VX]                 = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNMSUB_VV]                 = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNMSUB_VX]                 = { GEN_OP_VEC_MSUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNSRA_WI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNSRA_WV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNSRA_WX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNSRL_WI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNSRL_WV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VNSRL_WX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VOR_VI]                    = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VOR_VV]                    = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VOR_VX]                    = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VQMACCSU_2X8X2]         = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VQMACCSU_4X8X4]         = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VQMACCUS_2X8X2]         = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VQMACCUS_4X8X4]         = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VQMACCU_2X8X2]          = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VQMACCU_4X8X4]          = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VQMACC_2X8X2]           = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_SF_VQMACC_4X8X4]           = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREDAND_VS]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREDMAXU_VS]               = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREDMAX_VS]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREDMINU_VS]               = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREDMIN_VS]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREDOR_VS]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREDSUM_VS]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREDXOR_VS]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREMU_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREMU_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREM_VV]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREM_VX]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VREV8_V]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VRGATHEREI16_VV]           = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VRGATHER_VI]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VRGATHER_VV]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VRGATHER_VX]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VROL_VV]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VROL_VX]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VROR_VI]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VROR_VV]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VROR_VX]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VRSUB_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VRSUB_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VS1R_V]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VS2R_V]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VS4R_V]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VS8R_V]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSADDU_VI]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSADDU_VV]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSADDU_VX]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSADD_VI]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSADD_VV]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSADD_VX]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSBC_VVM]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSBC_VXM]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSE16_V]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSE32_V]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSE64_V]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSE8_V]                    = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSETIVLI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSETVL]                    = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSETVLI]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSEXT_VF2]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSEXT_VF4]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSEXT_VF8]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSHA2CH_VV]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSHA2CL_VV]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSHA2MS_VV]                = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSLIDE1DOWN_VX]            = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSLIDE1UP_VX]              = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSLIDEDOWN_VI]             = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSLIDEDOWN_VX]             = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSLIDEUP_VI]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSLIDEUP_VX]               = { GEN_OP_VEC_MOV, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSLL_VI]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSLL_VV]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSLL_VX]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSM3C_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSM3ME_VV]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSM4K_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSM4R_VS]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSM4R_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSMUL_VV]                  = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSMUL_VX]                  = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSM_V]                     = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXEI16_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXEI32_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXEI64_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXEI8_V]                 = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG2EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG2EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG2EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG2EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG3EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG3EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG3EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG3EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG4EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG4EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG4EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG4EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG5EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG5EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG5EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG5EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG6EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG6EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG6EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG6EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG7EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG7EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG7EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG7EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG8EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG8EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG8EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSOXSEG8EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSRA_VI]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSRA_VV]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSRA_VX]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSRL_VI]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSRL_VV]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSRL_VX]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSE16_V]                  = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSE32_V]                  = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSE64_V]                  = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSE8_V]                   = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG2E16_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG2E32_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG2E64_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG2E8_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG3E16_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG3E32_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG3E64_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG3E8_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG4E16_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG4E32_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG4E64_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG4E8_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG5E16_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG5E32_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG5E64_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG5E8_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG6E16_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG6E32_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG6E64_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG6E8_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG7E16_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG7E32_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG7E64_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG7E8_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG8E16_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG8E32_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG8E64_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSEG8E8_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSRA_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSRA_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSRA_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSRL_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSRL_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSRL_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG2E16_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG2E32_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG2E64_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG2E8_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG3E16_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG3E32_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG3E64_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG3E8_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG4E16_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG4E32_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG4E64_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG4E8_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG5E16_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG5E32_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG5E64_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG5E8_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG6E16_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG6E32_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG6E64_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG6E8_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG7E16_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG7E32_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG7E64_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG7E8_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG8E16_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG8E32_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG8E64_V]              = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSSEG8E8_V]               = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSUBU_VV]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSUBU_VX]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSUB_VV]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSSUB_VX]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUB_VV]                   = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUB_VX]                   = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXEI16_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXEI32_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXEI64_V]                = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXEI8_V]                 = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG2EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG2EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG2EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG2EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG3EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG3EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG3EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG3EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG4EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG4EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG4EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG4EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG5EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG5EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG5EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG5EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG6EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG6EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG6EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG6EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG7EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG7EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG7EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG7EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG8EI16_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG8EI32_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG8EI64_V]            = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VSUXSEG8EI8_V]             = { GEN_OP_STORE,  BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VT_MASKC]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VT_MASKCN]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWADDU_VV]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWADDU_VX]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWADDU_WV]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWADDU_WX]                 = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWADD_VV]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWADD_VX]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWADD_WV]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWADD_WX]                  = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMACCSU_VV]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMACCSU_VX]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMACCUS_VX]               = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMACCU_VV]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMACCU_VX]                = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMACC_VV]                 = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMACC_VX]                 = { GEN_OP_VEC_MADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMULSU_VV]                = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMULSU_VX]                = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMULU_VV]                 = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMULU_VX]                 = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMUL_VV]                  = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWMUL_VX]                  = { GEN_OP_VEC_MUL, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWREDSUMU_VS]              = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWREDSUM_VS]               = { GEN_OP_VEC_ADD, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWSLL_VI]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWSLL_VV]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWSLL_VX]                  = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWSUBU_VV]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWSUBU_VX]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWSUBU_WV]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWSUBU_WX]                 = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWSUB_VV]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWSUB_VX]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWSUB_WV]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VWSUB_WX]                  = { GEN_OP_VEC_SUB, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VXOR_VI]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VXOR_VV]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VXOR_VX]                   = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VZEXT_VF2]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VZEXT_VF4]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_VZEXT_VF8]                 = { GEN_OP_VEC_LOGIC, BRANCH_NONE,           MF_NONE },
    [RISCV_INS_WFI]                       = { GEN_OP_NOP,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_WRS_NTO]                   = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_WRS_STO]                   = { GEN_OP_FENCE,  BRANCH_NONE,           MF_ATOMIC },
    [RISCV_INS_XNOR]                      = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_XOR]                       = { GEN_OP_XOR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_XORI]                      = { GEN_OP_XOR,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_XPERM4]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_XPERM8]                    = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
    [RISCV_INS_ZIP]                       = { GEN_OP_AND,    BRANCH_NONE,           MF_NONE },
};

#endif /* CHAMPSIM_TRACER_MNEMONICS_RISCV_H */
