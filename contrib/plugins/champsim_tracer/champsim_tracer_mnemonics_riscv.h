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
    /* Standard groups Capstone decodes that this mapper used to drop on
     * the floor.  A guest declaring any of them in Tag_RISCV_arch had
     * those instructions decode as unknown -- for zicfiss that is the
     * entire shadow stack, and with it every reference to ssp. */
    if (g_str_equal(tok, "zicfiss")) return CS_MODE_RISCV_ZICFISS;
    if (g_str_equal(tok, "zfinx"))   return CS_MODE_RISCV_ZFINX;
    if (g_str_equal(tok, "zcmp") || g_str_equal(tok, "zcmt") ||
        g_str_equal(tok, "zce"))     return CS_MODE_RISCV_ZCMP_ZCMT_ZCE;
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
 * RISC-V address canonicalization.  The base ISA defines no address
 * tagging; Sv39 / Sv48 / Sv57 virtual addresses are already in
 * canonical form (bits above the translated width replicate the top
 * translated bit), and the same form is seen for both a stored
 * pointer and the effective address dereferencing it.  No transform
 * is needed — identity.  If a pointer-masking extension is ever
 * traced, its tag strip belongs here.
 */
static uint64_t riscv_canonicalize_addr(uint64_t a)
{
    return a;
}

/*
 * RISC-V: the architectural register whose VALUE a CSR's snapshot must
 * carry.
 *
 * fflags and frm are not registers beside fcsr; they are ADDRESSES OF
 * FIELDS INSIDE IT.  The unprivileged ISA defines fcsr as
 * {frm[7:5], fflags[4:0]} (RISC-V unpriv. spec, "Floating-Point Control
 * and Status Register"), and vcsr the same way as
 * {vxrm[2:1], vxsat[0]} (RVV 1.0 s3.2).  `csrw fflags, t3` therefore
 * does not leave a register called fflags holding 0x18; it leaves fcsr
 * holding {frm, 0x18}, and the guest's own `csrr s5, fcsr` reads that
 * composed word back.
 *
 * The wire has ONE name for the whole group -- REG_FCSR -- and no
 * discriminator to say which granularity a given snapshot was taken at,
 * so publishing the field's own value makes the id's history a mixture
 * of three different registers' contents that no consumer can separate
 * (R13/Spike, item #277: the wire published %fcsr[0x1] at one pc and
 * %fcsr[0x18] at another while the guest's next read returned 0x20 and
 * 0x38).  Naming the member on the wire is an EPOCH change and the
 * format is frozen, so the value published is the COMPOSED register's:
 * one wire name, one register's history, and it is the register the
 * guest can read back.
 *
 * This is a VALUE rule only.  The dependency identity is untouched --
 * every member still folds to REG_FCSR, which is what a consumer
 * schedules against.
 *
 * NULL for every other CSR: vl, vtype, vstart and vlenb are registers
 * in their own right, not fields of a container, and a rule that
 * invented one for them would publish a neighbour's content.
 */
static const char *riscv_sysreg_value_container(const char *name)
{
    if (!name || !name[0]) {
        return NULL;
    }
    if (cst_str_eq(name, "fflags") || cst_str_eq(name, "frm")) {
        return "fcsr";
    }
    if (cst_str_eq(name, "vxsat") || cst_str_eq(name, "vxrm")) {
        return "vcsr";
    }
    return NULL;
}

/* Register classification table. */
static const RegClassification riscv_reg_class[RISCV_REG_ENDING] = {
    /* Auto-generated by champsim_tracer_mnemonic_audit.py. */
    /* riscv regs: 458/459 mapped, 0 intentionally ignored */
    [RISCV_REG_INVALID] = {},
    [RISCV_REG_FFLAGS] = { .reg_id = REG_FCSR, .qemu_reg = { .feature = "org.gnu.gdb.riscv.csr", .name = "fflags" } },  /* fflags */
    [RISCV_REG_FRM] = { .reg_id = REG_FCSR, .qemu_reg = { .feature = "org.gnu.gdb.riscv.csr", .name = "frm" } },  /* frm */
    [RISCV_REG_SSP] = { .reg_id = REG_SSP, .qemu_reg = { .feature = "org.gnu.gdb.riscv.csr", .name = "ssp" } },  /* ssp */
    [RISCV_REG_VL] = { .reg_id = REG_VCTRL, .qemu_reg = { .feature = "org.gnu.gdb.riscv.csr", .name = "vl" } },  /* vl */
    [RISCV_REG_VLENB] = { .reg_id = REG_SYSID, .qemu_reg = { .feature = "org.gnu.gdb.riscv.csr", .name = "vlenb" } },  /* vlenb */
    [RISCV_REG_VTYPE] = { .reg_id = REG_VCTRL, .qemu_reg = { .feature = "org.gnu.gdb.riscv.csr", .name = "vtype" } },  /* vtype */
    [RISCV_REG_VXRM] = { .reg_id = REG_FCSR, .qemu_reg = { .feature = "org.gnu.gdb.riscv.csr", .name = "vxrm" } },  /* vxrm */
    [RISCV_REG_VXSAT] = { .reg_id = REG_FCSR, .qemu_reg = { .feature = "org.gnu.gdb.riscv.csr", .name = "vxsat" } },  /* vxsat */
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

/*
 * `riscv_insn_class[]` STOOD HERE, AND IS RETIRED (ruling R14).
 *
 * One row per Capstone instruction id, carrying the opcode,
 * branch class, flags, `.refine`, `.dep_refine` and the lane pair.
 * It was the wire's classification key until QEMU's own decode
 * identity replaced it, and after that it answered only where the
 * identity said nothing.  `enumocc.py` counted that population
 * over the whole enumerated encoding space -- four ISAs, wp0 and
 * wp16 -- and read `ENUM-OCCUPANCY total=0 key=STATED`.
 *
 * WHAT STAYS IN THIS FILE, and why it is not the table: the
 * Capstone arch/mode derivation, the register-classification
 * table, the address canonicaliser, the flags mapper and the
 * per-instance `.refine` callbacks.  The refiners in particular
 * are LIVE CODE ON THE IDENTITY KEY -- champsim_tracer_qemu_ident_
 * aarch64.h alone names refine_arm64_ldst_access on 218 rows --
 * so they retire with the operand walk, not with the table.
 */

#endif /* CHAMPSIM_TRACER_MNEMONICS_RISCV_H */
