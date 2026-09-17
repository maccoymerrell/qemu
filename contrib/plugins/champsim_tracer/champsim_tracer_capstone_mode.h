#ifndef CHAMPSIM_TRACER_CAPSTONE_MODE_H
#define CHAMPSIM_TRACER_CAPSTONE_MODE_H

/*
 * The Capstone arch/mode selection, and why it is not in the shipped plugin.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Nothing the wire publishes reads Capstone.  What still asks it anything is
 * the COMPARISON -- one column of the corpus that scores this classifier
 * against a second decoder -- and a comparison belongs outside the thing it
 * is comparing.  So the arch/mode pair that a Capstone call needs lives here,
 * in a header the release plugin does not include, rather than on a row of
 * IsaProperties[] where every translation unit in the tracer could reach it.
 *
 * TWO INCLUDERS, BOTH APPARATUS:
 *
 *   champsim_tracer_capture.cc, under -DCST_CAPTURE.  A release object
 *   contains none of this: neither the code, nor the CS_* constants, nor the
 *   names below -- a property `nm` and `strings` can check, which is the same
 *   discipline the capture file itself is built on.
 *
 *   tools/cst_referee_fields.cc, the offline referee, which links no plugin
 *   and no emulator.
 *
 * The mode resolvers introspect the guest binary through
 * qemu_plugin_path_to_binary(); offline that returns nothing and each falls
 * back to the documented default set, which is why the referee stamps which
 * set it used.
 */

#include <stdbool.h>
#include <stdint.h>

#include <capstone/capstone.h>
#include "elf.h"

extern "C" {
#include <qemu-plugin.h>
}

#include "champsim_tracer_generic_ids.h"
#include "champsim_tracer_elf_attrs.h"

static unsigned int cap_mode_x86(const char *target_name)
{
    (void)target_name;
    /*
     * The Capstone decode of i386 instructions in 64-bit mode covers
     * the same encodings; we don't currently distinguish 32-vs-64-bit
     * instruction streams here.
     */
    return CS_MODE_64;
}

static unsigned int cap_mode_aarch64(const char *target_name)
{
    (void)target_name;
    /* Capstone has no separate LE flag; 0 == little endian. */
    return CS_MODE_LITTLE_ENDIAN;
}

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

/*
 * The per-ISA rows, held here instead of on IsaProperties[].
 *
 * Both are keyed on TraceISA and both refuse an ISA they do not know: -1 for
 * the arch says "no Capstone for this target", which every caller already has
 * to handle, and 0 for the mode is not a legal mode for any of the four.
 */
static inline int cst_capstone_arch_for_isa(TraceISA isa)
{
    switch (isa) {
    case TRACE_ISA_X86:     return CS_ARCH_X86;
    case TRACE_ISA_AARCH64: return CS_ARCH_AARCH64;
    case TRACE_ISA_RISCV:   return CS_ARCH_RISCV;
    case TRACE_ISA_MIPS:    return CS_ARCH_MIPS;
    default:                return -1;
    }
}

static inline unsigned int cst_capstone_mode_for_isa(TraceISA isa,
                                                     const char *target_name)
{
    switch (isa) {
    case TRACE_ISA_X86:     return cap_mode_x86(target_name);
    case TRACE_ISA_AARCH64: return cap_mode_aarch64(target_name);
    case TRACE_ISA_RISCV:   return cap_mode_riscv(target_name);
    case TRACE_ISA_MIPS:    return cap_mode_mips(target_name);
    default:                return 0;
    }
}

#endif /* CHAMPSIM_TRACER_CAPSTONE_MODE_H */
