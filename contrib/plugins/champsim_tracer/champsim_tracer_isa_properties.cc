/*
 * The per-ISA property table.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * One row per ISA, and the handful of small per-ISA functions those rows
 * name.  It used to live inside the mnemonic tables, which is why deleting
 * those tables from the plugin was not a one-line change: the rows are read
 * on live paths -- the marker encoders, the endianness flag, the delay-slot
 * count, the address canonicalizer the profiler's data-is-address test runs
 * every candidate value through -- while the tables beside them answer only
 * to the offline comparison.
 *
 * Nothing here consults a second decoder.  The file includes no Capstone
 * header and the plugin does not link Capstone at all; the tables that did
 * are built into the two offline tools instead.
 */

#include <glib.h>
#include <stdint.h>

extern "C" {
#include <qemu-plugin.h>
}

/* The rows name the shared guest-marker encoders and their byte sizes. */
#include "champsim_marker.h"

#include "champsim_tracer_mnemonics.h"

/* ===================== x86 ===================== */

/*
 * x86 EFLAGS → canonical CST_METAFLAGS layout.  Mapping table:
 *   bit  0  CF -> CST_METAFLAGS_C
 *   bit  2  PF -> CST_METAFLAGS_P
 *   bit  6  ZF -> CST_METAFLAGS_Z
 *   bit  7  SF -> CST_METAFLAGS_N
 *   bit 11  OF -> CST_METAFLAGS_V
 * System bits (TF, IF, DF, IOPL, NT, RF, VM, AC, VIF, VIP, ID) and
 * the rest of RFLAGS are not exposed in the canonical view; consumers
 * that need them can keep reading the architectural REG_FLAGS slot.
 */
static uint8_t x86_flags_to_metaflags(uint64_t raw)
{
    uint8_t mf = 0;
    if (raw & (1u << 0))  mf |= CST_METAFLAGS_C;
    if (raw & (1u << 2))  mf |= CST_METAFLAGS_P;
    if (raw & (1u << 6))  mf |= CST_METAFLAGS_Z;
    if (raw & (1u << 7))  mf |= CST_METAFLAGS_N;
    if (raw & (1u << 11)) mf |= CST_METAFLAGS_V;
    return mf;
}

/*
 * x86-64 address canonicalization.  A valid virtual address is in
 * 48-bit canonical form: bits [63:48] replicate bit 47.  The MMU
 * faults a non-canonical address, so a genuine stored pointer and
 * the effective address that dereferences it are both already
 * canonical; sign-extending bit 47 normalises either form to the
 * same value and is the natural home for a future Linear Address
 * Masking (LAM) tag strip.  x86 carries no address tagging today.
 */
static uint64_t x86_canonicalize_addr(uint64_t a)
{
    return (uint64_t)(((int64_t)(a << 16)) >> 16);
}

/* =================== aarch64 =================== */

/*
 * AArch64 reg-alias inserter (used by RegHandleCache via
 * IsaProperties.reg_alias_inserter).
 *
 * The value-read route for v0..v31, fpsr and fpcr names them on the
 * AdvSIMD feature "org.gnu.gdb.aarch64.fpu", because that is where the
 * target declares them.  On a CPU that HAS SVE, target/arm/gdbstub.c
 * registers the SVE feature INSTEAD, and those descriptors arrive under
 * "org.gnu.gdb.aarch64.sve" with the arithmetic registers spelled
 * z0..z31.  Without the alias below the route resolves to nothing and
 * the read reports no value.  So: alias each z<N> to v<N>, and alias
 * fpsr/fpcr from sve into fpu, and the one route answers on both CPUs.
 */
static void insert_aarch64_reg_aliases(
    GHashTable *handles,
    const qemu_plugin_reg_descriptor *desc)
{
    static const char fpu_feature[] = "org.gnu.gdb.aarch64.fpu";
    static const char sve_feature[] = "org.gnu.gdb.aarch64.sve";

    if (!cst_str_eq(desc->feature, sve_feature)) {
        return;
    }

    const char *alias_name = NULL;
    char buf[8];
    if (desc->name && desc->name[0] == 'z' &&
        g_ascii_isdigit(desc->name[1])) {
        char *end = NULL;
        guint64 num = g_ascii_strtoull(desc->name + 1, &end, 10);
        if (end && *end == '\0' && num < 32) {
            g_snprintf(buf, sizeof(buf), "v%u", (unsigned)num);
            alias_name = buf;
        }
    } else if (cst_str_eq(desc->name, "fpsr") ||
               cst_str_eq(desc->name, "fpcr")) {
        alias_name = desc->name;
    }
    if (!alias_name) {
        return;
    }

    QemuRegKey *key = g_new(QemuRegKey, 1);
    key->feature = g_strdup(fpu_feature);
    key->name = g_strdup(alias_name);
    g_hash_table_insert(handles, key, desc->handle);
}

/*
 * AArch64 NZCV (top nibble of CPSR/PSTATE) → canonical
 * CST_METAFLAGS layout:
 *   bit 31 N -> CST_METAFLAGS_N
 *   bit 30 Z -> CST_METAFLAGS_Z
 *   bit 29 C -> CST_METAFLAGS_C
 *   bit 28 V -> CST_METAFLAGS_V
 * No parity bit on AArch64; CST_METAFLAGS_P stays zero.
 */
static uint8_t aarch64_flags_to_metaflags(uint64_t raw)
{
    uint8_t mf = 0;
    if (raw & (1u << 31)) mf |= CST_METAFLAGS_N;
    if (raw & (1u << 30)) mf |= CST_METAFLAGS_Z;
    if (raw & (1u << 29)) mf |= CST_METAFLAGS_C;
    if (raw & (1u << 28)) mf |= CST_METAFLAGS_V;
    return mf;
}

/*
 * AArch64 address canonicalization.  A user virtual address is
 * 48-bit; bits [63:48] are not part of the translated address.  The
 * top byte [63:56] holds a software tag the MMU ignores under Top
 * Byte Ignore (the basis of MTE and HWASAN), and bits [55:48] hold
 * the pointer-authentication signature when PAC is in use.  A pointer
 * sitting in memory therefore carries tag / PAC bits that the
 * effective address dereferencing it does not.  Masking to bits
 * [47:0] recovers the address both forms share, so the profiler's
 * page test matches a tagged or signed pointer against the address
 * space its accesses actually defined.
 */
static uint64_t aarch64_canonicalize_addr(uint64_t a)
{
    return a & ((UINT64_C(1) << 48) - 1);
}

/* ==================== riscv ==================== */

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

/* ==================== mips ===================== */

/*
 * MIPS address canonicalization.  MIPS defines no address tagging;
 * a stored pointer and the effective address dereferencing it share
 * one form (a MIPS32 address sign-extended into the 64-bit register
 * file, or a flat MIPS64 address).  No transform is needed —
 * identity.  The profiler's data-is-address test already masks a
 * sub-8-byte access to its captured width, which covers the MIPS32
 * pointer case.
 */
static uint64_t mips_canonicalize_addr(uint64_t a)
{
    return a;
}

/* ==================== the table ==================== */

static const char *const isa_prefixes_x86[]     = { "x86_64", "i386", NULL };
static const char *const isa_prefixes_aarch64[] = { "aarch64", NULL };
static const char *const isa_prefixes_riscv[]   = { "riscv64", "riscv32", NULL };
static const char *const isa_prefixes_mips[]    = { "mips64el", "mips64",
                                                    "mipsel", "mips", NULL };

const IsaProperties isa_properties[] = {
    [TRACE_ISA_UNKNOWN] = {},
    [TRACE_ISA_X86]     = {
        .include_implicit_regs = true,
        .target_prefixes = isa_prefixes_x86,
        .flags_to_metaflags = x86_flags_to_metaflags,
        .canonicalize_addr = x86_canonicalize_addr,
        .marker_encode_seq = cst_marker_x86_encode_seq_imm,
        .marker_insn_bytes = CST_MARKER_X86_INSN_BYTES,
        .marker_seq_insns  = CST_MARKER_SEQ_LEN,
    },
    [TRACE_ISA_AARCH64] = {
        .include_implicit_regs = true,
        .target_prefixes = isa_prefixes_aarch64,
        .reg_alias_inserter = insert_aarch64_reg_aliases,
        .flags_to_metaflags = aarch64_flags_to_metaflags,
        .canonicalize_addr = aarch64_canonicalize_addr,
        .marker_encode_seq = cst_marker_a64_encode_seq_imm,
        .marker_insn_bytes = CST_MARKER_PAIR_INSN_BYTES,
        .marker_seq_insns  = CST_MARKER_PAIR_SEQ_INSNS,
    },
    [TRACE_ISA_RISCV]   = {
        /* RISC-V MUST fold implicit regs too.  The vector-configuration
         * CSRs are the reason: `vl` and `vtype` never appear in an
         * operand field — `vsetvli` names only its GPR destination and a
         * vector op names only its vector registers — so without the
         * fold the edge every RVV instruction has on the `vsetvli` that
         * configured it does not exist, and a vector kernel's ops float
         * free of their own configuration.  The same applies to the FP
         * rounding mode `frm` on scalar and vector FP.  The historical
         * double-count worry is moot for the same reason it is on MIPS:
         * add_src/dst_cap_reg dedup by generic reg id, so a register
         * named both by an operand and by the implicit list occupies one
         * slot. */
        .include_implicit_regs = true,
        .target_prefixes = isa_prefixes_riscv,
        .canonicalize_addr = riscv_canonicalize_addr,
        .marker_encode_seq = cst_marker_riscv_encode_seq_imm,
        .marker_insn_bytes = CST_MARKER_PAIR_INSN_BYTES,
        .marker_seq_insns  = CST_MARKER_PAIR_SEQ_INSNS,
    },
    [TRACE_ISA_MIPS]    = {
        .branch_delay_slots = 1,
        /* MIPS MUST fold implicit regs: the HI:LO accumulator never
         * appears in MULT / DIV / MFHI / MFLO operand fields — only in
         * Capstone's implicit regs_read/regs_write — so without the
         * fold the whole accumulator dependency chain vanishes (mfhi
         * appears input-less).  The historical double-count worry is
         * moot: add_src/dst_cap_reg dedup by generic reg id.  (Caught
         * by probe_implicit_acc.) */
        .include_implicit_regs = true,
        .target_prefixes = isa_prefixes_mips,
        .canonicalize_addr = mips_canonicalize_addr,
        /* mips/mips64 are big-endian; mipsel/mips64el carry the "el" suffix. */
        .has_be_variant = true,
        .marker_encode_seq = cst_marker_mips_encode_seq_imm,
        .marker_insn_bytes = CST_MARKER_PAIR_INSN_BYTES,
        .marker_seq_insns  = CST_MARKER_PAIR_SEQ_INSNS,
    },
};
