/*
 * ISA-specific mnemonic tables for champsim_tracer.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <stdbool.h>
#include <string.h>

#include "champsim_tracer_generic_ids.h"

/* Null-safe string equality (g_strcmp0 replacement).  Defined here
 * rather than in champsim_tracer.h because the per-ISA mnemonic
 * headers (which call it) are pulled in directly by the C TU
 * champsim_tracer_mnemonic_tables.c without going through
 * champsim_tracer.h. */
static inline bool cst_str_eq(const char *a, const char *b)
{
    if (a == b) {
        return true;
    }
    if (!a || !b) {
        return false;
    }
    return strcmp(a, b) == 0;
}

/*
 * (OperandCaptureKind removed — Capstone structured operand detail
 *  now provides operand type (REG/IMM/MEM) and access (READ/WRITE)
 *  directly, eliminating the need for per-instruction regex capture
 *  semantic tags.)
 */

/*
 * Mnemonic entry flags.
 *
 * Only flags whose semantics cannot be derived from Capstone detail
 * are retained.  Capstone now provides operand access (READ/WRITE),
 * implicit regs_read/regs_write, and group membership (RET,
 * JUMP, BRANCH_REL, INT) for all ISAs, so most of the original
 * per-instruction flag bits are no longer needed.
 */
enum MnemonicFlags {
    MF_NONE             = 0,
    MF_CONDITIONAL      = (1 << 0),  /* x86: direct branch may be conditional */
    MF_ATOMIC           = (1 << 1),  /* Atomic/locked memory op → SYNC_ATOMIC   */
};

/*
 * Register classification: maps a Capstone register ID to one generic ID,
 * or to a small alias list when Capstone uses one enum value for a register
 * group.  Tables are indexed directly by the Capstone enum value.  qemu_reg
 * is the QEMU plugin register descriptor key for register-value reads, or
 * { NULL, NULL } when the Capstone register has no single readable QEMU
 * register.
 */
#define MAX_REG_ALIASES 8

typedef struct {
    const char *feature;
    const char *name;
} QemuRegKey;

typedef struct {
    uint8_t reg_id;                    /* GenericRegId */
    uint8_t n_regs;                    /* non-zero for composite aliases */
    uint8_t regs[MAX_REG_ALIASES];     /* GenericRegId[] */
    QemuRegKey qemu_reg;               /* qemu_plugin_reg_descriptor key */
    /*
     * Set true on the *one* row whose Capstone reg id maps to the
     * ISA's integer-flags register (x86 EFLAGS, AArch64 NZCV).  When
     * the generic decoder sees this flag during dst-reg classification
     * it mirrors a REG_METAFLAGS slot alongside REG_FLAGS so consumers
     * get a canonical Z/N/C/V/P byte without per-ISA bit math.  Stays
     * false on every other row, including non-integer flags writers
     * (x86 FPSW → REG_FLAGS but not the int-flags reg) and ISAs
     * without an integer flags reg (RISC-V, MIPS).
     */
    bool is_int_flags;
} RegClassification;

/*
 * Decoded per-instruction generic fields.
 *
 * Lives in this header (rather than champsim_tracer.h) so per-ISA
 * mnemonic refiners — compiled in the C tables TU — can read and
 * mutate fields directly without needing the rest of the tracer
 * internals.
 */
#define MAX_SRC_REGS 16
#define MAX_DST_REGS 16

typedef struct InsnFields {
    uint8_t opcode;                 /* GenericOpcode */
    uint8_t branch_type;            /* BranchType */
    bool    branch_conditional;
    /*
     * True when this insn's destination set includes the ISA's
     * integer-flags register (x86 EFLAGS, AArch64 NZCV) — matches
     * the RegClassification.is_int_flags marker on the per-ISA
     * mnemonic-header row.  The wire-format encoder reads this bit
     * and emits a side-channel CST_FID_METAFLAGS record carrying
     * the canonical Z/N/C/V/P byte derived from the REG_FLAGS dst
     * snap.  Consumers reasoning about architectural register sets
     * see the unchanged REG_FLAGS dst slot; the canonical byte
     * rides the field-delta stream as side data instead of as a
     * phantom dst-reg slot.
     */
    bool    writes_int_flags;
    uint8_t n_src_regs;
    uint8_t n_dst_regs;
    uint8_t src_regs[MAX_SRC_REGS];
    uint8_t dst_regs[MAX_DST_REGS];
    bool    has_immediate;
    int64_t immediate;
    uint8_t sync_hint;              /* SyncEventType */
    uint8_t n_loads;                /* Template default; runtime uses QEMU mem callbacks */
    uint8_t n_stores;               /* Template default; runtime uses QEMU mem callbacks */
} InsnFields;


/*
 * Optional post-classification refiner.
 *
 * Some Capstone insn_ids cover several distinct semantics that only
 * differ in operand encoding (e.g. RISC-V JALR is "indirect branch",
 * "indirect jump", or "ret" depending on rd/rs1).  A row may set
 * .refine to a function that fixes up the decoded InsnFields after
 * the generic operand-walk has populated src_regs/dst_regs/etc.
 *
 * The refiner is ISA-local: it is defined in the per-ISA mnemonic
 * table file and never referenced from the ISA-agnostic decoder.
 */
struct qemu_plugin_insn_info; /* fwd-decl: full type from <qemu-plugin.h> */
typedef void (*InsnRefineFn)(const struct qemu_plugin_insn_info *info,
                             InsnFields *fields);

/*
 * Instruction classification entry: maps a Capstone insn_id directly
 * to GenericOpcode + BranchType + MnemonicFlags via designated-initializer
 * arrays indexed by the Capstone enum value.  Eliminates all string-based
 * mnemonic matching (hash tables, regex, prefix stripping, caches).
 *
 * `.refine` is optional (NULL by default); see InsnRefineFn above.
 */
typedef struct {
    uint8_t      opcode;      /* GenericOpcode */
    uint8_t      branch_type; /* BranchType */
    uint16_t     flags;       /* MnemonicFlags */
    InsnRefineFn refine;      /* optional, NULL if unused */
} InsnClassification;


#ifdef CHAMPSIM_MNEMONIC_TABLES_IMPL

#include "champsim_tracer_mnemonics_x86.h"
#include "champsim_tracer_mnemonics_aarch64.h"
#include "champsim_tracer_mnemonics_riscv.h"
#include "champsim_tracer_mnemonics_mips.h"

/* Classification table selectors (indexed by TraceISA) */
const RegClassification *const isa_reg_class[] = {
    [TRACE_ISA_UNKNOWN] = NULL,
    [TRACE_ISA_X86]     = x86_reg_class,
    [TRACE_ISA_AARCH64] = aarch64_reg_class,
    [TRACE_ISA_RISCV]   = riscv_reg_class,
    [TRACE_ISA_MIPS]    = mips_reg_class,
};

const unsigned isa_reg_class_size[] = {
    [TRACE_ISA_UNKNOWN] = 0,
    [TRACE_ISA_X86]     = X86_REG_ENDING,
    [TRACE_ISA_AARCH64] = AARCH64_REG_ENDING,
    [TRACE_ISA_RISCV]   = RISCV_REG_ENDING,
    [TRACE_ISA_MIPS]    = MIPS_REG_ENDING,
};

/* Classification table selector (indexed by TraceISA) */
const InsnClassification *const isa_insn_class[] = {
    [TRACE_ISA_UNKNOWN] = NULL,
    [TRACE_ISA_X86]     = x86_insn_class,
    [TRACE_ISA_AARCH64] = aarch64_insn_class,
    [TRACE_ISA_RISCV]   = riscv_insn_class,
    [TRACE_ISA_MIPS]    = mips_insn_class,
};

const unsigned isa_insn_class_size[] = {
    [TRACE_ISA_UNKNOWN] = 0,
    [TRACE_ISA_X86]     = X86_INS_ENDING,
    [TRACE_ISA_AARCH64] = AARCH64_INS_ENDING,
    [TRACE_ISA_RISCV]   = RISCV_INS_ENDING,
    [TRACE_ISA_MIPS]    = MIPS_INS_ENDING,
};

#else /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

#ifdef __cplusplus
extern "C" {
#endif

extern const RegClassification *const isa_reg_class[TRACE_ISA_MIPS + 1];
extern const unsigned isa_reg_class_size[TRACE_ISA_MIPS + 1];
extern const InsnClassification *const isa_insn_class[TRACE_ISA_MIPS + 1];
extern const unsigned isa_insn_class_size[TRACE_ISA_MIPS + 1];

#ifdef __cplusplus
}
#endif

#endif /* CHAMPSIM_MNEMONIC_TABLES_IMPL */


/*
 * Static ISA property table.
 *
 * Concentrates every ISA-specific knob into one place so that adding a
 * new ISA requires only a new row rather than scattered switch arms.
 *
 *   branch_delay_slots       — number of delay-slot instructions after a
 *                              branch (0 for most ISAs, 1 for MIPS)
 *   pc_relative_branch_imm   — true if Capstone reports the immediate of
 *                              direct branches as a *relative* offset
 *                              from the branch PC (RISC-V, MIPS).  False
 *                              if Capstone resolves it to an absolute
 *                              target (x86, ARM64).  decode_detail_to_
 *                              generic() normalizes the field so
 *                              InsnFields.immediate is always the
 *                              absolute target on the wire.
 *   include_implicit_regs    — true to fold Capstone's implicit
 *                              regs_read/regs_write lists into the
 *                              decoded source/destination sets.  False
 *                              for ISAs (RISC-V, MIPS) whose operand
 *                              walk already covers everything the
 *                              implicit lists would, so including them
 *                              would double-count.
 *   target_prefixes          — NULL-terminated list of QEMU target_name
 *                              prefixes that map to this ISA
 *   cap_arch                 — Capstone cs_arch enum value (CS_ARCH_*),
 *                              or -1 if unsupported
 *   cap_mode_for_target      — derives a Capstone cs_mode bitmask
 *                              (CS_MODE_*) from target_name (handles e.g.
 *                              RISC-V 32/64 split, MIPS endianness)
 */
typedef unsigned int (*CapModeForTargetFn)(const char *target_name);

/*
 * Optional per-ISA hook called by RegHandleCache for every QEMU plugin
 * register descriptor.  May insert one or more alias entries into
 * @handles so reg-data lookups via Capstone names resolve to QEMU
 * descriptors registered under different feature/name pairs (currently
 * used for AArch64 SVE z<->v register aliasing).  May be null.
 */
typedef void (*RegAliasInserterFn)(
    GHashTable *handles,
    const qemu_plugin_reg_descriptor *desc);

/*
 * Per-ISA integer-flags → canonical metaflags shuffle.  Takes the
 * raw bytes of the architectural flags register (little-endian,
 * up to 8 bytes — all current ISAs' flag regs fit in a u64) and
 * returns the CST_METAFLAGS_* byte the snap collector ships in
 * REG_METAFLAGS slots.  NULL on ISAs without an integer flags reg,
 * in which case REG_METAFLAGS never lands in any template's
 * dst-reg list and this hook is never called.
 */
typedef uint8_t (*MetaFlagsMapperFn)(uint64_t raw_flags);

typedef struct {
    uint8_t               branch_delay_slots;
    bool                  pc_relative_branch_imm;
    bool                  include_implicit_regs;
    const char *const    *target_prefixes;
    int                   cap_arch;
    CapModeForTargetFn    cap_mode_for_target;
    RegAliasInserterFn    reg_alias_inserter;
    MetaFlagsMapperFn     flags_to_metaflags;
} IsaProperties;

#ifdef CHAMPSIM_MNEMONIC_TABLES_IMPL

static const char *const isa_prefixes_x86[]     = { "x86_64", "i386", NULL };
static const char *const isa_prefixes_aarch64[] = { "aarch64", NULL };
static const char *const isa_prefixes_riscv[]   = { "riscv64", "riscv32", NULL };
static const char *const isa_prefixes_mips[]    = { "mips64el", "mips64",
                                                    "mipsel", "mips", NULL };

const IsaProperties isa_properties[] = {
    [TRACE_ISA_UNKNOWN] = { 0 },
    [TRACE_ISA_X86]     = {
        .include_implicit_regs = true,
        .target_prefixes = isa_prefixes_x86,
        .cap_arch = CS_ARCH_X86,
        .cap_mode_for_target = cap_mode_x86,
        .flags_to_metaflags = x86_flags_to_metaflags,
    },
    [TRACE_ISA_AARCH64] = {
        .include_implicit_regs = true,
        .target_prefixes = isa_prefixes_aarch64,
        .cap_arch = CS_ARCH_AARCH64,
        .cap_mode_for_target = cap_mode_aarch64,
        .reg_alias_inserter = insert_aarch64_reg_aliases,
        .flags_to_metaflags = aarch64_flags_to_metaflags,
    },
    [TRACE_ISA_RISCV]   = {
        .include_implicit_regs = false,
        .target_prefixes = isa_prefixes_riscv,
        .cap_arch = CS_ARCH_RISCV,
        .cap_mode_for_target = cap_mode_riscv,
    },
    [TRACE_ISA_MIPS]    = {
        .branch_delay_slots = 1,
        .include_implicit_regs = false,
        .target_prefixes = isa_prefixes_mips,
        .cap_arch = CS_ARCH_MIPS,
        .cap_mode_for_target = cap_mode_mips,
    },
};

#else /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

#ifdef __cplusplus
extern "C" {
#endif

extern const IsaProperties isa_properties[TRACE_ISA_MIPS + 1];

#ifdef __cplusplus
}
#endif

#endif /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

