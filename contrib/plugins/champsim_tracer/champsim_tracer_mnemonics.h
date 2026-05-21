/*
 * ISA-specific mnemonic tables for champsim_tracer.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <stdbool.h>
#include <string.h>

#include "champsim_tracer_generic_ids.h"

/* Null-safe string equality (g_strcmp0 replacement).  Defined here,
 * not in champsim_tracer.h, because the per-ISA mnemonic headers are
 * pulled into the C tables TU without it. */
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
 * Mnemonic entry flags.  Only flags whose semantics Capstone detail
 * cannot supply are kept (Capstone provides operand access, implicit
 * regs, and group membership for all ISAs).
 */
enum MnemonicFlags {
    MF_NONE             = 0,
    MF_CONDITIONAL      = (1 << 0),  /* x86: direct branch may be conditional */
    MF_ATOMIC           = (1 << 1),  /* Atomic/locked memory op (LOCK prefix,
                                      * x86 XCHG, AArch64 LDXR/STXR, RISC-V A
                                      * extension, MIPS LL/SC) — sets the
                                      * CST_INSN_FLAG_ATOMIC bit on the wire. */
};

/*
 * Register classification: Capstone register ID -> one generic ID (or
 * a small alias list when Capstone groups regs under one enum value).
 * Indexed by the Capstone enum value.  qemu_reg is the QEMU register
 * descriptor key, or { NULL, NULL } when there's no single readable
 * QEMU register.
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
     * True on the *one* row whose Capstone reg id is the ISA's
     * integer-flags register (x86 EFLAGS, AArch64 NZCV); drives the
     * REG_METAFLAGS mirror (see generic_ids.h metaflags note).  False
     * on all other rows, including non-integer flags writers (x86
     * FPSW) and ISAs without an integer flags reg.
     */
    bool is_int_flags;
} RegClassification;

/*
 * Decoded per-instruction generic fields.  In this header (not
 * champsim_tracer.h) so the C tables-TU refiners can mutate fields
 * without the rest of the tracer internals.
 */
/*
 * Per-insn template-static caps.  Bound the static InsnFields arrays
 * and the dep-mask bit layout; must match the wire format's per-family
 * FID slot ceiling (CST_FID_SLOT_COUNT).  Source regs aren't
 * FID-slotted but the dep-mask layout uses MAX_SRC_REGS as the
 * lower-band boundary, so it grows in lockstep.
 */
#define MAX_SRC_REGS 64
#define MAX_DST_REGS 64
/*
 * Per-insn template-static memop caps.  Match CST_FID_SLOT_COUNT.
 * Real insns stay well below (ARM LD4/ST4 maxes at 4); the cap is
 * generous since cost is per InsnFields slot, not per emitted byte.
 */
#define MAX_STORES   64
#define MAX_LOADS    64

/*
 * Lane-mask dispatch kinds (InsnFields.lane_mask_kind).  Let the
 * exec-time FID extractor compute the lane bitmap via a small switch,
 * no ISA branching in the hot path.  Selection lives in the refiner.
 */
enum LaneMaskKind {
    LANE_MASK_KIND_NONE        = 0,
    LANE_MASK_KIND_STATIC      = 1,
    LANE_MASK_KIND_RISCV_VTYPE = 2,
    /* future: LANE_MASK_KIND_X86_MASKED_K1, LANE_MASK_KIND_AARCH64_SVE_PRED */
};

typedef struct InsnFields {
    uint8_t opcode;                 /* GenericOpcode */
    uint8_t branch_type;            /* BranchType */
    bool    branch_conditional;
    /*
     * True when this insn writes the ISA's integer-flags register
     * (matches RegClassification.is_int_flags).  The encoder then
     * emits a CST_FID_METAFLAGS side-channel record from the REG_FLAGS
     * dst snap; the REG_FLAGS dst slot itself is unchanged.
     */
    bool    writes_int_flags;
    uint8_t n_src_regs;
    uint8_t n_dst_regs;
    uint8_t src_regs[MAX_SRC_REGS];
    uint8_t dst_regs[MAX_DST_REGS];
    bool    has_immediate;
    int64_t immediate;
    /*
     * Static control-transfer target the per-ISA translator resolved
     * for this instruction (the same value handed to gen_goto_tb).
     * Sourced from QEMU's translator via
     * qemu_plugin_insn_branch_target_pc() — NOT from Capstone's
     * immediate operand, since per-ISA encoding (PC-relative vs
     * absolute, sign extension, MIPS delay-slot accounting, ARM
     * Thumb interworking) varies and is already correctly resolved
     * inside the translator.
     *
     * 0 means "no static target": either this insn is not a control
     * transfer, or it's an indirect branch whose target is only known
     * at runtime (the WP resolver falls back to BranchHistory for
     * those).  Wrong-path target selection on direct branches MUST
     * consume this field, not `immediate`.
     */
    uint64_t taken_target_pc;
    /*
     * True for architectural atomic / synchronizing memory ops (x86
     * LOCK RMW/XCHG, AArch64 LDXR/STXR & LDADD/SWP, RISC-V A, MIPS
     * LL/SC).  Drives the CST_INSN_FLAG_ATOMIC wire bit.
     */
    bool    is_atomic;
    /*
     * Template-static MAX memory read/write counts per execution
     * (dynamic per-iteration counts ride CST_FID_N_LOADS /
     * CST_FID_N_STORES deltas).  Also fix the dep-mask bit layout
     * below.  Populated by the operand walker at template-build time;
     * carried in the outer template header.
     */
    uint8_t  max_dep_loads;
    uint8_t  max_dep_stores;
    /*
     * Intra-instruction register dataflow (HAS_REG sub-block).
     * @has_reg_deps true -> encoder sets CST_INSN_FLAG_HAS_DEP_BLOCK
     * and appends n_dst + max_dep_stores ULEB masks; false (default)
     * -> consumers fall back to implicit all-to-all dataflow.
     * Populated by the row's optional .dep_refine.
     *
     * Bit layout inside each register/load mask:
     *   bits [0, n_src_regs)                          src_reg[i]
     *   bits [n_src_regs, n_src_regs + max_dep_loads) load_data[i - n_src_regs]
     *   bit  n_src_regs + max_dep_loads               immediate
     *
     * uint64_t so the imm bit fits when src + load slots stack up.
     */
    bool     has_reg_deps;
    uint64_t dst_dep_mask[MAX_DST_REGS];
    uint64_t store_data_dep_mask[MAX_STORES];
    /*
     * Intra-instruction address dataflow (HAS_ADDR sub-block).
     * Per-memop mask of which template inputs feed its address
     * computation.  Populated structurally by the operand walker (NOT
     * .dep_refine).  Addresses compute before any load fires, so the
     * layout omits load_data slots:
     *
     *   bits [0, n_src_regs)        src_reg[i]
     *   bit  n_src_regs             immediate
     *
     * has_addr_deps trips when at least one MEM operand was seen.
     */
    bool     has_addr_deps;
    uint64_t load_addr_dep_mask[MAX_LOADS];
    uint64_t store_addr_dep_mask[MAX_STORES];
    /*
     * Lane participation (CST_INSN_FLAG_VEC).  Unified runtime path:
     * the refiner picks lane_mask_kind + baseline data; the exec-time
     * FID extractor dispatches on it to compute the lane bitmap and
     * replicates the value across every (src/dst/load_data/store_data)
     * lane-mask FID slot.  Runtime-evaluated for ALL ISAs: static-mask
     * ISAs (x86 / NEON / MSA) return a constant so the delta stream
     * emits one record then zero bytes; dynamic ISAs (RISC-V V SEW,
     * x86 EVEX k, AArch64 SVE) emit deltas as the CSR/mask reg moves.
     *
     * uint64_t mask = AVX-512 ZMM at 8-bit lanes (64); ULEB on the
     * wire so common 4/8/16-lane cases stay one byte per slot.
     *
     * lane_parallel mirrors CST_INSN_FLAG_LANE_PARALLEL: set = dst
     * lane k depends only on src lane k; clear = cross-coupled
     * (shuffles / broadcasts / reductions).
     *
     * Four per-operand mask classes, each its own slotted FID family,
     * delta-emitted on value change.  src_lane_mask[i] / dst_lane_mask[d]
     * are stored here; load/store-data lane masks are computed at emit
     * time from each memop's addr+size vs the access base and
     * lane_bytes (not stored).
     *
     * lane_mask_kind decides ONLY where the active-lane value reads
     * from: NONE (non-vec); STATIC (from the instruction — src/dst
     * masks below are final); RISCV_VTYPE (from the vl CSR at exec —
     * masks are the structural pattern, gate ANDs in (1<<vl)-1).
     * Room for X86_MASKED_K1 / AARCH64_SVE_PRED (same model, gate from
     * EVEX k-mask / SVE predicate).
     */
    bool                  has_vec_lanes;
    bool                  lane_parallel;
    uint8_t               lane_mask_kind; /* LaneMaskKind */
    /* Vector element width in bytes (Capstone-derived).  Needed at
     * emit time to map each memop's byte range onto destination /
     * source lanes for the load/store data lane masks.  0 when the
     * width is data-dependent (RISC-V V SEW) — emit-time falls back
     * to one-memop-per-active-lane ordering. */
    uint8_t               lane_bytes;
    /* Per-operand STRUCTURAL lane participation, indexed parallel to
     * src_regs[] / dst_regs[].  STATIC: these are the final values.
     * Register-sourced kinds: structural pattern AND-ed at exec with
     * the gate read from lane_mask_source_reg. */
    uint64_t              src_lane_mask[MAX_SRC_REGS];
    uint64_t              dst_lane_mask[MAX_DST_REGS];
    /* Capstone-side (feature, name) of the register the dynamic gate
     * reads at exec — vl CSR on RISC-V V, k1 on x86 EVEX masked,
     * predicate reg on AArch64 SVE.  Empty key on STATIC rows. */
    QemuRegKey            lane_mask_source_reg;
    /*
     * x86 REP / REPNZ string-op metadata: memops issued per iteration.
     * The body emitter fans one TB-exec into N iteration entries (iter
     * 1 on the parent BB template, 2..N on its rep_subtmpl 1-insn
     * self-loop sub-template).  Zero on non-REP insns.
     */
    uint8_t  rep_loads_per_iter;
    uint8_t  rep_stores_per_iter;
} InsnFields;


/*
 * Optional post-classification refiner.  Some Capstone insn_ids cover
 * several semantics differing only in operand encoding (e.g. RISC-V
 * JALR = indirect branch / jump / ret by rd/rs1).  .refine fixes up
 * the decoded InsnFields after the generic operand-walk.  ISA-local:
 * defined in the per-ISA table, never referenced by the decoder.
 */
struct qemu_plugin_insn_info; /* fwd-decl: full type from <qemu-plugin.h> */
typedef void (*InsnRefineFn)(const struct qemu_plugin_insn_info *info,
                             InsnFields *fields);

/*
 * Optional dependency refiner.  Reads what the operand-walk and
 * `.refine` populated, then writes dst_dep_mask[] /
 * store_data_dep_mask[], sets n_dep_stores, flips has_reg_deps.
 * Refiner library is small and shared (champsim_tracer_mnemonic_
 * tables.c).  .dep_refine NULL -> no HAS_REG block -> consumer uses
 * the legacy implicit all-to-all fallback (the audit coverage report
 * flags these).  Runs once per unique PC at template build, not hot.
 */
typedef void (*InsnDepRefineFn)(const struct qemu_plugin_insn_info *info,
                                InsnFields *fields);

/*
 * Shared refiners (champsim_tracer_mnemonic_tables.c), referenced in
 * rows via `.dep_refine = dep_<name>`.  Each targets a *dataflow
 * behavior group* — wide coverage across the operand-shape variants
 * (rr / rm / mr / ri / mi / ...) Capstone groups under one insn id.
 * A small complementary set covers the full surface; the audit
 * classifier picks one refiner per Capstone id handling all variants.
 */
void dep_all_to_all(const struct qemu_plugin_insn_info *info,
                    InsnFields *fields);
void dep_passthrough(const struct qemu_plugin_insn_info *info,
                     InsnFields *fields);
void dep_lea(const struct qemu_plugin_insn_info *info,
             InsnFields *fields);
void dep_x86_stack_push(const struct qemu_plugin_insn_info *info,
                        InsnFields *fields);
void dep_x86_stack_pop(const struct qemu_plugin_insn_info *info,
                       InsnFields *fields);
void dep_vec_struct_load(const struct qemu_plugin_insn_info *info,
                         InsnFields *fields);
void dep_vec_struct_store(const struct qemu_plugin_insn_info *info,
                          InsnFields *fields);
void dep_vec_struct_load_interleaved(
    const struct qemu_plugin_insn_info *info, InsnFields *fields);
void dep_vec_struct_store_interleaved(
    const struct qemu_plugin_insn_info *info, InsnFields *fields);

/*
 * Instruction-level vector lane shape from the Capstone operand
 * layout + lane-selecting immediate.  Slot-agnostic; the caller
 * (decode.cc) applies it per operand.
 *
 *   NONE     no usable lane width (consumer falls back to all-to-all).
 *   UNIFORM  packed op (PADDD, NEON ADD, vadd.vv): all lanes live.
 *   INSERT   element insert (PINSR/INSERTPS): WRITE touches only
 *            lane_sel; same-reg READ supplies the other lanes.
 *   EXTRACT  element extract (PEXTR/EXTRACTPS): READ touches only
 *            lane_sel.
 *
 * full_mask = (1<<total_lanes)-1 (~0 for runtime-CSR widths, gated
 * later).
 */
enum LaneShapeKind {
    LANE_SHAPE_NONE = 0,
    LANE_SHAPE_UNIFORM,
    LANE_SHAPE_INSERT,
    LANE_SHAPE_EXTRACT,
};
typedef struct {
    uint8_t  kind;        /* LaneShapeKind */
    uint8_t  lane_bytes;  /* vec element width; 0 = runtime SEW */
    uint64_t full_mask;   /* all participating lanes */
    int16_t  lane_sel;    /* INSERT/EXTRACT selected lane; else -1 */
} LaneShape;

LaneShape lane_shape_from_operands(
    const struct qemu_plugin_insn_info *info, uint8_t lane_mask_kind);

/*
 * Instruction classification entry: Capstone insn_id ->
 * GenericOpcode + BranchType + MnemonicFlags via arrays indexed by
 * the Capstone enum value.  No string-based mnemonic matching.
 * .refine and .dep_refine are independent; when both set, .refine
 * runs first then .dep_refine reads the refined fields.
 */
typedef struct {
    uint8_t         opcode;      /* GenericOpcode */
    uint8_t         branch_type; /* BranchType */
    uint16_t        flags;       /* MnemonicFlags */
    InsnRefineFn    refine;      /* optional, NULL if unused */
    InsnDepRefineFn dep_refine;  /* optional, NULL → emit no HAS_REG block */
    /*
     * Vector lane info, orthogonal to .dep_refine (dep maps are
     * static; existing refiners work for vec ops too).  Drives the
     * dynamic lane-mask FID stream and CST_INSN_FLAG_LANE_PARALLEL:
     *
     *   lane_mask_kind  — NONE (non-vec); STATIC (x86 / NEON / MSA,
     *                     Capstone surfaces the lane count); RISCV_
     *                     VTYPE (RISC-V V, dispatch reads vl at exec).
     *   lane_parallel   — sets the wire bit.  True for element-wise
     *                     vec arith; false for cross-lane ops.
     *
     * decode.cc populates InsnFields.lane_mask_* after .dep_refine;
     * STATIC baseline from the first vec REG operand's (size,
     * lane_bytes) at template build.
     */
    uint8_t         lane_mask_kind;
    bool            lane_parallel;
} InsnClassification;


#ifdef CHAMPSIM_MNEMONIC_TABLES_IMPL

#include "champsim_tracer_mnemonics_x86.h"
#include "champsim_tracer_mnemonics_aarch64.h"
#include "champsim_tracer_mnemonics_riscv.h"
#include "champsim_tracer_mnemonics_mips.h"

/* Classification table selectors (indexed by TraceISA).  Explicit
 * `extern` so the const namespace-scope arrays get external linkage
 * under C++ (default is internal); the #else declarations match. */
extern const RegClassification *const isa_reg_class[];
const RegClassification *const isa_reg_class[] = {
    [TRACE_ISA_UNKNOWN] = NULL,
    [TRACE_ISA_X86]     = x86_reg_class,
    [TRACE_ISA_AARCH64] = aarch64_reg_class,
    [TRACE_ISA_RISCV]   = riscv_reg_class,
    [TRACE_ISA_MIPS]    = mips_reg_class,
};

extern const unsigned isa_reg_class_size[];
const unsigned isa_reg_class_size[] = {
    [TRACE_ISA_UNKNOWN] = 0,
    [TRACE_ISA_X86]     = X86_REG_ENDING,
    [TRACE_ISA_AARCH64] = AARCH64_REG_ENDING,
    [TRACE_ISA_RISCV]   = RISCV_REG_ENDING,
    [TRACE_ISA_MIPS]    = MIPS_REG_ENDING,
};

extern const InsnClassification *const isa_insn_class[];
const InsnClassification *const isa_insn_class[] = {
    [TRACE_ISA_UNKNOWN] = NULL,
    [TRACE_ISA_X86]     = x86_insn_class,
    [TRACE_ISA_AARCH64] = aarch64_insn_class,
    [TRACE_ISA_RISCV]   = riscv_insn_class,
    [TRACE_ISA_MIPS]    = mips_insn_class,
};

extern const unsigned isa_insn_class_size[];
const unsigned isa_insn_class_size[] = {
    [TRACE_ISA_UNKNOWN] = 0,
    [TRACE_ISA_X86]     = X86_INS_ENDING,
    [TRACE_ISA_AARCH64] = AARCH64_INS_ENDING,
    [TRACE_ISA_RISCV]   = RISCV_INS_ENDING,
    [TRACE_ISA_MIPS]    = MIPS_INS_ENDING,
};

#else /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

extern const RegClassification *const isa_reg_class[TRACE_ISA_MIPS + 1];
extern const unsigned isa_reg_class_size[TRACE_ISA_MIPS + 1];
extern const InsnClassification *const isa_insn_class[TRACE_ISA_MIPS + 1];
extern const unsigned isa_insn_class_size[TRACE_ISA_MIPS + 1];

#endif /* CHAMPSIM_MNEMONIC_TABLES_IMPL */


/*
 * Static ISA property table.  One row per ISA; adding an ISA needs
 * only a new row.
 *
 *   branch_delay_slots     — delay-slot insns after a branch (1 MIPS,
 *                            else 0)
 *   pc_relative_branch_imm — Capstone reports direct-branch imm
 *                            relative to the branch PC (RISC-V, MIPS)
 *                            vs absolute (x86, ARM64); the decoder
 *                            normalizes so the wire imm is always
 *                            absolute.
 *   include_implicit_regs  — fold Capstone implicit regs_read/write
 *                            into src/dst.  False where the operand
 *                            walk already covers them (RISC-V, MIPS;
 *                            else double-count).
 *   target_prefixes        — QEMU target_name prefixes for this ISA
 *   cap_arch               — Capstone CS_ARCH_*, or -1 if unsupported
 *   cap_mode_for_target    — derives the Capstone cs_mode bitmask
 *                            from target_name (RISC-V 32/64, MIPS
 *                            endianness)
 */
typedef unsigned int (*CapModeForTargetFn)(const char *target_name);

/*
 * Optional per-ISA hook called by RegHandleCache for every QEMU
 * register descriptor.  May insert alias entries into @handles so
 * Capstone-name lookups resolve to differently-registered descriptors
 * (currently AArch64 SVE z<->v aliasing).  May be null.
 */
typedef void (*RegAliasInserterFn)(
    GHashTable *handles,
    const qemu_plugin_reg_descriptor *desc);

/*
 * Per-ISA integer-flags -> canonical metaflags shuffle.  Takes the
 * raw flags-register value (little-endian u64) and returns the
 * CST_METAFLAGS_* byte.  NULL on ISAs without an integer flags reg
 * (then never called).
 */
typedef uint8_t (*MetaFlagsMapperFn)(uint64_t raw_flags);

/*
 * Per-ISA address canonicalization.  Maps a raw 64-bit value to the
 * form in which a stored pointer and the effective address that
 * dereferences it compare equal: stripping the bits the MMU ignores
 * (AArch64 top-byte tags under TBI, pointer-authentication signature
 * bits) and applying the ISA's canonical sign extension.  The
 * profiler's data-is-address page test (champsim_tracer_output.cc)
 * runs both the observed effective address and the candidate value
 * through this, so a tagged or signed pointer is page-matched against
 * the canonical address space rather than missed.  Never NULL: an
 * ISA that needs no transform supplies an identity function, so the
 * call site is unconditional.
 */
typedef uint64_t (*AddrCanonicalizeFn)(uint64_t addr);

typedef struct {
    uint8_t               branch_delay_slots;
    bool                  pc_relative_branch_imm;
    bool                  include_implicit_regs;
    const char *const    *target_prefixes;
    int                   cap_arch;
    CapModeForTargetFn    cap_mode_for_target;
    RegAliasInserterFn    reg_alias_inserter;
    MetaFlagsMapperFn     flags_to_metaflags;
    AddrCanonicalizeFn    canonicalize_addr;
} IsaProperties;

#ifdef CHAMPSIM_MNEMONIC_TABLES_IMPL

static const char *const isa_prefixes_x86[]     = { "x86_64", "i386", NULL };
static const char *const isa_prefixes_aarch64[] = { "aarch64", NULL };
static const char *const isa_prefixes_riscv[]   = { "riscv64", "riscv32", NULL };
static const char *const isa_prefixes_mips[]    = { "mips64el", "mips64",
                                                    "mipsel", "mips", NULL };

extern const IsaProperties isa_properties[];
const IsaProperties isa_properties[] = {
    [TRACE_ISA_UNKNOWN] = { 0 },
    [TRACE_ISA_X86]     = {
        .include_implicit_regs = true,
        .target_prefixes = isa_prefixes_x86,
        .cap_arch = CS_ARCH_X86,
        .cap_mode_for_target = cap_mode_x86,
        .flags_to_metaflags = x86_flags_to_metaflags,
        .canonicalize_addr = x86_canonicalize_addr,
    },
    [TRACE_ISA_AARCH64] = {
        .include_implicit_regs = true,
        .target_prefixes = isa_prefixes_aarch64,
        .cap_arch = CS_ARCH_AARCH64,
        .cap_mode_for_target = cap_mode_aarch64,
        .reg_alias_inserter = insert_aarch64_reg_aliases,
        .flags_to_metaflags = aarch64_flags_to_metaflags,
        .canonicalize_addr = aarch64_canonicalize_addr,
    },
    [TRACE_ISA_RISCV]   = {
        .include_implicit_regs = false,
        .target_prefixes = isa_prefixes_riscv,
        .cap_arch = CS_ARCH_RISCV,
        .cap_mode_for_target = cap_mode_riscv,
        .canonicalize_addr = riscv_canonicalize_addr,
    },
    [TRACE_ISA_MIPS]    = {
        .branch_delay_slots = 1,
        .include_implicit_regs = false,
        .target_prefixes = isa_prefixes_mips,
        .cap_arch = CS_ARCH_MIPS,
        .cap_mode_for_target = cap_mode_mips,
        .canonicalize_addr = mips_canonicalize_addr,
    },
};

#else /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

extern const IsaProperties isa_properties[TRACE_ISA_MIPS + 1];

#endif /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

