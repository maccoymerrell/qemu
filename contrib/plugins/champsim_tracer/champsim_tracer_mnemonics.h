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
    MF_ATOMIC           = (1 << 1),  /* Atomic/locked memory op (LOCK prefix,
                                      * x86 XCHG, AArch64 LDXR/STXR, RISC-V A
                                      * extension, MIPS LL/SC) — sets the
                                      * CST_INSN_FLAG_ATOMIC bit on the wire. */
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
/*
 * Per-insn template-static caps.  These bound the static InsnFields
 * arrays and the dep-mask bit-position layout; they must match the
 * wire format's per-family FID slot ceiling (CST_FID_SLOT_COUNT) so
 * a template can carry a slot for every dst/load/store the static
 * instruction can produce.  Bumped to 64 alongside the FID widening
 * in commit 3f9ea8bf12.
 *
 * Source regs aren't FID-slotted (sources are template-fixed; the
 * runtime varies only outputs and addresses) but the dep-mask bit
 * layout uses MAX_SRC_REGS as the lower-band boundary, so it grows
 * in lockstep.
 */
#define MAX_SRC_REGS 64
#define MAX_DST_REGS 64
/*
 * Per-insn template-static memop caps.  Match CST_FID_SLOT_COUNT so
 * any static insn that fits the FID load/store ranges also fits its
 * template-time dep-mask arrays.  Real static instructions stay well
 * below these (ARM LD4/ST4 maxes at 4); the cap is generous because
 * the storage cost is per InsnFields slot, not per emitted byte.
 */
#define MAX_STORES   64
#define MAX_LOADS    64

/*
 * Lane-mask dispatch kinds.  Stored in InsnFields.lane_mask_kind so
 * the exec-time FID extractor (champsim_tracer_output.cc) can compute
 * the current lane bitmap with no ISA branching in the hot path —
 * just a small switch.  ISA-specific selection lives in the refiner.
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
    /*
     * True when this insn is an architectural atomic / synchronizing
     * memory op (x86 LOCK-prefixed RMW or XCHG, AArch64 LDXR/STXR and
     * LDADD/SWP families, RISC-V A extension, MIPS LL/SC).  Drives the
     * CST_INSN_FLAG_ATOMIC bit on the wire so consumers can model
     * pipeline serialization without re-deriving it from mnemonic
     * strings.
     */
    bool    is_atomic;
    /*
     * Template-static MAX counts.  These are the upper bounds on how
     * many memory reads and writes the static instruction can issue
     * *per execution*; the dynamic per-iteration count is conveyed
     * runtime-side via CST_FID_N_LOADS / CST_FID_N_STORES deltas.
     *
     * They also fix the bit layout inside dep masks (see below) so
     * the consumer can map mask bits to input slots unambiguously.
     *
     * Populated by the operand walker at template-build time from
     * MEM operand access flags.  Carried on the wire in the outer
     * template header.
     */
    uint8_t  max_dep_loads;
    uint8_t  max_dep_stores;
    /*
     * Intra-instruction register dataflow (HAS_REG sub-block).
     * When @has_reg_deps is true, the wire-format encoder emits
     * CST_INSN_FLAG_HAS_DEP_BLOCK in the template-insn flag byte and
     * appends n_dst + max_dep_stores ULEB-encoded masks after the
     * insn bytes.  When false (the default), the template carries
     * no register-side masks and consumers fall back to the implicit
     * all-to-all dataflow for that family.
     *
     * Populated by the row's optional .dep_refine callback.
     *
     * Bit layout inside each register/load mask:
     *   bits [0, n_src_regs)                          src_reg[i]
     *   bits [n_src_regs, n_src_regs + max_dep_loads) load_data[i - n_src_regs]
     *   bit  n_src_regs + max_dep_loads               immediate
     *
     * Mask type is uint64_t so the imm bit fits when both src_regs
     * and load slots stack up; real instructions don't push close
     * to that ceiling but the storage cost is template-only.
     */
    bool     has_reg_deps;
    uint64_t dst_dep_mask[MAX_DST_REGS];
    uint64_t store_data_dep_mask[MAX_STORES];
    /*
     * Intra-instruction address dataflow (HAS_ADDR sub-block).
     * Per-memop "when can this load/store fire" mask: which template
     * inputs feed its address computation.  Populated structurally
     * by the operand walker (NOT by .dep_refine) — every MEM operand
     * the walker encounters contributes a mask saying which src_reg
     * slots its addressing-mode regs landed in.  Addresses are
     * computed before any load fires, so the bit layout omits the
     * load_data slots:
     *
     *   bits [0, n_src_regs)        src_reg[i]
     *   bit  n_src_regs             immediate
     *
     * Consumers use these to schedule load/store firing precisely
     * (avoid waiting on dst-as-src for RMW forms, etc.); refiners
     * leave them alone.  has_addr_deps trips when at least one MEM
     * operand was seen.
     */
    bool     has_addr_deps;
    uint64_t load_addr_dep_mask[MAX_LOADS];
    uint64_t store_addr_dep_mask[MAX_STORES];
    /*
     * Lane participation (CST_INSN_FLAG_VEC).  Unified runtime path:
     * the refiner picks a lane_mask_kind and stashes any data it
     * needs (baseline AND mask, optional source reg).  The exec-time
     * FID extractor dispatches on lane_mask_kind to compute the
     * current lane bitmap, then replicates the same value across
     * every (src/dst/load_data/store_data) lane-mask FID slot for
     * this insn.
     *
     * Treating lane mask as runtime-evaluated for ALL ISAs is the
     * point — for static-mask ISAs (x86 / aarch64 NEON / MIPS MSA)
     * the dispatch returns the same value every call, so the field-
     * delta stream emits one record per (template, insn-pos, slot)
     * at first observation and zero bytes thereafter.  For dynamic
     * ISAs (RISC-V V SEW changes, x86 EVEX masked variants, AArch64
     * SVE predicates) the dispatch reads the runtime CSR / mask reg
     * each call and the stream emits deltas as the value moves.
     *
     * Mask width is uint64_t — enough for AVX-512 ZMM at 8-bit lane
     * granularity (64 lanes).  On the wire each mask ULEB-encodes,
     * so common 4/8/16-lane cases stay one byte per slot.
     *
     * lane_parallel mirrors CST_INSN_FLAG_LANE_PARALLEL on the wire:
     *   - set: bit k of dst lanes depends only on bit k of src lanes.
     *   - clear: lanes touch but cross-couple (shuffles / broadcasts
     *     / horizontal reductions).
     *
     * lane_mask_kind values:
     *   LANE_MASK_KIND_NONE        — non-vec insn (has_vec_lanes off).
     *   LANE_MASK_KIND_STATIC      — return lane_mask_base unchanged.
     *                                Used by x86 / aarch64 NEON / MIPS
     *                                MSA where Capstone surfaces the
     *                                static lane count.
     *   LANE_MASK_KIND_RISCV_VTYPE — read RISC-V vtype CSR, compute
     *                                (1 << VL_FIELD) - 1.  Covers
     *                                both vsetvli (immediate) and
     *                                vsetvl (register) since the CSR
     *                                read is at exec time.
     *   (room for LANE_MASK_KIND_X86_MASKED_K1 and
     *    LANE_MASK_KIND_AARCH64_SVE_PRED in future commits.)
     */
    bool                  has_vec_lanes;
    bool                  lane_parallel;
    uint8_t               lane_mask_kind; /* LaneMaskKind */
    /* Refiner-set baseline AND mask.  STATIC dispatch returns this
     * directly; dynamic dispatches AND it with the read register
     * value (e.g. predicate AND lane-count mask). */
    uint64_t              lane_mask_base;
    /* Capstone-side (feature, name) for the register the dynamic
     * dispatch should read at exec time — vtype CSR on RISC-V V,
     * k1 on x86 EVEX masked, predicate reg on AArch64 SVE.  Empty
     * key on STATIC rows. */
    QemuRegKey            lane_mask_source_reg;
    /*
     * x86 REP / REPNZ string-op metadata.  Non-zero on insns whose
     * Capstone detail carried info->has_rep; both fields capture the
     * memops this insn issues *per iteration* (one architectural
     * REP loop).  Used by the body emitter to fan a single TB-exec
     * into N iteration entries: iter 1 stays on the parent BB
     * template, iter 2..N emit on the parent's rep_subtmpl (a
     * 1-insn self-loop sub-template built at translation time).
     * Zero on non-REP insns.
     */
    uint8_t  rep_loads_per_iter;
    uint8_t  rep_stores_per_iter;
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
 * Optional dependency refiner.
 *
 * Reads what the generic operand-walk and any `.refine` callback have
 * already populated in @fields, then writes dst_dep_mask[] and
 * store_data_dep_mask[], sets n_dep_stores, and flips has_reg_deps.
 *
 * The refiner library is small and shared across ISAs (defined in
 * champsim_tracer_mnemonic_tables.c).  A row may point at one of the
 * shared refiners or supply its own one-off (rare; the typical case
 * picks a shape from the library).  Rows that leave .dep_refine NULL
 * emit no HAS_REG block, which the consumer interprets as the legacy
 * "implicit all-to-all" fallback; the audit script's coverage report
 * flags these so unintentional fallbacks can be promoted to explicit
 * classifications over time.
 *
 * Runs once at template-construction time (per unique PC), not on the
 * hot path during tracing.
 */
typedef void (*InsnDepRefineFn)(const struct qemu_plugin_insn_info *info,
                                InsnFields *fields);

/*
 * Shared refiners (defined in champsim_tracer_mnemonic_tables.c).
 * Per-ISA mnemonic tables reference these directly in row
 * initialisers via `.dep_refine = dep_<name>`.
 *
 * Each refiner targets a *dataflow behavior group* — wide coverage
 * across the operand-shape variants Capstone groups under a single
 * insn id (rr / rm / mr / ri / mi / ...).  A small complementary
 * set of refiners covers the full classification surface; the audit
 * script's classifier picks one refiner per Capstone id that
 * correctly handles every variant of that id.
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
void dep_vec_lane_parallel(const struct qemu_plugin_insn_info *info,
                           InsnFields *fields);
void dep_vec_lane_cross(const struct qemu_plugin_insn_info *info,
                        InsnFields *fields);
/* RISC-V V variants — same shape as dep_vec_lane_{parallel,cross}
 * but pick LANE_MASK_KIND_RISCV_VTYPE so the exec-time dispatch
 * reads vl at runtime.  Referenced only from the RISC-V mnemonic
 * table — generic library code stays ISA-agnostic. */
void dep_riscv_v_lane_parallel(const struct qemu_plugin_insn_info *info,
                               InsnFields *fields);
void dep_riscv_v_lane_cross(const struct qemu_plugin_insn_info *info,
                            InsnFields *fields);

/*
 * Instruction classification entry: maps a Capstone insn_id directly
 * to GenericOpcode + BranchType + MnemonicFlags via designated-initializer
 * arrays indexed by the Capstone enum value.  Eliminates all string-based
 * mnemonic matching (hash tables, regex, prefix stripping, caches).
 *
 * `.refine` and `.dep_refine` are independent optional callbacks.
 * When both are set, `.refine` runs first (it may rewrite
 * src_regs/dst_regs/has_immediate etc.), then `.dep_refine` reads the
 * refined fields to produce dep masks.
 */
typedef struct {
    uint8_t         opcode;      /* GenericOpcode */
    uint8_t         branch_type; /* BranchType */
    uint16_t        flags;       /* MnemonicFlags */
    InsnRefineFn    refine;      /* optional, NULL if unused */
    InsnDepRefineFn dep_refine;  /* optional, NULL → emit no HAS_REG block */
} InsnClassification;


#ifdef CHAMPSIM_MNEMONIC_TABLES_IMPL

#include "champsim_tracer_mnemonics_x86.h"
#include "champsim_tracer_mnemonics_aarch64.h"
#include "champsim_tracer_mnemonics_riscv.h"
#include "champsim_tracer_mnemonics_mips.h"

/* Classification table selectors (indexed by TraceISA).  Explicit
 * `extern` so the const namespace-scope arrays get external linkage
 * under C++ (default would be internal).  The matching declarations
 * in the consumer #else branch use the same `extern`. */
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

extern const IsaProperties isa_properties[];
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

extern const IsaProperties isa_properties[TRACE_ISA_MIPS + 1];

#endif /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

