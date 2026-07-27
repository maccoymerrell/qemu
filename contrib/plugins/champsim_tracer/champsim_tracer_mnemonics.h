/*
 * ISA-specific mnemonic tables for champsim_tracer.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <stdbool.h>
#include <string.h>

#include "champsim_tracer_generic_ids.h"
#include "cst_wire_spec.h"

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
 * Per-insn TEMPLATE-STATIC caps.  These bound what the operand walker
 * may record at translation time — the static register and memop
 * operand counts Capstone reports for one instruction encoding — and
 * they fix the dep-mask bit layout below.
 *
 * They are deliberately NOT the same quantity as the wire's per-family
 * FID slot ceiling (CST_FID_SLOT_COUNT), which bounds the DYNAMIC
 * per-execution memop count.  The two diverge whenever one static memory
 * operand expands into many architectural accesses: x86 XSAVEOPT is a
 * single static store operand that issues 88 stores on a Haswell-class
 * guest, and a rep-string is one static operand with an unbounded
 * dynamic fan-out.  The wire ceiling must cover the dynamic count; the
 * static caps need only cover an encoding's operand list (the widest
 * real case is ARM LD4/ST4 at 4).
 *
 * Keeping the static caps at 64 is load-bearing, not incidental:
 *   - The dep masks are uint64_t.  Their bit layout stacks
 *     n_src_regs + max_dep_loads + 1 (immediate) bits into those 64
 *     bits, and the walker clamps each band independently
 *     (add_src_reg / the max_dep_loads guard in
 *     champsim_tracer_decode.cc), so the layout only has room while the
 *     two bands together stay under 64 — which real encodings do by a
 *     wide margin.  Raising either cap toward the wire ceiling would
 *     make the sum unrepresentable.
 *   - InsnFieldsScratch's build-time backing arrays are sized by these
 *     caps.  Raising them to the wire ceiling would restore exactly the
 *     fixed-64-slot-array footprint that made per-insn metadata dominate
 *     the plugin heap at 3272 B/insn.
 *
 * The invariant that DOES have to hold is static <= dynamic, asserted
 * below: a template-static slot must always be addressable on the wire.
 */
#define MAX_SRC_REGS 64
#define MAX_DST_REGS 64
#define MAX_STORES   64
#define MAX_LOADS    64

static_assert(MAX_SRC_REGS <= cst_wire::FID_SLOT_COUNT &&
              MAX_DST_REGS <= cst_wire::FID_SLOT_COUNT &&
              MAX_LOADS    <= cst_wire::FID_SLOT_COUNT &&
              MAX_STORES   <= cst_wire::FID_SLOT_COUNT,
              "a template-static slot must be addressable on the wire");

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
    /*
     * SPAN MEMBERS.  Every array below is a pointer span sized by its
     * count (noted per member), not a fixed inline array: per-insn
     * metadata dominated the plugin's heap at 3272 B/insn when these
     * were eight fixed 64-slot arrays.  Committed templates point the
     * spans into one per-template pool (BBTemplate::insn_fields_pool);
     * empty spans alias shared zero arrays so out-of-count reads still
     * return 0.  During template BUILD the spans point at the full-size
     * backing of an InsnFieldsScratch (below) so the operand walker and
     * dep/lane refiners can append and compact freely; the pack step at
     * template commit copies exactly the final-count prefixes.  Spans
     * are immutable after commit.  Indexing syntax is unchanged.
     */
    uint8_t *src_regs;              /* [n_src_regs] */
    uint8_t *dst_regs;              /* [n_dst_regs] */
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
    uint64_t *dst_dep_mask;         /* [n_dst_regs] */
    uint64_t *store_data_dep_mask;  /* [max_dep_stores] */
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
    uint64_t *load_addr_dep_mask;   /* [max_dep_loads] */
    uint64_t *store_addr_dep_mask;  /* [max_dep_stores] */
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
    uint64_t              *src_lane_mask;  /* [n_src_regs] */
    uint64_t              *dst_lane_mask;  /* [n_dst_regs] */
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
 * Build-time backing for one InsnFields: full-size arrays for every span
 * so the operand walker and the dep/lane refiners (which append past the
 * walker's counts — x86 stack push/pop — or compact and shrink them —
 * dep_lea, arm64 cmp-alias) always have room.  insn_fields_scratch_reset
 * gives the exact semantics the old fixed-array struct got from a whole-
 * struct memset: everything zero, spans wired to zeroed full-size arrays.
 *
 * SELF-REFERENTIAL: f's spans point into this object.  Never copy, move,
 * or place it in a reallocating container; reuse one instance per insn.
 */
typedef struct InsnFieldsScratch {
    InsnFields f;
    uint8_t  src_regs[MAX_SRC_REGS];
    uint8_t  dst_regs[MAX_DST_REGS];
    uint64_t dst_dep_mask[MAX_DST_REGS];
    uint64_t store_data_dep_mask[MAX_STORES];
    uint64_t load_addr_dep_mask[MAX_LOADS];
    uint64_t store_addr_dep_mask[MAX_STORES];
    uint64_t src_lane_mask[MAX_SRC_REGS];
    uint64_t dst_lane_mask[MAX_DST_REGS];
} InsnFieldsScratch;

static inline void insn_fields_scratch_reset(InsnFieldsScratch *s)
{
    memset(s, 0, sizeof(*s));
    s->f.src_regs            = s->src_regs;
    s->f.dst_regs            = s->dst_regs;
    s->f.dst_dep_mask        = s->dst_dep_mask;
    s->f.store_data_dep_mask = s->store_data_dep_mask;
    s->f.load_addr_dep_mask  = s->load_addr_dep_mask;
    s->f.store_addr_dep_mask = s->store_addr_dep_mask;
    s->f.src_lane_mask       = s->src_lane_mask;
    s->f.dst_lane_mask       = s->dst_lane_mask;
}


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
 *   include_implicit_regs  — fold Capstone implicit regs_read/write
 *                            into src/dst.  False only for RISC-V,
 *                            whose operand walk already covers them
 *                            (folding would double-count); true
 *                            elsewhere, including MIPS, where an
 *                            implicit-only register (HI:LO) would
 *                            otherwise vanish from the dependency chain.
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

/*
 * Per-ISA guest trace-marker encoder.  Writes the ISA's full marker
 * sequence for @imm (CST_MARKER_MAGIC / CST_MARKER_END_MAGIC) into @out
 * and returns the byte count.  The encoders themselves live in the
 * shared champsim_marker.h contract (also built into cst_attach); the
 * ISA row names the one to use.  NULL on an ISA with no marker support,
 * which leaves the window-marker detector disabled.
 */
typedef int (*MarkerEncodeSeqFn)(uint8_t *out, uint32_t imm);

/*
 * Per-ISA system/control-register mapper.  A QEMU_PLUGIN_OP_SYSREG
 * operand carries the ISA's raw system-register encoding (the packed
 * AArch64 op0:op1:CRn:CRm:op2 word, the RISC-V 12-bit CSR number)
 * rather than a Capstone register id, because those numbering spaces
 * are disjoint from the register enum the ordinary reg table is keyed
 * by.  This turns that encoding into a generic register ID.
 *
 * The long tail folds to REG_SYS.  Registers whose own dependency
 * population is worth separating -- the thread pointer, the vector
 * start index, the FP control word -- get their own IDs, because a
 * consumer is misled as badly by an edge onto a register the
 * instruction never touched as by a missing one.  Return REG_NONE to
 * drop the operand entirely.  NULL on an ISA with no system-register
 * operands.
 */
typedef uint8_t (*SysRegToGenericFn)(uint16_t enc);

typedef struct {
    uint8_t               branch_delay_slots;
    bool                  include_implicit_regs;
    const char *const    *target_prefixes;
    int                   cap_arch;
    CapModeForTargetFn    cap_mode_for_target;
    RegAliasInserterFn    reg_alias_inserter;
    MetaFlagsMapperFn     flags_to_metaflags;
    AddrCanonicalizeFn    canonicalize_addr;
    /*
     * xlate_bypass_priv — the privilege level that executes with the
     * paging/translation register bypassed, so pinned attribution must
     * exclude it (RISC-V M-mode runs with satp inert).  -1 means no such
     * level; every row that has none states it explicitly, because a
     * zero-filled default would read as user privilege.
     */
    int                   xlate_bypass_priv;
    /*
     * pin_reuse_asid — arm the ASID-reuse detector.  Set on ISAs whose
     * architectural ASID space is narrow enough that the OS recycles a
     * value within one trace (MIPS pins a bare 8-bit EntryHi.ASID); the
     * wide-register targets leave it clear.
     */
    bool                  pin_reuse_asid;
    /*
     * has_be_variant — the ISA ships a big-endian QEMU target.  The run
     * is big-endian when set unless the target_name carries the
     * little-endian "el" suffix (MIPS mips/mips64 vs mipsel/mips64el);
     * clear for the always-little-endian ISAs.
     */
    bool                  has_be_variant;
    /*
     * marker_encode_seq / marker_insn_bytes / marker_seq_insns — the
     * guest window-marker sequence for this ISA.  marker_encode_seq
     * builds the START/END byte patterns; marker_insn_bytes is the fixed
     * per-insn width in the sequence and marker_seq_insns the insn count,
     * both read by the execution-time adjacency detector.  A NULL encoder
     * (the unknown ISA) leaves the marker detector disabled.
     */
    MarkerEncodeSeqFn     marker_encode_seq;
    uint8_t               marker_insn_bytes;
    uint8_t               marker_seq_insns;
    /* Raw system-register encoding -> generic ID; NULL when the ISA
     * surfaces no QEMU_PLUGIN_OP_SYSREG operands. */
    SysRegToGenericFn     sysreg_to_generic;
} IsaProperties;

#ifdef CHAMPSIM_MNEMONIC_TABLES_IMPL

static const char *const isa_prefixes_x86[]     = { "x86_64", "i386", NULL };
static const char *const isa_prefixes_aarch64[] = { "aarch64", NULL };
static const char *const isa_prefixes_riscv[]   = { "riscv64", "riscv32", NULL };
static const char *const isa_prefixes_mips[]    = { "mips64el", "mips64",
                                                    "mipsel", "mips", NULL };

extern const IsaProperties isa_properties[];
const IsaProperties isa_properties[] = {
    [TRACE_ISA_UNKNOWN] = { .xlate_bypass_priv = -1 },
    [TRACE_ISA_X86]     = {
        .include_implicit_regs = true,
        .target_prefixes = isa_prefixes_x86,
        .cap_arch = CS_ARCH_X86,
        .cap_mode_for_target = cap_mode_x86,
        .flags_to_metaflags = x86_flags_to_metaflags,
        .canonicalize_addr = x86_canonicalize_addr,
        .xlate_bypass_priv = -1,
        .marker_encode_seq = cst_marker_x86_encode_seq_imm,
        .marker_insn_bytes = CST_MARKER_X86_INSN_BYTES,
        .marker_seq_insns  = CST_MARKER_SEQ_LEN,
    },
    [TRACE_ISA_AARCH64] = {
        .include_implicit_regs = true,
        .target_prefixes = isa_prefixes_aarch64,
        .cap_arch = CS_ARCH_AARCH64,
        .cap_mode_for_target = cap_mode_aarch64,
        .reg_alias_inserter = insert_aarch64_reg_aliases,
        .flags_to_metaflags = aarch64_flags_to_metaflags,
        .canonicalize_addr = aarch64_canonicalize_addr,
        .xlate_bypass_priv = -1,
        .marker_encode_seq = cst_marker_a64_encode_seq_imm,
        .marker_insn_bytes = CST_MARKER_PAIR_INSN_BYTES,
        .marker_seq_insns  = CST_MARKER_PAIR_SEQ_INSNS,
        .sysreg_to_generic = aarch64_sysreg_to_generic,
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
        .cap_arch = CS_ARCH_RISCV,
        .cap_mode_for_target = cap_mode_riscv,
        .canonicalize_addr = riscv_canonicalize_addr,
        /* M-mode (normalized priv 3) executes with satp bypassed. */
        .xlate_bypass_priv = 3,
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
        .cap_arch = CS_ARCH_MIPS,
        .cap_mode_for_target = cap_mode_mips,
        .canonicalize_addr = mips_canonicalize_addr,
        .xlate_bypass_priv = -1,
        /* Bare 8-bit EntryHi.ASID; the OS recycles values within a run. */
        .pin_reuse_asid = true,
        /* mips/mips64 are big-endian; mipsel/mips64el carry the "el" suffix. */
        .has_be_variant = true,
        .marker_encode_seq = cst_marker_mips_encode_seq_imm,
        .marker_insn_bytes = CST_MARKER_PAIR_INSN_BYTES,
        .marker_seq_insns  = CST_MARKER_PAIR_SEQ_INSNS,
    },
};

#else /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

extern const IsaProperties isa_properties[TRACE_ISA_MIPS + 1];

#endif /* CHAMPSIM_MNEMONIC_TABLES_IMPL */

