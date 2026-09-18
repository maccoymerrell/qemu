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
 * How a register's VALUE is reached.  A generic id says what the wire
 * publishes; this key says which QEMU register descriptor the value is
 * read out of -- the (feature, name) pair the gdbstub registers it
 * under -- or { NULL, NULL } when no single QEMU register holds it.
 * The generic-id-to-key join itself is generated per ISA into
 * champsim_tracer_gdbmap_<isa>.h.
 */
#define MAX_REG_ALIASES 8

typedef struct {
    const char *feature;
    const char *name;
} QemuRegKey;

/* A key with no name routes nowhere: the register has no value read. */
static inline bool qemu_reg_key_valid(const QemuRegKey *key)
{
    return key && key->name;
}

/*
 * Decoded per-instruction generic fields.  In this header (not
 * champsim_tracer.h) so the C tables-TU refiners can mutate fields
 * without the rest of the tracer internals.
 */
/*
 * Per-insn TEMPLATE-STATIC caps.  These bound what may be recorded at
 * translation time — the static register and memop operand counts one
 * instruction encoding can state — and they fix the dep-mask bit
 * layout below.
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
 *     (the per-band guards in
 *     champsim_tracer_qdep.cc), so the layout only has room while the
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
     * qemu_plugin_insn_branch_target_pc() — never re-derived from the
     * encoded immediate, since per-ISA encoding (PC-relative vs
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
    /* Vector element width in bytes, stated by the target's own decode
     * rule alongside the lane kind and selector.  Needed at
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
    /* The (feature, name) key of the register the dynamic gate
     * reads at exec — vl CSR on RISC-V V, k1 on x86 EVEX masked,
     * predicate reg on AArch64 SVE.  Empty key on STATIC rows. */
    QemuRegKey            lane_mask_source_reg;
    /*
     * Self-loop fan-out metadata: memops issued per fanned-out
     * iteration.  Nonzero marks an instruction whose single execution
     * is split into N body entries (iter 1 on the parent BB template,
     * 2..N on its rep_subtmpl 1-insn self-loop sub-template), so an
     * instruction with an unbounded memory fan-out reaches the wire
     * whole instead of being clamped at CST_FID_SLOT_COUNT.
     *
     * The value is the fan-out UNIT, and it differs by family:
     *
     *   x86 REP / REPNZ string ops — the iteration is architectural
     *     (RCX decrements once per element), so the unit is one
     *     element: loads + stores per iteration, stated by the x86
     *     decode rule and carried through self_loop_memops
     *     (champsim_tracer_qdep.cc).
     *
     *   AArch64 FEAT_MOPS bulk copy/set — the instruction has NO
     *     architectural iteration (QEMU's copy_step/set_step move up
     *     to a page per step, an implementation detail), so the unit
     *     is one memory access: 1.  That is also the only unit robust
     *     to the arrival ORDER, which for a copy is a run of loads
     *     followed by a run of stores (one bulk callback per step per
     *     direction), not the interleaved load/store pairs a REP
     *     string op produces.
     *
     * Zero on everything else.
     */
    uint8_t  rep_memops_per_iter;
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
 * Static ISA property table.  One row per ISA; adding an ISA needs
 * only a new row.
 *
 *   branch_delay_slots     — delay-slot insns after a branch (1 MIPS,
 *                            else 0)
 *   include_implicit_regs  — whether a reference decoder's implicit
 *                            regs_read/regs_write lists have to be
 *                            folded in to reach the set this ISA's
 *                            QEMU rules already state.  False only for
 *                            RISC-V, whose operand list already covers
 *                            them; true elsewhere, including MIPS,
 *                            where an implicit-only register (HI:LO)
 *                            would otherwise be missing.  Nothing in
 *                            the plugin reads it: it is the row the
 *                            OFFLINE referee (tools/cst_referee.py)
 *                            follows so its column is comparable with
 *                            the wire's.
 *   target_prefixes        — QEMU target_name prefixes for this ISA
 */

/*
 * Optional per-ISA hook called by RegHandleCache for every QEMU
 * register descriptor.  May insert alias entries into @handles so a
 * lookup under one name resolves to a differently-registered descriptor
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

typedef struct {
    uint8_t               branch_delay_slots;
    bool                  include_implicit_regs;
    const char *const    *target_prefixes;
    RegAliasInserterFn    reg_alias_inserter;
    MetaFlagsMapperFn     flags_to_metaflags;
    AddrCanonicalizeFn    canonicalize_addr;
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
} IsaProperties;

extern const IsaProperties isa_properties[TRACE_ISA_MIPS + 1];


