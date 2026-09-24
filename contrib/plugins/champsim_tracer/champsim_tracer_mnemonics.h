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
 * translation time: the register lists an instruction states, and the
 * template's max_dep_loads / max_dep_stores -- the most accesses one
 * execution of the instruction can perform, which the wire's u8 header
 * fields carry and which a record's dynamic CST_FID_N_LOADS/N_STORES
 * may fall short of and never exceed (format.rst §4.5).
 *
 * THE MEMOP CAPS ARE THE WIRE FIELD'S RANGE, NOT A GUESS AT THE WIDEST
 * ENCODING.  They were 64 on the reasoning that a static cap need only
 * cover an encoding's operand list, with ARM LD4/ST4 at 4 as the widest
 * -- false twice over: the maximum is a count of ACCESSES, not operands,
 * and a helper that moves a state area performs one per field.  x86
 * XSAVE/XSAVEOPT perform up to 100 (99 stores and the XSTATE_BV load) and
 * XRSTOR up to 98 loads on a CPU model with MPX and PKRU; a cap of 64
 * clamped the template below what the wire then carried, which is the
 * over-max contract broken by construction.  255 is what max_dep_loads /
 * max_dep_stores can hold.  An instruction that could exceed it is
 * counted (g_qdep.dropped_loads/_stores) and reads over-max, never
 * silently published short.
 *
 * These stay distinct from the wire's per-family FID slot ceiling
 * (CST_FID_SLOT_COUNT, 512), which bounds the DYNAMIC per-execution
 * count -- a rep-string's fan-out is bounded by nothing static -- and the
 * invariant that has to hold between them is static <= dynamic, asserted
 * below: a template-static slot must always be addressable on the wire.
 *
 * THE REGISTER DEP MASKS ARE AS WIDE AS THE POSITIONS THEY INDEX.  A
 * register mask (dst_dep / store_data_dep) stacks n_src_regs +
 * max_dep_loads + 1 (immediate) bit positions, and with the memop caps
 * above that stack runs to 320 -- aarch64 `ld4 {v5.16b-v8.16b}' puts its
 * sixty-fourth element's bit past 64, x86 XRSTOR its ninety-eighth.  The
 * wire's masks are ULEBs with no width of their own, so a mask is held as
 * dep_limbs 64-bit limbs, least significant first (dep_limbs_for()):
 * one limb for every instruction whose positions fit 64, which is every
 * instruction without a wide fan and whose wire bytes are therefore
 * those of a single uint64_t.  Row d of dst_dep_mask is the dep_limbs
 * words at dst_dep_mask + d * dep_limbs; the same for store_data_dep_mask.
 * Every producer and reader goes through dep_row() / dep_test() /
 * dep_set() below, never through a bare shift.  InsnFieldsScratch's
 * build-time arrays are sized by these caps at the widest stride;
 * committed templates are not (their spans are exact-count, exact-stride),
 * so the cost is one scratch per translating thread.
 *
 * The ADDRESS masks stay one uint64_t: their layout omits the load slots
 * (n_src_regs + 1 positions), and n_src_regs is bounded by MAX_SRC_REGS.
 */
#define MAX_SRC_REGS 64
#define MAX_DST_REGS 64
#define MAX_STORES   255
#define MAX_LOADS    255

static_assert(MAX_SRC_REGS <= cst_wire::FID_SLOT_COUNT &&
              MAX_DST_REGS <= cst_wire::FID_SLOT_COUNT &&
              MAX_LOADS    <= cst_wire::FID_SLOT_COUNT &&
              MAX_STORES   <= cst_wire::FID_SLOT_COUNT,
              "a template-static slot must be addressable on the wire");
static_assert(MAX_LOADS <= UINT8_MAX && MAX_STORES <= UINT8_MAX,
              "max_dep_loads / max_dep_stores are u8 on the wire");

/*
 * Bit @pos of a uint64_t mask, or 0 where the position is past its width.
 * For the one-limb ADDRESS masks and lane masks; the register dep masks are
 * multi-limb and use the dep_* accessors below.
 */
static inline uint64_t dep_bit(unsigned pos)
{
    return pos < 64 ? (uint64_t)1 << pos : 0;
}

/* The widest register-mask position stack, and its limb count. */
#define DEP_MASK_MAX_POS    (MAX_SRC_REGS + MAX_LOADS + 1)
#define DEP_MASK_MAX_LIMBS  ((DEP_MASK_MAX_POS + 63) / 64)

/* Limbs a register mask needs for @n_src sources and @n_loads load slots
 * (plus the immediate bit above them); never 0. */
static inline unsigned dep_limbs_for(unsigned n_src, unsigned n_loads)
{
    return (n_src + n_loads + 1 + 63) / 64;
}

/* Is position @pos set in the @limbs-limb mask @row? */
static inline bool dep_test(const uint64_t *row, unsigned limbs, unsigned pos)
{
    return pos / 64 < limbs && ((row[pos / 64] >> (pos % 64)) & 1);
}

/* Set position @pos; false (nothing set) if the mask has no such bit. */
static inline bool dep_set(uint64_t *row, unsigned limbs, unsigned pos)
{
    if (pos / 64 >= limbs) {
        return false;
    }
    row[pos / 64] |= (uint64_t)1 << (pos % 64);
    return true;
}

static inline void dep_clear(uint64_t *row, unsigned limbs, unsigned pos)
{
    if (pos / 64 < limbs) {
        row[pos / 64] &= ~((uint64_t)1 << (pos % 64));
    }
}

/* Set bits of @row at positions [lo, hi). */
static inline unsigned dep_count(const uint64_t *row, unsigned limbs,
                                 unsigned lo, unsigned hi)
{
    unsigned n = 0;

    for (unsigned p = lo; p < hi && p / 64 < limbs; p++) {
        n += (unsigned)((row[p / 64] >> (p % 64)) & 1);
    }
    return n;
}

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
     * Each mask is dep_limbs uint64_t limbs, least significant first,
     * because the stack passes 64 on a wide fan (see the caps comment);
     * dep_row() is row d's first limb.
     */
    bool     has_reg_deps;
    uint8_t  dep_limbs;
    uint64_t *dst_dep_mask;         /* [n_dst_regs * dep_limbs] */
    uint64_t *store_data_dep_mask;  /* [max_dep_stores * dep_limbs] */
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

/* Row @i of a register dep-mask family (dst_dep_mask / store_data_dep_mask). */
static inline uint64_t *dep_row(uint64_t *base, const InsnFields *f, unsigned i)
{
    return base + (size_t)i * f->dep_limbs;
}
static inline const uint64_t *dep_row(const uint64_t *base,
                                      const InsnFields *f, unsigned i)
{
    return base + (size_t)i * f->dep_limbs;
}

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
    uint64_t dst_dep_mask[MAX_DST_REGS * DEP_MASK_MAX_LIMBS];
    uint64_t store_data_dep_mask[MAX_STORES * DEP_MASK_MAX_LIMBS];
    uint64_t load_addr_dep_mask[MAX_LOADS];
    uint64_t store_addr_dep_mask[MAX_STORES];
    uint64_t src_lane_mask[MAX_SRC_REGS];
    uint64_t dst_lane_mask[MAX_DST_REGS];
} InsnFieldsScratch;

static inline void insn_fields_scratch_reset(InsnFieldsScratch *s)
{
    memset(s, 0, sizeof(*s));
    s->f.dep_limbs           = DEP_MASK_MAX_LIMBS;
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


