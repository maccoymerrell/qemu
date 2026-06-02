/*
 * Wrong-Path Tracing Plugin — shared types and plugin-wide globals.
 *
 * Private header: wire-format constants (CST_*, BODY_TAG_*, CST_FID_*),
 * shared POD types, plugin-wide globals, and cross-TU declarations.
 * Subsystem-private state lives in each subsystem's own header.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CHAMPSIM_TRACER_H
#define CHAMPSIM_TRACER_H

/* <atomic> is C++-only; pull it in first so its transitive includes
 * resolve before glib does. */
#ifdef __cplusplus
#include <atomic>
#include <vector>
#endif

#include <glib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern "C" {
#include <qemu-plugin.h>
}

#include "cst_wire_spec.h"

#include "champsim_tracer_mnemonics.h"

/*
 * The plugin is dlopen'd, so by default every thread_local resolves
 * through the general-dynamic TLS model (a __tls_get_addr call per
 * access — ~4-5% of plugin time in a wp+memdata+regdata profile,
 * concentrated in the per-memop / per-insn callbacks and the emit
 * path).  initial-exec collapses each access to a single %fs-relative
 * load with no call, but consumes the loader's finite static-TLS
 * surplus, so it must be applied selectively: only to the small,
 * hot thread_locals on the CP/WP critical path.  The large caches
 * (e.g. RegHandleCache::tls_ptr_cache_, ~4 KiB) deliberately stay on
 * general-dynamic to keep the IE footprint within surplus.
 *
 * Apply to BOTH the definition and any extern declaration of the same
 * variable — a model mismatch is an ODR/codegen hazard.
 */
#define CST_TLS_HOT __attribute__((tls_model("initial-exec")))

/* ===== Constants ===== */
/* Wire-format invariants aliased from the shared spec (cst_wire_spec.h)
 * so the plugin and the offline tools can't diverge. */
#define MAX_INSN_BYTES (cst_wire::INSN_BYTES_MAX)
/* MAX_SRC_REGS / MAX_DST_REGS now live in champsim_tracer_mnemonics.h
 * (alongside the InsnFields struct they size) so per-ISA mnemonic refiners
 * compiled in the C tables TU can manipulate InsnFields directly. */

/*
 * Binary format magic ("CST" + version 0x1D, u32 LE).  Wire format
 * fully specified in champsim_tracer_format.md.  Key invariants:
 * scalar fields carry a signed LEB delta against the active overlay's
 * most-recent observation (WP falls back to CP; template-default on
 * first appearance); WP state persists across chains, CP is the
 * architectural truth.  Templates track true BBs (start_pc to first
 * branch, immutable, unique by start_pc).
 */
#define CST_MAGIC          (cst_wire::MAGIC)

/*
 * REG_METAFLAGS bit layout is defined in champsim_tracer_generic_ids.h
 * (CST_METAFLAGS_*).  Kept there alongside the GenericRegId enum so
 * the per-ISA mnemonic tables (C-only TU) can populate the canonical
 * byte without depending on this header's plugin-API surface.
 */

/* Body entry tags (1 byte) */
#define BODY_TAG_END             0
#define BODY_TAG_ENTRY           1
#define BODY_TAG_THREAD_SWITCH   2
/*
 * BODY_TAG_IFRAME: self-contained absolute snapshot of the preceding
 * ENTRY (same payload minus tmpl_delta; inherits the ENTRY's
 * template_id), every field encoded against a fresh "nothing observed"
 * overlay.  Re-emits ALL of the CP entry's WP-chain entries too.
 * Pure validation/resync: does NOT advance the writer's persistent
 * overlays or prev_entry_template; decoders may safely skip IFRAMEs.
 */
#define BODY_TAG_IFRAME          3
/*
 * BODY_TAG_REGFILE: per-thread initial register-file snapshot, emitted
 * once per (segment, thread_id) before that thread's first ENTRY, so
 * consumers can prime each vCPU's state independently.  Absolute
 * values.  width=0 means the plugin couldn't resolve a live value
 * (e.g. install-time pre-vCPU snapshot): leave that slot uninitialised.
 * Wire format spec'd in champsim_tracer_format.md.
 */
#define BODY_TAG_REGFILE         4

/*
 * Per-insn template flags byte
 *
 *   bit 0    BRANCH_COND
 *   bit 1    HAS_IMM
 *   bit 2    ATOMIC         — atomic / locked memory op
 *   bit 3    (reserved)
 *   bit 4    VEC            — per-slot lane bitmaps present
 *   bit 5    LANE_PARALLEL  — lane bitmaps line up by lane index
 *                             (consumer can model per-lane chains).
 *                             LANE_PARALLEL implies VEC.
 *   bit 6    HAS_DEP_BLOCK
 *   bit 7    (reserved)
 *
 * VEC and LANE_PARALLEL are orthogonal:
 *   - VEC: per-slot lane bitmaps present on the wire (useful even for
 *     cross-lane ops since rename-slot allocation cares about lane
 *     participation regardless of parallelism).
 *   - LANE_PARALLEL: lane bitmaps line up by lane index so the
 *     consumer can model independent per-lane chains.  Set on
 *     element-wise vec arithmetic; cleared on shuffle/cross-lane/
 *     reduction.  Implies VEC.
 */
#define CST_INSN_FLAG_BRANCH_COND   (1u << 0)
#define CST_INSN_FLAG_HAS_IMM       (1u << 1)
#define CST_INSN_FLAG_ATOMIC        (1u << 2)
#define CST_INSN_FLAG_VEC           (1u << 4)
#define CST_INSN_FLAG_LANE_PARALLEL (1u << 5)
/*
 * Intra-instruction dataflow sub-block.  When set, an
 * extensible dependency block follows insn_bytes:
 *
 *   dep_block_flags : u8
 *     bit 0  DEP_BLOCK_HAS_REG   — dst_dep + store_data_dep present
 *     bit 1  DEP_BLOCK_HAS_ADDR  — load_addr_dep + store_addr_dep present
 *     bits 2..7 reserved
 *
 *   if HAS_REG:
 *     dst_dep[d]        : ULEB   for d in 0..n_dst-1
 *     store_data_dep[s] : ULEB   for s in 0..max_dep_stores-1
 *   if HAS_ADDR:
 *     load_addr_dep[l]  : ULEB   for l in 0..max_dep_loads-1
 *     store_addr_dep[s] : ULEB   for s in 0..max_dep_stores-1
 *
 * Mask array sizes (n_dst, max_dep_loads, max_dep_stores) all come
 * from the outer template header — the dep block itself carries no
 * size bytes.
 *
 * Bit layout inside each register/load mask:
 *   bits [0, n_src)                            depends on src_reg[i]
 *   bits [n_src, n_src + max_dep_loads)        depends on load_data[i - n_src]
 *   bit  n_src + max_dep_loads                 depends on the immediate
 *
 * Address masks omit the load_data bits (addresses are computed
 * before any load fires):
 *   bits [0, n_src)                       depends on src_reg[i]
 *   bit  n_src                            depends on the immediate
 *
 * Absence of CST_INSN_FLAG_HAS_DEP_BLOCK (or of a sub-family within
 * it) means the implicit all-to-all over-approximation (every dst /
 * store / mem-op depends on every input).  HAS_REG carries
 * refiner-produced output deps; HAS_ADDR carries walker-produced
 * per-memop address deps.  Future sub-flags stay inside the block so
 * the per-insn flag byte doesn't grow.
 */
#define CST_INSN_FLAG_HAS_DEP_BLOCK (1u << 6)
/* bit 7 reserved */

/* dep_block_flags bits inside the optional dependency sub-block. */
#define CST_DEP_BLOCK_HAS_REG       (1u << 0)
#define CST_DEP_BLOCK_HAS_ADDR      (1u << 1)

/* WP event flags byte */
#define CST_WP_EVENT_TRANSLATION_UNAVAIL (1u << 0)
#define CST_WP_EVENT_FAULT               (1u << 1)

/* WP-invocation envelope flags byte */
#define CST_WP_INV_CHAIN_REF      (1u << 0)
/* bits 1..7 reserved */

/* Header feature flags.  MEM_DATA / REG_DATA advise which optional
 * field-ID families may appear (the field IDs still determine actual
 * presence).  PROFILE / WP are structural gates: they decide whether
 * a whole block is present (the §6 template profile block, and the
 * per-entry wrong-path chain + events sections respectively).  See
 * champsim_tracer_format.md "Format Stability and Conformance". */
#define CST_FLAG_MEM_DATA      (1 << 0)  /* CST_FID_LOAD_DATA / STORE_DATA */
#define CST_FLAG_REG_DATA      (1 << 1)  /* CST_FID_DST_REG values        */
#define CST_FLAG_PROFILE       (1 << 2)  /* §6 profile block per template  */
#define CST_FLAG_WP            (1 << 3)  /* per-entry WP chain + events    */
/* bits 4..7 reserved */

/* ===== Field-ID space (unified delta stream) =====
 *
 * Each per-entry observation is one record; field IDs are ULEB128.
 * Slotted families are interleaved-by-slot so slot k's five family
 * IDs are contiguous, keeping low slots in the 1-byte ULEB range
 * alongside the hot singletons (slot 0..24 → 1 byte, 25..63 → 2).
 * See champsim_tracer_format.md §5.1.
 */
#define CST_FID_SLOT_COUNT       (cst_wire::FID_SLOT_COUNT)  /* slots per slotted family */
#define CST_FID_SLOT_STRIDE      8    /* family IDs per slot (== family count) */
#define CST_MAX_WIDE_BYTES       (cst_wire::WIDE_BYTES_MAX)  /* 512-bit data/reg scalar cap */

/* Hot singletons — kept in the 0..127 1-byte ULEB range. */
#define CST_FID_N_LOADS          0
#define CST_FID_N_STORES         1
#define CST_FID_METAFLAGS        2

/* Slotted families.  Slot k of family f lives at
 *   CST_FID_<FAMILY>_BASE + k * CST_FID_SLOT_STRIDE
 * Bases are adjacent (3..10) so slot 0 of all eight families plus the
 * three hot singletons occupy IDs 0..10.  No source-value family
 * exists: consumers reconstruct any register's current value from
 * the regfile + accumulated DST_REG snapshots.
 *
 * The *_SIZE / *_WIDTH families carry the byte width of each captured
 * memop value / destination-register write (1..CST_MAX_WIDE_BYTES) for
 * value-prediction consumers; the width is not derivable from the
 * magnitude-suppressed SLEB value, nor statically across ISAs (RVV SEW,
 * SVE VL).  They are gated with their value families and, being mostly
 * static per slot, cost one delta record per slot per segment.
 */
#define CST_FID_LOAD_ADDR_BASE      3    /* slot k at base + STRIDE*k  */
#define CST_FID_STORE_ADDR_BASE     4
#define CST_FID_LOAD_DATA_BASE      5    /* gated by CST_FLAG_MEM_DATA */
#define CST_FID_STORE_DATA_BASE     6
#define CST_FID_DST_REG_BASE        7    /* gated by CST_FLAG_REG_DATA */
#define CST_FID_LOAD_SIZE_BASE      8    /* gated by CST_FLAG_MEM_DATA */
#define CST_FID_STORE_SIZE_BASE     9    /* gated by CST_FLAG_MEM_DATA */
#define CST_FID_DST_REG_WIDTH_BASE  10   /* gated by CST_FLAG_REG_DATA */

/* Last slotted ID = base of the final family + (SLOT_COUNT-1) * STRIDE.
 * Lane-mask block + insn-metadata start immediately after. */
#define CST_FID_SLOTTED_END      (CST_FID_DST_REG_WIDTH_BASE + \
                                  (CST_FID_SLOT_COUNT - 1) * CST_FID_SLOT_STRIDE)

/* Lane-mask block.  Kept out of the hot slotted block so the cheap
 * 1-byte ULEB range stays reserved for per-entry memop/dst-reg FIDs;
 * static-case lane masks cost zero record bytes via field-delta
 * encoding anyway.  Four families, same per-slot bitmap shape (bit k
 * = lane k participates): SRC/DST per reg slot; LOAD_DATA/STORE_DATA
 * per memop (which lanes of the consuming/source reg the memop
 * fills/drains).  Refiner-set template baseline; FID deltas override
 * at runtime for predicated forms (EVEX k1, RVV vtype.VL, SVE).
 * Consumers combine e.g. dst_lane_mask[d] ∩ load_data_lane_mask[k];
 * gather/scatter (one memop per lane) drove the memop-side masks.
 */
#define CST_FID_LANE_BLOCK_BASE          (CST_FID_SLOTTED_END + 1)
#define CST_FID_LANE_BLOCK_STRIDE        4
#define CST_FID_SRC_LANE_MASK_BASE       (CST_FID_LANE_BLOCK_BASE + 0)
#define CST_FID_DST_LANE_MASK_BASE       (CST_FID_LANE_BLOCK_BASE + 1)
#define CST_FID_LOAD_DATA_LANE_MASK_BASE (CST_FID_LANE_BLOCK_BASE + 2)
#define CST_FID_STORE_DATA_LANE_MASK_BASE (CST_FID_LANE_BLOCK_BASE + 3)
#define CST_FID_LANE_BLOCK_END           (CST_FID_STORE_DATA_LANE_MASK_BASE + \
                                          (CST_FID_SLOT_COUNT - 1) * \
                                          CST_FID_LANE_BLOCK_STRIDE)

/* Cold instruction-metadata fields.  Baseline = template's static
 * value (unchanged fields cost zero bytes).  2-byte ULEBs.          */
#define CST_FID_INSN_BYTES_LO    (CST_FID_LANE_BLOCK_END + 1)  /* low 8 bytes of insn_bytes, LE u64 */
#define CST_FID_INSN_BYTES_HI    (CST_FID_LANE_BLOCK_END + 2)  /* high 8 bytes (x86 long enc.)      */
#define CST_FID_INSN_OPCODE      (CST_FID_LANE_BLOCK_END + 3)
#define CST_FID_INSN_BRANCH_TYPE (CST_FID_LANE_BLOCK_END + 4)
#define CST_FID_INSN_FLAGS       (CST_FID_LANE_BLOCK_END + 5)
#define CST_FID_INSN_IMMEDIATE   (CST_FID_LANE_BLOCK_END + 6)
#define CST_FID_INSN_SIZE        (CST_FID_LANE_BLOCK_END + 7)
#define CST_FID_EXTENDED         (CST_FID_LANE_BLOCK_END + 8)  /* reserved escape */

/* Total well-known field-id count, for sanity / encoding-map size. */
#define CST_FID_COUNT            (CST_FID_EXTENDED + 1)

/* ===== Types ===== */

/* InsnFields is defined in champsim_tracer_mnemonics.h. */

/*
 * Little-endian unsigned scalar used for dynamic data/register values.
 * The wire format deltas this modulo 2**512 and emits the signed LEB
 * two's-complement result; small values still take the usual short LEB.
 */
typedef struct {
    uint64_t limb[CST_MAX_WIDE_BYTES / sizeof(uint64_t)];
} CSTWideValue;

static inline void cst_wide_zero(CSTWideValue *v)
{
    memset(v, 0, sizeof(*v));
}

static inline CSTWideValue cst_wide_from_u64(uint64_t x)
{
    CSTWideValue v;
    cst_wide_zero(&v);
    v.limb[0] = x;
    return v;
}

static inline CSTWideValue cst_wide_from_i64(int64_t x)
{
    CSTWideValue v;
    uint64_t fill = x < 0 ? UINT64_MAX : 0;
    for (size_t i = 0; i < G_N_ELEMENTS(v.limb); i++) {
        v.limb[i] = fill;
    }
    v.limb[0] = (uint64_t)x;
    return v;
}

static inline void cst_wide_from_le_bytes(CSTWideValue *out,
                                          const uint8_t *bytes,
                                          size_t len)
{
    cst_wide_zero(out);
    if (!bytes || len == 0) {
        return;
    }
    if (len > CST_MAX_WIDE_BYTES) {
        len = CST_MAX_WIDE_BYTES;
    }
    memcpy(out->limb, bytes, len);
}

/* In-place target-endian -> little-endian normalisation for a buffer
 * returned by qemu_plugin_read_register().  No-op on LE targets (and
 * for length-1 buffers); on BE targets the buffer is byte-reversed so
 * downstream encoders can treat the bytes as little-endian.  Forward
 * declaration of the global so this header-only helper compiles before
 * the canonical extern in the plugin-wide globals block below. */
extern bool target_big_endian;
static inline void cst_normalize_reg_bytes_to_le(uint8_t *bytes, size_t len)
{
    if (!target_big_endian || !bytes || len < 2) {
        return;
    }
    for (size_t i = 0, j = len - 1; i < j; i++, j--) {
        uint8_t t = bytes[i];
        bytes[i] = bytes[j];
        bytes[j] = t;
    }
}

/*
 * Per-register snapshot, captured immediately before the issuing
 * instruction executes.  Registers the plugin could not resolve to a
 * runtime handle on this target are emitted as zero.
 */
typedef struct {
    CSTWideValue value;
    /* Architectural width of the register read, in bytes (the
     * qemu_plugin_read_register() byte count).  Surfaced via the
     * CST_FID_DST_REG_WIDTH family for value-prediction consumers, which
     * need to know how many bytes of @value the write covers (a width
     * not derivable from the magnitude-suppressed SLEB delta, nor static
     * across ISAs — SVE/RVV register width is VL/vtype-driven). */
    uint8_t     width_bytes;
} RegSnap;

/*
 * Per-thread wrong-path scratch buffer for per-insn destination-
 * register snapshots captured during a single qemu_plugin_exec_tb()
 * call.  Populated by vcpu_insn_reg_snap_cb when g_wp_state.in_progress
 * is true; drained by the WP fragment-walk loop in
 * champsim_tracer_wp.cc to attribute each insn its per-insn-accurate
 * post-write snapshot (the snap captured at the next canonical
 * insn's pre-exec hook).  See the docstring above
 * vcpu_insn_reg_snap_cb for the full lifecycle.
 *
 * Cleared just before each exec_tb in the WP loop; the fragment
 * walk consumes entries in FIFO execution order.  The very last
 * canonical insn of each fragment is NOT captured here (no
 * successor pre-exec hook within the fragment to trigger it) —
 * the WP walk falls back to a live post-fragment read for that
 * one insn.
 */
extern thread_local std::vector<RegSnap> wp_pending_reg_snaps CST_TLS_HOT;

/*
 * Architectural-register snapshot at segment start.  Captured once per
 * trace segment by walking the GenericRegId reverse index and reading
 * each resolvable register's value via the QEMU plugin API.  Emitted in
 * the per-segment header (extending the "reg" encoding-map entries
 * with a width-prefixed value blob).  Width 0 means "no live value
 * captured" (unresolved register or no vCPU context yet).
 */
typedef struct {
    uint8_t gen_id;
    uint8_t width_bytes;                  /* 0..CST_MAX_WIDE_BYTES */
    uint8_t bytes[CST_MAX_WIDE_BYTES];    /* little-endian          */
} InitialRegSnap;

/*
 * Per-insn QEMU register descriptor keys for InsnFields.src_regs[] /
 * dst_regs[].  Each entry is a stable singleton pointer into
 * g_qemu_reg_by_gen[]; pointer identity per logical register is what
 * makes RegHandleCache::lookup's TLS pointer-cache hit cross-insn.
 * NULL: generic reg has no single directly-readable QEMU register.
 */
typedef struct {
    const QemuRegKey *src_qemu_reg_keys[MAX_SRC_REGS];
    const QemuRegKey *dst_qemu_reg_keys[MAX_DST_REGS];
} InsnRegNames;

/*
 * Synthetic effective-address descriptor for instructions whose
 * canonical TCG translation does not emit a memory op (prefetch hints,
 * cache-line clean/flush/invalidate, TLB invalidate, ...).  Filled at
 * translation time from the Capstone memory operand; consumed at exec
 * time by a per-insn callback that reads base / index register values
 * and computes ea = base + (index << shift_amount) * scale + disp.
 *
 * has_addr is the discriminator: a zero descriptor means "no
 * synthetic EA for this insn."  base_key == NULL means the base
 * register is implicitly zero (e.g. pure-displacement form).
 * Likewise for index_key.  Both are stable pointers into
 * g_qemu_reg_by_gen[].
 */
typedef struct {
    const QemuRegKey *base_key;
    const QemuRegKey *index_key;
    int64_t  disp;
    uint8_t  scale;        /* x86 SIB; 0/1 = effective scale 1 */
    uint8_t  shift_type;   /* AArch64 ARM64_SFT_*; 0 = none    */
    uint8_t  shift_amount; /* AArch64 shift count              */
    uint8_t  has_addr;     /* nonzero when descriptor is valid */
} SyntheticEAInfo;

/*
 * Run-aggregated PGO-style profiling per template instruction
 * (champsim_tracer_format.md §6).  Pure metadata, never affects
 * deterministic replay; POD for the BBTemplate g_new0/g_free
 * lifecycle.  On-disk values are final run totals.
 *
 * Access-pattern class (pat_*) uses DERIVATIVE-CONVERGENCE BINNING:
 * each memop is classified individually by the lowest-order derivative
 * needed to explain it, then tallied into a per-insn histogram; the
 * emitted class is the bin with the highest count — the DOMINANT
 * regime the insn spends its lifetime in.
 *
 * Two complementary tests run per step:
 *
 *  1. POLYNOMIAL CHAIN.  Walk derivative levels 0..CST_PAT_POLY_DEPTH-1
 *     in ABSOLUTE MAGNITUDE space (each level is the abs difference of
 *     the previous level), declaring IRREGULAR on convergence at any
 *     deeper level and REGULAR on convergence at level 0.  K=4 covers
 *     up to degree-4 polynomial access streams.  Absolute magnitudes
 *     avoid the constructive-sign-compounding failure mode where
 *     bounded-complexity patterns (e.g. 0,1,3,4,6,7 ⇒ deltas 1,2,1,2,1,
 *     signed ddeltas +1,-1,+1,-1) would be mislabelled because their
 *     signed ddeltas never repeat — taking abs gives |ddelta|=1
 *     everywhere and the pattern resolves to IRREGULAR.
 *
 *  2. GEOMETRIC RESCUE.  Exponential patterns (e.g. 2^n) have NO
 *     polynomial convergence at any finite depth — at every level the
 *     magnitudes stay exponential.  Detected by the constant-ratio
 *     test |x_n| * |x_{n-2}| == |x_{n-1}|^2 (exact integer cross-
 *     multiply, no division, no FP rounding) applied at EVERY
 *     polynomial level the walk descends past.  This catches any
 *     (polynomial of degree <= K-2) + (exponential) mixture: the
 *     polynomial part annihilates under K-2 differences and the
 *     exponential survives, so at least one level shows the constant
 *     ratio.  Fires only as a rescue when the polynomial chain
 *     returned RANDOM.
 *
 * Per memop:
 *
 *   REGULAR    |delta_n| == |delta_{n-1}| (constant-magnitude stride;
 *              direction reversals of the same magnitude still count
 *              as REGULAR; first one or two memops default here).
 *   IRREGULAR  Either the abs-derivative chain converges at some
 *              level k in 1..K-1 (|Δ^(k+1)| constant — degree-2
 *              through degree-K polynomial access streams qualify),
 *              OR the geometric rescue fires at some walked level
 *              (constant ratio across three consecutive level-k
 *              magnitudes — catches pure exponential at any level
 *              and any polynomial-plus-exponential mixture up to
 *              degree K-2).
 *   RANDOM    Neither the abs-derivative chain converges within
 *              CST_PAT_POLY_DEPTH levels nor a constant ratio is
 *              detected — would need degree-(K+1) or higher
 *              polynomial, or a non-geometric non-polynomial pattern.
 *
 * Two trackers run in parallel: a per-insn classifier keyed by issuing
 * PC, and a CROSS-INSN spatial classifier keyed by page (within-page
 * offset deltas — picks up stencil sweeps where each insn looks
 * chaotic but the BB stripes a page linearly).  Each contributes its
 * own per-insn histogram; their argmax bins are composed at emit time
 * and the LOWER (more regular) class wins, so either tracker may
 * rescue the other.
 */
enum {
    CST_PAT_NONE = 0, CST_PAT_REGULAR = 1,
    CST_PAT_IRREGULAR = 2, CST_PAT_RANDOM = 3,
};
/*
 * profile pat_flags byte layout (self-described on the wire by the
 * "mem_access_pattern" and "profile_flag" encoding maps):
 *   bits[1:0]  CP access-pattern class (CST_PAT_*)
 *   bits[3:2]  WP access-pattern class (CST_PAT_*)
 *   bit[4]     CP data-is-address
 *   bit[5]     WP data-is-address
 */
enum {
    CST_PROFILE_PAT_CP_SHIFT = 0,
    CST_PROFILE_PAT_WP_SHIFT = 2,
    CST_PROFILE_PAT_MASK     = 0x3,
    CST_PROFILE_ADDR_CP      = 0x10,
    CST_PROFILE_ADDR_WP      = 0x20,
};

/*
 * Maximum polynomial derivative depth for the abs-magnitude chain
 * test.  Detects convergence in |Δ^(k+1)f| for k in 0..K-1 — i.e.
 * degree-1 through degree-K polynomial address streams.  K=4 covers
 * up to quartic, which is well past anything seen in real cache-
 * relevant code; exponential patterns (no polynomial convergence at
 * any depth) are caught separately by the geometric-ratio rescue.
 */
#define CST_PAT_POLY_DEPTH 4

/*
 * Derivative-convergence stride-classifier state.  prev_abs_d[k] /
 * prev_prev_abs_d[k] hold the last two observed |Δ^(k+1)f| magnitudes
 * at derivative level k — the second slot enables the per-level
 * geometric-ratio cross-multiply.  The per-step classifier
 * (profile_stride_step) returns the bin (REGULAR / IRREGULAR /
 * RANDOM) THIS step fits and rolls the state forward.  Bin selection
 * per step is the model's only output; tallying lives in the caller's
 * per-insn histograms.
 */
typedef struct {
    uint64_t prev_addr;
    uint64_t prev_abs_d[CST_PAT_POLY_DEPTH];      /* |Δ^(k+1)|_{n-1} */
    uint64_t prev_prev_abs_d[CST_PAT_POLY_DEPTH]; /* |Δ^(k+1)|_{n-2} */
    uint8_t  have_addr;
    uint8_t  have_d_mask;       /* bit k: prev_abs_d[k] valid      */
    uint8_t  have_pprev_d_mask; /* bit k: prev_prev_abs_d[k] valid */
} StrideState;

/* Per-insn histograms: [REGULAR-1, IRREGULAR-1, RANDOM-1] counts —
 * NONE is implicit (memops_X == 0 ⇒ no class emitted).  Argmax at
 * write_template_profile picks the dominant bin per stream. */
typedef struct {
    uint64_t memops_cp, memops_wp;       /* total mem-ops issued      */
    uint64_t lo_cp, hi_cp;               /* effective-addr bounds, CP */
    uint64_t lo_wp, hi_wp;               /*                        WP */
    StrideState stride_cp, stride_wp;    /* PC-keyed classifier state */
    uint32_t pc_bins_cp[3];              /* per-access PC tally       */
    uint32_t pc_bins_wp[3];
    uint32_t spatial_bins_cp[3];         /* per-access page-spatial tally */
    uint32_t spatial_bins_wp[3];
    uint8_t  addr_cp, addr_wp;           /* data-is-address seen      */
} InsnProfile;

/*
 * Per-(target_pc, CP count) tally for an indirect terminator.  When
 * multiple BBTemplates share a terminal branch PC (overlapping BBs
 * entered at different points), each template's own observed taken
 * targets must be attributed PER-TEMPLATE — the per-PC
 * g_branch_history aggregates across templates and would over-
 * attribute its full count to every template that shares the PC.
 * Filled by profile_branch CP for indirect terminators.  Fixed cap at
 * BRANCH_TARGET_HISTORY (== g_branch_history's per-PC cap).
 */
typedef struct {
    uint64_t target;
    uint64_t count_cp;
} TemplateProfTarget;
#define CST_PROFILE_INDIRECT_TARGETS_CAP 16  /* == BRANCH_TARGET_HISTORY */

typedef struct {
    uint64_t exec_cp, exec_wp;
    uint64_t br_taken_cp, br_nottaken_cp;
    uint64_t br_taken_wp, br_nottaken_wp;
    InsnProfile *insns;                /* g_new0 array, n_insns    */
    /* Indirect-only per-template target distribution; empty
     * (n_indirect_targets == 0) for non-indirect BBs. */
    TemplateProfTarget indirect_targets[CST_PROFILE_INDIRECT_TARGETS_CAP];
    uint8_t  n_indirect_targets;
} TemplateProfile;

/*
 * "Data is an address" heuristic: the set of 4 KiB pages a real
 * CORRECT-PATH mem-op touched (never wrong-path — WP is speculative
 * and must not define the address space).  A value counts as an
 * address when its page is in that CP-only set (sparse page-granular
 * membership, not a min/max span).  Page = vaddr >> PAGE_SHIFT.
 */
enum { CST_PROFILE_PAGE_SHIFT = 12 };

typedef struct BBTemplate BBTemplate;
struct BBTemplate {
    uint32_t template_id;
    uint64_t start_pc;
    uint32_t n_insns;
    uint64_t *insn_pcs;
    uint64_t fall_through_pc;
    /*
     * Terminal branch's observed taken-edge target.  Both edges are
     * always known per finalized BB (CP supplies the edge it took, the
     * WP resolver the other), so this is filled even if CP never took
     * the branch.  0 until resolved / non-branch BB.  Internal only,
     * NOT a wire field: at serialization it becomes target_pc[0] of a
     * non-indirect branch's 1-entry header list (indirect branches
     * enumerate the per-PC BranchRecord set and ignore this).
     */
    uint64_t taken_pc;
    char *symbol_name;
    uint8_t *insn_sizes;
    uint8_t *insn_bytes;
    InsnFields *insn_fields;
    /* Optional: parallel Capstone-name array, one entry per insn.
     * Allocated only when reg-data capture is enabled at translation
     * time. */
    InsnRegNames *insn_reg_names;
    /* Per-insn opaque udata for the reg-snap exec callback; lifetime
     * equals the BBTemplate's.  Allocated only when reg-data is on. */
    void *insn_snap_refs;
    /* Optional: synthetic-EA descriptors for prefetch / cache-flush /
     * TLB-flush instructions.  Allocated only when at least one insn
     * in the BB requires synthetic-EA capture; entries with
     * has_addr == 0 are skipped at exec time. */
    SyntheticEAInfo *insn_synthetic_ea;
    /* Per-insn opaque udata for the synthetic-EA exec callback. */
    void *insn_synth_ea_refs;
    /* Counts ENTRY emissions of this template (CP and WP combined).
     * Used by the writer to drive g_features.iframe_rate-triggered IFRAME
     * emissions on a per-template cadence. */
    uint64_t emit_count;
    /*
     * Set when this template's terminator is an x86 REP-prefixed
     * string op (rep_loads_per_iter + rep_stores_per_iter > 0 on the
     * last canonical insn): a 1-insn self-loop sub-template at the
     * REP's PC, built at translation time.  Body emitter fans a single
     * TB-exec into N entries (iter 1 on this template, iter 2..N on
     * rep_subtmpl).  NULL on non-REP TBs.  Materialized at translation
     * but only emitted at >= 2 iters, so an unexercised REP leaves a
     * 0/0-exec template in the dictionary — expected and benign;
     * consumers treat it as a pre-declared, unreferenced self-loop.
     */
    BBTemplate *rep_subtmpl;
    /* Run-aggregated profiling (champsim_tracer_format.md §6).
     * Lazily allocated on first accumulation; freed with the
     * template.  NULL until this BB executes at least once. */
    TemplateProfile *profile;
    /* Fast-path back-edge from a TB template to the true-BB template
     * it has been folded into.  Set when get_or_create_bb_template
     * commits or reuses a true-BB whose fragments include this TB;
     * subsequent re-finalizations of the same chain short-circuit
     * the fragment-walk + lookup dance and return this pointer
     * directly.  Invalidated to NULL by clear_bb_map() at segment
     * switches, since bb_map_ owns the pointee. */
    BBTemplate *parent_true_bb;
    /* How this TB fragment contributes to true-BB assembly (TbTerminus,
     * see split_tb_into_fragments).  Set on TB fragment templates at
     * translation time; the BB chain assembler and the WP walker both
     * read it to decide whether the fragment completes a true-BB, is
     * awaiting a delay-slot landing, or is a non-terminal fragment.
     * Unused (TB_TERMINUS_NONE) on assembled true-BB templates. */
    uint8_t terminus;
    /* Linked list of sibling fragments produced from the same QEMU TB
     * by the mid-TB-branch splitter.  Head is what vcpu_tb_trans
     * attached as the per-TB exec-cb udata; vcpu_tb_exec and the WP
     * walker walk the list to decide which fragments actually
     * executed in this exec (via the scoreboard's last-executed
     * fragment values, or via post_pc on WP).  NULL on singletons
     * (TBs with no mid-TB branch). */
    BBTemplate *next_tb_fragment;

    /* Cached BranchRecord* for this BB's terminal branch.  set lazily
     * on first observe_branch_transition (which would otherwise hash-
     * lookup g_branch_history.records_ by branch PC every fire — perf
     * showed BranchHistory::get_or_create at 2.15% of CP-only runtime
     * on mcf, all of it the same templates re-resolving the same PC).
     * Pointer stays valid across std::unordered_map rehashes (C++
     * standard guarantee for unordered associative containers); we
     * never erase entries.  NULL invalidates across segment switches
     * since the BBTemplate itself is freed/recreated. */
    struct BranchRecord *cached_branch_record;
};

enum DynParamType {
    DYN_LOAD_ADDR  = 0,
    DYN_STORE_ADDR = 1,
};

/*
 * Runtime memory-access record emitted as a dyn-param.  Only `value`
 * reaches disk; type / insn_index / data_* are writer-internal
 * (group by owning insn, split loads-then-stores, update N_LOADS/
 * N_STORES, emit mem-data).  Owning insn and load/store type are
 * implicit on disk: the consumer reconstructs them by walking the
 * template's per-insn (n_loads, n_stores) schema.
 */
typedef struct {
    uint8_t  type;         /* DynParamType (writer-internal)        */
    uint16_t insn_index;   /* Index in owning template's insn array */
    uint64_t value;        /* vaddr of the access                   */
    uint8_t  data_size;
    CSTWideValue data;
} DynParam;

/*
 * BodyEntry / WPBBEntry use std::vector for their dynamic arrays, so
 * they are visible only to C++ TUs.  The C-only mnemonic_tables.c
 * does not consume them.
 */
#ifdef __cplusplus
#include <vector>

struct WPBBEntry {
    uint32_t template_id;       /* TRUE BB id (start_pc → first branch) */
    uint64_t start_pc;
    std::vector<DynParam> dyn_params;  /* memops captured during this WP BB */
    uint32_t n_insns_executed;  /* BB length when complete; partial on fault */
    bool fault;
    bool translation_unavailable;
    /*
     * Index within THIS BB of the insn that raised the synchronous
     * exception when `fault`; undefined otherwise.  Consumers flag
     * that uop non-completing so its dependent slice is squashed.
     */
    uint32_t fault_insn_index;
    BBTemplate *tmpl;  /* Non-owning; for per-insn schema access */
    /* RegSnap vector, ordered: for each insn in this BB, n_src snaps
     * only.  Captured pre-insn via a per-fragment wide regfile dump.
     * Empty when reg-data is disabled. */
    std::vector<RegSnap> reg_snaps;
};

struct BodyEntry {
    uint32_t seq_num;
    uint32_t template_id;
    std::vector<DynParam> dyn_params;
    /* RegSnap vector, ordered: for each insn in the template, n_src
     * snaps only.  Only populated when g_features.reg_data is true. */
    std::vector<RegSnap> reg_snaps;
    std::vector<WPBBEntry> wp_entries;
    BBTemplate *tmpl;  /* Non-owning; for per-insn schema access */
    uint32_t thread_id;
    /* QEMU vCPU index this entry came from.  Used by the body writer
     * to capture this thread's BODY_TAG_REGFILE on first emit when
     * the thread did not trigger segment open (i.e. is not the seed
     * thread whose regfile was pre-captured at start_trace_segment). */
    uint32_t cpu_index;
};
#endif  /* __cplusplus */

/*
 * How a translation block contributes to true-BB assembly.  QEMU TBs
 * do NOT align with true basic blocks: a TB ends at a branch, a page
 * boundary, or a length limit, and on delay-slot ISAs a branch and
 * its delay slot can land in separate TBs (page split).  The chain
 * assembler folds TBs into true BBs using this per-TB classification.
 */
enum TbTerminus {
    /* Continuation fragment: no terminating branch.  Also the lone
     * delay-slot TB of a page-split branch (a bare insn — the chain
     * assembler recognises it from the pending-delay-slot state). */
    TB_TERMINUS_NONE = 0,
    /* TB completes a true BB: ends in a branch (non-delay-slot ISA),
     * or in [branch, delay-slot] (delay-slot ISA, both in this TB). */
    TB_TERMINUS_COMPLETE = 1,
    /* TB ends with a branch as its literal last insn on a delay-slot
     * ISA — the delay slot is the first insn of the NEXT TB.  The BB
     * is not complete until that delay slot is appended. */
    TB_TERMINUS_BARE_BRANCH = 2,
};

typedef struct {
    uint64_t current_pc;
    uint64_t prev_start_pc;
    uint64_t prev_fall_through;
    /* TbTerminus for the previous TB — drives true-BB finalization. */
    uint64_t prev_bb_terminus;
    uint64_t insn_count;
    /* Start PC of the most recent TB counted toward insn_count.  When
     * QEMU re-enters the same single-insn TB without architectural
     * progress (x86 REP string ops: each iteration is a separate
     * exec_tb at the same start_pc), insn_count is held steady so it
     * tracks unique-PC visits, keeping icount aligned with PIN-style
     * one-count-per-architectural-insn accounting. */
    uint64_t last_counted_start_pc;
    /* Mirror of g_trace_segments.is_active() as a per-vCPU scoreboard
     * slot (1 in-segment, 0 inter-segment).  Backs the cond_cb gate
     * on the per-insn heavy callbacks (reg_snap_cb, synth_ea_cb): a
     * GE-1 condition emitted into the TCG-compiled TB skips the
     * callback at the JIT level when inactive, avoiding the
     * function-call / TLS-cache overhead the callback's C-level
     * early-bail still pays. */
    uint64_t is_active;
    /* Signed budget tracking insns until the next window event
     * (segment open in inter-segment, or sentinel "far future" while
     * in-segment).  Bumped by INLINE_ADD_U64(-n_insns) per TB exec
     * so the JIT counts down without a C call; a cond_cb on
     * budget < 1 fires the heavy threshold-handler once when the
     * countdown crosses zero. */
    int64_t budget;
} VCPUScoreBoard;

enum { BRANCH_TARGET_HISTORY = 16 };

typedef struct {
    uint64_t target;
    uint32_t count;
    uint32_t last_seen;
    bool valid;
} BranchTargetHistoryEntry;

typedef struct BranchRecord {
    uint64_t pc;
    uint64_t fall_through;
    /* Distinct taken-target history.  CORRECT-PATH ONLY: note_target()
     * is never called during WP sim, so this pool stays unpolluted by
     * speculative targets — essential because indirect WP selection
     * mines this very pool (one observed target → monomorphic, use
     * fall-through; multiple → most frequent that isn't the CP
     * target). */
    BranchTargetHistoryEntry targets[BRANCH_TARGET_HISTORY];
    uint8_t n_targets;
    uint32_t target_tick;
} BranchRecord;

typedef struct {
    uint64_t insn_pc;
    uint64_t mem_vaddr;
    bool is_store;
    uint8_t data_size;
    CSTWideValue data;
} WPMemAccess;

typedef struct BodyStreamState BodyStreamState;
typedef struct WriterCtx WriterCtx;

typedef struct {
    uint64_t start_insn;
    uint64_t stop_insn;
    char *label;
    /* Body output destination: streams body bytes to a temp file.
     * With compress=<cmd> the FILE* is a popen() write end whose
     * compressor stdout is redirected to disk. */
    FILE *body_file;
    bool body_is_pipe;
    WriterCtx *body_writer;  /* async writer thread feeding body_file */
    char *body_temp_path;    /* on-disk path of the (possibly compressed) body bytes */
    char *body_member_name;  /* name inside the outer tar (body.cst[.<ext>]) */
    /* Header output destination.  Opened lazily at body_stream_finish;
     * one synchronous write.  Same compress=<cmd> handling as body. */
    FILE *header_file;
    bool header_is_pipe;
    char *header_temp_path;
    char *header_member_name;
    /* Final outer-tarball path.  After body+header members are
     * flushed and closed, the segment manager assembles a ustar of
     * them here and unlinks the temp files. */
    char *outfile_path;
    BodyStreamState *bin_stream;
    uint32_t body_seq_num;
    char start_datetime[64];
} TraceSegment;

typedef struct {
    uint64_t interval_id;
    uint64_t start_insn;
    uint64_t stop_insn;
    int cluster_id;
    double weight;
} SimPointEntry;

/*
 * Raw byte buffer with inlined append.  Replaces GByteArray for the
 * encoder's per-entry scratch (g_byte_array_append was 1.5% of
 * runtime — a glib call per uleb byte).  Capacity grows 2x, never
 * shrinks (matches the reuse-the-largest-scratch pattern).  Not
 * thread-safe; each holder is single-thread by construction.
 */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} RawBuf;

typedef struct {
    FILE *f;
    GByteArray *buf;       /* glib scratch (legacy mode, dynamic alloc) */
    RawBuf *rb;            /* fast scratch (inlined append) */
    WriterCtx *w;          /* async writer; mutually exclusive with f/buf/rb */
    uint64_t total_bytes;
} BitWriter;

/* ===== Plugin-wide globals ===== */

/* ISA resolution: set once during qemu_plugin_install based on the
 * guest target_name. */
/* Monotonic count of tb_flush events.  The wrong-path loop snapshots it
 * around each spec-mode exec_tb: if a flush fired during the call AND the
 * TB did not execute (last_executed_tb stayed null), that exec_tb was
 * unwound by the flush before the guest insn ran — JIT housekeeping, not
 * a spec-mode fault — so the loop retries instead of truncating the chain
 * (keeps WP flush-invariant). */
extern std::atomic<uint64_t> g_tb_flush_count;

extern TraceISA trace_isa;
extern int cst_cap_arch;
extern unsigned int cst_cap_mode;
extern const char *target_name;
/* True when the guest target is big-endian (currently only MIPS BE, when
 * trace_isa==TRACE_ISA_MIPS and target_name does not end in "el").  Set
 * once during qemu_plugin_install.  qemu_plugin_read_register() returns
 * bytes in target byte order; the reg-snap path normalises those bytes
 * to little-endian before they reach the trace, so the on-disk format
 * is unconditionally LE regardless of guest endianness. */
extern bool target_big_endian;
extern const InsnClassification *active_insn_table;
extern unsigned active_insn_table_size;
extern const RegClassification *active_reg_table;
extern unsigned active_reg_table_size;

/* Plugin configuration: parsed from -plugin args, immutable after
 * qemu_plugin_install. */
extern int max_wrong_path_depth;
extern bool enable_wrong_path;
/* Effective per-run trace-feature toggles, derived once from PluginConfig
 * at install (the tristate WP flags resolved against their CP counterparts)
 * and immutable after.  Grouped so the write-once/read-many feature set
 * travels as one object rather than as five scattered globals. */
struct TraceFeatures {
    bool     mem_data    = false;   /* capture CP memop effective addresses */
    bool     reg_data    = false;   /* capture CP per-insn register values  */
    /* WP-side data toggles.  Default to the matching CP-side flag when unset
     * at install time.
     *   wp_mem_data: gates only the VALUE half of WP memops; WP addresses
     *     are always recorded (preserves the speculative memory footprint
     *     for cache/prefetcher sims).
     *   wp_reg_data: gates WP per-insn register-value snapshots; register
     *     identifiers still come from the template. */
    bool     wp_mem_data = false;
    bool     wp_reg_data = false;
    /* I-frame trigger: emit a self-contained IFRAME after every N-th ENTRY
     * of the same template.  0 disables the feature. */
    uint32_t iframe_rate = 0;
};
extern TraceFeatures g_features;
extern char *qemu_command_line;
extern char *trace_comment;

/* Simpoint windowing.  warmup_insns is the number of instructions
 * traced BEFORE each simpoint position; simulation_insns is the
 * number traced AT-AND-AFTER it.  Both are zero outside simpoint mode
 * and propagate into the per-segment header for downstream consumers
 * that need to split warmup vs evaluation regions. */
extern uint64_t warmup_insns;
extern uint64_t simulation_insns;

/* Executable code range of the main binary, captured at plugin install.
 * Gates fragment-template creation and WP speculation entry; a PC
 * outside this range is dynamic memory and any "instructions" we'd read
 * there are non-deterministic.  See champsim_tracer.cc for details. */
extern uint64_t g_code_start;
extern uint64_t g_code_end;

static inline bool cst_pc_in_code(uint64_t pc)
{
    return pc >= g_code_start && pc < g_code_end;
}

/* Is @pc a TB start_pc that has been poisoned (decode failure or
 * byte change detected at translation time)?  Acquires data_lock. */
bool cst_pc_is_poisoned(uint64_t pc);

/* Synchronization & diagnostics.  Must stay GMutex, not std::mutex:
 * <mutex> pulls <ctype.h>, which QEMU's include/qemu/ctype.h shadows
 * on the plugin -I path, breaking libstdc++'s `using ::isalnum;`. */
extern GMutex data_lock;
extern GMutex unknown_warn_lock;
extern FILE *unknown_warn_file;

/* Null-safe string equality (cst_str_eq) is defined in
 * champsim_tracer_mnemonics.h, which this header pulls in below. */

/* ===== Cross-TU functions ===== */

/* Defined in champsim_tracer_decode.cc */
void decode_detail_to_generic(uint64_t pc,
                              const qemu_plugin_insn_info *info,
                              InsnFields *out,
                              InsnRegNames *out_names);

/* Defined in champsim_tracer_decode.cc */
bool decode_synthetic_ea(const qemu_plugin_insn_info *info,
                         uint8_t opcode,
                         uint64_t pc,
                         uint8_t insn_size,
                         SyntheticEAInfo *out);

/* Build the GenericRegId → QemuRegKey reverse index used by the
 * multi-reg path of add_src_cap_reg / add_dst_cap_reg.  Must run
 * after active_reg_table is set; idempotent.  Defined in
 * champsim_tracer_decode.cc. */
void build_qemu_reg_reverse_index(void);

/*
 * Wide regfile snapshot: opaque TLS scratch keyed by the active reg
 * table's QEMU descriptors.  Used by the WP loop to capture
 * pre-fragment register state (spec-mode CF_MEMI_ONLY suppresses
 * per-insn exec callbacks).
 */
typedef struct _WideRegSnap WideRegSnap;

/* Reg-snap capture is provided by RegSnapCollector; see
 * champsim_tracer_reg_snap_collector.h. */

/* Defined in champsim_tracer_wp.cc.  Returns the speculative chain by
 * value; callers move it into BodyEntry::wp_entries. */
#ifdef __cplusplus
std::vector<WPBBEntry> simulate_wrong_path_ext(uint64_t branch_pc,
                                               uint64_t correct_target,
                                               uint64_t wrong_target,
                                               unsigned int cpu_index,
                                               bool *flush_interrupted);
#endif

/*
 * Fill @out with one InitialRegSnap per resolvable architectural
 * register, read from @cpu_index.  @cpu_index == (unsigned)-1 (no
 * vCPU context at install time) → all entries width_bytes=0 (header
 * still pins which generic IDs exist, just no live values).  Defined
 * in champsim_tracer_decode.cc.
 */
void capture_initial_regfile(unsigned int cpu_index,
                             std::vector<InitialRegSnap> *out);

/* Defined in champsim_tracer_output.cc */
BodyStreamState *body_stream_new(WriterCtx *w, const char *seg_datetime,
                                 uint64_t start_insn,
                                 uint64_t warmup_insns,
                                 uint64_t total_target_insns,
                                 uint32_t seed_thread_id,
                                 double simpoint_weight,
                                 const std::vector<InitialRegSnap> *regfile);
void body_stream_write_entry(BodyStreamState *st, BodyEntry *entry);
/* Finish the body stream and hand the accumulated header buffer
 * back to the caller via @header_bytes (transferred ownership; the
 * caller must g_byte_array_unref it after writing).  The body
 * destination (the WriterCtx passed to body_stream_new) is closed
 * by the segment manager separately after this returns. */
void body_stream_finish(BodyStreamState *st, GByteArray **header_bytes);
/* Stash the in-trace architectural CP-insn count at which warmup
 * ends and the simulation phase begins, so finish writes it into
 * the header (§2.13 in champsim_tracer_format.md).  Call before
 * body_stream_finish.  0 = no warmup configured / warmup never
 * elapsed (the entire trace is warmup). */
void body_stream_set_warmup_end_arch_insns(BodyStreamState *st,
                                           uint64_t value);
/* Free a BodyStreamState.  Required (not free()): it carries
 * std::vector members needing destructors, and the opaque forward
 * decl here doesn't let callers `delete` directly. */
void body_stream_free(BodyStreamState *st);

#endif /* CHAMPSIM_TRACER_H */
