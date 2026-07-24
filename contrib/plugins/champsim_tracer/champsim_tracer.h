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
 * fully specified in docs/format.rst.  Key invariants:
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
 * Wire format spec'd in docs/format.rst.
 */
#define BODY_TAG_REGFILE         4
/*
 * BODY_TAG_ASID_SWITCH: rebases the address-space (ASID) dimension of
 * the current body context, sibling to BODY_TAG_THREAD_SWITCH.  The
 * context of a body record is the pair (thread_id, asid); memory is
 * keyed (asid, vaddr) so identical VAs under different asids are
 * distinct physical memory.  Payload: sleb128 asid-index delta from the
 * current asid.  The FIRST appearance of an asid index additionally
 * carries its identity inline — u64 root_phys (page-table root physical
 * address) + u64 sig (content signature) — mirroring how a thread's
 * register file rides its first sighting.  Every trace opens with an
 * initial (asid, thread) declaration before the first entry.
 * Wire format spec'd in docs/format.rst.
 */
#define BODY_TAG_ASID_SWITCH     5
/*
 * BODY_TAG_DEVIO_START / BODY_TAG_DEVIO_STOP: a block-device (disk) I/O
 * request bracketed in the body stream.  DEVIO_START carries the owning
 * (thread, asid) EXPLICITLY when the request was correlated to the vCPU
 * that rang the device doorbell (attr == CST_DEVIO_ATTR_EXACT); the
 * virtqueue kick executes in that vCPU's context, so the plugin captures
 * the owner there and stamps it here even though the block backend
 * issues the request later on the main loop.  When no doorbell matched
 * (non-virtio, IDE/AHCI, or kernel-internal I/O) the record is
 * POSITIONAL (attr == CST_DEVIO_ATTR_POSITIONAL): no owner fields, and
 * the consumer attributes it to the (thread, asid) context in force at
 * its stream position, as before.  DEVIO_STOP lands where the request's
 * completion is observed and pairs to its START by request_id (the
 * owner is inherited from the START).
 *
 *   START payload: uleb request_id (compact monotonic per-segment),
 *                  u8 rw (CST_DEVIO_*), uleb bytes, uleb block (disk
 *                  block number = byte offset / logical block size,
 *                  512 B), u8 attr (CST_DEVIO_ATTR_*); iff attr ==
 *                  CST_DEVIO_ATTR_EXACT then uleb owner_thread_id,
 *                  uleb owner_asid.
 *   STOP  payload: uleb request_id.
 *
 * System mode only, correct path only (a speculative doorbell store is
 * sandboxed and reaches no device).  Absent entirely in device-free
 * (e.g. user-mode) traces.  Wire format spec'd in
 * docs/format.rst.
 */
#define BODY_TAG_DEVIO_START     6
#define BODY_TAG_DEVIO_STOP      7

/* DEVIO_START rw byte (mirrors enum qemu_plugin_devio_dir). */
#define CST_DEVIO_READ           0
#define CST_DEVIO_WRITE          1
#define CST_DEVIO_FLUSH          2

/* DEVIO_START attribution byte: whether the owning (thread, asid) is
 * carried inline (EXACT — doorbell-correlated) or the consumer must use
 * the stream-position context (POSITIONAL — no doorbell matched). */
#define CST_DEVIO_ATTR_POSITIONAL 0
#define CST_DEVIO_ATTR_EXACT      1

/* Logical block size for the DEVIO_START disk-block-number field: the
 * block layer's fundamental sector unit (512 bytes).  block = byte
 * offset >> CST_DEVIO_LBA_SHIFT. */
#define CST_DEVIO_LBA_SHIFT      9

/*
 * Per-insn template flags byte
 *
 *   bit 0    BRANCH_COND
 *   bit 1    HAS_IMM
 *   bit 2    ATOMIC         — atomic / locked memory op
 *   bit 3    reserved (formerly STATIC, retired with the P1 sweep)
 *   bit 4    VEC            — per-slot lane bitmaps present
 *   bit 5    LANE_PARALLEL  — lane bitmaps line up by lane index
 *                             (consumer can model per-lane chains).
 *                             LANE_PARALLEL implies VEC.
 *   bit 6    HAS_DEP_BLOCK
 *   bit 7    SYSTEM         — privileged (non-user) execution context
 *
 * SYSTEM marks instructions translated at a privilege level other
 * than user (qemu_plugin_get_priv_level() != 0): in a system-mode
 * trace these are the traced-but-not-counted kernel instructions of
 * the pinned process (see the marker count set).  Uniform across a
 * template — a true BB never straddles a privilege transition, since
 * the transition instruction (syscall/iret/interrupt entry) seals
 * the BB.  Always clear in user-mode traces.
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
/* bit 3 reserved (formerly CST_INSN_FLAG_STATIC, retired with the P1 sweep) */
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
#define CST_INSN_FLAG_SYSTEM        (1u << 7)

/* dep_block_flags bits inside the optional dependency sub-block. */
#define CST_DEP_BLOCK_HAS_REG       (1u << 0)
#define CST_DEP_BLOCK_HAS_ADDR      (1u << 1)

/* WP event flags byte */
#define CST_WP_EVENT_TRANSLATION_UNAVAIL (1u << 0)
/* This wrong-path BB contains a SYNTHETIC-DATA FAULT at fault_insn_index: a
 * speculative memory access to an absent/unreadable page was served a
 * deterministic placeholder value (plugin_spec_garbage_fill), or a
 * mid-block execution-time exception (arithmetic overflow, illegal opcode,
 * alignment, a conditional trap) was skipped, its stale destination left as
 * a deterministic placeholder.  On a mispredicted path no instruction
 * retires, so neither kind is ever taken by a real core; the excursion
 * CONTINUES past it to the wpdepth budget.  Only a fault AT the BB's
 * terminator that is itself a syscall-type control transfer (a real
 * privilege escalation the single-address-space spec model cannot follow)
 * TERMINATES the excursion here instead, sealing this block as the chain's
 * last.  See docs/format.rst §4.4. */
#define CST_WP_EVENT_FAULT               (1u << 1)
/* Bit 2 is free — unassigned, reserved for a future event flag.  Writers
 * write it 0; readers ignore it (reserved-bits rule, docs/format.rst). */

/*
 * WP chain header flag: packed into the low bit of the wp_chain_section's
 * leading ULEB (docs/format.rst Step 6.8), alongside num_wp in the
 * remaining high bits (num_wp = chain_hdr >> 1).  Set when a
 * wp_events_section (Step 6.9) follows the chain on the wire; when clear,
 * the events section is entirely absent from this entry — no length
 * prefix, no payload — rather than present-but-empty.
 *
 * Event density is workload-dependent — measured traces range from ~1%
 * of CP entries carrying any wrong-path event (see docs/format.rst §4.4)
 * up to ~22% on a fault-heavy user-mode workload — but the no-event
 * majority always paid the unconditional wp_events_section's two-byte
 * empty-section framing (outer length prefix + num_events=0) for no
 * informational content.  Packing the presence bit
 * into the chain header's existing leading ULEB — rather than adding a
 * dedicated per-entry flag byte — keeps the common (no-event) case at
 * zero added bytes: the chain header is already unconditionally present
 * once CST_FLAG_WP is set, so this reinterprets an existing field instead
 * of introducing a new one.
 */
#define CST_WP_CHAIN_HAS_EVENTS           (1u << 0)

/* Header feature flags.  MEM_DATA / REG_DATA advise which optional
 * field-ID families may appear (the field IDs still determine actual
 * presence).  PROFILE / WP are structural gates: they decide whether
 * a whole block is present (the §6 template profile block, and the
 * per-entry wrong-path chain + events sections respectively).  See
 * docs/format.rst "Format Stability and Conformance". */
#define CST_FLAG_MEM_DATA      (1 << 0)  /* CST_FID_LOAD_DATA / STORE_DATA */
#define CST_FLAG_REG_DATA      (1 << 1)  /* CST_FID_DST_REG values        */
#define CST_FLAG_PROFILE       (1 << 2)  /* §6 profile block per template  */
#define CST_FLAG_WP            (1 << 3)  /* per-entry WP chain + events    */
#define CST_FLAG_FAULT         (1 << 4)  /* per-entry sync-fault trailer
                                          * (exception-nesting depth, +
                                          * anchor on a faulting BB); set in
                                          * system mode so user-mode traces
                                          * carry no trailer */
#define CST_FLAG_PHYSADDR      (1 << 5)  /* CST_FID_LOAD_PPAGE / STORE_PPAGE
                                          * families present: per-memop
                                          * physical PAGE bases for paddr
                                          * reconstruction.  SYSTEM MODE ONLY
                                          * (physaddr=1) — user-mode traces
                                          * never set it and stay byte-
                                          * identical.  See §5.3.1. */
/* bits 6..7 reserved */

/* Physical-page granule for the CST_FID_*_PPAGE families.  A ppage value
 * is the physical address masked to this page size; the consumer rebuilds
 * the full physical address as  ppage | (vaddr & CST_PPAGE_OFFSET_MASK).
 * Fixed at 4 KiB: the low 12 bits of a virtual address always equal the
 * low 12 bits of its physical address (page-offset invariance holds for
 * every hardware page size >= 4 KiB — 4K/16K/64K/2M/1G alike), so a 4 KiB
 * granule reconstructs the exact paddr regardless of the guest's actual
 * page size.  A larger hardware page merely re-emits the (unchanged) ppage
 * once per 4 KiB step; correctness is independent of the granule. */
#define CST_PPAGE_SHIFT        (cst_wire::PPAGE_SHIFT)
#define CST_PPAGE_OFFSET_MASK  (cst_wire::PPAGE_OFFSET_MASK)

/* ===== Field-ID space (unified delta stream) =====
 *
 * Each per-entry observation is one record; field IDs are ULEB128.
 * Slotted families are interleaved-by-slot so slot k's five family
 * IDs are contiguous, keeping low slots in the 1-byte ULEB range
 * alongside the hot singletons (slot 0..24 → 1 byte, 25..63 → 2).
 * See docs/format.rst §5.1.
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

/* Physical-page block (system mode, gated by CST_FLAG_PHYSADDR).  Two
 * slotted families parallel to LOAD_ADDR/STORE_ADDR — the physical PAGE
 * base of each memop slot (see CST_PPAGE_SHIFT).  Kept AFTER the reserved
 * EXTENDED escape, in its own stride-2 block, so no pre-existing field-id
 * moves: a trace produced without the flag is byte-identical to one from a
 * writer that predates the families.  Delta-encoded like every slotted
 * family (baseline default 0) — a ppage records once per translation and
 * then costs zero bytes until the mapping changes (in-page walks emit
 * nothing; an OS remap self-corrects on the next touch). */
#define CST_FID_PPAGE_BLOCK_BASE  (CST_FID_EXTENDED + 1)
#define CST_FID_PPAGE_BLOCK_STRIDE 2
#define CST_FID_LOAD_PPAGE_BASE   (CST_FID_PPAGE_BLOCK_BASE + 0)
#define CST_FID_STORE_PPAGE_BASE  (CST_FID_PPAGE_BLOCK_BASE + 1)
#define CST_FID_PPAGE_BLOCK_END   (CST_FID_STORE_PPAGE_BASE + \
                                   (CST_FID_SLOT_COUNT - 1) * \
                                   CST_FID_PPAGE_BLOCK_STRIDE)

/* Branch-outcome block (always present).  Two per-block singletons that ride
 * the terminating branch of a branch-terminated BB — on the correct path and
 * on every wrong-path chain block — making the branch's direction and dynamic
 * target explicit so a consumer need not decode the successor to recover them:
 *   CST_FID_BRANCH_TAKEN  — 1 = control transferred (taken), 0 = fell through.
 *   CST_FID_BRANCH_TARGET — the branch's landing PC encoded as a SIGNED
 *                           DISPLACEMENT from the branch instruction's own PC
 *                           (successor - branch_pc), so even a first sighting
 *                           is a small sleb; the decoder reconstructs
 *                           successor = branch_pc + displacement.  Equals the
 *                           fall-through when not taken.
 * Placed AFTER the physical-page block so no pre-existing field-id moves.
 * Delta-encoded singletons keyed on the branch insn's position (like
 * CST_FID_METAFLAGS): a direct branch's displacement is static after its first
 * emission (delta 0 -> zero record bytes) and cost concentrates in indirect
 * targets and direction flips.  WP blocks delta through the per-chain WP
 * overlay (wp_state -> CP -> default), so WP overhead tracks CP overhead.
 * Non-branch-terminated entries (page-split continuations) carry neither FID.
 * See docs/format.rst §5.6. */
#define CST_FID_BRANCH_BLOCK_BASE (CST_FID_PPAGE_BLOCK_END + 1)
#define CST_FID_BRANCH_TAKEN      (CST_FID_BRANCH_BLOCK_BASE + 0)
#define CST_FID_BRANCH_TARGET     (CST_FID_BRANCH_BLOCK_BASE + 1)

/* Total well-known field-id count, for sanity / encoding-map size. */
#define CST_FID_COUNT            (CST_FID_BRANCH_TARGET + 1)

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
    /* SPAN MEMBERS, sized by the sibling InsnFields' n_src_regs /
     * n_dst_regs and packed into the template's insn_fields_pool (see
     * champsim_tracer_mnemonics.h SPAN MEMBERS).  Empty or sentinel
     * tables alias a shared all-NULL key array so readers that index
     * them with a REAL sibling count (the kEmptyRegNames pairing) still
     * read NULL, exactly as the old zero-initialized fixed arrays did. */
    const QemuRegKey **src_qemu_reg_keys;   /* [n_src_regs] */
    const QemuRegKey **dst_qemu_reg_keys;   /* [n_dst_regs] */
} InsnRegNames;

/* Shared all-NULL key span for empty/sentinel InsnRegNames (defined in
 * champsim_tracer_bb_template_cache.cc). */
extern const QemuRegKey *g_zero_regkeys[MAX_SRC_REGS];

/*
 * Build-time backing for one InsnRegNames — same discipline as
 * InsnFieldsScratch (self-referential; reset in place; never copy). */
typedef struct InsnRegNamesScratch {
    InsnRegNames rn;
    const QemuRegKey *src_keys[MAX_SRC_REGS];
    const QemuRegKey *dst_keys[MAX_DST_REGS];
} InsnRegNamesScratch;

static inline void insn_reg_names_scratch_reset(InsnRegNamesScratch *s)
{
    memset(s, 0, sizeof(*s));
    s->rn.src_qemu_reg_keys = s->src_keys;
    s->rn.dst_qemu_reg_keys = s->dst_keys;
}

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
 * (docs/format.rst §6).  Pure metadata, never affects
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

/*
 * Template lifetime class.  A template is born into one of two classes
 * from the mode of the translation that minted it:
 *
 *   SPEC — minted by a wrong-path (spec-mode) translation.  Wrong-path
 *          fetch residue unless the correct path later runs it: freed
 *          wholesale at tb_flush (see reclaim_spec_templates).  Dedup-
 *          visible via a separate SPEC-class index that reclaim drops
 *          in one clear.
 *   CODE — minted by a correct-path translation, or promoted from SPEC
 *          on first correct-path execution (TemplateStore::promote).
 *          Persistent for the run; the CODE-class dedup index only
 *          ever contains CODE chains, so reclaim never touches it.
 *          Opportunistically-minted branch alternates (alt_map_) also
 *          carry this class — they are ordinary never-executed dictionary
 *          entries with no wire flag, indistinguishable from any block
 *          that happened not to run.
 *
 * The remaining lifetime regime — segment-scoped executed true-BB
 * templates — is expressed by bb_map_ membership, not by this enum:
 * bb_map_ owns its records and drops them wholesale at clear_bb_map().
 */
enum class TmplLife : uint8_t { SPEC, CODE };

/*
 * Generation-stamped handle for a cross-lifetime reference INTO the
 * segment-scoped true-BB store (bb_map_).  Flush-persistent fragment
 * templates outlive the true-BBs they point at, so a raw pointer would
 * dangle after every clear_bb_map(); instead of a remembered
 * invalidation walk over all translations, the handle carries the
 * segment generation it was minted in and staleness is detected at
 * deref (TemplateStore::seg_deref returns nullptr for a stale handle
 * — one integer compare, cheap enough for the REP fan-out hot path).
 * Zero-initialized state ({nullptr, 0}) is stale by construction: the
 * store's generation counter starts at 1.
 */
struct SegRef {
    BBTemplate *ptr;
    uint32_t    seg_gen;
};

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
    /* Backing pool for insn_fields' span members (one allocation per
     * template; see the SPAN MEMBERS comment in champsim_tracer_mnemonics.h).
     * pool_bytes is kept for footprint accounting. */
    void *insn_fields_pool;
    uint32_t insn_fields_pool_bytes;
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
     * rep_subtmpl).  Stale/null handle on non-REP TBs.  Materialized
     * lazily on first chain-finalize use, but only emitted at >= 2
     * iters, so an unexercised REP leaves a 0/0-exec template in the
     * dictionary — expected and benign; consumers treat it as a
     * pre-declared, unreferenced self-loop.  A SegRef because the
     * pointee lives in bb_map_ (segment lifetime) while this template
     * may persist across segments: a handle minted in a previous
     * segment derefs to nullptr and the sub-template is rebuilt on
     * next use (see ensure_rep_subtmpl).
     */
    SegRef rep_subtmpl;
    /* Run-aggregated profiling (docs/format.rst §6).
     * Lazily allocated on first accumulation; freed with the
     * template.  NULL until this BB executes at least once. */
    TemplateProfile *profile;
    /* Fast-path back-edge from a TB template to the true-BB template
     * it has been folded into.  Set when get_or_create_bb_template
     * commits or reuses a true-BB whose fragments include this TB;
     * subsequent re-finalizations of the same chain short-circuit
     * the fragment-walk + lookup dance and return the pointee
     * directly.  A SegRef because bb_map_ owns the pointee: after a
     * segment switch the handle is stale (generation mismatch) and
     * seg_deref returns nullptr, sending the finalize down the slow
     * path that re-commits the true-BB in the new segment. */
    SegRef parent_true_bb;
    /* How this TB fragment contributes to true-BB assembly (TbTerminus,
     * see split_tb_into_fragments).  Set on TB fragment templates at
     * translation time; the BB chain assembler and the WP walker both
     * read it to decide whether the fragment completes a true-BB, is
     * awaiting a delay-slot landing, or is a non-terminal fragment.
     * Unused (TB_TERMINUS_NONE) on assembled true-BB templates. */
    uint8_t terminus;
    /* Privileged (non-user) execution context.  Stamped on TB fragment
     * templates at translation time from qemu_plugin_get_priv_level()
     * (the seal happens in the SUCCESSOR's context — a syscall-ended BB
     * seals while the kernel runs — so translation is the only point
     * where the privilege belongs to this code).  Propagated onto the
     * assembled true-BB and serialized as CST_INSN_FLAG_SYSTEM on every
     * insn descriptor.  Always false in user mode.
     *
     * Correct-path stamps are authoritative (CP translates in the
     * context that really executes the code) and latch
     * is_system_cp_confirmed; a wrong-path stamp is only a seed for
     * WP-only-discovered BBs — the WP walk can speculate across the
     * privilege boundary and spec-translate code in the wrong
     * context, so it must never override a CP-confirmed value. */
    bool is_system;
    bool is_system_cp_confirmed;
    /*
     * Lifetime class (see TmplLife).  SPEC templates the correct path
     * never runs are speculative-fetch residue — the wrong path
     * wandering mutable data that happens to decode (millions of
     * one-insn CF_SINGLE_STEP templates at ever-fresh PCs, or 512-insn
     * nop-slides through zeroed pages at ~1.7 MB each) — and retaining
     * them for the run is the unbounded heap growth behind the
     * intermittent OOM aborts (#91).  They are freed at tb_flush (their
     * owning QEMU TBs are gone; nothing else references them), with a
     * flush requested proactively when their footprint crosses a budget.
     * CODE templates are never reclaimed, preserving the deferred-
     * prev/chain invariants and flush-invariance for real code.
     */
    TmplLife life;
    /* Set once the chain headed by this fragment has been entered into
     * the CODE-class dedup index — at registration for a CODE-born
     * chain, at first correct-path execution for a SPEC-born one
     * (TemplateStore::promote).  Meaningful on chain HEADS only; the
     * pre-lock fast gate in vcpu_tb_exec reads it racily, which is
     * benign — promote() rechecks under data_lock. */
    bool chain_indexed;
    /* Opportunistic branch-alternate minting (static_templates=1): latched
     * once this true BB's untaken-side alternate has been checked/minted, so
     * a block re-walked on every CP seal / WP excursion pays the mint check
     * ONCE, not per visit (the check is otherwise the dominant cost —
     * millions of block commits per trace).  Separate CP / WP latches so a
     * block reached on BOTH paths handles each path's alternate independently
     * (their not-followed sides can differ).  Meaningful on true-BB (bb_map_)
     * templates; zero-initialised, segment-scoped (dies with bb_map_). */
    bool alt_checked_cp;
    bool alt_checked_wp;
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
    /* Physical PAGE base of the access (physaddr=1, system mode), masked
     * to CST_PPAGE_SHIFT.  ppage_valid is false when no translation was
     * observable (user mode, MMIO-spec, or a garbage-filled wrong-path
     * access) — the CST_FID_*_PPAGE record is then omitted for this slot. */
    uint64_t ppage;
    bool     ppage_valid;
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
    /* Terminal-branch outcome for the CST_FID_BRANCH_TAKEN / _TARGET
     * singletons, carried on WP blocks as well as CP entries.
     * branch_successor_pc is the WP walker's commit_post_pc — the PC this
     * speculative block's terminating branch actually reached, i.e. the next
     * chain block's start_pc (and, for the chain's last block, where the
     * excursion would have continued).  branch_successor_known gates
     * emission.  Direction/target are derived at wire-emit time from the
     * successor and the template's fall-through (see emit_field_delta_section)
     * and delta-encode through the per-chain WP overlay. */
    uint64_t branch_successor_pc = 0;
    bool     branch_successor_known = false;
};

struct BodyEntry {
    uint32_t seq_num;
    uint32_t template_id;
    std::vector<DynParam> dyn_params;
    /* RegSnap vector, ordered: for each insn in the template, n_src
     * snaps only.  Only populated when g_features.reg_data is true. */
    std::vector<RegSnap> reg_snaps;
    std::vector<WPBBEntry> wp_entries;
    /* The wrong-path excursion was kicked but its FIRST target could
     * not be fetched/translated (wp_entries is empty, so there is no
     * WPBBEntry to carry translation_unavailable).  The body writer
     * emits it as a chain-level CST_WP_EVENT_TRANSLATION_UNAVAIL event
     * (resolved index >= num_wp; see docs/format.rst §4.4).
     * Set from simulate_wrong_path_ext's first_tb_unavail out-param;
     * always false in user mode and on REP fan-out sub-entries. */
    bool wp_first_tb_unavail = false;
    BBTemplate *tmpl;  /* Non-owning; for per-insn schema access */
    /* Exception-nesting depth at which this BB executed: 0 = normal code,
     * >=1 = synchronous-fault handler code that detoured execution at that
     * nesting level (system-mode).  Emitted as a metaflag-gated per-entry
     * trailer; absent/0 on a normal entry so user-mode output is unchanged. */
    uint32_t fault_depth = 0;
    /* For a faulting BB reassembled across its fault excursions (whole-BB
     * merge): the indices of the instructions that faulted, one per
     * excursion, in order.  Empty for ordinary entries. */
    std::vector<uint32_t> fault_anchors;
    /* Wire thread identity: the guest-thread id (system-mode pin,
     * resolved from the kernel per-thread pointer and stable across vCPU
     * migration) or the vCPU index (user mode / unpinned).  This is the
     * ONLY thread field that reaches the stream. */
    uint32_t thread_id;
    /* Wire address-space identity: the compact asid index of the live
     * page-table root at capture (0 in user mode / a single address space).
     * Pairs with thread_id as the body context (asid, thread); keys the
     * per-context field-state / regfile tables and drives
     * BODY_TAG_ASID_SWITCH.  Default 0 so any entry built off the main
     * capture path stays single-address-space. */
    uint32_t asid_index = 0;
    /* Context asid index — the PROCESS asid, decoupled from the memory
     * asid above.  Pinned system mode: the entering process's user CR3
     * index, held stable across a kernel excursion.  A kernel (is_system)
     * block carries THIS index on the wire instead of the live root
     * (KPTI-invariant tagging), and the per-(asid,thread) regfile /
     * FieldState tables are keyed by that wire asid — so one guest thread
     * keeps a single register-file context across user<->kernel even
     * under KPTI's distinct kernel CR3.  Equals asid_index in user mode /
     * unpinned (live == process), keeping those traces byte-identical.
     * INTERNAL: feeds the kernel-block wire tag only, never serialised
     * directly.  Default 0 to match asid_index's single-address-space
     * default. */
    uint32_t ctx_asid_index = 0;
    /* QEMU vCPU index this entry came from — used ONLY for live register
     * reads (BODY_TAG_REGFILE capture on a thread's first emit, WP lane
     * gates); never serialised.  Distinct from thread_id: on a system
     * pin one guest thread's entries may carry different cpu_index values
     * across a migration while keeping one thread_id. */
    uint32_t cpu_index;
    /* Terminal-branch outcome for the CST_FID_BRANCH_TAKEN / _TARGET
     * singletons.  branch_successor_pc is the architectural PC reached after
     * this BB's terminating branch — the deferred-seal successor passed to
     * emit_finalized_bb (collect_finalized_bbs' frag_current_pc), which is
     * the next emitted entry's start_pc.  branch_successor_known is false only
     * for a segment's final BB flushed with no observed successor
     * (PathBuilder::flush_final): the FIDs are then omitted and a consumer
     * decoding that lone entry sees no direction/target.  Direction and target
     * are derived at emit time from the successor and the template's
     * fall-through (see emit_field_delta_section). */
    uint64_t branch_successor_pc = 0;
    bool     branch_successor_known = false;
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
    uint64_t insn_count;
    /* Mirror of g_trace_segments.is_active() as a per-vCPU scoreboard
     * slot (1 in-segment, 0 inter-segment).  Backs the cond_cb gate
     * on the per-insn heavy callbacks (reg_snap_cb, synth_ea_cb): a
     * GE-1 condition emitted into the TCG-compiled TB skips the
     * callback at the JIT level when inactive, avoiding the
     * function-call / TLS-cache overhead the callback's C-level
     * early-bail still pays. */
    uint64_t is_active;
    /* 1 while the live address space is the pinned one, 0 otherwise.
     * Maintained by the synchronous ASID-write hook (see
     * asid_write_track_cb): the value only changes at the architectural
     * address-space-register commit points, so a per-write update keeps
     * the flag exact with zero per-TB cost.  Backs the cond_cb that
     * compensates the coarse fast-forward countdown for foreign-process
     * user instructions. */
    uint64_t asid_match;
    /* Context gate for the heavy per-TB capture callback (vcpu_tb_exec).
     * Folds is_active AND pinned-context-ownership into ONE JIT-testable
     * slot so a foreign / unowned TB is never dispatched at all — no
     * callback, no vclock pause, no drop decision.  Byte-identical to
     * is_active everywhere the ownership question is trivial (user mode,
     * unpinned system, and the wide-register system pins whose ASID is a
     * reliable process id); it diverges only for a narrow-ASID (MIPS)
     * system pin, where a recycled ASID cannot distinguish processes and
     * the physical-page probe adjudicates.  Maintained EVENT-DRIVEN (see
     * refresh_ctx_gates): at every is_active edge, at each ASID-write
     * commit, and when the light probe re-acquires the pinned process. */
    uint64_t trace_this_ctx;
    /* Companion gate for the light re-acquisition probe (vcpu_pin_probe),
     * set only for a narrow-ASID system pin.  1 exactly when a segment is
     * active but this vCPU's dwell is NOT a confirmed-owned pinned
     * context: the light probe runs per such TB (a user-clock cursor
     * tick, the physical-page content probe on user TBs, and the capture
     * mute the heavy drop path used to set) and flips trace_this_ctx to 1
     * on the TB that re-acquires the process.  0 (probe never fires) for
     * user mode, unpinned system, and wide-register pins. */
    uint64_t pin_probe;
    /* Signed budget tracking insns until the next window event
     * (segment open in inter-segment, or sentinel "far future" while
     * in-segment).  Bumped by INLINE_ADD_U64(-n_insns) per TB exec
     * so the JIT counts down without a C call; a cond_cb on
     * budget < 1 fires the heavy threshold-handler once when the
     * countdown crosses zero. */
    int64_t budget;
    /* Marker-mode user-clock cursor: this vCPU's insn_count at the
     * last TB the pinned fold observed HERE.  insn_count is per-vCPU
     * (each TB's inline-add bumps its own slot), so the fold's
     * consecutive-read delta must be per-vCPU too — one shared cursor
     * flip-flopping between two active vCPUs' independent counters
     * yields garbage deltas.  USER_SEEN_UNPRIMED marks a cursor whose
     * vCPU has not folded since the last user_count_reset(); its first
     * fold primes the cursor and contributes 0. */
    uint64_t user_seen;
} VCPUScoreBoard;

#define USER_SEEN_UNPRIMED UINT64_MAX

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
    /* Correct-path direction history (conditional branches), for the
     * wpprune cold-branch filter: how many times CP took / fell through
     * this branch.  CP-only, like targets[] — observe_branch_transition
     * is never called during WP. */
    uint32_t taken_count;
    uint32_t nottaken_count;
} BranchRecord;

typedef struct {
    uint64_t insn_pc;
    uint64_t mem_vaddr;
    bool is_store;
    uint8_t data_size;
    CSTWideValue data;
    /* This wrong-path access landed on an absent/unreadable page and was
     * served a deterministic placeholder value (never real memory).  Set from
     * the per-CPU qemu_plugin_spec_mem_faulted_take() flag; the walker marks
     * the owning WP BB entry as a synthetic-data fault at this insn. */
    bool faulted = false;
    /* Physical PAGE base (physaddr=1, system mode), masked to
     * CST_PPAGE_SHIFT.  ppage_valid is false when qemu_plugin_get_hwaddr
     * resolved no translation (user mode always; MMIO/absent-page spec
     * accesses on the wrong path) — the ppage FID is then omitted. */
    uint64_t ppage = 0;
    bool ppage_valid = false;
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
/* Privilege level (normalized, 0 = user) at which the target executes
 * WITHOUT translating through the address-space register that
 * qemu_plugin_get_addr_space_id() reports, or -1 when every privilege
 * level translates.  Set once during qemu_plugin_install.  At such a
 * level the reported register is a stale bystander — execution there is
 * firmware/monitor work that belongs to no guest address space — so the
 * pinned-attribution path drops those TBs (see the foreign-ASID
 * boundary in champsim_tracer_path_builder.cc).  Currently RISC-V
 * M-mode (priv 3): M-mode fetches bypass satp entirely, so OpenSBI
 * handling a sync SBI ecall still reads the pinned process's satp. */
extern int g_xlate_bypass_priv;
/* True when the guest target is big-endian (currently only MIPS BE, when
 * trace_isa==TRACE_ISA_MIPS and target_name does not end in "el").  Set
 * once during qemu_plugin_install.  qemu_plugin_read_register() returns
 * bytes in target byte order; the reg-snap path normalises those bytes
 * to little-endian before they reach the trace, so the on-disk format
 * is unconditionally LE regardless of guest endianness. */
extern bool target_big_endian;

/* True when @pc is a KERNEL code virtual address for the guest ISA — a
 * speculation-proof architectural classification (kernel/user VA ranges are
 * disjoint), unlike the privilege level a wrong-path walk can mis-stamp on a
 * speculatively-translated user VA.  Delegates to QEMU's own per-target MMU /
 * segment logic through the qemu_plugin_vaddr_is_kernel() plugin API (which
 * asks the target's TCGCPUOps hook), so there is no parallel VA-boundary
 * constant table in the plugin.  Drives the shared kernel template bucket
 * (store_asid_root), seeds is_system for wrong-path-only-discovered blocks,
 * and gates the wrong-path privilege-domain-switch terminate (multiasid_plan
 * §7).  In user mode the target reports no kernel domain, so every code VA
 * classifies user, the sentinel bucket is never used, and single-ASID output
 * stays byte-identical to the pre-classifier scheme. */
static inline bool cst_va_is_kernel_code(uint64_t pc)
{
    return qemu_plugin_vaddr_is_kernel(pc);
}

extern const InsnClassification *active_insn_table;
extern unsigned active_insn_table_size;
extern const RegClassification *active_reg_table;
extern unsigned active_reg_table_size;

/* Plugin configuration: parsed from -plugin args, immutable after
 * qemu_plugin_install. */
extern int max_wrong_path_depth;
extern int g_wp_prune;
extern bool enable_wrong_path;
/* Self-modifying-code per-PC revision cap (smc_plan.md §5-A).  When a
 * correct-path (asid_root, start_pc) slot mints more than this many DISTINCT
 * executed states, minting stops: the body keeps referencing the last
 * revision and a LOUD once-per-segment warning fires.  The cap is a BUG
 * DETECTOR sized far above any legitimate SMC pattern, not a fidelity budget;
 * default 1024, settable via smc_revisions=N and overridable for testing via
 * the CST_SMC_REVISION_CAP env var. */
extern uint32_t g_smc_revision_cap;
/* #77 diagnostic ring buffer (gated on CST_RING); 'C'=correct-path BB start,
 * 'W'=wrong-path instruction PC. */
void cst_ring_push(char tag, uint64_t pc);
/* Default depth of the alternate-minting successor walk (static_depth=N).
 * Chosen by the knee of the coverage/size sweep on mcf + system churn:
 * beyond this, executed-fall-through resolution barely rises while the
 * template count keeps climbing. */
#define CST_ALT_DEPTH_DEFAULT 4

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
    /* System-mode synchronous-fault DEPTH TRAILER: when set, entries carry
     * the per-entry fault trailer (CST_FLAG_FAULT) so handler code is tagged
     * with its exception-nesting depth and faulting BBs carry the detour
     * anchor, and the PathBuilder runs the kernel-handler whole-BB fault
     * merge.  Enabled only in marker (system) mode or a pinned simpoint;
     * off in user mode, so user-mode traces carry no trailer.  This is the
     * kernel-privilege depth machinery — decoupled from the wrong-path
     * fault-poisoning policy below, which runs in BOTH modes. */
    bool     fault_depth_trailer = false;
    /* Synchronous-fault handler tracing (faults=1, default).  Orthogonal to
     * fault_depth_trailer, which gates the depth-trailer WIRE machinery and
     * the kernel-handler merge in system mode: when trace_faults is off
     * (faults=0) that machinery still runs — the interrupted BB reassembles
     * whole through the merge — but the handler blocks are capture-suppressed
     * and every emitted entry is de-anchored and clamped to depth 0, so a
     * synchronous fault's handler excursion is excluded exactly as an async
     * interrupt's is.  Meaningful only where fault_depth_trailer is on. */
    bool     trace_faults = true;
    /* Asynchronous-interrupt handler tracing (interrupts=1).  Off by default:
     * an async excursion suspends (the handler is excluded, the interrupted
     * flow seals against its real successor).  When on, the async handler is
     * CAPTURED — its kernel blocks ride the fault depth trailer at exception
     * depth >= 1 (a captured async window contributes one level, added to any
     * live synchronous-fault nesting) and the interrupted block seals against
     * the departure PC so no phantom edge runs through the handler entry.
     * System mode only (forced off in user mode, where no async delivery
     * exists), so a user-mode trace is byte-identical regardless. */
    bool     trace_interrupts = false;
    /* Wrong-path SYNTHETIC-FAULT marking policy: when set, a speculative
     * memory access to an absent/unreadable page — served a deterministic
     * placeholder value instead of real memory (accel/tcg garbage-fill seam) —
     * marks its owning WP BB entry with CST_WP_EVENT_FAULT at the faulting
     * insn.  The excursion CONTINUES on the placeholder (no truncation, no
     * poison): on a mispredicted path no instruction retires, so the fault is
     * never taken by a real core.  A non-memory synchronous fault (arithmetic
     * / illegal opcode) still stops the excursion cleanly at its marked BB
     * (interim, pending the arithmetic pass).  ON whenever wrong-path
     * simulation runs — system AND user mode alike.  CST_NO_FAULT clears it
     * for A/B: accesses still run on garbage, but the fault is not marked. */
    bool     wp_synthetic_marking = false;
    /* Kernel-excursion ownership (kexc=1): attribute kernel (priv!=0) TBs
     * by the owning excursion's entry ASID — tracked through ASID-write
     * path events — instead of by the live ASID, so PTI-style kernel
     * entry switches don't drop the pinned process's synchronous kernel
     * work.  Off (default) keeps the live-ASID rule byte-for-byte; the
     * PathBuilder then consumes-and-ignores ASID_WRITE events.  See the
     * ownership state machine in champsim_tracer_path_builder.h. */
    bool     kexc = false;
    /* Physical-page capture (physaddr=1): record the physical PAGE base of
     * every load/store so a consumer can rebuild the physical address as
     * ppage | (vaddr & CST_PPAGE_OFFSET_MASK).  SYSTEM MODE ONLY — forced
     * off in user mode (qemu_plugin_get_hwaddr returns NULL there), so a
     * user-mode trace never emits the CST_FID_*_PPAGE families and stays
     * byte-identical.  Sets CST_FLAG_PHYSADDR in the header when on. */
    bool     physaddr = false;
    /* Opportunistic branch-alternate minting (static_templates=1, BOTH
     * modes).  At every evaluated branch on the correct path and inside a
     * wrong-path excursion, the UNTAKEN side's true BB is decoded and minted
     * as a never-executed dictionary template if not already covered — the
     * fall-through / branch-target coverage a trace-inferred wrong-path
     * consumer needs, filled convergently as branches are seen.  Mode-
     * independent (it reads guest bytes at a branch's untaken target through
     * the same probing read the wrong path uses), so it gives system-mode
     * traces their never-executed coverage as well as user-mode's.  Enabled
     * by static_templates=1 in either mode; carries NO wire flag (alternates
     * are ordinary never-executed entries), so a trace without it is
     * byte-identical. */
    bool     alt_mint = false;
    /* Depth-N alternate exploration (static_depth=N, default CST_ALT_DEPTH_
     * DEFAULT).  From each minted alternate BB, follow its statically-known
     * successors — the architectural fall-through always, and a direct
     * branch's decoded target — recursively up to N levels, minting each
     * never-executed block along the way (dedup + per-segment mint budget
     * bound the walk; an indirect terminator has no static target, so that
     * edge ends the chain).  0 mints only the immediate untaken side (no
     * successor walk).  Inert unless alt_mint is on. */
    uint32_t alt_depth = 0;
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

/* Is @pc a TB start_pc that has been poisoned (decode failure or
 * byte change detected at translation time)?  Acquires data_lock. */
bool cst_pc_is_poisoned(uint64_t pc);

/* Phase-2 ASID identity of the single pinned address space (see
 * multiasid_plan.md §2), read on the body-stream emit path to fill the
 * BODY_TAG_ASID_SWITCH record's first-sighting identity.  Root = the
 * page-table root physical address (masked CR3 / TTBR base / SATP PPN /
 * MIPS pgd); sig = a stable representative code-page content signature.
 * Both are 0 when unpinned (user mode / no marker), keeping user traces
 * byte-identical.  The emit path holds exec_lock, as does every writer. */
uint64_t cst_pinned_asid_root(void);
uint64_t cst_pinned_asid_sig(void);

/* Identity (page-table root physical address + content signature) of a
 * compact asid index, as recorded on the index's first sighting.  Returns
 * false for an unassigned index.  The body-stream emit path carries this
 * inline on an index's first BODY_TAG_ASID_SWITCH.  Caller holds exec_lock,
 * as does every writer of the identity store. */
bool cst_asid_identity(uint32_t index, uint64_t *root, uint64_t *sig);

/* Why the most recent spec-mode exec_tb produced no template (TLS; set
 * before each spec exec_tb, refined by detect_tb_poison).  Diagnostic
 * plumbing for the wrong-path first-TB-unavailable classification. */
enum class SpecRefusal : uint8_t { NONE, FETCH, POISON };
extern thread_local SpecRefusal g_last_spec_refusal;

/* Synchronization & diagnostics.  Must stay GMutex, not std::mutex:
 * <mutex> pulls <ctype.h>, which QEMU's include/qemu/ctype.h shadows
 * on the plugin -I path, breaking libstdc++'s `using ::isalnum;`. */
extern GMutex data_lock;
extern GMutex unknown_warn_lock;
extern FILE *unknown_warn_file;

/* Null-safe string equality (cst_str_eq) is defined in
 * champsim_tracer_mnemonics.h, which this header pulls in below. */

/* ===== Cross-TU functions ===== */

/*
 * Opportunistic branch-alternate minting (static_templates=1).  Defined in
 * champsim_tracer.cc.  No-op unless g_features.alt_mint.  Caller holds
 * exec_lock and must NOT hold data_lock (both take data_lock internally,
 * releasing it around the guest-byte read).
 */

/* Decode and mint the true BB starting at @alt_pc as a never-executed
 * dictionary template (alt_map_), unless it is already covered by an
 * executed or previously-minted template, the per-segment mint budget is
 * exhausted, or its page is unmapped (probing read fails → silently
 * skipped).  @alt_pc is a branch's untaken successor (fall-through or taken
 * target).  When static_depth>0, each freshly-minted block's own
 * statically-known successors (fall-through always; a direct branch's
 * decoded target too) are followed recursively up to that depth. */
void altmint_pc(uint64_t alt_pc);

/* Convenience for the wrong-path walker: given a completed block's terminal
 * branch @terminal, its architectural fall-through @fall_through, and the
 * successor the walk actually followed @followed_pc, mint the UNTAKEN side
 * (the statically-known alternate of a conditional-direct branch).  A no-op
 * for unconditional / indirect terminators (no decodable untaken side) or
 * when @followed_pc is neither edge (a fault redirect). */
void altmint_conditional_alternate(const InsnFields *terminal,
                                   uint64_t fall_through,
                                   uint64_t followed_pc);

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
 * table's QEMU descriptors.  RegSnapCollector::capture_wide() builds one
 * (a single upfront snapshot of every readable register); unused by the
 * WP loop today, which instead reads each instruction's destination
 * registers live — see champsim_tracer_reg_snap_collector.h.
 */
typedef struct _WideRegSnap WideRegSnap;

/* Reg-snap capture is provided by RegSnapCollector; see
 * champsim_tracer_reg_snap_collector.h. */

/* Defined in champsim_tracer_wp.cc.  Returns the speculative chain by
 * value; callers move it into BodyEntry::wp_entries.
 * @first_tb_unavail is set when the excursion's FIRST wrong-path
 * target could not be fetched/translated (genuine null, no flush): the
 * returned chain is empty and carries no WPBBEntry to mark, so the
 * condition rides this out-param instead.  The emitter records it as a
 * chain-level CST_WP_EVENT_TRANSLATION_UNAVAIL event (§4.4 of
 * docs/format.rst). */
#ifdef __cplusplus
std::vector<WPBBEntry> simulate_wrong_path_ext(uint64_t branch_pc,
                                               uint64_t correct_target,
                                               uint64_t wrong_target,
                                               unsigned int cpu_index,
                                               bool *flush_interrupted,
                                               bool *first_tb_unavail);
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

/*
 * ---- Block-device (disk) I/O records (DEVIO) ----
 *
 * The devio state is process-wide (one block backend), owned by
 * champsim_tracer_output.cc and serialised by its own mutex.  The
 * plugin's registered devio hooks call note_doorbell (in vCPU context,
 * at the virtqueue kick) / note_start (block-backend issue) / note_stop
 * (block-backend completion); the pending START/STOP records are drained
 * into the body stream at the next body entry (under exec_lock).  A
 * DEVIO_START carries its owner EXPLICITLY when the doorbell captured in
 * vCPU context correlates to it, otherwise it is positional.  A
 * DEVIO_STOP lands where the completion resumes.  Reset per segment.
 *
 * Correlation is a bounded FIFO of queued kicks per KICKING vCPU, matched
 * at issue against that SAME vCPU's FIFO by device token, oldest match
 * first — not a single per-vCPU slot, and not a search across every
 * vCPU.  A single slot assumed the kick and the matching blk_aio_* issue
 * always run back to back with nothing able to land in between; that
 * assumption breaks when one vCPU rings the doorbell twice before the
 * first is drained, overwriting the slot the first issue was about to
 * read.  The FIFO fixes it: each vCPU's FIFO has exactly one producer
 * (that vCPU's own doorbell, already BQL-serialised), so a burst of
 * kicks queues up instead of clobbering, and note_start matches
 * oldest-kick-first, mirroring a device's own in-order queue service.
 * The lookup stays scoped to the ISSUING vCPU rather than searching
 * every FIFO: virtio-blk's default queue count tracks the vCPU count,
 * so a multi-vCPU guest ordinarily runs one virtqueue per vCPU, and the
 * device token alone (the block backend has no queue index to report)
 * cannot tell two vCPUs' queues apart — only the issuing vCPU can.
 * Widening the search to every FIFO regardless of vCPU identity can
 * reattribute a request to whichever vCPU holds the globally-oldest
 * matching kick even when it belongs to a DIFFERENT queue, exactly the
 * concurrent multi-process failure this exists to get right and exactly
 * what 88d9b7e526's own report rejected a shared per-device FIFO over.
 * Each FIFO is capped; an overflowing kick is DROPPED (never evicts an
 * older, still-unmatched entry) so its own request falls back to
 * positional instead of ever borrowing a wrong owner.  See the
 * champsim_tracer_output.cc file-header comment for the full rationale.
 */

/* Doorbell: the guest kicked a block device's virtqueue on vCPU
 * @vcpu_index (correct path, vCPU context).  Push that vCPU's current
 * owning (thread_id, asid) and the device @dev_token onto @vcpu_index's
 * own kick FIFO, so a later note_start on that SAME vCPU can match it in
 * kick order. */
void devio_note_doorbell(int vcpu_index, uint64_t dev_token,
                         uint32_t owner_thread_id, uint32_t owner_asid);
/* Issue: assign a compact per-segment request id, compute the disk
 * block number (offset >> CST_DEVIO_LBA_SHIFT), and queue a pending
 * DEVIO_START.  When @vcpu_index is known (>=0), searches ONLY that
 * vCPU's kick FIFO for the oldest queued kick whose device token
 * matches @dev_token — @vcpu_index is what disambiguates two vCPUs'
 * separate virtqueues sharing one device token, so the lookup never
 * crosses into another vCPU's FIFO (see the file-header comment).  When
 * @vcpu_index is unknown (-1, off any vCPU thread), widens to every
 * FIFO and takes the globally oldest match as the best available guess.
 * Stamps the exact owner and pops the matched entry on a hit; otherwise
 * the record is positional.  @dir is a CST_DEVIO_* value.  Returns the
 * request id (always nonzero — the caller decides whether to track). */
uint64_t devio_note_start(int vcpu_index, int dir,
                          uint64_t offset, uint64_t bytes,
                          uint64_t dev_token);
/* Completion: queue a pending DEVIO_STOP for @request_id (dropped at
 * drain if its START never reached the wire, e.g. a segment switch). */
void devio_note_stop(uint64_t request_id);
/* Segment-open reset: clear pending records, the live-id set, the
 * per-vCPU kick FIFOs, and the per-segment id / sequence counters. */
void devio_reset_segment(void);
/* Advertise the DEVIO_* body-tag names in the header encoding map only
 * when the disk-I/O hook is active (system mode + devio enabled), so a
 * device-free trace keeps the historical body_tag vocabulary and stays
 * byte-identical. */
void devio_set_map_active(bool on);
/* Finish the body stream and hand the accumulated header buffer
 * back to the caller via @header_bytes (transferred ownership; the
 * caller must g_byte_array_unref it after writing).  The body
 * destination (the WriterCtx passed to body_stream_new) is closed
 * by the segment manager separately after this returns. */
void body_stream_finish(BodyStreamState *st, GByteArray **header_bytes);
/* Stash the in-trace architectural CP-insn count at which warmup
 * ends and the simulation phase begins, so finish writes it into
 * the header (§2.13 in docs/format.rst).  Call before
 * body_stream_finish.  0 = no warmup configured / warmup never
 * elapsed (the entire trace is warmup). */
void body_stream_set_warmup_end_arch_insns(BodyStreamState *st,
                                           uint64_t value);
/* Free a BodyStreamState.  Required (not free()): it carries
 * std::vector members needing destructors, and the opaque forward
 * decl here doesn't let callers `delete` directly. */
void body_stream_free(BodyStreamState *st);

#endif /* CHAMPSIM_TRACER_H */
