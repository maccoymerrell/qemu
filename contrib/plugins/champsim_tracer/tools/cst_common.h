/*
 * ChampSim Tracer offline tools — shared wire-format types.
 *
 * Glib-free, plugin-API-free, mmap-friendly POD types for the .cst
 * trace format, so the tools build without QEMU plugin/glib headers.
 *
 * The trace is self-describing: every header carries encoding maps
 * mapping wire ids to stable names.  The tools key off those names,
 * not the plugin's compile-time enums, so a future tracer that adds
 * new ids still decodes as long as its maps carry them.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "../cst_wire_spec.h"

namespace cst {

/* ===== Wire-format magic =====
 *
 * .cst is a POSIX-ustar archive of body.cst[.<codec>] +
 * header.cst[.<codec>].  Each member starts with CST_MAGIC; the body
 * also carries a trailing CST_MAGIC after BODY_TAG_END so truncation
 * is detectable at either end.
 *
 * Magic and the layout caps below are aliased from the shared spec
 * (../cst_wire_spec.h) so writer and readers can't diverge. */

inline constexpr uint32_t CST_MAGIC = cst_wire::MAGIC;

} /* namespace cst */

/* DEVIO_START rw byte values (BODY_TAG_DEVIO_START).  Macros (not in
 * namespace cst) so the decoder frontends can name them unqualified,
 * mirroring the plugin's champsim_tracer.h. */
#define CST_DEVIO_READ   0
#define CST_DEVIO_WRITE  1
#define CST_DEVIO_FLUSH  2

/* DEVIO_START attribution byte: EXACT carries inline owner (thread,
 * asid); POSITIONAL carries none and uses the stream-position context. */
#define CST_DEVIO_ATTR_POSITIONAL 0
#define CST_DEVIO_ATTR_EXACT      1

namespace cst {

/* ===== Format-layout invariants =====
 *
 * Buffer-size limits the encoding maps cannot describe.  Everything
 * else (flag bits, field_id assignments) IS derivable from the
 * header's maps via resolve_ids(); never hardcode those. */
inline constexpr uint16_t FID_SLOT_COUNT       = cst_wire::FID_SLOT_COUNT;
/* Intentionally no FID_SLOT_STRIDE / FID_LANE_BLOCK_STRIDE: slot->FID
 * is defined entirely by the CST_FID_<family><k> map entries;
 * consumers MUST look each slot's FID up by name, never by stride.
 * See ResolvedIds for the per-slot arrays. */
inline constexpr size_t  MAX_WIDE_BYTES       = cst_wire::WIDE_BYTES_MAX;
inline constexpr int     MAX_INSN_BYTES       = cst_wire::INSN_BYTES_MAX;

/* One resolved FID per wire slot of a slotted family (see ResolvedIds).
 * Sized by the wire ceiling rather than by observed occupancy: it is a
 * fixed per-header table, not a per-entry or per-template structure. */
using FidSlotArray = std::array<uint16_t, FID_SLOT_COUNT>;

/* ===== Resolved IDs =====
 *
 * parse_header reverse-resolves the well-known names in the trace's
 * encoding maps into this struct (throwing on any missing name); the
 * tools dispatch on @h.ids.<name> so the wire format stays the single
 * source of truth.  Names mirror the symbols the plugin emits (see
 * champsim_tracer_output.cc::write_header_encoding_maps). */
struct ResolvedIds {
    /* body_tag map */
    uint8_t body_tag_end           = 0;
    uint8_t body_tag_entry         = 0;
    uint8_t body_tag_thread_switch = 0;
    uint8_t body_tag_iframe        = 0;
    uint8_t body_tag_regfile       = 0;
    uint8_t body_tag_asid_switch   = 0;
    /* Disk-I/O records (BODY_TAG_DEVIO_START / _STOP).  Optional: a
     * device-free trace names neither, so these default to a sentinel
     * (0xFF) that no real tag byte (0..7) can equal — dispatch on them
     * simply never fires for a trace that predates the feature. */
    uint8_t body_tag_devio_start   = 0xFF;
    uint8_t body_tag_devio_stop    = 0xFF;

    /* field_id map: per-slot FID arrays + singletons.  FIDs are
     * ULEB128 on the wire; per-slot arrays are filled by name lookup
     * of CST_FID_<family><k> per k (no stride assumption).  Sized by
     * FID_SLOT_COUNT so the arrays track the wire's slot ceiling
     * automatically; an entry a trace does not advertise stays 0. */
    uint16_t fid_n_loads          = 0;
    uint16_t fid_n_stores         = 0;
    uint16_t fid_metaflags        = 0;
    FidSlotArray fid_load_addr             {};
    FidSlotArray fid_store_addr            {};
    FidSlotArray fid_load_data             {};
    FidSlotArray fid_store_data            {};
    FidSlotArray fid_dst_reg               {};
    /* Per-slot byte width of each memop value / dst-register write
     * (CST_FID_LOAD_SIZE / STORE_SIZE / DST_REG_WIDTH), for value
     * prediction.  Gated with their value families. */
    FidSlotArray fid_load_size             {};
    FidSlotArray fid_store_size            {};
    FidSlotArray fid_dst_reg_width         {};
    FidSlotArray fid_src_lane_mask         {};
    FidSlotArray fid_dst_lane_mask         {};
    FidSlotArray fid_load_data_lane_mask   {};
    FidSlotArray fid_store_data_lane_mask  {};
    /* Per-slot physical PAGE base of each memop (CST_FID_LOAD_PPAGE /
     * STORE_PPAGE).  Present only on CST_FLAG_PHYSADDR (system-mode) traces;
     * absent -> sentinel 0, so a non-physaddr trace resolves none. */
    FidSlotArray fid_load_ppage            {};
    FidSlotArray fid_store_ppage           {};
    uint16_t fid_insn_bytes_lo    = 0;
    uint16_t fid_insn_bytes_hi    = 0;
    uint16_t fid_insn_opcode      = 0;
    uint16_t fid_insn_branch_type = 0;
    uint16_t fid_insn_flags       = 0;
    uint16_t fid_insn_immediate   = 0;
    uint16_t fid_insn_size        = 0;
    uint16_t fid_extended         = 0;
    /* Branch-outcome singletons on the terminating branch (always advertised
     * by a post-branch writer): direction (1=taken) and dynamic target PC.
     * Sentinel 0 (never resolves) on traces predating the feature — a
     * consumer then falls back to successor look-ahead. */
    uint16_t fid_branch_taken     = 0;
    uint16_t fid_branch_target    = 0;

    /* insn_flag map: bit masks inside the per-insn flags byte */
    uint8_t insn_flag_branch_cond   = 0;
    uint8_t insn_flag_has_imm       = 0;
    uint8_t insn_flag_atomic        = 0;
    uint8_t insn_flag_vec           = 0;
    uint8_t insn_flag_lane_parallel = 0;
    uint8_t insn_flag_has_dep_block = 0;
    /* Optional (absent in traces predating the bit): 0 = never set. */
    uint8_t insn_flag_system        = 0;

    /* dep_block_flag map: bit masks inside the optional dep sub-block
     * header (only inspected when insn_flag_has_dep_block is set on
     * the per-insn flags byte). */
    uint8_t dep_block_has_reg  = 0;
    uint8_t dep_block_has_addr = 0;

    /* header_flag map: bit masks inside Header::flags */
    uint8_t flag_mem_data = 0;
    uint8_t flag_reg_data = 0;
    /* Bit mask within Header::flags marking the per-template
     * profile block present. */
    uint8_t flag_profile = 0;
    /* Bit mask within Header::flags marking the per-entry
     * wrong-path chain + events sections present. */
    uint8_t flag_wp = 0;
    /* Bit mask within Header::flags marking the per-entry synchronous-fault
     * trailer (exception-nesting depth, + anchor on a faulting BB) present. */
    uint8_t flag_fault = 0;
    /* Bit mask within Header::flags marking the physical-page families
     * (CST_FID_LOAD_PPAGE / STORE_PPAGE) present.  Optional: 0 (never set)
     * on user-mode / non-physaddr traces. */
    uint8_t flag_physaddr = 0;

    /* wp_event_flag map: bit masks inside the per-WP-event flags byte */
    uint8_t wp_event_translation_unavail = 0;
    uint8_t wp_event_fault               = 0;

    /* wp_chain_flag map: bit mask inside the WP chain section's leading
     * ULEB (packed alongside num_wp; see CST_WP_CHAIN_HAS_EVENTS).
     * Announces whether a wp_events_section follows this entry's chain. */
    uint8_t wp_chain_has_events = 0;

    /* metaflags map: bit positions inside the FID_METAFLAGS byte */
    uint8_t metaflags_z = 0;
    uint8_t metaflags_n = 0;
    uint8_t metaflags_c = 0;
    uint8_t metaflags_v = 0;
    uint8_t metaflags_p = 0;
};

/* ===== 512-bit unsigned scalar ===== */

struct Wide {
    static constexpr size_t LIMBS = MAX_WIDE_BYTES / sizeof(uint64_t);
    std::array<uint64_t, LIMBS> limb{};

    constexpr Wide() = default;

    static Wide from_u64(uint64_t v) {
        Wide w;
        w.limb[0] = v;
        return w;
    }

    static Wide from_le_bytes(const uint8_t *bytes, size_t n) {
        Wide w;
        if (n > MAX_WIDE_BYTES) n = MAX_WIDE_BYTES;
        std::memcpy(w.limb.data(), bytes, n);
        return w;
    }

    /* Truncate to a single u64 (low limb).  Most addresses, opcodes,
     * branch types fit here; callers fall back to the full limbs only
     * when wider data is on the wire (data values, vector-register
     * snaps). */
    uint64_t low64() const { return limb[0]; }
    uint64_t hi64()  const { return limb[1]; }

    bool fits_u64() const {
        for (size_t i = 1; i < LIMBS; i++) {
            if (limb[i]) return false;
        }
        return true;
    }

    /* (a + delta) mod 2^N (N=512).
     * @delta is a fully sign-extended Wide-shaped 8-limb array (the
     * shape produced by Reader::sleb_wide). */
    void add_signed_mod_wide(const std::array<uint64_t, LIMBS> &add,
                             int width_bits) {
        uint64_t carry = 0;
        for (size_t i = 0; i < LIMBS; i++) {
            uint64_t s1 = limb[i] + add[i];
            uint64_t c1 = (s1 < limb[i]) ? 1u : 0u;
            uint64_t s2 = s1 + carry;
            uint64_t c2 = (s2 < s1) ? 1u : 0u;
            limb[i] = s2;
            carry = c1 + c2;
        }
        size_t full_limbs = width_bits / 64;
        size_t rem_bits = width_bits % 64;
        for (size_t i = full_limbs; i < LIMBS; i++) {
            if (i == full_limbs && rem_bits) {
                limb[i] &= (1ull << rem_bits) - 1;
            } else {
                limb[i] = 0;
            }
        }
    }

    /* Convenience: 64-bit signed delta sign-extended to the full
     * width.  Suitable for compact fields where the delta is known
     * to fit in int64_t. */
    void add_signed_mod(int64_t delta, int width_bits) {
        std::array<uint64_t, LIMBS> add{};
        add[0] = (uint64_t)delta;
        if (delta < 0) {
            for (size_t i = 1; i < LIMBS; i++) add[i] = ~uint64_t(0);
        }
        add_signed_mod_wide(add, width_bits);
    }
};

inline bool operator==(const Wide &a, const Wide &b) {
    return a.limb == b.limb;
}
inline bool operator!=(const Wide &a, const Wide &b) {
    return a.limb != b.limb;
}

/* ===== Decoded entry shapes (consumer-facing) ===== */

struct DynParam {
    enum Type : uint8_t { Load, Store };
    Type     type        = Load;
    uint32_t insn_index  = 0;
    uint64_t addr        = 0;     /* always low 64 bits (virtual)          */
    Wide     data{};              /* full width when has_mem_data          */
    bool     has_data    = false;
    uint8_t  data_size   = 0;     /* access byte width; 0 = not captured    */
    /* Physical PAGE base of the access (CST_FLAG_PHYSADDR traces, system
     * mode), masked to cst_wire::PPAGE_SHIFT.  has_ppage is false when the
     * trace carried no translation for this memop (a non-physaddr trace,
     * an MMIO/absent-page spec access) — paddr() is then undefined. */
    uint64_t ppage       = 0;
    bool     has_ppage   = false;

    /* Reconstructed physical address: the recorded physical page base ORed
     * with the in-page offset carried by the virtual address.  Valid only
     * when has_ppage. */
    uint64_t paddr() const {
        return ppage | (addr & cst_wire::PPAGE_OFFSET_MASK);
    }
};

struct RegSnap {
    uint32_t insn_index    = 0;
    uint8_t  operand_index = 0;
    uint8_t  reg_id        = 0;
    Wide     value{};             /* full width */
    uint8_t  width_bytes   = 0;   /* write byte width; 0 = not captured */
};

/* Per-insn metaflags byte (FID_METAFLAGS).  Only emitted for insns
 * whose template writes the ISA's integer-flags register. */
struct MetaFlagsEntry {
    uint32_t insn_index = 0;
    uint8_t  byte       = 0;
};

/* Per-(insn, slot) lane-mask record materialised from the dynamic
 * CST_FID_*_LANE_MASK FID cells.  Family identifies which operand
 * family the slot indexes into, and the mask carries the lane bits
 * the slot participated in for this instance (bit k = lane k). */
struct LaneMaskEntry {
    enum Family : uint8_t { Src = 0, Dst = 1, LoadData = 2, StoreData = 3 };
    uint32_t insn_index  = 0;
    Family   family      = Src;
    uint8_t  slot_index  = 0;
    uint64_t mask        = 0;
};

/* Terminal-branch outcome decoded from the CST_FID_BRANCH_TAKEN / _TARGET
 * singletons, exposed directly per entry so a consumer never decodes the
 * successor to recover the branch's direction or dynamic target.  valid is
 * true iff the entry's template ends in a branch (a page-split continuation
 * carries no branch); target == the architectural landing PC (equal to the
 * fall-through when not taken).  On a trace predating the feature valid is
 * false — the fields are unset and a consumer falls back to look-ahead. */
struct BranchOutcome {
    bool     valid  = false;
    bool     taken  = false;
    uint64_t target = 0;
};

struct WPEntry {
    uint32_t                    index = 0;
    uint32_t                    template_id = 0;
    std::vector<DynParam>       dyn_params;
    std::vector<RegSnap>        reg_snaps;
    std::vector<MetaFlagsEntry> metaflags;
    std::vector<LaneMaskEntry>  lane_masks;
    bool                        fault = false;
    bool                        translation_unavailable = false;
    /* Only meaningful when fault. */
    uint32_t                    fault_insn_index = 0;
    bool                        has_fault_idx = false;
    uint32_t                    n_insns = 0;
    /* Terminal-branch direction/target (CST_FID_BRANCH_*) for this WP block,
     * decoded directly (displacement reconstructed to an absolute successor
     * PC).  valid iff the block's template ends in a branch; the successor is
     * the next chain block's start_pc, so a self-check can cross-verify it
     * in-chain. */
    BranchOutcome               branch;
};

struct DecodedEntry {
    uint32_t                    seq_num = 0;
    uint32_t                    template_id = 0;
    uint32_t                    thread_id = 0;
    bool                        thread_switched = false;
    /* Address-space (ASID) index the entry executed under — the second
     * half of the (thread_id, asid) context.  Memory is keyed
     * (asid, vaddr); identical VAs under different asids are distinct
     * physical memory.  Rebased by BODY_TAG_ASID_SWITCH records. */
    uint32_t                    asid = 0;
    std::vector<DynParam>       dyn_params;
    std::vector<RegSnap>        reg_snaps;
    std::vector<MetaFlagsEntry> metaflags;
    std::vector<LaneMaskEntry>  lane_masks;
    std::vector<WPEntry>        wp_entries;
    /* Chain-level TRANSLATION_UNAVAIL event (wp_events index >= num_wp,
     * §4.4): the wrong-path excursion was kicked but its first target
     * could not be fetched/translated, so wp_entries is empty and the
     * event applies to the chain as a whole. */
    bool                        wp_first_fetch_unavailable = false;
    /* Exception-nesting depth (CST_FLAG_FAULT traces): 0 = normal code,
     * >=1 = synchronous-fault handler code at that nesting level. */
    uint32_t                    fault_depth = 0;
    /* Faulting-instruction indices for a whole-BB-merged faulting BB (one
     * per fault excursion, in order); empty for ordinary entries. */
    std::vector<uint32_t>       fault_anchors;
    /* Terminal-branch direction/target (CST_FID_BRANCH_*), materialised
     * directly so a consumer need not decode the successor entry.  valid iff
     * the template ends in a branch; target == the architectural successor
     * (the next entry's start_pc), so a self-check can cross-verify it. */
    BranchOutcome               branch;
};

/* Forward declarations so Instruction can hold non-owning pointers
 * to template metadata defined further down in this header. */
struct Template;
struct InsnTemplate;

/*
 * Per-architectural-instance instruction container: one materialised
 * execution (correct- or wrong-path).  cst::instructions_from_entry()
 * fans a DecodedEntry into these (CP insns then WP insns in chain
 * order) with dyn_params/reg_snaps/metaflags pre-filtered per insn.
 * Static fields are copies so an Instruction outlives its
 * DecodedEntry; Templates are non-owning pointers, bb_template_id
 * keeps the linkage symbolic for consumers that drop them.
 */
struct Instruction {
    /* Static template fields (copies). */
    uint64_t              pc                  = 0;
    uint8_t               opcode              = 0;
    uint8_t               branch_type         = 0;
    bool                  branch_conditional  = false;
    bool                  has_immediate       = false;
    int64_t               immediate           = 0;
    bool                  is_atomic           = false;
    std::vector<uint8_t>  src_regs;
    std::vector<uint8_t>  dst_regs;
    std::vector<uint8_t>  raw_bytes;          /* 0..16 bytes */

    /*
     * Template-static MAX counts and intra-instruction dep masks.
     * Forwarded from InsnTemplate so the renderer can show precise
     * per-dst / per-store / per-memop dependency chains instead of
     * the over-approximating "every src → every dst" arrow.  When
     * the trace did not carry the corresponding sub-block, the
     * vectors stay empty and the renderer falls back to all-to-all.
     */
    uint32_t              max_dep_loads       = 0;
    uint32_t              max_dep_stores      = 0;
    bool                  has_reg_deps        = false;
    bool                  has_addr_deps       = false;
    std::vector<uint64_t> dst_dep_mask;
    std::vector<uint64_t> store_data_dep_mask;
    std::vector<uint64_t> load_addr_dep_mask;
    std::vector<uint64_t> store_addr_dep_mask;

    /* Per-slot lane participation from the dynamic lane-mask FID
     * cells.  Bit k of mask[i] set iff lane k of slot i participates.
     * Empty/zero on scalar instances and pre-lane-mask traces.
     * lane_parallel (template-static, CST_INSN_FLAG_LANE_PARALLEL):
     * set => lane k of each dst depends only on lane k of every src;
     * clear => lanes don't line up by index (shuffles/broadcasts/
     * horizontal reductions). */
    bool                  lane_parallel       = false;
    std::vector<uint64_t> src_lane_mask;
    std::vector<uint64_t> dst_lane_mask;
    std::vector<uint64_t> load_data_lane_mask;
    std::vector<uint64_t> store_data_lane_mask;

    /* Identifying context. */
    uint32_t              bb_template_id      = 0;
    uint32_t              insn_index_in_bb    = 0; /* position within bb */
    uint32_t              seq_num             = 0; /* parent BB visit's seq */
    uint32_t              thread_id           = 0;
    bool                  thread_switched     = false;

    /* Wrong-path metadata.  When is_wp == true, wp_index gives this
     * instruction's position in the WP chain (0-based); the fault /
     * translation_unavailable flags reflect any wp_event applied to
     * the containing WP basic block. */
    bool                  is_wp                   = false;
    uint16_t              wp_index                = 0;
    bool                  wp_fault                = false;
    bool                  wp_translation_unavail  = false;
    bool                  wp_has_fault_idx        = false;
    uint32_t              wp_fault_insn_index     = 0;

    /* Dynamic terminal-branch outcome from the CST_FID_BRANCH_TAKEN /
     * _TARGET singletons, attached by the renderer to the entry's (or WP
     * run's) terminating branch insn.  When @branch_outcome_valid, the
     * disassembly annotates the ENCODED architectural successor
     * (@branch_outcome_target — the taken target, or the fall-through when
     * not taken) instead of an immediate-derived guess.  This is the source
     * of truth: it is correct for ISAs whose branch immediate is not a
     * target displacement (ARM tbz/tbnz encode a bit index, not the label)
     * and under fault/interrupt diversions.  Left invalid on pre-branch-FID
     * traces, where the immediate-based branch_target_template is the
     * fallback. */
    bool                  branch_outcome_valid    = false;
    bool                  branch_outcome_taken    = false;
    uint64_t              branch_outcome_target   = 0;

    /* Dynamic per-instance data, already filtered to this insn. */
    std::vector<DynParam>       dyn_params;
    std::vector<RegSnap>        reg_snaps;
    std::vector<MetaFlagsEntry> metaflags;

    /* Optional template pointers for renderer convenience.  Non-
     * owning; valid for the lifetime of the templates vector this
     * Instruction was built from.  bb_template carries the
     * symbol_name / start_pc the renderer formats next to the PC;
     * branch_target_template is the template whose start_pc equals
     * the branch's static target (resolved by the builder when the
     * insn carries a recognised branch and immediate). */
    const Template       *bb_template          = nullptr;
    const Template       *branch_target_template = nullptr;
};

/* ===== Template (parsed from the templates section) ===== */

struct InsnTemplate {
    uint64_t pc = 0;
    uint8_t  opcode = 0;
    uint8_t  branch_type = 0;
    bool     branch_conditional = false;
    bool     has_imm = false;
    int64_t  imm = 0;
    bool     is_atomic = false;
    /* CST_INSN_FLAG_SYSTEM: privileged (non-user) execution context.
     * Uniform across a template; always false in user-mode traces and
     * in traces predating the flag. */
    bool     is_system = false;
    /*
     * Template-static MAX memop counts.  Runtime counts arrive via
     * CST_FID_N_LOADS/N_STORES and may be smaller but never larger.
     * Also fix the dep-mask bit layout: load slots at mask bits
     * [n_src, n_src+max_dep_loads), imm bit at n_src+max_dep_loads,
     * store_data_dep_mask length max_dep_stores.
     */
    uint32_t max_dep_loads = 0;
    uint32_t max_dep_stores = 0;
    std::vector<uint8_t> src_regs;
    std::vector<uint8_t> dst_regs;
    std::vector<uint8_t> raw_bytes;       /* may be 0..16 bytes */

    /*
     * Intra-instruction dataflow sub-block (CST_INSN_FLAG_HAS_DEP_BLOCK).
     * Empty when the wire format did not carry the corresponding
     * family — consumers fall back to the implicit all-to-all
     * dataflow for the absent family.
     *
     * HAS_REG masks (refiner-produced).  Bit layout:
     *   bits [0, src_regs.size())                          src_reg[i]
     *   bits [src_regs.size(), src_regs.size() + max_dep_loads)
     *                                                       load_data[i - src.size()]
     *   bit  src_regs.size() + max_dep_loads                immediate
     *
     * HAS_ADDR masks (walker-produced, structural — describes which
     * src_regs feed each memop's address so the consumer can fire
     * loads/stores precisely).  Bit layout omits the load_data slots
     * because addresses are computed before any load fires:
     *   bits [0, src_regs.size())                          src_reg[i]
     *   bit  src_regs.size()                                immediate
     */
    bool                  has_reg_deps  = false;
    bool                  has_addr_deps = false;
    std::vector<uint64_t> dst_dep_mask;
    std::vector<uint64_t> store_data_dep_mask;
    std::vector<uint64_t> load_addr_dep_mask;
    std::vector<uint64_t> store_addr_dep_mask;

    /*
     * Lane-parallel bit (CST_INSN_FLAG_LANE_PARALLEL): static per
     * instruction.  When set, lane k of each dst depends only on lane k
     * of every src; when clear, lanes participate but don't line up by
     * index (shuffles / broadcasts / horizontal reductions).  Per-slot
     * lane masks themselves are dynamic — emitted as FID deltas, not
     * here — see Instruction::src_lane_mask et al.
     */
    bool                  lane_parallel = false;
};

/*
 * Decoded template profile block (format §6).  Run-aggregated,
 * PGO-style metadata; pure annotation, never required for replay.
 */
struct InsnProfileInfo {
    uint64_t memops_cp = 0, memops_wp = 0;        /* item 3 */
    uint8_t  pat_cp = 0, pat_wp = 0;              /* item 4: CST_PAT_* */
    bool     addr_cp = false, addr_wp = false;    /* item 5 */
    bool     has_cp_bounds = false;               /* item 6 */
    bool     has_wp_bounds = false;
    uint64_t lo_cp = 0, hi_cp = 0;
    uint64_t lo_wp = 0, hi_wp = 0;
};

/* Per terminal-branch-target taken/not-taken counts, parsed 1:1 with
 * Template::target_pcs (the target identities live in the template
 * header, the counts here in the profile block). */
struct BranchTargetCount {
    uint64_t taken_cp = 0,  nottaken_cp = 0;
    uint64_t taken_wp = 0,  nottaken_wp = 0;
};

struct TemplateProfileInfo {
    uint64_t exec_cp = 0, exec_wp = 0;            /* item 1 */
    /* item 2 — per-target counts for the BB's terminal branch,
     * aligned with Template::target_pcs.  fall_through_pc is NOT
     * here; it is the template header's. */
    std::vector<BranchTargetCount> targets;
    std::vector<InsnProfileInfo>   insns;         /* size == insns */
};

struct Template {
    uint32_t                  template_id = 0;
    uint64_t                  start_pc = 0;
    uint64_t                  fall_through_pc = 0; /* not-taken edge   */
    /* Terminal-branch target identities (header).  Uniform layout:
     *   empty            -> last insn is not a branch
     *   size 1           -> non-indirect branch; [0] is the taken edge
     *   size k           -> indirect/return: distinct CP-observed
     *                       targets.  Per-target counts are in
     *                       profile.targets, same order/length. */
    std::vector<uint64_t>     target_pcs;
    std::string               symbol_name;
    std::vector<InsnTemplate> insns;
    TemplateProfileInfo       profile;
};

/* ===== Encoding maps + initial regfile (per-segment header) ===== */

struct EncodingMaps {
    /* Built-in defaults are merged with the trace-side override:
     * trace-supplied entries win when they conflict. */
    std::unordered_map<uint64_t, std::string> opcode;
    std::unordered_map<uint64_t, std::string> branch_type;
    std::unordered_map<uint64_t, std::string> reg;
    std::unordered_map<uint64_t, std::string> field_id;
    std::unordered_map<uint64_t, std::string> header_flag;
    std::unordered_map<uint64_t, std::string> insn_flag;
    std::unordered_map<uint64_t, std::string> body_tag;
    std::unordered_map<uint64_t, std::string> wp_event_flag;
    /* Bit mask inside the WP chain section's leading ULEB (packed
     * alongside num_wp; see CST_WP_CHAIN_HAS_EVENTS, format.rst §4.3). */
    std::unordered_map<uint64_t, std::string> wp_chain_flag;
    std::unordered_map<uint64_t, std::string> metaflags;
    std::unordered_map<uint64_t, std::string> dep_block_flag;
    /* Template-profile self-description (format §6). */
    std::unordered_map<uint64_t, std::string> mem_access_pattern;
    std::unordered_map<uint64_t, std::string> profile_flag;
};

/* ===== Parsed header ===== */

struct Header {
    uint32_t magic = 0;
    uint8_t  format_version = 0;
    uint8_t  isa = 0;                     /* TraceISA */
    uint8_t  flags = 0;
    uint64_t start_insn = 0;
    uint64_t warmup_insns = 0;
    uint64_t total_target_insns = 0;
    /* In-trace architectural CP-insn count at the warmup→simulation
     * boundary.  Consumer counts body-entry arch insns; once it
     * passes this many, the simulation phase has begun.  Decouples
     * warmup_insns (BBV-style, matches the inline_add budget) from
     * what the trace actually contains after REP fan-out.  Sentinel
     * UINT64_MAX = warmup boundary not crossed in this segment. */
    uint64_t warmup_end_arch_insns = 0;
    /* SimPoint weight: fraction of whole-program execution this
     * segment represents (0.0 for non-simpoint segments). */
    double   weight = 0.0;
    std::string command;
    std::string datetime;
    std::string comment;
    std::string target_name;
    EncodingMaps maps;
    ResolvedIds ids{};

    bool has_mem_data() const { return flags & ids.flag_mem_data; }
    bool has_reg_data() const { return flags & ids.flag_reg_data; }
    int  scalar_width_bits() const { return 512; }
};

/* Two byte ranges extracted from the outer ustar archive, each
 * pointing at a fully decompressed (or never-compressed) member
 * buffer in memory.  Lifetime tied to a CstFile owner. */
struct MemberView {
    const uint8_t *data = nullptr;
    size_t         size = 0;
};

}  /* namespace cst */
