/*
 * ChampSim Tracer offline tools — shared wire-format types.
 *
 * Glib-free, plugin-API-free, mmap-friendly POD types describing the
 * current .cst trace format.  Both cst_decode and cst_audit link
 * against this layer; the format-specific bits (header layout, tag
 * values, FID ranges) are duplicated here verbatim from the plugin's
 * champsim_tracer.h so the tools build without dragging QEMU's
 * plugin or glib headers in.
 *
 * The trace is self-describing: every header carries an encoding map
 * (opcode / branch_type / reg / field_id / insn_flag /
 * body_tag / wp_event_flag) that maps the wire-format integer ids to
 * stable string names.  The tools key off those strings rather than
 * pulling in the plugin's compile-time enums — so a trace produced
 * by a future tracer that adds new opcode or register ids will still
 * decode correctly as long as its map carries them.
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

namespace cst {

/* ===== Wire-format magic =====
 *
 * The .cst file is a POSIX-ustar archive carrying two regular-file
 * members, body.cst[.<codec>] and header.cst[.<codec>] (each
 * optionally compressed by the codec named in the suffix).  Each
 * member starts with CST_MAGIC; the body member additionally
 * carries a trailing CST_MAGIC after BODY_TAG_END so truncation is
 * detectable at either end. */

inline constexpr uint32_t CST_MAGIC = 0x1D545343u;

/* ===== Format-layout invariants =====
 *
 * Constants the encoding maps cannot describe (buffer-size limits,
 * not enum identities):
 *
 *   FID_SLOT_COUNT: number of slot positions per memop / dst-reg
 *     range in the field-id space.  Implied by the per-base stride
 *     in the field_id map.
 *   MAX_WIDE_BYTES / MAX_INSN_BYTES: largest scalar the wire format
 *     can carry / largest insn the template section can hold.
 *
 * Other layout details (sync-hint mask + shift, all flag bits,
 * field_id assignments) ARE derivable from the encoding-map entries
 * the trace header carries — consumers should always pull them
 * through resolve_ids() rather than hardcoding numeric values. */
inline constexpr uint16_t FID_SLOT_COUNT       = 64;
/* Note: there is intentionally no FID_SLOT_STRIDE / FID_LANE_BLOCK_STRIDE
 * constant here.  The wire format defines slot-to-FID mapping
 * entirely through the encoding map (CST_FID_<family><k> entries);
 * consumers MUST look each slot's FID up by name and never compute
 * from a hardcoded stride.  See ResolvedIds below for the per-slot
 * arrays. */
inline constexpr size_t  MAX_WIDE_BYTES       = 64;
inline constexpr int     MAX_INSN_BYTES       = 16;

/* ===== Resolved IDs =====
 *
 * The trace's encoding maps name every dispatch-time integer ID
 * (body tags, field IDs) and every named bit mask (header flags,
 * per-insn flags, WP event flags, metaflags bits).  parse_header
 * reverse-resolves the well-known names into this struct and the
 * tools dispatch on @h.ids.<name> instead of compile-time enum
 * values, so the wire format remains the single source of truth.
 * parse_header throws if a well-known name is missing from a map.
 *
 * The names below mirror the symbols the plugin emits in the header
 * maps (see champsim_tracer_output.cc::write_header_encoding_maps). */
struct ResolvedIds {
    /* body_tag map */
    uint8_t body_tag_end           = 0;
    uint8_t body_tag_entry         = 0;
    uint8_t body_tag_thread_switch = 0;
    uint8_t body_tag_iframe        = 0;
    uint8_t body_tag_regfile       = 0;

    /* field_id map: per-slot FID arrays + singletons.  FIDs are
     * ULEB128 on the wire; the uint16_t storage handles current
     * layouts comfortably.  Per-slot arrays are populated by
     * looking up CST_FID_<family><k> by name in the encoding map
     * for each k — the writer's slot-to-FID layout is opaque to
     * consumers (no stride assumption). */
    uint16_t fid_n_loads          = 0;
    uint16_t fid_n_stores         = 0;
    uint16_t fid_metaflags        = 0;
    std::array<uint16_t, 64> fid_load_addr     {};
    std::array<uint16_t, 64> fid_store_addr    {};
    std::array<uint16_t, 64> fid_load_data     {};
    std::array<uint16_t, 64> fid_store_data    {};
    std::array<uint16_t, 64> fid_dst_reg       {};
    std::array<uint16_t, 64> fid_src_lane_mask {};
    std::array<uint16_t, 64> fid_dst_lane_mask {};
    uint16_t fid_insn_bytes_lo    = 0;
    uint16_t fid_insn_bytes_hi    = 0;
    uint16_t fid_insn_opcode      = 0;
    uint16_t fid_insn_branch_type = 0;
    uint16_t fid_insn_flags       = 0;
    uint16_t fid_insn_immediate   = 0;
    uint16_t fid_insn_size        = 0;
    uint16_t fid_extended         = 0;

    /* insn_flag map: bit masks inside the per-insn flags byte */
    uint8_t insn_flag_branch_cond   = 0;
    uint8_t insn_flag_has_imm       = 0;
    uint8_t insn_flag_atomic        = 0;
    uint8_t insn_flag_vec           = 0;
    uint8_t insn_flag_lane_parallel = 0;
    uint8_t insn_flag_has_dep_block = 0;

    /* dep_block_flag map: bit masks inside the optional dep sub-block
     * header (only inspected when insn_flag_has_dep_block is set on
     * the per-insn flags byte). */
    uint8_t dep_block_has_reg  = 0;
    uint8_t dep_block_has_addr = 0;

    /* header_flag map: bit masks inside Header::flags */
    uint8_t flag_mem_data = 0;
    uint8_t flag_reg_data = 0;

    /* wp_event_flag map: bit masks inside the per-WP-event flags byte */
    uint8_t wp_event_translation_unavail = 0;
    uint8_t wp_event_fault               = 0;

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
    uint64_t addr        = 0;     /* always low 64 bits */
    Wide     data{};              /* full width when has_mem_data */
    bool     has_data    = false;
};

struct RegSnap {
    uint32_t insn_index    = 0;
    uint8_t  operand_index = 0;
    uint8_t  reg_id        = 0;
    Wide     value{};             /* full width */
};

/* Per-insn metaflags byte (FID_METAFLAGS).  Only emitted for insns
 * whose template writes the ISA's integer-flags register. */
struct MetaFlagsEntry {
    uint32_t insn_index = 0;
    uint8_t  byte       = 0;
};

struct WPEntry {
    uint32_t                    index = 0;
    uint32_t                    template_id = 0;
    std::vector<DynParam>       dyn_params;
    std::vector<RegSnap>        reg_snaps;
    std::vector<MetaFlagsEntry> metaflags;
    bool                        fault = false;
    bool                        translation_unavailable = false;
    /* Only meaningful when fault. */
    uint32_t                    fault_insn_index = 0;
    bool                        has_fault_idx = false;
    uint32_t                    n_insns = 0;
};

struct DecodedEntry {
    uint32_t                    seq_num = 0;
    uint32_t                    template_id = 0;
    uint32_t                    thread_id = 0;
    bool                        thread_switched = false;
    std::vector<DynParam>       dyn_params;
    std::vector<RegSnap>        reg_snaps;
    std::vector<MetaFlagsEntry> metaflags;
    std::vector<WPEntry>        wp_entries;
};

/* Forward declarations so Instruction can hold non-owning pointers
 * to template metadata defined further down in this header. */
struct Template;
struct InsnTemplate;

/*
 * Per-architectural-instance instruction container.
 *
 * One Instruction == one materialised execution of a single
 * instruction (correct-path or wrong-path).  The body walker
 * produces DecodedEntry objects keyed on BB visits; downstream
 * code (renderer, simulator) usually wants to think in terms of
 * single instructions instead.  cst::instructions_from_entry()
 * fans a DecodedEntry out into a vector<Instruction> — one per CP
 * insn followed by all WP insns in chain order, with the per-
 * instance dyn_params / reg_snaps / metaflags already filtered to
 * just that insn.  Renderers and simulators consume an
 * Instruction without re-filtering by insn_index.
 *
 * Static fields (PC, opcode, src/dst lists, raw_bytes) are copies
 * — Instructions are intended to outlive any specific
 * DecodedEntry, so consumers can collect them into a vector and
 * walk later.  Templates are pointers (non-owning) when present;
 * the bb_template_id keeps the linkage symbolic for consumers
 * that drop the pointers.
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

    /* Per-slot lane participation (CST_INSN_FLAG_VEC sub-block).
     * Empty on scalar / non-vec insns or on traces predating VEC. */
    bool                  lane_parallel       = false;
    std::vector<uint64_t> src_lane_mask;
    std::vector<uint64_t> dst_lane_mask;

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
    /*
     * Template-static MAX counts for the instruction's memory ops.
     * Runtime per-iteration counts arrive separately via
     * CST_FID_N_LOADS / CST_FID_N_STORES and may be smaller (e.g. a
     * conditional load that didn't fire) but never larger.
     *
     * These also fix the dep-mask bit layout: load slots occupy
     * mask bits [n_src, n_src + max_dep_loads), the imm bit sits at
     * n_src + max_dep_loads, and store_data_dep_mask is an array of
     * length max_dep_stores.
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
     * Intra-register lane participation (CST_INSN_FLAG_VEC sub-block).
     * Bit k of src_lane_mask[i] / dst_lane_mask[d] is set iff lane k
     * of the corresponding reg participates in this insn.  When VEC
     * is clear on the wire these vectors stay empty and the consumer
     * treats every lane as participating (legacy / scalar fallback).
     *
     * lane_parallel mirrors CST_INSN_FLAG_LANE_PARALLEL: when set,
     * lane k of each dst depends only on lane k of its src masks; when
     * clear, the lanes participate but don't line up by index
     * (shuffles / broadcasts / horizontal reductions).
     */
    bool                  lane_parallel = false;
    std::vector<uint64_t> src_lane_mask;
    std::vector<uint64_t> dst_lane_mask;
};

struct Template {
    uint32_t                  template_id = 0;
    uint64_t                  start_pc = 0;
    uint64_t                  fall_through_pc = 0;
    std::string               symbol_name;
    std::vector<InsnTemplate> insns;
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
    std::unordered_map<uint64_t, std::string> metaflags;
    std::unordered_map<uint64_t, std::string> dep_block_flag;
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
