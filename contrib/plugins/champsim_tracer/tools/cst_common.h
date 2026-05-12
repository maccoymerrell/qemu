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
 * (opcode / branch_type / sync_hint / reg / field_id / insn_flag /
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

inline constexpr uint32_t CST_MAGIC = 0x1C545343u;

/* ===== METAFLAGS bit layout =====
 *
 * Canonical Z/N/C/V/P byte carried in the field-delta stream under
 * FID_METAFLAGS for every insn whose template writes the ISA's
 * integer-flags register.  The numeric id of REG_FLAGS itself is
 * resolved at parse time from the trace's "reg" encoding map. */
inline constexpr uint8_t METAFLAGS_Z = 1u << 0;
inline constexpr uint8_t METAFLAGS_N = 1u << 1;
inline constexpr uint8_t METAFLAGS_C = 1u << 2;
inline constexpr uint8_t METAFLAGS_V = 1u << 3;
inline constexpr uint8_t METAFLAGS_P = 1u << 4;

/* ===== Body tags ===== */

inline constexpr uint8_t BODY_TAG_END           = 0;
inline constexpr uint8_t BODY_TAG_ENTRY         = 1;
inline constexpr uint8_t BODY_TAG_THREAD_SWITCH = 2;
inline constexpr uint8_t BODY_TAG_IFRAME        = 3;
inline constexpr uint8_t BODY_TAG_REGFILE       = 4;

/* ===== Per-insn template flag bits ===== */

inline constexpr uint8_t INSN_FLAG_BRANCH_COND = 1u << 0;
inline constexpr uint8_t INSN_FLAG_HAS_IMM     = 1u << 1;
inline constexpr uint8_t INSN_FLAG_SYNC_SHIFT  = 2;
inline constexpr uint8_t INSN_FLAG_SYNC_MASK   = 0x3Cu;

/* ===== Header feature flags ===== */

inline constexpr uint8_t FLAG_MEM_DATA = 1u << 0;
inline constexpr uint8_t FLAG_REG_DATA = 1u << 1;

/* ===== WP event flags ===== */

inline constexpr uint8_t WP_EVENT_TRANSLATION_UNAVAIL = 1u << 0;
inline constexpr uint8_t WP_EVENT_FAULT               = 1u << 1;

/* ===== Field IDs (unified delta stream) ===== */

inline constexpr uint8_t FID_SLOT_COUNT       = 16;
inline constexpr size_t  MAX_WIDE_BYTES       = 64;

inline constexpr uint8_t FID_N_LOADS          = 0x00;
inline constexpr uint8_t FID_LOAD_ADDR_BASE   = 0x01;
inline constexpr uint8_t FID_STORE_ADDR_BASE  = 0x11;
inline constexpr uint8_t FID_LOAD_DATA_BASE   = 0x21;
inline constexpr uint8_t FID_STORE_DATA_BASE  = 0x31;
inline constexpr uint8_t FID_DST_REG_BASE     = 0x51;
inline constexpr uint8_t FID_N_STORES         = 0x61;
inline constexpr uint8_t FID_EXTRA_LOAD_ADDR  = 0x62;
inline constexpr uint8_t FID_EXTRA_STORE_ADDR = 0x63;
inline constexpr uint8_t FID_EXTRA_LOAD_DATA  = 0x64;
inline constexpr uint8_t FID_EXTRA_STORE_DATA = 0x65;
inline constexpr uint8_t FID_INSN_BYTES_LO    = 0x70;
inline constexpr uint8_t FID_INSN_BYTES_HI    = 0x71;
inline constexpr uint8_t FID_INSN_OPCODE      = 0x72;
inline constexpr uint8_t FID_INSN_BRANCH_TYPE = 0x73;
inline constexpr uint8_t FID_INSN_FLAGS       = 0x74;
inline constexpr uint8_t FID_INSN_IMMEDIATE   = 0x75;
inline constexpr uint8_t FID_INSN_SIZE        = 0x76;
inline constexpr uint8_t FID_METAFLAGS        = 0x77;
inline constexpr uint8_t FID_EXTENDED         = 0xFF;

inline constexpr int MAX_INSN_BYTES = 16;

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

/* ===== Template (parsed from the templates section) ===== */

struct InsnTemplate {
    uint64_t pc = 0;
    uint8_t  opcode = 0;
    uint8_t  branch_type = 0;
    bool     branch_conditional = false;
    bool     has_imm = false;
    int64_t  imm = 0;
    uint8_t  sync_hint = 0;
    uint32_t n_loads = 0;
    uint32_t n_stores = 0;
    std::vector<uint8_t> src_regs;
    std::vector<uint8_t> dst_regs;
    std::vector<uint8_t> raw_bytes;       /* may be 0..16 bytes */
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
    std::unordered_map<uint64_t, std::string> sync_hint;
    std::unordered_map<uint64_t, std::string> reg;
    std::unordered_map<uint64_t, std::string> field_id;
    std::unordered_map<uint64_t, std::string> header_flag;
    std::unordered_map<uint64_t, std::string> insn_flag;
    std::unordered_map<uint64_t, std::string> body_tag;
    std::unordered_map<uint64_t, std::string> wp_event_flag;
    std::unordered_map<uint64_t, std::string> metaflags;
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

    bool has_mem_data() const { return flags & FLAG_MEM_DATA; }
    bool has_reg_data() const { return flags & FLAG_REG_DATA; }
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
