/*
 * ChampSim Tracer offline tools — format parsers (impl).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cst_format.h"

#include <stdexcept>
#include <string>

namespace cst {

namespace {

void parse_encoding_maps(Reader &r, EncodingMaps *out)
{
    uint64_t n_maps = r.uleb();
    for (uint64_t i = 0; i < n_maps; i++) {
        std::string name = r.string();
        uint64_t n_entries = r.uleb();
        std::unordered_map<uint64_t, std::string> *target = nullptr;
        if      (name == "opcode")        target = &out->opcode;
        else if (name == "branch_type")   target = &out->branch_type;
        else if (name == "sync_hint")     target = &out->sync_hint;
        else if (name == "reg")           target = &out->reg;
        else if (name == "field_id")      target = &out->field_id;
        else if (name == "header_flag")   target = &out->header_flag;
        else if (name == "insn_flag")     target = &out->insn_flag;
        else if (name == "body_tag")      target = &out->body_tag;
        else if (name == "wp_event_flag") target = &out->wp_event_flag;
        else if (name == "metaflags")     target = &out->metaflags;

        for (uint64_t j = 0; j < n_entries; j++) {
            uint64_t value = r.uleb();
            std::string ename = r.string();
            if (target) (*target)[value] = std::move(ename);
        }
    }
}

}  /* namespace */

Trailer parse_trailer(const uint8_t *data, size_t size)
{
    if (size < TRAILER_SIZE) {
        throw std::runtime_error("Trace file too small for trailer");
    }
    Reader r(data, size - TRAILER_SIZE, size);
    Trailer t;
    t.templates_off   = r.u64_le();
    t.templates_count = r.u64_le();
    t.body_off        = r.u64_le();
    t.body_byte_count = r.u64_le();
    t.magic           = r.u64_le();
    if (t.magic != CST_TRAILER_MAGIC) {
        throw std::runtime_error("Bad trailer magic");
    }
    return t;
}

Header parse_header(const uint8_t *data, size_t size,
                    uint64_t body_off, uint64_t trailer_magic)
{
    Header h;
    Reader r(data, 0, size);
    h.magic = r.u32_le();
    if (h.magic != CST_MAGIC) {
        throw std::runtime_error("Bad header magic");
    }
    if (trailer_magic != CST_TRAILER_MAGIC) {
        throw std::runtime_error("Header/trailer CST version mismatch");
    }
    h.format_version = (uint8_t)((h.magic >> 24) & 0xFF);
    h.isa            = r.u8();
    h.flags          = r.u8();
    h.start_insn         = r.uleb();
    h.warmup_insns       = r.uleb();
    h.total_target_insns = r.uleb();
    h.command     = r.string();
    h.datetime    = r.string();
    h.comment     = r.string();
    h.target_name = r.string();

    if (r.pos() < body_off) {
        Reader sub = r.sub();
        parse_encoding_maps(sub, &h.maps);
        if (!sub.eof()) {
            throw std::runtime_error("encoding-map section has trailing bytes");
        }
    }
    if (r.pos() != body_off) {
        throw std::runtime_error("header/body offset mismatch");
    }
    /* The trace's encoding maps are the only source of truth for
     * id->name lookups — the writer always emits the full set, so
     * the renderers fall back to "OP_<n>" / "REG_<n>" only on
     * malformed traces. */
    return h;
}

std::vector<Template> parse_templates(const uint8_t *data, size_t size,
                                      uint64_t templates_off,
                                      uint64_t expected,
                                      std::unordered_map<uint32_t, size_t> *out_by_id)
{
    std::vector<Template> out;
    if (expected == 0) return out;
    Reader r(data, templates_off, size);
    uint64_t n = r.uleb();
    if (n != expected) {
        throw std::runtime_error("template count mismatch (header vs trailer)");
    }
    out.reserve(n);
    for (uint64_t i = 0; i < n; i++) {
        Reader sub = r.sub();
        Template t;
        t.template_id     = (uint32_t)sub.uleb();
        t.start_pc        = sub.uleb();
        uint64_t n_insns  = sub.uleb();
        t.fall_through_pc = sub.uleb();
        t.symbol_name     = sub.string();

        uint64_t prev_pc = t.start_pc;
        t.insns.reserve(n_insns);
        for (uint64_t k = 0; k < n_insns; k++) {
            uint64_t delta = sub.uleb();
            uint64_t pc = (prev_pc + delta) & UINT64_MAX;
            prev_pc = pc;

            InsnTemplate I;
            I.pc          = pc;
            I.opcode      = sub.u8();
            I.branch_type = sub.u8();
            uint8_t flags = sub.u8();
            uint8_t n_src = sub.u8();
            uint8_t n_dst = sub.u8();
            I.src_regs.resize(n_src);
            for (auto &x : I.src_regs) x = sub.u8();
            I.dst_regs.resize(n_dst);
            for (auto &x : I.dst_regs) x = sub.u8();
            I.n_loads  = sub.u8();
            I.n_stores = sub.u8();
            I.branch_conditional = (flags & INSN_FLAG_BRANCH_COND) != 0;
            I.has_imm            = (flags & INSN_FLAG_HAS_IMM) != 0;
            I.sync_hint          =
                (flags & INSN_FLAG_SYNC_MASK) >> INSN_FLAG_SYNC_SHIFT;
            if (I.has_imm) I.imm = sub.sleb();
            uint8_t insn_size = sub.u8();
            I.raw_bytes.resize(insn_size);
            sub.raw(I.raw_bytes.data(), insn_size);

            t.insns.push_back(std::move(I));
        }

        if (out_by_id) (*out_by_id)[t.template_id] = out.size();
        out.push_back(std::move(t));
    }
    return out;
}

static std::string lookup_or(const std::unordered_map<uint64_t, std::string> &m,
                             uint64_t id, const std::string &fallback)
{
    auto it = m.find(id);
    return it == m.end() ? fallback : it->second;
}

std::string opcode_name(const Header &h, uint64_t id)
{
    return lookup_or(h.maps.opcode, id, "OP_" + std::to_string(id));
}
std::string branch_type_name(const Header &h, uint64_t id)
{
    return lookup_or(h.maps.branch_type, id, "BR_" + std::to_string(id));
}
std::string sync_hint_name(const Header &h, uint64_t id)
{
    return lookup_or(h.maps.sync_hint, id, "SYNC_" + std::to_string(id));
}
std::string reg_name_or_unknown(const Header &h, uint64_t id)
{
    auto it = h.maps.reg.find(id);
    if (it != h.maps.reg.end()) return it->second;
    return std::string("UNKNOWN_") + std::to_string(id);
}
std::string field_id_name(const Header &h, uint64_t id)
{
    auto it = h.maps.field_id.find(id);
    if (it != h.maps.field_id.end()) return it->second;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "FID_0x%02x", (unsigned)id);
    return buf;
}

}  /* namespace cst */
