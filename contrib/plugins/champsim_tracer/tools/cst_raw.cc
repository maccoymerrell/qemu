/*
 * cst_decode --format=raw — pseudo-wire structural dump.
 *
 * See cst_raw.h for the contract.  The walk mirrors the Part I decoder
 * recipe of docs/format.rst step for step:
 *
 *   §A  Header member            (recipe Step 2)
 *   §B  Encoding maps            (recipe Step 3)
 *   §C  Templates section        (recipe Step 4)
 *   §D  Body record stream       (recipe Steps 5–7)
 *
 * Every emitted line carries the absolute byte offset within its member
 * (`@xxxxxxxx`) and a hex column showing the raw bytes that line
 * consumed, so the output reads alongside an `xxd` of the same member.
 * The renderer never interprets values beyond resolving numeric ids
 * through the trace's own encoding maps — it is a structural view, not a
 * state reconstruction (use --format=disasm / legacy for that).
 *
 * Per-line bytes come from the reader's live buffer window: each line
 * records the consumed() offset before its reads, then slices
 * [start, consumed()) out of data().  This is exact for the
 * memory-backed header reader and for the streaming body reader except
 * when a line straddles a decompressor-buffer refill (shown as
 * "<refill>"); refills only happen at the 64 KiB window boundary, so it
 * is rare and the byte count is still implied by the decoded value.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <array>
#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "cst_raw.h"
#include "cst_common.h"
#include "cst_format.h"
#include "cst_reader.h"

namespace cst {
namespace {

/* ====================================================================
 * Per-line byte-range + emit helpers
 * ==================================================================== */

/* Hex column width (display chars).  Holds up to MAX_HEX_BYTES bytes
 * space-separated; longer fields truncate with a trailing '+'. */
constexpr int MAX_HEX_BYTES = 10;
constexpr int HEX_COL_W     = MAX_HEX_BYTES * 3;   /* "xx " * N */

/* The raw bytes a line consumed: [@start, reader.consumed()).  Sliced
 * from the live window when those bytes are still resident; "<refill>"
 * when a streaming refill shifted @start out of the buffer (rare, only
 * at a window boundary). */
std::string hex_consumed(Reader &r, size_t start)
{
    size_t end = r.consumed();
    if (end <= start) return std::string();
    size_t len = end - start;
    size_t shifted_out = r.consumed() - r.pos();   /* consumed_total_ */
    if (start < shifted_out) return "<refill>";
    const uint8_t *p = r.data() + (r.pos() - len);

    size_t show = (len <= (size_t)MAX_HEX_BYTES) ? len
                                                 : (size_t)(MAX_HEX_BYTES - 1);
    std::string s;
    char b[4];
    for (size_t i = 0; i < show; i++) {
        if (i) s.push_back(' ');
        std::snprintf(b, sizeof(b), "%02x", p[i]);
        s += b;
    }
    if (len > (size_t)MAX_HEX_BYTES) s += " +";
    return s;
}

/* Emit "@<off>  <hexcol>  <indent><text>", where the bytes shown are
 * those @r consumed since @start and @off == @start. */
void emit(FILE *out, Reader &r, size_t start, int depth,
          const std::string &text)
{
    std::fprintf(out, "  @%08zx  %-*s  %*s%s\n", start, HEX_COL_W,
                 hex_consumed(r, start).c_str(), depth * 2, "",
                 text.c_str());
}

void emitf(FILE *out, Reader &r, size_t start, int depth, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    emit(out, r, start, depth, buf);
}

/* A line with no byte range of its own (synthetic markers: leading /
 * trailing magic, --max stop).  Blank hex column. */
void emit_note(FILE *out, size_t off, int depth, const std::string &text)
{
    std::fprintf(out, "  @%08zx  %-*s  %*s%s\n", off, HEX_COL_W, "",
                 depth * 2, "", text.c_str());
}

/* ====================================================================
 * Value formatting
 * ==================================================================== */

const char *isa_name(uint8_t isa)
{
    switch (isa) {
    case 1: return "x86_64";
    case 2: return "aarch64";
    case 3: return "riscv64";
    case 4: return "mipsel";
    default: return "unknown";
    }
}

std::string hex(uint64_t v)
{
    char b[24];
    std::snprintf(b, sizeof(b), "0x%" PRIx64, v);
    return b;
}

/* Resolve a numeric id to "<v> (<name>)" via @m, or "<v> (?)" on miss. */
std::string named(const std::unordered_map<uint64_t, std::string> &m,
                  uint64_t v)
{
    auto it = m.find(v);
    char b[32];
    std::snprintf(b, sizeof(b), "%" PRIu64 " (", v);
    std::string s = b;
    s += (it != m.end()) ? it->second : "?";
    s += ')';
    return s;
}

/* Decode a flag byte/word into a "NAME_A|NAME_B" string by testing each
 * set bit against @m (which maps the single-bit mask value to a name). */
std::string flag_bits(const std::unordered_map<uint64_t, std::string> &m,
                      uint64_t bits)
{
    std::string s;
    for (int i = 0; i < 64; i++) {
        uint64_t b = (uint64_t)1 << i;
        if (!(bits & b)) continue;
        if (!s.empty()) s += '|';
        auto it = m.find(b);
        if (it != m.end()) {
            s += it->second;
        } else {
            s += "bit";
            s += std::to_string(i);
        }
    }
    return s.empty() ? std::string("none") : s;
}

/* Format an sleb_wide / uleb_wide 8-limb value.  Collapses to a signed
 * decimal + hex when it fits an int64 (the overwhelming common case —
 * addresses, counts, small deltas); falls back to a big-endian hex
 * limb dump for true >64-bit vector/register data. */
std::string fmt_wide(const std::array<uint64_t, 8> &v)
{
    uint64_t fill = ((int64_t)v[0] < 0) ? ~(uint64_t)0 : 0;
    bool fits = true;
    for (int i = 1; i < 8; i++) {
        if (v[i] != fill) { fits = false; break; }
    }
    if (fits) {
        char b[48];
        std::snprintf(b, sizeof(b), "%" PRId64 " (0x%" PRIx64 ")",
                      (int64_t)v[0], v[0]);
        return b;
    }
    int top = 7;
    while (top > 0 && v[top] == 0) top--;
    std::string s = "0x";
    char b[24];
    std::snprintf(b, sizeof(b), "%" PRIx64, v[top]);
    s += b;
    for (int i = top - 1; i >= 0; i--) {
        std::snprintf(b, sizeof(b), "%016" PRIx64, v[i]);
        s += b;
    }
    return s;
}

/* Format a register-id list "[a (NAME), b (NAME)]" via the reg map. */
std::string reg_list(const Header &h, const std::vector<uint8_t> &regs)
{
    std::string s = "[";
    for (size_t i = 0; i < regs.size(); i++) {
        if (i) s += ", ";
        s += named(h.maps.reg, regs[i]);
    }
    s += ']';
    return s;
}

/* ====================================================================
 * §A/§B/§C  Header member walk  (recipe Steps 2–4)
 *
 * Sections are decoded in place (read the len:ULEB, walk the payload off
 * the same reader, skip_to_consumed the trailing bytes) rather than via
 * Reader::sub(), so each emitted line's byte range stays addressable for
 * the hex column.
 * ==================================================================== */

void dump_encoding_map(FILE *out, Reader &r, int depth)
{
    size_t off = r.consumed();
    std::string name = r.string();
    uint64_t n = r.uleb();
    emitf(out, r, off, depth, "map \"%s\"  n_entries=%" PRIu64,
          name.c_str(), n);
    for (uint64_t i = 0; i < n; i++) {
        size_t eoff = r.consumed();
        uint64_t value = r.uleb();
        std::string ename = r.string();
        emitf(out, r, eoff, depth + 1, "%" PRIu64 " = %s",
              value, ename.c_str());
    }
}

void dump_encoding_maps(FILE *out, Reader &r, int depth)
{
    size_t soff = r.consumed();
    uint64_t payload = r.uleb();              /* section len:ULEB */
    size_t end = r.consumed() + payload;
    emitf(out, r, soff, depth,
          "encoding_maps_section  len=%" PRIu64 "  [Step 3]", payload);

    size_t noff = r.consumed();
    uint64_t n_maps = r.uleb();
    emitf(out, r, noff, depth + 1, "n_maps=%" PRIu64, n_maps);
    for (uint64_t i = 0; i < n_maps; i++) {
        dump_encoding_map(out, r, depth + 1);
    }
    r.skip_to_consumed(end);
}

/* One per-insn descriptor (recipe Step 4.4) + optional dep sub-block
 * (Step 4.5).  Reads are interleaved with emits so each line's hex
 * column shows exactly the bytes that line consumed. */
void dump_template_insn(FILE *out, const Header &h, Reader &s,
                        size_t k, uint64_t start_pc, uint64_t *prev_pc,
                        int depth)
{
    const ResolvedIds &ids = h.ids;

    size_t o1 = s.consumed();
    uint64_t pc_delta = s.uleb();
    uint64_t pc = (k == 0 ? start_pc : *prev_pc) + pc_delta;
    *prev_pc = pc;
    uint8_t opcode = s.u8();
    uint8_t branch_type = s.u8();
    emitf(out, s, o1, depth, "insn[%zu] pc=%s  pc_delta=%" PRIu64
          "  opcode=%s  branch_type=%s",
          k, hex(pc).c_str(), pc_delta,
          named(h.maps.opcode, opcode).c_str(),
          named(h.maps.branch_type, branch_type).c_str());

    size_t o2 = s.consumed();
    uint8_t flags = s.u8();
    uint8_t n_src = s.u8();
    uint8_t n_dst = s.u8();
    emitf(out, s, o2, depth + 1, "flags=0x%02x (%s)  n_src=%u  n_dst=%u",
          flags, flag_bits(h.maps.insn_flag, flags).c_str(),
          (unsigned)n_src, (unsigned)n_dst);

    size_t o3 = s.consumed();
    std::vector<uint8_t> src(n_src), dst(n_dst);
    for (uint8_t i = 0; i < n_src; i++) src[i] = s.u8();
    for (uint8_t i = 0; i < n_dst; i++) dst[i] = s.u8();
    emitf(out, s, o3, depth + 1, "src=%s  dst=%s",
          reg_list(h, src).c_str(), reg_list(h, dst).c_str());

    size_t o4 = s.consumed();
    uint8_t mdl = s.u8();
    uint8_t mds = s.u8();
    bool has_imm = (flags & ids.insn_flag_has_imm) != 0;
    int64_t imm = 0;
    if (has_imm) imm = s.sleb();
    uint8_t insn_size = s.u8();
    std::vector<uint8_t> bytes(insn_size);
    for (uint8_t i = 0; i < insn_size; i++) bytes[i] = s.u8();
    {
        std::string meta = "max_dep_loads=" + std::to_string(mdl) +
                           "  max_dep_stores=" + std::to_string(mds);
        if (has_imm) meta += "  imm=" + std::to_string((long long)imm);
        meta += "  insn_size=" + std::to_string((unsigned)insn_size);
        if (insn_size) {
            meta += "  bytes=";
            char b[4];
            for (uint8_t i = 0; i < insn_size; i++) {
                std::snprintf(b, sizeof(b), "%02x", bytes[i]);
                meta += b;
            }
        }
        emit(out, s, o4, depth + 1, meta);
    }

    if (flags & ids.insn_flag_has_dep_block) {
        size_t doff = s.consumed();
        uint8_t df = s.u8();
        emitf(out, s, doff, depth + 1,
              "dep_block flags=0x%02x (%s)  [Step 4.5]",
              df, flag_bits(h.maps.dep_block_flag, df).c_str());
        auto dump_masks = [&](const char *label, unsigned count) {
            size_t moff = s.consumed();
            std::string m = std::string(label) + "=[";
            for (unsigned i = 0; i < count; i++) {
                if (i) m += ", ";
                m += hex(s.uleb());
            }
            m += ']';
            emit(out, s, moff, depth + 2, m);
        };
        if (df & ids.dep_block_has_reg) {
            dump_masks("dst_dep", n_dst);
            dump_masks("store_data_dep", mds);
        }
        if (df & ids.dep_block_has_addr) {
            dump_masks("load_addr_dep", mdl);
            dump_masks("store_addr_dep", mds);
        }
    }
}

/* Template profile block (recipe Step 4.6); present only under
 * CST_FLAG_PROFILE.  Run-aggregated PGO metadata. */
void dump_template_profile(FILE *out, Reader &s, uint64_t n_targets,
                           uint64_t n_insns, int depth)
{
    size_t off = s.consumed();
    uint64_t exec_cp = s.uleb();
    uint64_t exec_wp = s.uleb();
    emitf(out, s, off, depth, "profile  exec_cp=%" PRIu64 "  exec_wp=%" PRIu64
          "  [Step 4.6]", exec_cp, exec_wp);
    for (uint64_t k = 0; k < n_targets; k++) {
        size_t toff = s.consumed();
        uint64_t tc = s.uleb(), ntc = s.uleb(), tw = s.uleb(), ntw = s.uleb();
        emitf(out, s, toff, depth + 1,
              "target[%" PRIu64 "] taken_cp=%" PRIu64 " nottaken_cp=%" PRIu64
              " taken_wp=%" PRIu64 " nottaken_wp=%" PRIu64,
              k, tc, ntc, tw, ntw);
    }
    for (uint64_t k = 0; k < n_insns; k++) {
        size_t ioff = s.consumed();
        uint64_t mcp = s.uleb();
        uint64_t mwp = s.uleb();
        uint8_t pat = s.u8();
        std::string extra;
        if (mcp > 0) {
            uint64_t lo = s.uleb(), span = s.uleb();
            extra += "  cp=[" + hex(lo) + "+" + hex(span) + "]";
        }
        if (mwp > 0) {
            uint64_t lo = s.uleb(), span = s.uleb();
            extra += "  wp=[" + hex(lo) + "+" + hex(span) + "]";
        }
        emitf(out, s, ioff, depth + 1,
              "insn[%" PRIu64 "] memops_cp=%" PRIu64 " memops_wp=%" PRIu64
              " pat_flags=0x%02x%s",
              k, mcp, mwp, pat, extra.c_str());
    }
}

void dump_one_template(FILE *out, const Header &h, Reader &r,
                       uint64_t idx, int depth)
{
    size_t soff = r.consumed();
    uint64_t payload = r.uleb();             /* template section len:ULEB */
    size_t end = r.consumed() + payload;
    emitf(out, r, soff, depth, "template[%" PRIu64 "]  len=%" PRIu64
          "  [Step 4.2]", idx, payload);

    size_t off = r.consumed();
    uint64_t template_id = r.uleb();
    uint64_t start_pc = r.uleb();
    uint64_t num_insns = r.uleb();
    uint64_t fall_through = r.uleb();
    uint64_t n_targets = r.uleb();
    emitf(out, r, off, depth + 1,
          "template_id=%" PRIu64 "  start_pc=%s  num_insns=%" PRIu64
          "  fall_through_pc=%s  n_targets=%" PRIu64,
          template_id, hex(start_pc).c_str(), num_insns,
          hex(fall_through).c_str(), n_targets);
    for (uint64_t k = 0; k < n_targets; k++) {
        size_t toff = r.consumed();
        uint64_t tp = r.uleb();
        emitf(out, r, toff, depth + 2, "target_pc[%" PRIu64 "]=%s",
              k, hex(tp).c_str());
    }
    size_t symoff = r.consumed();
    std::string sym = r.string();
    emitf(out, r, symoff, depth + 1, "symbol=\"%s\"", sym.c_str());

    uint64_t prev_pc = start_pc;
    for (uint64_t k = 0; k < num_insns; k++) {
        dump_template_insn(out, h, r, k, start_pc, &prev_pc, depth + 1);
    }
    if (h.flags & h.ids.flag_profile) {
        dump_template_profile(out, r, n_targets, num_insns, depth + 1);
    }
    r.skip_to_consumed(end);
}

void dump_header(FILE *out, MemberView hv, const Header &h)
{
    Reader r(hv.data, 0, hv.size);
    std::fprintf(out, "=== HEADER member (%zu bytes) ===\n", hv.size);

    size_t off = r.consumed();
    uint32_t magic = r.u32_le();
    emitf(out, r, off, 0, "magic=0x%08x  [Step 2.1]", magic);
    off = r.consumed();
    uint8_t isa = r.u8();
    emitf(out, r, off, 0, "isa=%u (%s)  [Step 2.2]", isa, isa_name(isa));
    off = r.consumed();
    uint8_t flags = r.u8();
    emitf(out, r, off, 0, "flags=0x%02x (%s)  [Step 2.3]",
          flags, flag_bits(h.maps.header_flag, flags).c_str());
    off = r.consumed();
    uint64_t start_insn = r.uleb();
    emitf(out, r, off, 0, "start_insn=%" PRIu64 "  [Step 2.4]", start_insn);
    off = r.consumed();
    uint64_t warmup = r.uleb();
    emitf(out, r, off, 0, "warmup_insns=%" PRIu64 "  [Step 2.5]", warmup);
    off = r.consumed();
    uint64_t total = r.uleb();
    emitf(out, r, off, 0, "total_target_insns=%" PRIu64 "  [Step 2.6]", total);
    off = r.consumed();
    uint64_t wbits = r.u64_le();
    double weight;
    std::memcpy(&weight, &wbits, sizeof(weight));
    emitf(out, r, off, 0, "simpoint_weight=%.17g  [Step 2.7]", weight);

    const char *snames[4] = {"command", "datetime", "comment", "target_name"};
    for (int i = 0; i < 4; i++) {
        off = r.consumed();
        std::string sv = r.string();
        emit(out, r, off, 0,
             std::string(snames[i]) + "=\"" + sv + "\"  [Step 2." +
             std::to_string(8 + i) + "]");
    }

    dump_encoding_maps(out, r, 0);

    off = r.consumed();
    uint64_t warmup_end = r.uleb();
    if (warmup_end == UINT64_MAX) {
        emit(out, r, off, 0, "warmup_end_arch_insns=UINT64_MAX (uncrossed)"
             "  [Step 2.13]");
    } else {
        emitf(out, r, off, 0, "warmup_end_arch_insns=%" PRIu64 "  [Step 2.13]",
              warmup_end);
    }

    std::fprintf(out, "\n=== TEMPLATES section  [Step 4] ===\n");
    off = r.consumed();
    uint64_t num_templates = r.uleb();
    emitf(out, r, off, 0, "num_templates=%" PRIu64 "  [Step 4.1]",
          num_templates);
    for (uint64_t i = 0; i < num_templates; i++) {
        dump_one_template(out, h, r, i, 0);
    }
}

/* ====================================================================
 * §D  Body record stream  (recipe Steps 5–7)
 * ==================================================================== */

/* One field-delta section (Step 6.7 / 6.10): the n_records framing plus
 * each ipos_delta / fid / delta record.  Consumes exactly the section
 * payload off @b. */
void dump_field_delta_section(FILE *out, const Header &h, Reader &b,
                              int depth, const char *label)
{
    const ResolvedIds &ids = h.ids;
    size_t soff = b.consumed();
    uint64_t payload = b.uleb();
    size_t sec_end = b.consumed() + payload;
    emitf(out, b, soff, depth, "%s  len=%" PRIu64 "  [Step 6.7]",
          label, payload);

    size_t roff = b.consumed();
    uint64_t n_records = b.uleb();
    emitf(out, b, roff, depth + 1, "n_records=%" PRIu64, n_records);

    uint32_t ipos = 0;
    for (uint64_t i = 0; i < n_records; i++) {
        size_t off = b.consumed();
        uint64_t ipos_delta = b.uleb();
        ipos += (uint32_t)ipos_delta;
        uint64_t fid = b.uleb();
        std::array<uint64_t, 8> delta = b.sleb_wide();
        std::string ext;
        if (fid == ids.fid_extended) {
            uint64_t ep = b.uleb();
            ext = "  ext_payload=" + std::to_string(ep);
        }
        emitf(out, b, off, depth + 1,
              "rec[%" PRIu64 "] ipos+=%" PRIu64 " ->ipos=%u  fid=%s"
              "  delta=%s%s",
              i, ipos_delta, ipos, named(h.maps.field_id, fid).c_str(),
              fmt_wide(delta).c_str(), ext.c_str());
    }
    if (b.consumed() != sec_end) {
        emit_note(out, b.consumed(), depth + 1,
                  "WARNING: section had trailing byte(s)");
        b.skip_to_consumed(sec_end);
    }
}

/* WP chain (Step 6.8) + WP events (Step 6.9) sections, present only
 * under CST_FLAG_WP.  wp_events_section is itself conditional on the
 * chain header's CST_WP_CHAIN_HAS_EVENTS bit — entirely absent from the
 * wire (no length prefix) when the chain produced no event. */
void dump_wp_sections(FILE *out, const Header &h, Reader &b, int depth)
{
    const ResolvedIds &ids = h.ids;

    size_t coff = b.consumed();
    uint64_t chain_payload = b.uleb();
    size_t chain_end = b.consumed() + chain_payload;
    emitf(out, b, coff, depth, "wp_chain_section  len=%" PRIu64 "  [Step 6.8]",
          chain_payload);
    size_t noff = b.consumed();
    uint64_t chain_hdr = b.uleb();
    uint64_t num_wp = chain_hdr >> 1;
    bool has_wp_events = (chain_hdr & ids.wp_chain_has_events) != 0;
    emitf(out, b, noff, depth + 1,
          "chain_hdr=%" PRIu64 " ->num_wp=%" PRIu64 " (%s)",
          chain_hdr, num_wp,
          flag_bits(h.maps.wp_chain_flag, chain_hdr & 1).c_str());
    int32_t wp_tid = 0;
    for (uint64_t w = 0; w < num_wp; w++) {
        size_t woff = b.consumed();
        int64_t d = b.sleb();
        wp_tid += (int32_t)d;
        emitf(out, b, woff, depth + 1,
              "wp[%" PRIu64 "] template_id_delta=%" PRId64 " ->template_id=%d",
              w, d, wp_tid);
        dump_field_delta_section(out, h, b, depth + 2, "wp_delta_section");
    }
    if (b.consumed() != chain_end) {
        b.skip_to_consumed(chain_end);
    }

    if (!has_wp_events) {
        emit_note(out, b.consumed(), depth,
                  "wp_events_section  absent (CST_WP_CHAIN_HAS_EVENTS clear)"
                  "  [Step 6.9]");
        return;
    }

    size_t eoff = b.consumed();
    uint64_t ev_payload = b.uleb();
    size_t ev_end = b.consumed() + ev_payload;
    emitf(out, b, eoff, depth, "wp_events_section  len=%" PRIu64 "  [Step 6.9]",
          ev_payload);
    size_t enoff = b.consumed();
    uint64_t num_events = b.uleb();
    emitf(out, b, enoff, depth + 1, "num_events=%" PRIu64, num_events);
    int32_t prev_idx = -1;
    for (uint64_t e = 0; e < num_events; e++) {
        size_t off = b.consumed();
        uint64_t gap = b.uleb();
        int32_t wp_index = prev_idx + 1 + (int32_t)gap;
        prev_idx = wp_index;
        uint8_t ev_flags = b.u8();
        std::string extra;
        if (ev_flags & ids.wp_event_fault) {
            uint64_t fi = b.uleb();
            extra = "  fault_insn_index=" + std::to_string(fi);
        }
        /* Resolved index past the chain = chain-level event (§4.4):
         * describes the excursion's unrealized first target. */
        if (wp_index >= 0 && (uint64_t)wp_index >= num_wp) {
            extra += "  (chain-level: first fetch unavailable)";
        }
        emitf(out, b, off, depth + 1,
              "event[%" PRIu64 "] pos_gap=%" PRIu64 " ->wp_index=%d"
              "  ev_flags=0x%02x (%s)%s",
              e, gap, wp_index, ev_flags,
              flag_bits(h.maps.wp_event_flag, ev_flags).c_str(),
              extra.c_str());
    }
    if (b.consumed() != ev_end) {
        b.skip_to_consumed(ev_end);
    }
}

/* The optional per-entry synchronous-fault trailer (CST_FLAG_FAULT):
 * exception-nesting depth + faulting-insn anchors, between the CP delta
 * and the WP sections. */
void dump_fault_trailer(FILE *out, Reader &b, int depth)
{
    size_t off = b.consumed();
    uint64_t depth_val = b.uleb();
    uint64_t n_anchors = b.uleb();
    std::string anchors;
    for (uint64_t a = 0; a < n_anchors; a++) {
        if (a) anchors += ",";
        anchors += std::to_string(b.uleb());
    }
    emitf(out, b, off, depth,
          "fault_trailer  fault_depth=%" PRIu64 "  anchors=[%s]"
          "  [CST_FLAG_FAULT]", depth_val, anchors.c_str());
}

void dump_body(FILE *out, BodyStream &bs, const Header &h, uint64_t max_entries)
{
    const ResolvedIds &ids = h.ids;
    const bool have_wp = (h.flags & ids.flag_wp) != 0;
    const bool have_fault =
        (ids.flag_fault != 0) && (h.flags & ids.flag_fault) != 0;
    Reader &b = bs.reader();

    std::fprintf(out, "\n=== BODY member ===\n");
    emit_note(out, 0, 0, "CST_MAGIC (leading, consumed at open)  [Step 5.2]");

    int32_t cp_tid = 0;
    uint32_t seq = 0;
    int32_t thread = 0;
    int32_t asid = 0;
    std::vector<bool> seen_asids;
    bool stopped_early = false;

    while (!b.eof()) {
        size_t off = b.consumed();
        uint8_t tag = b.u8();

        if (tag == ids.body_tag_thread_switch) {
            emitf(out, b, off, 0, "THREAD_SWITCH  tag=%u  [Step 6.2]",
                  (unsigned)tag);
            size_t doff = b.consumed();
            int64_t d = b.sleb();
            thread += (int32_t)d;
            emitf(out, b, doff, 1,
                  "thread_id_delta=%" PRId64 " ->thread_id=%d", d, thread);
            continue;
        }

        if (tag == ids.body_tag_asid_switch) {
            emitf(out, b, off, 0, "ASID_SWITCH  tag=%u  [Step 6.7]",
                  (unsigned)tag);
            size_t doff = b.consumed();
            int64_t d = b.sleb();
            asid += (int32_t)d;
            emitf(out, b, doff, 1,
                  "asid_index_delta=%" PRId64 " ->asid_index=%d", d, asid);
            bool first = true;
            if (asid >= 0) {
                if ((size_t)asid >= seen_asids.size()) {
                    seen_asids.resize((size_t)asid + 1, false);
                }
                first = !seen_asids[asid];
                seen_asids[asid] = true;
            }
            if (first) {
                size_t ioff = b.consumed();
                uint64_t root_phys = b.u64_le();
                uint64_t sig = b.u64_le();
                emitf(out, b, ioff, 1,
                      "identity (first sighting): root_phys=0x%" PRIx64
                      " sig=0x%" PRIx64, root_phys, sig);
            }
            continue;
        }

        if (tag == ids.body_tag_entry) {
            seq++;
            emitf(out, b, off, 0, "ENTRY  tag=%u  seq=%u  thread=%d",
                  (unsigned)tag, seq, thread);
            size_t doff = b.consumed();
            int64_t d = b.sleb();
            cp_tid += (int32_t)d;
            emitf(out, b, doff, 1,
                  "template_id_delta=%" PRId64 " ->template_id=%d  [Step 6.4]",
                  d, cp_tid);
            dump_field_delta_section(out, h, b, 1, "cp_delta_section");
            if (have_fault) {
                dump_fault_trailer(out, b, 1);
            }
            if (have_wp) {
                dump_wp_sections(out, h, b, 1);
            }
            if (max_entries && seq >= max_entries) {
                stopped_early = true;
                emit_note(out, b.consumed(), 0,
                          "(stopped after " + std::to_string(max_entries) +
                          " entries; --max)");
                break;
            }
            continue;
        }

        if (tag == ids.body_tag_iframe) {
            emitf(out, b, off, 0, "IFRAME  tag=%u  [Step 6.5]", (unsigned)tag);
            dump_field_delta_section(out, h, b, 1, "cp_delta_section");
            if (have_fault) {
                dump_fault_trailer(out, b, 1);
            }
            if (have_wp) {
                dump_wp_sections(out, h, b, 1);
            }
            continue;
        }

        if (tag == ids.body_tag_regfile) {
            emitf(out, b, off, 0, "REGFILE  tag=%u  [Step 6.3]", (unsigned)tag);
            size_t toff = b.consumed();
            uint64_t tid = b.uleb();
            uint64_t n = b.uleb();
            emitf(out, b, toff, 1, "thread_id=%" PRIu64 "  n_present=%" PRIu64,
                  tid, n);
            for (uint64_t i = 0; i < n; i++) {
                size_t roff = b.consumed();
                uint8_t gen_id = b.u8();
                uint8_t width = b.u8();
                std::string bytes;
                char hb[4];
                for (uint8_t k = 0; k < width; k++) {
                    std::snprintf(hb, sizeof(hb), "%02x", b.u8());
                    bytes += hb;
                }
                emitf(out, b, roff, 2, "reg[%" PRIu64 "] gen_id=%s width=%u "
                      "bytes=%s", i, named(h.maps.reg, gen_id).c_str(),
                      (unsigned)width, bytes.c_str());
            }
            continue;
        }

        if (tag == ids.body_tag_end) {
            emitf(out, b, off, 0, "END  tag=%u  [Step 6.6]", (unsigned)tag);
            size_t noff = b.consumed();
            uint64_t num_entries = b.uleb();
            emitf(out, b, noff, 1, "num_entries=%" PRIu64
                  "  (entries seen=%u%s)", num_entries, seq,
                  num_entries == seq ? ", OK" : ", MISMATCH");
            break;
        }

        emitf(out, b, off, 0, "UNKNOWN TAG %u — aborting walk", (unsigned)tag);
        return;
    }

    if (!stopped_early) {
        size_t off = b.consumed();
        bs.finalize();   /* consumes + verifies trailing CST_MAGIC */
        emit_note(out, off, 0, "CST_MAGIC (trailing)  [Step 7.1]");
    }
}

}  /* namespace */

void render_raw(FILE *out, const CstFile &cf, const Header &h,
                const std::vector<Template> &templates,
                const std::unordered_map<uint32_t, size_t> &by_id,
                uint64_t max_entries)
{
    (void)templates;
    (void)by_id;
    dump_header(out, cf.header(), h);
    auto bs = body_stream_open(cf);
    dump_body(out, *bs, h, max_entries);
}

}  /* namespace cst */
