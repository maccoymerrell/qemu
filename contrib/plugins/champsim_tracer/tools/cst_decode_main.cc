/*
 * cst_decode — textual decoder for .cst traces.
 *
 * Output modes:
 *
 *   --format=disasm  (default): objdump-style, one architectural
 *     instruction per line, with memops / register writes / branch
 *     resolution as inline `; metadata` comments.  Designed to be
 *     greppable by PC, opcode, register, or basic-block id.
 *
 *   --format=legacy: byte-identical to champsim_tracer_decode.py's
 *     render_text_streaming output.  Retained for wptrace_genval
 *     scripts that diff trace dumps.
 *
 *   --format=raw: pseudo-wire structural dump (cst_raw.cc).  Walks the
 *     raw header + body bytes and prints every field / record / section
 *     in decode order with its byte offset and the format-spec recipe
 *     step that produced it.  A debugging view of the wire structure,
 *     not a state reconstruction.
 *
 *   --templates-only: dump just the template dictionary (no body).
 *
 * File layout (top -> bottom):
 *   §1  Trivial value formatters       (isa_name, exception_name, ...)
 *   §2  Hex / bytes appenders          (append_hex, append_byte_hex, ...)
 *   §3  Map-driven fmt helpers         (fmt_reg, fmt_snap_value, ...)
 *   §4  Name -> mnemonic / regref      (mnem_from_genop, regref_from_name)
 *   §5  Branch-type helpers            (branch_is_none, branch_mnem_from_name)
 *   §6  Per-trace lookup tables        (DisasmTables, table_lookup)
 *   §7  Capstone wrapper               (ObjdumpRenderer)
 *   §8  Disasm renderer                (per-column emitters, render_disasm)
 *   §9  Templates-only renderer
 *   §10 Legacy renderer                (Python-compat output)
 *   §11 CLI + dispatch                 (Options, main)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

#include "cst_decode.h"
#include "cst_format.h"
#include "cst_objdump.h"
#include "cst_raw.h"

/* Pull ObjdumpRenderer into the anonymous namespace below so its
 * unqualified name works in the rest of this file — the class itself
 * lives in cst::ObjdumpRenderer (cst_objdump.h). */
namespace { using cst::ObjdumpRenderer; }

namespace {

/* ====================================================================
 * §1  Trivial value formatters
 * ==================================================================== */

const char *isa_name(uint8_t isa)
{
    switch (isa) {
    case 0: return "unknown";
    case 1: return "x86_64";
    case 2: return "aarch64";
    case 3: return "riscv64";
    case 4: return "mipsel";
    default: return "unknown";
    }
}

const char *exception_name(uint64_t v)
{
    switch (v) {
    case 0: return "NONE";
    case 1: return "UNKNOWN";
    case 2: return "INT_DIVIDE_BY_ZERO";
    case 3: return "FP_DIVIDE_BY_ZERO";
    case 4: return "MEMORY_ACCESS";
    default: return nullptr;
    }
}

const char *wp_stop_reason_name(uint64_t v)
{
    switch (v) {
    case 0: return "NONE";
    case 1: return "SYSCALL_USERMODE";
    default: return nullptr;
    }
}

/* ISA name with target_name fallback.  Header carries target_name when
 * the writer pinned an explicit string (e.g. "x86_64", "aarch64"); we
 * prefer that and only synthesize from the numeric isa byte when it's
 * blank. */
const char *isa_display(const cst::Header &h)
{
    return !h.target_name.empty() ? h.target_name.c_str() : isa_name(h.isa);
}

/* ====================================================================
 * §2  Hex / bytes appenders  (perf-critical; no allocation)
 * ==================================================================== */

inline const char *kHexDigits = "0123456789abcdef";

/* Lowercase hex, no leading zeros.  Builds end-first in a stack
 * buffer and appends in one shot (hot path). */
void append_hex(std::string *out, uint64_t v)
{
    if (v == 0) { out->push_back('0'); return; }
    char buf[16];
    int n = 0;
    while (v) { buf[15 - n] = kHexDigits[v & 0xF]; v >>= 4; n++; }
    out->append(buf + (16 - n), (size_t)n);
}

/* Width-padded hex (zero-padded to @width chars). */
void append_hex_padded(std::string *out, uint64_t v, int width)
{
    char buf[16];
    for (int i = 0; i < width; i++) {
        buf[width - 1 - i] = kHexDigits[v & 0xF];
        v >>= 4;
    }
    out->append(buf, (size_t)width);
}

void append_byte_hex(std::string *out, uint8_t b)
{
    out->push_back(kHexDigits[(b >> 4) & 0xF]);
    out->push_back(kHexDigits[b & 0xF]);
}

void append_pad_to(std::string *out, size_t target)
{
    while (out->size() < target) out->push_back(' ');
}

/* Append a lane-mask as "{0..3,6}" (set bits coalesced into ranges).
 * Renders nothing when @mask is zero so callers needn't gate. */
void append_lane_set(std::string *out, uint64_t mask)
{
    if (!mask) return;
    out->push_back('{');
    bool first = true;
    int i = 0;
    while (i < 64) {
        if (!(mask & ((uint64_t)1 << i))) { i++; continue; }
        int lo = i;
        while (i < 64 && (mask & ((uint64_t)1 << i))) i++;
        int hi = i - 1;
        if (!first) out->push_back(',');
        first = false;
        out->append(std::to_string(lo));
        if (hi != lo) {
            out->append("..");
            out->append(std::to_string(hi));
        }
    }
    out->push_back('}');
}

/* Append a Wide as a single hex integer (no leading zeros). */
void append_wide_hex(std::string *out, const cst::Wide &w)
{
    int top = -1;
    for (int i = (int)cst::Wide::LIMBS - 1; i >= 0; i--) {
        if (w.limb[i]) { top = i; break; }
    }
    if (top < 0) { out->append("0x0"); return; }
    out->append("0x");
    append_hex(out, w.limb[top]);
    /* Lower limbs are zero-padded to 16 hex chars. */
    for (int i = top - 1; i >= 0; i--) {
        append_hex_padded(out, w.limb[i], 16);
    }
}

/* ====================================================================
 * §3  Map-driven fmt helpers  (return std::string — used by legacy and
 *     by occasional cold paths in disasm)
 * ==================================================================== */

std::string enum_or(const std::unordered_map<uint64_t, std::string> &m,
                    uint64_t v, const char *prefix)
{
    auto it = m.find(v);
    if (it != m.end()) return it->second;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%s_%llu", prefix,
                  (unsigned long long)v);
    return buf;
}

std::string fmt_reg(const cst::Header &h, uint64_t r)
{
    auto it = h.maps.reg.find(r);
    if (it != h.maps.reg.end()) return it->second;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "REG_%llu", (unsigned long long)r);
    return buf;
}

/*
 * Hand-rolled lowercase-hex formatting.  These replace per-value /
 * per-byte snprintf("%02x"/"%lx"), which dominated cst_decode (glibc's
 * __printf_buffer + _itoa_word were ~28% of the legacy emit) because each
 * call re-parses the format string and goes through the locale-aware int
 * conversion.  A nibble table is far cheaper.  Output is byte-identical to
 * the printf forms below.
 */
static const char k_hex_lc[] = "0123456789abcdef";

/* Append @v as minimal-width lowercase hex (like "%" PRIx64). */
static inline void append_hex(std::string &out, uint64_t v)
{
    char tmp[16];
    int n = 0;
    do {
        tmp[n++] = k_hex_lc[v & 0xF];
        v >>= 4;
    } while (v);
    while (n) {
        out += tmp[--n];
    }
}

/* Append @v as exactly @w lowercase-hex digits (like "%0*" PRIx64). */
static inline void append_hex_width(std::string &out, uint64_t v, int w)
{
    char tmp[16];
    for (int i = w - 1; i >= 0; i--) {
        tmp[i] = k_hex_lc[v & 0xF];
        v >>= 4;
    }
    out.append(tmp, (size_t)w);
}

/* Append @x as two lowercase-hex digits (like "%02x"). */
static inline void append_byte_hex(std::string &out, uint8_t x)
{
    out += k_hex_lc[x >> 4];
    out += k_hex_lc[x & 0xF];
}

std::string fmt_hex_lower(uint64_t v)
{
    std::string out;
    append_hex(out, v);
    return out;
}

std::string fmt_bytes_hex(const std::vector<uint8_t> &b)
{
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t x : b) {
        append_byte_hex(out, x);
    }
    return out;
}

/* Snap-value formatting matches the Python:
 *   if hi != 0:  0x{hi:x}{lo:016x}
 *   else:        0x{lo:x}
 * Wide register values beyond 128 bits get truncated in this view —
 * pre-existing legacy behavior. */
std::string fmt_snap_value(const cst::Wide &w)
{
    uint64_t hi = w.limb[1];
    uint64_t lo = w.limb[0];
    std::string out = "0x";
    if (hi) {
        append_hex(out, hi);
        append_hex_width(out, lo, 16);
    } else {
        append_hex(out, lo);
    }
    return out;
}

/* ====================================================================
 * §4  Name -> mnemonic / regref converters
 * ==================================================================== */

/* Strip a fixed prefix (case-insensitively) and lowercase the rest. */
std::string strip_lower(const std::string &name, const char *prefix)
{
    size_t plen = std::strlen(prefix);
    std::string r;
    if (name.size() > plen && name.compare(0, plen, prefix) == 0) {
        r = name.substr(plen);
    } else {
        r = name;
    }
    for (char &c : r) {
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
    }
    return r;
}

/* Convert one GEN_OP_<X> name to a short mnemonic.  Drops INT_ prefix
 * (the int variant is the default), maps FP_/VEC_ to f-/v- prefixes.
 * GEN_OP_BRANCH defaults to "jmp"; the renderer overrides it with the
 * branch_type (jmp / jcc / jmpr / ...) at the call site. */
std::string mnem_from_genop(const std::string &name)
{
    std::string body = strip_lower(name, "GEN_OP_");
    if (body == "branch") return "jmp";
    if (body == "syscall") return "syscall";
    if (body == "ret") return "ret";
    if (body == "nop") return "nop";
    if (body == "fence") return "fence";
    if (body == "load") return "ld";
    if (body == "store") return "st";
    if (body == "prefetch") return "prefetch";
    if (body == "cache_flush") return "clflush";
    if (body == "tlb_flush") return "invlpg";
    if (body == "cmov") return "cmov";
    if (body == "setcc") return "setcc";
    if (body == "unknown") return "?";
    if (body.compare(0, 4, "int_") == 0) return body.substr(4);
    if (body.compare(0, 3, "fp_") == 0)  return "f" + body.substr(3);
    if (body.compare(0, 4, "vec_") == 0) return "v" + body.substr(4);
    return body;
}

/* Convert one REG_<X> name to a register reference (with leading '%').
 * Compresses GPRn → %gpN, FPRn → %fN, VECn → %vN, PREDn → %pN; leaves
 * specials (SP, IP, FLAGS, SEGn, CTRL, ...) as their lowercased
 * stripped name. */
std::string regref_from_name(const std::string &name)
{
    if (name == "REG_NONE") return "";
    std::string body = strip_lower(name, "REG_");
    if (body.compare(0, 3, "gpr") == 0)   return "%gp" + body.substr(3);
    if (body.compare(0, 3, "fpr") == 0)   return "%f"  + body.substr(3);
    if (body.compare(0, 3, "vec") == 0)   return "%v"  + body.substr(3);
    if (body.compare(0, 4, "pred") == 0)  return "%p"  + body.substr(4);
    if (body.compare(0, 5, "bound") == 0) return "%b"  + body.substr(5);
    if (body.compare(0, 7, "matrix_") == 0) return "%m" + body.substr(7);
    if (body == "fp_reg")   return "%fpr";
    if (body == "vec_reg")  return "%vr";
    if (body == "pred_reg") return "%pr";
    if (body == "metaflags") return "%mflags";
    return "%" + body;
}

/*
 * Render a FID_METAFLAGS byte as a bit-string of set flags:
 *   0x00         -> "-"          (no flags set)
 *   METAFLAGS_Z  -> "Z"
 *   Z|N|C        -> "ZNC"
 *   Z|N|C|V|P    -> "ZNCVP"
 * Order matches the bit-position order so the string is stable across
 * traces.
 */
inline void append_metaflags_bits(std::string *out,
                                  const cst::ResolvedIds &ids, uint8_t mf)
{
    if (mf == 0) { out->push_back('-'); return; }
    if (mf & ids.metaflags_z) out->push_back('Z');
    if (mf & ids.metaflags_n) out->push_back('N');
    if (mf & ids.metaflags_c) out->push_back('C');
    if (mf & ids.metaflags_v) out->push_back('V');
    if (mf & ids.metaflags_p) out->push_back('P');
}

/* ====================================================================
 * §5  Branch-type helpers  (keyed off the trace's encoding map names
 *     so the decoder stays forward-compatible with future numbering)
 * ==================================================================== */

const std::string *branch_name_lookup(const cst::Header &h, uint64_t bt)
{
    auto it = h.maps.branch_type.find(bt);
    if (it == h.maps.branch_type.end()) return nullptr;
    return &it->second;
}

bool branch_is_none(const cst::Header &h, uint64_t bt)
{
    if (bt == 0) return true;
    const std::string *n = branch_name_lookup(h, bt);
    return n && *n == "BRANCH_NONE";
}

const char *branch_mnem_from_name(const std::string *name)
{
    if (!name) return nullptr;
    const std::string &n = *name;
    if (n == "BRANCH_DIRECT_JUMP")   return "jmp";
    if (n == "BRANCH_INDIRECT_JUMP") return "jmpr";
    if (n == "BRANCH_COND_DIRECT")   return "jcc";
    if (n == "BRANCH_REP")           return "rep";
    if (n == "BRANCH_RETURN")        return "ret";
    if (n == "BRANCH_DIRECT_CALL")   return "call";
    if (n == "BRANCH_INDIRECT_CALL") return "callr";
    if (n == "BRANCH_SYSCALL_TYPE")  return "syscall";
    return nullptr;
}

/* ====================================================================
 * §6  Per-trace lookup tables  (vector-indexed; built once to avoid
 *     unordered_map::find on the disasm hot path)
 * ==================================================================== */

struct DisasmTables {
    std::vector<std::string> opcode; /* indexed by GEN_OP_* id */
    std::vector<std::string> reg;    /* indexed by REG_*    id */
};

void disasm_tables_build(DisasmTables *t, const cst::Header &h)
{
    auto build_from_map = [&](std::vector<std::string> &dst,
                              const std::unordered_map<uint64_t,
                                                       std::string> &map,
                              auto convert) {
        uint64_t mx = 0;
        for (auto &kv : map) if (kv.first > mx) mx = kv.first;
        dst.assign((size_t)mx + 1, std::string{});
        for (auto &kv : map) {
            dst[kv.first] = convert(kv.second);
        }
    };
    build_from_map(t->opcode, h.maps.opcode,
                   [](const std::string &n) { return mnem_from_genop(n); });
    build_from_map(t->reg, h.maps.reg,
                   [](const std::string &n) { return regref_from_name(n); });
}

inline const std::string *table_lookup(const std::vector<std::string> &t,
                                       uint64_t id)
{
    if (id >= t.size() || t[id].empty()) return nullptr;
    return &t[id];
}

/* ====================================================================
 * §7  Capstone wrapper — ObjdumpRenderer lives in cst_objdump.{h,cc}.
 * ==================================================================== */

/* ====================================================================
 * §8  Disasm renderer
 *
 * Each architectural-instance instruction renders to a single line:
 *
 *   0x<addr> <sym+off>: <bytes...>  <mnem>   <imm/srcs> -> <dsts[v]>  ; meta
 *
 * The line is composed from a sequence of per-column emit_disasm_*
 * helpers, each appending to a shared thread_local buffer.  Layout:
 *
 *     pc_prefix      | bytes_column | objdump_column? | mnemonic   |
 *     operands       | memops       | branch_target   | metadata
 *
 * Each helper is self-contained and only consumes the parts of the
 * Instruction / context it needs, so the column shapes can move
 * independently.
 * ==================================================================== */

/* Per-decode static context shared by every emit_disasm_* helper. */
struct DisasmContext {
    const cst::Header *h;
    const std::unordered_map<uint32_t, size_t> *by_id;
    const std::vector<cst::Template> *templates;
    const DisasmTables *t;
    /* Optional Capstone-backed objdump column. */
    const ObjdumpRenderer *od;
    /* --show-deps: append intra-instruction dep-mask annotation. */
    bool show_deps = false;
    /* --show-lanes: annotate vec operands with their lane sets and
     * split memop -> dst arrows by per-source lane contribution. */
    bool show_lanes = false;
};

/* Resolve register-id @r to its disasm reference (e.g. %gp3).  Hot path
 * uses the prebuilt table; misses fall back to the trace's encoding map
 * and then to a synthetic name. */
void append_regref(std::string *out, const DisasmContext &ctx, uint64_t r)
{
    if (const std::string *p = table_lookup(ctx.t->reg, r)) {
        out->append(*p);
        return;
    }
    auto it = ctx.h->maps.reg.find(r);
    if (it != ctx.h->maps.reg.end()) {
        out->append(regref_from_name(it->second));
        return;
    }
    out->append("%r");
    append_hex(out, r);
}

/* Resolve opcode-id @op to its disasm mnemonic.  Same fallback chain as
 * append_regref. */
void append_mnem(std::string *out, const DisasmContext &ctx, uint64_t op)
{
    if (const std::string *p = table_lookup(ctx.t->opcode, op)) {
        out->append(*p);
        return;
    }
    auto it = ctx.h->maps.opcode.find(op);
    if (it != ctx.h->maps.opcode.end()) {
        out->append(mnem_from_genop(it->second));
        return;
    }
    out->append("op");
    append_hex(out, op);
}

/* --- §8.a Per-column emitters ------------------------------------- */

constexpr int PC_COL_WIDTH       = 12;     /* hex digits */
constexpr int BYTES_COL_BYTES    = 7;      /* objdump-style */
constexpr int BYTES_COL_PAD      = BYTES_COL_BYTES * 3 + 4;
constexpr int OBJDUMP_COL_WIDTH  = 40;
constexpr int MNEM_COL_WIDTH     = 8;

/* "0x<pc> [<symbol+offset>]: " */
void emit_disasm_pc_prefix(std::string &line, const cst::Instruction &insn)
{
    line.append("0x");
    append_hex_padded(&line, insn.pc, PC_COL_WIDTH);
    if (insn.bb_template && !insn.bb_template->symbol_name.empty()) {
        line.append(" <");
        line.append(insn.bb_template->symbol_name);
        line.append("+0x");
        append_hex(&line, insn.pc - insn.bb_template->start_pc);
        line.push_back('>');
    }
    line.append(": ");
}

/* "<bb bb bb ...>   " — bytes column, padded to a stable width. */
void emit_disasm_bytes_column(std::string &line,
                              const std::vector<uint8_t> &raw_bytes)
{
    size_t bytes_start = line.size();
    for (size_t b = 0; b < raw_bytes.size(); b++) {
        if (b) line.push_back(' ');
        append_byte_hex(&line, raw_bytes[b]);
    }
    append_pad_to(&line, bytes_start + BYTES_COL_PAD);
}

/* Optional Capstone disasm column, "<text>     | ". */
void emit_disasm_objdump_column(std::string &line,
                                const ObjdumpRenderer &od,
                                const cst::Instruction &insn)
{
    size_t obj_start = line.size();
    std::string obj;
    if (od.render_one(insn.pc, insn.raw_bytes.data(),
                      insn.raw_bytes.size(), &obj)) {
        line.append(obj);
    } else {
        line.append("(undecoded)");
    }
    append_pad_to(&line, obj_start + OBJDUMP_COL_WIDTH);
    line.append("| ");
}

/* Branch mnemonic ("jmp"/"jcc"/...) when the insn is a branch, otherwise
 * the opcode mnemonic.  Padded to MNEM_COL_WIDTH so operands line up. */
void emit_disasm_mnemonic(std::string &line, const DisasmContext &ctx,
                          const cst::Instruction &insn)
{
    size_t mnem_start = line.size();
    if (branch_is_none(*ctx.h, insn.branch_type)) {
        append_mnem(&line, ctx, insn.opcode);
    } else if (const char *m =
                   branch_mnem_from_name(branch_name_lookup(*ctx.h,
                                                            insn.branch_type))) {
        line.append(m);
    } else {
        append_mnem(&line, ctx, insn.opcode);
    }
    append_pad_to(&line, mnem_start + MNEM_COL_WIDTH);
}

/* Find the regdata snap matching dst-slot @k, if any. */
const cst::RegSnap *find_dst_regdata(const cst::Instruction &insn, uint8_t k)
{
    for (const auto &r : insn.reg_snaps) {
        if (r.operand_index == k) return &r;
    }
    return nullptr;
}

/* Zero-default lookup so callers can probe every slot without length
 * guards. */
inline uint64_t lane_at(const std::vector<uint64_t> &v, size_t i)
{
    return i < v.size() ? v[i] : 0;
}

/* Pre-render the input pool (src_regs + load_data + imm) into strings
 * keyed by HAS_REG mask-bit position (layout in cst_common.h).  Loads
 * render with address inputs inline when HAS_ADDR is available. */
void render_input_pool(std::vector<std::string> &out,
                       const DisasmContext &ctx,
                       const cst::Instruction &insn,
                       const std::vector<uint64_t> &load_addrs,
                       bool have_load_addrs)
{
    auto reg_str = [&](uint8_t r) {
        std::string s;
        append_regref(&s, ctx, r);
        return s;
    };
    auto imm_str = [&]() {
        std::string s = "$0x";
        append_hex(&s, (uint64_t)insn.immediate);
        return s;
    };
    /* src_reg slots — with --show-lanes, suffix each name with its
     * participating lane set ("{0..3,6}").  Empty mask = no suffix
     * so scalar srcs render unchanged. */
    for (size_t i = 0; i < insn.src_regs.size(); i++) {
        std::string s = reg_str(insn.src_regs[i]);
        if (ctx.show_lanes) {
            append_lane_set(&s, lane_at(insn.src_lane_mask, i));
        }
        out.push_back(std::move(s));
    }
    /* load_data slots — each renders as "ld[<addr_inputs>](addr)" using
     * the matching HAS_ADDR mask + dynamic address.  An address mask
     * in HAS_ADDR has the layout bits [0, n_src) src, bit n_src imm
     * (no load_data — addresses are computed before any load fires).
     * With --show-lanes, append the load_data lane set ("{0..1}") so
     * vector loads show which lanes they populated. */
    unsigned n_src = (unsigned)insn.src_regs.size();
    for (unsigned k = 0; k < insn.max_dep_loads; k++) {
        std::string s = "ld";
        if (k < insn.load_addr_dep_mask.size()) {
            uint64_t am = insn.load_addr_dep_mask[k];
            std::string addr_inputs;
            bool any = false;
            for (unsigned i = 0; i < n_src; i++) {
                if (am & ((uint64_t)1 << i)) {
                    if (any) addr_inputs.push_back('+');
                    addr_inputs.append(reg_str(insn.src_regs[i]));
                    any = true;
                }
            }
            if (am & ((uint64_t)1 << n_src)) {
                if (any) addr_inputs.push_back('+');
                addr_inputs.append(imm_str());
                any = true;
            }
            s.push_back('[');
            s.append(addr_inputs);
            s.push_back(']');
        }
        if (have_load_addrs && k < load_addrs.size()) {
            s.append("(0x");
            append_hex(&s, load_addrs[k]);
            s.push_back(')');
        }
        if (ctx.show_lanes) {
            append_lane_set(&s, lane_at(insn.load_data_lane_mask, k));
        }
        out.push_back(std::move(s));
    }
    /* imm slot — only when has_immediate; the bit position is fixed
     * by the wire layout even if we don't push a name when absent. */
    if (insn.has_immediate) {
        out.push_back(imm_str());
    }
}

/*
 * Render @mask's flagged input names, comma-separated, with lane
 * refinement: a lane-structured input (own lane mask non-zero) feeds
 * the sink only where its lanes intersect @sink_lanes — if empty it's
 * dropped (PINSRD $3's pass-through %v0{0..2} does not feed written
 * lane %v0{3}).  Inputs with no lane mask pass through unchanged.
 * @in_lane(i) returns input i's lane mask. */
template <typename LaneFn>
void render_input_set_laned(std::string &line, uint64_t mask,
                            const std::vector<std::string> &input_names,
                            bool show_lanes, uint64_t sink_lanes,
                            LaneFn in_lane)
{
    bool any = false;
    for (size_t i = 0; i < input_names.size(); i++) {
        if (!(mask & ((uint64_t)1 << i))) continue;
        if (show_lanes && sink_lanes) {
            uint64_t il = in_lane(i);
            if (il && !(il & sink_lanes)) continue;  /* no shared lanes */
        }
        if (any) line.append(", ");
        line.append(input_names[i]);
        any = true;
    }
}

/* Render a store sink: "st[<addr_inputs>](addr){lanes}" sized off
 * HAS_ADDR for the addr inputs, the dynamic address (when available),
 * and the store-data lane set (when --show-lanes). */
std::string render_store_sink(const DisasmContext &ctx,
                              const cst::Instruction &insn,
                              unsigned s,
                              const std::vector<uint64_t> &store_addrs,
                              bool have_store_addrs)
{
    auto reg_str = [&](uint8_t r) {
        std::string sx;
        append_regref(&sx, ctx, r);
        return sx;
    };
    std::string out = "st";
    unsigned n_src = (unsigned)insn.src_regs.size();
    if (s < insn.store_addr_dep_mask.size()) {
        uint64_t am = insn.store_addr_dep_mask[s];
        std::string addr_inputs;
        bool any = false;
        for (unsigned i = 0; i < n_src; i++) {
            if (am & ((uint64_t)1 << i)) {
                if (any) addr_inputs.push_back('+');
                addr_inputs.append(reg_str(insn.src_regs[i]));
                any = true;
            }
        }
        if (am & ((uint64_t)1 << n_src)) {
            if (any) addr_inputs.push_back('+');
            addr_inputs.append("$0x");
            append_hex(&addr_inputs, (uint64_t)insn.immediate);
            any = true;
        }
        out.push_back('[');
        out.append(addr_inputs);
        out.push_back(']');
    }
    if (have_store_addrs && s < store_addrs.size()) {
        out.append("(0x");
        append_hex(&out, store_addrs[s]);
        out.push_back(')');
    }
    if (ctx.show_lanes) {
        append_lane_set(&out, lane_at(insn.store_data_lane_mask, s));
    }
    return out;
}

/*
 * "<inputs> -> <dst[regdata]>" arrows, multiple separated by " ; "
 * when sinks have distinct dep masks.  Returns true when the line
 * ends with >=1 operand.  Always dep-aware: when HAS_REG is absent,
 * synthesizes a default "all inputs" mask per sink (matching the
 * consumer's all-to-all fallback).  Register-flat insns collapse to
 * "<srcs> -> <dsts>" (legacy flat layout).
 */
bool emit_disasm_operands(std::string &line, const DisasmContext &ctx,
                          const cst::Instruction &insn)
{
    std::vector<uint64_t> load_addrs, store_addrs;
    for (const auto &dp : insn.dyn_params) {
        if (dp.type == cst::DynParam::Load)  load_addrs.push_back(dp.addr);
        else if (dp.type == cst::DynParam::Store) store_addrs.push_back(dp.addr);
    }
    bool have_load_addrs  = !load_addrs.empty();
    bool have_store_addrs = !store_addrs.empty();

    std::vector<std::string> inputs;
    render_input_pool(inputs, ctx, insn, load_addrs, have_load_addrs);

    /*
     * Default mask when HAS_REG is absent: drop src_reg slots the
     * walker recorded as exclusively addressing-mode (they reach the
     * dst transitively via the memop placeholder, not directly);
     * load_data slots stay.  Caveat: Capstone marks LEA's mem operand
     * READ so the walker counts a phantom load; a dedicated LEA
     * refiner overrides with the precise no-load mask.
     */
    unsigned n_src = (unsigned)insn.src_regs.size();
    uint64_t addr_only_srcs = 0;
    for (uint64_t m : insn.load_addr_dep_mask)  addr_only_srcs |= m;
    for (uint64_t m : insn.store_addr_dep_mask) addr_only_srcs |= m;
    /* Confine to src_reg bit range and drop the imm bit (which sits
     * at bit n_src in HAS_ADDR layout) so we don't accidentally
     * filter out the immediate from the default. */
    uint64_t src_bits_mask = (n_src == 64) ? ~(uint64_t)0
                                           : (((uint64_t)1 << n_src) - 1);
    addr_only_srcs &= src_bits_mask;

    uint64_t all_inputs = 0;
    for (size_t i = 0; i < inputs.size(); i++) {
        all_inputs |= ((uint64_t)1 << i);
    }
    uint64_t default_mask = all_inputs & ~addr_only_srcs;

    /* Addressing-src cleanup applies ONLY to a fully-saturated mask
     * (dep_all_to_all / synthesized default): there an addressing reg
     * is a false direct dep (it reaches the sink via the memop).  A
     * strict subset is a precise refiner's deliberate output (e.g.
     * dep_x86_stack_push's SP-dst = SP-src) and renders verbatim. */
    auto effective = [&](uint64_t m) -> uint64_t {
        return (m == all_inputs) ? (m & ~addr_only_srcs) : m;
    };

    auto dst_mask = [&](size_t d) {
        return d < insn.dst_dep_mask.size() ? insn.dst_dep_mask[d]
                                            : default_mask;
    };
    auto store_mask = [&](size_t s) {
        return s < insn.store_data_dep_mask.size()
                   ? insn.store_data_dep_mask[s]
                   : default_mask;
    };

    bool any_group = false;
    auto open_group = [&]() {
        if (any_group) line.append("  ;  ");
        any_group = true;
    };

    /* Per-input lane mask, indexed like @inputs (src_regs, then
     * load_data slots, then imm).  Imm carries no lanes. */
    auto input_lane_mask = [&](size_t i) -> uint64_t {
        if (i < n_src)                   return lane_at(insn.src_lane_mask, i);
        size_t k = i - n_src;
        if (k < insn.max_dep_loads)      return lane_at(insn.load_data_lane_mask, k);
        return 0;  /* imm slot */
    };

    /* Emit a single dst register name with optional dst-data hex and
     * (when --show-lanes) the dst lane set. */
    auto emit_dst_name = [&](size_t k, uint64_t lane_override) {
        append_regref(&line, ctx, insn.dst_regs[k]);
        if (const cst::RegSnap *r =
                find_dst_regdata(insn, (uint8_t)k)) {
            line.push_back('[');
            append_wide_hex(&line, r->value);
            /* Write byte width for value prediction (CST_FID_DST_REG_WIDTH). */
            if (r->width_bytes) {
                line.append("/w");
                line.append(std::to_string(r->width_bytes));
            }
            line.push_back(']');
        }
        if (ctx.show_lanes) {
            uint64_t lm = lane_override ? lane_override
                                        : lane_at(insn.dst_lane_mask, k);
            append_lane_set(&line, lm);
        }
    };

    /* Per-source lane split: with --show-lanes, when a dst's
     * contributing inputs carry pairwise-disjoint lane masks that
     * exactly partition the dst's, emit one arrow per source
     * ("ld[0] -> v0{0..1}  ;  ld[1] -> v0{2..3}").  Returns true when
     * applied. */
    auto try_split_dst = [&](size_t k) -> bool {
        if (!ctx.show_lanes) return false;
        uint64_t dst_lanes = lane_at(insn.dst_lane_mask, k);
        if (!dst_lanes) return false;
        uint64_t m = dst_mask(k);
        std::vector<size_t> contributors;
        uint64_t covered = 0;
        bool overlap = false;
        for (size_t i = 0; i < inputs.size(); i++) {
            if (!(m & ((uint64_t)1 << i))) continue;
            uint64_t lm = input_lane_mask(i);
            if (!lm) return false;          /* imm or scalar — bail */
            if ((lm & dst_lanes) != lm) return false; /* extends past dst */
            if (covered & lm) { overlap = true; break; }
            covered |= lm;
            contributors.push_back(i);
        }
        if (overlap || covered != dst_lanes || contributors.size() < 2) {
            return false;
        }
        for (size_t i : contributors) {
            open_group();
            line.append(inputs[i]);
            line.append(" -> ");
            emit_dst_name(k, input_lane_mask(i));
        }
        return true;
    };

    /* Dst groups: merge consecutive dsts with identical masks into
     * one arrow (preserving source order).  --show-lanes may split a
     * dst whose sources partition its lane set into per-source
     * arrows. */
    size_t d = 0;
    while (d < insn.dst_regs.size()) {
        if (try_split_dst(d)) {
            d++;
            continue;
        }
        uint64_t mask = dst_mask(d);
        size_t end = d + 1;
        while (end < insn.dst_regs.size() && dst_mask(end) == mask
               && !(ctx.show_lanes && lane_at(insn.dst_lane_mask, end))) {
            end++;
        }
        open_group();
        /* effective(): saturated-only addressing-src cleanup.
         * --show-lanes also filters inputs to this dst's lanes. */
        render_input_set_laned(line, effective(mask), inputs,
                               ctx.show_lanes,
                               lane_at(insn.dst_lane_mask, d),
                               input_lane_mask);
        line.append(" -> ");
        for (size_t k = d; k < end; k++) {
            if (k > d) line.append(", ");
            emit_dst_name(k, 0);
        }
        d = end;
    }

    /* Store-data groups: same pattern, sinks render as st[...](addr).
     * Iterate up to max_dep_stores so unclassified stores still get
     * rendered (using the default mask). */
    size_t s = 0;
    while (s < insn.max_dep_stores) {
        uint64_t mask = store_mask(s);
        size_t end = s + 1;
        while (end < insn.max_dep_stores && store_mask(end) == mask) {
            end++;
        }
        open_group();
        /* Same saturated-only addressing-src exclusion as dsts. */
        render_input_set_laned(line, effective(mask), inputs,
                               ctx.show_lanes,
                               lane_at(insn.store_data_lane_mask, s),
                               input_lane_mask);
        line.append(" -> ");
        for (size_t k = s; k < end; k++) {
            if (k > s) line.append(", ");
            line.append(render_store_sink(ctx, insn, (unsigned)k,
                                          store_addrs, have_store_addrs));
        }
        s = end;
    }

    /* No dsts/stores: render a pure-input line (e.g. CMP into
     * untracked implicit flags) in legacy flat form. */
    if (!any_group) {
        bool any = false;
        auto sep = [&]() {
            if (any) line.append(", ");
            any = true;
        };
        for (size_t i = 0; i < inputs.size(); i++) {
            sep();
            line.append(inputs[i]);
        }
        return any;
    }
    return true;
}

/* "%mflags[ZNCVP]" — at most one metaflags slot per insn. */
void emit_disasm_metaflags(std::string &line, const DisasmContext &ctx,
                           const cst::Instruction &insn, bool &any_operand)
{
    if (insn.metaflags.empty()) return;
    line.append(any_operand ? ", " : " ");
    any_operand = true;
    line.append("%mflags[");
    append_metaflags_bits(&line, ctx.h->ids, insn.metaflags.front().byte);
    line.push_back(']');
}

/*
 * Memops covered inline by the operand renderer are skipped here.
 * Uncovered ones — typically implicit stack memops on CALL/PUSH/POP/
 * RET that Capstone doesn't enumerate, so the walker never bumped
 * max_dep_loads/stores — get a trailing "  ld(0x..)"/"  st(0x..)".
 * With MEM_DATA every dp also gets a "  ld=0x.."/"  st=0x.." column.
 */
void emit_disasm_memops(std::string &line, const DisasmContext &ctx,
                        const cst::Instruction &insn)
{
    bool with_data = ctx.h->has_mem_data();
    unsigned load_idx = 0, store_idx = 0;
    for (const auto &dp : insn.dyn_params) {
        bool is_load = dp.type == cst::DynParam::Load;
        bool covered = is_load
                           ? load_idx  < insn.max_dep_loads
                           : store_idx < insn.max_dep_stores;
        if (!covered) {
            /* Untracked memop — surface its address (no
             * address-input set; the walker has no info). */
            line.append(is_load ? "  ld(0x" : "  st(0x");
            append_hex(&line, dp.addr);
            if (dp.data_size) {
                line.append(",w");
                line.append(std::to_string(dp.data_size));
            }
            line.push_back(')');
        }
        if (with_data) {
            /* append_wide_hex emits its own "0x"; no literal "0x"
             * here (would produce "st=0x0x.."). */
            line.append(is_load ? "  ld=" : "  st=");
            append_wide_hex(&line, dp.data);
            /* Access byte width for value prediction (CST_FID_*_SIZE). */
            if (dp.data_size) {
                line.append("/w");
                line.append(std::to_string(dp.data_size));
            }
        }
        /* Reconstructed physical address (CST_FLAG_PHYSADDR): the recorded
         * physical page base ORed with the virtual in-page offset. */
        if (dp.has_ppage) {
            line.append("  pa=0x");
            append_hex(&line, dp.paddr());
        }
        if (is_load) load_idx++;
        else         store_idx++;
    }
}

/* "  # 0x<pc> <symbol>" when a branch insn has a resolved target. */
void emit_disasm_branch_target(std::string &line, const DisasmContext &ctx,
                               const cst::Instruction &insn)
{
    if (branch_is_none(*ctx.h, insn.branch_type)) return;
    if (!insn.branch_target_template) return;
    line.append("  # 0x");
    append_hex(&line, insn.branch_target_template->start_pc);
    if (!insn.branch_target_template->symbol_name.empty()) {
        line.append(" <");
        line.append(insn.branch_target_template->symbol_name);
        line.push_back('>');
    }
}

/*
 * "[%ip,ld0,imm]" — one HAS_REG mask as a comma-separated bit-name
 * list (layout in cst_common.h).  src bits use the reg name; load
 * bits stay positional ("ld<k>").  With @insn + --show-lanes each
 * entry gets a per-input lane suffix so the deps line mirrors the
 * inline arrows.
 */
void append_dep_mask(std::string &line, uint64_t m,
                     const std::vector<uint8_t> &src_regs,
                     unsigned n_loads,
                     const DisasmContext &ctx,
                     const cst::Instruction *insn = nullptr,
                     uint64_t sink_lanes = 0)
{
    unsigned n_src = (unsigned)src_regs.size();
    const bool annotate_lanes = ctx.show_lanes && insn != nullptr;

    /* Build the comma-separated input list into @inner.  @filter
     * applies the per-lane refinement (a lane-structured input is
     * listed only where its lanes intersect the sink's); when false
     * the raw mask is rendered with no lane gating. */
    auto build = [&](bool filter) -> std::string {
        std::string inner;
        bool any = false;
        auto sep = [&]() {
            if (any) inner.push_back(',');
            any = true;
        };
        auto feeds = [&](uint64_t in_lane) -> bool {
            if (!filter || !sink_lanes) return true;
            if (!in_lane) return true;        /* scalar / imm: unfiltered */
            return (in_lane & sink_lanes) != 0;
        };
        for (unsigned i = 0; i < n_src; i++) {
            if (m & ((uint64_t)1 << i)) {
                uint64_t il = annotate_lanes
                                  ? lane_at(insn->src_lane_mask, i) : 0;
                if (!feeds(il)) continue;
                sep();
                append_regref(&inner, ctx, src_regs[i]);
                if (annotate_lanes) {
                    append_lane_set(&inner, il);
                }
            }
        }
        for (unsigned i = 0; i < n_loads; i++) {
            if (m & ((uint64_t)1 << (n_src + i))) {
                uint64_t il = annotate_lanes
                                  ? lane_at(insn->load_data_lane_mask, i)
                                  : 0;
                if (!feeds(il)) continue;
                sep();
                inner.append("ld");
                inner.append(std::to_string(i));
                if (annotate_lanes) {
                    append_lane_set(&inner, il);
                }
            }
        }
        if (m & ((uint64_t)1 << (n_src + n_loads))) {
            sep();
            inner.append("imm");
        }
        return inner;
    };

    std::string inner = build(annotate_lanes);
    /* Lane refinement narrows per-lane attribution; it must never
     * make a real dependency vanish.  If filtering dropped every
     * input but the mask is non-empty (seen with SVE scalable-vector
     * loads, whose static dst lane set degenerates to {0} while the
     * dynamic load-data lane mask spans the real byte lanes — they
     * don't intersect), fall back to the unfiltered list so the
     * dependency stays visible and matches the no-lanes rendering. */
    if (inner.empty() && annotate_lanes && m != 0) {
        inner = build(false);
    }
    line.push_back('[');
    line.append(inner);
    line.push_back(']');
}

/* "[%ip,imm]" — one HAS_ADDR mask (no load slots; layout in
 * cst_common.h). */
void append_addr_mask(std::string &line, uint64_t m,
                      const std::vector<uint8_t> &src_regs,
                      const DisasmContext &ctx)
{
    line.push_back('[');
    bool any = false;
    auto sep = [&]() {
        if (any) line.push_back(',');
        any = true;
    };
    unsigned n_src = (unsigned)src_regs.size();
    for (unsigned i = 0; i < n_src; i++) {
        if (m & ((uint64_t)1 << i)) {
            sep();
            append_regref(&line, ctx, src_regs[i]);
        }
    }
    if (m & ((uint64_t)1 << n_src)) {
        sep();
        line.append("imm");
    }
    line.push_back(']');
}

/*
 * "deps: %gp2=[ld0] sdata0=[%gp2] | laddr0=[%ip] saddr0=[%ip]" —
 * --show-deps only.  When HAS_REG is absent, synthesizes the same
 * default masks as emit_disasm_operands so the deps line mirrors the
 * inline arrows.
 */
void emit_disasm_deps_annotation(std::string &line,
                                 const cst::InsnTemplate &it,
                                 const cst::Instruction &insn,
                                 const DisasmContext &ctx)
{
    unsigned n_src = (unsigned)it.src_regs.size();
    unsigned n_loads = it.max_dep_loads;
    unsigned imm_bit = n_src + n_loads;

    /* Default mask, computed identically to the inline renderer's
     * fallback so the annotation can't disagree with the arrows. */
    uint64_t addr_only_srcs = 0;
    for (uint64_t m : it.load_addr_dep_mask)  addr_only_srcs |= m;
    for (uint64_t m : it.store_addr_dep_mask) addr_only_srcs |= m;
    uint64_t src_bits = (n_src == 64) ? ~(uint64_t)0
                                       : (((uint64_t)1 << n_src) - 1);
    addr_only_srcs &= src_bits;

    uint64_t all_inputs = src_bits;
    /* every load_data slot */
    for (unsigned k = 0; k < n_loads; k++) {
        all_inputs |= ((uint64_t)1 << (n_src + k));
    }
    /* imm bit only when the template carries an immediate. */
    if (it.has_imm) {
        all_inputs |= ((uint64_t)1 << imm_bit);
    }
    uint64_t default_mask = all_inputs & ~addr_only_srcs;

    /* Same saturated-only `effective` rule as emit_disasm_operands
     * so the annotation can't disagree with the arrows. */
    auto effective = [&](uint64_t m) -> uint64_t {
        return (m == all_inputs) ? (m & ~addr_only_srcs) : m;
    };

    bool wrote_reg = false;
    line.append("deps:");

    /* Dst masks: prefer wire HAS_REG; fall back to default. */
    size_t n_dst = it.dst_regs.size();
    for (size_t d = 0; d < n_dst; d++) {
        uint64_t m = d < it.dst_dep_mask.size() ? it.dst_dep_mask[d]
                                                : default_mask;
        m = effective(m);
        line.push_back(' ');
        append_regref(&line, ctx, it.dst_regs[d]);
        if (ctx.show_lanes) {
            append_lane_set(&line, lane_at(insn.dst_lane_mask, d));
        }
        line.push_back('=');
        append_dep_mask(line, m, it.src_regs, n_loads, ctx, &insn,
                        ctx.show_lanes ? lane_at(insn.dst_lane_mask, d) : 0);
        wrote_reg = true;
    }
    /* Store-data masks: prefer wire; fall back to default per slot
     * up to max_dep_stores so unclassified stores surface too. */
    for (size_t s = 0; s < it.max_dep_stores; s++) {
        uint64_t m = s < it.store_data_dep_mask.size()
                         ? it.store_data_dep_mask[s]
                         : default_mask;
        m = effective(m);   /* saturated-only addressing-src cleanup */
        line.append(" sdata");
        line.append(std::to_string(s));
        if (ctx.show_lanes) {
            append_lane_set(&line, lane_at(insn.store_data_lane_mask, s));
        }
        line.push_back('=');
        append_dep_mask(line, m, it.src_regs, n_loads, ctx, &insn,
                        ctx.show_lanes
                            ? lane_at(insn.store_data_lane_mask, s) : 0);
        wrote_reg = true;
    }
    /* HAS_ADDR masks — these are wire-emitted whenever the walker
     * saw a MEM operand; no synthesis needed. */
    if (it.has_addr_deps) {
        bool wrote_addr = !it.load_addr_dep_mask.empty() ||
                          !it.store_addr_dep_mask.empty();
        if (wrote_addr && wrote_reg) line.append(" |");
        for (size_t k = 0; k < it.load_addr_dep_mask.size(); k++) {
            line.append(" laddr");
            line.append(std::to_string(k));
            line.push_back('=');
            append_addr_mask(line, it.load_addr_dep_mask[k],
                             it.src_regs, ctx);
        }
        for (size_t k = 0; k < it.store_addr_dep_mask.size(); k++) {
            line.append(" saddr");
            line.append(std::to_string(k));
            line.push_back('=');
            append_addr_mask(line, it.store_addr_dep_mask[k],
                             it.src_regs, ctx);
        }
    }
}

/* "  ; <items...>" trailing comment block.  Items are written one by
 * one; first item gets "  ; " and subsequent items get " ". */
void emit_disasm_trailing_meta(std::string &line, const DisasmContext &ctx,
                               const cst::Instruction &insn,
                               const char *wp_status)
{
    bool wrote = false;
    auto begin_item = [&]() {
        if (!wrote) { line.append("  ; "); wrote = true; }
        else        { line.push_back(' '); }
    };

    if (wp_status && *wp_status) {
        begin_item();
        line.append(wp_status);
    }
    if (insn.is_atomic) {
        begin_item();
        line.append("atomic");
    }
    if (ctx.show_deps && insn.bb_template &&
        insn.insn_index_in_bb < insn.bb_template->insns.size()) {
        const cst::InsnTemplate &it =
            insn.bb_template->insns[insn.insn_index_in_bb];
        if (it.has_reg_deps || it.has_addr_deps) {
            begin_item();
            emit_disasm_deps_annotation(line, it, insn, ctx);
        }
    }
}

/* --- §8.b Per-instruction renderer (sequence of column emitters) -- */

/* Inline per-instruction profile tag ("prof: ..." / "").  Defined
 * after profile_pat_name (§ legacy templates). */
std::string insn_prof_text(const cst::Header &h,
                           const cst::InsnProfileInfo &ip);
std::string insn_prof_text_for(const DisasmContext &ctx,
                               const cst::Instruction &insn);

void render_disasm_insn(FILE *out, const DisasmContext &ctx,
                        const cst::Instruction &insn,
                        const char *wp_status)
{
    /* Reused thread_local buffer (amortised once at high-water). */
    static thread_local std::string line;
    line.clear();

    emit_disasm_pc_prefix(line, insn);
    emit_disasm_bytes_column(line, insn.raw_bytes);
    if (ctx.od) emit_disasm_objdump_column(line, *ctx.od, insn);
    emit_disasm_mnemonic(line, ctx, insn);

    bool any_operand = emit_disasm_operands(line, ctx, insn);
    emit_disasm_metaflags(line, ctx, insn, any_operand);
    emit_disasm_memops(line, ctx, insn);
    emit_disasm_branch_target(line, ctx, insn);
    emit_disasm_trailing_meta(line, ctx, insn, wp_status);

    /* Run-aggregated per-insn profile, inline (NONE/0 omitted). */
    std::string pt = insn_prof_text_for(ctx, insn);
    if (!pt.empty()) {
        line += "  ";
        line += pt;
    }

    line.push_back('\n');
    std::fwrite(line.data(), 1, line.size(), out);
}

/* --- §8.c Entry-level helpers (BB headers, WP-run grouping) ------- */

/* "; FAULT@insn3,TRANSLATION_UNAVAILABLE" / "" for clean WP runs. */
std::string compute_wp_status(const cst::Instruction &insn)
{
    std::string out;
    if (insn.wp_fault) {
        if (insn.wp_has_fault_idx) {
            char b[32];
            std::snprintf(b, sizeof(b), "FAULT@insn%u",
                          insn.wp_fault_insn_index);
            out = b;
        } else {
            out = "FAULT";
        }
    }
    if (insn.wp_translation_unavail) {
        if (!out.empty()) out += ",";
        out += "TRANSLATION_UNAVAILABLE";
    }
    if (insn.wp_dep_branch_kill) {
        if (!out.empty()) out += ",";
        out += "DEP_BRANCH_KILL";
    }
    return out;
}

/* Count contiguous WP insns sharing @first's wp_index, starting at @from
 * (assumed to be on a wp boundary).  Used to pre-compute the n_insns
 * field for the WP-run separator. */
size_t count_wp_run_length(const std::vector<cst::Instruction> &insns,
                           size_t from)
{
    if (from >= insns.size() || !insns[from].is_wp) return 0;
    uint16_t idx = insns[from].wp_index;
    size_t end = from;
    while (end < insns.size() && insns[end].is_wp &&
           insns[end].wp_index == idx) {
        end++;
    }
    return end - from;
}

/* Linear scan for a template whose start_pc == @target_pc.  Used by the
 * CP-final fallback that resolves unconditional branches to their
 * fall-through BB when no immediate-based target match was found. */
const cst::Template *find_template_by_start_pc(
    const std::vector<cst::Template> &templates, uint64_t target_pc)
{
    auto it = std::find_if(templates.begin(), templates.end(),
        [&](const cst::Template &x) { return x.start_pc == target_pc; });
    return it == templates.end() ? nullptr : &*it;
}

/* The CP chain's final insn falls through to template @t.fall_through_pc;
 * if that PC is the start of another template, return it for the
 * branch-target annotation.  Returns nullptr when the fall-through
 * PC is outside the trace window. */
const cst::Template *find_cp_fallback_target(
    const cst::Template &t,
    const std::vector<cst::Template> &templates)
{
    if (t.insns.empty() || !t.fall_through_pc) return nullptr;
    return find_template_by_start_pc(templates, t.fall_through_pc);
}

/* For the run-final insn of a WP entry, the branch target is the BB
 * that starts the *next* WP entry in this chain (if any).  @from is
 * the position of the current insn; we look forward until we find an
 * insn with a different wp_index. */
const cst::Template *find_next_wp_run_template(
    const std::vector<cst::Instruction> &insns, size_t from,
    int cur_wp_run,
    const std::unordered_map<uint32_t, size_t> &by_id,
    const std::vector<cst::Template> &templates)
{
    for (size_t j = from + 1; j < insns.size(); j++) {
        if (!insns[j].is_wp || (int)insns[j].wp_index == cur_wp_run) {
            continue;
        }
        auto nit = by_id.find(insns[j].bb_template_id);
        return nit == by_id.end() ? nullptr : &templates[nit->second];
    }
    return nullptr;
}

void emit_disasm_file_header(FILE *out, const cst::Header &h,
                             size_t n_templates)
{
    /* Greppable `; KEY=value` trace-identity summary. */
    std::fprintf(out, "; cst_decode disassembly\n");
    std::fprintf(out, "; version=0x%08X\n", h.magic);
    std::fprintf(out, "; isa=%s\n", isa_display(h));
    std::fprintf(out, "; command=%s\n", h.command.c_str());
    std::fprintf(out, "; datetime=%s\n", h.datetime.c_str());
    std::fprintf(out, "; flags=%s%s\n",
                 h.has_mem_data() ? "MEM_DATA " : "",
                 h.has_reg_data() ? "REG_DATA"  : "");
    std::fprintf(out,
                 "; start_insn=%llu warmup_insns=%llu total_target_insns=%llu\n",
                 (unsigned long long)h.start_insn,
                 (unsigned long long)h.warmup_insns,
                 (unsigned long long)h.total_target_insns);
    if (h.warmup_end_arch_insns == UINT64_MAX) {
        std::fprintf(out, "; warmup_end_arch_insns=uncrossed\n");
    } else {
        std::fprintf(out, "; warmup_end_arch_insns=%llu\n",
                     (unsigned long long)h.warmup_end_arch_insns);
    }
    std::fprintf(out, "; simpoint_weight=%.17g\n", h.weight);
    std::fprintf(out, "; templates=%zu\n\n", n_templates);
}

void emit_bb_header(FILE *out, const cst::DecodedEntry &e,
                    const cst::Template &t)
{
    char fd[40];
    fd[0] = '\0';
    if (e.fault_depth > 0) {
        std::snprintf(fd, sizeof(fd), " fault_depth=%u", e.fault_depth);
    }
    std::fprintf(out,
                 "; ----- BB %u entry pc=0x%" PRIx64
                 " insns=%zu seq=%u tid=%u asid=%u%s%s -----\n",
                 e.template_id, t.start_pc, t.insns.size(),
                 e.seq_num, e.thread_id, e.asid,
                 e.thread_switched ? " (thread_switch)" : "", fd);
}

void emit_wp_run_separator(FILE *out, const cst::Instruction &first,
                           size_t run_n, const std::string &status)
{
    std::fprintf(out,
                 "; ..... wp[%u] BB %u n_insns=%zu%s%s -----\n",
                 (unsigned)first.wp_index, first.bb_template_id, run_n,
                 status.empty() ? "" : " status=",
                 status.c_str());
}

/* --- §8.d Per-entry driver ---------------------------------------- */

/* One template's run-aggregated profile (format §6) emitted as a
 * block at its BB.  Defined after profile_pat_name (§ legacy
 * templates); see the fuller contract there. */
void emit_bb_profile_lines(FILE *out, const cst::Header &h,
                           const cst::Template &t, const char *pfx);

/* Walk one DecodedEntry's instructions in CP-then-WP order, injecting
 * WP-run separators and resolving CP/WP "final insn falls through to..."
 * branch fallbacks for the renderer. */
void render_entry_disasm(FILE *out, const DisasmContext &ctx,
                         const cst::DecodedEntry &e)
{
    auto it = ctx.by_id->find(e.template_id);
    if (it == ctx.by_id->end()) {
        std::fprintf(out, "; ----- BB %u (template not found) -----\n",
                     e.template_id);
        return;
    }
    const cst::Template &t = (*ctx.templates)[it->second];
    emit_bb_header(out, e, t);
    /* Run-aggregated profile for this BB, at its entry header (it is
     * a per-template total, identical for every entry of this id). */
    emit_bb_profile_lines(out, *ctx.h, t, "; ");

    /* Fan the entry into per-instance instructions.  The builder
     * pre-filters dyn_params/reg_snaps/metaflags per-insn and resolves
     * direct branch targets via immediate match. */
    std::vector<cst::Instruction> insns =
        cst::instructions_from_entry(e, *ctx.h, *ctx.templates, *ctx.by_id);

    /* CP fallback: when the CP-final insn is a branch we couldn't
     * statically resolve, attribute it to the fall_through_pc BB. */
    const cst::Template *cp_fallback =
        find_cp_fallback_target(t, *ctx.templates);

    int  cur_wp_run = -1;     /* -1 = CP, otherwise WPEntry::index */
    std::string wp_status;
    for (size_t i = 0; i < insns.size(); i++) {
        cst::Instruction &insn = insns[i];
        bool is_last_of_group =
            (i + 1 == insns.size()) ||
            (insn.is_wp != insns[i + 1].is_wp) ||
            (insn.is_wp && (int)insns[i + 1].wp_index != (int)insn.wp_index);

        if (!insn.is_wp) {
            if (is_last_of_group && !insn.branch_target_template) {
                insn.branch_target_template = cp_fallback;
            }
            render_disasm_insn(out, ctx, insn, /*wp_status=*/nullptr);
            continue;
        }

        /* New WP run: emit the separator before the first insn. */
        if ((int)insn.wp_index != cur_wp_run) {
            cur_wp_run = (int)insn.wp_index;
            wp_status = compute_wp_status(insn);
            emit_wp_run_separator(out, insn,
                                  count_wp_run_length(insns, i), wp_status);
        }

        if (is_last_of_group && !insn.branch_target_template) {
            insn.branch_target_template = find_next_wp_run_template(
                insns, i, cur_wp_run, *ctx.by_id, *ctx.templates);
        }

        render_disasm_insn(out, ctx, insn,
                           wp_status.empty() ? nullptr : wp_status.c_str());
    }
}

/* One template's run-aggregated profile (format §6), emitted as a
 * block at the BB it belongs to.  @pfx prefixes every line ("; " for
 * disasm comments, "  " for legacy/templates).  Per-insn rows use a
 * `prof:` tag and are omitted entirely when nothing is meaningful
 * (no memops, pattern NONE, not addr, no bounds).  Defined after
 * profile_pat_name (§ legacy templates). */
void emit_bb_profile_lines(FILE *out, const cst::Header &h,
                           const cst::Template &t, const char *pfx);

void render_disasm(FILE *out, const cst::Header &h,
                   const std::vector<cst::Template> &templates,
                   const std::unordered_map<uint32_t, size_t> &by_id,
                   cst::BodyWalker &body,
                   const ObjdumpRenderer *od,
                   bool show_deps, bool show_lanes)
{
    DisasmTables dt;
    disasm_tables_build(&dt, h);
    DisasmContext ctx{&h, &by_id, &templates, &dt, od, show_deps, show_lanes};

    emit_disasm_file_header(out, h, templates.size());
    /* Disk-I/O records surface as comment lines, in stream order with
     * the entries — a START at the request issue, a STOP where the
     * completion lands.  The (thread, asid) is the owning process: exact
     * for a doorbell-correlated START (attr=exact), the paired START's
     * owner for a STOP, else the stream-position context (attr=pos). */
    body.set_devio_callback([&](const cst::DecodedDevio &d) {
        if (d.is_start) {
            const char *rw = d.rw == CST_DEVIO_READ  ? "read"
                           : d.rw == CST_DEVIO_WRITE ? "write"
                           : d.rw == CST_DEVIO_FLUSH ? "flush"
                                                     : "?";
            std::fprintf(out,
                "; DEVIO START req=%llu %s bytes=%llu block=%llu "
                "(thread=%u asid=%u attr=%s)\n",
                (unsigned long long)d.request_id, rw,
                (unsigned long long)d.bytes, (unsigned long long)d.block,
                d.thread_id, d.asid, d.exact ? "exact" : "pos");
        } else {
            std::fprintf(out,
                "; DEVIO STOP  req=%llu (thread=%u asid=%u)\n",
                (unsigned long long)d.request_id, d.thread_id, d.asid);
        }
    });
    body.walk([&](const cst::DecodedEntry &e) {
        render_entry_disasm(out, ctx, e);
    });
}

/* ====================================================================
 * §9  Templates-only renderer  (--templates-only flag)
 *
 * Walks every template, dedupes insns by PC, and emits one line per
 * unique PC — the shape `objdump -d` produces over a binary's text
 * section.  Templates carry no run-time observation, so no regdata /
 * memdata appears.
 * ==================================================================== */

/* Mnemonic for the templates-only generic view: branch-flavour for
 * branches, mnem table for non-branches.  Falls back to "br"/"op"
 * when the trace's encoding maps don't carry the id. */
void emit_template_only_mnemonic(std::string &line, const cst::Header &h,
                                 const DisasmTables &dt,
                                 const cst::InsnTemplate &I)
{
    size_t mnem_start = line.size();
    if (branch_is_none(h, I.branch_type)) {
        const std::string *p = table_lookup(dt.opcode, I.opcode);
        line.append(p ? *p : std::string("op"));
    } else if (const char *m =
                   branch_mnem_from_name(branch_name_lookup(h, I.branch_type))) {
        line.append(m);
    } else {
        line.append("br");
    }
    append_pad_to(&line, mnem_start + MNEM_COL_WIDTH);
}

/* "<imm>, <srcs> -> <dsts>" — static-only variant of the disasm
 * operand emitter (no regdata since templates carry no per-instance
 * info). */
void emit_template_only_operands(std::string &line,
                                 const DisasmTables &dt,
                                 const cst::InsnTemplate &I)
{
    bool any = false;
    auto reg_or_q = [&](uint8_t r) {
        const std::string *p = table_lookup(dt.reg, r);
        line.append(p ? *p : std::string("%r?"));
    };
    if (I.has_imm) {
        line.append("$0x");
        append_hex(&line, (uint64_t)I.imm);
        any = true;
    }
    for (uint8_t r : I.src_regs) {
        if (any) line.append(", ");
        reg_or_q(r);
        any = true;
    }
    if (!I.dst_regs.empty()) {
        if (any) line.append(" -> ");
        for (size_t k = 0; k < I.dst_regs.size(); k++) {
            if (k) line.append(", ");
            reg_or_q(I.dst_regs[k]);
        }
    }
}


/* One templates-only line:
 *   "  <pc>:  <bytes...>  [objdump | ] <mnem>   <operands>\n"
 */
void emit_template_only_line(FILE *out, const cst::Header &h,
                             const DisasmTables &dt,
                             const ObjdumpRenderer *od,
                             const cst::InsnTemplate &I,
                             const cst::InsnProfileInfo *ip)
{
    std::string line;
    line.append("  ");
    append_hex_padded(&line, I.pc, 16);
    line.append(":  ");

    size_t bytes_start = line.size();
    for (size_t b = 0; b < I.raw_bytes.size(); b++) {
        if (b) line.push_back(' ');
        append_byte_hex(&line, I.raw_bytes[b]);
    }
    append_pad_to(&line, bytes_start + 16 * 3);
    line.append("  ");

    if (od) {
        size_t obj_start = line.size();
        std::string obj;
        if (od->render_one(I.pc, I.raw_bytes.data(), I.raw_bytes.size(),
                           &obj)) {
            line.append(obj);
        } else {
            line.append("(undecoded)");
        }
        append_pad_to(&line, obj_start + OBJDUMP_COL_WIDTH);
        line.append("| ");
    }

    emit_template_only_mnemonic(line, h, dt, I);
    emit_template_only_operands(line, dt, I);
    if (ip) {
        std::string pt = insn_prof_text(h, *ip);
        if (!pt.empty()) {
            line.append("  ");
            line.append(pt);
        }
    }
    line.push_back('\n');
    std::fwrite(line.data(), 1, line.size(), out);
}

void emit_templates_only_file_header(FILE *out, const cst::Header &h,
                                     size_t n_templates, bool with_objdump)
{
    std::fprintf(out, "\n%s:     file format trace template map\n",
                 isa_display(h));
    std::fprintf(out, "; version=0x%08X templates=%zu%s\n\n",
                 h.magic, n_templates,
                 with_objdump ? " objdump_disasm=on" : "");
}

void render_templates_only(FILE *out, const cst::Header &h,
                           const std::vector<cst::Template> &templates,
                           const std::unordered_map<uint32_t, size_t> &by_id,
                           const ObjdumpRenderer *od)
{
    (void)by_id;
    DisasmTables dt;
    disasm_tables_build(&dt, h);
    emit_templates_only_file_header(out, h, templates.size(), od != nullptr);

    /* Per-BB so the run-aggregated profile can be annotated as part
     * of each block (a flat dedup'd PC dump has nowhere to hang it). */
    for (const cst::Template &t : templates) {
        std::fprintf(out, "BB%u 0x%llx", t.template_id,
                     (unsigned long long)t.start_pc);
        if (!t.symbol_name.empty()) {
            std::fprintf(out, " <%s>", t.symbol_name.c_str());
        }
        std::fprintf(out, " (insns=%zu fall_through=0x%llx%s)\n",
                     t.insns.size(),
                     (unsigned long long)t.fall_through_pc,
                     (!t.insns.empty() && t.insns[0].is_system)
                         ? " system" : "");
        emit_bb_profile_lines(out, h, t, "  ");
        for (size_t k = 0; k < t.insns.size(); k++) {
            const cst::InsnProfileInfo *ip =
                k < t.profile.insns.size() ? &t.profile.insns[k] : nullptr;
            emit_template_only_line(out, h, dt, od, t.insns[k], ip);
        }
    }
}

/* ====================================================================
 * §10  Legacy renderer  (Python-compat output; byte-identical to
 *      champsim_tracer_decode.py's render_text_streaming)
 *
 * Section order: META → ENCODINGS → TEMPLATES → BODY → BODY_STATS.
 * Each section is a self-contained emit_legacy_* function below.
 * ==================================================================== */

void format_dyn_legacy(const cst::DynParam &dp, bool show_data,
                       std::string *out)
{
    out->append(dp.type == cst::DynParam::Load ? "load=0x" : "store=0x");
    out->append(fmt_hex_lower(dp.addr));
    if (show_data) {
        out->append(":data=");
        std::string w;
        w.reserve(16);
        append_wide_hex(&w, dp.data);
        out->append(w);
        /* Access byte width (CST_FID_*_SIZE), for value prediction; 0
         * when a trace predates the width families. */
        out->append(":size=");
        out->append(std::to_string(dp.data_size));
    }
}

/* Map a LaneMaskEntry::Family to its legacy section row name. */
const char *legacy_lane_family_name(cst::LaneMaskEntry::Family f)
{
    switch (f) {
    case cst::LaneMaskEntry::Src:       return "src";
    case cst::LaneMaskEntry::Dst:       return "dst";
    case cst::LaneMaskEntry::LoadData:  return "load";
    case cst::LaneMaskEntry::StoreData: return "store";
    }
    return "?";
}

/* "<prefix>memops:\n  insn[..] ...\n<prefix>regs:\n ..." */
void emit_legacy_observations(FILE *out, const std::string &prefix,
                              const cst::Header &h,
                              const std::vector<cst::DynParam> &dyns,
                              const std::vector<cst::RegSnap> &snaps,
                              const std::vector<cst::MetaFlagsEntry> &mflags,
                              const std::vector<cst::LaneMaskEntry> &lmasks)
{
    if (dyns.empty() && snaps.empty() && mflags.empty() && lmasks.empty()) {
        std::fprintf(out, "%sunchanged\n", prefix.c_str());
        return;
    }
    if (!dyns.empty()) {
        std::fprintf(out, "%smemops:\n", prefix.c_str());
        for (auto &dp : dyns) {
            std::string s;
            format_dyn_legacy(dp, h.has_mem_data(), &s);
            std::fprintf(out, "%s  insn[%u] %s\n", prefix.c_str(),
                         dp.insn_index, s.c_str());
        }
    }
    if (!snaps.empty()) {
        std::fprintf(out, "%sregs:\n", prefix.c_str());
        for (auto &r : snaps) {
            std::fprintf(out, "%s  insn[%u] dst[%u] %s=%s:w=%u\n",
                         prefix.c_str(), r.insn_index, r.operand_index,
                         fmt_reg(h, r.reg_id).c_str(),
                         fmt_snap_value(r.value).c_str(),
                         (unsigned)r.width_bytes);
        }
    }
    if (!mflags.empty()) {
        std::fprintf(out, "%smetaflags:\n", prefix.c_str());
        for (auto &m : mflags) {
            std::string s;
            append_metaflags_bits(&s, h.ids, m.byte);
            std::fprintf(out, "%s  insn[%u] 0x%02x [%s]\n",
                         prefix.c_str(), m.insn_index,
                         (unsigned)m.byte, s.c_str());
        }
    }
    if (!lmasks.empty()) {
        std::fprintf(out, "%slanes:\n", prefix.c_str());
        for (auto &lm : lmasks) {
            std::fprintf(out, "%s  insn[%u] %s[%u] 0x%llx\n",
                         prefix.c_str(), lm.insn_index,
                         legacy_lane_family_name(lm.family),
                         (unsigned)lm.slot_index,
                         (unsigned long long)lm.mask);
        }
    }
}

/* META section. */
void emit_legacy_meta(FILE *out, const cst::Header &h)
{
    std::fprintf(out, "META\n----\n");
    std::fprintf(out, "VERSION 0x%08X\n", h.magic);
    std::fprintf(out, "ISA %s\n", isa_display(h));
    std::fprintf(out, "COMMAND %s\n", h.command.c_str());
    std::fprintf(out, "DATETIME %s\n", h.datetime.c_str());
    std::fprintf(out, "COMMENT %s\n", h.comment.c_str());
    std::string flags;
    if (h.has_mem_data()) flags += " MEM_DATA";
    if (h.has_reg_data()) flags += " REG_DATA";
    std::fprintf(out, "FLAGS%s\n", flags.c_str());
    std::fprintf(out, "START_INSN %llu\n", (unsigned long long)h.start_insn);
    std::fprintf(out, "WARMUP_INSNS %llu\n",
                 (unsigned long long)h.warmup_insns);
    std::fprintf(out, "TOTAL_TARGET_INSNS %llu%s\n",
                 (unsigned long long)h.total_target_insns,
                 h.total_target_insns == 0 ? " (unbounded)" : "");
    if (h.warmup_end_arch_insns == UINT64_MAX) {
        std::fprintf(out, "WARMUP_END_ARCH_INSNS uncrossed\n");
    } else {
        std::fprintf(out, "WARMUP_END_ARCH_INSNS %llu\n",
                     (unsigned long long)h.warmup_end_arch_insns);
    }
    std::fprintf(out, "SIMPOINT_WEIGHT %.17g\n", h.weight);
    std::fprintf(out, "\n");
}

/* "<name> <count>\n  <id> <name>\n  ..." for one encoding map. */
void emit_legacy_encoding_map(FILE *out, const char *name,
                              const std::unordered_map<uint64_t, std::string> &m)
{
    if (m.empty()) return;
    std::fprintf(out, "%s %zu\n", name, m.size());
    std::vector<uint64_t> keys;
    keys.reserve(m.size());
    for (auto &kv : m) keys.push_back(kv.first);
    std::sort(keys.begin(), keys.end());
    for (uint64_t k : keys) {
        std::fprintf(out, "  %llu %s\n",
                     (unsigned long long)k, m.at(k).c_str());
    }
}

/* ENCODINGS section.  Walks the well-known encoding maps in
 * alphabetical order, then emits the two constant tables Python
 * carries inline (WP_STOP_REASONS, EXCEPTIONS). */
void emit_legacy_encodings(FILE *out, const cst::Header &h)
{
    std::fprintf(out, "ENCODINGS\n---------\n");
    struct MapRef {
        const char *name;
        const std::unordered_map<uint64_t, std::string> *m;
    };
    const MapRef refs[] = {
        {"body_tag",      &h.maps.body_tag},
        {"branch_type",   &h.maps.branch_type},
        {"field_id",      &h.maps.field_id},
        {"header_flag",   &h.maps.header_flag},
        {"insn_flag",     &h.maps.insn_flag},
        {"metaflags",     &h.maps.metaflags},
        {"mem_access_pattern", &h.maps.mem_access_pattern},
        {"opcode",        &h.maps.opcode},
        {"profile_flag",  &h.maps.profile_flag},
        {"reg",           &h.maps.reg},
        {"wp_event_flag", &h.maps.wp_event_flag},
    };
    for (auto &mr : refs) emit_legacy_encoding_map(out, mr.name, *mr.m);

    std::fprintf(out, "WP_STOP_REASONS 2\n");
    std::fprintf(out, "  0 NONE\n");
    std::fprintf(out, "  1 SYSCALL_USERMODE\n");
    std::fprintf(out, "EXCEPTIONS 5\n");
    std::fprintf(out, "  0 NONE\n");
    std::fprintf(out, "  1 UNKNOWN\n");
    std::fprintf(out, "  2 INT_DIVIDE_BY_ZERO\n");
    std::fprintf(out, "  3 FP_DIVIDE_BY_ZERO\n");
    std::fprintf(out, "  4 MEMORY_ACCESS\n");
    std::fprintf(out, "\n");
}

/* One template-insn line inside the legacy TEMPLATES section. */
void emit_legacy_template_insn(FILE *out, const cst::Header &h,
                               size_t i, const cst::InsnTemplate &I,
                               const cst::InsnProfileInfo *ip)
{
    std::string line = "  [";
    line += std::to_string(i);
    line += "] 0x";
    line += fmt_hex_lower(I.pc);
    line += ": op=";
    line += enum_or(h.maps.opcode, I.opcode, "OP");
    if (!branch_is_none(h, I.branch_type)) {
        line += " br=";
        line += enum_or(h.maps.branch_type, I.branch_type, "BR");
        line += " cond=";
        line += I.branch_conditional ? "1" : "0";
    }
    line += " src=[";
    for (size_t k = 0; k < I.src_regs.size(); k++) {
        if (k) line += ",";
        line += fmt_reg(h, I.src_regs[k]);
    }
    line += "] dst=[";
    for (size_t k = 0; k < I.dst_regs.size(); k++) {
        if (k) line += ",";
        line += fmt_reg(h, I.dst_regs[k]);
    }
    line += "]";
    if (I.has_imm) {
        line += " imm=";
        line += std::to_string(I.imm);
    }
    if (I.is_atomic) {
        line += " atomic";
    }
    if (I.lane_parallel) {
        line += " lane_parallel";
    }
    line += " bytes=";
    line += fmt_bytes_hex(I.raw_bytes);
    if (ip) {
        std::string pt = insn_prof_text(h, *ip);
        if (!pt.empty()) {
            line += "  ";
            line += pt;
        }
    }
    std::fprintf(out, "%s\n", line.c_str());

    /* Optional dep-mask continuation line (HAS_REG/HAS_ADDR):
     *   deps: [dst=..] [sd=..] [la=..] [sa=..]
     * Empty per-family vectors omitted. */
    if (!I.dst_dep_mask.empty() ||
        !I.store_data_dep_mask.empty() ||
        !I.load_addr_dep_mask.empty() ||
        !I.store_addr_dep_mask.empty()) {
        auto fmt_vec = [](const std::vector<uint64_t> &v,
                          const char *name, std::string *out) {
            if (v.empty()) return;
            if (!out->empty()) out->push_back(' ');
            out->append(name);
            out->push_back('=');
            for (size_t k = 0; k < v.size(); k++) {
                if (k) out->push_back(',');
                out->append("0x");
                append_hex(out, v[k]);
            }
        };
        std::string body;
        fmt_vec(I.dst_dep_mask,        "dst", &body);
        fmt_vec(I.store_data_dep_mask, "sd",  &body);
        fmt_vec(I.load_addr_dep_mask,  "la",  &body);
        fmt_vec(I.store_addr_dep_mask, "sa",  &body);
        std::fprintf(out, "    deps: %s\n", body.c_str());
    }
}

/* Resolve a profile pattern class id to its self-described name
 * ("CST_PAT_REGULAR"), falling back to the numeric value. */
static std::string profile_pat_name(const cst::Header &h, uint8_t v)
{
    auto it = h.maps.mem_access_pattern.find(v);
    if (it != h.maps.mem_access_pattern.end()) return it->second;
    return "CST_PAT_" + std::to_string((unsigned)v);
}

void emit_legacy_templates(FILE *out, const cst::Header &h,
                           const std::vector<cst::Template> &templates)
{
    std::fprintf(out, "TEMPLATES\n---------\n");
    for (const auto &t : templates) {
        std::fprintf(out,
                     "BB%u [pc=0x%llx, insns=%zu, fall_through=0x%llx%s]\n",
                     t.template_id,
                     (unsigned long long)t.start_pc,
                     t.insns.size(),
                     (unsigned long long)t.fall_through_pc,
                     (!t.insns.empty() && t.insns[0].is_system)
                         ? ", system" : "");
        if (!t.target_pcs.empty()) {
            std::fprintf(out, "  targets:");
            for (uint64_t tp : t.target_pcs) {
                std::fprintf(out, " 0x%llx", (unsigned long long)tp);
            }
            std::fprintf(out, "\n");
        }
        if (!t.symbol_name.empty()) {
            std::fprintf(out, "  symbol=%s\n", t.symbol_name.c_str());
        }

        /* BB-level profile (format §6): exec counts + per-target
         * taken/not-taken.  Per-insn profile rides inline on each
         * instruction's own line below (NONE/0 omitted). */
        emit_bb_profile_lines(out, h, t, "  ");

        for (size_t i = 0; i < t.insns.size(); i++) {
            const cst::InsnProfileInfo *ip =
                i < t.profile.insns.size() ? &t.profile.insns[i] : nullptr;
            emit_legacy_template_insn(out, h, i, t.insns[i], ip);
        }
        std::fprintf(out, "\n");
    }
}

/* Per-instruction profile rendered as an inline `prof: ...` tag to
 * sit on the instruction's own line.  Returns "" when nothing is
 * meaningful (no memops either path, pattern NONE, not address-like,
 * no effective-address bounds) so callers can omit it entirely. */
std::string insn_prof_text(const cst::Header &h,
                           const cst::InsnProfileInfo &ip)
{
    std::string s;
    char buf[160];
    auto add = [&](const char *frag) {
        if (!s.empty()) s.push_back(' ');
        s += frag;
    };
    if (ip.memops_cp) {
        std::snprintf(buf, sizeof(buf), "memops_cp=%llu",
                      (unsigned long long)ip.memops_cp);
        add(buf);
    }
    if (ip.memops_wp) {
        std::snprintf(buf, sizeof(buf), "memops_wp=%llu",
                      (unsigned long long)ip.memops_wp);
        add(buf);
    }
    if (ip.pat_cp) {
        std::snprintf(buf, sizeof(buf), "pat_cp=%s",
                      profile_pat_name(h, ip.pat_cp).c_str());
        add(buf);
    }
    if (ip.pat_wp) {
        std::snprintf(buf, sizeof(buf), "pat_wp=%s",
                      profile_pat_name(h, ip.pat_wp).c_str());
        add(buf);
    }
    if (ip.addr_cp) add("addr_cp=1");
    if (ip.addr_wp) add("addr_wp=1");
    if (ip.has_cp_bounds) {
        std::snprintf(buf, sizeof(buf), "cp=[0x%llx-0x%llx]",
                      (unsigned long long)ip.lo_cp,
                      (unsigned long long)ip.hi_cp);
        add(buf);
    }
    if (ip.has_wp_bounds) {
        std::snprintf(buf, sizeof(buf), "wp=[0x%llx-0x%llx]",
                      (unsigned long long)ip.lo_wp,
                      (unsigned long long)ip.hi_wp);
        add(buf);
    }
    if (s.empty()) {
        return s;
    }
    return "prof: " + s;
}

/* Look up the run-aggregated per-insn profile for an instruction by
 * its (bb_template_id, insn_index_in_bb), returning the inline tag or
 * "" — used by the disasm body renderer so the profile rides on each
 * dynamic instruction line rather than a header cluster. */
std::string insn_prof_text_for(const DisasmContext &ctx,
                               const cst::Instruction &insn)
{
    auto it = ctx.by_id->find(insn.bb_template_id);
    if (it == ctx.by_id->end()) {
        return {};
    }
    const cst::Template &t = (*ctx.templates)[it->second];
    if (insn.insn_index_in_bb >= t.profile.insns.size()) {
        return {};
    }
    return insn_prof_text(*ctx.h, t.profile.insns[insn.insn_index_in_bb]);
}

/* BB-level profile only (exec counts + per-target taken/not-taken).
 * Per-instruction profile is NOT emitted here — it rides inline on
 * each instruction line (see insn_prof_text). */
void emit_bb_profile_lines(FILE *out, const cst::Header & /*h*/,
                           const cst::Template &t, const char *pfx)
{
    const cst::TemplateProfileInfo &P = t.profile;
    std::fprintf(out, "%sprofile: exec_cp=%llu exec_wp=%llu\n",
                 pfx,
                 (unsigned long long)P.exec_cp,
                 (unsigned long long)P.exec_wp);
    for (size_t k = 0; k < P.targets.size(); k++) {
        const cst::BranchTargetCount &tc = P.targets[k];
        uint64_t tp = k < t.target_pcs.size() ? t.target_pcs[k] : 0;
        std::fprintf(out,
                     "%starget[%zu]: pc=0x%llx taken_cp=%llu "
                     "nottaken_cp=%llu taken_wp=%llu nottaken_wp=%llu\n",
                     pfx, k, (unsigned long long)tp,
                     (unsigned long long)tc.taken_cp,
                     (unsigned long long)tc.nottaken_cp,
                     (unsigned long long)tc.taken_wp,
                     (unsigned long long)tc.nottaken_wp);
    }
}

/* "FAULT@insn3 TRANSLATION_UNAVAILABLE" / "" for a single WPEntry. */
std::string compute_legacy_wp_status(const cst::WPEntry &wp)
{
    std::vector<std::string> parts;
    if (wp.fault) {
        parts.push_back(wp.has_fault_idx
                            ? "FAULT@insn" + std::to_string(wp.fault_insn_index)
                            : std::string("FAULT"));
    }
    if (wp.translation_unavailable) {
        parts.push_back("TRANSLATION_UNAVAILABLE");
    }
    if (wp.dep_branch_kill) {
        parts.push_back("DEP_BRANCH_KILL");
    }
    std::string out;
    for (size_t i = 0; i < parts.size(); i++) {
        if (i) out += " ";
        out += parts[i];
    }
    return out;
}

/* One BODY ENTRY block. */
void emit_legacy_entry(FILE *out, const cst::Header &h,
                       const cst::DecodedEntry &e)
{
    const char *sw = e.thread_switched ? " switch=1" : "";
    /* Exception-nesting depth + faulting-insn anchors (CST_FLAG_FAULT traces),
     * emitted only when present so normal/user-mode entries stay
     * byte-identical. */
    char fd[160];
    int n = 0;
    fd[0] = '\0';
    if (e.fault_depth > 0) {
        n += std::snprintf(fd + n, sizeof(fd) - n, " fault_depth=%u",
                           e.fault_depth);
    }
    if (!e.fault_anchors.empty()) {
        n += std::snprintf(fd + n, sizeof(fd) - n, " fault_at=");
        for (size_t i = 0; i < e.fault_anchors.size() &&
                           n < (int)sizeof(fd) - 12; i++) {
            n += std::snprintf(fd + n, sizeof(fd) - n, "%s%u",
                               i ? "," : "", e.fault_anchors[i]);
        }
    }
    std::fprintf(out, "ENTRY %04u thread=%u asid=%u%s%s template=BB%u\n",
                 e.seq_num, e.thread_id, e.asid, sw, fd, e.template_id);
    std::fprintf(out, "  cp:\n");
    emit_legacy_observations(out, "    ", h, e.dyn_params, e.reg_snaps,
                             e.metaflags, e.lane_masks);
    for (const auto &wp : e.wp_entries) {
        std::fprintf(out, "  wp[%u] template=BB%u n_insns=%u\n",
                     wp.index, wp.template_id, wp.n_insns);
        std::string status = compute_legacy_wp_status(wp);
        if (!status.empty()) {
            std::fprintf(out, "    status: %s\n", status.c_str());
        }
        emit_legacy_observations(out, "    ", h, wp.dyn_params, wp.reg_snaps,
                                 wp.metaflags, wp.lane_masks);
    }
    /* Chain-level TRANSLATION_UNAVAIL event (§4.4): the excursion was
     * kicked but its first target could not be fetched, so no wp[k]
     * blocks exist to carry a status line. */
    if (e.wp_first_fetch_unavailable) {
        std::fprintf(out, "  wp: none (first fetch unavailable)\n");
    }
    std::fprintf(out, "\n");
}

/* One REGFILE record block. */
void emit_legacy_regfile(FILE *out, const cst::Header &h,
                         const cst::DecodedRegfile &rf)
{
    std::fprintf(out, "REGFILE thread=%u n=%zu\n",
                 rf.thread_id, rf.regs.size());
    for (const auto &s : rf.regs) {
        std::fprintf(out, "  %s %s\n",
                     fmt_reg(h, s.gen_id).c_str(),
                     fmt_bytes_hex(s.bytes).c_str());
    }
    std::fprintf(out, "\n");
}

/* BODY_STATS section.  Trailing block so validators can cross-check
 * writer cadence without re-walking the body. */
void emit_legacy_body_stats(FILE *out, const cst::BodyStats &s)
{
    std::fprintf(out, "BODY_STATS\n----------\n");
    std::fprintf(out, "cp_entries %llu\n",          (unsigned long long)s.cp_entries);
    std::fprintf(out, "wp_entries %llu\n",          (unsigned long long)s.wp_entries);
    std::fprintf(out, "iframe_count %llu\n",        (unsigned long long)s.iframe_count);
    std::fprintf(out, "regfile_count %llu\n",       (unsigned long long)s.regfile_count);
    std::fprintf(out, "thread_switch_count %llu\n", (unsigned long long)s.thread_switch_count);
    std::fprintf(out, "asid_switch_count %llu\n",   (unsigned long long)s.asid_switch_count);
    std::fprintf(out, "fault_count %llu\n",         (unsigned long long)s.fault_count);
    std::fprintf(out, "translation_unavail_count %llu\n",
                 (unsigned long long)s.translation_unavail_count);
    std::fprintf(out, "atomic_count %llu\n",
                 (unsigned long long)s.atomic_count);
    std::fprintf(out, "\n");
}

void render_legacy(FILE *out, const cst::Header &h,
                   const std::vector<cst::Template> &templates,
                   const std::unordered_map<uint32_t, size_t> &by_id,
                   cst::BodyWalker &body)
{
    (void)by_id;
    emit_legacy_meta(out, h);
    emit_legacy_encodings(out, h);
    emit_legacy_templates(out, h, templates);

    std::fprintf(out, "BODY\n----\n");
    body.walk(
        [&](const cst::DecodedEntry &e)   { emit_legacy_entry(out, h, e); },
        [&](const cst::DecodedRegfile &rf){ emit_legacy_regfile(out, h, rf); });

    emit_legacy_body_stats(out, body.stats());

    /* Keep constant-table helpers reachable (unused here). */
    (void)exception_name; (void)wp_stop_reason_name;
}

/* ====================================================================
 * §11  CLI + dispatch
 * ==================================================================== */

struct Options {
    const char *trace_path     = nullptr;
    const char *format         = "disasm";
    bool        templates_only = false;
    bool        show_objdump   = false;
    bool        show_deps      = false;
    bool        show_lanes     = false;
    bool        strict         = false;
    uint64_t    max_entries    = 0;        /* 0 = unbounded */
};

void print_usage(FILE *err, const char *argv0)
{
    std::fprintf(err,
        "usage: %s [--format=disasm|legacy|raw] [--templates-only] "
        "[--objdump] [--show-deps] [--show-lanes] [--strict] [--max N] "
        "<trace.cst>\n"
        "  --format=raw      pseudo-wire structural dump: every field,\n"
        "                    record, and section in decode order with\n"
        "                    byte offsets + format-spec step refs (debug)\n"
        "  --templates-only  print only the template dictionary,\n"
        "                    skip the body delta-replay\n"
        "  --objdump         emit Capstone-rendered native disasm\n"
        "                    of each insn alongside the generic view\n"
        "  --show-deps       append intra-instruction dep masks as a\n"
        "                    trailing `; deps: d0=[s0,ld0] ...` comment\n"
        "                    when the template carries them\n"
        "  --show-lanes      annotate each vec operand with its lane set\n"
        "                    ({0..3,6}), split memop -> dst arrows by\n"
        "                    per-source lane contribution when disjoint\n"
        "  --strict          fail (exit 1, summary on stderr) when any\n"
        "                    CP observation is attributed to an insn\n"
        "                    that cannot produce it (memop on a\n"
        "                    memop-incapable insn, dst-reg value on a\n"
        "                    nonexistent operand slot)\n"
        "  --max N           stop after N body entries (tears the\n"
        "                    decompressor subprocess down early)\n",
        argv0);
}

/* Parse argv into @opts.  Returns 0 on success, 2 on usage error
 * (with usage written to stderr by the caller).  --max accepts both
 * "--max=N" and "--max N" forms. */
int parse_options(int argc, char **argv, Options *opts)
{
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (std::strncmp(a, "--format=", 9) == 0) {
            opts->format = a + 9;
        } else if (std::strcmp(a, "--legacy") == 0) {
            opts->format = "legacy";
        } else if (std::strcmp(a, "--templates-only") == 0) {
            opts->templates_only = true;
        } else if (std::strcmp(a, "--objdump") == 0) {
            opts->show_objdump = true;
        } else if (std::strcmp(a, "--show-deps") == 0) {
            opts->show_deps = true;
        } else if (std::strcmp(a, "--show-lanes") == 0) {
            opts->show_lanes = true;
        } else if (std::strcmp(a, "--strict") == 0) {
            opts->strict = true;
        } else if (std::strncmp(a, "--max=", 6) == 0) {
            opts->max_entries = std::strtoull(a + 6, nullptr, 10);
        } else if (std::strcmp(a, "--max") == 0 && i + 1 < argc) {
            opts->max_entries = std::strtoull(argv[++i], nullptr, 10);
        } else if (a[0] == '-') {
            return 2;
        } else {
            opts->trace_path = a;
        }
    }
    if (!opts->trace_path) return 2;
    if (opts->templates_only && std::strcmp(opts->format, "legacy") == 0) {
        std::fprintf(stderr,
            "cst_decode: --templates-only is incompatible with "
            "--format=legacy\n");
        return 2;
    }
    return 0;
}

/* Open Capstone for the trace's ISA when --objdump is set; returns
 * nullptr when objdump wasn't requested or the ISA is unsupported.
 * @od is provided as backing storage by the caller. */
ObjdumpRenderer *open_objdump_renderer(ObjdumpRenderer *od,
                                       const Options &opts,
                                       const cst::Header &h)
{
    if (!opts.show_objdump) return nullptr;
    if (od->open(h.isa)) return od;
    std::fprintf(stderr,
        "cst_decode: --objdump unsupported for ISA=%u; "
        "continuing without the objdump column\n", (unsigned)h.isa);
    return nullptr;
}

/* Walk the body section of @cf and dispatch to the requested
 * renderer.  Returns 0 on success, 2 on bad format string. */
int run_body_render(const Options &opts, const cst::Header &h,
                    cst::CstFile &cf,
                    const std::vector<cst::Template> &templates,
                    const std::unordered_map<uint32_t, size_t> &by_id,
                    const ObjdumpRenderer *odp)
{
    auto body_stream = cst::body_stream_open(cf);
    cst::BodyWalker walker(h, templates, by_id, body_stream->reader());
    walker.set_max_entries(opts.max_entries);

    if (std::strcmp(opts.format, "legacy") == 0) {
        render_legacy(stdout, h, templates, by_id, walker);
    } else if (std::strcmp(opts.format, "disasm") == 0) {
        render_disasm(stdout, h, templates, by_id, walker, odp,
                      opts.show_deps, opts.show_lanes);
    } else {
        std::fprintf(stderr, "cst_decode: unknown format '%s'\n",
                     opts.format);
        return 2;
    }

    /* finalize() reads + verifies the trailing magic.  Skip it when
     * --max stopped us early — the trailing magic isn't reachable. */
    bool stopped_early =
        opts.max_entries != 0 &&
        walker.stats().cp_entries >= opts.max_entries;
    if (!stopped_early) body_stream->finalize();

    /* Impossible-attribution lint (cst_lint.h).  Silent on a clean
     * trace so the rendered output stays byte-identical; a corrupt
     * trace gets a trailing summary comment, and --strict escalates
     * to stderr + a nonzero exit. */
    const cst::AttributionLint &lint = walker.lint();
    if (lint.any()) {
        if (opts.strict) {
            std::fprintf(stderr,
                         "cst_decode: impossible attributions: %s\n",
                         lint.summary().c_str());
            return 1;
        }
        std::fprintf(stdout, "; impossible attributions: %s\n",
                     lint.summary().c_str());
    }
    return 0;
}

int run(const Options &opts)
{
    /* Outer .cst is a ustar archive holding two members
     * (body.cst[.<codec>] + header.cst[.<codec>]).  cst_file_open
     * walks the tar, dispatches decompression per member suffix,
     * and returns a CstFile carrying the two byte ranges. */
    std::unique_ptr<cst::CstFile> cf = cst::cst_file_open(opts.trace_path);

    std::vector<cst::Template> templates;
    std::unordered_map<uint32_t, size_t> by_id;
    cst::Header h = cst::parse_header(cf->header(), &templates, &by_id);

    ObjdumpRenderer od;
    ObjdumpRenderer *odp = open_objdump_renderer(&od, opts, h);

    if (opts.templates_only) {
        /* No body access at all — no decompressor spawned, no body
         * bytes read off disk.  Cheap even on huge traces. */
        render_templates_only(stdout, h, templates, by_id, odp);
        return 0;
    }
    if (std::strcmp(opts.format, "raw") == 0) {
        /* Pseudo-wire structural dump: walks the raw bytes itself
         * (header + body) rather than going through BodyWalker, so it
         * owns its own body_stream_open + finalize. */
        cst::render_raw(stdout, *cf, h, templates, by_id, opts.max_entries);
        return 0;
    }
    return run_body_render(opts, h, *cf, templates, by_id, odp);
}

}  /* namespace */

int main(int argc, char **argv)
{
    Options opts;
    if (parse_options(argc, argv, &opts) != 0) {
        print_usage(stderr, argv[0]);
        return 2;
    }
    try {
        return run(opts);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "cst_decode: %s\n", e.what());
        return 1;
    }
}
