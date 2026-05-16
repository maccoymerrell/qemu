/*
 * cst_decode — textual decoder for .cst traces.
 *
 * Three output modes:
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

/* Lowercase hex, no leading zeros.  Builds digits in a stack buffer
 * end-first and appends in one shot — single push_back per char was
 * hot enough on a 200s decode (11.7% of total) to justify the small
 * overhead of computing a length first. */
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

/* Append a lane-mask as "{0..3,6}" — set bits coalesced into ascending
 * ranges, comma-separated.  Renders nothing (no braces) when @mask is
 * zero so callers can unconditionally invoke for every operand without
 * having to gate beforehand. */
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

std::string fmt_hex_lower(uint64_t v)
{
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%" PRIx64, v);
    return buf;
}

std::string fmt_bytes_hex(const std::vector<uint8_t> &b)
{
    std::string out;
    out.reserve(b.size() * 2);
    for (uint8_t x : b) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", x);
        out += buf;
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
    char buf[64];
    if (hi) {
        std::snprintf(buf, sizeof(buf), "0x%" PRIx64 "%016" PRIx64, hi, lo);
    } else {
        std::snprintf(buf, sizeof(buf), "0x%" PRIx64, lo);
    }
    return buf;
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
    if (n == "BRANCH_SYSCALL_TYPE")  return "syscall";
    return nullptr;
}

/* ====================================================================
 * §6  Per-trace lookup tables  (vector-indexed; built once at decode
 *     start to replace ~3.5% of total decode time spent in
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
 * §7  Capstone wrapper
 *
 * The ObjdumpRenderer class itself lives in cst_objdump.{h,cc} — see
 * those files for the implementation.  We pulled it out so that a
 * downstream consumer who lifts cst_decode for their own simulator
 * can drop cst_objdump.cc onto the build without -DCST_HAVE_CAPSTONE
 * and skip the capstone link dependency entirely; --objdump just
 * becomes a no-op at run time.
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

/*
 * Pre-render the input pool (src_regs + load_data + imm) into strings
 * keyed by their mask-bit position.  Loads render with their address
 * inputs inline ("ld[%base,%index](0x...)") when HAS_ADDR data is
 * available; otherwise fall back to "ld<k>(0x...)" or just "ld<k>".
 *
 * Bit layout matches the HAS_REG mask spec:
 *   bits [0, n_src)                          src_reg[i]
 *   bits [n_src, n_src + max_dep_loads)      load_data[k]
 *   bit  n_src + max_dep_loads               immediate
 */
/* Lookup helpers: zero-default when the per-slot vector is shorter
 * than the requested index, so callers can probe every slot without
 * length guards. */
inline uint64_t lane_at(const std::vector<uint64_t> &v, size_t i)
{
    return i < v.size() ? v[i] : 0;
}

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
 * Render the names of inputs flagged by @mask, comma-separated, with
 * lane-granularity refinement.  The coarse
 * dep mask says "this sink depends on input i"; the per-operand lane
 * masks say *which lanes* each side touches.  A lane-structured
 * input (its own lane mask non-zero) actually feeds the sink only on
 * the lanes they share — so when the intersection with @sink_lanes is
 * empty, the input does not feed this sink at all and is dropped
 * (e.g. PINSRD $3's pass-through src %v0{0..2} does NOT feed the
 * written lane %v0{3}).  Inputs with no lane mask (immediate, scalar
 * address regs) are not lane-structured and pass through unchanged.
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
 * "<inputs> -> <dst[regdata]>" arrow, possibly multiple arrows
 * separated by " ; " when dsts/store-data sinks have distinct dep
 * masks.  Returns true when the line ends with at least one operand.
 *
 * Always takes the dep-aware path: when HAS_REG is absent on the
 * wire, the renderer synthesizes a default "all inputs" mask for
 * every dst and store-data slot (matching the consumer's implicit
 * all-to-all fallback).  This gives symmetric output across
 * classified and unclassified rows — dst arrows track HAS_REG
 * precision when available and fall back to over-approximation
 * otherwise, while load/store memops always render with their
 * walker-derived address inputs inline.
 *
 * For purely register-flat instructions (no memops, no immediate)
 * the default-mask path collapses to "<srcs> -> <dsts>" — identical
 * to the legacy flat layout.
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
     * Default mask used when HAS_REG is absent on the wire.  Filters
     * out src_reg slots that the walker recorded as exclusively
     * addressing-mode (they appear in some load/store_addr mask but
     * the instruction has no other use for them): those srcs flow
     * into the dst transitively through the load/store address
     * placeholder, not directly.  Each load_data slot stays in the
     * default, since loads produce values consumed downstream by
     * default.
     *
     * Caveat — Capstone marks LEA's mem operand as CS_AC_READ even
     * though no real load fires, so the walker counts a "load" that
     * never happens.  The default mask for LEA then incorrectly
     * shows the dst depending on that phantom load.  A dedicated
     * LEA refiner overrides this with the precise "dst depends on
     * addressing-mode srcs + imm, no load" mask.
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

    uint64_t default_mask = 0;
    for (size_t i = 0; i < inputs.size(); i++) {
        default_mask |= ((uint64_t)1 << i);
    }
    default_mask &= ~addr_only_srcs;

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

    /* Per-input lane participation: bit at input-pool index `i` is set
     * iff lane k of that input is `mask_for_input(i, lane_k)`.  Returns
     * the per-input lane mask used when --show-lanes is set, indexed
     * the same way as @inputs (src_regs first, then load_data slots,
     * then imm).  Imm carries no lanes; addr-only loads carry the
     * load_data lane mask. */
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
            line.push_back(']');
        }
        if (ctx.show_lanes) {
            uint64_t lm = lane_override ? lane_override
                                        : lane_at(insn.dst_lane_mask, k);
            append_lane_set(&line, lm);
        }
    };

    /* Per-source lane split: when --show-lanes is set, a dst has a
     * non-empty lane mask, and the dst's contributing inputs each
     * carry a non-empty, pairwise-disjoint lane mask that exactly
     * partitions the dst lane mask, emit one arrow per source.  This
     * is the "ld[0] -> v0{0..1}  ;  ld[1] -> v0{2..3}" shape for vec
     * loads that fan into a single register.  Returns true when the
     * split was applied (caller skips the merged path). */
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

    /* Dst groups: walk in order, merging consecutive dsts with
     * identical masks into one arrow.  Preserving source order keeps
     * the rendering close to the instruction's natural reading.  With
     * --show-lanes, a dst whose sources partition its lane set is
     * split out into per-source arrows instead. */
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
        /* Address-only srcs feed the dst only transitively through the
         * memop (the dst depends on the load; the load's address
         * depends on those srcs, shown separately as laddr/saddr).
         * Drop them from the direct data-dependency set whether the
         * mask came from the wire or the default — otherwise an
         * all-to-all dst_dep_mask makes e.g. %v0{3} look directly
         * dependent on the stack pointer.  When --show-lanes broke the
         * merge, also filter inputs to those that feed this dst's
         * lanes. */
        render_input_set_laned(line, mask & ~addr_only_srcs, inputs,
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
        /* Same address-only-src exclusion as the dst path: a store's
         * data depends on the value srcs, not the addressing regs
         * (those feed the store address, shown as saddr). */
        render_input_set_laned(line, mask & ~addr_only_srcs, inputs,
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

    /* No dsts and no stores: render a "pure-input" line (e.g. a CMP
     * that only writes to implicit flags we don't track, or a NOP
     * with operands).  Fall through to the legacy flat form so we
     * still surface the operands. */
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
 * Memops the dep-aware operand renderer covered inline are skipped
 * here (their ld[...]/st[...] placeholders already carry the address
 * plus its address-input set).  Anything left — typically implicit
 * stack memops on CALL/PUSH/POP/RET that Capstone doesn't enumerate
 * as an explicit MEM operand, so the walker never bumped
 * max_dep_loads/stores for them — falls through to a trailing
 * "  ld(0x<addr>)" / "  st(0x<addr>)" column so the runtime address
 * stays visible.
 *
 * When the trace carries MEM_DATA, every dp (covered or not) gets a
 * "  ld=0x<data>" / "  st=0x<data>" column matched in order to its
 * placeholder/trailing form so the loaded/stored value isn't lost.
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
            /* Untracked memop — surface its address so the row isn't
             * silently missing a runtime side effect.  No address-
             * input set here: the walker has no info on it. */
            line.append(is_load ? "  ld(0x" : "  st(0x");
            append_hex(&line, dp.addr);
            line.push_back(')');
        }
        if (with_data) {
            line.append(is_load ? "  ld=0x" : "  st=0x");
            append_wide_hex(&line, dp.data);
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
 * "[%ip,ld0,imm]" — one HAS_REG mask rendered as a comma-separated
 * list of its set bit names.  Bit layout:
 *   bits [0, n_src)                          src_reg[i]
 *   bits [n_src, n_src + max_dep_loads)      load_data[i - n_src]
 *   bit  n_src + max_dep_loads               immediate
 *
 * src_reg bits use the actual reg name (looked up via @ctx) so the
 * annotation reads like the inline arrow rendering; load bits stay
 * positional ("ld<k>") since each load slot's own address is reported
 * separately as a load_addr mask.
 *
 * When @insn is non-null and --show-lanes is set, each entry gets a
 * per-input lane set suffix ("%v0{0..3}", "ld0{0..1}") drawn from the
 * per-Instance lane masks so the deps line mirrors the inline arrows.
 */
void append_dep_mask(std::string &line, uint64_t m,
                     const std::vector<uint8_t> &src_regs,
                     unsigned n_loads,
                     const DisasmContext &ctx,
                     const cst::Instruction *insn = nullptr,
                     uint64_t sink_lanes = 0)
{
    line.push_back('[');
    bool any = false;
    auto sep = [&]() {
        if (any) line.push_back(',');
        any = true;
    };
    unsigned n_src = (unsigned)src_regs.size();
    const bool annotate_lanes = ctx.show_lanes && insn != nullptr;
    /* Lane-granularity refinement: when the sink has a lane mask, a
     * lane-structured input is listed only where its lanes intersect
     * the sink's (PINSRD $3's pass-through src %v0{0..2} does not
     * feed the written lane %v0{3}). */
    auto feeds = [&](uint64_t in_lane) -> bool {
        if (!annotate_lanes || !sink_lanes) return true;
        if (!in_lane) return true;            /* scalar / imm: unfiltered */
        return (in_lane & sink_lanes) != 0;
    };
    for (unsigned i = 0; i < n_src; i++) {
        if (m & ((uint64_t)1 << i)) {
            uint64_t il = annotate_lanes
                              ? lane_at(insn->src_lane_mask, i) : 0;
            if (!feeds(il)) continue;
            sep();
            append_regref(&line, ctx, src_regs[i]);
            if (annotate_lanes) {
                append_lane_set(&line, il);
            }
        }
    }
    for (unsigned i = 0; i < n_loads; i++) {
        if (m & ((uint64_t)1 << (n_src + i))) {
            uint64_t il = annotate_lanes
                              ? lane_at(insn->load_data_lane_mask, i) : 0;
            if (!feeds(il)) continue;
            sep();
            line.append("ld");
            line.append(std::to_string(i));
            if (annotate_lanes) {
                append_lane_set(&line, il);
            }
        }
    }
    if (m & ((uint64_t)1 << (n_src + n_loads))) {
        sep();
        line.append("imm");
    }
    line.push_back(']');
}

/* "[%ip,imm]" — one HAS_ADDR mask rendered.  Bit layout has no load
 * slots (addresses are computed before any load fires): bits
 * [0, n_src) are src_regs, bit n_src is the immediate. */
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
 * "deps: %gp2=[ld0] sdata0=[%gp2] | laddr0=[%ip] saddr0=[%ip]"
 * — appended only when --show-deps is set and the template carries
 * a dep block or any memops (max_dep_loads/max_dep_stores > 0).
 *
 * When HAS_REG is absent on the wire, the annotation synthesizes
 * dst / store_data masks the same way emit_disasm_operands does
 * (non-address-only srcs + all loads + imm), so the deps line
 * mirrors the inline arrows.  Dst-reg slots use their actual reg
 * name; store/load slots stay positional since they don't have a
 * direct reg-name analog.
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

    uint64_t default_mask = 0;
    /* every src */
    default_mask |= src_bits;
    /* every load_data slot */
    for (unsigned k = 0; k < n_loads; k++) {
        default_mask |= ((uint64_t)1 << (n_src + k));
    }
    /* imm bit only when the template actually carries an immediate
     * — otherwise the annotation would falsely advertise "imm" as
     * an input on rows without one. */
    if (it.has_imm) {
        default_mask |= ((uint64_t)1 << imm_bit);
    }
    default_mask &= ~addr_only_srcs;

    bool wrote_reg = false;
    line.append("deps:");

    /* Dst masks: prefer wire HAS_REG; fall back to default. */
    size_t n_dst = it.dst_regs.size();
    for (size_t d = 0; d < n_dst; d++) {
        uint64_t m = d < it.dst_dep_mask.size() ? it.dst_dep_mask[d]
                                                : default_mask;
        /* Address-only srcs reach the dst transitively via the memop
         * (rendered as laddr/saddr), not as a direct data dep. */
        m &= ~addr_only_srcs;
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
        m &= ~addr_only_srcs;   /* store data != addressing srcs */
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

void render_disasm_insn(FILE *out, const DisasmContext &ctx,
                        const cst::Instruction &insn,
                        const char *wp_status)
{
    /* One thread_local buffer is reused across calls; the only
     * allocations come from short append_* / number conversions, and
     * those are amortised once the buffer reaches its high-water mark. */
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
    /* Parseable `; KEY=value` summary so simple greppers can pull the
     * trace's identity without parsing the binary header. */
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
    std::fprintf(out, "; templates=%zu\n\n", n_templates);
}

void emit_bb_header(FILE *out, const cst::DecodedEntry &e,
                    const cst::Template &t)
{
    std::fprintf(out,
                 "; ----- BB %u entry pc=0x%" PRIx64
                 " insns=%zu seq=%u tid=%u%s -----\n",
                 e.template_id, t.start_pc, t.insns.size(),
                 e.seq_num, e.thread_id,
                 e.thread_switched ? " (thread_switch)" : "");
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

struct UniqueTemplateInsn {
    uint64_t                 pc;
    const cst::InsnTemplate *insn;
};

/* Collect every distinct PC across all templates (first sighting wins
 * — the bytes are identical anyway), sorted ascending. */
std::vector<UniqueTemplateInsn> collect_unique_template_insns(
    const std::vector<cst::Template> &templates,
    std::unordered_map<uint64_t, std::string> *symbol_at)
{
    std::vector<UniqueTemplateInsn> out;
    out.reserve(templates.size() * 4);
    for (const cst::Template &t : templates) {
        if (!t.symbol_name.empty()) {
            (*symbol_at)[t.start_pc] = t.symbol_name;
        }
        for (const cst::InsnTemplate &I : t.insns) {
            out.push_back({I.pc, &I});
        }
    }
    std::sort(out.begin(), out.end(),
              [](const UniqueTemplateInsn &a, const UniqueTemplateInsn &b) {
                  return a.pc < b.pc;
              });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const UniqueTemplateInsn &a,
                             const UniqueTemplateInsn &b) {
                              return a.pc == b.pc;
                          }),
              out.end());
    return out;
}

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

void emit_template_only_symbol_marker(FILE *out, uint64_t pc,
                                      const std::string &symbol)
{
    std::string line;
    append_hex_padded(&line, pc, 16);
    line.append(" <");
    line.append(symbol);
    line.append(">:\n");
    std::fwrite(line.data(), 1, line.size(), out);
}

/* One templates-only line:
 *   "  <pc>:  <bytes...>  [objdump | ] <mnem>   <operands>\n"
 */
void emit_template_only_line(FILE *out, const cst::Header &h,
                             const DisasmTables &dt,
                             const ObjdumpRenderer *od,
                             const cst::InsnTemplate &I)
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

    std::unordered_map<uint64_t, std::string> symbol_at;
    auto unique_insns = collect_unique_template_insns(templates, &symbol_at);

    for (const UniqueTemplateInsn &e : unique_insns) {
        auto sit = symbol_at.find(e.pc);
        if (sit != symbol_at.end()) {
            emit_template_only_symbol_marker(out, e.pc, sit->second);
        }
        emit_template_only_line(out, h, dt, od, *e.insn);
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
            std::fprintf(out, "%s  insn[%u] dst[%u] %s=%s\n",
                         prefix.c_str(), r.insn_index, r.operand_index,
                         fmt_reg(h, r.reg_id).c_str(),
                         fmt_snap_value(r.value).c_str());
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
        {"opcode",        &h.maps.opcode},
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
                               size_t i, const cst::InsnTemplate &I)
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
    std::fprintf(out, "%s\n", line.c_str());

    /* Optional dep-mask continuation line — emitted when the template
     * carries HAS_REG and/or HAS_ADDR.  Format:
     *     deps: [dst=0x..,0x..] [sd=0x..,...] [la=0x..,...] [sa=0x..,...]
     * Empty per-family vectors are omitted entirely so a scalar
     * arith insn that only has dst_dep_mask renders as
     *     deps: dst=0x3,0x3
     * Aligned to match the indented insn-line style above. */
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

void emit_legacy_templates(FILE *out, const cst::Header &h,
                           const std::vector<cst::Template> &templates)
{
    std::fprintf(out, "TEMPLATES\n---------\n");
    for (const auto &t : templates) {
        std::fprintf(out,
                     "BB%u [pc=0x%llx, insns=%zu, fall_through=0x%llx]\n",
                     t.template_id,
                     (unsigned long long)t.start_pc,
                     t.insns.size(),
                     (unsigned long long)t.fall_through_pc);
        if (!t.symbol_name.empty()) {
            std::fprintf(out, "  symbol=%s\n", t.symbol_name.c_str());
        }
        for (size_t i = 0; i < t.insns.size(); i++) {
            emit_legacy_template_insn(out, h, i, t.insns[i]);
        }
        std::fprintf(out, "\n");
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
    std::fprintf(out, "ENTRY %04u thread=%u%s template=BB%u\n",
                 e.seq_num, e.thread_id, sw, e.template_id);
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

    /* Keep constant-table helpers reachable so the compiler doesn't
     * drop them — they're available to future callers but not used by
     * this renderer body. */
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
    uint64_t    max_entries    = 0;        /* 0 = unbounded */
};

void print_usage(FILE *err, const char *argv0)
{
    std::fprintf(err,
        "usage: %s [--format=disasm|legacy] [--templates-only] "
        "[--objdump] [--show-deps] [--show-lanes] [--max N] <trace.cst>\n"
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
