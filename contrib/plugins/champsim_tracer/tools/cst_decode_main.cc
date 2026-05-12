/*
 * cst_decode — textual decoder for .cst traces.
 *
 * Two output formats:
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

#include <capstone/capstone.h>

#include "cst_decode.h"
#include "cst_format.h"

namespace {

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

/* Reg name lookup honoring the trace's encoding map (which now also
 * carries initial-regfile bytes per entry). */
std::string fmt_reg(const cst::Header &h, uint64_t r)
{
    auto it = h.maps.reg.find(r);
    if (it != h.maps.reg.end()) return it->second;
    /* No map entry — synthesize a best-effort name; mirrors the
     * Python decoder's reg_name() fallback. */
    char buf[32];
    std::snprintf(buf, sizeof(buf), "REG_%llu", (unsigned long long)r);
    return buf;
}

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
 * pre-existing legacy behavior.  For dyn-param data values the
 * Python code uses the *full* integer, so wide loads get all their
 * bits printed.  We mirror both. */
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

/* Print a Wide as a single hex integer (no leading zeros), matching
 * Python's `f"0x{n:x}"`.  For values beyond 64 bits we walk the
 * upper limbs and concatenate. */
std::string fmt_wide_hex(const cst::Wide &w)
{
    /* Find the highest non-zero limb. */
    int top = -1;
    for (int i = (int)cst::Wide::LIMBS - 1; i >= 0; i--) {
        if (w.limb[i]) { top = i; break; }
    }
    if (top < 0) return "0x0";
    std::string out = "0x";
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%" PRIx64, w.limb[top]);
    out += buf;
    for (int i = top - 1; i >= 0; i--) {
        std::snprintf(buf, sizeof(buf), "%016" PRIx64, w.limb[i]);
        out += buf;
    }
    return out;
}

void format_dyn_legacy(const cst::DynParam &dp, bool show_data,
                       std::string *out)
{
    out->append(dp.type == cst::DynParam::Load ? "load=0x" : "store=0x");
    out->append(fmt_hex_lower(dp.addr));
    /* Always emit :data= when memdata was captured, even if the
     * value is zero — see the matching disasm-format note. */
    if (show_data) {
        out->append(":data=");
        out->append(fmt_wide_hex(dp.data));
    }
}

/* ===== Disasm-format helpers =====
 *
 * Pre-built per-id tables built once at the first render call.  Replace
 * the per-line unordered_map lookup in fmt_reg / enum_or — those were
 * ~3.5 % of total decode time on full-config mcf according to perf.
 *
 * Mnemonic table converts GEN_OP_INT_ADD → "add", GEN_OP_FP_ADD →
 * "fadd", GEN_OP_VEC_ADD → "vadd", etc. (objdump-style short forms).
 *
 * Reg table converts REG_GPR0 → "%gp0", REG_FPR3 → "%f3",
 * REG_VEC2 → "%v2", REG_SP → "%sp", REG_FLAGS → "%flags", and so on.
 *
 * Both fall back to the trace's own encoding map when an id wasn't
 * built into the lookup; that's the same path fmt_reg/enum_or used.
 */
struct DisasmTables {
    std::vector<std::string> opcode;     /* indexed by GEN_OP_* */
    std::vector<std::string> reg;        /* indexed by REG_* */
};

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
 * For GEN_OP_BRANCH the writer didn't pin a flavour into the opcode
 * name; the renderer overrides the mnemonic with the branch_type
 * (jmp / jcc / jmpr / ...) at the call site. */
std::string mnem_from_genop(const std::string &name)
{
    std::string body = strip_lower(name, "GEN_OP_");
    if (body == "branch") return "jmp";  /* default; overridden by branch_type */
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
    if (body.compare(0, 3, "gpr") == 0)  return "%gp" + body.substr(3);
    if (body.compare(0, 3, "fpr") == 0)  return "%f"  + body.substr(3);
    if (body.compare(0, 3, "vec") == 0)  return "%v"  + body.substr(3);
    if (body.compare(0, 4, "pred") == 0) return "%p"  + body.substr(4);
    if (body.compare(0, 5, "bound") == 0) return "%b" + body.substr(5);
    if (body.compare(0, 7, "matrix_") == 0) return "%m" + body.substr(7);
    if (body == "fp_reg") return "%fpr";   /* legacy alias bucket */
    if (body == "vec_reg") return "%vr";
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
 * traces.  Compact even on the busiest case (5 chars vs the
 * 1-byte-zero-padded "0x1f" hex form).
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

/*
 * Branch-type lookup keyed off the trace's own encoding-map name
 * rather than a compile-time enum.  The wire format pins the names
 * (BRANCH_NONE, BRANCH_DIRECT_JUMP, ...) regardless of which numeric
 * id the writer assigns; matching by string keeps the decoder
 * forward-compatible with future tracers that re-number the enum or
 * add new branch flavours.  Returns nullptr for ids the trace
 * carries no name for (the renderer falls back to a generic "br").
 */
const std::string *branch_name_lookup(const cst::Header &h, uint64_t bt)
{
    auto it = h.maps.branch_type.find(bt);
    if (it == h.maps.branch_type.end()) return nullptr;
    return &it->second;
}

bool branch_is_none(const cst::Header &h, uint64_t bt)
{
    /* Wire-format reserves id 0 for "not a branch"; the encoding map
     * names that slot "BRANCH_NONE" but the renderer doesn't depend on
     * the name being present. */
    if (bt == 0) return true;
    const std::string *n = branch_name_lookup(h, bt);
    return n && *n == "BRANCH_NONE";
}

/* Map encoding-map name → short objdump-style mnemonic. */
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

/*
 * Append @v as lowercase hex into @out.  Builds the digits in a stack
 * buffer end-first and appends in one shot — single push_back per
 * character was hot enough on a 200s decode (11.7 % of total) to
 * justify the small overhead of computing a length first.
 */
inline const char *kHexDigits = "0123456789abcdef";

void append_hex(std::string *out, uint64_t v)
{
    if (v == 0) { out->push_back('0'); return; }
    char buf[16];
    int n = 0;
    while (v) { buf[15 - n] = kHexDigits[v & 0xF]; v >>= 4; n++; }
    out->append(buf + (16 - n), (size_t)n);
}

/* Width-padded hex (zero-padded to @width chars).  Used for the PC
 * column where we always want 12 digits. */
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

/*
 * Capstone-backed objdump-style disassembler (--objdump flag).
 *
 * Holds one cs_handle per cst_decode invocation (NOT per insn) so
 * the per-line cost is just cs_disasm_iter on the raw_bytes that
 * the trace already carries.  Selected mode follows the trace's
 * declared ISA (header.isa).  When the ISA is unsupported or
 * Capstone is unavailable for a given build, render() returns
 * false and the caller suppresses the side-by-side column.
 */
class ObjdumpRenderer {
public:
    ObjdumpRenderer() = default;

    ~ObjdumpRenderer() {
        if (open_) cs_close(&handle_);
    }

    bool open(uint8_t trace_isa) {
        cs_arch arch;
        cs_mode mode;
        switch (trace_isa) {
        case 1: arch = CS_ARCH_X86;     mode = CS_MODE_64;            break;
        case 2: arch = CS_ARCH_AARCH64; mode = CS_MODE_LITTLE_ENDIAN; break;
        case 3: arch = CS_ARCH_RISCV;   mode = CS_MODE_RISCV64;       break;
        case 4: arch = CS_ARCH_MIPS;    mode = (cs_mode)(CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN); break;
        default: return false;
        }
        if (cs_open(arch, mode, &handle_) != CS_ERR_OK) return false;
        cs_option(handle_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
        open_ = true;
        return true;
    }

    /*
     * Disassemble one instruction at @pc from @bytes (length @n_bytes).
     * Writes "mnem  ops" into @out.  Returns true on success.  The
     * per-call cost is dominated by cs_disasm_iter — ~2 µs per insn
     * on x86-64 with default Capstone, comparable to a single fmt_*
     * call on our side; cheap enough to enable per-template at decode
     * time.
     */
    bool render_one(uint64_t pc, const uint8_t *bytes, size_t n_bytes,
                    std::string *out) const {
        if (!open_ || !bytes || n_bytes == 0) return false;
        cs_insn *insn = cs_malloc(handle_);
        if (!insn) return false;
        const uint8_t *code = bytes;
        size_t size = n_bytes;
        uint64_t addr = pc;
        bool ok = cs_disasm_iter(handle_, &code, &size, &addr, insn);
        if (ok) {
            /* Pad mnemonic to a fixed width so the operand column
             * lines up across instructions of varying mnemonic
             * length.  Capstone returns a separate mnemonic and
             * op_str — joining them with a single space (rather
             * than the tab Capstone uses internally) keeps
             * column alignment when the caller pads-to-N-chars. */
            const size_t mnem_col = 8;
            size_t before = out->size();
            out->append(insn->mnemonic);
            while (out->size() - before < mnem_col) out->push_back(' ');
            if (insn->op_str[0]) {
                out->push_back(' ');
                out->append(insn->op_str);
            }
        }
        cs_free(insn, 1);
        return ok;
    }

private:
    csh  handle_ = 0;
    bool open_   = false;
};

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

/* ===== Legacy renderer (byte-identical to champsim_tracer_decode.py) ===== */

void emit_observations_legacy(FILE *out, const std::string &prefix,
                              const cst::Header &h,
                              const std::vector<cst::DynParam> &dyns,
                              const std::vector<cst::RegSnap> &snaps,
                              const std::vector<cst::MetaFlagsEntry> &mflags)
{
    if (dyns.empty() && snaps.empty() && mflags.empty()) {
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
}

void render_legacy(FILE *out, const cst::Header &h,
                   const std::vector<cst::Template> &templates,
                   const std::unordered_map<uint32_t, size_t> &by_id,
                   cst::BodyWalker &body)
{
    std::fprintf(out, "META\n----\n");
    std::fprintf(out, "VERSION 0x%08X\n", h.magic);
    std::string isa_str = !h.target_name.empty() ? h.target_name
                                                 : isa_name(h.isa);
    std::fprintf(out, "ISA %s\n", isa_str.c_str());
    std::fprintf(out, "COMMAND %s\n", h.command.c_str());
    std::fprintf(out, "DATETIME %s\n", h.datetime.c_str());
    std::fprintf(out, "COMMENT %s\n", h.comment.c_str());
    std::string flags;
    if (h.has_mem_data()) flags += " MEM_DATA";
    if (h.has_reg_data()) flags += " REG_DATA";
    std::fprintf(out, "FLAGS%s\n", flags.c_str());
    std::fprintf(out, "START_INSN %llu\n",
                 (unsigned long long)h.start_insn);
    std::fprintf(out, "WARMUP_INSNS %llu\n",
                 (unsigned long long)h.warmup_insns);
    std::fprintf(out, "TOTAL_TARGET_INSNS %llu%s\n",
                 (unsigned long long)h.total_target_insns,
                 h.total_target_insns == 0 ? " (unbounded)" : "");
    std::fprintf(out, "\n");

    std::fprintf(out, "ENCODINGS\n---------\n");
    /* The Python decoder iterates encoding_maps in sorted order if any
     * map exists, else falls back to a built-in list.  We always have
     * the merged maps populated, so honor sorted iteration over the
     * maps that are non-empty. */
    struct MapRef {
        const char *name;
        const std::unordered_map<uint64_t, std::string> *m;
    };
    MapRef refs[] = {
        {"body_tag",      &h.maps.body_tag},
        {"branch_type",   &h.maps.branch_type},
        {"field_id",      &h.maps.field_id},
        {"header_flag",   &h.maps.header_flag},
        {"insn_flag",     &h.maps.insn_flag},
        {"metaflags",     &h.maps.metaflags},
        {"opcode",        &h.maps.opcode},
        {"reg",           &h.maps.reg},
        {"sync_hint",     &h.maps.sync_hint},
        {"wp_event_flag", &h.maps.wp_event_flag},
    };
    /* Already alphabetical above. */
    for (auto &mr : refs) {
        if (mr.m->empty()) continue;
        std::fprintf(out, "%s %zu\n", mr.name, mr.m->size());
        std::vector<uint64_t> keys;
        keys.reserve(mr.m->size());
        for (auto &kv : *mr.m) keys.push_back(kv.first);
        std::sort(keys.begin(), keys.end());
        for (uint64_t k : keys) {
            std::fprintf(out, "  %llu %s\n",
                         (unsigned long long)k, mr.m->at(k).c_str());
        }
    }
    /* WP_STOP_REASONS / EXCEPTIONS are constant tables in the Python. */
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

    std::fprintf(out, "TEMPLATES\n---------\n");
    for (auto &t : templates) {
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
            const auto &I = t.insns[i];
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
            if (I.sync_hint != 0) {
                line += " sync=";
                line += enum_or(h.maps.sync_hint, I.sync_hint, "SYNC");
            }
            line += " bytes=";
            line += fmt_bytes_hex(I.raw_bytes);
            std::fprintf(out, "%s\n", line.c_str());
        }
        std::fprintf(out, "\n");
    }

    std::fprintf(out, "BODY\n----\n");
    body.walk(
        [&](const cst::DecodedEntry &e) {
        const char *sw = e.thread_switched ? " switch=1" : "";
        std::fprintf(out, "ENTRY %04u thread=%u%s template=BB%u\n",
                     e.seq_num, e.thread_id, sw, e.template_id);
        std::fprintf(out, "  cp:\n");
        emit_observations_legacy(out, "    ", h, e.dyn_params, e.reg_snaps,
                                 e.metaflags);
        for (auto &wp : e.wp_entries) {
            std::fprintf(out,
                         "  wp[%u] template=BB%u n_insns=%u\n",
                         wp.index, wp.template_id, wp.n_insns);
            std::vector<std::string> statuses;
            if (wp.fault) {
                if (wp.has_fault_idx) {
                    statuses.push_back("FAULT@insn" +
                                       std::to_string(wp.fault_insn_index));
                } else {
                    statuses.push_back("FAULT");
                }
            }
            if (wp.translation_unavailable) {
                statuses.push_back("TRANSLATION_UNAVAILABLE");
            }
            if (!statuses.empty()) {
                std::string s;
                for (size_t i = 0; i < statuses.size(); i++) {
                    if (i) s += " ";
                    s += statuses[i];
                }
                std::fprintf(out, "    status: %s\n", s.c_str());
            }
            emit_observations_legacy(out, "    ", h, wp.dyn_params, wp.reg_snaps,
                                     wp.metaflags);
        }
        std::fprintf(out, "\n");
    },
    [&](const cst::DecodedRegfile &rf) {
        std::fprintf(out, "REGFILE thread=%u n=%zu\n",
                     rf.thread_id, rf.regs.size());
        for (const auto &s : rf.regs) {
            std::fprintf(out, "  %s %s\n",
                         fmt_reg(h, s.gen_id).c_str(),
                         fmt_bytes_hex(s.bytes).c_str());
        }
        std::fprintf(out, "\n");
    });

    /* Trailing structural-stats section so the validator can
     * cross-check the writer's cadence (one REGFILE per thread per
     * segment, at-least-one IFRAME per N entries, sync_hints, etc.)
     * without re-walking the body or shelling out to cst_audit. */
    const auto &s = body.stats();
    std::fprintf(out, "BODY_STATS\n----------\n");
    std::fprintf(out, "cp_entries %llu\n",
                 (unsigned long long)s.cp_entries);
    std::fprintf(out, "wp_entries %llu\n",
                 (unsigned long long)s.wp_entries);
    std::fprintf(out, "iframe_count %llu\n",
                 (unsigned long long)s.iframe_count);
    std::fprintf(out, "regfile_count %llu\n",
                 (unsigned long long)s.regfile_count);
    std::fprintf(out, "thread_switch_count %llu\n",
                 (unsigned long long)s.thread_switch_count);
    std::fprintf(out, "fault_count %llu\n",
                 (unsigned long long)s.fault_count);
    std::fprintf(out, "translation_unavail_count %llu\n",
                 (unsigned long long)s.translation_unavail_count);
    /* Sort sync hints by id for stable output. */
    std::vector<uint8_t> hint_keys;
    hint_keys.reserve(s.sync_hint_counts.size());
    for (auto &kv : s.sync_hint_counts) hint_keys.push_back(kv.first);
    std::sort(hint_keys.begin(), hint_keys.end());
    std::fprintf(out, "sync_hint_counts %zu\n", hint_keys.size());
    for (uint8_t k : hint_keys) {
        std::fprintf(out, "  %u %llu\n", (unsigned)k,
                     (unsigned long long)s.sync_hint_counts.at(k));
    }
    std::fprintf(out, "\n");

    /* Suppress unused-variable warnings for the constant tables that
     * the legacy renderer references but doesn't otherwise consume. */
    (void)exception_name; (void)wp_stop_reason_name;
}

/* ===== Disassembly renderer ===== */

/* Format a single canonical instruction as an objdump-style line.
 * Output:
 *
 *   0x<addr> <symbol+0xoff>: <OPCODE>  <operands>  ; tid=N bb=B [extras]
 *
 * The metadata after `;` includes per-insn dyn params (memops with
 * effective addresses, optional load/store data) and dst register
 * writes resolved to (reg=value) pairs.  Each instruction's line is
 * fully self-contained so a `grep '<name>'` or `grep 'st_addr=0x'`
 * over the dump produces a useful result.
 */
struct DisasmContext {
    const cst::Header *h;
    const std::unordered_map<uint32_t, size_t> *by_id;
    const std::vector<cst::Template> *templates;
    const DisasmTables *t;
    /* Optional Capstone-backed objdump-style renderer.  When non-null
     * each insn line is emitted twice on one row: bytes column,
     * objdump disasm in a fixed-width left field, then our generic
     * trace view (with regdata / memdata) on the right. */
    const ObjdumpRenderer *od;
    /* --show-deps: append intra-instruction dependency masks as a
     * trailing comment when the template carries them. */
    bool                   show_deps = false;
};

/* Append a register reference resolved through the prebuilt table; on
 * miss synthesizes from the trace's encoding map.  No allocation in
 * the hot path. */
void append_regref(std::string *out, const DisasmContext &ctx, uint64_t r)
{
    const std::string *p = table_lookup(ctx.t->reg, r);
    if (p) { out->append(*p); return; }
    auto it = ctx.h->maps.reg.find(r);
    if (it != ctx.h->maps.reg.end()) {
        out->append(regref_from_name(it->second));
        return;
    }
    out->append("%r");
    append_hex(out, r);
}

void append_mnem(std::string *out, const DisasmContext &ctx, uint64_t op)
{
    const std::string *p = table_lookup(ctx.t->opcode, op);
    if (p) { out->append(*p); return; }
    auto it = ctx.h->maps.opcode.find(op);
    if (it != ctx.h->maps.opcode.end()) {
        out->append(mnem_from_genop(it->second));
        return;
    }
    out->append("op");
    append_hex(out, op);
}

void append_pad_to(std::string *out, size_t target)
{
    while (out->size() < target) out->push_back(' ');
}

/* Render one objdump-style instruction line.  Layout:
 *
 *   <pc> <sym+off>: <bytes...>  <mnem>   <imm/srcs> -> <dsts[v]>  ; meta
 *
 * — bytes match objdump's per-byte hex columns
 * — operands listed AT&T-ish: imm first, then srcs, an arrow, then dsts
 *   with regdata appended in [v]
 * — memops decorate the address with their data inline as (addr)=val
 * — branch targets append <symbol> when the target's BB is known
 * — the trailing `; ...` carries thread/bb/wp/sync flags for greppers
 *
 * Consumes a fully-built cst::Instruction (dyn_params / reg_snaps /
 * metaflags pre-filtered to this insn, branch_target_template
 * already resolved).  @wp_status is the chain-level status string
 * the caller derived once per WP run (nullptr for CP / clean WP).
 *
 * One thread_local std::string is reused across calls; the only
 * allocations come from short append_hex / number conversions, and
 * those are amortised once the buffer reaches its high-water mark. */
void render_disasm_insn(FILE *out, const DisasmContext &ctx,
                        const cst::Instruction &insn,
                        const char *wp_status)
{
    /* Per-thread reusable buffer to avoid the malloc/free churn the
     * old per-line std::string + concat path created (~6 % memmove +
     * 5 % alloc/free on full-config mcf decode). */
    static thread_local std::string line;
    line.clear();

    /* PC + symbol prefix.  Padded to 12 hex chars so columns align. */
    line.append("0x");
    append_hex_padded(&line, insn.pc, 12);
    if (insn.bb_template && !insn.bb_template->symbol_name.empty()) {
        line.append(" <");
        line.append(insn.bb_template->symbol_name);
        line.append("+0x");
        append_hex(&line, insn.pc - insn.bb_template->start_pc);
        line.push_back('>');
    }
    line.append(": ");

    /* Bytes column — objdump prints up to ~7 bytes inline; we let it
     * grow as needed (raw_bytes is at most 16 for x86 long encodings).
     * Each byte is two hex chars + a space; pad to a fixed width so
     * the mnemonic column lines up regardless of actual byte count. */
    size_t bytes_start = line.size();
    for (size_t b = 0; b < insn.raw_bytes.size(); b++) {
        if (b) line.push_back(' ');
        append_byte_hex(&line, insn.raw_bytes[b]);
    }
    /* Pad to bytes_start + 7*3 + slack, putting the mnemonic at a
     * stable column. */
    append_pad_to(&line, bytes_start + 7 * 3 + 4);

    /* Optional --objdump column: native disasm of the raw bytes via
     * Capstone, padded to a stable width so the generic-trace view
     * lines up underneath.  Each per-insn cs_disasm_iter call is
     * ~2 µs on x86-64 — cheap relative to the surrounding decode
     * work since templates are small (5-20 insns each) and shared. */
    if (ctx.od) {
        size_t obj_start = line.size();
        std::string obj;
        if (ctx.od->render_one(insn.pc, insn.raw_bytes.data(),
                               insn.raw_bytes.size(), &obj)) {
            line.append(obj);
        } else {
            line.append("(undecoded)");
        }
        append_pad_to(&line, obj_start + 40);
        line.append("| ");
    }

    /* Mnemonic.  For branch opcodes we substitute a branch-flavoured
     * mnemonic (jmp / jcc / jmpr / ret / syscall) drawn from the
     * trace's own branch_type encoding map so the per-line annotation
     * doesn't have to repeat `br=...`.  Other opcodes use the
     * pre-built mnemonic table directly. */
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
    append_pad_to(&line, mnem_start + 8);

    /* Operands.  Order: imm, srcs, '->', dsts (with regdata in []). */
    bool first = true;
    auto sep = [&]() {
        if (!first) line.append(", ");
        first = false;
    };
    if (insn.has_immediate) {
        sep();
        line.append("$0x");
        append_hex(&line, (uint64_t)insn.immediate);
    }
    for (size_t k = 0; k < insn.src_regs.size(); k++) {
        sep();
        append_regref(&line, ctx, insn.src_regs[k]);
    }
    /* Dst section.  Skipped entirely when there are no dst regs, so
     * NOPs and stores stay clean. */
    if (!insn.dst_regs.empty()) {
        if (!first) line.append(" -> ");
        for (size_t k = 0; k < insn.dst_regs.size(); k++) {
            if (k) line.append(", ");
            append_regref(&line, ctx, insn.dst_regs[k]);
            /* Find the matching reg_snap for this dst slot.  reg_snaps
             * are in template-walk order, so the operand_index lines
             * up with k. */
            for (const auto &r : insn.reg_snaps) {
                if (r.operand_index == (uint8_t)k) {
                    line.append("[");
                    append_wide_hex(&line, r.value);
                    line.append("]");
                    break;
                }
            }
        }
        first = false;
    }
    /* FID_METAFLAGS side-channel: rendered as %mflags[ZNCVP] after the
     * dst section for any insn whose template writes the integer-flags
     * register.  Pulled from the per-entry metaflags vector populated
     * by the body walker. */
    for (const auto &mf : insn.metaflags) {
        if (first) {
            line.append(" ");
            first = false;
        } else {
            line.append(", ");
        }
        line.append("%mflags[");
        append_metaflags_bits(&line, ctx.h->ids, mf.byte);
        line.append("]");
        break;
    }

    /* Memory operands rendered inline as ld(addr)=val / st(addr)=val
     * after the dst section (or after operands if no dst).  When
     * memdata is enabled in the trace we ALWAYS print the =value, even
     * when it happens to be zero — otherwise the absence of an `=` is
     * ambiguous between "memdata wasn't captured" and "the loaded /
     * stored value was zero". */
    for (const auto &dp : insn.dyn_params) {
        line.append(dp.type == cst::DynParam::Load ? "  ld(0x" : "  st(0x");
        append_hex(&line, dp.addr);
        line.push_back(')');
        if (ctx.h->has_mem_data()) {
            line.push_back('=');
            append_wide_hex(&line, dp.data);
        }
    }

    /* Branch annotations: target PC and symbol when known. */
    if (!branch_is_none(*ctx.h, insn.branch_type)) {
        if (insn.branch_target_template) {
            line.append("  # 0x");
            append_hex(&line, insn.branch_target_template->start_pc);
            if (!insn.branch_target_template->symbol_name.empty()) {
                line.append(" <");
                line.append(insn.branch_target_template->symbol_name);
                line.push_back('>');
            }
        }
    }

    /* Trailing metadata.  thread / bb / wp markers are already on
     * the BB header line just above this group of insns, so we don't
     * repeat them per-instruction.  The remaining items are flavours
     * that aren't otherwise visible from the bytes/operands: sync
     * hints (rare) and per-WP fault / translation-unavailable status
     * (only meaningful for the WP-side entries that carry it). */
    bool wrote_meta = false;
    auto begin_meta = [&]() {
        if (!wrote_meta) { line.append("  ; "); wrote_meta = true; }
        else             { line.push_back(' '); }
    };
    if (wp_status && *wp_status) {
        begin_meta();
        line.append(wp_status);
    }
    if (insn.sync_hint != 0) {
        begin_meta();
        line.append("sync=");
        line.append(enum_or(ctx.h->maps.sync_hint, insn.sync_hint, "SYNC"));
    }
    /* Intra-instruction dependency masks live on the template (they
     * describe the canonical insn shape, not the per-instance data).
     * Look them up via Instruction::bb_template when --show-deps. */
    if (ctx.show_deps && insn.bb_template &&
        insn.insn_index_in_bb < insn.bb_template->insns.size() &&
        insn.bb_template->insns[insn.insn_index_in_bb].has_reg_deps) {
        const cst::InsnTemplate &it =
            insn.bb_template->insns[insn.insn_index_in_bb];
        unsigned n_src = (unsigned)it.src_regs.size();
        /* The template's n_loads is the static load count baseline;
         * the wire format always writes 0 here so we approximate by
         * scanning the highest "load" bit any mask sets.  Good enough
         * for human-readable comment; the bit layout itself is
         * unambiguous so no information is lost. */
        unsigned n_loads = 0;
        auto note_loads = [&](uint32_t m) {
            for (unsigned b = n_src; b < 32; b++) {
                if (m & (1u << b)) {
                    unsigned k = b - n_src + 1;
                    if (k > n_loads) n_loads = k;
                }
            }
        };
        for (auto m : it.dst_dep_mask) note_loads(m);
        for (auto m : it.store_data_dep_mask) note_loads(m);
        auto fmt_mask = [&](std::string *o, uint32_t m) {
            o->push_back('[');
            bool first = true;
            for (unsigned i = 0; i < n_src; i++) {
                if (m & (1u << i)) {
                    if (!first) o->push_back(',');
                    o->append("s");
                    o->append(std::to_string(i));
                    first = false;
                }
            }
            for (unsigned i = 0; i < n_loads; i++) {
                if (m & (1u << (n_src + i))) {
                    if (!first) o->push_back(',');
                    o->append("ld");
                    o->append(std::to_string(i));
                    first = false;
                }
            }
            if (m & (1u << (n_src + n_loads))) {
                if (!first) o->push_back(',');
                o->append("imm");
                first = false;
            }
            o->push_back(']');
        };
        begin_meta();
        line.append("deps:");
        for (size_t d = 0; d < it.dst_dep_mask.size(); d++) {
            line.append(" d");
            line.append(std::to_string(d));
            line.append("=");
            fmt_mask(&line, it.dst_dep_mask[d]);
        }
        for (size_t s = 0; s < it.store_data_dep_mask.size(); s++) {
            line.append(" st");
            line.append(std::to_string(s));
            line.append("=");
            fmt_mask(&line, it.store_data_dep_mask[s]);
        }
    }
    line.push_back('\n');
    std::fwrite(line.data(), 1, line.size(), out);
}

/*
 * Templates-only renderer (--templates-only flag).  Walks every
 * template, dedupes by PC, sorts ascending, and emits one insn line
 * per unique PC — exactly the shape `objdump -d` produces over a
 * binary's text section.  Symbol-rooted templates (those whose
 * start_pc is the entry of a named function) emit a
 * `<pc> <symbol>:` header above their first insn, mirroring
 * objdump's section markers.  Non-symbolic BBs do not emit any
 * synthetic delimiter.
 *
 * When @od is non-null the per-insn text is Capstone's native
 * disasm of the raw bytes; otherwise it's our generic view
 * (mnemonic, src/dst regs, branch flavour).  Templates carry no
 * run-time observation, so no regdata / memdata appears here.
 */
void render_templates_only(FILE *out, const cst::Header &h,
                           const std::vector<cst::Template> &templates,
                           const std::unordered_map<uint32_t, size_t> &by_id,
                           const ObjdumpRenderer *od)
{
    DisasmTables dt;
    disasm_tables_build(&dt, h);

    std::fprintf(out, "\n%s:     file format trace template map\n",
                 !h.target_name.empty() ? h.target_name.c_str()
                                        : isa_name(h.isa));
    std::fprintf(out, "; version=0x%08X templates=%zu%s\n\n",
                 h.magic, templates.size(),
                 od ? " objdump_disasm=on" : "");

    /* Index every distinct PC across all templates.  Different
     * templates can cover overlapping PC ranges (a true BB and one
     * of its prefixes both reaching the same later insn), so we
     * dedupe on PC.  The first sighting of each PC wins, which
     * is fine because the bytes are identical anyway. */
    struct Entry {
        uint64_t pc;
        const cst::InsnTemplate *insn;
    };
    std::vector<Entry> entries;
    std::unordered_map<uint64_t, std::string> symbol_at;
    entries.reserve(templates.size() * 4);
    for (const cst::Template &t : templates) {
        if (!t.symbol_name.empty()) {
            symbol_at[t.start_pc] = t.symbol_name;
        }
        for (const cst::InsnTemplate &I : t.insns) {
            entries.push_back({I.pc, &I});
        }
    }
    std::sort(entries.begin(), entries.end(),
              [](const Entry &a, const Entry &b) { return a.pc < b.pc; });
    /* Dedupe consecutive same-PC entries. */
    entries.erase(std::unique(entries.begin(), entries.end(),
                              [](const Entry &a, const Entry &b) {
                                  return a.pc == b.pc;
                              }),
                  entries.end());

    std::string line;
    for (const Entry &e : entries) {
        const cst::InsnTemplate &I = *e.insn;

        /* Symbol header before the first insn of a named function. */
        auto sit = symbol_at.find(I.pc);
        if (sit != symbol_at.end()) {
            line.clear();
            append_hex_padded(&line, I.pc, 16);
            line.append(" <");
            line.append(sit->second);
            line.append(">:\n");
            std::fwrite(line.data(), 1, line.size(), out);
        }

        line.clear();
        /* Address column: 2-space indent, 16-char zero-padded hex,
         * colon, 2-space gap.  Spaces (not tab) so visual alignment
         * is independent of terminal tab width. */
        line.append("  ");
        append_hex_padded(&line, I.pc, 16);
        line.append(":  ");

        /* Bytes column: each byte 2 hex chars + space, padded to a
         * fixed width so the next column lines up regardless of
         * how many bytes a particular insn encoded to. */
        size_t bytes_start = line.size();
        for (size_t b = 0; b < I.raw_bytes.size(); b++) {
            if (b) line.push_back(' ');
            append_byte_hex(&line, I.raw_bytes[b]);
        }
        append_pad_to(&line, bytes_start + 16 * 3);
        line.append("  ");

        /* When --objdump is set, emit Capstone's native disasm in the
         * left column then a `| ` separator before our generic view.
         * Both columns share the bytes column above; Capstone shows
         * what objdump itself would, our view shows the generic IR
         * the trace records.  Without --objdump only the generic
         * view is emitted. */
        if (od) {
            size_t obj_start = line.size();
            std::string obj;
            if (od->render_one(I.pc, I.raw_bytes.data(),
                               I.raw_bytes.size(), &obj)) {
                line.append(obj);
            } else {
                line.append("(undecoded)");
            }
            append_pad_to(&line, obj_start + 40);
            line.append("| ");
        }

        /* Generic-view mnemonic + operands (no regdata in templates-
         * only; templates carry no run-time observation). */
        size_t mnem_start = line.size();
        if (branch_is_none(h, I.branch_type)) {
            const std::string *p = table_lookup(dt.opcode, I.opcode);
            if (p) line.append(*p);
            else line.append("op");
        } else if (const char *m =
                       branch_mnem_from_name(branch_name_lookup(h,
                                                                I.branch_type))) {
            line.append(m);
        } else {
            line.append("br");
        }
        append_pad_to(&line, mnem_start + 8);

        bool first = true;
        if (I.has_imm) {
            if (!first) line.append(", ");
            line.append("$0x");
            append_hex(&line, (uint64_t)I.imm);
            first = false;
        }
        for (size_t k = 0; k < I.src_regs.size(); k++) {
            if (!first) line.append(", ");
            const std::string *p = table_lookup(dt.reg, I.src_regs[k]);
            if (p) line.append(*p);
            else line.append("%r?");
            first = false;
        }
        if (!I.dst_regs.empty()) {
            if (!first) line.append(" -> ");
            for (size_t k = 0; k < I.dst_regs.size(); k++) {
                if (k) line.append(", ");
                const std::string *p = table_lookup(dt.reg, I.dst_regs[k]);
                if (p) line.append(*p);
                else line.append("%r?");
            }
        }

        line.push_back('\n');
        std::fwrite(line.data(), 1, line.size(), out);
    }
}

void render_disasm(FILE *out, const cst::Header &h,
                   const std::vector<cst::Template> &templates,
                   const std::unordered_map<uint32_t, size_t> &by_id,
                   cst::BodyWalker &body,
                   const ObjdumpRenderer *od,
                   bool show_deps)
{
    DisasmTables dt;
    disasm_tables_build(&dt, h);
    DisasmContext ctx{&h, &by_id, &templates, &dt, od, show_deps};

    /* One-shot header summary (everything a grepper might want
     * before the per-insn lines).  Kept parseable: `; KEY=value`
     * pairs.  No leading blank lines so the first `0x` line
     * starts at the file head modulo the comment block. */
    std::fprintf(out, "; cst_decode disassembly\n");
    std::fprintf(out, "; version=0x%08X\n", h.magic);
    std::fprintf(out, "; isa=%s\n",
                 !h.target_name.empty() ? h.target_name.c_str()
                                        : isa_name(h.isa));
    std::fprintf(out, "; command=%s\n", h.command.c_str());
    std::fprintf(out, "; datetime=%s\n", h.datetime.c_str());
    std::fprintf(out, "; flags=%s%s\n",
                 h.has_mem_data() ? "MEM_DATA " : "",
                 h.has_reg_data() ? "REG_DATA"  : "");
    std::fprintf(out, "; start_insn=%llu warmup_insns=%llu total_target_insns=%llu\n",
                 (unsigned long long)h.start_insn,
                 (unsigned long long)h.warmup_insns,
                 (unsigned long long)h.total_target_insns);
    std::fprintf(out, "; templates=%zu\n", templates.size());
    std::fprintf(out, "\n");

    body.walk([&](const cst::DecodedEntry &e) {
        auto it = by_id.find(e.template_id);
        if (it == by_id.end()) {
            std::fprintf(out, "; ----- BB %u (template not found) -----\n",
                         e.template_id);
            return;
        }
        const cst::Template &t = templates[it->second];

        /* Separator line: makes BB boundaries trivial to grep
         * (`grep '^; ----- BB '`) and groups the per-insn lines in
         * the file. */
        std::fprintf(out,
                     "; ----- BB %u entry pc=0x%" PRIx64
                     " insns=%zu seq=%u tid=%u%s -----\n",
                     e.template_id, t.start_pc, t.insns.size(),
                     e.seq_num, e.thread_id,
                     e.thread_switched ? " (thread_switch)" : "");

        /* Fan the DecodedEntry out into per-instruction containers.
         * The builder handles CP-then-WP order, per-insn filtering of
         * dyn_params / reg_snaps / metaflags, and resolves direct
         * branch targets — so this loop only has to inject the
         * per-WP-run separator line. */
        std::vector<cst::Instruction> insns =
            cst::instructions_from_entry(e, h, templates, by_id);

        /* Override the CP-final branch target with the BB's
         * fall_through_pc when no immediate-based target resolved.
         * The fall-through PC carries the next BB for unconditional
         * branches we couldn't statically resolve; mirrors the
         * legacy renderer's behavior. */
        const cst::Template *cp_branch_target = nullptr;
        if (!t.insns.empty() && t.fall_through_pc) {
            auto fit = std::find_if(templates.begin(), templates.end(),
                [&](const cst::Template &x) { return x.start_pc == t.fall_through_pc; });
            if (fit != templates.end()) cp_branch_target = &*fit;
        }

        int  cur_wp_run = -1;     /* -1 = CP, otherwise WPEntry::index */
        std::string wp_status;
        for (size_t i = 0; i < insns.size(); i++) {
            cst::Instruction &insn = insns[i];

            if (!insn.is_wp) {
                /* CP final-insn branch fallback (see comment above). */
                bool is_cp_final =
                    (i + 1 == insns.size() || insns[i + 1].is_wp);
                if (is_cp_final && !insn.branch_target_template) {
                    insn.branch_target_template = cp_branch_target;
                }
                render_disasm_insn(out, ctx, insn, /* wp_status= */ nullptr);
                continue;
            }

            /* New WP run: emit the chain separator, recompute status
             * and the run-final branch fallback (= next WP run's BB
             * start, if any). */
            if ((int)insn.wp_index != cur_wp_run) {
                cur_wp_run = (int)insn.wp_index;
                /* n_insns for this run = count of contiguous insns
                 * sharing the same wp_index. */
                size_t run_end = i;
                while (run_end < insns.size() && insns[run_end].is_wp &&
                       (int)insns[run_end].wp_index == cur_wp_run) {
                    run_end++;
                }
                size_t run_n = run_end - i;

                wp_status.clear();
                if (insn.wp_fault) {
                    if (insn.wp_has_fault_idx) {
                        char b[32];
                        std::snprintf(b, sizeof(b), "FAULT@insn%u",
                                      insn.wp_fault_insn_index);
                        wp_status = b;
                    } else {
                        wp_status = "FAULT";
                    }
                }
                if (insn.wp_translation_unavail) {
                    if (!wp_status.empty()) wp_status += ",";
                    wp_status += "TRANSLATION_UNAVAILABLE";
                }
                std::fprintf(out,
                             "; ..... wp[%u] BB %u n_insns=%zu%s%s -----\n",
                             (unsigned)insn.wp_index, insn.bb_template_id,
                             run_n,
                             wp_status.empty() ? "" : " status=",
                             wp_status.c_str());
            }

            /* WP-run final-insn branch fallback: next WP run's BB
             * start, if any. */
            bool is_run_final =
                (i + 1 == insns.size() ||
                 !insns[i + 1].is_wp ||
                 (int)insns[i + 1].wp_index != cur_wp_run);
            if (is_run_final && !insn.branch_target_template) {
                /* Find the next WP run's first instruction. */
                for (size_t j = i + 1; j < insns.size(); j++) {
                    if (insns[j].is_wp &&
                        (int)insns[j].wp_index != cur_wp_run) {
                        auto nit = by_id.find(insns[j].bb_template_id);
                        if (nit != by_id.end()) {
                            insn.branch_target_template =
                                &templates[nit->second];
                        }
                        break;
                    }
                }
            }

            render_disasm_insn(out, ctx, insn,
                               wp_status.empty() ? nullptr
                                                 : wp_status.c_str());
        }
    });
}

}  /* namespace */

int main(int argc, char **argv)
{
    const char *trace_path = nullptr;
    const char *format = "disasm";
    bool templates_only = false;
    bool show_objdump   = false;
    bool show_deps      = false;
    uint64_t max_entries = 0;            /* 0 = unbounded */

    auto usage = [&]() {
        std::fprintf(stderr,
            "usage: %s [--format=disasm|legacy] [--templates-only] "
            "[--objdump] [--show-deps] [--max N] <trace.cst>\n"
            "  --templates-only  print only the template dictionary,\n"
            "                    skip the body delta-replay\n"
            "  --objdump         emit Capstone-rendered native disasm\n"
            "                    of each insn alongside the generic view\n"
            "  --show-deps       append intra-instruction dep masks as a\n"
            "                    trailing `; deps: d0=[s0,ld0] ...` comment\n"
            "                    when the template carries them\n"
            "  --max N           stop after N body entries (tears the\n"
            "                    decompressor subprocess down early)\n",
            argv[0]);
    };

    for (int i = 1; i < argc; i++) {
        if (std::strncmp(argv[i], "--format=", 9) == 0) {
            format = argv[i] + 9;
        } else if (std::strcmp(argv[i], "--legacy") == 0) {
            format = "legacy";
        } else if (std::strcmp(argv[i], "--templates-only") == 0) {
            templates_only = true;
        } else if (std::strcmp(argv[i], "--objdump") == 0) {
            show_objdump = true;
        } else if (std::strcmp(argv[i], "--show-deps") == 0) {
            show_deps = true;
        } else if (std::strncmp(argv[i], "--max=", 6) == 0) {
            max_entries = std::strtoull(argv[i] + 6, nullptr, 10);
        } else if (std::strcmp(argv[i], "--max") == 0 && i + 1 < argc) {
            max_entries = std::strtoull(argv[++i], nullptr, 10);
        } else if (argv[i][0] == '-') {
            usage();
            return 2;
        } else {
            trace_path = argv[i];
        }
    }
    if (!trace_path) {
        usage();
        return 2;
    }
    if (templates_only && std::strcmp(format, "legacy") == 0) {
        std::fprintf(stderr,
            "cst_decode: --templates-only is incompatible with "
            "--format=legacy\n");
        return 2;
    }

    try {
        /* Outer .cst is a ustar archive holding two members
         * (body.cst[.<codec>] + header.cst[.<codec>]).  cst_file_
         * open walks the tar, dispatches decompression per member
         * suffix, and returns a CstFile carrying the two byte
         * ranges. */
        std::unique_ptr<cst::CstFile> cf = cst::cst_file_open(trace_path);

        std::vector<cst::Template> templates;
        std::unordered_map<uint32_t, size_t> by_id;
        cst::Header h = cst::parse_header(cf->header(), &templates, &by_id);

        /* Optional Capstone-backed objdump column.  Open once per
         * invocation; the per-line render call reuses the handle. */
        ObjdumpRenderer od;
        ObjdumpRenderer *odp = nullptr;
        if (show_objdump) {
            if (od.open(h.isa)) {
                odp = &od;
            } else {
                std::fprintf(stderr,
                    "cst_decode: --objdump unsupported for ISA=%u; "
                    "continuing without the objdump column\n",
                    (unsigned)h.isa);
            }
        }

        if (templates_only) {
            /* No body access at all — no decompressor spawned, no
             * body bytes read off disk.  Cheap even on huge traces. */
            render_templates_only(stdout, h, templates, by_id, odp);
        } else {
            /* Open the body as a streaming Reader.  For compressed
             * bodies this forks the decompressor; uncompressed
             * bodies wrap the mmap directly.  Leading CST_MAGIC is
             * stripped at open(); trailing CST_MAGIC is verified by
             * finalize() (skipped on --max early exit, where the
             * subprocess is torn down by BodyStream's destructor). */
            auto body_stream = cst::body_stream_open(*cf);
            cst::BodyWalker walker(h, templates, by_id,
                                   body_stream->reader());
            walker.set_max_entries(max_entries);
            if (std::strcmp(format, "legacy") == 0) {
                render_legacy(stdout, h, templates, by_id, walker);
            } else if (std::strcmp(format, "disasm") == 0) {
                render_disasm(stdout, h, templates, by_id, walker, odp,
                              show_deps);
            } else {
                std::fprintf(stderr,
                             "cst_decode: unknown format '%s'\n", format);
                return 2;
            }
            /* finalize() reads + verifies the trailing magic.  Skip
             * it if we stopped early — the body wasn't fully drained
             * and the trailing magic isn't reachable. */
            if (max_entries == 0 ||
                walker.stats().cp_entries < max_entries) {
                body_stream->finalize();
            }
        }
    } catch (const std::exception &e) {
        std::fprintf(stderr, "cst_decode: %s\n", e.what());
        return 1;
    }
    return 0;
}
