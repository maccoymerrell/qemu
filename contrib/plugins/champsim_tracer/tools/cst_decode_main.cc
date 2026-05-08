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

/* Is the wide value all-zero?  Python's `if data:` checks truthiness,
 * which is false only when *every* limb is zero. */
bool wide_is_zero(const cst::Wide &w)
{
    for (auto x : w.limb) if (x) return false;
    return true;
}

void format_dyn_legacy(const cst::DynParam &dp, bool show_data,
                       std::string *out)
{
    out->append(dp.type == cst::DynParam::Load ? "load=0x" : "store=0x");
    out->append(fmt_hex_lower(dp.addr));
    if (show_data && !wide_is_zero(dp.data)) {
        out->append(":data=");
        out->append(fmt_wide_hex(dp.data));
    }
}

/* ===== Legacy renderer (byte-identical to champsim_tracer_decode.py) ===== */

void emit_observations_legacy(FILE *out, const std::string &prefix,
                              const cst::Header &h,
                              const std::vector<cst::DynParam> &dyns,
                              const std::vector<cst::RegSnap> &snaps)
{
    if (dyns.empty() && snaps.empty()) {
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
    if (!h.maps.initial_regfile.empty()) {
        std::fprintf(out, "INITIAL_REGFILE %zu\n",
                     h.maps.initial_regfile.size());
        std::vector<uint64_t> keys;
        keys.reserve(h.maps.initial_regfile.size());
        for (auto &kv : h.maps.initial_regfile) keys.push_back(kv.first);
        std::sort(keys.begin(), keys.end());
        for (uint64_t k : keys) {
            const auto &v = h.maps.initial_regfile.at(k);
            std::fprintf(out, "  %s %s\n", fmt_reg(h, k).c_str(),
                         fmt_bytes_hex(v).c_str());
        }
    }
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
            if (I.branch_type != BRANCH_NONE) {
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
    body.walk([&](const cst::DecodedEntry &e) {
        const char *sw = e.thread_switched ? " switch=1" : "";
        std::fprintf(out, "ENTRY %04u thread=%u%s template=BB%u\n",
                     e.seq_num, e.thread_id, sw, e.template_id);
        std::fprintf(out, "  cp:\n");
        emit_observations_legacy(out, "    ", h, e.dyn_params, e.reg_snaps);
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
            emit_observations_legacy(out, "    ", h, wp.dyn_params, wp.reg_snaps);
        }
        std::fprintf(out, "\n");
    });

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
};

/* Render one instruction line using a DecodedEntry's per-(insn_index)
 * dyn-params and reg-snaps as the metadata suffix. */
void render_disasm_insn(FILE *out, const DisasmContext &ctx,
                        const cst::Template &tmpl,
                        size_t insn_idx,
                        const std::vector<cst::DynParam> &dyns,
                        const std::vector<cst::RegSnap> &snaps,
                        uint32_t thread_id, uint32_t bb_id,
                        bool is_wp,
                        const char *wp_status)
{
    const cst::InsnTemplate &I = tmpl.insns[insn_idx];

    std::string line;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "0x%012" PRIx64, I.pc);
    line += buf;

    /* Symbol+offset.  Templates carry a symbol_name for the BB
     * entry; offset = pc - start_pc. */
    if (!tmpl.symbol_name.empty()) {
        std::snprintf(buf, sizeof(buf), " <%s+0x%" PRIx64 ">",
                      tmpl.symbol_name.c_str(), I.pc - tmpl.start_pc);
        line += buf;
    }
    line += ": ";

    /* Opcode mnemonic (generic), padded for visual alignment. */
    std::string mnem = enum_or(ctx.h->maps.opcode, I.opcode, "OP");
    line += mnem;
    while (line.size() < 32 + 28) line += ' ';
    /* Fall through with a single space if we exceeded the column. */
    if (line.back() != ' ') line += "  ";

    /* Operand encoding: dst regs first, then src regs, then imm.  We
     * separate dst from src with a `<-` marker so a reader can tell
     * read-from-write at a glance.  Also suppress if both are empty
     * (e.g. NOP). */
    bool wrote_op = false;
    if (!I.dst_regs.empty() || !I.src_regs.empty()) {
        wrote_op = true;
        for (size_t k = 0; k < I.dst_regs.size(); k++) {
            if (k) line += ",";
            line += fmt_reg(*ctx.h, I.dst_regs[k]);
        }
        if (!I.dst_regs.empty() && !I.src_regs.empty()) line += " <- ";
        for (size_t k = 0; k < I.src_regs.size(); k++) {
            if (k) line += ",";
            line += fmt_reg(*ctx.h, I.src_regs[k]);
        }
    }
    if (I.has_imm) {
        if (wrote_op) line += ",";
        std::snprintf(buf, sizeof(buf), "IMM(0x%" PRIx64 ")",
                      (uint64_t)I.imm);
        line += buf;
        wrote_op = true;
    }

    /* Metadata: thread, bb, wp marker, branch type, memops, dst writes. */
    line += "  ; tid=";
    line += std::to_string(thread_id);
    line += " bb=";
    line += std::to_string(bb_id);
    if (is_wp) line += " wp";
    if (wp_status && *wp_status) {
        line += " ";
        line += wp_status;
    }
    if (I.branch_type != BRANCH_NONE) {
        line += " br=";
        line += enum_or(ctx.h->maps.branch_type, I.branch_type, "BR");
        if (I.branch_conditional) line += " cond";
    }
    if (I.sync_hint != 0) {
        line += " sync=";
        line += enum_or(ctx.h->maps.sync_hint, I.sync_hint, "SYNC");
    }
    /* Per-insn memops. */
    for (auto &dp : dyns) {
        if (dp.insn_index != (uint32_t)insn_idx) continue;
        line += dp.type == cst::DynParam::Load ? " ld@0x" : " st@0x";
        line += fmt_hex_lower(dp.addr);
        if (ctx.h->has_mem_data() && !wide_is_zero(dp.data)) {
            line += ":";
            line += fmt_wide_hex(dp.data);
        }
    }
    /* Per-insn dst register writes (post-execution snapshot). */
    for (auto &r : snaps) {
        if (r.insn_index != (uint32_t)insn_idx) continue;
        line += " ";
        line += fmt_reg(*ctx.h, r.reg_id);
        line += "=";
        line += fmt_wide_hex(r.value);
    }

    std::fprintf(out, "%s\n", line.c_str());
}

void render_disasm(FILE *out, const cst::Header &h,
                   const std::vector<cst::Template> &templates,
                   const std::unordered_map<uint32_t, size_t> &by_id,
                   cst::BodyWalker &body)
{
    DisasmContext ctx{&h, &by_id, &templates};

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
    if (!h.maps.initial_regfile.empty()) {
        std::fprintf(out, "; initial_regfile:\n");
        std::vector<uint64_t> keys;
        keys.reserve(h.maps.initial_regfile.size());
        for (auto &kv : h.maps.initial_regfile) keys.push_back(kv.first);
        std::sort(keys.begin(), keys.end());
        for (uint64_t k : keys) {
            std::fprintf(out, ";   %s=%s\n",
                         fmt_reg(h, k).c_str(),
                         fmt_bytes_hex(h.maps.initial_regfile.at(k)).c_str());
        }
    }
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

        for (size_t i = 0; i < t.insns.size(); i++) {
            render_disasm_insn(out, ctx, t, i, e.dyn_params, e.reg_snaps,
                               e.thread_id, e.template_id,
                               /* is_wp= */ false,
                               /* wp_status= */ nullptr);
        }
        for (auto &wp : e.wp_entries) {
            auto wit = by_id.find(wp.template_id);
            if (wit == by_id.end()) continue;
            const cst::Template &wt = templates[wit->second];
            std::string status;
            if (wp.fault) {
                if (wp.has_fault_idx) {
                    char b[32];
                    std::snprintf(b, sizeof(b), "FAULT@insn%u",
                                  wp.fault_insn_index);
                    status = b;
                } else {
                    status = "FAULT";
                }
            }
            if (wp.translation_unavailable) {
                if (!status.empty()) status += ",";
                status += "TRANSLATION_UNAVAILABLE";
            }
            std::fprintf(out,
                         "; ..... wp[%u] BB %u n_insns=%u%s%s -----\n",
                         wp.index, wp.template_id, wp.n_insns,
                         status.empty() ? "" : " status=",
                         status.c_str());
            uint32_t wp_n = std::min<uint32_t>(wp.n_insns,
                                               (uint32_t)wt.insns.size());
            for (size_t i = 0; i < wp_n; i++) {
                render_disasm_insn(out, ctx, wt, i, wp.dyn_params, wp.reg_snaps,
                                   e.thread_id, wp.template_id,
                                   /* is_wp= */ true,
                                   status.empty() ? nullptr : status.c_str());
            }
        }
    });
}

}  /* namespace */

int main(int argc, char **argv)
{
    const char *trace_path = nullptr;
    const char *format = "disasm";

    for (int i = 1; i < argc; i++) {
        if (std::strncmp(argv[i], "--format=", 9) == 0) {
            format = argv[i] + 9;
        } else if (std::strcmp(argv[i], "--legacy") == 0) {
            format = "legacy";
        } else if (argv[i][0] == '-') {
            std::fprintf(stderr,
                         "usage: %s [--format=disasm|legacy] <trace.cst>\n",
                         argv[0]);
            return 2;
        } else {
            trace_path = argv[i];
        }
    }
    if (!trace_path) {
        std::fprintf(stderr,
                     "usage: %s [--format=disasm|legacy] <trace.cst>\n",
                     argv[0]);
        return 2;
    }

    int fd = ::open(trace_path, O_RDONLY);
    if (fd < 0) {
        std::fprintf(stderr, "cst_decode: cannot open %s: %s\n",
                     trace_path, std::strerror(errno));
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        std::fprintf(stderr, "cst_decode: empty/unstattable trace\n");
        ::close(fd);
        return 1;
    }
    void *map = mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    ::close(fd);
    if (map == MAP_FAILED) {
        std::fprintf(stderr, "cst_decode: mmap failed: %s\n",
                     std::strerror(errno));
        return 1;
    }
    const uint8_t *m = (const uint8_t *)map;
    size_t size = (size_t)st.st_size;

    try {
        cst::Trailer t = cst::parse_trailer(m, size);
        cst::Header h = cst::parse_header(m, size, t.body_off, t.magic);
        std::unordered_map<uint32_t, size_t> by_id;
        std::vector<cst::Template> templates =
            cst::parse_templates(m, size, t.templates_off,
                                  t.templates_count, &by_id);
        cst::BodyWalker walker(h, templates, by_id, m, size,
                               t.body_off, t.body_off + t.body_byte_count);

        if (std::strcmp(format, "legacy") == 0) {
            render_legacy(stdout, h, templates, by_id, walker);
        } else if (std::strcmp(format, "disasm") == 0) {
            render_disasm(stdout, h, templates, by_id, walker);
        } else {
            std::fprintf(stderr, "cst_decode: unknown format '%s'\n", format);
            munmap(map, size);
            return 2;
        }
    } catch (const std::exception &e) {
        std::fprintf(stderr, "cst_decode: %s\n", e.what());
        munmap(map, size);
        return 1;
    }

    munmap(map, size);
    return 0;
}
