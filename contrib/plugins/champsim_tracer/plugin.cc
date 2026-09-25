/*
 * ChampSim Tracer - QEMU TCG plugin writing .cst traces (docs/format.rst).
 *
 * Copyright (C) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * It installs, takes its two options, and publishes a structurally
 * complete segment on every ruled exit route.  In user mode it observes
 * execution and writes the correct-path body: true basic blocks as
 * pc/size templates and one entry per block run (blocks.h), with the
 * memory accesses the memory callbacks state (address, size, direction,
 * value), the registers QEMU states each instruction may read and write,
 * and after each block whose transfer has a nameable alternative a
 * wrong-path chain of the same facts (excursion()).  It claims nothing else
 * about an instruction; system mode keeps an empty body.
 *
 * Options:
 *   outfile=<path>   the trace is <path>.cst (required)
 *   compress=<cmd>   a filter command each member is streamed through,
 *                    e.g. compress="zstd -T0 -3 -q -c"
 *   wp=0|1           wrong-path chains (default 1)
 *   wpdepth=<n>      wrong-path instructions per chain (default 64)
 */
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <glib.h>            /* ahead of the C block: glib is C++-aware */
extern "C" {
#include "qemu/qemu-plugin.h"   /* the plugin ABI is C; this is its door */
}

#include "blocks.h"
#include "container.h"
#include "wire.h"

/* C linkage for both exports comes from their declarations above. */
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

namespace {

/* Why excursions ended early or were not taken (counted, never guessed). */
struct WpStats {
    uint64_t launched, first_unavail, unavail, exec_faults, bail_unwind,
             bail_slot, bail_overflow, bail_noseal, bail_stall, no_state;
};

struct Session {
    /* recursive: a wrong-path exec_tb fires callbacks on the same thread */
    std::recursive_mutex lock;
    bool published = false;     /* one segment per run, at most */
    bool system = false;
    std::string path;           /* <outfile>.cst */
    std::string scratch_dir;
    std::string compress;
    cst::HeaderFacts facts;
    cst::BlockAssembler blocks;
    std::vector<std::unique_ptr<cst::TbShape>> tbs;  /* live until exit */
    std::mutex tbs_lock;        /* taken under mmap_lock: guards tbs only */
    qemu_plugin_u64 started;    /* per vCPU: insns begun in the current TB */
    uint64_t no_value = 0;      /* accesses whose value the API withheld */
    bool wp = true;
    size_t wpdepth = 64;
    uint32_t wp_tid = 0;        /* the WP strand in flight, 0 when none */
    bool fired = false;         /* a WP TB began during this exec_tb */
    /* per indirect transfer: the latest CP target and the one before it */
    std::map<cst::InsnId, std::pair<uint64_t, uint64_t>> targets;
    /* per vCPU: a TB whose transfer's block is still open (a MIPS slot next) */
    std::map<unsigned int, const cst::TbShape *> xfer;
    WpStats wps{};
    uint64_t overflow = 0;      /* register slots past the capture cap */
};

/* Immortal: exit callbacks may run while static destructors do. */
Session &session()
{
    static Session *s = new Session;
    return *s;
}

void say(const std::string &msg)
{
    std::fprintf(stderr, "champsim_tracer: %s\n", msg.c_str());
}

/* The header's command string: the emulator's own command line. */
std::string own_command_line()
{
    std::ifstream f("/proc/self/cmdline", std::ios::binary);
    std::string raw((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
    while (!raw.empty() && raw.back() == '\0') {
        raw.pop_back();
    }
    for (char &c : raw) {
        c = c ? c : ' ';
    }
    return raw;
}

std::string local_datetime()
{
    char buf[32];
    std::time_t now = std::time(nullptr);
    std::tm tm;
    localtime_r(&now, &tm);
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

/*
 * The should-be-static tripwire's report: a count on the side log and, at
 * <outfile>.nonstatic_memops.tsv, each instruction whose (loads/stores)
 * count varied across executions -- pc, bytes, whether the engine's fan-out
 * account (expected to vary) named it, and the histograms per path.
 */
void memop_tripwire(const cst::MemopCensus &census, const std::string &path)
{
    size_t bugs = 0, fanout = 0;
    std::ofstream f(path.substr(0, path.size() - 4) + ".nonstatic_memops.tsv");
    f << "pc\tbytes\tfanout\tcp\twp\twp_fault_cut\n";
    for (const auto &r : census.rows) {
        std::map<uint64_t, uint64_t> seen(r.second.hist[0]);
        seen.insert(r.second.hist[1].begin(), r.second.hist[1].end());
        if (seen.size() < 2) {
            continue;
        }
        const cst::WireInsn &i = *r.second.insn;
        (i.fanout ? fanout : bugs)++;
        char hex[40] = "";
        for (unsigned k = 0; k < i.size; k++) {
            std::snprintf(hex + 2 * k, 3, "%02x", i.bytes[k]);
        }
        f << std::hex << "0x" << i.pc << std::dec << '\t' << hex << '\t'
          << i.fanout;
        for (const auto &h : r.second.hist) {
            f << '\t';
            for (const auto &c : h) {   /* loads/stores:executions */
                f << (c.first >> 32) << '/' << uint32_t(c.first) << ':'
                  << c.second << ' ';
            }
        }
        f << '\n';
    }
    say("nonstatic_memop_insns=" + std::to_string(bugs) + " (fan-out " +
        std::to_string(fanout) + " excluded, of " +
        std::to_string(census.rows.size()) + " executed insns)");
}

/*
 * The wire's GenericRegId (format.rst 5.4) for register @r of TraceISA
 * @isa: this plugin's vocabulary over QEMU's statement of identity.  The
 * stack, frame and link registers take the common ids; x86 GPRs follow the
 * wire's A C D B SI DI R8.. numbering, segments its cs ds es fs gs ss.
 */
uint8_t reg_id(int isa, const qemu_plugin_insn_reg &r)
{
    static const std::map<std::string, uint8_t> ctl = {
        { "fctrl", cst::kRegFcsr }, { "fstat", cst::kRegFcsr },
        { "ftag", cst::kRegFcsr }, { "mxcsr", cst::kRegFcsr },
        { "fpsr", cst::kRegFcsr }, { "fpcr", cst::kRegFcsr },
        { "FPSR", cst::kRegFcsr }, { "FPCR", cst::kRegFcsr },
        { "frm", cst::kRegFcsr }, { "fcr31", cst::kRegFcsr },
        { "vl", cst::kRegVctrl }, { "vtype", cst::kRegVctrl },
        { "ffr", cst::kRegVctrl }, { "vstart", cst::kRegVstart },
        { "vxrm", cst::kRegVcsr }, { "vxsat", cst::kRegVcsr },
        { "msacsr", cst::kRegVcsr }, { "dspctrl", cst::kRegDspctrl },
        { "userlocal", cst::kRegTls }, { "TPIDR_EL0", cst::kRegTls },
        { "TPIDRRO_EL0", cst::kRegTls }, { "za", cst::kRegMatrix },
    };
    static const int sp[5] = { 0, 4, 31, 2, 29 }, fp[5] = { 0, 5, 29, 8, 30 },
                     lr[5] = { 0, -1, 30, 1, 31 };
    int i = r.index;
    switch (r.reg_class) {
    case QEMU_PLUGIN_REG_GPR:
        return i == sp[isa] ? cst::kRegSp : i == fp[isa] ? cst::kRegFp :
               i == lr[isa] ? cst::kRegLr :
               cst::kRegGpr + (isa == 1 && i > 5 ? i - 2 : i);
    case QEMU_PLUGIN_REG_FP:            return cst::kRegFpr + i;
    case QEMU_PLUGIN_REG_VECTOR:        return cst::kRegVec + i;
    case QEMU_PLUGIN_REG_PREDICATE:     return cst::kRegPred + i;
    case QEMU_PLUGIN_REG_FLAGS:         return cst::kRegFlags;
    case QEMU_PLUGIN_REG_SEGMENT:       return cst::kRegSeg + "\2\0\5\1\3\4"[i];
    case QEMU_PLUGIN_REG_ACCUMULATOR:
        return i < 4 ? cst::kRegAcc + i : cst::kRegAccHi + i - 4;
    case QEMU_PLUGIN_REG_ZERO:          return cst::kRegZero;
    }
    auto c = ctl.find(r.name);
    return c != ctl.end() ? c->second : !std::strncmp(r.name, "cr", 2) ?
           cst::kRegCtrl : !std::strncmp(r.name, "bnd", 3) ?
           cst::kRegBound + (r.name[3] - '0') : cst::kRegSys;
}

/*
 * The instruction's register statement on the wire: slots in first-
 * appearance order, registers QEMU names apart that the wire does not
 * (x87 control/status/tag words, vl/vtype) merged into one slot.  A MIPS
 * vector register absorbs its FP half: $fN is the low half of wN.
 */
cst::Regs capture(Session &s, struct qemu_plugin_insn *insn)
{
    constexpr size_t kMax = 64;     /* per direction; more is counted */
    size_t n;
    cst::Regs out;
    const qemu_plugin_insn_reg *r = qemu_plugin_insn_reg_list(insn, &n,
                                                              &out.opaque);
    struct Slot { uint8_t id, access; };
    std::vector<Slot> l;
    for (size_t k = 0; k < n; k++) {
        uint8_t id = reg_id(s.facts.isa, r[k]);
        if (s.facts.isa == 4 && r[k].reg_class == QEMU_PLUGIN_REG_FP) {
            for (size_t j = 0; j < n; j++) {
                id = r[j].reg_class == QEMU_PLUGIN_REG_VECTOR &&
                     r[j].index == r[k].index ? cst::kRegVec + r[k].index : id;
            }
        }
        auto it = std::find_if(l.begin(), l.end(), [id](const Slot &x) {
            return x.id == id; });
        if (it == l.end()) {
            l.push_back({ id, r[k].access });
        } else {
            it->access |= r[k].access;
        }
    }
    for (const Slot &x : l) {
        bool rd = x.access & QEMU_PLUGIN_REG_READ;
        bool wr = x.access & QEMU_PLUGIN_REG_WRITE;
        s.overflow += (rd && out.src.size() == kMax) ||
                      (wr && out.dst.size() == kMax);
        if (rd && out.src.size() < kMax) {
            out.src.push_back(x.id);
        }
        if (wr && out.dst.size() < kMax) {
            out.dst.push_back(x.id);
        }
    }
    return out;
}

/*
 * The register statement's report: encodings executed, those with a
 * stated list, the ones it could not fully state by the first effect it
 * names (<outfile>.reg_opaque.tsv), and every retranslation that stated a
 * different list (<outfile>.reg_variance.tsv), classed: a vector, FP or
 * control context the translation depends on (RVV vtype, SVE VL, MIPS FR)
 * is expected; any other is a defect.
 */
void reg_report(Session &s, const std::string &path)
{
    std::string base = path.substr(0, path.size() - 4);
    std::map<std::string, size_t> opaque;
    size_t executed = s.blocks.regs.size(), stated = 0, odd = 0, full = 0;
    for (const cst::Regs &r : s.blocks.regs) {
        stated += !r.src.empty() || !r.dst.empty();
        full += !r.opaque;
        if (r.opaque) {
            opaque[r.opaque]++;
        }
    }
    std::ofstream o(base + ".reg_opaque.tsv"), v(base + ".reg_variance.tsv");
    o << "class\tencodings\n(complete)\t" << full << '\n';
    for (const auto &c : opaque) {
        o << c.first << '\t' << c.second << '\n';
    }
    v << "pc\tbytes\tclass\tfirst_src/dst\tthen_src/dst\n";
    auto list = [](const cst::Regs &r) {
        std::string t;
        for (const auto *l : { &r.src, &r.dst }) {
            for (uint8_t x : *l) {
                t += std::to_string(x) + ',';
            }
            t += '/';
        }
        return t;
    };
    for (const auto &e : s.blocks.variance) {
        const cst::Regs &a = s.blocks.regs[e.first], &b = e.second;
        std::vector<uint8_t> x, y, d;
        for (const auto *l : { &a.src, &a.dst }) x.insert(x.end(), l->begin(), l->end());
        for (const auto *l : { &b.src, &b.dst }) y.insert(y.end(), l->begin(), l->end());
        std::sort(x.begin(), x.end());
        std::sort(y.begin(), y.end());
        std::set_symmetric_difference(x.begin(), x.end(), y.begin(), y.end(),
                                      std::back_inserter(d));
        bool ctx = !d.empty() && std::all_of(d.begin(), d.end(), [](uint8_t i) {
            return (i >= cst::kRegFpr && i < cst::kRegSeg) || i == cst::kRegVctrl ||
                   i == cst::kRegVstart || i == cst::kRegFcsr; });
        odd += !ctx;
        const cst::Insn &i = s.blocks.insn(e.first);
        char hex[40] = "";
        for (unsigned k = 0; k < i.size; k++) {
            std::snprintf(hex + 2 * k, 3, "%02x", i.bytes[k]);
        }
        v << std::hex << "0x" << i.pc << std::dec << '\t' << hex << '\t'
          << (ctx ? "vector/fp context" : "UNEXPLAINED") << '\t' << list(a)
          << '\t' << list(b) << '\n';
    }
    say("regs: encodings=" + std::to_string(executed) + " stated=" +
        std::to_string(stated) + " reg_stmt_opaque=" +
        std::to_string(executed - full) + " (" +
        std::to_string(opaque.size()) + " classes) reg_list_overflow=" +
        std::to_string(s.overflow) + " reg_list_variance=" +
        std::to_string(s.blocks.variance.size()) + " (unexplained " +
        std::to_string(odd) + ")");
}

/*
 * Close the segment.  @root_phys is the asid-0 label: the live
 * address-space value, read by the caller where it is readable.
 * Idempotent: whichever ruled route arrives first publishes.
 */
void publish(uint64_t root_phys, const char *route)
{
    Session &s = session();
    std::lock_guard<std::recursive_mutex> guard(s.lock);
    if (s.published) {
        return;
    }
    s.published = true;
    s.blocks.finish_all([&s](uint32_t tid) {
        return qemu_plugin_u64_get(s.started, tid);
    });
    std::vector<cst::WireTemplate> templates;
    std::vector<cst::WireEntry> entries, chains;
    s.blocks.recut(templates, entries, chains, s.wpdepth);
    /* The body goes first, so the header can be finalised after it. */
    size_t slots;
    cst::MemopCensus census;
    cst::Member body = { "body.cst", cst::body_member(root_phys, templates,
                         entries, chains, s.blocks.memops(), slots, s.wp,
                         census).data() };
    memop_tripwire(census, s.path);
    reg_report(s, s.path);
    const auto &st = s.blocks.stats;
    say("entries=" + std::to_string(entries.size()) + " templates=" +
        std::to_string(templates.size()) + " early_exits=" +
        std::to_string(st.early_exits) + " late_block_ends=" +
        std::to_string(st.late_ends) + "; revised " +
        std::to_string(st.revised_shapes) + " shapes, " +
        std::to_string(st.recut_entries) + " entries re-cut; memops=" +
        std::to_string(s.blocks.memops().size()) + " max_slots=" +
        std::to_string(slots) + " no_value=" + std::to_string(s.no_value) +
        " uneven_fanout=" + std::to_string(st.uneven_fanout));
    const WpStats &w = s.wps;
    if (s.wp && !s.system) {
        say("wp: excursions=" + std::to_string(w.launched) + " blocks=" +
            std::to_string(chains.size()) + " first_unavail=" +
            std::to_string(w.first_unavail) + " unavail=" +
            std::to_string(w.unavail) + " exec_faults=" +
            std::to_string(w.exec_faults) + " bails unwind/slot/overflow/noseal/stall=" +
            std::to_string(w.bail_unwind) + "/" + std::to_string(w.bail_slot) +
            "/" + std::to_string(w.bail_overflow) + "/" +
            std::to_string(w.bail_noseal) + "/" + std::to_string(w.bail_stall) +
            " no_state=" +
            std::to_string(w.no_state) + " reserve_exhausted=" +
            std::to_string(qemu_plugin_spec_reserve_exhausted()) +
            " syscalls_blocked=" +
            std::to_string(qemu_plugin_spec_syscall_blocked_count()));
    }
    std::vector<cst::Member> members = {
        body, { "header.cst", cst::header_member(s.facts, templates, slots,
                                                 s.wp).data() },
    };
    std::string err;
    bool ok = true;
    for (cst::Member &m : members) {
        ok = ok && (s.compress.empty() ||
                    cst::filter_member(m, s.compress, s.scratch_dir, err));
    }
    ok = ok && cst::publish_archive(s.path, members, err);
    say(ok ? "published " + s.path + " at " + route :
             "no trace published: " + err);
}

/*
 * No trace is published when no vCPU can attest the opening address
 * space: a label the tracer did not read is a claim it cannot make.
 */
void refuse_unattested(const char *route)
{
    Session &s = session();
    std::lock_guard<std::recursive_mutex> guard(s.lock);
    if (!s.published) {
        s.published = true;
        say(std::string(route) + " with no vCPU to read the address space "
            "from; no trace published");
    }
}

/* System mode: the machine is going down, on a vCPU when one exists. */
void on_machine_window(const char *route, int vcpu_index)
{
    if (vcpu_index == QEMU_PLUGIN_VCPU_NONE) {
        refuse_unattested(route);
        return;
    }
    publish(qemu_plugin_get_addr_space_id(), route);
}

void on_shutdown(qemu_plugin_id_t, int vcpu_index, bool)
{
    on_machine_window("machine shutdown", vcpu_index);
}

/* A reset ends the recorded world; the segment closes there. */
void on_reset(qemu_plugin_id_t, int vcpu_index, bool)
{
    on_machine_window("machine reset", vcpu_index);
}

void on_exit(qemu_plugin_id_t, void *)
{
    if (session().system) {
        /* After qemu_cleanup(): no vCPU is left to read. */
        refuse_unattested("exit");
    } else {
        /* One address space in *-linux-user; the API defines it as 0. */
        publish(0, "exit");
    }
}

/*
 * The wrong path from @alt, after the CP entry @vcpu just sealed: the
 * engine contract of qemu-plugin.h (tests/tcg/plugins/wp-assert.c drives
 * the same sequence).  One exec_tb per block; each retires into the WP
 * strand at the pc it left for.  A false return with no TB begun is a
 * front-end fault and ends the walk; with one begun, the instruction the
 * scoreboard says began last raised: it is marked, skipped, and the walk
 * goes on at its fall-through (format.rst 4.4).  The walk ends once
 * wpdepth instructions are attributed and the block in flight has sealed.
 */
void excursion(Session &s, unsigned int vcpu, uint64_t alt)
{
    uint32_t wt = vcpu | cst::BlockAssembler::kWp;
    struct qemu_plugin_cpu_state *saved = qemu_plugin_cpu_state_save();
    if (!saved || !s.blocks.wp_begin(wt, vcpu)) {
        s.wps.no_state++;
        qemu_plugin_cpu_state_free(saved);
        return;
    }
    s.wps.launched++;
    uint64_t sb = qemu_plugin_u64_get(s.started, vcpu);
    qemu_plugin_spec_mode_begin(saved);
    qemu_plugin_set_pc(alt);
    s.wp_tid = wt;
    bool unavail = false;
    size_t sealed = ~size_t(0), extra = 0;
    for (;;) {
        s.fired = false;
        bool ok = qemu_plugin_exec_tb();
        uint64_t pc = qemu_plugin_get_pc();
        size_t ran = qemu_plugin_u64_get(s.started, vcpu);
        if (ok && (!s.fired || !ran)) {
            s.wps.bail_stall++;     /* no instruction retired: a kick, not a path */
            break;
        }
        if (ok) {
            cst::BulkRun bulk{ qemu_plugin_rep_pc(), qemu_plugin_rep_iterations(),
                               qemu_plugin_rep_reenter() };
            s.blocks.retire(wt, ran, &bulk, pc);
        } else {
            qemu_plugin_spec_clear_exception();
            const cst::TbShape *tb = s.blocks.pending(wt);
            if (!s.fired || !tb) {
                unavail = true;     /* the fetch itself failed */
                break;
            }
            /* the engine leaves the pc at the raiser, or past it (a call) */
            const cst::Insn *f = ran && ran <= tb->insns.size() ?
                                 &s.blocks.insn(tb->insns[ran - 1]) : nullptr;
            if (!f || (pc != f->pc && pc != f->pc + f->size)) {
                s.wps.bail_unwind++;
                break;
            }
            if (tb->transfer >= 0 && int(ran) - 1 > tb->transfer) {
                s.wps.bail_slot++;  /* a delay slot: no fall-through of its own */
                break;
            }
            s.blocks.retire(wt, ran, nullptr, f->pc + f->size, true);
            qemu_plugin_set_pc(f->pc + f->size);
            s.wps.exec_faults++;
        }
        if (qemu_plugin_spec_store_overflowed()) {
            s.wps.bail_overflow++;
            break;
        }
        if (sealed == ~size_t(0) && s.blocks.wp_insns(wt) >= s.wpdepth) {
            sealed = s.blocks.wp_blocks();  /* the budget is spent ... */
        }
        if (sealed != ~size_t(0) && (s.blocks.open_empty(wt) ||
                                     s.blocks.wp_blocks() > sealed)) {
            break;                          /* ... and the block in flight done */
        }
        if (sealed != ~size_t(0) && ++extra > 16384) {    /* straight-line: finite */
            s.wps.bail_noseal++;
            break;
        }
    }
    s.wps.unavail += unavail;
    s.wps.first_unavail += unavail && !s.blocks.wp_blocks() &&
                           s.blocks.open_empty(wt);
    s.blocks.wp_end(wt, unavail);
    s.wp_tid = 0;
    qemu_plugin_spec_mode_end();
    qemu_plugin_cpu_state_restore(saved);
    qemu_plugin_cpu_state_free(saved);
    qemu_plugin_u64_set(s.started, vcpu, sb);
}

/*
 * The block ending at @ft sealed on the lowered transfer of TB @x: launch
 * where it offers an alternative the plugin can name (INC5.md) -- the
 * fall-through of a taken one; the translator's static target of one that
 * fell through; for a run-time target, the latest earlier CP target other
 * than where it went.
 */
void launch(Session &s, unsigned int vcpu, const cst::TbShape *x, uint64_t ft,
            uint64_t next)
{
    uint64_t other = 0;
    if (x->indirect) {
        auto &h = s.targets[x->insns[x->transfer]];
        other = h.first != next ? h.first : h.second;
        if (h.first != next) {
            h = { next, h.first };
        }
    }
    uint64_t alt = next != ft ? (other ? other : ft) :
                   x->indirect ? other : x->target;
    if (alt && alt != next) {
        excursion(s, vcpu, alt);
    }
}

/* A TB begins: the previous one of this vCPU is over. */
void on_tb_exec(unsigned int vcpu, void *udata)
{
    Session &s = session();
    auto *tb = static_cast<cst::TbShape *>(udata);
    std::lock_guard<std::recursive_mutex> guard(s.lock);
    if (s.published) {
        return;
    }
    s.blocks.absorb(*tb);
    if (s.wp_tid) {             /* a wrong-path TB: excursion() retires it */
        s.blocks.begin(s.wp_tid, tb);
        s.fired = true;
        return;
    }
    cst::BulkRun bulk{ qemu_plugin_rep_pc(), qemu_plugin_rep_iterations(),
                       qemu_plugin_rep_reenter() };
    const cst::TbShape *prev = s.blocks.pending(vcpu);
    size_t ran = qemu_plugin_u64_get(s.started, vcpu);
    uint64_t next = s.blocks.insn(tb->insns.front()).pc;
    s.blocks.retire(vcpu, ran, &bulk, next);
    /* the TB whose transfer this retire completes: its own, or its slot's */
    const cst::TbShape *x = nullptr;
    if (prev && ran == prev->insns.size()) {
        x = prev->transfer >= 0 ? prev : s.xfer[vcpu];
    }
    s.xfer[vcpu] = x == prev && !s.blocks.open_empty(vcpu) ? x : nullptr;
    const cst::Insn *l = prev ? &s.blocks.insn(prev->insns.back()) : nullptr;
    if (s.wp && x && s.blocks.open_empty(vcpu) && bulk.pc != l->pc) {
        launch(s, vcpu, x, l->pc + l->size, next);
    }
    s.blocks.begin(vcpu, tb);
}

/* An access by the instruction at TB index @udata (sections 5.2, 5.3). */
void on_mem(unsigned int vcpu, qemu_plugin_meminfo_t info, uint64_t vaddr,
            void *udata)
{
    Session &s = session();
    cst::Memop m{};
    m.addr = vaddr;
    m.pos = uint32_t(reinterpret_cast<uintptr_t>(udata));
    m.size = uint8_t(1u << qemu_plugin_mem_size_shift(info));
    m.store = qemu_plugin_mem_is_store(info);
    m.fault = qemu_plugin_spec_mem_faulted_take();  /* false off the wrong path */
    qemu_plugin_mem_value v = qemu_plugin_mem_get_value(info);
    m.data_ok = v.type != QEMU_PLUGIN_MEM_VALUE_INVALID;  /* wider than 128 */
    m.hi = v.type == QEMU_PLUGIN_MEM_VALUE_U128 ? v.data.u128.high : 0;
    switch (v.type) {
    case QEMU_PLUGIN_MEM_VALUE_U8:   m.lo = v.data.u8; break;
    case QEMU_PLUGIN_MEM_VALUE_U16:  m.lo = v.data.u16; break;
    case QEMU_PLUGIN_MEM_VALUE_U32:  m.lo = v.data.u32; break;
    case QEMU_PLUGIN_MEM_VALUE_U64:  m.lo = v.data.u64; break;
    case QEMU_PLUGIN_MEM_VALUE_U128: m.lo = v.data.u128.low; break;
    default:                         break;
    }
    std::lock_guard<std::recursive_mutex> guard(s.lock);
    if (!s.published) {
        s.no_value += !m.data_ok;
        s.blocks.memop(s.wp_tid ? s.wp_tid : vcpu, m);
    }
}

/* A syscall ends the block of the instruction that raised it. */
void on_syscall(qemu_plugin_id_t, unsigned int vcpu, int64_t, uint64_t,
                uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                uint64_t)
{
    Session &s = session();
    std::lock_guard<std::recursive_mutex> guard(s.lock);
    if (s.wp_tid) {
        return;     /* never on the wrong path; counted by the engine if so */
    }
    const cst::TbShape *tb = s.blocks.pending(vcpu);
    uint64_t ran = qemu_plugin_u64_get(s.started, vcpu);
    if (tb && ran >= 1 && ran <= tb->insns.size()) {
        s.blocks.ends_block(tb->insns[ran - 1]);
    }
}

/* A guest thread is gone; its index may be handed to a later thread. */
void on_vcpu_exit(qemu_plugin_id_t, unsigned int vcpu)
{
    Session &s = session();
    std::lock_guard<std::recursive_mutex> guard(s.lock);
    if (!s.published) {
        s.blocks.finish(vcpu, qemu_plugin_u64_get(s.started, vcpu));
    }
}

void on_tb_trans(qemu_plugin_id_t, struct qemu_plugin_tb *tb)
{
    Session &s = session();
    auto shape = std::make_unique<cst::TbShape>();
    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        cst::Insn in{};
        in.pc = qemu_plugin_insn_vaddr(insn);
        in.size = uint8_t(qemu_plugin_insn_data(insn, in.bytes, sizeof(in.bytes)));
        shape->raw.push_back(in);
        shape->regs.push_back(capture(s, insn));
        auto kind = qemu_plugin_insn_transfer_kind(insn);
        if (kind == QEMU_PLUGIN_TRANSFER_COND_NO_TARGET) {
            shape->traps.push_back(i);
        } else if (kind != QEMU_PLUGIN_TRANSFER_NONE) {
            shape->transfer = int(i);
            shape->indirect = kind == QEMU_PLUGIN_TRANSFER_INDIRECT;
            shape->target = qemu_plugin_insn_branch_target_pc(insn);
        }
        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
            insn, QEMU_PLUGIN_INLINE_STORE_U64, s.started, i + 1);
        /* Also what arms the engine's count of a bulk op's units (MOPS). */
        qemu_plugin_register_vcpu_mem_cb(insn, on_mem, QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW,
                                         reinterpret_cast<void *>(uintptr_t(i)));
    }
    if (n == 0) {
        return;
    }
    /* RW: an excursion launched here saves, runs and restores the vCPU */
    qemu_plugin_register_vcpu_tb_exec_cb(tb, on_tb_exec, QEMU_PLUGIN_CB_RW_REGS,
                                         shape.get());
    std::lock_guard<std::mutex> guard(s.tbs_lock);
    s.tbs.push_back(std::move(shape));
}

bool parse_options(Session &s, int argc, char **argv)
{
    std::string outfile;
    for (int i = 0; i < argc; i++) {
        std::string opt = argv[i];
        size_t eq = opt.find('=');
        std::string key = opt.substr(0, eq);
        std::string val = eq == std::string::npos ? "" : opt.substr(eq + 1);
        if (eq != std::string::npos && key == "outfile" && !val.empty()) {
            outfile = val;
        } else if (eq != std::string::npos && key == "compress") {
            s.compress = val;
        } else if (key == "wp" && (val == "0" || val == "1")) {
            s.wp = val == "1";
        } else if (key == "wpdepth" && std::atoi(val.c_str()) > 0) {
            s.wpdepth = size_t(std::atoi(val.c_str()));
        } else {
            say("unknown or malformed option '" + opt + "'");
            return false;
        }
    }
    if (outfile.empty()) {
        say("outfile=<path> is required");
        return false;
    }
    s.path = outfile + ".cst";
    size_t slash = s.path.rfind('/');
    s.scratch_dir = slash == std::string::npos ? "." :
                    slash == 0 ? "/" : s.path.substr(0, slash);
    return true;
}

} /* namespace */

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                          const qemu_info_t *info,
                                          int argc, char **argv)
{
    Session &s = session();
    if (!parse_options(s, argc, argv)) {
        return -1;
    }
    int isa = cst::isa_for_target(info->target_name);
    if (isa < 0) {
        say(std::string("target '") + info->target_name + "' is not traced");
        return -1;
    }
    /* Fail at load, not at exit, if the trace cannot be written. */
    std::FILE *probe = std::fopen((s.path + ".part").c_str(), "wb");
    if (!probe) {
        say("cannot write " + s.path + ".part");
        return -1;
    }
    std::fclose(probe);
    std::remove((s.path + ".part").c_str());

    s.system = info->system_emulation;
    s.facts.isa = uint8_t(isa);
    s.facts.command = own_command_line();
    s.facts.datetime = local_datetime();
    s.facts.target_name = info->target_name;

    qemu_plugin_register_atexit_cb(id, on_exit, nullptr);
    if (s.system) {
        qemu_plugin_register_vm_shutdown_cb(id, on_shutdown);
        qemu_plugin_register_vm_reset_cb(id, on_reset);
    } else {
        /* System-mode thread identity is a later increment's claim. */
        s.started = qemu_plugin_scoreboard_u64(
            qemu_plugin_scoreboard_new(sizeof(uint64_t)));
        qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_trans);
        qemu_plugin_register_vcpu_syscall_cb(id, on_syscall);
        qemu_plugin_register_vcpu_exit_cb(id, on_vcpu_exit);
    }
    return 0;
}
