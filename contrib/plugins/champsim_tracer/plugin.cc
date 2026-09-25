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
 * pc/size templates and one entry per block run (blocks.h).  It claims
 * nothing else about an instruction; system mode keeps an empty body.
 *
 * Options:
 *   outfile=<path>   the trace is <path>.cst (required)
 *   compress=<cmd>   a filter command each member is streamed through,
 *                    e.g. compress="zstd -T0 -3 -q -c"
 */
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iterator>
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

struct Session {
    std::mutex lock;
    bool published = false;     /* one segment per run, at most */
    bool system = false;
    std::string path;           /* <outfile>.cst */
    std::string scratch_dir;
    std::string compress;
    cst::HeaderFacts facts;
    cst::BlockAssembler blocks;
    std::vector<std::unique_ptr<cst::TbShape>> tbs;  /* live until exit */
    qemu_plugin_u64 started;    /* per vCPU: insns begun in the current TB */
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
 * Close the segment.  @root_phys is the asid-0 label: the live
 * address-space value, read by the caller where it is readable.
 * Idempotent: whichever ruled route arrives first publishes.
 */
void publish(uint64_t root_phys, const char *route)
{
    Session &s = session();
    std::lock_guard<std::mutex> guard(s.lock);
    if (s.published) {
        return;
    }
    s.published = true;
    s.blocks.finish_all([&s](uint32_t tid) {
        return qemu_plugin_u64_get(s.started, tid);
    });
    std::vector<cst::WireTemplate> templates;
    std::vector<cst::WireEntry> entries;
    s.blocks.recut(templates, entries);
    const auto &st = s.blocks.stats;
    say("entries=" + std::to_string(entries.size()) + " templates=" +
        std::to_string(templates.size()) + " early_exits=" +
        std::to_string(st.early_exits) + " late_block_ends=" +
        std::to_string(st.late_ends) + "; revised " +
        std::to_string(st.revised_shapes) + " shapes, " +
        std::to_string(st.recut_entries) + " entries re-cut");
    /* The body goes first, so the header can be finalised after it. */
    std::vector<cst::Member> members = {
        { "body.cst", cst::body_member(root_phys, entries).data() },
        { "header.cst", cst::header_member(s.facts, templates).data() },
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
    std::lock_guard<std::mutex> guard(s.lock);
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

/* A TB begins: the previous one of this vCPU is over. */
void on_tb_exec(unsigned int vcpu, void *udata)
{
    Session &s = session();
    auto *tb = static_cast<const cst::TbShape *>(udata);
    std::lock_guard<std::mutex> guard(s.lock);
    if (s.published) {
        return;
    }
    cst::BulkRun bulk{ qemu_plugin_rep_pc(), qemu_plugin_rep_iterations(),
                       qemu_plugin_rep_reenter() };
    s.blocks.retire(vcpu, qemu_plugin_u64_get(s.started, vcpu), &bulk,
                    s.blocks.insn(tb->insns.front()).pc);
    s.blocks.begin(vcpu, tb);
}

/* A syscall ends the block of the instruction that raised it. */
void on_syscall(qemu_plugin_id_t, unsigned int vcpu, int64_t, uint64_t,
                uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                uint64_t)
{
    Session &s = session();
    std::lock_guard<std::mutex> guard(s.lock);
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
    std::lock_guard<std::mutex> guard(s.lock);
    if (!s.published) {
        s.blocks.finish(vcpu, qemu_plugin_u64_get(s.started, vcpu));
    }
}

void on_tb_trans(qemu_plugin_id_t, struct qemu_plugin_tb *tb)
{
    Session &s = session();
    auto shape = std::make_unique<cst::TbShape>();
    size_t n = qemu_plugin_tb_n_insns(tb);
    std::lock_guard<std::mutex> guard(s.lock);
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        cst::Insn in{};
        in.pc = qemu_plugin_insn_vaddr(insn);
        in.size = uint8_t(qemu_plugin_insn_data(insn, in.bytes, sizeof(in.bytes)));
        shape->insns.push_back(s.blocks.intern(in));
        auto kind = qemu_plugin_insn_transfer_kind(insn);
        if (kind == QEMU_PLUGIN_TRANSFER_COND_NO_TARGET) {
            s.blocks.ends_block(shape->insns.back());   /* a trap, in place */
        } else if (kind != QEMU_PLUGIN_TRANSFER_NONE) {
            shape->transfer = int(i);
        }
        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
            insn, QEMU_PLUGIN_INLINE_STORE_U64, s.started, i + 1);
        /* The engine counts a bulk op's units (FEAT_MOPS) only while the
         * op carries a memory callback; a no-op one arms the count. */
        qemu_plugin_register_vcpu_mem_inline_per_vcpu(
            insn, QEMU_PLUGIN_MEM_RW, QEMU_PLUGIN_INLINE_ADD_U64, s.started, 0);
    }
    if (n == 0) {
        return;
    }
    s.blocks.translated(*shape);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, on_tb_exec, QEMU_PLUGIN_CB_NO_REGS,
                                         shape.get());
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
