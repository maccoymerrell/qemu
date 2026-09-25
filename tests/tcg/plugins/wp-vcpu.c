/*
 * wp-vcpu: a wrong-path block's per-vCPU instrumentation names the vCPU
 * that runs it (E1).
 *
 * A TB is translated with the vCPU index folded to a constant while one
 * vCPU exists.  The correct path can never meet such a TB on another vCPU:
 * the first clone sets CF_PARALLEL, which changes every later lookup key.
 * The wrong-path executor (qemu_plugin_exec_tb) clears CF_PARALLEL from its
 * key, so it can: a block vCPU 0's excursion translated before the first
 * clone is found again by the next thread's excursion, until the clone's
 * deferred tb_flush lands.  If that block carries vCPU 0's index as a
 * constant, the new thread's inline ops write vCPU 0's scoreboard slot and
 * its callbacks are told they run on vCPU 0.
 *
 * The drive, made deterministic rather than raced against the flush:
 *   1. vCPU 0, alone, runs a one-block excursion at the pc of its 64th
 *      block P, which translates the wrong-path block at P.
 *   2. vCPU 0's return from the first clone waits (up to 20 s) in the
 *      syscall-return callback, so the flush the clone queued stays queued.
 *   3. The new vCPU's first block runs a one-block excursion at P.
 * Asserted for step 3:
 *   subject  no translation at P happened during it (it reused the block
 *            step 1 minted before the clone -- otherwise the run has
 *            nothing to say and FAILs as "subject absent")
 *   check    vCPU 0's slot of a per-vCPU tb-exec inline counter is
 *            unchanged, the running vCPU's slot moved by 1, and the block's
 *            exec callback was handed the running vCPU's index
 *
 * Arguments:
 *   e1=on        drive and assert (inert otherwise, so check-tcg's generic
 *                plugin loop may load it with any guest)
 *   control=E1   inside step 3 the plugin itself adds 1 to vCPU 0's slot,
 *                so the check MUST fail
 *
 * Verdict: "[wp-vcpu] PASS E1_VCPU_INDEX ..." or "[wp-vcpu] FAIL
 * E1_VCPU_INDEX: ..." at exit; a FAIL aborts.
 *
 * Copyright (c) 2026 Maccoy Merrell
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static bool active, control;
static int64_t clone_nr, clone3_nr;
static qemu_plugin_u64 hits;            /* per-vCPU tb-exec inline counter */

static GMutex lock;
static GCond cond;
static uint64_t n0;                     /* vCPU 0 blocks before arming */
static uint64_t P;                      /* the excursion target */
static bool armed, child_done, waited;
static unsigned trans_at_p;             /* spec-mode translations at P */

/* the step-3 record */
static unsigned child_vcpu, child_cb_vcpu, child_cb_calls;
static uint64_t s0_before, s0_after, s1_before, s1_after;
static unsigned trans_before, trans_after;
static bool child_ok;

static __thread bool in_exc;
static __thread unsigned cb_vcpu, cb_calls;

static bool excursion(uint64_t pc)
{
    struct qemu_plugin_cpu_state *saved = qemu_plugin_cpu_state_save();
    bool ok;

    if (!saved) {
        fprintf(stderr, "[wp-vcpu] qemu_plugin_cpu_state_save failed\n");
        abort();
    }
    qemu_plugin_spec_mode_begin(saved);
    qemu_plugin_set_pc(pc);
    in_exc = true;
    cb_calls = 0;
    ok = qemu_plugin_exec_tb();
    in_exc = false;
    if (!ok) {
        qemu_plugin_spec_clear_exception();
    }
    qemu_plugin_spec_mode_end();
    if (!qemu_plugin_cpu_state_restore(saved)) {
        fprintf(stderr, "[wp-vcpu] qemu_plugin_cpu_state_restore failed\n");
        abort();
    }
    qemu_plugin_cpu_state_free(saved);
    return ok;
}

static void tb_exec(unsigned int vcpu, void *udata)
{
    uint64_t pc = (uint64_t)(uintptr_t)udata;

    if (in_exc) {
        cb_vcpu = vcpu;
        cb_calls++;
        return;
    }
    if (vcpu == 0) {
        if (armed || ++n0 < 64 || qemu_plugin_num_vcpus() != 1) {
            return;
        }
        P = pc;
        excursion(P);
        g_mutex_lock(&lock);
        armed = true;
        g_mutex_unlock(&lock);
        return;
    }
    g_mutex_lock(&lock);
    if (!armed || child_done) {
        g_mutex_unlock(&lock);
        return;
    }
    child_vcpu = vcpu;
    trans_before = trans_at_p;
    g_mutex_unlock(&lock);
    s0_before = qemu_plugin_u64_get(hits, 0);
    s1_before = qemu_plugin_u64_get(hits, vcpu);
    if (control) {
        qemu_plugin_u64_add(hits, 0, 1);
    }
    child_ok = excursion(P);
    s0_after = qemu_plugin_u64_get(hits, 0);
    s1_after = qemu_plugin_u64_get(hits, vcpu);
    child_cb_vcpu = cb_vcpu;
    child_cb_calls = cb_calls;
    g_mutex_lock(&lock);
    trans_after = trans_at_p;
    child_done = true;
    g_cond_broadcast(&cond);
    g_mutex_unlock(&lock);
}

static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);

    if (in_exc && pc == P) {
        g_mutex_lock(&lock);
        trans_at_p++;
        g_mutex_unlock(&lock);
    }
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64, hits, 1);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, tb_exec, QEMU_PLUGIN_CB_RW_REGS,
                                         (void *)(uintptr_t)pc);
}

static void syscall_ret(qemu_plugin_id_t id, unsigned int vcpu, int64_t num,
                        int64_t ret)
{
    if (vcpu != 0 || ret <= 0 || (num != clone_nr && num != clone3_nr)) {
        return;
    }
    gint64 end = g_get_monotonic_time() + 20 * G_TIME_SPAN_SECOND;
    g_mutex_lock(&lock);
    if (armed && !waited) {
        waited = true;
        while (!child_done) {
            if (!g_cond_wait_until(&cond, &lock, end)) {
                break;
            }
        }
    }
    g_mutex_unlock(&lock);
}

static void at_exit(qemu_plugin_id_t id, void *p)
{
    const char *t = "E1_VCPU_INDEX";

    if (!armed || !waited || !child_done) {
        fprintf(stderr, "[wp-vcpu] FAIL %s: subject absent (armed=%d at "
                "pc 0x%" PRIx64 ", clone wait=%d, second vCPU excursion=%d)\n",
                t, armed, P, waited, child_done);
        abort();
    }
    fprintf(stderr, "[wp-vcpu] E1 vCPU %u excursion at 0x%" PRIx64
            ": ok=%d translations at P during it=%u, vCPU 0 slot %" PRIu64
            " -> %" PRIu64 ", own slot %" PRIu64 " -> %" PRIu64
            ", exec callbacks=%u told vCPU %u%s\n", child_vcpu, P, child_ok,
            trans_after - trans_before, s0_before, s0_after, s1_before,
            s1_after, child_cb_calls, child_cb_vcpu,
            control ? " (control=E1: the plugin wrote vCPU 0's slot)" : "");
    if (trans_after != trans_before) {
        fprintf(stderr, "[wp-vcpu] FAIL %s: subject absent (the excursion "
                "translated P anew instead of reusing vCPU 0's pre-clone "
                "block)\n", t);
        abort();
    }
    if (s0_after != s0_before || s1_after != s1_before + 1 ||
        child_cb_calls != 1 || child_cb_vcpu != child_vcpu) {
        fprintf(stderr, "[wp-vcpu] FAIL %s: vCPU %u's wrong-path block "
                "was accounted elsewhere (vCPU 0 slot +%" PRIu64 ", own slot +%"
                PRIu64 ", %u exec callback(s) told vCPU %u)\n", t, child_vcpu,
                s0_after - s0_before, s1_after - s1_before, child_cb_calls,
                child_cb_vcpu);
        abort();
    }
    fprintf(stderr, "[wp-vcpu] PASS %s vCPU %u reused vCPU 0's pre-clone "
            "wrong-path block and its instrumentation named vCPU %u\n", t,
            child_vcpu, child_vcpu);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        if (g_strcmp0(argv[i], "e1=on") == 0) {
            active = true;
        } else if (g_strcmp0(argv[i], "control=E1") == 0) {
            control = true;
        } else {
            fprintf(stderr, "[wp-vcpu] unknown argument %s\n", argv[i]);
            return -1;
        }
    }
    if (!active) {
        return 0;
    }
    if (info->system_emulation) {
        fprintf(stderr, "[wp-vcpu] linux-user only\n");
        return -1;
    }
    if (!strcmp(info->target_name, "x86_64")) {
        clone_nr = 56, clone3_nr = 435;
    } else if (!strcmp(info->target_name, "aarch64") ||
               !strcmp(info->target_name, "riscv64")) {
        clone_nr = 220, clone3_nr = 435;
    } else if (!strcmp(info->target_name, "mipsel") ||
               !strcmp(info->target_name, "mips")) {
        clone_nr = 4120, clone3_nr = 4435;
    } else {
        fprintf(stderr, "[wp-vcpu] no clone numbers for %s\n",
                info->target_name);
        return -1;
    }
    hits = qemu_plugin_scoreboard_u64(
        qemu_plugin_scoreboard_new(sizeof(uint64_t)));
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, syscall_ret);
    qemu_plugin_register_atexit_cb(id, at_exit, NULL);
    return 0;
}
