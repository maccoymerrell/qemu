/*
 * Machine-shutdown callback probe.
 *
 * Reports what qemu_plugin_vm_shutdown_cb_t was told, and can wedge vCPUs
 * so that the marshalled route has no vCPU to place the callback on.  Used
 * by tests/plugin-shutdown/check.sh.
 *
 * Arguments:
 *   out=PATH        where to write the report line (default stderr)
 *   wedge=on        block inside vcpu_tb_exec until the shutdown callback
 *                   fires, so vCPUs stop draining their work queues
 *   wedgeafter=N    number of translation blocks to execute first
 *   wedgecap=SECS   release the wedge unconditionally after SECS, so a
 *                   failing run ends instead of hanging the test host
 *
 * Author: Maccoy Merrell.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/*
 * The probe also builds against a QEMU from before the shutdown callback
 * separated origin from placement, which is how the before/after reading is
 * taken.  There, the vCPU whose state is live cannot be asked for at all --
 * the plugin's only handle on it is the argument that also has to answer
 * "which vCPU caused this", and that is the defect.
 */
#ifdef QEMU_PLUGIN_VCPU_UNNAMED
#define PROBE_CURRENT_VCPU() qemu_plugin_current_vcpu_index()
#else
#define PROBE_CURRENT_VCPU() (-99)
#endif

static FILE *report;
static gboolean wedge_mode;
static gint wedge_after = 200000;
static gint wedge_cap_secs = 120;

static GMutex wedge_lock;         /* held by the wedged vCPU */
static GMutex shutdown_lock;
static GCond shutdown_cond;
static gboolean shutdown_seen;    /* under shutdown_lock */

static gint blocks_executed;
static gint wedge_released;
static gint last_exec_vcpu = -1;

static void vcpu_tb_exec(unsigned int vcpu_index, void *udata)
{
    gint64 cap;

    g_atomic_int_set(&last_exec_vcpu, (gint)vcpu_index);

    if (!wedge_mode || g_atomic_int_get(&wedge_released)) {
        return;
    }
    if (g_atomic_int_add(&blocks_executed, 1) < wedge_after) {
        return;
    }

    /*
     * The first vCPU here takes wedge_lock and keeps it until the shutdown
     * callback fires; every other vCPU piles up behind it.  This is the
     * shape of the real stall it stands in for -- a plugin lock held
     * across something that is not making progress -- and it holds no QEMU
     * lock, so nothing but the vCPUs themselves is blocked.
     */
    g_mutex_lock(&wedge_lock);
    if (!g_atomic_int_get(&wedge_released)) {
        cap = g_get_monotonic_time() +
              (gint64)wedge_cap_secs * G_TIME_SPAN_SECOND;
        g_mutex_lock(&shutdown_lock);
        while (!shutdown_seen) {
            if (!g_cond_wait_until(&shutdown_cond, &shutdown_lock, cap)) {
                break;
            }
        }
        g_mutex_unlock(&shutdown_lock);
        g_atomic_int_set(&wedge_released, 1);
    }
    g_mutex_unlock(&wedge_lock);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS, NULL);
}

static void vm_shutdown_cb(qemu_plugin_id_t id, int vcpu_index,
                           bool in_guest_insn)
{
    fprintf(report,
            "SHUTDOWN origin=%d in_guest_insn=%d current=%d last_exec=%d\n",
            vcpu_index, in_guest_insn ? 1 : 0,
            PROBE_CURRENT_VCPU(),
            g_atomic_int_get(&last_exec_vcpu));
    fflush(report);

    g_mutex_lock(&shutdown_lock);
    shutdown_seen = TRUE;
    g_cond_broadcast(&shutdown_cond);
    g_mutex_unlock(&shutdown_lock);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    fprintf(report, "EXIT\n");
    fflush(report);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    report = stderr;

    for (int i = 0; i < argc; i++) {
        char **tokens = g_strsplit(argv[i], "=", 2);

        if (tokens[0] && tokens[1] && g_strcmp0(tokens[0], "out") == 0) {
            report = fopen(tokens[1], "w");
            if (!report) {
                fprintf(stderr, "shutdown-probe: cannot write %s\n", tokens[1]);
                g_strfreev(tokens);
                return -1;
            }
        } else if (tokens[0] && tokens[1] &&
                   g_strcmp0(tokens[0], "wedge") == 0) {
            wedge_mode = g_strcmp0(tokens[1], "on") == 0;
        } else if (tokens[0] && tokens[1] &&
                   g_strcmp0(tokens[0], "wedgeafter") == 0) {
            wedge_after = atoi(tokens[1]);
        } else if (tokens[0] && tokens[1] &&
                   g_strcmp0(tokens[0], "wedgecap") == 0) {
            wedge_cap_secs = atoi(tokens[1]);
        } else {
            fprintf(stderr, "shutdown-probe: bad argument %s\n", argv[i]);
            g_strfreev(tokens);
            return -1;
        }
        g_strfreev(tokens);
    }

    if (wedge_mode) {
        qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    }
    qemu_plugin_register_vm_shutdown_cb(id, vm_shutdown_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
