/*
 * QEMU Plugin system-emulation helpers
 *
 * Helpers that are specific to system emulation.
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019-2025, Linaro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/plugin.h"
#include "hw/boards.h"
#include "qemu/main-loop.h"
#include "qemu/error-report.h"
#include "hw/core/cpu.h"

#include "plugin.h"

void qemu_plugin_fillin_mode_info(qemu_info_t *info)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    info->system_emulation = true;
    info->system.smp_vcpus = ms->smp.cpus;
    info->system.max_vcpus = ms->smp.max_cpus;
}

/*
 * Machine shutdown -> plugin, placed on a vCPU thread.
 *
 * Called from the shutdown request and from the main loop's shutdown
 * acknowledge (system/runstate.c), both of which run BEFORE qemu_cleanup()
 * — so the machine is still assembled and the vCPUs still exist.  That is
 * the whole value of this seam: everything a plugin needs to close a
 * capture (guest memory, registers, privilege level, address space)
 * resolves through current_cpu, and at atexit(3) time — where
 * qemu_plugin_atexit_cb() fires — current_cpu is NULL and the machine is
 * already down.
 */

/*
 * How long the marshalled route holds the shutdown open while it waits for
 * some vCPU to reach its work queue.
 *
 * The wait is what makes the vCPU-context guarantee real, and it is also
 * the one place where a plugin's own scheduling can stall QEMU's exit: the
 * work runs when a vCPU next drains its queue, which it does between
 * translation blocks, and a vCPU that is not making progress between
 * translation blocks never gets there.  A plugin lock held across a stall,
 * a guest wedged in an MMIO access and a vCPU spinning inside an
 * instrumentation callback all read the same from here.  The request that
 * carries this dispatch is the operator's SIGTERM or `quit`, so an
 * unbounded wait converts a plugin's problem into a machine that does not
 * shut down.  Ten seconds is orders of magnitude above the microseconds a
 * healthy vCPU needs, and finite.
 */
#define PLUGIN_SHUTDOWN_PLACE_TIMEOUT_MS 10000

static QemuCond plugin_shutdown_placed_cond;
static bool plugin_shutdown_placed_cond_ready;
static bool plugin_shutdown_placed;

/*
 * Marshalled work: runs on a vCPU thread, at a TB BOUNDARY, with the BQL
 * held.  Two facts go out from here and they are separate facts.
 *
 * No guest instruction is in flight, so the last dispatched block
 * completed -- @in_guest_insn is false.
 *
 * And no vCPU asked for this shutdown.  The monitor, a QMP client or a
 * host signal did, from a thread that is not a vCPU thread at all; a vCPU
 * is borrowed purely because guest memory, registers and the privilege /
 * address-space APIs resolve through current_cpu and nowhere else.  WHICH
 * vCPU runs it is decided by which one drains its work queue first, which
 * is a fact about QEMU's scheduling and about nothing in the guest.
 * Naming that vCPU in the callback would hand the plugin an index it can
 * only read as "the vCPU this is about", and it is not.
 */
static void plugin_vm_shutdown_on_cpu(CPUState *cpu, run_on_cpu_data arg)
{
    /*
     * Under round-robin TCG the work for one vCPU is drained without
     * current_cpu being pointed at it, so the vCPU whose state is live is
     * not necessarily @cpu.  The plugin is told which one it is by
     * qemu_plugin_current_vcpu_index(); all that is promised here is that
     * there IS one.
     */
    qemu_plugin_vm_shutdown_dispatch(current_cpu ? QEMU_PLUGIN_VCPU_UNNAMED
                                                 : QEMU_PLUGIN_VCPU_NONE,
                                     false);
    qatomic_set(&plugin_shutdown_placed, true);
    qemu_cond_broadcast(&plugin_shutdown_placed_cond);
}

void qemu_plugin_vm_shutdown(void)
{
    CPUState *cpu;
    bool offered = false;
    int64_t deadline;

    if (!qemu_plugin_vm_shutdown_armed()) {
        return;
    }
    if (current_cpu) {
        /*
         * The common case, and the best one: a guest poweroff is a device
         * write the guest itself executed, so the request arrives on the
         * writing vCPU's own thread with its state live and coherent.
         * This is the only route on which a vCPU is named, because it is
         * the only route on which one is responsible.
         */
        qemu_plugin_vm_shutdown_dispatch(current_cpu->cpu_index, true);
        return;
    }
    if (!first_cpu || !bql_locked()) {
        /* No vCPU exists, or no way to place work on one from here. */
        qemu_plugin_vm_shutdown_dispatch(QEMU_PLUGIN_VCPU_NONE, false);
        return;
    }

    /*
     * Main loop, monitor or QMP.  Offer the work to EVERY live vCPU rather
     * than to first_cpu: the callback needs a vCPU thread, not a
     * particular one, and the first vCPU in the list has no better claim
     * to be reachable than any other -- it may be halted, stopped, or
     * parked behind whatever the plugin is doing on another thread.  The
     * dispatch is idempotent, so the first one there delivers and the rest
     * are no-ops.
     */
    if (!plugin_shutdown_placed_cond_ready) {
        qemu_cond_init(&plugin_shutdown_placed_cond);
        plugin_shutdown_placed_cond_ready = true;
    }
    CPU_FOREACH(cpu) {
        if (!cpu->created || cpu->unplug) {
            continue;
        }
        async_run_on_cpu(cpu, plugin_vm_shutdown_on_cpu, RUN_ON_CPU_NULL);
        offered = true;
    }
    if (!offered) {
        qemu_plugin_vm_shutdown_dispatch(QEMU_PLUGIN_VCPU_NONE, false);
        return;
    }

    deadline = g_get_monotonic_time() +
               (int64_t)PLUGIN_SHUTDOWN_PLACE_TIMEOUT_MS * 1000;
    while (!qatomic_read(&plugin_shutdown_placed)) {
        int64_t left_ms = (deadline - g_get_monotonic_time()) / 1000;

        if (left_ms <= 0) {
            break;
        }
        /* Releases the BQL while it waits, so the vCPUs can run. */
        qemu_cond_timedwait_bql(&plugin_shutdown_placed_cond, (int)left_ms);
    }
    if (qatomic_read(&plugin_shutdown_placed)) {
        return;
    }

    /*
     * Nothing reached its work queue in ten seconds.  Say so -- a
     * degraded close is a thing the operator has to know about, and the
     * alternative reading of the same silence is a machine that hangs on
     * shutdown -- and then dispatch from here, without vCPU context.  The
     * queued work items stay queued; if a vCPU frees up later its dispatch
     * finds the hook already fired and does nothing.
     */
    warn_report("plugin: no vCPU reached a translation-block boundary within "
                "%d ms of the shutdown request; delivering the machine-"
                "shutdown callback without vCPU context, so a plugin holding "
                "an open capture cannot read guest state to close it",
                PLUGIN_SHUTDOWN_PLACE_TIMEOUT_MS);
    qemu_plugin_vm_shutdown_dispatch(QEMU_PLUGIN_VCPU_NONE, false);
}
