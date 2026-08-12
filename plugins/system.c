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

static QemuCond plugin_shutdown_placed_cond;
static bool plugin_shutdown_placed_cond_ready;
static bool plugin_shutdown_placed;

/*
 * Marshalled work: runs on a vCPU thread, at a TB BOUNDARY, and is entered
 * with the BQL held -- which it drops around the callback, see below.  Two
 * facts go out from here and they are separate facts.
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
     * The BQL must not be held across the callback.
     *
     * process_queued_cpu_work() runs a non-exclusive work item with the BQL
     * held, and this vCPU reaching a translation-block boundary says nothing
     * about the others: they are free-running inside plugin callbacks the
     * whole time.  A plugin that closes a capture here takes its own callback
     * lock, and a plugin that instruments speculatively holds that same lock
     * across a wrong-path excursion -- which acquires the BQL from inside it,
     * at cpu_plugin_spec_vtime_pause, at cpu_plugin_spec_vtime_resume, and at
     * cpu_plugin_arch_state_restore on RISC-V.  So the excursion's order is
     * plugin lock then BQL, and arriving here holding the BQL and then
     * blocking on the plugin lock runs it the other way: the lock's holder is
     * waiting for the BQL this thread owns, and the machine stops dead --
     * every thread in futex_wait, zero CPU, no close, no trace.
     *
     * Measured on the ChampSim Tracer at -smp 4 with the wrong path enabled
     * and a marker window open, taken to a close by SIGTERM.  Every
     * reproduction so far is RISC-V: four of eight riscv64 cells stopped
     * dead, and the two aarch64 cells run with the same arms both closed.
     * That is a difference in exposure, not in kind -- the pause and the
     * resume take the BQL on every target, and RISC-V merely has a third
     * acquisition (the pending-interrupt replay in
     * cpu_plugin_arch_state_restore) and so a wider window -- so aarch64 is
     * unproven here rather than exempt.  Confirmed against this code by an
     * A/B of two binaries differing only in the ten bytes of the two calls
     * below: with the drop removed, two of sixteen cells deadlocked, each
     * with the shutdown callback on the plugin's lock beneath
     * process_queued_cpu_work and a peer's excursion on the BQL, no shutdown
     * banner and no assembled trace; with it in place, none of eight.
     *
     * Dropping it is the same treatment process_queued_cpu_work() already
     * gives an exclusive item, and for the same reason.  It costs nothing:
     * the requester is parked on the placement condition with the BQL
     * released, so no thread is waiting on this one to hold it.
     *
     * Under round-robin TCG the work for one vCPU is drained without
     * current_cpu being pointed at it, so the vCPU whose state is live is
     * not necessarily @cpu.  The plugin is told which one it is by
     * qemu_plugin_current_vcpu_index(); all that is promised here is that
     * there IS one.
     */
    bool had_bql = bql_locked();

    if (had_bql) {
        bql_unlock();
    }
    qemu_plugin_vm_shutdown_dispatch(current_cpu ? QEMU_PLUGIN_VCPU_UNNAMED
                                                 : QEMU_PLUGIN_VCPU_NONE,
                                     false);
    if (had_bql) {
        bql_lock();
    }
    qatomic_set(&plugin_shutdown_placed, true);
    qemu_cond_broadcast(&plugin_shutdown_placed_cond);
}

void qemu_plugin_vm_shutdown(void)
{
    CPUState *cpu;
    bool offered = false;

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
         *
         * This route can also arrive with the BQL held -- a TCG guest's
         * device write takes it in do_st_mmio_leN -- so it has the same
         * shape as the marshalled one and the same AB/BA exposure against a
         * plugin lock a peer vCPU holds across a wrong-path excursion.  It
         * is NOT given the same drop, because here the BQL is the device
         * write's own and releasing it mid-handler would publish a
         * half-updated device.  UNMEASURED: the marshalled route is the one
         * that has been reproduced; this one is reasoned only, and closing
         * it needs a dispatch that does not run inside the write.
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

    /*
     * Wait until some vCPU has delivered the callback.  The wait is
     * unbounded, deliberately: the work is offered to every live vCPU, so
     * it runs as soon as ANY of them drains its work queue, and the
     * lock-order inversion that could park the callback itself -- the BQL
     * held into a plugin lock a peer vCPU holds across a wrong-path
     * excursion -- is fixed at its source in plugin_vm_shutdown_on_cpu,
     * which drops the BQL around the dispatch.  What remains is a plugin
     * or a guest that is genuinely not making progress, and that is its
     * own defect to be fixed where it lives, not a condition to be
     * detected and stepped around from here.
     */
    while (!qatomic_read(&plugin_shutdown_placed)) {
        /* Releases the BQL while it waits, so the vCPUs can run. */
        qemu_cond_wait_bql(&plugin_shutdown_placed_cond);
    }
}
