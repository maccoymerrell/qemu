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
static void plugin_vm_shutdown_on_cpu(CPUState *cpu, run_on_cpu_data arg)
{
    /* Marshalled work runs at a TB BOUNDARY: no guest instruction is in
     * flight, so the last dispatched block completed. */
    qemu_plugin_vm_shutdown_dispatch(cpu->cpu_index, false);
}

void qemu_plugin_vm_shutdown(void)
{
    if (!qemu_plugin_vm_shutdown_armed()) {
        return;
    }
    if (current_cpu) {
        /*
         * The common case, and the best one: a guest poweroff is a device
         * write the guest itself executed, so the request arrives on the
         * writing vCPU's own thread with its state live and coherent.
         */
        qemu_plugin_vm_shutdown_dispatch(current_cpu->cpu_index, true);
        return;
    }
    if (first_cpu && bql_locked()) {
        /*
         * Main loop (host signal, monitor, QMP).  Marshal onto a vCPU
         * thread rather than read a running vCPU's state from here:
         * run_on_cpu() releases the BQL while it waits, and the work runs
         * at a TB boundary — outside any plugin callback, so the plugin's
         * own locks are free and current_cpu is that vCPU.
         */
        run_on_cpu(first_cpu, plugin_vm_shutdown_on_cpu, RUN_ON_CPU_NULL);
        return;
    }
    /* No vCPU exists: shutdown before the machine ever ran. */
    qemu_plugin_vm_shutdown_dispatch(-1, false);
}
