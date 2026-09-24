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
#include "qemu/timer.h"
#include "qemu/vclock-agency.h"
#include "qemu/cst_bqslice.h"
#include "system/cpu-timers.h"
#include "system/tcg.h"

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

/* Both callers run under the BQL, so the flag needs no lock of its own. */
static void plugin_shutdown_cond_init(void)
{
    if (!plugin_shutdown_placed_cond_ready) {
        qemu_cond_init(&plugin_shutdown_placed_cond);
        plugin_shutdown_placed_cond_ready = true;
    }
}

/*
 * Deferred work: runs on a vCPU thread, at a TB BOUNDARY, and is entered
 * with the BQL held -- which it drops around the callback, see below.  Two
 * facts go out from here and they are separate facts.
 *
 * No guest instruction is in flight, so the last dispatched block
 * completed -- @in_guest_insn is false.
 *
 * Whether a vCPU asked for this shutdown arrives in @arg.  A guest
 * poweroff queues the work on the vCPU that executed it, and that ORIGIN
 * index rides along to be handed to the plugin.  The monitor, a QMP
 * client or a host signal name no vCPU (arg -1): a vCPU is borrowed
 * purely because guest memory, registers and the privilege /
 * address-space APIs resolve through current_cpu and nowhere else, WHICH
 * vCPU is decided by which one drains its work queue first — a fact
 * about QEMU's scheduling and about nothing in the guest — and naming
 * that vCPU in the callback would hand the plugin an index it can only
 * read as "the vCPU this is about", and it is not.  An origin index is
 * only forwarded while it still is that fact: under round-robin TCG the
 * queue can be drained with another vCPU's state live, and then the
 * origin degrades to unnamed rather than pointing the plugin at
 * registers that belong to someone else.
 */
static void plugin_vm_shutdown_on_cpu(CPUState *cpu, run_on_cpu_data arg)
{
    int origin = arg.host_int;
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
    int vcpu_index;

    if (origin >= 0 && current_cpu == cpu) {
        vcpu_index = origin;
    } else {
        vcpu_index = current_cpu ? QEMU_PLUGIN_VCPU_UNNAMED
                                 : QEMU_PLUGIN_VCPU_NONE;
    }
    if (had_bql) {
        bql_unlock();
    }
    qemu_plugin_vm_shutdown_dispatch(vcpu_index, false);
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
         * The common case: the guest asked, so the request arrives on the
         * asking vCPU's own thread — part-way through the device write
         * (x86 outw, RISC-V's syscon store) or the hypercall
         * (aarch64 PSCI) that performs it.
         *
         * This route arrives with the BQL held — a TCG guest's device
         * write takes it in do_st_mmio_leN, an exception handler in
         * cpu_handle_exception — so a synchronous dispatch here has the
         * same AB/BA exposure the marshalled route had: this thread
         * blocks on a plugin lock a peer vCPU holds across a wrong-path
         * excursion, and that excursion blocks on the BQL this thread
         * owns.  Measured on the ChampSim Tracer, riscv64 -smp 4 with a
         * marker window open and the guest running poweroff -f: the
         * writing vCPU stood in the plugin's shutdown callback beneath
         * the syscon store while a peer's excursion waited for the BQL,
         * zero CPU, no close, no trace.  The marshalled route's cure
         * cannot be copied — this BQL is the device write's own, and
         * releasing it mid-handler would publish a half-updated device —
         * so the dispatch is not run inside the write at all: the work is
         * queued on this same vCPU and runs at its next TB boundary,
         * where plugin_vm_shutdown_on_cpu drops the BQL around the
         * callback.  The ORIGIN index rides along, because deferring the
         * dispatch does not change which vCPU the shutdown came from;
         * what changes is the position fact, in_guest_insn — by the time
         * the work runs, the store has retired and the block it ended is
         * complete, which is exactly what false reports.
         *
         * The request path returns without waiting.  The second dispatch
         * point (qemu_system_shutdown) runs before teardown and, finding
         * the callback still armed, offers the work to every vCPU and
         * waits for placement — and a stopped vCPU still drains its work
         * queue, so the callback cannot be outrun by qemu_cleanup().
         *
         * A vCPU-context request without the BQL held has no lock to
         * invert, so it keeps the synchronous dispatch and with it the
         * mid-instruction position fact.
         */
        if (!bql_locked()) {
            qemu_plugin_vm_shutdown_dispatch(current_cpu->cpu_index, true);
            return;
        }
        plugin_shutdown_cond_init();
        async_run_on_cpu(current_cpu, plugin_vm_shutdown_on_cpu,
                         RUN_ON_CPU_HOST_INT(current_cpu->cpu_index));
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
    plugin_shutdown_cond_init();
    CPU_FOREACH(cpu) {
        if (!cpu->created || cpu->unplug) {
            continue;
        }
        async_run_on_cpu(cpu, plugin_vm_shutdown_on_cpu,
                         RUN_ON_CPU_HOST_INT(-1));
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

/*
 * Machine reset -> plugin.  The mirror of qemu_plugin_vm_shutdown() above,
 * with the same three routes and the same discipline — keep the two in
 * step, in particular the BQL drop around the marshalled dispatch, whose
 * deadlock (a peer vCPU holding the plugin's lock across a wrong-path
 * excursion that acquires the BQL) was measured and A/B-proven on the
 * shutdown path.  Differences, both consequences of a reset not being
 * terminal: the placement flag is re-armed per event rather than latched
 * for the run, and the core-side dispatch folds only concurrent
 * duplicates (see qemu_plugin_vm_reset_dispatch).
 *
 * Called from qemu_system_reset_request() BEFORE reset_requested is set,
 * i.e. before the main loop can pause the vCPUs and tear the machine
 * down, so a plugin closing a capture still reads the machine the
 * capture was recording.
 */
static QemuCond plugin_reset_placed_cond;
static bool plugin_reset_placed_cond_ready;
static bool plugin_reset_placed;
/* A guest-route reset dispatch is queued but not yet delivered; the
 * reset performance waits on it (qemu_plugin_vm_reset_wait_placed). */
static bool plugin_reset_deferred;

static void plugin_reset_cond_init(void)
{
    if (!plugin_reset_placed_cond_ready) {
        qemu_cond_init(&plugin_reset_placed_cond);
        plugin_reset_placed_cond_ready = true;
    }
}

static void plugin_vm_reset_on_cpu(CPUState *cpu, run_on_cpu_data arg)
{
    /* See plugin_vm_shutdown_on_cpu: same BQL drop, same origin-index
     * discipline. */
    int origin = arg.host_int;
    bool had_bql = bql_locked();
    int vcpu_index;

    if (origin >= 0 && current_cpu == cpu) {
        vcpu_index = origin;
    } else {
        vcpu_index = current_cpu ? QEMU_PLUGIN_VCPU_UNNAMED
                                 : QEMU_PLUGIN_VCPU_NONE;
    }
    if (had_bql) {
        bql_unlock();
    }
    qemu_plugin_vm_reset_dispatch(vcpu_index, false);
    if (had_bql) {
        bql_lock();
    }
    qatomic_set(&plugin_reset_placed, true);
    qemu_cond_broadcast(&plugin_reset_placed_cond);
}

void qemu_plugin_vm_reset(void)
{
    CPUState *cpu;
    bool offered = false;

    if (!qemu_plugin_vm_reset_armed()) {
        return;
    }
    if (current_cpu) {
        /*
         * A guest-initiated reset: a device write (port 92h, PIIX RCR,
         * i8042 pulse, PSCI SYSTEM_RESET, the sifive_test finisher, the
         * Malta SOFTRES register) or an x86 triple fault, arriving on
         * the responsible vCPU's own thread with its state live.
         *
         * The same AB/BA the shutdown route measured (see
         * qemu_plugin_vm_shutdown): this thread holds the BQL from the
         * device write, and a synchronous dispatch would block on a
         * plugin lock a peer vCPU can hold across a wrong-path excursion
         * that needs the BQL.  Same cure: defer to this vCPU's own TB
         * boundary, where the work runner drops the BQL around the
         * callback, carrying the origin index.  A reset differs from a
         * shutdown in having no second dispatch point to wait at, and
         * the pause that precedes the reset does not wait for work
         * queues — so the reset performance itself waits, at
         * qemu_plugin_vm_reset_wait_placed(), for this queued dispatch
         * to land before the machine it must report on is torn down.
         */
        if (!bql_locked()) {
            qemu_plugin_vm_reset_dispatch(current_cpu->cpu_index, true);
            return;
        }
        plugin_reset_cond_init();
        qatomic_set(&plugin_reset_placed, false);
        plugin_reset_deferred = true;
        async_run_on_cpu(current_cpu, plugin_vm_reset_on_cpu,
                         RUN_ON_CPU_HOST_INT(current_cpu->cpu_index));
        return;
    }
    if (!first_cpu || !bql_locked()) {
        qemu_plugin_vm_reset_dispatch(QEMU_PLUGIN_VCPU_NONE, false);
        return;
    }

    /* Monitor, QMP or watchdog: borrow a vCPU thread, any live one. */
    plugin_reset_cond_init();
    qatomic_set(&plugin_reset_placed, false);
    CPU_FOREACH(cpu) {
        if (!cpu->created || cpu->unplug) {
            continue;
        }
        async_run_on_cpu(cpu, plugin_vm_reset_on_cpu,
                         RUN_ON_CPU_HOST_INT(-1));
        offered = true;
    }
    if (!offered) {
        qemu_plugin_vm_reset_dispatch(QEMU_PLUGIN_VCPU_NONE, false);
        return;
    }
    /* Unbounded for the shutdown path's reason: the offer reaches every
     * live vCPU and the dispatch drops the BQL, so a wait that does not
     * end is a vCPU genuinely not progressing — its own defect. */
    while (!qatomic_read(&plugin_reset_placed)) {
        qemu_cond_wait_bql(&plugin_reset_placed_cond);
    }
}

void qemu_plugin_vm_reset_wait_placed(void)
{
    /*
     * The reset performance's half of the guest-route deferral (see
     * qemu_plugin_vm_reset).  pause_all_vcpus() has run, but a pausing
     * vCPU signals the pause condition BEFORE it drains its work queue,
     * so the queued dispatch may still be pending here; a paused vCPU
     * keeps draining its queue on every wake, so the wait ends.  Called
     * under the BQL, which the wait releases so the vCPU can deliver.
     */
    if (!plugin_reset_deferred) {
        return;
    }
    while (!qatomic_read(&plugin_reset_placed)) {
        qemu_cond_wait_bql(&plugin_reset_placed_cond);
    }
    plugin_reset_deferred = false;
}

/*
 * Event-agency arming (PRODUCT; see qemu/vclock-agency.h).  The
 * condition is PLUGIN-ACTIVE -- a runtime fact decided at the plugin
 * loader's install/uninstall edges -- never an environment knob.
 *
 * Arming turns on BOTH halves of the discipline: the VIRTUAL
 * exclusion/consumption side (vclock_agency_set_active) and the
 * guest-insn slice bounding whose breakouts carry the consumption
 * (cst_bq_product_arm) -- the delivery bound IS the slice quantum, so
 * the two are one product decision, armed on one edge.  There is no
 * wake timer: the trigger-site wave (wave/proddr) proved the
 * dispatch-top trigger and its VIRTUAL_RT nudge are the disproven
 * geometry, and the slice breakout needs no real-time wake.
 */
void qemu_plugin_vclock_agency_mode(bool active)
{
    if (active) {
        /*
         * Under icount the deadline-consumption discipline is already
         * icount's own (same predicate, same notify branch, plus the
         * real warp timer); under a non-TCG accel there are no TB
         * boundaries to consume at.  Both leave stock behaviour.
         */
        if (icount_enabled() || !tcg_enabled()) {
            return;
        }
        /* the slice half arms first so no engaged window can exist
         * without its consumption sites */
        cst_bq_product_arm();
        vclock_agency_set_active(true);
        /* fold in every VIRTUAL timer armed before the plugin loaded
         * (witness slot; the consumption predicate is the fresh
         * breakout-site read) */
        vclock_agency_resync();
    } else {
        vclock_agency_set_active(false);
    }
}
