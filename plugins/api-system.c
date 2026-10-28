/*
 * QEMU Plugin API - System specific implementations
 *
 * This provides the APIs that have a specific system implementation
 * or are only relevant to system-mode.
 *
 * Copyright (C) 2017, Emilio G. Cota <cota@braap.org>
 * Copyright (C) 2019-2025, Linaro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"
#include "migration/blocker.h"
#include "hw/boards.h"
#include "exec/target_page.h"
#include "qemu/plugin-memory.h"
#include "qemu/plugin.h"
#include "qemu/timer.h"
#include "system/cpu-timers.h"

/*
 * In system mode we cannot trace the binary being executed so the
 * helpers all return NULL/0.
 */
const char *qemu_plugin_path_to_binary(void)
{
    return NULL;
}

uint64_t qemu_plugin_start_code(void)
{
    return 0;
}

uint64_t qemu_plugin_end_code(void)
{
    return 0;
}

uint64_t qemu_plugin_entry_code(void)
{
    return 0;
}

/*
 * Virtual Memory queries
 */

static __thread struct qemu_plugin_hwaddr hwaddr_info;

struct qemu_plugin_hwaddr *qemu_plugin_get_hwaddr(qemu_plugin_meminfo_t info,
                                                  uint64_t vaddr)
{
    CPUState *cpu = current_cpu;
    unsigned int mmu_idx = get_mmuidx(info);
    enum qemu_plugin_mem_rw rw = get_plugin_meminfo_rw(info);
    hwaddr_info.is_store = (rw & QEMU_PLUGIN_MEM_W) != 0;

    assert(mmu_idx < NB_MMU_MODES);

    if (!tlb_plugin_lookup(cpu, vaddr, mmu_idx,
                           hwaddr_info.is_store, &hwaddr_info)) {
        /*
         * A lookup miss during a plugin speculative (wrong-path)
         * excursion is expected, not misuse: the access address is
         * derived from mispredicted register state, so it frequently
         * has no TLB-resident translation.  Return NULL silently
         * there; keep the warning for correct-path misses, which do
         * indicate a misplaced call.
         */
        if (!cpu->plugin_spec_mode) {
            error_report("invalid use of qemu_plugin_get_hwaddr");
        }
        return NULL;
    }

    return &hwaddr_info;
}

bool qemu_plugin_hwaddr_is_io(const struct qemu_plugin_hwaddr *haddr)
{
    return haddr->is_io;
}

uint64_t qemu_plugin_hwaddr_phys_addr(const struct qemu_plugin_hwaddr *haddr)
{
    if (haddr) {
        return haddr->phys_addr;
    }
    return 0;
}

const char *qemu_plugin_hwaddr_device_name(const struct qemu_plugin_hwaddr *h)
{
    if (h && h->is_io) {
        MemoryRegion *mr = h->mr;
        if (!mr->name) {
            unsigned maddr = (uintptr_t)mr;
            g_autofree char *temp = g_strdup_printf("anon%08x", maddr);
            return g_intern_string(temp);
        } else {
            return g_intern_string(mr->name);
        }
    } else {
        return g_intern_static_string("RAM");
    }
}


/*
 * Time control
 */
static bool has_control;
static Error *migration_blocker;

const void *qemu_plugin_request_time_control(void)
{
    if (!has_control) {
        has_control = true;
        error_setg(&migration_blocker,
                   "TCG plugin time control does not support migration");
        migrate_add_blocker(&migration_blocker, NULL);
        return &has_control;
    }
    return NULL;
}

static void advance_virtual_time__async(CPUState *cpu, run_on_cpu_data data)
{
    int64_t new_time = data.host_ulong;
    qemu_clock_advance_virtual_time(new_time);
}

void qemu_plugin_update_ns(const void *handle, int64_t new_time)
{
    if (handle == &has_control) {
        /* Need to execute out of cpu_exec, so bql can be locked. */
        async_run_on_cpu(current_cpu,
                         advance_virtual_time__async,
                         RUN_ON_CPU_HOST_ULONG(new_time));
    }
}

/*
 * Guest clock queries.  These are the system-mode halves of a pair whose
 * user-mode halves live in api-user.c: api.c is built once for every
 * emulator, so a mode test there is never compiled in, and a user-only build
 * has neither the icount state nor the virtual clock to link against.
 */
bool qemu_plugin_icount_enabled(void)
{
    return icount_enabled();
}

/*
 * Read side of the same clock qemu_plugin_vclock_pause() freezes.  A plugin
 * that pauses for its own cost needs to be able to see what the guest was
 * left believing: guest-ns per host-ns is the guest realtime factor, and
 * guest instructions per guest-second is the rate the guest's periodic tick
 * load is charged against.  Read-only, so no BQL and no runstate interaction.
 */
int64_t qemu_plugin_vclock_ns(void)
{
    if (icount_enabled()) {
        /*
         * Under icount the virtual clock IS the instruction counter, and
         * reading it from a vCPU callback with cpu->running && !can_do_io
         * aborts ("Bad icount read").  There is also nothing to learn: icount
         * pins guest time to instructions by construction, so the factor this
         * call exists to measure is a constant of the configuration.
         */
        return 0;
    }
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
}
