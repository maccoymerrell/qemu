/*
 * RISC-V timer helper implementation.
 *
 * Copyright (c) 2022 Rivos Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "cpu_bits.h"
#include "time_helper.h"
#include "hw/intc/riscv_aclint.h"

static void riscv_vstimer_cb(void *opaque)
{
    RISCVCPU *cpu = opaque;
    CPURISCVState *env = &cpu->env;
#ifdef CONFIG_PLUGIN
    /*
     * Wrong-path: the host timer fired during a speculative excursion.  Don't
     * touch the (rolled-back) interrupt state on the discarded path; just flag
     * the host timer for re-sync on excursion exit so it isn't left dead (this
     * one-shot has now fired and the cb does not itself re-arm).
     */
    if (CPU(cpu)->plugin_spec_mode) {
        CPU(cpu)->plugin_spec_timer_dirty = true;
        return;
    }
#endif
    env->vstime_irq = 1;
    riscv_cpu_update_mip(env, 0, BOOL_TO_MASK(1));
}

static void riscv_stimer_cb(void *opaque)
{
    RISCVCPU *cpu = opaque;
#ifdef CONFIG_PLUGIN
    if (CPU(cpu)->plugin_spec_mode) {
        CPU(cpu)->plugin_spec_timer_dirty = true;
        return;
    }
#endif
    riscv_cpu_update_mip(&cpu->env, MIP_STIP, BOOL_TO_MASK(1));
}

/*
 * Called when timecmp is written to update the QEMU timer or immediately
 * trigger timer interrupt if mtimecmp <= current timer value.
 */
void riscv_timer_write_timecmp(CPURISCVState *env, QEMUTimer *timer,
                               uint64_t timecmp, uint64_t delta,
                               uint32_t timer_irq)
{
#ifdef CONFIG_PLUGIN
    /*
     * Wrong-path (speculative): a speculative stimecmp/vstimecmp CSR write
     * already updated env (rolled back at walk end); don't reprogram the
     * real guest timer (timer_mod) or raise its interrupt on the discarded
     * path.
     */
    if (env_cpu(env)->plugin_spec_mode) {
        env_cpu(env)->plugin_spec_timer_dirty = true;
        return;
    }
#endif
    uint64_t diff, ns_diff, next;
    RISCVAclintMTimerState *mtimer = env->rdtime_fn_arg;
    uint32_t timebase_freq = mtimer->timebase_freq;
    uint64_t rtc_r = env->rdtime_fn(env->rdtime_fn_arg) + delta;

    if (timecmp <= rtc_r) {
        /*
         * If we're setting an stimecmp value in the "past",
         * immediately raise the timer interrupt
         */
        if (timer_irq == MIP_VSTIP) {
            env->vstime_irq = 1;
            riscv_cpu_update_mip(env, 0, BOOL_TO_MASK(1));
        } else {
            riscv_cpu_update_mip(env, MIP_STIP, BOOL_TO_MASK(1));
        }
        return;
    }

    /* Clear the [VS|S]TIP bit in mip */
    if (timer_irq == MIP_VSTIP) {
        env->vstime_irq = 0;
        riscv_cpu_update_mip(env, 0, BOOL_TO_MASK(0));
    } else {
        riscv_cpu_update_mip(env, timer_irq, BOOL_TO_MASK(0));
    }

    /*
     * Sstc specification says the following about timer interrupt:
     * "A supervisor timer interrupt becomes pending - as reflected in
     * the STIP bit in the mip and sip registers - whenever time contains
     * a value greater than or equal to stimecmp, treating the values
     * as unsigned integers. Writes to stimecmp are guaranteed to be
     * reflected in STIP eventually, but not necessarily immediately.
     * The interrupt remains posted until stimecmp becomes greater
     * than time - typically as a result of writing stimecmp."
     *
     * When timecmp = UINT64_MAX, the time CSR will eventually reach
     * timecmp value but on next timer tick the time CSR will wrap-around
     * and become zero which is less than UINT64_MAX. Now, the timer
     * interrupt behaves like a level triggered interrupt so it will
     * become 1 when time = timecmp = UINT64_MAX and next timer tick
     * it will become 0 again because time = 0 < timecmp = UINT64_MAX.
     *
     * Based on above, we don't re-start the QEMU timer when timecmp
     * equals UINT64_MAX.
     */
    if (timecmp == UINT64_MAX) {
        timer_del(timer);
        return;
    }

    /* otherwise, set up the future timer interrupt */
    diff = timecmp - rtc_r;
    /* back to ns (note args switched in muldiv64) */
    ns_diff = muldiv64(diff, NANOSECONDS_PER_SECOND, timebase_freq);

    /*
     * check if ns_diff overflowed and check if the addition would potentially
     * overflow
     */
    if ((NANOSECONDS_PER_SECOND > timebase_freq && ns_diff < diff) ||
        ns_diff > INT64_MAX) {
        next = INT64_MAX;
    } else {
        /*
         * as it is very unlikely qemu_clock_get_ns will return a value
         * greater than INT64_MAX, no additional check is needed for an
         * unsigned integer overflow.
         */
        next = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + ns_diff;
        /*
         * if ns_diff is INT64_MAX next may still be outside the range
         * of a signed integer.
         */
        next = MIN(next, INT64_MAX);
    }

    timer_mod(timer, next);
}

void riscv_timer_init(RISCVCPU *cpu)
{
    CPURISCVState *env;

    if (!cpu) {
        return;
    }

    env = &cpu->env;
    env->stimer = timer_new_ns(QEMU_CLOCK_VIRTUAL, &riscv_stimer_cb, cpu);
    env->stimecmp = 0;

    env->vstimer = timer_new_ns(QEMU_CLOCK_VIRTUAL, &riscv_vstimer_cb, cpu);
    env->vstimecmp = 0;
}

#ifdef CONFIG_PLUGIN
void riscv_cpu_plugin_resync_timers(CPUState *cs)
{
    CPURISCVState *env = cpu_env(cs);
    bool held;

    if (likely(!cs->plugin_spec_timer_dirty)) {
        return;
    }
    cs->plugin_spec_timer_dirty = false;

    /* rdtime_fn is wired only when the supervisor timer (Sstc) is usable. */
    if (!env->rdtime_fn) {
        return;
    }

    /* riscv_timer_write_timecmp drives the interrupt line, which needs the BQL.
     * It runs in full here because spec mode has already ended. */
    held = bql_locked();
    if (!held) {
        bql_lock();
    }
    if (env->stimer) {
        riscv_timer_write_timecmp(env, env->stimer, env->stimecmp,
                                  0, MIP_STIP);
    }
    if (env->vstimer) {
        riscv_timer_write_timecmp(env, env->vstimer, env->vstimecmp,
                                  env->htimedelta, MIP_VSTIP);
    }
    if (!held) {
        bql_unlock();
    }
}
#endif
