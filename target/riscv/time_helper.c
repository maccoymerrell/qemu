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
     * touch the (rolled-back) interrupt state on the discarded path; return
     * without delivering.  The one-shot has now fired and the cb does not
     * itself re-arm, so the deferred firing is owed to the guest; it is paid
     * by riscv_cpu_plugin_resync_timers, which re-derives the deadline and
     * re-raises on every excursion exit whether or not this gate was taken.
     *
     * Gate on plugin_spec_vtime_paused (true for the WHOLE excursion), not just
     * plugin_spec_mode: a wrong-path fault-skip briefly clears spec_mode
     * (spec_mode_end -> restore -> spec_mode_begin) while the snapshot is still
     * live and vtime still paused.  A real IRQ set in that gap is rolled back by
     * the final wp_end restore, so it must not be raised here at all (#77).
     */
    if (CPU(cpu)->plugin_spec_mode || CPU(cpu)->plugin_spec_vtime_paused) {
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
    if (getenv("CST_TIMER_DIAG")) {
        fprintf(stderr, "[stimer] FIRE spec=%d vtp=%d stimecmp=0x%llx\n",
                (int)CPU(cpu)->plugin_spec_mode,
                (int)CPU(cpu)->plugin_spec_vtime_paused,
                (unsigned long long)cpu->env.stimecmp);
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
        return;
    }
#endif
    uint64_t diff, ns_diff, next;
    RISCVAclintMTimerState *mtimer = env->rdtime_fn_arg;
    uint32_t timebase_freq = mtimer->timebase_freq;
    uint64_t rtc_r = env->rdtime_fn(env->rdtime_fn_arg) + delta;

#ifdef CONFIG_PLUGIN
    if (getenv("CST_TIMER_DIAG")) {
        static long last;
        long now = (long)time(NULL);
        if (now != last) {
            last = now;
            fprintf(stderr, "[wtc] t=%ld irq=0x%x timecmp=0x%llx rtc_r=0x%llx "
                    "pc=0x%llx ra=0x%llx -> %s\n", now, timer_irq,
                    (unsigned long long)timecmp, (unsigned long long)rtc_r,
                    (unsigned long long)env->pc,
                    (unsigned long long)env->gpr[1],
                    timecmp <= rtc_r ? "RAISE-now"
                    : timecmp == UINT64_MAX ? "timer_del" : "CLEAR+arm");
        }
    }
#endif
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
/*
 * Reconcile the host stimer/vstimer QEMUTimers + STIP/VSTIP with the architected
 * stimecmp/vstimecmp on the REAL (running) clock.  Re-arm only timers the guest
 * has actually configured: stimecmp/vstimecmp are 0 at reset (the unconfigured
 * sentinel), and riscv_timer_write_timecmp(0) would take the "timecmp <= now"
 * branch and synthesise a pending interrupt the guest never armed.  The caller
 * must be on the correct path (spec mode ended) so driving the IRQ line is safe;
 * BQL is taken if not already held.
 */
static void riscv_plugin_reconcile_timers(CPURISCVState *env)
{
    bool held;

    /*
     * rdtime_fn is wired by the machine's ACLINT mtimer (provide_rdtime);
     * without it there is no time source to evaluate compares against and
     * no mtimer handle to reconcile.
     */
    if (!env->rdtime_fn) {
        return;
    }
    held = bql_locked();
    if (!held) {
        bql_lock();
    }
    if (env->stimer && env->stimecmp != 0) {
        riscv_timer_write_timecmp(env, env->stimer, env->stimecmp,
                                  0, MIP_STIP);
    }
    if (env->vstimer && env->vstimecmp != 0) {
        riscv_timer_write_timecmp(env, env->vstimer, env->vstimecmp,
                                  env->htimedelta, MIP_VSTIP);
    }
    /*
     * The ACLINT machine timer (mip.MTIP) is the hart's clockevent when it
     * has no usable Sstc (e.g. -cpu max,sstc=false: the kernel programs
     * timers through SBI ecalls into M-mode firmware, which writes mtimecmp
     * over MMIO).  Its compare register is device state — never rolled back
     * by the excursion's register-snapshot restore — but its one-shot host
     * QEMUTimer does not re-arm itself, and its expiry cb is deferred by the
     * same excursion gate as stimer/vstimer (or its mip.MTIP raise erased by
     * the restore when the fire races excursion entry).  Without this
     * reconcile the pending MTIP is lost and the guest tick never fires
     * again.  rdtime_fn_arg is the mtimer that owns this hart (the ACLINT is
     * the only in-tree rdtime provider) — the same handle
     * riscv_timer_write_timecmp above dereferences.
     */
    if (env->rdtime_fn_arg) {
        riscv_aclint_mtimer_plugin_resync(env->rdtime_fn_arg,
                                          (uint32_t)env->mhartid);
    }
    if (!held) {
        bql_unlock();
    }
}

/*
 * Wrong-path excursion-exit reconcile (#77).  A WP excursion can perturb the
 * host timers — a stimer cb fires and is deferred, or stimecmp is rolled back
 * by the register-state restore.  Re-arm and re-raise once per excursion,
 * unconditionally, so a firing the cb suppressed is not lost -- correctness
 * does not depend on the cb having recorded that it suppressed one, nor on
 * every way a timer can drift having been enumerated.  Runs at the true
 * excursion-exit boundary
 * (cpu_plugin_spec_vtime_resume), after ticks are re-enabled and spec mode has
 * ended, not at an intermediate fault-skip restore.
 */
void riscv_cpu_plugin_resync_timers(CPUState *cs)
{
    CPURISCVState *env = cpu_env(cs);

    /* Recompute the CPU_INTERRUPT_HARD line from the restored register
     * state when an excursion suppressed (or raced) a line update: the
     * snapshot restore is a raw memcpy and never drives the line, so a
     * raise derived from a rolled-back mip bit would otherwise persist —
     * observably (a stuck line costs the TB loop its BQL fast path), even
     * though the mip-based wake/deliver paths ignore it.
     * riscv_cpu_interrupt is the normal mip-update path's own line logic,
     * idempotent from current state.
     *
     * Unconditional, like the timer reconcile below.  The previous gate
     * (plugin_spec_irq_dirty) only fired when a line drive had actually been
     * observed and suppressed during the excursion, which misses every
     * desync produced by the rollback alone. */
    cs->plugin_spec_irq_dirty = false;
    riscv_cpu_update_mip(env, 0, 0);
    if (getenv("CST_TIMER_DIAG")) {
        fprintf(stderr, "[stimer] RESYNC stimecmp=0x%llx vstimecmp=0x%llx "
                "rdtime=%d%s\n",
                (unsigned long long)env->stimecmp,
                (unsigned long long)env->vstimecmp, env->rdtime_fn != NULL,
                env->vstimecmp == 0 ? " (old:spurious-VSTIP)" : "");
    }
    riscv_plugin_reconcile_timers(env);
}

#endif
