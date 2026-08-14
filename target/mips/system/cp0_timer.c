/*
 * QEMU MIPS timer support
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "hw/irq.h"
#include "qemu/timer.h"
#include "system/kvm.h"
#include "internal.h"

/*
 * The Count time base this VPE reads and writes.
 *
 * MIPS MT: Count belongs to the PROCESSOR, not to a VPE.  malta_mips_config()
 * advertises the vCPUs of an `-smp N` malta as the VPEs of ONE MT processor
 * (MVPConf0.PVPE), every one of them shares VPE 0's CPUMIPSMVPContext, and the
 * guest reads that single counter as the machine's clocksource -- Linux
 * registers it as "MIPS", 32 bits, and reads it with mfc0 $9 on whichever CPU
 * happens to be running.  A clocksource has to be monotonic across the CPUs
 * that read it.
 *
 * Per-VPE storage cannot be: the field is an OFFSET from the virtual clock, so
 * one instant reads as a different time on every VPE whose offset differs, and
 * the offsets do not stay equal because the guest writes Count.
 * synchronise_count_master()/_slave() has every CPU store the same value "all
 * at once", which on MT hardware is one register and is therefore exact; with
 * one field per vCPU each store landed whenever that vCPU thread happened to
 * be scheduled and moved only itself.  Measured on a Linux 6.6 malta -smp 4
 * guest that had just printed "Synchronize counters for CPU 1..3: done.", one
 * instant read 0x2e8126d5 / 0x2e8171f0 / 0x2e8128ad / 0x2e8126ca on VPEs 0..3:
 * a spread of 19,227 ticks, 120 us at the Malta 160 MHz count rate, and
 * permanent for the rest of the run.  Over 295 boots every single one was
 * incoherent, median 1,940 ticks and worst 20,833.  A clocksource read that
 * moves backwards makes the guest's clocksource_delta() return 0, so its
 * timekeeping stops advancing for the width of the skew each time it migrates
 * onto a lagging VPE.
 *
 * Storing the base once, in the shared MVP context, is what makes every VPE
 * read the same instant by construction; keeping it in step by copying between
 * per-VPE fields cannot, because two VPEs storing Count concurrently leave
 * whichever copy each wrote last (measured: a residual of up to 247 ticks).
 * CPUMIPSState::CP0_Count is still written as the migration/gdbstub view of
 * the register, and remains the storage on a CPU without the MT ASE.
 */
static int32_t *mips_count_base(CPUMIPSState *env)
{
    if (ase_mt_available(env) && env->mvp) {
        return &env->mvp->CP0_Count;
    }
    return &env->CP0_Count;
}

/* MIPS R4K timer */
uint32_t cpu_mips_get_count_val_raw(CPUMIPSState *env, int64_t now_ns)
{
    return qatomic_read(mips_count_base(env)) +
            (uint32_t)clock_ns_to_ticks(env->count_clock, now_ns);
}

static uint32_t cpu_mips_get_count_val(CPUMIPSState *env)
{
    return cpu_mips_get_count_val_raw(env,
                                      qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
}

static void cpu_mips_timer_update(CPUMIPSState *env)
{
    uint64_t now_ns, next_ns;
    uint32_t wait;
    int op;

    now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    wait = env->CP0_Compare - cpu_mips_get_count_val_raw(env, now_ns);
    op = MIPS_CP0T_ARM;
    /* Clamp interval to overflow if virtual time had not progressed */
    if (!wait) {
        op = MIPS_CP0T_ARM_WRAP;
        wait = UINT32_MAX;
    } else if (wait > INT32_MAX) {
        op = MIPS_CP0T_ARM_BEHIND;
        /*
         * The target is BEHIND Count: architectural equality-match
         * semantics say "fire at the wrap", a full ~2^32 ticks away.  Real
         * silicon only ever gets here transiently (a guest's next-event
         * write races Count by nanoseconds and its -ETIME readback
         * recovers); under TCG the guest's read-Count -> write-Compare
         * window costs wall (= virtual) time that can exceed small deltas
         * entirely — most of all while boot code is still being
         * translated — so the OS's bounded retries can ALL land behind
         * Count, its clockevent dies, and the CPU parks in idle until the
         * wrap fires or a cross-CPU rescue arrives (observed on Malta SMP,
         * Linux 6.6: a ~21 s RCU-stall-and-NMI tick outage on every boot,
         * and a permanent-at-timescale guest wedge when both CPUs are
         * caught at once).  Re-arm such a deadline at 2^24 ticks (~0.1 s
         * at Malta rates) instead: every parked state — a missed program,
         * an acknowledge rewrite awaiting its follow-up program, a stale
         * Compare after a Count write — self-heals at a bounded, far-sub-
         * tick-storm cadence, while every legitimate future program (OS
         * contract: delta <= 2^31 - 1) is untouched.  A real reprogram
         * replaces this deadline long before it fires.
         */
        wait = 1 << 24;
    }
    next_ns = now_ns + clock_ticks_to_ns(env->count_clock, wait);
    timer_mod(env->timer, next_ns);
    if (unlikely(mips_mvp_debug > 0)) {
        mips_mvp_note_timer(env, op, wait, now_ns, next_ns);
    }
}

/* Expire the timer.  */
static void cpu_mips_timer_expire(CPUMIPSState *env)
{
#ifdef CONFIG_PLUGIN
    /*
     * Wrong-path (speculative): don't set CP0_Cause[TI], drive the timer IRQ
     * line, or reprogram the host timer on the discarded path.  CP0_Cause is in
     * the register snapshot and is rolled back, but the IRQ line and the host
     * QEMUTimer are external state that is not.  This callback may be the host
     * timer firing mid-excursion; flag it so the expiry is re-delivered on exit
     * (mips_cpu_plugin_resync_timers) instead of being lost — the raise must
     * not be dropped, and re-arming alone would park the timer a full Count
     * wrap out (wait = Compare - Count computes ~0 -> clamps to UINT32_MAX).
     *
     * Gate on plugin_spec_vtime_paused (true for the WHOLE excursion), not
     * just plugin_spec_mode: a wrong-path fault-skip briefly clears spec_mode
     * (spec_mode_end -> restore -> spec_mode_begin) while the snapshot is
     * still live, and a Cause.TI/IP set in that gap is erased by the final
     * walk-end restore (mirror of the riscv stimer/aclint-mtimer gates, #77).
     */
    if (env_cpu(env)->plugin_spec_mode ||
        env_cpu(env)->plugin_spec_vtime_paused) {
        env_cpu(env)->plugin_spec_timer_dirty = true;
        env->plugin_spec_timer_expired = true;
        return;
    }
#endif
    cpu_mips_timer_update(env);
    if (env->insn_flags & ISA_MIPS_R2) {
        /* Atomic: this runs on the iothread, the guest clears it from its
         * own vCPU thread, and both touch the whole Cause word. */
        qatomic_or(&env->CP0_Cause, 1 << CP0Ca_TI);
    }
    qemu_irq_raise(env->irq[(env->CP0_IntCtl >> CP0IntCtl_IPTI) & 0x7]);
    if (unlikely(mips_mvp_debug > 0)) {
        mips_mvp_note_timer(env, MIPS_CP0T_FIRE, 0,
                            qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL), 0);
    }
}

#ifdef CONFIG_PLUGIN
/*
 * Reconcile the host R4K timer with the architected CP0_Count/Compare after a
 * wrong-path excursion (no-op unless the excursion dirtied the timer).  Called
 * from cpu_plugin_spec_vtime_resume — the true excursion-exit boundary, with
 * spec mode ended and the BQL held (a re-delivered expiry raises the timer IRQ
 * line through cpu_mips_irq_request, which expects the BQL).
 */
void mips_cpu_plugin_resync_timers(CPUState *cs)
{
    CPUMIPSState *env = cpu_env(cs);
    bool expired;

    /* Reconcile the interrupt line from restored CP0_Cause first: an
     * excursion (or its fault-skip gap) can suppress a line update while
     * the register snapshot is live, leaving the line stuck relative to
     * the restored IP bits (#77).  Idempotent; independent of the timer.
     * Unconditional, like the timer reconcile below: the previous gate
     * (plugin_spec_irq_dirty) only fired when a line drive had actually been
     * observed and suppressed, missing every desync the rollback produced on
     * its own. */
    cs->plugin_spec_irq_dirty = false;
    cpu_mips_plugin_reconcile_irq(env);

    cs->plugin_spec_timer_dirty = false;
    expired = env->plugin_spec_timer_expired;
    env->plugin_spec_timer_expired = false;

    if (env->timer && !(env->CP0_Cause & (1 << CP0Ca_DC))) {
        if (expired) {
            /*
             * The host timer genuinely expired mid-excursion and its delivery
             * was deferred by the gate in cpu_mips_timer_expire.  Re-deliver
             * it on the correct path — set Cause.TI, raise the timer IRQ
             * line, and re-arm — the same sequence a normal expiry runs.
             * cpu_mips_timer_update alone would lose the raise and, with
             * Count sitting at Compare, re-arm a full Count wrap (~2^32
             * ticks) in the future: a lost guest tick and a stalled
             * clockevent until the wraparound.
             */
            cpu_mips_timer_expire(env);
        } else {
            /* Only Count/Compare were rolled back (a speculative CP0 write
             * erased); re-arm the host deadline from the restored values. */
            cpu_mips_timer_update(env);
        }
    }
}
#endif

uint32_t cpu_mips_get_count(CPUMIPSState *env)
{
    if (env->CP0_Cause & (1 << CP0Ca_DC)) {
        return qatomic_read(mips_count_base(env));
    } else {
        uint64_t now_ns;

        now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        if (timer_pending(env->timer)
            && timer_expired(env->timer, now_ns)) {
            /* The timer has already expired.  */
            cpu_mips_timer_expire(env);
        }

        return cpu_mips_get_count_val(env);
    }
}

/*
 * A store of Count is a store to one register: every VPE sharing this
 * processor's base computes its own deadline from it, so all of them are
 * re-armed, not just the VPE that stored.  Their CPUMIPSState::CP0_Count
 * mirrors are refreshed at the same time, because that mirror is what
 * vmstate_mips_cpu saves.
 */
static void mips_count_rearm_siblings(CPUMIPSState *env)
{
    CPUState *cs;

    if (!ase_mt_available(env) || !env->mvp) {
        return;
    }
    CPU_FOREACH(cs) {
        CPUMIPSState *other = &MIPS_CPU(cs)->env;

        if (other == env || other->mvp != env->mvp || !other->timer) {
            continue;
        }
        other->CP0_Count = qatomic_read(&env->mvp->CP0_Count);
        if (!(other->CP0_Cause & (1 << CP0Ca_DC))) {
            cpu_mips_timer_update(other);
        }
    }
}

void cpu_mips_store_count(CPUMIPSState *env, uint32_t count)
{
    /*
     * This gets called from cpu_state_reset(), potentially before timer init.
     * So env->timer may be NULL, which is also the case with KVM enabled so
     * treat timer as disabled in that case.
     */
    if (env->CP0_Cause & (1 << CP0Ca_DC) || !env->timer) {
        env->CP0_Count = count;
        qatomic_set(mips_count_base(env), count);
    } else {
        /* Store new count register */
        env->CP0_Count = count - (uint32_t)clock_ns_to_ticks(env->count_clock,
                        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        qatomic_set(mips_count_base(env), env->CP0_Count);
        /* Update timer timer */
        cpu_mips_timer_update(env);
        mips_count_rearm_siblings(env);
    }
}

void cpu_mips_store_compare(CPUMIPSState *env, uint32_t value)
{
    env->CP0_Compare = value;
    if (!(env->CP0_Cause & (1 << CP0Ca_DC))) {
        cpu_mips_timer_update(env);
    }
    if (env->insn_flags & ISA_MIPS_R2) {
        qatomic_and(&env->CP0_Cause, ~(1 << CP0Ca_TI));
    }
    qemu_irq_lower(env->irq[(env->CP0_IntCtl >> CP0IntCtl_IPTI) & 0x7]);
}

void cpu_mips_start_count(CPUMIPSState *env)
{
    cpu_mips_store_count(env, qatomic_read(mips_count_base(env)));
}

void cpu_mips_stop_count(CPUMIPSState *env)
{
    /* Store the current value */
    env->CP0_Count = qatomic_read(mips_count_base(env)) +
        (uint32_t)clock_ns_to_ticks(env->count_clock,
                                    qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
    qatomic_set(mips_count_base(env), env->CP0_Count);
}

/*
 * vmstate_mips_cpu saves CPUMIPSState::CP0_Count, so a loaded machine has the
 * per-VPE mirrors but not the shared base they are mirrors of.  Seed it.
 */
void cpu_mips_restore_count_base(CPUMIPSState *env)
{
    qatomic_set(mips_count_base(env), env->CP0_Count);
}

static void mips_timer_cb(void *opaque)
{
    CPUMIPSState *env;

    env = opaque;

    if (env->CP0_Cause & (1 << CP0Ca_DC)) {
        return;
    }

    cpu_mips_timer_expire(env);
}

void cpu_mips_clock_init(MIPSCPU *cpu)
{
    CPUMIPSState *env = &cpu->env;

    /*
     * If we're in KVM mode, don't create the periodic timer, that is handled in
     * kernel.
     */
    if (!kvm_enabled()) {
        env->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, &mips_timer_cb, env);
    }
}
