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
 * MIPS MT: Count belongs to the processor, not to a VPE.  malta_mips_config()
 * advertises the vCPUs of an `-smp N` malta as the VPEs of one MT processor
 * (MVPConf0.PVPE), every one of them shares VPE 0's CPUMIPSMVPContext, and a
 * Linux guest reads that single counter as its clocksource on whichever CPU
 * happens to run, so it must be monotonic across VPEs.  The stored value is
 * an offset from the virtual clock; one offset per VPE would read one instant
 * as a different time on each VPE once the guest writes Count, and a
 * backwards read through Linux's 32-bit clocksource mask is a forward jump of
 * one full wrap.  Storing the base once, in the shared MVP context, makes
 * every VPE read the same instant by construction.  CPUMIPSState::CP0_Count
 * is still written as the migration/gdbstub view of the register, and remains
 * the storage on a CPU without the MT ASE.
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
    if (wait == 0 || wait > INT32_MAX) {
        op = MIPS_CP0T_ARM_BEHIND;
        /*
         * Compare is behind Count, or equal to it: the next equality match
         * is a full ~2^32 ticks away (26.8 s at the Malta 160 MHz count
         * rate).  Under TCG a guest's read-Count -> write-Compare window can
         * exceed a small delta, and a program that lands at or behind Count
         * with no readback-and-retry would park that VPE's tick for the whole
         * wrap.  Such a deadline is re-armed 2^24 ticks (~0.1 s) out instead;
         * every legitimate future program (delta <= 2^31 - 1) is untouched,
         * and a real reprogram replaces this deadline long before it fires.
         * When it does fire, cpu_mips_timer_expire raises the timer interrupt
         * while Count != Compare, which the architecture would not do before
         * the wrap.
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
     * QEMUTimer are external state that is not.
     *
     * Nothing is recorded for a later replay.  Inside an excursion this is not
     * the timer list's callback path: a QEMU_CLOCK_VIRTUAL timer is never
     * popped while the excursion holds that clock's processing stall.  What can
     * still reach it is cpu_mips_get_count, noticing an already-elapsed deadline
     * while a wrong-path mfc0 reads Count -- and that path does not pop the
     * timer either, so whatever the gate declines is still on the active list,
     * still armed, and delivered by the first timer pass after the thaw.
     * Nothing is owed, so nothing needs recording for a replay to pay back.
     *
     * Gate on plugin_excursion_active (true for the WHOLE excursion), not
     * just plugin_spec_mode: spec mode is clear at the excursion's edges
     * (before qemu_plugin_spec_mode_begin, and after qemu_plugin_spec_mode_end
     * until the register restore) while the snapshot is live, and a
     * Cause.TI/IP set there is erased by the walk-end restore.
     */
    if (env_cpu(env)->plugin_spec_mode ||
        env_cpu(env)->plugin_excursion_active) {
        return;
    }
#endif
    cpu_mips_timer_update(env);
    if (env->insn_flags & ISA_MIPS_R2) {
        /*
         * Atomic: this runs on the iothread, the guest clears it from its
         * own vCPU thread, and both touch the whole Cause word.
         */
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
 * wrong-path excursion.  Runs on every excursion exit, including ones that
 * disturbed nothing, and is idempotent on an already consistent timer.  Called
 * from cpu_plugin_excursion_close -- the true excursion-exit boundary, with
 * spec mode ended and the BQL held (a re-delivered expiry raises the timer IRQ
 * line through cpu_mips_irq_request, which expects the BQL).
 */
void mips_cpu_plugin_resync_timers(CPUState *cs)
{
    CPUMIPSState *env = cpu_env(cs);

    /*
     * Reconcile the interrupt line from restored CP0_Cause first: an
     * excursion can suppress a line update while
     * the register snapshot is live, leaving the line stuck relative to
     * the restored IP bits.  Idempotent; independent of the timer.
     * Unconditional, like the timer reconcile below: gating it on "a line
     * drive was observed and suppressed" misses every desync the rollback
     * produced on its own, so there is no gate.
     */
    cpu_mips_plugin_reconcile_irq(env);

    /*
     * Re-arm the host deadline from the restored CP0_Count/Compare.  There is
     * no expiry to replay: an expiry the gate declined to deliver is one the
     * timer list never popped, so it is still armed and still owed to the
     * guest by the timer list itself.
     */
    if (env->timer && !(env->CP0_Cause & (1 << CP0Ca_DC))) {
        cpu_mips_timer_update(env);
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
