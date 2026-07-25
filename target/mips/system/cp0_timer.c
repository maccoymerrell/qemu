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

/* MIPS R4K timer */
static uint32_t cpu_mips_get_count_val(CPUMIPSState *env)
{
    int64_t now_ns;
    now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    return env->CP0_Count +
            (uint32_t)clock_ns_to_ticks(env->count_clock, now_ns);
}

static void cpu_mips_timer_update(CPUMIPSState *env)
{
    uint64_t now_ns, next_ns;
    uint32_t wait;

    now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    wait = env->CP0_Compare - cpu_mips_get_count_val(env);
    /* Clamp interval to overflow if virtual time had not progressed */
    if (!wait) {
        wait = UINT32_MAX;
    }
    next_ns = now_ns + clock_ticks_to_ns(env->count_clock, wait);
    timer_mod(env->timer, next_ns);
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
        env->CP0_Cause |= 1 << CP0Ca_TI;
    }
    qemu_irq_raise(env->irq[(env->CP0_IntCtl >> CP0IntCtl_IPTI) & 0x7]);
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
        return env->CP0_Count;
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

void cpu_mips_store_count(CPUMIPSState *env, uint32_t count)
{
    /*
     * This gets called from cpu_state_reset(), potentially before timer init.
     * So env->timer may be NULL, which is also the case with KVM enabled so
     * treat timer as disabled in that case.
     */
    if (env->CP0_Cause & (1 << CP0Ca_DC) || !env->timer) {
        env->CP0_Count = count;
    } else {
        /* Store new count register */
        env->CP0_Count = count - (uint32_t)clock_ns_to_ticks(env->count_clock,
                        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
        /* Update timer timer */
        cpu_mips_timer_update(env);
    }
}

void cpu_mips_store_compare(CPUMIPSState *env, uint32_t value)
{
    env->CP0_Compare = value;
    if (!(env->CP0_Cause & (1 << CP0Ca_DC))) {
        cpu_mips_timer_update(env);
    }
    if (env->insn_flags & ISA_MIPS_R2) {
        env->CP0_Cause &= ~(1 << CP0Ca_TI);
    }
    qemu_irq_lower(env->irq[(env->CP0_IntCtl >> CP0IntCtl_IPTI) & 0x7]);
}

void cpu_mips_start_count(CPUMIPSState *env)
{
    cpu_mips_store_count(env, env->CP0_Count);
}

void cpu_mips_stop_count(CPUMIPSState *env)
{
    /* Store the current value */
    env->CP0_Count += (uint32_t)clock_ns_to_ticks(env->count_clock,
                        qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL));
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
