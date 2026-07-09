/*
 * QEMU MIPS interrupt support
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
#include "qemu/main-loop.h"
#include "hw/irq.h"
#include "system/kvm.h"
#include "kvm_mips.h"

static void cpu_mips_irq_request(void *opaque, int irq, int level)
{
    MIPSCPU *cpu = opaque;
    CPUMIPSState *env = &cpu->env;
    CPUState *cs = CPU(cpu);

    if (irq < 0 || irq > 7) {
        return;
    }

    BQL_LOCK_GUARD();

    if (level) {
        env->CP0_Cause |= 1 << (irq + CP0Ca_IP);
    } else {
        env->CP0_Cause &= ~(1 << (irq + CP0Ca_IP));
    }

    if (kvm_enabled() && (irq == 2 || irq == 3)) {
        kvm_mips_set_interrupt(cpu, irq, level);
    }

#ifdef CONFIG_PLUGIN
    /*
     * Wrong-path (speculative) or the fault-skip gap inside one: the
     * CP0_Cause.IP bits above are register state that the walk-end restore
     * reverts, but driving CPU_INTERRUPT_HARD is an external side effect
     * that would escape the discarded path -- leaving the line raised from
     * an IP bit the restore then erases.  Defer the line drive; the
     * excursion-exit resync recomputes it from the restored CP0_Cause
     * (mirror of the riscv path, #77).
     */
    if (cs->plugin_spec_mode || cs->plugin_spec_vtime_paused) {
        cs->plugin_spec_irq_dirty = true;
        return;
    }
#endif
    if (env->CP0_Cause & CP0Ca_IP_mask) {
        cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    } else {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    }
}

#ifdef CONFIG_PLUGIN
/* Recompute CPU_INTERRUPT_HARD from the restored CP0_Cause after a
 * wrong-path excursion suppressed a line update (#77).  Called from
 * mips_cpu_plugin_resync_timers at the excursion-exit boundary. */
void cpu_mips_plugin_reconcile_irq(CPUMIPSState *env)
{
    CPUState *cs = env_cpu(env);
    if (env->CP0_Cause & CP0Ca_IP_mask) {
        cpu_interrupt(cs, CPU_INTERRUPT_HARD);
    } else {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    }
}
#endif

void cpu_mips_irq_init_cpu(MIPSCPU *cpu)
{
    CPUMIPSState *env = &cpu->env;
    qemu_irq *qi;
    int i;

    qi = qemu_allocate_irqs(cpu_mips_irq_request, cpu, 8);
    for (i = 0; i < 8; i++) {
        env->irq[i] = qi[i];
    }
    g_free(qi);
}

void cpu_mips_soft_irq(CPUMIPSState *env, int irq, int level)
{
    if (irq < 0 || irq > 2) {
        return;
    }

    qemu_set_irq(env->irq[irq], level);
}
