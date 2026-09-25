/*
 * QEMU MIPS CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "internal.h"
#include "exec/cputlb.h"

/* Called for updates to CP0_Status.  */
void sync_c0_status(CPUMIPSState *env, CPUMIPSState *cpu, int tc)
{
    int32_t tcstatus, *tcst;
    uint32_t v = cpu->CP0_Status;
    uint32_t cu, mx, asid, ksu;
    uint32_t mask = ((1 << CP0TCSt_TCU3)
                       | (1 << CP0TCSt_TCU2)
                       | (1 << CP0TCSt_TCU1)
                       | (1 << CP0TCSt_TCU0)
                       | (1 << CP0TCSt_TMX)
                       | (3 << CP0TCSt_TKSU)
                       | (0xff << CP0TCSt_TASID));

    cu = (v >> CP0St_CU0) & 0xf;
    mx = (v >> CP0St_MX) & 0x1;
    ksu = (v >> CP0St_KSU) & 0x3;
    asid = env->CP0_EntryHi & env->CP0_EntryHi_ASID_mask;

    tcstatus = cu << CP0TCSt_TCU0;
    tcstatus |= mx << CP0TCSt_TMX;
    tcstatus |= ksu << CP0TCSt_TKSU;
    tcstatus |= asid;

    if (tc == cpu->current_tc) {
        tcst = &cpu->active_tc.CP0_TCStatus;
    } else {
        tcst = &cpu->tcs[tc].CP0_TCStatus;
    }

    *tcst &= ~mask;
    *tcst |= tcstatus;
    compute_hflags(cpu);
}

void cpu_mips_store_status(CPUMIPSState *env, target_ulong val)
{
    uint32_t mask = env->CP0_Status_rw_bitmask;
    target_ulong old = env->CP0_Status;

    if (env->insn_flags & ISA_MIPS_R6) {
        bool has_supervisor = extract32(mask, CP0St_KSU, 2) == 0x3;
#if defined(TARGET_MIPS64)
        uint32_t ksux = (1 << CP0St_KX) & val;
        ksux |= (ksux >> 1) & val; /* KX = 0 forces SX to be 0 */
        ksux |= (ksux >> 1) & val; /* SX = 0 forces UX to be 0 */
        val = (val & ~(7 << CP0St_UX)) | ksux;
#endif
        if (has_supervisor && extract32(val, CP0St_KSU, 2) == 0x3) {
            mask &= ~(3 << CP0St_KSU);
        }
        mask &= ~(((1 << CP0St_SR) | (1 << CP0St_NMI)) & val);
    }

    env->CP0_Status = (old & ~mask) | (val & mask);
#if defined(TARGET_MIPS64)
    if ((env->CP0_Status ^ old) & (old & (7 << CP0St_UX))) {
        /* Access to at least one of the 64-bit segments has been disabled */
        tlb_flush(env_cpu(env));
    }
#endif
    if (ase_mt_available(env)) {
        sync_c0_status(env, env, env->current_tc);
    } else {
        compute_hflags(env);
    }
}

/*
 * Count of guest CP0_Cause writes that raced a concurrent update of the same
 * word from another thread.  Every one of these was, before the compare-and-
 * swap below, a silently lost interrupt-pending bit.  Reported by MVPTIMER's
 * siblings under MIPS_MVP_DEBUG; the retry itself is unconditional.
 */
static uint64_t mvp_cause_cas_retries;

uint64_t mips_cause_cas_retries(void)
{
    return qatomic_read(&mvp_cause_cas_retries);
}

void cpu_mips_store_cause(CPUMIPSState *env, target_ulong val)
{
    uint32_t mask = 0x00C00300;
    uint32_t old, new;
    int i;

    if (env->insn_flags & ISA_MIPS_R2) {
        mask |= 1 << CP0Ca_DC;
    }
    if (env->insn_flags & ISA_MIPS_R6) {
        mask &= ~((1 << CP0Ca_WP) & val);
    }

    /*
     * Compare-and-swap, not a plain read-modify-write.
     *
     * @mask covers only the software-writable bits; IP7..IP2, and Cause.TI,
     * are driven by hardware -- the i8259/CBUS lines and the CP0 timer -- and
     * in QEMU that hardware is the iothread, running concurrently with this
     * vCPU.  A plain "Cause = (Cause & ~mask) | (val & mask)" reads the word,
     * computes, and writes it back; a device raise that lands in that window
     * is overwritten and the guest never sees the interrupt.  It then waits
     * for a wakeup that has already been delivered and lost, and sleeps to
     * its clockevent ceiling.
     *
     * This is reachable from a peer VPE too: Linux MIPS vsmp sends every IPI
     * as write_vpe_c0_cause(read_vpe_c0_cause() | C_SW0), which arrives here
     * through helper_mttc0_cause() writing ANOTHER vCPU's CP0_Cause.
     */
    do {
        old = qatomic_read(&env->CP0_Cause);
        new = (old & ~mask) | (val & mask);
        if (new == old) {
            break;
        }
        if (qatomic_cmpxchg(&env->CP0_Cause, old, new) == old) {
            break;
        }
        qatomic_inc(&mvp_cause_cas_retries);
    } while (true);

    if ((old ^ new) & (1 << CP0Ca_DC)) {
        if (env->CP0_Cause & (1 << CP0Ca_DC)) {
            cpu_mips_stop_count(env);
        } else {
            cpu_mips_start_count(env);
        }
    }

    /* Set/reset software interrupts */
    for (i = 0 ; i < 2 ; i++) {
        if ((old ^ new) & (1 << (CP0Ca_IP + i))) {
            cpu_mips_soft_irq(env, i, env->CP0_Cause & (1 << (CP0Ca_IP + i)));
        }
    }
}
