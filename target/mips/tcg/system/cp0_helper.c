/*
 *  Helpers for emulation of CP0-related MIPS instructions.
 *
 *  Copyright (C) 2004-2005  Jocelyn Mayer
 *  Copyright (C) 2020  Wave Computing, Inc.
 *  Copyright (C) 2020  Aleksandar Markovic <amarkovic@wavecomp.com>
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
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "internal.h"
#include "qemu/host-utils.h"
#include "exec/helper-proto.h"
#include "exec/cputlb.h"


/*
 * CST_CP0_AUDIT: temporary empirical audit of the CP0 registers a guest
 * kernel writes at context-switch time (Context PTEBase, EntryHi ASID,
 * MemoryMapID).  Gated off unless the environment variable is set; used
 * to establish what the staged Linux guests actually program so the
 * plugin's address-space identity can be grounded in observed writes.
 */
static bool cst_cp0_audit(void)
{
    static int on = -1;
    if (on < 0) {
        on = getenv("CST_CP0_AUDIT") ? 1 : 0;
    }
    return on;
}

/* SMP helpers.  */
static bool mips_vpe_is_wfi(MIPSCPU *c)
{
    CPUState *cpu = CPU(c);
    CPUMIPSState *env = &c->env;

    /*
     * If the VPE is halted but otherwise active, it means it's waiting for
     * an interrupt.\
     */
    return cpu->halted && mips_vpe_active(env);
}

static bool mips_vp_is_wfi(MIPSCPU *c)
{
    CPUState *cpu = CPU(c);
    CPUMIPSState *env = &c->env;

    return cpu->halted && mips_vp_active(env);
}

static inline void mips_vpe_wake(MIPSCPU *c, int why)
{
#ifdef CONFIG_PLUGIN
    /* Wrong-path: don't poke another VPE's global interrupt/run state. */
    if (CPU(c)->plugin_spec_mode) {
        return;
    }
#endif
    /*
     * Don't set ->halted = 0 directly, let it be done via cpu_has_work
     * because there might be other conditions that state that c should
     * be sleeping.
     */
    if (unlikely(mips_mvp_debug > 0)) {
        mips_mvp_note_run(CPU(c), why);
    }
    bql_lock();
    cpu_interrupt(CPU(c), CPU_INTERRUPT_WAKE);
    bql_unlock();
}

static inline void mips_vpe_sleep(MIPSCPU *cpu, int why)
{
    CPUState *cs = CPU(cpu);

#ifdef CONFIG_PLUGIN
    /* Wrong-path: don't halt the VPE or clear its wake request. */
    if (cs->plugin_spec_mode) {
        return;
    }
#endif
    /*
     * The VPE was shut off, really go to bed.
     * Reset any old _WAKE requests.
     */
    if (unlikely(mips_mvp_debug > 0)) {
        mips_mvp_note_run(cs, why);
    }
    cs->halted = 1;
    cpu_reset_interrupt(cs, CPU_INTERRUPT_WAKE);
}

/*
 * Is this VPE's OWN thread state activated -- mips_vpe_active() without the
 * processor-wide MVPControl.EVP term.
 *
 * The two questions are not interchangeable.  EVP says whether the whole
 * processor may issue right now, and it is 0 for every VPE inside any DVPE
 * section; VPA / TCStatus.A / TCHalt say whether this particular VPE and
 * thread context are enabled at all.  Only the second is a property of the
 * TC whose registers are being written.
 */
static bool mips_vpe_tc_activated(CPUMIPSState *env)
{
    return (env->CP0_VPEConf0 & (1 << CP0VPEC0_VPA))
        && (env->active_tc.CP0_TCStatus & (1 << CP0TCSt_A))
        && !(env->active_tc.CP0_TCHalt & 1);
}

/*
 * Reacting to a write of a TC's own halt/activation state.
 *
 * These asked mips_vpe_active(), which folds in EVP -- and MIPS MT requires
 * VPEs to be disabled before a VPE may touch another's TC registers, so
 * every one of these writes arrives with EVP already 0.  Both answers were
 * therefore constants inside the only window they are reached from:
 *
 *   - mips_tc_sleep() halted the VPE unconditionally.  Through
 *     helper_mtc0_tchalt() that VPE is the caller itself, so a VPE that had
 *     just executed DVPE put ITSELF to sleep in the middle of its own
 *     section, before the EVPE that would re-enable the processor.  Nothing
 *     could reschedule it, because mips_cpu_has_work() gates on the same
 *     EVP it had cleared, so the machine stopped with the restore still
 *     owed -- the residual malta -smp 4 boot wedge.
 *   - mips_tc_wake() woke nobody, so a TC that the guest un-halted inside a
 *     section was never scheduled, and an IPI delivered to it was never
 *     collected: "Unable to send backtrace IPI to CPU0 - perhaps it hung?".
 *
 * The processor-wide gate is not theirs to apply.  mips_cpu_has_work()
 * already holds every VPE off the run queue while EVP is clear, and it is
 * the DVPE that cleared EVP which owns waking them again.
 */
static inline void mips_tc_wake(MIPSCPU *cpu, int tc)
{
    CPUMIPSState *c = &cpu->env;

    /* FIXME: TC reschedule.  */
    if (mips_vpe_tc_activated(c) && !mips_vpe_is_wfi(cpu)) {
        mips_vpe_wake(cpu, MIPS_MVP_WAKE_TC);
    }
}

static inline void mips_tc_sleep(MIPSCPU *cpu, int tc)
{
    CPUMIPSState *c = &cpu->env;

    /* FIXME: TC reschedule.  */
    if (!mips_vpe_tc_activated(c)) {
        mips_vpe_sleep(cpu, MIPS_MVP_SLEEP_TC);
    }
}

/**
 * mips_cpu_map_tc:
 * @env: CPU from which mapping is performed.
 * @tc: Should point to an int with the value of the global TC index.
 *
 * This function will transform @tc into a local index within the
 * returned #CPUMIPSState.
 */

/*
 * FIXME: This code assumes that all VPEs have the same number of TCs,
 *        which depends on runtime setup. Can probably be fixed by
 *        walking the list of CPUMIPSStates.
 */
static CPUMIPSState *mips_cpu_map_tc(CPUMIPSState *env, int *tc)
{
    MIPSCPU *cpu;
    CPUState *cs;
    CPUState *other_cs;
    int vpe_idx;
    int tc_idx = *tc;

    if (!(env->CP0_VPEConf0 & (1 << CP0VPEC0_MVP))) {
        /* Not allowed to address other CPUs.  */
        *tc = env->current_tc;
        return env;
    }

    cs = env_cpu(env);
    vpe_idx = tc_idx / cs->nr_threads;
    *tc = tc_idx % cs->nr_threads;
    other_cs = qemu_get_cpu(vpe_idx);
    if (other_cs == NULL) {
        return env;
    }
    cpu = MIPS_CPU(other_cs);
    return &cpu->env;
}

/*
 * The per VPE CP0_Status register shares some fields with the per TC
 * CP0_TCStatus registers. These fields are wired to the same registers,
 * so changes to either of them should be reflected on both registers.
 *
 * Also, EntryHi shares the bottom 8 bit ASID with TCStauts.
 *
 * These helper call synchronizes the regs for a given cpu.
 */

/*
 * Called for updates to CP0_Status.  Defined in "cpu.h" for gdbstub.c.
 * static inline void sync_c0_status(CPUMIPSState *env, CPUMIPSState *cpu,
 *                                   int tc);
 */

/* Called for updates to CP0_TCStatus.  */
static void sync_c0_tcstatus(CPUMIPSState *cpu, int tc,
                             target_ulong v)
{
    uint32_t status;
    uint32_t tcu, tmx, tasid, tksu;
    uint32_t mask = ((1U << CP0St_CU3)
                       | (1 << CP0St_CU2)
                       | (1 << CP0St_CU1)
                       | (1 << CP0St_CU0)
                       | (1 << CP0St_MX)
                       | (3 << CP0St_KSU));

    tcu = (v >> CP0TCSt_TCU0) & 0xf;
    tmx = (v >> CP0TCSt_TMX) & 0x1;
    tasid = v & cpu->CP0_EntryHi_ASID_mask;
    tksu = (v >> CP0TCSt_TKSU) & 0x3;

    status = tcu << CP0St_CU0;
    status |= tmx << CP0St_MX;
    status |= tksu << CP0St_KSU;

    cpu->CP0_Status &= ~mask;
    cpu->CP0_Status |= status;

    /* Sync the TASID with EntryHi.  */
    cpu->CP0_EntryHi &= ~cpu->CP0_EntryHi_ASID_mask;
    cpu->CP0_EntryHi |= tasid;

    compute_hflags(cpu);
}

/* Called for updates to CP0_EntryHi.  */
static void sync_c0_entryhi(CPUMIPSState *cpu, int tc)
{
    int32_t *tcst;
    uint32_t asid, v = cpu->CP0_EntryHi;

    asid = v & cpu->CP0_EntryHi_ASID_mask;

    if (tc == cpu->current_tc) {
        tcst = &cpu->active_tc.CP0_TCStatus;
    } else {
        tcst = &cpu->tcs[tc].CP0_TCStatus;
    }

    *tcst &= ~cpu->CP0_EntryHi_ASID_mask;
    *tcst |= asid;
}

/* XXX: do not use a global */
uint32_t cpu_mips_get_random(CPUMIPSState *env)
{
    static uint32_t seed = 1;
    static uint32_t prev_idx;
    uint32_t idx;
    uint32_t nb_rand_tlb = env->tlb->nb_tlb - env->CP0_Wired;

    if (nb_rand_tlb == 1) {
        return env->tlb->nb_tlb - 1;
    }

#ifdef CONFIG_PLUGIN
    /*
     * Wrong-path (speculative): answer without advancing the generator.
     *
     * seed and prev_idx are file-scope statics, so they are not in
     * CPUArchState at all and cannot be in the region the plugin's
     * speculative snapshot copies -- that region is
     * CPUArchState[0 .. end_reset_fields).  A discarded `mfc0 $Random` would
     * therefore leave the sequence permanently advanced, and the sequence is
     * not decorative: it chooses which entry the correct path's next TLBWR
     * replaces, so a wrong path would change the correct path's TLB
     * replacement pattern and with it the miss stream a trace exists to
     * record.  Tracing a program must not alter the program it traces.
     *
     * nb_tlb - 1 is the value the single-random-entry case above already
     * returns, so it is a legal index by construction; the architecture
     * leaves which one Random reports unspecified, and the wrong path is not
     * entitled to a particular answer -- only to an answer that costs the
     * correct path nothing.  TLBWR itself never arrives here speculatively:
     * helper_tlbwr is gated in tcg/system/tlb_helper.c, so the only
     * speculative caller is the mfc0 read.
     */
    if (env_cpu(env)->plugin_spec_mode) {
        return env->tlb->nb_tlb - 1;
    }
#endif

    /* Don't return same value twice, so get another value */
    do {
        /*
         * Use a simple algorithm of Linear Congruential Generator
         * from ISO/IEC 9899 standard.
         */
        seed = 1103515245 * seed + 12345;
        idx = (seed >> 16) % nb_rand_tlb + env->CP0_Wired;
    } while (idx == prev_idx);
    prev_idx = idx;
    return idx;
}

/* CP0 helpers */
target_ulong helper_mfc0_mvpcontrol(CPUMIPSState *env)
{
    return env->mvp->CP0_MVPControl;
}

target_ulong helper_mfc0_mvpconf0(CPUMIPSState *env)
{
    return env->mvp->CP0_MVPConf0;
}

target_ulong helper_mfc0_mvpconf1(CPUMIPSState *env)
{
    return env->mvp->CP0_MVPConf1;
}

target_ulong helper_mfc0_random(CPUMIPSState *env)
{
    return (int32_t)cpu_mips_get_random(env);
}

target_ulong helper_mfc0_tcstatus(CPUMIPSState *env)
{
    return env->active_tc.CP0_TCStatus;
}

target_ulong helper_mftc0_tcstatus(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.CP0_TCStatus;
    } else {
        return other->tcs[other_tc].CP0_TCStatus;
    }
}

target_ulong helper_mfc0_tcbind(CPUMIPSState *env)
{
    return env->active_tc.CP0_TCBind;
}

target_ulong helper_mftc0_tcbind(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.CP0_TCBind;
    } else {
        return other->tcs[other_tc].CP0_TCBind;
    }
}

target_ulong helper_mfc0_tcrestart(CPUMIPSState *env)
{
    return env->active_tc.PC;
}

target_ulong helper_mftc0_tcrestart(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.PC;
    } else {
        return other->tcs[other_tc].PC;
    }
}

target_ulong helper_mfc0_tchalt(CPUMIPSState *env)
{
    return env->active_tc.CP0_TCHalt;
}

target_ulong helper_mftc0_tchalt(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.CP0_TCHalt;
    } else {
        return other->tcs[other_tc].CP0_TCHalt;
    }
}

target_ulong helper_mfc0_tccontext(CPUMIPSState *env)
{
    return env->active_tc.CP0_TCContext;
}

target_ulong helper_mftc0_tccontext(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.CP0_TCContext;
    } else {
        return other->tcs[other_tc].CP0_TCContext;
    }
}

target_ulong helper_mfc0_tcschedule(CPUMIPSState *env)
{
    return env->active_tc.CP0_TCSchedule;
}

target_ulong helper_mftc0_tcschedule(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.CP0_TCSchedule;
    } else {
        return other->tcs[other_tc].CP0_TCSchedule;
    }
}

target_ulong helper_mfc0_tcschefback(CPUMIPSState *env)
{
    return env->active_tc.CP0_TCScheFBack;
}

target_ulong helper_mftc0_tcschefback(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.CP0_TCScheFBack;
    } else {
        return other->tcs[other_tc].CP0_TCScheFBack;
    }
}

target_ulong helper_mfc0_count(CPUMIPSState *env)
{
    return (int32_t)cpu_mips_get_count(env);
}

target_ulong helper_mftc0_entryhi(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    return other->CP0_EntryHi;
}

target_ulong helper_mftc0_cause(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    return other->CP0_Cause;
}

target_ulong helper_mftc0_status(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    return other->CP0_Status;
}

target_ulong helper_mfc0_lladdr(CPUMIPSState *env)
{
    return (int32_t)(env->CP0_LLAddr >> env->CP0_LLAddr_shift);
}

target_ulong helper_mfc0_maar(CPUMIPSState *env)
{
    return (int32_t) env->CP0_MAAR[env->CP0_MAARI];
}

target_ulong helper_mfhc0_maar(CPUMIPSState *env)
{
    return env->CP0_MAAR[env->CP0_MAARI] >> 32;
}

target_ulong helper_mfc0_watchlo(CPUMIPSState *env, uint32_t sel)
{
    return (int32_t)env->CP0_WatchLo[sel];
}

target_ulong helper_mfc0_watchhi(CPUMIPSState *env, uint32_t sel)
{
    return (int32_t) env->CP0_WatchHi[sel];
}

target_ulong helper_mfhc0_watchhi(CPUMIPSState *env, uint32_t sel)
{
    return env->CP0_WatchHi[sel] >> 32;
}

target_ulong helper_mfc0_debug(CPUMIPSState *env)
{
    target_ulong t0 = env->CP0_Debug;
    if (env->hflags & MIPS_HFLAG_DM) {
        t0 |= 1 << CP0DB_DM;
    }

    return t0;
}

target_ulong helper_mftc0_debug(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    int32_t tcstatus;
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        tcstatus = other->active_tc.CP0_Debug_tcstatus;
    } else {
        tcstatus = other->tcs[other_tc].CP0_Debug_tcstatus;
    }

    /* XXX: Might be wrong, check with EJTAG spec. */
    return (other->CP0_Debug & ~((1 << CP0DB_SSt) | (1 << CP0DB_Halt))) |
            (tcstatus & ((1 << CP0DB_SSt) | (1 << CP0DB_Halt)));
}

#if defined(TARGET_MIPS64)
target_ulong helper_dmfc0_tcrestart(CPUMIPSState *env)
{
    return env->active_tc.PC;
}

target_ulong helper_dmfc0_tchalt(CPUMIPSState *env)
{
    return env->active_tc.CP0_TCHalt;
}

target_ulong helper_dmfc0_tccontext(CPUMIPSState *env)
{
    return env->active_tc.CP0_TCContext;
}

target_ulong helper_dmfc0_tcschedule(CPUMIPSState *env)
{
    return env->active_tc.CP0_TCSchedule;
}

target_ulong helper_dmfc0_tcschefback(CPUMIPSState *env)
{
    return env->active_tc.CP0_TCScheFBack;
}

target_ulong helper_dmfc0_lladdr(CPUMIPSState *env)
{
    return env->CP0_LLAddr >> env->CP0_LLAddr_shift;
}

target_ulong helper_dmfc0_maar(CPUMIPSState *env)
{
    return env->CP0_MAAR[env->CP0_MAARI];
}

target_ulong helper_dmfc0_watchlo(CPUMIPSState *env, uint32_t sel)
{
    return env->CP0_WatchLo[sel];
}

target_ulong helper_dmfc0_watchhi(CPUMIPSState *env, uint32_t sel)
{
    return env->CP0_WatchHi[sel];
}

#endif /* TARGET_MIPS64 */

void helper_mtc0_index(CPUMIPSState *env, target_ulong arg1)
{
    uint32_t index_p = env->CP0_Index & 0x80000000;
    uint32_t tlb_index = arg1 & 0x7fffffff;
    if (tlb_index < env->tlb->nb_tlb) {
        if (env->insn_flags & ISA_MIPS_R6) {
            index_p |= arg1 & 0x80000000;
        }
        env->CP0_Index = index_p | tlb_index;
    }
}

void helper_mtc0_mvpcontrol(CPUMIPSState *env, target_ulong arg1)
{
    uint32_t mask = 0;
    int32_t oldval, newval;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes the shared MVP context (env->mvp), out of snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    /*
     * MVPControl is shared by every VPE of the processor, so this masked
     * read-modify-write races the EVP bit that DVPE/EVPE own.  A plain
     * load-modify-store would publish a whole word computed from a stale
     * sample and silently undo a sibling's EVPE; the compare-exchange makes
     * the write conditional on nothing having moved underneath it.  The
     * STLB clause of the mask is recomputed each attempt because it is
     * itself a function of the value being replaced.
     */
    do {
        oldval = qatomic_read(&env->mvp->CP0_MVPControl);
        mask = 0;
        if (env->CP0_VPEConf0 & (1 << CP0VPEC0_MVP)) {
            mask |= (1 << CP0MVPCo_CPA) | (1 << CP0MVPCo_VPC) |
                    (1 << CP0MVPCo_EVP);
        }
        if (oldval & (1 << CP0MVPCo_VPC)) {
            mask |= (1 << CP0MVPCo_STLB);
        }
        newval = (oldval & ~mask) | (arg1 & mask);

        /* TODO: Enable/disable shared TLB, enable/disable VPEs. */
    } while (qatomic_cmpxchg(&env->mvp->CP0_MVPControl,
                             oldval, newval) != oldval);

    /*
     * EVP means the same thing however it was written, so an mtc0 that moves
     * it takes the same ownership as the DVPE or EVPE that would have.  Left
     * out, an mtc0 that cleared EVP would open a section nobody owns -- every
     * VPE reading the bit as its own disable, which is the state this claim
     * exists to prevent.
     */
    if ((oldval ^ newval) & (1 << CP0MVPCo_EVP)) {
        if (newval & (1 << CP0MVPCo_EVP)) {
            qatomic_cmpxchg(&env->mvp->evp_owner,
                            env_cpu(env)->cpu_index, -1);
        } else {
            qatomic_set(&env->mvp->evp_owner, env_cpu(env)->cpu_index);
            if (mips_vpe_tc_activated(env)) {
                env_cpu(env)->halted = 0;   /* see helper_dvpe() */
            }
        }
    }

    mips_mvp_note(env, mask ? MIPS_MVP_MTC0_WR : MIPS_MVP_MTC0_NA,
                  oldval, newval);
}

void helper_mtc0_vpecontrol(CPUMIPSState *env, target_ulong arg1)
{
    uint32_t mask;
    uint32_t newval;

    mask = (1 << CP0VPECo_YSI) | (1 << CP0VPECo_GSI) |
           (1 << CP0VPECo_TE) | (0xff << CP0VPECo_TargTC);
    newval = (env->CP0_VPEControl & ~mask) | (arg1 & mask);

    /*
     * Yield scheduler intercept not implemented.
     * Gating storage scheduler intercept not implemented.
     */

    /* TODO: Enable/disable TCs. */

    env->CP0_VPEControl = newval;
}

void helper_mttc0_vpecontrol(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;
    uint32_t mask;
    uint32_t newval;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    mask = (1 << CP0VPECo_YSI) | (1 << CP0VPECo_GSI) |
           (1 << CP0VPECo_TE) | (0xff << CP0VPECo_TargTC);
    newval = (other->CP0_VPEControl & ~mask) | (arg1 & mask);

    /* TODO: Enable/disable TCs.  */

    other->CP0_VPEControl = newval;
}

target_ulong helper_mftc0_vpecontrol(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);
    /* FIXME: Mask away return zero on read bits.  */
    return other->CP0_VPEControl;
}

target_ulong helper_mftc0_vpeconf0(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    return other->CP0_VPEConf0;
}

void helper_mtc0_vpeconf0(CPUMIPSState *env, target_ulong arg1)
{
    uint32_t mask = 0;
    uint32_t newval;

    if (env->CP0_VPEConf0 & (1 << CP0VPEC0_MVP)) {
        if (env->CP0_VPEConf0 & (1 << CP0VPEC0_VPA)) {
            mask |= (0xff << CP0VPEC0_XTC);
        }
        mask |= (1 << CP0VPEC0_MVP) | (1 << CP0VPEC0_VPA);
    }
    newval = (env->CP0_VPEConf0 & ~mask) | (arg1 & mask);

    /* TODO: TC exclusive handling due to ERL/EXL. */

    env->CP0_VPEConf0 = newval;
}

void helper_mttc0_vpeconf0(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;
    uint32_t mask = 0;
    uint32_t newval;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    mask |= (1 << CP0VPEC0_MVP) | (1 << CP0VPEC0_VPA);
    newval = (other->CP0_VPEConf0 & ~mask) | (arg1 & mask);

    /* TODO: TC exclusive handling due to ERL/EXL.  */
    other->CP0_VPEConf0 = newval;
}

void helper_mtc0_vpeconf1(CPUMIPSState *env, target_ulong arg1)
{
    uint32_t mask = 0;
    uint32_t newval;

    if (env->mvp->CP0_MVPControl & (1 << CP0MVPCo_VPC))
        mask |= (0xff << CP0VPEC1_NCX) | (0xff << CP0VPEC1_NCP2) |
                (0xff << CP0VPEC1_NCP1);
    newval = (env->CP0_VPEConf1 & ~mask) | (arg1 & mask);

    /* UDI not implemented. */
    /* CP2 not implemented. */

    /* TODO: Handle FPU (CP1) binding. */

    env->CP0_VPEConf1 = newval;
}

void helper_mtc0_yqmask(CPUMIPSState *env, target_ulong arg1)
{
    /* Yield qualifier inputs not implemented. */
    env->CP0_YQMask = 0x00000000;
}

void helper_mtc0_vpeopt(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_VPEOpt = arg1 & 0x0000ffff;
}

#define MTC0_ENTRYLO_MASK(env) ((env->PAMask >> 6) & 0x3FFFFFFF)

void helper_mtc0_entrylo0(CPUMIPSState *env, target_ulong arg1)
{
    /* 1k pages not implemented */
    target_ulong rxi = arg1 & (env->CP0_PageGrain & (3u << CP0PG_XIE));
    env->CP0_EntryLo0 = (arg1 & MTC0_ENTRYLO_MASK(env))
                        | (rxi << (CP0EnLo_XI - 30));
}

#if defined(TARGET_MIPS64)
#define DMTC0_ENTRYLO_MASK(env) (env->PAMask >> 6)

void helper_dmtc0_entrylo0(CPUMIPSState *env, uint64_t arg1)
{
    uint64_t rxi = arg1 & ((env->CP0_PageGrain & (3ull << CP0PG_XIE)) << 32);
    env->CP0_EntryLo0 = (arg1 & DMTC0_ENTRYLO_MASK(env)) | rxi;
}
#endif

void helper_mtc0_tcstatus(CPUMIPSState *env, target_ulong arg1)
{
    uint32_t mask = env->CP0_TCStatus_rw_bitmask;
    uint32_t newval;

    newval = (env->active_tc.CP0_TCStatus & ~mask) | (arg1 & mask);

    env->active_tc.CP0_TCStatus = newval;
    sync_c0_tcstatus(env, env->current_tc, newval);
}

void helper_mttc0_tcstatus(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        other->active_tc.CP0_TCStatus = arg1;
    } else {
        other->tcs[other_tc].CP0_TCStatus = arg1;
    }
    sync_c0_tcstatus(other, other_tc, arg1);
}

void helper_mtc0_tcbind(CPUMIPSState *env, target_ulong arg1)
{
    uint32_t mask = (1 << CP0TCBd_TBE);
    uint32_t newval;

    if (env->mvp->CP0_MVPControl & (1 << CP0MVPCo_VPC)) {
        mask |= (1 << CP0TCBd_CurVPE);
    }
    newval = (env->active_tc.CP0_TCBind & ~mask) | (arg1 & mask);
    env->active_tc.CP0_TCBind = newval;
}

void helper_mttc0_tcbind(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    uint32_t mask = (1 << CP0TCBd_TBE);
    uint32_t newval;
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    if (other->mvp->CP0_MVPControl & (1 << CP0MVPCo_VPC)) {
        mask |= (1 << CP0TCBd_CurVPE);
    }
    if (other_tc == other->current_tc) {
        newval = (other->active_tc.CP0_TCBind & ~mask) | (arg1 & mask);
        other->active_tc.CP0_TCBind = newval;
    } else {
        newval = (other->tcs[other_tc].CP0_TCBind & ~mask) | (arg1 & mask);
        other->tcs[other_tc].CP0_TCBind = newval;
    }
}

void helper_mtc0_tcrestart(CPUMIPSState *env, target_ulong arg1)
{
    env->active_tc.PC = arg1;
    env->active_tc.CP0_TCStatus &= ~(1 << CP0TCSt_TDS);
    env->CP0_LLAddr = 0;
    env->lladdr = 0;
    /* MIPS16 not implemented. */
}

void helper_mttc0_tcrestart(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        other->active_tc.PC = arg1;
        other->active_tc.CP0_TCStatus &= ~(1 << CP0TCSt_TDS);
        other->CP0_LLAddr = 0;
        other->lladdr = 0;
        /* MIPS16 not implemented. */
    } else {
        other->tcs[other_tc].PC = arg1;
        other->tcs[other_tc].CP0_TCStatus &= ~(1 << CP0TCSt_TDS);
        other->CP0_LLAddr = 0;
        other->lladdr = 0;
        /* MIPS16 not implemented. */
    }
}

void helper_mtc0_tchalt(CPUMIPSState *env, target_ulong arg1)
{
    MIPSCPU *cpu = env_archcpu(env);

    env->active_tc.CP0_TCHalt = arg1 & 0x1;

    /* TODO: Halt TC / Restart (if allocated+active) TC. */
    if (env->active_tc.CP0_TCHalt & 1) {
        mips_tc_sleep(cpu, env->current_tc);
    } else {
        mips_tc_wake(cpu, env->current_tc);
    }
}

void helper_mttc0_tchalt(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;
    MIPSCPU *other_cpu;

#ifdef CONFIG_PLUGIN
    /*
     * Wrong-path: writes a sibling TC's env and toggles its run state
     * (mips_tc_sleep/wake), both out of this CPU's snapshot.
     */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);
    other_cpu = env_archcpu(other);

    /* TODO: Halt TC / Restart (if allocated+active) TC. */

    if (other_tc == other->current_tc) {
        other->active_tc.CP0_TCHalt = arg1;
    } else {
        other->tcs[other_tc].CP0_TCHalt = arg1;
    }

    if (arg1 & 1) {
        mips_tc_sleep(other_cpu, other_tc);
    } else {
        mips_tc_wake(other_cpu, other_tc);
    }
}

void helper_mtc0_tccontext(CPUMIPSState *env, target_ulong arg1)
{
    env->active_tc.CP0_TCContext = arg1;
}

void helper_mttc0_tccontext(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        other->active_tc.CP0_TCContext = arg1;
    } else {
        other->tcs[other_tc].CP0_TCContext = arg1;
    }
}

void helper_mtc0_tcschedule(CPUMIPSState *env, target_ulong arg1)
{
    env->active_tc.CP0_TCSchedule = arg1;
}

void helper_mttc0_tcschedule(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        other->active_tc.CP0_TCSchedule = arg1;
    } else {
        other->tcs[other_tc].CP0_TCSchedule = arg1;
    }
}

void helper_mtc0_tcschefback(CPUMIPSState *env, target_ulong arg1)
{
    env->active_tc.CP0_TCScheFBack = arg1;
}

void helper_mttc0_tcschefback(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        other->active_tc.CP0_TCScheFBack = arg1;
    } else {
        other->tcs[other_tc].CP0_TCScheFBack = arg1;
    }
}

void helper_mtc0_entrylo1(CPUMIPSState *env, target_ulong arg1)
{
    /* 1k pages not implemented */
    target_ulong rxi = arg1 & (env->CP0_PageGrain & (3u << CP0PG_XIE));
    env->CP0_EntryLo1 = (arg1 & MTC0_ENTRYLO_MASK(env))
                        | (rxi << (CP0EnLo_XI - 30));
}

#if defined(TARGET_MIPS64)
void helper_dmtc0_entrylo1(CPUMIPSState *env, uint64_t arg1)
{
    uint64_t rxi = arg1 & ((env->CP0_PageGrain & (3ull << CP0PG_XIE)) << 32);
    env->CP0_EntryLo1 = (arg1 & DMTC0_ENTRYLO_MASK(env)) | rxi;
}
#endif

void helper_mtc0_context(CPUMIPSState *env, target_ulong arg1)
{
    target_ulong old = env->CP0_Context;
    env->CP0_Context = (env->CP0_Context & 0x007FFFFF) | (arg1 & ~0x007FFFFF);
    if (cst_cp0_audit() && old != env->CP0_Context) {
        fprintf(stderr, "[cp0audit] cpu=%d CTX  old=0x%08lx new=0x%08lx "
                "(ptebase 0x%08lx) um=%d\n",
                env_cpu(env)->cpu_index, (unsigned long)old,
                (unsigned long)env->CP0_Context,
                (unsigned long)(env->CP0_Context & ~(target_ulong)0x007FFFFF),
                (int)(env->hflags & MIPS_HFLAG_KSU));
    }
}

void helper_mtc0_memorymapid(CPUMIPSState *env, target_ulong arg1)
{
    int32_t old;
    old = env->CP0_MemoryMapID;
    env->CP0_MemoryMapID = (int32_t) arg1;
    /* If the MemoryMapID changes, flush qemu's TLB.  */
    if (old != env->CP0_MemoryMapID) {
        cpu_mips_tlb_flush(env);
    }
}

uint32_t compute_pagemask(uint32_t val)
{
    /* Don't care MASKX as we don't support 1KB page */
    uint32_t mask = extract32(val, CP0PM_MASK, 16);
    int maskbits = cto32(mask);

    /* Ensure no more set bit after first zero, and maskbits even. */
    if ((mask >> maskbits) == 0 && maskbits % 2 == 0) {
        return mask << CP0PM_MASK;
    } else {
        /* When invalid, set to default target page size. */
        return 0;
    }
}

void helper_mtc0_pagemask(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_PageMask = compute_pagemask(arg1);
}

void helper_mtc0_pagegrain(CPUMIPSState *env, target_ulong arg1)
{
    /* SmartMIPS not implemented */
    /* 1k pages not implemented */
    env->CP0_PageGrain = (arg1 & env->CP0_PageGrain_rw_bitmask) |
                         (env->CP0_PageGrain & ~env->CP0_PageGrain_rw_bitmask);
    compute_hflags(env);
    restore_pamask(env);
}

void helper_mtc0_segctl0(CPUMIPSState *env, target_ulong arg1)
{
    CPUState *cs = env_cpu(env);

    env->CP0_SegCtl0 = arg1 & CP0SC0_MASK;
    tlb_flush(cs);
}

void helper_mtc0_segctl1(CPUMIPSState *env, target_ulong arg1)
{
    CPUState *cs = env_cpu(env);

    env->CP0_SegCtl1 = arg1 & CP0SC1_MASK;
    tlb_flush(cs);
}

void helper_mtc0_segctl2(CPUMIPSState *env, target_ulong arg1)
{
    CPUState *cs = env_cpu(env);

    env->CP0_SegCtl2 = arg1 & CP0SC2_MASK;
    tlb_flush(cs);
}

void helper_mtc0_pwfield(CPUMIPSState *env, target_ulong arg1)
{
#if defined(TARGET_MIPS64)
    uint64_t mask = 0x3F3FFFFFFFULL;
    uint32_t old_ptei = (env->CP0_PWField >> CP0PF_PTEI) & 0x3FULL;
    uint32_t new_ptei = (arg1 >> CP0PF_PTEI) & 0x3FULL;

    if ((env->insn_flags & ISA_MIPS_R6)) {
        if (((arg1 >> CP0PF_BDI) & 0x3FULL) < 12) {
            mask &= ~(0x3FULL << CP0PF_BDI);
        }
        if (((arg1 >> CP0PF_GDI) & 0x3FULL) < 12) {
            mask &= ~(0x3FULL << CP0PF_GDI);
        }
        if (((arg1 >> CP0PF_UDI) & 0x3FULL) < 12) {
            mask &= ~(0x3FULL << CP0PF_UDI);
        }
        if (((arg1 >> CP0PF_MDI) & 0x3FULL) < 12) {
            mask &= ~(0x3FULL << CP0PF_MDI);
        }
        if (((arg1 >> CP0PF_PTI) & 0x3FULL) < 12) {
            mask &= ~(0x3FULL << CP0PF_PTI);
        }
    }
    env->CP0_PWField = arg1 & mask;

    if ((new_ptei >= 32) ||
            ((env->insn_flags & ISA_MIPS_R6) &&
                    (new_ptei == 0 || new_ptei == 1))) {
        env->CP0_PWField = (env->CP0_PWField & ~0x3FULL) |
                (old_ptei << CP0PF_PTEI);
    }
#else
    uint32_t mask = 0x3FFFFFFF;
    uint32_t old_ptew = (env->CP0_PWField >> CP0PF_PTEW) & 0x3F;
    uint32_t new_ptew = (arg1 >> CP0PF_PTEW) & 0x3F;

    if ((env->insn_flags & ISA_MIPS_R6)) {
        if (((arg1 >> CP0PF_GDW) & 0x3F) < 12) {
            mask &= ~(0x3F << CP0PF_GDW);
        }
        if (((arg1 >> CP0PF_UDW) & 0x3F) < 12) {
            mask &= ~(0x3F << CP0PF_UDW);
        }
        if (((arg1 >> CP0PF_MDW) & 0x3F) < 12) {
            mask &= ~(0x3F << CP0PF_MDW);
        }
        if (((arg1 >> CP0PF_PTW) & 0x3F) < 12) {
            mask &= ~(0x3F << CP0PF_PTW);
        }
    }
    env->CP0_PWField = arg1 & mask;

    if ((new_ptew >= 32) ||
            ((env->insn_flags & ISA_MIPS_R6) &&
                    (new_ptew == 0 || new_ptew == 1))) {
        env->CP0_PWField = (env->CP0_PWField & ~0x3F) |
                (old_ptew << CP0PF_PTEW);
    }
#endif
}

void helper_mtc0_pwsize(CPUMIPSState *env, target_ulong arg1)
{
#if defined(TARGET_MIPS64)
    env->CP0_PWSize = arg1 & 0x3F7FFFFFFFULL;
#else
    env->CP0_PWSize = arg1 & 0x3FFFFFFF;
#endif
}

void helper_mtc0_wired(CPUMIPSState *env, target_ulong arg1)
{
    if (env->insn_flags & ISA_MIPS_R6) {
        if (arg1 < env->tlb->nb_tlb) {
            env->CP0_Wired = arg1;
        }
    } else {
        env->CP0_Wired = arg1 % env->tlb->nb_tlb;
    }
}

void helper_mtc0_pwctl(CPUMIPSState *env, target_ulong arg1)
{
#if defined(TARGET_MIPS64)
    /* PWEn = 0. Hardware page table walking is not implemented. */
    env->CP0_PWCtl = (env->CP0_PWCtl & 0x000000C0) | (arg1 & 0x5C00003F);
#else
    env->CP0_PWCtl = (arg1 & 0x800000FF);
#endif
}

void helper_mtc0_srsconf0(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_SRSConf0 |= arg1 & env->CP0_SRSConf0_rw_bitmask;
}

void helper_mtc0_srsconf1(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_SRSConf1 |= arg1 & env->CP0_SRSConf1_rw_bitmask;
}

void helper_mtc0_srsconf2(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_SRSConf2 |= arg1 & env->CP0_SRSConf2_rw_bitmask;
}

void helper_mtc0_srsconf3(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_SRSConf3 |= arg1 & env->CP0_SRSConf3_rw_bitmask;
}

void helper_mtc0_srsconf4(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_SRSConf4 |= arg1 & env->CP0_SRSConf4_rw_bitmask;
}

void helper_mtc0_hwrena(CPUMIPSState *env, target_ulong arg1)
{
    uint32_t mask = 0x0000000F;

    if ((env->CP0_Config1 & (1 << CP0C1_PC)) &&
        (env->insn_flags & ISA_MIPS_R6)) {
        mask |= (1 << 4);
    }
    if (env->insn_flags & ISA_MIPS_R6) {
        mask |= (1 << 5);
    }
    if (env->CP0_Config3 & (1 << CP0C3_ULRI)) {
        mask |= (1 << 29);

        if (arg1 & (1 << 29)) {
            env->hflags |= MIPS_HFLAG_HWRENA_ULR;
        } else {
            env->hflags &= ~MIPS_HFLAG_HWRENA_ULR;
        }
    }

    env->CP0_HWREna = arg1 & mask;
}

void helper_mtc0_count(CPUMIPSState *env, target_ulong arg1)
{
#ifdef CONFIG_PLUGIN
    /* Wrong-path: don't reprogram the guest timer device. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    cpu_mips_store_count(env, arg1);
}

void helper_mtc0_entryhi(CPUMIPSState *env, target_ulong arg1)
{
    target_ulong old, val, mask;
    mask = (TARGET_PAGE_MASK << 1) | env->CP0_EntryHi_ASID_mask;
    if (((env->CP0_Config4 >> CP0C4_IE) & 0x3) >= 2) {
        mask |= 1 << CP0EnHi_EHINV;
    }

    /* 1k pages not implemented */
#if defined(TARGET_MIPS64)
    if (env->insn_flags & ISA_MIPS_R6) {
        int entryhi_r = extract64(arg1, 62, 2);
        int config0_at = extract32(env->CP0_Config0, 13, 2);
        bool no_supervisor = (env->CP0_Status_rw_bitmask & 0x8) == 0;
        if ((entryhi_r == 2) ||
            (entryhi_r == 1 && (no_supervisor || config0_at == 1))) {
            /* skip EntryHi.R field if new value is reserved */
            mask &= ~(0x3ull << 62);
        }
    }
    mask &= env->SEGMask;
#endif
    old = env->CP0_EntryHi;
    val = (arg1 & mask) | (old & ~mask);
    env->CP0_EntryHi = val;
    if (ase_mt_available(env)) {
        sync_c0_entryhi(env, env->current_tc);
    }
    /* If the ASID changes, flush qemu's TLB.  */
    if ((old & env->CP0_EntryHi_ASID_mask) !=
        (val & env->CP0_EntryHi_ASID_mask)) {
        tlb_flush(env_cpu(env));
#ifdef CONFIG_PLUGIN
        /*
         * Address-space switch observation: the ASID field
         * mips_get_plugin_state reports just changed.  EntryHi also
         * carries VPN bits for TLB maintenance; VPN-only writes take the
         * branch above and never land here.  The event's pc slot carries
         * the OLD field value; the push itself stamps the just-committed
         * NEW value as the event's asid (and is a no-op on the wrong
         * path or while the queue is disabled).
         */
        cpu_plugin_evq_push(env_cpu(env), QEMU_PLUGIN_CPU_EVENT_ASID_WRITE,
                            old & env->CP0_EntryHi_ASID_mask,
                            env_cpu(env)->plugin_fault_depth);
#endif
        if (cst_cp0_audit()) {
            fprintf(stderr, "[cp0audit] cpu=%d ASID old=0x%02lx new=0x%02lx "
                    "ctx=0x%08lx\n",
                    env_cpu(env)->cpu_index,
                    (unsigned long)(old & env->CP0_EntryHi_ASID_mask),
                    (unsigned long)(val & env->CP0_EntryHi_ASID_mask),
                    (unsigned long)env->CP0_Context);
        }
        cst_wit_asidw(env, old & env->CP0_EntryHi_ASID_mask,
                      val & env->CP0_EntryHi_ASID_mask);
    }
}

/*
 * CP0 PWBase — the hardware page-table walker's base register, and (on a
 * model with Config3.PW) the value mips_get_plugin_identity() reports as
 * the name of the address space.  Linux writes it from htw_set_pwbase(),
 * reached through TLBMISS_HANDLER_SETUP_PGD(), i.e. at every
 * switch_mm/activate_mm.
 *
 * A HELPER rather than the inline TCG store it replaces, for one reason:
 * the write is the ADDRESS-SPACE COMMIT POINT, and the plugin identity has
 * to be resampled exactly there.  Sampling per TB instead would let the
 * identity drift for an unbounded stretch of kernel code, and would make a
 * generation rollover — where two different mms can hold the same
 * EntryHi.ASID — indistinguishable from no switch at all.
 *
 * No tlb_flush(): PWBase says where the walker starts, not how any existing
 * translation was formed, so writing it invalidates no cached translation.
 * (EntryHi.ASID does flush, and does so in its own helper above.)
 *
 * cpu_plugin_evq_push() is inert on the wrong path and while the queue is
 * disabled, so a speculative excursion cannot manufacture a switch; a
 * --disable-plugins build compiles the push out entirely, leaving one
 * helper call per context switch and nothing else.
 */
static void mips_pwbase_write(CPUMIPSState *env, target_ulong val)
{
    target_ulong old = env->CP0_PWBase;

    env->CP0_PWBase = val;
    if (old == val) {
        return;                 /* re-arming the same root is not a switch */
    }
#ifdef CONFIG_PLUGIN
    /*
     * The event's pc slot carries the OLD root; the push stamps the
     * just-committed NEW one as the event's asid.
     */
    cpu_plugin_evq_push(env_cpu(env), QEMU_PLUGIN_CPU_EVENT_ASID_WRITE,
                        old, env_cpu(env)->plugin_fault_depth);
#endif
    if (cst_cp0_audit()) {
        fprintf(stderr, "[cp0audit] cpu=%d PWBase old=0x%08lx new=0x%08lx\n",
                env_cpu(env)->cpu_index,
                (unsigned long)old, (unsigned long)val);
    }
    cst_wit_pwbw(env, old, val);
}

void helper_mtc0_pwbase(CPUMIPSState *env, target_ulong arg1)
{
    /*
     * MTC0 moves a 32-bit GPR half, and the inline store this replaced
     * (gen_mtc0_store32) truncated to 32 bits too, so the written value is
     * unchanged on every target that can execute the instruction: the only
     * QEMU MIPS model with Config3.PW is P5600, a MIPS32r5 core, and
     * check_pw() turns the access into a Reserved Instruction on every
     * model without the bit — which is all of MIPS64.
     */
    mips_pwbase_write(env, (target_ulong)(uint32_t)arg1);
}

void helper_dmtc0_pwbase(CPUMIPSState *env, target_ulong arg1)
{
    /* DMTC0 writes the register's full width. */
    mips_pwbase_write(env, arg1);
}

void helper_mttc0_entryhi(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    other->CP0_EntryHi = arg1;
    sync_c0_entryhi(other, other_tc);
}

void helper_mtc0_compare(CPUMIPSState *env, target_ulong arg1)
{
#ifdef CONFIG_PLUGIN
    /* Wrong-path: don't reprogram the guest timer / clear its interrupt. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    cpu_mips_store_compare(env, arg1);
}

void helper_mtc0_status(CPUMIPSState *env, target_ulong arg1)
{
    uint32_t val, old;

    old = env->CP0_Status;
    cpu_mips_store_status(env, arg1);
    val = env->CP0_Status;

    if (qemu_loglevel_mask(CPU_LOG_EXEC)) {
        qemu_log("Status %08x (%08x) => %08x (%08x) Cause %08x",
                old, old & env->CP0_Cause & CP0Ca_IP_mask,
                val, val & env->CP0_Cause & CP0Ca_IP_mask,
                env->CP0_Cause);
        switch (mips_env_mmu_index(env)) {
        case 3:
            qemu_log(", ERL\n");
            break;
        case MIPS_HFLAG_UM:
            qemu_log(", UM\n");
            break;
        case MIPS_HFLAG_SM:
            qemu_log(", SM\n");
            break;
        case MIPS_HFLAG_KM:
            qemu_log("\n");
            break;
        default:
            cpu_abort(env_cpu(env), "Invalid MMU mode!\n");
            break;
        }
    }
}

void helper_mttc0_status(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    uint32_t mask = env->CP0_Status_rw_bitmask & ~0xf1000018;
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    other->CP0_Status = (other->CP0_Status & ~mask) | (arg1 & mask);
    sync_c0_status(env, other, other_tc);
}

void helper_mtc0_intctl(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_IntCtl = (env->CP0_IntCtl & ~0x000003e0) | (arg1 & 0x000003e0);
}

void helper_mtc0_srsctl(CPUMIPSState *env, target_ulong arg1)
{
    uint32_t mask = (0xf << CP0SRSCtl_ESS) | (0xf << CP0SRSCtl_PSS);
    env->CP0_SRSCtl = (env->CP0_SRSCtl & ~mask) | (arg1 & mask);
}

void helper_mtc0_cause(CPUMIPSState *env, target_ulong arg1)
{
#ifdef CONFIG_PLUGIN
    /*
     * Wrong-path: cpu_mips_store_cause toggles the soft IRQ line
     * (interrupt_request, out of snapshot) and on a CP0_Cause.DC flip
     * starts/stops the host count timer. The CP0_Cause register write
     * is rolled back with the snapshot anyway, so skip the whole store.
     */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    cpu_mips_store_cause(env, arg1);
}

void helper_mttc0_cause(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /*
     * Wrong-path: writes a sibling TC's CP0_Cause (out of this CPU's
     * snapshot) and toggles its soft IRQ line / host count timer.
     */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    cpu_mips_store_cause(other, arg1);
}

target_ulong helper_mftc0_epc(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    return other->CP0_EPC;
}

target_ulong helper_mftc0_ebase(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    return other->CP0_EBase;
}

void helper_mtc0_ebase(CPUMIPSState *env, target_ulong arg1)
{
    target_ulong mask = 0x3FFFF000 | env->CP0_EBaseWG_rw_bitmask;
    if (arg1 & env->CP0_EBaseWG_rw_bitmask) {
        mask |= ~0x3FFFFFFF;
    }
    env->CP0_EBase = (env->CP0_EBase & ~mask) | (arg1 & mask);
}

void helper_mttc0_ebase(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;
    target_ulong mask = 0x3FFFF000 | env->CP0_EBaseWG_rw_bitmask;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);
    if (arg1 & env->CP0_EBaseWG_rw_bitmask) {
        mask |= ~0x3FFFFFFF;
    }
    other->CP0_EBase = (other->CP0_EBase & ~mask) | (arg1 & mask);
}

target_ulong helper_mftc0_configx(CPUMIPSState *env, target_ulong idx)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    switch (idx) {
    case 0: return other->CP0_Config0;
    case 1: return other->CP0_Config1;
    case 2: return other->CP0_Config2;
    case 3: return other->CP0_Config3;
    /* 4 and 5 are reserved.  */
    case 6: return other->CP0_Config6;
    case 7: return other->CP0_Config7;
    default:
        break;
    }
    return 0;
}

void helper_mtc0_config0(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_Config0 = (env->CP0_Config0 & 0x81FFFFF8) | (arg1 & 0x00000007);
}

void helper_mtc0_config2(CPUMIPSState *env, target_ulong arg1)
{
    /* tertiary/secondary caches not implemented */
    env->CP0_Config2 = (env->CP0_Config2 & 0x8FFF0FFF);
}

void helper_mtc0_config3(CPUMIPSState *env, target_ulong arg1)
{
    if (env->insn_flags & ASE_MICROMIPS) {
        env->CP0_Config3 = (env->CP0_Config3 & ~(1 << CP0C3_ISA_ON_EXC)) |
                           (arg1 & (1 << CP0C3_ISA_ON_EXC));
    }
}

void helper_mtc0_config4(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_Config4 = (env->CP0_Config4 & (~env->CP0_Config4_rw_bitmask)) |
                       (arg1 & env->CP0_Config4_rw_bitmask);
}

void helper_mtc0_config5(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_Config5 = (env->CP0_Config5 & (~env->CP0_Config5_rw_bitmask)) |
                       (arg1 & env->CP0_Config5_rw_bitmask);
    env->CP0_EntryHi_ASID_mask = (env->CP0_Config5 & (1 << CP0C5_MI)) ?
            0x0 : (env->CP0_Config4 & (1 << CP0C4_AE)) ? 0x3ff : 0xff;
    compute_hflags(env);
}

void helper_mtc0_lladdr(CPUMIPSState *env, target_ulong arg1)
{
    target_long mask = env->CP0_LLAddr_rw_bitmask;
    arg1 = arg1 << env->CP0_LLAddr_shift;
    env->CP0_LLAddr = (env->CP0_LLAddr & ~mask) | (arg1 & mask);
}

#define MTC0_MAAR_MASK(env) \
        ((0x1ULL << 63) | ((env->PAMask >> 4) & ~0xFFFull) | 0x3)

void helper_mtc0_maar(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_MAAR[env->CP0_MAARI] = arg1 & MTC0_MAAR_MASK(env);
}

void helper_mthc0_maar(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_MAAR[env->CP0_MAARI] =
        (((uint64_t) arg1 << 32) & MTC0_MAAR_MASK(env)) |
        (env->CP0_MAAR[env->CP0_MAARI] & 0x00000000ffffffffULL);
}

void helper_mtc0_maari(CPUMIPSState *env, target_ulong arg1)
{
    int index = arg1 & 0x3f;
    if (index == 0x3f) {
        /*
         * Software may write all ones to INDEX to determine the
         *  maximum value supported.
         */
        env->CP0_MAARI = MIPS_MAAR_MAX - 1;
    } else if (index < MIPS_MAAR_MAX) {
        env->CP0_MAARI = index;
    }
    /*
     * Other than the all ones, if the value written is not supported,
     * then INDEX is unchanged from its previous value.
     */
}

void helper_mtc0_watchlo(CPUMIPSState *env, target_ulong arg1, uint32_t sel)
{
    /*
     * Watch exceptions for instructions, data loads, data stores
     * not implemented.
     */
    env->CP0_WatchLo[sel] = (arg1 & ~0x7);
}

void helper_mtc0_watchhi(CPUMIPSState *env, target_ulong arg1, uint32_t sel)
{
    uint64_t mask = 0x40000FF8 | (env->CP0_EntryHi_ASID_mask << CP0WH_ASID);
    uint64_t m_bit = env->CP0_WatchHi[sel] & (1 << CP0WH_M); /* read-only */
    if ((env->CP0_Config5 >> CP0C5_MI) & 1) {
        mask |= 0xFFFFFFFF00000000ULL; /* MMID */
    }
    env->CP0_WatchHi[sel] = m_bit | (arg1 & mask);
    env->CP0_WatchHi[sel] &= ~(env->CP0_WatchHi[sel] & arg1 & 0x7);
}

void helper_mthc0_watchhi(CPUMIPSState *env, target_ulong arg1, uint32_t sel)
{
    env->CP0_WatchHi[sel] = ((uint64_t) (arg1) << 32) |
                            (env->CP0_WatchHi[sel] & 0x00000000ffffffffULL);
}

void helper_mtc0_xcontext(CPUMIPSState *env, target_ulong arg1)
{
    target_ulong mask = (1ULL << (env->SEGBITS - 7)) - 1;
    env->CP0_XContext = (env->CP0_XContext & mask) | (arg1 & ~mask);
}

void helper_mtc0_framemask(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_Framemask = arg1; /* XXX */
}

void helper_mtc0_debug(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_Debug = (env->CP0_Debug & 0x8C03FC1F) | (arg1 & 0x13300120);
    if (arg1 & (1 << CP0DB_DM)) {
        env->hflags |= MIPS_HFLAG_DM;
    } else {
        env->hflags &= ~MIPS_HFLAG_DM;
    }
}

void helper_mttc0_debug(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    uint32_t val = arg1 & ((1 << CP0DB_SSt) | (1 << CP0DB_Halt));
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    /* XXX: Might be wrong, check with EJTAG spec. */
    if (other_tc == other->current_tc) {
        other->active_tc.CP0_Debug_tcstatus = val;
    } else {
        other->tcs[other_tc].CP0_Debug_tcstatus = val;
    }
    other->CP0_Debug = (other->CP0_Debug &
                     ((1 << CP0DB_SSt) | (1 << CP0DB_Halt))) |
                     (arg1 & ~((1 << CP0DB_SSt) | (1 << CP0DB_Halt)));
}

void helper_mtc0_performance0(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_Performance0 = arg1 & 0x000007ff;
}

void helper_mtc0_errctl(CPUMIPSState *env, target_ulong arg1)
{
    int32_t wst = arg1 & (1 << CP0EC_WST);
    int32_t spr = arg1 & (1 << CP0EC_SPR);
    int32_t itc = env->itc_tag ? (arg1 & (1 << CP0EC_ITC)) : 0;

    env->CP0_ErrCtl = wst | spr | itc;

    if (itc && !wst && !spr) {
        env->hflags |= MIPS_HFLAG_ITC_CACHE;
    } else {
        env->hflags &= ~MIPS_HFLAG_ITC_CACHE;
    }
}

void helper_mtc0_taglo(CPUMIPSState *env, target_ulong arg1)
{
    if (env->hflags & MIPS_HFLAG_ITC_CACHE) {
        /*
         * If CACHE instruction is configured for ITC tags then make all
         * CP0.TagLo bits writable. The actual write to ITC Configuration
         * Tag will take care of the read-only bits.
         */
        env->CP0_TagLo = arg1;
    } else {
        env->CP0_TagLo = arg1 & 0xFFFFFCF6;
    }
}

void helper_mtc0_datalo(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_DataLo = arg1; /* XXX */
}

void helper_mtc0_taghi(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_TagHi = arg1; /* XXX */
}

void helper_mtc0_datahi(CPUMIPSState *env, target_ulong arg1)
{
    env->CP0_DataHi = arg1; /* XXX */
}

/* MIPS MT functions */
target_ulong helper_mftgpr(CPUMIPSState *env, uint32_t sel)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.gpr[sel];
    } else {
        return other->tcs[other_tc].gpr[sel];
    }
}

target_ulong helper_mftlo(CPUMIPSState *env, uint32_t sel)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.LO[sel];
    } else {
        return other->tcs[other_tc].LO[sel];
    }
}

target_ulong helper_mfthi(CPUMIPSState *env, uint32_t sel)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.HI[sel];
    } else {
        return other->tcs[other_tc].HI[sel];
    }
}

target_ulong helper_mftacx(CPUMIPSState *env, uint32_t sel)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.ACX[sel];
    } else {
        return other->tcs[other_tc].ACX[sel];
    }
}

target_ulong helper_mftdsp(CPUMIPSState *env)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        return other->active_tc.DSPControl;
    } else {
        return other->tcs[other_tc].DSPControl;
    }
}

void helper_mttgpr(CPUMIPSState *env, target_ulong arg1, uint32_t sel)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        other->active_tc.gpr[sel] = arg1;
    } else {
        other->tcs[other_tc].gpr[sel] = arg1;
    }
}

void helper_mttlo(CPUMIPSState *env, target_ulong arg1, uint32_t sel)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        other->active_tc.LO[sel] = arg1;
    } else {
        other->tcs[other_tc].LO[sel] = arg1;
    }
}

void helper_mtthi(CPUMIPSState *env, target_ulong arg1, uint32_t sel)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        other->active_tc.HI[sel] = arg1;
    } else {
        other->tcs[other_tc].HI[sel] = arg1;
    }
}

void helper_mttacx(CPUMIPSState *env, target_ulong arg1, uint32_t sel)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        other->active_tc.ACX[sel] = arg1;
    } else {
        other->tcs[other_tc].ACX[sel] = arg1;
    }
}

void helper_mttdsp(CPUMIPSState *env, target_ulong arg1)
{
    int other_tc = env->CP0_VPEControl & (0xff << CP0VPECo_TargTC);
    CPUMIPSState *other;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes a sibling TC's env, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return;
    }
#endif
    other = mips_cpu_map_tc(env, &other_tc);

    if (other_tc == other->current_tc) {
        other->active_tc.DSPControl = arg1;
    } else {
        other->tcs[other_tc].DSPControl = arg1;
    }
}

/* MIPS MT functions */
target_ulong helper_dmt(void)
{
    /* TODO */
    return 0;
}

target_ulong helper_emt(void)
{
    /* TODO */
    return 0;
}

target_ulong helper_dvpe(CPUMIPSState *env)
{
    CPUState *other_cs = first_cpu;
    target_ulong prev;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes the shared mvp context, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return 0;
    }
#endif
    if (!(env->CP0_VPEConf0 & (1 << CP0VPEC0_MVP))) {
        /* Without MVP, DVPE reads MVPControl and changes nothing. */
        prev = env->mvp->CP0_MVPControl;
        mips_mvp_note(env, MIPS_MVP_DVPE_NA, prev, prev);
        return prev;
    }

    /*
     * One instruction, one read-modify-write.
     *
     * MVPControl is a single per-processor register shared by every VPE of
     * the processor, and the value DVPE returns is what the guest's nesting
     * protocol tests to decide whether its matching EVPE has to restore EVP
     * (`prev = dvpe(); ... evpe(prev);`).  Sampling it and clearing EVP must
     * therefore be indivisible.  Walking the sibling list and clearing the
     * bit once per sibling instead gave the instruction N-1 separate stores
     * with the sample outside all of them, so a peer's EVPE landing in the
     * middle was undone afterwards by this VPE's remaining stores: the peer
     * had already spent its restore, this VPE still owed one, and EVP stayed
     * clear.  Every VPE then failed mips_vpe_active(), mips_cpu_has_work()
     * forced has_work false with an enabled interrupt pending, and the
     * machine never retired another instruction.
     */
    prev = qatomic_fetch_and(&env->mvp->CP0_MVPControl,
                             ~(int32_t)(1 << CP0MVPCo_EVP));
    mips_mvp_note(env, MIPS_MVP_DVPE_RD, prev, prev);
    mips_mvp_note(env, MIPS_MVP_DVPE_WR, prev,
                  prev & ~(1 << CP0MVPCo_EVP));

    if (!(prev & (1 << CP0MVPCo_EVP))) {
        /*
         * The processor was already disabled, so this DVPE is nested inside
         * another VPE's -- and on hardware it could not have been reached at
         * all, because that other VPE's DVPE stopped this one from issuing.
         * QEMU cannot stop a sibling mid-TB, so the instruction does get
         * executed here; what it must not do is act as though it owned the
         * disable.  Sleeping the siblings from a nested DVPE halts the VPE
         * that is holding the section open -- the one VPE that will run the
         * matching EVPE, because the guest's `evpe(prev)` restores only when
         * its own DVPE saw EVP set.  That VPE then cannot be rescheduled,
         * since mips_vpe_active() is false for it too, and the whole
         * processor stops with EVP clear and the restore still owed.
         *
         * Sleeping siblings therefore belongs to the DVPE that performed the
         * 1 -> 0 transition, and to no other.  With the transition itself
         * atomic, exactly one VPE owns an open section at a time, and no peer
         * ISSUES a halt to it while that section is open.
         *
         * That is not the same as the owner never being found halted, and
         * reading it as though it were is what left this stall open.  An
         * order issued by the PREVIOUS owner, before the EVPE that let this
         * transition happen, is still unobserved in the target until its next
         * trip through the top of cpu_exec(); it lands on whatever that VPE
         * has become by then.  The claim below cancels it.
         */
        return prev;
    }

    /*
     * This VPE now holds the processor disabled, and the state has to say so,
     * because "EVP is clear" means the opposite thing about it than it means
     * about its siblings -- see CPUMIPSMVPContext::evp_owner.
     */
    qatomic_set(&env->mvp->evp_owner, env_cpu(env)->cpu_index);

    /*
     * A stop order this VPE is still carrying is void: it is executing.
     *
     * mips_vpe_sleep() stores into a sibling's ->halted from another thread,
     * and a sibling already inside a TB does not read that store until the
     * top of cpu_exec().  It can therefore run on for an unbounded number of
     * instructions after the store -- including, as measured on this guest in
     * every one of 14 stalls, the DVPE right here.  The order was issued to
     * stop a VPE from executing during someone else's section; that section
     * has since ended (its EVPE is what allowed this DVPE to win), and the
     * VPE it named is now the one VPE that architecture says must keep
     * running.  Observing it later would park the owner with EVP clear, and
     * nothing could ever wake it: the EVPE that would is the instruction it
     * has not reached.
     *
     * No further order can arrive while this section is open.  A peer's
     * sibling-sleep loop runs only inside a section it owns, and its EVPE --
     * the instruction that lets this DVPE win -- comes after that loop in its
     * own program order, so every order issued by the previous owner was
     * issued before this transition.
     *
     * The TC's own activation state is asked anyway rather than assumed: a
     * halt that came from TCHalt / VPA / TCStatus.A is the thread context
     * saying it must not execute, which is a fact about this VPE and not a
     * stale statement about someone else's section, and nothing here may
     * override it.
     */
    if (mips_vpe_tc_activated(env)) {
        env_cpu(env)->halted = 0;
    }

    CPU_FOREACH(other_cs) {
        MIPSCPU *other_cpu = MIPS_CPU(other_cs);
        /* Put every VPE except the one executing the dvpe to sleep. */
        if (&other_cpu->env != env) {
            mips_vpe_sleep(other_cpu, MIPS_MVP_SLEEP_DVPE);
        }
    }
    return prev;
}

target_ulong helper_evpe(CPUMIPSState *env)
{
    CPUState *other_cs = first_cpu;
    target_ulong prev;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: writes the shared mvp context, out of this CPU's snapshot. */
    if (env_cpu(env)->plugin_spec_mode) {
        return 0;
    }
#endif
    if (!(env->CP0_VPEConf0 & (1 << CP0VPEC0_MVP))) {
        /* Without MVP, EVPE reads MVPControl and changes nothing. */
        prev = env->mvp->CP0_MVPControl;
        mips_mvp_note(env, MIPS_MVP_EVPE_NA, prev, prev);
        return prev;
    }

    /* One instruction, one read-modify-write -- see helper_dvpe(). */
    prev = qatomic_fetch_or(&env->mvp->CP0_MVPControl,
                            (int32_t)(1 << CP0MVPCo_EVP));
    mips_mvp_note(env, MIPS_MVP_EVPE_RD, prev, prev);
    mips_mvp_note(env, MIPS_MVP_EVPE_WR, prev,
                  prev | (1 << CP0MVPCo_EVP));

    if (prev & (1 << CP0MVPCo_EVP)) {
        /*
         * Already enabled: this EVPE closes nothing, so there is nobody it
         * put to sleep to wake.  The mirror of the nested-DVPE case above.
         */
        return prev;
    }

    /*
     * The section is closed, so release the claim -- but only this VPE's own.
     * The enable above is what lets the next DVPE win, and that DVPE claims
     * ownership for itself; a plain store here could land after that claim and
     * erase it, leaving the new owner reading the shared bit as its own
     * disable again.  The compare-exchange releases nothing it does not own.
     */
    qatomic_cmpxchg(&env->mvp->evp_owner, env_cpu(env)->cpu_index, -1);

    CPU_FOREACH(other_cs) {
        MIPSCPU *other_cpu = MIPS_CPU(other_cs);

        /*
         * Wake every sibling, because the matching DVPE slept every sibling.
         * mips_vpe_sleep() halts a VPE that was running and clears its wake
         * request, so nothing but this wake will schedule it again: a VPE
         * stopped mid-computation has no pending interrupt to revive it.
         *
         * The old "if the VPE is WFI, don't disturb its sleep" guard could
         * not survive here.  It asked mips_vpe_is_wfi() of the live shared
         * word, so the first sibling's write set EVP and made the answer
         * true for every later halted sibling: an EVPE closing a DVPE that
         * had slept N-1 VPEs woke exactly one of them, and the rest stayed
         * halted with the wake request DVPE cleared never reissued.  An IPI
         * delivered into that window sets CPU_INTERRUPT_HARD on a vCPU that
         * is never asked for work again, which is how a guest reports
         * "Unable to send backtrace IPI to CPU0 - perhaps it hung?".
         *
         * Asked instead of the SAMPLED word the guard is vacuous rather than
         * order-dependent -- an EVPE that reaches this loop sampled EVP
         * clear, under which mips_vpe_active() is false for every VPE -- so
         * there is no honest form of it to keep.  The cost is that a VPE
         * that had executed WAIT before the DVPE leaves WAIT here without an
         * interrupt; MIPS permits WAIT to terminate for implementation
         * reasons and Linux's idle loop re-enters, and this is what the
         * first sibling has always had done to it.
         */
        if (&other_cpu->env != env) {
            mips_vpe_wake(other_cpu, MIPS_MVP_WAKE_EVPE); /* Wake it up. */
        }
    }
    return prev;
}

/* R6 Multi-threading */
target_ulong helper_dvp(CPUMIPSState *env)
{
    CPUState *other_cs = first_cpu;
    target_ulong prev;

#ifdef CONFIG_PLUGIN
    /*
     * Wrong-path: only own-CPU CP0_VPControl (in-snapshot) plus sibling
     * sleep/wake (gated in mips_vpe_sleep/wake) — safe, but gate at entry to
     * match dvpe/evpe and stay robust if the sink gates ever change.
     */
    if (env_cpu(env)->plugin_spec_mode) {
        return 0;
    }
#endif
    prev = env->CP0_VPControl;

    if (!((env->CP0_VPControl >> CP0VPCtl_DIS) & 1)) {
        /*
         * As in helper_dvpe(): the VP issuing DVP is the one VP that keeps
         * running, so a sleep order it is still carrying from a peer -- one
         * a VP inside a TB cannot observe until the top of cpu_exec() -- is
         * stale, and observing it later would park the VP that owes the
         * matching EVP.
         */
        if (mips_vpe_tc_activated(env)) {
            env_cpu(env)->halted = 0;
        }
        CPU_FOREACH(other_cs) {
            MIPSCPU *other_cpu = MIPS_CPU(other_cs);
            /* Turn off all VPs except the one executing the dvp. */
            if (&other_cpu->env != env) {
                mips_vpe_sleep(other_cpu, MIPS_MVP_SLEEP_DVP);
            }
        }
        env->CP0_VPControl |= (1 << CP0VPCtl_DIS);
    }
    return prev;
}

target_ulong helper_evp(CPUMIPSState *env)
{
    CPUState *other_cs = first_cpu;
    target_ulong prev;

#ifdef CONFIG_PLUGIN
    /* Wrong-path: see helper_dvp — gate at entry for symmetry/robustness. */
    if (env_cpu(env)->plugin_spec_mode) {
        return 0;
    }
#endif
    prev = env->CP0_VPControl;

    if ((env->CP0_VPControl >> CP0VPCtl_DIS) & 1) {
        CPU_FOREACH(other_cs) {
            MIPSCPU *other_cpu = MIPS_CPU(other_cs);
            if ((&other_cpu->env != env) && !mips_vp_is_wfi(other_cpu)) {
                /*
                 * If the VP is WFI, don't disturb its sleep.
                 * Otherwise, wake it up.
                 */
                mips_vpe_wake(other_cpu, MIPS_MVP_WAKE_EVP);
            }
        }
        env->CP0_VPControl &= ~(1 << CP0VPCtl_DIS);
    }
    return prev;
}
