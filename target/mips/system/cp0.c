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

void cpu_mips_store_cause(CPUMIPSState *env, target_ulong val)
{
    uint32_t mask = 0x00C00300;
    uint32_t old = env->CP0_Cause;
    int i;

    if (env->insn_flags & ISA_MIPS_R2) {
        mask |= 1 << CP0Ca_DC;
    }
    if (env->insn_flags & ISA_MIPS_R6) {
        mask &= ~((1 << CP0Ca_WP) & val);
    }

    env->CP0_Cause = (env->CP0_Cause & ~mask) | (val & mask);

    if ((old ^ env->CP0_Cause) & (1 << CP0Ca_DC)) {
        if (env->CP0_Cause & (1 << CP0Ca_DC)) {
            cpu_mips_stop_count(env);
        } else {
            cpu_mips_start_count(env);
        }
    }

    /* Set/reset software interrupts */
    for (i = 0 ; i < 2 ; i++) {
        if ((old ^ env->CP0_Cause) & (1 << (CP0Ca_IP + i))) {
            cpu_mips_soft_irq(env, i, env->CP0_Cause & (1 << (CP0Ca_IP + i)));
        }
    }
}

/*
 * MVPControl condition instrument (see internal.h).
 *
 * Every VPE of one MT processor shares a single MVPControl, and EVP in that
 * word can only be set by a VPE that is *executing* -- an EVPE instruction,
 * or an mtc0 to MVPControl.  So the wedge this instrument names is
 *
 *      every VPE is halted, and every VPE is held off the run queue by the
 *      EVP gate in mips_cpu_has_work().
 *
 * It is a statement about machine state and not about how long anything
 * took, which is what makes it usable: no VPE that has come to rest in it
 * can run, so none can execute the instruction that would let any of them
 * run again, and device interrupts do not help because mips_cpu_has_work()
 * discards them on exactly this arm.  The ring behind the report is the
 * interleaving of reads and writes of the shared word that produced it.
 *
 * It is NOT terminal by construction, and an earlier version of this comment
 * said it was.  cs->halted can be set on a vCPU from another thread, and a
 * vCPU already inside a TB does not read it until the top of cpu_exec(), so
 * the predicate can find every VPE halted while one of them is still
 * retiring instructions and about to reach the EVPE that reopens the
 * processor.  Measured: one control boot fired MVPWEDGE (owed=0x4, the owner
 * parked in mips_mt_send_ipi) and then powered off six seconds later.  A
 * single report is therefore a necessary condition, not a proof; what makes
 * a stall a stall is that the guest never resumes, and the report says which
 * of the four gates to look at when it does not.
 */

int mips_mvp_debug = -1;

#define MIPS_MVP_RING 4096
#define MIPS_MVP_MAXVPE 32

typedef struct MipsMvpEvent {
    uint64_t seq;
    int32_t cpu;        /* VPE that executed the instruction        */
    int32_t target;     /* VPE it acted on, or -1 for the shared word */
    int32_t op;
    uint32_t pc;        /* setter's guest PC                        */
    uint32_t before;
    uint32_t after;
    int32_t owed;
} MipsMvpEvent;

static MipsMvpEvent mvp_ring[MIPS_MVP_RING];
static uint64_t mvp_seq;
static uint32_t mvp_owed_mask;     /* VPEs that still owe an evpe restore */
static uint32_t mvp_strand_seen;   /* strand already reported for this run */
static uint64_t mvp_strands;
static uint64_t mvp_gate_mask;     /* VPEs observed gated off by EVP */

/*
 * Newest run-state edge per VPE, latched outside the ring.
 *
 * The ring answers "what was the interleaving"; these answer "what halted
 * this particular VPE", which is the question a stall with every VPE halted
 * actually poses, and they answer it however long ago it happened.
 */
static MipsMvpEvent mvp_last_halt[MIPS_MVP_MAXVPE];
static MipsMvpEvent mvp_last_wake[MIPS_MVP_MAXVPE];

void mips_mvp_debug_init(void)
{
    const char *s;

    if (mips_mvp_debug >= 0) {
        return;
    }
    s = getenv("MIPS_MVP_DEBUG");
    mips_mvp_debug = (s && *s && *s != '0') ? 1 : 0;
}

static const char *mvp_opname(int op)
{
    switch (op) {
    case MIPS_MVP_DVPE_RD: return "dvpe.rd";
    case MIPS_MVP_DVPE_WR: return "dvpe.wr";
    case MIPS_MVP_EVPE_RD: return "evpe.rd";
    case MIPS_MVP_EVPE_WR: return "evpe.wr";
    case MIPS_MVP_DVPE_NA: return "dvpe.na";
    case MIPS_MVP_EVPE_NA: return "evpe.na";
    case MIPS_MVP_MTC0_WR: return "mtc0.wr";
    case MIPS_MVP_MTC0_NA: return "mtc0.na";
    case MIPS_MVP_SLEEP_DVPE: return "slp.dvpe";
    case MIPS_MVP_SLEEP_DVP:  return "slp.dvp";
    case MIPS_MVP_SLEEP_TC:   return "slp.tc";
    case MIPS_MVP_SLEEP_WAIT: return "slp.wait";
    case MIPS_MVP_WAKE_EVPE:  return "wak.evpe";
    case MIPS_MVP_WAKE_EVP:   return "wak.evp";
    case MIPS_MVP_WAKE_TC:    return "wak.tc";
    default: return "?";
    }
}

static void mvp_print_event(const char *what, const MipsMvpEvent *e)
{
    fprintf(stderr, "%s %6" PRIu64 " cpu=%d %-8s target=%d pc=0x%08x "
                    "%08x -> %08x evp=%d->%d owed=0x%x\n",
            what, e->seq, e->cpu, mvp_opname(e->op), e->target, e->pc,
            e->before, e->after,
            (e->before >> CP0MVPCo_EVP) & 1, (e->after >> CP0MVPCo_EVP) & 1,
            e->owed);
}

static void mvp_dump_ring(void)
{
    uint64_t end = qatomic_read(&mvp_seq);
    uint64_t start = end > MIPS_MVP_RING ? end - MIPS_MVP_RING : 0;
    uint64_t i;

    fprintf(stderr, "MVPRING last=%" PRIu64 " events\n", end - start);
    for (i = start; i < end; i++) {
        MipsMvpEvent *e = &mvp_ring[i % MIPS_MVP_RING];

        if (e->seq != i) {
            continue;   /* overwritten while we were printing */
        }
        mvp_print_event("MVPRING", e);
    }
    fflush(stderr);
}

void mips_mvp_note(CPUMIPSState *env, int op, uint32_t before, uint32_t after)
{
    CPUState *cs = env_cpu(env);
    uint32_t bit = 1u << (cs->cpu_index & 31);
    uint32_t owed;
    uint64_t s;
    MipsMvpEvent *e;

    if (!mips_mvp_debug) {
        return;
    }

    /*
     * Debt bookkeeping.  A dvpe that read EVP set is the VPE that will drive
     * the matching EVPE; one that read it clear will not, because Linux's
     * evpe(prev) tests prev.
     */
    switch (op) {
    case MIPS_MVP_DVPE_RD:
        if (before & (1 << CP0MVPCo_EVP)) {
            qatomic_or(&mvp_owed_mask, bit);
        }
        break;
    case MIPS_MVP_EVPE_RD:
        qatomic_and(&mvp_owed_mask, ~bit);
        break;
    default:
        break;
    }
    owed = qatomic_read(&mvp_owed_mask);

    s = qatomic_fetch_inc(&mvp_seq);
    e = &mvp_ring[s % MIPS_MVP_RING];
    e->cpu = cs->cpu_index;
    e->target = -1;
    e->op = op;
    e->pc = (uint32_t)env->active_tc.PC;
    e->before = before;
    e->after = after;
    e->owed = owed;
    qatomic_set(&e->seq, s);

    /*
     * A write that clears EVP is only interesting in aggregate: on a healthy
     * boot the guest clears and restores it thousands of times.  Counting
     * them keeps the report honest about how ordinary the transient is.
     */
    if ((op == MIPS_MVP_DVPE_WR || op == MIPS_MVP_EVPE_WR ||
         op == MIPS_MVP_MTC0_WR) && !(after & (1 << CP0MVPCo_EVP))) {
        qatomic_inc(&mvp_strands);
    }
}

/*
 * Run-state edge: some VPE just halted or un-halted @target.
 *
 * cs->halted is the last word on whether a vCPU is offered to the scheduler,
 * so in a stall where every VPE is halted the only question left is which
 * instruction, on which VPE, set it -- and the sites that can are few:
 * DVPE/DVP sleeping siblings, an mtc0/mttc0 to TCHalt deactivating a thread
 * context, and the VPE's own WAIT.  Recording (setter, target, setter pc) at
 * each of them turns "every VPE is halted" into a named culprit.  The setter
 * is read from current_cpu because every one of these sites is reached from
 * a TCG helper on the issuing vCPU's own thread.
 */
void mips_mvp_note_run(CPUState *target, int op)
{
    CPUState *cs = current_cpu;
    uint64_t s;
    MipsMvpEvent *e, rec;

    if (!mips_mvp_debug) {
        return;
    }

    memset(&rec, 0, sizeof(rec));
    rec.cpu = cs ? cs->cpu_index : -1;
    rec.target = target->cpu_index;
    rec.op = op;
    rec.pc = cs ? (uint32_t)MIPS_CPU(cs)->env.active_tc.PC : 0;
    rec.before = (uint32_t)MIPS_CPU(target)->env.mvp->CP0_MVPControl;
    rec.after = rec.before;
    rec.owed = qatomic_read(&mvp_owed_mask);

    s = qatomic_fetch_inc(&mvp_seq);
    rec.seq = s;
    e = &mvp_ring[s % MIPS_MVP_RING];
    *e = rec;
    qatomic_set(&e->seq, s);

    if (target->cpu_index >= 0 && target->cpu_index < MIPS_MVP_MAXVPE) {
        bool halting = (op == MIPS_MVP_SLEEP_DVPE || op == MIPS_MVP_SLEEP_DVP ||
                        op == MIPS_MVP_SLEEP_TC || op == MIPS_MVP_SLEEP_WAIT);

        if (halting) {
            mvp_last_halt[target->cpu_index] = rec;
        } else {
            mvp_last_wake[target->cpu_index] = rec;
        }
    }
}

/*
 * Which of mips_vpe_active()'s four independent clauses is holding this VPE
 * off the run queue.  They are not interchangeable: EVP is processor-wide
 * and only an executing VPE can set it, while VPA/TCStatus.A/TCHalt are
 * per-VPE and are written by a peer through mttc0.  A report that says only
 * "not active" cannot tell the resulting stalls apart.
 */
static void mvp_gate_reason(CPUMIPSState *env, char *buf, size_t n)
{
    bool evp = env->mvp->CP0_MVPControl & (1 << CP0MVPCo_EVP);
    bool owner = qatomic_read(&env->mvp->evp_owner) ==
                 env_cpu(env)->cpu_index;

    snprintf(buf, n, "%s%s%s%s%s",
             (evp || owner) ? "" : "EVP0 ",
             (!evp && owner) ? "EVPOWNER " : "",
             (env->CP0_VPEConf0 & (1 << CP0VPEC0_VPA)) ? "" : "VPA0 ",
             (env->active_tc.CP0_TCStatus & (1 << CP0TCSt_A)) ? "" : "TCA0 ",
             (env->active_tc.CP0_TCHalt & 1) ? "TCHALT " : "");
}

static void mvp_report_cpu(const char *what, CPUState *cs)
{
    CPUMIPSState *env = &MIPS_CPU(cs)->env;
    char why[56];

    mvp_gate_reason(env, why, sizeof(why));
    fprintf(stderr, "%s cpu=%d gate=[%s] MVPControl=%08x VPEConf0=%08x "
                    "TCStatus=%08x TCHalt=%08x Status=%08x Cause=%08x ir=%x "
                    "halted=%d pc=0x" TARGET_FMT_lx "\n",
            what, cs->cpu_index, why, (uint32_t)env->mvp->CP0_MVPControl,
            (uint32_t)env->CP0_VPEConf0,
            (uint32_t)env->active_tc.CP0_TCStatus,
            (uint32_t)env->active_tc.CP0_TCHalt,
            (uint32_t)env->CP0_Status, (uint32_t)env->CP0_Cause,
            cs->interrupt_request, cs->halted, env->active_tc.PC);
}

/*
 * Called from mips_cpu_has_work() on the arm where the processor-wide EVP
 * gate overrides an otherwise runnable vCPU.
 *
 * The first observation per vCPU is reported because it is cheap and it
 * distinguishes a machine that has ever been gated from one that has not.
 * It is NOT the wedge: on a healthy boot every vCPU is gated many times,
 * transiently, while a peer holds a dvpe section.  The wedge is the second
 * report, and its predicate is exact -- no VPE is executing, and none can
 * become executable, because EVP is only settable by an executing VPE.
 */
void mips_mvp_note_gate(CPUMIPSState *env)
{
    CPUState *cs = env_cpu(env);
    uint64_t bit = 1ull << (cs->cpu_index & 63);
    uint64_t old;
    CPUState *other;

    if (!mips_mvp_debug) {
        return;
    }
    old = qatomic_fetch_or(&mvp_gate_mask, bit);
    if (!(old & bit)) {
        mvp_report_cpu("MVPGATE", cs);
        fflush(stderr);
    }

    /*
     * Terminal test.  Every vCPU halted and every vCPU MT-gated means no
     * instruction will retire on this machine again: every one of the four
     * gate inputs is guest state that only an executing VPE can write, and
     * mips_cpu_has_work() discards a pending enabled interrupt on this same
     * arm, so a device cannot break the tie either.
     */
    CPU_FOREACH(other) {
        CPUMIPSState *oenv = &MIPS_CPU(other)->env;

        if (other != cs && !other->halted) {
            return;
        }
        if (mips_vpe_active(oenv)) {
            return;
        }
    }
    if (qatomic_xchg(&mvp_strand_seen, 1) != 0) {
        return;
    }
    fprintf(stderr, "MVPWEDGE every vpe halted and MT-gated; "
                    "evp_clears=%" PRIu64 " owed=0x%x gated=0x%" PRIx64 "\n",
            qatomic_read(&mvp_strands), qatomic_read(&mvp_owed_mask),
            old | bit);
    CPU_FOREACH(other) {
        mvp_report_cpu("MVPWEDGE", other);
    }
    /*
     * The latched edges answer the question the state dump cannot: every VPE
     * is halted, so for each one, name the instruction that halted it and the
     * VPE that issued it.
     */
    CPU_FOREACH(other) {
        int i = other->cpu_index;

        if (i < 0 || i >= MIPS_MVP_MAXVPE) {
            continue;
        }
        if (mvp_last_halt[i].op || mvp_last_halt[i].seq) {
            mvp_print_event("MVPHALT", &mvp_last_halt[i]);
        } else {
            fprintf(stderr, "MVPHALT (none) target=%d\n", i);
        }
        if (mvp_last_wake[i].op || mvp_last_wake[i].seq) {
            mvp_print_event("MVPWAKE", &mvp_last_wake[i]);
        } else {
            fprintf(stderr, "MVPWAKE (none) target=%d\n", i);
        }
    }
    mvp_dump_ring();
}
