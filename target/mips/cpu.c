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
#include "qemu/cutils.h"
#include "qemu/qemu-print.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "cpu.h"
#include "internal.h"
#include "kvm_mips.h"
#include "qemu/module.h"
#include "system/kvm.h"
#include "system/qtest.h"
#include "exec/exec-all.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-clock.h"
#include "semihosting/semihost.h"
#include "qemu/qemu-plugin.h"
#include "fpu_helper.h"

const char regnames[32][3] = {
    "r0", "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "t8", "t9", "k0", "k1", "gp", "sp", "s8", "ra",
};

static void fpu_dump_fpr(fpr_t *fpr, FILE *f, bool is_fpu64)
{
    if (is_fpu64) {
        qemu_fprintf(f, "w:%08x d:%016" PRIx64 " fd:%13g fs:%13g psu: %13g\n",
                     fpr->w[FP_ENDIAN_IDX], fpr->d,
                     (double)fpr->fd,
                     (double)fpr->fs[FP_ENDIAN_IDX],
                     (double)fpr->fs[!FP_ENDIAN_IDX]);
    } else {
        fpr_t tmp;

        tmp.w[FP_ENDIAN_IDX] = fpr->w[FP_ENDIAN_IDX];
        tmp.w[!FP_ENDIAN_IDX] = (fpr + 1)->w[FP_ENDIAN_IDX];
        qemu_fprintf(f, "w:%08x d:%016" PRIx64 " fd:%13g fs:%13g psu:%13g\n",
                     tmp.w[FP_ENDIAN_IDX], tmp.d,
                     (double)tmp.fd,
                     (double)tmp.fs[FP_ENDIAN_IDX],
                     (double)tmp.fs[!FP_ENDIAN_IDX]);
    }
}

static void fpu_dump_state(CPUMIPSState *env, FILE *f, int flags)
{
    int i;
    bool is_fpu64 = !!(env->hflags & MIPS_HFLAG_F64);

    qemu_fprintf(f,
                 "CP1 FCR0 0x%08x  FCR31 0x%08x  SR.FR %d  fp_status 0x%02x\n",
                 env->active_fpu.fcr0, env->active_fpu.fcr31, is_fpu64,
                 get_float_exception_flags(&env->active_fpu.fp_status));
    for (i = 0; i < 32; (is_fpu64) ? i++ : (i += 2)) {
        qemu_fprintf(f, "%3s: ", fregnames[i]);
        fpu_dump_fpr(&env->active_fpu.fpr[i], f, is_fpu64);
    }
}

static void mips_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    CPUMIPSState *env = cpu_env(cs);
    int i;

    qemu_fprintf(f, "pc=0x" TARGET_FMT_lx " HI=0x" TARGET_FMT_lx
                 " LO=0x" TARGET_FMT_lx " ds %04x "
                 TARGET_FMT_lx " " TARGET_FMT_ld "\n",
                 env->active_tc.PC, env->active_tc.HI[0], env->active_tc.LO[0],
                 env->hflags, env->btarget, env->bcond);
    for (i = 0; i < 32; i++) {
        if ((i & 3) == 0) {
            qemu_fprintf(f, "GPR%02d:", i);
        }
        qemu_fprintf(f, " %s " TARGET_FMT_lx,
                     regnames[i], env->active_tc.gpr[i]);
        if ((i & 3) == 3) {
            qemu_fprintf(f, "\n");
        }
    }

    qemu_fprintf(f, "CP0 Status  0x%08x Cause   0x%08x EPC    0x"
                 TARGET_FMT_lx "\n",
                 env->CP0_Status, env->CP0_Cause, env->CP0_EPC);
    qemu_fprintf(f, "    Config0 0x%08x Config1 0x%08x LLAddr 0x%016"
                 PRIx64 "\n",
                 env->CP0_Config0, env->CP0_Config1, env->CP0_LLAddr);
    qemu_fprintf(f, "    Config2 0x%08x Config3 0x%08x\n",
                 env->CP0_Config2, env->CP0_Config3);
    qemu_fprintf(f, "    Config4 0x%08x Config5 0x%08x\n",
                 env->CP0_Config4, env->CP0_Config5);
#if !defined(CONFIG_USER_ONLY)
    /*
     * On an MT processor the run/halt state of a VPE is decided by state
     * that none of the above shows: MVPControl.EVP gates every VPE of the
     * processor at once (mips_cpu_has_work()), and TCStatus.A / TCHalt gate
     * the thread context.  A dump taken to explain why a vCPU is not
     * running has to be able to name them.
     */
    if (ase_mt_available(env)) {
        qemu_fprintf(f, "    MVPControl 0x%08x MVPConf0 0x%08x "
                     "VPEConf0 0x%08x\n",
                     env->mvp->CP0_MVPControl, env->mvp->CP0_MVPConf0,
                     env->CP0_VPEConf0);
        qemu_fprintf(f, "    TCStatus 0x%08x TCHalt 0x" TARGET_FMT_lx
                     " VPEControl 0x%08x\n",
                     env->active_tc.CP0_TCStatus, env->active_tc.CP0_TCHalt,
                     env->CP0_VPEControl);
    }
#endif
    if ((flags & CPU_DUMP_FPU) && (env->hflags & MIPS_HFLAG_FPU)) {
        fpu_dump_state(env, f, flags);
    }
}

void cpu_set_exception_base(int vp_index, target_ulong address)
{
    MIPSCPU *vp = MIPS_CPU(qemu_get_cpu(vp_index));
    vp->env.exception_base = address;
}

static void mips_cpu_set_pc(CPUState *cs, vaddr value)
{
    mips_env_set_pc(cpu_env(cs), value);
}

static vaddr mips_cpu_get_pc(CPUState *cs)
{
    MIPSCPU *cpu = MIPS_CPU(cs);

    return cpu->env.active_tc.PC;
}

#if !defined(CONFIG_USER_ONLY)
static bool mips_cpu_has_work(CPUState *cs)
{
    CPUMIPSState *env = cpu_env(cs);
    bool has_work = false;

    /*
     * Prior to MIPS Release 6 it is implementation dependent if non-enabled
     * interrupts wake-up the CPU, however most of the implementations only
     * check for interrupts that can be taken. For pre-release 6 CPUs,
     * check for CP0 Config7 'Wait IE ignore' bit.
     */
    if ((cs->interrupt_request & CPU_INTERRUPT_HARD) &&
        cpu_mips_hw_interrupts_pending(env)) {
        if (cpu_mips_hw_interrupts_enabled(env) ||
            (env->CP0_Config7 & (1 << CP0C7_WII)) ||
            (env->insn_flags & ISA_MIPS_R6)) {
            has_work = true;
        }
    }

    /* MIPS-MT has the ability to halt the CPU.  */
    if (ase_mt_available(env)) {
        /*
         * The QEMU model will issue an _WAKE request whenever the CPUs
         * should be woken up.
         */
        if (cs->interrupt_request & CPU_INTERRUPT_WAKE) {
            has_work = true;
        }

        if (!mips_vpe_active(env)) {
            /*
             * Condition instrument: this vCPU is runnable by every
             * architectural rule and is being held off the run queue by the
             * processor-wide EVP gate alone.  Reported once per vCPU, and
             * only when EVP -- not VPA -- is what closed the gate.
             */
            if (unlikely(mips_mvp_debug > 0)) {
                mips_mvp_note_gate(env);
            }
            has_work = false;
        }
    }
    /* MIPS Release 6 has the ability to halt the CPU.  */
    if (env->CP0_Config5 & (1 << CP0C5_VP)) {
        if (cs->interrupt_request & CPU_INTERRUPT_WAKE) {
            has_work = true;
        }
        if (!mips_vp_active(env)) {
            has_work = false;
        }
    }
    return has_work;
}
#endif /* !CONFIG_USER_ONLY */

static int mips_cpu_mmu_index(CPUState *cs, bool ifunc)
{
    return mips_env_mmu_index(cpu_env(cs));
}

#include "cpu-defs.c.inc"

static void mips_cpu_reset_hold(Object *obj, ResetType type)
{
    CPUState *cs = CPU(obj);
    MIPSCPU *cpu = MIPS_CPU(cs);
    MIPSCPUClass *mcc = MIPS_CPU_GET_CLASS(obj);
    CPUMIPSState *env = &cpu->env;

    if (mcc->parent_phases.hold) {
        mcc->parent_phases.hold(obj, type);
    }

    memset(env, 0, offsetof(CPUMIPSState, end_reset_fields));

    /* Reset registers to their default values */
    env->CP0_PRid = env->cpu_model->CP0_PRid;
    env->CP0_Config0 = deposit32(env->cpu_model->CP0_Config0,
                                 CP0C0_BE, 1, cpu->is_big_endian);
    env->CP0_Config1 = env->cpu_model->CP0_Config1;
    env->CP0_Config2 = env->cpu_model->CP0_Config2;
    env->CP0_Config3 = env->cpu_model->CP0_Config3;
    env->CP0_Config4 = env->cpu_model->CP0_Config4;
    env->CP0_Config4_rw_bitmask = env->cpu_model->CP0_Config4_rw_bitmask;
    env->CP0_Config5 = env->cpu_model->CP0_Config5;
    env->CP0_Config5_rw_bitmask = env->cpu_model->CP0_Config5_rw_bitmask;
    env->CP0_Config6 = env->cpu_model->CP0_Config6;
    env->CP0_Config6_rw_bitmask = env->cpu_model->CP0_Config6_rw_bitmask;
    env->CP0_Config7 = env->cpu_model->CP0_Config7;
    env->CP0_Config7_rw_bitmask = env->cpu_model->CP0_Config7_rw_bitmask;
    env->CP0_LLAddr_rw_bitmask = env->cpu_model->CP0_LLAddr_rw_bitmask
                                 << env->cpu_model->CP0_LLAddr_shift;
    env->CP0_LLAddr_shift = env->cpu_model->CP0_LLAddr_shift;
    env->SYNCI_Step = env->cpu_model->SYNCI_Step;
    env->CCRes = env->cpu_model->CCRes;
    env->CP0_Status_rw_bitmask = env->cpu_model->CP0_Status_rw_bitmask;
    env->CP0_TCStatus_rw_bitmask = env->cpu_model->CP0_TCStatus_rw_bitmask;
    env->CP0_SRSCtl = env->cpu_model->CP0_SRSCtl;
    env->current_tc = 0;
    env->SEGBITS = env->cpu_model->SEGBITS;
    env->SEGMask = (target_ulong)((1ULL << env->cpu_model->SEGBITS) - 1);
#if defined(TARGET_MIPS64)
    if (env->cpu_model->insn_flags & ISA_MIPS3) {
        env->SEGMask |= 3ULL << 62;
    }
#endif
    env->PABITS = env->cpu_model->PABITS;
    env->CP0_SRSConf0_rw_bitmask = env->cpu_model->CP0_SRSConf0_rw_bitmask;
    env->CP0_SRSConf0 = env->cpu_model->CP0_SRSConf0;
    env->CP0_SRSConf1_rw_bitmask = env->cpu_model->CP0_SRSConf1_rw_bitmask;
    env->CP0_SRSConf1 = env->cpu_model->CP0_SRSConf1;
    env->CP0_SRSConf2_rw_bitmask = env->cpu_model->CP0_SRSConf2_rw_bitmask;
    env->CP0_SRSConf2 = env->cpu_model->CP0_SRSConf2;
    env->CP0_SRSConf3_rw_bitmask = env->cpu_model->CP0_SRSConf3_rw_bitmask;
    env->CP0_SRSConf3 = env->cpu_model->CP0_SRSConf3;
    env->CP0_SRSConf4_rw_bitmask = env->cpu_model->CP0_SRSConf4_rw_bitmask;
    env->CP0_SRSConf4 = env->cpu_model->CP0_SRSConf4;
    env->CP0_PageGrain_rw_bitmask = env->cpu_model->CP0_PageGrain_rw_bitmask;
    env->CP0_PageGrain = env->cpu_model->CP0_PageGrain;
    env->CP0_EBaseWG_rw_bitmask = env->cpu_model->CP0_EBaseWG_rw_bitmask;
    env->lcsr_cpucfg1 = env->cpu_model->lcsr_cpucfg1;
    env->lcsr_cpucfg2 = env->cpu_model->lcsr_cpucfg2;
    env->active_fpu.fcr0 = env->cpu_model->CP1_fcr0;
    env->active_fpu.fcr31_rw_bitmask = env->cpu_model->CP1_fcr31_rw_bitmask;
    env->active_fpu.fcr31 = env->cpu_model->CP1_fcr31;
    env->msair = env->cpu_model->MSAIR;
    env->insn_flags = env->cpu_model->insn_flags;

#if defined(CONFIG_USER_ONLY)
    env->CP0_Status = (MIPS_HFLAG_UM << CP0St_KSU);
# ifdef TARGET_MIPS64
    /* Enable 64-bit register mode.  */
    env->CP0_Status |= (1 << CP0St_PX);
# endif
# ifdef TARGET_ABI_MIPSN64
    /* Enable 64-bit address mode.  */
    env->CP0_Status |= (1 << CP0St_UX);
# endif
    /*
     * Enable access to the CPUNum, SYNCI_Step, CC, and CCRes RDHWR
     * hardware registers.
     */
    env->CP0_HWREna |= 0x0000000F;
    if (env->CP0_Config1 & (1 << CP0C1_FP)) {
        env->CP0_Status |= (1 << CP0St_CU1);
    }
    if (env->CP0_Config3 & (1 << CP0C3_DSPP)) {
        env->CP0_Status |= (1 << CP0St_MX);
    }
# if defined(TARGET_MIPS64)
    /* For MIPS64, init FR bit to 1 if FPU unit is there and bit is writable. */
    if ((env->CP0_Config1 & (1 << CP0C1_FP)) &&
        (env->CP0_Status_rw_bitmask & (1 << CP0St_FR))) {
        env->CP0_Status |= (1 << CP0St_FR);
    }
# endif
#else /* !CONFIG_USER_ONLY */
    if (env->hflags & MIPS_HFLAG_BMASK) {
        /*
         * If the exception was raised from a delay slot,
         * come back to the jump.
         */
        env->CP0_ErrorEPC = (env->active_tc.PC
                             - (env->hflags & MIPS_HFLAG_B16 ? 2 : 4));
    } else {
        env->CP0_ErrorEPC = env->active_tc.PC;
    }
    env->active_tc.PC = env->exception_base;
    env->CP0_Random = env->tlb->nb_tlb - 1;
    env->tlb->tlb_in_use = env->tlb->nb_tlb;
    env->CP0_Wired = 0;
    env->CP0_GlobalNumber = (cs->cpu_index & 0xFF) << CP0GN_VPId;
    env->CP0_EBase = KSEG0_BASE | (cs->cpu_index & 0x3FF);
    if (env->CP0_Config3 & (1 << CP0C3_CMGCR)) {
        env->CP0_CMGCRBase = 0x1fbf8000 >> 4;
    }
    env->CP0_EntryHi_ASID_mask = (env->CP0_Config5 & (1 << CP0C5_MI)) ?
            0x0 : (env->CP0_Config4 & (1 << CP0C4_AE)) ? 0x3ff : 0xff;
    env->CP0_Status = (1 << CP0St_BEV) | (1 << CP0St_ERL);
    if (env->insn_flags & INSN_LOONGSON2F) {
        /* Loongson-2F has those bits hardcoded to 1 */
        env->CP0_Status |= (1 << CP0St_KX) | (1 << CP0St_SX) |
                            (1 << CP0St_UX);
    }

    /*
     * Vectored interrupts not implemented, timer on int 7,
     * no performance counters.
     */
    env->CP0_IntCtl = 0xe0000000;
    {
        int i;

        for (i = 0; i < 7; i++) {
            env->CP0_WatchLo[i] = 0;
            env->CP0_WatchHi[i] = 1 << CP0WH_M;
        }
        env->CP0_WatchLo[7] = 0;
        env->CP0_WatchHi[7] = 0;
    }
    /* Count register increments in debug mode, EJTAG version 1 */
    env->CP0_Debug = (1 << CP0DB_CNT) | (0x1 << CP0DB_VER);

    cpu_mips_store_count(env, 1);

    if (ase_mt_available(env)) {
        int i;

        /* Only TC0 on VPE 0 starts as active.  */
        for (i = 0; i < ARRAY_SIZE(env->tcs); i++) {
            env->tcs[i].CP0_TCBind = cs->cpu_index << CP0TCBd_CurVPE;
            env->tcs[i].CP0_TCHalt = 1;
        }
        env->active_tc.CP0_TCHalt = 1;
        cs->halted = 1;

        /* A reset leaves no DVPE section open, whichever VPE held one.  */
        qatomic_set(&env->mvp->evp_owner, -1);

        if (cs->cpu_index == 0) {
            /* VPE0 starts up enabled.  */
            env->mvp->CP0_MVPControl |= (1 << CP0MVPCo_EVP);
            env->CP0_VPEConf0 |= (1 << CP0VPEC0_MVP) | (1 << CP0VPEC0_VPA);

            /* TC0 starts up unhalted.  */
            cs->halted = 0;
            env->active_tc.CP0_TCHalt = 0;
            env->tcs[0].CP0_TCHalt = 0;
            /* With thread 0 active.  */
            env->active_tc.CP0_TCStatus = (1 << CP0TCSt_A);
            env->tcs[0].CP0_TCStatus = (1 << CP0TCSt_A);
        }
    }

    /*
     * Configure default legacy segmentation control. We use this regardless of
     * whether segmentation control is presented to the guest.
     */
    /* KSeg3 (seg0 0xE0000000..0xFFFFFFFF) */
    env->CP0_SegCtl0 =   (CP0SC_AM_MK << CP0SC_AM);
    /* KSeg2 (seg1 0xC0000000..0xDFFFFFFF) */
    env->CP0_SegCtl0 |= ((CP0SC_AM_MSK << CP0SC_AM)) << 16;
    /* KSeg1 (seg2 0xA0000000..0x9FFFFFFF) */
    env->CP0_SegCtl1 =   (0 << CP0SC_PA) | (CP0SC_AM_UK << CP0SC_AM) |
                         (2 << CP0SC_C);
    /* KSeg0 (seg3 0x80000000..0x9FFFFFFF) */
    env->CP0_SegCtl1 |= ((0 << CP0SC_PA) | (CP0SC_AM_UK << CP0SC_AM) |
                         (3 << CP0SC_C)) << 16;
    /* USeg (seg4 0x40000000..0x7FFFFFFF) */
    env->CP0_SegCtl2 =   (2 << CP0SC_PA) | (CP0SC_AM_MUSK << CP0SC_AM) |
                         (1 << CP0SC_EU) | (2 << CP0SC_C);
    /* USeg (seg5 0x00000000..0x3FFFFFFF) */
    env->CP0_SegCtl2 |= ((0 << CP0SC_PA) | (CP0SC_AM_MUSK << CP0SC_AM) |
                         (1 << CP0SC_EU) | (2 << CP0SC_C)) << 16;
    /* XKPhys (note, SegCtl2.XR = 0, so XAM won't be used) */
    env->CP0_SegCtl1 |= (CP0SC_AM_UK << CP0SC1_XAM);
#endif /* !CONFIG_USER_ONLY */
    if ((env->insn_flags & ISA_MIPS_R6) &&
        (env->active_fpu.fcr0 & (1 << FCR0_F64))) {
        /* Status.FR = 0 mode in 64-bit FPU not allowed in R6 */
        env->CP0_Status |= (1 << CP0St_FR);
    }

    if (env->insn_flags & ISA_MIPS_R6) {
        /* PTW  =  1 */
        env->CP0_PWSize = 0x40;
        /* GDI  = 12 */
        /* UDI  = 12 */
        /* MDI  = 12 */
        /* PRI  = 12 */
        /* PTEI =  2 */
        env->CP0_PWField = 0x0C30C302;
    } else {
        /* GDI  =  0 */
        /* UDI  =  0 */
        /* MDI  =  0 */
        /* PRI  =  0 */
        /* PTEI =  2 */
        env->CP0_PWField = 0x02;
    }

    if (env->CP0_Config3 & (1 << CP0C3_ISA) & (1 << (CP0C3_ISA + 1))) {
        /*  microMIPS on reset when Config3.ISA is 3 */
        env->hflags |= MIPS_HFLAG_M16;
    }

    msa_reset(env);
    fp_reset(env);

    compute_hflags(env);
    restore_pamask(env);
    cs->exception_index = EXCP_NONE;

    if (semihosting_get_argc()) {
        /* UHI interface can be used to obtain argc and argv */
        env->active_tc.gpr[4] = -1;
    }

#ifndef CONFIG_USER_ONLY
    if (kvm_enabled()) {
        kvm_mips_reset_vcpu(cpu);
    }
#endif
}

static void mips_cpu_disas_set_info(CPUState *s, disassemble_info *info)
{
    if (!(cpu_env(s)->insn_flags & ISA_NANOMIPS32)) {
        info->endian = TARGET_BIG_ENDIAN ? BFD_ENDIAN_BIG
                                         : BFD_ENDIAN_LITTLE;
        info->print_insn = TARGET_BIG_ENDIAN ? print_insn_big_mips
                                             : print_insn_little_mips;
    } else {
        info->print_insn = print_insn_nanomips;
        info->endian = BFD_ENDIAN_LITTLE;
    }
}

/*
 * Since commit 6af0bf9c7c3 this model assumes a CPU clocked at 200MHz.
 */
#define CPU_FREQ_HZ_DEFAULT     200000000

static void mips_cp0_period_set(MIPSCPU *cpu)
{
    CPUMIPSState *env = &cpu->env;

    clock_set_mul_div(cpu->count_div, env->cpu_model->CCRes, 1);
    clock_set_source(cpu->count_div, cpu->clock);
    clock_set_source(env->count_clock, cpu->count_div);
}

static void mips_cpu_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    MIPSCPU *cpu = MIPS_CPU(dev);
    CPUMIPSState *env = &cpu->env;
    MIPSCPUClass *mcc = MIPS_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    if (!clock_get(cpu->clock)) {
#ifndef CONFIG_USER_ONLY
        if (!qtest_enabled()) {
            g_autofree char *cpu_freq_str = freq_to_str(CPU_FREQ_HZ_DEFAULT);

            warn_report("CPU input clock is not connected to any output clock, "
                        "using default frequency of %s.", cpu_freq_str);
        }
#endif
        /* Initialize the frequency in case the clock remains unconnected. */
        clock_set_hz(cpu->clock, CPU_FREQ_HZ_DEFAULT);
    }
    mips_cp0_period_set(cpu);

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    env->exception_base = (int32_t)0xBFC00000;

#if defined(CONFIG_TCG) && !defined(CONFIG_USER_ONLY)
    mmu_init(env, env->cpu_model);
#endif
    fpu_init(env, env->cpu_model);
    mvp_init(env);
#if !defined(CONFIG_USER_ONLY)
    mips_mvp_debug_init();
#endif

    cpu_reset(cs);
    qemu_init_vcpu(cs);

    mcc->parent_realize(dev, errp);
}

static void mips_cpu_initfn(Object *obj)
{
    MIPSCPU *cpu = MIPS_CPU(obj);
    CPUMIPSState *env = &cpu->env;
    MIPSCPUClass *mcc = MIPS_CPU_GET_CLASS(obj);

    cpu->clock = qdev_init_clock_in(DEVICE(obj), "clk-in", NULL, cpu, 0);
    cpu->count_div = clock_new(OBJECT(obj), "clk-div-count");
    env->count_clock = clock_new(OBJECT(obj), "clk-count");
    env->cpu_model = mcc->cpu_def;
#ifndef CONFIG_USER_ONLY
    if (mcc->cpu_def->lcsr_cpucfg2 & (1 << CPUCFG2_LCSRP)) {
        memory_region_init_io(&env->iocsr.mr, OBJECT(cpu), NULL,
                                env, "iocsr", UINT64_MAX);
        address_space_init(&env->iocsr.as,
                            &env->iocsr.mr, "IOCSR");
    }
#endif
}

static char *mips_cpu_type_name(const char *cpu_model)
{
    return g_strdup_printf(MIPS_CPU_TYPE_NAME("%s"), cpu_model);
}

static ObjectClass *mips_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;

    typename = mips_cpu_type_name(cpu_model);
    oc = object_class_by_name(typename);
    g_free(typename);
    return oc;
}

#ifndef CONFIG_USER_ONLY
#include "hw/core/sysemu-cpu-ops.h"

static const struct SysemuCPUOps mips_sysemu_ops = {
    .has_work = mips_cpu_has_work,
    .get_phys_page_debug = mips_cpu_get_phys_page_debug,
    .legacy_vmsd = &vmstate_mips_cpu,
};
#endif

static const Property mips_cpu_properties[] = {
    DEFINE_PROP_BOOL("big-endian", MIPSCPU, is_big_endian, TARGET_BIG_ENDIAN),
};

#ifdef CONFIG_TCG
#include "accel/tcg/cpu-ops.h"
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
/*
 * The MIPS page-table root, as an address a consumer can compare.
 *
 * CP0 PWBase (Config3.PW) is the base the HARDWARE page-table walker walks
 * from, so it is the same kind of register as x86 CR3, AArch64 TTBR0 and
 * RISC-V SATP: the value the architecture itself translates through, not a
 * tag an operating system hands out.  Linux writes it in
 * htw_set_pwbase(), reached from TLBMISS_HANDLER_SETUP_PGD(), i.e. from
 * every switch_mm()/activate_mm() — so it holds the current mm's pgd for
 * exactly as long as that mm is current.
 *
 * The kernel programs it with a KSEG0/KSEG1 virtual address (the pgd is
 * allocated from lowmem and used unmapped).  Normalise those to the
 * physical address they name so the reported key is the page-table root
 * itself: kseg0 and kseg1 are two virtual names for one physical page, and
 * an address space must not acquire a second identity because the kernel
 * chose the uncached window.  Anything else — an XKPHYS or mapped address
 * on a 64-bit kernel — is passed through verbatim; it is still a stable
 * per-mm value, and inventing a translation for it would be guesswork.
 */
static uint64_t mips_pwbase_key(CPUMIPSState *env)
{
    uint64_t pw = (uint64_t)env->CP0_PWBase;
    uint64_t seg = pw & 0xE0000000ULL;

    if (seg == 0x80000000ULL || seg == 0xA0000000ULL) {
        return pw & 0x1FFFFFFFULL;
    }
    return pw;
}

static void mips_get_plugin_state(CPUState *cs, int *priv, uint64_t *asid,
                                  bool *mmu_on)
{
    CPUMIPSState *env = cpu_env(cs);
    /* KSU: 0 = kernel, 1 = supervisor, 2 (MIPS_HFLAG_UM) = user.
     * Normalize so 0 = user (least privileged), larger = more privileged. */
    int ksu = env->hflags & MIPS_HFLAG_KSU;
    *priv = MIPS_HFLAG_UM - ksu;
    /*
     * The reported address-space value is the page-table ROOT wherever the
     * model has one, exactly as on the wide-register targets, so a consumer
     * that stores it stores a real root: CP0 PWBase under Config3.PW (see
     * mips_pwbase_key), which the hardware walker itself translates from
     * and which Linux repoints at each switch_mm.  It is per-mm, so both
     * vCPUs of an SMP guest report the same value for one address space and
     * a migration is not a rename; it is unforgeable, because a wrong value
     * faults the guest rather than mislabelling it; and a fork() child gets
     * a new pgd, hence a different value, from its first instruction.
     *
     * Config3.PW clear (24Kf, 34Kf, 20Kc — every non-P5600 MIPS model in
     * QEMU) leaves only EntryHi.ASID: 8 bits, 10 with Config4.AE, over a
     * 16-entry TLB, allocated per CPU and re-pointed at a DIFFERENT LIVE
     * process on generation rollover.  It is reported because it is what
     * the architecture says now, but it does not distinguish two live
     * processes and a consumer that needs that must check
     * qemu_plugin_identity_caps() and refuse.  Deliberately NOT composed
     * with anything on such a model: CP0 Context holds
     * smp_processor_id() << SMP_CPUID_REGSHIFT on 32-bit MIPS Linux, not a
     * pgd (a per-CPU constant would make cross-vCPU equality strictly
     * worse), XContext exists only on MIPS64 CONFIG_MIPS_PGD_C0_CONTEXT
     * kernels, and a KScratch-resident pgd needs Config4.KScrExist which
     * those models do not implement.  Reading any of them as a root would
     * be an OS convention, not an architectural fact.
     */
    if (env->CP0_Config3 & (1 << CP0C3_PW)) {
        *asid = mips_pwbase_key(env);
    } else {
        *asid = env->CP0_EntryHi & env->CP0_EntryHi_ASID_mask;
    }
    /* MIPS always translates through the TLB (mapped segments fault on a
     * TLB miss); there is no global paging-disable, so report on. */
    *mmu_on = true;
}

static bool mips_vaddr_is_kernel(CPUState *cs, uint64_t vaddr);

static uint64_t mips_get_plugin_thread_ptr(CPUState *cs)
{
    CPUMIPSState *env = cpu_env(cs);
    /*
     * CP0 UserLocal (reg 4 sel 2, the rdhwr $29 TLS base).  A kernel
     * writes it on every thread switch when Config3.ULRI advertises it;
     * on models without ULRI it stays 0 and threads are architecturally
     * indistinguishable by it (the kernel keeps the TLS pointer in RAM
     * and trap-emulates rdhwr).  Kept whenever it is non-zero, at any
     * privilege: it is reloaded from the incoming task at each switch,
     * so a thread's kernel excursions stay on the SAME identity its user
     * code carries.
     *
     * UserLocal == 0 in kernel mode is a task with no TLS identity — a
     * kernel thread or per-CPU idle task, or any task on a no-ULRI model
     * (this includes the whole 24K/34K Malta class).  Those are distinct
     * program paths, so fall through to the kernel's own per-task
     * contract: Linux/MIPS dedicates $28 (gp) to current_thread_info in
     * kernel mode (arch/mips/include/asm/thread_info.h declares it
     * register-resident in $28; stackframe.h SAVE_SOME derives it from
     * the kernel sp — `ori $28, sp, _THREAD_MASK; xori $28,
     * _THREAD_MASK` — on every entry from user).  MIPS keeps
     * thread_info at the base of each task's kernel stack (no
     * THREAD_INFO_IN_TASK), so the value is per-task and stable for the
     * task's life.  Before SAVE_SOME runs — the exception-vector window —
     * $28 still holds the interrupted user's gp, which on MIPS can only
     * be a useg VA: the kernel-VA test rejects it, the tracks-current
     * hook reports false, and the consumer inherits the entering thread
     * (which is the interrupted thread itself).
     */
    uint64_t tp = env->active_tc.CP0_UserLocal;
    if (tp != 0 || (env->hflags & MIPS_HFLAG_KSU) == MIPS_HFLAG_UM) {
        return tp;
    }
    uint64_t gp = env->active_tc.gpr[28];
    if (mips_vaddr_is_kernel(cs, gp)) {
        return gp;
    }
    return tp;
}

/*
 * Raw architectural identity keys (see TCGCPUOps::get_plugin_identity).
 *
 * Address space: CP0 PWBase, the hardware page-table walker's base
 * register, on any model that implements the walker (Config3.PW).  That
 * makes MIPS the same kind of target as x86-64 (CR3), AArch64 (TTBR0) and
 * RISC-V (SATP) — the key is the root the hardware translates from, which
 * is per-mm, identical on every vCPU running that mm, distinct for a fork
 * child from its first instruction, and self-enforcing (a guest that put
 * the wrong value there would fault, not merely be mislabelled).
 *
 * Zero is NOT a narrow fallback.  A model with Config3.PW whose guest has
 * not programmed PWBase ("nohtw", CONFIG_MIPS_HTW=n, or a kernel that
 * declined the walker after checking PTEI) reports 0, which the interning
 * layer already refuses to turn into an id.  Substituting EntryHi.ASID
 * there would silently reintroduce the whole reuse hazard on exactly the
 * boots where it is invisible, so it is not done: PW set means PWBase, and
 * 0 means no identity.
 *
 * Config3.PW clear leaves EntryHi.ASID under the CPU's own ASID mask, with
 * CP0 MemoryMapID above it when Config5.MI makes MemoryMapID (not ASID)
 * the TLB's tag.  That is a NAME, not an identity — 8 bits over a 16-entry
 * TLB, re-pointed at a different live address space on rollover — and
 * qemu_plugin_identity_caps() reports the difference so a consumer that
 * cannot tolerate it refuses the run rather than following the wrong
 * process.
 *
 * Thread: CP0 UserLocal.  A model that does not implement it (Config3.ULRI
 * clear — the 24K class, including the canonical Malta default) leaves it
 * 0, which is reported as "no thread identity" rather than being replaced
 * by a general-purpose register the architecture does not designate.
 */
static void mips_get_plugin_identity(CPUState *cs, uint64_t *space_key,
                                     uint64_t *thread_key)
{
    CPUMIPSState *env = cpu_env(cs);
    uint64_t key;

    if (env->CP0_Config3 & (1 << CP0C3_PW)) {
        key = mips_pwbase_key(env);
    } else {
        key = env->CP0_EntryHi & env->CP0_EntryHi_ASID_mask;
        if (env->CP0_Config5 & (1 << CP0C5_MI)) {
            key |= ((uint64_t)(uint32_t)env->CP0_MemoryMapID) << 32;
        }
    }
    *space_key = key;
    *thread_key = env->active_tc.CP0_UserLocal;
}

/*
 * The exhaustible tag, reported for WITNESSING only (see
 * TCGCPUOps::get_plugin_narrow_asid).  This is the value the identity hook
 * above stopped using on a walker-capable model, and it is deliberately
 * still readable: a consumer has to be able to observe the guest recycling
 * it WITHOUT that observation being derived from the ownership key it is
 * meant to corroborate.  Reported at every model, walker or not.
 */
static uint64_t mips_get_plugin_narrow_asid(CPUState *cs)
{
    CPUMIPSState *env = cpu_env(cs);
    uint64_t tag = env->CP0_EntryHi & env->CP0_EntryHi_ASID_mask;

    if (env->CP0_Config5 & (1 << CP0C5_MI)) {
        tag |= ((uint64_t)(uint32_t)env->CP0_MemoryMapID) << 32;
    }
    return tag;
}

/*
 * Which identity keys this MIPS MODEL can supply (see
 * CPUClass::plugin_identity_caps).  Read from the model definition, not
 * from a live CPU: the answer has to be available at plugin-install time,
 * which is before any CPUState exists.  Same shape as
 * cpu_type_supports_cps_smp() below.
 *
 * Today exactly one QEMU MIPS model implements the walker — P5600
 * (cpu-defs.c.inc sets CP0C3_PW there and nowhere else) — and it also sets
 * CP0C3_ULRI and CP0C3_CMGCR, so it names a thread and can boot an SMP
 * malta through the CPS path.  The test is on the bits, not on the model
 * name, so a model that gains the walker later is picked up for free.
 */
static uint64_t mips_plugin_identity_caps(ObjectClass *oc)
{
    const MIPSCPUClass *mcc = MIPS_CPU_CLASS(oc);
    uint64_t caps = 0;

    if (!mcc->cpu_def) {
        return 0;
    }
    if (mcc->cpu_def->CP0_Config3 & (1 << CP0C3_PW)) {
        caps |= QEMU_PLUGIN_IDENT_SPACE_IS_ROOT;
    }
    if (mcc->cpu_def->CP0_Config3 & (1 << CP0C3_ULRI)) {
        caps |= QEMU_PLUGIN_IDENT_NAMES_THREAD;
    }
    return caps;
}

static bool mips_plugin_thread_ptr_tracks_current(CPUState *cs)
{
    CPUMIPSState *env = cpu_env(cs);
    /* UserLocal is user-TLS-only state the kernel has no use of its own
     * for; it is reloaded from the incoming task at every switch and
     * untouched in between, at any privilege.  The state it cannot vouch
     * for: a no-TLS task (UserLocal 0) in the exception-vector window
     * before SAVE_SOME re-derives $28 — neither register names the task
     * there, so the consumer inherits the entering thread. */
    if (env->active_tc.CP0_UserLocal == 0 &&
        (env->hflags & MIPS_HFLAG_KSU) != MIPS_HFLAG_UM) {
        return mips_vaddr_is_kernel(cs, env->active_tc.gpr[28]);
    }
    return true;
}

static bool mips_vaddr_is_kernel(CPUState *cs, uint64_t vaddr)
{
    /*
     * MIPS partitions the VA space into fixed segments by address range
     * (see get_physical_address()): the low useg (and, on MIPS64, xuseg) is
     * the only user-accessible region; everything above — kseg0/1/2/3 and the
     * 64-bit xsseg/xkphys/xkseg — is kernel/supervisor.  So a code fetch is
     * kernel-domain exactly when it falls outside useg/xuseg.  This is a pure
     * range test on the fixed segment map (no CPU state, no TLB probe); the
     * same USEG_LIMIT / segment boundaries the address-translation path uses
     * are applied here.  Cast to target_ulong first so a 32-bit guest's PC
     * (kseg0 = 0x80000000) compares in its own width rather than as a
     * spuriously-small uint64_t.
     */
    (void)cs;
    target_ulong address = (target_ulong)vaddr;
    if (address <= USEG_LIMIT) {
        return false;                         /* useg — user */
    }
#if defined(TARGET_MIPS64)
    if (address < 0x4000000000000000ULL) {
        return false;                         /* xuseg — user */
    }
#endif
    return true;                              /* kseg / xsseg / xkphys / xkseg */
}

/*
 * TCGCPUOps::spec_clock_resync for MIPS — see the contract in
 * include/accel/tcg/cpu-ops.h.
 *
 * MIPS's audit.  The only architectural time source is the CP0 Count/Compare
 * pair (with Cause.DC as the count-disable), and Count is computed on demand
 * from QEMU_CLOCK_VIRTUAL (cpu_mips_get_count_val), so the freeze already
 * leaves it consistent with the frozen time.  What has to be reconciled is the
 * R4K host QEMUTimer behind Compare -- an architectural register inside the
 * rolled-back snapshot -- together with any expiry the excursion gate in
 * cpu_mips_timer_expire suppressed, and the CPU_INTERRUPT_HARD line, which
 * cpu_mips_irq_request stops driving for the whole excursion while
 * CP0_Cause.IP is rewound underneath it.  mips_cpu_plugin_resync_timers does
 * both, unconditionally.
 *
 * SPEC_CLOCK_THAW needs nothing: Count is a pure function of the virtual
 * clock.
 */
static void mips_spec_clock_resync(CPUState *cs, SpecClockResyncReason reason)
{
    if (reason != SPEC_CLOCK_EXCURSION_END) {
        return;
    }
    mips_cpu_plugin_resync_timers(cs);
}
#endif

static const TCGCPUOps mips_tcg_ops = {
    .initialize = mips_tcg_init,
    .translate_code = mips_translate_code,
    .synchronize_from_tb = mips_cpu_synchronize_from_tb,
    .restore_state_to_opc = mips_restore_state_to_opc,
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
    .get_plugin_state = mips_get_plugin_state,
    .get_plugin_thread_ptr = mips_get_plugin_thread_ptr,
    .get_plugin_identity = mips_get_plugin_identity,
    .get_plugin_narrow_asid = mips_get_plugin_narrow_asid,
    /* CP0 UserLocal is a dedicated TLS slot the kernel has no use of its
     * own for: Linux/MIPS writes it from the incoming task in switch_to()
     * and never touches it in between, so a kernel-privilege read names
     * the current task (0 for a kernel thread). */
    .plugin_thread_ptr_tracks_current = mips_plugin_thread_ptr_tracks_current,
    .vaddr_is_kernel = mips_vaddr_is_kernel,
    .spec_clock_resync = mips_spec_clock_resync,
#endif

#if !defined(CONFIG_USER_ONLY)
    .tlb_fill = mips_cpu_tlb_fill,
    .cpu_exec_interrupt = mips_cpu_exec_interrupt,
    .cpu_exec_halt = mips_cpu_has_work,
    .do_interrupt = mips_cpu_do_interrupt,
    .do_transaction_failed = mips_cpu_do_transaction_failed,
    .do_unaligned_access = mips_cpu_do_unaligned_access,
    .io_recompile_replay_branch = mips_io_recompile_replay_branch,
#endif /* !CONFIG_USER_ONLY */
};
#endif /* CONFIG_TCG */

static void mips_cpu_class_init(ObjectClass *c, void *data)
{
    MIPSCPUClass *mcc = MIPS_CPU_CLASS(c);
    CPUClass *cc = CPU_CLASS(c);
    DeviceClass *dc = DEVICE_CLASS(c);
    ResettableClass *rc = RESETTABLE_CLASS(c);

    device_class_set_props(dc, mips_cpu_properties);
    device_class_set_parent_realize(dc, mips_cpu_realizefn,
                                    &mcc->parent_realize);
    resettable_class_set_parent_phases(rc, NULL, mips_cpu_reset_hold, NULL,
                                       &mcc->parent_phases);

    cc->class_by_name = mips_cpu_class_by_name;
    cc->mmu_index = mips_cpu_mmu_index;
    cc->dump_state = mips_cpu_dump_state;
    cc->set_pc = mips_cpu_set_pc;
    cc->get_pc = mips_cpu_get_pc;
    cc->gdb_read_register = mips_cpu_gdb_read_register;
    cc->gdb_write_register = mips_cpu_gdb_write_register;
#if defined(TARGET_MIPS64)
    cc->gdb_core_xml_file = "mips64-cpu.xml";
#else
    cc->gdb_core_xml_file = "mips-cpu.xml";
#endif
#ifndef CONFIG_USER_ONLY
    cc->sysemu_ops = &mips_sysemu_ops;
#endif
    cc->disas_set_info = mips_cpu_disas_set_info;
    cc->gdb_num_core_regs = 73;
    cc->gdb_stop_before_watchpoint = true;
#if defined(CONFIG_TCG) && defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
    cc->plugin_identity_caps = mips_plugin_identity_caps;
#endif
#ifdef CONFIG_TCG
    cc->tcg_ops = &mips_tcg_ops;
#endif /* CONFIG_TCG */
}

static const TypeInfo mips_cpu_type_info = {
    .name = TYPE_MIPS_CPU,
    .parent = TYPE_CPU,
    .instance_size = sizeof(MIPSCPU),
    .instance_align = __alignof(MIPSCPU),
    .instance_init = mips_cpu_initfn,
    .abstract = true,
    .class_size = sizeof(MIPSCPUClass),
    .class_init = mips_cpu_class_init,
};

static void mips_cpu_cpudef_class_init(ObjectClass *oc, void *data)
{
    MIPSCPUClass *mcc = MIPS_CPU_CLASS(oc);
    mcc->cpu_def = data;
}

static void mips_register_cpudef_type(const struct mips_def_t *def)
{
    char *typename = mips_cpu_type_name(def->name);
    TypeInfo ti = {
        .name = typename,
        .parent = TYPE_MIPS_CPU,
        .class_init = mips_cpu_cpudef_class_init,
        .class_data = (void *)def,
    };

    type_register_static(&ti);
    g_free(typename);
}

static void mips_cpu_register_types(void)
{
    int i;

    type_register_static(&mips_cpu_type_info);
    for (i = 0; i < mips_defs_number; i++) {
        mips_register_cpudef_type(&mips_defs[i]);
    }
}

type_init(mips_cpu_register_types)

/* Could be used by generic CPU object */
MIPSCPU *mips_cpu_create_with_clock(const char *cpu_type, Clock *cpu_refclk,
                                    bool is_big_endian)
{
    DeviceState *cpu;

    cpu = qdev_new(cpu_type);
    qdev_connect_clock_in(cpu, "clk-in", cpu_refclk);
    object_property_set_bool(OBJECT(cpu), "big-endian", is_big_endian,
                             &error_abort);
    qdev_realize(cpu, NULL, &error_abort);

    return MIPS_CPU(cpu);
}

bool cpu_supports_isa(const CPUMIPSState *env, uint64_t isa_mask)
{
    return (env->cpu_model->insn_flags & isa_mask) != 0;
}

bool cpu_type_supports_isa(const char *cpu_type, uint64_t isa)
{
    const MIPSCPUClass *mcc = MIPS_CPU_CLASS(object_class_by_name(cpu_type));
    return (mcc->cpu_def->insn_flags & isa) != 0;
}

bool cpu_type_supports_cps_smp(const char *cpu_type)
{
    const MIPSCPUClass *mcc = MIPS_CPU_CLASS(object_class_by_name(cpu_type));
    return (mcc->cpu_def->CP0_Config3 & (1 << CP0C3_CMGCR)) != 0;
}
