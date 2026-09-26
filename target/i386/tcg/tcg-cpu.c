/*
 * i386 TCG cpu class initialization
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "helper-tcg.h"
#include "qemu/accel.h"
#include "accel/accel-cpu-target.h"
#include "exec/translation-block.h"
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
#include "qemu/timer.h"
#include "system/cpu-timers.h"
#include "qemu/plugin.h"
#include "qemu/bswap.h"
#endif

#include "tcg-cpu.h"
#include "exec/plugin-gen.h"

/* Frob eflags into and out of the CPU temporary format.  */

static void x86_cpu_exec_enter(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    CC_SRC = env->eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    env->df = 1 - (2 * ((env->eflags >> 10) & 1));
    CC_OP = CC_OP_EFLAGS;
    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
}

static void x86_cpu_exec_exit(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    env->eflags = cpu_compute_eflags(env);
}

static void x86_cpu_synchronize_from_tb(CPUState *cs,
                                        const TranslationBlock *tb)
{
    /* The instruction pointer is always up to date with CF_PCREL. */
    if (!(tb_cflags(tb) & CF_PCREL)) {
        CPUX86State *env = cpu_env(cs);

        if (tb->flags & HF_CS64_MASK) {
            env->eip = tb->pc;
        } else {
            env->eip = (uint32_t)(tb->pc - tb->cs_base);
        }
    }
}

static void x86_restore_state_to_opc(CPUState *cs,
                                     const TranslationBlock *tb,
                                     const uint64_t *data)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    int cc_op = data[1];
    uint64_t new_pc;

    if (tb_cflags(tb) & CF_PCREL) {
        /*
         * data[0] in PC-relative TBs is also a linear address, i.e. an address with
         * the CS base added, because it is not guaranteed that EIP bits 12 and higher
         * stay the same across the translation block.  Add the CS base back before
         * replacing the low bits, and subtract it below just like for !CF_PCREL.
         */
        uint64_t pc = env->eip + tb->cs_base;
        new_pc = (pc & TARGET_PAGE_MASK) | data[0];
    } else {
        new_pc = data[0];
    }
    if (tb->flags & HF_CS64_MASK) {
        env->eip = new_pc;
    } else {
        env->eip = (uint32_t)(new_pc - tb->cs_base);
    }

    if (cc_op != CC_OP_DYNAMIC) {
        env->cc_op = cc_op;
    }
}

#ifndef CONFIG_USER_ONLY
static bool x86_debug_check_breakpoint(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    /* RF disables all architectural breakpoints. */
    return !(env->eflags & RF_MASK);
}
#endif

#include "accel/tcg/cpu-ops.h"

#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
static void x86_get_plugin_state(CPUState *cs, int *priv, uint64_t *asid,
                                 bool *mmu_on)
{
    CPUX86State *env = cpu_env(cs);
    /*
     * CPL: 0 = kernel ... 3 = user.  Normalize so 0 = user (least
     * privileged), larger = more privileged.
     */
    int cpl = (env->hflags & HF_CPL_MASK) >> HF_CPL_SHIFT;
    *priv = 3 - cpl;
    /*
     * CR3 = current page-table base / address-space id, masking bit 63
     * (PCID NOFLUSH).  Architecturally bit 63 is a command bit on the
     * MOV-to-CR3 write -- "skip the TLB flush" -- not state: MOV from CR3
     * always reads it as 0, so it can never distinguish address spaces
     * and masking it is unconditionally safe.  TCG does not advertise
     * PCID (TCG_EXT_FEATURES), so the mask guards the verbatim CR3 image
     * loads (VMRUN, SMM RSM) and any future TCG PCID support.  PCID bits
     * [11:0] are not masked: with CR4.PCIDE they are a genuine component
     * of the address-space identity.  Producers of ASID-change
     * notifications must compare under this same mask (see
     * cpu_x86_update_cr3).
     */
    *asid = env->cr[3] & ~CR3_NOFLUSH_MASK;
    /* Paging active iff CR0.PG; off in real mode / early boot. */
    *mmu_on = (env->cr[0] & CR0_PG_MASK) != 0;
}

static bool x86_vaddr_is_kernel(CPUState *cs, uint64_t vaddr)
{
    CPUX86State *env = cpu_env(cs);
    /*
     * Long mode: the linear address space is split into a low (user) and a
     * high (kernel) canonical half with a non-canonical hole between them.
     * The split sits at the sign bit of the paging width -- 48-bit (LA48) or
     * 57-bit (LA57, CR4.LA57) -- so the kernel half is exactly the addresses
     * whose bits above that sign bit are all ones.  Deriving the boundary
     * from the live paging width (rather than a fixed constant) keeps the
     * classification correct under LA57.  Outside long mode there is no such
     * canonical kernel half (32-bit paging splits user/kernel by an
     * OS-chosen boundary the hardware does not define), so report user.
     */
    if (!(env->hflags & HF_LMA_MASK)) {
        return false;
    }
    return vaddr_in_upper_half(vaddr, (env->cr[4] & CR4_LA57_MASK) ? 57 : 48);
}

static uint64_t x86_get_plugin_thread_ptr(CPUState *cs)
{
    CPUX86State *env = cpu_env(cs);
    /*
     * The user TLS base the kernel context-switches per thread: FS.base
     * for a 64-bit task, GS.base for a 32-bit (compat/legacy) one -- the
     * i386 TLS ABI points GS at a set_thread_area GDT descriptor, whose
     * base the segment cache carries.  Selected by the current CS.L.
     * The register alone: a task with no TLS base reads 0 here at every
     * CPL, and no kernel data structure is consulted to name it.
     */
    if (env->hflags & HF_CS64_MASK) {
        return env->segs[R_FS].base;
    }
    return env->segs[R_GS].base;
}

static bool x86_plugin_thread_ptr_tracks_current(CPUState *cs)
{
    /*
     * FS.base (GS.base for a compat task) is user TLS state; the kernel's
     * own per-CPU base lives in the swapped GS, so the user register is
     * reloaded from the incoming task at every switch and untouched in
     * between, at any CPL.  A value of 0 names no thread; telling such
     * tasks apart is the consumer's business, not this register's.
     */
    return true;
}

/*
 * TCGCPUOps::plugin_clock_resync for x86 -- see the contract in
 * include/accel/tcg/cpu-ops.h.
 *
 * x86's audit of guest-observable time sources:
 *
 *   TSC (and TSC_AUX/rdtscp)   cpu_get_ticks(), via cpus_get_elapsed_ticks().
 *   LAPIC timer, TSC-deadline  QEMUTimers armed off QEMU_CLOCK_VIRTUAL
 *   HPET, PIT (i8254), RTC     (hw/intc/apic.c, hw/timer/).
 *
 * Everything in the second group is armed directly from QEMU_CLOCK_VIRTUAL,
 * which the freeze stops and the thaw resumes at the same value: a deadline
 * expressed in frozen-clock ns is still the same deadline afterwards, so
 * those timers need no re-arm.  None of them lives in CPUX86State either, so
 * the wrong-path register restore cannot roll one back -- x86 has no
 * architectural compare register shadowing a host timer the way Arm's
 * CNTV_CVAL, RISC-V's stimecmp and MIPS's CP0_Compare do.  (A speculative MSR
 * write to IA32_TSC_DEADLINE reaches apic_handle_tsc_deadline, but wrong-path
 * device access is sandboxed, so it never reaches the APIC model.)
 *
 * The TSC is made to follow the same clock.  This hook measures the host's
 * own cycles-per-CLOCK_MONOTONIC-second ratio over the first ~0.2 s of
 * emulation (both host clocks sampled over the same real intervals, so
 * freezes inside them do not bias it) and hands it to
 * cpu_plugin_tsc_lock_to_vclock(), which makes cpu_get_ticks() an affine
 * function of QEMU_CLOCK_VIRTUAL from that instant on.  The TSC and the
 * virtual clock are then one oscillator, so freezing one freezes both.
 * Arming is continuous (anchored at the current value) and one-shot, so the
 * guest sees neither a step nor a rate change.
 *
 * BQL-serialised: both callers of this hook hold it, which is what protects
 * the calibration accumulators below and the one-shot arming.
 */
static int64_t g_tsc_cal_last_ht, g_tsc_cal_last_hm; /* previous host sample */
static int64_t g_tsc_cal_tsc, g_tsc_cal_ns;          /* calibration sums */
static bool    g_tsc_cal_locked; /* lock armed; nothing left */

static void x86_plugin_clock_resync(CPUState *cs,
                                    CPUPluginClockResyncReason reason)
{
    int64_t ht, hm;

    if (g_tsc_cal_locked) {
        return;
    }

    ht = cpu_get_host_ticks();
    hm = get_clock();

    if (g_tsc_cal_last_hm) {
        g_tsc_cal_tsc += ht - g_tsc_cal_last_ht;
        g_tsc_cal_ns  += hm - g_tsc_cal_last_hm;
    }
    if (g_tsc_cal_ns >= 200 * 1000 * 1000) {
        cpu_plugin_tsc_lock_to_vclock((double)g_tsc_cal_tsc /
                                      (double)g_tsc_cal_ns * 1e9);
        g_tsc_cal_locked = true;
    }
    g_tsc_cal_last_ht = ht;
    g_tsc_cal_last_hm = hm;
}
#endif

#ifdef CONFIG_PLUGIN
/* The register behind a CPUX86State field (TCGCPUOps.plugin_reg_resolve) */
static int x86_plugin_reg_resolve(CPUState *cs, intptr_t off, unsigned size,
                                  PluginRegDesc *d)
{
    static const char *const gpr[] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };
    static const char *const seg[] = { "es", "cs", "ss", "ds", "fs", "gs" };
    int i;

#define IN(f) PLUGIN_REG_IN(CPUX86State, f, off)
#define ELT(f) PLUGIN_REG_ELT(CPUX86State, f, off)
    if (IN(regs)) {
        i = ELT(regs);
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_GPR, i, 8, "%s", gpr[i]);
    }
    /* the lazy condition codes and the direction flag are EFLAGS */
    if (IN(cc_dst) || IN(cc_src) || IN(cc_src2) || IN(df) || IN(eflags)) {
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_FLAGS, 0, 4, "eflags");
    }
    if (IN(segs)) {     /* named for gdb: the fs/gs bases, else selectors */
        i = ELT(segs);
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_SEGMENT, i, 8, "%s%s",
                               seg[i], i >= R_FS ? "_base" : "");
    }
    if (IN(xmm_regs)) {
        i = ELT(xmm_regs);
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_VECTOR, i, 64, "xmm%d", i);
    }
    if (IN(fpregs)) {       /* by CPU-state offset only as MMX, where TOP=0 */
        i = ELT(fpregs);
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_FP, i, 10, "st%d", i);
    }
    if (IN(opmask_regs)) {
        i = ELT(opmask_regs);
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_PREDICATE, i, 8, "k%d", i);
    }
    if (IN(fpuc)) {
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 0, 4, "fctrl");
    }
    if (IN(fpus) || IN(fpstt)) {
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 1, 4, "fstat");
    }
    if (IN(fptags)) {
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 2, 4, "ftag");
    }
    if (IN(mxcsr)) {
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 3, 4, "mxcsr");
    }
    if (IN(cr)) {
        i = ELT(cr);
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 4 + i, 8, "cr%d", i);
    }
    if (IN(bnd_regs)) {
        i = ELT(bnd_regs);
        return plugin_reg_desc(d, QEMU_PLUGIN_REG_CONTROL, 16 + i, 16, "bnd%d",
                               i);
    }
    /* the pc, the cc_op descriptor, translation flags, scratch, FIP/FDP */
    if (off < 0 || IN(eip) || IN(cc_op) || IN(hflags) || IN(hflags2) ||
        IN(xmm_t0) || IN(mmx_t0) || IN(ft0) || IN(fp_status) ||
        IN(mmx_status) || IN(sse_status) || IN(fpop) || IN(fpcs) ||
        IN(fpds) || IN(fpip) || IN(fpdp)) {
        return PLUGIN_REG_DROP;
    }
#undef IN
#undef ELT
    return PLUGIN_REG_UNKNOWN;
}
#endif

static const TCGCPUOps x86_tcg_ops = {
    .initialize = tcg_x86_init,
    .translate_code = x86_translate_code,
    .synchronize_from_tb = x86_cpu_synchronize_from_tb,
    .restore_state_to_opc = x86_restore_state_to_opc,
    .cpu_exec_enter = x86_cpu_exec_enter,
    .cpu_exec_exit = x86_cpu_exec_exit,
#ifdef CONFIG_PLUGIN
    .plugin_reg_resolve = x86_plugin_reg_resolve,
#endif
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
    .get_plugin_state = x86_get_plugin_state,
    .get_plugin_thread_ptr = x86_get_plugin_thread_ptr,
    .plugin_thread_ptr_tracks_current = x86_plugin_thread_ptr_tracks_current,
    .vaddr_is_kernel = x86_vaddr_is_kernel,
    .plugin_clock_resync = x86_plugin_clock_resync,
#endif
#ifdef CONFIG_USER_ONLY
    .fake_user_interrupt = x86_cpu_do_interrupt,
    .record_sigsegv = x86_cpu_record_sigsegv,
    .record_sigbus = x86_cpu_record_sigbus,
#else
    .tlb_fill = x86_cpu_tlb_fill,
    .do_interrupt = x86_cpu_do_interrupt,
    .cpu_exec_halt = x86_cpu_exec_halt,
    .cpu_exec_interrupt = x86_cpu_exec_interrupt,
    .do_unaligned_access = x86_cpu_do_unaligned_access,
    .debug_excp_handler = breakpoint_handler,
    .debug_check_breakpoint = x86_debug_check_breakpoint,
    .need_replay_interrupt = x86_need_replay_interrupt,
#endif /* !CONFIG_USER_ONLY */
};

static void x86_tcg_cpu_init_ops(AccelCPUClass *accel_cpu, CPUClass *cc)
{
    /* for x86, all cpus use the same set of operations */
    cc->tcg_ops = &x86_tcg_ops;
}

static void x86_tcg_cpu_class_init(CPUClass *cc)
{
    cc->init_accel_cpu = x86_tcg_cpu_init_ops;
}

static void x86_tcg_cpu_xsave_init(void)
{
#define XO(bit, field) \
    x86_ext_save_areas[bit].offset = offsetof(X86XSaveArea, field);

    XO(XSTATE_FP_BIT, legacy);
    XO(XSTATE_SSE_BIT, legacy);
    XO(XSTATE_YMM_BIT, avx_state);
    XO(XSTATE_BNDREGS_BIT, bndreg_state);
    XO(XSTATE_BNDCSR_BIT, bndcsr_state);
    XO(XSTATE_OPMASK_BIT, opmask_state);
    XO(XSTATE_ZMM_Hi256_BIT, zmm_hi256_state);
    XO(XSTATE_Hi16_ZMM_BIT, hi16_zmm_state);
    XO(XSTATE_PKRU_BIT, pkru_state);

#undef XO
}

/*
 * TCG-specific defaults that override cpudef models when using TCG.
 * Only for builtin_x86_defs models initialized with x86_register_cpudef_types.
 */
static PropValue x86_tcg_default_props[] = {
    { "vme", "off" },
    { NULL, NULL },
};

static void x86_tcg_cpu_instance_init(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    X86CPUClass *xcc = X86_CPU_GET_CLASS(cpu);

    if (xcc->model) {
        /* Special cases not set in the X86CPUDefinition structs: */
        x86_cpu_apply_props(cpu, x86_tcg_default_props);
    }

    x86_tcg_cpu_xsave_init();
}

static void x86_tcg_cpu_accel_class_init(ObjectClass *oc, void *data)
{
    AccelCPUClass *acc = ACCEL_CPU_CLASS(oc);

#ifndef CONFIG_USER_ONLY
    acc->cpu_target_realize = tcg_cpu_realizefn;
#endif /* CONFIG_USER_ONLY */

    acc->cpu_class_init = x86_tcg_cpu_class_init;
    acc->cpu_instance_init = x86_tcg_cpu_instance_init;
}
static const TypeInfo x86_tcg_cpu_accel_type_info = {
    .name = ACCEL_CPU_NAME("tcg"),

    .parent = TYPE_ACCEL_CPU,
    .class_init = x86_tcg_cpu_accel_class_init,
    .abstract = true,
};
static void x86_tcg_cpu_accel_register_types(void)
{
    type_register_static(&x86_tcg_cpu_accel_type_info);
}
type_init(x86_tcg_cpu_accel_register_types);
