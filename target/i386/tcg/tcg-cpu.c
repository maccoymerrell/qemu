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
    /* CPL: 0 = kernel … 3 = user.  Normalize so 0 = user (least
     * privileged), larger = more privileged. */
    int cpl = (env->hflags & HF_CPL_MASK) >> HF_CPL_SHIFT;
    *priv = 3 - cpl;
    /*
     * CR3 = current page-table base / address-space id, masking bit 63
     * (PCID NOFLUSH).  Architecturally bit 63 is a command bit on the
     * MOV-to-CR3 write — "skip the TLB flush" — not state: MOV from CR3
     * always reads it as 0, so it can never distinguish address spaces
     * and masking it is unconditionally safe.  It is also unreachable
     * under current TCG — system emulation never advertises PCID
     * (TCG_EXT_FEATURES), a Linux guest therefore never sets
     * CR4.PCIDE/NOFLUSH (audited empirically: -cpu Haswell boot, 20k+
     * committed CR3 writes, all 4 KiB-aligned, bit 63 clear), and
     * helper_write_crN faults long-mode CR3 writes with bits above
     * phys_bits as reserved anyway — so the mask only guards the
     * verbatim CR3 image loads (VMRUN, SMM RSM) and any future TCG PCID
     * support.  PCID bits [11:0] are deliberately NOT masked: with
     * CR4.PCIDE they are a genuine component of the address-space
     * identity (Linux PTI tags the user-half CR3 with PCID bit 11), and
     * no PCID-capable TCG configuration exists to justify collapsing
     * them.  Producers of ASID-change notifications must compare under
     * this same mask (see cpu_x86_update_cr3).
     */
    *asid = env->cr[3] & ~CR3_NOFLUSH_MASK;
    /* Paging active iff CR0.PG; off in real mode / early boot. */
    *mmu_on = (env->cr[0] & CR0_PG_MASK) != 0;
}

static bool x86_vaddr_is_kernel(CPUState *cs, uint64_t vaddr);

/*
 * Resolve the guest kernel's `current` at CPL0 through the per-CPU
 * area, for a task with no TLS identity (FS.base == 0).  Engaged only
 * when a plugin has declared the per-image current_task per-CPU offset
 * (qemu_plugin_set_current_task_offset); undeclared, the legacy
 * register-only contract is untouched byte-for-byte.
 *
 * The contract, as the kernel source states it (Linux 6.6/6.12,
 * arch/x86/entry/entry_64.S paranoid_entry): "the kernel enforces that
 * negative GSBASE values indicate kernel GSBASE" — in-kernel, GS.base
 * is the per-CPU base (a kernel VA), swapped in by SWAPGS at every
 * entry from user; the user GS base is 0 or a user VA
 * (do_arch_prctl_64 refuses ARCH_SET_GS >= TASK_SIZE_MAX, and the
 * 32-bit GDT TLS descriptors cannot reach the kernel half).  `current`
 * is the per-CPU variable current_task (pcpu_hot + 0 on
 * 6.2 <= v < 6.14), so at CPL0 with kernel GS the task is one load:
 * *(GS.base + offset).
 *
 * The states this helper refuses, each resolving to "cannot vouch"
 * (tracks_current false -> the consumer inherits the entering thread,
 * which in every refused window IS the current task):
 *
 *  - SWAPGS windows: entry_SYSCALL_64 before its first-instruction
 *    swapgs; the idtentry push sequence up to error_entry's swapgs;
 *    paranoid_entry (NMI/#DB/#MC/#DF) delivered before an entry path's
 *    swapgs ran, until SAVE_AND_SET_GSBASE / the conditional swapgs;
 *    the exit twins (paranoid_exit's wrgsbase/swapgs .. iret,
 *    swapgs_restore_regs_and_return_to_usermode's tail); and
 *    asm_load_gs_index's deliberate user-GS bracket.  GS.base holds a
 *    user value there, fails the kernel-VA test, and no context switch
 *    can occur inside such a window — inheritance is exact, the same
 *    treatment the AArch64/MIPS early-entry windows get.
 *  - A failed or unmapped load (a PTI user page table in the entry
 *    window — canonical runs are nopti — or pre-paging early boot).
 *  - A loaded value that is not a kernel VA (per-CPU area not yet
 *    initialised at early boot).
 *
 * Known residual, named not hidden: TCG advertises FSGSBASE, and "with
 * FSGSBASE no assumptions can be made about the GSBASE value when
 * entering from user space" (paranoid_entry comment) — a guest thread
 * that deliberately WRGSBASEs a kernel-half VA forges the kernel-GS
 * signature for its own entry windows.  The value gate above bounds it
 * (the forged base must ALSO hold a kernel-VA-shaped word at the
 * offset); the class is the same accepted one as an AArch64 user
 * setting SP to a kernel-shaped value before trapping.
 */
static bool x86_kernel_current_task(CPUState *cs, uint64_t *task)
{
    CPUX86State *env = cpu_env(cs);
    bool declared;
    uint64_t off = qemu_plugin_current_task_offset(&declared);
    if (!declared) {
        return false;
    }
    uint64_t gsbase = env->segs[R_GS].base;
    if (!x86_vaddr_is_kernel(cs, gsbase)) {
        return false;                        /* swapgs window / early boot */
    }
    uint8_t buf[8];
    if (cpu_memory_rw_debug(cs, gsbase + off, buf, sizeof(buf), false) < 0) {
        return false;
    }
    uint64_t t = ldq_le_p(buf);
    if (!x86_vaddr_is_kernel(cs, t)) {
        return false;
    }
    *task = t;
    return true;
}

static uint64_t x86_get_plugin_thread_ptr(CPUState *cs)
{
    CPUX86State *env = cpu_env(cs);
    /*
     * The user TLS base the kernel context-switches per thread: FS.base
     * for a 64-bit task, GS.base for a 32-bit (compat/legacy) one — the
     * i386 TLS ABI points GS at a set_thread_area GDT descriptor, whose
     * base the segment cache carries.  Selected by the current CS.L, so
     * sample at user privilege (in-kernel the bases are mid-switch and
     * GS is swapped onto the kernel's per-CPU base).
     *
     * FS.base == 0 at CPL0 is a task with no TLS identity — a kernel
     * thread, a per-CPU idle task, or a TLS-less user task's kernel
     * excursion: distinct program paths that would otherwise all
     * collapse onto the one identity 0.  Fall through to the kernel's
     * own per-task contract — `current` through the kernel GS base at
     * the plugin-declared per-image offset (x86_kernel_current_task) —
     * exactly as AArch64 falls back to SP_EL0-as-current and MIPS to
     * $28-as-current_thread_info.  The kernel CS is long-mode, so CPL0
     * always takes the CS64 arm; a compat task's kernel excursion
     * resolves its task pointer here and the plugin's kernel-entry
     * alias joins it to the thread's user (GS.base) identity.
     */
    if (env->hflags & HF_CS64_MASK) {
        uint64_t tp = env->segs[R_FS].base;
        if (tp == 0 && (env->hflags & HF_CPL_MASK) == 0) {
            uint64_t task;
            if (x86_kernel_current_task(cs, &task)) {
                return task;
            }
        }
        return tp;
    }
    return env->segs[R_GS].base;
}

/*
 * Raw architectural identity keys (see TCGCPUOps::get_plugin_identity).
 *
 * Address space: CR3.  Bit 63 is the PCID NOFLUSH command bit, which is
 * architecturally not stored (MOV from CR3 reads it 0), so it can never
 * distinguish address spaces.  Bits [11:0] are the PCID and are a genuine
 * part of the name ONLY when CR4.PCIDE is set; with paging tagging
 * disabled the processor ignores them, so a guest toggling CR3.PWT/PCD
 * must not read as an address-space change.
 *
 * Thread: FS.base, the per-thread TLS base the kernel switches per thread
 * and which SWAPGS does not touch, so it names the same thread at CPL0 as
 * at CPL3.  A non-long-mode (compat/legacy) task's TLS base is in GS.base
 * instead; CS.L selects, exactly as the segment cache reports it.  No
 * guest memory is read and no value is tested for shape.
 */
static void x86_get_plugin_identity(CPUState *cs, uint64_t *space_key,
                                    uint64_t *thread_key)
{
    CPUX86State *env = cpu_env(cs);
    uint64_t cr3 = env->cr[3] & ~CR3_NOFLUSH_MASK;

    if (!(env->cr[4] & CR4_PCIDE_MASK)) {
        cr3 &= ~0xfffULL;
    }
    *space_key = cr3;
    *thread_key = (env->hflags & HF_CS64_MASK) ? env->segs[R_FS].base
                                               : env->segs[R_GS].base;
}

static bool x86_plugin_thread_ptr_tracks_current(CPUState *cs)
{
    CPUX86State *env = cpu_env(cs);
    /* FS.base (GS.base for a compat task) is user TLS state; the kernel's
     * own per-CPU base lives in the swapped GS, so the user register is
     * reloaded from the incoming task at every switch and untouched in
     * between, at any CPL.  A non-zero read therefore names the current
     * task wherever it is taken.
     *
     * The one state that cannot vouch for itself is CPL0 with
     * FS.base == 0: the register names nothing there, and whether the
     * per-CPU fallback can answer instead is a property of THIS sample
     * (kernel GS in, mapping readable, value task-shaped — see
     * x86_kernel_current_task).  Mirror the get-hook exactly: true iff
     * the value the get-hook would return actually names the task.
     * With no declared offset this reports true and the get-hook
     * returns 0 — the pre-hint contract, byte-for-byte, in which every
     * TLS-less task shares the one identity 0 (honest indistinctness
     * for lack of a per-image offset, not a fabricated identity). */
    if ((env->hflags & HF_CS64_MASK) &&
        (env->hflags & HF_CPL_MASK) == 0 &&
        env->segs[R_FS].base == 0) {
        bool declared;
        uint64_t task;
        qemu_plugin_current_task_offset(&declared);
        if (declared) {
            return x86_kernel_current_task(cs, &task);
        }
    }
    return true;
}

static bool x86_vaddr_is_kernel(CPUState *cs, uint64_t vaddr)
{
    CPUX86State *env = cpu_env(cs);
    /*
     * Long mode: the linear address space is split into a low (user) and a
     * high (kernel) canonical half with a non-canonical hole between them.
     * The split sits at the sign bit of the paging width — 48-bit (LA48) or
     * 57-bit (LA57, CR4.LA57) — so the kernel half is exactly the addresses
     * whose bits above that sign bit are all ones.  Deriving the boundary
     * from the live paging width (rather than a fixed constant) keeps the
     * classification correct under LA57.  Outside long mode there is no such
     * canonical kernel half (32-bit paging splits user/kernel by an
     * OS-chosen boundary the hardware does not define), so report user.
     */
    if (!(env->hflags & HF_LMA_MASK)) {
        return false;
    }
    unsigned va_bits = (env->cr[4] & CR4_LA57_MASK) ? 57 : 48;
    return vaddr >= (~(uint64_t)0 << (va_bits - 1));
}

/*
 * TCGCPUOps::spec_clock_resync for x86 — see the contract in
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
 * the wrong-path register restore cannot roll one back — x86 has no
 * architectural compare register shadowing a host timer the way Arm's
 * CNTV_CVAL, RISC-V's stimecmp and MIPS's CP0_Compare do.  (A speculative MSR
 * write to IA32_TSC_DEADLINE reaches apic_handle_tsc_deadline, but wrong-path
 * device access is sandboxed, so it never reaches the APIC model.)
 *
 * The TSC was the exception, because cpu_get_ticks() accumulated the host
 * cycle counter while everything else accumulated host CLOCK_MONOTONIC: two
 * host oscillators, sampled at four different instants by each freeze/thaw
 * pair, drifting apart by a fixed displacement per pair that a one-directional
 * correction could only rectify and never remove — until the guest's
 * clocksource watchdog marked the TSC unstable and wedged timekeeping and RCU.
 *
 * It is no longer an exception.  The hook's whole remaining job is to measure
 * the host's own cycles-per-CLOCK_MONOTONIC-second ratio and hand it to
 * cpu_plugin_tsc_lock_to_vclock(), which makes cpu_get_ticks() an affine
 * function of QEMU_CLOCK_VIRTUAL from that instant on.  The two guest
 * clocksources are then the same oscillator, freezing one freezes both, and
 * the resync obligation is discharged structurally rather than at every thaw.
 *
 * The ratio is self-calibrated over the first ~0.2 s of emulation, both host
 * clocks sampled over the same real intervals so freezes inside them do not
 * bias it.  Arming is continuous (the line is anchored at the pair's current
 * value) and one-shot, so the guest sees neither a step nor a rate change,
 * and the displacement accumulated before arming is frozen in as a constant
 * instead of continuing to grow.  Reading the two host clocks here rather
 * than at one instant no longer matters: the difference lands in the ratio's
 * last few parts per billion, not in a term that ratchets.
 *
 * BQL-serialised: both callers of this hook hold it, which is what protects
 * the calibration accumulators below and the one-shot arming.
 */
static int64_t g_pin_last_ht, g_pin_last_hm;  /* previous host sample */
static int64_t g_pin_cal_tsc, g_pin_cal_ns;   /* calibration sums */
static bool    g_pin_locked;                  /* lock armed; nothing left */

static void x86_spec_clock_resync(CPUState *cs, SpecClockResyncReason reason)
{
    int64_t ht, hm;

    if (g_pin_locked) {
        return;
    }

    ht = cpu_get_host_ticks();
    hm = get_clock();

    if (g_pin_last_hm) {
        g_pin_cal_tsc += ht - g_pin_last_ht;
        g_pin_cal_ns  += hm - g_pin_last_hm;
    }
    if (g_pin_cal_ns >= 200 * 1000 * 1000) {
        cpu_plugin_tsc_lock_to_vclock((double)g_pin_cal_tsc /
                                      (double)g_pin_cal_ns * 1e9);
        g_pin_locked = true;
    }
    g_pin_last_ht = ht;
    g_pin_last_hm = hm;
}
#endif

static const TCGCPUOps x86_tcg_ops = {
    .initialize = tcg_x86_init,
    .translate_code = x86_translate_code,
    .synchronize_from_tb = x86_cpu_synchronize_from_tb,
    .restore_state_to_opc = x86_restore_state_to_opc,
    .cpu_exec_enter = x86_cpu_exec_enter,
    .cpu_exec_exit = x86_cpu_exec_exit,
#if defined(CONFIG_PLUGIN) && !defined(CONFIG_USER_ONLY)
    .get_plugin_state = x86_get_plugin_state,
    .get_plugin_thread_ptr = x86_get_plugin_thread_ptr,
    .get_plugin_identity = x86_get_plugin_identity,
    /* A 64-bit kernel keeps its own per-CPU base in GS (swapgs on entry)
     * and reloads FS.base from the incoming task in __switch_to(), so the
     * FS.base this hook reads above user privilege names the current
     * task. */
    .plugin_thread_ptr_tracks_current = x86_plugin_thread_ptr_tracks_current,
    .vaddr_is_kernel = x86_vaddr_is_kernel,
    .spec_clock_resync = x86_spec_clock_resync,
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
