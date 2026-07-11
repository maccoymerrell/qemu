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
     */
    if (env->hflags & HF_CS64_MASK) {
        return env->segs[R_FS].base;
    }
    return env->segs[R_GS].base;
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
