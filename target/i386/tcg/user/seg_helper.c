/*
 *  x86 segmentation related helpers (user-mode code):
 *  TSS, interrupts, system calls, jumps and call/task gates, descriptors
 *
 *  Copyright (c) 2003 Fabrice Bellard
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
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "tcg/helper-tcg.h"
#include "tcg/seg_helper.h"

void helper_syscall(CPUX86State *env, int next_eip_addend)
{
    CPUState *cs = env_cpu(env);

#if defined(TARGET_X86_64) && defined(CONFIG_LINUX_USER)
    /*
     * SYSCALL's REGISTER EFFECTS, WHICH HAPPEN IN THE INSTRUCTION AND NOT IN
     * THE KERNEL.
     *
     * Intel SDM vol.2 and AMD APM vol.3 both define SYSCALL as writing two
     * general-purpose registers before it transfers control:
     *
     *     RCX    <- RIP of the instruction following SYSCALL
     *     R11    <- RFLAGS, with RF cleared
     *     RFLAGS <- RFLAGS AND NOT(IA32_FMASK)
     *
     * The first two are architecture, not kernel policy: they happen on the
     * user side of the boundary, and a user-mode ABI is built on top of them
     * (Linux's SYSRET return path reloads RFLAGS from R11, which is why a
     * process observes its flags PRESERVED across a syscall but its RCX and
     * R11 DESTROYED).  Every x86_64 psABI accordingly lists both registers as
     * call-clobbered by a syscall.
     *
     * This helper used to raise EXCP_SYSCALL and write neither, so a guest
     * saw RCX and R11 carry their pre-SYSCALL values across the call.  That is
     * a value no real machine can produce, and it is visible: a dependency
     * chain through RCX or R11 that hardware breaks at the syscall survives
     * it here, and the registers land in a signal frame with stale contents.
     * Measured, natively and under emulation, in the witness that accompanies
     * this change: real hardware answers RCX = next RIP, R11 = the flags word
     * going in; qemu-user answered with the sentinels the program planted.
     *
     * The third effect is deliberately NOT emulated, and the same measurement
     * is why.  IA32_FMASK belongs to a kernel this mode does not have, and the
     * masking it describes is undone by the SYSRET the kernel returns through,
     * so a *-linux-user process must observe RFLAGS UNCHANGED across a
     * syscall -- which is exactly what it observes natively, and exactly what
     * it observes here.  Masking env->eflags by an env->fmask no guest ever
     * wrote would move this AWAY from the hardware answer.
     *
     * SCOPE, and both boundaries are there because a host dispatcher reads
     * the register this write would destroy:
     *
     *   - Long mode only.  Legacy-mode SYSCALL writes ECX alone, but it is
     *     not a Linux entry point on real 32-bit hardware, and this emulator
     *     routes it into cpu_loop()'s int-0x80 arm, which reads ECX as the
     *     syscall's SECOND ARGUMENT.
     *   - *-linux-user only.  bsd-user's amd64 dispatcher
     *     (bsd-user/x86_64/target_arch_cpu.h) passes env->regs[R_ECX] as the
     *     syscall's FOURTH ARGUMENT.  That is its own defect -- FreeBSD's
     *     amd64 ABI puts arg4 in %r10 for precisely the reason this comment
     *     is about -- but it is a defect in a dispatcher this change is not
     *     authorised to touch, and clobbering RCX underneath it would turn a
     *     wrong REGISTER VALUE into wrong SYSCALL BEHAVIOUR.
     *
     * Neither exclusion is a claim that the ISA differs there; both are
     * emulator paths that would break, and both are named so the next reader
     * can widen the scope by fixing the dispatcher rather than by guessing.
     */
    /*
     * WRONG-PATH CARVE-OUT, and it is the one already ruled for this
     * instruction.  A speculative SYSCALL is fetched and executed but never
     * performed: the walker treats the unfollowable kernel edge as a branch
     * side and continues at the architectural fall-through, leaving the
     * skipped instruction's destinations at their previous values as its
     * deterministic placeholder (champsim_tracer_wp.cc states the rule; the
     * system-mode SYSCALL states the identical carve-out in
     * target/i386/tcg/system/seg_helper.c, where the unwind precedes the
     * RCX/R11 stores for exactly this reason).  Writing them here would make
     * a wrong-path SYSCALL differ from a system-mode one for no architectural
     * reason.  The CORRECT path -- the one a trace publishes and a reference
     * measures -- takes the stores.
     */
    if ((env->hflags & HF_LMA_MASK)
#ifdef CONFIG_PLUGIN
        && likely(!cs->plugin_spec_mode)
#endif
        ) {
        env->regs[R_ECX] = env->eip + next_eip_addend;
        env->regs[11] = cpu_compute_eflags(env) & ~RF_MASK;
    }
#endif /* TARGET_X86_64 && CONFIG_LINUX_USER */

    cs->exception_index = EXCP_SYSCALL;
    env->exception_is_int = 0;
    env->exception_next_eip = env->eip + next_eip_addend;
    cpu_loop_exit(cs);
}

/*
 * fake user mode interrupt. is_int is TRUE if coming from the int
 * instruction. next_eip is the env->eip value AFTER the interrupt
 * instruction. It is only relevant if is_int is TRUE or if intno
 * is EXCP_SYSCALL.
 */
static void do_interrupt_user(CPUX86State *env, int intno, int is_int,
                              int error_code, target_ulong next_eip)
{
    if (is_int) {
        SegmentCache *dt;
        target_ulong ptr;
        int dpl, cpl, shift;
        uint32_t e2;

        dt = &env->idt;
        if (env->hflags & HF_LMA_MASK) {
            shift = 4;
        } else {
            shift = 3;
        }
        ptr = dt->base + (intno << shift);
        e2 = cpu_ldl_kernel(env, ptr + 4);

        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        cpl = env->hflags & HF_CPL_MASK;
        /* check privilege if software int */
        if (dpl < cpl) {
            raise_exception_err(env, EXCP0D_GPF, intno * 8 + 2);
        }
    }

    /* Since we emulate only user space, we cannot do more than
       exiting the emulation with the suitable exception and error
       code. So update EIP for INT 0x80 and EXCP_SYSCALL. */
    if (is_int || intno == EXCP_SYSCALL) {
        env->eip = next_eip;
    }
}

void x86_cpu_do_interrupt(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    /* if user mode only, we simulate a fake exception
       which will be handled outside the cpu execution
       loop */
    do_interrupt_user(env, cs->exception_index,
                      env->exception_is_int,
                      env->error_code,
                      env->exception_next_eip);
    /* successfully delivered */
    env->old_exception = -1;
}

void cpu_x86_load_seg(CPUX86State *env, X86Seg seg_reg, int selector)
{
    if (!(env->cr[0] & CR0_PE_MASK) || (env->eflags & VM_MASK)) {
        int dpl = (env->eflags & VM_MASK) ? 3 : 0;
        selector &= 0xffff;
        cpu_x86_load_seg_cache(env, seg_reg, selector,
                               (selector << 4), 0xffff,
                               DESC_P_MASK | DESC_S_MASK | DESC_W_MASK |
                               DESC_A_MASK | (dpl << DESC_DPL_SHIFT));
    } else {
        helper_load_seg(env, seg_reg, selector);
    }
}
