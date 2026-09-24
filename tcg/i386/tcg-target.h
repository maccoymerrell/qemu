/*
 * Tiny Code Generator for QEMU
 *
 * Copyright (c) 2008 Fabrice Bellard
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

#ifndef I386_TCG_TARGET_H
#define I386_TCG_TARGET_H

#define TCG_TARGET_INSN_UNIT_SIZE  1

/*
 * The i386/x86_64 backend honours CF_FORCE_SLOW: on a spec-mode TB it emits an
 * unconditional jump to the slow path for inline qemu_ld/qemu_st, keeping
 * speculative stores out of real guest RAM (see the CF_FORCE_SLOW handling in
 * tcg-target.c.inc).  This is the native wrong-path containment path and is
 * used in both user and system mode.  Other backends do not implement it and
 * rely on the portable per-TLB-entry TLB_FORCE_SLOW routing in system mode
 * (accel/tcg); user-mode wrong-path tracing still requires this capability.
 * Forcing this to 0 on an x86 host builds the portable path in its place,
 * which is how that path is functionally validated on this host.
 */
#define TCG_TARGET_HAS_SPEC_FORCE_SLOW 1

#ifdef __x86_64__
# define TCG_TARGET_NB_REGS   32
# define MAX_CODE_GEN_BUFFER_SIZE  (2 * GiB)
#else
# define TCG_TARGET_NB_REGS   24
# define MAX_CODE_GEN_BUFFER_SIZE  UINT32_MAX
#endif

typedef enum {
    TCG_REG_EAX = 0,
    TCG_REG_ECX,
    TCG_REG_EDX,
    TCG_REG_EBX,
    TCG_REG_ESP,
    TCG_REG_EBP,
    TCG_REG_ESI,
    TCG_REG_EDI,

    /* 64-bit registers; always define the symbols to avoid
       too much if-deffing.  */
    TCG_REG_R8,
    TCG_REG_R9,
    TCG_REG_R10,
    TCG_REG_R11,
    TCG_REG_R12,
    TCG_REG_R13,
    TCG_REG_R14,
    TCG_REG_R15,

    TCG_REG_XMM0,
    TCG_REG_XMM1,
    TCG_REG_XMM2,
    TCG_REG_XMM3,
    TCG_REG_XMM4,
    TCG_REG_XMM5,
    TCG_REG_XMM6,
    TCG_REG_XMM7,

    /* 64-bit registers; likewise always define.  */
    TCG_REG_XMM8,
    TCG_REG_XMM9,
    TCG_REG_XMM10,
    TCG_REG_XMM11,
    TCG_REG_XMM12,
    TCG_REG_XMM13,
    TCG_REG_XMM14,
    TCG_REG_XMM15,

    TCG_REG_RAX = TCG_REG_EAX,
    TCG_REG_RCX = TCG_REG_ECX,
    TCG_REG_RDX = TCG_REG_EDX,
    TCG_REG_RBX = TCG_REG_EBX,
    TCG_REG_RSP = TCG_REG_ESP,
    TCG_REG_RBP = TCG_REG_EBP,
    TCG_REG_RSI = TCG_REG_ESI,
    TCG_REG_RDI = TCG_REG_EDI,

    TCG_AREG0 = TCG_REG_EBP,
    TCG_REG_CALL_STACK = TCG_REG_ESP
} TCGReg;

#endif
