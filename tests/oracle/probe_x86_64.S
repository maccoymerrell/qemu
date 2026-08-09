/*
 * x86-64 probe for the behavioural oracle.
 *
 * The run between oracle_begin and oracle_end is chosen so that the register
 * reads and writes of every instruction in it are not in doubt, and so that
 * the places where a static decoder and QEMU's own translation can disagree
 * are all represented: the lazily computed flags, a conditional move whose
 * write is inert, a vector register QEMU reaches by pointer rather than by
 * TCG global, and an instruction whose whole behaviour lives in a helper.
 *
 * Copyright (c) 2026 Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

        .text
        .globl _start
_start:
        /* Somewhere to push to and load from. */
        leaq    scratch(%rip), %r15
        movq    $0x1122334455667788, %rax
        movq    $0x0000000000000003, %rbx
        movq    $0, %rcx
        movq    $7, %rdx
        movq    $0, %rsi
        movq    $0, %rdi
        movq    $0, %r8
        movq    $5, %r10
        movq    %rax, (%r15)

        .globl oracle_begin
oracle_begin:
        nop                             /* nothing at all */
        movq    %rax, %r9               /* w r9; no flags */
        addq    %rax, %rbx              /* r rax,rbx; w rbx + eflags */
        subq    %rcx, %rcx              /* w rcx + eflags; rcx was 0 */
        cmpq    %rax, %rbx              /* r rax,rbx; w eflags only */
        adcq    %rax, %rdx              /* r eflags(CF) as well */
        leaq    8(%rax,%rbx,2), %r11    /* r rax,rbx; w r11; NO flags */
        cmovzq  %rax, %rsi              /* inert: ZF is clear here */
        cmovnzq %rax, %rdi              /* the same write, taken */
        xorq    %r8, %r8                /* zeroing idiom */
        imulq   %rbx, %r10              /* w r10 + eflags */
        shlq    $1, %rax                /* w rax + eflags */
        setz    %r12b                   /* r eflags; w r12 (byte) */
        bswapq  %rbx                    /* w rbx; no flags */
        movzbl  %al, %ecx               /* w rcx; no flags */
        xchgq   %rax, %rbx              /* r/w both */
        pushq   %rax                    /* r rax,rsp; w rsp; memory */
        popq    %r13                    /* r rsp; w r13,rsp; memory */
        movq    (%r15), %r14            /* r r15; w r14; memory */
        movq    %r14, 8(%r15)           /* the same operand shape, storing */
        addq    (%r15), %r14            /* memory source, register dest */
        addq    %r14, 16(%r15)          /* read-modify-write in memory */
        movb    $3, 24(%r15)            /* store only, immediate source */
        cmpq    (%r15), %r14            /* memory read, no register dest */
        movq    %rax, %xmm0             /* w xmm0 -- no TCG global names it */
        movq    %rbx, %xmm1
        paddq   %xmm0, %xmm1            /* vector, reached by pointer */
        pxor    %xmm2, %xmm2
        bsfq    %rbx, %rbp              /* w rbp + eflags */
        cqto                            /* r rax; w rdx */
        movq    $9, %rax
        xorq    %rdx, %rdx
        movq    $2, %rcx
        divq    %rcx                    /* r rax,rdx,rcx; w rax,rdx */
        .globl oracle_end
oracle_end:

        movq    $60, %rax
        xorq    %rdi, %rdi
        syscall
        hlt

        .data
        .align 16
scratch:
        .quad   0, 0
        .space  64
