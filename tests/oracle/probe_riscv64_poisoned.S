/*
 * Oracle phase-1: poisoned-destination trial.
 *
 * A pure state differ cannot see a write whose value equals what was already
 * there.  Pre-loading each destination with a poison value that the
 * instruction will not produce makes every architectural write observable,
 * and lets us show which writes probe.S missed for that reason.
 */
        .section .data
        .align 6
scratch:
        .dword 0x3ff8000000000000        /* 1.5  */
        .dword 0x4002000000000000        /* 2.25 */
        .dword 0
        .dword 0

        .text
        .globl _start
_start:
        la      s0, scratch
        li      a0, 0x1111
        li      a1, 0x2222
        fld     fa1, 0(s0)
        fld     fa2, 8(s0)
        li      a6, 0x55
        lr.d    x0, (s0)                 /* take a reservation for the sc.d */

        /* poison every destination we are about to test */
        li      t2,  0x5A5A5A5ADEADBEEF
        li      t4,  0x5A5A5A5ADEADBEEF
        li      t0,  0x5A5A5A5ADEADBEEF
        li      s1,  0x5A5A5A5ADEADBEEF
        li      s2,  0x5A5A5A5ADEADBEEF
        fmv.d.x fa3, t2
        fmv.d.x fa4, t2

        .globl oracle_begin
oracle_begin:
        sc.d    t2, a6, (s0)      /* success -> t2 = 0 (invisible unpoisoned) */
        fmul.d  fa3, fa1, fa2     /* 1.5 * 2.25 = 3.375 -> f13 + fp status  */
        fcvt.w.d t4, fa1          /* 1.5 -> 1, sets inexact -> x29 + status */
        slt     s1, a0, a1        /* 0x1111 < 0x2222 -> s1 = 1              */
        sltu    s2, a1, a0        /* false            -> s2 = 0 (poisoned)  */
        addi    x0, a0, 5         /* rd = x0          -> writes nothing     */
        csrrs   t0, 0x003, x0     /* read fcsr only, rs1 = x0 -> no CSR write */
        csrrw   x0, 0x003, a0     /* write fcsr only, rd = x0 -> no reg write */
        vsetvli s3, x0, e64, m1, ta, ma
        vadd.vv v1, v2, v3        /* vector dest is NOT a TCG global        */
        .globl oracle_end
oracle_end:
        nop

        li      a0, 0
        li      a7, 93
        ecall
