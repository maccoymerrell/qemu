/*
 * Oracle phase-1 demonstration program (RISC-V 64, bare, no libc).
 * Every instruction between oracle_begin and oracle_end has a write set we
 * know for certain from the ISA manual.
 */
        .section .data
        .align 6
scratch:
        .dword 0x0123456789abcdef
        .dword 0x1122334455667788
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

        .globl oracle_begin
oracle_begin:
        nop                       /* addi x0,x0,0  -> writes nothing */
        add     a2, a0, a1        /* -> x12 only */
        sub     a3, a0, a1        /* -> x13 only */
        addi    x0, a0, 5         /* rd=x0        -> writes nothing */
        slli    a4, a0, 3         /* -> x14 only */
        lui     a5, 0x12345       /* -> x15 only */
        ld      a6, 0(s0)         /* -> x16 only */
        sd      a6, 16(s0)        /* -> nothing in env (memory only) */
        mul     a7, a0, a1        /* -> x17 only */
        div     t0, a1, a0        /* -> x5 only */
        jal     ra, 1f            /* -> x1 (ra) and control flow */
1:
        lr.d    t1, (s0)          /* -> x6 + QEMU load_res/load_val */
        sc.d    t2, a6, (s0)      /* -> x7 + load_res */
        amoadd.d t3, a0, (s0)     /* -> x28 + memory */
        fadd.d  fa0, fa1, fa2     /* -> f10 + fp exception/dirty state */
        fmul.d  fa3, fa1, fa2     /* -> f13 + fp exception/dirty state */
        fcvt.w.d t4, fa1          /* -> x29 + fp exception state */
        csrr    t5, 0xc00         /* rdcycle -> x30, via a helper */
        vsetvli t6, x0, e64, m1, ta, ma  /* -> vl/vtype/vstart */
        .globl oracle_end
oracle_end:
        nop

        li      a0, 0
        li      a7, 93            /* __NR_exit */
        ecall
