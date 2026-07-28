/* Oracle phase-1: where vector state lands (Phase 2 scoping). */
        .text
        .globl _start
_start:
        li      a0, 4
        vsetvli t0, a0, e64, m1, ta, ma
        vmv.v.i v2, 7
        vmv.v.i v3, 5
        vmv.v.i v1, -1
        .globl oracle_begin
oracle_begin:
        vadd.vv v1, v2, v3        /* 7+5 = 12 into v1[0..3] */
        vmul.vv v4, v2, v3        /* 7*5 = 35 into v4[0..3] */
        .globl oracle_end
oracle_end:
        nop
        li      a0, 0
        li      a7, 93
        ecall
