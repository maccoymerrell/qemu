/*
 * RISC-V port of wptrace_wrongpath_divsd_tagged.
 * Never-taken branch hides FP divide + ebreak.
 * Exercises: fdiv.d (FP_DIV), fld, branches, ecall.
 */
    .section .rodata
    .align 3
one_d:  .double 1.0
zero_d: .double 0.0

    .text
    .global _start
_start:
    li      s0, 500000          /* loop counter */
    li      s1, 1               /* always-true predicate */

.Lloop:
    bnez    s1, .Lsafe          /* always taken */

.Ltrap:
    la      t0, one_d
    fld     fa0, 0(t0)
    la      t0, zero_d
    fld     fa1, 0(t0)
    fdiv.d  fa2, fa0, fa1       /* FP divide by zero */
    ebreak                      /* trap on wrong path */

.Lsafe:
    addi    s0, s0, -1
    bnez    s0, .Lloop

    li      a0, 0
    li      a7, 93
    ecall
