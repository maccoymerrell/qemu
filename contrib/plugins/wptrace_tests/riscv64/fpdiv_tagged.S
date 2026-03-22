/*
 * RISC-V port of wptrace_wrongpath_fpdiv_tagged.
 * Never-taken branch hides FP divide + ebreak.
 */
    .text
    .global _start
_start:
    li      s0, 500000
    li      s1, 1               /* always-true */

.Lloop:
    bnez    s1, .Lsafe          /* always taken */

.Ltrap:
    li      t0, 0x3ff00000
    slli    t0, t0, 32
    fmv.d.x fa0, t0
    fmv.d.x fa1, zero
    fdiv.d  fa2, fa0, fa1
    ebreak

.Lsafe:
    addi    s0, s0, -1
    bnez    s0, .Lloop

    li      a0, 0
    li      a7, 93
    ecall
