/*
 * RISC-V port of wptrace_wrongpath_fpdiv_min.
 * Never-taken branch hides double-precision FP divide-by-zero.
 */
    .text
    .global _start
_start:
    li      s0, 200000          /* loop counter */
    li      s1, 1               /* always-true */

.Lloop:
    bnez    s1, .Lsafe          /* always taken */

.Ltrap:
    /* Build 1.0 in fa0 and 0.0 in fa1 */
    li      t0, 0x3ff00000
    slli    t0, t0, 32          /* t0 = 0x3ff0000000000000 = 1.0 */
    fmv.d.x fa0, t0
    fmv.d.x fa1, zero          /* 0.0 */
    fdiv.d  fa2, fa0, fa1       /* 1.0 / 0.0 */
    ebreak

.Lsafe:
    addi    s0, s0, -1
    bnez    s0, .Lloop

    li      a0, 0
    li      a7, 93
    ecall
