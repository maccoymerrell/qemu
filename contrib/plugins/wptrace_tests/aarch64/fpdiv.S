/*
 * AArch64 port of wptrace_wrongpath_fpdiv_min.
 * Never-taken branch hides FP divide-by-zero.
 * A64 FP div-by-zero produces +/-Inf (no trap by default),
 * so we add brk after the divide to force a wrong-path fault.
 */
    .text
    .global _start
_start:
    mov     w19, #0
    movk    w19, #3, lsl #16    /* w19 = 200000 (approx) */
    mov     w20, #1             /* always-true predicate */

.Lloop:
    cbnz    w20, .Lsafe         /* always taken */

.Ltrap:
    fmov    d0, #1.0
    movi    d1, #0
    fdiv    d2, d0, d1          /* FP divide by zero → +Inf */
    brk     #1                  /* force fault */

.Lsafe:
    subs    w19, w19, #1
    b.ne    .Lloop

    mov     x0, #0
    mov     x8, #93
    svc     #0
