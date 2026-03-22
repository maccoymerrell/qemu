/*
 * AArch64 port of wptrace_wrongpath_fpdiv_vec.
 * Never-taken path with single-precision FP div-by-zero,
 * plus an always-executed divss after loop for instruction coverage.
 */
    .text
    .global _start
_start:
    mov     w19, #0
    movk    w19, #3, lsl #16    /* ~200000 iterations */
    mov     w20, #1             /* always-true */

.Lloop:
    cbnz    w20, .Lsafe

    /* Wrong path: single-precision FP div by zero */
    fmov    s0, #1.0
    movi    v1.2s, #0
    fdiv    s2, s0, s1
    brk     #1

.Lsafe:
    subs    w19, w19, #1
    b.ne    .Lloop

    /* Always-executed single-precision FP divide for coverage */
    fmov    s0, #1.0
    movi    v1.2s, #0
    fdiv    s2, s0, s1          /* 1.0 / 0.0 = +Inf, no trap */

    mov     x0, #0
    mov     x8, #93
    svc     #0
