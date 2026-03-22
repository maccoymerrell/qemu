/*
 * AArch64 port of wptrace_wrongpath_divsd_tagged.
 * Never-taken branch hides an FP divide + brk trap.
 * Exercises: fdiv (FP_DIV), fmov/fldr, branch, subs, svc.
 */
    .section .rodata
    .align 3
one_d:  .double 1.0
zero_d: .double 0.0

    .text
    .global _start
_start:
    mov     w19, #0             /* loop counter low */
    movk    w19, #8, lsl #16    /* w19 = 0x80000 = 524288 */
    mov     w20, #1             /* always-true predicate */

.Lloop:
    cbnz    w20, .Lsafe         /* always taken */

.Ltrap:
    adrp    x0, one_d
    add     x0, x0, :lo12:one_d
    ldr     d0, [x0]
    adrp    x0, zero_d
    add     x0, x0, :lo12:zero_d
    ldr     d1, [x0]
    fdiv    d2, d0, d1          /* FP divide by zero */
    brk     #1                  /* trap on wrong path */

.Lsafe:
    subs    w19, w19, #1
    b.ne    .Lloop

    mov     x0, #0
    mov     x8, #93
    svc     #0
