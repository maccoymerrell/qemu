/*
 * MIPS port of wptrace_wrongpath_divsd_tagged.
 * Never-taken branch hides FP divide + break.
 * Exercises: div.d (FP_DIV), ldc1, branches, syscall.
 */
    .set noreorder
    .section .rodata
    .align 3
one_d:  .double 1.0
zero_d: .double 0.0

    .text
    .global __start
__start:
    li      $s0, 500000         /* loop counter */
    li      $s1, 1              /* always-true predicate */

.Lloop:
    bne     $s1, $zero, .Lsafe  /* always taken */
    nop

.Ltrap:
    la      $t0, one_d
    ldc1    $f0, 0($t0)
    la      $t0, zero_d
    ldc1    $f2, 0($t0)
    div.d   $f4, $f0, $f2       /* FP divide by zero */
    break                       /* trap */

.Lsafe:
    addiu   $s0, $s0, -1
    bne     $s0, $zero, .Lloop
    nop

    li      $v0, 4001
    li      $a0, 0
    syscall
