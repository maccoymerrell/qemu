/*
 * MIPS port of wptrace_wrongpath_fpdiv_vec.
 * Never-taken path with single-precision FP div-by-zero,
 * plus always-executed div.s for instruction coverage.
 */
    .set noreorder
    .text
    .global __start
__start:
    li      $s0, 200000
    li      $s1, 1              /* always-true */

.Lloop:
    bne     $s1, $zero, .Lsafe
    nop

    /* Wrong path: single-precision FP div by zero */
    li      $t0, 0x3f800000     /* 1.0f */
    mtc1    $t0, $f0
    mtc1    $zero, $f2
    div.s   $f4, $f0, $f2
    break

.Lsafe:
    addiu   $s0, $s0, -1
    bne     $s0, $zero, .Lloop
    nop

    /* Always-executed single-precision FP divide for coverage */
    li      $t0, 0x3f800000
    mtc1    $t0, $f0
    mtc1    $zero, $f2
    div.s   $f4, $f0, $f2      /* 1.0 / 0.0 = +Inf */

    li      $v0, 4001
    li      $a0, 0
    syscall
