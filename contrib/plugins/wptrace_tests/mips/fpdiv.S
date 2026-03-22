/*
 * MIPS port of wptrace_wrongpath_fpdiv_min.
 * Never-taken branch hides double-precision FP divide-by-zero.
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

.Ltrap:
    li      $t0, 0x3ff00000
    mtc1    $zero, $f0          /* low word of 1.0 */
    mthc1   $t0, $f0            /* high word of 1.0 → $f0 = 1.0 */
    mtc1    $zero, $f2          /* 0.0 low */
    mthc1   $zero, $f2          /* 0.0 high */
    div.d   $f4, $f0, $f2       /* 1.0 / 0.0 */
    break

.Lsafe:
    addiu   $s0, $s0, -1
    bne     $s0, $zero, .Lloop
    nop

    li      $v0, 4001
    li      $a0, 0
    syscall
