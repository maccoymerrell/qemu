/*
 * MIPS (little-endian) port of wptrace_wp_intdiv_fault.
 * Always-taken branch skips div-by-zero.
 * MIPS div by zero is architecturally undefined; QEMU may not trap,
 * so we follow with break to force a fault on the wrong path.
 */
    .set noreorder
    .global __start
    .text
__start:
    li      $t0, 40             /* loop counter */
loop:
    li      $a0, 0
    beq     $a0, $a0, safe_path /* always taken */
    nop

fault_path:
    li      $a0, 1234
    li      $a1, 0
    div     $zero, $a0, $a1     /* div by zero */
    break                       /* force SIGTRAP */

safe_path:
    addiu   $a0, $a0, 1
    addiu   $t0, $t0, -1
    bne     $t0, $zero, loop
    nop

    li      $v0, 4001           /* __NR_exit */
    li      $a0, 0
    syscall
