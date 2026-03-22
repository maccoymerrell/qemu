/*
 * RISC-V port of wptrace_wp_intdiv_fault.
 * Always-taken branch skips div-by-zero.
 * RV64M div by zero returns -1 (no trap), so we follow with ebreak.
 */
    .text
    .global _start
_start:
    li      t0, 40              /* loop counter */
loop:
    li      a0, 0
    beq     a0, a0, safe_path   /* always taken */

fault_path:
    li      a0, 1234
    li      a1, 0
    div     a2, a0, a1          /* RV: yields -1, no trap */
    ebreak                      /* force SIGTRAP on wrong path */

safe_path:
    addi    a0, a0, 1
    addi    t0, t0, -1
    bnez    t0, loop

    li      a0, 0
    li      a7, 93
    ecall
