/*
 * AArch64 port of wptrace_wp_intdiv_fault.
 * Always-taken branch skips a UDIV-by-zero (A64 UDIV by zero yields 0,
 * does NOT fault, so we follow up with a brk to force a trap on the
 * wrong path instead).
 */
    .text
    .global _start
_start:
    mov     w9, #40             /* loop counter */
loop:
    mov     w0, #0
    cmp     w0, w0
    b.eq    safe_path           /* always taken */

fault_path:
    mov     w0, #1234
    mov     w1, #0
    udiv    w2, w0, w1          /* A64: yields 0, no trap */
    brk     #1                  /* force SIGILL on wrong path */

safe_path:
    add     w0, w0, #1
    subs    w9, w9, #1
    b.ne    loop

    mov     x0, #0
    mov     x8, #93
    svc     #0
