/*
 * wptrace AArch64 ISA coverage test.
 * Exercises: ALU, mul, div, load, store, branch, compare, syscall.
 */
        .global _start
        .text
_start:
        /* Setup */
        mov     x0, #100            /* loop counter */
        mov     x1, #7              /* operand a */
        mov     x2, #3              /* operand b */

loop:
        /* Integer ALU */
        add     x3, x1, x2          /* x3 = 7 + 3 = 10 */
        sub     x4, x1, x2          /* x4 = 7 - 3 = 4  */
        and     x5, x1, x2          /* x5 = 7 & 3 = 3  */
        orr     x6, x1, x2          /* x6 = 7 | 3 = 7  */
        eor     x7, x1, x2          /* x7 = 7 ^ 3 = 4  */
        lsl     x8, x1, #2          /* x8 = 7 << 2 = 28 */
        lsr     x9, x8, #1          /* x9 = 28 >> 1 = 14 */
        asr     x10, x4, #1         /* x10 = 4 >> 1 = 2 */

        /* Multiply and divide */
        mul     x11, x1, x2         /* x11 = 7 * 3 = 21 */
        udiv    x12, x11, x2        /* x12 = 21 / 3 = 7 */
        sdiv    x13, x11, x1        /* x13 = 21 / 7 = 3 */

        /* Load and store (stack-based) */
        sub     sp, sp, #16
        str     x11, [sp]           /* store 21 to stack */
        ldr     x14, [sp]           /* load it back */
        add     sp, sp, #16

        /* Compare and conditional branch */
        cmp     x14, x11
        b.ne    fail                /* should not branch */
        subs    x0, x0, #1          /* decrement counter */
        cbnz    x0, loop            /* loop if != 0 */

        /* Exit with 0 */
        mov     x0, #0
        mov     x8, #93             /* __NR_exit */
        svc     #0

fail:
        mov     x0, #1
        mov     x8, #93
        svc     #0
