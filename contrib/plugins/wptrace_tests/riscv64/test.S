/*
 * wptrace RISC-V (RV64GC) ISA coverage test.
 * Exercises: ALU, mul, div, load, store, branch, compare, syscall.
 */
        .global _start
        .text
_start:
        /* Setup */
        li      t0, 100             /* loop counter */
        li      t1, 7               /* operand a */
        li      t2, 3               /* operand b */

loop:
        /* Integer ALU */
        add     t3, t1, t2          /* t3 = 10 */
        sub     t4, t1, t2          /* t4 = 4  */
        and     t5, t1, t2          /* t5 = 3  */
        or      t6, t1, t2          /* t6 = 7  */
        xor     s1, t1, t2          /* s1 = 4  */
        slli    s2, t1, 2           /* s2 = 28 */
        srli    s3, s2, 1           /* s3 = 14 */
        srai    s4, t4, 1           /* s4 = 2  */

        /* Multiply and divide (M extension) */
        mul     s5, t1, t2          /* s5 = 21 */
        div     s6, s5, t2          /* s6 = 7  */
        rem     s7, s5, t2          /* s7 = 0  */

        /* Load and store (stack-based) */
        addi    sp, sp, -16
        sd      s5, 0(sp)           /* store 21 to stack */
        ld      s8, 0(sp)           /* load it back */
        addi    sp, sp, 16

        /* Compare and conditional branch */
        bne     s8, s5, fail
        addi    t0, t0, -1
        bnez    t0, loop

        /* Exit with 0 */
        li      a0, 0
        li      a7, 93              /* __NR_exit */
        ecall

fail:
        li      a0, 1
        li      a7, 93
        ecall
