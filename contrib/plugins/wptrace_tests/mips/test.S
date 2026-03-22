/*
 * wptrace MIPS (little-endian) ISA coverage test.
 * Exercises: ALU, mul, div, load, store, branch, compare, syscall.
 * Targets mipsel-linux-gnu.
 */
        .set    noreorder
        .global __start
        .text
__start:
        /* Setup */
        li      $t0, 100            /* loop counter */
        li      $t1, 7              /* operand a */
        li      $t2, 3              /* operand b */

loop:
        /* Integer ALU */
        addu    $t3, $t1, $t2       /* t3 = 10 */
        subu    $t4, $t1, $t2       /* t4 = 4  */
        and     $t5, $t1, $t2       /* t5 = 3  */
        or      $t6, $t1, $t2       /* t6 = 7  */
        xor     $t7, $t1, $t2       /* t7 = 4  */
        sll     $t8, $t1, 2         /* t8 = 28 */
        srl     $t9, $t8, 1         /* t9 = 14 */
        sra     $s0, $t4, 1         /* s0 = 2  */

        /* Multiply: result in HI:LO */
        mult    $t1, $t2
        mflo    $s1                 /* s1 = 21 */

        /* Divide: result in LO, remainder HI */
        div     $zero, $s1, $t2
        mflo    $s2                 /* s2 = 7  */

        /* Load and store (stack-based) */
        addiu   $sp, $sp, -16
        sw      $s1, 0($sp)        /* store 21 to stack */
        lw      $s3, 0($sp)        /* load it back */
        addiu   $sp, $sp, 16

        /* Compare and conditional branch */
        bne     $s3, $s1, fail
        nop                         /* branch delay slot */
        addiu   $t0, $t0, -1
        bne     $t0, $zero, loop
        nop

        /* Exit with 0 */
        li      $v0, 4001           /* __NR_exit (o32) */
        li      $a0, 0
        syscall

fail:
        li      $v0, 4001
        li      $a0, 1
        syscall
