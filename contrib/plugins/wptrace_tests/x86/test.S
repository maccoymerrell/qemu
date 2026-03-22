/*
 * wptrace x86-64 ISA coverage test.
 * Exercises: ALU, mul, div, load, store, branch, compare, syscall.
 */
    .text
    .global _start
_start:
    movl    $100, %ecx          /* loop counter */
    movl    $7, %esi            /* operand a */
    movl    $3, %edi            /* operand b */

loop:
    /* Integer ALU */
    movl    %esi, %eax
    addl    %edi, %eax          /* eax = 10 */
    movl    %esi, %r8d
    subl    %edi, %r8d          /* r8d = 4  */
    movl    %esi, %r9d
    andl    %edi, %r9d          /* r9d = 3  */
    movl    %esi, %r10d
    orl     %edi, %r10d         /* r10d = 7 */
    movl    %esi, %r11d
    xorl    %edi, %r11d         /* r11d = 4 */
    movl    %esi, %edx
    shll    $2, %edx            /* edx = 28 */
    shrl    $1, %edx            /* edx = 14 */

    /* Multiply */
    movl    %esi, %eax
    mull    %edi                /* edx:eax = 7*3 = 21 */
    movl    %eax, %r12d         /* r12d = 21 */

    /* Divide */
    movl    %r12d, %eax
    xorl    %edx, %edx
    divl    %edi                /* eax = 7, edx = 0 */

    /* Load and store (stack-based) */
    subq    $16, %rsp
    movl    %r12d, (%rsp)       /* store 21 to stack */
    movl    (%rsp), %r13d       /* load it back */
    addq    $16, %rsp

    /* Compare and conditional branch */
    cmpl    %r13d, %r12d
    jne     fail
    decl    %ecx
    jnz     loop

    /* Exit with 0 */
    movl    $60, %eax
    xorl    %edi, %edi
    syscall

fail:
    movl    $60, %eax
    movl    $1, %edi
    syscall
