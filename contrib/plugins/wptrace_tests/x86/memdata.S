/*
 * x86-64 memdata test for wptrace load/store/reg data capture.
 *
 * Stores a sentinel value (0xdeadbeef) to a stack slot, then loads it back.
 * A second store uses 0xcafe1234.  When run with memdata=1 the trace will
 * contain ":data=0xdeadbeef" and ":data=0xcafe1234" annotations on the
 * store= and load= dynamic parameters.
 *
 * The loop runs 50 times so the watchpoint BBs are captured with certainty
 * before the stop=N limit fires.
 *
 * Compile: gcc -static -nostdlib -nostartfiles -o memdata_x86 memdata.S
 * Run:     qemu-x86_64 -plugin libwptrace.so,...,memdata=1 memdata_x86
 */
    .text
    .global _start
_start:
    movl    $50, %ecx           /* loop counter */
    subq    $16, %rsp           /* allocate 16-byte stack slot */

loop:
    /* Store sentinel A to stack */
    movl    $0xdeadbeef, %eax
    movl    %eax, (%rsp)        /* store: data = 0xdeadbeef */

    /* Load it back */
    movl    (%rsp), %edx        /* load:  data = 0xdeadbeef */

    /* Store sentinel B */
    movl    $0xcafe1234, %eax
    movl    %eax, 4(%rsp)       /* store: data = 0xcafe1234 */

    /* Load it back */
    movl    4(%rsp), %esi       /* load:  data = 0xcafe1234 */

    decl    %ecx
    jnz     loop

    addq    $16, %rsp
    movl    $60, %eax
    xorl    %edi, %edi
    syscall
