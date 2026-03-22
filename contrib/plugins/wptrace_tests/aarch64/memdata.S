/*
 * AArch64 memdata test for wptrace load/store/reg data capture.
 *
 * Stores sentinel values to stack slots and loads them back.
 * With memdata=1 the trace will contain ":data=0xdeadbeef" and
 * ":data=0xcafe1234" on the corresponding store= / load= parameters.
 *
 * Compile: aarch64-linux-gnu-gcc -static -nostdlib -nostartfiles \
 *              -o memdata_aarch64 memdata.S
 * Run:     qemu-aarch64 -plugin libwptrace.so,...,memdata=1 memdata_aarch64
 */
    .text
    .global _start
_start:
    mov     w19, #50            /* loop counter (callee-saved) */
    sub     sp, sp, #16         /* allocate 16-byte stack frame */

loop:
    /* Store sentinel A */
    mov     w0, #0xbeef
    movk    w0, #0xdead, lsl #16    /* w0 = 0xdeadbeef */
    str     w0, [sp]                /* store: data = 0xdeadbeef */

    /* Load it back */
    ldr     w1, [sp]                /* load:  data = 0xdeadbeef */

    /* Store sentinel B */
    mov     w0, #0x1234
    movk    w0, #0xcafe, lsl #16    /* w0 = 0xcafe1234 */
    str     w0, [sp, #4]            /* store: data = 0xcafe1234 */

    /* Load it back */
    ldr     w2, [sp, #4]            /* load:  data = 0xcafe1234 */

    subs    w19, w19, #1
    b.ne    loop

    add     sp, sp, #16
    mov     x0, #0
    mov     x8, #93             /* __NR_exit */
    svc     #0
