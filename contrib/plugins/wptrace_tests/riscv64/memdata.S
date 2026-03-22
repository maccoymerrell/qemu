/*
 * RISC-V (RV64GC) memdata test for wptrace load/store/reg data capture.
 *
 * Stores sentinel values to stack slots and loads them back.
 * With memdata=1 the trace will contain ":data=0xdeadbeef" and
 * ":data=0xcafe1234" on the corresponding store= / load= parameters.
 *
 * Compile: riscv64-linux-gnu-gcc -static -nostdlib -nostartfiles \
 *              -march=rv64gc -mabi=lp64d -o memdata_riscv64 memdata.S
 * Run:     qemu-riscv64 -plugin libwptrace.so,...,memdata=1 memdata_riscv64
 */
    .text
    .global _start
_start:
    li      s0, 50              /* loop counter (callee-saved) */
    addi    sp, sp, -16         /* allocate 16-byte stack frame */

loop:
    /* Store sentinel A */
    li      t0, 0xdeadbeef
    sw      t0, 0(sp)           /* store: data = 0xdeadbeef */

    /* Load it back */
    lw      t1, 0(sp)           /* load:  data = 0xdeadbeef */

    /* Store sentinel B */
    li      t0, 0xcafe1234
    sw      t0, 4(sp)           /* store: data = 0xcafe1234 */

    /* Load it back */
    lw      t2, 4(sp)           /* load:  data = 0xcafe1234 */

    addi    s0, s0, -1
    bnez    s0, loop

    addi    sp, sp, 16
    li      a0, 0
    li      a7, 93              /* __NR_exit */
    ecall
