/*
 * MIPS (little-endian, O32 ABI) memdata test for wptrace load/store data.
 *
 * Stores sentinel values to stack slots and loads them back.
 * With memdata=1 the trace will contain ":data=0xdeadbeef" and
 * ":data=0xcafe1234" on the corresponding store= / load= parameters.
 *
 * O32: each stack frame must be a multiple of 8, and $sp must be 8-byte
 * aligned.  We allocate 16 bytes.  $s0 is callee-saved loop counter.
 *
 * Compile: mipsel-linux-gnu-gcc -static -nostdlib -nostartfiles -e __start \
 *              -o memdata_mips memdata.S
 * Run:     qemu-mipsel -plugin libwptrace.so,...,memdata=1 memdata_mips
 */
    .set noreorder
    .global __start
    .text
__start:
    li      $s0, 50             /* loop counter (callee-saved) */
    addiu   $sp, $sp, -16       /* allocate 16-byte stack frame */

loop:
    /* Store sentinel A */
    lui     $t0, 0xdead
    ori     $t0, $t0, 0xbeef    /* t0 = 0xdeadbeef */
    sw      $t0, 0($sp)         /* store: data = 0xdeadbeef */

    /* Load it back */
    lw      $t1, 0($sp)         /* load:  data = 0xdeadbeef */
    nop                         /* load delay slot */

    /* Store sentinel B */
    lui     $t0, 0xcafe
    ori     $t0, $t0, 0x1234    /* t0 = 0xcafe1234 */
    sw      $t0, 4($sp)         /* store: data = 0xcafe1234 */

    /* Load it back */
    lw      $t2, 4($sp)         /* load:  data = 0xcafe1234 */
    nop                         /* load delay slot */

    addiu   $s0, $s0, -1
    bne     $s0, $zero, loop
    nop

    addiu   $sp, $sp, 16
    li      $v0, 4001           /* __NR_exit (O32) */
    li      $a0, 0
    syscall
