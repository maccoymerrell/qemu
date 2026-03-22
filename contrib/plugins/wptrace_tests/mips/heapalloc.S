/*
 * MIPS (little-endian, O32 ABI) heap allocation test for wptrace memalloc.
 *
 * Exercises brk(2) directly to trigger MEMALLOC events:
 *   1. brk(0)           — query current program break
 *   2. brk(break+4096)  — extend heap by one page  → MAP event
 *   3. write + read the allocated page
 *   4. brk(original)    — shrink back                → UNMAP event
 *   5. exit(0)
 *
 * MIPS O32 ABI: syscall number in $v0, args in $a0-$a3, result in $v0.
 * __NR_brk = 4045, __NR_exit = 4001 (O32 base 4000).
 *
 * Compile: mipsel-linux-gnu-gcc -static -nostdlib -nostartfiles -e __start \
 *              -o heapalloc_mips heapalloc.S
 * Run:     qemu-mipsel -plugin libwptrace.so,...,memalloc=1 heapalloc_mips
 */
    .set noreorder
    .global __start
    .text
__start:
    /* brk(0) — query current program break */
    li      $v0, 4045           /* __NR_brk (O32) */
    li      $a0, 0
    syscall
    move    $s0, $v0            /* s0 = original break (callee-saved) */

    /* brk(break + 4096) — allocate one page */
    li      $v0, 4045
    addiu   $a0, $s0, 4096
    syscall                     /* v0 = new break */

    /* Write to the newly allocated page */
    li      $t0, 0xdeadbeef
    sw      $t0, 0($s0)

    /* Read it back (ensures the page is actually touched) */
    lw      $t1, 0($s0)
    nop                         /* load delay slot */

    /* brk(original) — release the page */
    li      $v0, 4045
    move    $a0, $s0
    syscall

    /* exit(0) */
    li      $v0, 4001           /* __NR_exit (O32) */
    li      $a0, 0
    syscall
