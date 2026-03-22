/*
 * RISC-V (RV64GC) heap allocation test for wptrace memalloc capture.
 *
 * Exercises brk(2) directly to trigger MEMALLOC events:
 *   1. brk(0)           — query current program break
 *   2. brk(break+4096)  — extend heap by one page  → MAP event
 *   3. write + read the allocated page
 *   4. brk(original)    — shrink back                → UNMAP event
 *   5. exit(0)
 *
 * Compile: riscv64-linux-gnu-gcc -static -nostdlib -nostartfiles \
 *              -march=rv64gc -mabi=lp64d -o heapalloc_riscv64 heapalloc.S
 * Run:     qemu-riscv64 -plugin libwptrace.so,...,memalloc=1 heapalloc_riscv64
 */
    .text
    .global _start
_start:
    /* brk(0) — query current program break */
    li      a0, 0
    li      a7, 214             /* __NR_brk */
    ecall
    mv      s0, a0              /* s0 = original break (callee-saved) */

    /* brk(break + 4096) — allocate one page */
    li      t0, 4096
    add     a0, s0, t0
    li      a7, 214
    ecall

    /* Write to the newly allocated page */
    li      t1, 0xdeadbeef
    sw      t1, 0(s0)

    /* Read it back (ensures the page is actually touched) */
    lw      t2, 0(s0)

    /* brk(original) — release the page */
    mv      a0, s0
    li      a7, 214
    ecall

    /* exit(0) */
    li      a0, 0
    li      a7, 93
    ecall
