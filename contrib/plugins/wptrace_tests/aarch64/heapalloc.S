/*
 * AArch64 heap allocation test for wptrace memalloc capture.
 *
 * Exercises brk(2) directly to trigger MEMALLOC events:
 *   1. brk(0)           — query current program break
 *   2. brk(break+4096)  — extend heap by one page  → MAP event
 *   3. write + read the allocated page
 *   4. brk(original)    — shrink back                → UNMAP event
 *   5. exit(0)
 *
 * Compile: aarch64-linux-gnu-gcc -static -nostdlib -nostartfiles \
 *              -o heapalloc_aarch64 heapalloc.S
 * Run:     qemu-aarch64 -plugin libwptrace.so,...,memalloc=1 heapalloc_aarch64
 */
    .text
    .global _start
_start:
    /* brk(0) — query current program break */
    mov     x0, #0
    mov     x8, #214            /* __NR_brk */
    svc     #0
    mov     x19, x0             /* x19 = original break (callee-saved) */

    /* brk(break + 4096) — allocate one page */
    add     x0, x19, #4096
    mov     x8, #214
    svc     #0

    /* Write to the newly allocated page */
    mov     w1, #0xbeef
    movk    w1, #0xdead, lsl #16
    str     w1, [x19]

    /* Read it back (ensures the page is actually touched) */
    ldr     w2, [x19]

    /* brk(original) — release the page */
    mov     x0, x19
    mov     x8, #214
    svc     #0

    /* exit(0) */
    mov     x0, #0
    mov     x8, #93
    svc     #0
