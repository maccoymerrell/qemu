/*
 * x86-64 heap allocation test for wptrace memalloc capture.
 *
 * Exercises brk(2) directly to trigger MEMALLOC events:
 *   1. brk(0)           — query current program break
 *   2. brk(break+4096)  — extend heap by one page  → MAP event
 *   3. write + read the allocated page
 *   4. brk(original)    — shrink back                → UNMAP event
 *   5. exit(0)
 *
 * Compile: gcc -static -nostdlib -nostartfiles -o heapalloc_x86 heapalloc.S
 * Run:     qemu-x86_64 -plugin libwptrace.so,...,memalloc=1 heapalloc_x86
 */
    .text
    .global _start
_start:
    /* brk(0) — query current program break */
    movl    $12, %eax           /* __NR_brk */
    xorl    %edi, %edi
    syscall
    movq    %rax, %rbx          /* rbx = original break */

    /* brk(break + 4096) — allocate one page */
    movq    %rbx, %rdi
    addq    $4096, %rdi
    movl    $12, %eax
    syscall

    /* Write to the newly allocated page */
    movl    $0xdeadbeef, %ecx
    movl    %ecx, (%rbx)

    /* Read it back (ensures the page is actually touched) */
    movl    (%rbx), %edx

    /* brk(original) — release the page */
    movq    %rbx, %rdi
    movl    $12, %eax
    syscall

    /* exit(0) */
    movl    $60, %eax
    xorl    %edi, %edi
    syscall
