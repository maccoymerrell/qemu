/*
 * AArch64 port of wptrace_wrongpath_storefwd.
 * Store-forwarding pattern: store a word, immediately load it back.
 * Two paths (correct always taken, wrong never taken) exercise
 * BB equivalence with identical store/load sequences.
 */
    .bss
    .align 4
idx_slot:   .word 0
    .align 4
table:      .skip 2097152       /* 2 MB table */

    .text
    .global _start
_start:
    mov     w10, #0             /* index */
    mov     w11, #0             /* predicate (always 0 → always eq) */
    mov     w12, #5000          /* loop counter */
    adrp    x13, idx_slot
    add     x13, x13, :lo12:idx_slot
    adrp    x14, table
    add     x14, x14, :lo12:table

loop_top:
    cbnz    w11, wrong_path     /* never taken (w11 == 0) */

correct_path:
    str     w10, [x13]          /* store index */
    ldr     w0, [x13]           /* load it back (store-forwarding) */
    str     w0, [x14, w0, uxtw #2] /* table[idx] = idx */
    ldr     w8, [x14, w0, uxtw #2] /* load table[idx] */
    add     w10, w10, #1
    b       loop_tail

wrong_path:
    str     w10, [x13]
    ldr     w0, [x13]
    str     w0, [x14, w0, uxtw #2]
    ldr     w8, [x14, w0, uxtw #2]
    add     w10, w10, #2
    cmp     w10, #64
    b.lo    wrong_path
    /* fall through */

loop_tail:
    subs    w12, w12, #1
    b.ne    loop_top

    mov     x0, #0
    mov     x8, #93
    svc     #0
