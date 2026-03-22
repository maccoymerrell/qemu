/*
 * RISC-V port of wptrace_wrongpath_storefwd.
 * Store-forwarding: store a word, immediately load it back.
 * Two paths exercise BB equivalence with identical store/load sequences.
 */
    .bss
    .align 4
idx_slot:   .word 0
    .align 4
table:      .skip 2097152

    .text
    .global _start
_start:
    li      s0, 0               /* index */
    li      s1, 0               /* predicate (always 0 → always eq) */
    li      s2, 5000            /* loop counter */
    la      s3, idx_slot
    la      s4, table

loop_top:
    bnez    s1, wrong_path      /* never taken (s1 == 0) */

correct_path:
    sw      s0, 0(s3)           /* store index */
    lw      a0, 0(s3)           /* load it back */
    slli    t0, a0, 2
    add     t0, s4, t0
    sw      a0, 0(t0)           /* table[idx] = idx */
    lw      t1, 0(t0)           /* load table[idx] */
    addi    s0, s0, 1
    j       loop_tail

wrong_path:
    sw      s0, 0(s3)
    lw      a0, 0(s3)
    slli    t0, a0, 2
    add     t0, s4, t0
    sw      a0, 0(t0)
    lw      t1, 0(t0)
    addi    s0, s0, 2
    li      t2, 64
    bltu    s0, t2, wrong_path
    /* fall through */

loop_tail:
    addi    s2, s2, -1
    bnez    s2, loop_top

    li      a0, 0
    li      a7, 93
    ecall
