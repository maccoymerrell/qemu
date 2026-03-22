/*
 * MIPS port of wptrace_wrongpath_storefwd.
 * Store-forwarding: store a word, immediately load it back.
 * Two paths exercise BB equivalence with identical store/load sequences.
 *
 * Uses stack-allocated memory to avoid $gp-relative BSS addressing,
 * which is not available in a bare __start without C runtime setup.
 *
 * Stack layout:
 *   sp+0   : idx_slot (4 bytes)
 *   sp+8   : table[]  (5000 entries x 4 bytes = 20000 bytes)
 *   Total  : 20016 bytes, rounded to 20480
 */
    .set noreorder
    .text
    .global __start
__start:
    addiu   $sp, $sp, -20480    /* allocate stack frame */
    move    $s3, $sp            /* s3 = &idx_slot (sp+0) */
    addiu   $s4, $sp, 8        /* s4 = &table[0] (sp+8) */
    sw      $zero, 0($s3)      /* clear idx_slot */
    li      $s0, 0              /* index */
    li      $s1, 0              /* predicate (always 0) */
    li      $s2, 5000           /* loop counter */

loop_top:
    bne     $s1, $zero, wrong_path  /* never taken */
    nop

correct_path:
    sw      $s0, 0($s3)         /* store index */
    lw      $a0, 0($s3)         /* load it back (store-forwarding) */
    sll     $t0, $a0, 2
    addu    $t0, $s4, $t0
    sw      $a0, 0($t0)         /* table[idx] = idx */
    lw      $t1, 0($t0)         /* load table[idx] */
    addiu   $s0, $s0, 1
    b       loop_tail
    nop

wrong_path:
    sw      $s0, 0($s3)
    lw      $a0, 0($s3)
    sll     $t0, $a0, 2
    addu    $t0, $s4, $t0
    sw      $a0, 0($t0)
    lw      $t1, 0($t0)
    addiu   $s0, $s0, 2
    sltiu   $t2, $s0, 64
    bne     $t2, $zero, wrong_path
    nop
    /* fall through */

loop_tail:
    addiu   $s2, $s2, -1
    bne     $s2, $zero, loop_top
    nop

    addiu   $sp, $sp, 20480     /* restore stack */
    li      $v0, 4001
    li      $a0, 0
    syscall
