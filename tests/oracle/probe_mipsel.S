        .text
        .globl __start
        .globl _start
_start:
__start:
        li      $a0, 0x1111
        li      $a1, 0x2222
        .globl oracle_begin
oracle_begin:
        addu    $a2, $a0, $a1      /* -> $6 only            */
        subu    $a3, $a0, $a1      /* -> $7 only            */
        addu    $zero, $a0, $a1    /* rd = $0 -> nothing    */
        mult    $a0, $a1           /* -> HI and LO only     */
        sll     $t0, $a0, 3        /* -> $8 only            */
        slt     $t1, $a0, $a1      /* -> $9 only            */
        /*
         * Memory operands, so QEMU_CAP_MUTATE=memdir has a subject: without
         * a load and a store the mode scores 0/N and the check fails rather
         * than passing a mutation it never exercised.
         */
        sw      $a0, -8($sp)       /* store: memop direction OUT */
        lw      $t3, -8($sp)       /* load:  memop direction IN  */
        .globl oracle_end
oracle_end:
        nop
        li      $v0, 4001
        li      $a0, 0
        syscall
