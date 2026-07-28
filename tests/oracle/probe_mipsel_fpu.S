/*
 * Oracle probe (MIPS little-endian, bare, no libc).
 *
 * Aimed at fpr_t, the case where the offset -> register map is not enough.
 * MIPS stores each FP register as a sixteen-byte union and the TCG globals
 * table names only the low eight bytes of it.  With FR=0 -- which is what an
 * o32 binary gets -- the odd-numbered single-precision registers are the
 * *upper* half of the even-numbered register's storage, so a four-byte write
 * at fpr[n] + 4 is $f(2n+1) in one mode and the top half of $f(2n)'s double in
 * the other.  Nothing in the layout distinguishes them; only the instruction
 * does.
 */
        .set noreorder
        .section .data
        .align 6
scratch:
        .word 0x3f800000          /* 1.0f */
        .word 0x40000000          /* 2.0f */
        .word 0x40400000          /* 3.0f */
        .word 0x40800000          /* 4.0f */

        .text
        .globl _start
        .globl __start          /* the entry symbol the MIPS linker looks for */
_start:
__start:
        lui     $t0, %hi(scratch)
        addiu   $t0, $t0, %lo(scratch)
        lwc1    $f0, 0($t0)
        lwc1    $f2, 4($t0)
        lwc1    $f10, 0($t0)
        lwc1    $f12, 4($t0)

        .globl oracle_begin
oracle_begin:
        lwc1    $f1, 8($t0)       /* odd single: FR=0 puts it at fpr[0] + 4 */
        add.s   $f3, $f0, $f2     /* odd destination, even sources */
        add.s   $f4, $f0, $f2     /* even destination for contrast */
        mul.s   $f5, $f3, $f2     /* odd source and odd destination */
        div.s   $f6, $f0, $f2     /* inexact: sticky FP flag in fcr31 */
        add.d   $f8, $f10, $f12   /* a double: where do its two halves land? */
        .globl oracle_end
oracle_end:
        nop

        li      $a0, 0
        li      $v0, 4001         /* __NR_exit */
        syscall
