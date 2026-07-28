/*
 * Oracle probe (RISC-V 64, bare, no libc) for the sticky FP exception flags.
 *
 * The flags are the acute case of value-equality blindness: once a bit is set
 * it stays set, so every later instruction that raises it again writes a value
 * equal to the old one and is invisible for the rest of the run.  Clearing the
 * field before each instruction makes those writes visible again -- but only
 * if nothing reads the field, and RISC-V has an instruction that does.
 *
 * fround.d (Zfa) is specified to leave the inexact flag as it found it, and
 * QEMU implements that by reading the old NX bit and writing it back
 * afterwards.  So clearing the field ahead of fround.d does not merely reveal
 * a hidden write, it changes what the instruction computes.  That is what the
 * poison checker has to catch, and this probe is where it can.
 */
        .section .data
        .align 6
scratch:
        .dword 0x3ff8000000000000       /* 1.5 */
        .dword 0x4002000000000000       /* 2.25 */

        .text
        .globl _start
_start:
        la      s0, scratch
        fld     fa1, 0(s0)
        fld     fa2, 8(s0)
        li      a0, 3
        li      a1, 7

        .globl oracle_begin
oracle_begin:
        fdiv.d  fa3, fa1, fa2     /* 1.5/2.25 is inexact: raises NX */
        fadd.d  fa4, fa1, fa2     /* exact: raises nothing */
        fdiv.d  fa5, fa1, fa2     /* raises NX again -- already set, invisible */
        fround.d fa6, fa1         /* reads NX in order to preserve it */
        fdiv.d  fa7, fa1, fa2     /* raises NX a third time */
        .globl oracle_end
oracle_end:
        nop

        li      a0, 0
        li      a7, 93            /* __NR_exit */
        ecall
