/*
 * Oracle probe (AArch64, bare, no libc).
 *
 * Aimed at the state AArch64 keeps *outside* the TCG globals table, which is
 * where the interpretation layer earns its keep.  QEMU stores the condition
 * flags as four separate 32-bit words -- NF, ZF, CF, VF -- and stores ZF
 * inverted: the Z condition holds when the word is zero.  None of the four is
 * a TCG global, so they arrive at the oracle as raw byte offsets, and reading
 * "ZF changed 1 -> 0" as "Z was cleared" would be exactly backwards.
 */
        .section .data
        .align 6
scratch:
        .dword 0x0123456789abcdef
        .dword 0x1122334455667788

        .text
        .globl _start
_start:
        adrp    x8, scratch
        add     x8, x8, :lo12:scratch
        mov     x0, #0x1111
        mov     x1, #0x2222
        ldr     d1, [x8]
        fmov    d2, #1.5
        fmov    d3, #2.5

        .globl oracle_begin
oracle_begin:
        add     x2, x0, x1        /* -> x2 only, no flags */
        adds    x3, x0, x1        /* -> x3 and all four flag words */
        subs    x4, x0, x0        /* result zero: sets Z, so ZF word -> 0 */
        cmp     x0, x1            /* flags only, no register */
        ccmp    x0, x1, #0, eq    /* conditional flag write */
        fadd    d4, d2, d3        /* -> d4 and the FP status word */
        fdiv    d5, d2, d3        /* inexact: sticky FP flag */
        fcmp    d2, d3            /* FP compare writes the same flag words */
        /*
         * Memory operands.  Without at least one load and one store the
         * QEMU_CAP_MUTATE=memdir positive control has no subject, and
         * check-independence.py fails the mode 0/N rather than passing a
         * mutation it could not exercise.  x6 addresses the scratch word.
         */
        adr     x6, oracle_scratch
        str     x0, [x6]          /* store: memop direction OUT */
        ldr     x7, [x6]          /* load:  memop direction IN  */
        .globl oracle_end
oracle_end:
        nop

        mov     x0, #0
        mov     x8, #93           /* __NR_exit */
        svc     #0

        .data
        .align  3
oracle_scratch:
        .quad   0
