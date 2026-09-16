/*
 * ARC 3 -- is this aarch64 encoding REACHABLE by a QEMU guest AT EL1?
 *
 * qemu-aarch64 runs everything at EL0, so a SIGILL from an encoding says
 * "EL0" and not "QEMU does not implement it".  Declaring such a row
 * unreachable off an EL0 signal is the assumption the maintainer refused on
 * x86_64, and `sysprobe.S` is the leg that removed it there.  This is the
 * same leg for A64: a freestanding image that boots under
 * qemu-system-aarch64 -M virt, runs at EL1 with FP, SVE and SME enabled at
 * their maximum vector lengths, executes every encoding, and reports the
 * synchronous exception class it took -- 0xFF when the instruction RAN.
 *
 * WHAT THE VERDICT MEANS.  ESR_EL1.EC == 0x00 ("Unknown reason") is the
 * architecture's UNDEFINED, which at EL1 with every enable set can only be
 * the translator having no pattern for the encoding.  Any OTHER EC -- a
 * data abort (0x24/0x25), an alignment fault, an SVE/FP access trap
 * (0x07), an MSR/MRS trap (0x18) -- means QEMU DECODED the instruction and
 * then took an architectural exception on it, so the encoding is
 * implemented and the row is REACHABLE.  The distinction is the whole
 * point: a bare "it faulted" cannot make it.
 *
 * WHAT IT STILL CANNOT SEE.  An encoding QEMU implements only at EL2 or
 * EL3 is UNDEFINED at EL1 for the privilege.  That residue is named per
 * row by the adjudicator rather than folded into the decoder verdict.
 *
 * Output goes to the PL011 UART the virt machine puts at 0x09000000, with
 * no driver and no firmware involved.  Each encoding's hex is written
 * BEFORE it is executed, so an encoding that wedges the machine -- and at
 * EL1 one really can, a WFI or a write to SCTLR_EL1 -- is attributable to
 * its exact row and is skipped on the next pass.
 *
 * The MMU is deliberately left OFF.  With translation disabled every access
 * is Device-nGnRnE, so an unaligned or multi-register access takes an
 * alignment fault -- which is EC 0x25, not EC 0x00, and therefore scores as
 * DECODED exactly as it should.  Turning the MMU on would change which rows
 * abort; it would change no row's decoder verdict, which is what this
 * measures.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define UART            0x09000000
#define RAM_SCRATCH     0x40800000

    .section .text.boot, "ax"
    .globl _start
_start:
    ldr     x0, =stack_top
    mov     sp, x0

    /* Refuse loudly rather than measure the wrong exception level. */
    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #1
    b.eq    at_el1
    mov     x0, x0
    bl      put_el_and_die
at_el1:

    /* Vector table first: everything after this can fault safely. */
    ldr     x0, =vectors
    msr     vbar_el1, x0
    isb

    /* Every architectural enable this probe can set from EL1.
     * CPACR_EL1: FPEN[21:20]=3, ZEN[17:16]=3, SMEN[25:24]=3. */
    mov     x0, xzr
    orr     x0, x0, #(3 << 20)
    orr     x0, x0, #(3 << 16)
    orr     x0, x0, #(3 << 24)
    msr     cpacr_el1, x0
    isb

    /* ZCR_EL1.LEN = 15  -> the largest SVE vector length the model has. */
    mov     x0, #15
    msr     S3_0_C1_C2_0, x0            /* ZCR_EL1  */
    /* SMCR_EL1.LEN = 15, EZT0 (bit 30), FA64 (bit 31). */
    mov     x0, #15
    orr     x0, x0, #(1 << 30)
    orr     x0, x0, #(1 << 31)
    msr     S3_0_C1_C2_6, x0            /* SMCR_EL1 */
    isb

    /* PSTATE.SM and PSTATE.ZA.  The SME instruction set is UNDEFINED
     * outside streaming mode with ZA enabled, so an SME row measured with
     * SVCR = 0 is refused for the PSTATE and not for the opcode.  Guarded:
     * if SME is absent the MSR itself is UNDEFINED, the handler records it
     * and execution continues with SVCR = 0, which is a measurement and not
     * a crash. */
    mov     x0, #0xff
    ldr     x1, =last_ec
    str     x0, [x1]
    .inst   0xd503477f                  /* smstart (msr SVCRSMZA, #1) */
    ldr     x1, =last_ec
    ldr     x0, [x1]
    ldr     x1, =smstart_ec
    str     x0, [x1]

    /* ------------------------------------------------------- the loop */
    /* Loop state lives in MEMORY, never in a register.  The encoding under
     * test is arbitrary: an encoding whose destination happened to be the
     * loop counter would silently restart or end the run, which is a
     * truncation dressed as a measurement.  Every register is reloaded from
     * memory after the call, and SP is re-established from a fixed address
     * for the same reason. */
    msr     daifset, #0xf               /* no asynchronous exception can
                                         * reach the vectors and spin */
    ldr     x0, =enc_count
    ldr     x0, [x0]
    ldr     x1, =state_n
    str     x0, [x1]
    ldr     x1, =state_i
    str     xzr, [x1]

loop:
    ldr     x0, =stack_top
    mov     sp, x0
    ldr     x0, =state_i
    ldr     x0, [x0]
    ldr     x1, =state_n
    ldr     x1, [x1]
    cmp     x0, x1
    b.ge    finished

    /* One 16-byte row: a length byte, three pad bytes, then the encoding
     * WORD at offset 4.  The pad is not cosmetic: with the MMU off every
     * data access is Device-nGnRnE, so a word load from an odd offset takes
     * an alignment fault instead of reading the encoding. */
    ldr     x1, =enc_blob
    add     x1, x1, x0, lsl #4
    ldr     x2, =state_row
    str     x1, [x2]

    /* print the hex BEFORE executing it */
    ldrb    w0, [x1]
    add     x1, x1, #4
    bl      put_hexbytes

    /* plant the encoding, then a ret, in the executable slot */
    ldr     x2, =state_row
    ldr     x2, [x2]
    ldr     x0, =insn_slot
    ldr     w1, [x2, #4]
    str     w1, [x0]
    ldr     w1, =0xd65f03c0             /* ret */
    str     w1, [x0, #4]
    dc      cvau, x0
    dsb     ish
    ic      ivau, x0
    dsb     ish
    isb

    /* Re-establish the enables every iteration: the encoding under test may
     * itself have been an MSR that cleared one. */
    mov     x0, xzr
    orr     x0, x0, #(3 << 20)
    orr     x0, x0, #(3 << 16)
    orr     x0, x0, #(3 << 24)
    msr     cpacr_el1, x0
    mov     x0, #15
    msr     S3_0_C1_C2_0, x0            /* ZCR_EL1  */
    mov     x0, #15
    orr     x0, x0, #(1 << 30)
    orr     x0, x0, #(1 << 31)
    msr     S3_0_C1_C2_6, x0            /* SMCR_EL1 */
    isb
    ldr     x0, =smstart_ec
    ldr     x0, [x0]
    cmp     x0, #0xff
    b.ne    1f
    .inst   0xd503477f                  /* smstart, only if it is supported */
1:

    /* 0xFF means "no exception was taken" */
    mov     x0, #0xff
    ldr     x1, =last_ec
    str     x0, [x1]

    /* every general register points at real, writable memory so a memory
     * operand addresses something and a data abort is not read as a refusal */
    ldr     x0, =RAM_SCRATCH
    mov     x1, x0
    mov     x2, x0
    mov     x3, x0
    mov     x4, x0
    mov     x5, x0
    mov     x6, x0
    mov     x7, x0
    mov     x8, x0
    mov     x9, x0
    mov     x10, x0
    mov     x11, x0
    mov     x12, x0
    mov     x13, x0
    mov     x14, x0
    mov     x15, x0
    mov     x16, x0
    mov     x17, x0
    mov     x18, x0
    mov     x19, x0
    mov     x20, x0
    mov     x21, x0
    mov     x22, x0
    mov     x23, x0
    mov     x24, x0
    mov     x25, x0
    mov     x26, x0
    mov     x27, x0
    mov     x28, x0

    ldr     x29, =insn_slot
    blr     x29

    .globl  after_insn
after_insn:
    ldr     x0, =stack_top
    mov     sp, x0
    ldr     x1, =last_ec
    ldr     x0, [x1]
    bl      put_ec

    ldr     x1, =state_i
    ldr     x0, [x1]
    add     x0, x0, #1
    str     x0, [x1]
    b       loop

finished:
    ldr     x0, =smstart_ec
    ldr     x0, [x0]
    bl      put_smstart
    adr     x0, s_done
    bl      puts
    /* stop the machine so the harness sees a clean end */
    mov     x0, #0x18                   /* SYS_EXIT via semihosting  */
    ldr     x1, =semi_exit
    hlt     #0xf000
1:  wfi
    b       1b

/* ------------------------------------------------------------ UART out */
putc:
    ldr     x9, =UART
    strb    w0, [x9]
    ret

puts:
    mov     x10, x0
1:  ldrb    w0, [x10], #1
    cbz     w0, 2f
    stp     x30, x10, [sp, #-16]!
    bl      putc
    ldp     x30, x10, [sp], #16
    b       1b
2:  ret

/* w0 = nibble */
puthex4:
    and     w0, w0, #0xf
    cmp     w0, #10
    b.lt    1f
    add     w0, w0, #('a' - 10)
    b       putc
1:  add     w0, w0, #'0'
    b       putc

/* w0 = byte */
puthex8:
    stp     x30, x11, [sp, #-16]!
    mov     w11, w0
    lsr     w0, w11, #4
    bl      puthex4
    mov     w0, w11
    bl      puthex4
    ldp     x30, x11, [sp], #16
    ret

/* w0 = length, x1 = bytes -- prints them in file order */
put_hexbytes:
    stp     x30, x12, [sp, #-16]!
    stp     x13, x14, [sp, #-16]!
    mov     w12, w0
    mov     x13, x1
    mov     w14, wzr
1:  cmp     w14, w12
    b.ge    2f
    ldrb    w0, [x13, x14]
    bl      puthex8
    add     w14, w14, #1
    b       1b
2:  ldp     x13, x14, [sp], #16
    ldp     x30, x12, [sp], #16
    ret

/* x0 = exception class, printed as "\t%02x\n" */
put_ec:
    stp     x30, x15, [sp, #-16]!
    mov     x15, x0
    mov     w0, #'\t'
    bl      putc
    mov     w0, w15
    bl      puthex8
    mov     w0, #'\n'
    bl      putc
    ldp     x30, x15, [sp], #16
    ret

put_smstart:
    stp     x30, x15, [sp, #-16]!
    mov     x15, x0
    adr     x0, s_smstart
    bl      puts
    mov     w0, w15
    bl      puthex8
    mov     w0, #'\n'
    bl      putc
    ldp     x30, x15, [sp], #16
    ret

put_el_and_die:
    stp     x30, x15, [sp, #-16]!
    mov     x15, x0
    adr     x0, s_badel
    bl      puts
    mov     w0, w15
    bl      puthex8
    mov     w0, #'\n'
    bl      putc
1:  wfi
    b       1b

/* --------------------------------------------------------- exceptions */
    .align 11
vectors:
    .rept 16
    .align 7
    b       sync_handler
    .endr

/* Resumption is at a FIXED point, never at ELR+4.  Stepping over the
 * faulting instruction assumes the NEXT word is the harness's own `ret`,
 * and when it is not -- an encoding that is a branch, a slot the probe
 * failed to plant -- the machine walks forward through memory taking one
 * UNDEF per word until the timeout, which is a hang dressed as a
 * measurement.  Resuming at `after_insn` cannot do that.
 *
 * WHERE the exception was taken is itself part of the verdict, in three
 * cases:
 *
 *   ELR inside the 8-byte slot   the encoding under test faulted.  ESR.EC
 *                                is the answer: 0x00 is UNDEFINED, which
 *                                at EL1 with every enable set means the
 *                                translator has no pattern for it; any
 *                                other EC means it DECODED and then took
 *                                an architectural exception.
 *
 *   ELR anywhere else in RAM     the encoding DECODED, EXECUTED and
 *                                transferred control -- a branch, a call,
 *                                a return.  It ran off into zeroed memory
 *                                and faulted there.  That is 0xFE: ran,
 *                                left the slot.  Reading it as a refusal
 *                                would mark every branch encoding
 *                                unreachable, which is the error this
 *                                whole leg exists to remove.
 *
 *   ELR inside the harness text  the probe's OWN code faulted.  Nothing
 *                                about the subject is measurable from
 *                                there and resuming would corrupt every
 *                                row after it, so this REFUSES and stops.
 */
sync_handler:
    mrs     x0, esr_el1
    lsr     x0, x0, #26
    and     x0, x0, #0x3f
    ldr     x1, =last_ec
    str     x0, [x1]
    mrs     x0, elr_el1
    ldr     x1, =insn_slot
    sub     x1, x0, x1
    cmp     x1, #8
    b.lo    resume                      /* the subject itself faulted */
    ldr     x1, =__text_start
    cmp     x0, x1
    b.lo    left_slot
    ldr     x1, =__text_end
    cmp     x0, x1
    b.lo    fault_in_harness
left_slot:
    mov     x0, #0xfe
    ldr     x1, =last_ec
    str     x0, [x1]
resume:
    ldr     x0, =after_insn
    msr     elr_el1, x0
    eret

fault_in_harness:
    ldr     x0, =stack_top
    mov     sp, x0
    adr     x0, s_outside
    bl      puts
    mrs     x0, elr_el1
    bl      put_addr
    ldr     x0, =last_ec
    ldr     x0, [x0]
    bl      put_ec
1:  wfi
    b       1b

/* x0 = 64-bit address, printed as 16 hex digits */
put_addr:
    stp     x30, x16, [sp, #-16]!
    stp     x17, x18, [sp, #-16]!
    mov     x16, x0
    mov     w17, #56
1:  lsr     x0, x16, x17
    and     w0, w0, #0xff
    bl      puthex8
    subs    w17, w17, #8
    b.ge    1b
    mov     w0, #'\n'
    bl      putc
    ldp     x17, x18, [sp], #16
    ldp     x30, x16, [sp], #16
    ret

/* ------------------------------------------------------------- strings */
    .section .rodata
s_done:     .asciz "DONE\n"
s_smstart:  .asciz "SMSTART\t"
s_badel:    .asciz "REFUSED-not-EL1\t"
s_outside:  .asciz "REFUSED-fault-outside-slot\t"
    .align 3
semi_exit:  .quad 0x20026, 0

/* ---------------------------------------------------------------- data */
    .section .bss
    .align 12
insn_slot:  .space 4096
last_ec:    .space 8
smstart_ec: .space 8
state_i:    .space 8
state_n:    .space 8
state_row:  .space 8
    .align 12
stack_bot:  .space 65536
stack_top:
