/*
 * ARC 3 -- does ANY XCR0 configuration QEMU accepts make an EVEX encoding
 * decode?
 *
 * sysprobe.S answers "what exception vector does this encoding take at CPL 0".
 * It sets XCR0 to exactly what CPUID.0Dh advertises, which is the right
 * default but leaves the maintainer's question open: AVX-512 state
 * (opmask, ZMM_Hi256, Hi16_ZMM) and AMX state (XTILECFG, XTILEDATA) are
 * ENABLED THROUGH XCR0, so a row excused as unreachable is only honest if
 * turning those bits on has been TRIED and shown not to help.
 *
 * This probe adds that leg.  Before the encoding sweep it walks a table of
 * XCR0 masks -- each one attempted with a fault-protected XSETBV and the
 * vector reported -- so the output states, from the guest, exactly which
 * state components QEMU will let a guest enable.  It then pins XCR0 to the
 * WIDEST mask that was accepted and executes the encodings under it.
 *
 * Everything else follows sysprobe.S: long mode, CPL 0, paging, an IDT that
 * reports the vector, ISA debug console at port 0xE9, hex printed BEFORE
 * execution so an encoding that wedges the machine names itself.  The fault
 * resume target is a variable here rather than a fixed label, because the
 * XSETBV attempts and the encoding sweep resume in different places.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define MB_MAGIC   0x1BADB002
#define MB_FLAGS   0x00010000
#define DEBUGCON   0xE9

    .section .multiboot, "a"
    .align 8
mb_header:
    .long MB_MAGIC
    .long MB_FLAGS
    .long -(MB_MAGIC + MB_FLAGS)
    .long mb_header
    .long __load_start
    .long __load_end
    .long __bss_end
    .long _start

/* ------------------------------------------------------------- 32-bit boot */
    .section .text
    .code32
    .globl _start
_start:
    cli
    movl $stack_top, %esp

    movl $pml4, %edi
    xorl %eax, %eax
    movl $2048, %ecx
    rep stosb

    movl $pdpt, %eax
    orl  $0x3, %eax
    movl %eax, pml4
    movl $pd, %eax
    orl  $0x3, %eax
    movl %eax, pdpt

    movl $pd, %edi
    xorl %ecx, %ecx
1:  movl %ecx, %eax
    shll $21, %eax
    orl  $0x83, %eax
    movl %eax, (%edi,%ecx,8)
    movl $0, 4(%edi,%ecx,8)
    incl %ecx
    cmpl $512, %ecx
    jb   1b

    movl $pml4, %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl  $(1<<5), %eax              /* PAE */
    orl  $(1<<9), %eax              /* OSFXSR */
    orl  $(1<<10), %eax             /* OSXMMEXCPT */
    movl %eax, %cr4

    movl $0xC0000080, %ecx          /* EFER */
    rdmsr
    orl  $(1<<8), %eax              /* LME */
    orl  $(1<<11), %eax             /* NXE */
    wrmsr

    movl %cr0, %eax
    andl $~(1<<2), %eax             /* clear EM */
    orl  $(1<<1), %eax              /* MP */
    orl  $(1<<31), %eax             /* PG */
    movl %eax, %cr0

    /* ---- the running negative control ------------------------------
     * 0x62 and 0xD5 are refused in long mode by an unconditional MODE
     * check, not by a feature gate.  The way to SHOW that is to execute
     * the same first bytes where the check does not apply: in 32-bit
     * protected mode 0x62 IS the BOUND opcode and 0xD5 IS AAD, and QEMU
     * runs both.  No IDT exists yet, so a refusal here triple-faults and
     * the run never reaches DONE -- reaching DONE with these flags set is
     * the proof that the bytes are not universally rejected and that the
     * long-mode #UD is the CODE64 check and nothing else.
     */
    movl $0, bnd_lo
    movl $0x7fffffff, bnd_hi
    movl $bnd_lo, %esi
    movl $1, %eax
    .byte 0x62, 0x06                /* bound %eax, (%esi)  -- in range */
    movl $1, code32_bound

    movl $0x0305, %eax
    .byte 0xd5, 0x0a                /* aad $10   -> 0x0011 */
    movl %eax, code32_aad

    lgdt gdtr
    ljmp $0x08, $long_entry

/* ------------------------------------------------------------- 64-bit body */
    .code64
long_entry:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs
    movq $stack_top, %rsp

    movq %cr4, %rax
    orq  $(1<<18), %rax             /* OSXSAVE */
    movq %rax, %cr4

    call idt_init

    /* ---- the 32-bit control, reported from long mode ------------------ */
    leaq msg_c32(%rip), %rdi
    call print_str
    movl code32_bound(%rip), %edi
    call print_dec
    movl $'/', %edi
    call putc
    movzwq code32_aad(%rip), %rdi
    call print_dec
    movl $'\n', %edi
    call putc

    /* ---- report what CPUID.0Dh:0 says this CPU offers as XCR0 --------- */
    movl $0xd, %eax
    xorl %ecx, %ecx
    cpuid
    movl %eax, cpuid_xcr0_lo(%rip)
    movl %edx, cpuid_xcr0_hi(%rip)
    movl %edx, %ecx
    shlq $32, %rcx
    movl %eax, %eax
    orq  %rax, %rcx
    movq %rcx, xcr0_offered_slot(%rip)

    leaq msg_offer(%rip), %rdi
    call print_str
    movl cpuid_xcr0_hi(%rip), %eax
    shlq $32, %rax
    movl cpuid_xcr0_lo(%rip), %ecx
    orq  %rcx, %rax
    movq %rax, %rdi
    call print_qhex
    movl $'\n', %edi
    call putc

    /* ---- try every XCR0 mask in the table, report the vector ---------- */
    movq $0, widest(%rip)
    leaq xcr0_masks(%rip), %rbx
    movq %rbx, xcursor(%rip)
1:  movq xcursor(%rip), %rbx
    movq (%rbx), %rax
    cmpq $-1, %rax                  /* table terminator */
    je   2f
    addq $8, %rbx
    movq %rbx, xcursor(%rip)

    movq %rax, trymask(%rip)
    leaq msg_xcr0(%rip), %rdi
    call print_str
    movq trymask(%rip), %rdi
    call print_qhex
    movl $'\t', %edi
    call putc

    movq trymask(%rip), %rax
    call try_xsetbv
    movq last_vec(%rip), %rdi
    call print_dec
    movl $'\t', %edi
    call putc

    /* read XCR0 back, so an accepted-but-truncated set is visible */
    call read_xcr0
    movq %rax, %rdi
    call print_qhex
    movl $'\n', %edi
    call putc

    /* remember the widest mask that was actually accepted */
    cmpq $0xFF, last_vec(%rip)
    jne  1b
    call read_xcr0
    movq %rax, %rcx
    movq widest(%rip), %rdx
    cmpq %rdx, %rcx
    jbe  1b
    movq %rcx, widest(%rip)
    jmp  1b

2:  /* pin XCR0 to the widest accepted mask and say so */
    movq widest(%rip), %rax
    call try_xsetbv
    leaq msg_pinned(%rip), %rdi
    call print_str
    call read_xcr0
    movq %rax, %rdi
    call print_qhex
    movl $'\t', %edi
    call putc
    movq %cr4, %rdi
    call print_qhex
    movl $'\n', %edi
    call putc

    /* ---------------------------------------------------------- main loop */
    leaq resume_point(%rip), %rax
    movq %rax, resume_ptr(%rip)
    leaq enc_blob(%rip), %rax
    movq %rax, cursor(%rip)
    movq $0, idx(%rip)

next_enc:
    movq idx(%rip), %rax
    cmpq enc_count(%rip), %rax
    jae  done

    movq cursor(%rip), %rbx
    movzbq (%rbx), %rax
    movq %rax, enclen(%rip)

    movq %rbx, %rdi
    incq %rdi
    movq %rax, %rsi
    call print_hex
    movl $'\t', %edi
    call putc

    leaq codebuf(%rip), %rdi
    movq cursor(%rip), %rsi
    incq %rsi
    movq enclen(%rip), %rcx
    rep movsb
    movb $0xc3, (%rdi)

    leaq resume_point(%rip), %rax
    movq %rax, resume_ptr(%rip)
    movq $0xFF, last_vec(%rip)
    movq %rsp, saved_rsp(%rip)
    leaq scratch(%rip), %rax
    movq %rax, %rbx
    movq %rax, %rcx
    movq %rax, %rdx
    movq %rax, %rsi
    movq %rax, %rdi
    movq %rax, %rbp
    movq %rax, %r8
    movq %rax, %r9
    movq %rax, %r11
    movq %rax, %r12
    movq %rax, %r13
    movq %rax, %r14
    movq %rax, %r15
    leaq codebuf(%rip), %r10
    callq *%r10
resume_point:
    movq saved_rsp(%rip), %rsp

    movq last_vec(%rip), %rdi
    call print_dec
    movl $'\n', %edi
    call putc

    movq cursor(%rip), %rax
    addq $16, %rax
    movq %rax, cursor(%rip)
    incq idx(%rip)
    jmp  next_enc

done:
    leaq msg_done(%rip), %rdi
    call print_str
    movw $0x604, %dx
    movw $0x2000, %ax
    outw %ax, %dx
2:  hlt
    jmp 2b

/* ------------------------------------------------- fault-protected XSETBV */
try_xsetbv:                         /* rax = mask; last_vec = 0xFF if taken */
    movq %rsp, saved_rsp(%rip)
    leaq xsetbv_resume(%rip), %rcx
    movq %rcx, resume_ptr(%rip)
    movq $0xFF, last_vec(%rip)
    movq %rax, %rdx
    shrq $32, %rdx
    movl %eax, %eax
    xorl %ecx, %ecx
    xsetbv
xsetbv_resume:
    movq saved_rsp(%rip), %rsp
    ret

read_xcr0:                          /* -> rax */
    xorl %ecx, %ecx
    xgetbv
    shlq $32, %rdx
    movl %eax, %eax
    orq  %rdx, %rax
    ret

/* ------------------------------------------------------------------- I/O */
putc:
    movl %edi, %eax
    movw $DEBUGCON, %dx
    outb %al, %dx
    ret

print_str:
    pushq %rbx
    movq %rdi, %rbx
1:  movzbl (%rbx), %edi
    testl %edi, %edi
    je   2f
    call putc
    incq %rbx
    jmp  1b
2:  popq %rbx
    ret

print_hex:                          /* rdi = bytes, rsi = count */
    pushq %rbx
    pushq %r12
    movq %rdi, %rbx
    movq %rsi, %r12
1:  testq %r12, %r12
    je   2f
    leaq hexdigits(%rip), %r11
    movzbl (%rbx), %eax
    shrl $4, %eax
    movzbl (%r11,%rax), %edi
    call putc
    leaq hexdigits(%rip), %r11
    movzbl (%rbx), %eax
    andl $0xf, %eax
    movzbl (%r11,%rax), %edi
    call putc
    incq %rbx
    decq %r12
    jmp  1b
2:  popq %r12
    popq %rbx
    ret

print_qhex:                         /* rdi = 64-bit value, 16 nybbles */
    pushq %rbx
    pushq %r12
    movq %rdi, %rbx
    movq $60, %r12
1:  movq %rbx, %rax
    movq %r12, %rcx
    shrq %cl, %rax
    andq $0xf, %rax
    leaq hexdigits(%rip), %r11
    movzbl (%r11,%rax), %edi
    call putc
    subq $4, %r12
    jns  1b
    popq %r12
    popq %rbx
    ret

print_dec:
    pushq %rbx
    movq %rdi, %rax
    leaq decbuf(%rip), %rbx
    addq $23, %rbx
    movb $0, (%rbx)
    movq $10, %rcx
1:  decq %rbx
    xorq %rdx, %rdx
    divq %rcx
    addb $'0', %dl
    movb %dl, (%rbx)
    testq %rax, %rax
    jne  1b
    movq %rbx, %rdi
    call print_str
    popq %rbx
    ret

/* --------------------------------------------------------------- the IDT */
idt_init:
    pushq %rbx
    pushq %r12
    leaq isr_table(%rip), %rbx
    leaq idt(%rip), %r12
    xorq %rcx, %rcx
1:  cmpq $32, %rcx
    jae  2f
    movq (%rbx,%rcx,8), %rax
    movw %ax, (%r12)
    movw $0x08, 2(%r12)
    movb $0, 4(%r12)
    movb $0x8E, 5(%r12)
    shrq $16, %rax
    movw %ax, 6(%r12)
    shrq $16, %rax
    movl %eax, 8(%r12)
    movl $0, 12(%r12)
    addq $16, %r12
    incq %rcx
    jmp  1b
2:  lidt idtr(%rip)
    popq %r12
    popq %rbx
    ret

isr_common:
    /* stack: [vec][err][rip][cs][rflags][rsp][ss] */
    movq (%rsp), %rax
    movq %rax, last_vec(%rip)
    movq resume_ptr(%rip), %rax
    movq %rax, 16(%rsp)
    movq saved_rsp(%rip), %rax
    movq %rax, 40(%rsp)
    movq $0x2, 32(%rsp)
    movq $0x08, 24(%rsp)
    addq $16, %rsp
    iretq

.macro ISRNE v
isr\v:  pushq $0
        pushq $\v
        jmp isr_common
.endm
.macro ISRE v
isr\v:  pushq $\v
        jmp isr_common
.endm

    .irp v, 0,1,2,3,4,5,6,7,9,15,16,18,19,20,22,23,24,25,26,27,28,31
    ISRNE \v
    .endr
    .irp v, 8,10,11,12,13,14,17,21,29,30
    ISRE \v
    .endr

/* ------------------------------------------------------------------- data */
    .section .rodata
    .align 16
gdt:
    .quad 0
    .quad 0x00209A0000000000
    .quad 0x0000920000000000
gdt_end:
gdtr:
    .word gdt_end - gdt - 1
    .quad gdt

hexdigits: .ascii "0123456789abcdef"
msg_done:   .asciz "DONE\n"
msg_offer:  .asciz "CPUID0D-XCR0-OFFERED\t"
msg_xcr0:   .asciz "XCR0-TRY\t"
msg_pinned: .asciz "XCR0-PINNED\t"
msg_c32:    .asciz "CODE32-BOUND/AAD\t"

    .section .data
    .align 8
xcr0_masks:
    .quad 0x0000000000000003        /* FP|SSE                              */
    .quad 0x0000000000000007        /* +YMM                                */
    .quad 0x0000000000000023        /* FP|SSE|OPMASK            (AVX-512)  */
    .quad 0x0000000000000047        /* +ZMM_Hi256 without OPMASK           */
    .quad 0x0000000000000067        /* FP|SSE|YMM|OPMASK|ZMM_Hi256         */
    .quad 0x00000000000000e7        /* +Hi16_ZMM  -- full AVX-512 state    */
    .quad 0x00000000000002e7        /* +PKRU                               */
    .quad 0x00000000000600e7        /* +XTILECFG|XTILEDATA   (AMX)         */
    .quad 0x00000000000606e7        /* + the AVX-512/AMX set with MPX      */
    .quad 0x00000000ffffffff        /* every bit in the low word           */
xcr0_offered_slot:
    .quad 0                         /* filled at runtime from CPUID.0Dh:0  */
    .quad 0xffffffffffffffff        /* terminator (and an impossible mask) */

    .section .rodata

    .align 8
isr_table:
    .irp v, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    .quad isr\v
    .endr

    .section .bss
    .align 4096
pml4:     .skip 4096
pdpt:     .skip 4096
pd:       .skip 4096
codebuf:  .skip 4096
scratch:  .skip 8192
stack:    .skip 65536
stack_top:
    .align 16
idt:      .skip 32*16
last_vec:       .skip 8
cursor:         .skip 8
xcursor:        .skip 8
idx:            .skip 8
enclen:         .skip 8
saved_rsp:      .skip 8
resume_ptr:     .skip 8
trymask:        .skip 8
widest:         .skip 8
cpuid_xcr0_lo:  .skip 8
cpuid_xcr0_hi:  .skip 8
code32_bound:   .skip 8
code32_aad:     .skip 8
bnd_lo:         .skip 4
bnd_hi:         .skip 4
decbuf:         .skip 32

    .section .rodata
    .align 8
idtr:
    .word 32*16 - 1
    .quad idt
