/*
 * ARC 3 -- is this encoding REACHABLE by a QEMU x86_64 guest AT CPL 0?
 *
 * qemu-x86_64 runs everything at CPL 3, so a #UD from a privileged opcode
 * says "privilege", not "QEMU does not implement it".  Declaring such a row
 * unreachable off a CPL3 signal is exactly the assumption the maintainer
 * refused.  This is the missing measurement: a freestanding long-mode image
 * that boots under qemu-system-x86_64, runs at CPL 0 with paging, SSE and
 * AVX enabled, executes every encoding, and reports the exception vector it
 * took -- 0xFF when the instruction RAN.
 *
 * Output goes to the ISA debug console (port 0xE9) so no driver, no
 * interrupts and no firmware are involved.  Each encoding's hex is written
 * BEFORE it is executed, so an instruction that hangs the machine (a CPL0
 * probe really can execute HLT or reprogram CR0) is attributable to its
 * exact row and can be skipped on the next pass.
 *
 * Author: Maccoy Merrell
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define MB_MAGIC   0x1BADB002
#define MB_FLAGS   0x00010000        /* a.out kludge: QEMU's multiboot loader
                                       * refuses an ELF64 image ("give a 32bit
                                       * one"), and this probe must be linked
                                       * 64-bit, so the load addresses are
                                       * handed over explicitly instead. */
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

    /* zero PML4 and PDPT */
    movl $pml4, %edi
    xorl %eax, %eax
    movl $2048, %ecx
    rep stosb

    /* PML4[0] -> PDPT, PDPT[0] -> PD : identity-map the low 1 GiB, 2 MiB pages */
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
    orl  $0x83, %eax                /* present | rw | PS */
    movl %eax, (%edi,%ecx,8)
    movl $0, 4(%edi,%ecx,8)
    incl %ecx
    cmpl $512, %ecx
    jb   1b

    movl $pml4, %eax
    movl %eax, %cr3

    movl %cr4, %eax
    orl  $(1<<5), %eax              /* PAE */
    orl  $(1<<9), %eax              /* OSFXSR  -- SSE will be exercised */
    orl  $(1<<10), %eax             /* OSXMMEXCPT */
    movl %eax, %cr4

    movl $0xC0000080, %ecx          /* EFER */
    rdmsr
    orl  $(1<<8), %eax              /* LME.  NXE deliberately left clear so */
    wrmsr                           /* every mapped page stays executable.  */

    movl %cr0, %eax
    andl $~(1<<2), %eax             /* clear EM */
    orl  $(1<<1), %eax              /* MP */
    orl  $(1<<31), %eax             /* PG */
    movl %eax, %cr0

    /* CODE32 CONTROL: AAM/AAD are LEGAL in 32-bit mode and illegal in
     * 64-bit mode.  The chk(i64) fix to [0xD4]/[0xD5] must not take the
     * 32-bit forms with it, and no 32-bit user target is built here, so the
     * check rides in the boot path -- executed before long mode, printed
     * after it.  A #UD here has no IDT and triple-faults the machine, which
     * is a loud failure rather than a silent one. */
    movl $0x0305, %eax
    .byte 0xd5, 0x0a                /* aad $10   -> 0x0011 */
    movl %eax, code32_aad
    movl $0x0011, %eax
    .byte 0xd4, 0x0a                /* aam $10   -> 0x0107 */
    movl %eax, code32_aam

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

    /* XCR0 <- exactly what CPUID.0Dh:EAX says this CPU supports, so AVX
     * encodings fail on their own merits rather than on a clear XCR0 bit. */
    movq %cr4, %rax
    orq  $(1<<18), %rax             /* OSXSAVE */
    movq %rax, %cr4
    movl $0xd, %eax
    xorl %ecx, %ecx
    cpuid
    movl %eax, %esi
    movl %edx, %edi
    movl %esi, %eax
    movl %edi, %edx
    xorl %ecx, %ecx
    xsetbv

    call idt_init
    leaq resume_point(%rip), %rax
    movq %rax, resume_ptr(%rip)

    leaq msg_c32(%rip), %rdi
    call print_str
    movzwq code32_aad(%rip), %rdi
    call print_dec
    movl $'/', %edi
    call putc
    movzwq code32_aam(%rip), %rdi
    call print_dec
    movl $'\n', %edi
    call putc

#ifdef ENABLE_LEG
    call enab_stage
#endif

    /* ---------------------------------------------------------- main loop */
    /* The probed instruction may write ANY register, so no loop state is
     * held in one: the cursor and the index live in memory and are reloaded
     * after every probe.  A loop counter in r15 was the first draft and an
     * encoding that wrote r15 would have silently truncated the run. */
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

    /* print the hex of this encoding, then a tab -- BEFORE executing it, so
     * an encoding that hangs the machine names itself in the output */
    movq %rbx, %rdi
    incq %rdi
    movq %rax, %rsi
    call print_hex
    movl $'\t', %edi
    call putc

    /* copy the bytes into the code buffer and append ret */
    leaq codebuf(%rip), %rdi
    movq cursor(%rip), %rsi
    incq %rsi
    movq enclen(%rip), %rcx
    rep movsb
    movb $0xc3, (%rdi)

    movq $0xFF, last_vec(%rip)      /* 0xFF == it ran */
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
    /* tell the harness the run completed, then leave the machine halted */
    leaq msg_done(%rip), %rdi
    call print_str
    movw $0x604, %dx                /* ACPI PM1a_CNT on the pc machine */
    movw $0x2000, %ax
    outw %ax, %dx
2:  hlt
    jmp 2b

#ifdef ENABLE_LEG
/* ------------------------------------------------- the ENABLE-BIT stage */
/*
 * WHY THIS STAGE EXISTS.  The CPL0 leg proves the refusal is not a PRIVILEGE
 * refusal.  It does not prove the refusal is not an ENABLE refusal: an
 * instruction QEMU implements behind CR4.VMXE, EFER.SVME, XCR0 or an
 * IA32_* enable MSR would #UD at CPL 0 exactly the way an unimplemented one
 * does, and the two are indistinguishable from the vector alone.
 *
 * So every architectural enable that could gate any probed encoding is set
 * here BEFORE the encodings run, and each one is PROVEN to have taken by
 * reading the register back.  An enable QEMU REFUSES is a stronger answer
 * than one it accepts -- "QEMU has no such enable" -- and it is recorded
 * with the exception vector the write took, not silently dropped.
 *
 * The table is generated (enabblob.S) so an enable that wedges the machine
 * is skipped by name on the next pass, exactly like an encoding.
 *
 *   ENAB <name> <old> <new> <vector> <took>
 *
 * took==0 with vector==255 means QEMU accepted the write and DISCARDED it
 * (its wrmsr default arm ignores unknown MSRs); took==0 with a vector means
 * QEMU refused the enable outright.  Neither may be scored as "set".
 */
enab_stage:
    movq $0, eidx(%rip)
enab_loop:
    movq eidx(%rip), %rax
    cmpq enab_count(%rip), %rax
    jae  enab_done
    shlq $5, %rax
    leaq enab_blob(%rip), %rcx
    addq %rcx, %rax
    movq %rax, erec(%rip)

    leaq msg_enab(%rip), %rdi
    call print_str
    movq erec(%rip), %rax
    movq 24(%rax), %rdi
    call print_str
    movl $'\t', %edi
    call putc

    movq erec(%rip), %rax
    movq (%rax), %rax
    cmpq $0, %rax
    je   edo_cr4
    cmpq $1, %rax
    je   edo_msror
    cmpq $2, %rax
    je   edo_msrset
    cmpq $3, %rax
    je   edo_xcr0cpuid
    jmp  edo_xcr0

edo_cr4:                                /* a1 = CR4 bit index */
    movq %cr4, %rax
    movq %rax, eold(%rip)
    movq erec(%rip), %r8
    movq 8(%r8), %rcx
    movq $1, %rax
    shlq %cl, %rax
    movq %rax, ebits(%rip)
    movq eold(%rip), %rdi
    orq  %rax, %rdi
    call try_cr4
    movq %rax, evec(%rip)
    movq %cr4, %rax
    movq %rax, enew(%rip)
    jmp  etook_from_bits

edo_msror:                              /* a1 = MSR, a2 = bits to OR in */
    movq erec(%rip), %r8
    movq 16(%r8), %rax
    movq %rax, ebits(%rip)
    movq 8(%r8), %rdi
    call try_rdmsr
    movq emsr_val(%rip), %rax
    movq %rax, eold(%rip)
    movq erec(%rip), %r8
    movq 8(%r8), %rdi
    movq eold(%rip), %rsi
    orq  ebits(%rip), %rsi
    call try_wrmsr
    movq %rax, evec(%rip)
    movq erec(%rip), %r8
    movq 8(%r8), %rdi
    call try_rdmsr
    movq emsr_val(%rip), %rax
    movq %rax, enew(%rip)
    jmp  etook_from_bits

edo_msrset:                             /* a1 = MSR, a2 = value to write */
    movq erec(%rip), %r8
    movq 16(%r8), %rax
    movq %rax, ebits(%rip)
    movq 8(%r8), %rdi
    call try_rdmsr
    movq emsr_val(%rip), %rax
    movq %rax, eold(%rip)
    movq erec(%rip), %r8
    movq 8(%r8), %rdi
    movq 16(%r8), %rsi
    call try_wrmsr
    movq %rax, evec(%rip)
    movq erec(%rip), %r8
    movq 8(%r8), %rdi
    call try_rdmsr
    movq emsr_val(%rip), %rax
    movq %rax, enew(%rip)
    jmp  etook_from_bits

edo_xcr0cpuid:                          /* XCR0 <- every bit CPUID.0Dh names */
    call try_xgetbv
    movq emsr_val(%rip), %rax
    movq %rax, eold(%rip)
    movl $0xd, %eax
    xorl %ecx, %ecx
    cpuid
    movl %eax, %esi
    movl %edx, %edi
    shlq $32, %rdi
    orq  %rsi, %rdi
    movq %rdi, ebits(%rip)
    call try_xsetbv
    movq %rax, evec(%rip)
    call try_xgetbv
    movq emsr_val(%rip), %rax
    movq %rax, enew(%rip)
    jmp  etook_from_bits

edo_xcr0:                               /* a2 = XCR0 bits to OR in */
    call try_xgetbv
    movq emsr_val(%rip), %rax
    movq %rax, eold(%rip)
    movq erec(%rip), %r8
    movq 16(%r8), %rax
    movq %rax, ebits(%rip)
    movq eold(%rip), %rdi
    orq  %rax, %rdi
    call try_xsetbv
    movq %rax, evec(%rip)
    call try_xgetbv
    movq emsr_val(%rip), %rax
    movq %rax, enew(%rip)
    jmp  etook_from_bits

etook_from_bits:
    /* "it took" is a READBACK, never the absence of a fault: QEMU's wrmsr
     * default arm ignores an unknown MSR silently, so a clean vector 255
     * proves nothing on its own. */
    movq enew(%rip), %rax
    andq ebits(%rip), %rax
    cmpq ebits(%rip), %rax
    sete %al
    movzbl %al, %eax
    movq %rax, etook(%rip)

    movq eold(%rip), %rdi
    call print_hex64
    movl $'\t', %edi
    call putc
    movq enew(%rip), %rdi
    call print_hex64
    movl $'\t', %edi
    call putc
    movq evec(%rip), %rdi
    call print_dec
    movl $'\t', %edi
    call putc
    movq etook(%rip), %rdi
    call print_dec
    movl $'\n', %edi
    call putc

    incq eidx(%rip)
    jmp  enab_loop

enab_done:
    leaq msg_enabdone(%rip), %rdi
    call print_str
    ret

/* Each try_* runs ONE architecturally-refusable write with the fault handler
 * pointed at its own resume label, so a #GP is a measurement and not a
 * triple fault.  rax = the vector taken, 0xFF when the write completed. */
try_cr4:                                /* rdi = new CR4 */
    movq %rsp, saved_rsp(%rip)
    leaq 1f(%rip), %rax
    movq %rax, resume_ptr(%rip)
    movq $0xFF, last_vec(%rip)
    movq %rdi, %cr4
1:  movq saved_rsp(%rip), %rsp
    movq last_vec(%rip), %rax
    ret

try_rdmsr:                              /* rdi = MSR -> emsr_val */
    movq %rsp, saved_rsp(%rip)
    leaq 1f(%rip), %rax
    movq %rax, resume_ptr(%rip)
    movq $0xFF, last_vec(%rip)
    movq $0, emsr_val(%rip)
    movl %edi, %ecx
    rdmsr
    shlq $32, %rdx
    orq  %rdx, %rax
    movq %rax, emsr_val(%rip)
1:  movq saved_rsp(%rip), %rsp
    movq last_vec(%rip), %rax
    ret

try_wrmsr:                              /* rdi = MSR, rsi = value */
    movq %rsp, saved_rsp(%rip)
    leaq 1f(%rip), %rax
    movq %rax, resume_ptr(%rip)
    movq $0xFF, last_vec(%rip)
    movl %edi, %ecx
    movq %rsi, %rax
    movq %rsi, %rdx
    shrq $32, %rdx
    wrmsr
1:  movq saved_rsp(%rip), %rsp
    movq last_vec(%rip), %rax
    ret

try_xgetbv:                             /* -> emsr_val */
    movq %rsp, saved_rsp(%rip)
    leaq 1f(%rip), %rax
    movq %rax, resume_ptr(%rip)
    movq $0xFF, last_vec(%rip)
    movq $0, emsr_val(%rip)
    xorl %ecx, %ecx
    xgetbv
    shlq $32, %rdx
    orq  %rdx, %rax
    movq %rax, emsr_val(%rip)
1:  movq saved_rsp(%rip), %rsp
    movq last_vec(%rip), %rax
    ret

try_xsetbv:                             /* rdi = new XCR0 */
    movq %rsp, saved_rsp(%rip)
    leaq 1f(%rip), %rax
    movq %rax, resume_ptr(%rip)
    movq $0xFF, last_vec(%rip)
    movq %rdi, %rax
    movq %rdi, %rdx
    shrq $32, %rdx
    xorl %ecx, %ecx
    xsetbv
1:  movq saved_rsp(%rip), %rsp
    movq last_vec(%rip), %rax
    ret

print_hex64:                            /* rdi = value, 16 digits */
    pushq %rbx
    pushq %r12
    movq %rdi, %rbx
    movq $16, %r12
1:  testq %r12, %r12
    je   2f
    movq %rbx, %rax
    shrq $60, %rax
    leaq hexdigits(%rip), %r11
    movzbl (%r11,%rax), %edi
    call putc
    shlq $4, %rbx
    decq %r12
    jmp  1b
2:  popq %r12
    popq %rbx
    ret
#endif /* ENABLE_LEG */

/* ------------------------------------------------------------------- I/O */
putc:                               /* edi = char */
    movl %edi, %eax
    movw $DEBUGCON, %dx
    outb %al, %dx
    ret

print_str:                          /* rdi = NUL-terminated */
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

print_dec:                          /* rdi = value */
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
    movw %ax, (%r12)                /* offset 15:0 */
    movw $0x08, 2(%r12)             /* selector */
    movb $0, 4(%r12)                /* ist */
    movb $0x8E, 5(%r12)             /* present, DPL0, interrupt gate */
    shrq $16, %rax
    movw %ax, 6(%r12)               /* offset 31:16 */
    shrq $16, %rax
    movl %eax, 8(%r12)              /* offset 63:32 */
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
    .quad 0x00209A0000000000        /* 64-bit code, DPL0 */
    .quad 0x0000920000000000        /* data */
gdt_end:
gdtr:
    .word gdt_end - gdt - 1
    .quad gdt

hexdigits: .ascii "0123456789abcdef"
msg_done:  .asciz "DONE\n"
#ifdef ENABLE_LEG
msg_enab:     .asciz "ENAB\t"
msg_enabdone: .asciz "ENABDONE\n"
#endif
msg_c32:   .asciz "CODE32-AAD/AAM\t"

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
idtr_pad: .skip 6
last_vec:   .skip 8
cursor:     .skip 8
idx:        .skip 8
enclen:     .skip 8
code32_aad: .skip 8
code32_aam: .skip 8
saved_rsp:  .skip 8
resume_ptr: .skip 8
erec:       .skip 8
eidx:       .skip 8
eold:       .skip 8
enew:       .skip 8
ebits:      .skip 8
evec:       .skip 8
etook:      .skip 8
emsr_val:   .skip 8
decbuf:     .skip 32

    .section .rodata
    .align 8
idtr:
    .word 32*16 - 1
    .quad idt
