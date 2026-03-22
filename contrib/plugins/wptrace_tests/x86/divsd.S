    .section .rodata
one_d:
    .quad 0x3ff0000000000000
zero_d:
    .quad 0x0000000000000000

    .text
    .global _start
_start:
    movl $500000, %esi
    movl $1, %ebx

.Lloop:
    testl %ebx, %ebx
    jne .Lsafe

.Ltrap:
    # Ensure mnemonic is exactly divsd for FP_DIV classification.
    movsd one_d(%rip), %xmm0
    movsd zero_d(%rip), %xmm1
    divsd %xmm1, %xmm0

    # Deterministic trap so WP BB is marked as exception.
    xorl %edx, %edx
    movl $1, %eax
    xorl %ecx, %ecx
    divl %ecx

.Lsafe:
    decl %esi
    jnz .Lloop

    movl $60, %eax
    xorl %edi, %edi
    syscall
