    .text
    .global _start
_start:
    subq $16, %rsp

    # Unmask x87 divide-by-zero exception (clear mask bit 2 in control word).
    fnstcw (%rsp)
    movzwl (%rsp), %eax
    andw $0xfffb, %ax
    movw %ax, 2(%rsp)
    fldcw 2(%rsp)

    movl $200000, %ecx      # number of branch opportunities
    movl $1, %eax           # branch predicate (always true)

.Lloop:
    testl %eax, %eax
    jne .Lsafe

.Ltrap:
    fld1
    fldz
    fdivp %st, %st(1)
    fstp %st(0)

.Lsafe:
    decl %ecx
    jnz .Lloop

    movl $60, %eax
    xorl %edi, %edi
    syscall
