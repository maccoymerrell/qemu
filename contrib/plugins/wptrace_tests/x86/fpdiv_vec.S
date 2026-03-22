.global _start
.text
_start:
    sub $16, %rsp

    stmxcsr (%rsp)
    mov (%rsp), %eax
    and $0xfffffdff, %eax
    mov %eax, 4(%rsp)
    ldmxcsr 4(%rsp)

    mov $200000, %ecx
    mov $1, %eax

1:
    test %eax, %eax
    jne 2f

    mov $0x3f800000, %edx
    movd %edx, %xmm0
    xorps %xmm1, %xmm1
    divss %xmm1, %xmm0

2:
    dec %ecx
    jne 1b

    mov $0x3f800000, %edx
    movd %edx, %xmm0
    xorps %xmm1, %xmm1
    divss %xmm1, %xmm0

    mov $60, %eax
    xor %edi, %edi
    syscall
