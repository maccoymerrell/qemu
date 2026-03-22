    .text
    .global _start
_start:
    mov $40, %ecx
loop:
    xor %eax, %eax
    cmp %eax, %eax
    je safe_path

fault_path:
    mov $1234, %eax
    xor %edx, %edx
    xor %ebx, %ebx
    div %ebx

safe_path:
    add $1, %eax
    dec %ecx
    jne loop

    mov $60, %eax
    xor %edi, %edi
    syscall
