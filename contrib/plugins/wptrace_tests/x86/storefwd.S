.global _start

.section .bss
.align 16
idx_slot:
    .long 0
.align 16
table:
    .skip 2097152

.section .text
_start:
    xor %r10d, %r10d
    xor %edx, %edx
    mov $5000, %ecx

loop_top:
    cmp $0, %edx
    je correct_path

wrong_path:
    mov %r10d, idx_slot(%rip)
    mov idx_slot(%rip), %eax
    lea table(%rip), %rdi
    mov %eax, (%rdi,%rax,4)
    mov (%rdi,%rax,4), %r8d
    add $2, %r10d
    cmp $64, %r10d
    jb wrong_path
    jmp loop_tail

correct_path:
    mov %r10d, idx_slot(%rip)
    mov idx_slot(%rip), %eax
    lea table(%rip), %rdi
    mov %eax, (%rdi,%rax,4)
    mov (%rdi,%rax,4), %r8d
    add $1, %r10d

loop_tail:
    dec %ecx
    jne loop_top

    mov $60, %eax
    xor %edi, %edi
    syscall
