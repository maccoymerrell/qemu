"""Hand-written 2-thread asm programs, one per ISA, for the multi-thread
champsim_tracer test.

Each program spawns one child thread via the kernel's `clone` syscall
with `CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FILES | CLONE_FS |
CLONE_SYSVSEM | CLONE_CHILD_CLEARTID`, and both parent and child
execute identical bodies (1000 iterations of an atomic increment on a
shared word).  Parent waits for child via a user-space spin on the
`CLONE_CHILD_CLEARTID` target slot (the kernel zeroes it when the
child exits — no `futex` syscall required).

The asm bodies are intentionally minimal: no libc, no startup stub,
fixed-size statically-allocated child stack.  Run-to-completion under
qemu-user is reliable because the kernel honours CLONE_THREAD for
linux-user emulation; both threads make forward progress and the
parent's `exit_group` syscall terminates the process cleanly only
after the child has finished.

The validator's `thread_test` command uses these strings as the asm
source.  Each ISA's body is written so the trace produces:
  * 2 BODY_TAG_REGFILE records (one per thread),
  * at least one BODY_TAG_THREAD_SWITCH record (thread interleaving),
  * matching atomic_count / wp_events / iframe / encoding-map invariants
    that `validate_structural` checks.
"""

THREAD_TEST_ASM = {
    "x86_64": r"""
.section .data
.align 16
shared_counter:    .quad 0
child_tid:         .long 1

.section .bss
.align 16
child_stack_buf:   .skip 65536
child_stack_top:

.section .text
.globl _start
.type _start, @function
_start:
    movq $56, %rax
    movq $0x250F00, %rdi
    leaq child_stack_top(%rip), %rsi
    xorq %rdx, %rdx
    leaq child_tid(%rip), %r10
    xorq %r8, %r8
    syscall
    testq %rax, %rax
    jnz parent_body
.size _start, .-_start

.globl child_body
.type child_body, @function
child_body:
    movq $1000, %rcx
.Lchild_loop:
    lock incq shared_counter(%rip)
    decq %rcx
    jnz .Lchild_loop
    movq $60, %rax
    xorq %rdi, %rdi
    syscall
.size child_body, .-child_body

.globl parent_body
.type parent_body, @function
parent_body:
    movq $1000, %rcx
.Lparent_loop:
    lock incq shared_counter(%rip)
    decq %rcx
    jnz .Lparent_loop
.Lwait_child:
    movl child_tid(%rip), %eax
    testl %eax, %eax
    jnz .Lwait_child
    movq $231, %rax
    xorq %rdi, %rdi
    syscall
.size parent_body, .-parent_body
""",

    "aarch64": r"""
.section .data
.align 8
shared_counter:    .quad 0
child_tid:         .word 1

.section .bss
.align 16
child_stack_buf:   .skip 65536
child_stack_top:

.section .text
.globl _start
.type _start, @function
_start:
    // x8 = SYS_clone (220), x0=flags, x1=stack, x2=ptid, x3=tls, x4=ctid
    mov  x8, #220
    mov  x0, #0x0F00
    movk x0, #0x25, lsl #16
    adrp x1, child_stack_top
    add  x1, x1, :lo12:child_stack_top
    mov  x2, xzr
    mov  x3, xzr
    adrp x4, child_tid
    add  x4, x4, :lo12:child_tid
    svc  #0
    cbnz x0, parent_body
.size _start, .-_start

.globl child_body
.type child_body, @function
child_body:
    adrp x10, shared_counter
    add  x10, x10, :lo12:shared_counter
    mov  x11, #1000
.Lchild_loop:
    mov  x12, #1
    .arch armv8.1-a
    ldadd x12, x13, [x10]
    .arch armv8-a
    sub  x11, x11, #1
    cbnz x11, .Lchild_loop
    mov  x8, #93
    mov  x0, #0
    svc  #0
.size child_body, .-child_body

.globl parent_body
.type parent_body, @function
parent_body:
    adrp x10, shared_counter
    add  x10, x10, :lo12:shared_counter
    mov  x11, #1000
.Lparent_loop:
    mov  x12, #1
    .arch armv8.1-a
    ldadd x12, x13, [x10]
    .arch armv8-a
    sub  x11, x11, #1
    cbnz x11, .Lparent_loop
    adrp x14, child_tid
    add  x14, x14, :lo12:child_tid
.Lwait_child:
    ldr  w15, [x14]
    cbnz w15, .Lwait_child
    mov  x8, #94
    mov  x0, #0
    svc  #0
.size parent_body, .-parent_body
""",

    "riscv64": r"""
.section .data
.align 8
shared_counter:    .dword 0
child_tid:         .word 1

.section .bss
.align 16
child_stack_buf:   .skip 65536
child_stack_top:

.section .text
.globl _start
.type _start, @function
_start:
    li   a7, 220
    li   a0, 0x250F00
    la   a1, child_stack_top
    li   a2, 0
    li   a3, 0
    la   a4, child_tid
    ecall
    bnez a0, parent_body
.size _start, .-_start

.globl child_body
.type child_body, @function
child_body:
    la   t0, shared_counter
    li   t1, 1000
.Lchild_loop:
    li   t2, 1
    amoadd.d t3, t2, (t0)
    addi t1, t1, -1
    bnez t1, .Lchild_loop
    li   a7, 93
    li   a0, 0
    ecall
.size child_body, .-child_body

.globl parent_body
.type parent_body, @function
parent_body:
    la   t0, shared_counter
    li   t1, 1000
.Lparent_loop:
    li   t2, 1
    amoadd.d t3, t2, (t0)
    addi t1, t1, -1
    bnez t1, .Lparent_loop
    la   t4, child_tid
.Lwait_child:
    lw   t5, 0(t4)
    bnez t5, .Lwait_child
    li   a7, 94
    li   a0, 0
    ecall
.size parent_body, .-parent_body
""",

    "mipsel": r"""
.set noreorder
.section .data
.align 4
shared_counter:    .word 0
                   .word 0
child_tid:         .word 1

.section .bss
.align 16
child_stack_buf:   .space 65536
child_stack_top:

.section .text
.globl _start
.type _start, @function
_start:
    # SYS_clone = 4120; o32 abi: $a0 flags, $a1 stack, $a2 ptid, $a3 tls,
    # ctid passed on stack at sp+16
    li   $v0, 4120
    li   $a0, 0x250F00
    lui  $a1, %hi(child_stack_top)
    addiu $a1, $a1, %lo(child_stack_top)
    li   $a2, 0
    li   $a3, 0
    addiu $sp, $sp, -32
    lui  $t0, %hi(child_tid)
    addiu $t0, $t0, %lo(child_tid)
    sw   $t0, 16($sp)
    syscall
    addiu $sp, $sp, 32
    nop
    bnez $v0, parent_body
    nop
.size _start, .-_start

.globl child_body
.type child_body, @function
child_body:
    lui  $t0, %hi(shared_counter)
    addiu $t0, $t0, %lo(shared_counter)
    li   $t1, 1000
.Lchild_loop:
    ll   $t2, 0($t0)
    addiu $t2, $t2, 1
    sc   $t2, 0($t0)
    addiu $t1, $t1, -1
    bnez $t1, .Lchild_loop
    nop
    li   $v0, 4001
    li   $a0, 0
    syscall
    nop
.size child_body, .-child_body

.globl parent_body
.type parent_body, @function
parent_body:
    lui  $t0, %hi(shared_counter)
    addiu $t0, $t0, %lo(shared_counter)
    li   $t1, 1000
.Lparent_loop:
    ll   $t2, 0($t0)
    addiu $t2, $t2, 1
    sc   $t2, 0($t0)
    addiu $t1, $t1, -1
    bnez $t1, .Lparent_loop
    nop
    lui  $t3, %hi(child_tid)
    addiu $t3, $t3, %lo(child_tid)
.Lwait_child:
    lw   $t4, 0($t3)
    bnez $t4, .Lwait_child
    nop
    li   $v0, 4246
    li   $a0, 0
    syscall
    nop
.size parent_body, .-parent_body
""",
}
