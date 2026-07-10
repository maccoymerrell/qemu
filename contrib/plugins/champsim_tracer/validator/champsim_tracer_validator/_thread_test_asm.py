"""Hand-written 2-thread asm programs, one per ISA, for the multi-thread
champsim_tracer test.

Each program spawns one child thread via the kernel's `clone` syscall
with `CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | CLONE_FILES | CLONE_FS |
CLONE_SYSVSEM | CLONE_CHILD_CLEARTID`, and both parent and child
execute identical bodies (``iters`` iterations of an atomic increment on
a shared word).  Parent waits for child via a user-space spin on the
`CLONE_CHILD_CLEARTID` target slot (the kernel zeroes it when the
child exits — no `futex` syscall required).

The asm bodies are intentionally minimal: no libc, no startup stub,
fixed-size statically-allocated child stack.  Run-to-completion under
qemu-user is reliable because the kernel honours CLONE_THREAD for
linux-user emulation; both threads make forward progress and the
parent's `exit_group` syscall terminates the process cleanly only
after the child has finished.

Two consumers:

* ``thread_test`` (qemu-user): ``thread_test_asm(isa)`` — both host
  threads are vCPUs, the default 1000 iterations interleave reliably.
* ``thread_test --system``: ``thread_test_asm(isa, marker=True,
  iters=N)`` — the trace marker at ``_start`` opens and ASID-pins the
  window before the clone (both guest threads share the pinned address
  space), the end marker before ``exit_group`` closes it, and a large
  iteration count keeps both threads spinning long enough for the
  guest scheduler to spread them across the ``-smp`` vCPUs.

  On mipsel the system-mode variant drives the vCPU placement itself
  instead of gambling on the guest load balancer: ``_start`` confines
  the process to guest CPU 0 via ``sched_setaffinity`` *before* the
  marker fires (the clone child inherits the mask), so both threads'
  RMW loops deterministically time-share the marker vCPU — the regime
  where an async-excluded guest-thread switch puts two same-ASID
  threads adjacent on one vCPU, which is exactly what the tracer's
  abandoned-window seal handling must survive.  Same-vCPU confinement
  is also the only regime the MIPS pin can see at all: ``EntryHi.ASID``
  is a per-CPU value (Linux allocates each mm an independent ASID per
  CPU), so the pinned value captured at the marker cannot match the
  same process's execution on any other vCPU — a genuine cross-vCPU
  spread assertion is architecturally out of the pin's reach on MIPS.

The trace produced (either mode) must show:
  * one BODY_TAG_REGFILE per contributing thread, before its first entry,
  * BODY_TAG_THREAD_SWITCH records exactly at the tid changes,
  * both threads' entries forming valid control-flow chains
    (``validate_structural`` with ``expected_guest_threads=2``).
"""

from .asm_blocks import (emit_trace_marker, emit_trace_marker_end,
                         emit_entry_jump)

# Per-ISA source templates.  Placeholders:
#   {marker}     — trace start-marker block at _start ("" without --marker)
#   {end_marker} — trace end-marker before the parent's exit_group
#   {iters}      — per-thread loop iteration count (x86/riscv/mips: any
#                  32-bit value; aarch64 materialises via {iters_lo}/
#                  {iters_hi} movz/movk halves)
_THREAD_TEST_TEMPLATE = {
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
{marker}
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
    movq ${iters}, %rcx
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
    movq ${iters}, %rcx
.Lparent_loop:
    lock incq shared_counter(%rip)
    decq %rcx
    jnz .Lparent_loop
.Lwait_child:
    movl child_tid(%rip), %eax
    testl %eax, %eax
    jnz .Lwait_child
{end_marker}
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
{marker}
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
    movz x11, #{iters_lo}
    movk x11, #{iters_hi}, lsl #16
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
    movz x11, #{iters_lo}
    movk x11, #{iters_hi}, lsl #16
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
{end_marker}
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
{marker}
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
    li   t1, {iters}
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
    li   t1, {iters}
.Lparent_loop:
    li   t2, 1
    amoadd.d t3, t2, (t0)
    addi t1, t1, -1
    bnez t1, .Lparent_loop
    la   t4, child_tid
.Lwait_child:
    lw   t5, 0(t4)
    bnez t5, .Lwait_child
{end_marker}
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
cpu0_mask:         .word 1

.section .bss
.align 16
child_stack_buf:   .space 65536
child_stack_top:

.section .text
.globl _start
.type _start, @function
_start:
{affinity_pin}{marker}
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
    li   $t1, {iters}
.Lchild_loop:
    ll   $t2, 0($t0)
    addiu $t2, $t2, 1
    sc   $t2, 0($t0)
    addiu $t1, $t1, -1
{child_yield}    bnez $t1, .Lchild_loop
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
    li   $t1, {iters}
.Lparent_loop:
    ll   $t2, 0($t0)
    addiu $t2, $t2, 1
    sc   $t2, 0($t0)
    addiu $t1, $t1, -1
{parent_yield}    bnez $t1, .Lparent_loop
    nop
    lui  $t3, %hi(child_tid)
    addiu $t3, $t3, %lo(child_tid)
.Lwait_child:
    lw   $t4, 0($t3)
    bnez $t4, .Lwait_child
    nop
{end_marker}
    li   $v0, 4246
    li   $a0, 0
    syscall
    nop
.size parent_body, .-parent_body
""",
}


# mipsel system-mode vCPU placement (module docstring): confine the
# process to guest CPU 0 BEFORE the marker fires, so both threads
# deterministically time-share the marker vCPU.  sched_setaffinity(0,
# 4, &mask) is o32 4239; errors are deliberately ignored (a mask
# outside the online set leaves the scheduler's own placement,
# degrading to the old luck-based behavior).
_MIPSEL_AFFINITY_PIN = r"""    # Confine to CPU 0 (pre-marker; the clone child inherits the mask)
    li   $v0, 4239
    li   $a0, 0
    li   $a1, 4
    lui  $a2, %hi(cpu0_mask)
    addiu $a2, $a2, %lo(cpu0_mask)
    syscall
    nop
"""

# Periodic sched_yield (o32 4162) inside each RMW loop, every 4096
# iterations: with the guest virtual clock frozen across the tracer's
# per-TB instrumentation, timer ticks land so rarely inside a marker
# window that two same-CPU spinners may never preempt each other — the
# window can close with only one thread's flow in the trace.  The yield
# hands the CPU over deterministically (a traced synchronous syscall,
# not an excluded async switch, so it does not stand in for the
# timer-preemption regime — those switches still occur on top whenever
# a tick does land).  MIPS syscalls do NOT preserve the caller-saved
# $t registers (observed: the loop's $t0 came back 0 through a yield
# that context-switched, faulting the next ll at address 0), so the
# loop cursor and counter round-trip the call in callee-saved $s0/$s1,
# which the kernel keeps in the switched thread context.
_MIPSEL_LOOP_YIELD = r"""    andi $t7, $t1, 0xfff
    bnez $t7, {loop_label}
    nop
    move $s0, $t0
    move $s1, $t1
    li   $v0, 4162
    syscall
    nop
    move $t0, $s0
    move $t1, $s1
    bnez $t1, {loop_label}
    nop
"""


def thread_test_asm(isa: str, marker: bool = False,
                    iters: int = 1000) -> str:
    """Render the 2-thread test program for @isa.

    @marker prepends the trace start marker at ``_start`` (followed by
    a jump to a fresh label, so the clone syscall lives in a separate
    TB from the marker's — the marker TB is the one-TB lossy
    segment-open boundary) and places the end marker right before the
    parent's ``exit_group``.  @iters scales both threads' loop counts.
    On mipsel, @marker also enables the pre-marker CPU-0 pin (see the
    module docstring); user-mode renders stay affinity-free — under
    qemu-user the syscall would target HOST CPUs.
    """
    if isa not in _THREAD_TEST_TEMPLATE:
        raise KeyError(f"no thread-test template for ISA {isa!r}")
    mk = ""
    endmk = ""
    if marker:
        mk = "\n".join(emit_trace_marker(isa)
                       + emit_entry_jump(isa, "cst_thread_main")
                       + ["cst_thread_main:"])
        endmk = "\n".join(emit_trace_marker_end(isa))
    aff_pin = ""
    child_yield = ""
    parent_yield = ""
    if marker and isa == "mipsel":
        aff_pin = _MIPSEL_AFFINITY_PIN
        child_yield = _MIPSEL_LOOP_YIELD.format(loop_label=".Lchild_loop")
        parent_yield = _MIPSEL_LOOP_YIELD.format(loop_label=".Lparent_loop")
    return _THREAD_TEST_TEMPLATE[isa].format(
        marker=mk, end_marker=endmk, iters=int(iters),
        iters_lo=f"0x{int(iters) & 0xffff:x}",
        iters_hi=f"0x{(int(iters) >> 16) & 0xffff:x}",
        affinity_pin=aff_pin,
        child_yield=child_yield, parent_yield=parent_yield)


# Back-compat view for callers that only need the default user-mode
# program text (no marker, 1000 iterations).
THREAD_TEST_ASM = {isa: thread_test_asm(isa)
                   for isa in _THREAD_TEST_TEMPLATE}
