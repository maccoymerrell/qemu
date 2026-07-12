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
{extra_data}
.section .bss
.align 16
child_stack_buf:   .skip 65536
child_stack_top:

.section .text
.globl _start
.type _start, @function
_start:
{tp_parent}{marker}
    movq $56, %rax
    movq ${clone_flags}, %rdi
    leaq child_stack_top(%rip), %rsi
    xorq %rdx, %rdx
    leaq child_tid(%rip), %r10
    {child_tls}
    syscall
    testq %rax, %rax
    jnz parent_body
.size _start, .-_start

.globl child_body
.type child_body, @function
child_body:
{start_signal}    movq ${iters}, %rcx
.Lchild_loop:
    lock incq shared_counter(%rip)
    decq %rcx
{child_yield}    jnz .Lchild_loop
    movq $60, %rax
    xorq %rdi, %rdi
    syscall
.size child_body, .-child_body

.globl parent_body
.type parent_body, @function
parent_body:
{start_wait}    movq ${iters}, %rcx
.Lparent_loop:
    lock incq shared_counter(%rip)
    decq %rcx
{parent_yield}    jnz .Lparent_loop
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
{extra_data}
.section .bss
.align 16
child_stack_buf:   .skip 65536
child_stack_top:

.section .text
.globl _start
.type _start, @function
_start:
{tp_parent}{marker}
    // x8 = SYS_clone (220), x0=flags, x1=stack, x2=ptid, x3=tls, x4=ctid
    mov  x8, #220
    mov  x0, #0x0F00
    movk x0, #{clone_flags_hi}, lsl #16
    adrp x1, child_stack_top
    add  x1, x1, :lo12:child_stack_top
    mov  x2, xzr
    {child_tls}
    adrp x4, child_tid
    add  x4, x4, :lo12:child_tid
    svc  #0
    cbnz x0, parent_body
.size _start, .-_start

.globl child_body
.type child_body, @function
child_body:
{start_signal}    adrp x10, shared_counter
    add  x10, x10, :lo12:shared_counter
    movz x11, #{iters_lo}
    movk x11, #{iters_hi}, lsl #16
.Lchild_loop:
    mov  x12, #1
    .arch armv8.1-a
    ldadd x12, x13, [x10]
    .arch armv8-a
    sub  x11, x11, #1
{child_yield}    cbnz x11, .Lchild_loop
    mov  x8, #93
    mov  x0, #0
    svc  #0
.size child_body, .-child_body

.globl parent_body
.type parent_body, @function
parent_body:
{start_wait}    adrp x10, shared_counter
    add  x10, x10, :lo12:shared_counter
    movz x11, #{iters_lo}
    movk x11, #{iters_hi}, lsl #16
.Lparent_loop:
    mov  x12, #1
    .arch armv8.1-a
    ldadd x12, x13, [x10]
    .arch armv8-a
    sub  x11, x11, #1
{parent_yield}    cbnz x11, .Lparent_loop
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
{extra_data}
.section .bss
.align 16
child_stack_buf:   .skip 65536
child_stack_top:

.section .text
.globl _start
.type _start, @function
_start:
{tp_parent}{marker}
    li   a7, 220
    li   a0, {clone_flags}
    la   a1, child_stack_top
    li   a2, 0
    li   a3, {child_tls}
    la   a4, child_tid
    ecall
    bnez a0, parent_body
.size _start, .-_start

.globl child_body
.type child_body, @function
child_body:
{start_signal}    la   t0, shared_counter
    li   t1, {iters}
.Lchild_loop:
    li   t2, 1
    amoadd.d t3, t2, (t0)
    addi t1, t1, -1
{child_yield}    bnez t1, .Lchild_loop
    li   a7, 93
    li   a0, 0
    ecall
.size child_body, .-child_body

.globl parent_body
.type parent_body, @function
parent_body:
{start_wait}    la   t0, shared_counter
    li   t1, {iters}
.Lparent_loop:
    li   t2, 1
    amoadd.d t3, t2, (t0)
    addi t1, t1, -1
{parent_yield}    bnez t1, .Lparent_loop
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
{churn_data}{extra_data}
.section .bss
.align 16
child_stack_buf:   .space 65536
child_stack_top:

.section .text
.globl _start
.type _start, @function
_start:
{affinity_pin}{tp_parent}{marker}
    # SYS_clone = 4120; o32 abi: $a0 flags, $a1 stack, $a2 ptid, $a3 tls,
    # ctid passed on stack at sp+16
    li   $v0, 4120
    li   $a0, {clone_flags}
    lui  $a1, %hi(child_stack_top)
    addiu $a1, $a1, %lo(child_stack_top)
    li   $a2, 0
    li   $a3, {child_tls}
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
{start_signal}    lui  $t0, %hi(shared_counter)
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
{start_wait}    lui  $t0, %hi(shared_counter)
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

# mipsel guest-side cross-vCPU MIGRATION forcing (--migrate-churn).  The
# yield-only migrate regime lets each guest thread settle on its own vCPU and
# stay there (2 threads on -smp 2 is a balanced runqueue the scheduler never
# rebalances), so the wire shows one tid per vCPU — decoupling the run cannot
# distinguish from thread_id==vCPU.  To WITNESS a tid spanning vCPUs, the
# child deterministically bounces itself between guest CPU 0 and CPU 1 with
# sched_setaffinity every 4096 RMW iterations; the parent stays pinned to
# CPU 0 (its affinity_pin is kept in churn mode) and fires the marker there,
# so the pin is CPU 0's ASID for the shared mm.  On MIPS EntryHi.ASID is
# per-CPU, but a freshly booted minimal guest tends to hand the shared mm the
# same low ASID on both CPUs (empirically the child's CPU-1 execution matches
# the CPU-0 pin), so the churned child is traced on BOTH vCPUs under ONE tid
# — a genuine migration witness.  The block runs BEFORE the loop yield (which
# owns the loop-back branch), guards itself with its own skip label, and
# round-trips the loop cursor/counter through $s0/$s1 across the two syscalls
# the MIPS ABI does not preserve $t across.  Errors (e.g. CPU 1 offline) are
# ignored: the child simply stays put and the run degrades to ambiguous-split.
_MIPSEL_CHILD_AFFINITY_CHURN = r"""    andi $t7, $t1, 0xfff
    bnez $t7, .Lca_skip
    nop
    move $s0, $t0
    move $s1, $t1
    lui  $s2, %hi(aff_toggle)
    addiu $s2, $s2, %lo(aff_toggle)
    lw   $s3, 0($s2)
    xori $s3, $s3, 1
    sw   $s3, 0($s2)
    beqz $s3, .Lca_cpu0
    nop
    lui  $a2, %hi(cpu1_mask)
    addiu $a2, $a2, %lo(cpu1_mask)
    b    .Lca_do
    nop
.Lca_cpu0:
    lui  $a2, %hi(cpu0_mask)
    addiu $a2, $a2, %lo(cpu0_mask)
.Lca_do:
    li   $v0, 4239
    li   $a0, 0
    li   $a1, 4
    syscall
    nop
    move $t0, $s0
    move $t1, $s1
.Lca_skip:
"""

# Extra .data for the churn (cpu1 affinity mask + the alternating toggle).
# Appended only in churn renders, so non-churn program bytes are unchanged.
_MIPSEL_CHURN_DATA = r"""cpu1_mask:         .word 2
aff_toggle:        .word 0
"""

# ---------------------------------------------------------------------------
# Distinct per-thread pointers (system/marker mode only).
#
# The wire's thread_id is the guest-thread identity the tracer reads from
# the kernel-maintained per-thread pointer register (x86 FS.base, AArch64
# TPIDR_EL0, RISC-V tp, MIPS CP0 UserLocal).  A bare clone leaves both
# threads sharing the parent's value, so they would collapse to one tid;
# to make the pair two identities on the wire the parent installs A before
# the marker (so the pinned window opens under tid 0) and the child
# receives B through CLONE_SETTLS (so its very first user TB already
# carries the distinct value, tid 1).  Values are page-aligned and chosen
# to materialise in one immediate on every ISA.
_TP_PARENT_VAL = 0x00AA0000
_TP_CHILD_VAL = 0x00BB0000
_CLONE_BASE = 0x250F00            # CLONE_VM|THREAD|SIGHAND|FILES|FS|SYSVSEM|CHILD_CLEARTID
_CLONE_SETTLS = 0x00080000

# Parent thread-pointer install, emitted BEFORE the marker.  x86 arch_prctl
# (158, ARCH_SET_FS=0x1002) and MIPS set_thread_area (o32 4283) go through
# the kernel; AArch64 TPIDR_EL0 and RISC-V tp are writable at EL0/U-mode so
# the parent writes them directly.
_TP_SET_PARENT = {
    "x86_64": (
        f"    movq $158, %rax\n"
        f"    movq $0x1002, %rdi\n"
        f"    movq ${_TP_PARENT_VAL}, %rsi\n"
        f"    syscall\n"),
    "aarch64": (
        f"    movz x9, #0x{(_TP_PARENT_VAL >> 16) & 0xffff:x}, lsl #16\n"
        f"    msr  tpidr_el0, x9\n"),
    "riscv64": (
        f"    li   tp, {_TP_PARENT_VAL}\n"),
    "mipsel": (
        f"    li   $v0, 4283\n"
        f"    li   $a0, {_TP_PARENT_VAL}\n"
        f"    syscall\n"
        f"    nop\n"),
}

# Child tls register load (the clone `tls` argument the kernel installs on
# CLONE_SETTLS): distinct value in system mode, 0 (byte-identical to the old
# render) under qemu-user.
# x86 and aarch64 need a full-instruction placeholder so the user-mode
# render reproduces the original register-zeroing idiom byte-for-byte
# (xorq / mov xzr); riscv and mips zeroed with `li ..., 0`, which the value
# placeholder reproduces exactly.
_TP_CHILD_TLS = {
    "x86_64":  ("xorq %r8, %r8", f"movq $0x{_TP_CHILD_VAL:x}, %r8"),
    "aarch64": ("mov  x3, xzr",
                f"movz x3, #0x{(_TP_CHILD_VAL >> 16) & 0xffff:x}, lsl #16"),
    "riscv64": ("0", f"0x{_TP_CHILD_VAL:x}"),
    "mipsel":  ("0", f"0x{_TP_CHILD_VAL:x}"),
}

# Periodic sched_yield inside each RMW loop (every 4096 iterations).  With
# the guest virtual clock paused across the tracer's per-TB work, timer
# ticks land so rarely inside a marker window that two CPU-bound spinners
# may never preempt each other — a window could close with only one
# thread's flow traced.  The yield hands the CPU over deterministically (a
# traced synchronous syscall), which both time-slices two threads onto one
# vCPU and gives the guest load balancer the reschedule points that migrate
# a thread across vCPUs.  Every ISA's syscall clobbers the caller-saved
# loop registers, so the loop cursor and counter round-trip in callee-saved
# registers the kernel preserves across the context switch.  sched_yield:
# x86 24, aarch64/riscv 124, mips o32 4162.
_LOOP_YIELD = {
    "x86_64": (
        "    testq $0xfff, %rcx\n"
        "    jnz {loop_label}\n"
        "    movq %rcx, %rbx\n"
        "    movq $24, %rax\n"
        "    syscall\n"
        "    movq %rbx, %rcx\n"
        "    testq %rcx, %rcx\n"
        "    jnz {loop_label}\n"),
    "aarch64": (
        "    and  x16, x11, #0xfff\n"
        "    cbnz x16, {loop_label}\n"
        "    mov  x19, x10\n"
        "    mov  x20, x11\n"
        "    mov  x8, #124\n"
        "    svc  #0\n"
        "    mov  x10, x19\n"
        "    mov  x11, x20\n"
        "    cbnz x11, {loop_label}\n"),
    "riscv64": (
        "    andi t6, t1, 0x7ff\n"   # andi imm is signed-12-bit: 0x7ff, not 0xfff
        "    bnez t6, {loop_label}\n"
        "    mv   s0, t0\n"
        "    mv   s1, t1\n"
        "    li   a7, 124\n"
        "    ecall\n"
        "    mv   t0, s0\n"
        "    mv   t1, s1\n"
        "    bnez t1, {loop_label}\n"),
    "mipsel": _MIPSEL_LOOP_YIELD,
}

# SMP start barrier (all system/marker renders).  The child stores 1 to
# started_flag the instant it enters user code; the parent yield-waits on it
# before its main loop.  This guarantees BOTH threads are runnable before the
# bulk of the window's user instructions accrue, so a small, fast window
# still captures both guest-thread identities — without it the child can
# starve until the window closes and only one tid appears.  started_flag
# lives at the END of .data (a system-only line) so existing symbol
# addresses, and therefore every RIP/adrp/%hi-relative code byte, are
# unchanged in user-mode renders, which stay byte-identical.
_START_DATA = {
    "x86_64":  "started_flag:      .long 0",
    "aarch64": "started_flag:      .word 0",
    "riscv64": "started_flag:      .word 0",
    "mipsel":  "started_flag:      .word 0",
}
_START_SIGNAL = {
    "x86_64":  "    movl $1, started_flag(%rip)\n",
    "aarch64": ("    adrp x9, started_flag\n"
                "    add  x9, x9, :lo12:started_flag\n"
                "    mov  w10, #1\n"
                "    str  w10, [x9]\n"),
    "riscv64": ("    la   t0, started_flag\n"
                "    li   t1, 1\n"
                "    sw   t1, 0(t0)\n"),
    "mipsel":  ("    lui  $t0, %hi(started_flag)\n"
                "    addiu $t0, $t0, %lo(started_flag)\n"
                "    li   $t1, 1\n"
                "    sw   $t1, 0($t0)\n"),
}
# Parent yield-wait for the child's signal.  Uses callee-saved registers
# the kernel preserves across the yield syscall; runs to completion before
# the main loop, so it shares no live state with the loop's yield.
_START_WAIT = {
    "x86_64":  (".Lwait_start:\n"
                "    movl started_flag(%rip), %eax\n"
                "    testl %eax, %eax\n"
                "    jnz .Lstart_go\n"
                "    movq $24, %rax\n"
                "    syscall\n"
                "    jmp .Lwait_start\n"
                ".Lstart_go:\n"),
    "aarch64": ("    adrp x21, started_flag\n"
                "    add  x21, x21, :lo12:started_flag\n"
                ".Lwait_start:\n"
                "    ldr  w22, [x21]\n"
                "    cbnz w22, .Lstart_go\n"
                "    mov  x8, #124\n"
                "    svc  #0\n"
                "    b    .Lwait_start\n"
                ".Lstart_go:\n"),
    "riscv64": ("    la   s2, started_flag\n"
                ".Lwait_start:\n"
                "    lw   s3, 0(s2)\n"
                "    bnez s3, .Lstart_go\n"
                "    li   a7, 124\n"
                "    ecall\n"
                "    j    .Lwait_start\n"
                ".Lstart_go:\n"),
    "mipsel":  ("    lui  $s2, %hi(started_flag)\n"
                "    addiu $s2, $s2, %lo(started_flag)\n"
                ".Lwait_start:\n"
                "    lw   $s3, 0($s2)\n"
                "    bnez $s3, .Lstart_go\n"
                "    nop\n"
                "    li   $v0, 4162\n"
                "    syscall\n"
                "    nop\n"
                "    b    .Lwait_start\n"
                "    nop\n"
                ".Lstart_go:\n"),
}


def thread_test_asm(isa: str, marker: bool = False,
                    iters: int = 1000, migrate: bool = False,
                    affinity_churn: bool = False) -> str:
    """Render the 2-thread test program for @isa.

    @marker prepends the trace start marker at ``_start`` (followed by
    a jump to a fresh label, so the clone syscall lives in a separate
    TB from the marker's — the marker TB is the one-TB lossy
    segment-open boundary) and places the end marker right before the
    parent's ``exit_group``.  @iters scales both threads' loop counts.

    In marker (system) mode the two threads are given DISTINCT thread
    pointers (parent A before the marker, child B via CLONE_SETTLS) so the
    tracer resolves them to two guest-thread tids — a bare clone would
    leave them sharing one pointer and one tid.  User-mode renders are
    unchanged (thread pointer 0, base clone flags), so their goldens stay
    byte-identical.

    @migrate (system only) adds the periodic sched_yield to every ISA's
    RMW loop and drops the mipsel CPU-0 affinity pin, turning the workload
    into an SMP migration stress: under ``-smp N`` the yields both
    time-slice the pair on one vCPU and let the guest scheduler migrate a
    thread across vCPUs — the tracer must keep one tid per guest thread
    through either.  Without @migrate, marker mode keeps the historical
    regime (mipsel confined + yielding, others free-running).

    @affinity_churn (mipsel + marker only; implies @migrate) makes the
    child DETERMINISTICALLY bounce between guest CPU 0 and CPU 1 via
    sched_setaffinity while the parent stays pinned to CPU 0 and fires the
    marker there.  The child's single tid is then executed on two vCPUs, so
    the tracer's per-CPU-independent guest-thread identity witnesses a real
    cross-vCPU migration under ONE tid (the yield-only regime never forces a
    thread across vCPUs on a balanced -smp 2 runqueue).  A no-op off mipsel.
    """
    affinity_churn = affinity_churn and marker and isa == "mipsel"
    if isa not in _THREAD_TEST_TEMPLATE:
        raise KeyError(f"no thread-test template for ISA {isa!r}")
    mk = ""
    endmk = ""
    if marker:
        mk = "\n".join(emit_trace_marker(isa)
                       + emit_entry_jump(isa, "cst_thread_main")
                       + ["cst_thread_main:"])
        endmk = "\n".join(emit_trace_marker_end(isa))

    # Distinct thread pointers only make sense once the window is pinned
    # (system mode); qemu-user thread_id is the host thread and unchanged.
    tp_parent = _TP_SET_PARENT[isa] if marker else ""
    settls = _CLONE_SETTLS if marker else 0
    clone_flags = _CLONE_BASE | settls
    child_tls = _TP_CHILD_TLS[isa][1 if marker else 0]

    # Loop yields: mipsel always yields in marker mode (its confined regime
    # needs them); every ISA yields in @migrate mode.
    aff_pin = ""
    child_yield = ""
    parent_yield = ""
    want_yield = migrate or (marker and isa == "mipsel")
    if want_yield:
        child_yield = _LOOP_YIELD[isa].format(loop_label=".Lchild_loop")
        parent_yield = _LOOP_YIELD[isa].format(loop_label=".Lparent_loop")
    # Affinity confinement is the non-migration mipsel regime; a plain
    # migration run must let the pair spread, so it is dropped there.  In
    # @affinity_churn mode the pin is KEPT (the parent stays on CPU 0 so the
    # pin is stable) and the child's churn block is prepended to its loop
    # yield, so the child alternates CPU 0 / CPU 1 under one tid.
    churn_data = ""
    if marker and isa == "mipsel" and (affinity_churn or not migrate):
        aff_pin = _MIPSEL_AFFINITY_PIN
    if affinity_churn:
        child_yield = _MIPSEL_CHILD_AFFINITY_CHURN + child_yield
        churn_data = _MIPSEL_CHURN_DATA

    # SMP start barrier: all system/marker renders (see _START_DATA).
    # It guarantees both threads are runnable before the window fills, so
    # every system thread_test — migrate or not — reliably captures both
    # guest-thread identities instead of racing the child against the
    # window close.  User-mode renders omit it and stay byte-identical.
    extra_data = _START_DATA[isa] if marker else ""
    start_signal = _START_SIGNAL[isa] if marker else ""
    start_wait = _START_WAIT[isa] if marker else ""

    return _THREAD_TEST_TEMPLATE[isa].format(
        marker=mk, end_marker=endmk, iters=int(iters),
        iters_lo=f"0x{int(iters) & 0xffff:x}",
        iters_hi=f"0x{(int(iters) >> 16) & 0xffff:x}",
        tp_parent=tp_parent,
        clone_flags=f"0x{clone_flags:X}",
        clone_flags_hi=f"0x{(clone_flags >> 16) & 0xffff:x}",
        child_tls=child_tls,
        affinity_pin=aff_pin,
        extra_data=extra_data, churn_data=churn_data,
        start_signal=start_signal, start_wait=start_wait,
        child_yield=child_yield, parent_yield=parent_yield)


# Back-compat view for callers that only need the default user-mode
# program text (no marker, 1000 iterations).
THREAD_TEST_ASM = {isa: thread_test_asm(isa)
                   for isa in _THREAD_TEST_TEMPLATE}
