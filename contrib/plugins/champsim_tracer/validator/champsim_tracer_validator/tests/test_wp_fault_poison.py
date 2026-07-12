"""End-to-end regression guard for the wrong-path fault-poisoning policy.

Every synchronous exception a wrong-path (speculative) instruction would
raise -- a bad speculative memory load from a wild/unmapped address, an
x86 divide-by-zero (#DE), and by the same mechanism any other synchronous
trap -- must be caught inside spec mode, poison the faulting instruction's
destination register(s), and squash the excursion at the first branch that
consumes a poisoned source (``CST_WP_EVENT_DEP_BRANCH_KILL`` on the sealed
wrong-path entry).  It must NOT be delivered to the guest (it is
speculative -- a real CPU squashes it) and it must NOT be silently absorbed
(the pre-fix user-mode load returned zero for the unmapped bytes, so the
wrong path ran on garbage and never poisoned).

Each case assembles a tiny freestanding program whose correct path *takes*
a conditional branch, so the not-taken fall-through -- which the wrong-path
walker explores speculatively -- contains:

    fault-raising insn  ->  dependent compare/test  ->  conditional branch

and asserts the decoded trace carries a DEP_BRANCH_KILL.  The correct path
never executes the faulting block, so the process exits cleanly (a guest
SIGSEGV/SIGFPE leak would abort it instead).

This FAILS against a pre-fix build for the wild-load case (the load was
absorbed as zero, 0 kills) and PASSES post-fix.  Point it at any build with
``CST_BUILD_DIR=/path/to/build``.  The x86-64 cases are required (the host
ISA is always buildable); other ISAs are best-effort and skipped when their
cross toolchain or qemu-<isa> binary is absent.

Run standalone:
  python tests/test_wp_fault_poison.py
  CST_BUILD_DIR=../../qemu_prefix/build python tests/test_wp_fault_poison.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


# --------------------------------------------------------------------------
# Build-tree discovery
# --------------------------------------------------------------------------
def _find_build_dir() -> Path:
    env = os.environ.get("CST_BUILD_DIR")
    if env:
        return Path(env).resolve()
    # tests/ -> validator/ -> champsim_tracer/ -> plugins/ -> contrib/ -> repo
    repo = Path(__file__).resolve().parents[5]
    return repo / "build"


BUILD_DIR = _find_build_dir()
PLUGIN_SO = BUILD_DIR / "contrib" / "plugins" / "libchampsim_tracer.so"
CST_DECODE = BUILD_DIR / "contrib" / "plugins" / "cst_decode"

ISA_QEMU = {
    "x86_64":  "qemu-x86_64",
    "aarch64": "qemu-aarch64",
    "riscv64": "qemu-riscv64",
}
ISA_CC = {
    "x86_64":  "g++",
    "aarch64": "aarch64-linux-gnu-g++",
    "riscv64": "riscv64-linux-gnu-g++",
}
ISA_CFLAGS = {
    "x86_64":  ["-static", "-nostdlib", "-nostartfiles"],
    "aarch64": ["-static", "-nostdlib", "-nostartfiles"],
    "riscv64": ["-static", "-nostdlib", "-nostartfiles",
                "-march=rv64gc", "-mabi=lp64d",
                "-msmall-data-limit=0", "-mno-relax", "-Wl,--no-relax"],
}


# --------------------------------------------------------------------------
# Wrong-path fault micro-programs.  Correct path TAKES the first branch, so
# the speculative fall-through (explored by the WP walker) holds the fault.
# --------------------------------------------------------------------------
WILD_ADDR = 0x414243444546  # ~72 TiB: never mapped in a -nostdlib static image

WILDLOAD_ASM = {
    "x86_64": f"""
.intel_syntax noprefix
.global _start
.text
_start:
    mov rax, 10
    cmp rax, 0
    jne 1f                      # correct path takes this; WP = fall-through
    movabs rbx, {WILD_ADDR}
    mov rax, [rbx]              # wrong-path wild load -> fault, poisons rax
    test rax, rax
    je 2f                       # branch on poisoned flags -> DEP_BRANCH_KILL
    nop
2:  jmp 2b
1:  mov rax, 60
    xor rdi, rdi
    syscall
""",
    "aarch64": f"""
.global _start
.text
_start:
    mov x0, 10
    cmp x0, 0
    b.ne 1f
    movz x1, {WILD_ADDR & 0xffff}
    movk x1, {(WILD_ADDR >> 16) & 0xffff}, lsl 16
    movk x1, {(WILD_ADDR >> 32) & 0xffff}, lsl 32
    ldr x2, [x1]               // wrong-path wild load -> fault, poisons x2
    cmp x2, 0
    b.eq 2f
    nop
2:  b 2b
1:  mov x8, 93                 // __NR_exit
    mov x0, 0
    svc 0
""",
    "riscv64": f"""
.global _start
.text
_start:
    li a0, 10
    bnez a0, 1f                # correct path takes this; WP = fall-through
    li a1, {WILD_ADDR}
    ld a2, 0(a1)              # wrong-path wild load -> fault, poisons a2
    beqz a2, 2f
    nop
2:  j 2b
1:  li a7, 93                 # __NR_exit
    li a0, 0
    ecall
""",
}

# x86 divide-by-zero (#DE).  Arithmetic traps are x86-specific: aarch64 sdiv
# and riscv div return a defined value on /0 rather than trapping.
DIVZERO_ASM = {
    "x86_64": """
.intel_syntax noprefix
.global _start
.text
_start:
    mov rax, 10
    xor rcx, rcx               # divisor = 0
    cmp rax, 0
    jne 1f                     # correct path takes this; WP = fall-through
    xor rdx, rdx
    div rcx                    # wrong-path #DE -> fault, poisons rax,rdx
    test rax, rax
    je 2f                      # branch on poisoned flags -> DEP_BRANCH_KILL
    nop
2:  jmp 2b
1:  mov rax, 60
    xor rdi, rdi
    syscall
""",
}


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
def _toolchain_ready(isa: str) -> str | None:
    """Return a skip reason, or None when the ISA is fully buildable."""
    if not PLUGIN_SO.exists():
        return f"plugin not built: {PLUGIN_SO}"
    if not CST_DECODE.exists():
        return f"cst_decode not built: {CST_DECODE}"
    if shutil.which(ISA_CC[isa]) is None:
        return f"compiler missing: {ISA_CC[isa]}"
    if not (BUILD_DIR / ISA_QEMU[isa]).exists():
        return f"qemu binary missing: {BUILD_DIR / ISA_QEMU[isa]}"
    return None


def _kills_for(isa: str, asm: str, *, no_fault: bool) -> int:
    """Assemble @asm, trace it, and return the DEP_BRANCH_KILL event count."""
    with tempfile.TemporaryDirectory(prefix="cst_wpfault_") as d:
        dd = Path(d)
        src, exe, out = dd / "t.s", dd / "t", dd / "run"
        src.write_text(asm)
        subprocess.run([ISA_CC[isa], *ISA_CFLAGS[isa], "-o", str(exe), str(src)],
                       check=True, capture_output=True)
        env = dict(os.environ)
        if no_fault:
            env["CST_NO_FAULT"] = "1"
        else:
            env.pop("CST_NO_FAULT", None)
        subprocess.run(
            [str(BUILD_DIR / ISA_QEMU[isa]),
             "-plugin", f"{PLUGIN_SO},outfile={out},wpdepth=64",
             str(exe)],
            check=True, capture_output=True, env=env)
        trace = dd / "run.cst"
        dec = subprocess.run([str(CST_DECODE), str(trace)],
                             check=True, capture_output=True, text=True)
        # One kill event annotates every insn line of its sealed BB; count
        # the BB-header lines (`wp[..] ... status=...DEP_BRANCH_KILL`) so a
        # multi-insn killed block counts once.
        return sum(1 for ln in dec.stdout.splitlines()
                   if ln.lstrip().startswith("; ..... wp[")
                   and "DEP_BRANCH_KILL" in ln)


def _assert_wildload_kills(isa: str):
    reason = _toolchain_ready(isa)
    if reason:
        raise unittest.SkipTest(reason)
    kills = _kills_for(isa, WILDLOAD_ASM[isa], no_fault=False)
    assert kills >= 1, (
        f"{isa}: wrong-path wild load did NOT produce DEP_BRANCH_KILL "
        f"(kills={kills}); the bad speculative load was absorbed instead of "
        f"poisoning its destination -- the pre-fix user-mode bug.")


# ---- required (host ISA) --------------------------------------------------
def test_x86_wildload_kills():
    _assert_wildload_kills("x86_64")


def test_x86_divzero_kills():
    reason = _toolchain_ready("x86_64")
    if reason:
        raise unittest.SkipTest(reason)
    kills = _kills_for("x86_64", DIVZERO_ASM["x86_64"], no_fault=False)
    assert kills >= 1, (
        "x86_64: wrong-path divide-by-zero did NOT produce DEP_BRANCH_KILL "
        f"(kills={kills}); an arithmetic wrong-path trap must poison its "
        "destination just like a bad load.")


def test_x86_wildload_no_kill_under_cst_no_fault():
    # A/B control: CST_NO_FAULT disables the poison policy, so the fault is
    # still detected and skipped but no branch is killed.  This both proves
    # the policy is what produces the kill and mirrors the pre-fix shape.
    reason = _toolchain_ready("x86_64")
    if reason:
        raise unittest.SkipTest(reason)
    kills = _kills_for("x86_64", WILDLOAD_ASM["x86_64"], no_fault=True)
    assert kills == 0, (
        f"x86_64: CST_NO_FAULT must disable dep-branch-kill, got kills={kills}")


# ---- best-effort (skipped when cross toolchain / qemu-<isa> absent) -------
def test_aarch64_wildload_kills():
    _assert_wildload_kills("aarch64")


def test_riscv64_wildload_kills():
    _assert_wildload_kills("riscv64")


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    n_pass = n_skip = n_fail = 0
    for fn in fns:
        try:
            fn()
        except unittest.SkipTest as e:
            print(f"SKIP {fn.__name__}: {e}")
            n_skip += 1
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
            n_fail += 1
        else:
            print(f"PASS {fn.__name__}")
            n_pass += 1
    print(f"{'OK' if n_fail == 0 else 'FAILED'} "
          f"({n_pass} passed, {n_skip} skipped, {n_fail} failed)")
    sys.exit(1 if n_fail else 0)
