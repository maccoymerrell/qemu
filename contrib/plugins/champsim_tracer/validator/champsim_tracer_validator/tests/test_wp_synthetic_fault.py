"""End-to-end regression guard for the wrong-path SYNTHETIC-FAULT policy.

On a mispredicted (wrong) path no instruction ever retires, so a back-end
synchronous memory fault -- a speculative load/atomic from an
absent/unreadable page -- is never actually taken by a real core.  The
tracer must NOT truncate the excursion at such a fault.  Instead it fills a
deterministic pseudo-random placeholder value, MARKS the faulting
instruction with ``CST_WP_EVENT_FAULT`` (a synthetic-data fault at
``fault_insn_index``), and CONTINUES speculating to the ``wpdepth`` budget.
This holds symmetrically in user and system mode.

This retires the previous poison + ``CST_WP_EVENT_DEP_BRANCH_KILL`` policy,
which truncated the excursion at the first branch dependent on the faulted
load.  A wrong-path chain must therefore now carry FAULT (never
DEP_BRANCH_KILL) and run PAST the faulting block.

Only a FRONT-end fault (translation-unavailable / can't-fetch) still stops
the excursion.  A NON-memory EXECUTION-TIME fault -- an x86 divide-by-zero
(#DE), and by the same mechanism any other arithmetic / illegal-opcode /
conditional-trap exception -- still longjmps out of spec mode, but the walker
now clears the pending exception, SKIPS the faulting instruction, and
re-dispatches at its fall-through: the block is marked FAULT and the
excursion CONTINUES to the wpdepth budget, just like a memory fault (no kill,
no poison, no stop).

Each case assembles a tiny freestanding program whose correct path *takes* a
conditional branch, so the not-taken fall-through -- which the wrong-path
walker explores speculatively -- contains the fault.  The correct path never
executes the faulting block, so the process exits cleanly (a guest
SIGSEGV/SIGFPE leak would abort it instead).

For the wild-load cases the fall-through continues with a straight-line
arithmetic sled past the ``wpdepth`` budget, so the marked wrong-path block
runs to the budget rather than truncating.  This FAILS against a pre-fix
build (which emits DEP_BRANCH_KILL and truncates) and PASSES post-fix.
Point it at any build with ``CST_BUILD_DIR=/path/to/build``.  The x86-64
cases are required (the host ISA is always buildable); other ISAs are
best-effort and skipped when their cross toolchain or qemu-<isa> binary is
absent.

Run standalone:
  python tests/test_wp_synthetic_fault.py
  CST_BUILD_DIR=../../qemu_prefix/build python tests/test_wp_synthetic_fault.py
"""
from __future__ import annotations

import os
import re
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

WPDEPTH = 64

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
# The wild-load fall-through then runs a straight-line arithmetic sled well
# past wpdepth so the marked wrong-path block reaches the budget.
# --------------------------------------------------------------------------
WILD_ADDR = 0x414243444546  # ~72 TiB: never mapped in a -nostdlib static image
SLED = 96                   # > wpdepth, so the marked WP block runs to budget

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
    mov rax, [rbx]              # wrong-path wild load -> synthetic fault
    .rept {SLED}
    add rax, 1                  # forward sled: WP runs past wpdepth
    .endr
2:  jmp 2b                      # seal the WP block (budget already reached)
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
    ldr x2, [x1]               // wrong-path wild load -> synthetic fault
    .rept {SLED}
    add x2, x2, 1
    .endr
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
    ld a2, 0(a1)              # wrong-path wild load -> synthetic fault
    .rept {SLED}
    addi a2, a2, 1
    .endr
2:  j 2b
1:  li a7, 93                 # __NR_exit
    li a0, 0
    ecall
""",
}

# x86 divide-by-zero (#DE).  Arithmetic traps are x86-specific: aarch64 sdiv
# and riscv div return a defined value on /0 rather than trapping.  A #DE
# longjmps out of spec mode; the walker now skips the faulting div and
# CONTINUES.  The div lives in a SHORT wrong-path block ending at a branch
# (``jmp 3f``) so the fault block seals BEFORE the sled -- a graceful-stop
# build stops right there (~3 WP insns), while the continue build carries on
# into the separate sled block (block 3) and runs to the wpdepth budget.  That
# separation is what makes the test fail pre-fix and pass post-fix.
DIVZERO_ASM = {
    "x86_64": f"""
.intel_syntax noprefix
.global _start
.text
_start:
    mov rax, 10
    xor rcx, rcx               # divisor = 0
    cmp rax, 0
    jne 1f                     # correct path takes this; WP = fall-through
    xor rdx, rdx
    div rcx                    # wrong-path #DE -> synthetic fault, then skip
    jmp 3f                     # seal the fault block at a branch (before sled)
3:  .rept {SLED}
    add rax, 1                 # forward sled: continue build runs past wpdepth
    .endr
2:  jmp 2b                     # seal the sled block (budget already reached)
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


# `; ..... wp[N] BB M n_insns=K status=FAULT@insnX -----`
_WP_HDR = re.compile(
    r";\s*\.+\s*wp\[(?P<idx>\d+)\]\s+BB\s+(?P<bb>\d+)\s+"
    r"n_insns=(?P<n>\d+)(?:\s+status=(?P<status>\S+))?")


def _wp_blocks(isa: str, asm: str, *, no_fault: bool) -> list[dict]:
    """Assemble @asm, trace it, and return the decoded wrong-path blocks as
    dicts {idx, bb, n_insns, status}."""
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
             "-plugin", f"{PLUGIN_SO},outfile={out},wpdepth={WPDEPTH}",
             str(exe)],
            check=True, capture_output=True, env=env)
        trace = dd / "run.cst"
        dec = subprocess.run([str(CST_DECODE), str(trace)],
                             check=True, capture_output=True, text=True)
        blocks: list[dict] = []
        for ln in dec.stdout.splitlines():
            m = _WP_HDR.search(ln)
            if m:
                blocks.append({
                    "idx": int(m.group("idx")),
                    "bb": int(m.group("bb")),
                    "n_insns": int(m.group("n")),
                    "status": m.group("status") or "",
                })
        return blocks


def _has(blocks: list[dict], token: str) -> bool:
    return any(token in b["status"] for b in blocks)


def _assert_wildload_synthetic(isa: str):
    reason = _toolchain_ready(isa)
    if reason:
        raise unittest.SkipTest(reason)
    blocks = _wp_blocks(isa, WILDLOAD_ASM[isa], no_fault=False)
    assert blocks, f"{isa}: no wrong-path chain emitted at all"
    # (a) the faulting insn is MARKED synthetic (CST_WP_EVENT_FAULT).
    assert _has(blocks, "FAULT"), (
        f"{isa}: wrong-path wild load was NOT marked FAULT "
        f"(blocks={[b['status'] for b in blocks]}); a bad speculative load "
        f"must be tagged a synthetic-data fault.")
    # (b) it does NOT truncate: no DEP_BRANCH_KILL, and the excursion runs to
    # the wpdepth budget (the marked block continues on placeholder data).
    assert not _has(blocks, "DEP_BRANCH_KILL"), (
        f"{isa}: retired DEP_BRANCH_KILL still emitted "
        f"(blocks={[b['status'] for b in blocks]}); wrong-path memory faults "
        f"must continue, not squash at the dependent branch.")
    total = sum(b["n_insns"] for b in blocks)
    assert total >= WPDEPTH // 2, (
        f"{isa}: wrong-path excursion truncated early (total WP insns "
        f"{total} < {WPDEPTH // 2}); it must run on the placeholder value to "
        f"the wpdepth={WPDEPTH} budget instead of stopping at the fault.")


# ---- required (host ISA) --------------------------------------------------
def test_x86_wildload_synthetic():
    _assert_wildload_synthetic("x86_64")


def test_x86_divzero_synthetic():
    # A non-memory EXECUTION-TIME fault (#DE) longjmps out of spec mode, but the
    # walker now clears the exception, skips the faulting div, and CONTINUES on
    # placeholder data -- exactly like a bad load.  The div block is MARKED
    # FAULT and the excursion runs to the wpdepth budget instead of stopping at
    # the div.  This FAILS against a pre-fix (graceful-stop) build, which seals
    # the ~3-insn fault block and stops before the sled, and PASSES post-fix.
    reason = _toolchain_ready("x86_64")
    if reason:
        raise unittest.SkipTest(reason)
    blocks = _wp_blocks("x86_64", DIVZERO_ASM["x86_64"], no_fault=False)
    assert blocks, "x86_64: no wrong-path chain emitted for divzero"
    assert _has(blocks, "FAULT"), (
        "x86_64: wrong-path divide-by-zero was NOT marked FAULT "
        f"(blocks={[b['status'] for b in blocks]}); an arithmetic wrong-path "
        "trap must be tagged a synthetic fault just like a bad load.")
    assert not _has(blocks, "DEP_BRANCH_KILL"), (
        "x86_64: retired DEP_BRANCH_KILL still emitted for divzero")
    total = sum(b["n_insns"] for b in blocks)
    assert total >= WPDEPTH // 2, (
        f"x86_64: wrong-path divide-by-zero excursion truncated early (total "
        f"WP insns {total} < {WPDEPTH // 2}); an arithmetic wrong-path fault "
        f"must skip the faulting insn and continue to the wpdepth={WPDEPTH} "
        f"budget, not stop at the div.")


def test_x86_wildload_no_mark_under_cst_no_fault():
    # A/B control: CST_NO_FAULT disables the synthetic-fault marking, so the
    # bad load still runs on placeholder data but the block is NOT marked.
    # This both proves the marking is what the policy produces and mirrors the
    # pre-policy shape (no FAULT, no DEP_BRANCH_KILL).
    reason = _toolchain_ready("x86_64")
    if reason:
        raise unittest.SkipTest(reason)
    blocks = _wp_blocks("x86_64", WILDLOAD_ASM["x86_64"], no_fault=True)
    assert not _has(blocks, "FAULT"), (
        "x86_64: CST_NO_FAULT must disable synthetic-fault marking, but a "
        f"FAULT event was emitted (blocks={[b['status'] for b in blocks]})")
    assert not _has(blocks, "DEP_BRANCH_KILL"), (
        "x86_64: DEP_BRANCH_KILL is retired and must never be emitted")


# ---- best-effort (skipped when cross toolchain / qemu-<isa> absent) -------
def test_aarch64_wildload_synthetic():
    _assert_wildload_synthetic("aarch64")


def test_riscv64_wildload_synthetic():
    _assert_wildload_synthetic("riscv64")


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
