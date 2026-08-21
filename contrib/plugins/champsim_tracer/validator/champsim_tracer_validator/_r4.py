#!/usr/bin/env python3
"""R4 content-gate scope cells: fork child, concurrent instances, execve.

Under content-as-gate the tracer captures every address space that maps the
latched marker sequence's bytes, and only those.  Three consequences of that
model had never been proven able to fire (``_check_user_code_identity``, the
offline statement of the gate, is now the most load-bearing system-mode
assertion, and the mutation matrix carried no address-space mutation at all):

* :func:`run_fork_child` — a MARKED process forks; the child inherits the
  image (copy-on-write), so it MAPS the marker bytes at the latched vaddr
  WITHOUT re-executing the marker, and is therefore traced.  This is the
  model's "fork children are in scope" stated as a live test: the child is
  captured because it maps the bytes, not because it marked.

* :func:`run_concurrent_instances` — two instances of the SAME marked binary
  run concurrently; both map the marker bytes (identical vaddr + bytes = the
  one shared window, Q15) and both are traced under distinct asid LABELS.

* :func:`run_execve_boundary` — a marked launcher ``execve``\\ s an UNMARKED
  image.  The new image does not map the marker bytes at the latched vaddr,
  so the gate turns off and the post-``execve`` code is NOT captured: an
  ``execve``'d child legitimately falls OUT of the gate rather than
  mismatching.  Every captured user template must still byte-match the
  LAUNCHER image.

All three are x86_64 system-mode boots.  They are timing-sensitive in the
same way :func:`_multiproc.run_trace_all_differential` is — the peer/child
must be scheduled by the guest inside the open window — so ``full`` registers
them non-gating; the assertions they make are exact when they do run.

Author: Maccoy Merrell.  SPDX-License-Identifier: GPL-2.0-or-later
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from . import asm_blocks as B
from . import _multiproc as MP
from . import _system as SYS
from . import validator as V

SubCheck = MP.SubCheck
MPResult = MP.MPResult

# The window budget for these cells: large enough that the child/peer is
# scheduled and captured before a budget close, small enough to bound a run.
_R4_BUDGET = 3_000_000
_R4_IDLE_INSNS = 2_000_000


def _asm_build(isa: str, lines: list, out_dir: Path, tag: str) -> Path:
    """Assemble/link @lines (an asm listing) into @out_dir/<tag>_<isa>."""
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / f"{tag}_{isa}.S"
    src.write_text("\n".join(lines) + "\n")
    binp = out_dir / f"{tag}_{isa}"
    cc, base = MP._CC[isa]
    cmd = [cc, *base, *MP._COMMON_CFLAGS, str(src), "-o", str(binp)]
    subprocess.check_call(cmd)
    return binp


def _prologue() -> list:
    return [".text", ".globl _start", ".type _start, @function", "_start:"]


def _arena() -> list:
    return [".section .data", ".balign 64", ".globl arena",
            ".type arena, @object", "arena:", ".skip 4096"]


def _loop_x86(reg: str, iters: int, tag: str) -> list:
    return [f"  movq ${iters}, %rcx",
            f"L{tag}:",
            f"  addq $1, {reg}",
            "  subq $1, %rcx",
            f"  jne L{tag}"]


# ---------------------------------------------------------------------------
# workloads (x86_64)
# ---------------------------------------------------------------------------

def _wl_fork_marked() -> list:
    """Mark (open window), fork; parent works then runs END; child works.

    The child returns from fork PAST the marker — it never re-marks — yet is
    still traced because its copy-on-write address space maps the marker
    bytes at the latched vaddr."""
    return (_prologue()
            + B.emit_thread_ptr_install("x86_64")
            + B.emit_trace_marker_locked("x86_64")
            + ["  movq $57, %rax",            # __NR_fork
               "  syscall",
               "  testq %rax, %rax",
               "  jz Lr4_child"]
            + _loop_x86("%rbx", 400000, "r4_pl")   # parent work
            + B.emit_trace_marker_end("x86_64")     # parent END closes window
            + ["  jmp Lr4_exit",
               "Lr4_child:"]
            + _loop_x86("%r12", 600000, "r4_cl")   # child work (no re-mark)
            + ["Lr4_exit:",
               "  movq $60, %rax",
               "  xorq %rdi, %rdi",
               "  syscall"]
            + _arena())


def _wl_execve_launcher() -> list:
    """Mark (open window), work briefly, execve /plain (unmarked)."""
    return (_prologue()
            + B.emit_thread_ptr_install("x86_64")
            + B.emit_trace_marker_locked("x86_64")
            + _loop_x86("%rbx", 200000, "r4_lw")
            + ["  leaq Lr4_path(%rip), %rdi",
               "  leaq Lr4_argv(%rip), %rsi",
               "  xorq %rdx, %rdx",           # envp = NULL
               "  movq $59, %rax",            # __NR_execve
               "  syscall",
               # execve returned -> it failed; exit(1) loudly.
               "  movq $60, %rax",
               "  movq $1, %rdi",
               "  syscall"]
            + _arena()
            + ["Lr4_path:", '  .asciz "/plain"',
               ".balign 8",
               "Lr4_argv:", "  .quad Lr4_path", "  .quad 0"])


def _wl_plain() -> list:
    """Unmarked image: it never maps the marker bytes at the launcher's
    latched vaddr, so nothing it runs is captured."""
    return (_prologue()
            + _loop_x86("%rbx", 500000, "r4_plain")
            + ["  movq $60, %rax",
               "  xorq %rdi, %rdi",
               "  syscall"])


# ---------------------------------------------------------------------------
# init scripts
# ---------------------------------------------------------------------------

def _init_run_once(binname: str) -> str:
    return f"""#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst r4 guest: $(uname -r) ==="
/{binname}
echo "=== /{binname} exit=$? ; poweroff ==="
poweroff -f
"""


_INIT_CONCURRENT = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst r4 concurrent guest: $(uname -r) ==="
/workload &
p1=$!
/workload &
p2=$!
echo "=== launched two instances p1=$p1 p2=$p2 ==="
wait $p1; echo "=== instance1 exit=$? ==="
wait $p2; echo "=== instance2 exit=$? ; poweroff ==="
poweroff -f
"""


# ---------------------------------------------------------------------------
# cells
# ---------------------------------------------------------------------------

def _marker_opts(out_base: Path, cfg: MP.MPConfig, extra: str = "") -> str:
    return (f"outfile={out_base},wpdepth={cfg.depth},"
            f"trace_window=marker:policy=latch+simulation={_R4_BUDGET},"
            f"memdata=1{extra}")


def run_fork_child(cfg: MP.MPConfig) -> MPResult:
    isa = "x86_64"
    skip = MP._preconditions(cfg, isa)
    if skip:
        return MPResult(ok=True, subchecks=[], artifacts={}, skipped=True,
                        skip_reason=skip)
    od = cfg.out_dir
    od.mkdir(parents=True, exist_ok=True)
    binp = _asm_build(isa, _wl_fork_marked(), od / "build", "fork")
    cpio = MP._stage(isa, od / "stage", [("workload", binp)],
                     _init_run_once("workload"))
    out_base = od / "fork"
    rc, console, cst = MP._boot(cfg, isa, cpio, out_base,
                                _marker_opts(out_base, cfg),
                                budget=_R4_BUDGET)
    subs: list = []
    if not cst.exists():
        subs.append(SubCheck("boot produced a trace", False,
                             f"qemu_rc={rc} cst MISSING"))
        return MP._emit("x86 fork-child content gate", subs)

    labels = MP._entry_asid_labels(cfg, cst)
    subs.append(SubCheck(
        "1. parent AND fork-child both captured (>=2 asid labels)",
        len(labels) >= 2,
        f"asid_labels={sorted(labels)} (child inherits the gate by mapping "
        f"the marker bytes, without re-marking)"))

    ok_audit, asum = MP._audit_clean(cfg, cst)
    src = MP._strict_rc(cfg, cst)
    subs.append(SubCheck("2. audit clean + strict rc=0 + qemu rc=0",
                         ok_audit and src == 0 and rc == 0,
                         f"qemu_rc={rc} strict_rc={src} audit[{asum}]"))

    # Every captured user template byte-matches the fork image (content gate).
    report = V.validate_structural(cst, expected_threads=1,
                                   expected_guest_threads=1, marker=True,
                                   pinned_binary=binp)
    uci = [e for e in report.errors() if e.check == "user_code_identity"]
    subs.append(SubCheck(
        "3. captured user code byte-matches the fork image (content gate)",
        not uci,
        "user_code_identity clean" if not uci
        else "; ".join(e.message for e in uci)))

    res = MP._emit("x86 fork-child content gate", subs)
    res.artifacts = {"cst": str(cst)}
    return res


def run_concurrent_instances(cfg: MP.MPConfig) -> MPResult:
    isa = "x86_64"
    skip = MP._preconditions(cfg, isa)
    if skip:
        return MPResult(ok=True, subchecks=[], artifacts={}, skipped=True,
                        skip_reason=skip)
    od = cfg.out_dir
    od.mkdir(parents=True, exist_ok=True)
    # ONE marked binary, run twice: two address spaces from one image, both
    # mapping the marker bytes -> both traced under distinct labels.
    binp = MP._gen_build(isa, "conc", cfg.seed_a, 6, 4000, 2, True,
                         od / "build")
    cpio = MP._stage(isa, od / "stage", [("workload", binp)],
                     _INIT_CONCURRENT)
    out_base = od / "conc"
    rc, console, cst = MP._boot(cfg, isa, cpio, out_base,
                                _marker_opts(out_base, cfg),
                                budget=_R4_BUDGET)
    subs: list = []
    if not cst.exists():
        subs.append(SubCheck("boot produced a trace", False,
                             f"qemu_rc={rc} cst MISSING"))
        return MP._emit("x86 concurrent same-binary gate", subs)

    labels = MP._entry_asid_labels(cfg, cst)
    subs.append(SubCheck(
        "1. both instances captured (>=2 asid labels, one shared window)",
        len(labels) >= 2,
        f"asid_labels={sorted(labels)}"))

    ok_audit, asum = MP._audit_clean(cfg, cst)
    src = MP._strict_rc(cfg, cst)
    subs.append(SubCheck("2. audit clean + strict rc=0",
                         ok_audit and src == 0,
                         f"qemu_rc={rc} strict_rc={src} audit[{asum}]"))

    report = V.validate_structural(cst, expected_threads=1,
                                   expected_guest_threads=1, marker=True,
                                   pinned_binary=binp)
    uci = [e for e in report.errors() if e.check == "user_code_identity"]
    subs.append(SubCheck(
        "3. both instances' user code byte-matches the shared image",
        not uci,
        "user_code_identity clean" if not uci
        else "; ".join(e.message for e in uci)))

    res = MP._emit("x86 concurrent same-binary gate", subs)
    res.artifacts = {"cst": str(cst)}
    return res


def run_execve_boundary(cfg: MP.MPConfig) -> MPResult:
    isa = "x86_64"
    skip = MP._preconditions(cfg, isa)
    if skip:
        return MPResult(ok=True, subchecks=[], artifacts={}, skipped=True,
                        skip_reason=skip)
    od = cfg.out_dir
    od.mkdir(parents=True, exist_ok=True)
    launcher = _asm_build(isa, _wl_execve_launcher(), od / "build", "launch")
    plain = _asm_build(isa, _wl_plain(), od / "build", "plain")
    cpio = MP._stage(isa, od / "stage",
                     [("workload", launcher), ("plain", plain)],
                     _init_run_once("workload"))
    out_base = od / "execve"
    # No reachable END after execve; the idle backstop closes the window once
    # the post-execve image (gated OFF) has run without gated progress.
    rc, console, cst = MP._boot(
        cfg, isa, cpio, out_base,
        _marker_opts(out_base, cfg,
                     extra=f",latch_idle_insns={_R4_IDLE_INSNS}"),
        budget=_R4_BUDGET + _R4_IDLE_INSNS)
    subs: list = []
    if not cst.exists():
        subs.append(SubCheck("boot produced a trace", False,
                             f"qemu_rc={rc} cst MISSING"))
        return MP._emit("x86 execve boundary gate", subs)

    # The launcher WAS traced: its pre-execve code is present.
    labels = MP._entry_asid_labels(cfg, cst)
    subs.append(SubCheck(
        "1. the marked launcher was traced (>=1 asid label)",
        len(labels) >= 1,
        f"asid_labels={sorted(labels)}"))

    # The post-execve /plain image is NOT captured: every captured user
    # template byte-matches the LAUNCHER, none the plain image.  If plain
    # code had leaked in, user_code_identity(launcher) would fail.
    report = V.validate_structural(cst, expected_threads=1,
                                   expected_guest_threads=1, marker=True,
                                   pinned_binary=launcher)
    uci = [e for e in report.errors() if e.check == "user_code_identity"]
    subs.append(SubCheck(
        "2. post-execve /plain code is NOT captured (falls out of the gate)",
        not uci,
        "user_code_identity(launcher) clean -- no foreign image captured"
        if not uci else "; ".join(e.message for e in uci)))

    ok_audit, asum = MP._audit_clean(cfg, cst)
    src = MP._strict_rc(cfg, cst)
    subs.append(SubCheck("3. audit clean + strict rc=0",
                         ok_audit and src == 0,
                         f"strict_rc={src} audit[{asum}]"))

    res = MP._emit("x86 execve boundary gate", subs)
    res.artifacts = {"cst": str(cst)}
    return res
