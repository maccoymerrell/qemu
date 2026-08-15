#!/usr/bin/env python3
"""Multi-thread generative oracle — the GENERATOR half.

The single-thread validator's whole point is that the workload is
*generated*, so its exact expected content is known without ever
consulting a previous trace: a golden can only say "as broken as last
time", a generated oracle says "right" or "wrong".  Multi-thread content
had no such oracle — ``thread_test`` asserted the *shape* of the wire
(two tids, two well-formed chains, no vCPU) and nothing about what each
thread actually executed.

This module builds the missing subject: **N independent synthetic
workloads, one per guest thread, stitched into ONE binary**.

    thread K  ->  own seed, own CFG, own code region (symbol prefix
                  ``tK_``), own arena (``tK_arena``), own meta.json

    driver    ->  clones the N workers onto private stacks, each
                  entering at ``tK__start``; futex-joins every worker
                  through its ``CLONE_CHILD_CLEARTID`` slot; fires the
                  single END marker; ``exit_group``.

Because the regions are disjoint *by construction* — separate code,
separate data, separate expected streams — the trace can be split on the
wire's own ``thread_id`` and compared 1v1 against each thread's ground
truth.  That comparison is :mod:`._mt_check`.

Why a driver thread rather than running body 0 on the main thread: the
generated CFG's terminal block is the generator's ``ExitBlock``, whose
last instruction is ``SYS_exit`` — a thread that runs a body cannot
outlive it, and the END marker has to be fired by a thread that has
outlived *every* body (the marker contract: exactly one END, after all
the content it closes over).  So the process carries N body-running
threads plus one thin driver; the driver runs no generated code at all,
which is exactly what makes the containment invariant checkable — a
driver PC in a worker's stream, or a worker PC in the driver's, is a
tagging defect the checker names.

Symbol namespacing is done at the OBJECT level (``objcopy
--redefine-syms``), not in the emitter: the per-thread ``.S`` is byte-for-
byte what the single-thread generator emits, so the generated content
this oracle checks is the same content the single-thread oracle checks.

Author: Maccoy Merrell.  SPDX-License-Identifier: GPL-2.0-or-later
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import subprocess
from pathlib import Path

from . import asm_blocks as B
from . import generator as G


# Per-worker stack (bytes).  The generated bodies only touch the stack
# through the call-coverage blocks (`call wptgen_leaf`), so this is
# generous; it is also the clone `stack` argument's granularity.
STACK_BYTES = 65536

# CLONE_VM|THREAD|SIGHAND|FILES|FS|SYSVSEM|CHILD_CLEARTID, plus SETTLS
# when the run needs distinct guest-thread pointers (system mode).
_CLONE_BASE = 0x250F00
_CLONE_SETTLS = 0x00080000

# Per-thread pointer values (system mode only).  The wire's thread_id is
# resolved from the kernel-maintained per-thread pointer register, so the
# driver and every worker need a DISTINCT one or they collapse onto a
# single tid.  All values are (imm16 << 16) so every ISA materialises them
# in one instruction.
_TP_DRIVER = 0x00A00000
_TP_STEP = 0x00010000


def tp_value(thread: int | None) -> int:
    """Thread-pointer value for worker @thread (None = the driver)."""
    if thread is None:
        return _TP_DRIVER
    return _TP_DRIVER + (thread + 1) * _TP_STEP


# ---------------------------------------------------------------------------
# Per-ISA syscall numbers used by the driver
# ---------------------------------------------------------------------------

_SYS = {
    #            clone  futex  exit_group
    "x86_64":  (56, 202, 231),
    "aarch64": (220, 98, 94),
    "riscv64": (220, 98, 94),
    "mipsel":  (4120, 4238, 4246),
}


# ---------------------------------------------------------------------------
# Driver emitters (one per ISA)
# ---------------------------------------------------------------------------

def _driver_data(n: int) -> list[str]:
    """.data / .bss shared by every ISA's driver."""
    lines = [".section .data", ".balign 8", "mt_ctid:"]
    # CLONE_CHILD_CLEARTID target, one per worker.  Non-zero at start;
    # the kernel zeroes it and FUTEX_WAKEs when that worker exits.
    lines += ["  .long 1"] * n
    lines += [
        ".section .bss",
        ".balign 16",
        "mt_stacks:",
        f"  .skip {STACK_BYTES * n}",
        "mt_stacks_end:",
    ]
    return lines


def _tp_set_driver(isa: str) -> list[str]:
    v = _TP_DRIVER
    if isa == "x86_64":
        return [f"  movq $158, %rax", f"  movq $0x1002, %rdi",
                f"  movq ${v}, %rsi", "  syscall"]
    if isa == "aarch64":
        return [f"  movz x9, #0x{(v >> 16) & 0xffff:x}, lsl #16",
                "  msr tpidr_el0, x9"]
    if isa == "riscv64":
        return [f"  li tp, {v}"]
    return [f"  li $v0, 4283", f"  li $a0, {v}", "  syscall", "  nop"]


def _driver_x86_64(n: int, marker: bool) -> list[str]:
    clone, futex, exit_group = _SYS["x86_64"]
    flags = _CLONE_BASE | (_CLONE_SETTLS if marker else 0)
    L: list[str] = [".section .text", ".globl _start",
                    ".type _start, @function", "_start:"]
    if marker:
        L += _tp_set_driver("x86_64")
        L += B.emit_trace_marker("x86_64")
        L += B.emit_entry_jump("x86_64", "cst_mt_main")
        L += ["cst_mt_main:"]
        L += B.emit_trace_syscall_probe("x86_64")
        L += B.emit_trace_fault_probe("x86_64")
    for i in range(n):
        tls = (f"  movq $0x{tp_value(i):x}, %r8" if marker
               else "  xorq %r8, %r8")
        L += [
            f"  movq ${clone}, %rax",
            f"  movq $0x{flags:X}, %rdi",
            f"  leaq mt_stacks+{STACK_BYTES * (i + 1)}(%rip), %rsi",
            "  xorq %rdx, %rdx",
            f"  leaq mt_ctid+{4 * i}(%rip), %r10",
            tls,
            "  syscall",
            "  testq %rax, %rax",
            f"  jz .Lmt_child_{i}",
        ]
    for i in range(n):
        L += [
            f".Lmt_join_{i}:",
            f"  movl mt_ctid+{4 * i}(%rip), %edx",
            "  testl %edx, %edx",
            f"  jz .Lmt_joined_{i}",
            f"  leaq mt_ctid+{4 * i}(%rip), %rdi",
            "  xorq %rsi, %rsi",
            "  xorq %r10, %r10",
            f"  movq ${futex}, %rax",
            "  syscall",
            f"  jmp .Lmt_join_{i}",
            f".Lmt_joined_{i}:",
        ]
    if marker:
        L += B.emit_trace_marker_end("x86_64")
    L += [f"  movq ${exit_group}, %rax", "  xorq %rdi, %rdi", "  syscall",
          ".size _start, .-_start"]
    for i in range(n):
        L += [f".Lmt_child_{i}:", f"  jmp t{i}__start"]
    return L


def _driver_aarch64(n: int, marker: bool) -> list[str]:
    clone, futex, exit_group = _SYS["aarch64"]
    flags = _CLONE_BASE | (_CLONE_SETTLS if marker else 0)
    L: list[str] = [".section .text", ".globl _start",
                    ".type _start, @function", "_start:"]
    if marker:
        L += _tp_set_driver("aarch64")
        L += B.emit_trace_marker("aarch64")
        L += B.emit_entry_jump("aarch64", "cst_mt_main")
        L += ["cst_mt_main:"]
        L += B.emit_trace_syscall_probe("aarch64")
        L += B.emit_trace_fault_probe("aarch64")
    for i in range(n):
        off = STACK_BYTES * (i + 1)
        # `add xN, xN, #imm, lsl #12` covers multiples of 4096 up to
        # 0xFFF000, i.e. 63 workers of 64 KiB.
        tls = (f"  movz x3, #0x{(tp_value(i) >> 16) & 0xffff:x}, lsl #16"
               if marker else "  mov x3, xzr")
        L += [
            f"  mov x8, #{clone}",
            f"  mov x0, #0x{_CLONE_BASE & 0xffff:X}",
            f"  movk x0, #0x{(flags >> 16) & 0xffff:x}, lsl #16",
            "  adrp x1, mt_stacks",
            "  add x1, x1, :lo12:mt_stacks",
            f"  add x1, x1, #{off >> 12}, lsl #12",
            "  mov x2, xzr",
            tls,
            "  adrp x4, mt_ctid",
            "  add x4, x4, :lo12:mt_ctid",
            f"  add x4, x4, #{4 * i}",
            "  svc #0",
            f"  cbz x0, .Lmt_child_{i}",
        ]
    for i in range(n):
        L += [
            f".Lmt_join_{i}:",
            "  adrp x9, mt_ctid",
            "  add x9, x9, :lo12:mt_ctid",
            f"  add x9, x9, #{4 * i}",
            "  ldr w2, [x9]",
            f"  cbz w2, .Lmt_joined_{i}",
            "  mov x0, x9",
            "  mov x1, #0",
            "  mov x3, #0",
            f"  mov x8, #{futex}",
            "  svc #0",
            f"  b .Lmt_join_{i}",
            f".Lmt_joined_{i}:",
        ]
    if marker:
        L += B.emit_trace_marker_end("aarch64")
    L += [f"  mov x8, #{exit_group}", "  mov x0, #0", "  svc #0",
          ".size _start, .-_start"]
    for i in range(n):
        L += [f".Lmt_child_{i}:", f"  b t{i}__start"]
    return L


def _driver_riscv64(n: int, marker: bool) -> list[str]:
    clone, futex, exit_group = _SYS["riscv64"]
    flags = _CLONE_BASE | (_CLONE_SETTLS if marker else 0)
    L: list[str] = [".section .text", ".globl _start",
                    ".type _start, @function", "_start:"]
    if marker:
        L += _tp_set_driver("riscv64")
        L += B.emit_trace_marker("riscv64")
        L += B.emit_entry_jump("riscv64", "cst_mt_main")
        L += ["cst_mt_main:"]
        L += B.emit_trace_syscall_probe("riscv64")
        L += B.emit_trace_fault_probe("riscv64")
    for i in range(n):
        tls = f"  li a3, 0x{tp_value(i):x}" if marker else "  li a3, 0"
        L += [
            f"  li a7, {clone}",
            f"  li a0, 0x{flags:X}",
            "  la a1, mt_stacks",
            f"  li t0, {STACK_BYTES * (i + 1)}",
            "  add a1, a1, t0",
            "  li a2, 0",
            tls,
            "  la a4, mt_ctid",
            f"  addi a4, a4, {4 * i}",
            "  ecall",
            f"  beqz a0, .Lmt_child_{i}",
        ]
    for i in range(n):
        L += [
            f".Lmt_join_{i}:",
            "  la t0, mt_ctid",
            f"  addi t0, t0, {4 * i}",
            "  lw a2, 0(t0)",
            f"  beqz a2, .Lmt_joined_{i}",
            "  mv a0, t0",
            "  li a1, 0",
            "  li a3, 0",
            f"  li a7, {futex}",
            "  ecall",
            f"  j .Lmt_join_{i}",
            f".Lmt_joined_{i}:",
        ]
    if marker:
        L += B.emit_trace_marker_end("riscv64")
    L += [f"  li a7, {exit_group}", "  li a0, 0", "  ecall",
          ".size _start, .-_start"]
    for i in range(n):
        L += [f".Lmt_child_{i}:", f"  j t{i}__start"]
    return L


def _driver_mipsel(n: int, marker: bool) -> list[str]:
    clone, futex, exit_group = _SYS["mipsel"]
    flags = _CLONE_BASE | (_CLONE_SETTLS if marker else 0)
    L: list[str] = [".section .text", ".set noreorder", ".globl _start",
                    ".type _start, @function", "_start:"]
    if marker:
        L += _tp_set_driver("mipsel")
        L += B.emit_trace_marker("mipsel")
        L += B.emit_entry_jump("mipsel", "cst_mt_main")
        L += ["cst_mt_main:"]
        L += B.emit_trace_syscall_probe("mipsel")
        L += B.emit_trace_fault_probe("mipsel")
    for i in range(n):
        tls = f"  li $a3, 0x{tp_value(i):x}" if marker else "  li $a3, 0"
        L += [
            f"  li $v0, {clone}",
            f"  li $a0, 0x{flags:X}",
            "  lui $a1, %hi(mt_stacks)",
            "  addiu $a1, $a1, %lo(mt_stacks)",
            f"  li $t9, {STACK_BYTES * (i + 1)}",
            "  addu $a1, $a1, $t9",
            "  li $a2, 0",
            tls,
            "  addiu $sp, $sp, -32",
            "  lui $t0, %hi(mt_ctid)",
            "  addiu $t0, $t0, %lo(mt_ctid)",
            f"  addiu $t0, $t0, {4 * i}",
            "  sw $t0, 16($sp)",
            "  syscall",
            "  addiu $sp, $sp, 32",
            "  nop",
            f"  beqz $v0, .Lmt_child_{i}",
            "  nop",
        ]
    for i in range(n):
        L += [
            f".Lmt_join_{i}:",
            "  lui $t0, %hi(mt_ctid)",
            "  addiu $t0, $t0, %lo(mt_ctid)",
            f"  addiu $t0, $t0, {4 * i}",
            "  lw $a2, 0($t0)",
            f"  beqz $a2, .Lmt_joined_{i}",
            "  nop",
            "  move $a0, $t0",
            "  li $a1, 0",
            "  li $a3, 0",
            f"  li $v0, {futex}",
            "  syscall",
            "  nop",
            f"  b .Lmt_join_{i}",
            "  nop",
            f".Lmt_joined_{i}:",
        ]
    if marker:
        L += B.emit_trace_marker_end("mipsel")
    L += [f"  li $v0, {exit_group}", "  li $a0, 0", "  syscall", "  nop",
          ".size _start, .-_start"]
    for i in range(n):
        L += [f".Lmt_child_{i}:", f"  j t{i}__start", "  nop"]
    L += [".set reorder"]
    return L


_DRIVERS = {
    "x86_64": _driver_x86_64,
    "aarch64": _driver_aarch64,
    "riscv64": _driver_riscv64,
    "mipsel": _driver_mipsel,
}


def driver_source(isa: str, n_threads: int, marker: bool = False) -> str:
    """Render the stitcher: clone N workers, futex-join them all, close
    the window, exit_group."""
    if isa not in _DRIVERS:
        raise KeyError(f"no multi-thread driver for ISA {isa!r}")
    if not 1 <= n_threads <= 63:
        raise ValueError("n_threads must be in [1, 63]")
    lines = [f"# GENERATED by champsim_tracer_validator mt driver; "
             f"isa={isa} threads={n_threads} marker={int(marker)}"]
    lines += _driver_data(n_threads)
    lines += _DRIVERS[isa](n_threads, marker)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class MTParams:
    isa: str
    seed: int
    threads: int = 2
    num_diamonds: int = 6
    side_len_min: int = 2
    side_len_max: int = 4
    coverage: bool = False
    hot_iters: int = 0
    marker: bool = False


def thread_seed(base_seed: int, k: int) -> int:
    """Per-thread seed.  Derived by hashing so two threads of the same
    run share no CFG structure, and so a run's seed still names the whole
    set reproducibly."""
    h = hashlib.sha256(f"{base_seed}:mt:{k}".encode()).digest()
    return int.from_bytes(h[:8], "little") & 0x7FFFFFFF


def prefix_for(k: int) -> str:
    return f"t{k}_"


def generate(params: MTParams, out_dir: Path,
             prog: str = "mt") -> dict:
    """Emit N per-thread ``.S``/``.meta.json`` pairs, the driver ``.S``,
    and the index that ties them together.  Returns the index dict."""
    out_dir.mkdir(parents=True, exist_ok=True)
    isa = params.isa
    threads = []
    for k in range(params.threads):
        seed = thread_seed(params.seed, k)
        gp = G.GenerateParams(
            seed=seed,
            isa=isa,
            num_diamonds=params.num_diamonds,
            side_len_min=params.side_len_min,
            side_len_max=params.side_len_max,
            coverage=params.coverage,
            hot_iters=params.hot_iters,
            # The driver owns the marker: a worker that fired one would
            # open a second window, and a worker that fired the END would
            # close the trace over the other workers' unfinished content.
            marker=False,
        )
        name = f"{prog}_{isa}_t{k}"
        src, meta_path = G.generate(gp, out_dir, name)

        # Namespace the metadata to match the objcopy rename below, so
        # the checker resolves this thread's symbols in the linked image.
        pfx = prefix_for(k)
        meta = json.loads(meta_path.read_text())
        for blk in meta["blocks"]:
            blk["sym_name"] = pfx + blk["sym_name"]
        meta["arena"]["symbol"] = pfx + meta["arena"]["symbol"]
        meta["mt_thread"] = k
        meta["mt_sym_prefix"] = pfx
        meta_path.write_text(json.dumps(meta, indent=2))

        threads.append({
            "index": k,
            "seed": seed,
            "prefix": pfx,
            "entry_symbol": f"{pfx}_start",
            "source": src.name,
            "meta": meta_path.name,
            "arena_symbol": meta["arena"]["symbol"],
        })

    drv_path = out_dir / f"{prog}_{isa}_driver.S"
    drv_path.write_text(driver_source(isa, params.threads,
                                      marker=params.marker))

    index = {
        "format_version": 1,
        "generator": "champsim_tracer_validator._mt_gen",
        "isa": isa,
        "seed": params.seed,
        "n_threads": params.threads,
        "marker": bool(params.marker),
        "driver_source": drv_path.name,
        "binary": f"{prog}_{isa}",
        "threads": threads,
    }
    idx_path = out_dir / f"{prog}_{isa}.index.json"
    idx_path.write_text(json.dumps(index, indent=2))
    index["_index_path"] = str(idx_path)
    return index


# ---------------------------------------------------------------------------
# Build (assemble -> namespace -> link)
# ---------------------------------------------------------------------------

def _tool(compiler: str, tool: str) -> str:
    """Derive a binutils tool name from the configured compiler, e.g.
    ``aarch64-linux-gnu-g++`` -> ``aarch64-linux-gnu-objcopy``."""
    if compiler.endswith("g++"):
        return compiler[:-3] + tool
    return tool


def _defined_symbols(nm: str, obj: Path) -> list[str]:
    """Every DEFINED symbol in @obj.  Undefined ones (libgcc helpers on
    mipsel, the driver's ``tK__start`` references) must keep their names
    or the link breaks — which is why this is a redefine LIST and not
    ``objcopy --prefix-symbols``."""
    out = subprocess.run([nm, "--no-sort", str(obj)],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"{nm} {obj} failed: {out.stderr.strip()}")
    names: list[str] = []
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        kind = parts[-2] if len(parts) >= 3 else parts[0]
        name = parts[-1]
        if len(parts) == 2:
            kind, name = parts[0], parts[1]
        if kind.upper() in ("U", "W", "V"):
            continue
        if not name or name.startswith("$") or name.startswith("."):
            continue
        names.append(name)
    return sorted(set(names))


def build(params: MTParams, out_dir: Path, index: dict,
          compiler: str, cflags: list[str],
          extra_link: list[str] | None = None) -> tuple[int, Path]:
    """Assemble each thread body, namespace its symbols, assemble the
    driver, and link one binary.  Returns ``(rc, binary_path)``; rc != 0
    means no usable binary was produced."""
    isa = params.isa
    objcopy = _tool(compiler, "objcopy")
    nm = _tool(compiler, "nm")
    # -c compiles without linking; the link-only flags in cflags are inert
    # there but the ISA flags (-march/-mabi/-mnan) are not, so the whole
    # set is passed to both steps and the object matches the final link.
    compile_flags = [f for f in cflags if f not in ("-static", "-e", "_start")]

    objs: list[Path] = []
    for t in index["threads"]:
        src = out_dir / t["source"]
        obj = out_dir / f"{src.stem}.o"
        cmd = [compiler] + compile_flags + [
            "-O1", "-fno-asynchronous-unwind-tables", "-fno-stack-protector",
            "-fno-optimize-sibling-calls", "-c", str(src), "-o", str(obj)]
        rc = subprocess.call(cmd)
        if rc != 0:
            print(f"mt_build[{isa}]: FAIL  assembling {src.name} rc={rc}")
            return rc, out_dir / index["binary"]
        # Namespace: every DEFINED symbol gains the thread prefix, so the
        # N bodies coexist in one image with no name collision and the
        # checker can address each thread's blocks and arena by name.
        pfx = t["prefix"]
        syms = _defined_symbols(nm, obj)
        redef = out_dir / f"{src.stem}.redef"
        redef.write_text("".join(f"{s} {pfx}{s}\n" for s in syms))
        rc = subprocess.call([objcopy, f"--redefine-syms={redef}", str(obj)])
        if rc != 0:
            print(f"mt_build[{isa}]: FAIL  namespacing {obj.name} rc={rc}")
            return rc, out_dir / index["binary"]
        objs.append(obj)

    drv_src = out_dir / index["driver_source"]
    drv_obj = out_dir / f"{drv_src.stem}.o"
    rc = subprocess.call([compiler] + compile_flags + [
        "-O1", "-fno-asynchronous-unwind-tables", "-fno-stack-protector",
        "-c", str(drv_src), "-o", str(drv_obj)])
    if rc != 0:
        print(f"mt_build[{isa}]: FAIL  assembling driver rc={rc}")
        return rc, out_dir / index["binary"]

    bin_path = out_dir / index["binary"]
    link = ([compiler] + cflags + ["-O1", "-fno-asynchronous-unwind-tables"]
            + [str(drv_obj)] + [str(o) for o in objs]
            + (extra_link or []) + ["-o", str(bin_path)])
    print(f"mt_build[{isa}]: {' '.join(link)}")
    rc = subprocess.call(link)
    if rc != 0:
        print(f"mt_build[{isa}]: FAIL  link rc={rc}")
        return rc, bin_path
    if not bin_path.is_file():
        # The compiler exiting 0 without producing the binary is exactly
        # the silent-false-success shape this suite refuses to accept.
        print(f"mt_build[{isa}]: FAIL  linker exited 0 but produced no "
              f"{bin_path}")
        return 1, bin_path
    return 0, bin_path
