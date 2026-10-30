"""RISC-V atomics declare their access on the CF_PARALLEL route.

A multi-threaded guest runs under MTTCG, so every TB the correct path
translates carries ``CF_PARALLEL``.  On that route ``tcg_gen_atomic_*``
lowers an AMO / LR-SC read-modify-write to a single atomic *helper call*
(``tcg/tcg-op-ldst.c``): the op stream then holds no ``qemu_ld`` / ``qemu_st``
at all, while the helper still delivers one load and one store to the plugin
memory callbacks.  Unless the translator states the access explicitly
(``target/riscv`` ``gen_sc`` / ``gen_amo`` / the Zacas emitters call
``riscv_note_atomic_rmw`` under ``CF_PARALLEL``), the minted template declares
ZERO memops for an instruction that touches memory -- and because the first
translation of a block mints the template whichever regime ran it, an atomic's
template shape could come from a serial wrong-path translation the correct
path never runs.  ``format.rst`` 4.5 forbids a record's memop count from
exceeding its template's, so the loss is silent: the correct-path load and
store have no slot and vanish.

The program issues ``amoadd.w`` and an ``lr.w`` / ``sc.w`` pair in a two-thread
``clone`` loop, so the shared counter's RMW blocks translate under
``CF_PARALLEL`` and execute on the correct path.  ``wpdepth=1`` keeps the
wrong-path walk from minting the template before the correct path does.

Two things are asserted on every atomic that executed on the correct path:

* **R-W1-3** -- its template declares exactly one load and one store.  Against
  a build with the ``CF_PARALLEL`` statement reverted the count is zero, so
  this FAILS.
* **R-W1-2** -- its destination depends on the loaded value alone, naming no
  source register.  An atomic RMW helper returns the old memory contents and
  only that; the blanket "every result depends on every argument" rule the
  dataflow walk applies to an opaque call would widen the destination to the
  address and store operands, making one encoding publish a wider destination
  under ``CF_PARALLEL`` than its serial expansion.  Against a build with that
  narrowing reverted the destination mask carries source-register bits, so
  this FAILS too.

Point it at any build with ``CST_BUILD_DIR=/path/to/build``.  Skips when the
RISC-V cross toolchain or ``qemu-riscv64`` is absent.

Run standalone:
  python tests/test_cf_parallel_atomic_memops.py
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def _find_build_dir() -> Path:
    env = os.environ.get("CST_BUILD_DIR") or os.environ.get("BUILD_DIR")
    if env:
        return Path(env).resolve()
    # tests/ -> champsim_tracer_validator/ -> validator/ -> champsim_tracer/
    # -> plugins/ -> contrib/ -> repo
    return Path(__file__).resolve().parents[6] / "build"


BUILD_DIR = _find_build_dir()
PLUGIN_SO = BUILD_DIR / "contrib" / "plugins" / "libchampsim_tracer.so"
QEMU_BIN = BUILD_DIR / "qemu-riscv64"

CROSS_CC = os.environ.get("CROSS_CC", "riscv64-linux-gnu-gcc")
CROSS_OBJDUMP = os.environ.get("CROSS_OBJDUMP", "riscv64-linux-gnu-objdump")

#: The three atomic mnemonics under test, in program order.  ``lr.w`` lowers
#: to a plain ``qemu_ld`` in both regimes and is not a CALL-route subject, so
#: it is deliberately not asserted on -- it is here so the reservation that
#: ``sc.w`` needs is a real one.
ATOMIC_MNEMONICS = ("amoadd.w", "sc.w")

#: clone(2) flags: VM|THREAD|SIGHAND|FILES|FS|SYSVSEM|CHILD_CLEARTID.  The same
#: shape the validator's own thread_test uses; qemu-user sets CF_PARALLEL on
#: the clone syscall, so both bodies translate parallel from their first TB.
CLONE_FLAGS = 0x250F00

PROGRAM = r"""
    .section .data
    .align 8
shared_counter: .dword 0
child_tid:      .word 1
    .section .bss
    .align 16
child_stack_buf: .skip 65536
child_stack_top:

    .section .text
    .globl _start
_start:
    li   a7, 220              /* __NR_clone */
    li   a0, %(flags)#x
    la   a1, child_stack_top
    li   a2, 0
    li   a3, 0
    la   a4, child_tid
    ecall
    bnez a0, parent_body

child_body:
    la   t0, shared_counter
    li   t1, %(iters)d
.Lchild_loop:
    li   t2, 1
    amoadd.w t3, t2, (t0)
.Lc_sc:
    lr.w t4, (t0)
    addi t4, t4, 1
    sc.w t5, t4, (t0)
    bnez t5, .Lc_sc
    addi t1, t1, -1
    bnez t1, .Lchild_loop
    li   a7, 93
    li   a0, 0
    ecall

parent_body:
    la   t0, shared_counter
    li   t1, %(iters)d
.Lparent_loop:
    li   t2, 1
    amoadd.w t3, t2, (t0)
.Lp_sc:
    lr.w t4, (t0)
    addi t4, t4, 1
    sc.w t5, t4, (t0)
    bnez t5, .Lp_sc
    addi t1, t1, -1
    bnez t1, .Lparent_loop
    la   t4, child_tid
.Lwait_child:
    lw   t5, 0(t4)
    bnez t5, .Lwait_child
    li   a7, 94
    li   a0, 0
    ecall
""" % {"flags": CLONE_FLAGS, "iters": 16}


_DISAS_RE = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]+\s+(\S+)")


def _atomic_pcs(binary: Path) -> dict:
    """Map mnemonic -> set of PCs for the atomics in @binary."""
    out = subprocess.run([CROSS_OBJDUMP, "-d", str(binary)],
                         text=True, capture_output=True).stdout
    pcs: dict = {m: set() for m in ATOMIC_MNEMONICS}
    for line in out.splitlines():
        m = _DISAS_RE.match(line)
        if m and m.group(2) in ATOMIC_MNEMONICS:
            pcs[m.group(2)].add(int(m.group(1), 16))
    return pcs


@unittest.skipUnless(shutil.which(CROSS_CC), f"{CROSS_CC} not found")
@unittest.skipUnless(shutil.which(CROSS_OBJDUMP), f"{CROSS_OBJDUMP} not found")
@unittest.skipUnless(QEMU_BIN.is_file(), f"{QEMU_BIN} not built")
@unittest.skipUnless(PLUGIN_SO.is_file(), f"{PLUGIN_SO} not built")
class CfParallelAtomicMemopsTest(unittest.TestCase):

    def test_cf_parallel_atomic_declares_one_load_one_store(self):
        from champsim_tracer_validator import _cst_decode_runner as R

        with tempfile.TemporaryDirectory(prefix="cf_par_atomic.") as td:
            work = Path(td)
            src = work / "atomic.S"
            src.write_text(PROGRAM)
            binp = work / "atomic"
            build = subprocess.run(
                [CROSS_CC, "-static", "-nostdlib", "-nostartfiles",
                 "-march=rv64g", "-O0", "-fno-asynchronous-unwind-tables",
                 str(src), "-o", str(binp)],
                text=True, capture_output=True)
            self.assertEqual(build.returncode, 0,
                             f"assemble failed:\n{build.stderr[-600:]}")

            pcs = _atomic_pcs(binp)
            missing = [m for m in ATOMIC_MNEMONICS if not pcs[m]]
            self.assertFalse(missing,
                             f"disassembly did not show {missing}")
            atomic_pcs = {pc for s in pcs.values() for pc in s}

            # A fixed layout: ASLR off (setarch -R) and a pinned environment,
            # so the guest stack and entry counts do not wander between runs.
            # wpdepth=1 keeps the wrong-path walk from minting the atomic's
            # template before the CF_PARALLEL correct path does.
            out = work / "atomic"
            env = {"PATH": "/usr/local/bin:/usr/bin:/bin",
                   "HOME": os.environ.get("HOME", "/tmp"),
                   "LANG": "C", "LC_ALL": "C"}
            run = subprocess.run(
                ["setarch", "-R", str(QEMU_BIN), "-plugin",
                 f"{PLUGIN_SO},outfile={out},wpdepth=1,memdata=1",
                 str(binp)], text=True, capture_output=True, env=env)
            cst = Path(f"{out}.cst")
            self.assertEqual(run.returncode, 0,
                             f"guest exited {run.returncode}\n"
                             f"{run.stderr[-600:]}")
            self.assertTrue(cst.is_file(), "tracer produced no .cst")

            meta, templates = R.decode_champsim_tracer_header(cst)
            lint = R.lint_failure(meta.get("impossible_attributions"))
            self.assertIsNone(lint, f"{lint} (cst_decode --strict {cst})")

            # Every template whose atomic insn executed on the correct path:
            # in a two-thread guest the correct path IS the CF_PARALLEL route,
            # so each such insn's declaration is the one the helper-call regime
            # produced.
            checked = {m: 0 for m in ATOMIC_MNEMONICS}
            pc_mnemonic = {pc: m for m, s in pcs.items() for pc in s}
            for t in templates:
                if int(t.get("profile", {}).get("exec_cp", 0)) <= 0:
                    continue
                for insn in t.get("insns", []):
                    pc = int(insn.get("pc", -1))
                    if pc not in atomic_pcs or not insn.get("is_atomic"):
                        continue
                    mn = pc_mnemonic[pc]

                    # R-W1-3: the CF_PARALLEL atomic declares its access.
                    self.assertEqual(
                        (insn["n_loads"], insn["n_stores"]), (1, 1),
                        f"{mn} at 0x{pc:x} (template {t['template_id']}, "
                        f"exec_cp={t['profile']['exec_cp']}) declares "
                        f"{insn['n_loads']} load(s) + {insn['n_stores']} "
                        f"store(s), expected 1 + 1.  The CF_PARALLEL route "
                        f"lowered the RMW to an atomic helper call whose "
                        f"load/store the translator did not state "
                        f"(target/riscv riscv_note_atomic_rmw under "
                        f"CF_PARALLEL).")

                    # R-W1-2: the atomic's destination is the loaded value and
                    # only that -- no source-register bit.  Bit layout of a
                    # dst mask is [0, n_src) source regs, then the load-data
                    # bits, so a correct result mask is nonzero with its low
                    # n_src bits clear.
                    n_src = len(insn.get("src_regs", []))
                    src_bits = (1 << n_src) - 1
                    for d, mask in enumerate(insn.get("dst_dep_mask", [])):
                        self.assertNotEqual(
                            mask, 0,
                            f"{mn} at 0x{pc:x} dst[{d}] depends on nothing")
                        self.assertEqual(
                            mask & src_bits, 0,
                            f"{mn} at 0x{pc:x} dst[{d}] mask=0x{mask:x} names "
                            f"a source register (low {n_src} bits), but an "
                            f"atomic RMW helper returns the loaded value "
                            f"alone -- the CF_PARALLEL call result was not "
                            f"narrowed to the load (accel/tcg/insn-dataflow.c "
                            f"df_call).")
                    checked[mn] += 1

            unseen = [m for m in ATOMIC_MNEMONICS if checked[m] == 0]
            self.assertFalse(
                unseen,
                f"no correct-path (CF_PARALLEL) template exercised {unseen}; "
                f"the subject never ran, so the check proved nothing")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    unittest.main(verbosity=2)
