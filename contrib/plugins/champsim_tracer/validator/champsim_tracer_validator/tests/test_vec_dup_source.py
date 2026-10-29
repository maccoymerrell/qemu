"""A broadcast from a vector register reads the element it broadcasts.

``tcg_gen_gvec_dup_mem(vece, dofs, aofs, ...)`` emits ``dupm_vec(ret, base,
ofs)`` when the host has vectors (this x86-64 build does): a load of
``1 << vece`` bytes at ``base + ofs``, replicated across ``ret``.  The
dataflow reader's table of direct env accesses (``accel/tcg/insn-dataflow.c``
``df_ldst()``) did not list ``INDEX_op_dupm_vec``, so the read of the element
was never recorded and every register-source broadcast lost its source: the
destination was published with an empty source list.

The AArch64 callers of ``tcg_gen_gvec_dup_mem`` are:

* ``trans_DUP_element_v`` -- NEON ``DUP Vd.<T>, Vn.Ts[index]`` (base NEON,
  executable on every ``-cpu``); and
* ``trans_DUP_x`` -- SVE ``DUP Zd.<T>, Zn.<T>[index]`` (needs SVE);
  plus the SVE ``LD1RQ``/``LD1RO`` replicate helpers.

The x86 VPBROADCAST/VBROADCAST family (same op) is covered by its own probe;
these AArch64 callers were fixed in code (commit ad9ad531c3, the
``INDEX_op_dupm_vec`` case in ``df_ldst()``) with no probe executing them.
This test executes the NEON ``DUP (element)`` form across all four element
sizes as the standing executing witness, and additionally exercises the SVE
``DUP (indexed)`` form when the ``-cpu`` provides SVE.

Firing proof.  Against a build with ``df_ldst()``'s ``dupm_vec`` case
reverted, each ``dup`` publishes a **non-empty destination and an EMPTY
source list** -- the element read is lost -- so the ``src_regs`` assertions
FAIL.  Against the fixed build each ``dup``'s source list names the vector
register whose element it replicates.

Point it at any build with ``CST_BUILD_DIR=/path/to/build``.  Skips when the
AArch64 cross toolchain or ``qemu-aarch64`` is absent; the SVE leg skips
(with its reason named) when the default ``-cpu`` does not provide SVE, while
the NEON leg still carries the executing witness for the same ``df_ldst()``
code path.

Run standalone:
  python tests/test_vec_dup_source.py
"""
from __future__ import annotations

import os
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
    return Path(__file__).resolve().parents[6] / "build"


BUILD_DIR = _find_build_dir()
PLUGIN_SO = BUILD_DIR / "contrib" / "plugins" / "libchampsim_tracer.so"
QEMU_BIN = BUILD_DIR / "qemu-aarch64"

CROSS_CC = os.environ.get("CROSS_CC", "aarch64-linux-gnu-gcc")
CROSS_OBJDUMP = os.environ.get("CROSS_OBJDUMP", "aarch64-linux-gnu-objdump")

# NEON DUP (element): every lane takes one element of a source vector
# register, read through dupm_vec.  All four element sizes, each from its own
# source register so a lost or crossed source would show.
NEON_FORMS = ["pc_dup_b", "pc_dup_h", "pc_dup_s", "pc_dup_d"]
NEON_PROGRAM = r"""
    .text
    .globl _start
_start:
    movi v1.16b, #0x11
    movi v3.16b, #0x22
    movi v5.16b, #0x33
    movi v7.16b, #0x44
    .globl pc_dup_b
pc_dup_b:
    dup  v0.16b, v1.b[3]
    .globl pc_dup_h
pc_dup_h:
    dup  v2.8h,  v3.h[2]
    .globl pc_dup_s
pc_dup_s:
    dup  v4.4s,  v5.s[1]
    .globl pc_dup_d
pc_dup_d:
    dup  v6.2d,  v7.d[0]
    mov  x8, #93
    mov  x0, #0
    svc  #0
"""

# SVE DUP (indexed): the same dupm_vec op, from a Z register element.
SVE_FORMS = ["pc_sdup_b", "pc_sdup_d"]
SVE_PROGRAM = r"""
    .arch armv8-a+sve
    .text
    .globl _start
_start:
    dup  z1.b, #0x51
    dup  z7.d, #0x62
    .globl pc_sdup_b
pc_sdup_b:
    dup  z0.b, z1.b[3]
    .globl pc_sdup_d
pc_sdup_d:
    dup  z6.d, z7.d[1]
    mov  x8, #93
    mov  x0, #0
    svc  #0
"""


def _label_pcs(binary: Path) -> dict:
    out = subprocess.run([CROSS_OBJDUMP, "-t", str(binary)],
                         text=True, capture_output=True).stdout
    pcs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].startswith("pc_"):
            try:
                pcs[parts[-1]] = int(parts[0], 16)
            except ValueError:
                pass
    return pcs


@unittest.skipUnless(shutil.which(CROSS_CC), f"{CROSS_CC} not found")
@unittest.skipUnless(shutil.which(CROSS_OBJDUMP), f"{CROSS_OBJDUMP} not found")
@unittest.skipUnless(QEMU_BIN.is_file(), f"{QEMU_BIN} not built")
@unittest.skipUnless(PLUGIN_SO.is_file(), f"{PLUGIN_SO} not built")
class VecDupSourceTest(unittest.TestCase):

    _neon = None
    _sve = None  # None = not attempted; str = skip reason; dict = captured

    def _assemble(self, work: Path, name: str, program: str, labels):
        src = work / f"{name}.S"
        src.write_text(program)
        binp = work / name
        build = subprocess.run(
            [CROSS_CC, "-static", "-nostdlib", "-nostartfiles", "-O0",
             "-fno-asynchronous-unwind-tables", str(src), "-o", str(binp)],
            text=True, capture_output=True)
        if build.returncode != 0:
            return None, build.stderr
        return binp, None

    def _trace_and_collect(self, work: Path, binp: Path, labels):
        from champsim_tracer_validator import _cst_decode_runner as R
        # Decode with the build-under-test's OWN decoder, pinned on the
        # channel that never reaches the guest.
        decode = BUILD_DIR / "contrib" / "plugins" / "cst_decode"
        if decode.is_file():
            R.set_cst_decode(decode)
        pcs = _label_pcs(binp)
        out = work / binp.name
        run = subprocess.run(
            [str(QEMU_BIN), "-seed", "4242", "-plugin",
             f"{PLUGIN_SO},outfile={out},wpdepth=8",
             str(binp)], text=True, capture_output=True)
        cst = Path(f"{out}.cst")
        # returncode < 0 means the guest died on a signal (e.g. SIGILL when
        # the -cpu lacks the feature); surface it to the caller.
        if run.returncode != 0 or not cst.is_file():
            return None, pcs, (f"guest exited {run.returncode}: "
                               f"{run.stderr[-300:]}")
        _meta, templates, _entries = R.decode_champsim_tracer(cst)
        want = {pc: lbl for lbl, pc in pcs.items()}
        by_label = {lbl: [] for lbl in labels}
        for t in templates:
            for ins in (t.get("insns") or []):
                lbl = want.get(int(ins.get("pc", -1)))
                if lbl is not None:
                    by_label[lbl].append(ins)
        return (by_label, cst), pcs, None

    def _neon_cap(self):
        if VecDupSourceTest._neon is None:
            td = tempfile.mkdtemp(prefix="vec_dup_neon.")
            self.addClassCleanup(shutil.rmtree, td, ignore_errors=True)
            work = Path(td)
            binp, err = self._assemble(work, "neon", NEON_PROGRAM, NEON_FORMS)
            self.assertIsNotNone(binp, f"assembling NEON probe failed:\n{err}")
            for lbl in NEON_FORMS:
                self.assertIn(lbl, _label_pcs(binp),
                              f"symbol table did not show {lbl}")
            cap, _pcs, err = self._trace_and_collect(work, binp, NEON_FORMS)
            self.assertIsNotNone(cap, f"NEON probe did not trace: {err}")
            VecDupSourceTest._neon = cap
        return VecDupSourceTest._neon

    def _sve_cap(self):
        if VecDupSourceTest._sve is None:
            td = tempfile.mkdtemp(prefix="vec_dup_sve.")
            self.addClassCleanup(shutil.rmtree, td, ignore_errors=True)
            work = Path(td)
            binp, err = self._assemble(work, "sve", SVE_PROGRAM, SVE_FORMS)
            if binp is None:
                VecDupSourceTest._sve = ("skip", "assembler has no SVE "
                                         f"support: {err[-200:]}")
            else:
                cap, _pcs, err = self._trace_and_collect(work, binp, SVE_FORMS)
                if cap is None:
                    VecDupSourceTest._sve = (
                        "skip", "SVE not available on the default -cpu "
                        f"(the NEON leg carries the df_ldst witness): {err}")
                else:
                    VecDupSourceTest._sve = ("cap", cap)
        return VecDupSourceTest._sve

    def _assert_source_restored(self, by_label, forms):
        for lbl in forms:
            self.assertTrue(by_label[lbl],
                            f"{lbl} never appeared in a template -- the probe "
                            f"did not execute the form")
            for ins in by_label[lbl]:
                self.assertTrue(
                    ins["dst_regs"],
                    f"{lbl} published no destination at all")
                self.assertTrue(
                    ins["src_regs"],
                    f"{lbl} ({ins['opcode']=}) published an EMPTY source "
                    f"list: the broadcast's element read was lost "
                    f"(accel/tcg df_ldst INDEX_op_dupm_vec).  dst_regs="
                    f"{ins['dst_regs']}")

    def test_neon_dup_element_reads_its_source(self):
        by_label, _cst = self._neon_cap()
        self._assert_source_restored(by_label, NEON_FORMS)

    def test_sve_dup_indexed_reads_its_source(self):
        state = self._sve_cap()
        if state[0] == "skip":
            self.skipTest(state[1])
        by_label, _cst = state[1]
        self._assert_source_restored(by_label, SVE_FORMS)

    def test_decode_strict_is_clean(self):
        by_label, cst = self._neon_cap()
        decode = BUILD_DIR / "contrib" / "plugins" / "cst_decode"
        if not decode.is_file():
            self.skipTest("cst_decode not built")
        r = subprocess.run([str(decode), "--strict", str(cst)],
                           text=True, capture_output=True)
        self.assertEqual(r.returncode, 0,
                         f"cst_decode --strict failed:\n{r.stderr[-800:]}")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    unittest.main(verbosity=2)
