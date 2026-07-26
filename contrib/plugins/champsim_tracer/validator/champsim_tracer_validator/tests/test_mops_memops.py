"""AArch64 FEAT_MOPS bulk transfers are visible to memory instrumentation.

The ARMv8.8 bulk-memory instructions -- ``SETP``/``SETM``/``SETE`` and the
``CPYP``/``CPYM``/``CPYE`` family -- are implemented in QEMU by a helper that
takes a trapless ``tlb_vaddr_to_host()`` lookup and then moves the whole
page-bounded chunk with a host ``memset()``/``memmove()``.  That bulk move
never goes through a ``qemu_ld``/``qemu_st`` TCG op, so the plugin memory
callbacks accel/tcg emits around those ops never fire.  Before
``arm_plugin_bulk_mem_cb()`` (target/arm/tcg/helper-a64.c) reported the
transfer explicitly, every correct-path MOPS execution recorded **zero**
memory accesses -- and glibc's AArch64 ``memcpy``/``memmove``/``memset``
route through MOPS whenever ``HWCAP2_MOPS`` is set, so this hid essentially
all of a program's bulk memory traffic.

The program here issues the two triples directly, so nothing depends on a
libc ifunc choice.  Both buffers are page aligned and the transfer size is
0x2040 = two whole pages plus 64 bytes, which lands work on all six
instructions: the prologue takes the run up to the first page boundary, the
main instruction takes the whole pages after it, and the epilogue takes the
64-byte tail.

The assertion is a tiling one, which pins addresses and sizes and not just a
count: the store records of the SET triple must cover ``[dst, dst+size)``
exactly -- contiguous, no gap, no overlap -- and the CPY triple's loads must
tile ``[src, src+size)`` and its stores ``[dst, dst+size)``.  Every access
must also be naturally aligned and at most 16 bytes, the widest size the
plugin memory API can describe.

Against a pre-fix build all six instructions carry no memops at all and every
tiling is empty, so this FAILS.

Point it at any build with ``CST_BUILD_DIR=/path/to/build``.  Skips when the
AArch64 cross toolchain or ``qemu-aarch64`` is absent.

Run standalone:
  python tests/test_mops_memops.py
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
QEMU_BIN = BUILD_DIR / "qemu-aarch64"

CROSS_CC = os.environ.get("CROSS_CC", "aarch64-linux-gnu-gcc")
CROSS_OBJDUMP = os.environ.get("CROSS_OBJDUMP", "aarch64-linux-gnu-objdump")

#: Transfer size.  Two whole pages plus a 64-byte tail, so the prologue, the
#: main instruction and the epilogue each get a nonzero share of the work.
XFER = 0x2040

#: The six instructions under test, in program order.
MOPS_MNEMONICS = ("setp", "setm", "sete", "cpyfp", "cpyfm", "cpyfe")

PROGRAM = r"""
    .arch armv8.8-a
    .bss
    .balign 4096
mops_dst:
    .skip 16384
mops_src:
    .skip 16384

    .text
    .globl _start
_start:
    adrp x0, mops_dst
    add  x0, x0, :lo12:mops_dst
    adrp x1, mops_src
    add  x1, x1, :lo12:mops_src

    /* memset(dst, 0x5a, XFER) as the architectural SET triple. */
    mov  x3, x0
    mov  x2, #%(xfer)#x
    mov  x4, #0x5a
    setp [x3]!, x2!, x4
    setm [x3]!, x2!, x4
    sete [x3]!, x2!, x4

    /* memcpy(dst, src, XFER) as the architectural forward CPY triple. */
    mov  x5, x0
    mov  x6, x1
    mov  x2, #%(xfer)#x
    cpyfp [x5]!, [x6]!, x2!
    cpyfm [x5]!, [x6]!, x2!
    cpyfe [x5]!, [x6]!, x2!

    /* exit(0) */
    mov  x8, #93
    mov  x0, #0
    svc  #0
""" % {"xfer": XFER}


_DISAS_RE = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]+\s+(\S+)")


def _mops_pcs(binary: Path) -> dict:
    """Map mnemonic -> PC for the six MOPS instructions in @binary."""
    out = subprocess.run([CROSS_OBJDUMP, "-d", str(binary)],
                         text=True, capture_output=True).stdout
    pcs = {}
    for line in out.splitlines():
        m = _DISAS_RE.match(line)
        if m and m.group(2) in MOPS_MNEMONICS:
            pcs[m.group(2)] = int(m.group(1), 16)
    return pcs


def _tiling_error(accs, base, size, what):
    """Return None if @accs tiles [base, base+size) exactly, else why not.

    @accs is a list of (address, nbytes).  Order is not required, but every
    piece must be naturally aligned, at most 16 bytes (the widest access the
    plugin memory API can describe), and the pieces together must cover the
    range with no gap and no overlap.
    """
    if not accs:
        return (f"{what}: no memory accesses recorded at all "
                f"(expected a tiling of [0x{base:x}, 0x{base + size:x}))")
    for addr, n in accs:
        if n <= 0 or n > 16 or (n & (n - 1)):
            return f"{what}: access at 0x{addr:x} has bad size {n}"
        if addr % n:
            return f"{what}: access at 0x{addr:x} is not {n}-byte aligned"
    total = sum(n for _a, n in accs)
    if total != size:
        return (f"{what}: accesses cover {total} bytes, expected {size} "
                f"({len(accs)} accesses)")
    cur = base
    for addr, n in sorted(accs):
        if addr != cur:
            return (f"{what}: coverage breaks at 0x{cur:x} "
                    f"(next access is 0x{addr:x})")
        cur += n
    if cur != base + size:
        return f"{what}: coverage ends at 0x{cur:x}, expected 0x{base + size:x}"
    return None


@unittest.skipUnless(shutil.which(CROSS_CC), f"{CROSS_CC} not found")
@unittest.skipUnless(shutil.which(CROSS_OBJDUMP), f"{CROSS_OBJDUMP} not found")
@unittest.skipUnless(QEMU_BIN.is_file(), f"{QEMU_BIN} not built")
@unittest.skipUnless(PLUGIN_SO.is_file(), f"{PLUGIN_SO} not built")
class MopsMemopsTest(unittest.TestCase):

    def test_mops_transfers_are_instrumented(self):
        from champsim_tracer_validator import _cst_decode_runner as R

        with tempfile.TemporaryDirectory(prefix="mops_memops.") as td:
            work = Path(td)
            src = work / "mops.S"
            src.write_text(PROGRAM)
            binp = work / "mops"
            build = subprocess.run(
                [CROSS_CC, "-static", "-nostdlib", "-nostartfiles", "-O1",
                 "-fno-asynchronous-unwind-tables", str(src), "-o", str(binp)],
                text=True, capture_output=True)
            if build.returncode != 0:
                self.skipTest(f"assembler lacks FEAT_MOPS support:\n"
                              f"{build.stderr[-600:]}")

            pcs = _mops_pcs(binp)
            missing = [m for m in MOPS_MNEMONICS if m not in pcs]
            self.assertFalse(missing,
                             f"disassembly did not show {missing}")

            out = work / "mops"
            run = subprocess.run(
                [str(QEMU_BIN), "-plugin",
                 f"{PLUGIN_SO},outfile={out},wpdepth=4,memdata=1",
                 str(binp)], text=True, capture_output=True)
            cst = Path(f"{out}.cst")
            self.assertEqual(run.returncode, 0,
                             f"guest exited {run.returncode}\n"
                             f"{run.stderr[-600:]}")
            self.assertTrue(cst.is_file(), "tracer produced no .cst")

            _meta, templates, entries = \
                R.decode_champsim_tracer(cst)

            # Gather every correct-path memop landing on each MOPS PC.
            by_id = {t["template_id"]: t for t in templates}
            pc_of = {v: k for k, v in pcs.items()}
            found = {m: {"load": [], "store": []} for m in MOPS_MNEMONICS}
            for e in entries:
                tmpl = by_id.get(e.get("template_id")) or {}
                insns = tmpl.get("insns") or []
                for dp in (e.get("dyn_params") or []):
                    i = int(getattr(dp, "insn_index", -1))
                    if not (0 <= i < len(insns)):
                        continue
                    mn = pc_of.get(int(insns[i].get("pc", -1)))
                    if mn is None:
                        continue
                    kind = getattr(dp, "type_name", "")
                    if kind in ("load", "store"):
                        found[mn][kind].append(
                            (int(dp.value), int(dp.data_size)))

            # Every one of the six must have done *some* work: this is the
            # bare regression, and it is what a pre-fix build fails on.
            silent = [m for m in MOPS_MNEMONICS
                      if not found[m]["load"] and not found[m]["store"]]
            self.assertFalse(
                silent,
                f"FEAT_MOPS instructions recorded no memory accesses: "
                f"{silent}.  The bulk helper took the host-pointer fast path "
                f"and the transfer never reached the plugin memory "
                f"instrumentation (target/arm/tcg/helper-a64.c "
                f"arm_plugin_bulk_mem_cb).")

            # The SET triple must have no loads at all.
            for m in ("setp", "setm", "sete"):
                self.assertEqual(found[m]["load"], [],
                                 f"{m} is a store-only instruction but "
                                 f"recorded {len(found[m]['load'])} loads")

            # Tiling: the triples' stores cover the destination exactly and
            # the CPY triple's loads cover the source exactly.  The base of
            # each range is the lowest address the triple touched; asserting
            # page alignment on it pins that the buffers are where the
            # program put them.
            set_st = (found["setp"]["store"] + found["setm"]["store"]
                      + found["sete"]["store"])
            cpy_st = (found["cpyfp"]["store"] + found["cpyfm"]["store"]
                      + found["cpyfe"]["store"])
            cpy_ld = (found["cpyfp"]["load"] + found["cpyfm"]["load"]
                      + found["cpyfe"]["load"])

            dst = min(a for a, _n in set_st)
            src_base = min(a for a, _n in cpy_ld)
            self.assertEqual(dst & 0xfff, 0,
                             f"destination base 0x{dst:x} is not page aligned")
            self.assertEqual(src_base & 0xfff, 0,
                             f"source base 0x{src_base:x} is not page aligned")
            self.assertEqual(min(a for a, _n in cpy_st), dst,
                             "SET and CPY did not target the same buffer")

            for accs, base, what in (
                    (set_st, dst, "SETP/SETM/SETE stores"),
                    (cpy_ld, src_base, "CPYFP/CPYFM/CPYFE loads"),
                    (cpy_st, dst, "CPYFP/CPYFM/CPYFE stores")):
                err = _tiling_error(accs, base, XFER, what)
                self.assertIsNone(err, err)


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    unittest.main(verbosity=2)
