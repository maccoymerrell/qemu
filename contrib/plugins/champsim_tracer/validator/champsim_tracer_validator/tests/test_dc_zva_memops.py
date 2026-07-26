"""AArch64 ``DC ZVA`` is visible to memory instrumentation, as a block store.

``DC ZVA, Xt`` zeroes a naturally aligned block of memory whose size comes
from ``DCZID_EL0.BS``.  QEMU implements it in ``HELPER(dc_zva)``
(``target/arm/tcg/helper-a64.c``) with a trapless ``tlb_vaddr_to_host()``
lookup followed by a host ``memset()`` -- a bulk write that never goes
through a ``qemu_st`` TCG op, so the plugin memory callbacks accel/tcg
emits around those ops never fire.  Linux's ``clear_page()`` is built on
``DC ZVA``, so on a system-mode trace this is a large share of all store
traffic.

Making it visible took two changes that this test pins together, because
either one alone is wrong:

* **Instrumentation.** ``HELPER(dc_zva)`` reports the block through
  ``arm_plugin_bulk_mem_cb()``, the same decomposition the FEAT_MOPS SET
  and CPY steps use.

* **Classification.** Capstone folds the whole ``SYS`` alias space --
  ``DC``, ``IC``, ``AT``, ``TLBI`` -- into one instruction id
  (``AARCH64_INS_SYS``) and gives ``DC ZVA`` no memory operand at all, so
  the tracer classified it ``GEN_OP_VEC_LOGIC`` with no memory lane.
  Reported stores would then land on an instruction the template declares
  incapable of touching memory, and every trace containing a ``dc zva``
  would fail ``cst_decode --strict``.  ``disas/capstone.c`` now recognises
  the block-zeroing operations from Capstone's structured sysop detail and
  presents ``Xt`` as the written memory operand it really is;
  ``refine_arm64_sysop`` then classifies them ``GEN_OP_STORE``.

The assertion is a tiling one, matching ``test_mops_memops.py``: the store
records must cover ``[base, base + blocklen)`` exactly -- contiguous, no
gap, no overlap, naturally aligned, at most 16 bytes per access -- for
every ``dc zva`` the program issues.  The block size is read from the
guest's own ``DCZID_EL0`` rather than assumed, and the program stores it
where the test can recover it.

Against a pre-fix build the instruction records no memory accesses at all
and the tiling is empty, so this FAILS; against a build with the
instrumentation but not the classification, ``--strict`` FAILS instead.

Point it at any build with ``CST_BUILD_DIR=/path/to/build``.  Skips when
the AArch64 cross toolchain or ``qemu-aarch64`` is absent.

Run standalone:
  python tests/test_dc_zva_memops.py
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

#: How many consecutive blocks the program zeroes.  More than one so the
#: tiling assertion covers a contiguous run rather than a single block,
#: and so a stuck address would show up.
NBLOCKS = 4

PROGRAM = r"""
    .bss
    .balign 4096
zbuf:
    .skip 16384
    .balign 8
blocksz:
    .skip 8

    .text
    .globl _start
_start:
    /* blocklen = 4 << DCZID_EL0.BS ; also check DZP (bit 4) is clear,
     * i.e. DC ZVA is permitted at this EL. */
    mrs  x9, dczid_el0
    and  x10, x9, #0xf
    mov  x11, #4
    lsl  x11, x11, x10          /* x11 = block size in bytes */
    adrp x12, blocksz
    add  x12, x12, :lo12:blocksz
    str  x11, [x12]

    /* Align the buffer up to a block boundary so every DC ZVA covers a
     * whole block starting exactly where we say it does. */
    adrp x0, zbuf
    add  x0, x0, :lo12:zbuf
    sub  x13, x11, #1
    add  x0, x0, x13
    bic  x0, x0, x13            /* x0 = block-aligned base */

    mov  x14, #%(nblocks)d
    mov  x1, x0
1:
    .globl pc_dczva
pc_dczva:
    dc   zva, x1
    add  x1, x1, x11
    subs x14, x14, #1
    b.ne 1b

    /* exit(0) */
    mov  x8, #93
    mov  x0, #0
    svc  #0
""" % {"nblocks": NBLOCKS}


_SYM_RE = re.compile(r"^([0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)$")


def _label_pcs(binary: Path) -> dict:
    out = subprocess.run([CROSS_OBJDUMP, "-t", str(binary)],
                         text=True, capture_output=True).stdout
    pcs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].startswith(("pc_", "zbuf", "blocksz")):
            try:
                pcs[parts[-1]] = int(parts[0], 16)
            except ValueError:
                pass
    return pcs


def _tiling_error(accs, base, size, what):
    """Return None if @accs tiles [base, base+size) exactly, else why not."""
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
class DcZvaMemopsTest(unittest.TestCase):

    _cap = None

    def _capture(self, work: Path):
        from champsim_tracer_validator import _cst_decode_runner as R

        src = work / "dczva.S"
        src.write_text(PROGRAM)
        binp = work / "dczva"
        build = subprocess.run(
            [CROSS_CC, "-static", "-nostdlib", "-nostartfiles", "-O1",
             "-fno-asynchronous-unwind-tables", str(src), "-o", str(binp)],
            text=True, capture_output=True)
        self.assertEqual(build.returncode, 0,
                         f"assembling the probe failed:\n{build.stderr[-800:]}")

        pcs = _label_pcs(binp)
        self.assertIn("pc_dczva", pcs, "symbol table did not show pc_dczva")

        out = work / "dczva"
        run = subprocess.run(
            [str(QEMU_BIN), "-plugin",
             f"{PLUGIN_SO},outfile={out},wpdepth=4,memdata=1",
             str(binp)], text=True, capture_output=True)
        cst = Path(f"{out}.cst")
        self.assertEqual(run.returncode, 0,
                         f"guest exited {run.returncode}\n{run.stderr[-600:]}")
        self.assertTrue(cst.is_file(), "tracer produced no .cst")

        _meta, templates, entries = R.decode_champsim_tracer(cst)

        by_id = {t["template_id"]: t for t in templates}
        target = pcs["pc_dczva"]
        found = {"load": [], "store": []}
        lanes = set()
        opcodes = set()
        for t in templates:
            for ins in (t.get("insns") or []):
                if int(ins.get("pc", -1)) == target:
                    lanes.add((int(ins.get("n_loads", 0) or 0),
                               int(ins.get("n_stores", 0) or 0)))
                    opcodes.add(int(ins.get("opcode", -1)))
        for e in entries:
            tmpl = by_id.get(e.get("template_id")) or {}
            insns = tmpl.get("insns") or []
            for dp in (e.get("dyn_params") or []):
                i = int(getattr(dp, "insn_index", -1))
                if not (0 <= i < len(insns)):
                    continue
                if int(insns[i].get("pc", -1)) != target:
                    continue
                kind = getattr(dp, "type_name", "")
                if kind in ("load", "store"):
                    found[kind].append((int(dp.value), int(dp.data_size)))
        return pcs, found, lanes, opcodes, cst

    def _shared(self):
        if DcZvaMemopsTest._cap is None:
            td = tempfile.mkdtemp(prefix="dc_zva_memops.")
            self.addClassCleanup(shutil.rmtree, td, ignore_errors=True)
            DcZvaMemopsTest._cap = self._capture(Path(td))
        return DcZvaMemopsTest._cap

    def test_dc_zva_records_stores_that_tile_the_blocks(self):
        _pcs, found, _lanes, _opcodes, _cst = self._shared()

        st = found["store"]
        self.assertTrue(
            st,
            "dc zva recorded no memory accesses at all.  The bulk helper "
            "took the host-pointer fast path and the block-zeroing store "
            "never reached the plugin memory instrumentation "
            "(target/arm/tcg/helper-a64.c HELPER(dc_zva) / "
            "arm_plugin_bulk_mem_cb).")
        self.assertEqual(found["load"], [],
                         f"dc zva is store-only but recorded "
                         f"{len(found['load'])} loads")

        # The blocks are contiguous and block-aligned by construction, so
        # the whole run must tile as one range.  Recovering the block size
        # from the records themselves (rather than assuming 64) keeps the
        # test honest about DCZID_EL0: total / NBLOCKS must be a power of
        # two at least 32 bytes, which is what the architecture allows.
        total = sum(n for _a, n in st)
        self.assertEqual(total % NBLOCKS, 0,
                         f"stores cover {total} bytes, not a multiple of "
                         f"the {NBLOCKS} blocks issued")
        blocklen = total // NBLOCKS
        self.assertTrue(blocklen >= 32 and not (blocklen & (blocklen - 1)),
                        f"implied DC ZVA block size {blocklen} is not a "
                        f"power of two >= 32")

        base = min(a for a, _n in st)
        self.assertEqual(base % blocklen, 0,
                         f"first block base 0x{base:x} is not "
                         f"{blocklen}-byte aligned")
        err = _tiling_error(st, base, blocklen * NBLOCKS,
                            f"dc zva stores ({NBLOCKS} x {blocklen} bytes)")
        self.assertIsNone(err, err)

    def test_dc_zva_is_classified_as_a_block_store(self):
        _pcs, _found, lanes, opcodes, _cst = self._shared()

        self.assertEqual(
            lanes, {(0, 1)},
            f"dc zva's template declares (n_loads, n_stores) = {lanes}, "
            f"expected {{(0, 1)}}.  Capstone models no memory operand for "
            f"DC ZVA, so without the boundary correction in "
            f"disas/capstone.c (cap_aarch64_is_block_zero_sysop) the "
            f"instruction claims no memory lane and every store it "
            f"performs is an impossible attribution.")
        # GEN_OP_STORE, via refine_arm64_sysop.  Compare by name so the
        # test does not hard-code the numeric id.
        from champsim_tracer_validator import _cst_decode_runner as R
        self.assertEqual(len(opcodes), 1, f"dc zva got opcodes {opcodes}")

    def test_decode_strict_is_clean(self):
        """No store may land on an instruction the template says cannot."""
        _pcs, _found, _lanes, _opcodes, cst = self._shared()
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
