"""A MIPS identity or constant-folded form still reads and writes its registers.

Several MIPS arithmetic/logic forms carry their whole dataflow in a TCG op
that QEMU's lowering then erases, so the recovered op stream was short of a
register the instruction demonstrably uses:

* **Identity moves.**  ``addiu $rX,$rX,0``, ``ori $rX,$rX,0``,
  ``xori $rX,$rX,0`` and ``subu $rX,$rX,$zero`` are ``move $rX,$rX``.  QEMU
  lowers each to ``tcg_gen_mov_tl(rX, rX)``, which emits **nothing** when its
  destination and source are the same TCG global (and the ``ext32s`` that
  trails the 32-bit adds is the same self-move).  The instruction still reads
  ``$rX`` and still writes it; the op stream named neither, so the wire
  published no register at all.

* **Constant folds.**  ``mul $rd,$rs,$zero``, ``and $rd,$rs,$zero`` and
  ``andi $rt,$rs,0`` produce 0 whatever ``$rs`` holds, so QEMU emits a
  ``movi`` to the destination and no op names ``$rs``.  The destination is
  written (by the ``movi``) but the read of ``$rs`` -- which the machine
  performs -- was lost.

The fix (``target/mips/tcg/translate.c``, ``note_identity_move()`` /
``note_folded_operands()``, commit 40b2d45b25) states the elided read (and,
for the identity forms, the elided write) at the decode site, guarded on
exactly the elision.

``mul $rd,$rs,$zero`` is the form the golden-fix wave fixed in code with no
probe executing it; this test's headline cell executes it.  The identity and
AND/ANDI folds are covered in the same program so the whole fix carries a
standing, executing witness.

Precision matters here: a register-register form with a ``$zero`` operand
publishes ``REG_ZERO`` in its source list whether or not the fix fired (the
``$zero`` operand is noted independently), so "source non-empty" is NOT the
test -- the fix adds the *non-zero* operand (``$rs``) the fold reads.  Each
cell therefore asserts the exact register the fix restores:

* fold cells: the non-``$zero`` operand register is present in the source
  set (``mul $4,$5,$0`` -> ``REG_GPR5``; ``andi`` has no ``$zero`` operand,
  so on a pre-fix build its source set is empty outright);
* identity cells: the destination register is present in BOTH the source and
  destination sets -- the self-move reads what it writes.

Firing proof.  Against a build with the fix reverted, the fold cells'
non-``$zero`` register is absent (``mul``/``and`` keep only ``REG_ZERO``,
``andi`` is empty) and the identity cells publish empty source AND
destination sets, so every assertion below FAILS.  Against the fixed build
each cell names the register the instruction reads (and writes).

Point it at any build with ``CST_BUILD_DIR=/path/to/build``.  Skips when the
mipsel cross toolchain or ``qemu-mipsel`` is absent.

Run standalone:
  python tests/test_mips_identity_regs.py
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
    # tests/ -> champsim_tracer_validator/ -> validator/ -> champsim_tracer/
    # -> plugins/ -> contrib/ -> repo
    return Path(__file__).resolve().parents[6] / "build"


BUILD_DIR = _find_build_dir()
PLUGIN_SO = BUILD_DIR / "contrib" / "plugins" / "libchampsim_tracer.so"
QEMU_BIN = BUILD_DIR / "qemu-mipsel"

CROSS_CC = os.environ.get("CROSS_CC_MIPS", "mipsel-linux-gnu-gcc")
CROSS_OBJDUMP = os.environ.get("CROSS_OBJDUMP_MIPS", "mipsel-linux-gnu-objdump")

# Each target instruction is labelled so the expected register is recovered
# by position.  Setup registers are given real values with `ori $rX,$zero,
# imm` (not a form under test: rs == $zero takes the note_zero_reg() arm).
# `.set noreorder`/`noat` keep the assembler from reordering or expanding
# these into something that moves the labels.
PROGRAM = r"""
    .text
    .set noreorder
    .set noat
    .globl _start
    .globl __start               /* ld's default entry symbol for this target */
_start:
__start:
    ori   $5,  $0, 0x1234        /* $a1 */
    ori   $7,  $0, 0x5678        /* $a3 */
    ori   $8,  $0, 0x0007        /* $t0 */
    ori   $10, $0, 0x00ff        /* $t2 */
    ori   $12, $0, 0x4000        /* $t4 */
    ori   $13, $0, 0x0009        /* $t5 */
    ori   $14, $0, 0x000b        /* $t6 */
    ori   $19, $0, 0x002a        /* $s3 */

    /* --- constant folds (read restored) --- */
    .globl pc_mul_rtz
pc_mul_rtz:
    mul   $4,  $5,  $0           /* rt=$zero: folded to 0, reads $a1 */
    .globl pc_mul_rsz
pc_mul_rsz:
    mul   $6,  $0,  $7           /* rs=$zero: folded to 0, reads $a3 */
    .globl pc_andi0
pc_andi0:
    andi  $9,  $10, 0            /* imm=0: folded to 0, reads $t2 */
    .globl pc_and_z
pc_and_z:
    and   $11, $19, $0           /* rt=$zero: folded to 0, reads $s3 */

    /* --- identity moves (read AND write restored) --- */
    .globl pc_addiu0
pc_addiu0:
    addiu $8,  $8,  0            /* move $t0,$t0 */
    .globl pc_ori0
pc_ori0:
    ori   $13, $13, 0            /* move $t5,$t5 */
    .globl pc_xori0
pc_xori0:
    xori  $14, $14, 0            /* move $t6,$t6 */
    .globl pc_subu_z
pc_subu_z:
    subu  $12, $12, $0           /* move $t4,$t4 */

    /* exit(0) */
    ori   $4,  $0, 0
    ori   $2,  $0, 4001          /* __NR_exit (o32) */
    syscall
    nop
"""

# label -> (kind, the register the fix restores).  "fold" restores the read
# of this register; "ident" restores read AND write of it.
EXPECT = {
    "pc_mul_rtz": ("fold",  "REG_GPR5"),
    "pc_mul_rsz": ("fold",  "REG_GPR7"),
    "pc_andi0":   ("fold",  "REG_GPR10"),
    "pc_and_z":   ("fold",  "REG_GPR19"),
    "pc_addiu0":  ("ident", "REG_GPR8"),
    "pc_ori0":    ("ident", "REG_GPR13"),
    "pc_xori0":   ("ident", "REG_GPR14"),
    "pc_subu_z":  ("ident", "REG_GPR12"),
}
ALL_FORMS = list(EXPECT)


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
class MipsIdentityRegsTest(unittest.TestCase):

    _cap = None

    def _capture(self, work: Path):
        from champsim_tracer_validator import _cst_decode_runner as R

        # Decode with the build-under-test's OWN decoder, pinned on the
        # channel that never reaches the guest (not via CST_DECODE in the
        # environment, which would move the guest stack).
        decode = BUILD_DIR / "contrib" / "plugins" / "cst_decode"
        if decode.is_file():
            R.set_cst_decode(decode)

        src = work / "midr.S"
        src.write_text(PROGRAM)
        binp = work / "midr"
        build = subprocess.run(
            [CROSS_CC, "-static", "-nostdlib", "-nostartfiles",
             "-march=mips32r2", "-EL", "-fno-asynchronous-unwind-tables",
             str(src), "-o", str(binp)],
            text=True, capture_output=True)
        self.assertEqual(build.returncode, 0,
                         f"assembling the probe failed:\n{build.stderr[-800:]}")

        pcs = _label_pcs(binp)
        for lbl in ALL_FORMS:
            self.assertIn(lbl, pcs, f"symbol table did not show {lbl}")

        out = work / "midr"
        run = subprocess.run(
            [str(QEMU_BIN), "-seed", "4242", "-plugin",
             f"{PLUGIN_SO},outfile={out},wpdepth=8",
             str(binp)], text=True, capture_output=True)
        cst = Path(f"{out}.cst")
        self.assertEqual(run.returncode, 0,
                         f"guest exited {run.returncode}\n{run.stderr[-600:]}")
        self.assertTrue(cst.is_file(), "tracer produced no .cst")

        meta, templates, _entries = R.decode_champsim_tracer(cst)
        regmap = meta.get("reg_names", {})  # id -> name

        # Collect, per labelled PC, the source/destination register NAME sets
        # of every template-insn landing there.  The fix is at decode time,
        # so a CP template and any WP-minted copy agree.
        want = {pc: lbl for lbl, pc in pcs.items()}
        by_label: dict = {lbl: [] for lbl in ALL_FORMS}
        for t in templates:
            for ins in (t.get("insns") or []):
                lbl = want.get(int(ins.get("pc", -1)))
                if lbl is None:
                    continue
                srcn = {regmap.get(r, str(r)) for r in ins["src_regs"]}
                dstn = {regmap.get(r, str(r)) for r in ins["dst_regs"]}
                by_label[lbl].append((srcn, dstn))
        return pcs, by_label, cst

    def _shared(self):
        if MipsIdentityRegsTest._cap is None:
            td = tempfile.mkdtemp(prefix="mips_identity_regs.")
            self.addClassCleanup(shutil.rmtree, td, ignore_errors=True)
            MipsIdentityRegsTest._cap = self._capture(Path(td))
        return MipsIdentityRegsTest._cap

    def test_every_form_was_traced(self):
        _pcs, by_label, _cst = self._shared()
        for lbl in ALL_FORMS:
            self.assertTrue(
                by_label[lbl],
                f"{lbl} never appeared in any template -- the probe did not "
                f"execute the form")

    def test_folded_forms_restore_the_read(self):
        """mul/and/andi folded to a constant by a $zero operand still read the
        non-$zero operand.  A pre-fix build keeps only REG_ZERO (mul/and) or
        an empty source (andi)."""
        _pcs, by_label, _cst = self._shared()
        for lbl in ("pc_mul_rtz", "pc_mul_rsz", "pc_andi0", "pc_and_z"):
            reg = EXPECT[lbl][1]
            for srcn, _dstn in by_label[lbl]:
                self.assertIn(
                    reg, srcn,
                    f"{lbl}: the fold's read of {reg} was lost -- source set "
                    f"{sorted(srcn)} (target/mips note_folded_operands).  "
                    f"REG_ZERO alone is the $zero operand, not the fix")

    def test_identity_forms_restore_read_and_write(self):
        """move $rX,$rX via addiu/ori/xori-0 or subu-$zero reads AND writes
        $rX; both sets lack $rX on a pre-fix build (addiu/ori/xori publish
        nothing; subu keeps only REG_ZERO)."""
        _pcs, by_label, _cst = self._shared()
        for lbl in ("pc_addiu0", "pc_ori0", "pc_xori0", "pc_subu_z"):
            reg = EXPECT[lbl][1]
            for srcn, dstn in by_label[lbl]:
                self.assertIn(
                    reg, dstn,
                    f"{lbl}: the elided self-move's WRITE of {reg} was not "
                    f"restored -- dst {sorted(dstn)} "
                    f"(target/mips note_identity_move)")
                self.assertIn(
                    reg, srcn,
                    f"{lbl}: the elided self-move's READ of {reg} was not "
                    f"restored -- src {sorted(srcn)} "
                    f"(target/mips note_identity_move)")

    def test_decode_strict_is_clean(self):
        _pcs, _by_label, cst = self._shared()
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
