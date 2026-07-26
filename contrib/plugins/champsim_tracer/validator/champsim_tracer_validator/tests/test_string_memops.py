"""x86 string instructions fan out their REP iterations and record memops.

A ``rep``-prefixed string instruction is one architectural instruction that
performs one memory access per iteration.  The tracer models that by fanning
one TB execution out into N body entries, and it decides *how many* memops
belong to each iteration from the Capstone access flags on the instruction's
MEM operands -- ``rep_loads_per_iter`` / ``rep_stores_per_iter`` in
``champsim_tracer_decode.cc``.  When Capstone reports a MEM operand with
``access == 0`` those counters stay at zero, the per-iteration memop count
``mpi`` is zero, and ``champsim_tracer.cc`` skips the fan-out entirely: the
whole repeated string operation collapses to a single body entry carrying no
per-iteration records and no memops at all.

Capstone 6.0.0-Alpha7 does exactly that to ``CMPS`` at 32-bit operand size
(``cmpsl``, opcode ``A7`` with neither ``66`` nor ``REX.W``) -- both MEM
operands come back ``access == 0`` -- while ``cmpsb`` / ``cmpsw`` / ``cmpsq``
are reported correctly.  ``disas/capstone.c`` corrects it; without that
correction the ``cmpsl`` half of this test records zero memops.

The same file corrects two more ``access == 0`` defects that this test pins
from the other direction, because they are *loads that would silently
disappear* rather than fan-out failures: the MEM source operand of the
scalar ``ROUNDSS`` / ``ROUNDSD`` (the packed ``ROUNDPS`` / ``ROUNDPD`` forms
are reported correctly), and the phantom READ that the same version puts on
the memory operand of the multi-byte ``NOP`` -- an instruction that
architecturally performs no memory access at all.

The assertions are tiling ones, matching ``test_mops_memops.py``: the loads
of each string instruction must cover its buffer exactly -- contiguous, no
gap, no overlap, natural alignment -- which pins addresses, sizes and the
iteration count all at once rather than just a count.

Against a pre-fix build ``cmpsl`` records no memops and no fan-out, ``roundss``
records no load, and ``nop`` claims a load slot it never fills, so this FAILS.

Point it at any build with ``CST_BUILD_DIR=/path/to/build``.  Skips when
``qemu-x86_64`` or a native x86-64 toolchain is absent.

Run standalone:
  python tests/test_string_memops.py
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
QEMU_BIN = BUILD_DIR / "qemu-x86_64"

CC = os.environ.get("CST_X86_CC", "gcc")
NM = os.environ.get("CST_X86_NM", "nm")

#: Bytes touched by each string instruction under test.  256 keeps the trace
#: small while still making the tiling assertion meaningful (256 one-byte
#: iterations, or 64 four-byte ones).
NBYTES = 256

PROGRAM = r"""
    .bss
    .balign 4096
bufA:   .skip 4096
bufB:   .skip 4096
bufC:   .skip 4096
bufD:   .skip 4096
    .balign 16
fpsrc:  .skip 16

    .text
    .globl _start
_start:
    cld

    /* ---- repz cmpsb: 2 loads/iter, 1 byte each ----------------------
     * .bss is zero-filled, so bufA and bufB compare equal for the whole
     * count and all %(n)d iterations run.  AT&T operand order is
     * (%%rsi),(%%rdi) -> ES:(%%rdi) is the first MEM operand. */
    lea  bufA(%%rip), %%rsi
    lea  bufB(%%rip), %%rdi
    mov  $%(n)d, %%rcx
    .globl pc_cmpsb
pc_cmpsb:
    repz cmpsb

    /* ---- repz cmpsl: 2 loads/iter, 4 bytes each ---------------------
     * Opcode A7 with neither 66 nor REX.W.  This is the encoding whose
     * MEM operands Capstone 6.0.0-Alpha7 reports access == 0. */
    lea  bufA(%%rip), %%rsi
    lea  bufB(%%rip), %%rdi
    mov  $%(n4)d, %%rcx
    .globl pc_cmpsl
pc_cmpsl:
    repz cmpsl

    /* ---- repnz scasb: 1 load/iter, 1 byte each ----------------------
     * Scan a zero buffer for 0xff, which is never there, so the count
     * runs out and all %(n)d iterations execute. */
    lea  bufC(%%rip), %%rdi
    mov  $%(n)d, %%rcx
    mov  $0xff, %%al
    .globl pc_scasb
pc_scasb:
    repnz scasb

    /* ---- rep lodsb: 1 load/iter (control, reported correctly) ------- */
    lea  bufC(%%rip), %%rsi
    mov  $%(n)d, %%rcx
    .globl pc_lodsb
pc_lodsb:
    rep lodsb

    /* ---- rep stosb: 1 store/iter (control, inverted-flag workaround) */
    lea  bufD(%%rip), %%rdi
    mov  $%(n)d, %%rcx
    xor  %%eax, %%eax
    .globl pc_stosb
pc_stosb:
    rep stosb

    /* ---- rep movsb: 1 load + 1 store/iter (control, correct) -------- */
    lea  bufA(%%rip), %%rsi
    lea  bufD(%%rip), %%rdi
    mov  $%(n)d, %%rcx
    .globl pc_movsb
pc_movsb:
    rep movsb

    /* ---- roundss m32, xmm: exactly one 4-byte load ------------------ */
    lea  fpsrc(%%rip), %%rax
    .globl pc_roundss
pc_roundss:
    roundss $0, (%%rax), %%xmm1

    /* ---- roundsd m64, xmm: exactly one 8-byte load ------------------ */
    .globl pc_roundsd
pc_roundsd:
    roundsd $0, (%%rax), %%xmm2

    /* ---- multi-byte NOP with a memory operand: NO memory access -----
     * Intel SDM: the multi-byte NOP does not access memory.  Capstone
     * 6.0.0-Alpha7 reports its MEM operand READ anyway. */
    .globl pc_nop
pc_nop:
    nopw 0(%%rax,%%rax,1)

    /* exit(0) */
    mov  $60, %%eax
    xor  %%edi, %%edi
    syscall
""" % {"n": NBYTES, "n4": NBYTES // 4}


#: label -> (loads/iter, bytes/access, stores/iter)
EXPECT = {
    "pc_cmpsb":   (2, 1, 0),
    "pc_cmpsl":   (2, 4, 0),
    "pc_scasb":   (1, 1, 0),
    "pc_lodsb":   (1, 1, 0),
    "pc_stosb":   (0, 1, 1),
    "pc_movsb":   (1, 1, 1),
}

#: label -> (n_loads, n_stores) the template must declare.  These are the
#: static lane counts the operand walker derives from the Capstone access
#: flags; they are what a consumer sizes its load/store queues from, and
#: what ``cst_decode --strict`` checks each observed memop against.
EXPECT_LANES = {
    "pc_cmpsb":   (2, 0),
    "pc_cmpsl":   (2, 0),
    "pc_scasb":   (1, 0),
    "pc_lodsb":   (1, 0),
    "pc_stosb":   (0, 1),
    "pc_movsb":   (1, 1),
    "pc_roundss": (1, 0),
    "pc_roundsd": (1, 0),
    # The multi-byte NOP performs no memory access, so it must claim
    # neither lane.
    "pc_nop":     (0, 0),
}


def _label_pcs(binary: Path) -> dict:
    """Map pc_* label -> address, from the binary's symbol table."""
    out = subprocess.run([NM, str(binary)], text=True,
                         capture_output=True).stdout
    pcs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2].startswith("pc_"):
            pcs[parts[2]] = int(parts[0], 16)
    return pcs


def _tiling_error(accs, base, size, what):
    """Return None if @accs tiles [base, base+size) exactly, else why not.

    @accs is a list of (address, nbytes).  Order is not required, but every
    piece must be naturally aligned, at most 16 bytes, and the pieces
    together must cover the range with no gap and no overlap.
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


@unittest.skipUnless(shutil.which(CC), f"{CC} not found")
@unittest.skipUnless(shutil.which(NM), f"{NM} not found")
@unittest.skipUnless(QEMU_BIN.is_file(), f"{QEMU_BIN} not built")
@unittest.skipUnless(PLUGIN_SO.is_file(), f"{PLUGIN_SO} not built")
class StringMemopsTest(unittest.TestCase):

    def _capture(self, work: Path):
        """Assemble, trace, and return (pcs, per-label memops, templates)."""
        from champsim_tracer_validator import _cst_decode_runner as R

        src = work / "strops.S"
        src.write_text(PROGRAM)
        binp = work / "strops"
        build = subprocess.run(
            [CC, "-static", "-nostdlib", "-nostartfiles", "-O1",
             "-fno-asynchronous-unwind-tables", str(src), "-o", str(binp)],
            text=True, capture_output=True)
        self.assertEqual(build.returncode, 0,
                         f"assembling the probe failed:\n{build.stderr[-800:]}")

        pcs = _label_pcs(binp)
        missing = [k for k in list(EXPECT) + ["pc_roundss", "pc_roundsd",
                                              "pc_nop"] if k not in pcs]
        self.assertFalse(missing, f"symbol table did not show {missing}")

        out = work / "strops"
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
        pc_of = {v: k for k, v in pcs.items()}
        found = {k: {"load": [], "store": []} for k in pc_of.values()}
        # Template-declared static lane counts, keyed the same way.
        lanes = {}
        for t in templates:
            for ins in (t.get("insns") or []):
                lbl = pc_of.get(int(ins.get("pc", -1)))
                if lbl is not None:
                    lanes.setdefault(lbl, set()).add(
                        (int(ins.get("n_loads", 0) or 0),
                         int(ins.get("n_stores", 0) or 0)))
        # Per-body-entry memop counts, so the REP fan-out can be checked:
        # a fanned-out REP puts one iteration's worth of memops on each
        # entry, an unfanned one puts the whole run on a single entry.
        per_entry = {k: [] for k in pc_of.values()}
        for e in entries:
            tmpl = by_id.get(e.get("template_id")) or {}
            insns = tmpl.get("insns") or []
            here = {}
            for dp in (e.get("dyn_params") or []):
                i = int(getattr(dp, "insn_index", -1))
                if not (0 <= i < len(insns)):
                    continue
                lbl = pc_of.get(int(insns[i].get("pc", -1)))
                if lbl is None:
                    continue
                kind = getattr(dp, "type_name", "")
                if kind in ("load", "store"):
                    found[lbl][kind].append(
                        (int(dp.value), int(dp.data_size)))
                    here[lbl] = here.get(lbl, 0) + 1
            for lbl, n in here.items():
                per_entry[lbl].append(n)
        return pcs, found, lanes, per_entry, cst

    #: One capture serves every assertion; the program is deterministic.
    _cap = None

    def _shared(self):
        if StringMemopsTest._cap is None:
            td = tempfile.mkdtemp(prefix="string_memops.")
            self.addClassCleanup(shutil.rmtree, td, ignore_errors=True)
            StringMemopsTest._cap = self._capture(Path(td))
        return StringMemopsTest._cap

    def test_rep_string_ops_fan_out_per_iteration(self):
        """Each REP iteration is its own body entry carrying its own memops."""
        _pcs, found, _lanes, per_entry, _cst = self._shared()

        for lbl, (nld, width, nst) in EXPECT.items():
            mpi = nld + nst
            iters = NBYTES // width
            counts = per_entry[lbl]

            self.assertTrue(
                counts,
                f"{lbl}: no body entry carried a memop at all")
            # The fan-out puts exactly mpi memops on every entry.  Without
            # it the whole run lands on one entry -- which is what a build
            # without the CMPS access-flag correction does to cmpsl.
            self.assertEqual(
                max(counts), mpi,
                f"{lbl}: an entry carries {max(counts)} memops but one REP "
                f"iteration is {mpi}.  The REP fan-out did not engage: the "
                f"MEM operands came back from Capstone with access == 0, so "
                f"rep_{{loads,stores}}_per_iter stayed zero and mpi was zero "
                f"(disas/capstone.c cap_x86_string_mem_access).")
            self.assertEqual(
                len(counts), iters,
                f"{lbl}: {len(counts)} body entries carried memops, "
                f"expected one per iteration ({iters})")

    def test_rep_string_ops_tile_their_buffers(self):
        """Per-iteration memops cover each buffer exactly, once."""
        _pcs, found, _lanes, _per_entry, _cst = self._shared()

        for lbl, (nld, width, nst) in EXPECT.items():
            ld, st = found[lbl]["load"], found[lbl]["store"]
            iters = NBYTES // width

            self.assertEqual(
                len(ld), nld * iters,
                f"{lbl}: {len(ld)} loads, expected "
                f"{nld} per iteration x {iters} iterations")
            self.assertEqual(
                len(st), nst * iters,
                f"{lbl}: {len(st)} stores, expected "
                f"{nst} per iteration x {iters} iterations")

            # Tiling, per distinct buffer the instruction touched.  Each
            # buffer is its own page, so the page base separates the lanes.
            for kind, accs, nlane in (("load", ld, nld), ("store", st, nst)):
                if not accs:
                    continue
                bases = sorted({a & ~0xfff for a, _n in accs})
                self.assertEqual(
                    len(bases), nlane,
                    f"{lbl}: {kind}s span {len(bases)} buffers, expected "
                    f"{nlane}")
                for b in bases:
                    part = [(a, n) for a, n in accs if a & ~0xfff == b]
                    err = _tiling_error(part, b, NBYTES,
                                        f"{lbl} {kind}s at 0x{b:x}")
                    self.assertIsNone(err, err)

    def test_templates_declare_the_right_memory_lanes(self):
        """The static lane model matches what the instruction really does."""
        _pcs, _found, lanes, _per_entry, _cst = self._shared()

        why = {
            "pc_cmpsl": "both MEM operands of the 32-bit CMPS come back "
                        "access == 0 (cap_x86_string_mem_access)",
            "pc_roundss": "the MEM source of the scalar ROUNDSS comes back "
                          "access == 0 (cap_x86_is_scalar_round)",
            "pc_roundsd": "the MEM source of the scalar ROUNDSD comes back "
                          "access == 0 (cap_x86_is_scalar_round)",
            "pc_nop": "the multi-byte NOP performs no memory access at all "
                      "(Intel SDM), but its MEM operand comes back READ "
                      "(cap_x86_mem_is_never_accessed)",
        }
        for lbl, want in EXPECT_LANES.items():
            got = lanes.get(lbl)
            self.assertEqual(
                got, {want},
                f"{lbl}: template declares (n_loads, n_stores) = {got}, "
                f"expected {{{want}}}.  "
                f"{why.get(lbl, 'wrong Capstone access flags')} "
                f"-- see disas/capstone.c.")

    def test_scalar_round_records_its_load(self):
        _pcs, found, _lanes, _per_entry, _cst = self._shared()

        for lbl, width in (("pc_roundss", 4), ("pc_roundsd", 8)):
            ld = found[lbl]["load"]
            self.assertEqual(
                len(ld), 1,
                f"{lbl}: {len(ld)} loads, expected exactly 1")
            self.assertEqual(ld[0][1], width,
                             f"{lbl}: load width {ld[0][1]}, expected {width}")

    def test_multibyte_nop_touches_no_memory(self):
        _pcs, found, _lanes, _per_entry, _cst = self._shared()

        self.assertEqual(
            found["pc_nop"]["load"], [],
            "the multi-byte NOP recorded a load; it performs no memory "
            "access (Intel SDM)")
        self.assertEqual(found["pc_nop"]["store"], [], "same, for stores")

    def test_decode_strict_is_clean(self):
        """No memop may land on an instruction the template says cannot.

        This is the same gate the shipped traces are held to.  A build
        without the access-flag corrections fails it here: every load of
        the unfanned ``cmpsl`` and the two scalar ``round`` loads are
        attributed to instructions declaring no load lane.
        """
        _pcs, _found, _lanes, _per_entry, cst = self._shared()
        decode = BUILD_DIR / "contrib" / "plugins" / "cst_decode"
        if not decode.is_file():
            self.skipTest("cst_decode not built")
        r = subprocess.run([str(decode), "--strict", "--verify-branch",
                            str(cst)], text=True, capture_output=True)
        self.assertEqual(r.returncode, 0,
                         f"cst_decode --strict --verify-branch failed:\n"
                         f"{r.stderr[-800:]}")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    unittest.main(verbosity=2)
