"""A REP's fan-out shape is architectural, not a function of how QEMU ran it.

``do_gen_rep`` in ``target/i386/tcg/translate.c`` decides at TRANSLATION time
whether a REP-prefixed string operation loops at all::

    can_loop = !(tb_cflags & (CF_USE_ICOUNT | CF_SINGLE_STEP))
               && !(s->flags & (HF_TF_MASK | HF_INHIBIT_IRQ_MASK))

With ``can_loop`` false QEMU generates exactly one iteration and jumps back to
the instruction's own address, so a REP of N iterations arrives at the tracer
as N separate executions instead of one -- and, because that jump back happens
even after the iteration that exhausted the counter, as one *extra* execution
that performs no architectural work at all.

Counting iterations from delivered memory-op callbacks makes the trace inherit
all of that.  The extra pass becomes an extra architectural instruction, and
the last real iteration's successor becomes the REP's own PC instead of the
fall-through.  Both appear and disappear with a setting -- ``-icount``,
single-step, EFLAGS.TF, the interrupt shadow -- for guest execution that never
changed.  The count therefore comes from the loop counter itself, published by
QEMU as ``qemu_plugin_rep_iterations()`` / ``_complete()`` / ``_reenter()``.

Three things are pinned here.

**Translation invariance.**  Two binaries with byte-identical layout, one of
which precedes each REP with a MOV to SS.  That sets the interrupt shadow, so
the instruction after it translates with ``can_loop == false`` -- the same
condition ``-icount`` creates, reachable in ``*-linux-user`` with no QEMU flag,
no trap and no signal, and with every REP at the same address in both
binaries.  The two traces must agree on how many entries render each REP, on
each entry's branch direction and target, and on the memops those entries
carry.

**Correct path vs wrong path.**  ``cpu_plugin_exec_tb`` sets
``CF_SINGLE_STEP``, so every REP on the wrong path is translated one iteration
per TB whether or not the correct path's copy loops.  Nothing outside this
check can catch a divergence there: external references validate the correct
path only.  One REP is therefore reached both ways -- through a wrong-path
excursion and, at the same address with the same counter, on the correct path
-- and the two renderings must match block for block.

**Architectural truth.**  The number of entries rendering each REP must equal
the iteration count its ECX dictates, not one more and not one less.

**Window-clock invariance** (maintainer ruling, 2026-07-29).  The marker
window's user-instruction clock counts architectural instructions: a REP is
one tick however many executions QEMU splits it into, so a marker window
covers the same user instructions with ``-icount`` as without it.  Verified
with a real system boot of a marker-bracketed probe under both clocks —
``user_covered`` must be EQUAL — with the lever proven from the same close
line (``rep_fanout`` collapses to 0 under icount) and the deferred-emission
guarantee asserted where it was measured to fail: ``REP iters inferred from
memops`` must be 0 in BOTH arms, including the no-icount system arm whose
fault-deferred emissions once fell back.  Skipped when the system harness
(kernel + busybox root at /mnt/md0/QEMU/systest) is absent.

The lever is verified before anything is concluded from it: if the MOV to SS
did not actually change how QEMU translated the REPs, this check FAILS rather
than passing on a comparison of a run against itself.

Point it at any build with ``CST_BUILD_DIR=/path/to/build``.  Skips when
``qemu-x86_64`` or a native x86-64 toolchain is absent.

Run standalone:
  python tests/test_rep_fanout_invariance.py
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

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def _find_build_dir() -> Path:
    env = os.environ.get("CST_BUILD_DIR") or os.environ.get("BUILD_DIR")
    if env:
        return Path(env).resolve()
    # tests/ -> champsim_tracer_validator/ -> validator/ -> champsim_tracer/
    # -> plugins/ -> contrib/ -> repo
    return Path(__file__).resolve().parents[6] / "build"


BUILD_DIR = _find_build_dir()
QEMU_BIN = BUILD_DIR / "qemu-x86_64"
PLUGIN_SO = BUILD_DIR / "contrib" / "plugins" / "libchampsim_tracer.so"
CC = os.environ.get("CST_CC", "gcc")
NM = os.environ.get("CST_NM", "nm")

#: The interrupt-shadow lever.  ``mov %ss,%bx`` / ``mov %bx,%ss`` sets
#: HF_INHIBIT_IRQ_MASK for the following instruction; ``%ds`` does not.  Both
#: pairs assemble to the same lengths (66 8c dX / 8e dX), so the two binaries
#: have identical layout and every REP sits at the same address in both.
#:
#: %bx, not %ax: the shuttle writes its whole 16-bit destination, and the
#: SCAS probes compare against %al.  Using %ax would leave the two variants
#: scanning for different bytes -- different guest execution, which is
#: precisely what this check must not do.
SEG_CTL = ("mov %ds, %bx", "mov %bx, %ds")
SEG_TRG = ("mov %ss, %bx", "mov %bx, %ss")

#: label -> initial ECX -> architectural iteration count.
#:
#: An ECX-terminated REP performs exactly ECX iterations.  A REP entered with
#: ECX == 0 performs none but is still one retired instruction, so it renders
#: as a single entry.  A REPZ/REPNZ that breaks on its flag condition performs
#: as many iterations as it took to break.
#:
#: The ECX == 1 cases are the interesting ones for the lever: with can_loop
#: false the single generated iteration IS the whole instruction, so QEMU
#: retires the REP and then re-enters it once more -- the trailing pass -- with
#: no trap or signal anywhere in the guest.
EXPECT_ITERS = {
    "pc_movsb1":  1,    # rep movsb,  ECX=1
    "pc_stosb1":  1,    # rep stosb,  ECX=1
    "pc_movsb0":  1,    # rep movsb,  ECX=0 -> zero iterations, one instruction
    "pc_cmpsb1":  1,    # repz cmpsb, ECX=1
    "pc_movsb5":  5,    # rep movsb,  ECX=5
    "pc_scasb_x": 1,    # repnz scasb, ECX=200, matches on iteration 1
    "pc_cmpsb_x": 1,    # repz cmpsb, ECX=64, differs on iteration 1
}

#: memops per architectural iteration, from the instruction's MEM operands.
EXPECT_MPI = {
    "pc_movsb1":  2,    # 1 load + 1 store
    "pc_stosb1":  1,    # 1 store
    "pc_movsb0":  2,
    "pc_cmpsb1":  2,    # 2 loads
    "pc_movsb5":  2,
    "pc_scasb_x": 1,    # 1 load
    "pc_cmpsb_x": 2,    # 2 loads
}

PROGRAM = r"""
        .section .data
        .align 64
src:    .fill 256, 1, 0xA5
dst:    .fill 256, 1, 0x00
scan:   .byte 0x5a
        .fill 255, 1, 0x00

        .section .text
        .globl _start
_start:
        lea     src(%rip), %rsi
        lea     dst(%rip), %rdi
        mov     $1, %ecx
        {SEG_RD}
        {SEG_WR}
        .globl  pc_movsb1
pc_movsb1:
        rep movsb

        lea     dst(%rip), %rdi
        mov     $0x5a, %eax
        mov     $1, %ecx
        {SEG_RD}
        {SEG_WR}
        .globl  pc_stosb1
pc_stosb1:
        rep stosb

        lea     src(%rip), %rsi
        lea     dst(%rip), %rdi
        xor     %ecx, %ecx
        {SEG_RD}
        {SEG_WR}
        .globl  pc_movsb0
pc_movsb0:
        rep movsb

        lea     src(%rip), %rsi
        lea     src(%rip), %rdi
        mov     $1, %ecx
        {SEG_RD}
        {SEG_WR}
        .globl  pc_cmpsb1
pc_cmpsb1:
        repz cmpsb

        lea     src(%rip), %rsi
        lea     dst(%rip), %rdi
        mov     $5, %ecx
        {SEG_RD}
        {SEG_WR}
        .globl  pc_movsb5
pc_movsb5:
        rep movsb

        lea     scan(%rip), %rdi
        mov     $200, %ecx
        mov     $0x5a, %al
        {SEG_RD}
        {SEG_WR}
        .globl  pc_scasb_x
pc_scasb_x:
        repnz scasb

        lea     src(%rip), %rsi
        lea     scan(%rip), %rdi
        mov     $64, %ecx
        {SEG_RD}
        {SEG_WR}
        .globl  pc_cmpsb_x
pc_cmpsb_x:
        repz cmpsb

        mov     $231, %eax
        xor     %edi, %edi
        syscall
        hlt
"""

#: One REP reached both through a wrong-path excursion and, at the same
#: address with the same ECX, on the correct path.  The ``jz`` is taken on the
#: correct path, so the wrong-path walker explores its not-taken side -- the
#: REP -- and control then comes back round through ``around`` to run the very
#: same instruction for real.
WP_PROGRAM = r"""
        .section .data
        .align 64
src:    .fill 64, 1, 0xA5
dst:    .fill 64, 1, 0x00

        .section .text
        .globl _start
_start:
        lea     src(%rip), %rsi
        lea     dst(%rip), %rdi
        mov     $5, %ecx
        xor     %eax, %eax
        jz      around
        .globl  pc_wprep
pc_wprep:
        rep movsb
        jmp     done
around:
        lea     src(%rip), %rsi
        lea     dst(%rip), %rdi
        mov     $5, %ecx
        jmp     pc_wprep
done:
        mov     $231, %eax
        xor     %edi, %edi
        syscall
        hlt
"""

WP_REP_ITERS = 5
WP_REP_MPI = 2

_STATS_HEAD = re.compile(
    r"host_icount=(\d+)\s+traced_icount=(\d+)\s+rep_fanout=(\d+)")


def _label_pcs(binary: Path) -> dict:
    out = subprocess.run([NM, str(binary)], text=True,
                         capture_output=True).stdout
    pcs = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2].startswith("pc_"):
            pcs[parts[2]] = int(parts[0], 16)
    return pcs


@unittest.skipUnless(shutil.which(CC), f"{CC} not found")
@unittest.skipUnless(shutil.which(NM), f"{NM} not found")
@unittest.skipUnless(QEMU_BIN.is_file(), f"{QEMU_BIN} not built")
@unittest.skipUnless(PLUGIN_SO.is_file(), f"{PLUGIN_SO} not built")
class RepFanoutInvarianceTest(unittest.TestCase):

    # ------------------------------------------------------------------
    # plumbing
    # ------------------------------------------------------------------

    def _assemble(self, work: Path, name: str, source: str) -> Path:
        src = work / f"{name}.S"
        src.write_text(source)
        binp = work / name
        build = subprocess.run(
            [CC, "-static", "-nostdlib", "-nostartfiles", "-no-pie", "-O1",
             "-fno-asynchronous-unwind-tables", str(src), "-o", str(binp)],
            text=True, capture_output=True)
        self.assertEqual(build.returncode, 0,
                         f"assembling {name} failed:\n{build.stderr[-800:]}")
        return binp

    def _trace(self, work: Path, binp: Path, tag: str, wp: str):
        """Run the tracer and return (pcs, templates, entries, stats_text)."""
        from champsim_tracer_validator import _cst_decode_runner as R

        out = work / tag
        run = subprocess.run(
            [str(QEMU_BIN), "-plugin",
             f"{PLUGIN_SO},outfile={out},{wp},memdata=1,regdata=1",
             str(binp)],
            text=True, capture_output=True, timeout=600)
        self.assertEqual(run.returncode, 0,
                         f"{tag}: guest exited {run.returncode}\n"
                         f"{run.stderr[-800:]}")
        cst = Path(f"{out}.cst")
        self.assertTrue(cst.is_file(), f"{tag}: tracer produced no .cst")
        stats = Path(f"{out}.stats.log")
        self.assertTrue(stats.is_file(), f"{tag}: tracer produced no stats log")
        _meta, templates, entries = R.decode_champsim_tracer(cst)
        return templates, entries, stats.read_text()

    @staticmethod
    def _stat(stats_text: str, label: str) -> int:
        """Read one named counter out of the plugin's stats log.

        Raises if the counter is absent, so a renamed or removed counter
        surfaces as a failure rather than as a silent zero.
        """
        for line in stats_text.splitlines():
            if line.startswith(label):
                return int(line[len(label):].split()[0])
        raise AssertionError(f"stats log has no counter named {label!r}")

    @staticmethod
    def _host_icount(stats_text: str) -> int:
        m = _STATS_HEAD.search(stats_text)
        assert m, "stats log has no host_icount line"
        return int(m.group(1))

    @staticmethod
    def _reg_writes(templates, entries, rep_pc: int):
        """Destination-register writes the REP at @rep_pc publishes, per entry.

        Returns one integer per correct-path entry rendering that
        instruction, in order: how many of its destination slots carry a
        captured write.  A slot that carries one renders with a width
        (``:w=N``); a slot the instruction has not yet produced renders
        with no width at all, which is how the wire says "not yet".

        The contract (format.rst, fan-out sub-template rule 4) is that a
        self-looping instruction publishes its destination writes ONCE, on
        the entry where it completes -- so the expected shape is zeros
        followed by exactly one nonzero, at the end.
        """
        by_id = {t["template_id"]: t for t in templates}

        def carries_rep(tmpl):
            for i, ins in enumerate(tmpl.get("insns") or []):
                if int(ins.get("pc", -1)) == rep_pc:
                    return i
            return None

        out = []
        for e in entries:
            tmpl = by_id.get(e.get("template_id"))
            if tmpl is None:
                continue
            idx = carries_rep(tmpl)
            if idx is None:
                continue
            out.append(sum(
                1 for r in (e.get("reg_snaps") or [])
                if int(r.get("insn_index", -1)) == idx
                and r.get("kind") == "dst"
                and (r.get("width_bytes") or 0) > 0))
        return out

    @staticmethod
    def _render(templates, entries, rep_pc: int):
        """How the trace renders the REP at @rep_pc, on each path.

        Returns ``(cp, wp)``, each a list of one tuple per rendered
        execution of that instruction::

            (template_start_pc, n_insns, branch_taken, branch_target,
             ((addr, size, kind), ...))

        which together carry the fan-out count, the self-loop structure, the
        per-iteration direction/target sequence and the memops.
        """
        by_id = {t["template_id"]: t for t in templates}

        def carries_rep(tmpl):
            for i, ins in enumerate(tmpl.get("insns") or []):
                if int(ins.get("pc", -1)) == rep_pc:
                    return i
            return None

        def shape(tmpl, idx, taken, target, dyn):
            memops = tuple(sorted(
                (int(d.value), int(d.data_size or 0), d.type_name)
                for d in dyn if int(getattr(d, "insn_index", -1)) == idx))
            return (int(tmpl.get("start_pc", 0)), int(tmpl.get("n_insns", 0)),
                    taken, target, memops)

        cp, wp = [], []
        for e in entries:
            tmpl = by_id.get(e.get("template_id"))
            if tmpl is not None:
                idx = carries_rep(tmpl)
                if idx is not None:
                    cp.append(shape(tmpl, idx, e.get("branch_taken"),
                                    e.get("branch_target"),
                                    e.get("dyn_params") or []))
            for w in (e.get("wp_entries") or []):
                wt = by_id.get(w.get("template_id"))
                if wt is None:
                    continue
                idx = carries_rep(wt)
                if idx is not None:
                    wp.append(shape(wt, idx, None, None,
                                    w.get("dyn_params") or []))
        return cp, wp

    @staticmethod
    def _branch_types(templates, rep_pc: int):
        """Every branch_type the templates give the instruction at @rep_pc."""
        seen = set()
        for t in templates:
            for ins in (t.get("insns") or []):
                if int(ins.get("pc", -1)) == rep_pc:
                    seen.add(int(ins.get("branch_type", -1)))
        return seen

    # ------------------------------------------------------------------
    # the checks
    # ------------------------------------------------------------------

    def test_translation_invariance(self):
        """Same guest execution, can_loop true vs false, same rendering."""
        from champsim_tracer_validator import _cst_decode_runner as R

        with tempfile.TemporaryDirectory(prefix="cst_repinv_") as tmp:
            work = Path(tmp)
            ctl_bin = self._assemble(
                work, "rep_ctl",
                PROGRAM.replace("{SEG_RD}", SEG_CTL[0])
                       .replace("{SEG_WR}", SEG_CTL[1]))
            trg_bin = self._assemble(
                work, "rep_trg",
                PROGRAM.replace("{SEG_RD}", SEG_TRG[0])
                       .replace("{SEG_WR}", SEG_TRG[1]))

            ctl_pcs = _label_pcs(ctl_bin)
            trg_pcs = _label_pcs(trg_bin)
            self.assertEqual(
                ctl_pcs, trg_pcs,
                "the two variants must place every REP at the same address, "
                "otherwise this is not a comparison of the same execution; "
                "the DS and SS encodings are the same length, so a difference "
                "here means the probe source drifted")
            missing = [k for k in EXPECT_ITERS if k not in ctl_pcs]
            self.assertFalse(missing, f"symbol table did not show {missing}")

            # wp=0: this half is about the correct path only.  The wrong path
            # is compared separately, against the correct path, below.
            ctl_t, ctl_e, ctl_s = self._trace(work, ctl_bin, "ctl", "wp=0")
            trg_t, trg_e, trg_s = self._trace(work, trg_bin, "trg", "wp=0")

            # The lever must be shown to have engaged before anything is
            # concluded from the comparison.  Two independent witnesses:
            #
            #  - QEMU's own instruction count.  With can_loop false each
            #    iteration is a separate execution of the instruction, so the
            #    trigger run executes strictly more instructions than the
            #    control for the same guest program.  This witness does not
            #    depend on the tracer at all.
            #  - the tracer's trailing-pass counter, which can only be
            #    non-zero when a REP was re-entered after it had already
            #    retired -- i.e. exactly when can_loop was false.
            ctl_ic = self._host_icount(ctl_s)
            trg_ic = self._host_icount(trg_s)
            self.assertGreater(
                trg_ic, ctl_ic,
                "the interrupt-shadow lever did not change how QEMU "
                f"translated the REPs (host_icount {trg_ic} vs {ctl_ic}), so "
                "this comparison would be a run against itself and proves "
                "nothing.  Check that MOV to SS still reaches "
                "DISAS_EOB_INHIBIT_IRQ in target/i386/tcg/translate.c")
            trailing = self._stat(trg_s, "REP trailing pass dropped")
            self.assertGreater(
                trailing, 0,
                "no REP was seen re-entered after retiring, so can_loop was "
                "never false and the invariance below is untested")
            self.assertEqual(
                self._stat(ctl_s, "REP trailing pass dropped"), 0,
                "the control run should have no trailing passes: its REPs "
                "were translated as loops")

            # No REP may fall back to counting delivered memops on x86.
            for tag, s in (("control", ctl_s), ("trigger", trg_s)):
                self.assertEqual(
                    self._stat(s, "REP iters inferred from memops"), 0,
                    f"{tag} run counted a REP's iterations from delivered "
                    "memops instead of from the loop counter; the "
                    "architectural count did not reach the emission")

            for label, want_iters in EXPECT_ITERS.items():
                pc = ctl_pcs[label]
                ctl_cp, _ = self._render(ctl_t, ctl_e, pc)
                trg_cp, _ = self._render(trg_t, trg_e, pc)

                self.assertEqual(
                    len(ctl_cp), want_iters,
                    f"{label}: the loop-translated run rendered "
                    f"{len(ctl_cp)} entries for a REP that performs "
                    f"{want_iters} architectural iteration(s)")
                self.assertEqual(
                    ctl_cp, trg_cp,
                    f"{label}: the trace's rendering of this REP changed "
                    f"with how QEMU translated it.\n"
                    f"  can_loop=true : {ctl_cp}\n"
                    f"  can_loop=false: {trg_cp}\n"
                    "Each tuple is (template start_pc, template n_insns, "
                    "branch_taken, branch_target, memops).  A length "
                    "difference is a fabricated or lost architectural "
                    "instruction; a target difference is a self-loop edge "
                    "taken from observation instead of from the instruction.")

                self.assertEqual(
                    self._branch_types(ctl_t, pc),
                    self._branch_types(trg_t, pc),
                    f"{label}: the instruction's branch_type differs between "
                    "the two translations")

                # The register contract, in both translation regimes.
                # Its whole point is that it does NOT depend on how QEMU
                # chose to translate the instruction: a REP publishes one
                # set of destination writes, on the entry that completes
                # it, whether the loop ran as one execution or as N.
                ctl_w = self._reg_writes(ctl_t, ctl_e, pc)
                trg_w = self._reg_writes(trg_t, trg_e, pc)
                self.assertEqual(
                    ctl_w, trg_w,
                    f"{label}: where this REP publishes its destination "
                    f"register writes changed with how QEMU translated "
                    f"it.\n  can_loop=true : {ctl_w}\n"
                    f"  can_loop=false: {trg_w}\n"
                    "Each number is how many destination slots that entry "
                    "carries a captured write for.  A regime-dependent "
                    "answer means the wire's register content is a "
                    "function of a QEMU setting, not of the guest.")
                for tag, w in (("can_loop=true", ctl_w),
                               ("can_loop=false", trg_w)):
                    self.assertTrue(
                        all(x == 0 for x in w[:-1]),
                        f"{label} ({tag}): an iteration before the last "
                        f"published a destination register write: {w}.  "
                        "The intermediate values of a self-looping "
                        "instruction are not architectural results -- "
                        "publishing them invents rename pressure and a "
                        "serial dependency chain the hardware never has.")
                    self.assertGreater(
                        w[-1], 0,
                        f"{label} ({tag}): the entry that COMPLETES this "
                        f"REP published no destination register write: "
                        f"{w}.  The instruction's architectural result "
                        "reached no entry at all, so a consumer cannot "
                        "see what it produced.")

                mpi = EXPECT_MPI[label]
                for shape in ctl_cp:
                    memops = shape[4]
                    self.assertLessEqual(
                        len(memops), mpi,
                        f"{label}: an entry carries {len(memops)} memops for "
                        f"an instruction that performs {mpi} per iteration -- "
                        "the fan-out did not split this execution")

    def test_correct_path_and_wrong_path_agree(self):
        """One REP, reached both ways, must be rendered the same both ways.

        cpu_plugin_exec_tb sets CF_SINGLE_STEP, so the wrong path always sees
        the single-iteration translation while the correct path sees the
        looping one.  Nothing else in the suite can catch a divergence here:
        every external reference validates the correct path only.
        """
        with tempfile.TemporaryDirectory(prefix="cst_repwp_") as tmp:
            work = Path(tmp)
            binp = self._assemble(work, "repwp", WP_PROGRAM)
            pcs = _label_pcs(binp)
            self.assertIn("pc_wprep", pcs, "symbol table did not show pc_wprep")
            rep_pc = pcs["pc_wprep"]

            templates, entries, stats = self._trace(
                work, binp, "wp", "wp=1,wpdepth=64")

            cp, wp = self._render(templates, entries, rep_pc)

            self.assertEqual(
                len(cp), WP_REP_ITERS,
                f"the correct path rendered {len(cp)} entries for a REP that "
                f"performs {WP_REP_ITERS} iterations")
            self.assertTrue(
                wp, "the wrong path never reached the REP, so the "
                    "correct-path/wrong-path comparison is untested; the jz "
                    "must be taken on the correct path so its not-taken side "
                    "is the speculated one")
            self.assertEqual(
                len(wp) % WP_REP_ITERS, 0,
                f"the wrong path rendered {len(wp)} blocks for this REP, "
                f"which is not a whole number of {WP_REP_ITERS}-iteration "
                "renderings -- an excursion produced a different number of "
                "blocks than the correct path does for the same instruction")

            n_exc = len(wp) // WP_REP_ITERS
            for k in range(n_exc):
                chunk = wp[k * WP_REP_ITERS:(k + 1) * WP_REP_ITERS]
                # The wrong path carries no per-entry branch direction of its
                # own in the decoded view, so compare everything else: the
                # template the iteration rides, its shape, and its memops.
                cp_shape = [(s[0], s[1], s[4]) for s in cp]
                wp_shape = [(s[0], s[1], s[4]) for s in chunk]
                self.assertEqual(
                    cp_shape, wp_shape,
                    f"wrong-path excursion {k} renders this REP differently "
                    "from the correct path, for the same instruction with the "
                    "same counter.\n"
                    f"  correct path: {cp_shape}\n"
                    f"  wrong path  : {wp_shape}\n"
                    "A wrong-path-only divergence is invisible to every "
                    "external reference check, which validates the correct "
                    "path only.")

            self.assertEqual(
                self._stat(stats, "REP iters inferred from memops"), 0,
                "a REP's iterations were counted from delivered memops "
                "instead of from the loop counter")


#: Marker-bracketed system probe: the reptf.S REP cases (no TF machinery —
#: the can_loop lever here is -icount itself) plus a one-byte pre-touch of
#: the data page so no REP takes a mid-instruction CoW fault and the two
#: arms' coverage is confound-free.
SYS_PROGRAM = r"""
        .section .data
        .align 64
src:    .fill 256, 1, 0xA5
dst:    .fill 256, 1, 0x00

        .section .text
        .globl _start
_start:
        mov     $0x43535401, %eax
        mov     $0x43535401, %eax
        mov     $0x43535401, %eax

        lea     dst(%rip), %rdi
        movb    (%rdi), %al
        movb    %al, (%rdi)
        lea     src(%rip), %rsi
        movb    (%rsi), %al
        movb    %al, (%rsi)

        lea     src(%rip), %rsi
        lea     dst(%rip), %rdi
        mov     $7, %ecx
        rep movsb

        lea     dst(%rip), %rdi
        mov     $0x5a, %eax
        mov     $5, %ecx
        rep stosb

        lea     src(%rip), %rsi
        lea     dst(%rip), %rdi
        xor     %ecx, %ecx
        rep movsb

        lea     src(%rip), %rsi
        lea     src(%rip), %rdi
        mov     $9, %ecx
        repz cmpsb

        lea     src(%rip), %rsi
        lea     dst(%rip), %rdi
        mov     $3, %ecx
        addr32 rep movsb

        mov     $0x43535402, %eax
        mov     $0x43535402, %eax
        mov     $0x43535402, %eax

        mov     $231, %eax
        xor     %edi, %edi
        syscall
        hlt
"""

QEMU_SYS = BUILD_DIR / "qemu-system-x86_64"


def _sys_harness_present():
    try:
        from champsim_tracer_validator import _system as S
    except Exception:
        return False
    return (S.default_kernel("x86_64").is_file() and
            S.default_root("x86_64").is_dir() and
            shutil.which("cpio") is not None and
            shutil.which("gzip") is not None)


@unittest.skipUnless(shutil.which(CC), f"{CC} not found")
@unittest.skipUnless(QEMU_SYS.is_file(), f"{QEMU_SYS} not built")
@unittest.skipUnless(PLUGIN_SO.is_file(), f"{PLUGIN_SO} not built")
@unittest.skipUnless(_sys_harness_present(),
                     "system harness (kernel/rootfs/cpio) not present")
class RepWindowClockIcountInvarianceTest(unittest.TestCase):
    """user_covered must be icount-invariant: a REP is one clock tick."""

    def _boot(self, S, work: Path, cpio: Path, tag: str, icount: bool):
        out = work / tag
        cmd = S.system_qemu_cmd(
            QEMU_SYS, S.default_kernel("x86_64"), cpio, PLUGIN_SO,
            f"outfile={out},wpdepth=64,trace_window=marker:simulation=200000,"
            f"memdata=1")
        if icount:
            # insert before the plugin args so the -plugin pair stays last
            cmd = cmd[:-2] + ["-icount", "shift=0,sleep=off",
                              "-rtc", "clock=vm"] + cmd[-2:]
        env = dict(os.environ, CST_SYS_CPU="60")
        run = subprocess.run(cmd, text=True, capture_output=True,
                             timeout=600, env=env)
        self.assertEqual(run.returncode, 0,
                         f"{tag}: qemu-system exited {run.returncode}\n"
                         f"{(run.stdout + run.stderr)[-800:]}")
        segs = S.parse_finished_segments(run.stdout + run.stderr)
        self.assertEqual(len(segs), 1,
                         f"{tag}: expected exactly one closed segment, "
                         f"got {len(segs)} — a boot that closes no window "
                         "proves nothing")
        seg = segs[0]
        self.assertTrue(seg["user_clock"],
                        f"{tag}: segment did not run on the user clock")
        self.assertEqual(seg["flag"], "END",
                         f"{tag}: segment closed {seg['flag']}, not END — "
                         "an escaped wedge or an early close would make the "
                         "coverage comparison meaningless")
        stats = Path(f"{out}.stats.log")
        self.assertTrue(stats.is_file(), f"{tag}: no stats log")
        return seg, stats.read_text()

    def test_window_coverage_equal_across_icount(self):
        from champsim_tracer_validator import _system as S

        with tempfile.TemporaryDirectory(prefix="cst_repclk_") as tmp:
            work = Path(tmp)
            binp = self._assemble_sys(work)
            cpio = S.stage_initramfs(S.default_root("x86_64"), binp,
                                     work / "stage")

            seg_a, stats_a = self._boot(S, work, cpio, "arma", icount=False)
            seg_b, stats_b = self._boot(S, work, cpio, "armb", icount=True)

            # The lever, from the same close lines the coverage comes from:
            # loop translation fans out (rep_fanout > 0); icount's
            # single-iteration translation cannot (== 0).
            self.assertGreater(
                seg_a["rep_fanout"], 0,
                "no-icount arm shows no REP fan-out — the probe's REPs did "
                "not run inside the window, so the comparison is untested")
            self.assertEqual(
                seg_b["rep_fanout"], 0,
                "icount arm still fans out — the -icount lever did not "
                "engage, and this would be a run against itself")
            self.assertGreater(
                RepFanoutInvarianceTest._stat(
                    stats_b, "REP clock ticks withheld"), 0,
                "icount arm withheld no clock ticks — the ruling's "
                "correction never ran, so equality below would be luck")

            # The ruling: the window covers the same architectural user
            # instructions under either clock.
            self.assertEqual(
                seg_a["covered"], seg_b["covered"],
                f"user_covered differs across -icount: "
                f"{seg_a['covered']} (no icount) vs {seg_b['covered']} "
                "(icount).  The window clock is counting REP re-executions "
                "instead of architectural instructions.")

            # The deferred-emission guarantee, asserted in system mode where
            # it was measured to fail: no CP REP emission may fall back to
            # the memop-derived count in EITHER arm.
            for tag, st in (("no-icount", stats_a), ("icount", stats_b)):
                self.assertEqual(
                    RepFanoutInvarianceTest._stat(
                        st, "REP iters inferred from memops"), 0,
                    f"{tag} arm: a correct-path REP emission fell back to "
                    "the memop-derived count — the architectural facts did "
                    "not reach a (deferred) emission")

    def _assemble_sys(self, work: Path) -> Path:
        src = work / "repclk.S"
        src.write_text(SYS_PROGRAM)
        binp = work / "repclk"
        build = subprocess.run(
            [CC, "-static", "-nostdlib", "-nostartfiles", "-no-pie", "-O1",
             "-fno-asynchronous-unwind-tables", str(src), "-o", str(binp)],
            text=True, capture_output=True)
        self.assertEqual(build.returncode, 0,
                         f"assembling the system probe failed:\n"
                         f"{build.stderr[-800:]}")
        return binp


if __name__ == "__main__":
    unittest.main()
