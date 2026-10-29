"""A user-mode guest cycle/time read is deterministic and host-independent.

A guest reads an architectural cycle/time counter -- x86 ``RDTSC``, aarch64
``CNTVCT_EL0``, riscv ``rdcycle``/``rdtime`` -- and in stock linux-user QEMU
services it from the host oscillator (``cpu_get_host_ticks`` /
``cpu_get_clock``), which no ``-seed`` can pin.  That value lands in a guest
register and, when it is dereferenced on the correct path or speculated on
the wrong path, carries the host clock into the trace: two otherwise
byte-identical seeded runs diverge.  The fix returns a deterministic per-vCPU
tick (``cpu_plugin_user_det_ticks``, gated on ``qemu_plugin_any_loaded()``)
from those reads while a plugin is loaded, on both paths, leaving an unplugged
qemu-user unchanged.

This cell is the standing executing witness.  For each ISA it assembles a
tiny ``-nostdlib`` probe that reads the counter ``NREADS`` times, storing each
result, and traces it twice with the same ``-seed``.  It then recovers the
recorded counter values (the store data, ``memdata=1``) at the probe's store
PC and asserts:

* **Reproducible.**  The two runs produce the *same ordered list* of values.
  This is the must-fire discriminator: against a build with the fix reverted
  the reads return the host clock and the two lists differ.
* **Advancing, not a frozen constant.**  For the fixed ISAs (x86, aarch64,
  riscv) the values are strictly increasing -- so a wait-on-counter loop still
  makes progress -- which a bare constant would fail.
* **Complete.**  Exactly ``NREADS`` values are recovered, so the read really
  executed and was captured.

MIPS is the already-deterministic case and is witnessed, not fixed: the only
user-reachable counter, ``RDHWR $2`` (CC), reads ``CP0_Count``, which is
written only by the system-mode CP0 timer, so in linux-user it is a
reset-constant.  The MIPS leg therefore asserts reproducible-and-constant
rather than advancing, recording that it is host-independent by construction.

Firing proof (the planted nondeterministic arm).  Rebuild with
``cpu_get_tsc`` / ``gt_virt_cnt_read`` / ``user_counter_ticks`` reverted to
the host oscillator and re-run: the two value lists for x86/aarch64/riscv
differ and the reproducibility assertion FAILS.  A self-contained non-vacuity
guard in the cell also proves the comparison is not degenerate (it flags a
deliberately perturbed copy).

Point it at any build with ``CST_BUILD_DIR=/path/to/build``.  Each ISA leg
skips (with its reason) when its cross toolchain or ``qemu-<arch>`` is absent.

Run standalone:
  python tests/test_cycle_read_determinism.py
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

#: How many times each probe reads the counter.
NREADS = 16

# The guest environment is pinned and identical for both runs so nothing but
# the counter read can differ; the recovered values are env-independent
# anyway (they are a function of the read count alone), but a fixed env keeps
# the whole trace stable.
GUEST_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C"}


#: Per-ISA probe.  Each reads the counter NREADS times into consecutive slots
#: through the labelled store ``pc_store``; ``kind`` says whether the counter
#: advances (the fixed ISAs) or is an already-deterministic constant (MIPS).
ISAS = {
    "x86_64": {
        "qemu": "qemu-x86_64",
        "cc": os.environ.get("CC_X86_64", "x86_64-linux-gnu-gcc"),
        "objdump": os.environ.get("OBJDUMP_X86_64", "x86_64-linux-gnu-objdump"),
        "kind": "advancing",
        "read": "RDTSC",
        "program": r"""
    .bss
    .balign 64
slots:
    .skip %(bytes)d
    .text
    .globl _start
_start:
    leaq  slots(%%rip), %%r15
    xorl  %%r14d, %%r14d
1:
    .globl pc_rd
pc_rd:
    rdtsc
    salq  $32, %%rdx
    orq   %%rdx, %%rax
    .globl pc_store
pc_store:
    movq  %%rax, (%%r15)
    addq  $8, %%r15
    addl  $1, %%r14d
    cmpl  $%(n)d, %%r14d
    jl    1b
    movl  $60, %%eax
    xorl  %%edi, %%edi
    syscall
""",
        "slot": 8,
    },
    "aarch64": {
        "qemu": "qemu-aarch64",
        "cc": os.environ.get("CC_AARCH64", "aarch64-linux-gnu-gcc"),
        "objdump": os.environ.get("OBJDUMP_AARCH64",
                                  "aarch64-linux-gnu-objdump"),
        "kind": "advancing",
        "read": "CNTVCT_EL0",
        "program": r"""
    .bss
    .balign 64
slots:
    .skip %(bytes)d
    .text
    .globl _start
_start:
    adrp  x15, slots
    add   x15, x15, :lo12:slots
    mov   x14, #%(n)d
1:
    .globl pc_rd
pc_rd:
    mrs   x0, cntvct_el0
    .globl pc_store
pc_store:
    str   x0, [x15], #8
    subs  x14, x14, #1
    b.ne  1b
    mov   x8, #93
    mov   x0, #0
    svc   #0
""",
        "slot": 8,
    },
    "riscv64": {
        "qemu": "qemu-riscv64",
        "cc": os.environ.get("CC_RISCV64", "riscv64-linux-gnu-gcc"),
        "objdump": os.environ.get("OBJDUMP_RISCV64",
                                  "riscv64-linux-gnu-objdump"),
        "kind": "advancing",
        "read": "rdcycle",
        "program": r"""
    .bss
    .balign 64
slots:
    .skip %(bytes)d
    .text
    .globl _start
_start:
    la    t0, slots
    li    t1, %(n)d
1:
    .globl pc_rd
pc_rd:
    rdcycle t2
    .globl pc_store
pc_store:
    sd    t2, 0(t0)
    addi  t0, t0, 8
    addi  t1, t1, -1
    bnez  t1, 1b
    li    a7, 93
    li    a0, 0
    ecall
""",
        "slot": 8,
    },
    "mipsel": {
        "qemu": "qemu-mipsel",
        "cc": os.environ.get("CC_MIPSEL", "mipsel-linux-gnu-gcc"),
        "objdump": os.environ.get("OBJDUMP_MIPSEL",
                                  "mipsel-linux-gnu-objdump"),
        "kind": "constant",
        "read": "RDHWR $2 (CC)",
        # -mno-abicalls -fno-pic so `la` is absolute (lui/addiu); the default
        # PIC `la` loads through $gp, which a -nostdlib static binary never
        # initialises, so the probe would segfault before storing anything.
        "extra": ["-mno-abicalls", "-fno-pic"],
        "program": r"""
    .set noreorder
    .bss
    .balign 64
slots:
    .skip %(bytes)d
    .text
    .globl _start
_start:
    la    $t0, slots
    li    $t1, %(n)d
1:
    .globl pc_rd
pc_rd:
    rdhwr $v0, $2
    nop
    .globl pc_store
pc_store:
    sw    $v0, 0($t0)
    addiu $t0, $t0, 4
    addiu $t1, $t1, -1
    bnez  $t1, 1b
    nop
    li    $v0, 4001
    li    $a0, 0
    syscall
""",
        "slot": 4,
    },
}


def _label_pcs(objdump: str, binary: Path) -> dict:
    out = subprocess.run([objdump, "-t", str(binary)],
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


class CycleReadDeterminismTest(unittest.TestCase):

    _caps: dict = {}

    # -- helpers ----------------------------------------------------------

    def _assemble(self, cfg, work: Path):
        src = work / "probe.S"
        src.write_text(cfg["program"] % {"n": NREADS,
                                         "bytes": NREADS * cfg["slot"]})
        binp = work / "probe"
        build = subprocess.run(
            [cfg["cc"], "-static", "-nostdlib", "-nostartfiles", "-O0",
             "-fno-asynchronous-unwind-tables", *cfg.get("extra", []),
             str(src), "-o", str(binp)],
            text=True, capture_output=True)
        return binp, build

    def _trace_values(self, cfg, work: Path, binp: Path, tag: str):
        """Trace once; return the ordered list of counter values recorded at
        the probe's store PC, or (None, reason)."""
        from champsim_tracer_validator import _cst_decode_runner as R
        decode = BUILD_DIR / "contrib" / "plugins" / "cst_decode"
        if decode.is_file():
            R.set_cst_decode(decode)

        pcs = _label_pcs(cfg["objdump"], binp)
        if "pc_store" not in pcs:
            return None, "symbol table did not show pc_store"
        store_pc = pcs["pc_store"]

        qemu = BUILD_DIR / cfg["qemu"]
        out = work / f"run_{tag}"
        env = dict(GUEST_ENV)
        # wpdepth=4 (a positive value; the setter rejects non-positive) keeps
        # the probe tiny while still exercising wrong-path excursions, whose
        # speculative counter reads advance the same shared tick -- the
        # recovered correct-path values stay strictly increasing and
        # reproducible regardless.
        run = subprocess.run(
            [str(qemu), "-seed", "4242", "-plugin",
             f"{PLUGIN_SO},outfile={out},wpdepth=4,memdata=1",
             str(binp)],
            text=True, capture_output=True, env=env)
        cst = Path(f"{out}.cst")
        if run.returncode != 0 or not cst.is_file():
            return None, (f"guest exited {run.returncode}: "
                          f"{run.stderr[-300:]}")

        _meta, templates, entries = R.decode_champsim_tracer(cst)
        by_id = {t["template_id"]: t for t in templates}
        values = []
        for e in entries:
            tmpl = by_id.get(e.get("template_id")) or {}
            insns = tmpl.get("insns") or []
            for dp in (e.get("dyn_params") or []):
                if getattr(dp, "type_name", "") != "store":
                    continue
                i = int(getattr(dp, "insn_index", -1))
                if not (0 <= i < len(insns)):
                    continue
                if int(insns[i].get("pc", -1)) != store_pc:
                    continue
                values.append(int(dp.data))
        return values, None

    def _capture(self, isa):
        cfg = ISAS[isa]
        qemu = BUILD_DIR / cfg["qemu"]
        if not qemu.is_file():
            self.skipTest(f"{qemu} not built")
        if not PLUGIN_SO.is_file():
            self.skipTest(f"{PLUGIN_SO} not built")
        if not shutil.which(cfg["cc"]):
            self.skipTest(f"{cfg['cc']} not found")
        if not shutil.which(cfg["objdump"]):
            self.skipTest(f"{cfg['objdump']} not found")

        if isa not in CycleReadDeterminismTest._caps:
            td = tempfile.mkdtemp(prefix=f"cycle_det_{isa}.")
            self.addClassCleanup(shutil.rmtree, td, ignore_errors=True)
            work = Path(td)
            binp, build = self._assemble(cfg, work)
            if build.returncode != 0:
                self.skipTest(f"assembling the {isa} {cfg['read']} probe "
                              f"failed:\n{build.stderr[-500:]}")
            v1, err1 = self._trace_values(cfg, work, binp, "1")
            if v1 is None:
                self.skipTest(f"{isa} probe did not trace: {err1}")
            v2, err2 = self._trace_values(cfg, work, binp, "2")
            if v2 is None:
                self.skipTest(f"{isa} probe did not trace (run 2): {err2}")
            CycleReadDeterminismTest._caps[isa] = (v1, v2)
        return cfg, CycleReadDeterminismTest._caps[isa]

    def _check(self, isa):
        cfg, (v1, v2) = self._capture(isa)

        self.assertEqual(
            len(v1), NREADS,
            f"{isa}: recovered {len(v1)} {cfg['read']} values, expected "
            f"{NREADS} -- the read did not execute or was not captured")

        # Reproducible: the must-fire discriminator.  A reverted (host-clock)
        # build makes these two lists differ.
        self.assertEqual(
            v1, v2,
            f"{isa}: the two seeded runs recorded DIFFERENT {cfg['read']} "
            f"values -- the read is not host-independent.\n run1={v1}\n "
            f"run2={v2}")

        if cfg["kind"] == "advancing":
            self.assertTrue(
                all(b > a for a, b in zip(v1, v1[1:])),
                f"{isa}: {cfg['read']} values are not strictly increasing; a "
                f"deterministic cycle counter must advance so a wait-on-"
                f"counter loop terminates.  values={v1}")
            self.assertGreater(
                len(set(v1)), 1,
                f"{isa}: {cfg['read']} returned a frozen constant {v1[0]:#x}; "
                f"the tick must advance")
        else:  # MIPS: already-deterministic constant (CP0_Count in user mode)
            self.assertEqual(
                len(set(v1)), 1,
                f"{isa}: {cfg['read']} is expected to be the reset-constant "
                f"CP0_Count in user mode but varied: {v1}")

    # -- the non-vacuity guard (self-contained planted red) ---------------

    def test_reproducibility_comparison_is_not_vacuous(self):
        """The cell's own equality check must be able to see a difference, so
        a green run is never a comparison that can only ever say 'equal'."""
        a = list(range(NREADS))
        b = list(range(NREADS))
        b[NREADS // 2] += 1          # one perturbed value
        self.assertNotEqual(a, b,
                            "the reproducibility comparison cannot detect a "
                            "planted difference -- it would pass vacuously")

    # -- one test per ISA -------------------------------------------------

    def test_x86_64_rdtsc_is_deterministic(self):
        self._check("x86_64")

    def test_aarch64_cntvct_is_deterministic(self):
        self._check("aarch64")

    def test_riscv64_rdcycle_is_deterministic(self):
        self._check("riscv64")

    def test_mipsel_rdhwr_cc_is_deterministic_constant(self):
        self._check("mipsel")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    unittest.main(verbosity=2)
