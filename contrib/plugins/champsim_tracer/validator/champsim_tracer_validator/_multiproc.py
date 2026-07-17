#!/usr/bin/env python3
"""Multi-process ASID / marker-latch harnesses (system mode).

This module folds the three standalone Stage-B multi-ASID harnesses that
used to live outside the repo (``mp_trace_all.py``, ``mp_harness_mips.py``,
``mp_harness.py`` under ``/mnt/md0/QEMU/cst_runs/multiasid_b4/``) into the
validator package proper.  Each harness boots two (or one) marked/unmarked
workloads CONCURRENTLY under ``qemu-system-<isa>`` with the ChampSim Tracer
in ``trace_window=marker`` and asserts the multi-process latch behaviour
from the decoded trace.

The three scenarios exercised here:

* :func:`run_trace_all_differential` (x86_64) — ``policy=trace-all`` captures
  an UNMARKED peer's user code; ``policy=latch`` renders it invisible.  The
  differential is the whole point.
* :func:`run_mips_latch` (mipsel, narrow 8-bit ASID) — two MARKED workloads
  latch independently; the pin is anchored by physical-code-page identity,
  not the (aliased) EntryHi.ASID value.  ``--churn`` rolls the 8-bit ASID
  space to prove recycle-no-cross-attribution.
* :func:`run_x86_dead_latch_kill` (x86_64) — a marked peer is ``kill -9``'d
  mid-window with no END marker; the dead-latch detector must age it out so
  the segment still closes cleanly (qemu exits, trace is well-formed).

Every function returns an :class:`MPResult` (``.ok`` plus per-subcheck
detail) and takes an :class:`MPConfig` carrying the (parameterized) build
dir and a UNIQUE output dir — no hardcoded absolute paths, so the whole
thing is drivable from the unified ``full`` entrypoint or standalone.

Author: Maccoy Merrell.  SPDX-License-Identifier: GPL-2.0-or-later
"""
from __future__ import annotations

import dataclasses
import re
import subprocess
from pathlib import Path

from . import generator as G
from . import _system as SYS


# ---------------------------------------------------------------------------
# Config / result types
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class MPConfig:
    build_dir: Path
    out_dir: Path
    budget: int = 4_000_000
    depth: int = 16
    sleep: int = 2
    churn: int = 0
    seed_a: int = 0xA1A1
    seed_b: int = 0xB2B2


@dataclasses.dataclass
class SubCheck:
    name: str
    ok: bool
    detail: str


@dataclasses.dataclass
class MPResult:
    ok: bool
    subchecks: list
    artifacts: dict
    skipped: bool = False
    skip_reason: str = ""


_CC = {
    "x86_64": ("g++", ["-static", "-nostdlib", "-nostartfiles"]),
    "mipsel": ("mipsel-linux-gnu-g++",
               ["-static", "-nostdlib", "-nostartfiles", "-e", "_start",
                "-mno-abicalls", "-fno-pic"]),
}
_COMMON_CFLAGS = ["-O1", "-fno-asynchronous-unwind-tables",
                  "-fno-stack-protector", "-fno-optimize-sibling-calls"]


def _have(tool: str) -> bool:
    import os
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if os.access(os.path.join(d, tool), os.X_OK):
            return True
    return False


def _preconditions(cfg: MPConfig, isa: str) -> str | None:
    """Return a skip reason if this scenario can't run, else None."""
    cc = _CC[isa][0]
    if not _have(cc):
        return f"compiler {cc} not in PATH"
    qemu = cfg.build_dir / f"qemu-system-{isa}"
    plugin = cfg.build_dir / "contrib/plugins/libchampsim_tracer.so"
    kernel = SYS.default_kernel(isa)
    root = SYS.default_root(isa)
    for p, what in ((qemu, "qemu-system"), (plugin, "plugin"),
                    (kernel, "kernel"), (root, "rootfs")):
        if not Path(p).exists():
            return f"{what} not found: {p}"
    for tool in ("cst_decode", "cst_audit"):
        if not (cfg.build_dir / "contrib/plugins" / tool).exists():
            return f"tool {tool} not built"
    return None


# ---------------------------------------------------------------------------
# build / stage / boot
# ---------------------------------------------------------------------------

def _gen_build(isa: str, prog: str, seed: int, diamonds: int, hot_iters: int,
               sleep_probe: int, marker: bool, out_dir: Path,
               text_base: int | None = None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    params = G.GenerateParams(seed=seed, isa=isa, num_diamonds=diamonds,
                              hot_iters=hot_iters, marker=marker,
                              sleep_probe=sleep_probe)
    src, _meta = G.generate(params, out_dir, f"{prog}_{isa}")
    binp = out_dir / f"{prog}_{isa}"
    cc, base = _CC[isa]
    cmd = [cc, *base, *_COMMON_CFLAGS]
    if text_base is not None:
        cmd += [f"-Wl,-Ttext-segment=0x{text_base:x}"]
    cmd += [str(src), "-o", str(binp)]
    if isa == "mipsel":
        cmd += ["-lgcc"]
    subprocess.check_call(cmd)
    return binp


def _stage(isa: str, stage_dir: Path, payload: list, init_text: str) -> Path:
    """Copy the base rootfs, drop in @payload [(name, binpath), ...] plus an
    @init_text /init, repack the cpio.  @stage_dir is unique per scenario."""
    root = stage_dir / "sysroot"
    if root.exists():
        subprocess.check_call(["rm", "-rf", str(root)])
    root.mkdir(parents=True)
    base_root = SYS.default_root(isa)
    subprocess.check_call(["cp", "-a", f"{base_root}/.", str(root)])
    for name, src in payload:
        dst = root / name
        subprocess.check_call(["cp", str(src), str(dst)])
        dst.chmod(0o755)
    (root / "init").write_text(init_text)
    (root / "init").chmod(0o755)
    cpio = stage_dir / "rootfs.cpio.gz"
    with open(cpio, "wb") as out:
        find = subprocess.Popen(["find", "."], cwd=root,
                                stdout=subprocess.PIPE)
        pack = subprocess.Popen(["cpio", "-H", "newc", "-o", "--quiet"],
                                cwd=root, stdin=find.stdout,
                                stdout=subprocess.PIPE)
        find.stdout.close()
        gz = subprocess.Popen(["gzip", "-c"], stdin=pack.stdout, stdout=out)
        pack.stdout.close()
        gz.communicate()
        find.wait()
        pack.wait()
    return cpio


def _boot(cfg: MPConfig, isa: str, cpio: Path, out_base: Path,
          plugin_opts: str, extra_qemu: list | None = None) -> tuple:
    plugin = cfg.build_dir / "contrib/plugins/libchampsim_tracer.so"
    qemu = cfg.build_dir / f"qemu-system-{isa}"
    kernel = SYS.default_kernel(isa)
    if isa == "x86_64":
        # KPTI-off is the canonical system-mode config (multiasid_plan §0):
        # the kernel shares each process's ASID, so (asid,vaddr) covers both.
        cmd = [str(qemu), "-kernel", str(kernel), "-initrd", str(cpio),
               "-append", "console=ttyS0 panic=-1 nopti",
               "-nographic", "-no-reboot", "-m", "512M",
               "-plugin", f"{plugin},{plugin_opts}"]
    else:
        cmd = SYS.system_qemu_cmd(qemu, kernel, cpio, plugin, plugin_opts,
                                  mem="512M", isa=isa)
    if extra_qemu:
        cmd += list(extra_qemu)
    console = Path(f"{out_base}.console.log")
    with open(console, "w") as f:
        rc = subprocess.call(cmd, stdout=f, stderr=subprocess.STDOUT)
    cst = Path(f"{out_base}.cst")
    return rc, console, cst


# ---------------------------------------------------------------------------
# decode / audit helpers (stable cst_decode / cst_audit CLI text)
# ---------------------------------------------------------------------------

def _run(cmd: list) -> tuple:
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True)
    return p.returncode, p.stdout


def _decode(cfg: MPConfig) -> str:
    return str(cfg.build_dir / "contrib/plugins/cst_decode")


def _audit(cfg: MPConfig) -> str:
    return str(cfg.build_dir / "contrib/plugins/cst_audit")


def _raw_identities(cfg: MPConfig, cst: Path) -> dict:
    """asid_index -> (root_phys, sig) from the first-sighting identities."""
    _, out = _run([_decode(cfg), "--format=raw", str(cst)])
    idents: dict = {}
    cur = None
    for line in out.splitlines():
        m = re.search(r"->asid_index=(-?\d+)", line)
        if m:
            cur = int(m.group(1))
            continue
        m = re.search(r"identity \(first sighting\): root_phys=0x([0-9a-f]+)"
                      r"\s+sig=0x([0-9a-f]+)", line)
        if m and cur is not None:
            idents[cur] = (int(m.group(1), 16), int(m.group(2), 16))
    return idents


def _regfile_contexts(cfg: MPConfig, cst: Path) -> set:
    """Set of (asid_index, thread_id) contexts that emitted a REGFILE."""
    _, out = _run([_decode(cfg), "--format=raw", str(cst)])
    cur_asid = 0
    ctxs = set()
    lines = out.splitlines()
    for i, line in enumerate(lines):
        m = re.search(r"->asid_index=(-?\d+)", line)
        if m:
            cur_asid = int(m.group(1))
            continue
        if re.search(r"REGFILE\s+tag=4", line):
            for j in range(i + 1, min(i + 3, len(lines))):
                t = re.search(r"thread_id=(\d+)\s+n_present=", lines[j])
                if t:
                    ctxs.add((cur_asid, int(t.group(1))))
                    break
    return ctxs


def _legacy_entries(cfg: MPConfig, cst: Path) -> list:
    """List of (asid, template_id, switched) per body ENTRY, in order."""
    _, out = _run([_decode(cfg), "--format=legacy", str(cst)])
    ents = []
    for line in out.splitlines():
        m = re.match(r"ENTRY \d+ thread=\d+ asid=(\d+)(?: switch=(\d))?"
                     r".*template=BB(\d+)", line)
        if m:
            ents.append((int(m.group(1)), int(m.group(3)),
                         m.group(2) == "1"))
    return ents


def _template_pcs(cfg: MPConfig, cst: Path) -> dict:
    _, out = _run([_decode(cfg), "--templates-only", str(cst)])
    tp = {}
    for line in out.splitlines():
        m = re.match(r"BB(\d+) 0x([0-9a-f]+) ", line)
        if m:
            tp[int(m.group(1))] = int(m.group(2), 16)
    return tp


def _system_template_ids(cfg: MPConfig, cst: Path) -> set:
    _, out = _run([_decode(cfg), "--templates-only", str(cst)])
    return {int(m.group(1))
            for m in (re.match(r"BB(\d+) .*\bsystem\)", ln)
                      for ln in out.splitlines()) if m}


def _strict_rc(cfg: MPConfig, cst: Path) -> int:
    rc, _ = _run([_decode(cfg), "--strict", str(cst)])
    return rc


def _audit_clean(cfg: MPConfig, cst: Path) -> tuple:
    rc, out = _run([_audit(cfg), str(cst)])
    rollup = re.search(r"\[rollup (\d+\.\d+)%\]", out)
    imposs = re.search(r"impossible attributions: (\d+) memop.*?(\d+) regdata"
                       r".*?(\d+) dangling", out)
    ok = (rc == 0 and rollup is not None and rollup.group(1) == "100.00"
          and imposs is not None and imposs.group(1) == "0"
          and imposs.group(2) == "0" and imposs.group(3) == "0")
    summary = (f"rc={rc} rollup={rollup.group(1) if rollup else '?'}% "
               f"impossible=({imposs.group(1) if imposs else '?'} memop,"
               f"{imposs.group(2) if imposs else '?'} regdata) "
               f"dangling={imposs.group(3) if imposs else '?'}")
    return ok, summary


def _close_line(console: Path) -> tuple:
    """(reason, user_insns) from the plugin's close message (x86 trace-all)."""
    text = console.read_text(errors="replace")
    m = re.search(r"end marker — closing after (\d+) user insns", text)
    if m:
        return "END", int(m.group(1))
    m = re.search(r"end marker.*?closing.*?(\d+) user insns", text)
    if m:
        return "END", int(m.group(1))
    if "budget" in text.lower() or "UNDER" in text:
        return "BUDGET", None
    return "UNKNOWN", None


def _parse_console_mips(console: Path) -> dict:
    text = console.read_text(errors="replace")
    add = len(re.findall(r"additional window for narrow owner", text))
    mid = len(re.findall(r"closed narrow owner \d+ \(\d+ still tracing\)",
                         text))
    last = re.search(r"closing after (\d+) user insns \(last window\)", text)
    reuse = "pinned ASID value" in text
    return {"add": add, "mid": mid,
            "last_uinsns": int(last.group(1)) if last else None,
            "reuse_warn": reuse, "text": text}


# ---------------------------------------------------------------------------
# guest init scripts
# ---------------------------------------------------------------------------

_INIT_TRACE_ALL = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst trace-all guest: $(uname -r) ==="
/workloadB &
bpid=$!
/workloadA &
apid=$!
echo "=== launched A=$apid (marked) B=$bpid (unmarked) ==="
wait $apid; echo "=== workloadA exit=$? ==="
wait $bpid; echo "=== workloadB exit=$? ; poweroff ==="
poweroff -f
"""


def _init_mips(churn: int) -> str:
    pre = during = ""
    if churn > 0:
        pre = (f'i=0; while [ $i -lt {churn} ]; do /bin/true; '
               f'i=$((i+1)); done; echo "=== pre-churn done ==="\n')
        during = (f'i=0; while [ $i -lt {churn} ]; do /bin/true; '
                  f'i=$((i+1)); done; echo "=== during-churn done ==="\n')
    return f"""#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst multiproc-mips guest: $(uname -r) ==="
{pre}/workloadA &
apid=$!
/workloadB &
bpid=$!
echo "=== launched A=$apid B=$bpid ==="
{during}wait $apid; echo "=== workloadA exit=$? ==="
wait $bpid; echo "=== workloadB exit=$? ; poweroff ==="
poweroff -f
"""


_INIT_KILL = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst deadlatch kill-test guest: $(uname -r) ==="
/workloadA &
apid=$!
/workloadB &
bpid=$!
echo "=== launched A=$apid B=$bpid ==="
sleep %(kill_after)d
kill -9 $bpid
echo "=== killed B=$bpid (no END marker) ==="
wait $apid; echo "=== workloadA exit=$? ==="
i=0
while [ $i -lt %(churn)d ]; do /bin/true; i=$((i+1)); done
echo "=== churn done ; poweroff ==="
poweroff -f
"""


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------

def _emit(title: str, subs: list) -> MPResult:
    print(f"\n### {title} ###")
    ok_all = True
    for s in subs:
        print(f"  [{'PASS' if s.ok else 'FAIL'}] {s.name}: {s.detail}")
        ok_all = ok_all and s.ok
    print(f"  OVERALL: {'PASS' if ok_all else 'FAIL'}")
    return MPResult(ok=ok_all, subchecks=subs, artifacts={})


# ---------------------------------------------------------------------------
# scenario 1: x86 trace-all differential (+ latch differential)
# ---------------------------------------------------------------------------

def run_trace_all_differential(cfg: MPConfig) -> MPResult:
    isa = "x86_64"
    skip = _preconditions(cfg, isa)
    if skip:
        return MPResult(ok=True, subchecks=[], artifacts={}, skipped=True,
                        skip_reason=skip)
    od = cfg.out_dir
    od.mkdir(parents=True, exist_ok=True)
    # progA: marked + sleeps (holds the window); progB: UNMARKED, big work.
    bin_a = _gen_build(isa, "progA", cfg.seed_a, 4, 200, cfg.sleep, True,
                       od / "A")
    bin_b = _gen_build(isa, "progB", cfg.seed_b, 10, 1200, 0, False,
                       od / "B")
    cpio = _stage(isa, od / "stage", [("workloadA", bin_a),
                                      ("workloadB", bin_b)], _INIT_TRACE_ALL)

    def opts(policy: str) -> str:
        return (f"outfile={{base}},wpdepth={cfg.depth},"
                f"trace_window=marker:policy={policy}+simulation={cfg.budget},"
                f"memdata=1")

    subs: list = []
    # --- trace-all ---
    base_ta = od / "traceall"
    rc, console, cst = _boot(cfg, isa, cpio, base_ta,
                             opts("trace-all").format(base=base_ta))
    if not cst.exists():
        subs.append(SubCheck("trace-all boot produced a trace", False,
                             f"qemu_rc={rc} cst MISSING"))
        return _emit("x86 trace-all differential", subs)
    idents = _raw_identities(cfg, cst)
    ents = _legacy_entries(cfg, cst)
    entry_asids = {a for a, _t, _s in ents}
    roots = {r for (r, _s) in idents.values()}
    sigs = {s for (_r, s) in idents.values()}
    repr_root = idents.get(0, (None, None))[0]
    other = {i: v for i, v in idents.items()
             if i != 0 and v[0] != repr_root}
    subs.append(SubCheck(
        "1. progB captured with own root+sig (>=2 address spaces)",
        len(roots) >= 2 and len(other) >= 1 and len(entry_asids) >= 2,
        f"roots={len(roots)} sigs={len(sigs)} asid_idx={sorted(idents)}"))
    reason, uinsns = _close_line(console)
    b_entries = sum(1 for a, _t, _s in ents if a in other)
    subs.append(SubCheck(
        "2. clock = progA user insns only (END-close under budget; B busy)",
        reason == "END" and uinsns is not None and uinsns < cfg.budget
        and b_entries > 0,
        f"close={reason} user_insns={uinsns} budget={cfg.budget} "
        f"B_entries={b_entries}"))
    src = _strict_rc(cfg, cst)
    subs.append(SubCheck(
        "3. clean close at progA END",
        rc == 0 and reason == "END" and src == 0,
        f"qemu_rc={rc} close={reason} strict_rc={src}"))
    sysids = _system_template_ids(cfg, cst)
    sys_asids = {a for a, t, _s in ents if t in sysids}
    usr_asids = {a for a, t, _s in ents if t not in sysids}
    subs.append(SubCheck(
        "4. kernel (system) blocks carry process asids only",
        len(sysids) > 0 and sys_asids.issubset(usr_asids),
        f"sys_templates={len(sysids)} sys_asids={sorted(sys_asids)}"))
    ok5, asum = _audit_clean(cfg, cst)
    subs.append(SubCheck("5. audit clean (100%, 0 impossible, 0 dangling)",
                         ok5, asum))

    # --- latch differential ---
    base_l = od / "latchdiff"
    rc2, console2, cst2 = _boot(cfg, isa, cpio, base_l,
                                opts("latch").format(base=base_l))
    if cst2.exists():
        idents2 = _raw_identities(cfg, cst2)
        ents2 = _legacy_entries(cfg, cst2)
        entry_asids2 = {a for a, _t, _s in ents2}
        roots2 = {r for (r, _s) in idents2.values()}
        okL, asumL = _audit_clean(cfg, cst2)
        srcL = _strict_rc(cfg, cst2)
        subs.append(SubCheck(
            "L. latch differential: unmarked progB ABSENT (one address space)",
            len(roots2) <= 1 and entry_asids2.issubset({0})
            and okL and srcL == 0,
            f"roots={len(roots2)} entry_asids={sorted(entry_asids2)} "
            f"qemu_rc={rc2} strict_rc={srcL}"))
    else:
        subs.append(SubCheck("L. latch differential boot produced a trace",
                             False, f"qemu_rc={rc2} cst MISSING"))

    res = _emit("x86 trace-all differential", subs)
    res.artifacts = {"trace_all_cst": str(cst), "latch_cst": str(cst2)}
    return res


# ---------------------------------------------------------------------------
# scenario 2: mipsel narrow-ASID latch (+ optional recycle churn)
# ---------------------------------------------------------------------------

def run_mips_latch(cfg: MPConfig) -> MPResult:
    isa = "mipsel"
    skip = _preconditions(cfg, isa)
    if skip:
        return MPResult(ok=True, subchecks=[], artifacts={}, skipped=True,
                        skip_reason=skip)
    od = cfg.out_dir
    od.mkdir(parents=True, exist_ok=True)
    # progA: fewer diamonds/iters -> ENDs first (middle-close).
    # progB: more -> ENDs last (last-close + plugin exit(0)).
    bin_a = _gen_build(isa, "progA", cfg.seed_a, 6, 400, cfg.sleep, True,
                       od / "Amips")
    bin_b = _gen_build(isa, "progB", cfg.seed_b, 11, 1600, cfg.sleep, True,
                       od / "Bmips")
    cpio = _stage(isa, od / "stage", [("workloadA", bin_a),
                                      ("workloadB", bin_b)],
                  _init_mips(cfg.churn))
    out_base = od / "mpm"
    plugin_opts = (f"outfile={out_base},wpdepth={cfg.depth},"
                   f"trace_window=marker:policy=latch+simulation={cfg.budget},"
                   f"memdata=1")
    rc, console, cst = _boot(cfg, isa, cpio, out_base, plugin_opts)
    if not cst.exists():
        return _emit("mipsel narrow-ASID latch",
                     [SubCheck("boot produced a trace", False,
                               f"qemu_rc={rc} cst MISSING")])

    idents = _raw_identities(cfg, cst)
    ents = _legacy_entries(cfg, cst)
    entry_asids = {a for a, _t, _s in ents}
    tp = _template_pcs(cfg, cst)
    con = _parse_console_mips(console)
    subs: list = []

    roots = {r for (r, _s) in idents.values()}
    sigs = {s for (_r, s) in idents.values()}
    subs.append(SubCheck(
        "1. two owned processes, distinct (root_phys, sig)",
        len(idents) >= 2 and len(entry_asids) >= 2 and len(roots) >= 2
        and len(sigs) >= 2,
        f"asid_idx={sorted(idents)} roots={len(roots)} sigs={len(sigs)}"))

    seq = [a for a, _t, _s in ents]
    transitions = sum(1 for i in range(1, len(seq)) if seq[i] != seq[i - 1])
    subs.append(SubCheck(
        "2. interleaved asid stream (>=2 transitions)",
        transitions >= 2 and len(entry_asids) >= 2,
        f"entries={len(seq)} transitions={transitions} "
        f"asids={sorted(entry_asids)}"))

    asid_pc_tmpl: dict = {}
    for a, t, _s in ents:
        pc = tp.get(t)
        if pc is None:
            continue
        asid_pc_tmpl.setdefault((a, pc), set()).add(t)
    pc_to_asids: dict = {}
    for (a, pc), tmpls in asid_pc_tmpl.items():
        pc_to_asids.setdefault(pc, {})[a] = tmpls
    shared = {pc: d for pc, d in pc_to_asids.items() if len(d) >= 2}
    disambiguated = 0
    for pc, d in shared.items():
        per_asid = list(d.values())
        if set().union(*per_asid) and all(
                per_asid[0].isdisjoint(o) for o in per_asid[1:]):
            disambiguated += 1
    subs.append(SubCheck(
        "3. same-VA disambiguation (shared VA -> own templates per asid)",
        len(shared) >= 1 and disambiguated >= 1,
        f"shared_VAs={len(shared)} disambiguated={disambiguated}"))

    subs.append(SubCheck(
        "4. both windows open + middle-close + last-close",
        con["add"] >= 1 and con["mid"] >= 1 and con["last_uinsns"] is not None,
        f"add={con['add']} mid={con['mid']} last={con['last_uinsns']}"))

    rctx = _regfile_contexts(cfg, cst)
    rf_asids = {a for a, _t in rctx}
    subs.append(SubCheck(
        "5. per-(process,thread) regfiles",
        len(rctx) >= 2 and len(rf_asids) >= 2,
        f"regfile_contexts={sorted(rctx)}"))

    ok6, asum = _audit_clean(cfg, cst)
    src = _strict_rc(cfg, cst)
    subs.append(SubCheck(
        "6. audit clean + strict rc=0 + qemu rc=0",
        ok6 and src == 0 and rc == 0,
        f"qemu_rc={rc} strict_rc={src} audit[{asum}]"))

    subs.append(SubCheck(
        "CLOCK: last-window END-close on the user clock, under budget",
        con["last_uinsns"] is not None
        and 0 < con["last_uinsns"] < cfg.budget,
        f"user_insns={con['last_uinsns']} budget={cfg.budget}"))

    if cfg.churn > 0:
        subs.append(SubCheck(
            "RECYCLE: ASID churn provoked, owned procs stay attributed",
            entry_asids.issubset(set(idents.keys()))
            and len(roots) == len(idents) and ok6 and src == 0,
            f"reuse_warn={con['reuse_warn']} entry_asids={sorted(entry_asids)} "
            f"owned={sorted(idents)}"))

    res = _emit("mipsel narrow-ASID latch", subs)
    res.artifacts = {"cst": str(cst)}
    return res


# ---------------------------------------------------------------------------
# scenario 3: x86 dead-latch kill (peer killed mid-window, no END)
# ---------------------------------------------------------------------------

def run_x86_dead_latch_kill(cfg: MPConfig, latch_timeout: int = 3000,
                            kill_after: int = 2, churn: int = 60) -> MPResult:
    isa = "x86_64"
    skip = _preconditions(cfg, isa)
    if skip:
        return MPResult(ok=True, subchecks=[], artifacts={}, skipped=True,
                        skip_reason=skip)
    od = cfg.out_dir
    od.mkdir(parents=True, exist_ok=True)
    # progA: modest hold (< latch_timeout) then long active work; progB:
    # marks + sleeps long, is killed mid-sleep (never runs its END).
    bin_a = _gen_build(isa, "progA", cfg.seed_a, 6, 8000, 1, True, od / "A")
    bin_b = _gen_build(isa, "progB", cfg.seed_b, 11, 4000, 12, True, od / "B")
    init = _INIT_KILL % {"kill_after": kill_after, "churn": churn}
    cpio = _stage(isa, od / "stage", [("workloadA", bin_a),
                                      ("workloadB", bin_b)], init)
    out_base = od / "kill"
    plugin_opts = (f"outfile={out_base},wpdepth={cfg.depth},"
                   f"trace_window=marker:policy=latch+simulation={cfg.budget},"
                   f"memdata=1,latch_timeout={latch_timeout}")
    rc, console, cst = _boot(cfg, isa, cpio, out_base, plugin_opts)
    ctext = console.read_text(errors="replace") if console.exists() else ""
    subs: list = []
    subs.append(SubCheck(
        "1. peer killed mid-window (no END marker)",
        "killed B" in ctext,
        "guest reported the kill -9" if "killed B" in ctext
        else "guest never reported the kill"))
    subs.append(SubCheck(
        "2. dead-latch closed the segment: qemu exited, trace present",
        rc == 0 and cst.exists(),
        f"qemu_rc={rc} cst={'exists' if cst.exists() else 'MISSING'} "
        f"(hang-to-budget or timeout would leave rc!=0 / no clean exit)"))
    if cst.exists():
        idents = _raw_identities(cfg, cst)
        ok_audit, asum = _audit_clean(cfg, cst)
        src = _strict_rc(cfg, cst)
        subs.append(SubCheck(
            "3. surviving process (progA) attributed; trace well-formed",
            len(idents) >= 1 and ok_audit and src == 0,
            f"asid_idx={sorted(idents)} strict_rc={src} audit[{asum}]"))
    else:
        subs.append(SubCheck("3. trace well-formed", False, "no trace"))
    res = _emit("x86 dead-latch kill", subs)
    res.artifacts = {"cst": str(cst)}
    return res


# ---------------------------------------------------------------------------
# scenario 4: physaddr — per-memop physical-page capture (system mode)
# ---------------------------------------------------------------------------

_INIT_SINGLE = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst single-workload guest: $(uname -r) ==="
/workloadA
echo "=== workloadA exit=$? ; poweroff ==="
poweroff -f
"""


def run_physaddr_probe(cfg: MPConfig) -> MPResult:
    isa = "x86_64"
    skip = _preconditions(cfg, isa)
    if skip:
        return MPResult(ok=True, subchecks=[], artifacts={}, skipped=True,
                        skip_reason=skip)
    od = cfg.out_dir
    od.mkdir(parents=True, exist_ok=True)
    bin_a = _gen_build(isa, "workloadA", cfg.seed_a, 8, 300, 0, True,
                       od / "A")
    cpio = _stage(isa, od / "stage", [("workloadA", bin_a)], _INIT_SINGLE)
    out_base = od / "physaddr"
    plugin_opts = (f"outfile={out_base},wpdepth={cfg.depth},"
                   f"trace_window=marker:simulation={cfg.budget},"
                   f"memdata=1,physaddr=1")
    rc, console, cst = _boot(cfg, isa, cpio, out_base, plugin_opts)
    subs: list = []
    if not cst.exists():
        subs.append(SubCheck("boot produced a trace", False,
                             f"qemu_rc={rc} cst MISSING"))
        return _emit("physaddr physical-page capture", subs)
    _, raw = _run([_decode(cfg), "--format=raw", str(cst)])
    ppage = len(re.findall(r"(?i)ppage", raw))
    flag = bool(re.search(r"(?i)physaddr", raw))
    subs.append(SubCheck(
        "1. physical-page records present (LOAD/STORE_PPAGE families)",
        ppage >= 1, f"ppage_lines={ppage} header_physaddr={flag}"))
    ok_a, asum = _audit_clean(cfg, cst)
    src = _strict_rc(cfg, cst)
    subs.append(SubCheck("2. audit clean + strict rc=0",
                         ok_a and src == 0,
                         f"strict_rc={src} audit[{asum}]"))
    res = _emit("physaddr physical-page capture", subs)
    res.artifacts = {"cst": str(cst)}
    return res


# ---------------------------------------------------------------------------
# scenario 5: devio — disk-I/O bracketing records (virtio-blk, system mode)
# ---------------------------------------------------------------------------

def _init_devio(sleep_s: int) -> str:
    # workloadA marks + holds the (frozen-clock) window open on its
    # sleep_probe; while it holds, we read the virtio disk so the plugin
    # brackets each request with DEVIO_START/STOP inside the open window.
    return f"""#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst devio guest: $(uname -r) ==="
/workloadA &
apid=$!
sleep 1
if [ -b /dev/vda ]; then
  dd if=/dev/vda of=/dev/null bs=4096 count=256 2>/dev/null
  echo "=== DEVIO_DD_OK ==="
else
  echo "=== NO_VDA (guest kernel lacks virtio-blk) ==="
fi
wait $apid; echo "=== workloadA exit=$? ; poweroff ==="
poweroff -f
"""


def run_devio_probe(cfg: MPConfig) -> MPResult:
    isa = "x86_64"
    skip = _preconditions(cfg, isa)
    if skip:
        return MPResult(ok=True, subchecks=[], artifacts={}, skipped=True,
                        skip_reason=skip)
    od = cfg.out_dir
    od.mkdir(parents=True, exist_ok=True)
    # workloadA holds the whole-system (trace-all) window open ~6s so the
    # concurrent disk read lands in-window.
    bin_a = _gen_build(isa, "workloadA", cfg.seed_a, 6, 200, 6, True,
                       od / "A")
    cpio = _stage(isa, od / "stage", [("workloadA", bin_a)],
                  _init_devio(6))
    # A scratch disk to actually read.
    scratch = od / "scratch.raw"
    with open(scratch, "wb") as f:
        f.truncate(4 * 1024 * 1024)
    out_base = od / "devio"
    plugin_opts = (f"outfile={out_base},wpdepth={cfg.depth},"
                   f"trace_window=marker:policy=trace-all+"
                   f"simulation={cfg.budget},memdata=1,devio=1")
    extra_qemu = ["-drive", f"file={scratch},format=raw,if=none,id=d0",
                  "-device", "virtio-blk-pci,drive=d0,ioeventfd=off"]
    rc, console, cst = _boot(cfg, isa, cpio, out_base, plugin_opts,
                             extra_qemu=extra_qemu)
    ctext = console.read_text(errors="replace") if console.exists() else ""
    subs: list = []
    if not cst.exists():
        subs.append(SubCheck("boot produced a trace", False,
                             f"qemu_rc={rc} cst MISSING"))
        return _emit("devio disk-I/O records", subs)
    _, raw = _run([_decode(cfg), "--format=raw", str(cst)])
    devio = len(re.findall(r"DEVIO_(START|STOP)", raw))
    if devio == 0 and "NO_VDA" in ctext:
        return MPResult(ok=True, subchecks=[SubCheck(
            "devio records", False,
            "guest kernel lacks virtio-blk (/dev/vda absent)")],
            artifacts={"cst": str(cst)}, skipped=True,
            skip_reason="guest kernel lacks virtio-blk (/dev/vda absent)")
    subs.append(SubCheck(
        "1. DEVIO_START/STOP records bracketed in the body stream",
        devio >= 1, f"devio_records={devio} dd_ok={'DEVIO_DD_OK' in ctext}"))
    ok_a, asum = _audit_clean(cfg, cst)
    src = _strict_rc(cfg, cst)
    subs.append(SubCheck("2. audit clean + strict rc=0",
                         ok_a and src == 0,
                         f"strict_rc={src} audit[{asum}]"))
    res = _emit("devio disk-I/O records", subs)
    res.artifacts = {"cst": str(cst)}
    return res
