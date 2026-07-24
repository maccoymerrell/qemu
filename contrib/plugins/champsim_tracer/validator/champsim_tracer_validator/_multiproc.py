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
import os
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
    # Hard wall-clock cap per qemu-system boot.  A boot that neither
    # powers off nor is torn down by the plugin's window-close (a hung
    # dead-latch aging, say) is killed at this bound so the check reports
    # a failure instead of hanging the whole run.
    boot_timeout_s: int = 240


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
          plugin_opts: str, extra_qemu: list | None = None,
          kernel: Path | None = None) -> tuple:
    plugin = cfg.build_dir / "contrib/plugins/libchampsim_tracer.so"
    qemu = cfg.build_dir / f"qemu-system-{isa}"
    kernel = Path(kernel) if kernel is not None else SYS.default_kernel(isa)
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
    import os as _os
    import signal as _signal
    with open(console, "w") as f:
        proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            rc = proc.wait(timeout=cfg.boot_timeout_s)
        except subprocess.TimeoutExpired:
            # Kill the whole process group so no orphaned qemu survives.
            try:
                _os.killpg(_os.getpgid(proc.pid), _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            proc.wait()
            f.write(f"\n[cst] boot exceeded {cfg.boot_timeout_s}s wall "
                    f"clock — killed\n")
            rc = 124
    cst = Path(f"{out_base}.cst")
    return rc, console, cst


# ---------------------------------------------------------------------------
# decode / audit helpers (stable cst_decode / cst_audit CLI text)
# ---------------------------------------------------------------------------

def _run(cmd: list, timeout: int = 180) -> tuple:
    # Cap every offline-tool call: a truncated .cst left by a SIGKILL'd boot
    # can send a decoder into a long/spinning read, which would otherwise
    # hang the whole run after a capped boot.
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        return 124, (e.output or b"").decode(errors="replace") \
            if isinstance(e.output, bytes) else (e.output or "")


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

# Launch the MARKED progA first and give it a moment to mark + start its
# hold-open nanosleep BEFORE launching the unmarked progB, so B runs
# entirely INSIDE A's open whole-system window and is reliably captured
# (launching B first lets it finish before the window opens under load).
_INIT_TRACE_ALL = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst trace-all guest: $(uname -r) ==="
/workloadA &
apid=$!
sleep 1
/workloadB &
bpid=$!
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
    # progA: marked + sleeps ~3s (holds the whole-system window open); the
    # init launches B ~1s into that hold, so B runs INSIDE the window.  B is
    # unmarked and does a bounded workload that completes within the hold.
    bin_a = _gen_build(isa, "progA", cfg.seed_a, 4, 200, max(3, cfg.sleep),
                       True, od / "A")
    bin_b = _gen_build(isa, "progB", cfg.seed_b, 10, 600, 0, False,
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
    # progA: modest hold (< latch_timeout) then a long-enough active phase
    # to outlast progB's dead-latch timeout; progB: marks + sleeps long, is
    # killed mid-sleep (never runs its END).
    bin_a = _gen_build(isa, "progA", cfg.seed_a, 6, 800, 1, True, od / "A")
    bin_b = _gen_build(isa, "progB", cfg.seed_b, 8, 800, 12, True, od / "B")
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
    if rc == 124:
        # Boot hit the wall-clock cap before the dead-latch aged the killed
        # peer's window out (scheduling-sensitive under load).  Report it
        # without decoding the truncated trace; the check is non-gating.
        subs.append(SubCheck(
            "dead-latch closed the segment within the boot cap", False,
            f"boot exceeded {cfg.boot_timeout_s}s cap "
            f"(killed B={'killed B' in ctext}); aging did not close in time"))
        return _emit("x86 dead-latch kill", subs)
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
#
# The probe drives a small, self-contained O_DIRECT|O_SYNC C workload (NOT
# the diamond-CFG generator — devio cares about the disk requests a program
# issues, not instruction coverage) that brackets a KNOWN, deterministic
# request sequence inside the trace marker window: nops writes at ascending
# 4K-block offsets, then nops reads at the same offsets.  Mirrors the
# historical devio2/workload2.c exact-attribution harness (88d9b7e526) —
# imported here as two probes:
#
#   run_devio_probe          single marked process: pairing oracle + the
#                             exact (rw, bytes, LBA) payload assertion.
#   run_devio_attrib_probe   two CONCURRENTLY marked processes (-smp 2,
#                             disjoint LBA bands) proving DEVIO_START owner
#                             attribution, not just positional guessing.

def _devio_kernel(isa: str) -> Path:
    """Kernel to boot for the devio probe family.  A block-device probe
    needs virtio-blk compiled IN (CONFIG_VIRTIO_BLK=y): the busybox guest
    has no modprobe/hotplug wiring to pull in a module, so a kernel that
    only carries virtio_blk as =m never grows /dev/vda and every probe
    below reports the (pre-existing) NO_VDA skip.  CST_DEVIO_KERNEL
    overrides the shared system-mode kernel asset (SYS.default_kernel) for
    exactly these probes, so a maintainer with a virtio-blk-enabled build
    can point at it without moving every OTHER system-mode check off the
    default kernel."""
    override = os.environ.get("CST_DEVIO_KERNEL")
    return Path(override) if override else SYS.default_kernel(isa)


# x86-64 START/END markers: 3x `mov $imm,%eax` (champsim_marker.h) inlined
# directly, exactly as devio2/workload2.c did — this workload is its own
# tiny standalone C program, not generator.py's marker-emitting diamond CFG,
# so it embeds the same fixed byte pattern the plugin's detector matches.
_DEVIO_WORKLOAD_C = r"""/* champsim_tracer validator -- devio payload-oracle workload (generated).
 * Brackets a KNOWN, deterministic O_DIRECT|O_SYNC disk-request sequence
 * inside the trace marker window: {nops} writes at ascending 4K-block
 * offsets starting at block {base}, then {nops} reads at the same offsets.
 * O_DIRECT|O_SYNC forces one real device request per pwrite/pread (no
 * merging), so the sequence the decoded trace shows is exactly the one
 * this program issues.  SPDX-License-Identifier: GPL-2.0-or-later */
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static inline void marker_start(void){{
    __asm__ __volatile__(
        "mov $0x43535401,%%eax\n\t"
        "mov $0x43535401,%%eax\n\t"
        "mov $0x43535401,%%eax\n\t" ::: "eax");
}}
static inline void marker_end(void){{
    __asm__ __volatile__(
        "mov $0x43535402,%%eax\n\t"
        "mov $0x43535402,%%eax\n\t"
        "mov $0x43535402,%%eax\n\t" ::: "eax");
}}

#define BLK 4096

int main(void)
{{
    long base = {base}L;
    int  nops = {nops};
    int  fill = {fill};
    int  pin_cpu = {cpu};

    /* Pin to one vCPU before any traced work: the tracer's kernel-mode
     * ownership model (g_vcpu_cur_tid, champsim_tracer.cc) attributes
     * kernel code to whichever thread most recently entered the kernel
     * on that vCPU -- a thread the guest scheduler migrates mid-syscall
     * leaves its in-flight kernel work (here, the block-layer submission
     * + virtqueue kick) with no clean owner on the vCPU it left.  This
     * is a documented requirement of the whole ownership model, not
     * devio-specific (see the pinned-process migration-detect guard
     * comment in champsim_tracer.cc); an unpinned multi-process -smp
     * workload is outside its clean-attribution envelope regardless of
     * how the block-device doorbell is correlated. */
    if (pin_cpu >= 0) {{
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(pin_cpu, &set);
        if (sched_setaffinity(0, sizeof(set), &set) != 0) {{ return 6; }}
    }}

    marker_start();

    void *buf = NULL;
    if (posix_memalign(&buf, BLK, BLK) != 0) {{ marker_end(); return 2; }}

    int fd = open("{dev}", O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {{ marker_end(); return 3; }}

    for (int i = 0; i < nops; i++) {{
        memset(buf, fill + (i & 0xf), BLK);
        long off = (base + i) * (long)BLK;
        if (pwrite(fd, buf, BLK, off) != BLK) {{ marker_end(); return 4; }}
    }}
    fsync(fd);

    for (int i = 0; i < nops; i++) {{
        long off = (base + i) * (long)BLK;
        if (pread(fd, buf, BLK, off) != BLK) {{ marker_end(); return 5; }}
    }}
    fsync(fd);
    close(fd);

    marker_end();
    return 0;
}}
"""


def _build_devio_c(out_dir: Path, name: str, base: int, nops: int,
                   fill: int, dev: str = "/dev/vda", cpu: int = -1) -> Path:
    """Render + statically compile _DEVIO_WORKLOAD_C for (base, nops,
    fill).  Full libc (posix_memalign/open/pwrite/pread/fsync), so unlike
    the diamond generator's asm workloads this is a plain static build —
    no -nostdlib/-nostartfiles.  @cpu >= 0 pins the workload to that vCPU
    via sched_setaffinity before any traced work -- required to stay
    inside the tracer's kernel-mode ownership model's clean-attribution
    envelope on a concurrent multi-process -smp run (see the template's
    own comment); -1 (default) leaves it unpinned, fine for a single-
    process run with no other traced process to race against."""
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / f"{name}.c"
    src.write_text(_DEVIO_WORKLOAD_C.format(base=base, nops=nops, fill=fill,
                                            dev=dev, cpu=cpu))
    binp = out_dir / name
    subprocess.check_call(["gcc", "-O1", "-static", "-fno-stack-protector",
                           str(src), "-o", str(binp)])
    return binp


def _devio_expected(base: int, nops: int) -> list:
    """The known (rw, bytes, block) sequence _DEVIO_WORKLOAD_C(base, nops)
    issues: nops WRITEs at ascending LBA, then nops READs at the same LBAs
    -- the two O_DIRECT|O_SYNC loops, each call its own device request.
    FLUSH requests (fsync) are deliberately excluded from this exact list:
    their COUNT depends on the guest kernel's O_SYNC write-barrier policy
    (observed 2x per write + 1 trailing against the reference harness),
    not on anything this workload explicitly calls, so pinning an exact
    flush count would assert a kernel implementation detail rather than
    the workload's own contract.  _devio_flush_sanity covers them instead
    (payload must be empty, wherever they fall)."""
    lba = lambda i: (base + i) * 8   # BLK(4096) >> CST_DEVIO_LBA_SHIFT(9)
    out = [("write", 4096, lba(i)) for i in range(nops)]
    out += [("read", 4096, lba(i)) for i in range(nops)]
    return out


_DEVIO_START_RE = re.compile(
    r"; DEVIO START req=(\d+) (\w+) bytes=(\d+) block=(\d+) "
    r"\(thread=(\d+) asid=(\d+) attr=(\w+)\)")
_DEVIO_STOP_RE = re.compile(
    r"; DEVIO STOP  req=(\d+) \(thread=(\d+) asid=(\d+)\)")


def _decode_devio_events(cfg: MPConfig, cst: Path) -> list:
    """Every DEVIO_START/STOP record cst_decode's disasm renderer surfaces,
    in stream order: {"kind": "start"|"stop", "req", "rw", "bytes",
    "block", "thread", "asid", "exact"} ("stop" only sets kind/req/thread/
    asid).  --format=disasm is the only cst_decode mode with full DEVIO
    payload text: --format=raw's structural walker (cst_raw.cc dump_body)
    has no DEVIO_* branch and aborts the rest of the walk on the first one
    it meets, and the header's encoding-map dump only proves the tag NAMES
    were advertised (g_devio_map_active), not that any request actually
    happened -- the smoke-test gap this probe family replaces."""
    _, raw = _run([_decode(cfg), "--format=disasm", str(cst)], timeout=300)
    out = []
    for line in raw.splitlines():
        m = _DEVIO_START_RE.search(line)
        if m:
            out.append({"kind": "start", "req": int(m.group(1)),
                        "rw": m.group(2), "bytes": int(m.group(3)),
                        "block": int(m.group(4)), "thread": int(m.group(5)),
                        "asid": int(m.group(6)),
                        "exact": m.group(7) == "exact"})
            continue
        m = _DEVIO_STOP_RE.search(line)
        if m:
            out.append({"kind": "stop", "req": int(m.group(1)),
                        "thread": int(m.group(2)), "asid": int(m.group(3))})
    return out


def _devio_pairing_check(events: list) -> tuple:
    """Every STOP must pair a prior START by request_id: no orphan STOPs
    (a STOP whose request_id was never opened), no dangling STARTs (a
    START never closed), no duplicate STARTs, and a STOP must inherit its
    paired START's owner when that START is exact-attributed (the
    decoder's own devio_owner_ contract, re-asserted here)."""
    open_starts: dict = {}
    dup_starts = []
    orphan_stops = []
    owner_mismatch = []
    for e in events:
        if e["kind"] == "start":
            if e["req"] in open_starts:
                dup_starts.append(e["req"])
            open_starts[e["req"]] = e
        else:
            st = open_starts.pop(e["req"], None)
            if st is None:
                orphan_stops.append(e["req"])
            elif st["exact"] and (st["thread"], st["asid"]) != \
                    (e["thread"], e["asid"]):
                owner_mismatch.append(e["req"])
    dangling = sorted(open_starts.keys())
    ok = not (orphan_stops or dangling or dup_starts or owner_mismatch)
    detail = (f"stops={sum(1 for e in events if e['kind'] == 'stop')} "
              f"orphan_stops={orphan_stops} dangling_starts={dangling} "
              f"dup_starts={dup_starts} owner_mismatch={owner_mismatch}")
    return ok, detail


def _devio_payload_check(events: list, expected: list) -> tuple:
    """Filter to non-flush STARTs, in stream order, and assert they equal
    @expected EXACTLY: same length, same (rw, bytes, block) tuples, same
    order -- the workload's own known request list (_devio_expected)."""
    got = [(e["rw"], e["bytes"], e["block"]) for e in events
           if e["kind"] == "start" and e["rw"] != "flush"]
    ok = got == expected
    detail = f"got={len(got)} expected={len(expected)}"
    if not ok:
        mismatch = next(((i, g, x) for i, (g, x)
                         in enumerate(zip(got, expected)) if g != x), None)
        if mismatch:
            i, g, x = mismatch
            detail += f" first_mismatch@{i}: got={g} want={x}"
        else:
            detail += f" length mismatch (got[:3]={got[:3]} want[:3]={expected[:3]})"
    return ok, detail


def _devio_flush_sanity(events: list) -> tuple:
    bad = [e["req"] for e in events if e["kind"] == "start"
           and e["rw"] == "flush" and (e["bytes"] != 0 or e["block"] != 0)]
    return not bad, f"bad_flush_payload_reqs={bad}"


_INIT_DEVIO_SINGLE = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst devio guest: $(uname -r) ==="
if [ -b /dev/vda ]; then
  echo "=== /dev/vda present ==="
else
  echo "=== NO_VDA (guest kernel lacks virtio-blk) ==="
fi
/devio_wl
echo "=== DEVIO_WL_EXIT=$? ==="
echo "=== poweroff ==="
poweroff -f
"""


def run_devio_probe(cfg: MPConfig) -> MPResult:
    """Single marked process, known I/O: pairing oracle (every STOP pairs
    a prior START, no orphans) + exact payload oracle (R/W direction,
    bytes, and LBA match the workload's known request list byte-for-byte,
    not just "some DEVIO records appeared")."""
    isa = "x86_64"
    skip = _preconditions(cfg, isa)
    if skip:
        return MPResult(ok=True, subchecks=[], artifacts={}, skipped=True,
                        skip_reason=skip)
    od = cfg.out_dir
    od.mkdir(parents=True, exist_ok=True)
    base, nops, fill = 0, 8, 0xA0
    binp = _build_devio_c(od / "wl", "devio_wl", base, nops, fill)
    cpio = _stage(isa, od / "stage", [("devio_wl", binp)],
                  _INIT_DEVIO_SINGLE)
    scratch = od / "scratch.raw"
    with open(scratch, "wb") as f:
        f.truncate(4 * 1024 * 1024)
    out_base = od / "devio"
    plugin_opts = (f"outfile={out_base},wpdepth={cfg.depth},"
                   f"trace_window=marker:policy=latch+"
                   f"simulation={cfg.budget},memdata=1,devio=1")
    extra_qemu = ["-drive", f"file={scratch},format=raw,if=none,id=d0",
                  "-device", "virtio-blk-pci,drive=d0,ioeventfd=off"]
    rc, console, cst = _boot(cfg, isa, cpio, out_base, plugin_opts,
                             extra_qemu=extra_qemu, kernel=_devio_kernel(isa))
    ctext = console.read_text(errors="replace") if console.exists() else ""
    subs: list = []
    if not cst.exists():
        subs.append(SubCheck("boot produced a trace", False,
                             f"qemu_rc={rc} cst MISSING"))
        return _emit("devio disk-I/O records", subs)
    events = _decode_devio_events(cfg, cst)
    if not any(e["kind"] == "start" for e in events):
        reason = ("guest kernel lacks virtio-blk (/dev/vda absent)"
                  if "NO_VDA" in ctext else
                  "no real DEVIO_START records observed")
        return MPResult(ok=True, subchecks=[SubCheck(
            "devio records", False, reason)],
            artifacts={"cst": str(cst)}, skipped=True, skip_reason=reason)

    expected = _devio_expected(base, nops)
    pair_ok, pair_detail = _devio_pairing_check(events)
    subs.append(SubCheck(
        "1. every STOP pairs a prior START by request_id (no orphans/"
        "dangling/duplicates)", pair_ok, pair_detail))
    payload_ok, payload_detail = _devio_payload_check(events, expected)
    subs.append(SubCheck(
        "2. R/W direction + bytes + LBA match the workload's known "
        "request list exactly", payload_ok, payload_detail))
    flush_ok, flush_detail = _devio_flush_sanity(events)
    subs.append(SubCheck(
        "3. FLUSH requests carry no payload (bytes=0 block=0)",
        flush_ok, flush_detail))
    ok_a, asum = _audit_clean(cfg, cst)
    src = _strict_rc(cfg, cst)
    subs.append(SubCheck("4. audit clean + strict rc=0",
                         ok_a and src == 0,
                         f"strict_rc={src} audit[{asum}]"))
    res = _emit("devio disk-I/O records", subs)
    res.artifacts = {"cst": str(cst)}
    return res


_INIT_DEVIO_ATTRIB = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst devio attribution guest: $(uname -r) ==="
if [ -b /dev/vda ]; then
  echo "=== /dev/vda present ==="
else
  echo "=== NO_VDA (guest kernel lacks virtio-blk) ==="
fi
/devio_lo &
lopid=$!
/devio_hi &
hipid=$!
echo "=== launched lo=$lopid hi=$hipid ==="
wait $lopid; echo "=== devio_lo exit=$? ==="
wait $hipid; echo "=== devio_hi exit=$? ==="
echo "=== poweroff ==="
poweroff -f
"""


def run_devio_attrib_probe(cfg: MPConfig) -> MPResult:
    """Two marked processes (policy=latch), each pinned to its own ASID
    AND its own vCPU (sched_setaffinity in _DEVIO_WORKLOAD_C -- required
    to stay inside the tracer's kernel-mode ownership model's clean-
    attribution envelope; see that template's comment), CONCURRENTLY
    issue O_DIRECT|O_SYNC disk I/O to DISJOINT LBA bands on one
    virtio-blk disk under -smp 2 (ioeventfd=off) -- the exact-owner
    attribution scenario from 88d9b7e526.  The block backend issues each
    request off the vCPU thread, so a POSITIONAL record would attribute it
    to whichever process's context happened to be in force at the record's
    fall position in the interleaved stream, not the process that actually
    issued it; asserts every DEVIO_START is attr=exact and that the LOW
    band resolves to exactly one (thread,asid) owner, the HIGH band to a
    DIFFERENT one, despite the interleaving."""
    isa = "x86_64"
    skip = _preconditions(cfg, isa)
    if skip:
        return MPResult(ok=True, subchecks=[], artifacts={}, skipped=True,
                        skip_reason=skip)
    od = cfg.out_dir
    od.mkdir(parents=True, exist_ok=True)
    lo_base, hi_base, nops = 0, 256, 8
    # Pin each workload to its own vCPU (cpu=0 / cpu=1): required to stay
    # inside the tracer's kernel-mode ownership model's clean-attribution
    # envelope (see _DEVIO_WORKLOAD_C's own comment and the pinned-process
    # migration-detect guard in champsim_tracer.cc) -- an unpinned process
    # the guest scheduler migrates mid-syscall leaves its in-flight kernel
    # work (the block-layer submission + virtqueue kick) with no clean
    # owner on the vCPU it left, independent of how devio correlates the
    # doorbell.
    bin_lo = _build_devio_c(od / "lo", "devio_lo", lo_base, nops, 0xA0,
                            cpu=0)
    bin_hi = _build_devio_c(od / "hi", "devio_hi", hi_base, nops, 0xB0,
                            cpu=1)
    cpio = _stage(isa, od / "stage",
                  [("devio_lo", bin_lo), ("devio_hi", bin_hi)],
                  _INIT_DEVIO_ATTRIB)
    scratch = od / "scratch.raw"
    with open(scratch, "wb") as f:
        f.truncate(4 * 1024 * 1024)
    out_base = od / "devio_attrib"
    plugin_opts = (f"outfile={out_base},wpdepth={cfg.depth},"
                   f"trace_window=marker:policy=latch+"
                   f"simulation={cfg.budget},memdata=1,devio=1")
    extra_qemu = ["-smp", "2",
                  "-drive", f"file={scratch},format=raw,if=none,id=d0",
                  "-device", "virtio-blk-pci,drive=d0,ioeventfd=off"]
    rc, console, cst = _boot(cfg, isa, cpio, out_base, plugin_opts,
                             extra_qemu=extra_qemu, kernel=_devio_kernel(isa))
    ctext = console.read_text(errors="replace") if console.exists() else ""
    subs: list = []
    if not cst.exists():
        subs.append(SubCheck("boot produced a trace", False,
                             f"qemu_rc={rc} cst MISSING"))
        return _emit("devio exact-owner attribution (-smp 2)", subs)
    events = _decode_devio_events(cfg, cst)
    starts = [e for e in events if e["kind"] == "start"]
    if not starts:
        reason = ("guest kernel lacks virtio-blk (/dev/vda absent)"
                  if "NO_VDA" in ctext else
                  "no real DEVIO_START records observed")
        return MPResult(ok=True, subchecks=[SubCheck(
            "devio records", False, reason)],
            artifacts={"cst": str(cst)}, skipped=True, skip_reason=reason)

    lo_lba = {(lo_base + i) * 8 for i in range(nops)}
    hi_lba = {(hi_base + i) * 8 for i in range(nops)}

    exact = [e for e in starts if e["exact"]]
    subs.append(SubCheck(
        "1. every DEVIO_START is exact-attributed (ioeventfd=off vCPU "
        "doorbell)", len(exact) == len(starts),
        f"exact={len(exact)}/{len(starts)}"))

    owner_ctxs = {(e["thread"], e["asid"]) for e in exact}
    subs.append(SubCheck(
        "2. two distinct (thread,asid) owners observed",
        len(owner_ctxs) >= 2, f"owner_contexts={sorted(owner_ctxs)}"))

    band_starts = [e for e in exact if e["rw"] != "flush"]
    lo_owners = {(e["thread"], e["asid"]) for e in band_starts
                if e["block"] in lo_lba}
    hi_owners = {(e["thread"], e["asid"]) for e in band_starts
                if e["block"] in hi_lba}
    subs.append(SubCheck(
        "3. LOW-band requests attribute to ONE owner, HIGH-band to a "
        "DIFFERENT one (disjoint by LBA, despite an interleaved stream)",
        len(lo_owners) == 1 and len(hi_owners) == 1
        and lo_owners != hi_owners,
        f"lo_owners={sorted(lo_owners)} hi_owners={sorted(hi_owners)}"))

    lo_cnt = sum(1 for e in band_starts if e["block"] in lo_lba)
    hi_cnt = sum(1 for e in band_starts if e["block"] in hi_lba)
    subs.append(SubCheck(
        "4. request counts match the known per-process list (2*nops each)",
        lo_cnt == 2 * nops and hi_cnt == 2 * nops,
        f"lo={lo_cnt} hi={hi_cnt} want={2 * nops} each"))

    pair_ok, pair_detail = _devio_pairing_check(events)
    subs.append(SubCheck(
        "5. every STOP pairs a prior START by request_id, inheriting its "
        "owner (no orphans/dangling)", pair_ok, pair_detail))

    ok_a, asum = _audit_clean(cfg, cst)
    src = _strict_rc(cfg, cst)
    subs.append(SubCheck("6. audit clean + strict rc=0",
                         ok_a and src == 0,
                         f"strict_rc={src} audit[{asum}]"))
    res = _emit("devio exact-owner attribution (-smp 2)", subs)
    res.artifacts = {"cst": str(cst)}
    return res


def devio_mutation_substrate(build_dir: Path, work_root: Path) -> dict | None:
    """Build + trace a real single-process devio substrate for the
    mutation tier (devio_stop_drop), reusing run_devio_probe's own build/
    boot/decode pipeline so the mutation exercises the SAME wire a real
    probe run produces -- mirrors _smc.mutation_substrate's dedicated-
    substrate pattern (the shared diamond-CFG substrate carries no DEVIO
    records at all).  Returns {"cst", "events"} or None when devio
    coverage is unavailable in this environment (compiler/qemu-system/
    virtio-blk kernel absent, or no real DEVIO_START observed)."""
    cfg = MPConfig(build_dir=build_dir, out_dir=work_root)
    res = run_devio_probe(cfg)
    cst = res.artifacts.get("cst")
    if res.skipped or not cst or not Path(cst).exists():
        return None
    events = _decode_devio_events(cfg, Path(cst))
    if not any(e["kind"] == "stop" for e in events):
        return None
    return {"cst": cst, "events": events}


# ---------------------------------------------------------------------------
# scenario 6: faults / interrupts — the two handler-tracing flags (system)
# ---------------------------------------------------------------------------

def _depth_hist(cfg: MPConfig, cst: Path) -> dict:
    """{depth -> count} over the trace's per-entry fault trailers."""
    _, raw = _run([_decode(cfg), "--format=raw", str(cst)], timeout=600)
    hist: dict = {}
    for m in re.finditer(r"fault_depth=(\d+)", raw):
        d = int(m.group(1))
        hist[d] = hist.get(d, 0) + 1
    return hist


def _anchor_count(cfg: MPConfig, cst: Path) -> int:
    """Number of entries carrying a non-empty fault anchor list."""
    _, raw = _run([_decode(cfg), "--format=raw", str(cst)], timeout=600)
    return len(re.findall(r"anchors=\[\d", raw))


def run_faults_interrupts_probe(cfg: MPConfig) -> MPResult:
    """Exercise faults=0 and interrupts=1 against a fault-triggering system
    workload:

      * faults=1 (default) establishes the workload triggers synchronous
        handlers (a depth>=1 entry) — otherwise faults=0 proves nothing;
      * faults=0 SUPPRESSES them: no depth>0 entry, no anchor, and the
        interrupted blocks still reassemble whole (audit clean / strict rc=0);
      * interrupts=1 CAPTURES the asynchronous handler: depth>=1 present,
        audit clean, strict rc=0, no WP storm (boot completes in-budget).
    """
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
    common = (f"wpdepth={cfg.depth},"
              f"trace_window=marker:simulation={cfg.budget},memdata=1")
    subs: list = []

    # --- (1) faults=1 baseline: the workload must trigger a sync handler ---
    out1 = od / "faults1"
    rc1, _c1, cst1 = _boot(cfg, isa, cpio, out1, f"outfile={out1},{common}")
    base_deep = 0
    if cst1.exists():
        h1 = _depth_hist(cfg, cst1)
        base_deep = sum(c for d, c in h1.items() if d >= 1)
    subs.append(SubCheck(
        "1. faults=1 baseline triggers a synchronous handler (depth>=1)",
        base_deep >= 1, f"qemu_rc={rc1} deep_entries={base_deep}"))

    # --- (2) faults=0: handler excluded, interrupted blocks whole ---
    out0 = od / "faults0"
    rc0, _c0, cst0 = _boot(cfg, isa, cpio, out0,
                           f"outfile={out0},{common},faults=0")
    if not cst0.exists():
        subs.append(SubCheck("2. faults=0 boot produced a trace", False,
                             f"qemu_rc={rc0} cst MISSING"))
        return _emit("faults / interrupts handler-tracing flags", subs)
    h0 = _depth_hist(cfg, cst0)
    deep0 = sum(c for d, c in h0.items() if d >= 1)
    anch0 = _anchor_count(cfg, cst0)
    ok0a, asum0 = _audit_clean(cfg, cst0)
    src0 = _strict_rc(cfg, cst0)
    subs.append(SubCheck(
        "2. faults=0 excludes handlers (no depth>0, no anchors) + clean",
        deep0 == 0 and anch0 == 0 and ok0a and src0 == 0,
        f"deep_entries={deep0} anchors={anch0} strict_rc={src0} audit[{asum0}]"))

    # --- (3) interrupts=1: async handler captured at depth>=1 ---
    outi = od / "interrupts1"
    rci, _ci, csti = _boot(cfg, isa, cpio, outi,
                           f"outfile={outi},{common},interrupts=1")
    if not csti.exists():
        subs.append(SubCheck("3. interrupts=1 boot produced a trace", False,
                             f"qemu_rc={rci} cst MISSING"))
        return _emit("faults / interrupts handler-tracing flags", subs)
    hi = _depth_hist(cfg, csti)
    deepi = sum(c for d, c in hi.items() if d >= 1)
    okia, asumi = _audit_clean(cfg, csti)
    srci = _strict_rc(cfg, csti)
    subs.append(SubCheck(
        "3. interrupts=1 captures async handlers (depth>=1) + clean + rc=0",
        deepi >= 1 and okia and srci == 0 and rci == 0,
        f"qemu_rc={rci} deep_entries={deepi} strict_rc={srci} audit[{asumi}]"))

    res = _emit("faults / interrupts handler-tracing flags", subs)
    res.artifacts = {"faults0": str(cst0), "interrupts1": str(csti)}
    return res
