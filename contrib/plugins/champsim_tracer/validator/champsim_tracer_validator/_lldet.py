"""Calibrated watchdog with condition sampling (deadlock/livelock detection).

External, harness-side machinery only: nothing in here touches the tracer or
QEMU.  The tracer blocks honestly when its consumer stalls; it is the
HARNESS's job to judge whether a test cell is still doing useful work.  The
design implements the maintainer's ruling on automated livelock detection
verbatim: *"setting reasonable timeouts, given the number of instructions you
are tracing, non-livelocking traces should offer good estimates"* — plus one
refinement that separates this from a dumb timeout: when a cell crosses its
budgeted time, the watchdog samples the CONDITION before killing anything
(this project's standard: instrument the condition, not the outcome).

The two halves:

**Calibrated timeouts (the budget).**  A cell's instruction budget is known
up front (``--stop`` / the marker window's user-insn budget).  Expected wall
time is ``boot_floor + budget / ips`` where ``ips`` is the MEASURED healthy
throughput of that (isa, mode, smp, wp) configuration, taken from
``lldet_calibration.json`` next to this module — a checked-in data file
produced by running the validator's own healthy cells and recording
insns-per-wall-second, with the measurement's provenance (date, HEAD sha,
host) stored beside the numbers.  The timeout is ``k * expected`` with a
generous ``k`` (stated in the table file).  A cell with no stated budget (a
run that traces to workload exit) falls back to a per-mode ceiling.
Recalibration is one command::

    python -m champsim_tracer_validator lldet_calibrate \\
        --build-dir <build> -o <scratch-dir> --write

**Condition sampling at the threshold (the verdict).**  Crossing the
deadline never kills blind.  Two samples a few seconds apart measure the
qemu process group's host CPU time, the trace output's size (the
``.cst`` / ``.body_tmp`` files) and the console log's size, and classify:

===========  =============================  ================================
verdict      condition                      action
===========  =============================  ================================
DEADLOCK     zero CPU delta, zero growth    kill; verdict + stacks in log
LIVELOCK     CPU burning, zero growth       kill; verdict + stacks in log
SLOW         output still growing           EXTEND the deadline (bounded,
                                            logged); kill only if a later
                                            sample stops growing
===========  =============================  ================================

The SLOW arm exists because of a measured false-kill class: a healthy cell
on a loaded host is *slow*, not stuck, and a watchdog that kills at first
deadline accuses it falsely.  A cell that is provably progressing is never
killed at its deadline; the only bound on a progressing cell is the hard
ceiling (``hard_ceiling_mult`` x the calibrated timeout), an operational
last resort that names itself when it fires.

A watchdog kill is LOUD: the verdict, both samples, and a gdb backtrace
(where ptrace allows — the child is made ptraceable via
``prctl(PR_SET_PTRACER_ANY)``, the same trick as the wpflush harness's
``ptraceable`` wrapper) are written to the cell's log and to a ``.lldet``
sidecar, and the exit code is :data:`LLDET_EXIT`.  A kill that reads as an
ordinary failure is the silent-false-success shape this project keeps
finding; the verdict line is grep-able (``\\[lldet\\] VERDICT:``) precisely
so no cell log can carry one silently.

Environment knobs (operational / testing):

``CST_LLDET=off``      disable the watchdog (plain unwatched run).
``CST_LLDET_K=<f>``    override the safety factor ``k``.
``CST_LLDET_TIMEOUT=<s>``  override the computed base timeout outright.
``CST_LLDET_TABLE=<path>`` load an alternate calibration table.

Author: Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later
"""

from __future__ import annotations

import ctypes
import glob
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
import argparse
from pathlib import Path

# Exit status of a run the watchdog killed.  Distinct from the plugin's own
# RT_GATE_EXIT (88) so the two instruments never masquerade as each other.
LLDET_EXIT = 89

_TABLE_PATH = Path(__file__).with_name("lldet_calibration.json")

_HZ = os.sysconf("SC_CLK_TCK")

# Pre-bound libc handle: the prctl call happens in a post-fork pre-exec
# context where importing/allocating is off-limits.
_LIBC = ctypes.CDLL(None, use_errno=True)
_PR_SET_PTRACER = 0x59616D61          # 'Yama'
_PR_SET_PTRACER_ANY = ctypes.c_ulong(-1).value


def ptraceable_preexec() -> None:
    """preexec_fn: allow any process to ptrace the child (survives execve),
    so the watchdog's ``gdb -p`` works under yama ptrace_scope=1.  Failure
    is non-fatal — it only costs the backtrace, never the verdict."""
    try:
        _LIBC.prctl(_PR_SET_PTRACER, _PR_SET_PTRACER_ANY, 0, 0, 0)
    except Exception:
        pass


# --------------------------------------------------------------------------
# Calibration table
# --------------------------------------------------------------------------

def config_key(isa: str, mode: str, smp: int, wpdepth: int) -> str:
    """The table key for one measured configuration."""
    return f"{isa}/{mode}/smp{int(smp)}/{'wp' if wpdepth > 0 else 'nowp'}"


def load_table(path: Path | None = None) -> dict:
    """Load the calibration table; {} when absent (every lookup then lands
    on the built-in ceilings, and the timeout note says so)."""
    p = Path(os.environ.get("CST_LLDET_TABLE") or path or _TABLE_PATH)
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


# Built-in last-resort defaults, used only when the table cannot answer.
# Deliberately huge: an uncalibrated harness must err toward patience, and
# the condition sampler still bounds a genuinely stuck cell.
_DEFAULTS = {
    "k": 5.0,
    "boot_floor_s": {"user": 10.0, "system": 120.0},
    "fallback_ceiling_s": {"user": 900.0, "system": 2400.0},
    "hard_ceiling_mult": 12.0,
}


def _tbl(table: dict, key: str):
    return table.get(key, _DEFAULTS[key])


def lookup_ips(table: dict, key: str) -> tuple[float | None, str]:
    """Healthy throughput (insns per wall second) for @key, degrading
    gracefully: exact config -> slowest sibling of the same isa+mode ->
    slowest config of the same mode.  Returns (ips, provenance note);
    (None, note) when the table has nothing usable — the caller falls back
    to the per-mode ceiling."""
    configs = table.get("configs", {})
    ent = configs.get(key)
    if ent and ent.get("ips"):
        return float(ent["ips"]), f"calibrated {key}"
    isa, mode = key.split("/")[:2]
    for scope, pred in (
            (f"slowest sibling of {isa}/{mode}",
             lambda k: k.startswith(f"{isa}/{mode}/")),
            (f"slowest {mode}-mode config",
             lambda k: k.split("/")[1] == mode)):
        sibs = [float(v["ips"]) for k, v in configs.items()
                if pred(k) and v.get("ips")]
        if sibs:
            return min(sibs), f"{scope} (no entry for {key})"
    return None, f"no calibration for {key} or any {mode}-mode config"


def compute_timeout(table: dict, key: str,
                    budget: int | None) -> tuple[float, str]:
    """The calibrated deadline for one cell: ``k * (boot_floor +
    budget/ips)``, or the per-mode fallback ceiling when the budget is
    unstated or the table has no throughput to divide by.  Returns
    (timeout_s, human note naming every number that went into it)."""
    mode = key.split("/")[1]
    k = float(os.environ.get("CST_LLDET_K") or _tbl(table, "k"))
    override = os.environ.get("CST_LLDET_TIMEOUT")
    if override:
        return float(override), f"CST_LLDET_TIMEOUT override ({override}s)"
    floor = float(_tbl(table, "boot_floor_s").get(
        mode, _DEFAULTS["boot_floor_s"][mode]))
    ceiling = float(_tbl(table, "fallback_ceiling_s").get(
        mode, _DEFAULTS["fallback_ceiling_s"][mode]))
    if budget is None:
        return ceiling, (f"no stated budget -> per-{mode} ceiling "
                         f"{ceiling:.0f}s")
    ips, note = lookup_ips(table, key)
    if ips is None:
        return ceiling, f"{note} -> per-{mode} ceiling {ceiling:.0f}s"
    expected = floor + budget / ips
    return k * expected, (f"budget={budget} insns at {ips:,.0f} insns/s "
                          f"({note}) + boot floor {floor:.0f}s -> expected "
                          f"{expected:.1f}s, k={k:g} -> {k * expected:.1f}s")


# --------------------------------------------------------------------------
# Condition sampling
# --------------------------------------------------------------------------

def default_growth_patterns(prefix: str) -> list[str]:
    """Glob patterns for the trace output a run with outfile=@prefix grows
    while healthy: the packed .cst (and per-simpoint .cst members) plus the
    in-flight .body_tmp sidecar (compressed or not)."""
    return [f"{prefix}*.cst*", f"{prefix}*.body_tmp*"]


def _pgroup_cpu_io(pgid: int) -> tuple[float, int]:
    """(host CPU seconds, bytes written) consumed so far by every process
    in process group @pgid.  Scanning /proc keeps the compress child
    (zstd) on the books alongside qemu itself.

    The write counter (/proc/<pid>/io wchar) is the load-bearing progress
    signal for compressed runs: with ``compress=`` the on-disk
    ``.body_tmp.<ext>`` can sit at ZERO bytes for the entire run while the
    compressor buffers, so file sizes alone would accuse a perfectly
    healthy cell of producing nothing (measured: a 15s x86_64 user cell
    whose body_tmp.zst stayed 0B to the end while qemu's wchar grew in
    ~4MB stdio flushes).  wchar counts the plugin's writes INTO the
    compress pipe (and the progress lines on stderr), so it moves whenever
    the tracer emits -- and stands still for a frozen or spinning qemu."""
    cpu = 0
    wchar = 0
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat", "rb") as f:
                st = f.read().decode("ascii", errors="replace")
            f2 = st[st.rindex(")") + 2:].split()
            if int(f2[2]) != pgid:        # pgrp
                continue
            cpu += int(f2[11]) + int(f2[12])   # utime + stime
        except (OSError, ValueError, IndexError):
            continue
        try:
            with open(f"/proc/{d}/io", "rb") as f:
                for line in f.read().decode("ascii",
                                            errors="replace").splitlines():
                    if line.startswith("wchar:"):
                        wchar += int(line.split()[1])
                        break
        except (OSError, ValueError, IndexError):
            pass
    return cpu / _HZ, wchar


def _bytes_of(patterns: list[str]) -> int:
    total = 0
    for pat in patterns:
        for p in glob.glob(pat):
            try:
                total += os.stat(p).st_size
            except OSError:
                pass
    return total


def collect_stacks(pid: int) -> str:
    """Photograph the stuck process: per-thread state/wchan from /proc
    (always available), then ``gdb -p`` thread backtraces where ptrace
    allows.  Best-effort by design — the verdict never depends on it."""
    lines = [f"--- /proc/{pid} thread states ---"]
    try:
        for tid in sorted(os.listdir(f"/proc/{pid}/task"), key=int):
            try:
                st = open(f"/proc/{pid}/task/{tid}/stat",
                          "rb").read().decode("ascii", errors="replace")
                state = st[st.rindex(")") + 2:].split()[0]
                wchan = open(f"/proc/{pid}/task/{tid}/wchan",
                             "rb").read().decode("ascii", errors="replace")
                lines.append(f"  tid {tid}: state={state} wchan={wchan or '-'}")
            except OSError:
                continue
    except OSError as e:
        lines.append(f"  (unreadable: {e})")
    if shutil.which("gdb"):
        lines.append(f"--- gdb -p {pid} (thread apply all bt) ---")
        try:
            r = subprocess.run(
                ["gdb", "-p", str(pid), "-batch",
                 "-ex", "set pagination off",
                 "-ex", "thread apply all bt 25",
                 "-ex", "info threads"],
                capture_output=True, text=True, timeout=120)
            out = (r.stdout or "") + (r.stderr or "")
            lines.extend(out.splitlines()[:400])
        except (subprocess.TimeoutExpired, OSError) as e:
            lines.append(f"  (gdb failed: {e})")
    else:
        lines.append("--- gdb not on PATH; /proc evidence only ---")
    return "\n".join(lines)


@dataclass
class Verdict:
    kind: str                     # DEADLOCK | LIVELOCK | HARD_CEILING
    summary: str
    evidence: list[str] = field(default_factory=list)
    stacks: str = ""

    def block(self) -> str:
        out = [f"[lldet] VERDICT: {self.kind} -- {self.summary}"]
        out += [f"[lldet] {e}" for e in self.evidence]
        if self.stacks:
            out.append(self.stacks)
        out.append(f"[lldet] the cell FAILED by watchdog verdict "
                   f"(exit {LLDET_EXIT})")
        return "\n".join(out)


@dataclass
class _Sample:
    t: float
    cpu_s: float
    trace_b: int
    console_b: int | None
    wchar_b: int

    def describe(self) -> str:
        cb = "n/a" if self.console_b is None else str(self.console_b)
        return (f"cpu={self.cpu_s:.1f}s trace_bytes={self.trace_b} "
                f"console_bytes={cb} written_bytes={self.wchar_b}")


class Watch:
    """One cell's watchdog: a calibrated deadline plus the condition
    sampler that adjudicates a crossing.  Drive it either through
    :func:`run_watched` (it owns the child) or embedded in an existing
    poll loop via :meth:`adjudicate` (the loop owns the child and does
    the killing)."""

    # CPU burn below this fraction of one core across the sample gap is
    # "zero CPU delta": a blocked/frozen process, not a spinning one.
    CPU_IDLE_CORES = 0.02
    # Long enough to integrate over the tracer's bursty output (stdio
    # flushes into the compress pipe arrive in multi-MB steps seconds
    # apart on a slow cell; the stderr progress line fills the gaps).
    SAMPLE_GAP_S = 10.0

    def __init__(self, *, key: str, budget: int | None,
                 growth_patterns: list[str],
                 console_path: Path | None = None,
                 sidecar_path: Path | None = None,
                 table: dict | None = None,
                 label: str = ""):
        self.key = key
        self.budget = budget
        self.growth_patterns = list(growth_patterns)
        self.console_path = Path(console_path) if console_path else None
        self.sidecar_path = Path(sidecar_path) if sidecar_path else None
        self.label = label or key
        table = load_table() if table is None else table
        self.timeout_s, self.timeout_note = compute_timeout(
            table, key, budget)
        self.hard_ceiling_mult = float(_tbl(table, "hard_ceiling_mult"))
        self.extensions = 0
        self._pending: _Sample | None = None
        self._t0: float | None = None
        self._deadline: float | None = None

    # -- logging ----------------------------------------------------------

    def log(self, msg: str) -> None:
        line = f"[lldet] {msg}"
        print(line, flush=True)
        if self.sidecar_path:
            try:
                with open(self.sidecar_path, "a") as f:
                    f.write(line + "\n")
            except OSError:
                pass

    # -- lifecycle --------------------------------------------------------

    def start(self) -> None:
        self._t0 = time.monotonic()
        self._deadline = self._t0 + self.timeout_s
        self.log(f"watching {self.label}: timeout {self.timeout_s:.1f}s "
                 f"({self.timeout_note}); hard ceiling "
                 f"{self.hard_ceiling_mult:g}x")

    def elapsed(self) -> float:
        return time.monotonic() - (self._t0 or time.monotonic())

    def _sample(self, pid: int) -> _Sample:
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = pid
        cb = None
        if self.console_path:
            try:
                cb = self.console_path.stat().st_size
            except OSError:
                cb = 0
        cpu_s, wchar = _pgroup_cpu_io(pgid)
        return _Sample(time.monotonic(), cpu_s,
                       _bytes_of(self.growth_patterns), cb, wchar)

    def adjudicate(self, pid: int) -> Verdict | None:
        """Call periodically while the child runs.  None means keep
        waiting.  A Verdict means the cell must be killed: stacks are
        already collected (before the caller kills the process)."""
        if self._deadline is None:
            self.start()
        now = time.monotonic()
        # Hard ceiling: even an output-growing cell cannot run unbounded.
        if now - self._t0 >= self.hard_ceiling_mult * self.timeout_s:
            a, b = self._pending, self._sample(pid)
            ev = [f"elapsed {now - self._t0:.0f}s >= hard ceiling "
                  f"{self.hard_ceiling_mult:g} x {self.timeout_s:.1f}s "
                  f"(after {self.extensions} extension(s))",
                  f"last sample: {b.describe()}"]
            return Verdict("HARD_CEILING",
                           "the cell exceeded the operational hard ceiling "
                           "while still growing output; not a verdict about "
                           "the guest -- raise the calibration or budget",
                           ev, collect_stacks(pid))
        if now < self._deadline:
            return None
        if self._pending is None:
            self._pending = self._sample(pid)
            self.log(f"deadline crossed at {now - self._t0:.0f}s "
                     f"({self.timeout_note}); sampling the condition")
            self.log(f"sample A: {self._pending.describe()}")
            return None
        if now - self._pending.t < self.SAMPLE_GAP_S:
            return None
        a, b = self._pending, self._sample(pid)
        gap = max(b.t - a.t, 1e-6)
        cpu_cores = (b.cpu_s - a.cpu_s) / gap
        trace_delta = b.trace_b - a.trace_b
        console_delta = (0 if a.console_b is None or b.console_b is None
                         else b.console_b - a.console_b)
        wchar_delta = b.wchar_b - a.wchar_b
        self.log(f"sample B (+{gap:.1f}s): {b.describe()} "
                 f"(cpu {cpu_cores:.2f} cores, trace {trace_delta:+d}, "
                 f"console {console_delta:+d}, written {wchar_delta:+d})")
        if trace_delta > 0 or console_delta > 0 or wchar_delta > 0:
            # SLOW: progressing, never killed at its deadline.  One
            # bounded extension per adjudication, logged.
            ext = max(0.5 * self.timeout_s, 60.0)
            self.extensions += 1
            self._deadline = time.monotonic() + ext
            self._pending = None
            self.log(f"VERDICT: SLOW -- output still growing "
                     f"(trace {trace_delta:+d}B, console "
                     f"{console_delta:+d}B, written {wchar_delta:+d}B); "
                     f"extending deadline by "
                     f"{ext:.0f}s (extension {self.extensions})")
            return None
        ev = [f"sample A at t={a.t - self._t0:.0f}s: {a.describe()}",
              f"sample B at t={b.t - self._t0:.0f}s: {b.describe()}",
              f"cpu delta {b.cpu_s - a.cpu_s:.2f}s over {gap:.1f}s "
              f"({cpu_cores:.2f} cores); zero trace/console/write growth",
              f"deadline: {self.timeout_note}; "
              f"extensions granted: {self.extensions}"]
        if cpu_cores < self.CPU_IDLE_CORES:
            return Verdict(
                "DEADLOCK", "zero CPU delta and zero output growth -- the "
                "process is frozen, not computing", ev, collect_stacks(pid))
        return Verdict(
            "LIVELOCK", f"burning {cpu_cores:.2f} host cores with zero "
            f"trace, console or write growth -- computing without "
            f"progressing", ev, collect_stacks(pid))


# --------------------------------------------------------------------------
# Runners
# --------------------------------------------------------------------------

def enabled() -> bool:
    return os.environ.get("CST_LLDET", "").lower() not in ("off", "0", "no")


def watch_for(*, isa: str, mode: str, smp: int = 1, wpdepth: int = 64,
              budget: int | None, growth_prefix: str,
              console_path=None, label: str = "") -> Watch:
    """Build a Watch for one validator cell from its configuration."""
    prefix = str(growth_prefix)
    return Watch(key=config_key(isa, mode, smp, wpdepth), budget=budget,
                 growth_patterns=default_growth_patterns(prefix),
                 console_path=console_path,
                 sidecar_path=Path(prefix + ".lldet"),
                 label=label or f"{mode} cell {Path(prefix).name}")


def run_watched(cmd: list[str], watch: Watch, *,
                stdout=None, stderr=None,
                poll_s: float = 3.0) -> tuple[int, Verdict | None]:
    """Run @cmd under @watch.  Returns (rc, None) for a natural exit or
    (LLDET_EXIT, verdict) after a watchdog kill; the verdict block is
    already logged (stdout + sidecar).  stdout/stderr default to
    inherited, exactly like subprocess.call."""
    p = subprocess.Popen(cmd, stdout=stdout, stderr=stderr,
                         start_new_session=True,
                         preexec_fn=ptraceable_preexec)
    watch.start()
    try:
        while True:
            try:
                return p.wait(timeout=poll_s), None
            except subprocess.TimeoutExpired:
                pass
            v = watch.adjudicate(p.pid)
            if v is not None:
                _kill_group(p)
                for line in v.block().splitlines():
                    watch.log(line[len("[lldet] "):]
                              if line.startswith("[lldet] ") else line)
                return LLDET_EXIT, v
    finally:
        if p.poll() is None:
            _kill_group(p)


def _kill_group(p: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except OSError:
        try:
            p.kill()
        except OSError:
            pass
    try:
        p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        pass


def call_watched(cmd: list[str], *, isa: str, mode: str, smp: int = 1,
                 wpdepth: int = 64, budget: int | None,
                 growth_prefix, label: str = "") -> int:
    """Drop-in replacement for ``subprocess.call(cmd)`` at the validator's
    qemu invocation sites: same inherited stdio, same int return -- plus
    the watchdog.  A watchdog kill returns LLDET_EXIT after logging the
    verdict loudly."""
    if not enabled():
        return subprocess.call(cmd)
    watch = watch_for(isa=isa, mode=mode, smp=smp, wpdepth=wpdepth,
                      budget=budget, growth_prefix=growth_prefix,
                      label=label)
    rc, verdict = run_watched(cmd, watch)
    return rc


# --------------------------------------------------------------------------
# Calibration (the one-command recalibrate)
# --------------------------------------------------------------------------

_CAL_ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")


def _cal_cell(build_dir: Path, out_root: Path, isa: str, mode: str,
              smp: int, wpdepth: int, seed: int, budget: int,
              hot_iters: int) -> dict | None:
    """Run ONE healthy calibration cell (generate + build in-process, then
    the validator's own ``trace`` subcommand as a subprocess with stderr
    captured) and measure it.  Returns {seed, budget, covered, wall_s} or
    None when the cell failed -- a failed cell contributes NOTHING to the
    table; it never fabricates a throughput."""
    from . import _system as SYS
    name = f"cal_{mode}_{isa}_smp{smp}_wp{wpdepth}_s{seed}"
    d = out_root / name
    d.mkdir(parents=True, exist_ok=True)
    pkg_parent = Path(__file__).resolve().parent.parent
    base = [sys.executable, "-m", "champsim_tracer_validator"]
    env = dict(os.environ,
               PYTHONPATH=str(pkg_parent),
               CST_LLDET="off")     # never watch the measurement itself
    gen = base + ["generate", "-o", str(d), "--seed", str(seed),
                  "--isa", isa, "--hot-iters", str(hot_iters)]
    if mode == "system":
        gen += ["--marker"]
    trace = base + ["trace", "-o", str(d), "--isa", isa,
                    "--build-dir", str(build_dir),
                    "--depth", str(wpdepth), "--stop", str(budget),
                    "--compress", "zstd"]
    if mode == "system":
        trace += ["--system", "--smp", str(smp)]
    log = d / "calibrate.log"
    with open(log, "w") as f:
        for step in (gen, base + ["build", "-o", str(d), "--isa", isa]):
            r = subprocess.run(step, stdout=f, stderr=subprocess.STDOUT,
                               env=env)
            if r.returncode != 0:
                print(f"  {name}: FAIL rc={r.returncode} at "
                      f"{step[3]} (see {log})")
                return None
        t0 = time.monotonic()
        r = subprocess.run(trace, stdout=f, stderr=subprocess.STDOUT,
                           env=env)
        wall = time.monotonic() - t0
    if r.returncode != 0:
        print(f"  {name}: FAIL rc={r.returncode} at trace (see {log})")
        return None
    # Covered instructions: the plugin's own close line, from the trace
    # step's captured output (user mode) or the guest console (system).
    text = log.read_text(errors="replace")
    if mode == "system":
        cons = list(d.glob("*.console.log"))
        if cons:
            text = cons[0].read_text(errors="replace")
    segs = SYS.parse_finished_segments(text)
    covered = sum(s["covered"] for s in segs)
    if covered <= 0:
        print(f"  {name}: FAIL  no 'finished segment' coverage to measure "
              f"(a cell that traced nothing calibrates nothing)")
        return None
    print(f"  {name}: covered={covered} wall={wall:.1f}s "
          f"ips={covered / wall:,.0f}")
    return {"seed": seed, "budget": budget, "covered": covered,
            "wall_s": round(wall, 2)}


def cmd_lldet_calibrate(args) -> int:
    """Measure healthy per-configuration throughput and (re)write
    ``lldet_calibration.json``.  Uses the validator's own cells: the same
    generator, the same trace subcommand, the same plugin options the real
    cells run with.  ips folds fixed cost (boot, staging) into the
    denominator, which UNDERESTIMATES true throughput -- the safe
    direction for a timeout."""
    out_root = Path(args.out_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    build_dir = Path(args.build_dir).resolve()
    isas = args.isa or list(_CAL_ISAS)
    seeds = [4242 + 1000 * i for i in range(args.seeds)]
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]
    cells: list[tuple] = []
    for isa in isas:
        for mode in modes:
            smps = [1] if mode == "user" else [int(s) for s in
                                              str(args.smp).split(",")]
            for smp in smps:
                if mode == "user" and smp != 1:
                    continue
                # One wp arm only: wpdepth > 0 is a PLUGIN INVARIANT
                # (set_wpdepth rejects 0), so "WP off" is not a
                # configuration the product can express and a nowp row
                # cannot be measured honestly.  The nowp bucket exists in
                # the key schema for completeness; a lookup for it falls
                # back to the (slower) wp sibling, the safe direction.
                for seed in seeds:
                    cells.append((isa, mode, smp, args.depth, seed))
    print(f"lldet_calibrate: {len(cells)} cells "
          f"({len(isas)} isa x {modes} x wpdepth={args.depth} x "
          f"{len(seeds)} seed(s); no nowp arm -- wpdepth>0 is a plugin "
          f"invariant)")
    configs: dict[str, dict] = {}
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(_cal_cell, build_dir, out_root, isa, mode, smp,
                          wp, seed, args.budget, args.hot_iters):
                (isa, mode, smp, wp)
                for (isa, mode, smp, wp, seed) in cells}
        for fut in cf.as_completed(futs):
            isa, mode, smp, wp = futs[fut]
            res = fut.result()
            if res is None:
                continue
            key = config_key(isa, mode, smp, wp)
            configs.setdefault(key, {"samples": []})["samples"].append(res)
    failed = False
    for key, ent in sorted(configs.items()):
        # The per-config throughput is the SLOWEST healthy sample: the
        # timeout it produces is the most generous, which is the point.
        ent["ips"] = round(min(s["covered"] / s["wall_s"]
                               for s in ent["samples"]), 1)
        print(f"  {key}: ips={ent['ips']:,.1f} "
              f"({len(ent['samples'])} sample(s))")
    if not configs:
        print("lldet_calibrate: FAIL  no cell produced a measurement")
        return 1
    expected = len({(i, m, s, w) for (i, m, s, w, _) in cells})
    if len(configs) < expected:
        print(f"lldet_calibrate: WARNING  only {len(configs)}/{expected} "
              f"configurations measured; the rest will use fallbacks")
        failed = True
    # Boot floor: system-mode fixed cost estimated from the fastest system
    # cell's wall (boot dominates it at these budgets), rounded up.
    floors = dict(_DEFAULTS["boot_floor_s"])
    sys_walls = [s["wall_s"] for k, e in configs.items()
                 for s in e["samples"] if k.split("/")[1] == "system"]
    if sys_walls:
        floors["system"] = float(round(min(sys_walls) + 30))
    table = {
        "comment": "Healthy-throughput calibration for the validator's "
                   "lldet watchdog (see _lldet.py).  Regenerate with: "
                   "python -m champsim_tracer_validator lldet_calibrate "
                   "--build-dir <build> -o <scratch> --write.  k is the "
                   "safety factor applied to expected wall time; ips per "
                   "config is the SLOWEST healthy sample (most generous "
                   "timeout).",
        "provenance": {
            "date": time.strftime("%Y-%m-%d %H:%M:%S %z"),
            "head_sha": _git_head(),
            "host": socket.gethostname(),
            "budget": args.budget,
            "seeds": seeds,
            "command": " ".join(sys.argv),
        },
        "k": 5.0,
        "boot_floor_s": floors,
        "fallback_ceiling_s": dict(_DEFAULTS["fallback_ceiling_s"]),
        "hard_ceiling_mult": _DEFAULTS["hard_ceiling_mult"],
        "configs": configs,
    }
    out = json.dumps(table, indent=2) + "\n"
    if args.write:
        _TABLE_PATH.write_text(out)
        print(f"lldet_calibrate: wrote {_TABLE_PATH}")
    else:
        (out_root / "lldet_calibration.json").write_text(out)
        print(f"lldet_calibrate: wrote {out_root / 'lldet_calibration.json'} "
              f"(pass --write to install as the checked-in table)")
    return 1 if failed and args.strict else 0


def _git_head() -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(Path(__file__).parent), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def add_parser(sub) -> None:
    c = sub.add_parser(
        "lldet_calibrate",
        help="Measure healthy per-config qemu throughput and rewrite the "
             "watchdog's calibration table (lldet_calibration.json)")
    c.add_argument("-o", "--out-dir", type=Path, required=True,
                   help="Scratch dir for the calibration cells.")
    c.add_argument("--build-dir", type=Path, required=True)
    c.add_argument("--isa", choices=_CAL_ISAS, action="append",
                   help="Repeatable; default all four.")
    c.add_argument("--modes", default="user,system",
                   help="Comma list of user,system (default both).")
    c.add_argument("--smp", default="1",
                   help="Comma list of system-mode vCPU counts (default 1).")
    # verdict24: --seed would abbreviate to --seeds here too (the recorded
    # thread_test defect, same shape).  Defining it explicitly makes the exact
    # match win and refuses instead of silently running N repetitions.
    from .__main__ import _SeedsNotSeed as _SNS
    c.add_argument("--seed", action=_SNS, default=argparse.SUPPRESS,
                   help=argparse.SUPPRESS)
    c.add_argument("--seeds", type=int, default=2,
                   help="Healthy seeds per configuration (default 2).")
    c.add_argument("--budget", type=int, default=200_000,
                   help="Instruction budget per calibration cell.")
    c.add_argument("--depth", type=int, default=64,
                   help="wpdepth for the wp-on arm (default 64).")
    c.add_argument("--hot-iters", type=int, default=2_000,
                   help="Generator loop scale, sized like the churn cell "
                        "so the workload delivers >150k user insns while "
                        "staying inside the generator's CP-walk step cap "
                        "(default 2000).  ips is computed from the covered "
                        "count the plugin reports, so an END close under "
                        "budget still measures correctly.")
    c.add_argument("--jobs", type=int, default=4,
                   help="Concurrent calibration cells (default 4).")
    c.add_argument("--write", action="store_true",
                   help="Install the result as the checked-in table.")
    c.add_argument("--strict", action="store_true",
                   help="Exit nonzero if any requested configuration "
                        "could not be measured.")
