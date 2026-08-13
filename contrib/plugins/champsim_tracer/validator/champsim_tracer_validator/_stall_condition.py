"""The workload-progress stall CONDITION, read out of architectural counts.

WHY THIS EXISTS
===============

A system-mode capture can finish, assemble a ``.cst``, and pass every content
check while carrying tens of times the kernel work a healthy capture of the
same workload carries, at identical user coverage.  The cell that gets killed
at some outer cap is the visible half of that class; the dangerous half is the
one that *clears* the cap and ships.  Nothing looked for it.

The condition, stated in architectural terms and nothing else:

    over one contiguous stretch, the guest retires a large fraction of
    everything it retires while the capture is open, and across that whole
    stretch the traced process does not retire a single user-space
    instruction.

Both terms of that sentence are retired-instruction counts the guest's own
architecture defines.  Neither is a callback count, a host-time measurement,
an output-size measurement, or a rate.  A score built from them reads the same
on an idle host and a saturated one, which is the whole point: host load can
neither manufacture the verdict nor mask it.

WHAT IS MEASURED, AND WHERE IT COMES FROM
=========================================

The plugin already computes both terms and prints them at every close, in the
``guest_realtime`` line of ``<outfile>.stats.log``::

    champsim_tracer: guest_realtime factor=0.0768 worst_sample=0.0567
        samples=593 in_segment_host_s=161.05 guest_s=12.368
        insn_per_guest_s=1.909M ticktax=0.6968 worst_user_stall=22399574
        stall_detector=live-unarmed

``worst_user_stall``
    the largest number of instructions the guest retired between two advances
    of the traced process's user-space instruction clock, inside the capture
    segment.  (``RtFactorGate`` in ``champsim_tracer.cc``: ``icount_hwm()``
    minus the retired count at the last observed advance of ``g_user_icount``.)

``insn_per_guest_s`` x ``guest_s``
    the instructions the guest retired while the segment was open.

Their quotient is the score:

.. code-block:: text

    stall_fraction = worst_user_stall / segment retired instructions

It is dimensionless and self-normalising: no per-workload calibration table,
no per-ISA constant, no baseline measurement.  A reading of 0.95 says
*ninety-five per cent of everything this machine retired while the capture was
open happened inside one stretch during which the traced process did not
execute one instruction*, and that sentence is true or false on its own terms
whatever the workload is.

WHERE THE THRESHOLD IS, AND WHY
===============================

Measured over the 1350-cell labelled corpus under
``/mnt/md0/QEMU/cst_runs/p1/agentb/`` (x86_64 system marker cells, PVH kernel,
five build arms, every cell run under SMT-sibling saturation plus 40 loadgen
workers; 25 cells killed at a 180 s cap, 1325 cells closed):

===================== ======= ======= ======= ======= ======= =======
stall_fraction          min     p50     p90     p98     p99     max
===================== ======= ======= ======= ======= ======= =======
1325 cells that closed 0.0598  0.1652  0.2148  ~0.25   0.5788  0.9487
===================== ======= ======= ======= ======= ======= =======

:data:`STALL_FRACTION_MAX` is 0.50.  The number is not a percentile fit; it is
the majority statement above, which needs no reference population to mean
something.  What the corpus supplies is the margin: 0.50 sits at 2.3x the
healthy p90 and above the healthy p98, so the ordinary population is nowhere
near it.

Fourteen of those 1325 "closed" cells read above 0.50.  They are not healthy
cells that the threshold slanders — they are escaped instances, and the
corpus says so independently of this score.  Every cell in the corpus covers
the same 854-857 user instructions (the workload is fixed and the END marker
closes the window at the same place), so the kernel work a capture carries is
directly comparable across cells:

======================= ============== ================= ==============
cell                    stall_fraction trace_arch_insns  arch per user
======================= ============== ================= ==============
median of all 1325      0.165                    144,000          168.5
n_res1/tip_L3R37        0.605                    609,223          713.4
n_res1/tip_L4R5         0.940                  4,941,470        5,786.3
n_res1/julyP_L4R26      0.949                  7,025,221        8,197.5
======================= ============== ================= ==============

``julyP_L4R26`` shipped a trace carrying 45x the median cell's architectural
instructions for the same 857 instructions of user coverage, and it exited
zero.  The ladder from the healthy mode to that cell is continuous, and it
continues without a break into the 25 cells that were killed: the label
"killed" marks where an outer 180 s cap happened to cut, not where the
condition begins.  That is exactly why the gate is on the condition.

RESOLUTION: WHY A READING OF ZERO IS NOT AUTOMATICALLY A PASS
=============================================================

``worst_user_stall`` is not exact.  ``RtFactorGate`` reads the clocks on a
sampling grid (``sample_ns``, 250 ms of host time by default, configurable
through ``CST_RT_GATE_WINDOW_MS``) and only notices that the user clock moved
at a sample boundary.  A stall is therefore measured from the last sample
before it began to the last sample before it ended, so the reading is biased
LOW by at most one sample window at each end — at most ``2/samples`` of the
segment.  The instrument cannot over-report; it can only miss.

The bias has a direction, and the direction is what makes the gate sound.
Because the instrument can only under-report, **a reading above the gate is a
fact, not an inference** — the true stall is at least that large — so the trip
is valid at any sample count.  The converse is not: a reading *below* the gate
only rules the condition out when the grid was fine enough to have caught it,
which is ``stall_fraction + 2/samples <= gate``.  Both are reported:
:attr:`RtReport.stall_fraction` is the measured lower bound and
:attr:`RtReport.stall_fraction_ub` the largest value consistent with it.

A cell whose bound cannot clear the gate is neither passed nor failed on the
condition — it is named ``NOT CERTIFIED``, with its sample count, because
"the instrument could not look" and "the guest was healthy" are different
findings and this project has been bitten by conflating them.  What is failed
outright is a cell with no report at all, or one whose clock the plugin could
not read: those have no subject.

The resolution floor is set by the plugin, not by the cadence.
``RtFactorGate::tick`` only considers sampling on one TB in 1024 (a hardcoded
divider) and only records a sample once ``sample_ns`` of host time has also
passed, so a short segment cannot be sampled finely at any cadence.  Measured
on the validator's own x86_64 system cell (segment ~0.42 host-seconds, ~24 k
retired instructions): 1 sample at the stock 250 ms, 4 at 20 ms — the divider,
not the clock, is what binds.  :data:`SAMPLE_WINDOW_MS` takes the free part of
that (1 sample to 4, a structural zero to a real reading); certifying the gate
on a segment that small needs the plugin to sample on an ARCHITECTURAL grid
(every N retired instructions) instead of a host-time one, which would also
make the instrument's resolution load-invariant rather than a function of how
long the host took.  That is an open item against the plugin, recorded here
because a gate whose blind spot is undocumented is worse than no gate.

The corpus's real marker cells carry 15 (p50) to 593 samples and certify
comfortably; it is only the synthetic cell that cannot.

WHAT THIS SCORE DOES *NOT* SEPARATE
===================================

``worst_user_stall`` counts advances of the TRACED PROCESS's user clock, not
of user-space retirement machine-wide.  A workload whose traced process is
legitimately off-CPU for most of the window — the validator's own churn cell,
where a stream of short-lived processes runs alongside the marked one — can
therefore read a high stall_fraction while the machine is perfectly healthy,
because *other* user code is running the whole time.  The plugin's own
``CST_RT_GATE`` arm was measured false-positiving on exactly that cell, which
is why it is not armed by default.

Separating the two needs a count the plugin does not currently keep: user-mode
instructions retired MACHINE-WIDE, independent of which address space retired
them.  With that count, "no user code ran anywhere" is directly expressible and
the churn shape stops being ambiguous.  Until then this gate is applied only
where the traced process owns the guest's user time for the whole window
(:data:`OFF_CPU_WORKLOADS` names the exclusions and why), and the exclusion is
stated in the cell's own output rather than left implicit.

Author: Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------
# Thresholds
# --------------------------------------------------------------------------

#: A capture more than half of whose retired instructions fell inside a single
#: stretch with no user progress by the traced process.  See the module
#: docstring for the derivation and for the measured healthy distribution.
STALL_FRACTION_MAX = 0.50

#: Reported, never failed on: the upper edge of the healthy population
#: measured over the corpus (p98 ~ 0.25).  A cell between this and
#: :data:`STALL_FRACTION_MAX` is outside the ordinary band and is named in the
#: cell's output so a drift toward the gate is visible before it trips.
STALL_FRACTION_NOTE = 0.25

#: Operational override, for positive controls and for re-measuring the band.
#: Reading it is logged by :func:`threshold` so a lowered gate can never be
#: mistaken for the shipped one.
_ENV_MAX = "CST_STALL_FRACTION_MAX"

#: Sampling cadence (ms of host time) the validator asks the plugin's
#: diagnostic sampler for, via ``CST_RT_GATE_WINDOW_MS``.  The stock 250 ms
#: yields ONE sample on the validator's ~0.42 host-second system segment, at
#: which resolution the score cannot certify anything (see "RESOLUTION"
#: above).  20 ms yields ~20.  It moves only how often the plugin reads a
#: clock for its own report; it is not a tracing parameter and does not reach
#: the wire.  An operator who sets the variable keeps their value.
SAMPLE_WINDOW_MS = 20

#: Sampling windows the reading must span before a clean score is believed.
#: Derived, not chosen: clearing :data:`STALL_FRACTION_MAX` from a zero
#: reading needs ``2 / samples <= 0.50``.
MIN_SAMPLES = 5


def sampler_env(env: dict[str, str] | None = None) -> dict[str, str]:
    """@env (default a copy of the process environment) with the diagnostic
    sampler's cadence set, unless the caller already set it."""
    e = dict(os.environ if env is None else env)
    e.setdefault("CST_RT_GATE_WINDOW_MS", str(SAMPLE_WINDOW_MS))
    return e

#: Workloads whose traced process is legitimately off-CPU for much of the
#: window, so a high stall_fraction does not distinguish health from a wedge.
#: See "WHAT THIS SCORE DOES NOT SEPARATE" above.  Keyed by the substring the
#: validator puts in a cell's label.
OFF_CPU_WORKLOADS: dict[str, str] = {
    "churn": "the churn workload runs a stream of short-lived processes "
             "alongside the marked one, so the traced process is legitimately "
             "off-CPU while the guest retires instructions in other address "
             "spaces; separating that from a wedge needs a machine-wide "
             "user-retirement count the plugin does not keep",
}


def threshold() -> tuple[float, str]:
    """(gate, provenance).  The provenance string is printed with every
    verdict so an overridden gate names itself."""
    raw = os.environ.get(_ENV_MAX)
    if raw:
        try:
            return float(raw), f"{_ENV_MAX}={raw} (OVERRIDDEN, not the shipped gate)"
        except ValueError:
            pass
    return STALL_FRACTION_MAX, "built-in"


# --------------------------------------------------------------------------
# Parsing the plugin's own report
# --------------------------------------------------------------------------

_RT_LINE = re.compile(r"^champsim_tracer: guest_realtime (.*)$", re.M)
_KV = re.compile(r"([a-z_]+)=([^\s]+)")
_ICOUNT_LINE = re.compile(
    r"^champsim_tracer: host_icount=(\d+) traced_icount=(\d+)"
    r"(?:\s+rep_fanout=(\d+))?\s+trace_arch_insns=(\d+)", re.M)


def _mega(s: str) -> float:
    """The report prints insn_per_guest_s with an 'M' suffix."""
    return float(s[:-1]) * 1e6 if s.endswith("M") else float(s)


@dataclass
class RtReport:
    """The plugin's architectural accounting for one run."""
    measurable: bool             # False when the line reads factor=n/a
    why_not: str = ""
    worst_user_stall: int = 0
    guest_s: float = 0.0
    insn_per_guest_s: float = 0.0
    ticktax: float = 0.0
    samples: int = 0
    stall_detector: str = ""
    traced_icount: int | None = None
    trace_arch_insns: int | None = None

    @property
    def segment_insns(self) -> float:
        """Instructions the guest retired while the capture was open."""
        return self.insn_per_guest_s * self.guest_s

    @property
    def stall_fraction(self) -> float | None:
        seg = self.segment_insns
        if seg <= 0:
            return None
        return self.worst_user_stall / seg

    @property
    def resolution(self) -> float | None:
        """How much of the segment the sampling grid can hide: the reading is
        biased low by at most one sample window at each end."""
        if self.samples <= 0:
            return None
        return 2.0 / self.samples

    @property
    def stall_fraction_ub(self) -> float | None:
        """The largest stall fraction consistent with this reading."""
        sf, res = self.stall_fraction, self.resolution
        if sf is None or res is None:
            return None
        return min(1.0, sf + res)

    @property
    def arch_per_user(self) -> float | None:
        """Architectural instructions the capture carries per instruction of
        user coverage.  Not gated on here (its healthy value is a property of
        the workload, so it needs a per-workload baseline); reported because
        it is what a contaminated trace is contaminated WITH."""
        if not self.traced_icount or self.trace_arch_insns is None:
            return None
        return self.trace_arch_insns / self.traced_icount


def parse_rt_report(stats_text: str) -> RtReport | None:
    """The plugin's ``guest_realtime`` accounting, or None when the line is
    absent entirely.  ``None`` and ``measurable=False`` are different states
    and callers must keep them apart: the first is "this run produced no
    report", the second is "the report says the clock could not be read"."""
    m = _RT_LINE.search(stats_text)
    if not m:
        return None
    body = m.group(1)
    kv = dict(_KV.findall(body))
    ic = _ICOUNT_LINE.search(stats_text)
    traced = int(ic.group(2)) if ic else None
    arch = int(ic.group(4)) if ic else None
    if "factor" not in kv or kv["factor"] == "n/a":
        return RtReport(measurable=False,
                        why_not=body.strip(),
                        traced_icount=traced, trace_arch_insns=arch)
    try:
        return RtReport(
            measurable=True,
            worst_user_stall=int(kv["worst_user_stall"]),
            guest_s=float(kv["guest_s"]),
            insn_per_guest_s=_mega(kv["insn_per_guest_s"]),
            ticktax=float(kv.get("ticktax", 0.0)),
            samples=int(kv.get("samples", 0)),
            stall_detector=kv.get("stall_detector", ""),
            traced_icount=traced, trace_arch_insns=arch)
    except (KeyError, ValueError) as e:
        return RtReport(measurable=False,
                        why_not=f"unparsable guest_realtime line ({e}): {body}",
                        traced_icount=traced, trace_arch_insns=arch)


# --------------------------------------------------------------------------
# The check
# --------------------------------------------------------------------------

@dataclass
class Verdict:
    ok: bool
    lines: list[str]
    #: True when the reading cleared the gate but the sampling grid was too
    #: coarse to have ruled the condition out.  Not a pass on the condition —
    #: callers that aggregate cells must count these, never fold them into a
    #: clean total.
    not_certified: bool = False


def describe(r: RtReport) -> str:
    sf = r.stall_fraction
    ub = r.stall_fraction_ub
    apu = r.arch_per_user
    return ("stall_fraction=%s (<=%s at samples=%d) worst_user_stall=%d "
            "segment_insns=%.0f ticktax=%.3f arch/user=%s detector=%s"
            % ("%.3f" % sf if sf is not None else "n/a",
               "%.3f" % ub if ub is not None else "n/a",
               r.samples, r.worst_user_stall, r.segment_insns, r.ticktax,
               "%.1f" % apu if apu is not None else "n/a",
               r.stall_detector or "?"))


def assess(stats_path: Path, label: str = "",
           workload: str = "") -> Verdict:
    """Compute and judge the stall condition for one system cell.

    Fails when the condition is present, and — equally — when it cannot be
    measured on a cell that should have produced the measurement.  A gate
    whose subject is missing must not report a pass; that shape is how this
    class stayed invisible.
    """
    lines: list[str] = []
    excuse = next((why for key, why in OFF_CPU_WORKLOADS.items()
                   if key in (workload or label)), None)

    try:
        text = stats_path.read_text(errors="replace")
    except OSError as e:
        lines.append(f"stall[{label}]: FAIL  cannot read {stats_path.name} "
                     f"({e}) — the stall condition has no subject and a "
                     f"check that cannot find its subject fails")
        return Verdict(False, lines)

    r = parse_rt_report(text)
    if r is None:
        lines.append(f"stall[{label}]: FAIL  {stats_path.name} carries no "
                     f"'champsim_tracer: guest_realtime' line — the plugin's "
                     f"architectural stall accounting is missing, so the "
                     f"condition could not be measured")
        return Verdict(False, lines)
    if not r.measurable:
        lines.append(f"stall[{label}]: FAIL  the plugin could not measure the "
                     f"guest clock ({r.why_not}) — a system cell that closed "
                     f"a window must produce a readable segment, and without "
                     f"one the stall condition is unmeasured, not absent")
        return Verdict(False, lines)

    sf = r.stall_fraction
    if sf is None:
        lines.append(f"stall[{label}]: FAIL  the segment retired 0 "
                     f"instructions by the plugin's own accounting "
                     f"({describe(r)}) — the score has no denominator")
        return Verdict(False, lines)

    gate, prov = threshold()
    lines.append(f"stall[{label}]: {describe(r)}")

    if excuse is not None:
        lines.append(f"stall[{label}]: NOT GATED — {excuse}")
        return Verdict(True, lines)

    # THE TRIP IS SOUND AT ANY RESOLUTION.  The sampling grid can only make
    # worst_user_stall too small, never too large, so a reading over the gate
    # is a measurement of the condition and is checked before anything about
    # sample counts is considered.
    if sf > gate:
        lines.append(
            f"stall[{label}]: FAIL  stall_fraction {sf:.3f} exceeds "
            f"{gate:.3f} [{prov}]: {r.worst_user_stall} of the "
            f"{r.segment_insns:.0f} instructions the guest retired while the "
            f"capture was open fell inside ONE stretch in which the traced "
            f"process did not retire a single user-space instruction.  The "
            f"capture is not a sample of the workload; both terms are "
            f"architectural counts, so this reading does not depend on host "
            f"load.")
        return Verdict(False, lines)

    if sf > STALL_FRACTION_NOTE:
        lines.append(f"stall[{label}]: note  stall_fraction {sf:.3f} is above "
                     f"the measured healthy band ({STALL_FRACTION_NOTE:.2f}) "
                     f"but under the gate ({gate:.3f}) [{prov}]")

    # Under the gate — but only "ruled out" if the grid could have caught it.
    ub = r.stall_fraction_ub
    if ub is None or ub > gate:
        need = int(2.0 / gate) + 1 if gate > 0 else MIN_SAMPLES
        lines.append(
            f"stall[{label}]: NOT CERTIFIED  the reading is under the gate "
            f"but {r.samples} sampling window(s) leave up to "
            f"{(r.resolution if r.resolution is not None else 1.0):.3f} of "
            f"the segment unobserved, so the true stall fraction is bounded "
            f"only by {ub if ub is not None else 1.0:.3f} against "
            f"{gate:.3f} [{prov}].  This cell has NOT ruled the condition "
            f"out; {need}+ windows would (see _stall_condition.py: the "
            f"plugin's 1-in-1024-TB sampling divider is what binds on a "
            f"segment this short, not the cadence).")
        return Verdict(True, lines, not_certified=True)
    return Verdict(True, lines)


# --------------------------------------------------------------------------
# The machine-wide form, and the corpus that calibrated both
# --------------------------------------------------------------------------
#
# The score above reads the TRACED PROCESS's user clock, because that is what
# the plugin keeps.  A second form of the same sentence reads user retirement
# MACHINE-WIDE, and it is the stronger statement: user code stopped running
# anywhere, not merely in the address space under trace.
#
# It cannot be computed from the plugin's report — the plugin has no
# machine-wide user count — but it CAN be computed from a per-vCPU instruction
# sampler run alongside the tracer, and a 1350-cell corpus of exactly that
# already exists on disk.  ``stall_scan`` replays it.  That corpus is where
# both thresholds come from and it is the only labelled data either has, so it
# is kept re-runnable rather than quoted from a report nobody can re-execute.
#
# Sampler columns (all architectural; see the module docstring's standard):
#   insns_total    retired, machine-wide
#   insns_user     retired at CPL>0, machine-wide
#   insns_async    retired inside an asynchronous interrupt window
#   async_windows  asynchronous interrupt deliveries
#   guest_ns       the guest's own virtual clock
#
# THE INTERRUPT-LIVENESS CONDITION.  Every cell in the corpus, healthy and
# wedged alike, contains one enormous span in which insns_user does not move:
# the pre-workload boot, ~394 M kernel instructions over ~14 guest-seconds.
# In all 1350 cells that span delivers EXACTLY ZERO interrupts.  Requiring
# the span to have taken interrupts removes it with no special case and no
# time term, and what remains is the span this class lives in.

#: Machine-wide score gate: the fraction of everything the guest retired that
#: fell inside a single interrupt-taking stretch with no user retirement
#: anywhere.  Measured over the corpus: 1325 cells that closed have
#: min 0.00079, p50 0.00093, p90 0.00102; the 25 cells killed at the cap have
#: min 0.20157.  0.02 is ~20x the healthy p90 and ~10x below the least
#: extreme wedge, and flags 13 of the 1325 (0.98%) — every one of them on the
#: contamination ladder, none of them an ordinary cell.
SAMPLER_STALL_FRACTION_MAX = 0.02

_SAMPLER_COLS = ("guest_ns", "insns_total", "insns_async", "insns_user",
                 "async_windows")


@dataclass
class SamplerScore:
    samples: int
    insns_total: int
    insns_user: int
    span_kernel_insns: int       # kernel insns in the most-interrupted span
    span_windows: int            # interrupts delivered across it
    span_guest_s: float

    @property
    def fraction(self) -> float | None:
        if self.insns_total <= 0:
            return None
        return self.span_kernel_insns / self.insns_total


def score_sampler_tsv(path: Path) -> SamplerScore | None:
    """Instrument A over one sampler trajectory, or None when the file
    carries no usable header/rows (which the caller must treat as a failure
    to measure, never as a clean reading)."""
    idx: tuple[int, ...] | None = None
    rows: list[tuple[int, ...]] = []
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("#"):
                    p = [c.strip() for c in line.lstrip("#").split("\t")]
                    if "host_ns" in p:
                        try:
                            idx = tuple(p.index(c) for c in _SAMPLER_COLS)
                        except ValueError:
                            return None
                    continue
                if idx is None or not line.strip():
                    continue
                cells = line.rstrip("\n").split("\t")
                try:
                    rows.append((int(cells[idx[0]]), int(cells[idx[1]]),
                                 int(cells[idx[2]]), int(cells[idx[3]]),
                                 int(cells[idx[4]])))
                except (ValueError, IndexError):
                    continue
    except OSError:
        return None
    if idx is None or len(rows) < 2:
        return None

    # g, t, a, u, w  (guest_ns, total, async, user, windows)
    best = (0, 0, 0.0)     # (windows, kernel insns, guest seconds)
    i, n = 0, len(rows)
    while i < n:
        j = i
        while j + 1 < n and rows[j + 1][3] == rows[i][3]:
            j += 1
        if j > i:
            w = rows[j][4] - rows[i][4]
            if w > best[0]:
                k = (rows[j][1] - rows[i][1]) - (rows[j][3] - rows[i][3])
                best = (w, k, (rows[j][0] - rows[i][0]) / 1e9)
        i = j + 1
    return SamplerScore(samples=n,
                        insns_total=rows[-1][1] - rows[0][1],
                        insns_user=rows[-1][3] - rows[0][3],
                        span_kernel_insns=best[1],
                        span_windows=best[0],
                        span_guest_s=best[2])


def _verdict_of(status_path: Path) -> str | None:
    try:
        head = status_path.read_text(errors="replace").splitlines()[0]
    except (OSError, IndexError):
        return None
    for tok in head.split():
        if tok.startswith("verdict="):
            return tok.split("=", 1)[1]
    return None


def cmd_stall_scan(args) -> int:
    """Replay the labelled corpus and re-prove both instruments.

    This is the positive control for the whole tripwire: it shows the score
    firing on every cell known to have wedged, and clearing the population
    that did not.  It exits nonzero when that no longer holds, so a change
    that quietly blinds the detector fails here rather than in a report.
    """
    import glob

    cells = []
    for wave in args.wave:
        wave = Path(wave)
        for smp in sorted(glob.glob(str(wave / "*.sample.tsv"))):
            smp = Path(smp)
            label = smp.name[:-len(".sample.tsv")]
            cells.append((wave.name, label, smp,
                          wave / f"{label}.status.txt",
                          wave / f"{label}.stats.log"))
    if not cells:
        print(f"stall_scan: FAIL  no *.sample.tsv under {list(args.wave)} — "
              f"a scan that cannot find its corpus fails")
        return 2

    pos_hit = pos_tot = neg_hit = neg_tot = 0
    unreadable = 0
    escaped: list[tuple[str, str, float, float | None, float | None]] = []
    negs: list[float] = []
    # Instrument B, exercised exactly as the validator exercises it: the
    # shipped assess() over each cell's real stats.log.  This is the positive
    # control for the gate that actually runs in the suite -- the corpus's
    # sampler leg proves the CONDITION separates, this proves the SHIPPED
    # CODE fires on it.
    b_fail = b_notcert = b_seen = 0
    for wname, label, smp, stat, stats_log in cells:
        if stats_log.is_file():
            b_seen += 1
            v = assess(stats_log, label=f"{wname}/{label}")
            b_fail += int(not v.ok)
            b_notcert += int(v.not_certified)
    for wname, label, smp, stat, stats_log in cells:
        v = _verdict_of(stat)
        s = score_sampler_tsv(smp)
        if v is None or s is None or s.fraction is None:
            print(f"stall_scan: UNREADABLE {wname}/{label} "
                  f"(verdict={v} score={'none' if s is None else 'no-total'})")
            unreadable += 1
            continue
        f = s.fraction
        b = None
        apu = None
        if stats_log.is_file():
            r = parse_rt_report(stats_log.read_text(errors="replace"))
            if r is not None and r.measurable:
                b, apu = r.stall_fraction, r.arch_per_user
        trips = f > args.threshold
        if v == "CAP":
            pos_tot += 1
            pos_hit += int(trips)
        else:
            neg_tot += 1
            negs.append(f)
            if trips:
                neg_hit += 1
                escaped.append((wname, label, f, b, apu))

    negs.sort()
    q = (lambda p: negs[int(p * (len(negs) - 1))]) if negs else (lambda p: 0.0)
    print(f"stall_scan: {len(cells)} cells, {unreadable} unreadable, "
          f"threshold {args.threshold}")
    print(f"stall_scan: cells killed at the cap  : {pos_hit}/{pos_tot} trip")
    print(f"stall_scan: cells that closed        : {neg_hit}/{neg_tot} trip "
          f"({100.0 * neg_hit / neg_tot if neg_tot else 0:.2f}%)")
    if negs:
        print(f"stall_scan: closed-cell score        : min={negs[0]:.5f} "
              f"p50={q(.5):.5f} p90={q(.9):.5f} p99={q(.99):.5f} "
              f"max={negs[-1]:.5f}")
    gate, prov = threshold()
    print(f"stall_scan: shipped validator gate over the same cells' "
          f"stats.log: {b_fail}/{b_seen} FAIL, {b_notcert} not certified "
          f"(gate {gate:.3f} [{prov}])")
    if escaped:
        print("stall_scan: cells that CLOSED and still carry the condition "
              "(the escaped set):")
        for wname, label, f, b, apu in sorted(escaped, key=lambda t: -t[2]):
            print("  %-8s %-18s machine-wide=%.4f traced-process=%s "
                  "arch/user=%s"
                  % (wname, label, f,
                     "%.3f" % b if b is not None else "n/a",
                     "%.1f" % apu if apu is not None else "n/a"))

    rc = 0
    if unreadable:
        print(f"stall_scan: FAIL  {unreadable} cells could not be scored")
        rc = 1
    if pos_tot and pos_hit != pos_tot:
        print(f"stall_scan: FAIL  the instrument missed "
              f"{pos_tot - pos_hit} of {pos_tot} known-wedged cells")
        rc = 1
    if pos_tot == 0:
        print("stall_scan: FAIL  the corpus contains no known-wedged cell, "
              "so this run proves nothing about the instrument's ability to "
              "fire")
        rc = 1
    if b_seen and b_fail == 0:
        print(f"stall_scan: FAIL  the shipped gate fired on 0 of {b_seen} "
              f"cells that carry a stats.log — an instrument that never "
              f"fires on a corpus containing the condition is unproven")
        rc = 1
    if neg_tot and neg_hit / neg_tot > args.max_flag_rate:
        print(f"stall_scan: FAIL  flag rate {100.0 * neg_hit / neg_tot:.2f}% "
              f"on cells that closed exceeds "
              f"{100.0 * args.max_flag_rate:.2f}%")
        rc = 1
    print("stall_scan: %s" % ("PASS" if rc == 0 else "FAIL"))
    return rc


def add_parser(sub) -> None:
    c = sub.add_parser(
        "stall_scan",
        help="Replay a labelled corpus of sampler trajectories and re-prove "
             "the workload-progress stall detector (its positive control)")
    c.add_argument("wave", nargs="+",
                   help="Wave directories holding <cell>.sample.tsv, "
                        "<cell>.status.txt and (optionally) "
                        "<cell>.stats.log.")
    c.add_argument("--threshold", type=float,
                   default=SAMPLER_STALL_FRACTION_MAX,
                   help="Machine-wide score gate (default %(default)s).")
    c.add_argument("--max-flag-rate", type=float, default=0.05,
                   help="Fail if more than this fraction of the cells that "
                        "closed trip the gate (default %(default)s).")
