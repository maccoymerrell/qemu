"""System-mode trace runner.

Boots ``qemu-system-<isa>`` with a generated workload staged into an
initramfs, so the same validator flow that traces a program under
``qemu-user`` can trace it under full-system QEMU.  The workload carries the
trace marker (``generate --marker``), which executes in its own address
space at ``_start``; the plugin pins the trace window to that address space
(see champsim_marker.h / the marker docs in champsim_tracer.cc).

Only the *runner* differs from user mode — generation, decode, and analysis
are shared.

The system-mode assets (a kernel + a base initramfs root) are local and not
in the repo; default to the maintainer's harness under ``--rootfs``-able
paths and override on the command line.

Environment passthrough (read by :func:`system_qemu_cmd`):

``CST_QEMU_EXTRA_ARGS``
    Space-separated extra arguments appended verbatim to the end of the
    qemu-system command line — e.g.
    ``CST_QEMU_EXTRA_ARGS="-cpu qemu64,vendor=GenuineIntel"`` flips the
    staged x86 guest's CPUID vendor so the guest kernel enables page-table
    isolation (a later ``-cpu`` wins over an earlier one, so this also
    overrides a boot-table CPU).
``CST_PLUGIN_EXTRA_ARGS``
    Extra plugin arguments, comma-prefixed onto the plugin option string —
    e.g. ``CST_PLUGIN_EXTRA_ARGS=kexc=1`` rides the kernel-excursion
    ownership model along a validator run.

SPDX-License-Identifier: GPL-2.0-or-later
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path

# Default local harness (override with --kernel / --rootfs).  The base root
# is a busybox initramfs tree; we add /workload + /init and repack per run.
SYSTEST_ROOT = Path("/mnt/md0/QEMU/systest")
DEFAULT_SYSTEST = SYSTEST_ROOT / "x86"          # back-compat (x86 layout)

ISA_QEMU_SYSTEM = {
    "x86_64":  "qemu-system-x86_64",
    "aarch64": "qemu-system-aarch64",
    "riscv64": "qemu-system-riscv64",
    "mipsel":  "qemu-system-mipsel",
}

# Per-ISA boot shape: asset dir, kernel image name, machine/cpu flags, and
# the console the kernel must be told to use.  virt machines for aarch64
# and riscv64 (riscv's -kernel boots through the bundled OpenSBI); malta
# for mipsel (little-endian kernel).
_ISA_BOOT = {
    # nopti: KPTI-off is the canonical system-mode configuration
    # (multiasid_plan §0).  With page-table isolation disabled the kernel
    # shares each process's ASID, so the wire's (asid,vaddr) key covers kernel
    # and user under one process root and a consumer models OS isolation
    # externally from the per-insn system bit.  Booting the system-validation
    # guest with it makes the tested config the canonical one.
    "x86_64":  {"dir": "x86",     "kernel": "vmlinuz",
                "machine": [],
                "console": "ttyS0",
                "extra_append": "nopti"},
    "aarch64": {"dir": "aarch64", "kernel": "Image",
                "machine": ["-M", "virt", "-cpu", "max,pauth-impdef=on"],
                "console": "ttyAMA0"},
    "riscv64": {"dir": "riscv64", "kernel": "Image",
                # -cpu max exposes the V (vector) extension so --coverage's
                # vector ops are legal; the default virt CPU lacks V, making
                # vsetvli a true illegal-instruction (SIGILL) the guest kernel
                # cannot lazily enable.  The kernel still enables VS on first
                # use.
                "machine": ["-M", "virt", "-cpu", "max"],
                "console": "ttyS0"},
    # P5600 is the only MIPS model in QEMU that sets Config3.PW
    # (target/mips/cpu-defs.c.inc), so it is the only one on which the guest
    # kernel enables the hardware page-table walker and therefore the only
    # one on which CP0_PWBase -- the page-table root Linux writes from
    # htw_set_pwbase() at every switch_mm -- is a live register.  The
    # ownership model keys on that root, so the mipsel system guest boots on
    # P5600; "Hardware Page Table Walker enabled" on the console is the
    # condition that says so, and it does not appear on the malta default
    # (24Kc).
    #
    # ieee754=relaxed: P5600 resets FCR31 with ABS2008|NAN2008 set and its
    # rw_bitmask (0xFF83FFFF) makes both bits read-only, so Linux probes the
    # FPU as 2008-NaN-only and, under the default ieee754=strict, refuses
    # every legacy-NaN ELF with -ENOEXEC -- including the base rootfs's
    # busybox, which panics the guest at "No working init found".  The
    # validator's own guest binaries are built -mnan=2008 (ISA_CFLAGS) and
    # need no override; the imported busybox cannot be, because the
    # mipsel-linux-gnu cross toolchain ships no 2008-NaN libc multilib and
    # ld refuses to mix the two ABIs.  ieee754=relaxed is the upstream
    # kernel parameter for exactly this ("accept any binaries regardless of
    # whether supported by the FPU", arch/mips/kernel/fpu-probe.c); it
    # changes admission only, never code generation, and on this CPU it
    # cannot change FP semantics either, because FCSR.NAN2008 is read-only 1
    # no matter which ELF is admitted.  Drop it once the base rootfs is
    # rebuilt against a 2008-NaN libc.
    "mipsel":  {"dir": "mipsel",  "kernel": "vmlinux",
                # -cpu P5600 is REQUIRED, not a tuning choice: it is the only
                # QEMU MIPS model implementing Config3.PW / CP0 PWBase, the
                # hardware page-table walker's base register, which is what a
                # system capture names its process by.  malta defaults to
                # 24Kf, which supplies no page-table root, and the plugin
                # REFUSES TO INSTALL on it rather than name an address space
                # by an 8-bit EntryHi.ASID a Linux guest reassigns to a
                # different live process on rollover.  P5600 also sets
                # Config3.ULRI (thread ids keep working) and Config3.CMGCR
                # (the malta CPS SMP path).
                "machine": ["-M", "malta", "-cpu", "P5600"],
                "console": "ttyS0",
                # BLOCKER 3 (d9aa0e05ef): the shipped base rootfs is a
                # legacy-NaN o32 userland and P5600 pins FCR31.NAN2008=1,
                # so arch_check_elf() answers -ENOEXEC for every one of its
                # binaries and the guest panics "No working init found".
                # ieee754=relaxed changes ADMISSION only, never code
                # generation, and on this CPU it cannot change FP semantics
                # either.  Drop it once the base rootfs is rebuilt 2008-NaN.
                "extra_append": "ieee754=relaxed"},
}

# Per-ISA CPU override used only when more than one vCPU is asked for.
#
# mipsel: P5600 cannot be brought up multi-vCPU under QEMU.  malta routes
# -smp >1 on a Config3.CMGCR CPU through the CPS block, and QEMU's CPS
# models N vCPUs as N VPs inside ONE core (hw/misc/mips_cmgcr.c returns 0
# for GCR_CONFIG, so PCORES == 0), while Linux only counts more than one VP
# per core when the CPU has the MT ASE or the Release 6 VP bit
# (mips_cps_numvps(), arch/mips/include/asm/mips-cps.h).  P5600 is MIPS32r5
# with neither, so the topology comes out {1} total 1 and the guest boots
# single-CPU.  34Kf has the MT ASE and no CMGCR, so it takes malta's
# non-CPS path and Linux's MT SMVP bring-up, which does online every vCPU.
# The cost is that 34Kf has no Config3.PW: a multi-vCPU mipsel guest and a
# guest with CP0_PWBase are, today, mutually exclusive.  ONLINE_CPUS_RE
# below turns any silent fallback into a failure rather than a quiet
# single-CPU run.
_ISA_SMP_CPU = {
    "mipsel": "34Kf",
}

# The kernel's own count of the vCPUs it actually onlined.  A cell that asks
# for N vCPUs and silently gets one is not an SMP cell; every check that
# depends on concurrency then passes for the wrong reason.
_ONLINE_CPUS_RE = re.compile(r"smp: Brought up \d+ nodes?, (\d+) CPUs?")


def parse_online_cpus(console_text: str) -> int | None:
    """How many vCPUs the guest kernel reported onlining, or None when the
    line is absent (a kernel built without SMP never prints it)."""
    m = _ONLINE_CPUS_RE.search(console_text)
    return int(m.group(1)) if m else None


def assess_online_cpus(console_text: str, smp: int,
                       label: str = "") -> list[str]:
    """One message per way the guest failed to online the vCPUs the cell
    asked for.  A check that cannot find its subject fails: an smp>1 cell
    whose console has no "Brought up" line at all is reported, not passed."""
    if not smp or int(smp) <= 1:
        return []
    got = parse_online_cpus(console_text)
    if got is None:
        return [f"{label}: asked for {int(smp)} vCPUs but the guest never "
                f"printed an 'smp: Brought up ...' line -- the kernel is "
                f"not an SMP kernel, or it never finished bringing CPUs up"]
    if got != int(smp):
        return [f"{label}: asked for {int(smp)} vCPUs but the guest onlined "
                f"{got} -- this cell did not test concurrency"]
    return []


# The plugin's per-segment close line (stderr).  In marker mode the
# coverage and budget run on the user-instruction clock and carry the
# "user_" prefix.  SIX close flags exist, and every one of them has to be
# admitted here:
#
#   OK        covered >= budget
#   END       the end marker executed -- the workload finished under budget
#   UNDER     closed early for any other reason (always a failure)
#   IDLE      a dead latch: the window was open on a process that stopped
#   CEILING   an architectural stall ceiling terminated an unbounded run
#   SHUTDOWN  the machine went down with the window still open
#
# The last three are FORCED, TRUNCATING closes -- exactly the ones a
# progress gate exists to judge -- and until this pattern named them, a
# segment that closed for any of them matched nothing, parse_finished_segments
# returned an empty list, and the caller reported "the plugin never closed a
# window".  That is the same failure 7c2144b89c fixed one layer up: a gate
# that cannot find its subject.  It fails loudly rather than passing
# vacuously, but it fails with the wrong diagnosis and it takes the whole
# guest-clock progress gate down with it on precisely the cells that were
# terminated for lack of progress.
#
# Written as a fixed prefix plus a KEY=VALUE scan of the tail, because the
# tail grows: `wire_user_insns` / `clock_minus_wire` were appended to this
# line by 5e5d963255 and the previous fully-positional pattern stopped
# matching, which silently turned the coverage gate -- and with it the whole
# guest-clock progress gate, whose UNDER leg is the stall detector -- into a
# check that could not find its subject on ANY ISA.  Anchoring only on the
# fields this module reads means a future field cannot do that again.
_FINISHED_SEG_RE = re.compile(
    r"champsim_tracer: finished segment \[icount (\d+) \.\. (\d+)\]"
    r"((?:\s+\w+=-?\d+)+)\s+(OK|END|UNDER|IDLE|CEILING|SHUTDOWN)")

# The flags that mean the capture was cut short by something other than its
# own budget or the workload's own end.  Each is a failure, and each names
# itself rather than being folded into UNDER: which one fired says whether
# the process stopped running (IDLE), the guest stopped making progress at
# all (CEILING), or the machine went down under an open window (SHUTDOWN).
TRUNCATING_CLOSE_FLAGS = {
    "UNDER":    "the guest stopped making user-space progress",
    "IDLE":     "the pinned process went idle and the dead-latch close "
                "fired -- the window was open on a process that stopped",
    "CEILING":  "an architectural stall ceiling terminated the run -- the "
                "guest retired instructions without the traced process "
                "executing one user-space instruction",
    "SHUTDOWN": "the machine shut down with the window still open",
}
# clock_minus_wire is signed: a residual can go either way, and a pattern
# that only admits digits would truncate the field scan before the flag.
_SEG_FIELD_RE = re.compile(r"(\w+)=(-?\d+)")


def parse_finished_segments(console_text: str) -> list[dict]:
    """Parse every per-segment coverage line the plugin printed into the
    captured console log.  Returns one dict per closed segment with
    covered / budget / flag / user_clock keys.

    A line that matches the shape but is missing a field this function
    promises raises: a segment whose coverage cannot be read is not a
    segment that covered nothing."""
    out = []
    for m in _FINISHED_SEG_RE.finditer(console_text):
        fields = {k: int(v) for k, v in _SEG_FIELD_RE.findall(m.group(3))}
        user_clock = "user_covered" in fields
        try:
            rec = {
                "lo": int(m.group(1)),
                "hi": int(m.group(2)),
                "actual_icount": fields["actual_icount"],
                "user_clock": user_clock,
                "covered": fields["user_covered" if user_clock else "covered"],
                "budget": fields["user_budget" if user_clock else "budget"],
                "rep_fanout": fields["rep_fanout"],
                "trace_arch_insns": fields["trace_arch_insns"],
                "flag": m.group(4),
            }
        except KeyError as e:
            raise RuntimeError(
                f"'finished segment' line is missing {e.args[0]}= -- the "
                f"plugin's close line changed shape and this parser has to "
                f"be updated, not silently skipped: {m.group(0)!r}") from None
        # Optional, present since 5e5d963255.
        for opt in ("wire_user_insns", "clock_minus_wire"):
            if opt in fields:
                rec[opt] = fields[opt]
        out.append(rec)
    return out


# --------------------------------------------------------------------------
# Guest-clock progress gate
#
# A system-mode guest whose clock stops advancing during wrong-path
# (speculative) excursions stops taking timer interrupts and spins in the
# kernel.  Nothing crashes: the tracer faithfully records the spin loop, the
# trace is well-formed, and every structural oracle passes.  The only visible
# signature is in the ACCOUNTING -- the window fails to reach its budget, and
# the ratio of traced architectural instructions to covered user instructions
# explodes, because the kernel spin is charged to the trace while the user
# clock stands still.
#
# Measured on the mcf system-mode marker cell (5M user-insn window, wpdepth
# 64), 72 healthy cells against 5 stalled ones:
#
#              healthy arch/user      stalled arch/user
#   aarch64      1.15 -  2.23           67.6 - 645.0
#   riscv64      1.31 -  3.11
#   x86_64       1.50 -  8.43
#
# so a bound of 20 sits a factor of 2.4 clear of the worst healthy run and a
# factor of 3.4 below the mildest stall.  Kept uniform across ISAs rather than
# tuned per ISA: the separation is orders of magnitude wide, and one number
# cannot rot into a per-ISA exemption.
#
# The ratio is only informative once the window has covered enough user
# instructions to amortise fixed per-segment overhead (guest boot, ptrace
# marker injection, the first scheduler passes before the workload gets the
# CPU) -- below that, the fixed cost dominates the denominator and inflates
# the ratio *by construction*, with no stall involved.  A window that closes
# ``END`` (the workload exited on its own, under budget) after covering only
# a few hundred instructions is the common case here, not a corner case: it
# is exactly ``system.attach_mipsel``'s shape.  Measured by sweeping the
# validator's own synthetic workload (``all --system --attach``, 8 diamonds,
# ``--hot-iters`` scaling the amount of user work) across all four ISAs on a
# quiet host, budget large enough that every cell closes ``END``:
#
#   covered      x86_64   aarch64   riscv64   mipsel
#     ~350-570    40.8      26.9      28.9      17.6
#     ~960-1400   14.8      11.3      12.1       8.0
#   ~2600-3800     6.0       4.7       5.1       3.6
#   ~6000-8600     3.2       2.7       2.8       2.2
#  ~23000-31000    1.6       1.4       1.5       1.3
# ~112000-160000   1.1       1.1       1.1       1.1
#
# The ratio is still explained almost entirely by fixed cost below ~1000
# covered (worst case 14.8, less than 1.4x clear of the 20 bound -- exactly
# the margin that made this check flaky under host contention) and has
# settled into the steady-state healthy band (matching the 5M-window figures
# above) by ~2600.  CLOCK_INFLATION_MIN_COVERED sits at 5000: past the knee
# of the curve with better than 3x headroom under the worst nearby measurement
# (3.2), so the leg only fires once the ratio it is judging is actually
# measuring the guest rather than the boot.  It does not weaken the other two
# legs: the UNDER-close check below is unconditional, and every real stall on
# record (the pre-fix aarch64 gt-timer class, 5M-window cells at 67.6-645x;
# the irqvol reproducers at 24x/116x) closes UNDER with covered orders of
# magnitude above this floor, so both legs still catch it.
# --------------------------------------------------------------------------

CLOCK_INFLATION_MAX = 20.0

# See the sweep above: below this many covered user instructions, fixed
# per-segment overhead dominates the traced/user ratio and a reading past
# CLOCK_INFLATION_MAX is expected, not a symptom.
CLOCK_INFLATION_MIN_COVERED = 5000

# Wall-clock seconds the guest may go without the user-instruction clock
# advancing before the run is declared stalled.  The plugin prints a progress
# line every 10% of the window; a healthy cell emits one every few seconds, a
# stalled one never emits another.
CLOCK_STALL_TIMEOUT_S = 180

# Multiplier applied to that budget while the user clock is still at zero,
# i.e. the window is open but the marked workload has not started running
# yet.  Booting a guest and churning through a pre-window process stream is
# slow and bursty, so the startup state needs far more slack than a clock
# that was already moving; measured worst case for the churn guest is ~200s.
CLOCK_STALL_STARTUP_FACTOR = 4

# Exit status the plugin uses when its own architectural progress detector
# abandons a wedged capture (CST_RT_GATE_EXIT in champsim_tracer.h).
RT_GATE_EXIT = 88

_PROGRESS_RE = re.compile(r"champsim_tracer: progress (\d+)/(\d+) user insns")
_SEG_START_RE = re.compile(r"champsim_tracer: starting segment ")


def parse_user_clock_progress(console_text: str) -> int | None:
    """The most recent user-instruction count the plugin reported, or None
    when the trace window has not opened yet.  This is the guest's user
    clock: the quantity that stops moving when the guest stops taking
    interrupts."""
    if not _SEG_START_RE.search(console_text):
        return None
    last = None
    for m in _PROGRESS_RE.finditer(console_text):
        last = int(m.group(1))
    return last if last is not None else 0


def assess_clock_progress(segments: list[dict], label: str = "") -> list[str]:
    """The accounting half of the guest-clock progress gate: one message per
    way @segments show a guest whose clock stopped.  Empty list means clean.

    Two legs live here; the third, a live no-progress watchdog, has to run
    alongside the guest (see run_with_clock_watchdog).  All three are symptom
    detectors, deliberately: they know nothing about timers or interrupt
    lines, so they cannot be defeated by a new clock source nobody thought to
    reconcile.

    The ratio leg only judges segments that covered at least
    CLOCK_INFLATION_MIN_COVERED user instructions -- below that, fixed
    per-segment overhead (boot, marker injection, early scheduling) dominates
    the ratio by construction, not a stall (see the module-level comment for
    the measured curve).  The UNDER leg has no such floor: closing under
    budget is a failure at any window size."""
    if not segments:
        return [f"{label}: no 'finished segment' line "
                f"(the plugin never closed a window)"]
    bad = []
    for s in segments:
        why = TRUNCATING_CLOSE_FLAGS.get(s["flag"])
        if why:
            bad.append(f"{label}: window closed {s['flag']} short of budget "
                       f"(covered={s['covered']} budget={s['budget']}) -- "
                       f"{why}")
        cov, arch = s["covered"], s["trace_arch_insns"]
        if cov >= CLOCK_INFLATION_MIN_COVERED and arch / cov > CLOCK_INFLATION_MAX:
            bad.append(
                f"{label}: traced/user instruction ratio {arch / cov:.1f} "
                f"exceeds {CLOCK_INFLATION_MAX:.0f} "
                f"(trace_arch_insns={arch} covered={cov}) -- the guest is "
                f"spinning in the kernel while its user clock stands still")
    return bad


def run_with_clock_watchdog(cmd: list[str], log_path,
                            stall_timeout_s: int = CLOCK_STALL_TIMEOUT_S,
                            poll_s: float = 5.0,
                            lldet=None) -> tuple[int, str]:
    """Run a system-mode qemu @cmd with console + plugin stderr to
    @log_path, watching the guest's user-instruction clock while it runs.

    The third leg of the guest-clock progress gate.  A guest that has stopped
    taking interrupts still runs -- it spins in the kernel -- so it neither
    exits nor trips a normal timeout for as long as the harness is willing to
    wait; the segment-accounting legs only fire once it finally gives up.
    Watching the user clock instead detects the stall while it is happening
    and bounds the check's runtime: if no progress line advances for
    @stall_timeout_s of wall time after the window opens, the guest is killed
    and the run reported as stalled.

    Armed once the trace window opens, on two different budgets.  A guest
    that has already reported progress and then stops is unambiguous, and
    gets @stall_timeout_s.  A guest still at zero user instructions is not:
    the window can be open long before the marked workload runs (the churn
    guest spends its whole pre-churn phase there), so that state gets a
    grace period several times longer -- enough that no legitimate startup
    trips it, short enough that a guest which wedges before making any
    progress is still bounded rather than left to some outer timeout.

    @lldet, when given, is a ``_lldet.Watch``: the calibrated-deadline +
    condition-sampling watchdog rides this same poll loop as a second,
    complementary instrument.  The clock leg watches the GUEST's user
    clock (a guest that spins in the kernel); lldet watches the HOST
    process (a qemu that deadlocks before the window ever opens, or
    burns CPU with no trace output).  An lldet verdict kills the run,
    appends the verdict block (evidence + stacks) to @log_path, and is
    returned as the stall reason.

    Returns (rc, stall_reason); stall_reason is "" when the watchdog did not
    fire.  The process group is killed so a qemu that ignores SIGTERM in the
    TCG loop still dies."""
    # The plugin's own #61 progress detector (CST_RT_GATE) watches
    # architectural counts -- instructions retired by the guest against the
    # traced process's user-space instruction clock -- so it returns the same
    # verdict on an idle host and a saturated one, unlike the wall-clock
    # watchdog below, which is a cost tripwire.
    #
    # It is NOT armed here, and the reason is a measured false positive.  Its
    # budget (instructions retired with no workload progress) is calibrated on
    # the canonical devio cell, where 42 healthy cells under SMT-sibling
    # saturation peaked at 403 k against a budget of 8 M.  The CHURN cell is a
    # different animal: the marked workload runs concurrently with a stream of
    # short-lived processes, so the traced process is legitimately off-CPU
    # while the guest retires millions of instructions in other address
    # spaces.  Armed globally, the detector calls that a wedge -- it did, on
    # system.churn_x86.  A single budget cannot serve both workloads; the
    # budget has to be recorded per workload the way golden_net.py records the
    # escaped-wedge ratio, and until it is, this harness passes through only
    # what the operator set.  golden_net.py arms it for the canonical system
    # cells, where the calibration exists.
    # The plugin's diagnostic sampler, whose report the stall-condition gate
    # reads, samples on a 250 ms host-time grid by default: one sample over a
    # validator system segment, at which resolution the gate can certify
    # nothing and would pass on a reading it never took.
    #
    # THAT THE CADENCE CANNOT REACH THE WIRE IS A STATIC FACT, not an A/B
    # result: `sample_ns` in champsim_tracer.cc has exactly four references —
    # its initialiser, the CST_RT_GATE_WINDOW_MS parse, the `if (dh <
    # sample_ns) return;` that decides whether to record a diagnostic sample,
    # and a printf in the realtime gate's abort text.  No tracing decision
    # reads it.  (An A/B on the trace bytes could not have shown this anyway:
    # two runs of this cell at the SAME cadence differ, so the cell is not
    # byte-reproducible and a hash comparison proves nothing here.)
    from . import _stall_condition as _STALL
    env = _STALL.sampler_env()
    # Ptraceable child (prctl PR_SET_PTRACER_ANY, survives execve): under
    # yama ptrace_scope=1 the lldet verdict's `gdb -p` backtrace would
    # otherwise be refused.  Costs nothing when no verdict fires.
    from . import _lldet as _LL
    with open(log_path, "w") as f:
        p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT,
                             start_new_session=True, env=env,
                             preexec_fn=_LL.ptraceable_preexec)
        if lldet is not None:
            lldet.start()
        last_progress, last_change = None, time.monotonic()
        try:
            while True:
                try:
                    rc = p.wait(timeout=poll_s)
                    if rc == RT_GATE_EXIT:
                        return rc, ("the plugin's #61 progress detector "
                                    "abandoned the capture: the guest "
                                    "retired millions of instructions "
                                    "without the traced process executing a "
                                    "single user-space instruction (see the "
                                    "run log for the exact counts)")
                    return rc, ""
                except subprocess.TimeoutExpired:
                    pass
                if lldet is not None:
                    v = lldet.adjudicate(p.pid)
                    if v is not None:
                        # Stacks are already collected (pre-kill).  The
                        # verdict block lands in the cell's own log --
                        # loudly, after the child is dead so the append
                        # cannot be interleaved away.
                        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                        p.wait()
                        try:
                            with open(log_path, "a") as lf:
                                lf.write("\n" + v.block() + "\n")
                        except OSError:
                            pass
                        for line in v.block().splitlines():
                            print(line, flush=True)
                        return _LL.LLDET_EXIT, (
                            f"watchdog VERDICT {v.kind}: {v.summary}")
                try:
                    now = parse_user_clock_progress(
                        Path(log_path).read_text(errors="replace"))
                except OSError:
                    continue
                if now is None:        # window not open yet; not our business
                    last_change = time.monotonic()
                    continue
                if now != last_progress:
                    last_progress, last_change = now, time.monotonic()
                    continue
                # Zero is "the workload has not started yet", which is a
                # legitimate state for a while; anything else is a clock
                # that was moving and stopped.
                budget = stall_timeout_s * (CLOCK_STALL_STARTUP_FACTOR
                                            if now == 0 else 1)
                idle = time.monotonic() - last_change
                if idle >= budget:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                    p.wait()
                    return 1, (f"clock stall: user clock frozen at {now} "
                               f"user insns for "
                               f"{idle:.0f}s of wall time -- the guest has "
                               f"stopped making progress")
        finally:
            if p.poll() is None:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except OSError:
                    pass
                p.wait()


# f2b6e2f4e7 replaced the single `pin ASID reuse suspected` heuristic with
# the two counts the ownership model actually reasons from: how many raw ASID
# names the guest committed anywhere since the pin (the allocator pressure the
# churn test is manufacturing) and how many of them the OWNED address space
# itself executed under (a pinned process that stays put reads 0).  The
# validator kept asking for the old name and had been failing every churn
# cell, on every ISA, ever since.
_PIN_NAMES_RE = re.compile(
    r"distinct raw ASID names committed since the pin\s+(\d+)")
_OWNED_NAMES_RE = re.compile(
    r"distinct raw ASID names the OWNED space executed under\s+(\d+)")
_KEXC_ASID_RE = re.compile(r"kexc ASID-write events\s+(\d+)")


def parse_pin_asid_names(stats_text: str) -> tuple[int | None, int | None]:
    """(names committed since the pin, names the owned space ran under)
    from a <out>.stats.log.  Either is None when its row is absent, which
    the caller must treat as a check that could not find its subject."""
    m = _PIN_NAMES_RE.search(stats_text)
    o = _OWNED_NAMES_RE.search(stats_text)
    return (int(m.group(1)) if m else None,
            int(o.group(1)) if o else None)


def parse_kexc_asid_writes(stats_text: str) -> int | None:
    """The `kexc ASID-write events` counter from a <out>.stats.log —
    every guest context switch writes the ASID register, so this is the
    churn test's kernel-side evidence that other processes were being
    scheduled while the pinned window was open."""
    m = _KEXC_ASID_RE.search(stats_text)
    return int(m.group(1)) if m else None


# --------------------------------------------------------------------------
# Guest health.
#
# A system-mode check measures the guest.  When the guest never reaches the
# workload the check has no subject, and the ONE thing it must not do is
# report the absence as a clean result.  That is not hypothetical: with
# `panic=-1` and `-no-reboot`, a kernel that panics before init execs makes
# qemu exit ZERO, so every gate downstream that reads only the process's
# exit status sees success.  The signatures below are read out of the
# guest's own console and each one fails the run BY NAME.
# --------------------------------------------------------------------------
GUEST_FATAL_SIGNATURES: list[tuple[str, str]] = [
    ("Kernel panic - not syncing", "the guest kernel panicked"),
    ("---[ end Kernel panic", "the guest kernel panicked"),
    ("Attempted to kill init", "the guest kernel killed init"),
    ("No working init found", "the guest kernel found no executable init"),
    ("Failed to execute /init",
     "the guest kernel could not exec /init (error -8 is ENOEXEC: the "
     "staged userland's ABI does not match the -cpu model)"),
    ("exists but couldn't execute it",
     "the guest kernel found an init but could not exec it"),
    ("Unable to handle kernel",
     "an unhandled kernel memory fault in the guest"),
    ("Internal error: Oops", "a guest kernel oops"),
    ("Oops[#", "a guest kernel oops"),
    ("kernel BUG at ", "a guest kernel BUG assertion"),
    ("BUG: unable to handle", "a guest kernel BUG assertion"),
    ("System halted", "the guest halted instead of running the workload"),
]


def scan_guest_console(console_text: str) -> list[str]:
    """Every fatal guest-health signature present in @console_text, each
    rendered as a sentence naming what happened.  Empty means the console
    carries no evidence that the guest failed to reach the workload."""
    out = []
    for token, meaning in GUEST_FATAL_SIGNATURES:
        idx = console_text.find(token)
        if idx >= 0:
            line = console_text[idx:console_text.find("\n", idx)
                                if console_text.find("\n", idx) > 0
                                else len(console_text)]
            out.append(f"{meaning} — console says: {line.strip()[:160]!r}")
    return out


# --------------------------------------------------------------------------
# Kernel page-table isolation.
#
# KPTI-OFF is the canonical system-mode configuration (multiasid_plan §0):
# with isolation disabled the kernel shares each process's ASID, so the
# wire's (asid,vaddr) key covers kernel and user under one process root.
# Every system-mode capture on record was taken that way, and a capture with
# KPTI ON does not carry the same wire semantics.
#
# Nothing asserted it.  It held on x86 only because the boot table appends
# `nopti`; on the validator's default x86 boot it holds for a SECOND,
# unrelated reason (the default TCG cpu is AMD-branded, so Linux never
# considers Meltdown at all and prints nothing either way); and on aarch64 it
# holds for a THIRD (`-cpu max` reports ID_AA64PFR0_EL1.CSV3, so
# UNMAP_KERNEL_AT_EL0 -- which IS compiled into that kernel -- stays dormant).
# Two of the three are properties of a `-cpu` choice made for other reasons.
# Change the model and KPTI silently comes back on, with no line in any
# report saying so.
#
# The check below is deliberately ONE-SIDED: a kernel that turns isolation on
# always announces it, on both architectures that have it, so a positive
# signature is proof and its absence is the ordinary quiet case.  It can
# therefore never fail a healthy cell, and it cannot pass vacuously on the
# thing it is checking.  riscv64 and mipsel have no KPTI to assert.
KPTI_ON_SIGNATURES: list[tuple[str, str]] = [
    # x86: arch/x86/mm/pti.c pti_print_if_insecure()/pti_check_boottime_disable()
    ("Kernel/User page tables isolation: enabled", "x86_64"),
    # arm64: the cpufeature is announced like every other detected feature.
    ("CPU features: detected: Kernel page table isolation (KPTI)", "aarch64"),
    ("Kernel page table isolation (KPTI)", "aarch64"),
]


def kpti_is_on(console_text: str) -> str | None:
    """The console signature saying the guest turned page-table isolation
    ON, or None when it printed no such line.  One-sided by construction:
    see the comment above."""
    for token, _arch in KPTI_ON_SIGNATURES:
        if token in console_text:
            return token
    return None


def assess_kpti(console_text: str, label: str = "") -> list[str]:
    """One message when the guest booted with page-table isolation ON.

    Empty list means no KPTI-on signature was printed, which is the
    canonical configuration.  A cell that WANTS isolation on (the
    ``CST_QEMU_EXTRA_ARGS=-cpu qemu64,vendor=GenuineIntel`` shape the module
    docstring describes) declares it by setting ``CST_EXPECT_KPTI=1``, and
    then the same evidence is reported without failing the run."""
    tok = kpti_is_on(console_text)
    if tok is None:
        return []
    if os.environ.get("CST_EXPECT_KPTI", "").strip() not in ("", "0"):
        print(f"kpti[{label}]: page-table isolation is ON, as this cell "
              f"asked for (CST_EXPECT_KPTI set) — console says {tok!r}")
        return []
    return [f"{label}: the guest booted with kernel page-table isolation ON "
            f"(console says {tok!r}) -- KPTI-off is the canonical "
            f"system-mode configuration, and a capture taken with it on does "
            f"not carry the same (asid,vaddr) wire semantics.  Boot with "
            f"`nopti` (x86) / a CSV3-reporting -cpu (aarch64), or set "
            f"CST_EXPECT_KPTI=1 if this cell means to test isolation."]


def default_kernel(isa: str) -> Path:
    b = _ISA_BOOT[isa]
    return SYSTEST_ROOT / b["dir"] / b["kernel"]


def default_root(isa: str) -> Path:
    return SYSTEST_ROOT / _ISA_BOOT[isa]["dir"] / "root"

# Guest init: mount the pseudo-filesystems, run the staged workload, then
# power off so qemu exits and the plugin finalizes the trace.
#
# Two ways the workload's address space gets marked, chosen by
# default_init(attach=...):
#
#   compiled-in  the workload carries the marker at _start
#                (``generate --marker``) and init exec's it directly.
#   injected     the workload carries NO start marker; the staged
#                cst_attach (as /bin/cst_trace) exec's it under ptrace and
#                pokes the marker into its entry point.  This is the path
#                an UNMODIFIED binary must take, so running the validator
#                over it keeps the injector honest on every ISA.
_INIT = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst_validator system-mode guest: $(uname -r) ==="
{run}
echo "=== /workload exit=$? ; powering off ==="
poweroff -f
"""

# Where the injector lands inside the guest, and what it is called there.
ATTACH_GUEST_PATH = "bin/cst_trace"


def default_init(attach: bool = False) -> str:
    """The run-then-poweroff /init script.  @attach routes the workload
    through the staged ptrace marker injector instead of exec'ing it
    directly."""
    return _INIT.format(
        run=f"/{ATTACH_GUEST_PATH} /workload" if attach else "/workload")


# Idle-boundary init: the same run-then-poweroff shape as the default, with
# the guest kernel's own idle accounting read across the workload's sleep.
#
# It exists because "the guest reached its idle instruction" is not otherwise
# observable from outside.  A single-vCPU system cell whose workload never
# blocks never lets the run queue empty, so the kernel never executes its idle
# instruction (riscv `wfi`, arm `wfi`, x86 `hlt`) and the whole idle boundary
# — where a system commits to sleeping on a timer it has already armed — goes
# unexercised.  Pairing this init with a workload that nanosleeps inside the
# trace window (``--sleep-probe``) empties the run queue for a bounded stretch,
# and the two /proc/uptime reads MEASURE that it emptied rather than assuming
# it: field 2 of /proc/uptime is the kernel's summed idle time, so the
# difference is guest-observed idle seconds and a cell that stopped idling
# reports a difference of zero.
#
# WHY THE SECOND READ IS ON A TIMER, AND WHY THE TIMER IS SHORTER THAN THE
# SLEEP.  A traced system run does not outlive its trace: once the marked
# window spends its budget the capture closes and the run is torn down, so
# /init's line after /workload is never reached and the "after" read never
# happens.  Putting the read on a background timer is necessary but not
# sufficient — the timer counts GUEST time, and guest time barely advances
# once the workload starts computing, because that is exactly what the
# wrong-path excursion bracket freezes.  A timer armed past the end of the
# sleep therefore expires only in a stretch of guest time the trace has all
# but stopped, and it, too, never fires.
#
# So the read is taken a couple of seconds BEFORE the sleep is due to end,
# while the guest is still idling and its clock still running at wall rate.
# That is not a weaker reading: it samples the idle counter strictly inside
# the open window, which is where the boundary being covered has to be
# crossed.
#
# The subshell cannot manufacture what it measures.  Idle time accrues from an
# EMPTY run queue, and a shell blocked in sleep(1) is not on the run queue any
# more than /init blocked in wait(2) is; without the workload's own sleep the
# workload is runnable throughout and the difference stays at zero.  That
# direction is checked, not argued: idle_console_verdict is run against the
# console of a cell WITHOUT a sleep probe as well.
#
# Kept as a separate init rather than folded into the default because the
# console text and the extra forks are part of a system capture's traced
# bytes: every existing system cell, and the system golden net, would move.
_INIT_IDLE = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst_validator system-mode guest: $(uname -r) ==="
read _up _idle < /proc/uptime
echo "=== cst_idle_before $_idle ==="
( sleep {after} ; read _u2 _i2 < /proc/uptime ; \
  echo "=== cst_idle_after $_i2 ===" ) &
/workload
_rc=$?
echo "=== /workload exit=$_rc ; powering off ==="
poweroff -f
"""

# The console markers idle_init() writes, and the parser for them.  Kept
# beside the template so a change to one is a change to both.
IDLE_BEFORE_RE = re.compile(r"^=== cst_idle_before ([0-9.]+) ===", re.M)
IDLE_AFTER_RE = re.compile(r"^=== cst_idle_after ([0-9.]+) ===", re.M)


def idle_init(sleep_probe_s: int) -> str:
    """The run-then-poweroff /init that reads the guest's own idle accounting
    across a @sleep_probe_s-second workload sleep.  See _INIT_IDLE.

    The second read lands shortly before the workload's sleep is due to end,
    so it is taken while the guest is still idle and its clock still running
    at wall rate — not after the traced compute has all but stopped guest
    time, and not after the run has been torn down."""
    return _INIT_IDLE.format(after=max(1, int(sleep_probe_s) - 2))


def read_guest_idle(console_text: str):
    """Guest idle seconds accumulated across the workload, from the two
    /proc/uptime reads idle_init() writes to the console.

    Returns ``(before, after)`` or ``None`` when either marker is missing.
    ``None`` is not "no idle": it is "this console was not produced by
    idle_init(), so nothing about idling can be read from it", and a caller
    that treats it as a zero would be reporting a measurement it never made.
    """
    b = IDLE_BEFORE_RE.search(console_text)
    a = IDLE_AFTER_RE.search(console_text)
    if not b or not a:
        return None
    return float(b.group(1)), float(a.group(1))


# Churn-test init: the marked workload runs concurrently with a stream of
# short-lived unmarked processes (each shell-loop iteration forks a subshell
# and execs /bin/true, so every iteration burns through two fresh mm's and
# with them two fresh ASIDs).  A pre-workload burst gets the guest's ASID
# allocator away from its boot-time state; the in-flight churn then forces
# allocator pressure — on MIPS's 8-bit ASID space, a full generation
# rollover — while the pinned trace window is open.  The workload runs in
# the background so init's own shell can keep forking; init waits for it
# before powering off.
_INIT_CHURN = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst_validator churn-test guest: $(uname -r) ==="
i=0
while [ $i -lt {pre} ]; do /bin/true; i=$((i+1)); done
echo "=== pre-workload churn done ($i procs) ==="
/workload &
wpid=$!
echo "=== in-flight churn started ==="
i=0
while [ $i -lt {during} ]; do /bin/true; i=$((i+1)); done
echo "=== in-flight churn done ($i procs) ==="
wait $wpid
echo "=== /workload exit=$? ; powering off ==="
poweroff -f
"""


def churn_init(pre: int, during: int) -> str:
    """The churn-test /init script: @pre short-lived processes before the
    marked workload starts, @during more launched while it runs."""
    return _INIT_CHURN.format(pre=int(pre), during=int(during))


# Dead-latch-test inits.  The workload (built WITHOUT its END marker) runs
# in the foreground and exits with its window still open; what the guest
# does NEXT selects which of the latch's two failure mechanisms the cell
# exercises, and both shapes must end in a dead-latch IDLE close:
#
#   storm — a fork loop (each iteration burns a subshell + /bin/true, two
#   fresh mm's).  Linux hands the dead workload's freed page-table root to
#   one of those forks, QEMU's identity layer interns the raw root value,
#   and the successor then presents every refresh event in the dead
#   window's name.  This is the shape that held the latch inert for 580 s
#   in three sized attempts; the stamp's proof-of-life probe is what makes
#   it close.  No poweroff: the LATCH must end this run.
#
#   quiet — a pure shell-builtin spin (no forks, no execs, no address-space
#   writes after the first schedule).  Nothing recycles the root, but
#   nothing context-switches either, so the ASID-write sweep trigger never
#   fires; the retirement-driven sweep beat is what makes it close.
_INIT_DEADLATCH_STORM = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst_validator deadlatch-test guest (storm): $(uname -r) ==="
/workload
echo "=== /workload exit=$? (window left open) ==="
while true; do /bin/true; done
"""

_INIT_DEADLATCH_QUIET = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst_validator deadlatch-test guest (quiet): $(uname -r) ==="
/workload
echo "=== /workload exit=$? (window left open) ==="
while :; do :; done
"""


def deadlatch_init(shape: str) -> str:
    """The deadlatch-test /init script for @shape ('storm' or 'quiet')."""
    if shape == "storm":
        return _INIT_DEADLATCH_STORM
    if shape == "quiet":
        return _INIT_DEADLATCH_QUIET
    raise ValueError(f"deadlatch_init: unknown shape {shape!r}")


# The ptrace marker injector, built for the GUEST (it runs inside the
# guest, on the guest's own /workload).  The tracer's four target ISAs all
# have a backend in cst_attach.c; the compiler for each is the same cross
# toolchain the validator already uses to build workloads, minus the ++.
ATTACH_SRC = Path(__file__).resolve().parents[2] / "tools" / "cst_attach.c"

ISA_ATTACH_CC = {
    "x86_64":  "gcc",
    "aarch64": "aarch64-linux-gnu-gcc",
    "riscv64": "riscv64-linux-gnu-gcc",
    "mipsel":  "mipsel-linux-gnu-gcc",
}


def build_cst_attach(isa: str, out_dir: Path) -> Path | None:
    """Build cst_attach for @isa into @out_dir and return the binary, or
    None when that ISA's cross compiler is not installed (the caller then
    skips rather than staging an injector that cannot run).

    Static, because the guest rootfs it is staged into is a busybox tree
    with no matching dynamic loader for a foreign toolchain's libc.

    Deliberately NOT built -mnan=2008 on mipsel even though the guest runs
    on a 2008-NaN-only CPU: this one links against libc, and the
    mipsel-linux-gnu cross toolchain has no 2008-NaN multilib -- the build
    dies at <gnu/stubs-o32_hard_2008.h>, and forcing it through would hit
    ld's refusal to merge the two NaN ABIs.  It is admitted by the
    ieee754=relaxed on the mipsel kernel command line, alongside busybox,
    until the base rootfs and its libc are rebuilt 2008-NaN."""
    cc = ISA_ATTACH_CC.get(isa)
    if cc is None or shutil.which(cc) is None:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"cst_attach_{isa}"
    if out.is_file() and out.stat().st_mtime >= ATTACH_SRC.stat().st_mtime:
        return out
    cmd = [cc, "-std=gnu11", "-O2", "-static",
           str(ATTACH_SRC), "-o", str(out)]
    if subprocess.call(cmd) != 0:
        raise RuntimeError(f"build_cst_attach[{isa}]: {' '.join(cmd)} failed")
    return out


def stage_initramfs(base_root: Path, workload: Path, stage_dir: Path,
                    init_text: str | None = None,
                    attach_bin: Path | None = None) -> Path:
    """Copy @base_root, add @workload as /workload plus an init that runs it,
    and repack into <stage_dir>/rootfs.cpio.gz.  Returns the cpio path.
    @init_text overrides the default run-then-poweroff /init script.
    @attach_bin, when given, is installed as the guest's /bin/cst_trace so
    an init built by default_init(attach=True) can inject the marker."""
    root = stage_dir / "sysroot"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    # `cp -a`, not shutil.copytree: a busybox rootfs is hundreds of HARDLINKS
    # to one busybox inode, and copytree would explode each into a full copy
    # (~400x the size), overflowing the initramfs.  cp -a preserves hardlinks,
    # symlinks, and permissions.
    subprocess.check_call(["cp", "-a", f"{base_root}/.", str(root)])
    dst = root / "workload"
    shutil.copy2(workload, dst)
    dst.chmod(0o755)
    if attach_bin is not None:
        guest_attach = root / ATTACH_GUEST_PATH
        guest_attach.parent.mkdir(parents=True, exist_ok=True)
        # The base root's /bin/* are hardlinks into one busybox inode, so
        # write through a fresh path rather than over an existing name.
        if guest_attach.exists():
            guest_attach.unlink()
        shutil.copy2(attach_bin, guest_attach)
        guest_attach.chmod(0o755)
    init = root / "init"
    init.write_text(init_text if init_text is not None else default_init())
    init.chmod(0o755)

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
    if gz.returncode != 0:
        raise RuntimeError("stage_initramfs: cpio/gzip pack failed")
    return cpio


def system_qemu_cmd(qemu_system: Path, kernel: Path, initrd: Path,
                    plugin: Path, plugin_opts: str, mem: str = "512M",
                    isa: str = "x86_64", smp: int = 1) -> list[str]:
    """Build the qemu-system command that boots @kernel + @initrd headless
    with the plugin loaded, powering off (not rebooting) on guest halt.
    Machine model and console come from the per-ISA boot table.

    Honors ``CST_PLUGIN_EXTRA_ARGS`` (comma-prefixed onto @plugin_opts)
    and ``CST_QEMU_EXTRA_ARGS`` (space-split, appended last so e.g. a
    ``-cpu`` override wins) — see the module docstring."""
    b = _ISA_BOOT[isa]
    append = f"console={b['console']} panic=-1"
    if b.get("extra_append"):
        append += f" {b['extra_append']}"
    extra_plugin = os.environ.get("CST_PLUGIN_EXTRA_ARGS", "").strip()
    if extra_plugin:
        plugin_opts = f"{plugin_opts},{extra_plugin.lstrip(',')}"
    cmd = [
        str(qemu_system),
        *b["machine"],
        "-kernel", str(kernel),
        "-initrd", str(initrd),
        "-append", append,
        "-nographic", "-no-reboot", "-m", mem,
        "-plugin", f"{plugin},{plugin_opts}",
    ]
    if smp and int(smp) > 1:
        cmd += ["-smp", str(int(smp))]
        # No per-cell -cpu override anywhere: the model comes from the boot
        # shape above and nothing may quietly replace it.  mipsel SMP used to
        # switch to 34Kf for the MT ASE; P5600 has no MT ASE and brings up
        # secondaries through CPS (Config3.CMGCR) instead, so the guest
        # kernel needs CONFIG_MIPS_CPS=y.  Substituting 34Kf back would
        # silently restore a model with no page-table root -- which the
        # plugin now refuses outright, so the failure would at least be
        # loud, but the harness must not create it in the first place.
    cmd += os.environ.get("CST_QEMU_EXTRA_ARGS", "").split()
    return cmd
