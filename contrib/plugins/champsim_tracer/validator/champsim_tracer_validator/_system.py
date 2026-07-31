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
    "mipsel":  {"dir": "mipsel",  "kernel": "vmlinux",
                "machine": ["-M", "malta"],
                "console": "ttyS0"},
}


# The plugin's per-segment close line (stderr).  In marker mode the
# coverage and budget run on the user-instruction clock and carry the
# "user_" prefix; OK = covered >= budget, END = closed by the end
# marker / workload exit under budget, UNDER = closed early for any
# other reason (always a failure).
_FINISHED_SEG_RE = re.compile(
    r"champsim_tracer: finished segment \[icount (\d+) \.\. (\d+)\]\s+"
    r"actual_icount=(\d+)\s+(user_)?covered=(\d+)\s+(?:user_)?budget=(\d+)"
    r"\s+rep_fanout=(\d+)\s+trace_arch_insns=(\d+)\s+(OK|END|UNDER)")


def parse_finished_segments(console_text: str) -> list[dict]:
    """Parse every per-segment coverage line the plugin printed into the
    captured console log.  Returns one dict per closed segment with
    covered / budget / flag / user_clock keys."""
    out = []
    for m in _FINISHED_SEG_RE.finditer(console_text):
        out.append({
            "lo": int(m.group(1)),
            "hi": int(m.group(2)),
            "actual_icount": int(m.group(3)),
            "user_clock": m.group(4) is not None,
            "covered": int(m.group(5)),
            "budget": int(m.group(6)),
            "rep_fanout": int(m.group(7)),
            "trace_arch_insns": int(m.group(8)),
            "flag": m.group(9),
        })
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
        if s["flag"] == "UNDER":
            bad.append(f"{label}: window closed UNDER budget "
                       f"(covered={s['covered']} budget={s['budget']}) -- "
                       f"the guest stopped making user-space progress")
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
                            poll_s: float = 5.0) -> tuple[int, str]:
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
    env = dict(os.environ)
    with open(log_path, "w") as f:
        p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT,
                             start_new_session=True, env=env)
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
                    return 1, (f"user clock frozen at {now} user insns for "
                               f"{idle:.0f}s of wall time -- the guest has "
                               f"stopped making progress")
        finally:
            if p.poll() is None:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except OSError:
                    pass
                p.wait()


_PIN_REUSE_RE = re.compile(r"pin ASID reuse suspected\s+(\d+)")
_KEXC_ASID_RE = re.compile(r"kexc ASID-write events\s+(\d+)")


def parse_pin_asid_reuse(stats_text: str) -> int | None:
    """The `pin ASID reuse suspected` counter from a <out>.stats.log
    (None when the stats file carries no summary)."""
    m = _PIN_REUSE_RE.search(stats_text)
    return int(m.group(1)) if m else None


def parse_kexc_asid_writes(stats_text: str) -> int | None:
    """The `kexc ASID-write events` counter from a <out>.stats.log —
    every guest context switch writes the ASID register, so this is the
    churn test's kernel-side evidence that other processes were being
    scheduled while the pinned window was open."""
    m = _KEXC_ASID_RE.search(stats_text)
    return int(m.group(1)) if m else None


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
    with no matching dynamic loader for a foreign toolchain's libc."""
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
        if isa == "mipsel":
            # Malta SMP needs the MT ASE: the guest's CONFIG_MIPS_MT_SMP
            # secondary bring-up runs VPE probes that corrupt the stack
            # and panic on the default 24Kc ("stack-protector: Kernel
            # stack is corrupted in: vsnprintf"), leaving CPU 1 offline
            # for the whole run.  34Kf onlines both CPUs.
            cmd += ["-cpu", "34Kf"]
    cmd += os.environ.get("CST_QEMU_EXTRA_ARGS", "").split()
    return cmd
