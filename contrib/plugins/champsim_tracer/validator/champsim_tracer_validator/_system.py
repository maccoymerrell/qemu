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
import subprocess
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
    "x86_64":  {"dir": "x86",     "kernel": "vmlinuz",
                "machine": [],
                "console": "ttyS0"},
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

# Guest init: mount the pseudo-filesystems, run the staged workload (which
# fires the marker at _start so the plugin attaches + pins), then power off
# so qemu exits and the plugin finalizes the trace.
_INIT = """#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc  none /proc 2>/dev/null
mount -t sysfs none /sys  2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== cst_validator system-mode guest: $(uname -r) ==="
/workload
echo "=== /workload exit=$? ; powering off ==="
poweroff -f
"""

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


def stage_initramfs(base_root: Path, workload: Path, stage_dir: Path,
                    init_text: str | None = None) -> Path:
    """Copy @base_root, add @workload as /workload plus an init that runs it,
    and repack into <stage_dir>/rootfs.cpio.gz.  Returns the cpio path.
    @init_text overrides the default run-then-poweroff /init script."""
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
    init = root / "init"
    init.write_text(init_text if init_text is not None else _INIT)
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
