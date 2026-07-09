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


def stage_initramfs(base_root: Path, workload: Path, stage_dir: Path) -> Path:
    """Copy @base_root, add @workload as /workload plus an init that runs it,
    and repack into <stage_dir>/rootfs.cpio.gz.  Returns the cpio path."""
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
    init.write_text(_INIT)
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
                    isa: str = "x86_64") -> list[str]:
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
    cmd += os.environ.get("CST_QEMU_EXTRA_ARGS", "").split()
    return cmd
