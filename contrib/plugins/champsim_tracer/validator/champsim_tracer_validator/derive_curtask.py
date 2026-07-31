"""Derive the guest kernel's current-task per-CPU offset, per image.

The x86-64 target resolves kernel-privilege thread identity by reading
the kernel's per-CPU ``current_task`` pointer through the live kernel
GS base (``curtask_off=`` plugin option -> ``qemu_plugin_set_current_
task_offset``).  The offset is decided at the kernel's link time and
differs per build, so it must be derived from the very image being
booted — never hardcoded, never reused across builds.  This module is
the project's one derivation path; a caller that cannot derive the
offset must run WITHOUT the option (the tracer then keeps its weaker
register-only contract) rather than guess.

Three sources, in order of directness:

1. ``--vmlinux`` (unstripped ELF) — ``nm`` output.
2. ``--system-map`` / ``--kallsyms`` — a symbol text file, or a captured
   guest ``/proc/kallsyms`` dump.
3. ``--boot`` — boot the image once (no plugin) with an init that dumps
   ``/proc/kallsyms``, and parse the console.  This reads the running
   kernel's own statement of its layout, so it works for the common
   case — a stripped, compressed distribution ``vmlinuz`` — with no
   image-format parser to rot.  The result is cached per image content
   hash so the boot happens once per image ever.

The symbol rule: the per-CPU symbol ``current_task`` when the build has
one (v < 6.2, v >= 6.14); else ``pcpu_hot`` + 0 — ``current_task`` is
the FIRST member of ``struct pcpu_hot`` (arch/x86/include/asm/current.h,
6.2 <= v < 6.14), unconditionally, so its offset within the struct is 0.
Per-CPU symbol values are 0-based section offsets (``__per_cpu_start``
is 0 on x86-64); when a dump carries a non-zero ``__per_cpu_start`` the
value is rebased.  NO other symbol is accepted: a missing symbol is a
loud failure with no output, never a guess.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# Symbol line, as emitted by nm / System.map / /proc/kallsyms:
#   <hexvalue> <type> <name>
_SYM_RE = re.compile(
    r"^([0-9a-fA-F]+)\s+([A-Za-z])\s+(\S+)(?:\s|$)")

_INIT = r"""#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc none /proc 2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo 0 > /proc/sys/kernel/kptr_restrict 2>/dev/null
echo "=== CST_CURTASK KREL $(uname -r) ==="
echo "=== CST_CURTASK SYMBOLS BEGIN ==="
grep -wE "pcpu_hot|current_task|__per_cpu_start" /proc/kallsyms
echo "=== CST_CURTASK SYMBOLS END ==="
poweroff -f
"""


def offset_from_symbols(text: str) -> int:
    """Extract the current-task per-CPU offset from symbol-table text.

    Raises LookupError when neither ``current_task`` nor ``pcpu_hot``
    is present — the caller must treat that as "no offset, run without
    the option", never as 0.
    """
    syms: dict[str, int] = {}
    for line in text.splitlines():
        m = _SYM_RE.match(line.strip())
        if m:
            name = m.group(3)
            if name in ("current_task", "pcpu_hot", "__per_cpu_start"):
                # First sighting wins; a kernel has at most one of each.
                syms.setdefault(name, int(m.group(1), 16))
    base = syms.get("__per_cpu_start", 0)
    for name in ("current_task", "pcpu_hot"):
        if name in syms:
            off = syms[name] - base
            if off < 0:
                raise LookupError(
                    f"{name} (0x{syms[name]:x}) below __per_cpu_start "
                    f"(0x{base:x}) — not a per-CPU layout this rule knows")
            return off
    raise LookupError(
        "neither per-CPU symbol `current_task` nor `pcpu_hot` found "
        "(is this an x86-64 Linux symbol table with data symbols, "
        "kptr_restrict=0 and CONFIG_KALLSYMS_ALL?)")


def offset_from_vmlinux(vmlinux: Path) -> int:
    p = subprocess.run(["nm", str(vmlinux)], capture_output=True, text=True)
    if p.returncode != 0:
        raise LookupError(f"nm {vmlinux} failed: {p.stderr.strip()[:200]}")
    return offset_from_symbols(p.stdout)


def _cache_path(kernel: Path, cache_dir: Path) -> Path:
    h = hashlib.sha256(kernel.read_bytes()).hexdigest()[:16]
    return cache_dir / f"curtask.{kernel.name}.{h}"


def offset_from_boot(kernel: Path, qemu_system: Path, base_root: Path,
                     work_dir: Path, cache_dir: Path | None = None,
                     timeout: int = 300) -> int:
    """One-shot no-plugin boot of @kernel dumping /proc/kallsyms.

    The result is cached under @cache_dir keyed by the image's content
    hash, so a re-derivation for the same bytes never boots again.  A
    boot that produces no symbol section FAILS (raises), including when
    the guest never reached the init: a derivation that cannot find its
    subject must fail, not return something.
    """
    if cache_dir is not None:
        cp = _cache_path(kernel, cache_dir)
        if cp.is_file():
            return int(cp.read_text().strip(), 0)
    work_dir.mkdir(parents=True, exist_ok=True)
    root = work_dir / "sysroot"
    if root.exists():
        subprocess.run(["rm", "-rf", str(root)], check=True)
    root.mkdir(parents=True)
    subprocess.check_call(["cp", "-a", f"{base_root}/.", str(root)])
    (root / "init").write_text(_INIT)
    (root / "init").chmod(0o755)
    cpio = work_dir / "rootfs.cpio.gz"
    with open(cpio, "wb") as f:
        find = subprocess.Popen(["find", "."], cwd=root,
                                stdout=subprocess.PIPE)
        pack = subprocess.Popen(
            ["sh", "-c", "cpio -o -H newc --quiet | gzip -1"],
            cwd=root, stdin=find.stdout, stdout=f)
        find.stdout.close()
        pack.communicate()
        find.wait()
        if find.returncode != 0 or pack.returncode != 0:
            raise LookupError("initramfs pack failed")
    cmd = [str(qemu_system),
           "-kernel", str(kernel), "-initrd", str(cpio),
           "-append", "console=ttyS0 panic=-1",
           "-nographic", "-no-reboot", "-m", "512M"]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    console = p.stdout + p.stderr
    (work_dir / "console.log").write_text(console)
    m = re.search(r"=== CST_CURTASK SYMBOLS BEGIN ===\n(.*?)\n"
                  r"=== CST_CURTASK SYMBOLS END ===", console, re.S)
    if not m:
        raise LookupError(
            f"boot produced no symbol dump (console in "
            f"{work_dir / 'console.log'}; qemu rc={p.returncode})")
    off = offset_from_symbols(m.group(1))
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        _cache_path(kernel, cache_dir).write_text(f"0x{off:x}\n")
    return off


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="derive the x86-64 guest kernel's current-task "
                    "per-CPU offset (curtask_off= plugin option)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--vmlinux", type=Path,
                     help="unstripped vmlinux ELF (nm)")
    src.add_argument("--system-map", type=Path,
                     help="System.map / kallsyms-format text file")
    src.add_argument("--boot", type=Path, metavar="KERNEL",
                     help="kernel image to boot once for a "
                          "/proc/kallsyms dump (no plugin)")
    ap.add_argument("--build-dir", type=Path,
                    help="QEMU build dir providing qemu-system-x86_64 "
                         "(required with --boot)")
    ap.add_argument("--base-root", type=Path,
                    help="busybox rootfs to stage the dump init into "
                         "(default: the systest x86 root)")
    ap.add_argument("-o", "--work-dir", type=Path,
                    help="scratch dir for the boot (required with --boot)")
    ap.add_argument("--cache-dir", type=Path,
                    help="cache derived offsets per image hash here")
    a = ap.parse_args(argv)
    try:
        if a.vmlinux:
            off = offset_from_vmlinux(a.vmlinux)
        elif a.system_map:
            off = offset_from_symbols(a.system_map.read_text())
        else:
            if not a.build_dir or not a.work_dir:
                ap.error("--boot requires --build-dir and -o/--work-dir")
            base_root = a.base_root
            if base_root is None:
                from . import _system
                base_root = _system.SYSTEST_ROOT / "x86" / "root"
            off = offset_from_boot(
                a.boot, a.build_dir / "qemu-system-x86_64", base_root,
                a.work_dir, cache_dir=a.cache_dir)
    except (LookupError, OSError, subprocess.TimeoutExpired) as e:
        print(f"derive_curtask: FAIL: {e}", file=sys.stderr)
        return 1
    print(f"0x{off:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
