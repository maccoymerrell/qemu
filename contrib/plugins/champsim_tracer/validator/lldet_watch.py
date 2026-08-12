#!/usr/bin/env python3
"""lldet_watch — run one qemu cell under the calibrated lldet watchdog.

The standalone face of ``champsim_tracer_validator._lldet`` for ad-hoc cell
harnesses (the ``cellD.sh`` style): exec a qemu command line under the same
calibrated deadline + condition sampling the validator's own cells run
under, without importing anything.  The child's stdio is inherited — the
harness keeps doing its own redirection; pass ``--console`` so the watchdog
can watch that file's growth as a progress signal.

Exit status: the child's own, or 89 (LLDET_EXIT) after a watchdog kill.
A kill is loud: the verdict, both condition samples and a gdb backtrace go
to stderr and to ``<growth-prefix>.lldet`` (or ``--sidecar``), so a killed
cell can never read as an ordinary failure.

Examples::

    lldet_watch.py --isa x86_64 --mode user --budget 200000 \\
        --growth-prefix /run/out/prog_x86_64 -- \\
        ./build/qemu-x86_64 -plugin ... ./prog

    lldet_watch.py --isa mipsel --mode system --smp 2 --budget 150000 \\
        --growth-prefix "$CELL/out" --console "$CELL/console" -- \\
        ./build/qemu-system-mipsel ... < /dev/null >> "$CELL/console" 2>&1

The calibration table ships next to the engine
(``champsim_tracer_validator/lldet_calibration.json``); override with
``--table`` or ``CST_LLDET_TABLE``.  ``--timeout`` / ``--k`` override the
calibrated deadline (testing and one-off ops).

Author: Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from champsim_tracer_validator import _lldet  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run a qemu command under the calibrated lldet "
                    "watchdog (deadlock/livelock detection by condition "
                    "sampling).  Everything after `--` is the command.")
    ap.add_argument("--isa", required=True,
                    choices=("x86_64", "aarch64", "riscv64", "mipsel"))
    ap.add_argument("--mode", required=True, choices=("user", "system"))
    ap.add_argument("--smp", type=int, default=1)
    ap.add_argument("--wpdepth", type=int, default=64,
                    help="Cell's wpdepth (selects the wp/nowp calibration "
                         "row); default 64.")
    ap.add_argument("--budget", type=int, default=None,
                    help="The cell's instruction budget (trace_window "
                         "stop / user-insn budget).  Omit for an unbounded "
                         "trace-to-exit cell: the per-mode ceiling applies.")
    ap.add_argument("--growth-prefix", required=True,
                    help="The plugin's outfile= prefix; <prefix>*.cst* and "
                         "<prefix>*.body_tmp* are the trace-growth signal.")
    ap.add_argument("--console", type=Path, default=None,
                    help="The cell's console/log file (growth counts as "
                         "progress; system cells should always pass it).")
    ap.add_argument("--sidecar", type=Path, default=None,
                    help="Where the [lldet] event log goes "
                         "(default <growth-prefix>.lldet).")
    ap.add_argument("--table", type=Path, default=None,
                    help="Alternate calibration table "
                         "(default: the checked-in one).")
    ap.add_argument("--k", type=float, default=None,
                    help="Override the table's safety factor.")
    ap.add_argument("--timeout", type=float, default=None,
                    help="Override the computed base timeout (seconds).")
    ap.add_argument("--pid-file", type=Path, default=None,
                    help="Write the child's pid here (test orchestration).")
    ap.add_argument("cmd", nargs=argparse.REMAINDER,
                    help="-- qemu command line")
    args = ap.parse_args()

    cmd = args.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        ap.error("no command given (put it after `--`)")
    if args.table:
        os.environ["CST_LLDET_TABLE"] = str(args.table)
    if args.k is not None:
        os.environ["CST_LLDET_K"] = str(args.k)
    if args.timeout is not None:
        os.environ["CST_LLDET_TIMEOUT"] = str(args.timeout)

    watch = _lldet.Watch(
        key=_lldet.config_key(args.isa, args.mode, args.smp, args.wpdepth),
        budget=args.budget,
        growth_patterns=_lldet.default_growth_patterns(args.growth_prefix),
        console_path=args.console,
        sidecar_path=args.sidecar or Path(args.growth_prefix + ".lldet"),
        label=f"{args.mode} cell {Path(args.growth_prefix).name}")

    if args.pid_file:
        # run_watched owns the Popen; expose the pid via a tiny shim.
        orig = _lldet.subprocess.Popen

        def popen_with_pidfile(*a, **kw):
            p = orig(*a, **kw)
            try:
                args.pid_file.write_text(str(p.pid) + "\n")
            except OSError:
                pass
            return p
        _lldet.subprocess.Popen = popen_with_pidfile

    rc, verdict = _lldet.run_watched(cmd, watch)
    if verdict is not None:
        print(f"lldet_watch: cell KILLED by watchdog: VERDICT "
              f"{verdict.kind} -- {verdict.summary}", file=sys.stderr)
        return _lldet.LLDET_EXIT
    return rc


if __name__ == "__main__":
    sys.exit(main())
