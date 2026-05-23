#!/usr/bin/env python3
"""champsim_tracer_validator CLI.

Subcommands:
    generate   Build a seed-driven assembly source + metadata sidecar.
    build      Assemble/link the source for one or more ISAs.
  trace      Run the champsim_tracer plugin on a compiled binary.
  analyze    Disassemble the binary, annotate metadata with ground truth.
  validate   Compare the decoded trace to the metadata.
  all        Run every step above for the requested ISAs.

Example:
  python3 -m champsim_tracer_validator all --seed 0x0102 -o out/prog01 \\
      --build-dir ../../../build --isa x86_64
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from . import generator as G
from . import analyzer as A
from . import validator as V


ISA_CHOICES = ("x86_64", "aarch64", "riscv64", "mipsel")

ISA_COMPILER = {
    "x86_64":  "g++",
    "aarch64": "aarch64-linux-gnu-g++",
    "riscv64": "riscv64-linux-gnu-g++",
    "mipsel":  "mipsel-linux-gnu-g++",
}

ISA_CFLAGS = {
    "x86_64":  ["-static", "-nostdlib", "-nostartfiles"],
    "aarch64": ["-static", "-nostdlib", "-nostartfiles"],
    "riscv64": ["-static", "-nostdlib", "-nostartfiles",
                "-march=rv64gc", "-mabi=lp64d",
                # We use -nostartfiles, so no crt0 sets up `gp` to
                # __global_pointer$.  Without that, any compiler-emitted
                # gp-relative load/store (driven by the small-data
                # optimization or by linker relaxation) faults at runtime
                # because gp == 0.  Disable both: no small-data placement
                # and no linker relaxation.
                "-msmall-data-limit=0", "-mno-relax",
                "-Wl,--no-relax"],
    "mipsel":  [
        "-static", "-nostdlib", "-nostartfiles", "-e", "_start",
        "-mno-abicalls", "-fno-pic",
    ],
}

ISA_QEMU = {
    "x86_64":  "qemu-x86_64",
    "aarch64": "qemu-aarch64",
    "riscv64": "qemu-riscv64",
    "mipsel":  "qemu-mipsel",
}


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _have(tool: str) -> bool:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if os.access(os.path.join(d, tool), os.X_OK):
            return True
    return False


def _parse_seed(s: str) -> int:
    s = s.strip()
    return int(s, 0)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Procedural validator for the QEMU champsim_tracer plugin."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("-o", "--out-dir", type=Path, required=True,
                        help="Output directory (also program-name root).")
        sp.add_argument("--prog", default=None,
                        help="Program basename (default: name of out-dir).")

    # generate
    g = sub.add_parser("generate", help="Emit .S + .meta.json")
    common(g)
    g.add_argument("--seed", type=_parse_seed, required=True)
    g.add_argument("--isa", choices=ISA_CHOICES, required=True,
                   help="Target ISA (affects only exit-syscall asm).")
    g.add_argument("--diamonds", type=int, default=8)
    g.add_argument("--side-len-min", type=int, default=2)
    g.add_argument("--side-len-max", type=int, default=4)
    g.add_argument("--coverage", action="store_true",
                   help="Prepend one of every probe block (per ISA) so a "
                        "single trace exercises 100%% of the reachable "
                        "GenericOpcode classifications.")
    g.add_argument("--hot-iters", type=int, default=0,
                   help="If > 0, place one explicit loop region on each side "
                        "of every diamond and have the loop exit after this "
                        "many body executions.")
    g.add_argument("--stride-loops", action="store_true",
                   help="Generate a dedicated stride-loop CFG (x86_64 only) "
                        "that exercises varying load/store ADDRESSES across "
                        "executions of the same template; intended for "
                        "stressing the per-execution memop encoder.")

    # build
    b = sub.add_parser("build", help="Assemble/link .S for an ISA")
    common(b)
    b.add_argument("--isa", choices=ISA_CHOICES, required=True)

    # trace
    t = sub.add_parser("trace", help="Run the champsim_tracer plugin on the binary")
    common(t)
    t.add_argument("--isa", choices=ISA_CHOICES, required=True)
    t.add_argument("--build-dir", type=Path, required=True,
                   help="QEMU build dir containing qemu-<isa> and plugin")
    t.add_argument("--depth", type=int, default=64,
                   help="wrong-path depth (plugin option)")
    t.add_argument("--stop", type=int, default=200_000)
    t.add_argument("--regdata", action="store_true",
                   help="Enable per-insn register-value capture (regdata=1)")
    t.add_argument("--compress", choices=("none", "xz", "zstd", "gzip"),
                   default="none",
                   help="Compress each member inside the .cst tarball "
                        "(passes compress=<cmd> to the plugin). Output "
                        "file is always <out_base>.cst.")

    # analyze
    a = sub.add_parser("analyze",
                       help="Annotate metadata with ELF ground truth")
    common(a)
    a.add_argument("--isa", choices=ISA_CHOICES, required=True)

    # validate
    v = sub.add_parser("validate", help="Compare trace to metadata")
    common(v)
    v.add_argument("--isa", choices=ISA_CHOICES, required=True)
    v.add_argument("--depth", type=int, default=64,
                   help="plugin's WP instruction budget; must match "
                        "the value passed to `trace --depth`")

    # all
    al = sub.add_parser("all", help="generate+build+trace+analyze+validate")
    common(al)
    al.add_argument("--seed", type=_parse_seed, required=True)
    al.add_argument("--isa", choices=ISA_CHOICES, action="append",
                    required=True,
                    help="May be given multiple times.")
    al.add_argument("--build-dir", type=Path, required=True)
    al.add_argument("--diamonds", type=int, default=8)
    al.add_argument("--side-len-min", type=int, default=2)
    al.add_argument("--side-len-max", type=int, default=4)
    al.add_argument("--depth", type=int, default=64)
    al.add_argument("--stop", type=int, default=200_000)
    al.add_argument("--regdata", action="store_true",
                    help="Enable per-insn register-value capture (regdata=1)")
    al.add_argument("--iframe-rate", type=int, default=None,
                    help="Override the tracer's iframe_rate (default 100000)."
                         " Small values exercise the IFRAME-validation path.")
    al.add_argument("--start-symbol", type=str, default=None,
                    help="Use trace_window=symbol:name=...;simulation=<stop>"
                         " instead of the default icount-based window."
                         " Exercises the plugin's symbol-resolved start path.")
    al.add_argument("--coverage", action="store_true",
                    help="See `generate --coverage`.")
    al.add_argument("--hot-iters", type=int, default=0,
                    help="See `generate --hot-iters`.")
    al.add_argument("--stride-loops", action="store_true",
                    help="See `generate --stride-loops`.")
    al.add_argument("--compress", choices=("none", "xz", "zstd", "gzip"),
                    default="none", help="See `trace --compress`.")

    sp = sub.add_parser(
        "simpoint_test",
        help="End-to-end 2-segment simpoint test: validates per-segment"
             " decode independence")
    common(sp)
    sp.add_argument("--seed", type=_parse_seed, required=True)
    sp.add_argument("--isa", choices=ISA_CHOICES, action="append",
                    required=True)
    sp.add_argument("--build-dir", type=Path, required=True)
    sp.add_argument("--diamonds", type=int, default=4)
    sp.add_argument("--side-len-min", type=int, default=2)
    sp.add_argument("--side-len-max", type=int, default=3)
    sp.add_argument("--depth", type=int, default=64)
    sp.add_argument("--stop", type=int, default=40_000)
    sp.add_argument("--regdata", action="store_true")
    sp.add_argument("--hot-iters", type=int, default=5000,
                    help="Default is large so the program runs past the"
                         " second simpoint interval (typically icount > 4000).")
    sp.add_argument("--coverage", action="store_true")

    tt = sub.add_parser(
        "thread_test",
        help="End-to-end 2-thread test: parent+child run identical "
             "atomic-RMW loops, validator asserts both threads visible "
             "in the trace")
    common(tt)
    tt.add_argument("--isa", choices=ISA_CHOICES, action="append",
                    required=True)
    tt.add_argument("--build-dir", type=Path, required=True)
    tt.add_argument("--depth", type=int, default=64)
    tt.add_argument("--regdata", action="store_true")

    return p.parse_args()


# ---------------------------------------------------------------------------
# Path conventions
# ---------------------------------------------------------------------------

def _prog_base(out_dir: Path, prog: str | None) -> str:
    return prog or out_dir.name


def _src_path(out_dir: Path, prog: str) -> Path:
    return out_dir / f"{prog}.S"


def _meta_path(out_dir: Path, prog: str, isa: str) -> Path:
    return out_dir / f"{prog}_{isa}.meta.json"


def _bin_path(out_dir: Path, prog: str, isa: str) -> Path:
    return out_dir / f"{prog}_{isa}"


def _trace_base(out_dir: Path, prog: str, isa: str) -> Path:
    return out_dir / f"{prog}_{isa}"


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------

def cmd_generate(args, isa: str | None = None) -> None:
    isa = isa or args.isa
    prog = _prog_base(args.out_dir, args.prog)
    params = G.GenerateParams(
        seed=args.seed,
        isa=isa,
        num_diamonds=args.diamonds,
        side_len_min=args.side_len_min,
        side_len_max=args.side_len_max,
        coverage=getattr(args, "coverage", False),
        hot_iters=getattr(args, "hot_iters", 0),
        stride_loops=getattr(args, "stride_loops", False),
    )
    # Emit per-ISA metadata and a per-ISA assembly source.
    args.out_dir.mkdir(parents=True, exist_ok=True)
    cpp_name = f"{prog}_{isa}"
    cpp_path, meta_path = G.generate(params, args.out_dir, cpp_name)
    print(f"generate[{isa}]: {cpp_path.name}  {meta_path.name}")


def cmd_build(args, isa: str | None = None) -> int:
    isa = isa or args.isa
    prog = _prog_base(args.out_dir, args.prog)
    src = _src_path(args.out_dir, f"{prog}_{isa}")
    if not src.is_file():
        print(f"build[{isa}]: SKIP  source not found: {src}")
        return 0
    cc = ISA_COMPILER[isa]
    if not _have(cc):
        print(f"build[{isa}]: SKIP  {cc} not in PATH")
        return 0
    out = _bin_path(args.out_dir, prog, isa)
    cmd = [cc] + ISA_CFLAGS[isa] + [
        "-O1", "-fno-asynchronous-unwind-tables",
        "-fno-stack-protector",
        "-fno-optimize-sibling-calls",
        str(src), "-o", str(out),
    ]
    # 32-bit MIPS soft-float helpers (__floatdidf/__fixdfdi) live in
    # libgcc; -nostdlib doesn't exclude libgcc, but we still need to
    # link it explicitly because gcc's default driver glue is suppressed.
    if isa == "mipsel":
        cmd += ["-lgcc"]
    print(f"build[{isa}]: {' '.join(cmd)}")
    rc = subprocess.call(cmd)
    if rc != 0:
        print(f"build[{isa}]: FAIL rc={rc}")
    return rc


def cmd_trace(args, isa: str | None = None) -> int:
    isa = isa or args.isa
    prog = _prog_base(args.out_dir, args.prog)
    bin_path = _bin_path(args.out_dir, prog, isa)
    if not bin_path.is_file():
        print(f"trace[{isa}]: SKIP  binary not found: {bin_path}")
        return 0
    qemu = args.build_dir / ISA_QEMU[isa]
    plugin = args.build_dir / "contrib" / "plugins" / "libchampsim_tracer.so"
    if not qemu.is_file():
        print(f"trace[{isa}]: SKIP  qemu not found: {qemu}")
        return 0
    if not plugin.is_file():
        print(f"trace[{isa}]: SKIP  plugin not found: {plugin}")
        return 0

    out_base = _trace_base(args.out_dir, prog, isa)

    # Per-member compression inside the .cst tarball.  `compress=<cmd>`
    # tells the tracer to spawn that shell command for each member
    # (header.cst.<ext>, body.cst.<ext>); the outer container is always
    # a tar, so the on-disk path is always `<out_base>.cst`.
    compress = getattr(args, "compress", "none")
    compress_cmd = {
        "xz":   "xz -T0 -2 -c",
        "zstd": "zstd -T0 -3 -q -c",
        "gzip": "gzip -c",
    }

    # Plugin args (current ChampSim Tracer flag names, v1.11):
    #   - wpdepth=N            (was: depth=N)
    #   - trace_window=icount:start=0;stop=N  (was: stop=N)
    # The 'depth'/'stop' flat flags were dropped when the unified
    # trace_window= syntax landed; the validator must speak the new
    # vocabulary or the plugin refuses to load.
    start_sym = getattr(args, "start_symbol", None)
    if start_sym:
        # symbol-based start: tracer triggers on the first hit of
        # `name` and runs for `simulation` insns.  Note this puts a
        # non-zero start_insn into the trace header.
        window_opt = (f"trace_window=symbol:name={start_sym};"
                      f"simulation={args.stop}")
    else:
        window_opt = f"trace_window=icount:start=0;stop={args.stop}"
    plugin_opts = (
        f"outfile={out_base},"
        f"wpdepth={args.depth},{window_opt},memdata=1"
    )
    if compress != "none":
        cc = compress_cmd[compress]
        if "," in cc:
            raise SystemExit(
                "trace[--compress]: plugin arg parser uses ',' as a "
                "separator and the resolved compress= command contains "
                "a comma; wrap it in a script instead.")
        plugin_opts += f",compress={cc}"
    if getattr(args, "regdata", False):
        plugin_opts += ",regdata=1"
    if getattr(args, "iframe_rate", None) is not None:
        plugin_opts += f",iframe_rate={int(args.iframe_rate)}"
    cmd = [
        str(qemu), "-plugin", f"{plugin},{plugin_opts}", str(bin_path),
    ]
    print(f"trace[{isa}]: {' '.join(cmd)}")
    rc = subprocess.call(cmd)
    cst = Path(f"{out_base}.cst")
    if rc != 0 or not cst.is_file():
        print(f"trace[{isa}]: FAIL rc={rc}")
        return rc or 1
    print(f"trace[{isa}]: wrote {cst.name}")
    return 0


def cmd_analyze(args, isa: str | None = None) -> int:
    isa = isa or args.isa
    prog = _prog_base(args.out_dir, args.prog)
    bin_path = _bin_path(args.out_dir, prog, isa)
    meta = _meta_path(args.out_dir, prog, isa)
    if not bin_path.is_file() or not meta.is_file():
        print(f"analyze[{isa}]: SKIP  missing inputs")
        return 0
    A.analyze(bin_path, meta)
    print(f"analyze[{isa}]: annotated {meta.name}")
    return 0


def cmd_validate(args, isa: str | None = None) -> int:
    isa = isa or args.isa
    prog = _prog_base(args.out_dir, args.prog)
    bin_path = _bin_path(args.out_dir, prog, isa)
    meta = _meta_path(args.out_dir, prog, isa)
    trace = Path(f"{_trace_base(args.out_dir, prog, isa)}.cst")
    if not trace.is_file() or not meta.is_file():
        print(f"validate[{isa}]: SKIP  missing inputs "
              f"(trace={trace.is_file()}, meta={meta.is_file()})")
        return 0
    # Symbol-based start: validator can't know the exact icount the
    # symbol resolves to, so disable the strict header_window check.
    start_sym = getattr(args, "start_symbol", None)
    expected_start = None if start_sym else 0
    report = V.validate(meta, trace, bin_path,
                        wp_insn_budget=getattr(args, "depth", 64),
                        expected_start=expected_start,
                        expected_stop=getattr(args, "stop", None),
                        expected_warmup=0,
                        expected_threads=1,
                        start_symbol=start_sym)
    print(report.summary())
    return 1 if report.errors() else 0


def cmd_all(args) -> int:
    rc_total = 0
    for isa in args.isa:
        print(f"\n==== {isa} ====")
        cmd_generate(args, isa)
        if cmd_build(args, isa) != 0:
            rc_total = 1
            continue
        if cmd_trace(args, isa) != 0:
            rc_total = 1
            continue
        cmd_analyze(args, isa)
        if cmd_validate(args, isa) != 0:
            rc_total = 1
    return rc_total


def cmd_thread_test(args) -> int:
    """End-to-end multi-thread test.

    Builds a hand-written 2-thread program for the requested ISA
    (parent + child both run identical 1000-iteration atomic-RMW
    loops; parent spins on the kernel-cleared child-tid slot, then
    exit_groups), traces it, and validates that the resulting .cst
    captures both threads:

      * exactly 2 BODY_TAG_REGFILE records (one per thread),
      * at least one BODY_TAG_THREAD_SWITCH (the threads interleaved),
      * both thread_ids 0 and 1 contributed CP entries,
      * atomic_count / wp_events / iframe / encoding-map invariants pass.
    """
    from . import _thread_test_asm as TASM
    rc_total = 0
    for isa in args.isa:
        print(f"\n==== thread_test {isa} ====")
        if isa not in TASM.THREAD_TEST_ASM:
            print(f"thread_test[{isa}]: SKIP  no template available")
            continue

        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        s_path = out_dir / f"thread_test_{isa}.S"
        bin_path = out_dir / f"thread_test_{isa}"
        cst_path = out_dir / f"thread_test_{isa}.cst"
        s_path.write_text(TASM.THREAD_TEST_ASM[isa])

        cc_map = {
            "x86_64":  ["g++"],
            "aarch64": ["aarch64-linux-gnu-g++"],
            "riscv64": ["riscv64-linux-gnu-g++", "-march=rv64gc",
                        "-mabi=lp64d", "-mno-relax", "-Wl,--no-relax"],
            "mipsel":  ["mipsel-linux-gnu-g++", "-mno-abicalls",
                        "-fno-pic", "-e", "_start"],
        }[isa]
        build_cmd = cc_map + ["-static", "-nostdlib", "-nostartfiles",
                              str(s_path), "-o", str(bin_path)]
        print(f"build[{isa}]: {' '.join(build_cmd)}")
        rc = subprocess.call(build_cmd)
        if rc != 0:
            print(f"thread_test[{isa}]: build FAILED rc={rc}")
            rc_total = 1
            continue

        plugin = args.build_dir / "contrib" / "plugins" / "libchampsim_tracer.so"
        qemu = args.build_dir / f"qemu-{isa}"
        plugin_opts = f"outfile={bin_path},wpdepth={args.depth},memdata=1"
        if getattr(args, "regdata", False):
            plugin_opts += ",regdata=1"
        cmd = [str(qemu), "-plugin", f"{plugin},{plugin_opts}", str(bin_path)]
        print(f"trace[{isa}]: {' '.join(cmd)}")
        rc = subprocess.call(cmd)
        if rc != 0 or not cst_path.is_file():
            print(f"thread_test[{isa}]: trace FAILED rc={rc}")
            rc_total = 1
            continue

        print(f"validate[{isa}] {cst_path.name}:")
        report = V.validate_structural(cst_path, expected_threads=2)
        print(report.summary())
        if report.errors():
            rc_total = 1
    return rc_total


def cmd_simpoint_test(args) -> int:
    """End-to-end segmentation test.

    Generates a synthetic program with a long-running loop, writes a
    simpoint-selection file picking two intervals, traces them via
    `trace_window=simpoint:`, and validates each per-segment .cst file
    independently.  Each segment must be self-decodable: its header
    re-emits encoding maps and templates, its body starts with a
    REGFILE record, and the decoder reaches the trailer without
    leaking state from any other segment (we explicitly *do not*
    decode them in order — segment N is validated as if segment N-1
    never existed).
    """
    rc_total = 0
    for isa in args.isa:
        print(f"\n==== simpoint_test {isa} ====")
        cmd_generate(args, isa)
        if cmd_build(args, isa) != 0:
            rc_total = 1
            continue
        prog = _prog_base(args.out_dir, args.prog)
        bin_path = _bin_path(args.out_dir, prog, isa)
        out_base = _trace_base(args.out_dir, prog, isa)

        sp_file = Path(f"{out_base}.simpoints")
        sp_file.write_text("0 0\n2 1\n")

        plugin = args.build_dir / "contrib" / "plugins" / "libchampsim_tracer.so"
        qemu = args.build_dir / f"qemu-{isa}"
        interval = max(1000, args.stop // 4)
        simulation = max(200, args.stop // 16)
        plugin_opts = (
            f"outfile={out_base},"
            f"wpdepth={args.depth},"
            f"trace_window=simpoint:file={sp_file};"
            f"interval={interval};simulation={simulation},"
            f"memdata=1"
        )
        if getattr(args, "regdata", False):
            plugin_opts += ",regdata=1"
        cmd = [str(qemu), "-plugin", f"{plugin},{plugin_opts}", str(bin_path)]
        print(f"trace[{isa}]: {' '.join(cmd)}")
        rc = subprocess.call(cmd)
        if rc != 0:
            print(f"trace[{isa}]: FAIL rc={rc}")
            rc_total = 1
            continue

        # Per-simpoint files are named <base>-<positionB>.cst (the
        # simpoint position in billions of instructions), e.g.
        # mcf_x86_64-0B.cst, mcf_x86_64-0_000025B.cst — not the old
        # _sp<idx> ordinal.  The '-' separator distinguishes them
        # from the single-segment <base>.cst form.
        seg_files = sorted(Path(args.out_dir).glob(f"{prog}_{isa}-*.cst"))
        if len(seg_files) < 2:
            print(f"simpoint_test[{isa}]: FAIL  produced only "
                  f"{len(seg_files)} segment(s); expected 2 "
                  f"(program may not run long enough for "
                  f"interval={interval}; try --hot-iters)")
            rc_total = 1
            continue

        # Decode the segments standalone, in reverse order, deliberately
        # not in trace order — proves segment N is independently
        # decodable without state from any other segment.
        for seg in reversed(seg_files):
            print(f"validate[{isa}] segment {seg.name}:")
            report = V.validate_structural(seg, expected_threads=1)
            print(report.summary())
            if report.errors():
                rc_total = 1
    return rc_total


# ---------------------------------------------------------------------------

def main() -> int:
    args = _parse_args()
    if args.cmd == "generate":
        cmd_generate(args); return 0
    if args.cmd == "build":
        return cmd_build(args)
    if args.cmd == "trace":
        return cmd_trace(args)
    if args.cmd == "analyze":
        return cmd_analyze(args)
    if args.cmd == "validate":
        return cmd_validate(args)
    if args.cmd == "all":
        return cmd_all(args)
    if args.cmd == "simpoint_test":
        return cmd_simpoint_test(args)
    if args.cmd == "thread_test":
        return cmd_thread_test(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
