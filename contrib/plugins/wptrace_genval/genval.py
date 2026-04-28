#!/usr/bin/env python3
"""champsim_tracer_genval CLI.

Subcommands:
    generate   Build a seed-driven assembly source + metadata sidecar.
    build      Assemble/link the source for one or more ISAs.
  trace      Run the champsim_tracer plugin on a compiled binary.
  analyze    Disassemble the binary, annotate metadata with ground truth.
  validate   Compare the decoded trace to the metadata.
  all        Run every step above for the requested ISAs.

Example:
  ./genval.py all --seed 0x0102 -o out/prog01 \\
      --build-dir ../../../build --isa x86_64
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from genval import generator as G
from genval import analyzer as A
from genval import validator as V


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
    "mipsel":  ["-static", "-nostdlib", "-nostartfiles", "-e", "_start"],
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
                   help="Stream the .cst through a compressor via the "
                        "plugin's outpipe= option. Output file is "
                        "<out_base>.cst.<ext>.")
    t.add_argument("--outpipe", type=str, default=None,
                   help="Override --compress with a literal shell command "
                        "passed to outpipe=. Plugin args use ',' as a "
                        "separator so commas inside the command are not "
                        "supported.")

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
    al.add_argument("--coverage", action="store_true",
                    help="See `generate --coverage`.")
    al.add_argument("--hot-iters", type=int, default=0,
                    help="See `generate --hot-iters`.")
    al.add_argument("--compress", choices=("none", "xz", "zstd", "gzip"),
                    default="none", help="See `trace --compress`.")
    al.add_argument("--outpipe", type=str, default=None,
                    help="See `trace --outpipe`.")

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

    # Resolve output destination: explicit --outpipe wins, then --compress,
    # else default outfile= path.
    compress = getattr(args, "compress", "none")
    outpipe = getattr(args, "outpipe", None)
    compress_ext = {"xz": "xz", "zstd": "zst", "gzip": "gz"}
    compress_cmd = {
        "xz":   "xz -T0 -2 -c",
        "zstd": "zstd -T0 -3 -q -c",
        "gzip": "gzip -c",
    }
    if outpipe is None and compress != "none":
        ext = compress_ext[compress]
        outpipe = f"{compress_cmd[compress]} > {out_base}.cst.{ext}"

    if outpipe is not None:
        if "," in outpipe:
            raise SystemExit(
                "trace[--outpipe]: plugin arg parser uses ',' as a "
                "separator. Wrap your command in a script and reference "
                "it instead.")
        plugin_opts = (
            f"outpipe={outpipe},"
            f"depth={args.depth},stop={args.stop},memdata=1"
        )
    else:
        plugin_opts = (
            f"outfile={out_base},"
            f"depth={args.depth},stop={args.stop},memdata=1"
        )
    if getattr(args, "regdata", False):
        plugin_opts += ",regdata=1"
    cmd = [
        str(qemu), "-plugin", f"{plugin},{plugin_opts}", str(bin_path),
    ]
    print(f"trace[{isa}]: {' '.join(cmd)}")
    rc = subprocess.call(cmd)
    if outpipe is not None:
        if rc != 0:
            print(f"trace[{isa}]: FAIL rc={rc}")
            return rc
        print(f"trace[{isa}]: streamed via outpipe ({outpipe})")
        return 0
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
    report = V.validate(meta, trace, bin_path,
                        wp_insn_budget=getattr(args, "depth", 64))
    print(report.summary())
    return 1 if report.errors() else 0


def cmd_all(args) -> int:
    rc_total = 0
    skip_validate = (getattr(args, "compress", "none") != "none"
                     or getattr(args, "outpipe", None) is not None)
    for isa in args.isa:
        print(f"\n==== {isa} ====")
        cmd_generate(args, isa)
        if cmd_build(args, isa) != 0:
            rc_total = 1
            continue
        if cmd_trace(args, isa) != 0:
            rc_total = 1
            continue
        if skip_validate:
            print(f"validate[{isa}]: SKIP  (output is piped/compressed)")
            continue
        cmd_analyze(args, isa)
        if cmd_validate(args, isa) != 0:
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
    return 2


if __name__ == "__main__":
    sys.exit(main())
