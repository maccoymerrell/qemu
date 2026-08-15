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
from . import _system as SYS
from . import _full as FULL
from . import _lldet as LLDET
from . import _must0
from . import _stall_condition as STALL
from . import _plugin_load as PLUGLOAD


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
        # The system-mode guest runs on -cpu P5600, whose FCR31 resets with
        # ABS2008|NAN2008 set and read-only, so the CPU implements the IEEE
        # 754-2008 NaN encoding and nothing else.  Linux reads that back
        # from the FPU and rejects a legacy-NaN ELF with -ENOEXEC, so a
        # workload built without this flag cannot execute in the system
        # guest at all.  -mnan=2008 costs nothing here because these
        # binaries are -nostdlib: there is no libc to find a matching
        # multilib for (the mipsel-linux-gnu cross toolchain has none, and
        # ld refuses to link the two NaN ABIs together).
        #
        # This also moves USER mode onto P5600: qemu-user picks the CPU
        # model from the ELF, and linux-user/mips/target_elf.h maps
        # EF_MIPS_NAN2008 to "P5600" (everything else o32 lands on 24Kf).
        # That is deliberate -- one binary, one ABI, the same CPU under
        # qemu-mipsel and qemu-system-mipsel -- but it is a CPU change, so
        # P5600's wider feature set (MSA, EVA, XPA, the 2008 NaN encoding)
        # is now what user-mode mipsel cells trace.
        "-mnan=2008",
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

    def system_args(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--system", action="store_true",
                        help="Trace under qemu-system-<isa> (boot a guest with "
                             "the workload staged into an initramfs) instead of "
                             "qemu-user. Implies --marker. Runs on any ISA with "
                             "a boot shape (x86_64, aarch64, riscv64, mipsel). "
                             "Use --build-dir pointing at the softmmu build.")
        sp.add_argument("--attach", action="store_true",
                        help="System-mode: open the trace window by INJECTING "
                             "the marker instead of compiling it in. cst_attach "
                             "is cross-built for the guest ISA, staged as "
                             "/bin/cst_trace, and exec's the workload under "
                             "ptrace, poking the marker sequence into its entry "
                             "point -- the path an unmodified binary has to "
                             "take. The workload is generated WITHOUT a start "
                             "marker, so the injection is the only thing that "
                             "can open the window.")
        sp.add_argument("--kernel", type=Path, default=None,
                        help="System-mode kernel image (default: the local "
                             "systest vmlinuz).")
        sp.add_argument("--rootfs", type=Path, default=None,
                        help="System-mode base initramfs root dir to stage the "
                             "workload into (default: the local systest root).")
        sp.add_argument("--sys-mem", default="512M",
                        help="Guest RAM for system-mode (default: 512M).")
        sp.add_argument("--smp", type=int, default=1,
                        help="Guest vCPU count for system-mode (-smp N). "
                             "Body entries carry the GUEST-THREAD identity "
                             "as thread_id (stable across vCPU migration), "
                             "never the vCPU index; the validator asserts "
                             "the per-thread record cadence and one "
                             "well-formed chain per guest thread.")

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
    g.add_argument("--devio-probe", type=int, default=0,
                   help="Emit N write(1, ...) console writes right after the "
                        "in-window probes, so the traced process drives a "
                        "real device from inside its OWN kernel path.  The "
                        "seal walk's mid-flight-abandon case (an MMIO access "
                        "that is not its TB's last instruction) cannot occur "
                        "inside a marker window without it, and its counter "
                        "then reads zero from an instrument that never saw "
                        "its subject.  Off by default: it changes the "
                        "generated image.")
    g.add_argument("--marker", action="store_true",
                   help="Emit the trace marker at _start (x86_64) so the "
                        "plugin's trace_window=marker opens + ASID-pins the "
                        "window; lets one workload drive user and system mode.")

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
    t.add_argument("--wpprune", type=int, default=0, choices=(0, 1, 2),
                   help="wrong-path pruning level (plugin wpprune=N): 0 none, "
                        "1 drop WP for branches never seen taken / monomorphic "
                        "indirects, 2 also drop one-directional conditionals.")
    t.add_argument("--stop", type=int, default=200_000)
    t.add_argument("--tb-size", type=int, default=0,
                   help="QEMU code-cache size in MiB (passes -tb-size). "
                        "0 leaves QEMU's default. A small value (e.g. 1) "
                        "forces frequent tb_flush mid-trace, exercising the "
                        "flush-during-wrong-path reclamation path; only "
                        "bites on programs whose translation footprint "
                        "exceeds the cache (~700 synthetic BBs per MiB).")
    t.add_argument("--regdata", action="store_true",
                   help="Enable per-insn register-value capture (regdata=1)")
    t.add_argument("--compress", choices=("none", "xz", "zstd", "gzip"),
                   default="none",
                   help="Compress each member inside the .cst tarball "
                        "(passes compress=<cmd> to the plugin). Output "
                        "file is always <out_base>.cst.")
    system_args(t)

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
    system_args(v)

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
    al.add_argument("--wpprune", type=int, default=0, choices=(0, 1, 2),
                    help="wrong-path pruning level (plugin wpprune=N).")
    al.add_argument("--stop", type=int, default=200_000)
    al.add_argument("--simpoints", default=None,
                    help="SimPoint selections file.  In --system mode this "
                         "composes with the marker pin: the START marker "
                         "pins the address space, the schedule chooses the "
                         "intervals captured inside it.")
    al.add_argument("--sp-interval", type=int, default=100_000,
                    help="SimPoint interval length in user instructions.")
    al.add_argument("--sp-warmup", type=int, default=0,
                    help="User instructions of warmup before each simpoint.")
    al.add_argument("--tb-size", type=int, default=0,
                    help="QEMU code-cache size in MiB (passes -tb-size; "
                         "0 = QEMU default). Small values force tb_flush "
                         "mid-trace; see `trace --tb-size`.")
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
    al.add_argument("--devio-probe", type=int, default=0,
                    help="See `generate --devio-probe`.")
    al.add_argument("--marker", action="store_true",
                    help="See `generate --marker`.")
    al.add_argument("--compress", choices=("none", "xz", "zstd", "gzip"),
                    default="none", help="See `trace --compress`.")
    system_args(al)

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
             "in the trace.  With --system --smp 2 the clone pair runs "
             "inside a marker-pinned guest and thread_id is the "
             "guest-thread identity (stable across vCPU migration); "
             "--migrate --seeds K stresses SMP migration.")
    common(tt)
    tt.add_argument("--isa", choices=ISA_CHOICES, action="append",
                    required=True)
    tt.add_argument("--build-dir", type=Path, required=True)
    tt.add_argument("--depth", type=int, default=64)
    tt.add_argument("--regdata", action="store_true")
    tt.add_argument("--iters", type=int, default=None,
                    help="Per-thread loop iterations (default 1000; "
                         "system mode defaults to 300000 so both guest "
                         "threads stay runnable long enough for the "
                         "scheduler to spread them across vCPUs).")
    tt.add_argument("--stop", type=int, default=200_000,
                    help="System mode: marker-window user-insn budget.")
    tt.add_argument("--migrate", action="store_true",
                    help="System mode: SMP migration stress.  Adds a "
                         "periodic sched_yield to every ISA's RMW loop and "
                         "drops the mipsel CPU-0 affinity pin so the clone "
                         "pair spreads and migrates across the -smp vCPUs; "
                         "the tracer must keep one guest-thread tid per "
                         "thread through migration.  Use with --smp >1.")
    tt.add_argument("--migrate-churn", action="store_true",
                    help="System mode, mipsel: FORCE a cross-vCPU migration. "
                         "Implies --migrate but keeps the parent pinned to "
                         "CPU 0 (stable marker/pin) and makes the child bounce "
                         "between CPU 0 and CPU 1 via sched_setaffinity, so "
                         "ONE guest-thread tid is executed on two vCPUs. The "
                         "yield-only --migrate regime lets each thread settle "
                         "on its own vCPU (a balanced -smp 2 runqueue never "
                         "rebalances), so it reports ambiguous-split; this "
                         "forces the migration the decoupling proof needs. "
                         "Use with --smp 2.")
    tt.add_argument("--seeds", type=int, default=1,
                    help="Repeat the traced run this many times (varied "
                         "scheduling entropy) and require the guest-thread "
                         "invariants on every run; reports x/N.")
    system_args(tt)

    ct = sub.add_parser(
        "churn_test",
        help="Multi-process ASID-churn test (system mode): guest init "
             "burns through short-lived unmarked processes before and "
             "while the marked workload runs; asserts the pin followed "
             "only the marked process (every user template byte-matches "
             "the marked binary), coverage closed at budget, and "
             "audit/strict-lint stay clean.")
    common(ct)
    ct.add_argument("--seed", type=_parse_seed, required=True)
    ct.add_argument("--isa", choices=ISA_CHOICES, action="append",
                    required=True,
                    help="mipsel (8-bit ASIDs; churn forces a generation "
                         "rollover), x86_64, aarch64 or riscv64.  The test "
                         "body is ISA-generic; the guest-side churn is a "
                         "busybox shell loop.")
    ct.add_argument("--build-dir", type=Path, required=True)
    ct.add_argument("--diamonds", type=int, default=8)
    ct.add_argument("--side-len-min", type=int, default=2)
    ct.add_argument("--side-len-max", type=int, default=4)
    ct.add_argument("--depth", type=int, default=8,
                    help="Wrong-path depth; kept small — the test's "
                         "subject is the ASID pin, not WP coverage.")
    ct.add_argument("--stop", type=int, default=150_000,
                    help="Marker-window user-insn budget.  The workload "
                         "(scaled by --hot-iters) must run past it so "
                         "the window closes AT budget after the churn "
                         "overlap.")
    ct.add_argument("--hot-iters", type=int, default=2_000,
                    help="Loop iterations per diamond side; sized so the "
                         "workload's user-insn total exceeds --stop "
                         "while keeping the generator's CP walk within "
                         "its step cap.")
    ct.add_argument("--sleep-probe", type=int, default=40,
                    help="Seconds the marked workload nanosleeps right "
                         "after pinning (user clock frozen, window "
                         "open) so the in-flight churn can roll the "
                         "guest's ASID space before the workload's "
                         "user code runs.")
    ct.add_argument("--churn-pre", type=int, default=60,
                    help="Short-lived processes launched before the "
                         "marked workload starts.")
    ct.add_argument("--churn-during", type=int, default=300,
                    help="Short-lived processes launched while the "
                         "marked workload runs (each iteration forks a "
                         "subshell + execs /bin/true: two fresh mm's; "
                         "300 iterations comfortably roll MIPS's 8-bit "
                         "ASID space inside the sleep window).")
    system_args(ct)

    dl = sub.add_parser(
        "deadlatch_test",
        help="Dead-latch must-fire test (system mode): the marked "
             "workload is built WITHOUT its END marker, opens its window "
             "and exits — the run must then be ended by the "
             "latch_idle_insns dead latch, in BOTH inertness shapes: "
             "'storm' (a fork loop recycles the dead page-table root, so "
             "every stamp refresh is forged until the proof-of-life probe "
             "refuses it) and 'quiet' (no context switch ever happens, so "
             "only the retirement-driven sweep beat can run the sweep).  "
             "A run the latch does not close is killed by the watchdog "
             "and FAILS — this cell exists to prove the backstop fires.")
    common(dl)
    dl.add_argument("--seed", type=_parse_seed, required=True)
    dl.add_argument("--isa", choices=ISA_CHOICES, action="append",
                    required=True)
    dl.add_argument("--build-dir", type=Path, required=True)
    dl.add_argument("--diamonds", type=int, default=8)
    dl.add_argument("--side-len-min", type=int, default=2)
    dl.add_argument("--side-len-max", type=int, default=4)
    dl.add_argument("--depth", type=int, default=8,
                    help="Wrong-path depth; kept small — the test's "
                         "subject is the close, not WP coverage.")
    dl.add_argument("--stop", type=int, default=100_000_000_000,
                    help="Marker-window user-insn budget.  Deliberately "
                         "enormous: nothing but the dead latch may close "
                         "this window.")
    dl.add_argument("--hot-iters", type=int, default=2_000,
                    help="Loop iterations per diamond side, so the "
                         "workload retires enough user instructions for "
                         "the latch's refresh machinery to be exercised "
                         "while it is alive.")
    dl.add_argument("--latch-insns", type=int, default=3_000_000,
                    help="latch_idle_insns threshold for the run.")
    dl.add_argument("--shapes", default="storm,quiet",
                    help="Comma-separated subset of {storm,quiet}.")
    dl.add_argument("--compress", choices=["none", "xz", "zstd", "gzip"],
                    default="zstd",
                    help="Trace compression (the storm shape records the "
                         "guest until the latch threshold is spent).")
    system_args(dl)

    # full — the ONE unified entrypoint (tiers + coverage map + one code).
    FULL.add_parser(sub)

    # lldet_calibrate — remeasure the watchdog's healthy-throughput table.
    LLDET.add_parser(sub)

    # stall_scan — replay the labelled corpus behind the stall gate.
    STALL.add_parser(sub)

    # plugin_load — the plugin links AND loads (RTLD_NOW), not just links.
    PLUGLOAD.add_parser(sub)

    # mutation — adversarial strictness proof (see _mutation.py).
    from . import _mutation as MUT
    MUT.add_parser(sub)

    # range_cells — mid-block resume/stop acceptance harness (§4.2a).
    from . import _range_cells as RC
    RC.add_parser(sub)

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
        # System-mode tracing relies on the marker firing in the workload's
        # own address space, so --system implies --marker.
        marker=getattr(args, "marker", False) or getattr(args, "system", False),
        # --attach has cst_attach poke the start marker into the entry point
        # instead, so the image must not carry one: an injected run that
        # produced a trace anyway would prove nothing about the injector.
        start_marker=not getattr(args, "attach", False),
        # deadlatch_test builds the workload that opens its window and
        # exits without closing it (the latch's subject).
        end_marker=getattr(args, "end_marker", True),
        sleep_probe=getattr(args, "sleep_probe", 0),
        devio_probe=getattr(args, "devio_probe", 0),
    )
    # Emit per-ISA metadata and a per-ISA assembly source.
    args.out_dir.mkdir(parents=True, exist_ok=True)
    cpp_name = f"{prog}_{isa}"
    cpp_path, meta_path = G.generate(params, args.out_dir, cpp_name)
    print(f"generate[{isa}]: {cpp_path.name}  {meta_path.name}")


def cmd_build(args, isa: str | None = None) -> int:
    """Assemble/link the generated workload for @isa.  Returns 0 only when
    the binary exists afterwards.

    Neither "no source" nor "no compiler" is a success.  Both used to
    return 0, so `build --isa X` reported success while producing nothing:
    the caller that reads only the status was told the workload was built,
    and the next step failed on some unrelated symptom (or, for a caller
    that builds as its own step, did not fail at all).  A step that cannot
    do the thing it was asked to do fails, and names which of the two
    reasons it was."""
    isa = isa or args.isa
    prog = _prog_base(args.out_dir, args.prog)
    src = _src_path(args.out_dir, f"{prog}_{isa}")
    if not src.is_file():
        print(f"build[{isa}]: FAIL  source not found: {src} "
              f"(generate has to run first, and has to have succeeded)")
        return 1
    cc = ISA_COMPILER[isa]
    if not _have(cc):
        print(f"build[{isa}]: FAIL  {cc} not in PATH -- this host cannot "
              f"build a {isa} workload, so it cannot run a {isa} cell")
        return 1
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
    if not out.is_file():
        print(f"build[{isa}]: FAIL  the compiler exited 0 but produced no "
              f"{out} -- reporting the exit status alone would have passed "
              f"this")
        return 1
    return 0


def _optional_plugin_opts(args) -> str:
    """The compress/regdata/iframe_rate suffix shared by the user- and
    system-mode plugin option strings."""
    opts = ""
    compress = getattr(args, "compress", "none")
    if compress != "none":
        cc = {"xz": "xz -T0 -2 -c", "zstd": "zstd -T0 -3 -q -c",
              "gzip": "gzip -c"}[compress]
        if "," in cc:
            raise SystemExit("trace[--compress]: resolved compress= command "
                             "contains a comma (the plugin arg separator); "
                             "wrap it in a script instead.")
        opts += f",compress={cc}"
    if getattr(args, "regdata", False):
        opts += ",regdata=1"
    if getattr(args, "iframe_rate", None) is not None:
        opts += f",iframe_rate={int(args.iframe_rate)}"
    if getattr(args, "wpprune", 0):
        opts += f",wpprune={int(args.wpprune)}"
    extra = getattr(args, "_plugin_extra", "")
    if extra:
        opts += f",{extra}"
    return opts


# Exit code meaning "this run could not be performed, and that is a property
# of the HOST, not of the thing under test" -- an absent cross-compiler, a
# guest kernel/rootfs fixture that was never staged.  It is distinct from 0
# because a run that did not happen must never read as a run that passed:
# ``_full._cli_outcome`` maps it to SKIP, which the suite reports loudly.
#
# A missing BUILD PRODUCT is deliberately NOT this code.  If the build dir
# under test has no qemu-system-<isa>, the check cannot find its subject and
# fails -- that is the whole point of pointing it at that build dir.  This
# distinction is load-bearing: every one of these sites used to ``return 0``,
# so a system-tier check against a build that lacked its emulator traced
# nothing, validated nothing, and reported PASS in one second while still
# claiming its feature-coverage tags.
RC_SKIP = 77


def _trace_system(args, isa: str, bin_path: Path, plugin: Path,
                  out_base) -> int:
    """System-mode trace: boot qemu-system-<isa> with @bin_path staged into
    an initramfs.  The workload's compiled-in marker (generate --marker)
    opens and ASID-pins the trace window inside the guest — or, under
    --attach, the staged cst_attach injects that marker into the workload's
    entry point over ptrace, which is how an unmodified binary is traced."""
    if isa not in SYS.ISA_QEMU_SYSTEM:
        print(f"trace[{isa}]: SKIP  no system-mode boot shape for this ISA")
        return RC_SKIP
    qemu_sys = args.build_dir / SYS.ISA_QEMU_SYSTEM[isa]
    kernel = Path(getattr(args, "kernel", None) or SYS.default_kernel(isa))
    base_root = Path(getattr(args, "rootfs", None) or SYS.default_root(isa))
    # The emulator is a product of the build dir we were pointed at; its
    # absence means that build cannot answer the question this check asks.
    if not qemu_sys.exists():
        print(f"trace[{isa}]: FAIL  qemu-system not found: {qemu_sys}\n"
              f"trace[{isa}]:       the build dir under test does not provide "
              f"this ISA's system emulator, so this check has no subject; "
              f"rebuild with {isa}-softmmu in --target-list")
        return 1
    # Guest kernel/rootfs are staged host fixtures, not build products.
    for p, what in ((kernel, "kernel"), (base_root, "rootfs base")):
        if not p.exists():
            print(f"trace[{isa}]: SKIP  {what} not found: {p}")
            return RC_SKIP

    # The marker (at the workload's _start) opens + ASID-pins the window.
    #
    # With --simpoints, the window is the COMPOSITION the TODO here used to
    # defer: system-mode trace_window=simpoint IS a marker window with a
    # SimPoint schedule inside it (pinned_simpoint_mode).  The START marker
    # pins the address space and zeroes the user clock; the SimPoint offsets
    # then position the capture on that clock.  The count-set precondition
    # the TODO named is met -- the window counter excludes kernel and
    # wrong-ASID instructions, which is exactly what makes offsets derived
    # from a user-mode bbv run valid inside a full-system guest.
    sp_file = getattr(args, "simpoints", None)
    if sp_file:
        window_opt = (f"trace_window=simpoint:file={sp_file}"
                      f"+interval={getattr(args, 'sp_interval', 100000)}"
                      f"+warmup={getattr(args, 'sp_warmup', 0)}"
                      f"+simulation={args.stop}")
    else:
        window_opt = f"trace_window=marker:simulation={args.stop}"
    plugin_opts = (f"outfile={out_base},wpdepth={args.depth},"
                   f"{window_opt},memdata=1") + _optional_plugin_opts(args)

    stage_dir = args.out_dir / f"sysstage_{isa}"
    stage_dir.mkdir(parents=True, exist_ok=True)

    init_text = getattr(args, "_init_text", None)
    attach_bin = None
    if getattr(args, "attach", False):
        if init_text is not None:
            # Not an environment gap -- the caller asked for two things that
            # cannot both hold, which is a bug in the invocation.
            print(f"trace[{isa}]: FAIL  --attach and a custom guest init are "
                  f"mutually exclusive (the injector owns the workload's "
                  f"exec)")
            return 1
        attach_bin = SYS.build_cst_attach(isa, stage_dir)
        if attach_bin is None:
            print(f"trace[{isa}]: SKIP  --attach needs "
                  f"{SYS.ISA_ATTACH_CC.get(isa)} to cross-build the guest-side "
                  f"injector")
            return RC_SKIP
        init_text = SYS.default_init(attach=True)
        print(f"trace[{isa}] (system): injecting marker via "
              f"{attach_bin.name} -> /{SYS.ATTACH_GUEST_PATH}")

    initrd = SYS.stage_initramfs(base_root, bin_path, stage_dir,
                                 init_text=init_text,
                                 attach_bin=attach_bin)
    cmd = SYS.system_qemu_cmd(qemu_sys, kernel, initrd, plugin, plugin_opts,
                              mem=getattr(args, "sys_mem", "512M"), isa=isa,
                              smp=getattr(args, "smp", 1))
    print(f"trace[{isa}] (system): {' '.join(cmd)}")
    console = Path(f"{out_base}.console.log")
    # Third leg of the guest-clock progress gate: watch the user-instruction
    # clock while the guest runs.  A guest that has stopped taking interrupts
    # keeps executing (it spins in the kernel), so it never exits on its own;
    # without this the run only ends when some outer timeout fires.
    #
    # The lldet watchdog rides the same poll loop: a calibrated overall
    # deadline (from the window's user-insn budget and the measured healthy
    # throughput of this isa/system/smp/wp configuration) with condition
    # sampling at the threshold.  A simpoint-scheduled window has no single
    # stated budget, so it falls back to the per-mode ceiling.
    watch = None
    if LLDET.enabled():
        # A caller whose window budget is deliberately unreachable (the
        # deadlatch_test) sets _lldet_budget=None so the deadline falls
        # back to the per-mode ceiling instead of scaling with a budget
        # nothing will ever spend.
        watch = LLDET.watch_for(
            isa=isa, mode="system", smp=getattr(args, "smp", 1),
            wpdepth=args.depth,
            budget=getattr(args, "_lldet_budget",
                           None if sp_file else args.stop),
            growth_prefix=str(out_base), console_path=console,
            label=f"system trace {isa}")
    rc, stall = SYS.run_with_clock_watchdog(cmd, console, lldet=watch)
    if stall:
        print(f"trace[{isa}]: FAIL  {stall}")
        return 1
    # A GUEST THAT NEVER RAN THE WORKLOAD IS A FAILURE THAT MUST NAME
    # ITSELF.  With `panic=-1` and `-no-reboot`, a kernel that panics before
    # init execs makes qemu exit with status ZERO, so the return code alone
    # reports success for a run that measured nothing; the checks below then
    # fail on a downstream symptom ("no .cst") that says nothing about the
    # cause.  The guest's own console is the only witness, and it is read
    # here before any of it is believed.
    try:
        ctext = console.read_text(errors="replace")
    except OSError as e:
        print(f"trace[{isa}]: FAIL  the guest console log could not be read "
              f"({e}) — a check that cannot find its subject fails")
        return 1
    fatal = SYS.scan_guest_console(ctext)
    if fatal:
        print(f"trace[{isa}]: FAIL  the guest did not run the workload "
              f"(qemu exited rc={rc}):")
        for why in fatal:
            print(f"trace[{isa}]:       {why}")
        for line in ctext.splitlines()[-15:]:
            print(f"  {line}")
        return 1
    cst = Path(f"{out_base}.cst")
    if sp_file:
        # Simpoint mode never writes <out_base>.cst: each scheduled cluster
        # lands in <out_base>-simpoint_<N>.cst.  The user-mode simpoint path
        # below already checks the per-segment files; this is its system
        # twin.  Requiring the single-segment name here reported every
        # successful composition run as a failure.
        sp_csts = sorted(cst.parent.glob(f"{cst.stem}-simpoint_*.cst"))
        if rc != 0 or not sp_csts:
            print(f"trace[{isa}]: FAIL rc={rc}")
            try:
                for line in console.read_text().splitlines()[-15:]:
                    print(f"  {line}")
            except OSError:
                pass
            return rc or 1
        print(f"trace[{isa}]: wrote {' '.join(p.name for p in sp_csts)}")
        return 0
    if rc != 0 or not cst.is_file():
        print(f"trace[{isa}]: FAIL rc={rc}")
        try:
            for line in console.read_text().splitlines()[-15:]:
                print(f"  {line}")
        except OSError:
            pass
        return rc or 1
    print(f"trace[{isa}]: wrote {cst.name}")
    return 0


def _run_and_log(cmd: list[str], log_path: Path) -> int:
    """Run @cmd with guest console + plugin stderr captured to
    @log_path (system-mode qemu mixes both on stdio; the plugin's
    segment-coverage line is asserted from this log after the run).
    The log's tail is echoed on failure."""
    with open(log_path, "w") as f:
        rc = subprocess.call(cmd, stdout=f, stderr=subprocess.STDOUT)
    if rc != 0:
        try:
            tail = log_path.read_text().splitlines()[-15:]
            print(f"--- {log_path.name} (tail) ---")
            for line in tail:
                print(f"  {line}")
        except OSError:
            pass
    return rc


def _stats_log_for(console_log: Path) -> Path:
    """The plugin's stats sidecar for the cell whose console log is @console_log.

    The two are siblings of one ``outfile`` base.  The report line the stall
    gate reads is NOT in the console: ``qemu_plugin_outs`` goes through
    qemu_log, whose fd is already closed by the time plugin_exit runs on a
    guest-initiated exit, which is exactly why the plugin mirrors the report
    to ``<outfile>.stats.log``."""
    name = console_log.name
    base = name[:-len(".console.log")] if name.endswith(".console.log") \
        else console_log.stem
    return console_log.with_name(f"{base}.stats.log")


def _check_segment_coverage(console_log: Path, require_ok: bool = False,
                            label: str = "", smp: int = 1,
                            workload: str = "", system: bool = False) -> int:
    """Assert the plugin's per-segment coverage line from the captured
    console log: ``finished segment [...] user_covered=C user_budget=B
    ... FLAG``.  UNDER means the window closed before its budget for a
    reason other than the end marker — always an error.  @require_ok
    additionally rejects END closes (the workload must have run past
    its budget, so kernel/excursion instructions charged to the user
    clock would surface as covered != budget).  Returns 0 on pass.

    @workload names the cell's workload for the stall-condition leg, which
    does not gate the shapes whose traced process is legitimately off-CPU
    (see ``_stall_condition.OFF_CPU_WORKLOADS``); the label alone carries only
    the ISA at most call sites."""
    try:
        text = console_log.read_text()
    except OSError:
        print(f"coverage[{label}]: FAIL  console log missing: {console_log}")
        return 1
    # Did the guest actually online the vCPUs this cell asked for?  Checked
    # before the coverage lines because an smp>1 cell that came up with one
    # CPU tests no concurrency at all, yet every downstream check still
    # passes -- the reading this gate exists to prevent.
    rc_cpus = 0
    for msg in SYS.assess_online_cpus(text, smp, label=label):
        print(f"smp: {msg}  FAIL")
        rc_cpus = 1
    # Was the capture taken in the canonical KPTI-off configuration?  Asked
    # here for the same reason as the vCPU count: every downstream check
    # passes on a KPTI-on capture, and the wire it produced does not mean
    # what the consumer will read it to mean.
    for msg in SYS.assess_kpti(text, label=label):
        print(f"kpti: {msg}  FAIL")
        rc_cpus = 1
    segs = SYS.parse_finished_segments(text)
    if not segs:
        print(f"coverage[{label}]: FAIL  no 'finished segment' line in "
              f"{console_log.name} (plugin never closed a window)")
        return 1
    rc = rc_cpus
    for s in segs:
        ratio = (s["trace_arch_insns"] / s["covered"]) if s["covered"] else 0.0
        line = (f"coverage[{label}]: covered={s['covered']} "
                f"budget={s['budget']} flag={s['flag']} "
                f"arch/user={ratio:.2f} (user_clock={s['user_clock']})")
        # THE CLOCK AND THE WIRE MUST AGREE, EXACTLY.
        #
        # clock_minus_wire is (user instructions the window clock billed) -
        # (user instructions emitted).  Positive means the trace is SHORT of
        # what the guest ran -- instructions were dropped.  Negative means
        # the wire claims instructions the guest never executed.  Neither is
        # ever acceptable, at any rate, and the plugin has published the
        # number on every segment line since 5e5d963255 while nothing read
        # it.  Checked here so every system cell carries the check for free
        # rather than each harness recomputing it.
        #
        # Only asserted when the field is present: a trace captured by a
        # plugin that predates the field is not a cell that silently passes,
        # it is a cell this leg has no subject in, and it says so.
        if "clock_minus_wire" in s:
            if s["clock_minus_wire"] != 0:
                print(f"coverage[{label}]: FAIL  clock_minus_wire="
                      f"{s['clock_minus_wire']} -- the window clock and the "
                      f"wire disagree by "
                      f"{abs(s['clock_minus_wire'])} user instruction(s) "
                      f"({'the trace is short of what ran' if s['clock_minus_wire'] > 0 else 'the wire claims instructions that never ran'})")
                rc = 1
        else:
            print(f"coverage[{label}]: note  no clock_minus_wire= on the "
                  f"segment line -- the clock-vs-wire leg has no subject in "
                  f"this trace and did not run")
        if s["flag"] in SYS.TRUNCATING_CLOSE_FLAGS:
            print(f"{line}  FAIL (window closed {s['flag']}: "
                  f"{SYS.TRUNCATING_CLOSE_FLAGS[s['flag']]})")
            rc = 1
        elif require_ok and s["flag"] != "OK":
            print(f"{line}  FAIL (expected the window to close at "
                  f"budget, not at workload end)")
            rc = 1
        else:
            print(f"{line}  ok")
    # Guest-clock progress gate.  A guest that stops taking interrupts spins
    # in the kernel: the window closes UNDER and the traced/user instruction
    # ratio explodes.  The UNDER leg overlaps the check above; the ratio leg
    # also catches the milder form where the window still closes but the
    # guest spent nearly all of it in a kernel spin.
    for msg in SYS.assess_clock_progress(segs, label=label):
        print(f"clock: {msg}  FAIL")
        rc = 1
    # Workload-progress stall condition (_stall_condition.py).  The ratio leg
    # above is gated off below CLOCK_INFLATION_MIN_COVERED user instructions,
    # where fixed per-segment cost dominates the ratio; this leg has no
    # coverage floor because its score is normalised by the segment's own
    # retired count, so it is what covers the sub-floor regime the ratio leg
    # cannot judge -- and that regime is where the escaped x86 marker cells
    # live (854-857 covered, ratios to 8197).
    #
    # @system says the cell ran under qemu-system-<isa>, and it is what makes
    # "no guest clock" a failure rather than a fact.  Under qemu-user there is
    # no guest clock to read, so the plugin prints factor=n/a by design; a gate
    # that reads that as "a system cell that closed a window produced no
    # readable segment" convicts every user-mode cell of the defect it exists
    # to find.  simpoint_test is the one that showed it -- a user-mode battery
    # whose fourteen content checks all report errors=0, failed by this leg.
    if system:
        verdict = STALL.assess(_stats_log_for(console_log), label=label,
                               workload=workload or label)
        for line in verdict.lines:
            print(line)
        if not verdict.ok:
            rc = 1
    return rc


def cmd_trace(args, isa: str | None = None) -> int:
    isa = isa or args.isa
    prog = _prog_base(args.out_dir, args.prog)
    bin_path = _bin_path(args.out_dir, prog, isa)
    # The workload binary and the plugin are both products of steps that
    # already reported success (cmd_build, and the build dir under test).
    # Their absence here is a broken run, not an unavailable environment.
    if not bin_path.is_file():
        print(f"trace[{isa}]: FAIL  binary not found: {bin_path}")
        return 1
    plugin = args.build_dir / "contrib" / "plugins" / "libchampsim_tracer.so"
    if not plugin.is_file():
        print(f"trace[{isa}]: FAIL  plugin not found: {plugin}")
        return 1
    # THE PLUGIN LINKS IS NOT THE PLUGIN LOADS.  Two commits on this branch
    # ship an object with an undefined internal symbol; QEMU opens plugins
    # RTLD_NOW, so they die at load and every cell downstream fails on some
    # unrelated symptom.  Asserted here (memoised: tens of ms, once per
    # build) so the failure names itself before anything is run.
    load_ok, load_lines = PLUGLOAD.check_once(args.build_dir, label=isa)
    for line in load_lines:
        print(line)
    if not load_ok:
        return 1

    out_base = _trace_base(args.out_dir, prog, isa)

    if getattr(args, "system", False):
        return _trace_system(args, isa, bin_path, plugin, out_base)

    qemu = args.build_dir / ISA_QEMU[isa]
    if not qemu.is_file():
        print(f"trace[{isa}]: FAIL  qemu not found: {qemu}\n"
              f"trace[{isa}]:       the build dir under test does not provide "
              f"this ISA's user-mode emulator, so this check has no subject; "
              f"rebuild with {isa}-linux-user in --target-list")
        return 1

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
    ) + _optional_plugin_opts(args)
    cmd = [str(qemu)]
    tb_size = getattr(args, "tb_size", 0)
    if tb_size:
        # Shrink the TCG code cache so the program's translation
        # footprint overflows it, forcing tb_flush mid-trace.  This is
        # what exercises the flush-during-wrong-path template reclamation
        # path; on a small program (footprint < cache) it is a no-op.
        cmd += ["-tb-size", str(int(tb_size))]
    cmd += ["-plugin", f"{plugin},{plugin_opts}", str(bin_path)]
    print(f"trace[{isa}]: {' '.join(cmd)}")
    # Calibrated watchdog in place of a flat (or absent) timeout: the
    # icount window's stop is the cell's stated instruction budget; a
    # symbol window traces to workload exit, which has no stated budget
    # and falls back to the per-mode ceiling.
    rc = LLDET.call_watched(
        cmd, isa=isa, mode="user", wpdepth=args.depth,
        budget=None if start_sym else args.stop,
        growth_prefix=str(out_base), label=f"user trace {isa}")
    cst = Path(f"{out_base}.cst")
    if rc != 0 or not cst.is_file():
        print(f"trace[{isa}]: FAIL rc={rc}"
              + (" (killed by the lldet watchdog; see the [lldet] VERDICT "
                 f"above and {out_base}.lldet)" if rc == LLDET.LLDET_EXIT
                 else ""))
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
        # Reached only when tracing reported success, so the inputs are
        # supposed to exist.  Validating nothing is not validating.
        print(f"validate[{isa}]: FAIL  missing inputs "
              f"(trace={trace.is_file()}, meta={meta.is_file()})")
        return 1
    # Symbol-based start, or system-mode marker: validator can't know the
    # exact icount the trigger resolves to, so disable the strict
    # header_window start check (the window's total budget is in user
    # instructions in marker mode, so the raw-icount total is skipped too).
    start_sym = getattr(args, "start_symbol", None)
    marker = getattr(args, "system", False)
    expected_start = None if (start_sym or marker) else 0
    report = V.validate(meta, trace, bin_path,
                        wp_insn_budget=getattr(args, "depth", 64),
                        expected_start=expected_start,
                        expected_stop=None if marker else getattr(args, "stop", None),
                        expected_warmup=0,
                        expected_threads=1,
                        start_symbol=start_sym,
                        marker=marker)
    print(report.summary())
    rc = 1 if report.errors() else 0
    if marker:
        # System-mode runs capture the guest console; the plugin's
        # segment-close line must not report an under-budget close.
        console = Path(f"{_trace_base(args.out_dir, prog, isa)}.console.log")
        if console.is_file() and _check_segment_coverage(
                console, label=isa, smp=getattr(args, "smp", 1),
                system=bool(getattr(args, "system", False))):
            rc = 1
    return rc


def cmd_all(args) -> int:
    rc_total = 0
    skipped = False
    # Every trace base this run produced, for the "(must be 0)" census below.
    # Collected even for an ISA whose validate failed: a broken cell's
    # invariants are exactly the ones worth reading.
    traced_bases: list[Path] = []
    for isa in args.isa:
        print(f"\n==== {isa} ====")
        cmd_generate(args, isa)
        if cmd_build(args, isa) != 0:
            rc_total = 1
            continue
        rc_trace = cmd_trace(args, isa)
        # RC_SKIP means the host could not host this run at all.  Carry it
        # through as a skip rather than letting the downstream analyze/
        # validate steps "succeed" on absent inputs -- that laundering is
        # exactly how a check with no trace reported PASS.
        if rc_trace == RC_SKIP:
            skipped = True
            continue
        if rc_trace != 0:
            rc_total = 1
            continue
        traced_bases.append(_trace_base(args.out_dir,
                                        _prog_base(args.out_dir, args.prog),
                                        isa))
        # System-mode traces interleave the pinned process's kernel calls,
        # which carry CST_INSN_FLAG_SYSTEM and have no workload ground truth.
        # analyze maps only the user blocks (kernel PCs aren't in the binary,
        # so they get no ground-truth spans); validate aligns the user
        # subsequence against correct_path and structurally checks the
        # syscall->kernel->user transitions.
        cmd_analyze(args, isa)
        if cmd_validate(args, isa) != 0:
            rc_total = 1
    # THE "(must be 0)" CENSUS.  Every counter the plugin labels "(must be 0)"
    # is an invariant it asserts about the very trace this run just produced,
    # and until now nothing on this path read one: the riscv64 seal-walk fold
    # over-claim sat at 1 (41 instructions) in 9 system cells that were all
    # scored PASS, because the only census in the suite lived in run_full and
    # the waves ran `all`.  It gates here, generically, on whatever rows the
    # plugin emits — never on a hand-kept list, which would go stale the next
    # time a counter is added.
    if traced_bases and _must0.gate_out_bases(traced_bases, "all"):
        rc_total = 1
    # A real failure outranks a skip; a skip outranks silent success.
    if rc_total:
        return rc_total
    return RC_SKIP if skipped else 0


import re as _re

_TIDDIAG_BIND_RE = _re.compile(r"\[tiddiag\] binding vcpu=(\d+) tid=(\d+)")


def _parse_tiddiag_bindings(console_log: Path) -> dict:
    """Parse the plugin's CST_TIDDIAG ``binding vcpu=V tid=T`` lines from
    a system run's console log into the bipartite vCPU<->tid graph.

    A tid on >= 2 vCPUs proves the guest thread MIGRATED yet kept one
    identity; a vCPU hosting >= 2 tids proves two threads TIME-SLICED it
    yet stayed distinct.  Either witnesses that the wire's thread_id is
    the guest thread, not the vCPU (which the wire never carries)."""
    vcpus_of_tid: dict[int, set[int]] = {}
    tids_of_vcpu: dict[int, set[int]] = {}
    pairs: set[tuple[int, int]] = set()
    tids: set[int] = set()
    try:
        text = console_log.read_text(errors="replace")
    except OSError:
        text = ""
    for m in _TIDDIAG_BIND_RE.finditer(text):
        v, t = int(m.group(1)), int(m.group(2))
        vcpus_of_tid.setdefault(t, set()).add(v)
        tids_of_vcpu.setdefault(v, set()).add(t)
        pairs.add((v, t))
        tids.add(t)
    return {"tids": tids, "vcpus_of_tid": vcpus_of_tid,
            "tids_of_vcpu": tids_of_vcpu, "pairs": pairs}


_THREAD_TEST_CC = {
    "x86_64":  ["g++"],
    "aarch64": ["aarch64-linux-gnu-g++"],
    "riscv64": ["riscv64-linux-gnu-g++", "-march=rv64gc",
                "-mabi=lp64d", "-mno-relax", "-Wl,--no-relax"],
    # -mnan=2008 for the same reason as ISA_CFLAGS: the system guest boots
    # on a 2008-NaN-only CPU and will not exec a legacy-NaN ELF.
    "mipsel":  ["mipsel-linux-gnu-g++", "-mno-abicalls",
                "-fno-pic", "-e", "_start", "-mnan=2008"],
}


def cmd_thread_test(args) -> int:
    """End-to-end multi-thread test.

    Builds a hand-written 2-thread program for the requested ISA
    (parent + child both run identical atomic-RMW loops; parent spins
    on the kernel-cleared child-tid slot, then exit_groups), traces it,
    and validates that the resulting .cst captures both threads:

      * one BODY_TAG_REGFILE per contributing thread, positioned
        before that thread's first entry,
      * BODY_TAG_THREAD_SWITCH records exactly at the tid changes,
      * both threads' user entries decomposing into 2 valid
        control-flow chains (thread_chain),
      * atomic_count / wp_events / iframe / encoding-map invariants.

    Default mode traces under qemu-user (thread_id = host thread,
    deterministically 0 and 1).  With ``--system --smp N`` the same
    clone pair runs marker-pinned inside a booted guest.  thread_id is
    then the GUEST-THREAD identity (the tracer resolves it from the
    kernel per-thread pointer, not the vCPU), so the assertion is
    strong and vCPU-independent: exactly two tids, each a well-formed
    per-thread control-flow chain, no matter how the scheduler placed or
    migrated the pair.  ``--migrate`` turns it into an SMP migration
    stress (distinct per-thread pointers + yields + no affinity pin) and
    ``--seeds N`` repeats it under varied scheduling entropy; the run set
    must also DEMONSTRATE decoupling — a tid that spanned vCPUs
    (migration) or two tids that shared a vCPU (time-slice) — proving the
    tid is the guest thread and not the vCPU index.
    """
    from ._thread_test_asm import thread_test_asm
    system = getattr(args, "system", False)
    # Migration mode (system only): distinct per-thread pointers + periodic
    # sched_yield on every ISA + no mipsel affinity confinement, so the
    # clone pair spreads/migrates across the -smp vCPUs.  The tracer must
    # keep ONE guest-thread tid per thread through migration and time-slice.
    churn = system and getattr(args, "migrate_churn", False)
    migrate = (system and getattr(args, "migrate", False)) or churn
    iters = args.iters if args.iters is not None else \
        (300_000 if system else 1000)
    rc_total = 0
    for isa in args.isa:
        print(f"\n==== thread_test {isa}"
              f"{' (system)' if system else ''} ====")
        out_dir = Path(args.out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        suffix = "_sys" if system else ""
        s_path = out_dir / f"thread_test{suffix}_{isa}.S"
        bin_path = out_dir / f"thread_test{suffix}_{isa}"
        cst_path = out_dir / f"thread_test{suffix}_{isa}.cst"
        try:
            s_path.write_text(thread_test_asm(isa, marker=system,
                                              iters=iters,
                                              migrate=migrate,
                                              affinity_churn=churn))
        except KeyError:
            print(f"thread_test[{isa}]: SKIP  no template available")
            continue

        build_cmd = _THREAD_TEST_CC[isa] + [
            "-static", "-nostdlib", "-nostartfiles",
            str(s_path), "-o", str(bin_path)]
        print(f"build[{isa}]: {' '.join(build_cmd)}")
        rc = subprocess.call(build_cmd)
        if rc != 0:
            print(f"thread_test[{isa}]: build FAILED rc={rc}")
            rc_total = 1
            continue

        plugin = args.build_dir / "contrib" / "plugins" / "libchampsim_tracer.so"
        if not system:
            # ---- qemu-user: single run, thread_id = host thread (0, 1) ----
            qemu = args.build_dir / f"qemu-{isa}"
            plugin_opts = f"outfile={bin_path},wpdepth={args.depth},memdata=1"
            if getattr(args, "regdata", False):
                plugin_opts += ",regdata=1"
            cmd = [str(qemu), "-plugin", f"{plugin},{plugin_opts}",
                   str(bin_path)]
            print(f"trace[{isa}]: {' '.join(cmd)}")
            # The pair runs to exit (no stated instruction budget), so the
            # watchdog uses the per-mode ceiling instead of a calibrated
            # budget-derived deadline.
            rc = LLDET.call_watched(
                cmd, isa=isa, mode="user", wpdepth=args.depth, budget=None,
                growth_prefix=str(bin_path),
                label=f"thread_test {isa} (user)")
            if rc != 0 or not cst_path.is_file():
                print(f"thread_test[{isa}]: trace FAILED rc={rc}")
                rc_total = 1
                continue
            report = V.validate_structural(cst_path, expected_threads=2,
                                           expected_guest_threads=2)
            print(report.summary())
            if report.errors():
                rc_total = 1
            continue

        # ---- system: N seeded runs, guest-thread-identity assertions ----
        # The bindings the decoupling proof reads are stderr-only diag;
        # enable them for the pinned qemu-system child (they never touch
        # the wire).
        os.environ["CST_TIDDIAG"] = "1"
        seeds = max(1, getattr(args, "seeds", 1))
        console = Path(f"{bin_path}.console.log")
        passed = mig_runs = ts_runs = split_runs = decoupled_runs = 0
        for seed in range(seeds):
            rc = _trace_system(args, isa, bin_path, plugin, bin_path)
            if rc != 0:
                print(f"thread_test[{isa}] seed {seed + 1}/{seeds}: "
                      f"trace FAILED rc={rc}")
                continue
            report = V.validate_structural(
                cst_path, expected_threads=2,
                expected_guest_threads=2, marker=True,
                expect_migration=churn)
            chains = next((int((i.detail or {}).get("chains", 0))
                           for i in report.issues
                           if i.check == "thread_chain"
                           and i.severity == "info"), 0)
            run_ok = (not report.errors()) and chains == 2
            if _check_segment_coverage(console, label=isa,
                                       smp=getattr(args, "smp", 1),
                                       workload="thread_test",
                                       system=bool(getattr(args, "system",
                                                           False))):
                run_ok = False
            # Decoupling evidence from the vCPU<->tid bindings (diag).
            # thread_id == vCPU index would force every binding to be
            # (v, v): one tid per vCPU, equal to it.  ANY deviation
            # disproves that hypothesis — a tid seen on two vCPUs
            # (migration), a vCPU hosting two tids (time-slice), or simply
            # a binding whose tid differs from its vCPU index (the
            # first-sighting identity landed a thread on a non-matching
            # vCPU).  Only an all-(v, v) run is ambiguous.
            note = ""
            if migrate:
                b = _parse_tiddiag_bindings(console)
                migrated = any(len(v) >= 2
                               for v in b["vcpus_of_tid"].values())
                timesliced = any(len(t) >= 2
                                 for t in b["tids_of_vcpu"].values())
                inverted = any(v != t for (v, t) in b["pairs"])
                decoupled = migrated or timesliced or inverted
                mig_runs += int(migrated)
                ts_runs += int(timesliced)
                decoupled_runs += int(decoupled)
                split_runs += int(not decoupled)
                note = (f"  [migration={int(migrated)} "
                        f"time-slice={int(timesliced)} "
                        f"tid!=vcpu={int(inverted)} "
                        f"tids={sorted(b['tids'])}]")
            passed += int(run_ok)
            if not run_ok:
                for i in report.errors()[:4]:
                    print(f"    [{i.check}] {i.message}")
            print(f"thread_test[{isa}] seed {seed + 1}/{seeds}: "
                  f"{'PASS' if run_ok else 'FAIL'} chains={chains}{note}")

        print(f"thread_test[{isa}]: {passed}/{seeds} runs passed the "
              f"guest-thread-identity assertion (exactly 2 tids, 2 "
              f"well-formed per-thread chains, vCPU absent from the wire)")
        if passed < seeds:
            rc_total = 1
        if migrate:
            print(f"thread_test[{isa}]: decoupling over {seeds} run(s) — "
                  f"decoupled={decoupled_runs} (migration={mig_runs}, "
                  f"time-slice={ts_runs}), ambiguous-split={split_runs}")
            # The whole point: the run set must witness the tid decoupled
            # from the vCPU at least once (else an all-(vcpu==tid) split
            # would pass without ever distinguishing the identity).
            if decoupled_runs == 0:
                print(f"thread_test[{isa}]: FAIL  no run distinguished the "
                      f"guest-thread tid from the vCPU index (every "
                      f"binding was tid==vcpu)")
                rc_total = 1
    return rc_total


def cmd_churn_test(args) -> int:
    """Multi-process ASID-churn test (system mode).

    The guest's init launches a stream of short-lived unmarked
    processes before and while the marked workload runs (see
    ``_system.churn_init``); on MIPS the churn rolls the 8-bit ASID
    space over, forcing the guest kernel to reassign the pinned ASID
    value to foreign processes while the trace window is open.  The
    pin must follow only the marked process:

      * every user-privilege template the CP stream executed must
        byte-match the marked binary's ELF image (foreign user code
        leaking past the pin cannot byte-match the -nostdlib workload),
      * the user entries form one control-flow chain (thread_chain),
      * the window closes AT its budget on the user clock
        (user_covered == budget, OK flag) — the workload outlives the
        budget by construction (--hot-iters),
      * the ASID-name census is readable and the guest actually switched
        contexts inside the open window (``kexc ASID-write events`` > 0) —
        without that the pin was never under test and a pass is vacuous,
      * cst_audit and cst_decode --strict stay clean.
    """
    args.system = True
    rc_total = 0
    for isa in args.isa:
        print(f"\n==== churn_test {isa} ====")
        cmd_generate(args, isa)
        if cmd_build(args, isa) != 0:
            rc_total = 1
            continue
        prog = _prog_base(args.out_dir, args.prog)
        bin_path = _bin_path(args.out_dir, prog, isa)
        out_base = _trace_base(args.out_dir, prog, isa)
        plugin = args.build_dir / "contrib" / "plugins" / "libchampsim_tracer.so"

        args._init_text = SYS.churn_init(args.churn_pre, args.churn_during)
        try:
            rc = _trace_system(args, isa, bin_path, plugin, out_base)
        finally:
            args._init_text = None
        if rc != 0:
            rc_total = 1
            continue
        cst = Path(f"{out_base}.cst")

        # Guest-side churn actually happened: init echoes its phases.
        # The plugin exits qemu the moment the window closes at budget,
        # so the *completion* echo of the in-flight churn is usually
        # cut off — its start echo plus the kernel-side scheduling
        # signature (kexc ASID-write events in the stats log) are the
        # evidence that churn overlapped the open window.
        console = Path(f"{out_base}.console.log")
        ctext = console.read_text() if console.exists() else ""
        for tag in ("pre-workload churn done", "in-flight churn started"):
            if tag not in ctext:
                print(f"churn_test[{isa}]: FAIL  guest init never "
                      f"reported '{tag}' (churn did not run)")
                rc_total = 1
        if "in-flight churn done" in ctext:
            print(f"churn_test[{isa}]: in-flight churn completed before "
                  f"the window closed")

        print(f"validate[{isa}] {cst.name}:")
        dec = V._load_decoder()
        # Streaming: one pass keeping only a small set of thread ids.
        # Materialising every entry to build that set is what exhausts
        # memory on a large trace.
        _meta, _templates, entries = dec.iter_decode_champsim_tracer(cst)
        observed = sorted({int(e.get("thread_id", 0)) for e in entries})
        report = V.validate_structural(
            cst, expected_threads=max(1, len(observed)),
            expected_guest_threads=1, marker=True,
            pinned_binary=bin_path)
        print(report.summary())
        if report.errors():
            rc_total = 1

        if _check_segment_coverage(console, require_ok=True, label=isa,
                                   smp=getattr(args, "smp", 1),
                                   workload="churn",
                                   system=bool(getattr(args, "system",
                                                       False))):
            rc_total = 1

        stats_log = Path(f"{out_base}.stats.log")
        stats_text = stats_log.read_text() if stats_log.is_file() else ""
        names, owned_names = SYS.parse_pin_asid_names(stats_text)
        kexc_writes = SYS.parse_kexc_asid_writes(stats_text)
        if names is None or owned_names is None or kexc_writes is None:
            print(f"churn_test[{isa}]: FAIL  {stats_log.name} carries no "
                  f"ASID-name census ('distinct raw ASID names ...' / "
                  f"'kexc ASID-write events') -- the churn evidence cannot "
                  f"be read, so this cell is not adjudicated")
            rc_total = 1
        else:
            print(f"churn_test[{isa}]: asid_names_since_pin={names} "
                  f"owned_space_names={owned_names} "
                  f"kexc_asid_writes={kexc_writes} "
                  f"(detector report; content checks above are the gate)")
            # The churn must have reached the kernel while the window was
            # open.  Every guest context switch writes the ASID register,
            # so zero of them means no other process was scheduled and the
            # cell tested nothing -- a pass here would be vacuous.
            if kexc_writes == 0:
                print(f"churn_test[{isa}]: FAIL  no ASID writes while the "
                      f"pinned window was open -- no foreign process was "
                      f"scheduled, so the pin was never under test")
                rc_total = 1

        for tool, extra in (("cst_audit", []), ("cst_decode", ["--strict"])):
            tool_path = args.build_dir / "contrib" / "plugins" / tool
            cmd = [str(tool_path)] + extra + [str(cst)]
            res = subprocess.run(cmd, capture_output=True, text=True)
            name = " ".join([tool] + extra)
            print(f"churn_test[{isa}]: {name} rc={res.returncode}")
            if res.returncode != 0:
                for line in (res.stderr or res.stdout).splitlines()[-10:]:
                    print(f"  {line}")
                rc_total = 1
    return rc_total


def cmd_deadlatch_test(args) -> int:
    """Dead-latch must-fire test (system mode).

    The marked workload is generated WITHOUT its END marker: it opens
    the trace window, retires its user instructions, and exits with the
    window still open — the exact subject the dead latch exists for.
    The guest then keeps running in one of two shapes, each of which
    held the latch inert before its two mechanisms were fixed:

      * ``storm`` — init forks ``/bin/true`` in a loop.  Linux recycles
        the dead workload's freed page-table root into a successor
        process, whose every schedule-in and user instruction then
        arrives in the dead window's name; the stamp refresh must
        REFUSE those (the marker-page proof-of-life probe), or the idle
        never accumulates.  The cell asserts the refusals happened
        (``dead-latch refreshes refused``), so a pass is never vacuous.
      * ``quiet`` — init spins in shell builtins.  No fork, no context
        switch, no address-space write: the ASID-write sweep trigger is
        silent, and only the retirement-driven sweep beat can age the
        window out.

    In both shapes the run must END BY THE LATCH: close reason IDLE,
    ``dead-latch windows closed (idle insns)`` >= 1, a decodable .cst,
    and every ``(must be 0)`` census row at zero.  A run that does not
    close is killed by the clock watchdog and fails — this cell is the
    backstop's must-fire proof, not a content test (the storm shape's
    trace deliberately carries up to latch_idle_insns of successor
    execution between the death and the close; attribution under a
    recycled root is the separate, open identity issue).
    """
    args.system = True
    args.end_marker = False
    args._plugin_extra = f"latch_idle_insns={int(args.latch_insns)}"
    # The window budget is deliberately unreachable, so the watchdog must
    # not derive its deadline from it; fall back to the per-mode ceiling.
    args._lldet_budget = None
    shapes = [s.strip() for s in args.shapes.split(",") if s.strip()]
    rc_total = 0
    for isa in args.isa:
        for shape in shapes:
            print(f"\n==== deadlatch_test {isa} ({shape}) ====")
            cmd_generate(args, isa)
            if cmd_build(args, isa) != 0:
                rc_total = 1
                continue
            prog = _prog_base(args.out_dir, args.prog)
            bin_path = _bin_path(args.out_dir, prog, isa)
            out_base = Path(f"{_trace_base(args.out_dir, prog, isa)}"
                            f"_{shape}")
            plugin = (args.build_dir / "contrib" / "plugins"
                      / "libchampsim_tracer.so")
            args._init_text = SYS.deadlatch_init(shape)
            try:
                rc = _trace_system(args, isa, bin_path, plugin, out_base)
            finally:
                args._init_text = None
            if rc == RC_SKIP:
                return RC_SKIP
            if rc != 0:
                print(f"deadlatch_test[{isa}/{shape}]: FAIL  the run was "
                      f"not ended by the dead latch (rc={rc}) — the "
                      f"backstop did not fire")
                rc_total = 1
                continue

            console = Path(f"{out_base}.console.log")
            ctext = console.read_text() if console.exists() else ""
            if "(window left open)" not in ctext:
                print(f"deadlatch_test[{isa}/{shape}]: FAIL  the guest "
                      f"never reported the workload's exit — the latch "
                      f"was not under test")
                rc_total = 1
            if "dead-latch close asid=" not in ctext:
                print(f"deadlatch_test[{isa}/{shape}]: FAIL  no "
                      f"'dead-latch close' line — whatever closed this "
                      f"run, it was not the latch")
                rc_total = 1

            stats_log = Path(f"{out_base}.stats.log")
            stext = stats_log.read_text() if stats_log.is_file() else ""
            closes = _stats_value(stext,
                                  "dead-latch windows closed (idle insns)")
            refused = _stats_value(stext,
                                   "dead-latch refreshes refused")
            if not closes:
                print(f"deadlatch_test[{isa}/{shape}]: FAIL  statistics "
                      f"carry no idle-insn dead-latch close")
                rc_total = 1
            if shape == "storm" and not refused:
                print(f"deadlatch_test[{isa}/{shape}]: FAIL  zero "
                      f"refused refreshes — the recycled-root forgery "
                      f"this shape exists to present never arose, so "
                      f"the probe was not under test (vacuous)")
                rc_total = 1
            print(f"deadlatch_test[{isa}/{shape}]: closes={closes} "
                  f"refreshes_refused={refused}")

            cst = Path(f"{out_base}.cst")
            # The close route comes out of the run's own console line, not
            # out of what this cell meant to exercise: the thread_end
            # oracle relaxes exactly one arm for a sweep close, so the
            # relaxation must be keyed on what actually closed the segment.
            close_reason = V.parse_close_reason(ctext)
            if close_reason is None:
                print(f"deadlatch_test[{isa}/{shape}]: FAIL  no "
                      f"'finished segment' line to name the close route — "
                      f"the thread_end oracle cannot know which arm applies")
                rc_total = 1
            report = V.validate_structural(cst, expected_threads=1,
                                           expected_guest_threads=1,
                                           marker=True,
                                           close_reason=close_reason)
            print(report.summary())
            # One named, TRUE tolerance — printed, never silent:
            #
            #   storm shape, single-process structure: between the death
            #   and the close the recycled root's successor process IS
            #   captured under the stale pin (the open identity gap, task
            #   #44, bounded here by latch_idle_insns), so oracles that
            #   assume one process's control flow are inapplicable to this
            #   shape by construction.
            # thread_end is NO LONGER tolerated: the sweep-close arm of
            # the oracle now states the contract instead of excusing a
            # failure (format.rst §4.2a — a context with nothing pending
            # at the close ends unstamped), so a thread_end error here is
            # a real one again.
            tolerated: set[str] = set()
            if shape == "storm":
                tolerated |= {"syscall_transitions", "thread_chain",
                              "thread_distribution",
                              "syscall_fault_nesting", "range_continuity"}
            hard = [e for e in report.errors() if e.check not in tolerated]
            for e in report.errors():
                if e.check in tolerated:
                    print(f"deadlatch_test[{isa}/{shape}]: tolerated "
                          f"[{e.check}] (named open issue, see the cell's "
                          f"tolerance note): {e.message}")
            for e in hard:
                print(f"deadlatch_test[{isa}/{shape}]: FAIL [{e.check}] "
                      f"{e.message}")
            if hard:
                rc_total = 1
            if _must0.gate([stats_log], f"deadlatch_test[{isa}/{shape}]"):
                rc_total = 1
    return rc_total


def _stats_value(stats_text: str, label: str) -> int:
    """The integer value of the first statistics row whose label starts
    with @label, 0 when absent."""
    for line in stats_text.splitlines():
        if line.startswith(label):
            try:
                return int(line.split()[-1])
            except ValueError:
                return 0
    return 0


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
        # The program runs to exit after the scheduled intervals close, so
        # there is no stated total budget; the per-mode ceiling applies.
        # The console (plugin stderr) is captured to a file rather than
        # inherited: the per-segment coverage gate below reads every
        # `finished segment` line back out of it.  It is echoed into the
        # harness output afterwards so the cell log keeps showing the run.
        console = Path(f"{out_base}.console.log")
        with open(console, "w") as cf:
            if LLDET.enabled():
                watch = LLDET.watch_for(
                    isa=isa, mode="user", wpdepth=args.depth, budget=None,
                    growth_prefix=str(out_base),
                    label=f"simpoint_test {isa}")
                rc, _verdict = LLDET.run_watched(cmd, watch,
                                                 stdout=cf, stderr=cf)
            else:
                rc = subprocess.call(cmd, stdout=cf, stderr=cf)
        try:
            sys.stdout.write(console.read_text(errors="replace"))
        except OSError:
            pass
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

        # THE CLOCK AND THE WIRE MUST AGREE ON EVERY SEGMENT.  A
        # multi-segment run closes one window per cluster, and each close
        # line carries its own clock_minus_wire; the single-segment cells
        # were gated while a mid-stream reopen's residual rode through
        # rc=0 here.  _check_segment_coverage walks every parsed line:
        # any nonzero clock_minus_wire, any truncating close flag, or
        # (require_ok) a window that did not close at its budget fails
        # the cell, and a console with no parsable line fails as a check
        # that cannot find its subject.
        if _check_segment_coverage(console, require_ok=True,
                                   label=f"{isa} simpoint"):
            rc_total = 1

        # Decode the segments standalone, in reverse order, deliberately
        # not in trace order — proves segment N is independently
        # decodable without state from any other segment.
        for seg in reversed(seg_files):
            print(f"validate[{isa}] segment {seg.name}:")
            report = V.validate_structural(seg, expected_threads=1)
            print(report.summary())
            if report.errors():
                rc_total = 1

        # Cross-segment regression check: shared templates must report
        # the same per-execution memop shape across segments.  Catches
        # a TB whose per-insn callbacks aren't armed when it executes
        # inside one segment after caching during the inactive gap
        # between segments — the per-segment structural check would
        # see an internally consistent (but lossy) segment-N and pass.
        print(f"validate[{isa}] cross-segment consistency:")
        xseg = V.validate_cross_segment_consistency(list(seg_files))
        print(xseg.summary())
        if xseg.errors():
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
    if args.cmd == "churn_test":
        return cmd_churn_test(args)
    if args.cmd == "deadlatch_test":
        return cmd_deadlatch_test(args)
    if args.cmd == "full":
        return FULL.cmd_full(args)
    if args.cmd == "lldet_calibrate":
        return LLDET.cmd_lldet_calibrate(args)
    if args.cmd == "stall_scan":
        return STALL.cmd_stall_scan(args)
    if args.cmd == "plugin_load":
        return PLUGLOAD.cmd_plugin_load(args)
    if args.cmd == "mutation":
        from . import _mutation as MUT
        return MUT.cmd_mutation(args)
    if args.cmd == "range_cells":
        from . import _range_cells as RC
        return RC.cmd_range_cells(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
