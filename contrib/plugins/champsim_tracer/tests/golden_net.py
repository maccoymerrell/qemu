#!/usr/bin/env python3
"""Golden-trace safety net for behavior-preserving refactors of the
ChampSim Tracer plugin and tools.

A refactor must not change trace output. This harness captures stable
golden references for a matrix of synthetic validator workloads x ISAs,
then verifies — after each refactor step — that every trace is still
byte-identical and that the validator still reports errors=0.

Usage (run with the Anaconda python; see CLAUDE.md):
    export PATH=/home/maccoy-merrell/anaconda3/bin:$PATH
    python contrib/plugins/champsim_tracer/tests/golden_net.py capture --build-dir build
    python contrib/plugins/champsim_tracer/tests/golden_net.py check   --build-dir build

What is hashed per (workload, ISA) -- all three must match on `check`:
  1. raw `body.cst` tar member          (literal wire bytes; no volatile fields)
  2. `cst_decode --format=legacy` text  (COMMAND/DATETIME lines blanked) -- catch-all
  3. `cst_decode --templates-only` text (template dictionary; no volatile lines)
The header member is never hashed raw (it holds the only two volatile
fields, the COMMAND and DATETIME strings).

A separate SVG golden guards cst_visualize (Phase 7), which consumes a
.cst and emits SVG without touching the wire format.

`capture` traces every cell twice and refuses to record a golden for any
cell that is not bit-deterministic across the two runs (so `check` can
never raise a false alarm).
"""

import argparse
import datetime
import hashlib
import json
import fcntl
import os
import re
import resource
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

# --- layout -----------------------------------------------------------------
HERE = Path(__file__).resolve().parent                 # .../champsim_tracer/tests
PLUGIN_DIR = HERE.parent                                # .../champsim_tracer
VALIDATOR_DIR = PLUGIN_DIR / "validator"               # holds the importable pkg
REPO_ROOT = PLUGIN_DIR.parents[2]                      # worktree root (.../qemu)
GOLDEN_DIR = HERE / "golden"
MANIFEST = GOLDEN_DIR / "manifest.json"
# Frozen .cst traces kept as the renderer's golden inputs.  SVG goldens are
# rendered from THESE fixed files on both capture and check, never from a
# re-traced .cst -- a renderer refactor must be tested against an unchanging
# input so a trace difference can't masquerade as (or mask) a render change.
GOLDEN_TRACES = GOLDEN_DIR / "traces"

# Fixed environment for the trace pipeline.  The kernel sets the guest's
# initial stack pointer from the argv+envp block size; setarch -R pins ASLR
# but NOT that size, so a varying shell environment shifts the guest SP and
# with it the REGFILE record's REG_SP -- the one field that otherwise makes
# an otherwise-identical body trace differ across invocations (verified by
# decode-diff: a single differing REG_SP line out of thousands).  Spawn the
# whole generate/build/trace pipeline under a hard-coded env so argv+envp --
# and thus the stack base and the entire trace -- is reproducible across
# shell sessions.  PATH covers the anaconda python tooling and the /usr/bin
# cross-compilers; HOME/LANG are pinned so their lengths can't drift.
PINNED_ENV = {
    "PATH": "/home/maccoy-merrell/anaconda3/bin:/usr/local/bin:/usr/bin:/bin",
    "HOME": "/home/maccoy-merrell",
    "LANG": "C",
    "LC_ALL": "C",
}

ALL_ISAS = ["x86_64", "aarch64", "riscv64", "mipsel"]

# Workload matrix: real generator/trace knobs. --memdata is hardcoded on by
# cmd_trace, so it is not a knob. --compress none keeps the tar members raw.
WORKLOADS = [
    {"name": "w1_baseline",  "seed": "0x0101", "isas": ALL_ISAS,
     "args": ["--diamonds", "8"]},
    {"name": "w2_regdata",   "seed": "0x0202", "isas": ALL_ISAS,
     "args": ["--diamonds", "8", "--regdata"]},
    {"name": "w3_coverage",  "seed": "0x0303", "isas": ALL_ISAS,
     "args": ["--coverage"]},
    {"name": "w4_hotloops",  "seed": "0x0404", "isas": ALL_ISAS,
     "args": ["--diamonds", "6", "--hot-iters", "64"]},
    {"name": "w5_stride",    "seed": "0x0505", "isas": ["x86_64"],
     "args": ["--stride-loops"]},
    {"name": "w6_deepwp",    "seed": "0x0606", "isas": ALL_ISAS,
     "args": ["--diamonds", "8", "--depth", "128"]},
    {"name": "w7_iframe",    "seed": "0x0707", "isas": ALL_ISAS,
     "args": ["--diamonds", "8", "--depth", "4", "--iframe-rate", "50"]},
    # NOTE: flush-heavy workloads (large coverage+regdata, and --tb-size 1)
    # are intentionally NOT byte-golden cells.  When the guest's translated
    # code + plugin instrumentation overflows the code cache, tb_flush
    # timing depends on the plugin .so codegen, so the *byte* trace shifts
    # across any rebuild (even behavior-preserving ones) — a false positive
    # for byte-identity.  The tracer is flush-INVARIANT semantically (the
    # decoded execution and the validator result are identical with vs
    # without flushing); those workloads are covered by `validator all`
    # and tests/large_scale.sh (whose coverage/wide-cfg/hot-stress shapes
    # exercise coverage+regdata), not by this byte net.
    #   w8_dense  (--coverage --regdata)   -> validator/large_scale
    #   w9_tbflush(--diamonds 64 --tb-size 1) -> validator/large_scale
]

# SVG goldens: render every metric on two traces (guards Phase 7).
# Render only from non-flushing cells — w8_dense's .cst is build-sensitive
# (see the WORKLOADS note above), so it can't anchor a byte-stable SVG.
# w3_coverage stands in for it: it exercises every opcode/branch family
# the metric ladders touch.
SVG_WORKLOADS = ["w1_baseline", "w3_coverage"]
SVG_ISA = "x86_64"
SVG_METRICS = [
    "branch_mpki", "wp_insns", "wp_memops", "mem_pat", "branch_dir",
    "gen_op", "gen_reg", "btb_miss", "wp_divergence", "cache_miss",
    "bb_length", "indirect_targets", "branch_entropy", "working_set",
    "dep_depth", "ilp", "reuse_distance",
    # Context metrics that also render meaningfully on user-mode traces
    # (single asid / no faults degrade to flat-but-valid charts).
    "user_kernel", "fault_rate", "thread_switch", "asid_timeline",
    "wp_termination",
]

# System-scoped metrics: they read physaddr / DEVIO / multi-context
# content, so their SVG goldens render from the frozen system fixture
# below (a user-mode validator trace has none of that content).
SYS_METRICS = [
    "devio_queue", "devio_latency", "devio_lba",
    "ws_divergence", "translation_churn", "pagemap",
]

# Frozen system-mode fixture traces: renderer-golden inputs captured
# OUTSIDE the validator.  A system boot is not byte-deterministic
# across runs (boot timing moves the marker icount), so a single trace
# is frozen once and SVG goldens only ever render that frozen file.
# Fixtures live in FIXTURES_DIR permanently: `capture` clears
# GOLDEN_TRACES but never this directory, and fails loudly when a
# listed fixture is missing.  devio_sys_x86_64: qemu-system-x86_64 +
# virtio-blk guest doing O_DIRECT disk I/O inside a marker window,
# physaddr=1 wpdepth=64 regdata=1 memdata=1 (provenance:
# cst_runs/vis44/devio_sys_x86_64/run_devio.sh).
FIXTURES_DIR = GOLDEN_DIR / "fixtures"
FIXTURES = [
    {"name": "devio_sys_x86_64", "file": "devio_sys_x86_64.cst",
     "metrics": SVG_METRICS + SYS_METRICS},
]

VOLATILE_PREFIXES = ("COMMAND ", "DATETIME ", "; command=", "; datetime=")


# --- helpers ----------------------------------------------------------------
def cst_decode_bin(build: Path) -> Path:
    return build / "contrib" / "plugins" / "cst_decode"


def cst_visualize_bin(build: Path) -> Path:
    return build / "contrib" / "plugins" / "cst_visualize"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def run_all(build: Path, wl: dict, out_dir: Path) -> int:
    """generate+build+trace+analyze+validate for one workload (all its ISAs).
    Returns the validator exit code (0 == errors=0)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    # setarch -R disables ASLR (ADDR_NO_RANDOMIZE, inherited by the qemu
    # child) so guest stack/mmap bases are fixed -> recorded memory
    # addresses are reproducible across runs. Without it, only mipsel
    # happens to be deterministic; x86_64/aarch64/riscv64 traces vary.
    # env=PINNED_ENV pins argv+envp size so the guest stack base (and the
    # REGFILE REG_SP it sets) is reproducible across shell sessions too --
    # setarch -R alone does not fix that.  sys.executable is absolute, so the
    # pipeline still finds python regardless of the pinned PATH.
    cmd = ["setarch", "-R",
           sys.executable, "-m", "champsim_tracer_validator", "all",
           "--seed", wl["seed"], "--build-dir", str(build.resolve()),
           "--out-dir", str(out_dir.resolve()), "--compress", "none"]
    for isa in wl["isas"]:
        cmd += ["--isa", isa]
    cmd += wl["args"]
    proc = subprocess.run(cmd, cwd=VALIDATOR_DIR, env=PINNED_ENV,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True)
    return proc.returncode


def cst_path(out_dir: Path, isa: str) -> Path:
    # validator names the trace <out_dir.name>_<isa>.cst
    return out_dir / f"{out_dir.name}_{isa}.cst"


def body_member_hash(cst: Path) -> str:
    with tarfile.open(cst) as tf:
        member = next(m for m in tf.getmembers()
                      if Path(m.name).name.startswith("body.cst"))
        return sha(tf.extractfile(member).read())


def decode_text(build: Path, cst: Path, mode: str) -> str:
    flag = "--templates-only" if mode == "templates" else f"--format={mode}"
    proc = subprocess.run([str(cst_decode_bin(build)), flag, str(cst)],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True, check=True)
    return proc.stdout


def normalize(text: str) -> str:
    out = []
    for line in text.splitlines():
        if line.startswith(VOLATILE_PREFIXES):
            out.append(line.split(" ", 1)[0] + " <redacted>")
        else:
            out.append(line)
    return "\n".join(out)


def triple_hash(build: Path, cst: Path) -> dict:
    legacy = normalize(decode_text(build, cst, "legacy"))
    templates = decode_text(build, cst, "templates")
    assert "datetime" not in templates.lower() and "command" not in templates.lower(), \
        f"unexpected volatile line in --templates-only output of {cst}"
    return {
        "body": body_member_hash(cst),
        "legacy": sha(legacy.encode()),
        "templates": sha(templates.encode()),
    }


def svg_hash(build: Path, cst: Path, metric: str) -> str:
    # Render to a throwaway temp so the frozen-trace dir stays clean (it
    # holds only the golden .cst inputs, not render artifacts).
    with tempfile.NamedTemporaryFile(suffix=".svg") as tf:
        out_svg = Path(tf.name)
        subprocess.run([str(cst_visualize_bin(build)), "-m", metric,
                        "-o", str(out_svg), str(cst)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True)
        return sha(out_svg.read_bytes())


# ===========================================================================
# Build freshness + provenance gate
# ===========================================================================
#
# A golden manifest is only worth what the binaries that produced it were.
# The failure this gate exists to stop was silent and cost a whole reference:
# the plugin .so and qemu-x86_64 were built at 08:41, commit eb99d9ae72
# ("disas/capstone: four more places the decoder named the wrong direction")
# landed at 09:05, and the goldens were captured at 10:03 with the 08:41
# binaries.  The manifest therefore froze the PRE-fix STMXCSR direction --
# `deps: la=0x1` on a GEN_OP_STORE -- as the reference every later refactor
# would be measured against, and nothing anywhere complained.  Nothing could:
# capture's own GREEN-twice determinism gate re-ran the SAME stale binary
# twice and got the same answer both times, which is exactly what a stale
# build looks like from the inside.
#
# So this gate is deliberately about the INPUTS, never the output:
#
#   (1) every artifact the run will execute exists, and
#   (2) the build system itself confirms every one of them was already
#       current -- the gate runs a real `ninja` for the artifact targets and
#       refuses if it had to rewrite any of them.  That covers both halves of
#       the failure above (a commit landing between build and capture, and an
#       edit that was never built at all) without either of the mtime
#       heuristics this replaced, which shared baselines -- "oldest artifact",
#       "HEAD's commit time" -- that do not track what feeds a given
#       artifact.  See build_currency() for why the three cheaper tests are
#       each unsound, with the measurement behind each.  Proven four ways:
#       passes on a build whose goldens are byte-identical on both nets;
#       refuses a touched disas/capstone.c, naming the four qemu-<target>
#       binaries (the artifacts that actually carry a decoder repair, which
#       the old clause did not name); refuses a header-only plugin edit,
#       naming the .so, which the explicit input graph would have missed; and
#       is idempotent, so an immediate re-run passes and still nets GREEN.
#   (3) no tracked wire source is locally modified -- a manifest captured
#       from unpublished source is not reproducible by anyone else, so it is
#       not a reference.  (`check` tolerates this: verifying a work-in-
#       progress tree against a published reference is the whole point.)
#
# and it records what it proved INTO the manifest, so a manifest can always
# answer "which binaries, from which commit, with what uncommitted on top?"
# without anyone having to reconstruct it from mtimes months later.
#
# Escape hatches are per-clause (--allow-stale / --allow-dirty) and both are
# recorded in the manifest when used, because a waiver nobody can see later
# is the same silent failure wearing different clothes.

# Directories whose tracked C/C++ sources reach the wire.  disas/ is in the
# list because disas/capstone.c is the Capstone boundary the tracer's operand
# roles come from, and leaving it out is precisely how the STMXCSR repair went
# unnoticed.
#
# It does NOT compile into the plugin .so, and believing it does is its own
# trap.  Verified: `ninja -t inputs contrib/plugins/libchampsim_tracer.so`
# lists no disas/ object, `nm` finds no cap_* symbol in the .so, and
# champsim_tracer_decode.cc makes zero cs_open/cs_disasm calls -- it reads
# qemu_plugin_operand structs handed to it by QEMU (see the operand API in
# include/qemu/qemu-plugin.h, which documents itself as exposing the knowledge
# that "already lives (see disas/capstone.c)").  The real path is
#
#     disas/capstone.c -> libcommon.a -> qemu-<target> -> plugin API -> plugin
#
# so a decoder repair reaches a trace only through the QEMU BINARY.  The
# practical consequence, and the reason this is worth spelling out: `ninja
# contrib-plugins` can never pick one up, while it DOES rebuild isaxcheck,
# which links disas/capstone.c directly -- so the cross-checker you would
# reach for to confirm the decoders agree sees the fix while the trace path
# silently does not.
WIRE_SOURCE_DIRS = [
    "contrib/plugins",
    "disas",
    "plugins",
    "accel",
    "tcg",
    "target",
    "include",
    # subprojects/ contributes only its tracked *.wrap files (the checked-out
    # source trees are untracked, so `git ls-files` never reaches them).  That
    # is exactly what we want: capstone.wrap pins the decoder revision, and
    # bumping it changes operand roles across every ISA -- a wire change with
    # no .c file behind it.
    "subprojects",
]
WIRE_SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".h", ".hh", ".inc", ".h.inc",
                        ".c.inc", ".build", ".wrap")


def _git(*args: str) -> str | None:
    """Run git in the repo; None when git or the repo is unavailable."""
    try:
        p = subprocess.run(("git", "-C", str(REPO_ROOT)) + args,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True)
    except OSError:
        return None
    return p.stdout if p.returncode == 0 else None


def built_artifacts(build: Path, system: bool) -> list[Path]:
    """Every binary the requested net actually executes.  Anything not in
    this list cannot be fingerprinted, so keep it in step with the modes."""
    arts = [build / "contrib" / "plugins" / "libchampsim_tracer.so",
            cst_decode_bin(build), cst_visualize_bin(build)]
    if system:
        arts.append(sys_qemu_system_bin(build))
    else:
        arts += [build / f"qemu-{isa}" for isa in ALL_ISAS]
    return arts


def wire_sources() -> list[Path] | None:
    """Tracked sources under WIRE_SOURCE_DIRS whose changes reach the wire.
    Uses `git ls-files` rather than a find(1) sweep so an untracked scratch
    file can't fail the gate and a tracked one can't escape it.  None when
    git is unavailable (the caller treats that as a gate failure)."""
    out = _git("ls-files", "-z", "--", *WIRE_SOURCE_DIRS)
    if out is None:
        return None
    return [REPO_ROOT / p for p in out.split("\0")
            if p and p.endswith(WIRE_SOURCE_SUFFIXES)]


def dirty_wire_sources() -> list[str] | None:
    """Tracked wire sources with uncommitted modifications (staged or not).
    Untracked files are deliberately NOT dirt: subprojects/capstone/ and the
    golden fixtures live untracked by design."""
    out = _git("status", "--porcelain", "--untracked-files=no",
               "--", *WIRE_SOURCE_DIRS)
    if out is None:
        return None
    return [l for l in out.splitlines()
            if l.strip() and l[3:].endswith(WIRE_SOURCE_SUFFIXES)]


def head_commit_time() -> tuple[str, int] | None:
    """(short sha, committer epoch) of HEAD, or None if unavailable."""
    out = _git("show", "-s", "--format=%h %ct", "HEAD")
    if not out:
        return None
    short_sha, ct = out.split()[:2]
    return short_sha, int(ct)


def _iso(epoch: float) -> str:
    return datetime.datetime.fromtimestamp(
        epoch, datetime.timezone.utc).astimezone().isoformat(timespec="seconds")


def build_currency(build: Path, arts: list[Path]) -> tuple[list[str], str] | None:
    """Ask the build system itself whether @arts are current.

    Runs a real `ninja` for the artifact targets and returns the artifacts it
    had to rewrite (empty == the build was already current), plus ninja's
    output.  None when ninja is unavailable or the build fails.

    A real run is the only sound test available here.  The three cheaper ones
    are each blind in a way that matters, all three verified on this build:

      * mtime-vs-HEAD's-commit-time FALSE-FLAGS every artifact whose inputs
        genuinely did not change.  ninja correctly leaves those alone, so
        their mtimes stay behind any later commit -- it refused a build whose
        goldens were then proved byte-identical on both nets.
      * `ninja -n` OVERSTATES the work: a dry run cannot apply restat.
        qemu-version.h is regenerated unconditionally, so -n always reports
        the downstream recompile+relink that a real run then prunes (12
        pending targets that a real run resolves in one generator step).
      * `ninja -t inputs` UNDERSTATES it: depfile-discovered headers are
        absent from the explicit input graph (zero champsim_tracer *.h appear
        under the plugin .so), so a header-only edit would slip past.

    A real run has none of those blind spots, and it reaches header deps.  It
    is idempotent -- consecutive runs converge to the one always-dirty
    generator step -- so using it as a gate does not perturb what follows.
    """
    before = {a: a.stat().st_mtime for a in arts if a.exists()}
    rels = [str(a.relative_to(build)) for a in arts]
    try:
        p = subprocess.run(("ninja", "-C", str(build), *rels),
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True)
    except OSError:
        return None
    if p.returncode != 0:
        return None
    rebuilt = [str(a.relative_to(build)) for a in arts
               if not a.exists() or before.get(a) != a.stat().st_mtime]
    return rebuilt, p.stdout


def build_provenance(build: Path, system: bool,
                     waivers: dict) -> tuple[dict, list[str]]:
    """Fingerprint the artifacts + tree state and return (record, failures).

    `failures` empty means the gate passed.  The record is written into the
    manifest either way, so a waived capture still says so on the wire."""
    fails: list[str] = []
    head = head_commit_time()
    arts = built_artifacts(build, system)

    missing = [a for a in arts if not a.exists()]
    for a in missing:
        # An artifact that isn't there cannot be verified -- and a net that
        # cannot find its subject must fail, never quietly skip it.
        fails.append(f"artifact missing: {a}")
    present = [a for a in arts if a.exists()]

    art_rec = {}
    for a in present:
        st = a.stat()
        art_rec[str(a.relative_to(build))] = {
            "sha256": sha(a.read_bytes())[:16],
            "size": st.st_size,
            "mtime": _iso(st.st_mtime),
        }

    rec: dict = {
        "captured_at": _iso(datetime.datetime.now().timestamp()),
        "head": None if head is None else
                {"sha": head[0], "commit_time": _iso(head[1])},
        "artifacts": art_rec,
        "waivers": {k: v for k, v in waivers.items() if v},
    }

    if head is None:
        fails.append("cannot read HEAD (git unavailable or not a repo): "
                     "build provenance is unverifiable")
        return rec, fails

    # (2) the build system's own verdict on whether these artifacts were
    # current.  This replaces two mtime heuristics that shared a baseline
    # ("oldest artifact", "HEAD's commit time") neither of which tracks what
    # actually feeds a given artifact -- see build_currency() for the three
    # blind spots and the measurements behind each.
    cur = build_currency(build, arts)
    if cur is None:
        fails.append("cannot ask ninja whether the build is current "
                     "(ninja unavailable, or the build does not build) -- "
                     "freshness is unverifiable")
    else:
        rebuilt, _out = cur
        rec["rebuilt_by_gate"] = rebuilt
        srcs = wire_sources()
        rec["wire_sources_checked"] = 0 if srcs is None else len(srcs)
        if rebuilt and not waivers["allow_stale"]:
            fails.append(
                f"{len(rebuilt)} artifact(s) were STALE -- the gate had to "
                f"rebuild them, so anything captured before now ran old code")
            for r in rebuilt[:8]:
                fails.append(f"    {r}")
            fails.append("    re-run now that the build is current; the "
                         "rebuild has already happened")

    # (3) uncommitted wire sources make the manifest unreproducible.
    dirty = dirty_wire_sources()
    rec["dirty_wire_sources"] = dirty or []
    if dirty is None:
        fails.append("cannot read git status: tree cleanliness unverifiable")
    elif dirty and not waivers["allow_dirty"]:
        fails.append(f"{len(dirty)} tracked wire source(s) modified but not "
                     f"committed -- a golden captured from unpublished "
                     f"source is not a reference anyone can reproduce")
        for l in dirty[:8]:
            fails.append(f"    {l}")
    return rec, fails


def gate_build(build: Path, system: bool, waivers: dict,
               mode: str) -> tuple[dict, int]:
    """Enforce the freshness gate for @mode.  Returns (provenance, rc);
    rc != 0 means refuse.  `check` waives the dirty-tree clause: verifying a
    work-in-progress build against a published reference is its job."""
    w = dict(waivers)
    if mode == "check":
        w["allow_dirty"] = True
    rec, fails = build_provenance(build, system, w)
    if not fails:
        head = rec["head"]
        print(f"build gate OK: HEAD {head['sha']} ({head['commit_time']}), "
              f"{len(rec['artifacts'])} artifacts, ninja confirms all current "
              f"against {rec.get('wire_sources_checked', 0)} tracked wire "
              f"sources"
              + ("" if not rec['dirty_wire_sources'] else
                 f", {len(rec['dirty_wire_sources'])} uncommitted (waived)"))
        return rec, 0
    print(f"\n=== BUILD GATE REFUSED ({mode}) ===", file=sys.stderr)
    for f in fails:
        print(f"  {f}", file=sys.stderr)
    print("  Rebuild (ninja -C <build> contrib-plugins qemu-x86_64 ...) and "
          "re-run; override per clause with --allow-stale / --allow-dirty "
          "(recorded in the manifest).", file=sys.stderr)
    return rec, 2


# --- modes ------------------------------------------------------------------
def capture(build: Path, root: Path, waivers: dict) -> int:
    # Prove the build BEFORE destroying the previous reference: a refusal
    # must leave the old manifest and frozen traces exactly where they were.
    prov, rc = gate_build(build, system=False, waivers=waivers, mode="capture")
    if rc:
        return rc
    if root.exists():
        shutil.rmtree(root)
    if GOLDEN_TRACES.exists():
        shutil.rmtree(GOLDEN_TRACES)   # drop any stale frozen traces
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    # Record the capture-time work root: the path is a wire INPUT (guest
    # argv[0]/AT_EXECFN sizes set the stack base -> REG_SP), so a check
    # under any other root is structurally red.  check() enforces this.
    manifest = {"work_root": str(root), "provenance": prov, "cells": {},
                "svg": {}, "svg_fixtures": {}, "excluded": {}}
    bad = 0
    # Determinism pre-check: trace each cell N_DET times to the SAME out-dir
    # (check uses the identical path) and only record a golden for cells
    # whose hashes are stable across runs.  The out-dir path MUST be the
    # same in capture and check: it appears in the qemu argv (binary +
    # outfile paths), and argv length determines the guest stack base ->
    # the initial REG_SP recorded in the REGFILE record.  A differing path
    # shifts the stack and the trace bytes change even though execution is
    # identical (the tracer is flush- and execution-invariant; only the
    # stack address moves).
    N_DET = 2
    for wl in WORKLOADS:
        name = wl["name"]
        out = root / name          # identical path in capture and check
        runs = []
        rc0 = 0
        for i in range(N_DET):
            rc = run_all(build, wl, out)
            if i == 0:
                rc0 = rc
            runs.append({isa: (triple_hash(build, cst_path(out, isa))
                               if cst_path(out, isa).exists() else None)
                         for isa in wl["isas"]})
        for isa in wl["isas"]:
            cell = f"{name}:{isa}"
            hs = [r[isa] for r in runs]
            if any(h is None for h in hs):
                manifest["excluded"][cell] = "trace not produced"
                print(f"  EXCLUDE {cell}: trace missing"); bad += 1
                continue
            if any(h != hs[0] for h in hs[1:]):
                moved = sorted({k for h in hs[1:] for k in h if h[k] != hs[0][k]})
                manifest["excluded"][cell] = f"nondeterministic over {N_DET} runs: {moved}"
                print(f"  EXCLUDE {cell}: NONDETERMINISTIC {moved}"); bad += 1
                continue
            manifest["cells"][cell] = {**hs[0], "validate_rc": rc0}
            tag = "ok" if rc0 == 0 else f"VALIDATE_RC={rc0}"
            print(f"  {cell}: deterministic {tag}")
        out_a = out
        # SVG goldens.  Freeze the trace as a renderer-golden input, then
        # render THAT stored file -- so check renders the identical bytes
        # rather than a re-traced .cst (isolates render from trace drift).
        if name in SVG_WORKLOADS:
            cst = cst_path(out_a, SVG_ISA)
            if cst.exists():
                frozen = GOLDEN_TRACES / f"{name}_{SVG_ISA}.cst"
                frozen.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(cst, frozen)
                for m in SVG_METRICS:
                    try:
                        manifest["svg"][f"{name}:{SVG_ISA}:{m}"] = \
                            svg_hash(build, frozen, m)
                    except subprocess.CalledProcessError:
                        print(f"  WARN svg {name}:{m} failed")
    # Fixture SVG goldens: render each frozen system fixture (never
    # re-traced, never cleared) with its metric set.  A missing fixture
    # is a hard capture error -- silently skipping would drop the
    # system-mode renderer coverage without anyone noticing.
    for fx in FIXTURES:
        cst = FIXTURES_DIR / fx["file"]
        if not cst.exists():
            print(f"  ERROR fixture {fx['name']}: {cst} missing "
                  f"(install the frozen fixture trace first)")
            bad += 1
            continue
        for m in fx["metrics"]:
            try:
                manifest["svg_fixtures"][f"{fx['name']}:{m}"] = \
                    svg_hash(build, cst, m)
            except subprocess.CalledProcessError:
                print(f"  WARN fixture svg {fx['name']}:{m} failed")
        print(f"  fixture {fx['name']}: {len(fx['metrics'])} svg goldens")
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"\ncaptured {len(manifest['cells'])} cells, "
          f"{len(manifest['svg'])} svg goldens, "
          f"{len(manifest['svg_fixtures'])} fixture svg goldens, "
          f"{len(manifest['excluded'])} excluded -> {MANIFEST}")
    return 1 if bad else 0


def check(build: Path, root: Path, waivers: dict) -> int:
    if not MANIFEST.exists():
        print(f"no manifest at {MANIFEST}; run capture first", file=sys.stderr)
        return 2
    manifest = json.loads(MANIFEST.read_text())
    # A check run against a stale build is a false green, not a pass: it
    # compares the reference to binaries that predate the source.
    prov, rc = gate_build(build, system=False, waivers=waivers, mode="check")
    if rc:
        return rc
    _report_reference_provenance(manifest, prov)
    # The work root is a wire input (its length sets the guest stack base
    # via argv[0]/AT_EXECFN -> the REGFILE REG_SP): checking under a
    # different root than capture is a guaranteed all-cells hash red that
    # says nothing about the tracer.  Fail it loudly as a HARNESS error.
    cap_root = manifest.get("work_root")
    if cap_root is not None and cap_root != str(root):
        print(f"work-root mismatch: manifest captured under {cap_root}, "
              f"check invoked under {root}.  The path length feeds the "
              f"guest stack base (REG_SP), so hashes cannot match; re-run "
              f"with --work-root {Path(cap_root).parent} or re-capture.",
              file=sys.stderr)
        return 2
    if root.exists():
        shutil.rmtree(root)
    fails, validate_fails = [], []
    produced = {}
    for wl in WORKLOADS:
        name = wl["name"]
        out = root / name
        rc = run_all(build, wl, out)
        for isa in wl["isas"]:
            cell = f"{name}:{isa}"
            if cell not in manifest["cells"]:
                continue
            cst = cst_path(out, isa)
            if not cst.exists():
                fails.append(f"{cell}: trace not produced"); continue
            produced[cell] = (build, cst)
            got = triple_hash(build, cst)
            want = {k: manifest["cells"][cell][k] for k in ("body", "legacy", "templates")}
            if got != want:
                moved = [k for k in want if got[k] != want[k]]
                fails.append(f"{cell}: hash mismatch {moved}")
                if "legacy" in moved:
                    _dump_legacy_diff(build, cst, cell)
            # Compare to the recorded baseline rc, not absolute 0: some
            # cells have a known pre-existing validator issue (e.g. w5
            # stride's wrong_path_chains budget boundary).  Flag only a
            # REGRESSION (rc worse than baseline).
            base_rc = manifest["cells"][cell].get("validate_rc", 0)
            if rc != base_rc:
                validate_fails.append(
                    f"{cell}: validator rc={rc} (baseline {base_rc})")
    # SVG goldens: render the FROZEN golden trace, never a re-traced .cst,
    # so a mismatch can only be a renderer change.
    for key, want in manifest.get("svg", {}).items():
        name, isa, metric = key.split(":")
        cst = GOLDEN_TRACES / f"{name}_{isa}.cst"
        if not cst.exists():
            fails.append(f"svg {key}: frozen golden trace missing "
                         f"(re-run capture)"); continue
        if svg_hash(build, cst, metric) != want:
            fails.append(f"svg {key}: SVG mismatch (frozen trace {cst.name})")
    # Fixture SVG goldens: same discipline against the permanent
    # system-mode fixture traces.
    fx_files = {fx["name"]: fx["file"] for fx in FIXTURES}
    for key, want in manifest.get("svg_fixtures", {}).items():
        name, metric = key.split(":")
        fname = fx_files.get(name, f"{name}.cst")
        cst = FIXTURES_DIR / fname
        if not cst.exists():
            fails.append(f"fixture svg {key}: frozen fixture missing "
                         f"({cst})"); continue
        if svg_hash(build, cst, metric) != want:
            fails.append(f"fixture svg {key}: SVG mismatch "
                         f"(fixture {fname})")

    if fails or validate_fails:
        print("\n=== GOLDEN NET FAILED ===")
        for f in fails:
            print(f"  HASH  {f}")
        for f in sorted(set(validate_fails)):
            print(f"  VALID {f}")
        return 1
    print(f"\nGOLDEN NET GREEN: {len(manifest['cells'])} cells + "
          f"{len(manifest.get('svg', {}))} svg goldens + "
          f"{len(manifest.get('svg_fixtures', {}))} fixture svg goldens "
          f"byte-identical; validator errors=0")
    return 0


def _report_reference_provenance(manifest: dict, now: dict) -> None:
    """Say out loud which build the reference came from and which one is being
    compared against it.  A hash mismatch is only interpretable next to that
    pair, and a manifest with no provenance at all predates the gate -- which
    is itself worth printing, because such a manifest may encode a stale
    build and there is no way to tell from the hashes."""
    ref = manifest.get("provenance")
    if not ref:
        print("WARNING: this manifest carries no build provenance (captured "
              "before the gate existed).  It cannot be shown to come from a "
              "current build; re-capture to make it verifiable.")
        return
    rh, nh = ref.get("head") or {}, now.get("head") or {}
    print(f"reference: HEAD {rh.get('sha','?')} captured "
          f"{ref.get('captured_at','?')}"
          + (f", {len(ref['dirty_wire_sources'])} uncommitted wire source(s)"
             if ref.get("dirty_wire_sources") else "")
          + (f", WAIVERS {sorted(ref['waivers'])}" if ref.get("waivers")
             else ""))
    print(f"under test: HEAD {nh.get('sha','?')}"
          + (f", {len(now['dirty_wire_sources'])} uncommitted wire source(s)"
             if now.get("dirty_wire_sources") else ""))


def _dump_legacy_diff(build: Path, cst: Path, cell: str) -> None:
    """Print the first few differing legacy lines vs the manifest is not
    possible (we only stored a hash), but dump a hint: the normalized
    legacy text, so a human can diff against a re-captured reference."""
    print(f"    (legacy text changed for {cell}; re-run `capture` on a known-good "
          f"tree and diff the decoded output to localize)")


# ===========================================================================
# System-mode golden net
# ===========================================================================
#
# DETERMINISM VERDICT (measured; see tests/golden/sysfixtures/EXPERIMENT.txt
# for the full knob matrix and variant-field taxonomy).  A full-system boot is
# NOT byte-deterministic run to run, and no available knob makes it so without
# editing the plugin:
#
#   * baseline (canonical devio config, no icount): the marker fires at a
#     different boot icount every run; trace length, template count, BB-id
#     assignment, and every profile/exec count differ.  Two runs share a
#     common prefix only up to line 8 (the START_INSN icount).
#   * -icount shift=N,sleep=off -rtc clock=vm: still nondeterministic (marker
#     icount moves ~10^5-10^7 between runs) and it changes trace SEMANTICS
#     (x86 REP string ops single-step under icount -> rep_fanout collapses to
#     0 and per-op instruction counts balloon).  Boot-hardening knobs
#     (nokaslr, -cpu ...,-rdrand,-rdseed, random.trust_cpu=off, tsc=reliable)
#     narrow the gap but do not close it.
#   * record/replay (-icount ...,rr=record/replay): record WITH the plugin
#     crashes ("Bad icount read", accel/tcg/icount-common.c) because the
#     plugin's clock reads in its callbacks violate icount's can_do_io gating;
#     replaying a plugin-free recording WITH the plugin does reproduce the
#     boot deterministically (identical marker icount across replays) but the
#     WP excursion under icount single-steps and produces a runaway,
#     non-terminating trace (>1 GB, never finishes) -- impractical as a net.
#     (Root cause is upstream/plugin interplay, not fixable from tests/.)
#
# So byte-identity across independent boots is out.  What IS invariant: the
# marked workload runs the SAME user instructions every boot.  The
# CORRECT-PATH USER-code slice of the template dictionary -- each CP-executed
# user BB's start_pc, shape, decoded bytes, operand roles and classification,
# with the run-varying fields (BB-id, exec/profile counts, kernel branch
# targets, WP-only BBs, kernel BBs) canonicalized away -- is byte-identical
# across independent boots (verified: 5/5 boots -> one canon hash).  That
# slice is exactly the translation-time output a plugin refactor must
# preserve (fragment splitter, chain assembler, decoder, lane-mask/operand
# roles, dep classifier), so it is the normalized net.
#
# The system net therefore has two byte-exact guards (its own manifest,
# tests/golden/manifest_system.json; the same GREEN-twice + recorded-inputs
# discipline as the user net):
#
#   (1) fixture-decode net -- guards the DECODER/tools on a REAL system trace.
#       Triple-hash (body member / --format=legacy / --templates-only) of the
#       FROZEN system fixture .cst.  The fixture bytes never change, so any
#       hash move is a decoder/tool change.  (User-mode cells never carry
#       kernel BBs, faults, multi-context, physaddr, or DEVIO content.)
#   (2) canon-retrace net -- guards the PLUGIN's trace generation.  Re-boot
#       the canonical system recipe, canonicalize the CP-user-slice, compare
#       to the recorded hash.  capture traces N_DET times and refuses to
#       record a cell whose canon slice is not identical across the runs.
#
# System assets (kernel + initrd) are local, not in the repo (as with the
# validator's system mode).  capture freezes copies into sysfixtures/ and
# records their sha256; both guards SKIP cleanly when the assets are absent.

SYS_MANIFEST = GOLDEN_DIR / "manifest_system.json"
SYS_FIXTURES_DIR = GOLDEN_DIR / "sysfixtures"    # frozen kernel/initrd (local)

# Canonical system recipe (the devio config: nopti + ioeventfd=off + Haswell +
# virtio-blk O_DIRECT disk I/O in a marker window -- the same shape as the
# frozen devio fixture).  Kernel/initrd default to the maintainer's local
# devio build; override with CST_SYS_KERNEL / CST_SYS_INITRD.
SYS_KERNEL_DEFAULT = Path(os.environ.get(
    "CST_SYS_KERNEL",
    "/mnt/md0/QEMU/cst_runs/devio/kbuild-x86/arch/x86/boot/bzImage"))
SYS_INITRD_DEFAULT = Path(os.environ.get(
    "CST_SYS_INITRD",
    "/mnt/md0/QEMU/cst_runs/devio/disk/rootfs.cpio.gz"))
SYS_CPU_MODEL = "Haswell"
SYS_APPEND = "console=ttyS0 panic=-1 nopti"
SYS_PLUGIN_OPTS = ("wpdepth=64,trace_window=marker:simulation=3000000"
                   "+policy=latch,physaddr=1,regdata=1,memdata=1")
SYS_MEM = "512M"
SYS_SCRATCH_BYTES = 16 * 1024 * 1024
# Host CPU to pin the boot to (quiet-host isolation only; the canon slice is
# CPU-independent).  Override with CST_SYS_CPU.
SYS_CPU = os.environ.get("CST_SYS_CPU", "100")
SYS_TIMEOUT = 3600
SYS_VMEM_KB = 25165824                            # ulimit -v (24 GiB)
SYS_N_DET = 2                                     # GREEN-twice determinism gate

# System cells.  A cell's optional `opts` replaces SYS_PLUGIN_OPTS for it; an
# optional `qemu_args` list is appended to the qemu invocation.
#
# The int1 cell exists because SYS_PLUGIN_OPTS does NOT set interrupts=1, so
# without it nothing in the acceptance set boots the captured-async-window code
# at all: the window's depth level, the fault trailer it rides and the
# seal-successor substitution the window arms are all dark, and a change to any
# of them lands unmeasured.
#
# It boots under -icount, and the reason is measured, not assumed: on the
# realtime clock the CP user slice depends on WHERE interrupt arrival lands --
# a mid-BB IRQ splits the true BB, and observed indirect-branch target sets
# shift -- at ~20% flap per boot with MULTIPLE flap modes (8/10 dominant plus
# two distinct one-off slices in a 10-boot sweep).  That variance is real
# execution structure, so masking it in the canon would falsify the wire; and
# the GREEN-twice gate has only ~0.8^2 power against it, which false-passed
# once (captured on two agreeing boots, flapped on the third).  A deterministic
# virtual clock removes the variance at its source.  Maintainer ruling: icount
# is NOT canonical for delivered captures and must never band-aid a defect,
# but "for the sake of comparing against golden cells, it is fine to force
# icount for determinism" -- this cell is exactly that sanctioned use.
SYS_CELLS = [
    {"name": "devio_sys_x86_64", "isa": "x86_64"},
    {"name": "devio_sys_x86_64_int1", "isa": "x86_64",
     "opts": SYS_PLUGIN_OPTS + ",interrupts=1,faults=1",
     "qemu_args": ["-icount", "shift=0,sleep=off", "-rtc", "clock=vm"]},
]

# Frozen system fixtures for the DECODER guard (reuse the SVG fixture files).
SYS_DECODE_FIXTURES = [
    {"name": "devio_sys_x86_64", "file": "devio_sys_x86_64.cst"},
]

# --- CP-user-slice canonicalization ----------------------------------------
# Kernel/user split: x86-64 user VAs sit below the non-canonical hole; kernel
# and vsyscall live at/above it.  A user BB whose branch target is >= this is
# a syscall/int into the (KASLR-shifted) kernel and must be masked.
SYS_USER_MAX = 0x0000800000000000
_BB_RE = re.compile(r'^(BB\d+)\s+(0x[0-9a-fA-F]+)\s+\(insns=(\d+)\s+'
                    r'fall_through=(0x[0-9a-fA-F]+)\)')
_PROFILE_RE = re.compile(r'^\s*profile:\s+exec_cp=(\d+)\s+exec_wp=(\d+)')
_TARGET_RE = re.compile(r'^\s*target\[\d+\]:\s*pc=(0x[0-9a-fA-F]+)')
_INSN_RE = re.compile(r'^\s+([0-9a-fA-F]{16}):\s+(.*)$')


def canon_user_slice(build: Path, cst: Path) -> str:
    """Canonical CP-user-slice of a system trace's template dump: for every
    CP-executed user BB (exec_cp > 0, start_pc < SYS_USER_MAX), emit its
    id-stripped header, its user-range branch targets (counts dropped), and
    its decoded instruction lines (profile annotations dropped), sorted by
    start_pc.  Everything nondeterministic across boots -- kernel BBs, WP-only
    user BBs, exec/profile counts, BB-ids, kernel branch targets -- is masked.
    Byte-identical across independent boots (the determinism verdict above)."""
    txt = decode_text(build, cst, "templates")
    blocks: dict[int, list[str]] = {}
    cur = None
    cur_lines: list[str] = []
    cur_user = False
    exec_cp = 0

    def flush() -> None:
        if cur is not None and cur_user and exec_cp > 0:
            blocks[cur] = cur_lines

    for line in txt.splitlines():
        m = _BB_RE.match(line)
        if m:
            flush()
            cur = int(m.group(2), 16)
            cur_user = cur < SYS_USER_MAX
            exec_cp = 0
            cur_lines = [f"BB {m.group(2)} insns={m.group(3)} "
                         f"fall_through={m.group(4)}"]
            continue
        if cur is None or not cur_user:
            continue
        mp = _PROFILE_RE.match(line)
        if mp:
            exec_cp = int(mp.group(1))
            continue
        mt = _TARGET_RE.match(line)
        if mt:
            if int(mt.group(1), 16) < SYS_USER_MAX:
                cur_lines.append(f"  target pc={mt.group(1)}")
            continue
        mi = _INSN_RE.match(line)
        if mi:
            body = re.sub(r'\s*prof:.*$', '', mi.group(2)).rstrip()
            cur_lines.append(f"  {mi.group(1)}: {body}")
    flush()
    out: list[str] = []
    for pc in sorted(blocks):
        out.extend(blocks[pc])
    return "\n".join(out) + "\n"


# --- system recipe runner ---------------------------------------------------
def _set_vmem():
    resource.setrlimit(resource.RLIMIT_AS, (SYS_VMEM_KB * 1024,
                                            SYS_VMEM_KB * 1024))


def sys_assets(freeze: bool):
    """Resolve the (kernel, initrd) to boot.  On @freeze (capture), copy the
    default local assets into sysfixtures/ so check runs against stable frozen
    copies; otherwise read the already-frozen copies (falling back to the
    defaults).  Returns (kernel, initrd) or (None, None) when unavailable."""
    fk = SYS_FIXTURES_DIR / "kernel"
    fi = SYS_FIXTURES_DIR / "initrd.cpio.gz"
    if freeze:
        if not (SYS_KERNEL_DEFAULT.exists() and SYS_INITRD_DEFAULT.exists()):
            return None, None
        SYS_FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SYS_KERNEL_DEFAULT, fk)
        shutil.copyfile(SYS_INITRD_DEFAULT, fi)
        return fk, fi
    if fk.exists() and fi.exists():
        return fk, fi
    if SYS_KERNEL_DEFAULT.exists() and SYS_INITRD_DEFAULT.exists():
        return SYS_KERNEL_DEFAULT, SYS_INITRD_DEFAULT
    return None, None


def sys_qemu_system_bin(build: Path) -> Path:
    return build / "qemu-system-x86_64"


def _cpu_busy(cpus: list[int], secs: float = 2.0) -> dict[int, float]:
    """Busy percentage per CPU over @secs, straight from /proc/stat."""
    def snap() -> dict[int, list[int]]:
        d = {}
        for line in open("/proc/stat"):
            if line.startswith("cpu") and line[3:4].isdigit():
                f = line.split()
                d[int(f[0][3:])] = [int(x) for x in f[1:]]
        return d
    a = snap()
    time.sleep(secs)
    b = snap()
    out = {}
    for c in cpus:
        if c not in a or c not in b:
            continue
        d = [y - x for x, y in zip(a[c], b[c])]
        tot = sum(d)
        out[c] = 100.0 * (tot - (d[3] + d[4])) / tot if tot else 0.0
    return out


def sys_cpu_preflight() -> list[str]:
    """The system cells pin qemu to one host CPU.  On an SMT core the pinned
    thread shares execution resources with its sibling, so a saturated
    sibling does not merely slow the boot -- it wedges it: the canonical
    devio boot runs in ~18 s on a quiet core and has been seen to blow a
    3600 s timeout on a contended one, which capture then records as an
    EXCLUDED cell, i.e. a net that verifies nothing.

    Checking for a foreign qemu is not enough; the contending process is
    usually not qemu at all.  Measure the sibling's ACTUAL utilisation and
    refuse on a busy one, naming quiet alternatives.  Returns a list of
    failure strings (empty == go).

    WHAT THIS IS AND IS NOT.  This preflight is a cost tripwire: it stops a
    run that would burn an hour and record nothing.  It is NOT a correctness
    mechanism, and no trace may be called valid BECAUSE it passed here.  The
    fact that this check has to exist is itself the defect: system-mode
    capture ties the guest clock to host realtime, so host load reaches the
    guest's own execution -- tick density per unit of guest work, scheduler
    decisions, preemption points -- and therefore reaches the wire.  The
    wedge is merely that defect's cliff.  A capture is only trustworthy when
    its content is provably invariant to host load (a deterministic virtual
    clock), at which point this preflight protects wall-clock time and
    nothing else.  Until then, what a quiet-host golden certifies is
    reproducibility UNDER THE RECORDED CONDITIONS, not load-invariance."""
    if os.environ.get("CST_SYS_CPU_NOCHECK"):
        return []
    try:
        cpu = int(SYS_CPU.split(",")[0])
        sibs_raw = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/"
                        f"thread_siblings_list").read_text().strip()
    except (ValueError, OSError):
        return []                      # no topology info: don't invent a gate
    sibs = []
    for part in sibs_raw.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            sibs += list(range(int(lo), int(hi) + 1))
        else:
            sibs.append(int(part))
    busy = _cpu_busy(sorted(set(sibs)))
    hot = {c: b for c, b in busy.items() if b > 20.0}
    if not hot:
        print(f"  sys cpu preflight: cpu{cpu} siblings {sibs_raw} quiet ("
              + ", ".join(f"cpu{c}={b:.1f}%" for c, b in sorted(busy.items()))
              + ")")
        return []
    # Offer somewhere to go, so the operator is not left guessing.
    others = sorted(set(range(os.cpu_count() or 0)) - set(sibs))
    quiet = []
    if others:
        ob = _cpu_busy(others, 1.0)
        pairs: dict[str, list[int]] = {}
        for c in others:
            try:
                key = Path(f"/sys/devices/system/cpu/cpu{c}/topology/"
                           f"thread_siblings_list").read_text().strip()
            except OSError:
                continue
            pairs.setdefault(key, []).append(c)
        for key, members in pairs.items():
            if len(members) > 1 and all(ob.get(m, 100.0) < 1.0 for m in members):
                quiet.append(min(members))
    return [f"sys cpu preflight: CST_SYS_CPU={SYS_CPU} shares an SMT core "
            f"with " + ", ".join(f"cpu{c} ({b:.0f}% busy)"
                                 for c, b in sorted(hot.items()))
            + f" -- the boot will contend and can wedge past the "
              f"{SYS_TIMEOUT}s timeout.  Re-run with CST_SYS_CPU set to a "
              f"core whose sibling is idle"
            + (f", e.g. {quiet[:6]}" if quiet else "")
            + " (or set CST_SYS_CPU_NOCHECK=1 to proceed anyway)."]


def sys_trace_once(build: Path, kernel: Path, initrd: Path, out_dir: Path,
                   label: str, opts: str = SYS_PLUGIN_OPTS,
                   qemu_args: list[str] | None = None) -> Path | None:
    """Boot the canonical system recipe once with the plugin loaded, tracing
    to <out_dir>/<label>.cst.  Returns the .cst path, or None on failure."""
    out_dir.mkdir(parents=True, exist_ok=True)
    scratch = out_dir / f"{label}.scratch.raw"
    with open(scratch, "wb") as f:               # fresh zero-filled disk
        f.truncate(SYS_SCRATCH_BYTES)
    plugin = build / "contrib" / "plugins" / "libchampsim_tracer.so"
    out_base = out_dir / label
    cmd = [
        "taskset", "-c", SYS_CPU, str(sys_qemu_system_bin(build)),
        "-cpu", SYS_CPU_MODEL, "-nographic", "-no-reboot", "-m", SYS_MEM,
        "-kernel", str(kernel), "-initrd", str(initrd),
        "-append", SYS_APPEND,
        "-drive", f"file={scratch},format=raw,if=none,id=vblk0",
        "-device", "virtio-blk-pci,drive=vblk0,ioeventfd=off",
        *(qemu_args or []),
        "-plugin", f"{plugin},outfile={out_base},{opts}",
    ]
    log = out_dir / f"{label}.run.log"
    with open(log, "w") as f:
        try:
            rc = subprocess.call(cmd, stdout=f, stderr=subprocess.STDOUT,
                                 timeout=SYS_TIMEOUT, preexec_fn=_set_vmem)
        except subprocess.TimeoutExpired:
            print(f"  sys trace {label}: TIMEOUT after {SYS_TIMEOUT}s")
            return None
    cst = Path(f"{out_base}.cst")
    if rc != 0 or not cst.is_file():
        print(f"  sys trace {label}: FAIL rc={rc} (see {log})")
        return None
    return cst


def sys_capture(build: Path, root: Path, waivers: dict) -> int:
    # Same discipline as the user net: prove the build before unlinking the
    # manifest a refusal has to leave intact.
    prov, rc = gate_build(build, system=True, waivers=waivers, mode="capture")
    if rc:
        return rc
    pre = sys_cpu_preflight()
    if pre:
        print("\n=== SYSTEM CAPTURE REFUSED ===", file=sys.stderr)
        for f in pre:
            print(f"  {f}", file=sys.stderr)
        return 2
    if SYS_MANIFEST.exists():
        SYS_MANIFEST.unlink()
    if root.exists():
        shutil.rmtree(root)
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {"work_root": str(root), "provenance": prov, "recipe": {},
                "canon_cells": {}, "fixture_decode": {}, "excluded": {}}
    bad = 0

    # (1) fixture-decode net: triple-hash the frozen system fixture's decode.
    for fx in SYS_DECODE_FIXTURES:
        cst = FIXTURES_DIR / fx["file"]
        if not cst.exists():
            manifest["excluded"][f"decode:{fx['name']}"] = "fixture missing"
            print(f"  EXCLUDE decode:{fx['name']}: {cst} missing")
            bad += 1
            continue
        h0 = triple_hash(build, cst)
        h1 = triple_hash(build, cst)             # GREEN-twice (decoder)
        if h0 != h1:
            manifest["excluded"][f"decode:{fx['name']}"] = "decode not stable"
            print(f"  EXCLUDE decode:{fx['name']}: decode nondeterministic")
            bad += 1
            continue
        manifest["fixture_decode"][fx["name"]] = h0
        print(f"  decode:{fx['name']}: stable triple-hash")

    # (2) canon-retrace net: boot the recipe N_DET times; record only if the
    # CP-user-slice is byte-identical across the runs (GREEN-twice).
    kernel, initrd = sys_assets(freeze=True)
    if kernel is None:
        for c in SYS_CELLS:
            manifest["excluded"][f"canon:{c['name']}"] = "system assets absent"
        print("  canon-retrace: SKIP (no local kernel/initrd; set "
              "CST_SYS_KERNEL / CST_SYS_INITRD)")
    else:
        manifest["recipe"] = {
            "kernel_sha": sha(kernel.read_bytes()),
            "initrd_sha": sha(initrd.read_bytes()),
            "cpu": SYS_CPU_MODEL, "append": SYS_APPEND,
            "plugin_opts": SYS_PLUGIN_OPTS, "mem": SYS_MEM,
            "cell_opts": {c["name"]: c.get("opts", SYS_PLUGIN_OPTS)
                          for c in SYS_CELLS},
            "cell_qemu_args": {c["name"]: c.get("qemu_args", [])
                               for c in SYS_CELLS},
        }
        for c in SYS_CELLS:
            name = c["name"]
            opts = c.get("opts", SYS_PLUGIN_OPTS)
            hs = []
            for i in range(SYS_N_DET):
                cst = sys_trace_once(build, kernel, initrd, root / name,
                                     f"{name}_{i}", opts,
                                     c.get("qemu_args"))
                hs.append(sha(canon_user_slice(build, cst).encode())
                          if cst else None)
            if any(h is None for h in hs):
                manifest["excluded"][f"canon:{name}"] = "trace not produced"
                print(f"  EXCLUDE canon:{name}: trace missing")
                bad += 1
                continue
            if any(h != hs[0] for h in hs[1:]):
                manifest["excluded"][f"canon:{name}"] = \
                    f"CP-user-slice nondeterministic over {SYS_N_DET} runs"
                print(f"  EXCLUDE canon:{name}: NONDETERMINISTIC user-slice")
                bad += 1
                continue
            manifest["canon_cells"][name] = {"canon": hs[0]}
            print(f"  canon:{name}: deterministic CP-user-slice")

    SYS_MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"\ncaptured {len(manifest['fixture_decode'])} decode + "
          f"{len(manifest['canon_cells'])} canon cells, "
          f"{len(manifest['excluded'])} excluded -> {SYS_MANIFEST}")
    return 1 if bad else 0


def sys_check(build: Path, root: Path, waivers: dict) -> int:
    if not SYS_MANIFEST.exists():
        print(f"no system manifest at {SYS_MANIFEST}; run "
              f"`capture --system` first", file=sys.stderr)
        return 2
    manifest = json.loads(SYS_MANIFEST.read_text())
    prov, rc = gate_build(build, system=True, waivers=waivers, mode="check")
    if rc:
        return rc
    _report_reference_provenance(manifest, prov)
    pre = sys_cpu_preflight()
    if pre:
        print("\n=== SYSTEM CHECK REFUSED ===", file=sys.stderr)
        for f in pre:
            print(f"  {f}", file=sys.stderr)
        return 2
    cap_root = manifest.get("work_root")
    if cap_root is not None and cap_root != str(root):
        print(f"work-root mismatch: manifest captured under {cap_root}, "
              f"check invoked under {root}.  Re-run with "
              f"--work-root {Path(cap_root).parent} or re-capture.",
              file=sys.stderr)
        return 2
    if root.exists():
        shutil.rmtree(root)
    fails = []

    # (1) fixture-decode net.
    for fx in SYS_DECODE_FIXTURES:
        want = manifest.get("fixture_decode", {}).get(fx["name"])
        if want is None:
            continue
        cst = FIXTURES_DIR / fx["file"]
        if not cst.exists():
            fails.append(f"decode:{fx['name']}: fixture missing ({cst})")
            continue
        got = triple_hash(build, cst)
        if got != want:
            moved = [k for k in want if got.get(k) != want[k]]
            fails.append(f"decode:{fx['name']}: decode hash mismatch {moved}")

    # (2) canon-retrace net.
    canon_cells = manifest.get("canon_cells", {})
    if canon_cells:
        kernel, initrd = sys_assets(freeze=False)
        if kernel is None:
            fails.append("canon: system assets absent at check "
                         "(kernel/initrd) -- cannot verify")
        else:
            for c in SYS_CELLS:
                name = c["name"]
                want = canon_cells.get(name)
                if want is None:
                    continue
                cst = sys_trace_once(build, kernel, initrd, root / name,
                                     f"{name}_chk",
                                     c.get("opts", SYS_PLUGIN_OPTS),
                                     c.get("qemu_args"))
                if cst is None:
                    fails.append(f"canon:{name}: trace not produced")
                    continue
                got = sha(canon_user_slice(build, cst).encode())
                if got != want["canon"]:
                    fails.append(f"canon:{name}: CP-user-slice mismatch "
                                 f"(plugin trace-generation changed)")

    # A net with an empty guard is not a green net, it is an unverified one.
    # The canon-retrace cell is the ONLY guard on the plugin's system-mode
    # trace generation (the fixture-decode cell guards the decoder against
    # frozen bytes and would pass with the plugin removed entirely), so a
    # manifest that recorded zero canon cells -- because the boot timed out
    # at capture, say -- must fail here rather than announce "GREEN: 1 decode
    # + 0 canon" and let an excluded cell read as a pass.
    if not canon_cells:
        fails.append("canon: manifest records NO canon cells -- the system "
                     "net's only guard on plugin trace generation is absent, "
                     "so this net verifies nothing.  Re-capture (see the "
                     "manifest's `excluded` map for why it was dropped; a "
                     "wedged boot usually means the pinned host CPU's SMT "
                     "sibling is busy -- override CST_SYS_CPU).")
    if not manifest.get("fixture_decode"):
        fails.append("decode: manifest records NO fixture-decode cells -- "
                     "the decoder guard is absent.")
    if fails:
        print("\n=== SYSTEM GOLDEN NET FAILED ===")
        for f in fails:
            print(f"  {f}")
        return 1
    print(f"\nSYSTEM GOLDEN NET GREEN: "
          f"{len(manifest.get('fixture_decode', {}))} decode + "
          f"{len(canon_cells)} canon cells byte-identical")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=("capture", "check"))
    ap.add_argument("--build-dir", type=Path, required=True)
    ap.add_argument("--system", action="store_true",
                    help="operate on the SYSTEM-mode cells (separate manifest "
                         "manifest_system.json): the frozen-fixture decoder "
                         "guard and the normalized CP-user-slice re-trace "
                         "guard.  A full-system boot is not byte-deterministic "
                         "(see the module notes); this net byte-compares the "
                         "proven-invariant slices only.")
    # Default matches the full harness's canonical GOLDEN_WORK_ROOT
    # (validator/_full.py).  The work-root path appears in the qemu argv
    # AND on the guest stack (argv[0] + AT_EXECFN), so its LENGTH shifts
    # the guest stack base and with it the REGFILE record's REG_SP — a
    # manifest captured under one root is byte-red under any other.  A
    # /tmp default invited exactly that capture/check split (and /tmp is
    # the wrong disk for run outputs on this host); default to the one
    # canonical root instead.
    ap.add_argument("--work-root", type=Path,
                    default=Path("/mnt/md0/QEMU/cst_runs/valunify/golden_wr"),
                    help="scratch dir for generated workloads/traces; MUST "
                         "be the same path at capture and check (recorded "
                         "in the manifest and enforced)")
    ap.add_argument("--allow-stale", action="store_true",
                    help="waive the build-freshness clauses (artifact older "
                         "than HEAD's commit, or a tracked wire source newer "
                         "than the oldest artifact).  Recorded in the "
                         "manifest.")
    ap.add_argument("--allow-dirty", action="store_true",
                    help="waive the clean-tree clause on capture, permitting "
                         "a reference captured from uncommitted wire sources. "
                         "Recorded in the manifest.  `check` always waives "
                         "it.")
    args = ap.parse_args()
    build = args.build_dir
    waivers = {"allow_stale": args.allow_stale,
               "allow_dirty": args.allow_dirty}

    # ONE net at a time per work root.  capture and check both create and
    # delete cell directories under the root, and nothing else serialized
    # them: a check running concurrently with another session's check had
    # its freshly-traced cell rmtree'd from under it and failed with
    # "trace not produced" -- a false RED, and the same race can in
    # principle hand a check another run's bytes, a false GREEN.  (Both
    # observed; the second only in principle.)  An exclusive flock on a
    # sidecar of the root closes it: waiting is always correct here, and a
    # crashed holder's lock dies with its fd, so there is nothing to clean
    # up.  Announce the wait so a stuck-looking net names its blocker.
    args.work_root.mkdir(parents=True, exist_ok=True)
    _lock_path = args.work_root / ".golden_net.lock"
    _lock_fd = os.open(str(_lock_path), os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print(f"waiting for {_lock_path} (another golden_net run holds the "
              f"work root)...", flush=True)
        fcntl.flock(_lock_fd, fcntl.LOCK_EX)
    if not cst_decode_bin(build).exists():
        print(f"cst_decode not found under {build}; build contrib-plugins first",
              file=sys.stderr)
        return 2
    # capture and check MUST use the identical trace path so the qemu argv
    # (and thus the guest stack base / initial REG_SP) matches.
    shared = args.work_root / "t"
    if args.system:
        # System-mode net: its own manifest + recorded work root.  The system
        # trace path does NOT feed a guest stack (the workload is staged in
        # the initramfs, not passed via argv), so the canon slice is path-
        # independent; the root is still recorded/enforced for provenance.
        if not sys_qemu_system_bin(build).exists():
            print(f"qemu-system-x86_64 not found under {build}; build it first",
                  file=sys.stderr)
            return 2
        sys_root = args.work_root / "sys"
        return sys_capture(build, sys_root, waivers) if args.mode == "capture" \
            else sys_check(build, sys_root, waivers)
    if args.mode == "capture":
        return capture(build, shared, waivers)
    return check(build, shared, waivers)


if __name__ == "__main__":
    sys.exit(main())
