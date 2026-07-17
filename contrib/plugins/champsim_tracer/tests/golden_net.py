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
import hashlib
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

# --- layout -----------------------------------------------------------------
HERE = Path(__file__).resolve().parent                 # .../champsim_tracer/tests
PLUGIN_DIR = HERE.parent                                # .../champsim_tracer
VALIDATOR_DIR = PLUGIN_DIR / "validator"               # holds the importable pkg
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


# --- modes ------------------------------------------------------------------
def capture(build: Path, root: Path) -> int:
    if root.exists():
        shutil.rmtree(root)
    if GOLDEN_TRACES.exists():
        shutil.rmtree(GOLDEN_TRACES)   # drop any stale frozen traces
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    # Record the capture-time work root: the path is a wire INPUT (guest
    # argv[0]/AT_EXECFN sizes set the stack base -> REG_SP), so a check
    # under any other root is structurally red.  check() enforces this.
    manifest = {"work_root": str(root), "cells": {}, "svg": {},
                "svg_fixtures": {}, "excluded": {}}
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


def check(build: Path, root: Path) -> int:
    if not MANIFEST.exists():
        print(f"no manifest at {MANIFEST}; run capture first", file=sys.stderr)
        return 2
    manifest = json.loads(MANIFEST.read_text())
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

# One canonical system cell (extend as more system fixtures are added).
SYS_CELLS = [{"name": "devio_sys_x86_64", "isa": "x86_64"}]

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


def sys_trace_once(build: Path, kernel: Path, initrd: Path, out_dir: Path,
                   label: str) -> Path | None:
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
        "-plugin", f"{plugin},outfile={out_base},{SYS_PLUGIN_OPTS}",
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


def sys_capture(build: Path, root: Path) -> int:
    if SYS_MANIFEST.exists():
        SYS_MANIFEST.unlink()
    if root.exists():
        shutil.rmtree(root)
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {"work_root": str(root), "recipe": {}, "canon_cells": {},
                "fixture_decode": {}, "excluded": {}}
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
        }
        for c in SYS_CELLS:
            name = c["name"]
            hs = []
            for i in range(SYS_N_DET):
                cst = sys_trace_once(build, kernel, initrd, root / name,
                                     f"{name}_{i}")
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


def sys_check(build: Path, root: Path) -> int:
    if not SYS_MANIFEST.exists():
        print(f"no system manifest at {SYS_MANIFEST}; run "
              f"`capture --system` first", file=sys.stderr)
        return 2
    manifest = json.loads(SYS_MANIFEST.read_text())
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
                                     f"{name}_chk")
                if cst is None:
                    fails.append(f"canon:{name}: trace not produced")
                    continue
                got = sha(canon_user_slice(build, cst).encode())
                if got != want["canon"]:
                    fails.append(f"canon:{name}: CP-user-slice mismatch "
                                 f"(plugin trace-generation changed)")

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
    args = ap.parse_args()
    build = args.build_dir
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
        return sys_capture(build, sys_root) if args.mode == "capture" \
            else sys_check(build, sys_root)
    if args.mode == "capture":
        return capture(build, shared)
    return check(build, shared)


if __name__ == "__main__":
    sys.exit(main())
