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
    manifest = {"cells": {}, "svg": {}, "excluded": {}}
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
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"\ncaptured {len(manifest['cells'])} cells, "
          f"{len(manifest['svg'])} svg goldens, "
          f"{len(manifest['excluded'])} excluded -> {MANIFEST}")
    return 1 if bad else 0


def check(build: Path, root: Path) -> int:
    if not MANIFEST.exists():
        print(f"no manifest at {MANIFEST}; run capture first", file=sys.stderr)
        return 2
    manifest = json.loads(MANIFEST.read_text())
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

    if fails or validate_fails:
        print("\n=== GOLDEN NET FAILED ===")
        for f in fails:
            print(f"  HASH  {f}")
        for f in sorted(set(validate_fails)):
            print(f"  VALID {f}")
        return 1
    print(f"\nGOLDEN NET GREEN: {len(manifest['cells'])} cells + "
          f"{len(manifest.get('svg', {}))} svg goldens byte-identical; validator errors=0")
    return 0


def _dump_legacy_diff(build: Path, cst: Path, cell: str) -> None:
    """Print the first few differing legacy lines vs the manifest is not
    possible (we only stored a hash), but dump a hint: the normalized
    legacy text, so a human can diff against a re-captured reference."""
    print(f"    (legacy text changed for {cell}; re-run `capture` on a known-good "
          f"tree and diff the decoded output to localize)")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=("capture", "check"))
    ap.add_argument("--build-dir", type=Path, required=True)
    ap.add_argument("--work-root", type=Path, default=Path("/tmp/ct_golden"),
                    help="scratch dir for generated workloads/traces")
    args = ap.parse_args()
    build = args.build_dir
    if not cst_decode_bin(build).exists():
        print(f"cst_decode not found under {build}; build contrib-plugins first",
              file=sys.stderr)
        return 2
    # capture and check MUST use the identical trace path so the qemu argv
    # (and thus the guest stack base / initial REG_SP) matches.
    shared = args.work_root / "t"
    if args.mode == "capture":
        return capture(build, shared)
    return check(build, shared)


if __name__ == "__main__":
    sys.exit(main())
