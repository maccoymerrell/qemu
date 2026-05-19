"""Reproducible baseline corpus for refactor/perf regression checking.

Produces a fixed set of reference .cst traces under the maximum-
reproducibility recipe from docs/quickstart.rst
(:ref:`reproducibility`):

    env -i HOME=/tmp PATH=/usr/bin LANG=C \\
      taskset -c 0 setarch -R \\
      qemu-<arch> -seed 42 -plugin libchampsim_tracer.so,... <workload>

Corpus:
  * 20 genval seeds x {x86_64, aarch64, riscv64, mipsel}
  * SPEC mcf (x86_64) first 20M instructions
each traced twice: wp=0 (byte-exact CP oracle) and wp=1 (exercises
the wrong-path code; only the run-stable aggregate subset is
compared, since WP records are documented non-bit-deterministic).

Usage:
  python3 baseline.py build               # (re)generate the reference
  python3 baseline.py compare             # re-trace + diff vs reference
  python3 baseline.py compare --keep      # keep the freshly traced set

`build` writes _ref/<key>.cst + _ref/manifest.json.  `compare`
re-traces into _cmp/ and checks every entry:
  wp0  -> sha256 must match exactly AND audit stats must match
  wp1  -> only the reproducible audit subset must match
A non-zero exit means a regression (trace output changed).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import pathlib

_HERE = pathlib.Path(__file__).resolve().parent
_QEMU = _HERE.parents[3]                       # qemu repo root
_BUILD = _QEMU / "build"
_PLUGIN = _BUILD / "contrib/plugins/libchampsim_tracer.so"
_AUDIT = _BUILD / "contrib/plugins/cst_audit"
_VALIDATOR = _HERE.parent / "validator"
_PY = os.environ.get("CST_PY", os.path.expanduser(
    "~/anaconda3/bin/python3"))

_ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")
_ISA_QEMU = {i: f"qemu-{i}" for i in _ISAS}

# 20 fixed genval seeds.  Stable list -> stable corpus.
_SEEDS = [0x51A0 + i for i in range(20)]

# genval program shape — fixed so the corpus is deterministic.
_GEN_ARGS = ["--diamonds", "6", "--side-len-min", "2",
             "--side-len-max", "4", "--coverage", "--hot-iters", "8"]
# genval programs exit via a syscall well before this; a high cap
# just means "trace to program end".
_GEN_STOP = 100_000_000

_MCF_BIN = (_QEMU / ".." / ".." / "ChampSimTraces" / "speccpu_bin"
            / "benchspec/CPU/505.mcf_r/exe/mcf_r_base.avx2-m64")
_MCF_INP = (_QEMU / ".." / ".." / "ChampSimTraces" / "speccpu_bin"
            / "benchspec/CPU/505.mcf_r/data/refrate/input/inp.in")
_MCF_STOP = 20_000_000

_WPDEPTH = 32


def _sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


_DECODE = _BUILD / "contrib/plugins/cst_decode"


def _body_sha(cst: pathlib.Path) -> str:
    """sha256 of the `body.cst` tar member — the per-instruction
    record stream.  Excludes the volatile outer tar mtime and the
    header member's datetime/command preamble, so it is byte-exact
    run-to-run for wp=0 (proven) while still covering every body
    field a tracer/encoder refactor could perturb."""
    with tarfile.open(cst) as t:
        for m in t.getmembers():
            if m.name == "body.cst":
                f = t.extractfile(m)
                return hashlib.sha256(f.read()).hexdigest() if f else ""
    return ""


def _tmpl_sha(cst: pathlib.Path) -> str:
    """sha256 of the decoded template dictionary.  Timestamp-free
    and bounded (templates = unique BBs), so it is a cheap exact
    oracle for template-encoding changes even on large traces."""
    r = _sh([str(_DECODE), "--templates-only", str(cst)])
    return hashlib.sha256(r.stdout.encode()).hexdigest()


_AUDIT_PROF = re.compile(
    r"exec_cp=(\d+)\s+exec_wp=(\d+)\s+mem-insns=(\d+)\s+"
    r"addr-insns=(\d+)\s+pat\[[^\]]*\]=(\d+)/(\d+)/(\d+)/(\d+)")
_AUDIT_TMPL = re.compile(r"\[\s*([\d,]+)\s+tmpl")
_AUDIT_ENTRY = re.compile(r"\[\s*([\d,]+)\s+entry")


def _audit(cst: pathlib.Path) -> dict:
    r = _sh([str(_AUDIT), str(cst)])
    txt = r.stdout + r.stderr
    out: dict = {}
    m = _AUDIT_PROF.search(txt)
    if m:
        (out["exec_cp"], out["exec_wp"], out["mem_insns"],
         out["addr_insns"], out["pat_none"], out["pat_reg"],
         out["pat_irr"], out["pat_rand"]) = (int(x) for x in m.groups())
    mt = _AUDIT_TMPL.search(txt)
    if mt:
        out["templates"] = int(mt.group(1).replace(",", ""))
    me = _AUDIT_ENTRY.search(txt)
    if me:
        out["cp_entries"] = int(me.group(1).replace(",", ""))
    return out


# Audit keys that are reproducible run-to-run even with wp=1
# (docs/limitations.rst: aggregate CP + structural counts stable;
# exec_wp and WP byte sizes are not).
_WP_STABLE_KEYS = ("exec_cp", "mem_insns", "addr_insns", "pat_none",
                   "pat_reg", "pat_irr", "pat_rand", "templates",
                   "cp_entries")


def _gen_build(seed: int, isa: str, work: pathlib.Path) -> pathlib.Path:
    """genval generate+build -> binary path (or raise)."""
    outdir = work / f"g_{seed:04x}_{isa}"
    outdir.mkdir(parents=True, exist_ok=True)
    base = [_PY, "-m", "champsim_tracer_validator"]
    env = dict(os.environ)
    for stage, extra in (("generate",
                           ["--seed", str(seed), *_GEN_ARGS]),
                          ("build", [])):
        r = _sh(base + [stage, "-o", str(outdir), "--isa", isa, *extra],
                cwd=str(_VALIDATOR), env=env)
        if r.returncode != 0:
            raise RuntimeError(
                f"genval {stage} {isa} seed={seed:#x} failed:\n"
                f"{r.stdout[-800:]}\n{r.stderr[-800:]}")
    binp = outdir / f"{outdir.name}_{isa}"
    if not binp.is_file():
        raise RuntimeError(f"genval produced no binary: {binp}")
    return binp


def _trace(qemu: pathlib.Path, binp: pathlib.Path, args: list[str],
           wp: int, stop: int, out_base: pathlib.Path,
           cwd: pathlib.Path | None = None) -> pathlib.Path:
    """Run the reproducibility-wrapped trace; return the .cst path."""
    cst = pathlib.Path(f"{out_base}.cst")
    if cst.exists():
        cst.unlink()
    opts = (f"outfile={out_base},wpdepth={_WPDEPTH},wp={wp},"
            f"trace_window=icount:start=0;stop={stop},"
            f"memdata=1,regdata=1")
    cmd = ["env", "-i", "HOME=/tmp", "PATH=/usr/bin", "LANG=C",
           "taskset", "-c", "0", "setarch", "-R",
           str(qemu), "-seed", "42",
           "-plugin", f"{_PLUGIN},{opts}", str(binp), *args]
    r = subprocess.run(cmd, capture_output=True, text=True,
                        cwd=str(cwd) if cwd else None)
    if not cst.is_file():
        raise RuntimeError(
            f"trace produced no file ({cst.name}); rc={r.returncode}\n"
            f"{r.stderr[-800:]}")
    return cst


def _mcf_workdir(work: pathlib.Path) -> pathlib.Path:
    d = work / "mcf_x86_64"
    d.mkdir(parents=True, exist_ok=True)
    dst = d / "inp.in"
    if not dst.exists():
        shutil.copy(_MCF_INP.resolve(), dst)
    return d


# Inner-loop subset: first 3 seeds, all ISAs, both wp, no mcf.
# Used by `compare --fast` for the per-extraction refactor check;
# the full corpus (incl. mcf) gates each top-level step / commit.
_FAST_SEEDS = _SEEDS[:3]


def _produce(dest: pathlib.Path, work: pathlib.Path,
             fast: bool = False) -> dict:
    """Trace the corpus into @dest; return the manifest dict.
    @fast restricts to _FAST_SEEDS genval only (no mcf)."""
    dest.mkdir(parents=True, exist_ok=True)
    manifest: dict = {}
    seeds = _FAST_SEEDS if fast else _SEEDS

    for seed in seeds:
        for isa in _ISAS:
            try:
                binp = _gen_build(seed, isa, work)
            except RuntimeError as e:
                print(f"  SKIP g_{seed:04x}_{isa}: {e}")
                continue
            qemu = _BUILD / _ISA_QEMU[isa]
            if not qemu.is_file():
                print(f"  SKIP {isa}: {qemu} not built")
                continue
            for wp in (0, 1):
                key = f"g_{seed:04x}_{isa}_wp{wp}"
                ob = dest / key
                try:
                    cst = _trace(qemu, binp, [], wp, _GEN_STOP, ob)
                except RuntimeError as e:
                    print(f"  FAIL {key}: {e}")
                    manifest[key] = {"error": str(e)}
                    continue
                manifest[key] = {
                    "body_sha": _body_sha(cst),
                    "tmpl_sha": _tmpl_sha(cst),
                    "size": cst.stat().st_size,
                    "audit": _audit(cst),
                    "wp": wp,
                }
                print(f"  {key}: {manifest[key]['size']} B")

    # SPEC mcf, x86_64, first 20M insns.  Skipped in --fast.
    if not fast and _MCF_BIN.resolve().is_file():
        mwd = _mcf_workdir(work)
        qemu = _BUILD / _ISA_QEMU["x86_64"]
        for wp in (0, 1):
            key = f"mcf_x86_64_20M_wp{wp}"
            ob = dest / key
            try:
                cst = _trace(qemu, _MCF_BIN.resolve(), ["inp.in"],
                             wp, _MCF_STOP, ob, cwd=mwd)
            except RuntimeError as e:
                print(f"  FAIL {key}: {e}")
                manifest[key] = {"error": str(e)}
                continue
            manifest[key] = {
                "body_sha": _body_sha(cst),
                "tmpl_sha": _tmpl_sha(cst),
                "size": cst.stat().st_size,
                "audit": _audit(cst),
                "wp": wp,
            }
            print(f"  {key}: {manifest[key]['size']} B")
    elif fast:
        print("  SKIP mcf: --fast (genval subset only)")
    else:
        print(f"  SKIP mcf: binary not found ({_MCF_BIN})")

    return manifest


def cmd_build(args) -> int:
    ref = _HERE / "_ref"
    work = _HERE / "_work"
    if ref.exists():
        shutil.rmtree(ref)
    print("Producing reference corpus...")
    manifest = _produce(ref, work)
    (ref / "manifest.json").write_text(json.dumps(manifest, indent=2,
                                                  sort_keys=True))
    ok = sum(1 for v in manifest.values() if "error" not in v)
    print(f"\nReference: {ok}/{len(manifest)} traces -> "
          f"{ref/'manifest.json'}")
    return 0 if ok == len(manifest) else 1


def _cmp_entry(key: str, ref: dict, cur: dict) -> list[str]:
    if "error" in ref or "error" in cur:
        return [f"{key}: error ref={ref.get('error')} "
                f"cur={cur.get('error')}"]
    diffs = []
    wp = ref.get("wp", 0)
    # mcf is a real dynamic glibc binary: the reproducibility recipe
    # pins host ASLR + AT_RANDOM, but guest-side address variation
    # (brk/mmap/malloc pointer values captured by memdata=1) is not
    # pinned, so its body byte-stream is not run-to-run stable even
    # at wp=0.  Its structure *is* stable, so mcf is checked via the
    # aggregate subset only (both wp).  The synthetic freestanding
    # genval corpus (proven byte-exact, all ISAs/opcodes) is the
    # byte-level regression oracle.
    is_mcf = key.startswith("mcf")
    if wp == 0 and not is_mcf:
        # wp0 genval is fully deterministic: body record stream +
        # template dictionary + every audit stat byte/stat-identical.
        if ref["body_sha"] != cur["body_sha"]:
            diffs.append(f"{key}: body.cst mismatch (wp0 byte-exact) "
                         f"ref={ref['body_sha'][:12]} "
                         f"cur={cur['body_sha'][:12]}")
        if ref["tmpl_sha"] != cur["tmpl_sha"]:
            diffs.append(f"{key}: template-dict mismatch "
                         f"ref={ref['tmpl_sha'][:12]} "
                         f"cur={cur['tmpl_sha'][:12]}")
        keys = ref["audit"].keys()
    else:
        # wp1 (WP-on-uninitialised-memory residue) and all mcf:
        # only the run-stable aggregate subset is a valid oracle.
        keys = _WP_STABLE_KEYS
    for k in keys:
        rv = ref["audit"].get(k)
        cv = cur["audit"].get(k)
        if rv != cv:
            diffs.append(f"{key}: audit.{k} ref={rv} cur={cv}")
    return diffs


def cmd_compare(args) -> int:
    ref = _HERE / "_ref"
    mf = ref / "manifest.json"
    if not mf.is_file():
        print(f"no reference manifest ({mf}); run `build` first")
        return 2
    ref_manifest = json.loads(mf.read_text())
    cmp_dir = _HERE / "_cmp"
    work = _HERE / "_work"
    if cmp_dir.exists():
        shutil.rmtree(cmp_dir)
    fast = getattr(args, "fast", False)
    print(f"Re-tracing {'fast subset' if fast else 'corpus'} "
          f"for comparison...")
    cur_manifest = _produce(cmp_dir, work, fast=fast)

    # Compare every trace we just produced against the reference.
    # In --fast we only produce a subset, so reference-only keys are
    # expected and not flagged; a full run additionally checks that
    # every reference trace was reproduced.
    all_diffs: list[str] = []
    missing = []
    for key in sorted(cur_manifest):
        if key not in ref_manifest:
            missing.append(f"{key}: not in reference")
            continue
        all_diffs += _cmp_entry(key, ref_manifest[key],
                                cur_manifest[key])
    if not fast:
        for key in sorted(ref_manifest):
            if key not in cur_manifest:
                missing.append(f"{key}: not reproduced")

    if not args.keep:
        shutil.rmtree(cmp_dir, ignore_errors=True)

    n = len(cur_manifest)
    if not all_diffs and not missing:
        print(f"\nPASS: {n}/{n} traces match the reference "
              f"({'fast subset; ' if fast else ''}genval wp0 "
              f"byte-exact, mcf/wp1 stable-stats).")
        return 0
    for d in missing + all_diffs:
        print(f"  !! {d}")
    print(f"\nFAIL: {len(all_diffs)+len(missing)} discrepancies "
          f"over {n} traces.")
    return 1


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build")
    cp = sub.add_parser("compare")
    cp.add_argument("--keep", action="store_true",
                    help="keep the freshly traced _cmp/ set")
    cp.add_argument("--fast", action="store_true",
                    help="inner-loop subset (3 genval seeds x 4 ISA "
                         "x {wp0,wp1}, no mcf) for per-extraction "
                         "refactor checks")
    args = ap.parse_args(argv[1:])
    if args.cmd == "build":
        return cmd_build(args)
    if args.cmd == "compare":
        return cmd_compare(args)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
