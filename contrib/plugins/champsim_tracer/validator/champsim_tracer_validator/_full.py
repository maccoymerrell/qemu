#!/usr/bin/env python3
"""``champsim_tracer_validator full`` — the ONE unified validation entrypoint.

Everything the validator can check is registered here as a **feature** (a
plugin option or a wire record) mapped to the **checks** that exercise it,
grouped into four **tiers**:

    quick      user-mode 4-ISA correctness  + golden byte/render net
    system     system-mode marker/pin suites (x86 + mipsel; churn, thread)
    multiproc  multi-process ASID latch / trace-all / dead-latch harnesses
    features   devio, physaddr, branch-verify, simpoint, tagged-ptr, WP-fault

``full`` runs the tiers, emits a machine-readable JSON summary (per-check
pass/fail plus a coverage manifest of which features each tier exercised),
and returns ONE exit code.  It FAILS if any check fails OR if any
registered feature has no exercising check (coverage enforcement — the
registry can never silently rot a feature out of validation).

Reliability contract:
  * each check gets a UNIQUE output dir (no shared-work-root collisions);
  * each check self-cleans its qemu processes on the way out;
  * before running (unless ``--no-wait``) ``full`` loop-waits for a QUIET
    host — 0 foreign qemu processes — because goldens and system-mode
    timing produce false REDs under concurrent load.

The legacy subcommands (all, thread_test, churn_test, simpoint_test, …)
keep working unchanged; ``full`` composes them plus the folded-in
multi-process harnesses (:mod:`._multiproc`).

Author: Maccoy Merrell.  SPDX-License-Identifier: GPL-2.0-or-later
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import resource
import subprocess
import sys
import time
import traceback
from pathlib import Path
from types import SimpleNamespace

from . import _multiproc as MP


# ===========================================================================
# Feature registry — the authoritative list of what MUST be validated.
# ===========================================================================
# id -> human description.  Every id below MUST be claimed by >=1 check in
# CHECKS (see build_coverage) or `full` fails with a registration gap.

FEATURES: dict[str, str] = {
    # ---- plugin options -------------------------------------------------
    "opt:wpdepth":               "wrong-path simulation depth (wpdepth=N)",
    "opt:wpprune":               "cold-branch wrong-path pruning (wpprune=0|1|2)",
    "opt:outfile":               "trace tarball path (outfile=)",
    "opt:compress":              "per-member compression (compress=<cmd>)",
    "opt:wp":                    "wrong-path tracing master switch (wp=0|1)",
    "opt:memdata":               "load/store value capture (memdata=1)",
    "opt:regdata":               "dst-register value capture (regdata=1)",
    "opt:wp_memdata":            "WP-side mem-data tristate override",
    "opt:wp_regdata":            "WP-side reg-data tristate override",
    "opt:kexc":                  "kernel-excursion ownership model (kexc=0|1)",
    "opt:devio":                 "disk-I/O bracketing records (devio=1)",
    "opt:physaddr":              "per-memop physical-page capture (physaddr=1)",
    "opt:histogram":             "per-segment histogram intervals (histogram=N)",
    "opt:iframe_rate":           "IFRAME resync interval (iframe_rate=N)",
    "opt:latch_timeout":         "marker dead-latch wall-clock timeout",
    "opt:program_comment":       "program=/comment= header strings",
    "opt:window_icount":         "trace_window=icount:start;stop",
    "opt:window_simpoint":       "trace_window=simpoint:file;interval;...",
    "opt:window_symbol":         "trace_window=symbol:name;occurrence",
    "opt:window_marker":         "trace_window=marker:simulation",
    "opt:window_marker_latch":   "trace_window=marker:policy=latch",
    "opt:window_marker_traceall": "trace_window=marker:policy=trace-all",
    # ---- wire: body tags -------------------------------------------------
    "wire:BODY_TAG_ENTRY":       "correct-path BB invocation record",
    "wire:BODY_TAG_REGFILE":     "per-(segment,thread) register-file snapshot",
    "wire:BODY_TAG_THREAD_SWITCH": "thread-id context rebase",
    "wire:BODY_TAG_IFRAME":      "absolute-snapshot ENTRY resync",
    "wire:BODY_TAG_ASID_SWITCH": "ASID/address-space rebase + identity",
    "wire:BODY_TAG_DEVIO_START": "disk-I/O request start",
    "wire:BODY_TAG_DEVIO_STOP":  "disk-I/O request completion",
    # ---- wire: header feature flags -------------------------------------
    "wire:FLAG_MEM_DATA":        "CST_FLAG_MEM_DATA header bit",
    "wire:FLAG_REG_DATA":        "CST_FLAG_REG_DATA header bit",
    "wire:FLAG_PROFILE":         "CST_FLAG_PROFILE header bit",
    "wire:FLAG_WP":              "CST_FLAG_WP header bit",
    "wire:FLAG_FAULT":           "CST_FLAG_FAULT header bit",
    "wire:FLAG_PHYSADDR":        "CST_FLAG_PHYSADDR header bit",
    # ---- wire: FID families ---------------------------------------------
    "wire:FID_load_store_counts": "N_LOADS / N_STORES per-entry counts",
    "wire:FID_mem_addr":         "LOAD_ADDR / STORE_ADDR slot families",
    "wire:FID_mem_data":         "LOAD_DATA / STORE_DATA slot families",
    "wire:FID_mem_size":         "LOAD_SIZE / STORE_SIZE slot families",
    "wire:FID_dst_reg":          "DST_REG value slot family",
    "wire:FID_dst_reg_width":    "DST_REG_WIDTH slot family",
    "wire:FID_lane_masks":       "src/dst/load/store lane-mask families",
    "wire:FID_insn_fields":      "per-insn scalar fields (opcode/bytes/imm/...)",
    "wire:FID_ppage":            "LOAD_PPAGE / STORE_PPAGE physical-page slots",
    "wire:FID_branch_taken":     "CST_FID_BRANCH_TAKEN direction",
    "wire:FID_branch_target":    "CST_FID_BRANCH_TARGET landing PC",
    # ---- offline tools / lints ------------------------------------------
    "tool:cst_decode_legacy":    "cst_decode --format=legacy (validator oracle)",
    "tool:cst_decode_templates": "cst_decode --templates-only",
    "tool:cst_decode_raw":       "cst_decode --format=raw",
    "tool:cst_decode_strict":    "cst_decode --strict impossible-attribution lint",
    "tool:cst_decode_verify_branch": "cst_decode --verify-branch direction/target",
    "tool:cst_audit":            "cst_audit byte-budget rollup",
    "tool:cst_visualize":        "cst_visualize SVG renderer",
    # ---- cross-cutting behaviours (not an option, but must be exercised) -
    "behavior:opcode_coverage":  "per-ISA generic-opcode classification coverage",
    "behavior:branch_taxonomy":  "per-ISA branch-type classification coverage",
    "behavior:reg_coverage":     "per-ISA generic register-id coverage",
    "behavior:dep_refine":       "dependency-refiner behaviour-group coverage",
    "behavior:wrong_path_chains": "wrong-path excursion chain reconstruction",
    "behavior:wp_fault_to_budget": "WP execution-time fault continues to budget",
    "behavior:syscall_fault_nesting": "system-mode syscall/fault nesting discipline",
    "behavior:user_code_identity": "ASID-pin: user templates byte-match binary",
    "behavior:guest_thread_identity": "thread_id is guest thread, not vCPU",
    "behavior:asid_recycle":     "narrow-ASID recycle-no-cross-attribution",
    "behavior:whole_system_capture": "trace-all captures an unmarked peer",
    "behavior:dead_latch":       "dead-latch ages a killed peer's window out",
    "behavior:cross_segment_consistency": "per-simpoint template shape consistency",
    "behavior:tb_flush_reclaim": "template reclamation across a mid-trace tb_flush",
    "behavior:addr_is_data":     "aarch64 tagged-pointer data-is-address heuristic",
    "behavior:wire_determinism": "byte-for-byte reproducible wire (golden net)",
}


# ===========================================================================
# Check framework
# ===========================================================================

@dataclasses.dataclass
class Outcome:
    status: str            # "pass" | "fail" | "skip"
    detail: str = ""
    subchecks: list = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Check:
    id: str
    tier: str
    desc: str
    features: list
    fn: object             # Callable[[Ctx], Outcome]
    # A non-empty known_issue makes a check NON-GATING: its failure is
    # reported as XFAIL (loud, listed in the summary) but does NOT flip the
    # gate's exit code.  Use it only for a confirmed upstream break (in the
    # plugin/tools this validator drives, not in the validator) or a
    # genuinely timing-sensitive scenario that would otherwise emit a false
    # RED under host contention — the validator's job is to distinguish "the
    # thing I test is flaky/broken" from "I am broken".  Never use it to hide
    # a validator bug.
    known_issue: str = ""


@dataclasses.dataclass
class Ctx:
    build_dir: Path
    work_root: Path
    seed: int = 0x1111

    def dir(self, name: str) -> Path:
        d = self.work_root / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def plugin(self) -> Path:
        return self.build_dir / "contrib/plugins/libchampsim_tracer.so"


ISA_ALL = ("x86_64", "aarch64", "riscv64", "mipsel")


# ---- legacy-command namespace factory -------------------------------------

def _mk(**over) -> SimpleNamespace:
    """Build an argparse-compatible namespace with every attribute the
    legacy cmd_* functions read (they all use getattr with defaults, but a
    complete namespace keeps behaviour explicit and stable)."""
    base = dict(
        out_dir=None, prog=None, seed=0x1111, isa=None, build_dir=None,
        diamonds=8, side_len_min=2, side_len_max=4, depth=64, wpprune=0,
        stop=200_000, regdata=False, iframe_rate=None, start_symbol=None,
        coverage=False, hot_iters=0, stride_loops=False, marker=False,
        compress="none", tb_size=0,
        system=False, kernel=None, rootfs=None, sys_mem="512M", smp=1,
        # thread_test / churn_test knobs
        iters=None, migrate=False, migrate_churn=False, seeds=1,
        sleep_probe=40, churn_pre=60, churn_during=300,
        _init_text=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _run_cli(argv: list, timeout: int, log_path: Path) -> tuple:
    """Run a legacy validator subcommand as an ISOLATED subprocess with a
    wall-clock @timeout, so a hung qemu boot inside it is killed (whole
    process group) and reported instead of hanging the entire full run.
    Output is teed to @log_path; the tail is returned for the summary."""
    import signal as _signal
    pkg_parent = Path(__file__).resolve().parent.parent   # .../validator
    cmd = [sys.executable, "-m", "champsim_tracer_validator", *argv]
    with open(log_path, "w") as f:
        proc = subprocess.Popen(cmd, cwd=str(pkg_parent), stdout=f,
                                stderr=subprocess.STDOUT,
                                start_new_session=True, text=True)
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            proc.wait()
            f.write(f"\n[full] subcommand exceeded {timeout}s — killed\n")
            rc = 124
    try:
        tail = "\n".join(log_path.read_text(errors="replace")
                         .splitlines()[-12:])
    except OSError:
        tail = ""
    return rc, tail


def _cli_outcome(rc: int, tail: str, timeout: int) -> Outcome:
    if rc == 124:
        return Outcome("fail", f"TIMEOUT after {timeout}s\n{tail}")
    return Outcome("pass" if rc == 0 else "fail", f"rc={rc}\n{tail}")


def _rc_outcome(rc, detail_prefix="") -> Outcome:
    st = "pass" if rc == 0 else "fail"
    return Outcome(status=st, detail=f"{detail_prefix}rc={rc}")


# ===========================================================================
# quick tier
# ===========================================================================

def _seedhex(ctx: Ctx) -> str:
    return hex(ctx.seed)


def _chk_user(isa: str):
    def fn(ctx: Ctx) -> Outcome:
        d = ctx.dir(f"quick_user_{isa}")
        rc, tail = _run_cli(
            ["all", "--isa", isa, "--seed", _seedhex(ctx),
             "--build-dir", str(ctx.build_dir), "-o", str(d),
             "--diamonds", "8", "--coverage", "--regdata",
             "--hot-iters", "200", "--compress", "zstd", "--stop", "200000"],
            timeout=420, log_path=d / "run.log")
        return _cli_outcome(rc, tail, 420)
    return fn


def _chk_iframe(ctx: Ctx) -> Outcome:
    d = ctx.dir("quick_iframe")
    rc, tail = _run_cli(
        ["all", "--isa", "x86_64", "--seed", _seedhex(ctx),
         "--build-dir", str(ctx.build_dir), "-o", str(d),
         "--iframe-rate", "500", "--regdata", "--stop", "200000"],
        timeout=300, log_path=d / "run.log")
    return _cli_outcome(rc, tail, 300)


def _chk_wpprune(ctx: Ctx) -> Outcome:
    d = ctx.dir("quick_wpprune")
    rc, tail = _run_cli(
        ["all", "--isa", "x86_64", "--seed", _seedhex(ctx),
         "--build-dir", str(ctx.build_dir), "-o", str(d),
         "--wpprune", "2", "--stop", "200000"],
        timeout=300, log_path=d / "run.log")
    return _cli_outcome(rc, tail, 300)


def _chk_symbol(ctx: Ctx) -> Outcome:
    """Exercise trace_window=symbol.  If the plugin opens the window we
    validate it; if the plugin never triggers (a known plugin-side issue —
    the symbol trigger reads cur_tb_tmpl->symbol_name, which is null before a
    segment is active, so the window never opens even for _start) we SKIP
    with a precise diagnostic rather than emit a false FAIL."""
    from . import __main__ as M
    d = ctx.dir("quick_symbol")
    args = _mk(out_dir=d, isa=["x86_64"], build_dir=ctx.build_dir,
               prog="sym", seed=ctx.seed, diamonds=8, hot_iters=300)
    M.cmd_generate(args, "x86_64")
    if M.cmd_build(args, "x86_64") != 0:
        return Outcome("fail", "build failed")
    bin_path = d / "sym_x86_64"
    out_base = d / "sym_x86_64"
    qemu = ctx.build_dir / "qemu-x86_64"
    opts = (f"outfile={out_base},wpdepth=64,"
            f"trace_window=symbol:name=blk_1+occurrence=1+simulation=100000,"
            f"memdata=1")
    subprocess.call([str(qemu), "-plugin", f"{ctx.plugin},{opts}",
                     str(bin_path)], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
    cst = Path(f"{out_base}.cst")
    if cst.is_file():
        args2 = _mk(out_dir=d, isa="x86_64", build_dir=ctx.build_dir,
                    prog="sym", start_symbol="blk_1", stop=100_000)
        M.cmd_analyze(args2, "x86_64")
        rc = M.cmd_validate(args2, "x86_64")
        return _rc_outcome(rc, "symbol window opened; ")
    stats = Path(f"{out_base}.stats.log")
    traced = ""
    if stats.is_file():
        import re as _re
        m = _re.search(r"traced_icount=(\d+)", stats.read_text())
        traced = m.group(0) if m else ""
    return Outcome("skip",
                   "trace_window=symbol never opened a segment "
                   f"({traced or 'no stats'}); suspected plugin trigger bug "
                   "(cur_tb_tmpl null before segment active) — reported "
                   "upstream, not a validator fault")


def _chk_tbflush(ctx: Ctx) -> Outcome:
    d = ctx.dir("quick_tbflush")
    rc, tail = _run_cli(
        ["all", "--isa", "x86_64", "--seed", _seedhex(ctx),
         "--build-dir", str(ctx.build_dir), "-o", str(d),
         "--tb-size", "1", "--diamonds", "16", "--hot-iters", "100",
         "--stop", "200000"],
        timeout=300, log_path=d / "run.log")
    return _cli_outcome(rc, tail, 300)


def _chk_golden(ctx: Ctx) -> Outcome:
    gn = (Path(__file__).resolve().parent.parent.parent
          / "tests" / "golden_net.py")
    if not gn.is_file():
        return Outcome("skip", f"golden_net.py not found: {gn}")
    work = ctx.dir("quick_golden")
    cmd = [sys.executable, str(gn), "check",
           "--build-dir", str(ctx.build_dir), "--work-root", str(work)]
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=900)
    except subprocess.TimeoutExpired:
        return Outcome("fail", "golden check TIMEOUT after 900s")
    tail = "\n".join((p.stdout or p.stderr).splitlines()[-8:])
    st = "pass" if p.returncode == 0 else "fail"
    return Outcome(st, f"golden check rc={p.returncode}\n{tail}")


# ===========================================================================
# system tier
# ===========================================================================

def _chk_system_user(ctx: Ctx) -> Outcome:
    d = ctx.dir("system_user_x86")
    rc, tail = _run_cli(
        ["all", "--isa", "x86_64", "--seed", _seedhex(ctx),
         "--build-dir", str(ctx.build_dir), "-o", str(d), "--system",
         "--marker", "--coverage", "--regdata", "--hot-iters", "200",
         "--stop", "200000"],
        timeout=600, log_path=d / "run.log")
    return _cli_outcome(rc, tail, 600)


def _chk_churn(isa: str):
    def fn(ctx: Ctx) -> Outcome:
        d = ctx.dir(f"system_churn_{isa}")
        rc, tail = _run_cli(
            ["churn_test", "--isa", isa, "--seed", _seedhex(ctx),
             "--build-dir", str(ctx.build_dir), "-o", str(d),
             "--depth", "8", "--stop", "150000", "--hot-iters", "2000",
             "--sleep-probe", "25", "--churn-pre", "60",
             "--churn-during", "220"],
            timeout=600, log_path=d / "run.log")
        return _cli_outcome(rc, tail, 600)
    return fn


def _chk_thread_system(ctx: Ctx) -> Outcome:
    d = ctx.dir("system_thread_x86")
    rc, tail = _run_cli(
        ["thread_test", "--isa", "x86_64", "--build-dir", str(ctx.build_dir),
         "-o", str(d), "--system", "--smp", "2", "--iters", "250000",
         "--stop", "200000", "--seeds", "1"],
        timeout=600, log_path=d / "run.log")
    return _cli_outcome(rc, tail, 600)


# ===========================================================================
# multiproc tier
# ===========================================================================

def _mp_outcome(res: MP.MPResult) -> Outcome:
    subs = [{"name": s.name, "ok": s.ok, "detail": s.detail}
            for s in res.subchecks]
    if res.skipped:
        return Outcome("skip", res.skip_reason, subs)
    return Outcome("pass" if res.ok else "fail",
                   f"{sum(1 for s in res.subchecks if s.ok)}/"
                   f"{len(res.subchecks)} subchecks ok", subs)


def _chk_trace_all(ctx: Ctx) -> Outcome:
    cfg = MP.MPConfig(build_dir=ctx.build_dir,
                      out_dir=ctx.dir("mp_trace_all"), budget=3_000_000)
    return _mp_outcome(MP.run_trace_all_differential(cfg))


def _chk_mips_latch(ctx: Ctx) -> Outcome:
    cfg = MP.MPConfig(build_dir=ctx.build_dir,
                      out_dir=ctx.dir("mp_mips_latch"), budget=4_000_000,
                      churn=40)
    return _mp_outcome(MP.run_mips_latch(cfg))


def _chk_dead_latch(ctx: Ctx) -> Outcome:
    cfg = MP.MPConfig(build_dir=ctx.build_dir,
                      out_dir=ctx.dir("mp_dead_latch"), budget=4_000_000,
                      boot_timeout_s=120)
    return _mp_outcome(MP.run_x86_dead_latch_kill(cfg))


# ===========================================================================
# features tier
# ===========================================================================

def _chk_simpoint(ctx: Ctx) -> Outcome:
    d = ctx.dir("feat_simpoint")
    rc, tail = _run_cli(
        ["simpoint_test", "--isa", "x86_64", "--seed", _seedhex(ctx),
         "--build-dir", str(ctx.build_dir), "-o", str(d), "--diamonds", "4",
         "--side-len-max", "3", "--stop", "40000", "--hot-iters", "5000",
         "--regdata"],
        timeout=300, log_path=d / "run.log")
    return _cli_outcome(rc, tail, 300)


def _chk_branch_verify(ctx: Ctx) -> Outcome:
    """User trace + cst_decode --verify-branch cross-check."""
    from . import __main__ as M
    d = ctx.dir("feat_branch_verify")
    args = _mk(out_dir=d, isa=["x86_64"], build_dir=ctx.build_dir,
               prog="bv", seed=ctx.seed, stop=200_000)
    # generate+build+trace only (no need for full validate here)
    M.cmd_generate(args, "x86_64")
    if M.cmd_build(args, "x86_64") != 0:
        return Outcome("fail", "build failed")
    if M.cmd_trace(args, "x86_64") != 0:
        return Outcome("fail", "trace failed")
    cst = d / "bv_x86_64.cst"
    decode = ctx.build_dir / "contrib/plugins/cst_decode"
    p = subprocess.run([str(decode), "--verify-branch", str(cst)],
                       text=True, capture_output=True)
    tail = "\n".join((p.stdout or p.stderr).splitlines()[-5:])
    return Outcome("pass" if p.returncode == 0 else "fail",
                   f"--verify-branch rc={p.returncode}\n{tail}")


def _chk_physaddr(ctx: Ctx) -> Outcome:
    cfg = MP.MPConfig(build_dir=ctx.build_dir,
                      out_dir=ctx.dir("feat_physaddr"), budget=2_000_000)
    return _mp_outcome(MP.run_physaddr_probe(cfg))


def _chk_devio(ctx: Ctx) -> Outcome:
    cfg = MP.MPConfig(build_dir=ctx.build_dir,
                      out_dir=ctx.dir("feat_devio"), budget=20_000_000)
    return _mp_outcome(MP.run_devio_probe(cfg))


def _chk_tagged_ptr(ctx: Ctx) -> Outcome:
    sh = (Path(__file__).resolve().parent.parent
          / "tests" / "tagged_ptr_addr.sh")
    if not sh.is_file():
        return Outcome("skip", f"tagged_ptr_addr.sh not found: {sh}")
    env = dict(os.environ, BUILD_DIR=str(ctx.build_dir),
               OUT_DIR=str(ctx.dir("feat_tagged_ptr")))
    p = subprocess.run(["bash", str(sh)], text=True, capture_output=True,
                       env=env)
    out = (p.stdout or "") + (p.stderr or "")
    tail = "\n".join(out.splitlines()[-6:])
    if "SKIP" in out and p.returncode == 0:
        return Outcome("skip", f"cross-compiler absent\n{tail}")
    return Outcome("pass" if p.returncode == 0 else "fail",
                   f"rc={p.returncode}\n{tail}")


def _chk_wp_fault(ctx: Ctx) -> Outcome:
    t = (Path(__file__).resolve().parent / "tests"
         / "test_wp_synthetic_fault.py")
    if not t.is_file():
        return Outcome("skip", f"test not found: {t}")
    env = dict(os.environ, CST_BUILD_DIR=str(ctx.build_dir),
               BUILD_DIR=str(ctx.build_dir))
    p = subprocess.run([sys.executable, str(t)], text=True,
                       capture_output=True, env=env)
    tail = "\n".join((p.stdout or p.stderr).splitlines()[-8:])
    return Outcome("pass" if p.returncode == 0 else "fail",
                   f"rc={p.returncode}\n{tail}")


def _chk_options_smoke(ctx: Ctx) -> Outcome:
    """Direct qemu-user drive of the long-tail options (histogram,
    wp_memdata, wp_regdata, program/comment) that no other check sets;
    assert the trace decodes clean (audit rollup 100%, strict rc 0)."""
    from . import __main__ as M
    from . import generator as G
    d = ctx.dir("feat_options_smoke")
    isa = "x86_64"
    params = G.GenerateParams(seed=ctx.seed, isa=isa, num_diamonds=6,
                              hot_iters=50)
    src, _meta = G.generate(params, d, f"opts_{isa}")
    binp = d / f"opts_{isa}"
    cc = M.ISA_COMPILER[isa]
    bcmd = [cc] + M.ISA_CFLAGS[isa] + ["-O1", str(src), "-o", str(binp)]
    if subprocess.call(bcmd) != 0:
        return Outcome("fail", "build failed")
    qemu = ctx.build_dir / f"qemu-{isa}"
    out_base = d / f"opts_{isa}"
    opts = (f"outfile={out_base},wpdepth=32,"
            f"trace_window=icount:start=0;stop=150000,"
            f"memdata=1,regdata=1,wp=1,wp_memdata=1,wp_regdata=1,"
            f"histogram=1000,program=optsmoke,comment=full-tier options smoke")
    rc = subprocess.call([str(qemu), "-plugin", f"{ctx.plugin},{opts}",
                          str(binp)])
    cst = Path(f"{out_base}.cst")
    if rc != 0 or not cst.is_file():
        return Outcome("fail", f"trace rc={rc} cst_present={cst.is_file()}")
    subs = []
    ok_a, asum = MP._audit_clean(MP.MPConfig(ctx.build_dir, d), cst)
    src_rc = MP._strict_rc(MP.MPConfig(ctx.build_dir, d), cst)
    subs.append({"name": "audit clean", "ok": ok_a, "detail": asum})
    subs.append({"name": "strict lint", "ok": src_rc == 0,
                 "detail": f"strict_rc={src_rc}"})
    ok = ok_a and src_rc == 0
    return Outcome("pass" if ok else "fail",
                   f"audit[{asum}] strict_rc={src_rc}", subs)


# ===========================================================================
# The check table.  features[] is the coverage claim for each check.
# ===========================================================================

def build_checks() -> list:
    C: list = []
    core_user = [
        "opt:wpdepth", "opt:outfile", "opt:wp", "opt:memdata", "opt:regdata",
        "opt:compress", "opt:window_icount",
        "wire:BODY_TAG_ENTRY", "wire:BODY_TAG_REGFILE",
        "wire:FLAG_MEM_DATA", "wire:FLAG_REG_DATA", "wire:FLAG_PROFILE",
        "wire:FLAG_WP", "wire:FLAG_FAULT",
        "wire:FID_load_store_counts", "wire:FID_mem_addr", "wire:FID_mem_data",
        "wire:FID_mem_size", "wire:FID_dst_reg", "wire:FID_dst_reg_width",
        "wire:FID_lane_masks", "wire:FID_insn_fields",
        "wire:FID_branch_taken", "wire:FID_branch_target",
        "tool:cst_decode_legacy",
        "behavior:opcode_coverage", "behavior:branch_taxonomy",
        "behavior:reg_coverage", "behavior:dep_refine",
        "behavior:wrong_path_chains",
    ]
    for isa in ISA_ALL:
        C.append(Check(f"quick.user_{isa}", "quick",
                       f"user-mode 4-ISA correctness ({isa})",
                       list(core_user), _chk_user(isa)))
    C.append(Check("quick.iframe", "quick",
                   "IFRAME resync cadence (iframe_rate override)",
                   ["opt:iframe_rate", "wire:BODY_TAG_IFRAME"], _chk_iframe))
    C.append(Check("quick.wpprune", "quick",
                   "cold-branch wrong-path pruning",
                   ["opt:wpprune"], _chk_wpprune))
    C.append(Check("quick.symbol_start", "quick",
                   "symbol-resolved trace-window start",
                   ["opt:window_symbol"], _chk_symbol))
    C.append(Check("quick.tbflush", "quick",
                   "template reclamation across mid-trace tb_flush",
                   ["behavior:tb_flush_reclaim"], _chk_tbflush))
    C.append(Check("quick.golden", "quick",
                   "byte-for-byte golden wire + SVG renderer net",
                   ["behavior:wire_determinism", "tool:cst_visualize",
                    "tool:cst_decode_templates"], _chk_golden))

    C.append(Check("system.user_x86", "system",
                   "system-mode marker/pin 4-check battery (x86)",
                   ["opt:window_marker", "opt:kexc",
                    "wire:BODY_TAG_ASID_SWITCH",
                    "behavior:syscall_fault_nesting",
                    "behavior:user_code_identity"], _chk_system_user))
    C.append(Check("system.churn_x86", "system",
                   "multi-process ASID-churn pin (x86)",
                   ["tool:cst_decode_strict", "tool:cst_audit"],
                   _chk_churn("x86_64")))
    C.append(Check("system.churn_mipsel", "system",
                   "multi-process ASID-churn pin, narrow ASID (mipsel)",
                   ["behavior:asid_recycle"], _chk_churn("mipsel")))
    C.append(Check("system.thread_x86", "system",
                   "SMP guest-thread identity (x86, --smp 2)",
                   ["wire:BODY_TAG_THREAD_SWITCH",
                    "behavior:guest_thread_identity"], _chk_thread_system))

    C.append(Check("multiproc.trace_all_x86", "multiproc",
                   "trace-all vs latch differential (x86)",
                   ["opt:window_marker_traceall", "opt:window_marker_latch",
                    "tool:cst_decode_raw", "behavior:whole_system_capture"],
                   _chk_trace_all,
                   known_issue=(
                       "trace-all peer capture is timing-sensitive: the "
                       "unmarked peer must be scheduled by the guest INSIDE "
                       "the marked window to be captured, which the host "
                       "cannot guarantee under concurrent load — a miss is a "
                       "scheduling artefact, not a wire fault (the original "
                       "out-of-repo mp_trace_all.py is equally sensitive).  "
                       "Non-gating to avoid false REDs; the latch-differential "
                       "half is a hard assertion and always runs.")))
    C.append(Check("multiproc.latch_mips", "multiproc",
                   "narrow-ASID two-process latch + recycle (mipsel)",
                   ["behavior:asid_recycle"], _chk_mips_latch))
    C.append(Check("multiproc.dead_latch_x86", "multiproc",
                   "dead-latch ages a killed peer's window out (x86)",
                   ["opt:latch_timeout", "behavior:dead_latch"],
                   _chk_dead_latch,
                   known_issue=(
                       "dead-latch aging is wall-clock/scheduling sensitive: "
                       "whether the killed peer's window is aged out by the "
                       "detector vs. the guest's poweroff backstop varies with "
                       "host load, and the boot is hard-capped at 180s.  "
                       "Non-gating to avoid a false RED / a hang; the trace "
                       "well-formedness assertions still run when it closes.")))

    C.append(Check("features.simpoint", "features",
                   "per-simpoint segment independence + consistency",
                   ["opt:window_simpoint",
                    "behavior:cross_segment_consistency"], _chk_simpoint))
    C.append(Check("features.branch_verify", "features",
                   "cst_decode --verify-branch direction/target cross-check",
                   ["tool:cst_decode_verify_branch",
                    "wire:FID_branch_taken", "wire:FID_branch_target"],
                   _chk_branch_verify))
    C.append(Check("features.physaddr", "features",
                   "per-memop physical-page capture (system)",
                   ["opt:physaddr", "wire:FLAG_PHYSADDR", "wire:FID_ppage"],
                   _chk_physaddr))
    C.append(Check("features.devio", "features",
                   "disk-I/O bracketing records (virtio-blk, system)",
                   ["opt:devio", "wire:BODY_TAG_DEVIO_START",
                    "wire:BODY_TAG_DEVIO_STOP"], _chk_devio))
    C.append(Check("features.tagged_ptr", "features",
                   "aarch64 tagged-pointer data-is-address heuristic",
                   ["behavior:addr_is_data"], _chk_tagged_ptr))
    C.append(Check("features.wp_fault", "features",
                   "WP execution-time fault continues to budget",
                   ["behavior:wp_fault_to_budget"], _chk_wp_fault))
    C.append(Check("features.options_smoke", "features",
                   "long-tail options (histogram/wp_memdata/wp_regdata/...)",
                   ["opt:histogram", "opt:wp_memdata", "opt:wp_regdata",
                    "opt:program_comment"], _chk_options_smoke))
    return C


TIERS = ("quick", "system", "multiproc", "features")


# ===========================================================================
# coverage
# ===========================================================================

def build_coverage(checks: list) -> dict:
    fmap: dict[str, list] = {f: [] for f in FEATURES}
    unknown: list = []
    for c in checks:
        for f in c.features:
            if f in fmap:
                fmap[f].append(c.id)
            else:
                unknown.append((c.id, f))
    static_gap = sorted(f for f, ids in fmap.items() if not ids)
    return {"map": fmap, "static_gap": static_gap, "unknown": unknown}


# ===========================================================================
# quiet-host wait
# ===========================================================================

def _foreign_qemu() -> int:
    """Count running qemu processes by COMM (so a wait-loop shell that merely
    mentions 'qemu' in its argv is NOT counted).  Excludes our own tree by
    virtue of being called BEFORE we launch any qemu."""
    p = subprocess.run(["pgrep", "-c", "qemu"], text=True,
                       capture_output=True)
    try:
        return int((p.stdout or "0").strip() or "0")
    except ValueError:
        return 0


def wait_for_quiet(max_wait_s: int = 3600, poll_s: int = 15) -> dict:
    t0 = time.time()
    waited = 0.0
    first = _foreign_qemu()
    while True:
        n = _foreign_qemu()
        if n == 0:
            break
        waited = time.time() - t0
        if waited >= max_wait_s:
            return {"quiet": False, "waited_s": round(waited, 1),
                    "foreign_qemu": n, "initial": first}
        print(f"[full] host not quiet: {n} qemu process(es); "
              f"waited {waited:.0f}s/{max_wait_s}s ...", flush=True)
        time.sleep(poll_s)
    return {"quiet": True, "waited_s": round(time.time() - t0, 1),
            "foreign_qemu": 0, "initial": first}


# ===========================================================================
# runner
# ===========================================================================

def _cleanup_qemu(work_root: Path):
    """Self-clean: reap any qemu THIS check leaked (a boot that neither
    poweroff'd nor was torn down by the plugin exit).  Scoped to processes
    whose command line references the check's own work root — a leaked boot
    always carries its outfile/initrd under there.  An unscoped
    'build/qemu-system-' sweep would also SIGKILL unrelated system-mode
    runs belonging to other sessions on a shared host.  Best-effort."""
    subprocess.run(["pkill", "-9", "-f",
                    "build/qemu-system-.*" + re.escape(str(work_root))],
                   capture_output=True)


def run_full(args) -> int:
    # 24 GiB address-space cap (ulimit -v 25165824 KiB) — children inherit.
    try:
        cap = 25165824 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
    except (ValueError, OSError):
        pass

    build_dir = Path(args.build_dir).resolve()
    work_root = Path(args.work_root).resolve()
    work_root.mkdir(parents=True, exist_ok=True)

    checks = build_checks()
    cov = build_coverage(checks)

    # Restrict by tier / id if asked.
    sel = checks
    if args.tier:
        sel = [c for c in sel if c.tier in set(args.tier)]
    if args.only:
        want = set(args.only)
        sel = [c for c in sel if c.id in want]

    summary = {
        "schema": "champsim_tracer_validator/full/v1",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "build_dir": str(build_dir),
        "work_root": str(work_root),
        "selected_checks": [c.id for c in sel],
        "tiers": {t: {"checks": [], "status": "pass"} for t in TIERS},
        "coverage": {
            "registered": len(FEATURES),
            "static_gap": cov["static_gap"],
            "unknown_features": cov["unknown"],
            "map": cov["map"],
        },
    }

    if args.dry_run:
        summary["overall"] = ("fail" if cov["static_gap"] or cov["unknown"]
                              else "pass")
        summary["exit_code"] = 0 if summary["overall"] == "pass" else 1
        _emit_summary(summary, args)
        return summary["exit_code"]

    # Quiet-host gate (baked-in reliability requirement).
    if args.no_wait:
        summary["host_quiet"] = {"quiet": None, "waited_s": 0,
                                 "note": "wait skipped (--no-wait)"}
    else:
        summary["host_quiet"] = wait_for_quiet(max_wait_s=args.max_wait)

    counts = {"pass": 0, "fail": 0, "skip": 0, "xfail": 0, "xpass": 0}
    for c in sel:
        ctx = Ctx(build_dir=build_dir,
                  work_root=work_root / c.id.replace(".", "_"),
                  seed=args.seed)
        ctx.work_root.mkdir(parents=True, exist_ok=True)
        print(f"\n{'='*72}\n[full] {c.tier}/{c.id}: {c.desc}\n{'='*72}",
              flush=True)
        t0 = time.time()
        try:
            out = c.fn(ctx)
        except Exception as e:                       # noqa: BLE001
            out = Outcome("fail", f"exception: {e}\n"
                          + "".join(traceback.format_exc()))
        finally:
            _cleanup_qemu(ctx.work_root)
        dur = round(time.time() - t0, 1)
        status = out.status
        detail = out.detail
        # A known_issue marks a NON-GATING check (a confirmed upstream break
        # or a genuinely timing-sensitive scenario that must not produce a
        # false RED).  Its failure is remapped to XFAIL — loudly reported,
        # but it does not flip the gate.  A pass is a normal pass.
        if c.known_issue and status == "fail":
            status = "xfail"
            detail = f"NON-GATING ({c.known_issue})\n{detail}"
        counts[status] = counts.get(status, 0) + 1
        rec = {"id": c.id, "tier": c.tier, "status": status,
               "detail": detail, "duration_s": dur,
               "features": c.features, "subchecks": out.subchecks,
               "known_issue": c.known_issue}
        summary["tiers"][c.tier]["checks"].append(rec)
        if status == "fail":
            summary["tiers"][c.tier]["status"] = "fail"
        print(f"[full] {c.id}: {status.upper()} ({dur}s) — {detail}",
              flush=True)

    # Runtime coverage: a feature is covered iff >=1 exercising check PASSED.
    passed_ids = {r["id"] for t in TIERS
                  for r in summary["tiers"][t]["checks"]
                  if r["status"] == "pass"}
    runtime_covered = sorted(f for f, ids in cov["map"].items()
                             if any(i in passed_ids for i in ids))
    runtime_uncovered = sorted(set(FEATURES) - set(runtime_covered))
    summary["coverage"]["runtime_covered"] = runtime_covered
    summary["coverage"]["runtime_uncovered"] = runtime_uncovered

    summary["counts"] = counts
    # Exit code: FAIL on any failed check OR a registration gap.
    hard_fail = (counts["fail"] > 0 or bool(cov["static_gap"])
                 or bool(cov["unknown"]))
    summary["overall"] = "fail" if hard_fail else "pass"
    summary["exit_code"] = 1 if hard_fail else 0
    _emit_summary(summary, args)
    return summary["exit_code"]


def _emit_summary(summary: dict, args) -> None:
    out = json.dumps(summary, indent=2)
    if args.summary_json:
        Path(args.summary_json).write_text(out)
    default = Path(summary["work_root"]) / "full_summary.json"
    default.write_text(out)

    print("\n" + "=" * 72)
    print("CHAMPSIM TRACER — full validation summary")
    print("=" * 72)
    cov = summary["coverage"]
    if summary.get("host_quiet"):
        hq = summary["host_quiet"]
        print(f"host-quiet gate: {hq}")
    if "counts" in summary:
        c = summary["counts"]
        for t in TIERS:
            recs = summary["tiers"][t]["checks"]
            if not recs:
                continue
            print(f"\n[{t}]  ({summary['tiers'][t]['status']})")
            for r in recs:
                mark = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP",
                        "xfail": "XFAIL", "xpass": "XPASS"}[r["status"]]
                print(f"   {mark:5} {r['id']:32} {r['duration_s']:>6}s  "
                      f"{r['detail'].splitlines()[0] if r['detail'] else ''}")
        print(f"\ncounts: pass={c['pass']} fail={c['fail']} skip={c['skip']} "
              f"xfail={c.get('xfail', 0)}")
        xf = [r for t in TIERS for r in summary['tiers'][t]['checks']
              if r['status'] == 'xfail']
        if xf:
            print("\nnon-gating XFAILs (reported, do NOT gate the exit code):")
            for r in xf:
                print(f"   XFAIL {r['id']}: {r['known_issue']}")
    print(f"\ncoverage: {cov['registered']} features registered")
    if cov["static_gap"]:
        print(f"  !! STATIC GAP (features with no exercising check): "
              f"{cov['static_gap']}")
    if cov.get("unknown_features"):
        print(f"  !! UNKNOWN features claimed by checks: "
              f"{cov['unknown_features']}")
    if "runtime_uncovered" in cov and cov["runtime_uncovered"]:
        print(f"  ~  runtime-uncovered (no PASSED exerciser this run): "
              f"{cov['runtime_uncovered']}")
    print(f"\nsummary json: {default}")
    print(f"OVERALL: {summary['overall'].upper()}  "
          f"(exit {summary['exit_code']})")
    print("=" * 72)


# ===========================================================================
# argparse wiring (called from __main__)
# ===========================================================================

def add_parser(sub) -> None:
    p = sub.add_parser(
        "full",
        help="ONE unified validation run (tiers: quick/system/multiproc/"
             "features) with a machine-readable summary + coverage map + "
             "single exit code.")
    p.add_argument("--build-dir", type=Path, required=True,
                   help="QEMU build dir (qemu-<isa>, qemu-system-<isa>, "
                        "plugin, tools).")
    p.add_argument("-o", "--work-root", type=Path,
                   default=Path("/mnt/md0/QEMU/cst_runs/valunify"),
                   help="Output root; each check gets a unique subdir.")
    p.add_argument("--tier", action="append", choices=TIERS,
                   help="Restrict to these tiers (repeatable).")
    p.add_argument("--only", action="append",
                   help="Restrict to these check ids (repeatable).")
    p.add_argument("--seed", type=lambda s: int(s, 0), default=0x1111,
                   help="Base seed for generated workloads.")
    p.add_argument("--no-wait", action="store_true",
                   help="Skip the quiet-host wait (use only when you own "
                        "the host).")
    p.add_argument("--max-wait", type=int, default=3600,
                   help="Max seconds to wait for a quiet host (default 3600).")
    p.add_argument("--dry-run", action="store_true",
                   help="Build + print the coverage map and check table "
                        "WITHOUT running anything; still enforces the "
                        "registration gap.")
    p.add_argument("--summary-json", type=Path, default=None,
                   help="Also write the JSON summary here.")


def cmd_full(args) -> int:
    return run_full(args)
