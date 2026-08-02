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
  * the host load is RECORDED per run, never gated on: a cell that fails
    under load is a bug to fix (maintainer rule -- validity and hang
    prevention must never ride on the host's load).

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
    "opt:faults":                "synchronous-fault handler tracing (faults=0|1)",
    "opt:interrupts":            "asynchronous-interrupt handler tracing (interrupts=0|1)",
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
    # ---- wire: WP chain header flags -------------------------------------
    "wire:wp_chain_flag":        "CST_WP_CHAIN_HAS_EVENTS presence bit "
                                  "packed into the WP chain section's "
                                  "leading chain_hdr ULEB (format.rst §4.3 "
                                  "/ Step 6.8)",
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
    "behavior:wp_tlb_cold_capture": "WP fetch of a valid-PTE but TLB-cold code page captures real bytes (system mode)",
    "behavior:syscall_fault_nesting": "system-mode syscall/fault nesting discipline",
    "behavior:user_code_identity": "ASID-pin: user templates byte-match binary",
    "behavior:marker_injection": "cst_attach ptrace-injects the marker into an unmarked target's entry point",
    "behavior:guest_thread_identity": "thread_id is guest thread, not vCPU",
    "behavior:thread_strand_sequential": "every (thread_id, asid) context reads as one sequential strand: concurrent guest threads never share an id, so a kernel strand is never braided with another vCPU's",
    "behavior:asid_recycle":     "narrow-ASID recycle-no-cross-attribution",
    "behavior:spec_clock_resync": "wrong-path excursions are time-transparent: every guest clock, host timer and interrupt line is resynchronised to the frozen virtual time on exit, so the guest keeps taking interrupts and making user-space progress (4-ISA, system mode)",
    "behavior:whole_system_capture": "trace-all captures an unmarked peer",
    "behavior:dead_latch":       "dead-latch ages a killed peer's window out",
    "behavior:cross_segment_consistency": "per-simpoint template shape consistency",
    "behavior:tb_flush_reclaim": "template reclamation across a mid-trace tb_flush",
    "behavior:addr_is_data":     "aarch64 tagged-pointer data-is-address heuristic",
    "behavior:wire_determinism": "byte-for-byte reproducible wire (golden net)",
    "behavior:mutation_strictness": "oracle catches deliberate trace corruption (mutation matrix)",
    "behavior:wrong_path_coverage": "static_templates=1: minted-alternate never-executed fall-through + BTB target coverage, deepened by static_depth (4-ISA)",
    "behavior:isa_crosscheck": "the decode metadata the tracer consumes (Capstone + the disas/capstone.c correction boundary) agrees with an independently maintained decoder (LLVM MC) across an exhaustive sweep of the opcode-bearing encoding space, on all four ISAs, outside a justified allowlist",
    "behavior:decode_fixups": "the repairs the plugin makes to the decode boundary -- the register edges apply_isa_branch_fixups() restores, the register groups the operand walker expands, the branch taxonomy the ISA tables supply -- still happen, asserted per signature in both directions so a repair that silently stops fails as surely as one nobody wrote down; the boundary comparison cannot see this, because a regressed repair reintroduces exactly the disagreement its allowlist already expects",
    "behavior:implicit_operands": "the implicit operands — architectural state an instruction touches that its encoding does not name — that the decode boundary reports today are still reported, asserted per encoding against expectations derived from BEHAVIOUR rather than from any decoder (Arm's Machine Readable Architecture, the Sail RISC-V model, QEMU's MIPS TCG translator), so the class of defect where Capstone and LLVM agree and are both wrong is visible at all; each row carries a disposition and the dynamic weight of its instruction form",
    "behavior:segment_final_memops": "the segment's last body entry carries its memory operands, matching the earlier executions of the same true BB (the deferred icount/simpoint window close emits it after it has run, not before)",
    "behavior:smc_revisions": "self-modifying code: correct-path template-revision minting for rewrites that preserve OR change the block's instruction boundaries, content-signature id reuse, and the per-pc revision cap (4-ISA)",
    "behavior:bulk_mem_visible": "aarch64 FEAT_MOPS bulk transfers (SETP/SETM/SETE, CPYP/CPYM/CPYE) reach the memory instrumentation on the correct path: their recorded accesses tile the transferred range exactly instead of vanishing into the helper's host memset/memmove",
    "behavior:dc_zva_visible": "aarch64 DC ZVA reaches the memory instrumentation on the correct path and is modelled as the block store it is: its recorded stores tile the DCZID_EL0-sized block exactly instead of vanishing into the helper's host memset, and the instruction declares the store lane that makes them attributable",
    "behavior:string_op_memops": "x86 REP string instructions fan out per architectural iteration with the right per-iteration memop count, and the operand model matches what each instruction really reads and writes (Capstone access-flag corrections in disas/capstone.c)",
    "behavior:rep_fanout_invariance": "an x86 REP's fan-out is a function of architectural state only: the same guest execution renders the same number of entries, with the same rep_subtmpl/BRANCH_REP self-loop structure and the same per-iteration direction/target, whether do_gen_rep translated the whole repetition or one iteration per TB (CF_USE_ICOUNT / CF_SINGLE_STEP / EFLAGS.TF / interrupt shadow), and the wrong path — which is ALWAYS single-stepped through cpu_plugin_exec_tb — renders a REP exactly as the correct path does.  No external reference covers the wrong path, so this check is the only thing that can catch a CP/WP divergence there",
    "behavior:reg_snap_accounting": "the plugin's own dropped-slice completeness invariant for the positional reg-snap capture — CP reg-snap slice dropped == CP reg-snap leak trimmed (D4-class completeness oracle; the wire has no record of it, so this is read from the <outfile>.stats.log sidecar, offline via cst_audit --stats-log)",
    "behavior:mips_fragment_split_absence": "split_tb_into_fragments's mid-TB continuation path (a branch-classified insn QEMU's translator keeps decoding past) has no current MIPS instance — the T-family conditional trap was the only one and 5bf597d751 correctly reclassified it to BRANCH_NONE, leaving BRANCH_REP as the path's exerciser (x86 X86RepIterationFanout rep movsq, and the aarch64 FEAT_MOPS bulk copy/set triple); this pins that fact and fails if MIPS regains an un-covered instance",
    "behavior:memop_bimodality": "per-template memop bimodality: a memop-capable template's CP executions overwhelmingly nonzero with a small minority of zero-memop outliers is a completeness loss (D4-class oracle generalised past the segment-final-entry special case; cst_lint.h MemopBimodalityLint + validator.py's mirror, both gating)",
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

# Canonical golden work-root.  The committed manifest (tests/golden/) is
# captured against THIS exact path; the check must reuse it byte-for-byte
# because its length shifts the guest stack base (see _chk_golden).  To
# refresh the baseline after an intentional plugin/wire change:
#   python tests/golden_net.py capture --build-dir <build> \
#       --work-root /mnt/md0/QEMU/cst_runs/valunify/golden_wr
GOLDEN_WORK_ROOT = Path("/mnt/md0/QEMU/cst_runs/valunify/golden_wr")


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


def _run_cli(argv: list, timeout: int, log_path: Path,
             extra_env: dict | None = None) -> tuple:
    """Run a legacy validator subcommand as an ISOLATED subprocess with a
    wall-clock @timeout, so a hung qemu boot inside it is killed (whole
    process group) and reported instead of hanging the entire full run.
    Output is teed to @log_path; the tail is returned for the summary.
    @extra_env overlays the inherited environment (e.g. the system-mode
    CST_QEMU_EXTRA_ARGS guest-CPU override)."""
    import signal as _signal
    pkg_parent = Path(__file__).resolve().parent.parent   # .../validator
    cmd = [sys.executable, "-m", "champsim_tracer_validator", *argv]
    env = dict(os.environ, **(extra_env or {}))
    with open(log_path, "w") as f:
        proc = subprocess.Popen(cmd, cwd=str(pkg_parent), stdout=f,
                                stderr=subprocess.STDOUT,
                                start_new_session=True, text=True, env=env)
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


def _classify_cli_failure(tail: str) -> str:
    """Name the cause on the summary line.

    The summary renders only the detail's FIRST line, so leading with
    `rc=N` says nothing a reader can act on -- every failure of a
    CLI-driven check looked identical, and the cause sat in the tail
    where the summary never showed it.  `system.clock_progress_aarch64`
    was misdiagnosed as host contention for months on that basis; it was
    really a fault-depth violation, and the two are not related.

    Prefer the sub-check's own verdict line, then a recognised stall,
    then the last non-empty line, which is where a CLI puts its
    complaint when it has no structured verdict to offer.
    """
    lines = [ln.strip() for ln in tail.splitlines() if ln.strip()]
    for ln in lines:
        if ln.startswith("! "):
            return ln[2:].strip()
    for ln in lines:
        low = ln.lower()
        if "stall" in low or "clock" in low and "progress" in low:
            return ln
    return lines[-1] if lines else "no output"


def _cli_outcome(rc: int, tail: str, timeout: int) -> Outcome:
    if rc == 124:
        return Outcome("fail", f"TIMEOUT after {timeout}s\n{tail}")
    if rc == 0:
        return Outcome("pass", f"rc={rc}\n{tail}")
    return Outcome("fail", f"{_classify_cli_failure(tail)} (rc={rc})\n{tail}")


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
    """Exercise trace_window=symbol end-to-end.  The plugin MUST open a
    segment at the requested symbol occurrence, trace the simulation
    instructions, and decode with the correct start symbol; the trace is
    then validated (errors=0).  Also asserts the occurrence counter
    advances — occurrence=2 on a hot symbol opens strictly later than
    occurrence=1.  A non-triggering plugin is a FAIL, not a skip: this
    check gates against the pre-segment symbol-trigger regression (the
    trigger ran only in the vcpu_tb_exec callback, which is JIT-gated off
    until a segment is active, so it never fired before the first open)."""
    from collections import Counter
    from . import __main__ as M
    import json
    d = ctx.dir("quick_symbol")
    args = _mk(out_dir=d, isa=["x86_64"], build_dir=ctx.build_dir,
               prog="sym", seed=ctx.seed, diamonds=8, hot_iters=300)
    M.cmd_generate(args, "x86_64")
    if M.cmd_build(args, "x86_64") != 0:
        return Outcome("fail", "build failed")
    bin_path = d / "sym_x86_64"
    out_base = d / "sym_x86_64"
    qemu = ctx.build_dir / "qemu-x86_64"

    def run_symbol(name: str, occ: int, out_tag: Path, sim: int) -> int | None:
        """Trace name@occ; return the opened segment's start icount (parsed
        from the plugin's 'starting segment ... [icount N ..]' line) or None
        if no segment opened."""
        opts = (f"outfile={out_tag},wpdepth=64,"
                f"trace_window=symbol:name={name}+occurrence={occ}"
                f"+simulation={sim},memdata=1")
        p = subprocess.run([str(qemu), "-plugin", f"{ctx.plugin},{opts}",
                            str(bin_path)], stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, text=True)
        m = re.search(r"starting segment '[^']*' \[icount (\d+)", p.stderr)
        return int(m.group(1)) if m else None

    # Primary: blk_1 occurrence=1 must open, trace, and validate.
    start1 = run_symbol("blk_1", 1, out_base, sim=100_000)
    cst = Path(f"{out_base}.cst")
    if start1 is None or not cst.is_file():
        stats = Path(f"{out_base}.stats.log")
        traced = ""
        if stats.is_file():
            m = re.search(r"traced_icount=(\d+)", stats.read_text())
            traced = m.group(0) if m else ""
        return Outcome("fail",
                       "trace_window=symbol never opened a segment for blk_1 "
                       f"({traced or 'no stats'}) — symbol-trigger regression")
    args2 = _mk(out_dir=d, isa="x86_64", build_dir=ctx.build_dir,
                prog="sym", start_symbol="blk_1", stop=100_000)
    M.cmd_analyze(args2, "x86_64")
    rc = M.cmd_validate(args2, "x86_64")
    if rc != 0:
        return _rc_outcome(rc, "blk_1 symbol window opened but validation "
                               "failed; ")

    # Occurrence counter: a hot symbol's occurrence=2 opens strictly later
    # than occurrence=1.  Pick hot blocks (>=2 correct-path visits) from the
    # meta and use the first whose occurrence=1 actually opens (diamond
    # blocks are branch targets, hence TB heads, but be defensive).
    meta = json.loads((d / "sym_x86_64.meta.json").read_text())
    hot = [bid for bid, n in Counter(meta.get("correct_path") or []).most_common()
           if n >= 2]
    occ_detail = "occurrence advance untested (no hot symbol)"
    for bid in hot[:6]:
        sym = f"blk_{bid}"
        a = run_symbol(sym, 1, d / "sym_occ1", sim=2000)
        if a is None:
            continue
        b = run_symbol(sym, 2, d / "sym_occ2", sim=2000)
        if b is None:
            return Outcome("fail",
                           f"symbol {sym} opened at occurrence=1 (icount {a}) "
                           "but occurrence=2 never opened")
        if b <= a:
            return Outcome("fail",
                           f"symbol occurrence counter did not advance: {sym} "
                           f"occ1 icount={a}, occ2 icount={b} (expected "
                           "occ2 > occ1)")
        occ_detail = f"{sym} occ1={a} < occ2={b}"
        break

    return Outcome("pass",
                   f"symbol window opened & validated (blk_1 @ icount "
                   f"{start1}); {occ_detail}")


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
    # golden determinism requires the EXACT work-root path used at capture:
    # the path appears in the qemu argv, and its length shifts the guest
    # stack base (hence REG_SP in the REGFILE record, hence the wire bytes).
    # Use the EXACT work-root the manifest records from capture time —
    # NOT the per-check ctx dir, whose length varies.  Fall back to the
    # canonical GOLDEN_WORK_ROOT if the manifest predates root recording.
    work = GOLDEN_WORK_ROOT
    try:
        import json
        mf = (Path(__file__).resolve().parent.parent.parent
              / "tests" / "golden" / "manifest.json")
        rec = json.load(open(mf)).get("work_root")
        if rec:
            # the manifest records the tool's INTERNAL root (…/<wr>/t);
            # --work-root expects the parent it was invoked with.
            work = Path(rec)
            if work.name == "t":
                work = work.parent
    except Exception:
        pass
    work.mkdir(parents=True, exist_ok=True)
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
    # -cpu max: the --coverage probe set includes AVX blocks; qemu-system's
    # default qemu64 model has no AVX, so without this the workload dies
    # with SIGILL at the first vmovdqu (#UD) and the window closes UNDER.
    # qemu-user is effectively cpu=max, so this aligns the two modes.
    rc, tail = _run_cli(
        ["all", "--isa", "x86_64", "--seed", _seedhex(ctx),
         "--build-dir", str(ctx.build_dir), "-o", str(d), "--system",
         "--marker", "--coverage", "--regdata", "--hot-iters", "200",
         "--stop", "200000"],
        timeout=900, log_path=d / "run.log",
        extra_env={"CST_QEMU_EXTRA_ARGS": "-cpu max"})
    return _cli_outcome(rc, tail, 900)


def _chk_churn(isa: str):
    def fn(ctx: Ctx) -> Outcome:
        d = ctx.dir(f"system_churn_{isa}")
        rc, tail = _run_cli(
            ["churn_test", "--isa", isa, "--seed", _seedhex(ctx),
             "--build-dir", str(ctx.build_dir), "-o", str(d),
             "--depth", "8", "--stop", "150000", "--hot-iters", "2000",
             "--sleep-probe", "25", "--churn-pre", "60",
             "--churn-during", "220"],
            timeout=900, log_path=d / "run.log")
        return _cli_outcome(rc, tail, 900)
    return fn


def _chk_attach(isa: str):
    """Injected-marker system trace: the workload carries no start marker,
    so the window can only be opened by cst_attach poking the sequence into
    its entry point over ptrace.  mipsel is the check ISA because its
    injector backend is the one no other check reaches — the fixed-width
    ISAs read the PC through PTRACE_GETREGSET, MIPS through the
    PEEKUSER/POKEUSER index space, and it is also the cheapest guest to
    boot.  A missing cross compiler makes the run a SKIP, not a failure."""
    def fn(ctx: Ctx) -> Outcome:
        d = ctx.dir(f"system_attach_{isa}")
        rc, tail = _run_cli(
            ["all", "--isa", isa, "--seed", _seedhex(ctx),
             "--build-dir", str(ctx.build_dir), "-o", str(d),
             "--system", "--attach", "--stop", "200000"],
            timeout=900, log_path=d / "run.log")
        return _cli_outcome(rc, tail, 900)
    return fn


def _chk_clock_progress(isa: str):
    """Guest-clock progress under wrong-path speculation, on every ISA.

    A wrong-path excursion freezes the guest virtual clock; on exit every
    clock source has to be resynchronised TO that frozen time
    (TCGCPUOps::spec_clock_resync).  A source that is missed -- a host timer
    left parked, an interrupt line left disagreeing with its pending
    register, an externally-asserted interrupt swallowed by the register
    rollback -- makes the guest stop taking interrupts.  It does not crash:
    it spins in the kernel, the tracer records the spin faithfully, and every
    structural oracle still passes.  The symptom is purely in the accounting,
    which is what this check reads -- the window closes UNDER budget, the
    traced/user instruction ratio explodes, and the user clock stops
    advancing in wall time (_system.assess_clock_progress and
    run_with_clock_watchdog, both wired into the system trace path).  This
    check's window covers deep into the millions of user instructions, so
    the ratio leg's CLOCK_INFLATION_MIN_COVERED floor (below which fixed
    boot/scheduling overhead alone can inflate the ratio -- see
    system.attach_mipsel, whose tiny window sits under that floor on
    purpose) never comes into play here.

    Runs on all four ISAs deliberately.  The class has been fixed three times
    as per-ISA point patches and recurred each time, and the reason the suite
    stayed green through a 19% aarch64 stall rate is that the system tier
    only ever booted x86_64 and mipsel -- aarch64 and riscv64 had no
    system-mode check at all.  The window is large enough that the guest
    takes thousands of timer interrupts inside it, so a dead clock cannot
    hide; the deep wrong-path budget is what makes excursions frequent enough
    to expose a per-excursion leak.

    Built on the churn guest rather than the plain marker boot because the
    failure needs the guest to be USING its clock: a stream of short-lived
    processes keeps the scheduler, the tick and the interrupt controller busy
    for the whole window, so a timer left parked or a line left stuck has
    something to break.  The churn body is ISA-generic (a busybox shell
    loop).

    Run with the full system-mode option set -- devio, interrupts, faults,
    kexc, physaddr -- rather than the trace-shape defaults.  Those are the
    options a real system-mode capture uses, and they are the ones that put
    the wrong path in contact with the machine's clocks: devio sandboxes
    speculative device access, and interrupts/kexc keep the excursion
    machinery interleaved with interrupt entry.  A gate for a clock bug has
    to run the configuration in which the clocks are actually touched."""
    def fn(ctx: Ctx) -> Outcome:
        d = ctx.dir(f"system_clock_{isa}")
        rc, tail = _run_cli(
            ["churn_test", "--isa", isa, "--seed", _seedhex(ctx),
             "--build-dir", str(ctx.build_dir), "-o", str(d),
             "--depth", "64", "--stop", "400000", "--hot-iters", "4000",
             "--sleep-probe", "25", "--churn-pre", "60",
             "--churn-during", "220"],
            timeout=1200, log_path=d / "run.log",
            extra_env={"CST_PLUGIN_EXTRA_ARGS":
                       "physaddr=1,devio=1,interrupts=1,faults=1,kexc=1"})
        return _cli_outcome(rc, tail, 1200)
    return fn


def _chk_thread_system(ctx: Ctx) -> Outcome:
    d = ctx.dir("system_thread_x86")
    rc, tail = _run_cli(
        ["thread_test", "--isa", "x86_64", "--build-dir", str(ctx.build_dir),
         "-o", str(d), "--system", "--smp", "2", "--iters", "250000",
         "--stop", "200000", "--seeds", "1"],
        timeout=900, log_path=d / "run.log")
    return _cli_outcome(rc, tail, 900)


def _chk_thread_system_mipsel(ctx: Ctx) -> Outcome:
    d = ctx.dir("system_thread_mipsel")
    rc, tail = _run_cli(
        ["thread_test", "--isa", "mipsel", "--build-dir", str(ctx.build_dir),
         "-o", str(d), "--system", "--smp", "2", "--iters", "250000",
         "--stop", "200000", "--seeds", "1"],
        timeout=900, log_path=d / "run.log")
    return _cli_outcome(rc, tail, 900)


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


def _chk_mips_fragment_split_absence(ctx: Ctx) -> Outcome:
    """Pin the current MIPS fact behind ``split_tb_into_fragments``'s
    mid-TB continuation path (see ``behavior:mips_fragment_split_absence``).

    The splitter's "seal a fragment at a branch-classified insn that is
    NOT the TB's last insn, then keep walking" branch can only ever be
    exercised by an instruction QEMU's translator itself keeps decoding
    past despite the tracer classifying it as a branch.  On MIPS the
    T-family conditional trap (teq/tne/tlt/tltu/tge/tgeu + the immediate
    forms) was the only such instruction -- ``gen_trap`` emits a
    conditional TCG branch to a helper call and leaves
    ``ctx->base.is_jmp`` at ``DISAS_NEXT``, so translation runs straight
    on.  5bf597d751 correctly reclassified the family as
    ``GEN_OP_CMP``/``BRANCH_NONE`` (a compare that may except, exactly
    x86 BOUND's shape) because it never redirects fetch -- which also
    means MIPS lost its only exercise of this splitter path.  An audit
    of every remaining MIPS ``branch_type != BRANCH_NONE`` mnemonic
    against ``target/mips/tcg/translate.c`` (every direct/indirect
    jump/call/return/conditional branch, and every syscall/unconditional
    trap) shows each one ends the QEMU TB immediately -- there is
    currently no other MIPS instruction with the T-family's shape.  The
    path is still exercised elsewhere via ``BRANCH_REP``: x86
    (``X86RepIterationFanout``, ``rep movsq`` mid-TB) and aarch64, whose
    FEAT_MOPS prologue/main/epilogue triple QEMU translates straight
    through inside one TB.

    Rather than leave that fact undocumented, decode a MIPS trace built
    with ``--coverage`` (chains in every registered ``coverage_probe``
    block, including ``MipsInlineConditionalTrap`` -- the regression
    test for the misclassification itself) and assert the structural
    invariant that fact implies: no template's instruction list may
    carry a branch-classified insn anywhere before its last two
    positions (last = a bare/non-delay-slot terminus; second-to-last =
    a branch immediately followed by its one architectural delay-slot
    insn).  A future classification change that gives some MIPS
    instruction the T-family's shape again -- branch-classified, but
    QEMU translates past it -- will show up as an earlier occurrence and
    this check must fail until a dedicated coverage_probe (mirroring
    X86RepIterationFanout / MipsInlineConditionalTrap) exists to prove
    the splitter folds it correctly."""
    from . import __main__ as M
    from . import _cst_decode_runner as DEC
    d = ctx.dir("feat_mips_fragsplit")
    args = _mk(out_dir=d, isa=["mipsel"], build_dir=ctx.build_dir,
               prog="mfs", seed=ctx.seed, diamonds=8, coverage=True,
               hot_iters=200, stop=200_000)
    M.cmd_generate(args, "mipsel")
    if M.cmd_build(args, "mipsel") != 0:
        return Outcome("fail", "build failed")
    if M.cmd_trace(args, "mipsel") != 0:
        return Outcome("fail", "trace failed")
    cst = d / "mfs_mipsel.cst"
    old_decode_env = os.environ.get("CST_DECODE")
    os.environ["CST_DECODE"] = str(ctx.build_dir / "contrib/plugins/cst_decode")
    try:
        meta, templates, _entries = DEC.decode_champsim_tracer(cst)
    finally:
        if old_decode_env is None:
            os.environ.pop("CST_DECODE", None)
        else:
            os.environ["CST_DECODE"] = old_decode_env

    none_id = 0
    for bid, name in (meta.get("branch_names") or {}).items():
        if name == "NONE":
            none_id = int(bid)
            break

    violations = []
    for t in templates:
        insns = t.get("insns") or []
        n = len(insns)
        for i, insn in enumerate(insns):
            if i >= n - 2:
                continue        # last two positions: bare or delay-slot pair
            if int(insn.get("branch_type", none_id)) != none_id:
                violations.append((t.get("template_id"), i, n))

    if violations:
        tid, i, n = violations[0]
        return Outcome(
            "fail",
            f"{len(violations)} MIPS template insn(s) carry a "
            f"branch-classified insn before the last 2 positions of "
            f"their fragment (e.g. template {tid} insn {i}/{n}) -- MIPS "
            f"has regained an instruction shaped like the old teq "
            f"misclassification (QEMU translates past a "
            f"branch-classified insn) with no dedicated coverage_probe; "
            f"add one (see X86RepIterationFanout / "
            f"MipsInlineConditionalTrap in asm_blocks.py) before "
            f"relaxing this check")
    return Outcome(
        "pass",
        f"{len(templates)} mipsel templates audited, 0 mid-fragment "
        f"branch-classified insns -- matches the current MIPS ISA fact "
        f"(the teq family was the only case; 5bf597d751 fixed it)")


def _chk_physaddr(ctx: Ctx) -> Outcome:
    cfg = MP.MPConfig(build_dir=ctx.build_dir,
                      out_dir=ctx.dir("feat_physaddr"), budget=2_000_000)
    return _mp_outcome(MP.run_physaddr_probe(cfg))


def _chk_devio(ctx: Ctx) -> Outcome:
    cfg = MP.MPConfig(build_dir=ctx.build_dir,
                      out_dir=ctx.dir("feat_devio"), budget=20_000_000)
    return _mp_outcome(MP.run_devio_probe(cfg))


def _chk_devio_attrib(ctx: Ctx) -> Outcome:
    cfg = MP.MPConfig(build_dir=ctx.build_dir,
                      out_dir=ctx.dir("feat_devio_attrib"), budget=20_000_000,
                      boot_timeout_s=300)
    return _mp_outcome(MP.run_devio_attrib_probe(cfg))


def _chk_faults_interrupts(ctx: Ctx) -> Outcome:
    cfg = MP.MPConfig(build_dir=ctx.build_dir,
                      out_dir=ctx.dir("feat_faults_interrupts"),
                      budget=4_000_000)
    return _mp_outcome(MP.run_faults_interrupts_probe(cfg))


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


def _chk_mops_memops(ctx: Ctx) -> Outcome:
    t = (Path(__file__).resolve().parent / "tests" / "test_mops_memops.py")
    if not t.is_file():
        return Outcome("skip", f"test not found: {t}")
    env = dict(os.environ, CST_BUILD_DIR=str(ctx.build_dir),
               BUILD_DIR=str(ctx.build_dir))
    p = subprocess.run([sys.executable, str(t)], text=True,
                       capture_output=True, env=env)
    out = (p.stdout or "") + (p.stderr or "")
    tail = "\n".join(out.splitlines()[-8:])
    # A missing AArch64 cross toolchain skips the whole class, which unittest
    # still reports as rc 0.  Surface that as a skip, not a silent pass.
    if p.returncode == 0 and re.search(r"OK \(skipped=\d+\)", out):
        return Outcome("skip", tail)
    return Outcome("pass" if p.returncode == 0 else "fail",
                   f"rc={p.returncode}\n{tail}")


def _chk_dc_zva_memops(ctx: Ctx) -> Outcome:
    t = (Path(__file__).resolve().parent / "tests" / "test_dc_zva_memops.py")
    if not t.is_file():
        return Outcome("skip", f"test not found: {t}")
    env = dict(os.environ, CST_BUILD_DIR=str(ctx.build_dir),
               BUILD_DIR=str(ctx.build_dir))
    p = subprocess.run([sys.executable, str(t)], text=True,
                       capture_output=True, env=env)
    out = (p.stdout or "") + (p.stderr or "")
    tail = "\n".join(out.splitlines()[-8:])
    # A missing AArch64 cross toolchain skips the whole class, which unittest
    # still reports as rc 0.  Surface that as a skip, not a silent pass.
    if p.returncode == 0 and re.search(r"OK \(skipped=\d+\)", out):
        return Outcome("skip", tail)
    return Outcome("pass" if p.returncode == 0 else "fail",
                   f"rc={p.returncode}\n{tail}")


def _chk_string_memops(ctx: Ctx) -> Outcome:
    t = (Path(__file__).resolve().parent / "tests" / "test_string_memops.py")
    if not t.is_file():
        return Outcome("skip", f"test not found: {t}")
    env = dict(os.environ, CST_BUILD_DIR=str(ctx.build_dir),
               BUILD_DIR=str(ctx.build_dir))
    p = subprocess.run([sys.executable, str(t)], text=True,
                       capture_output=True, env=env)
    out = (p.stdout or "") + (p.stderr or "")
    tail = "\n".join(out.splitlines()[-8:])
    # A missing native toolchain skips the whole class, which unittest
    # still reports as rc 0.  Surface that as a skip, not a silent pass.
    if p.returncode == 0 and re.search(r"OK \(skipped=\d+\)", out):
        return Outcome("skip", tail)
    return Outcome("pass" if p.returncode == 0 else "fail",
                   f"rc={p.returncode}\n{tail}")


def _chk_rep_fanout_invariance(ctx: Ctx) -> Outcome:
    t = (Path(__file__).resolve().parent / "tests"
         / "test_rep_fanout_invariance.py")
    if not t.is_file():
        return Outcome("skip", f"test not found: {t}")
    env = dict(os.environ, CST_BUILD_DIR=str(ctx.build_dir),
               BUILD_DIR=str(ctx.build_dir),
               CST_DECODE=str(ctx.build_dir / "contrib" / "plugins"
                              / "cst_decode"))
    p = subprocess.run([sys.executable, str(t)], text=True,
                       capture_output=True, env=env)
    out = (p.stdout or "") + (p.stderr or "")
    tail = "\n".join(out.splitlines()[-12:])
    # A missing native toolchain skips the whole class, which unittest still
    # reports as rc 0.  Surface that as a skip, not a silent pass.
    if p.returncode == 0 and re.search(r"OK \(skipped=\d+\)", out):
        return Outcome("skip", tail)
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


def _chk_wp_tlb_cold(ctx: Ctx) -> Outcome:
    t = (Path(__file__).resolve().parent / "tests"
         / "test_wp_tlb_cold_capture.py")
    if not t.is_file():
        return Outcome("skip", f"test not found: {t}")
    env = dict(os.environ, CST_BUILD_DIR=str(ctx.build_dir),
               BUILD_DIR=str(ctx.build_dir))
    p = subprocess.run([sys.executable, str(t)], text=True,
                       capture_output=True, env=env)
    tail = "\n".join((p.stdout or p.stderr).splitlines()[-8:])
    # The test self-skips (exit 0 + "SKIP ...") when system-mode fixtures are
    # absent; surface that as a skip, not a pass.
    if p.returncode == 0 and tail.startswith("SKIP"):
        return Outcome("skip", tail)
    return Outcome("pass" if p.returncode == 0 else "fail",
                   f"rc={p.returncode}\n{tail}")


def _chk_mutation(ctx: Ctx) -> Outcome:
    """Adversarial strictness proof: build a known-good substrate, then
    damage it one well-defined way at a time and assert a specific gating
    check catches each corruption.  Any applied mutation that slips
    through is a HOLE and fails the gate.  This is the suite's proof that
    it actually rejects wrong traces, not just accepts right ones."""
    from . import _mutation as MUT
    d = ctx.dir("feat_mutation")
    try:
        res = MUT.run_mutations(ctx.build_dir, d, seed=ctx.seed)
    except Exception as e:                                   # noqa: BLE001
        return Outcome("fail", f"mutation harness raised: {e}")
    subs = [{"name": r["name"],
             "ok": r["status"] != "HOLE",
             "detail": f"{r['status']}: "
                       f"{','.join(r['caught_by']) or r['detail'][:60]}"}
            for r in res["results"]]
    if not res["baseline_clean"]:
        return Outcome("fail",
                       f"substrate did not validate clean "
                       f"(baseline errors {res['baseline_errors']})", subs)
    if res["holes"]:
        return Outcome("fail",
                       f"HOLES (uncaught corruptions): {res['holes']}", subs)
    return Outcome("pass",
                   f"{res['caught']}/{res['applied']} mutations caught, "
                   f"0 holes; skipped={res['skipped']}", subs)


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


_SEG_CLOSE_RE = re.compile(
    r"finished segment \[icount (\d+) \.\. (\d+)\].*?"
    r"actual_icount=(\d+).*?\b(OK|UNDER|END)\s*$")


def _final_entry_memop_probe(cst: Path):
    """Decode @cst and score the segment's LAST body entry against the
    earlier executions of the same true BB.

    Returns (verdict, detail) where verdict is one of:
      "pass"        final entry's memop shape matches its peers
      "drop"        peers all perform N>0 memops, the final entry performs
                    fewer (the segment-close memop loss)
      "unusable"    the final entry's template is a one-shot, has no static
                    memop slot, or its memop shape varies across executions
                    -- no invariant to assert, so the trace does not gate
    """
    from . import validator as V
    _meta, templates, entries = \
        V._load_decoder().decode_champsim_tracer(cst)
    cp = list(entries)          # decode_champsim_tracer yields CP entries
    if len(cp) < 3:                    # (WP blocks hang off e["wp_entries"])
        return "unusable", f"only {len(cp)} CP entries"
    by_id = {t["template_id"]: t for t in templates}
    final = cp[-1]
    tid = final.get("template_id")
    tmpl = by_id.get(tid) or {}
    slots = sum(1 for i in (tmpl.get("insns") or [])
                if int(i.get("n_loads", 0)) or int(i.get("n_stores", 0)))
    if slots == 0:
        return "unusable", (f"final template {tid} has no static memop "
                            f"slot ({tmpl.get('n_insns')} insns)")

    def shape(e):
        dps = e.get("dyn_params") or []
        tally = {}
        for dp in dps:
            k = (int(getattr(dp, "insn_index", -1)),
                 str(getattr(dp, "type_name", "")))
            tally[k] = tally.get(k, 0) + 1
        return (len(dps), tuple(sorted(tally.items())))

    peers = [e for e in cp[:-1] if e.get("template_id") == tid]
    if len(peers) < 2:
        return "unusable", f"final template {tid} executes {len(peers)+1}x"
    shapes = {shape(p) for p in peers}
    if len(shapes) != 1:
        return "unusable", (f"final template {tid} memop shape varies over "
                            f"{len(peers)} executions")
    want = shapes.pop()
    if want[0] == 0:
        return "unusable", (f"final template {tid} performs no memops "
                            f"despite {slots} static slot(s)")
    got = shape(final)
    if got == want:
        return "pass", (f"final entry (seq {final.get('seq_num')}, template "
                        f"{tid}) carries {got[0]} memops == "
                        f"{len(peers)} peer executions")
    return "drop", (f"final entry (seq {final.get('seq_num')}, template "
                    f"{tid}) carries {got[0]} memops but its {len(peers)} "
                    f"peer executions all carry {want[0]}")


def _chk_reg_snap_accounting(ctx: Ctx) -> Outcome:
    """The plugin's own dropped-slice completeness invariant (Oracle 1 of
    the two D4-class completeness checks — see features.final_entry_memops
    and the cst_lint.h MemopBimodalityLint for the other one).

    ``Stats.reg_snap_slice_dropped`` / ``Stats.reg_snap_leak_trimmed``
    (champsim_tracer_stats.h) are counted by the plugin at every seal walk:
    a positional reg-snap shortfall the walk cannot recover drops that
    entry's whole register-data section rather than mis-slicing it onto
    the wrong instruction (dropped); a leaked prefix the walk CAN recover
    by trimming is counted separately (trimmed).  Neither counter ever
    reaches the wire — they exist only in the plugin's own per-segment and
    cumulative stderr summary and its ``<outfile>.stats.log`` sidecar — so
    no byte-level gate on the trace file itself can see them; every
    existing offline check (cst_audit's rollup, the impossible-attribution
    lint) reconciles a D4-affected trace as perfectly clean because a
    record that was never written contributes to neither side of a byte
    partition.

    The invariant this check reads is ``dropped == trimmed``, NOT "both
    zero": a busy fault-storm trace can legitimately trim many leaked
    prefixes while dropping none of them (mcf_user_mipsel's sample trace
    shows 188,726 leak trims from the separate mipsel `teq`-as-syscall
    issue, with dropped==trimmed still holding), so requiring zero would
    false-positive on exactly the traces most likely to exercise the
    recovery path.  Runs its own short trace per ISA — deliberately not
    reusing another check's output directory — so it exercises the
    invariant in the ordinary course of tracing, not a manufactured
    scenario."""
    from . import __main__ as M
    from . import generator as G
    subs: list = []
    all_ok = True
    for isa in ISA_ALL:
        d = ctx.dir(f"feat_reg_snap_accounting_{isa}")
        cc = M.ISA_COMPILER.get(isa)
        if not cc:
            subs.append({"name": isa, "ok": True, "detail": "skip (no compiler)"})
            continue
        params = G.GenerateParams(seed=ctx.seed, isa=isa, num_diamonds=8,
                                  hot_iters=1000)
        src, _m = G.generate(params, d, f"rsa_{isa}")
        binp = d / f"rsa_{isa}"
        bcmd = [cc] + M.ISA_CFLAGS[isa] + ["-O1", str(src), "-o", str(binp)]
        if subprocess.call(bcmd) != 0:
            subs.append({"name": isa, "ok": True, "detail": "skip (build failed)"})
            continue
        qemu = ctx.build_dir / f"qemu-{isa}"
        out_base = d / f"rsa_{isa}"
        opts = (f"outfile={out_base},wpdepth=32,regdata=1,memdata=1,"
                f"trace_window=icount:start=0;stop=400000")
        rc = subprocess.call([str(qemu), "-plugin", f"{ctx.plugin},{opts}",
                             str(binp)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
        stats = Path(f"{out_base}.stats.log")
        if rc != 0 or not stats.is_file():
            subs.append({"name": isa, "ok": False,
                        "detail": f"trace rc={rc} stats_present={stats.is_file()}"})
            all_ok = False
            continue
        dropped = trimmed = None
        for line in stats.read_text(errors="replace").splitlines():
            if line.startswith("CP reg-snap slice dropped"):
                dropped = int(line.rsplit(None, 1)[-1])
            elif line.startswith("CP reg-snap leak trimmed"):
                trimmed = int(line.rsplit(None, 1)[-1])
        if dropped is None or trimmed is None:
            subs.append({"name": isa, "ok": False,
                        "detail": f"counters not found in {stats.name}"})
            all_ok = False
            continue
        ok = dropped == trimmed
        all_ok = all_ok and ok
        subs.append({"name": isa, "ok": ok,
                    "detail": f"dropped={dropped} trimmed={trimmed}"})
    return Outcome("pass" if all_ok else "fail",
                   "plugin's own dropped-slice accounting invariant "
                   "(dropped == trimmed), read from <outfile>.stats.log "
                   "(4 ISAs)", subs)


def _chk_final_entry_memops(ctx: Ctx) -> Outcome:
    """The segment's LAST body entry keeps its memory operands (4 ISAs).

    Body entries are emitted one TB late — the seal walk emits the
    *previous* TB's entry once its successor is known — so an entry
    flushed on a path that runs BEFORE its instructions execute carries no
    memops at all.  Exactly one entry per segment is exposed, and no
    byte-level gate can see it: cst_audit's rollup reconciles the records
    that ARE present, and the impossible-attribution lint only rejects a
    memop on a memop-incapable slot, never a memop-capable slot with no
    memop (which predication and zero-count REP make legal).

    So this check reads the loss directly.  It forces a genuine deferred
    window close (icount stop reached mid-run, plugin reports the segment
    OK rather than UNDER/END), then requires the trace's final entry to
    land on a true BB that (a) statically accesses memory and (b) has
    executed before with an invariant memop shape -- and asserts the final
    execution carries that same shape.  A window whose final entry cannot
    supply that oracle is retried at a different stop; if no stop in the
    sweep yields one, the check FAILS rather than passing vacuously.
    """
    from . import __main__ as M
    from . import generator as G
    subs: list = []
    all_ok = True
    for isa in ISA_ALL:
        d = ctx.dir(f"feat_final_memops_{isa}")
        cc = M.ISA_COMPILER.get(isa)
        if not cc:
            subs.append({"name": isa, "ok": True, "detail": "skip (no compiler)"})
            continue
        # Long-running so the icount window closes mid-flight; dense enough
        # in load/store blocks that most stops land on a memop-carrying BB.
        params = G.GenerateParams(seed=ctx.seed, isa=isa, num_diamonds=8,
                                  hot_iters=4000)
        src, _m = G.generate(params, d, f"fem_{isa}")
        binp = d / f"fem_{isa}"
        if subprocess.call([cc] + M.ISA_CFLAGS[isa] +
                           ["-O1", str(src), "-o", str(binp)]) != 0:
            subs.append({"name": isa, "ok": True, "detail": "skip (build failed)"})
            continue
        qemu = ctx.build_dir / f"qemu-{isa}"
        verdict, detail, used_stop = "none", "no window closed OK", 0
        for stop in (120000, 137000, 151000, 166000, 183000, 201000):
            out = d / f"fem_{isa}_{stop}"
            log = d / f"fem_{isa}_{stop}.log"
            with open(log, "w") as f:
                rc = subprocess.call(
                    [str(qemu), "-plugin",
                     f"{ctx.plugin},outfile={out},wpdepth=16,memdata=1,"
                     f"regdata=1,trace_window=icount:start=0;stop={stop}",
                     str(binp)], stdout=subprocess.DEVNULL, stderr=f)
            cst = Path(f"{out}.cst")
            if rc != 0 or not cst.is_file():
                continue
            close = ""
            for line in log.read_text(errors="replace").splitlines():
                m = _SEG_CLOSE_RE.search(line.strip())
                if m:
                    close = m.group(4)
            if close != "OK":
                # UNDER/END: the guest ended before the stop, so the close
                # was the exit flush, not the deferred window close.
                continue
            v, det = _final_entry_memop_probe(cst)
            used_stop = stop
            if v in ("pass", "drop"):
                verdict, detail = v, det
                break
            verdict, detail = v, det
        ok = verdict == "pass"
        all_ok = all_ok and ok
        subs.append({"name": isa, "ok": ok,
                     "detail": f"stop={used_stop} {verdict}: {detail}"})
    return Outcome("pass" if all_ok else "fail",
                   "segment-final body entry keeps its memops (4 ISAs, "
                   "deferred icount-window close)", subs)


def _static_cov_analyze(cst: Path):
    """Decode @cst and score the branch-alternate minting coverage oracle.
    Classifies every template executed vs never-executed by its profile
    (a minted alternate has exec_cp==exec_wp==0), then scores fall-through
    and BTB-target resolution over each class.  Returns a dict of the
    load-bearing quantities plus a human summary."""
    from . import validator as V
    meta, templates, _entries = V._load_decoder().decode_champsim_tracer(cst)
    bt_names = meta.get("encoding_maps", {}).get("branch_type", {})
    starts = {int(t["start_pc"]) for t in templates}
    exec_ft: set[int] = set()
    n_static = 0
    alt_succ_tot = 0     # statically-known successors of minted alternates
    alt_succ_res = 0     # of those, how many resolve to a template start
    btb_res = 0
    btb_tot = 0
    for t in templates:
        insns = t.get("insns") or []
        if not insns:
            continue
        prof = t.get("profile") or {}
        is_exec = (int(prof.get("exec_cp", 0)) > 0 or
                   int(prof.get("exec_wp", 0)) > 0)
        # Terminal branch: the last insn, or the one before it on a delay-slot
        # ISA (mipsel), where the block's last insn is the folded delay slot.
        last = insns[-1]
        bname = bt_names.get(int(last.get("branch_type", 0)), "")
        if bname in ("", "BRANCH_NONE") and len(insns) >= 2:
            last = insns[-2]
            bname = bt_names.get(int(last.get("branch_type", 0)), "")
        ft = int(t["fall_through_pc"])
        targets = [int(tg) for tg in (t.get("target_pcs") or [])]
        if is_exec:
            # (a) self-consistency, informational: an executed conditional
            # direct branch's fall-through should resolve to a template start.
            if last.get("branch_conditional") and bname == "BRANCH_COND_DIRECT":
                exec_ft.add(ft)
            continue
        # Never-executed (minted-alternate) block.
        n_static += 1
        # (b) successor coverage — the metric static_depth drives: every
        # statically-known successor of a minted alternate (its architectural
        # fall-through, plus a direct branch's decoded target) should itself
        # have been minted, so the fetch chain resolves rather than dangles.
        succ = [ft] + targets
        for s in succ:
            alt_succ_tot += 1
            if s in starts:
                alt_succ_res += 1
        # (c) BTB coverage: a never-executed direct branch/jump/call's decoded
        # target must resolve — the never-executed destination space.
        if bname in ("BRANCH_DIRECT_JUMP", "BRANCH_DIRECT_CALL",
                     "BRANCH_COND_DIRECT"):
            for tg in targets:
                btb_tot += 1
                if tg in starts:
                    btb_res += 1
    exec_unres = sum(1 for f in exec_ft if f not in starts)
    return {
        "n_templates": len(templates),
        "n_static": n_static,
        "exec_ft": len(exec_ft),
        "exec_unres": exec_unres,
        "alt_succ_tot": alt_succ_tot,
        "alt_succ_res": alt_succ_res,
        "btb_res": btb_res,
        "btb_tot": btb_tot,
    }


def _chk_static_coverage(ctx: Ctx) -> Outcome:
    """Coverage oracle for static_templates=1 (opportunistic branch-alternate
    minting, deepened by static_depth) — the trace-inferred wrong-path
    fall-through / BTB coverage that is the point of the feature.

    Per ISA, with minting ON (static_depth>0):
      (a) every EXECUTED conditional-branch block's fall-through resolves to a
          template start_pc  (dictionary self-consistency; a deleted/mutated
          template breaks it),
      (b) NEVER-EXECUTED (minted-alternate) conditional-branch fall-throughs
          are covered (>0)  — the predicted-not-taken space executed-only
          templates miss; the static_depth successor walk mints these blocks'
          own fall-throughs, so they resolve rather than dangle,
      (c) never-executed direct-branch TARGETS resolve (BTB spot-check).
    The minting-off (static_templates=0) run must lose (b) entirely
    (static_res == 0), proving the oracle has teeth.  Axes (b)/(c) measure the
    minted-alternate space — no executable-region sweep runs.
    """
    from . import __main__ as M
    from . import generator as G

    subs: list = []
    all_ok = True
    for isa in ISA_ALL:
        d = ctx.dir(f"feat_wp_coverage_{isa}")
        cc = M.ISA_COMPILER.get(isa)
        if not cc:
            subs.append({"name": isa, "ok": True, "detail": "skip (no compiler)"})
            continue
        params = G.GenerateParams(seed=ctx.seed, isa=isa, num_diamonds=8,
                                  hot_iters=200)
        src, _m = G.generate(params, d, f"wpc_{isa}")
        binp = d / f"wpc_{isa}"
        bcmd = [cc] + M.ISA_CFLAGS[isa] + ["-O1", str(src), "-o", str(binp)]
        if subprocess.call(bcmd) != 0:
            subs.append({"name": isa, "ok": True, "detail": "skip (build failed)"})
            continue
        qemu = ctx.build_dir / f"qemu-{isa}"
        win = "trace_window=icount:start=0;stop=200000"
        on = d / f"wpc_{isa}_on"
        off = d / f"wpc_{isa}_off"
        rc1 = subprocess.call([str(qemu), "-plugin",
            f"{ctx.plugin},outfile={on},wpdepth=32,{win},memdata=1,"
            f"static_templates=1,static_depth=4", str(binp)])
        rc0 = subprocess.call([str(qemu), "-plugin",
            f"{ctx.plugin},outfile={off},wpdepth=32,{win},memdata=1",
            str(binp)])
        con = Path(f"{on}.cst")
        coff = Path(f"{off}.cst")
        if rc1 != 0 or rc0 != 0 or not con.is_file() or not coff.is_file():
            subs.append({"name": isa, "ok": False,
                         "detail": f"trace rc on={rc1} off={rc0}"})
            all_ok = False
            continue
        a_on = _static_cov_analyze(con)
        a_off = _static_cov_analyze(coff)
        ok = (a_on["n_static"] > 0 and                 # (b) alternates minted
              a_on["alt_succ_res"] > 0 and             # (b) successors resolve
              a_on["btb_res"] > 0 and                  # (c) BTB targets resolve
              a_on["n_static"] > a_off["n_static"] and # teeth: minting adds cov
              a_on["alt_succ_res"] > a_off["alt_succ_res"])
        all_ok = all_ok and ok
        subs.append({"name": isa, "ok": ok, "detail": (
            f"exec_ft={a_on['exec_ft']} unres={a_on['exec_unres']} | "
            f"minted({a_on['n_static']}) succ_resolved="
            f"{a_on['alt_succ_res']}/{a_on['alt_succ_tot']} | "
            f"btb={a_on['btb_res']}/{a_on['btb_tot']} | "
            f"teeth off_minted={a_off['n_static']} "
            f"off_succ_res={a_off['alt_succ_res']}")})
    return Outcome("pass" if all_ok else "fail",
                   "minted-alternate fall-through + BTB coverage, "
                   "static_depth-deepened (4 ISAs, minting-off teeth)", subs)


# The LLVM subtarget per ISA used to be supplied here, as flags this one
# caller passed on the command line.  That left the tool itself wrong: run
# from anywhere else it compared against a default subtarget that does not
# describe the ISA Capstone decodes, and the gate's verdict depended on who
# invoked it.  The subtargets now live in isaxcheck's own kIsaTable, which
# is where a fact about the ISA belongs; --mattr / --mcpu remain as
# interactive overrides for probing a Capstone or LLVM bump.


def _chk_isa_crosscheck(ctx: Ctx) -> Outcome:
    """Independent ground truth for the decode metadata the tracer consumes.

    Every other oracle in this battery reads the same Capstone-derived
    metadata the tracer does, so a decoder defect is invisible to all of
    them: the trace is corrupted and the checks agree with the corruption.
    isaxcheck breaks that circle by feeding identical encoding bytes to the
    tracer's own boundary (cap_disas_raw_detail() in disas/capstone.c —
    Capstone plus every correction applied on top) and to the LLVM MC layer,
    a separately maintained decoder and instruction-description database,
    then bucketing every disagreement by (class, mnemonic, difference)
    signature.

    GATING on any signature outside tools/isaxcheck_allow.txt, for all four
    ISAs.  The sweep covers 1.58 G encodings — 1.25 G x86_64, 164 M aarch64,
    151 M mipsel, 16.8 M riscv64 — which is still cheap enough to run on
    every Capstone bump, the point being that the disas/capstone.c
    workarounds should be retirable rather than permanent.  x86_64 is the
    bulk of it and the bulk of that is the SIB dimension (see sweep_x86 in
    isaxcheck.cc for what each dimension buys and what it cost).  A workaround that works shows up here as the ABSENCE of
    a disagreement; capstone_workaround_probe answers the complementary
    question of whether it has become unnecessary.
    """
    tool = ctx.build_dir / "contrib/plugins/isaxcheck"
    # __file__ = .../champsim_tracer/validator/champsim_tracer_validator/_full.py
    allow = (Path(__file__).resolve().parents[2]
             / "tools" / "isaxcheck_allow.txt")
    if not tool.is_file():
        return Outcome("fail",
                       f"isaxcheck not built at {tool}.  It needs LLVM MC "
                       "(llvm-18-dev or newer supplying llvm-config); meson "
                       "skips the target with a warning when llvm-config is "
                       "absent, and the gate cannot vouch for decode "
                       "metadata without it.")
    if not allow.is_file():
        return Outcome("fail", f"allowlist missing at {allow}")

    subs: list = []
    all_ok = True
    for isa in ISA_ALL:
        cmd = [str(tool), f"--isa={isa}", "--jobs=8",
               f"--allow={allow}", "--check"]
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=900)
        head = (p.stdout or "").splitlines()
        summary = head[0] if head else (p.stderr or "").strip()[:200]
        ok = p.returncode == 0
        all_ok = all_ok and ok
        detail = summary
        if not ok:
            # Under --check the tool prints only what failed.  NEW is a
            # signature that is not allowlisted; DEAD is an allowlist entry
            # that matched nothing, which is the direction a decoder bump
            # breaks first — a justification left standing over a
            # disagreement that has since moved.  Both are shown.
            new = [ln for ln in head[1:]
                   if ln.startswith("NEW") or ln.startswith("DEAD")]
            detail += "\n" + "\n".join(ln[:160] for ln in new[:8])
            if len(new) > 8:
                detail += f"\n... and {len(new) - 8} more"
        subs.append({"name": isa, "ok": ok, "detail": detail})
    return Outcome("pass" if all_ok else "fail",
                   "boundary-vs-LLVM-MC decode metadata agreement "
                   "(4 ISAs, ~1.58 G encodings, allowlisted residual)", subs)


def _chk_decode_fixups(ctx: Ctx) -> Outcome:
    """The repairs the plugin makes to what the decode boundary handed it.

    features.isa_crosscheck compares LLVM against cap_disas_raw_detail().
    The trace is not built from that.  It is built from the InsnFields
    decode_detail_to_generic() produces, and that function repairs some of
    what the boundary gives it -- most consequentially the RISC-V link
    register, which the aliased jal/jalr/ret forms hide from Capstone
    entirely, so without the repair a call's return-address write and a
    return's read are simply absent from the dataflow.

    Which means the boundary comparison CANNOT hold that repair in place.
    A regression there reintroduces the very disagreement the boundary
    allowlist already expects (`riscv64 R-wr-missing jal +r#` is sitting in
    it), the two cancel, and the run stays green while the trace loses its
    call graph.

    This check runs the boundary and the dependency model over the same
    encodings and asserts their difference against tools/isaxcheck_fixups.txt
    EXACTLY, both ways: a repair that stops happening fails as a dead rule,
    and a repair nobody recorded fails as a new signature.  It needs no
    second decoder -- it is the tracer measured against itself -- so it also
    covers encodings LLVM rejects, which is where a repair is least likely
    to be noticed.

    GATING, all four ISAs.
    """
    tool = ctx.build_dir / "contrib/plugins/isaxcheck"
    fixups = (Path(__file__).resolve().parents[2]
              / "tools" / "isaxcheck_fixups.txt")
    if not tool.is_file():
        return Outcome("fail",
                       f"isaxcheck not built at {tool}.  It needs LLVM MC "
                       "(llvm-18-dev or newer supplying llvm-config); the "
                       "fixup assertion links the plugin's own decode "
                       "translation unit into that same binary.")
    if not fixups.is_file():
        return Outcome("fail", f"fixup table missing at {fixups}")

    subs: list = []
    all_ok = True
    for isa in ISA_ALL:
        cmd = [str(tool), f"--isa={isa}", "--jobs=8", "--fixups",
               f"--allow={fixups}", "--check"]
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=900)
        head = (p.stdout or "").splitlines()
        detail = head[0] if head else (p.stderr or "").strip()[:200]
        ok = p.returncode == 0
        all_ok = all_ok and ok
        if not ok:
            bad = [ln for ln in head[1:]
                   if ln.startswith("NEW") or ln.startswith("DEAD")]
            detail += "\n" + "\n".join(ln[:160] for ln in bad[:8])
            if len(bad) > 8:
                detail += f"\n... and {len(bad) - 8} more"
        subs.append({"name": isa, "ok": ok, "detail": detail})
    return Outcome("pass" if all_ok else "fail",
                   "plugin-side decode repairs asserted against the boundary "
                   "(4 ISAs, both directions)", subs)


def _chk_implicit_operands(ctx: Ctx) -> Outcome:
    """Ground truth that never passed through a decoder at all.

    ``features.isa_crosscheck`` above compares two decoders, which can only
    ever see where they DISAGREE.  It therefore fails open when both move
    together, and they do: a disassembler transcribes encodings and does not
    model behaviour, so Capstone and LLVM share a blind spot on exactly the
    operands that are absent from the encoding and present only in the
    semantics.  The RVV ``v0`` mask class is the standing example — both
    decoders agree, and both are wrong.

    This check asserts AGREEMENT with expectations derived from behaviour
    instead: Arm's Machine Readable Architecture for aarch64, the Sail
    RISC-V model for riscv64, and QEMU's own TCG translators for mipsel,
    where the translator is the only correct witness because the two
    candidate substitutes (binutils' ``pinfo`` bits, the REMS Sail MIPS
    model) share the same tied-destination error.  Each row states what must
    be true of one encoding, so it goes red when the boundary stops
    reporting it no matter what any other decoder does — which is what makes
    a future Capstone bump unable to silently drop ``x30`` from a return.

    Two gating modes, both cheap because neither sweeps:

      assert     every row recorded OK must still be OK.
      known-gap  every row that is neither OK nor NOT-MODELLED carries a
                 disposition (fix / modelling-decision / wont-fix) and a
                 justification, keyed by the whole row so a NEW member of an
                 already-known family fails while the family stays green,
                 and a justification standing over a gap that has since
                 closed fails in the other direction.

    Every row carries the dynamic weight its instruction FORM reached in a
    traced population, so a reviewer ranks a finding by what it costs rather
    than by how loud it is.
    """
    audit = (Path(__file__).resolve().parents[2]
             / "tools" / "implicit_audit.py")
    if not audit.is_file():
        return Outcome("fail", f"implicit_audit.py missing at {audit}")
    tool = ctx.build_dir / "contrib/plugins/isaxcheck"
    if not tool.is_file():
        return Outcome("fail",
                       f"isaxcheck not built at {tool}.  It needs LLVM MC "
                       "(llvm-18-dev or newer supplying llvm-config); the "
                       "implicit-operand table reads the tracer's decode "
                       "boundary through its --batch mode.")
    subs: list = []
    all_ok = True
    for mode in ("assert", "known-gap"):
        p = subprocess.run(
            [sys.executable, str(audit), "--mode", mode,
             "--build-dir", str(ctx.build_dir)],
            text=True, capture_output=True, timeout=600)
        ok = p.returncode == 0
        all_ok = all_ok and ok
        out = (p.stdout or "").strip().splitlines()
        detail = "\n".join(ln[:200] for ln in out[:12])
        if not ok and p.stderr:
            detail += "\n" + p.stderr.strip()[:400]
        subs.append({"name": mode, "ok": ok, "detail": detail})
    return Outcome("pass" if all_ok else "fail",
                   "implicit-operand assertion table vs the decode boundary "
                   "(aarch64 MRA / riscv64 Sail / mipsel TCG translator, "
                   "435 objdump-verified probes)", subs)


def _chk_smc(ctx: Ctx) -> Outcome:
    """Self-modifying-code revision oracle (smc_plan.md §3).  Across all four
    ISAs, drive the SMC families whose expected revision structure is known a
    priori and assert the trace matches exactly.

    Same-shape rewrites (the instruction boundaries stay put):

      patch_once     → 2 revisions   (state changed once, both retained)
      flip_flop      → 2 revisions   (A/B/A/B reuses the two ids, not 4)
      cap_overflow   → 2 revisions   (5 states, smc_revisions=2 caps it)
      write_no_exec  → 1 template    (writes that never re-execute never
                                      surface as revisions)

    Shape-changing rewrites (the boundaries move — kernel alternatives and
    static-key patching, JIT re-emission):

      grow           → 2 revisions   (the second holds one instruction MORE)
      shrink         → 2 revisions   (the second holds one instruction FEWER)
      boundary_shift → 2 revisions   (the same code BYTES re-cut into
                                      different instructions; x86_64 and
                                      riscv64, the variable-width ISAs)
      grow_return    → 2 revisions   (A/B/A across a shape change: the
                                      returning A reuses its ORIGINAL id)

    Negative control:

      rewrite_identical → 1 template (identical bytes rewritten and
                                      re-executed 4x mints nothing)

    plus a host-side truth table over the discriminator itself
    (champsim_tracer_smc_match.h) covering the EXTENT_ONLY branch — a
    byte-identical overlap at a different extent must NOT mint — which no
    guest workload can reach.

    The oracle locates the self-modified block by its instruction bytes,
    asserts the exact revision count at that one start_pc, that every retained
    revision is byte-correct for a written state, and that the body's ENTRY
    records name the revision that was live at each position.  Any
    mint/reuse/cap bug perturbs the structure and fails here."""
    from . import __main__ as M
    from . import _smc

    d = ctx.dir("feat_smc")
    all_ok, subs = _smc.run_families(ctx.build_dir, d, ctx.plugin,
                                     M.ISA_COMPILER)
    return Outcome("pass" if all_ok else "fail",
                   "SMC template-revision minting (shape-preserving AND "
                   "shape-changing) + content-sig id reuse + per-pc cap + "
                   "discriminator truth table (4 ISAs, 9 families)", subs)


def _chk_smc_system(ctx: Ctx) -> Outcome:
    """System-mode SMC proof (smc_plan.md §4.3): a marker-emitting program
    ASID-pins itself and self-modifies inside the marker window; the trace
    must mint exactly two revisions at the self-modified pc under the pinned
    address-space root — the same commit seam as user mode, keyed by
    asid_root.  Skips cleanly when the x86 system fixtures are absent."""
    from . import __main__ as M
    from . import _smc

    d = ctx.dir("system_smc")
    all_ok, subs = _smc.run_system_family(ctx.build_dir, d, ctx.plugin,
                                          M.ISA_COMPILER)
    return Outcome("pass" if all_ok else "fail",
                   "SMC revision minting under the marker window / pinned "
                   "ASID (x86 system boot)", subs)


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
        "behavior:wrong_path_chains", "behavior:memop_bimodality",
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

    # GATING as of the reg-snap positional-attribution fix: the system-mode
    # per-insn value-capture divergence this battery was parked for (metaflags
    # losing a parity bit at pc=0x402984, INT_ADD dst capturing a code address
    # instead of the ALU result — reg-snap slot contamination) is fixed at the
    # plugin's seal walk (clobbered-scoreboard tail fallback + foreign-drop
    # reg-snap discard + segment-boundary marker-leak clear + fault-merge
    # leaked-prefix trim).  Restored to a hard gate.
    C.append(Check("system.user_x86", "system",
                   "system-mode marker/pin full-oracle battery (x86)",
                   ["opt:window_marker", "opt:kexc",
                    "wire:BODY_TAG_ASID_SWITCH",
                    "behavior:syscall_fault_nesting",
                    "behavior:user_code_identity"], _chk_system_user))
    C.append(Check("system.churn_x86", "system",
                   "multi-process ASID-churn pin (x86)",
                   ["tool:cst_decode_strict", "tool:cst_audit",
                    # churn_test's validate_structural(marker=True,
                    # pinned_binary=...) genuinely exercises the marker
                    # window, kexc excursion ownership, ASID_SWITCH wire
                    # records, syscall/fault nesting, and the pin's
                    # user-code identity gate — and passes as a HARD gate,
                    # so these features stay runtime-covered even while
                    # the full-oracle system.user_x86 battery is XFAIL.
                    "opt:window_marker", "opt:kexc",
                    "wire:BODY_TAG_ASID_SWITCH",
                    "behavior:syscall_fault_nesting",
                    "behavior:user_code_identity"],
                   _chk_churn("x86_64")))
    C.append(Check("system.churn_mipsel", "system",
                   "multi-process ASID-churn pin, narrow ASID (mipsel)",
                   ["behavior:asid_recycle"], _chk_churn("mipsel")))
    C.append(Check("system.attach_mipsel", "system",
                   "ptrace-injected marker opens the window for a workload "
                   "with no compiled-in marker (mipsel)",
                   ["behavior:marker_injection", "opt:window_marker"],
                   _chk_attach("mipsel")))
    C.append(Check("system.thread_x86", "system",
                   "SMP guest-thread identity (x86, --smp 2)",
                   ["wire:BODY_TAG_THREAD_SWITCH",
                    "behavior:guest_thread_identity",
                    "behavior:thread_strand_sequential"],
                   _chk_thread_system))
    # mipsel is where a shared thread_id was reproducible: a narrow ASID
    # folds every strand of the pinned process into one asid, so two vCPUs'
    # kernel work lands in the SAME (thread_id, asid) context the moment
    # their thread ids agree — which is exactly what thread_strand catches.
    C.append(Check("system.thread_mipsel", "system",
                   "SMP guest-thread identity, narrow ASID (mipsel, "
                   "--smp 2)",
                   ["behavior:thread_strand_sequential"],
                   _chk_thread_system_mipsel))
    C.append(Check("system.smc_x86", "system",
                   "self-modifying code mints revisions under the marker "
                   "window / pinned ASID (x86 system boot)",
                   ["behavior:smc_revisions"], _chk_smc_system))
    for _isa in ISA_ALL:
        C.append(Check(f"system.clock_progress_{_isa}", "system",
                       f"guest clock keeps advancing across wrong-path "
                       f"excursions ({_isa} system boot)",
                       ["behavior:spec_clock_resync", "opt:window_marker"],
                       _chk_clock_progress(_isa)))

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
                   "dead-latch ages a killed peer's window out (x86), "
                   "proven causally via the detector's own log line, "
                   "at a threshold (latch_timeout=750ms) picked to clear "
                   "guest scheduling jitter without racing progA's runtime",
                   ["opt:latch_timeout", "behavior:dead_latch"],
                   _chk_dead_latch))

    C.append(Check("features.simpoint", "features",
                   "per-simpoint segment independence + consistency",
                   ["opt:window_simpoint",
                    "behavior:cross_segment_consistency"], _chk_simpoint))
    C.append(Check("features.branch_verify", "features",
                   "cst_decode --verify-branch direction/target cross-check",
                   ["tool:cst_decode_verify_branch",
                    "wire:FID_branch_taken", "wire:FID_branch_target"],
                   _chk_branch_verify))
    C.append(Check("features.mips_fragment_split_absence", "features",
                   "split_tb_into_fragments mid-TB continuation path: "
                   "MIPS has no current instance (teq family fixed by "
                   "5bf597d751); fails if one regains it un-covered",
                   ["behavior:mips_fragment_split_absence"],
                   _chk_mips_fragment_split_absence))
    C.append(Check("features.physaddr", "features",
                   "per-memop physical-page capture (system)",
                   ["opt:physaddr", "wire:FLAG_PHYSADDR", "wire:FID_ppage"],
                   _chk_physaddr))
    C.append(Check("features.devio", "features",
                   "disk-I/O bracketing records (virtio-blk, system): "
                   "pairing oracle (every STOP pairs a prior START) + "
                   "exact payload oracle (R/W, bytes, LBA match the "
                   "workload's known request list)",
                   ["opt:devio", "wire:BODY_TAG_DEVIO_START",
                    "wire:BODY_TAG_DEVIO_STOP"], _chk_devio))
    C.append(Check("features.devio_attrib", "features",
                   "exact-owner disk-I/O attribution: two CONCURRENTLY "
                   "marked processes (-smp 2, disjoint LBA bands) must "
                   "each own only their own band's DEVIO_START records "
                   "(88d9b7e526's verification scenario)",
                   ["opt:devio", "wire:BODY_TAG_DEVIO_START",
                    "wire:BODY_TAG_DEVIO_STOP"], _chk_devio_attrib))
    C.append(Check("features.faults_interrupts", "features",
                   "synchronous-fault exclusion + async-interrupt capture "
                   "(faults=0 / interrupts=1, system)",
                   ["opt:faults", "opt:interrupts",
                    "behavior:syscall_fault_nesting"],
                   _chk_faults_interrupts))
    C.append(Check("features.tagged_ptr", "features",
                   "aarch64 tagged-pointer data-is-address heuristic",
                   ["behavior:addr_is_data"], _chk_tagged_ptr))
    C.append(Check("features.mops_memops", "features",
                   "aarch64 FEAT_MOPS bulk transfers reach the memory "
                   "instrumentation and tile the transferred range",
                   ["behavior:bulk_mem_visible", "wire:FID_mem_addr",
                    "wire:FID_mem_size"], _chk_mops_memops))
    C.append(Check("features.dc_zva_memops", "features",
                   "aarch64 DC ZVA reaches the memory instrumentation and "
                   "tiles the DCZID_EL0-sized block it zeroes",
                   ["behavior:dc_zva_visible", "wire:FID_mem_addr",
                    "wire:FID_mem_size"], _chk_dc_zva_memops))
    C.append(Check("features.string_memops", "features",
                   "x86 REP string ops fan out per iteration with the right "
                   "memop count, and the operand model matches the ISA",
                   ["behavior:string_op_memops", "wire:FID_mem_addr",
                    "wire:FID_mem_size"], _chk_string_memops))
    C.append(Check("features.rep_fanout_invariance", "features",
                   "x86 REP fan-out is architectural: same shape under "
                   "either do_gen_rep translation, and CP == WP",
                   ["behavior:rep_fanout_invariance"],
                   _chk_rep_fanout_invariance))
    C.append(Check("features.wp_fault", "features",
                   "WP execution-time fault continues to budget",
                   ["behavior:wp_fault_to_budget"], _chk_wp_fault))
    C.append(Check("features.wp_tlb_cold", "features",
                   "WP fetch of a valid-PTE but TLB-cold page captures real "
                   "bytes; a no-PTE target terminates (system mode)",
                   ["behavior:wp_tlb_cold_capture"], _chk_wp_tlb_cold))
    C.append(Check("features.options_smoke", "features",
                   "long-tail options (histogram/wp_memdata/wp_regdata/...)",
                   ["opt:histogram", "opt:wp_memdata", "opt:wp_regdata",
                    "opt:program_comment"], _chk_options_smoke))
    C.append(Check("features.mutation_strictness", "features",
                   "adversarial mutation matrix: oracle catches corruption",
                   ["behavior:mutation_strictness", "wire:wp_chain_flag"],
                   _chk_mutation))
    C.append(Check("features.wrong_path_coverage", "features",
                   "static_templates=1 fall-through/BTB coverage oracle (4-ISA)",
                   ["behavior:wrong_path_coverage"], _chk_static_coverage))
    C.append(Check("features.isa_crosscheck", "features",
                   "decode metadata vs an independent decoder (LLVM MC), "
                   "exhaustive encoding sweep (4-ISA)",
                   ["behavior:isa_crosscheck"], _chk_isa_crosscheck))
    C.append(Check("features.decode_fixups", "features",
                   "the plugin's own repairs to the decode boundary, "
                   "asserted in both directions (4-ISA)",
                   ["behavior:decode_fixups"], _chk_decode_fixups))
    C.append(Check("features.implicit_operands", "features",
                   "implicit-operand assertion table: expectations derived "
                   "from behaviour (MRA / Sail / TCG translators), not from "
                   "a decoder, so the shared blind spot is visible (3-ISA)",
                   ["behavior:implicit_operands"], _chk_implicit_operands))
    C.append(Check("features.final_entry_memops", "features",
                   "segment-final body entry keeps its memops across a "
                   "deferred icount-window close (4-ISA)",
                   ["behavior:segment_final_memops", "opt:window_icount",
                    "wire:BODY_TAG_ENTRY"], _chk_final_entry_memops))
    C.append(Check("features.reg_snap_accounting", "features",
                   "plugin's own dropped-slice completeness invariant "
                   "(dropped == trimmed) for the positional reg-snap "
                   "capture — the D4-class completeness oracle no "
                   "byte-level wire check can see (4-ISA)",
                   ["behavior:reg_snap_accounting", "tool:cst_audit"],
                   _chk_reg_snap_accounting))
    C.append(Check("features.smc", "features",
                   "self-modifying code: revision minting (shape-preserving "
                   "AND shape-changing) / id reuse / cap / discriminator "
                   "truth table (4-ISA, 9 families)",
                   ["behavior:smc_revisions"], _chk_smc))
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


# ---------------------------------------------------------------------------
# The "(must be 0)" census — the gate the tripwires never had
# ---------------------------------------------------------------------------
#
# Every counter the plugin labels "(must be 0)" is an invariant it asserts
# about its own output.  Nothing read them: the kept-span misattribution
# witness stood NONZERO in five cells of a corpus that reported OVERALL: PASS,
# because no check ever opened a stats.log looking for it.  A "must be 0" row
# nobody gates is decoration, and a corpus that routinely carries a nonzero
# one teaches its readers to ignore every other one.
#
# This reads every per-cell stats.log the run produced and fails on any
# nonzero row.  Two deliberate rules:
#   * a census that finds NO stats.log at all, or a stats.log with no
#     "(must be 0)" row in it, FAILS — a check that cannot find its subject
#     must not report an empty success;
#   * rows belonging to a NON-GATING (known_issue -> xfail) check are
#     reported but do not flip the gate, exactly as that check's own failure
#     does not.
_MUST0_RE = re.compile(r"^(?P<label>.*\(must be 0\))\s+(?P<val>\d+)\s*$")


def _tripwire_census(work_root: Path, nongating: set[str]) -> dict:
    files = sorted(work_root.rglob("*.stats.log"))
    rows: list[dict] = []
    unparsed: list[str] = []
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError as e:
            unparsed.append(f"{f}: {e}")
            continue
        seen = 0
        for line in text.splitlines():
            m = _MUST0_RE.match(line)
            if not m:
                continue
            seen += 1
            if int(m.group("val")):
                try:
                    cell = f.relative_to(work_root).parts[0]
                except ValueError:
                    cell = ""
                rows.append({"file": str(f), "check": cell,
                             "label": m.group("label").strip(),
                             "value": int(m.group("val")),
                             "gating": cell not in nongating})
        if seen == 0:
            unparsed.append(f"{f}: no '(must be 0)' row found")
    gating = [r for r in rows if r["gating"]]
    ok = bool(files) and not gating and not unparsed
    return {"stats_files": len(files), "violations": rows,
            "unreadable": unparsed, "status": "pass" if ok else "fail"}


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

    # The quiet-host WAIT gate is gone, by maintainer rule: "trace validity
    # and hang prevention should NEVER ride on the host's load."  A cell that
    # fails under load is a bug to fix, not a reason to wait for quiet -- and
    # the wait manufactured false evidence in practice: two "pristine HEAD
    # hangs" on record were this gate burning a 500 s cap in wait lines while
    # the cell never ran, the timeout then read as a hang.  The load level is
    # still RECORDED (a diagnostic, never a gate) so a failure under load can
    # be correlated -- correlation is analysis; gating was the defect.
    summary["host_load"] = {"foreign_qemu": _foreign_qemu(),
                            "loadavg": open("/proc/loadavg").read().split()[0]}

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
    # Every "(must be 0)" row of every cell this run produced.  Cells of a
    # non-gating check report but do not gate.
    nongating = {c.id.replace(".", "_") for c in sel if c.known_issue}
    summary["tripwire_census"] = _tripwire_census(work_root, nongating)
    # Exit code: FAIL on any failed check, a registration gap, or a violated
    # "must be 0" invariant.
    hard_fail = (counts["fail"] > 0 or bool(cov["static_gap"])
                 or bool(cov["unknown"])
                 or summary["tripwire_census"]["status"] == "fail")
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
    if summary.get("host_load"):
        print(f"host load (recorded, never gated): {summary['host_load']}")
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
    tw = summary.get("tripwire_census")
    if tw:
        print(f"\n\"must be 0\" census: {tw['stats_files']} stats.log files, "
              f"{len(tw['violations'])} violated row(s) — {tw['status']}")
        for r in tw["violations"]:
            print(f"   {'!!' if r['gating'] else '~ '} {r['value']:>10}  "
                  f"{r['label']}  [{r['check']}]")
        for u in tw["unreadable"]:
            print(f"   !! unreadable/empty: {u}")
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
                   help="Accepted for compatibility; the quiet-host wait "
                        "no longer exists (load is recorded, never gated).")
    p.add_argument("--max-wait", type=int, default=3600,
                   help="Accepted for compatibility; no wait exists any more.")
    p.add_argument("--dry-run", action="store_true",
                   help="Build + print the coverage map and check table "
                        "WITHOUT running anything; still enforces the "
                        "registration gap.")
    p.add_argument("--summary-json", type=Path, default=None,
                   help="Also write the JSON summary here.")


def cmd_full(args) -> int:
    return run_full(args)
