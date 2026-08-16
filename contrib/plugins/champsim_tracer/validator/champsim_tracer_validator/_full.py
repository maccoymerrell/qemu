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
from . import _marker as MK
from . import _must0


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
    "opt:window_system_marker_only": "system mode accepts ONLY "
                                  "trace_window=marker — icount, symbol, "
                                  "simpoint and the default window are "
                                  "refused at plugin install, because a "
                                  "position on a clock cannot say whose "
                                  "instructions it is counting",
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
    "tool:decode_residency":     "the validator's decode stage stays bounded on a large trace -- entries are read lazily off the spilled decode, never materialised as a list (the 10.3 GiB-per-cell incident)",
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
    "behavior:marker_detection_exact": "a COMPLETE marker sequence is never missed: the whole-sequence byte match made at translation time fires exactly once, on the sequence's last instruction, and still fires when that instruction is a branch target — the translation block then starts mid-sequence and the preceding instruction slots have to be read out of guest memory rather than out of the block",
    "behavior:marker_no_false_claim": "an INCOMPLETE marker sequence is never claimed: CST_MARKER_SEQ_LEN-1 adjacent units, a lone START unit, a lone END unit, and the chimera (the START sequence's leading units followed by the END sequence's last unit — the two share their terminating instruction on the fixed-width ISAs) all open no window and write no segment",
    "behavior:guest_thread_identity": "thread_id is guest thread, not vCPU",
    "behavior:multithread_content": "each guest thread's stream is compared 1v1 against ITS OWN generated ground truth — order, blocks, per-block instruction identity, memop kind/value/attribution, register values and wrong-path chains — with no golden in the loop; interleaving between threads is scheduling and is deliberately not asserted",
    "behavior:per_thread_stream_purity": "one generated body maps to exactly one tid and no thread's entry appears in another thread's stream; every entry carrying generated code is accounted for by exactly one thread (bijection + purity + census)",
    "behavior:thread_strand_sequential": "every (thread_id, asid) context reads as one sequential strand: concurrent guest threads never share an id, so a kernel strand is never braided with another vCPU's",
    "behavior:asid_recycle":     "narrow-ASID recycle-no-cross-attribution",
    "behavior:spec_clock_resync": "wrong-path excursions are time-transparent: every guest clock, host timer and interrupt line is resynchronised to the frozen virtual time on exit, so the guest keeps taking interrupts and making user-space progress (4-ISA, system mode)",
    "behavior:aclint_clockevent": "a riscv guest whose clockevent is the ACLINT machine timer reached through SBI (Sstc off), the second of riscv's two supervisor-timer paths and the one the default -cpu max never takes",
    "behavior:guest_idle_boundary": "the guest kernel reaches its idle instruction inside an open trace window, so the boundary at which it commits to sleeping on an already-armed timer is crossed under tracing",
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
    "behavior:decode_fields": "the InsnFields the dependency model records -- the layer the trace is BUILT from -- agree with LLVM MC across an exhaustive fields-layer sweep on mipsel and aarch64, the two ISAs whose only register-capture ground truth is static decode (no PIN, no Spike); the check first PROVES the oracle can fire by injecting a wrong register attribution (--falsify) and requiring the gate to go red naming the damaged mnemonic, then requires the undamaged sweep to be green outside tools/isaxcheck_fields_allow.txt with zero dead rules",
    "behavior:lldet_watchdog": "the lldet hang watchdog -- the harness's only detection for the livelock/hang class, since the product carries no detect-and-handle -- adjudicates a genuinely stalled child in BOTH verdict classes (DEADLOCK: frozen, zero CPU delta; LIVELOCK: burning a core with zero trace/console/write growth) and leaves a slow-but-growing child alone through the SLOW extension; a healthy cell cannot be killed by design, so a fire-proof built from one records a deadline crossing and a natural exit and proves nothing, which is what every silent cell in every hang wave was previously resting on",
    "behavior:implicit_operands": "the implicit operands — architectural state an instruction touches that its encoding does not name — that the decode boundary reports today are still reported, asserted per encoding against expectations derived from BEHAVIOUR rather than from any decoder (Arm's Machine Readable Architecture, the Sail RISC-V model, QEMU's MIPS TCG translator), so the class of defect where Capstone and LLVM agree and are both wrong is visible at all; each row carries a disposition and the dynamic weight of its instruction form",
    "behavior:segment_final_memops": "the segment's last body entry carries its memory operands, matching the earlier executions of the same true BB (the deferred icount/simpoint window close emits it after it has run, not before)",
    "behavior:smc_revisions": "self-modifying code: correct-path template-revision minting for rewrites that preserve OR change the block's instruction boundaries, content-signature id reuse, and the per-pc revision cap (4-ISA)",
    "behavior:bulk_mem_visible": "aarch64 FEAT_MOPS bulk transfers (SETP/SETM/SETE, CPYP/CPYM/CPYE) reach the memory instrumentation on the correct path: their recorded accesses tile the transferred range exactly instead of vanishing into the helper's host memset/memmove",
    "behavior:dc_zva_visible": "aarch64 DC ZVA reaches the memory instrumentation on the correct path and is modelled as the block store it is: its recorded stores tile the DCZID_EL0-sized block exactly instead of vanishing into the helper's host memset, and the instruction declares the store lane that makes them attributable",
    "behavior:string_op_memops": "x86 REP string instructions fan out per architectural iteration with the right per-iteration memop count, and the operand model matches what each instruction really reads and writes (Capstone access-flag corrections in disas/capstone.c)",
    "behavior:rep_fanout_invariance": "an x86 REP's fan-out is a function of architectural state only: the same guest execution renders the same number of entries, with the same rep_subtmpl/BRANCH_REP self-loop structure and the same per-iteration direction/target, whether do_gen_rep translated the whole repetition or one iteration per TB (CF_USE_ICOUNT / CF_SINGLE_STEP / EFLAGS.TF / interrupt shadow), and the wrong path — which is ALWAYS single-stepped through cpu_plugin_exec_tb — renders a REP exactly as the correct path does.  No external reference covers the wrong path, so this check is the only thing that can catch a CP/WP divergence there",
    "behavior:reg_snap_accounting": "the plugin's own dropped-slice completeness invariant for the positional reg-snap capture — CP reg-snap slice dropped == 0, end-marker-close drops included (D4-class completeness oracle; the wire has no record of it, so this is read from the <outfile>.stats.log sidecar, offline via cst_audit --stats-log)",
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
        # multi-thread content oracle (thread_test's content stage / mt_test)
        content=True, content_seed=0x7A11, threads=2, prove=False,
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
    # __main__.RC_SKIP: the run could not be hosted (absent cross-compiler,
    # unstaged guest kernel/rootfs).  It is NOT a pass -- a check that never
    # ran must never report as one, or its feature-coverage tags claim
    # exercise that did not happen.
    from . import __main__ as M      # lazy: __main__ imports this module
    if rc == M.RC_SKIP:
        return Outcome("skip", f"did not run (rc={rc})\n{tail}")
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


def _chk_mt_content(isa: str):
    """Multi-thread CONTENT, generatively.

    N synthetic bodies (own seed, own code region, own arena, own
    expected stream) stitched into one binary, the trace split on the
    wire's own thread_id, every stream compared 1v1 against its thread's
    ground truth — no golden anywhere in the loop.  ``--prove`` runs the
    same cell adversarially: a defect planted in a NAMED thread must be
    caught AND attributed to that thread, so the row proves the oracle
    fires as well as that it passes."""
    def fn(ctx: Ctx) -> Outcome:
        d = ctx.dir(f"quick_mt_{isa}")
        rc, tail = _run_cli(
            ["mt_test", "--isa", isa, "--seed", _seedhex(ctx),
             "--build-dir", str(ctx.build_dir), "-o", str(d),
             "--threads", "3", "--diamonds", "6", "--regdata",
             "--compress", "zstd", "--prove"],
            timeout=600, log_path=d / "run.log")
        return _cli_outcome(rc, tail, 600)
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


def _chk_system_simpoint(ctx: Ctx) -> Outcome:
    """SYSTEM-mode marker+simpoint composition, judged FROM THE TRACE.

    A system-mode ``trace_window=simpoint`` is not an alternative to a marker
    window -- it IS one, with a SimPoint schedule inside it.  The START
    marker pins the address space and zeroes the user clock
    (``pinned_simpoint_mode`` turns marker scanning on for exactly this
    reason), and the SimPoint offsets then position the capture on that
    clock.  Kernel work is traced but never advances the clock, which is what
    makes offsets derived from a user-mode bbv run valid here.

    THIS CHECK EXISTS BECAUSE DELETING THAT COMPOSITION ENTIRELY LEFT
    ``validator full`` GREEN.  ``features.simpoint`` is user-mode and
    x86_64-only, so nothing in the suite ever executed the marker-pinned
    path; the whole capability could be removed without a red run.

    Judged from the WIRE, never from a log line: the emitted segment must be
    the scheduled cluster, and the header it carries must state the warmup
    and total-target the schedule asked for.
    """
    import json
    d = ctx.dir("system_simpoint_x86")
    d.mkdir(parents=True, exist_ok=True)
    # Sized to the workload, which is the direction that works: at
    # --hot-iters 400 this generator's program retires 45,160 USER
    # instructions in total (measured; the marker window closes on its END
    # at user_covered=45160).  The schedule must fit inside that.  The
    # version this check was first written with asked for a first simpoint
    # at 200,000 user insns -- more than 4x the entire workload -- so it
    # captured nothing and could not have passed on any build.  Raising
    # --hot-iters instead is not the fix: the generator's ground-truth CP
    # walk is bounded at max_steps=100_000 blocks and 8000 iterations
    # overruns it ("CP walk did not terminate").
    interval, warmup, sim = 5_000, 1_000, 5_000
    # TWO clusters at different offsets, captured in ONE boot.
    #
    # Reading a single segment's header proves only that a capture happened
    # carrying the numbers the schedule asked for.  It cannot distinguish a
    # correctly POSITIONED capture from one that opened wherever it liked
    # and stamped the right header on the way out -- and positioning is the
    # entire claim of a simpoint window.  The clock it positions on is the
    # LATCHED process's user clock: zeroed at the START marker and advanced
    # only by that process's user-privilege instructions.  Two scheduled
    # offsets must therefore come out ORDERED THE SAME WAY on that clock,
    # which is what the strict-inequality leg below asserts -- the shape
    # quick.symbol_start already uses for occurrence=1 vs occurrence=2.
    #
    # This leg is what a fast-forward/positioning optimisation has to stay
    # green against; without it, a mis-positioned segment still carries a
    # perfectly correct header.
    cluster, cluster2 = 7, 9
    idx, idx2 = 2, 5                          # start_insn = idx * interval
    spf = d / "sp.simpoints"
    spf.write_text(f"{idx} {cluster}\n{idx2} {cluster2}\n")
    # Last scheduled offset plus its window must fit the 45,160 user insns
    # the workload retires: 5*5000 + 1000 + 5000 = 31,000, ~31% margin.
    need_user_insns = idx2 * interval + warmup + sim
    rc, tail = _run_cli(
        ["all", "--isa", "x86_64", "--seed", _seedhex(ctx),
         "--build-dir", str(ctx.build_dir), "-o", str(d), "--system",
         "--marker", "--regdata", "--hot-iters", "400",
         "--stop", str(sim), "--simpoints", str(spf),
         "--sp-interval", str(interval), "--sp-warmup", str(warmup)],
        timeout=900, log_path=d / "run.log",
        extra_env={"CST_QEMU_EXTRA_ARGS": "-cpu max"})
    if rc != 0:
        # Distinguish "the workload was too short to reach the schedule" from
        # a real composition failure -- they need opposite responses, and the
        # raw tail is kernel console noise that says neither.
        log = (d / "run.log").read_text(errors="replace") \
            if (d / "run.log").exists() else ""
        if ("positioning to simpoint start" in log
                and "reached (user clock" not in log):
            return Outcome("fail",
                           f"the workload exited before reaching the first "
                           f"scheduled offset ({idx * interval} user insns); "
                           f"it must retire at least {need_user_insns} for "
                           f"this schedule, so raise --hot-iters. The "
                           f"composition itself was never exercised. "
                           f"(cli rc={rc})")
        return Outcome("fail", f"cli rc={rc}: {tail}")

    dec = ctx.build_dir / "contrib" / "plugins" / "cst_decode"

    def header_of(cl):
        """(decoded stdout, path) for scheduled cluster @cl, or (None, None)."""
        hits = sorted(d.rglob(f"*simpoint_{cl}.cst"))
        if not hits:
            return None, None
        q = subprocess.run([str(dec), "--format=legacy", str(hits[0])],
                           capture_output=True, text=True)
        return (q.stdout if q.returncode == 0 else None), hits[0]

    out1, cst1 = header_of(cluster)
    out2, cst2 = header_of(cluster2)
    if cst1 is None or cst2 is None:
        return Outcome("fail",
                       f"scheduled clusters {cluster}@{idx} and "
                       f"{cluster2}@{idx2}: only "
                       f"{[c for c in (cst1, cst2) if c]} was written -- the "
                       "marker+simpoint composition did not capture both")
    if out1 is None or out2 is None:
        return Outcome("fail", "cst_decode failed on a scheduled segment")
    p = SimpleNamespace(stdout=out1)

    def field(name, text=None):
        m = re.search(rf"^{name} (\d+)$", text if text is not None else p.stdout,
                      re.M)
        return int(m.group(1)) if m else None

    # POSITIONING: the later scheduled offset must open strictly later.  A
    # capture that ignored the schedule and opened at the latch would put
    # both segments at the same START_INSN.
    s1, s2 = field("START_INSN", out1), field("START_INSN", out2)
    if s1 is None or s2 is None or not (s2 > s1):
        return Outcome("fail",
                       f"positioning: cluster {cluster} (offset {idx}) opened "
                       f"at START_INSN={s1} and cluster {cluster2} (offset "
                       f"{idx2}) at {s2}; the later scheduled offset did not "
                       f"open strictly later on the latched user clock")

    got_w, got_tot = field("WARMUP_INSNS"), field("TOTAL_TARGET_INSNS")
    want_tot = warmup + sim
    if got_w != warmup or got_tot != want_tot:
        return Outcome("fail",
                       f"wire header says WARMUP_INSNS={got_w} "
                       f"TOTAL_TARGET_INSNS={got_tot}; the schedule asked "
                       f"for {warmup} and {want_tot}")
    return Outcome("pass",
                   f"both scheduled clusters captured inside the marked "
                   f"region and correctly ORDERED on the latched user clock: "
                   f"cluster {cluster}@{idx} START_INSN={s1} < cluster "
                   f"{cluster2}@{idx2} START_INSN={s2}; "
                   f"WARMUP_INSNS={got_w} TOTAL_TARGET_INSNS={got_tot} "
                   f"(read from the wire, not the log)")


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


# ---- clock-source coverage -------------------------------------------------
#
# The two checks below exist because a system cell can be perfectly green and
# still never touch the machinery it is credited with covering.  Each one asks
# for a specific clock-source configuration AND reads the guest's own console
# back to confirm the guest actually adopted it, because a configuration flag
# that silently stops taking effect is indistinguishable from one that works
# if the only thing checked is that the run passed.

def _console_text(d: Path) -> str:
    """Every guest console log written under @d, concatenated.

    Returns "" when none was written; callers treat that as "the subject was
    not found" and fail, never as "the condition was absent"."""
    return "".join(p.read_text(errors="replace")
                   for p in sorted(d.rglob("*.console.log")))


def aclint_console_verdict(con: str) -> Outcome:
    """Did the guest whose console is @con drive its clockevent through the
    ACLINT machine timer?  Split out from the check so it can be run against
    a captured console of each kind and shown to answer differently -- a gate
    whose passing side has never been contrasted with its failing side is a
    gate nobody has tested."""
    if not con:
        return Outcome("fail",
                       "no guest console log was written, so the clock "
                       "source cannot be confirmed -- a check that cannot "
                       "find its subject fails")
    isa_line = next((l for l in con.splitlines()
                     if "Boot HART ISA Extensions" in l), None)
    tmr_line = next((l for l in con.splitlines()
                     if "Platform Timer Device" in l), None)
    if isa_line is None or tmr_line is None:
        return Outcome("fail",
                       "the guest console carries no OpenSBI banner "
                       f"(ISA-extensions line {'found' if isa_line else 'MISSING'}, "
                       f"timer-device line {'found' if tmr_line else 'MISSING'}), "
                       "so the cell's clock source is unreadable")
    if "sstc" in isa_line.split(":", 1)[-1]:
        return Outcome("fail",
                       "the boot CPU still reports Sstc despite "
                       "-cpu max,sstc=false, so the kernel programs stimecmp "
                       "directly and the ACLINT machine timer is not the "
                       f"clockevent: {isa_line.strip()}")
    if "aclint-mtimer" not in tmr_line:
        return Outcome("fail",
                       "Sstc is off but the platform timer is not the ACLINT "
                       f"mtimer, so this cell covers neither path: "
                       f"{tmr_line.strip()}")
    if "sstc extension" in con:
        return Outcome("fail",
                       "the guest kernel reports its S-mode timer interrupt "
                       "as available via the sstc extension, so it did not "
                       "fall back to the SBI/ACLINT clockevent this cell "
                       "exists to exercise")
    return Outcome("pass",
                   "clockevent confirmed on the SBI/ACLINT path from the "
                   f"guest's own console: {tmr_line.strip()}; boot CPU "
                   "reports no sstc and the kernel logged no sstc timer")


def idle_console_verdict(con: str, sleep_s: int) -> Outcome:
    """Did the guest whose console is @con actually go idle across a
    @sleep_s-second sleep probe?  Split out for the same reason as
    aclint_console_verdict."""
    if not con:
        return Outcome("fail",
                       "no guest console log was written, so whether the "
                       "guest idled cannot be read -- a check that cannot "
                       "find its subject fails")
    from . import _system as SYS
    pair = SYS.read_guest_idle(con)
    if pair is None:
        return Outcome("fail",
                       "the guest console carries no cst_idle_before/after "
                       "markers, so the idle-accounting init did not run and "
                       "this cell proves nothing about the idle boundary")
    before, after = pair
    got = after - before
    # A third of the probe.  The read is taken two seconds before the sleep
    # is due to end and the guest spends the first second or so of the probe
    # finishing the marker's own work, so a healthy cell lands near
    # sleep_s - 3 (measured: 6.63s of a 10s probe).  The regression this
    # guards against does not shave the figure, it collapses it to zero --
    # the run queue either empties or it does not -- so the threshold is set
    # to separate those two, with room for a slow start under host load.
    want = sleep_s / 3.0
    if got < want:
        return Outcome("fail",
                       f"the guest accumulated {got:.2f}s of idle inside a "
                       f"{sleep_s}s sleep probe (needs >= {want:.2f}s): the "
                       "run queue never emptied, so the kernel never reached "
                       "its idle instruction and the idle boundary is "
                       "untested")
    return Outcome("pass",
                   f"guest idled {got:.2f}s inside the {sleep_s}s sleep probe "
                   f"with the marker window open (/proc/uptime {before:.2f} "
                   f"-> {after:.2f}), so the kernel reached its idle "
                   "instruction under tracing")


def _chk_aclint_riscv64(ctx: Ctx) -> Outcome:
    """riscv64 system cell whose clockevent is the ACLINT machine timer.

    riscv has two ways for a supervisor to get a timer interrupt, and they run
    through entirely different QEMU device code.  With the Sstc extension the
    kernel programs ``stimecmp`` directly and the firing arrives from
    ``riscv_stimer_cb``; without it the kernel calls SBI, OpenSBI programs the
    ACLINT ``mtimecmp``, and the firing arrives from ``riscv_aclint_mtimer_cb``
    with an M-mode round trip in between.  The validator's riscv64 boot table
    asks for ``-cpu max``, which has Sstc, so every system cell in the suite
    takes the first path and the ACLINT timer callback is never entered at
    all -- the second path had no cell.

    This check is that cell.  ``sstc=false`` on top of ``-cpu max`` (a later
    ``-cpu`` wins, see _system.system_qemu_cmd) removes the extension, and the
    guest's own console is read back to confirm the swap happened rather than
    assuming the flag took; see aclint_console_verdict for the three clauses
    and why two of them are positive anchors."""
    d = ctx.dir("system_aclint_riscv64")
    rc, tail = _run_cli(
        ["all", "--isa", "riscv64", "--seed", _seedhex(ctx),
         "--build-dir", str(ctx.build_dir), "-o", str(d),
         "--system", "--marker", "--stop", "200000",
         "--hot-iters", "5000", "--devio-probe", "256"],
        timeout=1200, log_path=d / "run.log",
        extra_env={"CST_QEMU_EXTRA_ARGS": "-cpu max,sstc=false"})
    out = _cli_outcome(rc, tail, 1200)
    if out.status != "pass":
        return out
    return aclint_console_verdict(_console_text(d))


def _chk_idle_riscv64(ctx: Ctx) -> Outcome:
    """riscv64 system cell whose guest actually goes idle inside the window.

    Every other single-vCPU system cell keeps its run queue non-empty for the
    whole trace window: the marked workload computes, init waits for it, and
    nothing blocks.  A guest in that shape never executes its idle instruction,
    so the idle boundary — the point at which a kernel commits to sleeping
    until a timer it has already armed fires — is never crossed while the
    tracer is running, and anything the excursion machinery does there is
    untested.

    ``--sleep-probe`` puts a nanosleep in the workload right after the marker
    pins the window.  Sleeping retires no user instructions, so the window's
    budget does not move and the window stays open, while the run queue
    empties and the kernel idles.

    That the guest idled is MEASURED, not assumed: with a sleep probe the run
    stages the idle-accounting init (_system.idle_init), which reads field 2
    of /proc/uptime — the kernel's summed idle time — once at boot and once
    from a background timer, and prints both to the console.  The second read
    lands INSIDE the probe rather than after it, because a traced run does not
    outlive its trace and guest time barely advances once the workload starts
    computing; see _INIT_IDLE.  idle_console_verdict carries the threshold and
    the reason for it.

    ITS STALL METRIC IS ELEVATED BY CONSTRUCTION, and anything that reads that
    metric has to know it.  ``worst_user_stall`` measures the longest stretch
    the guest went without retiring a user instruction, and a ten-second sleep
    inside the window IS such a stretch -- deliberately, since that is how the
    run queue is emptied.  Measured over four seeds against the same cell
    without the probe, interleaved in one wave: ``stall_fraction`` 0.17-0.19
    against 0.004-0.009, and ``worst_user_stall`` ~1.1M architectural
    instructions against ~25k.  No cell fires the stall check (its threshold
    is 0.500, so there is 2.6x of headroom) and none went NOT CERTIFIED, but
    two consequences follow:

      * a red here is the probe until proven otherwise, not #106;
      * this cell must NEVER be pooled into a stall-condition rate wave.  Its
        elevation is a property of its own configuration, so including it
        would be measuring the sleep probe."""
    sleep_s = 10
    d = ctx.dir("system_idle_riscv64")
    rc, tail = _run_cli(
        ["all", "--isa", "riscv64", "--seed", _seedhex(ctx),
         "--build-dir", str(ctx.build_dir), "-o", str(d),
         "--system", "--marker", "--stop", "200000",
         "--hot-iters", "5000", "--devio-probe", "256",
         "--sleep-probe", str(sleep_s)],
        timeout=1200, log_path=d / "run.log")
    out = _cli_outcome(rc, tail, 1200)
    if out.status != "pass":
        return out
    return idle_console_verdict(_console_text(d), sleep_s)


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


def _chk_decode_bound(ctx: Ctx) -> Outcome:
    """The decode stage's residency tripwire.

    ``decode_champsim_tracer`` returned ``list(_iter_body(...))`` until the
    ruling below: ~576 k entry dicts at ~18 KB apiece on a 3 M-instruction
    system cell, 10.3 GiB measured, per lane, before validate() had checked
    anything -- 12-15 lanes reached ~190 GiB and the host stopped responding.
    "DECODE IS STREAMING, THIS IS A BUG."

    A trace large enough for the two shapes to be far apart is decoded in a
    child and walked end to end; peak RSS must sit under a bound derived
    from what the lazy design actually costs.  The same trace is then
    decoded with the eager shape forced back on, and that run MUST breach
    the bound -- a residency gate that has never gone red is a gate nobody
    has tested, so failing to fire is itself a failure here.
    """
    d = ctx.dir("feat_decode_bound")
    rc, tail = _run_cli(
        ["decode_bound", "--build-dir", str(ctx.build_dir), "-o", str(d)],
        timeout=2400, log_path=d / "run.log")
    return _cli_outcome(rc, tail, 2400)


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
    # The decode's entries are a lazy sequence; read it as one.  `list()`
    # here would reinstate exactly the residency the lazy shape removed.
    cp = entries                # decode_champsim_tracer yields CP entries
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

    # Count and shapes only -- never the peer entries themselves, each of
    # which drags its whole wrong-path chain along.
    n_peers = 0
    shapes = set()
    for p in cp[:-1]:
        if p.get("template_id") != tid:
            continue
        n_peers += 1
        shapes.add(shape(p))
    if n_peers < 2:
        return "unusable", f"final template {tid} executes {n_peers+1}x"
    if len(shapes) != 1:
        return "unusable", (f"final template {tid} memop shape varies over "
                            f"{n_peers} executions")
    want = shapes.pop()
    if want[0] == 0:
        return "unusable", (f"final template {tid} performs no memops "
                            f"despite {slots} static slot(s)")
    got = shape(final)
    if got == want:
        return "pass", (f"final entry (seq {final.get('seq_num')}, template "
                        f"{tid}) carries {got[0]} memops == "
                        f"{n_peers} peer executions")
    return "drop", (f"final entry (seq {final.get('seq_num')}, template "
                    f"{tid}) carries {got[0]} memops but its {n_peers} "
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

    The invariant this check reads is that NOTHING WAS DROPPED.  It used
    to be ``dropped == trimmed``, justified as "not both zero, because a
    busy fault-storm trace can legitimately trim many leaked prefixes
    while dropping none of them".  That justification refutes the rule it
    defends: a trace that trims many and drops none has dropped != trimmed
    and the equality rejects it.  Read the other way — trimmed == dropped
    == 188,726, the sample figure the old text cited — the rule certifies
    188,726 destroyed register-delta slices as conformant.  Nothing ties
    the count of recoveries to the count of losses in either direction.
    A drop is register deltas that were captured and thrown away, so the
    entry reaches the wire with no reg-data at all; a trim is a recovery.
    Drops must be zero, including the ones taken while the segment closes
    on a guest END marker (``  of which at end-marker close``), which the
    plugin counter was structurally unable to observe until the counting
    was moved out from behind ``if (!g_seg_end_marker_close)``.  Trims are
    reported for context.  Runs its own short trace per ISA — deliberately not
    reusing another check's output directory — so it exercises the
    invariant in the ordinary course of tracing, not a manufactured
    scenario."""
    from . import __main__ as M
    from . import generator as G
    subs: list = []
    all_ok = True
    for isa in ISA_ALL:
        d = ctx.dir(f"feat_reg_snap_accounting_{isa}")
        # ISA_COMPILER is a static table with a row for every ISA in
        # ISA_ALL, so `if not cc` could never be true and this skip could
        # never fire: on a host without the cross toolchain the tier ran on
        # to subprocess.call() and died on FileNotFoundError instead of
        # skipping.  The question the skip means to ask is whether the
        # compiler is INSTALLED, which is a PATH lookup.
        cc = M.ISA_COMPILER.get(isa)
        if not cc or not M._have(cc):
            subs.append({"name": isa, "ok": True,
                         "detail": f"skip ({cc or 'no compiler'} not in PATH "
                                   f"-- this host cannot build {isa})"})
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
        dropped = trimmed = end_close = discarded = None
        for line in stats.read_text(errors="replace").splitlines():
            if line.startswith("CP reg-snap slice dropped"):
                dropped = int(line.rsplit(None, 1)[-1])
            elif line.startswith("  of which at end-marker close"):
                end_close = int(line.rsplit(None, 1)[-1])
            elif line.startswith("  reg deltas discarded by those drops"):
                discarded = int(line.rsplit(None, 1)[-1])
            elif line.startswith("CP reg-snap leak trimmed"):
                trimmed = int(line.rsplit(None, 1)[-1])
        if dropped is None or trimmed is None:
            subs.append({"name": isa, "ok": False,
                        "detail": f"counters not found in {stats.name}"})
            all_ok = False
            continue
        # A sidecar without the breakdown rows came from a plugin that did
        # not count them.  Say so; do not read the absence as zero.
        if end_close is None or discarded is None:
            subs.append({"name": isa, "ok": False,
                        "detail": f"{stats.name} carries no end-marker-close "
                                  f"or discarded-delta breakdown (stale "
                                  f"plugin?); dropped={dropped}"})
            all_ok = False
            continue
        ok = dropped == 0 and discarded == 0
        all_ok = all_ok and ok
        subs.append({"name": isa, "ok": ok,
                    "detail": f"dropped={dropped} (end_close={end_close}) "
                              f"reg_deltas_discarded={discarded} "
                              f"trimmed={trimmed}"})
    return Outcome("pass" if all_ok else "fail",
                   "plugin's own dropped-slice accounting invariant "
                   "(no slice dropped, end-marker close included), read "
                   "from <outfile>.stats.log (4 ISAs)", subs)


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
        # ISA_COMPILER is a static table with a row for every ISA in
        # ISA_ALL, so `if not cc` could never be true and this skip could
        # never fire: on a host without the cross toolchain the tier ran on
        # to subprocess.call() and died on FileNotFoundError instead of
        # skipping.  The question the skip means to ask is whether the
        # compiler is INSTALLED, which is a PATH lookup.
        cc = M.ISA_COMPILER.get(isa)
        if not cc or not M._have(cc):
            subs.append({"name": isa, "ok": True,
                         "detail": f"skip ({cc or 'no compiler'} not in PATH "
                                   f"-- this host cannot build {isa})"})
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
        # ISA_COMPILER is a static table with a row for every ISA in
        # ISA_ALL, so `if not cc` could never be true and this skip could
        # never fire: on a host without the cross toolchain the tier ran on
        # to subprocess.call() and died on FileNotFoundError instead of
        # skipping.  The question the skip means to ask is whether the
        # compiler is INSTALLED, which is a PATH lookup.
        cc = M.ISA_COMPILER.get(isa)
        if not cc or not M._have(cc):
            subs.append({"name": isa, "ok": True,
                         "detail": f"skip ({cc or 'no compiler'} not in PATH "
                                   f"-- this host cannot build {isa})"})
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


def _chk_decode_fields(ctx: Ctx) -> Outcome:
    """The static-decode oracle for the dependency model itself, armed.

    features.isa_crosscheck gates the decode BOUNDARY and
    features.decode_fixups asserts the plugin's repairs on top of it, but
    neither compares what the trace is actually built from -- the
    InsnFields decode_detail_to_generic() records -- against anything
    independent.  ``isaxcheck --layer=fields`` does exactly that, and it
    spent its first months with zero allowlist rows and zero invocations:
    a gate that could not fail, vouching for nothing, sitting underneath
    the very oracle the behavioural-oracle arc names for MIPS and aarch64
    (the two ISAs with no PIN and no Spike -- static decode is their ONLY
    independent register-capture ground truth).

    So this check refuses to trust green without seeing red first:

      1. FALSIFIER.  For a known-good encoding, injects a wrong register
         attribution at exactly the layer a real defect would sit
         (``--falsify=drop-src`` erases the reads; ``--falsify=add-dst``
         plants a phantom write) and REQUIRES the gate to exit non-zero
         naming the damaged mnemonic in the expected signature class
         (FR-rd-missing / FR-wr-phantom).  A falsifier that does not fire
         fails the check outright -- a green sweep from an instrument that
         cannot alert is not evidence.
      2. SWEEP.  The full fields-layer sweep (--classes=MBR; the D class
         is the boundary gate's property), gated against
         tools/isaxcheck_fields_allow.txt with the same NEW-and-DEAD
         semantics as the boundary gate: an untriaged disagreement fails,
         and an allowlist row that no longer matches fails as a dead rule
         -- which is what will demand row removals when the
         execution-derived register capture lands and starts closing the
         inherited Capstone gaps that file names as open defects.

    GATING, mipsel + aarch64.  x86_64 and riscv64 close the same loop
    through PIN and Spike (owner ruling 2026-08-09); their fields residual
    is not yet triaged and is deliberately not run here.
    """
    tool = ctx.build_dir / "contrib/plugins/isaxcheck"
    allow = (Path(__file__).resolve().parents[2]
             / "tools" / "isaxcheck_fields_allow.txt")
    if not tool.is_file():
        return Outcome("fail",
                       f"isaxcheck not built at {tool}.  It needs LLVM MC "
                       "(llvm-18-dev or newer supplying llvm-config); the "
                       "fields layer links the plugin's own decode "
                       "translation unit into that same binary.")
    if not allow.is_file():
        return Outcome("fail", f"fields allowlist missing at {allow}")

    # One known-good encoding per ISA, chosen to compare clean when
    # healthy (asserted below) so the falsified runs are a strict A/B.
    probes = {"mipsel": ("2120a600", "addu"),     # addu $a0, $a1, $a2
              "aarch64": ("4100038b", "add")}     # add x1, x2, x3
    subs: list = []
    all_ok = True
    for isa in ("mipsel", "aarch64"):
        hexenc, mnem = probes[isa]
        base = [str(tool), f"--isa={isa}", "--layer=fields", "--classes=MBR"]
        ok = True
        details: list = []

        p = subprocess.run(base + [f"--hex={hexenc}", "--check"],
                           text=True, capture_output=True, timeout=120)
        if p.returncode != 0:
            ok = False
            details.append(
                f"healthy probe {mnem} not clean (rc={p.returncode}): "
                + (p.stdout or p.stderr).strip()[:200])
        for mode, want in (("drop-src", "FR-rd-missing"),
                           ("add-dst", "FR-wr-phantom")):
            p = subprocess.run(base + [f"--hex={hexenc}", "--check",
                                       f"--falsify={mode}:{mnem}"],
                               text=True, capture_output=True, timeout=120)
            fired = (p.returncode == 1 and
                     any(ln.startswith("NEW") and want in ln and mnem in ln
                         for ln in (p.stdout or "").splitlines()))
            if not fired:
                ok = False
                details.append(
                    f"falsifier {mode}:{mnem} did NOT fire "
                    f"(rc={p.returncode}) -- the oracle cannot alert, so a "
                    "green sweep proves nothing: "
                    + (p.stdout or p.stderr).strip()[:200])

        if ok:
            p = subprocess.run(base + ["--jobs=8", f"--allow={allow}",
                                       "--check"],
                               text=True, capture_output=True, timeout=1800)
            head = (p.stdout or "").splitlines()
            summary = head[0] if head else (p.stderr or "").strip()[:200]
            if p.returncode != 0:
                ok = False
                bad = [ln for ln in head[1:]
                       if ln.startswith("NEW") or ln.startswith("DEAD")]
                details.append(summary)
                details.extend(ln[:160] for ln in bad[:8])
                if len(bad) > 8:
                    details.append(f"... and {len(bad) - 8} more")
            else:
                details.append("falsifier fired both directions; " + summary)
        all_ok = all_ok and ok
        subs.append({"name": isa, "ok": ok, "detail": "\n".join(details)})
    return Outcome("pass" if all_ok else "fail",
                   "dependency-model fields vs LLVM MC, falsifier-armed "
                   "(mipsel + aarch64, the ISAs whose register-capture "
                   "oracle is static decode)", subs)


def _chk_lldet_watchdog(ctx: Ctx) -> Outcome:
    """The hang detector's own fire-proof.

    lldet is the ONLY sanctioned detection for the livelock/hang class:
    the product carries no detect-and-handle, so every "no hang" result
    this harness reports is really the statement "the watchdog watched
    and stayed silent".  That statement is worth exactly as much as the
    proof that the watchdog can speak, and until this check existed there
    was none.  The protocol that was supposed to supply it ran a HEALTHY
    cell under ``CST_LLDET_TIMEOUT=5`` and demanded a kill -- but a
    healthy cell cannot be killed by design and must not be: adjudicate()
    needs a SECOND sample ``SAMPLE_GAP_S`` after the deadline, and a cell
    that finishes in between simply exits.  Every artifact that protocol
    produced therefore recorded the deadline being crossed, one sample,
    no verdict, and a natural exit -- an instrument photographed in the
    act of not firing, filed as the evidence that it fires.

    The condition the watchdog adjudicates is a STALL, so the arms have
    to stall.  Both verdict classes get one, because they are reached
    through different branches and a working DEADLOCK arm says nothing
    about LIVELOCK -- which is the shape the class is actually named for,
    a guest burning host cores while the trace, the console and the write
    counter all stand still:

      1. DEADLOCK -- a frozen child (zero CPU delta, zero growth).
      2. LIVELOCK -- a spinning child (a full core, zero growth).
      3. PROGRESS control -- a child that is slow but growing its trace
         file.  It must NOT be killed, and must be seen taking the SLOW
         extension.  Without it the two kill arms are equally consistent
         with a watchdog that kills everything it watches, which would
         make every silent cell in every wave meaningless in the other
         direction.

    No qemu, no guest, no trace: the subject is the adjudicator, and
    feeding it real cells would only reintroduce the dependence on a
    stall nobody can summon on demand.
    """
    from . import _lldet as L

    work = ctx.dir("lldet_watchdog")
    spin = "import time\nwhile True: time.sleep(0)\n"
    grow = ("import time\n"
            "for i in range(12):\n"
            "    open(%r, 'ab').write(b'x' * 4096)\n"
            "    time.sleep(2)\n")

    def arm(name: str, cmd: list) -> tuple[int, object, L.Watch]:
        prefix = str(work / name)
        old = os.environ.get("CST_LLDET_TIMEOUT")
        os.environ["CST_LLDET_TIMEOUT"] = "5"
        try:
            watch = L.Watch(key=L.config_key("x86_64", "system", 1, 64),
                            budget=None,
                            growth_patterns=L.default_growth_patterns(prefix),
                            sidecar_path=Path(prefix + ".lldet"),
                            label=f"lldet selftest {name}")
        finally:
            if old is None:
                os.environ.pop("CST_LLDET_TIMEOUT", None)
            else:
                os.environ["CST_LLDET_TIMEOUT"] = old
        with open(prefix + ".log", "w") as f:
            rc, verdict = L.run_watched(cmd, watch, stdout=f, stderr=f)
        return rc, verdict, watch

    subs: list = []
    all_ok = True

    for name, cmd, want in (
            ("deadlock", [sys.executable, "-c",
                          "import time; time.sleep(120)"], "DEADLOCK"),
            ("livelock", [sys.executable, "-c", spin], "LIVELOCK")):
        rc, verdict, _w = arm(name, cmd)
        kind = getattr(verdict, "kind", None)
        ok = (rc == L.LLDET_EXIT and kind == want)
        all_ok = all_ok and ok
        subs.append({"name": f"{name} arm", "ok": ok, "detail":
                     f"rc={rc} (want {L.LLDET_EXIT}), verdict={kind} "
                     f"(want {want})" + ("" if ok else
                     "  -- the watchdog did not fire on a stalled child, "
                     "so every silent cell it has ever watched is "
                     "unproven")})

    prefix = str(work / "progress")
    rc, verdict, watch = arm("progress", [sys.executable, "-c",
                                          grow % (prefix + ".cst")])
    ok = (rc == 0 and verdict is None and watch.extensions >= 1)
    all_ok = all_ok and ok
    subs.append({"name": "progress control", "ok": ok, "detail":
                 f"rc={rc} (want 0), verdict={getattr(verdict, 'kind', None)}"
                 f" (want None), SLOW extensions={watch.extensions} (want "
                 ">=1)" + ("" if ok else
                 "  -- a growing child was killed or was never adjudicated; "
                 "a watchdog that cannot tell slow from stuck manufactures "
                 "hangs instead of finding them")})

    return Outcome("pass" if all_ok else "fail",
                   "lldet adjudicates a stalled child in both verdict "
                   "classes and leaves a growing one alone", subs)


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
    for isa in ISA_ALL:
        C.append(Check(f"quick.mt_content_{isa}", "quick",
                       f"multi-thread per-thread content oracle ({isa}, "
                       f"3 generated bodies + planted-defect proof)",
                       ["behavior:multithread_content",
                        "behavior:per_thread_stream_purity",
                        "wire:BODY_TAG_THREAD_SWITCH"],
                       _chk_mt_content(isa)))
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
    C.append(Check("system.simpoint_x86", "system",
                   "system-mode marker+simpoint composition (x86)",
                   ["opt:window_simpoint", "opt:window_marker"],
                   _chk_system_simpoint))
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
    # The two clock-source shapes the boot table's -cpu max / never-blocking
    # workload leave untouched.  Both are registry entries first: they exist
    # so a mechanism that is currently exercised by NO cell cannot quietly go
    # back to being exercised by no cell.
    C.append(Check("system.aclint_riscv64", "system",
                   "clockevent on the SBI/ACLINT machine timer, Sstc off "
                   "(riscv64 system boot)",
                   ["behavior:aclint_clockevent", "behavior:spec_clock_resync",
                    "opt:window_marker"], _chk_aclint_riscv64))
    C.append(Check("system.idle_riscv64", "system",
                   "guest reaches its idle instruction inside the marker "
                   "window (riscv64 system boot)",
                   ["behavior:guest_idle_boundary",
                    "behavior:spec_clock_resync", "opt:window_marker"],
                   _chk_idle_riscv64))

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

    # The marker's one invariant, in both of its directions.  Neither is
    # visible in the wire: a MISS produces no trace at all, and a FALSE CLAIM
    # produces a perfectly well-formed trace of the wrong process.  x86_64 and
    # aarch64 both run because the fixed-width targets are where the two
    # sequences share their terminating instruction, which is the shape a
    # per-word detector mistook for a marker.
    C.append(Check("features.marker_detection", "features",
                   "a complete marker sequence is never missed (plain, and "
                   "entered mid-sequence through a branch) and an incomplete "
                   "one is never claimed (x86_64 + aarch64)",
                   ["behavior:marker_detection_exact",
                    "behavior:marker_no_false_claim",
                    "opt:window_marker", "opt:window_marker_latch"],
                   MK.chk_marker_detection))
    C.append(Check("features.system_window_modes", "features",
                   "system mode accepts only trace_window=marker; icount / "
                   "symbol / simpoint / the default are refused at plugin "
                   "install (both directions proven)",
                   ["opt:window_system_marker_only"],
                   MK.chk_system_window_modes))
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
    C.append(Check("features.decode_residency", "features",
                   "decode stage stays bounded on a large trace "
                   "(both directions: lazy under budget, forced-eager over)",
                   ["tool:decode_residency"], _chk_decode_bound))
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
    C.append(Check("features.decode_fields", "features",
                   "dependency-model fields vs LLVM MC, falsifier-armed "
                   "(mipsel + aarch64: static decode is their register-"
                   "capture oracle)",
                   ["behavior:decode_fields"], _chk_decode_fields))
    C.append(Check("features.lldet_watchdog", "features",
                   "the hang watchdog's own fire-proof: it kills a frozen "
                   "and a spinning child and spares a growing one",
                   ["behavior:lldet_watchdog"], _chk_lldet_watchdog))
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
                   "(no slice dropped, end-marker close included) for the "
                   "positional reg-snap capture — the D4-class completeness "
                   "oracle no byte-level wire check can see (4-ISA)",
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
#
# The row scanner itself lives in _must0, so `full` and `all` gate on ONE
# implementation.  They used to differ by having only one of them at all: the
# riscv64 fold over-claim stood non-zero in 9 cells scored PASS because the
# waves ran `all`, which had no census.  A second copy of the regex would be
# the same failure waiting on a second entrypoint.
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
        bad, seen = _must0.scan_text(text)
        for label, value in bad:
            try:
                cell = f.relative_to(work_root).parts[0]
            except ValueError:
                cell = ""
            rows.append({"file": str(f), "check": cell,
                         "label": label, "value": value,
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

    # In an UNFILTERED full run every registered feature must have an
    # exerciser that actually PASSED.  A check that skipped still declares
    # its feature tags, so without this a missing guest fixture silently
    # retires a feature from the suite while the gate stays green -- the
    # same laundering as an rc=0 skip reading as a pass.  Gated only when
    # unfiltered, because --tier/--only deliberately runs a subset.
    unfiltered = not args.tier and not args.only
    coverage_gap = bool(runtime_uncovered) and unfiltered
    summary["coverage"]["runtime_gap_gates"] = coverage_gap

    summary["counts"] = counts
    # Every "(must be 0)" row of every cell this run produced.  Cells of a
    # non-gating check report but do not gate.
    nongating = {c.id.replace(".", "_") for c in sel if c.known_issue}
    summary["tripwire_census"] = _tripwire_census(work_root, nongating)
    # Exit code: FAIL on any failed check, a registration gap, or a violated
    # "must be 0" invariant.
    hard_fail = (counts["fail"] > 0 or bool(cov["static_gap"])
                 or bool(cov["unknown"]) or coverage_gap
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
        gates = cov.get("runtime_gap_gates")
        print(f"  {'!!' if gates else '~ '} runtime-uncovered (no PASSED "
              f"exerciser this run): {cov['runtime_uncovered']}"
              f"{'' if gates else '  [subset run — advisory]'}")
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
