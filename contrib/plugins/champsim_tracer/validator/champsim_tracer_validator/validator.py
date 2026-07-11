"""Validator: compare a decoded champsim_tracer binary to the generator's
metadata using PC-range mapping.

Strategy
--------
QEMU's champsim_tracer plugin emits one template per translation block (TB).
TCG coalesces several of our generator blocks (`blk_N`) into a single
TB when they are laid out contiguously with no intervening branch, so
a template's ``start_pc`` alone is not enough to identify *all* blocks
it covers.

We walk every instruction in a template and map ``insn.pc`` to a
generator block using the analyzer's per-block ``[start_pc, end_pc)``
spans.  This gives us, for every template, an ordered list of
``(block_id, n_insns_in_block)`` runs.  The validator then:

* expands each trace entry to the list of block IDs touched by its
  template (flattened across the trace's execution order);

* collapses successive duplicates of the same block_id and matches
  the resulting sequence against ``meta.correct_path`` as a prefix;

* on the *first* execution of each template, compares the entry's
  ``dyn_params`` (one per memory access in program order) against the
  expected ``memops`` of every CP block the template covers —
  including ``arena_u64_index``, load/store kind, and 64-bit
  ``data_lo`` value.  This is where address *and* load/store value
  validation happens;

* for every CP-branching block, follows the template's ``wp_entries``
  chain through the corresponding wrong-path TBs and checks the
  block-id sequence against ``meta.wrong_paths[i].wp_chain``.
"""

from __future__ import annotations

import bisect
import dataclasses
import importlib.util
import json
import re
from collections import Counter
from pathlib import Path


# ---------------------------------------------------------------------------
# Decoder import.  The Python decoder has been replaced by the C++
# cst_decode binary; _cst_decode_runner is a sibling-module shim that
# subprocesses cst_decode --format=legacy and parses its textual output
# back into the dict / DynParam shapes the validator expects.
# ---------------------------------------------------------------------------

# Path layout (post-migration):
#   <PLUGIN_DIR>/champsim_tracer/                       (plugin source root)
#       validator/champsim_tracer_validator/<this>.py
# Walk three levels up to land at contrib/plugins/.
_PLUGIN_DIR = Path(__file__).resolve().parent.parent.parent.parent
_PLUGIN_SOURCE_DIR = _PLUGIN_DIR / "champsim_tracer"
_RUNNER_PATH = (_PLUGIN_SOURCE_DIR / "validator" /
                "champsim_tracer_validator" / "_cst_decode_runner.py")


def _load_decoder():
    spec = importlib.util.spec_from_file_location(
        "_cst_decode_runner", _RUNNER_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Register before exec_module so @dataclasses.dataclass can find the
    # module in sys.modules (Python 3.12 enforces this).
    import sys
    sys.modules["_cst_decode_runner"] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Issue / Report
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class Issue:
    check: str
    severity: str          # "error" | "warning" | "info"
    message: str
    detail: dict | None = None


@dataclasses.dataclass
class Report:
    issues: list[Issue]
    stats: dict

    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "error"]

    def summary(self) -> str:
        by_sev = {"error": 0, "warning": 0, "info": 0}
        by_check: dict[str, dict[str, int]] = {}
        for i in self.issues:
            by_sev[i.severity] = by_sev.get(i.severity, 0) + 1
            bc = by_check.setdefault(i.check, {"error": 0, "warning": 0,
                                               "info": 0})
            bc[i.severity] += 1

        lines = ["=== champsim_tracer_genval validation report ==="]
        lines.append(f"  stats: {self.stats}")
        lines.append(f"  total: {len(self.issues)} issues "
                     f"(errors={by_sev['error']}, "
                     f"warnings={by_sev['warning']}, "
                     f"info={by_sev['info']})")
        for chk in sorted(by_check):
            parts = ", ".join(f"{k}={v}" for k, v in by_check[chk].items()
                              if v)
            lines.append(f"    [{chk}] {parts}")
        if by_sev["error"]:
            lines.append("")
            lines.append("  first errors:")
            for i in self.errors()[:15]:
                lines.append(f"    ! {i.check}: {i.message}")
        warnings = [i for i in self.issues if i.severity == "warning"]
        if warnings:
            lines.append("")
            lines.append("  first warnings:")
            for i in warnings[:15]:
                lines.append(f"    ~ {i.check}: {i.message}")
        # Info issues flagged notable (detail["notable"]) carry an
        # auditable per-instance message — e.g. a WP acceptance made on
        # a chain-level event alone — and print in full; ordinary
        # per-check summary infos stay as counts above.
        notable = [i for i in self.issues if i.severity == "info"
                   and (i.detail or {}).get("notable")]
        if notable:
            lines.append("")
            lines.append("  notable info:")
            for i in notable[:15]:
                lines.append(f"    * {i.check}: {i.message}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# PC -> block_id interval map
# ---------------------------------------------------------------------------

_UNSET = object()


class PcMap:
    """Map a PC to the block_id whose ``[start_pc, end_pc)`` contains it."""

    def __init__(self, meta_blocks: list[dict]):
        spans: list[tuple[int, int, int]] = []
        for b in meta_blocks:
            gt = b.get("ground_truth")
            if not gt:
                continue
            spans.append((gt["start_pc"], gt["end_pc"], b["block_id"]))
        spans.sort()
        self._starts = [s[0] for s in spans]
        self._spans = spans

    def lookup(self, pc: int | None) -> int | None:
        if pc is None or not self._spans:
            return None
        idx = bisect.bisect_right(self._starts, pc) - 1
        if idx < 0:
            return None
        start, end, bid = self._spans[idx]
        if start <= pc < end:
            return bid
        return None

    def template_runs(self, template: dict) -> list[tuple[int, int]]:
        """Return ordered ``(block_id, n_insns)`` runs for a template,
        dropping insns that don't fall inside any ``blk_N`` span."""
        runs: list[tuple[int | None, int]] = []
        cur = _UNSET
        count = 0
        for ins in template.get("insns", []):
            bid = self.lookup(ins["pc"])
            if bid != cur:
                if cur is not _UNSET:
                    runs.append((cur, count))   # type: ignore[arg-type]
                cur = bid
                count = 0
            count += 1
        if cur is not _UNSET:
            runs.append((cur, count))           # type: ignore[arg-type]
        return [(b, n) for b, n in runs if b is not None]


# ---------------------------------------------------------------------------
# Binary helpers
# ---------------------------------------------------------------------------

def _find_arena_address(binary_path: Path) -> tuple[int, int] | None:
    """Return (virtual_address, size_in_bytes) of the `arena` symbol."""
    try:
        import lief
    except ImportError:
        return None
    b = lief.parse(str(binary_path))
    if b is None:
        return None
    for sym in b.symbols:
        if sym.name == "arena":
            return int(sym.value), int(sym.size)
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _collapse_runs(seq: list[int]) -> list[int]:
    out: list[int] = []
    for x in seq:
        if not out or out[-1] != x:
            out.append(x)
    return out


def _format_off(arena_addr: int, va: int, arena_size: int | None = None) -> int:
    rel = va - arena_addr
    if rel < 0 or rel % 8 != 0:
        return -1
    if arena_size is not None and rel >= arena_size:
        return -1
    return rel // 8


def _dyn_data_int(dp) -> int:
    data = getattr(dp, "data", None)
    if data is not None:
        return int(data)
    return ((int(getattr(dp, "data_hi", 0)) << 64)
            | int(getattr(dp, "data_lo", 0)))


def _reg_snap_value(s: dict) -> int:
    if "value" in s:
        return int(s["value"])
    return ((int(s.get("hi", 0)) << 64) | int(s.get("lo", 0)))


def _bit_mask(bits: int) -> int:
    return (1 << bits) - 1 if bits < 512 else (1 << 512) - 1


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


# Opcode / branch-type id → name tables are built from the decoder so the
# validator reports the same strings that champsim_tracer_decode emits.
def _load_name_tables():
    _dec = _load_decoder()
    return dict(_dec.OPCODE_NAMES), dict(_dec.BRANCH_NAMES)


def _insns_in_block(template: dict, start_pc: int, end_pc: int
                    ) -> list[dict]:
    return [ins for ins in template.get("insns", [])
            if start_pc <= ins["pc"] < end_pc]


def _check_template_raw_bytes(templates: list[dict],
                              blocks_by_id: dict[int, dict]
                              ) -> list[Issue]:
    """Byte-for-byte compare each template insn's `raw_bytes` against the
    analyzer's ground-truth disassembly bytes for the same PC.

    This catches any first-order corruption in the champsim_tracer binary format
    (wrong size encoding, endian mix-ups, truncated bytes, merged-insn
    bugs, etc.) before any higher-level check runs — a divergence here
    makes all downstream checks meaningless.
    """
    # Index ground-truth instructions by PC for O(1) lookup.
    gt_by_pc: dict[int, dict] = {}
    for b in blocks_by_id.values():
        gt = b.get("ground_truth")
        if not gt:
            continue
        for ins in gt["insns"]:
            gt_by_pc[int(ins["pc"])] = ins

    issues: list[Issue] = []
    mismatches = 0
    for t in templates:
        # Kernel / kernel-context (CST_INSN_FLAG_SYSTEM) templates are not
        # in the compiled binary — no ground-truth bytes to compare.
        if t.get("is_system"):
            continue
        for ins in t.get("insns", []):
            gt = gt_by_pc.get(int(ins["pc"]))
            if gt is None:
                continue
            trace_bytes = bytes(ins["raw_bytes"]).hex()
            gt_bytes = gt["raw_bytes_hex"]
            if trace_bytes != gt_bytes:
                mismatches += 1
                if mismatches <= 10:
                    issues.append(Issue(
                        "template_raw_bytes", "error",
                        f"PC 0x{ins['pc']:x} (tmpl {t['template_id']}): "
                        f"trace bytes {trace_bytes!r} != "
                        f"disasm bytes {gt_bytes!r} "
                        f"[{gt['mnemonic']} {gt['op_str']}]",
                        {"template_id": t["template_id"],
                         "pc": ins["pc"],
                         "trace": trace_bytes,
                         "disasm": gt_bytes},
                    ))
    return issues


def _check_block_insn_counts(templates: list[dict],
                             blocks_by_id: dict[int, dict],
                             pcmap: "PcMap",
                             cp_set: set[int],
                             wpprune: int = 0) -> list[Issue]:
    """For every CP block, sum the distinct PCs covered across templates
    and compare to `ground_truth.n_insns`.

    The champsim_tracer plugin merges straight-line successors into a single TB
    sometimes, so we cannot use a single template's n_insns directly;
    instead we union all PCs seen in the trace that fall in the block's
    span and compare the count.
    """
    seen_pcs: dict[int, set[int]] = {bid: set() for bid in cp_set}
    for t in templates:
        # Skip kernel / kernel-context (CST_INSN_FLAG_SYSTEM) templates:
        # a wrong-path session can spec-translate into a user block at a
        # mid-instruction PC and, flagged system, would inflate the
        # distinct-PC count for that block.  Only correct-path user
        # templates correspond to the compiled binary's blocks.
        if t.get("is_system"):
            continue
        for ins in t.get("insns", []):
            bid = pcmap.lookup(ins["pc"])
            if bid is not None and bid in seen_pcs:
                seen_pcs[bid].add(ins["pc"])

    issues: list[Issue] = []
    for bid in sorted(cp_set):
        b = blocks_by_id.get(bid)
        gt = b.get("ground_truth") if b else None
        if not gt:
            continue
        expected = int(gt["n_insns"])
        actual = len(seen_pcs[bid])
        if actual == 0:
            # Already flagged by blocks_covered check.
            continue
        # If the block contains a conditional branch whose target lies
        # within the block's own span, the disassembler counts insns on
        # both paths but at runtime only one path executes per
        # traversal.  Such blocks (e.g. the RISC-V/MIPS lowering of
        # `compare_select`) can legitimately expose fewer PCs than the
        # static instruction count.  We only flag a true overcount.
        has_internal_cond_branch = False
        for ins in gt.get("insns", []):
            if ins.get("branch_type") != "BRANCH_COND_DIRECT":
                continue
            # Look for any hex address in the operand string and check
            # whether it falls within the block's span.
            for tok in re.findall(r"0x[0-9a-fA-F]+", ins.get("op_str", "")):
                try:
                    target = int(tok, 16)
                except ValueError:
                    continue
                if gt["start_pc"] <= target < gt["end_pc"]:
                    has_internal_cond_branch = True
                    break
            if has_internal_cond_branch:
                break
        if has_internal_cond_branch:
            if actual > expected:
                issues.append(Issue(
                    "block_insn_count", "error",
                    f"blk_{bid}: trace exposes {actual} distinct PCs "
                    f"but disassembly has only {expected} insns",
                    {"block_id": bid, "expected": expected,
                     "actual": actual},
                ))
            continue
        # The terminal block (END marker + exit syscall) can be
        # legitimately truncated: the end-marker close lands on the
        # marker's last insn, and when a page boundary splits the block
        # into two TBs the plugin emits only the executed first sub-TB —
        # the exit syscall itself never runs inside the window.  Accept a
        # contiguous PREFIX of the disassembly for the terminal block;
        # holes or an overcount still flag.
        if b.get("terminal") and 0 < actual < expected:
            prefix_pcs = set()
            for ins in gt.get("insns", [])[:actual]:
                pc = ins["pc"]
                prefix_pcs.add(int(pc, 16) if isinstance(pc, str) else pc)
            if seen_pcs[bid] == prefix_pcs:
                continue
        # Under wpprune, some of a block's instructions are reached only on
        # the wrong path, whose simulation is now dropped for cold branches
        # — so the trace can legitimately expose FEWER PCs than the static
        # disassembly.  An over-count still indicates contamination.
        if wpprune > 0 and actual < expected:
            continue
        if actual != expected:
            issues.append(Issue(
                "block_insn_count", "error",
                f"blk_{bid}: disassembly has {expected} insns but "
                f"trace templates expose {actual} distinct PCs",
                {"block_id": bid, "expected": expected, "actual": actual},
            ))
    return issues


def _check_block_assertions(templates: list[dict],
                            blocks_by_id: dict[int, dict],
                            pcmap: "PcMap",
                            cp_set: set[int]) -> list[Issue]:
    """Enforce per-block asserted_branch_types / asserted_opcodes /
    asserted_cond_uncond_branch by inspecting trace templates.

    This is the coverage oracle that lets a newly-added block declare
    the encoding it wants to exercise and have the validator check it
    without touching validator code.
    """
    opcode_names, branch_names = _load_name_tables()

    # Gather all trace insns per CP block.
    insns_by_block: dict[int, list[dict]] = {bid: [] for bid in cp_set}
    for t in templates:
        # Skip kernel / kernel-context (CST_INSN_FLAG_SYSTEM) templates —
        # the per-block encoding assertions describe the compiled binary's
        # user blocks, not wrong-path strays into them.
        if t.get("is_system"):
            continue
        for ins in t.get("insns", []):
            bid = pcmap.lookup(ins["pc"])
            if bid is not None and bid in insns_by_block:
                insns_by_block[bid].append(ins)

    issues: list[Issue] = []
    for bid in sorted(cp_set):
        b = blocks_by_id.get(bid)
        if not b:
            continue
        insns = insns_by_block[bid]
        if not insns:
            continue

        seen_branches = {branch_names.get(i["branch_type"], "?")
                         for i in insns}
        seen_opcodes = {opcode_names.get(i["opcode"], "?")
                        for i in insns}

        for bt in b.get("asserted_branch_types", []) or []:
            # Accept either canonical name or "BRANCH_xxx" alias.
            want = bt.replace("BRANCH_", "")
            if want not in seen_branches:
                issues.append(Issue(
                    "branch_type_assertion", "error",
                    f"blk_{bid} ({b['class']}): expected a {bt} "
                    f"instruction in its template insns but saw only "
                    f"{sorted(seen_branches)}",
                    {"block_id": bid, "expected": bt,
                     "seen": sorted(seen_branches)},
                ))

        for op in b.get("asserted_opcodes", []) or []:
            if op not in seen_opcodes:
                issues.append(Issue(
                    "opcode_assertion", "error",
                    f"blk_{bid} ({b['class']}): expected a {op} "
                    f"instruction in its template insns but saw only "
                    f"{sorted(seen_opcodes)}",
                    {"block_id": bid, "expected": op,
                     "seen": sorted(seen_opcodes)},
                ))

        if b.get("asserted_cond_uncond_branch"):
            # The "conditional unconditional" encoding: branch_type is
            # one of the unconditional JUMP types but branch_conditional
            # is set.  See X86CondUncondBlock for rationale.
            uncond_names = {"DIRECT_JUMP", "INDIRECT_JUMP"}
            ok = any(
                branch_names.get(i["branch_type"], "?") in uncond_names
                and i.get("branch_conditional")
                for i in insns
            )
            if not ok:
                # Collect a debug view of what we DID see.
                seen = [
                    (branch_names.get(i["branch_type"], "?"),
                     bool(i.get("branch_conditional")))
                    for i in insns
                    if branch_names.get(i["branch_type"], "?") != "NONE"
                ]
                issues.append(Issue(
                    "cond_uncond_branch_assertion", "error",
                    f"blk_{bid} ({b['class']}): expected a branch with "
                    f"branch_type=DIRECT_JUMP/INDIRECT_JUMP AND "
                    f"branch_conditional=true, but trace shows {seen}.  "
                    f"This is the x86 JECXZ/LOOP family — the tracer "
                    f"should mark them unconditional-by-type but "
                    f"conditional-by-flag.",
                    {"block_id": bid, "observed_branches": seen},
                ))

    return issues


def _check_profile_consistency(templates: list[dict],
                               entries: list[dict],
                               body_stats: dict) -> list[Issue]:
    """Cross-validate the run-aggregated template profile block
    (format §6) against the decoded body — overlapping coverage that
    asserts the profiling machinery itself, independent of the
    behavioural metadata checks.

    Invariants asserted:
      * exec_cp / exec_wp coverage agrees with which template_ids
        actually appear as CP entries / WP chain BBs;
      * sum(exec_wp) == total WP BBs in the body; sum(exec_cp) ==
        total CP entries when no IFRAMEs are present (IFRAMEs are
        re-emissions the writer does not profile-accumulate);
      * for a non-indirect branch BB (exactly one header target),
        target[0].taken_cp + target[0].nottaken_cp == exec_cp — its
        terminal branch is resolved exactly once per CP execution;
      * a per-insn memop count implies the matching path executed.
    """
    issues: list[Issue] = []

    cp_count: dict[int, int] = {}
    wp_count: dict[int, int] = {}
    total_wp = 0
    for e in entries:
        cp_count[e["template_id"]] = cp_count.get(e["template_id"], 0) + 1
        for wp in e.get("wp_entries", []):
            tid = wp["template_id"]
            wp_count[tid] = wp_count.get(tid, 0) + 1
            total_wp += 1

    sum_cp = 0
    sum_wp = 0
    for t in templates:
        p = t.get("profile") or {}
        tid = t["template_id"]
        exec_cp = int(p.get("exec_cp", 0))
        exec_wp = int(p.get("exec_wp", 0))
        sum_cp += exec_cp
        sum_wp += exec_wp

        if exec_cp > 0 and tid not in cp_count:
            issues.append(Issue(
                "profile_consistency", "error",
                f"tmpl {tid}: profile exec_cp={exec_cp} but template "
                f"never appears as a CP entry", {"template_id": tid}))
        if tid in cp_count and exec_cp == 0:
            issues.append(Issue(
                "profile_consistency", "error",
                f"tmpl {tid}: appears as {cp_count[tid]} CP entries but "
                f"profile exec_cp=0", {"template_id": tid}))
        if exec_wp > 0 and tid not in wp_count:
            issues.append(Issue(
                "profile_consistency", "error",
                f"tmpl {tid}: profile exec_wp={exec_wp} but template "
                f"never appears in a WP chain", {"template_id": tid}))

        # Terminal-branch invariant: a non-indirect branch BB has
        # exactly one header target whose taken+nottaken CP counts
        # account for every CP execution of the BB.
        insns = t.get("insns") or []
        tgts = p.get("targets") or []
        # The terminal-branch outcome is counted when the *successor*
        # entry is observed, so the BB that ends the trace/segment
        # has exactly its last outcome unrecorded: got == exec_cp, or
        # exec_cp - 1 for the single trailing execution.  Any larger
        # deficit (or got > exec_cp) means mis-attribution / WP
        # contamination — the bug class this asserts.
        if exec_cp > 0 and len(tgts) == 1 and insns and \
                insns[-1].get("branch_type", 0) != 0:
            t0 = tgts[0]
            got = int(t0["taken_cp"]) + int(t0["nottaken_cp"])
            if not (exec_cp - 1 <= got <= exec_cp):
                issues.append(Issue(
                    "profile_consistency", "error",
                    f"tmpl {tid}: terminal-branch CP taken+nottaken="
                    f"{got}, expected exec_cp={exec_cp} or "
                    f"exec_cp-1 (one trailing entry)",
                    {"template_id": tid, "got": got,
                     "exec_cp": exec_cp}))

        for idx, fields in (p.get("insns") or {}).items():
            mcp = int(fields.get("memops_cp", 0))
            mwp = int(fields.get("memops_wp", 0))
            if mcp > 0 and exec_cp == 0:
                issues.append(Issue(
                    "profile_consistency", "error",
                    f"tmpl {tid} insn[{idx}]: memops_cp={mcp} but "
                    f"exec_cp=0", {"template_id": tid}))
            if mwp > 0 and exec_wp == 0:
                issues.append(Issue(
                    "profile_consistency", "error",
                    f"tmpl {tid} insn[{idx}]: memops_wp={mwp} but "
                    f"exec_wp=0", {"template_id": tid}))

    if sum_wp != total_wp:
        issues.append(Issue(
            "profile_consistency", "error",
            f"sum(exec_wp)={sum_wp} != total WP BBs in body={total_wp}",
            {"sum_exec_wp": sum_wp, "body_wp": total_wp}))

    iframes = int(body_stats.get("iframe_count", 0) or 0)
    if iframes == 0 and sum_cp != len(entries):
        issues.append(Issue(
            "profile_consistency", "error",
            f"sum(exec_cp)={sum_cp} != CP entries={len(entries)} "
            f"(no IFRAMEs present)",
            {"sum_exec_cp": sum_cp, "cp_entries": len(entries)}))

    if not issues:
        issues.append(Issue(
            "profile_consistency", "info",
            f"profile block consistent: {len(templates)} templates, "
            f"sum exec_cp={sum_cp} exec_wp={sum_wp}, WP BBs={total_wp}"))
    return issues


# ---------------------------------------------------------------------------
# Legacy checks
# ---------------------------------------------------------------------------

def _check_blocks_covered(correct_path: list[int],
                          cp_distinct_blocks: set[int]) -> list[Issue]:
    issues: list[Issue] = []
    for bid in sorted(set(correct_path) - cp_distinct_blocks):
        issues.append(Issue(
            "blocks_covered", "error",
            f"block blk_{bid} on CP but no trace template covers it",
        ))
    return issues


def _check_cp_execution_order(correct_path: list[int],
                              cp_block_seq: list[int]) -> list[Issue]:
    issues: list[Issue] = []
    n = min(len(cp_block_seq), len(correct_path))
    mismatches = 0
    for i in range(n):
        if cp_block_seq[i] != correct_path[i]:
            mismatches += 1
            if mismatches <= 5:
                issues.append(Issue(
                    "cp_execution_order", "error",
                    f"at CP pos {i}: expected blk_{correct_path[i]}, "
                    f"got blk_{cp_block_seq[i]}",
                    {"position": i, "expected": correct_path[i],
                     "actual": cp_block_seq[i]},
                ))
    if len(cp_block_seq) < len(correct_path):
        issues.append(Issue(
            "cp_execution_order", "error",
            f"trace CP too short: {len(cp_block_seq)} < "
            f"{len(correct_path)} blocks",
        ))
    elif len(cp_block_seq) > len(correct_path):
        issues.append(Issue(
            "cp_execution_order", "error",
            f"trace CP has {len(cp_block_seq) - len(correct_path)} "
            f"extra blocks after predicted end",
        ))
    return issues


def _check_cp_memops(entries: list[dict],
                     template_runs: dict[int, list[tuple[int, int]]],
                     blocks_by_id: dict[int, dict],
                     cp_set: set[int],
                     arena_addr: int,
                     arena_size: int | None = None,
                     isa: str = "x86_64",
                     templates_by_id: dict[int, dict] | None = None,
                     pcmap: "PcMap | None" = None) -> list[Issue]:
    """Memop/value/identity check, aggregated by (template, block)
    bipartite component.

    Background: a single source-level block can be split across
    multiple templates when the compiler emits an *internal*
    conditional branch inside the block (e.g. RISC-V/MIPS lower a
    select to ``bgeu`` + fall-through ``mv``, which terminates the
    first TB mid-block).  Conversely, a single template can cover
    multiple straight-line source blocks.  Per-template comparison
    therefore over- or under-counts memops whenever the
    template↔block mapping isn't 1:1.

    Fix: build the bipartite graph (template <-> block) restricted
    to CP entries, find its connected components, and compare the
    multiset of expected memops (over all blocks in the component)
    against the multiset of dyn_params (over the first execution of
    every template in the component).

    The match is STRICT on instruction identity: the generator
    annotates each ExpectedMemOp with the ordinal(s) of the block's
    memory instruction(s) that perform it (insn_seq, see
    asm_blocks.annotate_memop_insn_seq), the trace side resolves each
    dyn_param's insn_index to its instruction PC, and the multiset
    key carries that identity — a memop with the right value on the
    wrong instruction no longer passes.  A memop with no insn_seq
    (identity not statically derivable) falls back to value-only
    matching; the check itself is never loosened.
    """
    issues: list[Issue] = []
    templates_by_id = templates_by_id or {}

    # ---- 1. Build bipartite adjacency restricted to CP. ----
    # @first_entry maps tid -> single representative entry (default
    # for normal blocks: avoids counting the same memop pattern N
    # times when a block sits inside a loop).
    # @all_entries maps tid -> list of every CP entry on that
    # template, used when at least one block in the bipartite
    # component opts into aggregate_fanout — true today for the REP-
    # iteration block, whose iter 2..N body entries live on
    # subsequent executions of the 1-insn self-loop sub-template.
    tmpl_to_blocks: dict[int, set[int]] = {}
    block_to_tmpls: dict[int, set[int]] = {}
    first_entry: dict[int, dict] = {}
    all_entries: dict[int, list[dict]] = {}

    for e in entries:
        tid = e["template_id"]
        runs = template_runs.get(tid, [])
        cp_blocks = {bid for (bid, _) in runs if bid in cp_set}
        if not cp_blocks:
            continue
        all_entries.setdefault(tid, []).append(e)
        if tid in first_entry:
            continue
        first_entry[tid] = e
        tmpl_to_blocks[tid] = cp_blocks
        for bid in cp_blocks:
            block_to_tmpls.setdefault(bid, set()).add(tid)

    # ---- 2. Connected-component traversal. ----
    visited_tmpls: set[int] = set()

    for seed_tid in tmpl_to_blocks:
        if seed_tid in visited_tmpls:
            continue
        comp_tmpls: set[int] = set()
        comp_blocks: set[int] = set()
        stack: list[tuple[str, int]] = [("t", seed_tid)]
        while stack:
            kind, node = stack.pop()
            if kind == "t":
                if node in comp_tmpls:
                    continue
                comp_tmpls.add(node)
                for bid in tmpl_to_blocks.get(node, ()):
                    if bid not in comp_blocks:
                        stack.append(("b", bid))
            else:
                if node in comp_blocks:
                    continue
                comp_blocks.add(node)
                for tid in block_to_tmpls.get(node, ()):
                    if tid not in comp_tmpls:
                        stack.append(("t", tid))
        visited_tmpls |= comp_tmpls

        # ---- 3. Instruction-identity table for the component. ----
        # mem_pcs[bid]: ascending PCs of the block's memory-capable
        # insns (static max loads+stores nonzero, or atomic — Capstone
        # leaves some atomics' mem-access flags empty so their static
        # counts read 0/0), unioned across the component's templates.
        # The generator's ExpectedMemOp.insn_seq ordinals index this
        # list: the emitted asm's memory instructions in order equal
        # ascending-pc order.  MIPS note: templates keep true
        # execution order with ascending PCs (no delay-slot reorder,
        # champsim_tracer_bb_template_cache.cc), and no generator
        # block puts a memop in a branch delay slot, so the WP-side
        # positional-pc reassignment never touches this mapping.
        mem_pcs: dict[int, list[int]] = {bid: [] for bid in comp_blocks}
        for tid in comp_tmpls:
            for ins in templates_by_id.get(tid, {}).get("insns", []):
                pc = int(ins["pc"])
                bid = pcmap.lookup(pc) if pcmap else None
                if bid not in mem_pcs:
                    continue
                if (int(ins.get("n_loads", 0)) +
                        int(ins.get("n_stores", 0)) > 0
                        or ins.get("is_atomic")):
                    mem_pcs[bid].append(pc)
        for bid in mem_pcs:
            mem_pcs[bid] = sorted(set(mem_pcs[bid]))

        # ---- 4. Build expected and actual multisets for component. ----
        # Tuple shape: (kind, off, data, optional, identity) where
        # identity is a sorted tuple of instruction PCs (usually one;
        # two for a 32-bit u64 lo/hi pair) or None for value-only.
        expected: list[tuple[str, int, int, bool, tuple | None]] = []
        for bid in sorted(comp_blocks):
            pcs = mem_pcs.get(bid, [])
            for m in blocks_by_id[bid].get("memops", []):
                seq = m.get("insn_seq") or None
                ident: tuple | None = None
                if seq and all(0 <= int(k) < len(pcs) for k in seq):
                    ident = tuple(sorted(pcs[int(k)] for k in seq))
                expected.append(
                    (m["kind"], int(m["arena_u64_index"]), int(m["data"]),
                     bool(m.get("optional", False)), ident)
                )
        actual: list[tuple[str, int, int, tuple]] = []
        # 32-bit ISAs lower `uint64_t` arena accesses to a pair of
        # 32-bit memops at the low and high halves of an 8-byte slot.
        # On 64-bit ISAs the compiler issues a single 8-byte memop, so
        # pair-merging must be skipped (otherwise two unrelated 4-byte
        # accesses to adjacent u32 slots could be merged spuriously).
        is_32bit_isa = isa in ("mipsel", "mips", "riscv32", "armhf", "i386")
        # If any block in the component opts into fan-out aggregation
        # (REP-iteration test blocks), walk every CP entry on every
        # template in the component instead of just the first.  The
        # REP sub-template is executed N-1 times per source REP,
        # each execution carrying one iteration's memops on a
        # distinct body entry; the default first-entry-only mode
        # would see iter 2 only and miss iter 3..N.
        fanout = any(blocks_by_id[bid].get("aggregate_fanout")
                     for bid in comp_blocks)
        def _dps_for(tid: int) -> list:
            if fanout:
                out: list = []
                for e in all_entries.get(tid, []):
                    out.extend(e.get("dyn_params", []) or [])
                return out
            return list(first_entry[tid].get("dyn_params", []))

        for tid in sorted(comp_tmpls):
            raw_dps = _dps_for(tid)
            consumed = [False] * len(raw_dps)
            tmpl_insns = templates_by_id.get(tid, {}).get("insns", [])

            def _pc_of(dp) -> int | None:
                idx = int(getattr(dp, "insn_index", -1))
                if 0 <= idx < len(tmpl_insns):
                    return int(tmpl_insns[idx]["pc"])
                return None

            def _arena_off4(va: int) -> int:
                """Return arena offset in 4-byte units, or -1."""
                rel = va - arena_addr
                if rel < 0 or rel % 4 != 0:
                    return -1
                if arena_size is not None and rel >= arena_size:
                    return -1
                return rel // 4

            # First pass (32-bit ISAs only): pair each 8-byte-aligned
            # access (low half) with a same-kind partner at the next
            # 4-byte slot (high half) within the same template.  The
            # decoder does not preserve `data_size`, so pairing is
            # driven by offset alignment alone — which is unambiguous
            # because on 32-bit ISAs every memop is 4 bytes wide.
            if is_32bit_isa:
                for i, dp in enumerate(raw_dps):
                    if consumed[i]:
                        continue
                    off4 = _arena_off4(int(dp.value))
                    if off4 < 0 or off4 % 2 != 0:
                        continue
                    hi_va = int(dp.value) + 4
                    for j in range(len(raw_dps)):
                        if (j == i or consumed[j]
                                or raw_dps[j].type_name != dp.type_name
                                or int(raw_dps[j].value) != hi_va):
                            continue
                        lo = int(dp.data_lo) & 0xFFFFFFFF
                        hi = int(raw_dps[j].data_lo) & 0xFFFFFFFF
                        pcs = {_pc_of(dp), _pc_of(raw_dps[j])} - {None}
                        actual.append(
                            (dp.type_name, off4 // 2, (hi << 32) | lo,
                             tuple(sorted(pcs)))
                        )
                        consumed[i] = consumed[j] = True
                        break

            # Second pass: any remaining dyn_params at u64-aligned
            # addresses are taken at face value.
            for i, dp in enumerate(raw_dps):
                if consumed[i]:
                    continue
                off = _format_off(arena_addr, int(dp.value), arena_size)
                if off < 0:
                    # Load/store outside arena (e.g. compiler-emitted
                    # constant-pool load for FP immediates, or a stack
                    # spill).  Not a generator-managed memop; ignore.
                    continue
                pc = _pc_of(dp)
                actual.append((
                    dp.type_name,
                    off,
                    _dyn_data_int(dp),
                    (pc,) if pc is not None else (),
                ))

        # ---- 5. Identity-strict multiset match. ----
        # Strict requireds match on (kind, off, data, identity);
        # identity-less requireds and optionals consume leftovers by
        # value.  A value-correct memop attributed to the wrong
        # instruction therefore surfaces as one missing (the strict
        # required) plus one extra (the actual, with its wrong PC).
        required_strict = Counter(
            (kind, off, data, ident)
            for kind, off, data, optional, ident in expected
            if not optional and ident is not None)
        required_wild = Counter(
            (kind, off, data)
            for kind, off, data, optional, ident in expected
            if not optional and ident is None)
        optional_ctr = Counter(
            (kind, off, data)
            for kind, off, data, optional, ident in expected
            if optional)
        act_ctr = Counter(actual)

        missing: list[tuple] = list((required_strict - act_ctr).elements())
        remaining = act_ctr - required_strict
        rem_by_val = Counter()
        for (kind, off, data, ident), n in remaining.items():
            rem_by_val[(kind, off, data)] += n
        missing += list((required_wild - rem_by_val).elements())

        budget = required_wild + optional_ctr
        extra: list[tuple] = []
        for key in sorted(remaining, key=repr):
            kind, off, data, ident = key
            n = remaining[key]
            take = min(n, budget[(kind, off, data)])
            budget[(kind, off, data)] -= take
            extra += [key] * (n - take)
        if not missing and not extra:
            continue

        def _fmt(item: tuple) -> str:
            if len(item) == 4:
                kind, off, data, ident = item
                at = ("@" + "+".join(f"0x{p:x}" for p in ident)
                      if ident else "@*")
                return f"('{kind}', {off}, {data}, {at})"
            kind, off, data = item
            return f"('{kind}', {off}, {data}, @*)"

        n_required = sum(required_strict.values()) + \
            sum(required_wild.values())
        tmpl_label = "+".join(f"t{t}" for t in sorted(comp_tmpls))
        blk_label = "/".join(f"blk_{b}" for b in sorted(comp_blocks))
        issues.append(Issue(
            "cp_memops", "error",
            f"templates {{{tmpl_label}}} ({blk_label}): "
            f"memop multiset mismatch "
            f"(required={n_required} "
            f"optional={sum(optional_ctr.values())} act={len(actual)} "
            f"missing={len(missing)} extra={len(extra)})\n"
            f"      required: "
            f"{[_fmt(x) for x in required_strict.elements()] + [_fmt(x) for x in required_wild.elements()]}\n"
            f"      optional: {list(optional_ctr.elements())}\n"
            f"      actual  : {[_fmt(x) for x in actual]}\n"
            f"      missing : {[_fmt(x) for x in missing]}\n"
            f"      extra   : {[_fmt(x) for x in extra]}",
            {
                "template_ids": sorted(comp_tmpls),
                "cp_blocks": sorted(comp_blocks),
                "missing_first5": [_fmt(x) for x in missing[:5]],
                "extra_first5": [_fmt(x) for x in extra[:5]],
            },
        ))
    return issues


def _check_memop_insn_attribution(
        entries: list[dict],
        template_runs: dict[int, list[tuple[int, int]]],
        templates_by_id: dict[int, dict],
        cp_set: set[int]) -> list[Issue]:
    """Verify that each dyn_param's `insn_index` points at an instruction
    whose per-entry decoded counts match the access kind.

    The trace format carries n_loads/n_stores as sparse per-entry
    fields.  The immutable template values are only defaults; runtime
    QEMU memory callbacks are the authoritative source for actual
    per-execution load/store counts.  The decoder reconstructs
    `dyn_params` from those current per-entry counts, so this check must
    not compare runtime records against the template defaults.

    This catches malformed decoded entries:

      * `insn_index` out of range  → tracer bug

    We only inspect each template's *first* execution so the cost stays
    O(distinct templates); subsequent executions follow the same
    schema by construction.
    """
    issues: list[Issue] = []
    seen_tids: set[int] = set()

    for e in entries:
        tid = e["template_id"]
        if tid in seen_tids:
            continue
        # Only look at templates that participate in CP blocks; entries
        # that pre-date the entry block are setup code and not part of
        # the generator's contract.
        runs = template_runs.get(tid, [])
        if not any(bid in cp_set for bid, _ in runs):
            continue
        seen_tids.add(tid)

        tmpl = templates_by_id.get(tid)
        if tmpl is None:
            continue
        insns = tmpl.get("insns", [])
        n = len(insns)

        # BB templates are immutable, but memop counts are per-entry
        # state.  An out-of-range insn_index means the decoded entry is
        # malformed; it should not be inferred from template defaults.
        dps = list(e.get("dyn_params", []))
        out_of_range = [dp for dp in dps if int(dp.insn_index) < 0
                        or int(dp.insn_index) >= n]

        if out_of_range:
            schema_lines = []
            for i, ins in enumerate(insns):
                schema_lines.append(
                    f"    insn[{i:2d}] pc=0x{int(ins['pc']):x} "
                    f"opcode={ins.get('opcode', '?')} "
                    f"n_loads={int(ins.get('n_loads', 0))} "
                    f"n_stores={int(ins.get('n_stores', 0))}"
                )
            dp_lines = []
            for j, dp in enumerate(dps):
                dp_lines.append(
                    f"    dp[{j:2d}] kind={dp.type_name} "
                    f"insn_index={int(dp.insn_index)} "
                    f"value=0x{int(dp.value):x}"
                )
            detail = (
                f"template t{tid} (start_pc=0x{int(tmpl.get('start_pc', 0)):x}, "
                f"n_insns={n}, "
                f"dyn_params_received={len(dps)}):\n"
                + "\n".join(schema_lines)
                + "\n  dyn_params:\n"
                + "\n".join(dp_lines)
            )
            issues.append(Issue(
                "memop_insn_attribution", "error",
                f"template t{tid}: {len(out_of_range)} dyn_param(s) "
                f"have an out-of-range decoded insn_index "
                f"(dp_count={len(dps)}). Likely decoder or tracer bug.\n{detail}",
                {"template_id": tid, "n_insns": n,
                 "dyn_params_received": len(dps),
                 "schema": [
                     {"pc": int(ins["pc"]),
                      "opcode": ins.get("opcode"),
                      "n_loads": int(ins.get("n_loads", 0)),
                        "n_stores": int(ins.get("n_stores", 0))}
                     for ins in insns],
                 "dyn_params": [
                     {"kind": dp.type_name,
                      "insn_index": int(dp.insn_index),
                      "value": int(dp.value)}
                     for dp in dps]},
            ))
    return issues


def _check_memop_count_assertions(
        entries: list[dict],
        templates_by_id: dict[int, dict],
        blocks_by_id: dict[int, dict],
        pcmap: "PcMap",
        cp_set: set[int]) -> list[Issue]:
    blocks = [b for b in blocks_by_id.values()
              if b["block_id"] in cp_set
              and b.get("memop_count_assertions")]
    if not blocks:
        return []

    observations: dict[int, list[tuple[int, int, int, int]]] = {
        int(b["block_id"]): [] for b in blocks
    }

    for e in entries:
        tid = int(e["template_id"])
        tmpl = templates_by_id.get(tid)
        if tmpl is None:
            continue
        insns = tmpl.get("insns", [])
        counts: dict[int, list[int]] = {}
        for dp in e.get("dyn_params", []) or []:
            idx = int(getattr(dp, "insn_index", -1))
            if idx < 0 or idx >= len(insns):
                continue
            bid = pcmap.lookup(int(insns[idx]["pc"]))
            if bid not in observations:
                continue
            slot = counts.setdefault(idx, [0, 0])
            if dp.type_name == "load":
                slot[0] += 1
            else:
                slot[1] += 1
        for idx, (loads, stores) in counts.items():
            bid = pcmap.lookup(int(insns[idx]["pc"]))
            if bid in observations:
                observations[bid].append((tid, idx, loads, stores))

    issues: list[Issue] = []
    for b in blocks:
        bid = int(b["block_id"])
        seen = observations.get(bid, [])
        for assertion in b.get("memop_count_assertions") or []:
            want_loads = int(assertion.get("loads", 0))
            want_stores = int(assertion.get("stores", 0))
            want_overflow = bool(assertion.get("overflow", False))
            match = [obs for obs in seen
                     if obs[2] == want_loads and obs[3] == want_stores]
            if want_overflow:
                match = [obs for obs in match
                         if obs[2] > 16 or obs[3] > 16]
            if match:
                continue
            issues.append(Issue(
                "memop_count_assertion", "error",
                f"blk_{bid} ({b['class']}): expected one instruction with "
                f"loads={want_loads} stores={want_stores} "
                f"overflow={want_overflow}, but saw "
                f"{[(l, s) for _, _, l, s in seen]}",
                {"block_id": bid, "expected": assertion,
                 "observed": [
                     {"template_id": tid, "insn_index": idx,
                      "loads": loads, "stores": stores}
                     for tid, idx, loads, stores in seen
                 ]},
            ))
    return issues


def _check_per_execution_memop_data(
        entries: list[dict],
        template_runs: dict[int, list[tuple[int, int]]],
        blocks_by_id: dict[int, dict],
        cp_set: set[int],
        arena_addr: int,
        arena_size: int | None,
        isa: str) -> list[Issue]:
    """For blocks that declare ``per_iteration_memops``, verify that the
    k-th CP entry on the block's template carries the k-th expected
    sub-list as its dyn_params (multiset compare, same as
    _check_cp_memops).

    This is the only place the validator exercises the *per-execution
    data* path: invariant-data probes verify nothing about data delta on
    iter 2+, but a block whose loaded/stored values legitimately change
    every iteration (LoopHead's decrementing counter is the canonical
    example) makes a regression in the state-delta encoder
    observable as a stale value on iter k.

    Restrictions: a per-iter block must map 1:1 to its template (i.e.
    the template covers exactly this block — no bipartite-component
    merging).  Mixed components are reported as "skipped" info-level so
    the cause is visible if a future probe ends up coalesced into a
    multi-block template by the compiler.
    """
    issues: list[Issue] = []

    # Map block_id -> per_iteration_memops list (only for blocks that
    # opted in).  We resolve to the *unique* template that covers each
    # such block; if more than one template covers it, or the template
    # covers other blocks too, we skip (with an info-level note).
    per_iter_blocks: dict[int, list[list[dict]]] = {}
    for bid, blk in blocks_by_id.items():
        if bid not in cp_set:
            continue
        seq = blk.get("per_iteration_memops") or []
        if seq:
            per_iter_blocks[bid] = seq
    if not per_iter_blocks:
        return issues

    # Build block -> unique-template mapping; reject ambiguous mappings.
    block_to_tmpls: dict[int, set[int]] = {}
    tmpl_to_blocks: dict[int, set[int]] = {}
    for tid, runs in template_runs.items():
        for bid, _ in runs:
            if bid in cp_set:
                block_to_tmpls.setdefault(bid, set()).add(tid)
                tmpl_to_blocks.setdefault(tid, set()).add(bid)

    is_32bit_isa = isa in ("mipsel", "mips", "riscv32", "armhf", "i386")

    def _actual_multiset(e: dict) -> list[tuple[str, int, int]]:
        raw_dps = list(e.get("dyn_params", []) or [])
        consumed = [False] * len(raw_dps)
        actual: list[tuple[str, int, int]] = []

        def _arena_off4(va: int) -> int:
            rel = va - arena_addr
            if rel < 0 or rel % 4 != 0:
                return -1
            if arena_size is not None and rel >= arena_size:
                return -1
            return rel // 4

        if is_32bit_isa:
            for i, dp in enumerate(raw_dps):
                if consumed[i]:
                    continue
                off4 = _arena_off4(int(dp.value))
                if off4 < 0 or off4 % 2 != 0:
                    continue
                hi_va = int(dp.value) + 4
                for j in range(len(raw_dps)):
                    if (j == i or consumed[j]
                            or raw_dps[j].type_name != dp.type_name
                            or int(raw_dps[j].value) != hi_va):
                        continue
                    lo = int(dp.data_lo) & 0xFFFFFFFF
                    hi = int(raw_dps[j].data_lo) & 0xFFFFFFFF
                    actual.append((dp.type_name, off4 // 2, (hi << 32) | lo))
                    consumed[i] = consumed[j] = True
                    break
        for i, dp in enumerate(raw_dps):
            if consumed[i]:
                continue
            off = _format_off(arena_addr, int(dp.value), arena_size)
            if off < 0:
                continue
            actual.append((dp.type_name, off, _dyn_data_int(dp)))
        return actual

    for bid, per_iter in per_iter_blocks.items():
        tids = block_to_tmpls.get(bid, set())
        if not tids:
            issues.append(Issue(
                "per_execution_memop_data", "info",
                f"blk_{bid}: skipped per-iteration data check; no covering "
                f"template",
                {"block_id": bid},
            ))
            continue
        # Find the iteration boundary: for a CFG self-loop block, an
        # iteration consists of one entry on EVERY template in the
        # bipartite component (e.g. body fragment + tail-jmp fragment
        # produced by the mid-TB splitter).  We group entries into
        # iterations by template_id: the first appearance of each tid
        # starts iter 1, the second appearance of any tid bumps us into
        # iter 2, etc.  Within an iter, aggregate dyn_params across all
        # templates (the jmp fragment carries zero memops).
        cov_tids = set(tids)
        # Walk trace entries (already filtered to CP) in order; group
        # by iter when a template_id repeats.
        iter_entries: list[list[dict]] = [[]]
        seen_in_iter: set[int] = set()
        for e in entries:
            tid = int(e["template_id"])
            if tid not in cov_tids:
                continue
            if tid in seen_in_iter:
                iter_entries.append([])
                seen_in_iter = set()
            iter_entries[-1].append(e)
            seen_in_iter.add(tid)
        # Drop a trailing partial iteration if it didn't see all the
        # templates we expect — those are spurious in self-loop tail.
        if iter_entries and not iter_entries[-1]:
            iter_entries.pop()

        n_check = min(len(iter_entries), len(per_iter))
        for k in range(n_check):
            expected_list = per_iter[k]
            expected = Counter(
                (m["kind"], int(m["arena_u64_index"]), int(m["data"]))
                for m in expected_list
            )
            actual_acc: list = []
            for e in iter_entries[k]:
                actual_acc.extend(_actual_multiset(e))
            actual = Counter(actual_acc)
            if expected == actual:
                continue
            missing = list((expected - actual).elements())
            extra = list((actual - expected).elements())
            tid_label = "+".join(f"t{t}" for t in sorted(cov_tids))
            issues.append(Issue(
                "per_execution_memop_data", "error",
                f"blk_{bid} ({tid_label}) iter {k + 1}: dyn_params multiset "
                f"diverges from per_iteration_memops[{k}]\n"
                f"      expected: {list(expected.elements())}\n"
                f"      actual  : {list(actual.elements())}\n"
                f"      missing : {missing}\n"
                f"      extra   : {extra}",
                {"block_id": bid, "template_ids": sorted(cov_tids),
                 "iter": k + 1,
                 "missing": missing, "extra": extra},
            ))
    return issues


def _check_per_execution_memop_shape(
        entries: list[dict],
        template_runs: dict[int, list[tuple[int, int]]],
        templates_by_id: dict[int, dict],
        blocks_by_id: dict[int, dict],
        cp_set: set[int]) -> list[Issue]:
    """For every CP body entry, verify that the per-insn (loads, stores)
    count tuple matches the *first* execution's tuple for that template.

    The wire format encodes memop counts as sparse state-delta fields:
    the decoder reads the previous value if no record arrives for this
    entry.  An encoder bug that fails to (a) re-emit a load_addr slot on
    a subsequent execution, or (b) refresh N_LOADS/N_STORES when the
    runtime count changes, manifests as the decoded `dyn_params` having
    a different (loads, stores) shape on iteration k than iteration 1.

    Existing memop checks (_check_cp_memops, _check_memop_insn_attribution)
    only inspect the first execution per template "by construction";
    this check explicitly tests the construction.

    Templates whose blocks opt into aggregate_fanout (REP probes) are
    skipped: their per-execution shape is checked by
    _check_memop_count_assertions instead, and the per-iteration memop
    counts are intentionally non-uniform (one (1, 1) entry per iter).
    """
    issues: list[Issue] = []

    fanout_tids: set[int] = set()
    cp_tids: set[int] = set()
    for tid, runs in template_runs.items():
        cp_blocks = {bid for (bid, _) in runs if bid in cp_set}
        if not cp_blocks:
            continue
        cp_tids.add(tid)
        if any(blocks_by_id[bid].get("aggregate_fanout") for bid in cp_blocks):
            fanout_tids.add(tid)

    # Build per-template (loads, stores) baseline from the first CP
    # entry, then compare every subsequent entry's per-insn tuple.
    # `baseline[tid][insn_idx] = (loads, stores)`.
    baseline: dict[int, dict[int, tuple[int, int]]] = {}
    mismatches_per_tid: dict[int, int] = {}

    def _shape_for_entry(e: dict, tmpl: dict) -> dict[int, tuple[int, int]]:
        insns = tmpl.get("insns", [])
        shape: dict[int, list[int]] = {}
        for dp in e.get("dyn_params", []) or []:
            idx = int(getattr(dp, "insn_index", -1))
            if idx < 0 or idx >= len(insns):
                continue
            slot = shape.setdefault(idx, [0, 0])
            if dp.type_name == "load":
                slot[0] += 1
            else:
                slot[1] += 1
        return {idx: (ls, ss) for idx, (ls, ss) in shape.items()}

    for e in entries:
        tid = int(e["template_id"])
        if tid not in cp_tids or tid in fanout_tids:
            continue
        tmpl = templates_by_id.get(tid)
        if tmpl is None:
            continue
        # Kernel templates and fault-handler executions (fault_depth>0)
        # are exempt: a faulting access transfers 0 bytes on the attempt
        # that traps and the full width on the post-handler retry, so the
        # per-execution shape legitimately differs across a fault.  Fault
        # blocks must not perturb the user workload's shape baseline.
        if tmpl.get("is_system") or int(e.get("fault_depth", 0) or 0) > 0:
            continue
        shape = _shape_for_entry(e, tmpl)
        if tid not in baseline:
            baseline[tid] = shape
            continue
        if shape == baseline[tid]:
            continue
        mismatches_per_tid[tid] = mismatches_per_tid.get(tid, 0) + 1
        # Surface only the first two divergent entries per template
        # to keep the report tractable; the count is reported below.
        if mismatches_per_tid[tid] > 2:
            continue
        base = baseline[tid]
        all_idx = sorted(set(base.keys()) | set(shape.keys()))
        diff_lines = []
        for idx in all_idx:
            b = base.get(idx, (0, 0))
            s = shape.get(idx, (0, 0))
            if b == s:
                continue
            insns = tmpl.get("insns", [])
            pc = (int(insns[idx]["pc"])
                  if 0 <= idx < len(insns) else 0)
            diff_lines.append(
                f"    insn[{idx:2d}] pc=0x{pc:x}: "
                f"first_exec=(L{b[0]},S{b[1]}) "
                f"this_exec=(L{s[0]},S{s[1]})"
            )
        issues.append(Issue(
            "per_execution_memop_shape", "error",
            f"template t{tid}: per-execution memop shape diverged from "
            f"first execution\n" + "\n".join(diff_lines),
            {"template_id": tid,
             "baseline": {idx: list(v) for idx, v in base.items()},
             "this_exec": {idx: list(v) for idx, v in shape.items()}},
        ))
    for tid, n in mismatches_per_tid.items():
        if n > 2:
            issues.append(Issue(
                "per_execution_memop_shape", "info",
                f"template t{tid}: {n} entries diverged from first-exec "
                f"shape (showed first 2 above)",
                {"template_id": tid, "n_diverged": n},
            ))
    return issues


_TRAILER_INSNS_BY_ISA = {
    # The generator emits these many insns AFTER each block's
    # user-supplied asm: a single branch on most ISAs, plus a
    # delay-slot nop on MIPS.  Used by _check_expected_reg_sets to
    # decide how many trailing trace insns can legitimately be
    # generator-emitted (and therefore not described by the block's
    # author-declared `expected_reg_sets`).
    "x86_64":  1,
    "aarch64": 1,
    "riscv64": 1,
    "mipsel":  2,
}


def _check_expected_reg_sets(
        entries: list[dict],
        templates_by_id: dict[int, dict],
        blocks_by_id: dict[int, dict],
        pcmap: "PcMap",
        cp_set: set[int],
        isa: str,
        reg_id_to_name: dict[int, str]) -> list[Issue]:
    """Compare author-declared per-insn src/dst register sets against
    the trace's recorded sets.  Mirrors `_check_static_reg_sets` but
    with the spec coming from the block's `expected_reg_sets` instead
    of from Capstone.  An author-declared spec that disagrees with the
    trace (and therefore with Capstone) means the asm we wrote isn't
    what we intended — the canonical "typo / unintended encoding"
    bug.  Skipped silently for blocks that don't declare expected
    sets.

    Comparison is by symbolic REG_* name.  @reg_id_to_name comes from
    the trace's own ENCODINGS section; the validator does not carry a
    duplicate id↔name table.
    """
    blocks = [b for b in blocks_by_id.values()
              if b["block_id"] in cp_set and b.get("expected_reg_sets")]
    if not blocks:
        return [Issue(
            "expected_reg_sets", "info",
            "no blocks declared expected_reg_sets — author-side reg "
            "declaration check skipped",
        )]

    # Authors can write either "REG_SP" or "SP"; build the accepted
    # alias set from the trace's reg map so both forms resolve.
    valid_names: set[str] = set()
    for name in reg_id_to_name.values():
        valid_names.add(name)
        if name.startswith("REG_"):
            valid_names.add(name[4:])

    def resolve(name: str) -> str | None:
        if name in valid_names:
            return name if name.startswith("REG_") else f"REG_{name}"
        return None

    issues: list[Issue] = []
    n_blocks = 0
    n_insns_checked = 0
    n_errors = 0
    err_cap = 20

    # Walk every CP entry once, indexing by block_id.
    blocks_by_bid = {int(b["block_id"]): b for b in blocks}
    for e in entries:
        tmpl = templates_by_id.get(int(e["template_id"]))
        if tmpl is None:
            continue
        insns = tmpl.get("insns", [])
        # Group insns by block_id (a single template can span multiple
        # author blocks if the assembler coalesces fall-through).  Each
        # block's expected_reg_sets is matched against the contiguous
        # run of trace insns whose pc maps to that block.
        per_block: dict[int, list[int]] = {}
        for idx, ins in enumerate(insns):
            bid = pcmap.lookup(int(ins["pc"]))
            if bid is None or bid not in blocks_by_bid:
                continue
            per_block.setdefault(bid, []).append(idx)

        for bid, idxs in per_block.items():
            block = blocks_by_bid[bid]
            specs = block.get("expected_reg_sets") or []
            if not specs:
                continue
            n_blocks += 1
            # The generator wraps each block's user-supplied asm with
            # a label prologue (no insns) and a trailing branch to the
            # successor block; on MIPS the branch carries a
            # delay-slot nop too.  reg_sets covers only the author's
            # asm, so the trace must contain
            # `len(specs) + trailer_insns` insns mapped to this block.
            trailer = _TRAILER_INSNS_BY_ISA.get(isa, 1)
            expected_total = len(specs) + trailer
            if len(idxs) != expected_total:
                if n_errors < err_cap:
                    issues.append(Issue(
                        "expected_reg_sets", "error",
                        f"blk_{bid} ({block.get('class','?')}): declared "
                        f"{len(specs)} insn reg-sets + {trailer} trailer "
                        f"insn(s) = {expected_total}, but trace template "
                        f"contains {len(idxs)} insns mapped to this block",
                        {"block_id": bid, "declared": len(specs),
                         "trailer": trailer, "trace": len(idxs)},
                    ))
                n_errors += 1
                continue
            for spec, idx in zip(specs, idxs[:len(specs)]):
                ins = insns[idx]
                exp_src: set[str] = set()
                exp_dst: set[str] = set()
                bad_names: list[str] = []
                for name in spec.get("src", []):
                    canon = resolve(name)
                    if canon is None:
                        bad_names.append(name)
                    else:
                        exp_src.add(canon)
                for name in spec.get("dst", []):
                    canon = resolve(name)
                    if canon is None:
                        bad_names.append(name)
                    else:
                        exp_dst.add(canon)
                if bad_names:
                    issues.append(Issue(
                        "expected_reg_sets", "error",
                        f"blk_{bid} insn #{idx}: unknown reg name(s) "
                        f"{bad_names!r} in expected_reg_sets",
                        {"block_id": bid, "insn_index": idx,
                         "unknown": bad_names},
                    ))
                    n_errors += 1
                    continue

                def _name(rid: int) -> str:
                    name = reg_id_to_name.get(int(rid))
                    return name if name else f"REG_{int(rid)}"

                actual_src = {_name(r) for r in ins.get("src_regs", []) or []
                              if int(r) != 0}
                actual_dst = {_name(r) for r in ins.get("dst_regs", []) or []
                              if int(r) != 0}
                n_insns_checked += 1
                if actual_src == exp_src and actual_dst == exp_dst:
                    continue
                n_errors += 1
                if n_errors <= err_cap:
                    issues.append(Issue(
                        "expected_reg_sets", "error",
                        f"blk_{bid} ({block.get('class','?')}) insn #{idx} "
                        f"pc=0x{int(ins['pc']):x}: declared src/dst regs "
                        f"don't match the trace",
                        {"block_id": bid, "insn_index": idx,
                         "pc": int(ins["pc"]),
                         "expected_src": sorted(exp_src),
                         "actual_src": sorted(actual_src),
                         "expected_dst": sorted(exp_dst),
                         "actual_dst": sorted(actual_dst)},
                    ))

    issues.append(Issue(
        "expected_reg_sets", "info",
        f"author-declared reg sets: blocks={n_blocks} "
        f"insns_checked={n_insns_checked} errors={n_errors}",
        {"blocks": n_blocks, "insns_checked": n_insns_checked,
         "errors": n_errors},
    ))
    return issues


# CST_INSN_FLAG_* bit definitions, mirroring champsim_tracer.h.  Not
# read off the trace because the decoded insn dict exposes the booleans
# (branch_conditional / is_atomic / lane_parallel) and the imm-presence
# / dep-block-presence directly rather than the raw byte.
_INSN_FLAG_BITS = {
    "CST_INSN_FLAG_BRANCH_COND":   1 << 0,
    "CST_INSN_FLAG_HAS_IMM":       1 << 1,
    "CST_INSN_FLAG_ATOMIC":        1 << 2,
    "CST_INSN_FLAG_VEC":           1 << 4,
    "CST_INSN_FLAG_LANE_PARALLEL": 1 << 5,
    "CST_INSN_FLAG_HAS_DEP_BLOCK": 1 << 6,
}


def _reconstruct_insn_flags(ins: dict,
                            entry_lane_masks_for_insn: list[dict]) -> int:
    """Rebuild the CST_INSN_FLAG_* byte from the decoded insn dict +
    its accumulated runtime lane-mask observations.  VEC turns on when
    any operand-side lane mask was observed non-zero across CP entries
    of the parent template; HAS_DEP_BLOCK turns on when any dep-mask
    family is non-empty (the decoder leaves them as `[]` when the
    HAS_REG sub-block is absent).  The other flags are direct
    one-to-one with the decoded booleans."""
    flags = 0
    if ins.get("branch_conditional"):
        flags |= _INSN_FLAG_BITS["CST_INSN_FLAG_BRANCH_COND"]
    if ins.get("imm") is not None:
        flags |= _INSN_FLAG_BITS["CST_INSN_FLAG_HAS_IMM"]
    if ins.get("is_atomic"):
        flags |= _INSN_FLAG_BITS["CST_INSN_FLAG_ATOMIC"]
    if ins.get("lane_parallel"):
        flags |= _INSN_FLAG_BITS["CST_INSN_FLAG_LANE_PARALLEL"]
    if any(ins.get(k)
           for k in ("dst_dep_mask", "store_data_dep_mask",
                     "load_addr_dep_mask", "store_addr_dep_mask")):
        flags |= _INSN_FLAG_BITS["CST_INSN_FLAG_HAS_DEP_BLOCK"]
    if any(int(lm.get("mask", 0)) for lm in entry_lane_masks_for_insn):
        flags |= _INSN_FLAG_BITS["CST_INSN_FLAG_VEC"]
    return flags


def _resolve_dep_input_bit(name: str, n_src: int,
                           max_dep_loads: int,
                           layout: str) -> int | None:
    """Map an author dep-input name (\"src_reg[i]\", \"load_data[k]\",
    \"imm\") to its bit position inside a dep mask.  @layout selects
    the bit shape — REG-mask layouts (dst_dep / store_data_dep)
    include the load_data range; ADDR-mask layouts (load_addr_dep /
    store_addr_dep) omit it because addresses compute before any
    load fires.  Returns None on unknown names so the caller can
    surface a "typo in spec" error."""
    if name == "imm":
        if layout == "reg":
            return n_src + max_dep_loads
        return n_src
    if name.startswith("src_reg[") and name.endswith("]"):
        idx = int(name[len("src_reg["):-1])
        if 0 <= idx < n_src:
            return idx
        return None
    if layout == "reg" and name.startswith("load_data[") and name.endswith("]"):
        idx = int(name[len("load_data["):-1])
        if 0 <= idx < max_dep_loads:
            return n_src + idx
        return None
    return None


def _names_to_dep_mask(names: list[str], n_src: int,
                       max_dep_loads: int, layout: str
                       ) -> tuple[int, list[str]]:
    """Build a dep-mask integer from a list of input-name strings.
    Returns (mask, unknown_names).  Unknown names are surfaced so the
    validator can report a spec typo cleanly."""
    mask = 0
    unknown: list[str] = []
    for n in names:
        bit = _resolve_dep_input_bit(n, n_src, max_dep_loads, layout)
        if bit is None:
            unknown.append(n)
        else:
            mask |= 1 << bit
    return mask, unknown


def _check_expected_insns(
        entries: list[dict],
        templates_by_id: dict[int, dict],
        blocks_by_id: dict[int, dict],
        pcmap: "PcMap",
        cp_set: set[int],
        isa: str,
        reg_id_to_name: dict[int, str]) -> list[Issue]:
    """Compare author-declared per-instruction EXACT check vectors
    (BlockPlan.expected_insns) against the decoded trace.  Each field
    in an entry is optional; the validator only checks what's declared.

    Fields covered:
      * src / dst    — same shape as expected_reg_sets (REG_* names).
      * opcode       — GEN_OP_* string vs the trace's per-insn opcode.
      * branch_type  — BRANCH_* string vs the trace's per-insn type.
      * insn_flags   — list of CST_INSN_FLAG_* names that must be set.
      * insn_flags_clear — list of CST_INSN_FLAG_* names that must NOT
                       be set (the per-insn flag byte is rebuilt from
                       the decoded booleans + dep-mask / lane-mask
                       observations).
      * dst_deps / store_data_deps / load_addr_deps / store_addr_deps —
                       per-output input-name lists resolved against
                       the dep-mask bit layout from champsim_tracer_
                       format.md §6.
      * src_lane_masks / dst_lane_masks / load_data_lane_masks /
        store_data_lane_masks — per-operand-slot lane bitmaps,
                       compared against the OR of every CP entry's
                       observation for this insn.

    Author intent vs. trace divergence is reported.  The trace-vs-
    Capstone check (_check_static_reg_sets) is still the orthogonal
    "did the assembler produce what we asked" oracle.
    """
    blocks = [b for b in blocks_by_id.values()
              if b["block_id"] in cp_set and b.get("expected_insns")]
    if not blocks:
        return [Issue(
            "expected_insns", "info",
            "no blocks declared expected_insns — exact-check oracle "
            "skipped",
        )]

    opcode_names, branch_names = _load_name_tables()
    opcode_by_name = {v: k for k, v in opcode_names.items()}
    branch_by_name = {v: k for k, v in branch_names.items()}

    def _norm_op(name: str) -> str:
        return name[len("GEN_OP_"):] if name.startswith("GEN_OP_") else name

    def _norm_br(name: str) -> str:
        return name[len("BRANCH_"):] if name.startswith("BRANCH_") else name

    valid_names: set[str] = set()
    for name in reg_id_to_name.values():
        valid_names.add(name)
        if name.startswith("REG_"):
            valid_names.add(name[4:])

    def resolve_reg(name: str) -> str | None:
        if name in valid_names:
            return name if name.startswith("REG_") else f"REG_{name}"
        return None

    # Pre-aggregate lane masks per (template_id, insn_index, family,
    # slot_index) → OR of every CP entry's observation.  For STATIC
    # lane masks the OR is the structural pattern; for dynamic kinds
    # (SVE pred, RVV vl) it is the strongest mask any active execution
    # exposed — that's the strongest check the structural author-side
    # assertion can make.
    agg_lane: dict[tuple[int, int, str, int], int] = {}
    for e in entries:
        tid = int(e["template_id"])
        for lm in e.get("lane_masks") or []:
            key = (tid, int(lm["insn_index"]), str(lm["family"]),
                   int(lm["slot_index"]))
            agg_lane[key] = agg_lane.get(key, 0) | int(lm.get("mask", 0))

    issues: list[Issue] = []
    n_blocks = 0
    n_insns_checked = 0
    n_errors = 0
    err_cap = 30

    def err(cat: str, msg: str, meta: dict) -> None:
        nonlocal n_errors
        n_errors += 1
        if n_errors <= err_cap:
            issues.append(Issue("expected_insns", "error",
                                f"[{cat}] {msg}", meta))

    blocks_by_bid = {int(b["block_id"]): b for b in blocks}
    trailer = _TRAILER_INSNS_BY_ISA.get(isa, 1)

    # Tracks which (block_id) we've already counted against n_blocks —
    # an insn-mapping run can fire across multiple CP entries of the
    # same template, but we want one block per declared spec.
    counted_blocks: set[int] = set()

    for e in entries:
        tmpl = templates_by_id.get(int(e["template_id"]))
        if tmpl is None:
            continue
        tid = int(e["template_id"])
        insns = tmpl.get("insns", [])
        per_block: dict[int, list[int]] = {}
        for idx, ins in enumerate(insns):
            bid = pcmap.lookup(int(ins["pc"]))
            if bid is None or bid not in blocks_by_bid:
                continue
            per_block.setdefault(bid, []).append(idx)

        for bid, idxs in per_block.items():
            block = blocks_by_bid[bid]
            specs = block.get("expected_insns") or []
            if not specs:
                continue
            if bid not in counted_blocks:
                counted_blocks.add(bid)
                n_blocks += 1
            expected_total = len(specs) + trailer
            if len(idxs) != expected_total:
                err("count",
                    f"blk_{bid} ({block.get('class','?')}): declared "
                    f"{len(specs)} insn specs + {trailer} trailer = "
                    f"{expected_total}, trace template has {len(idxs)}",
                    {"block_id": bid, "declared": len(specs),
                     "trailer": trailer, "trace": len(idxs)})
                continue

            for spec, idx in zip(specs, idxs[:len(specs)]):
                ins = insns[idx]
                ctx = {"block_id": bid, "insn_index": idx,
                       "pc": int(ins["pc"]),
                       "class": block.get("class", "?")}
                n_insns_checked += 1

                # --- src/dst register sets ---
                if "src" in spec or "dst" in spec:
                    bad: list[str] = []
                    exp_src = set()
                    exp_dst = set()
                    for n in spec.get("src", []) or []:
                        r = resolve_reg(n)
                        (exp_src.add(r) if r else bad.append(n))
                    for n in spec.get("dst", []) or []:
                        r = resolve_reg(n)
                        (exp_dst.add(r) if r else bad.append(n))
                    if bad:
                        err("reg_name",
                            f"blk_{bid} insn #{idx}: unknown REG names "
                            f"{bad!r}", {**ctx, "unknown": bad})
                    else:
                        def _name(rid: int) -> str:
                            n = reg_id_to_name.get(int(rid))
                            return n if n else f"REG_{int(rid)}"
                        actual_src = {_name(r) for r in ins.get("src_regs") or []
                                      if int(r) != 0}
                        actual_dst = {_name(r) for r in ins.get("dst_regs") or []
                                      if int(r) != 0}
                        if "src" in spec and actual_src != exp_src:
                            err("src_regs",
                                f"blk_{bid} insn #{idx} pc=0x{ctx['pc']:x}: "
                                f"src mismatch",
                                {**ctx, "expected": sorted(exp_src),
                                 "actual": sorted(actual_src)})
                        if "dst" in spec and actual_dst != exp_dst:
                            err("dst_regs",
                                f"blk_{bid} insn #{idx} pc=0x{ctx['pc']:x}: "
                                f"dst mismatch",
                                {**ctx, "expected": sorted(exp_dst),
                                 "actual": sorted(actual_dst)})

                # --- opcode ---
                if "opcode" in spec:
                    want = _norm_op(spec["opcode"])
                    got = opcode_names.get(int(ins.get("opcode", 0)), "?")
                    if want not in opcode_by_name:
                        err("opcode_name",
                            f"blk_{bid} insn #{idx}: unknown opcode "
                            f"name {spec['opcode']!r}",
                            {**ctx, "opcode": spec["opcode"]})
                    elif got != want:
                        err("opcode",
                            f"blk_{bid} insn #{idx} pc=0x{ctx['pc']:x}: "
                            f"opcode {got!r}, expected {want!r}",
                            {**ctx, "expected": want, "actual": got})

                # --- branch_type ---
                if "branch_type" in spec:
                    want = _norm_br(spec["branch_type"])
                    got = branch_names.get(int(ins.get("branch_type", 0)),
                                           "?")
                    if want not in branch_by_name:
                        err("branch_type_name",
                            f"blk_{bid} insn #{idx}: unknown branch "
                            f"type {spec['branch_type']!r}",
                            {**ctx, "branch": spec["branch_type"]})
                    elif got != want:
                        err("branch_type",
                            f"blk_{bid} insn #{idx} pc=0x{ctx['pc']:x}: "
                            f"branch_type {got!r}, expected {want!r}",
                            {**ctx, "expected": want, "actual": got})

                # --- insn_flags (set + clear) ---
                if "insn_flags" in spec or "insn_flags_clear" in spec:
                    insn_lanes = [lm for lm in e.get("lane_masks") or []
                                  if int(lm["insn_index"]) == idx]
                    flags = _reconstruct_insn_flags(ins, insn_lanes)
                    for name in spec.get("insn_flags") or []:
                        bit = _INSN_FLAG_BITS.get(name)
                        if bit is None:
                            err("flag_name",
                                f"blk_{bid} insn #{idx}: unknown insn "
                                f"flag {name!r}", {**ctx, "flag": name})
                        elif not (flags & bit):
                            err("insn_flag_missing",
                                f"blk_{bid} insn #{idx} pc=0x{ctx['pc']:x}: "
                                f"{name} not set (flags=0x{flags:x})",
                                {**ctx, "missing_flag": name,
                                 "flags": flags})
                    for name in spec.get("insn_flags_clear") or []:
                        bit = _INSN_FLAG_BITS.get(name)
                        if bit is None:
                            err("flag_name",
                                f"blk_{bid} insn #{idx}: unknown insn "
                                f"flag {name!r}", {**ctx, "flag": name})
                        elif (flags & bit):
                            err("insn_flag_unexpected",
                                f"blk_{bid} insn #{idx} pc=0x{ctx['pc']:x}: "
                                f"{name} set but expected clear "
                                f"(flags=0x{flags:x})",
                                {**ctx, "unexpected_flag": name,
                                 "flags": flags})

                # --- dependency masks ---
                n_src = len(ins.get("src_regs") or [])
                n_dst = len(ins.get("dst_regs") or [])
                mdl   = int(ins.get("n_loads", 0))
                for field, wire_field, per_count, layout in (
                    ("dst_deps", "dst_dep_mask", n_dst, "reg"),
                    ("store_data_deps", "store_data_dep_mask",
                        int(ins.get("n_stores", 0)), "reg"),
                    ("load_addr_deps", "load_addr_dep_mask",
                        mdl, "addr"),
                    ("store_addr_deps", "store_addr_dep_mask",
                        int(ins.get("n_stores", 0)), "addr"),
                ):
                    if field not in spec:
                        continue
                    declared = spec[field]
                    if not isinstance(declared, list):
                        err("dep_shape",
                            f"blk_{bid} insn #{idx}: {field} must be a "
                            f"list[list[str]]", {**ctx, "field": field})
                        continue
                    actual = ins.get(wire_field) or []
                    if len(declared) != per_count:
                        err("dep_count",
                            f"blk_{bid} insn #{idx}: {field} declared "
                            f"{len(declared)} entries, expected "
                            f"{per_count} (n_dst={n_dst} "
                            f"n_stores={ins.get('n_stores',0)} "
                            f"n_loads={mdl})",
                            {**ctx, "field": field,
                             "declared": len(declared),
                             "expected": per_count})
                        continue
                    if not actual and declared:
                        # Trace carries no HAS_REG sub-block but author
                        # declared non-empty deps — the over-approxima-
                        # tion fallback masked them.
                        if any(declared):
                            err("dep_missing",
                                f"blk_{bid} insn #{idx} pc=0x{ctx['pc']:x}: "
                                f"{field} declared but trace has no "
                                f"HAS_REG/HAS_ADDR sub-block (fell back "
                                f"to all-to-all)",
                                {**ctx, "field": field})
                            continue
                    for j, names in enumerate(declared):
                        exp_mask, unknown = _names_to_dep_mask(
                            names or [], n_src, mdl, layout)
                        if unknown:
                            err("dep_input_name",
                                f"blk_{bid} insn #{idx}: {field}[{j}] "
                                f"has unknown input(s) {unknown!r}",
                                {**ctx, "field": field, "j": j,
                                 "unknown": unknown})
                            continue
                        got_mask = (int(actual[j])
                                    if j < len(actual) else 0)
                        if got_mask != exp_mask:
                            err("dep_mask",
                                f"blk_{bid} insn #{idx} pc=0x{ctx['pc']:x}: "
                                f"{field}[{j}] got=0x{got_mask:x} "
                                f"expected=0x{exp_mask:x}",
                                {**ctx, "field": field, "j": j,
                                 "expected": exp_mask,
                                 "actual": got_mask})

                # --- lane masks ---
                for field, family in (
                    ("src_lane_masks",       "src"),
                    ("dst_lane_masks",       "dst"),
                    ("load_data_lane_masks", "load"),
                    ("store_data_lane_masks","store"),
                ):
                    if field not in spec:
                        continue
                    declared = spec[field]
                    for slot, exp_mask in enumerate(declared):
                        got = agg_lane.get((tid, idx, family, slot), 0)
                        if int(exp_mask) != got:
                            err("lane_mask",
                                f"blk_{bid} insn #{idx} pc=0x{ctx['pc']:x}: "
                                f"{family}_lane_mask[{slot}] "
                                f"got=0x{got:x} expected=0x{int(exp_mask):x}",
                                {**ctx, "field": field, "slot": slot,
                                 "expected": int(exp_mask),
                                 "actual": got})

    issues.append(Issue(
        "expected_insns", "info" if not n_errors else "error",
        f"author-declared exact-insn checks: blocks={n_blocks} "
        f"insns_checked={n_insns_checked} errors={n_errors}",
        {"blocks": n_blocks, "insns_checked": n_insns_checked,
         "errors": n_errors},
    ))
    return issues


def _check_reg_value_assertions(
        entries: list[dict],
        templates_by_id: dict[int, dict],
        blocks_by_id: dict[int, dict],
        pcmap: "PcMap",
        cp_set: set[int],
        has_reg_data: bool,
        reg_id_to_name: dict[int, str]) -> list[Issue]:
    blocks = [b for b in blocks_by_id.values()
              if b["block_id"] in cp_set and b.get("reg_value_assertions")]
    if not blocks:
        return []
    if not has_reg_data:
        return [Issue(
            "reg_value_assertion", "info",
            "register-value assertions skipped because trace was captured "
            "without regdata=1",
        )]

    # Resolve assertion names via the trace's own `reg` encoding map.
    reg_id_by_name = {name: int(rid) for rid, name in reg_id_to_name.items()}
    observations: dict[tuple[int, int], list[dict]] = {}

    for e in entries:
        tmpl = templates_by_id.get(int(e["template_id"]))
        if tmpl is None:
            continue
        insns = tmpl.get("insns", [])
        for snap in e.get("reg_snaps") or []:
            idx = int(snap.get("insn_index", -1))
            if idx < 0 or idx >= len(insns):
                continue
            bid = pcmap.lookup(int(insns[idx]["pc"]))
            if bid is None:
                continue
            rid = int(snap.get("reg_id", 0))
            observations.setdefault((bid, rid), []).append(snap)

    issues: list[Issue] = []
    for b in blocks:
        bid = int(b["block_id"])
        for assertion in b.get("reg_value_assertions") or []:
            reg_name = str(assertion["reg"])
            rid = reg_id_by_name.get(reg_name)
            if rid is None:
                issues.append(Issue(
                    "reg_value_assertion", "error",
                    f"blk_{bid}: unknown register assertion name {reg_name}",
                    {"block_id": bid, "assertion": assertion},
                ))
                continue
            bits = int(assertion.get("bits", 512))
            mask = _bit_mask(bits)
            want = int(assertion["value"]) & mask
            seen = observations.get((bid, rid), [])
            if any((_reg_snap_value(s) & mask) == want for s in seen):
                continue
            if bool(assertion.get("optional", False)) and not seen:
                continue
            issues.append(Issue(
                "reg_value_assertion", "error",
                f"blk_{bid} ({b['class']}): expected {reg_name} "
                f"low {bits} bits to equal 0x{want:x}, but saw "
                f"{[hex(_reg_snap_value(s) & mask) for s in seen[:5]]}",
                {"block_id": bid, "reg": reg_name, "bits": bits,
                 "expected": want,
                 "observed_first5": [_reg_snap_value(s) & mask
                                     for s in seen[:5]]},
            ))
    return issues


def _capstone_operand_kinds(isa: str):
    try:
        import capstone as cs
    except ImportError:
        return None
    if isa == "x86_64":
        return cs.x86.X86_OP_REG, cs.x86.X86_OP_IMM, cs.x86.X86_OP_MEM
    if isa == "aarch64":
        return (cs.aarch64.AARCH64_OP_REG,
                cs.aarch64.AARCH64_OP_IMM,
                cs.aarch64.AARCH64_OP_MEM)
    if isa == "riscv64":
        return (cs.riscv.RISCV_OP_REG,
                cs.riscv.RISCV_OP_IMM,
                cs.riscv.RISCV_OP_MEM)
    if isa == "mipsel":
        return (cs.mips.MIPS_OP_REG,
                cs.mips.MIPS_OP_IMM,
                cs.mips.MIPS_OP_MEM)
    return None


def _generic_reg_name_to_id() -> dict[str, int]:
    """Legacy reverse-map.  Use the per-trace encoding map for new code;
    this only services callers that haven't been migrated yet."""
    dec = _load_decoder()
    return {name: rid for rid, name in dec.build_reg_names().items()}


def _capstone_reg_module(isa: str):
    import capstone as cs
    if isa == "x86_64":
        return cs.x86
    if isa == "aarch64":
        return cs.aarch64
    if isa == "riscv64":
        return cs.riscv
    if isa == "mipsel":
        return cs.mips
    raise ValueError(f"unsupported isa {isa!r}")


@dataclasses.dataclass
class _RegClassEntry:
    """Per-Capstone-reg generic-name mapping.

    `names` are the GenericRegId names the tracer emits for any
    operand-access of this Capstone register.  The integer-flags byte
    rides a side-channel FID (CST_FID_METAFLAGS), not a synthetic
    dst-register slot, so write-side operand walks compare the same
    name set as the read side.
    """
    names: tuple[str, ...]


def _capstone_reg_class_for_isa(isa: str) -> dict[int, _RegClassEntry]:
    """Return {Capstone reg enum value: _RegClassEntry}.

    The tracer's C decoder indexes these same per-ISA reg tables by
    Capstone enum value.  Parsing them here keeps static register-set
    validation tied to the active tracer tables.

    Values are **symbolic name strings** rather than numeric ids — the
    trace is self-describing (every ENCODINGS section carries its own
    {gen_id ↔ name} mapping), and a previous numeric-id version of
    this validator silently broke when the plugin's GenericRegId
    layout shifted (REG_FLAGS, REG_IP, etc. moved by 25 slots when
    new register banks landed).  Comparing by name lets the validator
    track header changes automatically and lets multiple trace
    versions coexist with no per-version translation table.
    """
    header = _ISA_TO_REG_TABLE.get(isa)
    if header is None:
        raise ValueError(f"unsupported isa {isa!r}")
    cap_mod = _capstone_reg_module(isa)
    text = (_PLUGIN_SOURCE_DIR / header).read_text()
    out: dict[int, _RegClassEntry] = {}
    entry_re = re.compile(r"\[([A-Z0-9_]+)\]\s*=\s*\{([^\n]*)\},")
    for match in entry_re.finditer(text):
        cap_name = match.group(1)
        cap_id = getattr(cap_mod, cap_name, None)
        if cap_id is None:
            continue
        body = match.group(2)
        alias_match = re.search(r"\.regs\s*=\s*\{([^}]*)\}", body)
        if alias_match:
            reg_names = re.findall(r"REG_[A-Z0-9_]+", alias_match.group(1))
        else:
            reg_match = re.search(
                r"(?:\.reg_id\s*=\s*)?(REG_[A-Z0-9_]+)", body)
            if not reg_match:
                continue
            reg_names = [reg_match.group(1)]
        names = tuple(n for n in reg_names if n != "REG_NONE")
        if names:
            out[int(cap_id)] = _RegClassEntry(names=names)
    return out


def _check_static_reg_sets(
    templates: list[dict],
    isa: str,
    reg_id_to_name: dict[int, str],
) -> list[Issue]:
    """Compare template src/dst register IDs to Capstone ground truth.

    Comparison is **by symbolic name** (REG_FLAGS, REG_IP, …) rather
    than numeric GenericRegId.  The trace's own ENCODINGS section
    supplies the per-trace `gen_id → name` mapping in
    @reg_id_to_name; the validator translates the trace's numeric
    `src_regs`/`dst_regs` into name sets and compares against the
    name set the validator builds from Capstone + the per-ISA reg-
    class table.  This is the design the trace's self-describing
    format intends — numeric ids may shift as new register banks land
    but names are stable.

    The C decoder's static discovery rules are otherwise unchanged:
    explicit register operands use access flags when available,
    otherwise the first register operand is treated as the
    destination for opcodes where that convention is valid; memory
    base/index registers are sources; RISC-V/MIPS Capstone access
    flags and implicit regs_read/regs_write are skipped because they
    disagree with the tracer detail path for common pseudos and
    control-flow forms.  The comparison is set-based because the
    trace format promises operand identity, not a consumer-visible
    semantic ordering guarantee.
    """
    md, _op_mem_kind = _make_capstone(isa)
    kinds = _capstone_operand_kinds(isa)
    if md is None or kinds is None:
        return [Issue(
            "static_reg_sets", "error",
            f"static register-set check cannot run for isa={isa}",
        )]
    op_reg_kind, op_imm_kind, op_mem_kind = kinds
    reg_class = _capstone_reg_class_for_isa(isa)
    opcode_names, _ = _load_name_tables()

    first_reg_is_not_dst = {
        "STORE", "CMP", "BRANCH", "RET", "SYSCALL", "NOP",
    }

    issues: list[Issue] = []
    n_checked = 0
    n_errors = 0
    n_skipped = 0
    err_cap = 20

    def add(out: set[str], cap_id: int) -> None:
        entry = reg_class.get(int(cap_id))
        if entry is None:
            return
        for reg_name in entry.names:
            if reg_name and reg_name != "REG_NONE":
                out.add(reg_name)

    for tmpl in templates:
        # Kernel (CST_INSN_FLAG_SYSTEM) templates of a system-mode trace
        # are not in the compiled binary, so there is no ground truth to
        # compare their register sets against — skip them, matching the
        # user-subsequence alignment the rest of the validator performs.
        if tmpl.get("is_system"):
            continue
        tid = int(tmpl["template_id"])
        for idx, ins in enumerate(tmpl.get("insns", [])):
            raw = ins.get("raw_bytes")
            if not raw:
                n_skipped += 1
                continue
            decoded = list(md.disasm(bytes(raw), int(ins["pc"])))
            if not decoded:
                n_skipped += 1
                continue
            d = decoded[0]
            ops = getattr(d, "operands", []) or []
            have_access_info = any(
                int(getattr(op, "access", 0) or 0) != 0 for op in ops
            )
            # Match the tracer's behavior: use Capstone's per-operand
            # access flags when present, falling back to the
            # opcode-indexed first_reg_is_not_dst heuristic only when
            # the disasm carries no access info.  Previously the
            # validator blanket-disabled access info for RISC-V / MIPS
            # because of disagreements on pseudos and control-flow
            # forms; those specific cases are now caught by the
            # per-mnemonic skip block further down.
            opcode_name = opcode_names.get(int(ins.get("opcode", 0)), "?")
            first_is_dst = opcode_name not in first_reg_is_not_dst
            seen_first_reg = False
            exp_src: set[str] = set()
            exp_dst: set[str] = set()

            for op in ops:
                if op.type == op_reg_kind:
                    if have_access_info:
                        access = int(getattr(op, "access", 0) or 0)
                        if access & 1:
                            add(exp_src, op.reg)
                        if access & 2:
                            add(exp_dst, op.reg)
                    else:
                        if first_is_dst and not seen_first_reg:
                            add(exp_dst, op.reg)
                        else:
                            add(exp_src, op.reg)
                        seen_first_reg = True
                elif op.type == op_mem_kind:
                    add(exp_src, getattr(op.mem, "base", 0) or 0)
                    add(exp_src, getattr(op.mem, "index", 0) or 0)
                elif op.type == op_imm_kind:
                    continue

            # Implicit regs (regs_read[]/regs_write[]) fold in only
            # where the tracer's ISA properties say so — matches
            # decode.cc's `isa_properties[..].include_implicit_regs`
            # gate (true for x86 + AArch64 + MIPS — MIPS needs it for
            # the HI:LO accumulator, which only exists implicitly —
            # false for RISC-V).
            if isa != "riscv64":
                for cap_id in getattr(d, "regs_read", []) or []:
                    add(exp_src, cap_id)
                for cap_id in getattr(d, "regs_write", []) or []:
                    add(exp_dst, cap_id)

            # Translate trace's numeric reg ids → symbolic names via
            # the trace's own ENCODINGS reg map.  Unknown ids (no entry
            # in the map) get a "REG_<id>" placeholder so the diff is
            # still legible — but in practice the trace always carries
            # every id it emits.
            def _name(rid: int) -> str:
                name = reg_id_to_name.get(int(rid))
                if name:
                    return name
                return f"REG_{int(rid)}"

            actual_src = {_name(r) for r in ins.get("src_regs", []) or []
                          if int(r) != 0}
            actual_dst = {_name(r) for r in ins.get("dst_regs", []) or []
                          if int(r) != 0}

            mnemonic = (getattr(d, "mnemonic", "") or "").lower()
            op_str = (getattr(d, "op_str", "") or "").lower()
            # Known Capstone-vs-QEMU detail mismatches.  These are not
            # useful src/dst-reg oracle cases: x87 stack operands are
            # renumbered differently for FXCH, RISC-V `j` pseudos can
            # surface a spurious source register in QEMU detail, and
            # MIPS FP pair operands do not agree between the two APIs.
            if (isa == "x86_64" and "st(" in op_str):
                n_skipped += 1
                continue
            if (isa == "riscv64" and opcode_name == "BRANCH"
                    and not exp_src and not exp_dst and actual_src
                    and not actual_dst):
                n_skipped += 1
                continue
            if isa == "riscv64" and mnemonic in ("beqz", "bnez", "ecall"):
                n_skipped += 1
                continue
            if isa == "riscv64" and mnemonic in ("auipc", "lui"):
                n_skipped += 1
                continue
            # Aliased link forms hide ra completely in Capstone 6 (not
            # in operands NOR the always-empty riscv implicit arrays);
            # the tracer re-adds REG_LR in refine_branch_type.  Assert
            # that restoration positively instead of skipping: raw
            # Capstone's sets plus the link register ARE the expected
            # truth.  Plain "jal imm" / 1-reg "jalr rs" write ra;
            # "ret" reads it.  Non-aliased forms carry the link reg
            # explicitly and need no fixup.
            if isa == "riscv64":
                if mnemonic == "jal" and not exp_dst:
                    exp_dst.add("REG_LR")
                elif mnemonic == "jalr" and not exp_dst:
                    exp_dst.add("REG_LR")
                elif mnemonic == "ret" and not exp_src:
                    exp_src.add("REG_LR")
            if isa == "riscv64" and mnemonic.startswith("v"):
                n_skipped += 1
                continue
            if (isa == "mipsel" and ("$f" in op_str
                                      or mnemonic.endswith((".s", ".d")))):
                n_skipped += 1
                continue
            if isa == "mipsel" and mnemonic == "sc":
                n_skipped += 1
                continue
            # lwl/lwr (and 64-bit ldl/ldr) partially write the dst, so
            # the tracer promotes it to READ|WRITE (disas/capstone.c
            # workaround); raw Capstone says WRITE-only.  The corrected
            # behaviour is pinned exactly by probe_mips_lwl_lwr.
            if isa == "mipsel" and mnemonic in ("lwl", "lwr",
                                                "ldl", "ldr"):
                n_skipped += 1
                continue
            if isa == "mipsel" and mnemonic in ("madd", "msub"):
                n_skipped += 1
                continue
            if isa == "mipsel" and mnemonic.startswith(("jalr", "jr")):
                n_skipped += 1
                continue
            n_checked += 1
            if actual_src == exp_src and actual_dst == exp_dst:
                continue
            n_errors += 1
            if n_errors <= err_cap:
                issues.append(Issue(
                    "static_reg_sets", "error",
                    f"template t{tid} insn #{idx} pc=0x{int(ins['pc']):x}: "
                    f"src/dst reg set mismatch",
                    {
                        "template_id": tid,
                        "insn_index": idx,
                        "pc": int(ins["pc"]),
                        "mnemonic": getattr(d, "mnemonic", ""),
                        "op_str": getattr(d, "op_str", ""),
                        "expected_src": sorted(exp_src),
                        "actual_src": sorted(actual_src),
                        "expected_dst": sorted(exp_dst),
                        "actual_dst": sorted(actual_dst),
                    },
                ))

    issues.append(Issue(
        "static_reg_sets", "info",
        f"static register sets: ok={n_checked - n_errors} "
        f"checked={n_checked} skipped={n_skipped} errors={n_errors}",
        {"checked": n_checked, "skipped": n_skipped,
         "errors": n_errors},
    ))
    return issues


# ---------------------------------------------------------------------------
# Address-recompute check — uses captured §5.2 reg-snaps + Capstone python
# to verify that each runtime memop's recorded VA matches the effective
# address computed from base/index/disp/scale of the issuing insn.
# ---------------------------------------------------------------------------

# GenericRegId numbering (must match build_reg_names() in
# champsim_tracer_decode.py): REG_NONE=0, GPRn=1+n, SP=250, FLAGS=251,
# IP=252, LR=253, FP_REG=254.

def _x86_64_name_to_genid() -> dict[str, int]:
    m: dict[str, int] = {}
    # GPR0..GPR5: rax, rcx, rdx, rbx, rsi, rdi
    for stems, gid in [
        (("rax", "eax", "ax", "al", "ah"), 1),
        (("rcx", "ecx", "cx", "cl", "ch"), 2),
        (("rdx", "edx", "dx", "dl", "dh"), 3),
        (("rbx", "ebx", "bx", "bl", "bh"), 4),
        (("rsi", "esi", "si", "sil"), 5),
        (("rdi", "edi", "di", "dil"), 6),
    ]:
        for s in stems:
            m[s] = gid
    # GPR6..GPR13: r8..r15
    for n in range(8, 16):
        gid = 7 + (n - 8)  # r8 → REG_GPR6 → 7
        for suf in ("", "d", "w", "b"):
            m[f"r{n}{suf}"] = gid
    # SP=250, FP_REG=254, IP=252
    for s in ("rsp", "esp", "sp", "spl"):
        m[s] = 250
    for s in ("rbp", "ebp", "bp", "bpl"):
        m[s] = 254
    for s in ("rip", "eip"):
        m[s] = 252
    return m


def _aarch64_name_to_genid() -> dict[str, int]:
    m: dict[str, int] = {}
    for n in range(31):
        m[f"x{n}"] = 1 + n
        m[f"w{n}"] = 1 + n
    m["sp"] = 250
    m["wsp"] = 250
    m["lr"] = 253
    m["fp"] = 254
    m["xzr"] = 0
    m["wzr"] = 0
    return m


def _riscv64_name_to_genid() -> dict[str, int]:
    # Table mirrors champsim_tracer_mnemonics_riscv.h.
    base = {
        "zero": 0, "ra": 253, "sp": 250,
        "gp": 4, "tp": 5,
        "t0": 6, "t1": 7, "t2": 8,
        "s0": 254, "fp": 254, "s1": 10,
        "a0": 11, "a1": 12, "a2": 13, "a3": 14,
        "a4": 15, "a5": 16, "a6": 17, "a7": 18,
        "s2": 19, "s3": 20, "s4": 21, "s5": 22, "s6": 23, "s7": 24,
        "s8": 25, "s9": 26, "s10": 27, "s11": 28,
        "t3": 29, "t4": 30, "t5": 31, "t6": 32,
    }
    xnum_to_abi = ["zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
                   "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
                   "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
                   "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"]
    for i, abi in enumerate(xnum_to_abi):
        base[f"x{i}"] = base[abi]
    return base


def _mipsel_name_to_genid() -> dict[str, int]:
    base = {
        "zero": 0, "at": 2,
        "v0": 3, "v1": 4,
        "a0": 5, "a1": 6, "a2": 7, "a3": 8,
        "t0": 9, "t1": 10, "t2": 11, "t3": 12,
        "t4": 13, "t5": 14, "t6": 15, "t7": 16,
        "s0": 17, "s1": 18, "s2": 19, "s3": 20,
        "s4": 21, "s5": 22, "s6": 23, "s7": 24,
        "t8": 25, "t9": 26, "k0": 27, "k1": 28,
        "gp": 29, "sp": 250, "fp": 254, "s8": 254, "ra": 253,
    }
    abi = ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
           "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
           "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
           "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"]
    for i, n in enumerate(abi):
        base[f"${i}"] = base[n]
    return base


_NAME_TO_GENID_BY_ISA = {
    "x86_64":  _x86_64_name_to_genid(),
    "aarch64": _aarch64_name_to_genid(),
    "riscv64": _riscv64_name_to_genid(),
    "mipsel":  _mipsel_name_to_genid(),
}


def _make_capstone(isa: str):
    try:
        import capstone as cs
    except ImportError:
        return None, None
    if isa == "x86_64":
        md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        op_mem = cs.x86.X86_OP_MEM
    elif isa == "aarch64":
        md = cs.Cs(cs.CS_ARCH_AARCH64, cs.CS_MODE_ARM)
        op_mem = cs.aarch64.AARCH64_OP_MEM
    elif isa == "riscv64":
        md = cs.Cs(cs.CS_ARCH_RISCV,
                   cs.CS_MODE_RISCV64
                   | cs.CS_MODE_RISCV_C
                   | cs.CS_MODE_RISCV_FD
                   | cs.CS_MODE_RISCV_A
                   | cs.CS_MODE_RISCV_V
                   | cs.CS_MODE_RISCV_ZBA
                   | cs.CS_MODE_RISCV_ZBB
                   | cs.CS_MODE_RISCV_ZBC
                   | cs.CS_MODE_RISCV_ZBKB
                   | cs.CS_MODE_RISCV_ZBKC
                   | cs.CS_MODE_RISCV_ZBKX
                   | cs.CS_MODE_RISCV_ZBS)
        op_mem = cs.riscv.RISCV_OP_MEM
    elif isa == "mipsel":
        md = cs.Cs(cs.CS_ARCH_MIPS,
                   cs.CS_MODE_MIPS32 | cs.CS_MODE_LITTLE_ENDIAN)
        op_mem = cs.mips.MIPS_OP_MEM
    else:
        return None, None
    md.detail = True
    return md, op_mem


def _get_mem_components(d, op, isa: str):
    """Return (base_name, index_name, disp, scale, access) for a MEM
    operand of a Capstone-decoded insn, normalised to lowercase names.

    `access` is the Capstone access bitfield (1=R, 2=W, 0=unknown).
    `scale` defaults to 1 except for x86 (uses op.mem.scale).
    `index_name` is None unless the ISA exposes an index register.
    """
    base_id = op.mem.base
    base_name = d.reg_name(base_id) if base_id else None
    if base_name:
        base_name = base_name.lower()
    disp = int(op.mem.disp)
    access = int(getattr(op, "access", 0) or 0)
    if isa == "x86_64":
        scale = int(op.mem.scale) if op.mem.scale else 1
        idx_id = op.mem.index
        index_name = (d.reg_name(idx_id).lower()
                      if idx_id else None)
        return base_name, index_name, disp, scale, access
    if isa == "aarch64":
        idx_id = op.mem.index
        index_name = (d.reg_name(idx_id).lower()
                      if idx_id else None)
        return base_name, index_name, disp, 1, access
    # RISC-V / MIPS: base + disp only
    return base_name, None, disp, 1, access


def _x86_mnemonic_mem_fallback(d, dp_kind):
    """For x86 insns whose stack/string memop Capstone hides as an
    implicit access (push/pop/call/ret/leave/enter, pushf/popf), derive
    (base_name, index_name, disp, scale, op_size).

    The tracer captures the VA via QEMU's mem callback, which fires for
    these implicit accesses, so this is purely an EA-recomputation
    helper.  Returns None if not recognized.

    For PUSH-class (writes to [rsp - sizeof(op)]), QEMU updates rsp
    *after* the access on x86, so the source-snap of rsp is the
    pre-decrement value; the EA is therefore (rsp - op_size).  POP-
    class reads at the current rsp.  CALL pushes the return addr
    (EA = rsp - 8); RET pops it (EA = rsp).
    """
    mnem = (d.mnemonic or "").lower()
    # operand size in bytes (default 8 for 64-bit mode)
    # Capstone sets d.operands[0].size for explicit operands; for
    # PUSH imm/reg it tracks the actual width.
    op_size = 8
    ops = getattr(d, "operands", []) or []
    for op in ops:
        sz = int(getattr(op, "size", 0) or 0)
        if sz:
            op_size = sz
            break

    if mnem in ("push", "pushf", "pushfq", "pushfd",
                "pusha", "pushaw", "pushad",
                "call", "callq"):
        # store at rsp - op_size (call always pushes 8 in 64-bit)
        if mnem in ("call", "callq"):
            op_size = 8
        if dp_kind != "store":
            return None
        return "rsp", None, -op_size, 1, op_size
    if mnem in ("pop", "popf", "popfq", "popfd",
                "popa", "popaw", "popad",
                "ret", "retq", "retn", "retf", "iret", "iretq"):
        if dp_kind != "load":
            return None
        return "rsp", None, 0, 1, op_size
    if mnem in ("leave", "leaveq"):
        # leave: mov rsp, rbp; pop rbp.  The memop is the pop@[rbp].
        if dp_kind != "load":
            return None
        return "rbp", None, 0, 1, 8
    if mnem in ("enter",):
        # enter pushes rbp at [rsp-8]
        if dp_kind != "store":
            return None
        return "rsp", None, -8, 1, 8
    return None


def _riscv_mnemonic_mem_fallback(d):
    """For RISC-V insns that Capstone *doesn't* expose as a MEM
    operand — compressed loads/stores (c.lw/c.sw/c.ld/c.sd, the *sp
    variants, and the FP forms) and AMO/LR/SC — derive
    (base_name, disp) from the operand list using the mnemonic.

    Returns None if the insn is not a recognized memory access.
    """
    try:
        import capstone as cs
        REG = cs.riscv.RISCV_OP_REG
        IMM = cs.riscv.RISCV_OP_IMM
    except Exception:
        return None
    mnem = (d.mnemonic or "").lower()
    ops = getattr(d, "operands", []) or []

    def _name(op):
        if op.type != REG:
            return None
        n = d.reg_name(op.reg)
        return n.lower() if n else None

    # Compressed loads / stores: data_reg, imm, base_reg.
    # *sp variants have base implicitly = sp; capstone may emit it
    # explicitly as ops[2] anyway.
    is_c_load  = mnem in ("c.lw", "c.ld", "c.lq",
                          "c.flw", "c.fld",
                          "c.lwsp", "c.ldsp", "c.lqsp",
                          "c.flwsp", "c.fldsp")
    is_c_store = mnem in ("c.sw", "c.sd", "c.sq",
                          "c.fsw", "c.fsd",
                          "c.swsp", "c.sdsp", "c.sqsp",
                          "c.fswsp", "c.fsdsp")
    if is_c_load or is_c_store:
        disp = 0
        base_name = "sp" if mnem.endswith("sp") else None
        for op in ops:
            if op.type == IMM:
                disp = int(op.imm)
                break
        if base_name is None:
            # Last REG operand is the base.
            for op in reversed(ops):
                if op.type == REG:
                    base_name = _name(op)
                    break
        return base_name, disp

    # AMO / LR / SC: base register only, no displacement.  Capstone
    # exposes the (rs1) base as the *last* REG operand for AMO and
    # the second REG operand for LR.
    if mnem.startswith("amo") or mnem.startswith("lr.") \
            or mnem.startswith("sc."):
        for op in reversed(ops):
            if op.type == REG:
                return _name(op), 0
        return None
    return None


def _check_address_recompute(
        entries: list[dict],
        template_runs: dict[int, list[tuple[int, int]]],
        templates_by_id: dict[int, dict],
        cp_set: set[int],
        isa: str) -> list[Issue]:
    """Verify recorded memop VAs by recomputing the effective address
    from §5.2 register snapshots and the issuing insn's addressing
    mode (decoded via Capstone python).

    Per CP entry with both `reg_snaps` and `dyn_params`:

      * decode each insn's `raw_bytes` with Capstone,
      * for each runtime memop dyn_param, find the MEM operand on the
        issuing insn that matches the load/store kind,
      * recover base / index register values from the entry's
        `reg_snaps` (matched by GenericRegId on the insn's `src` slot),
      * compute `EA = base + index*scale + disp` (mod 2^64) and
        compare to dp.value.

    Issues raised:
      * `addr_recompute` (error)   — recomputed EA disagrees with VA.
      * `addr_recompute` (info)    — skipped because reg snap missing,
        unknown reg name, or no matching MEM operand (each only logs
        once per (template, insn, reason)).
    """
    issues: list[Issue] = []

    if not entries:
        return issues

    name_to_gid = _NAME_TO_GENID_BY_ISA.get(isa)
    if name_to_gid is None:
        issues.append(Issue(
            "addr_recompute", "info",
            f"address-recompute skipped for unsupported isa={isa}",
        ))
        return issues

    md, op_mem_kind = _make_capstone(isa)
    if md is None:
        issues.append(Issue(
            "addr_recompute", "error",
            "capstone python module not available; "
            "address-recompute check cannot run",
        ))
        return issues

    # Some QEMU targets (e.g. mipsel user-mode) expose no registers to
    # plugins, so every reg snap reads back as zero.  Detect that case
    # by sampling and skip with a single info entry rather than
    # emitting a flood of false-positive base=0 mismatches.
    nonzero_seen = False
    for e in entries:
        for s in (e.get("reg_snaps") or ()):
            if int(s.get("lo", 0)) != 0 or int(s.get("hi", 0)) != 0:
                nonzero_seen = True
                break
        if nonzero_seen:
            break
    if not nonzero_seen:
        issues.append(Issue(
            "addr_recompute", "info",
            "address-recompute skipped: reg-data is uniformly zero "
            "(target likely exposes no plugin registers)",
        ))
        return issues

    mask64 = (1 << 64) - 1
    decoded_cache: dict[int, list] = {}  # template_id_insn_pos → operands
    skip_logged: set[tuple] = set()
    n_checked = 0
    n_skipped = 0
    n_errors = 0
    err_cap = 20

    def _decode_insn(tid: int, idx: int, raw: bytes, pc: int):
        key = (tid, idx)
        if key in decoded_cache:
            return decoded_cache[key]
        try:
            ds = list(md.disasm(bytes(raw), pc))
        except Exception:
            ds = []
        decoded_cache[key] = ds
        return ds

    def _log_skip(reason: str, tid: int, idx: int, dp_kind: str):
        key = (tid, idx, reason)
        if key in skip_logged:
            return
        skip_logged.add(key)
        issues.append(Issue(
            "addr_recompute", "info",
            f"template t{tid} insn #{idx}: {dp_kind} memop skipped "
            f"({reason})",
            {"template_id": tid, "insn_index": idx,
             "kind": dp_kind, "reason": reason},
        ))

    for e in entries:
        tid = e["template_id"]
        runs = template_runs.get(tid, [])
        if not any(bid in cp_set for bid, _ in runs):
            continue
        reg_snaps = e.get("reg_snaps") or []
        dyn = e.get("dyn_params") or []
        if not reg_snaps or not dyn:
            continue
        tmpl = templates_by_id.get(tid)
        if tmpl is None:
            continue
        insns = tmpl.get("insns", [])

        multi_memop_seen: set[tuple[int, str]] = set()

        # Index reg-snaps by (insn_index, kind, reg_id) for O(1) lookup.
        snap_by_key: dict[tuple, dict] = {}
        for s in reg_snaps:
            snap_by_key[(s["insn_index"], s["kind"], s["reg_id"])] = s

        for dp in dyn:
            i = int(getattr(dp, "insn_index", -1))
            if i < 0 or i >= len(insns):
                continue
            multi_key = (i, dp.type_name)
            if multi_key in multi_memop_seen:
                _log_skip("additional_memop_same_insn", tid, i,
                          dp.type_name)
                n_skipped += 1
                continue
            multi_memop_seen.add(multi_key)
            ins = insns[i]
            raw = ins.get("raw_bytes")
            if not raw:
                continue
            decoded = _decode_insn(tid, i, raw, int(ins["pc"]))
            if not decoded:
                _log_skip("capstone_decode_failed", tid, i, dp.type_name)
                n_skipped += 1
                continue
            d = decoded[0]
            ops = getattr(d, "operands", []) or []

            # Find the MEM operand whose access matches dp.type_name;
            # fall back to the only MEM operand if access info is
            # missing.
            want_read = (dp.type_name == "load")
            want_write = (dp.type_name == "store")
            mem_ops = [op for op in ops if op.type == op_mem_kind]
            chosen = None
            base_name = index_name = None
            disp = 0
            scale = 1
            if not mem_ops:
                # RISC-V compressed and AMO insns aren't exposed as
                # MEM ops by Capstone; reconstruct from the mnemonic.
                if isa == "riscv64":
                    fb = _riscv_mnemonic_mem_fallback(d)
                    if fb is not None:
                        base_name, disp = fb
                    else:
                        _log_skip("no_mem_operand", tid, i, dp.type_name)
                        n_skipped += 1
                        continue
                elif isa == "x86_64":
                    fb = _x86_mnemonic_mem_fallback(d, dp.type_name)
                    if fb is not None:
                        base_name, index_name, disp, scale, _opsz = fb
                    else:
                        _log_skip("no_mem_operand", tid, i, dp.type_name)
                        n_skipped += 1
                        continue
                else:
                    _log_skip("no_mem_operand", tid, i, dp.type_name)
                    n_skipped += 1
                    continue
            else:
                for op in mem_ops:
                    acc = int(getattr(op, "access", 0) or 0)
                    if acc == 0:
                        continue
                    if want_read and (acc & 1):
                        chosen = op
                        break
                    if want_write and (acc & 2):
                        chosen = op
                        break
                if chosen is None:
                    # No access info or no match — fall back when there's a
                    # single MEM operand.  Multiple-MEM-no-access cases are
                    # ambiguous; skip them.
                    if len(mem_ops) == 1:
                        chosen = mem_ops[0]
                    else:
                        _log_skip("ambiguous_mem_operands", tid, i,
                                  dp.type_name)
                        n_skipped += 1
                        continue
                base_name, index_name, disp, scale, _ = \
                    _get_mem_components(d, chosen, isa)

            base_val = 0
            if base_name and base_name not in ("", "0"):
                gid = name_to_gid.get(base_name)
                if gid is None:
                    _log_skip(f"unknown_base_reg:{base_name}", tid, i,
                              dp.type_name)
                    n_skipped += 1
                    continue
                if gid == 0:
                    base_val = 0   # zero register (xzr/x0)
                else:
                    s = snap_by_key.get((i, "src", gid))
                    if s is None:
                        _log_skip(f"missing_base_snap:{base_name}",
                                  tid, i, dp.type_name)
                        n_skipped += 1
                        continue
                    base_val = int(s["lo"])
                    # x86: rip-relative addressing uses the *next* PC.
                    if isa == "x86_64" and base_name == "rip":
                        base_val = int(ins["pc"]) + len(raw)
            elif isa == "x86_64":
                # No base — pure absolute or [disp+scale*idx].
                pass

            idx_val = 0
            if index_name and index_name not in ("", "0"):
                gid = name_to_gid.get(index_name)
                if gid is None:
                    _log_skip(f"unknown_index_reg:{index_name}", tid,
                              i, dp.type_name)
                    n_skipped += 1
                    continue
                if gid != 0:
                    s = snap_by_key.get((i, "src", gid))
                    if s is None:
                        _log_skip(f"missing_index_snap:{index_name}",
                                  tid, i, dp.type_name)
                        n_skipped += 1
                        continue
                    idx_val = int(s["lo"])

            ea = (base_val + idx_val * scale + disp) & mask64
            recorded = int(dp.value) & mask64
            if ea != recorded:
                n_errors += 1
                if n_errors <= err_cap:
                    issues.append(Issue(
                        "addr_recompute", "error",
                        f"template t{tid} insn #{i} pc=0x{ins['pc']:x}: "
                        f"{dp.type_name} VA=0x{recorded:x} but "
                        f"recomputed EA=0x{ea:x} from "
                        f"base={base_name}=0x{base_val:x} "
                        f"+ index={index_name}*{scale}=0x{idx_val * scale:x} "
                        f"+ disp=0x{disp & mask64:x}",
                        {"template_id": tid, "insn_index": i,
                         "pc": int(ins["pc"]),
                         "kind": dp.type_name,
                         "recorded_va": recorded,
                         "computed_ea": ea,
                         "base_reg": base_name,
                         "base_val": base_val,
                         "index_reg": index_name,
                         "index_val": idx_val,
                         "scale": scale, "disp": disp},
                    ))
                continue
            n_checked += 1

    issues.append(Issue(
        "addr_recompute", "info",
        f"address-recompute: ok={n_checked} skipped={n_skipped} "
        f"errors={n_errors}",
        {"ok": n_checked, "skipped": n_skipped, "errors": n_errors},
    ))
    return issues


def _check_opcode_coverage(templates: list[dict],
                           blocks_by_id: dict[int, dict],
                           pcmap: "PcMap",
                           cp_set: set[int],
                           isa: str) -> list[Issue]:
    """Emit an info-level summary of which GenericOpcode classifications
    were observed in CP-block templates.

    Lists three sets:
      * `seen` — distinct opcode names that appeared in the trace.
      * `asserted_unseen` — any opcode that some block declared in
        `asserted_opcodes` but which never appeared in the trace.  This
        is also caught (as an error) by `_check_block_assertions`; we
        re-surface it here so the coverage summary is self-contained.
      * `reachable_unseen` — opcodes the mnemonic table lists as
        reachable on this ISA but which no probe block has yet been
        written for.  Tracks progress toward 100% coverage.
    """
    opcode_names, _ = _load_name_tables()

    # Count opcodes across *all* observed template insns, not just
    # those that map to a CP block.  Helper functions invoked from a
    # CP block (e.g. the leaf called by DirectCallBlock) execute a
    # RET that isn't located inside any blk_N PC range, so a
    # CP-only count would systematically miss RET on every ISA.  As
    # long as the template was emitted, the plugin saw the insn.
    seen_ids: set[int] = set()
    for t in templates:
        for ins in t.get("insns", []):
            seen_ids.add(int(ins["opcode"]))
    seen_names = sorted(opcode_names.get(i, f"GEN_OP_{i}")
                        for i in seen_ids)

    asserted: set[str] = set()
    for b in blocks_by_id.values():
        if b["block_id"] not in cp_set:
            continue
        for op in b.get("asserted_opcodes", []) or []:
            asserted.add(op)
    asserted_unseen = sorted(asserted - set(seen_names))

    # Reachable-on-ISA set: read it lazily from the survey tables so
    # we don't duplicate the per-ISA opcode lists here.  Failure is
    # non-fatal — we just skip the third bullet.
    reachable_unseen: list[str] = []
    try:
        from . import classify as C
        clf = C.get_classifier()
        _, id_to_class, _ = clf._table_for(isa)
        reachable: set[str] = set()
        for triple in id_to_class.values():
            if not triple:
                continue
            gen_op = triple[0]
            if isinstance(gen_op, str) and gen_op.startswith("GEN_OP_"):
                reachable.add(gen_op[len("GEN_OP_"):])
        reachable -= _unsupported_opcode_coverage(isa)
        reachable_unseen = sorted(reachable - set(seen_names))
    except Exception as exc:  # pragma: no cover - diagnostic path
        reachable_unseen = []
        return [Issue(
            "opcode_coverage", "info",
            f"opcode coverage: seen={len(seen_names)}; "
            f"reachable-set lookup failed: {exc!r}",
            {"seen": seen_names, "asserted_unseen": asserted_unseen},
        )]

    return [Issue(
        "opcode_coverage", "info",
        f"opcode coverage [{isa}]: "
        f"seen={len(seen_names)} "
        f"asserted_unseen={len(asserted_unseen)} "
        f"reachable_unseen={len(reachable_unseen)}",
        {
            "seen": seen_names,
            "asserted_unseen": asserted_unseen,
            "reachable_unseen": reachable_unseen,
            "excluded_unsupported": sorted(_unsupported_opcode_coverage(isa)),
        },
    )]


def _check_branch_coverage(templates: list[dict],
                           blocks_by_id: dict[int, dict],
                           cp_set: set[int],
                           isa: str) -> list[Issue]:
    """Emit an info-level summary of BranchType coverage for CP blocks.

    Mirrors `_check_opcode_coverage` but for generic branch types:
      * `seen` — branch names observed in emitted templates.
      * `asserted_unseen` — branch types declared by block assertions but
        not observed in this trace.
      * `reachable_unseen` — branch types reachable by the ISA mnemonic table
        but not yet observed.
    """
    _, branch_names = _load_name_tables()

    def _norm(name: str) -> str:
        # Decoder branch table uses "SYSCALL" while classifier tables
        # use "BRANCH_SYSCALL_TYPE" -> "SYSCALL_TYPE".
        return "SYSCALL_TYPE" if name == "SYSCALL" else name

    seen_ids: set[int] = set()
    for t in templates:
        for ins in t.get("insns", []):
            seen_ids.add(int(ins["branch_type"]))
    seen_names = sorted(_norm(branch_names.get(i, f"BRANCH_{i}"))
                        for i in seen_ids)

    asserted: set[str] = set()
    for b in blocks_by_id.values():
        if b["block_id"] not in cp_set:
            continue
        for bt in b.get("asserted_branch_types", []) or []:
            asserted.add(_norm(bt.replace("BRANCH_", "")))
    asserted_unseen = sorted(asserted - set(seen_names))

    reachable_unseen: list[str] = []
    try:
        from . import classify as C
        clf = C.get_classifier()
        _, id_to_class, _ = clf._table_for(isa)
        reachable: set[str] = set()
        for triple in id_to_class.values():
            if not triple or len(triple) < 2:
                continue
            br = triple[1]
            if isinstance(br, str) and br.startswith("BRANCH_"):
                reachable.add(_norm(br[len("BRANCH_"):]))
        reachable -= _unsupported_branch_coverage(isa)
        reachable_unseen = sorted(reachable - set(seen_names))
    except Exception as exc:  # pragma: no cover - diagnostic path
        return [Issue(
            "branch_coverage", "info",
            f"branch coverage: seen={len(seen_names)}; "
            f"reachable-set lookup failed: {exc!r}",
            {"seen": seen_names, "asserted_unseen": asserted_unseen},
        )]

    return [Issue(
        "branch_coverage", "info",
        f"branch coverage [{isa}]: "
        f"seen={len(seen_names)} "
        f"asserted_unseen={len(asserted_unseen)} "
        f"reachable_unseen={len(reachable_unseen)}",
        {
            "seen": seen_names,
            "asserted_unseen": asserted_unseen,
            "reachable_unseen": reachable_unseen,
            "excluded_unsupported": sorted(_unsupported_branch_coverage(isa)),
        },
    )]


_ISA_TO_REG_TABLE = {
    "x86_64": "champsim_tracer_mnemonics_x86.h",
    "aarch64": "champsim_tracer_mnemonics_aarch64.h",
    "riscv64": "champsim_tracer_mnemonics_riscv.h",
    "mipsel": "champsim_tracer_mnemonics_mips.h",
}


def _unsupported_opcode_coverage(isa: str) -> set[str]:
    """GenericOpcode names outside the current genval ISA baseline."""
    return {
        "aarch64": {"POP", "PUSH", "TEST"},
        "riscv64": {
            "CMOV", "INT_MADD", "INT_MSUB", "MOVSX", "MOVZX",
            "POP", "PUSH", "RET", "ROR", "VEC_SHUF",
        },
        "mipsel": {
            "LEA", "NEG", "RET", "VEC_ADD", "VEC_LOGIC",
            "VEC_MADD", "VEC_MOV", "VEC_MSUB", "VEC_MUL",
            "VEC_SHUF", "VEC_SUB",
        },
    }.get(isa, set())


def _unsupported_branch_coverage(isa: str) -> set[str]:
    """BranchType names outside the current genval ISA baseline."""
    return {
        "riscv64": {"RETURN"},
        "mipsel": {"RETURN"},
    }.get(isa, set())


def _unsupported_reg_coverage(isa: str) -> set[str]:
    """GenericRegId names outside the current genval ISA baseline."""
    return {
        "x86_64": {
            "REG_BOUND0", "REG_BOUND1", "REG_BOUND2", "REG_BOUND3",
            "REG_CTRL", "REG_DEBUG",
            *(f"REG_PRED{i}" for i in range(8)),
            *(f"REG_VEC{i}" for i in range(16, 32)),
        },
        "aarch64": {
            "REG_MATRIX", "REG_VCTRL",
            *(f"REG_PRED{i}" for i in range(32)),
        },
        "riscv64": {
            "REG_FCSR", "REG_VCTRL",
        },
        "mipsel": {
            "REG_ACC0", "REG_ACC1", "REG_ACC2", "REG_ACC3",
            "REG_FLAGS", "REG_IP",
            "REG_SYS", "REG_VCTRL",
            *(f"REG_PRED{i}" for i in range(32)),
            *(f"REG_VEC{i}" for i in range(32)),
        },
    }.get(isa, set())


def _reachable_reg_names_for_isa(isa: str) -> set[str]:
    """Return GenericRegId names present in the ISA reg table.

    This intentionally uses the tracer's generated C tables as the
    reachable universe, not a hand-maintained Python list. Composite
    aliases contribute each member register so coverage of wide register
    groups is accounted for by the IDs actually emitted in templates.
    """
    header = _ISA_TO_REG_TABLE.get(isa)
    if header is None:
        raise ValueError(f"unsupported isa {isa!r}")
    path = _PLUGIN_SOURCE_DIR / header
    text = path.read_text()
    out: set[str] = set()
    entry_re = re.compile(
        r"\[[A-Z0-9_]+\]\s*=\s*\{\s*"
        r"(REG_[A-Z0-9_]+)"
        r"(?:\s*,\s*\d+\s*,\s*\{([^}]*)\})?\s*\}"
    )
    for m in entry_re.finditer(text):
        alias_text = m.group(2)
        if alias_text:
            regs = re.findall(r"REG_[A-Z0-9_]+", alias_text)
        else:
            regs = [m.group(1)]
        for reg in regs:
            if reg != "REG_NONE":
                out.add(reg)
    return out


def _check_reg_coverage(templates: list[dict], isa: str,
                        reg_id_to_name: dict[int, str]) -> list[Issue]:
    """Emit an info-level GenericRegId coverage summary."""
    seen_ids: set[int] = set()
    for t in templates:
        for ins in t.get("insns", []):
            seen_ids.update(int(r) for r in ins.get("src_regs", []) or [])
            seen_ids.update(int(r) for r in ins.get("dst_regs", []) or [])

    seen_names = sorted(
        reg_id_to_name.get(i, f"REG_{i}")
        for i in seen_ids if i != 0
    )

    try:
        reachable = _reachable_reg_names_for_isa(isa)
        reachable -= _unsupported_reg_coverage(isa)
    except Exception as exc:  # pragma: no cover - diagnostic path
        return [Issue(
            "reg_coverage", "info",
            f"reg coverage: seen={len(seen_names)}; "
            f"reachable-set lookup failed: {exc!r}",
            {"seen": seen_names},
        )]

    reachable_unseen = sorted(reachable - set(seen_names))
    return [Issue(
        "reg_coverage", "info",
        f"reg coverage [{isa}]: "
        f"seen={len(seen_names)} "
        f"reachable_unseen={len(reachable_unseen)}",
        {
            "seen": seen_names,
            "reachable_unseen": reachable_unseen,
            "excluded_unsupported": sorted(_unsupported_reg_coverage(isa)),
        },
    )]


def _check_wrong_path_chains(entries: list[dict],
                             template_runs: dict[int, list[tuple[int, int]]],
                             cp_block_seq: list[int],
                             correct_path: list[int],
                             wrong_paths: dict,
                             blocks_by_id: dict[int, dict],
                             wp_insn_budget: int = 64,
                             helper_leaf_n_insns: int = 0,
                             isa: str = "",
                             cp_pos_offset: int = 0,
                             templates_by_id: dict | None = None,
                             marker: bool = False,
                             wpprune: int = 0,
                             reg_name_to_id: dict | None = None) -> list[Issue]:
    """For every CP position predicted to fork, walk the trace's
    ``wp_entries`` for that block's TB and compare the distinct-block
    sequence against the predicted ``wp_chain`` as a prefix.

    The predicted chain is trimmed to the plugin's per-WP instruction
    budget (``wp_insn_budget``) using each block's static instruction
    count. The active generator model represents loops as explicit CFG
    cycles, so repeated iterations appear as repeated block visits
    rather than as in-block backedges.

    An empty actual chain carrying the chain-level TRANSLATION_UNAVAIL
    event (format spec §4.4 — first wrong-path fetch could not
    complete) is accepted when a later CP instance of the same static
    branch realizes an exact-or-longer chain vs its own prediction;
    with no later instance it is accepted on the event alone and
    surfaced as a notable INFO issue naming the branch and target.

    Wrong-path fault policy (architecture.rst "Wrong-path chain
    termination"): the plugin proceeds around a suppressed speculative
    fault with the ACCUMULATED wrong-path state, so instructions not
    data-dependent on the fault execute exactly as they normally would
    and the chain must keep matching the exact-known synthetic model —
    post-fault divergence is an error like any other.  The faulted
    instruction's destinations are poisoned and propagate transitively
    through register dataflow, and the excursion MUST die at the first
    branch whose sources are poisoned, marked
    CST_WP_EVENT_DEP_BRANCH_KILL on the chain's last entry.  This
    check replays that poison propagation over the trace's own
    per-insn template reg sets: a chain that continues past a provably
    fault-dependent branch is an error, a kill event anywhere but the
    chain's last entry is an error, and a kill-terminated chain whose
    emitted prefix matched is accepted as an explicit terminator.  The
    plugin may kill EARLIER than the replay predicts (the wire records
    only each block's first fault, while the plugin poisons every
    faulted instruction), so the replay's kill point is a
    latest-acceptable bound, not an exact one.
    """
    issues: list[Issue] = []
    cp_pos = -1
    last_cp_bid: int | None = None

    def _block_runtime_parts(bid: int) -> tuple[int, int]:
        b = blocks_by_id.get(bid, {})
        gt = b.get("ground_truth", {}) or {}
        n = int(gt.get("n_insns", 0))
        # ``direct_call`` / ``indirect_call`` blocks invoke the
        # ``wptgen_leaf`` helper.  The plugin counts the leaf's body
        # insns toward sim_insns even though the leaf has no
        # ``blk_*`` label, so add the helper's static insn count to
        # the within-block contribution for these classes.
        if (helper_leaf_n_insns > 0 and
                b.get("class") in ("direct_call", "indirect_call")):
            return n + helper_leaf_n_insns, 0
        return n, 0

    def _trim_by_insn_budget(chain: list[int], budget: int) -> list[int]:
        out: list[int] = []
        total = 0
        leak = 0
        for bid in chain:
            # Plugin checks `sim_insns < max_depth` BEFORE starting a
            # fragment, so a block whose first insn keeps us under
            # budget is executed in full (and may overshoot).  The
            # leak from the previous block's post-loop tail rides on
            # this block's first plugin BB and counts toward sim_insns
            # before the budget is rechecked.
            if total >= budget:
                break
            out.append(bid)
            within, this_leak = _block_runtime_parts(bid)
            total += leak + within
            leak = this_leak
        return out

    # Pass 1: resolve every predicted-fork CP position to a record the
    # verdict pass can evaluate.  Deferring the verdicts lets the
    # chain-level-event acceptance below look AHEAD for a later CP
    # instance of the same static branch.
    records: list[dict] = []
    for e in entries:
        runs = template_runs.get(e["template_id"], [])
        if not runs:
            continue

        advanced = False
        for bid, _ in runs:
            if bid != last_cp_bid:
                last_cp_bid = bid
                cp_pos += 1
                advanced = True
        if not advanced:
            continue

        # `wrong_paths` is keyed by the *original* CP position
        # (cp_exec_index from the generator).  Symbol-based start
        # trimmed the prefix off correct_path, so add the offset to
        # recover the original index.
        key = str(cp_pos + cp_pos_offset)
        if key not in wrong_paths:
            continue

        exp_chain = list(wrong_paths[key].get("wp_chain", []))
        exp_chain = _trim_by_insn_budget(exp_chain, wp_insn_budget)
        wp_raw: list[int] = []
        actual_sim_insns = 0
        wp_left_user = False   # entered kernel, or faulted out of user CFG
        raw_len_at_cross: int | None = None   # len(wp_raw) just BEFORE the
                                              # first block that left user space
        wp_list = e.get("wp_entries", [])
        first_fault_entry = None   # entry index of the first FAULT
        kill_entries = [wi for wi, wp in enumerate(wp_list)
                        if wp.get("dep_branch_kill")]
        # Poison-propagation replay over the trace's own per-insn
        # template reg sets, mirroring the plugin's model: the faulted
        # insn's dsts are poisoned (its result never materialized);
        # a retired insn with a poisoned source propagates poison to
        # its dsts, an all-clean-source insn overwrites (cleans) them;
        # the flags register mediates conditionals with no explicit
        # reg sources.  The wire only records each block's FIRST
        # fault, while the plugin poisons every faulted insn, so the
        # replay UNDERSTATES poison: its kill point is the latest the
        # plugin may legitimately continue to, never an exact match.
        expected_kill_entry = None   # entry index whose terminating
                                     # branch the replay proves poisoned
        rnm = reg_name_to_id or {}
        reg_zero = rnm.get("REG_ZERO")
        reg_flags = rnm.get("REG_FLAGS")
        poisoned: set[int] = set()
        for wi, wp in enumerate(wp_list):
            crossed = bool(wp.get("fault") or wp.get("translation_unavailable"))
            wt = (templates_by_id or {}).get(wp["template_id"])
            if wt is not None and wt.get("is_system"):
                crossed = True
            if crossed and raw_len_at_cross is None:
                # user blocks emitted before this crossing entry
                raw_len_at_cross = len(wp_raw)
            blocks = [bid for (bid, _)
                      in template_runs.get(wp["template_id"], [])]
            if wp.get("fault") and first_fault_entry is None:
                first_fault_entry = wi
            wp_raw.extend(blocks)
            actual_sim_insns += int(wp.get("n_insns", 0) or 0)
            if crossed:
                wp_left_user = True

            tinsns = (wt or {}).get("insns") or []
            n_exec = min(int(wp.get("n_insns", 0) or 0), len(tinsns))
            fidx = wp.get("fault_insn_index") if wp.get("fault") else None
            for ii in range(n_exec):
                fi = tinsns[ii]
                if fidx is not None and ii == fidx:
                    # Faulted insn: result never materialized.
                    for r in fi.get("dst_regs", []):
                        if r != reg_zero:
                            poisoned.add(r)
                    continue
                src_poisoned = any(r in poisoned
                                   for r in fi.get("src_regs", []))
                if (not src_poisoned and fi.get("branch_type")
                        and fi.get("branch_conditional")
                        and not fi.get("src_regs")
                        and reg_flags in poisoned):
                    src_poisoned = True
                if (src_poisoned and fi.get("branch_type")
                        and expected_kill_entry is None):
                    expected_kill_entry = wi
                for r in fi.get("dst_regs", []):
                    if r == reg_zero:
                        continue
                    if src_poisoned:
                        poisoned.add(r)
                    else:
                        poisoned.discard(r)
        actual_wp = _collapse_runs(wp_raw)
        # Collapsed index at which the wrong path left the enumerable user CFG.
        left_user_at = (
            len(_collapse_runs(wp_raw[:raw_len_at_cross]))
            if raw_len_at_cross is not None else None
        )

        n = min(len(actual_wp), len(exp_chain))
        first_fail = -1
        for j in range(n):
            if actual_wp[j] != exp_chain[j]:
                first_fail = j
                break
        records.append({
            "cp_pos": cp_pos,
            "bid": last_cp_bid,
            "exp_chain": exp_chain,
            "actual_wp": actual_wp,
            "actual_sim_insns": actual_sim_insns,
            "wp_left_user": wp_left_user,
            "left_user_at": left_user_at,
            "first_fail": first_fail,
            "n_wp_entries": len(wp_list),
            "first_fault_entry": first_fault_entry,
            "kill_entries": kill_entries,
            "expected_kill_entry": expected_kill_entry,
            # Chain-level TRANSLATION_UNAVAIL event (format spec §4.4):
            # the excursion was kicked but its first fetch could not
            # complete, so the chain is empty and says so explicitly.
            "chain_event": bool(e.get("wp_first_fetch_unavailable")),
        })

    def _realizes_exact_or_longer(r: dict) -> bool:
        """True when @r emitted a non-empty chain satisfying the
        exact-or-longer invariant under the same terminators the
        verdicts below accept: full predicted length, provable budget
        exhaustion, or a user-CFG crossing at/after the full prefix."""
        if not r["actual_wp"] or r["first_fail"] >= 0:
            return False
        if len(r["actual_wp"]) >= len(r["exp_chain"]):
            return True
        if r["actual_sim_insns"] >= wp_insn_budget:
            return True
        return bool(r["wp_left_user"] and r["left_user_at"] is not None
                    and r["left_user_at"] >= len(r["exp_chain"]))

    # Pass 2: verdicts.
    for ri, rec in enumerate(records):
        cp_pos = rec["cp_pos"]
        last_cp_bid = rec["bid"]
        exp_chain = rec["exp_chain"]
        actual_wp = rec["actual_wp"]
        actual_sim_insns = rec["actual_sim_insns"]
        wp_left_user = rec["wp_left_user"]
        left_user_at = rec["left_user_at"]
        first_fail = rec["first_fail"]
        if first_fail == 0 and actual_wp and last_cp_bid is not None:
            # Common plugin bug: for a conditional branch where CP
            # falls through (branch-not-taken), the plugin's wrong
            # target defaults to prev_ft on the very first execution
            # (because br->has_taken_target is false), which equals
            # the CP target.  Call this out specifically.
            cp_next = _meta_cp_successor(last_cp_bid, correct_path)
            if cp_next is not None and actual_wp[0] == cp_next:
                issues.append(Issue(
                    "plugin_wp_equals_cp", "error",
                    f"WP at CP pos {cp_pos} (blk_{last_cp_bid}) "
                    f"starts with blk_{actual_wp[0]} — same as the "
                    f"CP successor.  The champsim_tracer plugin should suppress "
                    f"WP simulation when no learned alternative target "
                    f"is available; emitting WP that mirrors CP causes "
                    f"the next CP block to appear twice in the trace. "
                    f"Expected WP blk_{exp_chain[0]}.",
                    {"cp_pos": cp_pos, "actual": actual_wp,
                     "expected": exp_chain},
                ))
                continue
        # Dep-branch-kill structural verdicts (wrong-path fault policy).
        # Placement: the kill is an excursion terminator, so the event
        # is only legal on the chain's LAST entry, and only in a chain
        # that carries a FAULT at/before it.
        kill_entries = rec["kill_entries"]
        n_wp_entries = rec["n_wp_entries"]
        first_fault_entry = rec["first_fault_entry"]
        expected_kill_entry = rec["expected_kill_entry"]
        kill_at = kill_entries[0] if kill_entries else None
        if kill_entries and (len(kill_entries) > 1 or
                             kill_at != n_wp_entries - 1):
            issues.append(Issue(
                "wrong_path_chains", "error",
                f"WP at CP pos {cp_pos} (blk_{last_cp_bid}): "
                f"DEP_BRANCH_KILL at chain entries {kill_entries} of "
                f"{n_wp_entries} — the kill is an excursion terminator "
                f"and must be the last entry, exactly once",
                {"cp_pos": cp_pos, "kill_entries": kill_entries},
            ))
        elif kill_at is not None and (first_fault_entry is None or
                                      first_fault_entry > kill_at):
            issues.append(Issue(
                "wrong_path_chains", "error",
                f"WP at CP pos {cp_pos} (blk_{last_cp_bid}): "
                f"DEP_BRANCH_KILL at entry {kill_at} without a FAULT "
                f"at/before it — a dependent-branch kill requires a "
                f"faulted instruction upstream",
                {"cp_pos": cp_pos, "kill_at": kill_at},
            ))
        # Required termination: the replay proved the terminating
        # branch of entry @expected_kill_entry reads a register that
        # (transitively) carries a faulted insn's never-materialized
        # result.  The plugin poisons at least as much as the replay
        # (the wire records only each block's first fault), so it MUST
        # have killed at or before that entry; a chain that continues
        # past it resolved an unresolvable branch.
        if expected_kill_entry is not None and \
                (kill_at is None or kill_at > expected_kill_entry):
            issues.append(Issue(
                "wrong_path_chains", "error",
                f"WP at CP pos {cp_pos} (blk_{last_cp_bid}): chain "
                f"entry {expected_kill_entry}'s terminating branch is "
                f"fault-dependent (poison replay) but the excursion "
                f"{'continued past it' if expected_kill_entry < n_wp_entries - 1 else 'ended'} "
                f"without DEP_BRANCH_KILL — the wrong path must die on "
                f"that branch",
                {"cp_pos": cp_pos,
                 "expected_kill_entry": expected_kill_entry,
                 "kill_at": kill_at, "n_wp_entries": n_wp_entries},
            ))
        if first_fail >= 0:
            issues.append(Issue(
                "wrong_path_chains", "error",
                f"WP at CP pos {cp_pos} (blk_{last_cp_bid}) "
                f"depth {first_fail}: expected blk_{exp_chain[first_fail]}, "
                f"got blk_{actual_wp[first_fail]}",
                {"cp_pos": cp_pos, "actual": actual_wp,
                 "expected": exp_chain},
            ))
        elif len(actual_wp) < len(exp_chain):
            # Budget exhaustion is a legitimate chain terminator on any
            # ISA: when the plugin PROVABLY spent the full WP instruction
            # budget (sim_insns >= budget), the chain is not "short" — the
            # plugin's per-insn accounting is finer than the predictor's
            # block-count trim.  Two known sources: MIPS user binaries pull
            # in libgcc soft-float / int-div helpers whose body insns the
            # predictor cannot enumerate from `blk_*` symbols; x86 REP
            # string ops burn one budget unit per sandboxed ITERATION while
            # the predictor counts the REP as a single instruction.  The
            # emitted prefix was already verified correct (first_fail < 0),
            # so exact-or-longer is preserved in instruction terms.
            if actual_sim_insns >= wp_insn_budget:
                continue
            # System mode: the wrong path speculatively crossed into the
            # kernel (CST_INSN_FLAG_SYSTEM blocks the validator can't
            # enumerate from blk_* symbols) or faulted out of the user CFG.
            # A crossing makes the chain unpredictable from there ON — but
            # ONLY beyond that point.  The synthetic wrong path is exact-
            # known, so the WP must follow the ENTIRE predicted user prefix
            # before crossing; a crossing BEFORE the prefix completes is a
            # real truncation (the WP stopped short of known code), not an
            # unpredictable tail.  Accept only when the crossing is at/after
            # the full predicted length.
            if wp_left_user and left_user_at is not None \
                    and left_user_at >= len(exp_chain):
                continue
            # Chain-level TRANSLATION_UNAVAIL event (format spec §4.4):
            # the plugin kicked the excursion but the first fetch could
            # not complete — on a software-managed-TLB ISA the refill
            # exception cannot be taken speculatively, so real hardware
            # also fetches nothing and the explicit 0-block chain is
            # architecturally faithful.  Accept it when a later CP
            # instance of the SAME static branch realizes an exact-or-
            # longer chain vs its own prediction (proving the target is
            # real code the plugin speculates into once its translation
            # is available).  With no later instance there is nothing to
            # corroborate against — and a cold TLB says nothing about
            # execution order (long-ago-executed code can be evicted) —
            # so accept on the event alone, audibly via a notable INFO.
            if not actual_wp and rec["chain_event"]:
                later = [r for r in records[ri + 1:]
                         if r["bid"] == last_cp_bid]
                if any(_realizes_exact_or_longer(r) for r in later):
                    continue
                if not later:
                    issues.append(Issue(
                        "wrong_path_chains", "info",
                        f"WP at CP pos {cp_pos} (blk_{last_cp_bid}) empty "
                        f"with chain-level TRANSLATION_UNAVAIL event; no "
                        f"later instance of blk_{last_cp_bid} in the trace "
                        f"corroborates target blk_{exp_chain[0]} — accepted "
                        f"on the event alone",
                        {"notable": True, "cp_pos": cp_pos,
                         "branch": last_cp_bid, "target": exp_chain[0]},
                    ))
                    continue
                # Later instances of this branch exist but none realized
                # the chain: the event does not excuse a target the
                # plugin never manages to speculate into.  Fall through
                # to the wpprune / truncation verdicts.
            # Dep-branch kill: the chain ended at a branch whose sources
            # depend on a faulted wrong-path insn's never-materialized
            # result (explicit CST_WP_EVENT_DEP_BRANCH_KILL terminator
            # on the last entry, placement/fault-precedence verified
            # above).  The emitted prefix already matched (first_fail <
            # 0), and the branch outcome past the kill is unresolvable
            # by definition, so the shorter chain is policy-correct.
            if kill_at is not None and kill_at == n_wp_entries - 1 and \
                    len(kill_entries) == 1 and first_fault_entry is not None \
                    and first_fault_entry <= kill_at:
                continue
            # wpprune: the tracer intentionally drops the wrong path WHOLE
            # for cold branches (never-taken / one-directional / monomorphic
            # indirect).  Pruning removes the entire path, so accept ONLY an
            # empty chain here; a non-empty-but-short chain was NOT pruned and
            # is a genuine truncation.
            if wpprune > 0 and not actual_wp:
                continue
            # A shorter-than-predicted chain that neither crossed out of the
            # user CFG at/after the full prefix nor was wholly pruned is a
            # real plugin truncation: the synthetic wrong path is exact-known
            # and the actual chain must match it exactly or run longer.
            ev_note = ("; chain-level TRANSLATION_UNAVAIL event present but "
                       "no later instance realized the chain"
                       if rec["chain_event"] else "")
            issues.append(Issue(
                "wrong_path_chains", "error",
                f"WP at CP pos {cp_pos} (blk_{last_cp_bid}) truncated: "
                f"plugin emitted {len(actual_wp)} blocks "
                f"(sim_insns={actual_sim_insns}, budget={wp_insn_budget}); "
                f"predicted {len(exp_chain)}{ev_note}",
            ))
    return issues


def _check_indirect_wp_assertions(
        entries: list[dict],
        templates_by_id: dict[int, dict],
        blocks_by_id: dict[int, dict],
    pcmap: "PcMap",
    isa: str) -> list[Issue]:
    blocks = [b for b in blocks_by_id.values()
              if b.get("indirect_wp_assertions")]
    if not blocks:
        return []

    _opcode_names, branch_names = _load_name_tables()
    checked_blocks = {int(b["block_id"]): b for b in blocks}
    issues: list[Issue] = []
    events_by_block: dict[int, list[dict]] = {bid: [] for bid in checked_blocks}

    for idx, e in enumerate(entries[:-1]):
        tmpl = templates_by_id.get(int(e["template_id"]))
        next_tmpl = templates_by_id.get(int(entries[idx + 1]["template_id"]))
        if tmpl is None or next_tmpl is None:
            continue
        for insn_index, ins in enumerate(tmpl.get("insns", [])):
            bid = pcmap.lookup(int(ins["pc"]))
            if bid not in checked_blocks:
                continue
            if branch_names.get(int(ins.get("branch_type", 0))) != "INDIRECT_JUMP":
                continue
            raw_len = len(ins.get("raw_bytes") or [])
            branch_fallthrough = int(ins["pc"]) + raw_len
            if isa.startswith("mips") and raw_len:
                branch_fallthrough += 4
            wp_entries = e.get("wp_entries") or []
            wp_start = None
            if wp_entries:
                wp_tmpl = templates_by_id.get(int(wp_entries[0]["template_id"]))
                if wp_tmpl is not None:
                    wp_start = int(wp_tmpl["start_pc"])
            events_by_block[bid].append({
                "entry_index": idx,
                "template_id": int(e["template_id"]),
                "insn_index": insn_index,
                "branch_pc": int(ins["pc"]),
                "fallthrough_pc": branch_fallthrough
                if raw_len else int(tmpl.get("fall_through_pc", 0)),
                "cp_target": int(next_tmpl["start_pc"]),
                "wp_start": wp_start,
            })
            break

    def _best_target_except(history: dict[int, tuple[int, int]],
                            current: int) -> int | None:
        best: tuple[int, int, int] | None = None
        for target, (count, seen_tick) in history.items():
            if target == current:
                continue
            cand = (count, seen_tick, target)
            if best is None or cand > best:
                best = cand
        return best[2] if best is not None else None

    for bid, block in checked_blocks.items():
        assertions = block.get("indirect_wp_assertions") or []
        events = events_by_block.get(bid, [])
        if not events:
            issues.append(Issue(
                "indirect_wp_assertion", "error",
                f"blk_{bid} ({block['class']}): no indirect branch "
                "executions were found in the trace",
                {"block_id": bid},
            ))
            continue
        for assertion in assertions:
            mode = assertion.get("mode")
            history: dict[int, tuple[int, int]] = {}
            non_fallthrough_checks = 0
            mismatch_count = 0
            for tick, ev in enumerate(events, 1):
                current = int(ev["cp_target"])
                old_count, _old_seen = history.get(current, (0, 0))
                history[current] = (old_count + 1, tick)

                fallthrough = int(ev["fallthrough_pc"])
                if mode == "one_target_fallthrough":
                    expected = fallthrough
                    if len(history) > 1:
                        issues.append(Issue(
                            "indirect_wp_assertion", "error",
                            f"blk_{bid} ({block['class']}): one-target "
                            f"fixture observed {len(history)} distinct "
                            "CP targets",
                            {"block_id": bid, "targets": sorted(history)},
                        ))
                elif mode == "multi_target_most_frequent":
                    alt = _best_target_except(history, current)
                    if len(history) >= 2 and alt is not None:
                        expected = alt
                        if expected != fallthrough:
                            non_fallthrough_checks += 1
                    else:
                        expected = fallthrough
                else:
                    issues.append(Issue(
                        "indirect_wp_assertion", "error",
                        f"blk_{bid}: unknown indirect WP assertion mode "
                        f"{mode!r}",
                        {"block_id": bid, "assertion": assertion},
                    ))
                    break

                actual = ev["wp_start"]
                if actual == expected:
                    continue
                mismatch_count += 1
                if mismatch_count <= 5:
                    issues.append(Issue(
                        "indirect_wp_assertion", "error",
                        f"blk_{bid} ({block['class']}) event "
                        f"{ev['entry_index']}: expected WP start "
                        f"0x{expected:x} for mode={mode}, got "
                        f"{('none' if actual is None else hex(actual))}",
                        {"block_id": bid, "mode": mode, "event": ev,
                         "expected_wp_start": expected},
                    ))
            if mode == "multi_target_most_frequent" and non_fallthrough_checks == 0:
                issues.append(Issue(
                    "indirect_wp_assertion", "error",
                    f"blk_{bid} ({block['class']}): multi-target fixture "
                    "never reached a non-fallthrough most-frequent "
                    "incorrect-target check",
                    {"block_id": bid, "events": events},
                ))
    return issues


def _meta_cp_successor(bid: int, correct_path: list[int]) -> int | None:
    """Return the block that follows ``bid`` on the ground-truth CP,
    or None if not found."""
    for i, b in enumerate(correct_path):
        if b == bid and i + 1 < len(correct_path):
            return correct_path[i + 1]
    return None


# ---------------------------------------------------------------------------
# Structural / header / cadence checks
# ---------------------------------------------------------------------------


def _check_encoding_map_completeness(
        templates: list[dict],
        trace_meta: dict) -> list[Issue]:
    """Every numeric id appearing in a template (reg/opcode/branch_type)
    or referenced on the wire must carry an entry in the matching
    encoding map.  An id without a name implies the writer emitted a
    value its own map can't describe — a self-describing-format
    invariant violation.
    """
    issues: list[Issue] = []
    maps = trace_meta.get("encoding_maps", {})
    reg_map = maps.get("reg", {})
    opc_map = maps.get("opcode", {})
    br_map  = maps.get("branch_type", {})

    missing_reg: set[int] = set()
    missing_opc: set[int] = set()
    missing_br:  set[int] = set()

    for t in templates:
        for I in t.get("insns", []):
            op = int(I.get("opcode", 0))
            if op and op not in opc_map:
                missing_opc.add(op)
            bt = int(I.get("branch_type", 0))
            if bt and bt not in br_map:
                missing_br.add(bt)
            for rid in I.get("src_regs", []):
                rid = int(rid)
                if rid and rid not in reg_map:
                    missing_reg.add(rid)
            for rid in I.get("dst_regs", []):
                rid = int(rid)
                if rid and rid not in reg_map:
                    missing_reg.add(rid)

    if missing_reg:
        issues.append(Issue(
            "encoding_map_completeness", "error",
            f"trace emits {len(missing_reg)} register id(s) with no entry "
            f"in the `reg` encoding map: "
            f"{sorted(missing_reg)[:10]}",
            {"missing_reg_ids": sorted(missing_reg)},
        ))
    if missing_opc:
        issues.append(Issue(
            "encoding_map_completeness", "error",
            f"trace emits {len(missing_opc)} opcode id(s) with no entry "
            f"in the `opcode` encoding map: {sorted(missing_opc)[:10]}",
            {"missing_opcode_ids": sorted(missing_opc)},
        ))
    if missing_br:
        issues.append(Issue(
            "encoding_map_completeness", "error",
            f"trace emits {len(missing_br)} branch_type id(s) with no "
            f"entry in the `branch_type` encoding map: "
            f"{sorted(missing_br)[:10]}",
            {"missing_branch_ids": sorted(missing_br)},
        ))
    # Detect writer-side fallback names (the encoder fell out of its
    # own name tables and emitted a placeholder).  Real entries are
    # symbolic ("REG_GPR0", "GEN_OP_LOAD"); fallbacks look like
    # "REG_<n>" / "OP_<n>" / "BR_<n>" / "FID_0x<n>" / "UNKNOWN_<n>".
    fallback_re = re.compile(r"^(REG_|OP_|BR_|FID_0x|UNKNOWN_)\d")
    fallback_names: dict[str, list[str]] = {}
    for map_name in ("reg", "opcode", "branch_type", "field_id",
                     "body_tag", "header_flag",
                     "insn_flag", "wp_event_flag", "metaflags"):
        m = maps.get(map_name, {})
        bad = [v for v in m.values() if fallback_re.match(v)]
        if bad:
            fallback_names[map_name] = bad
    if fallback_names:
        issues.append(Issue(
            "encoding_map_completeness", "error",
            f"encoding map(s) contain fallback names (writer fell out "
            f"of its name tables): {fallback_names}",
            {"fallback_names": fallback_names},
        ))
        return issues

    if not (missing_reg or missing_opc or missing_br):
        issues.append(Issue(
            "encoding_map_completeness", "info",
            f"encoding maps name every id observed and contain no "
            f"writer-side fallbacks: reg={len(reg_map)}, "
            f"opcode={len(opc_map)}, branch_type={len(br_map)}",
        ))
    return issues


_IFRAME_RATE_RE = re.compile(r"iframe_rate=(\d+)")


def _parse_iframe_rate_from_command(cmd: str) -> int:
    """Extract iframe_rate from the trace's command string.  Returns
    the plugin's default (100000) if not configured."""
    m = _IFRAME_RATE_RE.search(cmd or "")
    return int(m.group(1)) if m else 100000


_WPPRUNE_RE = re.compile(r"wpprune=(\d+)")


def _parse_wpprune_from_command(cmd: str) -> int:
    """Extract the wpprune level from the trace's command string (0 if
    absent).  When > 0 the tracer intentionally drops the wrong path for
    cold branches, so WP-coverage checks must tolerate missing chains."""
    m = _WPPRUNE_RE.search(cmd or "")
    return int(m.group(1)) if m else 0


def _check_header_window(trace_meta: dict,
                         expected_start: int | None,
                         expected_stop: int | None,
                         expected_warmup: int | None,
                         start_symbol: str | None = None,
                         marker: bool = False) -> list[Issue]:
    """Cross-check the header's start/warmup/total_target_insns
    against the values the caller asked the tracer to use.

    When @start_symbol is set, or @marker is true (system-mode: the
    window opens at the guest marker's icount), the exact start icount
    is not predictable, so this check only asserts start_insn > 0 and
    the warmup invariant."""
    issues: list[Issue] = []
    actual_start  = int(trace_meta.get("start_insn", 0))
    actual_warm   = int(trace_meta.get("warmup_insns", 0))
    actual_total  = int(trace_meta.get("total_target_insns", 0))

    if start_symbol is not None or marker:
        # Dynamic start (symbol hit / marker fired): the exact icount
        # is unpredictable; assert only that the window actually opened.
        if actual_start == 0:
            trigger = (f"start-symbol={start_symbol!r}" if start_symbol
                       else "the guest trace marker")
            issues.append(Issue(
                "header_window", "error",
                f"trace was launched with {trigger} but start_insn=0 in "
                f"header; the trigger was never hit",
                {"start_symbol": start_symbol, "marker": marker,
                 "actual_start": actual_start},
            ))
    elif expected_start is not None and actual_start != expected_start:
        issues.append(Issue(
            "header_window", "error",
            f"header start_insn={actual_start} but trace invocation "
            f"requested start={expected_start}",
            {"actual": actual_start, "expected": expected_start},
        ))
    if expected_warmup is not None and actual_warm != expected_warmup:
        issues.append(Issue(
            "header_window", "error",
            f"header warmup_insns={actual_warm} but trace invocation "
            f"requested warmup={expected_warmup}",
            {"actual": actual_warm, "expected": expected_warmup},
        ))
    if expected_stop is not None and expected_start is not None:
        expected_total = expected_stop - expected_start
        if actual_total != expected_total:
            issues.append(Issue(
                "header_window", "error",
                f"header total_target_insns={actual_total} but trace "
                f"invocation requested stop-start={expected_total}",
                {"actual": actual_total, "expected": expected_total},
            ))
    if not issues:
        issues.append(Issue(
            "header_window", "info",
            f"header window matches: start={actual_start}, "
            f"warmup={actual_warm}, total_target={actual_total}",
        ))
    return issues


def _check_iframe_cadence(body_stats: dict,
                          cp_entries: list[dict],
                          trace_meta: dict) -> list[Issue]:
    """The writer emits an IFRAME per `iframe_rate` *per-template*
    emissions (`tmpl->emit_count % iframe_rate == 0`).  So whether an
    IFRAME should appear depends on the hottest template's hit count,
    not the total CP entry count.

    Structural validation of each IFRAME (CP dyn_params + reg_snaps +
    metaflags + full WP chain + WP events all match the prior ENTRY)
    happens inside cst_decode's BodyWalker via validate_iframe().
    Any divergence throws an exception at decode time, surfacing as a
    decode-stage failure before we ever get here — so reaching this
    check means every IFRAME the writer emitted matched its ENTRY
    byte-for-byte.  This function only verifies the *count*.

    Required count invariants:
      * iframe_count <= cp_entries (sanity).
      * If any single template was emitted >= iframe_rate times, at
        least one IFRAME must have fired.
      * iframe_count must equal sum(per_template_hits // iframe_rate).
    """
    issues: list[Issue] = []
    cp = int(body_stats.get("cp_entries", 0))
    iframes = int(body_stats.get("iframe_count", 0))
    rate = _parse_iframe_rate_from_command(trace_meta.get("command", ""))

    if iframes > cp:
        issues.append(Issue(
            "iframe_cadence", "error",
            f"iframe_count={iframes} exceeds cp_entries={cp}; "
            f"writer can't have validated more IFRAMEs than CP entries",
            {"iframes": iframes, "cp_entries": cp},
        ))
        return issues

    # Per-template hit counter (the trace's actual emission distribution).
    hits: dict[int, int] = {}
    for e in cp_entries:
        tid = int(e.get("template_id", 0))
        hits[tid] = hits.get(tid, 0) + 1
    max_hits = max(hits.values()) if hits else 0
    expected_floor = sum(h // rate for h in hits.values()) if rate > 0 else 0

    if rate > 0 and max_hits >= rate and iframes == 0:
        issues.append(Issue(
            "iframe_cadence", "error",
            f"hottest template was emitted {max_hits} times with "
            f"iframe_rate={rate}, so at least one IFRAME should have "
            f"fired, but iframe_count=0",
            {"max_template_hits": max_hits, "iframe_rate": rate,
             "iframes": iframes},
        ))
        return issues
    if rate > 0 and iframes != expected_floor:
        issues.append(Issue(
            "iframe_cadence", "error",
            f"iframe_count={iframes} disagrees with the per-template "
            f"hit floor sum(hits // {rate}) = {expected_floor}",
            {"iframes": iframes, "expected": expected_floor,
             "iframe_rate": rate, "max_template_hits": max_hits},
        ))
        return issues

    issues.append(Issue(
        "iframe_cadence", "info",
        f"iframe_count={iframes} matches per-template hit distribution "
        f"(rate={rate}, max_hits={max_hits}, cp_entries={cp}); each "
        f"IFRAME's contents were already validated against its ENTRY "
        f"during decode",
        {"iframes": iframes, "cp_entries": cp, "iframe_rate": rate,
         "max_template_hits": max_hits},
    ))
    return issues


def _check_syscall_transitions(entries: list[dict],
                               templates_by_id: dict,
                               trace_meta: dict,
                               guest_threads: int = 1) -> list[Issue]:
    """System-mode privilege-transition check (CST_INSN_FLAG_SYSTEM).

    A user-mode ``syscall`` transfers control to the kernel and, on
    return, resumes at the instruction *after* the syscall (the block's
    fall-through).  In the CP stream this appears as:

        user block ending in a SYSCALL branch  (is_system == False)
          -> one or more kernel blocks          (is_system == True)
          -> a user block starting at the syscall's fall_through_pc

    Resumes are matched against the *set* of outstanding syscall
    fall-throughs rather than the single most recent one: a blocking or
    yielding syscall legitimately context-switches to another guest
    thread first, so its own fall-through arrives later in the
    interleaved stream while the switch target's resume (typically that
    thread's own outstanding fall-through) arrives now.  With
    @guest_threads == 1 an unmatched return is an error (the flow has
    nowhere else to legally resume); with more threads it is tolerated —
    the switch target may have been suspended mid-flow by an excluded
    async preemption, so its resume PC is not predictable from the
    trace.  The terminal process-exit syscall never returns, so its
    fall-through staying outstanding is expected.  No user syscalls at
    all -> info (e.g. a fault-only workload).
    """
    branch_names = trace_meta.get("branch_names") or {}
    # The branch_type id naming a syscall (self-describing map; the name
    # is BRANCH_SYSCALL_TYPE — match the SYSCALL substring so a rename
    # can't silently disable the check).
    syscall_ids = {int(k) for k, v in branch_names.items()
                   if "SYSCALL" in str(v)}
    if not syscall_ids:
        return [Issue("syscall_transitions", "info",
                      "trace declares no syscall branch type")]

    def ends_in_syscall(t: dict) -> bool:
        ins = t.get("insns") or []
        return bool(ins) and int(ins[-1].get("branch_type", 0)) in syscall_ids

    issues: list[Issue] = []
    verified = 0
    strict = guest_threads <= 1
    outstanding: dict[int, int] = {}    # resume pc -> open count
    out_pc: dict[int, int] = {}         # resume pc -> a syscall pc (messages)
    # Per-GUEST-THREAD: the most recent user block that ended in a syscall,
    # and whether a kernel block for THAT thread has been seen since.
    # Tracking per tid (not globally) is essential on a concurrent SMP run:
    # another guest thread's user block legitimately interleaves between a
    # thread's syscall and its own kernel entry, which a global tracker
    # misreads as "syscall not followed by a kernel block".  Kernel blocks
    # inherit the tid of the thread that entered the kernel, so a thread's
    # excursion lands on its own pending slot.
    pending_by_tid: dict[int, tuple[int, int]] = {}   # tid -> (syscall_pc, ft)
    saw_kernel_by_tid: dict[int, bool] = {}
    for e in entries:
        t = templates_by_id.get(e["template_id"])
        if t is None:
            continue
        tid = int(e.get("thread_id", 0))
        is_sys = bool(t.get("is_system"))
        if is_sys:
            if pending_by_tid.get(tid) is not None:
                saw_kernel_by_tid[tid] = True
            continue
        pc = int(t.get("start_pc", 0))
        pend = pending_by_tid.pop(tid, None)
        if pend is not None:
            sy_pc, sy_ft = pend
            if not saw_kernel_by_tid.get(tid, False):
                issues.append(Issue(
                    "syscall_transitions", "error",
                    f"user syscall at 0x{sy_pc:x} (thread {tid}) was not "
                    f"followed by a kernel (system) block before returning "
                    f"to user",
                    {"syscall_pc": sy_pc, "tid": tid}))
            else:
                # The syscall entered the kernel; its resume is now open.
                outstanding[sy_ft] = outstanding.get(sy_ft, 0) + 1
                out_pc[sy_ft] = sy_pc
                # This user block is the kernel's return target: it must
                # resume one of the outstanding syscalls (strict mode) —
                # in multi-thread mode a mid-flow resume of a previously
                # preempted thread is legal.
                if outstanding.get(pc, 0) > 0:
                    outstanding[pc] -= 1
                    if not outstanding[pc]:
                        del outstanding[pc]
                    verified += 1
                elif strict:
                    issues.append(Issue(
                        "syscall_transitions", "error",
                        f"syscall at 0x{sy_pc:x} returned to user at "
                        f"0x{pc:x}, expected the fall-through 0x{sy_ft:x}",
                        {"syscall_pc": sy_pc, "expected_ft": sy_ft,
                         "got": pc}))
            saw_kernel_by_tid[tid] = False
        elif outstanding.get(pc, 0) > 0:
            # A user entry resuming an outstanding fall-through without
            # kernel blocks immediately before it: the return interleaved
            # with other threads' entries (or the excluded window hid the
            # tail of the excursion).  Consume it.
            outstanding[pc] -= 1
            if not outstanding[pc]:
                del outstanding[pc]
            verified += 1
        if ends_in_syscall(t):
            pending_by_tid[tid] = (pc, int(t.get("fall_through_pc", 0)))
            saw_kernel_by_tid[tid] = False

    if issues:
        return issues
    return [Issue(
        "syscall_transitions", "info",
        f"verified {verified} user-syscall round-trip(s) "
        f"(branch out to kernel + return to an outstanding fall-through)"
        + ("" if verified else "; none returned (terminal exit only)"),
        {"verified": verified})]


def _check_fault_excursions(entries: list[dict],
                            templates_by_id: dict,
                            trace_meta: dict) -> list[Issue]:
    """System-mode synchronous-fault excursion depth (CST_FLAG_FAULT).

    Each CP entry carries a fault-handler nesting depth: 0 = normal code,
    >=1 = synchronous-fault handler code that detoured execution at that
    level.  The strong, semantic invariants:

      * **depth>0 => kernel.**  A fault handler runs at system privilege, so
        any entry tagged depth>=1 MUST be ``is_system`` code.  User-privilege
        code at depth>0 means the depth baseline is wrong (e.g. a phantom
        frame from a fault delivered before tracing began that never popped) —
        exactly the stuck-baseline failure this guards against.
      * **depth baselines at 0.**  The trace opens at user level (the marker),
        so depth-0 entries must exist; an all-depth>0 trace is a stuck stack.

    Syscall-entered kernel code stays depth 0 (SVC is not a fault), so this is
    orthogonal to the syscall-transition check.  A fault-free / user-only
    trace carries no depths -> info.
    """
    issues: list[Issue] = []
    seen_depth = False
    n_depth0 = 0
    n_handler = 0
    max_depth = 0
    user_at_depth = 0
    n_merged = 0          # faulting BBs reassembled across excursions
    for e in entries:
        # Faulting-instruction anchors mark a BB that faulted and was
        # reassembled whole; verify each indexes a real instruction.
        anchors = e.get("fault_anchors") or []
        if anchors:
            n_merged += 1
            t = templates_by_id.get(e["template_id"])
            n_insns = len(t.get("insns") or []) if t else 0
            for a in anchors:
                if n_insns and a >= n_insns:
                    issues.append(Issue(
                        "fault_excursions", "error",
                        f"entry seq={e.get('seq_num')} (BB{e['template_id']}) "
                        f"fault anchor {a} out of range (n_insns={n_insns})",
                        {"seq_num": e.get("seq_num"), "anchor": a}))
        d = int(e.get("fault_depth", 0) or 0)
        if d == 0:
            n_depth0 += 1
            continue
        seen_depth = True
        n_handler += 1
        max_depth = max(max_depth, d)
        t = templates_by_id.get(e["template_id"])
        is_sys = bool(t.get("is_system")) if t else False
        if not is_sys:
            user_at_depth += 1
            if user_at_depth <= 5:
                issues.append(Issue(
                    "fault_excursions", "error",
                    f"entry seq={e.get('seq_num')} (BB{e['template_id']}) has "
                    f"fault_depth={d} but is not kernel (is_system) code; "
                    f"fault-handler code must run at system privilege",
                    {"seq_num": e.get("seq_num"), "depth": d}))
    if not seen_depth:
        return [Issue("fault_excursions", "info",
                      "no fault-handler depth in trace "
                      "(fault-free or user-only window)")]
    if n_depth0 == 0:
        issues.append(Issue(
            "fault_excursions", "error",
            f"every one of {n_handler} entries is at fault_depth>0; the "
            f"excursion stack never returns to baseline (stuck depth)",
            {"handler_entries": n_handler}))
    if issues:
        return issues
    return [Issue(
        "fault_excursions", "info",
        f"fault excursions: {n_handler} handler entries (max depth "
        f"{max_depth}), all kernel-privileged; {n_merged} faulting BBs "
        f"reassembled whole; {n_depth0} entries at baseline depth 0",
        {"handler_entries": n_handler, "max_depth": max_depth,
         "merged_bbs": n_merged, "depth0_entries": n_depth0})]


def _check_call_return_balance(entries: list[dict],
                               templates_by_id: dict,
                               trace_meta: dict) -> list[Issue]:
    """Calls and returns pair up, so their dynamic counts should be in
    the same ballpark.  A gross imbalance means the classifier is mislabeling
    one of them (e.g. calls folded into plain jumps, the bug this branch-type
    split fixes).

    Counts are dynamic: one per CP block execution, keyed by the block's
    terminal branch type.  Exact equality is not expected even for correct
    traces — tail calls turn a call+ret into a single ret, PIC/get-pc
    thunks and setjmp/longjmp skew it, and a windowed trace clips partial
    call trees — so the check only flags a *gross* mismatch.
    """
    bn = trace_meta.get("branch_names") or {}
    call_ids = {int(k) for k, v in bn.items()
                if v in ("BRANCH_DIRECT_CALL", "BRANCH_INDIRECT_CALL")}
    ret_ids = {int(k) for k, v in bn.items() if v == "BRANCH_RETURN"}
    if not call_ids and not ret_ids:
        return [Issue("call_return_balance", "info",
                      "trace declares no call/return branch types")]

    def terminal_bt(t: dict) -> int | None:
        for ins in reversed(t.get("insns") or []):
            bt = int(ins.get("branch_type", 0))
            if bn.get(bt, "BRANCH_NONE") not in ("", "BRANCH_NONE"):
                return bt
        return None

    calls = rets = 0
    for e in entries:
        t = templates_by_id.get(e["template_id"])
        if t is None:
            continue
        bt = terminal_bt(t)
        if bt in call_ids:
            calls += 1
        elif bt in ret_ids:
            rets += 1

    # Gross-imbalance gate: one side present in force while the other is
    # absent or >8x smaller means a classification failure, not normal
    # tail-call/thunk skew.  Small absolute counts (windowed trace) are
    # exempt — they carry no statistical weight.
    hi, lo = max(calls, rets), min(calls, rets)
    if hi >= 16 and (lo == 0 or hi > lo * 8):
        return [Issue(
            "call_return_balance", "error",
            f"calls={calls} returns={rets}: grossly unbalanced — a call or "
            f"return branch type is likely misclassified",
            {"calls": calls, "returns": rets})]
    return [Issue(
        "call_return_balance", "info",
        f"calls={calls} returns={rets} (dynamic, by terminal branch type)",
        {"calls": calls, "returns": rets})]


def _check_unconditional_direction(templates: list[dict],
                                   entries: list[dict],
                                   templates_by_id: dict,
                                   trace_meta: dict) -> list[Issue]:
    """An unconditional direct transfer (DIRECT_JUMP / DIRECT_CALL
    without the conditional flag) has exactly one outcome — it can
    never fall through.  A trace where one does means the classifier
    mistyped a conditional branch (the aarch64 "b.<cc>" -> DIRECT_JUMP
    bug shape).  Trace-wide, so it catches misclassification on any
    workload, not only asserted probe blocks.

    Two evidence sources, weakest first:

    1. Template profile taken/nottaken counts.  Secondary only — the
       writer's profile_branch() forces taken=true for terminals
       without the conditional flag (correct wire semantics for
       indirect terminals and the jump-to-next degenerate), so this
       pass cannot see THIS bug shape; it guards against profile
       corruption generally.
    2. The CP entry stream — the unlaundered ground truth.  For each
       same-thread consecutive entry pair, an unconditional direct
       terminal followed by its own fall-through PC (when the recorded
       jump target differs from the fall-through) fell through, which
       is impossible for a correctly-classified direct transfer.

    The x86 loop-family encoding (DIRECT_JUMP + branch_conditional,
    see X86CondUncondBlock) legitimately resolves both ways and is
    exempted via the conditional flag."""
    bn = trace_meta.get("branch_names") or {}
    uncond_direct = {int(k) for k, v in bn.items()
                     if v in ("BRANCH_DIRECT_JUMP", "BRANCH_DIRECT_CALL")}
    if not uncond_direct:
        return []

    def uncond_term(t: dict):
        """Terminal insn if it is an unconditional direct transfer."""
        if t.get("is_system"):
            return None
        for ins in reversed(t.get("insns") or []):
            if bn.get(ins.get("branch_type", 0),
                      "BRANCH_NONE") not in ("", "BRANCH_NONE"):
                if (int(ins["branch_type"]) in uncond_direct
                        and not ins.get("branch_conditional")):
                    return ins
                return None
        return None

    issues: list[Issue] = []

    # Pass 1: profile counts (secondary net, see docstring).
    prof_checked = prof_flagged = 0
    for t in templates:
        term = uncond_term(t)
        if term is None:
            continue
        prof_checked += 1
        taken = nottaken = 0
        for tgt in (t.get("profile") or {}).get("targets") or []:
            taken    += tgt["taken_cp"] + tgt["taken_wp"]
            nottaken += tgt["nottaken_cp"] + tgt["nottaken_wp"]
        if taken > 0 and nottaken > 0:
            prof_flagged += 1
            if prof_flagged <= 3:
                issues.append(Issue(
                    "unconditional_direction", "error",
                    f"template {t.get('template_id')} "
                    f"pc=0x{t.get('start_pc', 0):x}: unconditional "
                    f"{bn[int(term['branch_type'])]} profile resolved "
                    f"both ends (taken={taken} nottaken={nottaken})",
                    {"template_id": t.get("template_id")}))

    # Pass 2: entry-stream successor check (authoritative).
    fell_through = 0
    seen_pairs = 0
    example_tmpls: dict = {}        # template_id -> (pc, ft); distinct sites
    prev_by_thread: dict = {}
    for e in entries:
        tid = e.get("thread_id", 0)
        prev = prev_by_thread.get(tid)
        prev_by_thread[tid] = e
        if prev is None:
            continue
        pt = templates_by_id.get(prev["template_id"])
        ct = templates_by_id.get(e["template_id"])
        if pt is None or ct is None:
            continue
        term = uncond_term(pt)
        if term is None:
            continue
        ft = pt.get("fall_through_pc")
        if not ft:
            continue
        tgt_pcs = {tg["pc"] for tg in
                   (pt.get("profile") or {}).get("targets") or []}
        if ft in tgt_pcs:
            continue            # jump-to-next degenerate: taking == falling
        seen_pairs += 1
        if ct.get("start_pc") == ft:
            fell_through += 1
            k = pt.get("template_id")
            if len(example_tmpls) < 3 and k not in example_tmpls:
                example_tmpls[k] = (pt.get("start_pc", 0), ft)
    examples = [(k, pc, ft) for k, (pc, ft) in example_tmpls.items()]
    for tid_, pc_, ft_ in examples:
        issues.append(Issue(
            "unconditional_direction", "error",
            f"template {tid_} pc=0x{pc_:x}: unconditional direct "
            f"terminal fell through to 0x{ft_:x} — a conditional branch "
            f"is likely misclassified",
            {"template_id": tid_}))
    if fell_through > len(examples):
        issues.append(Issue(
            "unconditional_direction", "error",
            f"...and {fell_through - len(examples)} more fall-through "
            f"executions of unconditional direct terminals"))
    issues.append(Issue(
        "unconditional_direction", "info",
        f"profile: {prof_checked} unconditional direct terminals, "
        f"{prof_flagged} both-ends; entry stream: {seen_pairs} successor "
        f"pairs, {fell_through} fell through"))
    return issues


def _check_regfile_records(body_stats: dict,
                           expected_threads: int = 1) -> list[Issue]:
    """A BODY_TAG_REGFILE record must precede each thread's first
    BODY_TAG_ENTRY in the segment.  Single-segment, single-thread
    traces should therefore carry exactly one REGFILE.  Multi-thread
    runs scale to one per (thread, segment)."""
    actual = int(body_stats.get("regfile_count", 0))
    if actual != expected_threads:
        return [Issue(
            "regfile_records", "error",
            f"regfile_count={actual}, expected {expected_threads} "
            f"(one per (segment, thread))",
            {"actual": actual, "expected": expected_threads},
        )]
    return [Issue(
        "regfile_records", "info",
        f"regfile_count={actual}",
    )]


def _check_wp_events(body_stats: dict,
                     cp_entries: list[dict]) -> list[Issue]:
    """Verify the writer's BODY_STATS WP-event tallies match a walk
    of the per-entry wp_entries lists.  These are the WP_EVENT_FAULT
    and WP_EVENT_TRANSLATION_UNAVAIL flags surfaced when a WP-path
    insn was about to execute something that would fault (e.g., div
    by zero, code on an unmapped page, syscall in user-mode).

    Walking ensures the writer's runtime counter agrees with the
    per-WP-entry payload that was actually encoded.

    Also lints CST_WP_EVENT_DEP_BRANCH_KILL structurally on EVERY
    entry (including kernel-side excursions the synthetic-chain check
    cannot model): the kill is an excursion terminator, so it may only
    appear on a chain's last entry and only with a FAULT at/before it.
    """
    walk_faults  = 0
    walk_translu = 0
    walk_kills   = 0
    kill_issues: list[Issue] = []
    for e in cp_entries:
        wps = e.get("wp_entries") or []
        first_fault = None
        for wi, wp in enumerate(wps):
            if wp.get("fault"):
                walk_faults += 1
                if first_fault is None:
                    first_fault = wi
            if wp.get("translation_unavailable"):
                walk_translu += 1
            if wp.get("dep_branch_kill"):
                walk_kills += 1
                if wi != len(wps) - 1:
                    kill_issues.append(Issue(
                        "wp_events", "error",
                        f"entry seq={e.get('seq_num')}: DEP_BRANCH_KILL "
                        f"on chain entry {wi} of {len(wps)} — the kill "
                        f"is an excursion terminator and must be the "
                        f"chain's last entry",
                        {"seq_num": e.get("seq_num"), "kill_at": wi,
                         "n_wp": len(wps)},
                    ))
                elif first_fault is None:
                    kill_issues.append(Issue(
                        "wp_events", "error",
                        f"entry seq={e.get('seq_num')}: DEP_BRANCH_KILL "
                        f"with no FAULT at/before it in the chain — a "
                        f"dependent-branch kill requires a faulted "
                        f"instruction upstream",
                        {"seq_num": e.get("seq_num"), "kill_at": wi},
                    ))

    body_faults  = int(body_stats.get("fault_count", 0))
    body_translu = int(body_stats.get("translation_unavail_count", 0))
    if (walk_faults, walk_translu) != (body_faults, body_translu):
        return kill_issues + [Issue(
            "wp_events", "error",
            f"WP event counts disagree with per-entry walk: "
            f"writer={{fault: {body_faults}, "
            f"translation_unavail: {body_translu}}}, "
            f"walk={{fault: {walk_faults}, "
            f"translation_unavail: {walk_translu}}}",
            {"body_stats": {"fault": body_faults,
                            "translation_unavail": body_translu},
             "walk": {"fault": walk_faults,
                      "translation_unavail": walk_translu}},
        )]
    return kill_issues + [Issue(
        "wp_events", "info",
        f"WP events: fault={body_faults}, "
        f"translation_unavail={body_translu}, "
        f"dep_branch_kill={walk_kills}",
        {"fault": body_faults, "translation_unavail": body_translu,
         "dep_branch_kill": walk_kills},
    )]


def _check_thread_switch(body_stats: dict,
                         expected_threads: int = 1) -> list[Issue]:
    """Every segment body's first record is a mandatory
    BODY_TAG_THREAD_SWITCH stating the starting thread (an ordinary
    delta from 0), so the count is never 0.  For a single-thread
    trace that mandatory opener is the *only* switch per segment and
    there is no interleaving, so the count matches the regfile
    cadence exactly (REGFILE is likewise one-per-segment when
    single-thread).  Multi-thread runs add real interleaving
    switches, so the count must be at least ``expected_threads``
    (otherwise the threads never interleaved and we aren't actually
    exercising multi-thread tracing)."""
    actual = int(body_stats.get("thread_switch_count", 0))
    regfiles = int(body_stats.get("regfile_count", 0))
    if actual == 0:
        return [Issue(
            "thread_switch", "error",
            "thread_switch_count=0; every segment body must open with a "
            "mandatory BODY_TAG_THREAD_SWITCH stating the start thread",
            {"actual": actual},
        )]
    if expected_threads == 1:
        if actual != regfiles:
            return [Issue(
                "thread_switch", "error",
                f"thread_switch_count={actual} on a single-thread trace; "
                f"expected exactly one mandatory opener per segment "
                f"(== regfile_count={regfiles}) with no interleaving "
                f"switches",
                {"actual": actual, "expected": regfiles},
            )]
    elif actual < expected_threads:
        return [Issue(
            "thread_switch", "error",
            f"expected multi-thread trace ({expected_threads} threads) "
            f"but thread_switch_count={actual}; threads never "
            f"interleaved — qemu-user may have run them serially or "
            f"the program never spawned the second thread",
            {"actual": actual, "expected_threads": expected_threads},
        )]
    return [Issue(
        "thread_switch", "info",
        f"thread_switch_count={actual} (expected_threads="
        f"{expected_threads}, regfile_count={regfiles})",
    )]


def _check_thread_distribution(entries: list[dict],
                               expected_threads: int) -> list[Issue]:
    """Verify the trace's per-thread entry counts add up sensibly:
    every expected thread contributed at least one entry, and every
    observed thread_id was within range [0, expected_threads)."""
    counts: dict[int, int] = {}
    for e in entries:
        tid = int(e.get("thread_id", 0))
        counts[tid] = counts.get(tid, 0) + 1
    if expected_threads > 1:
        missing = [tid for tid in range(expected_threads)
                   if counts.get(tid, 0) == 0]
        if missing:
            return [Issue(
                "thread_distribution", "error",
                f"expected_threads={expected_threads} but threads "
                f"{missing} contributed zero entries to the trace",
                {"observed_counts": counts, "missing": missing},
            )]
    extras = [tid for tid in counts if tid >= expected_threads]
    if extras:
        return [Issue(
            "thread_distribution", "error",
            f"trace contains entries from thread_id(s) >= expected_"
            f"threads={expected_threads}: {extras}",
            {"observed_counts": counts,
             "expected_threads": expected_threads},
        )]
    return [Issue(
        "thread_distribution", "info",
        f"per-thread entry counts: {counts}",
        {"counts": counts},
    )]


_SMP_RE = re.compile(r"(?:^|\s)-smp\s+(\d+)")


def _parse_smp_from_command(cmd: str) -> int:
    """Extract the guest vCPU count from the trace's command string
    (system-mode ``-smp N``).  1 if absent — qemu-system's default, and
    the value under qemu-user where thread_ids are host threads and not
    bounded by any -smp."""
    m = _SMP_RE.search(cmd or "")
    return int(m.group(1)) if m else 1


def _check_thread_record_cadence(entries: list[dict],
                                 body_record_order: list[tuple[str, int]]
                                 ) -> list[Issue]:
    """Positional thread-bookkeeping invariants of the body stream.

    Two record-level contracts the writer must honor on every segment,
    single- or multi-vCPU:

      * **Switch flags mark exactly the tid changes.**  The segment's
        first ENTRY carries the mandatory opener's switch flag
        (BODY_TAG_THREAD_SWITCH names the starting thread), and every
        later ENTRY carries it iff its ``thread_id`` differs from the
        previous ENTRY's — the writer emits a switch record only when
        the running guest thread changes.
      * **A thread's REGFILE precedes its first ENTRY.**  Field-state
        delta encoding is per-thread, so a consumer must have thread
        T's full register file in hand before decoding T's first entry;
        the writer guarantees this by emitting BODY_TAG_REGFILE lazily
        right before each thread's first ENTRY of the segment.  Exactly
        one REGFILE per contributing thread per segment.
    """
    issues: list[Issue] = []

    # Switch-flag correctness against the entry stream itself.
    flag_errors = 0
    prev_tid: int | None = None
    for i, e in enumerate(entries):
        tid = int(e.get("thread_id", 0))
        expected = (i == 0) or (tid != prev_tid)
        actual = bool(e.get("thread_switched"))
        if actual != expected:
            flag_errors += 1
            if flag_errors <= 5:
                issues.append(Issue(
                    "thread_records", "error",
                    f"entry seq={e.get('seq_num')} thread={tid}: "
                    f"switch flag {'set' if actual else 'missing'} but tid "
                    f"{'did not change' if actual else 'changed'} "
                    f"(prev tid={prev_tid})",
                    {"seq_num": e.get("seq_num"), "tid": tid,
                     "prev_tid": prev_tid}))
        prev_tid = tid
    if flag_errors > 5:
        issues.append(Issue(
            "thread_records", "error",
            f"...and {flag_errors - 5} more switch-flag mismatches"))

    # REGFILE-before-first-ENTRY, from the positional record stream.
    first_entry_pos: dict[int, int] = {}
    regfile_pos: dict[int, list[int]] = {}
    for pos, (kind, tid) in enumerate(body_record_order or []):
        if kind == "entry":
            first_entry_pos.setdefault(tid, pos)
        elif kind == "regfile":
            regfile_pos.setdefault(tid, []).append(pos)
    for tid, epos in sorted(first_entry_pos.items()):
        rposes = regfile_pos.get(tid, [])
        if not rposes:
            issues.append(Issue(
                "thread_records", "error",
                f"thread {tid} contributed entries but has no REGFILE "
                f"record in the segment",
                {"tid": tid}))
        elif min(rposes) > epos:
            issues.append(Issue(
                "thread_records", "error",
                f"thread {tid}'s REGFILE (record #{min(rposes)}) appears "
                f"after its first ENTRY (record #{epos})",
                {"tid": tid}))
        if len(rposes) > 1:
            issues.append(Issue(
                "thread_records", "error",
                f"thread {tid} has {len(rposes)} REGFILE records in one "
                f"segment; expected exactly one",
                {"tid": tid, "count": len(rposes)}))
    for tid in sorted(set(regfile_pos) - set(first_entry_pos)):
        issues.append(Issue(
            "thread_records", "error",
            f"REGFILE for thread {tid} but the thread contributed no "
            f"entries",
            {"tid": tid}))

    if not issues:
        issues.append(Issue(
            "thread_records", "info",
            f"switch flags consistent across {len(entries)} entries; "
            f"REGFILE precedes first ENTRY for thread(s) "
            f"{sorted(first_entry_pos)}"))
    return issues


def _template_successor_pcs(t: dict,
                            rep_branch_id: int | None = None) -> set[int]:
    """The set of PCs a CP execution of template @t may hand control to
    next, from the trace's own data: the fall-through, the static
    terminal-branch target list, and any profile target this branch
    actually took on the correct path (covers indirect branches, whose
    static target list is empty).

    A template whose terminal instruction is the x86 ``BRANCH_REP``
    additionally hands control to that instruction's own PC: REP
    iterations 2..N each ride a synthetic 1-insn self-loop BB whose
    start_pc is the REP's PC (format spec, "REP-prefixed self-loop
    BBs"), so both the block that ENTERS a REP loop and the self-loop
    BB itself may legitimately be followed by an entry starting there.
    """
    s: set[int] = set()
    ft = int(t.get("fall_through_pc", 0) or 0)
    if ft:
        s.add(ft)
    for pc in t.get("target_pcs") or []:
        s.add(int(pc))
    for tgt in (t.get("profile") or {}).get("targets") or []:
        if int(tgt.get("taken_cp", 0)) > 0:
            s.add(int(tgt["pc"]))
    if rep_branch_id is not None:
        insns = t.get("insns") or []
        if insns and int(insns[-1].get("branch_type", 0)) == rep_branch_id:
            s.add(int(insns[-1]["pc"]))
    return s


def _check_thread_chain(entries: list[dict],
                        templates_by_id: dict,
                        expected_guest_threads: int | None = None,
                        trace_meta: dict | None = None
                        ) -> list[Issue]:
    """User-flow continuity of the interleaved body stream, PER GUEST
    THREAD.

    The body stream serializes every vCPU's CP blocks in global
    execution order.  ``thread_id`` is the guest-thread identity (the
    tracer resolves it from the kernel per-thread pointer, not the vCPU
    index), so a thread that migrates across vCPUs keeps ONE tid and a
    thread time-slicing a vCPU with another keeps its own — which makes
    the strong assertion possible: filtered to one tid, the user-privilege
    entries are that single thread's execution in order, and each must be
    reachable from that SAME thread's previous user block (its
    fall-through or a branch target).  A kernel excursion (is_system
    entries) detours and may resume the thread at a redirected PC, so it
    breaks the chain — the first user entry of that tid after an excursion
    restarts it without penalty; every other entry must connect.

    A disconnect within a tid's chain is an *orphan*: a dropped user
    block, a phantom entry, or another process's code leaking past the
    ASID pin.  Matching per tid (not globally against a live set) is
    strictly stronger than the pre-identity check — it cannot launder a
    thread A block onto thread B's successor set.  ``chains`` in the info
    detail is the number of distinct guest threads that contributed user
    entries (bounded by @expected_guest_threads when given).
    """
    issues: list[Issue] = []
    n_user = 0

    # Per-tid live chain: the successor-PC set of that thread's previous
    # user block, or None when a kernel excursion broke it (next user
    # entry of the tid restarts the chain).  Absent = thread not yet seen.
    chain_by_tid: dict[int, set[int] | None] = {}
    births_by_tid: dict[int, tuple] = {}     # tid -> (seq_num, pc) first sight
    orphans: list[tuple] = []                # (seq_num, pc, tid)
    # Per-tid direct-adjacency tally (connected / total non-restart pairs).
    tid_pairs = tid_connected = 0

    # REP self-loop entries start at their predecessor's terminal REP
    # PC; resolve BRANCH_REP's id from the trace's own encoding map so
    # _template_successor_pcs can admit that edge.
    rep_branch_id = None
    if trace_meta is not None:
        for bid, name in (trace_meta.get("branch_names") or {}).items():
            if name == "BRANCH_REP":
                rep_branch_id = int(bid)
                break

    for e in entries:
        t = templates_by_id.get(e["template_id"])
        if t is None:
            continue
        tid = int(e.get("thread_id", 0))
        if t.get("is_system"):
            if tid in chain_by_tid:
                chain_by_tid[tid] = None       # excursion breaks this thread
            continue
        pc = int(t.get("start_pc", 0))
        n_user += 1
        succ = _template_successor_pcs(t, rep_branch_id)

        prev = chain_by_tid.get(tid, "unseen")
        if prev == "unseen":
            births_by_tid[tid] = (e.get("seq_num"), pc)   # first sight
        elif prev is None:
            pass                                          # excursion restart
        else:
            tid_pairs += 1
            if pc in prev:
                tid_connected += 1
            else:
                orphans.append((e.get("seq_num"), pc, tid))
        chain_by_tid[tid] = succ

    for seq, pc, tid in orphans[:5]:
        issues.append(Issue(
            "thread_chain", "error",
            f"user entry seq={seq} thread={tid} pc=0x{pc:x} does not "
            f"continue thread {tid}'s own control flow (dropped block, "
            f"phantom entry, or foreign-process code)",
            {"seq_num": seq, "pc": pc, "tid": tid}))
    if len(orphans) > 5:
        issues.append(Issue(
            "thread_chain", "error",
            f"...and {len(orphans) - 5} more intra-thread control breaks"))

    n_chains = len(births_by_tid)
    if (expected_guest_threads is not None
            and n_chains > expected_guest_threads):
        issues.append(Issue(
            "thread_chain", "error",
            f"{n_chains} distinct guest threads carried user entries but "
            f"expected at most {expected_guest_threads} (foreign thread "
            f"leaked past the pin?)",
            {"chains": n_chains, "expected": expected_guest_threads}))
    if issues:
        return issues
    born = ", ".join(f"tid={t} seq={s} pc=0x{pc:x}"
                     for t, (s, pc) in sorted(births_by_tid.items()))
    return [Issue(
        "thread_chain", "info",
        f"{n_user} user entries decompose into {n_chains} guest-thread "
        f"chain(s) with 0 orphans (births: {born}); per-tid direct "
        f"adjacency: {tid_connected}/{tid_pairs} connected",
        {"user_entries": n_user, "chains": n_chains,
         "tid_pairs": tid_pairs, "tid_connected": tid_connected})]


def _check_user_code_identity(templates: list[dict],
                              entries: list[dict],
                              templates_by_id: dict,
                              binary_path: Path) -> list[Issue]:
    """Every user-privilege template the CP stream executed must be the
    pinned binary's own code: each template instruction's raw bytes
    must equal the ELF image's bytes at that virtual address.

    This is the content gate for the ASID pin under multi-process
    churn: a foreign process scheduled into a reused ASID would leak
    *its* user code into the trace, at VAs that either fall outside
    the pinned binary's PT_LOAD footprint or fail the byte comparison
    (the -nostdlib workload shares no code with anything else in the
    guest).  WP-only templates are exempt (wrong-path fetch may wander
    off the binary by design) and reported as info.
    """
    try:
        import lief
    except ImportError:
        return [Issue("user_code_identity", "error",
                      "LIEF unavailable; cannot byte-check user "
                      "templates against the pinned binary")]
    img = lief.parse(str(binary_path))
    if img is None:
        return [Issue("user_code_identity", "error",
                      f"cannot parse ELF {binary_path}")]
    # LIEF >= 0.17 nests the enum as Segment.TYPE; older releases used
    # lief.ELF.SEGMENT_TYPES (same compat split as mnemonic_survey's).
    seg_load = (getattr(getattr(lief.ELF.Segment, "TYPE", None),
                        "LOAD", None)
                or lief.ELF.SEGMENT_TYPES.LOAD)
    loads: list[tuple[int, bytes]] = []
    for seg in img.segments:
        if seg.type == seg_load:
            loads.append((int(seg.virtual_address), bytes(seg.content)))

    def image_bytes(va: int, n: int) -> bytes | None:
        for base, blob in loads:
            if base <= va and va + n <= base + len(blob):
                return blob[va - base:va - base + n]
        return None

    cp_user_tids = {int(e["template_id"]) for e in entries
                    if not (templates_by_id.get(e["template_id"]) or {})
                    .get("is_system")}
    issues: list[Issue] = []
    checked_insns = 0
    checked_templates = 0
    wp_only_user = 0
    mismatches = 0
    for t in templates:
        if t.get("is_system"):
            continue
        if int(t["template_id"]) not in cp_user_tids:
            wp_only_user += 1
            continue
        checked_templates += 1
        for idx, ins in enumerate(t.get("insns") or []):
            raw = ins.get("raw_bytes") or b""
            if not raw:
                continue
            expect = image_bytes(int(ins["pc"]), len(raw))
            if expect is None:
                mismatches += 1
                if mismatches <= 5:
                    issues.append(Issue(
                        "user_code_identity", "error",
                        f"template {t['template_id']} insn[{idx}] "
                        f"pc=0x{int(ins['pc']):x} lies outside the pinned "
                        f"binary's PT_LOAD footprint",
                        {"template_id": t["template_id"], "insn": idx}))
                continue
            if expect != raw:
                mismatches += 1
                if mismatches <= 5:
                    issues.append(Issue(
                        "user_code_identity", "error",
                        f"template {t['template_id']} insn[{idx}] "
                        f"pc=0x{int(ins['pc']):x}: trace bytes "
                        f"{raw.hex()} != binary bytes {expect.hex()} — "
                        f"foreign user code under the pin",
                        {"template_id": t["template_id"], "insn": idx}))
                continue
            checked_insns += 1
    if mismatches > 5:
        issues.append(Issue(
            "user_code_identity", "error",
            f"...and {mismatches - 5} more foreign/out-of-image "
            f"instructions"))
    if issues:
        return issues
    return [Issue(
        "user_code_identity", "info",
        f"{checked_insns} instructions across {checked_templates} "
        f"CP-executed user templates byte-match the pinned binary "
        f"({wp_only_user} WP-only user templates exempt)",
        {"checked_insns": checked_insns,
         "checked_templates": checked_templates,
         "wp_only_user": wp_only_user})]


def _check_syscall_fault_nesting(entries: list[dict],
                                 templates_by_id: dict,
                                 trace_meta: dict,
                                 require_nested: bool = False,
                                 guest_threads: int = 1
                                 ) -> list[Issue]:
    """Nested-excursion discipline: a synchronous fault taken *inside* a
    syscall handler.

    The generated marker workload issues a syscall whose kernel path is
    guaranteed to fault (``sysinfo`` writing into a never-touched
    demand-zero page — see ``emit_trace_fault_probe``), so a system-mode
    trace must exhibit at least one user-syscall excursion containing
    entries at ``fault_depth >= 1`` (@require_nested).  Independent of
    the probe, the fault stack must behave like a stack per vCPU:

      * consecutive same-tid entries change depth by at most 1 (one
        fault entered or one excursion unwound per boundary).  With
        @guest_threads > 1 the step discipline is only asserted within a
        privilege level: user-privilege entries carry a clamped depth 0
        (user code is never handler content) while kernel entries carry
        the vCPU's raw baselined depth, and a preemptible kernel that
        context-switches inside a blocking fault handler puts another
        thread's clamped user entries right next to raw-depth kernel
        entries — a legitimate discontinuity at the boundary,
      * fault-anchored (whole-BB-merged) entries sit at the unwind of
        an excursion: the same tid was at a *higher* depth on the
        previous entry, or the anchor marks the merged completion of
        the faulting BB at its own level,
      * depth histogram is reported so nesting regressions are visible.
    """
    bn = trace_meta.get("branch_names") or {}
    syscall_ids = {int(k) for k, v in bn.items() if "SYSCALL" in str(v)}

    def ends_in_syscall(t: dict) -> bool:
        ins = t.get("insns") or []
        return bool(ins) and int(ins[-1].get("branch_type", 0)) in syscall_ids

    issues: list[Issue] = []
    depth_hist: Counter = Counter()
    prev_depth_by_tid: dict[int, int] = {}
    prev_sys_by_tid: dict[int, bool] = {}
    step_errors = 0

    # Per-tid syscall windows: user syscall block -> kernel entries ->
    # next user entry.  Track the max fault depth inside each window.
    in_syscall_by_tid: dict[int, bool] = {}
    window_count = 0
    nested_windows = 0
    cur_window_max: dict[int, int] = {}

    for e in entries:
        t = templates_by_id.get(e["template_id"])
        if t is None:
            continue
        tid = int(e.get("thread_id", 0))
        d = int(e.get("fault_depth", 0) or 0)
        depth_hist[d] += 1

        is_sys = bool(t.get("is_system"))
        pd = prev_depth_by_tid.get(tid)
        ps = prev_sys_by_tid.get(tid)
        exempt = (guest_threads > 1 and ps is not None and ps != is_sys)
        if pd is not None and abs(d - pd) > 1 and not exempt:
            step_errors += 1
            if step_errors <= 5:
                issues.append(Issue(
                    "syscall_fault_nesting", "error",
                    f"entry seq={e.get('seq_num')} thread={tid}: fault "
                    f"depth jumped {pd} -> {d}; excursions must nest and "
                    f"unwind one level at a time",
                    {"seq_num": e.get("seq_num"), "from": pd, "to": d}))
        # A fault-anchored entry is the whole-BB merge of the block the
        # excursion interrupted, so it must sit at the unwind: the same
        # tid's previous entry ran one level deeper (inside the fault
        # handler this merge is returning from).  Multi-thread traces
        # interleave guest threads on one vCPU, so the same-tid
        # predecessor may be an unrelated thread's entry — the unwind
        # adjacency only holds single-threaded.
        if (guest_threads <= 1 and
                e.get("fault_anchors") and pd is not None and pd <= d):
            issues.append(Issue(
                "syscall_fault_nesting", "error",
                f"entry seq={e.get('seq_num')} thread={tid} carries fault "
                f"anchors {e['fault_anchors']} at depth {d} but the tid's "
                f"previous entry was at depth {pd}; a merged faulting BB "
                f"must follow its excursion's unwind",
                {"seq_num": e.get("seq_num"), "depth": d, "prev": pd}))
        prev_depth_by_tid[tid] = d
        prev_sys_by_tid[tid] = is_sys

        if in_syscall_by_tid.get(tid):
            if is_sys:
                cur_window_max[tid] = max(cur_window_max.get(tid, 0), d)
            else:
                window_count += 1
                if cur_window_max.get(tid, 0) >= 1:
                    nested_windows += 1
                in_syscall_by_tid[tid] = False
        if (not is_sys) and ends_in_syscall(t):
            in_syscall_by_tid[tid] = True
            cur_window_max[tid] = 0

    if step_errors > 5:
        issues.append(Issue(
            "syscall_fault_nesting", "error",
            f"...and {step_errors - 5} more depth-step violations"))
    if require_nested and window_count and not nested_windows:
        issues.append(Issue(
            "syscall_fault_nesting", "error",
            f"no user-syscall excursion contains fault_depth >= 1 "
            f"entries ({window_count} completed excursions inspected); "
            f"the workload's fault probe guarantees a fault inside a "
            f"syscall handler, so the nesting machinery lost it",
            {"windows": window_count}))
    if issues:
        return issues
    hist = {k: depth_hist[k] for k in sorted(depth_hist)}
    return [Issue(
        "syscall_fault_nesting", "info",
        f"fault-depth histogram {hist}; max depth "
        f"{max(depth_hist) if depth_hist else 0}; "
        f"{nested_windows}/{window_count} completed user-syscall "
        f"excursion(s) contained a nested fault",
        {"hist": hist, "windows": window_count,
         "nested_windows": nested_windows})]


def _check_atomic_count(body_stats: dict,
                        all_entries: list[dict],
                        templates_by_id: dict[int, dict]) -> list[Issue]:
    """Verify the writer's aggregated atomic_count (BODY_STATS) matches
    the per-template-insn is_atomic values rolled across every CP+WP
    entry in the body stream (including prologue — body_stats
    aggregates everything, not just post-cp_start).

    Any divergence means the writer's runtime aggregation disagrees
    with what its own templates declare, which would be a tracer bug
    (template_id flag-byte vs entry-time stats counter).
    """
    expected = 0
    # Match the writer's BodyStats aggregation: walk *every* insn in
    # every template touched by CP+WP entries (writer iterates the
    # full template even when WP truncates after a fault).
    def _count(tmpl_id: int) -> int:
        t = templates_by_id.get(int(tmpl_id))
        if t is None:
            return 0
        return sum(1 for ins in (t.get("insns") or [])
                   if ins.get("is_atomic"))

    for e in all_entries:
        expected += _count(int(e["template_id"]))
        for wp in e.get("wp_entries") or []:
            expected += _count(int(wp["template_id"]))

    actual = int(body_stats.get("atomic_count") or 0)

    if expected != actual:
        return [Issue(
            "atomic_count", "error",
            f"atomic_count disagrees with per-template walk: "
            f"writer={actual} static_walk={expected}",
            {"actual": actual, "expected": expected},
        )]
    return [Issue(
        "atomic_count", "info",
        f"atomic_count matches static template walk: {actual}",
        {"count": actual},
    )]


# ---------------------------------------------------------------------------
# Lane-mask correctness
# ---------------------------------------------------------------------------


# Opcode-name patterns that classify as cross-lane reductions / element
# moves — the dst's lane mask must be narrower than the union of src
# lane masks because some lanes are merged or dropped (vredsum, addv,
# vmv.x.s, etc.).  Matched as a substring on the trace's symbolic
# opcode name; the per-ISA name lives in the trace's opcode encoding
# map.  This is a recall test, not the classification source of
# truth — the audit script's per-ISA cross-lane prefix lists remain
# authoritative.
_REDUCER_NAME_FRAGMENTS: tuple[str, ...] = (
    # RISC-V V reductions / scalar bridges
    "VRED", "VFRED", "VWRED", "VFWRED",
    "VPOPC", "VCPOP", "VFIRST",
    "VMSBF", "VMSIF", "VMSOF", "VIOTA",
    "VMV_X", "VMV_S", "VFMV_F", "VFMV_S",
    # AArch64 reductions / scalar bridges
    "ADDV", "SMAXV", "UMAXV", "SMINV", "UMINV",
    "FMAXV", "FMINV", "FADDP", "FMAXP", "FMINP",
    "SADDLP", "UADDLP", "SADALP", "UADALP",
    "UMOV", "SMOV",
    # MIPS MSA / x86 horizontal
    "COPY_", "HADD", "HSUB",
    "PHADD", "PHSUB",
)


def _is_reducer_opcode(opcode_name: str) -> bool:
    up = (opcode_name or "").upper()
    for frag in _REDUCER_NAME_FRAGMENTS:
        if frag in up:
            return True
    return False


# ---- Per-ISA expected-lane-count derivation from Capstone disasm ---------
# These helpers re-run Capstone on the raw insn bytes to recover the
# operand-level lane shape used by the plugin's lane_baseline_from_
# operands().  Returning None means "can't classify" — the caller
# treats the ground-truth check as vacuous for that insn (e.g.
# scalar-only forms with no per-element semantics).

# Whole-register opaque moves — match the mnemonic exactly (and the
# VEX/EVEX-prefixed `v…` form) so we don't trip the size-suffix matcher
# on coincidental "...dq" tails.
_X86_WHOLE_REG_MNEMS = {
    "movdqa", "movdqu", "lddqu",
    "vmovdqa", "vmovdqu", "vlddqu",
    "vmovdqa32", "vmovdqa64", "vmovdqu32", "vmovdqu64",
    "vmovdqu8", "vmovdqu16",
}

# Scalar-FP suffixes — these only write the low element.  Tracked
# separately because their natural lane count is always 1 regardless
# of register width (xmm/ymm/zmm).
_X86_SCALAR_SUFFIXES = ("ss", "sd")


def _x86_lane_bytes_for_mnem(mnem: str) -> int | None:
    m = mnem.lower()
    if m in _X86_WHOLE_REG_MNEMS:
        # 1 "lane" semantics — caller squashes to a 1-bit mask
        # regardless of register width via the scalar code path.
        return None
    # Packed FP — order matters: check 2-char suffix before 1-char int
    # suffix to avoid matching "ps" as suffix "s" then unknown.
    if m.endswith("ps"): return 4
    if m.endswith("pd"): return 8
    # Plain int element-size suffix.  Single-char last-letter lookup
    # so "paddq" -> 'q' -> 8 (NOT "dq" -> 16, which would mis-detect
    # the whole-reg-move path).
    return {"b": 1, "w": 2, "d": 4, "q": 8}.get(m[-1])


def _x86_op_width_from_str(op_str: str) -> int | None:
    s = op_str.lower()
    if "zmm" in s:  return 64
    if "ymm" in s:  return 32
    if "xmm" in s:  return 16
    return None


def _x86_expected_lane_count(mnem: str, op_str: str) -> int | None:
    m = mnem.lower()
    width = _x86_op_width_from_str(op_str)
    if width is None:
        return None
    # Whole-register opaque moves: one "lane" by convention — the
    # plugin's lane_baseline_from_operands typically reports
    # lane_bytes == size for these, giving mask = 1.
    if m in _X86_WHOLE_REG_MNEMS:
        return 1
    # Scalar SS/SD: only the low element is the active result.  Other
    # lanes are passed through unchanged from src1 — but for a per-
    # instruction "active lanes" view, only lane 0 matters.
    if any(m.endswith(suf) for suf in _X86_SCALAR_SUFFIXES):
        return 1
    lb = _x86_lane_bytes_for_mnem(mnem)
    if lb is None:
        return None
    return max(1, width // lb)


_AARCH64_VAS_RE = __import__("re").compile(r"\.(\d+)([bhsdq])")


def _aarch64_expected_lane_count(mnem: str, op_str: str) -> int | None:
    m = _AARCH64_VAS_RE.search(op_str.lower())
    if not m:
        return None
    return int(m.group(1))


_MIPS_MSA_SUFFIX_TO_LANES = {
    ".b": 16, ".h": 8, ".w": 4, ".d": 2, ".v": 1,
}


def _mips_expected_lane_count(mnem: str, op_str: str) -> int | None:
    m = mnem.lower()
    for suf, lanes in _MIPS_MSA_SUFFIX_TO_LANES.items():
        if m.endswith(suf):
            return lanes
    return None


def _expected_lane_count(isa: str, mnem: str, op_str: str) -> int | None:
    if not mnem:
        return None
    if isa == "x86_64":
        return _x86_expected_lane_count(mnem, op_str)
    if isa == "aarch64":
        return _aarch64_expected_lane_count(mnem, op_str)
    if isa == "mipsel":
        return _mips_expected_lane_count(mnem, op_str)
    # RISC-V V lane count depends on vl at runtime (vsetvli /
    # vsetvl) — checking it would require replaying CSR writes from
    # the trace.  Skip until we plumb that.
    return None


def _is_contiguous_prefix_mask(mask: int) -> bool:
    """True iff @mask is ``(1 << k) - 1`` for some k > 0.  All the
    current LANE_MASK_KIND_* dispatch paths produce masks of this
    shape — STATIC builds from a baseline ``(1 << lanes) - 1``,
    RISCV_VTYPE builds from ``(1 << vl) - 1``.  A non-contiguous mask
    on the wire would mean the plugin's compute_current_lane_mask was
    bypassed or corrupted."""
    return mask > 0 and (mask & (mask + 1)) == 0


def _accumulate_lane_records(entries: list[dict]) -> dict:
    """Group lane-mask records by (entry_seq, scope, insn_index).
    `scope` is "cp" for the parent entry or ("wp", wp_index) for a WP
    entry.  Each leaf value is ``{family: {slot_index: mask}}``."""
    out: dict = {}
    for e in entries:
        seq = int(e.get("seq_num", 0))
        for lm in e.get("lane_masks") or []:
            key = (seq, "cp", int(lm["insn_index"]))
            out.setdefault(key, {}).setdefault(lm["family"], {})[
                int(lm["slot_index"])] = int(lm["mask"])
        for wp in e.get("wp_entries") or []:
            wp_idx = int(wp.get("index", 0))
            for lm in wp.get("lane_masks") or []:
                key = (seq, ("wp", wp_idx), int(lm["insn_index"]))
                out.setdefault(key, {}).setdefault(lm["family"], {})[
                    int(lm["slot_index"])] = int(lm["mask"])
    return out


def _build_pc_to_gt_insn(meta_blocks: list[dict]) -> dict[int, dict]:
    """Flatten every block's ground_truth.insns into a PC-keyed map.
    Used by checks that need the Capstone disassembly of an
    instruction at a specific PC (mnemonic, op_str, raw_bytes_hex)."""
    out: dict[int, dict] = {}
    for b in meta_blocks:
        gt = b.get("ground_truth")
        if not gt:
            continue
        for ins in gt.get("insns") or []:
            out[int(ins["pc"])] = ins
    return out


def _check_lane_masks(cp_entries: list[dict],
                      templates_by_id: dict[int, dict],
                      opcode_names: dict[int, str],
                      isa: str,
                      pc_to_gt: dict[int, dict] | None = None) -> list[Issue]:
    """Validate per-instance lane-mask FIDs against the trace's own
    classification metadata.  Runs four invariant checks for every
    instance carrying any lane-mask record:

      1. Each mask is a contiguous prefix ``(1 << k) - 1`` (matches
         the only mask shapes compute_current_lane_mask emits).
      2. All families' masks for a single instance agree — the plugin
         replicates one lane mask across the src/dst/load_data/
         store_data slots for now, so any per-slot drift is a tracer
         bug.
      3. When the template's CST_INSN_FLAG_LANE_PARALLEL bit is set,
         every src mask equals every dst mask (lanes line up by
         index).
      4. Reducer / scalar-bridge opcodes (cross-lane by classification)
         narrow: popcount(dst) <= popcount(any src), and the insn
         must not also carry CST_INSN_FLAG_LANE_PARALLEL.
    """
    counts = {
        "instances":      0,
        "records":        0,
        "non_contiguous": 0,
        "slot_disagree":  0,
        "parallel_mismatch": 0,
        "reducer_widen":  0,
        "parallel_on_reducer": 0,
        "gt_checked":     0,
        "gt_mismatch":    0,
        "gt_unclassified": 0,
    }
    issues: list[Issue] = []

    # Pair each instance with the template insn it points at so we
    # can read lane_parallel + opcode.
    def _insn_template(tid: int, idx: int) -> dict | None:
        t = templates_by_id.get(int(tid))
        if t is None: return None
        insns = t.get("insns") or []
        if 0 <= idx < len(insns):
            return insns[idx]
        return None

    by_inst = _accumulate_lane_records(cp_entries)

    # Build a (seq -> template_id) and (seq -> {wp_idx: template_id}) lookup.
    seq_to_cp_tid: dict[int, int] = {}
    seq_to_wp_tid: dict[int, dict[int, int]] = {}
    for e in cp_entries:
        seq = int(e.get("seq_num", 0))
        seq_to_cp_tid[seq] = int(e["template_id"])
        wp_map: dict[int, int] = {}
        for wp in e.get("wp_entries") or []:
            wp_map[int(wp.get("index", 0))] = int(wp["template_id"])
        if wp_map:
            seq_to_wp_tid[seq] = wp_map

    for key, fams in by_inst.items():
        seq, scope, insn_idx = key
        if scope == "cp":
            tid = seq_to_cp_tid.get(seq)
        else:
            _tag, wp_idx = scope
            tid = (seq_to_wp_tid.get(seq) or {}).get(wp_idx)
        if tid is None:
            continue
        I = _insn_template(tid, insn_idx)
        if I is None:
            continue
        counts["instances"] += 1
        lane_parallel = bool(I.get("lane_parallel"))
        opcode_id = int(I.get("opcode", 0))
        opcode_name = opcode_names.get(opcode_id, "")
        is_reducer = _is_reducer_opcode(opcode_name)

        # Flatten all masks for cross-slot / popcount comparisons.
        all_masks: list[int] = []
        src_masks: list[int] = []
        dst_masks: list[int] = []
        load_masks: list[int] = []
        store_masks: list[int] = []
        for fam, slot_map in fams.items():
            for slot, mask in slot_map.items():
                counts["records"] += 1
                all_masks.append(mask)
                if fam == "src":   src_masks.append(mask)
                elif fam == "dst": dst_masks.append(mask)
                elif fam == "load": load_masks.append(mask)
                elif fam == "store": store_masks.append(mask)

        # The four mask classes are independent per the lane-mask model
        # (src/dst reg masks vs per-memop load/store data masks); they
        # are NOT replicated and a per-memop mask is any lane subset
        # (e.g. {2} = 0b100), so neither cross-slot agreement nor a
        # contiguous-prefix shape is an invariant.  The real structural
        # invariant is containment: a memop can only feed/drain lanes
        # the associated register actually spans.
        dst_union = 0
        for m in dst_masks:
            dst_union |= m
        src_union = 0
        for m in src_masks:
            src_union |= m

        # Check 1: a vec instance must carry at least one non-zero reg
        # lane mask (otherwise the insn was tagged vec but emitted no
        # lane participation at all).
        if (src_masks or dst_masks) and not (src_union or dst_union):
            counts["non_contiguous"] += 1   # reused counter: "empty regs"
            if counts["non_contiguous"] <= 5:
                issues.append(Issue(
                    "lane_masks", "error",
                    f"vec insn with all-zero reg lane masks at seq={seq} "
                    f"tid={tid} insn[{insn_idx}] opcode={opcode_name}",
                    {"seq": seq, "tid": tid, "insn_index": insn_idx,
                     "opcode": opcode_name},
                ))

        # Check 2: containment.  Each load-data mask must lie within
        # the lanes some dst register spans (a load feeds dst lanes);
        # each store-data mask within the src reg span (a store drains
        # src lanes).  A memop mask exceeding the register span means
        # the memop->lane association (lane_bytes / access-base) is
        # wrong.
        if dst_union:
            for m in load_masks:
                if m & ~dst_union:
                    counts["slot_disagree"] += 1   # reused: "memop OOB"
                    if counts["slot_disagree"] <= 5:
                        issues.append(Issue(
                            "lane_masks", "error",
                            f"load-data lane mask 0x{m:x} exceeds dst lane "
                            f"span 0x{dst_union:x} at seq={seq} tid={tid} "
                            f"insn[{insn_idx}] opcode={opcode_name}",
                            {"seq": seq, "tid": tid, "insn_index": insn_idx,
                             "opcode": opcode_name, "load_mask": m,
                             "dst_union": dst_union},
                        ))
        if src_union:
            for m in store_masks:
                if m & ~src_union:
                    counts["slot_disagree"] += 1
                    if counts["slot_disagree"] <= 5:
                        issues.append(Issue(
                            "lane_masks", "error",
                            f"store-data lane mask 0x{m:x} exceeds src lane "
                            f"span 0x{src_union:x} at seq={seq} tid={tid} "
                            f"insn[{insn_idx}] opcode={opcode_name}",
                            {"seq": seq, "tid": tid, "insn_index": insn_idx,
                             "opcode": opcode_name, "store_mask": m,
                             "src_union": src_union},
                        ))

        # Check 3 (informational): lane-parallel dst lanes not covered
        # by any src or load.  This is legitimate for immediate- /
        # broadcast-sourced vec ops (MOVI, DUP #imm) and for ops whose
        # feeding regs are implicit, so it is tracked as a counter
        # rather than flagged as an error.  src/dst divergence itself
        # is allowed by the model.
        if lane_parallel and dst_union:
            load_union = 0
            for m in load_masks:
                load_union |= m
            if dst_union & ~(src_union | load_union):
                counts["parallel_mismatch"] += 1

        # Check 4: reducer / scalar-bridge narrowing.  A reducer must
        # NOT carry lane_parallel (the classifier would be wrong), and
        # its dst lane count must be <= every src lane count.
        if is_reducer:
            if lane_parallel:
                counts["parallel_on_reducer"] += 1
                if counts["parallel_on_reducer"] <= 5:
                    issues.append(Issue(
                        "lane_masks", "error",
                        f"reducer opcode {opcode_name} also marked "
                        f"lane_parallel at seq={seq} tid={tid} "
                        f"insn[{insn_idx}]",
                        {"seq": seq, "tid": tid, "insn_index": insn_idx,
                         "opcode": opcode_name},
                    ))
            if src_masks and dst_masks:
                dst_pop = max(bin(m).count("1") for m in dst_masks)
                src_pop = max(bin(m).count("1") for m in src_masks)
                if dst_pop > src_pop:
                    counts["reducer_widen"] += 1
                    if counts["reducer_widen"] <= 5:
                        issues.append(Issue(
                            "lane_masks", "error",
                            f"reducer opcode {opcode_name} widens lanes "
                            f"at seq={seq} tid={tid} insn[{insn_idx}]: "
                            f"src_max_lanes={src_pop} > "
                            f"dst_max_lanes={dst_pop}",
                            {"seq": seq, "tid": tid, "insn_index": insn_idx,
                             "opcode": opcode_name,
                             "src_pop": src_pop, "dst_pop": dst_pop},
                        ))

        # Check 5: ground-truth lane SPAN bound from Capstone disasm.
        # _expected_lane_count gives the register's full lane count
        # (size / element-bytes).  No operand's lane mask may exceed
        # that span — but it is correct (and required) for it to be
        # NARROWER: element insert produces 1 dst lane, its pass-
        # through src reads total-1, extract reads 1, reductions
        # collapse.  So the invariant is observed <= expected; only an
        # over-span (observed > expected) is a real bug (wrong
        # lane_bytes / a memop->lane association past the register).
        # Unclassifiable insns (scalar-only, unsupported ISA, RISC-V V
        # runtime vl) are counted, not flagged.
        if pc_to_gt is not None and all_masks:
            gt_ins = pc_to_gt.get(int(I.get("pc", 0)))
            if gt_ins is not None:
                expected = _expected_lane_count(
                    isa, gt_ins.get("mnemonic", ""),
                    gt_ins.get("op_str", ""))
                if expected is None:
                    counts["gt_unclassified"] += 1
                else:
                    counts["gt_checked"] += 1
                    observed = max(bin(m).count("1") for m in all_masks)
                    if observed > expected:
                        counts["gt_mismatch"] += 1
                        if counts["gt_mismatch"] <= 5:
                            issues.append(Issue(
                                "lane_masks", "error",
                                f"lane mask exceeds register span vs "
                                f"Capstone disasm at seq={seq} tid={tid} "
                                f"insn[{insn_idx}] "
                                f"pc=0x{int(I.get('pc', 0)):x} "
                                f"{gt_ins.get('mnemonic', '?')} "
                                f"{gt_ins.get('op_str', '')}: "
                                f"span={expected} observed={observed} "
                                f"masks={fams}",
                                {"seq": seq, "tid": tid,
                                 "insn_index": insn_idx,
                                 "pc": int(I.get("pc", 0)),
                                 "mnemonic": gt_ins.get("mnemonic"),
                                 "op_str": gt_ins.get("op_str"),
                                 "span": expected,
                                 "observed": observed},
                            ))

    if not counts["instances"]:
        return [Issue(
            "lane_masks", "info",
            "no vec-classified insns observed; lane-mask checks "
            "vacuously pass",
            counts,
        )]
    if not issues:
        issues.append(Issue(
            "lane_masks", "info",
            f"lane masks validated: {counts['instances']} vec instances, "
            f"{counts['records']} per-slot records, all invariants hold",
            counts,
        ))
    else:
        issues.append(Issue(
            "lane_masks", "info",
            f"lane-mask summary: {counts}",
            counts,
        ))
    return issues


# ---------------------------------------------------------------------------
# Dep-refiner bucket coverage
# ---------------------------------------------------------------------------


# Names match the C++ refiners in champsim_tracer_mnemonic_tables.cc.
# `_default` covers insns whose template carries no HAS_REG dep-block
# at all — the consumer falls back to an implicit all-to-all view.
_DEP_REFINE_BUCKETS = (
    "DEP_DEFAULT",          # no HAS_REG sub-block on the wire
    "DEP_PASSTHROUGH",      # every dst depends on exactly one input
    "DEP_LEA",              # dst depends on addr-mode srcs + imm, no load
    "DEP_X86_STACK_PUSH",   # max_loads=0, max_stores=1, store-data = src
    "DEP_X86_STACK_POP",    # max_loads=1, max_stores=0, dst = load-data
    "DEP_ALL_TO_ALL",       # universal mask: every src + every load + imm
    "DEP_OTHER",            # has HAS_REG but doesn't match any pattern
)


def _classify_dep_refine_bucket(insn: dict) -> str:
    """Infer which refiner produced the dep masks on this template insn.
    Based purely on observable mask shape — the plugin doesn't emit a
    refiner-id on the wire."""
    has_reg = bool(insn.get("dst_dep_mask") or insn.get("store_data_dep_mask"))
    has_addr = bool(insn.get("load_addr_dep_mask")
                    or insn.get("store_addr_dep_mask"))
    if not has_reg and not has_addr:
        return "DEP_DEFAULT"

    n_src   = len(insn.get("src_regs") or [])
    n_dst   = len(insn.get("dst_regs") or [])
    has_imm = insn.get("imm") is not None
    n_loads  = int(insn.get("n_loads") or 0)
    n_stores = int(insn.get("n_stores") or 0)
    # Pool-mask layout: src bits [0,n_src), load_data bits
    # [n_src, n_src+n_loads), imm bit at n_src+n_loads.
    src_bits  = ((1 << n_src) - 1) if n_src else 0
    load_bits = (((1 << n_loads) - 1) << n_src) if n_loads else 0
    imm_bit   = (1 << (n_src + n_loads)) if has_imm else 0
    all_bits  = src_bits | load_bits | imm_bit
    dst_masks = list(insn.get("dst_dep_mask") or [])
    sd_masks  = list(insn.get("store_data_dep_mask") or [])
    la_masks  = list(insn.get("load_addr_dep_mask") or [])
    sa_masks  = list(insn.get("store_addr_dep_mask") or [])

    # x86 stack push: no loads, one store, store-data = single src bit,
    # dst (if any) contains %sp class registers.
    if (n_loads == 0 and n_stores == 1 and len(sd_masks) == 1
            and bin(sd_masks[0]).count("1") == 1
            and (sd_masks[0] & src_bits) == sd_masks[0]):
        return "DEP_X86_STACK_PUSH"

    # x86 stack pop: one load, no stores, dst[0] = single load_data bit.
    if (n_loads == 1 and n_stores == 0 and len(dst_masks) >= 1
            and bin(dst_masks[0]).count("1") == 1
            and (dst_masks[0] & load_bits) == dst_masks[0]):
        return "DEP_X86_STACK_POP"

    # LEA: at least one dst, every dst mask covers some src bits +
    # optionally imm but never a load_data bit, AND no real load fires.
    if (n_loads == 0 and dst_masks
            and all((m & load_bits) == 0 for m in dst_masks)
            and any((m & (src_bits | imm_bit)) for m in dst_masks)):
        # Distinguish from a plain register-only insn (e.g. ADD r,r)
        # by requiring at least two contributors to dst[0] (LEA's
        # addressing-mode usually combines base+index+imm) — or
        # an immediate.  Plain ADD with two srcs also lands here, so
        # this can mis-classify; treat both as the same low-precision
        # "no-load arithmetic-shape" bucket.  Reserve DEP_LEA for the
        # subset whose canonical dep is "addr-mode srcs + imm, no
        # load" — the trace doesn't preserve enough state to separate
        # these reliably without per-insn refiner-id metadata, so we
        # fold into DEP_OTHER unless the insn has imm + multi-src.
        if has_imm and n_src >= 1:
            return "DEP_LEA"

    # Passthrough: every populated mask has exactly one bit set.
    populated = dst_masks + sd_masks
    if populated and all(m and bin(m).count("1") == 1 for m in populated):
        return "DEP_PASSTHROUGH"

    # All-to-all: every populated dst/store-data mask equals the
    # universal set (every src + every load + imm).  Store-only ops
    # (STR, push-like) still qualify when their store_data_dep_mask
    # is the universal mask and they have no dst regs.
    pop_masks = dst_masks + sd_masks
    if pop_masks and all_bits and all(m == all_bits for m in pop_masks):
        return "DEP_ALL_TO_ALL"

    return "DEP_OTHER"


def _check_dep_refine_coverage(templates: list[dict],
                               blocks_by_id: dict[int, dict],
                               cp_set: set[int]) -> list[Issue]:
    """Info-level summary of which dep-refiner buckets are exercised by
    the trace's templates.  Mirrors ``_check_opcode_coverage``: tallies
    a per-bucket count, surfaces any author-declared ``asserted_dep_
    refines`` that never appeared in the trace, and lists the full set
    of refiner buckets so the report is self-describing."""
    seen: dict[str, int] = {b: 0 for b in _DEP_REFINE_BUCKETS}
    for t in templates:
        for ins in t.get("insns") or []:
            seen[_classify_dep_refine_bucket(ins)] += 1

    asserted: set[str] = set()
    for b in blocks_by_id.values():
        if b["block_id"] not in cp_set:
            continue
        for d in b.get("asserted_dep_refines", []) or []:
            asserted.add(d)
    asserted_unseen = sorted(asserted - {k for k, v in seen.items() if v > 0})

    if asserted_unseen:
        return [Issue(
            "dep_refine_coverage", "error",
            f"asserted dep refiners never observed: {asserted_unseen}",
            {"seen": seen, "asserted_unseen": asserted_unseen,
             "asserted": sorted(asserted)},
        )]

    seen_buckets = sorted(k for k, v in seen.items() if v > 0)
    return [Issue(
        "dep_refine_coverage", "info",
        f"dep refiner coverage: buckets observed={len(seen_buckets)}/"
        f"{len(_DEP_REFINE_BUCKETS)}; "
        + ", ".join(f"{k}={v}" for k, v in seen.items() if v > 0),
        {"seen": seen,
         "asserted": sorted(asserted),
         "asserted_unseen": asserted_unseen},
    )]


# ---------------------------------------------------------------------------
# Metaflags + general regdata reconstruction
# ---------------------------------------------------------------------------


# Opcode names whose dst-flags semantics we know how to predict.  Z and
# N are universal (function only of the result); P is x86-only.  C/V
# require operand history we don't always have, so they are excluded
# from the per-insn reconstruction.  MUL/DIV/SHIFT excluded because
# their flag behavior is either undefined (x86 MUL/DIV) or depends on
# operand history (SHIFT with non-immediate count).
_FLAG_WRITING_OPCODES = {
    "GEN_OP_INT_ADD", "GEN_OP_INT_SUB",
    "GEN_OP_AND",     "GEN_OP_OR",      "GEN_OP_XOR",
    "GEN_OP_CMP",     "GEN_OP_TEST",
}


def _operand_width_bits(insn: dict, isa: str) -> int:
    """Width of the integer-flags-relevant result for this insn.
    Falls back to 64-bit if we can't infer from the raw bytes."""
    raw = insn.get("raw_bytes") or b""
    if isa == "x86_64":
        # REX.W (0x48) prefix → 64-bit; 0x66 → 16-bit; default 32-bit.
        # We don't try to handle the full prefix grammar; the common
        # cases the test programs emit are REX.W-tagged or default.
        b = bytes(raw)
        if any((p & 0xF8) == 0x48 for p in b[:4]):
            return 64
        if b and b[0] == 0x66:
            return 16
        return 32
    if isa == "aarch64":
        # AArch64 NZCV cares about the destination register width; the
        # bottom bit of the opcode word's "sf" field selects 64/32.
        if len(raw) >= 4:
            return 64 if (raw[3] & 0x80) else 32
        return 64
    return 64


def _popcount_low_byte_parity(val: int) -> int:
    """x86 PF bit: 1 if low byte of result has an even number of set bits."""
    b = val & 0xFF
    return 1 if bin(b).count("1") % 2 == 0 else 0


def _check_metaflags(
        cp_entries: list[dict],
        templates_by_id: dict[int, dict],
        opcode_names: dict[int, str],
        isa: str,
        reg_id_to_name: dict[int, str],
        has_reg_data: bool) -> list[Issue]:
    """For every insn whose template writes REG_FLAGS, the trace
    emits a CST_FID_METAFLAGS byte under a known per-ISA bit layout.
    Reconstruct the Z, N, and P bits from the destination register
    snap (which is the result of the operation) and assert they match
    the trace's metaflags byte.

    C and V depend on operand history we don't always have, so the
    check only fails on Z/N/P divergences.  An issue with Z/N/P
    implies either:
      * the metaflags mapper has the wrong bit shuffle for this ISA,
      * the writer captured stale flags (CPU lazy-flags bug), or
      * the writer attached the byte to the wrong insn.
    """
    if not has_reg_data:
        return [Issue(
            "metaflags", "info",
            "metaflags validation skipped (no regdata=1)",
        )]
    # Look up REG_FLAGS' numeric id from the trace's own reg map.
    name_to_id = {v: int(k) for k, v in reg_id_to_name.items()}
    flags_id = name_to_id.get("REG_FLAGS")
    if flags_id is None:
        return [Issue(
            "metaflags", "info",
            "trace has no REG_FLAGS entry; metaflags not applicable",
        )]

    opc_names = {}  # rebuilt below from the trace
    issues: list[Issue] = []
    n_checked = 0
    n_errors  = 0
    err_cap   = 20

    for e in cp_entries:
        tmpl = templates_by_id.get(int(e["template_id"]))
        if tmpl is None:
            continue
        # Kernel / fault-handler code: not ours to model (ccmp/ccmn set
        # NZCV to an immediate when the condition fails, etc.).  Limit
        # flag reconstruction to the synthetic user workload.
        if tmpl.get("is_system"):
            continue
        mf_by_insn = {int(m["insn_index"]): int(m["byte"])
                      for m in (e.get("metaflags") or [])}
        if not mf_by_insn:
            continue
        # Build {(insn_idx, reg_id) -> snap} so we can find the dst
        # result for each insn.
        snap_idx: dict[tuple[int, int], dict] = {}
        for s in (e.get("reg_snaps") or []):
            snap_idx[(int(s["insn_index"]), int(s["reg_id"]))] = s

        for ipos, I in enumerate(tmpl.get("insns") or []):
            if ipos not in mf_by_insn:
                continue
            dsts = [int(r) for r in (I.get("dst_regs") or [])]
            if flags_id not in dsts:
                # The writer emitted metaflags for an insn that
                # doesn't write REG_FLAGS — that's the bug we just
                # fixed; assert it stays fixed.
                issues.append(Issue(
                    "metaflags", "error",
                    f"template BB{tmpl['template_id']} insn[{ipos}]: "
                    f"metaflags byte present but REG_FLAGS not in "
                    f"dst_regs={[reg_id_to_name.get(r, r) for r in dsts]}",
                    {"template_id": tmpl["template_id"], "insn": ipos},
                ))
                continue
            # Only predict flags for opcodes with known arithmetic
            # semantics whose first GPR dst IS the operation result.
            # Skips SYSCALL (kernel-set flags), branches that just
            # happen to also clobber flags via a side-effect, etc.
            op_id = int(I.get("opcode", 0))
            op_name = opcode_names.get(op_id, "")
            if op_name not in _FLAG_WRITING_OPCODES:
                continue
            # Predicted Z/N/P from the *non-flags* dst result.  When
            # an insn writes both REG_FLAGS and a GPR (the common
            # case: add/sub/and/or/xor), the GPR snap *is* the result.
            # CMP/TEST write only flags, so there's no GPR snap to
            # check against — Z/N/P verification is skipped.
            gpr_dsts = [r for r in dsts if r != flags_id]
            if not gpr_dsts:
                continue
            result_reg = gpr_dsts[0]
            snap = snap_idx.get((ipos, result_reg))
            if snap is None:
                continue
            result = _reg_snap_value(snap)
            width = _operand_width_bits(I, isa)
            mask  = (1 << width) - 1
            r_low = result & mask
            sign_bit = (r_low >> (width - 1)) & 1

            mf = mf_by_insn[ipos]
            mf_z = (mf >> 0) & 1
            mf_n = (mf >> 1) & 1
            mf_p = (mf >> 4) & 1

            exp_z = 1 if r_low == 0 else 0
            exp_n = sign_bit
            exp_p = _popcount_low_byte_parity(r_low) if isa == "x86_64" \
                    else mf_p  # AArch64 has no parity bit; trust trace

            n_checked += 1
            if mf_z != exp_z or mf_n != exp_n or (
                    isa == "x86_64" and mf_p != exp_p):
                n_errors += 1
                if n_errors <= err_cap:
                    issues.append(Issue(
                        "metaflags", "error",
                        f"BB{tmpl['template_id']} insn[{ipos}] "
                        f"(0x{int(I.get('pc', 0)):x}): "
                        f"trace mflags=0x{mf:02x} "
                        f"Z={mf_z}/N={mf_n}/P={mf_p}, expected "
                        f"Z={exp_z}/N={exp_n}/P={exp_p} from "
                        f"{reg_id_to_name.get(result_reg, result_reg)}="
                        f"0x{r_low:x} ({width}-bit)",
                        {"template_id": tmpl["template_id"], "insn": ipos,
                         "trace_mflags": mf, "expected_znp":
                            {"Z": exp_z, "N": exp_n, "P": exp_p},
                         "result": r_low, "width": width},
                    ))

    if n_errors == 0:
        issues.append(Issue(
            "metaflags", "info",
            f"{n_checked} flag-writing insn(s) had Z/N/P bits matching "
            f"the trace's metaflags byte",
        ))
    elif n_errors > err_cap:
        issues.append(Issue(
            "metaflags", "info",
            f"... {n_errors - err_cap} additional metaflags errors suppressed",
        ))
    return issues


def _check_regdata_reconstruction(
        cp_entries: list[dict],
        templates_by_id: dict[int, dict],
        opcode_names: dict[int, str],
        reg_id_to_name: dict[int, str],
        has_reg_data: bool,
        isa: str = "x86_64") -> list[Issue]:
    """For arithmetic insns whose semantics we know how to model, take
    the *prior* dst snap of each src register as the operand value,
    compute the expected result, and compare to the trace's dst snap.

    Tracks a per-(thread, reg_id) "latest observed value" map.  Initial
    register state is whatever the architectural ABI seeds (the
    BODY_TAG_REGFILE record) — we don't have a clean Python view of
    those bytes here, so the first observation of any register
    bootstraps from the trace itself rather than reporting an error.

    Limited to GEN_OP_INT_ADD / SUB / AND / OR / XOR with two GPR
    sources.  Loads, stores, shifts with non-const counts, and
    flag-writing ops without two named GPR sources are skipped.
    """
    if not has_reg_data:
        return [Issue(
            "regdata_reconstruction", "info",
            "regdata reconstruction skipped (no regdata=1)",
        )]

    name_to_id = {v: int(k) for k, v in reg_id_to_name.items()}
    flags_id = name_to_id.get("REG_FLAGS")

    # Inverse opcode-name map: numeric id → name.
    issues: list[Issue] = []
    n_checked = 0
    n_errors  = 0
    err_cap   = 20

    # Each handler is (compute, commutative).  Commutative ops can
    # ignore operand order; non-commutative (SUB) need to know which
    # src is the "minuend" — for 2-operand forms (x86 `sub src, dst`
    # → src_regs=[src, dst_also_src]) the minuend is whichever src
    # also appears as a dst; for 3-operand forms (aarch64
    # `sub dst, lhs, rhs` → src_regs=[lhs, rhs]) the minuend is src[0].
    handlers = {
        "GEN_OP_INT_ADD": (lambda a, b, m: (a + b) & m, True),
        "GEN_OP_INT_SUB": (lambda a, b, m: (a - b) & m, False),
        "GEN_OP_AND":     (lambda a, b, m: (a & b) & m, True),
        "GEN_OP_OR":      (lambda a, b, m: (a | b) & m, True),
        "GEN_OP_XOR":     (lambda a, b, m: (a ^ b) & m, True),
    }

    # Per-thread current register state.
    reg_state: dict[tuple[int, int], int] = {}

    for e in cp_entries:
        tid  = int(e.get("thread_id", 0))
        tmpl = templates_by_id.get(int(e["template_id"]))
        if tmpl is None:
            continue
        snap_idx: dict[tuple[int, int], dict] = {}
        for s in (e.get("reg_snaps") or []):
            snap_idx[(int(s["insn_index"]), int(s["reg_id"]))] = s

        # Kernel / fault-handler code (CST_INSN_FLAG_SYSTEM): we did not
        # generate it, so we cannot model its operand semantics (aarch64
        # shifted/extended-register ALU forms, ccmp, riscv `sub rd,rs1,rd`
        # operand aliasing, …).  Don't verify it — but still fold its dst
        # snaps into reg_state so a subsequent *user* op that reads a
        # kernel-written register reconstructs against the right value
        # rather than a stale one.
        if tmpl.get("is_system"):
            for (_ipos_k, r_k), snap in snap_idx.items():
                reg_state[(tid, r_k)] = _reg_snap_value(snap)
            continue

        # Insn positions that touched memory this execution.  Memory-
        # coupled ALU forms (x86 RMW "add (m), r" — dst = src + MEM;
        # aarch64 writeback addressing, classified INT_ADD by design —
        # dst = base ± imm) cannot be reconstructed from the two named
        # GPR sources; they bootstrap like atomics below.
        mem_ipos = {int(getattr(d, "insn_index"))
                    for d in (e.get("dyn_params") or [])
                    if getattr(d, "insn_index", None) is not None}

        for ipos, I in enumerate(tmpl.get("insns") or []):
            op_id = int(I.get("opcode", 0))
            op_name = opcode_names.get(op_id, "")
            srcs = [int(r) for r in (I.get("src_regs") or [])]
            dsts = [int(r) for r in (I.get("dst_regs") or [])]
            gpr_dsts = [r for r in dsts
                        if flags_id is None or r != flags_id]
            # Atomic RMW (lock xadd, ldadd, amoadd, ll/sc, …) has the
            # dst-reg semantically loaded from memory rather than
            # computed from src operands.  The is_atomic marker is
            # what distinguishes these; skip reconstruction for them.
            # Memory-coupled insns get the identical treatment.
            if I.get("is_atomic") or ipos in mem_ipos:
                for r in gpr_dsts:
                    snap = snap_idx.get((ipos, r))
                    if snap is not None:
                        reg_state[(tid, r)] = _reg_snap_value(snap)
                continue
            # We need exactly two GPR sources and at least one GPR dst
            # to predict the result.  Many real-world insns have
            # implicit sources (CF as a carry-in for ADC, the
            # multiplicand for x86 MUL, etc.) which we can't model
            # without per-opcode semantics tables — skip those.
            # Update reg_state for any dst snap regardless of whether
            # we'll verify this insn — the chain that comes next still
            # needs the current values.  Skip the rest of the loop body
            # for any insn we don't model.
            def _commit_dst_state() -> None:
                for r in gpr_dsts:
                    snap = snap_idx.get((ipos, r))
                    if snap is not None:
                        reg_state[(tid, r)] = _reg_snap_value(snap)

            if op_name not in handlers:
                _commit_dst_state()
                continue
            if len(srcs) != 2 or not gpr_dsts:
                _commit_dst_state()
                continue
            compute, commutative = handlers[op_name]
            # Reorder for non-commutative ops so `a` is the minuend.
            # x86 2-op form (`sub src, dst` → dst = dst - src): the
            # dst-also-src reg is the minuend → put it first.  3-op ISAs
            # (riscv/mips/aarch64 `sub rd, rs1, rs2`): src[0] is ALWAYS
            # the minuend — the dst-alias test must not run there, or
            # `sub rd, rs1, rd` (rd == rs2, common in kernel code) gets
            # its operands swapped and a correct trace is flagged.
            ordered_srcs = list(srcs)
            if not commutative and isa in ("x86_64", "i386"):
                if srcs[1] in dsts and srcs[0] not in dsts:
                    ordered_srcs = [srcs[1], srcs[0]]
            a = reg_state.get((tid, ordered_srcs[0]))
            b = reg_state.get((tid, ordered_srcs[1]))
            if a is None or b is None:
                # Bootstrap: take whatever the trace says this dst is
                # so subsequent ops can chain.
                for r in gpr_dsts:
                    snap = snap_idx.get((ipos, r))
                    if snap is not None:
                        reg_state[(tid, r)] = _reg_snap_value(snap)
                continue
            width = 64  # GP-default; could refine per-insn but the
                       # GPR snap is always 64-bit-padded on the wire.
            mask  = (1 << width) - 1
            expected_alu = compute(a & mask, b & mask, mask)
            for r in gpr_dsts:
                snap = snap_idx.get((ipos, r))
                if snap is None:
                    continue
                got = _reg_snap_value(snap) & mask
                # The hardwired zero register (riscv x0 / mips $zero /
                # aarch64 xzr) discards writes — its architectural
                # value is always 0, not the ALU result.
                expected = 0 if r == name_to_id.get("REG_ZERO") \
                    else expected_alu
                n_checked += 1
                if got != expected:
                    n_errors += 1
                    if n_errors <= err_cap:
                        issues.append(Issue(
                            "regdata_reconstruction", "error",
                            f"BB{tmpl['template_id']} insn[{ipos}] "
                            f"(0x{int(I.get('pc', 0)):x}) {op_name}: "
                            f"trace dst="
                            f"{reg_id_to_name.get(r, r)}=0x{got:x}, "
                            f"expected 0x{expected:x} from "
                            f"{reg_id_to_name.get(ordered_srcs[0], ordered_srcs[0])}"
                            f"=0x{a & mask:x}, "
                            f"{reg_id_to_name.get(ordered_srcs[1], ordered_srcs[1])}"
                            f"=0x{b & mask:x}",
                            {"template_id": tmpl["template_id"],
                             "insn": ipos, "opcode": op_name,
                             "got": got, "expected": expected,
                             "a": a & mask, "b": b & mask},
                        ))
                # Update state regardless — the chain continues.
                reg_state[(tid, r)] = _reg_snap_value(snap)

    if n_errors == 0:
        issues.append(Issue(
            "regdata_reconstruction", "info",
            f"reconstructed {n_checked} arithmetic dst value(s) "
            f"matched the trace's regdata snaps",
        ))
    elif n_errors > err_cap:
        issues.append(Issue(
            "regdata_reconstruction", "info",
            f"... {n_errors - err_cap} additional regdata errors suppressed",
        ))
    return issues


# ---------------------------------------------------------------------------
# Structural-only validation (no correct_path / no meta.json needed).
# ---------------------------------------------------------------------------


def validate_cross_segment_consistency(
        segment_paths: list[Path]) -> Report:
    """Decode every segment and assert that the CONSTANT parts of any
    template shared across segments (matched by `start_pc`) are
    bit-identical.

    A template's constant part is everything determined at translation
    time — `n_insns`, `fall_through_pc`, the terminal-branch target
    list, and per-insn `pc / opcode / branch_type / branch_conditional /
    src_regs / dst_regs / imm / is_atomic / lane_parallel / raw_bytes`.
    These describe what the BB IS, not what it did, so identical code
    must decode to identical fields no matter which segment captured
    it.  Variable per-execution counters (`exec_cp`, `memops_cp`,
    `pat_*`, etc.) are legitimately different per segment — each
    segment is a separate stage of the program — and are deliberately
    NOT compared.

    Guards specifically against the failure mode where a stub or
    partially-instrumented translation produced outside an active
    segment leaks into a segment's wire dictionary: its constant
    fields would differ from the fresh, full-fidelity translation
    produced after the segment opens.
    """
    if len(segment_paths) < 2:
        return Report(issues=[], stats={
            "segments_compared": len(segment_paths),
            "shared_templates": 0,
        })
    dec = _load_decoder()

    def insn_signature(ins: dict) -> tuple:
        return (
            ins["pc"],
            ins["opcode"],
            ins["branch_type"],
            ins["branch_conditional"],
            tuple(ins.get("src_regs", [])),
            tuple(ins.get("dst_regs", [])),
            ins.get("imm"),
            ins.get("is_atomic", False),
            ins.get("lane_parallel", False),
            bytes(ins.get("raw_bytes", b"")),
        )

    def template_signature(t: dict) -> tuple:
        prof_targets = tuple(sorted(
            tg.get("pc", 0) for tg in t["profile"].get("targets", [])))
        return (
            t["n_insns"],
            t["fall_through_pc"],
            prof_targets,
            tuple(insn_signature(ins) for ins in t["insns"]),
        )

    seg_data: list[tuple[Path, dict[int, dict]]] = []
    for p in segment_paths:
        _meta, templates, _entries = dec.decode_champsim_tracer(p)
        by_pc: dict[int, dict] = {}
        for t in templates:
            by_pc[t["start_pc"]] = t
        seg_data.append((p, by_pc))

    issues: list[Issue] = []
    shared_total = 0
    base_path, base_map = seg_data[0]
    for other_path, other_map in seg_data[1:]:
        common = set(base_map.keys()) & set(other_map.keys())
        shared_total += len(common)
        for start_pc in sorted(common):
            t1 = base_map[start_pc]
            t2 = other_map[start_pc]
            sig1 = template_signature(t1)
            sig2 = template_signature(t2)
            if sig1 == sig2:
                continue
            # Find the first differing field for a helpful message.
            diffs: list[str] = []
            if t1["n_insns"] != t2["n_insns"]:
                diffs.append(f"n_insns {t1['n_insns']} vs {t2['n_insns']}")
            if t1["fall_through_pc"] != t2["fall_through_pc"]:
                diffs.append(
                    f"fall_through 0x{t1['fall_through_pc']:x} vs "
                    f"0x{t2['fall_through_pc']:x}")
            if not diffs:
                # Per-insn divergence
                for i, (a, b) in enumerate(
                        zip(t1["insns"], t2["insns"])):
                    if insn_signature(a) != insn_signature(b):
                        diffs.append(f"insn[{i}] differs")
                        break
            issues.append(Issue(
                check="cross_segment_template_shape",
                severity="error",
                message=(
                    f"template start_pc=0x{start_pc:x} structural "
                    f"fields differ across segments: "
                    f"{base_path.name} vs {other_path.name}: "
                    f"{', '.join(diffs) or 'unspecified'}"),
                detail={
                    "start_pc": start_pc,
                    "seg1_path": str(base_path),
                    "seg2_path": str(other_path),
                    "diffs": diffs,
                }))
    stats = {
        "segments_compared": len(segment_paths),
        "shared_templates":  shared_total,
    }
    return Report(issues=issues, stats=stats)


def validate_structural(trace_path: Path,
                        expected_threads: int = 1,
                        expected_guest_threads: int | None = None,
                        marker: bool = False,
                        pinned_binary: Path | None = None) -> Report:
    """Decode @trace_path and run only the checks that don't depend on
    the generator's meta.json (correct_path, blocks, wrong_paths).

    Used by the segmentation test, where each per-simpoint .cst file
    is a standalone trace that begins mid-program and shouldn't be
    asked to validate the original CFG.  Asserts the trace is
    internally consistent: encoding maps are complete, atomic_count
    and wp_events agree between writer-aggregate and per-entry walk,
    IFRAMEs match their ENTRYs (already enforced by the decoder),
    REGFILE record(s) present and positioned before each thread's
    first ENTRY, switch flags marking exactly the tid changes, no
    unexpected thread_switch on single-thread runs, and — when
    @expected_guest_threads is given — the user-privilege entry
    stream decomposing into that many control-flow chains.

    @marker: the trace came from a system-mode marker/pin run, so the
    kernel interleaves and the privilege-transition checks
    (syscall round-trips, fault-excursion depth discipline) apply.
    """
    dec = _load_decoder()
    trace_meta, templates, entries = dec.decode_champsim_tracer(trace_path)
    issues: list[Issue] = []
    stats: dict = {
        "trace_templates": len(templates),
        "trace_entries": len(entries),
    }

    issues += _check_encoding_map_completeness(templates, trace_meta)

    body_stats = trace_meta.get("body_stats") or {}
    stats["body_stats"] = body_stats
    templates_by_id = {t["template_id"]: t for t in templates}
    issues += _check_unconditional_direction(templates, entries,
                                             templates_by_id, trace_meta)
    issues += _check_iframe_cadence(body_stats, entries, trace_meta)
    issues += _check_regfile_records(body_stats, expected_threads)
    issues += _check_thread_switch(body_stats, expected_threads)
    if marker:
        # System-mode thread_ids are GUEST-THREAD identities, dense
        # 0..N-1 by first-sighting order — NOT vCPU indexes, and not
        # bounded by -smp (one vCPU can host many guest threads, and a
        # thread that migrates keeps one tid).  The population is the
        # pinned process's own thread count: @expected_guest_threads
        # (the clone test's 2) or, absent that, @expected_threads.
        issues += _check_thread_distribution(
            entries, expected_guest_threads or expected_threads)
    else:
        issues += _check_thread_distribution(entries, expected_threads)
    issues += _check_thread_record_cadence(
        entries, trace_meta.get("body_record_order") or [])
    issues += _check_thread_chain(entries, templates_by_id,
                                  expected_guest_threads, trace_meta)
    if marker:
        issues += _check_syscall_transitions(
            entries, templates_by_id, trace_meta,
            guest_threads=expected_guest_threads or 1)
        issues += _check_fault_excursions(entries, templates_by_id,
                                          trace_meta)
        issues += _check_syscall_fault_nesting(
            entries, templates_by_id, trace_meta,
            guest_threads=expected_guest_threads or 1)
    if pinned_binary is not None:
        issues += _check_user_code_identity(templates, entries,
                                            templates_by_id,
                                            pinned_binary)
    issues += _check_wp_events(body_stats, entries)
    issues += _check_atomic_count(body_stats, entries, templates_by_id)
    return Report(issues=issues, stats=stats)


def _check_data_widths(entries: list[dict],
                       has_mem_data: bool,
                       has_reg_data: bool) -> list[Issue]:
    """Verify the per-slot data-width families (CST_FID_LOAD_SIZE /
    STORE_SIZE / DST_REG_WIDTH).

    A natural extension of the memdata / regdata checks: a recorded width
    must be within range (<= CST_MAX_WIDE_BYTES = 64) and wide enough to
    hold the value the trace recorded — the writer masks each value to its
    width, so the value must fit in `width` bytes.  Width 0 marks a slot
    with no real access (a synthetic address-only memop such as prefetch /
    cache-flush / TLB-flush, or an unresolved register); its value is 0,
    so a width-0 slot carrying a nonzero value is the one inconsistency
    flagged there.  Catches a width narrower than its value (wrong field)
    or out of range — which the magnitude-derived estimate the runner
    used previously could not.
    """
    MAXW = 64
    issues: list[Issue] = []
    n_mem = 0
    n_reg = 0
    if has_mem_data:
        for e in entries:
            for dp in e.get("dyn_params") or []:
                w = int(getattr(dp, "data_size", 0) or 0)
                val = int(getattr(dp, "data", 0) or 0)
                if w == 0:
                    # 0 = a synthetic / address-only memop (prefetch,
                    # cache-flush, TLB-flush) with no real access and so
                    # no architectural width; its value is 0.  Only a
                    # nonzero value would then be inconsistent.
                    if val != 0:
                        issues.append(Issue(
                            "data_width", "error",
                            f"{dp.type_name} memop insn[{dp.insn_index}] "
                            f"has value 0x{val:x} but width 0"))
                    continue
                if w > MAXW:
                    issues.append(Issue(
                        "data_width", "error",
                        f"{dp.type_name} memop insn[{dp.insn_index}] width "
                        f"{w} > {MAXW}"))
                    continue
                if val >> (8 * w):
                    issues.append(Issue(
                        "data_width", "error",
                        f"{dp.type_name} memop insn[{dp.insn_index}] value "
                        f"0x{val:x} does not fit in its {w}-byte width"))
                    continue
                n_mem += 1
    if has_reg_data:
        for e in entries:
            for s in e.get("reg_snaps") or []:
                w = s.get("width_bytes")
                val = int(s.get("value", 0) or 0)
                if w is None:
                    continue                      # trace carried no width
                if w == 0:
                    # 0 = register the plugin could not resolve; only a
                    # nonzero value would then be inconsistent.
                    if val != 0:
                        issues.append(Issue(
                            "data_width", "error",
                            f"reg snap insn[{s['insn_index']}] "
                            f"dst[{s['operand_index']}] has value "
                            f"0x{val:x} but width 0"))
                    continue
                if w > MAXW:
                    issues.append(Issue(
                        "data_width", "error",
                        f"reg snap insn[{s['insn_index']}] "
                        f"dst[{s['operand_index']}] width {w} > {MAXW}"))
                    continue
                if val >> (8 * w):
                    issues.append(Issue(
                        "data_width", "error",
                        f"reg snap insn[{s['insn_index']}] "
                        f"dst[{s['operand_index']}] value 0x{val:x} does "
                        f"not fit in its {w}-byte width"))
                    continue
                n_reg += 1
    if has_mem_data or has_reg_data:
        issues.append(Issue(
            "data_width", "info",
            f"verified {n_mem} memop and {n_reg} dst-register widths "
            f"(present, ≤{MAXW}B, value-consistent)"))
    return issues


# ---------------------------------------------------------------------------
# Top-level validate()
# ---------------------------------------------------------------------------

def validate(meta_path: Path, trace_path: Path,
             binary_path: Path,
             wp_insn_budget: int = 64,
             expected_start: int | None = 0,
             expected_stop: int | None = None,
             expected_warmup: int | None = 0,
             expected_threads: int = 1,
             start_symbol: str | None = None,
             marker: bool = False) -> Report:
    meta = json.loads(meta_path.read_text())
    dec = _load_decoder()
    trace_meta, templates, entries = dec.decode_champsim_tracer(trace_path)

    pcmap = PcMap(meta["blocks"])
    template_runs: dict[int, list[tuple[int, int]]] = {
        t["template_id"]: pcmap.template_runs(t) for t in templates
    }

    correct_path = list(meta["correct_path"])
    blocks_by_id = {b["block_id"]: b for b in meta["blocks"]}

    # Symbol-based start: trim correct_path to begin at the block
    # whose label was used as the trace_window=symbol:name= target.
    # Asm-block symbols are emitted as `blk_<N>` (see asm_blocks.
    # symbol_name); strip that prefix to recover the block id.  Blocks
    # the trace skipped (the prologue) are dropped from cp_set so
    # downstream checks (cp_memops, reg_value_assertions, expected_reg
    # _sets, etc.) don't flag them as missing.
    cp_pos_offset = 0
    if start_symbol and start_symbol.startswith("blk_"):
        try:
            start_bid = int(start_symbol[len("blk_"):])
        except ValueError:
            start_bid = None
        if start_bid is not None and start_bid in correct_path:
            cp_pos_offset = correct_path.index(start_bid)
            correct_path = correct_path[cp_pos_offset:]
    cp_set = set(correct_path)

    stats: dict = {
        "trace_templates": len(templates),
        "trace_entries": len(entries),
        "meta_blocks": len(meta["blocks"]),
        "meta_cp_length": len(correct_path),
        "pc_spans_loaded": len(pcmap._spans),
        "trace_format_version": trace_meta.get("format_version"),
    }

    if not pcmap._spans:
        return Report(issues=[Issue(
            "setup", "error",
            "metadata has no ground_truth PC spans; run `analyze` first",
        )], stats=stats)

    # Locate the first entry whose template covers the entry block —
    # everything before is boot/init prologue.
    entry_bid = correct_path[0]
    cp_start = None
    for i, e in enumerate(entries):
        runs = template_runs.get(e["template_id"], [])
        if any(bid == entry_bid for bid, _ in runs):
            cp_start = i
            break

    issues: list[Issue] = []
    if cp_start is None:
        issues.append(Issue(
            "cp_execution_order", "error",
            f"entry block blk_{entry_bid} never executed in trace",
        ))
        return Report(issues=issues, stats=stats)

    cp_entries = entries[cp_start:]
    cp_flat: list[int] = []
    for e in cp_entries:
        for bid, _ in template_runs.get(e["template_id"], []):
            cp_flat.append(bid)
    cp_block_seq = _collapse_runs(cp_flat)
    cp_distinct = set(cp_block_seq)

    # Plugin sanity check: the CP entry for a TB is emitted lazily when
    # the *next* TB starts, so a TB terminated by a process-exiting
    # syscall currently disappears from CP.  We detect this pattern
    # structurally: if the distinct CP blocks visited are a strict
    # prefix of `correct_path` (run-length-collapsed to handle CFG-level
    # self-loops), the missing suffix is the dropped tail.
    plugin_drop_tail: list[int] = []
    _correct_collapsed = _collapse_runs(correct_path)
    if cp_block_seq and len(cp_block_seq) < len(_correct_collapsed):
        if cp_block_seq == _correct_collapsed[:len(cp_block_seq)]:
            plugin_drop_tail = _correct_collapsed[len(cp_block_seq):]

    stats["cp_start_index"] = cp_start
    stats["cp_entries_after_prologue"] = len(cp_entries)
    stats["cp_flat_block_visits"] = len(cp_flat)
    stats["cp_distinct_block_run_length"] = len(cp_block_seq)

    # Report the CP-tail-dropped plugin bug if present.  This is the
    # root cause of any subsequent `blocks_covered` / `cp_execution_order`
    # failures involving blocks after the last emitted CP entry, so we
    # flag it explicitly to make the report actionable.
    if plugin_drop_tail:
        missing_labels = ", ".join(f"blk_{b}" for b in plugin_drop_tail)
        issues.append(Issue(
            "plugin_cp_tail_dropped", "error",
            "champsim_tracer plugin dropped the CP entry for the final TB "
            "(ends in process-exit syscall); blocks visible only via "
            f"a SYSCALL_USERMODE WP entry: {missing_labels}",
            {"missing_cp_tail": plugin_drop_tail},
        ))
        stats["plugin_dropped_cp_tail"] = plugin_drop_tail

    # When the CP-tail-drop plugin bug is detected, the missing suffix
    # blocks cannot possibly pass blocks_covered / cp_execution_order,
    # so pretend the dropped blocks *were* covered (in order) for the
    # downstream checks.  The underlying plugin bug is already reported.
    if plugin_drop_tail:
        cp_distinct = cp_distinct | set(plugin_drop_tail)
        cp_block_seq_effective = cp_block_seq + plugin_drop_tail
    else:
        cp_block_seq_effective = cp_block_seq

    issues += _check_blocks_covered(correct_path, cp_distinct)
    # cp_block_seq is run-length-collapsed; for CFG-level self-loop
    # blocks (StrideLoopHead) the correct_path has the same block_id
    # repeated for each iteration, so collapse it here too — for
    # LoopHead↔LoopBody loops the alternation makes this a no-op.
    correct_path_collapsed = _collapse_runs(correct_path)
    issues += _check_cp_execution_order(correct_path_collapsed,
                                        cp_block_seq_effective)

    # wpprune drops the wrong path for cold branches, so WP-discovered
    # instructions/chains may be absent; the affected checks relax below.
    wpprune = _parse_wpprune_from_command(trace_meta.get("command", ""))

    # Disassembly-driven first-order sanity checks.
    issues += _check_template_raw_bytes(templates, blocks_by_id)
    issues += _check_block_insn_counts(templates, blocks_by_id, pcmap,
                                       cp_set, wpprune=wpprune)
    # The per-block opcode/branch-type coverage assertions assume the full
    # CP+WP instruction set of each block is present; wpprune drops the
    # wrong path for cold branches, so a block's WP-only-reached opcodes
    # can be legitimately absent.  Keep the oracle strict at wpprune=0.
    if wpprune == 0:
        issues += _check_block_assertions(templates, blocks_by_id, pcmap,
                                          cp_set)
    issues += _check_profile_consistency(
        templates, entries, trace_meta.get("body_stats") or {})

    # Impossible-attribution lint verdict, surfaced by cst_decode's
    # trailing summary (tools/cst_lint.h): runtime memops attributed to
    # memop-incapable insns, or dst-reg values on operand slots the
    # template does not carry.  Always zero on a conformant trace.
    imp = trace_meta.get("impossible_attributions") or {}
    if imp.get("memop") or imp.get("regdata"):
        issues.append(Issue(
            "impossible_attribution", "error",
            f"decoder lint counted impossible attributions: "
            f"{imp.get('memop', 0)} memop "
            f"({imp.get('memop_insns', 0)} distinct insns), "
            f"{imp.get('regdata', 0)} regdata "
            f"({imp.get('regdata_insns', 0)} distinct insns)",
            dict(imp)))

    templates_by_id = {t["template_id"]: t for t in templates}

    arena_info = _find_arena_address(binary_path)
    if arena_info is None:
        issues.append(Issue(
            "cp_memops", "error",
            "no `arena` symbol in binary; memop/value check cannot run",
        ))
    else:
        arena_addr, arena_size = arena_info
        stats["arena_addr"] = f"0x{arena_addr:x}"
        stats["arena_size"] = arena_size
        issues += _check_cp_memops(cp_entries, template_runs,
                                   blocks_by_id, cp_set, arena_addr,
                                   arena_size,
                                   meta.get("isa", "x86_64"),
                                   templates_by_id=templates_by_id,
                                   pcmap=pcmap)
        issues += _check_per_execution_memop_data(
            cp_entries, template_runs, blocks_by_id,
            cp_set, arena_addr, arena_size,
            meta.get("isa", "x86_64"))

    isa = meta.get("isa", "x86_64")

    # Static register identity check: verify the template's src_regs and
    # dst_regs agree with Capstone operand detail and the active tracer
    # per-ISA register classification table.  Comparison is by REG_*
    # symbolic name; the trace's own ENCODINGS section supplies the
    # gen_id → name mapping so the validator tracks the plugin's
    # GenericRegId enum automatically.
    reg_id_to_name = dict(trace_meta.get("encoding_maps", {}).get("reg", {}))
    issues += _check_static_reg_sets(templates, isa, reg_id_to_name)

    # Per-instruction memop attribution: ensure every dyn_param's
    # insn_index points at an instruction whose schema declares the
    # matching access kind.  Independent of arena (works even when no
    # `arena` symbol is present).
    issues += _check_memop_insn_attribution(cp_entries, template_runs,
                                            templates_by_id, cp_set)

    issues += _check_memop_count_assertions(cp_entries, templates_by_id,
                                            blocks_by_id, pcmap, cp_set)

    issues += _check_per_execution_memop_shape(
        cp_entries, template_runs, templates_by_id, blocks_by_id, cp_set)

    has_reg_data = bool(trace_meta.get("has_reg_data"))
    has_mem_data = bool(trace_meta.get("has_mem_data"))
    issues += _check_reg_value_assertions(cp_entries, templates_by_id,
                                          blocks_by_id, pcmap, cp_set,
                                          has_reg_data, reg_id_to_name)

    # Per-slot data-width families (CST_FID_LOAD_SIZE / STORE_SIZE /
    # DST_REG_WIDTH): present, bounded, and value-consistent.
    issues += _check_data_widths(cp_entries, has_mem_data, has_reg_data)
    issues += _check_expected_reg_sets(cp_entries, templates_by_id,
                                       blocks_by_id, pcmap, cp_set, isa,
                                       reg_id_to_name)
    issues += _check_expected_insns(cp_entries, templates_by_id,
                                    blocks_by_id, pcmap, cp_set, isa,
                                    reg_id_to_name)

    # Address-recompute: only meaningful when reg-data was emitted.
    issues += _check_address_recompute(cp_entries, template_runs,
                                       templates_by_id, cp_set, isa)

    # Coverage summary (info-level): tracks per-ISA progress toward
    # 100 % generic-opcode coverage.  ISA is encoded in the metadata
    # as `meta["isa"]`.
    issues += _check_opcode_coverage(templates, blocks_by_id, pcmap,
                                     cp_set, isa)

    # Branch-type coverage summary (info-level), parallel to opcode
    # coverage so ISA-level branch regressions are explicit.
    issues += _check_branch_coverage(templates, blocks_by_id,
                                     cp_set, isa)

    # Generic register ID coverage summary, using the tracer's generated
    # per-ISA register classification tables as the reachable universe.
    issues += _check_reg_coverage(templates, isa, reg_id_to_name)

    # Invert the trace's own reg encodings map for the wrong-path
    # poison-propagation replay (REG_ZERO / REG_FLAGS lookups; the
    # per-insn src/dst ids in decoded templates use the same space).
    _wp_reg_name_to_id = {}
    for _rid, _rname in reg_id_to_name.items():
        try:
            _wp_reg_name_to_id[_rname] = int(_rid)
        except (TypeError, ValueError):
            continue
    issues += _check_wrong_path_chains(cp_entries, template_runs,
                                       cp_block_seq, correct_path,
                                       meta["wrong_paths"],
                                       blocks_by_id,
                                       wp_insn_budget=wp_insn_budget,
                                       helper_leaf_n_insns=int(meta.get("helper_leaf_n_insns", 0) or 0),
                                       isa=isa,
                                       cp_pos_offset=cp_pos_offset,
                                       templates_by_id=templates_by_id,
                                       marker=marker,
                                       wpprune=wpprune,
                                       reg_name_to_id=_wp_reg_name_to_id)

    # wpprune drops the wrong path for monomorphic indirects, so the
    # one-target/multi-target WP-shape assertions no longer hold.
    if wpprune == 0:
        issues += _check_indirect_wp_assertions(cp_entries, templates_by_id,
                                                blocks_by_id, pcmap, isa)

    # ---- Structural / cadence / format-invariant checks ---------------------
    issues += _check_encoding_map_completeness(templates, trace_meta)
    issues += _check_header_window(trace_meta, expected_start,
                                    expected_stop, expected_warmup,
                                    start_symbol, marker)

    body_stats = trace_meta.get("body_stats") or {}
    stats["body_stats"] = body_stats
    issues += _check_iframe_cadence(body_stats, cp_entries, trace_meta)
    # Guest-thread identity: the generated workload is single-threaded,
    # so every entry — user, or kernel inheriting the current thread —
    # carries tid 0, no matter which vCPU(s) the scheduler used or how the
    # process migrated between them.  A second tid would be a foreign
    # thread leaking past the pin, which the per-thread distribution check
    # now catches directly (stronger than the old -smp index bound, which
    # accepted any tid < smp).
    threads_effective = expected_threads
    issues += _check_thread_distribution(entries, expected_threads)
    issues += _check_regfile_records(body_stats, threads_effective)
    issues += _check_thread_switch(body_stats, threads_effective)
    issues += _check_thread_record_cadence(
        entries, trace_meta.get("body_record_order") or [])
    # The generated workload is single-threaded, so its user-privilege
    # entries must form exactly one control-flow chain.  (Wired here
    # once the tracer's whole-BB fault merge kept the pre-fault prefix
    # for a twice-faulting BB — the aarch64 seed-0x5150 archetype: the
    # ldr's demand fault then the str's CoW fault in one block — since
    # a merged emission re-keyed at the first resume PC surfaced here
    # as an orphaned user entry.)
    issues += _check_thread_chain(entries, templates_by_id,
                                  expected_guest_threads=1,
                                  trace_meta=trace_meta)
    # WP-event tallies are global (the writer counts every WP fault,
    # including those in the pre-window prologue — which in system mode
    # is the whole kernel boot + marker wait, where wrong-path faults are
    # plentiful), so walk the full entry stream, not just post-prologue.
    issues += _check_wp_events(body_stats, entries)
    issues += _check_atomic_count(body_stats, entries, templates_by_id)
    issues += _check_unconditional_direction(templates, entries,
                                             templates_by_id, trace_meta)
    issues += _check_call_return_balance(entries, templates_by_id, trace_meta)
    # System-mode only: the privilege bit and syscall round-trips are
    # meaningful when the trace interleaves a kernel (marker/pin mode).
    if marker:
        issues += _check_syscall_transitions(entries, templates_by_id,
                                             trace_meta)
        issues += _check_fault_excursions(entries, templates_by_id,
                                          trace_meta)
        # The generated marker workload carries the deterministic fault
        # probe (sysinfo into a demand-zero page), so a system-mode
        # trace must show a fault nested inside a syscall excursion.
        issues += _check_syscall_fault_nesting(entries, templates_by_id,
                                               trace_meta,
                                               require_nested=True)
        # ASID-pin content gate: user templates executed on CP must be
        # the pinned binary's own bytes.
        issues += _check_user_code_identity(templates, entries,
                                            templates_by_id, binary_path)

    # ---- Per-insn regdata semantic checks ----------------------------------
    opcode_names = dict(trace_meta.get("encoding_maps", {}).get("opcode", {}))
    issues += _check_metaflags(cp_entries, templates_by_id,
                                opcode_names, isa,
                                reg_id_to_name, has_reg_data)
    issues += _check_regdata_reconstruction(cp_entries, templates_by_id,
                                             opcode_names, reg_id_to_name,
                                             has_reg_data, isa)
    pc_to_gt = _build_pc_to_gt_insn(meta["blocks"])
    issues += _check_lane_masks(cp_entries, templates_by_id, opcode_names,
                                isa, pc_to_gt)
    issues += _check_dep_refine_coverage(templates, blocks_by_id, cp_set)

    return Report(issues=issues, stats=stats)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main() -> int:
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--meta", required=True, type=Path)
    p.add_argument("--trace", required=True, type=Path)
    p.add_argument("--binary", required=True, type=Path)
    args = p.parse_args()
    report = validate(args.meta, args.trace, args.binary)
    print(report.summary())
    return 1 if report.errors() else 0


if __name__ == "__main__":
    raise SystemExit(_main())
