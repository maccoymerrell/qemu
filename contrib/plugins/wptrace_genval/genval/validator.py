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
# Decoder import (champsim_tracer_decode.py is a sibling of this package)
# ---------------------------------------------------------------------------

_PLUGIN_DIR = Path(__file__).resolve().parent.parent.parent
_DECODE_PATH = _PLUGIN_DIR / "champsim_tracer_decode.py"


def _load_decoder():
    spec = importlib.util.spec_from_file_location(
        "champsim_tracer_decode", _DECODE_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
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
                             cp_set: set[int]) -> list[Issue]:
    """For every CP block, sum the distinct PCs covered across templates
    and compare to `ground_truth.n_insns`.

    The champsim_tracer plugin merges straight-line successors into a single TB
    sometimes, so we cannot use a single template's n_insns directly;
    instead we union all PCs seen in the trace that fall in the block's
    span and compare the count.
    """
    seen_pcs: dict[int, set[int]] = {bid: set() for bid in cp_set}
    for t in templates:
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
            "cp_execution_order", "warning",
            f"trace CP has {len(cp_block_seq) - len(correct_path)} "
            f"extra blocks after predicted end",
        ))
    return issues


def _check_cp_memops(entries: list[dict],
                     template_runs: dict[int, list[tuple[int, int]]],
                     blocks_by_id: dict[int, dict],
                     cp_set: set[int],
                     arena_addr: int,
                     arena_size: int | None = None) -> list[Issue]:
    """Memop/value check, aggregated by (template, block) bipartite
    component.

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
    """
    issues: list[Issue] = []

    # ---- 1. Build bipartite adjacency restricted to CP. ----
    tmpl_to_blocks: dict[int, set[int]] = {}
    block_to_tmpls: dict[int, set[int]] = {}
    first_entry: dict[int, dict] = {}

    for e in entries:
        tid = e["template_id"]
        if tid in first_entry:
            continue
        runs = template_runs.get(tid, [])
        cp_blocks = {bid for (bid, _) in runs if bid in cp_set}
        if not cp_blocks:
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

        # ---- 3. Build expected and actual multisets for component. ----
        expected: list[tuple[str, int, int]] = []
        for bid in sorted(comp_blocks):
            for m in blocks_by_id[bid].get("memops", []):
                expected.append(
                    (m["kind"], int(m["arena_u64_index"]), int(m["data"]))
                )
        actual: list[tuple[str, int, int]] = []
        for tid in sorted(comp_tmpls):
            raw_dps = list(first_entry[tid].get("dyn_params", []))
            # MIPS32 (and any 32-bit ISA) lowers `uint64_t` arena
            # accesses to a pair of 32-bit memops at the low and high
            # halves of an 8-byte slot.  The compiler may reorder the
            # halves freely, so we pair every 4-byte access at offset 8k
            # (low half) with any same-kind 4-byte access at offset 8k+4
            # (high half) within the same template's dyn_param list,
            # recombining them into a single 8-byte (kind, off, value)
            # tuple matching what blocks.py emits via _volatile_*_u64.
            consumed = [False] * len(raw_dps)

            def _arena_off4(va: int) -> int:
                """Return arena offset in 4-byte units, or -1."""
                rel = va - arena_addr
                if rel < 0 or rel % 4 != 0:
                    return -1
                if arena_size is not None and rel >= arena_size:
                    return -1
                return rel // 4

            # First pass: pair each 8-byte-aligned 4-byte access (low
            # half) with a same-kind partner at the next 4-byte slot
            # (high half).
            for i, dp in enumerate(raw_dps):
                if consumed[i] or int(dp.data_size) != 4:
                    continue
                off4 = _arena_off4(int(dp.value))
                if off4 < 0 or off4 % 2 != 0:
                    continue
                hi_va = int(dp.value) + 4
                for j in range(len(raw_dps)):
                    if (j == i or consumed[j]
                            or int(raw_dps[j].data_size) != 4
                            or raw_dps[j].type_name != dp.type_name
                            or int(raw_dps[j].value) != hi_va):
                        continue
                    lo = int(dp.data_lo) & 0xFFFFFFFF
                    hi = int(raw_dps[j].data_lo) & 0xFFFFFFFF
                    actual.append(
                        (dp.type_name, off4 // 2, (hi << 32) | lo)
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
                actual.append((
                    dp.type_name,
                    off,
                    int(dp.data_lo),
                ))

        exp_ctr = Counter(expected)
        act_ctr = Counter(actual)
        if exp_ctr == act_ctr:
            continue

        missing = list((exp_ctr - act_ctr).elements())
        extra = list((act_ctr - exp_ctr).elements())
        tmpl_label = "+".join(f"t{t}" for t in sorted(comp_tmpls))
        blk_label = "/".join(f"blk_{b}" for b in sorted(comp_blocks))
        issues.append(Issue(
            "cp_memops", "error",
            f"templates {{{tmpl_label}}} ({blk_label}): "
            f"memop multiset mismatch "
            f"(exp={len(expected)} act={len(actual)} "
            f"missing={len(missing)} extra={len(extra)})",
            {
                "template_ids": sorted(comp_tmpls),
                "cp_blocks": sorted(comp_blocks),
                "missing_first5": missing[:5],
                "extra_first5": extra[:5],
            },
        ))
    return issues


def _check_wrong_path_chains(entries: list[dict],
                             template_runs: dict[int, list[tuple[int, int]]],
                             cp_block_seq: list[int],
                             correct_path: list[int],
                             wrong_paths: dict,
                             blocks_by_id: dict[int, dict],
                             wp_insn_budget: int = 64) -> list[Issue]:
    """For every CP position predicted to fork, walk the trace's
    ``wp_entries`` for that block's TB and compare the distinct-block
    sequence against the predicted ``wp_chain`` as a prefix.

    The predicted chain is trimmed to the plugin's per-WP instruction
    budget (``wp_insn_budget``) using each block's compiled-insn count
    from ``ground_truth.n_insns``, so generator predictions match the
    plugin's actual depth semantics.
    """
    issues: list[Issue] = []
    cp_pos = -1
    last_cp_bid: int | None = None

    def _trim_by_insn_budget(chain: list[int]) -> list[int]:
        out: list[int] = []
        total = 0
        for bid in chain:
            # Plugin checks `sim_insns < max_depth` BEFORE executing,
            # so a block whose start keeps us under budget is executed
            # in full even if it overshoots.
            if total >= wp_insn_budget:
                break
            out.append(bid)
            n = blocks_by_id.get(bid, {}).get(
                "ground_truth", {}).get("n_insns", 0)
            total += n
        return out

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

        key = str(cp_pos)
        if key not in wrong_paths:
            continue

        exp_chain = list(wrong_paths[key].get("wp_chain", []))
        exp_chain = _trim_by_insn_budget(exp_chain)
        wp_raw: list[int] = []
        for wp in e.get("wp_entries", []):
            wp_raw.extend(
                bid for (bid, _) in template_runs.get(wp["template_id"], [])
            )
        actual_wp = _collapse_runs(wp_raw)

        n = min(len(actual_wp), len(exp_chain))
        first_fail = -1
        for j in range(n):
            if actual_wp[j] != exp_chain[j]:
                first_fail = j
                break
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
            # Plugin's WP depth budget counts ALL TBs executed (including
            # shared prologue / indirect-call trampolines that are not in
            # our user CFG), so the plugin commonly stops a block or two
            # before our purely-user-graph prediction.
            issues.append(Issue(
                "wrong_path_chains", "warning",
                f"WP at CP pos {cp_pos} (blk_{last_cp_bid}) truncated: "
                f"plugin emitted {len(actual_wp)} blocks, "
                f"predicted {len(exp_chain)} (plugin depth cap reached)",
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
# Top-level validate()
# ---------------------------------------------------------------------------

def validate(meta_path: Path, trace_path: Path,
             binary_path: Path) -> Report:
    meta = json.loads(meta_path.read_text())
    dec = _load_decoder()
    _trace_meta, templates, entries = dec.decode_champsim_tracer(trace_path)

    pcmap = PcMap(meta["blocks"])
    template_runs: dict[int, list[tuple[int, int]]] = {
        t["template_id"]: pcmap.template_runs(t) for t in templates
    }

    correct_path = list(meta["correct_path"])
    cp_set = set(correct_path)
    blocks_by_id = {b["block_id"]: b for b in meta["blocks"]}

    stats: dict = {
        "trace_templates": len(templates),
        "trace_entries": len(entries),
        "meta_blocks": len(meta["blocks"]),
        "meta_cp_length": len(correct_path),
        "pc_spans_loaded": len(pcmap._spans),
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
    # prefix of `correct_path`, the missing suffix is the dropped tail.
    plugin_drop_tail: list[int] = []
    if cp_block_seq and len(cp_block_seq) < len(correct_path):
        if cp_block_seq == correct_path[:len(cp_block_seq)]:
            plugin_drop_tail = correct_path[len(cp_block_seq):]

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
    issues += _check_cp_execution_order(correct_path, cp_block_seq_effective)

    # Disassembly-driven first-order sanity checks.
    issues += _check_template_raw_bytes(templates, blocks_by_id)
    issues += _check_block_insn_counts(templates, blocks_by_id, pcmap,
                                       cp_set)
    issues += _check_block_assertions(templates, blocks_by_id, pcmap,
                                      cp_set)

    arena_info = _find_arena_address(binary_path)
    if arena_info is None:
        issues.append(Issue(
            "cp_memops", "warning",
            "no `arena` symbol in binary; skipping memop/value check",
        ))
    else:
        arena_addr, arena_size = arena_info
        stats["arena_addr"] = f"0x{arena_addr:x}"
        stats["arena_size"] = arena_size
        issues += _check_cp_memops(cp_entries, template_runs,
                                   blocks_by_id, cp_set, arena_addr,
                                   arena_size)

    issues += _check_wrong_path_chains(cp_entries, template_runs,
                                       cp_block_seq, correct_path,
                                       meta["wrong_paths"],
                                       blocks_by_id)

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
