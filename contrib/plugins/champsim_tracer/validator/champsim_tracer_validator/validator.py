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
                     isa: str = "x86_64") -> list[Issue]:
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

        # ---- 3. Build expected and actual multisets for component. ----
        expected: list[tuple[str, int, int, bool]] = []
        for bid in sorted(comp_blocks):
            for m in blocks_by_id[bid].get("memops", []):
                expected.append(
                    (m["kind"], int(m["arena_u64_index"]), int(m["data"]),
                     bool(m.get("optional", False)))
                )
        actual: list[tuple[str, int, int]] = []
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
                    _dyn_data_int(dp),
                ))

        required_ctr = Counter((kind, off, data)
                               for kind, off, data, optional in expected
                               if not optional)
        optional_ctr = Counter((kind, off, data)
                               for kind, off, data, optional in expected
                               if optional)
        act_ctr = Counter(actual)
        missing = list((required_ctr - act_ctr).elements())
        extra = list((act_ctr - required_ctr - optional_ctr).elements())
        if not missing and not extra:
            continue

        tmpl_label = "+".join(f"t{t}" for t in sorted(comp_tmpls))
        blk_label = "/".join(f"blk_{b}" for b in sorted(comp_blocks))
        issues.append(Issue(
            "cp_memops", "error",
            f"templates {{{tmpl_label}}} ({blk_label}): "
            f"memop multiset mismatch "
            f"(required={sum(required_ctr.values())} "
            f"optional={sum(optional_ctr.values())} act={len(actual)} "
            f"missing={len(missing)} extra={len(extra)})\n"
            f"      required: {list(required_ctr.elements())}\n"
            f"      optional: {list(optional_ctr.elements())}\n"
            f"      actual  : {actual}\n"
            f"      missing : {missing}\n"
            f"      extra   : {extra}",
            {
                "template_ids": sorted(comp_tmpls),
                "cp_blocks": sorted(comp_blocks),
                "missing_first5": missing[:5],
                "extra_first5": extra[:5],
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
            if isa in ("riscv64", "mipsel"):
                have_access_info = False
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

            if isa not in ("riscv64", "mipsel"):
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
            if isa == "riscv64" and mnemonic in ("auipc", "lui", "jal"):
                n_skipped += 1
                continue
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
                             cp_pos_offset: int = 0) -> list[Issue]:
    """For every CP position predicted to fork, walk the trace's
    ``wp_entries`` for that block's TB and compare the distinct-block
    sequence against the predicted ``wp_chain`` as a prefix.

    The predicted chain is trimmed to the plugin's per-WP instruction
    budget (``wp_insn_budget``) using each block's static instruction
    count. The active generator model represents loops as explicit CFG
    cycles, so repeated iterations appear as repeated block visits
    rather than as in-block backedges.
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
        for wp in e.get("wp_entries", []):
            wp_raw.extend(
                bid for (bid, _) in template_runs.get(wp["template_id"], [])
            )
            actual_sim_insns += int(wp.get("n_insns", 0) or 0)
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
            # MIPS user binaries pull in many libgcc soft-float and
            # software int-div helpers whose body insns the validator
            # cannot enumerate from `blk_*` symbols.  Those helpers'
            # insns *are* counted by the plugin toward sim_insns, so
            # the predicted chain over-shoots the plugin's actual
            # output.  For MIPS only, accept any truncation as long
            # as the plugin's sim_insns reached the depth budget.
            # All other ISAs must match the predicted length exactly.
            if isa.startswith("mips") and actual_sim_insns >= wp_insn_budget:
                continue
            issues.append(Issue(
                "wrong_path_chains", "error",
                f"WP at CP pos {cp_pos} (blk_{last_cp_bid}) truncated: "
                f"plugin emitted {len(actual_wp)} blocks "
                f"(sim_insns={actual_sim_insns}, budget={wp_insn_budget}); "
                f"predicted {len(exp_chain)}",
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
                     "sync_hint", "body_tag", "header_flag",
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


def _check_header_window(trace_meta: dict,
                         expected_start: int | None,
                         expected_stop: int | None,
                         expected_warmup: int | None,
                         start_symbol: str | None = None) -> list[Issue]:
    """Cross-check the header's start/warmup/total_target_insns
    against the values the caller asked the tracer to use.

    When @start_symbol is set, the exact icount the symbol resolves
    to is not predictable, so this check only asserts start_insn > 0
    and the total/warmup invariants."""
    issues: list[Issue] = []
    actual_start  = int(trace_meta.get("start_insn", 0))
    actual_warm   = int(trace_meta.get("warmup_insns", 0))
    actual_total  = int(trace_meta.get("total_target_insns", 0))

    if start_symbol is not None:
        # Symbol-based start: just assert that the trace actually fired
        # (start_insn > 0 means the symbol was reached).
        if actual_start == 0:
            issues.append(Issue(
                "header_window", "error",
                f"trace was launched with start-symbol={start_symbol!r} "
                f"but start_insn=0 in header; the symbol was never hit "
                f"(typo or weak/visibility-hidden symbol?)",
                {"start_symbol": start_symbol,
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
    """
    walk_faults  = 0
    walk_translu = 0
    for e in cp_entries:
        for wp in e.get("wp_entries") or []:
            if wp.get("fault"):
                walk_faults += 1
            if wp.get("translation_unavailable"):
                walk_translu += 1

    body_faults  = int(body_stats.get("fault_count", 0))
    body_translu = int(body_stats.get("translation_unavail_count", 0))
    if (walk_faults, walk_translu) != (body_faults, body_translu):
        return [Issue(
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
    return [Issue(
        "wp_events", "info",
        f"WP events: fault={body_faults}, "
        f"translation_unavail={body_translu}",
        {"fault": body_faults, "translation_unavail": body_translu},
    )]


def _check_thread_switch_absent(body_stats: dict,
                                expected_threads: int = 1) -> list[Issue]:
    """Single-thread test programs must never produce BODY_TAG_THREAD_SWITCH
    records.  Multi-thread traces are expected to; multi-thread runs
    must produce at least one switch (otherwise the threads never
    interleaved and we aren't actually testing multi-thread tracing)."""
    actual = int(body_stats.get("thread_switch_count", 0))
    if expected_threads == 1 and actual != 0:
        return [Issue(
            "thread_switch", "error",
            f"thread_switch_count={actual} on a single-thread trace; "
            f"writer should not emit BODY_TAG_THREAD_SWITCH when there "
            f"is only one vCPU contributing entries",
            {"actual": actual},
        )]
    if expected_threads > 1 and actual == 0:
        return [Issue(
            "thread_switch", "error",
            f"expected multi-thread trace ({expected_threads} threads) "
            f"but thread_switch_count=0; no thread interleaving was "
            f"captured — qemu-user may have run threads serially or "
            f"the program never spawned the second thread",
            {"actual": actual, "expected_threads": expected_threads},
        )]
    return [Issue(
        "thread_switch", "info",
        f"thread_switch_count={actual} (expected_threads={expected_threads})",
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


def _check_sync_hints(body_stats: dict,
                      all_entries: list[dict],
                      templates_by_id: dict[int, dict],
                      trace_meta: dict) -> list[Issue]:
    """Verify the writer's aggregated sync_hint_counts (BODY_STATS)
    matches the per-template-insn sync_hint values rolled across
    every CP+WP entry in the body stream (including prologue —
    body_stats aggregates everything, not just post-cp_start).

    Any divergence means the writer's runtime aggregation disagrees
    with what its own templates declare, which would be a tracer bug
    (template_id flag-byte vs entry-time stats counter).
    """
    expected: dict[int, int] = {}
    # Match the writer's BodyStats aggregation: walk *every* insn in
    # every template touched by CP+WP entries (writer iterates the
    # full template even when WP truncates after a fault).
    def _count(tmpl_id: int) -> None:
        t = templates_by_id.get(int(tmpl_id))
        if t is None:
            return
        for ins in t.get("insns") or []:
            h = int(ins.get("sync_hint", 0))
            expected[h] = expected.get(h, 0) + 1

    for e in all_entries:
        _count(int(e["template_id"]))
        for wp in e.get("wp_entries") or []:
            _count(int(wp["template_id"]))

    actual = {int(k): int(v) for k, v in (
        body_stats.get("sync_hint_counts") or {}).items()}
    name_map = trace_meta.get("sync_hint_names") or {}

    if expected != actual:
        def named(d):
            return {name_map.get(k, f"SYNC_{k}"): v for k, v in d.items()}
        return [Issue(
            "sync_hints", "error",
            f"sync_hint_counts disagree with per-template walk: "
            f"writer={named(actual)} static_walk={named(expected)}",
            {"actual": actual, "expected": expected},
        )]
    # Surface the per-name distribution so atomic-emitting workloads
    # are observable in the report.
    return [Issue(
        "sync_hints", "info",
        f"sync_hint distribution matches static template walk: "
        f"{ {name_map.get(k, f'SYNC_{k}'): v for k, v in actual.items()} }",
        {"counts": actual},
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
        has_reg_data: bool) -> list[Issue]:
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

        for ipos, I in enumerate(tmpl.get("insns") or []):
            op_id = int(I.get("opcode", 0))
            op_name = opcode_names.get(op_id, "")
            srcs = [int(r) for r in (I.get("src_regs") or [])]
            dsts = [int(r) for r in (I.get("dst_regs") or [])]
            gpr_dsts = [r for r in dsts
                        if flags_id is None or r != flags_id]
            # Atomic RMW (lock xadd, ldadd, amoadd, ll/sc, …) has the
            # dst-reg semantically loaded from memory rather than
            # computed from src operands.  The sync_hint marker is
            # what distinguishes these; skip reconstruction for them.
            sync_hint = int(I.get("sync_hint", 0))
            if sync_hint != 0:
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
            # 2-op form: the dst-also-src reg is the minuend → put it
            # first.  3-op form: src[0] is already the minuend.
            ordered_srcs = list(srcs)
            if not commutative:
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
            expected = compute(a & mask, b & mask, mask)
            for r in gpr_dsts:
                snap = snap_idx.get((ipos, r))
                if snap is None:
                    continue
                got = _reg_snap_value(snap) & mask
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


def validate_structural(trace_path: Path,
                        expected_threads: int = 1) -> Report:
    """Decode @trace_path and run only the checks that don't depend on
    the generator's meta.json (correct_path, blocks, wrong_paths).

    Used by the segmentation test, where each per-simpoint .cst file
    is a standalone trace that begins mid-program and shouldn't be
    asked to validate the original CFG.  Asserts the trace is
    internally consistent: encoding maps are complete, sync_hints and
    wp_events agree between writer-aggregate and per-entry walk,
    IFRAMEs match their ENTRYs (already enforced by the decoder),
    REGFILE record(s) present, no unexpected thread_switch on
    single-thread runs.
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
    issues += _check_iframe_cadence(body_stats, entries, trace_meta)
    issues += _check_regfile_records(body_stats, expected_threads)
    issues += _check_thread_switch_absent(body_stats, expected_threads)
    issues += _check_thread_distribution(entries, expected_threads)
    issues += _check_wp_events(body_stats, entries)
    issues += _check_sync_hints(body_stats, entries,
                                 templates_by_id, trace_meta)
    return Report(issues=issues, stats=stats)


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
             start_symbol: str | None = None) -> Report:
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
                                   meta.get("isa", "x86_64"))

    templates_by_id = {t["template_id"]: t for t in templates}
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

    has_reg_data = bool(trace_meta.get("has_reg_data"))
    issues += _check_reg_value_assertions(cp_entries, templates_by_id,
                                          blocks_by_id, pcmap, cp_set,
                                          has_reg_data, reg_id_to_name)
    issues += _check_expected_reg_sets(cp_entries, templates_by_id,
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

    issues += _check_wrong_path_chains(cp_entries, template_runs,
                                       cp_block_seq, correct_path,
                                       meta["wrong_paths"],
                                       blocks_by_id,
                                       wp_insn_budget=wp_insn_budget,
                                       helper_leaf_n_insns=int(meta.get("helper_leaf_n_insns", 0) or 0),
                                       isa=isa,
                                       cp_pos_offset=cp_pos_offset)

    issues += _check_indirect_wp_assertions(cp_entries, templates_by_id,
                                            blocks_by_id, pcmap, isa)

    # ---- Structural / cadence / format-invariant checks ---------------------
    issues += _check_encoding_map_completeness(templates, trace_meta)
    issues += _check_header_window(trace_meta, expected_start,
                                    expected_stop, expected_warmup,
                                    start_symbol)

    body_stats = trace_meta.get("body_stats") or {}
    stats["body_stats"] = body_stats
    issues += _check_iframe_cadence(body_stats, cp_entries, trace_meta)
    issues += _check_regfile_records(body_stats, expected_threads)
    issues += _check_thread_switch_absent(body_stats, expected_threads)
    issues += _check_thread_distribution(entries, expected_threads)
    issues += _check_wp_events(body_stats, cp_entries)
    issues += _check_sync_hints(body_stats, entries,
                                 templates_by_id, trace_meta)

    # ---- Per-insn regdata semantic checks ----------------------------------
    opcode_names = dict(trace_meta.get("encoding_maps", {}).get("opcode", {}))
    issues += _check_metaflags(cp_entries, templates_by_id,
                                opcode_names, isa,
                                reg_id_to_name, has_reg_data)
    issues += _check_regdata_reconstruction(cp_entries, templates_by_id,
                                             opcode_names, reg_id_to_name,
                                             has_reg_data)

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
