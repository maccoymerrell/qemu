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
        # 32-bit ISAs lower `uint64_t` arena accesses to a pair of
        # 32-bit memops at the low and high halves of an 8-byte slot.
        # On 64-bit ISAs the compiler issues a single 8-byte memop, so
        # pair-merging must be skipped (otherwise two unrelated 4-byte
        # accesses to adjacent u32 slots could be merged spuriously).
        is_32bit_isa = isa in ("mipsel", "mips", "riscv32", "armhf", "i386")
        for tid in sorted(comp_tmpls):
            raw_dps = list(first_entry[tid].get("dyn_params", []))
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
            f"missing={len(missing)} extra={len(extra)})\n"
            f"      expected: {expected}\n"
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
    whose schema (n_loads / n_stores) matches the access kind.

    The decoder reconstructs `insn_index` by walking the template's
    static (n_loads, n_stores) schema in program order; if the plugin
    writes the schema and the dyn_param stream out of sync, the decoder
    will still produce *some* mapping, but it will be wrong.  This
    check catches that class of plugin bug:

      * `insn_index` out of range  → tracer bug
      * dp.type_name=='load' but insns[idx].n_loads == 0  → mis-attribution
      * dp.type_name=='store' but insns[idx].n_stores == 0 → mis-attribution

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

        # v1.6 contract: BBs are immutable, and per-insn (n_loads,
        # n_stores) is exact for non-variable_memop insns; variable
        # insns carry per-entry counts via the §4.1 preamble.  The
        # decoder reconstructs `insn_index` by walking that schema in
        # template order.  An out-of-range (-1) `insn_index` therefore
        # means the runtime emitted more dyn_params than the schema's
        # total declared memops — a tracer bug (mnemonic
        # misclassification or missing variable_memop flag).  Emit a
        # one-shot full dump of the template + dyn_params so the
        # offending insn is identifiable from the validator output.
        dps = list(e.get("dyn_params", []))
        sch_total = sum(int(ins.get("n_loads", 0)) +
                        int(ins.get("n_stores", 0))
                        for ins in insns)
        any_variable = any(ins.get("variable_memop", False)
                           for ins in insns)
        out_of_range = [dp for dp in dps if int(dp.insn_index) < 0
                        or int(dp.insn_index) >= n]

        if out_of_range:
            schema_lines = []
            for i, ins in enumerate(insns):
                schema_lines.append(
                    f"    insn[{i:2d}] pc=0x{int(ins['pc']):x} "
                    f"opcode={ins.get('opcode', '?')} "
                    f"n_loads={int(ins.get('n_loads', 0))} "
                    f"n_stores={int(ins.get('n_stores', 0))} "
                    f"variable_memop={int(bool(ins.get('variable_memop', False)))}"
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
                f"n_insns={n}, schema_total_memops={sch_total}, "
                f"variable_memop_present={int(any_variable)}, "
                f"dyn_params_received={len(dps)}):\n"
                + "\n".join(schema_lines)
                + "\n  dyn_params:\n"
                + "\n".join(dp_lines)
            )
            issues.append(Issue(
                "memop_insn_attribution", "error",
                f"template t{tid}: {len(out_of_range)} dyn_param(s) "
                f"could not be attributed by schema walk "
                f"(schema_total={sch_total}, dp_count={len(dps)}). "
                f"Likely tracer bug: an opcode in this BB has wrong "
                f"static (n_loads, n_stores) or is missing "
                f"variable_memop.\n{detail}",
                {"template_id": tid, "n_insns": n,
                 "schema_total_memops": sch_total,
                 "dyn_params_received": len(dps),
                 "variable_memop_present": any_variable,
                 "schema": [
                     {"pc": int(ins["pc"]),
                      "opcode": ins.get("opcode"),
                      "n_loads": int(ins.get("n_loads", 0)),
                      "n_stores": int(ins.get("n_stores", 0)),
                      "variable_memop": bool(ins.get("variable_memop", False))}
                     for ins in insns],
                 "dyn_params": [
                     {"kind": dp.type_name,
                      "insn_index": int(dp.insn_index),
                      "value": int(dp.value)}
                     for dp in dps]},
            ))
            # Skip per-dp mis-attribution checks: indices are unreliable
            # once schema walk overflowed.
            continue

        for dp in dps:
            idx = int(dp.insn_index)
            kind = dp.type_name
            ins = insns[idx]
            n_l = int(ins.get("n_loads", 0))
            n_s = int(ins.get("n_stores", 0))
            if kind == "load" and n_l == 0:
                issues.append(Issue(
                    "memop_insn_attribution", "error",
                    f"template t{tid}: load dyn_param attributed to "
                    f"insn #{idx} at pc=0x{int(ins['pc']):x} which the "
                    f"trace schema declares (n_loads=0, n_stores={n_s})",
                    {"template_id": tid, "insn_index": idx,
                     "pc": int(ins["pc"]), "kind": kind,
                     "n_loads": n_l, "n_stores": n_s},
                ))
            elif kind == "store" and n_s == 0:
                issues.append(Issue(
                    "memop_insn_attribution", "error",
                    f"template t{tid}: store dyn_param attributed to "
                    f"insn #{idx} at pc=0x{int(ins['pc']):x} which the "
                    f"trace schema declares (n_loads={n_l}, n_stores=0)",
                    {"template_id": tid, "insn_index": idx,
                     "pc": int(ins["pc"]), "kind": kind,
                     "n_loads": n_l, "n_stores": n_s},
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

        # Index reg-snaps by (insn_index, kind, reg_id) for O(1) lookup.
        snap_by_key: dict[tuple, dict] = {}
        for s in reg_snaps:
            snap_by_key[(s["insn_index"], s["kind"], s["reg_id"])] = s

        for dp in dyn:
            i = int(getattr(dp, "insn_index", -1))
            if i < 0 or i >= len(insns):
                continue
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

    seen_ids: set[int] = set()
    for t in templates:
        for ins in t.get("insns", []):
            seen_ids.add(int(ins["branch_type"]))
    seen_names = sorted(branch_names.get(i, f"BRANCH_{i}")
                        for i in seen_ids)

    asserted: set[str] = set()
    for b in blocks_by_id.values():
        if b["block_id"] not in cp_set:
            continue
        for bt in b.get("asserted_branch_types", []) or []:
            asserted.add(bt.replace("BRANCH_", ""))
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
                reachable.add(br[len("BRANCH_"):])
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
                             isa: str = "") -> list[Issue]:
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

        key = str(cp_pos)
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
             binary_path: Path,
             wp_insn_budget: int = 64) -> Report:
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

    # Per-instruction memop attribution: ensure every dyn_param's
    # insn_index points at an instruction whose schema declares the
    # matching access kind.  Independent of arena (works even when no
    # `arena` symbol is present).
    templates_by_id = {t["template_id"]: t for t in templates}
    issues += _check_memop_insn_attribution(cp_entries, template_runs,
                                            templates_by_id, cp_set)

    # Address-recompute: only meaningful when reg-data was emitted.
    isa = meta.get("isa", "x86_64")
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

    issues += _check_wrong_path_chains(cp_entries, template_runs,
                                       cp_block_seq, correct_path,
                                       meta["wrong_paths"],
                                       blocks_by_id,
                                       wp_insn_budget=wp_insn_budget,
                                       helper_leaf_n_insns=int(meta.get("helper_leaf_n_insns", 0) or 0),
                                       isa=isa)

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
