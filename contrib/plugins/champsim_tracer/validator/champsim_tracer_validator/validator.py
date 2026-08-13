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


def _load_pt_load_segments(binary_path: "Path | None"
                           ) -> list[tuple[int, bytes]]:
    """Return [(virtual_address, content_bytes), ...] for every PT_LOAD
    segment of @binary_path, or [] if it can't be parsed (missing LIEF,
    bad path, etc.) — callers treat that as "no fallback available", not
    an error, since the labeled-block ground truth still covers the
    templates it covers."""
    if binary_path is None:
        return []
    try:
        import lief
    except ImportError:
        return []
    img = lief.parse(str(binary_path))
    if img is None:
        return []
    # LIEF >= 0.17 nests the enum as Segment.TYPE; older releases used
    # lief.ELF.SEGMENT_TYPES (same compat split as elsewhere in this file).
    seg_load = (getattr(getattr(lief.ELF.Segment, "TYPE", None), "LOAD", None)
                or lief.ELF.SEGMENT_TYPES.LOAD)
    return [(int(seg.virtual_address), bytes(seg.content))
            for seg in img.segments if seg.type == seg_load]


def _check_template_raw_bytes(templates: list[dict],
                              blocks_by_id: dict[int, dict],
                              binary_path: "Path | None" = None
                              ) -> list[Issue]:
    """Byte-for-byte compare each template insn's `raw_bytes` against
    ground truth for the same PC.

    This catches any first-order corruption in the champsim_tracer binary format
    (wrong size encoding, endian mix-ups, truncated bytes, merged-insn
    bugs, etc.) before any higher-level check runs — a divergence here
    makes all downstream checks meaningless.

    Two tiers of ground truth, so coverage is never gated on generator
    labeling:

      1. The analyzer's per-block disassembly (`ground_truth`, keyed by
         `blk_N` symbol) — exact, and carries mnemonic/op_str for the
         error message.
      2. For any template PC that tier 1 doesn't index (there is no
         requirement that every byte of user code sit inside a labeled
         `blk_N` span — e.g. the `_start`/CRT prologue that runs before
         the first block label runs on the correct path like any other
         user code and is just as much a target for corruption) — the
         compiled ELF's own PT_LOAD bytes at that virtual address are the
         authoritative reference.  A PC outside every PT_LOAD segment is
         genuinely unknowable from the binary alone (vdso, JIT'd/kernel
         code) and is skipped, but counted, rather than silently ignored.
    """
    # Index ground-truth instructions by PC for O(1) lookup.
    gt_by_pc: dict[int, dict] = {}
    for b in blocks_by_id.values():
        gt = b.get("ground_truth")
        if not gt:
            continue
        for ins in gt["insns"]:
            gt_by_pc[int(ins["pc"])] = ins

    image_loads = _load_pt_load_segments(binary_path)

    def _image_bytes(va: int, n: int) -> bytes | None:
        for base, blob in image_loads:
            if base <= va and va + n <= base + len(blob):
                return blob[va - base: va - base + n]
        return None

    issues: list[Issue] = []
    mismatches = 0
    labeled_checked = 0
    fallback_checked = 0
    unresolvable = 0
    for t in templates:
        # Kernel / kernel-context (CST_INSN_FLAG_SYSTEM) templates are not
        # in the compiled binary — no ground-truth bytes to compare.
        if t.get("is_system"):
            continue
        for ins in t.get("insns", []):
            pc = int(ins["pc"])
            trace_raw = bytes(ins["raw_bytes"])
            trace_bytes = trace_raw.hex()
            gt = gt_by_pc.get(pc)
            if gt is not None:
                labeled_checked += 1
                gt_bytes = gt["raw_bytes_hex"]
                context = f" [{gt['mnemonic']} {gt['op_str']}]"
                ref = "disasm"
            else:
                # Unlabeled template (no blk_N span covers this PC) —
                # fall back to the ELF image itself.
                expect = _image_bytes(pc, len(trace_raw))
                if expect is None:
                    unresolvable += 1
                    continue
                fallback_checked += 1
                gt_bytes = expect.hex()
                context = " [unlabeled/prologue template]"
                ref = "ELF image"
            if trace_bytes != gt_bytes:
                mismatches += 1
                if mismatches <= 10:
                    issues.append(Issue(
                        "template_raw_bytes", "error",
                        f"PC 0x{pc:x} (tmpl {t['template_id']}): "
                        f"trace bytes {trace_bytes!r} != "
                        f"{ref} bytes {gt_bytes!r}{context}",
                        {"template_id": t["template_id"],
                         "pc": pc,
                         "trace": trace_bytes,
                         "disasm": gt_bytes},
                    ))
    if mismatches > 10:
        issues.append(Issue(
            "template_raw_bytes", "error",
            f"...and {mismatches - 10} more raw-byte mismatches"))
    if not issues:
        issues.append(Issue(
            "template_raw_bytes", "info",
            f"{labeled_checked} labeled-block + {fallback_checked} "
            f"unlabeled/ELF-fallback instruction(s) byte-match ground "
            f"truth ({unresolvable} unresolvable PC(s) outside every "
            f"PT_LOAD segment skipped)",
            {"labeled_checked": labeled_checked,
             "fallback_checked": fallback_checked,
             "unresolvable": unresolvable}))
    return issues


def _fallthrough_shortfall_unexplained(
        bid: int, gt: dict, missing: set[int],
        templates: list[dict], pcmap: "PcMap",
        cond_branch_id: "int | None") -> set[int]:
    """Return the subset of `missing` block PCs NOT accounted for as the
    never-executed fall-through of an always-taken internal conditional
    branch whose wrong-path fork minted no chain.

    A block whose terminating conditional branch was observed ONLY taken
    (``nottaken_cp == nottaken_wp == 0``) never runs the instruction(s)
    between that branch and its in-block taken target on the correct path.
    The sole way those PCs enter the trace is a wrong-path excursion forking
    at the not-taken edge — and that excursion's FIRST speculative fetch can
    be transiently unavailable: in system mode QEMU declines a spec-mode
    fetch whose page is not TLB-resident (``cpu_plugin_exec_tb``'s
    non-faulting ``probe_access_flags`` returns ``TLB_INVALID_MASK``), so a
    faithful speculation takes no page-walk side effect.  The excursion then
    returns an empty chain and the plugin records a chain-level
    ``CST_WP_EVENT_TRANSLATION_UNAVAIL`` (``num_wp=0``) — honest on the wire,
    but the fall-through PCs appear in no template.  Because TLB residency at
    the instant of the fork is timing-dependent, this is nondeterministic:
    a re-trace of the same binary often mints the fall-through normally.

    Accept a shortfall of EXACTLY those PCs; every predicate below is read
    from the wire (the terminal conditional branch, its single target's
    ``nottaken_{cp,wp}`` counts, and the block-local not-taken span), so any
    other missing PC — or an overcount — is left for the caller to flag.
    """
    if cond_branch_id is None or not missing:
        return set(missing)
    start = int(gt["start_pc"])
    end = int(gt["end_pc"])
    explained: set[int] = set()
    for t in templates:
        if t.get("is_system"):
            continue
        insns = t.get("insns") or []
        if not insns:
            continue
        term = insns[-1]
        if term.get("branch_type") != cond_branch_id:
            continue
        bpc = int(term["pc"])
        if not (start <= bpc < end) or pcmap.lookup(bpc) != bid:
            continue
        tgts = (t.get("profile") or {}).get("targets") or []
        if len(tgts) != 1:
            continue
        tg = tgts[0]
        if int(tg.get("nottaken_cp", -1)) != 0 or \
                int(tg.get("nottaken_wp", -1)) != 0:
            continue
        taken_target = int(tg["pc"])
        fall_through = int(t.get("fall_through_pc", 0))
        # Strictly-internal forward conditional skip: the taken edge lands
        # inside the block ahead of the fall-through, so [fall_through,
        # taken_target) is the never-executed not-taken span.
        if not (start <= taken_target < end):
            continue
        if not (start <= fall_through < taken_target):
            continue
        for pc in missing:
            if fall_through <= pc < taken_target:
                explained.add(pc)
    return set(missing) - explained


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
    _, _branch_names = _load_name_tables()
    cond_branch_id = next(
        (i for i, n in _branch_names.items() if n == "COND_DIRECT"), None)
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
        # Wrong-path-fork-unavailability carve-out: accept an undercount that
        # is EXACTLY the never-executed fall-through of an always-taken
        # internal conditional branch whose wrong-path fork minted no chain
        # (a transient, honestly-recorded CST_WP_EVENT_TRANSLATION_UNAVAIL —
        # see _fallthrough_shortfall_unexplained).  Any unexplained missing
        # PC, or an overcount, still errors.
        if actual < expected:
            block_pcs = {
                int(ins["pc"], 16) if isinstance(ins["pc"], str)
                else int(ins["pc"])
                for ins in gt.get("insns", [])
            }
            missing = block_pcs - seen_pcs[bid]
            if missing and not _fallthrough_shortfall_unexplained(
                    bid, gt, missing, templates, pcmap, cond_branch_id):
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

    # Range note (format spec §4.2a): the writer's profile counters are
    # PER-STRETCH — a split execution's [0, k) and [k, n) entries each
    # bump exec_cp, and its one resolved branch is attributed to both
    # stretches (verified on the wire: a once-split, once-executed BB
    # reads exec_cp=2 taken_cp=2).  Entry-count comparisons below are
    # therefore already in the writer's own units; folding stretches
    # here would put the two sides in different units and false-fail.
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

    RANGE-AWARENESS (format spec §4.2a).  One dynamic execution of a
    template can arrive as SEVERAL ranged entries — the ``[0, k)``
    prefix carries the memops it observed, the ``[k, n)`` continuation
    the rest — so the representative is an execution GROUP, never a
    single entry: the first execution whose stretches tile ``[0, n)``,
    its dyn_params joined across the group's entries.  When no
    complete execution exists (the window closed mid-block on the only
    invocation), the group is the first opened one and the expected
    multiset is scoped to the instructions the group's declared ranges
    actually observed — an unobserved tail at a close is not a missing
    memop, the wire says explicitly it was cut (identity-less
    expecteds, which cannot be scoped, demote to optional there).
    """
    issues: list[Issue] = []
    templates_by_id = templates_by_id or {}

    # ---- 1. Build bipartite adjacency restricted to CP. ----
    # @rep_group maps tid -> the entries of the representative dynamic
    # execution (default for normal blocks: one execution, avoiding
    # counting the same memop pattern N times when a block sits inside
    # a loop).  Preference order: the first COMPLETE execution (ranges
    # tiling [0, n)); if none ever completes, the first opened group.
    # @all_entries maps tid -> list of every CP entry on that
    # template, used when at least one block in the bipartite
    # component opts into aggregate_fanout — true today for the REP-
    # iteration block, whose iter 2..N body entries live on
    # subsequent executions of the 1-insn self-loop sub-template.
    tmpl_to_blocks: dict[int, set[int]] = {}
    block_to_tmpls: dict[int, set[int]] = {}
    rep_group: dict[int, list[dict]] = {}
    rep_complete: dict[int, bool] = {}
    all_entries: dict[int, list[dict]] = {}
    # (tid, (thread, asid)) -> [entries-so-far, next expected start]
    open_group: dict[tuple[int, tuple], list] = {}

    for e in entries:
        tid = e["template_id"]
        runs = template_runs.get(tid, [])
        cp_blocks = {bid for (bid, _) in runs if bid in cp_set}
        if not cp_blocks:
            continue
        all_entries.setdefault(tid, []).append(e)
        if tid not in tmpl_to_blocks:
            tmpl_to_blocks[tid] = cp_blocks
            for bid in cp_blocks:
                block_to_tmpls.setdefault(bid, set()).add(tid)
        if rep_complete.get(tid):
            continue
        start, stop, n = _entry_range(e, templates_by_id.get(tid))
        ctx = (int(e.get("thread_id", 0) or 0),
               int(e.get("asid_index", 0) or 0))
        key = (tid, ctx)
        if start == 0:
            grp = [e]
            open_group[key] = [grp, stop]
            if tid not in rep_group:
                rep_group[tid] = grp        # alias; grows with the group
        else:
            og = open_group.get(key)
            if og is None or og[1] != start:
                continue                    # not a stretch of a tracked group
            og[0].append(e)
            og[1] = stop
            grp = og[0]
        if stop >= n:
            rep_group[tid] = grp
            rep_complete[tid] = True
            open_group.pop(key, None)

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
        # template in the component instead of just the representative
        # execution group.  The REP sub-template is executed N-1 times
        # per source REP, each execution carrying one iteration's
        # memops on a distinct body entry; the default
        # one-execution-group mode would see iter 2 only and miss
        # iter 3..N.
        fanout = any(blocks_by_id[bid].get("aggregate_fanout")
                     for bid in comp_blocks)
        def _dps_for(tid: int) -> list:
            out: list = []
            src = (all_entries.get(tid, []) if fanout
                   else rep_group.get(tid, []))
            for e in src:
                out.extend(e.get("dyn_params", []) or [])
            return out

        # ---- 4a. Scope the expecteds to what the representative ----
        # groups observed.  With every template's representative
        # execution complete (the overwhelmingly common case) this is a
        # no-op and the check is exactly as strict as ever.  Otherwise
        # (window closed mid-block on the only invocation) the wire
        # declares the cut, and expecting a memop from an instruction
        # the declared ranges exclude would manufacture a failure out
        # of an honest partial range: identity-carrying requireds whose
        # instruction was never observed are dropped, identity-less
        # requireds demote to optional (they cannot be attributed).
        comp_fully = fanout or all(rep_complete.get(t, False)
                                   for t in comp_tmpls)
        if not comp_fully:
            observed_pcs: set[int] = set()
            for t in comp_tmpls:
                t_insns = templates_by_id.get(t, {}).get("insns", [])
                for e in rep_group.get(t, []):
                    s, st, _n = _entry_range(e, templates_by_id.get(t))
                    for i in range(s, min(st, len(t_insns))):
                        observed_pcs.add(int(t_insns[i]["pc"]))
            scoped: list[tuple[str, int, int, bool, tuple | None]] = []
            n_dropped = n_demoted = 0
            for kind, off, data, optional, ident in expected:
                if optional:
                    scoped.append((kind, off, data, True, ident))
                elif ident is not None:
                    if all(p in observed_pcs for p in ident):
                        scoped.append((kind, off, data, False, ident))
                    else:
                        n_dropped += 1      # instruction never observed
                else:
                    scoped.append((kind, off, data, True, None))
                    n_demoted += 1
            expected = scoped
            if n_dropped or n_demoted:
                issues.append(Issue(
                    "cp_memops", "info",
                    f"templates {{{'+'.join(f't{t}' for t in sorted(comp_tmpls))}}}: "
                    f"representative execution is range-partial (close cut "
                    f"the block); {n_dropped} expected memop(s) outside the "
                    f"observed range excluded, {n_demoted} identity-less "
                    f"expected(s) demoted to optional",
                    {"template_ids": sorted(comp_tmpls),
                     "dropped": n_dropped, "demoted": n_demoted}))

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


def _check_segment_final_memops(
        cp_entries: list[dict],
        templates_by_id: dict[int, dict]) -> list[Issue]:
    """The segment's LAST body entry carries its memory operands, exactly
    like every other execution of the same true BB.

    A body entry's memops are drained from the per-thread accumulator when
    the entry is emitted, and emission is deferred by one TB — so an entry
    flushed on a path that runs *before* its instructions execute carries
    no memop records at all.  The loss is confined to one entry per
    segment and is invisible to every byte-level gate: the audit's
    byte-rollup partitions the records that ARE present (a record never
    written contributes nothing to reconcile), and the impossible-
    attribution lint only rejects a memop landing on a memop-incapable
    slot — never the converse, because an instruction with static memop
    slots legitimately producing no access is normal (predication, a
    zero-count REP, a suppressed fault).

    The oracle here is the trace's own repetition.  The final entry's
    template is looked up among the entries before it; when every earlier
    execution of that same template agrees on how many memops it performs
    and on which instruction slots perform them, that agreement is this
    template's invariant and the final execution must satisfy it too.
    Self-calibrating (no per-workload expectation to keep in sync) and
    silent when the final template is a one-shot or genuinely variable.

    RANGE-AWARENESS (format spec §4.2a).  The invariant is calibrated
    from WHOLE-block peer executions only (a split stretch carries just
    its own range's memops and would poison the baseline), and when the
    final entry itself declares a partial range — a close cut the block
    mid-flight — the comparison is scoped to the instructions inside
    that range: the unobserved tail's memops are not "dropped", the
    wire says they were never observed.
    """
    if len(cp_entries) < 3:
        return [Issue("segment_final_memops", "info",
                      "fewer than 3 CP entries; no final-entry oracle")]
    final = cp_entries[-1]
    tid = final.get("template_id")
    tmpl = templates_by_id.get(tid) or {}
    peers = [e for e in cp_entries[:-1]
             if e.get("template_id") == tid
             and not _entry_is_partial(e, tmpl)]
    tmpl_insns = tmpl.get("insns") or []
    static_memop_slots = sum(
        1 for i in tmpl_insns
        if int(i.get("n_loads", 0)) or int(i.get("n_stores", 0)))
    f_start, f_stop, f_n = _entry_range(final, tmpl)

    def shape(e: dict, lo: int = 0, hi: int | None = None) -> tuple:
        """(count, sorted per-instruction load/store tally) — the part of
        an execution's memop set that a template repeats verbatim.  The
        ADDRESSES legitimately move between executions (a striding loop);
        which instruction accesses memory, and how often, does not.
        @lo/@hi restrict the tally to insn indices in [lo, hi) so a
        partial final entry is compared against the same stretch of its
        whole-block peers."""
        dps = e.get("dyn_params") or []
        tally: dict[tuple, int] = {}
        count = 0
        for dp in dps:
            idx = int(getattr(dp, "insn_index", -1))
            if idx < lo or (hi is not None and idx >= hi):
                continue
            count += 1
            key = (idx, str(getattr(dp, "type_name", "")))
            tally[key] = tally.get(key, 0) + 1
        return (count, tuple(sorted(tally.items())))

    if len(peers) < 2:
        return [Issue("segment_final_memops", "info",
                      f"final entry's template {tid} executes "
                      f"{len(peers) + 1}x; no repetition oracle "
                      f"(static memop slots={static_memop_slots})")]
    peer_shapes = {shape(p) for p in peers}
    if len(peer_shapes) != 1:
        return [Issue("segment_final_memops", "info",
                      f"final entry's template {tid} has a variable memop "
                      f"shape across {len(peers)} earlier executions; "
                      f"no invariant to assert")]
    want = peer_shapes.pop()
    if want[0] == 0:
        return [Issue("segment_final_memops", "info",
                      f"final entry's template {tid} performs no memops "
                      f"(static memop slots={static_memop_slots})")]
    if f_start > 0 or f_stop < f_n:
        # Partial final entry: scope the invariant to its declared
        # range (peer tallies re-derived over the same [start, stop)).
        want = {shape(p, f_start, f_stop) for p in peers}.pop()
        if want[0] == 0:
            return [Issue(
                "segment_final_memops", "info",
                f"final entry's template {tid} declares range "
                f"[{f_start},{f_stop}) of {f_n} with no memop-capable "
                f"peer activity inside it; nothing to assert")]
        got = shape(final, f_start, f_stop)
    else:
        got = shape(final)
    if got != want:
        return [Issue(
            "segment_final_memops", "error",
            f"segment's final body entry (seq {final.get('seq_num')}, "
            f"template {tid}) carries {got[0]} memops, but all "
            f"{len(peers)} earlier executions of that template carry "
            f"{want[0]} — the final entry's memory operands were dropped",
            {"template_id": tid,
             "final_seq": final.get("seq_num"),
             "final_memops": got[0],
             "expected_memops": want[0],
             "peer_executions": len(peers),
             "static_memop_slots": static_memop_slots,
             "final_shape": [list(k) + [v] for k, v in got[1]],
             "expected_shape": [list(k) + [v] for k, v in want[1]]},
        )]
    return [Issue(
        "segment_final_memops", "info",
        f"segment's final body entry carries its {want[0]} memops "
        f"(template {tid}, matched against {len(peers)} earlier "
        f"executions)",
        {"template_id": tid, "memops": want[0],
         "peer_executions": len(peers)})]


def _memop_is_architecturally_optional(isa: str, raw) -> bool:
    """Whether this encoding's memory access can be suppressed at run
    time by a register value, so that a zero-memop execution is the
    architecture working rather than an observation the writer lost.

    Mirrors ``cst::memop_is_architecturally_optional`` in
    ``tools/cst_lint.h`` — keep the two in step.  The families:

    * AArch64 FEAT_MOPS ``CPYP/CPYM/CPYE``, ``CPYFP/CPYFM/CPYFE``,
      ``SETP/SETM/SETE``, ``SETGP/SETGM/SETGE``.  The size register Xn
      decides how much moves; at zero the helper's transfer loop never
      runs and nothing is touched.  glibc routes every memcpy / memmove /
      memset through these on a FEAT_MOPS guest, so ``memmove(d, s, 0)``
      reaches the wire as a zero-memop execution of a busy template.
    * RISC-V ``SC.W`` / ``SC.D``.  A store-conditional whose reservation
      address does not match skips the compare-and-swap entirely and only
      writes the failure code to rd, so the failing iteration of an LR/SC
      retry loop realises no memop while every successful one realises
      two.
    """
    if raw is None or len(raw) < 4:
        return False
    w = int.from_bytes(bytes(raw)[:4], "little")
    if isa == "aarch64":
        # Memory Copy and Memory Set class: bits[31:24] select the family
        # (0x19 set / forward-only copy, 0x1D copy) and bits[11:10] == 0b01
        # pins the class against the neighbouring load/store encodings.
        return (w & 0xFF000C00) in (0x19000400, 0x1D000400)
    if isa.startswith("riscv"):
        # AMO major opcode with funct5 = 0b00011 (SC); funct3 pinned to
        # 2/3 so the vector indexed-AMO encodings, which share the major
        # opcode and use funct3 for the element width, cannot be swept in.
        return ((w & 0x7F) == 0x2F and (w >> 27) & 0x1F == 0x03
                and (w >> 12) & 0x7 in (2, 3))
    return False


def _check_memop_bimodality(
        cp_entries: list[dict],
        templates_by_id: dict[int, dict],
        isa: str = "",
        min_execs: int = 8,
        max_outlier_rate: float = 0.10) -> list[Issue]:
    """Per-template memop bimodality — the GENERAL D4-class completeness
    oracle (mirrors ``cst_lint.h``'s ``MemopBimodalityLint``, so the
    Python-side oracle chain — and its mutation-tier teeth — exercise the
    same invariant the offline C++ tools do).

    ``_check_segment_final_memops`` above catches exactly the D4
    mechanism: ONE specific entry (the segment's last) losing its memops
    to a positional emission bug.  This check generalises the same
    signature to every entry, not just the last one: a memop-capable
    template whose executions are overwhelmingly nonzero, with a small
    minority realising none, is flagged regardless of WHERE in the
    stream the outlier sits — so any future memop-loss bug of the same
    shape (not necessarily positional, not necessarily confined to
    segment close) is caught too, not just this one mechanism.

    Deliberately statistical rather than absolute, for the same reason
    ``AttributionLint``'s memop rule is one-sided: a memop-capable insn
    legitimately producing zero memops this execution is normal
    (predication, a zero-count REP, a suppressed fault).  A template
    that is legitimately bimodal AT SCALE (heavy predication, a REP loop
    that is empty as often as it is not) has a zero-rate the default
    threshold does not consider an "outlier", so it is not flagged; only
    a template whose zero executions are a small minority against an
    established nonzero majority trips this check.  Both thresholds are
    tunable (min_execs, max_outlier_rate) for a workload whose
    predication rate genuinely warrants a wider band.  Correct-path
    only — wrong-path wandering carries no dataflow contract.

    A PARTIAL execution is excluded from the population entirely.  An
    entry whose declared range ``[bb_start, bb_stop)`` (§4.2a) does not
    cover the whole template ran part of the block — in the limit one
    instruction — so it never had the chance to realise the template's
    full memop complement, and the wire says so explicitly.  Counting
    it as a zero-memop outlier reports a completeness loss the trace
    itself already explains (a kernel copy loop taking a page fault on
    its first store is the canonical case).  This costs the oracle no
    strictness: the loss it exists to catch is a SILENT one, and a
    silently dropped memop section declares no partial range.  (The
    population itself shifts once split emission makes partial entries
    routine rather than exceptional; the thresholds are tunable and the
    exclusion is exact — mirrored with ``cst_lint.h``'s
    ``MemopBimodalityLint``, which keys on the same range.)
    """
    from collections import defaultdict
    per_tid: dict[int, list[int]] = defaultdict(list)
    truncated = 0
    excluded: set[int] = set()            # not memop-capable, or all-optional
    optional_only: set[int] = set()       # all-optional (reported)
    # tid -> set of insn indices whose memop capacity is architecturally
    # optional; those slots are left out of the realised count so a
    # template that MIXES optional and mandatory accesses is still judged
    # on the mandatory ones.
    optional_slots: dict[int, set[int]] = {}
    for e in cp_entries:
        tid = e.get("template_id")
        tmpl = templates_by_id.get(tid) or {}
        insns = tmpl.get("insns") or []
        if tid not in optional_slots and tid not in excluded:
            opt, mandatory = set(), False
            for idx, i in enumerate(insns):
                if not (int(i.get("n_loads", 0)) or int(i.get("n_stores", 0))):
                    continue
                if _memop_is_architecturally_optional(isa, i.get("raw_bytes")):
                    opt.add(idx)
                else:
                    mandatory = True
            if mandatory:
                optional_slots[tid] = opt
            else:
                excluded.add(tid)         # nothing here to hold to the rule
                if opt:
                    optional_only.add(tid)
        if tid in excluded:
            continue                      # nothing here to hold to the rule
        if _entry_is_partial(e, tmpl):
            truncated += 1                # partial execution; not comparable
            continue
        dps = e.get("dyn_params") or []
        opt = optional_slots.get(tid, set())
        if not opt:
            per_tid[tid].append(len(dps))
        else:
            def _idx(dp):
                if isinstance(dp, dict):
                    return int(dp.get("insn_index", -1))
                return int(getattr(dp, "insn_index", -1))
            per_tid[tid].append(sum(1 for dp in dps if _idx(dp) not in opt))

    issues: list[Issue] = []
    for tid, counts in per_tid.items():
        total = len(counts)
        if total < min_execs:
            continue
        zero = sum(1 for c in counts if c == 0)
        nonzero = total - zero
        if zero == 0 or nonzero == 0:
            continue
        rate = zero / total
        if rate > max_outlier_rate:
            continue
        issues.append(Issue(
            "memop_bimodality", "error",
            f"template {tid}: {zero}/{total} CP executions realised zero "
            f"memops (rate {rate:.4f}) against a {nonzero}-execution "
            f"nonzero majority — memop bimodality (D4-class completeness "
            f"loss)",
            {"template_id": tid, "total": total, "zero": zero,
             "nonzero": nonzero, "rate": rate}))
    if not issues:
        issues.append(Issue(
            "memop_bimodality", "info",
            f"clean: 0 templates with a nonzero-majority / zero-outlier "
            f"memop split among {len(per_tid)} memop-capable template(s) "
            f"(min_execs={min_execs}, max_outlier_rate={max_outlier_rate}, "
            f"{truncated} fault-truncated execution(s) excluded, "
            f"{len(optional_only)} template(s) untracked as "
            f"architecturally-optional-only)"))
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
        # A CONTINUATION entry (bb_start > 0, format spec §4.2a) is a
        # further stretch of the SAME dynamic execution — an excursion
        # split the block — so it stays in the current iteration and
        # its template_id does not count as a repeat.
        cov_tids = set(tids)
        # Walk trace entries (already filtered to CP) in order; group
        # by iter when a template_id repeats.
        iter_entries: list[list[dict]] = [[]]
        seen_in_iter: set[int] = set()
        for e in entries:
            tid = int(e["template_id"])
            if tid not in cov_tids:
                continue
            is_continuation = int(e.get("bb_start", 0) or 0) > 0
            if tid in seen_in_iter and not is_continuation:
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
        # Kernel templates, fault-handler executions (fault_depth>0) and
        # PARTIAL entries (a declared range shorter than the template,
        # §4.2a) are exempt: a faulting access transfers 0 bytes on the
        # attempt that traps and the full width on the post-handler
        # retry, and a split stretch realises only its own range's
        # memops — neither may perturb the user workload's whole-block
        # shape baseline.
        if (tmpl.get("is_system") or int(e.get("fault_depth", 0) or 0) > 0
                or _entry_is_partial(e, tmpl)):
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
            # `expected_insns_full` blocks (the dense author-intent
            # annotator) spec EVERY machine instruction, so there is no
            # generator-emitted trailer to carve out.  They are also matched
            # tolerantly: a block whose true BB is exposed across more than
            # one template (a mid-block page split, or re-entry at an
            # interior PC) yields a partial `idxs` for some entries — those
            # are skipped rather than flagged, since the block is still
            # checked in full on the entry that carries the whole template.
            full = bool(block.get("expected_insns_full"))
            blk_trailer = 0 if full else trailer
            expected_total = len(specs) + blk_trailer
            if len(idxs) != expected_total:
                if not full:
                    err("count",
                        f"blk_{bid} ({block.get('class','?')}): declared "
                        f"{len(specs)} insn specs + {blk_trailer} trailer = "
                        f"{expected_total}, trace template has {len(idxs)}",
                        {"block_id": bid, "declared": len(specs),
                         "trailer": blk_trailer, "trace": len(idxs)})
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


# Raw system-register encoding -> generic register name.  Derived
# INDEPENDENTLY of the decode boundary that classifies these at run
# time (cap_aarch64_sysreg_class / cap_riscv_csr_class in
# disas/capstone.c): an oracle that imported the mapping it is checking
# would agree with a wrong one.  Keyed by encoding, which the operand
# still carries in reg_id, because a system-register operand carries an
# architectural encoding and not a Capstone register id, so it cannot
# go through the reg-class table the rest of this oracle uses; anything
# not listed folds to REG_SYS.
_AARCH64_SYSREG_GENERIC = {
    0xda10: "REG_FLAGS",                                      # NZCV
    0xda20: "REG_FCSR", 0xda21: "REG_FCSR", 0xda22: "REG_FCSR",
    0xde82: "REG_TLS", 0xde83: "REG_TLS",                     # TPIDR*_EL0
}
_RISCV_CSR_GENERIC = {
    0x001: "REG_FCSR", 0x002: "REG_FCSR", 0x003: "REG_FCSR",
    # vstart is vector control state, and RISC-V is the only ISA that
    # has one -- a single-ISA register does not earn a generic ID.
    0x008: "REG_VCTRL",
    # vxsat / vxrm / vcsr are a rounding-mode-and-status word, which is
    # what REG_FCSR already means; vcsr is fcsr's sibling CSR.
    0x009: "REG_FCSR", 0x00a: "REG_FCSR", 0x00f: "REG_FCSR",
    # vl / vtype are the configuration a vsetvl writes as a pair.
    0xc20: "REG_VCTRL", 0xc21: "REG_VCTRL",
    # vlenb is a read-only implementation constant.
    0xc22: "REG_SYS",
}


def _riscv_csr_access(raw: bytes) -> int:
    """Zicsr access direction read from the encoding, as
    `cap_riscv_csr_access` reads it: CSRRW/CSRRWI with rd == x0 does not
    read the CSR, CSRRS/CSRRC with a zero rs1 or uimm does not write it."""
    if len(raw) < 4:
        return 3
    word = int.from_bytes(bytes(raw[:4]), "little")
    if (word & 0x7f) != 0x73:
        return 3
    funct3 = (word >> 12) & 0x7
    rd = (word >> 7) & 0x1f
    rs1 = (word >> 15) & 0x1f
    if funct3 in (1, 5):
        return 2 | (1 if rd else 0)
    if funct3 in (2, 3, 6, 7):
        return 1 | (2 if rs1 else 0)
    return 3


def _riscv_reads_dynamic_frm(raw: bytes) -> bool:
    """A scalar FP encoding whose rm field is DYN reads fcsr.frm."""
    if len(raw) < 4:
        return False
    word = int.from_bytes(bytes(raw[:4]), "little")
    if (word & 0x7f) not in (0x43, 0x47, 0x4b, 0x4f, 0x53):
        return False
    return ((word >> 12) & 0x7) == 0x7


def _riscv_is_mask_dst(mnem: str) -> bool:
    """RVV forms whose destination is a mask register, and whose mask tail
    is therefore undisturbed unconditionally — see `cap_riscv_is_mask_dst`."""
    if not mnem.startswith("v"):
        return False
    if mnem in ("vlm.v", "vmmv.m", "vmnot.m", "vmclr.m", "vmset.m"):
        return True
    if mnem.startswith(("vms", "vmf", "vmadc")):
        return True
    return len(mnem) > 5 and mnem[1] == "m" and mnem.endswith(".mm")


def _apply_boundary_corrections(isa, d, ops, op_reg_kind, op_mem_kind,
                                add, exp_src: set, exp_dst: set) -> None:
    """Mirror the decode-boundary corrections in `disas/capstone.c`.

    The oracle above builds its expectation from the RAW Capstone the
    Python bindings expose, but the trace is built from Capstone AFTER
    `disas/capstone.c` repairs the operand metadata Capstone 6.0.0-Alpha7
    gets wrong.  Without mirroring those repairs here the oracle would
    report every repair as a defect — and, worse, would go green again if
    a repair were ever silently dropped.  Each correction below names the
    workaround it mirrors; see that file's comment for the encoding-level
    evidence and the retirement procedure, and `isaxcheck` for the
    exhaustive sweep that found them.
    """
    mnem = (getattr(d, "mnemonic", "") or "").lower()

    if isa == "aarch64":
        # Register-form shift aliases: Capstone drops the third operand
        # and parks the shift-amount REGISTER in operands[1].shift.value
        # (shift.type is one of the *_REG kinds).  `lsl x2, x1, x9` would
        # otherwise lose x9 entirely.
        if mnem in ("lsl", "lsr", "asr", "ror") and len(ops) == 2:
            sh = getattr(ops[1], "shift", None)
            if sh is not None and int(getattr(sh, "type", 0) or 0) >= 6:
                add(exp_src, int(getattr(sh, "value", 0) or 0))
        # SVE / SME governing predicates arrive as a dedicated PRED
        # operand type with the register in op.pred.reg, so the operand
        # walk above cannot see them.
        for op in ops:
            pred = getattr(op, "pred", None)
            reg = int(getattr(pred, "reg", 0) or 0) if pred is not None else 0
            if not reg:
                continue
            access = int(getattr(op, "access", 0) or 0)
            if access & 1:
                add(exp_src, reg)
            if access & 2:
                add(exp_dst, reg)
        # The compare-and-swap forms: the result register's write is
        # restored, and the phantom write of the address base that
        # detail->writeback fabricates is dropped.
        if mnem.startswith(("cas", "rcwcas", "rcwscas")):
            base = set()
            for op in ops:
                if op.type == op_mem_kind:
                    add(base, int(getattr(op.mem, "base", 0) or 0))
            exp_dst -= base
            if mnem.startswith("cas") and not mnem.startswith("casp"):
                for op in ops:
                    if op.type == op_reg_kind:
                        add(exp_src, op.reg)
                        add(exp_dst, op.reg)
                        break
        # The SVE merging-predicated `mov` alias of SEL keeps its
        # destination's previous value in the inactive lanes.
        if mnem == "mov" and len(ops) == 3:
            for op in ops:
                if op.type == op_reg_kind:
                    add(exp_src, op.reg)
                    break
        # The aliased `ret` (no printed operand) is `RET X30`: Capstone
        # follows the printed alias and reports neither an operand nor
        # an implicit read, so the return address dependency of every
        # AArch64 function return would vanish.  The boundary restores
        # the link register; assert it positively — the non-aliased
        # `ret x1` keeps its operand and must NOT gain x30.
        if mnem == "ret" and not ops:
            try:
                import capstone as _cs
                add(exp_src, _cs.aarch64.AARCH64_REG_LR)
            except Exception:
                pass
        # SIMD pre-/post-index writeback: Capstone claims writeback but
        # lists the base write only for the scalar forms.
        if getattr(d, "writeback", False):
            for op in ops:
                if op.type != op_mem_kind:
                    continue
                mem = op.mem
                if int(getattr(mem, "disp", 0) or 0) or int(
                        getattr(mem, "index", 0) or 0):
                    add(exp_dst, int(getattr(mem, "base", 0) or 0))
                break
        try:
            import capstone as _cs
            _a64 = _cs.aarch64
        except Exception:
            return
        # The system register an MRS/MSR moves.  Capstone models it with
        # its own operand type, in its own numbering space, and leaves
        # the access bits empty; the direction is in sysop.sub_type.
        for op in ops:
            if op.type not in (_a64.AARCH64_OP_SYSREG,
                               _a64.AARCH64_OP_REG_MRS,
                               _a64.AARCH64_OP_REG_MSR):
                continue
            sysop = getattr(op, "sysop", None)
            if sysop is None:
                continue
            sub = int(getattr(sysop, "sub_type", 0) or 0)
            if sub not in (_a64.AARCH64_OP_REG_MRS, _a64.AARCH64_OP_REG_MSR):
                continue          # TLBI / IC: an operation, not a register
            enc = int(getattr(getattr(sysop, "reg", None), "sysreg", 0) or 0)
            gen = _AARCH64_SYSREG_GENERIC.get(enc, "REG_SYS")
            (exp_src if sub == _a64.AARCH64_OP_REG_MRS
             else exp_dst).add(gen)
        # An SME operand names a ZA tile and the GPR that selects the
        # slice; neither is reachable through the plain REG arm.
        for op in ops:
            if op.type != _a64.AARCH64_OP_SME:
                continue
            sme = getattr(op, "sme", None)
            if sme is None:
                continue
            access = int(getattr(op, "access", 0) or 0)
            tile = int(getattr(sme, "tile", 0) or 0)
            if access & 1:
                add(exp_src, tile)
            if access & 2:
                add(exp_dst, tile)
            add(exp_src, int(getattr(sme, "slice_reg", 0) or 0))
        # The FEAT_MOPS prologue reads the PSTATE.NZCV it then rewrites.
        if mnem.startswith(("cpyp", "cpyfp", "setp", "setgp")):
            add(exp_src, _a64.AARCH64_REG_NZCV)
        # The FPCR read Capstone reports on these forms' siblings and
        # not on them.
        if (mnem.startswith(("fccmp", "fabs", "fneg", "fadda"))
                or (mnem[:1] in ("s", "u") and mnem[1:2] == "q")):
            add(exp_src, _a64.AARCH64_REG_FPCR)

    elif isa == "riscv64":
        try:
            import capstone as _cs
            _rv = _cs.riscv
        except Exception:
            return
        raw = bytes(getattr(d, "bytes", b"") or b"")
        # The CSR a Zicsr instruction exists to move.  Capstone carries
        # it as a bare number in its own operand type, and the F/D alias
        # forms (fsrm / frrm / fscsr / frflags) drop the operand
        # entirely, so it is recovered from the encoding when absent.
        csr = None
        for op in ops:
            if op.type == _rv.RISCV_OP_CSR:
                csr = int(getattr(op, "csr", 0) or 0)
                break
        if csr is None and len(raw) >= 4:
            word = int.from_bytes(raw[:4], "little")
            funct3 = (word >> 12) & 0x7
            if (word & 0x7f) == 0x73 and funct3 not in (0, 4):
                csr = (word >> 20) & 0xfff
        if csr is not None:
            gen = _RISCV_CSR_GENERIC.get(csr, "REG_SYS")
            acc = _riscv_csr_access(raw)
            if acc & 1:
                exp_src.add(gen)
            if acc & 2:
                exp_dst.add(gen)
        # Scalar FP with a dynamic rounding mode reads fcsr.frm.
        if _riscv_reads_dynamic_frm(raw):
            add(exp_src, _rv.RISCV_REG_FRM)
        # A mask destination is read as well as written, whatever the
        # runtime tail policy says.
        if _riscv_is_mask_dst(mnem):
            for op in ops:
                if op.type == op_reg_kind:
                    add(exp_src, op.reg)
                    break

    elif isa == "mipsel":
        # Tied destinations: bit-field insert, lane insert/shuffle,
        # masked select, multiply-accumulate, and the conditional moves,
        # each of which preserves part of its destination.
        tied = ("ins", "dins", "append", "prepend", "insv",
                "binsl", "binsr", "bmnz", "bmz", "bsel",
                "insert", "insve", "sld", "vshf",
                "maddv", "msubv", "madd_q", "maddr_q", "msub_q",
                "msubr_q", "fmadd", "fmsub", "dpa", "dps",
                "movn", "movz", "movt", "movf")
        if mnem.startswith(tied):
            for op in ops:
                if op.type == op_reg_kind:
                    add(exp_src, op.reg)
                    break
        # The floating-point compare/branch condition-code edge, and the
        # phantom $at write Capstone puts on the branch.
        try:
            import capstone as _cs
            fcc0 = _cs.mips.MIPS_REG_FCC0
            fcc7 = _cs.mips.MIPS_REG_FCC7
            at = _cs.mips.MIPS_REG_AT
        except Exception:
            return
        names_cc = any(op.type == op_reg_kind and fcc0 <= op.reg <= fcc7
                       for op in ops)
        is_br = mnem in ("bc1t", "bc1f", "bc1tl", "bc1fl")
        if is_br:
            phantom = set()
            add(phantom, at)
            exp_dst -= phantom
        if not names_cc:
            if mnem.startswith("c."):
                add(exp_dst, fcc0)
            elif is_br:
                add(exp_src, fcc0)
        # A multiply-accumulate that NAMES its accumulator reads it too;
        # Capstone reports that read only for the implicit-ac0 forms.
        # Paired with a structural test so `madd.s`, which shares the
        # stem and writes an FP register, cannot match.
        if mnem.startswith(("madd", "msub", "dpa", "dps", "maq",
                            "mulsa", "shilo", "mthlip")):
            for op in ops:
                if op.type != op_reg_kind:
                    continue
                r = int(op.reg)
                if (_cs.mips.MIPS_REG_AC0 <= r <= _cs.mips.MIPS_REG_AC3
                        or _cs.mips.MIPS_REG_HI0 <= r <= _cs.mips.MIPS_REG_HI3
                        or _cs.mips.MIPS_REG_LO0 <= r <= _cs.mips.MIPS_REG_LO3):
                    add(exp_src, r)
                    add(exp_dst, r)
                    break
        # DSPControl on the four forms that exist to move it.
        if mnem == "rddsp":
            add(exp_src, _cs.mips.MIPS_REG_DSPCCOND)
        elif mnem == "wrdsp":
            add(exp_dst, _cs.mips.MIPS_REG_DSPCCOND)
        elif mnem in ("bposge32", "mthlip"):
            add(exp_src, _cs.mips.MIPS_REG_DSPPOS)
        # `ctcmsa` WRITES the control register Capstone reports as read.
        if mnem == "ctcmsa" and ops and ops[0].type == op_reg_kind:
            written = set()
            add(written, int(ops[0].reg))
            exp_src -= written
            exp_dst |= written


def _check_call_return_store(
    templates: list[dict],
    isa: str,
    reg_id_to_name: dict[int, str],
) -> list[Issue]:
    """A call that pushes a return address must say it pushes the IP.

    On the ISAs that write the return address to memory (x86), the
    store's DATA dependency is the return address and nothing else --
    not the register a `call *%rax` reads to find its target, not the
    base register a `call *0x10(%rax)` reads to form the address of the
    target.  Naming either of those puts a false dependency edge on one
    of the most frequent instructions a program executes: a consumer
    would let the return-address store issue when `rax` is ready
    instead of when the return address is.

    Nothing else can see this.  The store's count, address, width and
    value are all correct and were cross-validated against Intel PIN --
    PIN's trace format carries no intra-instruction dependency masks, so
    it cannot adjudicate the mask, and neither can any decoder
    cross-check, since the mask is the tracer's own construction rather
    than anything a decoder reports.  Hence a direct invariant.

    Vacuous on the ISAs whose calls write a link REGISTER (aarch64,
    riscv64, mipsel): they declare no store, and the check says so
    rather than passing silently.
    """
    _, branch_names = _load_name_tables()
    call_types = {"BRANCH_DIRECT_CALL", "BRANCH_INDIRECT_CALL",
                  "DIRECT_CALL", "INDIRECT_CALL"}
    ip_names = {"REG_IP", "IP"}

    issues: list[Issue] = []
    n_checked = 0
    n_errors = 0
    err_cap = 20

    for tmpl in templates:
        for idx, ins in enumerate(tmpl.get("insns", [])):
            bt = branch_names.get(int(ins.get("branch_type", 0)), "")
            if bt not in call_types:
                continue
            sd = ins.get("store_data_dep_mask") or []
            if not sd:
                continue
            n_checked += 1
            srcs = ins.get("src_regs") or []
            ip_bits = 0
            for i, r in enumerate(srcs):
                if reg_id_to_name.get(int(r), "") in ip_names:
                    ip_bits |= 1 << i
            bad = (len(sd) != 1 or ip_bits == 0 or sd[0] != ip_bits)
            if not bad:
                continue
            n_errors += 1
            if n_errors <= err_cap:
                issues.append(Issue(
                    "call_return_store", "error",
                    f"template t{tmpl['template_id']} insn #{idx} "
                    f"pc=0x{int(ins['pc']):x}: a call's store-data "
                    f"dependency must name the return address (REG_IP) "
                    f"and only that",
                    {"template_id": int(tmpl["template_id"]),
                     "insn_index": idx,
                     "pc": int(ins["pc"]),
                     "store_data_dep_mask": [hex(v) for v in sd],
                     "expected_mask": hex(ip_bits),
                     "src_regs": [reg_id_to_name.get(int(r), str(r))
                                  for r in srcs]},
                ))

    stores_expected = isa == "x86_64"
    issues.append(Issue(
        "call_return_store",
        "warning" if (stores_expected and not n_checked) else "info",
        f"call return-address stores: checked={n_checked} "
        f"errors={n_errors}"
        + ("" if n_checked
           else " — no call declares a store slot; expected on the "
                "link-register ISAs, a coverage hole on x86_64"),
        {"checked": n_checked, "errors": n_errors},
    ))
    return issues


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

            # Implicit regs (regs_read[]/regs_write[]) fold in for every
            # ISA — matches decode.cc's
            # `isa_properties[..].include_implicit_regs` gate, which is
            # now true everywhere.  MIPS needs it for the HI:LO
            # accumulator and RISC-V for the vector-configuration CSRs
            # (`vl`/`vtype`) and the FP rounding mode (`frm`), none of
            # which appear in an operand field.
            for cap_id in getattr(d, "regs_read", []) or []:
                add(exp_src, cap_id)
            for cap_id in getattr(d, "regs_write", []) or []:
                add(exp_dst, cap_id)

            _apply_boundary_corrections(isa, d, ops, op_reg_kind,
                                        op_mem_kind, add, exp_src, exp_dst)

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
            # the tracer re-adds REG_LR in refine_alias_fields.  Assert
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
    termination", live since 2026-07-12; the poison/dep-branch-kill
    policy this once replayed was retired — commits 18bbec8956,
    914d452978, 7b69c88aa4).  On a mispredicted path nothing retires, so
    a back-end synchronous fault is never actually taken: the tracer
    serves the faulting instruction deterministic placeholder data,
    marks it ``CST_WP_EVENT_FAULT`` at ``fault_insn_index``, and
    CONTINUES the excursion to the depth budget (memory faults and
    execution-time arithmetic / illegal-opcode faults alike).  So the
    verdicts split cleanly along two axes:

    * **Sequence.**  Up to the FIRST marked fault the emitted block
      chain must be an exact-or-longer prefix of the synthetic
      prediction — a divergence there is UNMARKED and a real bug.  Past
      a marked fault everything downstream is synthetic placeholder, so
      the block sequence is no longer predictable from the fault-free
      model: a divergence at a collapsed position strictly after the
      first fault's position is EXPECTED and accepted.

    * **Termination.**  A chain shorter than its (fault-free) prediction
      is only legitimate when it ended on a real terminator: the depth
      budget, a privilege-domain crossing into the kernel (``is_system``
      template), a mid-chain / first-fetch translation-unavailable
      event, or a whole-path wpprune.  Every one of those is a FETCH
      condition — the wrong path could not fetch the next block.  A
      syscall-class terminator is NOT among them: the wrong path
      continues past a syscall at its architectural fall-through, the
      same not-taken side it takes for any other branch, so a chain that
      stops at one is a truncation like any other.  This gate holds
      regardless of faults — a fault must CONTINUE to one of these, not
      truncate — so a short chain with no terminator and below budget is
      a truncation error even when it carries a fault.
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
    n_unresolved_exempt = 0
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

        # THE FORK PREDICTION DOES NOT APPLY TO AN UNRESOLVED TERMINAL.
        # A wrong path forks off a RESOLVED branch outcome — the same
        # invariant _check_wp_fork_resolved enforces from the other side
        # — and the emit-at-departure family (a foreign-span departure,
        # an abandoned async window, the SMP migration drain) publishes
        # its block at the measured extent with the terminating branch
        # honestly unresolved and no chain.  The generator's positional
        # prediction has no subject there.  Scoped strictly: the entry
        # must carry NO outcome and NO chain — an entry that forked and
        # diverged still gets its verdict — and the exemption is tallied
        # in a notable INFO, never silent.
        if e.get("branch_taken") is None and not e.get("wp_entries"):
            n_unresolved_exempt += 1
            continue

        exp_chain = list(wrong_paths[key].get("wp_chain", []))
        exp_chain = _trim_by_insn_budget(exp_chain, wp_insn_budget)
        wp_raw: list[int] = []
        actual_sim_insns = 0
        # `wp_left_user` marks a genuine wrong-path terminator: the
        # excursion crossed the privilege domain into the kernel
        # (`is_system` template) or hit a mid-chain translation-
        # unavailable boundary.  A synthetic-data FAULT is deliberately
        # NOT a crossing — the plugin continues the excursion on
        # placeholder data rather than truncating (live policy).
        wp_left_user = False
        raw_len_at_cross: int | None = None   # len(wp_raw) just BEFORE the
                                              # first block that left user space
        raw_len_before_fault: int | None = None  # len(wp_raw) just BEFORE the
                                                  # first FAULT-marked block
        wp_list = e.get("wp_entries", [])
        has_fault = False
        for wp in wp_list:
            wt = (templates_by_id or {}).get(wp["template_id"])
            crossed = bool(wp.get("translation_unavailable"))
            if wt is not None and wt.get("is_system"):
                crossed = True
            if crossed and raw_len_at_cross is None:
                # user blocks emitted before this crossing entry
                raw_len_at_cross = len(wp_raw)
            if wp.get("fault") and raw_len_before_fault is None:
                raw_len_before_fault = len(wp_raw)
                has_fault = True
            blocks = [bid for (bid, _)
                      in template_runs.get(wp["template_id"], [])]
            wp_raw.extend(blocks)
            # A speculative block contributes the instructions of its
            # DECLARED range (§4.2a): bb_stop - bb_start, which is
            # n_insns exactly when the block ran whole.  The wpdepth
            # budget arithmetic must count what the walker simulated,
            # not what the template holds.
            w_start = int(wp.get("bb_start", 0) or 0)
            w_stop = wp.get("bb_stop")
            w_n = int(wp.get("n_insns", 0) or 0)
            w_stop = w_n if w_stop is None else int(w_stop)
            actual_sim_insns += max(0, w_stop - w_start)
            if crossed:
                wp_left_user = True


        actual_wp = _collapse_runs(wp_raw)
        # Collapsed index at which the wrong path left the enumerable user CFG.
        left_user_at = (
            len(_collapse_runs(wp_raw[:raw_len_at_cross]))
            if raw_len_at_cross is not None else None
        )
        # Collapsed position of the first FAULT-marked block.  A block
        # sequence divergence at a position strictly after this is
        # synthetic-placeholder-driven and expected; a divergence at or
        # before it is unmarked and a bug.
        first_fault_pos = (
            len(_collapse_runs(wp_raw[:raw_len_before_fault]))
            if raw_len_before_fault is not None else None
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
            "has_fault": has_fault,
            "first_fault_pos": first_fault_pos,
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
        # Sequence verdict (live fault policy).  Up to the FIRST marked
        # fault the emitted block chain must be an exact-or-longer prefix
        # of the prediction — a divergence there is UNMARKED and a real
        # bug.  A divergence at a collapsed position STRICTLY AFTER the
        # first fault is synthetic-placeholder-driven (the faulted insn's
        # result and anything a later branch derives from it are speculative
        # filler that never architecturally retires), so the wrong path is
        # no longer predictable from the fault-free model — that is expected
        # and accepted.
        first_fault_pos = rec["first_fault_pos"]
        if first_fail >= 0:
            if first_fault_pos is not None and first_fault_pos < first_fail:
                continue
            issues.append(Issue(
                "wrong_path_chains", "error",
                f"WP at CP pos {cp_pos} (blk_{last_cp_bid}) "
                f"depth {first_fail}: expected blk_{exp_chain[first_fail]}, "
                f"got blk_{actual_wp[first_fail]}",
                {"cp_pos": cp_pos, "actual": actual_wp,
                 "expected": exp_chain},
            ))
            continue

        # Termination verdict.  The emitted chain is an exact prefix of the
        # prediction (first_fail < 0); it only needs a verdict when SHORT.
        if len(actual_wp) < len(exp_chain):
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
            # System mode: the wrong path speculatively crossed the
            # privilege domain into the kernel (CST_INSN_FLAG_SYSTEM blocks
            # the validator can't enumerate from blk_* symbols) or hit a
            # mid-chain translation-unavailable boundary.  A crossing makes
            # the chain unpredictable from there ON — but ONLY beyond that
            # point.  The synthetic wrong path is exact-known, so the WP must
            # follow the ENTIRE predicted user prefix before crossing; a
            # crossing BEFORE the prefix completes is a real truncation (the
            # WP stopped short of known code), not an unpredictable tail.
            # Accept only when the crossing is at/after the full predicted
            # length.  (A synthetic-data FAULT is NOT a crossing — it does
            # not set wp_left_user — so a mid-prefix fault does not license a
            # short chain here; the fault must continue to a real terminator.)
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
            # wpprune: the tracer intentionally drops the wrong path WHOLE
            # for cold branches (never-taken / one-directional / monomorphic
            # indirect).  Pruning removes the entire path, so accept ONLY an
            # empty chain here; a non-empty-but-short chain was NOT pruned and
            # is a genuine truncation.
            if wpprune > 0 and not actual_wp:
                continue
            # A shorter-than-predicted chain that reached none of the
            # terminators above (budget / privilege crossing / translation-
            # unavailable / wpprune) is a real plugin truncation.  A syscall is
            # deliberately not on that list: the wrong path continues past one
            # at its fall-through, so stopping there is a truncation too.
            # This holds even when the chain carries a FAULT: the live policy
            # is that a synthetic-data fault CONTINUES on placeholder data to
            # a real terminator, so a fault that stops the excursion short is
            # itself the regression this catches.
            ev_note = ("; chain-level TRANSLATION_UNAVAIL event present but "
                       "no later instance realized the chain"
                       if rec["chain_event"] else "")
            if rec["has_fault"]:
                ev_note += "; chain carries a FAULT (must continue to a " \
                           "terminator, not truncate)"
            issues.append(Issue(
                "wrong_path_chains", "error",
                f"WP at CP pos {cp_pos} (blk_{last_cp_bid}) truncated: "
                f"plugin emitted {len(actual_wp)} blocks "
                f"(sim_insns={actual_sim_insns}, budget={wp_insn_budget}); "
                f"predicted {len(exp_chain)}{ev_note}",
            ))
    if n_unresolved_exempt:
        issues.append(Issue(
            "wrong_path_chains", "info",
            f"{n_unresolved_exempt} predicted fork(s) landed on entries "
            f"whose terminating branch is declared unresolved "
            f"(emit-at-departure / migration-drain emissions) — no chain "
            f"is owed off an unresolved outcome",
            {"notable": True, "unresolved_exempt": n_unresolved_exempt}))
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
                          entries: list[dict],
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

    @entries must be EVERY CP entry in the trace.  Both operands of the
    floor identity are whole-segment quantities — `emit_count` runs from
    the segment open and `iframe_count` counts every IFRAME in the file —
    so a caller that hands over a slice makes the identity compare a
    whole-trace numerator with a partial denominator and the check reports
    a tracer defect that is its own.  The population is asserted below
    rather than trusted: a check that cannot find its subject must fail.
    """
    issues: list[Issue] = []
    cp = int(body_stats.get("cp_entries", 0))
    iframes = int(body_stats.get("iframe_count", 0))
    rate = _parse_iframe_rate_from_command(trace_meta.get("command", ""))

    if len(entries) != cp:
        issues.append(Issue(
            "iframe_cadence", "error",
            f"the cadence check was handed {len(entries)} entries but the "
            f"trace has {cp} CP entries — the per-template hit floor would "
            f"be computed over a different population than iframe_count "
            f"covers, so this check has no subject",
            {"entries_given": len(entries), "cp_entries": cp},
        ))
        return issues

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
    for e in entries:
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

    RANGE-AWARENESS (format spec §4.2a).  A syscall is pending only
    when the entry's declared range actually includes the template's
    final (syscall) instruction: a ``[0, k)`` stretch of a
    syscall-terminated block — a demand fault split it before the
    syscall ever ran — must not arm, its continuation ``[k, n)`` does.
    And an entry's position is its range-resolved PC (the PC of
    ``insns[bb_start]``), never the template's start_pc: a
    continuation resumes mid-block, and comparing the block's start
    against a resume expectation would mis-report the wire.
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
        start, stop, n = _entry_range(e, t)
        # Range-resolved position: a continuation entry (bb_start > 0)
        # resumes mid-block at insns[bb_start], not at the template's
        # start_pc.
        pc = int(t.get("start_pc", 0))
        if start > 0:
            ins = t.get("insns") or []
            if start < len(ins):
                pc = int(ins[start]["pc"])
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
        # Arm only when this entry's range includes the final (syscall)
        # instruction: a prefix stretch cut before the syscall must not
        # arm — the syscall has not executed yet; the continuation that
        # carries it does.
        if ends_in_syscall(t) and stop >= n:
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
    n_split = 0           # continuation entries (bb_start > 0, §4.2a)
    for e in entries:
        # A continuation entry resumes the block an excursion (or a
        # capture boundary) interrupted; its resume index must name a
        # real instruction of its own template.  Contiguity with the
        # prefix is range_continuity's job — this asserts only the
        # in-template bound the anchor-era check asserted per anchor.
        t = templates_by_id.get(e["template_id"])
        e_start = int(e.get("bb_start", 0) or 0)
        if e_start > 0:
            n_split += 1
            n_insns = len(t.get("insns") or []) if t else 0
            if n_insns and e_start >= n_insns:
                issues.append(Issue(
                    "fault_excursions", "error",
                    f"entry seq={e.get('seq_num')} (BB{e['template_id']}) "
                    f"resumes at index {e_start}, out of range "
                    f"(n_insns={n_insns})",
                    {"seq_num": e.get("seq_num"), "bb_start": e_start}))
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
        f"{max_depth}), all kernel-privileged; {n_split} split-resumed "
        f"block stretch(es); {n_depth0} entries at baseline depth 0",
        {"handler_entries": n_handler, "max_depth": max_depth,
         "split_stretches": n_split, "depth0_entries": n_depth0})]


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

    def terminal_bt(t: dict) -> tuple[int, int] | None:
        ins_list = t.get("insns") or []
        for i in range(len(ins_list) - 1, -1, -1):
            bt = int(ins_list[i].get("branch_type", 0))
            if bn.get(bt, "BRANCH_NONE") not in ("", "BRANCH_NONE"):
                return bt, i
        return None

    calls = rets = 0
    for e in entries:
        t = templates_by_id.get(e["template_id"])
        if t is None:
            continue
        found = terminal_bt(t)
        if found is None:
            continue
        bt, term_idx = found
        # Range-awareness (§4.2a): a stretch that never reached the
        # terminal executed no call/return this entry; and counting
        # each stretch of a split invocation would double-count one
        # dynamic transfer.  Only the stretch containing the terminal
        # counts.
        start, stop, _n = _entry_range(e, t)
        if not (start <= term_idx < stop):
            continue
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
        # Range-awareness (§4.2a): a partial prev entry whose declared
        # range never reached the terminal observed no branch — its
        # successor is the excursion or its own continuation, not the
        # branch outcome; the pair asserts nothing.
        _ps, p_stop, p_n = _entry_range(prev, pt)
        if p_stop < p_n:
            continue
        ft = pt.get("fall_through_pc")
        if not ft:
            continue
        tgt_pcs = {tg["pc"] for tg in
                   (pt.get("profile") or {}).get("targets") or []}
        if ft in tgt_pcs:
            continue            # jump-to-next degenerate: taking == falling
        seen_pairs += 1
        # The successor's position is its range-resolved PC: a
        # continuation entry resumes at insns[bb_start], not at its
        # template's start_pc.
        c_start = int(e.get("bb_start", 0) or 0)
        c_pc = ct.get("start_pc")
        if c_start > 0:
            ci = ct.get("insns") or []
            c_pc = int(ci[c_start]["pc"]) if c_start < len(ci) else None
        if c_pc == ft:
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
                           expected_threads: int = 1,
                           entries: list[dict] | None = None) -> list[Issue]:
    """A BODY_TAG_REGFILE record must precede each thread's first
    BODY_TAG_ENTRY in the segment.  Single-segment, single-thread
    traces should therefore carry exactly one REGFILE.  Multi-thread
    runs scale to one per (thread, segment).

    @expected_threads is the traced process's thread population, which in
    system mode is a LOWER bound on the contexts that emit: a kernel-only
    strand (a kernel thread on a borrowed mm) is its own guest thread and
    needs its own initial register file.  Given @entries the expectation is
    therefore the number of distinct thread ids that actually contributed,
    which must still be at least @expected_threads; ``thread_records`` is
    the check that asserts each REGFILE's *position* relative to its
    thread's first entry.
    """
    actual = int(body_stats.get("regfile_count", 0))
    expected = expected_threads
    if entries is not None:
        observed = len({int(e.get("thread_id", 0)) for e in entries})
        expected = max(expected_threads, observed)
    if actual != expected:
        return [Issue(
            "regfile_records", "error",
            f"regfile_count={actual}, expected {expected} "
            f"(one per (segment, thread))",
            {"actual": actual, "expected": expected},
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
        wps = e.get("wp_entries") or []
        for wp in wps:
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


def _check_thread_switch(body_stats: dict,
                         expected_threads: int = 1,
                         system: bool = False) -> list[Issue]:
    """Every segment body's first record is a mandatory
    BODY_TAG_THREAD_SWITCH stating the starting thread (an ordinary
    delta from 0), so the count is never 0.  Multi-thread runs add real
    interleaving switches, so the count must be at least
    ``expected_threads`` (otherwise the threads never interleaved and we
    aren't actually exercising multi-thread tracing).

    USER mode, single thread: the mandatory opener is the *only* switch
    per segment and there is no interleaving, so the count matches the
    regfile cadence exactly (REGFILE is likewise one-per-segment when
    single-thread).  qemu-user gives every guest thread its own CPUState
    and nothing else executes in the traced address space, so a second
    strand cannot appear.

    SYSTEM mode: that equality is a user-mode premise and does not hold.
    A system-mode trace records whatever the GUEST executes inside the
    window, and the guest's own scheduler may run another task there --
    which is a genuinely different guest thread and carries its own
    ``thread_id``.  Measured on ``system.attach_mipsel`` (a ~540
    user-instruction window over a ``sysinfo`` syscall): in 16% of runs
    the guest preempts inside the syscall, so the wire reads
    ``thread_switch_count=3`` / ``regfile_count=2`` -- an opener plus
    two transitions.  Both transitions were decoded to the basic block
    at ``0x80111180``, which is ``resume`` in the guest's vmlinux: the
    MIPS kernel's context-switch routine, the very instruction sequence
    that reloads ``$28``/``current_thread_info``.  The strand it
    switches to executes disjoint kernel code (``div_u64_rem``,
    ``_raw_spin_lock_irqsave``) from the traced task's syscall path
    (``sys_sysinfo``, ``clear_page``), and the trace switches back at
    ``resume`` again.  The extra switches are the guest scheduler, not
    the tracer: the same shape and the same rate appear on the build
    WITHOUT the marker-detector rework that first exposed this (62/384
    vs 61/384 -- see cst_runs/tsw/FINDINGS.md).

    So in system mode the assertion here is only the one the wire
    guarantees: at least one opener per contributing context.  What
    would make an extra switch SYNTHETIC is asserted by the two checks
    that own it and are always run alongside this one:
    ``thread_records`` (a switch flag is set on an entry iff its tid
    differs from the previous entry's, and every REGFILE'd thread
    contributed entries -- so a switch to a phantom identity, or a
    switch where nothing changed, is an error there), and
    ``thread_distribution`` (at most ``expected_threads`` ids may carry
    USER entries -- so an extra strand that claimed the traced
    process's own user code is an error there).  Both pass on these
    traces.
    """
    actual = int(body_stats.get("thread_switch_count", 0))
    regfiles = int(body_stats.get("regfile_count", 0))
    if actual == 0:
        return [Issue(
            "thread_switch", "error",
            "thread_switch_count=0; every segment body must open with a "
            "mandatory BODY_TAG_THREAD_SWITCH stating the start thread",
            {"actual": actual},
        )]
    if expected_threads == 1 and not system:
        if actual != regfiles:
            return [Issue(
                "thread_switch", "error",
                f"thread_switch_count={actual} on a single-thread "
                f"user-mode trace; expected exactly one mandatory opener "
                f"per segment (== regfile_count={regfiles}) with no "
                f"interleaving switches",
                {"actual": actual, "expected": regfiles},
            )]
    elif expected_threads == 1 and system:
        if actual < regfiles:
            return [Issue(
                "thread_switch", "error",
                f"thread_switch_count={actual} < regfile_count="
                f"{regfiles}: every context that contributed entries must "
                f"have been announced by a BODY_TAG_THREAD_SWITCH before "
                f"its first entry",
                {"actual": actual, "expected_min": regfiles},
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
                               expected_threads: int,
                               templates_by_id: dict | None = None
                               ) -> list[Issue]:
    """Verify the trace's per-thread entry counts add up sensibly: exactly
    as many thread ids carried USER code as the traced process has threads.

    @expected_threads is the traced *process*'s thread population, which
    bounds the threads that run user code and nothing else.  A system-mode
    trace may additionally carry kernel-only strands: a kernel thread
    scheduled onto a borrowed mm passes the address-space gate and executes
    under the traced process's asid, and it is a genuinely different guest
    thread, so it carries its own id.  Those are counted and reported, not
    treated as a population violation.

    The assertion is on the COUNT of user-carrying ids, not on their
    numeric values, because ids are minted in first-sighting order across
    ALL strands: a kernel thread sighted between a process's two threads
    takes the id in between, leaving the process on 0 and 2.  That is the
    format's stated numbering and not a defect, so a value-range test would
    fail a correct trace.  Without @templates_by_id the privilege of an
    entry cannot be told, so every id is held to the range instead (the
    pre-identity behaviour).
    """
    counts: dict[int, int] = {}
    user_counts: dict[int, int] = {}
    for e in entries:
        tid = int(e.get("thread_id", 0))
        counts[tid] = counts.get(tid, 0) + 1
        if templates_by_id is not None:
            t = templates_by_id.get(e["template_id"])
            if t is not None and not t.get("is_system"):
                user_counts[tid] = user_counts.get(tid, 0) + 1

    if templates_by_id is None:
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
        return [Issue("thread_distribution", "info",
                      f"per-thread entry counts: {counts}",
                      {"counts": counts})]

    user_ids = sorted(user_counts)
    if len(user_ids) > expected_threads:
        return [Issue(
            "thread_distribution", "error",
            f"{len(user_ids)} thread ids carried USER entries ({user_ids}) "
            f"but the traced process has {expected_threads} thread(s) "
            f"(foreign thread leaked past the pin?)",
            {"observed_counts": counts, "user_ids": user_ids,
             "expected_threads": expected_threads},
        )]
    if expected_threads > 1 and len(user_ids) < expected_threads:
        return [Issue(
            "thread_distribution", "error",
            f"only {len(user_ids)} thread id(s) carried USER entries "
            f"({user_ids}) but the traced process has {expected_threads} "
            f"thread(s); one never reached the trace",
            {"observed_counts": counts, "user_ids": user_ids,
             "expected_threads": expected_threads},
        )]
    kernel_only = sorted(t for t in counts if t not in user_counts)
    note = (f"; kernel-only strands: {kernel_only}" if kernel_only else "")
    return [Issue(
        "thread_distribution", "info",
        f"per-thread entry counts: {counts} (user-carrying ids "
        f"{user_ids}){note}",
        {"counts": counts, "user_ids": user_ids,
         "kernel_only": kernel_only},
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

    A template whose terminal instruction is ``BRANCH_REP`` (an x86
    REP string op or an AArch64 FEAT_MOPS bulk copy/set) additionally
    hands control to that instruction's own PC: iterations 2..N each
    ride a synthetic 1-insn self-loop BB whose start_pc is that
    instruction's PC (format spec, "Bulk-memory self-loop BBs"), so
    both the block that ENTERS the loop and the self-loop BB itself
    may legitimately be followed by an entry starting there.
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


def _entry_range(e: dict, tmpl: dict | None) -> tuple[int, int, int]:
    """Resolve an entry's executed range ``[bb_start, bb_stop)`` against
    its template (format spec §4.2a).  ``bb_stop`` is ``None`` on a
    whole-block entry (the wire's baseline default), so it resolves to
    the template's instruction count.  Returns ``(start, stop, n_insns)``."""
    n = len((tmpl or {}).get("insns") or [])
    start = int(e.get("bb_start", 0) or 0)
    stop = e.get("bb_stop")
    stop = n if stop is None else int(stop)
    return start, stop, n


def _entry_is_partial(e: dict, tmpl: dict | None) -> bool:
    start, stop, n = _entry_range(e, tmpl)
    return start > 0 or stop < n


def _check_range_invocations(entries: list[dict],
                             templates_by_id: dict,
                             trace_meta: dict | None = None) -> list[Issue]:
    """Executed-range well-formedness and continuity (format spec §4.2a).

    An entry declares the half-open range ``[bb_start, bb_stop)`` of its
    template it fully observed.  A block interrupted mid-flight emits one
    entry per stretch, in strict program order within its
    ``(thread_id, asid)`` context: the prefix ``[0, k)``, the excursion's
    entries at a deeper ``fault_depth``, then the continuation ``[k, n)``.
    This check enforces what that shape makes checkable:

      * **sanity** — every entry satisfies ``0 <= start < stop <= n``
        (the decoder rejects violations on the wire; this re-asserts it
        for the decoded structures the oracle mutations perturb);
      * **continuity** — an entry with ``bb_start = k > 0`` must continue
        an OPEN invocation of the same template in the same context whose
        stop is exactly ``k``.  A continuation without its prefix, or a
        non-contiguous one, is a wire defect, never a licensed shorthand
        (§4.2a: the format has no way to skip instructions mid-block);
      * **abandonment** — while an invocation is open, the only entries
        its context may emit before the continuation are the excursion's
        (``fault_depth`` strictly deeper).  A same-or-shallower entry
        that is not the continuation abandons the block: legal when an
        excursion is on the wire to explain the redirect (a handler may
        never return), a defect when nothing intervened — a user-mode
        stream cannot lose the tail of a block invisibly.  With
        ``faults=0`` the handler is deliberately excluded from capture,
        so a redirect leaves no wire evidence and the abandonment arm is
        N/A there (continuity above still holds — §4.2a promises the
        stretches arrive adjacent, in order, with nothing between).

    A trailing open invocation (window/budget close mid-block) is legal:
    the stream simply ends, or the entry is its context's last.
    """
    issues: list[Issue] = []
    faults_excluded = "faults=0" in str((trace_meta or {}).get("command", ""))
    # ctx -> {template_id -> {"stop", "depth", "seq", "excursion_seen"}}
    open_by_ctx: dict[tuple, dict[int, dict]] = {}
    n_split = n_continued = 0
    err_cap = 5

    def _err(msg: str, **detail):
        if len(issues) < err_cap:
            issues.append(Issue("range_continuity", "error", msg, detail))
        else:
            issues.append(Issue("range_continuity", "error", msg))

    for e in entries:
        t = templates_by_id.get(e["template_id"])
        if t is None:
            continue
        ctx = (int(e.get("thread_id", 0)), int(e.get("asid_index", 0)))
        d = int(e.get("fault_depth", 0) or 0)
        start, stop, n = _entry_range(e, t)
        seq = e.get("seq_num")
        tid = int(e["template_id"])

        if not (0 <= start < stop <= n):
            _err(f"entry seq={seq} (BB{tid}) declares malformed range "
                 f"[{start},{stop}) against n_insns={n}",
                 seq_num=seq, start=start, stop=stop, n_insns=n)
            continue

        opens = open_by_ctx.setdefault(ctx, {})

        # Excursion bookkeeping: an entry strictly deeper than an open
        # invocation is the excursion that interrupted it — expected.
        for inv in opens.values():
            if d > inv["depth"]:
                inv["excursion_seen"] = True

        if start > 0:
            n_continued += 1
            inv = opens.get(tid)
            if inv is None:
                _err(f"entry seq={seq} (BB{tid}) continues at "
                     f"[{start},{stop}) but no open invocation of that "
                     f"template exists in context {ctx}",
                     seq_num=seq, start=start)
            elif inv["stop"] != start or inv["depth"] != d:
                _err(f"entry seq={seq} (BB{tid}) continues at {start} but "
                     f"its open invocation stopped at {inv['stop']} "
                     f"(depth {inv['depth']} vs {d}); a continuation must "
                     f"resume exactly where the prefix stopped",
                     seq_num=seq, start=start, open_stop=inv["stop"])
                del opens[tid]
            else:
                if stop < n:
                    inv.update(stop=stop, seq=seq, excursion_seen=False)
                else:
                    del opens[tid]
            # Fall through to the abandonment sweep below for OTHER opens.
        else:
            prev = opens.get(tid)
            if prev is not None and prev["depth"] == d:
                if not (prev["excursion_seen"] or faults_excluded):
                    _err(f"entry seq={seq} (BB{tid}) re-opens the template "
                         f"while its invocation from seq={prev['seq']} is "
                         f"still open at {prev['stop']} with no excursion "
                         f"between — the earlier block lost its tail",
                         seq_num=seq, prev_seq=prev["seq"])
                del opens[tid]

        # Abandonment: any open invocation at depth >= d that this entry
        # did not continue can no longer be continued (the context moved
        # on at its level).  With an excursion on the wire the redirect
        # is explained; without one it is a defect.
        for otid in [k for k, inv in opens.items()
                     if inv["depth"] >= d and not (k == tid and start > 0)]:
            inv = opens[otid]
            if not (inv["excursion_seen"] or faults_excluded):
                _err(f"entry seq={seq} in context {ctx} abandons the open "
                     f"invocation of BB{otid} (stopped at {inv['stop']}, "
                     f"seq={inv['seq']}) with no excursion on the wire to "
                     f"explain the cut",
                     seq_num=seq, abandoned=otid, open_stop=inv["stop"])
            del opens[otid]

        if start == 0 and stop < n:
            n_split += 1
            opens[tid] = {"stop": stop, "depth": d, "seq": seq,
                          "excursion_seen": False}

    errors = [i for i in issues if i.severity == "error"]
    if errors:
        return errors[: err_cap + 1]
    return [Issue(
        "range_continuity", "info",
        f"{n_split} split invocation(s) opened, {n_continued} "
        f"continuation(s), all contiguous within their contexts",
        {"splits": n_split, "continuations": n_continued})]


def _check_wp_fork_resolved(entries: list[dict]) -> list[Issue]:
    """A wrong path forks off a RESOLVED terminating branch (the fork
    redirects the PC to the not-taken alternative of an outcome the
    tracer observed).  An entry that carries a wrong-path chain but no
    resolved branch outcome is therefore self-contradictory: either the
    outcome was withheld (a stuck CST_BB_FLAG_BRANCH_UNRESOLVED — the
    flag latching past the entry it described) or the chain was forged.
    An entry whose range does not reach the terminating branch forks no
    wrong path, so absence of both is always consistent."""
    issues: list[Issue] = []
    n_forked = 0
    for e in entries:
        wps = [w for w in (e.get("wp_entries") or []) if w.get("template_id")]
        if not wps:
            continue
        n_forked += 1
        if e.get("branch_taken") is None and len(issues) < 5:
            issues.append(Issue(
                "wp_fork_resolved", "error",
                f"entry seq={e.get('seq_num')} (BB{e['template_id']}) "
                f"carries a {len(wps)}-block wrong-path chain but no "
                f"resolved branch outcome; a wrong path forks off a "
                f"resolved branch only",
                {"seq_num": e.get("seq_num"), "wp_blocks": len(wps)}))
    if issues:
        return issues
    return [Issue(
        "wp_fork_resolved", "info",
        f"{n_forked} WP-forking entries all carry a resolved branch "
        f"outcome", {"forked": n_forked})]


#: Close routes that fire BECAUSE the pinned context stopped executing.
#: The dead latch and the any-context ceiling are raised by a sweep, not
#: by the context's own progress, so at the moment they fire the context
#: has nothing pending: its last entry went to the wire through the
#: ordinary seal path, when nothing could know it was final, and the
#: close-time flush emits nothing to carry the stamp.  The fact is
#: retroactive and the wire is already written, so THREAD_END is a
#: positive marker here and its absence is the contract (format.rst
#: §4.2a, "Thread end"), not a forgotten stamp.  Every other route --
#: END marker, process exit, icount/simpoint budget, machine shutdown,
#: reset -- is raised on a context that is still running, so the close
#: does have a final to stamp and the F6 arm applies in full.
_THREAD_END_SWEEP_CLOSES = frozenset({"IDLE", "CEILING"})

_CLOSE_REASON_RE = re.compile(
    r"champsim_tracer: finished segment \[icount .*?\]\s.*?\s(\S+)\s*$",
    re.MULTILINE)


def parse_close_reason(console_text: str) -> str | None:
    """The close route named by the LAST ``finished segment`` line.

    The plugin ends that line with the close reason (IDLE, CEILING,
    SHUTDOWN, RESET, END) or, when no route named itself, with the
    coverage verdict (OK / UNDER / END).  Returns None when the text
    carries no such line, which callers must treat as "unknown" — the
    strict arm, never a tolerance.
    """
    found = _CLOSE_REASON_RE.findall(console_text or "")
    return found[-1] if found else None


def _check_thread_end_flags(entries: list[dict],
                            close_reason: str | None = None) -> list[Issue]:
    """CST_BB_FLAG_THREAD_END marks each context's final entry at EVERY
    close route (thread exit, END marker, icount/simpoint budget, idle
    ceiling, machine shutdown), format spec §4.2a/§5.6.  A consumer
    learns a context is over from the flag, never by inferring it from
    the context not reappearing, so a close route that forgets the
    stamp silently breaks the consumer contract.  Two directions:

      * **the close's finals are stamped** — the F6 oracle.  Whichever
        route closes the window, the entries it emits as each context's
        final form the stream's trailing run of context-final entries
        (walking back from the end, one entry per context until a
        context repeats); every entry in that run must carry the flag.
        This FAILS when a budget/simpoint/END/shutdown close forgets
        the stamp.  It deliberately does NOT demand a stamp on a
        context that merely scheduled away mid-window (its final entry
        is already on the wire when the window closes, and the frozen
        wire has no way to stamp it retroactively — the thread-switch
        record explains that departure);
      * **the stamp never lies** — an entry carrying the flag anywhere
        in the stream must be its context's last; a flagged context
        that keeps executing declared an end that wasn't.

    @close_reason names the route that ended the segment (see
    parse_close_reason).  On a SWEEP close — the dead latch and the
    any-context ceiling — the first arm does not apply and is not run:
    those routes fire because the context stopped executing, so nothing
    of it is pending and the close emits no final to stamp.  The arm is
    reported as not-applicable with the reason and the unstamped count
    named, never as a pass, and the second arm still runs in full.  An
    unknown reason takes the strict path: a check does not weaken itself
    on missing evidence.

    An empty body has no contexts and nothing to assert (info)."""
    issues: list[Issue] = []
    last_by_ctx: dict[tuple, dict] = {}
    lied: list[dict] = []

    def _ctx_of(e: dict) -> tuple:
        return (int(e.get("thread_id", 0) or 0),
                int(e.get("asid_index", 0) or 0))

    for e in entries:
        ctx = _ctx_of(e)
        prev = last_by_ctx.get(ctx)
        if prev is not None and prev.get("thread_end"):
            lied.append(prev)
        last_by_ctx[ctx] = e
    if not last_by_ctx:
        return [Issue("thread_end", "info",
                      "no body entries; no contexts to close")]
    # Trailing run of context-final entries: what the close route
    # emitted as finals, one entry per context, ending at the stream's
    # last entry.
    tail_finals: list[dict] = []
    seen_back: set[tuple] = set()
    for e in reversed(entries):
        ctx = _ctx_of(e)
        if ctx in seen_back:
            break
        seen_back.add(ctx)
        tail_finals.append(e)
    missing = [e for e in tail_finals if not e.get("thread_end")]
    sweep = (close_reason or "").upper() in _THREAD_END_SWEEP_CLOSES
    if sweep:
        issues.append(Issue(
            "thread_end", "info",
            f"close route {close_reason} is a sweep: it fires because the "
            f"context stopped executing, so the close has no pending final "
            f"to stamp and {len(missing)} of {len(tail_finals)} trailing "
            f"context final(s) end unstamped by contract (format.rst §4.2a) "
            f"— the close-finals arm is NOT APPLICABLE here and was not "
            f"run; the stamp-never-lies arm was",
            {"close_reason": close_reason, "unstamped_finals": len(missing),
             "tail_finals": len(tail_finals)}))
        missing = []
    for e in missing[:5]:
        issues.append(Issue(
            "thread_end", "error",
            f"context {_ctx_of(e)} closes at seq={e.get('seq_num')} "
            f"(BB{e.get('template_id')}) without CST_BB_FLAG_THREAD_END — "
            f"the close route that emitted this final entry did not stamp "
            f"the context's end",
            {"ctx": list(_ctx_of(e)), "seq_num": e.get("seq_num")}))
    if len(missing) > 5:
        issues.append(Issue(
            "thread_end", "error",
            f"...and {len(missing) - 5} more close-final entr(ies) "
            f"lacking THREAD_END"))
    for e in lied[:5]:
        issues.append(Issue(
            "thread_end", "error",
            f"entry seq={e.get('seq_num')} (BB{e.get('template_id')}) "
            f"carries CST_BB_FLAG_THREAD_END but its context continues "
            f"afterwards — the flag declared an end that wasn't",
            {"seq_num": e.get("seq_num")}))
    if issues:
        return issues
    n_stamped = sum(1 for e in last_by_ctx.values() if e.get("thread_end"))
    return [Issue(
        "thread_end", "info",
        f"all {len(tail_finals)} close-final entr(ies) stamped with "
        f"CST_BB_FLAG_THREAD_END, no stamp lies mid-stream "
        f"({n_stamped}/{len(last_by_ctx)} context finals stamped overall)",
        {"close_finals": len(tail_finals),
         "contexts": len(last_by_ctx), "stamped_finals": n_stamped})]


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

    # tid -> (template_id, stop) of an OPEN partial user entry (§4.2a):
    # its only legitimate user-side successor is its own continuation.
    partial_by_tid: dict[int, tuple[int, int]] = {}

    # tid -> (template_id, rep_index, rep_pc): the §4.2a rep-split
    # license, the format's ONE sanctioned range overlap.  A template
    # whose terminal instruction is a self-loop (BRANCH_REP) and whose
    # entry ran to its end may be continued at ``bb_start == n - 1`` —
    # the self-loop faulted mid-loop, the piece published the iterations
    # it observed, and the continuation re-enters AT the shared
    # instruction.  The license survives the instruction's own 1-insn
    # fan-out sub-entries and the kernel excursion (the fault is the
    # excursion); any other user entry retires it.
    rep_split_lic: dict[int, tuple[int, int, int]] = {}

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
        start, stop, n = _entry_range(e, t)

        prev = chain_by_tid.get(tid, "unseen")
        if start > 0:
            # A continuation names the SAME template and resumes exactly
            # where the thread's open partial entry stopped — asserted
            # here even across an intervening kernel excursion, which is
            # precisely the case the old excursion-restart laxity could
            # not check.  A continuation with no open partial, or at the
            # wrong index, does not continue this thread's control flow.
            # The one other admissible start is §4.2a's licensed overlap:
            # ``bb_start == n - 1`` of the same template whose terminal
            # self-loop the thread's previous piece rendered whole — the
            # rep-split continuation re-entering AT the shared
            # instruction.
            tid_pairs += 1
            lic = rep_split_lic.get(tid)
            if partial_by_tid.get(tid) == (int(e["template_id"]), start):
                tid_connected += 1
            elif lic is not None and lic[0] == int(e["template_id"]) \
                    and lic[1] == start:
                tid_connected += 1
            else:
                orphans.append((e.get("seq_num"), pc, tid))
        elif prev == "unseen":
            births_by_tid[tid] = (e.get("seq_num"), pc)   # first sight
        elif prev is None:
            # Excursion restart: the kernel may resume the thread at a
            # redirected PC (a handler that never returns), so a fresh
            # whole-or-prefix entry restarts the chain without penalty.
            # Any open partial was legitimately abandoned by the redirect.
            partial_by_tid.pop(tid, None)
        else:
            tid_pairs += 1
            if pc in prev:
                tid_connected += 1
            else:
                orphans.append((e.get("seq_num"), pc, tid))

        if stop < n:
            # Partial user entry: it never reached its terminating
            # branch, so the template's successor set is NOT a
            # legitimate next-user-PC — only its own continuation is.
            partial_by_tid[tid] = (int(e["template_id"]), stop)
            chain_by_tid[tid] = set()
        else:
            partial_by_tid.pop(tid, None)
            chain_by_tid[tid] = _template_successor_pcs(t, rep_branch_id)

        # Maintain the rep-split license.  A full-extent entry whose
        # terminal instruction is the self-loop grants it (the piece may
        # be cut there by a fault, the continuation re-entering at the
        # shared instruction); the instruction's own 1-insn fan-out
        # sub-entries carry an existing grant forward; any other user
        # entry retires it.  (Kernel entries never reach here, so the
        # excursion between the pieces preserves the grant.)
        ins = t.get("insns") or []
        terminal_rep = (rep_branch_id is not None and stop == n and
                        bool(ins) and
                        int(ins[-1].get("branch_type", 0)) == rep_branch_id)
        lic = rep_split_lic.get(tid)
        if terminal_rep and n > 1:
            rep_split_lic[tid] = (int(e["template_id"]), n - 1,
                                  int(ins[-1].get("pc", 0)))
        elif terminal_rep and n == 1 and lic is not None \
                and int(ins[-1].get("pc", 0)) == lic[2]:
            pass
        else:
            rep_split_lic.pop(tid, None)

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


def _check_thread_strand_sequential(entries: list[dict],
                                    templates_by_id: dict) -> list[Issue]:
    """Every ``(thread_id, asid)`` context is ONE sequential strand.

    The format's contract is that ``thread_id`` names a guest thread and the
    vCPU is absent from the wire.  What a consumer does with that is key its
    per-thread state on ``(thread_id, asid)`` and read the entries under one
    key as a single instruction stream, in order.  That reading is only
    sound if no two threads ever carry the same id at the same time — the
    property this check tests, using the only evidence the wire has:
    control flow.

    Filtered to one context, entry N's terminal branch names entry N+1's
    resume PC — the template's start, or ``insns[bb_start].pc`` for a
    continuation entry (§4.2a); one explicit PC, never a set of
    alternatives.  When it does not, the strand was diverted, and the
    diversion is remembered.  Every
    diversion the format documents ends the strand's participation for a
    while and resumes exactly where a *nesting* boundary says it should:
    entering an excursion raises ``fault_depth``, returning lowers it, a
    privilege-domain gap is visible as an is_system change.  A diversion at
    the SAME depth and the SAME privilege, whose dangling target is picked
    up later while the entries in between chained happily among themselves,
    is none of those — it is two independent instruction streams braided
    into one context, which is exactly what a shared ``thread_id`` looks
    like from the outside.  Those are reported as errors.

    Diversions that never resume are NOT errors here: an excursion the
    tracer excludes, a privilege domain outside the trace's coverage, or a
    strand that simply ends leave a dangling target with no braid, and the
    documented-diversion census (``cst_decode --verify-branch``) is the tool
    for those.  This check is deliberately about the braid alone.

    Two guards keep an ordinary loop from being mistaken for a braid, since
    a loop re-executes the same PCs indefinitely and would otherwise match
    any old dangling target:

    * a dangling target is only tested against an entry that is ITSELF
      unexplained by its immediate predecessor.  A resumption is by
      definition a place the flow did not arrive at from the previous
      entry; an entry that continued its predecessor normally is not
      resuming anything, whatever PC it starts at.
    * a dangling target expires after ``BRAID_WINDOW`` further entries of
      its context.  Braiding is an *alternation* — the two streams trade
      off within a few blocks of each other (the observed chunks are
      single digits) — so a target picked up thousands of entries later is
      a loop revisiting a PC, not a second stream still waiting its turn.
    """
    issues: list[Issue] = []

    # Per context: the previous entry's summary, the still-dangling branch
    # targets it left behind, and how many entries that context has seen
    # (the clock the dangling targets expire on).
    prev_by_ctx: dict[tuple, dict] = {}
    open_by_ctx: dict[tuple, list[dict]] = {}
    seen_by_ctx: dict[tuple, int] = {}
    OPEN_CAP = 64
    BRAID_WINDOW = 64

    braids: list[tuple] = []          # (defer_seq, resume_seq, ctx, target)
    n_chained = n_diverted = 0

    for e in entries:
        t = templates_by_id.get(e["template_id"])
        if t is None:
            continue
        ctx = (int(e.get("thread_id", 0)), int(e.get("asid_index", 0)))
        depth = int(e.get("fault_depth", 0) or 0)
        is_sys = bool(t.get("is_system"))
        clock = seen_by_ctx.get(ctx, 0) + 1
        seen_by_ctx[ctx] = clock

        # Where control lands in THIS entry — SINGULAR and explicit
        # (§4.2a): a whole-block or prefix entry starts at the template's
        # start; a continuation entry (bb_start > 0) resumes at exactly
        # its bb_start instruction's PC.  One PC, not a set of
        # alternatives — strictly stronger than the anchor-era union.
        insns = t.get("insns") or []
        e_start = int(e.get("bb_start", 0) or 0)
        if 0 < e_start < len(insns):
            resume_pcs = {int(insns[e_start]["pc"])}
        else:
            resume_pcs = {int(t.get("start_pc", 0))}

        prev = prev_by_ctx.get(ctx)
        known = prev is not None and prev["target"] is not None
        chained = known and prev["target"] in resume_pcs

        openl = open_by_ctx.setdefault(ctx, [])
        if openl:
            openl[:] = [o for o in openl if clock - o["clock"] <= BRAID_WINDOW]
        if openl and known and not chained:
            for i in range(len(openl) - 1, -1, -1):
                if openl[i]["target"] in resume_pcs:
                    if openl[i]["braid"]:
                        braids.append((openl[i]["seq"], e.get("seq_num"), ctx,
                                       openl[i]["target"]))
                    openl.pop(i)

        if known:
            if chained:
                n_chained += 1
            else:
                n_diverted += 1
                # A same-depth, same-privilege break is the braid candidate;
                # everything else is a documented nesting boundary.
                braid = (depth == prev["depth"]
                         and is_sys == prev["is_sys"]
                         and not e.get("thread_switched"))
                openl.append({"target": prev["target"], "seq": prev["seq"],
                              "braid": braid, "clock": clock})
                if len(openl) > OPEN_CAP:
                    del openl[:len(openl) - OPEN_CAP]

        prev_by_ctx[ctx] = {"target": e.get("branch_target"),
                            "seq": e.get("seq_num"), "depth": depth,
                            "is_sys": is_sys}

    for dseq, rseq, ctx, tgt in braids[:5]:
        issues.append(Issue(
            "thread_strand", "error",
            f"context (thread={ctx[0]}, asid={ctx[1]}) is braided: the "
            f"branch at seq={dseq} to 0x{tgt:x} was left dangling and only "
            f"resumed at seq={rseq}, with unrelated entries of the SAME "
            f"context, depth and privilege in between — two concurrent "
            f"instruction streams are sharing one thread_id",
            {"defer_seq": dseq, "resume_seq": rseq, "thread": ctx[0],
             "asid": ctx[1], "target": tgt}))
    if len(braids) > 5:
        issues.append(Issue(
            "thread_strand", "error",
            f"...and {len(braids) - 5} more braided resumptions"))
    if issues:
        return issues
    return [Issue(
        "thread_strand", "info",
        f"{n_chained} in-strand successions, {n_diverted} diversions, "
        f"0 braided resumptions: every (thread_id, asid) context reads as "
        f"one sequential strand",
        {"chained": n_chained, "diverted": n_diverted, "braids": 0})]


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
                                 guest_threads: int = 1,
                                 expect_migration: bool = False
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
        entries — a legitimate discontinuity at the boundary.  With
        @expect_migration (the cross-vCPU migration test) one guest tid
        is executed on more than one vCPU, and the fault stack is a
        per-vCPU object: the SAME tid's consecutive kernel entries can
        straddle two vCPUs' baselines at the migration boundary, which
        the wire deliberately hides (thread_id carries no vCPU).  That
        kernel->kernel step is therefore exempted too, as a DOCUMENTED
        SCOPE BOUNDARY, not a papered-over bug.  The ChampSim Tracer is
        single-address-space (one pinned process; thread_id names a
        thread WITHIN it): the SUPPORTED regime pins the process to one
        core, where it never migrates and per-thread attribution is
        exact.  A cross-vCPU migration is explicitly outside that
        clean-attribution envelope — the plugin's migration-detect guard
        emits a stderr warning and a pin_multivcpu_observed stat when it
        sees the pinned process span vCPUs, and cst_attach pins the
        target by default to avoid it.  A migrated thread's USER-code
        tid still follows the thread correctly (verified by the thread
        chain and distribution checks); only KERNEL-code per-thread
        identity across the migration is unrecoverable from an
        architectural signal — kernel code carries no per-thread
        register — so the per-vCPU stack discipline cannot be asserted
        for it.  The user-level clamp and the non-migrating threads stay
        strict; whole-system multi-process attribution (ASID on the
        wire) is future work, see docs/architecture.rst,
      * continuation entries (``bb_start > 0``) sit directly at the
        excursion boundary: the same tid's previous entry either ran
        strictly deeper (the handler this continuation returns from) or
        is the block's own ``[0, k)`` prefix (``faults=0``, where the
        handler is excluded and the stretches arrive adjacent),
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
    prev_tmpl_by_tid: dict[int, tuple[int, int]] = {}
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
        # Privilege-boundary discontinuity (multi-thread, always) and the
        # per-vCPU-baseline discontinuity a migrated tid carries across a
        # kernel->kernel vCPU boundary.  The latter is exempted only under
        # @expect_migration, the deliberate out-of-envelope migration test:
        # a single-address-space trace attributes kernel code by the vCPU it
        # ran on, which a migration straddles.  This is the documented scope
        # boundary (see the docstring + docs/architecture.rst), not a bug —
        # the SUPPORTED regime pins the process to one core (cst_attach does
        # this by default; the plugin warns when a process migrates anyway).
        exempt = (guest_threads > 1 and ps is not None
                  and (ps != is_sys
                       or (expect_migration and ps and is_sys)))
        if pd is not None and abs(d - pd) > 1 and not exempt:
            step_errors += 1
            if step_errors <= 5:
                issues.append(Issue(
                    "syscall_fault_nesting", "error",
                    f"entry seq={e.get('seq_num')} thread={tid}: fault "
                    f"depth jumped {pd} -> {d}; excursions must nest and "
                    f"unwind one level at a time",
                    {"seq_num": e.get("seq_num"), "from": pd, "to": d}))
        # A continuation entry (bb_start = k > 0, §4.2a) resumes the
        # block an excursion interrupted, so within its own tid it must
        # sit DIRECTLY at the excursion boundary: the tid's previous
        # entry either ran strictly deeper (the handler content this
        # continuation returns from), or — when the handler was excluded
        # from capture (``faults=0``) — is this block's own prefix, same
        # template, stopped at exactly k.  This is checkable by
        # ADJACENCY because program order is unconditional: nothing is
        # deferred or reassembled, so the split shape sits on the wire
        # exactly where the guest ran it.  It replaces the anchor-era
        # unwind heuristic with a direct statement, expressible only
        # because the range made program order unconditional.
        #
        # This runs keyed BY tid, so the predecessor is the same thread
        # by construction.  The one multi-thread caveat is the step
        # rule's own: a PRIVILEGE-CROSSING predecessor carries no usable
        # depth (user entries are clamped to 0 next to raw-depth kernel
        # entries), so exactly that pair is exempted — the check stays
        # live everywhere else, including churn_x86's multi-process
        # fault contention where a continuation-order regression would
        # first appear.
        cont_exempt = (guest_threads > 1 and ps is not None
                       and ps != is_sys)
        e_start = int(e.get("bb_start", 0) or 0)
        pt = prev_tmpl_by_tid.get(tid)
        if (not cont_exempt and e_start > 0 and pd is not None
                and not (pd > d
                         or (pd == d and pt is not None
                             and pt[0] == int(e["template_id"])
                             and pt[1] == e_start))):
            issues.append(Issue(
                "syscall_fault_nesting", "error",
                f"entry seq={e.get('seq_num')} thread={tid} resumes at "
                f"index {e_start} (depth {d}) but the tid's previous "
                f"entry was neither the excursion it returns from "
                f"(depth {pd} not > {d}) nor its own prefix stopped at "
                f"{e_start}; a continuation must directly follow the "
                f"excursion that interrupted its block",
                {"seq_num": e.get("seq_num"), "depth": d, "prev": pd,
                 "bb_start": e_start}))
        prev_depth_by_tid[tid] = d
        prev_sys_by_tid[tid] = is_sys
        e_stop = e.get("bb_stop")
        prev_tmpl_by_tid[tid] = (
            int(e["template_id"]),
            len(t.get("insns") or []) if e_stop is None else int(e_stop))

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
    # faults=0 deliberately EXCLUDES synchronous handler excursions, so a
    # trace produced with it carries no fault_depth >= 1 entry by design —
    # the nested-fault requirement is N/A there.  Gate on the advertised
    # option (the plugin command line recorded in the header), not on the
    # empty result, so a genuine nesting regression under faults=1 is still
    # caught.  The step-discipline and anchor checks above still run: a
    # faults=0 trace's uniform depth 0 satisfies them trivially.
    faults_excluded = "faults=0" in str(trace_meta.get("command", ""))
    if (require_nested and window_count and not nested_windows
            and not faults_excluded):
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

    RANGE-SCOPED (§4.2a): the tally counts OBSERVATIONS, so each entry
    contributes the atomics inside its declared [bb_start, bb_stop)
    only.  An atomic outside an entry's range was not executed by that
    stretch — a fault-split prefix stops before it (the continuation
    carries it exactly once), and a budget-cut WP last block never
    simulated it.  A full-template walk double-counts every split visit
    of an atomic-bearing template and over-counts every cut that
    excludes one (measured: riscv64 thread_test --system --smp 2,
    static_walk = writer + 1 from one [0,3)-of-12 fault-split prefix
    whose AMO sits at index 9).

    Any divergence means the writer's runtime aggregation disagrees
    with what its own templates and ranges declare, which would be a
    tracer bug (template_id flag-byte vs entry-time stats counter).
    """
    expected = 0

    def _count(tmpl_id: int, start, stop) -> int:
        t = templates_by_id.get(int(tmpl_id))
        if t is None:
            return 0
        ins = t.get("insns") or []
        n = len(ins)
        lo = 0 if start is None else max(0, int(start))
        hi = n if stop is None else min(int(stop), n)
        return sum(1 for i in range(lo, hi) if ins[i].get("is_atomic"))

    for e in all_entries:
        expected += _count(int(e["template_id"]),
                           e.get("bb_start"), e.get("bb_stop"))
        for wp in e.get("wp_entries") or []:
            expected += _count(int(wp["template_id"]),
                               wp.get("bb_start"), wp.get("bb_stop"))

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
            # Width 0 is the WIRE-LEVEL "never captured" signal: the decoder
            # reads width_bytes from CST_FID_DST_REG_WIDTH, whose field-state
            # default is 0, so a dst that no runtime capture ever staged
            # materialises as width 0.  This is NOT an oracle loosening — a
            # captured-but-WRONG value (a mis-slice, slot contamination) is a
            # real captured register and carries the wrong register's width
            # (> 0), so it still fails this check; and a positionally
            # mis-counted entry trips the plugin's emit-time backstop and is
            # dropped whole (all-default, all-w0) before it reaches here.  The
            # only entries with a w=0 RESULT are ones whose reg-data the plugin
            # could not capture — the segment-final block the END marker cut
            # mid-execution, whose later insns never ran.  Flags cannot be
            # predicted from a result that was never observed; skip it.  (The
            # mutation-strictness tier confirms real value mutations, which are
            # width > 0, stay caught.)
            if snap.get("width_bytes") == 0:
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
                        pinned_binary: Path | None = None,
                        expect_migration: bool = False,
                        close_reason: str | None = None) -> Report:
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
    issues += _check_regfile_records(body_stats, expected_threads,
                                     entries)
    issues += _check_thread_switch(body_stats, expected_threads,
                                   system=bool(marker))
    if marker:
        # System-mode thread_ids are GUEST-THREAD identities, dense
        # 0..N-1 by first-sighting order — NOT vCPU indexes, and not
        # bounded by -smp (one vCPU can host many guest threads, and a
        # thread that migrates keeps one tid).  The population is the
        # pinned process's own thread count: @expected_guest_threads
        # (the clone test's 2) or, absent that, @expected_threads.
        issues += _check_thread_distribution(
            entries, expected_guest_threads or expected_threads,
            templates_by_id)
    else:
        issues += _check_thread_distribution(entries, expected_threads,
                                             templates_by_id)
    issues += _check_thread_record_cadence(
        entries, trace_meta.get("body_record_order") or [])
    issues += _check_range_invocations(entries, templates_by_id, trace_meta)
    issues += _check_wp_fork_resolved(entries)
    issues += _check_thread_end_flags(entries, close_reason)
    issues += _check_thread_chain(entries, templates_by_id,
                                  expected_guest_threads, trace_meta)
    issues += _check_thread_strand_sequential(entries, templates_by_id)
    if marker:
        issues += _check_syscall_transitions(
            entries, templates_by_id, trace_meta,
            guest_threads=expected_guest_threads or 1)
        issues += _check_fault_excursions(entries, templates_by_id,
                                          trace_meta)
        issues += _check_syscall_fault_nesting(
            entries, templates_by_id, trace_meta,
            guest_threads=expected_guest_threads or 1,
            expect_migration=expect_migration)
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
        # A continuation entry (bb_start > 0, §4.2a) resumes an
        # invocation its [0, k) prefix already opened: the prefix
        # contributed the block visit, so the continuation contributes
        # none — one invocation, however many stretches carried it.
        # Whether the stretches actually chain contiguously is
        # _check_range_invocations' job (range_continuity), asserted
        # below; folding here without that check would silently launder
        # a prefixless continuation into a fresh visit.
        if int(e.get("bb_start", 0) or 0) > 0:
            continue
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
    issues += _check_template_raw_bytes(templates, blocks_by_id, binary_path)
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

    issues += _check_segment_final_memops(cp_entries, templates_by_id)
    issues += _check_memop_bimodality(cp_entries, templates_by_id,
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
    issues += _check_call_return_store(templates, isa, reg_id_to_name)

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
    # checks (REG_ZERO / REG_FLAGS lookups; the per-insn src/dst ids in
    # decoded templates use the same space).
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
    # one-target/multi-target WP-shape assertions no longer hold.  The
    # same relaxation applies in system-mode marker runs: the kernel
    # interleaves with the pinned process, and a WP simulation for an
    # individual indirect execution is legitimately suppressed when the
    # excursion machinery owns the slot (WP-skip / first-TB-unavailable),
    # so "every indirect execution carries a WP" is not an invariant
    # there — only intermittently true, which is worse than useless as
    # an oracle.  The per-event indirect WP shape stays fully asserted
    # in user mode.
    if wpprune == 0 and not marker:
        issues += _check_indirect_wp_assertions(cp_entries, templates_by_id,
                                                blocks_by_id, pcmap, isa)

    # ---- Structural / cadence / format-invariant checks ---------------------
    issues += _check_encoding_map_completeness(templates, trace_meta)
    issues += _check_header_window(trace_meta, expected_start,
                                    expected_stop, expected_warmup,
                                    start_symbol, marker)

    body_stats = trace_meta.get("body_stats") or {}
    stats["body_stats"] = body_stats
    # THE WHOLE ENTRY LIST, NOT THE PROLOGUE-STRIPPED TAIL.  The IFRAME
    # cadence is a writer invariant over the SEGMENT: the counter it
    # divides (BBTemplate::emit_count) starts at the segment open and
    # `iframe_count` in body_stats counts every IFRAME in the file.
    # Handing it `cp_entries` — entries[cp_start:], the slice that drops
    # everything before the generated block's first execution — compared a
    # whole-trace numerator against a partial denominator: measured on
    # /mnt/md0/QEMU/cst_runs/ub/agentc/wave/post_a_aarch64_2_97 (aarch64
    # system -smp 2), template 700 is emitted 200102 times across the
    # trace and 2001 times after cp_start, so the floor read 0 against a
    # correct iframe_count of 2 and the cell scored error=1 on a conforming
    # tracer.
    issues += _check_iframe_cadence(body_stats, entries, trace_meta)
    # Guest-thread identity: the generated workload is single-threaded,
    # so every entry — user, or kernel inheriting the current thread —
    # carries tid 0, no matter which vCPU(s) the scheduler used or how the
    # process migrated between them.  A second tid would be a foreign
    # thread leaking past the pin, which the per-thread distribution check
    # now catches directly (stronger than the old -smp index bound, which
    # accepted any tid < smp).
    threads_effective = expected_threads
    issues += _check_thread_distribution(entries, expected_threads,
                                         templates_by_id)
    issues += _check_regfile_records(body_stats, threads_effective,
                                     entries)
    issues += _check_thread_switch(body_stats, threads_effective,
                                   system=bool(marker))
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
    issues += _check_range_invocations(entries, templates_by_id, trace_meta)
    issues += _check_wp_fork_resolved(entries)
    issues += _check_thread_end_flags(entries)
    issues += _check_thread_strand_sequential(entries, templates_by_id)
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
