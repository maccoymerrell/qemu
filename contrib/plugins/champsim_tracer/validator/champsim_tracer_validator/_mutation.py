#!/usr/bin/env python3
"""``champsim_tracer_validator mutation`` — adversarial strictness proof.

The rest of the validator asks *"does a correct trace pass?"*.  This
module asks the dual, and far more important, question: **"does an
INCORRECT trace fail — and does the RIGHT check catch it?"**  A
validation suite is only as trustworthy as the corruptions it provably
rejects, so this harness deliberately damages a known-good trace one
well-defined way at a time and asserts that a *specific* gating check
fires.  A mutation that slips through is a HOLE — a place where the
oracle tolerates a wrong trace — and is exactly the class of
permissiveness this subcommand exists to keep out.

Two mutation layers, matching the two places strictness lives:

  * **oracle** — the mutation is applied to the *decoded* trace
    (``(trace_meta, templates, entries)`` as produced by the C++
    ``cst_decode`` and parsed by :mod:`._cst_decode_runner`).  The full
    :func:`validator.validate` oracle is then re-run against the damaged
    decode (by injecting it in place of the decoder) and MUST raise a
    gating ``error`` in one of the expected checks.  This is where the
    per-insn value / classification / sequencing assertions live, and
    where recent "fix" commits have historically been tempted to add
    tolerance.

  * **wire** — the mutation is applied to the ``.cst`` container bytes
    themselves (ustar member payloads), and the real C++ ``cst_decode``
    is run on the damaged file.  This proves the decoder rejects
    structurally malformed input rather than silently producing a
    partial trace a downstream consumer would trust.

  * **wire_oracle** — a wire mutation whose catch is not guaranteed to be
    an explicit decoder bounds/tag check: the corruption may desync the
    body record stream in a way ``cst_decode`` merely tolerates (garbage
    in, garbage out) rather than rejects outright.  The real decoder is
    still run first, but when it returns 0 the mutated file is handed to
    the full :func:`validator.validate` oracle as a second line of
    defense — a semantic mismatch there is an equally valid catch.

Each mutation carries an ``expect`` set of check ids (oracle) or a wire
predicate; the runner records, per mutation, whether it was applied,
whether it was caught, and by which check — the "mutation matrix".  The
subcommand exits non-zero if ANY applied mutation was not caught.

Author: Maccoy Merrell.  SPDX-License-Identifier: GPL-2.0-or-later
"""
from __future__ import annotations

import copy
import dataclasses
import io
import re
import subprocess
import tarfile
from pathlib import Path
from typing import Callable, Optional

from . import validator as V
from . import _multiproc as MP


# ===========================================================================
# Decode-injection plumbing
# ===========================================================================

class _InjectedDecoder:
    """Stands in for the :func:`validator._load_decoder` return value so
    ``validate()`` consumes a pre-decoded (and possibly mutated) triple
    instead of re-running ``cst_decode`` on the file.  Every attribute
    other than ``decode_champsim_tracer`` (e.g. the OPCODE_NAMES /
    BRANCH_NAMES tables some checks read off the decoder module) is
    delegated to the real decoder so the oracle behaves identically."""

    def __init__(self, triple, real):
        self._triple = triple
        self._real = real

    def decode_champsim_tracer(self, _path):
        # Fresh copy per call: validate() must not see mutations bleed
        # across a re-decode, and the caller keeps the pristine triple.
        return copy.deepcopy(self._triple)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_real"), name)


def _decode_good(trace_path: Path):
    """Decode a trace to the ``(trace_meta, templates, entries)`` triple
    via the real C++ decoder + legacy parser."""
    dec = V._load_decoder()
    return dec.decode_champsim_tracer(trace_path)


def _validate_with(triple, meta_path: Path, trace_path: Path,
                   binary_path: Path, vkw: dict) -> "V.Report":
    """Run the full oracle against @triple (injected in place of the
    decoder) and return the Report."""
    orig = V._load_decoder
    dec = _InjectedDecoder(triple, orig())
    try:
        V._load_decoder = lambda: dec
        return V.validate(meta_path, trace_path, binary_path, **vkw)
    finally:
        V._load_decoder = orig


def _error_checks(report: "V.Report") -> set:
    return {i.check for i in report.errors()}


# ===========================================================================
# Target pickers (deterministic)
# ===========================================================================

def _richest_entry(entries: list, key: str):
    """Return (index, entry) of the entry carrying the most observations
    of @key ("reg_snaps" | "dyn_params"), or (None, None)."""
    best_i, best = None, -1
    for i, e in enumerate(entries):
        n = len(e.get(key) or [])
        if n > best:
            best, best_i = n, i
    if best <= 0:
        return None, None
    return best_i, entries[best_i]


def _memop_dps(entry) -> list:
    return [dp for dp in (entry.get("dyn_params") or [])
            if getattr(dp, "type_name", None) in ("load", "store")]


def _entry_with_wp_blocks(entries: list):
    """First entry whose wrong-path chain has >= 2 blocks (so a
    truncation/mis-sequence is well-defined)."""
    for i, e in enumerate(entries):
        wps = [w for w in (e.get("wp_entries") or [])
               if w.get("template_id") and not w.get("fault")
               and not w.get("translation_unavailable")]
        if len(wps) >= 2:
            return i, e, wps
    return None, None, None


# ---- coverage-surface targeting (mirrors the --coverage full-gate run) ------
#
# The exact per-insn oracles (_check_expected_insns / _check_reg_value_
# assertions) fire only on blocks the generator annotated — exactly the
# probe blocks a `--coverage` trace carries.  These helpers locate a
# template instruction (or register snapshot) covered by such an
# annotation so a value/opcode/branch mutation lands where the exact
# oracle is designed to catch it.

def _block_span(block: dict):
    gt = block.get("ground_truth") or {}
    return int(gt.get("start_pc", block.get("start_pc", 0))), \
        int(gt.get("end_pc", 0))


def _insns_at_block_pos(templates: list, start_pc: int, end_pc: int, k: int):
    """Every insn dict (across all templates) sitting at the k-th distinct
    PC of the block [start_pc, end_pc) in ascending-PC order, plus that PC.
    Mutating all copies covers block retranslations."""
    at_pc: dict = {}
    for t in templates:
        if t.get("is_system"):
            continue
        for ins in t.get("insns", []):
            pc = int(ins["pc"])
            if start_pc <= pc < end_pc:
                at_pc.setdefault(pc, []).append(ins)
    pcs = sorted(at_pc)
    if k >= len(pcs):
        return None, []
    return pcs[k], at_pc[pcs[k]]


def _first_expected_insns_block(gen_meta: dict, field: str):
    """Return (block, spec_index) for the first coverage block whose
    expected_insns spec #i declares @field ("opcode" | "branch_type" |
    "insn_flags_clear")."""
    for b in gen_meta.get("blocks", []):
        specs = b.get("expected_insns") or []
        for i, spec in enumerate(specs):
            if field in spec:
                return b, i
    return None, None


# ===========================================================================
# Mutation catalogue
# ===========================================================================

@dataclasses.dataclass
class Mutation:
    name: str
    layer: str                       # "oracle" | "wire" | "wire_verify" |
                                     # "wire_oracle"
    desc: str
    # oracle:       apply(triple) -> str|None  (returns a human note, or
    #   None when the substrate can't carry the mutation -> SKIP)
    # wire:         apply(cst_bytes) -> bytes|None
    # wire_verify:  apply(cst_bytes, decode_bin, work) -> bytes|None
    #   (structurally valid but semantically corrupt; caught by
    #   `cst_decode --strict --verify-branch`, not by a plain decode)
    # wire_oracle:  apply(cst_bytes, decode_bin, work) -> bytes|None
    #   (locating the target needs its own raw-format decode pass, so it
    #   gets the tool path + a scratch dir the plain wire layer doesn't)
    apply: Callable
    expect: tuple = ()               # oracle: acceptable catching-check ids
    expect_wire_rc_nonzero: bool = True   # wire: decoder must reject
    covered_by: str = ""             # cross-ref printed when the mutation
                                     # SKIPs (feature absent from substrate)
    # SMC mutations run against a dedicated self-modifying substrate (the
    # diamond CFG never self-modifies) with the version-aware revision oracle,
    # not the shared diamond substrate + validate().  The value names the
    # _smc.FAMILIES entry the substrate is traced from, so a mutation can
    # target a same-shape or a shape-changing revision structure.
    smc: str = ""
    # devio mutations run against a dedicated real devio trace (the diamond
    # CFG substrate carries no DEVIO records) with _multiproc's pairing
    # oracle, not validate().  apply(events, devio_sub) mutates the decoded
    # DEVIO event list in place.
    devio: bool = False


# ---- oracle mutations ------------------------------------------------------

def _reg_value_targets(triple, gen_meta):
    """Yield (block, reg_name, reg_id, matching_snaps) for each
    reg_value_assertion whose asserted value is actually observed in the
    trace — the snaps we must corrupt to break the value oracle."""
    trace_meta, templates, entries = triple
    reg_map = trace_meta.get("encoding_maps", {}).get("reg", {}) \
        or trace_meta.get("reg_names", {})
    id_by_name = {n: int(r) for r, n in reg_map.items()}
    by_id = {t["template_id"]: t for t in templates}
    out = []
    for b in gen_meta.get("blocks", []):
        assertions = b.get("reg_value_assertions") or []
        if not assertions:
            continue
        s, en = _block_span(b)
        for a in assertions:
            rid = id_by_name.get(str(a["reg"]))
            if rid is None:
                continue
            snaps = []
            for e in entries:
                t = by_id.get(e["template_id"])
                if not t:
                    continue
                insns = t.get("insns", [])
                for snap in e.get("reg_snaps") or []:
                    idx = int(snap.get("insn_index", -1))
                    if 0 <= idx < len(insns) and int(snap["reg_id"]) == rid \
                            and s <= int(insns[idx]["pc"]) < en:
                        snaps.append(snap)
            if snaps:
                out.append((b, str(a["reg"]), rid, snaps))
    return out


def _m_regdata_value_flip(triple, gen_meta) -> Optional[str]:
    """Flip the captured value on EVERY observation of a register the
    generator pins to an exact value (reg_value_assertions).  Flipping
    all of them defeats the oracle's ``any(observation matches)`` and
    proves an off-model captured value is rejected."""
    targets = _reg_value_targets(triple, gen_meta)
    if not targets:
        return None
    b, reg_name, rid, snaps = targets[0]
    old = int(snaps[0]["value"])
    for snap in snaps:
        v = int(snap["value"]) ^ 0x1
        snap["value"] = v
        snap["lo"] = int(snap.get("lo", v)) ^ 0x1
    return (f"flipped {len(snaps)} captured {reg_name} value(s) in "
            f"blk_{b['block_id']} (was 0x{old:x})")


def _m_reg_snap_misattribute(triple, gen_meta) -> Optional[str]:
    """Relabel a pinned register's captured value onto a different id
    (value present, attribution wrong): no observation for (block, reg)
    remains, so the exact-value oracle must miss its expected value."""
    targets = _reg_value_targets(triple, gen_meta)
    if not targets:
        return None
    b, reg_name, rid, snaps = targets[0]
    for snap in snaps:
        snap["reg_id"] = rid + 1 if rid + 1 != 241 else rid + 2
    return (f"relabeled {len(snaps)} {reg_name} snap(s) -> reg_id "
            f"{rid + 1} in blk_{b['block_id']}")


def _m_memdata_addr_swap(triple, gen_meta) -> Optional[str]:
    _meta, _tmpl, entries = triple
    for e in entries:
        mds = _memop_dps(e)
        vals = {id(dp): int(dp.value) for dp in mds}
        # need two memops with distinct addresses
        distinct = [dp for dp in mds]
        pairs = [(a, b) for x, a in enumerate(distinct)
                 for b in distinct[x + 1:] if int(a.value) != int(b.value)]
        if pairs:
            a, b = pairs[0]
            a.value, b.value = int(b.value), int(a.value)
            return (f"swapped memop addrs 0x{vals[id(b)]:x} <-> "
                    f"0x{vals[id(a)]:x} on entry seq={e.get('seq_num')}")
    return None


def _m_final_entry_memops_dropped(triple, gen_meta) -> Optional[str]:
    """Strip the memops from the trace's LAST body entry — the shape of the
    segment-close loss, where the entry is flushed before its instructions
    have run and its memop accumulator is therefore still empty.  Only
    meaningful when the final entry's template repeats with an invariant
    memop shape, which is exactly the condition the check asserts on."""
    _meta, _tmpl, entries = triple
    if len(entries) < 3:
        return None
    final = entries[-1]
    tid = final.get("template_id")
    peers = [e for e in entries[:-1] if e.get("template_id") == tid]
    if len(peers) < 2:
        return None
    counts = {len(p.get("dyn_params") or []) for p in peers}
    if len(counts) != 1 or 0 in counts:
        return None
    n = len(final.get("dyn_params") or [])
    if n == 0:
        return None
    final["dyn_params"] = []
    return (f"dropped {n} memop(s) from the final body entry "
            f"(seq={final.get('seq_num')}, template {tid})")


def _m_mid_entry_memops_dropped(triple, gen_meta) -> Optional[str]:
    """Strip the memops from ONE non-final execution of a template that
    otherwise always performs memops — the GENERAL shape
    ``memop_bimodality`` detects, as opposed to
    ``_m_final_entry_memops_dropped``'s positional (always-the-very-last-
    entry) special case.  Targets whichever template has the most
    invariant-nonzero executions in the substrate, so the single dropped
    execution is comfortably a minority outlier (clears both
    ``min_execs`` and ``max_outlier_rate``) regardless of substrate size,
    and picks an execution near the MIDDLE of that template's run so the
    corruption is unambiguously not the final-entry mechanism."""
    _meta, _tmpl, entries = triple
    per_tid: dict = {}
    for e in entries:
        per_tid.setdefault(e.get("template_id"), []).append(e)
    best_tid, best_execs = None, []
    for tid, execs in per_tid.items():
        if len(execs) < 12:            # headroom over min_execs=8 so a
            continue                   # single outlier stays <= 10% rate
        counts = {len(e.get("dyn_params") or []) for e in execs}
        if len(counts) != 1 or 0 in counts:
            continue
        if len(execs) > len(best_execs):
            best_tid, best_execs = tid, execs
    if best_tid is None:
        return None
    victim = best_execs[len(best_execs) // 2]
    n = len(victim.get("dyn_params") or [])
    if n == 0:
        return None
    victim["dyn_params"] = []
    return (f"dropped {n} memop(s) from a MID-STREAM execution "
            f"(seq={victim.get('seq_num')}, template {best_tid}, 1 of "
            f"{len(best_execs)} otherwise-invariant executions)")


def _m_memdata_data_flip(triple, gen_meta) -> Optional[str]:
    _meta, _tmpl, entries = triple
    for e in entries:
        for dp in _memop_dps(e):
            old = int(dp.data_lo)
            dp.data = int(dp.data) ^ 0x100
            dp.data_lo = old ^ 0x100
            return (f"flipped memop data 0x{old:x}->0x{dp.data_lo:x} "
                    f"(kind={dp.type_name}) entry seq={e.get('seq_num')}")
    return None


def _pick_executed_template(triple):
    """A template that a CP entry actually executed (so its block is in
    cp_set and the block-level assertions will evaluate it)."""
    _meta, templates, entries = triple
    by_id = {t["template_id"]: t for t in templates}
    for e in entries:
        if e.get("reg_snaps") or e.get("dyn_params"):
            t = by_id.get(e["template_id"])
            if t and t.get("insns"):
                return t
    # fall back to any template with insns
    for t in templates:
        if t.get("insns"):
            return t
    return None


def _m_opcode_class_change(triple, gen_meta) -> Optional[str]:
    """Relabel the opcode of an instruction the generator pinned via an
    expected_insns ``opcode`` spec — the exact per-insn classification
    oracle must reject it."""
    trace_meta, templates, _entries = triple
    b, k = _first_expected_insns_block(gen_meta, "opcode")
    if b is None:
        return None
    s, en = _block_span(b)
    pc, insns = _insns_at_block_pos(templates, s, en, k)
    if not insns:
        return None
    opmap = trace_meta.get("encoding_maps", {}).get("opcode", {}) \
        or trace_meta.get("opcode_names", {})
    old = int(insns[0]["opcode"])
    alt = next((int(oid) for oid in opmap if int(oid) != old), None)
    if alt is None:
        return None
    for ins in insns:
        ins["opcode"] = alt
    return (f"blk_{b['block_id']} insn@0x{pc:x} opcode {old}"
            f"({opmap.get(old)})->{alt}({opmap.get(alt)}) [expected_insns "
            f"spec #{k}]")


def _m_template_raw_byte_flip(triple, gen_meta) -> Optional[str]:
    t = _pick_executed_template(triple)
    if t is None:
        return None
    for ins in t["insns"]:
        rb = ins.get("raw_bytes")
        if rb:
            b = bytearray(rb)
            b[0] ^= 0xFF
            ins["raw_bytes"] = bytes(b)
            return (f"template {t['template_id']} insn@0x{ins['pc']:x} "
                    f"raw byte0 flipped")
    return None


def _pick_unlabeled_template(triple, gen_meta):
    """A non-system template every one of whose instructions falls
    OUTSIDE every generator block's PC span -- e.g. the `_start`/CRT
    prologue that runs before the first `blk_N` label.  This is exactly
    the class of template the labeled-block ground truth (`_block_span`)
    cannot index, so it is the class `template_raw_bytes`'s binary-image
    fallback exists to cover; targeting it here proves that fallback
    fires rather than relying on `_pick_executed_template` landing there
    incidentally (which is substrate/ISA order dependent)."""
    _meta, templates, _entries = triple
    spans = [s for s in (_block_span(b) for b in gen_meta.get("blocks", []))
             if s[1] > s[0]]

    def _labeled(pc: int) -> bool:
        return any(s <= pc < e for s, e in spans)

    for t in templates:
        if t.get("is_system") or not t.get("insns"):
            continue
        if all(not _labeled(int(ins["pc"])) for ins in t["insns"]):
            return t
    return None


def _m_template_raw_byte_flip_prologue(triple, gen_meta) -> Optional[str]:
    """Flip a raw byte in an UNLABELED template (no generator block spans
    its PCs -- the `_start`/CRT prologue). Dedicated from
    `_m_template_raw_byte_flip`, whose "richest executed template" pick
    lands on the prologue only incidentally: this row exists so the
    binary-image fallback in `_check_template_raw_bytes` is exercised on
    every substrate/ISA, not just the ones where target selection
    happens to wander there."""
    t = _pick_unlabeled_template(triple, gen_meta)
    if t is None:
        return None
    for ins in t["insns"]:
        rb = ins.get("raw_bytes")
        if rb:
            b = bytearray(rb)
            b[0] ^= 0xFF
            ins["raw_bytes"] = bytes(b)
            return (f"template {t['template_id']} insn@0x{ins['pc']:x} "
                    f"raw byte0 flipped [unlabeled/prologue template]")
    return None


def _m_branch_type_change(triple, gen_meta) -> Optional[str]:
    """Corrupt the branch classification of an instruction the generator
    pinned via an expected_insns ``branch_type`` spec (and set its
    conditional flag, which the spec clears) — the exact oracle rejects
    both."""
    trace_meta, templates, _entries = triple
    b, k = _first_expected_insns_block(gen_meta, "branch_type")
    if b is None:
        return None
    s, en = _block_span(b)
    pc, insns = _insns_at_block_pos(templates, s, en, k)
    if not insns:
        return None
    brmap = trace_meta.get("encoding_maps", {}).get("branch_type", {}) \
        or trace_meta.get("branch_names", {})
    old = int(insns[0].get("branch_type", 0))
    alt = next((int(bid) for bid in brmap if int(bid) != old), None)
    for ins in insns:
        if alt is not None:
            ins["branch_type"] = alt
        ins["branch_conditional"] = not bool(ins.get("branch_conditional"))
    return (f"blk_{b['block_id']} insn@0x{pc:x} branch_type {old}->{alt} + "
            f"conditional flip [expected_insns spec #{k}]")


def _predicted_fork_entries(triple, gen_meta):
    """Mirror _check_wrong_path_chains's cp_pos walk (prologue skip +
    per-block advance) to find the CP entries that sit at a PREDICTED
    wrong-path fork — the only entries whose WP chain the oracle actually
    checks against a prediction.  Returns a list of
    (entry, wp_chain_prediction, wp_block_entries) for fault-free forks
    carrying >= 2 WP blocks (so a divergence/truncation is well-defined),
    plus a template->ordered-blocks resolver."""
    trace_meta, templates, entries = triple
    by_id = {t["template_id"]: t for t in templates}
    spans = []
    for b in gen_meta.get("blocks", []):
        s, en = _block_span(b)
        if en > s:
            spans.append((s, en, int(b["block_id"])))
    spans.sort()

    def blk_of_pc(pc: int):
        for s, en, bid in spans:
            if s <= pc < en:
                return bid
        return None

    def tmpl_blocks(t):
        out = []
        for ins in t.get("insns", []):
            bid = blk_of_pc(int(ins["pc"]))
            if bid is None:
                continue
            if not out or out[-1] != bid:
                out.append(bid)
        return out

    correct_path = gen_meta.get("correct_path") or []
    if not correct_path:
        return [], by_id, tmpl_blocks
    entry_bid = correct_path[0]
    # prologue skip: first entry whose template covers the entry block
    cp_start = None
    for i, e in enumerate(entries):
        if entry_bid in tmpl_blocks(by_id.get(e["template_id"], {})):
            cp_start = i
            break
    if cp_start is None:
        return [], by_id, tmpl_blocks

    wrong = gen_meta.get("wrong_paths") or {}
    cp_pos = -1
    last = None
    forks = []
    for e in entries[cp_start:]:
        t = by_id.get(e["template_id"])
        if not t:
            continue
        blocks = tmpl_blocks(t)
        if not blocks:
            continue
        advanced = False
        for bid in blocks:
            if bid != last:
                last = bid
                cp_pos += 1
                advanced = True
        if not advanced:
            continue
        key = str(cp_pos)
        if key not in wrong:
            continue
        wpe = [w for w in (e.get("wp_entries") or []) if w.get("template_id")]
        faulted = any(w.get("fault") or w.get("translation_unavailable")
                      for w in (e.get("wp_entries") or []))
        if len(wpe) >= 2 and not faulted:
            forks.append((e, list(wrong[key].get("wp_chain", [])), wpe))
    return forks, by_id, tmpl_blocks


def _m_wp_chain_truncate(triple, gen_meta) -> Optional[str]:
    """Drop the last block of a PREDICTED wrong-path chain."""
    forks, _by_id, _tb = _predicted_fork_entries(triple, gen_meta)
    if not forks:
        return None
    e, _pred, wpe = forks[0]
    dropped = wpe[-1]
    e["wp_entries"].remove(dropped)
    return (f"dropped last WP block (tmpl={dropped.get('template_id')}) from "
            f"predicted-fork entry seq={e.get('seq_num')} "
            f"({len(wpe)} blocks)")


def _m_wp_chain_missequence(triple, gen_meta) -> Optional[str]:
    """Reorder the first two blocks of a PREDICTED wrong-path chain so the
    emitted chain diverges from the prediction at depth 0."""
    forks, by_id, tmpl_blocks = _predicted_fork_entries(triple, gen_meta)
    for e, _pred, wpe in forks:
        w0, w1 = wpe[0], wpe[1]
        b0 = tmpl_blocks(by_id.get(w0["template_id"], {}))
        b1 = tmpl_blocks(by_id.get(w1["template_id"], {}))
        if b0 and b1 and b0[0] != b1[0]:
            w0["template_id"], w1["template_id"] = \
                w1["template_id"], w0["template_id"]
            return (f"swapped WP blocks 0/1 (blk_{b0[0]}<->blk_{b1[0]}) on "
                    f"predicted-fork entry seq={e.get('seq_num')}")
    return None


def _m_wp_late_fault_no_excuse(triple, gen_meta) -> Optional[str]:
    """Missequence the wrong-path chain at depth 0 AND mark a LATER block a
    synthetic-data FAULT.  The reconciled fault policy licenses a block-
    sequence divergence only at a position STRICTLY AFTER the first marked
    fault (everything downstream of a fault is synthetic placeholder), so a
    fault at block >= 2 must NOT retroactively excuse the depth-0 divergence.
    This guards the reconciliation from degrading into a blanket
    "any fault anywhere tolerates any divergence" hole: wrong_path_chains
    must still fire on the unlicensed early divergence."""
    forks, by_id, tmpl_blocks = _predicted_fork_entries(triple, gen_meta)
    for e, _pred, wpe in forks:
        if len(wpe) < 2:
            continue
        w0, w1 = wpe[0], wpe[1]
        b0 = tmpl_blocks(by_id.get(w0["template_id"], {}))
        b1 = tmpl_blocks(by_id.get(w1["template_id"], {}))
        if b0 and b1 and b0[0] != b1[0]:
            w0["template_id"], w1["template_id"] = \
                w1["template_id"], w0["template_id"]
            # Mark the LAST block a synthetic-data fault at its first insn:
            # its collapsed position is strictly AFTER the depth-0 divergence
            # the swap created, so it must not license that earlier divergence.
            wpe[-1]["fault"] = True
            wpe[-1]["fault_insn_index"] = 0
            return (f"swapped WP blocks 0/1 (blk_{b0[0]}<->blk_{b1[0]}) and "
                    f"FAULT-marked the last block on predicted-fork entry "
                    f"seq={e.get('seq_num')} — a later fault must not excuse "
                    f"the depth-0 divergence")
    return None


def _m_bb_successor_missequence(triple, gen_meta) -> Optional[str]:
    """Swap two CP entries carrying different templates so the emitted
    block-visit order no longer matches the ground-truth correct path."""
    _meta, _tmpl, entries = triple
    # find two entries with different template ids that both carry
    # observations (i.e. are post-prologue workload blocks)
    idxs = [i for i, e in enumerate(entries)
            if e.get("reg_snaps") or e.get("dyn_params")]
    for a in idxs:
        for b in idxs:
            if b <= a:
                continue
            if entries[a]["template_id"] != entries[b]["template_id"]:
                entries[a], entries[b] = entries[b], entries[a]
                return (f"swapped CP entries at positions {a}<->{b} "
                        f"(templates {entries[b]['template_id']} / "
                        f"{entries[a]['template_id']})")
    return None


def _m_split_pair_reorder(triple, gen_meta) -> Optional[str]:
    """Split one whole-block entry into its two §4.2a stretches and emit
    them in the WRONG order — the continuation ``[k, n)`` before its own
    prefix ``[0, k)``.  Program order is unconditional: a continuation
    that arrives before the prefix that opens its invocation is exactly
    the reordering the range contract exists to make detectable, and
    ``range_continuity`` must flag it (a continuation with no open
    invocation, then a prefix left dangling)."""
    _meta, templates, entries = triple
    by_id = {t["template_id"]: t for t in templates}
    for j in range(1, len(entries)):
        e = entries[j]
        t = by_id.get(e["template_id"])
        n = len((t or {}).get("insns") or [])
        if n < 2 or e.get("bb_start") or e.get("bb_stop") is not None:
            continue
        k = n // 2
        cont = dict(e)
        pref = dict(e)
        cont["bb_start"], cont["bb_stop"] = k, n
        pref["bb_start"], pref["bb_stop"] = 0, k
        # The prefix never reached the terminating branch: no outcome.
        pref["branch_taken"] = None
        pref["branch_target"] = None
        pref["wp_entries"] = []

        def _by_idx(rows, lo, hi):
            out = []
            for r in rows or []:
                idx = getattr(r, "insn_index", None)
                if idx is None and isinstance(r, dict):
                    idx = r.get("insn_index")
                if idx is not None and lo <= int(idx) < hi:
                    out.append(r)
            return out

        cont["dyn_params"] = _by_idx(e.get("dyn_params"), k, n)
        pref["dyn_params"] = _by_idx(e.get("dyn_params"), 0, k)
        cont["reg_snaps"] = _by_idx(e.get("reg_snaps"), k, n)
        pref["reg_snaps"] = _by_idx(e.get("reg_snaps"), 0, k)
        entries[j: j + 1] = [cont, pref]
        return (f"entry seq={e.get('seq_num')} (BB{e['template_id']}, "
                f"n={n}) split at {k} and REORDERED: [{k},{n}) emitted "
                f"before [0,{k})")
    return None


def _m_ppage_corrupt(triple, gen_meta) -> Optional[str]:
    """Corrupt a per-memop physical-page (LOAD_PPAGE / STORE_PPAGE) value.
    Requires a physaddr=1 (system-mode) substrate; the fast user-mode
    substrate carries no ppage records, so this SKIPs with a cross-ref to
    the gating features.physaddr probe."""
    _meta, _tmpl, entries = triple
    for e in entries:
        for dp in e.get("dyn_params") or []:
            if getattr(dp, "type_name", "").endswith("ppage"):
                old = int(dp.value)
                dp.value = old ^ 0x1000
                return f"corrupted ppage 0x{old:x}->0x{dp.value:x}"
    return None


def _m_devio_stop_drop(events: list, _devio_sub: dict) -> Optional[str]:
    """Drop one DEVIO_STOP event, unbalancing its START's bracket.

    Runs against a REAL devio trace (devio_mutation_substrate, the same
    build/boot/decode pipeline run_devio_probe uses), not the shared
    diamond-CFG substrate, which carries no DEVIO records at all.  The
    drop happens on the DECODED event list --format=disasm's real
    cst_decode already surfaced from that trace, rather than a byte-exact
    wire splice: tools/cst_raw.cc's --format=raw structural walker
    (dump_body) has no DEVIO_* branch and aborts the rest of the walk on
    the first one it meets, so there is no tool-supported way to locate a
    DEVIO_STOP's exact body.cst byte offset without extending cst_raw.cc
    (a tools/ change, out of scope here) -- dropping the event a real
    decode of a real wire already produced is the substrate-faithful
    equivalent of losing that STOP on the wire.  _run_devio_mutation then
    re-runs _multiproc._devio_pairing_check, the SAME oracle
    run_devio_probe's own check (1) uses, and it must flag the resulting
    dangling START."""
    for i, e in enumerate(events):
        if e["kind"] == "stop":
            req = e["req"]
            del events[i]
            return f"dropped DEVIO STOP req={req} (unbalanced bracket)"
    return None


def _m_thread_id_forge(triple, gen_meta) -> Optional[str]:
    """Stamp a foreign guest-thread id onto one CP entry — the pin-leak
    class the single-thread distribution / chain checks must catch."""
    _meta, _tmpl, entries = triple
    _i, e = _richest_entry(entries, "reg_snaps")
    if e is None:
        return None
    old = int(e.get("thread_id", 0))
    e["thread_id"] = old + 7
    return f"entry seq={e.get('seq_num')} thread_id {old}->{e['thread_id']}"


def _m_thread_end_dropped(triple, gen_meta) -> Optional[str]:
    """Strip CST_BB_FLAG_THREAD_END from the close's final entry (the
    stream tail) — the close route that forgets the stamp (the F6
    defect class).  The thread_end oracle must fail: a consumer would
    otherwise have to infer the context's end from it not reappearing,
    which the format forbids."""
    _meta, _tmpl, entries = triple
    if entries and entries[-1].get("thread_end"):
        e = entries[-1]
        e["thread_end"] = False
        return (f"entry seq={e.get('seq_num')} "
                f"(thread={e.get('thread_id')}) thread_end 1->0")
    return None            # substrate carries no stamped close-final


# ---- wire mutations --------------------------------------------------------

def _tar_members(cst_bytes: bytes) -> dict:
    out = {}
    with tarfile.open(fileobj=io.BytesIO(cst_bytes)) as t:
        for m in t.getmembers():
            out[m.name] = (m, t.extractfile(m).read())
    return out


def _repack(members: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, (m, data) in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = m.mode
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _member_name(members: dict, prefix: str) -> Optional[str]:
    for name in members:
        if name.startswith(prefix):
            return name
    return None


def _mw_header_magic_corrupt(cst_bytes: bytes) -> Optional[bytes]:
    members = _tar_members(cst_bytes)
    hn = _member_name(members, "header.cst")
    if hn is None:
        return None
    m, data = members[hn]
    b = bytearray(data)
    b[0] ^= 0xFF   # first 4 bytes are the CST_MAGIC u32_le
    members[hn] = (m, bytes(b))
    return _repack(members)


def _mw_body_member_drop(cst_bytes: bytes) -> Optional[bytes]:
    members = _tar_members(cst_bytes)
    bn = _member_name(members, "body.cst")
    if bn is None:
        return None
    del members[bn]
    return _repack(members)


def _mw_body_truncate(cst_bytes: bytes) -> Optional[bytes]:
    members = _tar_members(cst_bytes)
    bn = _member_name(members, "body.cst")
    if bn is None:
        return None
    m, data = members[bn]
    if len(data) < 32:
        return None
    members[bn] = (m, data[: len(data) // 2])   # lose the second half
    return _repack(members)


def _raw_dump(cst_path: Path, decode_bin: Path) -> Optional[str]:
    """``cst_decode --format=raw`` stdout for @cst_path, or None if the
    (supposedly pristine) substrate doesn't even raw-decode."""
    proc = subprocess.run([str(decode_bin), "--format=raw", str(cst_path)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    return proc.stdout


# ---- epoch 0x1E block-record injection (format.rst §5.7 / Step 6.7) --------
#
# The block-level facts — executed range, flags, fault depth — are ordinary
# field-delta records at BLOCK_POS = num_insns, delta-persistent per
# (template_id, BLOCK_POS, fid) with baselines (0, num_insns, 0, ...).  A
# wire mutation therefore INJECTS a record into one entry's own
# cp_delta_section: re-encode the section's len and n_records ULEBs, keep
# the existing record bytes, and append the new record at the section's
# tail (BLOCK_POS is the highest position, so a trailing block record
# keeps the non-descending (ipos, fid) order).  Everything needed to aim
# the splice — the numeric field ids, the bb_flag masks, each template's
# num_insns, each entry's section geometry — is parsed from the
# ``cst_decode --format=raw`` structural dump of the pristine substrate.


def _uleb_encode(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _sleb_encode(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        done = (v == 0 and not (b & 0x40)) or (v == -1 and (b & 0x40))
        out.append(b if done else b | 0x80)
        if done:
            return bytes(out)


_RAW_OFF = re.compile(r"^\s*@([0-9a-fA-F]+)\s")
_RAW_MAP = re.compile(r'map "(\w+)"')
_RAW_MAP_ENTRY = re.compile(r"(\d+) = (\S+)$")
_RAW_TMPL = re.compile(r"template_id=(\d+)\s+start_pc=\S+\s+num_insns=(\d+)")
_RAW_CPSEC = re.compile(r"cp_delta_section\s+len=(\d+)")
_RAW_NREC = re.compile(r"n_records=(\d+)$")
# cst_raw's named() prints "fid=<numeric> (<resolved name>)".
_RAW_REC = re.compile(
    r"rec\[\d+\] ipos\+=\d+ ->ipos=(\d+)\s+fid=\d+ \(([^)]*)\)")
_RAW_ENTRY_TMPL = re.compile(r"->template_id=(-?\d+)\s+\[Step 6\.4\]")
_RAW_NUMWP = re.compile(r"num_wp=(\d+)$")


def _parse_raw_body(raw_text: str) -> dict:
    """Structure of the raw dump the injection helpers aim by: the
    field_id / bb_flag encoding maps (name -> numeric id / mask), each
    template's num_insns, and per CP entry the template id, the
    cp_delta_section geometry (len-ULEB offset, payload length,
    n_records offset + count), its records' (ipos, fid name), and the
    entry's num_wp.  Body offsets are in-member byte offsets of
    ``body.cst`` (cst_raw.cc prints each line's read-start offset)."""
    maps: dict[str, dict[str, int]] = {}
    tmpl_insns: dict[int, int] = {}
    entries: list[dict] = []
    cur_map = None
    in_body = False
    e = None                      # entry under construction
    state = None                  # None | "want_sec" | "want_nrec" | "recs"
    for line in raw_text.splitlines():
        if "=== BODY member ===" in line:
            in_body = True
            cur_map = None
            continue
        if not in_body:
            mm = _RAW_MAP.search(line)
            if mm:
                cur_map = maps.setdefault(mm.group(1), {})
                continue
            if cur_map is not None:
                me = _RAW_MAP_ENTRY.search(line)
                if me:
                    cur_map[me.group(2)] = int(me.group(1))
                    continue
            mt = _RAW_TMPL.search(line)
            if mt:
                tmpl_insns[int(mt.group(1))] = int(mt.group(2))
            continue
        # body member
        off_m = _RAW_OFF.match(line)
        off = int(off_m.group(1), 16) if off_m else None
        if "ENTRY  tag=" in line:
            e = {"template_id": None, "sec_off": None, "sec_len": None,
                 "nrec_off": None, "n_records": None, "recs": [],
                 "num_wp": 0}
            entries.append(e)
            state = "want_sec"
            continue
        if e is None:
            continue
        if state == "want_sec":
            mt = _RAW_ENTRY_TMPL.search(line)
            if mt:
                e["template_id"] = int(mt.group(1))
                continue
            ms = _RAW_CPSEC.search(line)
            if ms and off is not None:
                e["sec_off"], e["sec_len"] = off, int(ms.group(1))
                state = "want_nrec"
            continue
        if state == "want_nrec":
            mn = _RAW_NREC.search(line)
            if mn and off is not None:
                e["nrec_off"], e["n_records"] = off, int(mn.group(1))
                state = "recs"
            continue
        if state == "recs":
            mr = _RAW_REC.search(line)
            if mr:
                e["recs"].append((int(mr.group(1)), mr.group(2)))
                continue
            if "wp_chain_section" in line:
                state = "want_numwp"    # num_wp prints on the NEXT line
                continue
            state = None                # CP section fully captured, no WP
            continue
        if state == "want_numwp":
            mw = _RAW_NUMWP.search(line)
            if mw:
                e["num_wp"] = int(mw.group(1))
            state = None
            continue
    return {"maps": maps, "tmpl_insns": tmpl_insns, "entries": entries}


def _inject_block_record(cst_bytes: bytes, entry: dict, n_insns: int,
                         fid: int, delta: int) -> Optional[bytes]:
    """Splice one field-delta record (ipos = BLOCK_POS, @fid, @delta) at
    the tail of @entry's cp_delta_section inside the ``body.cst`` tar
    member, re-encoding the section's len and n_records ULEBs."""
    members = _tar_members(cst_bytes)
    bn = _member_name(members, "body.cst")
    if bn is None:
        return None
    m, data = members[bn]
    sec_off, sec_len = entry["sec_off"], entry["sec_len"]
    nrec_off, n_records = entry["nrec_off"], entry["n_records"]
    if None in (sec_off, sec_len, nrec_off, n_records):
        return None
    sec_end = nrec_off + sec_len          # payload starts at n_records
    if sec_end > len(data):
        return None
    last_ipos = entry["recs"][-1][0] if entry["recs"] else 0
    if last_ipos > n_insns:
        return None
    rec = (_uleb_encode(n_insns - last_ipos) + _uleb_encode(fid)
           + _sleb_encode(delta))
    old_nrec_w = len(_uleb_encode(n_records))
    body_rest = data[nrec_off + old_nrec_w: sec_end]
    new = (data[:sec_off]
           + _uleb_encode(sec_len + len(rec))
           + _uleb_encode(n_records + 1)
           + body_rest + rec + data[sec_end:])
    members[bn] = (m, bytes(new))
    return _repack(members)


_BR_TARGET_REC = re.compile(r"^\s*@([0-9a-fA-F]+)\s+((?:[0-9a-f]{2} )+)\s")


def _branch_target_cell_offset(raw_text: str) -> Optional[int]:
    """``body.cst`` byte offset of the LAST byte of the first
    ``CST_FID_BRANCH_TARGET`` delta record (format.rst §5.6) in a
    ``cst_decode --format=raw`` structural dump.  That byte closes the
    record's signed-LEB displacement delta, so flipping its low bit moves
    the encoded branch target without changing the record's length -- the
    body stream stays structurally intact and only the SEMANTICS of the
    branch outcome are corrupt.  Records whose byte column the raw dump
    elided (trailing ``+``) are skipped: their length is unknown."""
    for line in raw_text.splitlines():
        if "CST_FID_BRANCH_TARGET" not in line or "rec[" not in line:
            continue
        if "+" in line.split("rec[")[0]:
            continue
        m = _BR_TARGET_REC.match(line)
        if m:
            return int(m.group(1), 16) + len(m.group(2).split()) - 1
    return None


def _mw_branch_target_corrupt(cst_bytes: bytes, decode_bin: Path,
                              work: Path) -> Optional[bytes]:
    """Move one encoded branch target on the wire.  The decoder replays the
    corrupt displacement without complaint (it is a well-formed LEB in a
    well-formed record), so the catch has to come from the branch-outcome
    self-check: ``cst_decode --strict --verify-branch`` cross-checks every
    CST_FID_BRANCH_* against the architectural continuation and must flag
    the moved target."""
    probe = work / "_branch_target_probe.cst"
    probe.write_bytes(cst_bytes)
    try:
        raw_text = _raw_dump(probe, decode_bin)
    finally:
        probe.unlink(missing_ok=True)
    if raw_text is None:
        return None
    off = _branch_target_cell_offset(raw_text)
    if off is None:
        return None
    members = _tar_members(cst_bytes)
    bn = _member_name(members, "body.cst")
    if bn is None or off >= len(members[bn][1]):
        return None
    m, data = members[bn]
    b = bytearray(data)
    b[off] ^= 0x01
    members[bn] = (m, bytes(b))
    return _repack(members)


def _raw_parsed(cst_bytes: bytes, decode_bin: Path, work: Path,
                tag: str) -> Optional[dict]:
    probe = work / f"_{tag}_probe.cst"
    probe.write_bytes(cst_bytes)
    try:
        raw_text = _raw_dump(probe, decode_bin)
    finally:
        probe.unlink(missing_ok=True)
    if raw_text is None:
        return None
    return _parse_raw_body(raw_text)


def _entry_geometry_ok(e: dict) -> bool:
    return (e.get("template_id") is not None and e.get("sec_off") is not None
            and e.get("nrec_off") is not None)


def _mw_range_stop_overflow(cst_bytes: bytes, decode_bin: Path,
                            work: Path) -> Optional[bytes]:
    """Push one entry's CST_FID_BB_STOP past its template's num_insns
    (delta +1 against the num_insns baseline, §5.7).  A conformant
    decoder MUST reject the entry at Step 6.4's range check — this is
    the epoch's replacement for the retired presence-bit desync proof:
    a block record that mis-frames the entry must fail loudly, never
    silently reshape what the entry claims."""
    p = _raw_parsed(cst_bytes, decode_bin, work, "range_stop_overflow")
    if p is None:
        return None
    fid = p["maps"].get("field_id", {}).get("CST_FID_BB_STOP")
    if fid is None:
        return None
    for e in p["entries"]:
        if not _entry_geometry_ok(e):
            continue
        n = p["tmpl_insns"].get(e["template_id"])
        if not n:
            continue
        if any(ip >= n for ip, _ in e["recs"]):
            continue                      # keep clear of existing block recs
        return _inject_block_record(cst_bytes, e, n, fid, +1)
    return None


def _mw_range_inverted(cst_bytes: bytes, decode_bin: Path,
                       work: Path) -> Optional[bytes]:
    """Raise one entry's CST_FID_BB_START to num_insns while BB_STOP
    stays at its num_insns baseline: the declared range is empty /
    inverted, which no honest entry can state (a block that executed
    nothing is not an event, §4.2a) — the decoder MUST reject."""
    p = _raw_parsed(cst_bytes, decode_bin, work, "range_inverted")
    if p is None:
        return None
    fid = p["maps"].get("field_id", {}).get("CST_FID_BB_START")
    if fid is None:
        return None
    for e in p["entries"]:
        if not _entry_geometry_ok(e):
            continue
        n = p["tmpl_insns"].get(e["template_id"])
        if not n:
            continue
        if any(ip >= n for ip, _ in e["recs"]):
            continue
        return _inject_block_record(cst_bytes, e, n, fid, +n)
    return None


def _mw_range_out_of_record(cst_bytes: bytes, decode_bin: Path,
                            work: Path) -> Optional[bytes]:
    """Shrink CST_FID_BB_STOP by one on an entry whose OWN section
    carries a per-instruction record at the template's last position:
    that record now claims an observation of an instruction the entry
    itself disclaims, and a conformant decoder MUST reject it (§4.2a's
    normative rule; the range scopes every per-instruction family)."""
    p = _raw_parsed(cst_bytes, decode_bin, work, "range_out_of_record")
    if p is None:
        return None
    fid = p["maps"].get("field_id", {}).get("CST_FID_BB_STOP")
    if fid is None:
        return None
    for e in p["entries"]:
        if not _entry_geometry_ok(e):
            continue
        n = p["tmpl_insns"].get(e["template_id"])
        if not n or n < 2:
            continue
        if any(ip >= n for ip, _ in e["recs"]):
            continue
        if not any(ip == n - 1 for ip, _ in e["recs"]):
            continue                      # need a record the shrink orphans
        return _inject_block_record(cst_bytes, e, n, fid, -1)
    return None


def _mw_range_stuck(cst_bytes: bytes, decode_bin: Path,
                    work: Path) -> Optional[bytes]:
    """Shrink CST_FID_BB_STOP by one on a QUIET entry (no record of its
    own at the last position): the wire stays decoder-clean — the range
    is well-formed and scopes every record present — but the entry now
    claims it stopped one instruction short, and the cell DELTA-PERSISTS
    to every later entry of the template.  The catch must come from the
    validator's range oracle: an invocation left open mid-stream with no
    excursion on the wire to explain the cut (range_continuity)."""
    p = _raw_parsed(cst_bytes, decode_bin, work, "range_stuck")
    if p is None:
        return None
    fid = p["maps"].get("field_id", {}).get("CST_FID_BB_STOP")
    if fid is None:
        return None
    for i, e in enumerate(p["entries"]):
        if not _entry_geometry_ok(e) or i + 1 >= len(p["entries"]):
            continue
        n = p["tmpl_insns"].get(e["template_id"])
        if not n or n < 2:
            continue
        if any(ip >= n - 1 for ip, _ in e["recs"]):
            continue                      # quiet at the orphaned tail
        return _inject_block_record(cst_bytes, e, n, fid, -1)
    return None


def _mw_stuck_bb_flags(cst_bytes: bytes, decode_bin: Path,
                       work: Path) -> Optional[bytes]:
    """Latch CST_BB_FLAG_BRANCH_UNRESOLVED onto an entry that carries a
    wrong-path chain and no branch record of its own (its outcome rides
    the delta-persistent cells).  The decoder tolerates it — the flag
    legitimately suppresses the outcome read — and the flag then STICKS
    to every later entry of the template, eating their outcomes too.
    The catch must come from the validator: an entry whose wrong-path
    chain proves the branch WAS resolved cannot honestly claim its
    successor was never observed (wp_fork_resolved)."""
    p = _raw_parsed(cst_bytes, decode_bin, work, "stuck_bb_flags")
    if p is None:
        return None
    fid = p["maps"].get("field_id", {}).get("CST_FID_BB_FLAGS")
    mask = p["maps"].get("bb_flag", {}).get("CST_BB_FLAG_BRANCH_UNRESOLVED")
    if fid is None or not mask:
        return None
    for e in p["entries"]:
        if not _entry_geometry_ok(e) or e["num_wp"] < 1:
            continue
        n = p["tmpl_insns"].get(e["template_id"])
        if not n:
            continue
        if any(ip >= n for ip, _ in e["recs"]):
            continue
        if any("BRANCH" in name for _, name in e["recs"]):
            continue                      # decoder would reject (§5.6); the
                                          # tolerated shape is the point here
        return _inject_block_record(cst_bytes, e, n, fid, +mask)
    return None


def _mw_fabricated_branch_on_unresolved(cst_bytes: bytes, decode_bin: Path,
                                        work: Path) -> Optional[bytes]:
    """Raise CST_BB_FLAG_BRANCH_UNRESOLVED on an entry that stages a
    branch-outcome singleton in its OWN section: the entry now both
    declares its successor unobserved and publishes one — §5.6's
    writer-side prohibition made bytes.  A conformant decoder MUST
    reject the contradiction rather than pick a side silently."""
    p = _raw_parsed(cst_bytes, decode_bin, work, "fabricated_branch")
    if p is None:
        return None
    fid = p["maps"].get("field_id", {}).get("CST_FID_BB_FLAGS")
    mask = p["maps"].get("bb_flag", {}).get("CST_BB_FLAG_BRANCH_UNRESOLVED")
    if fid is None or not mask:
        return None
    for e in p["entries"]:
        if not _entry_geometry_ok(e):
            continue
        n = p["tmpl_insns"].get(e["template_id"])
        if not n:
            continue
        if any(ip >= n for ip, _ in e["recs"]):
            continue
        if not any(name in ("CST_FID_BRANCH_TAKEN", "CST_FID_BRANCH_TARGET")
                   for _, name in e["recs"]):
            continue
        return _inject_block_record(cst_bytes, e, n, fid, +mask)
    return None


def _m_smc_revision_byte_flip(triple, smc_sub) -> Optional[str]:
    """Corrupt a NON-baseline template revision's load-immediate byte at the
    self-modified pc.  The version-aware revision oracle must flag it — a
    revision whose bytes no longer match any known patch state (or the
    consequent count mismatch) is exactly the corruption class SMC support
    introduces.  Returns None (SKIP) if the substrate lacks ≥2 revisions."""
    _meta, templates, _entries = triple
    pc = int(smc_sub["pc"])
    revs = [t for t in templates
            if int(t["start_pc"]) == pc and t.get("insns")]
    revs.sort(key=lambda t: int(t["template_id"]))
    if len(revs) < 2:
        return None
    t = revs[1]                      # a non-baseline revision
    ins = t["insns"][0]              # the load-immediate word
    rb = bytearray(ins["raw_bytes"])
    if not rb:
        return None
    rb[-1] ^= 0xFF                   # corrupt the immediate's high byte
    ins["raw_bytes"] = bytes(rb)
    return (f"revision tmpl {t['template_id']} @pc=0x{pc:x} "
            f"load-immediate byte flipped")


def _m_smc_shape_revision_byte_flip(triple, smc_sub) -> Optional[str]:
    """Corrupt a SHAPE-CHANGED revision at the self-modified pc: the substrate
    is the ``grow`` family, whose second revision holds one instruction MORE
    than the block's original template, so the corrupted template is one that
    only shape-agnostic revision minting produces at all.  Flip a byte of its
    LAST pre-terminator instruction — the one the grow added — which the
    version-aware oracle must reject as bytes matching no written state.
    Returns None (SKIP) if the substrate lacks a shape-changed revision."""
    _meta, templates, _entries = triple
    pc = int(smc_sub["pc"])
    revs = [t for t in templates
            if int(t["start_pc"]) == pc and t.get("insns")]
    revs.sort(key=lambda t: len(t["insns"]))
    if len(revs) < 2 or len(revs[-1]["insns"]) == len(revs[0]["insns"]):
        return None                  # no shape change in this substrate
    t = revs[-1]                     # the revision with the LARGER insn count
    ins = t["insns"][-2]             # the instruction the grow introduced
    rb = bytearray(ins["raw_bytes"])
    if not rb:
        return None
    rb[0] ^= 0xFF
    ins["raw_bytes"] = bytes(rb)
    return (f"shape-changed revision tmpl {t['template_id']} @pc=0x{pc:x} "
            f"({len(t['insns'])} insns vs {len(revs[0]['insns'])}) "
            f"insn[-2] byte flipped")


CATALOGUE: list = [
    Mutation("regdata_value_flip", "oracle",
             "flip a captured dst-register value bit",
             _m_regdata_value_flip,
             expect=("regdata_reconstruction", "reg_value_assertion",
                     "expected_insns", "expected_reg_sets")),
    Mutation("reg_snap_misattribute", "oracle",
             "attribute a captured value to the wrong register id",
             _m_reg_snap_misattribute,
             expect=("regdata_reconstruction", "reg_value_assertion",
                     "expected_insns", "expected_reg_sets",
                     "impossible_attribution")),
    Mutation("memdata_addr_swap", "oracle",
             "swap two memop addresses within an entry",
             _m_memdata_addr_swap,
             expect=("cp_memops", "per_execution_memop_data",
                     "memop_insn_attribution")),
    Mutation("memdata_data_flip", "oracle",
             "flip a captured load/store data byte",
             _m_memdata_data_flip,
             expect=("cp_memops", "per_execution_memop_data")),
    Mutation("final_entry_memops_dropped", "oracle",
             "strip the memops from the segment's last body entry",
             _m_final_entry_memops_dropped,
             expect=("segment_final_memops",),
             # The standard substrate closes its window at the guest's exit
             # syscall, so its last entry is the exit block — no memops and
             # no repeat, hence nothing for this mutation to strip.  The
             # strictness is proven end-to-end on a substrate that DOES
             # close mid-flight (a real deferred icount-window close, all
             # four ISAs), where the pre-fix plugin's own output is the
             # mutation.
             covered_by="features.final_entry_memops (4-ISA, gating)"),
    Mutation("mid_entry_memops_dropped", "oracle",
             "strip the memops from one non-final, otherwise-invariant "
             "execution of a template — the general memop-bimodality "
             "shape (D4-class loss anywhere in the stream, not just the "
             "segment's last entry)",
             _m_mid_entry_memops_dropped,
             expect=("memop_bimodality",)),
    Mutation("opcode_class_change", "oracle",
             "relabel a pinned instruction's opcode class",
             _m_opcode_class_change,
             expect=("expected_insns", "opcode_assertion",
                     "block_insn_count", "template_raw_bytes")),
    Mutation("template_raw_byte_flip", "oracle",
             "flip a raw instruction byte in a template",
             _m_template_raw_byte_flip,
             expect=("template_raw_bytes", "block_insn_count",
                     "static_reg_sets", "opcode_assertion")),
    Mutation("template_raw_byte_flip_prologue", "oracle",
             "flip a raw instruction byte in an UNLABELED template (no "
             "generator block spans it, e.g. the _start/CRT prologue) -- "
             "proves the ELF-image fallback in template_raw_bytes covers "
             "user code the ground-truth ISN'T indexed by, not just "
             "labeled blk_N spans",
             _m_template_raw_byte_flip_prologue,
             expect=("template_raw_bytes",)),
    Mutation("branch_type_change", "oracle",
             "corrupt a pinned instruction's branch classification",
             _m_branch_type_change,
             expect=("expected_insns", "branch_type_assertion",
                     "cond_uncond_branch_assertion",
                     "unconditional_direction")),
    Mutation("wp_chain_truncate", "oracle",
             "drop the last block of a predicted wrong-path chain",
             _m_wp_chain_truncate,
             # A budget-exhausted chain's tail truncation is legitimately
             # WP-accepted (exact-or-longer in insn terms), but the
             # dropped block still breaks the profile exec_wp counts, so
             # profile_consistency is an accepted catcher alongside the
             # wrong-path oracle.
             expect=("wrong_path_chains", "profile_consistency")),
    Mutation("wp_chain_missequence", "oracle",
             "reorder the first two blocks of a predicted wrong-path chain",
             _m_wp_chain_missequence,
             expect=("wrong_path_chains", "profile_consistency")),
    Mutation("wp_late_fault_no_excuse", "oracle",
             "depth-0 missequence plus a later synthetic-fault mark "
             "(the fault must not excuse the earlier divergence)",
             _m_wp_late_fault_no_excuse,
             expect=("wrong_path_chains", "profile_consistency")),
    Mutation("bb_successor_missequence", "oracle",
             "reorder two correct-path entries",
             _m_bb_successor_missequence,
             # A reorder of identity-carrying entries trips the per-thread
             # bookkeeping (chain / switch-flag cadence) before the
             # positional CP comparison gets a say — both routes gate.
             expect=("cp_execution_order", "wrong_path_chains",
                     "thread_chain", "thread_records")),
    Mutation("thread_id_forge", "oracle",
             "stamp a foreign guest-thread id onto an entry",
             _m_thread_id_forge,
             expect=("thread_distribution", "thread_chain",
                     "thread_record_cadence")),
    Mutation("thread_end_dropped", "oracle",
             "strip CST_BB_FLAG_THREAD_END from a context's final entry "
             "(a close route forgetting the stamp)",
             _m_thread_end_dropped,
             expect=("thread_end",),
             covered_by="range_cells --selftest (thread_end falsifier "
                        "fixtures, always run)"),
    Mutation("ppage_corrupt", "oracle",
             "corrupt a per-memop physical-page value",
             _m_ppage_corrupt,
             expect=("per_execution_memop_data", "cp_memops"),
             covered_by="features.physaddr (system-mode MP probe, gating)"),
    Mutation("devio_stop_drop", "oracle",
             "drop a DEVIO_STOP record (unbalanced disk-I/O bracket)",
             _m_devio_stop_drop,
             covered_by="features.devio (system-mode MP probe, gating)",
             devio=True),
    Mutation("smc_revision_byte_flip", "oracle",
             "corrupt a self-modified block's non-baseline revision bytes",
             _m_smc_revision_byte_flip,
             expect=("smc_revision_bytes",),
             smc="flip_flop"),
    Mutation("smc_shape_revision_byte_flip", "oracle",
             "corrupt a SHAPE-CHANGED revision's bytes (a revision minted at "
             "a different instruction count than the block's original "
             "template -- the class only shape-agnostic minting produces)",
             _m_smc_shape_revision_byte_flip,
             expect=("smc_revision_bytes",),
             smc="grow"),
    Mutation("header_magic_corrupt", "wire",
             "corrupt the CST_MAGIC in the header member",
             _mw_header_magic_corrupt),
    Mutation("body_member_drop", "wire",
             "remove the body member from the container",
             _mw_body_member_drop),
    Mutation("body_truncate", "wire",
             "truncate the body member payload",
             _mw_body_truncate),
    Mutation("branch_target_corrupt", "wire_verify",
             "move one encoded branch target (CST_FID_BRANCH_TARGET "
             "displacement) on the wire",
             _mw_branch_target_corrupt),
    Mutation("split_pair_reorder", "oracle",
             "reorder a split invocation's stretches: the [k,n) "
             "continuation emitted before its own [0,k) prefix",
             _m_split_pair_reorder,
             expect=("range_continuity", "thread_chain")),
    Mutation("range_stop_overflow", "wire_oracle",
             "push CST_FID_BB_STOP past the template's num_insns "
             "(decoder MUST reject the malformed range)",
             _mw_range_stop_overflow),
    Mutation("range_inverted", "wire_oracle",
             "raise CST_FID_BB_START to num_insns against the default "
             "stop (empty/inverted range; decoder MUST reject)",
             _mw_range_inverted),
    Mutation("range_out_of_record", "wire_oracle",
             "shrink CST_FID_BB_STOP below a per-insn record the entry "
             "itself stages (decoder MUST reject the out-of-range record)",
             _mw_range_out_of_record),
    Mutation("fabricated_branch_on_unresolved", "wire_oracle",
             "raise CST_BB_FLAG_BRANCH_UNRESOLVED on an entry that stages "
             "a branch outcome in its own section (decoder MUST reject "
             "the contradiction, per the section 5.6 prohibition)",
             _mw_fabricated_branch_on_unresolved),
    Mutation("range_stuck", "wire_oracle",
             "shrink CST_FID_BB_STOP on a quiet entry: decoder-clean, but "
             "the invocation is left open mid-stream with no excursion "
             "and the shrunken cell delta-persists (range_continuity)",
             _mw_range_stuck),
    Mutation("stuck_bb_flags", "wire_oracle",
             "latch CST_BB_FLAG_BRANCH_UNRESOLVED onto a WP-forking entry "
             "with no branch record of its own: decoder-clean, but the "
             "chain proves the branch resolved (wp_fork_resolved)",
             _mw_stuck_bb_flags),
]


# ===========================================================================
# Runner
# ===========================================================================

@dataclasses.dataclass
class MutResult:
    name: str
    layer: str
    status: str            # "caught" | "HOLE" | "skip"
    applied: str = ""      # human note of what was mutated
    caught_by: tuple = ()  # check ids (oracle) that fired
    detail: str = ""


def _run_oracle_mutation(m: Mutation, good_triple, gen_meta, meta_path,
                         trace_path, binary_path, vkw,
                         baseline_errcks: set) -> MutResult:
    triple = copy.deepcopy(good_triple)
    try:
        note = m.apply(triple, gen_meta)
    except Exception as e:                                 # noqa: BLE001
        return MutResult(m.name, m.layer, "skip",
                         detail=f"apply raised: {e}")
    if note is None:
        ref = f"; strictness proven by {m.covered_by}" if m.covered_by else ""
        return MutResult(m.name, m.layer, "skip",
                         detail=f"substrate does not carry this feature{ref}")
    try:
        report = _validate_with(triple, meta_path, trace_path,
                                binary_path, vkw)
    except Exception as e:                                 # noqa: BLE001
        # An exception inside the oracle counts as a catch: a wrong trace
        # did not pass silently.
        return MutResult(m.name, m.layer, "caught", applied=note,
                         caught_by=("<oracle-exception>",),
                         detail=f"validate() raised: {e}")
    new_errcks = _error_checks(report) - baseline_errcks
    hit = tuple(sorted(new_errcks & set(m.expect)))
    if hit:
        return MutResult(m.name, m.layer, "caught", applied=note,
                         caught_by=hit,
                         detail=f"expected check(s) fired: {hit}")
    if new_errcks:
        # Caught, but by a check outside the expected set — still gates,
        # but the routing is worth surfacing.
        return MutResult(m.name, m.layer, "caught", applied=note,
                         caught_by=tuple(sorted(new_errcks)),
                         detail=(f"caught by UNEXPECTED check(s) "
                                 f"{sorted(new_errcks)}; expected {m.expect}"))
    return MutResult(m.name, m.layer, "HOLE", applied=note,
                     detail=(f"NO gating error; expected one of {m.expect}. "
                             f"The oracle tolerated this corruption."))


def _run_devio_mutation(m: Mutation, devio_sub) -> MutResult:
    """Run a devio mutation against a dedicated real devio trace
    (devio_mutation_substrate) with _multiproc._devio_pairing_check --
    the SAME oracle run_devio_probe's own check (1) runs -- rather than
    validate(), which knows nothing about DEVIO records.  The baseline
    decode MUST pass the pairing oracle clean (a probe substrate that
    doesn't is unfit); the mutation then drops a STOP and MUST be
    flagged by that same oracle."""
    if devio_sub is None:
        return MutResult(m.name, m.layer, "skip",
                         detail="no devio substrate (compiler/qemu-system/"
                                "virtio-blk kernel absent, or no real "
                                "DEVIO_START observed in this environment)")
    good_events = devio_sub["events"]
    base_ok, base_detail = MP._devio_pairing_check(good_events)
    if not base_ok:
        return MutResult(m.name, m.layer, "skip",
                         detail=f"substrate not clean: {base_detail}")
    events = copy.deepcopy(good_events)
    try:
        note = m.apply(events, devio_sub)
    except Exception as e:                                 # noqa: BLE001
        return MutResult(m.name, m.layer, "skip", detail=f"apply raised: {e}")
    if note is None:
        return MutResult(m.name, m.layer, "skip",
                         detail="substrate carries no DEVIO STOP record")
    ok, detail = MP._devio_pairing_check(events)
    if not ok:
        return MutResult(m.name, m.layer, "caught", applied=note,
                         caught_by=("devio_pairing",), detail=detail)
    return MutResult(m.name, m.layer, "HOLE", applied=note,
                     detail=f"pairing oracle tolerated the dropped STOP: "
                            f"{detail}")


def _run_smc_mutation(m: Mutation, smc_subs) -> MutResult:
    """Run an SMC mutation against the dedicated self-modifying substrate its
    ``smc`` family names, with the version-aware revision oracle.  The baseline
    decode MUST pass the revision oracle clean; the mutation then corrupts a
    revision and MUST be caught by the same oracle."""
    from . import _smc
    smc_sub = (smc_subs or {}).get(m.smc)
    if smc_sub is None:
        return MutResult(m.name, m.layer, "skip",
                         detail=f"no SMC substrate for family '{m.smc}' "
                                f"(compiler/qemu absent)")
    isa, family = smc_sub["isa"], smc_sub["family"]
    good = smc_sub["templates"]
    base = _smc.check_substrate(good, isa, family)
    if base:
        return MutResult(m.name, m.layer, "skip",
                         detail=f"substrate not clean: {base}")
    triple = ({}, copy.deepcopy(good), [])
    try:
        note = m.apply(triple, smc_sub)
    except Exception as e:                                 # noqa: BLE001
        return MutResult(m.name, m.layer, "skip", detail=f"apply raised: {e}")
    if note is None:
        return MutResult(m.name, m.layer, "skip",
                         detail="substrate lacks ≥2 revisions")
    issues = _smc.check_substrate(triple[1], isa, family)
    if issues:
        return MutResult(m.name, m.layer, "caught", applied=note,
                         caught_by=tuple(i[0] for i in issues),
                         detail=str([i[2] for i in issues]))
    return MutResult(m.name, m.layer, "HOLE", applied=note,
                     detail="the revision oracle tolerated corrupted bytes")


def _run_wire_mutation(m: Mutation, cst_bytes: bytes, work: Path,
                       decode_bin: Path) -> MutResult:
    try:
        mutated = m.apply(cst_bytes)
    except Exception as e:                                 # noqa: BLE001
        return MutResult(m.name, m.layer, "skip",
                         detail=f"apply raised: {e}")
    if mutated is None:
        return MutResult(m.name, m.layer, "skip",
                         detail="substrate lacks the targeted member")
    p = work / f"mut_{m.name}.cst"
    p.write_bytes(mutated)
    proc = subprocess.run([str(decode_bin), "--format=legacy", str(p)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return MutResult(m.name, m.layer, "caught", applied=m.desc,
                         caught_by=("cst_decode",),
                         detail=f"cst_decode rejected (rc={proc.returncode})")
    return MutResult(m.name, m.layer, "HOLE", applied=m.desc,
                     detail="cst_decode accepted a structurally corrupt .cst")


def _run_wire_verify_mutation(m: Mutation, cst_bytes: bytes, work: Path,
                              decode_bin: Path) -> MutResult:
    """Wire mutation whose catcher is the branch-outcome self-check rather
    than a structural decode.  A corruption that keeps the body stream
    well-formed but moves a recorded branch outcome is invisible to
    ``--format=legacy``; ``--strict --verify-branch`` is the check that
    owns it, and it must reject.  The PRISTINE substrate has to pass that
    same check first, or the "catch" would be inherited from a substrate
    that was already flagged."""
    base = work / f"base_{m.name}.cst"
    base.write_bytes(cst_bytes)
    try:
        pre = subprocess.run([str(decode_bin), "--strict", "--verify-branch",
                              str(base)], capture_output=True, text=True)
    finally:
        base.unlink(missing_ok=True)
    if pre.returncode != 0:
        return MutResult(m.name, m.layer, "skip",
                         detail=f"substrate not clean: --verify-branch "
                                f"rc={pre.returncode}")
    try:
        mutated = m.apply(cst_bytes, decode_bin, work)
    except Exception as e:                                 # noqa: BLE001
        return MutResult(m.name, m.layer, "skip",
                         detail=f"apply raised: {e}")
    if mutated is None:
        return MutResult(m.name, m.layer, "skip",
                         detail="substrate carries no addressable "
                                "CST_FID_BRANCH_TARGET cell")
    p = work / f"mut_{m.name}.cst"
    p.write_bytes(mutated)
    proc = subprocess.run([str(decode_bin), "--strict", "--verify-branch",
                           str(p)], capture_output=True, text=True)
    if proc.returncode != 0:
        return MutResult(m.name, m.layer, "caught", applied=m.desc,
                         caught_by=("cst_decode --verify-branch",),
                         detail=f"branch self-check rejected "
                                f"(rc={proc.returncode})")
    return MutResult(m.name, m.layer, "HOLE", applied=m.desc,
                     detail="the branch self-check accepted a moved "
                            "branch target")


def _run_wire_oracle_mutation(m: Mutation, cst_bytes: bytes, work: Path,
                              decode_bin: Path, meta_path: Path,
                              binary_path: Path, vkw: dict) -> MutResult:
    """Like :func:`_run_wire_mutation`, but when ``cst_decode`` tolerates
    the corrupt bytes (rc==0) falls back to the full end-to-end oracle
    (real decode + :func:`validator.validate`) so a corruption that
    desyncs the body stream WITHOUT tripping an explicit decoder
    bounds/tag check is still required to surface as a semantic
    mismatch, not pass silently.  @m.apply takes (cst_bytes, decode_bin,
    work) -- unlike the plain "wire" layer's apply(cst_bytes) -- because
    locating the mutation target needs its own raw-format decode pass."""
    try:
        mutated = m.apply(cst_bytes, decode_bin, work)
    except Exception as e:                                 # noqa: BLE001
        return MutResult(m.name, m.layer, "skip",
                         detail=f"apply raised: {e}")
    if mutated is None:
        return MutResult(m.name, m.layer, "skip",
                         detail="substrate lacks a matching WP chain header")
    p = work / f"mut_{m.name}.cst"
    p.write_bytes(mutated)
    proc = subprocess.run([str(decode_bin), "--format=legacy", str(p)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        return MutResult(m.name, m.layer, "caught", applied=m.desc,
                         caught_by=("cst_decode",),
                         detail=f"cst_decode rejected (rc={proc.returncode})")
    # The decoder tolerated the corrupt bytes -- fall back to the full
    # oracle re-run on the mutated file (real decode, not an injected
    # triple): an exception counts as a catch, same as _run_oracle_mutation.
    try:
        report = V.validate(meta_path, p, binary_path, **vkw)
    except Exception as e:                                 # noqa: BLE001
        return MutResult(m.name, m.layer, "caught", applied=m.desc,
                         caught_by=("<oracle-exception>",),
                         detail=("cst_decode accepted the corrupt wire but "
                                 f"validate() raised: {e}"))
    errs = tuple(sorted(_error_checks(report)))
    if errs:
        return MutResult(m.name, m.layer, "caught", applied=m.desc,
                         caught_by=errs,
                         detail=(f"cst_decode accepted the corrupt wire; "
                                 f"oracle check(s) fired: {errs}"))
    return MutResult(m.name, m.layer, "HOLE", applied=m.desc,
                     detail="cst_decode accepted AND the full oracle "
                            "validated clean")


def run_mutations(build_dir: Path, work_root: Path, seed: int = 0x1111,
                  substrate=None) -> dict:
    """Build (or reuse) a known-good substrate trace, apply every
    mutation, and return a machine-readable matrix.  @substrate, when
    given, is a dict {meta,trace,binary,vkw} pointing at an existing
    validated trace (used by the full-gate check to avoid re-tracing)."""
    work_root.mkdir(parents=True, exist_ok=True)
    if substrate is None:
        substrate = build_substrate(build_dir, work_root, seed)

    meta_path = Path(substrate["meta"])
    trace_path = Path(substrate["trace"])
    binary_path = Path(substrate["binary"])
    vkw = substrate.get("vkw") or {}

    import json
    gen_meta = json.loads(Path(meta_path).read_text())

    good = _decode_good(trace_path)
    # Baseline: the pristine decode MUST validate clean, or the substrate
    # is unfit and every "catch" would be a false positive.
    base_report = _validate_with(copy.deepcopy(good), meta_path, trace_path,
                                 binary_path, vkw)
    baseline_errcks = _error_checks(base_report)

    decode_bin = build_dir / "contrib/plugins/cst_decode"
    results: list[MutResult] = []
    with open(trace_path, "rb") as f:
        cst_bytes = f.read()

    # SMC mutations run on a dedicated self-modifying substrate (the diamond
    # CFG never self-modifies): build it once, on demand.
    smc_subs: dict = {}
    smc_families = sorted({m.smc for m in CATALOGUE if getattr(m, "smc", "")})
    if smc_families:
        from . import __main__ as M
        from . import _smc
        plugin = build_dir / "contrib/plugins/libchampsim_tracer.so"
        try:
            smc_subs = _smc.mutation_substrates(build_dir,
                                                work_root / "smc",
                                                M.ISA_COMPILER, plugin,
                                                families=smc_families)
        except Exception:                                  # noqa: BLE001
            smc_subs = {}

    # devio mutations run on a dedicated real devio trace (the diamond CFG
    # substrate carries no DEVIO records): build it once, on demand.
    devio_sub = None
    if any(getattr(m, "devio", False) for m in CATALOGUE):
        try:
            devio_sub = MP.devio_mutation_substrate(build_dir,
                                                    work_root / "devio")
        except Exception:                                  # noqa: BLE001
            devio_sub = None

    for m in CATALOGUE:
        if getattr(m, "smc", ""):
            results.append(_run_smc_mutation(m, smc_subs))
        elif getattr(m, "devio", False):
            results.append(_run_devio_mutation(m, devio_sub))
        elif m.layer == "oracle":
            results.append(_run_oracle_mutation(
                m, good, gen_meta, meta_path, trace_path, binary_path, vkw,
                baseline_errcks))
        elif m.layer == "wire_verify":
            results.append(_run_wire_verify_mutation(m, cst_bytes, work_root,
                                                     decode_bin))
        elif m.layer == "wire_oracle":
            results.append(_run_wire_oracle_mutation(
                m, cst_bytes, work_root, decode_bin, meta_path, binary_path,
                vkw))
        else:
            results.append(_run_wire_mutation(m, cst_bytes, work_root,
                                              decode_bin))

    holes = [r for r in results if r.status == "HOLE"]
    applied = [r for r in results if r.status != "skip"]
    return {
        "baseline_clean": not baseline_errcks,
        "baseline_errors": sorted(baseline_errcks),
        "substrate": {"trace": str(trace_path), "meta": str(meta_path)},
        "total": len(results),
        "applied": len(applied),
        "caught": sum(1 for r in results if r.status == "caught"),
        "holes": [r.name for r in holes],
        "skipped": [r.name for r in results if r.status == "skip"],
        "results": [dataclasses.asdict(r) for r in results],
        "ok": (not baseline_errcks) and (not holes) and bool(applied),
    }


def build_substrate(build_dir: Path, work_root: Path, seed: int) -> dict:
    """Generate + build + trace a small user-mode x86_64 workload with
    regdata + memdata + wrong-path enabled — the richest substrate for
    the value/classification/sequencing mutations — and return the paths
    plus the validate() kwargs that make its clean decode pass."""
    from . import __main__ as M
    from . import generator as G

    isa = "x86_64"
    d = work_root / "substrate"
    d.mkdir(parents=True, exist_ok=True)
    # coverage=True prepends the per-ISA probe blocks that carry the
    # exact per-insn oracles (expected_insns / reg_value_assertions /
    # asserted_opcodes) — the same surface the full gate's --coverage
    # quick.user_* run validates.  Without it those oracles are inert and
    # opcode/branch/value mutations would have nothing to catch them.
    params = G.GenerateParams(seed=seed, isa=isa, num_diamonds=6,
                              hot_iters=100, coverage=True)
    src, _meta = G.generate(params, d, f"mut_{isa}")
    binp = d / f"mut_{isa}"
    cc = M.ISA_COMPILER[isa]
    bcmd = [cc] + M.ISA_CFLAGS[isa] + ["-O1", str(src), "-o", str(binp)]
    if subprocess.call(bcmd) != 0:
        raise RuntimeError("substrate build failed")
    qemu = build_dir / f"qemu-{isa}"
    plugin = build_dir / "contrib/plugins/libchampsim_tracer.so"
    out_base = d / f"mut_{isa}"
    opts = (f"outfile={out_base},wpdepth=64,"
            f"trace_window=icount:start=0;stop=120000,"
            f"memdata=1,regdata=1,wp=1")
    if subprocess.call([str(qemu), "-plugin", f"{plugin},{opts}",
                        str(binp)]) != 0:
        raise RuntimeError("substrate trace failed")
    # analyze: attach ground-truth PC spans to the meta the generator wrote
    args = SimpleNamespaceCompat(out_dir=d, isa=isa, build_dir=build_dir,
                                 prog=f"mut", stop=120_000)
    M.cmd_analyze(args, isa)
    return {
        "meta": str(d / f"mut_{isa}.meta.json"),
        "trace": str(f"{out_base}.cst"),
        "binary": str(binp),
        "vkw": {"wp_insn_budget": 64, "marker": False},
    }


class SimpleNamespaceCompat:
    def __init__(self, **kw):
        self.__dict__.update(kw)
    def __getattr__(self, _n):     # tolerate the getattr-with-default cmd_* style
        return None


# ===========================================================================
# argparse + printing
# ===========================================================================

def add_parser(sub) -> None:
    p = sub.add_parser(
        "mutation",
        help="adversarial strictness proof: damage a known-good trace one "
             "way at a time and assert a specific gating check catches each.")
    p.add_argument("--build-dir", type=Path, required=True)
    p.add_argument("-o", "--work-root", type=Path,
                   default=Path("/mnt/md0/QEMU/cst_runs/strictaudit/mutation"))
    p.add_argument("--seed", type=lambda s: int(s, 0), default=0x1111)
    p.add_argument("--json", type=Path, default=None,
                   help="also write the mutation matrix here")


def cmd_mutation(args) -> int:
    import json
    res = run_mutations(Path(args.build_dir).resolve(),
                        Path(args.work_root).resolve(), args.seed)
    print("\n" + "=" * 72)
    print("CHAMPSIM TRACER — mutation strictness matrix")
    print("=" * 72)
    print(f"substrate: {res['substrate']['trace']}")
    print(f"baseline clean: {res['baseline_clean']} "
          f"(errors: {res['baseline_errors'] or 'none'})")
    print(f"{'MUTATION':32} {'LAYER':7} {'STATUS':6} CAUGHT-BY")
    for r in res["results"]:
        cb = ",".join(r["caught_by"]) if r["caught_by"] else r["detail"][:40]
        print(f"  {r['name']:30} {r['layer']:7} {r['status']:6} {cb}")
    print(f"\napplied={res['applied']} caught={res['caught']} "
          f"holes={res['holes']} skipped={res['skipped']}")
    print(f"OVERALL: {'PASS' if res['ok'] else 'FAIL'}")
    print("=" * 72)
    if args.json:
        Path(args.json).write_text(json.dumps(res, indent=2, default=str))
    return 0 if res["ok"] else 1
