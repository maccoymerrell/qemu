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
import subprocess
import tarfile
from pathlib import Path
from typing import Callable, Optional

from . import validator as V


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
    layer: str                       # "oracle" | "wire"
    desc: str
    # oracle: apply(triple) -> str|None  (returns a human note, or None
    #   when the substrate can't carry the mutation -> SKIP)
    # wire:   apply(cst_bytes) -> bytes|None
    apply: Callable
    expect: tuple = ()               # oracle: acceptable catching-check ids
    expect_wire_rc_nonzero: bool = True   # wire: decoder must reject
    covered_by: str = ""             # cross-ref printed when the mutation
                                     # SKIPs (feature absent from substrate)


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


def _m_devio_stop_drop(triple, gen_meta) -> Optional[str]:
    """Drop a DEVIO_STOP body record, unbalancing the disk-I/O bracket.
    Requires a devio=1 (system-mode virtio-blk) substrate; the user-mode
    substrate carries none, so this SKIPs with a cross-ref to the gating
    features.devio probe."""
    trace_meta, _tmpl, _entries = triple
    bs = trace_meta.get("body_stats") or {}
    if not (bs.get("devio_start") or bs.get("devio_stop")):
        return None
    bs["devio_stop"] = int(bs.get("devio_stop", 0)) - 1
    return "decremented devio_stop count (unbalanced bracket)"


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
             expect=("cp_execution_order", "wrong_path_chains")),
    Mutation("thread_id_forge", "oracle",
             "stamp a foreign guest-thread id onto an entry",
             _m_thread_id_forge,
             expect=("thread_distribution", "thread_chain",
                     "thread_record_cadence")),
    Mutation("ppage_corrupt", "oracle",
             "corrupt a per-memop physical-page value",
             _m_ppage_corrupt,
             expect=("per_execution_memop_data", "cp_memops"),
             covered_by="features.physaddr (system-mode MP probe, gating)"),
    Mutation("devio_stop_drop", "oracle",
             "drop a DEVIO_STOP record (unbalanced disk-I/O bracket)",
             _m_devio_stop_drop,
             expect=("wp_events", "profile_consistency"),
             covered_by="features.devio (system-mode MP probe, gating)"),
    Mutation("header_magic_corrupt", "wire",
             "corrupt the CST_MAGIC in the header member",
             _mw_header_magic_corrupt),
    Mutation("body_member_drop", "wire",
             "remove the body member from the container",
             _mw_body_member_drop),
    Mutation("body_truncate", "wire",
             "truncate the body member payload",
             _mw_body_truncate),
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

    for m in CATALOGUE:
        if m.layer == "oracle":
            results.append(_run_oracle_mutation(
                m, good, gen_meta, meta_path, trace_path, binary_path, vkw,
                baseline_errcks))
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
