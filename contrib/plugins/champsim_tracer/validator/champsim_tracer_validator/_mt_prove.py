#!/usr/bin/env python3
"""Multi-thread generative oracle — the BOTH-WAYS PROOF.

A checker that only ever passes is indistinguishable from no checker.
This module plants a defect in a NAMED thread and requires that the
multi-thread oracle (a) catches it and (b) says which thread it was in.
"Caught somewhere" is not 1v1 — attribution is the whole claim the
directive makes about a per-thread oracle, so it is the thing proved.

Four planted defects, each per thread K:

``meta_insn``
    One instruction's expected content in thread K's ``meta.json`` is
    perturbed (an ``expected_insns`` opcode).  The trace is untouched and
    correct; the oracle must reject it because the ground truth no longer
    describes it.  Catches with ``tK.expected_insns``.

``meta_memop``
    One expected memop *value* in thread K's meta is flipped.  Catches
    with ``tK.cp_memops``.

``image_byte``
    ONE byte in the linked binary — the byte of thread K's arena that
    seeds one ``cond_branch`` predicate — is flipped, and the workload is
    re-traced.  Thread K then walks the other side of that diamond while
    every other thread is bit-identical, so the divergence is real
    execution, not a bookkeeping edit.  Catches with
    ``tK.cp_execution_order``.

``wp_drop``
    Thread K's wrong-path chains are dropped from the decoded trace.
    Proves the per-thread wrong-path oracle is live rather than
    vacuously silent (it reports nothing on a clean run by design).
    Catches with ``tK.wrong_path_chains``.

A planted defect that is caught but attributed to the wrong thread — or
to no thread — FAILS the proof exactly as loudly as one that slips
through.

Author: Maccoy Merrell.  SPDX-License-Identifier: GPL-2.0-or-later
"""
from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path

from . import _mt_check as MC
from . import validator as V


@dataclasses.dataclass
class ProofRow:
    isa: str
    thread: int
    mutation: str
    applied: bool
    description: str
    caught: bool
    attributed: bool
    checks: list


def _fmt(rows: list[ProofRow]) -> str:
    w = max([len(r.mutation) for r in rows] + [8])
    out = [f"{'isa':8} {'thr':>3} {'mutation':{w}} {'caught':>6} "
           f"{'attributed':>10}  check"]
    for r in rows:
        if not r.applied:
            out.append(f"{r.isa:8} {r.thread:>3} {r.mutation:{w}} "
                       f"{'SKIP':>6} {'-':>10}  {r.description}")
            continue
        out.append(f"{r.isa:8} {r.thread:>3} {r.mutation:{w}} "
                   f"{'yes' if r.caught else 'NO':>6} "
                   f"{'yes' if r.attributed else 'NO':>10}  "
                   f"{','.join(sorted(r.checks)[:3]) or '(none)'}")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Mutators
# ---------------------------------------------------------------------------

def _cp_blocks(meta: dict) -> list[dict]:
    cp = set(meta["correct_path"])
    return [b for b in meta["blocks"] if b["block_id"] in cp]


def mutate_meta_insn(meta: dict) -> "str | None":
    """Perturb ONE instruction's declared opcode in a CP block."""
    for b in _cp_blocks(meta):
        for j, ins in enumerate(b.get("expected_insns") or []):
            cur = ins.get("opcode")
            if not cur:
                continue
            new = "GEN_OP_XOR" if cur != "GEN_OP_XOR" else "GEN_OP_ADD"
            ins["opcode"] = new
            return (f"blk_{b['block_id']} insn {j}: expected opcode "
                    f"{cur} -> {new}")
    return None


def mutate_meta_memop(meta: dict) -> "str | None":
    """Flip ONE expected memop value in a CP block."""
    for b in _cp_blocks(meta):
        for j, m in enumerate(b.get("memops") or []):
            if m.get("optional"):
                continue
            old = int(m.get("data", 0))
            m["data"] = old ^ 0x5A5A
            return (f"blk_{b['block_id']} memop {j} ({m.get('kind')}): "
                    f"expected data {old} -> {m['data']}")
    return None


def _va_to_file_offset(binary_path: Path, va: int) -> "int | None":
    import lief
    b = lief.parse(str(binary_path))
    if b is None:
        return None
    for seg in b.segments:
        if str(seg.type).split(".")[-1] != "LOAD":
            continue
        lo = int(seg.virtual_address)
        if lo <= va < lo + int(seg.physical_size):
            return int(seg.file_offset) + (va - lo)
    return None


def plan_image_byte(meta: dict, binary_path: Path) -> "tuple[int, str] | None":
    """Locate the single image byte whose flip re-routes ONE of this
    thread's diamonds.

    The generator seeds every ``cond_branch`` predicate from a dedicated
    arena slot (``branch_slot``), 1 for the taken side and 0 for the
    other.  Flipping the low byte of that u64 sends this thread — and
    only this thread, the arenas are per-thread — down the other side."""
    arena = MC.find_symbol(binary_path, meta["arena"]["symbol"])
    if arena is None:
        return None
    cp = set(meta["correct_path"])
    for b in meta["blocks"]:
        if b.get("class") != "cond_branch" or b["block_id"] not in cp:
            continue
        slot = b.get("branch_slot")
        if slot is None:
            continue
        va = arena[0] + int(slot) * 8
        off = _va_to_file_offset(binary_path, va)
        if off is None:
            continue
        return off, (f"blk_{b['block_id']} branch predicate at "
                     f"{meta['arena']['symbol']}+{slot * 8} "
                     f"(va 0x{va:x}, file offset 0x{off:x})")
    return None


def apply_image_byte(binary_path: Path, offset: int) -> str:
    data = bytearray(binary_path.read_bytes())
    old = data[offset]
    data[offset] = 0 if old else 1
    binary_path.write_bytes(bytes(data))
    return f"byte 0x{offset:x}: 0x{old:02x} -> 0x{data[offset]:02x}"


def mutate_wp_drop(triple, pcmap: "V.PcMap") -> "str | None":
    """Drop the wrong-path chains from this thread's entries."""
    _tm, templates, entries = triple
    owned = {int(t["template_id"]) for t in templates
             if any(pcmap.lookup(i["pc"]) is not None
                    for i in t.get("insns", []))}
    n = 0
    for e in entries:
        if int(e["template_id"]) in owned and e.get("wp_entries"):
            e["wp_entries"] = []
            n += 1
    if not n:
        return None
    return f"dropped wp_entries from {n} of this thread's entries"


# ---------------------------------------------------------------------------
# The proof runner
# ---------------------------------------------------------------------------

def _errors_for_thread(report, thread: int) -> tuple[bool, bool, list]:
    """(caught, attributed, checks) — did anything error, and was the
    error stamped with @thread?"""
    errs = report.errors()
    if not errs:
        return False, False, []
    mine = [i for i in errs
            if (i.detail or {}).get("mt_thread") == thread
            or i.check.startswith(f"t{thread}.")]
    others = [i for i in errs if i not in mine]
    checks = sorted({i.check for i in mine}) or sorted({i.check for i in errs})
    # Attribution demands BOTH that this thread was named and that no
    # other thread was blamed for a defect that is not theirs.
    other_threads = {(i.detail or {}).get("mt_thread") for i in others}
    other_threads.discard(None)
    other_threads.discard(thread)
    return True, bool(mine) and not other_threads, checks


def prove(index_path: Path, trace_path: Path, binary_path: Path,
          isa: str, wp_insn_budget: int,
          retrace, decode=None) -> tuple[int, list[ProofRow]]:
    """Run the four planted defects against every generated thread.

    @retrace is ``fn(binary_path) -> rc`` — re-runs the tracer on a
    mutated image, since ``image_byte`` has to change what the guest
    actually executes."""
    index = json.loads(Path(index_path).read_text())
    base = Path(index_path).parent
    rows: list[ProofRow] = []

    if decode is None:
        dec = V._load_decoder()
        good = dec.decode_champsim_tracer(trace_path)
    else:
        good = decode

    metas = {int(t["index"]): (base / t["meta"]) for t in index["threads"]}

    for k in sorted(metas):
        meta_path = metas[k]
        pristine = meta_path.read_text()

        # ---- meta-side defects: same trace, damaged ground truth ------
        for name, fn in (("meta_insn", mutate_meta_insn),
                         ("meta_memop", mutate_meta_memop)):
            meta = json.loads(pristine)
            desc = fn(meta)
            if desc is None:
                rows.append(ProofRow(isa, k, name, False,
                                     "no eligible site in this thread's "
                                     "metadata", False, False, []))
                continue
            meta_path.write_text(json.dumps(meta, indent=2))
            try:
                rep = MC.validate_mt(index_path, trace_path, binary_path,
                                     wp_insn_budget=wp_insn_budget,
                                     decoded=copy.deepcopy(good))
                caught, attributed, checks = _errors_for_thread(rep, k)
            finally:
                meta_path.write_text(pristine)
            rows.append(ProofRow(isa, k, name, True, desc,
                                 caught, attributed, checks))

        # ---- decode-side defect: prove the WP oracle is live ----------
        meta = json.loads(pristine)
        pm = V.PcMap(meta["blocks"])
        triple = copy.deepcopy(good)
        desc = mutate_wp_drop(triple, pm)
        if desc is None:
            rows.append(ProofRow(isa, k, "wp_drop", False,
                                 "this thread's entries carry no wrong-path "
                                 "chains to drop", False, False, []))
        else:
            rep = MC.validate_mt(index_path, trace_path, binary_path,
                                 wp_insn_budget=wp_insn_budget,
                                 decoded=triple)
            caught, attributed, checks = _errors_for_thread(rep, k)
            rows.append(ProofRow(isa, k, "wp_drop", True, desc,
                                 caught, attributed, checks))

        # ---- image-side defect: one byte, re-traced -------------------
        plan = plan_image_byte(json.loads(pristine), binary_path)
        if plan is None:
            rows.append(ProofRow(isa, k, "image_byte", False,
                                 "no cond_branch predicate reachable in "
                                 "this thread's image", False, False, []))
            continue
        off, where = plan
        backup = binary_path.read_bytes()
        try:
            byte_desc = apply_image_byte(binary_path, off)
            rc = retrace(binary_path)
            if rc != 0:
                rows.append(ProofRow(isa, k, "image_byte", False,
                                     f"re-trace of the mutated image failed "
                                     f"rc={rc}", False, False, []))
                continue
            rep = MC.validate_mt(index_path, trace_path, binary_path,
                                 wp_insn_budget=wp_insn_budget)
            caught, attributed, checks = _errors_for_thread(rep, k)
            rows.append(ProofRow(isa, k, "image_byte", True,
                                 f"{where}; {byte_desc}",
                                 caught, attributed, checks))
        finally:
            binary_path.write_bytes(backup)

    # The image mutations left the on-disk trace describing a mutated
    # run; restore it so a caller that keeps going sees the clean subject.
    rc = retrace(binary_path)
    failures = sum(1 for r in rows
                   if r.applied and not (r.caught and r.attributed))
    if rc != 0:
        print(f"mt_prove[{isa}]: FAIL  restoring the clean trace after the "
              f"image mutations failed rc={rc}")
        failures += 1
    return failures, rows


def format_table(rows: list[ProofRow]) -> str:
    return _fmt(rows)
