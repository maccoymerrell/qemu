#!/usr/bin/env python3
"""Multi-thread generative oracle — the CHECKER half.

:mod:`._mt_gen` stitched N independent synthetic workloads into one
binary, one per guest thread, each with its own seed, its own code and
data region, and its own ``meta.json`` ground truth.  This module splits
the produced trace on the wire's own ``thread_id`` and compares each
stream **1v1** against that thread's expected content — the same content
oracle the single-thread validator applies, applied per thread.

What is ground truth and what is not:

* **Per-thread ORDER is ground truth.**  Filtered to one thread, the
  correct-path block sequence, the blocks covered, the per-block
  instruction identity, the memop kinds/values/attribution and the
  wrong-path chains are all exactly predicted by that thread's meta.
  Every one of them is asserted.
* **INTERLEAVING between threads is scheduling.**  Nothing here asserts
  where one thread's entries fall relative to another's.  A check that
  did would be asserting the host scheduler, and would fail for reasons
  that say nothing about the tracer.

Cross-thread invariants (the part a single-thread oracle can never see):

* **Bijection** — each generated thread's code is claimed by exactly one
  tid, and each tid claims at most one thread's code.
* **Purity** — no thread's entry appears in another thread's stream.
  This is the assertion that actually falsifies a mis-tagging tracer.
* **Total = sum of parts** — every labelled entry in the trace is
  accounted for by exactly one thread.
* **Per-thread REGFILE** — every contributing tid has its initial
  ``BODY_TAG_REGFILE`` before its first entry (``docs/format.rst``).

Attribution is the point.  Every issue this module raises carries the
thread index and the tid it belongs to, in the check id, in the message
and in the detail — "a mismatch somewhere" is not 1v1.

Author: Maccoy Merrell.  SPDX-License-Identifier: GPL-2.0-or-later
"""
from __future__ import annotations

import json
from array import array
from collections.abc import Sequence
from pathlib import Path

from . import validator as V
from .validator import Issue, Report


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def find_symbol(binary_path: Path, name: str) -> "tuple[int, int] | None":
    """(virtual_address, size) of @name in @binary_path, or None."""
    try:
        import lief
    except ImportError:
        return None
    b = lief.parse(str(binary_path))
    if b is None:
        return None
    for sym in b.symbols:
        if sym.name == name:
            return int(sym.value), int(sym.size)
    return None


def _retag(issues: list, thread: int, tid: "int | None") -> list:
    """Stamp every issue with the thread it belongs to.

    The directive's bar is that a planted mutation in thread K is caught
    AND NAMED as thread K's.  A shared check id across threads would let
    a report say "cp_execution_order failed" without saying whose, so the
    id itself is namespaced and the tid travels in the detail."""
    out = []
    for i in issues:
        detail = dict(i.detail or {})
        detail["mt_thread"] = thread
        detail["mt_tid"] = tid
        out.append(Issue(f"t{thread}.{i.check}", i.severity,
                         f"[thread {thread} tid {tid}] {i.message}", detail))
    return out


class _ThreadStream(Sequence):
    """One thread's entries, as a lazy view over the decode's own lazy body.

    Holds entry INDICES (an ``array('q')``, a machine word apiece), never
    the entry dicts: each read goes back through the decode's byte-budgeted
    sequence, so the checker's residency stays bounded by that budget.  The
    eager shape this replaces -- ``[e for e in entries if e["thread_id"] ==
    tid]`` -- pinned every one of a thread's entry dicts simultaneously,
    which on a system-mode SMP capture re-materialised the body the lazy
    decode exists to keep off the heap (measured: a 7.85 GB legacy text
    walked into ~14 GB RSS before the compare had judged anything; the same
    decode-into-RAM shape the residency ruling removed from the decode
    stage).  Supports everything the per-thread oracle does to a stream:
    ``len()``, ``seq[i]``, negative indices, slicing (another view over the
    same indices), iteration, ``enumerate``, ``reversed``."""

    __slots__ = ("_entries", "_idx")

    def __init__(self, entries, idx):
        self._entries = entries
        self._idx = idx

    def __len__(self) -> int:
        return len(self._idx)

    def __getitem__(self, key):
        if isinstance(key, slice):
            return _ThreadStream(self._entries, self._idx[key])
        return self._entries[self._idx[key]]


# ---------------------------------------------------------------------------
# Ownership: which generated thread does a template belong to?
# ---------------------------------------------------------------------------

class _Ownership:
    """Maps template_id -> owning generated thread index (or None).

    The N bodies occupy disjoint PC ranges by construction, so a
    template's instructions land in at most one thread's blocks.  A
    template that straddles two threads' ranges would mean the linker
    interleaved the regions, which this reports rather than silently
    resolving."""

    def __init__(self, templates: list[dict], pcmaps: dict[int, "V.PcMap"]):
        self.owner: dict[int, int | None] = {}
        self.straddlers: list[tuple[int, list[int]]] = []
        for t in templates:
            owners: set[int] = set()
            for ins in t.get("insns", []):
                for k, pm in pcmaps.items():
                    if pm.lookup(ins["pc"]) is not None:
                        owners.add(k)
            tid_ = int(t["template_id"])
            if len(owners) > 1:
                self.straddlers.append((tid_, sorted(owners)))
                self.owner[tid_] = sorted(owners)[0]
            elif owners:
                self.owner[tid_] = owners.pop()
            else:
                self.owner[tid_] = None

    def of(self, template_id: int) -> "int | None":
        return self.owner.get(int(template_id))


# ---------------------------------------------------------------------------
# The per-thread content oracle
# ---------------------------------------------------------------------------

def _thread_content_issues(meta: dict, thread: int, tid: int,
                           entries: list[dict],
                           all_templates: list[dict],
                           templates_by_id: dict[int, dict],
                           owned_templates: list[dict],
                           trace_meta: dict,
                           binary_path: Path,
                           arena: "tuple[int, int] | None",
                           wp_insn_budget: int,
                           marker: bool) -> tuple[list, dict]:
    """Run the single-thread content oracle against ONE thread's stream.

    @entries is the trace filtered to @tid — the thread's own execution,
    in order.  @meta is that thread's generated ground truth."""
    issues: list = []
    stats: dict = {}
    isa = meta.get("isa", "x86_64")

    pcmap = V.PcMap(meta["blocks"])
    if not pcmap._spans:
        return [Issue("content_setup", "error",
                      "metadata has no ground_truth PC spans; "
                      "analyze has to run first")], stats

    template_runs = {t["template_id"]: pcmap.template_runs(t)
                     for t in all_templates}
    correct_path = list(meta["correct_path"])
    blocks_by_id = {b["block_id"]: b for b in meta["blocks"]}
    cp_set = set(correct_path)

    # Locate this thread's entry block inside its own stream; everything
    # before it is the clone landing / driver hand-off prologue.
    entry_bid = correct_path[0]
    cp_start = None
    for i, e in enumerate(entries):
        if any(bid == entry_bid
               for bid, _ in template_runs.get(e["template_id"], [])):
            cp_start = i
            break
    if cp_start is None:
        return [Issue("cp_execution_order", "error",
                      f"entry block blk_{entry_bid} never executed in this "
                      f"thread's stream ({len(entries)} entries)")], stats

    cp_entries = entries[cp_start:]
    cp_flat: list[int] = []
    for e in cp_entries:
        if int(e.get("bb_start", 0) or 0) > 0:
            continue
        for bid, _ in template_runs.get(e["template_id"], []):
            cp_flat.append(bid)
    cp_block_seq = V._collapse_runs(cp_flat)
    cp_distinct = set(cp_block_seq)

    stats["cp_start_index"] = cp_start
    stats["entries"] = len(entries)
    stats["cp_entries"] = len(cp_entries)
    stats["cp_block_run_length"] = len(cp_block_seq)
    stats["templates_owned"] = len(owned_templates)

    # --- order and coverage: the two assertions the directive names -----
    issues += V._check_blocks_covered(correct_path, cp_distinct)
    issues += V._check_cp_execution_order(V._collapse_runs(correct_path),
                                          cp_block_seq)

    wpprune = V._parse_wpprune_from_command(trace_meta.get("command", ""))

    # --- static content of this thread's own templates ------------------
    issues += V._check_template_raw_bytes(owned_templates, blocks_by_id,
                                          binary_path)
    issues += V._check_block_insn_counts(owned_templates, blocks_by_id,
                                         pcmap, cp_set, wpprune=wpprune)
    if wpprune == 0:
        issues += V._check_block_assertions(owned_templates, blocks_by_id,
                                            pcmap, cp_set)

    reg_id_to_name = dict(trace_meta.get("encoding_maps", {})
                          .get("reg", {}))

    # --- memop content: kind, value, and which insn performed it --------
    if arena is None:
        issues.append(Issue(
            "cp_memops", "error",
            f"no `{meta['arena']['symbol']}` symbol in binary; this "
            f"thread's memop/value check has no subject"))
    else:
        arena_addr, arena_size = arena
        stats["arena_addr"] = f"0x{arena_addr:x}"
        issues += V._check_cp_memops(cp_entries, template_runs, blocks_by_id,
                                     cp_set, arena_addr, arena_size, isa,
                                     templates_by_id=templates_by_id,
                                     pcmap=pcmap)
        issues += V._check_per_execution_memop_data(
            cp_entries, template_runs, blocks_by_id, cp_set,
            arena_addr, arena_size, isa)
    issues += V._check_memop_insn_attribution(cp_entries, template_runs,
                                              templates_by_id, cp_set)
    issues += V._check_memop_count_assertions(cp_entries, templates_by_id,
                                              blocks_by_id, pcmap, cp_set)
    issues += V._check_per_execution_memop_shape(
        cp_entries, template_runs, templates_by_id, blocks_by_id, cp_set)

    # --- register content ------------------------------------------------
    has_reg_data = bool(trace_meta.get("has_reg_data"))
    issues += V._check_reg_value_assertions(cp_entries, templates_by_id,
                                            blocks_by_id, pcmap, cp_set,
                                            has_reg_data, reg_id_to_name)
    issues += V._check_expected_reg_sets(cp_entries, templates_by_id,
                                         blocks_by_id, pcmap, cp_set, isa,
                                         reg_id_to_name)
    issues += V._check_expected_insns(cp_entries, templates_by_id,
                                      blocks_by_id, pcmap, cp_set, isa,
                                      reg_id_to_name)

    # --- wrong path: this thread's speculative chains --------------------
    reg_name_to_id: dict[str, int] = {}
    for rid, rname in reg_id_to_name.items():
        try:
            reg_name_to_id[rname] = int(rid)
        except (TypeError, ValueError):
            continue
    issues += V._check_wrong_path_chains(
        cp_entries, template_runs, cp_block_seq, correct_path,
        meta["wrong_paths"], blocks_by_id,
        wp_insn_budget=wp_insn_budget,
        helper_leaf_n_insns=int(meta.get("helper_leaf_n_insns", 0) or 0),
        isa=isa, cp_pos_offset=0, templates_by_id=templates_by_id,
        marker=marker, wpprune=wpprune, reg_name_to_id=reg_name_to_id)

    return issues, stats


# ---------------------------------------------------------------------------
# Top level
# ---------------------------------------------------------------------------

def validate_mt(index_path: Path, trace_path: Path, binary_path: Path,
                wp_insn_budget: int = 64,
                decoded=None) -> Report:
    """Split @trace_path by guest thread and check each stream against
    its generated ground truth.

    @decoded, when given, is a pre-decoded ``(trace_meta, templates,
    entries)`` triple — the hook the mutation proof uses to damage a
    decode without re-tracing."""
    index = json.loads(Path(index_path).read_text())
    base = Path(index_path).parent
    marker = bool(index.get("marker"))

    if decoded is None:
        dec = V._load_decoder()
        trace_meta, templates, entries = dec.decode_champsim_tracer(trace_path)
    else:
        trace_meta, templates, entries = decoded

    metas: dict[int, dict] = {}
    pcmaps: dict[int, V.PcMap] = {}
    for t in index["threads"]:
        k = int(t["index"])
        metas[k] = json.loads((base / t["meta"]).read_text())
        pcmaps[k] = V.PcMap(metas[k]["blocks"])

    issues: list = []
    stats: dict = {
        "isa": index["isa"],
        "n_threads": index["n_threads"],
        "trace_templates": len(templates),
        "trace_entries": len(entries),
    }

    missing = [k for k, pm in pcmaps.items() if not pm._spans]
    if missing:
        return Report(issues=[Issue(
            "mt_setup", "error",
            f"threads {missing} have no ground_truth PC spans; `analyze` "
            f"has to run on every thread's meta before this check")],
            stats=stats)

    own = _Ownership(templates, pcmaps)
    for tmpl_id, owners in own.straddlers:
        issues.append(Issue(
            "mt_region_disjoint", "error",
            f"template {tmpl_id} spans the code of threads {owners}; the "
            f"per-thread regions are supposed to be disjoint by "
            f"construction", {"template_id": tmpl_id, "threads": owners}))

    templates_by_id = {t["template_id"]: t for t in templates}

    # ---- tid <-> thread mapping, discovered from the wire ---------------
    # Never assumed: the checker resolves each thread's tid from which
    # stream carries that thread's code, then asserts the result is a
    # bijection.  Assuming "tid == clone order" would make the purity
    # assertion circular.
    owners_by_tid: dict[int, dict[int, int]] = {}
    unlabelled_by_tid: dict[int, int] = {}
    # One pass also records each tid's entry indices, so the per-thread
    # streams below are views into the lazy decode rather than lists of
    # entry dicts (see _ThreadStream for why that distinction is the whole
    # residency story).
    idx_by_tid: dict[int, array] = {}
    for i, e in enumerate(entries):
        etid = int(e.get("thread_id", 0))
        idx_by_tid.setdefault(etid, array("q")).append(i)
        k = own.of(e["template_id"])
        if k is None:
            unlabelled_by_tid[etid] = unlabelled_by_tid.get(etid, 0) + 1
        else:
            d = owners_by_tid.setdefault(etid, {})
            d[k] = d.get(k, 0) + 1

    tid_of_thread: dict[int, int] = {}
    for k in sorted(metas):
        claimants = sorted(
            ((cnt, t) for t, d in owners_by_tid.items()
             for kk, cnt in d.items() if kk == k), reverse=True)
        if not claimants:
            issues.append(Issue(
                "mt_thread_present", "error",
                f"thread {k}'s code never appears in the trace under any "
                f"thread_id — its synthetic workload was not captured",
                {"mt_thread": k}))
            continue
        if len(claimants) > 1:
            # One generated body executed under two tids.  Either the
            # tracer re-tagged a running thread, or the body was entered
            # twice; both are defects, and both are named here.
            issues.append(Issue(
                "mt_thread_identity", "error",
                f"thread {k}'s code appears under {len(claimants)} distinct "
                f"tids {[t for _c, t in claimants]} — one generated body "
                f"must map to exactly one guest thread",
                {"mt_thread": k, "tids": [t for _c, t in claimants]}))
        tid_of_thread[k] = claimants[0][1]

    # Purity: a tid that carries two threads' code is a mis-tagged stream.
    for etid, d in sorted(owners_by_tid.items()):
        if len(d) > 1:
            issues.append(Issue(
                "mt_stream_purity", "error",
                f"tid {etid} carries code from {len(d)} generated threads "
                f"{sorted(d)} (entry counts {dict(sorted(d.items()))}) — a "
                f"thread's entries must never appear in another's stream",
                {"mt_tid": etid, "threads": sorted(d),
                 "counts": dict(sorted(d.items()))}))

    if len(set(tid_of_thread.values())) != len(tid_of_thread):
        issues.append(Issue(
            "mt_bijection", "error",
            f"tid assignment is not a bijection: {tid_of_thread}",
            {"map": dict(tid_of_thread)}))
    else:
        issues.append(Issue(
            "mt_bijection", "info",
            f"thread -> tid: {dict(sorted(tid_of_thread.items()))}",
            {"map": dict(sorted(tid_of_thread.items()))}))
    stats["tid_of_thread"] = dict(sorted(tid_of_thread.items()))
    stats["unlabelled_entries_by_tid"] = dict(sorted(
        unlabelled_by_tid.items()))

    # ---- per-thread REGFILE (docs/format.rst): before the first entry ---
    order = trace_meta.get("body_record_order") or []
    first_entry_at: dict[int, int] = {}
    first_regfile_at: dict[int, int] = {}
    for pos, rec in enumerate(order):
        try:
            kind, rtid = rec[0], int(rec[1])
        except (TypeError, IndexError, ValueError):
            continue
        if kind == "entry":
            first_entry_at.setdefault(rtid, pos)
        elif kind == "regfile":
            first_regfile_at.setdefault(rtid, pos)
    for k, t in sorted(tid_of_thread.items()):
        if t not in first_entry_at:
            continue
        if t not in first_regfile_at:
            issues.append(Issue(
                f"t{k}.thread_regfile", "error",
                f"[thread {k} tid {t}] no BODY_TAG_REGFILE for this "
                f"thread's stream", {"mt_thread": k, "mt_tid": t}))
        elif first_regfile_at[t] > first_entry_at[t]:
            issues.append(Issue(
                f"t{k}.thread_regfile", "error",
                f"[thread {k} tid {t}] BODY_TAG_REGFILE at body-record "
                f"{first_regfile_at[t]} follows this thread's first entry "
                f"at {first_entry_at[t]}",
                {"mt_thread": k, "mt_tid": t}))

    # ---- per-thread content, 1v1 ---------------------------------------
    accounted = 0
    for k in sorted(metas):
        tid = tid_of_thread.get(k)
        if tid is None:
            continue
        stream = _ThreadStream(entries, idx_by_tid.get(tid, array("q")))
        owned = [t for t in templates if own.of(t["template_id"]) == k]
        arena = find_symbol(binary_path, metas[k]["arena"]["symbol"])
        t_issues, t_stats = _thread_content_issues(
            metas[k], k, tid, stream, templates, templates_by_id, owned,
            trace_meta, binary_path, arena, wp_insn_budget, marker)
        issues += _retag(t_issues, k, tid)
        stats[f"thread_{k}"] = t_stats
        accounted += owners_by_tid.get(tid, {}).get(k, 0)

    # ---- total = sum of parts -------------------------------------------
    labelled_total = sum(sum(d.values()) for d in owners_by_tid.values())
    if labelled_total != accounted:
        issues.append(Issue(
            "mt_entry_census", "error",
            f"{labelled_total} entries carry generated-thread code but only "
            f"{accounted} were accounted for by a thread's own stream — "
            f"{labelled_total - accounted} entries belong to a thread whose "
            f"tid did not claim them",
            {"labelled": labelled_total, "accounted": accounted}))
    else:
        issues.append(Issue(
            "mt_entry_census", "info",
            f"{labelled_total} generated-code entries, all accounted for "
            f"by their own thread's stream",
            {"labelled": labelled_total}))
    stats["labelled_entries"] = labelled_total

    # ---- the driver is not generated content: assert containment --------
    # The driver thread runs the clone/join/marker code and nothing else.
    # Its stream carrying a worker's block would be exactly the tagging
    # defect the purity check hunts, approached from the other side.
    driver_tids = sorted(set(unlabelled_by_tid)
                         - set(tid_of_thread.values()))
    stats["driver_tids"] = driver_tids
    issues.append(Issue(
        "mt_driver_containment", "info",
        f"tids carrying no generated body: {driver_tids} "
        f"(driver + any kernel strand)",
        {"driver_tids": driver_tids}))

    return Report(issues=issues, stats=stats)
