"""Targeted mid-block resume/stop cells (format spec §4.2a).

Five cells, each asserting an EXACT executed-range shape the epoch-0x1E
wire contract requires at a specific capture boundary:

  ``fault_split``   a user block demand-faulting mid-block splits at the
                    faulting memory instruction: ``[0, k)`` at depth 0,
                    kernel handler entries at depth >= 1, ``[k, n)`` at
                    depth 0, contiguous, in program order;
  ``budget_close``  an icount window closing mid-block bills EXACTLY the
                    budget: the sum of every entry's ``stop - start``
                    equals the stated stop, and the final entry declares
                    the partial range that makes it exact;
  ``marker_end``    the END marker terminates the tracer mid-block: the
                    final user entry stops AT the END marker — the close
                    fires from inside the firing instruction's execution,
                    so the published range excludes it, stopping either
                    exactly at the firing instruction (stash path, tail
                    snap captured) or one retired-but-unobserved
                    instruction earlier (direct-cursor path); the
                    END-marker pcs are DERIVED from the trace's own
                    template bytes (the champsim_marker.h contract),
                    an existing carrier, not a new meta field;
  ``rep_split``     a REP invocation interrupted mid-flight by a kernel
                    excursion keeps its fan-out intact: iteration
                    entries appear on both sides of the excursion and
                    the per-iteration stores tile the staged transfer
                    span exactly — no iteration lost, none duplicated
                    (the cell stages its own system boot: a
                    marker-bracketed REP STOSB whose destination
                    crosses into a never-touched page);
  ``wp_own_range``  a speculative block carries its OWN range: a chain
                    that exhausts the wpdepth budget mid-block cuts its
                    last block at exactly the remainder — the chain's
                    simulated instructions sum to the budget, never past
                    it.

A sixth assertion, ``cut_head_fault``, is a universal invariant rather
than a staged cell: no chain may complete at a non-branch instruction
unless execution provably continued at its fall-through.  It is the
wire signature of a TRANSLATION-CUT faulting head (a MIPS
coprocessor-unusable FPU store ends its TB at the faulting instruction,
so the fault fold's template ends where no block can end) bounding its
merge continuation — the deterministic mipsel ``clock_minus_wire=+20``,
twenty resumed instructions billed to the window clock and on no entry.

Each cell has a FALSIFIER twin: the same assertion run against a
synthetic decoded stream shaped like the pre-range world (merged whole
blocks, overshooting tails).  ``--selftest`` runs conforming + falsifier
fixtures for all five and requires every falsifier to FAIL — an
assertion that cannot reject the old shape has no teeth and must not
gate.  The selftest also proves the ``thread_end`` oracle
(validator._check_thread_end_flags: CST_BB_FLAG_THREAD_END on each
context's final entry at EVERY close route) rejects both its
falsifiers — a final entry missing the stamp, and a stamp that lies
mid-stream.

The live cells state the CONTRACT.  A writer that still merges or
overshoots (the pre-split-emission writer) fails them — that is the
cells' purpose: they are the acceptance harness for the emit-at-stop
surgery, runnable before it lands and green only after it.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from . import validator as V


# ---------------------------------------------------------------------------
# Shared range helpers over decoded entries
# ---------------------------------------------------------------------------

def _rng(e: dict, tby: dict) -> tuple[int, int, int]:
    return V._entry_range(e, tby.get(e["template_id"]))


def _is_sys(e: dict, tby: dict) -> bool:
    t = tby.get(e["template_id"]) or {}
    return bool(t.get("is_system"))


def _ctx(e: dict) -> tuple:
    return (int(e.get("thread_id", 0)), int(e.get("asid_index", 0)))


# ---------------------------------------------------------------------------
# Assertion engines (pure; also driven by the selftest fixtures)
# ---------------------------------------------------------------------------

def assert_fault_split(entries: list[dict], tby: dict) -> tuple[bool, str]:
    """There exists a USER-block invocation split by a kernel excursion:
    ``[0, k)`` user depth-0, then >= 1 same-context entries that are
    kernel or depth >= 1, then ``[k, n)`` of the SAME template, depth 0,
    with k the index of a memory instruction of that template (a
    demand fault interrupts at the access that faulted, never at an
    arbitrary index)."""
    open_pref: dict[tuple, dict] = {}   # ctx -> {tmpl, k, saw_excursion}
    for e in entries:
        t = tby.get(e["template_id"])
        if t is None:
            continue
        c = _ctx(e)
        start, stop, n = _rng(e, tby)
        depth = int(e.get("fault_depth", 0) or 0)
        sysn = _is_sys(e, tby)
        p = open_pref.get(c)
        if p is not None:
            if sysn or depth >= 1:
                p["saw_excursion"] = True
            elif (int(e["template_id"]) == p["tmpl"] and start == p["k"]
                  and p["saw_excursion"] and stop == n):
                ins = (tby.get(p["tmpl"]) or {}).get("insns") or []
                k = p["k"]
                if 0 <= k < len(ins):
                    i = ins[k]
                    memk = int(i.get("n_loads", 0)) + int(i.get("n_stores", 0))
                    if memk > 0:
                        return True, (f"split of BB{p['tmpl']} at k={k} "
                                      f"(memory insn) across a kernel "
                                      f"excursion, rejoined [0,{k})+[{k},{n})")
                    return False, (f"split of BB{p['tmpl']} resumed at k={k} "
                                   f"which is not a memory instruction — a "
                                   f"demand fault cannot interrupt there")
                open_pref.pop(c, None)
            else:
                open_pref.pop(c, None)
        if (not sysn and depth == 0 and start == 0 and stop < n):
            open_pref[c] = {"tmpl": int(e["template_id"]), "k": stop,
                            "saw_excursion": False}
    return False, ("no user-block invocation was split across a kernel "
                   "excursion (writer still merges, or the workload's "
                   "demand fault never hit a user block)")


def _branch_terminated(t: dict) -> bool:
    """Whether template @t ends at its terminal branch.  The branch is the
    last instruction, or — on a delay-slot ISA — the one before it (the
    template is in true execution order [branch, delay slot]).  A
    translation-cut head (the M20 shape: the translator stopped at an
    instruction it knew would raise, e.g. a MIPS coprocessor-unusable FPU
    store) ends at a non-branch instruction and returns False."""
    ins = t.get("insns") or []
    n = len(ins)
    for i in (n - 1, n - 2):
        if i >= 0 and int(ins[i].get("branch_type", 0) or 0) != 0:
            return True
    return False


def assert_cut_head_continuity(entries: list[dict],
                               tby: dict) -> tuple[bool, str]:
    """No chain completes at a lie: a mid-start continuation (``start > 0``,
    ``stop == n``) whose template ends at a NON-BRANCH instruction claims
    the block is over where no block can end, so the instructions the
    resume actually executed past that point are on no entry — the
    deterministic mipsel ``clock_minus_wire=+20`` (a translation-cut
    faulting head bounding its merge continuation).  The one honest way
    such a completion can sit in a stream is with the next same-context
    depth-0 user entry starting at the template's fall-through pc —
    execution really did continue there under another template.  Any
    other successor means instructions were swallowed.  Universal: passes
    vacuously on a stream with no such completion (the repaired canonical
    shape completes at a branch), and the falsifier fixture proves the
    rejection fires."""
    pending: dict[tuple, tuple[int, int]] = {}   # ctx -> (tmpl_id, ft_pc)
    checked = 0
    for e in entries:
        t = tby.get(e["template_id"])
        if t is None:
            continue
        c = _ctx(e)
        depth = int(e.get("fault_depth", 0) or 0)
        if _is_sys(e, tby) or depth >= 1:
            continue                       # excursion interior: not the successor
        p = pending.pop(c, None)
        if p is not None:
            tmpl_id, ft = p
            if int(t.get("start_pc", -1)) != ft:
                return False, (f"BB{tmpl_id} completed at a non-branch "
                               f"instruction and the next entry starts at "
                               f"0x{int(t.get('start_pc', 0)):x}, not its "
                               f"fall-through 0x{ft:x} — the resumed "
                               f"instructions between them are on no entry")
            checked += 1
        start, stop, n = _rng(e, tby)
        if (start > 0 and stop == n and not _branch_terminated(t)
                and t.get("fall_through_pc") is not None):
            pending[c] = (int(e["template_id"]), int(t["fall_through_pc"]))
    return True, (f"{checked} non-branch-terminal completion(s) continued "
                  f"at their fall-through; none swallowed a resume"
                  if checked else
                  "no mid-start completion ends at a non-branch instruction "
                  "(every merge continuation completes at its block's "
                  "terminal branch)")


def assert_budget_close(entries: list[dict], tby: dict,
                        budget: int) -> tuple[bool, str]:
    """The window bills EXACTLY @budget instructions: the entries' range
    sum equals it (billing at emit, covered advances by emitted ranges),
    and the final entry declares whatever partial range makes it exact."""
    total = 0
    last = None
    for e in entries:
        start, stop, _n = _rng(e, tby)
        total += stop - start
        last = e
    if total != budget:
        return False, (f"entries bill {total} instructions against a "
                       f"budget of {budget} ({'+' if total > budget else ''}"
                       f"{total - budget}); a close mid-block must emit the "
                       f"partial range that makes billing exact")
    if last is not None:
        start, stop, n = _rng(last, tby)
        return True, (f"billing exact: {total} == budget; final entry "
                      f"BB{last['template_id']} [{start},{stop}) of {n}")
    return False, "no entries decoded — nothing was billed"


def _le32(w: int) -> bytes:
    return bytes((w & 0xff, (w >> 8) & 0xff, (w >> 16) & 0xff,
                  (w >> 24) & 0xff))


def _end_marker_seq_bytes(isa: str) -> list[bytes] | None:
    """Per-instruction byte encodings of the END-marker sequence for @isa,
    mirroring champsim_marker.h's encoders exactly (the contract's magic
    and length are parsed out of the header via asm_blocks, so this can
    never silently drift from what the plugin detects)."""
    from . import asm_blocks as B
    _magic, end, seq = B._marker_contract()
    if isa == "x86_64":
        unit = [bytes((0xB8,)) + _le32(end)]
    elif isa == "aarch64":
        unit = [_le32(0x52800000 | ((end & 0xffff) << 5)),
                _le32(0x72a00000 | ((end >> 16) << 5))]
    elif isa == "riscv64":
        unit = [_le32(((end >> 12) << 12) | (10 << 7) | 0x37),
                _le32(((end & 0xfff) << 20) | (10 << 15) | (10 << 7) | 0x13)]
    elif isa in ("mipsel", "mips"):
        unit = [_le32(0x3c080000 | (end >> 16)),
                _le32(0x35080000 | (end & 0xffff))]
    else:
        return None
    return unit * seq


def derive_end_marker_pcs(tby: dict, isa: str) -> tuple[list[int] | None, str]:
    """Derive the END-marker sequence's instruction pcs from the trace's
    own template bytes — the existing carrier.  The templates section
    publishes every instruction's encoding, and a marker workload's END
    sequence is on the wire in at least one template (typically cut short
    by the close, sometimes complete via a wrong-path visit).  A partial
    witness is placed by contradiction: candidate positions whose other
    slots collide with KNOWN non-marker bytes are rejected, and the
    candidate witnessed by the most template instructions wins; a tie is
    ambiguity and fails loudly rather than guessing."""
    seqb = _end_marker_seq_bytes(isa)
    if seqb is None:
        return None, f"no END-marker encoding known for ISA {isa!r}"
    offs = [0]
    for b in seqb[:-1]:
        offs.append(offs[-1] + len(b))
    known: dict[int, bytes] = {}
    conflict: set = set()
    for t in tby.values():
        if t.get("is_system"):
            continue
        for insd in (t.get("insns") or []):
            pc = int(insd.get("pc", -1))
            b = insd.get("raw_bytes") or b""
            if pc < 0 or not b:
                continue
            if pc in known and known[pc] != b:
                conflict.add(pc)
            else:
                known[pc] = b
    candidates: set = set()
    for pc, b in known.items():
        if pc in conflict:
            continue
        for j, exp in enumerate(seqb):
            if b == exp:
                candidates.add(pc - offs[j])
    scored: list[tuple[int, int, int]] = []
    for c in sorted(candidates):
        wit: list[int] = []
        ok = True
        for i, exp in enumerate(seqb):
            slot = c + offs[i]
            if slot in conflict:
                ok = False
                break
            kb = known.get(slot)
            if kb is None:
                continue                      # not on the wire: allowed
            if kb == exp:
                wit.append(i)
            else:
                ok = False                    # a KNOWN different insn sits
                break                         # where the sequence would be
        if ok:
            # A PARTIAL WITNESS IS A PREFIX, NEVER A MIDDLE.
            #
            # The only thing that takes marker instructions off the wire is
            # the END close, and it removes a SUFFIX: the firing instruction
            # (mid-callback, unobservable) and, on the direct-cursor path,
            # the retired-but-unsnapped one before it.  Everything earlier
            # in the sequence executed and was published.  So the true
            # placement's witnessed slots are 0..k-1 with no hole, and a
            # candidate witnessed only from the middle outward is proposing
            # that the writer dropped marker instructions the guest ran
            # before ones it kept — which no close does.
            #
            # This is what separates the two placements a pair-encoded
            # marker (aarch64 / riscv64 / mipsel: a repeated two-insn
            # load pair) otherwise ties on once the close has truncated it:
            # 4 witnessed pair-slots match the sequence read from slot 0 and,
            # equally well, read from slot 2.  Only the first is a prefix.
            prefix = 1 if wit == list(range(len(wit))) else 0
            scored.append((prefix, len(wit), c))
    if not scored:
        return None, ("no template instruction carries the END-marker "
                      "byte sequence — the trace has no END marker to "
                      "derive (not a marker-mode trace, or the close "
                      "dropped every marker template)")
    best_key = max((p, n) for p, n, _ in scored)
    top = [c for p, n, c in scored if (p, n) == best_key]
    best = best_key[1]
    if len(top) != 1:
        return None, (f"END-marker position ambiguous: {len(top)} "
                      f"candidate placements tie at {best}/{len(seqb)} "
                      f"witnessed instructions")
    seq_pcs = [top[0] + o for o in offs]
    return seq_pcs, (f"derived from template bytes: sequence at "
                     f"0x{seq_pcs[0]:x}..0x{seq_pcs[-1]:x} "
                     f"({best}/{len(seqb)} insns witnessed on the wire)")


def assert_marker_end(entries: list[dict], tby: dict,
                      seq_pcs: list[int]) -> tuple[bool, str]:
    """The final user entry stops AT the END marker.  The close fires
    from inside the firing instruction (the sequence's last), so the
    published range always excludes it; the S18 stop rule licenses
    exactly two stop points (``bb_stop`` counts fully-OBSERVED
    instructions, not retired ones):

      * the firing instruction itself — stash path, the last retired
        instruction's results were snapped;
      * one instruction earlier — direct-cursor path, the last retired
        instruction's results were never observable and it is excluded
        too.

    Anything past the firing instruction published its execution (the
    pre-range overshoot); anything earlier than the one licensed
    unobserved-tail instruction under-published what retired."""
    if len(seq_pcs) < 2:
        return False, "END-marker sequence must carry >= 2 pcs"
    firing, before = seq_pcs[-1], seq_pcs[-2]
    last_user = None
    for e in entries:
        if not _is_sys(e, tby):
            last_user = e
    if last_user is None:
        return False, "no user entries decoded"
    t = tby.get(last_user["template_id"]) or {}
    ins = t.get("insns") or []
    start, stop, n = _rng(last_user, tby)
    if stop < n:
        stop_pc = int(ins[stop].get("pc", -1))
    else:
        stop_pc = int(t.get("fall_through_pc", -1))
    if stop_pc == firing:
        return True, (f"final user entry BB{last_user['template_id']} "
                      f"stops exactly at the END firing insn "
                      f"0x{firing:x} (every retired insn observed)")
    if stop_pc == before:
        return True, (f"final user entry BB{last_user['template_id']} "
                      f"stops one insn short of the END firing insn "
                      f"0x{firing:x} (the one licensed "
                      f"retired-but-unobserved tail excluded)")
    published_firing = any(
        int(x.get("pc", -1)) == firing for x in ins[start:stop])
    if published_firing:
        return False, (f"final user entry BB{last_user['template_id']} "
                       f"publishes the END firing insn 0x{firing:x} "
                       f"inside its range [{start},{stop}) — an END "
                       f"close must exclude the instruction that fired "
                       f"it (its results are unobservable)")
    return False, (f"final user entry BB{last_user['template_id']} stops "
                   f"at pc 0x{stop_pc:x}, but an END close may stop only "
                   f"at the firing insn 0x{firing:x} or one insn before "
                   f"it (0x{before:x}) — more than the licensed "
                   f"unobserved tail is missing from the wire")


def assert_rep_split(entries: list[dict], tby: dict, rep_pc: int,
                     expect_lo: int | None = None,
                     expect_bytes: int | None = None) -> tuple[bool, str]:
    """A REP invocation interrupted mid-flight keeps its fan-out intact
    (format spec §4.2a + the bulk-memory self-loop contract): iteration
    entries appear on BOTH sides of the kernel excursion, and the
    per-iteration stores of the whole invocation tile a contiguous byte
    span — no iteration lost, none duplicated, each rendered at its own
    position.  With @expect_lo/@expect_bytes (the staged transfer span)
    the tile must equal ``[expect_lo, expect_lo + expect_bytes)`` — the
    architectural count, not the delivered-callback count.

    An invocation is the maximal run, within one context, of entries
    whose executed range covers the REP instruction at @rep_pc
    (the entering block's entry, ranged continuations, and the 1-insn
    self-loop sub-template's per-iteration entries alike), with kernel
    or ``fault_depth >= 1`` entries in between marking excursions."""
    idx_by_tmpl: dict[int, int] = {}
    for tid, t in tby.items():
        for i, x in enumerate(t.get("insns") or []):
            if int(x.get("pc", -1)) == rep_pc:
                idx_by_tmpl[tid] = i
                break
    if not idx_by_tmpl:
        return False, f"no template contains the REP insn at 0x{rep_pc:x}"

    st: dict[tuple, dict] = {}
    results: list[tuple[str, str]] = []       # (kind, msg): ok|bad|unsplit

    def finalize(s: dict) -> None:
        stores = sorted(s["stores"])
        if not stores:
            return                            # zero-count REP: no subject
        holes = []
        cur = stores[0][0]
        for a, sz in stores:
            if a != cur:
                holes.append((cur, a))
            cur = max(cur, a + sz)
        lo, span = stores[0][0], cur - stores[0][0]
        if holes:
            h = holes[0]
            results.append(("bad", (
                f"REP@0x{rep_pc:x}: iteration stores do not tile — "
                f"[0x{h[0]:x},0x{h[1]:x}) missing inside "
                f"[0x{lo:x},0x{cur:x}) ({len(stores)} stores over "
                f"{s['interruptions']} interruption(s)); an iteration "
                f"was lost or overlapped")))
            return
        if expect_lo is not None and expect_bytes is not None and \
                (lo != expect_lo or span != expect_bytes):
            results.append(("bad", (
                f"REP@0x{rep_pc:x}: invocation tiles "
                f"[0x{lo:x},0x{lo + span:x}) ({span} bytes) but the "
                f"staged transfer was [0x{expect_lo:x},"
                f"0x{expect_lo + expect_bytes:x}) ({expect_bytes} "
                f"bytes) — {expect_bytes - span} byte(s) of retired "
                f"iterations are not on the wire")))
            return
        if not s["resumed"]:
            results.append(("unsplit", (
                f"invocation tiles [0x{lo:x},0x{cur:x}) whole, with no "
                f"kernel excursion between iteration entries")))
            return
        results.append(("ok", (
            f"REP@0x{rep_pc:x}: invocation split by "
            f"{s['interruptions']} kernel excursion(s), {len(stores)} "
            f"iteration stores tile [0x{lo:x},0x{lo + span:x}) exactly")))

    for e in entries:
        c = _ctx(e)
        tid = int(e["template_id"])
        depth = int(e.get("fault_depth", 0) or 0)
        sysn = _is_sys(e, tby)
        s = st.get(c)
        covers = False
        if tid in idx_by_tmpl:
            k = idx_by_tmpl[tid]
            start, stop, _n = _rng(e, tby)
            covers = start <= k < stop
        if covers:
            if s is None:
                st[c] = s = {"stores": [], "interruptions": 0,
                             "resumed": False, "pending_exc": False}
            elif s["pending_exc"]:
                s["interruptions"] += 1
                if s["stores"]:
                    s["resumed"] = True       # iterations on both sides
                s["pending_exc"] = False
            k = idx_by_tmpl[tid]
            for d in (e.get("dyn_params") or []):
                if getattr(d, "type_name", "") == "store" and \
                        int(getattr(d, "insn_index", -1)) == k:
                    s["stores"].append((int(d.value),
                                        max(1, int(d.data_size or 1))))
        elif s is not None:
            if sysn or depth >= 1:
                s["pending_exc"] = True
            else:
                finalize(s)
                del st[c]
    for s in st.values():
        finalize(s)

    if not results:
        return False, (f"no invocation of the REP insn at 0x{rep_pc:x} "
                       f"delivered any stores — nothing to assert")
    bad = [m for k, m in results if k == "bad"]
    if bad:
        return False, bad[0]
    ok = [m for k, m in results if k == "ok"]
    if ok:
        return True, ok[0]
    return False, (f"REP@0x{rep_pc:x}: no invocation was interrupted "
                   f"mid-flight — the staged kernel excursion between "
                   f"iterations is not on the wire "
                   f"({results[0][1]})")


def assert_wp_own_range(entries: list[dict], tby: dict,
                        budget: int) -> tuple[bool, str]:
    """A WP chain never simulates past the wpdepth budget: summing each
    speculative block's OWN range, a chain with no fault/translation
    terminator that reaches the budget reaches it EXACTLY — its last
    block is cut mid-block at the remainder, not run whole past it."""
    n_chains = n_exact_cut = 0
    for e in entries:
        wps = [w for w in (e.get("wp_entries") or []) if w.get("template_id")]
        if not wps:
            continue
        if any(w.get("fault") or w.get("translation_unavailable")
               for w in wps):
            continue
        n_chains += 1
        total = 0
        for w in wps:
            ws = int(w.get("bb_start", 0) or 0)
            wn = int(w.get("n_insns", 0) or 0)
            wt = w.get("bb_stop")
            wt = wn if wt is None else int(wt)
            total += wt - ws
        if total > budget:
            return False, (f"entry seq={e.get('seq_num')}: WP chain "
                           f"simulates {total} insns past the wpdepth "
                           f"budget {budget}; the last block must carry "
                           f"its own cut range")
        if total == budget:
            last = wps[-1]
            wn = int(last.get("n_insns", 0) or 0)
            wt = last.get("bb_stop")
            wt = wn if wt is None else int(wt)
            if wt < wn:
                n_exact_cut += 1
    if n_chains == 0:
        return False, "no fault-free WP chains decoded — nothing to assert"
    if n_exact_cut == 0:
        return False, (f"{n_chains} fault-free chains, none reached the "
                       f"budget through a mid-block cut — either every "
                       f"chain terminated early or the writer still runs "
                       f"the last block whole (overshoot is clamped by "
                       f"the old exact-or-longer rule, not by a range)")
    return True, (f"{n_chains} chains within budget; {n_exact_cut} cut "
                  f"exactly at the budget mid-block")


# ---------------------------------------------------------------------------
# Selftest fixtures: a conforming stream must PASS, its falsifier twin
# (the pre-range shape) must FAIL.
# ---------------------------------------------------------------------------

def _fx_tmpl(tid, n, sys=False, pcs=None, mem_at=(), fall_through=None,
             raw=None):
    ins = []
    for i in range(n):
        ins.append({"pc": (pcs[i] if pcs else 0x1000 + 16 * tid + i),
                    "n_loads": 1 if i in mem_at else 0, "n_stores": 0,
                    "branch_type": 0,
                    "raw_bytes": (raw or {}).get(i, b"")})
    return {"template_id": tid, "start_pc": ins[0]["pc"], "insns": ins,
            "is_system": sys,
            "fall_through_pc": (fall_through if fall_through is not None
                                else ins[-1]["pc"] + 4)}


class _FxDyn:
    """Fixture stand-in for the decode runner's DynParam."""

    def __init__(self, type_name, value, insn_index, data_size=1):
        self.type_name = type_name
        self.value = value
        self.insn_index = insn_index
        self.data_size = data_size


def _fx_e(tid, start=0, stop=None, depth=0, thread=0, wp=None, seq=0,
          thread_end=False, dyn=None):
    return {"template_id": tid, "thread_id": thread, "asid_index": 0,
            "seq_num": seq, "fault_depth": depth, "bb_start": start,
            "bb_stop": stop, "wp_entries": wp or [], "dyn_params": dyn or [],
            "reg_snaps": [], "branch_taken": None, "branch_target": None,
            "thread_end": thread_end}


def assert_thread_end(entries: list[dict]) -> tuple[bool, str]:
    """Adapter over validator._check_thread_end_flags (the F6 oracle:
    CST_BB_FLAG_THREAD_END on each context's final entry at EVERY close
    route) so the selftest proves the check rejects its falsifier."""
    iss = V._check_thread_end_flags(entries)
    errs = [i for i in iss if i.severity == "error"]
    if errs:
        return False, errs[0].message
    return True, iss[0].message if iss else "no issues"


def run_selftest() -> int:
    fails = []

    def check(name, fn, conforming, falsifier):
        ok_c, d_c = fn(*conforming)
        ok_f, d_f = fn(*falsifier)
        if not ok_c:
            fails.append(f"{name}: conforming fixture REJECTED: {d_c}")
        if ok_f:
            fails.append(f"{name}: falsifier fixture PASSED: {d_f}")
        print(f"  [{'ok' if ok_c and not ok_f else 'FAIL':4}] {name}: "
              f"conforming={'pass' if ok_c else 'FAIL'} "
              f"falsifier={'fails (good)' if not ok_f else 'PASSES (BAD)'}")

    # 1. fault_split: user BB4 (6 insns, load at 3) split at 3 around a
    # kernel entry — vs. the merged whole entry the old writer emitted.
    tby = {4: _fx_tmpl(4, 6, mem_at=(3,)), 9: _fx_tmpl(9, 2, sys=True)}
    check("fault_split", assert_fault_split,
          ([_fx_e(4, 0, 3), _fx_e(9, depth=1), _fx_e(4, 3, None)], tby),
          ([_fx_e(9, depth=1), _fx_e(4, 0, None)], tby))

    # 1b. cut_head_fault: the M20 translation-cut shape.  Conforming
    # stream carries all three honest faces: a delay-slot-terminated
    # merge continuation (branch at n-2: the canonical whole-template
    # repair, exempt), a cut prefix completed as its own block whose
    # successor starts at its fall-through (the fallback repair), and
    # the excursion interior between them.  The falsifier is the exact
    # pre-fix wire: a 4-insn cut template claiming completion [3,4) at
    # its non-branch store, with the next entry at an unrelated pc —
    # the 20 resumed instructions between them on no entry.
    tby1b = {
        # arm-1 face: 6-insn block, branch at index 4, delay slot at 5
        11: _fx_tmpl(11, 6, pcs=[0x900 + 4 * i for i in range(6)]),
        # arm-2 face: 3-insn cut prefix completed at its own extent,
        # falling through to the suffix block
        12: _fx_tmpl(12, 3, pcs=[0xa00, 0xa04, 0xa08], fall_through=0xa0c),
        13: _fx_tmpl(13, 4, pcs=[0xa0c, 0xa10, 0xa14, 0xa18]),
        # the kernel handler
        19: _fx_tmpl(19, 2, sys=True),
        # falsifier: the pre-fix cut template and the unrelated successor
        14: _fx_tmpl(14, 4, pcs=[0xb00, 0xb04, 0xb08, 0xb0c],
                     mem_at=(3,), fall_through=0xb10),
        15: _fx_tmpl(15, 2, pcs=[0xc00, 0xc04]),
    }
    tby1b[11]["insns"][4]["branch_type"] = 2
    check("cut_head_fault", assert_cut_head_continuity,
          ([_fx_e(11, 0, 3), _fx_e(19, depth=1), _fx_e(11, 3, None),
            _fx_e(12, 0, None), _fx_e(19, depth=1), _fx_e(13, 0, None)],
           tby1b),
          ([_fx_e(14, 0, 3), _fx_e(19, depth=1), _fx_e(14, 3, None),
            _fx_e(15, 0, None)], tby1b))

    # 2. budget_close: 3 whole 5-insn blocks + [0,2) of a fourth = 17 —
    # vs. the fourth emitted whole (overshoot 20).
    tby2 = {i: _fx_tmpl(i, 5) for i in (1, 2, 3, 4)}
    check("budget_close", assert_budget_close,
          ([_fx_e(1), _fx_e(2), _fx_e(3), _fx_e(4, 0, 2)], tby2, 17),
          ([_fx_e(1), _fx_e(2), _fx_e(3), _fx_e(4)], tby2, 17))

    # 3. marker_end: END sequence at pcs 0x44/0x48/0x4c of BB7 (firing
    # 0x4c).  Stash path stops AT the firing insn — vs. the whole block
    # published (the pre-range overshoot, firing insn inside the range).
    tby3 = {7: _fx_tmpl(7, 5, pcs=[0x40, 0x44, 0x48, 0x4c, 0x50],
                        fall_through=0x54)}
    seq3 = [0x44, 0x48, 0x4c]
    check("marker_end", assert_marker_end,
          ([_fx_e(7, 0, 3)], tby3, seq3),
          ([_fx_e(7)], tby3, seq3))

    # 3b. marker_end direct-cursor path: one retired-but-unobserved tail
    # insn excluded — vs. stopping two short (an under-published close).
    check("marker_end_tail", assert_marker_end,
          ([_fx_e(7, 0, 2)], tby3, seq3),
          ([_fx_e(7, 0, 1)], tby3, seq3))

    # 3c. the END-marker pc DERIVATION (the existing-carrier surface):
    # a full byte-witnessed sequence resolves to its pcs, and a partial
    # single-insn witness is placed by contradiction with known
    # neighbouring bytes — vs. a trace carrying no marker bytes at all.
    seqb = _end_marker_seq_bytes("x86_64")
    stride = len(seqb[0])
    d_pcs = [0x100 + i * stride for i in range(len(seqb))]

    def drv(tby, want):
        pcs, detail = derive_end_marker_pcs(tby, "x86_64")
        return (pcs == want), detail

    tby_full = {1: _fx_tmpl(1, 4, pcs=d_pcs + [d_pcs[-1] + stride],
                            raw={0: seqb[0], 1: seqb[1], 2: seqb[2],
                                 3: b"\x0f\x05"})}
    tby_part = {1: _fx_tmpl(1, 3, pcs=[0x100 - 2 * stride,
                                       0x100 - stride, 0x100],
                            raw={0: b"\x83\xc3\x01", 1: b"\xeb\x00",
                                 2: seqb[0]})}
    tby_none = {1: _fx_tmpl(1, 2, pcs=[0x100, 0x105],
                            raw={0: b"\x0f\x05", 1: b"\xeb\x00"})}
    check("marker_derive", drv, (tby_full, d_pcs), (tby_none, d_pcs))
    check("marker_derive_partial", drv, (tby_part, d_pcs), (tby_none, d_pcs))

    # 3d. the PREFIX tie-break, on a pair-encoded marker (aarch64-shaped:
    # a two-instruction load pair repeated, so slot i and slot i+2 carry
    # identical bytes).  An END close truncates the sequence's tail, and
    # the surviving 4-of-6 witness matches the sequence read from slot 0
    # and, byte for byte, read from slot 2 — placement by contradiction
    # cannot separate them because the two slots BEFORE the block are not
    # on the wire at all.  Only the prefix rule can: the close removes a
    # suffix, so the witnessed slots of the true placement start at 0.
    #
    # Conforming: one such truncated witness resolves to the earlier
    # placement.  Falsifier: the same shape appearing at TWO unrelated
    # addresses, where both placements are prefixes with equal witness —
    # genuinely ambiguous, and the derivation must refuse rather than pick.
    a_seqb = _end_marker_seq_bytes("aarch64")
    a_stride = len(a_seqb[0])

    def drv_a64(tby, want):
        pcs, detail = derive_end_marker_pcs(tby, "aarch64")
        return (pcs == want), detail

    def _a64_trunc(base, tid):
        """Template holding only the first 4 slots of the pair marker,
        with nothing on the wire below @base (the truncated close's shape).
        """
        return _fx_tmpl(tid, 4,
                        pcs=[base + i * a_stride for i in range(4)],
                        raw={i: a_seqb[i] for i in range(4)})

    a_base = 0x400a2c
    a_pcs = [a_base + i * a_stride for i in range(len(a_seqb))]
    tby_pair = {1: _a64_trunc(a_base, 1)}
    tby_pair_two = {1: _a64_trunc(a_base, 1),
                    2: _a64_trunc(a_base + 0x1000, 2)}
    check("marker_derive_pair_prefix", drv_a64,
          (tby_pair, a_pcs), (tby_pair_two, a_pcs))

    # 4. rep_split: a REP invocation split by a kernel excursion with its
    # fan-out intact (stores tile the staged span) — vs. an iteration
    # LOST across the excursion (a hole in the tile).
    tby4 = {5: _fx_tmpl(5, 4, pcs=[0x10, 0x15, 0x1a, 0x1f]),
            12: _fx_tmpl(12, 1, pcs=[0x1f]),
            9: _fx_tmpl(9, 2, sys=True)}
    rep_conform = [_fx_e(5, dyn=[_FxDyn("store", 0xA000, 3)]),
                   _fx_e(9, depth=1),
                   _fx_e(12, dyn=[_FxDyn("store", 0xA001, 0)]),
                   _fx_e(12, dyn=[_FxDyn("store", 0xA002, 0)])]
    rep_hole = [_fx_e(5, dyn=[_FxDyn("store", 0xA000, 3)]),
                _fx_e(9, depth=1),
                _fx_e(12, dyn=[_FxDyn("store", 0xA002, 0)])]
    check("rep_split", assert_rep_split,
          (rep_conform, tby4, 0x1f, 0xA000, 3),
          (rep_hole, tby4, 0x1f, 0xA000, 3))

    # 4b. rep_split subject direction: the same tile with NO excursion
    # between iterations is a missing subject, not a pass — the staged
    # interruption must be visible on the wire.
    rep_unsplit = [_fx_e(5, dyn=[_FxDyn("store", 0xA000, 3)]),
                   _fx_e(12, dyn=[_FxDyn("store", 0xA001, 0)]),
                   _fx_e(12, dyn=[_FxDyn("store", 0xA002, 0)])]
    check("rep_split_subject", assert_rep_split,
          (rep_conform, tby4, 0x1f, 0xA000, 3),
          (rep_unsplit, tby4, 0x1f, 0xA000, 3))

    # 5. wp_own_range: chain of 3x5-insn blocks under budget 12: last
    # block cut [0,2) — vs. run whole (15 > 12).
    wp_cut = [{"template_id": 11, "n_insns": 5, "bb_start": 0,
               "bb_stop": None, "fault": False,
               "translation_unavailable": False} for _ in range(2)]
    wp_cut.append({"template_id": 11, "n_insns": 5, "bb_start": 0,
                   "bb_stop": 2, "fault": False,
                   "translation_unavailable": False})
    wp_over = [dict(w, bb_stop=None) for w in wp_cut]
    tby5 = {6: _fx_tmpl(6, 2), 11: _fx_tmpl(11, 5)}
    check("wp_own_range", assert_wp_own_range,
          ([_fx_e(6, wp=wp_cut)], tby5, 12),
          ([_fx_e(6, wp=wp_over)], tby5, 12))

    # 6. thread_end (the F6 oracle): two contexts, each final entry
    # flagged — vs. one context's close route forgetting the stamp
    # (the budget/simpoint-close shape).
    check("thread_end", assert_thread_end,
          ([_fx_e(1, thread=0, seq=1), _fx_e(1, thread=1, seq=2),
            _fx_e(1, thread=0, seq=3, thread_end=True),
            _fx_e(1, thread=1, seq=4, thread_end=True)],),
          ([_fx_e(1, thread=0, seq=1), _fx_e(1, thread=1, seq=2),
            _fx_e(1, thread=0, seq=3, thread_end=True),
            _fx_e(1, thread=1, seq=4)],))

    # 6b. thread_end converse: a flag mid-stream lies (the context
    # continues) — the conforming stream is the same as 6's.
    check("thread_end_final_only", assert_thread_end,
          ([_fx_e(1, thread=0, seq=1),
            _fx_e(1, thread=0, seq=2, thread_end=True)],),
          ([_fx_e(1, thread=0, seq=1, thread_end=True),
            _fx_e(1, thread=0, seq=2, thread_end=True)],))

    if fails:
        print("SELFTEST FAIL:")
        for f in fails:
            print("  " + f)
        return 1
    print("SELFTEST PASS: every assertion accepts the conforming shape "
          "and rejects its falsifier")
    return 0


# ---------------------------------------------------------------------------
# Live cells over real run directories
# ---------------------------------------------------------------------------

def _decode(trace: Path):
    dec = V._load_decoder()
    meta, templates, entries = dec.decode_champsim_tracer(trace)
    tby = {t["template_id"]: t for t in templates}
    return meta, tby, entries


def end_marker_pcs(meta: dict, tby: dict,
                   isa: str) -> tuple[list[int] | None, str]:
    """The END-marker sequence's instruction pcs.  Preferred carrier is
    the trace's own template bytes (:func:`derive_end_marker_pcs` — on
    the wire today, no format change); a future epoch that publishes the
    resolved firing pc in META is honoured first if present."""
    for key in ("end_marker_pc", "marker_end_pc"):
        v = meta.get(key)
        if v:
            seqb = _end_marker_seq_bytes(isa)
            if seqb is None:
                return None, f"no END-marker encoding known for ISA {isa!r}"
            offs = [0]
            for b in seqb[:-1]:
                offs.append(offs[-1] + len(b))
            start = int(v) - offs[-1]
            return ([start + o for o in offs],
                    f"META {key}=0x{int(v):x}")
    return derive_end_marker_pcs(tby, isa)


# The dedicated rep_split subject: a marker-bracketed REP STOSB whose
# destination begins _REP_PRE bytes before a never-touched page, so the
# guest kernel demand-faults mid-loop with retired iterations on both
# sides.  The .bss region is 64 KiB-padded from the file tail so the
# loader's partial-page zeroing cannot pre-map it (same discipline as
# asm_blocks.emit_trace_fault_probe); x86-64 guest pages are 4 KiB.
_REP_COUNT = 96
_REP_PRE = 32
_REP_PAGE = 4096


def _rep_probe_source() -> str:
    from . import asm_blocks as B
    lines = [
        "        .section .bss",
        "        .balign 65536",
        "        .skip 65536",
        "cst_rep_page:",
        "        .skip 65536",
        "",
        "        .section .text",
        "        .globl _start",
        "_start:",
    ]
    lines += B.emit_trace_marker("x86_64")
    # A fresh TB after the marker: the marker's own TB is the dropped
    # one-TB segment-open boundary, so the REP must not share it.
    lines += [
        "        jmp Lrep",
        "Lrep:",
        f"        leaq cst_rep_page+{_REP_PAGE - _REP_PRE}(%rip), %rdi",
        f"        mov ${_REP_COUNT}, %ecx",
        "        mov $0x5a, %eax",
        "        rep stosb",
        "        jmp Lend",
        "Lend:",
        "        add $1, %ebx",
    ]
    lines += B.emit_trace_marker_end("x86_64")
    lines += [
        "        mov $60, %eax",
        "        xor %edi, %edi",
        "        syscall",
        "        hlt",
    ]
    return "\n".join(lines) + "\n"


def _rep_split_cell(build_dir: Path, work: Path) -> tuple[bool, str]:
    """Stage, boot and judge the rep_split subject (x86_64 system boot).
    Every missing prerequisite is a loud failure: a cell whose subject
    cannot be staged must never read as a pass."""
    import shutil
    from . import _system as S

    qemu = build_dir / "qemu-system-x86_64"
    plugin = build_dir / "contrib/plugins/libchampsim_tracer.so"
    missing = [str(p) for p in (qemu, plugin) if not p.is_file()]
    if missing:
        return False, f"cannot stage the REP boot: missing {missing}"
    kernel, root = S.default_kernel("x86_64"), S.default_root("x86_64")
    if not kernel.is_file() or not root.is_dir():
        return False, ("system harness absent (x86_64 kernel/rootfs) — "
                       "the REP subject needs a system boot for its "
                       "mid-flight kernel excursion")
    for tool in ("gcc", "nm", "cpio", "gzip"):
        if not shutil.which(tool):
            return False, f"cannot stage the REP boot: {tool} not in PATH"

    work.mkdir(parents=True, exist_ok=True)
    src = work / "rep_probe.S"
    src.write_text(_rep_probe_source())
    binp = work / "rep_probe"
    r = subprocess.run(["gcc", "-static", "-nostdlib", "-nostartfiles",
                        "-no-pie", "-O1",
                        "-fno-asynchronous-unwind-tables",
                        str(src), "-o", str(binp)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return False, f"REP probe failed to assemble: {r.stderr[-300:]}"
    page_sym = None
    for ln in subprocess.run(["nm", str(binp)], capture_output=True,
                             text=True).stdout.splitlines():
        parts = ln.split()
        if len(parts) >= 3 and parts[2] == "cst_rep_page":
            page_sym = int(parts[0], 16)
    if page_sym is None:
        return False, "cst_rep_page not in the REP probe's symbol table"
    expect_lo = page_sym + _REP_PAGE - _REP_PRE

    cpio = S.stage_initramfs(root, binp, work / "stage")
    out = work / "rep_probe_trace"
    cst = Path(f"{out}.cst")
    if cst.exists():
        cst.unlink()
    opts = (f"outfile={out},wpdepth=8,"
            f"trace_window=marker:simulation=200000,memdata=1,"
            f"compress=zstd -T0 -3 -q -c")
    cmd = S.system_qemu_cmd(qemu, kernel, cpio, plugin, opts)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return False, "REP boot timed out (600s)"
    console = (p.stdout or "") + (p.stderr or "")
    (work / "rep_probe.console.log").write_text(console)
    if p.returncode != 0:
        return False, f"REP boot exited rc={p.returncode}"
    segs = S.parse_finished_segments(console)
    if len(segs) != 1 or segs[0].get("flag") != "END":
        return False, (f"REP boot closed "
                       f"{[s.get('flag') for s in segs] or 'no segment'}, "
                       f"expected exactly one END close — the REP did "
                       f"not run inside a marker window")
    if not cst.is_file():
        return False, "REP boot closed a window but wrote no .cst"

    meta, tby, entries = _decode(cst)
    bn = meta.get("branch_names") or {}
    rep_ids = {int(k) for k, v in bn.items() if v == "BRANCH_REP"}
    rep_pcs = sorted({int(x.get("pc", -1)) for t in tby.values()
                      if not t.get("is_system")
                      for x in (t.get("insns") or [])
                      if int(x.get("branch_type", 0)) in rep_ids})
    if not rep_pcs:
        return False, ("REP boot trace carries no user BRANCH_REP "
                       "template — the staged REP is not on the wire")
    ok, detail = assert_rep_split(entries, tby, rep_pcs[0],
                                  expect_lo, _REP_COUNT)
    return ok, (f"(dedicated boot, staged span 0x{expect_lo:x}"
                f"+{_REP_COUNT}) {detail}")


def _budget_close_cell(user_dir: Path, u_trace: Path, build_dir: Path,
                       wpdepth: int) -> tuple[bool, str]:
    """Self-sizing budget cell: measure the workload's true instruction
    total from its exit-closed trace, choose a stop S that provably
    lands MID-BLOCK (a prefix of entries plus half of the next), re-run
    the same binary under an icount window of exactly S, and assert the
    new trace bills exactly S.  The prediction comes from the trace's
    own decoded ranges — generator arithmetic, not a tuned guess."""
    _meta, tby, entries = _decode(u_trace)
    spans = []
    for e in entries:
        start, stop, _n = _rng(e, tby)
        spans.append(stop - start)
    total = sum(spans)
    if total < 8:
        return False, f"substrate trace too short to size a window ({total})"
    cum = 0
    S = None
    half = total // 2
    for j, s in enumerate(spans):
        if cum >= half and j + 1 < len(spans) and spans[j] >= 2:
            S = cum + max(1, spans[j] // 2)   # mid-block inside entry j
            break
        cum += s
    if S is None:
        S = total - 1
    binary = u_trace.with_suffix("")          # <base>.cst -> <base>
    qemu = build_dir / "qemu-x86_64"
    plugin = build_dir / "contrib/plugins/libchampsim_tracer.so"
    if not (binary.is_file() and qemu.is_file() and plugin.is_file()):
        return False, (f"cannot re-trace: missing "
                       f"{[p for p in (binary, qemu, plugin) if not p.is_file()]}")
    out = user_dir / "range_budget"
    out.mkdir(exist_ok=True)
    base = out / "budget"
    opts = (f"outfile={base},wpdepth=4,"
            f"trace_window=icount:start=0;stop={S},memdata=1")
    r = subprocess.run([str(qemu), "-plugin", f"{plugin},{opts}",
                        str(binary)], capture_output=True)
    cst = Path(f"{base}.cst")
    if r.returncode != 0 or not cst.is_file():
        return False, f"budget re-trace failed rc={r.returncode}"
    _m2, tby2, entries2 = _decode(cst)
    ok, detail = assert_budget_close(entries2, tby2, S)
    return ok, f"(window sized to S={S} of {total}) {detail}"


def run_cells(user_dir: Path, sys_dir: Path, build_dir: Path,
              wpdepth: int) -> int:
    """Run the live cells against an existing `all` user run dir and an
    `all --system` marker run dir; ``budget_close`` re-traces its own
    sized window and ``rep_split`` boots its own staged system subject.
    Reports each verdict; rc 1 if any cell fails — including failing
    because the writer does not yet emit the split shape (that is a
    true statement about the trace)."""
    rc = 0
    verdicts: list[tuple[str, bool, str]] = []

    u_trace = next(iter(user_dir.glob("*_x86_64.cst")), None)
    s_trace = next(iter(sys_dir.glob("*_x86_64.cst")), None) \
        if sys_dir else None

    if u_trace:
        verdicts.append(("budget_close",
                         *_budget_close_cell(user_dir, u_trace, build_dir,
                                             wpdepth)))
        _meta, tby, entries = _decode(u_trace)
        verdicts.append(("wp_own_range",
                         *assert_wp_own_range(entries, tby, wpdepth)))
    else:
        verdicts.append(("budget_close", False, f"no trace in {user_dir}"))
        verdicts.append(("wp_own_range", False, f"no trace in {user_dir}"))

    if s_trace:
        meta_s, tby_s, entries_s = _decode(s_trace)
        verdicts.append(("fault_split",
                         *assert_fault_split(entries_s, tby_s)))
        verdicts.append(("cut_head_fault",
                         *assert_cut_head_continuity(entries_s, tby_s)))
        isa = meta_s.get("target_name") or "x86_64"
        seq_pcs, why = end_marker_pcs(meta_s, tby_s, isa)
        if seq_pcs is None:
            verdicts.append(("marker_end", False, why))
        else:
            ok, detail = assert_marker_end(entries_s, tby_s, seq_pcs)
            verdicts.append(("marker_end", ok, f"({why}) {detail}"))
    else:
        for name in ("fault_split", "marker_end"):
            verdicts.append((name, False, f"no trace in {sys_dir}"))

    # rep_split stages its own subject (a dedicated system boot): the
    # `all` workloads deliberately carry no REP, so the cell brings one.
    verdicts.append(("rep_split",
                     *_rep_split_cell(build_dir,
                                      (sys_dir or user_dir) / "range_rep")))

    print("\nRANGE CELLS (format spec 4.2a acceptance harness)")
    for name, ok, detail in verdicts:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")
        if not ok:
            rc = 1
    return rc


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def add_parser(sub) -> None:
    p = sub.add_parser(
        "range_cells",
        help="targeted mid-block resume/stop cells: exact executed-range "
             "assertions at fault/budget/marker/REP/WP boundaries, plus a "
             "--selftest that proves each assertion rejects its falsifier.")
    p.add_argument("--selftest", action="store_true",
                   help="run only the fixture selftest (no traces needed)")
    p.add_argument("--user-dir", type=Path, default=None,
                   help="an `all` x86_64 user run directory")
    p.add_argument("--sys-dir", type=Path, default=None,
                   help="an `all --system` x86_64 marker run directory")
    p.add_argument("--build-dir", type=Path, default=None,
                   help="QEMU build dir (for the self-sized budget re-trace "
                        "and the staged REP system boot)")
    p.add_argument("--depth", type=int, default=64,
                   help="the runs' wpdepth (WP budget target)")


def cmd_range_cells(args) -> int:
    rc = run_selftest()
    if args.selftest:
        return rc
    if not args.user_dir or not args.build_dir:
        print("range_cells: --user-dir and --build-dir required for the "
              "live cells")
        return 1
    live = run_cells(args.user_dir, args.sys_dir, args.build_dir, args.depth)
    return rc or live
