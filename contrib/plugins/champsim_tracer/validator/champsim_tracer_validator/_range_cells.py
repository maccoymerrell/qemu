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
                    final user entry's ``bb_stop`` indexes the END-marker
                    instruction itself — the close fires from inside its
                    execution, so its results are unobservable and it is
                    excluded (``bb_stop`` counts fully-OBSERVED
                    instructions, not retired ones);
  ``rep_split``     a REP invocation interrupted mid-flight re-joins by
                    range chaining alone: every stretch contiguous, the
                    fan-out sub-entries' counts intact;
  ``wp_own_range``  a speculative block carries its OWN range: a chain
                    that exhausts the wpdepth budget mid-block cuts its
                    last block at exactly the remainder — the chain's
                    simulated instructions sum to the budget, never past
                    it.

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


def assert_marker_end(entries: list[dict], tby: dict,
                      marker_pc: int) -> tuple[bool, str]:
    """The final user entry stops AT the END-marker instruction: its
    template contains @marker_pc at index m, and ``bb_stop == m`` — the
    marker instruction's own execution triggered the close, so it is
    retired but not fully observed, and the range excludes it."""
    last_user = None
    for e in entries:
        if not _is_sys(e, tby):
            last_user = e
    if last_user is None:
        return False, "no user entries decoded"
    t = tby.get(last_user["template_id"]) or {}
    ins = t.get("insns") or []
    m = next((i for i, x in enumerate(ins)
              if int(x.get("pc", -1)) == marker_pc), None)
    start, stop, n = _rng(last_user, tby)
    if m is None:
        return False, (f"final user entry BB{last_user['template_id']} does "
                       f"not contain the END-marker pc 0x{marker_pc:x} "
                       f"(range [{start},{stop}) of {n})")
    if stop != m:
        return False, (f"final user entry stops at {stop} but the END "
                       f"marker sits at index {m}: an END marker close "
                       f"must exclude the marker instruction itself "
                       f"(bb_stop counts fully-observed instructions)")
    return True, (f"final user entry BB{last_user['template_id']} stops "
                  f"exactly at the END marker (index {m})")


def assert_rep_split(entries: list[dict], tby: dict,
                     rep_tmpl: int) -> tuple[bool, str]:
    """Every invocation of the REP template @rep_tmpl folds to exactly
    ``[0, n)`` through contiguous stretches, and at least one invocation
    was split (>= 2 stretches) — the shape a mid-REP interruption must
    leave under range chaining."""
    n = len((tby.get(rep_tmpl) or {}).get("insns") or [])
    open_stop: dict[tuple, int] = {}
    n_split = n_whole = 0
    for e in entries:
        if int(e["template_id"]) != rep_tmpl:
            continue
        c = _ctx(e)
        start, stop, _n = _rng(e, tby)
        if start == 0:
            if c in open_stop:
                return False, (f"REP BB{rep_tmpl} re-opened while a stretch "
                               f"was open at {open_stop[c]} — an invocation "
                               f"lost its tail")
            if stop == n:
                n_whole += 1
            else:
                open_stop[c] = stop
        else:
            if open_stop.get(c) != start:
                return False, (f"REP BB{rep_tmpl} continuation at {start} "
                               f"does not continue its open stretch "
                               f"({open_stop.get(c)})")
            if stop == n:
                del open_stop[c]
                n_split += 1
            else:
                open_stop[c] = stop
    if open_stop:
        return False, f"REP BB{rep_tmpl}: {len(open_stop)} stretch(es) open"
    if n_split == 0:
        return False, (f"REP BB{rep_tmpl}: {n_whole} whole invocations, 0 "
                       f"split — the interruption the cell stages never "
                       f"produced a split shape")
    return True, (f"REP BB{rep_tmpl}: {n_split} split invocation(s) "
                  f"rejoined exactly, {n_whole} whole")


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

def _fx_tmpl(tid, n, sys=False, pcs=None, mem_at=()):
    ins = []
    for i in range(n):
        ins.append({"pc": (pcs[i] if pcs else 0x1000 + 16 * tid + i),
                    "n_loads": 1 if i in mem_at else 0, "n_stores": 0,
                    "branch_type": 0})
    return {"template_id": tid, "start_pc": ins[0]["pc"], "insns": ins,
            "is_system": sys}


def _fx_e(tid, start=0, stop=None, depth=0, thread=0, wp=None, seq=0,
          thread_end=False):
    return {"template_id": tid, "thread_id": thread, "asid_index": 0,
            "seq_num": seq, "fault_depth": depth, "bb_start": start,
            "bb_stop": stop, "wp_entries": wp or [], "dyn_params": [],
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

    # 2. budget_close: 3 whole 5-insn blocks + [0,2) of a fourth = 17 —
    # vs. the fourth emitted whole (overshoot 20).
    tby2 = {i: _fx_tmpl(i, 5) for i in (1, 2, 3, 4)}
    check("budget_close", assert_budget_close,
          ([_fx_e(1), _fx_e(2), _fx_e(3), _fx_e(4, 0, 2)], tby2, 17),
          ([_fx_e(1), _fx_e(2), _fx_e(3), _fx_e(4)], tby2, 17))

    # 3. marker_end: END pc at index 2 of BB7; stop==2 — vs. stop==n.
    tby3 = {7: _fx_tmpl(7, 4, pcs=[0x40, 0x44, 0x48, 0x4c])}
    check("marker_end", assert_marker_end,
          ([_fx_e(7, 0, 2)], tby3, 0x48),
          ([_fx_e(7)], tby3, 0x48))

    # 4. rep_split: [0,1)+[1,3) rejoined — vs. the stretches REORDERED.
    tby4 = {5: _fx_tmpl(5, 3)}
    check("rep_split", assert_rep_split,
          ([_fx_e(5, 0, 1), _fx_e(5, 1, None)], tby4, 5),
          ([_fx_e(5, 1, None), _fx_e(5, 0, 1)], tby4, 5))

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


def _find_marker_pc(meta: dict, tby: dict) -> int | None:
    """END-marker pc: the plugin records the resolved END pc in the trace
    meta when marker mode ran (surfaced by the legacy header)."""
    for key in ("end_marker_pc", "marker_end_pc"):
        v = meta.get(key)
        if v:
            return int(v)
    return None


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
    `all --system` marker run dir.  Reports each verdict; rc 1 if any
    cell fails — including failing because the writer does not yet emit
    the split shape (that is a true statement about the trace)."""
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
        mpc = _find_marker_pc(meta_s, tby_s)
        if mpc is None:
            verdicts.append(("marker_end", False,
                             "trace meta carries no END-marker pc"))
        else:
            verdicts.append(("marker_end",
                             *assert_marker_end(entries_s, tby_s, mpc)))
        # REP template: the x86 generator's REP block is the template
        # whose first insn repeats (the 1-insn self-loop sub-template's
        # parent); locate by the REP branch class in the encoding maps.
        bn = meta_s.get("branch_names") or {}
        rep_ids = {int(k) for k, v in bn.items() if v == "BRANCH_REP"}
        rep_tmpl = None
        for tid, t in tby_s.items():
            ins = t.get("insns") or []
            if ins and int(ins[-1].get("branch_type", 0)) in rep_ids \
                    and not t.get("is_system"):
                rep_tmpl = tid
                break
        if rep_tmpl is None:
            verdicts.append(("rep_split", False,
                             "no user REP template in the trace"))
        else:
            verdicts.append(("rep_split",
                             *assert_rep_split(entries_s, tby_s, rep_tmpl)))
    else:
        for name in ("fault_split", "marker_end", "rep_split"):
            verdicts.append((name, False, f"no trace in {sys_dir}"))

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
                   help="QEMU build dir (for the self-sized budget re-trace)")
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
