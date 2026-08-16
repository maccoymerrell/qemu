"""Residency tripwire for the decode stage.

THE INCIDENT.  ``decode_champsim_tracer`` used to return
``list(_iter_body(...))``.  On a ``--stop 3000000`` system-marker cell that
is ~576 k entry dicts at ~18 KB apiece — 10.3 GiB, measured, for one cell,
before ``validate()`` had checked anything.  Twelve to fifteen concurrent
validator lanes reached ~190 GiB and the host stopped responding.  The
ruling was that the decode stage is streaming and a decode that needs a
"massive amount of RAM" is a bug, not a property of an API shape.

WHAT THIS CHECKS.  That the ruling still holds — measured, not asserted
from the source.  A trace big enough for the difference to be unmistakable
is decoded in a child process and walked end to end; the child's peak RSS
must sit under a bound DERIVED from what the lazy design actually costs
(the line index, the entry index, the bounded LRU), not under a number
somebody once wrote down.

AND THAT THE TRIPWIRE CAN FIRE.  A gate that has never gone red is a gate
nobody has tested.  The same trace is decoded a second time with
``CST_DECODE_FORCE_EAGER_UNBOUNDED=1``, which reinstates the pre-fix
materialisation; that run MUST exceed the bound.  If it does not — the
substrate is too small, the machine is too generous, the lever stopped
working — this check FAILS rather than reporting a pass it cannot support.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

MiB = 1 << 20

# --- the bound -------------------------------------------------------------
# Everything the lazy decode is entitled to hold, and nothing else.
#
#   BASE       interpreter, imported modules, the parsed templates and
#              encoding maps (bounded by template count, not trace length),
#              plus headroom for the checks' own working sets.
#   PER_LINE   the _LineFile line-start index: 8 bytes per line of legacy
#              text, doubled for array over-allocation and slack.
#   PER_ENTRY  the entry-head index and the body-record-order index: a few
#              machine words per body record.
#   PER_CACHED the bounded LRU of parsed entries, at a generous ceiling for
#              how large one entry (with its wrong-path chain) can get.
#
# Nothing here scales with how much the trace EXECUTED except through the
# indices, which is the whole point: a term proportional to entry count at
# entry SIZE is precisely what was removed.
BASE_BYTES = 384 * MiB
PER_LINE_BYTES = 16
PER_ENTRY_BYTES = 64
PER_CACHED_ENTRY_BYTES = 32 * 1024

# A floor on the substrate, not the proof.  The proof is the explicit
# "forced-eager exceeds the budget" assertion below; this only stops the
# check reporting a pass off a trace so small that both shapes fit under
# the base term and the comparison says nothing.  At this size the eager
# list is already multiple times the budget.
MIN_ENTRIES_TO_PROVE = 60_000


def bound_bytes(facts: dict) -> int:
    return (BASE_BYTES
            + PER_LINE_BYTES * int(facts.get("lines", 0))
            + PER_ENTRY_BYTES * int(facts.get("entries", 0))
            + PER_CACHED_ENTRY_BYTES * int(facts.get("cache_cap", 0)))


# --- the probe (runs as a child process) -----------------------------------

def _order_view_survives(cst: str) -> tuple[bool, str]:
    """The streaming decoder's record-order view must outlive its decode.

    ``iter_decode_champsim_tracer(..., body_record_order=True)`` used to hand
    back a plain ``list[tuple]``; it is now a lazy view over the same spilled
    decode that the entry generator closes when it finishes.  A caller that
    reads the order after walking the body is doing nothing wrong, so the
    view has to still work — and the failure is not a clean one.  A closed
    ``_LineFile`` whose fd number has been reused reads THAT file's bytes,
    so the wrong answer arrives without an error.  Checked, not assumed.
    """
    from . import _cst_decode_runner as R

    meta, _t, it = R.iter_decode_champsim_tracer(cst, body_record_order=True)
    order = meta.get("body_record_order")
    if order is None:
        return False, "body_record_order=True produced no view"
    n = len(order)
    if n < 2:
        return False, f"record-order view has only {n} records"
    probe_at = range(min(4, n))
    head = [order[k] for k in probe_at]
    next(it, None)      # start the generator so close() reaches its finally
    it.close()          # the decode-close path, without paying for a walk
    try:
        again = [order[k] for k in probe_at]
    except Exception as e:                                   # noqa: BLE001
        return False, (f"record-order view unusable once its decode closed: "
                       f"{type(e).__name__}: {e}")
    if len(order) != n or again != head:
        return False, ("record-order view changed once its decode closed: "
                       f"{head} -> {again}")
    return True, f"{n} records, readable after the decode closed"


def _probe(cst: str) -> int:
    """Decode @cst, walk every entry, report peak RSS and shape as JSON.

    Run as a child so the measurement is of the decode alone and cannot be
    contaminated by whatever the parent already had resident.
    """
    import resource
    from . import _cst_decode_runner as R

    meta, templates, entries = R.decode_champsim_tracer(cst)
    facts = R.decode_residency_facts(entries)

    # Walk the body exactly as a check would: full pass, plus the indexed
    # and reversed access patterns the validator actually uses.  A "lazy"
    # container that quietly materialised on iteration would show up here.
    n = 0
    seq_sum = 0
    for e in entries:
        n += 1
        seq_sum += int(e.get("seq_num", 0) or 0)
    if len(entries) > 4:
        for probe in (0, len(entries) // 2, -1):
            seq_sum += int(entries[probe].get("seq_num", 0) or 0)
    order = meta.get("body_record_order") or []
    n_order = len(order)

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024

    # Lifetime, not residency — but it belongs to the same contract (the
    # views are what made the decode bounded, and a view that outlives its
    # decode is the price).  Measured after `peak` is taken so it cannot
    # move the number this check is really about.
    order_ok, order_detail = _order_view_survives(cst)

    json.dump({"peak_rss": peak, "walked": n, "seq_sum": seq_sum,
               "order": n_order, "templates": len(templates),
               "order_survives": order_ok, "order_detail": order_detail,
               **facts},
              sys.stdout)
    sys.stdout.write("\n")
    return 0


def _run_probe(cst: Path, *, eager: bool, timeout: int) -> dict:
    env = dict(os.environ)
    if eager:
        from ._cst_decode_runner import FORCE_EAGER_ENV
        env[FORCE_EAGER_ENV] = "1"
    else:
        from ._cst_decode_runner import FORCE_EAGER_ENV
        env.pop(FORCE_EAGER_ENV, None)
    proc = subprocess.run(
        [sys.executable, "-m", "champsim_tracer_validator._decode_bound",
         "--probe", str(cst)],
        check=False, capture_output=True, env=env, timeout=timeout,
        cwd=str(Path(__file__).resolve().parent.parent))
    out = (proc.stdout or b"").decode("utf-8", "replace").strip()
    err = (proc.stderr or b"").decode("utf-8", "replace").strip()
    if proc.returncode != 0 or not out:
        # A probe that could not run is a FAILED probe, never a skipped one.
        tail = " | ".join(err.splitlines()[-4:])
        return {"error": f"probe rc={proc.returncode}: {tail or 'no output'}"}
    try:
        return json.loads(out.splitlines()[-1])
    except ValueError as e:                                  # noqa: BLE001
        return {"error": f"probe output not JSON ({e}): {out[:200]}"}


# --- the check -------------------------------------------------------------

def check_decode_bound(cst: Path, *, timeout: int = 1800) -> tuple[bool, str]:
    """Returns (ok, detail).  See the module docstring for what is proven."""
    lazy = _run_probe(cst, eager=False, timeout=timeout)
    if "error" in lazy:
        return False, f"lazy probe failed: {lazy['error']}"

    n_entries = int(lazy.get("entries", 0))
    walked = int(lazy.get("walked", 0))
    limit = bound_bytes(lazy)
    peak = int(lazy.get("peak_rss", 0))

    if walked != n_entries:
        return False, (f"probe walked {walked} entries but len() says "
                       f"{n_entries} -- the sequence disagrees with itself")
    if n_entries < MIN_ENTRIES_TO_PROVE:
        # Not a skip: the check was asked to prove something and the
        # substrate cannot carry the proof.
        return False, (f"substrate too small to prove a residency bound: "
                       f"{n_entries} entries < {MIN_ENTRIES_TO_PROVE}")
    if not lazy.get("lazy"):
        return False, (f"decode_champsim_tracer returned a plain list of "
                       f"{n_entries} entries -- the eager shape is back")
    if not lazy.get("order_survives"):
        return False, ("the streaming decoder's record-order view did not "
                       "survive its own decode closing: "
                       f"{lazy.get('order_detail', 'no detail')}")
    if peak > limit:
        return False, (f"lazy decode peaked at {peak / MiB:.0f} MiB, over its "
                       f"{limit / MiB:.0f} MiB budget for {n_entries} entries "
                       f"/ {lazy.get('lines')} lines")

    # The other direction: the same measurement, against the shape the fix
    # removed.  It has to blow the budget, or this check proves nothing.
    eager = _run_probe(cst, eager=True, timeout=timeout)
    if "error" in eager:
        return False, f"forced-eager probe failed: {eager['error']}"
    e_peak = int(eager.get("peak_rss", 0))
    if eager.get("lazy"):
        return False, ("forced-eager probe still returned the lazy sequence; "
                       "the tripwire's fire-proof lever is dead")
    if e_peak <= limit:
        return False, (f"forced-eager decode peaked at {e_peak / MiB:.0f} MiB, "
                       f"WITHIN the {limit / MiB:.0f} MiB budget -- this check "
                       f"cannot distinguish the defect from the fix at this "
                       f"trace size, so its pass would be unearned")

    return True, (f"{n_entries} entries / {lazy.get('lines')} lines: "
                  f"lazy peak {peak / MiB:.0f} MiB <= {limit / MiB:.0f} MiB "
                  f"budget; forced-eager peak {e_peak / MiB:.0f} MiB exceeds "
                  f"it ({e_peak / max(peak, 1):.1f}x the lazy peak), so the "
                  f"bound is measured and the tripwire is proven live; "
                  f"record-order view lifetime OK "
                  f"({lazy.get('order_detail', '')})")


# --- CLI ------------------------------------------------------------------

# Sized so the two shapes are unmistakably far apart: this cell decodes to
# a few hundred thousand body entries, where the eager list is multiple GiB
# and the lazy sequence is a few hundred MiB.  --stop is only a BUDGET --
# what actually makes the workload long is --hot-iters, so both matter.
_CELL_STOP = "3000000"
_CELL_HOT_ITERS = "5000"


def add_parser(sub) -> None:
    p = sub.add_parser(
        "decode_bound",
        help="residency tripwire: the decode stage stays bounded on a "
             "large trace, proven in both directions")
    p.add_argument("--build-dir", required=True)
    p.add_argument("-o", "--out-dir", required=True)
    p.add_argument("--isa", default="x86_64",
                   choices=("x86_64", "aarch64", "riscv64", "mipsel"))
    p.add_argument("--cst", default=None,
                   help="Use this existing trace instead of capturing one.")
    p.add_argument("--stop", default=_CELL_STOP)


def _capture(args) -> tuple[Path | None, str]:
    """generate + build + trace a user-mode cell big enough to prove on."""
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    prog = out.name
    steps = (
        ["generate", "-o", str(out), "--isa", args.isa, "--seed", "0x5150",
         "--hot-iters", _CELL_HOT_ITERS],
        ["build", "-o", str(out), "--isa", args.isa],
        ["trace", "-o", str(out), "--isa", args.isa,
         "--build-dir", str(args.build_dir), "--stop", str(args.stop),
         "--compress", "zstd"],
    )
    for step in steps:
        proc = subprocess.run(
            [sys.executable, "-m", "champsim_tracer_validator", *step],
            check=False, capture_output=True,
            cwd=str(Path(__file__).resolve().parent.parent))
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout or b"").decode(
                "utf-8", "replace").strip().splitlines()[-4:]
            return None, f"{step[0]} failed (rc={proc.returncode}): " \
                         f"{' | '.join(tail)}"
    cst = out / f"{prog}_{args.isa}.cst"
    if not cst.is_file():
        return None, f"trace produced no {cst}"
    return cst, ""


def cmd_decode_bound(args) -> int:
    if args.cst:
        cst = Path(args.cst)
        if not cst.is_file():
            print(f"decode_bound: FAIL  no such trace: {cst}")
            return 1
    else:
        cst, err = _capture(args)
        if cst is None:
            print(f"decode_bound: FAIL  {err}")
            return 1
    ok, detail = check_decode_bound(cst)
    print(f"decode_bound: {'PASS' if ok else 'FAIL'}  {detail}")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[1] == "--probe":
        return _probe(argv[2])
    if len(argv) >= 2:
        ok, detail = check_decode_bound(Path(argv[1]))
        print(("PASS  " if ok else "FAIL  ") + detail)
        return 0 if ok else 1
    print("usage: _decode_bound.py <trace.cst> | --probe <trace.cst>",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
