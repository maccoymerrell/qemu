"""The "(must be 0)" census — the one gate every entrypoint shares.

A counter the plugin labels ``(must be 0)`` is an invariant it asserts about
its own output.  A gate that does not read it is not a gate: the riscv64 fold
over-claim stood at ``of them resumed INSIDE the folded block (must be 0) = 1``
with 41 instructions over-claimed in 9 system cells, and every one of those
cells was scored PASS, because the only census in the suite lived in
``run_full`` and the waves ran ``all``.  Worse, a corpus that routinely
carries one nonzero must-be-0 row teaches its readers to ignore every other
one.

So the census lives here, once, and every entrypoint that produces a
``<outfile>.stats.log`` calls it.  Three rules, each of them the fix to a
failure this suite has actually had:

  * it is GENERIC.  It matches the label pattern, not a hand-kept list of
    counters, so a counter added to the plugin tomorrow is gated the day it
    is added and nobody has to remember to register it.  The enumerated list
    is the survivorship-bias failure mode in a different costume.
  * a census that finds NO stats.log, or a stats.log with no ``(must be 0)``
    row in it, FAILS.  A check that cannot find its subject must not report
    an empty success.
  * it reports WHICH counter and BY HOW MUCH.  A gate that only says "fail"
    cannot be acted on, and a non-zero must never be summarised as closed.
"""

from __future__ import annotations

import re
from pathlib import Path

# The plugin renders every counter as "%-40s %" PRIu64 (see
# champsim_tracer_stats_report.cc), so the label and the value are separated
# by at least one space and the value is the whole rest of the line.
_MUST0_RE = re.compile(r"^(?P<label>.*\(must be 0\))\s+(?P<val>\d+)\s*$")


def scan_text(text: str) -> tuple[list[tuple[str, int]], int]:
    """Return (violations, rows_seen) for one stats.log body."""
    rows = 0
    bad: list[tuple[str, int]] = []
    for line in text.splitlines():
        m = _MUST0_RE.match(line)
        if not m:
            continue
        rows += 1
        v = int(m.group("val"))
        if v:
            bad.append((m.group("label").strip(), v))
    return bad, rows


def census(paths) -> dict:
    """Census a set of stats.log paths.

    Returns {"status": "pass"|"fail", "files": n, "violations": [...],
             "unreadable": [...]}.  Status is "fail" when any row is
    non-zero, when a file cannot be read, when a file carries no
    ``(must be 0)`` row at all, or when there are no files.
    """
    files = [Path(p) for p in paths]
    violations: list[dict] = []
    unreadable: list[str] = []
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError as e:
            unreadable.append(f"{f}: {e}")
            continue
        bad, rows = scan_text(text)
        if rows == 0:
            unreadable.append(f"{f}: no '(must be 0)' row found")
            continue
        for label, value in bad:
            violations.append({"file": str(f), "label": label,
                               "value": value})
    ok = bool(files) and not violations and not unreadable
    return {"status": "pass" if ok else "fail", "files": len(files),
            "violations": violations, "unreadable": unreadable,
            "empty": not files}


def gate(paths, tag: str) -> int:
    """Census @paths, print the verdict, return 0 (pass) or 1 (fail).

    @tag names the caller in the printed lines so a wave log says which
    cell's invariant broke.
    """
    r = census(paths)
    if r["status"] == "pass":
        print(f"must0[{tag}]: ok  {r['files']} stats.log, every "
              f"'(must be 0)' row is 0")
        return 0
    if r["empty"]:
        print(f"must0[{tag}]: FAIL  no <outfile>.stats.log was produced — "
              f"the invariant census has no subject, which is a failure and "
              f"not an empty pass")
    for v in r["violations"]:
        print(f"must0[{tag}]: FAIL  {v['label']} = {v['value']}  "
              f"[{Path(v['file']).name}]")
    for u in r["unreadable"]:
        print(f"must0[{tag}]: FAIL  unreadable/empty: {u}")
    return 1


def gate_out_bases(out_bases, tag: str) -> int:
    """gate() over ``<out_base>.stats.log`` for each trace base."""
    return gate([Path(f"{b}.stats.log") for b in out_bases], tag)
