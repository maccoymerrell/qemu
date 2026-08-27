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

A fourth rule, learned the same way as the first three (#263/#265): it reads
EVERY shape the report writes such a row in, not the one shape the scanner
was first written against.  Two shapes exist, and the reason is that they
come from two different report writers:

  * LABEL-FIRST — ``champsim_tracer_stats_report.cc`` renders a counter as
    ``"%-40s %" PRIu64``, so the label carries ``(must be 0)`` and the value
    ends the line.  This is the table form, 28 rows of it.
  * VALUE-FIRST — ``qdep_report()`` renders a census as ``"%10" PRIu64 "  "``
    followed by a sentence that may run over several continuation lines, so
    the value comes FIRST and its ``MUST BE 0`` may sit on the row's own line
    OR on a continuation of it.

Reading only the first shape is not a narrower gate, it is a FALSE one: the
scanner matched 28 of the 30 rows an x86_64 ``stats.log`` carries and printed
``every '(must be 0)' row is 0`` while the qdep census's
``QEMU wrote some OTHER named register the wire does not carry (MUST BE 0)``
row stood at 134.  A census whose subject it cannot see reports a clean run
over a violated invariant, which is this suite's dominant failure mode in a
new costume.

The marker is matched with LITERAL SPACES and case-insensitively, which is
load-bearing in the other direction too: the report deliberately spells the
one row that is *not* an invariant as ``NOT a must-be-0`` with hyphens (the
R10.1 REG_PC row, correct by contract), and a scanner that normalised the
separators would count it and then fail on a number that is supposed to move
with argv length.
"""

from __future__ import annotations

import re
from pathlib import Path

# The marker itself.  Literal spaces, so the hyphenated "not a must-be-0"
# prose that disclaims a row is NOT read as declaring one.
_MARKER_RE = re.compile(r"must be 0", re.IGNORECASE)

# Shape 1, the stats table: "<label ... (must be 0)>   <value>".
_LABEL_FIRST_RE = re.compile(r"^(?P<label>.*\(must be 0\))\s+(?P<val>\d+)\s*$")

# Shape 2, the qdep census: "   <value>  <sentence>", whose sentence may
# continue on following, more-indented lines that carry no value of their own.
_VALUE_FIRST_RE = re.compile(r"^\s+(?P<val>\d+)\s\s+(?P<text>\S.*?)\s*$")

# A continuation of a value-first row: indented, non-blank, no value.
_CONT_RE = re.compile(r"^\s+(?P<text>\S.*?)\s*$")

# A label long enough to be a paragraph is still reported in full up to here,
# because the gate's job is to say WHICH row broke.
_LABEL_CAP = 240


def _squash(text: str) -> str:
    s = " ".join(text.split())
    return s if len(s) <= _LABEL_CAP else s[:_LABEL_CAP - 3] + "..."


def scan_text(text: str) -> tuple[list[tuple[str, int]], int]:
    """Return (violations, rows_seen) for one stats.log body."""
    rows = 0
    bad: list[tuple[str, int]] = []
    # The open value-first row, as (value, [sentence parts]).  It is only
    # adjudicated once its last continuation line has been read, because the
    # marker may live on any of them.
    pending: tuple[int, list[str]] | None = None

    def close(pending):
        nonlocal rows
        if pending is None:
            return
        val, parts = pending
        label = " ".join(parts)
        if not _MARKER_RE.search(label):
            return
        rows += 1
        if val:
            bad.append((_squash(label), val))

    for line in text.splitlines():
        m = _LABEL_FIRST_RE.match(line)
        if m:
            close(pending)
            pending = None
            rows += 1
            v = int(m.group("val"))
            if v:
                bad.append((m.group("label").strip(), v))
            continue
        m = _VALUE_FIRST_RE.match(line)
        if m:
            close(pending)
            pending = (int(m.group("val")), [m.group("text")])
            continue
        m = _CONT_RE.match(line)
        if m and pending is not None:
            pending[1].append(m.group("text"))
            continue
        close(pending)
        pending = None
    close(pending)
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


# ---------------------------------------------------------------------------
# selftest
#
# The instruments under tools/arc3_cov/instruments/ each plant a defect and
# require the tool to fail on it; the census gate is held to the same bar,
# because its failure mode is silence.  The fixture below is a verbatim
# excerpt of a real x86_64 ``stats.log``: both row shapes, a continuation-
# carried marker, the hyphenated disclaimer that must NOT be counted, and a
# by-mnemonic tally whose value-first rows must not be mistaken for census
# rows.
# ---------------------------------------------------------------------------

_FIXTURE = """
the HAS_REG block's EXISTENCE, per instruction (R12):
       12162  QEMU stated a dependency fact and the block carries it
        1267  no block: neither side had anything, consumer at the format's
               own all-to-all over-approximation
           0  QEMU facts STATED minus CARRIED -- MUST BE 0.  A fact established
              and not carried is an emission gate standing between them, which
               is the defect R12 deleted (it read 15,763 destination rows on
               the four-ISA workload).  13113 stated, 13113 carried

  the wire's destination LIST against QEMU's writes:
           9  QEMU wrote REG_PC and the wire's list does not carry it
              (CORRECT BY CONTRACT per R10.1, NOT a must-be-0: a translation
               block ends by writing the pc and QEMU charges that write to
               whichever instruction was last)
         134  QEMU wrote some OTHER named register the wire does not carry
              (MUST BE 0 -- a destination the machine writes and the wire
               does not name)

  by mnemonic and register:
        35  ja         REG_FLAGS
        31  jg         REG_FLAGS

MOPS bytes mismatch (must be 0)          0
  >1 in one seal walk (must be 0)        0
WP session flag on correct path (must be 0) 0
"""


def selftest() -> int:
    checks: list[tuple[str, bool, str]] = []

    def chk(label, ok, detail=""):
        checks.append((label, bool(ok), detail))

    bad, rows = scan_text(_FIXTURE)
    labels = {b[0] for b in bad}

    # 1. Every shape is SEEN.  Three label-first rows, the value-first row
    #    whose marker is on its own line, and the value-first row whose
    #    marker is on a continuation: five.
    chk("all five census rows seen", rows == 5, f"rows={rows} (want 5)")

    # 2. The continuation-carried row is the one the old scanner was blind
    #    to, and it is a violation at 134.
    cont = [b for b in bad if "OTHER named register" in b[0]]
    chk("continuation-carried MUST BE 0 row read",
        len(cont) == 1 and cont[0][1] == 134,
        f"got {cont}")

    # 3. The hyphenated disclaimer is NOT a census row.  If it were counted
    #    the gate would fail on a number the report says moves with argv
    #    length, and a gate that cries wolf gets ignored.
    chk("hyphenated 'NOT a must-be-0' row not counted",
        not any("CORRECT BY CONTRACT" in l for l in labels),
        f"labels={sorted(labels)}")

    # 4. A by-mnemonic tally row is not a census row.
    chk("by-mnemonic tally rows not counted",
        not any("REG_FLAGS" in l for l in labels), f"labels={sorted(labels)}")

    # 5. The label-first shape still reads, and reads zero as zero.
    chk("label-first zeros stay clean",
        not any("MOPS" in l or "seal walk" in l or "WP session" in l
                for l in labels), f"labels={sorted(labels)}")

    # 6. PLANTED MISMATCH, both shapes.  A scanner that cannot fail is not a
    #    gate: each shape is re-run with a non-zero value and must report it.
    plant_vf = _FIXTURE.replace(
        "           0  QEMU facts STATED minus CARRIED",
        "          77  QEMU facts STATED minus CARRIED")
    pbad, prows = scan_text(plant_vf)
    chk("planted value-first non-zero FAILS",
        prows == 5 and any(v == 77 for _, v in pbad),
        f"rows={prows} bad={pbad}")

    plant_lf = _FIXTURE.replace("MOPS bytes mismatch (must be 0)          0",
                                "MOPS bytes mismatch (must be 0)          5")
    pbad, prows = scan_text(plant_lf)
    chk("planted label-first non-zero FAILS",
        prows == 5 and any(v == 5 for _, v in pbad), f"bad={pbad}")

    plant_cont = _FIXTURE.replace(
        "         134  QEMU wrote some OTHER",
        "           0  QEMU wrote some OTHER")
    pbad, prows = scan_text(plant_cont)
    chk("continuation row at 0 is clean (control for check 2)",
        prows == 5 and not pbad, f"bad={pbad}")

    # 7. A subjectless census is a failure, not an empty pass.
    import tempfile
    tmp = tempfile.mkdtemp(prefix="must0_selftest_")
    nosub = Path(tmp) / "nosubject.stats.log"
    nosub.write_text("Cumulative totals\n  entries 12\n")
    chk("stats.log with no census row FAILS",
        census([nosub])["status"] == "fail")
    chk("no stats.log at all FAILS", census([])["status"] == "fail")
    good = Path(tmp) / "good.stats.log"
    good.write_text(_FIXTURE.replace(
        "         134  QEMU wrote some OTHER",
        "           0  QEMU wrote some OTHER"))
    chk("an all-zero stats.log PASSES", census([good])["status"] == "pass")
    real = Path(tmp) / "real.stats.log"
    real.write_text(_FIXTURE)
    chk("the 134 row FAILS the file gate", census([real])["status"] == "fail")

    print("=== _must0.py --selftest ===")
    nbad = 0
    for label, ok, detail in checks:
        if not ok:
            nbad += 1
        print("  %-4s %s%s" % ("ok" if ok else "FAIL", label,
                               ("  -- " + detail) if detail and not ok else ""))
    print("_must0.py selftest: %d check(s), %d failure(s)"
          % (len(checks), nbad))
    return 1 if nbad else 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit(gate(sys.argv[1:], "cli"))
