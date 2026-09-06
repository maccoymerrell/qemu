#!/usr/bin/env python3
"""ARC 3 -- the CP-H census, over whatever population an arm root holds.

For every ISA's merged `corpus_mech_<isa>.tsv` this reports the write state
QEMU's extractor reached (`WSTQ`), the class of rows whose write list it could
not finish, and the ONE safety property those rows exist to protect:

    a row whose extraction was incomplete must SAY SO.  A row carrying the
    incomplete-extraction marker while ALSO claiming a complete publish is
    the failure this census is for, and it must be 0.

WHY THIS IS A TREE TOOL.  It was written twice as a pass-local script, and
after the second time the derivation was lost with the run directory that held
it -- so an aarch64 number that had been published could not be re-derived
from the tree at all, and the only way back to it was to write the script
again from the shape of its own output.  A census the tree cannot reproduce is
a number, not a measurement.  The output format is deliberately unchanged from
the pass-local versions so that every banked CENSUS.txt stays comparable to
one produced here.

THE COLUMNS ARE CHECKED BEFORE THEY ARE READ, and that is not ceremony.  The
pass-local version reached its columns with `.get(name, "")`, so a corpus that
renamed `WSTQ` would have scored every row REFUSED, and one that renamed
`PUBD` and `wstate` would have made the MUST-BE-0 property VACUOUS -- printing
`: 0` and `CENSUS PASSED` while looking at nothing.  A check that cannot find
its subject must fail, so a missing column is a REFUSAL naming the column and
the file.

Usage:
    cph_census.py --arm DIR [--isa ISA ...] [--wp N ...] [-o FILE]
    cph_census.py --selftest

`--arm` is the sweep root holding `<isa>.wp<N>/corpus_mech_<isa>.tsv`.  An
encoding seen in more than one wp arm is counted ONCE, on first sight, which
is what makes the headline a population and not a sum over arms.

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
"""
import argparse
import collections
import os
import sys

_D = os.path.dirname(os.path.abspath(__file__))
if _D not in sys.path:
    sys.path.insert(0, _D)
from evopen import evopen, resolve                            # noqa: E402

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")
WPS = ("0", "16")

OK = "PUBLISHED from QEMU's emitters"
INCOMPLETE = ("LOWER BOUND", "ABANDONED")

#: Every column this census reads, and what it would silently become if the
#: column were absent.  Read by need_cols() and by ARM D of the selftest.
NEEDED = {
    "encoding": "the dedup key; without it every arm's rows would recount",
    "WSTQ":     "the write state itself; absent, every row scores REFUSED",
    "PUBD":     "half the MUST-BE-0 subject; absent, the property is vacuous",
    "wstate":   "the other half of the MUST-BE-0 subject",
    "WR":       "the write list the empty-marker report is measured on",
}


def klass(v):
    for m in INCOMPLETE:
        if m in v:
            return "INCOMPLETE"
    return "OK" if v == OK else "REFUSED"


def need_cols(hdr, path):
    missing = [c for c in NEEDED if c not in hdr]
    if missing:
        sys.exit("census REFUSING: %s has no %s column(s).\n%s\n"
                 "  This census scores columns it did not write.  Reaching a "
                 "missing one with a default would score the whole corpus on "
                 "an absence -- and for PUBD/wstate it would print the "
                 "MUST-BE-0 property as a satisfied 0 while looking at "
                 "nothing."
                 % (path, ", ".join(sorted(missing)),
                    "\n".join("    %-9s %s" % (c, NEEDED[c])
                              for c in sorted(missing))))


def one(arm, isa, wps):
    rows = 0
    wstq = collections.Counter()
    kinds = collections.Counter()
    marker_on_ok = 0
    incomplete_empty_wr = 0
    seen = set()
    for w in wps:
        p = os.path.join(arm, "%s.wp%s" % (isa, w), "corpus_mech_%s.tsv" % isa)
        if not os.path.exists(resolve(p)):
            sys.exit("census: %s missing -- REFUSING" % p)
        with evopen(p, errors="replace") as f:
            hdr = None
            for line in f:
                if line.startswith("#"):
                    if hdr is None:
                        hdr = line.lstrip("#").rstrip("\n").split("\t")
                        need_cols(hdr, p)
                    continue
                c = line.rstrip("\n").split("\t")
                if hdr is None or len(c) < len(hdr):
                    continue
                if c[1] in seen:
                    continue
                seen.add(c[1])
                r = dict(zip(hdr, c))
                v = r["WSTQ"]
                rows += 1
                wstq[v[:70]] += 1
                k = klass(v)
                kinds[k] += 1
                if k == "INCOMPLETE":
                    # The marker may never ride a row that also claims the
                    # complete publish, and a row that claims incompleteness
                    # with nothing extracted is a different (empty) defect.
                    if r["PUBD"] == OK or r["wstate"] == OK:
                        marker_on_ok += 1
                    # `-` is how the corpus spells an empty write list
                    # (150,327 of them on the aarch64 arm, and it is the ONLY
                    # short spelling that occurs).  The whitespace is stripped
                    # on both sides of the dash rather than only after it, so
                    # a padded field cannot be miscounted as a real list.
                    if not r["WR"].strip().strip("-").strip():
                        incomplete_empty_wr += 1
    return rows, wstq, kinds, marker_on_ok, incomplete_empty_wr


def census(arm, isas, wps, emit):
    bad = 0
    for isa in isas:
        rows, wstq, kinds, mok, iempty = one(arm, isa, wps)
        if not rows:
            sys.exit("census REFUSING: %s contributed no rows at %s.  An "
                     "empty population is not a 0%% result." % (isa, arm))
        emit("=== %s ===  distinct encodings=%d" % (isa, rows))
        for k in ("OK", "INCOMPLETE", "REFUSED"):
            emit("    %-11s %8d   %6.3f%%"
                 % (k, kinds[k], 100.0 * kinds[k] / rows))
        for v, n in wstq.most_common():
            emit("        %8d  %s" % (n, v))
        emit("    MUST BE 0  marker on a row that also claims the complete "
             "publish : %d" % mok)
        emit("    reported   incomplete rows with an EMPTY write list        "
             "  : %d" % iempty)
        if mok:
            bad = 1
    emit("\nCENSUS %s" % ("FAILED" if bad else "PASSED"))
    return bad


# --------------------------------------------------------------- selftest
HDR = ("#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\twstate\tPUB\tQN\t"
       "SURV\tRD\tSTATUS\tRDX\tCONT\tXLAT\tWR\tPUBD\tWSTQ\n")


def _row(enc, wstq, pubd=OK, wstate="x", wr="REG_GPR0"):
    return ("x86_64\t%s\tm\td\tr\ts\t%s\tp\tq\tsu\trd\tst\trdx\tc\tx\t%s\t%s"
            "\t%s\n" % (enc, wstate, wr, pubd, wstq))


def _arm(d, rows, wps=("0",), isa="x86_64", hdr=HDR):
    for w in wps:
        a = os.path.join(d, "%s.wp%s" % (isa, w))
        os.makedirs(a, exist_ok=True)
        with open(os.path.join(a, "corpus_mech_%s.tsv" % isa), "w") as f:
            f.write(hdr)
            for r in rows:
                f.write(r)
    return d


def selftest():
    import tempfile
    import shutil
    ran, fails = [], []

    def chk(name, ok, ev=""):
        ran.append(name)
        if not ok:
            fails.append(name)
        print("  %s %s" % (name, "ok" if ok else "FAIL"))
        if not ok and ev:
            print("      %s" % (ev,))

    def run(d, isas=("x86_64",), wps=("0",)):
        out = []
        try:
            rc = census(d, isas, wps, out.append)
        except SystemExit as e:
            return (e.code if isinstance(e.code, int) else 2,
                    "\n".join(out) + str(e.code))
        return rc, "\n".join(out)

    d = tempfile.mkdtemp(prefix="cph_census_selftest.")
    try:
        # A -- the classifier, over one row of each class
        _arm(d, [_row("01", OK),
                 _row("02", "LOWER BOUND: extraction incomplete", pubd="no"),
                 _row("03", "refused: something")])
        rc, t = run(d)
        chk("ARM A: OK / INCOMPLETE / REFUSED are counted apart",
            rc == 0 and "OK                 1" in t
            and "INCOMPLETE         1" in t and "REFUSED            1" in t, t)

        # B -- THE PROPERTY CONVICTS.  An instrument that cannot be watched
        # fire is not an instrument, and this is the census's only verdict.
        _arm(d, [_row("01", "ABANDONED: write list unfinished", pubd=OK)])
        rc, t = run(d)
        chk("ARM B: the marker on a row that ALSO claims the complete publish "
            "FAILS the census",
            rc == 1 and "publish : 1" in t and "CENSUS FAILED" in t, t)

        # B2 -- and through the OTHER half of the subject, so neither column
        # can go unread while the other carries the arm.
        _arm(d, [_row("01", "ABANDONED: write list unfinished", pubd="no",
                      wstate=OK)])
        rc, t = run(d)
        chk("ARM B2: and it convicts through `wstate` as well as `PUBD`",
            rc == 1 and "publish : 1" in t, t)

        # C -- the empty-write-list report is REPORTED, not fatal
        _arm(d, [_row("01", "LOWER BOUND: incomplete", pubd="no", wr="-"),
                 _row("02", "LOWER BOUND: incomplete", pubd="no", wr="  -  "),
                 _row("03", "LOWER BOUND: incomplete", pubd="no",
                      wr="REG_GPR0")])
        rc, t = run(d)
        chk("ARM C: an incomplete row with an EMPTY write list is reported "
            "and does not fail the census -- padded or bare",
            rc == 0 and "EMPTY write list          : 2" in t
            and "CENSUS PASSED" in t, t)

        # D -- EVERY named column, dropped one at a time, must REFUSE.  This
        # is the arm the pass-local script had no version of: with `.get()`
        # the PUBD/wstate drop printed `: 0` and PASSED.
        for col in sorted(NEEDED):
            cols = HDR.lstrip("#").rstrip("\n").split("\t")
            keep = [i for i, c in enumerate(cols) if c != col]
            hdr2 = "#" + "\t".join(cols[i] for i in keep) + "\n"
            body = _row("01", "ABANDONED: x", pubd=OK).rstrip("\n").split("\t")
            row2 = "\t".join(body[i] for i in keep) + "\n"
            dd = tempfile.mkdtemp(prefix="cph_census_col.")
            try:
                _arm(dd, [row2], hdr=hdr2)
                rc, t = run(dd)
                chk("ARM D/%-9s a corpus without this column is REFUSED, "
                    "never scored on the absence" % (col + ":"),
                    rc not in (0,) and "REFUSING" in t and col in t, t[:200])
            finally:
                shutil.rmtree(dd, ignore_errors=True)

        # E -- the dedup, which is what makes the headline a population
        _arm(d, [_row("01", OK), _row("02", OK)], wps=("0", "16"))
        rc, t = run(d, wps=("0", "16"))
        chk("ARM E: an encoding present in two wp arms is counted ONCE",
            rc == 0 and "distinct encodings=2" in t, t)

        # F -- a missing arm is a refusal, never an empty census
        rc, t = run(d, wps=("0", "99"))
        chk("ARM F: a missing wp arm REFUSES rather than scoring what is there",
            rc != 0 and "missing" in t, t[:200])

        # G -- and a corpus with a header but no rows is not a 0% result
        _arm(d, [])
        rc, t = run(d)
        chk("ARM G: an empty population REFUSES rather than printing 0%",
            rc != 0 and "not a 0%" in t, t[:200])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    print("\ncph_census.py selftest: %d check(s), %d failure(s)"
          % (len(ran), len(fails)))
    return 1 if fails else 0


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", help="sweep root holding <isa>.wp<N>/")
    ap.add_argument("--isa", action="append", choices=ISAS)
    ap.add_argument("--wp", action="append")
    ap.add_argument("-o", default=None, help="also write the census here")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if not a.arm:
        ap.error("--arm is required (or --selftest)")
    out = []
    rc = census(a.arm, a.isa or list(ISAS), a.wp or list(WPS), out.append)
    text = "\n".join(out) + "\n"
    sys.stdout.write(text)
    if a.o:
        with open(a.o, "w") as f:
            f.write(text)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
