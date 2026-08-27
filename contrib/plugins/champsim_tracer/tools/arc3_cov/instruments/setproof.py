#!/usr/bin/env python3
"""SETPROOF -- the three-column A/B set comparison, with the #235 guard.

Supersedes exec26/admission/setproof.py, exec27/slots/setproof.py,
exec27c/*/setproof3.py and exec27c/writeprov/setproof_ab.py.

WHY THREE COLUMNS (#212/#214).  A key is (pc, family).  Comparing two arms
naively reports a row as LOST or GAINED whenever the PC itself is absent
from one side -- and the published PC set is NOT stable across BUILDS of
identical source: measured on riscv64, two full builds of the same tree
published 4 PCs on one side and 6 on the other, with 0 of the 12,016 common
keys differing.  Reporting that as "10 blocks moved" would be an artefact of
the instrument.  So the verdict splits:

  CHANGED     the PC is in both arms and the key's content differs
  REAL-LOST   the PC is in both arms and the family disappeared
  REAL-GAIN   the PC is in both arms and the family appeared
  FLOOR       the PC is in one arm only -- the build-order noise floor

Only CHANGED and REAL are results.  FLOOR is printed so it can never be
quietly counted as either, and it is never counted as a regression.

THE #235 GUARD.  Given an arm with no rows at all, the two-column ancestor
reported the whole opposite side as "floor" and exited 0 -- clean zeros from
a comparison that had no subject.  An empty side is a FAILURE, never a
floor.  Both arms must have rows, per ISA, before anything is scored; a
missing or empty key file exits non-zero and says which arm and why.

Usage:
  setproof.py <before-dir> <after-dir> [--isas a,b] [--suffix .key|.dkey]
  setproof.py --selftest
"""
import argparse
import collections
import os
import shutil
import sys
import tempfile

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import _arc3lib as L  # noqa: E402


def compare(a, b):
    """Score one ISA.  Both sides are known non-empty by the time we get here."""
    pa = {k[0] for k in a}
    pb = {k[0] for k in b}
    both = pa & pb
    common = set(a) & set(b)
    changed = sorted(k for k in common if a[k] != b[k])
    real_lost = sorted(k for k in set(a) - set(b) if k[0] in both)
    real_gain = sorted(k for k in set(b) - set(a) if k[0] in both)
    floor = (len(set(a) - set(b)) - len(real_lost)
             + len(set(b) - set(a)) - len(real_gain))
    return common, changed, real_lost, real_gain, floor


def run(before, after, isas, suffix, show=12, quiet=False):
    """Returns (exit_code, totals)."""
    reasons = []
    tot = collections.Counter()
    for isa in isas:
        pa = L.keyfile(before, isa, suffix)
        pb = L.keyfile(after, isa, suffix)
        a = L.load_key(pa)
        b = L.load_key(pb)
        ok_a = L.require_subject(a, "%s BEFORE arm (%s)" % (isa, pa), reasons)
        ok_b = L.require_subject(b, "%s AFTER arm (%s)" % (isa, pb), reasons)
        if not (ok_a and ok_b):
            if not quiet:
                print("%-8s NOT SCORED -- vacuity (see below)" % isa)
            continue
        common, changed, lost, gain, floor = compare(a, b)
        if not quiet:
            fam = collections.Counter(k[1] for k in changed)
            print("%-8s arms=%d/%d common=%-6d CHANGED=%-4d REAL-LOST=%-4d "
                  "REAL-GAIN=%-4d floor(pc-only-one-arm)=%d"
                  % (isa, len(a), len(b), len(common), len(changed),
                     len(lost), len(gain), floor))
            for f, n in sorted(fam.items(), key=lambda kv: -kv[1]):
                print("           CHANGED by family: %-18s %d" % (f, n))
            for tag, rows, src in (("REAL-LOST", lost, a), ("REAL-GAIN", gain, b)):
                for k in rows:
                    print("     %s %s %s %s" % (tag, k[0], k[1], src[k]))
            for k in changed[:show]:
                print("     CHANGED %s %s  %s -> %s" % (k[0], k[1], a[k], b[k]))
        tot["common"] += len(common)
        tot["chg"] += len(changed)
        tot["lost"] += len(lost)
        tot["gain"] += len(gain)
        tot["floor"] += floor
        tot["scored"] += 1
    if not quiet:
        print("TOTAL scored_isas=%d common=%d CHANGED=%d REAL-LOST=%d "
              "REAL-GAIN=%d floor=%d"
              % (tot["scored"], tot["common"], tot["chg"], tot["lost"],
                 tot["gain"], tot["floor"]))
    rc = L.report_vacuity(reasons) if not quiet else (2 if reasons else 0)
    return rc, tot


# --------------------------------------------------------------------------
# selftest

def _plant(root, name, rows):
    d = os.path.join(root, name)
    os.makedirs(d, exist_ok=True)
    return d


def _write(d, isa, rows, suffix=".key"):
    L.write_tsv(os.path.join(d, "%s_none__%s" % (isa, suffix)), rows)


def selftest():
    checks = []
    tmp = tempfile.mkdtemp(prefix="setproof_selftest_")
    try:
        base = {("0x1000", "dst_dep"): ("RAW=0x1", "NAME=rax"),
                ("0x1000", "store_data_dep"): ("RAW=0x2", "NAME=rbx"),
                ("0x1004", "dst_dep"): ("RAW=0x4", "NAME=rcx")}

        # ARM 1: identical -- everything zero, exit 0, and the arms had rows.
        A = _plant(tmp, "A", None); B = _plant(tmp, "B", None)
        for isa in ("x86_64",):
            _write(A, isa, base); _write(B, isa, base)
        rc, tot = run(A, B, ["x86_64"], ".key", quiet=True)
        checks.append(("identical arms score clean and exit 0",
                       rc == 0 and tot["chg"] == 0 and tot["common"] == 3,
                       "rc=%d common=%d changed=%d" % (rc, tot["common"], tot["chg"])))

        # ARM 2: PLANTED VACUITY -- the AFTER arm is empty.  The pre-#235
        # instrument printed common=0 floor=3 and exited 0.
        C = _plant(tmp, "C", None)
        _write(C, "x86_64", {})
        rc, tot = run(A, C, ["x86_64"], ".key", quiet=True)
        checks.append(("PLANTED empty AFTER arm FAILS (never a floor)",
                       rc != 0 and tot["scored"] == 0,
                       "rc=%d scored_isas=%d floor=%d"
                       % (rc, tot["scored"], tot["floor"])))

        # ARM 3: PLANTED VACUITY -- the arm was never produced at all.
        D = _plant(tmp, "D", None)
        rc, tot = run(A, D, ["x86_64"], ".key", quiet=True)
        checks.append(("PLANTED missing AFTER arm FAILS",
                       rc != 0 and tot["scored"] == 0,
                       "rc=%d scored_isas=%d" % (rc, tot["scored"])))

        # ARM 4: PLANTED FLOOR-AS-REGRESSION -- a PC present in one arm only
        # must land in FLOOR, never in REAL-LOST.
        E = _plant(tmp, "E", None)
        floored = dict(base)
        del floored[("0x1004", "dst_dep")]
        floored[("0x2000", "dst_dep")] = ("RAW=0x9", "NAME=rdx")
        _write(E, "x86_64", floored)
        rc, tot = run(A, E, ["x86_64"], ".key", quiet=True)
        checks.append(("PLANTED build-noise PC scores FLOOR, not REAL-LOST",
                       rc == 0 and tot["lost"] == 0 and tot["gain"] == 0
                       and tot["floor"] == 2,
                       "rc=%d lost=%d gain=%d floor=%d"
                       % (rc, tot["lost"], tot["gain"], tot["floor"])))

        # ARM 5: a genuine family loss at a COMMON pc is REAL-LOST, and the
        # floor column must not absorb it.
        F = _plant(tmp, "F", None)
        real = dict(base)
        del real[("0x1000", "store_data_dep")]
        _write(F, "x86_64", real)
        rc, tot = run(A, F, ["x86_64"], ".key", quiet=True)
        checks.append(("a real family loss at a common PC is REAL-LOST",
                       rc == 0 and tot["lost"] == 1 and tot["floor"] == 0,
                       "rc=%d lost=%d floor=%d"
                       % (rc, tot["lost"], tot["floor"])))

        # ARM 6: a content change at a common key is CHANGED.
        G = _plant(tmp, "G", None)
        chg = dict(base)
        chg[("0x1000", "dst_dep")] = ("RAW=0x2", "NAME=rbx")
        _write(G, "x86_64", chg)
        rc, tot = run(A, G, ["x86_64"], ".key", quiet=True)
        checks.append(("a content change at a common key is CHANGED",
                       rc == 0 and tot["chg"] == 1,
                       "rc=%d changed=%d" % (rc, tot["chg"])))

        # ARM 7: one ISA vacuous among several still FAILS the whole run --
        # a per-ISA hole may not be averaged away by its siblings.
        H = _plant(tmp, "H", None); I2 = _plant(tmp, "I", None)
        for isa in ("x86_64", "aarch64"):
            _write(H, isa, base)
        _write(I2, "x86_64", base)
        _write(I2, "aarch64", {})
        rc, tot = run(H, I2, ["x86_64", "aarch64"], ".key", quiet=True)
        checks.append(("one vacuous ISA among several FAILS the run",
                       rc != 0 and tot["scored"] == 1,
                       "rc=%d scored_isas=%d" % (rc, tot["scored"])))

        # ARM 8: .dkey suffix is honoured (the per-destination-register form).
        J = _plant(tmp, "J", None); K = _plant(tmp, "K", None)
        dk = {("0x1000", "dst_dep@rax"): ("N=rcx", "R=0x1")}
        _write(J, "x86_64", dk, ".dkey"); _write(K, "x86_64", dk, ".dkey")
        rc, tot = run(J, K, ["x86_64"], ".dkey", quiet=True)
        checks.append(("--suffix .dkey scores the per-register form",
                       rc == 0 and tot["common"] == 1,
                       "rc=%d common=%d" % (rc, tot["common"])))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return L.selftest_report("setproof.py", checks)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("before", nargs="?")
    ap.add_argument("after", nargs="?")
    ap.add_argument("--isas", default=",".join(L.ISAS))
    ap.add_argument("--suffix", default=".key",
                    help=".key (per-family) or .dkey (per destination register)")
    ap.add_argument("--show", type=int, default=12,
                    help="how many CHANGED rows to print per ISA")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not (args.before and args.after):
        L.die_usage("usage: setproof.py <before-dir> <after-dir> "
                    "[--isas ...] [--suffix .key|.dkey]")
    rc, _ = run(args.before, args.after, args.isas.split(","), args.suffix,
                show=args.show)
    return rc


if __name__ == "__main__":
    sys.exit(main())
