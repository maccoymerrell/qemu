#!/usr/bin/env python3
"""The J3 battery scorer: all four dependency families, floor-excluded.

Supersedes exec27/verify/score4.py + score4b.py and their per-wave copies.

WHAT J3 MEASURES.  Each arm re-runs the same workload with one Capstone
input corrupted (`implic`, `memdir`, `access`) and asks whether a published
fact MOVED.  A fact that does not move is not sourced from what was
corrupted.  `mnem__` is the LIVE CONTROL: a battery whose dependency columns
are all zero says nothing unless something in the same run moved, so the
identity facts are scored in the same pass and a run whose control moved
nothing FAILS.

THE FLOOR.  A family cannot be scored at a PC the arm never published, and
counting such a key as "vanished" would charge the family for a whole-row
suppression it did not cause.  Floor-excluded columns are the verdict.  Two
floor definitions exist and they are NOT the same measurement -- reporting
only the narrow one is what made the suppression column read 12 in one pass
and thousands in the next:

  ALL-FLOOR   a PC is common if the arm decoded it at all (every decoded
              instruction has an opcode row).  A family that leaves the wire
              is counted even when its siblings left with it.
  DEP-FLOOR   a PC is common only if it published at least one dependency
              family in BOTH arms.  A PC that lost every family drops out of
              the denominator, so a whole-row suppression is invisible.

Both are printed.  ALL-FLOOR is the verdict; DEP-FLOOR is shown so the
narrower reading can never be quoted as if it were the same number.

VACUITY (#235).  An arm with no rows is a FAILURE, never a floor and never a
zero.  This is not hypothetical here: under the `mnem` mutation on aarch64,
riscv64 and mipsel the tracer publishes ZERO dst_dep blocks, so a scorer
that treats an empty arm as "nothing moved" reports a dead control as a
clean result.

Usage:  score_families.py <battery-dir> [--isas ...] [--arms ...]
        score_families.py --selftest
"""
import argparse
import collections
import shutil
import sys
import tempfile
import os

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import _arc3lib as L  # noqa: E402

DEP = list(L.DEP_FAMILIES)
IDENT = list(L.IDENT_FACTS)


def score_pair(base, cur, fams, mode):
    """Score one (base, arm) pair.  Returns {fam: [value, named, vanished, new]}."""
    if mode == "ALL-FLOOR":
        bp = {pc for pc, _ in base}
        cp = {pc for pc, _ in cur}
    else:
        bp = {pc for pc, f in base if f in DEP}
        cp = {pc for pc, f in cur if f in DEP}
    both = bp & cp
    out = {f: [0, 0, 0, 0] for f in fams}
    for (pc, f), val in base.items():
        if f not in out or pc not in both:
            continue
        got = cur.get((pc, f))
        if got is None:
            out[f][2] += 1
        else:
            if got[0] != val[0]:
                out[f][0] += 1
            if got[1] != val[1]:
                out[f][1] += 1
    for (pc, f) in cur:
        if f in out and pc in both and (pc, f) not in base:
            out[f][3] += 1
    return out, len(bp), len(cp), len(both), len(bp - cp)


def run(battery, isas, arms, quiet=False):
    reasons = []
    grand = {}
    control = collections.Counter()
    scored_cells = 0
    for mode in ("ALL-FLOOR", "DEP-FLOOR"):
        g = {}
        for isa in isas:
            bp = os.path.join(battery, "%s_none__.key" % isa)
            base = L.load_key(bp)
            if not L.require_subject(base, "%s reference arm none__ (%s)"
                                     % (isa, bp), reasons):
                continue
            for arm in arms:
                ap = os.path.join(battery, "%s_%s.key" % (isa, arm))
                cur = L.load_key(ap)
                if not L.require_subject(cur, "%s arm %s (%s)" % (isa, arm, ap),
                                         reasons):
                    continue
                res, nb, nc, nboth, floor = score_pair(base, cur,
                                                       DEP + IDENT, mode)
                for f, v in res.items():
                    r = g.setdefault((f, arm), [0, 0, 0, 0])
                    for i in range(4):
                        r[i] += v[i]
                    if mode == "ALL-FLOOR" and f in IDENT:
                        control[arm] += v[0]
                if mode == "ALL-FLOOR":
                    scored_cells += 1
                    if not quiet:
                        print("%-8s %-6s pcs base=%d arm=%d common=%d floor=%d"
                              % (isa, arm, nb, nc, nboth, floor))
        if mode == "ALL-FLOOR":
            grand = g
        if not quiet:
            print("\n########## %s ##########" % mode)
            print("%-16s %-7s %8s %8s %9s %6s"
                  % ("family", "arm", "value", "named", "vanished", "new"))
            for fam in DEP:
                for arm in arms:
                    v, n, van, new = g.get((fam, arm), [0, 0, 0, 0])
                    print("%-16s %-7s %8d %8d %9d %6d"
                          % (fam, arm, v, n, van, new))

    moved = 0
    if not quiet:
        print("\n=== IDENTITY FACTS -- the live control (ALL-FLOOR) ===")
        print("%-12s %-7s %8s %9s %6s" % ("fact", "arm", "value", "vanished", "new"))
    for fam in IDENT:
        for arm in arms:
            v, n, van, new = grand.get((fam, arm), [0, 0, 0, 0])
            if not quiet:
                print("%-12s %-7s %8d %9d %6d" % (fam, arm, v, van, new))
    for fam in DEP:
        for arm in arms:
            if arm == "mnem__":
                continue
            moved += sum(grand.get((fam, arm), [0, 0, 0, 0]))

    ctl = control.get("mnem__", 0)
    if not quiet:
        print("\nmnem control moved %d identity facts (must be > 0)" % ctl)
        print("MOVEMENT in the four families excluding the mnem control: %d" % moved)
        print("cells scored: %d" % scored_cells)
    rc = L.report_vacuity(reasons) if not quiet else (2 if reasons else 0)
    if "mnem__" in arms and ctl == 0:
        if not quiet:
            print("CONTROL FAILURE: the mnem arm moved no identity fact.  A "
                  "battery whose control did not move cannot be quoted for "
                  "anything it did not move either.")
        rc = rc or 1
    return rc, grand, ctl, moved


# --------------------------------------------------------------------------
# selftest

def _cell(d, isa, arm, rows):
    L.write_tsv(os.path.join(d, "%s_%s.key" % (isa, arm)), rows)


def selftest():
    checks = []
    tmp = tempfile.mkdtemp(prefix="score_families_selftest_")
    try:
        base = {
            ("0x1000", "F_opcode"): ("V=OP_ADD", "-"),
            ("0x1000", "F_branch"): ("V=BRANCH_NOT", "-"),
            ("0x1000", "dst_dep"): ("RAW=0x1", "NAME=rax"),
            ("0x1000", "store_data_dep"): ("RAW=0x2", "NAME=rbx"),
            ("0x1004", "F_opcode"): ("V=OP_SUB", "-"),
            ("0x1004", "dst_dep"): ("RAW=0x4", "NAME=rcx"),
        }
        isa = "x86_64"
        arms = ["access", "mnem__"]

        # HEALTHY: access moves nothing, mnem moves the identity facts.
        d = os.path.join(tmp, "healthy"); os.makedirs(d)
        _cell(d, isa, "none__", base)
        _cell(d, isa, "access", base)
        mnem = dict(base)
        mnem[("0x1000", "F_opcode")] = ("V=OP_MUTANT", "-")
        _cell(d, isa, "mnem__", mnem)
        rc, g, ctl, moved = run(d, [isa], arms, quiet=True)
        checks.append(("healthy battery: rc=0, control live, dep movement 0",
                       rc == 0 and ctl == 1 and moved == 0,
                       "rc=%d control=%d moved=%d" % (rc, ctl, moved)))

        # PLANTED DEFECT 1 -- VACUITY.  The access arm is empty.  The
        # pre-guard scorer reported all-zero columns and a pass.
        d = os.path.join(tmp, "vacuous"); os.makedirs(d)
        _cell(d, isa, "none__", base)
        _cell(d, isa, "access", {})
        _cell(d, isa, "mnem__", mnem)
        rc, g, ctl, moved = run(d, [isa], arms, quiet=True)
        checks.append(("PLANTED empty arm FAILS instead of scoring zeros",
                       rc != 0 and moved == 0,
                       "rc=%d moved=%d (zeros without the guard)" % (rc, moved)))

        # PLANTED DEFECT 2 -- DEAD CONTROL.  mnem moves nothing, so the
        # zeros in the dependency columns are unquotable.
        d = os.path.join(tmp, "deadctl"); os.makedirs(d)
        _cell(d, isa, "none__", base)
        _cell(d, isa, "access", base)
        _cell(d, isa, "mnem__", base)
        rc, g, ctl, moved = run(d, [isa], arms, quiet=True)
        checks.append(("PLANTED inert control FAILS (zeros unquotable)",
                       rc != 0 and ctl == 0, "rc=%d control=%d" % (rc, ctl)))

        # PLANTED DEFECT 3 -- FLOOR AS REGRESSION.  A PC absent from the arm
        # entirely must not be charged to any family as `vanished`.
        d = os.path.join(tmp, "floor"); os.makedirs(d)
        _cell(d, isa, "none__", base)
        shrunk = {k: v for k, v in base.items() if k[0] != "0x1004"}
        _cell(d, isa, "access", shrunk)
        _cell(d, isa, "mnem__", mnem)
        rc, g, ctl, moved = run(d, [isa], arms, quiet=True)
        checks.append(("PLANTED absent PC is FLOOR, not a family regression",
                       rc == 0 and moved == 0,
                       "rc=%d moved=%d (a floor-blind scorer charges 1)"
                       % (rc, moved)))

        # A GENUINE family suppression at a COMMON pc IS charged.
        d = os.path.join(tmp, "real"); os.makedirs(d)
        _cell(d, isa, "none__", base)
        real = {k: v for k, v in base.items()
                if k != ("0x1000", "store_data_dep")}
        _cell(d, isa, "access", real)
        _cell(d, isa, "mnem__", mnem)
        rc, g, ctl, moved = run(d, [isa], arms, quiet=True)
        van = g[("store_data_dep", "access")][2]
        checks.append(("a real suppression at a common PC IS charged",
                       rc == 0 and van == 1 and moved == 1,
                       "rc=%d vanished=%d moved=%d" % (rc, van, moved)))

        # DEP-FLOOR vs ALL-FLOOR are different measurements: a PC that lost
        # EVERY dependency family is invisible under DEP-FLOOR.
        d = os.path.join(tmp, "twofloor"); os.makedirs(d)
        _cell(d, isa, "none__", base)
        nodeps = {k: v for k, v in base.items() if k[1] in IDENT}
        _cell(d, isa, "access", nodeps)
        _cell(d, isa, "mnem__", mnem)
        rc, g, ctl, moved = run(d, [isa], arms, quiet=True)
        checks.append(("ALL-FLOOR sees a whole-row suppression DEP-FLOOR hides",
                       rc == 0 and moved == 3,
                       "rc=%d moved=%d (DEP-FLOOR would report 0)" % (rc, moved)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return L.selftest_report("score_families.py", checks)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("battery", nargs="?")
    ap.add_argument("--isas", default=",".join(L.ISAS))
    ap.add_argument("--arms", default=",".join(L.ARMS))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.battery:
        L.die_usage("usage: score_families.py <battery-dir>")
    rc, _, _, _ = run(args.battery, args.isas.split(","), args.arms.split(","))
    return rc


if __name__ == "__main__":
    sys.exit(main())
