#!/usr/bin/env python3
"""The destination-family scorer, keyed per destination REGISTER.

Supersedes exec27b/seating/scoredst.py and its per-wave copies.  Reads the
`.dkey` files produced by `keyfacts.py --dst`.

WHY NOT THE SLOT (#231).  `dst_dep[]` is an ARRAY with one mask per wire
destination slot, and the slot list is the operand walk's.  Diffing the
array reports movement whenever the WALK's destination list changes, which
under an access-flag mutation is nearly every instruction -- and that
movement swamps, and hides, whatever the masks themselves did.  Measured,
the array-keyed form overstated the mover count by 219x: 17,520 array rows
against 80 real per-register movers.  So each row is (pc, dst_dep@<REG>).
A destination the mutated arm no longer has is VANISHED and counted apart:
the dictionary effect stated as its own number instead of folded into the
mask column.

VACUITY (#235), AND IT IS NOT HYPOTHETICAL HERE.  Under the `mnem`
mutation, aarch64 / riscv64 / mipsel publish ZERO dst_dep blocks -- every
instruction is an unknown mnemonic -- so the control arm's `.dkey` is empty
on three of four ISAs.  The pre-guard scorer printed `rows=0 name_moved=0
... vanished=0` for those cells, which reads as "the control was clean" and
is in fact "the control had no subject".  An empty arm is a FAILURE here.

AND THE EMPTY ARM WAS NOT THE ONLY EMPTY SUBJECT (#249).  A second floor
sits below it: an arm whose file is full can still share no PC with the
reference, which scores 0 rows and prints as an inert arm.  Measured on
this battery, `access` and `memdir` on aarch64 and mipsel are exactly that
-- the access-flag inversion turns every write into a read, the destination
list empties and refills, and the intersection is ZERO.  require_overlap()
names those as failures too.

THE CONTROL IS `dstmsk`, NOT `mnem__` (#249).  The `mnem` arm is the wrong
control for this family in the strongest sense: it does not merely fail to
move the masks, it deletes them, because the block's existence is the
refiner's decision and the refiner has no row for an unknown mnemonic.  A
control has to leave the population it is the control for standing.
`dstmsk` moves the mask on the line that publishes it and touches nothing
else -- rows, vanished and new are all unchanged under it -- so it is live
on every ISA where a destination is published at all, which is the property
`mnem` never had here.

Usage:  score_dst.py <battery-dir> [--isas ...] [--arms ...]
        score_dst.py --selftest
"""
import argparse
import os
import shutil
import sys
import tempfile

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import _arc3lib as L  # noqa: E402


def score_pair(base, cur):
    bp = {pc for pc, _ in base}
    cp = {pc for pc, _ in cur}
    both = bp & cp
    rows = nm = rw = van = new = 0
    for (pc, k), v in base.items():
        if pc not in both:
            continue
        rows += 1
        got = cur.get((pc, k))
        if got is None:
            van += 1
        else:
            if got[0] != v[0]:
                nm += 1
            if got[1] != v[1]:
                rw += 1
    for (pc, k) in cur:
        if pc in both and (pc, k) not in base:
            new += 1
    return [rows, nm, rw, van, new]


def run(battery, isas, arms, quiet=False):
    reasons = []
    tot = {a: [0] * 5 for a in arms}
    live = {a: {} for a in arms}
    if not quiet:
        print("%-8s %-7s %8s %8s %8s %9s %6s"
              % ("isa", "arm", "rows", "namemvd", "rawmvd", "vanished", "new"))
    for isa in isas:
        bp = os.path.join(battery, "%s_none__.dkey" % isa)
        base = L.load_key(bp)
        if not L.require_subject(base, "%s reference arm none__ (%s)" % (isa, bp),
                                 reasons):
            continue
        for arm in arms:
            ap = os.path.join(battery, "%s_%s.dkey" % (isa, arm))
            cur = L.load_key(ap)
            if not L.require_subject(cur, "%s arm %s (%s)" % (isa, arm, ap),
                                     reasons):
                if not quiet:
                    print("%-8s %-7s NOT SCORED -- vacuity" % (isa, arm))
                continue
            r = score_pair(base, cur)
            if not L.require_overlap(r[0], "%s arm %s (%s)"
                                     % (isa, arm, ap), reasons):
                if not quiet:
                    print("%-8s %-7s NOT SCORED -- vacuity (no shared PC)"
                          % (isa, arm))
                continue
            if not quiet:
                print("%-8s %-7s %8d %8d %8d %9d %6d"
                      % (isa, arm, r[0], r[1], r[2], r[3], r[4]))
            for i in range(5):
                tot[arm][i] += r[i]
            if r[1]:
                live[arm][isa] = (r[1], r[0])
    if not quiet:
        print("")
        for arm in arms:
            t = tot[arm]
            print("TOTAL x%d %-7s rows=%d name_moved=%d raw_moved=%d "
                  "vanished=%d new=%d"
                  % (len(isas), arm, t[0], t[1], t[2], t[3], t[4]))
    ctl = L.DST_CONTROL
    ctl_rc = 0
    if ctl in arms:
        if not quiet:
            print("")
            print("CONTROL %s: LIVE on %d/%d ISAs, %d destination row(s) "
                  "moved" % (ctl, len(live[ctl]), len(isas), tot[ctl][1]))
            for isa in isas:
                print("  %-8s %s" % (isa, ("moved %d of %d" % live[ctl][isa])
                                     if isa in live[ctl] else "NOT LIVE"))
        if len(live[ctl]) != len(isas):
            if not quiet:
                print("CONTROL FAILURE: %s did not move a destination row on "
                      "every ISA.  A zero scored on an ISA where the control "
                      "did not move is not quotable." % ctl)
            ctl_rc = 1
    # Vacuity outranks a dead control in the exit code because it is the
    # stronger statement -- one says a number cannot be read, the other says
    # it cannot be trusted -- but both are printed, never one instead of the
    # other.
    rc = L.report_vacuity(reasons) if not quiet else (2 if reasons else 0)
    return (rc or ctl_rc), tot


# --------------------------------------------------------------------------
# selftest

def _cell(d, isa, arm, rows):
    L.write_tsv(os.path.join(d, "%s_%s.dkey" % (isa, arm)), rows)


def selftest():
    checks = []
    tmp = tempfile.mkdtemp(prefix="score_dst_selftest_")
    try:
        isa = "x86_64"
        arms = ["access", L.DST_CONTROL]
        ctl = L.DST_CONTROL
        base = {("0x1000", "dst_dep@rbx"): ("N=rcx", "R=0x1"),
                ("0x1000", "dst_dep@rax"): ("N=IMM", "R=0x8"),
                ("0x1004", "dst_dep@rdx"): ("N=rsi", "R=0x2")}
        moved = dict(base)
        moved[("0x1000", "dst_dep@rbx")] = ("N=rcx,IMM", "R=0x9")

        d = os.path.join(tmp, "healthy"); os.makedirs(d)
        _cell(d, isa, "none__", base); _cell(d, isa, "access", base)
        _cell(d, isa, ctl, moved)
        rc, tot = run(d, [isa], arms, quiet=True)
        checks.append(("healthy: rc=0, access inert, control live",
                       rc == 0 and tot["access"][1] == 0 and tot[ctl][1] == 1,
                       "rc=%d access_moved=%d control_moved=%d"
                       % (rc, tot["access"][1], tot[ctl][1])))

        # PLANTED DEFECT 1 -- VACUITY, the shape actually present in
        # exec27b/seating, exec27b/verify and exec27c/writeprov.
        d = os.path.join(tmp, "vacuous"); os.makedirs(d)
        _cell(d, isa, "none__", base); _cell(d, isa, "access", base)
        _cell(d, isa, ctl, {})
        rc, tot = run(d, [isa], arms, quiet=True)
        checks.append(("PLANTED empty control arm FAILS (was rows=0, clean)",
                       rc != 0 and tot[ctl][0] == 0,
                       "rc=%d control_rows=%d" % (rc, tot[ctl][0])))

        # PLANTED DEFECT 2 -- DEAD CONTROL that is present but inert.  This
        # is the #249 shape exactly: `mnem__` scored 99 x86_64 rows and moved
        # none of them, and three ISAs never even got that far.
        d = os.path.join(tmp, "deadctl"); os.makedirs(d)
        _cell(d, isa, "none__", base); _cell(d, isa, "access", base)
        _cell(d, isa, ctl, base)
        rc, tot = run(d, [isa], arms, quiet=True)
        checks.append(("PLANTED present-but-inert control FAILS",
                       rc != 0 and tot[ctl][0] == 3 and tot[ctl][1] == 0,
                       "rc=%d control_rows=%d moved=%d"
                       % (rc, tot[ctl][0], tot[ctl][1])))

        # PLANTED DEFECT 3 -- WRONG KEY.  Renaming the destination REGISTER
        # while leaving the mask word alone must show as vanished+new, not
        # as silence.  A slot-indexed key reports nothing here.
        d = os.path.join(tmp, "wrongkey"); os.makedirs(d)
        renamed = {(("0x1000", "dst_dep@r11") if k == ("0x1000", "dst_dep@rbx")
                    else k): v for k, v in base.items()}
        _cell(d, isa, "none__", base); _cell(d, isa, "access", renamed)
        _cell(d, isa, ctl, moved)
        rc, tot = run(d, [isa], arms, quiet=True)
        checks.append(("PLANTED destination rename shows vanished+new",
                       rc == 0 and tot["access"][3] == 1 and tot["access"][4] == 1,
                       "rc=%d vanished=%d new=%d (a slot key reports 0/0)"
                       % (rc, tot["access"][3], tot["access"][4])))

        # PLANTED DEFECT 4 -- FLOOR AS REGRESSION.  A PC absent from the arm
        # is build noise and must not be charged as vanished.
        d = os.path.join(tmp, "floor"); os.makedirs(d)
        shrunk = {k: v for k, v in base.items() if k[0] != "0x1004"}
        _cell(d, isa, "none__", base); _cell(d, isa, "access", shrunk)
        _cell(d, isa, ctl, moved)
        rc, tot = run(d, [isa], arms, quiet=True)
        checks.append(("PLANTED absent PC is FLOOR, not vanished",
                       rc == 0 and tot["access"][3] == 0 and tot["access"][0] == 2,
                       "rc=%d vanished=%d rows=%d"
                       % (rc, tot["access"][3], tot["access"][0])))

        # PLANTED DEFECT 5 -- THE EMPTY INTERSECTION (#249).  The arm is a
        # full file and shares no PC with the reference, which is the real
        # shape of aarch64/mipsel `access` in the battery.  It must FAIL,
        # not print as an inert arm.
        d = os.path.join(tmp, "disjoint"); os.makedirs(d)
        elsewhere = {("0x9000", "dst_dep@rbx"): ("N=rcx", "R=0x1"),
                     ("0x9004", "dst_dep@rdx"): ("N=rsi", "R=0x2")}
        _cell(d, isa, "none__", base); _cell(d, isa, "access", elsewhere)
        _cell(d, isa, ctl, moved)
        rc, tot = run(d, [isa], arms, quiet=True)
        checks.append(("PLANTED disjoint-PC arm FAILS (was 'rows=0, clean')",
                       rc == 2 and tot["access"][0] == 0,
                       "rc=%d access_rows=%d access_moved=%d"
                       % (rc, tot["access"][0], tot["access"][1])))

        # PLANTED DEFECT 6 -- A CONTROL LIVE ON ONE ISA IS NOT A CONTROL FOR
        # TWO.  #249's whole subject: a per-total mover count hides an ISA on
        # which the control never moved, and every zero scored on that ISA is
        # then quoted against a control that was not there.
        d = os.path.join(tmp, "oneisa"); os.makedirs(d)
        _cell(d, isa, "none__", base); _cell(d, isa, "access", base)
        _cell(d, isa, ctl, moved)
        _cell(d, "aarch64", "none__", base); _cell(d, "aarch64", "access", base)
        _cell(d, "aarch64", ctl, base)
        rc, tot = run(d, [isa, "aarch64"], arms, quiet=True)
        checks.append(("PLANTED control live on 1 of 2 ISAs FAILS",
                       rc != 0 and tot[ctl][1] == 1,
                       "rc=%d control_moved_total=%d (a total hides the "
                       "dead ISA)" % (rc, tot[ctl][1])))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return L.selftest_report("score_dst.py", checks)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("battery", nargs="?")
    ap.add_argument("--isas", default=",".join(L.ISAS))
    ap.add_argument("--arms", default=",".join(L.DST_ARMS))
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.battery:
        L.die_usage("usage: score_dst.py <battery-dir>")
    rc, _ = run(args.battery, args.isas.split(","), args.arms.split(","))
    return rc


if __name__ == "__main__":
    sys.exit(main())
