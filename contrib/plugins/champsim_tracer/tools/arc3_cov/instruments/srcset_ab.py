#!/usr/bin/env python3
"""THE FLIP-RELATIVE SOURCE-LOSS INSTRUMENT: per-pc published source sets, A vs B.

WHY IT EXISTS, and the two standing instruments it is here to cover.

A change that lands AFTER a fixed baseline cannot be cleared by either of the
instruments this tree already runs, and both of them read GREEN on a change
measured to take 48 registers off the wire:

  the SOURCE CENSUS scores whether every PUBLISHED source is justified.  A
    source that stops being published leaves no row to score, so the census is
    structurally blind to the LOSS direction.  It read MISSING 0 / FABRICATION
    0 on all four ISAs on both arms of that measurement.

  SETPROOF compares against a FIXED baseline (2fb9757182), which predates the
    source-list flip.  A register the flip ADDED and a later change REMOVES was
    absent on both sides of that comparison and never enters it.  REAL-LOST = 0
    against an old baseline is necessary and not sufficient.

So this instrument compares TWO ARMS OF THE SAME TIP: the arm as it is, and the
arm with the candidate change in it.  Its subject is the one sentence neither
of the above can say --

    a register-instance published at a pc BEFORE and absent at that same pc
    AFTER, with no written adjudication.  MUST BE 0.

WHAT IT IS NOT.  It is not a total and it is not a rate.  A register that
leaves one pc and arrives at another is a LOSS at the first pc; netting the two
would report zero for a change that moved a register somewhere it does not
belong.  Losses and gains are counted apart and only losses are the bar.

MATCHED COVERAGE IS A PRECONDITION, NOT A RESULT.  qemu-user puts the host
environment on the guest stack, so two arms produced by different wrappers do
not cover the same pcs even at equal path length (#327).  A pc present in one
arm and not the other is an ERROR here, not a skipped row: an unmatched arm
makes every number below unreadable, and reporting `losses=0` over a pc set
that shrank is exactly the silent false success this file is shaped against.

THE ADJUDICATION LEDGER.  --adjudicated FILE names (isa, pc, register) triples
a maintainer has ruled may leave the wire, one per line, each with a reason:

    <isa> <pc> <REG_NAME>   # reason

An adjudicated loss is counted, printed and EXCLUDED FROM THE BAR; an
unadjudicated one fails the gate.  A ledger line that matches nothing in this
measurement is reported as STALE and fails too, because a ledger that outlives
its subject is how a gate quietly stops gating.

INPUT.  Two directories of `.key` files as keyfacts.py writes them (one per
ISA, `<isa>_none__.key` by default), whose `F_src` rows carry the published
source list per pc.

Run with --selftest for the planted-fire proof, both directions.
"""
import argparse
import os
import re
import sys

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")


def load(path):
    """pc -> set(register names), from a keyfacts .key file's F_src rows."""
    d = {}
    with open(path, errors="replace") as fh:
        for line in fh:
            f = line.rstrip("\n").split("\t")
            if len(f) >= 3 and f[1] == "F_src":
                v = f[2][2:] if f[2].startswith("V=") else f[2]
                d[f[0]] = set(x.strip() for x in v.split(",") if x.strip())
    return d


def read_ledger(path):
    """{(isa, pc, reg): reason}.  A ledger with no reason column is refused."""
    out = {}
    if not path:
        return out
    with open(path, errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            body = line.split("#", 1)
            row = body[0].split()
            if not row:
                continue
            if len(row) != 3:
                sys.exit("FAIL %s:%d: want '<isa> <pc> <REG>  # reason'"
                         % (path, n))
            if len(body) < 2 or not body[1].strip():
                sys.exit("FAIL %s:%d: an adjudication with no reason is not "
                         "an adjudication" % (path, n))
            isa, pc, reg = row
            out[(isa, pc.lower(), reg)] = body[1].strip()
    return out


def compare(a_dir, b_dir, suffix, isas, ledger):
    """Returns (rc, report_lines, losses, adjudicated, gains)."""
    lines = []
    losses = []          # (isa, pc, reg)
    adjud = []           # (isa, pc, reg, reason)
    gains = 0
    used = set()
    rc = 0
    scored = 0
    lines.append("=== PUBLISHED SOURCE SETS, PER PC, ARM A vs ARM B ===")
    lines.append("A = %s" % a_dir)
    lines.append("B = %s" % b_dir)
    for isa in isas:
        pa = os.path.join(a_dir, isa + suffix)
        pb = os.path.join(b_dir, isa + suffix)
        if not (os.path.exists(pa) and os.path.exists(pb)):
            lines.append("%-8s REFUSED: missing arm file (%s / %s)"
                         % (isa, os.path.basename(pa), os.path.basename(pb)))
            rc = 2
            continue
        A, B = load(pa), load(pb)
        only_a, only_b = set(A) - set(B), set(B) - set(A)
        common = set(A) & set(B)
        scored += len(common)
        il, ig, ia = 0, 0, 0
        for pc in sorted(common):
            for r in sorted(A[pc] - B[pc]):
                key = (isa, pc.lower(), r)
                if key in ledger:
                    used.add(key)
                    adjud.append((isa, pc, r, ledger[key]))
                    ia += 1
                else:
                    losses.append((isa, pc, r))
                    il += 1
            for r in sorted(B[pc] - A[pc]):
                ig += 1
        gains += ig
        lines.append("%-8s pcs A=%d B=%d matched=%d  only_A=%d only_B=%d  "
                     "LOST=%d (adjudicated %d)  GAINED=%d"
                     % (isa, len(A), len(B), len(common), len(only_a),
                        len(only_b), il, ia, ig))
        if only_a or only_b:
            lines.append("         COVERAGE ERROR: the arms do not cover the "
                         "same pcs -- every number on this row is unreadable")
            rc = 2
    if losses:
        lines.append("")
        lines.append("-- REGISTER-INSTANCES PUBLISHED IN A AND ABSENT IN B, "
                     "UNADJUDICATED (MUST BE 0):")
        for isa, pc, r in losses:
            lines.append("   %-8s %s  %s" % (isa, pc, r))
    if adjud:
        lines.append("")
        lines.append("-- and the ADJUDICATED losses, counted and excluded "
                     "from the bar:")
        for isa, pc, r, why in adjud:
            lines.append("   %-8s %s  %-14s %s" % (isa, pc, r, why))
    stale = sorted(set(ledger) - used)
    if stale:
        lines.append("")
        lines.append("-- STALE ADJUDICATIONS: a ledger row whose subject this "
                     "measurement does not contain.  A ledger that outlives "
                     "its subject stops gating:")
        for isa, pc, r in stale:
            lines.append("   %-8s %s  %s" % (isa, pc, r))
    lines.append("")
    lines.append("TOTAL matched pcs %d   UNADJUDICATED LOSSES %d   "
                 "adjudicated %d   gains %d   stale %d"
                 % (scored, len(losses), len(adjud), gains, len(stale)))
    if scored == 0:
        lines.append("REFUSED: nothing was compared -- a reader that cannot "
                     "find its subject FAILS")
        rc = 2
    if losses or stale:
        rc = rc or 1
    lines.append("VERDICT: " + ("PASS -- nothing left the wire unadjudicated"
                                if rc == 0 else "FAIL"))
    return rc, lines, losses, adjud, gains


# ------------------------------------------------------------------ selftest
def _write_key(path, rows):
    with open(path, "w") as fh:
        for pc, regs in rows:
            fh.write("%s\tF_src\tV=%s\t-\n" % (pc, ",".join(regs)))
            fh.write("%s\tF_opcode\tV=1\t-\n" % pc)


def selftest():
    import tempfile
    d = tempfile.mkdtemp(prefix="srcset_ab_selftest.")
    fails, ran = [], []

    def chk(name, cond, why=""):
        ran.append(name)
        print("  %-58s %s%s" % (name, "ok" if cond else "FAIL",
                                "" if cond else "  -- " + why))
        if not cond:
            fails.append(name)

    def arm(tag, rows):
        p = os.path.join(d, tag)
        os.makedirs(p, exist_ok=True)
        for isa in ISAS:
            _write_key(os.path.join(p, isa + ".key"), rows)
        return p

    base = [("0x1000", ["REG_GPR0", "REG_GPR1"]), ("0x1004", ["REG_SSP"])]

    a = arm("a", base)
    b = arm("b", base)
    rc, lines, loss, adj, gains = compare(a, b, ".key", ISAS, {})
    chk("A identical arms PASS (rc=0, losses 0)",
        rc == 0 and not loss and gains == 0, "\n".join(lines))

    # PLANTED FIRE, DIRECTION 1: a register disappears.
    c = arm("c", [("0x1000", ["REG_GPR0"]), ("0x1004", ["REG_SSP"])])
    rc, lines, loss, adj, gains = compare(a, c, ".key", ISAS, {})
    chk("B a REMOVED register FIRES (rc=1, 4 losses -- one per ISA)",
        rc == 1 and len(loss) == 4
        and all(x[2] == "REG_GPR1" for x in loss), "\n".join(lines))

    # PLANTED FIRE, DIRECTION 2: a register appears.  A GAIN is NOT the bar,
    # and this arm proves the instrument does not confuse the two.
    e = arm("e", [("0x1000", ["REG_GPR0", "REG_GPR1", "REG_PC"]),
                  ("0x1004", ["REG_SSP"])])
    rc, lines, loss, adj, gains = compare(a, e, ".key", ISAS, {})
    chk("C a GAINED register does NOT fire, and is counted (rc=0, gains 4)",
        rc == 0 and not loss and gains == 4, "\n".join(lines))

    # A loss AND a gain at the same pc: netting would report zero.
    f = arm("f", [("0x1000", ["REG_GPR0", "REG_PC"]), ("0x1004", ["REG_SSP"])])
    rc, lines, loss, adj, gains = compare(a, f, ".key", ISAS, {})
    chk("D loss+gain at one pc still FIRES (netting would read zero)",
        rc == 1 and len(loss) == 4 and gains == 4, "\n".join(lines))

    led = os.path.join(d, "adj.txt")
    with open(led, "w") as fh:
        for isa in ISAS:
            fh.write("%s 0x1000 REG_GPR1  # selftest: ruled removable\n" % isa)
    rc, lines, loss, adj, gains = compare(a, c, ".key", ISAS,
                                          read_ledger(led))
    chk("E an ADJUDICATED loss is excluded from the bar (rc=0, adj 4)",
        rc == 0 and not loss and len(adj) == 4, "\n".join(lines))

    rc, lines, loss, adj, gains = compare(a, b, ".key", ISAS, read_ledger(led))
    chk("F a STALE ledger row FAILS (its subject is not in the measurement)",
        rc == 1 and not loss, "\n".join(lines))

    with open(os.path.join(d, "noreason.txt"), "w") as fh:
        fh.write("x86_64 0x1000 REG_GPR1\n")
    try:
        read_ledger(os.path.join(d, "noreason.txt"))
        ok = False
    except SystemExit:
        ok = True
    chk("G an adjudication with no reason is REFUSED", ok)

    # UNMATCHED COVERAGE is an error, not a skipped row.
    g = arm("g", [("0x1000", ["REG_GPR0", "REG_GPR1"])])
    rc, lines, loss, adj, gains = compare(a, g, ".key", ISAS, {})
    chk("H unmatched pc coverage is an ERROR (rc=2)", rc == 2,
        "\n".join(lines))

    h = os.path.join(d, "empty")
    os.makedirs(h, exist_ok=True)
    rc, lines, loss, adj, gains = compare(a, h, ".key", ISAS, {})
    chk("I a missing arm file REFUSES rather than passing vacuously", rc == 2,
        "\n".join(lines))

    print("\nsrcset_ab.py selftest: %d check(s), %d failure(s)"
          % (len(ran), len(fails)))
    return 1 if fails else 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("a", nargs="?", help="arm A directory (the BEFORE arm)")
    ap.add_argument("b", nargs="?", help="arm B directory (the AFTER arm)")
    ap.add_argument("--suffix", default="_none__.key")
    ap.add_argument("--isa", action="append", default=None)
    ap.add_argument("--adjudicated", default=None)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if not (args.a and args.b):
        ap.error("two arm directories are required")
    rc, lines, _, _, _ = compare(args.a, args.b, args.suffix,
                                 tuple(args.isa or ISAS),
                                 read_ledger(args.adjudicated))
    print("\n".join(lines))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
