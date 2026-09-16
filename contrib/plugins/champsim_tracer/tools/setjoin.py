#!/usr/bin/env python3
"""Per encoding and direction: which registers does each decoder name?

The wire's src_regs[] and dst_regs[] are the Capstone operand walk's.  A flip
to QEMU's stated sets has one bar -- REAL-LOST=0, no pessimistic-direction
discount -- and until CST_GEN_SET_DUMP existed that bar had no subject.  The
statement corpus carried the two set SIZES, and a size cannot say WHICH
register left; the register-map corpus is keyed on the NAME for a whole run,
so it cannot be joined per encoding; and CST_DF_SET_DUMP spells QEMU's set in
QEMU's own currency, which is right for comparing two QEMU-side BUILDS and not
a join between two DECODERS.

This reads the corpus that is that join: one run, one window, both sides, the
generic names the wire itself publishes.  For every (encoding, direction) that
BOTH sides answered for it reports the three columns this tree scores flips in:

    REAL-LOST    Capstone named it; QEMU does not.  The bar.
    REAL-GAIN    QEMU names it; Capstone does not.
    CHANGED      an encoding whose two sides differ at all.

WHAT A ROW MEANS, and it is not "defect".  Both sides are decoders.  A lost
name is a fact to adjudicate on the merits -- it is routinely QEMU declining to
fabricate something the incumbent invented -- and this tool never calls one a
defect in either column.  What it does is make the population enumerable and
nameable instead of a count.

A MEMBER WITH NO GENERIC NAME IS STILL A MEMBER.  The capture spells an
unmapped QEMU name as @unmapped:<name>, an atom as its index, an undeclared env
range as its offset and extent, and the Capstone side's unknown ids as
GEN_OP-style unknowns.  They compare as themselves.  Dropping them would make a
short set compare equal to a complete one, and a REAL-LOST of zero measured
that way is the discount R12.1 forbids -- so --strict (the default) refuses to
report at all if either side is entirely unspellable.

Refusals, because a scorer that reports on nothing is this tree's oldest
failure:

  * a corpus that is missing, empty or has no data rows FAILS
  * a corpus carrying only ONE side FAILS -- a join with one arm is not a join
  * an overlap of zero (encoding, direction) keys FAILS: two sides keyed on
    different things produce a perfect zero, and a perfect zero is what this
    looks for

Copyright (c) 2026 Maccoy Merrell

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import collections
import os
import sys


class Refusal(Exception):
    pass


def read_gen(path):
    """{(enc, dir): {side: set(names)}} from one CST_GEN_SET_DUMP corpus."""
    if not os.path.exists(path):
        raise Refusal("%s: no such corpus -- a corpus that was asked for and "
                      "is absent is a refusal, not an empty result" % path)

    rows = collections.defaultdict(dict)
    stamp = None
    ndata = 0
    sides = collections.Counter()

    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#so "):
                stamp = line[4:].strip()
                continue
            if line.startswith("#"):
                continue
            p = line.split("\t")
            if len(p) < 7:
                continue
            _isa, enc, side, direction, _nraw, _nuniq, names = p[:7]
            if side not in ("q", "c"):
                continue
            ndata += 1
            sides[side] += 1
            members = set()
            for nm in names.split(","):
                nm = nm.strip()
                if nm and nm not in ("-", "+MORE"):
                    members.add(nm)
            #
            # An encoding that decodes to two different sets in one run keeps
            # BOTH rows in the corpus, deliberately.  Here they are UNIONED,
            # because the question is which names a side can state for these
            # bytes -- and scoring a union against a union cannot manufacture
            # a REAL-LOST out of two occurrences of the same encoding.
            #
            rows[(enc, direction)].setdefault(side, set()).update(members)

    if ndata == 0:
        raise Refusal("%s: no data rows -- the run produced no corpus, and a "
                      "score over nothing is not a score" % path)
    for side, what in (("q", "QEMU"), ("c", "the Capstone walk")):
        if not sides[side]:
            raise Refusal("%s: no rows from %s at all.  A join with one arm "
                          "is not a join, and every encoding would read as a "
                          "total loss or a total gain" % (path, what))
    return stamp, rows


def score(rows, strict=True):
    """The three columns, per name and per encoding."""
    both = [k for k, v in rows.items() if "q" in v and "c" in v]
    if not both:
        raise Refusal("the two sides share no (encoding, direction) key at "
                      "all -- they are keyed on different things, and the "
                      "perfect zero that produces is the failure this check "
                      "exists for")

    lost = collections.Counter()      # name -> how many encodings lost it
    gain = collections.Counter()
    lost_enc = collections.defaultdict(list)
    gain_enc = collections.defaultdict(list)
    changed = 0
    q_named = c_named = 0

    for key in both:
        q, c = rows[key]["q"], rows[key]["c"]
        q_named += len(q)
        c_named += len(c)
        if q == c:
            continue
        changed += 1
        for nm in c - q:
            lost[nm] += 1
            if len(lost_enc[nm]) < 8:
                lost_enc[nm].append(key)
        for nm in q - c:
            gain[nm] += 1
            if len(gain_enc[nm]) < 8:
                gain_enc[nm].append(key)

    if strict and (q_named == 0 or c_named == 0):
        raise Refusal("one side named NOTHING across %d shared keys.  A "
                      "REAL-LOST measured against an empty side is not a "
                      "measurement" % len(both))

    return {
        "both": len(both), "changed": changed,
        "lost": lost, "gain": gain,
        "lost_enc": lost_enc, "gain_enc": gain_enc,
        "q_named": q_named, "c_named": c_named,
    }


def report(isa, path, top, out, strict=True):
    stamp, rows = read_gen(path)
    s = score(rows, strict)

    print("== %s   %d (encoding, direction) keys in BOTH sides" % (isa, s["both"]),
          file=out)
    print("   stamp %s" % (stamp or "<unstamped>"), file=out)
    print("   names stated: QEMU %d, Capstone walk %d"
          % (s["q_named"], s["c_named"]), file=out)
    print("   CHANGED   %8d  encodings whose two sides differ at all"
          % s["changed"], file=out)
    print("   REAL-LOST %8d  distinct names, %d (name, encoding) rows"
          % (len(s["lost"]), sum(s["lost"].values())), file=out)
    print("   REAL-GAIN %8d  distinct names, %d (name, encoding) rows"
          % (len(s["gain"]), sum(s["gain"].values())), file=out)

    for label, counts, wit in (("LOST", s["lost"], s["lost_enc"]),
                               ("GAIN", s["gain"], s["gain_enc"])):
        if not counts:
            continue
        print("   -- %s, most common first:" % label, file=out)
        for nm, n in counts.most_common(top):
            e = wit[nm][0]
            print("      %8d  %-22s  e.g. %s %s" % (n, nm, e[0], e[1]),
                  file=out)
    return s


SIDES = "#isa\tencoding\tside\tdir\tnraw\tnuniq\tnames\n"

SELFTEST_CASES = [
    # (name, rows as (enc, side, dir, names), expected)
    ("identical",
     [("01", "q", "r", "REG_GPR0"), ("01", "c", "r", "REG_GPR0")],
     ("changed", 0)),
    ("one name lost",
     [("01", "q", "r", "REG_GPR0"), ("01", "c", "r", "REG_GPR0,REG_FLAGS")],
     ("lost", 1)),
    ("one name gained",
     [("01", "q", "r", "REG_GPR0,REG_FLAGS"), ("01", "c", "r", "REG_GPR0")],
     ("gain", 1)),
    ("unmapped member counts",
     [("01", "q", "r", "@unmapped:zz"), ("01", "c", "r", "REG_GPR0")],
     ("lost", 1)),
    ("two occurrences union, no false loss",
     [("01", "q", "r", "REG_GPR0"), ("01", "q", "r", "REG_FLAGS"),
      ("01", "c", "r", "REG_GPR0,REG_FLAGS")],
     ("changed", 0)),
    ("direction is part of the key",
     [("01", "q", "r", "REG_GPR0"), ("01", "c", "w", "REG_GPR0")],
     "REFUSED"),
    ("no rows at all", [], "REFUSED"),
    ("only the QEMU side", [("01", "q", "r", "REG_GPR0")], "REFUSED"),
    ("only the Capstone side", [("01", "c", "r", "REG_GPR0")], "REFUSED"),
    ("disjoint encodings",
     [("01", "q", "r", "REG_GPR0"), ("99", "c", "r", "REG_GPR0")],
     "REFUSED"),
    ("both sides empty",
     [("01", "q", "r", "-"), ("01", "c", "r", "-")], "REFUSED"),
]


def selftest():
    """Prove every verdict and every refusal can fire, on planted corpora."""
    import tempfile

    bad = 0
    with tempfile.TemporaryDirectory() as d:
        for name, rows, want in SELFTEST_CASES:
            p = os.path.join(d, "gen_q.tsv")
            with open(p, "w") as f:
                f.write("#so plugin=aa emulator=bb\n" + SIDES)
                for enc, side, direction, names in rows:
                    n = 0 if names == "-" else len(names.split(","))
                    f.write("q\t%s\t%s\t%s\t%d\t%d\t%s\n"
                            % (enc, side, direction, n, n, names))

            sink = open(os.devnull, "w")
            got = None
            try:
                s = report("q", p, 0, sink)
                got = ("changed", s["changed"])
                if s["lost"]:
                    got = ("lost", sum(s["lost"].values()))
                elif s["gain"]:
                    got = ("gain", sum(s["gain"].values()))
            except Refusal:
                got = "REFUSED"
            finally:
                sink.close()

            ok = got == want
            print("  %-34s %s" % (name, "ok" if ok else "FAILED (%s)" % (got,)))
            if not ok:
                bad += 1

    print("setjoin selftest: %d of %d arms fired as designed"
          % (len(SELFTEST_CASES) - bad, len(SELFTEST_CASES)))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--selftest", action="store_true",
                    help="prove every verdict and refusal fires, then exit")
    ap.add_argument("--dir", default=None,
                    help="directory holding gen_<isa>.tsv")
    ap.add_argument("--isa", action="append", default=[])
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--require-no-loss", action="store_true",
                    help="fail unless REAL-LOST is 0 on every scored ISA")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.dir or not args.isa:
        print("setjoin: --dir and at least one --isa are required",
              file=sys.stderr)
        return 2

    bad = 0
    for isa in args.isa:
        try:
            s = report(isa, os.path.join(args.dir, "gen_%s.tsv" % isa),
                       args.top, sys.stdout)
        except Refusal as e:
            print("setjoin: REFUSED: %s" % e, file=sys.stderr)
            bad += 1
            continue
        if args.require_no_loss and s["lost"]:
            print("setjoin: %s: REAL-LOST is %d, required 0"
                  % (isa, sum(s["lost"].values())), file=sys.stderr)
            bad += 1

    print("setjoin: %s" % ("FAIL" if bad else "PASS"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
