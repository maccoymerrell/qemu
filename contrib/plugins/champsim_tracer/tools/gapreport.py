#!/usr/bin/env python3
"""The gap report: what QEMU says about an encoding, beside what Capstone says.

Two decoders, one encoding, two answers.  This joins the comparison capture's
two corpora on the encoding and puts every encoding in exactly one bucket, so
"QEMU is short here" and "QEMU and Capstone disagree here" are different
numbers and are never added together.

    AGREE          both name the same generic opcode
    DISAGREE       both name one, and they differ -- needs an ARBITRATION
    NO-RULE        the bytes reached no QEMU decode rule at all
    NO-WORD        a rule matched and carries no generic word yet
    UNKNOWN-WORD   QEMU stated a word this plugin cannot read: a skewed build
    CAPSTONE-BLANK QEMU named an opcode and Capstone did not

The buckets are deliberately not collapsed.  NO-RULE and NO-WORD are work
items with different owners -- one is identity instrumentation, the other a
per-rule payload -- and UNKNOWN-WORD is not a decoder gap at all but a
mismatched pair of binaries, which is why it is counted apart from both.

WHAT THIS CANNOT DO is say which side is right.  Both sides are decoders.  A
DISAGREE row is an arbitration to be written, on the merits, against the
precedent corpus; it is not a defect in either column and this tool never
calls one a defect.

WHAT IT CAN DO is say whether the arbitration HAS been written.  With
--rulings it joins each disagreement class against the checked-in corpus in
gapreport_rulings.tsv, keyed on (isa, rule, qemu opcode, capstone opcode),
and reports ARBITRATED against UNRULED.  The key carries the RULE because a
class keyed on the opcode pair grows silently -- x86's bitmanip-versus-test
class was one row when it was first ruled and thirty-six at a five-times
larger corpus -- and a new rule joining an old class is a new arbitration
that nobody has read.  The join refuses in both directions: --require-ruled
fails on an unruled class, and a ruling naming a class the scored corpora do
not contain is a dead rule and fails too.

Refusals, because a scorer that reports on nothing is the failure this tree
keeps relearning:

  * a corpus that is missing, empty, or has no data rows FAILS
  * a corpus whose #so stamp differs from its partner's FAILS -- two builds
    joined together is the frozen-arm shape
  * a join whose overlap is empty FAILS: two corpora keyed on different
    things produce a perfect zero, and a perfect zero is what this looks for

Copyright (c) 2026 Maccoy Merrell

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import collections
import os
import sys

BUCKETS = ["AGREE", "DISAGREE", "NO-RULE", "NO-WORD", "UNKNOWN-WORD",
           "CAPSTONE-BLANK"]


class Refusal(Exception):
    pass


def read_corpus(path, ncols):
    """Rows of a capture corpus, plus its #so stamp.  Refuses an empty one."""
    if not os.path.exists(path):
        raise Refusal("%s: no such corpus -- a corpus that was asked for and "
                      "is absent is a refusal, not an empty result" % path)

    stamp = None
    rows = {}
    ndata = 0

    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#so "):
                stamp = line[4:].strip()
                continue
            if line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < ncols:
                continue
            ndata += 1
            # Last writer wins; the same encoding decodes the same way every
            # time, so a repeat is a repeat and not a second answer.
            rows[parts[1]] = parts

    if ndata == 0:
        raise Refusal("%s: no data rows -- the run produced no corpus, and a "
                      "score over nothing is not a score" % path)
    return stamp, rows


RULING_COLS = 7


class Ruling:
    def __init__(self, verdict, state, reason):
        self.verdict = verdict
        self.state = state
        self.reason = reason
        self.used = 0


def read_rulings(path):
    """The checked-in arbitrations, keyed (isa, rule, qemu, capstone)."""
    rulings = {}
    bad = 0
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            p = line.split("\t")
            if len(p) < RULING_COLS:
                print("%s:%d: a ruling is isa, rule, qemu, capstone, verdict, "
                      "state, reason" % (path, n), file=sys.stderr)
                bad += 1
                continue
            isa, rule, q, c, verdict, state = [x.strip() for x in p[:6]]
            reason = "\t".join(p[6:]).strip()
            if verdict not in ("QEMU", "CAPSTONE"):
                print("%s:%d: verdict %r is not QEMU or CAPSTONE"
                      % (path, n, verdict), file=sys.stderr)
                bad += 1
            if state not in ("SETTLED", "COVERAGE-PATH"):
                print("%s:%d: state %r is not SETTLED or COVERAGE-PATH"
                      % (path, n, state), file=sys.stderr)
                bad += 1
            if not reason:
                print("%s:%d: no reason; an arbitration whose merits are not "
                      "written down is an assertion" % (path, n),
                      file=sys.stderr)
                bad += 1
            key = (isa, rule, q, c)
            if key in rulings:
                print("%s:%d: %s already arbitrated" % (path, n, str(key)),
                      file=sys.stderr)
                bad += 1
            rulings[key] = Ruling(verdict, state, reason)
    if bad:
        raise Refusal("%s: %d refused row(s)" % (path, bad))
    return rulings


def classify(ident, opc):
    """One encoding's bucket, and the pair of opcodes that decided it."""
    q_rule, q_word, q_op = ident[3], ident[4], ident[5]
    c_op = opc[3] if opc else None

    if q_rule == "#undecoded":
        return "NO-RULE", q_op, c_op
    if q_op == "#noword":
        return "NO-WORD", q_op, c_op
    if q_op == "#unknownword":
        return "UNKNOWN-WORD", q_op, c_op
    if c_op is None or c_op in ("", "-", "GEN_OP_UNKNOWN", "GEN_OP_???"):
        return "CAPSTONE-BLANK", q_op, c_op
    return ("AGREE" if q_op == c_op else "DISAGREE"), q_op, c_op


def report(isa, ident_path, opc_path, top, out, rulings=None):
    i_stamp, ident = read_corpus(ident_path, 6)
    o_stamp, opc = read_corpus(opc_path, 4)

    if i_stamp != o_stamp:
        raise Refusal("%s: the two corpora were written by different builds "
                      "(%s vs %s); joining them would score one build's "
                      "answers against another's"
                      % (isa, i_stamp or "<unstamped>", o_stamp or
                         "<unstamped>"))

    overlap = set(ident) & set(opc)
    if not overlap:
        raise Refusal("%s: the corpora share no encoding at all -- they are "
                      "keyed on different things, and the perfect zero that "
                      "produces is the failure this check exists for" % isa)

    counts = collections.Counter()
    pairs = collections.Counter()
    rules = collections.Counter()
    classes = collections.Counter()

    for enc, row in ident.items():
        bucket, q_op, c_op = classify(row, opc.get(enc))
        counts[bucket] += 1
        if bucket == "DISAGREE":
            pairs[(q_op, c_op)] += 1
            classes[(isa, row[3], q_op, c_op)] += 1
        if bucket in ("NO-RULE", "NO-WORD"):
            rules[row[3]] += 1
        if bucket == "NO-RULE" and c_op is not None:
            #
            # The bytes reached no rule and the incumbent nevertheless names
            # an opcode.  That is a class with two answers as much as a
            # DISAGREE is, so it is keyed and arbitrated the same way.
            #
            classes[(isa, "#undecoded", "#no-rule", c_op)] += 1

    total = sum(counts.values())
    print("== %s   %d encodings, %d also in the Capstone corpus"
          % (isa, total, len(overlap)), file=out)
    print("   stamp %s" % (i_stamp or "<unstamped>"), file=out)
    for b in BUCKETS:
        n = counts[b]
        print("   %-15s %8d  %5.1f%%"
              % (b, n, 100.0 * n / total if total else 0.0), file=out)

    if pairs:
        print("   -- disagreements, most common first (each needs a ruling):",
              file=out)
        for (q, c), n in pairs.most_common(top):
            print("      %8d  QEMU %-22s Capstone %s" % (n, q, c), file=out)
    if rules:
        print("   -- rules with no usable word, most common first:", file=out)
        for r, n in rules.most_common(top):
            print("      %8d  %s" % (n, r), file=out)

    unruled = collections.Counter()
    if rulings is not None:
        arb = cov = 0
        for key, n in classes.items():
            r = rulings.get(key)
            if r is None:
                unruled[key] = n
            else:
                r.used += n
                arb += n
                if r.state == "COVERAGE-PATH":
                    cov += n
        print("   -- arbitration: %d classes, %d encodings arbitrated "
              "(%d on a coverage path), %d classes UNRULED"
              % (len(classes), arb, cov, len(unruled)), file=out)
        for key, n in unruled.most_common(top):
            print("      UNRULED %8d  rule %-16s QEMU %-22s Capstone %s"
                  % (n, key[1], key[2], key[3]), file=out)

    return counts, classes, unruled


STAMP = "#so plugin=aa emulator=bb"

SELFTEST_CASES = [
    # (name, ident rows, opc rows, ident stamp, opc stamp, expected)
    ("agree",
     [("q", "01", "add", "add", "int.add", "GEN_OP_INT_ADD", "BRANCH_NONE")],
     [("q", "01", "add", "GEN_OP_INT_ADD")], STAMP, STAMP, ("AGREE", 1)),
    ("disagree",
     [("q", "01", "add", "add", "int.add", "GEN_OP_INT_ADD", "BRANCH_NONE")],
     [("q", "01", "add", "GEN_OP_INT_SUB")], STAMP, STAMP, ("DISAGREE", 1)),
    ("no-rule",
     [("q", "01", "add", "#undecoded", "-", "#undecoded", "#undecoded")],
     [("q", "01", "add", "GEN_OP_INT_ADD")], STAMP, STAMP, ("NO-RULE", 1)),
    ("no-word",
     [("q", "01", "add", "add", "-", "#noword", "#noword")],
     [("q", "01", "add", "GEN_OP_INT_ADD")], STAMP, STAMP, ("NO-WORD", 1)),
    ("unknown-word",
     [("q", "01", "add", "add", "zz", "#unknownword", "#unknownword")],
     [("q", "01", "add", "GEN_OP_INT_ADD")], STAMP, STAMP,
     ("UNKNOWN-WORD", 1)),
    ("capstone-blank",
     [("q", "01", "add", "add", "int.add", "GEN_OP_INT_ADD", "BRANCH_NONE")],
     [("q", "01", "add", "GEN_OP_UNKNOWN")], STAMP, STAMP,
     ("CAPSTONE-BLANK", 1)),
    ("empty-ident",
     [], [("q", "01", "add", "GEN_OP_INT_ADD")], STAMP, STAMP, "REFUSED"),
    ("empty-opc",
     [("q", "01", "add", "add", "int.add", "GEN_OP_INT_ADD", "BRANCH_NONE")],
     [], STAMP, STAMP, "REFUSED"),
    ("stamp-skew",
     [("q", "01", "add", "add", "int.add", "GEN_OP_INT_ADD", "BRANCH_NONE")],
     [("q", "01", "add", "GEN_OP_INT_ADD")], STAMP,
     "#so plugin=aa emulator=cc", "REFUSED"),
    ("disjoint-keys",
     [("q", "01", "add", "add", "int.add", "GEN_OP_INT_ADD", "BRANCH_NONE")],
     [("q", "99", "add", "GEN_OP_INT_ADD")], STAMP, STAMP, "REFUSED"),
]


RULING_ROW = ("q\tadd\tGEN_OP_INT_ADD\tGEN_OP_INT_SUB\tQEMU\tSETTLED\t"
              "a planted arm, so the join is seen to fire")


def selftest_rulings():
    """Prove the arbitration join refuses in BOTH directions.

    A join that only ever agrees has not been seen to work, and the two ways
    it can be wrong are opposite: a class nobody ruled, and a ruling that
    reaches no class.
    """
    import tempfile

    cases = [
        # (name, ruling rows, capstone opcode, expect)
        ("ruled",   [RULING_ROW],                    "GEN_OP_INT_SUB", "ok"),
        ("unruled", [],                              "GEN_OP_INT_SUB", "unruled"),
        ("dead",    [RULING_ROW,
                     "q\tsub\tGEN_OP_X\tGEN_OP_Y\tQEMU\tSETTLED\tno class"],
                                                     "GEN_OP_INT_SUB", "dead"),
        ("no-reason", ["q\tadd\tGEN_OP_INT_ADD\tGEN_OP_INT_SUB\tQEMU"
                       "\tSETTLED\t"],             "GEN_OP_INT_SUB", "REFUSED"),
        ("bad-verdict", ["q\tadd\tGEN_OP_INT_ADD\tGEN_OP_INT_SUB\tMAYBE"
                         "\tSETTLED\tno"],         "GEN_OP_INT_SUB", "REFUSED"),
    ]
    bad = 0
    with tempfile.TemporaryDirectory() as d:
        ip = os.path.join(d, "ident_q.tsv")
        op = os.path.join(d, "opc_q.tsv")
        rp = os.path.join(d, "rulings.tsv")
        for name, rows, c_op, want in cases:
            with open(ip, "w") as f:
                f.write(STAMP + "\n#h\n")
                f.write("q\t01\tadd\tadd\tint.add\tGEN_OP_INT_ADD\t"
                        "BRANCH_NONE\n")
            with open(op, "w") as f:
                f.write(STAMP + "\n#h\nq\t01\tadd\t%s\n" % c_op)
            with open(rp, "w") as f:
                f.write("\n".join(rows) + "\n")

            sink = open(os.devnull, "w")
            got = None
            try:
                rul = read_rulings(rp)
                _c, _cl, unruled = report("q", ip, op, 0, sink, rul)
                dead = [k for k, r in rul.items() if r.used == 0]
                got = "unruled" if unruled else ("dead" if dead else "ok")
            except Refusal:
                got = "REFUSED"
            finally:
                sink.close()
            ok = got == want
            print("  rulings:%-12s %s" % (name, "ok" if ok else
                                          "FAILED (%s)" % got))
            if not ok:
                bad += 1
    print("gapreport ruling selftest: %d of %d arms fired as designed"
          % (len(cases) - bad, len(cases)))
    return 1 if bad else 0


def selftest():
    """Prove every bucket and every refusal can fire, on planted corpora.

    A scorer nobody has seen say no is a scorer nobody has seen work.
    """
    import tempfile

    bad = 0
    with tempfile.TemporaryDirectory() as d:
        for name, irows, orows, istamp, ostamp, want in SELFTEST_CASES:
            ip = os.path.join(d, "ident_q.tsv")
            op = os.path.join(d, "opc_q.tsv")

            with open(ip, "w") as f:
                f.write(istamp + "\n#isa\tencoding\tmnem\trule\tword\t"
                        "opcode\tbranch\n")
                for r in irows:
                    f.write("\t".join(r) + "\n")
            with open(op, "w") as f:
                f.write(ostamp + "\n#isa\tencoding\tmnem\topcode\n")
                for r in orows:
                    f.write("\t".join(r) + "\n")

            sink = open(os.devnull, "w")
            try:
                counts = report("q", ip, op, 0, sink)[0]
                refused = False
            except Refusal:
                counts, refused = None, True
            finally:
                sink.close()

            if want == "REFUSED":
                ok = refused
            else:
                bucket, n = want
                ok = counts is not None and counts[bucket] == n
            print("  %-16s %s" % (name, "ok" if ok else "FAILED"))
            if not ok:
                bad += 1

    print("gapreport selftest: %d of %d arms fired as designed"
          % (len(SELFTEST_CASES) - bad, len(SELFTEST_CASES)))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--selftest", action="store_true",
                    help="prove every bucket and refusal fires, then exit")
    ap.add_argument("--dir", default=None,
                    help="directory holding ident_<isa>.tsv and opc_<isa>.tsv")
    ap.add_argument("--isa", action="append", default=[],
                    help="ISA to score; repeat for several")
    ap.add_argument("--top", type=int, default=10,
                    help="how many rows of each detail list to print")
    ap.add_argument("--require-zero", action="append", default=[],
                    metavar="BUCKET",
                    help="fail unless this bucket is 0 on every ISA")
    ap.add_argument("--rulings", default=None,
                    help="the checked-in arbitrations to join against")
    ap.add_argument("--require-ruled", action="store_true",
                    help="fail unless every disagreement class is arbitrated, "
                         "and unless every arbitration has a class")
    args = ap.parse_args()

    if args.selftest:
        return selftest() | selftest_rulings()

    if not args.dir or not args.isa:
        print("gapreport: --dir and at least one --isa are required",
              file=sys.stderr)
        return 2

    for b in args.require_zero:
        if b not in BUCKETS:
            print("gapreport: %s is not a bucket (%s)" % (b, ", ".join(BUCKETS)),
                  file=sys.stderr)
            return 2

    if args.require_ruled and not args.rulings:
        print("gapreport: --require-ruled needs --rulings; a bar with no "
              "corpus to read would pass by having looked at nothing",
              file=sys.stderr)
        return 2

    rulings = None
    if args.rulings:
        try:
            rulings = read_rulings(args.rulings)
        except Refusal as e:
            print("gapreport: REFUSED: %s" % e, file=sys.stderr)
            return 1

    bad = 0
    scored = set()
    for isa in args.isa:
        try:
            counts, _classes, unruled = report(
                isa,
                os.path.join(args.dir, "ident_%s.tsv" % isa),
                os.path.join(args.dir, "opc_%s.tsv" % isa),
                args.top, sys.stdout, rulings)
            scored.add(isa)
        except Refusal as e:
            print("gapreport: REFUSED: %s" % e, file=sys.stderr)
            bad += 1
            continue
        for b in args.require_zero:
            if counts[b]:
                print("gapreport: %s: %s is %d, required 0"
                      % (isa, b, counts[b]), file=sys.stderr)
                bad += 1
        if args.require_ruled and unruled:
            print("gapreport: %s: %d disagreement class(es) with no written "
                  "arbitration" % (isa, len(unruled)), file=sys.stderr)
            bad += 1

    #
    # The other direction.  A ruling that no scored corpus reaches is a dead
    # rule: it was written for a class that has since moved or was never
    # there, and an arbitration corpus nobody can falsify is the shape this
    # tree keeps relearning.  Only the ISAs actually scored are judged, so a
    # one-ISA run does not condemn the other three's rows.
    #
    if args.require_ruled and rulings is not None:
        dead = [k for k, r in rulings.items()
                if k[0] in scored and r.used == 0]
        for k in sorted(dead):
            print("gapreport: dead ruling: %s %s %s vs %s reaches no class "
                  "in the scored corpora" % k, file=sys.stderr)
        if dead:
            print("gapreport: %d dead ruling(s)" % len(dead), file=sys.stderr)
            bad += 1

    print("gapreport: %s" % ("FAIL" if bad else "PASS"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
