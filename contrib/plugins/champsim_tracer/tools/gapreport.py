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


def report(isa, ident_path, opc_path, top, out):
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

    for enc, row in ident.items():
        bucket, q_op, c_op = classify(row, opc.get(enc))
        counts[bucket] += 1
        if bucket == "DISAGREE":
            pairs[(q_op, c_op)] += 1
        if bucket in ("NO-RULE", "NO-WORD"):
            rules[row[3]] += 1

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

    return counts


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
                counts = report("q", ip, op, 0, sink)
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
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if not args.dir or not args.isa:
        print("gapreport: --dir and at least one --isa are required",
              file=sys.stderr)
        return 2

    for b in args.require_zero:
        if b not in BUCKETS:
            print("gapreport: %s is not a bucket (%s)" % (b, ", ".join(BUCKETS)),
                  file=sys.stderr)
            return 2

    bad = 0
    for isa in args.isa:
        try:
            counts = report(isa,
                            os.path.join(args.dir, "ident_%s.tsv" % isa),
                            os.path.join(args.dir, "opc_%s.tsv" % isa),
                            args.top, sys.stdout)
        except Refusal as e:
            print("gapreport: REFUSED: %s" % e, file=sys.stderr)
            bad += 1
            continue
        for b in args.require_zero:
            if counts[b]:
                print("gapreport: %s: %s is %d, required 0"
                      % (isa, b, counts[b]), file=sys.stderr)
                bad += 1

    print("gapreport: %s" % ("FAIL" if bad else "PASS"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
