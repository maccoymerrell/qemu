#!/usr/bin/env python3
"""The alias refiners: what they move, and whether QEMU's rule says the same.

WHY THIS FILE EXISTS.  Two of the Capstone facts the wire reads had no
instrument that could score them: `info->mnemonic`, read by
refine_alias_fields(), and the per-row `.refine` callbacks.  The claim standing
in for a measurement was "the decode rule already separates what one Capstone
instruction id merged" -- plausible case by case, and an argument.  No corpus
carried the branch type the alias surface produces beside the branch type the
vocabulary derives, so aarch64 `b` vs `b.<cc>`, mips `jr $ra` vs `jr $rN`,
`bal`'s false conditional and riscv's alias-hidden link register were unscored.
A flip that retires that surface without this column would be flipping on the
argument.

CST_ALIAS_DUMP carries three readings of every encoding -- as the operand walk
left it, after refine_alias_fields(), after `.refine` -- and this joins them
against the identity corpus's own branch column.  Every encoding lands in
exactly one bucket:

    UNTOUCHED-AGREE   no refiner moved it, and QEMU's rule says the same
    UNTOUCHED-DIFFER  no refiner moved it, and the two sides differ anyway
    CONVERGED         a refiner moved it, and the move landed ON QEMU's answer
    DIVERGED          a refiner moved it, and the move landed AWAY from QEMU's
    STILL-DIFFERS     a refiner moved it; both readings differ from QEMU's
    NO-QEMU-BRANCH    QEMU stated no branch type for these bytes

THE NAMES ARE DELIBERATELY NOT VERDICTS.  An earlier draft called these two
REPAIRED and BROKEN, and that presumes QEMU is the reference -- while this
tool's whole premise is that both sides are decoders and neither column is a
defect.  CONVERGED and DIVERGED say only which way a refiner moved the two
answers relative to each other.

CONVERGED IS THE POPULATION A FLIP IS ABOUT: the encodings where the alias
surface is what makes the two sides agree, so retiring it costs something
unless QEMU's rule supplies the distinction independently.  DIVERGED is the
same question asked the other way, and is an ARBITRATION rather than a loss --
riscv64 `j` is the worked example, where QEMU's rule is JAL (a call) and the
refiner reads rd == x0 off the printed alias to call it a jump.  Which of the
two the wire should carry is a ruling to write; this tool's job is to make the
population nameable instead of arguable.

The `moved` column says WHICH refiner, because they have different fates: the
alias surface keys on the printed mnemonic and is what a flip retires, while a
per-row .refine reads the operand walk and is a different question.

Refusals:

  * either corpus missing, empty, or with no data rows FAILS
  * a `#so` stamp mismatch between the two FAILS -- two builds joined
  * an empty overlap FAILS: a perfect zero from two keys that never meet is
    what this check exists to catch

Copyright (c) 2026 Maccoy Merrell

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import collections
import os
import sys

BUCKETS = ["UNTOUCHED-AGREE", "UNTOUCHED-DIFFER", "CONVERGED", "DIVERGED",
           "STILL-DIFFERS", "NO-QEMU-BRANCH"]

#: The identity corpus spells "QEMU has nothing to say here" three ways, and
#: none of them is a branch type.  Kept apart from a real disagreement.
NO_BRANCH = ("#undecoded", "#noword", "#unknownword", "-", "")


class Refusal(Exception):
    pass


def read_tsv(path, ncols, key):
    """Rows keyed by @key(parts), plus the #so stamp.  Refuses an empty one."""
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
            p = line.split("\t")
            if len(p) < ncols:
                continue
            ndata += 1
            rows[key(p)] = p
    if ndata == 0:
        raise Refusal("%s: no data rows -- the run produced no corpus, and a "
                      "score over nothing is not a score" % path)
    return stamp, rows


ALIAS_COLS = 14        # isa enc mnem br_walk br_alias br_final c_w c_a c_f
                       # ns_w ns_a ns_f nd_f moved
IDENT_COLS = 7


def classify(alias_row, q_branch):
    """One encoding's bucket, plus which refiner moved it."""
    br_walk, br_alias, br_final = alias_row[3], alias_row[4], alias_row[5]
    cond_walk, cond_final = alias_row[6], alias_row[8]
    moved = alias_row[13]

    if q_branch in NO_BRANCH:
        return "NO-QEMU-BRANCH", moved

    touched = moved != "none"
    if not touched:
        return ("UNTOUCHED-AGREE" if br_final == q_branch
                else "UNTOUCHED-DIFFER"), moved

    #
    # The refiner moved something.  Three outcomes, and the one that matters is
    # whether the move ENDED on QEMU's answer.  The conditional flag is part of
    # the comparison only where it is the whole of the move: mips `bal` keeps
    # BRANCH_DIRECT_CALL and flips conditional off, so a branch-type-only test
    # would call that untouched and silently drop the one case the column was
    # built for.
    #
    before = br_walk if br_walk != br_final or cond_walk == cond_final \
        else br_walk
    landed = br_final == q_branch
    started = before == q_branch and cond_walk == cond_final

    if landed and not started:
        return "CONVERGED", moved
    if started and not landed:
        return "DIVERGED", moved
    if landed:
        #
        # It agreed before and agrees now: the refiner moved the conditional
        # flag or a register count, which the identity corpus's branch column
        # cannot see.  Reported as REPAIRED only if something actually
        # differed; otherwise it is an untouched agreement by this column's
        # lights and says so.
        #
        return ("CONVERGED" if br_walk != br_final
                else "UNTOUCHED-AGREE"), moved
    return "STILL-DIFFERS", moved


def report(isa, alias_path, ident_path, top, out):
    a_stamp, alias = read_tsv(alias_path, ALIAS_COLS, lambda p: p[1])
    i_stamp, ident = read_tsv(ident_path, IDENT_COLS, lambda p: p[1])

    if a_stamp != i_stamp:
        raise Refusal("%s: the two corpora were written by different builds "
                      "(%s vs %s); joining them would score one build's "
                      "answers against another's"
                      % (isa, a_stamp or "<unstamped>",
                         i_stamp or "<unstamped>"))

    overlap = set(alias) & set(ident)
    if not overlap:
        raise Refusal("%s: the corpora share no encoding at all -- they are "
                      "keyed on different things, and the perfect zero that "
                      "produces is the failure this check exists for" % isa)

    counts = collections.Counter()
    by_moved = collections.Counter()
    pairs = collections.Counter()
    mnems = collections.Counter()

    for enc in overlap:
        row = alias[enc]
        q_branch = ident[enc][6]
        bucket, moved = classify(row, q_branch)
        counts[bucket] += 1
        by_moved[(bucket, moved)] += 1
        if bucket in ("CONVERGED", "DIVERGED", "STILL-DIFFERS",
                      "UNTOUCHED-DIFFER"):
            pairs[(bucket, row[5], q_branch)] += 1
            mnems[(bucket, row[2])] += 1

    total = sum(counts.values())
    print("== %s   %d encodings in both corpora" % (isa, total), file=out)
    print("   stamp %s" % (a_stamp or "<unstamped>"), file=out)
    for b in BUCKETS:
        n = counts[b]
        print("   %-18s %8d  %5.1f%%"
              % (b, n, 100.0 * n / total if total else 0.0), file=out)

    touched = sum(n for (b, m), n in by_moved.items() if m != "none")
    print("   -- the alias surface is load-bearing on %d encodings" % touched,
          file=out)
    for (b, m), n in by_moved.most_common():
        if m == "none":
            continue
        print("      %8d  %-18s by %s" % (n, b, m), file=out)

    if pairs:
        print("   -- Capstone-final vs QEMU, most common first:", file=out)
        for (b, c, q), n in pairs.most_common(top):
            print("      %8d  %-18s Capstone %-22s QEMU %s" % (n, b, c, q),
                  file=out)
    if mnems:
        print("   -- by printed mnemonic:", file=out)
        for (b, m), n in mnems.most_common(top):
            print("      %8d  %-18s %s" % (n, b, m), file=out)

    return counts


STAMP = "#so plugin=aa emulator=bb"


def _arow(enc, mnem, w, a, fin, cw=0, ca=0, cf=0, moved="none"):
    return "\t".join(["q", enc, mnem, w, a, fin, str(cw), str(ca), str(cf),
                      "1", "1", "1", "1", moved])


def _irow(enc, mnem, branch):
    return "\t".join(["q", enc, mnem, "rule", "word", "GEN_OP_BRANCH", branch])


SELFTEST_CASES = [
    ("untouched agree",
     [_arow("01", "b", "BRANCH_DIRECT_JUMP", "BRANCH_DIRECT_JUMP",
            "BRANCH_DIRECT_JUMP")],
     [_irow("01", "b", "BRANCH_DIRECT_JUMP")], ("UNTOUCHED-AGREE", 1)),
    ("untouched differ",
     [_arow("01", "b", "BRANCH_DIRECT_JUMP", "BRANCH_DIRECT_JUMP",
            "BRANCH_DIRECT_JUMP")],
     [_irow("01", "b", "BRANCH_COND_DIRECT")], ("UNTOUCHED-DIFFER", 1)),
    ("repaired by the alias surface",
     [_arow("01", "b.eq", "BRANCH_DIRECT_JUMP", "BRANCH_COND_DIRECT",
            "BRANCH_COND_DIRECT", moved="alias")],
     [_irow("01", "b.eq", "BRANCH_COND_DIRECT")], ("CONVERGED", 1)),
    ("broken by the alias surface",
     [_arow("01", "b", "BRANCH_COND_DIRECT", "BRANCH_DIRECT_JUMP",
            "BRANCH_DIRECT_JUMP", moved="alias")],
     [_irow("01", "b", "BRANCH_COND_DIRECT")], ("DIVERGED", 1)),
    ("still differs after a move",
     [_arow("01", "jr", "BRANCH_DIRECT_JUMP", "BRANCH_INDIRECT_JUMP",
            "BRANCH_INDIRECT_JUMP", moved="alias")],
     [_irow("01", "jr", "BRANCH_RETURN")], ("STILL-DIFFERS", 1)),
    ("conditional-only move is not silently untouched",
     [_arow("01", "bal", "BRANCH_DIRECT_CALL", "BRANCH_DIRECT_CALL",
            "BRANCH_DIRECT_CALL", cw=1, ca=0, cf=0, moved="alias")],
     [_irow("01", "bal", "BRANCH_DIRECT_CALL")], ("CONVERGED", 1)),
    ("QEMU states no branch",
     [_arow("01", "b", "BRANCH_DIRECT_JUMP", "BRANCH_DIRECT_JUMP",
            "BRANCH_DIRECT_JUMP")],
     [_irow("01", "b", "#undecoded")], ("NO-QEMU-BRANCH", 1)),
    ("empty alias corpus", [],
     [_irow("01", "b", "BRANCH_DIRECT_JUMP")], "REFUSED"),
    ("empty ident corpus",
     [_arow("01", "b", "BRANCH_DIRECT_JUMP", "BRANCH_DIRECT_JUMP",
            "BRANCH_DIRECT_JUMP")], [], "REFUSED"),
    ("disjoint keys",
     [_arow("01", "b", "BRANCH_DIRECT_JUMP", "BRANCH_DIRECT_JUMP",
            "BRANCH_DIRECT_JUMP")],
     [_irow("99", "b", "BRANCH_DIRECT_JUMP")], "REFUSED"),
]


def selftest():
    """Prove every bucket and every refusal can fire, on planted corpora."""
    import tempfile

    bad = 0
    with tempfile.TemporaryDirectory() as d:
        ap_ = os.path.join(d, "alias_q.tsv")
        ip = os.path.join(d, "ident_q.tsv")
        for name, arows, irows, want in SELFTEST_CASES:
            with open(ap_, "w") as f:
                f.write(STAMP + "\n#h\n" + "".join(r + "\n" for r in arows))
            with open(ip, "w") as f:
                f.write(STAMP + "\n#h\n" + "".join(r + "\n" for r in irows))

            sink = open(os.devnull, "w")
            try:
                counts = report("q", ap_, ip, 0, sink)
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
            print("  %-42s %s" % (name, "ok" if ok else "FAILED"))
            if not ok:
                bad += 1

    # A stamp skew has to refuse too, and needs two different stamps.
    with tempfile.TemporaryDirectory() as d:
        ap_ = os.path.join(d, "alias_q.tsv")
        ip = os.path.join(d, "ident_q.tsv")
        with open(ap_, "w") as f:
            f.write(STAMP + "\n#h\n" + _arow(
                "01", "b", "BRANCH_DIRECT_JUMP", "BRANCH_DIRECT_JUMP",
                "BRANCH_DIRECT_JUMP") + "\n")
        with open(ip, "w") as f:
            f.write("#so plugin=aa emulator=cc\n#h\n"
                    + _irow("01", "b", "BRANCH_DIRECT_JUMP") + "\n")
        sink = open(os.devnull, "w")
        try:
            report("q", ap_, ip, 0, sink)
            ok = False
        except Refusal:
            ok = True
        finally:
            sink.close()
        print("  %-42s %s" % ("stamp skew", "ok" if ok else "FAILED"))
        if not ok:
            bad += 1

    n = len(SELFTEST_CASES) + 1
    print("aliasscore selftest: %d of %d arms fired as designed" % (n - bad, n))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--dir", default=None,
                    help="directory holding alias_<isa>.tsv and ident_<isa>.tsv")
    ap.add_argument("--isa", action="append", default=[])
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--require-zero", action="append", default=[],
                    metavar="BUCKET",
                    help="fail unless this bucket is 0 on every ISA")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.dir or not args.isa:
        print("aliasscore: --dir and at least one --isa are required",
              file=sys.stderr)
        return 2
    for b in args.require_zero:
        if b not in BUCKETS:
            print("aliasscore: %s is not a bucket (%s)"
                  % (b, ", ".join(BUCKETS)), file=sys.stderr)
            return 2

    bad = 0
    for isa in args.isa:
        try:
            counts = report(isa,
                            os.path.join(args.dir, "alias_%s.tsv" % isa),
                            os.path.join(args.dir, "ident_%s.tsv" % isa),
                            args.top, sys.stdout)
        except Refusal as e:
            print("aliasscore: REFUSED: %s" % e, file=sys.stderr)
            bad += 1
            continue
        for b in args.require_zero:
            if counts[b]:
                print("aliasscore: %s: %s is %d, required 0"
                      % (isa, b, counts[b]), file=sys.stderr)
                bad += 1

    print("aliasscore: %s" % ("FAIL" if bad else "PASS"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
