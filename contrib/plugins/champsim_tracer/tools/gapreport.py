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

TWO BUCKETS ALSO MINT CLASSES, because a bucket is not always the end of the
question.  NO-RULE and NO-WORD both mean "QEMU named nothing"; when the
reference names an opcode anyway, that encoding has two answers exactly as a
DISAGREE does, and it is keyed and arbitrated the same way -- `#no-rule` and
`#no-word` standing in for the missing QEMU word.  When the reference is also
silent no class is minted, because there is nothing to arbitrate.  That split
matters: measured on the tip corpora the NO-WORD bucket is 2 / 29 / 18 / 380
and the half a reference actually names is 2 / 29 / 1 / 26, so a reading that
took the bucket whole would convict on hundreds of encodings nobody states
anything about.

WHAT IT CAN DO is say whether the arbitration HAS been written.  With
--rulings it joins each disagreement class against the checked-in corpus in
gapreport_rulings.tsv, keyed on (isa, rule, qemu opcode, capstone opcode),
and reports ARBITRATED against UNRULED.  The key carries the RULE because a
class keyed on the opcode pair grows silently -- x86's bitmanip-versus-test
class was one row when it was first ruled and thirty-six at a five-times
larger corpus -- and a new rule joining an old class is a new arbitration
that nobody has read.  The join refuses in both directions: --require-ruled
fails on an unruled class, and on a ruling whose RULE no longer exists.

THE OTHER DIRECTION IS NOT A QUESTION ABOUT THE CORPORA, and asking it of
them was a defect.  "This ruling reaches no class in the scored corpora" is
a property of the sample: mipsel OPC_TGE flipped UNRULED -> DEAD between two
corpora of one tree, because the Capstone side of the join is a strict subset
of the QEMU side on every ISA and all 27 OPC_TGE encodings are ident-only, so
the class cannot form at all.  Nothing about the ruling or the decoder moved.

So an arbitration is judged against the RULE UNIVERSE -- every rule the
build's decoders can state, read out of that build by rule_universe.py and
stamped with its emulator's build-id -- and gets one of three dispositions:

    ARBITRATED   a class in these corpora reached it
    RESERVED     its rule exists in the build; this sample did not reach it
    DEAD         its rule is not in the build's universe at all

Only DEAD fails.  RESERVED is the honest name for a ruling about a rule that
is gated on a CPU feature, a privilege level or an ASE this corpus never
touched -- an arbitration written ahead of the encodings that need it, not a
stale one.  --require-ruled therefore needs --universe: without it the DEAD
column would be the sample verdict again.

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rule_universe

BUCKETS = ["AGREE", "DISAGREE", "NO-RULE", "NO-WORD", "UNKNOWN-WORD",
           "CAPSTONE-BLANK"]


class Refusal(Exception):
    pass


#: rule_universe raises its own Refusal type; one `except Refusal` in main()
#: has to catch both, or a universe problem would traceback instead of being
#: reported as the refusal it is.
REFUSALS = (Refusal, rule_universe.Refusal)


def emulator_of(stamp):
    """The emulator build-id out of a corpus's `#so` stamp, or None.

    The stamp is `plugin=<sha> emulator=<sha>`; the universe is keyed on the
    emulator alone, because the rules are the EMULATOR's and a plugin rebuild
    does not move one.
    """
    for field in (stamp or "").split():
        if field.startswith("emulator="):
            return field[len("emulator="):]
    return None


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


#: The words that mean "the reference said nothing here".  One test, used
#: everywhere a class is minted, because a reference that names nothing states
#: nothing to arbitrate -- and a class minted over its silence would be an
#: arbitration between one answer and no answer.
BLANK_WORDS = ("", "-", "GEN_OP_UNKNOWN", "GEN_OP_???")


def ref_named(c_op):
    """Did the reference actually name an opcode for this encoding?"""
    return c_op is not None and c_op not in BLANK_WORDS


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
    if not ref_named(c_op):
        return "CAPSTONE-BLANK", q_op, c_op
    return ("AGREE" if q_op == c_op else "DISAGREE"), q_op, c_op


def report(isa, ident_path, opc_path, top, out, rulings=None, universe=None):
    i_stamp, ident = read_corpus(ident_path, 6)
    o_stamp, opc = read_corpus(opc_path, 4)

    #
    # THE 219-B RULE, ahead of the skew check.  Two unstamped corpora COMPARE
    # EQUAL, so a skew check alone passes them both and the verdict goes out
    # naming no corpus at all -- which is how two passes of this report read
    # green on samples that differed.  A verdict is a property of
    # (commit, corpus); a corpus that cannot name its build cannot carry one.
    #
    for what, st in (("identity", i_stamp), ("opcode", o_stamp)):
        if not st:
            raise Refusal("%s: the %s corpus has no #so stamp.  A bucket "
                          "verdict is a property of (commit, corpus), and an "
                          "unstamped corpus cannot say which build wrote it"
                          % (isa, what))
    if i_stamp != o_stamp:
        raise Refusal("%s: the two corpora were written by different builds "
                      "(%s vs %s); joining them would score one build's "
                      "answers against another's"
                      % (isa, i_stamp, o_stamp))

    if universe is not None:
        u_stamp = universe[0]
        c_emu = emulator_of(i_stamp)
        if c_emu is None:
            raise Refusal("%s: the corpus stamp names no emulator, so the "
                          "rule universe cannot be proven to describe the "
                          "build that wrote it (%s)"
                          % (isa, i_stamp or "<unstamped>"))
        if c_emu != u_stamp:
            raise Refusal("%s: the rule universe is a DIFFERENT emulator's "
                          "(%s) from the one that wrote this corpus (%s).  A "
                          "rule this build dropped and that one kept would "
                          "read as alive, which is the verdict being fixed"
                          % (isa, u_stamp, c_emu))

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
        if bucket == "NO-RULE" and ref_named(c_op):
            #
            # The bytes reached no rule and the incumbent nevertheless names
            # an opcode.  That is a class with two answers as much as a
            # DISAGREE is, so it is keyed and arbitrated the same way.
            #
            classes[(isa, "#undecoded", "#no-rule", c_op)] += 1
        if bucket == "NO-WORD" and ref_named(c_op):
            #
            # A RULE MATCHED, THE WIRE HAS NO WORD FOR IT, AND THE REFERENCE
            # NAMES ONE.  Exactly the shape above, one step further in: the
            # bytes reached a decoder rule, so the identity is not in doubt,
            # and the generic vocabulary still has nothing to publish while
            # the incumbent does.  Two answers, one encoding; it is keyed and
            # arbitrated like any other.
            #
            # IT WAS INVISIBLE BEFORE THIS, and invisible in the one direction
            # that matters.  `NO-WORD` is a single bucket count, and it adds
            # together two facts that are not the same: an encoding the
            # reference also cannot name (nothing is lost -- nobody states
            # anything) and an encoding the reference names while the wire is
            # silent (information the trace does not carry).  Measured on the
            # tip corpora the split is 2 of 2 / 29 of 29 / 1 of 18 / 26 of
            # 380 -- so on riscv64 and mipsel the collapsed count is mostly
            # the harmless half, and a gate reading the bucket would have
            # convicted on rows where no reference says anything at all.
            #
            # `#no-word` is the qemu-side key, parallel to `#no-rule`, and the
            # RULE is carried in the key for the reason the header gives: a
            # class keyed on the opcode pair alone grows silently as new rules
            # join it.
            #
            classes[(isa, row[3], "#no-word", c_op)] += 1

    total = sum(counts.values())
    print("== %s   %d encodings, %d also in the Capstone corpus"
          % (isa, total, len(overlap)), file=out)
    print("   corpus stamp %s" % i_stamp, file=out)
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

    return counts, classes, unruled, i_stamp


def dispose(rulings, scored, universes):
    """The unreached rulings, split RESERVED vs DEAD against the universes.

    A ruling a class reached is neither; it is ARBITRATED and report() has
    already counted it.  Of what is left on a SCORED ISA, the build's own rule
    set decides: a rule it can still state is RESERVED, and a rule it cannot
    is DEAD.  The synthetic #undecoded rule belongs to no decoder and is
    always reserved -- gapreport, not a target, mints that class.
    """
    reserved, dead = [], []
    for k, r in sorted(rulings.items()):
        if k[0] not in scored or r.used:
            continue
        if k[1] == rule_universe.SYNTHETIC or k[1] in universes.get(k[0], ()):
            reserved.append(k)
        else:
            dead.append(k)
    return reserved, dead


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
    #
    # The 219-B arms.  Two UNSTAMPED corpora compare EQUAL, so the skew check
    # passes them and the bucket verdict goes out naming no corpus at all.
    # Both directions must refuse, or the sample stops being nameable.
    #
    ("ident-unstamped",
     [("q", "01", "add", "add", "int.add", "GEN_OP_INT_ADD", "BRANCH_NONE")],
     [("q", "01", "add", "GEN_OP_INT_ADD")], "", STAMP, "REFUSED"),
    ("opc-unstamped",
     [("q", "01", "add", "add", "int.add", "GEN_OP_INT_ADD", "BRANCH_NONE")],
     [("q", "01", "add", "GEN_OP_INT_ADD")], STAMP, "", "REFUSED"),
    ("both-unstamped",
     [("q", "01", "add", "add", "int.add", "GEN_OP_INT_ADD", "BRANCH_NONE")],
     [("q", "01", "add", "GEN_OP_INT_ADD")], "", "", "REFUSED"),
]


RULING_ROW = ("q\tadd\tGEN_OP_INT_ADD\tGEN_OP_INT_SUB\tQEMU\tSETTLED\t"
              "a planted arm, so the join is seen to fire")


def selftest_rulings():
    """Prove the arbitration join sees BOTH directions.

    A join that only ever agrees has not been seen to work, and the two ways
    it can be wrong are opposite: a class nobody ruled, and a ruling nothing
    reached.  What an unreached ruling MEANS is the universe's question and is
    proven in selftest_universe(); this proves the join can tell the two
    directions apart at all.
    """
    import tempfile

    cases = [
        # (name, ruling rows, capstone opcode, expect)
        ("ruled",   [RULING_ROW],                    "GEN_OP_INT_SUB", "ok"),
        ("unruled", [],                              "GEN_OP_INT_SUB", "unruled"),
        ("unreached", [RULING_ROW,
                     "q\tsub\tGEN_OP_X\tGEN_OP_Y\tQEMU\tSETTLED\tno class"],
                                                     "GEN_OP_INT_SUB", "unreached"),
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
                _c, _cl, unruled, _st = report("q", ip, op, 0, sink, rul)
                dead = [k for k, r in rul.items() if r.used == 0]
                got = ("unruled" if unruled else
                       "unreached" if dead else "ok")
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


def selftest_universe():
    """Prove the three dispositions, and the two refusals the universe adds.

    The disposition is the whole point of the universe, so all three have to
    be seen: a ruling a class reached, a ruling whose rule the build still has
    and this sample did not reach, and a ruling naming a rule that is gone.
    The last one is the only failure, and a run that could not tell the middle
    one from the last is the reading this column replaced.
    """
    import tempfile

    scored = {"q"}
    uni = {"q": {"add": "decodetree:x.c.inc", "sub": "decodetree:x.c.inc"}}
    cases = []

    def arm(name, rows_used, rule, want):
        r = Ruling("QEMU", "SETTLED", "planted")
        r.used = rows_used
        res, dead = dispose({("q", rule, "A", "B"): r}, scored, uni)
        got = ("arbitrated" if not res and not dead
               else "reserved" if res else "dead")
        ok = got == want
        print("  universe:%-16s %s" % (name, "ok" if ok else
                                       "FAILED (%s)" % got))
        cases.append(ok)

    arm("reached", 5, "add", "arbitrated")
    arm("unreached, rule lives", 0, "add", "reserved")
    arm("unreached, rule gone", 0, "cachee", "dead")
    arm("synthetic #undecoded", 0, rule_universe.SYNTHETIC, "reserved")

    # An ISA that was not scored is judged by nobody, in either direction.
    r = Ruling("QEMU", "SETTLED", "planted")
    ok = dispose({("other", "gone", "A", "B"): r}, scored, uni) == ([], [])
    print("  universe:%-16s %s" % ("unscored isa", "ok" if ok else "FAILED"))
    cases.append(ok)

    # And the stamp skew: a universe from a different emulator must refuse.
    with tempfile.TemporaryDirectory() as d:
        ip = os.path.join(d, "ident_q.tsv")
        op = os.path.join(d, "opc_q.tsv")
        with open(ip, "w") as f:
            f.write(STAMP + "\n#h\nq\t01\tadd\tadd\tint.add\t"
                    "GEN_OP_INT_ADD\tBRANCH_NONE\n")
        with open(op, "w") as f:
            f.write(STAMP + "\n#h\nq\t01\tadd\tGEN_OP_INT_ADD\n")
        sink = open(os.devnull, "w")
        try:
            for name, u, want in (
                    ("matching stamp", ("bb", uni["q"]), "ok"),
                    ("skewed stamp", ("zz", uni["q"]), "REFUSED")):
                try:
                    report("q", ip, op, 0, sink, None, u)
                    got = "ok"
                except Refusal:
                    got = "REFUSED"
                ok = got == want
                print("  universe:%-16s %s" % (name, "ok" if ok else
                                               "FAILED (%s)" % got))
                cases.append(ok)
        finally:
            sink.close()

    print("gapreport universe selftest: %d of %d arms fired as designed"
          % (sum(cases), len(cases)))
    return 0 if all(cases) else 1


def selftest_noword():
    """Prove the `#no-word` class is minted, and ONLY where it should be.

    Both directions, because the whole value of the class is the split it
    makes: a rule that matched with no generic word is an arbitration when the
    reference names an opcode and is NOTHING when the reference is silent.  An
    arm that only ever mints would put every unnamed encoding in the gate's
    criterion; an arm that never mints is the invisibility this class replaces.
    """
    import tempfile

    cases = [
        # (name, capstone opcode, expect a class?)
        ("reference names one", "GEN_OP_INT_ADD", True),
        ("reference blank word", "GEN_OP_UNKNOWN", False),
        ("reference empty",      "-",             False),
        ("reference absent",     None,            False),
    ]
    bad = 0
    with tempfile.TemporaryDirectory() as d:
        ip = os.path.join(d, "ident_q.tsv")
        op = os.path.join(d, "opc_q.tsv")
        for name, c_op, want in cases:
            with open(ip, "w") as f:
                f.write(STAMP + "\n#h\n")
                # one AGREE row so the join is never empty, then the subject
                f.write("q\t01\tadd\tadd\tint.add\tGEN_OP_INT_ADD\t"
                        "BRANCH_NONE\n")
                f.write("q\t02\tsys\tSYS\t-\t#noword\t#noword\n")
            with open(op, "w") as f:
                f.write(STAMP + "\n#h\nq\t01\tadd\tGEN_OP_INT_ADD\n")
                if c_op is not None:
                    f.write("q\t02\tsys\t%s\n" % c_op)
            sink = open(os.devnull, "w")
            try:
                _c, classes, _u, _s = report("q", ip, op, 0, sink)
            finally:
                sink.close()
            got = ("q", "SYS", "#no-word", c_op) in classes
            ok = got == want
            print("  no-word:%-22s %s" % (name, "ok" if ok else
                                          "FAILED (minted=%s)" % got))
            if not ok:
                bad += 1
    print("gapreport no-word selftest: %d of %d arms fired as designed"
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
                         "and unless every arbitration names a rule the build "
                         "still has")
    ap.add_argument("--universe", default=None,
                    help="directory of rules_<isa>.tsv from rule_universe.py: "
                         "every rule the scored build's decoders can state")
    args = ap.parse_args()

    if args.selftest:
        return (selftest() | selftest_rulings() | selftest_universe()
                | selftest_noword())

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

    if args.require_ruled and not args.universe:
        print("gapreport: --require-ruled needs --universe.  Without the set "
              "of rules the build can state, the only available test for a "
              "stale arbitration is whether this SAMPLE reached it -- and "
              "that verdict moves with the sample in both directions, which "
              "is the defect being fixed rather than the bar being met",
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
    universes = {}
    stamps = {}
    for isa in args.isa:
        u = None
        if args.universe:
            try:
                u = rule_universe.read(
                    os.path.join(args.universe, "rules_%s.tsv" % isa))
            except REFUSALS as e:
                print("gapreport: REFUSED: %s" % e, file=sys.stderr)
                bad += 1
                continue
            universes[isa] = u[1]
        try:
            counts, _classes, unruled, stamp = report(
                isa,
                os.path.join(args.dir, "ident_%s.tsv" % isa),
                os.path.join(args.dir, "opc_%s.tsv" % isa),
                args.top, sys.stdout, rulings, u)
            scored.add(isa)
            stamps[isa] = stamp
        except REFUSALS as e:
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
    # The other direction, asked of the BUILD rather than of the sample.
    #
    # An arbitration nobody can falsify is the shape this tree keeps
    # relearning, so the corpus of rulings has to be falsifiable -- but the
    # falsifier used to be "did any encoding in these corpora reach it", and
    # that is a fact about the corpora.  mipsel OPC_TGE flipped UNRULED ->
    # DEAD between two samples of one tree without the ruling or the decoder
    # moving at all.
    #
    # The subject a sample cannot move is the rule universe: the set of rules
    # the scored build's decoders can state, derived from that build.  So an
    # unreached ruling whose rule the build still has is RESERVED -- written
    # ahead of the encodings that need it, which is what an arbitration for a
    # feature-gated, privilege-gated or ASE-gated rule looks like -- and only
    # a ruling naming a rule the build no longer has is DEAD.
    #
    # Only ISAs actually scored are judged, so a one-ISA run does not condemn
    # the other three's rows.
    #
    if args.require_ruled and rulings is not None:
        reserved, dead = dispose(rulings, scored, universes)
        for k in reserved:
            print("gapreport: RESERVED ruling: %s %s %s vs %s -- the rule "
                  "exists in this build; no encoding in this sample reached "
                  "the class" % k)
        for k in dead:
            print("gapreport: DEAD ruling: %s %s %s vs %s -- rule %s is not "
                  "in this build's decoders at all"
                  % (k[0], k[1], k[2], k[3], k[1]), file=sys.stderr)
        print("gapreport: rulings: %d RESERVED, %d DEAD"
              % (len(reserved), len(dead)))
        if dead:
            bad += 1

    #
    # The verdict carries its corpus (219-B).  A "gapreport: PASS"
    # pasted into a report without the stamp beside it is the same
    # failure in prose form.
    #
    for isa in args.isa:
        print("gapreport: %s read on corpus %s"
              % (isa, stamps.get(isa) or "<REFUSED, not read>"))
    print("gapreport: %s" % ("FAIL" if bad else "PASS"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
