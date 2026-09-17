#!/usr/bin/env python3
"""Per encoding and direction: which registers does each decoder name?

The wire's src_regs[] and dst_regs[] are QEMU's stated sets, and the bar on
that flip is REAL-LOST=0 with no pessimistic-direction discount.  Until
CST_GEN_SET_DUMP existed the bar had no subject: the statement corpus carried
the two set SIZES, and a size cannot say WHICH register left; the register-map
corpus is keyed on the NAME for a whole run, so it cannot be joined per
encoding; and CST_DF_SET_DUMP spells QEMU's set in QEMU's own currency, which
is right for comparing two QEMU-side BUILDS and not a join between two
DECODERS.

This reads the corpus that is that join: one run, one window, both sides, the
generic names the wire itself publishes.

THE QEMU ARM IS THE WIRE, and that is a correction.  This scorer used to read
side 'q' as qemu_plugin_insn_reg_reads/writes -- the raw provenance bit sets
the seating works FROM -- and the seating adds to them from the vector-operand
statements, the store-data dependency family and the write notes.  So a
register the trace publishes through any of those scored as a LOSS while
nothing was lost: `dup v0.16b, w1` published `-> %v0` against an empty write
set, and `str q0, [x0]` published `vstore %v0` while naming no vector register
at all.  Side 'q' is now the published lists; the provenance sets are side 'p'
and are reported beside the bar, from the same corpus, so the change of
comparand is a measured difference rather than a claim.

For every (encoding, direction) that BOTH sides answered for it reports the
three columns this tree scores flips in:

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
            if side not in ("q", "c", "p"):
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
    #
    # THE 219-B RULE.  A verdict is a property of (commit, corpus), never of
    # a commit alone -- two passes of this scorer read green on corpora that
    # differed, and the green was the sample.  So a reading has to be able to
    # say WHICH corpus it read, and a corpus that cannot say which build
    # produced it cannot support one.  Printing "<unstamped>" beside the
    # number was not enough: the number still travelled.  This refuses.
    #
    if not stamp:
        raise Refusal("%s: no #so stamp.  A REAL-LOST reading is a property "
                      "of (commit, corpus); an unstamped corpus cannot name "
                      "the build it came from, so no verdict read on it can "
                      "be quoted against a commit" % path)
    for side, what in (("q", "QEMU"), ("c", "the Capstone walk")):
        if not sides[side]:
            raise Refusal("%s: no rows from %s at all.  A join with one arm "
                          "is not a join, and every encoding would read as a "
                          "total loss or a total gain" % (path, what))
    return stamp, rows


def score(rows, strict=True, qside="q"):
    """The three columns, per name and per encoding.

    @qside picks which QEMU-side column is scored: "q" is the WIRE's published
    src_regs[]/dst_regs[] and is the bar; "p" is the raw provenance bit sets
    the seating works from, which is the comparand this scorer used until the
    wire column existed and is kept so the two readings can be taken from one
    corpus and the difference between them attributed rather than guessed.
    """
    both = [k for k, v in rows.items() if qside in v and "c" in v]
    if not both:
        raise Refusal("the two sides share no (encoding, direction) key at "
                      "all -- they are keyed on different things, and the "
                      "perfect zero that produces is the failure this check "
                      "exists for")

    lost = collections.Counter()      # name -> how many encodings lost it
    lost_dir = collections.Counter()  # (name, direction) -> the same, keyed
                                      # by direction, because the read and
                                      # the write halves of one register are
                                      # separate arbitrations
    gain = collections.Counter()
    lost_enc = collections.defaultdict(list)
    gain_enc = collections.defaultdict(list)
    changed = 0
    q_named = c_named = 0

    for key in both:
        q, c = rows[key][qside], rows[key]["c"]
        q_named += len(q)
        c_named += len(c)
        if q == c:
            continue
        changed += 1
        for nm in c - q:
            lost[nm] += 1
            lost_dir[(nm, key[1])] += 1
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
        "lost": lost, "lost_dir": lost_dir, "gain": gain,
        "lost_enc": lost_enc, "gain_enc": gain_enc,
        "q_named": q_named, "c_named": c_named,
    }


RULING_COLS = 7


def read_rulings(path):
    """{(isa, name, dir): (verdict, state, third, reason)} from the TSV.

    REFUSES an absent or empty file rather than scoring everything UNRULED
    against nothing: "I could not find the rulings" is not "there are none",
    and a --require-ruled that failed for that reason would be naming the
    wrong defect.
    """
    if not os.path.exists(path):
        raise Refusal("%s: no such rulings file -- a ruling join that was "
                      "asked for and is absent is a refusal, not an empty "
                      "verdict set" % path)
    out = {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            p = line.split("\t")
            if len(p) < RULING_COLS:
                continue
            isa, name, direction, verdict, state, third = \
                [x.strip() for x in p[:6]]
            out[(isa, name, direction)] = (verdict, state, third,
                                           "\t".join(p[6:]).strip())
    if not out:
        raise Refusal("%s: parsed 0 rulings -- an empty join marks every "
                      "class UNRULED for a reason that is about the file"
                      % path)
    return out


GENERIC_IDS_H = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..",
    "champsim_tracer_generic_ids.h")


def name_universe(path=None):
    """Every generic register name this BUILD's vocabulary can spell.

    THE DEAD COLUMN IS NOT A QUESTION ABOUT THE SAMPLE, and asking it of
    the sample was the same defect the gap report already had fixed.  A
    class with no rows in THESE corpora is a fact about the corpora:
    aarch64 and riscv64 REG_ZERO w flipped from a live class to an empty
    one at 22cf161b5f without the ruling, the decoder or the wire moving
    -- the scorer had simply stopped mis-spelling the name.  Condemning
    the arbitration for that would retire a reading that is still correct
    and still reachable.

    The subject a sample cannot move is the VOCABULARY: the names
    champsim_tracer_generic_ids.h defines.  A ruling naming one of them is
    RESERVED when this corpus did not reach it -- written ahead of the
    encodings that need it.  Only a ruling naming a register this build
    can no longer spell at all is DEAD.
    """
    p = path or GENERIC_IDS_H
    if not os.path.exists(p):
        raise Refusal("%s: no vocabulary header -- without it the DEAD "
                      "column would be the sample verdict again, which is "
                      "the reading being fixed" % p)
    #
    # COMMENTS ARE STRIPPED FIRST, and that is load-bearing: the header's
    # own prose NAMES the identifiers it retired (REG_DSPCTRL, REG_VSTART,
    # REG_VCSR) to explain why they are gone.  Scraping the file as flat
    # text would put a deleted register back in the vocabulary and let a
    # ruling about it read RESERVED forever.
    #
    src = open(p, errors="replace").read()
    out = []
    i = 0
    while True:
        j = src.find("/*", i)
        if j < 0:
            out.append(src[i:])
            break
        out.append(src[i:j])
        k = src.find("*/", j + 2)
        if k < 0:
            break
        i = k + 2
    body = "".join(out)

    names = set()
    for tok in body.replace(",", " ").replace("=", " ").split():
        if tok.startswith("REG_") and tok.replace("_", "").isalnum():
            names.add(tok)
    names.discard("REG_ID_COUNT")   # the sentinel, not a register
    names.discard("REG_NONE")       # the absence of one
    if len(names) < 32:
        raise Refusal("%s: parsed only %d register names; a universe that "
                      "small is a parse failure, not a small vocabulary"
                      % (p, len(names)))
    return names


def join_rulings(isa, s, rulings, out, universe=None):
    """Report UNRULED classes and the disposition of every ruling.

    A class with REAL-LOST rows and no ruling is UNRULED.  In the other
    direction a ruling this corpus did not reach is RESERVED when its
    register name is one the build's vocabulary still has, and DEAD only
    when the name is gone -- see name_universe() for why the sample is the
    wrong subject for that question.  Only DEAD fails.
    """
    live = set()
    unruled = []
    for (nm, direction), n in sorted(
            (((nm, d), n) for (nm, d), n in s["lost_dir"].items()),
            key=lambda x: -x[1]):
        key = (isa, nm, direction)
        if key in rulings:
            live.add(key)
        else:
            unruled.append((nm, direction, n))

    unreached = [k for k in rulings if k[0] == isa and k not in live]
    if universe is None:
        reserved, dead = [], unreached
    else:
        reserved = [k for k in unreached if k[1] in universe]
        dead = [k for k in unreached if k[1] not in universe]

    kinds = collections.Counter(rulings[k][0] for k in live)
    print("   -- arbitration: %d classes live, %s; %d UNRULED, "
          "%d RESERVED, %d DEAD"
          % (len(live),
             ", ".join("%s %d" % (v, n) for v, n in sorted(kinds.items()))
             or "none",
             len(unruled), len(reserved), len(dead)), file=out)
    for nm, direction, n in unruled[:20]:
        print("      UNRULED %8d  %s %s" % (n, nm, direction), file=out)
    for k in sorted(reserved)[:20]:
        print("      RESERVED    %s %s  (%s) -- the name is in this build's "
              "vocabulary; this corpus did not reach the class"
              % (k[1], k[2], rulings[k][0]), file=out)
    for k in sorted(dead)[:20]:
        print("      DEAD        %s %s  (%s) -- no such register name in "
              "this build" % (k[1], k[2], rulings[k][0]), file=out)
    return unruled, dead


def report(isa, path, top, out, strict=True, rulings=None,
           universe=None):
    stamp, rows = read_gen(path)
    s = score(rows, strict)

    print("== %s   %d (encoding, direction) keys in BOTH sides" % (isa, s["both"]),
          file=out)
    print("   corpus stamp %s" % stamp, file=out)
    s["stamp"] = stamp
    print("   the QEMU arm is the WIRE: src_regs[]/dst_regs[] as published",
          file=out)
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

    #
    # THE RETIRED COMPARAND, BESIDE THE LIVE ONE.
    #
    # Side 'p' is the raw provenance bit sets, which is what this scorer read
    # as the QEMU arm before the wire column existed.  Reporting it from the
    # SAME corpus is what makes the change of comparand attributable: the two
    # numbers come from one run, one window and one build, so the difference
    # between them is the instrument and nothing else.  A corpus with no 'p'
    # rows says so rather than printing a zero.
    #
    if any("p" in v for v in rows.values()):
        try:
            sp = score(rows, strict, qside="p")
        except Refusal as e:
            print("   -- provenance-side reading REFUSED: %s" % e, file=out)
        else:
            s["prov"] = sp
            print("   -- side p, the RETIRED comparand (raw provenance sets, "
                  "not the wire):", file=out)
            print("      %d keys in both sides; REAL-LOST %d names / %d rows, "
                  "REAL-GAIN %d names / %d rows, CHANGED %d"
                  % (sp["both"], len(sp["lost"]), sum(sp["lost"].values()),
                     len(sp["gain"]), sum(sp["gain"].values()),
                     sp["changed"]), file=out)
            print("      DELTA wire-minus-provenance: REAL-LOST rows %+d, "
                  "REAL-GAIN rows %+d, CHANGED %+d"
                  % (sum(s["lost"].values()) - sum(sp["lost"].values()),
                     sum(s["gain"].values()) - sum(sp["gain"].values()),
                     s["changed"] - sp["changed"]), file=out)
    else:
        print("   -- side p absent from this corpus: the retired comparand "
              "cannot be read here, and no delta is claimed", file=out)

    if rulings is not None:
        s["unruled"], s["dead"] = join_rulings(isa, s, rulings, out,
                                               universe)
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
    # The 219-B arm.  Written with NOSTAMP as the first element so the
    # writer below leaves the #so line out entirely; a corpus that cannot
    # name its build must refuse, not read as a clean zero.
    ("an UNSTAMPED corpus REFUSES",
     [("NOSTAMP", "", "", ""),
      ("01", "q", "r", "REG_GPR0"), ("01", "c", "r", "REG_GPR0")],
     "REFUSED"),
]


def selftest():
    """Prove every verdict and every refusal can fire, on planted corpora."""
    import tempfile

    bad = 0
    with tempfile.TemporaryDirectory() as d:
        for name, rows, want in SELFTEST_CASES:
            p = os.path.join(d, "gen_q.tsv")
            stamped = not (rows and rows[0][0] == "NOSTAMP")
            with open(p, "w") as f:
                if stamped:
                    f.write("#so plugin=aa emulator=bb\n")
                f.write(SIDES)
                for enc, side, direction, names in rows:
                    if enc == "NOSTAMP":
                        continue
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



def prov_selftest():
    """Prove the two comparands are read apart, and that each can move alone.

    The change this exists for is a change of COMPARAND, and a change of
    comparand that cannot be shown to alter a reading is indistinguishable
    from no change at all.  Each arm plants a corpus where the wire side and
    the provenance side disagree in a known way, and asserts both readings.
    """
    import tempfile

    def plant(d, rows):
        p = os.path.join(d, "gen_q.tsv")
        with open(p, "w") as f:
            f.write("#so plugin=aa emulator=bb\n" + SIDES)
            for enc, side, direction, names in rows:
                n = 0 if names == "-" else len(names.split(","))
                f.write("q\t%s\t%s\t%s\t%d\t%d\t%s\n"
                        % (enc, side, direction, n, n, names))
        return p

    #
    # Arm 1 is the 220-B witness in miniature: `dup v0.16b, w1` publishes a
    # vector destination on the wire and names NOTHING to the provenance sets.
    # The old comparand calls that a loss; the wire does not.
    # Arm 2 is its mirror: a member the provenance sets carry and the wire
    # does not, which the wire reading must still call a loss -- so the new
    # comparand is not simply a quieter one.
    # Arm 3 is the control on the control: identical sides read zero on both,
    # so a nonzero delta is never the instrument talking to itself.
    #
    cases = [
        # The second encoding keeps the provenance side non-empty overall, so
        # the arm measures a difference and not the strict-mode refusal a
        # wholly blank side would (correctly) raise.
        ("a wire-published member the provenance set lacks",
         [("01", "q", "w", "REG_VEC0"), ("01", "p", "w", "-"),
          ("01", "c", "w", "REG_VEC0"),
          ("02", "q", "r", "REG_GPR0"), ("02", "p", "r", "REG_GPR0"),
          ("02", "c", "r", "REG_GPR0")],
         (0, 1)),
        ("a member BOTH sides lack is lost on both readings",
         [("01", "q", "r", "REG_GPR0"), ("01", "p", "r", "REG_GPR0"),
          ("01", "c", "r", "REG_GPR0,REG_FLAGS")],
         (1, 1)),
        ("identical sides: zero on both readings",
         [("01", "q", "r", "REG_GPR0"), ("01", "p", "r", "REG_GPR0"),
          ("01", "c", "r", "REG_GPR0")],
         (0, 0)),
    ]

    bad = 0
    with tempfile.TemporaryDirectory() as d:
        for name, rows, want in cases:
            p = plant(d, rows)
            sink = open(os.devnull, "w")
            try:
                s = report("q", p, 0, sink)
                got = (sum(s["lost"].values()),
                       sum(s["prov"]["lost"].values()))
            except (Refusal, KeyError) as e:
                got = "REFUSED (%s)" % e
            finally:
                sink.close()
            ok = got == want
            print("  %-52s %s" % (name, "ok" if ok else "FAILED %s" % (got,)))
            bad += 0 if ok else 1

        # A corpus with no provenance side must SAY SO rather than report a
        # zero delta: an absent column is not a measured agreement.
        p = plant(d, [("01", "q", "r", "REG_GPR0"),
                      ("01", "c", "r", "REG_GPR0")])
        import io
        buf = io.StringIO()
        report("q", p, 0, buf)
        ok = "side p absent" in buf.getvalue()
        print("  %-52s %s" % ("a corpus with no provenance side says so",
                              "ok" if ok else "FAILED"))
        bad += 0 if ok else 1

    print("setjoin comparand selftest: %d of %d arms fired as designed"
          % (len(cases) + 1 - bad, len(cases) + 1))
    return 1 if bad else 0


def ruling_selftest():
    """Prove the ruling join's three verdicts fire on planted data.

    A --require-ruled that has never been seen to FAIL is not a check, and a
    ruling file this cannot prove it reads is the silent-false-success shape.
    """
    import tempfile

    bad = 0
    with tempfile.TemporaryDirectory() as d:
        corpus = os.path.join(d, "gen_q.tsv")
        with open(corpus, "w") as f:
            f.write("#so plugin=aa emulator=bb\n" + SIDES)
            # TWO lost classes, so "one ruled and one not" is expressible
            # without an empty rulings file (which refuses, correctly, for a
            # different reason).
            f.write("q\t01\tq\tr\t1\t1\tREG_GPR0\n")
            f.write("q\t01\tc\tr\t2\t2\tREG_GPR0,REG_FLAGS\n")
            f.write("q\t02\tq\tw\t1\t1\tREG_GPR0\n")
            f.write("q\t02\tc\tw\t2\t2\tREG_GPR0,REG_VEC1\n")

        def run(rows, universe=None):
            rp = os.path.join(d, "r.tsv")
            with open(rp, "w") as f:
                f.write("# planted\n")
                for r in rows:
                    f.write("\t".join(r) + "\n")
            sink = open(os.devnull, "w")
            try:
                st = report("q", corpus, 0, sink, rulings=read_rulings(rp),
                            universe=universe)
                return len(st["unruled"]), len(st["dead"])
            finally:
                sink.close()

        FL = ("q", "REG_FLAGS", "r", "QEMU", "SETTLED", "LLVM-WITH-QEMU", "b")
        V1 = ("q", "REG_VEC1", "w", "REAL", "COVERAGE-PATH", "x", "y")
        cases = [
            ("both classes ruled: neither unruled nor dead", [FL, V1], (0, 0)),
            ("an UNRULED class FIRES", [FL], (1, 0)),
            ("with no universe, an unreached ruling is DEAD",
             [FL, V1, ("q", "REG_VEC9", "w", "REAL", "COVERAGE-PATH",
                       "x", "y")], (0, 1)),
            ("the DIRECTION is part of the key: a w ruling does not cover "
             "an r class",
             [("q", "REG_FLAGS", "w", "QEMU", "SETTLED", "x", "y"), V1],
             (1, 1)),
        ]
        for name, rows, want in cases:
            got = run(rows)
            ok = got == want
            print("  %-58s %s" % (name, "ok" if ok else "FAILED %s" % (got,)))
            bad += 0 if ok else 1

        #
        # The RESERVED/DEAD split, both directions, against a planted
        # vocabulary.  A name the build still has is RESERVED (0 dead); a
        # name it does not have is DEAD (1 dead).  Without both arms the
        # split is an assertion.
        #
        UNREACHED = ("q", "REG_VEC9", "w", "REAL", "COVERAGE-PATH", "x", "y")
        GONE = ("q", "REG_DSPCTRL", "w", "REAL", "COVERAGE-PATH", "x", "y")
        uni = {"REG_FLAGS", "REG_VEC1", "REG_VEC9"}
        for name, rows, want in (
                ("a ruling the build can still spell is RESERVED, not DEAD",
                 [FL, V1, UNREACHED], (0, 0)),
                ("a ruling naming a RETIRED register is DEAD",
                 [FL, V1, GONE], (0, 1))):
            got = run(rows, universe=uni)
            ok = got == want
            print("  %-58s %s" % (name, "ok" if ok else "FAILED %s" % (got,)))
            bad += 0 if ok else 1

        # and the vocabulary reader itself must refuse rather than return a
        # short set that would mark live rulings DEAD
        vp = os.path.join(d, "tiny.h")
        open(vp, "w").write("enum { REG_ZERO = 1, REG_SP = 2 };\n")
        try:
            name_universe(vp)
            print("  %-58s FAILED (returned)"
                  % "a too-small vocabulary REFUSES")
            bad += 1
        except Refusal:
            print("  %-58s ok" % "a too-small vocabulary REFUSES")
        try:
            name_universe(os.path.join(d, "absent.h"))
            print("  %-58s FAILED (returned)"
                  % "an absent vocabulary header REFUSES")
            bad += 1
        except Refusal:
            print("  %-58s ok" % "an absent vocabulary header REFUSES")

        # a rulings file that is not there must REFUSE, not read as empty
        try:
            read_rulings(os.path.join(d, "absent.tsv"))
            print("  %-58s FAILED (returned)" % "an absent rulings file REFUSES")
            bad += 1
        except Refusal:
            print("  %-58s ok" % "an absent rulings file REFUSES")
        # and so must one with no parsable rows
        ep = os.path.join(d, "empty.tsv")
        open(ep, "w").write("# only a comment\n")
        try:
            read_rulings(ep)
            print("  %-58s FAILED (returned)" % "an empty rulings file REFUSES")
            bad += 1
        except Refusal:
            print("  %-58s ok" % "an empty rulings file REFUSES")

    print("setjoin ruling-join selftest: %d of 10 arms fired as designed"
          % (10 - bad))
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
    ap.add_argument("--rulings", default=None,
                    help="the checked-in REAL-LOST arbitrations to join against")
    ap.add_argument("--name-universe", default=None,
                    help="champsim_tracer_generic_ids.h of the build whose "
                         "vocabulary decides RESERVED from DEAD "
                         "(default: this tree's)")
    ap.add_argument("--require-ruled", action="store_true",
                    help="fail unless every surviving REAL-LOST class is "
                         "arbitrated, and unless every arbitration still has "
                         "a class in this corpus")
    args = ap.parse_args()

    if args.selftest:
        return selftest() or prov_selftest() or ruling_selftest()
    if not args.dir or not args.isa:
        print("setjoin: --dir and at least one --isa are required",
              file=sys.stderr)
        return 2

    universe = None
    if args.require_ruled:
        try:
            universe = name_universe(args.name_universe)
        except Refusal as e:
            print("setjoin: REFUSED: %s" % e, file=sys.stderr)
            return 2

    rulings = None
    if args.rulings or args.require_ruled:
        path = args.rulings or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "setjoin_rulings.tsv")
        try:
            rulings = read_rulings(path)
        except Refusal as e:
            print("setjoin: REFUSED: %s" % e, file=sys.stderr)
            return 2

    bad = 0
    stamps = {}
    for isa in args.isa:
        try:
            s = report(isa, os.path.join(args.dir, "gen_%s.tsv" % isa),
                       args.top, sys.stdout, rulings=rulings,
                       universe=universe)
        except Refusal as e:
            print("setjoin: REFUSED: %s" % e, file=sys.stderr)
            bad += 1
            continue
        stamps[isa] = s.get("stamp")
        if args.require_no_loss and s["lost"]:
            print("setjoin: %s: REAL-LOST is %d, required 0"
                  % (isa, sum(s["lost"].values())), file=sys.stderr)
            bad += 1
        if args.require_ruled:
            if s.get("unruled"):
                print("setjoin: %s: %d REAL-LOST classes (%d rows) have no "
                      "arbitration, required 0"
                      % (isa, len(s["unruled"]),
                         sum(n for _, _, n in s["unruled"])), file=sys.stderr)
                bad += 1
            if s.get("dead"):
                print("setjoin: %s: %d arbitrations name a register this "
                      "build cannot spell at all, required 0"
                      % (isa, len(s["dead"])), file=sys.stderr)
                bad += 1

    #
    # The verdict carries its corpus.  A "setjoin: PASS" line pasted into a
    # report without the stamp beside it is the 219-B failure in prose form.
    #
    for isa in args.isa:
        print("setjoin: %s read on corpus %s"
              % (isa, stamps.get(isa) or "<REFUSED, not read>"))
    print("setjoin: %s" % ("FAIL" if bad else "PASS"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
