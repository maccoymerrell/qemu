#!/usr/bin/env python3
"""SCORE aarch64 IDENT CORPORA AGAINST THE DECODE-ROW CENSUS.

The census (`a64_row_census.py`) says which decode rows a user-mode aarch64
trace CAN reach.  This scores which of them any corpus actually DID reach, and
it is written to make three different ways of being wrong visible instead of
averaging them into a percentage.

  EXERCISED        a reachable-candidate row some corpus witnessed.
  UNEXERCISED      a reachable-candidate row no corpus witnessed.  This is the
                   gap the corpus generator has to close, and it is printed by
                   name, never as a count alone -- a count cannot be worked on.
  IMPOSSIBLE-HIT   a row the census called aarch32-only or a filter, witnessed
                   anyway.  That is not a coverage result, it REFUTES the
                   census's own classification, and it FAILS.

THE CORPUS AND THE CENSUS MUST DESCRIBE ONE DECODER.  A corpus carries the
emulator build-id that produced it.  Scoring a corpus whose decoder states
rules this census has never heard of is a cross-build join, and it is refused:
an unknown rule is indistinguishable, in the arithmetic, from a row nobody
reached.  A corpus from a DIFFERENT build whose rule set is a subset of the
census's is accepted and REPORTED AS SUCH, because the decode-row question is
answered by the decoder's pattern set and that set is allowed to be proven
equal across two builds -- but the reader is told, every run, which build the
numbers came from.

A ZERO IS NOT A PASS.  An empty corpus, a corpus with no rule column, and a
census with no reachable rows each REFUSE, because a coverage figure computed
over nothing reads exactly like complete coverage.

Author: Maccoy Merrell.

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import os
import sys


#: Not a decoder's rule.  The capture writes this when the bytes reached no
#: pattern at all, so it is a legitimate corpus row and must not be counted as
#: a name the census failed to know -- that reading would make every corpus
#: containing one undecodable word look like a cross-build join.
SYNTHETIC = {"#undecoded"}


class Refusal(Exception):
    pass


def read_census(path):
    """(rows, {rule: class}) from a64_row_census.py's output."""
    if not os.path.exists(path):
        raise Refusal("%s: no census.  Coverage has no denominator without "
                      "one, and a percentage over an absent denominator is "
                      "the silent false success this tool exists to refuse"
                      % path)
    klass = {}
    stamp = None
    for line in open(path, "r", errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("#emulator "):
            stamp = line.split(None, 1)[1].strip()
            continue
        if line.startswith("#"):
            continue
        p = line.split("\t")
        if len(p) < 2:
            continue
        klass[p[0]] = p[1]
    if not stamp:
        raise Refusal("%s: no #emulator stamp; the census cannot be shown to "
                      "describe any particular decoder" % path)
    if not klass:
        raise Refusal("%s: no census rows" % path)
    if not any(v == "reachable-candidate" for v in klass.values()):
        raise Refusal("%s: the census names no reachable row at all.  Every "
                      "corpus would then score 0 of 0, which prints as 100%%"
                      % path)
    return stamp, klass


def read_corpus(path):
    """(emulator stamp or None, {rule: hits}) from a CST_QEMU_IDENT_PAIRS TSV."""
    if not os.path.exists(path):
        raise Refusal("%s: no corpus" % path)
    stamp = None
    hits = {}
    cols = None
    for line in open(path, "r", errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("#so "):
            for tok in line.split():
                if tok.startswith("emulator="):
                    stamp = tok.split("=", 1)[1]
            continue
        if line.startswith("#isa\t"):
            cols = line[1:].split("\t")
            continue
        if line.startswith("#"):
            continue
        p = line.split("\t")
        if cols is None or "rule" not in cols:
            continue
        i = cols.index("rule")
        if len(p) <= i:
            continue
        r = p[i]
        if r and r != "-":
            hits[r] = hits.get(r, 0) + 1
    if cols is None or "rule" not in (cols or []):
        raise Refusal("%s: no '#isa ... rule ...' header.  A corpus whose rule "
                      "column this reader cannot find would score every row "
                      "unexercised, which is a tooling failure printed as a "
                      "coverage result" % path)
    if not hits:
        raise Refusal("%s: carries no rule row at all -- REFUSING rather than "
                      "reporting 0%% coverage of a corpus that measured "
                      "nothing" % path)
    return stamp, hits


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--census", required=True)
    ap.add_argument("--corpus", action="append", required=True,
                    help="a CST_QEMU_IDENT_PAIRS TSV; repeat to union several")
    ap.add_argument("--list-unexercised", default=None,
                    help="write every unexercised reachable row here, by name")
    a = ap.parse_args()

    try:
        cstamp, klass = read_census(a.census)
        allhits = {}
        sources = []
        for c in a.corpus:
            estamp, hits = read_corpus(c)
            sources.append((c, estamp, len(hits)))
            for r, n in hits.items():
                allhits[r] = allhits.get(r, 0) + n
    except Refusal as e:
        print("a64_row_score: REFUSED: %s" % e, file=sys.stderr)
        return 1

    unknown = sorted(r for r in allhits
                     if r not in klass and r not in SYNTHETIC)
    synth = sorted(r for r in allhits if r in SYNTHETIC)
    reach = sorted(r for r, k in klass.items() if k == "reachable-candidate")
    exercised = [r for r in reach if r in allhits]
    unexercised = [r for r in reach if r not in allhits]
    impossible = sorted(r for r in allhits
                        if klass.get(r) in ("aarch32-only",
                                            "fa64-streaming-filter"))

    print("census        %s  (emulator %s)" % (a.census, cstamp))
    for c, e, n in sources:
        print("corpus        %s  (emulator %s, %d distinct rules)"
              % (c, e or "UNSTAMPED", n))
    same = all(e == cstamp for _c, e, _n in sources)
    print("build join    %s" % ("SAME BUILD as the census" if same else
                                "DIFFERENT build from the census -- the rule "
                                "sets are compared below, and only a SUBSET "
                                "reading is sound"))
    print("")
    print("reachable rows (denominator)      %d" % len(reach))
    print("  exercised                       %d" % len(exercised))
    print("  unexercised                     %d" % len(unexercised))
    if reach:
        print("  coverage                        %.2f%%"
              % (100.0 * len(exercised) / len(reach)))
    print("distinct rules seen in corpora    %d" % len(allhits))
    print("synthetic rows seen (bytes that reached no rule): %s"
          % (" ".join(synth) if synth else "none"))
    print("rules seen that the census does not know: %d" % len(unknown))
    for r in unknown[:20]:
        print("    UNKNOWN %s" % r)
    print("rows the census called unreachable and a corpus hit: %d"
          % len(impossible))
    for r in impossible[:20]:
        print("    IMPOSSIBLE-HIT %s (census class %s)" % (r, klass[r]))

    if a.list_unexercised:
        with open(a.list_unexercised, "w") as f:
            f.write("#unexercised reachable aarch64 decode rows\n")
            f.write("#census %s\n" % os.path.abspath(a.census))
            for c, e, _n in sources:
                f.write("#corpus %s emulator=%s\n" % (os.path.abspath(c), e))
            for r in unexercised:
                f.write("%s\n" % r)
        print("unexercised rows written to %s" % a.list_unexercised)

    # An UNKNOWN rule means the corpus's decoder is not the census's; an
    # IMPOSSIBLE-HIT means the census's own reachability claim is false.
    # Either way the percentage above describes nothing, and saying so is the
    # whole point of printing it.
    bad = len(unknown) + len(impossible)
    print("\nVERDICT: %s" % ("SOUND" if bad == 0 else
                             "UNSOUND -- %d unknown + %d impossible-hit rows; "
                             "the coverage figure above must not be quoted"
                             % (len(unknown), len(impossible))))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
