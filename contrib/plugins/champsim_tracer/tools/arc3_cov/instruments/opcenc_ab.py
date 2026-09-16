#!/usr/bin/env python3
"""THE PER-ENCODING OPCODE-CLASS INSTRUMENT: published GenericOpcode, A vs B,
keyed on the ENCODING and reaching the WRONG PATH.

WHY IT EXISTS.  Nothing in this tree watches `.opcode`.  PASS 45 stated the
consequence in one line -- "no loss instrument can see an opcode-class move"
-- and the three instruments it was talking about say why:

    SETPROOF        scores register SETS per pc
    srcenc_ab       scores published READ LISTS per encoding
    the identity census   counts identity rows and their tiers

Not one of them reads the opcode column.  An arm that reclassifies an
encoding -- GEN_OP_INT_ADD becoming GEN_OP_UNKNOWN, or becoming
GEN_OP_INT_SUB -- passes every standing bar in the tree with nothing
printed anywhere.

THAT GAP IS LOAD-BEARING RIGHT NOW.  6,570 identity rows carry a QEMU-stated
opcode; 86.7% of them are tier STATED, `qemu_ident_classify()` returns
nullptr for STATED, and so those classes are counted and then REFUSED -- they
have no path to the wire.  Admitting them is the next arc step, and it moves
the opcode column on an unknown number of encodings.  Under R19 a
verification that ratchets toward truth has to be able to SEE the movement it
is claiming, per encoding, in both directions.  This is the instrument that
sees it.

THE THREE OUTCOMES, NAMED APART AND NEVER NETTED.

    LOSS   A published a class, B publishes GEN_OP_UNKNOWN.
           The encoding stopped being classified.  This is the R12.1 bar.
    MOVE   A published class X, B publishes a different class Y, both real.
           NOT automatically a defect -- the whole QID_STATED admission is a
           deliberate set of moves -- and NOT automatically fine either.  It
           is a wire change, so it is unadjudicated-fails, ruled-passes.
    GAIN   A published GEN_OP_UNKNOWN, B publishes a class.
           Counted and NAMED, never the bar: it cannot take information off
           the wire.  It is named because a class arriving where none was
           published is still a claim somebody has to be able to check.

Netting any pair of these would read zero for a change that reclassified
half the corpus, which is the failure this file is shaped against.

MATCHED COVERAGE IS A PRECONDITION, NOT A RESULT.  An encoding present in one
arm and not the other is an ERROR (rc=2), not a skipped row: a clean
comparison over a population that shrank is the silent false success this
tree fails at most often.

A PUBLISHED CLASS THAT IS NOT A NAME is an error too.  `GEN_OP_???` is what
generic_opcode_name_or_unknown() returns for an id outside the enum, and an
encoding whose class the plugin cannot spell is a defect to report, never a
row to score.

THE ADJUDICATION LEDGER.  --adjudicated FILE names the exact transition a
maintainer has ruled, one per line with a reason:

    <isa> <encoding-hex> <A_CLASS> <B_CLASS>            # reason  -- PENDING
    LANDED <isa> <encoding-hex> <A_CLASS> <B_CLASS>     # reason  -- LANDED

An adjudicated loss or move is counted, printed and EXCLUDED FROM THE BAR; an
unadjudicated one fails.

THE TWO ROW KINDS DIFFER IN ONE PLACE AND ONE ONLY: whether the row is
required to have a subject.

A PENDING row describes a transition between the two arms of a comparison
that is being run NOW.  It must appear in that measurement; a PENDING line
matching nothing is STALE and fails, because a ledger that outlives its
subject is how a gate quietly stops gating, and because once the change is
the tip the row has to be retired or it silently amnesties a future
regression of the same shape.

A LANDED row describes a transition that IS ALREADY ON THE WIRE at the tip.
It is exempt from the stale rule for a reason that is not convenience: an A/A
comparison at the tip contains none of them, and a cross-tip A/B against an
older arm contains all of them, and BOTH are legitimate runs of this gate.
Without the kind, the twenty transitions #333 admitted and the thirteen the
PREFETCH repair returned had to be re-litigated by hand every time anyone
compared across them, which is how a ruling gets re-decided differently.

A LANDED ROW CANNOT AMNESTY A REGRESSION.  A row names BOTH classes, so
`A -> B` says nothing about `B -> A`; a change that put a landed transition
back the way it was is a different key, is unadjudicated, and fails.

INPUT.  Two corpus files as CST_OPC_ENC_DUMP writes them, one row per
distinct encoding:

    <isa>\t<encoding hex>\t<mnemonic>\t<GEN_OP_NAME>

Rows are merged across wp settings by the capture wrapper; a duplicate
encoding whose class DISAGREES is a CONFLICT and refuses, never a
last-writer-wins.

Run with --selftest for the planted-fire proof, in every direction.

Author: Maccoy Merrell.
"""
import argparse
import os
import sys

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")
UNCLASSIFIED = "GEN_OP_UNKNOWN"
UNSPELLABLE = "GEN_OP_???"


def load(path):
    """(isa, encoding) -> (mnemonic, class).

       A file that carries no rows is a REFUSAL, never an empty agreement; a
       duplicate encoding whose class differs is a CONFLICT; a class the
       plugin could not spell is an ERROR."""
    per, problems, n = {}, [], 0
    if not os.path.exists(path):
        return None, ["MISSING: %s" % path]
    with open(path, errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) < 4:
                continue
            isa, enc, mnem, cls = f[0], f[1].strip().lower(), f[2], f[3].strip()
            if not cls:
                continue
            key = (isa, enc)
            if key in per and per[key][1] != cls:
                problems.append("CONFLICT %s %s: two disagreeing rows (%s vs "
                                "%s)" % (isa, enc, per[key][1], cls))
            if cls == UNSPELLABLE:
                problems.append("UNSPELLABLE %s %s %s: the published class is "
                                "not a name -- an opcode id outside the enum"
                                % (isa, enc, mnem))
            per[key] = (mnem, cls)
            n += 1
    if n == 0:
        return None, ["EMPTY: %s carried no rows" % path]
    return per, problems


def read_ledger(path):
    """({key: reason}, {key: reason}) -- (pending, landed).

    A key is (isa, encoding, a_class, b_class).  Both kinds amnesty the same
    way; only PENDING keys are subject to the stale rule.  See the module
    docstring for why that distinction is not a loophole.
    """
    pending, landed = {}, {}
    if not path:
        return pending, landed
    with open(path, errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            body = line.split("#", 1)
            row = body[0].split()
            if not row:
                continue
            into = pending
            if row[0] == "LANDED":
                into = landed
                row = row[1:]
            elif row[0].upper() == "LANDED":
                sys.exit("FAIL %s:%d: the LANDED keyword is spelled in "
                         "capitals; %r is not it" % (path, n, row[0]))
            if len(row) != 4:
                sys.exit("FAIL %s:%d: want '[LANDED] <isa> <encoding> "
                         "<A_CLASS> <B_CLASS>  # reason'" % (path, n))
            if len(body) < 2 or not body[1].strip():
                sys.exit("FAIL %s:%d: an adjudication with no reason is not "
                         "an adjudication" % (path, n))
            isa, enc, ca, cb = row
            key = (isa, enc.lower(), ca, cb)
            if key in pending or key in landed:
                sys.exit("FAIL %s:%d: this transition is already ruled "
                         "earlier in the file; one row per transition, so "
                         "the reason a reader finds is the reason that "
                         "applies" % (path, n))
            into[key] = body[1].strip()
    return pending, landed


def compare(a_path, b_path, isas, ledgers):
    """Returns (rc, lines, losses, moves, adjudicated, gains).

    @ledgers is (pending, landed) as read_ledger() returns it.  Both amnesty;
    only PENDING rows must have a subject in THIS measurement.
    """
    pending, landed = ledgers
    ledger = {**landed, **pending}
    lines = []
    losses = []          # (isa, enc, mnem, a_cls, b_cls)
    moves = []           # (isa, enc, mnem, a_cls, b_cls)
    gains = []           # (isa, enc, mnem, b_cls)
    adjud = []           # (isa, enc, mnem, a_cls, b_cls, reason, kind)
    used = set()
    rc = 0
    lines.append("=== PUBLISHED OPCODE CLASS, PER ENCODING, ARM A vs ARM B ===")
    lines.append("A = %s" % a_path)
    lines.append("B = %s" % b_path)

    A, ea = load(a_path)
    B, eb = load(b_path)
    for m in ea + eb:
        lines.append("  REFUSED: " + m)
    if A is None or B is None or ea or eb:
        lines.append("VERDICT: REFUSED -- a corpus this gate cannot read is "
                     "not a corpus it may pass.")
        return 2, lines, losses, moves, adjud, gains

    seen_isas = sorted({k[0] for k in A} | {k[0] for k in B})
    for isa in isas:
        ka = {k for k in A if k[0] == isa}
        kb = {k for k in B if k[0] == isa}
        if not ka and not kb:
            lines.append("  %-8s ABSENT from both corpora -- an ISA this gate "
                         "was asked about and cannot see is an ERROR" % isa)
            rc = 2
            continue
        shared = ka & kb
        only_a = ka - kb
        only_b = kb - ka
        lines.append("  %-8s shared=%-7d only_A=%-4d only_B=%-4d"
                     % (isa, len(shared), len(only_a), len(only_b)))
        if only_a or only_b:
            rc = 2
            for k in sorted(only_a)[:8]:
                lines.append("      only in A: %-16s %s" % (k[1], A[k][0]))
            for k in sorted(only_b)[:8]:
                lines.append("      only in B: %-16s %s" % (k[1], B[k][0]))
            lines.append("      COVERAGE ERROR: the two arms do not cover the "
                         "same encodings, so a class comparison over them is "
                         "not readable.")
        for k in sorted(shared):
            ca, cb = A[k][1], B[k][1]
            if ca == cb:
                continue
            if cb == UNCLASSIFIED:
                kind = "LOSS"
            elif ca == UNCLASSIFIED:
                kind = "GAIN"
            else:
                kind = "MOVE"
            lines.append("      %-5s %-16s %-12s %s -> %s"
                         % (kind, k[1][:16], A[k][0][:12], ca, cb))
            if kind == "GAIN":
                gains.append((isa, k[1], A[k][0], cb))
                continue
            lk = (isa, k[1], ca, cb)
            if lk in ledger:
                used.add(lk)
                adjud.append((isa, k[1], A[k][0], ca, cb, ledger[lk], kind))
            elif kind == "LOSS":
                losses.append((isa, k[1], A[k][0], ca, cb))
            else:
                moves.append((isa, k[1], A[k][0], ca, cb))

    for isa in seen_isas:
        if isa not in isas:
            lines.append("  NOTE: %s is in the corpus and was not scored "
                         "(not in --isa)" % isa)

    lines.append("")
    lines.append("ADJUDICATED (counted, excluded from the bar): %d"
                 % len(adjud))
    for isa, enc, mnem, ca, cb, why, kind in adjud:
        lines.append("    %-5s %-8s %-16s %-10s %s -> %s   %s"
                     % (kind, isa, enc, mnem[:10], ca, cb, why))
    # LANDED rows are exempt from the stale rule BY DESIGN: an A/A run at
    # the tip contains none of them and a cross-tip A/B contains all of
    # them, and both are legitimate.  PENDING rows are not exempt, which is
    # what keeps the rule doing its job.
    stale = [k for k in pending if k not in used]
    used_landed = sum(1 for k in landed if k in used)
    if landed:
        lines.append("LANDED ledger rows: %d ruled, %d reached by this "
                     "measurement (a LANDED row needs no subject here -- an "
                     "A/A run at the tip contains none of them)"
                     % (len(landed), used_landed))
    if stale:
        rc = max(rc, 1)
        lines.append("STALE ledger rows (subject not in this measurement): %d"
                     % len(stale))
        for k in sorted(stale):
            lines.append("    %-8s %-16s %s -> %s   %s"
                         % (k[0], k[1], k[2], k[3], ledger[k]))
        lines.append("    A ledger that outlives its subject stops gating.")
    lines.append("GAINS (counted and named, never netted, never the bar): %d"
                 % len(gains))
    for isa, enc, mnem, cb in gains:
        lines.append("    %-8s %-16s %-10s %s -> %s"
                     % (isa, enc, mnem[:10], UNCLASSIFIED, cb))
    lines.append("UNADJUDICATED CLASS LOSSES: %d" % len(losses))
    for isa, enc, mnem, ca, cb in losses:
        lines.append("    %-8s %-16s %-10s %s -> %s"
                     % (isa, enc, mnem[:10], ca, cb))
    lines.append("UNADJUDICATED CLASS MOVES: %d" % len(moves))
    for isa, enc, mnem, ca, cb in moves:
        lines.append("    %-8s %-16s %-10s %s -> %s"
                     % (isa, enc, mnem[:10], ca, cb))
    if losses or moves:
        rc = max(rc, 1)
    if rc == 2:
        lines.append("VERDICT: REFUSED -- the arms could not be compared.")
    elif rc == 1:
        lines.append("VERDICT: FAIL -- %d unadjudicated loss(es), %d "
                     "unadjudicated move(s), %d stale ledger row(s)."
                     % (len(losses), len(moves), len(stale)))
    else:
        lines.append("VERDICT: PASS -- no encoding lost or changed its "
                     "published opcode class unadjudicated.")
    return rc, lines, losses, moves, adjud, gains


# ------------------------------------------------------------------ selftest
def _write_corpus(path, rows):
    with open(path, "w") as fh:
        fh.write("#isa\tencoding\tmnem\topcode\n")
        for isa, enc, mnem, cls in rows:
            fh.write("%s\t%s\t%s\t%s\n" % (isa, enc, mnem, cls))


def selftest():
    import tempfile
    d = tempfile.mkdtemp(prefix="opcenc_ab_selftest.")
    fails, ran = [], []

    def chk(name, cond, why=""):
        ran.append(name)
        print("  %-64s %s%s" % (name, "ok" if cond else "FAIL",
                                "" if cond else "  -- " + why))
        if not cond:
            fails.append(name)

    def arm(tag, rows):
        p = os.path.join(d, tag + ".tsv")
        _write_corpus(p, rows)
        return p

    base = []
    for isa in ISAS:
        base.append((isa, "0106", "addl", "GEN_OP_INT_ADD"))
        base.append((isa, "d9e5", "fxam", "GEN_OP_FP_CMP"))
        base.append((isa, "ffff", "weird", UNCLASSIFIED))

    a = arm("a", base)
    b = arm("b", base)
    rc, L, loss, mv, adj, gn = compare(a, b, ISAS, ({}, {}))
    chk("A identical arms PASS (rc=0; 0 losses, 0 moves, 0 gains)",
        rc == 0 and not loss and not mv and not gn, "\n".join(L))

    # PLANTED FIRE 1 -- a class becomes UNKNOWN.  This is the R12.1 bar and
    # the exact shape a table deletion would produce.
    c = arm("c", [(i, e, m, UNCLASSIFIED if e == "0106" else k)
                  for i, e, m, k in base])
    rc, L, loss, mv, adj, gn = compare(a, c, ISAS, ({}, {}))
    chk("B a class LOST to GEN_OP_UNKNOWN FIRES (rc=1, 4 losses, one per ISA)",
        rc == 1 and len(loss) == 4 and not mv
        and all(x[3] == "GEN_OP_INT_ADD" for x in loss), "\n".join(L))

    # PLANTED FIRE 2 -- a class MOVES.  The QID_STATED admission's own shape.
    e = arm("e", [(i, en, m, "GEN_OP_INT_SUB" if en == "0106" else k)
                  for i, en, m, k in base])
    rc, L, loss, mv, adj, gn = compare(a, e, ISAS, ({}, {}))
    chk("C a class MOVE fires SEPARATELY from a loss (rc=1, 0 losses, 4 moves)",
        rc == 1 and not loss and len(mv) == 4, "\n".join(L))

    # A GAIN is not the bar, and is never confused with a move.
    f = arm("f", [(i, en, m, "GEN_OP_INT_XOR" if en == "ffff" else k)
                  for i, en, m, k in base])
    rc, L, loss, mv, adj, gn = compare(a, f, ISAS, ({}, {}))
    chk("D a GAIN does not fire and is NAMED (rc=0, 4 gains, 0 moves)",
        rc == 0 and not loss and not mv and len(gn) == 4, "\n".join(L))

    # A loss on one encoding and a gain on another: netting reads zero.
    g = arm("g", [(i, en, m,
                   UNCLASSIFIED if en == "0106"
                   else ("GEN_OP_INT_XOR" if en == "ffff" else k))
                  for i, en, m, k in base])
    rc, L, loss, mv, adj, gn = compare(a, g, ISAS, ({}, {}))
    chk("E loss+gain in one arm still FIRES (netting would read zero)",
        rc == 1 and len(loss) == 4 and len(gn) == 4, "\n".join(L))

    led = os.path.join(d, "adj.txt")
    with open(led, "w") as fh:
        for isa in ISAS:
            fh.write("%s 0106 GEN_OP_INT_ADD GEN_OP_INT_SUB  # selftest\n"
                     % isa)
    rc, L, loss, mv, adj, gn = compare(a, e, ISAS, read_ledger(led))
    chk("F an ADJUDICATED move is excluded from the bar (rc=0, adj 4)",
        rc == 0 and not mv and len(adj) == 4, "\n".join(L))

    rc, L, loss, mv, adj, gn = compare(a, c, ISAS, read_ledger(led))
    chk("G a ledger keyed on the WRONG transition does not amnesty a loss",
        rc == 1 and len(loss) == 4, "\n".join(L))

    # --- THE LANDED ROW KIND -------------------------------------------
    # A transition already on the wire is ruled once and re-read on every
    # cross-tip A/B; it must not go stale in an A/A run at the tip, and it
    # must not amnesty the same transition running backwards.
    lled = os.path.join(d, "landed.txt")
    with open(lled, "w") as fh:
        for isa in ISAS:
            fh.write("LANDED %s 0106 GEN_OP_INT_ADD GEN_OP_INT_SUB"
                     "  # selftest, already on the wire\n" % isa)
    rc, L, loss, mv, adj, gn = compare(a, e, ISAS, read_ledger(lled))
    chk("H1 a LANDED row amnesties its transition exactly as PENDING does",
        rc == 0 and not mv and len(adj) == 4, "\n".join(L))
    rc, L, loss, mv, adj, gn = compare(a, b, ISAS, read_ledger(lled))
    chk("H2 a LANDED row with NO subject is NOT stale (A/A at the tip)",
        rc == 0 and not loss and not mv, "\n".join(L))
    # ...and running the same transition BACKWARDS is a different key, so
    # the landed ruling cannot cover a regression of what it ruled.
    eb = arm("eb", [(i, en, m, "GEN_OP_INT_SUB" if en == "0106" else k)
                    for i, en, m, k in base])
    rc, L, loss, mv, adj, gn = compare(eb, a, ISAS, read_ledger(lled))
    chk("H3 a LANDED row does NOT amnesty the same transition reversed",
        rc == 1 and len(mv) == 4, "\n".join(L))
    # A PENDING row with no subject is still stale -- the rule survives.
    rc, L, loss, mv, adj, gn = compare(a, b, ISAS, read_ledger(led))
    chk("H a STALE ledger row FAILS (its subject is not in the measurement)",
        rc == 1 and not loss and not mv, "\n".join(L))

    with open(os.path.join(d, "noreason.txt"), "w") as fh:
        fh.write("x86_64 0106 GEN_OP_INT_ADD GEN_OP_INT_SUB\n")
    lc = os.path.join(d, "lowercase.txt")
    with open(lc, "w") as fh:
        fh.write("landed x86_64 0106 GEN_OP_INT_ADD GEN_OP_INT_SUB  # r\n")
    ok = False
    try:
        read_ledger(lc)
    except SystemExit:
        ok = True
    chk("H4 a lowercase `landed` keyword is REFUSED, never read as an ISA",
        ok)

    try:
        read_ledger(os.path.join(d, "noreason.txt"))
        ok = False
    except SystemExit:
        ok = True
    chk("I an adjudication with no reason is REFUSED", ok)

    h = arm("h", [r for r in base if r[1] != "d9e5"])
    rc, L, loss, mv, adj, gn = compare(a, h, ISAS, ({}, {}))
    chk("J unmatched encoding coverage is an ERROR (rc=2)", rc == 2,
        "\n".join(L))

    p = os.path.join(d, "empty.tsv")
    open(p, "w").write("#isa\tencoding\tmnem\topcode\n")
    rc, L, loss, mv, adj, gn = compare(a, p, ISAS, ({}, {}))
    chk("K an EMPTY corpus REFUSES rather than passing vacuously", rc == 2,
        "\n".join(L))

    rc, L, loss, mv, adj, gn = compare(a, os.path.join(d, "nope.tsv"),
                                       ISAS, ({}, {}))
    chk("L a MISSING corpus REFUSES rather than passing vacuously", rc == 2,
        "\n".join(L))

    q = os.path.join(d, "conflict.tsv")
    _write_corpus(q, base + [("x86_64", "0106", "addl", "GEN_OP_INT_SUB")])
    rc, L, loss, mv, adj, gn = compare(a, q, ISAS, ({}, {}))
    chk("M a CONFLICTING duplicate encoding REFUSES (rc=2)", rc == 2,
        "\n".join(L))

    r = os.path.join(d, "unspell.tsv")
    _write_corpus(r, base + [("x86_64", "ab12", "?", UNSPELLABLE)])
    rc, L, loss, mv, adj, gn = compare(a, r, ISAS, ({}, {}))
    chk("N a class the plugin could not SPELL is an ERROR, not a row (rc=2)",
        rc == 2, "\n".join(L))

    s = arm("s", [x for x in base if x[0] != "aarch64"])
    rc, L, loss, mv, adj, gn = compare(s, s, ISAS, ({}, {}))
    chk("O an ISA absent from BOTH arms is an ERROR, not a silent zero",
        rc == 2, "\n".join(L))

    print("\nopcenc_ab.py selftest: %d check(s), %d failure(s)"
          % (len(ran), len(fails)))
    return 1 if fails else 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("a", nargs="?", help="arm A corpus.tsv (the BEFORE arm)")
    ap.add_argument("b", nargs="?", help="arm B corpus.tsv (the AFTER arm)")
    ap.add_argument("--isa", action="append", default=None)
    ap.add_argument("--adjudicated", default=None)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)
    if args.selftest:
        return selftest()
    if not (args.a and args.b):
        ap.error("two corpus files are required")
    rc, lines, _, _, _, _ = compare(args.a, args.b, tuple(args.isa or ISAS),
                                    read_ledger(args.adjudicated))
    print("\n".join(lines))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
