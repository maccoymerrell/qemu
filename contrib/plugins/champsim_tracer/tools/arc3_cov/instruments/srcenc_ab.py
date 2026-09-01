#!/usr/bin/env python3
"""THE PER-ENCODING SOURCE-LOSS INSTRUMENT: published source sets, A vs B,
keyed on the ENCODING and reaching the WRONG PATH.

WHY IT EXISTS, and the blindness it is here to cover.

`srcset_ab.py` beside it asks the same question keyed on the PROGRAM COUNTER,
and it is the tree's standing source-loss bar.  It cannot see the wrong path,
and neither can any other source instrument here: the census, SETPROOF, the
witness arms and `srcset_ab` itself are all taken at wp=0, because their
subject is a pc set and the correct-path pc set is the one that repeats.

That is not a small gap.  Measured (PASS 44): with the Capstone operand walk's
read arm deleted, `srcset_ab` read UNADJUDICATED LOSSES 0 over 32,612 matched
pcs on all four ISAs, and TWENTY encodings were losing a published register at
the same tip -- x86 `fxam`, `fstp`, `fstpt` x2 and `fucomi` losing REG_FPR0,
`idivl` losing REG_GPR0 and REG_GPR2, and fourteen aarch64 SVE `ld1b` / `st1b`
encodings losing their governing predicate or their store-data vector.  All
twenty read `wp0 = 0, wp16 = 1`: reached ONLY on the wrong path, on both arms.
A bar every one of whose instruments is wp=0 by construction is a bar with a
carve-out nobody wrote down, and the wrong path is not a carve-out for source
lists -- WP is identical to CP except for three named carve-outs, and this is
not one of them.

SO THE KEY IS THE ENCODING, NOT THE PC.  A wrong-path instruction has no
stable program counter to compare across arms: it is reached by a redirected
PC on a speculative excursion, and #327's environment-length effect moves it
again.  The ENCODING BYTES are stable -- the same bytes decode to the same
instruction on both arms -- so this instrument keys on them, which is also why
it can be read at wp=0 and wp=16 together and merged.

    a register published for an encoding in arm A and absent for that same
    encoding in arm B, with no written adjudication.  MUST BE 0.

WHAT IT IS NOT.  Not a total, not a rate, and not netted: a register lost on
one encoding and gained on another is a LOSS on the first, and reporting the
difference would read zero for a change that moved a register somewhere it does
not belong.  Losses and gains are counted apart and only losses are the bar.

MATCHED COVERAGE IS A PRECONDITION, NOT A RESULT.  An encoding present in one
arm and not the other is an ERROR here, not a skipped row.  A `DISAGREE = 0`
read over an encoding set that shrank is exactly the silent false success this
file is shaped against, and the deletion arm really does reach encodings the
tip arm does not (PASS 44 measured only_B = 3 on x86_64), so this is a live
condition and not a hypothetical one.

THE ADJUDICATION LEDGER.  --adjudicated FILE names (isa, encoding, register)
triples a maintainer has ruled may leave the wire, one per line with a reason:

    <isa> <encoding-hex> <REG_NAME>   # reason

An adjudicated loss is counted, printed and EXCLUDED FROM THE BAR; an
unadjudicated one fails the gate.  A ledger line matching nothing in this
measurement is reported as STALE and fails too, because a ledger that outlives
its subject is how a gate quietly stops gating.

INPUT.  Two corpus files as CST_SRC_ENC_DUMP writes them, one row per distinct
encoding:

    <isa>\t<encoding hex>\t<mnemonic>\t<REG,REG,...>

Rows are merged across wp settings by the capture wrapper; a duplicate
encoding whose register set DISAGREES is a CONFLICT and refuses, never a
last-writer-wins.

Run with --selftest for the planted-fire proof, both directions.

Author: Maccoy Merrell.
"""
import argparse
import os
import sys

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")


def load(path):
    """(isa, encoding) -> (mnemonic, frozenset(registers)).

       A file that carries no rows is a REFUSAL, never an empty agreement, and
       a duplicate encoding whose register set differs is a CONFLICT."""
    per, conflicts, n = {}, [], 0
    if not os.path.exists(path):
        return None, ["MISSING: %s" % path]
    with open(path, errors="replace") as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) < 3:
                continue
            isa, enc, mnem = f[0], f[1].strip().lower(), f[2]
            src = f[3] if len(f) > 3 else ""
            regs = frozenset(r for r in src.replace(" ", "").split(",") if r)
            key = (isa, enc)
            if key in per and per[key][1] != regs:
                conflicts.append("CONFLICT %s %s: two disagreeing rows"
                                 % (isa, enc))
            per[key] = (mnem, regs)
            n += 1
    if n == 0:
        return None, ["EMPTY: %s carried no rows" % path]
    return per, conflicts


def read_ledger(path):
    """{(isa, encoding, reg): reason}.  A row with no reason is refused."""
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
                sys.exit("FAIL %s:%d: want '<isa> <encoding> <REG>  # reason'"
                         % (path, n))
            if len(body) < 2 or not body[1].strip():
                sys.exit("FAIL %s:%d: an adjudication with no reason is not "
                         "an adjudication" % (path, n))
            isa, enc, reg = row
            out[(isa, enc.lower(), reg)] = body[1].strip()
    return out


def compare(a_path, b_path, isas, ledger):
    """Returns (rc, report_lines, losses, adjudicated, gains)."""
    lines = []
    losses = []          # (isa, enc, mnem, reg)
    adjud = []           # (isa, enc, mnem, reg, reason)
    gains = 0
    used = set()
    rc = 0
    lines.append("=== PUBLISHED SOURCE SETS, PER ENCODING, ARM A vs ARM B ===")
    lines.append("A = %s" % a_path)
    lines.append("B = %s" % b_path)

    A, ea = load(a_path)
    B, eb = load(b_path)
    for m in ea + eb:
        lines.append("  REFUSED: " + m)
    if A is None or B is None or ea or eb:
        lines.append("VERDICT: REFUSED -- a corpus this gate cannot read is "
                     "not a corpus it may pass.")
        return 2, lines, losses, adjud, gains

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
            # #327 doctrine: unmatched coverage makes every number below
            # unreadable.  It is an ERROR, and the encodings are NAMED so the
            # reader can see which population moved.
            rc = 2
            for k in sorted(only_a)[:8]:
                lines.append("      only in A: %-16s %s" % (k[1], A[k][0]))
            for k in sorted(only_b)[:8]:
                lines.append("      only in B: %-16s %s" % (k[1], B[k][0]))
            lines.append("      COVERAGE ERROR: the two arms do not cover the "
                         "same encodings, so a DISAGREE count over them is "
                         "not readable.")
        for k in sorted(shared):
            lost = sorted(A[k][1] - B[k][1])
            got = sorted(B[k][1] - A[k][1])
            gains += len(got)
            if not lost and not got:
                continue
            lines.append("      %-16s %-10s LOST=%s GAINED=%s"
                         % (k[1][:16], A[k][0], ",".join(lost) or "-",
                            ",".join(got) or "-"))
            for reg in lost:
                lk = (isa, k[1], reg)
                if lk in ledger:
                    used.add(lk)
                    adjud.append((isa, k[1], A[k][0], reg, ledger[lk]))
                else:
                    losses.append((isa, k[1], A[k][0], reg))

    for isa in seen_isas:
        if isa not in isas:
            lines.append("  NOTE: %s is in the corpus and was not scored "
                         "(not in --isa)" % isa)

    lines.append("")
    lines.append("ADJUDICATED losses (counted, excluded from the bar): %d"
                 % len(adjud))
    for isa, enc, mnem, reg, why in adjud:
        lines.append("    %-8s %-16s %-10s %-12s  %s"
                     % (isa, enc, mnem, reg, why))
    stale = [k for k in ledger if k not in used]
    if stale:
        rc = max(rc, 1)
        lines.append("STALE ledger rows (subject not in this measurement): %d"
                     % len(stale))
        for k in sorted(stale):
            lines.append("    %-8s %-16s %-12s  %s"
                         % (k[0], k[1], k[2], ledger[k]))
        lines.append("    A ledger that outlives its subject stops gating.")
    lines.append("GAINS (counted, never netted against losses): %d" % gains)
    lines.append("UNADJUDICATED LOSSES: %d" % len(losses))
    for isa, enc, mnem, reg in losses:
        lines.append("    %-8s %-16s %-10s %s" % (isa, enc, mnem, reg))
    if losses:
        rc = max(rc, 1)
    if rc == 2:
        lines.append("VERDICT: REFUSED -- the arms could not be compared.")
    elif rc == 1:
        lines.append("VERDICT: FAIL -- %d unadjudicated loss(es), %d stale "
                     "ledger row(s)." % (len(losses), len(stale)))
    else:
        lines.append("VERDICT: PASS -- no encoding lost a published source.")
    return rc, lines, losses, adjud, gains


# ------------------------------------------------------------------ selftest
def _write_corpus(path, rows):
    with open(path, "w") as fh:
        fh.write("#isa\tencoding\tmnem\tsrc\n")
        for isa, enc, mnem, regs in rows:
            fh.write("%s\t%s\t%s\t%s\n" % (isa, enc, mnem, ",".join(regs)))


def selftest():
    import tempfile
    d = tempfile.mkdtemp(prefix="srcenc_ab_selftest.")
    fails, ran = [], []

    def chk(name, cond, why=""):
        ran.append(name)
        print("  %-62s %s%s" % (name, "ok" if cond else "FAIL",
                                "" if cond else "  -- " + why))
        if not cond:
            fails.append(name)

    def arm(tag, rows):
        p = os.path.join(d, tag + ".tsv")
        _write_corpus(p, rows)
        return p

    base = []
    for isa in ISAS:
        base.append((isa, "d9e5", "fxam", ["REG_FCSR", "REG_FPR0"]))
        base.append((isa, "f7fe", "idivl", ["REG_GPR4", "REG_GPR0"]))

    a = arm("a", base)
    b = arm("b", base)
    rc, lines, loss, adj, gains = compare(a, b, ISAS, {})
    chk("A identical arms PASS (rc=0, losses 0, gains 0)",
        rc == 0 and not loss and gains == 0, "\n".join(lines))

    # PLANTED FIRE, DIRECTION 1: a register disappears from an encoding.
    # This is the exact shape PASS 44 measured on the wrong path.
    c = arm("c", [(i, e, m, [r for r in g if r != "REG_FPR0"])
                  for i, e, m, g in base])
    rc, lines, loss, adj, gains = compare(a, c, ISAS, {})
    chk("B a REMOVED register FIRES (rc=1, 4 losses -- one per ISA)",
        rc == 1 and len(loss) == 4
        and all(x[3] == "REG_FPR0" for x in loss), "\n".join(lines))

    # PLANTED FIRE, DIRECTION 2: a register appears.  A GAIN is not the bar,
    # and this arm proves the instrument does not confuse the two.
    e = arm("e", [(i, en, m, list(g) + ["REG_PC"]) for i, en, m, g in base])
    rc, lines, loss, adj, gains = compare(a, e, ISAS, {})
    chk("C a GAINED register does NOT fire, and is counted (rc=0, gains 8)",
        rc == 0 and not loss and gains == 8, "\n".join(lines))

    # A loss AND a gain on the same encoding: netting would report zero.
    f = arm("f", [(i, en, m, [r for r in g if r != "REG_FPR0"] + ["REG_PC"])
                  for i, en, m, g in base])
    rc, lines, loss, adj, gains = compare(a, f, ISAS, {})
    chk("D loss+gain on one encoding still FIRES (netting would read zero)",
        rc == 1 and len(loss) == 4 and gains == 8, "\n".join(lines))

    led = os.path.join(d, "adj.txt")
    with open(led, "w") as fh:
        for isa in ISAS:
            fh.write("%s d9e5 REG_FPR0  # selftest: ruled removable\n" % isa)
    rc, lines, loss, adj, gains = compare(a, c, ISAS, read_ledger(led))
    chk("E an ADJUDICATED loss is excluded from the bar (rc=0, adj 4)",
        rc == 0 and not loss and len(adj) == 4, "\n".join(lines))

    rc, lines, loss, adj, gains = compare(a, b, ISAS, read_ledger(led))
    chk("F a STALE ledger row FAILS (its subject is not in the measurement)",
        rc == 1 and not loss, "\n".join(lines))

    with open(os.path.join(d, "noreason.txt"), "w") as fh:
        fh.write("x86_64 d9e5 REG_FPR0\n")
    try:
        read_ledger(os.path.join(d, "noreason.txt"))
        ok = False
    except SystemExit:
        ok = True
    chk("G an adjudication with no reason is REFUSED", ok)

    # UNMATCHED COVERAGE is an error, not a skipped row -- and it outranks a
    # clean DISAGREE, because the DISAGREE is not readable over it.
    g = arm("g", [r for r in base if r[1] != "f7fe"])
    rc, lines, loss, adj, gains = compare(a, g, ISAS, {})
    chk("H unmatched encoding coverage is an ERROR (rc=2)", rc == 2,
        "\n".join(lines))

    h = os.path.join(d, "empty.tsv")
    open(h, "w").write("#isa\tencoding\tmnem\tsrc\n")
    rc, lines, loss, adj, gains = compare(a, h, ISAS, {})
    chk("I an EMPTY corpus REFUSES rather than passing vacuously", rc == 2,
        "\n".join(lines))

    rc, lines, loss, adj, gains = compare(a, os.path.join(d, "nope.tsv"),
                                          ISAS, {})
    chk("J a MISSING corpus REFUSES rather than passing vacuously", rc == 2,
        "\n".join(lines))

    # A CONFLICTING duplicate row is a refusal, never a last-writer-wins.
    k = os.path.join(d, "conflict.tsv")
    _write_corpus(k, base + [("x86_64", "d9e5", "fxam", ["REG_FCSR"])])
    rc, lines, loss, adj, gains = compare(a, k, ISAS, {})
    chk("K a CONFLICTING duplicate encoding REFUSES (rc=2)", rc == 2,
        "\n".join(lines))

    # An ISA the caller asked about that no corpus carries is an ERROR, not a
    # silent zero.  This is the arm that would have caught a capture whose
    # aarch64 run produced nothing.
    m = arm("m", [r for r in base if r[0] != "aarch64"])
    rc, lines, loss, adj, gains = compare(m, m, ISAS, {})
    chk("L an ISA absent from BOTH arms is an ERROR, not a silent zero",
        rc == 2, "\n".join(lines))

    print("\nsrcenc_ab.py selftest: %d check(s), %d failure(s)"
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
    rc, lines, _, _, _ = compare(args.a, args.b, tuple(args.isa or ISAS),
                                 read_ledger(args.adjudicated))
    print("\n".join(lines))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
