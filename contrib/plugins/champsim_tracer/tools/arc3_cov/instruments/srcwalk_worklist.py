#!/usr/bin/env python3
"""THE OPERAND WALK'S PRICE, DECOMPOSED AND ADJUDICATED.

WHY IT EXISTS.  `srcenc_ab.py` beside it measures, per ENCODING, the source
registers the wire would stop publishing if the Capstone operand walk were
deleted.  Run at exec171 that instrument returned a single number per ISA --
540,798 encodings move, B_GAINED 0 on all four -- and a single verdict:
LOAD-BEARING, the deletion may not land.  A number that large is not a work
item.  It says the deletion is blocked; it does not say WHAT is blocked, and
it cannot be worked down.

This file turns that number into a WORKLIST.  It keys the same measurement on
(ISA, register, mnemonic), joins every losing pair to an adjudication table,
and rolls the population up by DISPOSITION.  The split the table exists to
make is one question asked per class:

    does the ENCODING NAME the register?

If it does, the loss is REAL and the remedy is a QEMU-side STATEMENT -- R7.3,
R15 and R16 are unanimous that QEMU's lowering eliding a register the encoding
names is never grounds to drop it from the wire.  If it does not, the walk was
publishing a register the instruction does not read, the wire is RIGHT to drop
it, and the class is a Capstone SUPERSET that costs nothing to lose.

THE DISPOSITIONS, and what each one asserts:

    REAL-OPERAND    the encoding names the register as an ordinary operand and
                    QEMU simply does not state that read.  A statement, at
                    QEMU's decoder.  Owes R13.
    REAL-VOCAB-GAP  the encoding names it, QEMU reads it, and the tracer has
                    no declared regfile row to name it WITH.  The remedy is a
                    second row source -- the riscv csr_ops / a64 declare_regfile
                    / mipsel MSA-ENC precedent (#332).
    REAL-QEMU-ELIDES QEMU's chosen lowering drops a register the encoding
                    names.  R15 verbatim: the absence of a register from
                    QEMU's lowering is NEVER grounds to remove it.
    SUPERSET        the encoding does NOT name the register, or a standing
                    ruling says the read does not exist.  The walk over-named
                    it; losing it is a CORRECTION, not a loss.  Needs the
                    ruling AND a whole-population arm, not plausibility.
    OPEN            no verdict yet.  Carries the QUESTION and the method that
                    would answer it.  An OPEN row with no question is a
                    refusal wearing a row's clothes.

TRAP-STATE IS MEASURED, NOT ASSERTED.  `--trapstate <isa>=<file>` takes
`trapstate_probe.py`'s per-encoding verdict table and decides that disposition
from QEMU's own ops rather than from a row in the table: every losing register
on an encoding the probe read TRAP-ONLY is credited to the built-in class
`trapstate-measured` under D17, and the table is never consulted for it.  Three
reasons it is built in rather than written as rows:

  * the split is PER ENCODING and the table's key is (isa, mnemonic,
    register).  exec177 already met a mnemonic whose encodings split across
    trap and execute (`append`) and had to carve it by hand; a signature-keyed
    row cannot express the split at all, so a hand-written TRAP-STATE row is
    always an approximation of a measurement that exists.
  * a row asserts; the probe measures, at the same cpu model and privilege the
    corpus was swept at, with two controls that REFUSE the whole run if they do
    not fire.
  * and it cannot go stale silently: an ISA given a trapstate map whose table
    does not cover every losing encoding of that ISA is a REFUSAL, because a
    filter that quietly scores the rows it happens to know is the silent false
    success this file is shaped against.

NO-OPS IS NOT A TRAP and is deliberately NOT credited: R16 is explicit that "a
NOP semantic still has real dependencies", so a NO-OPS encoding goes to the
table like any executing one.

HOW IT REFUSES, in all three directions, because a join that cannot refuse is
a join that reports whatever it was given:

  * a losing (isa, mnem, reg) that NO row claims       -> UNCLAIMED, rc=1
  * a losing pair that TWO rows claim                  -> AMBIGUOUS,  rc=1
  * a table row that claims NOTHING in the measurement -> STALE,      rc=1

The third is the one that matters over time: a row that outlives its subject
is how a worklist quietly stops being a worklist.  It is the same discipline
`barledger.py` applies to BAR_CLASSES.tsv, for the same reason.

AND IT REFUSES AN EMPTY MEASUREMENT.  A corpus pair that produces no losing
rows at all is a REFUSAL, never a clean bill: the arms may simply not have
been built, and "0 losses" from an instrument that never found its subject is
the silent false success this tree has been burned by repeatedly.

INPUT.  The two `--srcenc` corpora `srcenc_sweep.sh` writes, arm A (tip
behaviour) and arm B (the walk deleted), one row per distinct encoding:

    <isa>\t<encoding hex>\t<mnemonic>\t<REG,REG,...>

`-` is the corpus's spelling of "no sources" and is NOT a register name.

Run with --selftest for the planted-fire proof in every refusal direction.

Author: Maccoy Merrell.
"""
import argparse
import collections
import os
import re
import struct
import sys

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")

#: the dispositions that assert the register must STAY on the wire
REAL = ("REAL-OPERAND", "REAL-VOCAB-GAP", "REAL-QEMU-ELIDES")
#: the disposition that asserts the wire is right to drop it
DROP = ("SUPERSET",)
#: the disposition that says the QUESTION DOES NOT ARISE IN THIS CORPUS --
#: the machine did not execute the encoding's datapath in the state the sweep
#: ran in, so the walk's operand names are not what was read and the register
#: is neither a REAL loss nor a proven over-name.  It is a CORPUS-STATE fact.
STATE = ("TRAP-STATE",)
#: no verdict
UNDECIDED = ("OPEN",)
DISPOSITIONS = REAL + DROP + STATE + UNDECIDED


def load_corpus(path):
    """(isa, encoding) -> (mnemonic, frozenset(registers)), or (None, errors)."""
    per, errs, n = {}, [], 0
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
            regs = frozenset(r for r in src.replace(" ", "").split(",")
                             if r and r != "-")
            key = (isa, enc)
            if key in per and per[key][1] != regs:
                errs.append("CONFLICT %s %s: two disagreeing rows" % (isa, enc))
            per[key] = (mnem, regs)
            n += 1
    if n == 0:
        return None, ["EMPTY: %s carried no rows" % path]
    return per, errs


def load_table(path):
    """The adjudication rows, in file order.  A row missing any of the three
       load-bearing fields -- disposition, citation, note -- is REFUSED here
       rather than being allowed to stand as an unexplained verdict."""
    rows, errs = [], []
    if not os.path.exists(path):
        return None, ["MISSING TABLE: %s" % path]
    with open(path, errors="replace") as fh:
        for ln, line in enumerate(fh, 1):
            if line.startswith("#") or not line.strip():
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) != 7:
                errs.append("TABLE LINE %d: want 7 fields, got %d" % (ln, len(f)))
                continue
            cid, isa, mnem_rx, reg_rx, disp, cite, note = f
            if disp not in DISPOSITIONS:
                errs.append("TABLE LINE %d (%s): unknown disposition %r"
                            % (ln, cid, disp))
                continue
            if not cite.strip() or not note.strip():
                errs.append("TABLE LINE %d (%s): a verdict with no citation or "
                            "no note is not a row" % (ln, cid))
                continue
            if disp in STATE and "trapstate" not in note.lower():
                errs.append("TABLE LINE %d (%s): a TRAP-STATE row asserts what "
                            "QEMU's own ops did, so its note must name the "
                            "trapstate_probe evidence" % (ln, cid))
                continue
            if disp in UNDECIDED and "?" not in note:
                errs.append("TABLE LINE %d (%s): an OPEN row must carry the "
                            "QUESTION it is open on" % (ln, cid))
                continue
            try:
                rows.append(dict(cid=cid, isa=isa, mnem=re.compile(mnem_rx),
                                 reg=re.compile(reg_rx), disp=disp,
                                 cite=cite, note=note, hits=0, encs=0))
            except re.error as e:
                errs.append("TABLE LINE %d (%s): bad regex: %s" % (ln, cid, e))
    if not rows:
        errs.append("EMPTY TABLE: %s claimed nothing" % path)
    return rows, errs


def load_trapstate(spec):
    """`isa=file` -> {(isa, encoding): verdict}, merged over every --trapstate.

       The verdict table is `trapstate_probe.py`'s own output and is keyed on
       the corpus's hex spelling, which is why that probe was changed to keep
       that spelling end to end: a %08x round trip re-orders the bytes and the
       join then matches nothing and reads MISSING -- silently, and in the
       direction that scores every trap as REAL."""
    out, errs = {}, []
    for one in spec:
        if "=" not in one:
            errs.append("TRAPSTATE %r: want <isa>=<file>" % one)
            continue
        isa, path = one.split("=", 1)
        if not os.path.exists(path):
            errs.append("MISSING TRAPSTATE TABLE: %s" % path)
            continue
        n = 0
        with open(path, errors="replace") as fh:
            for line in fh:
                if line.startswith("#"):
                    continue
                f = line.split()
                if len(f) >= 2:
                    out[(isa, f[0].strip().lower())] = f[1].strip()
                    n += 1
        if n == 0:
            errs.append("EMPTY TRAPSTATE TABLE: %s" % path)
    return out, errs


def losses(a, b, isa):
    """Per encoding, the registers arm A published and arm B does not.

       Counted apart from gains and never netted: a register lost on one
       encoding and gained on another is a LOSS on the first."""
    out = []
    for (i, enc), (mnem, ra) in a.items():
        if i != isa:
            continue
        rb = b.get((i, enc), (None, frozenset()))[1]
        lost = ra - rb
        if lost:
            out.append((enc, mnem, lost))
    return out


def encfield(a, b, isa, mnem_re, lo, hi):
    """Histogram an ENCODING BIT-FIELD over the LOSING encodings of a family.

       THE THIRD QUESTION.  exec177 asked "does the encoding NAME the
       register" and answered with a disassembler.  exec181 asked "did the
       datapath RUN" and answered with QEMU's ops.  Both can say yes while
       the register is still not read, because a fixed-width ISA's own
       definition can make a NAMED operand of an EXECUTING instruction
       contribute nothing:

           extr Xd,Xn,Xm,#0   ->  concat(Xn:Xm)<63:0> == Xm.  Rn is named,
                                  the instruction runs, and Rn supplies zero
                                  bits.  QEMU lowers it to `ext32u_i64 x0,x1`
                                  -- one source -- and QEMU is right.

       A ruling of that shape is only as good as its arm, and an arm that
       reads four examples is an assertion.  This histograms the field over
       the WHOLE losing family from the same two corpora the bar is scored
       from, so "all 96 carry imms=0" is a measurement with a denominator.

       Fixed-width ISAs only: the encodings are read as one little-endian
       32-bit word, which is what the corpus's own hex spelling holds for
       aarch64, mipsel and riscv64.  x86 has no bit-field to histogram and
       asking for one would be pretending a decoder is a table."""
    rx = re.compile(mnem_re)
    hist, bad = collections.Counter(), []
    for enc, mnem, lost in losses(a, b, isa):
        if not rx.search(mnem):
            continue
        try:
            w = struct.unpack("<I", bytes.fromhex(enc))[0]
        except Exception:
            bad.append(enc)
            continue
        hist[(w >> lo) & ((1 << (hi - lo + 1)) - 1)] += len(lost)
    return hist, bad


def score(a, b, rows, isas=ISAS, bar=False, trap=None):
    """Join the measured losses to the table.  Returns (report, rc)."""
    out, rc = [], 0
    unclaimed, ambiguous = {}, {}
    by_disp = {d: [0, 0] for d in DISPOSITIONS}   # [reg-instances, encodings]
    #: REAL-LOST, per ISA.  A losing register instance whose class asserts the
    #: register must STAY on the wire (REAL-*) or has no verdict yet (OPEN).
    #: An UNCLAIMED or AMBIGUOUS loss is counted here too -- a loss nobody has
    #: adjudicated is a loss, and letting the join's own refusal quietly keep
    #: it out of the bar would be the silent false success this file is shaped
    #: against.
    real_lost = {isa: 0 for isa in isas}
    total_regs = total_encs = 0
    trap = trap or {}
    joinbad = False
    trap_isas = {k[0] for k in trap}
    #: the measured TRAP-STATE credit, and the encodings an ISA's map misses
    trapped = {isa: [0, 0] for isa in isas}     # [reg-instances, encodings]
    uncovered = []

    for isa in isas:
        for enc, mnem, lost in losses(a, b, isa):
            enc_counted = set()
            if isa in trap_isas:
                v = trap.get((isa, enc.lower()))
                if v is None:
                    uncovered.append((isa, enc))
                    continue
                if v == "TRAP-ONLY":
                    trapped[isa][0] += len(lost)
                    trapped[isa][1] += 1
                    by_disp["TRAP-STATE"][0] += len(lost)
                    by_disp["TRAP-STATE"][1] += 1
                    total_regs += len(lost)
                    total_encs += 1
                    continue
            for reg in lost:
                total_regs += 1
                claims = [r for r in rows
                          if r["isa"] == isa and r["mnem"].search(mnem)
                          and r["reg"].search(reg)]
                if not claims:
                    unclaimed.setdefault((isa, mnem, reg), [0, enc])[0] += 1
                    real_lost[isa] += 1
                    continue
                if len(claims) > 1:
                    ambiguous.setdefault(
                        (isa, mnem, reg),
                        [0, enc, ",".join(c["cid"] for c in claims)])[0] += 1
                    real_lost[isa] += 1
                    continue
                c = claims[0]
                if c["disp"] in REAL or c["disp"] in UNDECIDED:
                    real_lost[isa] += 1
                c["hits"] += 1
                by_disp[c["disp"]][0] += 1
                if c["cid"] not in enc_counted:
                    c["encs"] += 1
                    by_disp[c["disp"]][1] += 1
                    enc_counted.add(c["cid"])
            if enc_counted or lost:
                total_encs += 1

    if total_regs == 0:
        out.append("REFUSING: the measurement has no losing rows at all -- "
                   "either the arms are identical or an arm was never built")
        return out, 1

    out.append("=== THE OPERAND WALK'S PRICE, BY DISPOSITION ===")
    out.append("%-18s %12s %12s" % ("disposition", "reg-insts", "encodings"))
    for d in DISPOSITIONS:
        out.append("%-18s %12d %12d" % (d, by_disp[d][0], by_disp[d][1]))
    out.append("%-18s %12d %12d" % ("TOTAL", total_regs, total_encs))
    out.append("")
    if trap:
        out.append("=== TRAP-STATE, MEASURED PER ENCODING (D17) ===")
        for isa in isas:
            if isa in trap_isas:
                out.append("%-10s TRAP-ONLY %10d reg-inst  %8d encodings"
                           % (isa, trapped[isa][0], trapped[isa][1]))
        if uncovered:
            rc = 1
            joinbad = True
            out.append("UNCOVERED by the trapstate map: %d encoding(s) -- "
                       "REFUSING." % len(uncovered))
            for k in uncovered[:8]:
                out.append("      %-9s %s" % k)
            out.append("      A map that does not cover the population cannot "
                       "say whether the rows it does not name trapped.")
        out.append("")
    # THE BAR ITSELF.  R12.1 is REAL-LOST = 0 hard, per ISA and with no
    # pessimistic-direction discount, so the number the deletion excursion is
    # judged on is printed here rather than left to be re-added by hand from
    # the disposition table.  SUPERSET and TRAP-STATE are excluded because
    # each carries a written ruling that the register does not belong on the
    # wire; every other outcome, INCLUDING a loss no row claims, counts.
    out.append("=== REAL-LOST (REAL-* + OPEN + unadjudicated), PER ISA ===")
    for isa in isas:
        out.append("%-10s REAL-LOST %10d" % (isa, real_lost[isa]))
    out.append("%-10s REAL-LOST %10d" % ("TOTAL", sum(real_lost.values())))
    if bar and any(real_lost.values()):
        rc = 1
        out.append("BAR: FAIL -- REAL-LOST is not 0 on every ISA.")
    elif bar:
        out.append("BAR: PASS -- REAL-LOST = 0 on every ISA.")
    out.append("")
    out.append("=== PER CLASS ===")
    out.append("%-26s %-9s %-17s %10s" % ("class_id", "isa", "disposition",
                                          "reg-insts"))
    for r in sorted(rows, key=lambda r: -r["hits"]):
        out.append("%-26s %-9s %-17s %10d"
                   % (r["cid"], r["isa"], r["disp"], r["hits"]))

    joinbad = bool(unclaimed or ambiguous)
    stale = [r for r in rows if r["hits"] == 0]
    if stale:
        joinbad = True
        rc = 1
        out.append("")
        out.append("STALE ROWS -- claim nothing in this measurement (%d):"
                   % len(stale))
        for r in stale:
            out.append("   %s (%s)" % (r["cid"], r["isa"]))
    if unclaimed:
        rc = 1
        out.append("")
        out.append("UNCLAIMED LOSSES -- no row claims these (%d signatures):"
                   % len(unclaimed))
        for (isa, mnem, reg), (n, ex) in sorted(unclaimed.items(),
                                                key=lambda kv: -kv[1][0])[:40]:
            out.append("   %-9s %-16s %-18s %6d  e.g. %s"
                       % (isa, mnem, reg, n, ex))
    if ambiguous:
        rc = 1
        out.append("")
        out.append("AMBIGUOUS LOSSES -- two rows claim these (%d signatures):"
                   % len(ambiguous))
        for (isa, mnem, reg), (n, ex, cids) in sorted(
                ambiguous.items(), key=lambda kv: -kv[1][0])[:40]:
            out.append("   %-9s %-16s %-18s %6d  %s" % (isa, mnem, reg, n, cids))

    out.append("")
    # THE TWO FAILURES ARE DIFFERENT AND ARE NAMED APART.  A join that cannot
    # place a loss REFUSES; a join that places every loss and finds REAL-LOST
    # non-zero has done its work and is reporting a bar.  Printing "REFUSED"
    # for the second would read as an instrument that could not look, which is
    # the misreading this tree files against.
    if joinbad:
        out.append("VERDICT: REFUSED -- the join could not place every loss.")
    elif rc:
        out.append("VERDICT: every losing register is claimed by exactly one "
                   "adjudicated class; the BAR is what failed.")
    else:
        out.append("VERDICT: every losing register is claimed by exactly "
                   "one adjudicated class")
    return out, rc


def selftest():
    """Every refusal direction PLANTED and proven to fire, and the clean arm
       proven to pass -- an instrument whose refusals have never been seen
       fire is an instrument with no demonstrated fail condition."""
    import tempfile
    ok = True

    def corpus(rows):
        fd, p = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write("#tip\tselftest\n")
            for r in rows:
                fh.write("\t".join(r) + "\n")
        return p

    def table(lines):
        fd, p = tempfile.mkstemp(suffix=".tsv")
        with os.fdopen(fd, "w") as fh:
            fh.write("# selftest\n")
            for l in lines:
                fh.write(l + "\n")
        return p

    A = corpus([("mipsel", "00000080", "lb", "REG_ZERO,REG_GPR1"),
                ("mipsel", "00000084", "lh", "REG_ZERO")])
    B = corpus([("mipsel", "00000080", "lb", "-"),
                ("mipsel", "00000084", "lh", "-")])

    n_check = [0]
    n_fail = [0]

    def check(name, tbl_lines, want_rc, want_sub=None, corpB=B,
              trap=None, bar=False):
        nonlocal ok
        n_check[0] += 1
        a, ea = load_corpus(A)
        b, eb = load_corpus(corpB)
        rows, et = load_table(table(tbl_lines))
        if ea or eb:
            print("  %-34s LOAD ERROR %s" % (name, ea + eb))
            ok = False
            return
        if rows is None or et:
            got_rc, rep = 1, et
        else:
            rep, got_rc = score(a, b, rows, isas=("mipsel",), trap=trap,
                                bar=bar)
        txt = "\n".join(rep)
        good = (got_rc == want_rc) and (want_sub is None or want_sub in txt)
        if good:
            print("  ARM %d %s (rc=%d) ok" % (n_check[0], name, got_rc))
        else:
            n_fail[0] += 1
            ok = False
            print("  ARM %d %s FAILED (rc=%d, wanted %d)"
                  % (n_check[0], name, got_rc, want_rc))

    full = ["z\tmipsel\t.*\t^REG_ZERO$\tREAL-QEMU-ELIDES\tR15\tthe encoding names it",
            "g\tmipsel\t.*\t^REG_GPR\\d+$\tREAL-OPERAND\tR16\tordinary operand"]
    check("clean join passes", full, 0, "VERDICT: every losing")
    check("unclaimed loss REFUSES", full[:1], 1, "UNCLAIMED LOSSES")
    check("stale row REFUSES",
          full + ["x\tmipsel\t^nosuch$\t^REG_SP$\tSUPERSET\tcite\tnote"],
          1, "STALE ROWS")
    check("ambiguous claim REFUSES",
          full + ["d\tmipsel\t.*\t^REG_ZERO$\tSUPERSET\tcite\tnote"],
          1, "AMBIGUOUS LOSSES")
    check("OPEN row with no question REFUSES",
          ["o\tmipsel\t.*\t.*\tOPEN\tcite\tno question here"],
          1, "must carry the QUESTION")
    check("TRAP-STATE row with no probe evidence REFUSES",
          ["t\tmipsel\t.*\t.*\tTRAP-STATE\tcite\tit looked like a trap"],
          1, "must name the trapstate_probe evidence")
    check("TRAP-STATE row that names the probe is accepted",
          ["z\tmipsel\t.*\t^REG_ZERO$\tREAL-QEMU-ELIDES\tR15\tnames it",
           "t\tmipsel\t.*\t^REG_GPR\\d+$\tTRAP-STATE\tcite\t"
           "trapstate_probe reads TRAP-ONLY"],
          0, "TRAP-STATE")
    check("row with no citation REFUSES",
          ["n\tmipsel\t.*\t.*\tREAL-OPERAND\t \tnote"], 1, "no citation")
    check("unknown disposition REFUSES",
          ["u\tmipsel\t.*\t.*\tPROBABLY-FINE\tcite\tnote"], 1,
          "unknown disposition")
    check("empty measurement REFUSES", full, 1,
          "the measurement has no losing rows", corpB=A)

    # THE BAR AND THE MEASURED TRAP-STATE, both directions.
    #
    # The selftest corpus loses REG_ZERO + REG_GPR1 on 00000080 and REG_ZERO
    # on 00000084 -- three register instances, all REAL under `full`.
    check("REAL-LOST is the bar and it FAILS when non-zero", full, 1,
          "mipsel     REAL-LOST          3", bar=True)
    check("a bar failure is NOT reported as a refusal", full, 1,
          "the BAR is what failed", bar=True)
    trap_one = {("mipsel", "00000080"): "TRAP-ONLY",
                ("mipsel", "00000084"): "DATAPATH"}
    # 00000080 loses REG_ZERO + REG_GPR1, 00000084 loses REG_ZERO.  Trapping
    # the first takes TWO instances out of the bar and leaves ONE, and the
    # table is not consulted for the trapped encoding at all -- which is why
    # the `g` row is dropped here: its only subject was that encoding, and a
    # row left claiming nothing is a STALE row by this file's own rule.
    check("a TRAP-ONLY encoding leaves the bar and is counted apart",
          full[:1], 1, "mipsel     REAL-LOST          1",
          trap=trap_one, bar=True)
    check("... and its registers are reported as TRAP-ONLY", full[:1], 1,
          "TRAP-ONLY          2 reg-inst", trap=trap_one, bar=True)
    trap_all = {("mipsel", "00000080"): "TRAP-ONLY",
                ("mipsel", "00000084"): "TRAP-ONLY"}
    # THE JOIN'S OWN GUARDS STAY ARMED under a trapstate map: a table whose
    # rows now claim nothing is STALE, not quietly tolerated.
    check("a table left behind by a wholly trapped population is STALE",
          full, 1, "STALE ROWS", trap=trap_all, bar=True)
    trap_half = {("mipsel", "00000080"): "TRAP-ONLY"}
    check("a trapstate map that misses an encoding REFUSES", full, 1,
          "UNCOVERED by the trapstate map", trap=trap_half, bar=True)
    trap_dp = {("mipsel", "00000080"): "DATAPATH",
               ("mipsel", "00000084"): "NO-OPS"}
    check("NO-OPS and DATAPATH both stay REAL (R16: a NOP has dependencies)",
          full, 1, "mipsel     REAL-LOST          3", trap=trap_dp, bar=True)

    print("srcwalk_worklist selftest: %d check(s), %d failure(s)"
          % (n_check[0], n_fail[0]))
    print("SELFTEST %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--arm-a", help="corpus directory for arm A (tip)")
    ap.add_argument("--arm-b", help="corpus directory for arm B (walk deleted)")
    ap.add_argument("--table", default=os.path.join(here, "SRCWALK_CLASSES.tsv"))
    ap.add_argument("--isa", action="append", choices=ISAS)
    ap.add_argument("--trapstate", action="append", default=[],
                    metavar="ISA=FILE",
                    help="trapstate_probe.py verdicts for ISA; every losing "
                         "encoding it reads TRAP-ONLY is credited TRAP-STATE "
                         "under D17 and never reaches the table")
    ap.add_argument("--bar", action="store_true",
                    help="fail unless REAL-LOST is 0 on every scored ISA")
    ap.add_argument("--encfield", metavar="ISA:MNEM_RE:LO:HI",
                    help="instead of scoring, histogram encoding bits LO:HI "
                         "over the losing encodings whose mnemonic matches "
                         "MNEM_RE -- the whole-population arm behind a "
                         "family ruling.  Fixed-width ISAs only.")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.arm_a or not args.arm_b:
        ap.error("--arm-a and --arm-b are required (or --selftest)")

    isas = tuple(args.isa) if args.isa else ISAS
    a, b, errs = {}, {}, []
    for isa in isas:
        pa, ea = load_corpus(os.path.join(args.arm_a, "%s.tsv" % isa))
        pb, eb = load_corpus(os.path.join(args.arm_b, "%s.tsv" % isa))
        errs += ea + eb
        if pa is None or pb is None:
            continue
        a.update(pa)
        b.update(pb)
    if args.encfield:
        try:
            fisa, mre, lo, hi = args.encfield.rsplit(":", 3)
            # ARM and MIPS manuals write a field high:low ("imms is 15:10");
            # famarm.py writes it low:high.  Both spellings name the same
            # bits, so neither is refused -- the pair is normalised instead.
            lo, hi = sorted((int(lo), int(hi)))
        except Exception:
            ap.error("--encfield wants ISA:MNEM_RE:LO:HI")
        if fisa not in ISAS:
            ap.error("--encfield ISA must be one of %s" % (ISAS,))
        if fisa == "x86_64":
            print("REFUSING: x86_64 has no fixed encoding bit-field to "
                  "histogram; a slot table for it would be a decoder.")
            return 2
        if not a or not b:
            print("REFUSING: a corpus arm is empty, so the histogram would "
                  "have no subject.")
            return 2
        hist, bad = encfield(a, b, fisa, mre, lo, hi)
        tot = sum(hist.values())
        if tot == 0:
            print("REFUSING: no losing encoding on %s matches %s -- an arm "
                  "with no subject abstains." % (fisa, mre))
            return 2
        print("encfield %s /%s/ bits %d:%d over %d losing register "
              "instance(s)" % (fisa, mre, lo, hi, tot))
        for v, n in sorted(hist.items()):
            print("  0x%02x  %6d  %5.1f%%" % (v, n, 100.0 * n / tot))
        if bad:
            print("  UNPARSED encodings: %d (%s ...)" % (len(bad), bad[0]))
        return 1 if bad else 0

    rows, et = load_table(args.table)
    errs += et
    trap, te = load_trapstate(args.trapstate)
    errs += te
    if errs:
        for e in errs:
            print("ERROR: %s" % e)
        if rows is None or not a or not b:
            return 1
    rep, rc = score(a, b, rows, isas=isas, bar=args.bar, trap=trap)
    print("\n".join(rep))
    return 1 if (rc or errs) else 0


if __name__ == "__main__":
    sys.exit(main())
