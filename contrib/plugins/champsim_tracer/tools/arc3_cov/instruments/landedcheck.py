#!/usr/bin/env python3
"""THE LANDED-STATEMENT DETECTOR: does the class's own bar know the remedy
landed?

WHY THIS EXISTS
---------------
Nothing in the 19-leg R13 gate or the 36-row battery can see a QEMU statement
that landed and did not reach the published set, and nothing can see the
opposite either -- a statement that landed, reached the set, and left the
ledger row that asked for it saying QEMU is still short.  Both are invisible
for the same reason: every instrument in this directory scores a MEASUREMENT
against a CEILING, and a ledger row is neither.  It is a sentence about the
measurement, written once, by hand, and never re-read.

PASS 87 found both faces in one pass, and filed both under the wrong headline:

  `mips-dsp-extr-dst`  read QEMU-STATES-IT while 26ba0eb823 had already put
                       DSPControl in QEMU's write list for every EXTR/EXTP
                       encoding the helper arm reaches.  The 38 registers the
                       row still counts belong to a DIFFERENT population --
                       the rt == 0 arm QEMU turns into a NOP -- so the row was
                       right about a number and wrong about the reason, and
                       the reason is what a reader acts on.

  `a64-shift-degenerate-accum`  read QEMU-STATES-IT while 2fad558e0c had
                       already put Rd in QN on all 234 degenerate encodings.
                       The 216 registers the row still counts are the Rn half,
                       which the row's OWN note calls a correct drop.

Both rows were re-read by hand, in a pass that went looking.  This is the
instrument that does not need one to go looking.

WHAT IT ASSERTS, PER CLASS ROW
------------------------------
A `QEMU-STATES-IT` row says one thing: *for these families, this register is a
real dependency and QEMU does not state it.*  Two things can make that false,
and they are opposite, so the check has two arms:

  SPLIT   Inside the very families that still LOSE the register, QEMU states
          it on some other encoding.  The remedy landed for part of the class
          and the row still describes the whole of it as unstated -- so the
          number it carries and the reason it gives belong to two different
          populations, and the reason is what the next reader acts on.

  INERT   The row's citation names a source LINE, an `insn_dataflow_note_*`
          call sits within the window around it -- so a remedy IS landed at
          the cited site -- and QEMU states the register on NONE of the
          losing families' encodings.  A statement that reaches no published
          row is a statement nobody can read.

THE POPULATION IS THE BAR'S, NOT THE FAMILY'S, and that is the whole
difference between an instrument and a grep.  Scored over every encoding a
class's regexes match, `zero-register` reads "QEMU names REG_ZERO on 291,551
rows" and `mips-trap-dst` reads "18,609 of 18,720" -- both true, both about
encodings the bar never counted, and both worthless as a verdict.  So the
subject is the LOSING set: for the source bar, the registers arm A publishes
and arm B does not; for the destination bar, `PUBD - WR` on the rows dstbar.py
itself scores.  The stated-elsewhere question is then asked only of families
that contribute at least one losing row, because a family with no losing row
is not what the sentence is about.

A row whose citation names no line abstains from the INERT arm and says so.
An abstention is printed, not hidden: a check that cannot reach its subject
must report that it did not, which is the whole of this file's discipline.

WHAT IT DOES NOT ASSERT
-----------------------
It does not adjudicate.  SPLIT and INERT are both "this row and this corpus
disagree", and which one is wrong is a judgement with a source site behind it:
a SPLIT closes either by narrowing the row's regexes onto the population it is
really about, or by re-adjudicating the whole class.  The detector's job is to
make the disagreement impossible to carry to the next pass unnoticed -- and to
make the ARGUMENT cheap, by naming the witness encodings.

A row whose class no longer loses anything reads EMPTIED and is not a red of
this instrument's own: that failure already has an owner in barledger.py's
total-join, and two instruments reporting one fact as two is how a number
gets double-counted.

Author: Maccoy Merrell.
"""
import argparse, collections, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import barledger
import srcenc_reach
from evopen import evopen, resolve

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")

#: The QEMU column each bar is a claim about.  SOURCE rows claim QEMU does not
#: READ the register, so the column is QN -- qemu_named_regs(), the list the
#: wire's src_regs[] is built from.  DESTINATION rows claim QEMU does not WRITE
#: it, so the column is WR, QEMU's own write list.  Nothing here reads PUB or
#: PUBD: those are the WIRE's lists and a row about QEMU's silence cannot be
#: refuted by what the operand walk found.
QCOL = {"source": "QN", "destination": "WR"}

#: How far from a cited line a landed statement may sit and still be the one
#: the citation means.  Wide, because a citation names the FUNCTION's first
#: line as often as the note's -- `gengvec.c:282 gen_gvec_usra` cites the
#: constructor and its note is at 319 -- and narrow enough that a note for an
#: unrelated instruction elsewhere in a 5,000-line translate.c is not read as
#: this row's remedy.
CITE_WINDOW = 80

#: THE ONE WAY A SPLIT MAY BE GREEN.
#:
#: A SPLIT usually cannot be closed by narrowing the row's regexes, and that is
#: not a weakness of the check -- it is the shape of the thing.  The families
#: `mips-trap-dst` matches lose REG_SYSEXC on gen_trap()'s never-trap arm and
#: state it on the always-trap arm of the SAME mnemonic, so no pattern over
#: (rule, mnemonic, register) separates them; only a sentence does.  So the
#: close is a sentence, and this token is how the row proves it wrote one.
#: The instrument does not read the prose -- it cannot -- but it can refuse to
#: go green until prose exists at all, which is the difference between a split
#: somebody decided about and a split nobody noticed.
ACK = "SPLIT-ACK"

NOTE_RX = re.compile(r"insn_dataflow_note_\w+\s*\(")
#: `path/to/file.c:1234`, the form every citation in both tables uses when it
#: names a line at all.
CITE_RX = re.compile(r"((?:target|accel|tcg|hw)/[\w./-]+\.(?:c|h|inc)):(\d+)")


def read_mech(root, isa, wps):
    """The class's subject population: REACH=INSTRUCTION mech rows, merged
    across the wp arms on the encoding.  A wp disagreement on the QEMU column
    is a CONFLICT and is counted, never resolved -- an instrument that picks
    one of two answers has stopped measuring."""
    out, conflicts = {}, 0
    for w in wps:
        p = os.path.join(root, "%s.wp%s" % (isa, w), "corpus_mech_%s.tsv" % isa)
        if not os.path.exists(resolve(p)):
            sys.exit("landedcheck: %s missing -- REFUSING (a class scored "
                     "against an absent corpus reads as a class with no "
                     "subject, which is the one answer this file may not "
                     "give)" % p)
        hdr = None
        with evopen(p, errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    if hdr is None:
                        hdr = line.lstrip("#").rstrip("\n").split("\t")
                    continue
                if hdr is None:
                    continue
                c = line.rstrip("\n").split("\t")
                if len(c) < len(hdr):
                    continue
                row = dict(zip(hdr, c))
                if srcenc_reach.classify(row)[0] != "INSTRUCTION":
                    continue
                enc = row.get("encoding", "")
                prev = out.get(enc)
                if prev is not None:
                    if prev != row:
                        conflicts += 1
                    continue
                out[enc] = row
    return out, conflicts


def regset(s):
    return [r for r in (s or "").split(",") if r and r != "-"]


def cite_has_landed_note(cite, qemu_root):
    """(verdict, why).  True only when the citation names a LINE and an
    insn_dataflow_note_* call sits within CITE_WINDOW of it."""
    m = CITE_RX.search(cite)
    if not m:
        return None, "citation names no source line"
    path = os.path.join(qemu_root, m.group(1))
    if not os.path.exists(path):
        return None, "cited file %s is not in the tree" % m.group(1)
    line = int(m.group(2))
    lo, hi = max(1, line - CITE_WINDOW), line + CITE_WINDOW
    with open(path, errors="replace") as f:
        for n, text in enumerate(f, 1):
            if lo <= n <= hi and NOTE_RX.search(text):
                return True, "%s:%d states at line %d" % (m.group(1), line, n)
    return False, "no insn_dataflow_note_* within %d lines of %s:%d" % (
        CITE_WINDOW, m.group(1), line)


#: state_name(QDEP_OK) and the two dstbar exclusions, verbatim -- a row the
#: destination bar does not score is not a row this file may score either.
OKW = "PUBLISHED from QEMU's emitters"


def lost_regs(row, bar, srcA, srcB, enc):
    """The registers THIS encoding contributes to the bar, by the bar's own
    definition.  Empty means the encoding is not a subject."""
    if bar == "destination":
        if row.get("WSTQ", "") != OKW or row.get("WRU", "0") == "1":
            return []
        return [r for r in regset(row.get("PUBD", ""))
                if r not in set(regset(row.get("WR", "")))]
    a, b = srcA.get(enc), srcB.get(enc)
    if a is None or b is None:
        return []
    return [r for r in a if r not in b]


def read_src(root, isa, wps):
    """encoding -> published source list, merged across wp arms."""
    out = {}
    for w in wps:
        p = os.path.join(root, "%s.wp%s" % (isa, w), "corpus_%s.tsv" % isa)
        if not os.path.exists(resolve(p)):
            sys.exit("landedcheck: %s missing -- REFUSING" % p)
        with evopen(p, errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                c = line.rstrip("\n").split("\t")
                if len(c) < 4:
                    continue
                out.setdefault(c[1], frozenset(regset(c[3])))
    return out


def score(classes, arm, isas, wps, bar, qemu_root, base=None, out=sys.stdout):
    col = QCOL[bar]
    if bar == "source" and not base:
        sys.exit("landedcheck: the source bar's losing set is arm A minus arm "
                 "B and --b was not given -- REFUSING (scored over the whole "
                 "family instead, this instrument reports on encodings the "
                 "bar never counted, which is the shape it exists against)")
    reds, rows_out = [], []
    unscored = 0
    per_isa, srcA, srcB = {}, {}, {}
    for isa in isas:
        per_isa[isa] = read_mech(arm, isa, wps)
        if bar == "source":
            srcA[isa] = read_src(arm, isa, wps)
            srcB[isa] = read_src(base, isa, wps)
    for k in classes:
        if k["disp"] != "QEMU-STATES-IT":
            continue
        isa_list = [i for i in (ISAS if k["isa"] == "*" else [k["isa"]])
                    if i in per_isa]
        if not isa_list:
            # NOT ITS CORPUS, SO NOT ITS VERDICT.  Run with --isa naming a
            # subset and every row for an ISA left out has no encodings to
            # lose -- which the EMPTIED arm would report as "this class is
            # over", the exact reading that retires a live row.  Found by
            # this instrument's own first partial run, on four rows.
            rows_out.append((k["cid"], k["isa"], "NOT-SCORED", 0, 0,
                             "%s is not in --isa; this row was not measured "
                             "and its silence means nothing" % k["isa"]))
            unscored += 1
            continue
        # PASS 1 -- the LOSING set: which encodings, in which families, and
        # WHICH REGISTER NAMES.  The names matter: a class regex as wide as
        # `.` matches every register a row carries, and asking "is anything
        # matching stated" of such a row answers yes on the row's own
        # untouched destinations.
        losing = 0
        fams, lost_names, losing_encs = set(), set(), set()
        conflicts = 0
        for isa in isa_list:
            if isa not in per_isa:
                continue
            rows, cf = per_isa[isa]
            conflicts += cf
            for enc, row in rows.items():
                rule, mnem = row.get("rule", "?"), row.get("mnem", "?")
                if not (k["rule"].search(rule) and k["mnem"].search(mnem)):
                    continue
                lost = [r for r in lost_regs(row, bar, srcA.get(isa, {}),
                                             srcB.get(isa, {}), enc)
                        if k["reg"].search(r)]
                if lost:
                    losing += 1
                    fams.add((isa, rule, mnem))
                    lost_names.update(lost)
                    losing_encs.add((isa, enc))
        # PASS 2 -- inside those families, on OTHER encodings, does QEMU state
        # one of the very registers this class loses?  Other encodings only:
        # a losing row cannot state the register it loses (that is what losing
        # means on the destination bar), so counting it would make every class
        # its own witness.
        stated = 0
        witness = []
        for isa in isa_list:
            if isa not in per_isa:
                continue
            rows, _ = per_isa[isa]
            for enc, row in rows.items():
                key = (isa, row.get("rule", "?"), row.get("mnem", "?"))
                if key not in fams or (isa, enc) in losing_encs:
                    continue
                hit = [r for r in regset(row.get(col, "")) if r in lost_names]
                if hit:
                    stated += 1
                    if len(witness) < 4:
                        witness.append("%s %s %s %s=%s"
                                       % (isa, enc, key[2], col, ",".join(hit)))
        landed, why = cite_has_landed_note(k["cite"], qemu_root)
        if losing == 0:
            verdict = "EMPTIED"
            note = ("no encoding of this class still loses the register; the "
                    "row survives its own subject (barledger's join owns it)")
        elif stated > 0 and ACK in k["note"]:
            verdict = "ok-ack"
            note = ("SPLIT, ACKNOWLEDGED in the row's own note: %d losing, %d "
                    "stated in the same families" % (losing, stated))
        elif stated > 0:
            verdict = "SPLIT"
            note = ("%d encodings still lose it and QEMU STATES it on %d "
                    "others in the same families; one row, two populations"
                    % (losing, stated))
            reds.append((k["cid"], verdict, note, witness))
        elif landed is True:
            verdict = "INERT"
            note = ("a statement is landed (%s) and QEMU states the register "
                    "on NONE of the %d losing families' encodings"
                    % (why, len(fams)))
            reds.append((k["cid"], verdict, note, []))
        elif landed is None:
            verdict = "ABSTAIN"
            note = ("%s; the SPLIT arm ran over %d losing encodings in %d "
                    "families and found none stated" % (why, losing, len(fams)))
        else:
            verdict = "ok"
            note = ("no statement landed yet (%s); %d losing encodings, none "
                    "stated" % (why, losing))
        rows_out.append((k["cid"], k["isa"], verdict, losing, stated, note))
        if conflicts:
            print("  WP CONFLICT %s: %d rows disagree across wp arms"
                  % (k["cid"], conflicts), file=out)

    print("landedcheck  bar=%s  arm=%s  base=%s  wps=%s"
          % (bar, arm, base or "-", " ".join(wps)), file=out)
    print("  %-28s %-9s %-8s %8s %7s" % ("class", "isa", "verdict",
                                         "losing", "stated"), file=out)
    for cid, isa, verdict, losing, stated, note in sorted(rows_out):
        print("  %-28s %-9s %-8s %8d %7d  %s"
              % (cid, isa, verdict, losing, stated, note), file=out)
    if unscored:
        print("", file=out)
        print("  %d row(s) NOT SCORED -- their ISA was not in --isa.  This "
              "report is PARTIAL and no row above may be retired on it: an "
              "unmeasured class reads exactly like a finished one." % unscored,
              file=out)
    if not rows_out:
        # THE ZERO-SUBJECT ARM (FINDING 91-C).  A table with no
        # QEMU-STATES-IT row has two entirely different causes and they do not
        # get the same answer.
        #
        # The one this refusal was written for: a table that is INCOMPLETE.
        # Rows are still BLOCKED, or the dispositions do not add up, and every
        # verdict this instrument would print below is vacuous because the
        # population it scores has not been decided yet.  That still REFUSES,
        # and it must: a check that cannot find its subject may not report
        # all-clear (the standing rule, and #235/#238's vacuity guard is the
        # same shape).
        #
        # The other is the ARC'S OWN GOAL STATE, and refusing it made the
        # eight-step barscore green unreachable by construction: every class
        # in the table is RULED, none is BLOCKED, and none says QEMU is short.
        # There is no QEMU-STATES-IT row because there is nothing left for
        # QEMU to state.  That is a POSITIVE ledger fact, and it is asserted
        # positively here rather than inferred from an absence: STATES-IT == 0
        # AND RULED == total AND BLOCKED == 0.  An absence alone proves
        # nothing -- a table truncated to zero rows also has no STATES-IT row
        # -- so `total` must be non-zero and must equal RULED exactly.
        n = collections.Counter(k["disp"] for k in classes)
        total = sum(n.values())
        ruled, blocked = n.get("RULED", 0), n.get("BLOCKED", 0)
        if total and ruled == total and blocked == 0:
            print("  NO QEMU-STATES-IT ROWS, AND THE LEDGER SAYS WHY: "
                  "%d class(es), RULED %d, BLOCKED %d, QEMU-STATES-IT 0.  "
                  "Every class is adjudicated and none is waiting on a QEMU "
                  "statement, so this instrument has no subject BECAUSE its "
                  "subject is finished -- not because it could not look."
                  % (total, ruled, blocked), file=out)
            print("", file=out)
            print("LANDED-STATEMENT CHECK: PASS (ZERO SUBJECT) -- the "
                  "positive ledger statement holds", file=out)
            return 0
        print("  NO QEMU-STATES-IT ROWS -- REFUSING: this instrument's whole "
              "subject is that disposition, and a table with none of it makes "
              "every verdict below vacuous.  The zero-subject PASS needs the "
              "POSITIVE ledger statement and this table does not carry it: "
              "%d class(es), RULED %d, BLOCKED %d."
              % (total, ruled, blocked), file=out)
        return 2
    print("", file=out)
    if reds:
        print("LANDED-STATEMENT CHECK: RED -- %d row(s)" % len(reds), file=out)
        for cid, verdict, note, witness in reds:
            print("  %s  %s -- %s" % (cid, verdict, note), file=out)
            for w in witness:
                print("      %s" % w, file=out)
        return 1
    print("LANDED-STATEMENT CHECK: PASS -- %d QEMU-STATES-IT row(s) scored, "
          "none split, none inert" % len(rows_out), file=out)
    return 0


# --------------------------------------------------------------------------
# SELFTEST.  Four arms, and the two that matter are the PLANTED reds: a check
# for a silent failure has to be shown failing on one, or its green is the
# same green a check with no subject prints.
# --------------------------------------------------------------------------
HDR = ("#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\twstate\tPUB\tQN\t"
       "SURV\tRD\tSTATUS\tRDX\tCONT\tXLAT\tWR\tPUBD\tWSTQ\tOPC\tBR\tCFLAGS\t"
       "REFINE\tLANEK\tLANEP\tWRU\n")
#: An XLAT srcenc_reach.classify() reads as REACH=INSTRUCTION.
XLAT_OK = "noret=1,calls=1,memr=0,memw=0,refused=0"


def _row(isa, enc, mnem, rule, qn, wr, pubd=None):
    c = [isa, enc, mnem, "1", rule, OKW, OKW, qn, qn, "-", qn, "-", "-", "-",
         XLAT_OK, wr, pubd if pubd is not None else wr, OKW, "GEN_OP_INT",
         "BRANCH_NONE", "-", "-", "0", "0", "0"]
    return "\t".join(c) + "\n"


def _arm(root, isa, wp, rows, src=None):
    d = os.path.join(root, "%s.wp%s" % (isa, wp))
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "corpus_mech_%s.tsv" % isa), "w") as f:
        f.write(HDR)
        for r in rows:
            f.write(r)
    with open(os.path.join(d, "corpus_%s.tsv" % isa), "w") as f:
        f.write("#isa\tencoding\tmnem\tsrc\n")
        for enc, mnem, regs in (src or []):
            f.write("%s\t%s\t%s\t%s\n" % (isa, enc, mnem, regs))


def selftest(tmp):
    import io
    os.makedirs(tmp, exist_ok=True)
    npass = nfail = 0

    def check(name, cond):
        nonlocal npass, nfail
        if cond:
            print("PASS %s" % name); npass += 1
        else:
            print("FAIL %s" % name); nfail += 1

    # A source file with a landed note, and one without.
    qroot = os.path.join(tmp, "qemu")
    os.makedirs(os.path.join(qroot, "target/zz"), exist_ok=True)
    with open(os.path.join(qroot, "target/zz/landed.c"), "w") as f:
        f.write("\n" * 99 + "    insn_dataflow_note_stated_read_env(o, s);\n")
    with open(os.path.join(qroot, "target/zz/bare.c"), "w") as f:
        f.write("\n" * 200)

    tbl = os.path.join(tmp, "classes.tsv")

    def write_table(rows):
        with open(tbl, "w") as f:
            f.write("# selftest table\n")
            for r in rows:
                f.write("\t".join(r) + "\n")

    def cls(cid, rule, mnem, cite):
        return (cid, "mipsel", "^%s$" % rule, "^%s$" % mnem, "^REG_A$",
                "QEMU-STATES-IT", cite,
                "the wire carries REG_A and QEMU states nothing")

    CLEAN = cls("zz-clean", "r_c", "mc", "target/zz/bare.c:100 nothing landed")
    SPLIT = cls("zz-split", "r_s", "ms", "target/zz/bare.c:100 not the point")
    INERT = cls("zz-inert", "r_i", "mi", "target/zz/landed.c:100 the remedy")

    def run(mech, table, bar="source", srcA=None, srcB=None):
        a, b = os.path.join(tmp, "armA"), os.path.join(tmp, "armB")
        for isa in ISAS:
            _arm(a, isa, "0", mech if isa == "mipsel" else [],
                 srcA if isa == "mipsel" else [])
            _arm(b, isa, "0", [], srcB if isa == "mipsel" else [])
        write_table(table)
        buf = io.StringIO()
        rc = score(barledger.load_classes(tbl), a, list(ISAS), ["0"], bar,
                   qroot, base=b, out=buf)
        return rc, buf.getvalue()

    # ARM 1 -- CLEAN, source bar: one encoding loses REG_A (arm A publishes it,
    # arm B does not) and QEMU states it nowhere in the family.  Green.
    rc, o = run([_row("mipsel", "aa", "mc", "r_c", "REG_B", "REG_B")],
                [CLEAN], srcA=[("aa", "mc", "REG_A,REG_B")],
                srcB=[("aa", "mc", "REG_B")])
    check("clean row is green", rc == 0 and "PASS" in o)
    check("clean row is not vacuous: it has a losing encoding",
          re.search(r"zz-clean\s+mipsel\s+ok\s+1\s+0", o) is not None)

    # ARM 2 -- PLANTED SPLIT: the same family, a second encoding on which QEMU
    # DOES state REG_A.  The remedy landed for half the class.
    rc, o = run([_row("mipsel", "aa", "mc", "r_c", "REG_B", "REG_B"),
                 _row("mipsel", "ab", "mc", "r_c", "REG_A", "REG_B")],
                [CLEAN], srcA=[("aa", "mc", "REG_A,REG_B"),
                               ("ab", "mc", "REG_A")],
                srcB=[("aa", "mc", "REG_B"), ("ab", "mc", "REG_A")])
    check("planted SPLIT is RED", rc == 1 and "SPLIT" in o)
    check("planted SPLIT names the witness encoding",
          "ab" in o and "QN=REG_A" in o)

    # ARM 2b -- the SAME planted split, ACKNOWLEDGED in the row's note, is
    # green; and an acknowledgement on a row with no split does not create
    # one, so the token cannot be used to silence anything but a split.
    ACKED = list(CLEAN); ACKED[7] = ACKED[7] + " -- SPLIT-ACK: the two arms"
    rc, o = run([_row("mipsel", "aa", "mc", "r_c", "REG_B", "REG_B"),
                 _row("mipsel", "ab", "mc", "r_c", "REG_A", "REG_B")],
                [tuple(ACKED)], srcA=[("aa", "mc", "REG_A,REG_B"),
                                      ("ab", "mc", "REG_A")],
                srcB=[("aa", "mc", "REG_B"), ("ab", "mc", "REG_A")])
    check("an ACKNOWLEDGED split is green", rc == 0 and "ok-ack" in o)
    rc, o = run([_row("mipsel", "ba", "mi", "r_i", "REG_B", "REG_B")],
                [tuple(list(INERT)[:7] + [INERT[7] + " SPLIT-ACK: x"])],
                srcA=[("ba", "mi", "REG_A,REG_B")],
                srcB=[("ba", "mi", "REG_B")])
    check("the token does not silence an INERT row", rc == 1 and "INERT" in o)

    # ARM 3 -- THE POPULATION IS THE BAR'S.  The same two encodings, but the
    # stating one is in a DIFFERENT family that loses nothing: not a subject,
    # so the row stays green.  This is the arm that separates this instrument
    # from a grep over the class's regexes.
    rc, o = run([_row("mipsel", "aa", "mc", "r_c", "REG_B", "REG_B"),
                 _row("mipsel", "ac", "mother", "r_c", "REG_A", "REG_B")],
                [cls("zz-clean", "r_c", "m.*", "target/zz/bare.c:100 x")],
                srcA=[("aa", "mc", "REG_A,REG_B"), ("ac", "mother", "REG_A")],
                srcB=[("aa", "mc", "REG_B"), ("ac", "mother", "REG_A")])
    check("a stating family that loses nothing is NOT a subject", rc == 0)

    # ARM 4 -- PLANTED INERT: a landed note at the citation and nothing stated
    # anywhere in the losing families.
    rc, o = run([_row("mipsel", "ba", "mi", "r_i", "REG_B", "REG_B")],
                [INERT], srcA=[("ba", "mi", "REG_A,REG_B")],
                srcB=[("ba", "mi", "REG_B")])
    check("planted INERT is RED", rc == 1 and "INERT" in o)

    # ARM 5 -- the DESTINATION bar's losing set is PUBD - WR, and it needs no
    # second arm.  Same row: green when WR carries REG_A, RED when it does not
    # and a sibling encoding's WR does.
    ok_d = [_row("mipsel", "ca", "ms", "r_s", "-", "REG_A", "REG_A")]
    split_d = [_row("mipsel", "ca", "ms", "r_s", "-", "REG_B", "REG_A,REG_B"),
               _row("mipsel", "cb", "ms", "r_s", "-", "REG_A", "REG_A")]
    rc_ok, _ = run(ok_d, [SPLIT], bar="destination")
    rc_bad, o_d = run(split_d, [SPLIT], bar="destination")
    check("destination bar scores PUBD-minus-WR",
          rc_ok == 0 and rc_bad == 1 and "WR=REG_A" in o_d)

    # ARM 6 -- a destination row the bar does NOT score (WSTQ not OK) is not a
    # subject here either.
    short = split_d[0].split("\t"); short[17] = "LOWER BOUND: incomplete"
    rc, o = run(["\t".join(short), split_d[1]], [SPLIT], bar="destination")
    check("an unscorable WSTQ row is not a losing subject",
          rc == 0 and "EMPTIED" in o)

    # ARM 7 -- THE ZERO-SUBJECT SPLIT (FINDING 91-C), BOTH DIRECTIONS.  "No
    # QEMU-STATES-IT row" is two different states and the arm has to
    # discriminate them, or the PASS half is just the refusal with the guard
    # removed.
    #
    # 7a: every class RULED, none BLOCKED -- the arc's own goal state.  The
    #     positive ledger statement holds, so this PASSES and says so.
    # 7b: the same table with one BLOCKED class added -- the ledger is not
    #     finished, so the refusal stands.  Without this half, 7a alone would
    #     accept any table whose STATES-IT column happens to be empty.
    RULED = list(CLEAN); RULED[5] = "RULED"
    ROWS = [_row("mipsel", "aa", "mc", "r_c", "REG_B", "REG_B")]
    SRC = dict(srcA=[("aa", "mc", "REG_A")], srcB=[("aa", "mc", "")])
    rc, o = run(ROWS, [tuple(RULED)], **SRC)
    check("7a all-RULED / none-BLOCKED PASSES as a finished subject",
          rc == 0 and "ZERO SUBJECT" in o and "RULED 1, BLOCKED 0" in o)
    BLOCKED = list(CLEAN)
    BLOCKED[0] = "zz-open"; BLOCKED[5] = "BLOCKED"
    BLOCKED[7] = "what does QEMU state for this family?"
    rc, o = run(ROWS, [tuple(RULED), tuple(BLOCKED)], **SRC)
    check("7b one BLOCKED class still REFUSES (the ledger is not finished)",
          rc == 2 and "does not carry it" in o)

    # ARM 8 -- a missing corpus REFUSES rather than scoring zero rows.
    try:
        read_mech(os.path.join(tmp, "nope"), "mipsel", ["0"])
        check("missing corpus REFUSES", False)
    except SystemExit as e:
        check("missing corpus REFUSES", "REFUSING" in str(e))

    # ARM 9 -- the source bar REFUSES without its second arm; scored over the
    # family instead it would report on encodings the bar never counted.
    try:
        score(barledger.load_classes(tbl), os.path.join(tmp, "armA"),
              list(ISAS), ["0"], "source", qroot, base=None,
              out=io.StringIO())
        check("source bar without --b REFUSES", False)
    except SystemExit as e:
        check("source bar without --b REFUSES", "REFUSING" in str(e))

    # ARM 10a -- A ROW FOR AN ISA THE RUN DID NOT MEASURE READS NOT-SCORED,
    # not EMPTIED.  Found by this instrument's own first partial run, where
    # four live rows read "no encoding still loses the register" because
    # their corpora had not been loaded at all.
    a, b = os.path.join(tmp, "armA"), os.path.join(tmp, "armB")
    write_table([CLEAN])
    buf = io.StringIO()
    rc = score(barledger.load_classes(tbl), a, ["x86_64"], ["0"], "source",
               qroot, base=b, out=buf)
    o = buf.getvalue()
    check("a row whose ISA was not measured reads NOT-SCORED",
          "NOT-SCORED" in o and "EMPTIED" not in o and "PARTIAL" in o)

    # ARM 10 -- a row whose class no longer loses anything reads EMPTIED.
    rc, o = run([_row("mipsel", "aa", "mc", "r_c", "REG_B", "REG_B")],
                [CLEAN], srcA=[("aa", "mc", "REG_B")],
                srcB=[("aa", "mc", "REG_B")])
    check("a class that lost its subject reads EMPTIED",
          "EMPTIED" in o and rc == 0)

    print("landedcheck selftest: %d pass, %d fail" % (npass, nfail))
    return 1 if nfail else 0


def main():
    if "--selftest" in sys.argv:
        i = sys.argv.index("--selftest")
        tmp = (sys.argv[i + 1] if len(sys.argv) > i + 1
               and not sys.argv[i + 1].startswith("-")
               else "/tmp/landedcheck_st")
        return selftest(tmp)
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True,
                    help="the TIP sweep root -- the one whose mech corpora "
                         "describe the build the ledger rows are about")
    ap.add_argument("--b", default=None,
                    help="the DELETION arm, required for --bar source: its "
                         "losing set is arm A minus arm B, exactly as "
                         "srcbar.py derives it.  The destination bar's losing "
                         "set is PUBD - WR inside one arm and needs none.")
    ap.add_argument("--bar", choices=("source", "destination"),
                    default="source")
    ap.add_argument("--classes", default=None)
    ap.add_argument("--isa", default=" ".join(ISAS))
    ap.add_argument("--wps", default="0 16")
    ap.add_argument("--qemu-root", default="/mnt/md0/QEMU/qemu",
                    help="tree the citations' paths are relative to")
    a = ap.parse_args()
    table = a.classes or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "BAR_CLASSES.tsv" if a.bar == "source" else "DEST_CLASSES.tsv")
    return score(barledger.load_classes(table), a.arm, a.isa.split(),
                 a.wps.split(), a.bar, a.qemu_root, base=a.b)


if __name__ == "__main__":
    sys.exit(main())
