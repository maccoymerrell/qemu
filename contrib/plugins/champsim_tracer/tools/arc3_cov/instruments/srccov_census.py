#!/usr/bin/env python3
"""The SOURCE-SIDE membership census -- what the plugin's own sidecar says
about whether QEMU justifies each register the wire publishes as a source.

WHY THIS READER EXISTS AS AN INSTRUMENT.  The census itself lives in the
plugin (champsim_tracer_qdep.cc, landed 36a34a28a9) and prints into every
stats sidecar.  The pass that landed it reported that the census EXISTED and
never reported what it SAID -- "not measured" carried as "measured and fine",
which is the exact shape the census was written to correct.  A number nobody
reads is not a measurement, so the reader belongs beside the other standing
instruments rather than in one pass's scratch directory (#306's pattern).

WHAT THE COLUMNS MEAN, and why they are kept apart:

  JUSTIFIED    a published src_regs[i] that QEMU's ORDERED read list contains.
  UNJUSTIFIED  a published src_regs[i] that it does NOT.  Under R12.1 these
               are the NAMED SURVIVORS a source-list flip must carry or
               knowingly lose.  This is the number the arc is driving down.
  NOT-SCORED   QEMU withheld the read list for the instruction entirely.  A
               THIRD outcome, never folded into UNJUSTIFIED -- folding it
               would blame the wire for the emulator's own refusal, which is
               how the destination side's first figures became a 219x
               overstatement (#231).  HONESTLY NON-ZERO: the census runs
               before apply_dst's write-side refusal return (#327/#328), so
               it scores the whole population.  A zero here would now mean
               every instruction in the corpus had its read list stated, not
               that nothing was withheld -- and the zero this column printed
               before the hoist was a zero about instructions it never
               looked at.
  QEMU-EXTRA   the OPPOSITE direction: a register QEMU reads that the wire
               does not publish.  Counted apart because it is what a flip
               would GAIN, not what it owes.  Netting it against UNJUSTIFIED
               would hide both.
  INSN-SCORED  the population the other columns are drawn from.  It is also
               what makes a cross-tip comparison legitimate: if it is stable
               and UNJUSTIFIED moves by orders of magnitude, the movement is
               the change and not the environment (#314).
  OVER-BOUND   read lists past the fold's cap, refused rather than shortened.
  ADJ-OWED     published sources the flip's union does not contain that are
               NOT counted as MISSING, because their deletion was written,
               landed, measured against the external references and REVERTED
               when those references contradicted it (PASS 29).  A FOURTH
               outcome, and it is kept apart from BOTH neighbours on purpose:
               folding it into JUSTIFIED would assert the wire is right,
               which is the very thing no ruling has said; leaving it in
               MISSING would assert a flip may delete it, which R12.1
               forbids.  Non-zero here is not a defect -- it is an open
               maintainer question, and it blocks any source-list flip until
               it is answered.
  ADJ-R16      the FIFTH outcome, and the one an answered question lands in:
               the same ledger, the rows a RULING has closed.  R16 (2026-08-30)
               rules that an architectural dependency is recorded whatever
               QEMU's lowering or the modelled machine's state does with it,
               and it closed riscv64 `fence` REG_SYS (menvcfg.FIOM decides
               what the fence ORDERS; Sail states it) and x86_64 `rdsspq`
               REG_SSP (XED SRC {REG_SSP}; a NOP semantic still has real
               dependencies).  STILL NOT FOLDED INTO JUSTIFIED: JUSTIFIED
               means QEMU's ordered read list contains the register, which
               for these rows it does not, and one column cannot say both.
               Non-zero here does NOT block a flip -- it OBLIGES one: the
               flip must carry every register in it.
               ADJ-OWED and ADJ-R16 never share a row.  A row leaves ADJ-OWED
               by being ruled, never by being deleted, and the count follows
               it, so the closure of a question is visible as an arithmetic
               identity across two censuses rather than as an absence.

VACUITY (#313/#235).  A stats file with no census block FAILS.  A census
whose INSN-SCORED is zero FAILS.  A reader that cannot find its subject must
not report success -- that is the standing failure mode in this tree.

Usage:  srccov_census.py <stats.log>... [--max-unjustified N]
        srccov_census.py --selftest
"""
import argparse
import contextlib
import io
import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _arc3lib as L  # noqa: E402

ROWS = [
    ("JUSTIFIED",   r"(\d+)\s+published source entries JUSTIFIED"),
    ("UNJUSTIFIED", r"(\d+)\s+published source entries UNJUSTIFIED"),
    ("NOT-SCORED",  r"(\d+)\s+published source entries NOT SCORED"),
    ("QEMU-EXTRA",  r"(\d+)\s+registers QEMU reads that the wire does"),
    ("INSN-SCORED", r"(\d+)\s+instructions scored"),
    ("INSN-NOT",    r"(\d+)\s+instructions not scored"),
    ("OVER-BOUND",  r"(\d+)\s+read lists over the fold's bound"),
    ("ADJ-OWED",    r"(\d+)\s+of the loss direction held back as "
                    r"ADJUDICATION-OWED"),
    ("ADJ-R16",     r"(\d+)\s+JUSTIFIED BY ADJUDICATION \(R16\)"),
]
MARKER = "SOURCE-SIDE MEMBERSHIP COVERAGE"


def read_one(path):
    """Return (label, values|None, reason)."""
    label = os.path.basename(path).split(".")[0]
    try:
        txt = open(path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        return label, None, "unreadable: %s" % e
    if MARKER not in txt:
        return label, None, "no census block in this file"
    vals, miss = [], []
    for name, rx in ROWS:
        m = re.search(rx, txt)
        if m:
            vals.append(int(m.group(1)))
        else:
            vals.append(None)
            miss.append(name)
    if miss:
        return label, None, "missing rows: %s" % ",".join(miss)
    if vals[4] == 0:
        return label, None, "instructions scored == 0 (vacuous)"
    return label, vals, ""


def census(paths, quiet=False):
    out, bad = [], []
    for p in paths:
        label, vals, reason = read_one(p)
        out.append((label, vals, reason))
        if vals is None:
            bad.append("%s: %s" % (label, reason))
    if not quiet:
        print(__doc__.split("Usage:")[0].rstrip())
        # WHERE THIS READING WAS TAKEN FROM (#327).  Part of the number, not
        # context: see L.cwd_stamp().
        print(); print(L.cwd_stamp())
        hdr = "%-9s" % "isa" + "".join("%13s" % n for n, _ in ROWS)
        print(); print(hdr); print("-" * len(hdr))
        for label, vals, reason in out:
            if vals is None:
                print("%-9s REFUSED -- %s" % (label, reason))
            else:
                print("%-9s" % label + "".join("%13d" % v for v in vals))
        print()
    if bad:
        if not quiet:
            print("REFUSED: %d file(s) had no usable census:" % len(bad))
            for b in bad:
                print("  " + b)
        return 2, out
    if not quiet:
        print("all %d censuses present and non-vacuous" % len(out))
    return 0, out


# --------------------------------------------------------------------------
# selftest

def _block(just, unjust, nots, extra, scored, notscored, over, owed=0,
           r16=0):
    return (MARKER + " -- per PUBLISHED src_regs[i]\n"
            "  %d  published source entries JUSTIFIED\n"
            "  %d  published source entries UNJUSTIFIED -- x\n"
            "  %d  published source entries NOT SCORED -- x\n"
            "  %d  registers QEMU reads that the wire does NOT publish -- x\n"
            "  %d  instructions scored\n"
            "  %d  instructions not scored\n"
            "  %d  read lists over the fold's bound, refused rather than "
            "shortened\n"
            "  %d  of the loss direction held back as ADJUDICATION-OWED, and\n"
            "               NOT counted in the first row above\n"
            "  %d  JUSTIFIED BY ADJUDICATION (R16) -- the same ledger, the\n"
            "               rows a RULING has closed\n"
            % (just, unjust, nots, extra, scored, notscored, over, owed,
               r16))


SURV_HDR = "SOURCE SURVIVORS KEYED ON QEMU'S DECODE IDENTITY"
SURV_ROW = re.compile(r"^\s*(\d+)\s+([0-9a-f]{8})\s+(\S+)\s+(REG_\S+)"
                      r"\s+(SELF@\d+|FIXED)\s+(\S+)\s*$")


def survivors(paths, quiet=False):
    """Print the NAMED survivor rows the UNJUSTIFIED column counts.

    The column says HOW MANY; this says WHICH, which is the form an
    adjudication needs.  It is the same block gen_src_survivors.py reads,
    so a row printed here and a row in the emitted table are the same
    measurement seen twice -- and a disagreement between them is visible
    rather than inferred.

    A file with no survivor block FAILS.  A reader that cannot find its
    subject must not report success (#313/#235): "no rows" and "no block"
    are different facts and only one of them is a clean census.
    """
    rc, seen = 0, 0
    for path in paths:
        try:
            text = open(path, errors="replace").read()
        except OSError as e:
            print("FAIL %s: %s" % (path, e))
            rc = 1
            continue
        if SURV_HDR not in text:
            print("FAIL %s: no survivor block -- the census did not run"
                  % path)
            rc = 1
            continue
        rows, none = [], False
        for line in text.split(SURV_HDR, 1)[1].splitlines():
            if line.strip() == "(none)":
                none = True
                break
            m = SURV_ROW.match(line)
            if m:
                rows.append(m.groups())
            elif rows and not line.strip():
                break
        seen += 1
        if not quiet:
            print("%s: %d survivor row(s)%s"
                  % (path, len(rows), "  (block read `(none)`)"
                     if none and not rows else ""))
            for cnt, did, rule, reg, role, mnem in rows:
                print("  %8s  %s  %-30s %-14s %-7s %s"
                      % (cnt, did, rule, reg, role, mnem))
    if not seen and not rc:
        print("FAIL: no file carried a survivor block")
        rc = 1
    return rc


def selftest():
    checks = []
    tmp = tempfile.mkdtemp(prefix="srccov_census_selftest_")
    try:
        good = os.path.join(tmp, "x86_64.stats.log")
        vac = os.path.join(tmp, "vacuous.stats.log")
        absent = os.path.join(tmp, "absent.stats.log")
        short = os.path.join(tmp, "short.stats.log")
        open(good, "w").write(_block(22235, 5436, 0, 21, 20315, 0, 0, 22, 19))
        open(vac, "w").write(_block(0, 0, 0, 0, 0, 0, 0, 0, 0))
        open(absent, "w").write("a stats file with everything BUT the census\n")
        open(short, "w").write(MARKER + "\n  5  published source entries "
                               "JUSTIFIED\n")

        rc, out = census([good], quiet=True)
        checks.append(("clean census: rc=0 and the columns are read exactly",
                       rc == 0 and out[0][1] == [22235, 5436, 0, 21, 20315,
                                                 0, 0, 22, 19],
                       "rc=%d vals=%s" % (rc, out[0][1])))

        # A census that scored nothing is not a census with no survivors.
        rc, out = census([vac], quiet=True)
        checks.append(("PLANTED vacuous census (scored=0) FAILS, not 'clean'",
                       rc != 0 and out[0][1] is None, "rc=%d" % rc))

        # A file with no census at all must not read as zero survivors.
        rc, out = census([absent], quiet=True)
        checks.append(("PLANTED absent census FAILS (the #313 shape)",
                       rc != 0 and out[0][1] is None, "rc=%d" % rc))

        # A census the plugin printed only half of is a refusal, not a
        # partial read with the missing rows silently zero.
        rc, out = census([short], quiet=True)
        checks.append(("PLANTED truncated census FAILS rather than zero-filling",
                       rc != 0 and out[0][1] is None, "rc=%d" % rc))

        rc, out = census([os.path.join(tmp, "nope.log")], quiet=True)
        checks.append(("PLANTED missing file FAILS", rc != 0, "rc=%d" % rc))

        # One bad file among good ones must still fail: a batch that reports
        # success because most of it worked is the same defect wearing a
        # bigger input.
        rc, out = census([good, absent], quiet=True)
        checks.append(("one bad file in a batch FAILS the whole run",
                       rc != 0, "rc=%d" % rc))

        # --survivors reads the NAMED rows.  Both arms matter: a real row
        # must be found, and a file with no survivor block must FAIL rather
        # than print "0 rows" -- the flag existed only in prose until now
        # and prose cannot be vacuous the way a reader can.
        surv = os.path.join(tmp, "surv.stats.log")
        open(surv, "w").write(
            _block(1, 1, 0, 0, 1, 0, 0, 0)
            + "\n" + SURV_HDR + " -- rows:\n"
            "         2  e91326ac disas_a64/FADD_v           REG_FCSR"
            "       SELF@1  fadd\n"
            "       521  000006da RET                        REG_SEG5"
            "       FIXED   retq\n\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            src_rc = survivors([surv])
        txt = buf.getvalue()
        checks.append(("--survivors prints the NAMED rows, role included",
                       src_rc == 0 and "2 survivor row(s)" in txt
                       and "SELF@1" in txt and "FIXED" in txt,
                       "rc=%d" % src_rc))
        checks.append(("--survivors FAILS on a file with no survivor block",
                       survivors([absent], quiet=True) != 0,
                       "a reader that cannot find its subject must fail"))

        # #327: the reading must carry the directory it was taken from, and
        # the stamp must actually MOVE when the directory does -- a constant
        # string would satisfy a grep and prove nothing.
        here = os.getcwd()
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                census([good], quiet=False)
            printed_here = buf.getvalue()
            os.chdir(tmp)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                census([good], quiet=False)
            printed_tmp = buf.getvalue()
        finally:
            os.chdir(here)
        checks.append(("#327 the table carries a HARNESS CWD stamp",
                       L.CWD_STAMP_TAG in printed_here
                       and here in printed_here,
                       "tag+path present"))
        checks.append(("#327 the stamp MOVES with the directory",
                       os.path.realpath(tmp) in printed_tmp
                       and here not in printed_tmp.split("isa")[0],
                       "differs between two cwds"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return L.selftest_report("srccov_census.py", checks)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stats", nargs="*")
    ap.add_argument("--max-unjustified", type=int, default=None,
                    help="fail when the UNJUSTIFIED total exceeds N; this is "
                         "the R12.1 named-survivor budget for a source-list "
                         "flip, and it only means anything with a stated tip")
    ap.add_argument("--survivors", action="store_true",
                    help="print the NAMED survivor rows the UNJUSTIFIED "
                         "column counts -- decode id, rule, register, role "
                         "and mnemonic -- instead of the column table")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.stats:
        L.die_usage("usage: srccov_census.py <stats.log>...")
    if args.survivors:
        return survivors(args.stats)
    rc, out = census(args.stats)
    if rc:
        return rc
    if args.max_unjustified is not None:
        tot = sum(v[1][1] for v in out)
        if tot > args.max_unjustified:
            print("FAIL: UNJUSTIFIED total %d exceeds the budget %d"
                  % (tot, args.max_unjustified))
            return 1
        print("UNJUSTIFIED total %d within the budget %d"
              % (tot, args.max_unjustified))
    return 0


if __name__ == "__main__":
    sys.exit(main())
