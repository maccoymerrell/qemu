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
               overstatement (#231).
  QEMU-EXTRA   the OPPOSITE direction: a register QEMU reads that the wire
               does not publish.  Counted apart because it is what a flip
               would GAIN, not what it owes.  Netting it against UNJUSTIFIED
               would hide both.
  INSN-SCORED  the population the other columns are drawn from.  It is also
               what makes a cross-tip comparison legitimate: if it is stable
               and UNJUSTIFIED moves by orders of magnitude, the movement is
               the change and not the environment (#314).
  OVER-BOUND   read lists past the fold's cap, refused rather than shortened.

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

def _block(just, unjust, nots, extra, scored, notscored, over):
    return (MARKER + " -- per PUBLISHED src_regs[i]\n"
            "  %d  published source entries JUSTIFIED\n"
            "  %d  published source entries UNJUSTIFIED -- x\n"
            "  %d  published source entries NOT SCORED -- x\n"
            "  %d  registers QEMU reads that the wire does NOT publish -- x\n"
            "  %d  instructions scored\n"
            "  %d  instructions not scored\n"
            "  %d  read lists over the fold's bound, refused rather than "
            "shortened\n" % (just, unjust, nots, extra, scored, notscored, over))


def selftest():
    checks = []
    tmp = tempfile.mkdtemp(prefix="srccov_census_selftest_")
    try:
        good = os.path.join(tmp, "x86_64.stats.log")
        vac = os.path.join(tmp, "vacuous.stats.log")
        absent = os.path.join(tmp, "absent.stats.log")
        short = os.path.join(tmp, "short.stats.log")
        open(good, "w").write(_block(22235, 5436, 0, 21, 20315, 0, 0))
        open(vac, "w").write(_block(0, 0, 0, 0, 0, 0, 0))
        open(absent, "w").write("a stats file with everything BUT the census\n")
        open(short, "w").write(MARKER + "\n  5  published source entries "
                               "JUSTIFIED\n")

        rc, out = census([good], quiet=True)
        checks.append(("clean census: rc=0 and the columns are read exactly",
                       rc == 0 and out[0][1] == [22235, 5436, 0, 21, 20315, 0, 0],
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
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.stats:
        L.die_usage("usage: srccov_census.py <stats.log>...")
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
