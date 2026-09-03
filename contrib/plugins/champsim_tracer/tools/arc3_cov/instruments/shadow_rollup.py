#!/usr/bin/env python3
"""THE SHADOW ROLL-UP: aggregate the SHADOW LOOKUP and QEMU decode-identity
blocks over a set of sidecars and assert the identities that must hold.

WHY IT IS IN THE TREE NOW, AND WHY THAT IS THE FIX RATHER THAN A TIDY-UP.
Five verification passes each shipped their own copy of this reader
(verify41 through verify45), and the copy they shipped had a defect that no
pass could have caught from its own output.  The reader takes its subject as
a ROOT DIRECTORY and walks it.  Handed a FILE LIST -- which is the shape
every other instrument beside it takes -- `os.walk()` of a regular file
yields nothing, the file set is empty, and every identity it then asserts is
`0 == 0 + 0`.  All three CLOSE, it prints "ROLL-UP CLOSES", and it exits 0:

    == ALL ARMS (wp0 + wp16) : 0 sidecars, 0 refused
      comparable == agree + KD       YES
      ENUM-PUB == SILENT             YES
      scored == tiers summed         YES
      ROLL-UP CLOSES

That is the standing dominant failure mode of this tree -- a check that
cannot find its subject reporting success -- and it was found by counting
the glob separately beside the run, not by any signal the instrument gave.
A sixth pass-local copy would have carried it forward again, so the reader
lands here, next to the instruments whose subject-refusal shape it now
shares.

WHAT CHANGED, EXACTLY.

  * THE SUBJECT MAY BE EITHER SHAPE.  Directories are walked for
    `*.stats.log`; explicit files are taken as given, whatever they are
    named, so a glob expanded by the shell is a first-class subject rather
    than a silent zero.  A path that does not exist REFUSES.

  * AN EMPTY SUBJECT REFUSES (rc=2) instead of closing.  `roll()` itself
    refuses an empty population, so no identity is ever asserted over zero
    rows anywhere in this file -- not at the top level and not in a
    partition.

  * A PARTITION WITH NO ARMS IS NAMED, NOT ROLLED.  A corpus captured at
    wp=0 only is a legitimate subject, and its wp16 partition is honestly
    empty; that is reported as "no arms present (not rolled)" and asserts
    nothing.  The distinction the old reader lost is between "no arms" and
    "arms that agree".

  * `--selftest` PROVES BOTH DIRECTIONS, because an instrument nobody has
    shown can fire is not evidence: a good corpus CLOSES, a broken identity
    FIRES, an empty subject REFUSES both ways round (empty directory and
    empty file list), a missing path REFUSES, a sidecar without the blocks
    REFUSES, and the two subject shapes read the SAME numbers off the same
    sidecars.

WHAT DID NOT CHANGE: the identities themselves, the tier vocabulary (the two
R20 tiers VERIFIED and STATED are read, so `scored == tiers summed` has
seven terms), and the refusal on a sidecar missing either block.

USAGE
    shadow_rollup.py <path> [<path> ...]      paths are dirs and/or files
    shadow_rollup.py --selftest [scratch-dir]

rc: 0 the roll-up closes, 1 an identity does not hold, 2 REFUSED (no
subject, a missing path, or a sidecar without the blocks).  rc=2 is never
folded into rc=0.

Author: Maccoy Merrell.
"""
import re, sys, os, collections, tempfile, shutil

SHADOW = {"instructions classified": "classified",
          "both keys answered": "comparable",
          "and AGREED on every column": "agree",
          "KEY-DISAGREE": "kd",
          "ENUM-PUBLISHED: classifications": "enumpub",
          "identity key SILENT": "silent",
          "no enum row for this insn_id": "norow"}
IDENT = {"translated instructions read": "translated",
         "no identity exported (id == 0)": "noid",
         "id carried, NO ROW IN TABLE": "norow_tbl",
         "row found, NAME DISAGREES": "namedis",
         "scored against the Capstone row": "scored",
         "ENUM-PUBLISHED, this run": "enumpub_id"}
TIER = re.compile(
    r"tier of the rows that executed:\s+"
    r"(?:VERIFIED (\d+)\s+STATED (\d+)\s+)?OBSERVED (\d+)\s+ADJUDICATED (\d+)"
    r"\s+SPLIT (\d+)\s+NAME_MATCHED (\d+)\s+NONE (\d+)\s+tier out of range (\d+)")
COL = re.compile(r"^\s{4}(\w+)\s+(\d+)\s*$")
IDENT_HDR = "QEMU decode identity: the rule the translator dispatched on"
TIERS = ("VERIFIED", "STATED", "OBSERVED", "ADJUDICATED",
         "SPLIT", "NAME_MATCHED", "NONE", "OUTOFRANGE")


def refuse(msg):
    print("shadow_rollup: REFUSED -- %s" % msg)
    sys.exit(2)


def resolve(paths):
    """Directories are walked, files are taken as given.  Returns the sorted
    subject.  A path that does not exist is a REFUSAL, never an empty
    contribution: the whole defect this reader is replacing was an
    unresolvable subject read as zero."""
    out = []
    for p in paths:
        if os.path.isdir(p):
            out += [os.path.join(d, x)
                    for d, _, fs in os.walk(p) for x in fs
                    if x.endswith(".stats.log")]
        elif os.path.isfile(p):
            out.append(p)
        else:
            refuse("subject path %r is neither a directory nor a file.  "
                   "A reader that cannot find its subject FAILS." % p)
    return sorted(set(out))


def roll(files, label):
    """Aggregate and assert.  REFUSES an empty population: `0 == 0 + 0` is
    not an identity holding, it is an instrument with nothing to look at."""
    if not files:
        refuse("%s has no sidecars.  An empty subject is not a clean one -- "
               "every identity over zero rows closes vacuously." % label)
    t = collections.Counter()
    cols = collections.Counter()
    n = 0
    refused = []
    for f in files:
        try:
            txt = open(f, errors="replace").read()
        except OSError as e:
            refused.append("%s (%s)" % (f, e))
            continue
        i = txt.find("SHADOW LOOKUP")
        j = txt.find(IDENT_HDR)
        if i < 0 or j < 0:
            refused.append(f)
            continue
        n += 1
        for line in txt[i:i + 6000].splitlines():
            m = re.match(r'\s*(\d+)\s+(.*)', line)
            if not m:
                continue
            for k, name in SHADOW.items():
                if k in m.group(2):
                    t[name] += int(m.group(1))
                    break
        for line in txt[j:j + 4000].splitlines():
            for k, name in IDENT.items():
                mm = re.match(r'\s+' + re.escape(k) + r'\s+(\d+)', line)
                if mm:
                    t[name] += int(mm.group(1))
                    break
        m = TIER.search(txt[j:j + 4000])
        if not m:
            refused.append(f + " (no tier line)")
            continue
        for name, v in zip(TIERS, m.groups()):
            t[name] += int(v or 0)
        k = txt.find("per-column disagreements:", i)
        if k > 0:
            for line in txt[k:k + 900].splitlines()[1:]:
                mm = COL.match(line)
                if not mm:
                    break
                cols[mm.group(1)] += int(mm.group(2))
    if refused:
        print("shadow_rollup: REFUSED -- sidecars without a shadow/identity "
              "block:")
        for f in refused:
            print("   ", f)
        sys.exit(2)
    # AN EMPTY SUBJECT HAS A SECOND SHAPE, AND IT IS THE ONE THAT SURVIVED.
    #
    # The file-count refusal above catches "no sidecars".  It does not catch
    # sidecars that PARSE and carry nothing: N files whose blocks are present
    # and whose every counter is zero roll up to `0 == 0 + 0` on all three
    # identities, print "N sidecars", and CLOSE.  That is the same instrument
    # with nothing to look at, wearing a non-zero file count -- and the
    # guard the selftest wrote against the original defect ("no output pairs
    # '0 sidecars' with 'CLOSES'") reads it as clean, because the count is not
    # zero.  A corpus that classified nothing AND translated nothing is a
    # subject the roll-up cannot speak about, so it refuses instead.
    if not t["classified"] and not t["translated"]:
        refuse("%s: %d sidecar(s) parsed and every population is EMPTY -- "
               "0 classified, 0 translated.  The identities would all close "
               "vacuously over zero rows, which is the file-count refusal's "
               "defect in a second dress." % (label, n))
    print("== %s : %d sidecars, 0 refused" % (label, n))
    print("  classified                     %10d" % t["classified"])
    print("  comparable                     %10d" % t["comparable"])
    print("  agree                          %10d" % t["agree"])
    print("  KEY-DISAGREE                   %10d" % t["kd"])
    print("  comparable == agree + KD       %10s"
          % ("YES" if t["comparable"] == t["agree"] + t["kd"] else "NO <<<<"))
    print("  ENUM-PUBLISHED (shadow)        %10d" % t["enumpub"])
    print("  identity key SILENT            %10d" % t["silent"])
    print("  ENUM-PUB == SILENT             %10s"
          % ("YES" if t["enumpub"] == t["silent"] else "NO <<<<"))
    print("  no enum row (must be 0)        %10d" % t["norow"])
    print("  -- identity census")
    print("  translated instructions read   %10d" % t["translated"])
    print("  scored against Capstone row    %10d" % t["scored"])
    tiersum = sum(t[x] for x in TIERS if x != "OUTOFRANGE")
    print("  tiers summed                   %10d" % tiersum)
    print("  scored == tiers summed         %10s"
          % ("YES" if t["scored"] == tiersum else "NO <<<<"))
    print("  no identity exported (id==0)   %10d" % t["noid"])
    print("  id carried, NO ROW (must be 0) %10d" % t["norow_tbl"])
    print("  row found, NAME DISAGREES (0)  %10d" % t["namedis"])
    print("  tier out of range (must be 0)  %10d" % t["OUTOFRANGE"])
    print("  ENUM-PUBLISHED (identity blk)  %10d" % t["enumpub_id"])
    print("  R20 tiers: VERIFIED %d  STATED %d" % (t["VERIFIED"], t["STATED"]))
    print("  SURVIVOR tiers per translated insn: SPLIT %d  NAME_MATCHED %d  "
          "NONE %d  total %d"
          % (t["SPLIT"], t["NAME_MATCHED"], t["NONE"],
             t["SPLIT"] + t["NAME_MATCHED"] + t["NONE"]))
    print("  per-column disagreements: %s" % dict(cols))
    bad = (t["comparable"] != t["agree"] + t["kd"]
           or t["enumpub"] != t["silent"]
           or t["norow"] or t["norow_tbl"] or t["namedis"] or t["OUTOFRANGE"]
           or t["scored"] != tiersum)
    print("  ROLL-UP %s" % ("CLOSES" if not bad else "DOES NOT CLOSE <<<<"))
    print()
    return 1 if bad else 0


def partition(allf, tag):
    return [f for f in allf if tag in f]


def main(paths):
    allf = resolve(paths)
    if not allf:
        refuse("the subject resolved to 0 sidecars.  Directories were walked "
               "for *.stats.log and files were taken as given; neither found "
               "anything.  A roll-up over no sidecars asserts 0 == 0 + 0 and "
               "would CLOSE, which is the defect this refusal exists to "
               "prevent.")
    rc = roll(allf, "ALL ARMS (wp0 + wp16)")
    for tag, label in (("_wp0.", "wp0 ARMS ALONE"), ("_wp16.", "wp16 ARMS ALONE")):
        part = partition(allf, tag)
        if part:
            rc |= roll(part, label)
        else:
            # NAMED, not rolled.  "No arms" and "arms that agree" are
            # different facts and the old reader printed them identically.
            print("== %s : no arms present (not rolled)\n" % label)
    print("sidecars total = %d" % len(allf))
    return rc


# ----------------------------------------------------------------- selftest
GOOD = """
--- SHADOW LOOKUP: the decode-identity key against the Capstone-enum key ---
%(classified)12d  instructions classified
%(comparable)12d  both keys answered -- the comparable population
%(agree)12d  ... and AGREED on every column
%(kd)12d  KEY-DISAGREE: instructions the two keys answer differently.
%(enumpub)12d  ENUM-PUBLISHED: classifications the ENUM TABLE is the answer for.
%(silent)12d  identity key SILENT (reasons in the survivor block below)
%(norow)12d  no enum row for this insn_id at all
  per-column disagreements:
    opcode          0
    branchtype      0
--- QEMU decode identity: the rule the translator dispatched on ---
  translated instructions read              %(translated)6d
  no identity exported (id == 0)                 0    0.0%%
  id carried, NO ROW IN TABLE                    0  <- stale table
  row found, NAME DISAGREES                      0  <- stale table
  scored against the Capstone row           %(scored)6d
  tier of the rows that executed:  VERIFIED %(VERIFIED)d   STATED %(STATED)d   OBSERVED %(OBSERVED)d   ADJUDICATED 0   SPLIT 0   NAME_MATCHED 0   NONE 0   tier out of range 0
"""


def _sidecar(path, **kw):
    d = dict(classified=100, comparable=90, agree=80, kd=10, enumpub=7,
             silent=7, norow=0, translated=100, scored=95,
             VERIFIED=5, STATED=10, OBSERVED=80)
    d.update(kw)
    open(path, "w").write(GOOD % d)


def _run(args):
    """Run main() in-process and capture (rc, stdout)."""
    import io
    import contextlib
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = main(args)
    except SystemExit as e:
        rc = e.code
    return rc, buf.getvalue()


def selftest(scratch=None):
    tmp = scratch or tempfile.mkdtemp(prefix="shadow_rollup_selftest.")
    os.makedirs(tmp, exist_ok=True)
    fails = 0

    def check(tag, cond, detail=""):
        nonlocal fails
        print("%-4s %s  %s" % ("PASS" if cond else "FAIL", tag, detail))
        if not cond:
            fails += 1

    root = os.path.join(tmp, "cells")
    os.makedirs(root, exist_ok=True)
    a = os.path.join(root, "x86_64__cellA_wp0.stats.log")
    b = os.path.join(root, "x86_64__cellA_wp16.stats.log")
    _sidecar(a)
    _sidecar(b)

    rc, out = _run([root])
    check("A root-dir form CLOSES on a good corpus", rc == 0
          and out.count("ROLL-UP CLOSES") == 3
          and "sidecars total = 2" in out, "rc=%s" % rc)

    rc2, out2 = _run([a, b])
    check("B FILE-LIST form is a first-class subject (the defect)",
          rc2 == 0 and "sidecars total = 2" in out2, "rc=%s" % rc2)

    def numbers(s):
        return [l.strip() for l in s.splitlines()
                if l.startswith("  ") and "%" not in l]
    check("C both subject shapes read the SAME numbers",
          numbers(out) == numbers(out2))

    empty = os.path.join(tmp, "empty")
    os.makedirs(empty, exist_ok=True)
    rc, out = _run([empty])
    check("D an EMPTY DIRECTORY refuses (rc=2), never closes",
          rc == 2 and "CLOSES" not in out, "rc=%s" % rc)

    rc, out = _run([])
    check("E an EMPTY FILE LIST refuses (rc=2), never closes",
          rc == 2 and "CLOSES" not in out, "rc=%s" % rc)

    rc, out = _run([os.path.join(tmp, "nope")])
    check("F a MISSING path refuses (rc=2)", rc == 2, "rc=%s" % rc)

    junk = os.path.join(tmp, "junk")
    os.makedirs(junk, exist_ok=True)
    jf = os.path.join(junk, "x_wp0.stats.log")
    open(jf, "w").write("no blocks here\n")
    rc, out = _run([junk])
    check("G a sidecar without the blocks refuses (rc=2)", rc == 2,
          "rc=%s" % rc)

    bad = os.path.join(tmp, "bad")
    os.makedirs(bad, exist_ok=True)
    bf = os.path.join(bad, "y_wp0.stats.log")
    _sidecar(bf, kd=11)          # comparable != agree + kd
    rc, out = _run([bad])
    check("H a BROKEN identity FIRES (rc=1) and says so",
          rc == 1 and "DOES NOT CLOSE" in out, "rc=%s" % rc)

    bad2 = os.path.join(tmp, "bad2")
    os.makedirs(bad2, exist_ok=True)
    _sidecar(os.path.join(bad2, "z_wp0.stats.log"), scored=94)
    rc, out = _run([bad2])
    check("I a tier-sum mismatch FIRES (rc=1)", rc == 1, "rc=%s" % rc)

    onearm = os.path.join(tmp, "onearm")
    os.makedirs(onearm, exist_ok=True)
    _sidecar(os.path.join(onearm, "q_wp0.stats.log"))
    rc, out = _run([onearm])
    check("J a wp0-only corpus NAMES the absent wp16 partition rather than "
          "closing it", rc == 0
          and "wp16 ARMS ALONE : no arms present (not rolled)" in out
          and out.count("ROLL-UP CLOSES") == 2, "rc=%s" % rc)

    check("K the old failure shape cannot recur: no output ever pairs "
          "'0 sidecars' with 'CLOSES'",
          all(not ("0 sidecars" in o and "CLOSES" in o)
              for o in (out, out2)))

    # L: the file count is not zero and the POPULATION is.  This is the arm
    # the original selftest could not have written, because K's guard keys on
    # the sidecar count and this shape has two of them.
    hollow = os.path.join(tmp, "hollow")
    os.makedirs(hollow, exist_ok=True)
    for arm in ("wp0", "wp16"):
        _sidecar(os.path.join(hollow, "h_%s.stats.log" % arm),
                 classified=0, comparable=0, agree=0, kd=0, enumpub=0,
                 silent=0, translated=0, scored=0,
                 VERIFIED=0, STATED=0, OBSERVED=0)
    rcL, outL = _run([hollow])
    check("L sidecars that PARSE and carry NOTHING refuse (rc=2), never "
          "close on 0 == 0 + 0", rcL == 2 and "CLOSES" not in outL,
          "rc=%s" % rcL)

    print("failures=%d" % fails)
    if scratch is None:
        shutil.rmtree(tmp, ignore_errors=True)
    return 1 if fails else 0


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "--selftest":
        sys.exit(selftest(args[1] if len(args) > 1 else None))
    if not args:
        refuse("no subject given.  usage: shadow_rollup.py <dir|file> ...  "
               "(or --selftest)")
    sys.exit(main(args))
