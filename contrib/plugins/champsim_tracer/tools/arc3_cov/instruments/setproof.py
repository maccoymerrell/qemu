#!/usr/bin/env python3
"""SETPROOF -- the three-column A/B set comparison, with the #235 guard.

Supersedes exec26/admission/setproof.py, exec27/slots/setproof.py,
exec27c/*/setproof3.py and exec27c/writeprov/setproof_ab.py.

WHY THREE COLUMNS (#212/#214).  A key is (pc, family).  Comparing two arms
naively reports a row as LOST or GAINED whenever the PC itself is absent
from one side -- and the published PC set is NOT stable across BUILDS of
identical source: measured on riscv64, two full builds of the same tree
published 4 PCs on one side and 6 on the other, with 0 of the 12,016 common
keys differing.  Reporting that as "10 blocks moved" would be an artefact of
the instrument.  So the verdict splits:

  CHANGED     the PC is in both arms and the key's content differs
  REAL-LOST   the PC is in both arms and the family disappeared
  REAL-GAIN   the PC is in both arms and the family appeared
  FLOOR       the PC is in one arm only -- the build-order noise floor

Only CHANGED and REAL are results.  FLOOR is printed so it can never be
quietly counted as either, and it is never counted as a regression.

THE #235 GUARD.  Given an arm with no rows at all, the two-column ancestor
reported the whole opposite side as "floor" and exited 0 -- clean zeros from
a comparison that had no subject.  An empty side is a FAILURE, never a
floor.  Both arms must have rows, per ISA, before anything is scored; a
missing or empty key file exits non-zero and says which arm and why.

THE COVERAGE COLUMN, and why cross-pass byte-identity is not the property
it reads as (PASS 34, verify34/SETPROOF_DELTA.txt).  The BEFORE arm here is
usually a banked baseline that never moves; the AFTER arm is a fresh run,
and WHICH PCs that run reaches is not fixed.  Measured across PASSes 31-34
against one banked baseline, strncmp's aligned fast path was executed in
PASS 34 and not in 31-33, and eleven CHANGED rows appeared with it.  Two
readings can therefore differ without a single fact having moved, and --
worse for the reader -- can AGREE while covering different subjects.

So every reading now states its own coverage beside its verdict:

  baseline    PCs in the BEFORE arm (the reference's whole subject)
  compared    PCs present in BOTH arms -- the only PCs any verdict is
              about
  skipped     PCs in one arm only.  These are the FLOOR: never a result,
              and now never invisible either.

and the cross-reading comparison (`--compare`) will NOT use the word
IDENTICAL unless the two readings' coverages match.  When they do not it
scores the verdicts at the MATCHED coverage -- the PCs both readings
actually looked at -- and says so in its own verdict word.  Comparing the
two report files as bytes, which is what passes used to do, silently reads
a coverage difference as a content difference and a coverage difference as
sameness in the other direction.

Usage:
  setproof.py <before-dir> <after-dir> [--isas a,b] [--suffix .key|.dkey]
                                       [--verdicts OUT.tsv]
  setproof.py --compare A.tsv B.tsv
  setproof.py --selftest
"""
import argparse
import collections
import contextlib
import io
import os
import shutil
import sys
import tempfile

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import _arc3lib as L  # noqa: E402


def compare(a, b):
    """Score one ISA.  Both sides are known non-empty by the time we get here.

    Returns (common, changed, real_lost, real_gain, floor, cov) where @cov is
    the reading's COVERAGE -- see coverage() -- because a verdict without its
    coverage is not a reading anyone can compare to another one.
    """
    pa = {k[0] for k in a}
    pb = {k[0] for k in b}
    both = pa & pb
    common = set(a) & set(b)
    changed = sorted(k for k in common if a[k] != b[k])
    real_lost = sorted(k for k in set(a) - set(b) if k[0] in both)
    real_gain = sorted(k for k in set(b) - set(a) if k[0] in both)
    floor = (len(set(a) - set(b)) - len(real_lost)
             + len(set(b) - set(a)) - len(real_gain))
    cov = {"baseline_pcs": pa, "after_pcs": pb, "compared_pcs": both}
    return common, changed, real_lost, real_gain, floor, cov


def cov_line(isa, cov):
    """The coverage of one ISA's reading, as one printable line.

    THE PROPERTY THIS MAKES VISIBLE (PASS 34).  `compared` is the ONLY set
    any verdict above is about.  `skipped` is the rest of either arm, and it
    MOVES between runs of the same build: PASS 34's after-arm executed
    strncmp's aligned fast path and PASSes 31-33's did not, which is eleven
    CHANGED rows appearing with no fact having changed.  Two readings whose
    coverages differ are not two readings of the same thing.
    """
    return ("%-8s COVERAGE baseline_pcs=%d after_pcs=%d compared_pcs=%d "
            "skipped_floor=%d (baseline-only %d, after-only %d)"
            % (isa, len(cov["baseline_pcs"]), len(cov["after_pcs"]),
               len(cov["compared_pcs"]),
               len(cov["baseline_pcs"] ^ cov["after_pcs"]),
               len(cov["baseline_pcs"] - cov["after_pcs"]),
               len(cov["after_pcs"] - cov["baseline_pcs"])))


#
# THE CROSS-READING VERDICT FILE.
#
# One row per key, carrying the verdict AND enough of the coverage to
# reconstruct it: which arms the key's PC was present in.  A pass banks this
# beside its report and the next pass compares THESE, not the report bytes.
#
VERDICT_HEADER = "#isa\tpc\tfamily\tverdict\tin_baseline\tin_after"


def verdict_rows(isa, a, b):
    """Every key of either arm, with its verdict and its arm membership."""
    pa = {k[0] for k in a}
    pb = {k[0] for k in b}
    both = pa & pb
    rows = []
    for k in sorted(set(a) | set(b)):
        in_a, in_b = k in a, k in b
        if in_a and in_b:
            v = "SAME" if a[k] == b[k] else "CHANGED"
        elif in_a:
            v = "REAL-LOST" if k[0] in both else "FLOOR-BASELINE-ONLY"
        else:
            v = "REAL-GAIN" if k[0] in both else "FLOOR-AFTER-ONLY"
        rows.append((isa, k[0], k[1], v,
                     "1" if k[0] in pa else "0",
                     "1" if k[0] in pb else "0"))
    return rows


def write_verdicts(path, rows):
    with open(path, "w") as fh:
        fh.write(VERDICT_HEADER + "\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")


def load_verdicts(path):
    """Read a verdict file into (verdicts, baseline_pcs, after_pcs) per ISA.

    Returns None when the file does not exist -- a missing reading is a
    refusal, never an empty comparison, for the #235 reason.
    """
    if not os.path.exists(path):
        return None
    verdicts = collections.defaultdict(dict)
    base = collections.defaultdict(set)
    after = collections.defaultdict(set)
    with open(path) as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            f = line.rstrip("\n").split("\t")
            if len(f) < 6:
                continue
            isa, pc, fam, v, in_a, in_b = f[:6]
            verdicts[isa][(pc, fam)] = v
            if in_a == "1":
                base[isa].add(pc)
            if in_b == "1":
                after[isa].add(pc)
    return verdicts, base, after


def compare_readings(pa, pb, quiet=False):
    """Compare two SETPROOF READINGS at their MATCHED coverage.

    WHY THIS EXISTS AND WHY IT REFUSES THE WORD "IDENTICAL" (PASS 34).
    Passes used to establish "the SETPROOF is unchanged" by diffing the two
    report files as bytes.  That reads a coverage difference as a content
    difference -- and, worse, cannot distinguish "the same verdicts over the
    same PCs" from "the same verdicts over different PCs".  The after arm's
    executed-PC set is not stable across runs of one build, so the second
    case is the common one and the byte diff never said so.

    So: coverage first, verdicts second, and the word IDENTICAL is reserved
    for the case where BOTH match.  When only the verdicts match, the reading
    is IDENTICAL-AT-MATCHED-COVERAGE and the coverage delta is printed beside
    it.  A verdict that differs at a PC both readings looked at is a real
    difference and exits non-zero; a coverage difference alone does not,
    because it is the instrument's own floor -- but it is never silent.
    """
    reasons = []
    if pa is None:
        reasons.append("VACUITY FAILURE: reading A was never produced.")
    if pb is None:
        reasons.append("VACUITY FAILURE: reading B was never produced.")
    if reasons:
        return (L.report_vacuity(reasons) if not quiet else 2), {}

    va, ba, aa = pa
    vb, bb, ab = pb
    tot = collections.Counter()
    isas = sorted(set(va) | set(vb))
    if not isas:
        reasons.append("VACUITY FAILURE: neither reading scored any ISA.")
        return L.report_vacuity(reasons), tot

    for isa in isas:
        if isa not in va or isa not in vb:
            reasons.append("VACUITY FAILURE: %s is scored in only one of the "
                           "two readings, so there is nothing to compare for "
                           "it." % isa)
            continue
        if ba[isa] != bb[isa]:
            # Not a floor.  The baseline is supposed to be the SAME banked
            # arm in both readings; if its PC set moved, the two readings are
            # against different references and no verdict comparison is
            # meaningful.
            reasons.append("VACUITY FAILURE: %s BASELINE differs between the "
                           "two readings (%d vs %d PCs, %d not shared) -- "
                           "these are readings against different references."
                           % (isa, len(ba[isa]), len(bb[isa]),
                              len(ba[isa] ^ bb[isa])))
            continue

        matched = aa[isa] & ab[isa]
        cov_same = aa[isa] == ab[isa]
        if not matched:
            reasons.append("VACUITY FAILURE: %s matched coverage is EMPTY -- "
                           "the two readings share no executed PC, so any "
                           "agreement between them would be about nothing."
                           % isa)
            continue

        ka = {k: v for k, v in va[isa].items() if k[0] in matched}
        kb = {k: v for k, v in vb[isa].items() if k[0] in matched}
        keys = set(ka) | set(kb)
        differ = sorted(k for k in keys if ka.get(k) != kb.get(k))
        tot["isas"] += 1
        tot["matched_pcs"] += len(matched)
        tot["rows"] += len(keys)
        tot["differ"] += len(differ)
        if not cov_same:
            tot["cov_moved"] += 1
        tot["a_only_pcs"] += len(aa[isa] - ab[isa])
        tot["b_only_pcs"] += len(ab[isa] - aa[isa])

        if not quiet:
            print("%-8s coverage A after_pcs=%d  B after_pcs=%d  "
                  "MATCHED=%d  (A-only %d, B-only %d)"
                  % (isa, len(aa[isa]), len(ab[isa]), len(matched),
                     len(aa[isa] - ab[isa]), len(ab[isa] - aa[isa])))
            print("%-8s verdicts at matched coverage: rows=%d differing=%d %s"
                  % (isa, len(keys), len(differ),
                     "" if differ else "(none)"))
            for k in differ[:20]:
                print("     DIFFER %s %s  A=%s  B=%s"
                      % (k[0], k[1], ka.get(k, "-"), kb.get(k, "-")))

    rc = (L.report_vacuity(reasons) if not quiet else (2 if reasons else 0))
    if rc:
        return rc, tot
    if tot["differ"]:
        verdict = "VERDICTS DIFFER AT MATCHED COVERAGE"
        rc = 1
    elif tot["cov_moved"]:
        verdict = ("IDENTICAL-AT-MATCHED-COVERAGE -- and NOT identical: the "
                   "two readings covered different executed-PC sets "
                   "(A-only %d, B-only %d PCs over %d ISA(s)).  The word "
                   "IDENTICAL is refused here on purpose."
                   % (tot["a_only_pcs"], tot["b_only_pcs"], tot["cov_moved"]))
        rc = 0
    else:
        verdict = "IDENTICAL -- same coverage AND same verdicts"
        rc = 0
    if not quiet:
        print("READING COMPARISON: %s" % verdict)
        print("TOTAL isas=%d matched_pcs=%d rows=%d differing=%d "
              "coverage_moved_on=%d isa(s)"
              % (tot["isas"], tot["matched_pcs"], tot["rows"], tot["differ"],
                 tot["cov_moved"]))
    tot["verdict_identical"] = 1 if verdict.startswith("IDENTICAL --") else 0
    tot["verdict_matched_only"] = 1 if verdict.startswith(
        "IDENTICAL-AT-MATCHED") else 0
    return rc, tot


def rename_pairs(lost, gain, a, b):
    """LOST/GAIN pairs that are one register RENAME, not a loss and a gain.

    WHY THIS COLUMN EXISTS (#267).  With --suffix .dkey the family key is
    per destination REGISTER -- "dst_dep@REG_IP" -- so renaming a generic
    register moves every row of that register from the LOST column to the
    GAIN column, at the same PCs, carrying the same facts.  Measured at
    be8767a9aa against exec27d/verify/basekey: R11's REG_IP -> REG_PC
    (5664563443) scored REAL-LOST=562 / REAL-GAIN=562 on x86_64 while the
    wire had lost nothing at all.  A reader taking that 562 to R12.1's
    "REAL-LOST=0, HARD" bar would report non-compliance that does not exist;
    a reader in the other direction could let a real loss ride in beside a
    rename.  Both are the instrument, not the wire.

    SO IT IS REPORTED, NEVER SUBTRACTED.  REAL-LOST and REAL-GAIN keep their
    full counts -- R12.1 forbids discounts and this is not one.  What is
    added is the NAME of the shape, so the adjudication is on the record
    instead of in someone's head:

      RENAME-PAIRED      same PC, same family prefix, the register the
                         family is keyed on is the only difference, and the
                         pairing is 1:1 at that PC (an ambiguous pairing is
                         not claimed).
      payload-identical  ...and the row's own payload matches once the old
                         register name is rewritten to the new one.  That is
                         the strong form: nothing about the row changed but
                         the register's spelling.

    A LOST row with no partner is never paired, so a genuine loss cannot hide
    here; the selftest plants exactly that case.
    """
    def split(fam):
        return fam.split("@", 1) if "@" in fam else (fam, None)

    by_pc_lost = collections.defaultdict(list)
    by_pc_gain = collections.defaultdict(list)
    for k in lost:
        pre, reg = split(k[1])
        if reg is not None:
            by_pc_lost[(k[0], pre)].append((k, reg))
    for k in gain:
        pre, reg = split(k[1])
        if reg is not None:
            by_pc_gain[(k[0], pre)].append((k, reg))

    pairs = []
    for slot, ls in by_pc_lost.items():
        gs = by_pc_gain.get(slot)
        # 1:1 only.  Two lost and one gained at the same (pc, family) is not
        # a rename this instrument is willing to assert.
        if not gs or len(ls) != 1 or len(gs) != 1:
            continue
        (lk, lreg), (gk, greg) = ls[0], gs[0]
        if lreg == greg:
            continue
        same = str(a[lk]).replace(lreg, greg) == str(b[gk])
        pairs.append((slot[0], slot[1], lreg, greg, same))
    return pairs


def run(before, after, isas, suffix, show=12, quiet=False, verdicts=None):
    """Returns (exit_code, totals).

    @verdicts, when given, is a path to write the per-key verdict file
    that --compare reads.  A pass banks that beside its report so the
    NEXT pass can compare readings at matched coverage instead of
    diffing report bytes.
    """
    reasons = []
    vrows = []
    tot = collections.Counter()
    if not quiet:
        # WHERE THIS READING WAS TAKEN FROM (#327).  The x86_64 CHANGED
        # column moves with the harness's working directory; the stamp is
        # part of the number.  See L.cwd_stamp().
        print(L.cwd_stamp())
    for isa in isas:
        pa = L.keyfile(before, isa, suffix)
        pb = L.keyfile(after, isa, suffix)
        a = L.load_key(pa)
        b = L.load_key(pb)
        ok_a = L.require_subject(a, "%s BEFORE arm (%s)" % (isa, pa), reasons)
        ok_b = L.require_subject(b, "%s AFTER arm (%s)" % (isa, pb), reasons)
        if not (ok_a and ok_b):
            if not quiet:
                print("%-8s NOT SCORED -- vacuity (see below)" % isa)
            continue
        common, changed, lost, gain, floor, cov = compare(a, b)
        pairs = rename_pairs(lost, gain, a, b)
        vrows.extend(verdict_rows(isa, a, b))
        if not quiet:
            fam = collections.Counter(k[1] for k in changed)
            print("%-8s arms=%d/%d common=%-6d CHANGED=%-4d REAL-LOST=%-4d "
                  "REAL-GAIN=%-4d floor(pc-only-one-arm)=%d"
                  % (isa, len(a), len(b), len(common), len(changed),
                     len(lost), len(gain), floor))
            # THE COVERAGE, printed BESIDE the verdict and never below
            # it, because the verdict is only about the compared set.
            print("         " + cov_line(isa, cov))
            if pairs:
                # REPORTED, NEVER SUBTRACTED -- see rename_pairs().
                ident = sum(1 for p in pairs if p[4])
                regs = collections.Counter((p[2], p[3]) for p in pairs)
                print("           RENAME-PAIRED %d of REAL-LOST %d "
                      "(payload identical modulo the rename: %d) -- reported, "
                      "NOT subtracted"
                      % (len(pairs), len(lost), ident))
                for (o, n), c in sorted(regs.items(), key=lambda kv: -kv[1]):
                    print("             %-14s -> %-14s %d" % (o, n, c))
            for f, n in sorted(fam.items(), key=lambda kv: -kv[1]):
                print("           CHANGED by family: %-18s %d" % (f, n))
            for tag, rows, src in (("REAL-LOST", lost, a), ("REAL-GAIN", gain, b)):
                for k in rows:
                    print("     %s %s %s %s" % (tag, k[0], k[1], src[k]))
            for k in changed[:show]:
                print("     CHANGED %s %s  %s -> %s" % (k[0], k[1], a[k], b[k]))
        tot["common"] += len(common)
        tot["chg"] += len(changed)
        tot["lost"] += len(lost)
        tot["gain"] += len(gain)
        tot["floor"] += floor
        tot["renamed"] += len(pairs)
        tot["renamed_identical"] += sum(1 for p in pairs if p[4])
        tot["scored"] += 1
        tot["compared_pcs"] += len(cov["compared_pcs"])
        tot["skipped_pcs"] += len(cov["baseline_pcs"] ^ cov["after_pcs"])
    if verdicts and vrows:
        write_verdicts(verdicts, vrows)
    if not quiet:
        print("TOTAL scored_isas=%d common=%d CHANGED=%d REAL-LOST=%d "
              "REAL-GAIN=%d floor=%d"
              % (tot["scored"], tot["common"], tot["chg"], tot["lost"],
                 tot["gain"], tot["floor"]))
        print("TOTAL COVERAGE compared_pcs=%d skipped_floor_pcs=%d -- every "
              "verdict above is about the COMPARED set alone.  The skipped "
              "set is not stable run to run (PASS 34), so two readings are "
              "compared with --compare, never as report bytes."
              % (tot["compared_pcs"], tot["skipped_pcs"]))
        if tot["renamed"]:
            print("TOTAL RENAME-PAIRED=%d (payload identical modulo the "
                  "rename: %d) -- reported, NOT subtracted from REAL-LOST"
                  % (tot["renamed"], tot["renamed_identical"]))
    rc = L.report_vacuity(reasons) if not quiet else (2 if reasons else 0)
    return rc, tot


# --------------------------------------------------------------------------
# selftest

def _plant(root, name, rows):
    d = os.path.join(root, name)
    os.makedirs(d, exist_ok=True)
    return d


def _write(d, isa, rows, suffix=".key"):
    L.write_tsv(os.path.join(d, "%s_none__%s" % (isa, suffix)), rows)


def selftest():
    checks = []
    tmp = tempfile.mkdtemp(prefix="setproof_selftest_")
    try:
        base = {("0x1000", "dst_dep"): ("RAW=0x1", "NAME=rax"),
                ("0x1000", "store_data_dep"): ("RAW=0x2", "NAME=rbx"),
                ("0x1004", "dst_dep"): ("RAW=0x4", "NAME=rcx")}

        # ARM 1: identical -- everything zero, exit 0, and the arms had rows.
        A = _plant(tmp, "A", None); B = _plant(tmp, "B", None)
        for isa in ("x86_64",):
            _write(A, isa, base); _write(B, isa, base)
        rc, tot = run(A, B, ["x86_64"], ".key", quiet=True)
        checks.append(("identical arms score clean and exit 0",
                       rc == 0 and tot["chg"] == 0 and tot["common"] == 3,
                       "rc=%d common=%d changed=%d" % (rc, tot["common"], tot["chg"])))

        # ARM 2: PLANTED VACUITY -- the AFTER arm is empty.  The pre-#235
        # instrument printed common=0 floor=3 and exited 0.
        C = _plant(tmp, "C", None)
        _write(C, "x86_64", {})
        rc, tot = run(A, C, ["x86_64"], ".key", quiet=True)
        checks.append(("PLANTED empty AFTER arm FAILS (never a floor)",
                       rc != 0 and tot["scored"] == 0,
                       "rc=%d scored_isas=%d floor=%d"
                       % (rc, tot["scored"], tot["floor"])))

        # ARM 3: PLANTED VACUITY -- the arm was never produced at all.
        D = _plant(tmp, "D", None)
        rc, tot = run(A, D, ["x86_64"], ".key", quiet=True)
        checks.append(("PLANTED missing AFTER arm FAILS",
                       rc != 0 and tot["scored"] == 0,
                       "rc=%d scored_isas=%d" % (rc, tot["scored"])))

        # ARM 4: PLANTED FLOOR-AS-REGRESSION -- a PC present in one arm only
        # must land in FLOOR, never in REAL-LOST.
        E = _plant(tmp, "E", None)
        floored = dict(base)
        del floored[("0x1004", "dst_dep")]
        floored[("0x2000", "dst_dep")] = ("RAW=0x9", "NAME=rdx")
        _write(E, "x86_64", floored)
        rc, tot = run(A, E, ["x86_64"], ".key", quiet=True)
        checks.append(("PLANTED build-noise PC scores FLOOR, not REAL-LOST",
                       rc == 0 and tot["lost"] == 0 and tot["gain"] == 0
                       and tot["floor"] == 2,
                       "rc=%d lost=%d gain=%d floor=%d"
                       % (rc, tot["lost"], tot["gain"], tot["floor"])))

        # ARM 5: a genuine family loss at a COMMON pc is REAL-LOST, and the
        # floor column must not absorb it.
        F = _plant(tmp, "F", None)
        real = dict(base)
        del real[("0x1000", "store_data_dep")]
        _write(F, "x86_64", real)
        rc, tot = run(A, F, ["x86_64"], ".key", quiet=True)
        checks.append(("a real family loss at a common PC is REAL-LOST",
                       rc == 0 and tot["lost"] == 1 and tot["floor"] == 0,
                       "rc=%d lost=%d floor=%d"
                       % (rc, tot["lost"], tot["floor"])))

        # ARM 6: a content change at a common key is CHANGED.
        G = _plant(tmp, "G", None)
        chg = dict(base)
        chg[("0x1000", "dst_dep")] = ("RAW=0x2", "NAME=rbx")
        _write(G, "x86_64", chg)
        rc, tot = run(A, G, ["x86_64"], ".key", quiet=True)
        checks.append(("a content change at a common key is CHANGED",
                       rc == 0 and tot["chg"] == 1,
                       "rc=%d changed=%d" % (rc, tot["chg"])))

        # ARM 7: one ISA vacuous among several still FAILS the whole run --
        # a per-ISA hole may not be averaged away by its siblings.
        H = _plant(tmp, "H", None); I2 = _plant(tmp, "I", None)
        for isa in ("x86_64", "aarch64"):
            _write(H, isa, base)
        _write(I2, "x86_64", base)
        _write(I2, "aarch64", {})
        rc, tot = run(H, I2, ["x86_64", "aarch64"], ".key", quiet=True)
        checks.append(("one vacuous ISA among several FAILS the run",
                       rc != 0 and tot["scored"] == 1,
                       "rc=%d scored_isas=%d" % (rc, tot["scored"])))

        # ARM 8: .dkey suffix is honoured (the per-destination-register form).
        J = _plant(tmp, "J", None); K = _plant(tmp, "K", None)
        dk = {("0x1000", "dst_dep@rax"): ("N=rcx", "R=0x1")}
        _write(J, "x86_64", dk, ".dkey"); _write(K, "x86_64", dk, ".dkey")
        rc, tot = run(J, K, ["x86_64"], ".dkey", quiet=True)
        checks.append(("--suffix .dkey scores the per-register form",
                       rc == 0 and tot["common"] == 1,
                       "rc=%d common=%d" % (rc, tot["common"])))

        # ARM: #267 -- A REGISTER RENAME IS NAMED, AND IS NOT SUBTRACTED.
        # The .dkey family key carries the register, so R11's REG_IP->REG_PC
        # moved 562 x86_64 rows from LOST to GAIN at be8767a9aa while the wire
        # lost nothing.  REAL-LOST must still read 1 (no discount, R12.1) AND
        # the pair must be NAMED, with the payload-identity stated.
        M = _plant(tmp, "M", None); N = _plant(tmp, "N", None)
        pre = {("0x1000", "dst_dep@REG_IP"): ("N=REG_SP,REG_IP,IMM", "R=0x7")}
        post = {("0x1000", "dst_dep@REG_PC"): ("N=REG_SP,REG_PC,IMM", "R=0x7")}
        # A second PC keeps both arms non-vacuous and gives the pairing a
        # negative neighbour it must not touch.
        keep = {("0x2000", "dst_dep@REG_GPR0"): ("N=REG_GPR1", "R=0x4")}
        _write(M, "x86_64", {**pre, **keep}, ".dkey")
        _write(N, "x86_64", {**post, **keep}, ".dkey")
        rc, tot = run(M, N, ["x86_64"], ".dkey", quiet=True)
        checks.append(("PLANTED register rename: REAL-LOST is NOT discounted",
                       rc == 0 and tot["lost"] == 1 and tot["gain"] == 1,
                       "rc=%d lost=%d gain=%d" % (rc, tot["lost"], tot["gain"])))
        checks.append(("...and it is NAMED as a rename pair, payload-identical",
                       tot["renamed"] == 1 and tot["renamed_identical"] == 1,
                       "renamed=%d identical=%d"
                       % (tot["renamed"], tot["renamed_identical"])))

        # ARM: A GENUINE LOSS CANNOT HIDE IN THE RENAME COLUMN.  The PC stays
        # in both arms -- otherwise it would score FLOOR and never reach the
        # loss column at all -- but its dst_dep is gone and what appeared in
        # its place belongs to a DIFFERENT family.  The row must still be
        # REAL-LOST, and must NOT be paired: a rename is same-PC AND
        # same-family-prefix, and this is only the first of those.
        P = _plant(tmp, "P", None)
        _write(P, "x86_64",
               {("0x1000", "store_data_dep@REG_GPR3"): ("N=Z", "R=0x8"),
                **keep}, ".dkey")
        rc, tot = run(M, P, ["x86_64"], ".dkey", quiet=True)
        checks.append(("PLANTED genuine loss is NOT paired away",
                       rc == 0 and tot["lost"] == 1 and tot["renamed"] == 0,
                       "rc=%d lost=%d renamed=%d"
                       % (rc, tot["lost"], tot["renamed"])))

        # ARM: an AMBIGUOUS pairing (two lost, one gained at the same PC and
        # family) is NOT claimed as a rename -- the instrument declines rather
        # than guesses, which is what keeps the column trustworthy.
        Q = _plant(tmp, "Q", None); R = _plant(tmp, "R", None)
        amb_a = {("0x3000", "dst_dep@REG_IP"): ("N=A", "R=0x1"),
                 ("0x3000", "dst_dep@REG_SP"): ("N=B", "R=0x2")}
        amb_b = {("0x3000", "dst_dep@REG_PC"): ("N=A", "R=0x1")}
        _write(Q, "x86_64", {**amb_a, **keep}, ".dkey")
        _write(R, "x86_64", {**amb_b, **keep}, ".dkey")
        rc, tot = run(Q, R, ["x86_64"], ".dkey", quiet=True)
        checks.append(("AMBIGUOUS 2-lost/1-gained pairing is DECLINED",
                       tot["lost"] == 2 and tot["renamed"] == 0,
                       "lost=%d renamed=%d" % (tot["lost"], tot["renamed"])))

        # ==================================================================
        # PASS 34, F-B: THE COVERAGE ARMS.  A reading must state what it
        # looked at, and two readings may only be called IDENTICAL when they
        # looked at the same thing.
        # ==================================================================

        # ARM: the report PRINTS its coverage, and the numbers are the real
        # ones -- baseline 2 PCs, after 2 PCs, compared 2, skipped 0 for the
        # identical pair; and the FLOORED pair (ARM 4's shape) must show the
        # skip rather than hide it.
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(A, B, ["x86_64"], ".key")
        cov_same = buf.getvalue()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            run(A, E, ["x86_64"], ".key")
        cov_moved = buf.getvalue()
        checks.append(("the reading PRINTS its coverage beside the verdict",
                       "COVERAGE baseline_pcs=2 after_pcs=2 compared_pcs=2 "
                       "skipped_floor=0" in cov_same,
                       "coverage line present and exact"))
        checks.append(("a MOVED coverage is stated, not hidden in the floor",
                       "compared_pcs=1 skipped_floor=2" in cov_moved,
                       "skipped_floor is non-zero and named"))

        # ARM: two readings with the SAME coverage and the SAME verdicts are
        # the only case allowed to be called IDENTICAL.
        v1 = os.path.join(tmp, "r1.tsv")
        v2 = os.path.join(tmp, "r2.tsv")
        run(A, B, ["x86_64"], ".key", quiet=True, verdicts=v1)
        run(A, B, ["x86_64"], ".key", quiet=True, verdicts=v2)
        rc, ct = compare_readings(load_verdicts(v1), load_verdicts(v2),
                                  quiet=True)
        checks.append(("two readings, same coverage + same verdicts = "
                       "IDENTICAL",
                       rc == 0 and ct["verdict_identical"] == 1
                       and ct["differ"] == 0,
                       "rc=%d identical=%d differ=%d"
                       % (rc, ct["verdict_identical"], ct["differ"])))

        # ARM: THE PLANT THIS WHOLE COLUMN EXISTS FOR.  The second reading's
        # AFTER arm reaches a PC the first never executed -- strncmp's
        # aligned fast path, in miniature -- and agrees on every PC they
        # share.  A byte diff of the two reports calls that a difference; the
        # honest verdict is IDENTICAL-AT-MATCHED-COVERAGE, and the word
        # IDENTICAL must be REFUSED.
        S1 = _plant(tmp, "S1", None)
        S2 = _plant(tmp, "S2", None)
        base2 = dict(base)
        base2[("0x3000", "dst_dep")] = ("RAW=0x8", "NAME=rsi")
        _write(S1, "x86_64", base2)          # baseline: knows 0x3000
        _write(S2, "x86_64", base)           # after run 1: did NOT reach it
        v3 = os.path.join(tmp, "r3.tsv")
        run(S1, S2, ["x86_64"], ".key", quiet=True, verdicts=v3)
        S3 = _plant(tmp, "S3", None)
        _write(S3, "x86_64", base2)          # after run 2: DID reach it
        v4 = os.path.join(tmp, "r4.tsv")
        run(S1, S3, ["x86_64"], ".key", quiet=True, verdicts=v4)
        rc, ct = compare_readings(load_verdicts(v3), load_verdicts(v4),
                                  quiet=True)
        checks.append(("PLANTED coverage move: IDENTICAL is REFUSED",
                       rc == 0 and ct["verdict_identical"] == 0
                       and ct["verdict_matched_only"] == 1
                       and ct["cov_moved"] == 1 and ct["differ"] == 0,
                       "rc=%d identical=%d matched_only=%d cov_moved=%d "
                       "differ=%d" % (rc, ct["verdict_identical"],
                                      ct["verdict_matched_only"],
                                      ct["cov_moved"], ct["differ"])))
        checks.append(("...and the two report BODIES really do differ, so a "
                       "byte diff would have called it a change",
                       open(v3).read() != open(v4).read(),
                       "verdict files differ as bytes"))

        # ARM: a REAL verdict difference at a PC both readings covered is a
        # difference, and exits non-zero -- the coverage column may not
        # absorb it.
        S4 = _plant(tmp, "S4", None)
        moved = dict(base)
        moved[("0x1000", "dst_dep")] = ("RAW=0x99", "NAME=zzz")
        _write(S4, "x86_64", moved)
        v5 = os.path.join(tmp, "r5.tsv")
        run(A, S4, ["x86_64"], ".key", quiet=True, verdicts=v5)
        rc, ct = compare_readings(load_verdicts(v1), load_verdicts(v5),
                                  quiet=True)
        checks.append(("a verdict difference at MATCHED coverage FAILS",
                       rc == 1 and ct["differ"] == 1,
                       "rc=%d differ=%d" % (rc, ct["differ"])))

        # ARM: a missing reading is a REFUSAL, never an empty comparison.
        rc, ct = compare_readings(load_verdicts(v1),
                                  load_verdicts(os.path.join(tmp, "nope.tsv")),
                                  quiet=True)
        checks.append(("a MISSING reading REFUSES, never compares",
                       rc == 2, "rc=%d" % rc))

        # ARM: readings taken against DIFFERENT baselines refuse -- their
        # verdicts are not about the same reference.
        v6 = os.path.join(tmp, "r6.tsv")
        run(S1, S3, ["x86_64"], ".key", quiet=True, verdicts=v6)
        rc, ct = compare_readings(load_verdicts(v1), load_verdicts(v6),
                                  quiet=True)
        checks.append(("readings against DIFFERENT baselines REFUSE",
                       rc == 2, "rc=%d" % rc))

        # ARM: disjoint after-arms -> matched coverage EMPTY -> refuse,
        # because agreement over nothing is not agreement (#235's shape).
        S5 = _plant(tmp, "S5", None)
        S6 = _plant(tmp, "S6", None)
        wide = {("0x1000", "dst_dep"): ("R=1", "N=a"),
                ("0x2000", "dst_dep"): ("R=2", "N=b")}
        _write(S5, "x86_64", wide)
        _write(S6, "x86_64", {("0x1000", "dst_dep"): ("R=1", "N=a")})
        v7 = os.path.join(tmp, "r7.tsv")
        run(S5, S6, ["x86_64"], ".key", quiet=True, verdicts=v7)
        S7 = _plant(tmp, "S7", None)
        _write(S7, "x86_64", {("0x2000", "dst_dep"): ("R=2", "N=b")})
        v8 = os.path.join(tmp, "r8.tsv")
        run(S5, S7, ["x86_64"], ".key", quiet=True, verdicts=v8)
        rc, ct = compare_readings(load_verdicts(v7), load_verdicts(v8),
                                  quiet=True)
        checks.append(("DISJOINT after-arms: empty matched coverage REFUSES",
                       rc == 2, "rc=%d" % rc))

        # #327: the report must carry the directory it was taken from, and
        # the stamp must MOVE when the directory does.
        here = os.getcwd()
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run(A, B, ["x86_64"], ".key")
            printed_here = buf.getvalue()
            os.chdir(tmp)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run(A, B, ["x86_64"], ".key")
            printed_tmp = buf.getvalue()
        finally:
            os.chdir(here)
        checks.append(("#327 the report carries a HARNESS CWD stamp",
                       L.CWD_STAMP_TAG in printed_here
                       and here in printed_here,
                       "tag+path present"))
        checks.append(("#327 the stamp MOVES with the directory",
                       os.path.realpath(tmp) in printed_tmp
                       and here not in printed_tmp,
                       "differs between two cwds"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return L.selftest_report("setproof.py", checks)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("before", nargs="?")
    ap.add_argument("after", nargs="?")
    ap.add_argument("--isas", default=",".join(L.ISAS))
    ap.add_argument("--suffix", default=".key",
                    help=".key (per-family) or .dkey (per destination register)")
    ap.add_argument("--show", type=int, default=12,
                    help="how many CHANGED rows to print per ISA")
    ap.add_argument("--verdicts",
                    help="write the per-key verdict file --compare reads")
    ap.add_argument("--compare", nargs=2, metavar=("A.tsv", "B.tsv"),
                    help="compare two verdict files at MATCHED coverage")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.compare:
        rc, _ = compare_readings(load_verdicts(args.compare[0]),
                                 load_verdicts(args.compare[1]))
        return rc
    if not (args.before and args.after):
        L.die_usage("usage: setproof.py <before-dir> <after-dir> "
                    "[--isas ...] [--suffix .key|.dkey]")
    rc, _ = run(args.before, args.after, args.isas.split(","), args.suffix,
                show=args.show, verdicts=args.verdicts)
    return rc


if __name__ == "__main__":
    sys.exit(main())
