"""Shared primitives for the ARC-3 measurement instruments.

Every scorer in this directory reads the same TSV shape and obeys the same
rule about an absent subject, so both live here rather than in five copies
that drift.

THE RULE (#235/#238).  An empty comparison side is a FAILURE, never a floor.
The two-column ancestor of setproof.py, handed an arm with no rows, reported
the whole opposite side as "build noise" and exited 0 -- clean zeros from a
comparison that had no subject, which is indistinguishable in a report from
a flip that genuinely moved nothing.  So every scorer here calls
`require_subject()` on both arms of every comparison before it scores
anything, and a violation is named, printed, and carried into the exit code.
"""
import os
import sys

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")

#: The J3 mutation battery's arms.  `none__` is the unmutated reference and
#: `mnem__` is the live control -- a run in which nothing moved says nothing
#: unless the control moved in the same run.
ARMS = ("implic", "memdir", "access", "mnem__")

#: THE DESTINATION FAMILY'S ARMS, and they are not the same list (#249).
#: `mnem__` cannot serve here: blanking the opcode taxonomy makes the refiner
#: emit no dep block at all, so on aarch64 / riscv64 / mipsel the control arm
#: had no subject and every dst zero on those ISAs was unquotable.  Two arms
#: replace it and between them they partition the wire's destination
#: population by SOURCE:
#:
#:   dstmsk  the CONTROL.  Moves the mask at the line that publishes it, so
#:           its subject is every destination QEMU's provenance decided.
#:   refmsk  a TEST arm.  Moves the REFINER's mask in the window before
#:           qdep_apply() overwrites it, so its subject is every destination
#:           the wire still takes from Capstone.
#:
#: The two are disjoint and exhaustive by construction, which is a standing
#: self-check: their mover counts must sum to the scored row count.
DST_ARMS = ("implic", "memdir", "access", "refmsk", "dstmsk")
DST_CONTROL = "dstmsk"

#: The four published dependency families.
DEP_FAMILIES = ("dst_dep", "store_data_dep", "load_addr_dep", "store_addr_dep")

#: Identity facts.  These are what the `mnem` control arm is expected to move.
IDENT_FACTS = ("F_opcode", "F_branch", "F_length", "F_slots", "F_depflags")


class Vacuity(Exception):
    """A comparison side with no subject.  Never a zero, never a floor."""


def load_key(path):
    """Load a TSV key file: (col0, col1) -> (col2, col3).

    Returns None when the file does not exist -- callers must distinguish
    "the arm was never produced" from "the arm produced nothing", because
    both are failures but they have different causes.
    """
    if not os.path.exists(path):
        return None
    rows = {}
    with open(path) as fh:
        for line in fh:
            f = line.rstrip("\n").split("\t")
            if len(f) >= 4:
                rows[(f[0], f[1])] = (f[2], f[3])
    return rows


def keyfile(directory, isa, suffix=".key"):
    """The conventional key-file name for @isa under @directory.

    Accepts both the battery's `<isa>_none__<suffix>` naming and the bare
    `<isa><suffix>` used by the two-build A/B waves.
    """
    for cand in ("%s_none__%s" % (isa, suffix), "%s%s" % (isa, suffix)):
        p = os.path.join(directory, cand)
        if os.path.exists(p):
            return p
    return os.path.join(directory, "%s_none__%s" % (isa, suffix))


def require_subject(rows, label, reasons):
    """Record a vacuity failure unless @rows has at least one row.

    @rows is None when the file is missing and {} when it is empty; both are
    failures and both are named as such.  Returns True when the side has a
    subject.
    """
    if rows is None:
        reasons.append("VACUITY FAILURE: %s -- the arm was never produced "
                       "(no such file).  A comparison with no subject is not "
                       "a zero." % label)
        return False
    if not rows:
        reasons.append("VACUITY FAILURE: %s -- the arm produced 0 rows.  An "
                       "empty side is a FAILURE, never a floor." % label)
        return False
    return True


#
# THE SHARE OF THE REFERENCE A COMPARISON MUST COVER BEFORE ITS ZERO MEANS
# ANYTHING.  Stated as a constant so the bar is a number in the source and
# not a judgement made per wave.
#
OVERLAP_FLOOR = 0.99


def require_overlap(rows, label, reasons, base_rows=None,
                    floor=OVERLAP_FLOOR):
    """Record a vacuity failure when a comparison scored too little subject.

    THE SECOND FLOOR, one level below require_subject() (#249).  An arm can
    produce a file full of rows and still share not one PC with the
    reference -- measured, and not hypothetically: under the `access`
    mutation the aarch64 and mipsel destination lists empty and refill with
    a disjoint set, so the reference's 882 / 1,555 PCs and the arm's 457 /
    959 intersect in ZERO.  The scorer printed `rows=0 name_moved=0` for
    those cells, which passes require_subject() (the file is not empty) and
    reads exactly like a clean inert arm.  A comparison whose scored
    population is empty is a comparison with no subject, whatever the file
    sizes were.

    AND AN EMPTY INTERSECTION IS THE DEGENERATE CASE, NOT THE CONDITION
    (#257, measured 2026-08-27).  The rows==0 test caught those cells only
    because the intersection happened to be exactly zero at the sha it was
    written against.  At `685914abf2` the emission flip grew the published
    destination population three-fold, the same arms began to intersect
    PARTIALLY, and the guard fell silent while the cells stayed just as
    unquotable: `access` covered 45.6 / 20.6 / 32.7 / 17.0 % of the
    reference on x86_64 / aarch64 / riscv64 / mipsel and printed clean
    zeros for three of them.  A zero over a fifth of the population is not
    a statement about the family; the protection at rows==0 was accidental.

    So the bar is the SHARE COVERED, with the empty case kept as its own
    message because it is a different failure to read.  `base_rows` is the
    reference's own row count; pass it and the fraction is checked, omit it
    and only the degenerate case is (which is what the callers that predate
    this did).
    """
    if rows == 0:
        reasons.append("VACUITY FAILURE: %s -- the arm and the reference "
                       "share no PC, so 0 rows were scored.  A comparison "
                       "with an empty intersection is not a zero." % label)
        return False
    if base_rows:
        cov = float(rows) / float(base_rows)
        if cov < floor:
            reasons.append("VACUITY FAILURE: %s -- the comparison covers "
                           "%.1f%% of the reference (%d of %d rows), below "
                           "the %.1f%% floor.  A zero over a subset this "
                           "small is not a statement about the family."
                           % (label, 100.0 * cov, rows, base_rows,
                              100.0 * floor))
            return False
    return True


def report_vacuity(reasons):
    """Print every recorded vacuity failure.  Returns a suggested exit code."""
    if not reasons:
        return 0
    print("")
    print("=== VACUITY FAILURES (#235): a comparison with no subject ===")
    for r in reasons:
        print("  " + r)
    print("These are FAILURES.  The zeros printed above them, if any, were "
          "produced by an absent arm and mean nothing.")
    return 2


#: The stamp every scorer prints above its table (#327).
CWD_STAMP_TAG = "HARNESS CWD:"


def cwd_stamp():
    """The working directory a reading was taken from, as a header block.

    WHY A NUMBER FROM THESE TOOLS IS NOT PORTABLE BETWEEN DIRECTORIES (#327).
    qemu-user copies the host environment onto the guest's starting stack,
    and the working directory is part of that environment, so a run started
    from a longer path puts every guest stack address somewhere else.  On
    x86_64 that moves which instructions the corpus reaches: the source
    census and SETPROOF's CHANGED column were measured at 576/3491 from
    .../p3/arc3 and 577/3489 from .../exec45/verify24 -- same commit, same
    binaries, each reading exactly repeatable inside its own directory.
    PASS 23 saw the spread, checked repeatability, and concluded it was a
    source difference between tips; it was not.  The same carrier is #294's,
    which found it for the OUTPUT directory.

    So the directory is not context, it is part of the reading, and it is
    printed with the reading rather than left to a pass to remember.  A
    comparison between two numbers carrying different stamps is not a
    comparison.
    """
    return ("# %s %s\n"
            "#   (#327) qemu-user puts the host environment, working "
            "directory included,\n"
            "#   on the guest's starting stack, so x86_64 columns move with "
            "this path.\n"
            "#   Compare only against a reading carrying the SAME stamp."
            % (CWD_STAMP_TAG, os.getcwd()))


def selftest_report(name, checks):
    """Print and adjudicate a list of (label, ok, detail) selftest checks."""
    bad = 0
    print("=== %s --selftest ===" % name)
    for label, ok, detail in checks:
        print("  %-4s %-52s %s" % ("PASS" if ok else "FAIL", label, detail))
        if not ok:
            bad += 1
    print("%s selftest: %d check(s), %d failure(s)" % (name, len(checks), bad))
    return 1 if bad else 0


def tsv(rows):
    """Render a {(a,b): (c,d)} mapping back to the TSV text form."""
    return "".join("%s\t%s\t%s\t%s\n" % (a, b, c, d)
                   for (a, b), (c, d) in sorted(rows.items()))


def write_tsv(path, rows):
    with open(path, "w") as fh:
        fh.write(tsv(rows))


def die_usage(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)
