#!/usr/bin/env python3
"""Per-FIELD diff of a QID_SPLIT identity row's candidate classifications.

A QID_SPLIT row says several Capstone constants were observed decoding
through one QEMU decode rule and the classifier gave them different
answers.  That statement is made by comparing the WHOLE `Entry`, so it is
true of a row whose candidates disagree about what the instruction IS and
equally true of a row whose candidates agree on every field the wire
carries and differ only in whether a refiner is named.  Those are not the
same finding and they do not have the same disposition, so the whole-Entry
comparison cannot be the thing an adjudication is written against.

This tool re-runs the generator's own join -- same universe, same corpus,
same `full_entry` classifier -- and prints, per split row, the candidate
set FIELD BY FIELD, with the fields partitioned into

    AGREE     every candidate states the same value
    DIFFER    the candidates state different values

and a verdict word derived from which fields are in DIFFER:

    DEP-REFINER-ONLY  the candidates agree on opcode, branch class, flags
                   and the lane pair, and differ only in whether
                   `.dep_refine` is stated.  `.dep_refine` writes
                   DEPENDENCY MASKS and nothing else, and it is derived
                   from Capstone's per-constant encoding-variant table, so
                   this is a disagreement between two spellings about a
                   Capstone artefact and not about the instruction.  This
                   is the ("x86", 0x1ee) shape, and it is the ONLY shape
                   the standing refiner adjudications were written for.
    REFINE-ONLY    they differ only in `.refine`.  This is NOT the 0x1ee
                   shape and the precedent does not reach it: `.refine`
                   runs FIRST and rewrites the classification itself --
                   refine_arm64_cmp_alias turns GEN_OP_AND into
                   GEN_OP_TEST -- so adopting one candidate's refiner can
                   change the OPCODE the wire publishes for the other's
                   rows.  "The same answer said precisely" is false of it.
    GENUINE        at least one of opcode / branch / flags / lane differs.
                   The candidates disagree about the instruction; the row
                   stays split and carries as a named survivor.

The verdict is an INPUT to an adjudication, never a substitute for one:
DEP-REFINER-ONLY says the row is in the shape a refiner adjudication may
be written for, and the adjudication itself still has to name a QEMU
source fact and still has to survive the wire's own acceptance (the riscv
`ori` lesson -- a candidate the validator rejects is REVERTED, not
argued).

Usage:

    identsplit.py --isa x86 --build-dir <qemu-build> --pairs <tsv>...
    identsplit.py --selftest
"""

import argparse
import importlib.util
import os
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _arc3lib as L                                          # noqa: E402

PLUGIN_DIR = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
GEN = os.path.join(PLUGIN_DIR, "champsim_tracer_mnemonic_audit.py")


def load_generator():
    """Import the generator as a module.  It is the ONE classifier; this
    tool must never carry a second copy of full_entry()."""
    spec = importlib.util.spec_from_file_location("cst_mnemonic_audit", GEN)
    mod = importlib.util.module_from_spec(spec)
    # The generator uses @dataclass, which resolves its own module out of
    # sys.modules; registering before exec is required, not cosmetic.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# The fields of Entry, split by what they say.
#
# INSN_FIELDS are statements about the instruction, and every one of them
# reaches the wire: .op is the published opcode, .branch the published
# transfer class, .flags the memory-op flags, and the lane pair decides
# whether lane-mask FID records are produced at all.
#
# The two refiner fields are NOT interchangeable and the tool must not
# treat them as one bucket.  `.dep_refine` writes dependency masks only.
# `.refine` runs first and rewrites the classification -- opcode
# included -- so a `.refine` disagreement is a disagreement about what
# the wire will say, even when every other field agrees.
INSN_FIELDS = ("op", "branch", "flags", "lane_mask_kind", "lane_parallel")
DEP_REFINER_FIELDS = ("dep_refine",)
REFINE_FIELDS = ("refine",)
ALL_FIELDS = INSN_FIELDS + REFINE_FIELDS + DEP_REFINER_FIELDS


def split_rows(mod, isa_key, build_dir, pair_paths):
    """Every QID_SPLIT row of one ISA, with its candidates.

    Returns [(ident, pattern, {const: Entry})].  Built from the generator's
    own universe/observation/classifier path so the candidate set is
    exactly the one the emitted header's SPLIT comment was built from.
    """
    info = mod.ISAS[isa_key]
    idents = mod.qemu_ident_universe(build_dir, isa_key)
    mine = [p for p in pair_paths if mod._observed_matches_isa(Path(p), isa_key)]
    if not mine:
        raise SystemExit("identsplit: no pair-census file matches isa %s -- "
                         "an empty corpus would report every row as having "
                         "no candidates, which is a vacuous zero, not a "
                         "measurement" % isa_key)
    obs = mod.load_pairs([Path(p) for p in mine])
    existing = mod.parse_existing(info)
    v2c = mod.enum_value_map(info)
    out = []
    for ident in sorted(idents, key=lambda r: r.ident):
        seen = obs.get(ident.ident)
        if not seen:
            continue
        cands = {}
        for cap, _n in seen["caps"].most_common():
            const = v2c.get(cap)
            if const is None:
                continue
            e = mod.full_entry(info, const, existing)
            if e is None:
                continue
            cands[const] = e
        if len({tuple(getattr(e, f) for f in ALL_FIELDS)
                for e in cands.values()}) > 1:
            out.append((ident.ident, ident.pattern, cands))
    return out


def field_diff(cands):
    """Partition the fields into AGREE and DIFFER, and give the verdict."""
    agree, differ = {}, {}
    for f in ALL_FIELDS:
        vals = {getattr(e, f) for e in cands.values()}
        if len(vals) == 1:
            agree[f] = next(iter(vals))
        else:
            differ[f] = {c: getattr(e, f) for c, e in cands.items()}
    if any(f in INSN_FIELDS for f in differ):
        verdict = "GENUINE"
    elif any(f in REFINE_FIELDS for f in differ):
        verdict = "REFINE-ONLY"
    else:
        verdict = "DEP-REFINER-ONLY"
    return agree, differ, verdict


def report(mod, isa_key, build_dir, pair_paths, counts=None):
    rows = split_rows(mod, isa_key, build_dir, pair_paths)
    print("===== %s: %d split row(s) =====" % (isa_key, len(rows)))
    tally = {"DEP-REFINER-ONLY": 0, "REFINE-ONLY": 0, "GENUINE": 0}
    for ident, pattern, cands in rows:
        agree, differ, verdict = field_diff(cands)
        dyn = ""
        if counts and ident in counts:
            dyn = "   %d dynamic row(s)" % counts[ident]
        tally[verdict] += 1
        print("\n  0x%08x  %-46s %s%s" % (ident, pattern, verdict, dyn))
        print("    candidates: %s" % ", ".join(sorted(cands)))
        print("    AGREE  : %s" % ", ".join(
            "%s=%s" % (f, agree[f]) for f in ALL_FIELDS if f in agree))
        for f in ALL_FIELDS:
            if f in differ:
                print("    DIFFER : %-14s %s" % (f, "  |  ".join(
                    "%s=%s" % (c, v) for c, v in sorted(differ[f].items()))))
    print("\n  %s: DEP-REFINER-ONLY %d, REFINE-ONLY %d, GENUINE %d"
          % (isa_key, tally["DEP-REFINER-ONLY"], tally["REFINE-ONLY"],
             tally["GENUINE"]))
    return rows


# --------------------------------------------------------------- selftest
def selftest():
    """Two planted arms and one real one.

    The tool's whole job is to tell a refiner-only split from a genuine
    one, so both directions are planted, and the vacuity refusal is
    exercised because a corpus that matches no ISA would otherwise print
    a clean "0 split rows"."""
    checks = []

    class E:                       # a stand-in Entry with the same fields
        def __init__(self, op, branch="BRANCH_NONE", flags="MF_NONE",
                     refine=None, dep_refine=None,
                     lane_mask_kind="LANE_MASK_KIND_NONE",
                     lane_parallel=False):
            self.op, self.branch, self.flags = op, branch, flags
            self.refine, self.dep_refine = refine, dep_refine
            self.lane_mask_kind, self.lane_parallel = (lane_mask_kind,
                                                       lane_parallel)

    a, d, v = field_diff({"A": E("GEN_OP_SHL"),
                          "B": E("GEN_OP_SHL", dep_refine="dep_passthrough")})
    checks.append(("a dep_refine-only split is DEP-REFINER-ONLY",
                   v == "DEP-REFINER-ONLY" and list(d) == ["dep_refine"],
                   "verdict=%s differ=%s" % (v, sorted(d))))
    checks.append(("its agreeing fields are reported as AGREE",
                   a.get("op") == "GEN_OP_SHL" and "branch" in a,
                   "agree=%s" % sorted(a)))

    a, d, v = field_diff({"A": E("GEN_OP_MOV"), "B": E("GEN_OP_VEC_MOV")})
    checks.append(("opcode split is called GENUINE",
                   v == "GENUINE" and list(d) == ["op"],
                   "verdict=%s differ=%s" % (v, sorted(d))))

    a, d, v = field_diff({"A": E("GEN_OP_MOV", lane_parallel=True),
                          "B": E("GEN_OP_MOV", lane_parallel=False)})
    checks.append(("a lane-pair-only split is GENUINE, not refiner-only",
                   v == "GENUINE",
                   "verdict=%s differ=%s" % (v, sorted(d))))

    a, d, v = field_diff({"A": E("GEN_OP_MOV", refine="r1", dep_refine="d1"),
                          "B": E("GEN_OP_MOV", refine="r2", dep_refine="d1")})
    checks.append((".refine alone is REFINE-ONLY, NOT the 0x1ee shape -- "
                   "an opcode-rewriting refiner is not 'the same answer "
                   "said precisely'",
                   v == "REFINE-ONLY" and list(d) == ["refine"],
                   "verdict=%s differ=%s" % (v, sorted(d))))

    # Vacuity: a corpus with no file for the ISA must REFUSE, not print 0.
    mod = load_generator()
    empty = tempfile.mkdtemp(prefix="identsplit_selftest_")
    ok = False
    try:
        split_rows(mod, "x86", Path(os.environ.get("CST_BUILD_DIR",
                                                     "/mnt/md0/QEMU/qemu/build")),
                   [os.path.join(empty, "pairs_riscv64_none.tsv")])
    except SystemExit as e:
        ok = "no pair-census file matches" in str(e)
    checks.append(("an ISA with no corpus file REFUSES rather than "
                   "reporting zero split rows", ok, "raised=%s" % ok))

    return L.selftest_report("identsplit.py", checks)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--isa", action="append",
                    help="generator ISA key (x86/aarch64/riscv/mips); repeatable")
    ap.add_argument("--build-dir")
    ap.add_argument("--pairs", nargs="*", default=[])
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.isa or not args.build_dir:
        ap.error("--isa and --build-dir are required")
    mod = load_generator()
    for key in args.isa:
        report(mod, key, Path(args.build_dir), args.pairs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
