#!/usr/bin/env python3
"""The absolute no-dependency census -- the #230-class standing gate.

Supersedes exec27b/verify/nodep_census.py and its per-wave copies.

WHY AN ABSOLUTE CENSUS EXISTS AT ALL.  #230 was an x86_64 direct callq
publishing its return-address store-data dependency as the IMMEDIATE bit
instead of REG_IP, and its INDIRECT sibling publishing an empty mask.  Every
J3 arm was blind to it, and blind for a structural reason worth writing
down: J3 measures COUPLING -- whether a fact MOVES when Capstone is
corrupted -- and a fact that is uniformly wrong in BOTH arms does not move.
340 rows were false in the unmutated arm and false in exactly the same way
in the mutated one, so the coupling score was a correct zero about an
incorrect wire.

The census that does see it is absolute, not differential: for every
PUBLISHED dependency slot, what CLASS of input does its mask resolve to,
grouped by the instruction's own opcode and branch class.  A slot naming no
architectural register -- EMPTY, or IMM alone -- is the signature.  Reading
this table at the base tip would have printed

    BRANCH_DIRECT_CALL    store_data_dep  IMM     294
    BRANCH_INDIRECT_CALL  store_data_dep  EMPTY    46

and no reader could have called a call's pushed return address an immediate.

Input is a `.key` file from keyfacts.py: the `<fam>@shape` rows joined
against the F_opcode / F_branch rows.  EVERY class is reported so the zero
rows are visible too -- a census that only prints its own alarm cannot be
told apart from a census that did not run.

VACUITY (#235).  A key file with no shape rows is a FAILURE: a census with
no subject is not a clean census.  --require-fams names the families that
must have at least one subject, so a family that silently left the wire
cannot read as "no alarms".

Usage:  nodep_census.py <key-file> [--require-fams f,f] [--max-noreg N]
        nodep_census.py --selftest
"""
import argparse
import collections
import os
import shutil
import sys
import tempfile

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import _arc3lib as L  # noqa: E402

FAMS = list(L.DEP_FAMILIES)
NOREG = ("EMPTY", "IMM")


def census(path, require_fams=(), quiet=False):
    """Returns (rc, total_counter, noreg_counter)."""
    reasons = []
    rows = L.load_key(path)
    if not L.require_subject(rows, "census input (%s)" % path, reasons):
        if not quiet:
            L.report_vacuity(reasons)
        return 2, collections.Counter(), collections.Counter()

    op, br, shp = {}, {}, collections.defaultdict(dict)
    for (pc, fact), (val, _) in rows.items():
        if fact == "F_opcode":
            op[pc] = val[2:]
        elif fact == "F_branch":
            br[pc] = val[2:]
        elif fact.endswith("@shape"):
            shp[fact[:-6]][pc] = val[2:]

    tot = collections.Counter()
    noreg = collections.Counter()
    for fam in FAMS:
        for pc, v in shp.get(fam, {}).items():
            key = (op.get(pc, "?"), br.get(pc, "?"), fam)
            for slot in v.split(" | "):
                slot = slot.strip()
                tot[(key, slot)] += 1
                if slot in NOREG:
                    noreg[(key, slot)] += 1

    for fam in require_fams:
        if not shp.get(fam):
            reasons.append("VACUITY FAILURE: family %s has no published slot "
                           "in %s -- a census with no subject is not a clean "
                           "census." % (fam, os.path.basename(path)))

    if not quiet:
        print("=== ALL published dependency slots, by "
              "(opcode, branch_type, family, class) ===")
        for (key, slot), n in sorted(tot.items(), key=lambda kv: -kv[1]):
            o, b, fam = key
            print("%8d  %-16s %-22s %-16s %s" % (n, o, b, fam, slot))
        print("\n=== SLOTS NAMING NO ARCHITECTURAL REGISTER "
              "(the #230 signature) ===")
        if not noreg:
            print("  none")
        for (key, slot), n in sorted(noreg.items(), key=lambda kv: -kv[1]):
            o, b, fam = key
            print("%8d  %-16s %-22s %-16s %s" % (n, o, b, fam, slot))
        print("\nTOTAL published slots: %d" % sum(tot.values()))
        print("TOTAL slots naming no architectural register: %d"
              % sum(noreg.values()))
    rc = L.report_vacuity(reasons) if not quiet else (2 if reasons else 0)
    return rc, tot, noreg


# --------------------------------------------------------------------------
# selftest

GOOD = {
    ("0x1000", "F_opcode"): ("V=OP_CALL", "-"),
    ("0x1000", "F_branch"): ("V=BRANCH_DIRECT_CALL", "-"),
    ("0x1000", "store_data_dep@shape"): ("V=REG", "-"),
    ("0x1000", "dst_dep@shape"): ("V=REG", "-"),
    ("0x1000", "load_addr_dep@shape"): ("V=REG", "-"),
    ("0x1000", "store_addr_dep@shape"): ("V=REG", "-"),
}
# The #230 wire: the call's pushed return address published as an immediate,
# and its indirect sibling published empty.
BAD = dict(GOOD)
BAD[("0x1000", "store_data_dep@shape")] = ("V=IMM", "-")
BAD[("0x1008", "F_opcode")] = ("V=OP_CALL", "-")
BAD[("0x1008", "F_branch")] = ("V=BRANCH_INDIRECT_CALL", "-")
BAD[("0x1008", "store_data_dep@shape")] = ("V=EMPTY", "-")


def selftest():
    checks = []
    tmp = tempfile.mkdtemp(prefix="nodep_census_selftest_")
    try:
        good = os.path.join(tmp, "good.key")
        bad = os.path.join(tmp, "bad.key")
        empty = os.path.join(tmp, "empty.key")
        nofam = os.path.join(tmp, "nofam.key")
        L.write_tsv(good, GOOD)
        L.write_tsv(bad, BAD)
        L.write_tsv(empty, {})
        L.write_tsv(nofam, {k: v for k, v in GOOD.items()
                            if not k[1].startswith("store_data_dep")})

        rc, tot, noreg = census(good, FAMS, quiet=True)
        checks.append(("clean wire: rc=0, every family has a subject, 0 noreg",
                       rc == 0 and sum(tot.values()) == 4
                       and sum(noreg.values()) == 0,
                       "rc=%d slots=%d noreg=%d"
                       % (rc, sum(tot.values()), sum(noreg.values()))))

        # PLANTED DEFECT 1 -- the #230 wire itself.  A differential scorer
        # scores zero on this because both arms are equally wrong.
        rc, tot, noreg = census(bad, (), quiet=True)
        got = {(k[1], slot): n for (k, slot), n in noreg.items()}
        checks.append(("PLANTED #230 wire: IMM + EMPTY call slots are NAMED",
                       got.get(("BRANCH_DIRECT_CALL", "IMM")) == 1
                       and got.get(("BRANCH_INDIRECT_CALL", "EMPTY")) == 1,
                       "noreg=%s" % sorted(got.items())))

        # PLANTED DEFECT 2 -- VACUITY.  An empty key file is a failure, not
        # a census with no alarms.
        rc, tot, noreg = census(empty, (), quiet=True)
        checks.append(("PLANTED empty key file FAILS (not 'no alarms')",
                       rc != 0 and sum(tot.values()) == 0,
                       "rc=%d slots=%d" % (rc, sum(tot.values()))))

        # PLANTED DEFECT 3 -- a required family with no subject at all.
        rc, tot, noreg = census(nofam, FAMS, quiet=True)
        checks.append(("PLANTED family with no subject FAILS --require-fams",
                       rc != 0, "rc=%d" % rc))
        rc2, _, _ = census(nofam, (), quiet=True)
        checks.append(("...and without --require-fams the same file passes, "
                       "which is why the flag exists",
                       rc2 == 0, "rc=%d" % rc2))

        # A missing file is a failure with its own reason, not a crash.
        rc, _, _ = census(os.path.join(tmp, "nope.key"), (), quiet=True)
        checks.append(("PLANTED missing key file FAILS", rc != 0, "rc=%d" % rc))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return L.selftest_report("nodep_census.py", checks)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("keyfile", nargs="?")
    ap.add_argument("--require-fams", default="",
                    help="comma-separated families that MUST have a subject")
    ap.add_argument("--max-noreg", type=int, default=None,
                    help="fail when more than N slots name no architectural "
                         "register (use 0 to gate the #230 class at zero)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.keyfile:
        L.die_usage("usage: nodep_census.py <key-file>")
    fams = [f for f in args.require_fams.split(",") if f]
    rc, tot, noreg = census(args.keyfile, fams)
    if args.max_noreg is not None and sum(noreg.values()) > args.max_noreg:
        print("GATE FAILURE: %d slots name no architectural register "
              "(limit %d)" % (sum(noreg.values()), args.max_noreg))
        rc = rc or 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
