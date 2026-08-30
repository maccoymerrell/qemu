#!/usr/bin/env python3
#
# merge_ident_pairs.py -- keep the pair census the identity tables rest on
# inside the tree, and never let it narrow.
#
# WHY THIS EXISTS.  champsim_tracer_qemu_ident_<isa>.h is generated from a
# PAIR CENSUS: the (QEMU decode id, QEMU decode name, Capstone insn id,
# count) join the tracer writes when CST_QEMU_IDENT_PAIRS is set.  A rule the
# census reaches is QID_OBSERVED and answers; a rule it does not reach is
# QID_NAME_MATCHED or QID_NONE, says nothing, and every instruction decoding
# through it falls back to the Capstone table.
#
# That makes the census load-bearing, and until this file existed it lived
# nowhere: each regeneration used whatever run directories the author had to
# hand.  EXEC57 measured the consequence and refused to regenerate -- a fresh
# whole-battery corpus reached FEWER rules than the shipped tables carry
# (x86 302 -> 230 QID_OBSERVED, riscv 143 -> 127, mips 101 -> 85), so applying
# it would have DEMOTED 104 rows that already answer.  A generated file whose
# content depends on which programs happened to run that day is not
# reproducible, and one that silently loses rows is worse.
#
# So the census is banked here, in the tree, and it only ever GROWS:
# `merge` folds new run output into the bank as a union.  A rule that has ever
# been observed stays observed.
#
# THE STALENESS GUARD, and it is the reason the census carries the NAME beside
# the id.  A decode id is not stable across source edits, and on i386 it is
# literally __LINE__ in decode-new.c.inc -- inserting a line in that file
# renumbers every slot after it.  A banked record whose id now belongs to a
# DIFFERENT rule would attach an old observation to a new rule, which is a
# fabricated decode.  `verify` therefore checks every banked id against the
# universe the current build's decoders declare and REFUSES on any name
# disagreement.  The generator makes the same check before it reads a row.
#
# USAGE
#   merge_ident_pairs.py merge  --isa x86 <run.tsv>...   fold into the bank
#   merge_ident_pairs.py verify --build-dir <dir>        bank vs the universe
#   merge_ident_pairs.py --selftest
#
# rc=2 is "this could not run" and is never folded into rc=0.
#
# Author: Maccoy Merrell.

import argparse
import collections
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN_DIR = HERE.parent
BANK_DIR = PLUGIN_DIR / "ident_corpus"

ISAS = ("x86", "aarch64", "riscv", "mips")

HEADER = """\
# QEMU decode-identity / Capstone-constant PAIR CENSUS -- the observed set the
# generated champsim_tracer_qemu_ident_%s.h rests on.
#
# Written by the tracer (CST_QEMU_IDENT_PAIRS=<path>, ONE qemu process per
# file) and folded in here by tools/merge_ident_pairs.py, which is a UNION:
# a rule that has ever been observed stays observed, so regeneration cannot
# narrow the table.  Sorted by (decode_id, cap_insn_id) so a diff is readable.
#
# The NAME is not decoration.  A decode id is not stable across source edits
# -- on i386 it is __LINE__ in decode-new.c.inc -- so the name is what proves
# a banked record still belongs to the rule it was taken from.  Both this
# tool's `verify` and the generator refuse a record whose name disagrees with
# the current universe.
#
#decode_id\tdecode_name\tcap_insn_id\tcount
"""


def bank_path(isa):
    return BANK_DIR / ("pairs_%s.tsv" % isa)


def read_tsv(path):
    """(id, name, cap, count) records from one pair-census file."""
    out = []
    for lineno, line in enumerate(Path(path).read_text().splitlines(), 1):
        if line.startswith("#") or not line.strip():
            continue
        f = line.split("\t")
        if len(f) != 4:
            raise SystemExit("%s:%d: expected 4 tab-separated fields, got %d "
                             "-- this is not a pair census" % (path, lineno,
                                                               len(f)))
        out.append((int(f[0]), f[1], int(f[2]), int(f[3])))
    return out


def fold(records, counts, names, origin):
    """Union RECORDS into (counts, names).  Refuses a name disagreement."""
    for ident, name, cap, n in records:
        was = names.get(ident)
        if was is not None and was != name:
            raise SystemExit(
                "%s: decode id 0x%08x is banked as %r and this census calls "
                "it %r.  One of them is stale -- an id that changed rules "
                "would attach an old observation to a new rule, which is a "
                "fabricated decode.  Re-take the census at this tip rather "
                "than merging across the edit." % (origin, ident, was, name))
        names[ident] = name
        counts[(ident, cap)] += n


def load_bank(isa):
    counts = collections.Counter()
    names = {}
    p = bank_path(isa)
    if p.exists():
        fold(read_tsv(p), counts, names, str(p))
    return counts, names


def write_bank(isa, counts, names):
    BANK_DIR.mkdir(exist_ok=True)
    body = [HEADER % isa]
    for (ident, cap) in sorted(counts):
        body.append("%d\t%s\t%d\t%d\n" % (ident, names[ident], cap,
                                          counts[(ident, cap)]))
    bank_path(isa).write_text("".join(body))


def cmd_merge(args):
    counts, names = load_bank(args.isa)
    before_rows, before_ids = len(counts), len(names)
    for src in args.sources:
        fold(read_tsv(src), counts, names, src)
    if not counts:
        print("merge_ident_pairs: nothing read -- REFUSING to bank an empty "
              "census", file=sys.stderr)
        return 2
    write_bank(args.isa, counts, names)
    print("%s: (id,cap) rows %d -> %d, distinct ids %d -> %d, from %d file(s)"
          % (args.isa, before_rows, len(counts), before_ids, len(names),
             len(args.sources)))
    return 0


def cmd_verify(args):
    sys.path.insert(0, str(PLUGIN_DIR))
    import champsim_tracer_mnemonic_audit as aud
    rc = 0
    for isa in ISAS:
        p = bank_path(isa)
        if not p.exists():
            print("%-8s NO BANK at %s -- REFUSING" % (isa, p), file=sys.stderr)
            return 2
        counts, names = load_bank(isa)
        uni = {i.ident: i.name for i in
               aud.qemu_ident_universe(args.build_dir, isa)}
        stale = [(i, names[i], uni[i]) for i in names
                 if i in uni and uni[i] != names[i]]
        absent = [i for i in names if i not in uni]
        print("%-8s ids=%-5d rows=%-5d matched=%-5d absent-from-universe=%-4d "
              "STALE=%d" % (isa, len(names), len(counts),
                            len(names) - len(absent), len(absent), len(stale)))
        for (i, was, now) in stale[:10]:
            print("    STALE 0x%08x banked %r, universe %r" % (i, was, now))
            rc = 1
    return rc


def selftest():
    """Three arms: a clean union grows, a stale name REFUSES, an empty
       source REFUSES.  A guard nobody has seen fire is not a guard."""
    import tempfile
    fails = 0
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        a = d / "pairs_x86_a.tsv"
        a.write_text("#h\n10\tMOV\t5\t3\n11\tADD\t7\t1\n")
        b = d / "pairs_x86_b.tsv"
        b.write_text("#h\n10\tMOV\t5\t4\n12\tSUB\t9\t2\n")
        bad = d / "pairs_x86_bad.tsv"
        bad.write_text("#h\n10\tXCHG\t5\t1\n")

        print("=== ARM A: a union of two censuses grows and sums")
        c, n = collections.Counter(), {}
        fold(read_tsv(a), c, n, str(a))
        fold(read_tsv(b), c, n, str(b))
        if c[(10, 5)] == 7 and len(n) == 3:
            print("    ok")
        else:
            print("    ARM A FAILED: %r %r" % (dict(c), n)); fails += 1

        print("=== ARM B: a record renaming a banked id must REFUSE")
        try:
            fold(read_tsv(bad), c, n, str(bad))
            print("    ARM B FAILED -- the stale record was accepted"); fails += 1
        except SystemExit as e:
            if "stale" in str(e):
                print("    ok, refused")
            else:
                print("    ARM B FAILED -- wrong refusal: %s" % e); fails += 1

        print("=== ARM C: a malformed census must REFUSE, never parse to zero")
        m = d / "pairs_x86_malformed.tsv"
        m.write_text("10\tMOV\t5\n")
        try:
            read_tsv(m)
            print("    ARM C FAILED -- 3 fields accepted"); fails += 1
        except SystemExit:
            print("    ok, refused")

    print()
    if fails:
        print("SELFTEST FAILED -- %d arm(s)" % fails)
        return 1
    print("SELFTEST PASSED -- 3 arms: union grows and sums, a renamed id "
          "refuses, a malformed census refuses.")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    m = sub.add_parser("merge")
    m.add_argument("--isa", required=True, choices=ISAS)
    m.add_argument("sources", nargs="+")
    v = sub.add_parser("verify")
    v.add_argument("--build-dir", type=Path, required=True)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.cmd == "merge":
        return cmd_merge(args)
    if args.cmd == "verify":
        return cmd_verify(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
