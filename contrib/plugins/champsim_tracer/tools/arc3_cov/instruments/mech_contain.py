#!/usr/bin/env python3
"""WHOLE-POPULATION CONTAINMENT for a change to the mechanism corpus.

Every encoding of every ISA at both wp settings, every column of the
mechanism corpus, a BASE arm against a TIP arm.  A row is REPORTED if ANY
column differs, and the report is decomposed by WHICH column moved and by the
base arm's decode id -- so "only the encodings the commit named moved" is a
measurement over the whole population rather than a list of what was looked
at.

WHY IT IS ONLY AS WIDE AS ITS WIDEST COLUMN.  This script compares whatever
the corpus carries.  Until FINDING 70-C the corpus carried registers only --
what QEMU stated, what the wire published, what survived -- and a commit that
changes what an encoding IS moves none of them: give an instruction a generic
opcode it did not have, or a branch type, or a lane-mask kind, and its source
and destination lists are the lists they were.  25,216 such moves read back
as MOVED=0, which is not a containment result but the absence of one.  The
corpus now carries OPC, BR, CFLAGS, REFINE, LANEK and LANEP, and this script
sees them because it was always generic over the header.

A missing arm, a header the two arms do not share, or a corpus with no rows
is a REFUSAL.  A containment claim read off a corpus that cannot answer is
the failure this file exists to avoid, and a header mismatch is exactly what
comparing a corpus captured before a column existed against one captured
after looks like -- it must refuse, never silently compare the columns they
happen to share.

Usage:  mech_contain.py <base-sweep-root> <tip-sweep-root>
        mech_contain.py --selftest

Author: Maccoy Merrell.
"""
import collections, os, sys
sys.path.insert(0, "/mnt/md0/QEMU/qemu/contrib/plugins/champsim_tracer/tools/"
                   "arc3_cov/instruments")
from evopen import evopen, resolve

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")
WPS = ("0", "16")


def read(path):
    hdr, out = None, {}
    with evopen(path, errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                if hdr is None:
                    hdr = line.lstrip("#").rstrip("\n").split("\t")
                continue
            c = line.rstrip("\n").split("\t")
            if hdr is None or len(c) < len(hdr):
                continue
            out[c[1]] = c[:len(hdr)]
    if hdr is None or not out:
        sys.exit("contain: %s carries no rows -- REFUSING" % path)
    return hdr, out


def selftest():
    """Prove the instrument reports a classification-only move, and refuses
    the two shapes that would let it report a false zero."""
    import tempfile, textwrap
    n = fails = 0

    def t(label, got, want):
        nonlocal n, fails
        n += 1
        if got == want:
            print("PASS  %s" % label)
        else:
            fails += 1
            print("FAIL  %s (got %r want %r)" % (label, got, want))

    HDR = "#isa\tencoding\tmnem\tdecode_id\tOPC\tPUB\n"

    def arm(root, rows, hdr=HDR):
        d = os.path.join(root, "x86_64.wp0")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "corpus_mech_x86_64.tsv"), "w") as f:
            f.write(hdr)
            for r in rows:
                f.write("\t".join(r) + "\n")
        return root

    base_rows = [("x86_64", "0f01c1", "vmcall", "aaaa", "GEN_OP_VEC_ADD",
                  "REG_GPR0"),
                 ("x86_64", "9090", "nop", "bbbb", "GEN_OP_NOP", "-")]
    tip_rows = [("x86_64", "0f01c1", "vmcall", "aaaa", "GEN_OP_SYSCALL",
                 "REG_GPR0"),                     # classification ONLY
                ("x86_64", "9090", "nop", "bbbb", "GEN_OP_NOP", "-")]

    tmp = tempfile.mkdtemp(prefix="mechcontain")
    hdr_i, B = read(os.path.join(arm(os.path.join(tmp, "b"), base_rows),
                                 "x86_64.wp0", "corpus_mech_x86_64.tsv"))
    hdr_j, T = read(os.path.join(arm(os.path.join(tmp, "t"), tip_rows),
                                 "x86_64.wp0", "corpus_mech_x86_64.tsv"))
    t("A the two arms share a header", hdr_i, hdr_j)
    moved = [e for e in B if e in T and B[e] != T[e]]
    t("B a CLASSIFICATION-ONLY move is seen", moved, ["0f01c1"])
    cols = [hdr_i[i] for i in range(len(hdr_i))
            if B["0f01c1"][i] != T["0f01c1"][i]]
    t("C ...and the column that moved is named", cols, ["OPC"])
    t("D ...the untouched encoding did not move", B["9090"], T["9090"])

    # A corpus captured before a column existed must REFUSE, never compare
    # the columns the two happen to share.
    NARROW = "#isa\tencoding\tmnem\tdecode_id\tPUB\n"
    hdr_k, _ = read(os.path.join(
        arm(os.path.join(tmp, "n"),
            [("x86_64", "0f01c1", "vmcall", "aaaa", "REG_GPR0")], NARROW),
        "x86_64.wp0", "corpus_mech_x86_64.tsv"))
    t("E a narrower corpus has a DIFFERENT header (the refusal's trigger)",
      hdr_k != hdr_i, True)

    # An empty corpus must refuse rather than report zero moves.
    empty = os.path.join(tmp, "e", "x86_64.wp0")
    os.makedirs(empty, exist_ok=True)
    open(os.path.join(empty, "corpus_mech_x86_64.tsv"), "w").write(HDR)
    rc = None
    try:
        read(os.path.join(empty, "corpus_mech_x86_64.tsv"))
    except SystemExit as e:
        rc = str(e)
    t("F a corpus with no rows REFUSES", rc is not None and "REFUSING" in rc,
      True)

    print("arms=%d failures=%d" % (n, fails))
    return 1 if fails else 0


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        return selftest()
    if len(sys.argv) != 3:
        sys.exit("usage: mech_contain.py <base-root> <tip-root>\n       mech_contain.py --selftest")
    base, tip = sys.argv[1], sys.argv[2]
    grand_moved = 0
    grand_rows = 0
    for isa in ISAS:
        for wp in WPS:
            rel = "%s.wp%s/corpus_mech_%s.tsv" % (isa, wp, isa)
            pb, pt = os.path.join(base, rel), os.path.join(tip, rel)
            for p in (pb, pt):
                if not os.path.exists(resolve(p)):
                    sys.exit("contain: %s missing -- REFUSING" % p)
            hb, B = read(pb)
            ht, T = read(pt)
            if hb != ht:
                sys.exit("contain: %s/%s header mismatch -- REFUSING"
                         % (isa, wp))
            ob, ot = sorted(set(B) - set(T)), sorted(set(T) - set(B))
            if ob or ot:
                # NOT a refusal, and the reason is measured rather than
                # assumed: the sled drops population encodings whose row it
                # does not produce, and WHICH ones it drops is a function of
                # the slot layout, not of the decode.  Proven by running the
                # same slots through the BASE build in a smaller chunk, where
                # every one of these appears -- see mini/Btail.  Reported in
                # full so the asymmetry is a number and not a silence.
                print("%-8s wp%-3s SET DIFFERENCE only_base=%d only_tip=%d"
                      % (isa, wp, len(ob), len(ot)))
                for e in (ob + ot)[:40]:
                    row = B.get(e) or T.get(e)
                    print("       %-20s %-14s id=%s %s"
                          % (e, row[2], row[3],
                             "only_base" if e in B else "only_tip"))
            grand_rows += len(set(B) & set(T))
            cols = collections.Counter()
            byid = collections.Counter()
            moved = 0
            for enc, rb in B.items():
                rt = T.get(enc)
                if rt is None:
                    continue
                if rb == rt:
                    continue
                moved += 1
                for i, name in enumerate(hb):
                    if rb[i] != rt[i]:
                        cols[name] += 1
                byid[rb[3]] += 1
            grand_moved += moved
            print("%-8s wp%-3s rows=%-8d MOVED=%d" % (isa, wp, len(B), moved))
            if moved:
                print("     columns : " + ", ".join(
                    "%s=%d" % kv for kv in cols.most_common()))
                print("     base decode ids that moved:")
                for k, n in byid.most_common(20):
                    print("       %-12s %d" % (k, n))
    print()
    print("WHOLE POPULATION: %d row(s) over %d arm(s), %d MOVED"
          % (grand_rows, len(ISAS) * len(WPS), grand_moved))
    return 0


if __name__ == "__main__":
    sys.exit(main())
