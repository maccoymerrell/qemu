#!/usr/bin/env python3
"""Enumerate the write-side verdict (WSTQ) by class across two arms, and
prove the columns the wire is built from did not move.

    wstate_ab.py <base-arm-dir> <tip-arm-dir>

Each arm is a sled sweep root holding <isa>.wp<N>/corpus_mech_<isa>.tsv.

STREAMING, one row at a time, both arms in lockstep.  The corpora are 2.4 GB
per ISA arm and materialising even one of them as a dict is how a scorer
takes the host down (the ruling is standing: a scorer that eagerly
materialises a whole trace is a BUG, not a slow tool); nothing here holds
more than the current row and a handful of counters.

THE ARMS ARE THE SAME SLED OVER THE SAME POPULATION, so the rows arrive in
the same order -- but they need not arrive in the same NUMBER.  A tip that
makes QEMU decode an encoding the base declined adds a row, and a strict
lockstep zip reads that as a row-order divergence and refuses a comparison
that is perfectly well defined.  So the tip arm is advanced with a COUNTED
LOOK-AHEAD: up to LOOK rows are skipped to re-find the base's encoding, the
number skipped is REPORTED, and a divergence that outruns the window still
REFUSES.  A silent re-pair is the one thing this must not do -- it would
compare two different instructions and call the difference a result.

This was a pass-local script, patched in place by a sibling script, for three
passes.  It is in the tree because a scorer that lives beside its evidence is
a scorer nobody can re-run.
"""
import collections, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evopen import evopen, resolve

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")
WPS = ("0", "16")


def rows(path):
    hdr = None
    with evopen(path, errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                if hdr is None:
                    hdr = line.lstrip("#").rstrip("\n").split("\t")
                continue
            c = line.rstrip("\n").split("\t")
            if hdr is None or len(c) < len(hdr):
                continue
            yield hdr, c


def regs(s):
    return frozenset(r for r in s.split(",") if r and r != "-")


def main():
    base, tip = sys.argv[1], sys.argv[2]
    gmoved = collections.Counter()
    gmove = collections.Counter()
    gwr = [0, 0]
    for isa in ISAS:
        for wp in WPS:
            pb = os.path.join(base, "%s.wp%s" % (isa, wp),
                              "corpus_mech_%s.tsv" % isa)
            pt = os.path.join(tip, "%s.wp%s" % (isa, wp),
                              "corpus_mech_%s.tsv" % isa)
            for p in (pb, pt):
                if not os.path.exists(resolve(p)):
                    sys.exit("missing %s -- REFUSING" % p)
            wb = collections.Counter(); wt = collections.Counter()
            moved = collections.Counter(); newly = collections.Counter()
            wr_enc = wr_reg = 0
            n = 0
            gb, gt = rows(pb), rows(pt)
            # exec119 filed a SLED defect: which encodings a large population
            # drops is a function of the slot layout, so the TIP arm can carry
            # rows the BASE arm lacks.  Re-pair with a BOUNDED look-ahead in
            # the tip arm and COUNT every row skipped; a divergence the bound
            # cannot close still REFUSES.  Nothing is re-paired silently.
            LOOK = 256
            skipped_tip = 0
            it_t = iter(gt)
            for (hb, cb) in gb:
                nxt = next(it_t, None)
                if nxt is None:
                    sys.exit("%s wp%s: tip arm ended early -- REFUSING"
                             % (isa, wp))
                (ht, ct) = nxt
                if cb[1] != ct[1]:
                    hops = 0
                    while cb[1] != ct[1] and hops < LOOK:
                        nxt = next(it_t, None)
                        if nxt is None:
                            break
                        (ht, ct) = nxt
                        hops += 1
                    if cb[1] != ct[1]:
                        sys.exit("%s wp%s: row order diverged at %s beyond %d "
                                 "rows -- REFUSING" % (isa, wp, cb[1], LOOK))
                    skipped_tip += hops
                n += 1
                rb = dict(zip(hb, cb)); rt = dict(zip(ht, ct))
                wb[rb["WSTQ"]] += 1
                wt[rt["WSTQ"]] += 1
                for col in ("PUB", "PUBD", "RD", "wstate"):
                    a = rb.get(col, ""); b = rt.get(col, "")
                    if col != "wstate":
                        a, b = regs(a), regs(b)
                    if a != b:
                        moved[col] += 1
                        gmoved["%s/%s" % (isa, col)] += 1
                if rb["WSTQ"] != rt["WSTQ"]:
                    newly[(rb["WSTQ"][:46], rt["WSTQ"][:46])] += 1
                    gmove[(rb["WSTQ"][:46], rt["WSTQ"][:46])] += 1
                    g = regs(rt["WR"]) - regs(rb["WR"])
                    if g:
                        wr_enc += 1; wr_reg += len(g)
            tail = 0
            while next(it_t, None) is not None:
                tail += 1
            skipped_tip += tail
            gwr[0] += wr_enc; gwr[1] += wr_reg
            print("=== %s wp%s  rows=%d  (tip-only rows skipped: %d)"
                  % (isa, wp, n, skipped_tip))
            for k, v in wb.most_common():
                print("   BASE %9d  %s" % (v, k[:70]))
            for k, v in wt.most_common():
                print("   TIP  %9d  %s" % (v, k[:70]))
            for (a, b), v in newly.most_common():
                print("   MOVED %9d  %s  ->  %s" % (v, a, b))
            print("   WR GAINED: %d encoding(s) / %d register(s)"
                  % (wr_enc, wr_reg))
            print("   WIRE COLUMNS MOVED: %s"
                  % (dict(moved) if moved else "NONE (PUB / PUBD / RD / "
                                               "wstate identical on every "
                                               "encoding)"))
            sys.stdout.flush()
    print("\n=== ALL ISAs, BOTH WP ARMS ===")
    for (a, b), v in gmove.most_common():
        print("  MOVED %10d  %s  ->  %s" % (v, a, b))
    print("  WR GAINED TOTAL: %d encoding(s) / %d register(s)"
          % (gwr[0], gwr[1]))
    print("  WIRE-COLUMN MOVEMENT: %s"
          % (dict(gmoved) if gmoved else "NONE on any ISA in either wp arm "
                                         "-- REAL-LOST = 0 by whole-population "
                                         "diff, not by argument"))
    return 0

sys.exit(main())
