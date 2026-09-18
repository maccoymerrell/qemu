#!/usr/bin/env python3
"""Fold one ISA's per-guest capture corpora into one, and REFUSE a stamp skew.

Several guests, one build, one window.  Concatenating them is right only if
they came from the same build: a mixed file would let a scorer join one
build's answers against another's, which is the frozen-arm shape every corpus
reader in this tree already refuses.  So the merge checks the `#so` line
itself rather than trusting that four processes of the same binary agree.

A guest that produced no rows at all is NAMED and not silently skipped: a
corpus quietly missing a guest is a smaller population reported as a clean
one, which is the survivorship shape the floors exist against.

    merge.py --cap <capture-dir> --out <merged-dir> [--isa x86_64 ...]

<capture-dir> holds <isa>/<guest>/{gen,ident}.tsv as the capture arm wrote
them.  Exit 0 when every ISA merged, 1 otherwise.

Copyright (c) 2026 Maccoy Merrell

SPDX-License-Identifier: GPL-2.0-or-later
"""
import argparse
import os
import sys

KINDS = ("gen", "ident")


def merge_one(cap, out, isa, kind):
    """-> (rows, guests, error_or_None)"""
    stamp = header = None
    seen, rows, contributed = set(), [], []
    gdir = os.path.join(cap, isa)
    if not os.path.isdir(gdir):
        return 0, [], "%s: no capture directory %s" % (isa, gdir)
    for guest in sorted(os.listdir(gdir)):
        p = os.path.join(gdir, guest, "%s.tsv" % kind)
        if not os.path.exists(p):
            continue
        n = 0
        with open(p, errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#so "):
                    s = line[4:].strip()
                    if stamp is None:
                        stamp = s
                    elif s != stamp:
                        return 0, contributed, (
                            "%s/%s: %s carries stamp %r against %r -- two "
                            "builds in one corpus is the frozen-arm shape"
                            % (isa, kind, guest, s, stamp))
                    continue
                if line.startswith("#"):
                    if header is None:
                        header = line
                    continue
                if not line.strip():
                    continue
                if line in seen:
                    continue
                seen.add(line)
                rows.append(line)
                n += 1
        contributed.append("%s:%d" % (guest, n))
    if stamp is None:
        return 0, contributed, ("%s/%s: no guest carried a #so stamp; an "
                                "unstamped corpus cannot name the build it "
                                "came from" % (isa, kind))
    if not rows:
        return 0, contributed, "%s/%s: merged to zero rows" % (isa, kind)
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "%s_%s.tsv" % (kind, isa)), "w") as f:
        f.write("#so %s\n" % stamp)
        if header:
            f.write(header + "\n")
        f.write("\n".join(rows) + "\n")
    return len(rows), contributed, None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cap", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--isa", action="append", default=[])
    a = ap.parse_args()
    isas = a.isa or ["x86_64", "aarch64", "riscv64", "mipsel"]

    bad = 0
    for isa in isas:
        for kind in KINDS:
            n, guests, err = merge_one(a.cap, a.out, isa, kind)
            if err:
                print("merge: REFUSED: %s" % err, file=sys.stderr)
                bad += 1
                continue
            print("%-8s %-6s %7d distinct rows  (%s)"
                  % (isa, kind, n, " ".join(guests)))
    print("merge: %s" % ("FAIL" if bad else "PASS"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
