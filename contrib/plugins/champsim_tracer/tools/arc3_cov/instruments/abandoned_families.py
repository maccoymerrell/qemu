#!/usr/bin/env python3
"""ARC 3 -- decompose the `...ABANDONED` write-list class by FAMILY.

A row is ABANDONED when the write-list extractor named some of QEMU's writes,
reached one whose CPUArchState byte range no target declaration covers, and
stopped -- publishing the PREFIX it had.  The class is large (x86_64 carries
2,871,210 of them, 43% of its population) and the census reports it as one
number under one reason, which is true and not yet actionable: "an env byte
range no target declared" does not say WHICH range, and the remedy is one
declaration per range.

WHAT THIS GROUPS ON, and why it is a proxy that earns its keep.  The corpus
does not record the offset that stopped the walk -- if it did, this tool would
be a `sort | uniq -c` on it.  What it does record is the PREFIX that was named
before the stop, and the prefix's last element is the write immediately before
the undeclared one.  So the family key is

    (generic opcode, the SHAPE of the named prefix)

where the shape is the prefix with register INDICES stripped, so that
`REG_VEC0` and `REG_VEC7` are one family and not two.  Instructions that stop
at the same place in the same kind of write list land together, and a family
is then small enough to read one representative of.

A family is a HYPOTHESIS about a shared undeclared range, not a proof of one.
The proof is the declaration: it lands, the class shrinks by the family's own
count, and the count is what says whether the reading was right.

Usage:
    abandoned_families.py --corpus FILE [--top N] [--examples N]
    abandoned_families.py --selftest

Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
"""
import argparse
import collections
import os
import re
import sys

_D = os.path.dirname(os.path.abspath(__file__))
if _D not in sys.path:
    sys.path.insert(0, _D)
from evopen import evopen, resolve                            # noqa: E402

MARK = "...ABANDONED"
IDX = re.compile(r"(REG_[A-Z]+?)\d+$")
NEEDED = ("encoding", "mnem", "WR", "OPC")


def shape(prefix):
    """The named prefix with register indices stripped.

    `REG_VEC0,REG_FCSR` -> `REG_VEC*,REG_FCSR`.  An index is a fact about
    which register the encoding chose; the family is about which FILE the
    walk had reached when it stopped.
    """
    out = []
    for r in prefix.split(","):
        r = r.strip()
        if not r:
            continue
        m = IDX.match(r)
        out.append(m.group(1) + "*" if m else r)
    return ",".join(out) or "(nothing named)"


def scan(path, examples):
    fams = collections.Counter()
    ex = collections.defaultdict(list)
    total = rows = 0
    hdr = None
    with evopen(path, errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                if hdr is None:
                    hdr = line.lstrip("#").rstrip("\n").split("\t")
                    missing = [c for c in NEEDED if c not in hdr]
                    if missing:
                        sys.exit("REFUSING: %s has no %s column(s); this tool "
                                 "scores columns it did not write and must "
                                 "not reach a missing one with a default"
                                 % (path, ", ".join(missing)))
                    idx = {c: hdr.index(c) for c in NEEDED}
                continue
            c = line.rstrip("\n").split("\t")
            if hdr is None or len(c) < len(hdr):
                continue
            rows += 1
            wr = c[idx["WR"]]
            if MARK not in wr:
                continue
            total += 1
            key = (c[idx["OPC"]], shape(wr.split(MARK)[0]))
            fams[key] += 1
            if len(ex[key]) < examples:
                ex[key].append((c[idx["encoding"]], c[idx["mnem"]]))
    if hdr is None:
        sys.exit("REFUSING: %s has no header line" % path)
    if not rows:
        sys.exit("REFUSING: %s carried no rows; an empty corpus is not a "
                 "zero-abandonment result" % path)
    return total, rows, fams, ex


def report(path, top, examples, emit):
    total, rows, fams, ex = scan(path, examples)
    emit("corpus %s" % path)
    emit("  rows %d   ABANDONED %d   %.3f%%"
         % (rows, total, 100.0 * total / rows))
    if not total:
        emit("  no ABANDONED rows -- nothing to decompose")
        return 0
    emit("  distinct families %d" % len(fams))
    emit("")
    emit("  %9s  %6s  %-22s %s" % ("rows", "share", "opcode", "named prefix"))
    cum = 0
    for (opc, sh), n in fams.most_common(top):
        cum += n
        emit("  %9d  %5.1f%%  %-22s %s" % (n, 100.0 * n / total, opc, sh))
        for enc, mn in ex[(opc, sh)]:
            emit("             %-14s %s" % (enc, mn))
    emit("")
    emit("  top %d families cover %d of %d (%.1f%%)"
         % (min(top, len(fams)), cum, total, 100.0 * cum / total))
    return 0


def selftest():
    import tempfile
    import shutil
    ran, fails = [], []

    def chk(name, ok, ev=""):
        ran.append(name)
        if not ok:
            fails.append(name)
        print("  %s %s" % (name, "ok" if ok else "FAIL"))
        if not ok and ev:
            print("      %s" % (ev,))

    H = "#isa\tencoding\tmnem\tWR\tOPC\n"

    def corpus(d, rows, hdr=H):
        p = os.path.join(d, "c.tsv")
        with open(p, "w") as f:
            f.write(hdr)
            for r in rows:
                f.write(r)
        return p

    def run(p, top=10):
        out = []
        try:
            report(p, top, 1, out.append)
        except SystemExit as e:
            return (e.code if isinstance(e.code, int) else 2,
                    "\n".join(out) + str(e.code))
        return 0, "\n".join(out)

    d = tempfile.mkdtemp(prefix="abandoned_families.")
    try:
        # A -- indices are stripped, so one file is one family
        p = corpus(d, ["x\t01\tm1\tREG_VEC0%s\tOP_A\n" % MARK,
                       "x\t02\tm2\tREG_VEC7%s\tOP_A\n" % MARK])
        rc, t = run(p)
        chk("ARM A: two indices of one file are ONE family",
            rc == 0 and "distinct families 1" in t and "REG_VEC*" in t, t)

        # B -- a different opcode is a different family even at the same stop
        p = corpus(d, ["x\t01\tm1\tREG_VEC0%s\tOP_A\n" % MARK,
                       "x\t02\tm2\tREG_VEC0%s\tOP_B\n" % MARK])
        rc, t = run(p)
        chk("ARM B: the opcode is part of the key",
            rc == 0 and "distinct families 2" in t, t)

        # C -- a row with no marker is not in the class
        p = corpus(d, ["x\t01\tm1\tREG_VEC0%s\tOP_A\n" % MARK,
                       "x\t02\tm2\tREG_GPR0,REG_FLAGS\tOP_A\n"])
        rc, t = run(p)
        chk("ARM C: a complete write list is not counted as abandoned",
            rc == 0 and "ABANDONED 1" in t and "rows 2" in t, t)

        # D -- an abandonment that named NOTHING is its own family, and is
        # not silently merged with one that named something.
        p = corpus(d, ["x\t01\tm1\t%s\tOP_A\n" % MARK,
                       "x\t02\tm2\tREG_VEC0%s\tOP_A\n" % MARK])
        rc, t = run(p)
        chk("ARM D: a prefix that named nothing is a family, not a blank",
            rc == 0 and "(nothing named)" in t
            and "distinct families 2" in t, t)

        # E -- the column guard, one drop at a time
        for col in NEEDED:
            cols = H.lstrip("#").rstrip("\n").split("\t")
            keep = [i for i, c in enumerate(cols) if c != col]
            h2 = "#" + "\t".join(cols[i] for i in keep) + "\n"
            body = ("x\t01\tm1\tREG_VEC0%s\tOP_A" % MARK).split("\t")
            r2 = "\t".join(body[i] for i in keep) + "\n"
            dd = tempfile.mkdtemp(prefix="abandoned_col.")
            try:
                rc, t = run(corpus(dd, [r2], hdr=h2))
                chk("ARM E/%-9s a corpus without this column is REFUSED"
                    % (col + ":"), rc != 0 and "REFUSING" in t and col in t,
                    t[:160])
            finally:
                shutil.rmtree(dd, ignore_errors=True)

        # F -- an empty corpus is a refusal, never "0% abandoned"
        rc, t = run(corpus(d, []))
        chk("ARM F: a corpus with no rows REFUSES rather than reporting 0%",
            rc != 0 and "not a" in t, t[:160])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    print("\nabandoned_families.py selftest: %d check(s), %d failure(s)"
          % (len(ran), len(fails)))
    return 1 if fails else 0


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus")
    ap.add_argument("--top", type=int, default=25)
    ap.add_argument("--examples", type=int, default=2)
    ap.add_argument("-o", default=None)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        return selftest()
    if not a.corpus:
        ap.error("--corpus is required (or --selftest)")
    if not os.path.exists(resolve(a.corpus)):
        sys.exit("REFUSING: no corpus at %s" % a.corpus)
    out = []
    rc = report(a.corpus, a.top, a.examples, out.append)
    text = "\n".join(out) + "\n"
    sys.stdout.write(text)
    if a.o:
        with open(a.o, "w") as f:
            f.write(text)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
