#!/usr/bin/env python3
"""THE ARM BEHIND A FAMILY'S RULING: what do the LOSING encodings have in
common, over the whole family and never a sample?

WHY THIS IS A TOOL AND NOT FIVE SCRIPTS IN A RUN DIRECTORY.  Every `RULED`
row in `BAR_CLASSES.tsv` rests on a sentence of the form "100% of the N
losing encodings carry X" -- cond=AL/NV on the conditional compares, shift ==
esize on the degenerate vector shifts, rs == 0 on the mipsel logic fold.  A
ruling is only as good as the arm under it, and an arm nobody can re-run is
an assertion.  exec137 wrote four of these by hand; this is the one that
stays.

TWO MODES, because the rulings needed two questions answered:

  --field LO:HI   histogram an ENCODING BIT-FIELD over the losing set.  This
                  is how "all 1,152 carry cond=AL or NV" was measured: the
                  cond field is bits 15:12 and the histogram has exactly two
                  bins.  A ruling written from a handful of examples cannot
                  say that; a histogram over the family can.

  --role          split each lost register by the OPERAND SLOT it occupies --
                  Rd, Rn, both, or neither -- for fixed-width ISAs whose
                  slots are at known bit positions.  This is what separated
                  `a64-shift-degenerate-accum` (the lost Rd is real, the lost
                  Rn beside it is a correct drop) from
                  `a64-narrow-upper-half` (100% Rd, and preservation is not
                  a source).  The register NAME cannot answer it: `REG_VEC0`
                  is Rd on one encoding and Rn on the next.

THE REACH FILTER IS APPLIED AND IS NOT OPTIONAL.  exec137's hand-written
arms joined the two source corpora directly and skipped it, and one family
came back with 168 losing encodings where the bar holds 72 -- the extra rows
were NO-DECODE encodings the bar excludes by ruling.  Nothing was published
from that reading, but it would have been a whole-population claim over the
wrong population.  This reads `corpus_mech_<isa>.tsv` and scores only
REACH=INSTRUCTION rows, so the population here IS the bar's, and the printed
count can be checked against the family table.

Author: Maccoy Merrell.
"""
import argparse, collections, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import srcenc_reach
from evopen import evopen, resolve

#: Operand slots, by ISA, as (name, lsb, width).  Only fixed-width encodings
#: are listed: a slot table for x86 would be a decoder, not a table, and
#: pretending otherwise is how a role claim stops meaning anything.
SLOTS = {
    "aarch64": (("Rd", 0, 5), ("Rn", 5, 5), ("Rm", 16, 5)),
    "riscv64": (("rd", 7, 5), ("rs1", 15, 5), ("rs2", 20, 5)),
    "mipsel":  (("rs", 21, 5), ("rt", 16, 5), ("rd", 11, 5)),
}


def read_arm(root, isa, wps, want_mech):
    """encoding -> (mnem, regs) and, when asked, the mech row."""
    src, mech = {}, {}
    for w in wps:
        p = os.path.join(root, "%s.wp%s" % (isa, w), "corpus_%s.tsv" % isa)
        if not os.path.exists(resolve(p)):
            sys.exit("famarm: %s missing -- REFUSING" % p)
        with evopen(p, errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                c = line.rstrip("\n").split("\t")
                if len(c) < 4:
                    continue
                src[c[1]] = (c[2], frozenset(r for r in c[3].split(",")
                                             if r and r != "-"))
        if not want_mech:
            continue
        pm = os.path.join(root, "%s.wp%s" % (isa, w), "corpus_mech_%s.tsv" % isa)
        if not os.path.exists(resolve(pm)):
            sys.exit("famarm: %s missing -- REFUSING (the reach filter is "
                     "not optional; without it the population is not the "
                     "bar's)" % pm)
        hdr = None
        with evopen(pm, errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    if hdr is None:
                        hdr = line.lstrip("#").rstrip("\n").split("\t")
                    continue
                c = line.rstrip("\n").split("\t")
                if hdr is None or len(c) < len(hdr):
                    continue
                mech[c[1]] = dict(zip(hdr, c))
    return src, mech


def word(enc):
    """The sled stores the instruction's BYTES in memory order."""
    return int.from_bytes(bytes.fromhex(enc), "little")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True, help="tip arm root")
    ap.add_argument("--b", required=True, help="deletion arm root")
    ap.add_argument("--isa", required=True)
    ap.add_argument("--mnem", required=True,
                    help="exact mnemonic, or a comma-separated list")
    ap.add_argument("--wps", default="0 16")
    ap.add_argument("--field", default=None,
                    help="HI:LO bit field to histogram, e.g. 15:12")
    ap.add_argument("--role", action="store_true",
                    help="split each lost register by operand slot")
    ap.add_argument("--names", default=None,
                    help="comma-separated names for the --field bins, in "
                         "value order from 0")
    a = ap.parse_args()
    if not a.field and not a.role:
        sys.exit("famarm: give --field or --role -- REFUSING (an arm that "
                 "asks nothing measures nothing)")
    wps = a.wps.split()
    mnems = set(a.mnem.split(","))
    A, M = read_arm(a.a, a.isa, wps, True)
    B, _ = read_arm(a.b, a.isa, wps, False)

    losing = []
    excluded = collections.Counter()
    for enc, (mn, ra) in A.items():
        if mn not in mnems:
            continue
        if enc not in B:
            continue
        lost = ra - B[enc][1]
        if not lost:
            continue
        m = M.get(enc)
        if m is None:
            excluded["NO MECH ROW"] += 1
            continue
        reach = srcenc_reach.classify(m)[0]
        if reach != "INSTRUCTION":
            excluded[reach] += 1
            continue
        losing.append((enc, lost))

    print("famarm  isa=%s  mnem=%s  wps=%s" % (a.isa, a.mnem, " ".join(wps)))
    print("  LOSING ENCODINGS AT REACH=INSTRUCTION : %d" % len(losing))
    if excluded:
        print("  excluded by reach (NOT in the bar)    : %s"
              % ", ".join("%s=%d" % kv for kv in sorted(excluded.items())))
    if not losing:
        sys.exit("famarm: no losing encodings -- REFUSING (an empty arm "
                 "proves nothing and must not read as agreement)")

    if a.field:
        hi, lo = (int(x) for x in a.field.split(":"))
        if hi < lo:
            sys.exit("famarm: --field is HI:LO -- REFUSING")
        width = hi - lo + 1
        mask = (1 << width) - 1
        names = a.names.split(",") if a.names else None
        h = collections.Counter()
        for enc, _ in losing:
            h[(word(enc) >> lo) & mask] += 1
        print("  BIT FIELD [%d:%d], %d distinct value(s):" % (hi, lo, len(h)))
        for v, n in sorted(h.items()):
            label = ""
            if names and v < len(names):
                label = "  " + names[v]
            print("      0x%X %-6s %8d  %5.1f%%%s"
                  % (v, "", n, 100.0 * n / len(losing), label))
        top = max(h.values())
        print("  the largest bin is %.1f%% of the family"
              % (100.0 * top / len(losing)))

    if a.role:
        if a.isa not in SLOTS:
            sys.exit("famarm: --role has no slot table for %s -- REFUSING "
                     "(a slot table for a variable-length encoding would be "
                     "a decoder, and guessing one is how a role claim stops "
                     "meaning anything)" % a.isa)
        slots = SLOTS[a.isa]
        roles = collections.Counter()
        for enc, lost in losing:
            w = word(enc)
            idx = {nm: (w >> lsb) & ((1 << wd) - 1) for nm, lsb, wd in slots}
            for r in sorted(lost):
                num = None
                for pre in ("REG_VEC", "REG_GPR", "REG_FPR"):
                    if r.startswith(pre) and r[len(pre):].isdigit():
                        num = int(r[len(pre):])
                        break
                if num is None:
                    roles["not a numbered register: " + r] += 1
                    continue
                hit = [nm for nm in idx if idx[nm] == num]
                roles["+".join(hit) if hit else "no slot"] += 1
        tot = sum(roles.values())
        print("  OPERAND ROLE of each lost register (%d):" % tot)
        for k, n in sorted(roles.items(), key=lambda kv: (-kv[1], kv[0])):
            print("      %-34s %8d  %5.1f%%" % (k, n, 100.0 * n / tot))
    return 0


def selftest(tmp):
    """Two planted families: one whose losing set is uniform in a bit field,
    one whose losses are all in the same operand slot -- plus the reach row
    that must NOT be counted, which is the defect this tool exists to have
    stopped."""
    import shutil, subprocess
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    isa, wp = "aarch64", "0"
    OKS = "PUBLISHED from QEMU's emitters"
    HDR = ("#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\twstate\tPUB\t"
           "QN\tSURV\tRD\tSTATUS\tRDX\tCONT\tXLAT\tWR\tPUBD\tWSTQ\tOPC\tBR\t"
           "CFLAGS\tREFINE\tLANEK\tLANEP\tWRU\n")
    BODY = "noret=0,calls=0,memr=0,memw=0,refused=0"

    def w32(v):
        return v.to_bytes(4, "little").hex()

    #: cond field at 15:12 set to 0xE on both, Rd = 3 and Rn = 7.
    rows = [(w32((0xE << 12) | (7 << 5) | 3), "cc", "REG_VEC3,REG_VEC7",
             "REG_VEC7", "aa"),
            (w32((0xE << 12) | (9 << 5) | 4), "cc", "REG_VEC4,REG_VEC9",
             "REG_VEC9", "aa"),
            #: a NO-DECODE row that also loses -- must be EXCLUDED
            (w32((0x1 << 12) | (2 << 5) | 1), "cc", "REG_VEC1,REG_VEC2",
             "REG_VEC2", "0")]
    for root, col in ((os.path.join(tmp, "A"), 2), (os.path.join(tmp, "B"), 3)):
        d = os.path.join(root, "%s.wp%s" % (isa, wp))
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "corpus_%s.tsv" % isa), "w") as f:
            f.write("#isa\tencoding\tmnem\tsrc\n")
            for r in rows:
                f.write("%s\t%s\t%s\t%s\n" % (isa, r[0], r[1], r[col]))
        with open(os.path.join(d, "corpus_mech_%s.tsv" % isa), "w") as f:
            f.write(HDR)
            for r in rows:
                f.write("\t".join([isa, r[0], r[1], r[4], "rule_cc", OKS, OKS,
                                   "-", "-", "-", "-", "-", "-", "-", BODY,
                                   "REG_VEC0", "-", OKS, "-", "-", "-", "-",
                                   "0", "0", "0"]) + "\n")

    def run(*extra):
        return subprocess.run([sys.executable, __file__,
                               "--a", os.path.join(tmp, "A"),
                               "--b", os.path.join(tmp, "B"),
                               "--isa", isa, "--mnem", "cc", "--wps", wp]
                              + list(extra), capture_output=True, text=True)

    fails = 0; n = 0
    def chk(cond, what):
        nonlocal fails, n
        n += 1
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            fails += 1

    r = run("--field", "15:12")
    chk("LOSING ENCODINGS AT REACH=INSTRUCTION : 2" in r.stdout,
        "the NO-DECODE row is NOT in the population the arm measures")
    chk("excluded by reach (NOT in the bar)    : NO-DECODE=1" in r.stdout,
        "and its exclusion is REPORTED, never silent")
    chk("the largest bin is 100.0% of the family" in r.stdout,
        "a uniform bit field reads as 100%, which is what a ruling may cite")
    r2 = run("--field", "15:12", "--names", "a,b,c,d")
    chk("0xE" in r2.stdout, "the field value is printed even without a name")
    r3 = run("--role")
    # The planted rows lose REG_VEC3 (Rd=3, Rn=7) and REG_VEC4 (Rd=4,
    # Rn=9): both losses are in the Rd SLOT, and the two register NAMES
    # differ -- which is the whole point of splitting by slot.
    chk("Rd " in r3.stdout and "100.0%" in r3.stdout
        and "Rn" not in r3.stdout.split("OPERAND ROLE")[1],
        "the role split names the SLOT, which the register name cannot")
    r4 = run()
    chk(r4.returncode != 0 and "asks nothing" in (r4.stdout + r4.stderr),
        "an arm with no question REFUSES")
    r5 = subprocess.run([sys.executable, __file__, "--a", os.path.join(tmp, "A"),
                         "--b", os.path.join(tmp, "B"), "--isa", "x86_64",
                         "--mnem", "cc", "--wps", wp, "--role"],
                        capture_output=True, text=True)
    chk(r5.returncode != 0 and "REFUSING" in (r5.stdout + r5.stderr),
        "--role on a variable-length ISA REFUSES rather than guessing slots")
    r6 = subprocess.run([sys.executable, __file__, "--a", os.path.join(tmp, "A"),
                         "--b", os.path.join(tmp, "B"), "--isa", isa,
                         "--mnem", "nosuch", "--wps", wp, "--field", "15:12"],
                        capture_output=True, text=True)
    chk(r6.returncode != 0 and "proves nothing" in (r6.stdout + r6.stderr),
        "an EMPTY arm REFUSES; it never reads as agreement")
    print("arms=%d failures=%d" % (n, fails))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        i = sys.argv.index("--selftest")
        t = (sys.argv[i + 1] if len(sys.argv) > i + 1
             and not sys.argv[i + 1].startswith("-") else "/tmp/famarm_st")
        sys.exit(selftest(t))
    sys.exit(main())
