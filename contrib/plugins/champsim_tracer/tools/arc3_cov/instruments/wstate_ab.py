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

USAGE = ("usage: wstate_ab.py <base-arm-dir> <tip-arm-dir> [--isa ISA] "
         "[--wps 'N N']\n       wstate_ab.py --selftest [TMPDIR]")


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



MECH_HDR = ("#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\twstate\t"
            "PUB\tQN\tSURV\tRD\tSTATUS\tRDX\tCONT\tXLAT\tWR\tPUBD\t"
            "WSTQ\tOPC\tBR\tCFLAGS\tREFINE\tLANEK\tLANEP\tWRU\n")
OKW = "PUBLISHED from QEMU's emitters"


def _write_arm(root, isa, wp, rows):
    d = os.path.join(root, "%s.wp%s" % (isa, wp))
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "corpus_mech_%s.tsv" % isa), "w") as f:
        f.write(MECH_HDR)
        for r in rows:
            f.write("\t".join([
                isa, r["enc"], r.get("mnem", "m"), "aa", "rule", OKW,
                r.get("wstate", OKW), r.get("PUB", "-"), "-", "-",
                r.get("RD", "-"), "-", "-", "-", "x", r.get("WR", "-"),
                r.get("PUBD", "-"), r["WSTQ"], "-", "-", "-", "-",
                "0", "0", "0"]) + "\n")
    return d


def selftest(tmp):
    """FINDING 83-D's other half.  The refusal above is not the whole debt:
    a tool with no selftest has never been asked to fail, and this one's
    whole value is the sentence "WIRE-COLUMN MOVEMENT: NONE" -- a zero that
    a broken comparison prints just as readily as a correct one."""
    import shutil, subprocess
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    isa, wp = "riscv64", "0"
    base = os.path.join(tmp, "base"); tip = os.path.join(tmp, "tip")
    B = [dict(enc="01", WSTQ=OKW, PUB="R1", PUBD="R1", RD="R1", WR="R1"),
         dict(enc="02", WSTQ="refused: x", PUB="R2", PUBD="R2", RD="R2",
              WR="R2"),
         dict(enc="03", WSTQ=OKW, PUB="R3", PUBD="R3", RD="R3", WR="R3")]
    T = [dict(r) for r in B]
    _write_arm(base, isa, wp, B)
    _write_arm(tip, isa, wp, T)

    def run(*extra):
        return subprocess.run([sys.executable, __file__, base, tip,
                               "--isa", isa, "--wps", wp] + list(extra),
                              capture_output=True, text=True)

    fails = 0; n = 0
    def chk(cond, what):
        nonlocal fails, n
        n += 1
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            fails += 1

    r = run()
    chk(r.returncode == 0 and "WIRE-COLUMN MOVEMENT: NONE" in r.stdout,
        "identical arms report NO wire-column movement")
    chk("rows=3" in r.stdout, "and the zero is not vacuous -- 3 rows read")

    # A MOVED WIRE COLUMN MUST BE SEEN.  One register added to PUBD only.
    T2 = [dict(r) for r in B]; T2[0]["PUBD"] = "R1,R9"
    _write_arm(tip, isa, wp, T2)
    r = run()
    chk("'PUBD': 1" in r.stdout,
        "a single moved PUBD cell is REPORTED, not averaged away")
    chk("WIRE-COLUMN MOVEMENT: NONE" not in r.stdout,
        "and the NONE sentence does not survive it")

    # A MOVED VERDICT AND ITS WR GAIN.
    T3 = [dict(r) for r in B]
    T3[1]["WSTQ"] = OKW; T3[1]["WR"] = "R2,R8"
    _write_arm(tip, isa, wp, T3)
    r = run()
    chk("MOVED" in r.stdout and "refused: x" in r.stdout,
        "a WSTQ verdict that moved is named with BOTH its ends")
    chk("WR GAINED: 1 encoding(s) / 1 register(s)" in r.stdout,
        "and the register the move gained is counted")

    # THE LOOK-AHEAD RE-PAIRS, AND SAYS SO.
    T4 = [dict(r) for r in B]
    T4.insert(1, dict(enc="01a", WSTQ=OKW, PUB="-", PUBD="-", RD="-", WR="-"))
    _write_arm(tip, isa, wp, T4)
    r = run()
    chk(r.returncode == 0 and "tip-only rows skipped: 1" in r.stdout,
        "a tip-only row is re-paired past and the skip is COUNTED")

    # A DIVERGENCE THE WINDOW CANNOT CLOSE REFUSES.
    T5 = [dict(r, enc="z" + r["enc"]) for r in B]
    _write_arm(tip, isa, wp, T5)
    r = run()
    chk(r.returncode != 0 and "REFUSING" in (r.stdout + r.stderr),
        "a divergence past the look-ahead REFUSES rather than re-pairing")

    # A MISSING ARM REFUSES.
    os.remove(os.path.join(tip, "%s.wp%s" % (isa, wp),
                           "corpus_mech_%s.tsv" % isa))
    r = run()
    chk(r.returncode != 0 and "REFUSING" in (r.stdout + r.stderr),
        "a missing corpus REFUSES; it is never an empty comparison")

    # NO ARGUMENTS IS A REFUSAL, NOT A TRACEBACK (the finding itself).
    r0 = subprocess.run([sys.executable, __file__], capture_output=True,
                        text=True)
    chk(r0.returncode != 0 and "REFUSING" in (r0.stdout + r0.stderr)
        and "Traceback" not in r0.stderr,
        "no arguments gives a STATED refusal and no traceback")
    print("arms=%d failures=%d" % (n, fails))
    return 0 if fails == 0 else 1

def main():
    # FINDING 83-D.  This died on an uncaught IndexError when called with no
    # arguments -- including by the README's own `--selftest` loop, which is
    # how the pass that ran that loop reported "8 of 8" while three tools had
    # never been asked anything.  A traceback is not a refusal: it names a
    # line number instead of the thing the caller got wrong, and a harness
    # reading stderr cannot tell it apart from a crash on real evidence.
    argv = sys.argv[1:]
    if "--selftest" in argv:
        i = argv.index("--selftest")
        tmp = (argv[i + 1] if len(argv) > i + 1
               and not argv[i + 1].startswith("-") else "/tmp/wstate_ab_st")
        return selftest(tmp)
    isas, wps = list(ISAS), list(WPS)
    pos = []
    i = 0
    while i < len(argv):
        if argv[i] == "--isa" and i + 1 < len(argv):
            isas = [argv[i + 1]]; i += 2
        elif argv[i] == "--wps" and i + 1 < len(argv):
            wps = argv[i + 1].split(); i += 2
        elif argv[i].startswith("-"):
            sys.exit("wstate_ab: unknown option %r\n%s" % (argv[i], USAGE))
        else:
            pos.append(argv[i]); i += 1
    if len(pos) != 2:
        sys.exit("wstate_ab: needs exactly two arm directories, got %d "
                 "-- REFUSING\n%s" % (len(pos), USAGE))
    base, tip = pos
    for d in (base, tip):
        if not os.path.isdir(d):
            sys.exit("wstate_ab: %s is not a directory -- REFUSING" % d)
    gmoved = collections.Counter()
    gmove = collections.Counter()
    gwr = [0, 0]
    for isa in isas:
        for wp in wps:
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
