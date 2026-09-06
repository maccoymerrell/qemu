#!/usr/bin/env python3
"""BEFORE AGAINST AFTER, ON ONE POPULATION, FOR BOTH BARS AND THE WIRE.

IN THE TREE FOR THE REASON dstbar.py IS.  Every source-side family since
exec115 has been scored by a copy of `iodelta.py` pasted into that pass's wave
root -- an eleven-line join with the reach filter, the wp merge and the
carve-out rules all re-typed by hand.  Two of those copies disagreed about
whether a row absent from the BEFORE arm counts, which is the difference
between "the family closed" and "the family was never in the denominator".

WHAT IT ANSWERS, on the encodings both arms carry:

    SOURCE      PUB - RD    registers the wire publishes that QEMU does not
                            state.  This is the single-arm proxy for the
                            two-arm deletion bar; it is a PROXY and is named
                            as one -- the deletion bar is PUB_tip - PUB_del
                            and only the paired excursion produces it.
    DEST        PUBD - WR   the same question on the destination side, with
                            R10.1's REG_PC carve-out applied exactly as
                            dstbar.py applies it, and counted separately.
    REACH       the structural discriminator, BEFORE and AFTER.  A family
                whose registers fall while its INSTRUCTION count also falls
                did not close: it left the denominator.
    WIRE        rows whose published SET changed, and rows whose ORDER
                changed.  A source flip moves order by contract; a set change
                is a claim that has to be argued.

ROWS PRESENT IN ONLY ONE ARM ARE COUNTED AND PRINTED, never dropped in
silence: a decoder change can make an encoding decode that did not, and that
is a result, not noise.

Author: Maccoy Merrell.
"""
import argparse, collections, os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import srcenc_reach
from evopen import evopen, resolve

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")


def read_mech(paths):
    d, conf, hdr = {}, 0, None
    for p in paths:
        rp = resolve(p)
        if not os.path.exists(rp):
            sys.exit("armdelta: %s missing -- REFUSING" % p)
        with evopen(p, errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    if hdr is None:
                        hdr = line.lstrip("#").rstrip("\n").split("\t")
                    continue
                c = line.rstrip("\n").split("\t")
                if hdr is None or len(c) < len(hdr):
                    continue
                row = dict(zip(hdr, c))
                prev = d.get(c[1])
                if prev is not None and prev != row:
                    conf += 1
                d[c[1]] = row
    return d, conf


def L(v):
    return [x for x in v.split(",") if x and x != "-"]


def S(v):
    return set(L(v))


#: R10.1, THE SAME CARVE-OUT dstbar.py MAKES AND FOR THE SAME REASON: QEMU
#: charges a translation block's final pc write to whichever instruction the
#: block ended on, so WR carries REG_PC on instructions the ISA does not
#: define as writing it.  Dropped only in that exact shape -- REG_PC in
#: QEMU's list when the wire's has none -- and counted, so the size of the
#: carve-out is a number and not a silence.
def dst_gap(row, tally):
    pubd, wr = S(row["PUBD"]), S(row["WR"])
    if "REG_PC" in wr and "REG_PC" not in pubd:
        wr = wr - {"REG_PC"}
        tally["r10_1_pc"] += 1
    return pubd - wr


def arm(d, isa, wps):
    return [os.path.join(d, "%s.wp%s" % (isa, w), "corpus_mech_%s.tsv" % isa)
            for w in wps]



MECH_HDR = ("#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\twstate\t"
            "PUB\tQN\tSURV\tRD\tSTATUS\tRDX\tCONT\tXLAT\tWR\tPUBD\t"
            "WSTQ\tOPC\tBR\tCFLAGS\tREFINE\tLANEK\tLANEP\tWRU\n")
_OKW = "PUBLISHED from QEMU's emitters"
_BODY = "noret=0,calls=0,memr=0,memw=0,refused=0"


def _write_arm(root, isa, wp, rows):
    d = os.path.join(root, "%s.wp%s" % (isa, wp))
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "corpus_mech_%s.tsv" % isa), "w") as f:
        f.write(MECH_HDR)
        for r in rows:
            f.write("\t".join([
                isa, r["enc"], r.get("mnem", "m"), r.get("did", "aa"),
                r.get("rule", "rule_x"), _OKW, _OKW, r.get("PUB", "-"),
                "-", "-", r.get("RD", "-"), "-", "-", "-",
                r.get("xlat", _BODY), r.get("WR", "-"), r.get("PUBD", "-"),
                _OKW, "-", "-", "-", "-", "0", "0", "0"]) + "\n")
    return d


def selftest(tmp):
    """FINDING 83-D.  This is the tool every source-side family is argued
    with, and the defect its own header describes -- two pasted copies
    disagreeing about whether a row absent from the BEFORE arm counts -- is
    exactly the kind a selftest catches and a reading never does."""
    import shutil, subprocess
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    isa, wp = "riscv64", "0"
    before = os.path.join(tmp, "before"); after = os.path.join(tmp, "after")
    B = [
        # a source gap that CLOSES: PUB names R9, QEMU does not; after, it does
        dict(enc="01", mnem="fam_a", PUB="R1,R9", RD="R1", PUBD="R1", WR="R1"),
        # a source gap that SURVIVES, on a second family
        dict(enc="02", mnem="fam_b", PUB="R2,R8", RD="R2", PUBD="R2", WR="R2"),
        # a destination gap, and the R10.1 carve-out beside it
        dict(enc="03", mnem="fam_c", PUB="R3", RD="R3", PUBD="R3,R7",
             WR="R3,REG_PC"),
        # present only in the BEFORE arm
        dict(enc="04", mnem="gone", PUB="R4", RD="R4", PUBD="R4", WR="R4"),
    ]
    A = [dict(r) for r in B[:3]]
    A[0]["RD"] = "R1,R9"                       # the gap closed at the source
    A.append(dict(enc="05", mnem="new", PUB="R5", RD="R5", PUBD="R5",
                  WR="R5"))                    # present only in the AFTER arm
    _write_arm(before, isa, wp, B)
    _write_arm(after, isa, wp, A)

    def run(*extra):
        return subprocess.run([sys.executable, __file__, "--before", before,
                               "--after", after, "--isa", isa, "--wps", wp]
                              + list(extra), capture_output=True, text=True)

    fails = 0; n = 0
    def chk(cond, what):
        nonlocal fails, n
        n += 1
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            fails += 1

    r = run(); o = r.stdout
    chk(r.returncode == 0, "the tool runs on two well-formed arms")
    chk("population=3  only-before=1  only-after=1" in o,
        "rows present in ONE arm are COUNTED APART -- never dropped, and "
        "never scored as agreement (the header's own defect)")
    chk("SOURCE  PUB-minus-RD : 2 regs / 2 enc  ->  1 regs / 1 enc" in o,
        "the closed source gap moves the number and the surviving one does "
        "not")
    chk("R10.1 REG_PC carve-out applied 2 time(s)" in o,
        "the REG_PC carve-out is COUNTED at both ends, not silently applied")
    chk("DEST    PUBD-minus-WR: 1 regs / 1 enc  ->  1 regs / 1 enc" in o,
        "and the destination gap it protects is still scored")
    chk("fam_b | R8" in o, "the SURVIVING family is named in the residue")
    chk("fam_a | R9" not in o, "the CLOSED one is not")

    # THE WIRE COLUMNS.  A published SET that moves and an ORDER that moves
    # are different claims and must not collapse into one count.
    A2 = [dict(r) for r in A]
    A2[1]["PUB"] = "R8,R2"                     # same set, order reversed
    _write_arm(after, isa, wp, A2)
    o2 = run().stdout
    chk("set changed=0  order changed=1" in o2,
        "an ORDER-only wire change is order-only, never a set change")
    A3 = [dict(r) for r in A]
    A3[1]["PUB"] = "R2,R8,R6"
    _write_arm(after, isa, wp, A3)
    o3 = run().stdout
    chk("set changed=1" in o3, "a SET change is seen")

    # THE FILTERS SELECT, AND A CUT TABLE SAYS SO.
    _write_arm(after, isa, wp, A)
    o4 = run("--mnem", "fam_b").stdout
    chk("population=1" in o4, "--mnem narrows the population it scores")
    o5 = run("--top", "0").stdout
    chk("NOT SHOWN" not in o5, "--top 0 shows the whole residue")

    # A MISSING ARM REFUSES.
    os.remove(os.path.join(after, "%s.wp%s" % (isa, wp),
                           "corpus_mech_%s.tsv" % isa))
    r6 = run()
    chk(r6.returncode != 0 and "REFUSING" in (r6.stdout + r6.stderr),
        "a missing corpus REFUSES; it is never an empty delta")
    print("arms=%d failures=%d" % (n, fails))
    return 0 if fails == 0 else 1

def main():
    if "--selftest" in sys.argv:
        i = sys.argv.index("--selftest")
        tmp = (sys.argv[i + 1] if len(sys.argv) > i + 1
               and not sys.argv[i + 1].startswith("-")
               else "/tmp/armdelta_st")
        return selftest(tmp)
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", required=True)
    ap.add_argument("--after", required=True)
    ap.add_argument("--isa", action="append", default=None)
    ap.add_argument("--wps", default="0 16")
    ap.add_argument("--mnem", default=None,
                    help="python regex on the mnemonic: score only this family")
    ap.add_argument("--rule", default=None,
                    help="python regex on the decode rule")
    ap.add_argument("--enc-list", default=None,
                    help="file of encodings (one per line, or TSV whose 2nd "
                         "column is the encoding): score only these")
    ap.add_argument("--by", default="mnem_reg",
                    help="rule|mnem|reg|mnem_reg|rule_reg for the residue")
    ap.add_argument("--top", type=int, default=30)
    a = ap.parse_args()

    keep = None
    if a.enc_list:
        keep = set()
        with evopen(a.enc_list, errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                c = line.rstrip("\n").split("\t")
                keep.add(c[1] if len(c) > 1 else c[0])
    rx_m = re.compile(a.mnem) if a.mnem else None
    rx_r = re.compile(a.rule) if a.rule else None

    wps = a.wps.split()
    tot = collections.Counter()
    for isa in (a.isa or list(ISAS)):
        B, cb = read_mech(arm(a.before, isa, wps))
        A, ca = read_mech(arm(a.after, isa, wps))

        def sel(row):
            if keep is not None and row["encoding"] not in keep:
                return False
            if rx_m and not rx_m.search(row["mnem"]):
                return False
            if rx_r and not rx_r.search(row.get("rule", "")):
                return False
            return True

        for e, r in list(B.items()):
            r["encoding"] = e
        for e, r in list(A.items()):
            r["encoding"] = e
        selB = {e for e, r in B.items() if sel(r)}
        selA = {e for e, r in A.items() if sel(r)}
        pop = selB & selA
        onlyB = selB - selA
        onlyA = selA - selB

        t = collections.Counter()
        reachB, reachA = collections.Counter(), collections.Counter()
        resid = collections.Counter()
        for e in pop:
            b, aa = B[e], A[e]
            rb = srcenc_reach.classify(b)[0]
            ra = srcenc_reach.classify(aa)[0]
            reachB[rb] += 1
            reachA[ra] += 1
            if rb == "INSTRUCTION":
                g = S(b["PUB"]) - S(b["RD"])
                t["src_b"] += len(g)
                t["src_b_enc"] += 1 if g else 0
                d = dst_gap(b, t)
                t["dst_b"] += len(d)
                t["dst_b_enc"] += 1 if d else 0
            if ra == "INSTRUCTION":
                g = S(aa["PUB"]) - S(aa["RD"])
                t["src_a"] += len(g)
                t["src_a_enc"] += 1 if g else 0
                d = dst_gap(aa, t)
                t["dst_a"] += len(d)
                t["dst_a_enc"] += 1 if d else 0
                for r in g:
                    k = {"rule": aa.get("rule", "?"), "mnem": aa["mnem"],
                         "reg": r,
                         "mnem_reg": "%s | %s" % (aa["mnem"], r),
                         "rule_reg": "%s | %s" % (aa.get("rule", "?"), r),
                         }[a.by]
                    resid[k] += 1
            if S(aa["PUB"]) != S(b["PUB"]) or S(aa["PUBD"]) != S(b["PUBD"]):
                t["set_changed"] += 1
            if L(aa["PUB"]) != L(b["PUB"]) or L(aa["PUBD"]) != L(b["PUBD"]):
                t["order_changed"] += 1

        print("=== %s ===  population=%d  only-before=%d  only-after=%d  "
              "wp-conflicts B=%d A=%d" % (isa, len(pop), len(onlyB),
                                          len(onlyA), cb, ca))
        print("  REACH before: %s" % dict(reachB))
        print("  REACH after : %s" % dict(reachA))
        print("  SOURCE  PUB-minus-RD : %d regs / %d enc  ->  %d regs / %d enc"
              % (t["src_b"], t["src_b_enc"], t["src_a"], t["src_a_enc"]))
        print("  DEST    PUBD-minus-WR: %d regs / %d enc  ->  %d regs / %d enc"
              "   (R10.1 REG_PC carve-out applied %d time(s))"
              % (t["dst_b"], t["dst_b_enc"], t["dst_a"], t["dst_a_enc"],
                 t["r10_1_pc"]))
        print("  WIRE    set changed=%d  order changed=%d"
              % (t["set_changed"], t["order_changed"]))
        if t["src_a"]:
            print("  SOURCE RESIDUE, top %d by %s:" % (a.top, a.by))
            rows = sorted(resid.items(), key=lambda kv: (-kv[1], kv[0]))
            shown = rows[:a.top] if a.top else rows
            for k, n in shown:
                print("      %-60s %8d" % (k[:60], n))
            rest = rows[len(shown):]
            if rest:
                print("      ... %d further key(s) totalling %d NOT SHOWN "
                      "(--top %d); the smallest shown is %d"
                      % (len(rest), sum(n for _, n in rest), a.top,
                         shown[-1][1] if shown else 0))
        for k in ("src_b", "src_a", "dst_b", "dst_a", "set_changed",
                  "order_changed"):
            tot[k] += t[k]
    print("=== ALL ===  source %d -> %d   dest %d -> %d   "
          "set-changed %d  order-changed %d"
          % (tot["src_b"], tot["src_a"], tot["dst_b"], tot["dst_a"],
             tot["set_changed"], tot["order_changed"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
