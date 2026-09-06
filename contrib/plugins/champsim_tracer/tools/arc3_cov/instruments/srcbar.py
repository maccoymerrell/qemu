#!/usr/bin/env python3
"""exec91 -- THE LOSS BAR RE-DERIVED OVER REACHED=INSTRUCTION ROWS ONLY.

Arm A = the tip, arm B = the banked exec72 step-3 deletion.  Both arms are the
wp0 and wp16 sweeps MERGED per ISA (a duplicate encoding whose register set
disagrees across the two wp settings is a CONFLICT and is counted, never a
last-writer-wins).  Matched coverage is a precondition and is reported.

Every losing encoding is decomposed by MECHANISM (exec89's mechclass, on arm
A's own mechanism row) and by REACH (the structural discriminator that lands
in the tree as srcenc_reach.py), and the two are crossed.  The headline is the
bar over REACH=INSTRUCTION; the excluded population is printed by class and by
rule so it can be argued row-class by row-class rather than as a total.

IN THE TREE, AND WHY THAT TOOK UNTIL NOW
----------------------------------------
This scorer produced the SOURCE bar for nine passes as a copy inside a wave
root -- exec91 wrote it, exec135 and verify62 each carried their own.  The
DESTINATION bar was promoted for that reason (`dstbar.py`), and the census
after it (`cph_census.py`, whose header records the number that could not be
re-derived once its run directory was gone).  The source bar is the LAST of
the three still un-promoted, and it is the one the deletion is measured
against: `9,535 encodings / 11,035 registers` is quoted in the standing
records, and until now the only route back to it was a directory a disk
sweep is entitled to delete.

WHAT THE PROMOTION ADDS, BEYOND BEING RE-DERIVABLE
--------------------------------------------------
THE BAR IS NOW DECOMPOSED, not just totalled.  The excluded population has
been printed by class and rule since exec91 -- the INCLUDED population, the
bar itself, has only ever been a number per ISA.  A total is not something a
declaration can be aimed at; exec136's `abandoned_families.py` made that
argument for the write side and this is the same argument for the read side.
Each losing encoding is grouped by its FAMILY -- `(decode rule, mnemonic)`,
the key `dstbar.py` already reports its own rows under -- and crossed with
the register that is lost and the mechanism that lost it.

THE ORDERING IS DETERMINISTIC (FINDING 83-E).  Two passes' reports were 96
lines with every scored number identical and differed by exactly ONE line,
at the truncation boundary of a tie at count 17: `Counter.most_common()`
leaves equal counts in insertion order, and insertion order over a set is
not stable across runs.  Every table here sorts by `(-count, key)`, so a
tie is broken by the key's own name and a truncation boundary inside a tie
falls in the same place every time.
"""
import argparse, collections, os, sys
sys.path.insert(0, "/mnt/md0/QEMU/qemu/contrib/plugins/champsim_tracer/tools/"
                   "arc3_cov/instruments")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import srcenc_reach                      # the tree's discriminator
from evopen import evopen, resolve     # the tree's compressed-member reader


#: THE REFUSAL SET, joined from an arm that carries it.
#:
#: Adding a reach class means BOTH ends of the trajectory must be re-derived
#: on the NEW discriminator (the 49-B rule), and an arm captured before
#: insn_dataflow_note_translation_refused() existed carries no `refused` key
#: at all.  Joining just that ONE BIT from an arm that does carry it -- over
#: the same encoding population -- lets the base end be scored on the new
#: discriminator using its OWN register columns, which is what the rule asks
#: for.  It is legitimate because the statement is proven CAPTURE-ONLY: the
#: whole-population RD / WR / PUB / PUBD diff across the arm that added it is
#: 0 on all four ISAs, so nothing about the translation moved, only what the
#: target says about it.
def load_refused(arm, isa, wps):
    if not arm:
        return None
    out = set()
    can_answer = False
    for w in wps:
        p = os.path.join(arm, "%s.wp%s" % (isa, w), "corpus_mech_%s.tsv" % isa)
        if not os.path.exists(resolve(p)):
            sys.exit("refused-arm: %s missing -- REFUSING" % p)
        with evopen(p, errors="replace") as f:
            hdr = None
            for line in f:
                if line.startswith("#"):
                    if hdr is None:
                        hdr = line.lstrip("#").rstrip().split("\t")
                    continue
                c = line.rstrip("\n").split("\t")
                if hdr is None or len(c) < len(hdr):
                    continue
                row = dict(zip(hdr, c))
                if "refused=" in row.get("XLAT", ""):
                    can_answer = True
                    if "refused=1" in row["XLAT"]:
                        out.add(c[1])
    if not can_answer:
        # The arm predates insn_dataflow_note_translation_refused(), so its
        # rows carry no `refused` key in EITHER direction.  That is a corpus
        # that cannot answer, and it must not read as a clean zero.  An arm
        # that CAN answer and finds none is a different fact -- riscv64
        # states nothing today -- and is returned as the empty set.
        sys.exit("refused-arm: %s carries no `refused` key for %s -- "
                 "REFUSING (a corpus that cannot answer must not read as a "
                 "clean zero)" % (arm, isa))
    return out


def classify_joined(row, refused):
    """srcenc_reach.classify(), with the refusal bit joined in first."""
    if (refused is not None and row["encoding"] in refused
            and "refused=" not in row.get("XLAT", "")):
        row = dict(row, XLAT=row.get("XLAT", "") + ",refused=1")
    return srcenc_reach.classify(row)
from mechclass import mech_of            # exec89's mechanism classifier,
                                        # promoted beside this file

ISAS = ("x86_64", "aarch64", "riscv64", "mipsel")


def ordered(counter, cap=0):
    """(-count, key) -- FINDING 83-E.  `most_common()` leaves ties in
    insertion order, and insertion order over a set is not stable across
    runs, so a truncation boundary that falls inside a tie moves between
    passes.  Every table in this file goes through here."""
    rows = sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return rows[:cap] if cap else rows


def print_trunc(rows, shown, indent, cap, what):
    """A cut table SAYS it was cut, and by how much.  dstbar.py's header
    records the nine passes in which it did not: the eighth aarch64 row was
    1,185 and every register below it read as zero."""
    rest = rows[len(shown):]
    if rest:
        print("%s... %d further %s totalling %d NOT SHOWN (--famtop %d); "
              "the smallest shown is %d"
              % (indent, len(rest), what, sum(n for _, n in rest), cap,
                 shown[-1][1] if shown else 0))


def read_src_merged(paths):
    """encoding -> (mnem, frozenset(regs)); conflicts across wp arms counted."""
    d, conf = {}, 0
    for p in paths:
        with evopen(p, errors="replace") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                c = line.rstrip("\n").split("\t")
                if len(c) < 4:
                    continue
                regs = frozenset(r for r in c[3].split(",") if r and r != "-")
                prev = d.get(c[1])
                if prev is not None and prev[1] != regs:
                    conf += 1
                d[c[1]] = (c[2], regs)
    return d, conf


def read_mech_merged(paths):
    d, conf = {}, 0
    hdr = None
    for p in paths:
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
    return d, conf, hdr



MECH_HDR = ("#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\twstate\t"
            "PUB\tQN\tSURV\tRD\tSTATUS\tRDX\tCONT\tXLAT\tWR\tPUBD\t"
            "WSTQ\tOPC\tBR\tCFLAGS\tREFINE\tLANEK\tLANEP\tWRU\n")
OKS = "PUBLISHED from QEMU's emitters"


def _arm(root, isa, rows, srcidx):
    """Write one arm dir.  `srcidx` picks which of a row's two source lists
    is published, so the same row table builds arm A and arm B."""
    d = os.path.join(root, "%s.wp0" % isa)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "corpus_%s.tsv" % isa), "w") as f:
        f.write("#isa\tencoding\tmnem\tsrc\n")
        for r in rows:
            f.write("%s\t%s\t%s\t%s\n" % (isa, r["enc"], r["mnem"],
                                            r["src"][srcidx]))
    with open(os.path.join(d, "corpus_mech_%s.tsv" % isa), "w") as f:
        f.write(MECH_HDR)
        for r in rows:
            f.write("\t".join([
                isa, r["enc"], r["mnem"], r["did"], r["rule"], OKS, OKS,
                "-", "-", r.get("surv", "-"), "-", r.get("status", "-"), "-",
                "-", r["xlat"], r.get("wr", "REG_PC"), "-", OKS,
                "GEN_OP_ALU", "-", "-", "-", "0", "0", "0"]) + "\n")
    return d


def selftest(tmp):
    """Nine arms.  The bar is a number other people quote, so each of its
    parts must be shown to MOVE when the thing it measures moves, and the
    decomposition must be shown to roll up to the headline exactly."""
    import shutil, subprocess
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    isa = "riscv64"
    # enc, mnem, (srcA, srcB), rule, decode_id, XLAT
    BODY = "noret=0,calls=0,memr=0,memw=0,refused=0"
    RAISE = "noret=1,calls=1,memr=0,memw=0,refused=0"
    rows = [
        # a real loss under a body translation -- IN the bar
        dict(enc="01", mnem="add", src=("R1,R2", "R1"), did="aa",
             rule="decode_insn32/add", xlat=BODY),
        # a second family, two registers lost -- IN the bar
        dict(enc="02", mnem="mul", src=("R1,R2,R3", "R1"), did="bb",
             rule="decode_insn32/mul", xlat=BODY),
        # same family as 01: families group, they do not multiply
        dict(enc="03", mnem="add", src=("R4,R5", "R4"), did="aa",
             rule="decode_insn32/add", xlat=BODY),
        # NO-DECODE: decode_id 0.  Losing, and OUT of the bar.
        dict(enc="04", mnem="?", src=("R1,R2", "R1"), did="0",
             rule="?", xlat=BODY),
        # no loss at all -- never counted anywhere
        dict(enc="05", mnem="sub", src=("R1", "R1"), did="cc",
             rule="decode_insn32/sub", xlat=BODY),
    ]
    A = os.path.join(tmp, "A"); B = os.path.join(tmp, "B")
    _arm(A, isa, rows, 0)
    _arm(B, isa, rows, 1)

    def run(*extra):
        return subprocess.run([sys.executable, __file__, "--a", A, "--b", B,
                               "--isa", isa, "--wps", "0"] + list(extra),
                              capture_output=True, text=True)

    out = run().stdout
    fails = 0; n = 0
    def chk(cond, what):
        nonlocal fails, n
        n += 1
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            fails += 1

    chk("REACH=INSTRUCTION: 3   <-- THE BAR" in out,
        "the bar counts the three body rows and NOT the NO-DECODE one")
    chk("LOSING ENCODINGS, ALL REACH CLASSES: 4" in out,
        "the NO-DECODE loss is counted in the population it belongs to")
    chk("THE BAR BY FAMILY (decode rule / mnemonic): 2 families, "
        "3 encodings / 4 registers" in out,
        "the decomposition ROLLS UP to the headline -- 2 families, 3 enc")
    chk("decode_insn32/add" in out and "decode_insn32/mul" in out,
        "both families are named")
    chk("decode_insn32/sub" not in out,
        "a family that loses nothing does not appear")
    # R2 (from 01 and 02), R3 (02), R5 (03) = THREE distinct.  The
    # NO-DECODE row also loses R2 and contributes nothing here, which is the
    # property being asserted: the register table is the BAR's, not the
    # losing population's.
    chk("THE BAR BY LOST REGISTER: 3 distinct" in out,
        "the register table enumerates the BAR's losses, not the whole "
        "losing population's")
    chk("R2                          2" in out,
        "and it counts encodings per register -- R2 is lost by two of them")
    chk("decode_insn32/mul" in out.split("BY FAMILY AND LOST REGISTER")[1]
        .split("BY LOST REGISTER")[0],
        "each family is crossed with the register it loses, so a family "
        "losing two registers is two adjudications and not one")
    # TRUNCATION SAYS SO
    out_t = run("--famtop", "1").stdout
    chk("NOT SHOWN (--famtop 1)" in out_t,
        "a cut family table SAYS it was cut and by how much")
    # THE ROLLUP GUARD FIRES.  Plant a mech row the bar reaches and the
    # family key cannot: an INSTRUCTION row whose rule column is absent is
    # impossible by construction, so the guard is exercised by removing a
    # row from the mech corpus instead -- the bar then counts it nowhere and
    # `nomech` must say so rather than the family total silently shrinking.
    import re as _re
    mp = os.path.join(A, "%s.wp0" % isa, "corpus_mech_%s.tsv" % isa)
    keep = [l for l in open(mp) if not l.startswith("%s\t02\t" % isa)]
    open(mp, "w").writelines(keep)
    out_m = run().stdout
    chk("(mech row missing for 1)" in out_m,
        "an encoding with no mechanism row is COUNTED as missing, never "
        "silently dropped into a family")
    chk("2 encodings / 2 registers" in out_m,
        "and the family rollup follows the bar down rather than diverging")
    # A MISSING ARM REFUSES.
    os.remove(mp)
    r = run()
    chk(r.returncode != 0 and "REFUSING" in (r.stdout + r.stderr),
        "a missing corpus REFUSES; it is never an empty population")
    print("arms=%d failures=%d" % (n, fails))
    return 0 if fails == 0 else 1

def main():
    if "--selftest" in sys.argv:
        i = sys.argv.index("--selftest")
        tmp = (sys.argv[i + 1] if len(sys.argv) > i + 1
               and not sys.argv[i + 1].startswith("-")
               else "/tmp/srcbar_st")
        return selftest(tmp)
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", required=True, help="sledA dir")
    ap.add_argument("--b", required=True, help="sledB dir")
    ap.add_argument("--isa", action="append", default=None)
    ap.add_argument("--wps", default="0 16")
    #: 0 = every family.  A bar decomposed for the purpose of aiming a
    #: declaration at each row must not silently stop at the interesting ones.
    ap.add_argument("--famtop", type=int, default=0)
    #: THE FAMILY TABLE AS DATA.  The report is for reading; the ledger that
    #: adjudicates each family is written against a table, and re-parsing a
    #: printed report to get one is how a column width becomes a semantic.
    ap.add_argument("--tsv", default=None,
                    help="write the family/register rows here as TSV")
    a = ap.parse_args()
    isas = a.isa or list(ISAS)
    wps = a.wps.split()

    grand = collections.Counter()
    grand_r = collections.Counter()
    tsv = None
    if a.tsv:
        tsv = open(a.tsv, "w")
        tsv.write("#isa\trule\tmnem\treg\tencodings\tfam_enc\tfam_reg\t"
                  "mech\n")
    excl_rules = {}
    tot_all = collections.Counter()

    for isa in isas:
        REFUSED = load_refused(os.environ.get("REFUSEDARM"), isa, wps)
        pa = [os.path.join(a.a, "%s.wp%s" % (isa, w), "corpus_%s.tsv" % isa)
              for w in wps]
        pb = [os.path.join(a.b, "%s.wp%s" % (isa, w), "corpus_%s.tsv" % isa)
              for w in wps]
        pm = [os.path.join(a.a, "%s.wp%s" % (isa, w),
                           "corpus_mech_%s.tsv" % isa) for w in wps]
        for p in pa + pb + pm:
            if not os.path.exists(resolve(p)):
                sys.exit("bar: %s missing -- REFUSING" % p)
        A, ca = read_src_merged(pa)
        B, cb = read_src_merged(pb)
        M, cm, _ = read_mech_merged(pm)

        shared = set(A) & set(B)
        only_a, only_b = set(A) - set(B), set(B) - set(A)
        print("=== %s ===" % isa)
        print("  arm A encodings=%d  arm B encodings=%d  shared=%d"
              "  only_A=%d  only_B=%d" % (len(A), len(B), len(shared),
                                          len(only_a), len(only_b)))
        print("  wp-merge conflicts: A=%d B=%d mech=%d" % (ca, cb, cm))
        if only_a or only_b:
            print("  *** COVERAGE ERROR: the arms do not cover the same "
                  "encodings; the counts below are not readable ***")

        per = collections.Counter()      # (reach, mech) -> losing encodings
        perreg = collections.Counter()   # (reach, mech) -> losing registers
        nomech = 0
        # THE BAR'S OWN DECOMPOSITION.  Keyed the way a fix is aimed: the
        # decode RULE that produced the identity, the MNEMONIC under it, and
        # the register that is lost.  `famenc` counts encodings once per
        # family; `famreg` counts registers, so the two columns are the same
        # pair the headline prints and they roll up to it exactly.
        famenc = collections.Counter()   # (rule, mnem) -> encodings
        famreg = collections.Counter()   # (rule, mnem) -> registers
        fammech = collections.defaultdict(collections.Counter)
        famrow = collections.Counter()   # (rule, mnem, reg) -> encodings
        barreg = collections.Counter()   # reg -> losing encodings
        for enc in shared:
            lost = A[enc][1] - B[enc][1]
            if not lost:
                continue
            m = M.get(enc)
            if m is None:
                nomech += 1
                continue
            reach, sub, _ = classify_joined(m, REFUSED)
            # mechclass.mech_of() reads the per-pc witness's own key spelling;
            # the corpus header spells three of them in capitals.  Translated
            # here rather than by renaming either side, so exec89's classifier
            # is the SAME code and this reading is comparable to its own.
            mech, _st = mech_of(dict(src_state=m["src_state"],
                                     surv=m["SURV"], status=m["STATUS"]), lost)
            per[(reach, mech)] += 1
            perreg[(reach, mech)] += len(lost)
            grand[(reach, mech)] += 1
            grand_r[(reach, mech)] += len(lost)
            tot_all[isa] += 1
            if reach != "INSTRUCTION":
                d = excl_rules.setdefault((isa, reach), collections.Counter())
                d[m.get("rule", "?")] += 1
            else:
                fam = (m.get("rule", "?"), m.get("mnem", "?"))
                famenc[fam] += 1
                famreg[fam] += len(lost)
                fammech[fam][mech] += 1
                for r in sorted(lost):
                    famrow[(fam[0], fam[1], r)] += 1
                    barreg[r] += 1

        tot = sum(per.values())
        ins = sum(v for k, v in per.items() if k[0] == "INSTRUCTION")
        print("  LOSING ENCODINGS, ALL REACH CLASSES: %d  (mech row missing "
              "for %d)" % (tot, nomech))
        print("  LOSING ENCODINGS, REACH=INSTRUCTION: %d   <-- THE BAR" % ins)
        for k in sorted(per, key=lambda k: (-per[k], str(k))):
            print("    %-16s %-18s enc=%-9d regs=%d"
                  % (k[0], k[1], per[k], perreg[k]))
        bar_fam_enc = sum(famenc.values())
        bar_fam_reg = sum(famreg.values())
        if bar_fam_enc != ins:
            sys.exit("srcbar: family rollup %d != bar %d on %s -- REFUSING"
                     % (bar_fam_enc, ins, isa))
        print("  THE BAR BY FAMILY (decode rule / mnemonic): %d families, "
              "%d encodings / %d registers" % (len(famenc), bar_fam_enc,
                                               bar_fam_reg))
        frows = ordered(famenc)
        fshown = frows[:a.famtop] if a.famtop else frows
        for (rule, mnem), n in fshown:
            mechs = ",".join("%s=%d" % (k, v)
                             for k, v in ordered(fammech[(rule, mnem)]))
            print("      %7d enc %7d reg  %-44s %-14s %s"
                  % (n, famreg[(rule, mnem)], rule[:44], mnem[:14],
                     mechs[:46]))
        print_trunc(frows, fshown, "      ", a.famtop, "family/families")
        if tsv is not None:
            for (rule, mnem, r), nrow in ordered(famrow):
                fam = (rule, mnem)
                tsv.write("%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n"
                          % (isa, rule, mnem, r, nrow, famenc[fam],
                             famreg[fam],
                             ",".join("%s=%d" % kv
                                      for kv in ordered(fammech[fam]))))
        print("  THE BAR BY FAMILY AND LOST REGISTER: %d rows" % len(famrow))
        xrows = ordered(famrow)
        xshown = xrows[:a.famtop] if a.famtop else xrows
        for (rule, mnem, r), n in xshown:
            print("      %7d  %-44s %-14s %s" % (n, rule[:44], mnem[:14], r))
        print_trunc(xrows, xshown, "      ", a.famtop, "row(s)")
        print("  THE BAR BY LOST REGISTER: %d distinct" % len(barreg))
        rrows = ordered(barreg)
        rshown = rrows[:a.famtop] if a.famtop else rrows
        for r, n in rshown:
            print("      %-20s %8d" % (r, n))
        print_trunc(rrows, rshown, "      ", a.famtop, "register(s)")
        print()

    print("=== ALL ISAs ===")
    tot = sum(grand.values())
    ins = sum(v for k, v in grand.items() if k[0] == "INSTRUCTION")
    for k in sorted(grand, key=lambda k: (-grand[k], str(k))):
        print("  %-16s %-18s enc=%-9d regs=%d" % (k[0], k[1], grand[k],
                                                  grand_r[k]))
    print("  GRAND TOTAL, ALL REACH CLASSES : %d encodings / %d registers"
          % (tot, sum(grand_r.values())))
    print("  THE HONEST BAR (REACH=INSTRUCTION): %d encodings / %d registers"
          % (ins, sum(v for k, v in grand_r.items()
                      if k[0] == "INSTRUCTION")))
    print("  EXCLUDED                          : %d encodings / %d registers"
          % (tot - ins, sum(grand_r.values())
             - sum(v for k, v in grand_r.items() if k[0] == "INSTRUCTION")))
    if tsv is not None:
        tsv.close()
    print()
    print("=== THE EXCLUDED LOSING POPULATION, BY ISA / CLASS / RULE ===")
    for key in sorted(excl_rules):
        d = excl_rules[key]
        print("  %s / %s   %d encodings, %d distinct rules"
              % (key[0], key[1], sum(d.values()), len(d)))
        for rn, n in ordered(d, 15):
            print("      %-58s %8d" % (rn[:58], n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
