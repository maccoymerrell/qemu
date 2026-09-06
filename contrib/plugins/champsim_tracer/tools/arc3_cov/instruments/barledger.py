#!/usr/bin/env python3
"""EVERY FAMILY IN THE SOURCE BAR GETS A DISPOSITION, OR THIS REFUSES.

THE PROBLEM THIS EXISTS FOR.  The bar was a number per ISA -- 2,527 / 4,096 /
1,093 / 1,819 -- and a number cannot be argued with.  `srcbar.py --tsv` turns
it into 170 families keyed `(decode rule, mnemonic)`.  That is progress and
it is not yet an answer: 170 rows nobody has ruled on is the same silence in
a longer form.

So the families are joined to a CHECKED-IN ADJUDICATION TABLE, and the join
is TOTAL BY CONSTRUCTION:

  * a family matching NO class is a REFUSAL, not a row printed without a
    verdict;
  * a family matching TWO classes is a REFUSAL, because a disposition that
    depends on table order is not a disposition;
  * a class matching NO family is reported as DEAD, which is the
    dead-allowlist-rule tripwire this tree files against everywhere else --
    a rule kept alive by nobody looking at it is how a stale ruling outlives
    the fact it was written about.

THE THREE DISPOSITIONS, and they are exhaustive by rule of the program:

  QEMU-STATES-IT   QEMU's own translation contains the read and the
                   EXTRACTION does not carry it out.  This is a defect with
                   a source site, and the citation column names the file and
                   function.  Closing it is a wire change and owes R13 legs.

  RULED            an architectural fact or a standing ruling says the
                   register is NOT a source, so the arm that drops it is
                   RIGHT and the bar row is not a loss.  The citation names
                   the ruling AND the QEMU code that agrees with it.  A
                   disposition of this kind may not rest on the ruling
                   alone: the row must also carry the arm that measured the
                   whole population, never a sample.

  BLOCKED          a NAMED question stands between the row and a verdict.
                   The question is written out in the note column.  This is
                   the only honest third answer and it is not a parking
                   space: a BLOCKED row with no question is a REFUSAL.

Author: Maccoy Merrell.
"""
import argparse, collections, os, re, sys

DISPOSITIONS = ("QEMU-STATES-IT", "RULED", "BLOCKED")


def load_classes(path):
    """class_id, isa, rule_rx, mnem_rx, reg_rx, disposition, citation, note"""
    out = []
    with open(path) as f:
        for ln, line in enumerate(f, 1):
            if not line.strip() or line.startswith("#"):
                continue
            c = line.rstrip("\n").split("\t")
            if len(c) != 8:
                sys.exit("barledger: %s:%d has %d columns, need 8 -- REFUSING"
                         % (path, ln, len(c)))
            cid, isa, rrx, mrx, grx, disp, cite, note = c
            if disp not in DISPOSITIONS:
                sys.exit("barledger: %s:%d disposition %r is not one of %s "
                         "-- REFUSING" % (path, ln, disp, DISPOSITIONS))
            if not cite.strip():
                sys.exit("barledger: %s:%d (%s) has no citation -- REFUSING; "
                         "a disposition without one is an opinion"
                         % (path, ln, cid))
            if disp == "BLOCKED" and "?" not in note:
                sys.exit("barledger: %s:%d (%s) is BLOCKED and its note asks "
                         "no question -- REFUSING; BLOCKED is a named "
                         "question, not a parking space" % (path, ln, cid))
            out.append(dict(cid=cid, isa=isa, rule=re.compile(rrx),
                            mnem=re.compile(mrx), reg=re.compile(grx),
                            disp=disp, cite=cite, note=note, line=ln,
                            rule_s=rrx, mnem_s=mrx, reg_s=grx))
    return out


def match(classes, isa, rule, mnem, reg):
    hits = [k for k in classes
            if (k["isa"] in ("*", isa)
                and k["rule"].search(rule) and k["mnem"].search(mnem)
                and k["reg"].search(reg))]
    return hits



def selftest(tmp):
    """The whole value of this tool is the REFUSALS, so each one is planted.
    A join that quietly drops a family it cannot classify would print a
    complete-looking ledger over an incomplete bar, which is the failure the
    tool exists against."""
    import shutil, subprocess
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    fam = os.path.join(tmp, "fam.tsv")
    with open(fam, "w") as f:
        f.write("#isa\trule\tmnem\treg\tencodings\tfam_enc\tfam_reg\tmech\n")
        f.write("t\trule_a\tmn_a\tREG_X\t10\t10\t10\tQ-SILENT=10\n")
        f.write("t\trule_b\tmn_b\tREG_Y\t5\t5\t5\tQ-SILENT=5\n")

    def cls(path, rows):
        with open(path, "w") as f:
            f.write("# header\n")
            for r in rows:
                f.write("\t".join(r) + "\n")

    def run(cpath):
        return subprocess.run([sys.executable, __file__, "--families", fam,
                               "--classes", cpath],
                              capture_output=True, text=True)

    fails = 0; n = 0
    def chk(cond, what):
        nonlocal fails, n
        n += 1
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            fails += 1

    GOOD = [("c_a", "t", "rule_a", "mn_a", ".", "RULED", "cite A", "note A"),
            ("c_b", "t", "rule_b", "mn_b", ".", "BLOCKED", "cite B",
             "QUESTION: what?")]
    p_ok = os.path.join(tmp, "ok.tsv"); cls(p_ok, GOOD)
    r = run(p_ok)
    chk(r.returncode == 0 and "EVERY FAMILY IN THE BAR CARRIES A DISPOSITION"
        in r.stdout, "a fully adjudicated bar passes")
    chk("RULED : 10 registers" in r.stdout and "BLOCKED : 5 registers"
        in r.stdout, "and the registers roll up per disposition")

    # AN UNADJUDICATED FAMILY REFUSES.
    p_miss = os.path.join(tmp, "miss.tsv"); cls(p_miss, GOOD[:1])
    r = run(p_miss)
    chk(r.returncode != 0 and "UNADJUDICATED" in r.stdout and "rule_b"
        in r.stdout, "a family matching NO class REFUSES and is NAMED")

    # A FAMILY MATCHING TWO CLASSES REFUSES.
    p_amb = os.path.join(tmp, "amb.tsv")
    cls(p_amb, list(GOOD) + [("c_dup", "t", "rule_a", "mn_a", ".", "RULED",
                              "cite dup", "")])
    r = run(p_amb)
    chk(r.returncode != 0 and "AMBIGUOUS" in r.stdout,
        "a family matching TWO classes REFUSES -- order is not a verdict")

    # A DEAD CLASS IS REPORTED.
    p_dead = os.path.join(tmp, "dead.tsv")
    cls(p_dead, list(GOOD) + [("c_dead", "t", "nothing_here", ".", ".",
                               "RULED", "cite dead", "")])
    r = run(p_dead)
    chk(r.returncode != 0 and "DEAD ADJUDICATION CLASSES" in r.stdout
        and "c_dead" in r.stdout,
        "a class matching NO family is reported DEAD -- the stale-rule "
        "tripwire")

    # A BLOCKED ROW WITH NO QUESTION IS A REFUSAL.
    p_noq = os.path.join(tmp, "noq.tsv")
    cls(p_noq, [GOOD[0], ("c_b", "t", "rule_b", "mn_b", ".", "BLOCKED",
                          "cite B", "we will look at this later")])
    r = run(p_noq)
    chk(r.returncode != 0 and "asks no question" in (r.stdout + r.stderr),
        "BLOCKED without a question REFUSES -- it is not a parking space")

    # A DISPOSITION WITHOUT A CITATION IS A REFUSAL.
    p_noc = os.path.join(tmp, "noc.tsv")
    cls(p_noc, [("c_a", "t", "rule_a", "mn_a", ".", "RULED", "", ""), GOOD[1]])
    r = run(p_noc)
    chk(r.returncode != 0 and "no citation" in (r.stdout + r.stderr),
        "a disposition without a citation REFUSES -- it is an opinion")

    # AN UNKNOWN DISPOSITION IS A REFUSAL.
    p_bad = os.path.join(tmp, "bad.tsv")
    cls(p_bad, [("c_a", "t", "rule_a", "mn_a", ".", "PROBABLY-FINE",
                 "cite", ""), GOOD[1]])
    r = run(p_bad)
    chk(r.returncode != 0 and "is not one of" in (r.stdout + r.stderr),
        "a disposition outside the three REFUSES")

    # AN EMPTY BAR IS A MISSING MEASUREMENT.
    empty = os.path.join(tmp, "empty.tsv")
    open(empty, "w").write("#isa\trule\tmnem\treg\tencodings\tfam_enc\t"
                           "fam_reg\tmech\n")
    r = subprocess.run([sys.executable, __file__, "--families", empty,
                        "--classes", p_ok], capture_output=True, text=True)
    chk(r.returncode != 0 and "REFUSING" in (r.stdout + r.stderr),
        "an EMPTY bar REFUSES; it is never a closed one")
    print("arms=%d failures=%d" % (n, fails))
    return 0 if fails == 0 else 1

def main():
    if "--selftest" in sys.argv:
        i = sys.argv.index("--selftest")
        tmp = (sys.argv[i + 1] if len(sys.argv) > i + 1
               and not sys.argv[i + 1].startswith("-")
               else "/tmp/barledger_st")
        return selftest(tmp)
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", required=True, help="srcbar.py --tsv output")
    ap.add_argument("--classes", default=None,
                    help="the adjudication table (default: beside this file)")
    a = ap.parse_args()
    cpath = a.classes or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "BAR_CLASSES.tsv")
    classes = load_classes(cpath)

    rows = []
    with open(a.families) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            c = line.rstrip("\n").split("\t")
            rows.append(dict(isa=c[0], rule=c[1], mnem=c[2], reg=c[3],
                             enc=int(c[4]), fam_enc=int(c[5]),
                             fam_reg=int(c[6]), mech=c[7]))
    if not rows:
        sys.exit("barledger: %s has no rows -- REFUSING (an empty bar is a "
                 "missing measurement, never a closed one)" % a.families)

    unmatched, ambiguous = [], []
    used = collections.Counter()
    per_class = collections.Counter()
    per_class_isa = collections.defaultdict(collections.Counter)
    per_disp = collections.Counter()
    fams = collections.defaultdict(set)
    for r in rows:
        hits = match(classes, r["isa"], r["rule"], r["mnem"], r["reg"])
        if not hits:
            unmatched.append(r)
            continue
        if len(hits) > 1:
            ambiguous.append((r, [h["cid"] for h in hits]))
            continue
        k = hits[0]
        used[k["cid"]] += 1
        per_class[k["cid"]] += r["enc"]
        per_class_isa[k["cid"]][r["isa"]] += r["enc"]
        per_disp[k["disp"]] += r["enc"]
        fams[k["cid"]].add((r["isa"], r["rule"], r["mnem"]))

    total = sum(r["enc"] for r in rows)
    print("THE SOURCE BAR, ADJUDICATED")
    print("  rows (isa/rule/mnem/register) : %d" % len(rows))
    print("  registers lost, summed        : %d" % total)
    print("  families                      : %d"
          % len({(r["isa"], r["rule"], r["mnem"]) for r in rows}))
    print("  adjudication classes          : %d" % len(classes))
    print()
    byd = collections.defaultdict(list)
    for k in classes:
        byd[k["disp"]].append(k)
    for disp in DISPOSITIONS:
        n = per_disp[disp]
        print("=== %s : %d registers (%.1f%%) ==="
              % (disp, n, 100.0 * n / total if total else 0))
        for k in sorted(byd[disp], key=lambda k: -per_class[k["cid"]]):
            if not used[k["cid"]]:
                continue
            isas = " ".join("%s=%d" % kv
                            for kv in sorted(per_class_isa[k["cid"]].items()))
            print("  %-26s %6d reg  %2d fam  [%s]"
                  % (k["cid"], per_class[k["cid"]], len(fams[k["cid"]]), isas))
            print("        %s" % k["cite"])
            if k["note"]:
                print("        %s" % k["note"])
        print()

    dead = [k for k in classes if not used[k["cid"]]]
    rc = 0
    if dead:
        print("DEAD ADJUDICATION CLASSES -- matched no family in this bar:")
        for k in dead:
            print("  %-26s %s:%d" % (k["cid"], os.path.basename(cpath),
                                     k["line"]))
        print("  A rule nobody's evidence reaches is a rule nobody is "
              "checking.  Either the bar moved and the row should go, or the "
              "pattern is wrong.")
        rc = 1
    if ambiguous:
        print("AMBIGUOUS -- a family matched more than one class:")
        for r, cids in ambiguous[:20]:
            print("  %s %s %s %s -> %s"
                  % (r["isa"], r["rule"], r["mnem"], r["reg"], cids))
        rc = 1
    if unmatched:
        agg = collections.Counter()
        for r in unmatched:
            agg[(r["isa"], r["rule"], r["mnem"])] += r["enc"]
        print("UNADJUDICATED -- %d row(s), %d register(s), %d family/families:"
              % (len(unmatched), sum(r["enc"] for r in unmatched), len(agg)))
        for k, n in sorted(agg.items(), key=lambda kv: (-kv[1], kv[0])):
            print("  %-9s %-46s %-16s %6d" % (k[0], k[1][:46], k[2][:16], n))
        print("  THE BAR IS NOT ADJUDICATED WHILE THIS LIST IS NON-EMPTY.")
        rc = 1
    if rc == 0:
        print("EVERY FAMILY IN THE BAR CARRIES A DISPOSITION AND A CITATION.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
