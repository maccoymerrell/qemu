#!/usr/bin/env python3
"""Decompose a per-encoding SOURCE LOSS set by MECHANISM.

Inputs
  --a  corpus_<isa>.tsv from arm A (the tip: the operand walk still supplies
       the read side)
  --b  corpus_<isa>.tsv from arm B (the walk's read arm deleted)
  --mech corpus_mech_<isa>.tsv from arm A (the mechanism columns)

A LOSS is a register published in A and absent in B for the SAME encoding.
Only encodings present in BOTH arms are scored; an encoding in one arm only is
UNREACHED and counted apart, never scored as agreement.

MECHANISM, per losing encoding, decided from arm A's own mechanism row:

  R-REFUSED     QEMU's read list was REFUSED for this encoding (src_state is
                one of the refusal states).  QEMU knows the operands; the
                extraction did not survive.  Split by whether the refusal
                carries helper_unbounded.
  R-SHORT       the read list is a declared LOWER BOUND (QDEP_R_SHORT):
                extraction incomplete, what there was was taken.
  Q-SILENT      QEMU STATED a complete read list (QDEP_OK) and it does not
                mention the lost register.  The statement is the thing that
                is missing, not the extraction.
  NO-BLOCK      QEMU stated nothing at all for this instruction (QDEP_NONE).
  SURV-ONLY     the lost register is in the survivor table for this decode
                identity -- i.e. it is covered today and still lost, which
                would be a survivor-seating defect rather than a statement
                gap.  Checked first because it refutes the others.

Author: Maccoy Merrell.
"""
import argparse, collections, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# THE CORPUS THIS READS IS ARCHIVED COMPRESSED BY THE DISK RULE.
# Named uncompressed and opened with open(), a swept corpus is a
# FileNotFoundError at best and a decompression frame handed to a
# line parser at worst; see evopen.py's own header for the arm
# where that printed a population of zero as though the corpus
# had said so.  Promoted into the tree reading through the sweep.
from evopen import evopen

REFUSAL_PREFIX = "refused:"
SHORT_PREFIX   = "LOWER BOUND:"
OK_STATE       = "PUBLISHED from QEMU's emitters"
NONE_STATE     = "no accesses / no dataflow ABI"

def read_src(path):
    d = {}
    with evopen(path, errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                continue
            c = line.rstrip("\n").split("\t")
            if len(c) < 4:
                continue
            regs = frozenset(r for r in c[3].split(",") if r and r != "-")
            d[c[1]] = (c[2], regs)
    return d

def read_mech(path):
    d = {}
    with evopen(path, errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                continue
            c = line.rstrip("\n").split("\t")
            if len(c) < 14:
                continue
            d[c[1]] = dict(mnem=c[2], decode_id=c[3], rule=c[4],
                           src_state=c[5], wstate=c[6],
                           pub=c[7], qn=c[8], surv=c[9], rd=c[10],
                           status=c[11], rdx=c[12], cont=c[13])
    return d

def mech_of(m, lost):
    if m is None:
        return "NO-MECH-ROW", ""
    surv = set(r for r in m["surv"].split(",") if r and r != "-")
    if lost & surv:
        return "SURV-ONLY", ""
    st = m["src_state"]
    helper = "helper_unbounded" in m["status"]
    if st.startswith(SHORT_PREFIX):
        return ("R-SHORT+helper" if helper else "R-SHORT"), st
    if st.startswith(REFUSAL_PREFIX):
        return ("R-REFUSED+helper" if helper else "R-REFUSED"), st
    if st == OK_STATE:
        return ("Q-SILENT+helper" if helper else "Q-SILENT"), st
    if st == NONE_STATE:
        return "NO-BLOCK", st
    return "OTHER:" + st[:40], st

SELFTEST_MECH_HDR = ("#isa\tencoding\tmnem\tdecode_id\trule\tsrc_state\t"
                     "wstate\tPUB\tQN\tSURV\tRD\tSTATUS\tRDX\tCONT\n")

def selftest(tmp):
    """Twelve arms.  Every mechanism class must be REACHED by a constructed
    case, and every non-loss shape must be rejected -- a classifier nobody has
    made produce each of its own answers is a classifier whose zeros mean
    nothing."""
    import os, subprocess
    os.makedirs(tmp, exist_ok=True)
    rows = [
        # enc, mnem, srcA,        srcB,      src_state,      status, surv, want
        ("01", "ok",   "R1,R2",   "R1,R2",   OK_STATE,       "-", "-",  None),
        ("02", "sil",  "R1,R2",   "R1",      OK_STATE,       "-", "-",  "Q-SILENT"),
        ("03", "silh", "R1,R2",   "R1",      OK_STATE,
                                             "helper_unbounded,", "-", "Q-SILENT+helper"),
        ("04", "shrt", "R1,R2",   "R1",      SHORT_PREFIX + " x", "-", "-", "R-SHORT"),
        ("05", "shrth","R1,R2",   "R1",      SHORT_PREFIX + " x",
                                             "helper_unbounded,", "-", "R-SHORT+helper"),
        ("06", "ref",  "R1,R2",   "R1",      REFUSAL_PREFIX + " y", "-", "-", "R-REFUSED"),
        ("07", "refh", "R1,R2",   "R1",      REFUSAL_PREFIX + " y",
                                             "helper_unbounded,", "-", "R-REFUSED+helper"),
        ("08", "nob",  "R1,R2",   "R1",      NONE_STATE,     "-", "-",  "NO-BLOCK"),
        ("09", "sv",   "R1,R2",   "R1",      OK_STATE,       "-", "R2", "SURV-ONLY"),
    ]
    fa, fb, fm = tmp + "/a.tsv", tmp + "/b.tsv", tmp + "/m.tsv"
    with open(fa, "w") as A, open(fb, "w") as B, open(fm, "w") as M:
        A.write("#isa\tencoding\tmnem\tsrc\n")
        B.write("#isa\tencoding\tmnem\tsrc\n")
        M.write(SELFTEST_MECH_HDR)
        for enc, mn, sa, sb, st, status, surv, _ in rows:
            A.write("t\t%s\t%s\t%s\n" % (enc, mn, sa))
            B.write("t\t%s\t%s\t%s\n" % (enc, mn, sb))
            M.write("t\t%s\t%s\t00\trule_%s\t%s\t%s\t%s\t-\t%s\t-\t%s\t-\t-\n"
                    % (enc, mn, mn, st, OK_STATE, sa, surv, status))
        # an encoding with NO mechanism row at all, and one only arm A has
        A.write("t\t0a\tnomech\tR1,R2\n"); B.write("t\t0a\tnomech\tR1\n")
        A.write("t\t0b\tonlya\tR1\n")
        B.write("t\t0c\tonlyb\tR1\n")
    out = subprocess.run([sys.executable, __file__, "--isa", "t",
                          "--a", fa, "--b", fb, "--mech", fm],
                         capture_output=True, text=True).stdout
    fails = 0
    n = 0
    def chk(cond, what):
        nonlocal fails, n
        n += 1
        print(("PASS  " if cond else "FAIL  ") + what)
        if not cond:
            fails += 1
    for enc, mn, sa, sb, st, status, surv, want in rows:
        if want is None:
            continue
        chk(("  %-22s" % want) in out or (want + " ") in out,
            "%s reaches mechanism %s" % (mn, want))
    chk("LOSING encodings=9" in out, "the no-loss encoding is NOT counted (9 of 10 matched lose)")
    chk("NO-MECH-ROW" in out, "an encoding with no mechanism row gets its OWN class, never a guessed one")
    chk("mechanism rows missing=1" in out, "an encoding with no mechanism row is COUNTED, not silently classed")
    chk("onlyA=1 onlyB=1" in out, "unmatched encodings are reported apart and not scored")

    # THE COMPRESSED ARM.  Reading through the sweep is a capability, and a
    # capability with no arm is a claim.  The corpus is compressed under the
    # SAME name the caller keeps passing -- that is the whole contract -- and
    # the output must not move by one byte.
    import gzip, shutil
    for src in (fa, fm):
        with open(src, "rb") as r, gzip.open(src + ".gz", "wb") as w:
            shutil.copyfileobj(r, w)
        os.remove(src)
    out_z = subprocess.run([sys.executable, __file__, "--isa", "t",
                            "--a", fa, "--b", fb, "--mech", fm],
                           capture_output=True, text=True).stdout
    chk(out_z == out, "a corpus compressed under the caller's own name reads "
                      "BYTE-IDENTICALLY (the disk rule may not move a number)")
    chk(out_z != "", "the compressed arm is not vacuous -- it produced output")
    print("arms=%d failures=%d" % (n, fails))
    return 0 if fails == 0 else 1


def main():
    if "--selftest" in sys.argv:
        i = sys.argv.index("--selftest")
        tmp = sys.argv[i + 1] if len(sys.argv) > i + 1 else "/tmp/mechclass_st"
        sys.exit(selftest(tmp))
    ap = argparse.ArgumentParser()
    ap.add_argument("--isa", required=True)
    ap.add_argument("--a", required=True)
    ap.add_argument("--b", required=True)
    ap.add_argument("--mech", required=True)
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--dump-mnem", default=None)
    a = ap.parse_args()

    A, B, M = read_src(a.a), read_src(a.b), read_mech(a.mech)
    only_a = len(set(A) - set(B))
    only_b = len(set(B) - set(A))
    no_mech = 0

    enc_by_mech  = collections.Counter()
    reg_by_mech  = collections.Counter()
    mnem_by_mech = collections.defaultdict(set)
    rule_by_mech = collections.Counter()
    detail       = collections.Counter()
    losing = 0
    per_mnem = collections.Counter()

    for enc, (mnem, ra) in A.items():
        if enc not in B:
            continue
        lost = ra - B[enc][1]
        if not lost:
            continue
        losing += 1
        m = M.get(enc)
        if m is None:
            no_mech += 1
        k, st = mech_of(m, lost)
        enc_by_mech[k] += 1
        reg_by_mech[k] += len(lost)
        mnem_by_mech[k].add(mnem)
        per_mnem[(k, mnem)] += 1
        if m is not None:
            rule_by_mech[(k, m["rule"])] += 1
        if st:
            detail[(k, st)] += 1

    print("=== %s ===" % a.isa)
    print("  arm A encodings=%d  arm B=%d  matched=%d  onlyA=%d onlyB=%d"
          % (len(A), len(B), len(set(A) & set(B)), only_a, only_b))
    print("  LOSING encodings=%d   mechanism rows missing=%d" % (losing, no_mech))
    print("  %-22s %10s %10s %10s" % ("mechanism", "encodings", "registers", "mnemonics"))
    for k, v in enc_by_mech.most_common():
        print("  %-22s %10d %10d %10d"
              % (k, v, reg_by_mech[k], len(mnem_by_mech[k])))
    print("  -- top decode RULES per mechanism --")
    seen = collections.Counter()
    for (k, rule), v in rule_by_mech.most_common():
        if seen[k] >= 6:
            continue
        seen[k] += 1
        print("     %-18s %8d  %s" % (k, v, rule[:70]))
    if a.dump_mnem:
        with open(a.dump_mnem, "w") as f:
            for (k, mn), v in per_mnem.most_common():
                f.write("%s\t%s\t%s\t%d\n" % (a.isa, k, mn, v))

if __name__ == "__main__":
    main()
