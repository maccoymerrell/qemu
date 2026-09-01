#!/bin/bash
# THE SLED'S REACHABILITY GATE: score the per-encoding source-loss bar over
# the encodings the sled reached as INSTRUCTIONS, and name everything it did
# not.
#
#   srcenc_reach_gate.sh classify <build-dir> <reach.tsv> <mech-corpus>...
#   srcenc_reach_gate.sh compare  <build-dir> <A.tsv> <B.tsv> <reach.tsv>
#   srcenc_reach_gate.sh plant    <build-dir> <A.tsv> <B.tsv> <reach.tsv>
#   srcenc_reach_gate.sh --selftest
#
# WHY IT IS A SIBLING OF srcenc_loss_gate.sh AND NOT AN EDIT TO IT.
# srcenc_loss_gate scores the WHOLE population of a capture, which over a
# guest workload is the right population: every encoding in it was executed.
# Over the SLED it is not.  A sled slot is bytes at an address, and QEMU is
# free to decode nothing (an unimplemented encoding, or one that is illegal
# in the sled's flat architectural context) or to translate an ACCESS TRAP
# instead of the instruction (an enable check that refused).  exec89 measured
# at least 559,523 of 2,908,759 "losing" encodings -- 19.2% -- to be one of
# those two, and a bar computed over them is scoring the sled's context, not
# the tracer.
#
# So this gate exists beside that one, with the same instrument underneath
# (arc3_cov/instruments/srcenc_ab.py) and one restriction: the population is
# the encodings srcenc_reach.py classified REACHED=INSTRUCTION.  Matched
# coverage is still checked over the FULL population inside the instrument,
# so the restriction cannot hide an arm that stopped reaching an encoding,
# and the excluded rows are printed by class and by rule.
#
# THE BAR is UNADJUDICATED losses == 0 over REACHED=INSTRUCTION.
#
# rc=0 PASS, rc=1 FAIL, rc=2 REFUSED.  rc=2 is never folded into rc=0: a gate
# that cannot look must not report all-clear.  Both instruments' own
# planted-fire selftests are run before every compare, because an instrument
# nobody has shown can fire is not evidence.
#
# Author: Maccoy Merrell.
set -u

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
py=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
ab=$here/arc3_cov/instruments/srcenc_ab.py
rch=$here/arc3_cov/instruments/srcenc_reach.py
led=${CST_SRCENC_LEDGER:-$here/srcenc_loss_adjudicated.txt}

selftests() {
    "$py" "$rch" --selftest > /dev/null 2>&1
    r=$?
    if [ "$r" != 0 ]; then
        echo "srcenc_reach_gate: REFUSED -- the reach discriminator's own" \
             "constructed-case proof did not pass (rc=$r)."
        return 2
    fi
    "$py" "$ab" --selftest > /dev/null 2>&1
    r=$?
    if [ "$r" != 0 ]; then
        echo "srcenc_reach_gate: REFUSED -- the A/B instrument's own" \
             "planted-fire proof did not pass (rc=$r)."
        return 2
    fi
    return 0
}

mode=${1:?usage: srcenc_reach_gate.sh classify|compare|plant|--selftest ...}
shift

if [ "$mode" = "--selftest" ]; then
    selftests || exit 2
    echo "srcenc_reach_gate: both instrument selftests PASS"
    exit 0
fi

build=${1:?build directory}
shift
if [ ! -x "$build/qemu-x86_64" ] && [ ! -f "$build/contrib/plugins/libchampsim_tracer.so" ]; then
    echo "srcenc_reach_gate: REFUSED -- $build is not a build directory."
    exit 2
fi

case $mode in
classify)
    out=${1:?output reach.tsv}
    shift
    [ $# -gt 0 ] || { echo "srcenc_reach_gate: REFUSED -- no mechanism" \
                           "corpus named.  A classification with no subject" \
                           "is not one."; exit 2; }
    args=()
    for m in "$@"; do
        if [ ! -f "$m" ]; then
            echo "srcenc_reach_gate: REFUSED -- $m does not exist."
            exit 2
        fi
        args+=(--mech "$m")
    done
    "$py" "$rch" "${args[@]}" --out "$out" --report
    exit $?
    ;;
compare)
    A=${1:?arm A corpus}; B=${2:?arm B corpus}; RE=${3:?reach corpus}
    for f in "$A" "$B" "$RE"; do
        if [ ! -f "$f" ]; then
            echo "srcenc_reach_gate: REFUSED -- $f does not exist." \
                 "A gate that cannot find its subject FAILS."
            exit 2
        fi
    done
    selftests || exit 2
    "$py" "$ab" "$A" "$B" --adjudicated "$led" --reach "$RE"
    rc=$?
    case $rc in
    0) echo "srcenc_reach_gate: PASS -- no encoding the sled reached as an" \
            "INSTRUCTION lost a published source" ;;
    1) echo "srcenc_reach_gate: FAIL -- a reached instruction lost a" \
            "published source, or a ledger row has no subject" ;;
    *) echo "srcenc_reach_gate: REFUSED (rc=$rc)" ;;
    esac
    exit $rc
    ;;
plant)
    # THE PLANTED FIRES, ON THE REAL CORPORA.  A selftest over constructed
    # rows shows the instrument can fire; it does not show that THIS
    # measurement's population can carry a fire, which is the claim a zero
    # over it makes.  Two plants, in opposite directions:
    #
    #   1. a register removed from a REACHED=INSTRUCTION encoding -- the bar
    #      must go RED;
    #   2. the same removal on an encoding the reach corpus classes
    #      TRAP-TRANSLATED -- the bar must stay GREEN and the row must appear
    #      in the excluded enumeration.
    #
    # A plant that produces an empty file is the tool REFUSING, not firing;
    # both plants assert their subject exists before they are scored.
    A=${1:?arm A corpus}; B=${2:?arm B corpus}; RE=${3:?reach corpus}
    for f in "$A" "$B" "$RE"; do
        [ -f "$f" ] || { echo "srcenc_reach_gate: REFUSED -- $f missing."; exit 2; }
    done
    selftests || exit 2
    tmp=$(mktemp -d) || exit 2
    trap 'rm -rf "$tmp"' EXIT
    "$py" - "$A" "$B" "$RE" "$tmp" <<'PLANT'
import sys, os
A, B, RE, tmp = sys.argv[1:5]
reach = {}
for line in open(RE, errors="replace"):
    if line.startswith("#"):
        continue
    f = line.rstrip("\n").split("\t")
    if len(f) >= 3:
        reach[(f[0], f[1].lower())] = f[2]

def pick(cls):
    for line in open(A, errors="replace"):
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) < 4 or not f[3].strip() or f[3].strip() == "-":
            continue
        if reach.get((f[0], f[1].lower())) == cls:
            return f[0], f[1], f[3].split(",")[0]
    return None

def write(path, victim):
    isa, enc, reg = victim
    n = 0
    with open(path, "w") as out:
        for line in open(B, errors="replace"):
            if line.startswith("#"):
                out.write(line); continue
            f = line.rstrip("\n").split("\t")
            if len(f) >= 4 and f[0] == isa and f[1].lower() == enc.lower():
                regs = [r for r in f[3].split(",") if r and r != reg]
                f[3] = ",".join(regs) or "-"
                n += 1
            out.write("\t".join(f) + "\n")
    if n != 1:
        sys.exit("PLANT REFUSED: rewrote %d rows for %s %s, wanted exactly 1"
                 % (n, isa, enc))
    return isa, enc, reg

vi = pick("INSTRUCTION")
vt = pick("TRAP-TRANSLATED")
if vi is None:
    sys.exit("PLANT REFUSED: the corpus carries no REACHED=INSTRUCTION "
             "encoding with a published source to remove")
if vt is None:
    sys.exit("PLANT REFUSED: the corpus carries no TRAP-TRANSLATED encoding "
             "with a published source to remove -- the second plant has no "
             "subject and its GREEN would prove nothing")
print("PLANT-1 (must FIRE)      %s %s LOST=%s" % write(tmp + "/b_insn.tsv", vi))
print("PLANT-2 (must stay GREEN) %s %s LOST=%s" % write(tmp + "/b_trap.tsv", vt))
PLANT
    [ $? = 0 ] || { echo "srcenc_reach_gate: REFUSED -- the plant could not" \
                         "be built."; exit 2; }
    "$py" "$ab" "$A" "$tmp/b_insn.tsv" --adjudicated "$led" --reach "$RE" \
        > "$tmp/o1" 2>&1; r1=$?
    "$py" "$ab" "$A" "$tmp/b_trap.tsv" --adjudicated "$led" --reach "$RE" \
        > "$tmp/o2" 2>&1; r2=$?
    grep -E "UNADJUDICATED LOSSES|VERDICT" "$tmp/o1" | sed 's/^/  plant-1: /'
    grep -E "UNADJUDICATED LOSSES|VERDICT" "$tmp/o2" | sed 's/^/  plant-2: /'
    ok=0
    [ "$r1" = 1 ] || { echo "PLANT-1 DID NOT FIRE (rc=$r1)"; ok=1; }
    [ "$r2" = 0 ] || { echo "PLANT-2 FIRED (rc=$r2) -- a trap row is being" \
                            "scored"; ok=1; }
    [ "$ok" = 0 ] && echo "srcenc_reach_gate: PLANTED FIRES OK -- a reached" \
                          "loss fires, a trap loss does not"
    exit $ok
    ;;
*)
    echo "srcenc_reach_gate: REFUSED -- unknown mode '$mode'."
    exit 2
    ;;
esac
