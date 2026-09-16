#!/bin/sh
# ARC 3 / R13 -- the DEPENDENCY-MAP leg, end to end, for one ISA.
#
#   usage: REPRODUCE_depmap.sh <x86_64|aarch64>
#
# WHY THIS LEG EXISTS.  R13 makes external truth a standing gate on every
# wire-changing wave, and the dependency map is wire content -- so a map with
# no external leg is a hole in the gate's own rule.  Every other check of the
# four dependency families compares the map against the thing that produces
# it: irdf reads QEMU's TCG, CP-M and CP-H are QEMU's own emitters, and
# Capstone gives architectural operands with no edges at all.  gem5 cracks a
# macro-op into micro-ops carrying explicit srcRegIdx / destRegIdx lists, and
# that cracking is what makes an EDGE observable.  See score_depmap.py for the
# method and its scope guard.
#
# THREE STEPS, AND THE CONTROLS ARE NOT OPTIONAL.
#
#   1. THE PROBES, regenerated from their generator, so the leg cannot be run
#      against a probe set nobody can rebuild.
#   2. THE BASELINE, kept, because the controls are scored as MOVEMENT off it.
#   3. THE FIVE FALSIFIERS, each of which MUST move a published number.  An
#      axis nobody could falsify is not a validated axis; an arm that does not
#      fire fails this script.  The arms split across the two columns on
#      purpose -- drop-edge and swap-addr-data convict in the loss column,
#      add-edge and all-to-all in the precision column, drop-addr-edge in
#      whichever the ISA's addressing puts it -- which is the whole reason the
#      gate holds BOTH numbers against a ceiling.
#   4. THE PUBLISHED RUN, into <root>/gem5/depmap_<isa>/REPORT.md, which is
#      the path ADJUDICATED.tsv names.
#
# Every exit code is taken from the process that produced it.  A step whose
# subject is missing is a failure, never a skip.
#
# Author: Maccoy Merrell.
set -e

ISA=${1:?usage: REPRODUCE_depmap.sh <x86_64|aarch64>}
: "${QEMU_DIR:=/mnt/md0/QEMU/qemu}"
: "${GEM5_DIR:=/mnt/md0/QEMU/cst_runs/p3/arc3/gem5exec/gem5}"
: "${OUT:=/mnt/md0/QEMU/cst_runs/p3/arc3/depmap/$ISA}"
: "${PY:=/home/maccoy-merrell/anaconda3/bin/python}"
#: the evidence root the R13 gate scores; the report lands under it
: "${EVROOT:=$OUT/evroot}"

HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"

case "$ISA" in
x86_64)  GEN=mkprobes_x86_64.py
         SET="p_int p_mem p_simd p_x87 p_flow p_atomic" ;;
aarch64) GEN=mkprobes_aarch64.py
         SET="p_int p_mem p_simd p_atomic p_fp p_flow p_hint p_cache" ;;
*) echo "unknown ISA $ISA -- this leg models gem5 micro-op decomposition for\
 x86_64 and aarch64 only; see README.md" >&2; exit 2 ;;
esac

"$PY" "$HERE/probes/$GEN" "$OUT/probes" > "$OUT/probes.log"
GUESTS=""
for g in $SET; do GUESTS="$GUESTS $OUT/probes/$g"; done

COMMON="--isa $ISA --gem5-dir $GEM5_DIR --qemu-dir $QEMU_DIR \
        --decode $QEMU_DIR/build/contrib/plugins/cst_decode"

# Both numbers are read out of the report the scorer wrote, never carried
# forward from a variable this script set: the report is the artefact the
# gate scores, so it is the artefact the controls are read from too.
loss() { sed -n 's/^THE NUMBER THAT MATTERS: MISSING-EDGE + BOTH = \([0-9]*\)$/\1/p' "$1"; }
prec() { sed -n 's/^PRECISION-DISCARDED (STRICTLY-SMALLER) = \([0-9]*\)$/\1/p' "$1"; }

# 1+2. THE BASELINE.  Its own rc is NOT this script's verdict: the scorer
# exits non-zero whenever the loss column is non-zero, and a loss row that a
# maintainer has adjudicated row by row lives in ADJUDICATED.tsv, not here.
# What must hold at this step is that the run PRODUCED a report.
"$PY" "$HERE/score_depmap.py" $COMMON -o "$OUT/base" $GUESTS \
    > "$OUT/base.log" 2>&1 || true
test -s "$OUT/base/REPORT.md" || { echo "BASELINE PRODUCED NO REPORT" >&2
                                   tail -20 "$OUT/base.log" >&2; exit 3; }
BL=$(loss "$OUT/base/REPORT.md"); BP=$(prec "$OUT/base/REPORT.md")
echo "baseline: loss=$BL precision=$BP"

# 3. THE FALSIFIERS.
FAILED=0
for f in drop-edge add-edge swap-addr-data all-to-all drop-addr-edge; do
    "$PY" "$HERE/score_depmap.py" $COMMON --falsify "$f" -o "$OUT/f_$f" \
        $GUESTS > "$OUT/f_$f.log" 2>&1 || true
    if ! test -s "$OUT/f_$f/REPORT.md"; then
        echo "FALSIFIER $f PRODUCED NO REPORT -- the control cannot be read"
        FAILED=1
        continue
    fi
    FL=$(loss "$OUT/f_$f/REPORT.md"); FP=$(prec "$OUT/f_$f/REPORT.md")
    if [ "$FL" = "$BL" ] && [ "$FP" = "$BP" ]; then
        echo "FALSIFIER $f DID NOT FIRE: loss $BL->$FL precision $BP->$FP"
        FAILED=1
    else
        echo "falsifier $f FIRED: loss $BL->$FL precision $BP->$FP"
    fi
done
test "$FAILED" = 0 || { echo "A CONTROL DID NOT FIRE -- the leg is not\
 validated at this tip, so it does not report a result" >&2; exit 4; }

# 4. THE PUBLISHED RUN.
mkdir -p "$EVROOT/gem5/depmap_$ISA"
"$PY" "$HERE/score_depmap.py" $COMMON -o "$EVROOT/gem5/depmap_$ISA" $GUESTS \
    > "$OUT/final.log" 2>&1 || true
test -s "$EVROOT/gem5/depmap_$ISA/REPORT.md" || {
    echo "PUBLISHED RUN PRODUCED NO REPORT" >&2; exit 3; }
echo "done: $EVROOT/gem5/depmap_$ISA/REPORT.md  (loss=$(loss \
"$EVROOT/gem5/depmap_$ISA/REPORT.md") precision=$(prec \
"$EVROOT/gem5/depmap_$ISA/REPORT.md"))"
