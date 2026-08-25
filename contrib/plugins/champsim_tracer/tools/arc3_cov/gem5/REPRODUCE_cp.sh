#!/bin/sh
# ARC 3 -- the gem5 CORRECT-PATH execution legs, end to end, for one ISA.
#
#   usage: REPRODUCE_cp.sh <x86_64|aarch64|mipsel>
#
# Four steps, in this order, and none of them is optional:
#
#   1. THE PROBES.  Regenerated from their generator, so the leg cannot be
#      run against a probe set nobody can rebuild.
#   2. THE NEGATIVE CONTROL, FIRST.  The comparison is a result only because
#      every axis it scores can be made to convict; an axis nobody could
#      falsify is not a validated axis.  Exit status is non-zero when any
#      axis did not fire.
#   3. THE COMPARISON.  Exit status is non-zero when TRACER-SUBSET or
#      UNACCOUNTED is non-zero, when an axis is INERT, or when the
#      declared/compared identity does not hold.
#   4. x86_64 ONLY -- THE THIRD REFERENCE.  PIN, on real silicon, running the
#      same probes.  It writes a per-row adjudication and the comparison is
#      then RE-RUN with it, so that a gem5 row a third witness overturns is
#      labelled from a measurement instead of from an argument.  The
#      adjudication can only ever CONVICT the trace, never excuse it: where
#      PIN returns gem5's value the row keeps a label that does not account.
#
# Every exit code is taken from the process.  Nothing is read through a pipe.
#
# Author: Maccoy Merrell.
set -e

ISA=${1:?usage: REPRODUCE_cp.sh <x86_64|aarch64|mipsel>}
: "${QEMU_DIR:=/mnt/md0/QEMU/qemu}"
: "${GEM5_DIR:=/mnt/md0/QEMU/cst_runs/p3/arc3/gem5exec/gem5}"
: "${OUT:=/mnt/md0/QEMU/cst_runs/p3/arc3/cpexec/$ISA}"
: "${PY:=/home/maccoy-merrell/anaconda3/bin/python}"
: "${PIN_ROOT:=/mnt/md0/PIN/pin-external-4.2-99776-g21d818fa2-gcc-linux}"

HERE=$(cd "$(dirname "$0")" && pwd)
PINTOOLS=$HERE/../../arc3_pinexec
mkdir -p "$OUT"

case "$ISA" in
x86_64)  GEN=mkprobes_x86_64.py
         SET="p_int p_mem p_simd p_x87 p_flow p_atomic" ;;
aarch64) GEN=mkprobes_aarch64.py
         SET="p_int p_mem p_simd p_atomic p_fp p_flow p_hint p_cache" ;;
mipsel)  GEN=mkprobes_mipsel.py
         SET="p_int p_mem p_fp p_flow" ;;
*) echo "unknown ISA $ISA" >&2; exit 2 ;;
esac

"$PY" "$HERE/probes/$GEN" "$OUT/probes" > "$OUT/probes.log"
GUESTS=""
for g in $SET; do GUESTS="$GUESTS $OUT/probes/$g"; done

COMMON="--isa $ISA --gem5-dir $GEM5_DIR --qemu-dir $QEMU_DIR \
        --decode $QEMU_DIR/build/contrib/plugins/cst_decode"

# 1. THE CONTROL.
"$PY" "$HERE/selftest_cp_gem5.py" $COMMON -o "$OUT/selftest" $GUESTS

# 2. THE COMPARISON.
"$PY" "$HERE/compare_exec_gem5.py" $COMMON \
      -o "$OUT/final" --tsv "$OUT/final/rows.tsv" $GUESTS \
    || echo "compare_exec_gem5 rc=$? (named rows; see $OUT/final/REPORT.txt)"

# 3. x86_64: the third reference, then the comparison again with its answer.
if [ "$ISA" = x86_64 ]; then
    "$PY" "$HERE/cmp3_x86.py" \
        --gem5-dir "$GEM5_DIR" --qemu-dir "$QEMU_DIR" \
        --decode "$QEMU_DIR/build/contrib/plugins/cst_decode" \
        --pin-root "$PIN_ROOT" --pin-tools "$PINTOOLS" \
        --gem5-out "$OUT/final" -o "$OUT/three" \
        --tsv "$OUT/three/rows.tsv" \
        --adjudication "$OUT/three/adjud.tsv" $GUESTS \
        || echo "cmp3_x86 rc=$? (see $OUT/three/REPORT.txt)"
    "$PY" "$HERE/compare_exec_gem5.py" $COMMON \
        --pin-adjudicate "$OUT/three/adjud.tsv" \
        -o "$OUT/adjudicated" --tsv "$OUT/adjudicated/rows.tsv" $GUESTS \
        || echo "compare_exec_gem5 (adjudicated) rc=$? -- see \
$OUT/adjudicated/REPORT.txt"
fi

echo "done: $OUT"
