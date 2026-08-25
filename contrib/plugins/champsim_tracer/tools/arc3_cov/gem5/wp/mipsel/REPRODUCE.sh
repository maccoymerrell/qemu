#!/bin/sh
# ARC 3 -- the mipsel WRONG-PATH execution leg, end to end.
#
# Two commands, in this order.  The comparison is a result only because the
# control shows every axis it scores CAN go red, so the control is not
# optional and is run FIRST.
#
# Author: Maccoy Merrell.
set -e

: "${QEMU_BUILD:=/mnt/md0/QEMU/qemu/build}"
: "${GEM5_DIR:=/mnt/md0/QEMU/cst_runs/p3/arc3/gem5exec/gem5}"
: "${OUT:=/mnt/md0/QEMU/cst_runs/p3/arc3/mipswp_repro}"
: "${PY:=/home/maccoy-merrell/anaconda3/bin/python}"

HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"

"$PY" "$HERE/probes_wp_mipsel.py"            "$OUT/wprobes"
"$PY" "$HERE/../../probes/mkprobes_mipsel.py" "$OUT/probes"

# p_flow is the correct-path probe that kicks excursions; the p_wp* guests put
# the classes worth measuring in the shadow of a conditional branch.
G="$OUT/probes/p_flow $(ls -d "$OUT"/wprobes/p_wp* | grep -v '\.' | tr '\n' ' ')"

COMMON="--gem5-dir $GEM5_DIR --qemu $QEMU_BUILD/qemu-mipsel
        --plugin $QEMU_BUILD/contrib/plugins/libchampsim_tracer.so
        --decode $QEMU_BUILD/contrib/plugins/cst_decode"

env -u LD_LIBRARY_PATH -u CST_GEM5_PYLIB -u PYTHONHOME \
  "$PY" "$HERE/selftest_wp_mipsel.py" $COMMON -o "$OUT/nc" $G

env -u LD_LIBRARY_PATH -u CST_GEM5_PYLIB -u PYTHONHOME \
  "$PY" "$HERE/compare_wp_mipsel.py" $COMMON --wpdepth 16 --max 0 \
      -o "$OUT/final" --tsv "$OUT/rows.tsv" $G
