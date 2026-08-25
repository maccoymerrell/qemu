#!/bin/sh
# ARC 3 -- the x86_64 WRONG-PATH execution leg, end to end.
#
# Two commands, in this order.  The comparison is a result only because the
# control shows every axis it scores CAN go red, so the control is not
# optional and is run FIRST.
#
# Author: Maccoy Merrell.
set -e

: "${QEMU_BUILD:=/mnt/md0/QEMU/qemu/build}"
: "${GEM5_DIR:=/mnt/md0/QEMU/cst_runs/p3/arc3/gem5exec/gem5}"
: "${OUT:=/mnt/md0/QEMU/cst_runs/p3/arc3/x86wp}"
: "${PY:=/home/maccoy-merrell/anaconda3/bin/python}"

HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT/probes"

# The guests.  Every class sits in the SHADOW of a conditional branch, which
# is where the wrong-path walker goes; a straight-line probe kicks no
# excursion at all and would leave the axes unprovable.
"$PY" "$HERE/probes_wp_x86.py" "$OUT/probes"

COMMON="--gem5-dir $GEM5_DIR --gem5-build $GEM5_DIR/build/X86 \
        --qemu $QEMU_BUILD/qemu-x86_64 \
        --plugin $QEMU_BUILD/contrib/plugins/libchampsim_tracer.so \
        --decode $QEMU_BUILD/contrib/plugins/cst_decode"

# 1. THE CONTROL.  Exit status is non-zero when any attempted axis did not
#    fire, or when the injection control did not.
"$PY" "$HERE/selftest_wp_gem5.py" $COMMON -o "$OUT/selftest" \
      "$OUT/probes/p_wpmem" "$OUT/probes/p_wpsse" "$OUT/probes/p_wpchain"

# 2. THE COMPARISON.  Exit status is non-zero when
#    WP-DEFECT + RECONSTRUCTION-GAP + UNACCOUNTED is non-zero, or when the
#    declared/compared identity does not hold.
"$PY" "$HERE/compare_wp_gem5.py" $COMMON --wpdepth 32 \
      -o "$OUT/final" --tsv "$OUT/final/rows.tsv" \
      "$OUT/probes/p_wpmem" "$OUT/probes/p_wpchain" "$OUT/probes/p_wpflag" \
      "$OUT/probes/p_wpsse" "$OUT/probes/p_wpx87"
