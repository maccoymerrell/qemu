#!/bin/sh
# ARC 3 -- the aarch64 WRONG-PATH execution leg, end to end.
#
# Two commands, in this order.  The comparison is a result only because the
# control shows every axis it scores CAN go red, so the control is not
# optional and is run FIRST.
#
# No LD_LIBRARY_PATH, no CST_GEM5_PYLIB and no PYTHONHOME: run under the
# interpreter gem5 was built against and gem5_env.py works the loader path out
# for itself.  The obvious remedy -- exposing the interpreter's whole lib/ --
# SIGSEGVs gem5 at its first cprintf; see gem5/METHOD.md.
#
# Author: Maccoy Merrell.
set -e

: "${QEMU_BUILD:=/mnt/md0/QEMU/qemu/build}"
: "${GEM5_DIR:=/mnt/md0/QEMU/cst_runs/p3/arc3/gem5exec/gem5}"
: "${OUT:=/mnt/md0/QEMU/cst_runs/p3/arc3/a64wp_repro}"
: "${PY:=/home/maccoy-merrell/anaconda3/bin/python}"

HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"

# p_wpcache is IN the run set and is not excluded the way the correct-path leg
# once excluded it: an excursion that aborts the reference is exactly the case
# where the reference's silence must be NAMED rather than read as agreement.
"$PY" "$HERE/probes_wp_a64.py"          "$OUT/wpprobes"
"$PY" "$HERE/../probes/mkprobes_aarch64.py" "$OUT/cpprobes"

G="$OUT/wpprobes/p_wpmem $OUT/wpprobes/p_wpchain $OUT/wpprobes/p_wpsel
   $OUT/wpprobes/p_wpcache
   $OUT/cpprobes/p_int $OUT/cpprobes/p_mem $OUT/cpprobes/p_simd
   $OUT/cpprobes/p_atomic $OUT/cpprobes/p_fp $OUT/cpprobes/p_flow
   $OUT/cpprobes/p_hint"

COMMON="--gem5-dir $GEM5_DIR --qemu $QEMU_BUILD/qemu-aarch64
        --plugin $QEMU_BUILD/contrib/plugins/libchampsim_tracer.so
        --decode $QEMU_BUILD/contrib/plugins/cst_decode"

env -u LD_LIBRARY_PATH -u CST_GEM5_PYLIB -u PYTHONHOME \
  "$PY" "$HERE/selftest_wp_a64.py" $COMMON -o "$OUT/nc" $G

env -u LD_LIBRARY_PATH -u CST_GEM5_PYLIB -u PYTHONHOME \
  "$PY" "$HERE/compare_wp_a64.py" $COMMON --wpdepth 32 --max 0 \
      -o "$OUT/final" --tsv "$OUT/rows.tsv" $G
