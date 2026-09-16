#!/bin/sh
# ARC 3 -- the riscv64 WRONG-PATH execution leg, end to end.
#
# Two commands, in this order.  The comparison is a result only because the
# control shows every axis it scores CAN go red, so the control is not
# optional and is run FIRST.
#
# Author: Maccoy Merrell.
set -e

: "${QEMU_BUILD:=/mnt/md0/QEMU/qemu/build}"
: "${SPIKE:=/mnt/md0/QEMU/cst_runs/spike_probe/build/spike}"
: "${PK:=/mnt/md0/QEMU/cst_runs/p3/arc3/spike_exec/pkbuild/pk}"
: "${DTC_DIR:=/mnt/md0/QEMU/cst_runs/spike_probe/dtc}"
: "${VALDIR:=/mnt/md0/QEMU/cst_runs/p3/arc3/spike_exec}"
: "${OUT:=/mnt/md0/QEMU/cst_runs/p3/arc3/rvwp}"
: "${PY:=/home/maccoy-merrell/anaconda3/bin/python}"

HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"

# The guests.  The correct-path probe set covers ISA classes on the CORRECT
# path and contributes the excursions a straight-line probe never kicks;
# p_wpmem and p_wpchain put sub-word, FP and RVV work -- and a dependent-load
# chain, so the excursion's own addresses depend on data the reconstruction
# had to get right -- in the shadow of a conditional branch.  The five
# validator guests are real generated programs rather than probes.
"$PY" "$HERE/../probes/mkprobes.py" "$OUT/cpprobes"
"$PY" "$HERE/probes_wp.py"          "$OUT/wpprobes"

G="$OUT/cpprobes/p_atomic $OUT/cpprobes/p_flow $OUT/cpprobes/p_fp
   $OUT/cpprobes/p_int $OUT/cpprobes/p_mem $OUT/cpprobes/p_muldiv
   $OUT/cpprobes/p_vec $OUT/wpprobes/p_wpchain $OUT/wpprobes/p_wpmem
   $VALDIR/val_1/val_1_riscv64         $VALDIR/val_31337/val_31337_riscv64
   $VALDIR/val_4242/val_4242_riscv64   $VALDIR/val_7/val_7_riscv64
   $VALDIR/val_90210/val_90210_riscv64"

COMMON="--spike $SPIKE --qemu $QEMU_BUILD/qemu-riscv64
        --plugin $QEMU_BUILD/contrib/plugins/libchampsim_tracer.so
        --decode $QEMU_BUILD/contrib/plugins/cst_decode --dtc-dir $DTC_DIR"

# 1. THE CONTROL.  Non-zero when any attempted axis did not fire, or when the
#    injection control or the identity control did not.  selftest_wp.py takes
#    no --pk: it never runs the pk-hosted arm.
"$PY" "$HERE/selftest_wp.py" $COMMON --wpdepth 16 -o "$OUT/nc" $G

# 2. THE COMPARISON.  Non-zero when WP-DEFECT + RECONSTRUCTION-GAP +
#    UNACCOUNTED is non-zero, or when the declared/compared identity does not
#    hold.
"$PY" "$HERE/compare_wp.py" $COMMON --pk "$PK" --wpdepth 32 --max 0 \
      -o "$OUT/final" --tsv "$OUT/rows.tsv" $G
