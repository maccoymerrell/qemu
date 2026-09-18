#!/bin/sh
# ARC 3 -- the riscv64 CORRECT-PATH execution leg against Spike, end to end.
#
# WHY THIS FILE DID NOT EXIST, AND WHAT RAN IN ITS PLACE.  FINDING 239-B.
# ---------------------------------------------------------------------------
# Every other execution leg has a REPRODUCE script; this one had README prose
# and a `python compare_exec.py ...` block, so the `spikecp` R13 row had no
# entry point a driver could name.  What the inherited wave driver named for
# it was `arc3_cov/riscv64/REPRODUCE.sh` -- the SAIL REGISTER-ATTRIBUTION
# sweep, which is the `static`/riscv64 row and answers a different question
# entirely.  That script refuses without its banked denominator tree
# (`clauses.json`, `rows.json`, `ref/sail-riscv`), so `spikecp rc=2` was
# recorded, read as "the leg refuses", and carried forward as a blocker on
# this row for two waves.  The blocker was about a script that is not this
# leg.
#
# THE CONTROL IS RUN, AND IT IS RUN SECOND HERE, WHICH IS THE DIFFERENCE.
# The wrong-path legs run their control FIRST because `selftest_wp*.py` builds
# its own pairs.  `selftest_exec.py` does not: it takes a spike commit log and
# a `.cst` trace that already exist and perturbs one fact on one side of a
# real aligned pair.  Those artifacts are what the comparison produces, per
# guest, as `<outdir>/<guest>.commits.log` and `<outdir>/<guest>.cst`.  So the
# order is comparison then control, and the control's exit status is taken
# from the process and reported -- an UNPROVEN axis disqualifies the leg
# exactly as it does everywhere else, and the comparison's own report is on
# disk either way so the gate can see which of the two failed.
#
# Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -e

: "${QEMU_BUILD:=/mnt/md0/QEMU/qemu/build}"
: "${SPIKE:=/mnt/md0/QEMU/cst_runs/spike_probe/build/spike}"
: "${PK:=/mnt/md0/QEMU/cst_runs/p3/arc3/spike_exec/pkbuild/pk}"
: "${DTC_DIR:=/mnt/md0/QEMU/cst_runs/spike_probe/dtc}"
: "${VALDIR:=/mnt/md0/QEMU/cst_runs/p3/arc3/spike_exec}"
: "${OUT:=/mnt/md0/QEMU/cst_runs/p3/arc3/rvcp}"
: "${PY:=/home/maccoy-merrell/anaconda3/bin/python}"

HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"

# EVERY PREREQUISITE IS CHECKED BEFORE ANY WORK.  A leg that cannot find its
# reference must say which one, not die three frames inside a comparison.
for f in "$SPIKE" "$PK"; do
    [ -x "$f" ] || { echo "REFUSED: $f is not executable." >&2
                     echo "  spike must be the PATCHED build (spike-patches/)" >&2
                     echo "  and pk the riscv-pk build; see README.md." >&2
                     exit 2; }
done
[ -d "$DTC_DIR" ] || { echo "REFUSED: no dtc directory $DTC_DIR (spike needs" >&2
                       echo "  dtc on PATH)." >&2; exit 2; }

# The guests.  The same probe set the wrong-path leg uses for its correct-path
# half, plus the five generated validator programs -- real programs rather
# than probes, which is what stops the leg's population being a set of
# hand-written class exercises.
"$PY" "$HERE/probes/mkprobes.py" "$OUT/cpprobes"

G="$OUT/cpprobes/p_atomic $OUT/cpprobes/p_flow $OUT/cpprobes/p_fp
   $OUT/cpprobes/p_int $OUT/cpprobes/p_mem $OUT/cpprobes/p_muldiv
   $OUT/cpprobes/p_vec
   $VALDIR/val_1/val_1_riscv64         $VALDIR/val_31337/val_31337_riscv64
   $VALDIR/val_4242/val_4242_riscv64   $VALDIR/val_7/val_7_riscv64
   $VALDIR/val_90210/val_90210_riscv64"

COMMON="--spike $SPIKE --pk $PK --qemu $QEMU_BUILD/qemu-riscv64
        --plugin $QEMU_BUILD/contrib/plugins/libchampsim_tracer.so
        --decode $QEMU_BUILD/contrib/plugins/cst_decode --dtc-dir $DTC_DIR"

# 1. THE COMPARISON.  Exit status is non-zero when TRACER-SUBSET +
#    UNACCOUNTED is non-zero, when an instruction is unaligned for a reason
#    the trap log does not explain, or when any axis is UNPROVEN.  The report
#    is written whichever way it goes.
CMP_RC=0
"$PY" "$HERE/compare_exec.py" $COMMON \
      -o "$OUT/final" --tsv "$OUT/final/exec_attrib.tsv" $G || CMP_RC=$?

# 2. THE CONTROL, over the artifacts the comparison just produced.  It is run
#    on ONE guest -- the mutation is per aligned pair and the axes it proves
#    are properties of the comparator, not of the guest -- and the guest has
#    to be one that carries a subject for every axis, because an axis with no
#    subject reports UNPROVEN and an UNPROVEN axis fails the leg.
#
#    `p_int` WAS that guest and IS NOT ONE: it carries no CSR access and no
#    load, so csr-src-set, csr-dst-set, csr-dst-value and load-data had
#    nothing to perturb and this control has been exiting 1 on all four for
#    as long as the CSR axes have existed.  The comparison's own per-axis
#    control, which picks a guest per axis, proved them live in the same run
#    -- so the leg was reporting a failure of its fixture, not of itself.
#
#    `p_fp` carries all twelve: GPR and FP destinations with values, a store
#    and a load (fsw/flw) for the memop axes, and -- since the fcsr access is
#    stated at QEMU's FP decode sites -- a CSR source, a CSR destination and a
#    CSR destination VALUE the reference also names.
NC_RC=0
"$PY" "$HERE/selftest_exec.py" \
      --commits "$OUT/final/p_fp.commits.log" \
      --trace   "$OUT/final/p_fp.cst" \
      --guest   "$OUT/cpprobes/p_fp" \
      --decode  "$QEMU_BUILD/contrib/plugins/cst_decode" \
      > "$OUT/final/SELFTEST.txt" 2>&1 || NC_RC=$?

if [ "$NC_RC" != 0 ]; then
    echo "selftest_exec rc=$NC_RC -- an axis this control attempted did not" >&2
    echo "fire.  The comparison's own headline is on disk but is NOT a" >&2
    echo "result: see $OUT/final/SELFTEST.txt" >&2
    exit "$NC_RC"
fi
exit "$CMP_RC"
