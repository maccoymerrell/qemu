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

# THE CONTROL'S TWO SHORTFALLS ARE NOT THE SAME SHORTFALL, AND `set -e` USED
# TO TREAT THEM AS ONE.  selftest_wp_a64.py returned 1 both when a mutation it
# wrote failed to make its axis fire -- a comparator that cannot see what it
# scores, and disqualifying -- and when an axis simply had no instance of its
# fact anywhere in the probe set.  `set -e` then killed this script before the
# comparison ran, so a control whose every attempted axis FIRED produced no
# report at all and the R13 gate read REPORT MISSING.
#
# MEASURED at exec237/r13/gem5wp_aarch64.log: `AXES WITH A FIRING MUTATION:
# 13 of 13 attempted`, `INJECTION CONTROL: FIRED`, `NO MUTATION AVAILABLE
# (no excursion in this set carries an instance of the fact): fpsr-dst-set,
# sys-src-set`, rc=1, and `final/` never created.
#
# rc=2 is now that second case alone.  The comparison runs, and the gap's own
# line is APPENDED TO THE REPORT below so it travels with the number -- a gap
# recorded only in SELFTEST.txt is a gap nothing downstream reads, which is
# the survivorship shape this tree keeps having to relearn.  Closing it means
# writing a probe that carries an FPSR write and a system-register read into a
# wrong-path shadow, not lowering this bar.
set +e
env -u LD_LIBRARY_PATH -u CST_GEM5_PYLIB -u PYTHONHOME \
  "$PY" "$HERE/selftest_wp_a64.py" $COMMON -o "$OUT/nc" $G
NC_RC=$?
set -e
case "$NC_RC" in
  0) NC_GAP= ;;
  2) NC_GAP=$(grep '^NO MUTATION AVAILABLE' "$OUT/nc/SELFTEST.txt") ;;
  *) echo "selftest_wp_a64 rc=$NC_RC -- an axis this control attempted did" >&2
     echo "not fire, or the injection control did not.  The comparison is" >&2
     echo "NOT scored: see $OUT/nc/SELFTEST.txt" >&2
     exit "$NC_RC" ;;
esac

# The axis control mutates only pairs whose baseline is clean on the axis it
# targets, and every cache-maintenance row is dirty by construction -- so it
# proves nothing about the four rules that account for them.  Those rules get
# their own control, which breaks the trace's cache records the way a real
# defect would and requires each rule to REFUSE.
# Same two-shortfall split as above, and for the same reason: rc=2 is "this
# run produced no clean excursion carrying a cache-maintenance rule", which
# means those rules accounted for nothing here and there is no row for a
# too-broad one to launder.  rc=1 (a rule covered a broken record) and rc=3
# (gem5 did not run) both still stop the leg.
set +e
env -u LD_LIBRARY_PATH -u CST_GEM5_PYLIB -u PYTHONHOME \
  "$PY" "$HERE/selftest_wp_cache_a64.py" $COMMON -o "$OUT/nc_cache" \
      "$OUT/wpprobes/p_wpcache"
NCC_RC=$?
set -e
case "$NCC_RC" in
  0) ;;
  2) NC_GAP="$NC_GAP
  no clean excursion carrying a cache-maintenance rule (selftest_wp_cache_a64 rc=2)" ;;
  *) echo "selftest_wp_cache_a64 rc=$NCC_RC -- a cache-maintenance rule" >&2
     echo "covered a record a real defect would have broken, or gem5 did" >&2
     echo "not run.  The comparison is NOT scored." >&2
     exit "$NCC_RC" ;;
esac

# The comparison's own exit status is the leg's, so it is taken from the
# process and reported after the gap line is appended -- a report that exists
# and a leg that failed are different facts and both are wanted.
set +e
env -u LD_LIBRARY_PATH -u CST_GEM5_PYLIB -u PYTHONHOME \
  "$PY" "$HERE/compare_wp_a64.py" $COMMON --wpdepth 32 --max 0 \
      -o "$OUT/final" --tsv "$OUT/rows.tsv" $G
CMP_RC=$?
set -e

if [ -n "$NC_GAP" ] && [ -f "$OUT/final/REPORT.txt" ]; then
    {
        echo
        echo "AXIS COVERAGE SHORTFALL (from the negative control, rc=2):"
        echo "  $NC_GAP"
        echo "  The comparison scores no fact on those axes either, so the"
        echo "  headline above is over the axes that HAD a subject.  Closing"
        echo "  this needs a probe carrying the fact, not a wider ceiling."
    } >> "$OUT/final/REPORT.txt"
fi
exit "$CMP_RC"
