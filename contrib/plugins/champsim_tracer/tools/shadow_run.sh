#!/bin/bash
# THE SHADOW SIDECAR ARM: fresh at-tip sidecars over the banked shadow corpus,
# one ISA per invocation.  The SIDECAR is the product; the .cst is proven
# compressed from cst_audit's own member line and then dropped.
#
#   shadow_run.sh <isa> <out-dir> [--build-dir DIR] [--seed N] [--cells DIR]...
#
# THE SEED IS NOT OPTIONAL AND THAT IS THE POINT.  This lived as a pass-local
# script, copied forward and edited, and every copy invoked qemu-user with no
# `-seed`.  qemu-user seeds its guest randomness from the host when the option
# is absent, so two runs of the same binary at the same tip take DIFFERENT
# wrong paths -- measured at exec120 on `prog.mipsel` wp16: two unseeded runs
# differ in Dyn WP bits (4,183,520 vs 4,183,632) and in the census rows built
# from them, while two runs at `-seed 4242` produce a BYTE-IDENTICAL sidecar
# and `-seed 99` differs again.
#
# What that cost: FINDING 69-B scored a row (mipsel `sdc2`, REG_COPROC0 under
# decode id 0) as firing 7 times in 60 runs and read the 53 zeros as a
# property of the row.  They were a property of the seed.  A census over an
# unreproducible wrong path cannot distinguish "did not fire" from "was not
# reached this time", so its zeros are not evidence -- and `setarch -R` does
# not close it, because it disables host ASLR and says nothing about the
# guest's own random stream.
#
# WHAT THE SEED DOES NOT CLOSE, measured here rather than assumed.  Two runs
# of `exec59/cells/heldout_mipsel` at the SAME seed, at wp0 -- where there is
# no wrong path at all -- still differ: 127,734,800 vs 127,734,896 body bits,
# 96 bits in the CP stream.  That is the GUEST diverging, not the excursion,
# and this option does not reach it.  A census that needs byte-identical
# sidecars must therefore also pin the cell's own inputs; the seed makes the
# WRONG PATH reproducible and nothing more.  Named here so a reader does not
# take `-seed` for a guarantee it was never measured to give.
#
# Author: Maccoy Merrell.
set -u

ISA=${1:-}
OUT=${2:-}
[ -n "$ISA" ] && [ -n "$OUT" ] || {
    echo "usage: shadow_run.sh <isa> <out-dir> [--build-dir DIR] [--seed N]" \
         "[--cells DIR]... [--workload BIN]" >&2; exit 2; }
shift 2

B=${CST_BUILD_DIR:-/mnt/md0/QEMU/qemu/build}
SEED=${CST_SHADOW_SEED:-4242}
CELLS=()
WORKLOAD=""
while [ $# -gt 0 ]; do
    case $1 in
        --build-dir) B=$2; shift 2 ;;
        --seed)      SEED=$2; shift 2 ;;
        --cells)     CELLS+=("$2"); shift 2 ;;
        --workload)  WORKLOAD=$2; shift 2 ;;
        *) echo "shadow_run.sh: unknown option $1" >&2; exit 2 ;;
    esac
done

SO=$B/contrib/plugins/libchampsim_tracer.so
QEMU=$B/qemu-$ISA
for f in "$SO" "$QEMU" "$B/contrib/plugins/cst_audit"; do
    [ -x "$f" ] || { echo "shadow_run.sh: $f missing -- REFUSING" >&2; exit 2; }
done
[ ${#CELLS[@]} -gt 0 ] || { echo "shadow_run.sh: no --cells given --" \
    "REFUSING (a run with no subject has not passed)" >&2; exit 2; }

S=$OUT/side_$ISA
mkdir -p "$S" || exit 2
RC=$OUT/RC_$ISA.txt
: > "$RC"
{
  echo "HARNESS_CWD=$PWD"
  echo "SEED=$SEED"
  echo "TIP=$(git -C "$(dirname "$0")" rev-parse HEAD 2>/dev/null)"
  echo "DIRTY=$(git -C "$(dirname "$0")" status --porcelain 2>/dev/null | grep -vc '^??')"
  echo "SO_SHA=$(sha256sum "$SO" | cut -d' ' -f1)"
  echo "QEMU_SHA=$(sha256sum "$QEMU" | cut -d' ' -f1)"
} >> "$RC"

rc_total=0
run() {
  local tag=$1 bin=$2 wp=$3
  local wpopt="wp=0"; [ "$wp" != 0 ] && wpopt="wpdepth=$wp"
  local o=$S/${ISA}__${tag}_wp${wp}
  if [ ! -x "$bin" ]; then
    echo "  FAIL: $tag missing binary $bin" >> "$RC"; rc_total=1; return
  fi
  setarch -R "$QEMU" -seed "$SEED" \
     -plugin "$SO,outfile=$o,$wpopt,memdata=1,regdata=1,compress=zstd -T0 -3 -q -c" \
     "$bin" > "$o.out" 2>&1
  local rc=$?
  if ! grep -q "SHADOW LOOKUP" "$o.stats.log" 2>/dev/null; then
    echo "  FAIL: $tag wp$wp produced NO shadow block" >> "$RC"; rc_total=1
  fi
  if ! grep -q "SOURCE SURVIVORS KEYED ON QEMU'S DECODE IDENTITY" "$o.stats.log" 2>/dev/null; then
    echo "  FAIL: $tag wp$wp produced NO survivor census block" >> "$RC"; rc_total=1
  fi
  # compression proven from cst_audit's own member line, never from size
  local memb
  memb=$("$B/contrib/plugins/cst_audit" "$o.cst" 2>/dev/null | grep -ci 'zstd')
  echo "shadow $tag wp=$wp seed=$SEED run_rc=$rc zstd_member_lines=$memb" >> "$RC"
  [ "${memb:-0}" -ge 1 ] || { echo "  FAIL: $tag wp$wp not compressed" >> "$RC"; rc_total=1; }
  rm -f "$o.cst"
}

# The globs OVERLAP -- `*_$ISA` and `heldout_$ISA` name the same file in a
# flat cell directory -- so a seen-set is kept.  Without it a cell runs twice,
# its second run overwrites the first's sidecar, and the RC file reports a
# cell count that is not the number of subjects.
n=0
declare -A SEEN=()
for dir in "${CELLS[@]}"; do
  for b in "$dir"/*/*_"$ISA" "$dir"/*_"$ISA"; do
    [ -x "$b" ] || continue
    rb=$(readlink -f "$b")
    [ -n "${SEEN[$rb]:-}" ] && continue
    SEEN[$rb]=1
    run "$(basename "$b")" "$b" 0
    run "$(basename "$b")" "$b" 16
    n=$((n + 1))
  done
done
if [ -n "$WORKLOAD" ]; then
  run w19 "$WORKLOAD" 0; run w19 "$WORKLOAD" 16; n=$((n + 1))
fi
if [ "$n" -eq 0 ]; then
  echo "  FAIL: no cell binary for $ISA under the declared roots" >> "$RC"
  rc_total=1
fi
echo "cells=$n rc_total=$rc_total" >> "$RC"
echo SHADOW_DONE >> "$RC"
exit $rc_total
