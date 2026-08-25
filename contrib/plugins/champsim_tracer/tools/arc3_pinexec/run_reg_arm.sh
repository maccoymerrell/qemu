#!/bin/bash
# The register arm, end to end, with its negative controls.
#
# Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
#
#   usage: run_reg_arm.sh <outdir> [qemu-build-dir] [pin-root]
#
# Builds nothing it can avoid rebuilding, runs BOTH halves under ONE minimal
# environment, pairs them with the anchor the pairing needs, and then runs
# every negative control through the SAME anchor.  cmp_reg.py refuses an
# unaligned pair with rc=2 rather than scoring it, which is why the anchor
# is supplied here and not left to be rediscovered per control.
#
# Every exit code is taken from the process.  Nothing is read through a pipe.
set -u

OUT=${1:?usage: run_reg_arm.sh <outdir> [qemu-build] [pin-root]}
QB=${2:-/mnt/md0/QEMU/qemu/build}
PIN_ROOT=${3:-/mnt/md0/PIN/pin-external-4.2-99776-g21d818fa2-gcc-linux}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
N=400000

mkdir -p "$OUT" || exit 1
cd "$OUT" || exit 1

fail() { echo "FAIL: $*" >&2; exit 1; }

# ---------------------------------------------------------------- the tool
make -C "$HERE" PIN_ROOT="$PIN_ROOT" >"$OUT/make.log" 2>&1
[ $? -eq 0 ] || fail "pintool build (see $OUT/make.log)"
TOOL=$HERE/obj-intel64/champsim_reg_pintool.so
[ -f "$TOOL" ] || fail "no pintool at $TOOL"

# ------------------------------------------------------------- the workload
cat > w.c <<'EOF'
#include <stdio.h>
int main(void){ long s=0; for(int i=0;i<20000;i++) s+= i*3 % 7; printf("%ld\n", s); return 0; }
EOF
gcc -static -O1 -no-pie -o w w.c || fail "workload build"

# ONE minimal environment for both halves: the two processes place their
# stacks independently, and an environment block of a different length
# multiplies the distinct pointer deltas the comparison has to establish.
ENV=(env -i HOME=/tmp LANG=C)

# ------------------------------------------------------------- reference
"${ENV[@]}" setarch -R "$PIN_ROOT"/pin -t "$TOOL" -o reg.bin -s 0 -t $N \
    -- ./w >pin.stdout 2>pin.err
[ $? -eq 0 ] || fail "PIN reference (see $OUT/pin.err)"
[ -s reg.bin ] || fail "PIN wrote no reference"

# ---------------------------------------------------------------- tracer
"${ENV[@]}" setarch -R "$QB"/qemu-x86_64 \
    -plugin "$QB"/contrib/plugins/libchampsim_tracer.so,outfile=q,wp=0,memdata=1,regdata=1 \
    ./w >q.stdout 2>q.err
[ $? -eq 0 ] || fail "tracer run (see $OUT/q.err)"

"$QB"/contrib/plugins/cst_decode --format=disasm --objdump q.cst > q.disasm 2>q.dec.err
[ $? -eq 0 ] || fail "cst_decode (see $OUT/q.dec.err)"
PYTHONPATH=$HERE python "$HERE"/qextract_mem.py q.disasm $N > q.jsonl 2>q.ext.err
[ $? -eq 0 ] || fail "qextract_mem (see $OUT/q.ext.err)"
rm -f q.disasm
NQ=$(wc -l < q.jsonl)
[ "$NQ" -eq $N ] || fail "extracted $NQ instructions, wanted $N"

# ------------------------------------------------------------ the pairing
# --anchor 0 --qskip 1: PIN's skip gate consumes one instruction before it
# arms, so the reference's record 0 is the tracer's record 1.
rm -f negcontrols.txt
run_cmp() {
    local tag=$1; shift
    PYTHONPATH=$HERE python "$HERE"/cmp_reg.py \
        --pin reg.bin --qemu q.jsonl --anchor 0 --qskip 1 \
        --maxreport 99999 --summary negcontrols.txt \
        --out "cmp_$tag.txt" "$@"
    local rc=$?
    [ $rc -eq 0 ] || fail "cmp_reg $tag rc=$rc (see $OUT/cmp_$tag.txt)"
}

run_cmp baseline
for m in dropsrc extrasrc dropdst dstvalue srcvalue; do
    run_cmp "$m" --mutate="$m"
done

echo "=== $OUT/negcontrols.txt ==="
cat negcontrols.txt
