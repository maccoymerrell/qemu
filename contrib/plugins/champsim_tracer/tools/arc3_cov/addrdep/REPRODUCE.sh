#!/bin/bash
# The address-DEPENDENCY leg, all four ISAs, end to end.
#
# Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
#
#   usage: REPRODUCE.sh <outdir> [qemu-build-dir]
#
# A leg with no entry point is a leg nobody re-runs (b72c2a09b9).  This is
# that entry point: it builds the probe sets from the same denominators the
# other arc3_cov legs use, scores every ISA, and then runs the falsifier on
# each one -- because a green cell nobody could turn red is not a validated
# cell.  Every exit code is taken from the process; nothing is read through
# a pipe.
set -u

OUT=${1:?usage: REPRODUCE.sh <outdir> [qemu-build]}
QB=${2:-/mnt/md0/QEMU/qemu/build}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
COV=${CST_ARC3_COV:-/mnt/md0/QEMU/cst_runs/_arc3_cov}
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
export CST_ISAXCHECK=${CST_ISAXCHECK:-$QB/contrib/plugins/isaxcheck}

mkdir -p "$OUT" || exit 1
cd "$OUT" || exit 1
fail() { echo "FAIL: $*" >&2; exit 1; }
[ -x "$CST_ISAXCHECK" ] || fail "no isaxcheck at $CST_ISAXCHECK"

# ------------------------------------------------------- the probe sets
# Each is the ISA's own arc3_cov denominator, so this leg is scored over
# exactly the opcode population every other facet table is scored over.
cp "$COV/aarch64/all.hex" aarch64.hex || fail "aarch64 denominator"
cp "$COV/x86_64/attrib/probe_uniq.hex" x86_64.hex || fail "x86_64 probe set"
"$PY" - "$COV" <<'PYEOF' || fail "riscv64/mipsel denominators"
import csv, sys
cov = sys.argv[1]
for isa, path, col in (
        ('riscv64', cov + '/riscv64/opcodes.tsv', 'hex'),
        ('mipsel', cov + '/mipsel/opcodes.tsv',
         'representative_encoding_hex_le')):
    rows = list(csv.DictReader(open(path), delimiter='\t'))
    open(isa + '.hex', 'w').write('\n'.join(r[col] for r in rows) + '\n')
    print('%s %d encodings' % (isa, len(rows)))
PYEOF

# ------------------------------------------------------------- the score
rc_all=0
for isa in x86_64 aarch64 riscv64 mipsel; do
    "$PY" "$HERE/compare_addrdep.py" --isa "$isa" --hex "$isa.hex" \
          --out "$isa.txt" --workdir . > "$isa.stdout" 2> "$isa.err"
    rc=$?
    echo "$isa rc=$rc"
    [ $rc -eq 0 ] || rc_all=1
done

# ------------------------------------------------ prove the gate can fire
# A mnemonic per ISA that the denominator actually contains AND that has a
# non-empty address mask, so --falsify has something to damage.  isaxcheck
# refuses with rc=2 when it matched nothing or changed nothing, which is
# what makes this a control rather than a formality.
for spec in x86_64:movq aarch64:ldr riscv64:ld mipsel:lw; do
    isa=${spec%%:*}; mn=${spec##*:}
    "$PY" "$HERE/compare_addrdep.py" --isa "$isa" --hex "$isa.hex" \
          --out "$isa.falsify.txt" --workdir . \
          --falsify="drop-addr:$mn" > /dev/null 2> "$isa.falsify.err"
    rc=$?
    echo "$isa falsify(drop-addr:$mn) rc=$rc"
    [ $rc -eq 0 ] || rc_all=1
    grep -E 'addrdep-union' "$isa.falsify.txt"
    grep -E '^# falsify=' "$isa.falsify.err"
done

echo "=== $OUT ==="
grep -hE 'SCORED|addrdep-union|addrdep-split' \
     x86_64.txt aarch64.txt riscv64.txt mipsel.txt
exit $rc_all
