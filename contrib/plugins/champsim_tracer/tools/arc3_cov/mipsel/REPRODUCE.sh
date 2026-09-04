#!/bin/bash
# ARC 3 -- mipsel REGISTER ATTRIBUTION against LLVM MC + binutils, with the
# R6 leg out of QEMU's own C.  Start to finish.
#
# ONE ENTRY POINT, because there was none: ATTRIB_METHOD.md gave a cd and
# eight commands, so the mipsel R13 gate row could not be refreshed as a unit
# after a rebuild (#286).
#
# THE FIRING CONTROL IS PART OF THE RUN, not an appendix.  mipsel is the only
# one of the four ISAs whose table reads 977 AGREE / 0 DISAGREE, and a zero is
# the one result equally consistent with "they agree everywhere" and "the
# comparison never reached its subject".  parse.py probes one encoding at a
# time with --hex, where isaxcheck REFUSES --falsify and says why, so the
# damage is planted by attrib/falsify_shim.sh on the tracer arm's own text.
#
# Author: Maccoy Merrell.
set -euo pipefail
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"      # this directory, in-tree
D=${CST_COV_DIR:-/mnt/md0/QEMU/cst_runs/_arc3_cov}/mipsel
R=${CST_REF_DIR:-/mnt/md0/QEMU/cst_runs/_arc3_refs}/mipsel/work
Q=${CST_QEMU_ROOT:-/mnt/md0/QEMU/qemu}
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
ISAX=${CST_ISAXCHECK:-$Q/build/contrib/plugins/isaxcheck}
F='+mips32r2,+msa,+dsp,+dspr2,+dspr3,+fp64,+eva,+virt,+ginv,+crc,+abs2008,+nan2008,+mt,+mips3d'

# ---- PREREQUISITES, CHECKED BEFORE ANY WORK -------------------------------
[ -f "$D/opcodes.tsv" ] || { echo "REFUSED: no $D/opcodes.tsv -- the 977-row" >&2
    echo "  denominator is not here.  This script refreshes the ATTRIBUTION," >&2
    echo "  it does not rebuild the denominator (see METHOD.md)." >&2; exit 2; }
for p in llvm_probe binutils_probe; do
    [ -x "$R/$p" ] || { echo "REFUSED: no $R/$p -- the reference decoder" >&2
        echo "  binary is absent, so nothing below is a measurement." >&2
        exit 2; }
done

ninja -j "${CST_JOBS:-12}" -C "$Q/build" contrib-plugins
[ -x "$ISAX" ] || { echo "REFUSED: no isaxcheck at $ISAX" >&2; exit 2; }

# The harness is the TREE's copy; the working directory only holds evidence.
mkdir -p "$D/attrib"
cp "$T"/attrib/parse.py "$T"/attrib/canon.py "$T"/attrib/build_ref.py \
   "$T"/attrib/adjudicate.py "$T"/attrib/emit.py "$T"/attrib/qemu_classes.py \
   "$T"/attrib/falsify_shim.sh "$D"/attrib/
chmod +x "$D"/attrib/falsify_shim.sh
cd "$D/attrib"

# ---- the reference arms ---------------------------------------------------
awk -F'\t' 'NR>1{h=$3;print $1" "substr(h,7,2) substr(h,5,2) substr(h,3,2) substr(h,1,2)}' \
    ../opcodes.tsv > enc_word.txt
"$R"/llvm_probe --cpu=mips32r2 --feats="$F" < enc_word.txt > llvm_raw.txt
"$R"/binutils_probe                         < enc_word.txt > bu_raw.txt

# ---- the tracer arm, re-derived from the live binary ----------------------
awk -F'\t' 'NR>1{print $3}' ../opcodes.tsv \
    | "$ISAX" --isa=mipsel --layer=fields --batch > batch_tip.tsv

# ---- the R6 leg, read out of QEMU's own C ---------------------------------
$PY qemu_classes.py "$Q"

# ---- score ----------------------------------------------------------------
CST_ISAXCHECK="$ISAX" $PY parse.py
$PY build_ref.py
$PY adjudicate.py
CST_ISAXCHECK="$ISAX" $PY emit.py        # -> ../attrib.tsv, ../attrib_signatures.tsv
cp ../attrib.tsv attrib.clean.tsv

# THE CLEAN BASELINE IS A MEASUREMENT, NOT THE LITERAL ZERO.
#
# The two control arms below used to assert `dis == 0` for the inert arm and
# `dis > 0` for the firing one, which is the same test only while the clean
# table happens to carry no disagreement.  It stopped being true the day an
# ADJUDICATED reference defect landed: 8a1829235d dropped `jalr`'s phantom $ra
# write -- LLVM's MCInstrDesc carries Defs=[RA] on the JALR opcode whatever rd
# says, Capstone's MIPS tables are generated from LLVM, and the ISA manual and
# QEMU both refute them -- so the clean table reads ONE DISAGREE and the inert
# arm failed with "the shim is not matching what it claims to match" while the
# shim was behaving perfectly.
#
# A control that reads a baseline as damage is a control that convicts the
# tree for being correct.  Both arms are compared against THIS run's own clean
# figure, taken here, from the table just published.
BASE_DIS=$($PY - <<'PYEOF'
import csv, collections, os
d = os.environ.get('CST_COV_DIR', '/mnt/md0/QEMU/cst_runs/_arc3_cov') + '/mipsel'
c = collections.Counter(r['verdict'] for r in
                        csv.DictReader(open(d + '/attrib.tsv'), delimiter='\t'))
print(c['DISAGREE'])
PYEOF
)
echo "clean baseline: DISAGREE = $BASE_DIS (the figure both control arms move from)"

# ---- the firing control, BOTH WAYS ----------------------------------------
# ARM A damages a mnemonic that IS in the 977 and requires exactly one row to
# fall out of agreement.  ARM B names one that is ABSENT and requires the run
# to damage nothing -- which is what proves the shim is not simply damaging
# everything it is pointed at.
#
# THE SHIM'S OWN REACH IS CHECKED, not assumed: parse.py runs the probe under
# subprocess.run(capture_output=True), which SWALLOWS stderr, so a shim that
# announced "reached no subject" there would announce it to nobody.  It
# appends to CST_FALSIFY_LOG instead, and this is where that log is read.
run_arm() {   # $1 mnemonic  $2 expected-damage: some|none
  rm -f fals.log
  CST_ISAXCHECK="$PWD/falsify_shim.sh" CST_FALSIFY_MNEM="$1" \
      CST_FALSIFY_LOG="$PWD/fals.log" $PY parse.py
  $PY build_ref.py && $PY adjudicate.py
  CST_ISAXCHECK="$ISAX" $PY emit.py > "emit_falsify_$1.log" 2>&1
  local dmg; dmg=$(grep -c 'damaged [1-9]' fals.log || true)
  local dis; dis=$($PY - <<'PYEOF'
import csv, collections, os
d = os.environ.get('CST_COV_DIR', '/mnt/md0/QEMU/cst_runs/_arc3_cov') + '/mipsel'
c = collections.Counter(r['verdict'] for r in
                        csv.DictReader(open(d + '/attrib.tsv'), delimiter='\t'))
print(c['DISAGREE'])
PYEOF
)
  echo "falsify $1: shim damaged $dmg probe(s), table DISAGREE = $dis"
  case "$2" in
    some) [ "$dmg" -gt 0 ] && [ "$dis" -gt "$BASE_DIS" ] || {
            echo "CONTROL INERT: '$1' damaged $dmg probes and moved the table" >&2
            echo "  to $dis disagreements, from a clean baseline of" >&2
            echo "  $BASE_DIS.  No MOVEMENT here means the control never" >&2
            echo "  reached its subject, so the clean figure is not a" >&2
            echo "  measurement.  NAME A MNEMONIC THAT IS IN THE 977." >&2
            return 1; } ;;
    none) [ "$dmg" -eq 0 ] && [ "$dis" -eq "$BASE_DIS" ] || {
            echo "INERT ARM IS NOT INERT: '$1' is not in the denominator yet" >&2
            echo "  damaged $dmg probes / moved the table to $dis from a" >&2
            echo "  clean baseline of $BASE_DIS.  The shim is not matching" >&2
            echo "  what it claims to match." >&2
            return 1; } ;;
  esac
}
run_arm abs.d some
run_arm move  none          # absent from the 977: they carry move.v, the MSA form

# ---- restore the undamaged table ------------------------------------------
CST_ISAXCHECK="$ISAX" $PY parse.py
$PY build_ref.py && $PY adjudicate.py
CST_ISAXCHECK="$ISAX" $PY emit.py > /dev/null
cmp attrib.clean.tsv ../attrib.tsv || {
  echo "RESTORE IS NOT BYTE-IDENTICAL: the control arms left the published" >&2
  echo "  table changed.  Nothing below may be quoted." >&2; exit 1; }
echo "restore byte-identical: the control arms left no residue"

# ---- the gate, and it is this script's exit status ------------------------
$PY - <<'PYEOF' || exit 1
import csv, collections, os, sys
d = os.environ.get('CST_COV_DIR', '/mnt/md0/QEMU/cst_runs/_arc3_cov') + '/mipsel'
rows = list(csv.DictReader(open(d + '/attrib.tsv'), delimiter='\t'))
c = collections.Counter(r['verdict'] for r in rows)
dirs = collections.Counter(r.get('direction', '?')
                           for r in rows if r['verdict'] == 'DISAGREE')
print('probed %d  AGREE %d  DISAGREE %d' % (len(rows), c['AGREE'], c['DISAGREE']))
for k in sorted(dirs):
    print('  %-18s %d' % (k, dirs[k]))
matters = dirs.get('TRACER-SUBSET', 0) + dirs.get('UNACCOUNTED', 0)
print('the number that matters: TRACER-SUBSET + UNACCOUNTED = %d' % matters)
if len(rows) < 900:
    sys.exit('population %d is below the floor -- the sweep did not reach its '
             'denominator' % len(rows))
PYEOF
