#!/bin/bash
# ARC 3 -- riscv64 REGISTER ATTRIBUTION against the Sail-RISCV model.
# Start to finish.
#
# ONE ENTRY POINT, because there was none: README.md gave three commands, the
# middle one a runpy incantation, so the riscv64 R13 gate row could not be
# refreshed as a unit after a rebuild (#286).
#
# Author: Maccoy Merrell.
set -euo pipefail
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"      # this directory, in-tree

# ---- SETTLE BEFORE ANY WORK, AND STAMP FOR THE REST OF IT -------------------
# A leg started against a tree with pending build work writes a table that is
# stale before it is finished, and the only thing that notices is
# coverage_report.py -- at PUBLISH, after all four legs have been paid for.
# The same refusal is made HERE, where nothing has been spent yet, and the
# subjects are hashed so that a relink DURING this leg is named by the leg it
# invalidated rather than by a report four hours later.  The trap keeps this
# leg's own exit status unless the guard has something to say.
# See ../settle_guard.sh for the subjects and why `qemu-*` is not one.
_SG="$T/../settle_guard.sh"
_SG_STAMP=$(mktemp -t arc3_settle_riscv64.XXXXXX)
"$_SG" arm "$_SG_STAMP"
trap '_sg_rc=$?; "$_SG" check "$_SG_STAMP" || _sg_rc=3; rm -f "$_SG_STAMP"; \
      exit $_sg_rc' EXIT

D=${CST_COV_DIR:-/mnt/md0/QEMU/cst_runs/_arc3_cov}/riscv64
Q=${CST_QEMU_ROOT:-/mnt/md0/QEMU/qemu}
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
ISAX=${CST_ISAXCHECK:-$Q/build/contrib/plugins/isaxcheck}

# ---- PREREQUISITES, CHECKED BEFORE ANY WORK -------------------------------
[ -d "$D" ] || { echo "REFUSED: no working directory $D." >&2
                 echo "  It carries the denominator tree the coverage run" >&2
                 echo "  built (clauses.json, rows.json, sail_parse.py," >&2
                 echo "  gen_opcodes.py, expand.py, ref/sail-riscv).  This" >&2
                 echo "  script REFRESHES that tree." >&2; exit 2; }
for f in clauses.json rows.json expand.py gen_opcodes.py; do
    [ -e "$D/$f" ] || { echo "REFUSED: $D/$f is missing." >&2; exit 2; }
done
[ -d "$D/ref/sail-riscv" ] || { echo "REFUSED: no $D/ref/sail-riscv -- the" >&2
    echo "  reference model itself is absent, so nothing below is a" >&2
    echo "  measurement." >&2; exit 2; }

ninja -j "${CST_JOBS:-12}" -C "$Q/build" contrib-plugins
[ -x "$ISAX" ] || { echo "REFUSED: no isaxcheck at $ISAX" >&2; exit 2; }

# The harness is the TREE's copy; the working directory only holds evidence.
mkdir -p "$D/attrib"
cp "$T"/emit.py "$D"/
cp "$T"/compare.py "$T"/expand_vals.py "$T"/sail_effects.py \
   "$T"/zcmp_profile.py "$D"/attrib/
cd "$D"

# ---- the three steps ------------------------------------------------------
# emit.py RE-DECODES every representative encoding with the live isaxcheck
# before it classifies anything, and ends the run if a named exclusion reason
# has stopped matching rows -- a justification nobody can check is how
# ssamoswap.w/.d stayed excluded as undecodable for as long as it took
# CS_MODE_RISCV_ZICFISS to be switched on.
CST_ISAXCHECK="$ISAX" $PY emit.py               # -> opcodes.tsv, excluded.tsv
$PY - <<'PYEOF'
import sys, runpy
sys.path.insert(0, '.')
runpy.run_path('attrib/expand_vals.py', run_name='__main__')
PYEOF
CST_ISAXCHECK="$ISAX" $PY attrib/compare.py     # -> attrib.tsv, attrib_signatures.txt

# ---- prove the comparison can go red --------------------------------------
# R8.7.  The riscv64 headline is 0 TRACER-SUBSET, and a zero is the one result
# equally consistent with "the two models agree" and "the comparison never
# reached its subject".  compare.py already reads CST_FALSIFY and passes it to
# isaxcheck as --falsify (compare.py:178), and CST_OUT keeps the damaged table
# OUT of attrib.tsv, so the published file is never written by a control arm.
#
# The two arms are the ones the report itself names.  THE COSTS ARE THE
# CONTROL: each must move AGREE downwards against THIS run's own baseline, and
# an arm that moves nothing has not reached its subject -- name a mnemonic
# that is in the denominator instead of quoting the unchanged number.
BASE=$($PY - <<'PYEOF'
import csv, collections, os
d = os.environ.get('CST_COV_DIR', '/mnt/md0/QEMU/cst_runs/_arc3_cov') + '/riscv64'
c = collections.Counter(r['verdict'] for r in
                        csv.DictReader(open(d + '/attrib.tsv'), delimiter='\t'))
print(c['AGREE'])
PYEOF
)
echo "falsify baseline AGREE = $BASE"
for M in ctz vadd.vv; do
  CST_FALSIFY=drop-src:$M CST_OUT=fals_$M.tsv CST_ISAXCHECK="$ISAX" \
      $PY attrib/compare.py > falsify_$M.txt 2>&1
  NOW=$($PY - "fals_$M.tsv" <<'PYEOF'
import csv, collections, os, sys
d = os.environ.get('CST_COV_DIR', '/mnt/md0/QEMU/cst_runs/_arc3_cov') + '/riscv64'
c = collections.Counter(r['verdict'] for r in
                        csv.DictReader(open(d + '/' + sys.argv[1]), delimiter='\t'))
print(c['AGREE'])
PYEOF
)
  echo "falsify drop-src:$M -> AGREE $NOW (was $BASE)"
  [ "$NOW" -lt "$BASE" ] || {
      echo "CONTROL INERT: drop-src:$M did not move AGREE." >&2
      echo "  Either the mnemonic is absent from the denominator -- name one" >&2
      echo "  that is present -- or the comparison is not reading the arm it" >&2
      echo "  just damaged.  Either way the zero above is not a measurement." >&2
      exit 1; }
done

# ---- the gate, and it is this script's exit status ------------------------
$PY - <<'PYEOF' || exit 1
import csv, collections, os, sys
d = os.environ.get('CST_COV_DIR', '/mnt/md0/QEMU/cst_runs/_arc3_cov') + '/riscv64'
rows = list(csv.DictReader(open(d + '/attrib.tsv'), delimiter='\t'))
c = collections.Counter(r['verdict'] for r in rows)
dirs = collections.Counter(r.get('direction', '?')
                           for r in rows if r['verdict'] == 'DISAGREE')
print('probed %d  AGREE %d  DISAGREE %d' % (len(rows), c['AGREE'], c['DISAGREE']))
for k in sorted(dirs):
    print('  %-18s %d' % (k, dirs[k]))
matters = dirs.get('TRACER-SUBSET', 0) + dirs.get('UNACCOUNTED', 0)
print('the number that matters: TRACER-SUBSET + UNACCOUNTED = %d' % matters)
if len(rows) < 1000:
    sys.exit('population %d is below the floor -- the sweep did not reach its '
             'denominator' % len(rows))
PYEOF
