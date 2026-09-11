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

# ---- the DECODE IDENTITY for this leg's denominator (98-F) ----------------
# The tracer arm below asks the plugin what it makes of each encoding, and
# the plugin classifies from QEMU's decode_id -- which a host tool does not
# have.  Until 2fdabefe79 the answer came from the Capstone-enum table, so
# what this leg scored was Capstone's classification; R14 deleted it.  The
# identity is captured here from a real translation and handed to every
# isaxcheck invocation in this leg through CST_ISAX_IDENT.  isaxcheck
# REFUSES the fields layer without one, so a capture that fails stops the
# leg rather than letting it score a layer that classified nothing.
# THE DENOMINATOR IS rows.json, NOT opcodes.tsv: emit.py WRITES opcodes.tsv,
# and its own first act is a fields-layer batch over these same
# representatives.  Capturing after it would be capturing after the step
# that needs the capture.
# Written to a FILE, not a process substitution: the hex list is the leg's
# denominator and a capture that silently saw an empty stream is the failure
# mode this whole item is about.  The file is checked non-empty here and
# ident_capture.sh REFUSES an empty one again.
"$PY" - "$D/rows.json" > "$D/ident_pop.txt" <<'PYHEX' || exit 2
import json, sys
for r in json.load(open(sys.argv[1])):
    print(r["hex"])
PYHEX
[ -s "$D/ident_pop.txt" ] || { echo "REFUSED: rows.json yielded no hex" >&2
                               exit 2; }
# THE MODEL IS PASSED, AND IT IS NOT THE CAUSE.  Measured this pass: the
# sled produces a chain for 413 of this leg's 1093 representatives, and the
# reading is IDENTICAL on the default model and on `max` -- so the 680 are
# not an extension the model fails to implement, and the cause is NOT YET
# ATTRIBUTED.  The consequence is on the record rather than papered over:
# the leg's own negative control, drop-src:vadd.vv, goes CONTROL INERT
# because its subject is among the 680, and a leg whose control cannot be
# made to fail may not have its zero quoted (98-F residue, riscv64).  The
# knob stays because the model IS part of the measurement for any ISA where
# it turns out to matter -- mipsel MSA on 24Kf is the sled's own example.
CST_IDENT_CPU=${CST_IDENT_CPU:-max} \
CST_ISAX_IDENT=$("$T"/../ident_capture.sh riscv64 "$D/ident_pop.txt" \
    "$D/ident" "$Q") || exit 2
export CST_ISAX_IDENT
echo "ident corpus: $CST_ISAX_IDENT"

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
