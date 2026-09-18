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
ISAX=${CST_ISAXCHECK:-$T/../sled_fields.py}
# EVERY HELPER IN THIS LEG READS THE SAME ARM.  Five python helpers
# across the four legs resolve the tracer binary from CST_ISAXCHECK with
# a deleted path as their fallback; exporting it here means the arm this
# script checked is the arm they run, rather than each one silently
# falling back to a binary that is not there (FINDING 244-H).
export CST_ISAXCHECK="$ISAX"

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
[ -x "$ISAX" ] || { echo "REFUSED: no tracer arm at $ISAX" >&2; exit 2; }

# THE DECODE-BOUNDARY ARM IS A SECOND DECODER, CHECKED HERE (FINDING 246-C).
# emit.py used to get it from `isaxcheck --layer=boundary`, which answered with
# Capstone and LLVM MC together and went with Capstone at c32824defa.  The
# surviving half is LLVM MC, from the probe binary this leg's reference corpus
# was built with, and a leg that cannot reach it must FAIL here.
RV_LLVMOPS=${CST_RV_LLVMOPS:-/mnt/md0/QEMU/cst_runs/_arc3_refs/riscv64/bin_llvm_ops}
[ -x "$RV_LLVMOPS" ] || { echo "REFUSED: no LLVM MC probe at $RV_LLVMOPS." >&2
    echo "  The decode-boundary cross-check is a SECOND DECODER; without" >&2
    echo "  one there is nothing to cross-check the Sail model against." >&2
    echo "  Build it: /mnt/md0/QEMU/cst_runs/_arc3_refs/riscv64/reproduce.sh" >&2
    exit 2; }
export CST_RV_LLVMOPS="$RV_LLVMOPS"

# The harness is the TREE's copy; the working directory only holds evidence.
mkdir -p "$D/attrib"
cp "$T"/emit.py "$T"/llvm_arm.py "$D"/
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
# THE TRACER ARM READS THE SAME CAPTURE.  ident_capture.sh prints the mechanism
# corpus; the register-set and identity corpora the arm needs sit beside it, in
# the directory the sled wrote into.  Deriving the directory from the printed
# path rather than re-spelling it keeps the two from ever naming different
# captures (FINDING 244-H).
CST_SLED_CAPTURE=$(dirname "$CST_ISAX_IDENT")
export CST_SLED_CAPTURE
echo "ident corpus: $CST_ISAX_IDENT"

# ---- THE SECOND CAPTURE: the Zcmp/Zcmt profile (FINDING 246-C) ------------
# Zcmp and Zcmt occupy the compressed FP-store encoding space and QEMU refuses
# to build a CPU carrying both them and Zcd, so ONE capture cannot answer for
# both profiles -- zcmp_profile.py holds the measurement and the QEMU source
# citation.  The eight encodings therefore get their own sled run on their own
# guest CPU, and compare.py's Zcmp arm reads THIS directory.
#
# It was not always a capture.  Until this pass the arm was
# `isaxcheck --cs-mode-add=zcmp`, a flag on a host decoder that no longer
# exists; the call returned nothing and all eight rows published
# `trc_status=no-fields`, i.e. the leg's ENTIRE coverage hole was the harness
# asking a retired binary.  A missing second decoder is a refusal, not a hole.
ZC_CPU=$($PY - "$T/zcmp_profile.py" <<'PYEOF'
import runpy, sys
print(runpy.run_path(sys.argv[1])['QEMU_CPU'])
PYEOF
)
$PY - "$T/zcmp_profile.py" > "$D/ident_pop_zcmp.txt" <<'PYEOF'
import runpy, sys
for r in runpy.run_path(sys.argv[1])['ROWS']:
    print(r['hex'])
PYEOF
[ -s "$D/ident_pop_zcmp.txt" ] || { echo "REFUSED: zcmp_profile.py yielded no hex" >&2
                                    exit 2; }
CST_RV_ZCMP_CAPTURE=$(dirname "$(CST_IDENT_CPU="$ZC_CPU" \
    "$T"/../ident_capture.sh riscv64 "$D/ident_pop_zcmp.txt" \
        "$D/ident_zcmp" "$Q")") || exit 2
export CST_RV_ZCMP_CAPTURE
echo "zcmp ident corpus: $CST_RV_ZCMP_CAPTURE  (cpu $ZC_CPU)"
# AND IT MUST HAVE DECODED THEM AS Zcmp.  A capture taken on a model where C
# is still on comes back full of `c_fsd` rows -- the failure this whole block
# exists for -- and every downstream number would then be about c.fsdsp.  The
# capture's own rule column is asked, here, before anything reads it.
$PY - "$CST_RV_ZCMP_CAPTURE/ident_riscv64.tsv" "$D/ident_pop_zcmp.txt" <<'PYEOF' || exit 2
import sys
rule = {}
for l in open(sys.argv[1]):
    if l.startswith('#'):
        continue
    c = l.rstrip('\n').split('\t')
    if len(c) >= 4:
        rule[c[1].lower()] = c[3]
bad = [(h, rule.get(h, '(no row)')) for h in
       (x.strip().lower() for x in open(sys.argv[2]) if x.strip())
       if not rule.get(h, '').startswith('cm_')]
if bad:
    sys.exit('REFUSED: the zcmp capture did not decode %d of its own '
             'encodings as Zcmp/Zcmt:\n  ' % len(bad)
             + '\n  '.join('%s -> %s' % b for b in bad)
             + '\n  The CPU model reached the sled but the Zcmp patterns did '
               'not win the\n  decode; see zcmp_profile.QEMU_CPU for why plain '
               'C has to be off.')
print('zcmp capture: all %d encodings decoded as Zcmp/Zcmt rules' % len(rule))
PYEOF

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
