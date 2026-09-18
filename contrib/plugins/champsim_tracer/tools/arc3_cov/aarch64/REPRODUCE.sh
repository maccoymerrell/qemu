#!/bin/bash
# ARC 3 -- aarch64 REGISTER ATTRIBUTION against the Arm MRA.  Start to finish.
#
# ONE ENTRY POINT, because there was none.  The four steps below existed only
# as prose in METHOD.md, so the aarch64 R13 gate row could not be refreshed as
# a unit after a rebuild (#286) -- and the step it is easiest to skip is the
# one whose absence is SILENT: compare.py reads tracer_fields.tsv off disk, so
# a stale snapshot scores as an attribution change.  MEASURED 2026-08-23: a
# tracer arm four commits stale returned 3609/311 where the re-probed one
# returned 3655/265.  (compare.py has since grown its own re-derive-or-refuse
# guard; this file makes the order right rather than relying on the guard.)
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
_SG_STAMP=$(mktemp -t arc3_settle_aarch64.XXXXXX)
"$_SG" arm "$_SG_STAMP"
trap '_sg_rc=$?; "$_SG" check "$_SG_STAMP" || _sg_rc=3; rm -f "$_SG_STAMP"; \
      exit $_sg_rc' EXIT

D=${CST_COV_DIR:-/mnt/md0/QEMU/cst_runs/_arc3_cov}/aarch64
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
# A leg that cannot find its subject must FAIL, and it must fail here rather
# than after two minutes of MRA evaluation.
[ -d "$D" ] || { echo "REFUSED: no working directory $D." >&2
                 echo "  It holds the denominator (opcodes.tsv) and the MRA" >&2
                 echo "  XML under asl/; this script REFRESHES that tree, it" >&2
                 echo "  does not build it from nothing." >&2; exit 2; }
for f in opcodes.tsv aslinterp.py aslparse.py mra_ref.py mraxml.py; do
    [ -e "$D/$f" ] || { echo "REFUSED: $D/$f is missing." >&2; exit 2; }
done

ninja -j "${CST_JOBS:-12}" -C "$Q/build" contrib-plugins
[ -x "$ISAX" ] || { echo "REFUSED: no tracer arm at $ISAX" >&2; exit 2; }

# THE SECOND DECODER IS A PREREQUISITE, CHECKED WITH THE REST (FINDING 246-C).
# This leg's reference side is the Arm MRA with LLVM MC behind it, and the LLVM
# arm used to arrive through the retired isaxcheck's boundary layer.  It now
# comes from the same probe binary the aarch64 reference corpus was built with,
# driven by llvm_arm.py.  A leg that cannot reach it must FAIL here rather than
# score QEMU against QEMU further down.
A64_LLVMREF=${CST_A64_LLVMREF:-/mnt/md0/QEMU/cst_runs/_arc3_refs/aarch64/probes/llvmref}
[ -x "$A64_LLVMREF" ] || { echo "REFUSED: no LLVM MC probe at $A64_LLVMREF." >&2
    echo "  The reference side of this leg is a SECOND DECODER; without one" >&2
    echo "  the cross-check has nothing to check against.  Build it:" >&2
    echo "  /mnt/md0/QEMU/cst_runs/_arc3_refs/aarch64/REPRODUCE.sh" >&2; exit 2; }
export CST_A64_LLVMREF="$A64_LLVMREF"

# The harness is the TREE's copy; the working directory only holds evidence.
cp "$T"/reprobe.py "$T"/sweep.py "$T"/compare.py "$T"/adjudicate.py \
   "$T"/mra_ref.py "$T"/mra_sweep.py "$T"/census.py "$T"/llvm_arm.py "$D"/
cd "$D"


# ---- the DECODE IDENTITY for this leg's denominator (98-F) ----------------
# The tracer arm below asks the plugin what it makes of each encoding, and
# the plugin classifies from QEMU's decode_id -- which a host tool does not
# have.  Until 2fdabefe79 the answer came from the Capstone-enum table, so
# what this leg scored was Capstone's classification; R14 deleted it.  The
# identity is captured here from a real translation and handed to every
# isaxcheck invocation in this leg through CST_ISAX_IDENT.  isaxcheck
# REFUSES the fields layer without one, so a capture that fails stops the
# leg rather than letting it score a layer that classified nothing.
CST_ISAX_IDENT=$("$T"/../ident_capture.sh aarch64 \
    <(tail -n +2 opcodes.tsv | cut -f3) "$D/ident" "$Q") || exit 2
export CST_ISAX_IDENT
# THE TRACER ARM READS THE SAME CAPTURE.  ident_capture.sh prints the mechanism
# corpus; the register-set and identity corpora the arm needs sit beside it, in
# the directory the sled wrote into.  Deriving the directory from the printed
# path rather than re-spelling it keeps the two from ever naming different
# captures (FINDING 244-H).
CST_SLED_CAPTURE=$(dirname "$CST_ISAX_IDENT")
export CST_SLED_CAPTURE
echo "ident corpus: $CST_ISAX_IDENT"

# ---- the four steps, in the order that makes them a measurement -----------
$PY reprobe.py "$ISAX"          # tracer arm  -> tracer_fields.tsv
# The LLVM cross-check arm is a CACHE over the denominator's encodings, and a
# cache that is not re-derived goes stale exactly the way tracer_fields.tsv
# did: a representative that moves loses its row and the column reads blank.
# compare.py refuses on an uncovered denominator; this is what keeps it
# covered.
#
# IT IS THE SECOND DECODER, NOT THE TRACER.  This call used to be
# `isaxcheck --isa=aarch64 --batch` with no --layer, which meant the retired
# binary's BOUNDARY layer; that binary went with Capstone.  Answering it with
# the fields layer would put QEMU's own columns under a name compare.py reads
# as the other decoder's and score QEMU against QEMU on every row the MRA has
# no entry for, so the arm is re-pointed at LLVM MC itself.  llvm_arm.py's
# --selfcheck scores it against the retired tool's own banked table.
$PY llvm_arm.py < <(tail -n +2 opcodes.tsv | cut -f3) > fields_all.txt
$PY sweep.py                    # MRA         -> ref_mra.json  (~135 s)
$PY compare.py                  # both + LLVM -> attrib.tsv, attrib_signatures.txt
$PY adjudicate.py               # -> attrib_adjudication.txt

# ---- prove the comparison can go red --------------------------------------
# R8.7: an agreement rate quoted off an instrument nobody has watched fail
# vouches for nothing, and this leg's headline is a ZERO.  drop-src damages the
# tracer arm for one mnemonic; the agreement must fall by exactly the rows
# isaxcheck says it mutated, and no others.
#
# CST_FALSIFY reaches BOTH the re-probe and compare.py's own re-derivation, so
# the DAMAGED table is what gets scored.  A command-line flag could not do
# that: compare.py re-derives the arm with no arguments and would refuse the
# damaged file instead of reporting off it.
#
# THE ARMS NAME QEMU DECODE RULES, NOT ASSEMBLY MNEMONICS (FINDING 246-C).
# They used to read `add`, `ldr`, `fmla` -- the retired isaxcheck keyed its
# falsifier on the mnemonic ITS decoder printed.  The successor is the sled,
# and what the sled records per encoding is the rule QEMU's decodetree
# reached, so `add` matches nothing and sled_fields.py REFUSES rather than
# damaging nothing quietly.  The three below are rules this leg's own
# denominator carries WITH ROWS THAT CURRENTLY AGREE -- measured here:
# LDR_i 45, STR_i 20, CAS 16 -- because an arm aimed at rows that already
# disagree cannot move the agreement and would be inert for a reason that
# says nothing about the tracer.
#
# THE COSTS ARE THE CONTROL; THE BASELINE IS NOT.  A baseline written here
# goes stale the moment the decode moves, and a stale one invites reading an
# unchanged number as a passing control.  So this run's own baseline is taken
# first and each arm is required to move by its own mutated count.
cp tracer_fields.tsv tracer_fields.good.tsv
BASE_AGREE=$($PY - <<'PYEOF'
import csv, collections, os
d = os.environ.get('CST_COV_DIR', '/mnt/md0/QEMU/cst_runs/_arc3_cov') + '/aarch64'
c = collections.Counter(r['verdict'] for r in
                        csv.DictReader(open(d + '/attrib.tsv'), delimiter='\t'))
print(c['agree'])
PYEOF
)
echo "falsify baseline agree = $BASE_AGREE"
for M in LDR_i STR_i CAS; do
  CST_FALSIFY=drop-src:$M $PY reprobe.py "$ISAX"
  CST_FALSIFY=drop-src:$M $PY compare.py > falsify_$M.txt 2>&1 || {
      echo "falsify drop-src:$M: compare.py refused" >&2; exit 1; }
  NOW=$($PY - <<'PYEOF'
import csv, collections, os
d = os.environ.get('CST_COV_DIR', '/mnt/md0/QEMU/cst_runs/_arc3_cov') + '/aarch64'
c = collections.Counter(r['verdict'] for r in
                        csv.DictReader(open(d + '/attrib.tsv'), delimiter='\t'))
print(c['agree'])
PYEOF
)
  echo "falsify drop-src:$M -> agree $NOW (was $BASE_AGREE)"
  [ "$NOW" -lt "$BASE_AGREE" ] || {
      echo "CONTROL INERT: drop-src:$M did not move the agreement." >&2
      echo "  Either the RULE is absent from the 3,920 subjects, or its" >&2
      echo "  rows already disagree -- in either case NAME A QEMU DECODE" >&2
      echo "  RULE THAT HAS AGREEING ROWS -- or the comparison is" >&2
      echo "  not reading the tracer arm it just damaged.  Either way the" >&2
      echo "  zero above is not a measurement." >&2
      cp tracer_fields.good.tsv tracer_fields.tsv; exit 1; }
done
cp tracer_fields.good.tsv tracer_fields.tsv
$PY compare.py > /dev/null            # restore the undamaged table
$PY adjudicate.py > /dev/null

# ---- the gate, and it is this script's exit status ------------------------
$PY - <<'PYEOF' || exit 1
import csv, collections, os, sys
d = os.environ.get('CST_COV_DIR', '/mnt/md0/QEMU/cst_runs/_arc3_cov') + '/aarch64'
rows = list(csv.DictReader(open(d + '/attrib.tsv'), delimiter='\t'))
c = collections.Counter(r['verdict'] for r in rows)
dirs = collections.Counter(r.get('direction', '?')
                           for r in rows if r['verdict'] == 'disagree')
print('probed %d  agree %d  disagree %d' % (len(rows), c['agree'], c['disagree']))
for k in sorted(dirs):
    print('  %-18s %d' % (k, dirs[k]))
matters = dirs.get('TRACER-SUBSET', 0) + dirs.get('UNACCOUNTED', 0)
print('the number that matters: TRACER-SUBSET + UNACCOUNTED = %d' % matters)
if len(rows) < 3000:
    sys.exit('population %d is below the floor -- the sweep did not reach its '
             'denominator, and a small number off a small population is not a '
             'result' % len(rows))
PYEOF
