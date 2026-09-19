#!/bin/bash
#
# score_referee.sh -- the external referee end to end, over one pass's corpora.
#
# WHY THIS IS IN THE TREE.  Four passes in a row re-discovered the same thing:
# gapreport.py --require-ruled needs --rulings, and refuses (rc=2) without it.
# Each pass patched its own banked copy of this script, none of them carried
# the patch anywhere durable, and the next pass started from a copy that had
# lost it again.  Filed as 226-A, re-filed as 227-A, 229-B and 230-C.  The
# argument is not the defect; the script living only in an evidence directory
# is, so the script lives here now and a pass copies it rather than writing it.
#
# WHAT THIS STAGE'S NUMBERS COUNT, AND WHAT THEY DO NOT (finding 250-E).
#
# The push-ready readout's C5 row is "the scorers", and it was being read as
# "every UNRULED count in the pass".  It is not, and counting it that way
# counts one measurement twice: the REGISTER-SET UNRULED number is the gate row
# `refsrc/all`, which C1 already scores and already turns red on.  A pass in
# which that row reads 17 then has one failure appearing as two, or -- worse,
# and it happened -- as one red and one green.
#
#   C5 is the scorers' STRUCTURAL HEALTH: gapreport and setjoin each ran to
#   completion over the corpora this pass produced, with every class they
#   reach carrying a ruling and no ruling naming a class the build does not
#   have (0 UNRULED, 0 DEAD, RESERVED counted and named).
#
#   C1 owns the register-set count.  `refsrc/all` is a gate row with a
#   ceiling, it is scored there, and it is not re-counted here.
#
# Both halves are printed below, per stage, so the readout can quote each one
# once from the stage that measured it.
#
# Every stage's rc is captured PER PROCESS.  Nothing pipes a status it needs:
# a stage whose output cannot be read fails loudly rather than reporting a zero
# it never measured.
#
# Usage:
#   score_referee.sh <evidence-root> [qemu-tree] [release-build] [capture-build]
#
# <evidence-root> must already hold merge.py and the corpora it merges, which
# are the capture run's output and not this script's business.
#
# Author: Maccoy Merrell.
# SPDX-License-Identifier: GPL-2.0-or-later
set -u

ROOT="${1:?usage: score_referee.sh <evidence-root> [qemu-tree] [build] [capture-build]}"
Q="${2:-/mnt/md0/QEMU/qemu}"
BUILD="${3:-$Q/build}"
CAPBUILD="${4:-$Q/build-cap212}"

T="$Q/contrib/plugins/champsim_tracer/tools"
PY="${PY:-/home/maccoy-merrell/anaconda3/bin/python}"
# The referee is an OFFLINE python producer over the recorded encodings:
# the repository carries no Capstone, and the Capstone side of the
# comparison is written through the Python bindings, exactly the way the
# retired mnemonic-table generator always reached Capstone.  $BUILD is
# still an argument because every other stage below reads that build.
REF=("$PY" "$T/cst_referee.py")
ISAS="x86_64 aarch64 riscv64 mipsel"

# The rulings files are arguments the tools REFUSE without.  Named here, once,
# so a caller cannot drop one and read the refusal as a result.
GAP_RULINGS="$T/gapreport_rulings.tsv"
SET_RULINGS="$T/setjoin_rulings.tsv"

for f in "$T/cst_referee.py" "$T/gapreport.py" "$T/setjoin.py" "$T/rule_universe.py" \
         "$GAP_RULINGS" "$ROOT/merge.py"; do
    if [ ! -e "$f" ]; then
        echo "score_referee: REFUSING -- missing $f" >&2
        exit 2
    fi
done

mkdir -p "$ROOT"/{merged,ref,join,universe,logs,gap}

echo "== merge"
"$PY" "$ROOT/merge.py" > "$ROOT/logs/MERGE.txt" 2>&1; echo "merge rc=$?"
tail -6 "$ROOT/logs/MERGE.txt"

echo "== referee selftest"
"${REF[@]}" --selftest > "$ROOT/logs/REF_SELFTEST.txt" 2>&1; echo "selftest rc=$?"
tail -2 "$ROOT/logs/REF_SELFTEST.txt"

echo "== referee, one run per ISA"
for isa in $ISAS; do
    "${REF[@]}" --isa "$isa" --in "$ROOT/merged/ident_$isa.tsv" --out-dir "$ROOT/ref" \
        > "$ROOT/logs/REF_$isa.txt" 2>&1
    echo "referee $isa rc=$?"
done

echo "== join"
for isa in $ISAS; do
    m="$ROOT/merged/gen_$isa.tsv"; c="$ROOT/ref/gen_c_$isa.tsv"
    test -s "$m" || { echo "JOIN $isa: no QEMU side"; continue; }
    test -s "$c" || { echo "JOIN $isa: no Capstone side"; continue; }
    { cat "$m"; grep -v '^#' "$c"; } > "$ROOT/join/gen_$isa.tsv"
    echo "join $isa q=$(grep -vc '^#' "$m") c=$(grep -vc '^#' "$c")"
done

echo "== rule universe"
"$PY" "$T/rule_universe.py" --build-dir "$CAPBUILD" -o "$ROOT/universe" \
    > "$ROOT/logs/UNIVERSE.txt" 2>&1; echo "universe rc=$?"
tail -3 "$ROOT/logs/UNIVERSE.txt"

echo "== setjoin --require-ruled"
setjoin_rulings=()
if [ -e "$SET_RULINGS" ]; then
    setjoin_rulings=(--rulings "$SET_RULINGS")
fi
"$PY" "$T/setjoin.py" --dir "$ROOT/join" --isa x86_64 --isa aarch64 \
      --isa riscv64 --isa mipsel --require-ruled --top 0 \
      "${setjoin_rulings[@]}" \
      > "$ROOT/SETJOIN_TIP.txt" 2> "$ROOT/SETJOIN_TIP.err"
echo "setjoin rc=$?"
grep -E "arbitration|read on corpus|^setjoin:" "$ROOT/SETJOIN_TIP.txt"
cat "$ROOT/SETJOIN_TIP.err"

echo "== gap dir: the identity corpus beside the referee's opcode corpus"
for isa in $ISAS; do
    cp -f "$ROOT/merged/ident_$isa.tsv" "$ROOT/gap/" 2>/dev/null
    cp -f "$ROOT/ref/opc_$isa.tsv"      "$ROOT/gap/" 2>/dev/null
    echo "gapdir $isa ident=$(grep -vc '^#' "$ROOT/gap/ident_$isa.tsv" 2>/dev/null || echo MISSING) opc=$(grep -vc '^#' "$ROOT/gap/opc_$isa.tsv" 2>/dev/null || echo MISSING)"
done

echo "== gapreport --require-ruled --universe --rulings"
"$PY" "$T/gapreport.py" --dir "$ROOT/gap" --isa x86_64 --isa aarch64 \
      --isa riscv64 --isa mipsel --require-ruled \
      --rulings "$GAP_RULINGS" \
      --universe "$ROOT/universe" --top 20 \
      > "$ROOT/GAP_TIP.txt" 2> "$ROOT/GAP_TIP.err"
echo "gapreport rc=$?"
grep -E "UNRULED|DEAD|RESERVED|read on corpus|^gapreport:" "$ROOT/GAP_TIP.txt" | head -30
cat "$ROOT/GAP_TIP.err"
