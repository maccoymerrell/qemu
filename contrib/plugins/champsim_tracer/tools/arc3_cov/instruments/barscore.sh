#!/bin/bash
# THE BAR SCORING STEP, AS ONE ENTRY POINT.
#
# srcbar, dstbar and barledger are in the tree; the SEQUENCE that runs them was
# not.  Every pass carried its own `score.sh` in its own run directory, and a
# step added to one of those is a step the next pass does not have -- which is
# how `landedcheck.py` would have been optional from the day it landed, and how
# the two ledger rows it exists to catch stayed uncaught for a pass.
#
# So the sequence lives here, beside the instruments it drives, and it REFUSES
# rather than reporting a partial score:
#
#   1  srcbar     --a TIP --b DEL   -> FAMILIES.tsv        (source loss bar)
#   2  dstbar     --a TIP           -> DEST_FAMILIES.tsv   (destination bar)
#   3  barledger  x2                 total-join: every family carries a
#                                    disposition and a citation
#   4  landedcheck x2                every QEMU-STATES-IT row still describes
#                                    the population it is about
#
# Step 4 is the one that cannot be skipped by accident any more.  A ledger row
# is a sentence about a measurement; steps 1-3 re-take the measurement every
# pass and step 4 re-reads the sentence against it.
#
# Usage:  ./barscore.sh TIP_ARM DELETION_ARM OUTDIR
#
# TIP_ARM and DELETION_ARM are sweep roots holding <isa>.wp<N>/ directories.
# The deletion arm is required: the source bar's losing set is arm A minus arm
# B and there is no honest one-arm form of it.
set -u
I="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}"
NICE=(taskset -c 0-23 nice -n 10)

A=${1:?TIP_ARM}; B=${2:?DELETION_ARM}; O=${3:?OUTDIR}
mkdir -p "$O" || exit 2
: > "$O/BARSCORE_RC.txt"
bad=0

run() {   # run NAME LOGFILE -- cmd...
    local name=$1 log=$2; shift 2
    "${NICE[@]}" "$@" > "$O/$log" 2>> "$O/barscore.err"
    local rc=$?
    echo "$name rc=$rc" >> "$O/BARSCORE_RC.txt"
    [ "$rc" = 0 ] || bad=1
    return 0
}

run srcbar SRCBAR.txt "$PY" "$I/srcbar.py" --a "$A" --b "$B" \
    --tsv "$O/FAMILIES.tsv"
run dstbar DSTBAR.txt "$PY" "$I/dstbar.py" --a "$A" --top 0 --regtop 0 \
    --tsv "$O/DEST_FAMILIES.tsv"

# A LEDGER SCORED AGAINST A FAMILY TABLE THE STEP ABOVE DID NOT WRITE IS A
# LEDGER SCORED AGAINST THE LAST PASS.  Refused here rather than joined.
for f in FAMILIES.tsv DEST_FAMILIES.tsv; do
    if [ ! -s "$O/$f" ]; then
        echo "barscore: $O/$f is missing or empty -- REFUSING (the bar it " \
             "describes was not measured, and a ledger run against an absent " \
             "table reports on nothing)" >&2
        echo "PRECONDITION rc=2" >> "$O/BARSCORE_RC.txt"
        cat "$O/BARSCORE_RC.txt"; exit 2
    fi
done

run barledger_src SRC_LEDGER.txt "$PY" "$I/barledger.py" \
    --families "$O/FAMILIES.tsv" --bar source
run barledger_dst DEST_LEDGER.txt "$PY" "$I/barledger.py" \
    --families "$O/DEST_FAMILIES.tsv" --bar destination

run landedcheck_src LANDED_SRC.txt "$PY" "$I/landedcheck.py" \
    --arm "$A" --b "$B" --bar source
run landedcheck_dst LANDED_DST.txt "$PY" "$I/landedcheck.py" \
    --arm "$A" --bar destination

cat "$O/BARSCORE_RC.txt"
if [ "$bad" != 0 ]; then
    echo "BAR SCORE: RED -- see the rc lines above and the report beside them"
    exit 1
fi
echo "BAR SCORE: GREEN -- both bars measured, both ledgers total-joined, and"
echo "every QEMU-STATES-IT row re-read against the corpus it is about"
exit 0
