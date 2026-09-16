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
#   5  legcheck                      every leg record given can be resolved
#                                    from the commit that carries it
#   6  legcheck --message            every in-commit leg record NAMED is
#                                    COMPLETE: it transcribes all 19 legs
#                                    the R13 manifest lists, its own "GATE
#                                    PASSED -- N legs" line agrees with the
#                                    rows it prints, and it names the tree
#                                    it measured
#
# Step 4 is the one that cannot be skipped by accident any more.  A ledger row
# is a sentence about a measurement; steps 1-3 re-take the measurement every
# pass and step 4 re-reads the sentence against it.
#
# STEP 6 IS STEP 5's OWN LESSON, ONE LEVEL UP -- FINDING 90-A.  Step 5 asks
# whether a record's POINTER resolves; nothing asked whether the record was
# COMPLETE, and b5fa1e58be's says "GATE PASSED -- 19 legs" over FOURTEEN
# printed rows, with the five missing legs' reports sitting in the evidence
# root the record itself names.  The gate scores the RUN and the record is a
# TRANSCRIPT of it, so no gate row and no battery row could ever see the gap.
# CST_LEG_MESSAGE names the commits whose records to read; empty is PRINTED.
#
# STEP 5 IS HERE FOR THE REASON STEP 4 IS, and by the same lesson: PASS 89
# found five in-commit leg records naming trees a reader cannot reach, and
# nothing in the 19-leg gate or the battery could see it, because a leg record
# is a POINTER and every instrument beside it scores a measurement.  Adding
# legcheck to one pass's own runner would have made it optional from the day
# it landed -- which is exactly what this file's first paragraph exists to
# prevent -- so it runs here or it does not run.  It is skipped only when the
# caller names no records, and says so out loud when it is.
#
# Usage:  ./barscore.sh TIP_ARM DELETION_ARM OUTDIR [LEG_RC ...]
#
# TIP_ARM and DELETION_ARM are sweep roots holding <isa>.wp<N>/ directories.
# The deletion arm is required: the source bar's losing set is arm A minus arm
# B and there is no honest one-arm form of it.  LEG_RC are this pass's R13 leg
# RC.txt files; CST_LEG_COMMIT names the commit they are attached to (default
# HEAD).
set -u
I="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}"
NICE=(taskset -c 0-23 nice -n 10)

A=${1:?TIP_ARM}; B=${2:?DELETION_ARM}; O=${3:?OUTDIR}
shift 3
LEGRC=("$@")
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

# The selftest runs UNCONDITIONALLY -- a check that has not been proven able
# to go red this pass is not evidence -- and the records are scored when the
# caller names them.  "No records given" is PRINTED, never silent.
run legcheck_selftest LEGCHECK_SELFTEST.txt "$PY" "$I/legcheck.py" --selftest
if [ ${#LEGRC[@]} -gt 0 ]; then
    run legcheck LEGCHECK.txt "$PY" "$I/legcheck.py" \
        --repo "$(cd "$I/../../../../../.." && pwd)" \
        --commit "${CST_LEG_COMMIT:-HEAD}" "${LEGRC[@]}"
else
    echo "legcheck SKIPPED -- no leg RC.txt named on the command line;" \
         "this pass's in-commit leg records were NOT checked" \
         >> "$O/BARSCORE_RC.txt"
fi

LEGMSG=${CST_LEG_MESSAGE:-}
if [ -n "$LEGMSG" ]; then
    msgargs=""
    for c in $LEGMSG; do msgargs="$msgargs --message $c"; done
    run legmessage LEGMESSAGE.txt "$PY" "$I/legcheck.py" \
        --repo "$(cd "$I/../../../../../.." && pwd)" $msgargs
else
    echo "legmessage SKIPPED -- CST_LEG_MESSAGE names no commit; this pass's" \
         "in-commit leg records were NOT read for COMPLETENESS" \
         >> "$O/BARSCORE_RC.txt"
fi

cat "$O/BARSCORE_RC.txt"
if [ "$bad" != 0 ]; then
    echo "BAR SCORE: RED -- see the rc lines above and the report beside them"
    exit 1
fi
echo "BAR SCORE: GREEN -- both bars measured, both ledgers total-joined, and"
echo "every QEMU-STATES-IT row re-read against the corpus it is about"
exit 0
