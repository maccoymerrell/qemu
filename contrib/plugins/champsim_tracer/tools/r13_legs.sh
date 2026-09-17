#!/bin/bash
# RUN THE R13 LEGS INTO THE PATHS THE GATE'S MANIFEST NAMES.
#
#   r13_legs.sh <evidence-root> [--build-dir DIR] [--only leg[,leg...]]
#   r13_legs.sh --list
#
# WHY THIS EXISTS, AND IT IS NOT CONVENIENCE.  FINDING 237-C.
# ---------------------------------------------------------------------------
# `external_truth_gate.sh` scores an evidence root; it does not run the legs,
# and it says so.  What ran them was a per-wave shell script, copied forward
# from wave to wave, whose `OUT=` for every leg pointed at `<root>/<leg>`
# while `external_truth_gate/ADJUDICATED.tsv` reads `<root>/gem5/...`,
# `<root>/spike/...`, `<root>/statics/...`.  The two have disagreed since
# exec233.  The consequence is not a missing number, it is a WRONG ONE: the
# gate printed REPORT MISSING -- "a leg that did not run has not passed" --
# for legs that HAD run and HAD written a report, and two consecutive waves
# recorded that as a blocked leg.
#
# The depmap legs were the exception and that is the proof: REPRODUCE_depmap.sh
# writes its published run to `$EVROOT/gem5/depmap_<isa>/REPORT.md` itself, and
# they are the two legs that have scored cleanly throughout.
#
# So the mapping lives here, once, next to the manifest it has to agree with,
# and each row states the producer's own output path beside the manifest's.
# A leg whose producer wrote no report leaves the manifest path ABSENT, which
# the gate then reads as REPORT MISSING -- correctly, because that is what it
# is.  Nothing is fabricated to make a path exist.
#
# THE MAPPING IS CHECKED, NOT ASSUMED.  `--list` prints every row with the
# manifest path beside the producer path, and the script refuses at startup if
# a manifest path it is about to write is not one ADJUDICATED.tsv names.  A
# driver that quietly invents a path is the defect this file exists to fix.
#
# WHAT IT DOES NOT DO.  It does not decide whether a leg passed: that is the
# gate's, over the reports this places.  It takes every exit status from the
# process, writes one line per leg to `<root>/LEGS_RC.txt`, and exits non-zero
# if any leg did.
#
# Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
QEMU_ROOT=$(cd "$HERE/../../../.." && pwd)
MANIFEST="$HERE/external_truth_gate/ADJUDICATED.tsv"
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}

# ---------------------------------------------------------------------------
# THE ROWS.  leg | manifest-relative report | producer-relative report
#
# The producer path is relative to that leg's own OUT directory, which this
# script sets to <root>/_work/<leg>.  An empty producer path means the leg
# writes the manifest path itself and needs no placement (the depmap pair).
#
# `static` and `isaxdead`/`isaxunallowed` share a report with another row, so
# they are not separate legs here -- the manifest has more ROWS than this
# driver has LEGS, and that is not a mismatch: four static rows read one
# cross-tabulation, and two isax rows read each arm shape's rc.txt.
# ---------------------------------------------------------------------------
ROWS="
depmap_aarch64|gem5/depmap_aarch64/REPORT.md|
depmap_x86_64|gem5/depmap_x86_64/REPORT.md|
gem5cp_aarch64|gem5/rc_aarch64.log|final/REPORT.txt
gem5cp_mipsel|gem5/rc_mipsel.log|final/REPORT.txt
gem5wp_aarch64|gem5/wp_aarch64.log|final/REPORT.txt
gem5wp_x86_64|gem5/wp_x86_64.log|final/REPORT.txt
gem5wp_mipsel|gem5/wp_mipsel.log|final/REPORT.txt
spikewp|spike/wp/final/REPORT.txt|final/REPORT.txt
spikecp|spike/FINAL/REPORT.txt|final/REPORT.txt
pin|pin/cmp_fixed_sameinput.txt|cmp_baseline.txt
isax_bare|statics/isax/rc.txt|rc.txt
isax_srcenc|statics/isax_srcenc/rc.txt|rc.txt
statics|statics/coverage_report.txt|
"

row_field() { echo "$1" | cut -d'|' -f"$2"; }

list_rows() {
    printf '%-16s %-34s %s\n' LEG 'MANIFEST PATH' 'PRODUCER PATH (under OUT)'
    echo "$ROWS" | while IFS= read -r r; do
        [ -n "$r" ] || continue
        printf '%-16s %-34s %s\n' "$(row_field "$r" 1)" \
               "$(row_field "$r" 2)" "$(row_field "$r" 3)"
    done
}

# EVERY MANIFEST PATH THIS DRIVER WRITES MUST BE ONE THE MANIFEST READS.
# Checked against ADJUDICATED.tsv column 3 before a single leg starts, because
# a path invented here is exactly the defect 237-C was.
check_mapping() {
    local bad=0 r p
    [ -f "$MANIFEST" ] || { echo "r13_legs: no $MANIFEST" >&2; return 2; }
    for r in $(echo "$ROWS" | tr ' ' '\n'); do
        [ -n "$r" ] || continue
        p=$(row_field "$r" 2)
        if ! awk -F'\t' -v want="$p" \
             '$0 !~ /^#/ && $3 == want { found=1 } END { exit !found }' \
             "$MANIFEST"; then
            echo "r13_legs: $p is not a report path ADJUDICATED.tsv names" >&2
            bad=1
        fi
    done
    return $bad
}

usage() {
    echo "usage: r13_legs.sh <evidence-root> [--build-dir DIR] [--only legs]"
    echo "       r13_legs.sh --list"
    exit 2
}

[ $# -ge 1 ] || usage
if [ "$1" = "--list" ]; then list_rows; exit 0; fi

ROOT=$1; shift
BUILD="$QEMU_ROOT/build"
ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --build-dir) BUILD=$2; shift 2 ;;
        --only) ONLY=$2; shift 2 ;;
        *) usage ;;
    esac
done

check_mapping || exit 2
mkdir -p "$ROOT" || exit 2
ROOT=$(cd "$ROOT" && pwd)
RC="$ROOT/LEGS_RC.txt"
: > "$RC"

wanted() {
    [ -z "$ONLY" ] && return 0
    case ",$ONLY," in *",$1,"*) return 0 ;; esac
    return 1
}

T="$HERE/arc3_cov"

# One leg: run it, take rc from the process, then PLACE its report where the
# manifest reads.  A leg that wrote no report places nothing and says so.
place() {
    local leg=$1 rc=$2
    local r m p
    r=$(echo "$ROWS" | tr ' ' '\n' | grep "^$leg|")
    m=$(row_field "$r" 2); p=$(row_field "$r" 3)
    echo "$leg rc=$rc" >> "$RC"
    [ -n "$p" ] || return 0             # writes the manifest path itself
    local src="$ROOT/_work/$leg/$p"
    if [ -f "$src" ]; then
        mkdir -p "$(dirname "$ROOT/$m")"
        cp "$src" "$ROOT/$m"
        echo "  placed $p -> $m" >> "$RC"
    else
        echo "  NO REPORT: $src was not written; $m stays ABSENT" >> "$RC"
    fi
}

run_leg() {
    local leg=$1; shift
    wanted "$leg" || return 0
    local out="$ROOT/_work/$leg"
    mkdir -p "$out"
    ( "$@" ) > "$ROOT/_work/$leg.log" 2>&1
    place "$leg" "$?"
}

# --- group 1: the dependency maps.  EVROOT is the evidence root itself, which
#     is what makes these two the legs that have always scored.
run_leg depmap_aarch64 env QEMU_DIR="$QEMU_ROOT" EVROOT="$ROOT" \
        OUT="$ROOT/_work/depmap_aarch64" "$T/gem5/REPRODUCE_depmap.sh" aarch64 &
run_leg depmap_x86_64  env QEMU_DIR="$QEMU_ROOT" EVROOT="$ROOT" \
        OUT="$ROOT/_work/depmap_x86_64" "$T/gem5/REPRODUCE_depmap.sh" x86_64 &

# --- group 2: gem5 correct path
run_leg gem5cp_aarch64 env QEMU_DIR="$QEMU_ROOT" OUT="$ROOT/_work/gem5cp_aarch64" \
        "$T/gem5/REPRODUCE_cp.sh" aarch64 &
run_leg gem5cp_mipsel  env QEMU_DIR="$QEMU_ROOT" OUT="$ROOT/_work/gem5cp_mipsel" \
        "$T/gem5/REPRODUCE_cp.sh" mipsel &

# --- group 3: gem5 wrong path
run_leg gem5wp_x86_64  env QEMU_BUILD="$BUILD" OUT="$ROOT/_work/gem5wp_x86_64" \
        "$T/gem5/wp/REPRODUCE.sh" &
run_leg gem5wp_aarch64 env QEMU_BUILD="$BUILD" OUT="$ROOT/_work/gem5wp_aarch64" \
        "$T/gem5/wp/REPRODUCE_aarch64.sh" &
run_leg gem5wp_mipsel  env QEMU_BUILD="$BUILD" OUT="$ROOT/_work/gem5wp_mipsel" \
        "$T/gem5/wp/mipsel/REPRODUCE.sh" &

# --- group 4: spike.  BOTH legs, and the correct-path one is NOT the riscv64
#     STATIC leg: the inherited driver ran `arc3_cov/riscv64/REPRODUCE.sh` --
#     the Sail register-attribution sweep -- under the name `spikecp`, so the
#     blocker recorded against this row for two waves was about a script that
#     answers a different question.  FINDING 239-B.
run_leg spikewp env QEMU_BUILD="$BUILD" OUT="$ROOT/_work/spikewp" \
        "$T/riscv64/spike/wp/REPRODUCE.sh" &
run_leg spikecp env QEMU_BUILD="$BUILD" OUT="$ROOT/_work/spikecp" \
        "$T/riscv64/spike/REPRODUCE_cp.sh" &

# --- group 5: PIN.  run_reg_arm.sh writes cmp_baseline.txt; the manifest has
#     read cmp_fixed_sameinput.txt since f85ee00ccc and nothing has produced
#     that name since.  The placement above is the join; the name in the
#     manifest is left alone because it is the one every adjudication cites.
run_leg pin "$HERE/arc3_pinexec/run_reg_arm.sh" "$ROOT/_work/pin" "$BUILD" &

# --- group 6: the four static legs, then the cross-tabulation they publish
#     into.  coverage_report.py is the ONE report the four static rows read,
#     and it is written after all four have been paid for.
if wanted statics; then
  for isa in x86_64 aarch64 riscv64 mipsel; do
    ( env QEMU_DIR="$QEMU_ROOT" "$T/$isa/REPRODUCE.sh" ) \
        > "$ROOT/_work/static_$isa.log" 2>&1
    echo "static_$isa rc=$?" >> "$RC"
  done &
  P_ST=$!
fi

# --- group 7: the isax arms.  `bare` needs no corpus; `run` needs the sled's.
run_leg isax_bare "$HERE/isax_srcenc_gate.sh" bare "$BUILD" \
        "$ROOT/_work/isax_bare" &

wait

# The --srcenc arms need a corpus, and the corpus needs the sled driver, so
# this one runs LAST and against whatever CST_SLED_CORPUS names.  With no
# corpus it refuses, which is the honest answer and not a zero.
if wanted isax_srcenc; then
  run_leg isax_srcenc "$HERE/isax_srcenc_gate.sh" run "$BUILD" \
          "$ROOT/_work/isax_srcenc" "${CST_SLED_CORPUS:-$ROOT/_work/nocorpus}"
fi

if wanted statics; then
  wait ${P_ST:-} 2>/dev/null
  mkdir -p "$ROOT/statics"
  ( "$PY" "$T/coverage_report.py" -o "$ROOT/statics/coverage_report.txt" ) \
      > "$ROOT/_work/coverage_report.log" 2>&1
  echo "statics rc=$?" >> "$RC"
fi

sort "$RC" | grep -v '^ ' > "$ROOT/LEGS_RC.sorted.txt"
cat "$RC"
! grep -q 'rc=[^0]' "$RC"
