#!/bin/bash
# EVERY INSTRUMENT, ENUMERATED FROM THE DIRECTORY -- NOT FROM A LIST.
#
# The README carried a hand-written loop over eight names while the directory
# held twenty-two files.  A pass ran that loop and reported "8 of 8"; three of
# the fourteen it never named had no --selftest at all, and one of those three
# (wstate_ab.py) answered the loop with an uncaught IndexError.  FINDING 83-D.
#
# A hand list cannot report on what it does not mention, which is the
# survivorship-bias failure this tree files against enumerated zeros.  So the
# subject set is the glob, a module with no --selftest is a FAILURE rather
# than an absence, and the count printed is the count of files found.
#
# Usage:  ./selftest_all.sh [TMPROOT]
set -u
cd "$(dirname "$0")" || exit 2
TMP="${1:-/tmp/arc3_instr_selftest}"
rm -rf "$TMP"; mkdir -p "$TMP" || exit 2
PY="${PYTHON:-python}"

# THE ARM COUNT IS A GATE, NOT A DECORATION -- FINDING 84-A.
#
# The count printed beside each PASS used to be `grep -c '^PASS'`, and 14 of
# the 24 instruments printed 0 for it.  They were checked before anything was
# claimed and they are NOT vacuous -- ordlist_check asserts 7 things, setproof
# 11, keyfacts 11, srcenc_ab 12 -- they simply spell their assertions in a
# different word.  FIVE conventions live in this directory and the counter
# knew one, so four were invisible to it.  The fifth was found BY THIS GATE
# on its first run: abandoned_families.py and cph_census.py print `  ARM A:
# ... ok`, asserting 9 and 12 things respectively, and both scored zero and
# went red -- which is the gate doing its job and the one-line fix the
# paragraph below predicts.
#
# What that cost is the whole point: with an unreliable count a selftest that
# asserts twelve things and one that asserts NOTHING render identically, and a
# module whose --selftest is `sys.exit(0)` was PROVEN by plant to score green.
# That is the "green whose subject was never established" shape this tree
# files against everywhere else, and must0_scan.py already carries the remedy
# in its own words -- "A scanner that cannot find its subject FAILS."  The
# concept was in the INSTRUMENTS and absent from the RUNNER that scores them.
#
# So: all four conventions are counted, and a green with ZERO counted arms is
# a RED.  An instrument that invents a fifth spelling shows up as a red with
# a real selftest, which is a visible, one-line fix -- and is the direction
# this has to fail in, because the alternative is scoring silence as proof.
# A SIXTH SPELLING, AND THE END OF COUNTING BY HAND -- FINDING 97-B.
#
# `^  A .* ok` matched the FIRST arm of the `  <label> <text> ok` convention
# and none of the others, so opcenc_ab (19 checks), srcenc_ab (17) and
# srcset_ab (9) each scored ONE; and enumocc.py, whose six arms were the
# census the enum tables' retirement turned on, scored ZERO and stood as
# RED / ASSERTS NOTHING from the day it was added.  (That instrument is
# itself retired now, with its subject: the four enum tables are gone and
# the plugin can no longer state the ENUM key it scored.)  The label is
# widened to the convention it belongs to -- one short leading token, then
# `ok` at the end.
#
# But widening a hand-list only postpones the next gap, so the count is no
# longer the only witness.  An instrument that states its own check count
# (`<name> selftest: N check(s), M failure(s)`) is a SECOND SOURCE, and the
# two must agree: N - M is the number of arms that passed, and the counted
# `ok` lines must equal it.  A disagreement is reported and is RED, in both
# directions -- a grammar this runner does not know, and a summary claiming
# checks whose arms were never printed, are the same defect seen from two
# sides, and neither may be silent.  Instruments that print no summary are
# scored on the count alone, as before; that is the remaining blind spot and
# it is named here rather than left to be discovered.
count_arms() {
    grep -c -E "^PASS|^  PASS|^ARM [0-9]+ ok:|^selftest .*-> OK|^  ARM .* ok|^  [A-Z][A-Za-z0-9]{0,3} .* ok$" "$1"
}

# The instrument's own count of passing checks, or empty when it states none.
claimed_pass() {
    local s n m
    s=$(grep -oE '[0-9]+ check\(s\), [0-9]+ failure\(s\)' "$1" | tail -1)
    [ -n "$s" ] || return 0
    n=${s%% *}; m=$(printf '%s' "$s" | sed 's/.*, \([0-9]*\) failure.*/\1/')
    echo $((n - m))
}

n=0; ok=0; nost=0; vac=0; mis=0
declare -a RED=() NOST=() VAC=() MIS=()
for f in *.py; do
    case "$f" in
        _*|evopen.py) continue ;;   # library modules, not instruments
    esac
    n=$((n + 1))
    if ! grep -q -- '--selftest' "$f"; then
        nost=$((nost + 1)); NOST+=("$f")
        printf 'NO-SELFTEST  %s\n' "$f"
        continue
    fi
    # TWO CONVENTIONS LIVE HERE AND BOTH ARE LEGITIMATE.  Tools that plant
    # files on disk take a temp root (`--selftest DIR`); tools that plant
    # them in memory take `--selftest` alone and REFUSE an extra argument --
    # `mech_contain.py` requires argv to be exactly that one word.  A runner
    # that knows only one convention reports the other as RED, which is a
    # defect in the runner wearing a finding's clothes.  Both are tried, and
    # WHICH ONE ANSWERED is printed, so the grammar is visible rather than
    # guessed at.
    log="$TMP/${f%.py}.log"
    if "$PY" "$f" --selftest > "$log" 2>&1; then
        form=bare
    elif "$PY" "$f" --selftest "$TMP/${f%.py}" > "$log" 2>&1; then
        form=tmpdir
    else
        form=
    fi
    if [ -n "$form" ]; then
        arms=$(count_arms "$log")
        claim=$(claimed_pass "$log")
        if [ "$arms" -eq 0 ]; then
            vac=$((vac + 1)); VAC+=("$f")
            printf 'RED   %-26s %-7s 0 arm(s) -- ASSERTS NOTHING\n' \
                   "$f" "$form"
        elif [ -n "$claim" ] && [ "$claim" != "$arms" ]; then
            mis=$((mis + 1)); MIS+=("$f")
            printf 'RED   %-26s %-7s %s arm(s) counted but the instrument says %s passed -- THE TWO SOURCES DISAGREE\n' \
                   "$f" "$form" "$arms" "$claim"
        else
            ok=$((ok + 1))
            printf 'PASS  %-26s %-7s %s arm(s)%s\n' "$f" "$form" "$arms" \
                   "${claim:+ (instrument agrees: $claim)}"
        fi
    else
        RED+=("$f")
        printf 'RED   %-26s see %s\n' "$f" "$log"
    fi
done

printf '\ninstruments found %d  green %d  RED %d  ZERO-ARM %d  ARM-COUNT-MISMATCH %d  NO-SELFTEST %d\n' \
       "$n" "$ok" "${#RED[@]}" "$vac" "$mis" "$nost"
[ "${#RED[@]}" -eq 0 ] || printf 'RED: %s\n' "${RED[*]}"
[ "$vac" -eq 0 ] || printf 'ZERO-ARM: %s\n' "${VAC[*]}"
[ "$mis" -eq 0 ] || printf 'ARM-COUNT-MISMATCH: %s\n' "${MIS[*]}"
[ "$nost" -eq 0 ] || printf 'NO-SELFTEST: %s\n' "${NOST[*]}"
# A module without a selftest is a failure of this script, not a silence; a
# selftest that asserts nothing is the same failure one step later; and a
# count this runner cannot reconcile with the instrument's own is the same
# failure one step later again.
[ "${#RED[@]}" -eq 0 ] && [ "$vac" -eq 0 ] && [ "$mis" -eq 0 ] \
    && [ "$nost" -eq 0 ]
