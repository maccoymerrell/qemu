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

n=0; ok=0; nost=0
declare -a RED=() NOST=()
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
        ok=$((ok + 1))
        printf 'PASS  %-26s %-7s %s arm(s)\n' "$f" "$form" \
               "$(grep -c '^PASS' "$log")"
    else
        RED+=("$f")
        printf 'RED   %-26s see %s\n' "$f" "$log"
    fi
done

printf '\ninstruments found %d  green %d  RED %d  NO-SELFTEST %d\n' \
       "$n" "$ok" "${#RED[@]}" "$nost"
[ "${#RED[@]}" -eq 0 ] || printf 'RED: %s\n' "${RED[*]}"
[ "$nost" -eq 0 ] || printf 'NO-SELFTEST: %s\n' "${NOST[*]}"
# A module without a selftest is a failure of this script, not a silence.
[ "${#RED[@]}" -eq 0 ] && [ "$nost" -eq 0 ]
