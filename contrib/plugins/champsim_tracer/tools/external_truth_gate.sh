#!/bin/sh
# ARC 3 / R13 -- THE EXTERNAL-TRUTH GATE.  ONE ENTRY POINT.
#
#   external_truth_gate.sh <evidence-root> [--build-dir DIR] [--only a,b]
#   external_truth_gate.sh --selftest [scratch-dir]
#
# R13 makes the reference flow a STANDING GATE rather than a deliverable: the
# trace's facts are scored against LLVM MC / Capstone-as-external-reference /
# XED / iced per ISA, and against PIN (x86_64), Spike (riscv64) and gem5
# (aarch64, mipsel) as EXECUTION references for registers, memops, register
# values, memory values and wrong-path correctness.  Internal instruments
# prove PROVENANCE; only these references prove TRUTH.
#
# A future wave's COMMON section cites THIS PATH and nothing else.
#
# WHAT IT DOES.  Each leg writes its own report; this gate reads them and
# compares each leg's headline -- the count of rows where the tracer drops
# information a reference states, or where the difference is not understood --
# against the ceiling a maintainer adjudicated row by row in
# external_truth_gate/ADJUDICATED.tsv.
#
# IT FAILS, never skips, when: a report is missing; a headline cannot be
# parsed; a headline exceeds its ceiling; a leg's scored population is below
# its floor; or a report is older than the tracer binaries it claims to have
# measured.  A check that cannot find its subject fails.
#
# WHAT IT DOES NOT DO.  It does not run the legs.  Running gem5, Spike and PIN
# takes hours and needs guests this repository does not carry; the legs have
# their own REPRODUCE scripts (arc3_cov/{gem5,riscv64/spike}/REPRODUCE*.sh,
# arc3_cov/x86_64/REPRODUCE.sh, arc3_pinexec/).  This gate is what turns their
# output into a pass or a failure, and the staleness guard is what stops a
# green being taken from a run that predates the build.
#
# Exit codes come from the process.  Nothing is read through a pipe.
#
# Author: Maccoy Merrell.
set -e

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PY=${PY:-/home/maccoy-merrell/anaconda3/bin/python}
SCORE="$HERE/external_truth_gate/score.py"

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

# --------------------------------------------------------------- selftest
# A gate is only a gate if it can go red.  The selftest builds a copy of a
# real evidence root, plants ONE disagreement above a ceiling, and requires
# the gate to fail on it and to pass without it.  Both directions, because a
# gate that always fails is as useless as one that always passes.
selftest() {
    SCRATCH=${1:-${TMPDIR:-/tmp}/etg_selftest.$$}
    SRC=${ETG_SELFTEST_ROOT:-/mnt/md0/QEMU/cst_runs/p3/arc3/exec33/verify/evroot}
    if [ ! -d "$SRC" ]; then
        echo "SELFTEST CANNOT RUN: no evidence root at $SRC." >&2
        echo "Set ETG_SELFTEST_ROOT.  A selftest with no subject FAILS." >&2
        exit 1
    fi
    rm -rf "$SCRATCH"
    mkdir -p "$SCRATCH/clean"
    # Copy only the reports the manifest names -- cheap, and it proves the
    # manifest's paths are the ones that matter.
    #
    # A SOURCE ROOT MISSING A REPORT IS A REFUSAL, NOT A SHORTFALL.  The
    # default used to be a fixed wave directory, and when the manifest gained
    # the gem5wp/x86_64 row that directory stopped containing every report --
    # `cp` printed one line to stderr and the selftest died mid-loop with no
    # statement of what was wrong.  Name the missing report and say what to do.
    MISSING=
    for rel in $(awk -F'\t' '!/^#/ && NF>=7 {print $3}' \
                     "$HERE/external_truth_gate/ADJUDICATED.tsv"); do
        [ -n "$rel" ] || continue
        if [ ! -f "$SRC/$rel" ]; then
            MISSING="$MISSING $rel"
            continue
        fi
        mkdir -p "$SCRATCH/clean/$(dirname "$rel")"
        cp -p "$SRC/$rel" "$SCRATCH/clean/$rel"
    done
    if [ -n "$MISSING" ]; then
        echo "SELFTEST CANNOT RUN: the evidence root $SRC does not carry" >&2
        echo "every report the manifest names.  Missing:" >&2
        for m in $MISSING; do echo "    $m" >&2; done
        echo "A selftest run over a partial root proves less than it claims," >&2
        echo "so it refuses.  Point ETG_SELFTEST_ROOT at a COMPLETE root -- the" >&2
        echo "newest wave's evroot -- and run it again." >&2
        exit 1
    fi
    cp -a "$SCRATCH/clean" "$SCRATCH/planted"

    echo "=== SELFTEST ARM A: the unmodified reports must PASS"
    if "$PY" "$SCORE" "$SCRATCH/clean" > "$SCRATCH/a.out" 2>&1; then
        echo "    PASS (rc=0), as required"
    else
        echo "    ARM A FAILED -- the gate went red on unmodified evidence:" >&2
        cat "$SCRATCH/a.out" >&2
        exit 1
    fi

    echo "=== SELFTEST ARM B: one planted disagreement must FAIL"
    # aarch64's gem5 correct-path leg is adjudicated at 22; plant 23.
    TARGET="$SCRATCH/planted/gem5/rc_aarch64.log"
    sed -i 's/the number that matters: TRACER-SUBSET + UNACCOUNTED = 22/the number that matters: TRACER-SUBSET + UNACCOUNTED = 23/' "$TARGET"
    if grep -q 'UNACCOUNTED = 23' "$TARGET"; then
        :
    else
        echo "    PLANT DID NOT TAKE -- the selftest could not create its own" >&2
        echo "    subject, so it proves nothing.  FAIL." >&2
        exit 1
    fi
    if "$PY" "$SCORE" "$SCRATCH/planted" > "$SCRATCH/b.out" 2>&1; then
        echo "    ARM B FAILED -- the gate stayed green with a planted" >&2
        echo "    disagreement above the ceiling:" >&2
        cat "$SCRATCH/b.out" >&2
        exit 1
    fi
    if grep -q 'UNADJUDICATED DISAGREEMENT: 23 > adjudicated 22' "$SCRATCH/b.out"; then
        echo "    FAIL (rc!=0) naming the planted row, as required"
    else
        echo "    ARM B went red for the WRONG REASON -- it must name the" >&2
        echo "    planted row, not fail for some unrelated cause:" >&2
        cat "$SCRATCH/b.out" >&2
        exit 1
    fi

    echo "=== SELFTEST ARM C: a missing report must FAIL, not pass by absence"
    rm -f "$SCRATCH/planted/gem5/rc_aarch64.log"
    sed -i 's/UNACCOUNTED = 23/UNACCOUNTED = 22/' "$SCRATCH/planted/gem5/rc_mipsel.log" 2>/dev/null || true
    if "$PY" "$SCORE" "$SCRATCH/planted" > "$SCRATCH/c.out" 2>&1; then
        echo "    ARM C FAILED -- a missing leg report passed the gate:" >&2
        cat "$SCRATCH/c.out" >&2
        exit 1
    fi
    if grep -q 'REPORT MISSING' "$SCRATCH/c.out"; then
        echo "    FAIL (rc!=0) naming the absent report, as required"
    else
        echo "    ARM C went red for the WRONG REASON:" >&2
        cat "$SCRATCH/c.out" >&2
        exit 1
    fi

    echo "=== SELFTEST ARM D: a report OLDER than the build must FAIL"
    # The arm that was missing, and its absence was a hole rather than a
    # cosmetic gap.  The staleness reference used to be the plugin .so and
    # cst_decode alone; #288's fix lived entirely in QEMU's translator, so a
    # report predating it would have been called fresh.  The reference is now
    # the newest of the plugin, cst_decode and every EMULATOR in the build
    # directory, and this arm is what holds it there: back-date every report
    # by a year and require a red that names staleness.
    rm -rf "$SCRATCH/stale"
    cp -a "$SCRATCH/clean" "$SCRATCH/stale"
    find "$SCRATCH/stale" -exec touch -d '2000-01-01 00:00:00' {} +
    BD=${ETG_SELFTEST_BUILD:-/mnt/md0/QEMU/qemu/build}
    if [ ! -d "$BD" ]; then
        echo "    ARM D CANNOT RUN: no build dir at $BD.  A selftest with no" >&2
        echo "    subject FAILS.  Set ETG_SELFTEST_BUILD." >&2
        exit 1
    fi
    if "$PY" "$SCORE" "$SCRATCH/stale" --build-dir "$BD" \
            > "$SCRATCH/d.out" 2>&1; then
        echo "    ARM D FAILED -- a year-old report passed the staleness guard:" >&2
        cat "$SCRATCH/d.out" >&2
        exit 1
    fi
    if grep -q 'STALE REPORT' "$SCRATCH/d.out"; then
        echo "    FAIL (rc!=0) naming staleness, as required"
    else
        echo "    ARM D went red for the WRONG REASON -- it must name the" >&2
        echo "    stale report, not fail for some unrelated cause:" >&2
        cat "$SCRATCH/d.out" >&2
        exit 1
    fi

    echo "=== SELFTEST ARM E: the staleness reference must include the EMULATORS"
    # Arm D would still pass if the reference watched only the plugin.  This
    # arm asks the scorer WHICH file set the bar and requires it to be able to
    # be an emulator: it reads the printed reference back and checks that the
    # emulator binaries were in the candidate set at all.
    "$PY" "$SCORE" "$SCRATCH/clean" --build-dir "$BD" > "$SCRATCH/e.out" 2>&1 || true
    REF=$(sed -n 's/^  newest binary : //p' "$SCRATCH/e.out")
    if [ -z "$REF" ]; then
        echo "    ARM E FAILED -- the scorer did not print its staleness" >&2
        echo "    reference, so nobody can tell what the reports are held" >&2
        echo "    against." >&2
        exit 1
    fi
    NEWEST_EMU=$(ls -t "$BD"/*_tls_guard.ok 2>/dev/null | head -1)
    if [ -z "$NEWEST_EMU" ]; then
        echo "    ARM E CANNOT RUN: $BD has no emulator stamps, so the" >&2
        echo "    discriminator has no subject.  FAIL." >&2
        exit 1
    fi
    EMU=${NEWEST_EMU%_tls_guard.ok}
    if [ "$REF" = "$BD/contrib/plugins/libchampsim_tracer.so" ] ||
       [ "$REF" = "$BD/contrib/plugins/cst_decode" ] ||
       [ -f "${REF}_tls_guard.ok" ]; then
        echo "    reference is $REF -- in the watched set, as required"
    else
        echo "    ARM E FAILED -- the reference $REF is neither a tracer" >&2
        echo "    binary nor an emulator, so the guard is watching the wrong" >&2
        echo "    files." >&2
        exit 1
    fi

    echo ""
    echo "SELFTEST PASSED -- 5 arms: clean green, planted red, missing red,"
    echo "stale red, and the staleness reference proven to cover the emulators."
    echo "evidence: $SCRATCH"
    exit 0
}

[ $# -ge 1 ] || usage
case "$1" in
    --selftest) shift; selftest "$@" ;;
    -h|--help)  usage ;;
esac

ROOT=$1; shift
exec "$PY" "$SCORE" "$ROOT" "$@"
