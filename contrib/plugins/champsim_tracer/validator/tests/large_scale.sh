#!/bin/bash
#
# Large-scale genval sweep for the champsim_tracer.
#
# Walks the cross product of {N seeds} × {4 ISAs} × {several program
# shapes that stress hot loops + many BBs}, runs the full validator
# on each, and aggregates pass/fail counts.  Designed to be the
# standing regression net once the per-probe exact-check library is
# in place — covers what individual seeds can miss.
#
# Defaults are sized to run in a few minutes; bump SEEDS / DIAMONDS /
# STOP for an exhaustive overnight sweep before tagging a release.
#
# Usage:
#   tests/large_scale.sh                          # default sweep
#   SEEDS=64 ISAS="x86_64 aarch64" tests/large_scale.sh
#   STOP=2000000 DIAMONDS=10 HOT_ITERS=64 tests/large_scale.sh
#
# Environment knobs:
#   SEEDS         : number of distinct seeds per (ISA, shape).         [16]
#   FIRST_SEED    : starting seed (decimal or 0x...).                  [0x51A0]
#   ISAS          : space-separated ISA list.            [x86_64 aarch64 riscv64 mipsel]
#   STOP          : icount stop bound per program.                     [200000]
#   DIAMONDS      : genval --diamonds value (controls BB count).       [8]
#   SIDE_LEN_MIN  : genval --side-len-min.                             [2]
#   SIDE_LEN_MAX  : genval --side-len-max.                             [5]
#   HOT_ITERS     : genval --hot-iters value.                          [16]
#   BUILD_DIR     : QEMU build dir.                  [QEMU_ROOT/build]
#   PYTHON        : Python with capstone available.  [~/anaconda3/bin/python3]
#   PARALLEL      : nproc to use; defaults to half the host cores.     [auto]
#   STOP_ON_FAIL  : "1" to abort on the first failure.                 [0]
#
# This script is intentionally an unmoderated oracle: every validator
# error surfaces.  Do NOT add filters that hide categories of
# failures — the whole point is to find tracer bugs.
#
# Output: per-run pass/fail line, then an aggregate summary.  Failing
# runs leave their working dir at $OUT_ROOT/<seed>_<isa>_<shape>/
# for post-mortem inspection.
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
VAL_ROOT="$(cd "$HERE/.." && pwd)"
QEMU_ROOT="$(cd "$VAL_ROOT/../../../.." && pwd)"

: "${BUILD_DIR:=$QEMU_ROOT/build}"
: "${PYTHON:=$HOME/anaconda3/bin/python3}"

: "${SEEDS:=16}"
: "${FIRST_SEED:=0x51A0}"
: "${ISAS:=x86_64 aarch64 riscv64 mipsel}"
: "${STOP:=200000}"
: "${DIAMONDS:=8}"
: "${SIDE_LEN_MIN:=2}"
: "${SIDE_LEN_MAX:=5}"
: "${HOT_ITERS:=16}"
: "${STOP_ON_FAIL:=0}"

if [ -z "${PARALLEL:-}" ]; then
    cores=$(nproc 2>/dev/null || echo 4)
    PARALLEL=$(( cores / 2 ))
    [ "$PARALLEL" -lt 1 ] && PARALLEL=1
fi

# Shape configs: each is a label and a set of extra genval args.
# Index 0 is the baseline (coverage probes + hot loops, medium size).
# Index 1 stresses the CFG (more diamonds, wider sides) to surface
# rare-path tracer bugs.  Index 2 piles on iterations so hot-loop
# state-machine bugs in the tracer become more likely to hit.
SHAPES=(
    "coverage      --coverage --hot-iters $HOT_ITERS --diamonds $DIAMONDS --side-len-min $SIDE_LEN_MIN --side-len-max $SIDE_LEN_MAX"
    "wide-cfg      --coverage --hot-iters $HOT_ITERS --diamonds $((DIAMONDS * 2)) --side-len-min $((SIDE_LEN_MIN + 1)) --side-len-max $((SIDE_LEN_MAX + 2))"
    "hot-stress    --coverage --hot-iters $((HOT_ITERS * 4)) --diamonds $DIAMONDS --side-len-min $SIDE_LEN_MIN --side-len-max $SIDE_LEN_MAX"
)

OUT_ROOT="$(mktemp -d -t large_scale.XXXXXXXX)"
trap '[ -d "$OUT_ROOT" ] && find "$OUT_ROOT" -maxdepth 1 -type d -empty -delete; echo "" ; echo "Failure dirs (if any) under $OUT_ROOT/"' EXIT

# Compute the seed list: FIRST_SEED..FIRST_SEED+SEEDS-1 (hex format).
seed_list=()
first_dec=$(printf '%d' "$FIRST_SEED")
for ((i=0; i<SEEDS; i++)); do
    seed_list+=( "$(printf '0x%X' "$((first_dec + i))")" )
done

# Run one validator invocation; the validator's `all` subcommand
# drives generate → build → trace → validate end-to-end.  Every
# non-zero error count from the validator counts as a failure;
# nothing is filtered.
run_one() {
    local seed="$1" isa="$2" shape_label="$3"; shift 3
    local shape_args=("$@")
    local tag="${shape_label}_${isa}_${seed//0x/}"
    local out="$OUT_ROOT/$tag"
    mkdir -p "$out"

    local log="$out/validator.log"
    # Capture the exit code so we can distinguish "validator ran and
    # reported errors" (non-zero exit + summary line) from "validator
    # itself crashed before producing a summary" (non-zero exit + no
    # summary).  The validator returns non-zero whenever errors > 0
    # by design — we still want to read its findings out of the log.
    ( cd "$VAL_ROOT" && "$PYTHON" -m champsim_tracer_validator all \
            --seed "$seed" -o "$out" --isa "$isa" \
            --build-dir "$BUILD_DIR" --stop "$STOP" \
            "${shape_args[@]}" ) >"$log" 2>&1
    local rc=$?
    local summary
    summary=$(grep -E '^[[:space:]]*total: ' "$log" | tail -1)
    if [ -z "$summary" ]; then
        echo "RUN seed=$seed isa=$isa shape=$shape_label status=CRASH rc=$rc log=$log"
        return 1
    fi
    local errors
    errors=$(printf '%s\n' "$summary" | sed -nE 's/.*errors=([0-9]+).*/\1/p')
    errors=${errors:-0}
    if [ "$errors" -gt 0 ]; then
        echo "RUN seed=$seed isa=$isa shape=$shape_label status=FAIL errors=$errors log=$log"
        return 1
    fi
    echo "RUN seed=$seed isa=$isa shape=$shape_label status=OK errors=0 log=$log"
    rm -rf "$out"
    return 0
}

total=0
pids=()
slots=$PARALLEL

# Bounded-concurrency pool: up to $slots run_one calls in flight at
# once.  Each prints a RUN line on completion; the trailing tally
# walks $OUT_ROOT (failures leave their dir behind, OKs unlink).
for shape in "${SHAPES[@]}"; do
    label="$(echo "$shape" | awk '{print $1}')"
    args="$(echo "$shape" | cut -d' ' -f2-)"
    # shellcheck disable=SC2086
    set -- $args
    args_arr=( "$@" )
    for isa in $ISAS; do
        for seed in "${seed_list[@]}"; do
            total=$((total + 1))
            run_one "$seed" "$isa" "$label" "${args_arr[@]}" &
            pids+=( "$!" )
            if [ "${#pids[@]}" -ge "$slots" ]; then
                wait -n
                new_pids=()
                for p in "${pids[@]}"; do
                    if kill -0 "$p" 2>/dev/null; then new_pids+=( "$p" ); fi
                done
                pids=( "${new_pids[@]}" )
            fi
        done
    done
done

# Drain the pool.
for p in "${pids[@]}"; do wait "$p" || true; done

# Tally by walking $OUT_ROOT — failures leave their directory; OKs
# rm -rf themselves on completion.
left=$(find "$OUT_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)

echo ""
echo "=================================================================="
echo "large-scale sweep complete"
echo "  total runs:         $total"
echo "  preserved fail dirs: $left ($OUT_ROOT)"
echo "  PARALLEL=$PARALLEL  STOP=$STOP  SEEDS=$SEEDS"
echo "  ISAS=$ISAS"
printf "  SHAPES=\n"
for s in "${SHAPES[@]}"; do printf "    %s\n" "$s"; done
echo "=================================================================="
if [ "$left" -gt 0 ]; then
    if [ "$STOP_ON_FAIL" = "1" ]; then exit 1; fi
    exit 2
fi
exit 0
