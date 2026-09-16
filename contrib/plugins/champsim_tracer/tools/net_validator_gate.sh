#!/usr/bin/env bash
# net_validator_gate.sh — run the golden net's VALIDATOR arm as a standing gate.
#
# Usage: net_validator_gate.sh <build-dir> [workload ...]
#
# WHAT THIS IS, AND WHAT IT IS NOT.
# The golden net has two arms.  The HASH arm compares trace bytes to a
# recorded reference; it is parked by a standing hold and this script never
# touches it.  The VALIDATOR arm runs the net's generated cells through the
# validator and adjudicates every run with val_gate.sh.  That arm is the only
# place several content checks have ever had a subject at all — the standalone
# battery reports checked=0 for call_return_store, proven — so holding the
# hash arm must not take the validator arm down with it.
#
# A green from this script means: the net's cells ran and the validator
# reported errors=0 on each.  It means NOTHING about trace bytes.
#
# TO PROVE THE GATE FIRES, break one cell arm on purpose:
#   CST_NET_VALIDATE_FAULT=w1_baseline net_validator_gate.sh <build> w1_baseline
# The named workload's validator invocation is given a bad argument, the
# validator process really fails, val_gate.sh really adjudicates it, and this
# script must exit non-zero.  A green under fault injection is itself a
# failure of the gate.
set -u
build=${1:?usage: net_validator_gate.sh <build-dir> [workload ...]}
shift || true

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
net="$here/../tests/golden_net.py"
py=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}

args=("$net" validate --build-dir "$build")
for wl in "$@"; do
    args+=(--only "$wl")
done

log=$(mktemp)
trap 'rm -f "$log"' EXIT
"$py" "${args[@]}" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}

if [ -n "${CST_NET_VALIDATE_FAULT:-}" ]; then
    # Under injection the ONLY acceptable outcome is red.  A pass here means
    # the gate cannot see a failing cell, which is worse than a failing cell.
    if [ "$rc" = 0 ]; then
        echo "net_validator_gate: FAIL — fault injection was armed for" \
             "'$CST_NET_VALIDATE_FAULT' and the gate still came back GREEN." \
             "The gate cannot see a failing cell."
        exit 1
    fi
    # A non-zero exit is not the proof.  The proof is that the NET-VALIDATOR
    # ARM is what went red: a build-gate refusal or a missing binary is also
    # non-zero and would let a blind gate pass this check.
    if ! grep -q "NET-VALIDATOR ARM FAILED" "$log"; then
        echo "net_validator_gate: FAIL — the run exited $rc but the" \
             "net-validator arm never reported a failing cell.  Something" \
             "else refused (build gate, missing binary); the injection is" \
             "NOT proven.  Fix that first and re-run."
        exit 1
    fi
    echo "net_validator_gate: injection proof OK — the net-validator arm" \
         "went red (rc=$rc) with '$CST_NET_VALIDATE_FAULT' broken on purpose."
    exit 0
fi

if [ "$rc" != 0 ]; then
    echo "net_validator_gate: FAIL — net-validator arm rc=$rc" \
         "(hash arm parked by standing hold; untouched)"
    exit "$rc"
fi
echo "net_validator_gate: PASS — net-validator arm green" \
     "(hash arm parked by standing hold; untouched)"
