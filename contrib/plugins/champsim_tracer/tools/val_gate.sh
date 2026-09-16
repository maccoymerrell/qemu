#!/usr/bin/env bash
# val_gate.sh — adjudicate a champsim_tracer_validator log.
#
# Usage: val_gate.sh <validator-log> [<validator-exit-code>]
#
# A validator run passes ONLY when all three hold:
#   1. the exit code (if given) is 0,
#   2. the log contains the summary line "total: N issues (errors=E, ...)",
#   3. E is 0.
# A log with NO summary line FAILS: a check that cannot find its subject
# must fail, never pass.  This exists because ad-hoc wave scripts grepped
# for "errors=0 warnings=0" (space-separated), matched nothing against the
# comma-separated real output, and recorded a blank as a pass.
set -u
log=${1:?usage: val_gate.sh <validator-log> [<exit-code>]}
rc=${2:-0}

if [ "$rc" != 0 ]; then
    echo "val_gate: FAIL — validator exit code $rc ($log)"
    exit 1
fi
line=$(grep -E 'total: [0-9]+ issues \(errors=[0-9]+' "$log" | tail -n 1)
if [ -z "$line" ]; then
    echo "val_gate: FAIL — no summary line found in $log (a blank match is a failure, not a pass)"
    exit 1
fi
errors=$(printf '%s\n' "$line" | sed -E 's/.*errors=([0-9]+).*/\1/')
if [ "$errors" != 0 ]; then
    echo "val_gate: FAIL — errors=$errors ($line)"
    exit 1
fi
echo "val_gate: PASS — $line"
