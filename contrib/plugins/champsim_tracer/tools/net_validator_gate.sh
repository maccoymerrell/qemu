#!/usr/bin/env bash
# net_validator_gate.sh — run the golden net (`golden_net.py check`) as a
# standing gate.
#
# Usage: net_validator_gate.sh <build-dir>
#
# WHAT THIS IS.
# `golden_net.py check` runs every net cell through the validator `all`
# battery and compares each per-ISA verdict to the baseline recorded in the
# manifest (a cell that prints no verdict fails), and it compares each
# cell's body/legacy/templates hashes and the SVG goldens to the manifest.
# A green from this script means both of those held on the build under
# test.  The validator arm matters on its own: it is the only place several
# content checks have ever had a subject at all — the standalone battery
# reports checked=0 for call_return_store, proven.
#
# WHAT IT IS NOT.
# This script used to describe a validator-only `validate` mode with
# per-workload `--only` selection and a CST_NET_VALIDATE_FAULT injection
# proof.  golden_net.py has never had any of the three, so the gate was red
# on every run with argparse's rc=2.  The call is now to `check`; a
# workload argument or CST_NET_VALIDATE_FAULT is REFUSED rather than
# silently ignored, because honouring neither would report a whole-net
# verdict for a subset request, or an injection proof that injected
# nothing.
set -u
build=${1:?usage: net_validator_gate.sh <build-dir>}
shift || true

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
net="$here/../tests/golden_net.py"
py=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}

# THE SUBCOMMAND THIS GATE CALLS MUST EXIST.  This script used to run
# `golden_net.py validate --only <wl>`, and golden_net.py has never had a
# `validate` mode (its CLI is `capture | check`, with no --only): argparse
# refused, rc=2, and row 11 of battery15 was red on every run for a reason
# that had nothing to do with the tracer -- an always-red gate is one
# nobody reads.  The mode is now `check`, which runs every net cell
# through the validator (each per-ISA verdict compared to its recorded
# baseline; a missing verdict is a failure) AND compares each cell's
# hashes to the manifest.  So a green from this script now covers both
# arms of the net.  The subcommand is checked against golden_net.py's own
# usage line before the run, so a renamed or removed mode is refused by
# name instead of surfacing as an anonymous rc=2.
mode=check
[ -f "$net" ] || { echo "net_validator_gate: FAIL — $net not found" >&2; exit 2; }
usage_line=$("$py" "$net" --help 2>&1 | grep -m1 -oE '\{[a-z,_-]+\}')
case ",$(printf '%s' "$usage_line" | tr -d '{}')," in
    *",$mode,"*) ;;
    *) echo "net_validator_gate: FAIL — golden_net.py has no '$mode'" \
            "subcommand (its usage offers '${usage_line:-nothing parseable}')." \
            "The gate cannot call what does not exist; fix the call." >&2
       exit 2 ;;
esac

# Neither per-workload selection nor fault injection exists in `check`.
# Both used to be accepted here and forwarded to the absent `validate`
# mode; silently ignoring them now would report a full-net verdict for a
# subset request, or a "proof" that injected nothing.  Refuse both.
if [ $# -gt 0 ]; then
    echo "net_validator_gate: FAIL — workload selection ($*) is not" \
         "supported: golden_net.py check has no --only; run the whole net." >&2
    exit 2
fi
if [ -n "${CST_NET_VALIDATE_FAULT:-}" ]; then
    echo "net_validator_gate: FAIL — CST_NET_VALIDATE_FAULT is set, but" \
         "golden_net.py has no fault-injection hook, so nothing would be" \
         "injected and no firing could be proven.  REFUSING." >&2
    exit 2
fi

args=("$net" "$mode" --build-dir "$build")

log=$(mktemp -p "${CST_GATE_TMP:-/mnt/md0/QEMU/cst_runs/scratch}")
trap 'rm -f "$log"' EXIT
"$py" "${args[@]}" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}

if [ "$rc" != 0 ]; then
    echo "net_validator_gate: FAIL — golden_net.py $mode rc=$rc"
    exit "$rc"
fi
if ! grep -q "GOLDEN NET GREEN" "$log"; then
    echo "net_validator_gate: FAIL — golden_net.py $mode exited 0 without" \
         "its GOLDEN NET GREEN line; a green with no verdict is not a pass."
    exit 1
fi
echo "net_validator_gate: PASS — golden net green (validator verdicts at" \
     "baseline and every cell's hashes byte-identical)"
