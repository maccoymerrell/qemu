#!/bin/bash
# acceptance_gate.sh — the rebuild program's fail-closed push gate.
#
# Author: Maccoy Merrell
# SPDX-License-Identifier: GPL-2.0-or-later
#
# MAINTAINER RULING 2026-10-15: the standing drift/external-truth legs may
# never be dropped; no justification is sufficient. This gate makes that
# mechanical: EVERY row of ACCEPTANCE_MANIFEST.tsv must resolve to a fresh
# artifact, stamped with the CURRENT tips of both trees, containing its
# required PASS line. A missing, stale, empty, or unstamped artifact is a
# FAIL. There is no skip flag, no row filter, no environment override.
# Rows change only when the maintainer edits the manifest.
#
# usage: acceptance_gate.sh <results_dir> [<rebuild_tree>]
#   results_dir:  where a wave wrote its leg artifacts (parity/, r13/, det/,
#                 golden/, gates/, rate/, cost/, screen/, trailers/ subdirs).
#   rebuild_tree: the checkout whose HEAD is the rebuild tip every artifact
#                 must be stamped with.  Given as the second argument or as
#                 CST_REBUILD_TREE; there is NO default.
# exit 0 = every leg green at the current tips; nonzero = push is refused.
#
# THE REBUILD TREE IS NAMED, NEVER DEFAULTED.  This gate used to read its
# rebuild tip from a hard-coded /mnt/md0/QEMU/qemu-rebuild -- a tree the
# 2026-10-17 hard reset DISCARDED -- so it would have stamped a push of the
# fresh rebuild against the discarded tree's HEAD.  Worse, a failed
# rev-parse left REBUILD_TIP empty, and `grep -q ""` matches every
# artifact: the staleness guard would have accepted anything.  So the tree
# is required, must be a git checkout carrying the plugin, and must yield a
# tip; otherwise the gate refuses before reading a single leg.
#
# THE GATE AND ITS MANIFEST LIVE IN THE TREE THEY GATE.  Both sit in
# contrib/plugins/champsim_tracer/tools/, under git, so the manifest a run
# reads is the one committed beside the script, and the tools tip is the
# HEAD of the checkout the script was run from -- never a fixed path to a
# tree elsewhere on the host.
set -u
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
M=$HERE/ACCEPTANCE_MANIFEST.tsv
[ -s "$M" ] || { echo "acceptance_gate: REFUSED — no manifest at $M" >&2; exit 2; }
TOOLS_TREE=$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null) || TOOLS_TREE=""
R=${1:?usage: acceptance_gate.sh <results_dir> [<rebuild_tree>]  (or CST_REBUILD_TREE)}
RT=${2:-${CST_REBUILD_TREE:-}}
refuse() { echo "acceptance_gate: REFUSED — $*" >&2; exit 2; }
[ -n "$RT" ] || refuse "no rebuild tree named (second argument or" \
    "CST_REBUILD_TREE).  There is no default: the old one was the discarded" \
    "/mnt/md0/QEMU/qemu-rebuild."
[ -d "$RT/contrib/plugins/champsim_tracer" ] || refuse "'$RT' has no" \
    "contrib/plugins/champsim_tracer -- not a tracer tree (an upstream-QEMU" \
    "checkout or a wrong path)."
REBUILD_TIP=$(git -C "$RT" rev-parse HEAD 2>/dev/null) || REBUILD_TIP=""
[ -n "$REBUILD_TIP" ] || refuse "cannot read HEAD of '$RT'; an empty tip" \
    "would match every artifact."
[ -n "$TOOLS_TREE" ] || refuse "'$HERE' is not inside a git checkout; the" \
    "tools tip cannot be read."
TOOLS_TIP=$(git -C "$TOOLS_TREE" rev-parse HEAD 2>/dev/null) || TOOLS_TIP=""
[ -n "$TOOLS_TIP" ] || refuse "cannot read HEAD of $TOOLS_TREE."

fails=0 rows=0
echo "acceptance_gate: rebuild_tree=$RT rebuild_tip=$REBUILD_TIP tools_tip=$TOOLS_TIP results=$R"
while IFS=$'\t' read -r leg glob regex desc; do
    case "$leg" in ''|'#'*) continue ;; esac
    rows=$((rows + 1))
    found=""
    for f in $R/$glob; do
        [ -s "$f" ] || continue
        # staleness guard: the artifact must carry the CURRENT rebuild tip
        # (and, where it names one, the current tools tip).
        grep -q "$REBUILD_TIP" "$f" || continue
        if grep -q 'TOOLS_TIP=' "$f"; then
            grep -q "TOOLS_TIP=$TOOLS_TIP" "$f" || continue
        fi
        grep -Eq "$regex" "$f" || continue
        found="$f"
        break
    done
    if [ -n "$found" ]; then
        echo "  PASS $leg ($found)"
    else
        echo "  FAIL $leg -- no fresh, stamped, passing artifact for '$glob' ($desc)" | cut -c1-200
        fails=$((fails + 1))
    fi
done < "$M"

echo "acceptance_gate: $rows legs, $fails FAIL"
if [ "$fails" -ne 0 ] || [ "$rows" -eq 0 ]; then
    echo "acceptance_gate: REFUSED — a leg without a fresh green artifact is a FAIL; absence is never a pass."
    exit 1
fi
echo "acceptance_gate: ALL LEGS GREEN at $REBUILD_TIP"
