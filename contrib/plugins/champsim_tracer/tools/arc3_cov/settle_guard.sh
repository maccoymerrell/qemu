#!/bin/bash
# ARC 3 -- SETTLE-BEFORE-LEGS.  The precondition every attribution leg owes,
# and the stamp that makes a mid-run relink the LEG's failure instead of the
# report's.
#
# THE FAILURE THIS EXISTS FOR.  coverage_report.py refuses to publish a
# headline whose per-ISA table is older than the isaxcheck binary it scores.
# That guard is right and it stays.  What it cannot do is fire in time: it runs
# at PUBLISH, after four heterogeneous legs have taken hours -- aarch64 walks
# the Arm MRA, riscv64 the Sail model, x86_64 four reachability legs under
# qemu-system -- so a relink anywhere in that window is discovered only once
# every one of them has already been paid for.  And the relink does not have to
# be anybody's mistake: a leg script that builds a probe, a second agent in the
# same tree, an editor's save picked up by the next ninja, all move the binary
# under tables already written.
#
# So the check moves to the two places that can act on it:
#
#   arm    BEFORE ANY WORK.  A leg started against a tree with pending work is
#          a leg whose table is stale before it is written.  Refuse there,
#          where nothing has been spent yet.
#   check  AFTER the table is written.  The subject is re-hashed against the
#          stamp, so a relink DURING the leg is named by the leg it
#          invalidated, at the leg, with the binary that moved.
#
# WHY THE STAMP HASHES AND DOES NOT ONLY COMPARE mtime.  PASS 81 restored a
# source file to an mtime OLDER than the object built from it during an
# excursion, and ninja kept a binary that silently carried the excursion's
# code.  An mtime that went BACKWARD is exactly as disqualifying as one that
# went forward, and only content can say so.  Both are recorded; the content
# is what decides.
#
# WHY `ninja -n` IS ASKED PER TARGET, AND WHY THE SUBJECT LIST IS SHORT.
# A bare `ninja -C build -n` in this tree is NEVER empty, and it never will be.
# Measured at 11b4a7f539, a full dry run is 175 edges of which 113 are real
# work, and the root of all of it is one line of build.ninja:
#
#     build qemu-version.h: CUSTOM_COMMAND | .../qemu-version.sh PHONY
#
# PHONY as an input means always dirty by construction.  Every ninja
# regenerates qemu-version.h, which recompiles `linux-user/main.c` for all
# thirty-odd user targets and RELINKS every `qemu-*` binary.  A settle probe
# written against the whole build would refuse every time it was asked and be
# switched off within a day, and a guard that is always red is a guard nobody
# reads.  The `*-tls-guard` custom commands are the same shape.
#
# AND THE RELINK IS NOT CONTENT-NEUTRAL, which is the part worth knowing before
# trusting a hash of a guest binary.  qemu-version.sh embeds `git describe`, so
# a single commit changes QEMU_PKGVERSION and therefore the bytes of every
# qemu-* binary, with no line of emulation code having moved:
#
#     -#define QEMU_PKGVERSION "v10.0.8-1599-g5f6907e9f7"
#     +#define QEMU_PKGVERSION "v10.0.8-1600-g11b4a7f539"
#
# So `qemu-*` is deliberately NOT a subject here.  Stamping it would convict
# every leg that happened to span a commit, on a version string, and a guard
# that cries on a version string teaches people to pass --allow-stale.  The
# subjects are the three binaries whose CONTENT is the tracer's behaviour --
# and isaxcheck, the one coverage_report.py actually measures freshness
# against, is settle-able and stays settled across all of this.
#
#   usage: settle_guard.sh arm   <stampfile> [extra ninja target ...]
#          settle_guard.sh check <stampfile>
#
# Author: Maccoy Merrell.
set -euo pipefail

MODE=${1:?usage: settle_guard.sh arm|check <stampfile> [target ...]}
STAMP=${2:?usage: settle_guard.sh arm|check <stampfile> [target ...]}
shift 2 || true

: "${CST_QEMU_DIR:=/mnt/md0/QEMU/qemu}"
: "${CST_BUILD:=$CST_QEMU_DIR/build}"

# The subjects, in the build's own target spelling.  isaxcheck is first
# because it is the binary coverage_report.py measures freshness against, so
# a leg that passes this guard cannot fail that one for a reason this guard
# could have seen.
SUBJECTS=(contrib/plugins/isaxcheck
          contrib/plugins/libchampsim_tracer.so
          contrib/plugins/cst_decode
          "$@")

die() { echo "SETTLE GUARD REFUSED: $*" >&2; exit 3; }

stamp_one() {   # $1 target -> "<target> <sha256> <mtime>"
    local t=$1 p="$CST_BUILD/$1"
    [ -f "$p" ] || die "no such subject: $p
  This guard scores the tree the legs are about to measure.  A check that
  cannot find its subject must fail, never pass quietly.  Build it first."
    echo "$t $(sha256sum "$p" | cut -d' ' -f1) $(stat -c %Y "$p")"
}

case "$MODE" in
arm)
    [ -d "$CST_BUILD" ] || die "no build directory at $CST_BUILD"
    for t in "${SUBJECTS[@]}"; do
        out=$(ninja -C "$CST_BUILD" -n "$t" 2>&1) || die "ninja could not \
evaluate $t:
$out"
        case "$out" in
        *"no work to do."*) ;;
        *) case "$out" in
           *qemu-version.h*) echo "NOTE: the pending work below starts at qemu-version.h, which build.ninja declares PHONY and which is therefore always dirty.  If \`$t\` is a qemu-* binary it can never settle; it is not a subject of this guard, and the header above says why." >&2 ;;
           esac
           die "the tree is NOT SETTLED: \`$t\` has pending build work.

$out

  A leg started here writes a table older than the binary it describes, and
  coverage_report.py will refuse it -- hours from now, after every other leg
  has been paid for too.  Settle first (a FULL ninja, twice), then re-run." ;;
        esac
    done
    : > "$STAMP"
    for t in "${SUBJECTS[@]}"; do stamp_one "$t" >> "$STAMP"; done
    echo "settle guard ARMED against $CST_BUILD:"
    sed 's/^/  /' "$STAMP"
    ;;
check)
    [ -s "$STAMP" ] || die "no stamp at $STAMP -- this leg never armed the
  guard, so nothing here can say whether its subject moved.  An unarmed check
  reports success without verifying, which is the failure it exists to catch."
    moved=0
    while read -r t was_sha was_mt; do
        now=$(stamp_one "$t")
        now_sha=$(echo "$now" | cut -d' ' -f2)
        now_mt=$(echo "$now" | cut -d' ' -f3)
        if [ "$now_sha" != "$was_sha" ]; then
            echo "  RELINKED DURING THIS LEG  $t" >&2
            echo "    content  $was_sha -> $now_sha" >&2
            echo "    mtime    $was_mt -> $now_mt" >&2
            moved=$((moved + 1))
        elif [ "$now_mt" != "$was_mt" ]; then
            echo "  TOUCHED (content unchanged)  $t  mtime $was_mt -> $now_mt" \
                 >&2
        fi
    done < "$STAMP"
    [ "$moved" -eq 0 ] || die "$moved subject(s) were rebuilt while this leg
  ran, named above.  The table this leg just wrote describes a binary that no
  longer exists.  Re-run the leg against a settled tree; do not publish it."
    echo "settle guard CLEAN: no subject moved during this leg"
    ;;
*)  die "unknown mode '$MODE' (want: arm | check)" ;;
esac
