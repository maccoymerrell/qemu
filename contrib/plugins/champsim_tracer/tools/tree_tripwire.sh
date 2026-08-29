#!/usr/bin/env bash
# tree_tripwire.sh — has anyone else written to this checkout since we started?
#
# WHY THIS EXISTS.  A measurement pass and a source edit cannot share a tree.
# On 2026-08-29 (EXEC42 / PASS 22) a second agent began editing
# /mnt/md0/QEMU/qemu seven minutes into a verification pass, bumped the
# plugin/QEMU dataflow ABI, and every number taken after the resulting rebuild
# belonged to no tip at all.  Half that pass had to be thrown away.
#
# THE DEFECT THIS REPLACES, because it is the one worth remembering.  That
# pass DID install a tripwire first.  It was `git ls-files -s | sha1sum`,
# which hashes the INDEX: it reads identical no matter what you do to a file
# in the working tree, and it read identical through the entire contamination.
# The writer was found by an unrelated `git status` run by luck.  A check that
# cannot see its own subject and reports success is the standing failure mode
# of this tree, and that instrument was a perfect specimen of it.
#
# WHAT THIS HASHES, therefore: HEAD, the porcelain status, and the CONTENT of
# every tracked file that status reports as modified.  A working-tree edit
# moves it.  A `git add` moves it.  A commit moves it.  An edit-then-revert
# correctly does NOT move it -- the tree really is where it was.
#
# UNTRACKED files are listed but NOT hashed: `subprojects/capstone/` is a
# permanent untracked fixture in this checkout and would otherwise make the
# tripwire fire on every run, which is how a real tripwire gets ignored.
#
# USAGE
#   tree_tripwire.sh arm   <file>   record the state now
#   tree_tripwire.sh check <file>   compare; rc=0 unchanged, rc=1 MOVED
#   tree_tripwire.sh --selftest [scratch-dir]
#
# rc=2 is reserved for "this check could not run" -- missing file, not a git
# repo. It is never folded into rc=0.  A tripwire that cannot look must not
# report all-clear.
#
# Author: Maccoy Merrell.
set -u

REPO=${TREE_TRIPWIRE_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)}

digest() {
    local repo=$1
    git -C "$repo" rev-parse --verify HEAD 2>/dev/null || return 2
    echo "--- status ---"
    git -C "$repo" status --porcelain 2>/dev/null || return 2
    echo "--- content of tracked modified paths ---"
    # Field 2 of porcelain is the path; XY of '??' is untracked and skipped.
    git -C "$repo" status --porcelain 2>/dev/null \
      | while read -r xy path rest; do
            [ "$xy" = "??" ] && continue
            # Renames print "old -> new"; hash the destination.
            [ -n "${rest:-}" ] && path=${rest##* }
            if [ -f "$repo/$path" ]; then
                printf '%s  %s\n' "$(sha256sum "$repo/$path" | cut -d' ' -f1)" "$path"
            else
                printf 'ABSENT  %s\n' "$path"
            fi
        done
}

arm() {
    local out=$1
    { echo "# tree_tripwire armed $(date -Is) repo=$REPO"; digest "$REPO"; } > "$out" || {
        echo "tree_tripwire: cannot read $REPO -- REFUSING (not a pass)" >&2; return 2; }
    grep -q . "$out" || { echo "tree_tripwire: empty digest -- REFUSING" >&2; return 2; }
    echo "tree_tripwire: armed at $out"
}

check() {
    local ref=$1
    [ -f "$ref" ] || { echo "tree_tripwire: no armed state at $ref -- REFUSING" >&2; return 2; }
    local now; now=$(mktemp) || return 2
    { echo "# tree_tripwire armed IGNORED"; digest "$REPO"; } > "$now" || {
        rm -f "$now"; echo "tree_tripwire: cannot read $REPO -- REFUSING" >&2; return 2; }
    if diff <(tail -n +2 "$ref") <(tail -n +2 "$now") > /dev/null; then
        rm -f "$now"; echo "tree_tripwire: UNCHANGED since arming"; return 0
    fi
    echo "tree_tripwire: TREE MOVED since arming -- anything measured across this"
    echo "               boundary belongs to no single tip.  Difference:"
    diff <(tail -n +2 "$ref") <(tail -n +2 "$now") | sed 's/^/    /'
    rm -f "$now"; return 1
}

selftest() {
    local S=${1:-$(mktemp -d)}; mkdir -p "$S" || return 2
    local R=$S/repo; rm -rf "$R"; mkdir -p "$R"
    git -C "$R" init -q 2>/dev/null || { echo "SELFTEST: no git" >&2; return 2; }
    git -C "$R" config user.email t@t; git -C "$R" config user.name t
    echo one > "$R/f.c"; echo keep > "$R/g.c"
    git -C "$R" add f.c g.c; git -C "$R" commit -qm base
    export TREE_TRIPWIRE_REPO=$R; REPO=$R
    local rc fails=0

    echo "=== ARM A: unchanged tree must read UNCHANGED"
    arm "$S/a" >/dev/null; check "$S/a" >/dev/null; rc=$?
    if [ $rc -ne 0 ]; then echo "    ARM A FAILED (rc=$rc)"; fails=$((fails+1));
    else echo "    ok"; fi

    echo "=== ARM B: a WORKING-TREE edit must be caught (the case the index"
    echo "           hash was blind to, and the reason this file exists)"
    echo two >> "$R/f.c"
    check "$S/a" >/dev/null; rc=$?
    if [ $rc -ne 1 ]; then echo "    ARM B FAILED -- edit not seen (rc=$rc)"; fails=$((fails+1));
    else echo "    ok, caught"; fi

    echo "=== ARM C: a proven-blind instrument must NOT be what we ship"
    local i1 i2
    i1=$(git -C "$R" ls-files -s | sha1sum)
    git -C "$R" checkout -- f.c; echo three >> "$R/f.c"
    i2=$(git -C "$R" ls-files -s | sha1sum)
    if [ "$i1" != "$i2" ]; then
        echo "    ARM C INCONCLUSIVE -- index hash moved; premise not demonstrated"
    else
        echo "    ok: the index hash is identical across a real edit, as claimed"
    fi
    check "$S/a" >/dev/null; rc=$?
    if [ $rc -ne 1 ]; then echo "    ARM C FAILED -- we are blind too (rc=$rc)"; fails=$((fails+1));
    else echo "    ok: this instrument is not blind to it"; fi

    echo "=== ARM D: edit-then-revert must read UNCHANGED (no false alarm)"
    git -C "$R" checkout -- f.c
    check "$S/a" >/dev/null; rc=$?
    if [ $rc -ne 0 ]; then echo "    ARM D FAILED -- false alarm (rc=$rc)"; fails=$((fails+1));
    else echo "    ok"; fi

    echo "=== ARM E: a commit must be caught (HEAD is part of the digest)"
    echo four >> "$R/g.c"; git -C "$R" commit -qam next
    check "$S/a" >/dev/null; rc=$?
    if [ $rc -ne 1 ]; then echo "    ARM E FAILED (rc=$rc)"; fails=$((fails+1));
    else echo "    ok, caught"; fi

    echo "=== ARM F: a missing armed state must REFUSE, never pass"
    check "$S/does-not-exist" >/dev/null 2>&1; rc=$?
    if [ $rc -ne 2 ]; then echo "    ARM F FAILED -- rc=$rc, not the refusal 2"; fails=$((fails+1));
    else echo "    ok, refused"; fi

    echo
    if [ $fails -eq 0 ]; then
        echo "SELFTEST PASSED -- 6 arms: unchanged clean, working-tree edit caught,"
        echo "the index-hash blindness demonstrated and not shared, revert not a"
        echo "false alarm, commit caught, missing state refused."
        return 0
    fi
    echo "SELFTEST FAILED -- $fails arm(s)"; return 1
}

case "${1:-}" in
    arm)        shift; arm   "${1:?usage: tree_tripwire.sh arm <file>}" ;;
    check)      shift; check "${1:?usage: tree_tripwire.sh check <file>}" ;;
    --selftest) shift; selftest "$@" ;;
    *) echo "usage: tree_tripwire.sh {arm|check} <file> | --selftest [dir]" >&2; exit 2 ;;
esac
