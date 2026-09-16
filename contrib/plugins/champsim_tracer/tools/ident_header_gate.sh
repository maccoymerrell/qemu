#!/bin/bash
# IS THE SHIPPED IDENTITY HEADER THE ONE THIS TREE GENERATES?  ALL FOUR ISAs.
#
# WHY THIS FILE EXISTS, AND IT IS NOT THAT THE DETECTOR WAS MISSING.  92-A's
# remedy -- the shipped-vs-generated comparison at the end of the
# `--qemu-ident --diff` census -- WORKS.  Run by hand at 290215f0d8 it prints
#
#     SHIPPED HEADER IS STALE -- .../champsim_tracer_qemu_ident_x86.h is not
#     what this tree generates.
#         @@ -1778 +1778 @@
#         -    { 0x00000b5fu, "HLT", QID_STATED, false,
#         +    { 0x00000b68u, "HLT", QID_STATED, false,
#
# and exits non-zero.  What was missing is a CALLER.  Nothing in battery15,
# in the R13 manifest or in any pass's own runner ran `--qemu-ident --diff`,
# so the one check that can see a stale generated file was, for every pass
# since it landed, a check nobody took.  A detector that is never run is not
# a weaker detector than one that is blind -- it is the same thing -- and the
# lesson is the one barscore.sh's own header states: a step added to a run
# directory is a step the next pass does not have.  So the caller lives here,
# beside the instruments, and battery15.sh runs it.
#
# WHAT A STALE HEADER COSTS.  The plugin links the header committed beside
# it, not the rows the generator derives at census time, so every number a
# census prints describes a table that is not in the binary.  That is how
# 92-A shipped a table missing INVPCID and HLT while the census reported
# "NO ROW ... 0 BY CONSTRUCTION", and how ~6,000 x86 encodings reached the
# wire with no published source list at all.
#
# Usage:
#   ident_header_gate.sh BUILD_DIR [OUTDIR]
#   ident_header_gate.sh --selftest [TMPDIR]
#
# EXIT STATUS IS THE RESULT, not the last echo.
#
# Author: Maccoy Merrell.
set -u
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
PLUGIN_DIR=$(cd "$HERE/.." && pwd)
GEN=$PLUGIN_DIR/champsim_tracer_mnemonic_audit.py
PY="${CST_PYTHON:-${PYTHON:-python}}"

#: The generator's own ISA keys, which are NOT the emulator names: the
#: header files are champsim_tracer_qemu_ident_{aarch64,mips,riscv,x86}.h.
KEYS="aarch64 mips riscv x86"

#: The line the census prints when the file on disk IS what the tree makes.
#: The gate asserts this line is PRESENT rather than asserting the stale line
#: is absent, because a run that died before reaching the comparison also has
#: no stale line in it -- a check that cannot find its subject must fail.
OKLINE='SHIPPED HEADER: byte-identical'

# ---------------------------------------------------------------- one ISA
#
# Echoes one row.  Returns non-zero on stale, missing, or unreached.
check_one() {
    local build=$1 out=$2 key=$3 log rc
    log=$out/ident_$key.log
    "$PY" "$GEN" --qemu-ident --diff --isa "$key" --build-dir "$build" \
        > "$log" 2>&1
    rc=$?
    if grep -qF "$OKLINE" "$log"; then
        echo "row $key rc=0   shipped header byte-identical to the generator"
        return 0
    fi
    if grep -q 'SHIPPED HEADER IS STALE' "$log"; then
        echo "row $key rc=1   SHIPPED HEADER IS STALE -- see $log"
        sed -n '/SHIPPED HEADER IS STALE/,/^[A-Z]/p' "$log" | head -12 \
            | sed 's/^/       /'
        return 1
    fi
    if grep -q 'SHIPPED HEADER: .* DOES NOT EXIST' "$log"; then
        echo "row $key rc=1   SHIPPED HEADER DOES NOT EXIST -- see $log"
        return 1
    fi
    echo "row $key rc=1   REFUSED -- the census never reached its shipped-header" \
         "comparison (generator rc=$rc); a check that cannot find its subject" \
         "is not a check.  See $log"
    return 1
}

# RETURNS, NEVER EXITS.  The selftest calls this five times in one shell; an
# `exit` in the refusal arm would kill the selftest at its FIRST arm and leave
# it reporting nothing at all -- which is exactly what the first draft did, and
# what the caller then read as a status from `tail`.
cmd_gate() {
    local build=${1:?BUILD_DIR} out=${2:-}
    [ -d "$build" ] || { echo "ident_header_gate: no build dir $build"; return 2; }
    [ -f "$GEN" ] || { echo "ident_header_gate: no generator at $GEN"; return 2; }
    out=${out:-$(mktemp -d)}
    mkdir -p "$out" || return 2
    local bad=0 key
    echo "ident_header_gate  build=$build  out=$out"
    echo "TIP=$(git -C "$PLUGIN_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
    for key in $KEYS; do
        check_one "$build" "$out" "$key" || bad=1
    done
    if [ "$bad" = 0 ]; then
        echo "IDENT HEADER GATE: PASS -- all 4 shipped headers are what this tree generates"
        return 0
    fi
    echo "IDENT HEADER GATE: RED -- a shipped identity header is not the one this" \
         "tree generates.  The plugin uses the SHIPPED rows, so every identity" \
         "number measured against this build describes a table that is not in" \
         "the binary.  Re-emit with --qemu-ident --apply."
    return 1
}

# --------------------------------------------------------------- selftest
#
# THE PLANT IS ON THE REAL FILE AND IS RESTORED BY CONTENT.  There is no
# second copy of the tree to plant into: the generator resolves PLUGIN_DIR
# from its own location, so a gate that cannot be made to fire on the real
# header cannot be proven at all.  The original bytes are saved, the plant is
# applied, the arm is scored, and the file is restored FROM THE SAVED BYTES
# and then re-hashed -- a restore that does not reproduce the original sha
# is itself a failure, loudly.
selftest() {
    local T=${1:-$(mktemp -d)}
    mkdir -p "$T" || exit 2
    local fails=0 checks=0
    local hdr=$PLUGIN_DIR/champsim_tracer_qemu_ident_x86.h
    local save=$T/x86.h.orig before after
    local build=${CST_IDENT_BUILD:-/mnt/md0/QEMU/qemu/build}

    ck() {  # ck NAME EXPECT_RC ACTUAL_RC
        checks=$((checks + 1))
        if [ "$2" = "$3" ]; then echo "  ok   $1 (rc=$3)"
        else echo "  FAIL $1 (rc=$3, wanted $2)"; fails=$((fails + 1)); fi
    }

    [ -f "$hdr" ] || { echo "selftest: no $hdr"; exit 2; }
    cp "$hdr" "$save" || exit 2
    before=$(sha256sum "$hdr" | cut -d' ' -f1)

    # ARM 1 -- a build directory that does not exist must REFUSE, not pass.
    cmd_gate "$T/no-such-build" > "$T/a1.log" 2>&1
    ck "missing build dir REFUSES" 2 $?

    # ARM 2 -- the clean tree.  This is the arm that can only be green if the
    # gate is actually looking; it is scored before the plant so a plant that
    # fails to restore cannot make it look green afterwards.
    cmd_gate "$build" "$T/o2" > "$T/a2.log" 2>&1
    ck "clean tree PASSES" 0 $?
    grep -qF "$OKLINE" "$T/o2/ident_x86.log" \
        && ck "clean x86 row names the byte-identical line" 0 0 \
        || ck "clean x86 row names the byte-identical line" 0 1

    # ARM 3 -- PLANT: one shipped row's identity changed by one digit.  This
    # is exactly the 92-A shape and exactly the shape found at 290215f0d8.
    "$PY" - "$hdr" <<'EOF'
import re, sys
p = sys.argv[1]
t = open(p).read()
m = re.search(r'\{ 0x([0-9a-f]{8})u, "', t)
assert m, "no identity row found to plant into"
old = m.group(0)
new = old.replace(m.group(1), "%08x" % (int(m.group(1), 16) ^ 1))
open(p, "w").write(t.replace(old, new, 1))
EOF
    ck "plant applied" 0 $?
    cmd_gate "$build" "$T/o3" > "$T/a3.log" 2>&1
    ck "PLANTED stale header is RED" 1 $?
    grep -q 'SHIPPED HEADER IS STALE' "$T/a3.log" \
        && ck "planted arm names staleness" 0 0 \
        || ck "planted arm names staleness" 0 1
    grep -q '^row x86 rc=1' "$T/a3.log" \
        && ck "planted arm names the ISA" 0 0 \
        || ck "planted arm names the ISA" 0 1

    # ARM 4 -- MISSING header must be RED and must say so, not read as clean.
    mv "$hdr" "$T/x86.h.away" || exit 2
    cmd_gate "$build" "$T/o4" > "$T/a4.log" 2>&1
    ck "MISSING header is RED" 1 $?
    grep -q 'DOES NOT EXIST' "$T/a4.log" \
        && ck "missing arm names the absent file" 0 0 \
        || ck "missing arm names the absent file" 0 1

    # RESTORE BY CONTENT, then prove the restore.
    cp "$save" "$hdr" || exit 2
    after=$(sha256sum "$hdr" | cut -d' ' -f1)
    [ "$before" = "$after" ] \
        && ck "restore reproduces the original sha" 0 0 \
        || ck "restore reproduces the original sha" 0 1

    # ARM 5 -- and the restored tree is green again, which is what says the
    # planted RED was the plant and not a pre-existing state.
    cmd_gate "$build" "$T/o5" > "$T/a5.log" 2>&1
    ck "restored tree PASSES again" 0 $?

    echo "ident_header_gate selftest: $checks check(s), $fails failure(s)"
    [ "$fails" = 0 ] || return 1
    return 0
}

case "${1:-}" in
    --selftest) shift; selftest "$@"; exit $? ;;
    "") echo "usage: ident_header_gate.sh BUILD_DIR [OUTDIR] | --selftest [TMPDIR]"; exit 2 ;;
    *)  cmd_gate "$@"; exit $? ;;
esac
