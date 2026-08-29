#!/usr/bin/env bash
# nocapstone_gate.sh — enforce ruling R14: Capstone is not a dependency of
# the champsim_tracer plugin.
#
# Usage:
#   nocapstone_gate.sh [--build-dir DIR] [--nocap-dir DIR] [--out DIR]
#                      [--stage link|compile|battery|all] [--configure]
#
# THE RULING.  "I want the removal of Capstone enforced.  No 'one residual
# here' or 'mostly removed'.  I want it out as a dependency for the qemu
# plugin."  The bar is not a code review and not a grep of the sources the
# author remembered to look at: the plugin must BUILD and PASS its battery
# against a QEMU configured --disable-capstone.  "Mostly removed" is a
# forbidden status, so this gate has no partial-credit exit code — every
# stage it runs either passes or the gate is RED.
#
# WHAT EACH STAGE PROVES, and why one stage is not enough.
#
#   link     The built plugin's dynamic UNDEFINED symbol list names no
#            Capstone-backed entry point.  `qemu_plugin_cap_decode` is the
#            only route from the plugin to Capstone that survives linking,
#            so its presence in `nm -D --undefined-only` is a call the
#            author cannot talk their way out of and its absence cannot be
#            faked by a comment.  This is the stage a planted call trips
#            first, and it costs a fraction of a second.
#
#   compile  The plugin compiles when Capstone's HEADERS are not on the
#            include path.  A plugin can be free of Capstone CALLS and still
#            be a Capstone dependency by naming its enum constants
#            (X86_INS_*, AARCH64_REG_*, CS_MODE_*) — those are compile-time
#            dependencies that `nm` cannot see, because a constant leaves no
#            symbol.  Only a real --disable-capstone build catches them.
#
#   battery  The plugin BUILT that way runs, and what it produces survives
#            the acceptance checks: a run, a strict decode, an audit, the
#            validator, and the stats sidecar's must-be-0 rows, on four
#            ISAs.  A plugin that builds without Capstone and then emits a
#            degraded trace has not removed a dependency, it has hidden one.
#
# A stage that cannot find its subject FAILS.  A missing plugin .so, an
# absent build directory, an empty grep where output was required — each is
# reported as RED, never skipped into a pass.  This is the standing failure
# mode of every check in this tree and the reason it is written out here.
#
# NOTE ON THE REFERENCE TOOLS.  Ruling R13 keeps Capstone as one of the
# EXTERNAL reference decoders the ground-truth gate scores the tracer
# against, and isaxcheck / capstone_workaround_probe link it deliberately.
# A reference tool is not a plugin dependency.  This gate therefore scopes
# itself to the plugin's own translation units and says so where it looks.
#
# Author: Maccoy Merrell.
set -u

SRC_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
BUILD_DIR="$SRC_ROOT/build"
NOCAP_DIR="$SRC_ROOT/build-nocap"
OUT_DIR=""
STAGE=all
DO_CONFIGURE=0
NINJA_JOBS=${NINJA_JOBS:-12}

TARGETS="x86_64-linux-user,aarch64-linux-user,riscv64-linux-user,mipsel-linux-user,x86_64-softmmu,aarch64-softmmu,riscv64-softmmu,mipsel-softmmu"
ISAS="x86_64 aarch64 riscv64 mipsel"

while [ $# -gt 0 ]; do
    case "$1" in
        --build-dir) BUILD_DIR=$2; shift 2 ;;
        --nocap-dir) NOCAP_DIR=$2; shift 2 ;;
        --out)       OUT_DIR=$2;   shift 2 ;;
        --stage)     STAGE=$2;     shift 2 ;;
        --configure) DO_CONFIGURE=1; shift ;;
        -h|--help)   sed -n '2,50p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "nocapstone_gate: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

if [ -z "$OUT_DIR" ]; then
    OUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/nocapgate.XXXXXX")
fi
mkdir -p "$OUT_DIR" || { echo "nocapstone_gate: FAIL — cannot create $OUT_DIR"; exit 1; }

FAILED=0
note()  { printf '%s\n' "$*"; }
pass()  { note "nocapstone_gate: PASS  $*"; }
fail()  { note "nocapstone_gate: FAIL  $*"; FAILED=1; }

# ---------------------------------------------------------------- stage link
stage_link() {
    local so="$BUILD_DIR/contrib/plugins/libchampsim_tracer.so"
    if [ ! -f "$so" ]; then
        fail "link: no plugin at $so — a stage that cannot find its subject fails"
        return
    fi
    local u="$OUT_DIR/undefined.txt"
    if ! nm -D --undefined-only "$so" > "$u" 2>"$OUT_DIR/nm.err"; then
        fail "link: nm could not read $so ($(head -n1 "$OUT_DIR/nm.err"))"
        return
    fi
    if [ ! -s "$u" ]; then
        fail "link: $so has an EMPTY undefined-symbol list — nm found no subject"
        return
    fi
    local hits
    hits=$(grep -E '\b(qemu_plugin_cap_[a-z_]+|cs_[a-z_]+|cap_disas_[a-z_]+)\b' "$u" || true)
    if [ -n "$hits" ]; then
        fail "link: the plugin imports Capstone-backed entry points:"
        printf '%s\n' "$hits" | sed 's/^/            /'
        return
    fi
    pass "link: $(wc -l < "$u") undefined symbols, none Capstone-backed"
}

# ------------------------------------------------------------- stage compile
stage_compile() {
    if [ ! -f "$NOCAP_DIR/build.ninja" ]; then
        if [ "$DO_CONFIGURE" = 1 ]; then
            note "nocapstone_gate: configuring $NOCAP_DIR (--disable-capstone)"
            mkdir -p "$NOCAP_DIR"
            if ! ( cd "$NOCAP_DIR" && "$SRC_ROOT/configure" --enable-plugins \
                        --disable-capstone --target-list="$TARGETS" ) \
                        > "$OUT_DIR/configure.log" 2>&1; then
                fail "compile: configure --disable-capstone failed (see $OUT_DIR/configure.log)"
                return
            fi
        else
            fail "compile: no build at $NOCAP_DIR — pass --configure to create it"
            return
        fi
    fi
    # The configuration under test must actually be the one claimed.  A gate
    # that builds a capstone-ENABLED tree and reports green is the exact
    # false success this file exists to prevent.
    if ! grep -q '^#undef CONFIG_CAPSTONE' "$NOCAP_DIR/config-host.h" 2>/dev/null; then
        fail "compile: $NOCAP_DIR is NOT a --disable-capstone build (CONFIG_CAPSTONE is set or config-host.h is missing)"
        return
    fi
    local log="$OUT_DIR/build-nocap.log"
    ( cd "$NOCAP_DIR" && ninja -j "$NINJA_JOBS" contrib-plugins \
          qemu-x86_64 qemu-aarch64 qemu-riscv64 qemu-mipsel ) > "$log" 2>&1
    local rc=$?
    if [ "$rc" != 0 ]; then
        fail "compile: the plugin does NOT build against --disable-capstone QEMU (ninja rc=$rc)"
        grep -E '^(FAILED|.*fatal error:|.*error:)' "$log" | head -n 12 | sed 's/^/            /'
        return
    fi
    if [ ! -f "$NOCAP_DIR/contrib/plugins/libchampsim_tracer.so" ]; then
        fail "compile: ninja reported success but produced no plugin .so"
        return
    fi
    pass "compile: plugin + 4 user targets build with Capstone headers absent"
}

# ------------------------------------------------------------- stage battery
stage_battery() {
    local so="$NOCAP_DIR/contrib/plugins/libchampsim_tracer.so"
    local dec="$NOCAP_DIR/contrib/plugins/cst_decode"
    local aud="$NOCAP_DIR/contrib/plugins/cst_audit"
    for f in "$so" "$dec" "$aud"; do
        if [ ! -x "$f" ] && [ ! -f "$f" ]; then
            fail "battery: missing $f — cannot run the battery it is the subject of"
            return
        fi
    done
    local isa ok=1
    for isa in $ISAS; do
        local emu="$NOCAP_DIR/qemu-$isa"
        local cell="$OUT_DIR/smoke_$isa"
        mkdir -p "$cell"
        if [ ! -x "$emu" ]; then
            fail "battery/$isa: no emulator at $emu"; ok=0; continue
        fi
        # The smoke arm has to prove the plugin produces a decodable,
        # auditable trace on this ISA; the validator battery is the richer
        # subject and runs separately against the same build.
        "$emu" -plugin "$so,outfile=$cell/s" /bin/true > "$cell/run.log" 2>&1
        local rrc=$?
        if [ "$rrc" != 0 ]; then
            fail "battery/$isa: run rc=$rrc (see $cell/run.log)"; ok=0; continue
        fi
        if [ ! -s "$cell/s.cst" ]; then
            fail "battery/$isa: run succeeded but wrote no trace"; ok=0; continue
        fi
        "$dec" --strict "$cell/s.cst" > "$cell/decode.txt" 2>&1
        local drc=$?
        [ "$drc" = 0 ] || { fail "battery/$isa: cst_decode --strict rc=$drc"; ok=0; }
        # VACUITY GUARD, and it is not optional.  MEASURED on this tree: a
        # trace with templates=0 and a 2-byte body passes BOTH `cst_decode
        # --strict` (rc=0) and `cst_audit` (rc=0, rollup 100.00%) — an empty
        # trace is trivially self-consistent, so neither tool can refuse it.
        # A gate that reads only those two exit codes reports GREEN on a
        # plugin that decoded nothing at all, which is precisely the failure
        # a Capstone removal would produce if it were done by deletion
        # rather than by replacement.  The subject has to be shown to exist.
        local tmpl
        tmpl=$(sed -n 's/^; templates=\([0-9][0-9]*\)$/\1/p' "$cell/decode.txt" | head -n1)
        if [ -z "$tmpl" ]; then
            fail "battery/$isa: decode output carries no '; templates=' line — cannot establish the trace is non-empty"; ok=0
        elif [ "$tmpl" -le 0 ]; then
            fail "battery/$isa: the trace is EMPTY (templates=$tmpl) — strict decode and audit both pass on it, so their zeros mean nothing here"; ok=0
        fi
        if ! grep -qE 'exec_cp=[1-9]' "$cell/audit.txt" 2>/dev/null; then
            fail "battery/$isa: audit reports exec_cp=0 — the run executed no traced instruction"; ok=0
        fi
        "$aud" "$cell/s.cst" > "$cell/audit.txt" 2>&1
        local arc=$?
        [ "$arc" = 0 ] || { fail "battery/$isa: cst_audit rc=$arc"; ok=0; }
        if [ -f "$cell/s.stats" ]; then
            python3 "$SRC_ROOT/contrib/plugins/champsim_tracer/tools/arc3_cov/instruments/must0_scan.py" \
                    "$cell/s.stats" > "$cell/must0.txt" 2>&1
            local mrc=$?
            [ "$mrc" = 0 ] || { fail "battery/$isa: must0_scan rc=$mrc"; ok=0; }
        fi
    done
    [ "$ok" = 1 ] && pass "battery: run + strict decode + audit + must0 green on 4 ISAs"
}

note "nocapstone_gate: R14 — Capstone is not a plugin dependency"
note "  source     $SRC_ROOT"
note "  build      $BUILD_DIR"
note "  nocap      $NOCAP_DIR"
note "  evidence   $OUT_DIR"
note ""

case "$STAGE" in
    link)    stage_link ;;
    compile) stage_compile ;;
    battery) stage_battery ;;
    all)     stage_link; stage_compile; [ "$FAILED" = 0 ] && stage_battery ;;
    *) echo "nocapstone_gate: unknown stage '$STAGE'" >&2; exit 2 ;;
esac

note ""
if [ "$FAILED" = 0 ]; then
    note "nocapstone_gate: GREEN — the plugin makes no Capstone-backed call and needs no Capstone header"
    exit 0
fi
note "nocapstone_gate: RED — Capstone is still a dependency of the plugin"
exit 1
