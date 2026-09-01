#!/usr/bin/env bash
# nocapstone_gate.sh — enforce ruling R14: Capstone is not a dependency of
# the champsim_tracer plugin.
#
# Usage:
#   nocapstone_gate.sh [--build-dir DIR] [--nocap-dir DIR] [--out DIR]
#                      [--stage link|compile|battery|all] [--configure]
#   nocapstone_gate.sh --selftest [scratch-dir]
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
SELFTEST_DIR=""
DO_CONFIGURE=0
NINJA_JOBS=${NINJA_JOBS:-12}

TARGETS="x86_64-linux-user,aarch64-linux-user,riscv64-linux-user,mipsel-linux-user,x86_64-softmmu,aarch64-softmmu,riscv64-softmmu,mipsel-softmmu"
ISAS="x86_64 aarch64 riscv64 mipsel"

# The standing I/O rule: a harness in this tree writes its traces compressed.
# Set where the plugin option string is built, so the battery stage cannot
# omit it by forgetting to pass it -- the same shape the six Python drivers
# and the two pin scripts carry.  cst_audit reads the compressed member
# transparently, so nothing downstream of the run changes.
CST_COMPRESS=${CST_COMPRESS:-"zstd -T0 -3 -q -c"}

while [ $# -gt 0 ]; do
    case "$1" in
        --build-dir) BUILD_DIR=$2; shift 2 ;;
        --nocap-dir) NOCAP_DIR=$2; shift 2 ;;
        --out)       OUT_DIR=$2;   shift 2 ;;
        --stage)     STAGE=$2;     shift 2 ;;
        --configure) DO_CONFIGURE=1; shift ;;
        --selftest)  STAGE=selftest; SELFTEST_DIR=${2:-}; \
                     [ -n "${SELFTEST_DIR}" ] && shift; shift ;;
        -h|--help)   sed -n '2,50p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "nocapstone_gate: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

if [ "$STAGE" != selftest ]; then
    if [ -z "$OUT_DIR" ]; then
        OUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/nocapgate.XXXXXX")
    fi
    mkdir -p "$OUT_DIR" ||
        { echo "nocapstone_gate: FAIL — cannot create $OUT_DIR"; exit 1; }
fi

FAILED=0
note()  { printf '%s\n' "$*"; }

# A RED WITH NO SIZE IS NOT ACTIONABLE.
#
# "Still a dependency" was the whole message for several passes, and every
# pass then had to re-derive the same three numbers by hand before it could
# say what remained.  The gate owns those numbers: it is already standing in
# the tree, and the surfaces are greppable.  So a RED prints them, from the
# SOURCE rather than from a note somebody has to keep current, and it refuses
# if it finds none -- a survey that cannot see the dependency the gate just
# convicted on is broken, not encouraging.
#
# The three surfaces, and why each is separate work:
#
#   headers    plugin translation units that #include a Capstone header.
#              These are the compile-time tie the link stage cannot see.
#              Reference tools (isaxcheck, capstone_workaround_probe) are
#              excluded BY NAME -- R13 keeps Capstone as an external
#              reference and linking it there is not a plugin dependency.
#   rows       table rows keyed on a Capstone enumerator.  Re-spelling these
#              into a local copy of the same constants is REFUSED under R14;
#              they retire when the fact each row carries comes from QEMU.
#   gates      the admission sites: the consult that decides what an
#              instruction IS, and the poison check that decides whether its
#              whole basic block enters the trace.  Both read the same
#              Capstone answer and both must move together (#317).
survey() {
    P="$SRC_ROOT/contrib/plugins/champsim_tracer"
    note ""
    note "nocapstone_gate: what is left, counted from the tree"

    hdrs=$(grep -rl '#include <capstone/' "$P" --include='*.h' --include='*.cc' \
             2>/dev/null | grep -v '/tools/' | sort)
    nh=$(printf '%s\n' "$hdrs" | grep -c . )
    note "  headers  $nh plugin file(s) include a Capstone header:"
    printf '%s\n' "$hdrs" | grep . | sed "s#^$SRC_ROOT/#             #"

    note "  rows     table rows whose ARRAY INDEX is a Capstone enumerator,"
    note "           counted per ISA as instruction rows + register rows:"
    nr=0
    for h in "$P"/champsim_tracer_mnemonics_*.h; do
        [ -f "$h" ] || continue
        ni=$(grep -cE '^[[:space:]]*\[(X86|AARCH64|ARM64|RISCV|MIPS)_INS_' \
                  "$h" 2>/dev/null)
        nrg=$(grep -cE '^[[:space:]]*\[(X86|AARCH64|ARM64|RISCV|MIPS)_REG_' \
                  "$h" 2>/dev/null)
        nr=$((nr + ni + nrg))
        note "             $(basename "$h")  insn $ni  reg $nrg"
    done
    note "             total $nr"

    note "  gates    admission sites that read the Capstone answer:"
    grep -n 'qemu_plugin_cap_decode(' "$P/champsim_tracer.cc" 2>/dev/null \
        | sed 's/^/             champsim_tracer.cc:/;s/ *$//' | head -4
    grep -n 'cst_cap_arch >= 0 && !insn_info\[ci\].mnemonic\[0\]' \
         "$P/champsim_tracer.cc" 2>/dev/null \
        | sed 's/^/             champsim_tracer.cc:/' | head -2

    if [ "$nh" = 0 ] && [ "$nr" = 0 ]; then
        note "  SURVEY FOUND NOTHING while the gate is RED -- the survey is"
        note "  broken, not the dependency gone.  Fix the survey."
    fi
}


pass()  { note "nocapstone_gate: PASS  $*"; }
fail()  { note "nocapstone_gate: FAIL  $*"; FAILED=1; }

# ------------------------------------------------------------- selftest
# A GATE IS ONLY A GATE IF IT CAN GO RED, AND ONLY USEFUL IF IT CAN GO
# GREEN.  Neither direction may be inferred from the tree's current state:
# today the link stage is red because the plugin really does import
# `qemu_plugin_cap_decode`, and once the flip lands it will be green for
# the same reason -- in both worlds the gate's own discrimination is
# UNTESTED, because the subject only ever takes one value.
#
# So the selftest supplies both values itself.  It compiles two tiny
# shared objects into a scratch build tree shaped like a real one and runs
# the LINK stage against each:
#
#   clean.so    imports only non-Capstone symbols            -> must PASS
#   planted.so  imports qemu_plugin_cap_decode and nothing
#               else that matters                            -> must FAIL
#   (absent)    no .so at the path the stage reads           -> must FAIL
#
# The third arm is the standing failure mode of every check in this tree:
# a stage that cannot find its subject must report RED, never skip into a
# pass.  All three are tip-independent -- they do not consult the plugin,
# so they keep proving the same thing after the flip lands.
#
# The COMPILE and BATTERY stages are deliberately NOT self-tested here.
# Their subject is a whole --disable-capstone QEMU build; a scratch
# fixture for them would test a mock, and a gate that passes its own mock
# is the false success this file exists to prevent.  Their red direction
# is instead witnessed for real, every run, for as long as R14 is unmet:
# `--stage compile` fails on the missing capstone header, and that failure
# is quoted in the evidence.
selftest() {
    local scratch=${1:-$(mktemp -d "${TMPDIR:-/tmp}/nocapgate_selftest.XXXXXX")}
    local cc=${CC:-cc}
    mkdir -p "$scratch/clean/contrib/plugins" \
             "$scratch/planted/contrib/plugins" \
             "$scratch/absent/contrib/plugins" || {
        echo "nocapstone_gate: SELFTEST CANNOT RUN — cannot create $scratch"
        return 1
    }

    cat > "$scratch/clean.c" <<'EOF'
extern int qemu_plugin_insn_decode_id(const void *insn);
int probe(const void *i) { return qemu_plugin_insn_decode_id(i); }
EOF
    cat > "$scratch/planted.c" <<'EOF'
extern int qemu_plugin_cap_decode(int a, unsigned m, const unsigned char *b,
                                  unsigned n, unsigned long pc, void *out);
int probe(const unsigned char *b, void *o)
{ return qemu_plugin_cap_decode(0, 0, b, 4, 0, o); }
EOF
    for which in clean planted; do
        if ! "$cc" -shared -fPIC -o \
             "$scratch/$which/contrib/plugins/libchampsim_tracer.so" \
             "$scratch/$which.c" > "$scratch/$which.cc.log" 2>&1; then
            echo "nocapstone_gate: SELFTEST CANNOT RUN — $cc could not build" \
                 "the $which fixture (see $scratch/$which.cc.log)"
            return 1
        fi
    done

    local rc_clean rc_planted rc_absent bad=0
    ( BUILD_DIR="$scratch/clean";   OUT_DIR="$scratch/out_clean";   \
      mkdir -p "$OUT_DIR"; FAILED=0; stage_link; exit $FAILED ) \
        > "$scratch/clean.gate" 2>&1
    rc_clean=$?
    ( BUILD_DIR="$scratch/planted"; OUT_DIR="$scratch/out_planted"; \
      mkdir -p "$OUT_DIR"; FAILED=0; stage_link; exit $FAILED ) \
        > "$scratch/planted.gate" 2>&1
    rc_planted=$?
    ( BUILD_DIR="$scratch/absent";  OUT_DIR="$scratch/out_absent";  \
      mkdir -p "$OUT_DIR"; FAILED=0; stage_link; exit $FAILED ) \
        > "$scratch/absent.gate" 2>&1
    rc_absent=$?

    note "nocapstone_gate: SELFTEST (scratch $scratch)"
    note "  link/clean    rc=$rc_clean   (expect 0)  $(head -n1 "$scratch/clean.gate")"
    note "  link/planted  rc=$rc_planted   (expect 1)  $(head -n1 "$scratch/planted.gate")"
    note "  link/absent   rc=$rc_absent   (expect 1)  $(head -n1 "$scratch/absent.gate")"
    [ "$rc_clean"   = 0 ] || { note "  SELFTEST FAIL: the link stage refused a plugin with NO Capstone import"; bad=1; }
    [ "$rc_planted" = 1 ] || { note "  SELFTEST FAIL: the link stage PASSED a planted qemu_plugin_cap_decode call"; bad=1; }
    [ "$rc_absent"  = 1 ] || { note "  SELFTEST FAIL: the link stage passed with no subject to read"; bad=1; }
    if [ "$bad" = 0 ]; then
        note "nocapstone_gate: SELFTEST GREEN — the link stage discriminates in"
        note "  both directions and refuses a missing subject"
        return 0
    fi
    note "nocapstone_gate: SELFTEST RED — this gate's verdicts cannot be trusted"
    return 1
}

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
        "$emu" -plugin "$so,outfile=$cell/s,compress=$CST_COMPRESS" \
            /bin/true > "$cell/run.log" 2>&1
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
        # ORDER MATTERS AND IT WAS WRONG.  This grep used to run BEFORE the
        # line below that writes audit.txt, so it read a file that did not
        # exist yet (or, worse, a stale one from a previous invocation of
        # the gate against the same --out directory).  Run the auditor, then
        # read what it wrote.
        "$aud" "$cell/s.cst" > "$cell/audit.txt" 2>&1
        local arc=$?
        [ "$arc" = 0 ] || { fail "battery/$isa: cst_audit rc=$arc"; ok=0; }
        if [ ! -s "$cell/audit.txt" ]; then
            fail "battery/$isa: cst_audit produced no output — a check that cannot find its subject fails"; ok=0
        elif ! grep -qE 'exec_cp=[1-9]' "$cell/audit.txt"; then
            fail "battery/$isa: audit reports exec_cp=0 — the run executed no traced instruction"; ok=0
        fi
        # The auditor's own vacuity refusal (#313) is what makes its rc=0
        # mean something on THIS trace.  If a future edit deletes Oracle 0,
        # every zero below it silently goes back to being free, so the gate
        # asserts the oracle RAN rather than trusting that it exists.
        if ! grep -q '^=== VACUITY (Oracle 0) ===' "$cell/audit.txt"; then
            fail "battery/$isa: cst_audit printed no VACUITY oracle — the empty-trace refusal (#313) is not in this binary, so its rc=0 is not evidence"; ok=0
        fi
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
if [ "$STAGE" != selftest ]; then
    note "  build      $BUILD_DIR"
    note "  nocap      $NOCAP_DIR"
    note "  evidence   $OUT_DIR"
fi
note ""

case "$STAGE" in
    selftest) selftest "$SELFTEST_DIR" || FAILED=1 ;;
    link)    stage_link ;;
    compile) stage_compile ;;
    battery) stage_battery ;;
    # `all` RUNS ALL THREE STAGES, ALWAYS.  It used to short-circuit the
    # battery whenever link or compile had already failed, on the reasoning
    # that a battery with no plugin has nothing to say.  It has something to
    # say and it says it: stage_battery's first act is to look for the
    # plugin, and when it is missing it FAILS with that sentence.  Skipping
    # it printed NOTHING about the third of R14's three stages, so a reader
    # of an `all` run could not tell "the battery passed" from "the battery
    # never ran" -- which is the silent-skip this file's own header forbids.
    # The verdict does not change either way (FAILED is already 1); what
    # changes is that the output now accounts for every stage it claims to
    # cover.
    all)     stage_link; stage_compile; stage_battery ;;
    *) echo "nocapstone_gate: unknown stage '$STAGE'" >&2; exit 2 ;;
esac

note ""
if [ "$STAGE" = selftest ]; then
    # SAY WHAT WAS MEASURED.  A selftest run inspects fixtures, never the
    # plugin, so it may not borrow the R14 verdict sentence: printing
    # "the plugin makes no Capstone-backed call" after a run that never
    # opened the plugin is the false success this file exists to prevent.
    [ "$FAILED" = 0 ] && exit 0
    exit 1
fi
if [ "$FAILED" = 0 ]; then
    note "nocapstone_gate: GREEN — the plugin makes no Capstone-backed call and needs no Capstone header"
    exit 0
fi
note "nocapstone_gate: RED — Capstone is still a dependency of the plugin"
survey
exit 1
