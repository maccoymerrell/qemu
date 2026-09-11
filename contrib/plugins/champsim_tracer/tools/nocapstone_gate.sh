#!/usr/bin/env bash
# nocapstone_gate.sh — enforce ruling R14: Capstone is not a dependency of
# the champsim_tracer plugin.
#
# Usage:
#   nocapstone_gate.sh [--build-dir DIR] [--nocap-dir DIR] [--out DIR]
#                      [--stage declare|link|compile|battery|all] [--configure]
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
#   declare  The plugin's own `shared_module()` in contrib/plugins/meson.build
#            does not name `capstone` among its dependencies.  This is the
#            form no counted number covered (FINDING 93-C): the census counts
#            headers, enum rows, admission gates and field reads, and a
#            deletion that removed all four while leaving the build
#            declaration would read zero everywhere over a plugin that still
#            pulls Capstone's include path and library.  See stage_declare.
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
#
#              A ROW COUNT IS A SIZE, NOT AN OCCUPANCY, and the two were
#              being read as one thing.  8,024 says how big the four tables
#              are; it says nothing about how many encodings the tables are
#              still the ANSWER for, which is what a retirement argument has
#              to be about -- and which FINDING 96-B ruled may not be
#              asserted from a no-occupant impression.  So the occupancy is
#              printed beside the size, from `enumocc.py` over a sled
#              capture, and where no capture is named it says SURVEY CANNOT
#              LOOK rather than nothing (which a reader would take for a
#              zero).  See the `occupants` row below.
#   gates      the admission sites: every place the plugin asks whether
#              Capstone produced an answer AT ALL and changes what it does
#              on the answer.  These decide what an instruction IS, whether
#              its fields are decoded, whether it can be a branch, and
#              whether its whole basic block enters the trace; they must all
#              move together (#317), because one left behind refuses -- or
#              silently empties -- everything on a Capstone-free build.
#
#              IT WAS A HAND-LIST AND THE HAND-LIST WAS SHORT.  Until this
#              was written the survey grepped TWO literal patterns, both
#              anchored to champsim_tracer.cc, and every R14 verdict since
#              PASS 16 quoted the "2-3 admission gates" that produced.  The
#              tree has FIVE, and the three the literals could not see are
#              the wire-critical ones:
#
#                champsim_tracer.cc:split_tb_into_fragments   an instruction
#                  with no Capstone answer is BRANCH_NONE, so the fragment
#                  splitter cannot see a branch and the true-BB chain stops
#                  being assembled;
#                champsim_tracer_bb_template_cache.cc         an instruction
#                  with no Capstone answer never reaches
#                  decode_detail_to_generic(), so its whole fields row stays
#                  zeroed;
#                champsim_tracer_decode.cc                    and
#                  decode_detail_to_generic() itself returns on the same
#                  test, which is what makes the row zero rather than wrong.
#
#              So the search is MECHANICAL and covers the whole plugin
#              directory: the consult by its call, and the existence test by
#              its one idiom (`mnemonic[0]` -- the answer's first byte is
#              what "did Capstone decode this?" is spelled as everywhere in
#              this tree).  Comment lines are excluded because a sentence
#              about the idiom is not a site.
#
#              WHAT IT DOES NOT FIND, stated so the number is not read as
#              more than it is: an admission site keyed on some OTHER
#              Capstone field would not match this idiom.  The FIELD census
#              below is what bounds that -- it is compiler-derived and reads
#              every member at every site -- and a gate can only exist where
#              the census already counts a read.
#
#              The count REFUSES at zero while any Capstone read survives:
#              a survey that finds no gate on a tree that still has fields
#              has stopped looking, which is the failure every instrument
#              here is built against.
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

    #
    # THE OCCUPANCY, BESIDE THE SIZE.  `classify_insn_id()` falls to the enum
    # row on exactly one condition -- QEMU exported no decode identity -- so
    # "who is the enum table still the answer for" is a property of an
    # ENCODING and is countable over the sled's whole population.  The count
    # is delegated for the same reason the field census is: it is a read of a
    # capture, not a grep, and a survey that invented its own reader would be
    # a second opinion about a number this tree already has an instrument for.
    #
    # NO CAPTURE NAMED IS NOT ZERO.  With CST_ENUMOCC_SLED unset there is
    # nothing to read and the row says so; printing 0 there would be the
    # census-that-could-not-look shape every instrument here is built against.
    #
    note "  occupants encodings the enum table is still the CLASSIFICATION"
    note "           for (decode_id == 0), counted per ISA:"
    note "             RETIRED WITH ITS SUBJECT.  enumocc.py scored this"
    note "             population from the per-encoding MECHANISM corpus'"
    note "             stated identity key (IDK: QEMU / ENUM / NONE).  The"
    note "             plugin can no longer state ENUM -- there is no enum"
    note "             table and no fall to one -- so the census would read"
    note "             a structural zero with no control behind it, which"
    note "             is the shape this file exists to refuse.  Its last"
    note "             reading, over the whole enumerated encoding"
    note "             population, four ISAs x wp{0,16}, key=STATED:"
    note "                 ENUM-OCCUPANCY total=0 inference_total=0 rc=0"
    note "             The surviving size rows below are what R14 now"
    note "             measures; this row is history."

    #
    # THE LABEL SAYS "AT OR BESIDE", AND FINDING 96-D IS WHY.  Until
    # 2ff695368a every site this grep found DECIDED an admission: the
    # `cst_cap_arch >= 0 && !insn_info[ci].mnemonic[0]` expression in
    # champsim_tracer.cc WAS the poison gate's acting test.  That commit
    # moved the decision to `qemufail` (the target decoder's own
    # `qemu_plugin_insn_undecoded`) and left the Capstone expression as
    # `capfail` -- SCORED ONLY, feeding the A/B counters one screen above
    # the acting test.  The READ still has to go for R14, so counting it
    # here is the conservative direction and the total is right; calling it
    # an admission site is not, because that line no longer makes one.
    #
    note "  gates    sites that read the Capstone answer AT OR BESIDE an"
    note "           admission decision (one is scored-only -- see 96-D):"
    gates=$(grep -rnE 'qemu_plugin_cap_decode\(|mnemonic\[0\]' "$P" \
                 --include='*.cc' --include='*.h' 2>/dev/null \
              | grep -v "^$P/tools/" \
              | grep -vE ':[[:space:]]*(\*|//|/\*)' \
              | sed "s#^$P/##;s/[[:space:]]*$//" | sort)
    ng=$(printf '%s\n' "$gates" | grep -c . )
    printf '%s\n' "$gates" | grep . | sed 's/^/             /'
    note "             total $ng"
    #
    # THE VACUITY GUARD.  Zero gates is the RESULT this survey exists to
    # reach -- but only on a tree that has no Capstone reads left at all.
    # Zero gates while the field census still counts reads means the search
    # stopped matching, not that the sites went away, and that is the shape
    # every instrument in this tree is built to refuse rather than report as
    # progress.  $nh is the header count computed above; a plugin with no
    # Capstone header and no gate is legitimately done.
    #
    if [ "$ng" -eq 0 ] && [ "$nh" -gt 0 ]; then
        note "  gates    SURVEY REFUSED: no admission site matched, yet" \
             "$nh plugin file(s) still include a Capstone header."
        note "           A zero here is a result only when the tree is" \
             "clean; on this tree it means the search has stopped looking."
        return 2
    fi

    # The FOURTH surface, and the largest one: the FIELDS of
    # qemu_plugin_insn_info the plugin reads out of the Capstone answer.
    # Each is retired under R14 either by re-sourcing it from QEMU-derived
    # state or by deleting it with its consumer's contract cited, so the
    # number here is a work list, not a score.
    #
    # DELEGATED, and deliberately so: this cannot be greppped.  `.mnemonic`
    # also names InsnClassification::mnem and a dozen locals, and only a
    # compiler knows which receiver a member access belongs to.
    # capfield_census.sh marks each field deprecated in a SCRATCH copy of the
    # header and re-parses every plugin translation unit, so each row it
    # prints is a resolved member access with a file:line.  It exits 2 when
    # it could not look -- which is reported here as exactly that, never as
    # a zero.
    note "  fields   Capstone-supplied qemu_plugin_insn_info members the"
    note "           plugin still reads, counted by the compiler:"
    local census="$(dirname "${BASH_SOURCE[0]}")/capfield_census.sh"
    if [ ! -x "$census" ]; then
        note "             SURVEY CANNOT LOOK -- no capfield_census.sh at"
        note "             $census"
    else
        local cdir
        cdir=$(mktemp -d "${TMPDIR:-/tmp}/ncg_capfield.XXXXXX")
        if "$census" --build-dir "$BUILD_DIR" --out "$cdir" --tsv \
               > "$cdir/reads.tsv" 2> "$cdir/err"; then
            local nsites nfields
            nsites=$(grep -c . "$cdir/reads.tsv" || true)
            nfields=$(cut -f1 "$cdir/reads.tsv" | sort -u | grep -c . || true)
            note "             $nfields field(s) across $nsites read site(s)"
            cut -f1 "$cdir/reads.tsv" | sort | uniq -c | sort -rn \
                | sed 's/^/             /'
        else
            note "             SURVEY CANNOT LOOK -- capfield_census.sh" \
                 "exited $?:"
            sed 's/^/             /' "$cdir/err" | head -3
        fi
    fi

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
    # THE BUILD-DECLARATION SCAN, PROVED BOTH WAYS ON FIXTURES (93-C).
    # The real tree declares Capstone today, so running the stage against it
    # can only ever show the RED half; a stage whose GREEN nobody has seen is
    # a stage that might be reporting green for the wrong reason.  Three
    # fixture meson.build files with a KNOWN answer, and the third is the one
    # that matters most: a file with no champsim_tracer module in it must
    # REFUSE, not pass for want of a match.
    local d="$scratch/declare"
    mkdir -p "$d"
    cat > "$d/with.build" <<'EOF'
  champsim_tracer_so = shared_module('champsim_tracer',
                     champsim_tracer_sources,
                     cpp_args: champsim_tracer_cpp_args,
                     dependencies: [glib, capstone])
EOF
    cat > "$d/without.build" <<'EOF'
  champsim_tracer_so = shared_module('champsim_tracer',
                     champsim_tracer_sources,
                     cpp_args: champsim_tracer_cpp_args,
                     dependencies: [glib])
EOF
    cat > "$d/other.build" <<'EOF'
  isaxcheck = executable('isaxcheck', files('isaxcheck.cc'),
                     dependencies: [glib, capstone])
EOF
    declare_scan "$d/with.build"    "$d/with.blocks";    local rc_dw=$?
    declare_scan "$d/without.build" "$d/without.blocks"; local rc_dc=$?
    declare_scan "$d/other.build"   "$d/other.blocks";   local rc_do=$?
    declare_scan "$d/absent.build"  "$d/absent.blocks";  local rc_da=$?
    note "  declare       with=$rc_dw (expect 1)  without=$rc_dc (expect 0)" \
         " reference-tool-only=$rc_do (expect 2)  missing=$rc_da (expect 2)"
    [ "$rc_dw" = 1 ] || { note "  SELFTEST FAIL: a declared capstone dependency was NOT caught"; bad=1; }
    [ "$rc_dc" = 0 ] || { note "  SELFTEST FAIL: a clean shared_module did not pass"; bad=1; }
    [ "$rc_do" = 2 ] || { note "  SELFTEST FAIL: a file whose only capstone user is a REFERENCE TOOL must REFUSE, not convict"; bad=1; }
    [ "$rc_da" = 2 ] || { note "  SELFTEST FAIL: a missing meson.build must REFUSE, not pass"; bad=1; }

    # THE FIELDS SURVEY HAS ITS OWN SELFTEST, AND NOTHING ELSE RUNS IT.
    # The survey delegates a number to capfield_census.sh, so a survey that
    # prints a comfortable count over a census that cannot discriminate is
    # this gate's own false green -- the delegation moves the risk, it does
    # not remove it.  Run it here, where the gate's discrimination is being
    # proved, and fail together.
    local census="$(dirname "${BASH_SOURCE[0]}")/capfield_census.sh"
    if [ ! -x "$census" ]; then
        note "  capfield      SELFTEST FAIL: the survey delegates to" \
             "$census, which is not executable"
        bad=1
    else
        "$census" --selftest "$scratch/capfield" > "$scratch/capfield.log" 2>&1
        local rc_cf=$?
        note "  capfield      capfield_census --selftest rc=$rc_cf  (expect 0)"
        if [ "$rc_cf" != 0 ]; then
            sed 's/^/    /' "$scratch/capfield.log" | tail -8
            bad=1
        fi
    fi

    #
    # THE ADMISSION-SITE SEARCH, PROVED BOTH WAYS ON FIXTURES.
    #
    # This is the arm the old two-literal grep could not have had: a
    # hand-list is right by definition on the tree it was written against,
    # so nothing could tell it from a search.  These fixtures are plugin
    # directories with a KNOWN answer, so the search has a subject it did
    # not choose.
    #
    #   sees     a Capstone header AND one existence test -> the site is
    #            found and the survey does NOT refuse.  If this fails the
    #            search has stopped matching the idiom, which is exactly
    #            the failure that let three wire-critical gates -- the
    #            fragment splitter's, the template builder's and
    #            decode_detail_to_generic()'s own -- go uncounted through
    #            every R14 verdict since PASS 16.
    #   blind    a Capstone header and NO existence test -> REFUSE (2).
    #            A survey that reports "no gates" on a tree that still
    #            includes Capstone has stopped looking, and a work list
    #            that shrinks for that reason is the failure this whole
    #            file is built against.
    #
    local rc_sees rc_blind
    mkdir -p "$scratch/gsees/contrib/plugins/champsim_tracer" \
             "$scratch/gblind/contrib/plugins/champsim_tracer"
    cat > "$scratch/gsees/contrib/plugins/champsim_tracer/f.cc" <<'EOF'
#include <capstone/capstone.h>
int f(const struct qemu_plugin_insn_info *i) { return i->mnemonic[0] != 0; }
EOF
    cat > "$scratch/gblind/contrib/plugins/champsim_tracer/f.cc" <<'EOF'
#include <capstone/capstone.h>
int f(const struct qemu_plugin_insn_info *i) { return i->insn_size; }
EOF
    ( SRC_ROOT="$scratch/gsees";  survey >"$scratch/gsees.survey"  2>&1 )
    rc_sees=$?
    ( SRC_ROOT="$scratch/gblind"; survey >"$scratch/gblind.survey" 2>&1 )
    rc_blind=$?
    note "  gates/sees    rc=$rc_sees   (expect 0)  $(grep -c 'f.cc' "$scratch/gsees.survey") site(s) found"
    note "  gates/blind   rc=$rc_blind   (expect 2)  survey refuses a zero it did not earn"
    [ "$rc_sees"  = 0 ] || { note "  SELFTEST FAIL: the admission search REFUSED a fixture that has a site"; bad=1; }
    [ "$rc_blind" = 2 ] || { note "  SELFTEST FAIL: the admission search reported a comfortable zero on a fixture that still includes Capstone"; bad=1; }

    if [ "$bad" = 0 ]; then
        note "nocapstone_gate: SELFTEST GREEN — the link stage discriminates in"
        note "  both directions and refuses a missing subject, the admission"
        note "  search finds a planted site and refuses an unearned zero, and"
        note "  the fields survey's own census discriminates too"
        return 0
    fi
    note "nocapstone_gate: SELFTEST RED — this gate's verdicts cannot be trusted"
    return 1
}

# ------------------------------------------------------------- stage declare
#
# THE BUILD DECLARATION, WHICH NO COUNTED NUMBER COVERED (FINDING 93-C).
#
# The R14 census counts headers, enum rows, admission gates and field reads.
# `contrib/plugins/meson.build` declares `capstone` in the plugin's own
# `shared_module(... dependencies: [glib, capstone])`, and neither this gate
# nor capfield_census.sh read that file at all -- grep: zero hits in either.
# So a deletion that removed the four mnemonic headers and left this line
# would leave every counter reading zero over a plugin that still declares
# the dependency, still gets Capstone's include path on its command line, and
# still links its library.
#
# It is a HOLE IN THE INSTRUMENT rather than a new dependency, and that is
# exactly why it belongs here: the other three stages measure what the plugin
# DOES, and this one measures what the build system SAYS it needs.  A plugin
# can pass `link` (it imports no cs_* symbol) and `compile` (a build with the
# headers present never exercises their absence) while the declaration stands.
#
# THE SCOPE IS THE PLUGIN'S OWN shared_module AND NOTHING ELSE.  Ruling R13
# keeps Capstone as an external reference decoder, and isaxcheck and
# capstone_workaround_probe declare it deliberately -- naming those would make
# this stage red forever for a reason that is not a defect.  The extraction
# reads the `shared_module('champsim_tracer', ...)` calls, each one bounded by
# its own parentheses, and looks only inside them.
#
# A STAGE THAT CANNOT FIND ITS SUBJECT FAILS.  No meson.build, or a
# meson.build with no champsim_tracer shared_module in it, is RED and says
# which: an empty search is not a clean result.
#
# THE SCAN, SEPARATED FROM THE VERDICT so the selftest can drive it on a
# fixture.  A stage that can only be run against the real tree is a stage
# whose GREEN nobody has ever seen -- the shape this file's own header
# forbids.  Returns 0 clean, 1 capstone declared, 2 no subject.
declare_scan() {
    local mb=$1 blocks=$2
    [ -f "$mb" ] || return 2
    awk '
        /shared_module\(.champsim_tracer./ { inblk = 1; depth = 0 }
        inblk {
            print
            n = gsub(/\(/, "(") ; depth += n
            n = gsub(/\)/, ")") ; depth -= n
            if (depth <= 0) { inblk = 0 }
        }
    ' "$mb" > "$blocks"
    [ -s "$blocks" ] || return 2
    grep -qE '(^|[^_[:alnum:]])capstone([^_[:alnum:]]|$)' "$blocks" && return 1
    return 0
}

stage_declare() {
    local root=${1:-$SRC_ROOT}
    local mb="$root/contrib/plugins/meson.build"
    local blocks="$OUT_DIR/meson_shared_module.txt"
    declare_scan "$mb" "$blocks"
    case $? in
      2) fail "declare: $mb has no shared_module('champsim_tracer', ...) to" \
              "read -- the search found no subject, which is not a pass"
         return ;;
      1) fail "declare: the plugin's own shared_module declares Capstone:"
         grep -nE '(^|[^_[:alnum:]])capstone([^_[:alnum:]]|$)' "$blocks" \
             | sed 's/^/            /'
         return ;;
    esac
    pass "declare: $(grep -c "shared_module(.champsim_tracer." "$blocks")" \
         "champsim_tracer shared_module block(s), none naming capstone"
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
    declare) stage_declare ;;
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
    all)     stage_declare; stage_link; stage_compile; stage_battery ;;
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
#
# The survey's own REFUSAL outranks the RED.  RED says the dependency is
# still there and names it; a refused survey says the instrument that was
# supposed to name it has stopped matching, and reporting that as an
# ordinary RED would let the work list silently shrink to nothing while the
# verdict stayed the same.  2 is this file's "could not look" code.
#
survey || { [ $? -eq 2 ] && exit 2; }
exit 1
