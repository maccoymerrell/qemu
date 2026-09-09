#!/usr/bin/env bash
# capfield_census.sh — which Capstone-supplied fields does the plugin still
# read, and from exactly where?
#
# WHY THIS EXISTS.  `nocapstone_gate.sh` answers "is Capstone still a
# dependency" (yes/no) and sizes three surfaces: header includes, enum-keyed
# table rows, admission gates.  It does NOT size the fourth and largest one —
# the FIELDS of `qemu_plugin_insn_info` that the plugin reads out of the
# Capstone answer.  That number has been re-derived BY HAND at the head of
# every R14 pass since PASS 37 ("11 of 15 fields still read across 96 reads,
# 4 at zero"), by grepping for member names and eyeballing which receiver each
# belongs to.  A hand count of a C++ member access is not a measurement: `.mnemonic`
# also names `InsnClassification::mnem`, `e->mnem`, a local `mnemonic`, and a
# comment; and a grep cannot tell a read in dead `#if 0` from a live one.
#
# THE DELETION NEEDS THE OPPOSITE OF A NUMBER.  Ruling R14 retires each read
# either by re-sourcing it from QEMU-derived state or by deleting it with its
# consumer's contract cited.  That is a per-SITE obligation, so the useful
# artifact is the list of sites, not the count — and the count is then the
# list's length, which cannot drift from it.
#
# HOW IT MEASURES, and why this is not another grep.  The COMPILER is the
# only thing in this tree that knows which `.mnemonic` is
# `qemu_plugin_insn_info::mnemonic`.  So each field is marked
# `__attribute__((deprecated("CAPFIELD")))` and every plugin translation unit
# is re-parsed with `-fsyntax-only -Wdeprecated-declarations`.  GCC then names
# each read as `file:line:col: warning: 'qemu_plugin_insn_info::<field>' is
# deprecated: CAPFIELD`, with the member fully qualified — the receiver's type
# resolved, not guessed.  Dead code behind a false `#if` is not parsed and so
# is not counted, which is correct: it is not a read.
#
# THE TREE IS NOT TOUCHED.  The annotation goes into a SCRATCH COPY of
# `qemu-plugin.h` in a temporary directory, which is put FIRST on the include
# path so it shadows `../include/qemu/qemu-plugin.h` for this parse only.
# Nothing is written under the checkout and no object is relinked.
#
#   Measured before this was written, and the reason it is done this way:
#   annotating the header IN PLACE and rebuilding produces a plugin whose
#   `.text` and `.rodata` are BYTE-IDENTICAL (the macro expands to nothing
#   unless the census define is set) but whose FILE md5 differs, because
#   inserting lines into a header moves every DWARF line-table entry below
#   it.  A `.so` file hash is therefore not a neutrality oracle for a header
#   edit; the section hashes are.
#
# WHICH FIELDS COUNT.  The fifteen members of `qemu_plugin_insn_info` that
# `qemu_plugin_cap_decode()` fills from Capstone.  `decode_id` is deliberately
# NOT among them: it is QEMU's own decode-table slot, written into the same
# struct by the caller AFTER the Capstone decode, and it is the key the wire
# is being moved onto.  Counting it would make the residue look larger every
# time the migration succeeded.
#
# USAGE
#   capfield_census.sh [--build-dir DIR] [--out DIR] [--tsv]
#   capfield_census.sh --selftest [scratch-dir]
#
# EXIT CODES
#   0  the census ran and printed its result (zero reads is a legitimate
#      result — it is what the deletion is FOR — and is reported as such)
#   2  THE CENSUS COULD NOT LOOK.  No compile database, no plugin translation
#      units in it, the scratch header did not take the annotation, or a
#      translation unit failed to parse.  This is never folded into 0: a check
#      that cannot find its subject must not report all-clear, which is the
#      standing failure mode of every instrument in this tree.
#
# Author: Maccoy Merrell.
set -u

SRC_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
BUILD_DIR="$SRC_ROOT/build"
OUT_DIR=""
TSV=0
MODE=census
SELFTEST_DIR=""

# The fifteen Capstone-filled members, in declaration order.  decode_id is
# excluded by the rule stated in the header comment above.
CAPFIELDS="insn_id groups n_operands n_regs_read n_regs_write has_lock \
has_rep insn_size mnemonic op_str operands regs_read regs_write \
regs_read_id regs_write_id"

while [ $# -gt 0 ]; do
    case "$1" in
        --build-dir) BUILD_DIR=$2; shift 2 ;;
        --out)       OUT_DIR=$2;   shift 2 ;;
        --tsv)       TSV=1;        shift ;;
        --selftest)  MODE=selftest; SELFTEST_DIR=${2:-}; \
                     [ -n "${SELFTEST_DIR}" ] && shift; shift ;;
        -h|--help)   sed -n '2,60p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "capfield_census: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

die() { echo "capfield_census: CANNOT LOOK — $*" >&2; exit 2; }

# ---------------------------------------------------------------- annotate
#
# Write an annotated copy of qemu-plugin.h into $1/qemu-plugin.h.  Returns
# non-zero if the file does not have the shape this depends on, rather than
# emitting a header that silently marks nothing: an un-annotated header parses
# perfectly and yields a census of zero, which is the exact false green this
# instrument exists to avoid.
annotate_header() {
    local src=$1 dst=$2
    CAPFIELDS="$CAPFIELDS" python3 - "$src" "$dst" <<'PYEOF'
import os, re, sys
src, dst = sys.argv[1], sys.argv[2]
fields = os.environ["CAPFIELDS"].split()
s = open(src).read()
anchor = "typedef struct qemu_plugin_insn_info {"
end = "} qemu_plugin_insn_info;"
if anchor not in s or end not in s:
    sys.exit("qemu-plugin.h does not declare qemu_plugin_insn_info as expected")
i = s.index(anchor)
j = s.index(end, i)
body = s[i:j]
marked = []
for f in fields:
    # A member declaration: newline, indent, type words, then the name.  The
    # count=1 keeps a name that also appears in a comment below from taking
    # the annotation instead of the declaration, because the declaration is
    # first in every case in this struct.
    new, n = re.subn(r'(\n    [A-Za-z_][A-Za-z0-9_ ]*?\s)(' + f + r')(\b)',
                     r'\1__attribute__((deprecated("CAPFIELD"))) \2\3',
                     body, count=1)
    if n:
        marked.append(f)
        body = new
missing = [f for f in fields if f not in marked]
if missing:
    sys.exit("could not annotate: " + " ".join(missing))
open(dst, "w").write(s[:i] + body + s[j:])
print(" ".join(marked))
PYEOF
}

# ------------------------------------------------------------------ census
run_census() {
    local build=$1 out=$2
    [ -f "$build/compile_commands.json" ] ||
        die "no compile database at $build/compile_commands.json"

    local hdr="$SRC_ROOT/include/qemu/qemu-plugin.h"
    [ -f "$hdr" ] || die "no $hdr"

    mkdir -p "$out/inc" || die "cannot create $out/inc"
    annotate_header "$hdr" "$out/inc/qemu-plugin.h" > "$out/annotated.txt" ||
        die "$(cat "$out/annotated.txt" 2>/dev/null)"

    # One syntax-only parse per plugin translation unit, with the annotated
    # header shadowing the real one.  -Werror is stripped: the whole point is
    # to let the deprecation warnings through and read them.
    BUILD="$build" INC="$out/inc" python3 - > "$out/cmds.sh" <<'PYEOF'
import json, os, shlex, sys
build = os.environ["BUILD"]
inc = os.environ["INC"]
d = json.load(open(os.path.join(build, "compile_commands.json")))
seen = set()
n = 0
for c in d:
    f = c["file"]
    if "champsim_tracer" not in f or "/tools/" in f:
        continue
    if f in seen:
        continue
    seen.add(f)
    parts = shlex.split(c["command"])
    out, i = [], 0
    while i < len(parts):
        p = parts[i]
        if p == "-o":
            i += 2; continue
        if p in ("-MQ", "-MF"):
            i += 2; continue
        if p.startswith("-MD") or p.startswith("-MMD"):
            i += 1; continue
        if p == "-Werror":
            i += 1; continue
        out.append(p); i += 1
    for flag in ("-Wdeprecated-declarations", "-fsyntax-only", "-I" + inc):
        out.insert(1, flag)
    print(" ".join(shlex.quote(p) for p in out))
    n += 1
if n == 0:
    sys.exit("no champsim_tracer translation units in the compile database")
PYEOF
    [ $? -eq 0 ] || die "$(cat "$out/cmds.sh")"
    local ntu
    ntu=$(grep -c . "$out/cmds.sh")
    [ "$ntu" -gt 0 ] || die "no translation units to parse"

    ( cd "$build" && bash "$out/cmds.sh" ) > "$out/parse.log" 2>&1
    local rc=$?
    if [ $rc -ne 0 ]; then
        # A parse failure means the census saw only part of the plugin.  A
        # partial census reads LOWER than the truth, which is the direction
        # that looks like progress -- so it fails instead.
        grep -E 'error:' "$out/parse.log" | head -5 >&2
        die "$ntu translation unit(s) queued; at least one failed to parse" \
            "(see $out/parse.log)"
    fi

    grep -E "warning: .*qemu_plugin_insn_info::.*CAPFIELD" "$out/parse.log" \
        | perl -ne 'print "$4\t$1:$2:$3\n"
                    if /^(\S+?):(\d+):(\d+):.*?qemu_plugin_insn_info::(\w+)/' \
        | sort -u > "$out/reads.tsv"

    echo "$ntu" > "$out/n_tu"
}

report() {
    local out=$1
    local ntu total nread
    ntu=$(cat "$out/n_tu")
    total=$(grep -c . "$out/reads.tsv" || true)

    if [ "$TSV" = 1 ]; then
        cat "$out/reads.tsv"
        return
    fi

    echo "capfield_census: Capstone-supplied fields the plugin still reads"
    echo "  source        $SRC_ROOT"
    echo "  build         $BUILD_DIR"
    echo "  parsed        $ntu plugin translation unit(s)"
    echo "  evidence      $out"
    echo ""
    nread=0
    for f in $CAPFIELDS; do
        local n
        n=$(awk -F'\t' -v f="$f" '$1==f' "$out/reads.tsv" | grep -c . || true)
        [ "$n" -gt 0 ] && nread=$((nread + 1))
        printf '  %-16s %4d\n' "$f" "$n"
    done
    local nfields
    nfields=$(printf '%s\n' $CAPFIELDS | grep -c .)
    echo ""
    echo "  $nread of $nfields field(s) read, across $total read site(s);" \
         "$((nfields - nread)) at zero"
    echo ""
    echo "  per file:"
    cut -f2 "$out/reads.tsv" | sed 's#:[0-9]*:[0-9]*$##' \
        | sed "s#^\.\./##" | sort | uniq -c | sort -rn \
        | sed 's/^/    /'
    if [ "$total" = 0 ]; then
        echo ""
        echo "  ZERO READS.  Under R14 that is the goal state, not a broken"
        echo "  census: the annotation applied to all $nfields fields (see"
        echo "  $out/annotated.txt) and all $ntu translation unit(s) parsed."
    fi
}

# ---------------------------------------------------------------- selftest
#
# THREE ARMS, and each one is a way this census could report a comfortable
# number while being wrong.
#
#   plant     A read of a field that currently reads ZERO (`groups`) is added
#             to a scratch translation unit.  The census must COUNT it.  This
#             is the arm that proves the instrument sees a read at all, and
#             it uses a zero-field so a pass cannot be inherited from the
#             plugin's existing reads.
#   unmarked  The scratch header is left UNANNOTATED.  The parse then succeeds
#             and yields zero warnings -- a perfect false green.  The
#             annotator must REFUSE rather than emit that header.
#   broken    A translation unit that does not compile.  A census that skips
#             it silently reads lower than the truth, so the run must FAIL.
#
# All three are tip-independent: they compile their own fixtures and never
# consult the plugin, so they keep proving the same thing after the deletion
# lands and the real census reads zero.
selftest() {
    local scratch=${1:-$(mktemp -d "${TMPDIR:-/tmp}/capfield_selftest.XXXXXX")}
    local cxx=${CXX:-c++} bad=0
    mkdir -p "$scratch/inc" || { echo "capfield_census: SELFTEST CANNOT RUN"; return 1; }

    local hdr="$SRC_ROOT/include/qemu/qemu-plugin.h"
    [ -f "$hdr" ] || { echo "capfield_census: SELFTEST CANNOT RUN — no $hdr"; return 1; }

    # --- arm 1: plant ---------------------------------------------------
    if ! annotate_header "$hdr" "$scratch/inc/qemu-plugin.h" \
            > "$scratch/annot.txt" 2>&1; then
        echo "capfield_census: SELFTEST FAIL — annotator refused the REAL header:"
        sed 's/^/    /' "$scratch/annot.txt"
        return 1
    fi
    # C++, because the plugin is C++ throughout and the census keys on the
    # FULLY QUALIFIED member name (`qemu_plugin_insn_info::groups`) that only
    # a C++ front end prints.  A C fixture reports the bare name `groups`,
    # passes a looser grep, and would leave the real key untested -- so the
    # fixture must speak the same language as the subject.
    cat > "$scratch/plant.cc" <<'EOF'
#include <cstdint>
#include <cstddef>
#include <glib.h>
#include <qemu-plugin.h>
unsigned probe(const qemu_plugin_insn_info *i) { return i->groups; }
EOF
    "$cxx" -fsyntax-only -Wdeprecated-declarations \
          -I"$scratch/inc" -I"$SRC_ROOT/include/qemu" \
          $(pkg-config --cflags glib-2.0 2>/dev/null) \
          "$scratch/plant.cc" > "$scratch/plant.log" 2>&1
    local planted
    planted=$(grep -c "qemu_plugin_insn_info::groups.*CAPFIELD" \
                   "$scratch/plant.log" || true)
    echo "capfield_census: SELFTEST (scratch $scratch)"
    echo "  plant     groups reads found=$planted  (expect >=1)"
    [ "$planted" -ge 1 ] || {
        echo "  SELFTEST FAIL: a planted read of a zero-field was NOT counted"
        sed 's/^/    /' "$scratch/plant.log" | head -5
        bad=1
    }

    # --- arm 2: unmarked header ----------------------------------------
    local unmarked="$scratch/unmarked"
    mkdir -p "$unmarked"
    # A header whose struct has been renamed: the annotator's anchor is gone,
    # so it must refuse rather than write a header that marks nothing.
    sed 's/typedef struct qemu_plugin_insn_info {/typedef struct qemu_plugin_insn_NOPE {/' \
        "$hdr" > "$unmarked/in.h"
    if annotate_header "$unmarked/in.h" "$unmarked/qemu-plugin.h" \
           > "$unmarked/log" 2>&1; then
        echo "  unmarked  annotator ACCEPTED a header it could not mark"
        echo "  SELFTEST FAIL: an unannotated header yields a census of zero"
        bad=1
    else
        echo "  unmarked  annotator refused, as it must:" \
             "$(head -n1 "$unmarked/log")"
    fi

    # --- arm 3: a translation unit that does not parse ------------------
    #
    # Not "the compiler rejects bad C" -- that proves nothing about THIS
    # script.  run_census itself is invoked against a scratch compile
    # database whose one champsim_tracer unit does not parse, and it must
    # exit 2.  If it exited 0 it would print a census of zero reads over a
    # plugin it never read, which is the direction that looks like the
    # deletion succeeding.
    local broke="$scratch/broke"
    mkdir -p "$broke/build"
    cat > "$broke/champsim_tracer_broken.cc" <<'EOF'
this is not C++;
EOF
    printf '[{"directory":"%s","command":"%s -c %s","file":"%s"}]\n' \
        "$broke/build" "${CXX:-c++}" \
        "$broke/champsim_tracer_broken.cc" \
        "$broke/champsim_tracer_broken.cc" \
        > "$broke/build/compile_commands.json"
    ( FAILED=0; run_census "$broke/build" "$broke/out" ) \
        > "$broke/log" 2>&1
    local rc_broke=$?
    echo "  broken    run_census over a non-parsing unit rc=$rc_broke" \
         "(expect 2)"
    if [ "$rc_broke" != 2 ]; then
        echo "  SELFTEST FAIL: a census that could not read the plugin did" \
             "not report that it could not look"
        sed 's/^/    /' "$broke/log" | head -5
        bad=1
    fi

    # --- arm 4: the tree is not written ---------------------------------
    #
    # The whole design rests on the annotation going to a scratch copy.  If
    # it ever went in place, every pass that ran this census would silently
    # move the shipped header -- and, per the note at the top of this file,
    # the plugin's DWARF with it.
    local hdr_before hdr_after
    hdr_before=$(md5sum "$hdr" | cut -d' ' -f1)
    run_census "$BUILD_DIR" "$scratch/tree_out" > "$scratch/tree.log" 2>&1
    hdr_after=$(md5sum "$hdr" | cut -d' ' -f1)
    if [ "$hdr_before" = "$hdr_after" ]; then
        echo "  pristine  qemu-plugin.h unchanged by a census run" \
             "($hdr_before)"
    else
        echo "  pristine  qemu-plugin.h MOVED $hdr_before -> $hdr_after"
        echo "  SELFTEST FAIL: the census wrote to the tree"
        bad=1
    fi

    if [ "$bad" = 0 ]; then
        echo "capfield_census: SELFTEST GREEN — the census counts a planted"
        echo "  read, refuses a header it cannot annotate, reports that it"
        echo "  could not look when a unit will not parse, and leaves the"
        echo "  tree pristine"
        return 0
    fi
    echo "capfield_census: SELFTEST RED — this census cannot be trusted"
    return 1
}

# -------------------------------------------------------------------- main
if [ "$MODE" = selftest ]; then
    selftest "$SELFTEST_DIR"
    exit $?
fi

if [ -z "$OUT_DIR" ]; then
    OUT_DIR=$(mktemp -d "${TMPDIR:-/tmp}/capfield.XXXXXX")
fi
mkdir -p "$OUT_DIR" || die "cannot create $OUT_DIR"
run_census "$BUILD_DIR" "$OUT_DIR"
report "$OUT_DIR"
exit 0
