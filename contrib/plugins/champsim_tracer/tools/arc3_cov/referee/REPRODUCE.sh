#!/bin/bash
# THE OFFLINE REFERENCE LEG.  The producer behind eight rows of the R13 gate.
#
#   REPRODUCE.sh <evidence-root> [--build-dir DIR] [--corpus DIR] [--spec DIR]
#
# WHAT IT REPLACES, AND WHY THE REPLACEMENT IS NOT A DOWNGRADE.
# ---------------------------------------------------------------------------
# Eight manifest rows -- the four `static/<isa>` decode-agreement rows and the
# four `isax*` allowlist rows -- were produced by `build/contrib/plugins/
# isaxcheck`, a binary that linked Capstone INTO the build.  That binary is
# gone with Capstone, so those eight rows had no producer and the gate read
# REPORT MISSING on all of them: a red about the apparatus, not about the
# trace.  The reference did not have to run in the traced process to answer
# the question it answers, and under the standing external-comparison ruling
# it no longer does.  It runs HERE, offline, over encodings the guest actually
# executed and a capture build recorded:
#
#   cst_referee.py    decodes each recorded encoding with the reference and
#                     writes its opcode word and register sets in the wire's
#                     own vocabulary
#   gapreport.py      joins the opcode words, buckets every encoding, and
#                     joins each disagreement class against the written
#                     arbitrations in gapreport_rulings.tsv
#   setjoin.py        joins the register-name sets per (encoding, direction)
#                     and reports every REAL-LOST class with no arbitration
#   rule_universe.py  reads the BUILD's own decode rules, so "this ruling is
#                     dead" is a fact about the build and not about the sample
#
# WHAT IT WRITES, at the paths external_truth_gate/ADJUDICATED.tsv names:
#
#   <root>/referee/OPCODE.txt   gapreport, stdout and stderr in one file
#   <root>/referee/REGSET.txt   setjoin, the same
#   <root>/referee/STAGES.txt   one `stage <name> rc=<n>` line per arm
#
# STAGES.txt does NOT carry the two scorers' own exit codes.  They exit
# non-zero exactly when their UNRULED or DEAD counts are non-zero, and those
# counts are what six of the eight rows already score; counting them again
# here would convict the apparatus twice for one disagreement.
#
# THE CORPUS.  Capturing it needs the capture build (-Dcst_capture=true) and
# the SPEC guests, which this repository does not carry, so `--corpus DIR`
# takes a corpus a previous run produced and the capture arm is skipped.  With
# neither a corpus nor a usable SPEC tree this script REFUSES and writes no
# report: the gate then reads REPORT MISSING, which is the honest answer --
# a leg that did not run has not passed.
#
# Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TOOLS=$(cd "$HERE/../.." && pwd)
QEMU_ROOT=$(cd "$TOOLS/../../.." && pwd)
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
ISAS="x86_64 aarch64 riscv64 mipsel"

usage() {
    sed -n '2,6p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

[ $# -ge 1 ] || usage
ROOT=$1; shift
BUILD=${CST_CAPTURE_BUILD:-$QEMU_ROOT/build-cap212}
CORPUS=${CST_REF_CORPUS:-}
SPEC=${CST_SPEC_DIR:-/mnt/md0/ChampSimTraces/speccpu_bin/benchspec/CPU}
while [ $# -gt 0 ]; do
    case "$1" in
        --build-dir) BUILD=$2; shift 2 ;;
        --corpus)    CORPUS=$2; shift 2 ;;
        --spec)      SPEC=$2; shift 2 ;;
        *) usage ;;
    esac
done

mkdir -p "$ROOT/referee" "$ROOT/_refwork" || exit 2
ROOT=$(cd "$ROOT" && pwd)
W="$ROOT/_refwork"
mkdir -p "$W/logs"
STAGES="$ROOT/referee/STAGES.txt"
: > "$STAGES"

stage() {   # stage <name> <rc>
    echo "stage $1 rc=$2" >> "$STAGES"
}

refuse() {
    echo "referee: REFUSING -- $*" >&2
    echo "referee: no report written; the gate reads REPORT MISSING, which is" >&2
    echo "what a leg that did not run has earned." >&2
    exit 2
}

for f in "$TOOLS/cst_referee.py" "$TOOLS/gapreport.py" "$TOOLS/setjoin.py" \
         "$TOOLS/rule_universe.py" "$TOOLS/gapreport_rulings.tsv" \
         "$TOOLS/setjoin_rulings.tsv" "$HERE/merge.py"; do
    [ -e "$f" ] || refuse "missing $f"
done

# --------------------------------------------------------------- 1. corpus
# Either a corpus is handed in, or one is captured.  Both routes end with
# $MERGED holding merged/{gen,ident}_<isa>.tsv, and the stage's rc says which
# happened only in the log -- the gate scores the rc, not the route.
if [ -n "$CORPUS" ]; then
    MERGED=$CORPUS
    rc=0
    for isa in $ISAS; do
        for kind in gen ident; do
            [ -s "$MERGED/${kind}_${isa}.tsv" ] || {
                echo "referee: $MERGED/${kind}_${isa}.tsv missing or empty" \
                     >> "$W/logs/corpus.log"; rc=1; }
        done
    done
    echo "corpus: supplied at $MERGED (rc=$rc)" >> "$W/logs/corpus.log"
    stage corpus "$rc"
    [ "$rc" = 0 ] || refuse "the supplied corpus is incomplete (see $W/logs/corpus.log)"
else
    [ -d "$SPEC" ] || refuse "no corpus given and no SPEC tree at $SPEC"
    MERGED="$W/merged"
    (
      set -u
      WIN=trace_window=icount:start=0+stop=20000000
      PLUG=$BUILD/contrib/plugins/libchampsim_tracer.so
      test -f "$PLUG" || { echo "NO PLUGIN $PLUG"; exit 2; }
      for isa in $ISAS; do
        case $isa in
        x86_64)  SUF=avx2-m64;    EMU=qemu-x86_64  ;;
        aarch64) SUF=aarch64-m64; EMU=qemu-aarch64 ;;
        riscv64) SUF=riscv64-m64; EMU=qemu-riscv64 ;;
        mipsel)  SUF=mipsel-m32;  EMU=qemu-mipsel  ;;
        esac
        test -x "$BUILD/$EMU" || { echo "NO EMULATOR $BUILD/$EMU"; exit 2; }
        (
          for spec in "505.mcf_r inp.in" \
                      "519.lbm_r 20 reference.dat 0 1 100_100_130_cf_a.of" \
                      "508.namd_r --input namd.in --iterations 1" \
                      "511.povray_r SPEC-benchmark-test.ini" \
                      "502.gcc_r t1.c -O3 -o /dev/null"; do
            set -- $spec
            gdir=$1; shift
            name=${gdir%%.*}
            d="$W/cap/$isa/$name"
            mkdir -p "$d" || exit 1
            cp -f "$SPEC/$gdir"/data/test/input/* "$d"/ 2>/dev/null
            exe=$(ls "$SPEC/$gdir"/exe/*_base.$SUF 2>/dev/null | head -1)
            [ -n "$exe" ] || { echo "MISSING $gdir ($SUF)"; continue; }
            ( cd "$d" && \
              CST_CAPTURE_ISA=$isa \
              CST_QEMU_IDENT_PAIRS="$d/ident.tsv" \
              CST_GEN_SET_DUMP="$d/gen.tsv" \
              ionice -c3 nice -n10 timeout 3000 \
                "$BUILD/$EMU" -plugin "$PLUG,outfile=t,$WIN,compress=zstd -T8 -3 -q -c" \
                "$exe" "$@" > "$d/run.log" 2>&1 )
            echo "rc[$isa/$name]=$?"
            rm -f "$d"/t*.cst* 2>/dev/null
          done
        ) > "$W/logs/cap_$isa.log" 2>&1 &
      done
      wait
    ) > "$W/logs/capture.log" 2>&1
    caprc=$?
    "$PY" "$HERE/merge.py" --cap "$W/cap" --out "$MERGED" \
        >> "$W/logs/capture.log" 2>&1
    [ $? = 0 ] || caprc=1
    stage corpus "$caprc"
    [ "$caprc" = 0 ] || refuse "the capture arm did not produce a corpus (see $W/logs/capture.log)"
fi

# ----------------------------------------------------- 2. referee selftest
"$PY" "$TOOLS/cst_referee.py" --selftest > "$W/logs/REF_SELFTEST.txt" 2>&1
stage selftest "$?"

# ---------------------------------------------- 3. the reference, per ISA
mkdir -p "$W/ref"
for isa in $ISAS; do
    "$PY" "$TOOLS/cst_referee.py" --isa "$isa" \
        --in "$MERGED/ident_$isa.tsv" --out-dir "$W/ref" \
        > "$W/logs/REF_$isa.txt" 2>&1
    stage "referee-$isa" "$?"
done

# --------------------------------------------------------- 4. rule universe
mkdir -p "$W/universe"
"$PY" "$TOOLS/rule_universe.py" --build-dir "$BUILD" -o "$W/universe" \
    > "$W/logs/UNIVERSE.txt" 2>&1
stage universe "$?"

# ------------------------------------------------------------------ 5. join
# The register-set scorer reads ONE file per ISA carrying both sides, so the
# two are concatenated here.  A side that is empty is a refusal rather than a
# join with nothing in it -- a scorer whose comparison has one side reports no
# losses for the one reason that is never a pass.
mkdir -p "$W/join" "$W/gap"
joinrc=0
for isa in $ISAS; do
    m="$MERGED/gen_$isa.tsv"; c="$W/ref/gen_c_$isa.tsv"
    if [ ! -s "$m" ] || [ ! -s "$c" ]; then
        echo "join $isa: a side is missing or empty (q=$m c=$c)" \
            >> "$W/logs/JOIN.txt"
        joinrc=1
        continue
    fi
    { cat "$m"; grep -v '^#' "$c"; } > "$W/join/gen_$isa.tsv"
    echo "join $isa q=$(grep -vc '^#' "$m") c=$(grep -vc '^#' "$c")" \
        >> "$W/logs/JOIN.txt"
    cp -f "$MERGED/ident_$isa.tsv" "$W/gap/" 2>/dev/null
    cp -f "$W/ref/opc_$isa.tsv"    "$W/gap/" 2>/dev/null
done
stage join "$joinrc"

# ----------------------------------------------------------- 6. the reports
# --top 0 prints EVERY detail line.  The scorer sums the printed UNRULED
# lines and refuses a truncated list, so a limit here would turn a real
# headline into a refusal for no reason.
"$PY" "$TOOLS/gapreport.py" --dir "$W/gap" \
      --isa x86_64 --isa aarch64 --isa riscv64 --isa mipsel \
      --require-ruled --rulings "$TOOLS/gapreport_rulings.tsv" \
      --universe "$W/universe" --top 0 \
      > "$ROOT/referee/OPCODE.txt" 2> "$W/logs/OPCODE.err"
opcrc=$?
cat "$W/logs/OPCODE.err" >> "$ROOT/referee/OPCODE.txt"

"$PY" "$TOOLS/setjoin.py" --dir "$W/join" \
      --isa x86_64 --isa aarch64 --isa riscv64 --isa mipsel \
      --require-ruled --rulings "$TOOLS/setjoin_rulings.tsv" --top 0 \
      > "$ROOT/referee/REGSET.txt" 2> "$W/logs/REGSET.err"
setrc=$?
cat "$W/logs/REGSET.err" >> "$ROOT/referee/REGSET.txt"

echo "referee: gapreport rc=$opcrc setjoin rc=$setrc (scored by the gate's"
echo "         own rows, not by STAGES.txt -- see the header)"
cat "$STAGES"
! grep -q 'rc=[^0]' "$STAGES"
