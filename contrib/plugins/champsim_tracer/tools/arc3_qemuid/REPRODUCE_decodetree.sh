#!/bin/bash
#
# Reproduce the QEMU-decode-identity census for the DECODETREE targets
# (aarch64, riscv64, mipsel), end to end.
#
#   REPRODUCE_decodetree.sh <out-dir> [build-dir]
#
# Every step checks the rc at the point it is produced, never through a
# pipe, and every census refuses an empty input rather than reporting a
# zero it did not measure.
#
# All three arms are expected to identify effectively every translated
# instruction.  The mipsel arm used to be the exception -- the MIPS base
# ISA is a hand-written switch, not decodetree, so this script once
# accepted "0 identities" there.  It no longer does:
# scripts/mips_ident_instrument.py exports that switch's own case labels,
# and a mipsel arm reporting no identities now means the instrumentation
# was lost, which is a failure and is checked for below.
#
# Author: Maccoy Merrell
set -u

OUT=${1:?usage: REPRODUCE_decodetree.sh <out-dir> [build-dir]}
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../../../../.." && pwd)
BUILD=${2:-$SRC/build}
PYTHON=${PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
JOBS=${JOBS:-12}
AUDIT=$SRC/contrib/plugins/champsim_tracer/champsim_tracer_mnemonic_audit.py

mkdir -p "$OUT/wl" || exit 1
rc_total=0
note() { printf '\n=== %s ===\n' "$*"; }

note "tree $SRC   build $BUILD   -j $JOBS"
uptime

note "build the three decodetree targets"
ninja -C "$BUILD" -j "$JOBS" qemu-aarch64 qemu-riscv64 qemu-mipsel \
    > "$OUT/build.log" 2>&1
rc=$?; echo "ninja rc=$rc"
[ $rc -ne 0 ] && { echo "FATAL: build failed, see $OUT/build.log"; exit 1; }

note "build idprobe.so"
gcc -shared -fPIC -O1 -o "$OUT/idprobe.so" "$HERE/idprobe.c" \
    -I"$SRC/include/qemu" $(pkg-config --cflags glib-2.0) \
    > "$OUT/probe_build.log" 2>&1
rc=$?; echo "gcc rc=$rc"
[ $rc -ne 0 ] && { cat "$OUT/probe_build.log"; exit 1; }

note "cross-compile the workload"
for spec in aarch64:aarch64-linux-gnu:-O3 \
            riscv64:riscv64-linux-gnu:-O2 \
            mipsel:mipsel-linux-gnu:-O2; do
    isa=${spec%%:*}; rest=${spec#*:}; tri=${rest%%:*}; opt=${rest##*:}
    for w in int fp; do
        for link in static dyn; do
            [ "$link" = static ] && lf=-static || lf=
            $tri-gcc $opt $lf -o "$OUT/wl/${isa}_${w}_${link}" \
                "$HERE/wl_$w.c" -lm > "$OUT/wl/${isa}_${w}_${link}.log" 2>&1
            r=$?
            echo "  ${isa}_${w}_${link} gcc rc=$r"
            [ $r -ne 0 ] && rc_total=1
        done
    done
done
[ $rc_total -ne 0 ] && { echo "FATAL: workload did not build"; exit 1; }

note "probe: one record per translated instruction"
for isa in aarch64 riscv64 mipsel; do
    case $isa in
        aarch64) tri=aarch64-linux-gnu;;
        riscv64) tri=riscv64-linux-gnu;;
        mipsel)  tri=mipsel-linux-gnu;;
    esac
    for w in int fp; do
        for link in static dyn; do
            tag=${isa}_${w}_${link}
            "$BUILD/qemu-$isa" -L "/usr/$tri" \
                -plugin "$OUT/idprobe.so,out=$OUT/tsv_$tag.tsv" \
                "$OUT/wl/$tag" > "$OUT/run_$tag.log" 2>&1
            r=$?
            n=0; [ -f "$OUT/tsv_$tag.tsv" ] && n=$(wc -l < "$OUT/tsv_$tag.tsv")
            echo "  $tag rc=$r records=$n"
            if [ "$r" -ne 0 ] || [ "$n" -eq 0 ]; then
                echo "  FAIL: $tag produced no usable evidence"
                rc_total=1
            fi
        done
    done
done

note "census: QEMU identity vs the mnemonic tables"
for pair in aarch64:aarch64 riscv:riscv64 mips:mipsel; do
    isa=${pair%%:*}; t=${pair##*:}
    "$PYTHON" "$AUDIT" --qemu-ident --isa "$isa" --diff \
        --build-dir "$BUILD" --observed "$OUT"/tsv_${t}_*.tsv \
        --max-lines 8 > "$OUT/CENSUS_TABLE_$isa.txt" 2>&1
    rc=$?
    echo "  $isa census rc=$rc"
    [ $rc -ne 0 ] && { cat "$OUT/CENSUS_TABLE_$isa.txt"; rc_total=1; }
    grep -E "carrying|row provenance|QID_|1:1|N:1|1:N|RESIDUE" \
        "$OUT/CENSUS_TABLE_$isa.txt" | head -12
done

note "identified fraction per ISA -- the number the export exists to move"
for t in aarch64 riscv64 mipsel; do
    line=$(awk -F'\t' '{n++; if ($2 == 0) z++}
                        END {printf "records=%d no-identity=%d identified=%.3f%%",
                                    n, z+0, n ? 100.0*(n-(z+0))/n : 0}' \
               "$OUT"/tsv_${t}_*.tsv)
    echo "  $t  $line"
    frac=$(awk -F'\t' '{n++; if ($2 == 0) z++}
                        END {print (n && (n-(z+0)) * 100 >= n * 99) ? "ok" : "LOW"}' \
               "$OUT"/tsv_${t}_*.tsv)
    if [ "$frac" != ok ]; then
        echo "  FAIL: $t identifies under 99% of translated instructions"
        rc_total=1
    fi
    # An instruction with no identity is named, never counted: a bare
    # total cannot be reviewed and cannot be shown to be the right ones.
    awk -F'\t' '$2 == 0 {print "    UNIDENTIFIED " $5}' \
        "$OUT"/tsv_${t}_*.tsv | sort | uniq -c | sort -rn | head -20
done

note "verdict"
echo "REPRODUCE_decodetree rc=$rc_total"
exit $rc_total
