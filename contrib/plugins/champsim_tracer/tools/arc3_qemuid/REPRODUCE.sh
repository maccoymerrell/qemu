#!/bin/bash
#
# Reproduce the QEMU-decode-identity census for x86_64, end to end.
#
#   REPRODUCE.sh <out-dir> [build-dir]
#
# Builds the probe, runs the workload, runs both censuses, and exits
# non-zero if any step fails.  There is no path through this script that
# reports success without having measured something: the static census
# refuses a zero-slot scan, the dynamic census refuses a zero-record
# input, and every rc is checked at the point it is produced rather than
# taken through a pipe.
#
# Author: Maccoy Merrell
set -u

OUT=${1:?usage: REPRODUCE.sh <out-dir> [build-dir]}
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../../../../.." && pwd)
BUILD=${2:-$SRC/build}
PYTHON=${PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
JOBS=${JOBS:-12}

mkdir -p "$OUT" || exit 1
rc_total=0
note() { printf '\n=== %s ===\n' "$*"; }

note "tree $SRC   build $BUILD   -j $JOBS"

note "load check"
uptime

note "build qemu-x86_64"
ninja -C "$BUILD" -j "$JOBS" qemu-x86_64 > "$OUT/build.log" 2>&1
rc=$?
echo "ninja rc=$rc"
if [ $rc -ne 0 ]; then
    echo "FATAL: build failed, see $OUT/build.log"
    exit 1
fi

QEMU=$BUILD/qemu-x86_64
if [ ! -x "$QEMU" ]; then
    echo "FATAL: $QEMU missing"
    exit 1
fi

note "build idprobe.so"
gcc -shared -fPIC -O1 -o "$OUT/idprobe.so" "$HERE/idprobe.c" \
    -I"$SRC/include/qemu" $(pkg-config --cflags glib-2.0) \
    > "$OUT/probe_build.log" 2>&1
rc=$?
echo "gcc rc=$rc"
[ $rc -ne 0 ] && { cat "$OUT/probe_build.log"; exit 1; }

note "workload"
run() {
    local tag=$1; shift
    "$QEMU" -plugin "$OUT/idprobe.so,out=$OUT/w_$tag.tsv" "$@" \
        > "$OUT/w_$tag.log" 2>&1
    local r=$?
    local n=0
    [ -f "$OUT/w_$tag.tsv" ] && n=$(wc -l < "$OUT/w_$tag.tsv")
    echo "  $tag rc=$r records=$n"
    if [ "$r" -ne 0 ] || [ "$n" -eq 0 ]; then
        echo "  FAIL: $tag produced no usable evidence"
        rc_total=1
    fi
}
run echo /bin/echo hello
run ls   /bin/ls -laR /usr/include
run gzip /bin/gzip -9 -c /usr/lib/x86_64-linux-gnu/libc.so.6
run grep /bin/grep -rc int /usr/include/stdio.h
run py   /usr/bin/python3 -c \
    "import math;print(sum(math.sqrt(i) for i in range(200000)))"

note "static census (guard: no two slots may share a source line)"
"$PYTHON" "$HERE/static_census.py" \
    "$SRC/target/i386/tcg/decode-new.c.inc" \
    --json "$OUT/slots.json" > "$OUT/STATIC_CENSUS.txt" 2>&1
rc=$?
cat "$OUT/STATIC_CENSUS.txt"
echo "static_census rc=$rc"
[ $rc -ne 0 ] && rc_total=1

note "dynamic census"
"$PYTHON" "$HERE/census.py" "$OUT"/w_*.tsv \
    --label "echo, ls -laR /usr/include, gzip -9 libc.so.6, grep -rc, python3 sqrt loop" \
    > "$OUT/CENSUS.txt" 2>&1
rc=$?
cat "$OUT/CENSUS.txt"
echo "census rc=$rc"
[ $rc -ne 0 ] && rc_total=1

note "verdict"
echo "REPRODUCE rc=$rc_total"
exit $rc_total
