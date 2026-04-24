#!/bin/bash
# End-to-end smoke test for champsim_tracer_genval on x86_64.
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GENVAL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
QEMU_ROOT="$(cd "$GENVAL_DIR/../../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$QEMU_ROOT/build}"

OUT="$GENVAL_DIR/out/rt_$$"
mkdir -p "$OUT"
trap 'rm -rf "$OUT"' EXIT

SEED="${SEED:-0x0102}"

cd "$GENVAL_DIR"
python3 ./genval.py all \
    --seed "$SEED" \
    -o "$OUT" \
    --isa x86_64 \
    --build-dir "$BUILD_DIR" \
    --diamonds 4 --side-len-min 2 --side-len-max 3 \
    --stop 20000
