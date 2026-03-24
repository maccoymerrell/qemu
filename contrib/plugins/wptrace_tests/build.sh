#!/bin/bash
# Build all wptrace test binaries for x86, aarch64, riscv64, and mips.
#
# Usage:
#   ./build.sh [--out-dir DIR] [ISA ...]
#
#   --out-dir DIR   Write binaries to DIR (default: <script-dir>/bin)
#   ISA             Limit to specific ISAs: x86 aarch64 riscv64 mips
#                   (default: all four)
#
# Output naming: bin/<test>_<isa>
#
# Requirements:
#   x86    : gcc (or x86_64-linux-gnu-gcc)
#   aarch64: aarch64-linux-gnu-gcc
#   riscv64: riscv64-linux-gnu-gcc
#   mips   : mipsel-linux-gnu-gcc

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/bin"
WANTED_ISAS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        x86|aarch64|riscv64|mips) WANTED_ISAS+=("$1"); shift ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------------
# ISA configuration
# ---------------------------------------------------------------------------

declare -A CC=(
    [x86]="gcc"
    [aarch64]="aarch64-linux-gnu-gcc"
    [riscv64]="riscv64-linux-gnu-gcc"
    [mips]="mipsel-linux-gnu-gcc"
)

declare -A CFLAGS=(
    [x86]="-static -nostdlib -nostartfiles"
    [aarch64]="-static -nostdlib -nostartfiles"
    [riscv64]="-static -nostdlib -nostartfiles -march=rv64gc -mabi=lp64d"
    [mips]="-static -nostdlib -nostartfiles -e __start"
)

# Tests to build for each ISA (determines the .S filename and binary name)
declare -A TESTS=(
    [x86]="test storefwd intdiv divsd fpdiv fpdiv_vec heapalloc memdata"
    [aarch64]="test storefwd intdiv divsd fpdiv fpdiv_vec heapalloc memdata"
    [riscv64]="test storefwd intdiv divsd fpdiv fpdiv_tagged heapalloc memdata"
    [mips]="test storefwd intdiv divsd fpdiv fpdiv_vec heapalloc memdata"
)

# C tests built from shared sources (not ISA-specific .S files)
declare -A C_TESTS=(
    [x86]="multithreaded synctest sync_spin sync_sem sync_prodcons sync_barrier sync_spsc sync_rwlock"
    [aarch64]="multithreaded synctest sync_spin sync_sem sync_prodcons sync_barrier sync_spsc sync_rwlock"
    [riscv64]="multithreaded synctest sync_spin sync_sem sync_prodcons sync_barrier sync_spsc sync_rwlock"
    [mips]="multithreaded synctest sync_spin sync_sem sync_prodcons sync_barrier sync_spsc sync_rwlock"
)

ISA_ORDER=(x86 aarch64 riscv64 mips)

# If the user specified ISAs, restrict to those
if [[ ${#WANTED_ISAS[@]} -gt 0 ]]; then
    ISA_ORDER=("${WANTED_ISAS[@]}")
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

BUILT=0
SKIPPED=0
FAILED=0

build_one() {
    local isa="$1"
    local name="$2"
    local cc="${CC[$isa]}"
    local flags="${CFLAGS[$isa]}"
    local src="$SCRIPT_DIR/$isa/$name.S"
    local out="$OUT_DIR/${name}_${isa}"
    if ! command -v "$cc" >/dev/null 2>&1; then
        printf "  SKIP  %-36s (compiler '%s' not found)\n" "$isa/$name.S" "$cc"
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    if [[ ! -f "$src" ]]; then
        printf "  SKIP  %-36s (source not found)\n" "$isa/$name.S"
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    if $cc $flags -o "$out" "$src" 2>/tmp/wptrace_build_err_$$; then
        printf "  CC    %-36s -> bin/%s_%s\n" "$isa/$name.S" "$name" "$isa"
        BUILT=$((BUILT + 1))
    else
        printf "  FAIL  %-36s\n" "$isa/$name.S"
        cat /tmp/wptrace_build_err_$$
        FAILED=$((FAILED + 1))
    fi
    rm -f /tmp/wptrace_build_err_$$
}

# build_one_c: compile a shared C source (from wptrace_tests/) for an ISA.
# Uses -static -pthread instead of the assembly-specific nostdlib flags.
build_one_c() {
    local isa="$1"
    local name="$2"
    local cc="${CC[$isa]}"
    local src="$SCRIPT_DIR/$name.c"
    local out="$OUT_DIR/${name}_${isa}"

    local extra_flags="-static -pthread"
    if [[ "$isa" == "riscv64" ]]; then
        extra_flags="$extra_flags -march=rv64gc -mabi=lp64d"
    fi

    if ! command -v "$cc" >/dev/null 2>&1; then
        printf "  SKIP  %-36s (compiler '%s' not found)\n" "$name.c[$isa]" "$cc"
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    if [[ ! -f "$src" ]]; then
        printf "  SKIP  %-36s (source not found)\n" "$name.c"
        SKIPPED=$((SKIPPED + 1))
        return
    fi

    if $cc $extra_flags -o "$out" "$src" 2>/tmp/wptrace_build_err_$$; then
        printf "  CC    %-36s -> bin/%s_%s\n" "$name.c[$isa]" "$name" "$isa"
        BUILT=$((BUILT + 1))
    else
        printf "  FAIL  %-36s\n" "$name.c[$isa]"
        cat /tmp/wptrace_build_err_$$
        FAILED=$((FAILED + 1))
    fi
    rm -f /tmp/wptrace_build_err_$$
}

for isa in "${ISA_ORDER[@]}"; do
    echo "--- $isa ---"
    for name in ${TESTS[$isa]}; do
        build_one "$isa" "$name"
    done
    for name in ${C_TESTS[$isa]}; do
        build_one_c "$isa" "$name"
    done
done

echo ""
echo "Built: $BUILT  Skipped: $SKIPPED  Failed: $FAILED"
echo "Binaries: $OUT_DIR/"
[[ $FAILED -eq 0 ]]
