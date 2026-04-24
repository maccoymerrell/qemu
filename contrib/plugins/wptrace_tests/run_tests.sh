#!/bin/bash
# Run the champsim_tracer plugin on all test binaries and verify binary/text consistency.
#
# Usage:
#   ./run_tests.sh [--build-dir DIR] [--bin-dir DIR] [--out-dir DIR] [ISA ...]
#
#   --build-dir DIR  Path to QEMU build directory
#                    (default: auto-detect from script location: ../../../build)
#   --bin-dir   DIR  Path to compiled test binaries
#                    (default: <script-dir>/bin)
#   --out-dir   DIR  Directory for plugin output files (.wpt/.txt)
#                    (default: <script-dir>/run_output; kept on disk for inspection)
#   ISA              Limit to specific ISAs: x86 aarch64 riscv64 mips
#
# Verification method:
#   For each test, the plugin runs once generating both a binary trace (.wpt)
#   and a text trace (.txt).  The decoder then re-reads the binary and compares
#   its output against the text file.  A VERIFY: OK result means the two
#   representations are bit-for-bit equivalent.
#
# Exit code: 0 if all executed tests pass, 1 if any fail.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
QEMU_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
BUILD_DIR="$QEMU_ROOT/build"
BIN_DIR="$SCRIPT_DIR/bin"
OUT_DIR="$SCRIPT_DIR/run_output"
WANTED_ISAS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --bin-dir)   BIN_DIR="$2";   shift 2 ;;
        --out-dir)   OUT_DIR="$2";   shift 2 ;;
        x86|aarch64|riscv64|mips) WANTED_ISAS+=("$1"); shift ;;
        -h|--help)
            sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

PLUGIN="$BUILD_DIR/contrib/plugins/libchampsim_tracer.so"
DECODE="$QEMU_ROOT/contrib/plugins/champsim_tracer_decode.py"

if [[ ! -f "$PLUGIN" ]]; then
    echo "ERROR: plugin not found: $PLUGIN"
    echo "       Run: ninja -C '$BUILD_DIR' contrib/plugins/libchampsim_tracer.so"
    exit 1
fi

mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------------
# ISA configuration — must match build.sh
# ---------------------------------------------------------------------------

declare -A QEMU=(
    [x86]="qemu-x86_64"
    [aarch64]="qemu-aarch64"
    [riscv64]="qemu-riscv64"
    [mips]="qemu-mipsel"
)

declare -A TESTS=(
    [x86]="test storefwd intdiv divsd fpdiv fpdiv_vec heapalloc memdata"
    [aarch64]="test storefwd intdiv divsd fpdiv fpdiv_vec heapalloc memdata"
    [riscv64]="test storefwd intdiv divsd fpdiv fpdiv_tagged heapalloc memdata"
    [mips]="test storefwd intdiv divsd fpdiv fpdiv_vec heapalloc memdata"
)

# Multi-thread tests: produce a single monolithic trace that notes thread switches
declare -A THREADED_TESTS=(
    [x86]="multithreaded"
    [aarch64]="multithreaded"
    [riscv64]="multithreaded"
    [mips]="multithreaded"
)

# Extra plugin options for specific tests (e.g. "memalloc=1").
# Any test listed here gets these options appended to the plugin invocation.
declare -A EXTRA_PLUGIN_OPTS=(
    [heapalloc]="memalloc=1"
    [memdata]="memdata=1"
)

# Content-check patterns: after decode verification, grep the .txt for this
# pattern.  Failure to match fails the test — confirms the feature fired.
# Multiple patterns separated by '|||' are checked independently (all required).
declare -A CONTENT_CHECK=(
    [heapalloc]="^MEMALLOC "
    [memdata]=":data=0xdeadbeef"
)

ISA_ORDER=(x86 aarch64 riscv64 mips)

if [[ ${#WANTED_ISAS[@]} -gt 0 ]]; then
    ISA_ORDER=("${WANTED_ISAS[@]}")
fi

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
SKIP=0

run_one() {
    local isa="$1"
    local name="$2"
    local qemu_name="${QEMU[$isa]}"
    local qemu_bin="$BUILD_DIR/$qemu_name"
    local binary="$BIN_DIR/${name}_${isa}"
    local label="${name}_${isa}"
    local out="$OUT_DIR/$label"

    if [[ ! -f "$qemu_bin" ]]; then
        printf "  SKIP  %-34s (QEMU binary '%s' not in %s)\n" \
            "$label" "$qemu_name" "$BUILD_DIR"
        SKIP=$((SKIP + 1))
        return
    fi

    if [[ ! -f "$binary" ]]; then
        printf "  SKIP  %-34s (binary not found — run build.sh first)\n" "$label"
        SKIP=$((SKIP + 1))
        return
    fi

    # Remove stale outputs from previous run
    rm -f "${out}.wpt" "${out}.txt"

    # Build plugin option string, appending any test-specific extras
    local plugin_opts="outfile=${out},stop=50000,debug=1"
    local extra="${EXTRA_PLUGIN_OPTS[$name]:-}"
    [[ -n "$extra" ]] && plugin_opts="$plugin_opts,$extra"

    # Run the plugin; QEMU user-mode prints nothing useful to stdout/stderr
    "$qemu_bin" \
        -plugin "$PLUGIN,$plugin_opts" \
        "$binary" >/dev/null 2>&1

    if [[ ! -f "${out}.wpt" ]]; then
        printf "  FAIL  %-34s (no plugin output produced)\n" "$label"
        FAIL=$((FAIL + 1))
        return
    fi

    result=$(python3 "$DECODE" "${out}.wpt" -o "${out}.decoded.txt" --expect "${out}.txt" 2>&1 | tail -1)
    if ! echo "$result" | grep -q "VERIFY: OK"; then
        printf "  FAIL  %-34s  %s\n" "$label" "$result"
        FAIL=$((FAIL + 1))
        return
    fi

    # Content check against decoded output (includes footer sections)
    local check_file="${out}.decoded.txt"
    [[ ! -f "$check_file" ]] && check_file="${out}.txt"
    local patterns="${CONTENT_CHECK[$name]:-}"
    if [[ -n "$patterns" ]]; then
        local IFS_OLD="$IFS"
        IFS='|||'
        read -ra PATS <<< "$patterns"
        IFS="$IFS_OLD"
        for pat in "${PATS[@]}"; do
            [[ -z "$pat" ]] && continue
            if ! grep -qP "$pat" "$check_file" 2>/dev/null; then
                printf "  FAIL  %-34s  (no '%s' lines in trace)\n" "$label" "$pat"
                FAIL=$((FAIL + 1))
                return
            fi
        done
    fi

    printf "  PASS  %s\n" "$label"
    PASS=$((PASS + 1))
}

# run_threaded: run a multi-thread test and validate the monolithic trace.
# All threads share a single output file; thread switches are noted in the trace.
run_threaded() {
    local isa="$1"
    local name="$2"
    local qemu_name="${QEMU[$isa]}"
    local qemu_bin="$BUILD_DIR/$qemu_name"
    local binary="$BIN_DIR/${name}_${isa}"
    local label="${name}_${isa}"
    local out="$OUT_DIR/$label"

    if [[ ! -f "$qemu_bin" ]]; then
        printf "  SKIP  %-34s (QEMU binary '%s' not in %s)\n" \
            "$label" "$qemu_name" "$BUILD_DIR"
        SKIP=$((SKIP + 1))
        return
    fi

    if [[ ! -f "$binary" ]]; then
        printf "  SKIP  %-34s (binary not found — run build.sh first)\n" "$label"
        SKIP=$((SKIP + 1))
        return
    fi

    # Remove any stale output from a previous run
    rm -f "${out}.wpt" "${out}.txt"

    local plugin_opts="outfile=${out},debug=1"
    local extra="${EXTRA_PLUGIN_OPTS[$name]:-}"
    [[ -n "$extra" ]] && plugin_opts="$plugin_opts,$extra"
    if ! timeout 120 "$qemu_bin" \
        -plugin "$PLUGIN,$plugin_opts" \
        "$binary" >/dev/null 2>&1; then
        if [[ ! -f "${out}.wpt" ]]; then
            printf "  FAIL  %-34s (timeout or crash — no output)\n" "$label"
            FAIL=$((FAIL + 1))
            return
        fi
    fi

    if [[ ! -f "${out}.wpt" ]]; then
        printf "  FAIL  %-34s (no .wpt produced)\n" "$label"
        FAIL=$((FAIL + 1))
        return
    fi

    # Verify monolithic trace file decodes without error
    local result
    result=$(timeout 120 python3 "$DECODE" "${out}.wpt" -o "${out}.decoded.txt" 2>&1 | tail -1)
    if echo "$result" | grep -qi "error\|traceback\|ValueError"; then
        printf "  FAIL  %-34s  %s\n" "$label" "${result:-(decode error)}"
        FAIL=$((FAIL + 1))
        return
    fi

    # Verify the debug text output contains THREAD_SWITCH markers
    # (confirms the trace correctly tracks thread changes).
    # THREAD_SWITCH markers are written to the debug text output (not binary).
    local txt_file="${out}.txt"
    if [[ -f "$txt_file" ]] && ! grep -q "THREAD_SWITCH" "$txt_file" 2>/dev/null; then
        printf "  FAIL  %-34s  (no THREAD_SWITCH markers in trace)\n" "$label"
        FAIL=$((FAIL + 1))
        return
    fi

    printf "  PASS  %s\n" "$label"
    PASS=$((PASS + 1))
}

for isa in "${ISA_ORDER[@]}"; do
    echo "--- $isa ---"
    for name in ${TESTS[$isa]}; do
        run_one "$isa" "$name"
    done
    for name in ${THREADED_TESTS[$isa]}; do
        run_threaded "$isa" "$name"
    done
done

echo ""
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "Output:  $OUT_DIR/"
[[ $FAIL -eq 0 ]]
