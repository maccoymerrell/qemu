#!/bin/bash
#
# Focused regression test for the profiler's data-is-address
# heuristic under AArch64 address tagging.
#
# The profiler flags a loaded/stored value as a pointer when its 4 KiB
# page is one a real correct-path mem-op touched.  An AArch64 pointer
# sitting in memory carries a top-byte tag (TBI — the basis of MTE /
# HWASAN) and, under PAC, signature bits in [55:48]; the MMU ignores
# them, so the raw stored value's page never matches the canonical
# effective-address page unless the profiler canonicalizes first.
# aarch64_canonicalize_addr (champsim_tracer_mnemonics_aarch64.h)
# masks the value to bits [47:0] before the page lookup.
#
# This test builds a tiny AArch64 program that touches an arena (so
# its pages enter the observed-page set), constructs a pointer into
# that arena with bits [63:48] dirtied by a tag, stores it, and exits.
# It traces the program, decodes the trace, and asserts the tagging
# store classified as an address.  Without the canonicalization the
# tagged value page-misses and the classification is lost — so a
# regression fails this test.
#
# Usage:
#   tests/tagged_ptr_addr.sh
#
# Environment knobs:
#   BUILD_DIR : QEMU build dir.                      [QEMU_ROOT/build]
#   CROSS_CC  : AArch64 cross-compiler driver.  [aarch64-linux-gnu-gcc]
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
VAL_ROOT="$(cd "$HERE/.." && pwd)"
QEMU_ROOT="$(cd "$VAL_ROOT/../../../.." && pwd)"

: "${BUILD_DIR:=$QEMU_ROOT/build}"
: "${CROSS_CC:=aarch64-linux-gnu-gcc}"

QEMU="$BUILD_DIR/qemu-aarch64"
PLUGIN="$BUILD_DIR/contrib/plugins/libchampsim_tracer.so"
CST_DECODE="$BUILD_DIR/contrib/plugins/cst_decode"

for f in "$QEMU" "$PLUGIN" "$CST_DECODE"; do
    if [ ! -x "$f" ]; then
        echo "FAIL: missing build artifact: $f"
        echo "  build it from the QEMU build dir, e.g."
        echo "  ninja qemu-aarch64 contrib/plugins/libchampsim_tracer.so \\"
        echo "        contrib/plugins/cst_decode"
        exit 1
    fi
done
if ! command -v "$CROSS_CC" >/dev/null 2>&1; then
    echo "SKIP: AArch64 cross-compiler '$CROSS_CC' not found"
    exit 0
fi

WORK="$(mktemp -d -t tagged_ptr_addr.XXXXXXXX)"
trap '[ -n "${KEEP:-}" ] || rm -rf "$WORK"' EXIT

# The program is one straight-line basic block ending in the exit
# syscall.  It touches the arena with non-pointer loads/stores (whose
# stored values — 0 and 1 — are NOT addresses, the negative control),
# then builds a tagged pointer into the arena and stores it.  The
# tagged store is the only memory op whose value is a real address,
# so any addr_cp=1 the profiler emits is attributable to it.
cat > "$WORK/prog.S" <<'EOF'
    .data
    .balign 4096
arena:
    .skip 8192                  /* two zero-filled writable pages */

    .text
    .globl _start
_start:
    adrp x20, arena
    add  x20, x20, :lo12:arena  /* x20 = arena base */

    /* Touch both arena pages with non-pointer data so they enter the
     * profiler's correct-path observed-page set.  Stored values are
     * 1 and 0 — small integers, never classified as addresses. */
    ldr  x0, [x20]
    add  x0, x0, #1
    str  x0, [x20]
    ldr  x1, [x20, #4096]
    str  x1, [x20, #4096]

    /* Build a tagged pointer into the arena: take a real arena
     * address and overwrite bits [63:48] with a tag — top byte 0x42
     * (a TBI / MTE-style tag) plus 0x42 in [55:48] (the PAC region).
     * This is the bit pattern a real tagged or signed pointer holds
     * in memory. */
    add  x2, x20, #64
    movk x2, #0x4242, lsl #48
    str  x2, [x20, #128]        /* <-- store of the tagged pointer */

    /* exit(0) */
    mov  x8, #93                /* __NR_exit */
    mov  x0, #0
    svc  #0
EOF

if ! "$CROSS_CC" -static -nostdlib -nostartfiles -O1 \
        -fno-asynchronous-unwind-tables \
        "$WORK/prog.S" -o "$WORK/prog" 2>"$WORK/build.log"; then
    echo "FAIL: build"
    cat "$WORK/build.log"
    exit 1
fi

"$QEMU" -plugin "$PLUGIN,outfile=$WORK/prog,trace_window=icount:start=0;stop=100000,memdata=1" \
        "$WORK/prog" >"$WORK/run.log" 2>&1
if [ ! -s "$WORK/prog.cst" ]; then
    echo "FAIL: tracer produced no .cst trace"
    cat "$WORK/run.log"
    exit 1
fi

DECODED="$WORK/decoded.txt"
if ! "$CST_DECODE" --format=legacy "$WORK/prog.cst" >"$DECODED" 2>"$WORK/decode.log"; then
    echo "FAIL: cst_decode"
    cat "$WORK/decode.log"
    exit 1
fi

# Sanity: the decode is non-empty and carries per-instruction profile
# data, so an absent addr_cp below is a real classification result and
# not a silently empty trace.
if ! grep -q 'prof: ' "$DECODED"; then
    echo "FAIL: decoded trace carries no per-instruction profile data"
    echo "  (profiling is unconditionally on — an empty profile means"
    echo "   the program did not trace as expected)"
    exit 1
fi

# The assertion: the tagged-pointer store classified as an address.
# addr_cp=1 is emitted only for a value whose canonicalized page is in
# the observed-page set; the tagged store is the program's sole
# address-valued memory op, so its presence proves the tag/PAC bits
# were stripped before the page lookup.
if grep -q 'addr_cp=1' "$DECODED"; then
    n=$(grep -c 'addr_cp=1' "$DECODED")
    echo "PASS: tagged AArch64 pointer classified as an address" \
         "($n addr_cp=1 profile insn(s))"
    exit 0
fi

echo "FAIL: tagged AArch64 pointer NOT classified as an address"
echo "  expected addr_cp=1 on the tagging store; the profiler likely"
echo "  page-tested the raw tagged value instead of canonicalizing it"
echo "  (champsim_tracer_mnemonics_aarch64.h aarch64_canonicalize_addr)."
echo "  --- profile lines from the decoded trace ---"
grep 'prof: ' "$DECODED" | sed 's/^/  /'
exit 1
