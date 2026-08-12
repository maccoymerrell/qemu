#!/bin/sh
# Static-TLS budget tripwire for a QEMU emulator binary.
#
# Author: Maccoy Merrell
#
# Why this exists: glibc carves a thread's static TLS block out of the stack
# allocation pthread_attr_setstacksize() names.  linux-user's do_fork() asks
# for NEW_STACK_SIZE (256 KiB) because a guest thread's HOST stack holds only
# QEMU's own interpreter frames, so an emulator whose static TLS approaches
# that size gets EINVAL from pthread_create -- for the first guest thread and
# for every guest thread the program will ever create.  Static TLS is also
# charged to every thread the process creates at all, guest or not: vCPU,
# iothread, RCU, each one paying for scratch only the thread currently inside
# translator_loop() ever touches.
#
# Both costs are invisible in a source review, because a __thread array shows
# up as an ordinary declaration.  This check turns the next one into a BUILD
# failure that names the binary, the budget, and the TLS symbols to look at.
#
# The ceiling is a TRIPWIRE AGAINST GROWTH tied to the failure above: it
# leaves the great majority of a 256 KiB guest-thread stack for the stack.  A
# deliberate increase raises it in meson.build alongside a re-measured
# multithreaded guest run that shows do_fork() not falling back.
#
# Usage: check-emulator-static-tls.sh <readelf> <binary> <stamp-out> <ceiling>
#
# A check that cannot find its subject must FAIL: an unreadable file, a
# readelf error, or an unparseable program-header table all exit nonzero
# rather than skipping.

set -u

READELF="$1"
BIN="$2"
STAMP="$3"
CEILING="$4"

fail() {
    echo "static-TLS guard: $*" >&2
    exit 1
}

[ -r "$BIN" ] || fail "cannot read '$BIN'"

PHDRS=$("$READELF" -l -W "$BIN" 2>&1) || fail "'$READELF -l -W $BIN' failed:
$PHDRS"

# Subject-presence check: the parse below must be looking at a real program
# header table.  Every executable has at least one LOAD segment; if none
# parses, the readelf output format drifted (or the file is not ELF) and this
# check can no longer see its subject -- fail, never skip.
LOADS=$(printf '%s\n' "$PHDRS" | awk '$1 == "LOAD" { n++ } END { print n+0 }')
[ "$LOADS" -gt 0 ] 2>/dev/null || \
    fail "no LOAD program headers parsed from '$BIN' -- cannot measure PT_TLS"

# PT_TLS MemSiz is column 6 of the -W (wide) program-header row:
#   TLS  Offset  VirtAddr  PhysAddr  FileSiz  MemSiz  Flg  Align
# No TLS segment at all means zero TLS use: trivially within budget.
MEMSZ_HEX=$(printf '%s\n' "$PHDRS" | awk '$1 == "TLS" { print $6; exit }')
if [ -z "$MEMSZ_HEX" ]; then
    MEMSZ=0
else
    MEMSZ=$(printf '%d' "$MEMSZ_HEX" 2>/dev/null) || \
        fail "unparseable PT_TLS MemSiz '$MEMSZ_HEX' in '$BIN'"
fi

if [ "$MEMSZ" -gt "$CEILING" ]; then
    echo "static-TLS guard: $BIN has $MEMSZ bytes of static TLS," \
         "over the $CEILING byte ceiling." >&2
    echo "  Static TLS is charged to every thread the process creates, and" >&2
    echo "  glibc places it inside the 256 KiB stack linux-user's do_fork()" >&2
    echo "  requests for a guest thread." >&2
    echo "  Largest TLS symbols:" >&2
    "$READELF" -sW "$BIN" 2>/dev/null |
        awk '$4 == "TLS" { print $3, $8 }' | sort -rn | head -10 >&2
    echo "  Move the storage somewhere with the lifetime it actually needs" >&2
    echo "  (see TCGContext::insn_df), or raise the ceiling in meson.build" >&2
    echo "  with a measurement showing do_fork() still gets its stack." >&2
    exit 1
fi

: > "$STAMP" || fail "cannot write stamp '$STAMP'"
exit 0
