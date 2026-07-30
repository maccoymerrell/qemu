#!/bin/sh
# Static-TLS budget tripwire for libchampsim_tracer.so.
#
# Author: Maccoy Merrell
#
# Why this exists: the plugin is dlopen()ed, so its PT_TLS block must fit in
# glibc's static-TLS surplus.  Exceeding it breaks SYSTEM MODE ONLY, at load
# time, with an error ("cannot allocate memory in static TLS block") that
# names neither the plugin nor the offending variable — three separate
# incidents hit that cliff in one week.  This check turns the next TLS-size
# regression into a BUILD failure that names the .so, the budget, and the
# TLS symbols to look at.
#
# The ceiling passed by meson.build is a TRIPWIRE AGAINST GROWTH, not a model
# of glibc: the real budget is glibc-version- and binary-dependent (surplus
# 1664 bytes observed on the reference host).  The ceiling sits just above
# the plugin's current PT_TLS memsz, so any new thread_local shows up here
# first, while an intentional, measured increase raises the ceiling in
# contrib/plugins/meson.build alongside a re-measured load test.
#
# Usage: check_static_tls.sh <readelf> <plugin.so> <stamp-out> <ceiling-bytes>
#
# A check that cannot find its subject must FAIL: unreadable file, readelf
# errors, or an unparseable program-header table all exit nonzero rather
# than skipping.

set -u

READELF="$1"
SO="$2"
STAMP="$3"
CEILING="$4"

fail() {
    echo "champsim_tracer TLS guard: $*" >&2
    exit 1
}

[ -r "$SO" ] || fail "cannot read '$SO'"

PHDRS=$("$READELF" -l -W "$SO" 2>&1) || fail "'$READELF -l -W $SO' failed:
$PHDRS"

# Subject-presence check: the parse below must be looking at a real program
# header table.  Every shared object has at least one LOAD segment; if none
# parses, the readelf output format drifted (or the file is not ELF) and
# this check can no longer see its subject -- fail, never skip.
LOADS=$(printf '%s\n' "$PHDRS" | awk '$1 == "LOAD" { n++ } END { print n+0 }')
[ "$LOADS" -gt 0 ] 2>/dev/null || \
    fail "no LOAD program headers parsed from '$SO' -- cannot measure PT_TLS"

# PT_TLS MemSiz is column 6 of the -W (wide) program-header row:
#   TLS  Offset  VirtAddr  PhysAddr  FileSiz  MemSiz  Flg  Align
# No TLS segment at all means zero TLS use: trivially within budget.
MEMSZ_HEX=$(printf '%s\n' "$PHDRS" | awk '$1 == "TLS" { print $6; exit }')
if [ -z "$MEMSZ_HEX" ]; then
    MEMSZ=0
else
    MEMSZ=$(printf '%d' "$MEMSZ_HEX" 2>/dev/null) || \
        fail "unparseable PT_TLS MemSiz '$MEMSZ_HEX' in '$SO'"
fi

if [ "$MEMSZ" -gt "$CEILING" ]; then
    {
        echo "champsim_tracer TLS guard: PT_TLS memsz of $SO is $MEMSZ bytes," \
             "over the $CEILING-byte build ceiling."
        echo "A dlopen()ed plugin's static TLS must fit glibc's surplus" \
             "(1664 bytes observed; system mode fails to LOAD past it, with" \
             "an error naming neither the plugin nor the variable)."
        echo "Find the growth below and shrink it (heap-allocate, or make it" \
             "process-wide under a lock); raise the ceiling in" \
             "contrib/plugins/meson.build only with a re-measured load test."
        echo "TLS symbols in $SO:"
        "$READELF" -s -W "$SO" | awk '$4 == "TLS" { print "  " $0 }'
    } >&2
    exit 1
fi

echo "champsim_tracer TLS guard: PT_TLS memsz $MEMSZ <= ceiling $CEILING" \
     > "$STAMP"
