#!/bin/bash
#
# THE CAPSTONE CENSUS, IN THE TREE.  FINDING 250-I.
#
# Every pass re-measures the same question -- does anything the tracer ships
# still reach Capstone -- and every pass has re-written the script that asks
# it.  The answer has therefore been a NUMBER rather than a MEASUREMENT: it
# could not be re-derived from the tree, and a pass-local grep is exactly what
# went wrong at exec250.
#
# WHAT WENT WRONG, and the trap this file exists to hold shut.  The pass-local
# census counted "plugin refs to cap_ fns" with the pattern `cap_[a-z_]*(`
# and reported TWENTY-THREE.  Not one of them was Capstone.  `cap_min`,
# `cap_loads`, `cap_stores`, `cap_dst_regs` and the `cap_*_lane_masks` family
# in champsim_tracer_output.cc are "cap" as in CAPPED -- the wire's per-slot
# ceiling -- and share three letters with a library they have nothing to do
# with.  The pass caught it and printed a correction under the table, which is
# the right response to a reading and the wrong place for the fix: the next
# census would have written the same pattern and reported the same 23.
#
# So the pattern here matches CAPSTONE'S OWN BOUNDARY NAMES, enumerated, and
# never a bare `cap_` prefix.  The names are QEMU's disassembler boundary
# (disas/capstone.c) plus the library's own API: a call into Capstone is one
# of these or it does not exist.  A NEW boundary name added to disas/capstone.c
# and not added here would be missed, so the list is checked against that file
# and a name found there but absent here FAILS the census rather than being
# silently uncounted.
#
# Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../../.." && pwd)
BUILD=${BUILD:-$ROOT/build}
PLUGIN=$ROOT/contrib/plugins/champsim_tracer

#: Capstone's boundary, by NAME.  `cap_disas*`/`cap_fill_*`/`cap_arch`/
#: `cap_mode_for_target` are QEMU's own wrappers in disas/capstone.c; `cs_*`
#: is the library's API.  Nothing else is a call into Capstone, and no bare
#: `cap_` prefix appears here -- see the header.
CAPSTONE_FNS='cap_disas|cap_fill|cap_arch|cap_mode|cap_create|cap_insn|cap_open|cap_close|cap_dump'
CS_SYMS='\bcs_(open|close|disasm|free|malloc|option|reg_name|insn_name|group_name|version|support|errno|strerror)\b'

fail=0
say() { printf '%s\n' "$*"; }

say "=== CAPSTONE CENSUS at $(cd "$ROOT" && git rev-parse --short=10 HEAD) ==="
say ""

say "-- A. SHIPPED PLUGIN .so"
so=$BUILD/contrib/plugins/libchampsim_tracer.so
if [ ! -f "$so" ]; then
    say "   REFUSING: $so does not exist -- a census that cannot find its"
    say "   subject is not a zero."
    exit 2
fi
ls -l "$so" | sed 's/^/   /'
say "   nm cs_* ALL (incl. local) : $(nm -a "$so" 2>/dev/null | grep -cE ' cs_' || true)"
say "   strings 'apstone'         : $(strings "$so" | grep -c 'apstone' || true)"
say "   DT_NEEDED capstone        : $(objdump -p "$so" 2>/dev/null | grep -c 'NEEDED.*capstone' || true)"
say ""

#
# ROW B IS NOT A MUST-BE-0 AND MUST NOT BE READ AS ONE.  An emulator links
# Capstone for `-d in_asm' disassembly through disas/capstone.c, which row D
# names as the ALLOWED boundary: it is QEMU's disassembler, reached by a human
# reading a log, and no wire fact passes through it.  The rows are printed so
# a reader can see WHICH object carries the dependency; the census's verdict
# is rows A and C, which are the tracer's own.
#
say "-- B. SHIPPED EMULATORS (reported, not judged -- see the note above)"
for t in x86_64 aarch64 riscv64 mipsel; do
    q=$BUILD/qemu-$t
    [ -x "$q" ] || { say "   qemu-$t: ABSENT (not built here)"; continue; }
    say "   qemu-$t: nm-cs=$(nm -a "$q" 2>/dev/null | grep -cE ' cs_' || true)" \
        "strings=$(strings "$q" | grep -c 'apstone' || true)" \
        "DT_NEEDED=$(objdump -p "$q" 2>/dev/null | grep -c 'NEEDED.*capstone' || true)"
done
say ""

#
# THE SUBJECT IS THE SHIPPED PLUGIN, WHICH IS ITS OWN DIRECTORY AND NOT THE
# APPARATUS UNDER IT.  tools/ holds the OFFLINE REFEREE -- cst_referee.py
# disassembles recorded bytes through the Python bindings ON PURPOSE, and row
# E is where it is listed.  Counting its cs_version() as plugin reach would
# report the referee's whole reason for existing as a defect, which is the
# mirror image of the cap_ trap: a pattern that is right about its letters and
# wrong about its subject.  So row C reads the plugin's own translation units
# and headers, at depth one, and nothing below them.
#
say "-- C. SOURCE: live Capstone reach from the SHIPPED PLUGIN (depth 1)"
#
# A SHELL GLOB, NOT `find'.  A `find -maxdepth 1 -name A -o -name B'
# expression recurses through the second clause, and this census read the
# whole subtree with it -- reporting the OFFLINE REFEREE's own Capstone
# calls as plugin reach, which is the cap_ trap wearing a different hat.
#
src="$PLUGIN/*.cc $PLUGIN/*.h"
inc=$(grep -lE '^[[:space:]]*#[[:space:]]*include.*capstone' $src 2>/dev/null | wc -l)
say "   live #include of a capstone header : $inc"
[ "$inc" -eq 0 ] || fail=1
#
# THE CALL COUNT IS OVER NAMES, NOT OVER A PREFIX (250-I).  A bare `cap_`
# pattern reports the wire's CAPPED-slot helpers and says nothing about
# Capstone; see this file's header for the twenty-three that were.
#
calls=$(grep -hoE "($CAPSTONE_FNS)[a-z_]*[[:space:]]*\(" $src 2>/dev/null | wc -l)
cssym=$(grep -hoE "$CS_SYMS" $src 2>/dev/null | wc -l)
say "   calls to a Capstone boundary fn    : $calls"
say "   references to a cs_* API symbol    : $cssym"
[ "$calls" -eq 0 ] || fail=1
[ "$cssym" -eq 0 ] || fail=1
#
# AND THE TRAP IS PROVEN SHUT, not asserted: the CAPPED-slot names must be
# present in the tree (they are live wire code) and must NOT be counted above.
# A tree where they vanished would make this check vacuous, so their absence
# REFUSES rather than passing quietly.
#
capped=$(grep -hoE '\bcap_(min|loads|stores|dst_regs|src_regs)[a-z_]*' \
             $src 2>/dev/null | wc -l)
say "   CAPPED-slot names in the tree      : $capped (must be > 0, and are"
say "                                        NOT counted in the two rows above)"
if [ "$capped" -eq 0 ]; then
    say "   REFUSING: the CAPPED-slot names this census must not confuse with"
    say "   Capstone are absent, so the separation it proves has no subject."
    exit 2
fi
say ""

say "-- D. QEMU-side boundary (ALLOWED: disassembly, not the wire)"
say "   disas/capstone.c present : $([ -f "$ROOT/disas/capstone.c" ] && echo yes || echo no)"
#
# EVERY BOUNDARY NAME disas/capstone.c DEFINES MUST BE IN $CAPSTONE_FNS.  A
# name added there and not added here would be a call this census cannot see,
# which is the failure mode the enumeration replaced a prefix to avoid -- so
# the enumeration is checked against the file rather than trusted.
#
if [ -f "$ROOT/disas/capstone.c" ]; then
    miss=0
    #
    # FUNCTIONS, NOT TYPES.  `cap_skipdata_s' is a struct -- the name of a
    # Capstone option's payload, never called -- and listing it as an
    # uncovered boundary would make this check fail on a thing that cannot be
    # a call.  A boundary name is one that appears followed by `(`.
    #
    for n in $(grep -hoE '\bcap_[a-z_]+[[:space:]]*\(' "$ROOT/disas/capstone.c" |
               grep -oE 'cap_[a-z_]+' | sort -u); do
        printf '%s' "$n" | grep -qE "^($CAPSTONE_FNS)" || {
            say "   UNCOVERED boundary name: $n"
            miss=1
        }
    done
    say "   every disas/capstone.c boundary name covered : $([ $miss -eq 0 ] && echo yes || echo NO)"
    [ $miss -eq 0 ] || fail=1
fi
say ""

say "-- E. OFFLINE REFEREE (allowed: over recorded bytes, out of process)"
for f in gapreport.py cst_referee.py gen_src_survivors.py srcenc_sled.py; do
    [ -f "$PLUGIN/tools/$f" ] && say "   contrib/plugins/champsim_tracer/tools/$f"
done
say ""
say "CAPSTONE CENSUS $([ $fail -eq 0 ] && echo PASSED || echo FAILED)"
exit $fail
