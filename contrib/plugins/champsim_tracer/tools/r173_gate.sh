#!/bin/bash
# R17.3 -- THE INVOCATION-INVARIANCE ORACLE, as a tree harness.
#
#   r173_gate.sh <build-dir> <out-dir> --workload-dir DIR [--wp A --wp B]
#
# R17 made this a STANDING ORACLE: "SETS ARE INVOCATION-INVARIANT".  The
# enumerated source and destination sets of a STATIC instruction do not
# depend on how the instruction was reached, so the same (pc, encoding)
# occurring under two different wrong-path depths must state the same
# src=[] and dst=[].  Two runs at different wpdepth are the cheapest way to
# reach one instruction through different chains.
#
# WHY IT IS IN THE TREE.  It lived as a pass-local script that each wave
# copied and edited, and exec107 recorded what that costs (CORRECTIONS C4):
# the wp values are named in a `for` loop and the checker was then handed
# FIXED file names built from them in three separate places.  Changing the
# loop to fresh values -- which every pass is supposed to do -- left the
# checker reading `x86_64_wp46.raw` while the run had written
# `x86_64_wp52.raw`.  The result was a FileNotFoundError traceback and a
# planted control with no input, under a last line that still read
# `rc=1 (non-zero REQUIRED)`.  A reader skimming for that line would have
# scored a green.
#
# So the names are DERIVED from the loop variable and from nothing else,
# the wp values are arguments, and every rc is read from the process that
# produced it.  A checker handed a file that does not exist REFUSES.
#
# THE PLANTED CONTROL IS A ROW, NOT AN EXTRA.  An oracle whose headline is
# VARIANT=0 is exactly as consistent with "the sets are invariant" as with
# "the oracle never reached its subject", so one source list is damaged in
# one dump and the checker is REQUIRED to report VARIANT>0 on it.  A
# control that cannot be armed -- no pc with two occurrences and a
# multi-register source -- is a FAILURE, never a skip.
#
# Author: Maccoy Merrell.
# SPDX-License-Identifier: GPL-2.0-or-later
set -u

usage() {
    sed -n '2,6p' "$0"
    echo "  --wp N        repeatable; two or more depths, DIFFERENT each pass"
    echo "  --isa NAME    repeatable; default x86_64 aarch64 riscv64 mipsel"
}

[ $# -ge 2 ] || { usage >&2; exit 2; }
Q=$1; O=$2; shift 2
WORKLOAD=${CST_R173_WORKLOAD:-}
PY=${CST_PYTHON:-python3}
WPS=()
ISAS=()
while [ $# -gt 0 ]; do
    case $1 in
        --workload-dir) WORKLOAD=$2; shift 2 ;;
        --wp)           WPS+=("$2"); shift 2 ;;
        --isa)          ISAS+=("$2"); shift 2 ;;
        --python)       PY=$2; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "r173_gate: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
done
[ ${#WPS[@]} -ge 2 ] || WPS=(56 58)
[ ${#ISAS[@]} -ge 1 ] || ISAS=(x86_64 aarch64 riscv64 mipsel)
T=$(cd "$(dirname "$0")" && pwd)

if [ -z "$WORKLOAD" ] || [ ! -d "$WORKLOAD" ]; then
    echo "r173_gate: REFUSED -- no workload directory (--workload-dir)." >&2
    echo "  It must hold prog, prog.a64, prog.rv64, prog.mipsel." >&2
    exit 2
fi
mkdir -p "$O" || exit 2
RC=$O/RC.txt
: > "$RC"
RED=0
say() { printf '%s\n' "$*" >> "$RC"; }
note() { local rc=$1; shift; say "$(printf 'rc=%-3s %s' "$rc" "$*")"
         [ "$rc" -eq 0 ] || RED=1; }

bin_for() {
    case $1 in
        x86_64)  echo "$WORKLOAD/prog" ;;
        aarch64) echo "$WORKLOAD/prog.a64" ;;
        riscv64) echo "$WORKLOAD/prog.rv64" ;;
        mipsel)  echo "$WORKLOAD/prog.mipsel" ;;
        *)       echo "" ;;
    esac
}

say "r173_gate  build=$Q  out=$O"
say "TIP=$(git -C "$T" rev-parse HEAD 2>/dev/null || echo '?')"
say "SO_SHA=$(sha256sum "$Q/contrib/plugins/libchampsim_tracer.so" | cut -c1-16)"
say "WP=${WPS[*]}  ISA=${ISAS[*]}"

# ---- the runs.  Every output path is built ONCE, here, from the loop -----
declare -a DUMPS=()
for wp in "${WPS[@]}"; do
    for isa in "${ISAS[@]}"; do
        b=$(bin_for "$isa")
        if [ -z "$b" ] || [ ! -x "$b" ]; then
            note 2 "run $isa wp=$wp -- no workload binary at '$b'"
            continue
        fi
        o=$O/${isa}_wp${wp}
        setarch -R "$Q/qemu-$isa" \
            -plugin "$Q/contrib/plugins/libchampsim_tracer.so,outfile=$o,wpdepth=$wp,compress=zstd -T0 -3 -q -c" \
            "$b" > "$o.stdout" 2> "$o.stats.log"
        note $? "run $isa wp=$wp"
        "$Q/contrib/plugins/cst_decode" --format=raw "$o.cst" > "$o.raw" 2> "$o.derr"
        note $? "decode $isa wp=$wp"
        rm -f "$o.cst"
        DUMPS+=("$o.raw")
    done
done

# ---- the oracle, per wp, over the dumps THAT RUN ACTUALLY WROTE ----------
for wp in "${WPS[@]}"; do
    set -- $(printf '%s\n' "${DUMPS[@]}" | grep -E "_wp${wp}\.raw$" || true)
    if [ $# -eq 0 ]; then
        note 2 "R17.3 wp=$wp -- no dump was produced; the oracle has no subject"
        continue
    fi
    "$PY" "$T/r173_check.py" "$@" > "$O/R173_wp${wp}.txt" 2>&1
    note $? "R17.3 invocation-invariance, wp=$wp, $# dump(s)"
    cat "$O/R173_wp${wp}.txt"
done

# ---- the planted control ------------------------------------------------
FIRST=""
for d in "${DUMPS[@]}"; do case $d in *x86_64_wp*) FIRST=$d; break;; esac; done
[ -n "$FIRST" ] || FIRST=${DUMPS[0]:-}
if [ -z "$FIRST" ]; then
    note 2 "PLANTED CONTROL -- no dump to damage; VARIANT=0 above proves nothing"
else
    "$PY" "$T/r173_plant.py" "$FIRST" "$O/plant.raw" > "$O/PLANT.txt" 2>&1
    if [ $? -ne 0 ]; then
        note 2 "PLANTED CONTROL COULD NOT BE ARMED -- $(tail -1 "$O/PLANT.txt")"
    else
        "$PY" "$T/r173_check.py" "$O/plant.raw" >> "$O/PLANT.txt" 2>&1
        prc=$?
        if [ "$prc" -eq 0 ]; then
            note 1 "PLANTED CONTROL -- the oracle read a DAMAGED dump as clean"
        else
            note 0 "PLANTED CONTROL -- the oracle REFUSED the damaged dump (rc=$prc)"
        fi
    fi
    cat "$O/PLANT.txt"
fi

say "R173_DONE red=$RED"
cat "$RC"
exit $RED
