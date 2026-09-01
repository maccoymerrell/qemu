#!/bin/bash
# THE EIGHT isaxcheck ARMS UNDER THE WIRE'S OWN SOURCE LIST.
#
#   isax_srcenc_gate.sh run  <build-dir> <out-dir> <corpus-dir> [isa...]
#   isax_srcenc_gate.sh bare <build-dir> <out-dir>              [isa...]
#   isax_srcenc_gate.sh --selftest
#
# `run` scores the read classes against the corpus (`--srcenc`); `bare` is
# the same eight arms without it, which is what the tree has always run.
# A corpus directory carries one file per ISA named `<isa>.tsv`, written by
# `CST_SRC_ENC_DUMP` through tools/srcenc_sled.py.
#
# WHY THIS EXISTS AS A GATE AND NOT AS A ONE-OFF INVOCATION.
#
# isaxcheck scores the tracer's READ side by decoding an encoding in the
# tool's own process and asking the tracer's model about that decode.  The
# wire's sources are no longer built that way -- they are QEMU's ordered
# read list, stated at translation time inside the emulator, plus the
# survivor rows for what QEMU does not state -- and neither is reachable
# from a host tool.  With the operand walk's read arm removed the read
# classes therefore do not go RED and do not go GREEN: their SUBJECT
# vanishes.  Measured under exec72's banked deletion at 38373b47be, the
# bare arms read
#
#     dead_allow_rules  1037 (x86_64 fields)   892 (aarch64 boundary)
#                        947 (aarch64 fields)  877 (riscv64 fields)
#                        252 (mipsel fields)
#
# and 10,398 new signatures, essentially all of the form `FR-rd-missing
# <mnem> +<regs>` with `fieldsRD{-}` -- one defect reported ten thousand
# times.  Under `run` with a corpus captured from the same build the dead
# count is 0 on seven arms of eight, and the eighth's 25 dead rules are
# memory rules, not read rules.  That is the difference between an
# instrument measuring the tracer and an instrument measuring its own
# plumbing.
#
# REACH IS PRINTED AND UNREACHED RULES ARE NAMED.  An encoding the corpus
# does not carry is scored by nothing; `ISAX_DUMP_UNREACHED` is exported so
# every wholly unreached mnemonic is listed with its encoding count beside
# the arm that could not see it.  isaxcheck itself exits 2 when a corpus
# answers nothing at all, and rc=2 is never folded into rc=0 here: an arm
# that reaches nothing must not report all-clear.
#
# rc=0 every arm green, rc=1 an arm failed, rc=2 the gate could not look.
#
# Author: Maccoy Merrell.
set -u

ALL_ISAS="x86_64 aarch64 riscv64 mipsel"

usage() {
    sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

# One arm.  $1 layer tag, $2 isa, $3 build, $4 out, $5 corpus file or "".
arm() {
    local layer=$1 isa=$2 build=$3 out=$4 corpus=$5
    local tools; tools=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    local se=() extra=()
    [ -n "$corpus" ] && se=(--srcenc="$corpus")
    local allow
    if [ "$layer" = fields ]; then
        allow=$tools/isaxcheck_fields_allow.txt
        extra=(--layer=fields --classes=MBR)
    else
        allow=$tools/isaxcheck_allow.txt
    fi
    "$build/contrib/plugins/isaxcheck" --isa="$isa" --check \
        --jobs="${ISAX_JOBS:-12}" "${se[@]}" "${extra[@]}" \
        --allow="$allow" > "$out/${layer:0:1}_$isa.txt" 2>&1
    return $?
}

run_arms() {
    local build=$1 out=$2 corpusdir=$3; shift 3
    local isas="${*:-$ALL_ISAS}"
    [ -x "$build/contrib/plugins/isaxcheck" ] || {
        echo "isax_srcenc_gate: REFUSED -- no isaxcheck in $build" >&2; return 2; }
    mkdir -p "$out" || return 2
    export ISAX_DUMP_UNREACHED=1
    : > "$out/rc.txt"
    {
      echo "SO_SHA=$(sha256sum "$build/contrib/plugins/libchampsim_tracer.so" | cut -c1-16)"
      echo "ISAX_SHA=$(sha256sum "$build/contrib/plugins/isaxcheck" | cut -c1-16)"
      echo "CORPUS_DIR=${corpusdir:-<none>}"
    } >> "$out/rc.txt"
    local worst=0 isa layer corpus r
    for isa in $isas; do
        corpus=""
        if [ -n "$corpusdir" ]; then
            corpus=$corpusdir/$isa.tsv
            if [ ! -f "$corpus" ]; then
                echo "REFUSED $isa -- no corpus file $corpus" >> "$out/rc.txt"
                worst=2; continue
            fi
            echo "corpus $isa md5=$(md5sum "$corpus" | cut -d' ' -f1)" \
                 "rows=$(grep -vc '^#' "$corpus")" >> "$out/rc.txt"
        fi
        for layer in boundary fields; do
            arm "$layer" "$isa" "$build" "$out" "$corpus"; r=$?
            printf '%-8s %-8s rc=%d\n' "$layer" "$isa" "$r" >> "$out/rc.txt"
            # rc=2 dominates rc=1: "could not look" is never a mere failure.
            [ "$r" = 2 ] && worst=2
            [ "$r" = 1 ] && [ "$worst" = 0 ] && worst=1
            grep -h '^# srcenc=' "$out/${layer:0:1}_$isa.txt" >> "$out/rc.txt" 2>/dev/null
            local u
            u=$(grep -c '^UNREACHED' "$out/${layer:0:1}_$isa.txt" 2>/dev/null || echo 0)
            [ "$u" != 0 ] && echo "  unreached_mnemonics_named=$u (UNREACHED lines" \
                "in ${layer:0:1}_$isa.txt)" >> "$out/rc.txt"
        done
    done
    echo "ALL_ARMS_DONE worst_rc=$worst" >> "$out/rc.txt"
    cat "$out/rc.txt"
    return $worst
}

# The gate's own proof that it can refuse.  It does not run isaxcheck: the
# arms take minutes each and what is under test here is this script's
# refusal and roll-up, which is where a gate silently turns 2 into 0.
selftest() {
    local t f=0
    t=$(mktemp -d) || return 2
    run_arms "$t/nobuild" "$t/o1" "" >/dev/null 2>&1
    [ $? = 2 ] && echo "PASS  A a build dir with no isaxcheck REFUSES (rc=2)" \
               || { echo "FAIL  A"; f=$((f+1)); }
    mkdir -p "$t/b/contrib/plugins"
    printf '#!/bin/sh\nexit 0\n' > "$t/b/contrib/plugins/isaxcheck"
    chmod +x "$t/b/contrib/plugins/isaxcheck"
    : > "$t/b/contrib/plugins/libchampsim_tracer.so"
    mkdir -p "$t/corpus_empty"
    run_arms "$t/b" "$t/o2" "$t/corpus_empty" x86_64 >/dev/null 2>&1
    [ $? = 2 ] && echo "PASS  B a corpus with no file for the ISA REFUSES (rc=2)" \
               || { echo "FAIL  B"; f=$((f+1)); }
    grep -q '^REFUSED x86_64' "$t/o2/rc.txt" \
        && echo "PASS  B2 and the missing corpus file is NAMED" \
        || { echo "FAIL  B2"; f=$((f+1)); }
    mkdir -p "$t/corpus_ok"; printf 'x86_64\t90\tnop\t-\n' > "$t/corpus_ok/x86_64.tsv"
    run_arms "$t/b" "$t/o3" "$t/corpus_ok" x86_64 >/dev/null 2>&1
    [ $? = 0 ] && echo "PASS  C a green arm rolls up rc=0" \
               || { echo "FAIL  C"; f=$((f+1)); }
    printf '#!/bin/sh\nexit 1\n' > "$t/b/contrib/plugins/isaxcheck"
    run_arms "$t/b" "$t/o4" "$t/corpus_ok" x86_64 >/dev/null 2>&1
    [ $? = 1 ] && echo "PASS  D a failing arm rolls up rc=1" \
               || { echo "FAIL  D"; f=$((f+1)); }
    printf '#!/bin/sh\nexit 2\n' > "$t/b/contrib/plugins/isaxcheck"
    run_arms "$t/b" "$t/o5" "$t/corpus_ok" x86_64 >/dev/null 2>&1
    [ $? = 2 ] && echo "PASS  E rc=2 is NOT folded into rc=1" \
               || { echo "FAIL  E"; f=$((f+1)); }
    # A run whose arms disagree must report the worst, not the last.
    cat > "$t/b/contrib/plugins/isaxcheck" <<'SH'
#!/bin/sh
case "$*" in *--layer=fields*) exit 0 ;; *) exit 2 ;; esac
SH
    chmod +x "$t/b/contrib/plugins/isaxcheck"
    run_arms "$t/b" "$t/o6" "$t/corpus_ok" x86_64 >/dev/null 2>&1
    [ $? = 2 ] && echo "PASS  F the WORST arm decides, not the last one" \
               || { echo "FAIL  F"; f=$((f+1)); }
    grep -q 'ISAX_DUMP_UNREACHED' "${BASH_SOURCE[0]}" \
        && echo "PASS  G the unreached dump is armed by the gate itself" \
        || { echo "FAIL  G"; f=$((f+1)); }
    rm -rf "$t"
    echo "isax_srcenc_gate selftest: $f failure(s)"
    [ "$f" = 0 ] || return 1
    return 0
}

[ $# -ge 1 ] || usage
case "$1" in
  --selftest) selftest ;;
  run)  shift; [ $# -ge 3 ] || usage; b=$1 o=$2 c=$3; shift 3; run_arms "$b" "$o" "$c" "$@" ;;
  bare) shift; [ $# -ge 2 ] || usage; b=$1 o=$2; shift 2; run_arms "$b" "$o" "" "$@" ;;
  *) usage ;;
esac
