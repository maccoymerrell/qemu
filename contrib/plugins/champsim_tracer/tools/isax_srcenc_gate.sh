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
# THE JOIN IS SEPARATED FROM THE DATAFLOW.  A corpus row is keyed on bytes
# and the reference answer is LLVM's decode of those bytes; when the two
# decoders read the bytes as DIFFERENT INSTRUCTIONS the resulting register
# difference is a JOIN FAILURE, not a tracer finding, and scoring it as one
# inflates the residue with rows no dataflow change can close.  Such rows are
# separated into their own `JOINFAIL` family, counted by ordered mnemonic
# pair, and reported on the `# srcenc_join` line beside the scored count --
# never dropped.  See the --srcenc commentary in isaxcheck.cc for the test.
#
# REACH IS PRINTED AND UNREACHED RULES ARE NAMED.  An encoding the corpus
# does not carry is scored by nothing; `ISAX_DUMP_UNREACHED` is exported so
# every wholly unreached mnemonic is listed with its encoding count beside
# the arm that could not see it.  isaxcheck itself exits 2 when a corpus
# answers nothing at all, and rc=2 is never folded into rc=0 here: an arm
# that reaches nothing must not report all-clear.
#
# rc=0 every arm green, rc=1 an arm failed, rc=2 the gate could not look --
# and "could not look" includes a BARE arm over an allowlist carrying
# `SR-rd-*` rules, which that arm never scores.  See the NOT-A-FULL-GATE
# roll-up in run_arms() and FINDING 65-D.
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
    local worst=0 partial=0 isa layer corpus r
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
            grep -hE '^# srcenc=|^# srcenc_join ' "$out/${layer:0:1}_$isa.txt" \
                >> "$out/rc.txt" 2>/dev/null
            # THE PARTIALITY OF A BARE ARM IS STATED, NOT INFERRED.
            # isaxcheck exempts the `SR-rd-*` family from its dead-rule
            # detector in a bare arm, because a bare arm never scores that
            # family -- correct, and silent.  FINDING 65-D: two mipsel
            # `SR-rd-phantom` rows landed DEAD, the eight standing bare arms
            # all reported `dead_allow_rules=0`, and exec110's table quoted
            # that eight times.  A bare arm is not a full gate over an
            # allowlist carrying rules it cannot reach, and it says so here.
            local sup
            sup=$(sed -n 's/.*superseded_allow_rules=\([0-9]*\).*/\1/p' \
                  "$out/${layer:0:1}_$isa.txt" | head -1)
            if [ -z "$corpus" ] && [ -n "${sup:-}" ] && [ "${sup:-0}" -gt 0 ]; then
                echo "  NOT-A-FULL-GATE $layer $isa: $sup allowlist rule(s)" \
                     "in SR-rd-* are UNSCORED by a bare arm -- their" \
                     "dead/live state is unknown here.  Run this gate as" \
                     "\`run <build> <out> <corpus>\` to score them." \
                     >> "$out/rc.txt"
                partial=$((partial+1))
            fi
            # Only a --srcenc arm has a reach to report.  `grep -c` exits 1
            # on zero matches, so its status is discarded rather than turned
            # into a second count by an `|| echo`.
            if [ -n "$corpus" ]; then
                local u
                u=$(grep -c '^UNREACHED' "$out/${layer:0:1}_$isa.txt" 2>/dev/null) || true
                echo "  unreached_mnemonics_named=${u:-0} (UNREACHED lines in" \
                     "${layer:0:1}_$isa.txt)" >> "$out/rc.txt"
                # The join census is bounded by DISTINCT mnemonic pairs, so
                # its line count is a number worth carrying beside the reach.
                local j
                j=$(grep -c '^JOINFAIL' "$out/${layer:0:1}_$isa.txt" 2>/dev/null) || true
                echo "  joinfail_pairs_named=${j:-0} (JOINFAIL lines in" \
                     "${layer:0:1}_$isa.txt)" >> "$out/rc.txt"
            fi
        done
    done
    echo "ALL_ARMS_DONE worst_rc=$worst unscored_arms=$partial" >> "$out/rc.txt"
    # An arm that could not look at part of its allowlist is the gate's own
    # rc=2 case -- "could not look" -- not a pass.  Rolling it up as rc=0 is
    # what let 65-D's two rows through a gate built to catch them.
    [ "$partial" -gt 0 ] && [ "$worst" = 0 ] && worst=2
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
    # H/I: FINDING 65-D.  A bare arm over an allowlist carrying rules it
    # never scores is not a pass, and the count has to be the tool's own.
    cat > "$t/b/contrib/plugins/isaxcheck" <<'SH'
#!/bin/sh
echo "# isa=x86_64 layer=boundary encodings_tried=1 distinct_signatures=0 \
allowlisted=0 unallowed=0 subtarget_gap=0/0 size_gap=0/0 dead_allow_rules=0 \
superseded_allow_rules=327 unscored_family=SR-rd-* ambiguous_reg_tokens=0"
exit 0
SH
    chmod +x "$t/b/contrib/plugins/isaxcheck"
    run_arms "$t/b" "$t/o7" "" x86_64 >/dev/null 2>&1
    [ $? = 2 ] && echo "PASS  H a BARE arm with unscored allowlist rules is rc=2, not rc=0" \
               || { echo "FAIL  H"; f=$((f+1)); }
    grep -q 'NOT-A-FULL-GATE boundary x86_64: 327 ' "$t/o7/rc.txt" \
        && echo "PASS  I and the unscored count is NAMED with its arm" \
        || { echo "FAIL  I"; f=$((f+1)); }
    # J: the same arm WITH a corpus is a full gate and stays green.
    run_arms "$t/b" "$t/o8" "$t/corpus_ok" x86_64 >/dev/null 2>&1
    [ $? = 0 ] && echo "PASS  J the same arm WITH a corpus rolls up rc=0" \
               || { echo "FAIL  J"; f=$((f+1)); }
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
