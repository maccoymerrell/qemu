#!/bin/bash
# THE --srcenc SWEEP AND THE ASSEMBLY OF ITS SILENCE PARTITION.
#
# Two jobs, one file, because the second one drifted away from the first when
# they lived apart.  `sweep` runs srcenc_sled.py over an encoding population
# for every (ISA, wp) arm; `assemble` folds the per-arm captures into the
# per-ISA corpus (`<isa>.tsv`) and its silence partition (`<isa>.refused.tsv`)
# that isax_srcenc_gate.sh and isaxcheck read.
#
# WHY IT IS IN THE TREE.  FINDING 97-A.  `3207b08e4e` gave srcenc_sled.py a
# third silence token, `DECODED-AT-ANOTHER-LENGTH`, and taught the gate and
# isaxcheck to count it.  The assembler was a per-run-directory `sweep.sh`
# copied forward from pass to pass, it selected `$3=="REFUSED"` and
# `$3=="UNATTRIBUTED"` and nothing else, and so the 35,919 x86_64 encodings
# the sled had just explained left the capture and arrived nowhere.  The
# assembled file stopped being the partition its own header promised, and a
# count improved because a category had stopped being written.  A landing
# pass could not carry the fix because the file it had to change was not in
# the tree.  It is now.
#
# THE PARTITION, AND WHAT EACH PART MEANS TO A CONSUMER:
#
#   covered      the encoding produced a corpus row in SOME arm.  It is not
#                silent at all and leaves every list, even if this arm was
#                silent about it -- an answer from either arm is an answer.
#   REFUSED      QEMU's admission gate declined the block.  A rule whose
#                subjects are all of this kind HAS been superseded, and this
#                is the only token that may excuse one.
#   DECODED-AT-ANOTHER-LENGTH
#                QEMU translated the slot and the plugin DID write a row --
#                under the bytes the decoder consumed, not the bytes the
#                sweep planted.  Nothing refused it, so it may NOT excuse a
#                rule; and it is not a hole, so it may not be pooled with
#                UNATTRIBUTED either.  The fourth column names the key the
#                answer went to, and it is carried through the assembly.
#   UNATTRIBUTED a population encoding with no row and no recorded cause.
#                The reason a rule may NOT be excused.
#
# CROSS-ARM DISAGREEMENT IS REFUSED, NOT RANKED.  If one arm calls an
# encoding REFUSED and another calls it DECODED-AT-ANOTHER-LENGTH, no
# precedence between them is honest: one would excuse a rule the other says
# nothing refused.  Measured at 3f11049dc5 over all four ISAs and both wp
# arms, all three pairwise intersections are EMPTY, so no precedence is in
# use today and inventing one would be an unadjudicated rule nothing needs.
# A future capture that does disagree stops here and gets adjudicated.
#
# Usage:
#   srcenc_sweep.sh sweep    --build-dir D --pop P --sled S --out O \
#                            [--isa X]... [--wp N]... [--nice] [--mech]
#   srcenc_sweep.sh assemble --sled S --out O [--isa X]... [--wp N]...
#   srcenc_sweep.sh --selftest [TMPDIR]
#
# EXIT STATUS IS THE RESULT, not the last echo.
#
# Author: Maccoy Merrell.
set -u

# ONE COLLATION FOR THE WHOLE ASSEMBLY.  `sort`, `comm` and `join` must agree
# about order or `comm` silently mis-partitions and `join` silently drops
# rows -- both of which are the shape this file exists to stop.
export LC_ALL=C

HERE=$(cd "$(dirname "$0")" && pwd)
SLED=$HERE/srcenc_sled.py
PY="${PYTHON:-python}"

ISAS_DEFAULT="x86_64 aarch64 riscv64 mipsel"
WPS_DEFAULT="0 16"

die() { echo "srcenc_sweep: $*" >&2; exit 2; }

# ---------------------------------------------------------------- assembly
#
# One ISA's arms -> $OUT/<isa>.tsv and $OUT/<isa>.refused.tsv.
# Echoes one RC line.  Returns non-zero on a refusal.
assemble_isa() {
    local S=$1 OUT=$2 isa=$3; shift 3
    local wps=("$@")
    local wp a b t0 s0 f

    local corpora=() refuseds=()
    for wp in "${wps[@]}"; do
        a=$S/$isa.wp$wp/corpus_$isa.tsv
        b=$S/$isa.wp$wp/refused_$isa.tsv
        [ -f "$a" ] || { echo "REFUSE: $isa wp$wp has no corpus $a"; return 2; }
        [ -f "$b" ] || { echo "REFUSE: $isa wp$wp has no refused set $b"; return 2; }
        corpora+=("$a"); refuseds+=("$b")
    done

    # THE STAMPS.  Every arm must describe ONE tree and ONE BUILD; two builds
    # do not describe one admission gate (92-C).
    #
    # AND A BUILD IS TWO BINARIES (FINDING 98-B).  The sled launches
    # `qemu-<isa>` with `libchampsim_tracer.so` loaded into it, and every
    # corpus row is the plugin's callback reading facts the EMULATOR
    # exported -- so a `target/<isa>/` change moves the rows with the plugin
    # byte-identical, and a stamp naming only the plugin cannot tell arm A
    # from arm B.  MEASURED at cf6bf3b64f: 1,459 x86_64 encodings left the
    # corpus while `#so`'s plugin field read 6bee8d520b02e3f3 in both arms.
    # `#so` now carries `<plugin>\t<emulator>`; a one-field stamp is a
    # corpus captured before that and is REFUSED rather than compared on the
    # half it happens to have.
    t0=$(sed -n '1p' "${corpora[0]}"); s0=$(sed -n '2p' "${corpora[0]}")
    case "$t0" in '#tip'*) ;; *) echo "REFUSE: $isa has no #tip stamp"; return 2;; esac
    case "$s0" in '#so'*)  ;; *) echo "REFUSE: $isa has no #so stamp";  return 2;; esac
    case "$s0" in *unknown*) echo "REFUSE: $isa #so is unknown"; return 2;; esac
    [ "$(printf '%s' "$s0" | awk -F'\t' '{print NF}')" -ge 3 ] \
        || { echo "REFUSE: $isa #so names one binary, not two -- it was" \
                  "captured before the emulator stamp (98-B) and cannot be" \
                  "shown to describe THIS emulator"; return 2; }
    for f in "${corpora[@]}" "${refuseds[@]}"; do
        [ "$(sed -n '1p' "$f")" = "$t0" ] \
            || { echo "REFUSE: $isa $f carries a different #tip"; return 2; }
        [ "$(sed -n '2p' "$f")" = "$s0" ] \
            || { echo "REFUSE: $isa $f carries a different #so"; return 2; }
    done

    # THE CORPUS: the union of the arms' rows.
    { printf '%s\n' "$t0"; printf '%s\n' "$s0"
      cat "${corpora[@]}" | grep -v '^#' | sort -u ; } > "$OUT/$isa.tsv"
    local n dup
    n=$(grep -vc '^#' "$OUT/$isa.tsv")
    dup=$(grep -v '^#' "$OUT/$isa.tsv" | cut -f2 | sort | uniq -d | wc -l)
    [ "$n" -gt 0 ] || { echo "REFUSE: $isa corpus empty"; return 2; }

    local w=$OUT/.w_$isa
    rm -rf "$w"; mkdir -p "$w" || return 2
    grep -v '^#' "$OUT/$isa.tsv" | cut -f2 | sort -u > "$w/cov"

    # THE THREE SILENCES, each taken across the arms and then stripped of
    # anything some arm covered.  The ELSE set keeps its fourth column.
    cat "${refuseds[@]}" | grep -v '^#' | awk -F'\t' \
        '$3=="REFUSED"{print $2}' | sort -u > "$w/ref"
    cat "${refuseds[@]}" | grep -v '^#' | awk -F'\t' \
        '$3=="UNATTRIBUTED"{print $2}' | sort -u > "$w/una"
    cat "${refuseds[@]}" | grep -v '^#' | awk -F'\t' \
        '$3=="DECODED-AT-ANOTHER-LENGTH"{print $2"\t"$4}' | sort -u > "$w/els_kv"
    cut -f1 "$w/els_kv" | sort -u > "$w/els"

    # A TOKEN THIS ASSEMBLER HAS NO MEANING FOR IS A REFUSAL, not a row it
    # quietly drops.  This is 97-A's own failure mode, made loud: the sled
    # gaining a fourth token must stop the assembly rather than delete it.
    local unknown
    unknown=$(cat "${refuseds[@]}" | grep -v '^#' | awk -F'\t' \
        '$3!="REFUSED" && $3!="UNATTRIBUTED" && $3!="DECODED-AT-ANOTHER-LENGTH" \
         {print $3}' | sort -u | head -3 | tr '\n' ' ')
    if [ -n "${unknown// /}" ]; then
        echo "REFUSE: $isa refused sets carry silence token(s) [$unknown]" \
             "this assembler has no meaning for -- a row it cannot place is" \
             "not a row it may drop (FINDING 97-A)"
        return 2
    fi

    # THE LANDING KEY MUST BE ONE KEY.  Two arms naming two different keys
    # for one encoding is two answers, which is no answer.
    local nkv nk
    nkv=$(wc -l < "$w/els_kv"); nk=$(wc -l < "$w/els")
    if [ "$nkv" != "$nk" ]; then
        echo "REFUSE: $isa has $nkv (encoding,landing-key) pairs over $nk" \
             "encodings -- the arms disagree about where an answer landed"
        return 2
    fi

    comm -23 "$w/ref" "$w/cov" > "$w/ref2"
    comm -23 "$w/els" "$w/cov" > "$w/els2"
    comm -23 "$w/una" "$w/cov" > "$w/una2"

    # CROSS-ARM DISAGREEMENT: refused, not ranked.  See the header.
    local c1 c2 c3
    c1=$(comm -12 "$w/ref2" "$w/els2" | wc -l)
    c2=$(comm -12 "$w/ref2" "$w/una2" | wc -l)
    c3=$(comm -12 "$w/els2" "$w/una2" | wc -l)
    if [ "$c1" != 0 ] || [ "$c2" != 0 ] || [ "$c3" != 0 ]; then
        echo "REFUSE: $isa silence categories intersect across arms" \
             "(refused^else=$c1 refused^unattr=$c2 else^unattr=$c3) --" \
             "no precedence between them is honest, so this needs" \
             "adjudication rather than a rule"
        return 2
    fi

    local nr ne nu
    nr=$(wc -l < "$w/ref2"); ne=$(wc -l < "$w/els2"); nu=$(wc -l < "$w/una2")

    # THE PARTITION, ASSERTED RATHER THAN PROMISED.  Every encoding any arm
    # reported as silent is either covered by some arm or lands in exactly
    # one of the three categories.  This is the invariant 97-A broke, and
    # breaking it again now stops the assembly.
    local total covered placed
    cat "$w/ref" "$w/els" "$w/una" | sort -u > "$w/all"
    total=$(wc -l < "$w/all")
    covered=$(comm -12 "$w/all" "$w/cov" | wc -l)
    placed=$((nr + ne + nu))
    if [ "$total" != "$((covered + placed))" ]; then
        echo "REFUSE: $isa partition lost rows -- $total silent encodings," \
             "$covered covered by an arm, $placed placed ($nr/$ne/$nu)"
        return 2
    fi

    { printf '%s\n' "$t0"; printf '%s\n' "$s0"
      printf '#refused\tisa=%s\tencodings=%s\tunattributed=%s\t' \
             "$isa" "$nr" "$nu"
      printf 'decoded_at_another_length=%s\tassembled=wp%s\n' \
             "$ne" "$(printf '%s' "${wps[*]}" | tr ' ' '+' | sed 's/+/+wp/g')"
      printf '#isa\tencoding\tsilence\n'
      awk -v i="$isa" '{print i"\t"$1"\tREFUSED"}' "$w/ref2"
      join -t'	' "$w/els2" "$w/els_kv" \
        | awk -F'\t' -v i="$isa" \
              '{print i"\t"$1"\tDECODED-AT-ANOTHER-LENGTH\t"$2}'
      awk -v i="$isa" '{print i"\t"$1"\tUNATTRIBUTED"}' "$w/una2"
    } > "$OUT/$isa.refused.tsv"
    rm -rf "$w"

    echo "$isa rows=$n conflicting_encodings=$dup refused=$nr" \
         "decoded_at_another_length=$ne unattributed=$nu" \
         "md5=$(md5sum "$OUT/$isa.tsv" | cut -d' ' -f1)" \
         "refused_md5=$(md5sum "$OUT/$isa.refused.tsv" | cut -d' ' -f1)" \
         "$t0 $s0"
    return 0
}

cmd_assemble() {
    local S="" OUT="" isas="" wps=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --sled) S=${2:?}; shift 2 ;;
            --out)  OUT=${2:?}; shift 2 ;;
            --isa)  isas="$isas ${2:?}"; shift 2 ;;
            --wp)   wps="$wps ${2:?}"; shift 2 ;;
            *) die "assemble: unknown argument $1" ;;
        esac
    done
    [ -n "$S" ] || die "assemble: --sled is required"
    [ -n "$OUT" ] || die "assemble: --out is required"
    [ -d "$S" ] || die "assemble: no sled capture at $S"
    isas=${isas:-$ISAS_DEFAULT}; wps=${wps:-$WPS_DEFAULT}
    mkdir -p "$OUT" || exit 2
    : > "$OUT/RC.txt"
    local isa rc=0 line
    for isa in $isas; do
        # shellcheck disable=SC2086
        if line=$(assemble_isa "$S" "$OUT" "$isa" $wps); then
            echo "$line" >> "$OUT/RC.txt"
        else
            echo "$line" >> "$OUT/RC.txt"; rc=2
        fi
    done
    cat "$OUT/RC.txt"
    return $rc
}

# ------------------------------------------------------------------- sweep
cmd_sweep() {
    local B="" POP="" S="" OUT="" isas="" wps="" nice="" mech=--mech
    while [ $# -gt 0 ]; do
        case "$1" in
            --build-dir) B=${2:?}; shift 2 ;;
            --pop)  POP=${2:?}; shift 2 ;;
            --sled) S=${2:?}; shift 2 ;;
            --out)  OUT=${2:?}; shift 2 ;;
            --isa)  isas="$isas ${2:?}"; shift 2 ;;
            --wp)   wps="$wps ${2:?}"; shift 2 ;;
            --nice) nice=1; shift ;;
            --no-mech) mech=""; shift ;;
            *) die "sweep: unknown argument $1" ;;
        esac
    done
    [ -n "$B" ] || die "sweep: --build-dir is required"
    [ -n "$POP" ] || die "sweep: --pop is required (the population directory)"
    [ -n "$S" ] || die "sweep: --sled is required"
    [ -n "$OUT" ] || die "sweep: --out is required"
    isas=${isas:-$ISAS_DEFAULT}; wps=${wps:-$WPS_DEFAULT}
    mkdir -p "$S" "$OUT" || exit 2

    local so tip isa wp
    so=$(sha256sum "$B/contrib/plugins/libchampsim_tracer.so" | cut -c1-16) \
        || die "sweep: no plugin binary under $B"
    tip=$(git -C "$HERE" rev-parse HEAD)
    {
      echo "SWEEP start $(date -Is) TIP=$tip SO=$so"
      echo "DIRT=[$(git -C "$HERE" status --porcelain -uno)]"
    } > "$S/ARM.txt"

    for isa in $isas; do
        for wp in $wps; do
            (
              if [ -n "$nice" ]; then
                  set -- ionice -c3 nice -n 10 taskset -c 0-23
              else
                  set --
              fi
              # shellcheck disable=SC2086
              "$@" "$PY" "$SLED" --isa "$isa" --pop "$POP/$isa.pop.tsv" \
                   --out "$S/$isa.wp$wp" --build-dir "$B" --wp "$wp" $mech \
                   > "$S/$isa.wp$wp.log" 2> "$S/$isa.wp$wp.err"
              echo $? > "$S/$isa.wp$wp.rc"
            ) &
        done
    done
    wait

    local bad=0 rc
    for isa in $isas; do
        for wp in $wps; do
            rc=$(cat "$S/$isa.wp$wp.rc" 2>/dev/null || echo 99)
            echo "$isa wp$wp rc=$rc" >> "$S/ARM.txt"
            [ "$rc" = 0 ] || bad=1
        done
    done
    echo "SWEEP end $(date -Is) SO=$(sha256sum \
        "$B/contrib/plugins/libchampsim_tracer.so" | cut -c1-16)" \
        >> "$S/ARM.txt"
    cat "$S/ARM.txt"
    [ "$bad" = 0 ] || { echo "SWEEP REFUSING -- an arm failed"; return 1; }

    local args=(--sled "$S" --out "$OUT")
    for isa in $isas; do args+=(--isa "$isa"); done
    for wp in $wps; do args+=(--wp "$wp"); done
    cmd_assemble "${args[@]}" || return 1
    echo "SRCENC_SWEEP_DONE"
    return 0
}

# ---------------------------------------------------------------- selftest
#
# THE ASSEMBLER IS THE SUBJECT.  No emulator runs: the arms are planted
# capture directories, which is the only way to plant the shapes that matter
# (a token the assembler has no meaning for; two arms that disagree).  Every
# arm asserts, and the ones that matter most assert a REFUSAL -- 97-A was a
# silent drop, and a selftest that only checks the happy path would have
# scored the defect green.
_plant() {
    local d=$1 isa=$2 wp=$3 tip=$4 so=$5; shift 5
    # The fixture's stamp is two-field like the real one (98-B); a caller
    # that wants the ONE-field shape passes it whole and gets refused,
    # which is ARM 6b's subject.
    case "$so" in *$'\t'*) ;; *) so="$so"$'\t'"emu0000000000000" ;; esac
    mkdir -p "$d/$isa.wp$wp"
    { printf '#tip\t%s\n#so\t%s\n' "$tip" "$so"
      printf '#isa\tencoding\tsrc\n'
      printf '%s\taa\tREG_A\n' "$isa"
    } > "$d/$isa.wp$wp/corpus_$isa.tsv"
    { printf '#tip\t%s\n#so\t%s\n' "$tip" "$so"
      printf '#refused\tisa=%s\tencodings=0\n' "$isa"
      printf '#isa\tencoding\tsilence\n'
      local r
      for r in "$@"; do printf '%s\t%b\n' "$isa" "$r"; done
    } > "$d/$isa.wp$wp/refused_$isa.tsv"
}

selftest() {
    local T=${1:-/tmp/srcenc_sweep_selftest}
    rm -rf "$T"; mkdir -p "$T" || exit 2
    local fails=0 n=0
    local TIP=deadbeef SO=cafe0000

    _arm() {  # name expect_rc dir
        n=$((n + 1))
        local name=$1 want=$2 d=$3; shift 3
        local out=$T/out_$name got
        rm -rf "$out"
        cmd_assemble --sled "$d" --out "$out" --isa "$@" --wp 0 --wp 16 \
            > "$T/$name.log" 2>&1
        got=$?
        if [ "$got" != "$want" ]; then
            echo "  ARM $name FAIL: rc=$got want=$want"
            sed 's/^/    /' "$T/$name.log"
            fails=$((fails + 1)); return 1
        fi
        echo "  ARM $name ok (rc=$got)"
        return 0
    }

    # ARM 1 -- THE THIRD TOKEN SURVIVES THE ASSEMBLY.  This is 97-A itself:
    # the sled writes it, and it must be in the file the gate reads, counted
    # in the header and carrying its landing key.
    local d=$T/third
    local wp
    for wp in 0 16; do
        _plant "$d" x86_64 "$wp" "$TIP" "$SO" \
            'bb\tREFUSED' 'cc\tDECODED-AT-ANOTHER-LENGTH\tccdd' 'dd\tUNATTRIBUTED'
    done
    if _arm third 0 "$d" x86_64; then
        local f=$T/out_third/x86_64.refused.tsv
        grep -q 'decoded_at_another_length=1' "$f" \
            || { echo "  ARM third FAIL: header has no third count"; fails=$((fails+1)); }
        grep -qP '^x86_64\tcc\tDECODED-AT-ANOTHER-LENGTH\tccdd$' "$f" \
            || { echo "  ARM third FAIL: the row or its landing key is gone"; fails=$((fails+1)); }
        grep -q 'unattributed=1' "$f" \
            || { echo "  ARM third FAIL: the third token was folded into unattributed"; fails=$((fails+1)); }
        n=$((n + 3))
    fi

    # ARM 2 -- A TOKEN WITH NO MEANING STOPS THE ASSEMBLY.  The 97-A shape
    # exactly: a category the assembler does not know must not be dropped.
    d=$T/unknown
    for wp in 0 16; do
        _plant "$d" x86_64 "$wp" "$TIP" "$SO" 'bb\tREFUSED' 'ee\tSOMETHING-NEW'
    done
    _arm unknown 2 "$d" x86_64 \
        && grep -q 'has no meaning for' "$T/unknown.log" \
        || { echo "  ARM unknown FAIL: refused for the wrong reason"; fails=$((fails+1)); }
    n=$((n + 1))

    # ARM 3 -- TWO ARMS DISAGREEING ABOUT A CATEGORY IS A REFUSAL, NOT A
    # RANKING.  One arm refuses the encoding, the other says it decoded
    # elsewhere; there is no honest winner.
    d=$T/conflict
    _plant "$d" x86_64 0  "$TIP" "$SO" 'cc\tREFUSED'
    _plant "$d" x86_64 16 "$TIP" "$SO" 'cc\tDECODED-AT-ANOTHER-LENGTH\tccdd'
    _arm conflict 2 "$d" x86_64 \
        && grep -q 'silence categories intersect' "$T/conflict.log" \
        || { echo "  ARM conflict FAIL: refused for the wrong reason"; fails=$((fails+1)); }
    n=$((n + 1))

    # ARM 4 -- TWO LANDING KEYS FOR ONE ENCODING IS NO ANSWER.
    d=$T/twokeys
    _plant "$d" x86_64 0  "$TIP" "$SO" 'cc\tDECODED-AT-ANOTHER-LENGTH\tccdd'
    _plant "$d" x86_64 16 "$TIP" "$SO" 'cc\tDECODED-AT-ANOTHER-LENGTH\tcceee'
    _arm twokeys 2 "$d" x86_64 \
        && grep -q 'disagree about where an answer landed' "$T/twokeys.log" \
        || { echo "  ARM twokeys FAIL: refused for the wrong reason"; fails=$((fails+1)); }
    n=$((n + 1))

    # ARM 5 -- COVERAGE BEATS SILENCE, ACROSS ARMS.  wp16 produced a row for
    # `aa`; wp0 called it unattributed.  It is covered, and belongs to no
    # silence category.
    d=$T/covered
    _plant "$d" x86_64 0  "$TIP" "$SO" 'aa\tUNATTRIBUTED' 'bb\tREFUSED'
    _plant "$d" x86_64 16 "$TIP" "$SO" 'bb\tREFUSED'
    if _arm covered 0 "$d" x86_64; then
        grep -q 'unattributed=0' "$T/out_covered/x86_64.refused.tsv" \
            || { echo "  ARM covered FAIL: a covered encoding stayed silent"; fails=$((fails+1)); }
        n=$((n + 1))
    fi

    # ARM 6 -- TWO BUILDS DO NOT DESCRIBE ONE ADMISSION GATE (92-C).
    d=$T/twoso
    _plant "$d" x86_64 0  "$TIP" "$SO"     'bb\tREFUSED'
    _plant "$d" x86_64 16 "$TIP" deadc0de  'bb\tREFUSED'
    _arm twoso 2 "$d" x86_64 \
        && grep -q 'different #so' "$T/twoso.log" \
        || { echo "  ARM twoso FAIL: refused for the wrong reason"; fails=$((fails+1)); }
    n=$((n + 1))

    # ARM 6b -- THE EMULATOR HALF (FINDING 98-B).  Same plugin, DIFFERENT
    # emulator is two builds, and this is the arm the one-field stamp could
    # not see: it is exactly the shape of a `target/<isa>/` change, whose
    # plugin binary does not move at all.
    d=$T/twoemu
    _plant "$d" x86_64 0  "$TIP" "$SO"$'\t'"emuAAAAAAAAAAAAAA" 'bb\tREFUSED'
    _plant "$d" x86_64 16 "$TIP" "$SO"$'\t'"emuBBBBBBBBBBBBBB" 'bb\tREFUSED'
    _arm twoemu 2 "$d" x86_64 \
        && grep -q 'different #so' "$T/twoemu.log" \
        || { echo "  ARM twoemu FAIL: refused for the wrong reason"; fails=$((fails+1)); }
    n=$((n + 1))

    # ARM 6c -- A ONE-FIELD STAMP IS A PRE-98-B CAPTURE AND IS REFUSED, not
    # compared on the half it happens to carry.  A check that cannot find
    # its subject must fail.
    d=$T/oldso
    for wp in 0 16; do
        _plant "$d" x86_64 "$wp" "$TIP" "$SO"$'\t'x 'bb\tREFUSED'
        sed -i "s/^#so\t$SO\tx\$/#so\t$SO/" \
            "$d/x86_64.wp$wp/corpus_x86_64.tsv" \
            "$d/x86_64.wp$wp/refused_x86_64.tsv"
    done
    _arm oldso 2 "$d" x86_64 \
        && grep -q 'one binary, not two' "$T/oldso.log" \
        || { echo "  ARM oldso FAIL: refused for the wrong reason"; fails=$((fails+1)); }
    n=$((n + 1))

    # ARM 7 -- AN ABSENT ARM IS A REFUSAL, NOT AN EMPTY PARTITION.  A
    # scanner that cannot find its subject FAILS.
    d=$T/missing
    _plant "$d" x86_64 0 "$TIP" "$SO" 'bb\tREFUSED'
    _arm missing 2 "$d" x86_64 \
        && grep -q 'has no corpus' "$T/missing.log" \
        || { echo "  ARM missing FAIL: refused for the wrong reason"; fails=$((fails+1)); }
    n=$((n + 1))

    # ARM 8 -- AN EMPTY CORPUS IS A REFUSAL.  Same reason, other route.
    d=$T/empty
    for wp in 0 16; do
        _plant "$d" x86_64 "$wp" "$TIP" "$SO" 'bb\tREFUSED'
        # Two-field `#so` like every real capture (98-B); writing the
        # one-field shape here would make this arm refuse for THAT reason
        # and stop testing the empty corpus at all.
        { printf '#tip\t%s\n#so\t%s\temu0000000000000\n#isa\tencoding\tsrc\n' \
                 "$TIP" "$SO"; } \
            > "$d/x86_64.wp$wp/corpus_x86_64.tsv"
    done
    _arm empty 2 "$d" x86_64 \
        && grep -q 'corpus empty' "$T/empty.log" \
        || { echo "  ARM empty FAIL: refused for the wrong reason"; fails=$((fails+1)); }
    n=$((n + 1))

    echo "srcenc_sweep selftest: $n check(s), $fails failure(s)"
    [ "$fails" = 0 ]
}

# -------------------------------------------------------------------- main
[ $# -gt 0 ] || die "usage: srcenc_sweep.sh {sweep|assemble|--selftest} ..."
sub=$1; shift
case "$sub" in
    sweep)      cmd_sweep "$@" ;;
    assemble)   cmd_assemble "$@" ;;
    --selftest) selftest "$@" ;;
    *) die "unknown subcommand $sub" ;;
esac
