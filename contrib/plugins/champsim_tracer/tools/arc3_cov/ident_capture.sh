#!/bin/bash
# CAPTURE THE DECODE IDENTITY FOR A LEG'S OWN ENCODING DENOMINATOR (98-F).
#
#   ident_capture.sh <isa> <hex-list-file> <out-dir> [build-dir]
#
# Prints the path of the identity corpus on stdout; everything else goes to
# stderr.  Exit 2 is REFUSED and nothing downstream may run.
#
# WHY A LEG NEEDS THIS AT ALL.  The four arc3_cov static legs score the
# tracer's own InsnFields -- opcode, branch class, register sets -- against a
# reference, and they get them from `isaxcheck --layer=fields --batch`.  The
# plugin classifies an instruction from QEMU's DECODE IDENTITY, and a host
# tool has no decode_id of its own: until 2fdabefe79 the answer came from
# `active_insn_table[insn_id]`, the Capstone-enum table, so what these legs
# scored was Capstone's classification and not the wire's.  R14 deleted that
# table.  The identity has to come from a real translation, and
# srcenc_sled.py is what performs one: it lays the encodings out in a guest
# image and asks QEMU to TRANSLATE each slot without executing it.
#
# THE POPULATION IS THE LEG'S OWN.  Not the exec121 sweep population -- a
# leg's denominator is its reference's encoding list, and an encoding the
# sled was never asked about would read unclassified for a reason that has
# nothing to do with the tracer.
#
# AN ENCODING THE SLED CANNOT ANSWER FOR IS NOT AN ERROR HERE.  QEMU builds
# no chain for an encoding it does not decode; the sled writes those to
# `refused_<isa>.tsv` and isaxcheck reports them as unreached rather than as
# a tracer defect (`f_ident=0` in the batch columns).  Measured on the
# aarch64 leg: 923 of 3,920 MRA encodings, essentially the post-2022-12,
# SVE and SVE2 families QEMU does not implement.  Those are the rows the
# enum table used to answer for.
#
# Author: Maccoy Merrell.
set -u
ISA=${1:?isa}; HEXLIST=${2:?hex list}; OUT=${3:?out dir}
Q=${4:-${CST_QEMU_ROOT:-/mnt/md0/QEMU/qemu}}
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SLED=$HERE/../srcenc_sled.py

[ -r "$HEXLIST" ] || { echo "REFUSED: cannot read hex list $HEXLIST" >&2; exit 2; }
[ -f "$SLED" ]    || { echo "REFUSED: no srcenc_sled.py at $SLED" >&2; exit 2; }
mkdir -p "$OUT" || exit 2

# The sled's --pop format is `isa<TAB>encoding`; strip anything else on the
# line so a caller may hand over a whole TSV column or a bare hex list.
awk -v i="$ISA" 'NF { gsub(/[^0-9a-fA-F]/, "", $1);
                      if (length($1) >= 2) print i"\t"tolower($1) }' \
    "$HEXLIST" | sort -u > "$OUT/pop_$ISA.tsv"
n=$(wc -l < "$OUT/pop_$ISA.tsv")
if [ "$n" = 0 ]; then
    echo "REFUSED: $HEXLIST yielded no encodings for $ISA" >&2; exit 2
fi

# THE CPU MODEL IS PART OF THE MEASUREMENT.  A sled run on a model that
# does not implement an extension translates none of its encodings, so every
# one of them comes back with no identity and the leg scores them as
# QEMU-NO-RULE -- true of that machine, and misleading about the tracer if
# the leg's own reference covers the extension.  The caller names the model
# it is scoring; the default is the sled's, which is what the banked corpora
# were captured with.
CPU=()
[ -n "${CST_IDENT_CPU:-}" ] && CPU=(--cpu "$CST_IDENT_CPU")
# THE SLED NEEDS A CAPTURE BUILD, AND THE CANONICAL ONE IS NOT (FINDING
# 244-H).  Every corpus the sled drives is written by champsim_tracer_capture,
# which is compiled in only under -Dcst_capture=true; in the shipped object the
# entry points are inline no-ops, so a sled run against build/ produces no file
# at all and the failure reads like an empty population.  The driver loop and
# the CST_SLED name are compiled under the same guard, so the object itself can
# be asked which kind of build it is rather than the question being answered by
# a path convention.
CAPB=${CST_CAPTURE_BUILD:-}
if [ -z "$CAPB" ]; then
    for cand in "$Q/build" "$Q/build-cap212" "$Q/build-cap"; do
        if [ -f "$cand/contrib/plugins/libchampsim_tracer.so" ] &&
           grep -qa CST_SLED "$cand/contrib/plugins/libchampsim_tracer.so"; then
            CAPB=$cand; break
        fi
    done
fi
if [ -z "$CAPB" ]; then
    echo "REFUSED: no capture build found for the sled." >&2
    echo "  The per-encoding corpora are written by code compiled only" >&2
    echo "  under -Dcst_capture=true; a shipped build writes none, and a" >&2
    echo "  run against one is not a short capture but no capture." >&2
    echo "  Configure one (../configure -Dcst_capture=true ...) and name" >&2
    echo "  it in CST_CAPTURE_BUILD." >&2
    exit 2
fi
echo "ident_capture $ISA capture build: $CAPB" >&2
ionice -c3 nice -n 10 "$PY" "$SLED" --isa "$ISA" --pop "$OUT/pop_$ISA.tsv" \
    --out "$OUT" --build-dir "$CAPB" --mech "${CPU[@]}" >&2 || {
    echo "REFUSED: the sled could not capture an identity for $ISA" >&2
    exit 2; }

C=$OUT/corpus_mech_$ISA.tsv
[ -s "$C" ] || { echo "REFUSED: the sled wrote no $C" >&2; exit 2; }
grep -q '^#so' "$C" || { echo "REFUSED: $C carries no #so stamp" >&2; exit 2; }
# A HEADER IS NOT A CORPUS (FINDING 244-H).  `-s` and a `#so` line are both
# satisfied by a file that carries nothing but its stamp and its column names,
# and that is exactly what the sled produced for as long as its mechanism
# merge tested `len(c) < 4` against a three-column corpus: every row was
# discarded, the file was written, both guards above passed, and the leg went
# on to classify an encoding set the corpus said nothing about.  Count the
# rows and refuse a zero.
rows=$(grep -vc '^#' "$C")
if [ "$rows" = 0 ]; then
    echo "REFUSED: $C carries a header and no row.  A check that cannot" >&2
    echo "  find its subject must fail: the identity this leg classifies" >&2
    echo "  from would be empty, and every encoding would read unclassified" >&2
    echo "  for a reason that has nothing to do with the tracer." >&2
    exit 2
fi
echo "ident_capture $ISA population=$n rows=$rows" >&2
echo "$C"
