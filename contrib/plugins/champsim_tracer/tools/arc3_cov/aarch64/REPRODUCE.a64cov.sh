#!/bin/sh
# REPRODUCE THE aarch64 DECODE-ROW COVERAGE NUMBER, end to end.
#
# The four stages are separate programs because each answers a different
# question and each can refuse on its own: what the rows ARE, which word
# reaches each row, whether the tracer publishes it, and -- for whatever does
# not come back -- what QEMU itself does with the encoding.
#
# The identity stage needs a CAPTURE build of the plugin (-Dcst_capture=true):
# CST_QEMU_IDENT_PAIRS is written by the capture apparatus, which the shipped
# release object does not carry.  The EMULATOR may be the canonical one -- the
# census refuses a build whose decode rows differ from the checkout, so the
# two can be shown to describe one decoder rather than assumed to.
#
# Author: Maccoy Merrell.
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -e

ROOT=${ROOT:?the checkout}
BUILD=${BUILD:?the build whose decoders the census describes}
CAPSO=${CAPSO:?libchampsim_tracer.so from a -Dcst_capture=true build}
QEMU=${QEMU:?qemu-aarch64}
PLUGIN=${PLUGIN:?the SHIPPED libchampsim_tracer.so under test}
DECODE=${DECODE:?cst_decode}
OUT=${OUT:?evidence directory}
PY=${PY:-python3}
HERE=$(cd -- "$(dirname -- "$0")" && pwd)

mkdir -p "$OUT/census"

# 1. the denominator, from the build and the tree
$PY "$HERE/a64_row_census.py" --root "$ROOT" --build-dir "$BUILD" \
    -o "$OUT/census"

# 2. candidate words, from the tree's own patterns
$PY "$HERE/a64_row_encodings.py" --root "$ROOT" --build-dir "$BUILD" \
    --census "$OUT/census/a64_rows.tsv" \
    -o "$OUT/cand_words.tsv" --pop "$OUT/pop_aarch64.tsv"

# 3. QEMU arbitrates: which row did the decoder actually reach.  The sled's
#    own srcenc corpus is not what this pass wants, so its refusal on an empty
#    srcenc capture is expected and the ident corpus is read regardless.
mkdir -p "$OUT/sled"
CST_QEMU_IDENT_PAIRS="$OUT/ident_a64_raw.tsv" \
  $PY "$HERE/../../srcenc_sled.py" --isa aarch64 \
      --pop "$OUT/pop_aarch64.tsv" --out "$OUT/sled" \
      --build-dir "$(dirname "$CAPSO")/../.." --cpu max || true
test -s "$OUT/ident_a64_raw.tsv"

# 4. exercise every row whose word QEMU agreed on, and read the bytes back
#    off the wire.  (final_words.tsv is the rule -> agreed-words join; see
#    DIGEST.md for the widening pass that settles the rows the six value
#    banks miss.)
$PY "$HERE/a64_row_exercise.py" --repo "$ROOT" --qemu "$QEMU" \
    --plugin "$PLUGIN" --cst-decode "$DECODE" \
    --words "$OUT/final_words.tsv" --cells "$OUT/cells_final" \
    -o "$OUT/exercise_final.tsv" --per-row 6 --jobs 12

# 5. whatever did not come back, asked of QEMU with no plugin attached
$PY "$HERE/a64_absent_triage.py" --qemu "$QEMU" --plugin "$PLUGIN" \
    --cst-decode "$DECODE" --rows "$OUT/triage_rows.tsv" \
    --cells "$OUT/cells_triage" -o "$OUT/triage_final.tsv" --jobs 12
