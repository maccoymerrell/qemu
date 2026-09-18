#!/bin/bash
# ARC 3 -- the mipsel attribution harness's FIRING CONTROL.
#
# THE PROBLEM THIS EXISTS FOR.  mipsel's register-attribution table is the one
# whose headline a zero could equally well explain two ways: "the tracer and
# the reference agree" and "the comparison never reached its subject".  This
# project has been bitten by the second often enough to have a standing rule:
# a zero needs a control that has been WATCHED FIRING.  x86_64 and riscv64 got
# theirs from `--falsify=drop-src:<mnem>`; mipsel could not, because parse.py
# probes one encoding at a time with `--hex` and the tool refuses --falsify
# there (without --check the encoding is printed and the run returns before
# compare(), so nothing would be damaged).  So the damage is planted HERE, on
# the tracer arm's own text: for the mnemonic named in CST_FALSIFY_MNEM, the
# FIRST register is erased from the fields-layer SRC{} set parse.py reads.
#
# IT WAS BROKEN IN TWO PLACES BY THE isaxcheck RETIREMENT, AND IT FAILED
# SILENTLY IN BOTH.  Measured at exec246, running the leg end to end:
#
#   (1) THE ARM WAS HARD-CODED TO A DELETED BINARY.  The first line ran
#       `$Q/build/contrib/plugins/isaxcheck`, which linked Capstone into the
#       build and went with it.  Piped into awk, a missing program leaves the
#       PIPELINE's status as awk's -- zero -- so parse.py saw rc=0 and an
#       empty stream for all 977 encodings.  The control reported "damaged 0"
#       and the published table moved from 906 disagreements to 975, which is
#       the shape of a leg convicting the tracer for the harness's silence.
#       FINDING 244-H swept the five PYTHON helpers with this fallback; this
#       shell one was not in that sweep and kept the dead path.
#
#   (2) THE HIT PREDICATE KEYED ON A COLUMN THE SUCCESSOR DOES NOT EMIT.  It
#       matched the mnemonic on isaxcheck's `boundary <mnem> ...` line -- the
#       Capstone second-decoder view.  sled_fields.py prints `boundary ABSENT
#       (no second decoder in this tree)` and carries no mnemonic anywhere, so
#       even against a live arm the predicate could never fire.
#
# BOTH ARE FIXED BY ASKING THE LEG RATHER THAN A CONSTANT:
#
#   CST_FALSIFY_UNDER    the arm to run.  REQUIRED.  It cannot be read from
#                        CST_ISAXCHECK, because during a falsify run THIS FILE
#                        is CST_ISAXCHECK and that would recurse.
#   CST_FALSIFY_OPCODES  opcodes.tsv, the leg's own denominator, which carries
#                        mnemonic beside representative_encoding_hex_le.  The
#                        mnemonic for THIS invocation is resolved from the
#                        `--hex=` argument through that table, so the match is
#                        against the leg's own naming and not a decoder's.
#   CST_FALSIFY_MNEM     the mnemonic to damage.  Unset means pass through.
#   CST_FALSIFY_LOG      append one line per invocation (see below).
#
# AND AN EMPTY STREAM IS A REFUSAL, NOT ZERO DAMAGE.  That is what made (1)
# invisible: the caller cannot tell "the arm answered and nothing matched"
# from "the arm produced nothing" by the damage count alone.  An under-arm
# that writes no output now exits 3 and says so, and parse.py's own rc check
# stops the run there.
#
# NAME A MNEMONIC THAT IS IN THE DENOMINATOR.  The match is exact, so `move`
# selects nothing across the 977 representative encodings -- they carry
# `move.v`, the MSA form, and no plain `move` -- which is exactly what the
# inert arm requires.  The firing arm's caller checks the selection is
# non-empty BEFORE spending the run.
#
# SO THE REPORT DOES NOT GO ONLY TO STDERR.  parse.py calls the probe with
# `subprocess.run(capture_output=True)`, which SWALLOWS stderr: a shim that
# announced "reached no subject" there would announce it to nobody.  Set
# CST_FALSIFY_LOG and every invocation appends its count; a log with no
# damaged>0 line is a control that never fired, whatever emit.py reports.
#
# Author: Maccoy Merrell.
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -u

UNDER=${CST_FALSIFY_UNDER:-}
if [ -z "$UNDER" ] || [ ! -x "$UNDER" ]; then
    echo "falsify_shim: CST_FALSIFY_UNDER names no executable tracer arm" \
         "(got '${UNDER}').  This shim damages the arm's OWN output and" \
         "cannot guess which arm that is; a hard-coded one is how it ran a" \
         "deleted binary for a whole leg." >&2
    exit 2
fi

out=$("$UNDER" "$@" 2>/dev/null)
rc=$?
[ $rc -eq 0 ] || exit $rc
if [ -z "$out" ]; then
    echo "falsify_shim: $UNDER produced NO OUTPUT for '$*'.  An empty stream" \
         "is indistinguishable from 'nothing matched' at the damage count," \
         "so it is refused here instead of being passed on as zero damage." >&2
    exit 3
fi

# Which encoding is this invocation about, and what does the leg call it?
HEX=
for a in "$@"; do
    case "$a" in --hex=*) HEX=${a#--hex=} ;; esac
done
MNEM=
if [ -n "${CST_FALSIFY_MNEM:-}" ] && [ -n "$HEX" ]; then
    OPC=${CST_FALSIFY_OPCODES:-}
    if [ -z "$OPC" ] || [ ! -f "$OPC" ]; then
        echo "falsify_shim: CST_FALSIFY_MNEM is set but CST_FALSIFY_OPCODES" \
             "names no table ('${OPC}'), so this invocation cannot know which" \
             "mnemonic it is looking at." >&2
        exit 2
    fi
    MNEM=$(awk -F'\t' -v h="$HEX" 'NR>1 && $3 == h { print $2; exit }' "$OPC")
fi

printf '%s\n' "$out" | awk -v M="${CST_FALSIFY_MNEM:-}" -v N="$MNEM" \
                           -v H="$HEX" -v L="${CST_FALSIFY_LOG:-}" '
  BEGIN { hit = (M != "" && N != "" && M == N) }
  /^   SRC\{[^}]/ && hit { sub(/\{[^,}]*,?/, "{"); n++ }
  { print }
  END {
    if (M != "") {
      fmt = "# falsify_shim: damaged %d SRC set(s) for mnemonic %s (this encoding %s is %s)%s"
      msg = sprintf(fmt, n, M, (H == "" ? "?" : H), (N == "" ? "unnamed" : N), (n ? "" : "  -- this invocation reached no subject"))
      print msg > "/dev/stderr"
      if (L != "") print msg >> L
    }
  }
'
