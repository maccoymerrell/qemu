#!/bin/bash
# ARC 3 -- the mipsel attribution harness's FIRING CONTROL.
#
# THE PROBLEM THIS EXISTS FOR.  mipsel is the only one of the four ISAs whose
# register-attribution table reads 977 AGREE / 0 DISAGREE.  A zero is the one
# result that is equally consistent with "the tracer and the reference agree
# on every opcode" and with "the comparison never reached its subject", and
# this project has been bitten by the second often enough to have a standing
# rule about it: a zero needs a control that has been WATCHED FIRING.  x86_64
# and riscv64 get theirs from `isaxcheck --falsify=drop-src:<mnem>`.  mipsel
# could not: parse.py probes one encoding at a time with `--hex`, and the tool
# refuses --falsify there and says why --
#
#   "--falsify with --hex needs --check -- without it the encoding is printed
#    and the run returns before compare(), so nothing is damaged"
#
# -- which is correct behaviour and leaves mipsel without a control.
#
# So the damage is planted HERE instead, on the tracer arm's own text, at the
# same place drop-src plants it on the other ISAs: for the mnemonic named in
# CST_FALSIFY_MNEM, the FIRST register is erased from the fields-layer SRC{}
# set that parse.py reads.  Point the harness at this file and run the chain:
#
#   CST_ISAXCHECK=<this file> CST_FALSIFY_MNEM=abs.d python parse.py
#   python build_ref.py && python adjudicate.py && python emit.py
#
# MEASURED at 47bbdc2619 (cst_runs/p3/arc3/exec31/statics/mipsel):
#   clean          attempted=977 agree=977 disagree=0  signatures=0
#   CST_FALSIFY_MNEM=abs.d
#                  attempted=977 agree=976 disagree=1  signatures=1
#                  1  SRC-miss{FPRN}
# so the zero is a MEASUREMENT and not a vacuity.
#
# NAME A MNEMONIC THAT IS IN THE DENOMINATOR.  The match is exact and
# whitespace-delimited, so `move` selects nothing across the 977
# representative encodings -- they carry `move.v`, the MSA form, and no plain
# `move` -- and the shim would run silently inert, which is the very failure
# it exists to prevent.
#
# SO THE REPORT DOES NOT GO ONLY TO STDERR.  `parse.py` calls the probe with
# `subprocess.run(capture_output=True)`, which SWALLOWS stderr: a shim that
# announced "CONTROL DID NOT REACH ITS SUBJECT" there would be announcing it
# to nobody, and the operator would see a clean chain and a table that had
# never been damaged.  Set CST_FALSIFY_LOG to a path and every invocation
# appends its count there; the operator's check is then
#
#   grep -c 'damaged 0 ' "$CST_FALSIFY_LOG"     # must be < the opcode count
#
# and a log with no damaged>0 line is a control that never fired, whatever
# the emit.py numbers say.
#
# Author: Maccoy Merrell.
/mnt/md0/QEMU/qemu/build/contrib/plugins/isaxcheck "$@" | awk -v M="${CST_FALSIFY_MNEM:-}" \
                                                        -v L="${CST_FALSIFY_LOG:-}" '
  /^boundary / { hit = (M != "" && index($0, " " M " ") > 0) }
  /^   SRC\{[^}]/ && hit { sub(/\{[^,}]*,?/, "{"); n++ }
  { print }
  END {
    if (M == "") next_nothing = 1
    else {
      msg = sprintf("# falsify_shim: damaged %d SRC set(s) for mnemonic %s%s",
                    n, M, (n ? "" : "  -- this invocation reached no subject"))
      print msg > "/dev/stderr"
      if (L != "") print msg >> L
    }
  }
'
