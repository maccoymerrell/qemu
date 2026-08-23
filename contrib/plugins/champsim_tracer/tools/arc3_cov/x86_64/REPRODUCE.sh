#!/bin/bash
# ARC 3 -- x86_64 REGISTER ATTRIBUTION over the whole opcode space.
# Start to finish.  Author: Maccoy Merrell.
set -euo pipefail
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"      # this directory, in-tree
D=/mnt/md0/QEMU/cst_runs/_arc3_cov/x86_64/attrib       # working copy + evidence
R=/mnt/md0/QEMU/cst_runs/_arc3_refs/x86_64             # reference decoder kits
Q=/mnt/md0/QEMU/qemu
PY=/home/maccoy-merrell/anaconda3/bin/python
K=$R/xed-src/kits/xed-install-base-2026-08-22-lin-x86-64
LC=/usr/bin/llvm-config-18
mkdir -p "$D"; cd "$D"

# The harness is the TREE's copy; the working directory only holds evidence.
cp "$T"/compare_attrib.py "$T"/icedtsv.py "$T"/mkprobe.py \
   "$T"/xediform.c "$T"/xl3.cc .
ln -sfn "$R/pylib" pylib                      # iced-x86 1.21.0

# The tracer arm needs the fields columns in --batch (commit 5379a000ac).
ninja -C "$Q/build" contrib-plugins

# ---- probe set -------------------------------------------------------------
# One row per opcode from the denominator.  For an EVEX opcode whose iform
# carries a mask slot the representative encoding has aaa=000, which
# architecturally means UNMASKED -- the mask operand is never exercised.  C3
# requires showing the operand is captured FOR THAT OPCODE TYPE, so those are
# re-probed with aaa=001, accepted only when XED still decodes the variant to
# the same iform at the same length.
gcc -O2 -I"$K/include" -o xediform xediform.c "$K/lib/libxed.a"
$PY mkprobe.py                 # -> probe_map.json, probe_uniq.hex

# ---- the four arms ---------------------------------------------------------
g++ -O2 -std=c++17 -I"$K/include" $($LC --cxxflags | sed 's/-fno-exceptions//') \
    -o xl3 xl3.cc "$K/lib/libxed.a" $($LC --ldflags) -lLLVM-18
"$Q/build/contrib/plugins/isaxcheck" --isa=x86_64 --layer=fields --batch \
    < probe_uniq.hex > tracer_batch.tsv
PROBE_FEAT="$(cat "$R/llvm_features.txt")" ./xl3 probe_uniq.hex \
    > xl3.tsv 2> xl3.err                      # XED (primary) + LLVM MC
$PY icedtsv.py probe_uniq.hex > iced.tsv 2> iced.err

# R7.1-NARROW and R7.1-SCALAR are standing rules: they still DETECT the
# preserve-read they suppress, and print the counts.  A zero here means the
# rule has stopped reaching its subject -- a finding, not a pass.
grep -h 'R7.1-NARROW' xl3.err iced.err

# ---- compare ---------------------------------------------------------------
$PY compare_attrib.py     # -> ../attrib.tsv, ../attrib_signatures.txt

# ---- prove the gate can fire ----------------------------------------------
# An agreement rate quoted off an instrument nobody has watched fail vouches
# for nothing.  drop-src must cost exactly the agreeing rows of the damaged
# mnemonic, against a baseline of 5835:
#   movq 20   vmovq 13   vpsadbw 10   sqrtsd 2
# sqrtsd is in the list on purpose -- it is an R7.1-SCALAR row, so it proves
# the rows that rule closed are watched rather than blindly agreeing.
cp tracer_batch.tsv tracer_batch.good.tsv
for M in movq vmovq vpsadbw sqrtsd; do
  "$Q/build/contrib/plugins/isaxcheck" --isa=x86_64 --layer=fields \
      --falsify=drop-src:$M --batch < probe_uniq.hex > tracer_batch.tsv
  echo -n "falsify drop-src:$M -> "
  $PY compare_attrib.py 2>/dev/null | grep -m1 '  AGREE  '
done
cp tracer_batch.good.tsv tracer_batch.tsv
$PY compare_attrib.py > /dev/null
