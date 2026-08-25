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
cp "$T"/compare_attrib.py "$T"/qemu_tcg_scope.py "$T"/icedtsv.py \
   "$T"/mkprobe.py "$T"/xediform.c "$T"/xl3.cc "$T"/reach_probe.c \
   "$T"/cpuiddump.c "$T"/qemu_reach_matrix.py .
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

# ---- reachability, MEASURED, in four legs -------------------------------
# Whether a QEMU x86_64 guest can execute an encoding decides whether a decode
# gap there costs anything.  It is not read off XED's extension string: that
# guess called all 128 APX forms of BMI1/BMI2/ADOX_ADCX/LZCNT/MOVBE/RAO/
# USER_MSR reachable, and QEMU TCG SIGILLs every one.  Each encoding the
# tracer arm could not decode is EXECUTED instead, and compare_attrib.py
# refuses to run without the result.
#
# ONE LEG IS NOT ENOUGH, and each of the three added here closes a specific
# way the single leg could be wrong:
#  * its INPUT is the rows the tracer's own decoder rejected ($2 != 1).  That
#    is deliberate and stays -- reach_probe calls the bytes for real, and
#    calling all 8,880 encodings in-process would run jumps, syscalls and
#    halts -- but it does mean the decoder chose the sample, so the sample
#    cannot also be the justification.
#  * -cpu max is ONE configuration.  reach_models.sh runs every 64-bit-capable
#    CPU model QEMU has and then every CPUID flag forced on at once, so "no
#    model advertises the feature" is counted rather than assumed, and it
#    reads each model's CPUID out of the guest so the count is measured too.
#  * qemu-x86_64 runs everything at CPL 3, so a SIGILL from a privileged
#    opcode says "privilege".  sysprobe_run.sh executes the same encodings at
#    CPL 0 in long mode under qemu-system-x86_64 and reports the exception
#    vector, which removes the privilege reading entirely.
#  * WHERE QEMU refused is discriminated by -d unimp: gen_unknown_opcode()
#    logs ILLOPC and means the tables have no entry; its absence means QEMU
#    decoded something and refused it later -- or ran it, which is the worst
#    case and the one a signal alone cannot tell apart.
gcc -O0 -Wall -static -o reach_probe reach_probe.c
awk -F'\t' 'NR>1 && $2 != 1 { print $1 }' tracer_batch.tsv > reach_in.hex
"$T"/reach_models.sh "$D"                 # -> r_max_postfix, model_matrix, illopc, cpuid/
"$T"/sysprobe_run.sh "$D" max             # -> cpl0.tsv
cp r_max_postfix.tsv reach.tsv            # the single-leg name compare_attrib.py uses

# ---- the exclusion, derived from QEMU rather than from the decoder ---------
# Prints the feature vocabulary the decode tables can gate on, the CPUID
# symbols inside the TCG_*_FEATURES masks, and the prefix facts; exits 1 when
# any cited fact has stopped holding (e.g. QEMU gains EVEX or a new VEX map).
$PY qemu_tcg_scope.py

# ---- compare ---------------------------------------------------------------
$PY compare_attrib.py     # -> ../attrib.tsv, ../attrib_signatures.txt

# ---- the three-valued verdict ---------------------------------------------
# Every opcode ends COVERED, UNREACHABLE or UNCOVERED, with the evidence for
# an UNREACHABLE row ON the row: the CPL3 signal, the count of CPU models it
# ran under, the all-flags signal, the CPL0 vector, where QEMU refused, the
# gating CPUID word, whether that word is inside a TCG_*_FEATURES mask, how
# many configurations actually advertise it, and which builtin_x86_defs[]
# models name it.  Exits 1 while any row is UNCOVERED -- which is the point.
$PY qemu_reach_matrix.py --evidence "$D" --attrib ../attrib.tsv \
    --meta ../opcodes_meta.tsv -o ../reach_matrix.tsv || true

# ---- prove the gate can fire ----------------------------------------------
# An agreement rate quoted off an instrument nobody has watched fail vouches
# for nothing.  drop-src must cost exactly the agreeing rows of the damaged
# mnemonic, against a baseline of 5835:
#   movq 20   vmovq 13   vpsadbw 10   sqrtsd 2   ud0 3   ud1 2
#   xlatb 1   smswl 1   lmsww 2   rdfsbasel 1   lfsl 1   cmpxchg8b 1
# NOTE THE SPELLINGS.  --falsify matches the mnemonic EXACTLY, so `smsw`
# matches nothing and the tool says so with exit 2 -- take the exit code,
# never the AGREE line, or an unchanged count reads as a passing control.
ud0 is in the list on purpose too -- it is the family the UD0 misdecode
# repair created, and a repair nobody has watched fail is a repair that
# vouches for nothing.
# sqrtsd is in the list on purpose -- it is an R7.1-SCALAR row, so it proves
# the rows that rule closed are watched rather than blindly agreeing.
cp tracer_batch.tsv tracer_batch.good.tsv
for M in movq vmovq vpsadbw sqrtsd ud0 ud1 xlatb smswl lmsww \
         rdfsbasel lfsl cmpxchg8b; do
  "$Q/build/contrib/plugins/isaxcheck" --isa=x86_64 --layer=fields \
      --falsify=drop-src:$M --batch < probe_uniq.hex > tracer_batch.tsv \
      || { echo "falsify drop-src:$M did not reach its subject"; exit 1; }
  echo -n "falsify drop-src:$M -> "
  $PY compare_attrib.py 2>/dev/null | grep -m1 '  AGREE  '
done
cp tracer_batch.good.tsv tracer_batch.tsv
$PY compare_attrib.py > /dev/null

# ---- audit the ILLOPC rows -------------------------------------------------
# An UNREACHABLE row refused at NO-TABLE-ENTRY(ILLOPC) asserts two things, and
# each has its own way of being false: that the BYTES are the instruction the
# row names (the UD0 misdecode was exactly this failure), and that QEMU really
# has no table entry for them.  illopc_audit.py re-decodes every such probe
# under XED, LLVM MC, iced-x86 and objdump, and independently walks each
# probe's prefix/map/opcode/ModRM shape through decode-new.c.inc AS IT IS ON
# DISK to name the table, the slot and what occupies it.  A slot that turns
# out to be OCCUPIED is fatal.
#
# PASS A RECENT objdump.  A distribution objdump lags the newest ISA
# extensions by years -- Ubuntu's 2.42 does not know MOVRS, AMX-FP8,
# AMX-MOVRS or the MSR_IMM forms, and its silence would read as "only one
# decoder names this row".  2.45 settles all ten.  Repeat --objdump freely;
# every one contributes a column.
$PY "$T"/illopc_audit.py --matrix ../reach_matrix.tsv \
    --xl3 xl3.tsv --iced iced.tsv --root "$Q" \
    --objdump "${CST_OBJDUMP_NEW:-objdump}" --objdump objdump \
    --allow-single-source "$T"/illopc_single_source.allow \
    -o ../illopc_audit.tsv
