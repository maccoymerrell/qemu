#!/bin/bash
# ARC 3 -- drive the CPL0 reachability probe to completion.
#
# usage: sysprobe_run.sh <evidence-dir> [cpu-model]
# reads  <evidence-dir>/reach_in.hex, writes <evidence-dir>/cpl0.tsv
#
# qemu-x86_64 runs everything at CPL 3, so a #UD from a privileged opcode says
# "privilege" and not "QEMU does not implement it".  This is the leg that
# removes the assumption: the same encodings, at CPL 0, in long mode, under
# qemu-system-x86_64.  An encoding that wedges the machine is
# identified by the last hex the probe printed (it prints BEFORE executing),
# added to skip.txt, and the image rebuilt.  Exit codes come from the tool.
#
# THE PASS BUDGET IS THE POPULATION, NOT A CONSTANT (exec249 ITEM 1).  This
# loop removes at most ONE encoding per pass, because the machine is dead
# after the first one that kills it and only the last line printed names a
# suspect.  So the number of passes a population needs is the number of
# encodings in it that wedge -- a property of the population and the target,
# not something a literal can know.  It was written `seq 1 40`, and the
# population grew: the x86_64 leg's reach set is 8,313 encodings at
# bf9db9ab05 against the 5,904 the last completed run measured, and the 2,409
# new ones are dominated by the `0f 01` system group (vmrun, vmxoff, stgi,
# invlpga, swapgs ...), which genuinely destroys the machine.  The leg then
# spent 40 passes, exhausted the budget 131 lines into 8,313 encodings, and
# exited 4 -- reported as "too many wedges", which named the ceiling and not
# the cause.
#
# NOT A REGRESSION, and that was MEASURED rather than assumed: the exact
# 5,904-encoding population of the last completed run, replayed at this tip,
# COMPLETES IN ONE PASS with zero wedges and 5,904 rows
# (cst_runs/p3/arc3/exec249/fresh/item1_cov/sysprobe_ctrl/).  The emulator did
# not get worse; the question got bigger.
#
# The budget is now the population size, which is the most passes this loop
# can ever need, and the real stopping condition is stated where it belongs:
# a pass that neither completes nor identifies a NEW suspect has stopped
# making progress, and that REFUSES immediately instead of burning the rest
# of the budget on identical passes.  The refusal names how far it got.
set -u
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E="$(cd "$1" && pwd)"; shift
Q=${CST_QEMU_ROOT:-/mnt/md0/QEMU/qemu}/build/qemu-system-x86_64
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
CPU=${1:-max}
cd "$E"
cp "$T"/sysprobe.S "$T"/sysprobe.ld "$T"/sysprobe_mkblob.py .
: > all.tsv
: > skip.txt
POP=$(grep -c . reach_in.hex)
[ "$POP" -gt 0 ] || { echo "reach_in.hex is empty; nothing to probe" >&2; exit 3; }
echo "population $POP encodings; pass budget $POP (one wedge removed per pass)"
for pass in $(seq 1 "$POP"); do
  $PY sysprobe_mkblob.py reach_in.hex || exit 2
  gcc -m64 -c -o sysprobe.o sysprobe.S || exit 2
  gcc -m64 -c -o encblob.o encblob.S || exit 2
  ld -T sysprobe.ld -o sysprobe.elf sysprobe.o encblob.o || exit 2
  objcopy -O binary sysprobe.elf sysprobe.bin || exit 2
  rm -f out.txt; touch out.txt
  timeout 300 $Q -cpu "$CPU" -M pc -m 256 -no-reboot -kernel sysprobe.bin \
      -debugcon file:out.txt -display none -serial none >/dev/null 2>&1
  rc=$?
  if grep -q '^DONE' out.txt; then
     echo "pass $pass: COMPLETE (rc=$rc)"
     grep -P '^[0-9a-f]+\t[0-9]+$' out.txt >> all.tsv
     $PY - <<'EOF'
import collections
d = {}
for line in open('all.tsv'):
    h, v = line.split()
    d[h] = int(v)
want = [x.strip() for x in open('reach_in.hex') if x.strip()]
miss = [h for h in want if h not in d]
open('cpl0.tsv', 'w').write('hex\tcpl0_vec\n' +
    ''.join('%s\t%d\n' % (h, d[h]) for h in want if h in d))
print('CPL0: %d rows, %s%s' % (len(d), collections.Counter(d.values()),
      ('  NOT MEASURED (wedged the machine): %s' % ' '.join(miss)) if miss else ''))
EOF
     exit 0
  fi
  # incomplete: the last line names the encoding that wedged the machine
  grep -P '^[0-9a-f]+\t[0-9]+$' out.txt >> all.tsv
  bad=$(tail -1 out.txt | cut -f1)
  echo "pass $pass: rc=$rc wedged at '$bad' after $(wc -l < out.txt) lines"
  [ -n "$bad" ] || { echo "no progress marker; aborting"; exit 3; }
  # A PASS THAT NAMES A SUSPECT IT HAS ALREADY SKIPPED HAS STOPPED.  The next
  # pass would rebuild the same image and die in the same place, so the run
  # would spend the rest of the budget proving that once per pass.  This is
  # the honest stopping condition and it is separate from the budget: it says
  # the loop is not converging, and it says so at the first repetition rather
  # than at pass $POP.
  if grep -qxF "$bad" skip.txt; then
      echo "NO PROGRESS: pass $pass names '$bad', which is already skipped."
      echo "  $(grep -c . skip.txt) skipped, $(cut -f1 all.tsv | sort -u | wc -l) measured,"
      echo "  $POP in the population.  The suspect is the LAST ENCODING PRINTED,"
      echo "  so a wedge whose cause is an EARLIER encoding's state damage names"
      echo "  its victim; skipping the victim then moves the damage one along."
      exit 5
  fi
  echo "$bad" >> skip.txt
done
echo "BUDGET EXHAUSTED: $POP passes, $(grep -c . skip.txt) encodings skipped," >&2
echo "  $(cut -f1 all.tsv | sort -u | wc -l) of $POP measured." >&2
exit 4
