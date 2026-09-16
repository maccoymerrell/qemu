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
for pass in $(seq 1 40); do
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
  echo "$bad" >> skip.txt
done
echo "too many wedges"; exit 4
