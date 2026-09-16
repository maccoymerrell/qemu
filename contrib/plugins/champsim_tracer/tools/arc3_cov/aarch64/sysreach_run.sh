#!/bin/bash
# ARC 3 -- drive the aarch64 EL1 reachability probe to completion.
#
# usage: sysreach_run.sh <evidence-dir> [cpu-model]
# reads  <evidence-dir>/reach_in.hex, writes <evidence-dir>/el1.tsv
#
# An encoding that wedges the machine is identified by the last hex the probe
# printed (it prints BEFORE executing), added to skip.txt, and the image
# rebuilt.  Exit codes come from the tool, never through a pipe.
set -u
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E="$(cd "$1" && pwd)"; shift
Q=${CST_QEMU_ROOT:-/mnt/md0/QEMU/qemu}/build/qemu-system-aarch64
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
CC=${CST_A64_CC:-aarch64-linux-gnu-gcc}
LD=${CST_A64_LD:-aarch64-linux-gnu-ld}
CPU=${1:-max}
cd "$E"
cp "$T"/sysreach.S "$T"/sysreach.ld "$T"/sysreach_mkblob.py .
: > all.tsv
: > skip.txt
for pass in $(seq 1 40); do
  $PY sysreach_mkblob.py reach_in.hex || exit 2
  $CC -c -o sysreach.o sysreach.S || exit 2
  $CC -c -o encblob.o encblob.S || exit 2
  $LD -T sysreach.ld -o sysreach.elf sysreach.o encblob.o || exit 2
  rm -f out.txt; touch out.txt
  timeout ${CST_A64_TIMEOUT:-900} $Q -M virt -cpu "$CPU" -m 1024 -nographic -no-reboot \
      -semihosting -kernel sysreach.elf -serial file:out.txt \
      -monitor none -display none >/dev/null 2>&1
  rc=$?
  if grep -q '^REFUSED-not-EL1' out.txt; then
     echo "REFUSED: $(grep '^REFUSED-not-EL1' out.txt)"; exit 3
  fi
  # A fault in the harness's OWN code is a wedge by the row that ran last:
  # the only way to get there is an encoding that changed machine state
  # under the probe (the MMU, the vectors, the UART mapping).  Attribute it
  # to that row, skip it, and rebuild -- the same treatment a hang gets.
  if grep -q '^REFUSED-fault-outside-slot' out.txt; then
     grep -P '^[0-9a-f]{8}\t[0-9a-f]{2}$' out.txt >> all.tsv
     bad=$(grep -oP '^[0-9a-f]{8}' out.txt | tail -1)
     echo "pass $pass: fault outside the slot after '$bad'"
     [ -n "$bad" ] || { echo "no progress marker; aborting"; exit 4; }
     echo "$bad" >> skip.txt
     continue
  fi
  if grep -q '^DONE' out.txt; then
     echo "pass $pass: COMPLETE (rc=$rc)  $(grep '^SMSTART' out.txt)"
     grep -P '^[0-9a-f]{8}\t[0-9a-f]{2}$' out.txt >> all.tsv
     $PY - <<'PYX'
import collections
d = {}
for line in open('all.tsv'):
    h, v = line.split()
    d[h] = int(v, 16)
want = [x.strip() for x in open('reach_in.hex') if x.strip()]
miss = [h for h in want if h not in d]
with open('el1.tsv', 'w') as f:
    f.write('hex\tel1_ec\tel1_decoded\n')
    for h in want:
        if h in d:
            f.write('%s\t%02x\t%s\n' % (h, d[h], 'no' if d[h] == 0 else 'yes'))
print('EL1: %d rows, %s%s' % (len(d), collections.Counter(d.values()),
      ('  NOT MEASURED (wedged the machine): %s' % ' '.join(miss)) if miss else ''))
PYX
     exit 0
  fi
  grep -P '^[0-9a-f]{8}\t[0-9a-f]{2}$' out.txt >> all.tsv
  bad=$(tail -c 4096 out.txt | tail -1 | cut -f1)
  echo "pass $pass: rc=$rc wedged at '$bad' after $(wc -l < out.txt) lines"
  [ -n "$bad" ] || { echo "no progress marker; aborting"; exit 4; }
  echo "$bad" >> skip.txt
done
echo "too many wedges"; exit 5
