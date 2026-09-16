#!/bin/bash
# ARC 3 -- drive the EVEX/XCR0 CPL0 probe (evexprobe.S) to completion.
#
# usage: evexprobe_run.sh <evidence-dir> [cpu-model]
# reads  <evidence-dir>/probe_in.hex, writes <evidence-dir>/evex_cpl0.tsv
#                                     and   <evidence-dir>/xcr0.tsv
#
# Same wedge-and-skip loop as sysprobe_run.sh: the probe prints an encoding's
# hex BEFORE executing it, so an encoding that hangs the machine names itself
# and is retried nowhere.  Exit codes are taken from the process.
set -u
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E="$(cd "$1" && pwd)"; shift
Q=${CST_QEMU_ROOT:-/mnt/md0/QEMU/qemu}/build/qemu-system-x86_64
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
CPU=${1:-max}
cd "$E"
cp "$T"/evexprobe.S "$T"/sysprobe.ld "$T"/sysprobe_mkblob.py .
: > all.tsv
: > skip.txt
for pass in $(seq 1 40); do
  $PY sysprobe_mkblob.py probe_in.hex || exit 2
  gcc -m64 -c -o evexprobe.o evexprobe.S || exit 2
  gcc -m64 -c -o encblob.o encblob.S || exit 2
  ld -T sysprobe.ld -o evexprobe.elf evexprobe.o encblob.o || exit 2
  objcopy -O binary evexprobe.elf evexprobe.bin || exit 2
  rm -f out.txt; touch out.txt
  timeout 300 $Q -cpu "$CPU" -M pc -m 256 -no-reboot -kernel evexprobe.bin \
      -debugcon file:out.txt -display none -serial none >/dev/null 2>&1
  rc=$?
  if grep -q '^DONE' out.txt; then
     echo "pass $pass: COMPLETE (rc=$rc)"
     grep -P '^[0-9a-f]+\t[0-9]+$' out.txt >> all.tsv
     grep -P '^(CPUID0D-XCR0-OFFERED|XCR0-TRY|XCR0-PINNED)\t' out.txt > xcr0.tsv
     $PY - <<'EOF'
import collections
d = {}
for line in open('all.tsv'):
    h, v = line.split()
    d[h] = int(v)
want = [x.strip() for x in open('probe_in.hex') if x.strip()]
miss = [h for h in want if h not in d]
open('evex_cpl0.tsv', 'w').write('hex\tcpl0_vec\n' +
    ''.join('%s\t%d\n' % (h, d[h]) for h in want if h in d))
print('CPL0: %d rows, %s%s' % (len(d), collections.Counter(d.values()),
      ('  NOT MEASURED (wedged the machine): %s' % ' '.join(miss)) if miss else ''))
EOF
     exit 0
  fi
  grep -P '^[0-9a-f]+\t[0-9]+$' out.txt >> all.tsv
  bad=$(tail -1 out.txt | cut -f1)
  echo "pass $pass: rc=$rc wedged at '$bad' after $(wc -l < out.txt) lines"
  [ -n "$bad" ] || { echo "no progress marker; aborting"; exit 3; }
  echo "$bad" >> skip.txt
done
echo "too many wedges"; exit 4
