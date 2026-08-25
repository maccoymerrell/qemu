#!/bin/bash
# ARC 3 -- the ENABLE-BIT leg of the CPL0 reachability probe.
#
# usage: sysprobe_enab_run.sh <evidence-dir> [cpu-model]
# reads  <evidence-dir>/reach_in.hex
# writes <evidence-dir>/cpl0_enab.tsv   hex -> exception vector
#        <evidence-dir>/enables.tsv     enable -> old, new, vector, held
#
# The plain CPL0 leg proves a #UD is not a PRIVILEGE refusal.  It cannot
# prove the #UD is not an ENABLE refusal: an instruction QEMU implements
# behind CR4.VMXE, EFER.SVME, XCR0 or an IA32_* enable MSR would fault at
# CPL 0 exactly the way an unimplemented one does.  This leg is the same
# image, the same encodings, with every architectural enable SET AND PROVEN
# SET first; an enable QEMU refuses is recorded with its exception vector,
# which is the stronger answer.
#
# Enables and encodings both print BEFORE they are attempted, so whichever
# one wedges the machine names itself and is skipped on the next pass.
# Exit codes come from the tool.
set -u
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E="$(cd "$1" && pwd)"; shift
Q=${CST_QEMU_ROOT:-/mnt/md0/QEMU/qemu}/build/qemu-system-x86_64
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
CPU=${1:-max}
cd "$E"
cp "$T"/sysprobe.S "$T"/sysprobe.ld "$T"/sysprobe_mkblob.py \
   "$T"/sysprobe_enables.py .
: > enab_all.tsv
: > enab_e.tsv
[ -f skip.txt  ] || : > skip.txt
[ -f eskip.txt ] || : > eskip.txt
for pass in $(seq 1 60); do
  $PY sysprobe_mkblob.py reach_in.hex || exit 2
  $PY sysprobe_enables.py enabblob.S  || exit 2
  gcc -m64 -DENABLE_LEG -c -o sysprobe.o sysprobe.S || exit 2
  gcc -m64 -c -o encblob.o  encblob.S  || exit 2
  gcc -m64 -c -o enabblob.o enabblob.S || exit 2
  ld -T sysprobe.ld -o sysprobe_enab.elf sysprobe.o encblob.o enabblob.o \
     || exit 2
  objcopy -O binary sysprobe_enab.elf sysprobe_enab.bin || exit 2
  rm -f eout.txt; touch eout.txt
  timeout 300 $Q -cpu "$CPU" -M pc -m 256 -no-reboot \
      -kernel sysprobe_enab.bin \
      -debugcon file:eout.txt -display none -serial none >/dev/null 2>&1
  rc=$?
  grep -P '^ENAB\t' eout.txt >> enab_e.tsv
  grep -P '^[0-9a-f]+\t[0-9]+$' eout.txt >> enab_all.tsv
  if grep -q '^DONE' eout.txt; then
     echo "pass $pass: COMPLETE (rc=$rc)"
     break
  fi
  if ! grep -q '^ENABDONE' eout.txt; then
     bad=$(grep -P '^ENAB\t' eout.txt | tail -1 | cut -f2)
     [ -n "$bad" ] || { echo "no enable marker; aborting"; exit 3; }
     echo "pass $pass: rc=$rc the machine did not survive enable '$bad'"
     echo "$bad" >> eskip.txt
     continue
  fi
  bad=$(grep -P '^[0-9a-f]+\t' eout.txt | tail -1 | cut -f1)
  echo "pass $pass: rc=$rc wedged at encoding '$bad'"
  [ -n "$bad" ] || { echo "no progress marker; aborting"; exit 3; }
  echo "$bad" >> skip.txt
done
grep -q '^DONE' eout.txt || { echo "too many wedges"; exit 4; }

$PY - <<'PYEOF'
import collections
import sys
sys.path.insert(0, '.')
import sysprobe_enables as EN

held, rows = {}, []
for line in open('enab_e.tsv'):
    f = line.rstrip('\n').split('\t')
    if len(f) != 6:
        continue
    _, nm, old, new, vec, took = f
    held[nm] = int(took)
    rows.append((nm, old, new, int(vec), int(took)))
open('enables.tsv', 'w').write(
    'enable\told\tnew\tvector\theld\n' +
    ''.join('%s\t%s\t%s\t%d\t%d\n' % r for r in rows))

# R8.7 -- the leg is only worth the controls that convict it.
bad = []
for nm in EN.MUST_HOLD:
    if held.get(nm) != 1:
        bad.append('%s MUST be held and is not (held=%s): every enable this '
                   'leg reports as SET is then unproven' % (nm, held.get(nm)))
for nm in EN.MUST_REFUSE:
    if held.get(nm) != 0:
        bad.append('%s MUST be refused by QEMU and was held (held=%s): the '
                   'readback is not discriminating' % (nm, held.get(nm)))
skipped = [n for n, _, _, _ in EN.ENABLES if n not in held]
if skipped:
    bad.append('enables never attempted (they wedged the machine): %s'
               % ' '.join(skipped))
if bad:
    sys.exit('ENABLE LEG REFUSED:\n  ' + '\n  '.join(bad))

d = {}
for line in open('enab_all.tsv'):
    h, v = line.split()
    d[h] = int(v)
want = [x.strip() for x in open('reach_in.hex') if x.strip()]
miss = [h for h in want if h not in d]
open('cpl0_enab.tsv', 'w').write(
    'hex\tcpl0_enab_vec\n' +
    ''.join('%s\t%d\n' % (h, d[h]) for h in want if h in d))
print('enables held %d/%d: %s'
      % (sum(held.values()), len(held),
         ' '.join(n for n in held if held[n])))
print('enables REFUSED: %s'
      % ' '.join('%s(vec=%d)' % (r[0], r[3]) for r in rows if not r[4]))
print('CPL0+ENABLES: %d rows, %s%s'
      % (len(d), collections.Counter(d.values()),
         ('  NOT MEASURED (wedged the machine): %s' % ' '.join(miss))
          if miss else ''))
PYEOF
