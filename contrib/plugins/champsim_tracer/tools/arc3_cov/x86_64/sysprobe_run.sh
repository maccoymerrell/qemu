#!/bin/bash
# ARC 3 -- drive the CPL0 reachability probe to completion.
#
# usage: sysprobe_run.sh <evidence-dir> [cpu-model]
# reads  <evidence-dir>/reach_in.hex, writes <evidence-dir>/cpl0.tsv
#
# qemu-x86_64 runs everything at CPL 3, so a #UD from a privileged opcode says
# "privilege" and not "QEMU does not implement it".  This is the leg that
# removes the assumption: the same encodings, at CPL 0, in long mode, under
# qemu-system-x86_64.  The probe prints each encoding's hex BEFORE executing
# it, so an encoding that kills the machine is named by the last line of
# output.  Exit codes come from the tool.
#
# THREE THINGS DECIDE WHAT THIS LOOP COSTS, and exec249 got two of them wrong.
#
# 1. THE LAST HEX PRINTED IS A SUSPECT, NOT A VERDICT (finding 250-A).  A probe
#    may LOAD machine state, not only write registers: `0f 01 10` is
#    `lgdt (%rax)` with %rax pointing at the scratch buffer, so it replaces the
#    GDT and then RETURNS NORMALLY with its own vector reported.  The next
#    encoding to take an exception dies loading CS from a table that is no
#    longer a table -- and the loop names THAT one, skips it, and the damage
#    moves one along.  Measured 2026-09-19: 2,652 consecutive passes, each
#    convicting a different innocent encoding, 2,586 of them stopping at the
#    same line; `62f2fd494e00`, the row the last pass convicted, completes on
#    its own with vector 6.  The cure is in sysprobe.S -- restore_machine()
#    puts the descriptor tables, segments, CR0/CR3/CR4, XCR0 and the FP control
#    state back after every probe -- and the guard is here: A SUSPECT IS
#    RE-RUN ON ITS OWN BEFORE IT IS SKIPPED.  If the encoding alone does not
#    kill the machine, it did not kill the machine, and this refuses instead of
#    convicting it.
#
# 2. A WEDGE COSTS ONE PASS OVER WHATEVER THE IMAGE HOLDS.  With the whole
#    population in one image that is the whole population, once per wedging
#    encoding, and a `mov %rax,%cr0` that HANGS costs the full timeout as well.
#    So the population is sharded, the aarch64 leg's pattern
#    (../aarch64/sysreach_batch.sh): a wedge costs its shard's pass, shards run
#    concurrently up to a courtesy cap, and a hang costs one shard's timeout.
#
# 3. THE PASS BUDGET IS THE SHARD, NOT A CONSTANT.  It was written
#    `seq 1 40` against a population that grew to 8,313; it is now the shard's
#    own row count, which is the most passes a shard can need.
set -u
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E="$(cd "$1" && pwd)"; shift
Q=${CST_QEMU_ROOT:-/mnt/md0/QEMU/qemu}/build/qemu-system-x86_64
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
CPU=${1:-max}
SHARD=${CST_X86_SHARD:-256}      # encodings per image
PAR=${CST_X86_PAR:-8}            # concurrent machines; a courtesy cap
TMO=${CST_X86_TIMEOUT:-30}       # per boot; a shard of this size runs in ~1s

# Build the probe image in $1 from its reach_in.hex minus its skip.txt.
build_image() {
  ( cd "$1" && $PY sysprobe_mkblob.py reach_in.hex \
      && gcc -m64 -c -o sysprobe.o sysprobe.S \
      && gcc -m64 -c -o encblob.o encblob.S \
      && ld -T sysprobe.ld -o sysprobe.elf sysprobe.o encblob.o \
      && objcopy -O binary sysprobe.elf sysprobe.bin ) >> "$1/build.log" 2>&1
}

run_image() {
  rm -f "$1/out.txt"; : > "$1/out.txt"
  timeout "$TMO" $Q -cpu "$CPU" -M pc -m 256 -no-reboot \
      -kernel "$1/sysprobe.bin" -debugcon "file:$1/out.txt" \
      -display none -serial none >/dev/null 2>&1
}

# Does THIS encoding, alone, kill the machine?  0 = yes (a genuine wedge),
# 1 = no (the machine died on something earlier, and the suspect is innocent).
confirm_wedge() {
  local d=$1 hx=$2 iso="$1/iso"
  rm -rf "$iso"; mkdir -p "$iso"
  cp "$T"/sysprobe.S "$T"/sysprobe.ld "$T"/sysprobe_mkblob.py "$iso"/
  printf '%s\n' "$hx" > "$iso/reach_in.hex"
  build_image "$iso" || return 2
  run_image "$iso"
  grep -q '^DONE' "$iso/out.txt" && return 1
  return 0
}

shard_run() {
  local d=$1 pass bad rc
  cp "$T"/sysprobe.S "$T"/sysprobe.ld "$T"/sysprobe_mkblob.py "$d"/
  : > "$d/all.tsv"; : > "$d/skip.txt"; : > "$d/wedged.tsv"; : > "$d/build.log"
  local n; n=$(grep -c . "$d/reach_in.hex")
  for pass in $(seq 1 $((n + 1))); do
    build_image "$d" || { echo "BUILD FAILED"; return 2; }
    run_image "$d"; rc=$?
    grep -P '^[0-9a-f]+\t[0-9]+$' "$d/out.txt" >> "$d/all.tsv"
    if grep -q '^RESTOREFAULT' "$d/out.txt"; then
      echo "RESTORE FAULTED after '$(tail -2 "$d/out.txt" | head -1 | cut -f1)'"
      echo "  The per-probe restore itself took an exception.  That is a"
      echo "  harness failure, not a measurement, and it is reported rather"
      echo "  than skipped."
      return 7
    fi
    if grep -q '^DONE' "$d/out.txt"; then
      echo "pass $pass: COMPLETE (rc=$rc)"
      return 0
    fi
    bad=$(tail -1 "$d/out.txt" | cut -f1)
    echo "pass $pass: rc=$rc stopped at '$bad' after $(wc -l < "$d/out.txt") lines"
    [ -n "$bad" ] || { echo "no progress marker; aborting"; return 3; }
    if grep -qxF "$bad" "$d/skip.txt"; then
      echo "NO PROGRESS: pass $pass names '$bad', which is already skipped."
      return 5
    fi
    if confirm_wedge "$d" "$bad"; then
      echo "$bad" >> "$d/skip.txt"
      printf '%s\tWEDGES-THE-MACHINE\n' "$bad" >> "$d/wedged.tsv"
    else
      echo "INNOCENT SUSPECT: '$bad' runs to DONE on its own, so it is not"
      echo "  what killed the machine -- an encoding earlier in this shard"
      echo "  damaged state the probe does not restore.  Skipping it would"
      echo "  convict the wrong row and move the damage one along"
      echo "  (finding 250-A).  REFUSING."
      return 6
    fi
  done
  echo "BUDGET EXHAUSTED after $n passes"
  return 4
}

cd "$E"
cp "$T"/sysprobe.S "$T"/sysprobe.ld "$T"/sysprobe_mkblob.py .
POP=$(grep -c . reach_in.hex)
[ "$POP" -gt 0 ] || { echo "reach_in.hex is empty; nothing to probe" >&2; exit 3; }
echo "population $POP encodings; shards of $SHARD, $PAR concurrent, ${TMO}s each"

rm -rf shards; mkdir -p shards
split -l "$SHARD" -d -a 4 reach_in.hex shards/s
for f in shards/s*; do mkdir -p "$f.d"; mv "$f" "$f.d/reach_in.hex"; done

i=0
for d in shards/*.d; do
  ( shard_run "$d" > "$d/run.log" 2>&1; echo $? > "$d/rc" ) &
  i=$((i + 1))
  if [ $((i % PAR)) -eq 0 ]; then wait; fi
done
wait

ok=0; bad=0
: > all.tsv; : > wedged.tsv
for d in shards/*.d; do
  cat "$d/all.tsv" >> all.tsv
  cat "$d/wedged.tsv" >> wedged.tsv 2>/dev/null
  if [ "$(cat "$d/rc" 2>/dev/null)" = "0" ]; then
    ok=$((ok + 1))
  else
    bad=$((bad + 1))
    echo "SHARD INCOMPLETE ($d, rc=$(cat "$d/rc" 2>/dev/null))"
    sed 's/^/    /' "$d/run.log"
  fi
done
echo "shards ok=$ok incomplete=$bad"

# The ENABLE leg runs the same encodings in the same directory and picks up
# this file, which is how it used to inherit the plain leg's skips.  Only
# CONFIRMED wedges go in it: each of these was re-run on its own and killed
# the machine by itself, so the enable leg does not have to spend a 300s
# timeout per row rediscovering that.
cut -f1 wedged.tsv | sort -u > skip.txt

$PY - <<'EOF'
import collections
d = {}
for line in open('all.tsv'):
    h, v = line.split()
    d[h] = int(v)
want = [x.strip() for x in open('reach_in.hex') if x.strip()]
wedged = set()
try:
    for line in open('wedged.tsv'):
        wedged.add(line.split('\t')[0])
except IOError:
    pass
miss = [h for h in want if h not in d]
open('cpl0.tsv', 'w').write('hex\tcpl0_vec\n' +
    ''.join('%s\t%d\n' % (h, d[h]) for h in want if h in d))
# A row this probe could not measure is named by WHY: an encoding that kills
# the machine on its own was CONFIRMED to do so in isolation, and one that is
# merely absent was not.  The two are not the same silence.
say = 'CPL0: %d rows, %s' % (len(d), collections.Counter(d.values()))
conf = [h for h in miss if h in wedged]
other = [h for h in miss if h not in wedged]
if conf:
    say += '\n  WEDGES THE MACHINE (confirmed alone, no vector): %s' % ' '.join(conf)
if other:
    say += '\n  NOT MEASURED, cause not established: %s' % ' '.join(other)
print(say)
EOF

[ "$bad" -eq 0 ] || exit 4
exit 0
