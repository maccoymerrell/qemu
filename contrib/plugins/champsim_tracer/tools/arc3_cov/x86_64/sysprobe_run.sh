#!/bin/bash
# ARC 3 -- drive the CPL0 reachability probe to completion.
#
# usage: sysprobe_run.sh <evidence-dir> [cpu-model]
# reads  <evidence-dir>/reach_in.hex
# writes <evidence-dir>/cpl0.tsv        hex -> exception vector
#        <evidence-dir>/cpl0_wedge.tsv  hex -> what it did instead
#
# THE SECOND FILE IS WHY THIS LEG NO LONGER PUBLISHES HOLES.  A CPL0 probe
# can legitimately halt the machine or leave ring 0, and the shard loop can
# only skip such an encoding and move on.  Every row it skips is re-run in
# its own bounded machine (sysprobe_isolate.sh) and comes back with a class
# derived from that boot's own logs -- executed-and-halted,
# executed-and-left-CPL0-flow, executed-then-machine-unusable -- or with
# UNDETERMINED, which fails this script.  NOT-MEASURED is not an outcome
# this leg can produce any more.
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

# ---- EVERY ROW THE SHARDS COULD NOT MEASURE GETS ITS OWN MACHINE ----------
# The shard loop's job is throughput: it skips the encoding that ended the
# boot so the other 255 in that shard stay measurable.  What it leaves behind
# is an encoding with no row, and "no row" used to travel all the way to the
# published matrix as NOT-MEASURED.  It is not unmeasurable -- a CPL0 HLT
# halts, a SYSRET leaves ring 0, a mov to CR0 turns paging off, and the boot
# stopping IS the observation.  So each one is re-run alone, under an
# external watchdog, with QEMU's execution and exception logs kept, and
# sysprobe_verdict.py derives the class from what the log shows.
cut -f1 all.tsv | sort -u > .measured.hex
comm -23 <(sort -u reach_in.hex) .measured.hex > .unmeasured.hex
iso_rc=0
if [ -s .unmeasured.hex ]; then
  echo "unmeasured after the shards: $(wc -l < .unmeasured.hex) -- isolating"
  # shellcheck disable=SC2046
  "$T"/sysprobe_isolate.sh "$E" plain "$CPU" "$E/isolate_plain.tsv" \
      $(cat .unmeasured.hex) || iso_rc=1
else
  printf 'hex\toutcome\tvector\tevidence\n' > "$E/isolate_plain.tsv"
fi

$PY - <<'EOF'
import collections
import sys
d = {}
for line in open('all.tsv'):
    h, v = line.split()
    d[h] = int(v)
want = [x.strip() for x in open('reach_in.hex') if x.strip()]

# The isolated arm's MEASURED rows are ordinary measurements -- the shard just
# could not carry them -- so they join cpl0.tsv.  Everything else it returned
# is a VERDICT about what the encoding did, and it goes in its own file with
# the class and the evidence on the row.
iso = {}
for i, line in enumerate(open('isolate_plain.tsv')):
    if i == 0:
        continue
    f = line.rstrip('\n').split('\t', 3)
    if len(f) != 4:
        sys.exit('isolate_plain.tsv line %d has %d fields, not 4: a '
                 'verdict row this reader cannot parse is a row '
                 'it would DROP, and a dropped verdict reads '
                 'exactly like a hole.  %r'
                 % (i + 1, len(f), line))
    iso[f[0]] = (f[1], f[2], f[3])
for h, (outcome, vec, why) in iso.items():
    if outcome == 'MEASURED':
        d[h] = int(vec)

open('cpl0.tsv', 'w').write('hex\tcpl0_vec\n' +
    ''.join('%s\t%d\n' % (h, d[h]) for h in want if h in d))
wedge = [(h, iso[h]) for h in want
         if h in iso and iso[h][0] != 'MEASURED']
with open('cpl0_wedge.tsv', 'w') as f:
    f.write('hex\toutcome\tevidence\n')
    for h, (outcome, _v, why) in wedge:
        f.write('%s\t%s\t%s\n' % (h, outcome, why))

miss = [h for h in want if h not in d and h not in iso]
print('CPL0: %d rows, %s' % (len(d), collections.Counter(d.values())))
for h, (outcome, _v, why) in wedge:
    print('  %s  %s -- %s' % (h, outcome, why))
# A row with NO verdict at all is the only silence left, and it stops the leg
# rather than reaching the matrix as NOT-MEASURED.
undet = [h for h, (o, _v, _w) in wedge if o.startswith('UNDETERMINED')]
if miss or undet:
    sys.exit('CPL0 LEG REFUSED: %d row(s) have no verdict (%s) and %d came '
             'back UNDETERMINED (%s).  A reachability leg that cannot reach '
             'its subject says so here; it does not publish a hole.'
             % (len(miss), ' '.join(miss) or '-',
                len(undet), ' '.join(undet) or '-'))
EOF
py_rc=$?

[ "$bad" -eq 0 ] || exit 4
[ "$iso_rc" -eq 0 ] || exit 5
[ "$py_rc" -eq 0 ] || exit 6
exit 0
