#!/bin/bash
# ARC 3 -- shard the aarch64 EL1 reachability probe and merge the verdicts.
#
# usage: sysreach_batch.sh <evidence-dir> <rows-per-shard> <parallel> [cpu]
# reads  <evidence-dir>/reach_in.hex, writes <evidence-dir>/el1.tsv
#
# WHY SHARDS.  An encoding that wedges the machine is skipped and the pass is
# re-run, and a self-looping branch -- `bl .+4` returns to itself forever --
# is not rare.  With one image for the whole denominator each wedge costs a
# full pass; with shards it costs only the shard's.  The parallel cap is a
# COURTESY constraint on a shared workstation and is honoured exactly: this
# script never runs more than `parallel` concurrent machines.
set -u
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E="$(cd "$1" && pwd)"; N=${2:-250}; P=${3:-8}; CPU=${4:-max}
cd "$E" || exit 2
rm -rf shards; mkdir -p shards
split -l "$N" -d -a 3 reach_in.hex shards/s
for d in shards/s*; do
  mkdir -p "$d.d"; mv "$d" "$d.d/reach_in.hex"
done
i=0
for d in shards/*.d; do
  ( CST_A64_TIMEOUT=${CST_A64_TIMEOUT:-60} "$T"/sysreach_run.sh "$d" "$CPU" > "$d/run.log" 2>&1 ) &
  i=$((i + 1))
  if [ $((i % P)) -eq 0 ]; then wait; fi
done
wait
ok=0; bad=0
: > el1_merged.tsv
for d in shards/*.d; do
  if [ -f "$d/el1.tsv" ]; then
    tail -n +2 "$d/el1.tsv" >> el1_merged.tsv; ok=$((ok + 1))
  else
    echo "SHARD INCOMPLETE: $d"; bad=$((bad + 1))
  fi
done
( printf 'hex\tel1_ec\tel1_decoded\n'; cat el1_merged.tsv ) > el1.tsv
rm -f el1_merged.tsv
want=$(grep -c . reach_in.hex)
got=$(( $(wc -l < el1.tsv) - 1 ))
echo "shards ok=$ok incomplete=$bad   rows $got of $want"
grep -h 'wedged\|outside the slot' shards/*.d/run.log 2>/dev/null | sed 's/^/  /'
[ "$bad" -eq 0 ] || exit 3
exit 0
