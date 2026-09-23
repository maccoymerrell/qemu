#!/bin/bash
# ARC 3 -- ONE BOUNDED MACHINE PER VICTIM, so a wedge is a VERDICT.
#
# usage: sysprobe_isolate.sh <evidence-dir> <plain|enab> <cpu-model> <out.tsv>
#                            <hex> [hex...]
#
# The batch legs (sysprobe_run.sh, sysprobe_enab_run.sh) probe a whole shard
# in one boot.  An encoding that ends the boot is skipped and the shard is
# re-run without it, which keeps the OTHER rows measurable and leaves that one
# with nothing -- and "nothing" reached the published matrix as NOT-MEASURED
# on six x86_64 rows: dd30 FNSAVE, f4 HLT, 0f2200 mov-to-CR0, 0f05 SYSCALL and
# 0f07 / 480f07 SYSRET.
#
# THAT IS NOT A HOLE, IT IS AN UNREAD MEASUREMENT.  At CPL 0 these encodings
# do what the architecture says: HLT halts, SYSCALL and SYSRET leave the
# current flow, a mov to CR0 turns paging off.  The machine stopping IS the
# observation, and the only thing missing was an instrument that reads the
# boot rather than giving up on it.  So each victim gets its own machine,
# its own external watchdog, and QEMU's own execution and exception logs;
# sysprobe_verdict.py then derives the class from what the log shows.
#
# BOUNDED THREE WAYS, because a victim that runs away is the normal case here:
#   * one encoding per image, so nothing else can be blamed and nothing else
#     is lost when the boot ends;
#   * `timeout -k` is an EXTERNAL process: the reaper is not inside the thing
#     that wedged;
#   * the log is excerpted to the part the verdict was read off and the raw
#     `-d exec` stream is dropped above CST_ISO_KEEP bytes -- a mov to CR0
#     executing RAM for the whole window writes hundreds of megabytes, and
#     the verdict needs the first hundred lines after the victim.
#     CST_ISO_KEEP=0 keeps every raw log.
#
# Exit status: 0 when every victim got a verdict that answers the reachability
# question, 1 when any came back UNDETERMINED.  A verdict this cannot derive
# is reported by name, never folded into a neighbouring class.
#
# Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
#
# SPDX-License-Identifier: GPL-2.0-or-later
set -u
T="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E="$(cd "$1" && pwd)"; shift
LEG=$1; shift
CPU=$1; shift
OUT=$1; shift
Q=${CST_QEMU_ROOT:-/mnt/md0/QEMU/qemu}/build/qemu-system-x86_64
PY=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
TMO=${CST_ISO_TIMEOUT:-12}
KEEP=${CST_ISO_KEEP:-8388608}

case "$LEG" in plain|enab) ;; *) echo "leg must be plain or enab" >&2; exit 2;; esac

printf 'hex\toutcome\tvector\tevidence\n' > "$OUT"
bad=0
for hx in "$@"; do
  d="$E/isolate/$LEG/$hx"
  rm -rf "$d"; mkdir -p "$d" || exit 2
  cp "$T"/sysprobe.S "$T"/sysprobe.ld "$T"/sysprobe_mkblob.py \
     "$T"/sysprobe_enables.py "$d"/ || exit 2
  printf '%s\n' "$hx" > "$d/reach_in.hex"
  # NO skip.txt HERE, and that is the point: the batch legs inherit each
  # other's skips so a confirmed wedge is not re-discovered at full cost.
  # This arm exists to run exactly the encoding those legs skipped.
  (
    cd "$d" || exit 2
    $PY sysprobe_mkblob.py reach_in.hex || exit 2
    if [ "$LEG" = enab ]; then
      $PY sysprobe_enables.py enabblob.S     || exit 2
      gcc -m64 -DENABLE_LEG -c -o sysprobe.o sysprobe.S || exit 2
      gcc -m64 -c -o encblob.o  encblob.S    || exit 2
      gcc -m64 -c -o enabblob.o enabblob.S   || exit 2
      ld -T sysprobe.ld -o sysprobe.elf sysprobe.o encblob.o enabblob.o \
         || exit 2
    else
      gcc -m64 -c -o sysprobe.o sysprobe.S   || exit 2
      gcc -m64 -c -o encblob.o  encblob.S    || exit 2
      ld -T sysprobe.ld -o sysprobe.elf sysprobe.o encblob.o || exit 2
    fi
    objcopy -O binary sysprobe.elf sysprobe.bin || exit 2
    nm sysprobe.elf > syms.txt
  ) > "$d/build.log" 2>&1
  if [ $? -ne 0 ]; then
    printf '%s\tUNDETERMINED-BUILD-FAILED\t-\tsee %s\n' "$hx" "$d/build.log" \
      >> "$OUT"
    bad=$((bad + 1)); continue
  fi

  # The watchdog is a SEPARATE PROCESS.  -k guarantees the boot dies even if
  # it ignores the first signal; rc 124 is timeout's own "I reaped it".
  timeout -k 5 "$TMO" $Q -cpu "$CPU" -M pc -m 256 -no-reboot \
      -kernel "$d/sysprobe.bin" -debugcon "file:$d/out.txt" \
      -display none -serial none \
      -d exec,int,cpu_reset -D "$d/qlog.txt" >/dev/null 2>&1
  rc=$?
  reaped=0; [ "$rc" = 124 ] && reaped=1
  [ "$rc" = 137 ] && reaped=1

  $PY "$T/sysprobe_verdict.py" --dir "$d" --hex "$hx" \
      --qemu-rc "$rc" --reaped "$reaped" >> "$OUT" || bad=$((bad + 1))

  if [ "$KEEP" -gt 0 ] 2>/dev/null; then
    sz=$(stat -c %s "$d/qlog.txt" 2>/dev/null || echo 0)
    if [ "$sz" -gt "$KEEP" ]; then
      rm -f "$d/qlog.txt"
      echo "raw qlog $sz bytes > CST_ISO_KEEP=$KEEP: dropped, the excerpt \
beside it is what the verdict was read off" > "$d/qlog.DROPPED.txt"
    fi
  fi
done

echo "isolated verdicts -> $OUT"
sed 's/^/  /' "$OUT"
[ "$bad" -eq 0 ] || echo "$bad victim(s) came back UNDETERMINED"
exit $([ "$bad" -eq 0 ] && echo 0 || echo 1)
