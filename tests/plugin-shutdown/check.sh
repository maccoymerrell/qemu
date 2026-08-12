#!/bin/bash
#
# Contract check for the machine-shutdown plugin callback.
#
# Four cells, each asserting one clause of qemu_plugin_vm_shutdown_cb_t:
#
#   origin    a guest poweroff NAMES the vCPU that executed the device
#             write, and that vCPU is the one whose state is live
#   unnamed   a shutdown nobody in the guest asked for names NO vCPU, and
#             still runs in vCPU context
#   wedge0    the first vCPU in the list is not the only candidate: with it
#             stalled, some other vCPU carries the callback promptly
#   wedgeall  with EVERY vCPU stalled the wait is bounded, QEMU says so,
#             and the machine shuts down anyway
#
# Usage: check.sh [outdir]
#   BUILD=<dir>    QEMU build directory (default <src>/build)
#   SYSTEST=<dir>  guest kernel/rootfs tree (default /mnt/md0/QEMU/systest)
#   CPUS=<list>    taskset CPU list
#
# Author: Maccoy Merrell.
#
# SPDX-License-Identifier: GPL-2.0-or-later

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/../.." && pwd)"
BUILD="${BUILD:-$SRC/build}"
SYSTEST="${SYSTEST:-/mnt/md0/QEMU/systest}"
CPUS="${CPUS:-120-143}"
OUT="${1:-/mnt/md0/QEMU/cst_runs/qfix/d_shut/check}"

QBIN="$BUILD/qemu-system-x86_64"
PROBE="$OUT/shutdown-probe.so"

rm -rf "$OUT"; mkdir -p "$OUT" || exit 90
fails=0

say() { printf '%s\n' "$*"; }

# ---------------------------------------------------------------- probe ---
[ -x "$QBIN" ] || { say "FAIL setup: no $QBIN"; exit 90; }

gcc -O2 -g -shared -fPIC -Wall \
    -I "$SRC/include/qemu" $(pkg-config --cflags glib-2.0) \
    -o "$PROBE" "$HERE/shutdown-probe.c" \
    $(pkg-config --libs glib-2.0) > "$OUT/probe.build.log" 2>&1
[ -f "$PROBE" ] || { say "FAIL setup: probe did not build"; cat "$OUT/probe.build.log"; exit 90; }

# ----------------------------------------------------------------- guest ---
# A cell that cannot find its guest FAILS; it does not quietly skip.
build_initrd() {
    local tail="$1" dst="$2" sr="$OUT/sysroot.$$"
    [ -d "$SYSTEST/x86/root" ] || return 1
    rm -rf "$sr"; cp -a "$SYSTEST/x86/root" "$sr" || return 1
    cat > "$sr/init" <<EOS
#!/bin/sh
mount -t devtmpfs none /dev 2>/dev/null
mount -t proc none /proc 2>/dev/null
exec >/dev/console 2>&1 </dev/console
echo "=== shutdown-probe guest up ==="
$tail
EOS
    chmod 755 "$sr/init"
    ( cd "$sr" && find . | cpio -H newc -o --quiet | gzip -c > "$dst" ) || return 1
    rm -rf "$sr"
    return 0
}

# ------------------------------------------------------------------ cell ---
# run_cell <name> <sigterm_after_s|-> <exit_deadline_s> <qemu args...>
run_cell() {
    local name="$1" term_at="$2" deadline="$3"; shift 3
    local dir="$OUT/$name"
    mkdir -p "$dir"

    printf '%s\n' "$@" > "$dir/cmd"
    ( ulimit -v 16777216; exec taskset -c "$CPUS" "$@" ) \
        > "$dir/console" 2> "$dir/qemu.err" &
    local pid=$!

    if [ "$term_at" != "-" ]; then
        sleep "$term_at"
        kill -TERM "$pid" 2>/dev/null
    fi

    local waited=0 rc=""
    while [ "$waited" -lt "$deadline" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"; rc=$?
            break
        fi
        sleep 1; waited=$((waited + 1))
    done
    if [ -z "$rc" ]; then
        kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
        echo "TIMEOUT" > "$dir/rc"
        return 1
    fi
    echo "$rc" > "$dir/rc"
    return 0
}

# A report line the cell never produced is a failed cell, not a passed one.
field() {
    local dir="$1" key="$2"
    sed -n 's/.*[^a-z_]\?'"$key"'=\(-\?[0-9]\+\).*/\1/p' "$dir/probe.txt" 2>/dev/null | head -1
}

check() {
    local what="$1" got="$2" want="$3"
    if [ "$got" = "$want" ]; then
        say "    ok   $what = $got"
    else
        say "    BAD  $what = ${got:-<absent>} (want $want)"
        fails=$((fails + 1))
    fi
}

check_ge() {
    local what="$1" got="$2" want="$3"
    if [ -n "$got" ] && [ "$got" -ge "$want" ] 2>/dev/null; then
        say "    ok   $what = $got (>= $want)"
    else
        say "    BAD  $what = ${got:-<absent>} (want >= $want)"
        fails=$((fails + 1))
    fi
}

# =========================================================== cell: origin ===
say "cell origin: guest poweroff names the vCPU that performed the write"
d="$OUT/origin"; mkdir -p "$d"
if ! build_initrd 'poweroff -f' "$OUT/origin.cpio.gz"; then
    say "    BAD  no guest image under $SYSTEST/x86 -- cannot run this cell"
    fails=$((fails + 1))
elif ! run_cell origin - 120 \
        "$QBIN" -nographic -no-reboot -m 512 -smp 2 -cpu Haswell \
        -kernel "$SYSTEST/x86/vmlinuz" -initrd "$OUT/origin.cpio.gz" \
        -append "console=ttyS0 panic=-1" \
        -plugin "$PROBE,out=$d/probe.txt"; then
    say "    BAD  guest never powered off"
    fails=$((fails + 1))
else
    o=$(field "$d" origin); check_ge "origin"        "$o" 0
    check    "in_guest_insn" "$(field "$d" in_guest_insn)" 1
    check    "current"       "$(field "$d" current)" "$o"
fi

# ========================================================== cell: unnamed ===
say "cell unnamed: SIGTERM names no vCPU and still runs in vCPU context"
d="$OUT/unnamed"; mkdir -p "$d"
if ! build_initrd 'while true; do :; done' "$OUT/spin.cpio.gz"; then
    say "    BAD  no guest image under $SYSTEST/x86 -- cannot run this cell"
    fails=$((fails + 1))
elif ! run_cell unnamed 25 60 \
        "$QBIN" -nographic -no-reboot -m 512 -smp 4 -cpu Haswell \
        -kernel "$SYSTEST/x86/vmlinuz" -initrd "$OUT/spin.cpio.gz" \
        -append "console=ttyS0 panic=-1" \
        -plugin "$PROBE,out=$d/probe.txt"; then
    say "    BAD  qemu did not exit after SIGTERM"
    fails=$((fails + 1))
else
    check    "origin"        "$(field "$d" origin)" -2
    check    "in_guest_insn" "$(field "$d" in_guest_insn)" 0
    check_ge "current"       "$(field "$d" current)" 0
fi

# =========================================================== cell: wedge0 ===
# vCPU 0 stalls inside an instrumentation callback on its first block; the
# other three never leave the firmware's halt, so they are idle and their
# work queues drain at once.  Placing the callback on first_cpu alone would
# wait for the one vCPU that cannot take it.
say "cell wedge0: a stalled first_cpu does not hold the shutdown"
d="$OUT/wedge0"; mkdir -p "$d"
if ! run_cell wedge0 8 40 \
        "$QBIN" -nographic -m 256 -smp 4 -cpu Haswell \
        -plugin "$PROBE,out=$d/probe.txt,wedge=on,wedgeafter=1,wedgecap=120"; then
    say "    BAD  qemu did not exit after SIGTERM (wedged first_cpu held it)"
    fails=$((fails + 1))
else
    check    "origin"        "$(field "$d" origin)" -2
    check_ge "current"       "$(field "$d" current)" 0
    if grep -q "no vCPU reached a translation-block boundary" "$d/qemu.err"; then
        say "    BAD  fell back to the bounded path although a vCPU was idle"
        fails=$((fails + 1))
    else
        say "    ok   delivered on a live vCPU, no fallback"
    fi
fi

# ========================================================= cell: wedgeall ===
# The only vCPU stalls, so nothing can ever drain a work queue.  The wait
# must end, say so, and let the machine go down.
say "cell wedgeall: with every vCPU stalled the wait is bounded and loud"
d="$OUT/wedgeall"; mkdir -p "$d"
if ! run_cell wedgeall 8 45 \
        "$QBIN" -nographic -m 256 -smp 1 -cpu Haswell \
        -plugin "$PROBE,out=$d/probe.txt,wedge=on,wedgeafter=1,wedgecap=120"; then
    say "    BAD  qemu never exited: the shutdown wait is unbounded"
    fails=$((fails + 1))
else
    check "origin"        "$(field "$d" origin)" -1
    check "in_guest_insn" "$(field "$d" in_guest_insn)" 0
    if grep -q "no vCPU reached a translation-block boundary" "$d/qemu.err"; then
        say "    ok   QEMU reported the degraded close"
    else
        say "    BAD  bounded path taken with no diagnostic"
        fails=$((fails + 1))
    fi
fi

say ""
if [ "$fails" -eq 0 ]; then
    say "plugin-shutdown: PASS"
    exit 0
fi
say "plugin-shutdown: FAIL ($fails checks)"
exit 1
