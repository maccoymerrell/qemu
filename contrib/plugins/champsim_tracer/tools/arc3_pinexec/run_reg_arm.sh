#!/bin/bash
# The register arm, end to end, with its negative controls.
#
# Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
#
#   usage: run_reg_arm.sh <outdir> [qemu-build-dir] [pin-root]
#
# Builds nothing it can avoid rebuilding, runs BOTH halves under ONE minimal
# environment, pairs them with the anchor the pairing needs, and then runs
# every negative control through the SAME anchor.  cmp_reg.py refuses an
# unaligned pair with rc=2 rather than scoring it, which is why the anchor
# is supplied here and not left to be rediscovered per control.
#
# Every exit code is taken from the process.  Nothing is read through a pipe.
#
# ---------------------------------------------------------------------------
# WHERE THE GUEST RUNS IS AN INPUT TO THE COMPARISON  (#294)
# ---------------------------------------------------------------------------
# The leg read criterion 265, 266, 268, 275, 277, 277, 278 across waves that
# changed nothing but the directory their output went to.  The mechanism is
# not noise:
#
#   qemu-user resolves the program with realpath() and hands the RESULT to
#   the guest as AT_EXECFN (linux-user/main.c `exec_path = real_exec_path`,
#   linux-user/elfload.c `NEW_AUX_ENT(AT_EXECFN, info->file_string)`).  That
#   string sits at the top of the guest stack, so EVERY guest stack address
#   below it moves with its LENGTH.
#
#   MEASURED: the same `w` run from a directory nine characters longer
#   starts with rsp 0x10 lower (0x7fffe5dffe30 -> 0x7fffe5dffe20).  The
#   comparison's pointer-delta model is built from exactly those addresses,
#   and a delta that gains or loses a page domain flips a batch of rows
#   between "same pointer under an ESTABLISHED delta" and UNACCOUNTED.
#
#   MEASURED both ways: three runs at path length 60 read 278/278/278 and
#   three at length 51 read 266/266/266.  Same length, same criterion; a
#   different length, a different criterion.
#
# So both halves are run from a work directory whose absolute path has a
# FIXED WIDTH -- a fixed root plus a 16-hex token derived from OUT, so two
# output directories never collide and neither one's NAME can reach the
# guest stack -- and the artifacts are moved into OUT when the leg is done.
# The width is asserted, not assumed: a work root of a different length is a
# REFUSAL, because a leg that silently changes its own subject is worse than
# a leg that does not run.
#
# THE OTHER THREE INPUTS, and what is done with each:
#
#   CPUID initial APIC ID.  The native half's CPUID leaf 1 EBX[31:24] and
#   leaf 0xB EDX are the APIC id of the core the process landed on -- it read
#   0x03 on one run and 0x44 on the next.  `taskset` pins it.  (qemu-user
#   emulates a fixed id, so the tracer half never had this.)
#
#   AT_RANDOM and getrandom(2) on the TRACER half.  qemu-user serves both
#   from its own PRNG (07fb07507f); unseeded, that PRNG is seeded from the
#   host and the guest's TLS stack guard and pointer guard differ every run.
#   `-seed 1` makes the tracer half repeat itself.
#
#   AT_RANDOM on the NATIVE half, and gettid()/getpid() on both.  NOT
#   PINNABLE and not pretended to be: the kernel draws 16 fresh bytes for
#   every execve and glibc's static startup turns them into the guard words
#   before any code this project owns runs, and a deterministic pid needs a
#   PID namespace this host does not grant unprivileged (`unshare -Urpf`
#   fails: /proc/self/uid_map, Operation not permitted).  Their blast radius
#   is MEASURED, not assumed -- see REPRO.txt and the leg's evidence.
set -u

OUT=${1:?usage: run_reg_arm.sh <outdir> [qemu-build] [pin-root]}
QB=${2:-/mnt/md0/QEMU/qemu/build}
PIN_ROOT=${3:-/mnt/md0/PIN/pin-external-4.2-99776-g21d818fa2-gcc-linux}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
N=400000

# The canonical work root.  Its LENGTH is the load-bearing property; an
# override is allowed for a different filesystem but only at the same width,
# because a wider or narrower one moves the guest stack and makes this run's
# criterion incomparable with every other run's.
CANON_WORKROOT=/mnt/md0/QEMU/cst_runs/_pinexec_work
WORKROOT=${CST_PINEXEC_WORKROOT:-$CANON_WORKROOT}
CPU=${CST_PINEXEC_CPU:-0}
PY=${PY:-/home/maccoy-merrell/anaconda3/bin/python}
SEED=${CST_PINEXEC_SEED:-1}

fail() { echo "FAIL: $*" >&2; exit 1; }

mkdir -p "$OUT" || exit 1
OUT=$(cd "$OUT" && pwd) || fail "cannot resolve $1"

[ ${#WORKROOT} -eq ${#CANON_WORKROOT} ] || fail \
  "work root '$WORKROOT' is ${#WORKROOT} characters, the canonical
  '$CANON_WORKROOT' is ${#CANON_WORKROOT}.  The guest's own path length is an
  input to this comparison (#294), so a differently sized work root would
  produce a criterion that cannot be compared with any other run's."

TOKEN=$(printf '%s' "$OUT" | sha256sum | cut -c1-16)
WORK=$WORKROOT/$TOKEN
rm -rf "$WORK" || fail "cannot clear $WORK"
mkdir -p "$WORK" || fail "cannot create $WORK"
# realpath() is what qemu-user applies, so a symlink anywhere above the work
# directory would defeat the whole point.  Prove it, do not assume it.
RWORK=$(cd "$WORK" && pwd -P) || fail "cannot resolve $WORK"
[ "$RWORK" = "$WORK" ] || fail \
  "$WORK resolves to $RWORK -- a symlinked work root changes the guest's
  AT_EXECFN length and with it every guest stack address (#294)."

cd "$WORK" || exit 1

# Stated rather than inherited: RLIMIT_STACK places the native half's stack.
ulimit -s 8192 || fail "cannot pin RLIMIT_STACK"

# ---------------------------------------------------------------- the tool
make -C "$HERE" PIN_ROOT="$PIN_ROOT" >"$WORK/make.log" 2>&1
[ $? -eq 0 ] || fail "pintool build (see $WORK/make.log)"
TOOL=$HERE/obj-intel64/champsim_reg_pintool.so
[ -f "$TOOL" ] || fail "no pintool at $TOOL"

# ------------------------------------------------------------- the workload
cat > w.c <<'EOF'
#include <stdio.h>
int main(void){ long s=0; for(int i=0;i<20000;i++) s+= i*3 % 7; printf("%ld\n", s); return 0; }
EOF
gcc -static -O1 -no-pie -o w w.c || fail "workload build"

# ONE minimal environment for both halves: the two processes place their
# stacks independently, and an environment block of a different length
# multiplies the distinct pointer deltas the comparison has to establish.
ENV=(env -i HOME=/tmp LANG=C)
PIN_CPU=(taskset -c "$CPU")

# ------------------------------------------------------------- reference
"${PIN_CPU[@]}" "${ENV[@]}" setarch -R "$PIN_ROOT"/pin -t "$TOOL" \
    -o reg.bin -s 0 -t $N -- ./w >pin.stdout 2>pin.err
[ $? -eq 0 ] || fail "PIN reference (see $WORK/pin.err)"
[ -s reg.bin ] || fail "PIN wrote no reference"

# ---------------------------------------------------------------- tracer
"${PIN_CPU[@]}" "${ENV[@]}" setarch -R "$QB"/qemu-x86_64 -seed "$SEED" \
    -plugin "$QB"/contrib/plugins/libchampsim_tracer.so,outfile=q,wp=0,memdata=1,regdata=1 \
    ./w >q.stdout 2>q.err
[ $? -eq 0 ] || fail "tracer run (see $WORK/q.err)"

"$QB"/contrib/plugins/cst_decode --format=disasm --objdump q.cst > q.disasm 2>q.dec.err
[ $? -eq 0 ] || fail "cst_decode (see $WORK/q.dec.err)"
PYTHONPATH=$HERE "$PY" "$HERE"/qextract_mem.py q.disasm $N > q.jsonl 2>q.ext.err
[ $? -eq 0 ] || fail "qextract_mem (see $WORK/q.ext.err)"
rm -f q.disasm
NQ=$(wc -l < q.jsonl)
[ "$NQ" -eq $N ] || fail "extracted $NQ instructions, wanted $N"

# ------------------------------------------------------ what this run PINNED
# Written before the comparison so it survives a comparison failure.  The two
# input hashes are here to be READ, not to be equal: the tracer half is
# expected to repeat byte for byte, the native half is NOT, and saying so in
# the artifact is what stops a future pass reading "reg.bin changed" as a
# finding.
{
  echo "work                 $WORK"
  echo "work path length     ${#WORK}   (guest AT_EXECFN is $WORK/w)"
  echo "guest realpath       $WORK/w   (${#WORK} + 2 characters)"
  echo "workload sha256      $(sha256sum w | cut -d' ' -f1)"
  echo "cpu pinned to        $CPU  (taskset; fixes CPUID initial APIC ID)"
  echo "qemu seed            $SEED  (fixes AT_RANDOM + getrandom on the tracer half)"
  echo "RLIMIT_STACK         $(ulimit -s) KiB"
  echo "environment          env -i HOME=/tmp LANG=C, setarch -R"
  echo "reference sha256     $(sha256sum reg.bin | cut -d' ' -f1)"
  echo "tracer   sha256      $(sha256sum q.jsonl | cut -d' ' -f1)"
  echo "tracer   .cst sha256 $(sha256sum q.cst | cut -d' ' -f1)"
  echo
  echo "NOT PINNED, and MEASURED rather than asserted:"
  echo "  * the NATIVE half's AT_RANDOM.  The kernel draws 16 fresh bytes per"
  echo "    execve and glibc's static startup turns them into the TLS stack"
  echo "    guard and the pointer guard before any code this project owns"
  echo "    runs.  reg.bin's hash therefore differs every run BY"
  echo "    CONSTRUCTION.  Measured blast radius over three runs: the two"
  echo "    canary-check sites and their two flag consumers, 4 rows, ALL"
  echo "    ORTHOGONAL, criterion unchanged."
  echo "  * both halves' gettid()/getpid().  Values below 0x400000 never"
  echo "    enter the pointer-delta map, so they name no row."
  echo "  * WHOLE-MAPPING RELOCATION of the tracer half.  q.jsonl repeats"
  echo "    byte for byte run to run in the common case, but qemu-user'\''s"
  echo "    guest mappings can land at a different host address between"
  echo "    runs (measured: 0x7fffe5dfe... and 0x7ffff21ed... over three"
  echo "    runs of one command).  It is NOT the directory name -- four"
  echo "    different work-dir tokens of equal length gave one placement --"
  echo "    and the comparison'\''s delta model absorbs a relocated mapping by"
  echo "    construction, which is why the criterion did not move.  So do"
  echo "    not read a changed q.jsonl hash as a finding on its own; read"
  echo "    the criterion and the row set."
} > REPRO.txt

# ------------------------------------------------------------ the pairing
# --anchor 0 --qskip 1: PIN's skip gate consumes one instruction before it
# arms, so the reference's record 0 is the tracer's record 1.
rm -f negcontrols.txt
run_cmp() {
    local tag=$1; shift
    PYTHONPATH=$HERE "$PY" "$HERE"/cmp_reg.py \
        --pin reg.bin --qemu q.jsonl --anchor 0 --qskip 1 \
        --maxreport 99999 --summary negcontrols.txt \
        --out "cmp_$tag.txt" "$@"
    local rc=$?
    [ $rc -eq 0 ] || fail "cmp_reg $tag rc=$rc (see $WORK/cmp_$tag.txt)"
}

run_cmp baseline
for m in dropsrc extrasrc dropdst dstvalue srcvalue; do
    run_cmp "$m" --mutate="$m"
done

# --------------------------------------------------------- hand back to OUT
cd / || exit 1
mv "$WORK"/* "$OUT"/ || fail "cannot move artifacts from $WORK to $OUT"
rmdir "$WORK" 2>/dev/null

echo "=== $OUT/negcontrols.txt ==="
cat "$OUT/negcontrols.txt"
