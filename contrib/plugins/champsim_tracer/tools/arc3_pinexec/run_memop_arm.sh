#!/bin/bash
# The memop arm, end to end, with its negative controls.
#
# Author: Maccoy Merrell <maccoy.merrell@tamu.edu>
#
#   usage: run_memop_arm.sh <outdir> [qemu-build-dir] [pin-root]
#
# The register arm has had `run_reg_arm.sh` since it was written; the memop
# arm had only the three commands in README.md, which is why every memop
# cell in the coverage document had to be quoted from an earlier tip -- the
# reference half was expensive to reconstruct from prose and so it was not
# re-run.  This is that arm's entry point: it builds the tool, runs BOTH
# halves under ONE minimal environment (the two processes place their stacks
# independently, and an environment block of a different length multiplies
# the distinct pointer deltas the comparison has to establish), scores them,
# and then runs every negative control the arm owns.
#
# THE ACCEPTANCE BAR IS CHECKED HERE AND NOT LEFT TO A READER.  cmp_memop.py
# prints a report and exits 0 whatever it found; a runner that does the same
# is a gate that cannot fail.  So the bar -- TRACER-SUBSET 0, UNACCOUNTED 0,
# COUNT and WIDTH exact in both directions -- is read off the report and
# turned into an exit status, and every control must MOVE the instrument
# that owns its fact.  A control that does not fire is a finding about the
# harness, not a clean bill of health for the tracer.
#
# Every exit code is taken from the process.  Nothing is read through a pipe.
#
# ---------------------------------------------------------------------------
# WHERE THE GUEST RUNS IS AN INPUT TO THIS COMPARISON TOO  (#304, the
# mechanism #294 closed on the register arm)
# ---------------------------------------------------------------------------
# qemu-user resolves the program with realpath() and hands the RESULT to the
# guest as AT_EXECFN (linux-user/main.c `exec_path = real_exec_path`,
# linux-user/elfload.c `NEW_AUX_ENT(AT_EXECFN, info->file_string)`).  That
# string sits at the top of the guest stack, so every guest stack address
# below it moves with its LENGTH.
#
# The register arm was equalised for that at 175e1f52f5 and this one was not:
# it ran `cd "$OUT"` and built the workload there, so the guest path was
# `<whatever the caller passed>/w` and a caller who named a longer output
# directory moved the guest stack under the comparison.  The memop arm reads
# ADDRESSES as its subject on two of its four axes, so the exposure here is
# not smaller than the register arm's.
#
# So both halves run from a work directory of FIXED WIDTH -- a fixed root
# plus a 16-hex token derived from OUT, so two output directories never
# collide and neither one's NAME can reach the guest stack -- and the
# artifacts are moved into OUT when the leg is done.  The width is asserted,
# not assumed: a work root of a different length is a REFUSAL, because a leg
# that silently changes its own subject is worse than a leg that does not
# run.
set -u

OUT=${1:?usage: run_memop_arm.sh <outdir> [qemu-build] [pin-root]}
QB=${2:-/mnt/md0/QEMU/qemu/build}
PIN_ROOT=${3:-/mnt/md0/PIN/pin-external-4.2-99776-g21d818fa2-gcc-linux}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PY=${PY:-/home/maccoy-merrell/anaconda3/bin/python}
N=400000

# The canonical work root.  Its LENGTH is the load-bearing property; an
# override is allowed for a different filesystem but only at the same width,
# because a wider or narrower one moves the guest stack and makes this run's
# criterion incomparable with every other run's.  It is the SAME root the
# register arm uses, and the same width, so the two arms describe one guest.
CANON_WORKROOT=/mnt/md0/QEMU/cst_runs/_pinexec_work
WORKROOT=${CST_PINEXEC_WORKROOT:-$CANON_WORKROOT}

mkdir -p "$OUT" || exit 1
OUT=$(cd "$OUT" && pwd) || { echo "FAIL: cannot resolve $1" >&2; exit 1; }

[ ${#WORKROOT} -eq ${#CANON_WORKROOT} ] || {
  echo "FAIL: work root '$WORKROOT' is ${#WORKROOT} characters, the canonical
  '$CANON_WORKROOT' is ${#CANON_WORKROOT}.  The guest's own path length is an
  input to this comparison (#304), so a differently sized work root would
  produce a criterion that cannot be compared with any other run's." >&2
  exit 1; }

TOKEN=$(printf '%s' "$OUT" | sha256sum | cut -c1-16)
WORK=$WORKROOT/$TOKEN
rm -rf "$WORK" || { echo "FAIL: cannot clear $WORK" >&2; exit 1; }
mkdir -p "$WORK" || { echo "FAIL: cannot create $WORK" >&2; exit 1; }
# realpath() is what qemu-user applies, so a symlink anywhere above the work
# directory would defeat the whole point.  Prove it, do not assume it.
RWORK=$(cd "$WORK" && pwd -P) || { echo "FAIL: cannot resolve $WORK" >&2; exit 1; }
[ "$RWORK" = "$WORK" ] || {
  echo "FAIL: $WORK resolves to $RWORK -- a symlinked work root changes the
  guest's AT_EXECFN length and with it every guest stack address (#304)." >&2
  exit 1; }

cd "$WORK" || exit 1

RC=0
fail() { echo "FAIL: $*" >&2; exit 1; }
soft() { echo "NOT PROVEN: $*" >&2; RC=1; }

# ---------------------------------------------------------------- the tool
make -C "$HERE" PIN_ROOT="$PIN_ROOT" >"$WORK/make.log" 2>&1
[ $? -eq 0 ] || fail "pintool build (see $WORK/make.log)"
TOOL=$HERE/obj-intel64/champsim_memop_pintool.so
[ -f "$TOOL" ] || fail "no pintool at $TOOL"

# ------------------------------------------------------------- the workload
# The SAME workload the register arm uses, so the two arms describe one run.
cat > w.c <<'EOF'
#include <stdio.h>
int main(void){ long s=0; for(int i=0;i<20000;i++) s+= i*3 % 7; printf("%ld\n", s); return 0; }
EOF
gcc -static -O1 -no-pie -o w w.c || fail "workload build"

ENV=(env -i HOME=/tmp LANG=C)

# ------------------------------------------------------------- reference
"${ENV[@]}" setarch -R "$PIN_ROOT"/pin -t "$TOOL" -o memop.bin -s 0 -t $N \
    -- ./w >pin.stdout 2>pin.err
[ $? -eq 0 ] || fail "PIN reference (see $WORK/pin.err)"
[ -s memop.bin ] || fail "PIN wrote no reference"

# ---------------------------------------------------------------- tracer
# compress= is part of the option string, not an afterthought: a reference
# run's trace is a working file and an uncompressed one costs disk for
# nothing.  cst_audit names the member codec, which is how the compliance
# check reads it back rather than assuming.
#
# The comment sits HERE and not inside the command: a `#` line between two
# backslash continuations ENDS the continuation, so `./w` became its own
# command and qemu ran with no guest ("qemu: no user program specified").
# `bash -n` accepts that happily -- it is valid syntax and the wrong
# command -- and only running the leg caught it.
"${ENV[@]}" setarch -R "$QB"/qemu-x86_64 \
    -plugin "$QB"/contrib/plugins/libchampsim_tracer.so,outfile=q,wp=0,memdata=1,regdata=1,"compress=zstd -T0 -3 -q -c" \
    ./w >q.stdout 2>q.err
[ $? -eq 0 ] || fail "tracer run (see $WORK/q.err)"

# THE REFERENCE-MNEMONIC COLUMN IS GONE AND THAT IS THE DESIGN.
# `--objdump` rendered a Capstone column beside the generic one and
# retired with the tables at c32824defa; the comparison's Capstone
# side is an OFFLINE producer now (tools/cst_referee.py).  The column
# was a LABEL on report rows and never a term in the criterion -- the
# row keys carry the ENCODING, which is strictly finer than any
# mnemonic -- so dropping it costs the report a word per row and the
# scoring nothing.  qextract_mem.py fills `c` with "-" and says so.
"$QB"/contrib/plugins/cst_decode --format=disasm q.cst > q.disasm 2>q.dec.err
[ $? -eq 0 ] || fail "cst_decode (see $WORK/q.dec.err)"
PYTHONPATH=$HERE "$PY" "$HERE"/qextract_mem.py q.disasm $N > qm.jsonl 2>q.ext.err
[ $? -eq 0 ] || fail "qextract_mem (see $WORK/q.ext.err)"
rm -f q.disasm
NQ=$(wc -l < qm.jsonl)
[ "$NQ" -eq $N ] || fail "extracted $NQ instructions, wanted $N"

# ------------------------------------------------------------ the pairing
run_cmp() {
    local tag=$1 jsonl=$2
    PYTHONPATH=$HERE "$PY" "$HERE"/cmp_memop.py \
        --pin memop.bin --qemu "$jsonl" --anchor 0 \
        --out "cmp_$tag.txt" >"cmp_$tag.stdout" 2>"cmp_$tag.err"
    [ $? -eq 0 ] || fail "cmp_memop $tag (see $WORK/cmp_$tag.err)"
    [ -s "cmp_$tag.txt" ] || fail "cmp_memop $tag wrote no report"
}

# One number out of a report, by the label that owns it.  A grep that finds
# nothing returns the empty string and every comparison below then fails,
# which is the correct behaviour for a check that cannot find its subject.
field() {  # field <file> <regex> <awk-field>
    local v
    v=$(grep -m1 -E "$2" "$1" | awk "{print \$$3}")
    [ -n "$v" ] || { echo "NO SUCH FIELD in $1: $2" >&2; return 1; }
    echo "$v"
}
mism() {   # mism <file> <"load|store"> <"COUNT|ADDRESS|WIDTH|DATA">
    grep -m1 -E "^  $2 memop $3 " "$1" | sed -E 's/.*mismatched *([0-9]+).*/\1/'
}

run_cmp baseline qm.jsonl

# The reference-free arm: it needs no second process, and it is what
# convicts a corrupted VALUE at an address the two runs legitimately hold
# different bytes in.
PYTHONPATH=$HERE "$PY" "$HERE"/memcheck_self.py --qemu qm.jsonl \
    --out self_qemu.txt >self_qemu.stdout 2>self_qemu.err
[ $? -eq 0 ] || fail "memcheck_self (see $WORK/self_qemu.err)"

# ------------------------------------------------------- the acceptance bar
UNACC=$(field cmp_baseline.txt '^  UNACCOUNTED memops:' 3)   || fail "no UNACCOUNTED line"
SUBSET=$(grep -m1 -E '^  TRACER-SUBSET ' cmp_baseline.txt | sed -E 's/.*: *([0-9]+).*/\1/')
[ -n "$SUBSET" ] || fail "no TRACER-SUBSET line"
echo "baseline: UNACCOUNTED=$UNACC TRACER-SUBSET=$SUBSET"
[ "$UNACC" = 0 ]  || { echo "BAR: UNACCOUNTED is $UNACC, must be 0" >&2; RC=1; }
[ "$SUBSET" = 0 ] || { echo "BAR: TRACER-SUBSET is $SUBSET, must be 0" >&2; RC=1; }
for d in load store; do
    for a in COUNT WIDTH; do
        m=$(mism cmp_baseline.txt "$d" "$a")
        [ -n "$m" ] || fail "no $d memop $a line"
        [ "$m" = 0 ] || { echo "BAR: $d $a mismatched=$m, must be 0" >&2; RC=1; }
    done
done

# --------------------------------------------------------- the controls
# Each mutation names the instrument that must convict it.  `value` is the
# honest exception the README states: at an address the two processes
# already hold different bytes in, a cross-run value difference cannot by
# itself convict either instrument, so memcheck_self -- which needs no
# second process -- is what owns that row.
SELF0=$(field self_qemu.txt '^  loads VIOLATED' 3) || fail "no VIOLATED line"

for m in drop extra width addr value; do
    PYTHONPATH=$HERE "$PY" "$HERE"/negative_control.py \
        --in qm.jsonl --out "q_$m.jsonl" --mutation "$m" >"nc_$m.log" 2>&1
    [ $? -eq 0 ] || fail "negative_control $m (see $OUT/nc_$m.log)"
    run_cmp "$m" "q_$m.jsonl"
    case $m in
    drop)  v=$(mism "cmp_$m.txt" load  COUNT) ; own="load COUNT" ;;
    extra) v=$(mism "cmp_$m.txt" store COUNT) ; own="store COUNT" ;;
    width) v=$(mism "cmp_$m.txt" store WIDTH) ; own="store WIDTH" ;;
    addr)  v=$(mism "cmp_$m.txt" load  ADDRESS) ; own="load ADDRESS" ;;
    value) PYTHONPATH=$HERE "$PY" "$HERE"/memcheck_self.py --qemu "q_$m.jsonl" \
               --out "self_$m.txt" >/dev/null 2>&1
           [ $? -eq 0 ] || fail "memcheck_self $m"
           v=$(field "self_$m.txt" '^  loads VIOLATED' 3)
           own="memcheck_self VIOLATED (baseline $SELF0)"
           [ -n "$v" ] && v=$(( v - SELF0 )) ;;
    esac
    [ -n "$v" ] || fail "control $m: could not read $own"
    if [ "$v" -gt 0 ]; then
        echo "FIRES     $m -> $own moved by $v"
    else
        soft "$m did not move $own"
    fi
done

# --------------------------------------------------- what this run PINNED
# Written before the hand-back so it survives a failure, and it names the
# property #304 is about: the length of the path the guest was given.
{
  echo "work                 $WORK"
  echo "work path length     ${#WORK}   (guest AT_EXECFN is $WORK/w)"
  echo "guest realpath       $WORK/w   (${#WORK} + 2 characters)"
  echo "workload sha256      $(sha256sum w | cut -d' ' -f1)"
  echo "environment          env -i HOME=/tmp LANG=C, setarch -R"
  echo "reference sha256     $(sha256sum memop.bin | cut -d' ' -f1)"
  echo "tracer   sha256      $(sha256sum qm.jsonl | cut -d' ' -f1)"
} > REPRO.txt

# --------------------------------------------------------- hand back to OUT
cd / || exit 1
mv "$WORK"/* "$OUT"/ || fail "cannot move artifacts from $WORK to $OUT"
rmdir "$WORK" 2>/dev/null

echo "=== $OUT/cmp_baseline.txt ==="
sed -n '/=== memop agreement/,/=== every disagreeing/p' "$OUT/cmp_baseline.txt"
exit $RC
