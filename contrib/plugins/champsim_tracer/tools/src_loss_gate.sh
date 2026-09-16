#!/bin/bash
# THE SOURCE-LOSS GATE: does a candidate change take a published source off
# the wire?  Usage: src_loss_gate.sh <build-dir> <arm-A-dir> <arm-B-dir>
#
# Arm A is the wire as it is; arm B is the wire with the candidate change in
# it.  Both must be produced by the SAME wrapper from arm directories of the
# same path LENGTH -- qemu-user puts the host environment on the guest stack,
# so two arms taken differently do not cover the same pcs (#327) and the
# instrument reports that as an ERROR rather than skipping the row.
#
# WHY IT IS A STANDING ROW AND NOT A ONE-OFF.  The two instruments this tree
# already runs cannot see this direction.  The source CENSUS scores whether a
# PUBLISHED source is justified, so a source that stops being published leaves
# no row to score.  SETPROOF compares against a baseline that PREDATES the
# source-list flip, so a register the flip added and a later change removes was
# absent on both sides and never enters the comparison.  Measured: with the
# Capstone operand walk's read arm deleted, both read GREEN while 48
# register-instances left the wire at 33 program counters.
#
# The bar is UNADJUDICATED losses == 0.  A loss a maintainer has ruled
# removable goes in tools/src_loss_adjudicated.txt with its reason and is
# counted, printed and excluded; a ledger row whose subject the measurement
# does not contain FAILS, because a ledger that outlives its subject stops
# gating.
set -u
build=${1:?usage: src_loss_gate.sh <build-dir> <arm-A-dir> <arm-B-dir>}
A=${2:?arm A directory}
B=${3:?arm B directory}
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
py=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
led=${CST_SRC_LOSS_LEDGER:-$here/src_loss_adjudicated.txt}

for d in "$A" "$B"; do
    if [ ! -d "$d" ]; then
        echo "src_loss_gate: REFUSED -- arm directory $d does not exist." \
             "A gate that cannot find its subject FAILS."
        exit 2
    fi
done

"$py" "$here/arc3_cov/instruments/srcset_ab.py" --selftest > /dev/null
sel=$?
if [ "$sel" != 0 ]; then
    echo "src_loss_gate: REFUSED -- the instrument's own planted-fire proof" \
         "did not pass (rc=$sel).  An instrument nobody has shown can fire" \
         "is not evidence."
    exit 2
fi

"$py" "$here/arc3_cov/instruments/srcset_ab.py" "$A" "$B" --adjudicated "$led"
rc=$?
case $rc in
0) echo "src_loss_gate: PASS -- no published source left the wire unadjudicated" ;;
1) echo "src_loss_gate: FAIL -- a published source left the wire, or a" \
        "ledger row has no subject" ;;
*) echo "src_loss_gate: REFUSED -- the arms could not be compared (rc=$rc)" ;;
esac
exit $rc
