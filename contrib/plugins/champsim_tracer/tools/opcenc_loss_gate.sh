#!/bin/bash
# THE PER-ENCODING OPCODE-CLASS GATE: does a candidate change move, or erase,
# the GenericOpcode an encoding publishes?
#
#   opcenc_loss_gate.sh capture <build-dir> <out-dir> <workload-dir>
#   opcenc_loss_gate.sh compare <build-dir> <A-corpus.tsv> <B-corpus.tsv>
#
# WHY IT IS A STANDING ROW BESIDE srcenc_loss_gate.sh AND NOT A ONE-OFF.
# PASS 45 named the hole in one line -- "no loss instrument can see an
# opcode-class move" -- and the three instruments it meant say why.  SETPROOF
# scores register SETS.  srcenc_loss_gate scores published READ LISTS.  The
# identity census counts identity rows and their tiers.  None of them reads
# the opcode column, so an arm that reclassifies an encoding passes every
# standing bar this tree has, silently.
#
# THAT IS THE GAP THE NEXT ARC STEP HAS TO CROSS.  6,570 identity rows carry a
# QEMU-stated opcode and 86.7% of them are tier STATED; `qemu_ident_classify()`
# returns nullptr for STATED, so those classes are counted and then refused --
# no wire path at all.  Admitting them moves the wire's opcode column.  R19
# says a verification ratchets toward truth, which it cannot do while the
# movement it is claiming is invisible per encoding.
#
# KEYED ON THE ENCODING for the same reason its sibling is: a wrong-path
# instruction has no stable pc to compare across arms, and every per-pc
# instrument here runs at wp=0.  So this captures at wp=0 AND wp=16 and
# merges, and a duplicate encoding whose class DISAGREES across the two
# settings is a conflict the instrument refuses on -- never a
# last-writer-wins.
#
# THE BAR is UNADJUDICATED class LOSSES == 0 and UNADJUDICATED class MOVES
# == 0, with matched coverage as a PRECONDITION.  A GAIN -- an encoding that
# published GEN_OP_UNKNOWN in A and a class in B -- is counted and NAMED but
# is never the bar: it cannot take information off the wire.  Nothing is ever
# netted against anything.
#
# A ruled transition goes in tools/opcenc_loss_adjudicated.txt naming the
# exact `<A_CLASS> <B_CLASS>` pair with its reason, and is counted, printed
# and excluded; a ledger row whose subject the measurement does not contain
# FAILS, because a ledger that outlives its subject stops gating.
#
# rc=0 PASS, rc=1 FAIL (a loss, an unadjudicated move, or a stale ledger row),
# rc=2 REFUSED (the arms could not be compared, or the capture produced
# nothing).  rc=2 is never folded into rc=0: a gate that cannot look must not
# report all-clear.
#
# Author: Maccoy Merrell.
set -u

mode=${1:?usage: opcenc_loss_gate.sh capture|compare ...}
shift
build=${1:?build directory}
shift
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
py=${CST_PYTHON:-/home/maccoy-merrell/anaconda3/bin/python}
inst=$here/arc3_cov/instruments/opcenc_ab.py
led=${CST_OPCENC_LEDGER:-$here/opcenc_loss_adjudicated.txt}
ISAS="x86_64 aarch64 riscv64 mipsel"
# THE COVERAGE PRECONDITION IS NOT FREE, AND IT WAS NOT STABLE.
#
# This gate refuses unless the two arms cover the SAME encodings, which is
# right: a class comparison over two different populations is not readable.
# But exec96 ran the control that had never been run -- ONE build, TWO
# captures, compared against each other -- and it REFUSED: x86_64 only_A=1
# only_B=6, aarch64 only_B=4, riscv64 only_A=13 only_B=2.  The arms were the
# same binary.
#
# The moving part is the WRONG PATH.  A wrong-path excursion walks whatever
# bytes the redirected pc lands on, and some of those addresses hold data the
# guest has not written yet, so a handful of the encodings the sweep reaches
# differ between two runs of one binary.  It is a few rows in seven thousand,
# and that is exactly what makes it dangerous: a REFUSED verdict reads as "the
# change moved the population" when it can just as easily be this.
#
# THE CAUSE IS AT_RANDOM, AND IT IS PINNABLE.  `setarch -R` fixes the address
# space and fixes nothing else: the guest is still handed sixteen fresh random
# bytes in its auxv every run, glibc turns them into the stack canary and the
# pointer guard, and those bytes sit in guest memory where a wrong-path walk
# reads them AS INSTRUCTIONS.  Two runs of one binary therefore decode
# different bytes at the same address.  linux-user already has the pin --
# `-seed` for AT_RANDOM and `-pid` for the identity the guest reads from
# set_tid_address -- and this gate simply never used them.  With both, two
# captures of one build are BYTE-IDENTICAL, dump file for dump file.
#
# The corpus is ALSO a union over repeats, and with the input pinned that is
# no longer a way to average over noise -- it is a CHECK.  Every repeat must
# reach the same set, so `missed_by_one_capture` must read 0 on every cell,
# and a non-zero says the reach depends on something still unpinned.  The
# conflict check is unchanged: an encoding two repeats give different rows
# for is a refusal, never a last-writer-wins.
# The wrong path is part of the subject, so wp=0 alone would be the carve-out
# this gate exists to remove.  Both settings, always.
WPS=${CST_OPCENC_WPS:-"0 16"}
# Repeats per (isa, wp); see THE COVERAGE PRECONDITION note above.
REPEATS=${CST_OPCENC_REPEATS:-3}
# The guest-side inputs `setarch -R` does NOT pin.  Fixed values, not
# per-run ones: the point is that two captures of one build agree.
SEED=${CST_ENC_SEED:-1}
PIDBASE=${CST_ENC_PIDBASE:-90000}

case $mode in
capture)
    out=${1:?output directory}
    wl=${2:?workload directory (prog, prog.a64, prog.rv64, prog.mipsel)}
    mkdir -p "$out" || exit 2
    : > "$out/RC.txt"
    echo "SO_SHA=$(sha256sum "$build/contrib/plugins/libchampsim_tracer.so" \
                   | cut -d' ' -f1)" >> "$out/RC.txt"
    declare -A BIN=( [x86_64]="$wl/prog"        [aarch64]="$wl/prog.a64" \
                     [riscv64]="$wl/prog.rv64"  [mipsel]="$wl/prog.mipsel" )
    for isa in $ISAS; do
        if [ ! -f "${BIN[$isa]}" ]; then
            echo "opcenc_loss_gate: REFUSED -- ${BIN[$isa]} does not exist." \
                 "A capture that cannot find its guest FAILS." \
                 | tee -a "$out/RC.txt"
            exit 2
        fi
        for wp in $WPS; do
          for rep in $(seq 1 "$REPEATS"); do
            d=$out/$isa.wp$wp.r$rep.tsv
            # compress= on every trace this writes (the I/O rule); the trace
            # itself is a by-product here and is removed after the run, but a
            # harness that writes one uncompressed is how the rule rots.
            CST_OPC_ENC_DUMP="$d" setarch -R "$build/qemu-$isa" \
                -seed "$SEED" -pid "$PIDBASE" \
                -plugin "$build/contrib/plugins/libchampsim_tracer.so,outfile=$out/t_$isa,wp=$wp,compress=zstd -T0 -3 -q -c" \
                "${BIN[$isa]}" > /dev/null \
                2> "$out/$isa.wp$wp.r$rep.stats.log"
            rc=$?
            n=$(grep -vc '^#' "$d" 2>/dev/null)
            [ -n "$n" ] || n=0
            if [ "$n" -le 0 ]; then
                echo "opcenc_loss_gate: REFUSED -- $isa wp$wp repeat $rep" \
                     "produced no corpus rows.  An empty corpus is not a" \
                     "short one." | tee -a "$out/RC.txt"
                exit 2
            fi
            echo "dump $isa wp$wp r$rep rc=$rc encodings=$n" >> "$out/RC.txt"
            rm -f "$out/t_$isa.cst"
          done
          # THE INSTABILITY, MEASURED AT THE POINT IT HAPPENS.  Repeat 1 is
          # scored against the union of all repeats for this (isa, wp): how
          # many encodings one capture alone would have missed.  A zero here
          # says the wrong-path reach was stable on this cell; a non-zero is
          # the number a single-capture arm would have been comparing with.
          u=$(cat "$out"/$isa.wp$wp.r*.tsv | grep -v '^#' | cut -f2 \
              | sort -u | wc -l)
          o=$(grep -v '^#' "$out/$isa.wp$wp.r1.tsv" | cut -f2 | sort -u | wc -l)
          echo "repeat-spread $isa wp$wp union=$u first_capture=$o" \
               "missed_by_one_capture=$((u - o))" >> "$out/RC.txt"
        done
    done
    # MERGE per ISA.  sort -u collapses identical rows; an encoding left with
    # two DIFFERENT rows is a conflict the instrument refuses on, and it is
    # reported here too so the capture names it at the point it was made.
    for isa in $ISAS; do
        cat "$out"/$isa.wp*.r*.tsv | grep -v '^#' | sort -u \
            > "$out/$isa.merged.tsv"
        dup=$(cut -f2 "$out/$isa.merged.tsv" | sort | uniq -d | wc -l)
        echo "merge $isa encodings=$(wc -l < "$out/$isa.merged.tsv")" \
             "conflicting_encodings=$dup" >> "$out/RC.txt"
    done
    { echo -e "#isa\tencoding\tmnem\topcode"
      for isa in $ISAS; do cat "$out/$isa.merged.tsv"; done
    } > "$out/corpus.tsv"
    echo "corpus rows=$(grep -vc '^#' "$out/corpus.tsv")" >> "$out/RC.txt"
    # The class histogram is printed with the capture, not derived later: the
    # population a bar was read over is part of the reading.
    echo "class histogram (isa: class=count):" >> "$out/RC.txt"
    for isa in $ISAS; do
        printf '  %-8s %s\n' "$isa" \
            "$(cut -f1,4 "$out/$isa.merged.tsv" | sort | uniq -c \
               | awk '{printf "%s=%s ", $3, $1}')" >> "$out/RC.txt"
    done
    cat "$out/RC.txt"
    exit 0
    ;;
compare)
    A=${1:?arm A corpus.tsv}
    B=${2:?arm B corpus.tsv}
    for f in "$A" "$B"; do
        if [ ! -f "$f" ]; then
            echo "opcenc_loss_gate: REFUSED -- corpus $f does not exist." \
                 "A gate that cannot find its subject FAILS."
            exit 2
        fi
    done
    "$py" "$inst" --selftest > /dev/null
    sel=$?
    if [ "$sel" != 0 ]; then
        echo "opcenc_loss_gate: REFUSED -- the instrument's own planted-fire" \
             "proof did not pass (rc=$sel).  An instrument nobody has shown" \
             "can fire is not evidence."
        exit 2
    fi
    "$py" "$inst" "$A" "$B" --adjudicated "$led"
    rc=$?
    case $rc in
    0) echo "opcenc_loss_gate: PASS -- no encoding lost or changed its" \
            "published opcode class unadjudicated" ;;
    1) echo "opcenc_loss_gate: FAIL -- an encoding lost or changed its" \
            "published opcode class, or a ledger row has no subject" ;;
    *) echo "opcenc_loss_gate: REFUSED -- the arms could not be compared" \
            "(rc=$rc)" ;;
    esac
    exit $rc
    ;;
*)
    echo "opcenc_loss_gate: REFUSED -- unknown mode '$mode';" \
         "want 'capture' or 'compare'."
    exit 2
    ;;
esac
