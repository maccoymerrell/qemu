#!/bin/bash
# THE ACCEPTANCE BATTERY -- all FIFTEEN rows, plus every planted-fire arm,
# in one script.
#
#   battery15.sh <build-dir> <out-dir> [options]
#   battery15.sh --selftest [<scratch-dir>]
#
# WHY THIS FILE EXISTS.  The battery grew a row at a time and lived as a
# pass-local script that was copied forward and edited: verify45 carried
# fourteen rows in battery14.sh, verify46 added the fifteenth in a SECOND
# script beside it, and exec86 ran that fifteenth row by hand.  A bar nobody
# can invoke in one command is a bar that gets run in pieces, and a bar run in
# pieces is how exec86 closed GREEN on a tip where five standing rows were
# RED: its close ran neither must0_scan nor the validator, because those were
# in the copy of the script it did not take.  This is that lesson landed in
# the tree instead of written down again.
#
# THE FIFTEEN ROWS
#
#    1  plugin_abi_gate              the plugin/QEMU dataflow ABI handshake
#    2-5  smoke x4 ISAs              run + strict decode + audit + vacuity,
#                                    every trace compressed, read from
#                                    cst_audit's own member line
#    6  must0_scan                   every "MUST BE 0" row in EVERY sidecar
#                                    this run produces -- see the scope note
#    6w   ... THE DECLARED WIDER      the same scan over the sidecar
#           POPULATION                populations this run did NOT produce:
#                                    the R13 evidence root and any
#                                    --must0-root.  A declared root with no
#                                    census is REFUSED, never skipped
#    6s   ... THE CONDITION-ASSERTED  the same scan over a population whose
#           POPULATION                SUBJECT is asserted too: a zero from a
#                                    seed that never reached the instruction
#                                    is not closure (FINDING 69-B / 73-E).
#                                    Declaring none is RED
#    6b   ... PLANTED FIRE            a synthetic non-zero row under a
#                                    declared root; row 6w must go red
#    7-10 val_gate x4 ISAs           the seed-driven validator, per ISA
#   11  net_validator_gate           the golden-net corpus
#   12  src_loss_gate                the PER-PC source-loss gate
#   12b   ... PLANTED FIRE           one register removed from one pc
#   13  srcset_ab --selftest         the instrument's own arms
#   14  srcenc_loss_gate             the PER-ENCODING source-loss gate, two
#                                    independent captures of THIS build
#   14b   ... PLANTED FIRE           one register removed from one encoding
#   15  opcenc_loss_gate             the PER-ENCODING opcode-class gate
#   15b   ... PLANTED FIRE, LOSS     the class erased in BOTH layers
#   15c   ... PLANTED FIRE, MOVE     the class changed
#   16  external_truth_gate          R13, the STANDING external-truth gate,
#                                    run at this tip with its staleness
#                                    guard armed (--build-dir).  MANDATORY,
#                                    and RED without an evidence root
#
# THE NAME IS HISTORICAL.  "battery15" is what a pass invokes and what every
# transcript names; the row count is not in the contract and renaming the
# file would orphan every ledger that cites it.  There are sixteen rows.
#
# EVERY rc IS READ FROM THE PROCESS THAT PRODUCED IT.  Nothing here quotes a
# number from a log it did not also take the exit status of, and no row is
# allowed to report PASS because its subject was missing: a row whose input
# does not exist is REFUSED (rc=2) and REFUSED is red, never skipped.  That is
# the standing rule this tree keeps having to reinstate -- a check that cannot
# find its subject must fail.
#
# THE PLANTED FIRES ARE ROWS, NOT EXTRAS.  A loss gate that cannot be made to
# fire is not evidence of no loss; it is evidence of nothing.  Rows 12b, 14b,
# 15b and 15c each construct a known loss and REQUIRE a non-zero rc.  15b and
# 15c COMPILE their plant in, which means this script edits a tracked header
# and rebuilds.  It restores by CONTENT AND THEN TOUCHES -- a `cp -p` revert
# preserves mtime, ninja does not relink, and the tree is left carrying a
# planted .so behind a clean `git diff`.  That has bitten this tree twice, so
# every build stage here asserts the .so hash it expects and the script fails
# loudly if a revert did not return.
#
# RUN `ninja` FIRST, ESPECIALLY AFTER A COMMIT.  Row 11's build gate refuses
# if it has to rebuild anything, on the correct ground that a capture taken
# before that rebuild ran old code.  `git commit -o <paths>` -- a PARTIAL
# commit -- checks the named paths out through a temporary index and rewrites
# their mtimes, so a battery started straight after one sees four stale
# emulators whose CONTENT never changed.  Measured at exec98: row 11 rc=2
# with net_validator_gate.sh standalone green on the same bytes minutes
# earlier.  The gate is right and the remedy is the one it prints.
#
# ARM DIRECTORY NAMES ARE ALL THE SAME LENGTH (#327).  qemu-user puts the cwd
# on the guest stack, so two arms at paths of different lengths reach
# different pc sets and a gate correctly refuses on coverage instead of
# reporting what the plant did.
#
# NOTHING ELSE MAY RUN WHILE THIS RUNS, AND THE SCRIPT NOW REFUSES RATHER
# THAN ASKING.  Rows 15b and 15c PLANT a class into a tracked header, rebuild
# the plugin, and revert -- so for part of this script's life the tree's .so
# is a deliberately wrong one.  Any other job that starts a capture in that
# window captures the plant.  It has happened: a validator arm was
# contaminated exactly this way.  The build directory is shared state and a
# second champsim process is a second writer of it, so the guard below looks
# for one and refuses to start.  --allow-concurrent overrides it, prints a
# banner, and marks the close NOT A CLEAN BATTERY.
#
# SETTLE THE BUILD WITH A FULL `ninja` RUN TWICE BEFORE STARTING.  Not
# `ninja <target>`: a partial build leaves other targets stale, row 11's build
# gate refuses on them, and a pass has already lost its gate to exactly that.
# Twice, because the first run can itself regenerate an input (meson
# reconfigure, a generated header) and leave a second round of work to do; a
# settled tree is one where the SECOND run says "no work to do".
#
# Author: Maccoy Merrell.
set -u

usage() {
    cat <<'EOF'
usage: battery15.sh <build-dir> <out-dir> [options]
       battery15.sh --selftest [<scratch-dir>]

options:
  --workload-dir DIR   guests for the smoke, source and opcode rows.
                       Must hold prog, prog.a64, prog.rv64, prog.mipsel.
                       (default: $CST_BATTERY_WORKLOAD)
  --src-loss-a DIR     arm A for row 12, a directory of per-pc .key files.
  --src-loss-b DIR     arm B for row 12 (default: same as A -- the identity
                       arm, which is what makes row 12 a standing row rather
                       than a comparison against whatever ran last).
  --rows LIST          comma-separated row selection, e.g. 1,6,14,15.
                       Rows not selected are reported NOT SELECTED and are
                       not counted either way.  The default is all fifteen;
                       a partial battery prints a banner saying so, because
                       a partial run must never read as a full one.
  --seed N             validator seed (default 4242).
  --wp N               wpdepth for the smoke arms (default 16).
  --no-plants          skip 12b/14b/15b/15c.  The banner says so and the
                       close is marked NOT A FULL BATTERY: without the
                       planted fires the loss rows' zeros are unfalsified.
  --allow-concurrent   start even though another champsim process is
                       running.  The plants make this UNSAFE; the banner
                       says so and the close is marked NOT A CLEAN BATTERY.
  --python PATH        interpreter (default: $CST_PYTHON or python3)
EOF
}

# ---------------------------------------------------------------- selftest --
# Twelve arms, in a scratch tree, over the parts of this script that can be
# exercised without a QEMU build: the row selector, the refusal behaviour, the
# rc bookkeeping and the restore-and-touch recipe.  Run it before believing a
# green battery from a script nobody has falsified.
# 74-E: are BOTH guard probes still running?  Prints two characters, one per
# probe, so a refusal can name WHICH one went and after which scan.
guard_probes_alive() {
    local a=n b=n
    [ -n "$1" ] && [ -d "/proc/$1" ] && a=y
    [ -n "$2" ] && [ -d "/proc/$2" ] && b=y
    printf '%s%s' "$a" "$b"
}

selftest() {
    local scratch=${1:-$(mktemp -d)}
    local fails=0 n=0
    mkdir -p "$scratch" || return 2
    ok()   { n=$((n+1)); echo "PASS  $*"; }
    bad()  { n=$((n+1)); fails=$((fails+1)); echo "FAIL  $*"; }
    t()    { if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1 (got $2 want $3)"; fi; }

    # A: the row selector admits a listed row.
    ROWS="1,6,14"; t "A row selector admits a listed row" "$(selected 6 && echo y || echo n)" y
    # B: and refuses an unlisted one.
    t "B row selector refuses an unlisted row" "$(selected 7 && echo y || echo n)" n
    # C: sub-rows follow their parent (12b rides on 12).
    ROWS="12"; t "C sub-row follows its parent" "$(selected 12b && echo y || echo n)" y
    # D: the default selects everything.
    ROWS="all"; t "D default selects every row" "$(selected 9 && echo y || echo n)" y

    # E/F: a row RECORDED red makes the battery red; a green one does not.
    RCFILE="$scratch/rc.txt"; : > "$RCFILE"; RED=0
    record "x" 0 "green row"; t "E a green row leaves the battery green" "$RED" 0
    record "y" 1 "red row";   t "F a red row turns the battery red" "$RED" 1
    # G: a REFUSED row (rc=2) is red, not skipped.
    RED=0; record "z" 2 "refused row"; t "G rc=2 is RED, never skipped" "$RED" 1
    # H: the transcript names every row it recorded.
    t "H the transcript names each row" \
      "$(grep -c '^row ' "$RCFILE")" 3

    # I: need_dir refuses a directory that is not there...
    RED=0; need_dir "$scratch/nope" "a subject that does not exist" >/dev/null 2>&1
    t "I a missing subject REFUSES" "$?" 2
    # J: ...and accepts one that is.
    need_dir "$scratch" "the scratch dir" >/dev/null 2>&1
    t "J a present subject is accepted" "$?" 0

    # K/L: restore_and_touch puts CONTENT back and moves mtime FORWARD, which
    # is the whole point -- a cp -p revert leaves ninja seeing no change.
    local f="$scratch/f" b="$scratch/f.orig"
    printf 'original\n' > "$f"; cp "$f" "$b"
    touch -d '2001-01-01 00:00:00' "$f" "$b"
    printf 'planted\n' > "$f"; touch -d '2001-01-01 00:00:00' "$f"
    restore_and_touch "$b" "$f"
    t "K restore puts the CONTENT back" "$(cat "$f")" original
    if [ "$f" -nt "$b" ]; then ok "L restore moves MTIME FORWARD (ninja relinks)"
    else bad "L restore left the old mtime -- a planted build would survive"; fi

    # M/N/O: THE MANDATORY ROWS.  A --rows run that leaves out a row which
    # guards the wire must be RED, not quietly narrower.  This is the exact
    # shape that let the PREFETCH class off the wire: the wave ran rows 7-10,
    # reported "validator all seed 4242 rc=0", and never ran row 11 -- the
    # only standing row whose corpus contains a prefetch, and the row that
    # was red on exactly those encodings.
    RCFILE="$scratch/rc2.txt"; : > "$RCFILE"; RED=0
    ROWS="1,14"
    for m in $MANDATORY; do
        selected "$m" || record "$m" 2 "MANDATORY ROW NOT SELECTED"
    done
    t "M omitting a mandatory row turns the battery RED" "$RED" 1
    t "N ...and every omitted mandatory row is NAMED" \
      "$(grep -c 'MANDATORY ROW NOT SELECTED' "$RCFILE")" \
      "$(set -- $MANDATORY; echo $#)"
    RCFILE="$scratch/rc3.txt"; : > "$RCFILE"; RED=0
    ROWS="all"
    for m in $MANDATORY; do
        selected "$m" || record "$m" 2 "MANDATORY ROW NOT SELECTED"
    done
    t "O a full battery records no mandatory omission" "$RED" 0
    # P: row 11 is in the set.  Named explicitly, because the set is only
    # worth having if the row the defect went through is a member.
    case " $MANDATORY " in
      *" 11 "*) ok "P row 11 (net_validator_gate) is MANDATORY" ;;
      *) bad "P row 11 is NOT mandatory -- the set does not cover the defect" ;;
    esac
    # Q: row 16 is in the set, for the same reason and a second defect.  R13
    # is a standing gate by ruling and exec99 landed eight wire-changing
    # commits without it; a battery that can go green while the external
    # references were never consulted is the hole verify48 filed.
    case " $MANDATORY " in
      *" 16 "*) ok "Q row 16 (R13 external-truth gate) is MANDATORY" ;;
      *) bad "Q row 16 is NOT mandatory -- a wave can still skip R13" ;;
    esac
    # R: with no evidence root the row is RED, never skipped.
    RCFILE="$scratch/rc4.txt"; : > "$RCFILE"; RED=0
    R13_ROOT=""
    if selected 16; then
        if [ -z "$R13_ROOT" ]; then
            record 16 2 "R13 external-truth gate -- NO EVIDENCE ROOT"
        fi
    fi
    t "R a battery with no R13 evidence root is RED" "$RED" 1
    n=$((n+1))
    ROWS="all"

    # S: FINDING 59-B.  A battery that declares NO wider sidecar population
    # has not closed the finding, so row 6w is RED rather than absent.  The
    # gap was never the scanner -- it was that nothing pointed it at the
    # corpora where the rows fire.
    RCFILE="$scratch/rc5.txt"; : > "$RCFILE"; RED=0
    O=$scratch/s; mkdir -p "$O"; R13_ROOT=""; MUST0_ROOTS=()
    run_row6w
    t "S a battery declaring no wider must-be-0 population is RED" "$RED" 1
    n=$((n+1))

    # T: a DECLARED root that carries no census is REFUSED, not skipped.  A
    # root nobody could check must never read as a root that came back clean.
    RCFILE="$scratch/rc6.txt"; : > "$RCFILE"; RED=0
    mkdir -p "$scratch/emptyroot"
    MUST0_ROOTS=("$scratch/emptyroot")
    run_row6w
    t "T a declared root with no sidecar REFUSES" "$RED" 1
    n=$((n+1))
    MUST0_ROOTS=()

    # U: the wide scope can fire.  A scan nobody has watched fail vouches for
    # nothing, and this is the arm that says the planted control works.
    RCFILE="$scratch/rc7.txt"; : > "$RCFILE"; RED=0
    PLANTS=1
    run_row6b
    t "U the planted non-zero row is REFUSED (the wide scope can fire)" \
      "$RED" 0
    n=$((n+1))
    grep -q 'rc=0' "$RCFILE"
    t "U2 ... and it was recorded as a PASSING control arm" "$?" 0
    n=$((n+1))

    # ---- V/W/X/Y: THE ISOLATION GUARD, BOTH DIRECTIONS (FINDING 70-D) ----
    #
    # The guard was rewritten from matching command lines to reading the
    # kernel's record, and BOTH directions of that change need proving: it
    # must still catch a process argv cannot describe, and it must no longer
    # refuse over one that is none of this build's business.  A guard nobody
    # has watched fire, and nobody has watched stay quiet, is a guard whose
    # zero means nothing.
    #
    # EACH ARM ASSERTS ON THE PROBE'S OWN PID, not on a string in the output.
    # The first version of these arms grepped for the fake path, and passed
    # against the SHELL THAT LAUNCHED THE SELFTEST -- whose command line
    # contained the path because the invocation did.  A probe that never ran
    # would have read as a probe that was found.
    #
    # setsid puts each probe in its OWN process group.  A background job
    # started from here shares this script's group and the guard excludes its
    # own group by design, so without setsid every arm below would "pass" by
    # never being looked at.
    #
    # AND EACH PROBE REPORTS THAT IT IS ALIVE.  `sleep 47 /some/path` is not a
    # sleeping process: GNU sleep sums its arguments as durations and exits
    # immediately on a path.  The second arm was that command, so it died
    # before it could be looked for, and the arm asserting the guard IGNORED
    # it passed for the wrong reason.  Each probe now writes its own pid after
    # `exec` has given it the command line under test, and the arms REFUSE if
    # a pid file does not appear.
    #
    # AND IT REPORTS THAT IT IS STILL ALIVE WHEN EACH SCAN READS IT (74-E).
    # The probes used to live 47 seconds, and that number had to outlast
    # however long the scans take -- which is not a constant and is not small.
    # concurrent_champsim() reads /proc/<pid>/maps for EVERY process on the
    # host; measured here, one scan is 25-30 s over ~1450 processes.  Arms V
    # and W read `hard`, which is ONE scan.  Arm X reads `soft`, and
    # nearby_champsim() runs concurrent_champsim() AGAIN before its own loop,
    # so X is evaluated TWO whole scans later.  Timestamped, on this host:
    #
    #     T+0    probes launched          v alive, w alive
    #     T+30s  hard computed            v alive, w alive   -> V, W pass
    #     T+65s  soft computed            v DEAD,  w DEAD    -> X reads n
    #
    # That is exec127's flaky arm X, and it is a DEADLINE rather than a race:
    # X and only X flips because X and only X is read after the second scan.
    # verify58's seven clean runs were seven runs where two scans happened to
    # fit inside 47 s; the mechanism was never absent, only unexposed, which
    # is why the zero could not close it.
    #
    # FIXED AT SOURCE IN BOTH HALVES.  The lifetime no longer has to beat an
    # unbounded amount of scanning, and -- because a bound that nothing checks
    # is exactly how this stayed hidden -- LIVENESS IS ASSERTED AT EVERY SCAN
    # THAT FEEDS A VERDICT.  A probe that died before the scan reading it
    # makes these arms REFUSE, not report: a dead probe is absent from every
    # list, so it reads as a clean `n` on X and as a clean PASS on W, and the
    # second of those is a guard reported as correct over a subject that was
    # not there.  The bound stays (an unbounded sleep orphaned by a killed
    # battery is exactly the stray this project has been bitten by) but it is
    # now a tripwire instead of a silent input.
    local fb=$scratch/fakebuild vp wp fakearg
    fakearg="cst_decode /some/other/checkout/build/libchampsim_tracer.so"
    mkdir -p "$fb/contrib/plugins" "$fb/bin"
    # A REUSED SCRATCH MUST NOT HAND THESE ARMS A PREVIOUS RUN'"'"'S PID.  The
    # wait below is satisfied by a NON-EMPTY pid file, so a leftover one is
    # read instantly and names a process that exited long ago -- which the
    # liveness check then correctly refuses, with a message blaming the probe
    # for "not starting" when it had not yet been asked to.  Truncate first;
    # the refusal is for a probe that really did fail, not for a stale file.
    : > "$scratch/v.pid"
    : > "$scratch/w.pid"
    cp "$(command -v sleep)" "$fb/bin/zzz_not_a_tracer_name" 2>/dev/null
    if [ -x "$fb/bin/zzz_not_a_tracer_name" ] && command -v setsid >/dev/null
    then
        # V: EXE under the build dir, with an argv that names nothing of ours.
        setsid bash -c 'echo $$ > "$2"; exec -a totally-innocuous-name "$1" 900' \
               _ "$fb/bin/zzz_not_a_tracer_name" "$scratch/v.pid" \
               >/dev/null 2>&1 &
        # W: an argv naming another checkout's plugin, on a stock binary.
        setsid bash -c 'echo $$ > "$2"; exec -a "$1" sleep 900' \
               _ "$fakearg" "$scratch/w.pid" >/dev/null 2>&1 &
        local i=0
        while [ $i -lt 50 ] && { [ ! -s "$scratch/v.pid" ] || \
                                 [ ! -s "$scratch/w.pid" ]; }; do
            sleep 0.1; i=$((i+1))
        done
        vp=$(cat "$scratch/v.pid" 2>/dev/null)
        wp=$(cat "$scratch/w.pid" 2>/dev/null)
        if [ -z "$vp" ] || [ -z "$wp" ] || [ ! -d "/proc/$vp" ] || \
           [ ! -d "/proc/$wp" ]; then
            bad "V-Y the guard probes did not start (v='$vp' w='$wp') -- \
REFUSING to report these arms as passed"
            n=$((n+3))
        else
            local hard soft t0 alive_hard alive_soft
            t0=$(date +%s)
            hard=$(concurrent_champsim "$fb" | cut -d' ' -f1 | tr '\n' ' ')
            alive_hard=$(guard_probes_alive "$vp" "$wp")
            soft=$(nearby_champsim "$fb" | cut -d' ' -f1 | tr '\n' ' ')
            alive_soft=$(guard_probes_alive "$vp" "$wp")
            printf '%s\n' "$hard" > "$scratch/guard_hard.txt"
            printf '%s\n' "$soft" > "$scratch/guard_soft.txt"
            printf 'elapsed=%ss alive_after_hard=%s alive_after_soft=%s\n' \
                   "$(( $(date +%s) - t0 ))" "$alive_hard" "$alive_soft" \
                   > "$scratch/guard_timing.txt"
            if [ "$alive_hard" != yy ] || [ "$alive_soft" != yy ]; then
                # 74-E.  A probe that is gone is absent from every list, so it
                # reads as a clean `n` on X and a clean PASS on W -- a guard
                # reported correct over a subject that was not there.  Refuse.
                bad "V-Y a guard probe did not survive the scan that reads it \
(after hard: $alive_hard, after soft: $alive_soft, elapsed \
$(( $(date +%s) - t0 ))s) -- REFUSING to report these arms.  The scans are \
whole-/proc walks and the probe lifetime has to outlast them; see the 74-E \
note above."
                n=$((n+3))
            else
            t "V the guard CATCHES a process argv cannot describe" \
              "$(case " $hard " in *" $vp "*) echo y ;; *) echo n ;; esac)" y
            t "W ...and does NOT refuse over another tree's command line" \
              "$(case " $hard " in *" $wp "*) echo y ;; *) echo n ;; esac)" n
            t "X ...which is reported as an ADVISORY rather than dropped" \
              "$(case " $soft " in *" $wp "*) echo y ;; *) echo n ;; esac)" y
            t "Y the guard never reports this script's own process" \
              "$(case " $hard " in *" $$ "*) echo y ;; *) echo n ;; esac)" n
            fi
            kill "$vp" "$wp" 2>/dev/null
        fi
        wait 2>/dev/null
    else
        bad "V-Y the isolation guard arms could not run (no setsid or no \
sleep to copy) -- REFUSING to report them as passed"
        n=$((n+3))
    fi

    echo "arms=$n failures=$fails"
    [ "$fails" -eq 0 ]
}

# ------------------------------------------------------------- primitives --
# THE MANDATORY ROWS.  A row here may be deselected, but deselecting it is
# RED: it is recorded rc=2 with its reason, so a partial battery cannot read
# as a bar.  Row 11 is the reason the set exists -- it is the only standing
# row whose corpus reaches an x86 prefetch, it was RED at 391e65d07f on
# exactly those encodings, and the wave that put them on the wrong side of
# the wire reported "validator all seed 4242 rc=0" (rows 7-10) and never ran
# it.  Row 15 joins it because it is the only per-encoding opcode gate, and
# row 6 because its scan is what reads every sidecar the run produced.
MANDATORY="6 11 15 16"

# A row is selected when --rows was not given, or names it, or names its
# parent (so 12b rides on 12 and nobody has to list both).
selected() {
    local r=$1
    [ "${ROWS:-all}" = all ] && return 0
    local p=${r%%[b-z]}
    case ",${ROWS}," in
        *",$r,"*) return 0 ;;
        *",$p,"*) return 0 ;;
    esac
    return 1
}

# Record one row's verdict.  rc 0 is green; ANYTHING else is red, including
# rc=2, because a gate that could not look has not reported all-clear.
record() {
    local row=$1 rc=$2; shift 2
    printf 'row %-5s rc=%-3s %s\n' "$row" "$rc" "$*" >> "$RCFILE"
    [ "$rc" -eq 0 ] || RED=1
}

# A subject that is not there REFUSES.  Never returns 0 for a missing input.
need_dir() {
    if [ -d "$1" ]; then return 0; fi
    echo "battery15: $2 is not at '$1' -- REFUSING (a row whose subject is" \
         "missing must fail, not pass)" >&2
    return 2
}

# Restore CONTENT and then move mtime forward.  See the header: `cp -p` here
# has twice left this tree carrying a planted .so behind a clean git diff.
restore_and_touch() {
    cp "$1" "$2" && touch "$2"
}

so_hash() { sha256sum "$Q/contrib/plugins/libchampsim_tracer.so" | cut -c1-12; }

# ---- WHO ELSE IS USING THIS BUILD ----------------------------------------
#
# FINDING 70-D.  This guard used to answer the question by matching COMMAND
# LINES: anything whose argv mentioned libchampsim_tracer.so, srcenc_sled.py,
# cst_decode and so on.  argv is neither necessary nor sufficient for the
# question actually being asked, which is "will this process be affected by,
# or interfere with, a plant in THIS build tree".
#
#   NOT SUFFICIENT -- argv is what a process SAYS it is.  An emulator started
#   through a wrapper, re-exec'd, or invoked with a changed argv[0] loads the
#   plugin and says nothing about it.  So does a tool run from a shell whose
#   own command line the kernel has since rewritten.
#
#   NOT NECESSARY -- a `cst_decode` belonging to a DIFFERENT build tree is
#   matched by the old rule and is not a hazard: rows 15b/15c plant into
#   THIS tree's .so and nothing else's.  So is a text editor holding the
#   string, and so is a report that quotes it.
#
# The question is answered from the kernel's own record instead:
#
#   EXE      /proc/<pid>/exe resolved -- the file the process is RUNNING,
#            whatever argv says.  Under this build dir, it is one of ours.
#   MAPPED   /proc/<pid>/maps names THIS build's libchampsim_tracer.so.  An
#            emulator with the plugin loaded is caught here however it was
#            started, which is the case argv could not answer.
#   HARNESS  the command line, kept for the one case where the exe is an
#            interpreter and tells us nothing: a python or shell harness
#            under THIS repo's champsim_tracer tree.  Scoped to the repo
#            path, so another checkout's harness is not this run's problem.
#
# This script's own process group and its ancestors' groups are excluded: a
# command substitution runs in a SUBSHELL with a pid of its own and this
# script's command line, so a guard keyed on `$$` reports the guard as the
# thing it is guarding against -- measured, on the first run of this check.
#
# WHAT IT CANNOT SEE, said plainly: another user's processes.  /proc/<pid>/exe
# and /proc/<pid>/maps are unreadable across users, so a concurrent capture
# run by somebody else is invisible to EXE and MAPPED and reaches only the
# advisory below.  The battery is a single-operator bar and that is the
# boundary of this guard, not a claim it does not have one.
concurrent_champsim() {
    local build=${1:-$Q} self=$$ mine="" anc d p pg st rest exe cmd why
    mine=" $(ps -o pgid= -p $self 2>/dev/null | tr -d ' ') "
    anc=$(ps -o ppid= -p "$self" 2>/dev/null | tr -d ' ')
    while [ -n "$anc" ] && [ "$anc" != 0 ] && [ "$anc" != 1 ]; do
        mine="$mine$(ps -o pgid= -p "$anc" 2>/dev/null | tr -d ' ') "
        anc=$(ps -o ppid= -p "$anc" 2>/dev/null | tr -d ' ')
    done
    local QR SO RR
    QR=$(cd "$build" 2>/dev/null && pwd -P) || return 0
    SO=$QR/contrib/plugins/libchampsim_tracer.so
    RR=$(cd "$T/../../../.." 2>/dev/null && pwd -P)
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "$p" = "$self" ] && continue
        # A process can exit between the glob and the read; the redirect's
        # own failure message is bash's, so the group is what silences it.
        { read -r st < "$d/stat"; } 2>/dev/null || continue
        rest=${st#*') '}
        # stat after the comm field: state ppid pgrp ...
        set -- $rest
        pg=$3
        case "$mine" in *" $pg "*) continue ;; esac
        cmd=$( { tr '\0' ' ' < "$d/cmdline"; } 2>/dev/null )
        why=""
        exe=$(readlink -f "$d/exe" 2>/dev/null)
        case "$exe" in "$QR"/*) why="EXE under the build dir: $exe" ;; esac
        if [ -z "$why" ] && grep -qsF "$SO" "$d/maps"; then
            why="MAPPED this build's plugin"
        fi
        if [ -z "$why" ] && [ -n "$RR" ]; then
            case "$cmd" in
                *"$RR/contrib/plugins/champsim_tracer/tools/"*|\
                *"$RR/contrib/plugins/champsim_tracer/validator/"*)
                    why="HARNESS from this repo" ;;
            esac
        fi
        [ -n "$why" ] && printf '%s  [%s]  %s\n' "$p" "$why" "$cmd"
    done
    return 0
}

# The old rule, kept as an ADVISORY and never as a refusal.  Narrowing a guard
# can drop a real hazard as easily as a false alarm, so everything the command
# line rule used to catch and the kernel-backed one does not is still NAMED in
# the transcript -- it just no longer stops the run.
nearby_champsim() {
    local build=${1:-$Q} d p cmd exe hard
    hard=$(concurrent_champsim "$build" | cut -d' ' -f1 | tr '\n' ' ')
    for d in /proc/[0-9]*; do
        p=${d#/proc/}
        [ "$p" = "$$" ] && continue
        case " $hard " in *" $p "*) continue ;; esac
        cmd=$( { tr '\0' ' ' < "$d/cmdline"; } 2>/dev/null )
        case $cmd in
            *libchampsim_tracer.so*|*srcenc_sled.py*|*champsim_tracer_validator*|\
            *battery15.sh*|*cst_decode*|*cst_audit*|*isaxcheck*)
                printf '%s  %s\n' "$p" "$cmd" ;;
        esac
    done
    return 0
}

# The harness root and the interpreter are needed by the rows AND by the
# selftest, which runs before the option parser; a row that cannot find
# must0_scan.py would otherwise "pass" in the selftest for the wrong reason.
T=$(cd "$(dirname "$0")" && pwd)
PY=${CST_PYTHON:-python3}
PLANTS=1
MUST0_ROOTS=()
R13_ROOT=${CST_R13_ROOT:-}

# ---- ROW 6w: THE DECLARED WIDER POPULATION -------------------------------
#
# FINDING 59-B.  Row 6 above reads every sidecar THIS RUN produces, and its
# scope is honest, but it is not the population where the rows fire.  The
# `published sources the union DOES NOT CONTAIN` row was NON-ZERO on 19
# sidecars across all four ISAs -- the shadow corpus and the R13 reference
# probes -- for at least two passes, and neither standing instrument looked:
# row 6 does not run those corpora, and shadow_rollup.py checks a different
# identity set entirely.  A must-be-0 row that no gate evaluates over the
# population where it fires is a row that can go non-zero for a whole arc
# with nobody learning.
#
# So the battery now reads the populations it is RESPONSIBLE FOR but does not
# produce: the R13 evidence root (added automatically -- row 16 already
# requires one, and reading a probe's trace without reading its census is
# precisely the gap) plus any --must0-root the wave declares.
#
# EACH ROOT IS SCANNED SEPARATELY AND EACH IS REFUSED ON ITS OWN.  A declared
# root with no census-carrying sidecar under it has not been checked, and
# reporting one aggregate rc would let a root that contributed nothing hide
# behind one that contributed everything.  The file counts are printed so a
# shrinking scope is visible in the record.
#
# THIS ROW IS RED AT THE TIP AND THAT IS THE FINDING, NOT A BUG IN THE ROW.
# What is left non-zero after the census was re-keyed onto the producer's own
# union is a small named class of published sources that ONLY the operand
# walk supplies -- x86 MPX `bnd*` address registers and the lazy-flag `adc`
# read, aarch64 `prfm`/`prfum`, mipsel `synci`, riscv64 RVV `vm`/`vtype`.
# Each is an open defect with a named mechanism and an owner at a QEMU decode
# site (R20), NOT a loss anyone has ruled removable, so none of it belongs in
# an adjudicated-loss ledger: those files say "EMPTY IS THE CORRECT STATE"
# and they mean it.  The row goes green when the class closes.
run_row6w() {
    local roots=() r n rc=0 i=0
    [ -n "$R13_ROOT" ] && roots+=("$R13_ROOT")
    [ ${#MUST0_ROOTS[@]} -gt 0 ] && roots+=("${MUST0_ROOTS[@]}")
    if [ ${#roots[@]} -eq 0 ]; then
        record 6w 2 "must0_scan WIDE -- no population declared (--must0-root \
or --r13-root).  FINDING 59-B is that this scan had no population; a battery \
that declares none has not closed it"
        return
    fi
    for r in "${roots[@]}"; do
        i=$((i+1))
        if [ ! -d "$r" ]; then
            record 6w.$i 2 "must0_scan WIDE -- declared root '$r' is not a directory"
            rc=1
            continue
        fi
        mapfile -t MW < <(find "$r" -name '*.stats.log' -type f | sort)
        n=${#MW[@]}
        if [ "$n" -eq 0 ]; then
            record 6w.$i 2 "must0_scan WIDE -- no sidecar under declared root '$r'"
            rc=1
            continue
        fi
        # --min-subjects 1: a declared root that turns out to carry no census
        # at all is a root nobody checked, and it fails rather than passing.
        "$PY" "$T/arc3_cov/instruments/must0_scan.py" --min-subjects 1 \
              "${MW[@]}" > "$O/MUST0_WIDE_$i.txt" 2>&1
        local one=$?
        [ "$one" -eq 0 ] || rc=$one
        record 6w.$i $one "must0_scan over $n sidecar(s) under declared root '$r'"
    done
    record 6w $rc "must0_scan WIDE -- ${#roots[@]} declared population(s)"
}

# ---- ROW 6s: THE CONDITION-ASSERTED POPULATION ---------------------------
#
# FINDING 73-E.  Row 6w reads the populations the wave DECLARES, and reads
# them honestly, but a declared root that never reached the instruction the
# row is about answers 0 for a reason that is not closure.  That is FINDING
# 69-B's own lesson -- 53 quiet seeds were read as a pass because nobody
# asked whether the subject was there -- and the arm that found the 72-G
# class asserts BOTH halves by hand:
#
#     seed  sidecars  files with a non-zero must-be-0 row
#       9      18        0        <- and 18 of 18 NAME sdc2
#      13      18        1
#      32      18        1
#      54      18        1
#
# Three non-zero rows, live at the tip, on a population the standing bar
# does not scan: rows 6 / 6w.1 / 6w.2 / 6w all read 0 over 896 + 41 + 80
# sidecars while these three existed the whole time.  What separates them is
# the SEED, and a fixed corpus cannot bound a class that appears at 3 of 7
# seeds in one cell.  So the assertion moves out of a wave-local script and
# into the battery, GENERICALLY: a root declared here must satisfy the
# must-be-0 rows AND must be shown to have reached its subject.
#
#   --must0-seedroot <dir>=<token>
#
# The token is grepped in the sidecars themselves, so a population that
# stopped reaching the instruction goes RED rather than quietly green -- the
# 69-B hole, closed by construction instead of by an agent remembering.
#
# NOT DECLARING ONE IS RED.  A battery whose must-be-0 scope is the fixed
# corpora only may say so -- by declaring the fixed corpora as seed roots and
# naming what they reach -- but it may not say nothing.  That is row 6w's own
# rule ("a declared root with no census is REFUSED, never skipped") applied
# to the half of the scope 73-E found missing.
#
# THIS ROW IS RED AT THE TIP AND THAT IS THE FINDING.  The three rows above
# are the MSA identity-less class (STATUS.md open item 7): `ori.b`,
# `xori.b`, `nori.b` reached on a WRONG PATH with decode_id 0x00000000 and
# rule `?`, so QEMU exported no identity, no survivor row can be keyed on
# them and no R16 ledger row can carry them.  Both directions are open at
# once on the same instruction.  Making the row BLOCK is the 72-G treatment
# for a class that can be neither stated nor ruled yet; it goes green when
# the identity exists.
run_row6s() {
    local spec r tok n rc=0 i=0 hit
    if [ ${#MUST0_SEEDROOTS[@]} -eq 0 ]; then
        record 6s 2 "must0_scan CONDITION-ASSERTED -- no population declared \
(--must0-seedroot <dir>=<token>).  FINDING 73-E is that the must-be-0 scope \
excluded the only population where the class fires; a battery that declares \
none has not closed it"
        return
    fi
    for spec in "${MUST0_SEEDROOTS[@]}"; do
        i=$((i+1))
        r=${spec%%=*}
        tok=${spec#*=}
        if [ "$tok" = "$spec" ] || [ -z "$tok" ]; then
            record 6s.$i 2 "must0_scan CONDITION-ASSERTED -- '$spec' names no \
subject token; the form is <dir>=<token> and a root with no asserted subject \
is exactly the zero 69-B was misread on"
            rc=1
            continue
        fi
        if [ ! -d "$r" ]; then
            record 6s.$i 2 "must0_scan CONDITION-ASSERTED -- declared root \
'$r' is not a directory"
            rc=1
            continue
        fi
        mapfile -t MS < <(find "$r" -name '*.stats.log' -type f | sort)
        n=${#MS[@]}
        if [ "$n" -eq 0 ]; then
            record 6s.$i 2 "must0_scan CONDITION-ASSERTED -- no sidecar under \
declared root '$r'"
            rc=1
            continue
        fi
        # THE CONDITION FIRST.  A zero from a population that never reached
        # the subject is not closure, and it is checked before the outcome so
        # the record cannot show a green outcome over an empty subject.
        hit=$(grep -l -F -- "$tok" "${MS[@]}" 2>/dev/null | wc -l)
        if [ "$hit" -eq 0 ]; then
            record 6s.$i 1 "must0_scan CONDITION-ASSERTED -- 0 of $n \
sidecar(s) under '$r' NAME '$tok'.  The population does not reach its \
subject, so its must-be-0 zero proves nothing (FINDING 69-B)"
            rc=1
            continue
        fi
        "$PY" "$T/arc3_cov/instruments/must0_scan.py" --min-subjects 1 \
              "${MS[@]}" > "$O/MUST0_SEED_$i.txt" 2>&1
        local one=$?
        [ "$one" -eq 0 ] || rc=$one
        record 6s.$i $one "must0_scan over $n sidecar(s) under '$r', \
$hit of them naming '$tok'"
    done
    record 6s $rc "must0_scan CONDITION-ASSERTED -- ${#MUST0_SEEDROOTS[@]} \
declared population(s)"
}

# ---- ROW 6b: THE PLANTED FIRE FOR THE WIDE SCOPE -------------------------
#
# A scope that has never been seen to fire is not evidence that the
# population is clean; it is evidence of nothing.  This plants a sidecar
# carrying a non-zero must-be-0 row under a scratch root, declares that root
# exactly the way a wave declares one, and REQUIRES a non-zero rc.
run_row6b() {
    local d=$O/must0_plant
    rm -rf "$d"; mkdir -p "$d"
    printf 'PLANTED CONTROL -- not a tracer sidecar\n' > "$d/plant.stats.log"
    printf '         7  a row this control invented -- MUST BE 0\n' \
        >> "$d/plant.stats.log"
    "$PY" "$T/arc3_cov/instruments/must0_scan.py" --min-subjects 1 \
          "$d/plant.stats.log" > "$O/MUST0_PLANT.txt" 2>&1
    local rc=$?
    if [ "$rc" -eq 0 ]; then
        record 6b 1 "PLANTED FIRE -- must0_scan read a planted NON-ZERO row \
as clean; the wide scope proves nothing"
    else
        record 6b 0 "PLANTED FIRE -- must0_scan REFUSED the planted non-zero \
row (rc=$rc), so the wide scope can fire"
    fi
}


# ------------------------------------------------------------------- main --
[ $# -ge 1 ] || { usage >&2; exit 2; }
if [ "$1" = "--selftest" ]; then
    shift
    Q=""; RCFILE=/dev/null; RED=0; ROWS=all
    selftest "$@"
    exit $?
fi
[ $# -ge 2 ] || { usage >&2; exit 2; }

Q=$1; O=$2; shift 2
WORKLOAD=${CST_BATTERY_WORKLOAD:-}
SRC_LOSS_A=${CST_SRC_LOSS_A:-}
SRC_LOSS_B=""
R13_ROOT=${CST_R13_ROOT:-}
# Sidecar populations this run does not produce but is responsible for
# reading.  Colon-separated in the environment, repeatable on the command
# line; the R13 evidence root is added automatically below because row 16
# already requires one and a battery that reads its probes' traces without
# reading their censuses is the exact gap FINDING 59-B named.
MUST0_ROOTS=()
if [ -n "${CST_MUST0_ROOTS:-}" ]; then
    IFS=':' read -r -a MUST0_ROOTS <<< "$CST_MUST0_ROOTS"
fi
# Sidecar populations whose SUBJECT is asserted as well as their outcome.
# See run_row6s(): a root here is a <dir>=<subject-token> pair, and the row
# is red when the token is absent from the census as well as when a
# must-be-0 row is non-zero.
MUST0_SEEDROOTS=()
if [ -n "${CST_MUST0_SEEDROOTS:-}" ]; then
    IFS=':' read -r -a MUST0_SEEDROOTS <<< "$CST_MUST0_SEEDROOTS"
fi
ROWS=all
SEED=4242
WP=16
PLANTS=1
CONCURRENT=0
PY=${CST_PYTHON:-python3}
while [ $# -gt 0 ]; do
    case $1 in
        --workload-dir) WORKLOAD=$2; shift 2 ;;
        --src-loss-a)   SRC_LOSS_A=$2; shift 2 ;;
        --src-loss-b)   SRC_LOSS_B=$2; shift 2 ;;
        --rows)         ROWS=$2; shift 2 ;;
        --r13-root)     R13_ROOT=$2; shift 2 ;;
        --must0-root)   MUST0_ROOTS+=("$2"); shift 2 ;;
        --must0-seedroot) MUST0_SEEDROOTS+=("$2"); shift 2 ;;
        --seed)         SEED=$2; shift 2 ;;
        --wp)           WP=$2; shift 2 ;;
        --no-plants)    PLANTS=0; shift ;;
        --allow-concurrent) CONCURRENT=1; shift ;;
        --python)       PY=$2; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "battery15: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
done
[ -n "$SRC_LOSS_B" ] || SRC_LOSS_B=$SRC_LOSS_A

REPO=$(cd "$T/../../../.." && pwd)
VD=$T/../validator
mkdir -p "$O" || exit 2
RCFILE=$O/RC.txt
RED=0
: > "$RCFILE"

[ -x "$Q/contrib/plugins/cst_decode" ] || {
    echo "battery15: '$Q' is not a build directory with the tools in it" \
         "-- REFUSING" >&2; exit 2; }

# ---- THE ISOLATION GUARD -------------------------------------------------
# Rows 15b/15c compile a wrong class into the plugin and rebuild, so while
# this script runs the build tree's .so is, for a while, a planted one.  A
# capture started by anything else in that window silently gets the plant.
# The guard names the processes it found and refuses; it does not wait, and
# it does not kill anything, because both of those are decisions about
# someone else's job.  concurrent_champsim() is defined with the other
# helpers above, so --selftest can exercise it.
CONCUR=$(concurrent_champsim)
NEARBY=$(nearby_champsim)
if [ -n "$CONCUR" ]; then
    if [ "$CONCURRENT" -eq 1 ]; then
        echo "*** battery15: --allow-concurrent, and these were running:" >&2
        echo "$CONCUR" >&2
    else
        {
          echo "battery15: REFUSING to start -- another champsim process is"
          echo "  running, and rows 15b/15c plant a wrong class into the"
          echo "  plugin and rebuild.  Anything capturing in that window gets"
          echo "  the plant.  Wait for these, or pass --allow-concurrent:"
          echo "$CONCUR"
        } >&2
        exit 2
    fi
fi

{
  echo "battery15  build=$Q  out=$O"
  echo "HARNESS_CWD=$PWD"
  echo "TIP=$(git -C "$REPO" rev-parse HEAD 2>/dev/null)"
  echo "DIRTY=$(git -C "$REPO" status --porcelain 2>/dev/null | grep -vc '^??')"
  echo "SO_SHA=$(sha256sum "$Q/contrib/plugins/libchampsim_tracer.so" | cut -d' ' -f1)"
  echo "WP=$WP SEED=$SEED ROWS=$ROWS PLANTS=$PLANTS"
  [ "$ROWS" = all ] || echo "*** PARTIAL BATTERY -- rows=$ROWS.  This is NOT the acceptance bar. ***"
  [ "$PLANTS" -eq 1 ] || echo "*** NO PLANTED FIRES -- the loss rows' zeros are UNFALSIFIED here. ***"
  if [ -n "$CONCUR" ]; then
      echo "*** NOT A CLEAN BATTERY -- these ran alongside it: ***"
      echo "$CONCUR"
  fi
  # The advisory: what the old command-line rule would have refused over and
  # this one does not.  Recorded, never acted on, so narrowing the guard
  # cannot silently drop a hazard nobody thought of.
  if [ -n "$NEARBY" ]; then
      echo "NEARBY (advisory, not a refusal -- command line only):"
      echo "$NEARBY"
  fi
} >> "$RCFILE"
SO0=$(so_hash)

# ---- ROW 1 ---------------------------------------------------------------
if selected 1; then
    "$T/plugin_abi_gate.sh" "$Q" > "$O/abi_gate.log" 2>&1
    record 1 $? "plugin_abi_gate"
fi

declare -A BIN=( [x86_64]=prog [aarch64]=prog.a64 \
                 [riscv64]=prog.rv64 [mipsel]=prog.mipsel )

# ---- ROWS 2-5: smoke, one per ISA ---------------------------------------
smoke_done=0
if selected 2 || selected 6; then
    if need_dir "$WORKLOAD" "the workload directory (--workload-dir)"; then
        mkdir -p "$O/smoke"
        for isa in x86_64 aarch64 riscv64 mipsel; do
            o=$O/smoke/$isa
            setarch -R "$Q/qemu-$isa" -plugin \
              "$Q/contrib/plugins/libchampsim_tracer.so,outfile=$o,wpdepth=$WP,memdata=1,regdata=1,compress=zstd -T0 -3 -q -c" \
              "$WORKLOAD/${BIN[$isa]}" > "$o.out" 2> "$o.stats.log"; rrc=$?
            "$Q/contrib/plugins/cst_decode" --strict "$o.cst" > /dev/null 2> "$o.derr"; drc=$?
            "$Q/contrib/plugins/cst_audit" "$o.cst" > "$o.audit" 2>&1; arc=$?
            # Compression read from cst_audit's own member line, never from
            # the fact that a compress= option was passed.
            z=$(grep -c 'body member (zstd)' "$o.audit")
            u=$(grep -c 'body member (raw)' "$o.audit")
            vac=$(sed -n '/=== VACUITY (Oracle 0) ===/,+2p' "$o.audit" \
                  | grep -c 'OK: the population')
            rc=0
            [ "$rrc" -eq 0 ] && [ "$drc" -eq 0 ] && [ "$arc" -eq 0 ] \
              && [ "$vac" -ge 1 ] && [ "$z" -ge 1 ] && [ "$u" -eq 0 ] || rc=1
            record "$isa" $rc \
              "smoke run=$rrc decode=$drc audit=$arc vacuity=$vac zstd=$z raw=$u"
        done
        smoke_done=1
    else
        record 2-5 2 "smoke -- no workload directory"
    fi
fi

# ---- ROW 6: the must-be-0 scan ------------------------------------------
#
# THE SCOPE WAS THE BUG, NOT THE SCANNER (exec97 FINDING 49-D).  This row
# read exactly four sidecars -- the four smoke runs -- for as long as it has
# existed.  verify47 filed a published-source witness (`0000054b NOP
# REG_GPR2/REG_GPR5`, `nopl`, #331) as a class "the standing corpora are
# blind to", and PASS 48 confirmed it by scanning thirty-six sidecars and
# reading NON-ZERO 0.  Pointed at all 291 sidecars a pass produces, the same
# scanner finds the witness sitting on two SHADOW cells -- a corpus that runs
# every pass -- and finds four more non-zero rows on the R13 probe sidecars.
# Neither the instrument nor the corpora were blind; the four paths were.
#
# So the row now scans every *.stats.log under the run directory, whatever
# produced it, and the count of files is reported so a shrinking scope is
# visible in the record rather than in nobody's memory.  It runs LAST of the
# rows that write sidecars -- placement below, at the end of the file -- so
# that the validator, the net gate and the four per-encoding gates have all
# left theirs behind by the time it looks.
#
# A row that finds NO sidecar at all is REFUSED, not passed: that is the
# standing rule, and it is the rule this scope violated by construction.
run_row6() {
    local n
    mapfile -t M0 < <(find "$O" -name '*.stats.log' -type f | sort)
    n=${#M0[@]}
    if [ "$n" -eq 0 ]; then
        record 6 2 "must0_scan -- no sidecar anywhere under the run directory"
        return
    fi
    # --min-subjects 4: the four smoke sidecars are guaranteed to carry a
    # census, so a run that finds fewer than four is a scanner that lost its
    # subject and fails.  The rest of the sweep is short exit reports the
    # per-encoding captures write, which carry none and are named rather
    # than counted as failures -- see must0_scan.py's own note on why the
    # subject rule belongs to the RUN and not to each file.
    "$PY" "$T/arc3_cov/instruments/must0_scan.py" --min-subjects 4 \
          "${M0[@]}" > "$O/MUST0.txt" 2>&1
    record 6 $? "must0_scan over $n sidecar(s) -- every *.stats.log this run produced"
}

# ---- ROWS 7-10: the validator, four ISAs --------------------------------
if selected 7; then
    mkdir -p "$O/val"
    ( cd "$VD" || exit 2
      for isa in x86_64 aarch64 riscv64 mipsel; do
        ( "$PY" -m champsim_tracer_validator all --isa "$isa" --seed "$SEED" \
              --compress zstd --build-dir "$Q" -o "$O/val/$isa" \
              > "$O/val/$isa.log" 2>&1
          echo $? > "$O/val/$isa.rc" ) &
      done
      wait )
    for isa in x86_64 aarch64 riscv64 mipsel; do
        vrc=$(cat "$O/val/$isa.rc" 2>/dev/null || echo 2)
        "$T/val_gate.sh" "$O/val/$isa.log" "$vrc" > "$O/val/$isa.gate" 2>&1
        record "$isa" $? "val_gate (validator rc=$vrc)"
    done
fi

# ---- ROW 11: the golden-net validator gate ------------------------------
if selected 11; then
    "$T/net_validator_gate.sh" "$Q" > "$O/netval.log" 2>&1
    record 11 $? "net_validator_gate"
fi

# ---- ROW 12: the PER-PC source-loss gate --------------------------------
if selected 12; then
    if [ -n "$SRC_LOSS_A" ] && need_dir "$SRC_LOSS_A" "row 12's arm A (--src-loss-a)"; then
        "$T/src_loss_gate.sh" "$Q" "$SRC_LOSS_A" "$SRC_LOSS_B" > "$O/src_loss.log" 2>&1
        record 12 $? "src_loss_gate (A=$(basename "$SRC_LOSS_A") B=$(basename "$SRC_LOSS_B"))"
        # ---- ROW 12b: the planted fire ----
        if selected 12b && [ "$PLANTS" -eq 1 ]; then
            PL=$O/plnt; rm -rf "$PL"; mkdir -p "$PL/armA" "$PL/armB"
            cp "$SRC_LOSS_A"/*.key "$PL/armA/" 2>/dev/null
            cp "$SRC_LOSS_A"/*.key "$PL/armB/" 2>/dev/null
            victim=$(ls "$PL/armB"/*.key 2>/dev/null | head -1)
            if [ -n "$victim" ]; then
                "$PY" - "$victim" >> "$RCFILE" <<'PYEOF'
import sys
p = sys.argv[1]
lines = open(p, errors="replace").read().split("\n")
done = None
for i, ln in enumerate(lines):
    f = ln.split("\t")
    if len(f) >= 3 and f[1] == "F_src":
        raw = f[2]
        pre = "V=" if raw.startswith("V=") else ""
        regs = [r for r in (raw[2:] if pre else raw).split(",") if r]
        if len(regs) >= 2:
            done = (f[0], regs[0])
            f[2] = pre + ",".join(regs[1:])
            lines[i] = "\t".join(f)
            break
open(p, "w").write("\n".join(lines))
print("     12b PLANT removed %s from pc %s" % (done[1], done[0])
      if done else "     12b PLANT FAILED -- no F_src row with >=2 registers")
PYEOF
                "$T/src_loss_gate.sh" "$Q" "$PL/armA" "$PL/armB" \
                    > "$O/src_loss_plant.log" 2>&1
                prc=$?
                record 12b $([ "$prc" -ne 0 ] && echo 0 || echo 1) \
                    "src_loss_gate PLANTED FIRE gate_rc=$prc (non-zero REQUIRED)"
            else
                record 12b 2 "planted fire -- arm A carries no .key file"
            fi
        fi
    else
        record 12 2 "src_loss_gate -- no arm A given (--src-loss-a)"
    fi
fi

# ---- ROW 13: the set comparator's own selftest --------------------------
if selected 13; then
    "$PY" "$T/arc3_cov/instruments/srcset_ab.py" --selftest > "$O/srcset_selftest.log" 2>&1
    record 13 $? "srcset_ab --selftest"
fi

# ---- ROW 14: the PER-ENCODING source-loss gate --------------------------
# The corpus is CAPTURED HERE and not banked: a standing row whose subject is
# a file somebody else wrote stops gating the day that file goes stale.  Two
# independent captures of THIS build are also the determinism arm -- if they
# disagree, the gate's zero means nothing.
if selected 14; then
    "$PY" "$T/arc3_cov/instruments/srcenc_ab.py" --selftest > "$O/srcenc_selftest.log" 2>&1
    record 14s $? "srcenc_ab --selftest"
    if need_dir "$WORKLOAD" "the workload directory (--workload-dir)"; then
        "$T/srcenc_loss_gate.sh" capture "$Q" "$O/srce/armA" "$WORKLOAD" > "$O/srce_capA.log" 2>&1
        record 14A $? "srcenc capture A"
        "$T/srcenc_loss_gate.sh" capture "$Q" "$O/srce/armB" "$WORKLOAD" > "$O/srce_capB.log" 2>&1
        record 14B $? "srcenc capture B"
        "$T/srcenc_loss_gate.sh" compare "$Q" "$O/srce/armA/corpus.tsv" \
            "$O/srce/armB/corpus.tsv" > "$O/srce.log" 2>&1
        record 14 $? "srcenc_loss_gate, two independent captures of THIS build"
        grep -E "UNADJUDICATED|GAINS|VERDICT" "$O/srce.log" | head -3 >> "$RCFILE"
        if selected 14b && [ "$PLANTS" -eq 1 ]; then
            mkdir -p "$O/srce/plnt"
            "$PY" - "$O/srce/armA/corpus.tsv" "$O/srce/plnt/armB.tsv" >> "$RCFILE" <<'PYEOF'
import sys
src, dst = sys.argv[1], sys.argv[2]
out, done = [], None
for line in open(src, errors="replace"):
    if not done and not line.startswith("#"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 4:
            regs = [r for r in f[3].split(",") if r]
            if len(regs) >= 2:
                done = (f[0], f[1], f[2], regs[0])
                f[3] = ",".join(regs[1:])
                line = "\t".join(f) + "\n"
    out.append(line)
open(dst, "w").writelines(out)
print("     14b PLANT removed %s from %s %s (%s)" % (done[3], done[0], done[1], done[2])
      if done else "     14b PLANT FAILED -- no row with >=2 registers")
PYEOF
            "$T/srcenc_loss_gate.sh" compare "$Q" "$O/srce/armA/corpus.tsv" \
                "$O/srce/plnt/armB.tsv" > "$O/srce_plant.log" 2>&1
            prc=$?
            record 14b $([ "$prc" -ne 0 ] && echo 0 || echo 1) \
                "srcenc_loss_gate PLANTED FIRE gate_rc=$prc (non-zero REQUIRED)"
        fi
    else
        record 14 2 "srcenc_loss_gate -- no workload directory"
    fi
fi

# ---- ROW 15: the PER-ENCODING opcode-class gate -------------------------
# Rows 15b/15c COMPILE their plant in, so they edit a tracked header and
# rebuild.  Two layers are erased for the LOSS direction, and that is the
# finding verify46 had to supply: an identity row carrying GEN_OP_UNKNOWN is
# an ABSTAIN (champsim_tracer_decode.cc), so the Capstone-era enum table
# answers and erasing only the identity row changes nothing at all.  A control
# that does not fire is not a control.
IDH=$REPO/contrib/plugins/champsim_tracer/champsim_tracer_qemu_ident_x86.h
ENUMH=$REPO/contrib/plugins/champsim_tracer/champsim_tracer_mnemonics_x86.h
if selected 15; then
    "$PY" "$T/arc3_cov/instruments/opcenc_ab.py" --selftest > "$O/opcenc_selftest.log" 2>&1
    record 15s $? "opcenc_ab --selftest"
    if need_dir "$WORKLOAD" "the workload directory (--workload-dir)"; then
        # THE GATE'S CORPUS MAY NOT BE NARROWER THAN THE WIRE IT GUARDS.
        # w19's four guests are 31,325 encodings and contain no prefetch, so
        # this gate scored the x86 PREFETCH class off the wire and read "0
        # unadjudicated moves" -- correctly, about a population that could
        # not contain the instruction (exec97 FINDING 49-C).  Row 11 has just
        # built the golden-net cells, which do contain it, so they are handed
        # to both captures as extra guests.
        #
        # The list is derived from what is on disk, not written down: a cell
        # that stops being generated drops out of the corpus and the
        # per-cell counts in the capture's own RC.txt say so, where a
        # hard-coded list would keep naming it and refuse.  A missing NET
        # root is not fatal here -- row 11 owns that verdict and is
        # mandatory -- but the widening is REPORTED either way, because a
        # gate whose population silently narrowed is the whole defect.
        NETROOT=${CST_NET_WORK_ROOT:-/mnt/md0/QEMU/cst_runs/valunify/golden_wr}/netval
        NETCELLS=()
        for isa in x86_64 aarch64 riscv64 mipsel; do
            while IFS= read -r cb; do
                [ -x "$cb" ] && NETCELLS+=("$isa:$cb")
            done < <(find "$NETROOT" -type f -name "*_$isa" 2>/dev/null | sort)
        done
        record 15w $([ "${#NETCELLS[@]}" -gt 0 ] && echo 0 || echo 1) \
            "opcenc corpus widened by ${#NETCELLS[@]} golden-net cell(s) beside the 4 w19 guests"
        "$T/opcenc_loss_gate.sh" capture "$Q" "$O/opce/armA" "$WORKLOAD" ${NETCELLS[@]+"${NETCELLS[@]}"} > "$O/opce_capA.log" 2>&1
        record 15A $? "opcenc capture A"
        "$T/opcenc_loss_gate.sh" capture "$Q" "$O/opce/armB" "$WORKLOAD" ${NETCELLS[@]+"${NETCELLS[@]}"} > "$O/opce_capB.log" 2>&1
        record 15B $? "opcenc capture B"
        "$T/opcenc_loss_gate.sh" compare "$Q" "$O/opce/armA/corpus.tsv" \
            "$O/opce/armB/corpus.tsv" > "$O/opce.log" 2>&1
        record 15 $? "opcenc_loss_gate, two independent captures of THIS build"

        if [ "$PLANTS" -eq 1 ] && ( selected 15b || selected 15c ); then
          plant_opc() {   # $1=arm (4 chars)  $2=new class  $3=both-layers?
            local arm=$1 new=$2 both=$3 rc sop sob
            cp "$IDH" "$O/idh.orig"; cp "$ENUMH" "$O/enumh.orig"
            "$PY" - "$IDH" "$new" >> "$RCFILE" <<'PYEOF'
import sys, re
p, new = sys.argv[1], sys.argv[2]
s = open(p).read()
i = s.index('{ 0x00000746u, "LEA", QID_VERIFIED,')
j = s.index('},', i)
blk = s[i:j]
blk2 = re.sub(r'GEN_OP_[A-Z0-9_]+', new, blk, count=1)
assert blk2 != blk, "no GEN_OP_ token in the LEA row"
open(p, "w").write(s[:i] + blk2 + s[j:])
print("     PLANT identity row 0x746 LEA -> %s" % new)
PYEOF
            if [ "$both" = both ]; then
                "$PY" - "$ENUMH" "$new" >> "$RCFILE" <<'PYEOF'
import sys, re
p, new = sys.argv[1], sys.argv[2]
s = open(p).read()
i = s.index('[X86_INS_LEA]')
j = s.index('\n', i)
row = s[i:j]
row2 = re.sub(r'GEN_OP_[A-Z0-9_]+', new, row, count=1)
assert row2 != row, "no GEN_OP_ token in the [X86_INS_LEA] row"
open(p, "w").write(s[:i] + row2 + s[j:])
print("     PLANT enum row [X86_INS_LEA] -> %s (SECOND LAYER)" % new)
PYEOF
            fi
            ninja -C "$Q" contrib-plugins > "$O/opce_${arm}_build.log" 2>&1; rc=$?
            sop=$(so_hash)
            if [ "$sop" = "$SO0" ]; then
                record "$arm" 2 "the build did NOT move the .so -- the plant did not compile in"
            fi
            # THE SAME POPULATION AS ARM A, INCLUDING THE GOLDEN-NET CELLS.
            # A plant arm captured over a narrower corpus refuses on
            # COVERAGE instead of reporting the loss it planted -- non-zero
            # either way, so the row still passes, but "the gate could not
            # look" is much weaker evidence than "the gate saw the loss",
            # and the point of a planted fire is the second one.  Measured
            # when this was wrong: only_A=4581, gate_rc=2 where PASS 49
            # read gate_rc=1.
            "$T/opcenc_loss_gate.sh" capture "$Q" "$O/opce/$arm" "$WORKLOAD" \
                ${NETCELLS[@]+"${NETCELLS[@]}"} \
                > "$O/opce_cap_$arm.log" 2>&1
            "$T/opcenc_loss_gate.sh" compare "$Q" "$O/opce/armA/corpus.tsv" \
                "$O/opce/$arm/corpus.tsv" > "$O/opce_$arm.log" 2>&1
            local prc=$?
            record "$arm" $([ "$prc" -ne 0 ] && echo 0 || echo 1) \
                "opcenc PLANTED FIRE build_rc=$rc so=$SO0->$sop gate_rc=$prc (non-zero REQUIRED)"
            grep -E "^(LOSS|MOVE) " "$O/opce_$arm.log" | head -2 >> "$RCFILE"
            restore_and_touch "$O/idh.orig" "$IDH"
            restore_and_touch "$O/enumh.orig" "$ENUMH"
            ninja -C "$Q" contrib-plugins > "$O/opce_${arm}_revert.log" 2>&1
            sob=$(so_hash)
            record "${arm}r" $([ "$sob" = "$SO0" ] && echo 0 || echo 1) \
                "revert .so $sob (tip $SO0); tracked modifications now $(git -C "$REPO" status --porcelain | grep -vc '^??')"
          }
          selected 15b && plant_opc plnU GEN_OP_UNKNOWN  both
          selected 15c && plant_opc plnM GEN_OP_INT_ADD  one
        fi
    else
        record 15 2 "opcenc_loss_gate -- no workload directory"
    fi
fi

# ---- THE MANDATORY ROWS ---------------------------------------------------
# A mandatory row that was not selected is RED, with its reason on the
# record.  --rows stays useful for chasing one row; it just cannot produce a
# green transcript while a row that guards the wire went unrun.
for m in $MANDATORY; do
    selected "$m" || record "$m" 2 \
        "MANDATORY ROW NOT SELECTED -- a battery that skips it is not a bar"
done

# ---- ROW 6, RUN HERE ------------------------------------------------------
# Defined above, invoked here: the scan is over EVERY sidecar this run
# produced, so it must run after the last row that produces one.  Selecting
# row 6 without the rows that write sidecars is still legal and still
# refuses if nothing was written, which is the honest answer to "scan what
# this run made" when the run made nothing.
if selected 6; then
    run_row6
    run_row6w
    run_row6s
    if [ "$PLANTS" -eq 1 ]; then
        run_row6b
    else
        record 6b 2 "PLANTED FIRE DESELECTED (--no-plants) -- a wide scope \
nobody has watched fire is not evidence"
    fi
fi

# ---- ROW 16 RUNS LAST, AND THAT IS PART OF THE ROW -----------------------
#
# It used to run in numeric position, before rows 6/6w/6b.  Its subject is
# the R13 evidence root, and score.py refuses a root older than the
# BEHAVIOUR of the binaries it claims to have measured -- so the row's answer
# depends on when in the battery it is asked.  exec110/CORRECTIONS C2 is the
# measured case: a regeneration arm restored generated headers by content and
# then TOUCHED them (the standing rule that forbids `cp -p`), the next ninja
# relinked, and two static legs scored before the tracer they describe was
# built.  The rule that came out of it is that every leg whose guard reads
# the binary must run after the last arm that can move one.  Inside this
# script that means LAST: any earlier position leaves rows that write
# sidecars, plant fires and touch tracked files still to come, and a green
# taken before them is a green against a previous build.
# ---- ROW 16: THE R13 EXTERNAL-TRUTH GATE, AT THIS TIP ---------------------
#
# THE HOLE THIS CLOSES.  R13 is a STANDING GATE by ruling -- the external
# references are consulted on EVERY wire-changing wave -- and nothing made
# the battery ask.  exec99 landed EIGHT wire-changing commits, closed on a
# green fifteen-row battery, and never ran it; verify48 ran it afterwards and
# found it RED.  A standing gate that only runs when somebody remembers is
# not standing, and "the wave forgot" is a mechanism, so it gets a row.
#
# THE STALENESS TEST IS NOT REIMPLEMENTED HERE.  score.py already refuses an
# evidence root older than the tracer binaries it is supposed to have
# measured, and it decides that on the binaries' BEHAVIOUR DIGEST rather than
# on mtimes or commit dates -- so a comment-only commit that relinks 62
# emulators does not stale the evidence, and a wire change that leaves the
# mtime alone does.  A second staleness rule written here would be a second
# opinion about the same question, and the two would drift.  This row's whole
# job is to make the gate RUN, with --build-dir on so the guard is armed.
#
# NO EVIDENCE ROOT IS RED, NOT SKIPPED.  A battery that cannot find the R13
# evidence cannot say the gate passed, and a row that reports PASS because
# its subject is missing is the standing failure mode of this tree.  Point it
# at the root with --r13-root or CST_R13_ROOT.
if selected 16; then
    if [ -z "$R13_ROOT" ]; then
        record 16 2 "R13 external-truth gate -- NO EVIDENCE ROOT (--r13-root \
or CST_R13_ROOT).  R13 is a standing gate; a battery that cannot run it \
cannot report a bar"
    elif [ ! -d "$R13_ROOT" ]; then
        record 16 2 "R13 external-truth gate -- evidence root '$R13_ROOT' \
is not a directory"
    else
        "$T/external_truth_gate.sh" "$R13_ROOT" --build-dir "$Q" \
            > "$O/r13_gate.log" 2>&1
        record 16 $? "external_truth_gate (staleness guard ARMED via --build-dir)"
    fi
fi

# ---- close ---------------------------------------------------------------
# The I/O sweep is read from cst_audit, not from the options the runs were
# given: a trace is compressed when the file says so.
unc=0
while IFS= read -r c; do
    "$Q/contrib/plugins/cst_audit" "$c" 2>/dev/null | grep -q 'body member (zstd)' || unc=$((unc+1))
done < <(find "$O" -name '*.cst')
record io $([ "$unc" -eq 0 ] && echo 0 || echo 1) "uncompressed traces=$unc"

{
  echo "SO_AT_CLOSE=$(so_hash)  (start $SO0)"
  echo "TRACKED_MODIFICATIONS_AT_CLOSE=$(git -C "$REPO" status --porcelain 2>/dev/null | grep -vc '^??')"
  echo "BATTERY_DONE red=$RED"
} >> "$RCFILE"
cat "$RCFILE"
exit "$RED"
