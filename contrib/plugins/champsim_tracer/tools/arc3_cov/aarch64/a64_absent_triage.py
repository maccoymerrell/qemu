#!/usr/bin/env python3
"""WHY A REACHABLE aarch64 ROW DID NOT COME BACK OFF THE WIRE -- decided by running it.

"NOT EXERCISED" IS NOT A CLASS, IT IS A QUESTION
------------------------------------------------
The exercise pass reports a row ABSENT when a trace was written and the probe's
address is not in it.  That single word covers three completely different
animals, and the whole point of a coverage pass is to tell them apart:

  EL0-UNDEF            the probe raises SIGILL with no plugin attached, so the
                       instruction did not execute and there is nothing to
                       publish.  THE EXIT STATUS DOES NOT SAY WHY, and this
                       file does not guess: "no rule matched at EL0" and "the
                       rule matched and the instruction raised an
                       illegal-instruction exception" both arrive here as
                       SIGILL.  The two ARE separable, by a different
                       measurement — whether QEMU's decoder named the row for
                       the encoding at translation time (the sled's identity
                       corpus) — and the coverage report splits them on that,
                       not on this exit status.

  FAULTED-NOT-RETIRED  QEMU DECODED the encoding and then took an
                       architectural exception -- a data abort on the address
                       it computed, an authentication failure, a
                       Memory-Copy/Set exception.  The bare probe dies on a
                       signal that is NOT SIGILL, which is positive evidence of
                       decode, and the traced run's last published instruction
                       is the word immediately BEFORE the probe.  The wire
                       publishes retired instructions; an instruction that
                       faults has nothing to publish, and that is the contract.

  RAN-BUT-ABSENT       the bare probe RAN to one of the guest's exit stubs and
                       the tracer still did not publish it.  That is a TRACER
                       DEFECT, it is the hole this whole pass exists to find,
                       and this file exits non-zero when it sees one.

WHY THE BARE PROBER IS A SEPARATE RUN
--------------------------------------
Asking the traced run "did it execute" is circular: the trace is the thing
under test.  The same image is therefore re-run with NO plugin, and QEMU's own
exit status answers.  The image is built so that only the probe can raise
SIGILL (see `a64_probe_elf`), so the discrimination is sound.

A ROW WHOSE TRACE STOPS EARLIER THAN THE PROBE IS A DIFFERENT ANIMAL AGAIN, and
it is counted separately rather than folded into FAULTED-NOT-RETIRED: it would
mean the tracer lost the guest before the instruction under test, which is a
defect of its own.  The riscv64 leg's first pass conflated exactly this, and
the correction is written into its own commit.

Author: Maccoy Merrell.

SPDX-License-Identifier: GPL-2.0-or-later
"""

import argparse
import concurrent.futures
import os
import re
import signal
import struct
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import a64_probe_elf as P                                  # noqa: E402

COMPRESS = "zstd -T0 -3 -q -c"
_ANY_PC = re.compile(r"^0x([0-9a-f]+):\s+(?:[0-9a-f]{2} )+")

#: The word immediately before the probe.  The image fills that run with `nop`,
#: so a tracer that followed the guest all the way to the instruction under
#: test publishes exactly this address last.
LAST_BEFORE_PROBE = P.PROBE_PC - 4


def bare(qemu, cpu, elf, timeout):
    """QEMU's own verdict on the probe, with NO plugin attached."""
    try:
        r = subprocess.run([qemu, "-cpu", cpu, elf],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    rc = r.returncode
    if rc == P.EXIT_FELL_THROUGH:
        return "RAN-FELL-THROUGH"
    if rc == P.EXIT_TRANSFERRED:
        return "RAN-TRANSFERRED"
    if rc < 0:
        try:
            nm = signal.Signals(-rc).name
        except ValueError:
            nm = "SIG%d" % -rc
        return "SIG:%s" % nm
    return "EXIT:%d" % rc


def traced_last_pc(qemu, cpu, plugin, decode, elf, cell, timeout):
    """The highest instruction address the trace published, and probe presence."""
    plug = "%s,outfile=t,compress=%s" % (plugin, COMPRESS)
    try:
        subprocess.run([qemu, "-cpu", cpu, "-plugin", plug, elf],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=timeout, cwd=cell)
    except subprocess.TimeoutExpired:
        return (None, False)
    trace = None
    for cand in sorted(os.listdir(cell)):
        if cand.startswith("t.cst"):
            trace = os.path.join(cell, cand)
            break
    if trace is None:
        return (None, False)
    try:
        out = subprocess.run([decode, trace], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        return (None, False)
    hi = None
    saw_probe = False
    for line in out.stdout.decode("utf-8", "replace").splitlines():
        m = _ANY_PC.match(line.strip())
        if not m:
            continue
        pc = int(m.group(1), 16)
        if pc == P.PROBE_PC:
            saw_probe = True
        if P.BASE <= pc < P.BASE + P.IMAGE_LEN and (hi is None or pc > hi):
            hi = pc
    return (hi, saw_probe)


def triage(job):
    (qemu, cpu, plugin, decode, outdir, rule, word, timeout) = job
    cell = os.path.join(outdir, "%s_%08x" % (rule, word))
    os.makedirs(cell, exist_ok=True)
    elf = os.path.join(cell, "p.elf")
    verdicts = {}
    for arm in sorted(P.ARMS):
        with open(elf, "wb") as fh:
            fh.write(P.build_elf(word, arm))
        os.chmod(elf, 0o755)
        verdicts[arm] = bare(qemu, cpu, elf, timeout)
    # The traced reading uses the arm whose bare run got furthest, so a row
    # that only decodes under SMSTART is not judged on the plain arm's trace.
    rank = {"RAN-FELL-THROUGH": 0, "RAN-TRANSFERRED": 1, "TIMEOUT": 2}
    best = sorted(P.ARMS, key=lambda a: rank.get(verdicts[a], 3 if
                                                 verdicts[a].startswith("SIG:")
                                                 and verdicts[a] != "SIG:SIGILL"
                                                 else 4))[0]
    with open(elf, "wb") as fh:
        fh.write(P.build_elf(word, best))
    os.chmod(elf, 0o755)
    hi, saw = traced_last_pc(qemu, cpu, plugin, decode, elf, cell, timeout)

    v = verdicts[best]
    if saw:
        klass = "EXERCISED"
    elif v.startswith("RAN-"):
        klass = "RAN-BUT-ABSENT"
    elif v == "SIG:SIGILL":
        klass = "EL0-UNDEF"
    elif v == "TIMEOUT":
        klass = "NON-TERMINATING"
    elif v.startswith("SIG:"):
        klass = ("FAULTED-NOT-RETIRED" if hi == LAST_BEFORE_PROBE
                 else "TRACE-STOPPED-EARLY")
    else:
        klass = "UNEXPLAINED"
    return (rule, word, best, v, hi, klass)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--qemu", required=True)
    ap.add_argument("--cpu", default="max")
    ap.add_argument("--plugin", required=True)
    ap.add_argument("--cst-decode", required=True)
    ap.add_argument("--rows", required=True,
                    help="rule<TAB>space-separated candidate words")
    ap.add_argument("--cells", required=True)
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--per-row", type=int, default=3)
    ap.add_argument("--jobs", type=int, default=12)
    ap.add_argument("--timeout", type=float, default=25.0)
    a = ap.parse_args()

    rows = {}
    for line in open(a.rows, "r", errors="replace"):
        if line.startswith("#") or not line.strip():
            continue
        p = line.rstrip("\n").split("\t")
        if len(p) < 2:
            continue
        ws = [int(w, 16) for w in p[1].split()][:a.per_row]
        if ws:
            rows[p[0]] = ws
    if not rows:
        sys.exit("REFUSING: %s named no row" % a.rows)

    os.makedirs(a.cells, exist_ok=True)
    jobs = [(a.qemu, a.cpu, a.plugin, a.cst_decode, a.cells, r, w, a.timeout)
            for r in sorted(rows) for w in rows[r]]
    res = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        for x in ex.map(triage, jobs):
            res.append(x)

    # THE CONTROL.  `add x0, x0, #1` must come back EXERCISED here too: a
    # triage frame that cannot see a live instruction would call every row
    # undefined.
    ctl = triage((a.qemu, a.cpu, a.plugin, a.cst_decode, a.cells,
                  "_control", 0x91000400, a.timeout))
    print("control (add x0, x0, #1): bare=%s class=%s" % (ctl[3], ctl[5]))
    if ctl[5] != "EXERCISED":
        sys.exit("REFUSING: the control did not come back EXERCISED, so no "
                 "verdict in this run means anything")

    # ONE VERDICT PER ROW, the most favourable its candidates reached.
    order = ["EXERCISED", "RAN-BUT-ABSENT", "TRACE-STOPPED-EARLY",
             "FAULTED-NOT-RETIRED", "NON-TERMINATING", "EL0-UNDEF",
             "UNEXPLAINED"]
    per = {}
    for (r, w, arm, v, hi, k) in res:
        cur = per.get(r)
        if cur is None or order.index(k) < order.index(cur[4]):
            per[r] = (w, arm, v, hi, k)

    counts = {}
    with open(a.out, "w") as f:
        f.write("#rule\tclass\tarm\tword\tbare\tlast_pc\n")
        for r in sorted(per):
            w, arm, v, hi, k = per[r]
            counts[k] = counts.get(k, 0) + 1
            f.write("%s\t%s\t%s\t%08x\t%s\t%s\n"
                    % (r, k, arm, w, v,
                       "-" if hi is None else "0x%x" % hi))
    for k in order:
        if counts.get(k):
            print("  %-22s %4d" % (k, counts[k]))
    print("written to %s" % a.out)

    bad = counts.get("RAN-BUT-ABSENT", 0) + counts.get("TRACE-STOPPED-EARLY", 0)
    if bad:
        print("TRACER DEFECT: %d row(s) the guest ran and the wire does not "
              "carry" % bad, file=sys.stderr)
        return 1
    if counts.get("UNEXPLAINED"):
        print("UNEXPLAINED: %d row(s) fit no class -- a remainder nobody can "
              "name is not a remainder" % counts["UNEXPLAINED"], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
